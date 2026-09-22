//! secp256k1, natively: the reference `crates/emulator` executes and the
//! reference `crates/trace`'s witness builder writes its columns from.
//!
//! One implementation, held to an outside oracle by
//! `crates/program/tests/secp256k1.rs` — the shape S21 used for
//! `emulator::keccak_f` against `tiny-keccak`. It is *not* the guest SDK's
//! software fallback: that one is `no_std`, lives in `crates/guest-sdk`, links
//! only `constants`, and is held to this one through the guests' own tests.
//!
//! **Everything here is a 256-bit integer as four 64-bit limbs, least
//! significant first** — [`U256`] — because that is the circuit's unit
//! (`constants::secp256k1::LIMBS`). A 256-bit value does not fit in `Fr`, and
//! that is the whole reason the circuit is non-native; nothing in this file
//! touches `Fr` at all.
//!
//! The modulus is a **parameter**, not a type. secp256k1 needs arithmetic mod
//! `p` and mod `n` and the two differ in nothing but the modulus, so a second
//! copy of this module would be a second copy of every bug. That is not the
//! trait-generic field master rule 1 forbids — there is no trait, no generic
//! and no abstraction, just a function argument — and it is what the circuit
//! does too: a congruence row carries its modulus as gate literals.

use constants::secp256k1 as k;

/// A 256-bit unsigned integer: four 64-bit limbs, **least significant first**.
pub type U256 = [u64; k::LIMBS];

/// Zero.
pub const ZERO: U256 = [0; k::LIMBS];

/// One.
pub const ONE: U256 = [1, 0, 0, 0];

// ---------------------------------------------------------------------------
// Plain 256-bit arithmetic
// ---------------------------------------------------------------------------

/// `a + b`, and whether it carried out of 256 bits.
pub fn add(a: &U256, b: &U256) -> (U256, bool) {
    let mut out = ZERO;
    let mut carry = 0u64;
    for i in 0..k::LIMBS {
        let (s, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s.overflowing_add(carry);
        out[i] = s;
        carry = u64::from(c1) + u64::from(c2);
    }
    (out, carry != 0)
}

/// `a - b`, and whether it borrowed.
pub fn sub(a: &U256, b: &U256) -> (U256, bool) {
    let mut out = ZERO;
    let mut borrow = 0u64;
    for i in 0..k::LIMBS {
        let (d, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d.overflowing_sub(borrow);
        out[i] = d;
        borrow = u64::from(b1) + u64::from(b2);
    }
    (out, borrow != 0)
}

/// `a < b`.
pub fn less(a: &U256, b: &U256) -> bool {
    for i in (0..k::LIMBS).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// `a == 0`.
pub fn is_zero(a: &U256) -> bool {
    a.iter().all(|l| *l == 0)
}

/// The schoolbook product, eight limbs. This is exactly the convolution the
/// circuit's position equations enforce (`docs/spec/ecrecover.md` §3.1), so a
/// disagreement here is a disagreement with the circuit.
pub fn mul_wide(a: &U256, b: &U256) -> [u64; 2 * k::LIMBS] {
    let mut out = [0u64; 2 * k::LIMBS];
    for i in 0..k::LIMBS {
        let mut carry = 0u128;
        for j in 0..k::LIMBS {
            let t = u128::from(a[i]) * u128::from(b[j]) + u128::from(out[i + j]) + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        out[i + k::LIMBS] = carry as u64;
    }
    out
}

/// `(x / m, x % m)` for an eight-limb `x` and a **normalized** four-limb `m`,
/// meaning `m`'s top limb has its high bit set. Both `p` and `n` are
/// normalized, so Knuth's algorithm D needs no normalization step and this is
/// the whole of it.
///
/// Panics if `m` is not normalized, or if the quotient does not fit in 256
/// bits — neither is reachable from this module and both would be a caller's
/// broken invariant.
pub fn div_rem_wide(x: &[u64; 2 * k::LIMBS], m: &U256) -> (U256, U256) {
    assert!(
        m[k::LIMBS - 1] >> 63 == 1,
        "div_rem_wide: the divisor is not normalized"
    );
    const N: usize = k::LIMBS;
    // `u` is the running remainder, one limb wider than the dividend.
    let mut u = [0u64; 2 * N + 1];
    u[..2 * N].copy_from_slice(x);
    let mut q = ZERO;

    for j in (0..=N).rev() {
        if j + N >= u.len() {
            continue;
        }
        // Estimate this quotient limb from the top two limbs of what is left.
        let top = (u128::from(u[j + N]) << 64) | u128::from(u[j + N - 1]);
        let mut qhat = top / u128::from(m[N - 1]);
        let mut rhat = top % u128::from(m[N - 1]);
        loop {
            let too_big = qhat >> 64 != 0
                || qhat * u128::from(m[N - 2]) > (rhat << 64) | u128::from(u[j + N - 2]);
            if !too_big {
                break;
            }
            qhat -= 1;
            rhat += u128::from(m[N - 1]);
            if rhat >> 64 != 0 {
                break;
            }
        }

        // Multiply and subtract. At most one of the two borrows can fire: if
        // the first did, the difference is at least 1 and the second cannot.
        let mut borrow = 0u64;
        let mut carry = 0u128;
        for (i, limb) in m.iter().enumerate() {
            let prod = qhat * u128::from(*limb) + carry;
            carry = prod >> 64;
            let (d, b1) = u[i + j].overflowing_sub(prod as u64);
            let (d, b2) = d.overflowing_sub(borrow);
            u[i + j] = d;
            borrow = u64::from(b1) + u64::from(b2);
        }
        let (d, b1) = u[j + N].overflowing_sub(carry as u64);
        let (d, b2) = d.overflowing_sub(borrow);
        u[j + N] = d;

        if b1 || b2 {
            // `qhat` was one too large: add the divisor back once.
            qhat -= 1;
            let mut c = 0u128;
            for (i, limb) in m.iter().enumerate() {
                let s = u128::from(u[i + j]) + u128::from(*limb) + c;
                u[i + j] = s as u64;
                c = s >> 64;
            }
            u[j + N] = (u128::from(u[j + N]) + c) as u64;
        }

        if j < N {
            q[j] = qhat as u64;
        } else {
            assert!(qhat == 0, "div_rem_wide: the quotient exceeds 256 bits");
        }
    }

    let mut r = ZERO;
    r.copy_from_slice(&u[..N]);
    (q, r)
}

/// `x mod m` for a 256-bit `x`.
pub fn rem(x: &U256, m: &U256) -> U256 {
    let mut wide = [0u64; 2 * k::LIMBS];
    wide[..k::LIMBS].copy_from_slice(x);
    div_rem_wide(&wide, m).1
}

/// `(a + b) mod m`, for `a, b < m`.
pub fn addmod(a: &U256, b: &U256, m: &U256) -> U256 {
    let (s, carry) = add(a, b);
    if carry || !less(&s, m) {
        sub(&s, m).0
    } else {
        s
    }
}

/// `(a - b) mod m`, for `a, b < m`.
pub fn submod(a: &U256, b: &U256, m: &U256) -> U256 {
    let (d, borrow) = sub(a, b);
    if borrow {
        add(&d, m).0
    } else {
        d
    }
}

/// `(a * b) mod m`, for `a, b < m`.
pub fn mulmod(a: &U256, b: &U256, m: &U256) -> U256 {
    div_rem_wide(&mul_wide(a, b), m).1
}

/// The quotient and remainder of `a * b` by `m`: the **witness pair** a
/// congruence row commits, `a*b = q*m + r` over the integers
/// (`docs/spec/ecrecover.md` §3.1).
pub fn mul_quotient_rem(a: &U256, b: &U256, m: &U256) -> (U256, U256) {
    div_rem_wide(&mul_wide(a, b), m)
}

/// `a^-1 mod m` for a prime `m`, or `None` at `a = 0`.
///
/// The binary extended Euclidean algorithm: shifts, adds and subtracts only,
/// about 512 iterations. Fermat's `a^(m-2)` would be shorter to write and
/// about 380 modular multiplications long, and the witness builder takes one
/// inverse per point operation — 392 of them an invocation — so the short one
/// is not affordable.
pub fn invmod(a: &U256, m: &U256) -> Option<U256> {
    if is_zero(a) {
        return None;
    }
    // u = a, v = m, x1 = 1, x2 = 0, with the invariant
    // u = x1*a mod m and v = x2*a mod m.
    let mut u = *a;
    let mut v = *m;
    let mut x1 = ONE;
    let mut x2 = ZERO;
    while !(u == ONE || v == ONE) {
        while u[0] & 1 == 0 {
            u = shr1(&u);
            x1 = half_mod(&x1, m);
        }
        while v[0] & 1 == 0 {
            v = shr1(&v);
            x2 = half_mod(&x2, m);
        }
        if !less(&u, &v) {
            u = sub(&u, &v).0;
            x1 = submod(&x1, &x2, m);
        } else {
            v = sub(&v, &u).0;
            x2 = submod(&x2, &x1, m);
        }
    }
    Some(if u == ONE { x1 } else { x2 })
}

/// `x >> 1`.
fn shr1(x: &U256) -> U256 {
    let mut out = ZERO;
    for i in 0..k::LIMBS {
        out[i] = x[i] >> 1;
        if i + 1 < k::LIMBS {
            out[i] |= x[i + 1] << 63;
        }
    }
    out
}

/// `x / 2 mod m`, for an odd `m`: exact when `x` is even, and `(x + m) / 2`
/// otherwise, which is the same residue.
fn half_mod(x: &U256, m: &U256) -> U256 {
    if x[0] & 1 == 0 {
        shr1(x)
    } else {
        let (s, carry) = add(x, m);
        let mut out = shr1(&s);
        if carry {
            out[k::LIMBS - 1] |= 1 << 63;
        }
        out
    }
}

/// `a^e mod m`, square and multiply, most significant bit first.
pub fn powmod(a: &U256, e: &U256, m: &U256) -> U256 {
    let mut out = ONE;
    for i in (0..k::LIMBS).rev() {
        for bit in (0..64).rev() {
            out = mulmod(&out, &out, m);
            if e[i] >> bit & 1 == 1 {
                out = mulmod(&out, a, m);
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The curve
// ---------------------------------------------------------------------------

/// An affine point, with the identity carried as a flag rather than as a
/// coordinate pair: `y^2 = x^3 + 7` has no affine representation for it, which
/// is exactly why the circuit carries an infinity flag too
/// (`docs/spec/ecrecover.md` §5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub infinity: bool,
    pub x: U256,
    pub y: U256,
}

/// The identity.
pub const INFINITY: Point = Point {
    infinity: true,
    x: ZERO,
    y: ZERO,
};

/// The generator.
pub fn generator() -> Point {
    Point {
        infinity: false,
        x: k::G_X,
        y: k::G_Y,
    }
}

/// Whether `point` satisfies `y^2 = x^3 + 7` with both coordinates canonical.
/// The identity satisfies it by definition.
pub fn on_curve(point: &Point) -> bool {
    if point.infinity {
        return true;
    }
    if !less(&point.x, &k::P) || !less(&point.y, &k::P) {
        return false;
    }
    let lhs = mulmod(&point.y, &point.y, &k::P);
    let x2 = mulmod(&point.x, &point.x, &k::P);
    let x3 = mulmod(&x2, &point.x, &k::P);
    let rhs = addmod(&x3, &[7, 0, 0, 0], &k::P);
    lhs == rhs
}

/// `-point`.
pub fn negate(point: &Point) -> Point {
    if point.infinity || is_zero(&point.y) {
        return *point;
    }
    Point {
        infinity: false,
        x: point.x,
        y: sub(&k::P, &point.y).0,
    }
}

/// `a + b`, the complete affine group law — the same five cases the circuit's
/// addition gadget carries (`docs/spec/ecrecover.md` §5.2).
pub fn point_add(a: &Point, b: &Point) -> Point {
    if a.infinity {
        return *b;
    }
    if b.infinity {
        return *a;
    }
    if a.x == b.x {
        if a.y == b.y {
            return point_double(a);
        }
        // Equal x, different y: on this curve that is b = -a, because the two
        // roots of one x are y and p - y.
        return INFINITY;
    }
    let num = submod(&b.y, &a.y, &k::P);
    let den = submod(&b.x, &a.x, &k::P);
    let lambda = mulmod(&num, &invmod(&den, &k::P).expect("distinct x"), &k::P);
    chord(a, b, &lambda)
}

/// `2 * a`.
pub fn point_double(a: &Point) -> Point {
    if a.infinity || is_zero(&a.y) {
        return INFINITY;
    }
    let x2 = mulmod(&a.x, &a.x, &k::P);
    let three_x2 = addmod(&addmod(&x2, &x2, &k::P), &x2, &k::P);
    let two_y = addmod(&a.y, &a.y, &k::P);
    let lambda = mulmod(
        &three_x2,
        &invmod(&two_y, &k::P).expect("y is nonzero"),
        &k::P,
    );
    chord(a, a, &lambda)
}

/// The two lines every non-degenerate case shares:
/// `x3 = l^2 - x1 - x2` and `y3 = l*(x1 - x3) - y1`.
fn chord(a: &Point, b: &Point, lambda: &U256) -> Point {
    let l2 = mulmod(lambda, lambda, &k::P);
    let x3 = submod(&submod(&l2, &a.x, &k::P), &b.x, &k::P);
    let y3 = submod(
        &mulmod(lambda, &submod(&a.x, &x3, &k::P), &k::P),
        &a.y,
        &k::P,
    );
    Point {
        infinity: false,
        x: x3,
        y: y3,
    }
}

/// The window table `1*base ..= 15*base`, indexed by `digit - 1`.
pub fn window_table(base: &Point) -> [Point; k::WINDOW_ENTRIES] {
    let mut table = [INFINITY; k::WINDOW_ENTRIES];
    table[0] = *base;
    for i in 1..k::WINDOW_ENTRIES {
        table[i] = point_add(&table[i - 1], base);
    }
    table
}

/// `scalar`'s 64 width-4 digits, **most significant first** — the order the
/// ladder consumes them.
pub fn window_digits(scalar: &U256) -> [u8; k::WINDOWS] {
    let mut out = [0u8; k::WINDOWS];
    for (i, slot) in out.iter_mut().enumerate() {
        let index = k::WINDOWS - 1 - i;
        *slot = ((scalar[index / 16] >> (4 * (index % 16))) & 0xF) as u8;
    }
    out
}

/// `u1*G + u2*base`, the **joint ladder with shared doublings** the circuit
/// proves: one accumulator, four doublings a window, then the two table
/// entries added in turn.
///
/// Separate ladders would cost 259 doublings and 133 additions and this costs
/// the same, because the doublings are `u2*base`'s either way — which is why
/// `G`'s multiples need no per-window table and are gate literals
/// (`docs/spec/ecrecover.md` §5.1).
pub fn joint_mul(u1: &U256, u2: &U256, base: &Point) -> Point {
    let table_g = window_table(&generator());
    let table_b = window_table(base);
    let digits_1 = window_digits(u1);
    let digits_2 = window_digits(u2);
    let mut acc = INFINITY;
    for w in 0..k::WINDOWS {
        if w > 0 {
            for _ in 0..k::WINDOW_BITS {
                acc = point_double(&acc);
            }
        }
        let d1 = digits_1[w];
        if d1 != 0 {
            acc = point_add(&acc, &table_g[d1 as usize - 1]);
        }
        let d2 = digits_2[w];
        if d2 != 0 {
            acc = point_add(&acc, &table_b[d2 as usize - 1]);
        }
    }
    acc
}

// ---------------------------------------------------------------------------
// Recovery
// ---------------------------------------------------------------------------

/// Why a recovery failed. Every one of these is a **provable** outcome: the
/// circuit carries a success flag and zeroes its output words, and the EVM
/// precompile returns empty output rather than reverting
/// (`docs/spec/ecrecover.md` §1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoverFailure {
    /// `v` was neither 27 nor 28.
    BadRecoveryId,
    /// `r` was 0 or at least `n`.
    ROutOfRange,
    /// `s` was 0 or at least `n`.
    SOutOfRange,
    /// `x = r` is not the x-coordinate of any curve point: `x^3 + 7` is a
    /// quadratic non-residue mod `p`.
    NotOnCurve,
    /// The recovered point is the identity, which has no public key.
    Infinity,
}

/// The EVM `ecrecover` precompile's recovery, to the affine public key.
///
/// `hash`, `r` and `s` are 256-bit integers in this module's limb form; `v` is
/// 27 or 28. The address is **not** computed here: it is
/// `keccak256(x ‖ y)[12..]`, which is the guest shim's job through S21's
/// keccak path and never a second keccak in this circuit (stage prompt,
/// must-be-exact 4).
pub fn recover(hash: &U256, v: u32, r: &U256, s: &U256) -> Result<Point, RecoverFailure> {
    use constants::ecrecover as e;
    if !(e::V_MIN..=e::V_MAX).contains(&v) {
        return Err(RecoverFailure::BadRecoveryId);
    }
    if is_zero(r) || !less(r, &k::N) {
        return Err(RecoverFailure::ROutOfRange);
    }
    if is_zero(s) || !less(s, &k::N) {
        return Err(RecoverFailure::SOutOfRange);
    }
    let recid = v - e::V_MIN;

    // R from (r, recid). `x = r`, never `r + n`: ids 2 and 3 have no encoding
    // through the precompile.
    let y = match curve_y(r, recid) {
        Some(y) => y,
        None => return Err(RecoverFailure::NotOnCurve),
    };
    let big_r = Point {
        infinity: false,
        x: *r,
        y,
    };

    // Q = r^-1 * (s*R - h*G) = u1*G + u2*R with u1 = -h/r and u2 = s/r, both
    // mod n. `h` is reduced mod n, which is not an error: a hash at or above n
    // behaves exactly as its residue.
    let e_scalar = rem(hash, &k::N);
    let r_inv = invmod(r, &k::N).expect("r is nonzero and below n");
    let u1 = mulmod(&submod(&ZERO, &e_scalar, &k::N), &r_inv, &k::N);
    let u2 = mulmod(s, &r_inv, &k::N);
    let q = joint_mul(&u1, &u2, &big_r);
    if q.infinity {
        return Err(RecoverFailure::Infinity);
    }
    Ok(q)
}

/// The curve's `y` at `x` with `y mod 2 == parity`, or `None` when `x^3 + 7`
/// is a non-residue.
pub fn curve_y(x: &U256, parity: u32) -> Option<U256> {
    let x2 = mulmod(x, x, &k::P);
    let x3 = mulmod(&x2, x, &k::P);
    let c = addmod(&x3, &[7, 0, 0, 0], &k::P);
    // p = 3 mod 4, so a residue's roots are c^((p+1)/4) and its negation.
    let root = powmod(&c, &k::P_PLUS_1_OVER_4, &k::P);
    if mulmod(&root, &root, &k::P) != c {
        return None;
    }
    let y = if root[0] & 1 == u64::from(parity) {
        root
    } else {
        sub(&k::P, &root).0
    };
    Some(y)
}

// ---------------------------------------------------------------------------
// Byte forms
// ---------------------------------------------------------------------------

/// A 32-byte **big-endian** value — the EVM's encoding, and the shim's
/// argument — as limbs.
pub fn from_be_bytes(bytes: &[u8; 32]) -> U256 {
    let mut out = ZERO;
    for i in 0..k::LIMBS {
        let mut limb = [0u8; 8];
        limb.copy_from_slice(&bytes[8 * (k::LIMBS - 1 - i)..8 * (k::LIMBS - i)]);
        out[i] = u64::from_be_bytes(limb);
    }
    out
}

/// The inverse of [`from_be_bytes`].
pub fn to_be_bytes(value: &U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..k::LIMBS {
        out[8 * (k::LIMBS - 1 - i)..8 * (k::LIMBS - i)].copy_from_slice(&value[i].to_be_bytes());
    }
    out
}

/// A value as the frame holds it: [`constants::ecrecover::VALUE_WORDS`]
/// little-endian 32-bit words, word `2i` being limb `i`'s low half
/// (`docs/spec/ecrecover.md` §2.1).
pub fn to_frame_words(value: &U256) -> [u32; constants::ecrecover::VALUE_WORDS] {
    let mut out = [0u32; constants::ecrecover::VALUE_WORDS];
    for i in 0..k::LIMBS {
        out[2 * i] = value[i] as u32;
        out[2 * i + 1] = (value[i] >> 32) as u32;
    }
    out
}

/// The inverse of [`to_frame_words`].
pub fn from_frame_words(words: &[u32]) -> U256 {
    assert_eq!(words.len(), constants::ecrecover::VALUE_WORDS);
    let mut out = ZERO;
    for i in 0..k::LIMBS {
        out[i] = u64::from(words[2 * i]) | (u64::from(words[2 * i + 1]) << 32);
    }
    out
}

// ---------------------------------------------------------------------------
// The frame
// ---------------------------------------------------------------------------

/// The delegated function itself: read the frame's inputs and write its
/// outputs in place (`docs/spec/ecrecover.md` §2).
///
/// The one place the frame layout is interpreted on the host side. The
/// emulator calls it to execute the ecall and `crates/trace`'s witness builder
/// calls it to know what the circuit must prove; the guest SDK's software
/// fallback fills the *same* frame from its own copy of this arithmetic, which
/// is what makes the two paths bit-identical — neither derives an address, and
/// both hand the same 42 words to the same caller.
///
/// **On failure every output word is zero, the flag included.** That is the
/// circuit's rule too (stage prompt, must-be-exact 2): a forged "failure with
/// a live pubkey" has no witness.
pub fn apply_frame(words: &mut [u32]) {
    use constants::ecrecover as e;
    assert_eq!(
        words.len(),
        e::FRAME_WORDS,
        "an ecrecover frame is {} words",
        e::FRAME_WORDS
    );
    for i in 0..e::VALUE_WORDS {
        words[e::OFF_PUBKEY_X + i] = 0;
        words[e::OFF_PUBKEY_Y + i] = 0;
    }
    words[e::OFF_SUCCESS] = 0;

    let hash = from_frame_words(&words[e::OFF_HASH..e::OFF_HASH + e::VALUE_WORDS]);
    let v = words[e::OFF_V];
    let r = from_frame_words(&words[e::OFF_R..e::OFF_R + e::VALUE_WORDS]);
    let s = from_frame_words(&words[e::OFF_S..e::OFF_S + e::VALUE_WORDS]);

    if let Ok(q) = recover(&hash, v, &r, &s) {
        let x = to_frame_words(&q.x);
        let y = to_frame_words(&q.y);
        words[e::OFF_PUBKEY_X..e::OFF_PUBKEY_X + e::VALUE_WORDS].copy_from_slice(&x);
        words[e::OFF_PUBKEY_Y..e::OFF_PUBKEY_Y + e::VALUE_WORDS].copy_from_slice(&y);
        words[e::OFF_SUCCESS] = 1;
    }
}

/// The frame a call with these arguments starts from: the inputs written and
/// the outputs zero. What [`apply_frame`] turns into the answer.
pub fn frame_of(
    hash: &U256,
    v: u32,
    r: &U256,
    s: &U256,
) -> [u32; constants::ecrecover::FRAME_WORDS] {
    use constants::ecrecover as e;
    let mut words = [0u32; e::FRAME_WORDS];
    words[e::OFF_HASH..e::OFF_HASH + e::VALUE_WORDS].copy_from_slice(&to_frame_words(hash));
    words[e::OFF_V] = v;
    words[e::OFF_R..e::OFF_R + e::VALUE_WORDS].copy_from_slice(&to_frame_words(r));
    words[e::OFF_S..e::OFF_S + e::VALUE_WORDS].copy_from_slice(&to_frame_words(s));
    words
}
