#![no_std]
#![no_main]
//! S26c's guest for the `EC_ADD` delegation: one complete point addition on
//! secp256k1 or BN254 G1, as three invocations, checked three ways.
//!
//! # The three halves, and why each
//!
//! **The ABI, called by name.** [`guest_sdk::recursion::ec_add_complete`] over
//! frames this guest writes itself, once per curve, so the three-group schedule
//! is driven at the frame level and not only through a library.
//!
//! **A software path, run rather than reserved.** §2 of
//! `docs/spec/delegation.md` requires a caller to have one. This guest's is
//! [`soft_add`] — Renes-Costello-Batina 2015 Algorithm 7 over eight-limb
//! schoolbook multiplication and long division, sharing no line with
//! `emulator::ec_add_frame` or with the prover's fill — and it runs on **every**
//! delegated addition and compares. Both paths compute the same formula, so
//! they agree on the projective representative and not merely on the point:
//! the comparison is limb for limb, which is the strongest form it can take.
//!
//! **Two library oracles, one per curve.** A formula both implementations here
//! got wrong the same way would survive the check above. `k256`'s
//! `ProjectivePoint` and `ark_bn254`'s `G1Projective` are the independent
//! answer, and the comparison is **projective** — `X3·z = x·Z3` and
//! `Y3·z = y·Z3` against the library's affine result — so it needs no modular
//! inverse in the guest and no assumption that two implementations pick the same
//! representative.
//!
//! `k256` is also the *seam*: its `ProjectivePoint::add` is this delegation's
//! own formula (`guests/vendor/k256/src/arithmetic/projective.rs`, RCB
//! Algorithm 7), so on this target the oracle's own addition is a delegated one
//! — which is why the literal SEC1 encodings of `2G`, `3G` and `7G` are here
//! too. Those are absolute values, not identities: an identity-only test passes
//! under an addition that is wrong the same way everywhere.
//!
//! # Completeness, which is the property worth testing
//!
//! Algorithm 7 is *complete*: `P + P`, `P + (-P)`, `P + O` and a
//! non-normalized `Z` all come out right, so the guest branches on nothing and
//! the circuit has no degenerate row. Every one of those cases is checked, and
//! they are the reason this delegation is a plain addition rather than an
//! addition and a separate doubling.
//!
//! # Input, advice and the journal
//!
//! Unused. `EXIT` and `PRECOMPILE_EC_ADD` are this guest's only ecalls — the
//! field multiplications the oracles run reach `MOD_MUL` as well, which is
//! `guests/mod-mul-ops`' business and not this guest's.
//!
//! # The result
//!
//! The exit status, `a0`: one per check passed but the first, or `200 + i` on
//! the first that fails.

use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use guest_sdk::recursion::{ec_add_complete, EcAddFrame, BN254_GROUPS, SECP256K1_GROUPS};
use guest_sdk::{entry, exit};
use k256::elliptic_curve::sec1::ToEncodedPoint;

entry!(main);

/// Limbs in a coordinate.
const L: usize = 8;

/// A coordinate: eight little-endian 32-bit limbs.
type V = [u32; L];

/// A point in homogeneous projective coordinates: `x = X/Z`, `y = Y/Z`.
type P = [V; 3];

/// secp256k1's `p = 2^256 - 2^32 - 977`, and BN254's `q`. Spelled here rather
/// than taken from `constants`, which is not this guest's dependency: what holds
/// them to the circuit's is that a wrong modulus makes every check below
/// disagree with its library oracle.
const SECP256K1_P: V = [
    0xffff_fc2f,
    0xffff_fffe,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
    0xffff_ffff,
];
const BN254_Q: V = [
    0xd87c_fd47,
    0x3c20_8c16,
    0x6871_ca8d,
    0x9781_6a91,
    0x8181_585d,
    0xb850_45b6,
    0xe131_a029,
    0x3064_4e72,
];

/// `b3 = 3b`: 21 for secp256k1's `b = 7`, 9 for BN254's `b = 3`.
const SECP256K1_B3: u32 = 21;
const BN254_B3: u32 = 9;

/// The compressed SEC1 encodings of `2G`, `3G` and `7G` on secp256k1.
const G2: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const G3: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const G7: &str = "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc";

// ---------------------------------------------------------------------------
// Eight-limb modular arithmetic, in software
// ---------------------------------------------------------------------------

/// Whether `x < y`.
fn below(x: &V, y: &V) -> bool {
    for k in (0..L).rev() {
        if x[k] != y[k] {
            return x[k] < y[k];
        }
    }
    false
}

/// `a + b mod m`, both operands below `m`.
fn add_mod(a: &V, b: &V, m: &V) -> V {
    let mut out = [0u32; L];
    let mut carry = 0u64;
    for k in 0..L {
        let total = a[k] as u64 + b[k] as u64 + carry;
        out[k] = total as u32;
        carry = total >> 32;
    }
    if carry != 0 || !below(&out, m) {
        out = sub_raw(&out, m);
    }
    out
}

/// `a - b` over eight limbs, wrapping.
fn sub_raw(a: &V, b: &V) -> V {
    let mut out = [0u32; L];
    let mut borrow = 0i64;
    for k in 0..L {
        let d = a[k] as i64 - b[k] as i64 - borrow;
        borrow = i64::from(d < 0);
        out[k] = (d + if d < 0 { 1i64 << 32 } else { 0 }) as u32;
    }
    out
}

/// `a - b mod m`, both operands below `m`.
fn sub_mod(a: &V, b: &V, m: &V) -> V {
    if below(a, b) {
        // `a + m - b`, and `a + m` may not fit in eight limbs, so the
        // subtraction goes first: `m - b` is below `m` and `a + (m - b)` is
        // below `2m`.
        let t = sub_raw(m, b);
        add_mod(a, &t, m)
    } else {
        sub_raw(a, b)
    }
}

/// `a * b mod m`: schoolbook into sixteen lanes, then long division from the
/// top bit. It shares no line with the executor's reduction or the prover's
/// fill, which is what makes the comparison in [`delegated_add`] worth making.
fn mul_mod(a: &V, b: &V, m: &V) -> V {
    let mut product = [0u64; 2 * L];
    for (i, ai) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, bj) in b.iter().enumerate() {
            let total = product[i + j] + *ai as u64 * *bj as u64 + carry;
            product[i + j] = total & 0xffff_ffff;
            carry = total >> 32;
        }
        product[i + L] += carry;
    }
    let mut rem = [0u64; L];
    for bit in (0..32 * 2 * L).rev() {
        let mut carry = (product[bit / 32] >> (bit % 32)) & 1;
        for word in rem.iter_mut() {
            let total = (*word << 1) | carry;
            *word = total & 0xffff_ffff;
            carry = total >> 32;
        }
        let narrow: V = core::array::from_fn(|k| rem[k] as u32);
        if carry == 1 || !below(&narrow, m) {
            let reduced = sub_raw(&narrow, m);
            for (k, word) in rem.iter_mut().enumerate() {
                *word = reduced[k] as u64;
            }
        }
    }
    core::array::from_fn(|k| rem[k] as u32)
}

/// `k * a mod m` for a small `k`.
fn scale_mod(k: u32, a: &V, m: &V) -> V {
    let mut scalar = [0u32; L];
    scalar[0] = k;
    mul_mod(&scalar, a, m)
}

/// `P + Q` by Renes-Costello-Batina 2015 Algorithm 7, in software: the
/// three groups the delegation splits the formula into, run back to back.
///
/// The group boundaries are kept rather than flattened, so this is the same
/// computation the three invocations perform and the comparison against them
/// can be limb for limb.
fn soft_add(p: &P, q: &P, m: &V, b3: u32) -> P {
    // Group 0.
    let xx = mul_mod(&p[0], &q[0], m);
    let yy = mul_mod(&p[1], &q[1], m);
    let zz = mul_mod(&p[2], &q[2], m);
    // Group 1.
    let m4 = mul_mod(&add_mod(&p[0], &p[1], m), &add_mod(&q[0], &q[1], m), m);
    let m5 = mul_mod(&add_mod(&p[1], &p[2], m), &add_mod(&q[1], &q[2], m), m);
    let m6 = mul_mod(&add_mod(&p[0], &p[2], m), &add_mod(&q[0], &q[2], m), m);
    // Group 2.
    let xy = sub_mod(&sub_mod(&m4, &xx, m), &yy, m);
    let yz = sub_mod(&sub_mod(&m5, &yy, m), &zz, m);
    let xz = sub_mod(&sub_mod(&m6, &xx, m), &zz, m);
    let bzz3 = scale_mod(b3, &zz, m);
    let ym = sub_mod(&yy, &bzz3, m);
    let yp = add_mod(&yy, &bzz3, m);
    let byz3 = scale_mod(b3, &yz, m);
    let xx3 = scale_mod(3, &xx, m);
    let bxx9 = scale_mod(3 * b3, &xx, m);
    [
        sub_mod(&mul_mod(&xy, &ym, m), &mul_mod(&byz3, &xz, m), m),
        add_mod(&mul_mod(&yp, &ym, m), &mul_mod(&bxx9, &xz, m), m),
        add_mod(&mul_mod(&yz, &yp, m), &mul_mod(&xx3, &xy, m), m),
    ]
}

// ---------------------------------------------------------------------------
// The delegation, and the comparison
// ---------------------------------------------------------------------------

/// `P + Q`, by the delegation and by [`soft_add`], compared limb for limb.
///
/// `false` from the shim is exactly `-ENOSYS` — an executor with no `EC_ADD`
/// circuit, which is every executor but this VM's — and then the software
/// answer is the only one. That is the ABI's fall-through convention
/// (`docs/spec/delegation.md` §2).
fn delegated_add(codes: &[u32; 3], p: &P, q: &P, m: &V, b3: u32) -> P {
    let soft = soft_add(p, q, m, b3);
    let mut frame = EcAddFrame::of(codes, p, q);
    if ec_add_complete(&mut frame, codes) && frame.result() != soft {
        // The two implementations disagree. There is no honest way to pick one,
        // so the run ends naming the disagreement.
        exit(251);
    }
    soft
}

/// Whether the projective point `a` and the **affine** point `(x, y)` are the
/// same point: `X·1 = x·Z` and `Y·1 = y·Z`.
///
/// Cross-multiplication, so no modular inverse runs in the guest and neither
/// side has to pick a representative. An `a` at infinity — `Z = 0` — matches
/// nothing affine, and that is the right answer: the libraries hand back an
/// affine point only for a point that has one.
fn same_as_affine(a: &P, x: &V, y: &V, m: &V) -> bool {
    let z = &a[2];
    !is_zero(z) && a[0] == mul_mod(x, z, m) && a[1] == mul_mod(y, z, m)
}

/// Whether every limb is zero.
fn is_zero(v: &V) -> bool {
    v.iter().all(|w| *w == 0)
}

/// The projective identity, `(0 : 1 : 0)`.
fn identity() -> P {
    [[0u32; L], one(), [0u32; L]]
}

/// `1` as eight limbs.
fn one() -> V {
    let mut v = [0u32; L];
    v[0] = 1;
    v
}

/// Thirty-two big-endian bytes as eight little-endian 32-bit limbs.
fn from_be(bytes: &[u8]) -> V {
    core::array::from_fn(|k| {
        let at = 32 - 4 * (k + 1);
        u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    })
}

/// A k256 point's affine coordinates, from its uncompressed SEC1 encoding:
/// `0x04 ‖ x ‖ y`, each thirty-two big-endian bytes. `None` at infinity, whose
/// encoding is the single byte `0x00`.
fn k256_affine(point: &k256::ProjectivePoint) -> Option<(V, V)> {
    let affine = point.to_affine();
    let encoded = affine.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    if bytes.len() != 65 {
        return None;
    }
    Some((from_be(&bytes[1..33]), from_be(&bytes[33..65])))
}

/// A BN254 field element's canonical value as eight little-endian limbs.
/// arkworks holds `x·R`; `into_bigint` is the conversion out of Montgomery
/// form, so what this returns is the integer the frame wants.
fn ark_limbs(f: &ark_bn254::Fq) -> V {
    let limbs = f.into_bigint().0;
    core::array::from_fn(|k| (limbs[k / 2] >> (32 * (k % 2))) as u32)
}

/// A BN254 G1 point's affine coordinates. `None` at infinity.
fn bn254_affine(point: &ark_bn254::G1Projective) -> Option<(V, V)> {
    let affine: ark_bn254::G1Affine = (*point).into();
    if affine.is_zero() {
        return None;
    }
    Some((ark_limbs(&affine.x), ark_limbs(&affine.y)))
}

/// A projective point built from a library's affine coordinates: `Z = 1`.
fn lift(x: V, y: V) -> P {
    [x, y, one()]
}

/// A k256 point's compressed SEC1 encoding against its lowercase hex.
fn is(point: &k256::ProjectivePoint, want: &str) -> bool {
    let encoded = point.to_affine().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() * 2 != want.len() {
        return false;
    }
    let digits = want.as_bytes();
    for (i, byte) in bytes.iter().enumerate() {
        if digits[2 * i] != nibble(byte >> 4) || digits[2 * i + 1] != nibble(byte & 0xf) {
            return false;
        }
    }
    true
}

/// A nibble as its lowercase hex digit.
fn nibble(n: u8) -> u8 {
    match n {
        0..=9 => b'0' + n,
        _ => b'a' + (n - 10),
    }
}

fn main() {
    let mut passed = 0i32;
    let mut i = 0i32;
    let mut check = |ok: bool| {
        if !ok {
            exit(200 + i);
        }
        i += 1;
        passed += 1;
    };

    // -----------------------------------------------------------------------
    // secp256k1, against k256
    // -----------------------------------------------------------------------

    let m = &SECP256K1_P;
    let b3 = SECP256K1_B3;
    let codes = &SECP256K1_GROUPS;

    let kg = k256::ProjectivePoint::GENERATOR;
    let (gx, gy) = k256_affine(&kg).unwrap_or(([0; L], [0; L]));
    let g = lift(gx, gy);

    // `G + G = 2G`, which is the completeness case a separate doubling formula
    // would exist for. Against k256's own `double`, and against the literal.
    let g2 = delegated_add(codes, &g, &g, m, b3);
    let k2 = kg.double();
    let (k2x, k2y) = k256_affine(&k2).unwrap_or(([0; L], [0; L]));
    check(same_as_affine(&g2, &k2x, &k2y, m));
    check(is(&k2, G2));

    // `2G + G = 3G`, the ordinary case, with `2G`'s `Z` **not** 1 — so the
    // formula is exercised on a non-normalized operand, which is the shape
    // every addition in a scalar multiplication has.
    let g3 = delegated_add(codes, &g2, &g, m, b3);
    let k3 = k2 + kg;
    let (k3x, k3y) = k256_affine(&k3).unwrap_or(([0; L], [0; L]));
    check(same_as_affine(&g3, &k3x, &k3y, m));
    check(is(&k3, G3));
    check(!is_zero(&g2[2]) && g2[2] != one());

    // Two routes to `7G`, so a wrong addition would have to be wrong
    // identically on both: `4G + 2G + G`, and `4G + 3G`.
    let g4 = delegated_add(codes, &g2, &g2, m, b3);
    let g6 = delegated_add(codes, &g4, &g2, m, b3);
    let g7 = delegated_add(codes, &g6, &g, m, b3);
    let g7b = delegated_add(codes, &g4, &g3, m, b3);
    let k7 = kg.double().double() + kg.double() + kg;
    let (k7x, k7y) = k256_affine(&k7).unwrap_or(([0; L], [0; L]));
    check(same_as_affine(&g7, &k7x, &k7y, m));
    check(same_as_affine(&g7b, &k7x, &k7y, m));
    check(is(&k7, G7));

    // `P + O = P`: completeness at the identity, on the right and on the left.
    let o = identity();
    let right = delegated_add(codes, &g, &o, m, b3);
    let left = delegated_add(codes, &o, &g, m, b3);
    check(same_as_affine(&right, &gx, &gy, m));
    check(same_as_affine(&left, &gx, &gy, m));

    // `O + O = O`, and `P + (-P) = O`: the two cases whose answer has `Z = 0`,
    // which is what an incomplete formula gets wrong.
    check(is_zero(&delegated_add(codes, &o, &o, m, b3)[2]));
    let neg_g = [gx, sub_mod(m, &gy, m), one()];
    check(is_zero(&delegated_add(codes, &g, &neg_g, m, b3)[2]));

    // -----------------------------------------------------------------------
    // BN254 G1, against ark-bn254
    // -----------------------------------------------------------------------

    let m = &BN254_Q;
    let b3 = BN254_B3;
    let codes = &BN254_GROUPS;

    let ag = ark_bn254::G1Projective::from(ark_bn254::G1Affine::generator());
    let (bx, by) = bn254_affine(&ag).unwrap_or(([0; L], [0; L]));
    let b = lift(bx, by);

    let b2 = delegated_add(codes, &b, &b, m, b3);
    let a2 = ag + ag;
    let (a2x, a2y) = bn254_affine(&a2).unwrap_or(([0; L], [0; L]));
    check(same_as_affine(&b2, &a2x, &a2y, m));

    let b3p = delegated_add(codes, &b2, &b, m, b3);
    let a3 = a2 + ag;
    let (a3x, a3y) = bn254_affine(&a3).unwrap_or(([0; L], [0; L]));
    check(same_as_affine(&b3p, &a3x, &a3y, m));
    check(!is_zero(&b2[2]) && b2[2] != one());

    // `7G` two ways, as on secp256k1.
    let b4 = delegated_add(codes, &b2, &b2, m, b3);
    let b6 = delegated_add(codes, &b4, &b2, m, b3);
    let b7 = delegated_add(codes, &b6, &b, m, b3);
    let b7b = delegated_add(codes, &b4, &b3p, m, b3);
    let a7 = a2 + a2 + a2 + ag;
    let (a7x, a7y) = bn254_affine(&a7).unwrap_or(([0; L], [0; L]));
    check(same_as_affine(&b7, &a7x, &a7y, m));
    check(same_as_affine(&b7b, &a7x, &a7y, m));

    // Completeness, as above.
    let o = identity();
    check(same_as_affine(
        &delegated_add(codes, &b, &o, m, b3),
        &bx,
        &by,
        m,
    ));
    check(is_zero(&delegated_add(codes, &o, &o, m, b3)[2]));
    let neg_b = [bx, sub_mod(m, &by, m), one()];
    check(is_zero(&delegated_add(codes, &b, &neg_b, m, b3)[2]));

    // The two curves are told apart by the selector and by nothing else: the
    // same limb pattern added to itself under the two code triples gives two
    // different points. `G`'s coordinates are below both moduli, BN254's `q`
    // being the smaller, so one operand pair serves both calls.
    let under_k1 = delegated_add(&SECP256K1_GROUPS, &b, &b, &SECP256K1_P, SECP256K1_B3);
    check(under_k1 != b2);

    exit(passed - 1);
}
