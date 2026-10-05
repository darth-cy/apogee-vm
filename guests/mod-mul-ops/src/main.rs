#![no_std]
#![no_main]
//! The guest for the `MOD_MUL` delegation: Ethereum field
//! multiplication over four fixed moduli, checked four ways in one
//! binary.
//!
//! # The four halves, and why each
//!
//! **The ABI, called by name.** [`guest_sdk::recursion::mod_mul`] over frames
//! this guest writes itself, once per selector, so every modulus the circuit
//! holds is exercised at the frame level and not only through a library.
//! Every expectation here is a **literal** — `7·9 = 63`, `(m−1)² mod m = 1`,
//! `(m−1)·2 mod m = m−2` — so none of the checks is a second computation of
//! the thing it checks.
//!
//! **The software path, run rather than reserved.** §2 of
//! `docs/spec/delegation.md` requires a caller to have one, and here it
//! cannot be a single `u128` expression, as it can for a 64-bit modulus:
//! every selectable modulus is 256 bits, so the fallback is
//! [`soft_mul_mod`], a schoolbook multiply and a
//! shift-and-subtract division. Rather than leave forty lines nothing ever
//! runs, this guest runs **both** paths on every ABI check and compares —
//! which makes the fallback a live differential oracle against
//! `emulator::mod_mul_frame` instead of dead weight.
//!
//! **The `k256` seam, called by nobody.** secp256k1's group and scalar
//! arithmetic, which reach the delegation through `guests/vendor/k256`'s
//! patched `FieldElement10x26::mul`/`::square` and `Scalar::mul` and name no
//! shim at all. This is the same shape a `revm-precompile` `ecrecover` runs,
//! and it is the only test of the patches' packing: the 10×26 limbs a field
//! element is stored in are not the 8×32 limbs the frame carries, and under
//! every executor but this VM's the ecall answers `-ENOSYS` and upstream's
//! software multiply runs instead.
//!
//! **The `ark-bn254` seam, likewise.** BN254's two fields through
//! `guests/vendor/ark-ff`'s patched `MontBackend::mul_assign` and
//! `::square_in_place`, which is the shape `revm-precompile`'s `0x06`, `0x07`
//! and `0x08` precompiles run. It is the only place the **two-call**
//! Montgomery correction is exercised: arkworks holds `x·R` and the
//! delegation multiplies plain integers, so one arkworks multiply is two
//! invocations.
//!
//! **Nothing in this guest can observe whether a seam is live**, and that is
//! by construction — a delegated multiply and a software one agree on the
//! value. What observes it is the *invocation count*, pinned host-side in
//! `crates/emulator/tests/guests.rs`; if a patch stops routing, the count
//! moves and that test fails.
//!
//! # Input, advice and the journal
//!
//! Unused. `EXIT`, `PRECOMPILE_MOD_MUL` and, through `k256`'s points,
//! `PRECOMPILE_EC_ADD` are this guest's only ecalls, which keeps it provable.
//!
//! # The result
//!
//! The exit status, `a0`: one per check passed but the first, as every fixture
//! guest here reports it, or `200 + i` on the first that fails — which names
//! the check rather than leaving a count one short.

use ark_bn254::{Fq, Fr};
use ark_ff::{AdditiveGroup, Field};
use guest_sdk::recursion::{
    mod_mul, ModMulFrame, BN254_P, BN254_R, MODULI, SECP256K1_N, SECP256K1_P,
};
use guest_sdk::{entry, exit};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, Scalar};

entry!(main);

/// The compressed SEC1 encodings of `G`, `2G`, `3G` and `7G`. Absolute values,
/// not identities: an identity-only test passes under a multiply that is wrong
/// the same way everywhere.
const G1: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const G2: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const G3: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const G7: &str = "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc";

/// `a · b mod m` for the modulus `code` selects, computed **twice** and
/// compared: once by the delegation and once by [`soft_mul_mod`].
///
/// `false` from the shim is exactly `-ENOSYS` — an executor with no `MOD_MUL`
/// circuit, which is every executor but this VM's — and then the software
/// answer is the only one. That is the ABI's fall-through convention
/// (`docs/spec/delegation.md` §2), and running the software path on both
/// executors is what keeps it a path somebody has checked.
fn mul_mod(code: u32, a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let m = &MODULI[code as usize - 1];
    let soft = soft_mul_mod(m, a, b);
    let mut frame = ModMulFrame::of(code, a, b);
    if mod_mul(&mut frame) && frame.result() != soft {
        // The two implementations disagree. There is no honest way to pick
        // one, so the run ends naming the disagreement.
        exit(251);
    }
    soft
}

/// `a · b mod m` over eight little-endian 32-bit limbs, in software.
///
/// Schoolbook into sixteen lanes, then long division from the top bit. It
/// shares no line with `emulator::mod_mul_frame` or with the prover's fill,
/// which is what makes [`mul_mod`]'s comparison worth making.
fn soft_mul_mod(m: &[u32; 8], a: &[u32; 8], b: &[u32; 8]) -> [u32; 8] {
    let mut product = [0u64; 16];
    for (i, ai) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, bj) in b.iter().enumerate() {
            let total = product[i + j] + *ai as u64 * *bj as u64 + carry;
            product[i + j] = total & 0xffff_ffff;
            carry = total >> 32;
        }
        product[i + 8] += carry;
    }
    let mut rem = [0u64; 8];
    for bit in (0..512).rev() {
        let mut carry = (product[bit / 32] >> (bit % 32)) & 1;
        for word in rem.iter_mut() {
            let total = (*word << 1) | carry;
            *word = total & 0xffff_ffff;
            carry = total >> 32;
        }
        if carry == 1 || !below(&rem, m) {
            let mut borrow = 0i64;
            for (k, word) in rem.iter_mut().enumerate() {
                let d = *word as i64 - m[k] as i64 - borrow;
                borrow = i64::from(d < 0);
                *word = (d + if d < 0 { 1i64 << 32 } else { 0 }) as u64;
            }
        }
    }
    core::array::from_fn(|k| rem[k] as u32)
}

/// Whether `x < y` over eight little-endian limbs, `x` held in `u64` lanes.
fn below(x: &[u64; 8], y: &[u32; 8]) -> bool {
    for k in (0..8).rev() {
        if x[k] != y[k] as u64 {
            return x[k] < y[k] as u64;
        }
    }
    false
}

/// A small integer as eight little-endian limbs.
fn small(x: u32) -> [u32; 8] {
    [x, 0, 0, 0, 0, 0, 0, 0]
}

/// `m − n` for a small `n`, over eight limbs. Every selectable modulus has a
/// low limb far above any `n` this guest uses, so there is no borrow.
fn modulus_minus(code: u32, n: u32) -> [u32; 8] {
    let mut m = MODULI[code as usize - 1];
    m[0] -= n;
    m
}

/// A point's compressed SEC1 encoding, as lowercase hex, compared against
/// `want`. Written out rather than decoded, so the expectation in this file is
/// the form a reader can check against any other secp256k1 implementation.
fn is(point: &ProjectivePoint, want: &str) -> bool {
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

    // --- The ABI, over all four selectors, against literal expectations.
    for code in [SECP256K1_P, SECP256K1_N, BN254_P, BN254_R] {
        // `7 · 9 = 63`, below every modulus, so the reduction is the identity
        // and the arithmetic is one a reader can do.
        check(mul_mod(code, &small(7), &small(9)) == small(63));
        // `(m − 1)² mod m = 1`: the largest operand pair the frame admits,
        // and the row a bound off by one would refuse.
        let minus_one = modulus_minus(code, 1);
        check(mul_mod(code, &minus_one, &minus_one) == small(1));
        // `(m − 1) · 2 mod m = m − 2`: one subtraction's worth of reduction,
        // with an expectation that is not 1 and not a small number.
        check(mul_mod(code, &minus_one, &small(2)) == modulus_minus(code, 2));
    }

    // The same operands under two selectors give two answers, which is what
    // says the modulus is read from the selector and not fixed in the
    // circuit. `2^200` squared exceeds BN254's `r` and not secp256k1's `p`.
    let mut wide = [0u32; 8];
    wide[6] = 0x0100; // 2^200
    check(mul_mod(SECP256K1_P, &wide, &wide) != mul_mod(BN254_R, &wide, &wide));

    // --- The `k256` seam: secp256k1's base field, through group arithmetic.

    let g = ProjectivePoint::GENERATOR;
    check(is(&g, G1));
    check(is(&g.double(), G2));
    check(is(&(g.double() + g), G3));
    // Two routes to `7G`, so a wrong field multiply would have to be wrong
    // identically on both: `4G + 2G + G`, and `4G + 3G`.
    let seven_g = g.double().double() + g.double() + g;
    check(is(&seven_g, G7));
    check(g.double().double() + (g.double() + g) == seven_g);

    // --- The `k256` seam: secp256k1's scalar field.

    let seven = Scalar::from(7u64);
    let nine = Scalar::from(9u64);
    check(seven * nine == Scalar::from(63u64));
    // `−1` squared is 1, which at the scalar field is `(n − 1)²`: the widest
    // operands the type holds.
    check((-Scalar::ONE) * (-Scalar::ONE) == Scalar::ONE);
    // An inversion, which is an addition chain of some 250 multiplies and
    // squares and is where `ecrecover` spends its scalar cycles.
    let inv = Option::<Scalar>::from(seven.invert()).unwrap_or(Scalar::ZERO);
    check(seven * inv == Scalar::ONE);

    // --- The `ark-bn254` seam: both BN254 fields, through arkworks.

    check(Fq::from(7u64) * Fq::from(9u64) == Fq::from(63u64));
    check((-Fq::ONE) * (-Fq::ONE) == Fq::ONE);
    check(Fq::from(7u64).square() == Fq::from(49u64));
    let fq_inv = Fq::from(7u64).inverse().unwrap_or(Fq::ZERO);
    check(Fq::from(7u64) * fq_inv == Fq::ONE);

    check(Fr::from(7u64) * Fr::from(9u64) == Fr::from(63u64));
    check((-Fr::ONE) * (-Fr::ONE) == Fr::ONE);
    check(Fr::from(7u64).square() == Fr::from(49u64));
    let fr_inv = Fr::from(7u64).inverse().unwrap_or(Fr::ZERO);
    check(Fr::from(7u64) * fr_inv == Fr::ONE);

    exit(passed - 1);
}
