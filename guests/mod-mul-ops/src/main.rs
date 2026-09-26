#![no_std]
#![no_main]
//! S26's guest for the `MOD_MUL` delegation: `256`-bit modular multiplication
//! over a **witnessed** modulus, checked two ways in one binary.
//!
//! # The two halves, and why both
//!
//! **The ABI, called by name.** [`guest_sdk::recursion::mod_mul`] over frames
//! this guest writes itself, so the modulus is a value and not a constant:
//! `2^32` and the Mersenne prime `2^61 - 1`, with the curve half below
//! contributing a third, secp256k1's `p`. That is what
//! `docs/spec/delegation.md` §14.1 means by a witnessed modulus.
//!
//! **Both of this half's moduli fit a `u64`, and that is the whole reason they
//! were chosen.** The ABI's fall-through convention requires every caller to
//! have a software path (§2): under `qemu-riscv32` the ecall answers `-ENOSYS`
//! and the caller runs its own. A 256-bit modulus would make that path a
//! second 512-bit long division living in a guest — a duplicate of
//! `emulator::mod_mul_frame` with no way to share code with it — where a
//! `u64` modulus makes it one `u128` expression. The circuit's coverage over
//! 256-bit moduli is `crates/checker/tests/mod_mul.rs`', whose honest rows are
//! a secp256k1 product and a BN254 one, and the executor's is its own unit
//! tests'. This guest is the *ABI's* test, not the arithmetic's.
//!
//! **The seam, called by nobody.** `k256`'s group arithmetic, which reaches the
//! delegation through `guests/vendor/k256`'s patched `FieldElement10x26::mul`
//! and `::square` and names no shim at all. This is the same shape a
//! `revm-precompile` `ecrecover` runs, and it is the only test of the patch's
//! `pack`/`unpack`: the 10×26 limbs a field element is stored in are not the
//! 8×32 limbs the frame carries, and under every executor but this VM's the
//! ecall answers `-ENOSYS` and the software multiply runs instead — so a host
//! test could not see the delegated path at all.
//!
//! # fd 0, fd 1, fd 2, fd 3
//!
//! Unused. `EXIT` and `PRECOMPILE_MOD_MUL` are this guest's only ecalls, which
//! is what keeps it provable.
//!
//! # The result
//!
//! The exit status, `a0`: **12**, one per check passed but the first, as every
//! fixture guest here reports it, or `200 + i` on the first that fails — which
//! names the check rather than leaving a count one short. It is the same status
//! under both executors, which is what §3 rule 6 of
//! `docs/guest-program-manual.md` asks of a delegation's caller.

use guest_sdk::recursion::{mod_mul, ModMulFrame};
use guest_sdk::{entry, exit};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::ProjectivePoint;

entry!(main);

/// `2^32`, and `2^61 - 1`: the two moduli this half calls the delegation with.
///
/// Both fit a `u64`, so the software path is one `u128` expression. `2^32` is
/// where a product's wrap is arithmetic a reader can do; `2^61 - 1` is a prime
/// wide enough that a 61-bit reduction is not the trivial one.
const TWO_32: u64 = 1 << 32;
const MERSENNE: u64 = (1 << 61) - 1;

/// The compressed SEC1 encodings of `G`, `2G`, `3G` and `7G`. Absolute values,
/// not identities: an identity-only test passes under a multiply that is wrong
/// the same way everywhere.
const G1: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const G2: &str = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
const G3: &str = "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";
const G7: &str = "025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc";

/// An operand with every byte of its eight low limbs set to something, below
/// both moduli, so a reduction has work to do.
const A: u64 = 0x1BB8_E645_AE21_6DA7;
const B: u64 = 0x0123_4567_89AB_CDEF;

/// `a · b mod m`, delegated, over three operands that fit a `u64`.
///
/// `false` from the shim is exactly `-ENOSYS` — this executor has no `MOD_MUL`
/// circuit, which is every executor but this VM's — and then the answer comes
/// from `u128`. **That is the ABI's fall-through convention, not a shortcut**
/// (`docs/spec/delegation.md` §2): a caller with no software path is a binary
/// that runs on one executor, and every check below is the same check either
/// way.
fn mul_mod(m: u64, a: u64, b: u64) -> u64 {
    let mut frame = ModMulFrame::of(&limbs(m), &limbs(a), &limbs(b));
    match mod_mul(&mut frame) {
        true => value(&frame.result()),
        false => ((a as u128 * b as u128) % m as u128) as u64,
    }
}

/// A `u64` as the frame's eight little-endian 32-bit limbs.
fn limbs(x: u64) -> [u32; 8] {
    [x as u32, (x >> 32) as u32, 0, 0, 0, 0, 0, 0]
}

/// [`limbs`]' inverse. The six high limbs must be zero, which they are for a
/// result below a modulus that fits a `u64`; a nonzero one is the delegation
/// answering something impossible, and there is no honest way to continue.
fn value(w: &[u32; 8]) -> u64 {
    for high in &w[2..] {
        if *high != 0 {
            exit(252);
        }
    }
    w[0] as u64 | ((w[1] as u64) << 32)
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
    let mut check = |i: i32, ok: bool| {
        if !ok {
            exit(200 + i);
        }
        passed += 1;
    };

    // --- The ABI, over two moduli read from the frame.
    //
    // Every expectation here is a **literal**, not a second computation of the
    // same product, so none of these checks is vacuous on either executor.

    // `7 · 9 mod 2^32 = 63`: arithmetic a reader can do.
    check(0, mul_mod(TWO_32, 7, 9) == 63);
    // And one that wraps: `(2^32 - 1)^2 = 2^64 - 2^33 + 1`, so mod `2^32` it
    // is 1.
    check(1, mul_mod(TWO_32, TWO_32 - 1, TWO_32 - 1) == 1);
    // `2^31 · 2^31 = 2^62 = 2·(2^61 - 1) + 2`, so mod the Mersenne prime it
    // is 2.
    check(2, mul_mod(MERSENNE, 1 << 31, 1 << 31) == 2);
    // `(m - 1)^2 mod m = 1`: the largest operand the modulus admits, squared.
    check(3, mul_mod(MERSENNE, MERSENNE - 1, MERSENNE - 1) == 1);

    // The two rows where a wrong quotient is least visible.
    check(4, mul_mod(MERSENNE, A, 1) == A);
    check(5, mul_mod(MERSENNE, A, 0) == 0);

    // Commutativity, and — the point of a witnessed modulus — the same
    // operands under two moduli giving two answers, which says the modulus is
    // read from the frame and not from the circuit.
    //
    // The second call is also the one row here whose **operands are far above
    // its modulus**: `A` and `B` are about `2^61` against `2^32`, so the
    // quotient is 85 bits. `docs/spec/delegation.md` §14.3 says that is fine as
    // long as the quotient fits eight limbs, and this is where that is run.
    let mersenne = mul_mod(MERSENNE, A, B);
    check(6, mul_mod(MERSENNE, B, A) == mersenne);
    check(7, mul_mod(TWO_32, A, B) != mersenne);

    // --- The seam, through `k256`'s group arithmetic.

    let g = ProjectivePoint::GENERATOR;
    check(8, is(&g, G1));
    check(9, is(&g.double(), G2));
    check(10, is(&(g.double() + g), G3));
    // Two routes to `7G`, so a wrong field multiply would have to be wrong
    // identically on both: `4G + 2G + G`, and `4G + 3G`.
    let seven_g = g.double().double() + g.double() + g;
    check(11, is(&seven_g, G7));
    check(12, g.double().double() + (g.double() + g) == seven_g);

    exit(passed - 1);
}
