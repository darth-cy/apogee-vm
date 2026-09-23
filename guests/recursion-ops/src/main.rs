#![no_std]
#![no_main]
//! S23's guest: `field::Fr` arithmetic and `transcript::poseidon2_permute`,
//! checked in-guest against values the same two crates compute on the host.
//!
//! It is the fixture for both delegation families
//! (`docs/spec/delegation.md` §12 and §13), and it is the same binary under
//! both executors. Under `crates/emulator` every `Fr` multiply, add and
//! inverse becomes an `FR_ARITH` invocation and the permutation a `POSEIDON2`
//! one; under `qemu-riscv32` the same ecalls answer `-ENOSYS` and the software
//! paths inside `field` and `transcript` run instead. **The values are the
//! same either way** — they are the same code — which is what acceptances 1
//! and 2 ask of the fallback.
//!
//! It calls no shim by name. That is the point: `S26`'s verifier guest will
//! write ordinary `Fr` arithmetic, and this guest is the evidence that
//! ordinary `Fr` arithmetic is what the delegations accelerate.
//!
//! # fd 0, fd 1, fd 2, fd 3
//!
//! Unused. The guest reads nothing and writes nothing: `EXIT` and the two
//! delegation calls are its only ecalls, so a `write` would make the fixture
//! unprovable.
//!
//! # The result
//!
//! The exit status, `a0`: **9**, one per check passed, or `200 + i` on the
//! first that fails — which names the check rather than leaving a count one
//! short of what it should be.

use field::Fr;
use guest_sdk::{entry, exit};
use transcript::poseidon2_permute;

entry!(main);

/// The known-answer input of `docs/spec/transcript.md`: `[0, 1, 2]`.
const KAT_OUT: [&str; 3] = [
    "0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033",
    "0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570",
    "0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8",
];

/// Two wide operands, spelled as hex so every limb is exercised rather than
/// only the bottom one.
const X: &str = "0x2a3c09f0a58a7e8500e0a7eb8ef62abc402d111e41112ed49bd61b6e725b19f0";
const Y: &str = "0x1bb8e645ae216da753fe3ab1e35c59e38c49833d53bb80850216d0b17f4e44a5";

fn hex(s: &str) -> Fr {
    match Fr::from_hex(s) {
        Some(x) => x,
        None => exit(250),
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

    // The permutation, over the spec's known-answer state.
    let mut state = [Fr::ZERO, Fr::from_u64(1), Fr::from_u64(2)];
    poseidon2_permute(&mut state);
    for (i, want) in KAT_OUT.iter().enumerate() {
        check(i as i32, state[i] == hex(want));
    }

    // And once more, so the shard holds more than one invocation and the
    // permutation is shown to be a function of its input rather than of the
    // row it lands on.
    let mut again = [Fr::ZERO, Fr::from_u64(1), Fr::from_u64(2)];
    poseidon2_permute(&mut again);
    check(3, again == state);

    // `Fr`'s three delegated operations, each against what the other two say.
    let (x, y) = (hex(X), hex(Y));
    check(4, x + y == y + x);
    check(5, x * y == y * x);
    let inv = match x.inverse() {
        Some(i) => i,
        None => exit(251),
    };
    check(6, x * inv == Fr::ONE);
    // `inverse` of one is one, and of minus one is minus one: the two values
    // where a wrong Montgomery factor would be least visible.
    check(7, Fr::ONE.inverse() == Some(Fr::ONE));
    check(8, Fr::MINUS_ONE.inverse() == Some(Fr::MINUS_ONE));
    // Zero has no inverse, and the delegation is never asked for one.
    check(9, Fr::ZERO.inverse().is_none());

    exit(passed - 1);
}
