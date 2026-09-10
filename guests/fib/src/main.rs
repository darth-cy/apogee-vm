#![no_std]
#![no_main]
//! Fibonacci: the smallest guest that reads something, computes something and
//! commits something. It is the toolchain's canary — nothing else in `guests/`
//! builds, loads or runs if this does not.
//!
//! # fd 0, the public input
//!
//! ```text
//!           0..4     n               u32 LE; how many steps to take
//! ```
//!
//! Exactly four bytes. A shorter stream is a fault rather than a default,
//! because a guest that proceeds on a partly-filled buffer proves a statement
//! about zeroes.
//!
//! # fd 1, the public output
//!
//! ```text
//!           0..4     f_n             u32 LE, wrapping
//! ```
//!
//! `f_0 = 0` and `f_1 = 1`. The addition wraps rather than panicking, so an `n`
//! above 47 — the last index whose term fits in 32 bits — commits the sequence
//! modulo `2^32`. That is an ordinary input with an ordinary answer, not a
//! failed execution.
//!
//! # fd 2 and fd 3
//!
//! Unused. There is nothing to diagnose, and nothing a hint could shorten:
//! `f_n` costs a verifier exactly as much to check as to compute.

guest_sdk::entry!(main);

fn main() {
    let mut n = [0u8; 4];
    assert_eq!(
        guest_sdk::read_input(&mut n),
        4,
        "fib: public input is one u32"
    );
    let n = u32::from_le_bytes(n);

    let mut a: u32 = 0;
    let mut b: u32 = 1;
    for _ in 0..n {
        let next = a.wrapping_add(b);
        a = b;
        b = next;
    }
    guest_sdk::commit(&a.to_le_bytes());
}
