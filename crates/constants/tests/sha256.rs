//! `constants::sha256`'s two tables, re-derived rather than trusted.
//!
//! FIPS 180-4 §4.2.2 and §5.3.3 define both by a generator: the initial hash
//! value is the first 32 bits of the fractional parts of the **square** roots of
//! the first eight primes, and the round constants are the same of the **cube**
//! roots of the first sixty-four. A copied table is a table nobody checked, so
//! this file runs the generators and holds the constants to them.
//! `crates/constraints`, `crates/emulator` and `crates/guest-sdk` all read the
//! constants and none defines its own.
//!
//! **The arithmetic is exact and integer.** `floor(frac(sqrt(p)) · 2^32)` is
//! `isqrt(p · 2^64) mod 2^32` and `floor(frac(cbrt(p)) · 2^32)` is
//! `icbrt(p · 2^96) mod 2^32`, both of which fit `u128` for every prime this
//! table uses — `311 · 2^96` is about `2^104`. Doing it in `f64` would put the
//! last of the thirty-two bits inside the mantissa's rounding, which for a table
//! whose whole purpose is those thirty-two bits is not good enough.

use constants::sha256;

/// The first `n` primes.
fn primes(n: usize) -> Vec<u128> {
    let mut out = Vec::with_capacity(n);
    let mut c = 2u128;
    while out.len() < n {
        if (2..c)
            .take_while(|d| d * d <= c)
            .all(|d| !c.is_multiple_of(d))
        {
            out.push(c);
        }
        c += 1;
    }
    out
}

/// `floor(x^(1/k))` for a `u128` `x`, by binary search. Exact: the predicate is
/// integer, so the answer is the largest `r` with `r^k <= x`.
fn iroot(x: u128, k: u32) -> u128 {
    let power = |r: u128| -> Option<u128> {
        let mut acc = 1u128;
        for _ in 0..k {
            acc = acc.checked_mul(r)?;
        }
        Some(acc)
    };
    let (mut lo, mut hi) = (0u128, 1u128 << (128 / k as u128 as u32));
    while lo + 1 < hi {
        let mid = lo + (hi - lo) / 2;
        match power(mid) {
            Some(p) if p <= x => lo = mid,
            _ => hi = mid,
        }
    }
    lo
}

/// The first 32 bits of the fractional part of `p^(1/k)`.
fn fractional_bits(p: u128, k: u32) -> u32 {
    // `frac(p^(1/k)) · 2^32 = p^(1/k) · 2^32 − floor(p^(1/k)) · 2^32`, and
    // `p^(1/k) · 2^32` is `(p · 2^(32k))^(1/k)`, so one integer root does it.
    let scaled = iroot(p << (32 * k), k);
    (scaled & 0xffff_ffff) as u32
}

#[test]
fn the_initial_hash_value_is_the_square_roots_of_the_first_eight_primes() {
    let want: Vec<u32> = primes(sha256::STATE_WORDS)
        .into_iter()
        .map(|p| fractional_bits(p, 2))
        .collect();
    assert_eq!(want.as_slice(), &sha256::IV, "FIPS 180-4 §5.3.3");
    // The generator is worth nothing if it is wrong the same way the table is,
    // so one entry is pinned against the standard's own printed value.
    assert_eq!(want[0], 0x6a09_e667, "sqrt(2)'s fractional part");
    assert_eq!(want[7], 0x5be0_cd19, "sqrt(19)'s");
}

#[test]
fn the_round_constants_are_the_cube_roots_of_the_first_sixty_four_primes() {
    let want: Vec<u32> = primes(sha256::ROUNDS)
        .into_iter()
        .map(|p| fractional_bits(p, 3))
        .collect();
    assert_eq!(
        want.as_slice(),
        &sha256::ROUND_CONSTANTS,
        "FIPS 180-4 §4.2.2"
    );
    assert_eq!(want[0], 0x428a_2f98, "cbrt(2)'s fractional part");
    assert_eq!(want[63], 0xc671_78f2, "cbrt(311)'s");
}

// The shapes, as **compile-time** assertions rather than a test: each is a
// constant compared against a constant, which clippy rightly refuses as a
// runtime `assert!` and which a `const` block states exactly.
//
// Each number is one a reader can check against FIPS 180-4's own text, and each
// is what a frame or a circuit is sized by.
const _: () = assert!(sha256::STATE_WORDS == 8);
const _: () = assert!(sha256::BLOCK_WORDS == 16);
const _: () = assert!(sha256::ROUNDS == 64);

// S26e's frame: one call is four rounds, so a compression is sixteen calls, and
// the frame is the group word, the eight working variables and the sixteen-word
// schedule window — the window being exactly one block wide, which is what lets
// call 0's window *be* the block.
const _: () = assert!(sha256::ROUNDS_PER_CALL == 4);
const _: () = assert!(sha256::GROUPS * sha256::ROUNDS_PER_CALL == sha256::ROUNDS);
const _: () = assert!(sha256::GROUP_WORD == 0);
const _: () = assert!(sha256::STATE_WORD == 1);
const _: () = assert!(sha256::WINDOW_WORD == 9);
const _: () = assert!(sha256::FRAME_WORDS == 25);
const _: () = assert!(sha256::FRAME_BYTES == 100);
