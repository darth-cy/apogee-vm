//! `constants::keccak`'s two tables, re-derived rather than trusted.
//!
//! The rho offsets and the iota round constants are the only keccak numbers in
//! this repository that are not shapes, and both have a short generator in the
//! Keccak reference. A copied table is a table nobody checked, so this file
//! runs the generators and holds the constants to them. `crates/constraints`,
//! `crates/emulator` and `crates/guest-sdk` all read the constants and none
//! defines its own.

use constants::keccak;

/// The rho offsets, from the reference's walk over the lanes.
///
/// Start at `(x, y) = (1, 0)` with `r[0][0] = 0`, and for `t = 0..24` set
/// `r[x][y] = (t + 1)(t + 2) / 2 mod 64` before stepping
/// `(x, y) <- (y, 2x + 3y mod 5)` — the same step the pi permutation takes.
fn rho_offsets() -> [[u32; 5]; 5] {
    let mut r = [[0u32; 5]; 5];
    let (mut x, mut y) = (1usize, 0usize);
    for t in 0..24u32 {
        r[y][x] = ((t + 1) * (t + 2) / 2) % 64;
        let next = (y, (2 * x + 3 * y) % 5);
        x = next.0;
        y = next.1;
    }
    r
}

/// One bit of the iota LFSR: the reference's `rc(t)`.
///
/// `R` is eight bits with `R[0]` in the low position; each step shifts left and,
/// when the shifted-out bit is set, xors the feedback mask `0x171` — bits 0, 4,
/// 5 and 6 of the polynomial, plus the bit 8 the shift produced.
fn rc(t: u32) -> bool {
    let t = t % 255;
    if t == 0 {
        return true;
    }
    let mut r: u16 = 1;
    for _ in 0..t {
        r <<= 1;
        if r & 0x100 != 0 {
            r ^= 0x171;
        }
    }
    r & 1 == 1
}

/// The iota round constants: bit `2^j - 1` of round `i` is `rc(j + 7i)`.
fn round_constants() -> [u64; keccak::ROUNDS] {
    let mut out = [0u64; keccak::ROUNDS];
    for (i, word) in out.iter_mut().enumerate() {
        for j in 0..7u32 {
            if rc(j + 7 * i as u32) {
                *word |= 1u64 << ((1u32 << j) - 1);
            }
        }
    }
    out
}

#[test]
fn the_rho_offsets_are_the_references() {
    assert_eq!(keccak::ROTATIONS, rho_offsets());
}

#[test]
fn the_round_constants_are_the_lfsrs() {
    assert_eq!(keccak::ROUND_CONSTANTS, round_constants());
}

#[test]
fn the_rho_walk_visits_every_lane_but_the_origin() {
    // 24 steps over 25 lanes, and `(0, 0)` is the one the walk never reaches —
    // which is why its offset is 0 and why iota's constant lands there.
    let (mut x, mut y) = (1usize, 0usize);
    let mut seen = [[false; 5]; 5];
    for _ in 0..24 {
        assert!(!seen[y][x], "the rho walk repeats a lane at ({x}, {y})");
        seen[y][x] = true;
        let next = (y, (2 * x + 3 * y) % 5);
        x = next.0;
        y = next.1;
    }
    assert!(!seen[0][0], "the walk must not reach the origin lane");
    assert_eq!(
        seen.iter().flatten().filter(|s| **s).count(),
        24,
        "the walk covers the other 24 lanes"
    );
    assert_eq!(keccak::ROTATIONS[0][0], 0);
}

#[test]
fn the_shapes_agree() {
    assert_eq!(keccak::STATE_BITS, 1600);
    assert_eq!(keccak::STATE_BYTES, 200);
    assert_eq!(keccak::FRAME_WORDS, 50);
    assert_eq!(keccak::LANES * keccak::LANE_BITS, keccak::STATE_BITS);
    assert_eq!(keccak::FRAME_WORDS * 4, keccak::STATE_BYTES);
    // keccak256's capacity is twice its digest, and rate + capacity is the
    // state: 136 + 64 = 200.
    assert_eq!(
        keccak::RATE_BYTES + 2 * keccak::DIGEST_BYTES,
        keccak::STATE_BYTES
    );
    // The rate is a whole number of lanes, which is what lets the sponge xor a
    // block in lane by lane.
    assert_eq!(keccak::RATE_BYTES % 8, 0);
}
