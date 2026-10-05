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

/// Iota touches four byte positions of a lane and no others, which is what makes
/// the circuit's iota four `XOR8` obligations instead of eight — and, with the
/// fraction tree's power-of-two padding, what keeps that channel at 1,024 leaves
/// instead of 2,048 (`docs/spec/delegation-circuits.md` §2.4).
///
/// `constants::keccak::IOTA_BYTES_ARE_THE_ONLY_ONES` asserts the same thing at
/// compile time. This is the reading that says *why*: the LFSR sets only the bits
/// `2^j - 1`, so the bytes it can reach are 0, 1, 3 and 7.
#[test]
fn iota_touches_four_bytes_of_a_lane() {
    let bits: Vec<u32> = (0..7).map(|j| (1u32 << j) - 1).collect();
    let mut want: Vec<usize> = bits.iter().map(|b| (*b / 8) as usize).collect();
    want.sort_unstable();
    want.dedup();
    assert_eq!(want, keccak::IOTA_BYTES.to_vec());
    let mask = keccak::IOTA_BYTES
        .iter()
        .fold(0u64, |m, b| m | 0xffu64 << (8 * b));
    for (r, constant) in keccak::ROUND_CONSTANTS.iter().enumerate() {
        assert_eq!(constant & !mask, 0, "round constant {r}");
    }
    // And the mask is not vacuous: every byte position outside it exists.
    assert_eq!(keccak::IOTA_BYTES.len(), 4);
}

#[test]
fn the_shapes_agree() {
    assert_eq!(keccak::STATE_BITS, 1600);
    assert_eq!(keccak::STATE_BYTES, 200);
    assert_eq!(keccak::STATE_WORDS, 50);
    assert_eq!(keccak::LANES * keccak::LANE_BITS, keccak::STATE_BITS);
    assert_eq!(keccak::STATE_WORDS * 4, keccak::STATE_BYTES);
    // The frame is the round selector and the state, and nothing else: one
    // invocation is one round since S26d (`docs/spec/delegation-circuits.md` §2).
    assert_eq!(keccak::ROUND_WORD, 0);
    assert_eq!(keccak::STATE_WORD, 1);
    assert_eq!(keccak::FRAME_WORDS, 51);
    assert_eq!(keccak::FRAME_BYTES, 204);
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
