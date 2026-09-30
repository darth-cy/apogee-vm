//! The reference permutation, against `tiny-keccak`.
//!
//! `emulator::keccak_f` is the one keccak-f[1600] the host side of this
//! repository has: the delegation ecall runs it, and every fixture the
//! delegation circuit is checked against comes out of it. This suite holds it
//! to an outside implementation on the zero-state KAT and on a corpus wide
//! enough that a wrong rho offset, a wrong pi map or a dropped round constant
//! cannot survive — one round at a time, so a divergence names its round
//! rather than the whole permutation.
//!
//! The frame/lane packing is checked here too: `lanes_of` and `words_of` are
//! how a 200-byte state becomes 25 lanes and back, and a swapped half would
//! give a permutation that is self-consistent and wrong.
//!
//! Since S26d the unit one invocation performs is `emulator::keccak_round`, so
//! that is what the last two tests hold: 24 of them are the permutation, and a
//! round differs from another exactly when its round constant does — which is
//! **not** the same as "pairwise distinct", the LFSR repeating twice.

use constants::keccak;
use emulator::{keccak_f, lanes_of, words_of};
use test_support::Rng;

/// `tiny-keccak`'s permutation over the same lane order.
fn reference(lanes: &mut [u64; keccak::LANES]) {
    tiny_keccak::keccakf(lanes);
}

/// A pseudo-random state, seeded so a failure repeats.
fn state(seed: u64) -> [u64; keccak::LANES] {
    let mut rng = Rng::new(seed);
    core::array::from_fn(|_| rng.next_u64())
}

#[test]
fn the_zero_state_kat_matches() {
    let mut ours = [0u64; keccak::LANES];
    let mut theirs = [0u64; keccak::LANES];
    keccak_f(&mut ours);
    reference(&mut theirs);
    assert_eq!(ours, theirs);
    // The first lane of keccak-f(0) is a published value; a permutation that
    // agreed with a wrong oracle would still fail here.
    assert_eq!(ours[0], 0xf1258f7940e1dde7);
    assert_eq!(ours[1], 0x84d5ccf933c0478a);
    assert_eq!(ours[24], 0xeaf1ff7b5ceca249);
}

#[test]
fn every_single_bit_state_matches() {
    // One bit set, each of the 1600 in turn: the sparsest inputs there are,
    // and the ones a wrong rotation offset or pi map shows up in first.
    for bit in 0..keccak::STATE_BITS {
        let mut start = [0u64; keccak::LANES];
        start[bit / 64] = 1u64 << (bit % 64);
        let (mut ours, mut theirs) = (start, start);
        keccak_f(&mut ours);
        reference(&mut theirs);
        assert_eq!(ours, theirs, "the state with only bit {bit} set diverges");
    }
}

#[test]
fn iterating_the_permutation_matches() {
    // 64 applications: a round constant used at the wrong round agrees with
    // the reference on one application only by coincidence, and never twice.
    let (mut ours, mut theirs) = (state(7), state(7));
    for i in 0..64 {
        keccak_f(&mut ours);
        reference(&mut theirs);
        assert_eq!(ours, theirs, "application {i} diverges");
    }
}

#[test]
fn the_frame_packing_round_trips() {
    let mut rng = Rng::new(11);
    for _ in 0..64 {
        let words: [u32; keccak::STATE_WORDS] = core::array::from_fn(|_| rng.next_u64() as u32);
        assert_eq!(words_of(&lanes_of(&words)), words);
    }
    let lanes = state(13);
    assert_eq!(lanes_of(&words_of(&lanes)), lanes);
}

#[test]
fn the_frame_is_the_states_little_endian_bytes() {
    // `docs/spec/delegation.md` §4: the frame is the state in SHA-3 byte
    // order, lane `i` at bytes `8i..8i+8`, little-endian — so reading the
    // frame's words as bytes must give exactly `tiny-keccak`'s byte view.
    let lanes = state(23);
    let words = words_of(&lanes);
    let mut bytes = Vec::new();
    for w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    let mut want = Vec::new();
    for lane in lanes {
        want.extend_from_slice(&lane.to_le_bytes());
    }
    assert_eq!(bytes, want);
    assert_eq!(bytes.len(), keccak::STATE_BYTES);
}

/// The 24 rounds a guest now delegates compose to the permutation an oracle
/// computes, and each is the round the executor's own `keccak_round` performs.
///
/// This is the S26d invariant no other test reaches: `keccak_round` is what one
/// invocation does and what the circuit is checked against, and the only thing
/// that makes 24 of them a keccak-f is that they are the right 24 in the right
/// order. Comparing the composition against `tiny-keccak` is what says so.
#[test]
fn twenty_four_rounds_are_the_permutation() {
    let mut rng = Rng::new(29);
    for _ in 0..16 {
        let start: [u64; keccak::LANES] = core::array::from_fn(|_| rng.next_u64());
        let mut ours = start;
        for round in 0..keccak::ROUNDS {
            emulator::keccak_round(&mut ours, round);
        }
        let mut theirs = start;
        tiny_keccak::keccakf(&mut theirs);
        assert_eq!(ours, theirs, "24 rounds are not the permutation");
        // And a round is not the permutation: one application differs, so the
        // test above is not passing on a function that ignores its round.
        let mut one = start;
        emulator::keccak_round(&mut one, 0);
        assert_ne!(one, theirs);
    }
}

/// A round's index is load-bearing, and **exactly** as load-bearing as its round
/// constant: two rounds of one state agree if and only if their constants do.
///
/// That is the honest statement, and the interesting half is that it is not
/// "pairwise distinct". `theta`, `rho`, `pi` and `chi` do not read the round at
/// all — `keccak_round`'s last line is the only place it appears — so two rounds
/// differ only in lane `(0,0)`, by `RC[r1] ^ RC[r2]`. And the LFSR **repeats**:
/// `ROUND_CONSTANTS[5] == ROUND_CONSTANTS[22]` and `[6] == [20]`, so 24 rounds of
/// one state take **22** distinct values. A test asserting distinctness would
/// fail on Keccak itself, which is what this one exists to record.
///
/// What it pins for the circuit: the one-hot `round_sel` has to select the right
/// constant, and nothing else about the round depends on the index.
#[test]
fn a_round_is_its_round_constant() {
    let mut rng = Rng::new(31);
    let start: [u64; keccak::LANES] = core::array::from_fn(|_| rng.next_u64());
    let after: Vec<[u64; keccak::LANES]> = (0..keccak::ROUNDS)
        .map(|round| {
            let mut lanes = start;
            emulator::keccak_round(&mut lanes, round);
            lanes
        })
        .collect();
    for a in 0..keccak::ROUNDS {
        for b in 0..keccak::ROUNDS {
            assert_eq!(
                after[a] == after[b],
                keccak::ROUND_CONSTANTS[a] == keccak::ROUND_CONSTANTS[b],
                "rounds {a} and {b}"
            );
            // And the difference is lane (0,0) alone.
            for (i, (x, y)) in after[a].iter().zip(after[b].iter()).enumerate() {
                assert!(i == 0 || x == y, "rounds {a} and {b} differ at lane {i}");
            }
        }
    }
    let distinct: std::collections::BTreeSet<_> = after.iter().collect();
    assert_eq!(distinct.len(), 22, "the LFSR repeats twice over 24 rounds");
}
