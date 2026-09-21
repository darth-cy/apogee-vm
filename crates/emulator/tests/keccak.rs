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
//! how a 200-byte frame becomes 25 lanes and back, and a swapped half would
//! give a permutation that is self-consistent and wrong.

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
fn a_corpus_of_states_matches() {
    for seed in 0..64 {
        let start = state(seed);
        let (mut ours, mut theirs) = (start, start);
        keccak_f(&mut ours);
        reference(&mut theirs);
        assert_eq!(ours, theirs, "state {seed} diverges");
    }
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
        let words: [u32; keccak::FRAME_WORDS] = core::array::from_fn(|_| rng.next_u64() as u32);
        assert_eq!(words_of(&lanes_of(&words)), words);
    }
    let lanes = state(13);
    assert_eq!(lanes_of(&words_of(&lanes)), lanes);
}

#[test]
fn a_frame_word_is_its_lane_half() {
    let lanes = state(17);
    let words = words_of(&lanes);
    for (i, lane) in lanes.iter().enumerate() {
        assert_eq!(words[2 * i], *lane as u32, "lane {i}'s low half");
        assert_eq!(
            words[2 * i + 1],
            (*lane >> 32) as u32,
            "lane {i}'s high half"
        );
    }
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
