//! The LogUp channels' verifier half: the derived challenge slots a shard's two
//! drawn ones imply, and the root check.
//!
//! `docs/spec/lookup.md` §2 and §8.

use constants::{challenge_slot, lookup_channel};
use field::Fr;

use crate::ExternalChallenges;

/// Insert every LogUp slot a circuit may name, from the two drawn per shard:
/// `g` and `β` themselves, then `β^2 … β^6`, **derived** because a gate
/// coefficient is one literal or one challenge and no power above the first is
/// either.
///
/// `decoder_width` is the artifact's decoder tuple width, and 0 for a circuit
/// with no decoder channel: at a nonzero width the derived
/// `LOOKUP_DECODER_NEUTRAL` is `g − Σ_{j < width} β^j`, the denominator of the
/// `MINUS_ONE` tuple a switched-off decoder row looks up.
///
/// Panics if a slot is already present, as `ExternalChallenges::insert` does,
/// or if `decoder_width` is above `lookup_channel::MAX_TUPLE`.
pub fn insert_lookup_challenges(
    into: &mut ExternalChallenges,
    g: Fr,
    beta: Fr,
    decoder_width: usize,
) {
    assert!(
        decoder_width <= lookup_channel::MAX_TUPLE,
        "a lookup tuple has at most {} columns, and the decoder's is {decoder_width}",
        lookup_channel::MAX_TUPLE
    );
    into.insert(challenge_slot::LOOKUP_G, g);
    let mut power = beta;
    for (i, slot) in challenge_slot::LOOKUP_BETA_POWERS.iter().enumerate() {
        into.insert(*slot, power);
        if i + 1 < challenge_slot::LOOKUP_BETA_POWERS.len() {
            power = power * beta;
        }
    }
    if decoder_width > 0 {
        let mut sum = Fr::ZERO;
        let mut power = Fr::ONE;
        for _ in 0..decoder_width {
            sum = sum + power;
            power = power * beta;
        }
        into.insert(challenge_slot::LOOKUP_DECODER_NEUTRAL, g - sum);
    }
}

/// A channel's root check, S15 must-be-exact 8: **both** conditions, on the
/// `(num, den)` pair the artifact's output map carries for that channel.
///
/// `num == 0` is the channel's claim. `den != 0` is the other half and it is
/// load-bearing: a fraction whose denominator is 0 propagates a zero
/// denominator to the root, and every numerator above it is then a multiple of
/// it, so `num == 0` alone accepts a witness that made one up.
pub fn channel_holds(root: (Fr, Fr)) -> bool {
    root.0 == Fr::ZERO && root.1 != Fr::ZERO
}
