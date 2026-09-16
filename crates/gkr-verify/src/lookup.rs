//! The LogUp channels' verifier half: the derived challenge slots a shard's two
//! drawn ones imply, and the root check.
//!
//! `docs/spec/lookup.md` §2 and §8.

use constants::{challenge_slot, lookup_channel};
use constraints::CircuitArtifact;
use field::Fr;

use crate::ExternalChallenges;

/// Insert every LogUp slot a circuit may name, from the two drawn per shard:
/// `g` and `β` themselves, then `β^2 … β^6`, **derived** because a gate
/// coefficient is one literal or one challenge and no power above the first is
/// either.
///
/// The decoder's neutral slot is read **from the artifact**, not from the
/// caller: `LOOKUP_DECODER_NEUTRAL` is `g − Σ_{j < W} β^j` for `W` the width of
/// that circuit's decoder tuple, the denominator of the `MINUS_ONE` tuple a
/// switched-off decoder row looks up, and a circuit with no decoder channel gets
/// no such slot. A caller passing `W` itself could pass the wrong one, and the
/// gate would then mean something else on every padding row.
///
/// Panics if a slot is already present, as `ExternalChallenges::insert` does, or
/// if the artifact's decoder tuple is wider than `lookup_channel::MAX_TUPLE`.
/// Assumes an artifact that passed `CircuitArtifact::validate`, which is what
/// holds every lookup of a channel to one width.
pub fn insert_lookup_challenges(
    into: &mut ExternalChallenges,
    g: Fr,
    beta: Fr,
    a: &CircuitArtifact,
) {
    let decoder_width = a
        .lookups
        .iter()
        .find(|l| l.channel == lookup_channel::DECODER)
        .map_or(0, |l| l.tuple.len());
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
            power *= beta;
        }
    }
    if decoder_width > 0 {
        let mut sum = Fr::ZERO;
        let mut power = Fr::ONE;
        for _ in 0..decoder_width {
            sum += power;
            power *= beta;
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
