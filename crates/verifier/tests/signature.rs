//! S16 acceptance 12 and S20 must-be-exact 2: every verification entry point
//! takes the verifying key, the proof and the public inputs, and nothing else
//! — master rule 6. Pinned at compile time: a changed signature does not build.

use verifier::{
    verify_block, verify_shard, BlockProof, PublicInputs, ShardProof, VerifyError, VerifyingKey,
};

const _: fn(&VerifyingKey, &ShardProof, &PublicInputs) -> Result<(), VerifyError> = verify_shard;
const _: fn(&VerifyingKey, &BlockProof, &PublicInputs) -> Result<(), VerifyError> = verify_block;

/// The no_std core's two halves, which both entry points compose (S20).
const _: fn(&VerifyingKey, &PublicInputs) -> Result<verifier_core::GlobalChallenges, VerifyError> =
    verifier_core::derive_global_phase;
const _: fn(
    &VerifyingKey,
    &verifier_core::GlobalChallenges,
    &ShardProof,
    &PublicInputs,
) -> Result<verifier_core::OpeningClaim, VerifyError> = verifier_core::verify_shard_local;

/// The no_std core's entry point takes the same three and returns the opening
/// claim the wrapper finishes.
const _: fn(
    &VerifyingKey,
    &ShardProof,
    &PublicInputs,
) -> Result<verifier_core::OpeningClaim, VerifyError> = verifier_core::reduce_shard;

/// The pins above are the test; this one says so at run time too.
#[test]
fn the_verifier_entry_points_take_the_key_the_proof_and_the_public_inputs() {
    let shard: fn(&VerifyingKey, &ShardProof, &PublicInputs) -> Result<(), VerifyError> =
        verify_shard;
    let block: fn(&VerifyingKey, &BlockProof, &PublicInputs) -> Result<(), VerifyError> =
        verify_block;
    let _ = (shard, block);
}

/// The SRS verifier's bytes are S07's layout, and every point goes back
/// through its validating decoder.
#[test]
fn the_srs_verifier_round_trips_through_its_layout() {
    use curve::{G1Affine, G2Affine};
    // Three distinct points, so a decoder that read one field at another's
    // offset would not give the same verifier back.
    let tau = G2Affine::GENERATOR.double();
    let vsrs = srs::SrsVerifier {
        g1_gen: G1Affine::GENERATOR,
        g2_gen: G2Affine::GENERATOR,
        g2_tau: tau,
    };
    let bytes = verifier::encode_srs_verifier(&vsrs);
    assert_eq!(&bytes[..64], &G1Affine::GENERATOR.to_bytes());
    assert_eq!(&bytes[64..192], &G2Affine::GENERATOR.to_bytes());
    assert_eq!(&bytes[192..], &tau.to_bytes());
    assert_eq!(verifier::decode_srs_verifier(&bytes), Some(vsrs));
    // One low bit of a coordinate of each point, flipped: none is a point.
    for (at, which) in [(0, "g1_gen"), (64, "g2_gen"), (192 + 96, "g2_tau")] {
        let mut off = bytes;
        off[at] ^= 1;
        assert_eq!(
            verifier::decode_srs_verifier(&off),
            None,
            "{which} with a bit flipped is not a point"
        );
    }
}
