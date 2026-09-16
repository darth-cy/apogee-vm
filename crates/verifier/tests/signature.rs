//! S16 acceptance 12: the one verification entry point takes the verifying
//! key, the proof and the public inputs, and nothing else. Pinned at compile
//! time: a changed signature does not build.

use verifier::{verify_shard, PublicInputs, ShardProof, VerifyError, VerifyingKey};

const _: fn(&VerifyingKey, &ShardProof, &PublicInputs) -> Result<(), VerifyError> = verify_shard;

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
    let entry: fn(&VerifyingKey, &ShardProof, &PublicInputs) -> Result<(), VerifyError> =
        verify_shard;
    let _ = entry;
}

/// The SRS verifier's bytes are S07's layout, and every point goes back
/// through its validating decoder.
#[test]
fn the_srs_verifier_round_trips_through_its_layout() {
    use curve::{G1Affine, G2Affine};
    let vsrs = srs::SrsVerifier {
        g1_gen: G1Affine::GENERATOR,
        g2_gen: G2Affine::GENERATOR,
        g2_tau: G2Affine::GENERATOR,
    };
    let bytes = verifier::encode_srs_verifier(&vsrs);
    assert_eq!(&bytes[..64], &G1Affine::GENERATOR.to_bytes());
    assert_eq!(verifier::decode_srs_verifier(&bytes), Some(vsrs));
    let mut off = bytes;
    off[0] ^= 1;
    assert_eq!(
        verifier::decode_srs_verifier(&off),
        None,
        "(0, 2) is not a point"
    );
}
