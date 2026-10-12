//! Every verification entry point takes the verifying key, the proof and the
//! public inputs, and nothing else. Pinned at compile time: a changed signature
//! does not build.

use verifier::{
    verify_block, verify_shard, BlockProof, PublicInputs, ShardProof, VerifyError, VerifyingKey,
};

const _: fn(&VerifyingKey, &ShardProof, &PublicInputs) -> Result<(), VerifyError> = verify_shard;
const _: fn(&VerifyingKey, &BlockProof, &PublicInputs) -> Result<(), VerifyError> = verify_block;

/// The no_std core's three parts, which both entry points compose. Two
/// of them are per statement and one is per shard, which is the whole point of
/// the split: a block runs `derive_global_phase` and `verify_global_memory`
/// once each, and `verify_shard_local` once a shard.
const _: fn(&VerifyingKey, &PublicInputs) -> Result<verifier_core::GlobalChallenges, VerifyError> =
    verifier_core::derive_global_phase;
const _: fn(
    &VerifyingKey,
    &verifier_core::GlobalChallenges,
    &PublicInputs,
) -> Result<(), VerifyError> = verifier_core::verify_global_memory;
const _: fn(
    &VerifyingKey,
    &verifier_core::GlobalChallenges,
    &ShardProof,
    &PublicInputs,
) -> Result<verifier_core::ColumnClaims, VerifyError> = verifier_core::verify_shard_local;

/// The no_std core's entry point takes the same three and returns the column
/// claims the wrapper discharges.
const _: fn(
    &VerifyingKey,
    &ShardProof,
    &PublicInputs,
) -> Result<verifier_core::ColumnClaims, VerifyError> = verifier_core::reduce_shard;
