//! Shard verification: `verifier_core::reduce_shard`, then the shard's one
//! batched Mercury opening. `docs/spec/shard-proof.md` §6 is normative.
//!
//! This crate is the core's thin `std` wrapper and holds nothing else of the
//! protocol: it decodes the curve points the core carries as bytes, through
//! the curve's validating readers, and runs `pcs::batch_verify`, which is where
//! the base verifier's pairings happen. The `verifier` binary is the CLI.

use curve::{G1Affine, G2Affine};
use pcs::{batch_verify, MercuryCommitment, MercuryProof};
use srs::SrsVerifier;
use verifier_core::{check_ts_windows, derive_global_phase, verify_shard_local, OpeningClaim};

pub use verifier_core::{
    BlockProof, BlockReconciliation, PublicInputs, ShardProof, ShardRecord, VerifyError,
    VerifyingKey, OPENING_BYTES, SRS_VERIFIER_BYTES,
};

/// Verify one shard's proof against its statement: **the one verification
/// path**. The CLI, every test and the tamper harness call this and nothing
/// else. `vk` is a key [`load_verifying_key`] loaded, or one the prover built
/// and checked; its identity is compared with a registered one by the caller.
///
/// A statement is proven when every one of its shards' proofs verifies against
/// one `public`: a shard checks the memory argument's reconciliation over roots
/// the other shards' proofs establish. [`verify_block`] is that, over a block
/// that carries its whole shard set.
pub fn verify_shard(
    vk: &VerifyingKey,
    proof: &ShardProof,
    public: &PublicInputs,
) -> Result<(), VerifyError> {
    let global = derive_global_phase(vk, public)?;
    spend(vk, proof, verify_shard_local(vk, &global, proof, public)?)
}

/// Verify a whole block: **the one block verification path**, and the same
/// per-shard path [`verify_shard`] runs. `docs/spec/block-proof.md` §3 is
/// normative; the checks are, in order:
///
/// 1. the block's descriptor is the key's and its statement is `public`;
/// 2. the statement's own checks and the global transcript, once
///    (`derive_global_phase`);
/// 3. **shard-set exactness**: the proofs are the statement's shards, each
///    once, no gap and no extra, in statement order;
/// 4. the time windows: ordered and disjoint within each cycle-owning family
///    (`check_ts_windows`);
/// 5. every shard through `verify_shard_local` and its opening, which is where
///    the read/write root products reconcile across every shard and family
///    (step 10) and every channel's roots are checked (step 9).
///
/// A family in the config with zero shards this execution is valid and has no
/// record; omitting a shard whose cycles ran is caught by step 5's
/// reconciliation, because its writes and reads are missing from one side of
/// the global multiset.
pub fn verify_block(
    vk: &VerifyingKey,
    proof: &BlockProof,
    public: &PublicInputs,
) -> Result<(), VerifyError> {
    let statement = VerifyError::Statement;
    // 1. The descriptor and the statement the block binds are the ones the
    //    verifier holds. Both are absorbed before any challenge (§2, G3–G9),
    //    so a block cannot claim one occupancy and bind another.
    if proof.config != vk.config {
        return Err(statement("the block's VmConfig is not the key's"));
    }
    if proof.statement != *public {
        return Err(statement("the block's statement is not the one given"));
    }
    // 2. The statement, and the global transcript once for every shard.
    let global = derive_global_phase(vk, public)?;
    // 3. Shard-set exactness.
    proof.shape().map_err(statement)?;
    // 4. The time windows.
    check_ts_windows(&proof.reconciliation().records).map_err(statement)?;
    // 5. Every shard, by the one per-shard path.
    for shard in &proof.shards {
        spend(vk, shard, verify_shard_local(vk, &global, shard, public)?)?;
    }
    Ok(())
}

/// Step 12, the wrapper's: decode every point the opening claim reads through
/// its validating decoder, and run `pcs::batch_verify`. This is where the
/// base verifier's pairings happen.
fn spend(vk: &VerifyingKey, proof: &ShardProof, claim: OpeningClaim) -> Result<(), VerifyError> {
    let opening = VerifyError::Opening;
    let vsrs = decode_srs_verifier(&vk.srs_verifier).ok_or(opening)?;
    let cms = claim
        .commitments
        .iter()
        .map(|b| G1Affine::from_bytes(b).map(MercuryCommitment))
        .collect::<Option<Vec<_>>>()
        .ok_or(opening)?;
    let mercury = MercuryProof::from_bytes(&proof.opening).ok_or(opening)?;
    let mut t = claim.transcript;
    batch_verify(&vsrs, &cms, &claim.point, &claim.values, &mercury, &mut t).map_err(|_| opening)
}

/// `g1_gen ‖ g2_gen ‖ g2_tau`, S07's layout, each through its validating
/// decoder. `None` if any point is not one.
pub fn decode_srs_verifier(bytes: &[u8; SRS_VERIFIER_BYTES]) -> Option<SrsVerifier> {
    Some(SrsVerifier {
        g1_gen: G1Affine::from_bytes(bytes[..64].try_into().expect("64 bytes"))?,
        g2_gen: G2Affine::from_bytes(bytes[64..192].try_into().expect("128 bytes"))?,
        g2_tau: G2Affine::from_bytes(bytes[192..].try_into().expect("128 bytes"))?,
    })
}

/// S07's layout of `vsrs`, the inverse of [`decode_srs_verifier`].
pub fn encode_srs_verifier(vsrs: &SrsVerifier) -> [u8; SRS_VERIFIER_BYTES] {
    let mut out = [0u8; SRS_VERIFIER_BYTES];
    out[..64].copy_from_slice(&vsrs.g1_gen.to_bytes());
    out[64..192].copy_from_slice(&vsrs.g2_gen.to_bytes());
    out[192..].copy_from_slice(&vsrs.g2_tau.to_bytes());
    out
}

/// Load a verifying key: `VerifyingKey::from_bytes`, whose load rules are
/// `docs/spec/shard-proof.md` §7.2, and then every curve point it carries —
/// the `SrsVerifier`, every setup commitment and every generic-table
/// commitment — through its validating decoder. Run once per key.
pub fn load_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, String> {
    let vk = VerifyingKey::from_bytes(bytes)?;
    if decode_srs_verifier(&vk.srs_verifier).is_none() {
        return Err("the key's SrsVerifier holds a point that is not one".into());
    }
    let points = vk.setup_commitments.iter().flatten();
    if points.clone().any(|p| G1Affine::from_bytes(p).is_none()) {
        return Err("a setup commitment is not a point".into());
    }
    if vk
        .generic_table
        .iter()
        .any(|p| G1Affine::from_bytes(p).is_none())
    {
        return Err("a generic-table commitment is not a point".into());
    }
    Ok(vk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The core's opening width is S08's proof size.
    #[test]
    fn the_core_holds_an_opening_of_pcs_width() {
        assert_eq!(OPENING_BYTES, pcs::PROOF_BYTES);
    }

    /// A key whose every other point is one loads; a generic-table commitment
    /// that is not a point is refused, and so is a setup commitment.
    #[test]
    fn every_generic_table_commitment_is_decoded_at_load() {
        use constants::family;
        use curve::{G1Affine, G2Affine};
        use verifier_core::{identity_digest, srs_digest, VmConfig};

        let point = G1Affine::GENERATOR.to_bytes();
        let config = VmConfig {
            families: vec![
                (family::JUMP_BRANCH_SLT, 1 << 20),
                (family::INIT_TEARDOWN, 1 << 16),
                (family::ZERO_WINDOWS, 1 << 16),
            ],
            bytecode_size_words: 1 << 20,
        };
        let setup = vec![vec![point; 7], vec![point], vec![]];
        let srs_verifier = encode_srs_verifier(&SrsVerifier {
            g1_gen: G1Affine::GENERATOR,
            g2_gen: G2Affine::GENERATOR,
            g2_tau: G2Affine::GENERATOR.double(),
        });
        let generic_table = [point; 3];
        let key = VerifyingKey {
            code_version: family::CODE_VERSION,
            entry_pc: 0x1_0000,
            identity: identity_digest(family::CODE_VERSION, &config, 0x1_0000, &setup),
            config: config.clone(),
            setup_commitments: setup,
            srs_verifier,
            generic_table,
            srs_digest: srs_digest(&srs_verifier, &generic_table),
            circuits: config
                .families
                .iter()
                .map(|(f, h)| constraints::family_circuit(*f, h.trailing_zeros()).unwrap())
                .collect(),
        };
        assert_eq!(load_verifying_key(&key.to_bytes()), Ok(key.clone()));
        // Each of the three off the curve, its digest recomputed so that the
        // load reaches the point.
        for i in 0..3 {
            let mut off = key.clone();
            off.generic_table[i][0] ^= 1;
            off.srs_digest = srs_digest(&off.srs_verifier, &off.generic_table);
            assert_eq!(
                load_verifying_key(&off.to_bytes()),
                Err("a generic-table commitment is not a point".to_string()),
                "point {i}"
            );
        }
        let mut off = key.clone();
        off.setup_commitments[1][0][0] ^= 1;
        off.identity = identity_digest(
            off.code_version,
            &off.config,
            off.entry_pc,
            &off.setup_commitments,
        );
        assert_eq!(
            load_verifying_key(&off.to_bytes()),
            Err("a setup commitment is not a point".to_string())
        );
    }
}
