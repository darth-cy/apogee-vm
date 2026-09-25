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
use verifier_core::{
    check_ts_windows, derive_global_phase, verify_global_memory, verify_shard_local, OpeningClaim,
};

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
/// one `public` **and** the statement's memory argument reconciles over the
/// roots all of them establish. This runs both for its one shard; over a whole
/// shard set, that is [`verify_block`], which runs the second once.
pub fn verify_shard(
    vk: &VerifyingKey,
    proof: &ShardProof,
    public: &PublicInputs,
) -> Result<(), VerifyError> {
    let global = derive_global_phase(vk, public)?;
    let claim = verify_shard_local(vk, &global, proof, public)?;
    verify_global_memory(vk, &global, public)?;
    spend(vk, proof, claim)
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
/// 5. the memory argument's statement half **once** — the boundary, and the
///    read/write root product across every shard of every family
///    (`verify_global_memory`, step 10b). It reads the statement and no
///    proof, so it is one check for the block, not one per shard;
/// 6. every shard through `verify_shard_local` and its opening: its circuit,
///    its channels' roots (step 9), and its own roots held to the statement's
///    entry for it (step 10a), which is what puts it in check 5's product.
///
/// A family in the config with zero shards this execution is valid and has no
/// record; omitting a shard whose cycles ran is caught by check 5, because its
/// writes and reads are missing from one side of the global multiset.
///
/// Checks 1 to 5 read no proof, so a statement that cannot reconcile is
/// refused before any shard is verified.
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
    // 5. The memory argument's statement half, once for the whole block. Its
    //    operands are the statement's and the key's alone, so per shard it
    //    would be the same answer recomputed `shards.len()` times.
    verify_global_memory(vk, &global, public)?;
    // 6. Every shard, by the one per-shard path.
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

    /// A key over the registry's circuits: `JUMP_BRANCH_SLT` at `2^20` and the
    /// two RAM window families at `2^16`, every point the generator.
    fn key() -> VerifyingKey {
        use constants::family;
        use curve::{G1Affine, G2Affine};
        use verifier_core::{identity_digest, srs_digest, VmConfig};

        let point = G1Affine::GENERATOR.to_bytes();
        let config = VmConfig {
            families: vec![
                (family::JUMP_BRANCH_SLT, 1 << 20),
                (family::INIT_TEARDOWN, 1 << 16),
                (family::ZERO_WINDOWS, 1 << 16),
                (family::ADVICE_WINDOWS, 1 << 16),
            ],
            bytecode_size_words: 1 << 20,
        };
        let setup = vec![vec![point; 7], vec![point], vec![], vec![]];
        let srs_verifier = encode_srs_verifier(&SrsVerifier {
            g1_gen: G1Affine::GENERATOR,
            g2_gen: G2Affine::GENERATOR,
            g2_tau: G2Affine::GENERATOR.double(),
        });
        let generic_table = [point; 3];
        VerifyingKey {
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
        }
    }

    /// **`verify_block` runs the memory argument's statement half itself, at
    /// check 5, and not inside its per-shard loop** (`docs/spec/block-proof.md`
    /// §3). The block below carries one `INIT_TEARDOWN` shard whose proof is a
    /// shell — a digest of zero, no commitments, no outputs — so the loop
    /// would refuse it as `Statement` the moment it read it, as the second
    /// assertion shows. The answer is `MemoryArgument` instead, which is only
    /// possible if check 5 ran first and read the statement alone.
    #[test]
    fn the_block_checks_the_statement_s_memory_argument_before_any_shard() {
        use constants::family;
        use verifier_core::{BoundaryFinals, GkrProof, PublicInputs};

        let vk = key();
        let width = vk
            .circuit(family::INIT_TEARDOWN)
            .expect("the key's window family")
            .artifact
            .memory
            .len();
        let mut boundary = BoundaryFinals {
            reg_ts: [0; 32],
            pc_ts: 0,
            reg_values: [0; 31],
        };
        // Out of the clock, which is step 10b's first check.
        boundary.reg_ts[7] = 1 << 38;
        let statement = PublicInputs {
            input: vec![],
            output: vec![],
            exit_status: 0,
            // Positional over the config: no jump shard, the one window-0
            // shard the window rules require, no zero window, no advice.
            shard_counts: vec![0, 1, 0, 0],
            windows: vec![],
            boundary,
            memory_commitments: vec![vec![[0u8; 64]; width]],
            memory_roots: vec![[field::Fr::ONE, field::Fr::ONE]],
        };
        let shell = ShardProof {
            family: family::INIT_TEARDOWN,
            shard_index: 0,
            ts_window: [0, 0],
            global_digest: field::Fr::ZERO,
            witness_commitments: vec![],
            outputs: vec![],
            gkr: GkrProof { layers: vec![] },
            opening: [0; OPENING_BYTES],
        };
        let block = BlockProof {
            config: vk.config.clone(),
            statement: statement.clone(),
            shards: vec![shell.clone()],
        };
        assert_eq!(
            verify_block(&vk, &block, &statement),
            Err(VerifyError::MemoryArgument(
                "a boundary timestamp is not below 2^38"
            )),
            "check 5 reads the statement and runs before the shards"
        );
        assert_eq!(
            verify_shard(&vk, &shell, &statement),
            Err(VerifyError::Statement(
                "the proof was made for another statement"
            )),
            "the loop would have answered this, so the block's answer is check 5's"
        );
    }

    /// A key whose every other point is one loads; a generic-table commitment
    /// that is not a point is refused, and so is a setup commitment.
    #[test]
    fn every_generic_table_commitment_is_decoded_at_load() {
        use verifier_core::{identity_digest, srs_digest};

        let key = key();
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
