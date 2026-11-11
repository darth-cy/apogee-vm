//! Shard and block verification: `verifier_core`'s checks, each shard's
//! opening among them. `docs/spec/proof.md` §6 specifies it.
//!
//! This crate is the core's thin `std` wrapper and holds nothing else of the
//! protocol. The `verifier` binary is the CLI.
//!
//! [`proof_archive`] is the one other thing here, and it is the CLI's: the
//! four files a proved block leaves on disk, which are exactly what
//! `verifier block <vk> <identity> <public> <block>` reads back. It sits in
//! this crate rather than in the host SDK because the **reader** is here —
//! one definition of the format, beside the thing that consumes it —
//! and `host::proof_archive` is a re-export of it.

pub mod proof_archive;

use verifier_core::{
    check_ts_windows, derive_global_phase, verify_global_memory, verify_shard_local,
};

pub use verifier_core::{
    BlockProof, BlockReconciliation, PublicInputs, ShardProof, ShardRecord, VerifyError,
    VerifyingKey,
};

/// Verify one shard's proof against its statement: **the one single-shard
/// verification path**, which the CLI and the tamper harness call for a shard.
/// `vk` is a key [`load_verifying_key`] loaded, or one the prover built and
/// checked; its identity is compared with a registered one by the caller.
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
    verify_shard_local(vk, &global, proof, public)?;
    verify_global_memory(vk, &global, public)
}

/// Verify a whole block: **the one block verification path**, and the same
/// per-shard path [`verify_shard`] runs. `docs/spec/proof.md` §6 specifies
/// it; the checks are, in order:
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
/// 6. every shard through `verify_shard_local`: its circuit, its channels'
///    roots (step 9), its own roots held to the statement's entry for it
///    (step 10a), which is what puts it in check 5's product, and its opening
///    (step 11).
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
    //    verifier holds. Both are absorbed before any challenge (§2, G2–G7),
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
        verify_shard_local(vk, &global, shard, public)?;
    }
    Ok(())
}

/// Load a verifying key: `VerifyingKey::from_bytes`, whose load rules are
/// `docs/spec/proof.md` §7.2. Run once per key.
pub fn load_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, String> {
    VerifyingKey::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A commitment of group `g` — 0, 1, 2 for `M`, `W`, `S` — of family
    /// `f`'s columns' shape at `2^vars` rows, every lane zero.
    pub(crate) fn zeros(f: u32, vars: u32, g: usize) -> verifier_core::Commitment {
        let circuit = constraints::family_circuit(f, vars).unwrap();
        let columns = verifier_core::committed_groups(&circuit.artifact)[g];
        let (slices, len) =
            verifier_core::opening_schedule(&circuit.artifact).commitment_shape(columns);
        verifier_core::Commitment(vec![vec![field::Fp::ZERO; len]; slices])
    }

    /// The memory commitments of `statement`'s three shards — the window-0
    /// one and the two public windows' — in statement order.
    pub(crate) fn memory_zeros() -> Vec<verifier_core::Commitment> {
        use constants::family;
        let public = family::PUBLIC_WINDOW_HEIGHT.trailing_zeros();
        vec![
            zeros(family::INIT_TEARDOWN, 16, 0),
            zeros(family::PUBLIC_INPUT, public, 0),
            zeros(family::PUBLIC_OUTPUT, public, 0),
        ]
    }

    /// A key over the registry's circuits: `JUMP_BRANCH_SLT` at `2^20` and the
    /// two RAM window families at `2^16`, its setup commitments of their shape
    /// and its setup empty — no shard here reaches an opening.
    pub(crate) fn key() -> VerifyingKey {
        use constants::family;
        use verifier_core::{identity_digest, Setup, VmConfig};

        let config = VmConfig {
            families: vec![
                (family::JUMP_BRANCH_SLT, 1 << 20),
                (family::INIT_TEARDOWN, 1 << 16),
                (family::ZERO_WINDOWS, 1 << 16),
                // The public pair and advice, in every `VmConfig`
                // (`docs/spec/public-values.md` §4).
                (family::PUBLIC_INPUT, family::PUBLIC_WINDOW_HEIGHT),
                (family::PUBLIC_OUTPUT, family::PUBLIC_WINDOW_HEIGHT),
                (family::ADVICE_WINDOWS, 1 << 16),
            ],
            bytecode_size_words: 1 << 20,
        };
        let setup_commitments: Vec<_> = config
            .families
            .iter()
            .map(|(f, h)| zeros(*f, h.trailing_zeros(), 2))
            .collect();
        VerifyingKey {
            code_version: family::CODE_VERSION,
            entry_pc: 0x1_0000,
            identity: identity_digest(family::CODE_VERSION, &config, 0x1_0000, &setup_commitments),
            config: config.clone(),
            setup_commitments,
            circuits: config
                .families
                .iter()
                .map(|(f, h)| constraints::family_circuit(*f, h.trailing_zeros()).unwrap())
                .collect(),
            pcs: Setup(vec![]),
        }
    }

    /// **`verify_block` runs the memory argument's statement half itself, at
    /// check 5, and not inside its per-shard loop** (`docs/spec/proof.md`
    /// §6). The block below carries one `INIT_TEARDOWN` shard whose proof is a
    /// shell — a digest of zero, no outputs — so the loop
    /// would refuse it as `Statement` the moment it read it, as the second
    /// assertion shows. The answer is `MemoryArgument` instead, which is only
    /// possible if check 5 ran first and read the statement alone.
    #[test]
    fn the_block_checks_the_statement_s_memory_argument_before_any_shard() {
        use constants::family;
        use verifier_core::{BoundaryFinals, GkrProof, PublicInputs};

        let vk = key();
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
            // shard the window rules require, no zero window, one shard for
            // each public value family and no advice window.
            shard_counts: vec![0, 1, 0, 1, 1, 0],
            windows: vec![],
            boundary,
            memory_commitments: memory_zeros(),
            memory_roots: vec![[field::Fp2::ONE, field::Fp2::ONE]; 3],
        };
        let shell = ShardProof {
            family: family::INIT_TEARDOWN,
            shard_index: 0,
            ts_window: [0, 0],
            global_digest: field::Fp2::ZERO,
            witness_commitment: verifier_core::Commitment(vec![]),
            outputs: vec![],
            gkr: GkrProof { layers: vec![] },
            opening: Default::default(),
        };
        let public_shell = |f: u32| ShardProof {
            family: f,
            ..shell.clone()
        };
        let block = BlockProof {
            config: vk.config.clone(),
            statement: statement.clone(),
            shards: vec![
                shell.clone(),
                public_shell(family::PUBLIC_INPUT),
                public_shell(family::PUBLIC_OUTPUT),
            ],
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
}
