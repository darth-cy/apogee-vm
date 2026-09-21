//! `reduce_shard`: a shard proof reduced to the one Mercury opening it still
//! owes, or refused. `docs/spec/shard-proof.md` §6, steps 1 to 11, in order.
//!
//! Since S20 the steps are split at the fork in three public parts, so a block
//! pays for everything that depends on the statement alone once instead of
//! once per shard: [`derive_global_phase`] is steps 1 to 3 and the replay,
//! [`verify_shard_local`] is steps 4 to 11 but the memory argument's statement
//! half, and [`verify_global_memory`] is that half — step 10b, the boundary
//! and the cross-shard root product. `reduce_shard` is their composition and
//! its order, its classes and its answers are S16's, unchanged.

use alloc::vec::Vec;

use constants::memory::{READ_ROOT, TS_BITS, WRITE_ROOT};
use field::Fr;
use gkr_verify::{
    boundary_factors, channel_holds, reconciles, verify, ExternalChallenges, GkrError, OutputClaims,
};
use poly::{MultilinearPoly, PolyBacking};

use crate::statement::{
    check_memory_windows, global_commit, shard_challenges, shard_transcript, statement_shards,
};
use crate::types::{OpeningClaim, PublicInputs, ShardProof, VerifyError, VerifyingKey};

/// `x10`'s position in `BoundaryFinals::reg_values`, which starts at `x1`.
const EXIT_STATUS_REGISTER: usize = 10 - 1;

/// What the global commit phase leaves every shard of a statement: the four
/// memory challenges `γ_M, α_addr, α_ts, α_val` and the global state digest.
///
/// One per statement, whatever the shard counts. [`derive_global_phase`] is
/// the only way to obtain one, and it never returns one for a statement the
/// key does not describe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GlobalChallenges {
    pub memory: [Fr; 4],
    pub digest: Fr,
}

/// The statement's checks and the global transcript, `docs/spec/shard-proof.md`
/// §6 steps 1 to 3 and §2: the statement is one `vk` describes, its window
/// rules hold, its per-shard lists line up, and then G1 to G11 are replayed.
///
/// **Run once per statement**, by the prover's global commit phase and by
/// `verify_block`; `verify_shard` runs it for its one shard.
pub fn derive_global_phase(
    vk: &VerifyingKey,
    public: &PublicInputs,
) -> Result<GlobalChallenges, VerifyError> {
    let statement = VerifyError::Statement;
    let config = &vk.config;

    // 1. The statement is one the key describes.
    if public.shard_counts.len() != config.families.len() {
        return Err(statement(
            "the statement has not one shard count per config family",
        ));
    }
    if vk.circuits.len() != config.families.len()
        || vk
            .circuits
            .iter()
            .zip(&config.families)
            .any(|(c, (f, _))| c.family != *f)
        || vk.setup_commitments.len() != config.families.len()
    {
        return Err(statement(
            "the key's circuits are not its config's families",
        ));
    }

    // 2. The window rules.
    check_memory_windows(config, &public.shard_counts, &public.windows).map_err(statement)?;

    // 3. One commitment list and one root pair per statement shard, each list
    //    its family's memory width. The total is bounded before anything is
    //    built from the counts.
    let total: u64 = public.shard_counts.iter().map(|c| *c as u64).sum();
    if total != public.memory_commitments.len() as u64 {
        return Err(statement(
            "the statement has not one commitment list per shard",
        ));
    }
    if total != public.memory_roots.len() as u64 {
        return Err(statement("the statement has not one root pair per shard"));
    }
    for ((family, _), list) in statement_shards(config, &public.shard_counts)
        .iter()
        .zip(&public.memory_commitments)
    {
        let circuit = vk
            .circuit(*family)
            .expect("step 1 matched the circuits to the config");
        if list.len() != circuit.artifact.memory.len() {
            return Err(statement(
                "a shard's commitment list is not its family's memory width",
            ));
        }
    }

    let global = global_commit(vk, public);
    Ok(GlobalChallenges {
        memory: global.memory,
        digest: global.digest,
    })
}

/// One shard against a statement whose global phase is already derived,
/// `docs/spec/shard-proof.md` §6 steps 4 to 11: its time window, its seeding,
/// its shape, its circuit, its channels and the memory argument's **shard
/// half**, then the opening claim its caller owes.
///
/// **Not a whole verification on its own.** The memory argument's other half —
/// the boundary and the read/write root product over every shard — depends on
/// the statement and not on any one proof, so it is [`verify_global_memory`],
/// which a caller owes **once** per statement however many shards it runs.
/// `reduce_shard` and `verifier::verify_shard` run it for their one shard;
/// `verifier::verify_block` runs it once for the block.
///
/// `global` is [`derive_global_phase`]`(vk, public)`; passing one derived from
/// another statement is a caller error and makes the answer meaningless.
/// Nothing `proof` or `public` carries makes this panic.
pub fn verify_shard_local(
    vk: &VerifyingKey,
    global: &GlobalChallenges,
    proof: &ShardProof,
    public: &PublicInputs,
) -> Result<OpeningClaim, VerifyError> {
    let statement = VerifyError::Statement;
    let config = &vk.config;
    let shards = statement_shards(config, &public.shard_counts);

    // 4. The time window is a window: `[start, end)` inside the clock. Which
    //    windows a *block* admits — ordered and disjoint within a cycle-owning
    //    family — is `crate::check_ts_windows`, which needs every shard and so
    //    is `verify_block`'s (`docs/spec/block-proof.md` §4).
    let [start, end] = proof.ts_window;
    if start > end || end > 1 << TS_BITS {
        return Err(statement(
            "the time window is not [start, end) in the clock",
        ));
    }

    // 5. The global transcript's digest, replayed.
    if global.digest != proof.global_digest {
        return Err(statement("the proof was made for another statement"));
    }

    // 6. The proof has its circuit's shape.
    let malformed = VerifyError::Malformed;
    let position = shards
        .iter()
        .position(|s| *s == (proof.family, proof.shard_index))
        .ok_or(malformed(
            "the proof names a shard the statement does not have",
        ))?;
    let family_index = config
        .families
        .iter()
        .position(|(f, _)| *f == proof.family)
        .expect("a statement shard's family is a config family");
    let circuit = &vk.circuits[family_index];
    let artifact = &circuit.artifact;
    if proof.witness_commitments.len() != artifact.witness.len() {
        return Err(malformed(
            "the witness commitments are not the circuit's width",
        ));
    }
    if proof.outputs.len() != artifact.outputs.len() {
        return Err(malformed("the outputs are not the circuit's output map"));
    }

    // 7. The circuit, over the shard transcript.
    let (mut t, g, beta) = shard_transcript(
        global.digest,
        proof.family,
        proof.shard_index,
        proof.ts_window,
        &proof.witness_commitments,
    );
    let challenges: ExternalChallenges = shard_challenges(
        circuit,
        proof.shard_index,
        &public.windows,
        &global.memory,
        g,
        beta,
    );
    let outputs = OutputClaims {
        tables: proof
            .outputs
            .iter()
            .map(|v| MultilinearPoly::new(PolyBacking::Fr(Vec::from([*v]))))
            .collect(),
    };
    let claims =
        verify(artifact, &proof.gkr, &outputs, &challenges, &mut t).map_err(|e| match e {
            GkrError::LayerInconsistency { layer } => VerifyError::Constraint { layer },
            GkrError::ProofShape { .. } => malformed("a GKR transition is not its layer's shape"),
            GkrError::OutputShape => malformed("the outputs are not the circuit's output map"),
            GkrError::MissingChallenge { .. } => {
                malformed("the circuit names a challenge no shard draws")
            }
        })?;

    // 8. One point.
    let point = claims.first().map(|c| c.point.clone()).unwrap_or_default();
    if claims.iter().any(|c| c.point != point) {
        return Err(VerifyError::Constraint { layer: 0 });
    }

    // 9. Every channel balances.
    for (j, spec) in circuit.channels.iter().enumerate() {
        let root = (proof.outputs[2 + 2 * j], proof.outputs[3 + 2 * j]);
        if !channel_holds(root) {
            return Err(VerifyError::Lookup {
                channel: spec.channel,
            });
        }
    }

    // 10a. The memory argument's shard half: this proof's own roots are the
    //      ones the statement publishes for this shard, which is what binds
    //      this shard into the global product [`verify_global_memory`] takes.
    //      10b, the product itself, is a function of the statement alone and
    //      is the caller's, once.
    let memory = VerifyError::MemoryArgument;
    let own = [proof.outputs[READ_ROOT], proof.outputs[WRITE_ROOT]];
    if own != public.memory_roots[position] {
        return Err(memory("the shard's roots are not the statement's"));
    }

    // 11. The opening the wrapper owes: M from the statement, W from the
    //     proof, S from the key — identity's, then, for a family that reads
    //     the generic channel, the generic table's — in layout order.
    let mut commitments = public.memory_commitments[position].clone();
    commitments.extend_from_slice(&proof.witness_commitments);
    commitments.extend_from_slice(&vk.setup_commitments[family_index]);
    if circuit.reads_generic_table() {
        commitments.extend_from_slice(&vk.generic_table);
    }
    Ok(OpeningClaim {
        commitments,
        point,
        values: claims.iter().map(|c| c.value).collect(),
        transcript: t,
    })
}

/// The memory argument's **statement half**, `docs/spec/shard-proof.md` §6
/// step 10b and `docs/spec/memory.md` §4.2: the boundary is in range and names
/// the exit status, and the read/write root product reconciles over every
/// shard of every family in the statement, against the boundary's two factors.
///
/// **Run once per statement**, not once per shard. Every operand is the
/// statement's or the key's — `vk.entry_pc`, `public.boundary`,
/// `public.memory_roots` and `global.memory` — so the answer is the same for
/// every shard of one statement, and a block that ran it per shard would fold
/// the same 66 boundary tuples and the same root product `shard_count` times
/// over. What ties one shard's proof into the product it reads is step 10a,
/// in [`verify_shard_local`], which holds that proof's own roots to the
/// statement's entry for its shard; with shard-set exactness on top —
/// `BlockProof::shape`, one proof per statement shard and no other — every
/// root in the product is a verified shard's.
///
/// `global` is [`derive_global_phase`]`(vk, public)`. Nothing `public` carries
/// makes this panic.
pub fn verify_global_memory(
    vk: &VerifyingKey,
    global: &GlobalChallenges,
    public: &PublicInputs,
) -> Result<(), VerifyError> {
    let memory = VerifyError::MemoryArgument;
    let b = &public.boundary;
    if b.reg_ts
        .iter()
        .chain([&b.pc_ts])
        .any(|t| *t >= 1 << TS_BITS)
    {
        return Err(memory("a boundary timestamp is not below 2^38"));
    }
    if b.reg_values[EXIT_STATUS_REGISTER] != public.exit_status {
        return Err(memory("x10's final value is not the exit status"));
    }
    let drawn = crate::statement::memory_slots(&global.memory);
    let reads: Vec<Fr> = public.memory_roots.iter().map(|r| r[READ_ROOT]).collect();
    let writes: Vec<Fr> = public.memory_roots.iter().map(|r| r[WRITE_ROOT]).collect();
    let factors = boundary_factors(&drawn, vk.entry_pc, b);
    if !reconciles(&reads, &writes, factors) {
        return Err(memory("the statement's roots do not reconcile"));
    }
    Ok(())
}

/// Reduce `proof` to its opening claim, or refuse it with the class of the
/// first check that fails, `docs/spec/shard-proof.md` §6.
///
/// The one no_std entry point for a single shard. `verifier::verify_shard` is
/// this followed by the opening; nothing else verifies a shard. `vk` has
/// passed its load (`VerifyingKey::check`); nothing `proof` or `public`
/// carries makes this panic.
pub fn reduce_shard(
    vk: &VerifyingKey,
    proof: &ShardProof,
    public: &PublicInputs,
) -> Result<OpeningClaim, VerifyError> {
    let global = derive_global_phase(vk, public)?;
    let claim = verify_shard_local(vk, &global, proof, public)?;
    // Step 10b, at step 10's place in the order: step 11 builds the claim and
    // cannot fail, so running the statement half after it returns is the same
    // first failure, with the same class and the same message, as S16's
    // single step 10 was.
    verify_global_memory(vk, &global, public)?;
    Ok(claim)
}
