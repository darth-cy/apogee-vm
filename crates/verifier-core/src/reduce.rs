//! `reduce_shard`: a shard proof reduced to the one Mercury opening it still
//! owes, or refused. `docs/spec/shard-proof.md` §6, steps 1 to 11, in order.

use alloc::vec::Vec;

use constants::memory::{READ_ROOT, TS_BITS, WRITE_ROOT};
use field::Fr;
use gkr_verify::{
    boundary_factors, channel_holds, reconciles, verify, ExternalChallenges, GkrError, OutputClaims,
};
use poly::{MultilinearPoly, PolyBacking};

use crate::statement::{
    check_memory_windows, global_commit, shard_challenges, shard_transcript, statement_shards,
    TRIVIAL_TS_WINDOW,
};
use crate::types::{OpeningClaim, PublicInputs, ShardProof, VerifyError, VerifyingKey};

/// `x10`'s position in `BoundaryFinals::reg_values`, which starts at `x1`.
const EXIT_STATUS_REGISTER: usize = 10 - 1;

/// Reduce `proof` to its opening claim, or refuse it with the class of the
/// first check that fails, `docs/spec/shard-proof.md` §6.
///
/// The one no_std entry point of the verifier. `verifier::verify_shard` is this
/// followed by the opening; nothing else verifies a shard. `vk` has passed its
/// load (`VerifyingKey::check`); nothing `proof` or `public` carries makes
/// this panic.
pub fn reduce_shard(
    vk: &VerifyingKey,
    proof: &ShardProof,
    public: &PublicInputs,
) -> Result<OpeningClaim, VerifyError> {
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
    let shards = statement_shards(config, &public.shard_counts);
    for ((family, _), list) in shards.iter().zip(&public.memory_commitments) {
        let circuit = vk
            .circuit(*family)
            .expect("step 1 matched the circuits to the config");
        if list.len() != circuit.artifact.memory.len() {
            return Err(statement(
                "a shard's commitment list is not its family's memory width",
            ));
        }
    }

    // 4. The time window.
    if proof.ts_window != TRIVIAL_TS_WINDOW {
        return Err(statement("the time window is not the whole clock"));
    }

    // 5. The global transcript, replayed.
    let global = global_commit(vk, public);
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

    // 10. The memory argument.
    let memory = VerifyError::MemoryArgument;
    let own = [proof.outputs[READ_ROOT], proof.outputs[WRITE_ROOT]];
    if own != public.memory_roots[position] {
        return Err(memory("the shard's roots are not the statement's"));
    }
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
