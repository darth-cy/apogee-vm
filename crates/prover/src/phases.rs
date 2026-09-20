//! The prover's phase snapshots and resume, `docs/spec/shard-proof.md` §10:
//! the S12 trace archive's four later sections, their schemas, and `advance`,
//! which fills them in order and reads back whatever an imported archive
//! already holds.

use std::time::Instant;

use gkr::BaseLayer;
use rayon::prelude::*;
use trace::{plan_shards, Phase, PhaseTiming, ShardPlan, TraceArchive};
use transcript::{Transcript, TranscriptSnapshot};
use verifier_core::wire::{Read, Reader, Writer};
use verifier_core::{read_gkr, statement_shards, write_gkr, BlockProof, PublicInputs, ShardProof};

use crate::{
    global_commit_phase, public_inputs, shard_columns, statement_inputs, GlobalCommitState,
    ProverError, ProverSetup, ProvingContext, ShardGkr,
};

/// A transcript snapshot's fixed size under `postcard`, S02's wire form.
const SNAPSHOT_BYTES: usize = 226;

fn write_snapshot(w: &mut Writer, s: &TranscriptSnapshot) {
    let mut buf = [0u8; SNAPSHOT_BYTES];
    let used = postcard::to_slice(s, &mut buf)
        .expect("a transcript snapshot fits its fixed size")
        .len();
    assert_eq!(
        used, SNAPSHOT_BYTES,
        "a transcript snapshot is {SNAPSHOT_BYTES} bytes"
    );
    w.raw(&buf);
}

fn read_snapshot(r: &mut Reader) -> Read<TranscriptSnapshot> {
    postcard::from_bytes(r.take(SNAPSHOT_BYTES)?)
        .map_err(|_| "a transcript snapshot does not decode")
}

// ---------------------------------------------------------------------------
// The four sections
// ---------------------------------------------------------------------------

/// `PostCommit`: the statement, the global transcript, the four memory
/// challenges, the digest.
pub(crate) fn encode_global(g: &GlobalCommitState) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(&g.statement.to_bytes());
    write_snapshot(&mut w, &g.transcript);
    for c in &g.memory_challenges {
        w.fr(c);
    }
    w.fr(&g.digest);
    w.bytes
}

pub(crate) fn decode_global(bytes: &[u8]) -> Read<GlobalCommitState> {
    let mut r = Reader::new(bytes);
    let statement = PublicInputs::from_bytes(r.bytes()?)?;
    let transcript = read_snapshot(&mut r)?;
    let memory_challenges = [r.fr()?, r.fr()?, r.fr()?, r.fr()?];
    let digest = r.fr()?;
    r.finish()?;
    Ok(GlobalCommitState {
        statement,
        transcript,
        memory_challenges,
        digest,
    })
}

/// `PostGkr`: one entry per statement shard, in statement order.
fn encode_gkrs(shards: &[ShardGkr]) -> Vec<u8> {
    let mut w = Writer::new();
    w.count(shards.len());
    for s in shards {
        w.u32(s.family);
        w.u32(s.index);
        w.u64(s.ts_window[0]);
        w.u64(s.ts_window[1]);
        w.g1s(&s.witness_commitments);
        w.frs(&s.outputs);
        write_gkr(&mut w, &s.gkr);
        w.frs(&s.point);
        write_snapshot(&mut w, &s.transcript.snapshot());
    }
    w.bytes
}

fn decode_gkrs(bytes: &[u8]) -> Read<Vec<ShardGkr>> {
    let mut r = Reader::new(bytes);
    let n = r.count(8)?;
    let mut out = Vec::new();
    for _ in 0..n {
        let family = r.u32()?;
        let index = r.u32()?;
        let ts_window = [r.u64()?, r.u64()?];
        let witness_commitments = r.g1s()?;
        let outputs = r.frs()?;
        let gkr = read_gkr(&mut r)?;
        let point = r.frs()?;
        let transcript = Transcript::restore(&read_snapshot(&mut r)?);
        out.push(ShardGkr {
            family,
            index,
            ts_window,
            witness_commitments,
            outputs,
            gkr,
            point,
            transcript,
        });
    }
    r.finish()?;
    Ok(out)
}

/// `PostOpening`: every shard's proof, in statement order.
fn encode_proofs(w: &mut Writer, proofs: &[ShardProof]) {
    w.count(proofs.len());
    for p in proofs {
        w.bytes(&p.to_bytes());
    }
}

fn decode_proofs(r: &mut Reader) -> Read<Vec<ShardProof>> {
    let n = r.count(4)?;
    (0..n).map(|_| ShardProof::from_bytes(r.bytes()?)).collect()
}

/// `Final`: the complete statement, then every proof.
fn encode_final(public: &PublicInputs, proofs: &[ShardProof]) -> Vec<u8> {
    let mut w = Writer::new();
    w.bytes(&public.to_bytes());
    encode_proofs(&mut w, proofs);
    w.bytes
}

fn decode_final(bytes: &[u8]) -> Read<(PublicInputs, Vec<ShardProof>)> {
    let mut r = Reader::new(bytes);
    let public = PublicInputs::from_bytes(r.bytes()?)?;
    let proofs = decode_proofs(&mut r)?;
    r.finish()?;
    Ok((public, proofs))
}

// ---------------------------------------------------------------------------
// advance
// ---------------------------------------------------------------------------

/// The results of a parallel step, in order, or the **first** of them that
/// failed.
///
/// `collect::<Result<Vec<_>, _>>()` on a parallel iterator returns *some*
/// error when more than one fails, and which one is not deterministic — rayon
/// says so. Every other refusal this prover makes names a cycle or a family,
/// and one that named a different cycle on a different machine would be a
/// diagnostic nobody could reproduce. So the parallel step collects in order
/// and the first failure is picked here, sequentially.
fn first_error<T>(results: Vec<Result<T, ProverError>>) -> Result<Vec<T>, ProverError> {
    results.into_iter().collect()
}

fn archive_error(phase: Phase) -> impl Fn(&'static str) -> ProverError {
    move |e| ProverError::Archive(format!("{phase:?}: {e}"))
}

fn fill(
    archive: &mut TraceArchive,
    phase: Phase,
    content: Vec<u8>,
    since: Instant,
) -> Result<(), ProverError> {
    let timing = PhaseTiming {
        wall_nanos: since.elapsed().as_nanos() as u64,
    };
    archive
        .fill(phase, content, timing)
        .map_err(ProverError::Archive)
}

/// Prove the archived execution up to and including phase `until`, filling
/// each later phase of `archive` in order and timing it; a phase `archive`
/// already holds is read back instead of recomputed. **Resume** is
/// `TraceArchive::import` and this: an archive exported after any phase
/// finishes to the same bytes as an uninterrupted run.
///
/// The columns are never stored. A phase that needs them rebuilds them from
/// the post-execution section and `setup`, which is deterministic.
pub fn advance(
    setup: &ProverSetup,
    archive: &mut TraceArchive,
    until: Phase,
) -> Result<(), ProverError> {
    if until == Phase::PostExecution {
        return Ok(());
    }
    // PostCommit.
    let global = match archive.content(Phase::PostCommit) {
        Some(bytes) => decode_global(bytes).map_err(archive_error(Phase::PostCommit))?,
        None => {
            let since = Instant::now();
            let inputs = statement_inputs(setup, archive)?;
            let global = global_commit_phase(&setup.vk, &setup.srs, &inputs);
            fill(archive, Phase::PostCommit, encode_global(&global), since)?;
            global
        }
    };
    if until == Phase::PostCommit {
        return Ok(());
    }
    let ctx = ProvingContext { setup, global };
    let shards = statement_shards(&setup.vk.config, &ctx.global.statement.shard_counts);
    let windows = ctx.global.statement.windows.clone();
    let base =
        |archive: &TraceArchive, (family, index): (u32, u32)| -> Result<BaseLayer, ProverError> {
            Ok(BaseLayer::new(shard_columns(
                setup, archive, family, index, &windows,
            )?))
        };

    // PostGkr. Shard proving is the block's one parallel step, and it starts
    // only after the global phase has closed: each task forks its transcript
    // from the same global state, builds its own slice of the archive, proves
    // it and drops it, so the shards share no prover state, the schedule
    // cannot reach a challenge, and the peak is one shard trace per worker.
    // `map` over an indexed parallel iterator collects in order, so the result
    // is statement order whatever the thread count
    // (`docs/spec/block-proof.md` §5).
    let gkrs = match archive.content(Phase::PostGkr) {
        Some(bytes) => decode_gkrs(bytes).map_err(archive_error(Phase::PostGkr))?,
        None => {
            let since = Instant::now();
            let read_only: &TraceArchive = archive;
            let gkrs = first_error(
                shards
                    .par_iter()
                    .map(|&(family, index)| {
                        base(read_only, (family, index))
                            .map(|base| ctx.gkr_part(family, index, &base))
                    })
                    .collect(),
            )?;
            fill(archive, Phase::PostGkr, encode_gkrs(&gkrs), since)?;
            gkrs
        }
    };
    if until == Phase::PostGkr {
        return Ok(());
    }

    // PostOpening.
    let proofs = match archive.content(Phase::PostOpening) {
        Some(bytes) => {
            let mut r = Reader::new(bytes);
            let proofs = decode_proofs(&mut r).and_then(|p| r.finish().map(|()| p));
            proofs.map_err(archive_error(Phase::PostOpening))?
        }
        None => {
            let since = Instant::now();
            let read_only: &TraceArchive = archive;
            let proofs = first_error(
                gkrs.into_par_iter()
                    .map(|gkr| {
                        let shard = (gkr.family, gkr.index);
                        base(read_only, shard).map(|base| ctx.opening_part(gkr, &base).0)
                    })
                    .collect(),
            )?;
            let mut w = Writer::new();
            encode_proofs(&mut w, &proofs);
            fill(archive, Phase::PostOpening, w.bytes, since)?;
            proofs
        }
    };
    if until == Phase::PostOpening {
        return Ok(());
    }

    // Final.
    if archive.content(Phase::Final).is_none() {
        let since = Instant::now();
        let public = public_inputs(&ctx.global, &proofs);
        fill(archive, Phase::Final, encode_final(&public, &proofs), since)?;
    }
    Ok(())
}

/// Prove one archived execution as a **block**: `docs/spec/block-proof.md` §5.
///
/// `plan` is the execution's own shard plan and is checked against the
/// archive's cycle profile — a plan for another execution is refused rather
/// than silently proving a different shard set. The rest is [`advance`] to
/// `Phase::Final` and [`finish`]: the global commit phase once, every shard
/// proved from its own forked transcript, and the five phase sections left in
/// `archive`, so a killed run resumes to the same bytes.
///
/// The two RAM window families run no cycles, so `plan` counts 0 for both;
/// their shards — exactly one `INIT_TEARDOWN`, one `ZERO_WINDOWS` per touched
/// window — are the statement's, `docs/spec/memory.md` §3.
pub fn prove_block(
    setup: &ProverSetup,
    archive: &mut TraceArchive,
    plan: &ShardPlan,
) -> Result<BlockProof, ProverError> {
    let derived = plan_shards(archive.cycle_profile(), &setup.program.config);
    if *plan != derived {
        return Err(ProverError::Trace(format!(
            "the shard plan {:?} is not the archived execution's {:?}",
            plan.shards, derived.shards
        )));
    }
    advance(setup, archive, Phase::Final)?;
    let (statement, shards) = finish(archive)?;
    let block = BlockProof {
        config: setup.vk.config.clone(),
        statement,
        shards,
    };
    block
        .shape()
        .expect("prove_block assembles the statement's shards in statement order");
    Ok(block)
}

/// The statement and every shard's proof, from an archive whose final phase is
/// filled.
pub fn finish(archive: &TraceArchive) -> Result<(PublicInputs, Vec<ShardProof>), ProverError> {
    let bytes = archive
        .content(Phase::Final)
        .ok_or(ProverError::Archive("the final phase is empty".into()))?;
    decode_final(bytes).map_err(archive_error(Phase::Final))
}

#[cfg(test)]
mod tests {
    use super::*;
    use field::Fr;
    use verifier_core::BoundaryFinals;

    fn global() -> GlobalCommitState {
        let statement = PublicInputs {
            input: vec![1],
            output: vec![],
            exit_status: 0,
            shard_counts: vec![1, 1, 0],
            windows: vec![],
            boundary: BoundaryFinals {
                reg_ts: [0; 32],
                pc_ts: 4,
                reg_values: [0; 31],
            },
            memory_commitments: vec![vec![[7; 64]], vec![]],
            memory_roots: vec![],
        };
        let mut t = Transcript::new();
        t.append_scalar(9, Fr::from_u64(3));
        GlobalCommitState {
            statement,
            transcript: t.snapshot(),
            memory_challenges: [1, 2, 3, 4].map(Fr::from_u64),
            digest: Fr::from_u64(5),
        }
    }

    /// The post-commit section reads back exactly what it wrote, and nothing
    /// longer or shorter: a resumed archive is refused, not half-read.
    #[test]
    fn the_post_commit_section_is_its_encoding_exactly() {
        let g = global();
        let bytes = encode_global(&g);
        let back = decode_global(&bytes).expect("the section decodes");
        assert_eq!(back.statement, g.statement);
        assert_eq!(back.transcript, g.transcript);
        assert_eq!(back.memory_challenges, g.memory_challenges);
        assert_eq!(back.digest, g.digest);
        let mut long = bytes.clone();
        long.push(0);
        assert!(decode_global(&long).is_err(), "a trailing byte");
        assert!(
            decode_global(&bytes[..bytes.len() - 1]).is_err(),
            "a byte short"
        );
    }

    /// The post-GKR and final sections refuse a trailing byte the same way.
    #[test]
    fn the_later_sections_refuse_trailing_bytes() {
        let mut gkrs = encode_gkrs(&[]);
        assert!(decode_gkrs(&gkrs).unwrap().is_empty());
        gkrs.push(0);
        assert!(decode_gkrs(&gkrs).is_err());
        let g = global();
        let mut last = encode_final(&g.statement, &[]);
        let (public, proofs) = decode_final(&last).expect("the final section decodes");
        assert_eq!((public, proofs.len()), (g.statement, 0));
        last.push(0);
        assert!(decode_final(&last).is_err());
    }
}
