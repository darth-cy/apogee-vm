//! The **streaming prover**: one execution proved as a block without the whole
//! trace ever being live. `docs/spec/streaming.md` specifies it.
//!
//! ```text
//! PASS 1 -- EXECUTE                      PASS 2 -- REEXECUTE + PROVE
//!   max_in_flight workers, one executor    the same, over the same execution
//!   a worker with no shard claims one:     a worker with no shard claims one:
//!     it steps the guest until a buffer      it steps the guest until a buffer
//!     fills, and drops the shard             fills, fills that shard's
//!                                            columns, proves it, drops it
//!                                          at exit: the window shards
//!   the statement, then G1-G9              the block
//! ```
//!
//! Pass 1 fills each shard's `M` columns and commits them as the shard fills —
//! the window families' after the execution ends — so that the global
//! transcript absorbs every commitment before the memory challenges exist.
//! Pass 2 fills every column again and commits the `M` columns again, which a
//! shard's opening holds to pass 1's commitment: a pass that built different
//! columns makes a proof that fails.
//!
//! What differs from the archived path (`docs/spec/streaming.md` §6) is
//! **when** a column exists. Every absorption, every challenge and every proof
//! byte is what [`crate::prove_block`] produces over the same execution, by
//! construction; `crates/prover/tests/block.rs` holds the global commit phase
//! and every shard's proof, rebuilt from an archive, to the streamed block's
//! bytes.
//!
//! What it buys is a peak that does not grow with the shard or cycle count.
//! `emulator::trace_run`'s output, about 300 bytes a cycle between the memory
//! event log and the family buffers, does not exist here: the executor is
//! [`emulator::StreamingRun`], which holds one partial buffer per family and
//! the last-access tables, and this module holds at most `max_in_flight` shards
//! at a time (`docs/spec/streaming.md` §1).
//!
//! **The work is pulled, never pushed** (`docs/spec/streaming.md` §5). There
//! is no producer running ahead of the workers: a worker that has finished its
//! shard claims the next one, and only then — and only if no shard the executor
//! already filled is waiting — does it step the guest, under the pipeline's one
//! lock, until a buffer fills. Everything a shard grows into —
//! its columns, its forward pass and its proof — is built by
//! the worker that claimed it, after it claimed it, so `max_in_flight` bounds
//! every shard heavier than rows. And no worker waits on another: there is no
//! batch, so no barrier for the slowest shard of one to hold the rest behind.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

use emulator::{EmuError, GuestIo, ShardChunk, StreamedExecution, StreamingRun};
use rayon::prelude::*;
use trace::{build_boundary_finals, init_windows, plan_shards, FrameSlice, RowSlice};
use verifier_core::{
    statement_shards, window_height, BlockProof, BoundaryFinals, Commitment, PublicInputs,
    ShardProof,
};

use constraints::PolyAddress;
use poly::MultilinearPoly;

use program::FamilyId;

#[cfg(feature = "debug-info")]
use crate::debug;
use crate::{
    global_commit_of, memory_commitment, public_inputs, shard_counts, window_of, GlobalCommitState,
    ProverError, ProverSetup, ProvingContext, ShardRows, ShardSource,
};

/// What a streaming run measured about itself.
///
/// It is a measurement and never an input: the block is byte-identical whatever
/// this says, and nothing in a proof reads it. Each pass has one wall clock,
/// and the executor's time is a **part** of it and not a slice beside it: the
/// guest is stepped by whichever worker needs the next shard while the others
/// work on theirs, so the two overlap (`docs/spec/streaming.md` §5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamingReport {
    /// The execution's cycle count.
    pub cycles: u64,
    /// How many shards the statement holds.
    pub shards: usize,
    /// The most shards held at once in either pass, each claimed by a worker —
    /// or in one of the window families' batches — and not yet finished: its
    /// rows, and whatever columns, forward pass and proof it had grown into so
    /// far. At most `max_in_flight`, which is what the peak is a
    /// function of.
    ///
    /// It does not count a shard the executor has filled and no worker has
    /// claimed yet. That is rows and nothing else, at most one shard of them
    /// per family — the executor's own buffers, under a new owner.
    pub peak_in_flight: usize,
    pub max_in_flight: usize,
    /// Pass 1's wall clock: the execution, the statement and G1-G9.
    pub pass1_ns: u64,
    /// The executor's time in pass 1, summed over every step any worker took.
    /// A part of `pass1_ns`.
    pub pass1_execute_ns: u64,
    /// Pass 2's wall clock: the second execution and every shard's proof.
    pub pass2_ns: u64,
    /// The executor's time in pass 2. A part of `pass2_ns`.
    pub pass2_execute_ns: u64,
}

/// The shards in flight every proving path in this repository uses: 8, the
/// owner's default since 2026-11-16, until a caller knows its machine better.
///
/// Measured that day on an r8i.8xlarge (32 threads) over the three business
/// guests at `2^20` execution shards:
/// - 4 → 8 cut prove time by 16–25%, for 10–13 GiB more peak, with the
///   CPU-seconds unchanged: the extra shards fill idle threads;
/// - 16 added nothing for an 11-shard statement, whose pipeline held at most
///   7 at once, and 4% for an 18-shard one.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 8;

/// Prove one execution of `setup`'s program over `io` as a block, streaming.
///
/// `max_in_flight` is the backpressure: the number of workers, each holding at
/// most one shard at a time, and therefore what bounds the peak. It is an
/// argument and not a constant because the caller is the only one that knows
/// the machine, [`DEFAULT_MAX_IN_FLIGHT`] the default — a `2^20` `BITWISE` shard's forward pass alone is
/// 4.2 GiB (`docs/spec/streaming.md` §1). The work inside each shard runs on
/// rayon's pool, so
/// `RAYON_NUM_THREADS` is the cores the shards share and `max_in_flight` is
/// how many shards share them. It must be at least 1.
///
/// A worker claims a shard **before** anything heavier than its rows exists: it
/// steps the executor itself, and only when no filled shard is waiting. So the
/// shards no worker holds are rows, at most one per family — at exit every
/// family's partial buffer becomes a shard at once — and those are the buffers
/// the executor held anyway.
///
/// The block does not depend on it. Shards are placed by their statement
/// position, each proof is a function of the global state and its own columns
/// alone, and `tests/streaming.rs` proves the bytes equal at `max_in_flight` 1
/// and 8.
///
/// **Only an execution that exits 0 is proved.** Any other status is
/// [`ProverError::NonzeroExit`], the moment pass 1's execution ends and before
/// any shard is proven — but after pass 1 has committed the `M` columns of
/// every shard the execution filled, since the status exists only at the exit.
pub fn prove_block_streaming(
    setup: &ProverSetup,
    io: &GuestIo,
    max_in_flight: usize,
) -> Result<(BlockProof, StreamingReport), ProverError> {
    assert!(max_in_flight >= 1, "max_in_flight must be at least 1");
    debug_only!(debug::banner("prove_block_streaming"));
    dlog!(
        Phase,
        "apogee stream   begin max_in_flight={} families={}",
        max_in_flight,
        setup.families.len()
    );
    let mut report = StreamingReport {
        max_in_flight,
        ..StreamingReport::default()
    };
    let (global, done) = pass1(setup, io, max_in_flight, &mut report)?;
    let proofs = pass2(setup, io, &global, &done, max_in_flight, &mut report)?;
    let statement = public_inputs(&global, &proofs);
    let block = BlockProof {
        config: setup.program.config.clone(),
        statement,
        shards: proofs,
    };
    block
        .shape()
        .map_err(|e| ProverError::Trace(format!("the streamed block is not well shaped: {e}")))?;
    Ok((block, report))
}

/// Which shard of which family, and where it sits in statement order.
type ShardId = (FamilyId, u32);

/// PASS 1: execute, commit every shard's `M` columns, and fix the statement.
///
/// A shard the execution fills is committed by the worker that claimed it,
/// and the window families' after the pipeline, over the final state, in
/// batches under the same bound; the commitments are placed in statement order
/// for the global transcript to absorb (`docs/spec/proof.md` §2).
fn pass1(
    setup: &ProverSetup,
    io: &GuestIo,
    max_in_flight: usize,
    report: &mut StreamingReport,
) -> Result<(GlobalCommitState, StreamedExecution), ProverError> {
    let started = Instant::now();
    let config = &setup.program.config;
    // A config with no window height is refused before the guest runs.
    window_height(config).map_err(|e| ProverError::Trace(e.to_string()))?;

    let run = StreamingRun::new(&setup.program.image, io, &setup.program.tables, config)
        .map_err(|e| ProverError::Trace(e.to_string()))?;
    let piped = pipeline(1, run, max_in_flight, |chunk| {
        let height = setup.registration(chunk.family).height;
        memory_commitment(setup, chunk.family, &chunk_source(setup, io, chunk, height))
    })?;
    report.pass1_execute_ns = piped.execute_ns;
    let mut peak = piped.peak_in_flight;
    let done = piped.done;
    let filled = piped.results;
    report.cycles = done.execution.cycle_count;
    let ids: Vec<ShardId> = filled.iter().map(|(id, _)| *id).collect();
    let Record {
        windows,
        counts,
        boundary,
        status,
    } = record(setup, io, &done, &ids)?;
    // Every shard's memory commitment in statement order: the filled shards'
    // from the pipeline, the window families' now.
    let order = statement_shards(config, &counts);
    let mut commitments: Vec<Option<Commitment>> = vec![None; order.len()];
    for ((family, index), c) in filled {
        commitments[position(&order, family, index)] = Some(c);
    }
    let pending: Vec<ShardId> = order
        .iter()
        .zip(&commitments)
        .filter(|(_, c)| c.is_none())
        .map(|(id, _)| *id)
        .collect();
    for batch in pending.chunks(max_in_flight) {
        peak = peak.max(batch.len());
        let made = first_error(
            batch
                .par_iter()
                .map(|&(family, index)| {
                    let source = window_source(setup, io, &done, &windows, family, index);
                    memory_commitment(setup, family, &source)
                })
                .collect(),
        )?;
        for (&(family, index), c) in batch.iter().zip(made) {
            commitments[position(&order, family, index)] = Some(c);
        }
    }
    let memory_commitments: Vec<Commitment> = commitments
        .into_iter()
        .map(|c| c.expect("every statement shard is filled or a window shard"))
        .collect();
    report.peak_in_flight = report.peak_in_flight.max(peak);
    report.shards = order.len();

    let statement = PublicInputs {
        input: done.execution.io.input.clone(),
        output: done.execution.io.output.clone(),
        exit_status: status,
        shard_counts: counts,
        windows,
        boundary,
        memory_commitments,
        memory_roots: Vec::new(),
    };
    let global = global_commit_of(&setup.vk, statement);
    report.pass1_ns = started.elapsed().as_nanos() as u64;
    dlog!(
        Phase,
        "apogee stream   pass 1 done shards={} ms={:.1} execute_ms={:.1} peak_in_flight={}/{}",
        report.shards,
        report.pass1_ns as f64 / 1e6,
        report.pass1_execute_ns as f64 / 1e6,
        peak,
        max_in_flight
    );
    Ok((global, done))
}

/// The statement's variable-length record of a finished execution, and its
/// exit status.
struct Record {
    windows: Vec<u32>,
    counts: Vec<u32>,
    boundary: BoundaryFinals,
    status: u32,
}

/// The record pass 1 commits, all of it a function of the last-access tables
/// and the profile: the window list, the shard counts and the register/pc
/// boundary (`docs/spec/memory.md` §3.4, §4.1). `filled` is every shard the
/// execution filled.
fn record(
    setup: &ProverSetup,
    io: &GuestIo,
    done: &StreamedExecution,
    filled: &[ShardId],
) -> Result<Record, ProverError> {
    let config = &setup.program.config;
    let h = window_height(config).map_err(|e| ProverError::Trace(e.to_string()))?;
    let windows = init_windows(&done.state, h);
    let counts = shard_counts(config, &done.profile, &io.advice, &windows, h);
    let boundary = build_boundary_finals(&done.state);

    // **Only an execution that exits 0 is provable** (`docs/spec/proof.md`
    // §6, step 0). The status, `x10`'s final low word, exists once the guest
    // has exited, which is here: refused before a window shard is committed,
    // before the statement and before pass 2 proves any shard. The shards the
    // execution filled have had their `M` columns committed by now, and that
    // work is lost; a caller that would rather not pay it executes the guest
    // first, as `host::prove` does.
    let status = boundary.reg_values[9] as u32;
    if status != 0 {
        return Err(ProverError::NonzeroExit { status });
    }

    // The cut the streaming executor made is the plan's, family by family. It
    // cannot differ -- both are `ceil(rows / height)` over the same rows -- and
    // an assertion is what says so out loud rather than leaving the reader to
    // check `flush_family` against `plan_shards`.
    let plan = plan_shards(&done.profile, config);
    for (family, count) in &plan.shards {
        let n = filled.iter().filter(|(f, _)| f == family).count();
        assert_eq!(
            n,
            *count as usize,
            "streaming: {} filled {n} shards and the plan counts {count}",
            program::family_name(*family)
        );
    }
    Ok(Record {
        windows,
        counts,
        boundary,
        status,
    })
}

/// The fill's view of a shard a streaming run has just filled.
///
/// The chunk's rows **are** the shard's, so the cut is index 0 over the chunk
/// itself; `chunk.index` is the shard's real index and goes in the source for
/// the fills that read it. A window family never arrives as a chunk.
fn chunk_source<'a>(
    setup: &'a ProverSetup,
    io: &'a GuestIo,
    chunk: &'a ShardChunk,
    height: u32,
) -> ShardSource<'a> {
    let rows = match &chunk.calls {
        Some(calls) => ShardRows::Invocations(FrameSlice::shard(calls, 0, height as usize)),
        None => ShardRows::Cycles(RowSlice::shard(&chunk.rows, 0, height as usize)),
    };
    ShardSource {
        program: &setup.program,
        input: &io.input,
        advice: &io.advice,
        rows,
        index: chunk.index,
        height: height as usize,
        window: 0,
    }
}

/// PASS 2: execute the identical guest again and prove each shard as it fills.
///
/// The executor is a pure function of `(image, io)` — no clock, no randomness,
/// no threads — so this pass runs the same cycles in the same order and cuts
/// the same shards. What it must not do is re-derive the *statement*: that is
/// pass 1's, absorbed and challenged already, and this pass asserts its own
/// execution agrees with it rather than recomputing it. A shard's opening holds
/// this pass's columns to pass 1's memory commitments, so a pass which built
/// different columns produces a proof that fails verification.
fn pass2(
    setup: &ProverSetup,
    io: &GuestIo,
    global: &GlobalCommitState,
    pass1: &StreamedExecution,
    max_in_flight: usize,
    report: &mut StreamingReport,
) -> Result<Vec<ShardProof>, ProverError> {
    let started = Instant::now();
    let config = &setup.program.config;
    let order = statement_shards(config, &global.statement.shard_counts);
    let ctx = ProvingContext {
        setup,
        global: global.clone(),
    };

    let run = StreamingRun::new(&setup.program.image, io, &setup.program.tables, config)
        .map_err(|e| ProverError::Trace(e.to_string()))?;
    let piped = pipeline(2, run, max_in_flight, |chunk| {
        let height = setup.registration(chunk.family).height;
        let source = chunk_source(setup, io, chunk, height);
        prove_source(&ctx, chunk.family, chunk.index, &source)
    })?;
    report.pass2_execute_ns = piped.execute_ns;
    let mut peak = piped.peak_in_flight;
    let done = piped.done;
    let mut proofs: Vec<Option<ShardProof>> = (0..order.len()).map(|_| None).collect();
    for ((family, index), proof) in piped.results {
        let at = position(&order, family, index);
        assert!(
            proofs[at].replace(proof).is_none(),
            "streaming: shard ({}, {index}) was proved twice",
            program::family_name(family)
        );
    }

    // The two passes ran the same execution. Everything the statement carries
    // is checked here, cheaply, because a divergence would otherwise show up as
    // a proof nobody can verify and no message saying why.
    //
    // What is NOT compared is the last-access tables themselves: they are
    // `O(touched addresses)`, which for a large execution is tens of millions
    // of entries, and what the statement actually carries out of them is the
    // two things below. The window families' teardown *columns* are the
    // residue, which their openings hold to pass 1's commitments.
    assert_eq!(
        done.profile, pass1.profile,
        "streaming: the two passes ran different executions"
    );
    assert_eq!(
        done.execution, pass1.execution,
        "streaming: the two passes reached different results"
    );
    let h = window_height(config).map_err(|e| ProverError::Trace(e.to_string()))?;
    assert_eq!(
        init_windows(&done.state, h),
        global.statement.windows,
        "streaming: the two passes touched different RAM windows"
    );
    assert_eq!(
        build_boundary_finals(&done.state),
        global.statement.boundary,
        "streaming: the two passes left different boundary values"
    );

    // The window families last, over pass 2's own final state, in batches under
    // the same bound.
    let windows = global.statement.windows.clone();
    let mut pending: Vec<(FamilyId, u32)> = Vec::new();
    for (at, (family, index)) in order.iter().enumerate() {
        if proofs[at].is_none() {
            pending.push((*family, *index));
        }
    }
    for batch in pending.chunks(max_in_flight) {
        peak = peak.max(batch.len());
        let proved = first_error(
            batch
                .par_iter()
                .map(|&(family, index)| {
                    let source = window_source(setup, io, &done, &windows, family, index);
                    prove_source(&ctx, family, index, &source)
                })
                .collect(),
        )?;
        for ((family, index), proof) in batch.iter().zip(proved) {
            let at = position(&order, *family, *index);
            proofs[at] = Some(proof);
        }
    }
    report.peak_in_flight = report.peak_in_flight.max(peak);

    let proofs: Vec<ShardProof> = order
        .iter()
        .zip(proofs)
        .map(|((family, index), proof)| {
            proof.ok_or_else(|| {
                ProverError::Trace(format!(
                    "streaming: no shard ({}, {index}) reached pass 2",
                    program::family_name(*family)
                ))
            })
        })
        .collect::<Result<_, _>>()?;
    report.pass2_ns = started.elapsed().as_nanos() as u64;
    dlog!(
        Phase,
        "apogee stream   pass 2 done shards={} ms={:.1} execute_ms={:.1} peak_in_flight={}/{}",
        proofs.len(),
        report.pass2_ns as f64 / 1e6,
        report.pass2_execute_ns as f64 / 1e6,
        peak,
        max_in_flight
    );
    Ok(proofs)
}

/// The fill's view of window shard `(family, index)`: the execution's final
/// state, after it has exited.
fn window_source<'a>(
    setup: &'a ProverSetup,
    io: &'a GuestIo,
    done: &'a StreamedExecution,
    windows: &[u32],
    family: FamilyId,
    index: u32,
) -> ShardSource<'a> {
    let height = setup.registration(family).height;
    ShardSource {
        program: &setup.program,
        input: &done.execution.io.input,
        advice: &io.advice,
        rows: ShardRows::Window(&done.state),
        index,
        height: height as usize,
        window: window_of(family, index, windows, height),
    }
}

/// One shard's proof from its fill's source: the committed columns, then the
/// GKR proof over one base layer and the opening. Pass 2's work on a shard, for a chunk a worker
/// claimed and for a window shard alike.
fn prove_source(
    ctx: &ProvingContext,
    family: FamilyId,
    index: u32,
    source: &ShardSource,
) -> Result<ShardProof, ProverError> {
    #[cfg(feature = "debug-info")]
    let clock = debug::Clock::start();
    let columns = crate::shard_columns_of(ctx.setup, family, source)?;
    #[cfg(feature = "debug-info")]
    let fill_ms = clock.ms();
    let (proof, _events) = crate::prove_shard_columns(ctx, family, index, columns);
    dlog!(
        Phase,
        family = family,
        "apogee stream   pass 2 proved {:<22} fill_ms={fill_ms} ms={}",
        debug::shard(family, index),
        clock.ms()
    );
    Ok(proof)
}

fn position(order: &[(FamilyId, u32)], family: FamilyId, index: u32) -> usize {
    order
        .iter()
        .position(|s| *s == (family, index))
        .unwrap_or_else(|| {
            panic!(
                "streaming: the statement has no shard ({}, {index})",
                program::family_name(family)
            )
        })
}

/// The results in order, or the **first** of them that failed — rayon's
/// `collect::<Result<_, _>>()` returns an unspecified error when more than one
/// task fails, and a diagnostic that named a different cycle on a different
/// machine would be one nobody could reproduce (`crate::phases::first_error`).
fn first_error<T>(results: Vec<Result<T, ProverError>>) -> Result<Vec<T>, ProverError> {
    results.into_iter().collect()
}

// ---------------------------------------------------------------------------
// The witness pass
// ---------------------------------------------------------------------------

/// One statement shard's committed columns, as pass 2 fills them for its
/// proof: what [`witness_block_streaming`] hands its caller, shard by shard.
pub struct ShardWitness {
    pub family: FamilyId,
    pub index: u32,
    /// Every committed column, `M`, `W` and `S`, multiplicities last: the
    /// family's fill and `trace::build_multiplicities`, which is what
    /// `prove_shard_columns` receives in pass 2.
    pub columns: Vec<(PolyAddress, MultilinearPoly)>,
    /// The statement's `ZERO_WINDOWS` list for a window family's shard, whose
    /// challenges read it (`verifier_core::shard_challenges`). Empty for a
    /// shard the execution fills: that shard exists before the list does,
    /// and its challenges do not read it.
    pub windows: Vec<u32>,
}

/// What [`witness_block_streaming`] leaves.
pub struct WitnessedBlock<T> {
    /// The statement pass 1 commits, without its memory commitments and
    /// roots: the streams, the exit status, the shard counts, the window list
    /// and the boundary.
    pub statement: PublicInputs,
    /// The caller's result for every statement shard, in statement order.
    pub shards: Vec<T>,
    /// Pass 1's fields of a [`StreamingReport`]: the cycle and shard counts,
    /// the most shards held at once, the wall clock and the executor's time.
    pub report: StreamingReport,
}

/// Why [`witness_block_streaming`] stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WitnessError<E> {
    /// The executor stopped the guest: a fatal guest error, or
    /// `EmuError::CycleLimit` past the cap.
    Execution(EmuError),
    /// The prover refused, as pass 1 would: a nonzero exit status, or a
    /// column it cannot build.
    Prover(ProverError),
    /// The caller refused a shard.
    Work(E),
}

/// One execution of `setup`'s program over `io`, every statement shard's
/// committed columns built as pass 2 builds them and handed to `work`,
/// committing and proving nothing: the witness a proof of the execution would
/// be made from, for a caller that checks it first (`host::check`).
///
/// It is pass 1's execution, under a cap: `emulator::StreamingRun` stopped at
/// `max_cycles` (`emulator::run_bounded`), the same image, input and advice,
/// the same pipeline of `max_in_flight` workers, so the same bound on the
/// shards held at once (`docs/spec/streaming.md` §5), and the same statement,
/// whose record it returns. Where pass 1 commits a shard's `M` columns, this
/// fills every column, multiplicities included, through the fill pass 2's
/// proof takes them from, and calls `work` on them.
///
/// The failure returned is the earliest, as the pipeline's is: in fill order
/// for the shards the execution fills, an executor failure after every shard
/// it filled, then the record's — a nonzero exit status — and then the window
/// shards' in statement order.
pub fn witness_block_streaming<T: Send, E: Send>(
    setup: &ProverSetup,
    io: &GuestIo,
    max_in_flight: usize,
    max_cycles: u64,
    work: impl Fn(ShardWitness) -> Result<T, E> + Sync,
) -> Result<WitnessedBlock<T>, WitnessError<E>> {
    assert!(max_in_flight >= 1, "max_in_flight must be at least 1");
    let started = Instant::now();
    let config = &setup.program.config;
    window_height(config).map_err(|e| WitnessError::Prover(ProverError::Trace(e.to_string())))?;
    let witness = |family, index, source: &ShardSource, windows: Vec<u32>| {
        let columns =
            crate::shard_columns_of(setup, family, source).map_err(WitnessError::Prover)?;
        work(ShardWitness {
            family,
            index,
            columns,
            windows,
        })
        .map_err(WitnessError::Work)
    };

    let run = StreamingRun::new_bounded(
        &setup.program.image,
        io,
        &setup.program.tables,
        config,
        max_cycles,
    )
    .map_err(WitnessError::Execution)?;
    let piped = pipeline_with(
        1,
        run,
        max_in_flight,
        |chunk| {
            let height = setup.registration(chunk.family).height;
            let source = chunk_source(setup, io, chunk, height);
            witness(chunk.family, chunk.index, &source, Vec::new())
        },
        WitnessError::Execution,
    )?;
    let done = piped.done;
    let ids: Vec<ShardId> = piped.results.iter().map(|(id, _)| *id).collect();
    let Record {
        windows,
        counts,
        boundary,
        status,
    } = record(setup, io, &done, &ids).map_err(WitnessError::Prover)?;

    let order = statement_shards(config, &counts);
    let mut shards: Vec<Option<T>> = (0..order.len()).map(|_| None).collect();
    for ((family, index), result) in piped.results {
        shards[position(&order, family, index)] = Some(result);
    }
    // The window families last, over the final state, in batches under the
    // same bound, as pass 1 commits them.
    let pending: Vec<ShardId> = order
        .iter()
        .zip(&shards)
        .filter(|(_, result)| result.is_none())
        .map(|(id, _)| *id)
        .collect();
    let mut peak = piped.peak_in_flight;
    for batch in pending.chunks(max_in_flight) {
        peak = peak.max(batch.len());
        let made: Vec<Result<T, WitnessError<E>>> = batch
            .par_iter()
            .map(|&(family, index)| {
                let source = window_source(setup, io, &done, &windows, family, index);
                witness(family, index, &source, windows.clone())
            })
            .collect();
        for (&(family, index), result) in batch.iter().zip(made) {
            shards[position(&order, family, index)] = Some(result?);
        }
    }
    let report = StreamingReport {
        cycles: done.execution.cycle_count,
        shards: order.len(),
        peak_in_flight: peak,
        max_in_flight,
        pass1_ns: started.elapsed().as_nanos() as u64,
        pass1_execute_ns: piped.execute_ns,
        ..StreamingReport::default()
    };
    let statement = PublicInputs {
        input: done.execution.io.input.clone(),
        output: done.execution.io.output.clone(),
        exit_status: status,
        shard_counts: counts,
        windows,
        boundary,
        memory_commitments: Vec::new(),
        memory_roots: Vec::new(),
    };
    Ok(WitnessedBlock {
        statement,
        shards: shards
            .into_iter()
            .map(|result| result.expect("every statement shard is filled or a window shard"))
            .collect(),
        report,
    })
}

// ---------------------------------------------------------------------------
// The pipeline
// ---------------------------------------------------------------------------

/// What [`pipeline`] hands back: every filled shard's result, in no particular
/// order, and what the execution left behind.
struct Piped<T> {
    results: Vec<(ShardId, T)>,
    done: StreamedExecution,
    /// The executor's time, summed over every step any worker took.
    execute_ns: u64,
    /// The most shards claimed and not yet given back at once.
    peak_in_flight: usize,
}

/// **The pipeline**: `workers` threads over one executor, each claiming the
/// next shard the moment it has finished its own, and `work` run on every shard
/// the execution fills.
///
/// These are the prover's only threads and its only lock
/// (`docs/spec/streaming.md` §5). What they buy over fork-join is the one
/// thing fork-join cannot say: *start the next shard when any one finishes*,
/// with fewer shards in flight than the pool has cores.
///
/// Four properties, each a consequence of the structure rather than of a
/// schedule, which is what makes them hold on every machine:
///
/// - **The bound.** A worker holds one shard at a time and there are `workers`
///   of them, so at most `workers` shards exist in any form heavier than rows.
///   The workers are not rayon threads: rayon's pool runs the work *inside*
///   each shard, and a worker blocked on it cannot take a second shard the way
///   a rayon thread parked in a nested join steals a second task, so a thread
///   count would bound nothing.
/// - **Demand.** The executor runs only inside [`Source::claim`], for the
///   worker claiming, and only when no shard it filled is waiting; so it never
///   runs ahead of the workers, and what waits is at most one shard of rows per
///   family ([`Source::admit`] asserts it).
/// - **No barrier.** A worker claims its next shard when its own is done, not
///   when its neighbours' are.
/// - **No deadlock and no lost failure.** There is one lock, never held while
///   a shard is worked and never taken twice. A failure stops every claim after
///   it, and the one returned is the earliest in fill order, which is the same
///   one at any worker count ([`Source::fail`]). A panic stops the claims too,
///   and is re-raised as itself once every worker has stopped.
///
/// What it does not decide is anything a proof reads: the block is assembled by
/// statement position afterwards, so the order shards finish in reaches
/// nothing.
fn pipeline<T: Send>(
    pass: u8,
    run: StreamingRun<'_>,
    workers: usize,
    work: impl Fn(&ShardChunk) -> Result<T, ProverError> + Sync,
) -> Result<Piped<T>, ProverError> {
    pipeline_with(pass, run, workers, work, |e| {
        ProverError::Trace(e.to_string())
    })
}

/// [`pipeline`] with its own error type: `stopped` is how an executor failure
/// reads as one, for [`witness_block_streaming`], whose caller matches on the
/// executor's own error rather than its text.
fn pipeline_with<T: Send, E: Send>(
    pass: u8,
    run: StreamingRun<'_>,
    workers: usize,
    work: impl Fn(&ShardChunk) -> Result<T, E> + Sync,
    stopped: fn(EmuError) -> E,
) -> Result<Piped<T>, E> {
    let source = Mutex::new(Source::new(pass, workers, run, stopped));
    let joined: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| scope.spawn(|| worker(&source, &work)))
            .collect();
        handles.into_iter().map(|h| h.join()).collect()
    });
    let mut results = Vec::new();
    for outcome in joined {
        match outcome {
            Ok(mine) => results.extend(mine),
            // The worker's own panic, as itself: its message names the shard
            // and the invariant, and a wrapper would only bury them.
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
    let source = source
        .into_inner()
        .expect("a poisoned pipeline is a worker's panic, and that was re-raised above");
    if let Some((_, error)) = source.failure {
        return Err(error);
    }
    Ok(Piped {
        results,
        done: source
            .done
            .expect("a pipeline that did not fail ran the guest to its exit"),
        execute_ns: source.execute_ns,
        peak_in_flight: source.peak,
    })
}

/// One worker: claim a shard, work it, give it back, claim the next — until
/// nothing is left to claim or the pipeline has stopped.
fn worker<T, E>(
    source: &Mutex<Source<'_, E>>,
    work: &impl Fn(&ShardChunk) -> Result<T, E>,
) -> Vec<(ShardId, T)> {
    let _stop = StopOnPanic(source);
    let mut mine = Vec::new();
    // The shard this worker last held, and whether its work failed: given back
    // in the same critical section that claims the next, so the count of shards
    // in flight never holds one twice or drops one.
    let mut held: Option<(u64, Option<E>)> = None;
    loop {
        let claimed = {
            // A poisoned lock is a worker that panicked inside the executor,
            // and that panic is what the pipeline re-raises.
            let Ok(mut shared) = source.lock() else {
                return mine;
            };
            if let Some((seq, failed)) = held.take() {
                shared.give_back(failed.map(|error| (seq, error)));
            }
            shared.claim()
        };
        let Some((seq, chunk)) = claimed else {
            return mine;
        };
        match work(&chunk) {
            Ok(result) => {
                mine.push(((chunk.family, chunk.index), result));
                held = Some((seq, None));
            }
            Err(error) => held = Some((seq, Some(error))),
        }
        // `chunk`, the shard's rows, goes here: before the next claim, so a
        // worker never holds two shards' rows.
    }
}

/// Stops the pipeline when the worker holding it unwinds, so that one shard's
/// panic costs the shards already in flight and not the rest of the block.
struct StopOnPanic<'s, 'a, E>(&'s Mutex<Source<'a, E>>);

impl<E> Drop for StopOnPanic<'_, '_, E> {
    fn drop(&mut self) {
        // A poisoned lock means the panic was inside the executor, and every
        // other worker stops on the poison itself.
        if std::thread::panicking() {
            if let Ok(mut shared) = self.0.lock() {
                shared.stop = true;
            }
        }
    }
}

/// What the workers share, behind the pipeline's one lock: the executor, the
/// shards it filled that no worker has claimed, and the counts.
struct Source<'a, E> {
    /// 1 or 2, for the log and the assertions.
    pass: u8,
    /// How many workers there are, which no count of claims may pass.
    workers: usize,
    /// The executor, until the guest exits.
    run: Option<StreamingRun<'a>>,
    /// What the execution left behind, once the guest has exited.
    done: Option<StreamedExecution>,
    /// Filled and not yet claimed, each with its place in fill order. Rows,
    /// and at most one shard of them per family ([`Source::admit`]).
    waiting: VecDeque<(u64, ShardChunk)>,
    /// How many shards the executor has filled: the next one's place.
    filled: u64,
    /// Shards claimed and not yet given back, and the most there have been.
    working: usize,
    peak: usize,
    /// The executor's time, summed over every step any worker took.
    execute_ns: u64,
    /// The earliest failure in fill order, and its place.
    failure: Option<(u64, E)>,
    /// An executor failure, as a failure.
    stopped: fn(EmuError) -> E,
    /// A failure or a panic has happened: nothing more is claimed.
    stop: bool,
}

impl<'a, E> Source<'a, E> {
    fn new(
        pass: u8,
        workers: usize,
        run: StreamingRun<'a>,
        stopped: fn(EmuError) -> E,
    ) -> Source<'a, E> {
        Source {
            pass,
            workers,
            run: Some(run),
            done: None,
            waiting: VecDeque::new(),
            filled: 0,
            working: 0,
            peak: 0,
            execute_ns: 0,
            failure: None,
            stopped,
            stop: false,
        }
    }

    /// The next shard, with its place in fill order, for a worker that holds
    /// none; `None` once the execution is over and every shard it filled has
    /// been claimed, or once the pipeline has stopped.
    ///
    /// **This is the only place the guest is stepped**, for the worker that is
    /// claiming, and only when no filled shard is waiting: demand, and not a
    /// producer, is what moves the execution forward.
    fn claim(&mut self) -> Option<(u64, ShardChunk)> {
        if self.stop {
            return None;
        }
        if self.waiting.is_empty() {
            let run = self.run.as_mut()?;
            let since = Instant::now();
            let stepped = match run.next_shards() {
                // The guest has exited: every partial buffer is now its
                // family's last shard. The window families' shards are not
                // the pipeline's (`docs/spec/streaming.md` §5).
                Ok(filled) if filled.is_empty() => {
                    match self.run.take().expect("the executor").finish() {
                        Ok((tail, done)) => {
                            self.done = Some(done);
                            Ok(tail)
                        }
                        Err(e) => Err(e),
                    }
                }
                stepped => stepped,
            };
            self.execute_ns += since.elapsed().as_nanos() as u64;
            match stepped {
                Ok(filled) => self.admit(filled),
                Err(e) => {
                    // Every shard filled before this step has been claimed —
                    // the executor steps only when none is waiting — so the
                    // failure's place is after all of them.
                    self.fail(self.filled, (self.stopped)(e));
                    return None;
                }
            }
        }
        let (seq, chunk) = self.waiting.pop_front()?;
        self.working += 1;
        assert!(
            self.working <= self.workers,
            "streaming: pass {}: {} shards claimed by {} workers",
            self.pass,
            self.working,
            self.workers
        );
        self.peak = self.peak.max(self.working);
        dlog!(
            Phase,
            family = chunk.family,
            "apogee stream   pass {} take {:<22} fill#{} in_flight={}/{} waiting={}",
            self.pass,
            debug::shard(chunk.family, chunk.index),
            seq,
            self.working,
            self.workers,
            self.waiting.len()
        );
        Some((seq, chunk))
    }

    /// Shards the executor has just filled, in the order it filled them.
    ///
    /// **At most one waits per family, and this is where that is enforced.** The
    /// executor steps only when nothing is waiting; one step fills at most one
    /// buffer a family — its cycle's, and a delegation call's families' — and the
    /// exit fills at most one per family. So a
    /// second shard of a family arriving while the first waits would mean
    /// production had run ahead of demand, which is the one thing it may not do.
    fn admit(&mut self, filled: Vec<ShardChunk>) {
        for chunk in filled {
            assert!(
                self.waiting.iter().all(|(_, w)| w.family != chunk.family),
                "streaming: pass {}: the executor filled a second {} shard before a worker \
                 claimed the first -- production must follow demand (docs/spec/streaming.md §5)",
                self.pass,
                program::family_name(chunk.family)
            );
            self.waiting.push_back((self.filled, chunk));
            self.filled += 1;
        }
    }

    /// A worker is done with the shard it held; `failed` is that shard's place
    /// in fill order and its error, if its work failed.
    fn give_back(&mut self, failed: Option<(u64, E)>) {
        self.working -= 1;
        if let Some((seq, error)) = failed {
            self.fail(seq, error);
        }
    }

    /// Record a failure at `seq` in fill order, and stop every claim after it.
    ///
    /// **The earliest wins, which makes the answer the same at any worker
    /// count.** Shards are claimed in fill order, so every shard before the
    /// first failure recorded has already been claimed, and a claimed shard is
    /// always worked to its end; if one of them fails too, it is recorded here,
    /// and it is earlier. A diagnostic that named a different shard on a
    /// different machine would be one nobody could reproduce.
    fn fail(&mut self, seq: u64, error: E) {
        if self.failure.as_ref().is_none_or(|(at, _)| seq < *at) {
            self.failure = Some((seq, error));
        }
        self.stop = true;
    }
}

#[cfg(test)]
mod tests {
    //! The pipeline over a real execution and no proof. `guests/shards`'
    //! counted loop at `2^16` fills seventeen add/sub shards in mid-run and
    //! every other family's at exit, which is both of the executor's paths; the
    //! work each test does on a shard is a stand-in that costs nothing. What a
    //! shard's proof is does not reach the pipeline, so nothing here needs one —
    //! that the block is the same at any `max_in_flight` is
    //! `tests/streaming.rs`, `#[ignore]`d.

    use std::time::Duration;

    use constants::family;
    use loader::{load_elf, ProgramImage};
    use program::{decode_program, DecodedTables, ProgramParams};
    use verifier_core::VmConfig;

    use super::*;

    struct Guest {
        image: ProgramImage,
        tables: DecodedTables,
        config: VmConfig,
        io: GuestIo,
    }

    /// `guests/shards`, every family at `2^16`: 1,064,970 add/sub cycles.
    fn shards() -> Guest {
        let image = load_elf(&test_support::guest_elf("shards")).expect("shards loads");
        let params = ProgramParams {
            heights: [1 << 16; family::COUNT as usize],
            ..ProgramParams::defaults()
        };
        let (tables, config) = decode_program(&image, &params).expect("shards decodes");
        let io = GuestIo {
            input: Vec::new(),
            advice: Vec::new(),
        };
        Guest {
            image,
            tables,
            config,
            io,
        }
    }

    fn run(guest: &Guest) -> StreamingRun<'_> {
        StreamingRun::new(&guest.image, &guest.io, &guest.tables, &guest.config)
            .expect("shards starts")
    }

    fn rows(chunk: &ShardChunk) -> usize {
        chunk.rows.len()
    }

    /// Every shard the execution fills, in fill order, with its row count: the
    /// executor drained on one thread with no pipeline at all.
    fn reference(guest: &Guest) -> (Vec<(ShardId, usize)>, StreamedExecution) {
        let mut run = run(guest);
        let mut filled = Vec::new();
        loop {
            let ready = run.next_shards().expect("shards streams");
            if ready.is_empty() {
                break;
            }
            filled.extend(ready.iter().map(|c| ((c.family, c.index), rows(c))));
        }
        let (tail, done) = run.finish().expect("shards finishes");
        filled.extend(tail.iter().map(|c| ((c.family, c.index), rows(c))));
        (filled, done)
    }

    /// Every shard the execution fills is worked exactly once, at any worker
    /// count, and never more than `workers` of them at once — the bound read
    /// twice, once off the pipeline's own count and once off the intervals the
    /// work itself recorded, which is an observation the count cannot vouch for.
    #[test]
    fn every_filled_shard_is_worked_once_and_never_more_than_workers_at_once() {
        let guest = shards();
        let (want, done) = reference(&guest);
        let add_sub = want
            .iter()
            .filter(|((f, _), _)| *f == family::ADD_SUB_LUI_AUIPC)
            .count();
        assert!(
            add_sub >= 17,
            "shards fills its add/sub buffer in mid-run, which is the path under test: {add_sub}"
        );
        let mut sorted = want.clone();
        sorted.sort();

        for workers in [1, 3, 8] {
            let piped = pipeline(1, run(&guest), workers, |chunk| {
                let start = Instant::now();
                std::thread::sleep(Duration::from_millis(2));
                Ok((rows(chunk), start, Instant::now()))
            })
            .expect("nothing here fails");

            let mut got: Vec<(ShardId, usize)> = piped
                .results
                .iter()
                .map(|(id, (n, ..))| (*id, *n))
                .collect();
            got.sort();
            assert_eq!(got, sorted, "{workers} workers: the shards worked");
            assert_eq!(piped.done.profile, done.profile, "{workers} workers");
            assert_eq!(piped.done.execution, done.execution, "{workers} workers");

            assert!(
                (1..=workers).contains(&piped.peak_in_flight),
                "{workers} workers: {} in flight",
                piped.peak_in_flight
            );
            let spans: Vec<(Instant, Instant)> = piped
                .results
                .iter()
                .map(|(_, (_, s, e))| (*s, *e))
                .collect();
            for (at, _) in &spans {
                let open = spans.iter().filter(|(s, e)| s <= at && at < e).count();
                assert!(
                    open <= workers,
                    "{workers} workers: {open} shards were being worked at once"
                );
            }
        }
    }

    /// **Demand drives the executor.** A claim steps the guest only when nothing
    /// it filled is waiting, and a claim made while a shard waits takes that
    /// shard without stepping at all; a second claim with the first still held
    /// is a second shard in flight. Single-threaded, so every count is exact.
    #[test]
    fn the_guest_is_stepped_only_for_a_claim_with_nothing_waiting() {
        let guest = shards();
        let (want, _) = reference(&guest);
        let mut source = Source::new(1, 2, run(&guest), |e| ProverError::Trace(e.to_string()));
        assert_eq!(source.filled, 0, "building the source steps nothing");

        let (first, a) = source.claim().expect("a first shard");
        let (second, b) = source.claim().expect("a second, with the first still held");
        assert_eq!((first, second), (0, 1), "claims are in fill order");
        assert_eq!(
            ((a.family, a.index), (b.family, b.index)),
            (want[0].0, want[1].0)
        );
        assert_eq!((source.working, source.peak), (2, 2));
        source.give_back(None);
        source.give_back(None);

        let mut claimed = 2;
        let mut without_a_step = 0;
        loop {
            let waiting = source.waiting.len();
            let filled = source.filled;
            let Some((seq, chunk)) = source.claim() else {
                break;
            };
            if waiting > 0 {
                assert_eq!(
                    source.filled, filled,
                    "a waiting shard was claimed and the guest was stepped anyway"
                );
                without_a_step += 1;
            }
            assert_eq!(seq, claimed, "claims are in fill order");
            assert_eq!((chunk.family, chunk.index), want[claimed as usize].0);
            claimed += 1;
            source.give_back(None);
        }
        assert!(
            without_a_step > 0,
            "the exit fills several families at once, so some claim found one waiting"
        );
        assert_eq!(
            claimed as usize,
            want.len(),
            "every filled shard was claimed"
        );
        assert_eq!(source.filled, claimed);
        assert_eq!(source.working, 0);
        assert!(source.run.is_none() && source.done.is_some());
    }

    /// The failure returned is the earliest in fill order, whatever the worker
    /// count — and it is a value, not a panic, so the caller can act on it.
    #[test]
    fn the_earliest_failure_in_fill_order_is_the_one_returned() {
        let guest = shards();
        let (want, _) = reference(&guest);
        // Every add/sub shard from the fifth on fails; the fifth is the answer.
        let fails = |(f, i): ShardId| f == family::ADD_SUB_LUI_AUIPC && i >= 4;
        let first = want
            .iter()
            .map(|(id, _)| *id)
            .find(|id| fails(*id))
            .expect("shards fills a fifth add/sub shard");
        for workers in [1, 4] {
            let error = pipeline(2, run(&guest), workers, |chunk| {
                let id = (chunk.family, chunk.index);
                if fails(id) {
                    Err(ProverError::Trace(format!("{id:?}")))
                } else {
                    Ok(())
                }
            })
            .err()
            .expect("a shard failed");
            assert_eq!(
                error,
                ProverError::Trace(format!("{first:?}")),
                "{workers} workers"
            );
        }
    }

    /// A panic in one shard's work reaches the caller as itself, and the
    /// pipeline does not hang on the shards it stopped claiming.
    #[test]
    fn a_panic_in_one_shard_reaches_the_caller_as_itself() {
        let guest = shards();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pipeline(1, run(&guest), 4, |chunk| {
                if (chunk.family, chunk.index) == (family::ADD_SUB_LUI_AUIPC, 2) {
                    panic!("add/sub shard two");
                }
                Ok(())
            })
        }));
        let panic = outcome.err().expect("the panic reached the caller");
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"add/sub shard two"),
            "the worker's own payload, not a wrapper's"
        );
    }
}
