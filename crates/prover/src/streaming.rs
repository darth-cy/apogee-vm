//! The **streaming prover**: one execution proved as a block without the whole
//! trace ever being live. `docs/spec/streaming.md` is normative.
//!
//! ```text
//! PASS 1 -- EXECUTE + PRECOMMIT          PASS 2 -- REEXECUTE + PROVE
//!   max_in_flight workers, one executor    the same, over the same execution
//!   a worker with no shard claims one:     a worker with no shard claims one:
//!     it steps the guest until a buffer      it steps the guest until a buffer
//!     fills, builds that shard's M,          fills, fills that shard's
//!     commits it, drops it                   columns, proves it, drops it
//!   at exit: the window shards             at exit: the window shards
//!   the statement, then G1-G11             the block
//! ```
//!
//! The one thing this changes is **when** a column exists. Every commitment,
//! every absorption, every challenge and every proof byte is what
//! [`crate::prove_block`] would have produced over the same execution — by
//! construction, and no longer by test: the comparison that held the two
//! blocks byte for byte ran the archived path, and went with it at S-STREAM
//! (`docs/spec/streaming.md` §6). `crates/prover/tests/block.rs`'s `a7` is
//! the one place an archived construction and a streamed one still meet.
//!
//! What it buys is a peak that does not grow with the shard count.
//! `prover::statement_inputs` builds every shard's memory columns and
//! `global_commit_phase` commits them all, so before S26 a block's commit phase
//! was `O(total shards)` — about 300 MB a shard, measured — which put a
//! 27.9M-gas Ethereum block at 500-600 GB before a single shard was proved
//! (`docs/handoff/S25-block.md` §7). Above that, `emulator::trace_run`'s own
//! output is `O(cycles)`: about 300 bytes a cycle between the memory event log
//! and the family buffers, so the same block's trace alone is ~520 GB. Neither
//! survives here: the executor is [`emulator::StreamingRun`], which holds one
//! partial buffer per family and the last-access tables, and this module holds
//! at most `max_in_flight` shards at a time.
//!
//! **The work is pulled, never pushed** (S-PIPELINE, `docs/spec/streaming.md`
//! §5). There is no producer running ahead of the workers: a worker that has
//! finished its shard claims the next one, and only then — and only if no shard
//! the executor already filled is waiting — does it step the guest, under the
//! pipeline's one lock, until a buffer fills. Everything a shard grows into —
//! its columns, its commitments, its forward pass and its proof — is built by
//! the worker that claimed it, after it claimed it, so `max_in_flight` bounds
//! every shard heavier than rows. And no worker waits on another: there is no
//! batch, so no barrier for the slowest shard of one to hold the rest behind.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Instant;

use emulator::{ChunkRows, GuestIo, ShardChunk, StreamedExecution, StreamingRun};
use rayon::prelude::*;
use trace::{build_boundary_finals, init_windows, plan_shards, FrameSlice, RowSlice};
use verifier_core::{statement_shards, window_height, BlockProof, PublicInputs, ShardProof};

use program::FamilyId;

#[cfg(feature = "debug-info")]
use crate::debug;
use crate::{
    global_commit_from_commitments, public_inputs, shard_counts, window_of, GlobalCommitState,
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
    /// rows, and whatever columns, commitments, forward pass and proof it had
    /// grown into so far. At most `max_in_flight`, which is what the peak is a
    /// function of.
    ///
    /// It does not count a shard the executor has filled and no worker has
    /// claimed yet. That is rows and nothing else, at most one shard of them
    /// per family — the executor's own buffers, under a new owner.
    pub peak_in_flight: usize,
    pub max_in_flight: usize,
    /// Pass 1's wall clock: the execution, every shard's memory commitments,
    /// the statement and G1-G11.
    pub pass1_ns: u64,
    /// The executor's time in pass 1, summed over every step any worker took.
    /// A part of `pass1_ns`.
    pub pass1_execute_ns: u64,
    /// Pass 2's wall clock: the second execution and every shard's proof.
    pub pass2_ns: u64,
    /// The executor's time in pass 2. A part of `pass2_ns`.
    pub pass2_execute_ns: u64,
}

/// Prove one execution of `setup`'s program over `io` as a block, streaming.
///
/// `max_in_flight` is the backpressure: the number of workers, each holding at
/// most one shard at a time, and therefore what bounds the peak. It is an
/// argument and not a constant because the caller is the only one that knows
/// the machine — a shard's base layer plus its forward pass is about 1.5 GB at
/// `2^20` and rather more for a delegation family. The work inside each shard
/// runs on rayon's pool, so `RAYON_NUM_THREADS` is the cores the shards share
/// and `max_in_flight` is how many shards share them. It must be at least 1.
///
/// A worker claims a shard **before** anything heavier than its rows exists: it
/// steps the executor itself, and only when no filled shard is waiting. So the
/// shards no worker holds are rows, at most one per family — a delegating ecall
/// fills two buffers in one step, and at exit every family's partial buffer
/// becomes a shard at once — and those are the buffers the executor held
/// anyway.
///
/// The block does not depend on it. Shards are placed by their statement
/// position, each proof is a function of the global state and its own columns
/// alone, and `tests/streaming.rs` proves the bytes equal at `max_in_flight` 1
/// and 8.
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

/// PASS 1: execute, and commit each shard's `M` columns as it fills.
///
/// The commitments come back in the order the workers finish them, which is
/// neither execution order nor statement order (`INIT_TEARDOWN` and
/// `ZERO_WINDOWS` come first there and are built last here), so they are
/// collected against their `(family, index)` and placed afterwards. A
/// commitment is an MSM over the SRS and reads no transcript, so when it is
/// computed cannot matter; the order they are **absorbed** in is the
/// statement's, and that is the frozen one (`docs/spec/proof.md` §2).
fn pass1(
    setup: &ProverSetup,
    io: &GuestIo,
    max_in_flight: usize,
    report: &mut StreamingReport,
) -> Result<(GlobalCommitState, StreamedExecution), ProverError> {
    let started = Instant::now();
    let config = &setup.program.config;
    let h = window_height(config).map_err(|e| ProverError::Trace(e.to_string()))?;

    let run = StreamingRun::new(&setup.program.image, io, &setup.program.tables, config)
        .map_err(|e| ProverError::Trace(e.to_string()))?;
    let piped = pipeline(1, run, max_in_flight, |chunk| {
        let height = setup.registration(chunk.family).height;
        let source = chunk_source(setup, io, chunk, height);
        commit_source(setup, chunk.family, chunk.index, &source)
    })?;
    report.pass1_execute_ns = piped.execute_ns;
    let mut peak = piped.peak_in_flight;
    let done = piped.done;
    let mut committed = piped.results;

    // The statement's variable-length record, all of it a function of the
    // last-access tables and the profile: the window list, the shard counts and
    // the register/pc boundary (`docs/spec/memory.md` §3.4, §4.1).
    let windows = init_windows(&done.state, h);
    let counts = shard_counts(config, &done.profile, &done.state, &io.advice, &windows, h);
    let boundary = build_boundary_finals(&done.state);
    report.cycles = done.execution.cycle_count;

    // The cut the streaming executor made is the plan's, family by family. It
    // cannot differ -- both are `ceil(rows / height)` over the same rows -- and
    // an assertion is what says so out loud rather than leaving the reader to
    // check `flush_family` against `plan_shards`.
    let plan = plan_shards(&done.profile, config);
    for (family, count) in &plan.shards {
        let filled = committed.iter().filter(|((f, _), _)| f == family).count();
        assert_eq!(
            filled,
            *count as usize,
            "streaming: {} filled {filled} shards and the plan counts {count}",
            program::family_name(*family)
        );
    }

    // The window families' shards, which no chunk carries: their rows are
    // addresses and their teardown columns are every address's LAST write, so
    // they are not a fact until the execution is over. Committed after the
    // pipeline, in batches under the same bound.
    let pending: Vec<ShardId> = statement_shards(config, &counts)
        .into_iter()
        .filter(|(family, _)| committed.iter().all(|((f, _), _)| f != family))
        .collect();
    for batch in pending.chunks(max_in_flight) {
        peak = peak.max(batch.len());
        let commitments = first_error(
            batch
                .par_iter()
                .map(|&(family, index)| {
                    let height = setup.registration(family).height;
                    let source = ShardSource {
                        program: &setup.program,
                        input: &done.execution.io.input,
                        advice: &io.advice,
                        rows: ShardRows::Window(&done.state),
                        index,
                        height: height as usize,
                        window: window_of(family, index, &windows, height),
                    };
                    commit_source(setup, family, index, &source)
                })
                .collect(),
        )?;
        committed.extend(batch.iter().copied().zip(commitments));
    }
    report.peak_in_flight = report.peak_in_flight.max(peak);

    // Statement order, from the list the two steps filled.
    let order = statement_shards(config, &counts);
    report.shards = order.len();
    let memory_commitments: Vec<Vec<[u8; 64]>> = order
        .iter()
        .map(|shard| {
            committed
                .iter()
                .find(|(id, _)| id == shard)
                .map(|(_, c)| c.clone())
                .unwrap_or_else(|| {
                    panic!(
                        "streaming: the statement holds shard ({}, {}) and pass 1 committed none",
                        program::family_name(shard.0),
                        shard.1
                    )
                })
        })
        .collect();
    assert_eq!(
        committed.len(),
        order.len(),
        "streaming: pass 1 committed {} shards and the statement holds {}",
        committed.len(),
        order.len()
    );

    // **A nonzero exit status, on a line of its own**, as the archived path's
    // statement phase prints one. A guest that panicked exits 101 having
    // published whatever it had committed so far — a journal that decodes, a
    // proof that verifies, and an answer to a different question. A run whose
    // guest aborted should not need a careful reading to say so, and on this
    // path there is no statement phase to say it anywhere else.
    if boundary.reg_values[9] != 0 {
        dlog!(
            Phase,
            "apogee ABORTED  the guest exited {} (x10), journal={}B: this proves an \
             execution that failed, not one that succeeded",
            boundary.reg_values[9],
            done.execution.io.output.len()
        );
    }

    let statement = PublicInputs {
        input: done.execution.io.input.clone(),
        output: done.execution.io.output.clone(),
        exit_status: boundary.reg_values[9],
        shard_counts: counts,
        windows,
        boundary,
        memory_commitments,
        memory_roots: Vec::new(),
    };
    let global = global_commit_from_commitments(&setup.vk, statement);
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

/// One shard's `M` columns, built, committed and dropped: pass 1's work on a
/// shard, for a chunk a worker claimed and for a window shard alike.
///
/// The fill is one thread and the commitments are rayon's, so while one worker
/// fills, the others' MSMs have the pool — which is the overlap pass 1 never
/// had while it committed one shard at a time.
fn commit_source(
    setup: &ProverSetup,
    family: FamilyId,
    index: u32,
    source: &ShardSource,
) -> Result<Vec<[u8; 64]>, ProverError> {
    // Declared under the `cfg` and read only inside one, so the default build
    // has neither the binding nor the `Instant::now` behind it.
    #[cfg(feature = "debug-info")]
    let clock = debug::Clock::start();
    let memory = crate::memory_columns_of(setup, family, index, source)?;
    #[cfg(feature = "debug-info")]
    let fill_ms = clock.ms();
    let commitments = crate::commit_phase(
        &setup.srs,
        &memory.iter().collect::<Vec<_>>(),
        crate::sigma_of(setup, family),
    );
    dlog!(
        Phase,
        family = family,
        "apogee stream   pass 1 committed {:<22} M={} fill_ms={fill_ms} ms={}",
        debug::shard(family, index),
        commitments.len(),
        clock.ms()
    );
    Ok(commitments)
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
    let rows = match &chunk.rows {
        ChunkRows::Cycles(t) => ShardRows::Cycles(RowSlice::shard(t, 0, height as usize)),
        ChunkRows::Invocations(t) => {
            ShardRows::Invocations(FrameSlice::shard(t, 0, height as usize))
        }
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
/// execution agrees with it rather than recomputing it.
///
/// **The `M` columns are not recommitted.** A shard's opening builds `cm*` from
/// the statement's memory commitments — pass 1's — while its polynomial side is
/// this pass's columns, so a pass that built different columns produces an
/// opening that **fails verification**. That is a stronger check than a prover
/// assertion and it costs nothing: the prover checks nothing (S13) and the
/// verifier checks this already.
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
    // that is not a commitment is checked here, cheaply, because a divergence
    // would otherwise show up as a proof nobody can verify and no message
    // saying why.
    //
    // What is NOT compared is the last-access tables themselves: they are
    // `O(touched addresses)`, which for a real block is tens of millions of
    // entries, and what the statement actually carries out of them is the two
    // things below. The window families' teardown *columns* are the residue, and
    // the opening is what catches those — `cm*` is built from pass 1's
    // commitments (§2).
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
                    let height = setup.registration(family).height;
                    let source = ShardSource {
                        program: &setup.program,
                        input: &done.execution.io.input,
                        advice: &io.advice,
                        rows: ShardRows::Window(&done.state),
                        index,
                        height: height as usize,
                        window: window_of(family, index, &windows, height),
                    };
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

/// One shard's proof from its fill's source: the committed columns, then the
/// GKR proof and the opening over one base layer. Pass 2's work on a shard, for
/// a chunk a worker claimed and for a window shard alike.
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
/// This is the repository's one use of threads and of a lock, and master
/// anti-goal 7 names it as the one exception (`docs/spec/streaming.md` §5;
/// `crates/prover/tests/one_pipeline.rs` holds every other file to the rule).
/// What it buys over fork-join is the one thing fork-join cannot say: *start
/// the next shard when any one finishes*, with fewer shards in flight than the
/// pool has cores.
///
/// Four properties, each a consequence of the structure rather than of a
/// schedule, which is what makes them hold on every machine:
///
/// - **The bound.** A worker holds one shard at a time and there are `workers`
///   of them, so at most `workers` shards exist in any form heavier than rows.
///   The workers are not rayon threads: rayon's pool runs the work *inside*
///   each shard, and a worker blocked on it cannot take a second shard the way
///   a rayon thread parked in a nested join steals a second task — which is how
///   the archived path's thread count failed to bound anything
///   (`docs/handoff/S-BATCH-miniblock-gate.md` §3).
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
    let source = Mutex::new(Source::new(pass, workers, run));
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
fn worker<T>(
    source: &Mutex<Source<'_>>,
    work: &impl Fn(&ShardChunk) -> Result<T, ProverError>,
) -> Vec<(ShardId, T)> {
    let _stop = StopOnPanic(source);
    let mut mine = Vec::new();
    // The shard this worker last held, and whether its work failed: given back
    // in the same critical section that claims the next, so the count of shards
    // in flight never holds one twice or drops one.
    let mut held: Option<(u64, Option<ProverError>)> = None;
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
struct StopOnPanic<'s, 'a>(&'s Mutex<Source<'a>>);

impl Drop for StopOnPanic<'_, '_> {
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
struct Source<'a> {
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
    failure: Option<(u64, ProverError)>,
    /// A failure or a panic has happened: nothing more is claimed.
    stop: bool,
}

impl<'a> Source<'a> {
    fn new(pass: u8, workers: usize, run: StreamingRun<'a>) -> Source<'a> {
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
                // the pipeline's (§3.2).
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
                    self.fail(self.filled, ProverError::Trace(e.to_string()));
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
    /// executor steps only when nothing is waiting; one step fills at most two
    /// buffers — the requesting family's and, for a delegating ecall, the
    /// delegation family's — and the exit fills at most one per family. So a
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
    fn give_back(&mut self, failed: Option<(u64, ProverError)>) {
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
    fn fail(&mut self, seq: u64, error: ProverError) {
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
    //! `tests/streaming.rs`, deferred.

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
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../loader/tests/vectors/shards.elf"
        );
        let elf = std::fs::read(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
        let image = load_elf(&elf).expect("shards loads");
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
        match &chunk.rows {
            ChunkRows::Cycles(t) => t.len(),
            ChunkRows::Invocations(t) => t.len(),
        }
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
        let mut source = Source::new(1, 2, run(&guest));
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
