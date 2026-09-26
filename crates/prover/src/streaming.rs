//! The **streaming prover**: one execution proved as a block without the whole
//! trace ever being live. `docs/spec/streaming.md` is normative.
//!
//! ```text
//! PASS 1 -- EXECUTE + PRECOMMIT        PASS 2 -- REEXECUTE + PROVE
//!   execute the guest                    execute the same guest again
//!   a shard fills -> build its M         a shard fills -> queue it
//!   commit M, keep the commitment        the queue reaches N -> prove them
//!   drop M and the shard                 write the proofs, drop the shards
//!   at exit: the window shards           at exit: the window shards
//!   the statement, then G1-G11           the block
//! ```
//!
//! The one thing this changes is **when** a column exists. Every commitment,
//! every absorption, every challenge and every proof byte is what
//! [`crate::prove_block`] would have produced over the same execution, and
//! `crates/prover/tests/streaming.rs` holds the two blocks byte for byte.
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

use std::time::Instant;

use emulator::{ChunkRows, GuestIo, ShardChunk, StreamedExecution, StreamingRun};
use rayon::prelude::*;
use trace::{build_boundary_finals, init_windows, plan_shards, FrameSlice, RowSlice};
use verifier_core::{statement_shards, window_height, BlockProof, PublicInputs, ShardProof};

use program::FamilyId;

use crate::metrics::Recorder;
use crate::{
    global_commit_from_commitments, public_inputs, shard_counts, window_of, GlobalCommitState,
    ProverError, ProverSetup, ProvingContext, ShardRows, ShardSource,
};

/// What a streaming run measured about itself.
///
/// It is a measurement and never an input: the block is byte-identical whatever
/// this says, and nothing in a proof reads it. The two passes' clocks are sums
/// of disjoint intervals, because execution and proving interleave — the
/// executor runs until a shard fills, and then stops while that shard is dealt
/// with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StreamingReport {
    /// The execution's cycle count, transfer cycles included.
    pub cycles: u64,
    /// How many shards the statement holds.
    pub shards: usize,
    /// The largest number of filled shards held at once, which is what the peak
    /// is a function of. At most `max_in_flight`.
    pub peak_in_flight: usize,
    pub max_in_flight: usize,
    pub pass1_execute_ns: u64,
    pub pass1_commit_ns: u64,
    pub pass2_execute_ns: u64,
    pub pass2_prove_ns: u64,
}

/// Prove one execution of `setup`'s program over `io` as a block, streaming.
///
/// `max_in_flight` is the backpressure: the number of filled shards that may be
/// held between the executor and the proving workers, and therefore what bounds
/// the peak. It is an argument and not a constant because the caller is the only
/// one that knows the machine — a shard's base layer plus its forward pass is
/// about 1.5 GB at `2^20` and rather more for a delegation family — and it is
/// the knob `RAYON_NUM_THREADS` used to be: the batch is proved with a rayon
/// parallel iterator over at most that many shards. It must be at least 1.
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
    let mut report = StreamingReport {
        max_in_flight,
        ..StreamingReport::default()
    };
    let (global, done) = pass1(setup, io, &mut report)?;
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
/// The commitments come out in the order the shards fill, which is execution
/// order and not statement order (`INIT_TEARDOWN` and `ZERO_WINDOWS` come
/// first there and are built last here), so they are collected against their
/// `(family, index)` and placed afterwards. A commitment is an MSM over the
/// SRS and reads no transcript, so when it is computed cannot matter; the order
/// they are **absorbed** in is the statement's, and that is the frozen one
/// (`docs/spec/shard-proof.md` §2).
fn pass1(
    setup: &ProverSetup,
    io: &GuestIo,
    report: &mut StreamingReport,
) -> Result<(GlobalCommitState, StreamedExecution), ProverError> {
    let config = &setup.program.config;
    let h = window_height(config).map_err(|e| ProverError::Trace(e.to_string()))?;
    let mut committed: Vec<(ShardId, Vec<[u8; 64]>)> = Vec::new();
    let mut streamed: Vec<(FamilyId, u64)> = Vec::new();

    let mut run = StreamingRun::new(&setup.program.image, io, &setup.program.tables, config)
        .map_err(|e| ProverError::Trace(e.to_string()))?;
    loop {
        let since = Instant::now();
        let ready = run
            .next_shards()
            .map_err(|e| ProverError::Trace(e.to_string()))?;
        report.pass1_execute_ns += since.elapsed().as_nanos() as u64;
        if ready.is_empty() {
            break;
        }
        commit_chunks(setup, io, &ready, &mut committed, &mut streamed, report)?;
    }
    let since = Instant::now();
    let (tail, done) = run
        .finish()
        .map_err(|e| ProverError::Trace(e.to_string()))?;
    report.pass1_execute_ns += since.elapsed().as_nanos() as u64;
    commit_chunks(setup, io, &tail, &mut committed, &mut streamed, report)?;

    // The statement's variable-length record, all of it a function of the
    // last-access tables and the profile: the window list, the shard counts and
    // the register/pc boundary (`docs/spec/memory.md` §3.4, §4.1).
    let windows = init_windows(&done.state, h);
    let counts = shard_counts(config, &done.profile, &io.advice, &windows, h);
    let boundary = build_boundary_finals(&done.state);
    report.cycles = done.execution.cycle_count;

    // The cut the streaming executor made is the plan's, family by family. It
    // cannot differ -- both are `ceil(rows / height)` over the same rows -- and
    // an assertion is what says so out loud rather than leaving the reader to
    // check `flush_family` against `plan_shards`.
    let plan = plan_shards(&done.profile, config);
    for (family, count) in &plan.shards {
        let filled = streamed
            .iter()
            .find(|(f, _)| f == family)
            .map_or(0, |(_, n)| *n);
        assert_eq!(
            filled,
            *count as u64,
            "streaming: {} filled {filled} shards and the plan counts {count}",
            program::family_name(*family)
        );
    }

    // The window families' shards, which no chunk carries: their rows are
    // addresses and their teardown columns are every address's LAST write, so
    // they are not a fact until the execution is over.
    for (family, index) in statement_shards(config, &counts) {
        if streamed.iter().any(|(f, _)| *f == family) {
            continue;
        }
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
        let since = Instant::now();
        let m = crate::memory_columns_of(setup, family, index, &source)?;
        committed.push(((family, index), crate::commit_all_owned(&setup.srs, &m)));
        report.pass1_commit_ns += since.elapsed().as_nanos() as u64;
    }

    // Statement order, from the map the two loops filled.
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
    Ok((global_commit_from_commitments(&setup.vk, statement), done))
}

/// Build and commit each of `ready`'s `M` columns, then drop the columns.
///
/// One shard at a time: a shard's `M` list is 36 columns for the add/sub family
/// and the commitment of each is an MSM over `2^20` points, so the parallelism
/// is already inside `commit_all` and holding two shards' columns here would buy
/// nothing but a second shard's worth of peak.
fn commit_chunks(
    setup: &ProverSetup,
    io: &GuestIo,
    ready: &[ShardChunk],
    committed: &mut Vec<(ShardId, Vec<[u8; 64]>)>,
    streamed: &mut Vec<(FamilyId, u64)>,
    report: &mut StreamingReport,
) -> Result<(), ProverError> {
    for chunk in ready {
        let since = Instant::now();
        let height = setup.registration(chunk.family).height;
        let source = chunk_source(setup, io, chunk, height);
        let m = crate::memory_columns_of(setup, chunk.family, chunk.index, &source)?;
        committed.push((
            (chunk.family, chunk.index),
            crate::commit_all_owned(&setup.srs, &m),
        ));
        match streamed.iter_mut().find(|(f, _)| *f == chunk.family) {
            Some((_, n)) => *n += 1,
            None => streamed.push((chunk.family, 1)),
        }
        report.pass1_commit_ns += since.elapsed().as_nanos() as u64;
    }
    Ok(())
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
    let config = &setup.program.config;
    let order = statement_shards(config, &global.statement.shard_counts);
    let ctx = ProvingContext {
        setup,
        global: global.clone(),
    };
    let mut proofs: Vec<Option<ShardProof>> = (0..order.len()).map(|_| None).collect();
    let mut queue: Vec<ShardChunk> = Vec::new();

    let mut run = StreamingRun::new(&setup.program.image, io, &setup.program.tables, config)
        .map_err(|e| ProverError::Trace(e.to_string()))?;
    loop {
        let since = Instant::now();
        let ready = run
            .next_shards()
            .map_err(|e| ProverError::Trace(e.to_string()))?;
        report.pass2_execute_ns += since.elapsed().as_nanos() as u64;
        if ready.is_empty() {
            break;
        }
        queue.extend(ready);
        while queue.len() >= max_in_flight {
            let batch: Vec<ShardChunk> = queue.drain(..max_in_flight).collect();
            prove_chunks(&ctx, io, &batch, &order, &mut proofs, report)?;
        }
    }
    let since = Instant::now();
    let (tail, done) = run
        .finish()
        .map_err(|e| ProverError::Trace(e.to_string()))?;
    report.pass2_execute_ns += since.elapsed().as_nanos() as u64;
    queue.extend(tail);
    while !queue.is_empty() {
        let take = max_in_flight.min(queue.len());
        let batch: Vec<ShardChunk> = queue.drain(..take).collect();
        prove_chunks(&ctx, io, &batch, &order, &mut proofs, report)?;
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

    // The window families last, over pass 2's own final state.
    let windows = global.statement.windows.clone();
    let mut pending: Vec<(FamilyId, u32)> = Vec::new();
    for (at, (family, index)) in order.iter().enumerate() {
        if proofs[at].is_none() {
            pending.push((*family, *index));
        }
    }
    for batch in pending.chunks(max_in_flight) {
        let since = Instant::now();
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
        report.pass2_prove_ns += since.elapsed().as_nanos() as u64;
        for ((family, index), proof) in batch.iter().zip(proved) {
            let at = position(&order, *family, *index);
            proofs[at] = Some(proof);
        }
    }

    order
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
        .collect()
}

/// Prove one batch of filled shards, in parallel, and place each proof at its
/// statement position.
///
/// This is the block's one parallel step, as it is in
/// `docs/spec/block-proof.md` §5.2, and it is bounded by the batch rather than
/// by the core count: each task builds its shard's columns, its base layer, its
/// GKR proof and its opening and then drops all of it, so the peak is
/// `min(threads, batch)` shards' worth and the batch is the caller's
/// `max_in_flight`.
fn prove_chunks(
    ctx: &ProvingContext,
    io: &GuestIo,
    batch: &[ShardChunk],
    order: &[(FamilyId, u32)],
    proofs: &mut [Option<ShardProof>],
    report: &mut StreamingReport,
) -> Result<(), ProverError> {
    report.peak_in_flight = report.peak_in_flight.max(batch.len());
    let since = Instant::now();
    let proved = first_error(
        batch
            .par_iter()
            .map(|chunk| {
                let height = ctx.setup.registration(chunk.family).height;
                let source = chunk_source(ctx.setup, io, chunk, height);
                prove_source(ctx, chunk.family, chunk.index, &source)
            })
            .collect(),
    )?;
    report.pass2_prove_ns += since.elapsed().as_nanos() as u64;
    for (chunk, proof) in batch.iter().zip(proved) {
        let at = position(order, chunk.family, chunk.index);
        assert!(
            proofs[at].replace(proof).is_none(),
            "streaming: shard ({}, {}) was proved twice",
            program::family_name(chunk.family),
            chunk.index
        );
    }
    Ok(())
}

/// One shard's proof from its fill's source: the committed columns, then the
/// GKR proof and the opening over one base layer.
fn prove_source(
    ctx: &ProvingContext,
    family: FamilyId,
    index: u32,
    source: &ShardSource,
) -> Result<ShardProof, ProverError> {
    let columns = crate::shard_columns_of(ctx.setup, family, source)?;
    let (proof, _events) =
        crate::prove_shard_columns_rec(ctx, family, index, columns, &mut Recorder::new());
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
