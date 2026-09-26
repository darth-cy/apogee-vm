//! The **streaming executor** against `trace_run`, on every traced guest.
//!
//! `emulator::StreamingRun` is the same instruction core with a different
//! recorder: one partial buffer per family instead of the whole execution, and
//! the last-access tables instead of the event log (`docs/spec/streaming.md`
//! §3). This file is what says the two are one execution described twice —
//! which is the whole basis on which a streamed block can be the block
//! `prove_block` would have made.
//!
//! Four claims, over the same guests `tests/trace.rs` runs:
//!
//! 1. the chunks are exactly the shards `trace::plan_shards` counts, and each
//!    chunk's rows are exactly that slice of `trace_run`'s buffer, row for row;
//! 2. no chunk is longer than its family's height, so a partial buffer never
//!    holds more than `height − 1` rows and a shard needs no splitting;
//! 3. the final memory state is the log's — every register, every RAM word and
//!    the pc — so the boundary, the window list and every teardown column a
//!    streaming prover builds are the ones an archived one builds;
//! 4. the cycle profile and the `Execution` are equal, so the statement's
//!    descriptor and its public values are the same.
//!
//! The delegation guests are here for arm 2 of `ChunkRows`: `keccak-test` and
//! `recursion-ops` flush `DelegationTrace` chunks at `2^8`, which is small
//! enough that they flush **more than once** and the shard index arithmetic is
//! exercised rather than assumed.

mod common;

use std::collections::BTreeMap;

use common::{exit_code_of, image, input_of, io, uniform};
use emulator::{trace_run, ChunkRows, ShardChunk, StreamingRun};
use program::{decode_program, family_name, FamilyId, ProgramParams};
use trace::{plan_shards, FamilyTraces, MemoryEventLog};

/// The guests this file streams, and the height each family takes.
///
/// `smallest` for the plain ones, which puts every family at `2^16` and so cuts
/// no shard at all for most of them; the two delegation guests take `2^8` for
/// their delegation families, which is the menu's smallest and what a real
/// statement gives them (`docs/spec/delegation.md` §9), so their invocation
/// buffers flush.
const GUESTS: [(&str, u32); 13] = [
    ("fib", 16),
    ("heap", 16),
    ("atomics", 16),
    ("opcodes", 16),
    ("rvc-dense", 16),
    ("addsub", 16),
    ("control", 16),
    ("alu", 16),
    ("mem", 16),
    ("keccak-test", 16),
    ("recursion-ops", 16),
    // **`2^18` and not `2^16`**: its `.text` reaches pc `0x2161a`, and a decoded
    // table's row `i` is pc `2i`, so `2^16` rows run out at `0x20000`. It is the
    // second committed guest to need a taller table, `consistency` being the
    // first (`crates/program/tests/partition.rs`).
    ("mod-mul-ops", 18),
    // S20's counted loop: 1,064,970 add/sub cycles, so **seventeen** shards at
    // `2^16` and the only committed guest whose buffers fill mid-execution.
    // Without it every chunk here would come from the tail and the flush path
    // would never run.
    ("shards", 16),
];

/// Every family at `2^height`, but each **delegation** family at `2^8` so its
/// invocations are cut into more than one shard.
fn params(height: u32) -> ProgramParams {
    let mut params = uniform(1 << height);
    for (family, ..) in program::DELEGATIONS {
        params.heights[family as usize] = 1 << 8;
    }
    params
}

/// One guest streamed: every chunk in the order it filled, and what the
/// execution left behind.
struct Streamed {
    chunks: Vec<ShardChunk>,
    state: trace::MemoryState,
    profile: trace::CycleProfile,
    execution: emulator::Execution,
    /// How many times `next_shards` returned a non-empty batch: the number of
    /// times the executor actually stopped, which says the loop is pull-based
    /// rather than one batch at the end.
    stops: usize,
}

fn stream(name: &str, height: u32) -> Streamed {
    let image = image(name);
    let (tables, config) = decode_program(&image, &params(height))
        .unwrap_or_else(|e| panic!("{name} decodes at 2^{height}: {e}"));
    let guest_io = io(&input_of(name));
    let mut run = StreamingRun::new(&image, &guest_io, &tables, &config)
        .unwrap_or_else(|e| panic!("{name} starts: {e}"));
    let mut chunks = Vec::new();
    let mut stops = 0;
    loop {
        let ready = run
            .next_shards()
            .unwrap_or_else(|e| panic!("{name} streams: {e}"));
        if ready.is_empty() {
            break;
        }
        stops += 1;
        chunks.extend(ready);
    }
    let (tail, done) = run
        .finish()
        .unwrap_or_else(|e| panic!("{name} finishes: {e}"));
    chunks.extend(tail);
    Streamed {
        chunks,
        state: done.state,
        profile: done.profile,
        execution: done.execution,
        stops,
    }
}

/// The same guest through `trace_run`, over the same heights and the same io.
fn whole(
    name: &str,
    height: u32,
) -> (
    FamilyTraces,
    MemoryEventLog,
    trace::CycleProfile,
    emulator::Execution,
) {
    let image = image(name);
    let (tables, config) =
        decode_program(&image, &params(height)).unwrap_or_else(|e| panic!("{name} decodes: {e}"));
    trace_run(&image, &io(&input_of(name)), &tables, &config)
        .unwrap_or_else(|e| panic!("{name} traces: {e}"))
}

#[test]
fn the_chunks_are_the_planned_shards_row_for_row() {
    let mut delegation_chunks = 0;
    let mut split_families = 0;
    let mut total_stops = 0;
    for (name, height) in GUESTS {
        let s = stream(name, height);
        let (traces, _, profile, execution) = whole(name, height);
        assert_eq!(s.execution.exit_code, exit_code_of(name), "{name}");
        assert_eq!(s.profile, profile, "{name}: the cycle profile");
        assert_eq!(s.execution, execution, "{name}: the execution");

        // Claim 1: the chunk set is the plan's, family by family.
        let plan = plan_shards(&profile, &{
            let (_, config) = decode_program(&image(name), &params(height)).expect("decodes");
            config
        });
        let mut counted: BTreeMap<FamilyId, u32> = BTreeMap::new();
        for chunk in &s.chunks {
            *counted.entry(chunk.family).or_default() += 1;
        }
        for (family, count) in &plan.shards {
            assert_eq!(
                counted.get(family).copied().unwrap_or(0),
                *count,
                "{name} {}: shard count",
                family_name(*family)
            );
            if *count > 1 {
                split_families += 1;
            }
        }

        // Claim 1 continued, and claim 2: each chunk is the buffer's own slice,
        // at most a height long, and the indices of a family are 0.. in order.
        let mut next: BTreeMap<FamilyId, u32> = BTreeMap::new();
        for chunk in &s.chunks {
            let want = next.entry(chunk.family).or_default();
            assert_eq!(
                chunk.index,
                *want,
                "{name} {}: shard index",
                family_name(chunk.family)
            );
            *want += 1;
            match &chunk.rows {
                ChunkRows::Cycles(rows) => {
                    let buffer = traces.family(chunk.family).unwrap_or_else(|| {
                        panic!("{name}: no {} buffer", family_name(chunk.family))
                    });
                    let h = buffer.height as usize;
                    assert!(
                        rows.len() <= h,
                        "{name}: a chunk of {} rows at height {h}",
                        rows.len()
                    );
                    let start = chunk.index as usize * h;
                    for r in 0..rows.len() {
                        assert_eq!(
                            rows.row(r),
                            buffer.row(start + r),
                            "{name} {} shard {} row {r}",
                            family_name(chunk.family),
                            chunk.index
                        );
                    }
                }
                ChunkRows::Invocations(rows) => {
                    delegation_chunks += 1;
                    let buffer = traces.delegation(chunk.family).unwrap_or_else(|| {
                        panic!("{name}: no {} buffer", family_name(chunk.family))
                    });
                    let h = buffer.height as usize;
                    assert!(
                        rows.len() <= h,
                        "{name}: a chunk of {} rows at height {h}",
                        rows.len()
                    );
                    let start = chunk.index as usize * h;
                    for r in 0..rows.len() {
                        assert_eq!(rows.cycle[r], buffer.cycle[start + r], "{name} cycle {r}");
                        assert_eq!(rows.base[r], buffer.base[start + r], "{name} base {r}");
                        assert_eq!(rows.frame(r), buffer.frame(start + r), "{name} frame {r}");
                    }
                }
            }
        }
        total_stops += s.stops;
    }
    // Both arms of `ChunkRows` are exercised, and at least one family is cut
    // into more than one shard: a comparison over single-shard families alone
    // would never test the index arithmetic.
    assert!(
        delegation_chunks >= 2,
        "{delegation_chunks} delegation chunks"
    );
    assert!(split_families >= 1, "{split_families} families cut in two");
    // And the executor really stopped mid-execution rather than handing
    // everything back from the tail: `shards`' add/sub family fills sixteen
    // times before its last short shard.
    assert!(
        total_stops >= 16,
        "the executor stopped {total_stops} times"
    );
}

#[test]
fn the_streamed_state_is_the_logs() {
    for (name, height) in GUESTS {
        let s = stream(name, height);
        let (_, log, _, _) = whole(name, height);
        assert_eq!(
            s.state.final_state(),
            log.final_state(),
            "{name}: the last-access tables"
        );
        // And what a prover reads off them: the window list at three heights,
        // and the register and pc boundary.
        for h in [1u32 << 16, 1 << 20, 1 << 22] {
            assert_eq!(
                trace::init_windows(&s.state, h),
                trace::init_windows(log.state(), h),
                "{name}: the window list at {h} rows"
            );
        }
        assert_eq!(
            trace::build_boundary_finals(&s.state),
            trace::build_boundary_finals(log.state()),
            "{name}: the boundary"
        );
    }
}

/// The streaming run holds **one partial buffer per family**, and that is a
/// claim about the executor's own state rather than about its output.
///
/// What can be checked from outside is the consequence: a family whose rows are
/// cut into `k` shards hands back `k` chunks, each at most a height long, and
/// the executor stops at least `k` times — so at no point did it hold two
/// shards of one family.
#[test]
fn the_executor_holds_one_partial_shard_per_family() {
    // `guests/shards`' add/sub family runs 1,064,970 cycles, so at `2^16` it is
    // cut into seventeen shards -- sixteen full and one short. Every full one
    // was handed over the moment it filled, which is what the stop count says:
    // had the executor held them, it would have stopped once, at the end.
    let s = stream("shards", 16);
    let full: usize = s
        .chunks
        .iter()
        .filter(|c| match &c.rows {
            ChunkRows::Cycles(rows) => rows.len() == 1 << 16,
            ChunkRows::Invocations(_) => false,
        })
        .count();
    assert_eq!(full, 16, "sixteen full add/sub shards");
    assert!(
        s.stops >= full,
        "the executor stopped {} times for {full} full shards",
        s.stops
    );
    // Nothing is longer than a height, which is the invariant that makes a
    // chunk a shard: a `read` or `write` ecall commits one transfer cycle per
    // word it moves, so a single instruction can push many rows at once and a
    // flush that only ran between instructions could overshoot.
    for chunk in &s.chunks {
        if let ChunkRows::Cycles(rows) = &chunk.rows {
            assert!(rows.len() <= 1 << 16, "a chunk of {} rows", rows.len());
        }
    }
}
