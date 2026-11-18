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

mod common;

use std::collections::BTreeMap;

use common::{advice_of, exit_code_of, image, input_of, uniform, with_advice};
use constants::delegation::Per;
use emulator::{trace_run, ShardChunk, StreamingRun};
use program::{decode_program, family_name, FamilyId, ProgramParams};
use trace::{plan_shards, FamilyTraces, MemoryEventLog};

/// The guests this file streams, and the height each family takes: `2^16`,
/// which cuts no shard at all for most of them.
const GUESTS: [(&str, u32); 11] = [
    ("fib", 16),
    ("heap", 16),
    ("atomics", 16),
    ("opcodes", 16),
    ("rvc-dense", 16),
    ("addsub", 16),
    ("control", 16),
    ("alu", 16),
    ("mem", 16),
    // The counted loop: 1,064,970 add/sub cycles, so **seventeen** shards at
    // `2^16` and the only committed guest whose buffers fill mid-execution.
    // Without it every chunk here would come from the tail and the flush path
    // would never run.
    ("shards", 16),
    // The precompiles, their delegation families at `2^12`: 302 Poseidon2
    // calls fill the rounds' 256-call buffer mid-execution. Falcon's are at
    // `2^16`, and its 1,025 calls fill `FALCON_SPLIT`'s 1,024. The long trie
    // program's 6,151 ops fill `MPT_NODES`' 4,096 and its 4,100 hash ops
    // `MPT_ROUNDS`' 256, each mid-call. Every other family is at `2^18`, the
    // least height on the menu its decoded tables fit: its code runs past pc
    // `2^17`, a row being `pc/2`.
    ("precompiles", 18),
];

/// Every family at `2^height`; for `precompiles`, the delegation families at
/// `2^12`, but Falcon's at `2^16`, its `RANGE16` table's floor.
fn params(name: &str, height: u32) -> ProgramParams {
    use constants::family::{FALCON, FALCON_PRODUCT, FALCON_SPLIT};
    let mut p = uniform(1 << height);
    if name == "precompiles" {
        for (family, ..) in constants::delegation::TYPES {
            p.heights[family as usize] = match family {
                FALCON | FALCON_SPLIT | FALCON_PRODUCT => 1 << 16,
                _ => 1 << 12,
            };
        }
    }
    p
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
    let (tables, config) = decode_program(&image, &params(name, height))
        .unwrap_or_else(|e| panic!("{name} decodes at 2^{height}: {e}"));
    let guest_io = with_advice(&input_of(name), &advice_of(name));
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
    let (tables, config) = decode_program(&image, &params(name, height))
        .unwrap_or_else(|e| panic!("{name} decodes: {e}"));
    let guest_io = with_advice(&input_of(name), &advice_of(name));
    trace_run(&image, &guest_io, &tables, &config).unwrap_or_else(|e| panic!("{name} traces: {e}"))
}

#[test]
fn the_chunks_are_the_planned_shards_row_for_row() {
    let mut split_families = 0;
    // The op families' chunks that begin inside a program, by family: a
    // continuation the carry alone describes.
    let mut mid_program: BTreeMap<FamilyId, u32> = BTreeMap::new();
    // Each op family's last entry handed over: its cycle and its op index.
    let mut last: BTreeMap<FamilyId, (u64, u64)> = BTreeMap::new();
    let mut total_stops = 0;
    for (name, height) in GUESTS {
        let s = stream(name, height);
        let (traces, _, profile, execution) = whole(name, height);
        assert_eq!(s.execution.exit_code, exit_code_of(name), "{name}");
        assert_eq!(s.profile, profile, "{name}: the cycle profile");
        assert_eq!(s.execution, execution, "{name}: the execution");

        // Claim 1: the chunk set is the plan's, family by family.
        let plan = plan_shards(&profile, &{
            let (_, config) = decode_program(&image(name), &params(name, height)).expect("decodes");
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
        // `FALCON_SPLIT` is cut in two, `precompiles`' 1,025 calls against
        // the 1,024 a shard holds at `2^16`, while `FALCON_PRODUCT` holds
        // 4,096.
        if name == "precompiles" {
            use constants::family::{FALCON_PRODUCT, FALCON_SPLIT};
            for (family, shards) in [(FALCON_SPLIT, 2), (FALCON_PRODUCT, 1)] {
                assert_eq!(
                    counted.get(&family),
                    Some(&shards),
                    "{name} {}: {shards} shards",
                    family_name(family)
                );
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
            // A delegation chunk carries entries, each the buffer's own, at the
            // height over the family's rows an entry, and what each carries.
            if let Some(calls) = &chunk.calls {
                let buffer = traces
                    .delegation(chunk.family)
                    .expect("a delegation buffer");
                let per = (buffer.height / program::delegation_rows(chunk.family)) as usize;
                assert!(
                    calls.len() <= per && chunk.rows.is_empty(),
                    "{name}: a call chunk"
                );
                let start = chunk.index as usize * per;
                assert_eq!(
                    calls.cycle,
                    buffer.cycle[start..start + calls.len()],
                    "{name}"
                );
                assert_eq!(
                    calls.base,
                    buffer.base[start..start + calls.len()],
                    "{name}"
                );
                for (got, want) in calls.words.iter().zip(&buffer.words) {
                    assert_eq!(got.read_value, want.read_value[start..start + calls.len()]);
                    assert_eq!(
                        got.write_value,
                        want.write_value[start..start + calls.len()]
                    );
                    assert_eq!(got.read_ts, want.read_ts[start..start + calls.len()]);
                }
                for (got, want) in calls.carry.iter().zip(&buffer.carry) {
                    assert_eq!(got[..], want[start..start + calls.len()], "{name}: a carry");
                }
                // Carry value 9 is an op's index (`delegation::mpt::CARRY`). A
                // chunk begins inside a call where its first entry's is past 0,
                // or for a hash op's, which a LOAD before it has none of, where
                // the chunk before ended in the same call. It then continues
                // that one: the next op, or a later hash op.
                let kind = program::delegation_per(chunk.family);
                let index = |e: usize| calls.carry[9][e];
                let before = last.get(&chunk.family).copied();
                let mid = match kind {
                    Per::Op => index(0) > 0,
                    Per::Hash => before.is_some_and(|(cycle, _)| cycle == calls.cycle[0]),
                    _ => false,
                };
                if mid {
                    *mid_program.entry(chunk.family).or_default() += 1;
                    let (cycle, op) = before.expect("a chunk before");
                    assert_eq!(calls.cycle[0], cycle, "{name}: a program's ops in one call");
                    match kind {
                        Per::Op => assert_eq!(index(0), op + 1, "{name}: the next op"),
                        _ => assert!(index(0) > op, "{name}: a later hash op"),
                    }
                }
                if matches!(kind, Per::Op | Per::Hash) {
                    let end = calls.len() - 1;
                    last.insert(chunk.family, (calls.cycle[end], index(end)));
                }
                if program::delegation_rows(chunk.family) > 1 && calls.len() == per {
                    split_families += 1;
                }
                continue;
            }
            let rows = &chunk.rows;
            let buffer = traces
                .family(chunk.family)
                .unwrap_or_else(|| panic!("{name}: no {} buffer", family_name(chunk.family)));
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
        total_stops += s.stops;
    }
    // At least one family is cut into more than one shard: a comparison over
    // single-shard families alone would never test the index arithmetic.
    assert!(split_families >= 1, "{split_families} families cut in two");
    // And a program crosses a shard of each op family: `precompiles`' long
    // one's ops are 16 to 6,166, a node shard holding 4,096 and a round shard
    // 256 hash ops at `2^12`.
    for family in [constants::family::MPT_NODES, constants::family::MPT_ROUNDS] {
        assert!(
            mid_program.get(&family) >= Some(&1),
            "a {} shard begins inside a call",
            family_name(family)
        );
    }
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
    let full: usize = s.chunks.iter().filter(|c| c.rows.len() == 1 << 16).count();
    assert_eq!(full, 16, "sixteen full add/sub shards");
    assert!(
        s.stops >= full,
        "the executor stopped {} times for {full} full shards",
        s.stops
    );
    // Nothing is longer than a height, which is the invariant that makes a
    // chunk a shard. Every instruction commits exactly one cycle, so no
    // instruction can overshoot a height by more than a row — and the flush
    // happens inside `record` rather than between instructions, so the
    // property holds by construction and not by an argument about which
    // instructions exist.
    for chunk in &s.chunks {
        let rows = &chunk.rows;
        assert!(rows.len() <= 1 << 16, "a chunk of {} rows", rows.len());
    }
}
