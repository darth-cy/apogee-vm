//! The memory frame's columns, built **from the memory event log**: the
//! independent reading of `docs/spec/memory.md` §2.1 and §2.4 that
//! `crates/trace`'s production builders are held to.
//!
//! `trace::build_memory_columns` and `trace::build_frame_witness` read a
//! shard's **rows**, because that is what a streaming prover has in hand — it
//! never materializes the log at all (`docs/spec/streaming.md` §3). This module
//! is the same two tables computed from the log instead, sharing no code with
//! them, so that "a shard's columns are its execution's memory queries" stays a
//! claim something checks rather than a claim the one implementation defines.
//! `crates/checker/tests/memory.rs` is where the two are compared, over every
//! fixture guest's real execution.
//!
//! It is a validator and not a prover path: nothing here is reachable from
//! `crates/prover`, and it is `O(events)` per shard by design, the log being
//! the thing it reads.

use constants::lookup_channel;
use constants::memory::TS_STEP;
use constraints::memory::{
    deleg_space, frame, frame_query_takes, gap_hi, rd_inv, rd_is_zero, rd_selected, CYCLE, DELEG,
    FIELD_ADDR, FIELD_MASK, FIELD_READ_TS, FIELD_READ_VALUE, FIELD_WRITE_VALUE, FRAME_DELTA, RD,
};
use constraints::PolyAddress;
use field::Fr;
use poly::{MultilinearPoly, PolyBacking};
use trace::{AddressSpace, MemoryEvent, MemoryEventLog};

/// `values`, zero-padded to `height`, in the narrowest backing that holds its
/// largest entry — `docs/spec/memory.md`'s column convention, written out here
/// rather than shared, because a column that differed only in its backing would
/// be a difference this comparison must catch.
fn column(mut values: Vec<u64>, height: usize) -> MultilinearPoly {
    values.resize(height, 0);
    let max = values.iter().copied().max().unwrap_or(0);
    let backing = if max <= 1 {
        let mut limbs = vec![0u64; height.div_ceil(64)];
        for (i, v) in values.iter().enumerate() {
            limbs[i / 64] |= v << (i % 64);
        }
        PolyBacking::U1(limbs, height)
    } else if max <= u8::MAX as u64 {
        PolyBacking::U8(values.into_iter().map(|v| v as u8).collect())
    } else if max <= u16::MAX as u64 {
        PolyBacking::U16(values.into_iter().map(|v| v as u16).collect())
    } else if max <= u32::MAX as u64 {
        PolyBacking::U32(values.into_iter().map(|v| v as u32).collect())
    } else {
        PolyBacking::Fr(values.into_iter().map(Fr::from_u64).collect())
    };
    MultilinearPoly::new(backing)
}

/// Each of `cycles`' frame queries, `None` where the cycle has none, from one
/// pass over the log.
///
/// An event takes the first slot of its row still free whose space and slot are
/// its own — the routing rule of `docs/spec/memory.md` §2.1, which is exact for
/// every query but the three slot-2 register ones, and those fill in log order.
/// A **delegation invocation's** frame access belongs to no cycle's row: it
/// rides the requesting cycle at `constants::delegation::FRAME_DELTA` and is
/// that family's row (`docs/spec/delegation.md` §4.1), so that one `(space, Δ)`
/// pair is skipped by name and every other unmatched event panics.
fn frame_rows(
    log: &MemoryEventLog,
    queries: &[usize],
    cycles: &[u64],
    height: usize,
) -> Vec<Vec<Option<MemoryEvent>>> {
    assert!(
        cycles.len() <= height,
        "memory columns: {} cycles do not fit {height} rows",
        cycles.len()
    );
    let top = cycles.iter().copied().max().unwrap_or(0);
    let mut row_of: Vec<Option<usize>> = vec![None; top as usize + 1];
    for (i, &cycle) in cycles.iter().enumerate() {
        assert!(
            row_of[cycle as usize].replace(i).is_none(),
            "memory columns: cycle {cycle} is asked for twice"
        );
    }
    let mut rows = vec![vec![None; queries.len()]; cycles.len()];
    for event in log.events() {
        let Some(&Some(i)) = row_of.get(event.cycle() as usize) else {
            continue;
        };
        if event.space == AddressSpace::Ram && event.delta() == constants::delegation::FRAME_DELTA {
            continue;
        }
        let row = &mut rows[i];
        let at = (0..queries.len())
            .find(|&at| {
                let q = queries[at];
                row[at].is_none() && frame_query_takes(q, event.space.tag(), event.delta())
            })
            .unwrap_or_else(|| {
                panic!(
                    "memory columns: cycle {} has a {:?} query at slot {} that no free frame \
                     query of {queries:?} takes",
                    event.cycle(),
                    event.space,
                    event.delta()
                )
            });
        row[at] = Some(*event);
    }
    for (row, cycle) in rows.iter().zip(cycles) {
        assert!(
            row[0].is_some(),
            "memory columns: the log has no cycle {cycle}"
        );
    }
    rows
}

/// An execution family's `1 + 5·queries.len()` frame columns from the log,
/// `docs/spec/memory.md` §2.1: the independent reading of
/// `trace::build_memory_columns`.
pub fn memory_columns_from_log(
    log: &MemoryEventLog,
    queries: &[usize],
    cycles: &[u64],
    height: usize,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let rows = frame_rows(log, queries, cycles, height);
    let mut out = vec![(CYCLE, column(cycles.to_vec(), height))];
    for at in 0..queries.len() {
        let field = |f: fn(&MemoryEvent) -> u64| {
            let values = rows.iter().map(|row| row[at].as_ref().map_or(0, f));
            column(values.collect(), height)
        };
        out.push((frame(at, FIELD_MASK), field(|_| 1)));
        out.push((frame(at, FIELD_ADDR), field(|e| e.addr as u64)));
        out.push((frame(at, FIELD_READ_TS), field(|e| e.read_ts)));
        out.push((frame(at, FIELD_READ_VALUE), field(|e| e.read_value as u64)));
        out.push((
            frame(at, FIELD_WRITE_VALUE),
            field(|e| e.write_value as u64),
        ));
    }
    // The delegation mirror's leaf names the requested type through one more
    // `M` column, and the type is the mirror event's own address space
    // (`docs/spec/delegation.md` §5.1) -- which is exactly what the production
    // builder has to recover from the row's `a7` instead.
    if let Some(at) = queries.iter().position(|&q| q == DELEG) {
        let values = rows
            .iter()
            .map(|row| row[at].as_ref().map_or(0, |e| e.space.tag() as u64));
        out.push((deleg_space(queries.len()), column(values.collect(), height)));
    }
    out
}

/// The frame's `queries.len() + 3` witness columns from the log,
/// `docs/spec/memory.md` §2.4: the independent reading of
/// `trace::build_frame_witness`.
pub fn frame_witness_from_log(
    log: &MemoryEventLog,
    queries: &[usize],
    cycles: &[u64],
    height: usize,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let rows = frame_rows(log, queries, cycles, height);
    let chunk = lookup_channel::BITS[lookup_channel::TIMESTAMP as usize];
    let mut out = Vec::new();
    for (at, &q) in queries.iter().enumerate() {
        let hi = rows.iter().map(|row| {
            row[at].map_or(0, |e| {
                let gap = TS_STEP * e.cycle() + FRAME_DELTA[q] - e.read_ts - 1;
                gap >> chunk
            })
        });
        out.push((gap_hi(at), column(hi.collect(), height)));
    }
    let Some(at) = queries.iter().position(|&q| q == RD) else {
        return out;
    };
    let width = queries.len();
    let named = rows.iter().map(|row| row[at].filter(|e| e.addr != 0));
    let mut inv: Vec<Fr> = named
        .clone()
        .map(|e| {
            e.map_or(Fr::ZERO, |e| {
                let addr = Fr::from_u64(e.addr as u64);
                addr.inverse()
                    .expect("a nonzero register index is invertible")
            })
        })
        .collect();
    inv.resize(height, Fr::ZERO);
    out.push((rd_inv(width), MultilinearPoly::new(PolyBacking::Fr(inv))));
    let is_zero = rows
        .iter()
        .map(|row| row[at].map_or(0, |e| (e.addr == 0) as u64));
    out.push((rd_is_zero(width), column(is_zero.collect(), height)));
    let selected = named.map(|e| e.map_or(0, |e| e.write_value as u64));
    out.push((rd_selected(width), column(selected.collect(), height)));
    out
}
