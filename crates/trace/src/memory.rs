//! The memory argument's columns, filled from an execution: an execution
//! family's frame and its witness, a RAM window's teardown, and the register
//! and PC finals the verifier's boundary reads.
//!
//! `docs/spec/memory.md` is normative: §2.1 the frame, §2.4 its witness, §3.4
//! a window's columns, §4.1 the finals. Every column is keyed by
//! `constraints::memory`'s layout, which is where the layout lives.

use constants::lookup_channel;
use constants::memory::{HALT_PC, RAM_LIVE_BIT, TS_STEP};
use constraints::memory::{
    frame, gap_hi, rd_inv, rd_is_zero, rd_selected, CYCLE, FIELD_ADDR, FIELD_MASK, FIELD_READ_TS,
    FIELD_READ_VALUE, FIELD_WRITE_VALUE, FRAME_DELTA, FRAME_QUERIES, FRAME_SPACE, RD,
};
use constraints::PolyAddress;
use field::Fr;
use gkr_verify::BoundaryFinals;
use loader::ProgramImage;
use poly::{MultilinearPoly, PolyBacking};

use crate::log::{AddressSpace, MemoryEvent, MemoryEventLog};

/// `values`, zero-padded to `height` rows, in the narrowest backing that holds
/// its largest entry: `U1`, `U8`, `U16`, `U32`, or `Fr` for a timestamp past
/// 32 bits.
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
/// pass over the log. `queries` is the family's query list,
/// `constraints::memory::frame_queries`, and a slot of the result is a slot of
/// that list.
///
/// An event takes the first slot of its row still free whose space and slot
/// are its own. That is exact for every query but the three slot-2 register
/// ones, `rs2`, `arg1` and `arg2`, which the log files in that order and which
/// fill in that order: a row with `arg1` has `rs2`, and one with `arg2` has
/// `arg1`, because an ecall's arguments are a prefix of `a0, a1, a2`
/// (`docs/spec/execution-trace.md` §6, §7) and no other row reads `arg1`.
///
/// Panics on a cycle asked for twice or that the log lacks, on `cycles.len() >
/// height`, and — naming the event — on a query no free slot takes, which is
/// how a frame too narrow for the family filling it fails loudly rather than
/// dropping the event.
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
        // An event whose `(space, Δ)` pair no query of the table has belongs
        // to no cycle's row: it is a **delegation invocation's** frame access,
        // which rides the requesting cycle's timestamp at
        // `constants::delegation::FRAME_DELTA` and is that family's row, not
        // this one's (`docs/spec/delegation.md` §4.1). The panic below is
        // unchanged for every pair the table *does* have.
        let in_table = (0..FRAME_QUERIES)
            .any(|q| FRAME_SPACE[q] == event.space.tag() && FRAME_DELTA[q] == event.delta());
        if !in_table {
            continue;
        }
        let row = &mut rows[i];
        let at = (0..queries.len())
            .find(|&at| {
                let q = queries[at];
                row[at].is_none()
                    && FRAME_SPACE[q] == event.space.tag()
                    && FRAME_DELTA[q] == event.delta()
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

/// An execution family's `1 + 5·queries.len()` frame columns,
/// `docs/spec/memory.md` §2.1, in `constraints::memory`'s layout order: `M[0]`
/// cycle, then per slot of `queries` its mask, address, read timestamp, read
/// value and write value. `queries` is the family's query list,
/// `constraints::memory::frame_queries`.
///
/// Row `i` is cycle `cycles[i]` — a shard's cycles, in the order given — and
/// rows `cycles.len()..height` are padding, 0 in every column. A query the
/// cycle lacks is 0 in every one of its columns. The pc query's address is 0,
/// its read value the pc, its write value `next_pc` and its read timestamp the
/// previous cycle's pc write, all as the log records them. Each column takes
/// the narrowest backing its largest value fits.
///
/// Panics naming a cycle the log lacks or `cycles` repeats, on a cycle with a
/// query `queries` has no place for, and on `cycles.len() > height` or a
/// `height` that is not a power of two.
pub fn build_memory_columns(
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
    out
}

/// The frame's `queries.len() + 3` witness columns, `docs/spec/memory.md` §2.4,
/// over the rows [`build_memory_columns`] fills for the same `queries`,
/// `cycles` and `height`:
///
/// - `W[s] <q>_gap_hi`: `gap >> 19`, `gap = 4·cycle + Δ_q − read_ts − 1`, where
///   the cycle has the query at slot `s`;
/// - `W[w] rd_inv`: the inverse of `rd`'s address, where it is not 0;
/// - `W[w + 1] rd_is_zero`: 1 exactly on a live `rd` query at address 0;
/// - `W[w + 2] rd_selected`: `rd`'s write value, where its address is not 0;
///
/// and 0 everywhere else, padding rows included. The three x0 columns are
/// there exactly when the frame has `rd`, as its gadget is. On an honest log
/// every enforcing gate and every obligation of `frame_artifact` holds on
/// every row. Panics as [`build_memory_columns`] does.
pub fn build_frame_witness(
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

/// RAM window `ram_window`'s committed columns at `height` rows,
/// `docs/spec/memory.md` §3.4: `M[0] teardown_ts` and `M[1] teardown_value`
/// per row `y` at address `a = 4·height·ram_window + 4y`:
///
/// | row | `teardown_ts` | `teardown_value` |
/// | --- | --- | --- |
/// | `ram_window = 0` and `y < 2^14` | 0 | 0 |
/// | `a` touched | its last write's timestamp | its last write's value |
/// | `a` untouched | 0 | `image.initial_word(a)` |
///
/// and for `ram_window` 0, `INIT_TEARDOWN`'s window, `S[0]` too:
/// `program::image_init_column(image, height)`. `height` is the two init
/// families' one height. Panics unless the window lies inside `[0, 2^31)`, or
/// if `height` is not a power of two.
pub fn build_init_teardown_columns(
    log: &MemoryEventLog,
    image: &ProgramImage,
    ram_window: u32,
    height: usize,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let words = 4 * height as u64;
    let first = words * ram_window as u64;
    assert!(
        first + words <= 1 << 31,
        "build_init_teardown_columns: window {ram_window} at height {height} is not inside \
         [0, 2^31)"
    );
    let live = |y: usize| ram_window != 0 || y >= 1 << RAM_LIVE_BIT;
    let mut ts = vec![0u64; height];
    let mut value: Vec<u64> = (0..height)
        .map(|y| match live(y) {
            true => image.initial_word((first + 4 * y as u64) as u32) as u64,
            false => 0,
        })
        .collect();
    for f in log.final_state() {
        let a = f.addr as u64;
        if f.space != AddressSpace::Ram || a < first || a >= first + words {
            continue;
        }
        let y = ((a - first) / 4) as usize;
        if live(y) {
            ts[y] = f.ts;
            value[y] = f.value as u64;
        }
    }
    let mut out = vec![
        (PolyAddress::Memory(0), column(ts, height)),
        (PolyAddress::Memory(1), column(value, height)),
    ];
    if ram_window == 0 {
        let init = program::image_init_column(image, height as u32);
        out.push((PolyAddress::Setup(0), init));
    }
    out
}

/// The register and PC finals, `docs/spec/memory.md` §4.1, from the log's
/// final state: each register's last write timestamp and value, `(0, 0)` for
/// one never queried, and the pc's last write timestamp.
///
/// Panics naming the value if the pc's final value is not `HALT_PC` — the log
/// did not end on an exit row, or has no pc query — or `x0`'s is not 0: the
/// verifier fixes both, and neither is carried.
pub fn build_boundary_finals(log: &MemoryEventLog) -> BoundaryFinals {
    let mut finals = BoundaryFinals {
        reg_ts: [0; 32],
        pc_ts: 0,
        reg_values: [0; 31],
    };
    let mut pc = None;
    for f in log.final_state() {
        let r = f.addr as usize;
        match f.space {
            AddressSpace::Reg => {
                finals.reg_ts[r] = f.ts;
                match r {
                    0 => assert_eq!(
                        f.value, 0,
                        "build_boundary_finals: x0's final value is {:#x}, not 0",
                        f.value
                    ),
                    _ => finals.reg_values[r - 1] = f.value,
                }
            }
            AddressSpace::Pc => pc = Some(f),
            // A RAM word's final value is a window family's row, and a
            // delegation space has no final state at all.
            AddressSpace::Ram | AddressSpace::KeccakF => {}
        }
    }
    let pc = pc.expect("build_boundary_finals: the log has no pc query, so no final pc");
    assert_eq!(
        pc.value, HALT_PC,
        "build_boundary_finals: the pc's final value is {:#x}, not HALT_PC",
        pc.value
    );
    finals.pc_ts = pc.ts;
    finals
}
