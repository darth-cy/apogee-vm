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
    deleg_space, frame, frame_query_takes, gap_hi, rd_inv, rd_is_zero, rd_selected, CYCLE, DELEG,
    FIELD_ADDR, FIELD_MASK, FIELD_READ_TS, FIELD_READ_VALUE, FIELD_WRITE_VALUE, FRAME_DELTA, RD,
};
use constraints::PolyAddress;
use field::Fr;
use gkr_verify::BoundaryFinals;
use loader::ProgramImage;
use poly::{MultilinearPoly, PolyBacking};

use crate::family::{Row, RowSlice, ROLES};
use crate::log::{AddressSpace, MemoryEvent, MemoryState};

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

/// The events one row of a family buffer stands for, in log order: its pc
/// query, then one query per role it has in [`ROLES`] order
/// (`docs/spec/execution-trace.md` §7).
///
/// A row is a complete encoding of its events. The pc query's read timestamp is
/// the only field a buffer does not store, because it is always the previous
/// cycle's pc write, `4·(cycle − 1)`; every other field is in the row. What is
/// **not** here is a delegation invocation's frame accesses: they ride this
/// cycle's timestamp but they are the delegation family's own rows, not this
/// one's (`docs/spec/delegation.md` §4.1), and the frame builders skipped them
/// when they read the log.
///
/// `crates/trace/src/archive.rs`'s `check_parts` is the same derivation in the
/// other direction — it holds an archived log to the rows event for event — so
/// the two together say a row and its events are one thing said twice.
fn row_events(row: &Row) -> Vec<MemoryEvent> {
    let base = TS_STEP * row.cycle;
    let mut out = Vec::with_capacity(1 + row.present.count_ones() as usize);
    out.push(MemoryEvent {
        space: AddressSpace::Pc,
        addr: 0,
        ts: base,
        read_ts: base - TS_STEP,
        read_value: row.pc,
        write_value: row.next_pc,
    });
    let delegation = row.delegation_space();
    for role in ROLES {
        if let Some(q) = row.query(role) {
            out.push(MemoryEvent {
                space: role.space(delegation),
                addr: q.addr,
                ts: base + role.delta(),
                read_ts: q.read_ts,
                read_value: q.read_value,
                write_value: q.write_value,
            });
        }
    }
    out
}

/// Each of `rows`' frame queries, `None` where the row has none. `queries` is
/// the family's query list, `constraints::memory::frame_queries`, and a slot of
/// the result is a slot of that list.
///
/// An event takes the first slot of its row still free whose space and slot are
/// its own. That is exact for every query but the three slot-2 register ones,
/// `rs2`, `arg1` and `arg2`, which [`ROLES`] orders in that order and which
/// fill in that order: a row with `arg1` has `rs2`, and one with `arg2` has
/// `arg1`, because an ecall's arguments are a prefix of `a0, a1, a2`
/// (`docs/spec/execution-trace.md` §6, §7) and no other row reads `arg1`.
///
/// Panics on `rows.len() > height`, and — naming the event — on a query no free
/// slot takes, which is how a frame too narrow for the family filling it fails
/// loudly rather than dropping the event.
fn frame_rows(rows: &RowSlice, queries: &[usize], height: usize) -> Vec<Vec<Option<MemoryEvent>>> {
    assert!(
        rows.len() <= height,
        "memory columns: {} cycles do not fit {height} rows",
        rows.len()
    );
    let mut out = vec![vec![None; queries.len()]; rows.len()];
    for (i, slots) in out.iter_mut().enumerate() {
        let row = rows.row(i);
        for event in row_events(&row) {
            let at = (0..queries.len())
                .find(|&at| {
                    let q = queries[at];
                    slots[at].is_none() && frame_query_takes(q, event.space.tag(), event.delta())
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
            slots[at] = Some(event);
        }
        assert!(
            slots[0].is_some(),
            "memory columns: the pc query of cycle {} took no slot",
            row.cycle
        );
    }
    out
}

/// An execution family's `1 + 5·queries.len()` frame columns,
/// `docs/spec/memory.md` §2.1, in `constraints::memory`'s layout order: `M[0]`
/// cycle, then per slot of `queries` its mask, address, read timestamp, read
/// value and write value. `queries` is the family's query list,
/// `constraints::memory::frame_queries`.
///
/// Row `i` is `rows`' row `i` — one shard's rows, in the order the buffer holds
/// them — and rows `rows.len()..height` are padding, 0 in every column. A query
/// the cycle lacks is 0 in every one of its columns. The pc query's address is
/// 0, its read value the pc, its write value `next_pc` and its read timestamp
/// the previous cycle's pc write. Each column takes the narrowest backing its
/// largest value fits.
///
/// Panics on a cycle with a query `queries` has no place for, and on
/// `rows.len() > height` or a `height` that is not a power of two.
pub fn build_memory_columns(
    rows: &RowSlice,
    queries: &[usize],
    height: usize,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let cycles = rows.cycles();
    let rows = frame_rows(rows, queries, height);
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
    // The delegation mirror's leaf names the requested *type* through one more
    // `M` column, and the type is the mirror event's own address space — one
    // `deleg` query serves them all (`docs/spec/delegation.md` §5.1). Zero on
    // every row that requests nothing, which the leaf reads as no tuple at
    // all because the mask is zero there too.
    if let Some(at) = queries.iter().position(|&q| q == DELEG) {
        let values = rows
            .iter()
            .map(|row| row[at].as_ref().map_or(0, |e| e.space.tag() as u64));
        out.push((deleg_space(queries.len()), column(values.collect(), height)));
    }
    out
}

/// The frame's `queries.len() + 3` witness columns, `docs/spec/memory.md` §2.4,
/// over the rows [`build_memory_columns`] fills for the same `rows`, `queries`
/// and `height`:
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
    rows: &RowSlice,
    queries: &[usize],
    height: usize,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let rows = frame_rows(rows, queries, height);
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
    state: &MemoryState,
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
    // Probed per row rather than filtered out of the whole final state: a
    // window is `height` addresses and an execution touches far more, so
    // scanning the state once per window is `O(windows x touched words)` where
    // this is `O(windows x height)`.
    for y in 0..height {
        if !live(y) {
            continue;
        }
        if let Some((t, v)) = state.ram((first + 4 * y as u64) as u32) {
            ts[y] = t;
            value[y] = v as u64;
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

/// A **value window**'s committed columns at `height` rows,
/// `docs/spec/public-values.md` §4: `M[0] teardown_ts`, `M[1] teardown_value`
/// and `M[2] init_value` per row `y` at address `a = 4·height·ram_window + 4y`.
///
/// `initial[y]` is the word the window starts on — the statement's public
/// input for `PUBLIC_INPUT`, the prover's advice for `ADVICE_WINDOWS` — and 0
/// past the end of the slice. `M[2]` is exactly that vector; `M[0]` and `M[1]`
/// are [`build_init_teardown_columns`]'s teardown, an untouched row keeping
/// `(0, initial[y])` so that its init and teardown tuples cancel.
///
/// Panics unless the window lies inside the 32-bit address space, or if
/// `height` is not a power of two.
pub fn build_value_window_columns(
    state: &MemoryState,
    initial: &[u32],
    ram_window: u32,
    height: usize,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let words = 4 * height as u64;
    let first = words * ram_window as u64;
    assert!(
        first + words <= 1 << 32,
        "build_value_window_columns: window {ram_window} at height {height} is not inside \
         [0, 2^32)"
    );
    let init: Vec<u64> = (0..height)
        .map(|y| initial.get(y).copied().unwrap_or(0) as u64)
        .collect();
    let mut ts = vec![0u64; height];
    let mut value = init.clone();
    for y in 0..height {
        if let Some((t, v)) = state.ram((first + 4 * y as u64) as u32) {
            ts[y] = t;
            value[y] = v as u64;
        }
    }
    vec![
        (PolyAddress::Memory(0), column(ts, height)),
        (PolyAddress::Memory(1), column(value, height)),
        (PolyAddress::Memory(2), column(init, height)),
    ]
}

/// The register and PC finals, `docs/spec/memory.md` §4.1, from the execution's
/// last-access tables: each register's last write timestamp and value, `(0, 0)`
/// for one never queried, and the pc's last write timestamp.
///
/// Panics naming the value if the pc's final value is not `HALT_PC` — the
/// execution did not end on an exit row, or ran no cycle — or `x0`'s is not 0:
/// the verifier fixes both, and neither is carried.
pub fn build_boundary_finals(state: &MemoryState) -> BoundaryFinals {
    let mut finals = BoundaryFinals {
        reg_ts: [0; 32],
        pc_ts: 0,
        reg_values: [0; 31],
    };
    for r in 0..32u32 {
        let Some((ts, value)) = state.reg(r) else {
            continue;
        };
        finals.reg_ts[r as usize] = ts;
        match r {
            0 => assert_eq!(
                value, 0,
                "build_boundary_finals: x0's final value is {value:#x}, not 0"
            ),
            _ => finals.reg_values[r as usize - 1] = value,
        }
    }
    let pc = state
        .pc()
        .expect("build_boundary_finals: the execution has no pc query, so no final pc");
    assert_eq!(
        pc.1, HALT_PC,
        "build_boundary_finals: the pc's final value is {:#x}, not HALT_PC",
        pc.1
    );
    finals.pc_ts = pc.0;
    finals
}
