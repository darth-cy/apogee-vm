//! The memory argument's columns, filled from an execution: an execution
//! family's frame and its witness, a RAM window's teardown, and the register
//! and PC finals the verifier's boundary reads.
//!
//! `docs/spec/memory.md` specifies them: §2.1 the frame, §2.4 its witness,
//! §3.4 a window's columns, §4.1 the finals. Every column is keyed by
//! `constraints::memory`'s layout, which is where the layout lives.

use constants::lookup_channel;
use constants::memory::{HALT_PC, RAM_LIVE_BIT, TS_STEP};
use constraints::memory::{
    frame, frame_query_takes, gap_hi, rd_inv, rd_is_zero, rd_selected, CYCLE, FIELD_ADDR,
    FIELD_MASK, FIELD_READ_TS, FIELD_READ_VALUE, FIELD_WRITE_VALUE, FRAME_DELTA, FRAME_MIN_ADVANCE,
    RD,
};
use constraints::PolyAddress;
use field::Fr;
use gkr_verify::BoundaryFinals;
use loader::ProgramImage;
use poly::{MultilinearPoly, PolyBacking};

use crate::family::{Query, Role, Row, RowSlice, ROLES};
use crate::log::{AddressSpace, MemoryEvent, MemoryState};

/// A zero column of `height` rows in the narrowest backing that holds `max`:
/// `U1`, `U8`, `U16`, `U32`, or `Fr` for a timestamp past 32 bits. Chosen before
/// any entry is written, so no row is ever held wider than its column.
fn narrowest(max: u64, height: usize) -> PolyBacking {
    if max <= 1 {
        PolyBacking::U1(vec![0u64; height.div_ceil(64)], height)
    } else if max <= u8::MAX as u64 {
        PolyBacking::U8(vec![0; height])
    } else if max <= u16::MAX as u64 {
        PolyBacking::U16(vec![0; height])
    } else if max <= u32::MAX as u64 {
        PolyBacking::U32(vec![0; height])
    } else {
        PolyBacking::Fr(vec![Fr::ZERO; height])
    }
}

/// Entry `i` of a column [`narrowest`] made, set to `v`, which is at most the
/// `max` it was made for. A bit is or-ed in, so each entry is set once.
fn set(backing: &mut PolyBacking, i: usize, v: u64) {
    match backing {
        PolyBacking::U1(limbs, _) => limbs[i / 64] |= v << (i % 64),
        PolyBacking::U8(column) => column[i] = v as u8,
        PolyBacking::U16(column) => column[i] = v as u16,
        PolyBacking::U32(column) => column[i] = v as u32,
        PolyBacking::Fr(column) => column[i] = Fr::from_u64(v),
    }
}

/// `value(i)` on each of the first `len` rows and 0 on the rest, `height` rows
/// in all, in the narrowest backing that holds its largest entry. `value` is
/// read twice a row, the first time for that entry, so the column is written
/// once, at its own width.
fn column(len: usize, height: usize, value: impl Fn(usize) -> u64) -> MultilinearPoly {
    let max = (0..len).map(&value).max().unwrap_or(0);
    let mut backing = narrowest(max, height);
    for i in 0..len {
        set(&mut backing, i, value(i));
    }
    MultilinearPoly::new(backing)
}

/// Two columns of `height` rows read off one probe of each row, as [`column`]
/// builds one: `probe` is called twice a row, the first time for each column's
/// largest entry. A window's teardown timestamp and value are one lookup of
/// the final state.
fn column_pair(
    height: usize,
    probe: impl Fn(usize) -> (u64, u64),
) -> (MultilinearPoly, MultilinearPoly) {
    let (mut first_max, mut second_max) = (0, 0);
    for y in 0..height {
        let (a, b) = probe(y);
        first_max = first_max.max(a);
        second_max = second_max.max(b);
    }
    let mut first = narrowest(first_max, height);
    let mut second = narrowest(second_max, height);
    for y in 0..height {
        let (a, b) = probe(y);
        set(&mut first, y, a);
        set(&mut second, y, b);
    }
    (MultilinearPoly::new(first), MultilinearPoly::new(second))
}

/// The route of a row's pc query; the query in role `ROLES[r]` is `1 + r`.
const PC_EVENT: u8 = 0;

/// The route of a frame slot the row has no query for.
const NO_EVENT: u8 = u8::MAX;

/// Cycle `cycle`'s pc query: `pc` read and `next_pc` written, at slot 0. Its
/// read timestamp is the one field a buffer does not store, because it is
/// always the previous cycle's pc write, `4·(cycle − 1)`.
fn pc_event(cycle: u64, pc: u32, next_pc: u32) -> MemoryEvent {
    let base = TS_STEP * cycle;
    MemoryEvent {
        space: AddressSpace::Pc,
        addr: 0,
        ts: base,
        read_ts: base - TS_STEP,
        read_value: pc,
        write_value: next_pc,
    }
}

/// Cycle `cycle`'s query in `role`.
fn role_event(cycle: u64, role: Role, q: Query) -> MemoryEvent {
    MemoryEvent {
        space: role.space(),
        addr: q.addr,
        ts: TS_STEP * cycle + role.delta(),
        read_ts: q.read_ts,
        read_value: q.read_value,
        write_value: q.write_value,
    }
}

/// The events one row of a family buffer stands for, in log order, each with
/// its route: its pc query, then one query per role it has in [`ROLES`] order
/// (`docs/spec/execution-trace.md` §7).
///
/// A row is a complete encoding of its events. The pc query's read timestamp is
/// the only field a buffer does not store, because it is always the previous
/// cycle's pc write, `4·(cycle − 1)`; every other field is in the row.
///
/// `crates/trace/src/archive.rs`'s `check_parts` is the same derivation in the
/// other direction — it holds an archived log to the rows event for event — so
/// the two together say a row and its events are one thing said twice.
fn row_events(row: &Row) -> impl Iterator<Item = (u8, MemoryEvent)> + '_ {
    let queries = ROLES.iter().enumerate().filter_map(move |(r, &role)| {
        row.query(role)
            .map(|q| (1 + r as u8, role_event(row.cycle, role, q)))
    });
    core::iter::once((PC_EVENT, pc_event(row.cycle, row.pc, row.next_pc))).chain(queries)
}

/// The event `route` names on row `i` of `rows`: what [`row_events`] gives it,
/// read from the buffer's columns without the rest of the row.
fn routed(rows: &RowSlice, i: usize, route: u8) -> MemoryEvent {
    let cycle = rows.cycles()[i];
    match route {
        PC_EVENT => {
            let (pc, next_pc) = rows.pc(i);
            pc_event(cycle, pc, next_pc)
        }
        r => {
            let role = ROLES[r as usize - 1];
            let q = rows.query(i, role).expect("a routed query is the row's");
            role_event(cycle, role, q)
        }
    }
}

/// Which of each row's events takes each frame slot: `rows.len()·queries.len()`
/// routes, row by row, each [`PC_EVENT`], `1 + r` for the query in role
/// `ROLES[r]`, or [`NO_EVENT`] — a byte a slot where the events themselves would
/// be forty. `queries` is the family's query list,
/// `constraints::memory::frame_queries`, and a slot is a slot of that list.
///
/// An event takes the first slot of its row still free whose space and slot are
/// its own. That is exact: no two roles share a `(space, Δ)` pair — `rs2` and
/// `load` share slot 2, in [`ROLES`] order, but not a space — so a query's
/// events route by that pair alone (`docs/spec/execution-trace.md` §6, §7).
///
/// Panics on `rows.len() > height`, and — naming the event — on a query no free
/// slot takes, which is how a frame too narrow for the family filling it fails
/// loudly rather than dropping the event.
fn frame_routes(rows: &RowSlice, queries: &[usize], height: usize) -> Vec<u8> {
    assert!(
        rows.len() <= height,
        "memory columns: {} cycles do not fit {height} rows",
        rows.len()
    );
    let width = queries.len();
    let mut out = vec![NO_EVENT; rows.len() * width];
    for (i, slots) in out.chunks_mut(width).enumerate() {
        let row = rows.row(i);
        for (route, event) in row_events(&row) {
            let at = (0..width)
                .find(|&at| {
                    let q = queries[at];
                    slots[at] == NO_EVENT && frame_query_takes(q, event.space.tag(), event.delta())
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
            slots[at] = route;
        }
        assert!(
            slots[0] != NO_EVENT,
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
/// largest value fits, and each value is read from the rows as it is written
/// into its column: no event is held.
///
/// Panics on a cycle with a query `queries` has no place for, and on
/// `rows.len() > height` or a `height` that is not a power of two.
pub fn build_memory_columns(
    rows: &RowSlice,
    queries: &[usize],
    height: usize,
) -> Vec<(PolyAddress, MultilinearPoly)> {
    let cycles = rows.cycles();
    let routes = frame_routes(rows, queries, height);
    let (len, width) = (rows.len(), queries.len());
    let mut out = vec![(CYCLE, column(len, height, |i| cycles[i]))];
    for at in 0..width {
        let field = |f: fn(&MemoryEvent) -> u64| {
            column(len, height, |i| match routes[i * width + at] {
                NO_EVENT => 0,
                route => f(&routed(rows, i, route)),
            })
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
/// over the rows [`build_memory_columns`] fills for the same `rows`, `queries`
/// and `height`:
///
/// - `W[s] <q>_gap_hi`: `gap >> 19`, `gap = 4·cycle + Δ_q − read_ts − a_q`,
///   `a_q` the query's `FRAME_MIN_ADVANCE`, where the cycle has the query at
///   slot `s`;
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
    let routes = frame_routes(rows, queries, height);
    let (len, width) = (rows.len(), queries.len());
    // The event in slot `at` of row `i`, if the row has one there.
    let event = |i: usize, at: usize| match routes[i * width + at] {
        NO_EVENT => None,
        route => Some(routed(rows, i, route)),
    };
    let chunk = lookup_channel::BITS[lookup_channel::TIMESTAMP as usize];
    let mut out = Vec::new();
    for (at, &q) in queries.iter().enumerate() {
        let hi = column(len, height, |i| {
            event(i, at).map_or(0, |e| {
                let gap = TS_STEP * e.cycle() + FRAME_DELTA[q] - e.read_ts - FRAME_MIN_ADVANCE[q];
                gap >> chunk
            })
        });
        out.push((gap_hi(at), hi));
    }
    let Some(at) = queries.iter().position(|&q| q == RD) else {
        return out;
    };
    // `rd`'s query on row `i`, where its address is not 0.
    let named = |i: usize| event(i, at).filter(|e| e.addr != 0);
    let inv: Vec<Fr> = (0..height)
        .map(|i| match i < len {
            true => named(i).map_or(Fr::ZERO, |e| {
                let addr = Fr::from_u64(e.addr as u64);
                addr.inverse()
                    .expect("a nonzero register index is invertible")
            }),
            false => Fr::ZERO,
        })
        .collect();
    out.push((rd_inv(width), MultilinearPoly::new(PolyBacking::Fr(inv))));
    let is_zero = column(len, height, |i| {
        event(i, at).map_or(0, |e| (e.addr == 0) as u64)
    });
    out.push((rd_is_zero(width), is_zero));
    let selected = column(len, height, |i| {
        named(i).map_or(0, |e| e.write_value as u64)
    });
    out.push((rd_selected(width), selected));
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
    // Probed per row rather than filtered out of the whole final state: a
    // window is `height` addresses and an execution touches far more, so
    // scanning the state once per window is `O(windows x touched words)` where
    // this is `O(windows x height)`.
    let teardown = |y: usize| {
        if !live(y) {
            return (0, 0);
        }
        let a = (first + 4 * y as u64) as u32;
        match state.ram(a) {
            Some((t, v)) => (t, v as u64),
            None => (0, image.initial_word(a) as u64),
        }
    };
    let (ts, value) = column_pair(height, teardown);
    let mut out = vec![
        (PolyAddress::Memory(0), ts),
        (PolyAddress::Memory(1), value),
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
    let init = |y: usize| initial.get(y).copied().unwrap_or(0) as u64;
    let teardown = |y: usize| match state.ram((first + 4 * y as u64) as u32) {
        Some((t, v)) => (t, v as u64),
        None => (0, init(y)),
    };
    let (ts, value) = column_pair(height, teardown);
    vec![
        (PolyAddress::Memory(0), ts),
        (PolyAddress::Memory(1), value),
        (PolyAddress::Memory(2), column(height, height, init)),
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
