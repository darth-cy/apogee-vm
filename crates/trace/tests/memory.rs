//! The memory builders' table, refusals and edges, on logs written by hand: the
//! frame table `constraints::memory` holds as data against `Role`, each builder
//! panicking where `docs/spec/memory.md` says it must, a gap at the timestamp
//! chunk's edge, and a word at a window's edge. The honest columns are
//! held to the circuits over real executions in `crates/checker/tests/memory.rs`.

use constraints::memory::{gap_hi, FRAME_DELTA, FRAME_NAMES, FRAME_SPACE};
use constraints::PolyAddress;
use field::Fr;
use loader::load_elf;
use trace::{
    build_boundary_finals, build_frame_witness, build_init_teardown_columns, build_memory_columns,
    AddressSpace, MemoryEventLog, ROLES,
};

/// `docs/spec/memory.md` §2.1: query 0 is the pc query, at `PC` and slot 0,
/// and queries 1–7 are `ROLES` in order, each at its role's space and slot and
/// named after it. Kills a frame table that drifts from the trace's roles.
#[test]
fn the_frame_table_is_the_pc_query_then_the_roles() {
    assert_eq!(FRAME_SPACE.len(), 1 + ROLES.len());
    assert_eq!(
        (FRAME_SPACE[0], FRAME_DELTA[0], FRAME_NAMES[0]),
        (AddressSpace::Pc.tag(), 0, "pc")
    );
    for (i, role) in ROLES.iter().enumerate() {
        let name = format!("{role:?}").to_lowercase();
        assert_eq!(
            (FRAME_SPACE[1 + i], FRAME_DELTA[1 + i], FRAME_NAMES[1 + i]),
            (role.space().tag(), role.delta(), name.as_str()),
            "{role:?}"
        );
    }
}

/// Cycles 1 and 2 of a two-cycle program at entry 0x10000: `addi x5, x0, 7`,
/// then an exit row writing `HALT_PC`, or `end_pc` in its place.
fn two_cycles(end_pc: u32, x0_write: u32) -> MemoryEventLog {
    let mut log = MemoryEventLog::new();
    log.record(AddressSpace::Pc, 0, 4, 0x10000, 0x10004);
    log.record(AddressSpace::Reg, 0, 5, 0, x0_write);
    log.record(AddressSpace::Reg, 5, 7, 0, 7);
    log.record(AddressSpace::Pc, 0, 8, 0x10004, end_pc);
    log
}

#[test]
fn the_finals_of_an_exit() {
    let finals = build_boundary_finals(&two_cycles(1, 0));
    assert_eq!(
        (finals.pc_ts, finals.reg_ts[0], finals.reg_ts[5]),
        (8, 5, 7)
    );
    assert_eq!(finals.reg_values[4], 7);
}

#[test]
#[should_panic(expected = "build_boundary_finals: the pc's final value is 0x10008, not HALT_PC")]
fn the_finals_refuse_a_log_that_did_not_exit() {
    build_boundary_finals(&two_cycles(0x10008, 0));
}

#[test]
#[should_panic(expected = "build_boundary_finals: x0's final value is 0x5, not 0")]
fn the_finals_refuse_a_nonzero_x0() {
    build_boundary_finals(&two_cycles(1, 5));
}

#[test]
#[should_panic(expected = "memory columns: the log has no cycle 3")]
fn the_frame_refuses_a_cycle_the_log_lacks() {
    build_memory_columns(&two_cycles(1, 0), &[2, 3], 4);
}

const PC: usize = 0;
const RS1: usize = 1;
const RS2: usize = 2;

/// `docs/spec/memory.md` §2.4's high chunk at the chunk's edge. A hand-written
/// log on four cycles reads `x5` with gaps 4, `2^19 − 1`, `2^19` and
/// `2^19 + 3` — `rs1` at cycles 1 and `2^17 + 1`, `rs2` at the next two — and
/// its pc with gaps 3, `2^19 − 1`, `2^19 − 1` and `2^19 + 3`. Each gap column
/// holds `gap >> 19` on its rows and 0 where the cycle lacks the query, so the
/// low chunk `gap − 2^19·hi` is below `2^19` on every row. Fails if the builder
/// chunked `gap + 1`, or `gap` by any other width.
#[test]
fn the_gap_columns_hold_the_high_chunk_at_the_chunks_edge() {
    let c2 = (1 << 17) + 1;
    let c3 = c2 + (1 << 17);
    let c4 = c3 + (1 << 17) + 1;
    let mut log = MemoryEventLog::new();
    log.record(AddressSpace::Pc, 0, 4, 0x10000, 0x10004);
    log.record(AddressSpace::Reg, 5, 5, 0, 0);
    log.record(AddressSpace::Pc, 0, 4 * c2, 0x10004, 0x10008);
    log.record(AddressSpace::Reg, 5, 4 * c2 + 1, 0, 0);
    log.record(AddressSpace::Pc, 0, 4 * c3, 0x10008, 0x1000c);
    log.record(AddressSpace::Reg, 5, 4 * c3 + 2, 0, 0);
    log.record(AddressSpace::Pc, 0, 4 * c4, 0x1000c, 1);
    log.record(AddressSpace::Reg, 5, 4 * c4 + 2, 0, 0);
    let gap = |e: &trace::MemoryEvent| e.ts - e.read_ts - 1;
    let x5: Vec<u64> = log
        .events()
        .iter()
        .filter(|e| e.addr == 5)
        .map(gap)
        .collect();
    assert_eq!(x5, [4, (1 << 19) - 1, 1 << 19, (1 << 19) + 3]);

    let columns = build_frame_witness(&log, &[1, c2, c3, c4], 4);
    let at = |q: usize| {
        let column = &columns
            .iter()
            .find(|(a, _)| *a == gap_hi(q))
            .expect("a gap column")
            .1;
        (0..4).map(|y| column.get(y)).collect::<Vec<Fr>>()
    };
    let chunks = |v: [u64; 4]| v.map(Fr::from_u64).to_vec();
    assert_eq!(at(PC), chunks([0, 0, 0, 1]));
    assert_eq!(at(RS1), chunks([0, 0, 0, 0]));
    assert_eq!(at(RS2), chunks([0, 0, 1, 1]));
}

/// `docs/spec/memory.md` §3.4 at a window's upper edge: the one RAM write of a
/// hand-written log lands on `4h`, at `h = 2^16` the first word of window 1.
/// Window 0's columns hold no timestamp; window 1's row 0 holds the write. Fails
/// if a window took the first word of the next one.
#[test]
fn the_first_word_of_a_window_is_that_windows_alone() {
    let path = format!(
        "{}/../loader/tests/vectors/fib.elf",
        env!("CARGO_MANIFEST_DIR")
    );
    let image = load_elf(&std::fs::read(path).expect("fib.elf")).expect("fib loads");
    let h = 1usize << 16;
    let mut log = MemoryEventLog::new();
    log.record(AddressSpace::Pc, 0, 4, image.entry, 1);
    log.record(AddressSpace::Ram, 4 * h as u32, 7, 0, 0xabcd);
    let teardown = |w: u32, m: u32| {
        let columns = build_init_teardown_columns(&log, &image, w, h);
        columns
            .into_iter()
            .find(|(a, _)| *a == PolyAddress::Memory(m))
            .expect("a column")
            .1
    };
    let ts = teardown(0, 0);
    assert!(
        (0..h).all(|y| ts.get(y) == Fr::ZERO),
        "window 0 holds no write"
    );
    let (ts, value) = (teardown(1, 0), teardown(1, 1));
    assert_eq!(
        (ts.get(0), value.get(0)),
        (Fr::from_u64(7), Fr::from_u64(0xabcd))
    );
    assert!((1..h).all(|y| ts.get(y) == Fr::ZERO));
}
