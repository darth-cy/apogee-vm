//! The memory builders' table and refusals, on logs written by hand: the frame
//! table `constraints::memory` holds as data against `Role`, and each builder
//! panicking where `docs/spec/memory.md` says it must. The honest columns are
//! held to the circuits over real executions in `crates/checker/tests/memory.rs`.

use constraints::memory::{FRAME_DELTA, FRAME_NAMES, FRAME_SPACE};
use trace::{build_boundary_finals, build_memory_columns, AddressSpace, MemoryEventLog, ROLES};

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
