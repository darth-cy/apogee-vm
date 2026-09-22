//! S22's step program, as a **shape**: how many rows an invocation takes, how
//! many bus addresses it occupies, and how wide a row the choice of window
//! costs.
//!
//! The numbers here are a measurement, not a target. `ROWS_PER_INVOCATION`
//! was 2,048 when `docs/spec/ecrecover.md` was written, from an estimate of
//! the congruence count; the program corrected it, and the owner's decision
//! at S22 is that the ratio may be re-pinned on measurement while the block
//! stays fixed, aligned and protocol-wide.
//!
//! What the program *computes* is checked elsewhere, in
//! `crates/program/tests/ecrecover_schedule.rs`, which interprets it over
//! `program::secp256k1` and holds it to the committed corpus. This file is
//! only about its size.

use constants::ecrecover as e;
use std::collections::BTreeMap;

use constraints::ecrecover::schedule::{Digit, Frame, Output};
use constraints::ecrecover::{schedule, FAN_OUT, SELECTORS, TABLE, WINDOWS, WINDOW_BITS};

/// The program fits its block, and does not waste half of it.
#[test]
fn the_program_is_the_row_budget() {
    let program = schedule();
    assert_eq!(
        program.steps.len(),
        3779,
        "the step count moved: re-read the budget before changing this"
    );
    assert!(
        program.steps.len() <= e::ROWS_PER_INVOCATION,
        "the program does not fit the block"
    );
    assert_eq!(e::ROWS_PER_INVOCATION, 4096);
    assert!(
        program.steps.len() * 2 > e::ROWS_PER_INVOCATION,
        "half the block is idle: the next power of two down would do"
    );
    assert_eq!(program.fan_out, FAN_OUT, "the widest write is the cap");
}

/// Every bus address a step writes is written exactly once and read exactly
/// once, and every address a step reads is one some step wrote.
///
/// That is the multiset's rule, not a convention: a write with no read and a
/// read with no write each leave the global argument unbalanced, and the
/// honest prover is the one refused. The program spends copy steps to keep
/// it, and this is the check that it spent enough.
///
/// The address space is **sparse** -- a step owns the block
/// `[step·FAN_OUT, (step + 1)·FAN_OUT)` and uses as much of it as the value's
/// readers need -- so this iterates the addresses that are used rather than
/// the whole range. Density was never the property; pairing is. What the
/// blocks buy is that a write address is a closed form of the step index and
/// so costs no schedule table (`docs/spec/ecrecover.md` §6.2).
#[test]
fn every_bus_address_is_written_once_and_read_once() {
    let program = schedule();
    let mut written: BTreeMap<u32, usize> = BTreeMap::new();
    let mut read: BTreeMap<u32, usize> = BTreeMap::new();
    for step in &program.steps {
        for at in &step.writes {
            *written.entry(*at).or_default() += 1;
        }
        for at in step.reads() {
            *read.entry(at).or_default() += 1;
        }
    }
    for (at, w) in &written {
        assert_eq!(*w, 1, "bus address {at} is written {w} times");
        let r = read.get(at).copied().unwrap_or(0);
        assert_eq!(
            r, 1,
            "bus address {at} is written once and read {r} times; an address written and \
             never read is an unmatched write, and a multiset with one does not balance"
        );
    }
    for at in read.keys() {
        assert!(
            written.contains_key(at),
            "bus address {at} is read and never written"
        );
    }
    // Every address is inside its own step's block, which is what makes the
    // write address derivable from the row index.
    for (i, step) in program.steps.iter().enumerate() {
        for at in &step.writes {
            let block = *at as usize / FAN_OUT;
            assert_eq!(
                block, i,
                "step {i} writes {at}, which is step {block}'s block"
            );
        }
    }
    assert!(
        written.len() * 2 < program.values,
        "the block scheme is meant to be sparse; {} of {} addresses used",
        written.len(),
        program.values
    );
}

/// A row's slots are what every row pays for, used or not, so the shape is
/// worth pinning: five congruence operands and one table.
#[test]
fn a_row_carries_the_slots_the_widest_step_needs() {
    let program = schedule();
    let mut widest_table = 0;
    let mut selections = 0;
    let mut emits = 0;
    let mut frames = 0;
    let mut exact = 0;
    let mut zeroes = 0;
    let mut divisions = 0;
    let mut roots = 0;
    for step in &program.steps {
        widest_table = widest_table.max(step.table.len().max(step.table_literals.len()));
        match step.digit {
            Digit::None => {}
            Digit::Emit => emits += 1,
            Digit::Check(_) => selections += 1,
        }
        if !matches!(step.frame, Frame::None) {
            frames += 1;
        }
        if step.exact {
            exact += 1;
        }
        if step.is_zero {
            zeroes += 1;
        }
        match step.output {
            Output::A => divisions += 1,
            Output::Sqrt => roots += 1,
            _ => {}
        }
    }
    assert_eq!(widest_table, SELECTORS, "one table slot a selector");
    assert_eq!(SELECTORS, 2 * TABLE, "the sign lives in the selector");
    assert_eq!(emits, 2 * WINDOWS, "one digit a window a scalar");
    assert_eq!(
        selections,
        4 * WINDOWS,
        "each window's digit drives its two coordinates, for each scalar"
    );
    assert_eq!(frames, 7, "four values in, two out, and the success flag");
    assert_eq!(exact, frames + 1, "the frame moves, and the parity split");
    assert!(zeroes >= 5, "the two range tests and the recovery id");
    assert!(divisions > 2 * WINDOWS, "every addition inverts its gap");
    assert_eq!(roots, 3, "the two curve roots and one free boolean");
    assert_eq!(WINDOWS as u32 * WINDOW_BITS, 258, "258 bits covers 256");
}
