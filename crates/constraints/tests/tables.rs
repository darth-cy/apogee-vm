//! S22: the generated schedule columns are the program's.
//!
//! `crates/constraints/src/ecrecover/schedule_data.rs` is source the engine
//! links and the recursion guest will link after it, written by
//! `cargo run -p kat-gen -- ecrecover` from
//! `constraints::ecrecover::tables::derive`. A generated file and its
//! generator drift the moment someone edits one of them, and here the drift is
//! not cosmetic: a circuit built against stale schedule constants is a correct
//! circuit for a program nobody runs, and every downstream test would agree
//! with it.
//!
//! So the equality is checked in `cargo test --workspace` and not only by the
//! regenerate-and-diff in CI, which needs the generator to have been run.

use constants::ecrecover::ROWS_PER_INVOCATION;
use constraints::ecrecover::schedule_data::SPARSE;
use constraints::ecrecover::tables::{at, derive, id, write_address, MODAL};

/// The committed constants are the ones `derive` produces, pair for pair.
#[test]
fn the_generated_columns_are_the_derived_ones() {
    let want = derive();
    assert_eq!(SPARSE.len(), id::COUNT, "one column per table");
    assert_eq!(want.len(), id::COUNT);
    for k in 0..id::COUNT {
        assert_eq!(
            SPARSE[k].len(),
            want[k].len(),
            "table {k} has {} committed pairs and {} derived; rerun \
             `cargo run -p kat-gen -- ecrecover`",
            SPARSE[k].len(),
            want[k].len()
        );
        assert_eq!(
            SPARSE[k],
            want[k].as_slice(),
            "table {k} differs from the program's; rerun `cargo run -p kat-gen -- ecrecover`"
        );
    }
}

/// Every column is sorted by step and holds no step twice, which is what lets
/// a lookup binary-search it and what lets the extension read each step once.
#[test]
fn every_column_is_ascending_and_has_one_entry_a_step() {
    for (k, table) in SPARSE.iter().enumerate() {
        for pair in table.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "table {k} is not ascending at step {}",
                pair[0].0
            );
        }
        if let Some((last, _)) = table.last() {
            assert!(
                (*last as usize) < ROWS_PER_INVOCATION,
                "table {k} names step {last}, past the {ROWS_PER_INVOCATION}-row block"
            );
        }
    }
}

/// No stored pair is the modal value, or it would be a row the extension pays
/// for and learns nothing from.
#[test]
fn no_stored_entry_is_the_one_the_offset_removes() {
    for (k, table) in SPARSE.iter().enumerate() {
        for (step, value) in table.iter() {
            assert_ne!(
                *value, 0,
                "table {k} stores a zero offset at step {step}, which is the modal value \
                 {} and should have been dropped",
                MODAL[k]
            );
        }
    }
}

/// The saving §6.2 rests on, as a number rather than a claim.
#[test]
fn the_schedule_costs_a_fraction_of_its_dense_form() {
    let total: usize = SPARSE.iter().map(|t| t.len()).sum();
    let dense = id::COUNT * ROWS_PER_INVOCATION;
    assert_eq!(dense, 163_840);
    assert!(
        total * 6 < dense,
        "the sparse schedule is {total} pairs against {dense} dense, which is less than the \
         sixfold saving the measurement recorded"
    );
}

/// A write address is a closed form of the step and carries no column at all,
/// which is the one table the block scheme removed outright.
#[test]
fn a_write_address_needs_no_column() {
    assert_eq!(write_address(0, 0), 0);
    assert_eq!(write_address(1, 0), constraints::ecrecover::FAN_OUT);
    assert_eq!(write_address(7, 3), constraints::ecrecover::FAN_OUT * 7 + 3);
    // Nothing in the table set is a write address: the ids stop at the frame
    // words, and a base column would have to live among them.
    assert_eq!(id::COUNT, id::FRAME_WORD[7] + 1);
}

/// A lookup against the sparse form answers what the program says at every
/// step of the block, idle steps included.
#[test]
fn a_lookup_answers_every_step_of_the_block() {
    let want = derive();
    for k in 0..id::COUNT {
        for step in 0..ROWS_PER_INVOCATION {
            assert_eq!(
                at(SPARSE[k], MODAL[k], step),
                at(&want[k], MODAL[k], step),
                "table {k} at step {step}"
            );
        }
    }
}
