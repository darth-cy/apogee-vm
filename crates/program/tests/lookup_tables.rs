//! Acceptance 10: the generic channel's committed table, against an
//! independent reference computation of each of its two tables.
//!
//! The reference is written here from the ISA's own definitions — a bitwise AND
//! of two bytes, and bit 15 of a halfword — and never from
//! `program::lookup_tables`, so the two descriptions share no code. A poisoned
//! row is caught by the same comparison.

use field::Fr;
use program::lookup_tables::{
    generic_entries, generic_table, zero_entry, AND_BASE, AND_ROWS, GENERIC_ROWS, GENERIC_WIDTH,
    SIGN_BASE, SIGN_ROWS,
};

/// The smallest height holding the packed table: `2^17` is one row short of
/// its 131,073, so 18 is the floor and every menu height at or above it works.
const VARS: u32 = 18;

/// Every entry the packed table holds, in row order from row 1, recomputed
/// here: `(a + AND_BASE + 1, b, a & b)` for every byte pair, then
/// `(h + SIGN_BASE + 1, h >> 15, 0)` for every halfword. The `+ 1` is the
/// gated-key offset: it keeps every real entry off the all-zero tuple the
/// `ZeroEntry` answers.
fn reference() -> Vec<[u32; GENERIC_WIDTH]> {
    let mut out = Vec::with_capacity(GENERIC_ROWS - 1);
    for a in 0..256u32 {
        for b in 0..256u32 {
            out.push([AND_BASE + a + 1, b, a & b]);
        }
    }
    for h in 0..1u32 << 16 {
        // `U16GetSign`: the sign of the halfword read as a signed 16-bit
        // value, which is its bit 15.
        let signed = (h as u16) as i16;
        let sign = u32::from(signed < 0);
        out.push([SIGN_BASE + h + 1, sign, 0]);
    }
    out
}

/// Acceptance 10. Every committed cell of the packed table, `U16GetSign`
/// included, equals the reference: row 0 is the `ZeroEntry`, rows 1 onward are
/// the two tables in order, and every row past them is the `ZeroEntry` again.
#[test]
fn the_generic_table_is_its_reference_computation() {
    assert_eq!(GENERIC_ROWS, 1 + AND_ROWS + SIGN_ROWS);
    let reference = reference();
    assert_eq!(reference.len(), GENERIC_ROWS - 1);
    let entries: Vec<[u32; GENERIC_WIDTH]> = generic_entries().collect();
    assert_eq!(
        entries, reference,
        "the crate's entries are the reference's"
    );

    let columns = generic_table(VARS);
    assert_eq!(columns.len(), GENERIC_WIDTH);
    let rows = 1usize << VARS;
    for column in &columns {
        assert_eq!(column.num_vars(), VARS as usize);
    }
    let cell = |row: usize, j: usize| columns[j].get(row);
    for j in 0..GENERIC_WIDTH {
        assert_eq!(cell(0, j), zero_entry()[j], "the ZeroEntry at row 0");
    }
    for (i, entry) in reference.iter().enumerate() {
        for (j, value) in entry.iter().enumerate() {
            assert_eq!(
                cell(i + 1, j),
                Fr::from_u64(*value as u64),
                "row {} column {j}",
                i + 1
            );
        }
    }
    for row in [GENERIC_ROWS, GENERIC_ROWS + 1, rows - 1] {
        for j in 0..GENERIC_WIDTH {
            assert_eq!(cell(row, j), Fr::ZERO, "row {row} is the ZeroEntry again");
        }
    }
}

/// Acceptance 10's negative control: one poisoned row — an AND entry whose
/// result is off by one, and a sign entry whose bit is flipped — differs from
/// the committed table at exactly that cell.
#[test]
fn a_poisoned_row_differs_from_the_committed_table() {
    let columns = generic_table(VARS);
    let mut poisoned = reference();
    // `37 & 45 = 37`; claim one more.
    let (a, b) = (37u32, 45u32);
    let and = (256 * a + b) as usize;
    assert_eq!(poisoned[and], [AND_BASE + a + 1, b, a & b]);
    assert_ne!(a & b, 0, "a poisoned AND row that is not already 0");
    poisoned[and][2] += 1;
    // `0x8000 >> 15 = 1`; claim 0.
    let sign = AND_ROWS + 0x8000;
    assert_eq!(poisoned[sign], [SIGN_BASE + 0x8000 + 1, 1, 0]);
    poisoned[sign][1] = 0;

    let differing: Vec<usize> = (0..poisoned.len())
        .filter(|i| {
            (0..GENERIC_WIDTH)
                .any(|j| columns[j].get(i + 1) != Fr::from_u64(poisoned[*i][j] as u64))
        })
        .collect();
    assert_eq!(
        differing,
        vec![and, sign],
        "exactly the poisoned rows differ"
    );
}

/// A table of `2^n` rows cannot hold more entries than it has rows, and the
/// constructor says so rather than truncating.
#[test]
#[should_panic(expected = "the generic table needs 131073 rows")]
fn a_height_below_the_packed_tables_rows_is_refused() {
    generic_table(17);
}

/// The two tables' key ranges are disjoint, so no tuple of one is a tuple of
/// the other, and neither reaches the all-zero tuple.
#[test]
fn the_two_tables_key_ranges_are_disjoint_and_miss_zero() {
    let keys: Vec<u32> = generic_entries().map(|e| e[0]).collect();
    assert_eq!(keys.len(), GENERIC_ROWS - 1);
    assert!(keys.iter().all(|k| *k != 0), "no real entry has key 0");
    let and: Vec<u32> = keys[..AND_ROWS].to_vec();
    let sign: Vec<u32> = keys[AND_ROWS..].to_vec();
    let (and_low, and_high) = (*and.iter().min().unwrap(), *and.iter().max().unwrap());
    let (sign_low, sign_high) = (*sign.iter().min().unwrap(), *sign.iter().max().unwrap());
    assert_eq!((and_low, and_high), (AND_BASE + 1, AND_BASE + 256));
    assert_eq!(
        (sign_low, sign_high),
        (SIGN_BASE + 1, SIGN_BASE + (1 << 16))
    );
    assert!(and_high < sign_low, "the ranges do not overlap");
}
