//! The generic channel's committed table, against an independent reference
//! computation of each of its four tables.
//!
//! The reference is written here from the ISA's own definitions — a bitwise AND
//! of two bytes, bit 15 of a halfword, and the power of two a shift amount
//! multiplies by, as a register's two words — and never from
//! `program::lookup_tables`, so the two descriptions share no code. A poisoned
//! row is caught by the same comparison.

mod common;

use constants::generic_table::{AND, POW, POW_W, SIGN};
use field::Fp;
use program::lookup_tables::{
    generic_entries, generic_table, zero_entry, AND_ROWS, GENERIC_ROWS, GENERIC_WIDTH, POW_ROWS,
    POW_W_ROWS, SIGN_ROWS,
};

/// The smallest height holding the packed table: `2^17` is short of its
/// 131,169 rows, so 18 is the floor and every menu height at or above it
/// works.
const VARS: u32 = 18;

/// Every entry the packed table holds, in row order from row 1, recomputed
/// here: `(AND + 1, a, b, a & b)` for every byte pair, then
/// `(SIGN + 1, h, h >> 15, 0)` for every halfword, then
/// `(POW + 1, s, lo, hi)` with `2^s = hi·2^32 + lo` for every `s < 64`, then
/// `(POW_W + 1, s, 2^s, 0)` for every `s < 32`. The `+ 1` is the gated-tag
/// offset: it keeps every real entry off the all-zero tuple the `ZeroEntry`
/// answers.
fn reference() -> Vec<[u32; GENERIC_WIDTH]> {
    let mut out = Vec::with_capacity(GENERIC_ROWS - 1);
    for a in 0..256u32 {
        for b in 0..256u32 {
            out.push([AND + 1, a, b, a & b]);
        }
    }
    for h in 0..1u32 << 16 {
        // The sign of the halfword read as a signed 16-bit value.
        let sign = u32::from((h as u16 as i16) < 0);
        out.push([SIGN + 1, h, sign, 0]);
    }
    for s in 0..64u32 {
        // What a 64-bit left shift by `s` multiplies by, as (lo, hi) words.
        let pow = 2u128.pow(s);
        out.push([POW + 1, s, (pow % (1 << 32)) as u32, (pow >> 32) as u32]);
    }
    for s in 0..32u32 {
        out.push([POW_W + 1, s, 2u32.pow(s), 0]);
    }
    out
}

/// Every committed cell of the packed table, `SIGN`
/// included, equals the reference: row 0 is the `ZeroEntry`, rows 1 onward are
/// the three tables in order, and every row past them is the `ZeroEntry` again.
#[test]
fn the_generic_table_is_its_reference_computation() {
    assert_eq!(
        GENERIC_ROWS,
        1 + AND_ROWS + SIGN_ROWS + POW_ROWS + POW_W_ROWS
    );
    assert_eq!(
        (POW_ROWS, POW_W_ROWS),
        (64, 32),
        "one row per RV64 shift amount and per word shift amount, and no other"
    );
    let reference = reference();
    assert_eq!(reference.len(), GENERIC_ROWS - 1);
    let entries: Vec<[u32; GENERIC_WIDTH]> = generic_entries();
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
    let cell = |row: usize, j: usize| columns[j].get_base(row);
    for j in 0..GENERIC_WIDTH {
        assert_eq!(cell(0, j), zero_entry()[j], "the ZeroEntry at row 0");
    }
    for (i, entry) in reference.iter().enumerate() {
        for (j, value) in entry.iter().enumerate() {
            assert_eq!(
                cell(i + 1, j),
                Fp::from_u64(*value as u64),
                "row {} column {j}",
                i + 1
            );
        }
    }
    for row in [GENERIC_ROWS, GENERIC_ROWS + 1, rows - 1] {
        for j in 0..GENERIC_WIDTH {
            assert_eq!(cell(row, j), Fp::ZERO, "row {row} is the ZeroEntry again");
        }
    }
}

/// The negative control: one poisoned row per table — an AND entry whose
/// result is off by one, a sign entry whose bit is flipped, a power whose
/// words are swapped and a word power that is doubled — differs from the
/// committed table at exactly those rows.
#[test]
fn a_poisoned_row_differs_from_the_committed_table() {
    let columns = generic_table(VARS);
    let mut poisoned = reference();
    // `37 & 45 = 37`; claim one more.
    let (a, b) = (37u32, 45u32);
    let and = (256 * a + b) as usize;
    assert_eq!(poisoned[and], [AND + 1, a, b, a & b]);
    assert_ne!(a & b, 0, "a poisoned AND row that is not already 0");
    poisoned[and][3] += 1;
    // `0x8000 >> 15 = 1`; claim 0.
    let sign = AND_ROWS + 0x8000;
    assert_eq!(poisoned[sign], [SIGN + 1, 0x8000, 1, 0]);
    poisoned[sign][2] = 0;
    // `2^37 = 2^5 · 2^32`; claim `2^5` in the low word instead.
    let pow = AND_ROWS + SIGN_ROWS + 37;
    assert_eq!(poisoned[pow], [POW + 1, 37, 0, 1 << 5]);
    poisoned[pow].swap(2, 3);
    // `2^5`; claim `2^6`.
    let pow_w = AND_ROWS + SIGN_ROWS + POW_ROWS + 5;
    assert_eq!(poisoned[pow_w], [POW_W + 1, 5, 1 << 5, 0]);
    poisoned[pow_w][2] <<= 1;

    let differing: Vec<usize> = (0..poisoned.len())
        .filter(|i| {
            (0..GENERIC_WIDTH)
                .any(|j| columns[j].get_base(i + 1) != Fp::from_u64(poisoned[*i][j] as u64))
        })
        .collect();
    assert_eq!(
        differing,
        vec![and, sign, pow, pow_w],
        "exactly the poisoned rows differ"
    );
}

/// A table of `2^n` rows cannot hold more entries than it has rows, and the
/// constructor says so rather than truncating.
#[test]
#[should_panic(expected = "the generic table needs 131169 rows")]
fn a_height_below_the_packed_tables_rows_is_refused() {
    generic_table(17);
}

/// Each table's tag is its own, so no tuple of one is a tuple of another, and
/// none reaches the all-zero tuple; within a table the key runs over exactly the
/// range its lookups bound.
#[test]
fn every_table_has_its_own_tag_and_its_whole_key_range() {
    let entries = generic_entries();
    assert!(entries.iter().all(|e| e[0] != 0), "no real entry has tag 0");
    let mut at = 0;
    for (tag, rows) in [
        (AND, AND_ROWS),
        (SIGN, SIGN_ROWS),
        (POW, POW_ROWS),
        (POW_W, POW_W_ROWS),
    ] {
        let table = &entries[at..at + rows];
        assert!(table.iter().all(|e| e[0] == tag + 1), "tag {tag}");
        let keys: Vec<u64> = table
            .iter()
            .map(|e| {
                if tag == AND {
                    (e[1] as u64) << 8 | e[2] as u64
                } else {
                    e[1] as u64
                }
            })
            .collect();
        assert_eq!(
            keys,
            (0..rows as u64).collect::<Vec<_>>(),
            "tag {tag}'s keys"
        );
        at += rows;
    }
    assert_eq!(at, entries.len());
}
