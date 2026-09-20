//! S15 acceptance 10 and S18 acceptance 6: the generic channel's committed
//! table, against an independent reference computation of each of its three
//! tables.
//!
//! The reference is written here from the ISA's own definitions — a bitwise AND
//! of two bytes, bit 15 of a halfword, and the power of two a shift amount
//! multiplies by — and never from `program::lookup_tables`, so the two
//! descriptions share no code. A poisoned row is caught by the same
//! comparison.

mod common;

use field::Fr;
use program::lookup_tables::{
    generic_entries, generic_table, zero_entry, AND_BASE, AND_ROWS, GENERIC_ROWS, GENERIC_WIDTH,
    SHIFT_BASE, SHIFT_ROWS, SIGN_BASE, SIGN_ROWS,
};

/// The smallest height holding the packed table: `2^17` is short of its
/// 131,105 rows, so 18 is the floor and every menu height at or above it
/// works.
const VARS: u32 = 18;

/// Every entry the packed table holds, in row order from row 1, recomputed
/// here: `(a + AND_BASE + 1, b, a & b)` for every byte pair, then
/// `(h + SIGN_BASE + 1, h >> 15, 0)` for every halfword, then
/// `(s + SHIFT_BASE + 1, 2^s, 2^(31 − s))` for every shift amount. The `+ 1`
/// is the gated-key offset: it keeps every real entry off the all-zero tuple
/// the `ZeroEntry` answers.
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
    for s in 0..SHIFT_ROWS as u32 {
        // `ShiftPowers`: what a left shift by `s` multiplies by, and the
        // copower a residue bound scales by — stored halved, because
        // `2^(32 − s)` at `s = 0` is `2^32` and these columns are `u32`.
        // What the circuit needs of the pair is the line below it.
        let pow = 1u32 << s;
        let copow = 1u32 << (31 - s);
        assert_eq!(
            2 * pow as u64 * copow as u64,
            1 << 32,
            "the pair at {s} does not multiply to 2^32"
        );
        out.push([SHIFT_BASE + s + 1, pow, copow]);
    }
    out
}

/// Acceptance 10. Every committed cell of the packed table, `U16GetSign`
/// included, equals the reference: row 0 is the `ZeroEntry`, rows 1 onward are
/// the three tables in order, and every row past them is the `ZeroEntry` again.
#[test]
fn the_generic_table_is_its_reference_computation() {
    assert_eq!(GENERIC_ROWS, 1 + AND_ROWS + SIGN_ROWS + SHIFT_ROWS);
    assert_eq!(
        SHIFT_ROWS, 32,
        "one row per RV32 shift amount, and no other"
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

/// The negative control: one poisoned row per table — an AND entry whose
/// result is off by one, a sign entry whose bit is flipped, and a shift entry
/// whose copower is doubled — differs from the committed table at exactly
/// those cells.
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
    // `2^(31 − 5) = 2^26`; claim `2^27`, which no longer pairs to `2^32`.
    let shift = AND_ROWS + SIGN_ROWS + 5;
    assert_eq!(poisoned[shift], [SHIFT_BASE + 5 + 1, 1 << 5, 1 << 26]);
    poisoned[shift][2] <<= 1;

    let differing: Vec<usize> = (0..poisoned.len())
        .filter(|i| {
            (0..GENERIC_WIDTH)
                .any(|j| columns[j].get(i + 1) != Fr::from_u64(poisoned[*i][j] as u64))
        })
        .collect();
    assert_eq!(
        differing,
        vec![and, sign, shift],
        "exactly the poisoned rows differ"
    );
}

/// A table of `2^n` rows cannot hold more entries than it has rows, and the
/// constructor says so rather than truncating.
#[test]
#[should_panic(expected = "the generic table needs 131105 rows")]
fn a_height_below_the_packed_tables_rows_is_refused() {
    generic_table(17);
}

/// The three tables' key ranges are pairwise disjoint, so no tuple of one is a
/// tuple of another, and none reaches the all-zero tuple.
#[test]
fn the_three_tables_key_ranges_are_disjoint_and_miss_zero() {
    let keys: Vec<u32> = generic_entries().iter().map(|e| e[0]).collect();
    assert_eq!(keys.len(), GENERIC_ROWS - 1);
    assert!(keys.iter().all(|k| *k != 0), "no real entry has key 0");
    let span = |range: &[u32]| (*range.iter().min().unwrap(), *range.iter().max().unwrap());
    let and = span(&keys[..AND_ROWS]);
    let sign = span(&keys[AND_ROWS..AND_ROWS + SIGN_ROWS]);
    let shift = span(&keys[AND_ROWS + SIGN_ROWS..]);
    assert_eq!(and, (AND_BASE + 1, AND_BASE + 256));
    assert_eq!(sign, (SIGN_BASE + 1, SIGN_BASE + (1 << 16)));
    assert_eq!(shift, (SHIFT_BASE + 1, SHIFT_BASE + SHIFT_ROWS as u32));
    assert!(and.1 < sign.0, "AND's range is below U16GetSign's");
    assert!(sign.1 < shift.0, "U16GetSign's is below ShiftPowers'");
}

/// The packed table's commitments — what every verifying key carries and its
/// SRS digest covers — pinned under the ceremony `identity.txt` is over: a
/// trusted value anyone holding the ceremony can recompute
/// (`docs/spec/jump-branch-slt.md` §6). In CI: the file names the same
/// ceremony and holds three 64-byte points.
#[test]
fn the_generic_table_commitments_are_pinned_over_the_ceremony() {
    let (ceremony, points) = common::pinned_generic_table();
    assert_eq!(ceremony, common::pinned_identities().0);
    assert_eq!(points.len(), GENERIC_WIDTH);
    assert!(points.iter().all(|p| p.len() == 128));
}

/// Over the ceremony: `generic_commitments` is the pin, and the table over
/// every menu height it fits — `2^18`, `2^20`, `2^22` — commits to the same
/// three points, which is what lets one set serve every family's height.
#[test]
#[ignore = "needs assets/ptau/ppot_0080_24.ptau; run with --ignored"]
fn the_generic_table_commitments_are_the_ceremonys_at_every_height() {
    let srs = srs::Srs::from_ptau(&common::ptau(), 22).expect("the ceremony file ingests");
    let (ceremony, pinned) = common::pinned_generic_table();
    assert_eq!(test_support::to_hex(&srs.g1()[1].to_bytes()), ceremony);
    let hex = |p: &curve::G1Affine| test_support::to_hex(&p.to_bytes());
    let points = program::lookup_tables::generic_commitments(&srs);
    assert_eq!(points.iter().map(hex).collect::<Vec<_>>(), pinned);
    for log in [18, 20, 22] {
        for (column, point) in generic_table(log).iter().zip(&points) {
            let at = pcs::commit(&srs, column).expect("a commitment").0;
            assert_eq!(&at, point, "2^{log}");
        }
    }
}
