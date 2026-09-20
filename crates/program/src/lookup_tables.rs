//! The generic channel's committed table: the tables a wide field still
//! needs, packed into one column set under the gated-key convention of
//! `docs/spec/lookup.md` §4.
//!
//! ```text
//! row 0                       the ZeroEntry, all zero
//! rows 1 ..= 2^16             AND:          (a + AND_BASE + 1,   b,        a & b)
//! rows 2^16+1 ..= 2^17        U16GetSign:   (h + SIGN_BASE + 1,  h >> 15,  0)
//! rows 2^17+1 ..= 2^17+32     ShiftPowers:  (s + SHIFT_BASE + 1, 2^s,      2^(31−s))
//! rows above                  the ZeroEntry again, multiplicity 0
//! ```
//!
//! A table's key range is its own — `AND_BASE + 1 ..= AND_BASE + 256`,
//! `SIGN_BASE + 1 ..= SIGN_BASE + 2^16` and `SHIFT_BASE + 1 ..= SHIFT_BASE + 32`
//! are pairwise disjoint — so no tuple of one is a tuple of another, and the
//! `+ 1` the gating adds keeps every real entry off the all-zero tuple the
//! `ZeroEntry` answers. A narrower table is zero-padded to the widest's width,
//! which is [`GENERIC_WIDTH`].
//!
//! The taxonomy stays small on purpose. XOR and AND are positional — a wide
//! field says nothing extra about a byte's seventh bit — and `U16GetSign` is
//! load-bearing in a way it was not over a small field: with a whole word in one
//! column, its top bit is no longer a column that already exists, so every sign
//! comes from here. `ShiftPowers` is the one table whose *domain* is the bound:
//! it has a row for each of the 32 shift amounts and for no other value, which
//! is what truncates a shift (`docs/spec/shift-bitwise.md` §3).
//!
//! `ShiftPowers`' second value is `2^(31−s)`, half the `2^(32−s)` a residue
//! bound multiplies by, because `2^32` does not fit these columns' `u32`
//! backing; the two gates that read it carry the factor 2.
//! `constants::generic_table::SHIFT_COPOWER_BITS`.

use constants::generic_table;
use curve::G1Affine;
use field::Fr;
use pcs::commit;
use poly::{MultilinearPoly, PolyBacking};
use srs::Srs;

/// The channel's tuple width: a key and two values, the AND table being the
/// wider of the two and `U16GetSign` zero-padded to it.
/// `constants::generic_table::WIDTH`.
pub const GENERIC_WIDTH: usize = generic_table::WIDTH;

/// The AND byte table's key base. Its keys are `AND_BASE + a + 1` for
/// `a < 256`. `constants::generic_table::AND_BASE`.
pub const AND_BASE: u32 = generic_table::AND_BASE;

/// The AND byte table's rows: `256 × 256` entries `(a, b, a & b)`.
pub const AND_ROWS: usize = 1 << 16;

/// `U16GetSign`'s key base, one past the AND table's highest key, so the two
/// key ranges are disjoint. `constants::generic_table::SIGN_BASE`.
pub const SIGN_BASE: u32 = generic_table::SIGN_BASE;

/// `U16GetSign`'s rows: one per halfword.
pub const SIGN_ROWS: usize = 1 << 16;

/// `ShiftPowers`' key base, one past `U16GetSign`'s highest key.
/// `constants::generic_table::SHIFT_BASE`.
pub const SHIFT_BASE: u32 = generic_table::SHIFT_BASE;

/// `ShiftPowers`' rows: one per RV32 shift amount.
/// `constants::generic_table::SHIFT_ROWS`.
pub const SHIFT_ROWS: usize = generic_table::SHIFT_ROWS;

/// The rows the packed table needs: the `ZeroEntry` and the three tables.
pub const GENERIC_ROWS: usize = 1 + AND_ROWS + SIGN_ROWS + SHIFT_ROWS;

/// The smallest height that holds the packed table: `2^18`, the first power
/// of two at or above [`GENERIC_ROWS`].
pub const GENERIC_LOG_HEIGHT: u32 = 18;

const _: () = assert!(GENERIC_ROWS.next_power_of_two() == 1 << GENERIC_LOG_HEIGHT);

/// The packed table's `GENERIC_WIDTH` setup columns over `2^log_height` rows,
/// in tuple order: the key, then the two value columns.
///
/// Panics unless `2^log_height >= GENERIC_ROWS`: a table of `2^n` rows cannot
/// hold more entries than it has rows.
pub fn generic_table(log_height: u32) -> Vec<MultilinearPoly> {
    let rows = 1usize << log_height;
    assert!(
        rows >= GENERIC_ROWS,
        "the generic table needs {GENERIC_ROWS} rows and 2^{log_height} is {rows}"
    );
    let mut columns = vec![vec![0u32; rows]; GENERIC_WIDTH];
    for (row, entry) in generic_entries().into_iter().enumerate() {
        for (column, value) in columns.iter_mut().zip(entry) {
            column[row + 1] = value;
        }
    }
    columns
        .into_iter()
        .map(|c| MultilinearPoly::new(PolyBacking::U32(c)))
        .collect()
}

/// Every real entry of the packed table, in row order from row 1: the AND byte
/// table, then `U16GetSign`, then `ShiftPowers`. Row 0, the `ZeroEntry`, is not
/// among them.
///
/// This is the tuple a lookup expression must produce, so it is also what an
/// independent reference computation is diffed against.
pub fn generic_entries() -> Vec<[u32; GENERIC_WIDTH]> {
    let and = (0..256u32).flat_map(|a| (0..256u32).map(move |b| [AND_BASE + a + 1, b, a & b]));
    let sign = (0..1u32 << 16).map(|h| [SIGN_BASE + h + 1, h >> 15, 0]);
    let shift = (0..SHIFT_ROWS as u32).map(|s| {
        [
            SHIFT_BASE + s + 1,
            1 << s,
            1 << (generic_table::SHIFT_COPOWER_BITS - s),
        ]
    });
    and.chain(sign).chain(shift).collect()
}

/// The `ZeroEntry`, which every switched-off row of the channel looks up.
pub fn zero_entry() -> [Fr; GENERIC_WIDTH] {
    [Fr::ZERO; GENERIC_WIDTH]
}

/// The packed table's `GENERIC_WIDTH` commitments, in tuple order: what every
/// verifying key carries, and its SRS digest covers
/// (`docs/spec/jump-branch-slt.md` §6).
///
/// **One set at every height.** A Mercury commitment is the evaluation table
/// read as coefficients (`docs/spec/mercury.md`), and every row of
/// [`generic_table`] past its entries is zero, so the table over `2^n` rows
/// commits to these points for every even `n ≥ 18`; a family's shard opens its
/// `2^n`-row columns against them. They are computed at [`GENERIC_LOG_HEIGHT`].
/// A constant of the SRS, which is why anyone holding the ceremony can
/// recompute them, and why a verifier holding only its `SrsVerifier` cannot.
///
/// Panics if `srs` holds fewer than `2^18` powers.
pub fn generic_commitments(srs: &Srs) -> [G1Affine; GENERIC_WIDTH] {
    let columns = generic_table(GENERIC_LOG_HEIGHT);
    std::array::from_fn(|j| {
        commit(srs, &columns[j])
            .unwrap_or_else(|e| panic!("committing the generic table: {e:?}"))
            .0
    })
}
