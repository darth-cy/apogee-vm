//! The generic channel's committed table: the two tables a wide field still
//! needs, packed into one column set under the gated-key convention of
//! `docs/spec/lookup.md` §4.
//!
//! ```text
//! row 0                      the ZeroEntry, all zero
//! rows 1 ..= 2^16            AND:          (a + AND_BASE + 1,  b,  a & b)
//! rows 2^16+1 ..= 2^17       U16GetSign:   (h + SIGN_BASE + 1, h >> 15, 0)
//! rows above                 the ZeroEntry again, multiplicity 0
//! ```
//!
//! A table's key range is its own — `AND_BASE + 1 ..= AND_BASE + 256` and
//! `SIGN_BASE + 1 ..= SIGN_BASE + 2^16` are disjoint — so no tuple of one is a
//! tuple of the other, and the `+ 1` the gating adds keeps every real entry off
//! the all-zero tuple the `ZeroEntry` answers. The narrower table is
//! zero-padded to the wider's width, which is [`GENERIC_WIDTH`].
//!
//! The taxonomy stays small on purpose. XOR and AND are positional — a wide
//! field says nothing extra about a byte's seventh bit — and `U16GetSign` is
//! load-bearing in a way it was not over a small field: with a whole word in one
//! column, its top bit is no longer a column that already exists, so every sign
//! comes from here.

use field::Fr;
use poly::{MultilinearPoly, PolyBacking};

/// The channel's tuple width: a key and two values, the AND table being the
/// wider of the two and `U16GetSign` zero-padded to it.
pub const GENERIC_WIDTH: usize = 3;

/// The AND byte table's key base. Its keys are `AND_BASE + a + 1` for
/// `a < 256`.
pub const AND_BASE: u32 = 0;

/// The AND byte table's rows: `256 × 256` entries `(a, b, a & b)`.
pub const AND_ROWS: usize = 1 << 16;

/// `U16GetSign`'s key base, one past the AND table's highest key, so the two
/// key ranges are disjoint.
pub const SIGN_BASE: u32 = 256;

/// `U16GetSign`'s rows: one per halfword.
pub const SIGN_ROWS: usize = 1 << 16;

/// The rows the packed table needs: the `ZeroEntry` and both tables.
pub const GENERIC_ROWS: usize = 1 + AND_ROWS + SIGN_ROWS;

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
    for (row, entry) in generic_entries().enumerate() {
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
/// table, then `U16GetSign`. Row 0, the `ZeroEntry`, is not among them.
///
/// This is the tuple a lookup expression must produce, so it is also what an
/// independent reference computation is diffed against.
pub fn generic_entries() -> impl Iterator<Item = [u32; GENERIC_WIDTH]> {
    let and = (0..256u32).flat_map(|a| (0..256u32).map(move |b| [AND_BASE + a + 1, b, a & b]));
    let sign = (0..1u32 << 16).map(|h| [SIGN_BASE + h + 1, h >> 15, 0]);
    and.chain(sign)
}

/// The `ZeroEntry`, which every switched-off row of the channel looks up.
pub fn zero_entry() -> [Fr; GENERIC_WIDTH] {
    [Fr::ZERO; GENERIC_WIDTH]
}
