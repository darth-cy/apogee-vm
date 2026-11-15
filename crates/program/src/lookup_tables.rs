//! The generic channel's table: the tables a wide field still needs, packed
//! into one column set under the gated-key convention of
//! `docs/spec/lookup.md` §4.
//!
//! ```text
//! row 0                        the ZeroEntry, all zero
//! rows 1 ..= 2^16              AND:    (AND + 1,    a, b,       a & b)          a, b < 2^8
//! rows 2^16+1 ..= 2^17         SIGN:   (SIGN + 1,   h, h >> 15, 0)              h < 2^16
//! rows 2^17+1 ..= 2^17+64      POW:    (POW + 1,    s, 2^s mod 2^32, 2^s >> 32) s < 64
//! rows 2^17+65 ..= 2^17+96     POW_W:  (POW_W + 1,  s, 2^s,     0)              s < 32
//! rows above                   the ZeroEntry again, multiplicity 0
//! ```
//!
//! The first column is the sub-table's tag, plus the 1 the gating adds, which
//! keeps every real entry off the all-zero tuple the `ZeroEntry` answers. A
//! tuple of one sub-table is never a tuple of another, so a lookup that names a
//! tag has its key bounded by that sub-table's rows: a byte below 256, a
//! halfword below `2^16`, a shift amount below 64 or 32. No family bounds a
//! key of this table with an obligation of its own.
//!
//! The taxonomy stays small on purpose. AND is positional — a wide field says
//! nothing extra about a byte's seventh bit — and `SIGN` is load-bearing in a
//! way it was not over a small field: with a whole word in one column, its top
//! bit is not a column that already exists, so every sign comes from here. The
//! two power tables give a shift its multiplier, `2^s` as a register's two
//! words (`docs/spec/mul-div.md` §2).

use constants::generic_table::{AND, POW, POW_W, SIGN, WIDTH};
use field::Fp;
use poly::{MultilinearPoly, PolyBacking};

/// The channel's tuple width: a tag, a key and two values.
/// `constants::generic_table::WIDTH`.
pub const GENERIC_WIDTH: usize = WIDTH;

/// The AND byte table's rows: `256 × 256` entries `(a, b, a & b)`.
pub const AND_ROWS: usize = 1 << 16;

/// `SIGN`'s rows: one per halfword.
pub const SIGN_ROWS: usize = 1 << 16;

/// `POW`'s rows: one per 64-bit shift amount.
pub const POW_ROWS: usize = 64;

/// `POW_W`'s rows: one per 32-bit shift amount.
pub const POW_W_ROWS: usize = 32;

/// The rows the packed table needs: the `ZeroEntry` and the four tables.
pub const GENERIC_ROWS: usize = 1 + AND_ROWS + SIGN_ROWS + POW_ROWS + POW_W_ROWS;

/// The smallest height that holds the packed table: `2^18`, the first power
/// of two at or above [`GENERIC_ROWS`].
pub const GENERIC_LOG_HEIGHT: u32 = 18;

const _: () = assert!(GENERIC_ROWS.next_power_of_two() == 1 << GENERIC_LOG_HEIGHT);

/// The packed table's `GENERIC_WIDTH` setup columns over `2^log_height` rows,
/// in tuple order: the tag, the key, then the two value columns.
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
/// table, then `SIGN`, then `POW` and `POW_W`. Row 0, the `ZeroEntry`, is not
/// among them.
///
/// This is the tuple a lookup expression must produce, so it is also what an
/// independent reference computation is diffed against.
pub fn generic_entries() -> Vec<[u32; GENERIC_WIDTH]> {
    let and = (0..256u32).flat_map(|a| (0..256u32).map(move |b| [AND + 1, a, b, a & b]));
    let sign = (0..1u32 << 16).map(|h| [SIGN + 1, h, h >> 15, 0]);
    let pow = (0..POW_ROWS as u32).map(|s| {
        let p = 1u64 << s;
        [POW + 1, s, p as u32, (p >> 32) as u32]
    });
    let pow_w = (0..POW_W_ROWS as u32).map(|s| [POW_W + 1, s, 1 << s, 0]);
    and.chain(sign).chain(pow).chain(pow_w).collect()
}

/// The `ZeroEntry`, which every switched-off row of the channel looks up.
pub fn zero_entry() -> [Fp; GENERIC_WIDTH] {
    [Fp::ZERO; GENERIC_WIDTH]
}
