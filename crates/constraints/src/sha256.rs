//! The `SHA256_COMP` family's circuit: **four SHA-256 rounds a row**, over the
//! 25-word frame a delegation request handed over.
//!
//! `docs/spec/delegation-circuits.md` §6 is normative. S26c's row was a whole
//! compression — every frame word and all 64 rounds' working variables as bits,
//! 16,688 inner columns — which pinned the family at `2^8`, 256 compressions a
//! shard, and made 32 shards two thirds of a real block's proof once the
//! stateless guest's SSZ hashing started calling it 8,011 times. This is
//! `KECCAK_F`'s trade made a second time (§6): a compression is **16 rows**,
//! the frame is ordinary RAM, and the global memory multiset is what proves
//! call `r`'s written frame is call `r + 1`'s read one. The guest's own proven
//! loop supplies `r`.
//!
//! # The frame, and what one call does
//!
//! ```text
//! word 0        r                   the round group, 0..16, written back unchanged
//! words 1..9    a b c d e f g h     the working variables, rewritten
//! words 9..25   W_{4r} .. W_{4r+15} the schedule window, written back shifted by
//!                                   four, its last four the words this call derives
//! ```
//!
//! Call `r` runs rounds `4r..4r + 4` with `W_{4r+k}` = window word `k`, and
//! derives `W_{4r+16+m}` for `m < 4` from the window — which is exactly the
//! schedule those rounds' successors need, so the message schedule costs the
//! guest nothing and crosses the frame sixteen words at a time. Calls 12 to 15
//! derive `W_64..W_79`, which nothing reads: a uniform row is cheaper than a
//! row with a mode.
//!
//! Over the four rounds the state is two sequences, `A_j` and `E_j`, with
//! `A_0 = a`, `A_{-1} = b`, `A_{-2} = c`, `A_{-3} = d` and `E` likewise, so
//! round `k` reads `A_k, A_{k-1}, A_{k-2}, A_{k-3}` and writes `A_{k+1}`; after
//! four the frame holds `A_4..A_1` and `E_4..E_1`. **Every one of the sixteen
//! values has an `M` column**: `j <= 0` a read value and `j >= 1` a written
//! one, so every word a gate needs is one column.
//!
//! # No bit
//!
//! The committed unit is a **byte**, and every Boolean operation is one
//! obligation on the `XOR8` channel (`docs/spec/lookup.md` §3). Membership of
//! a three-wide tuple bounds each of its positions to `[0, 256)`
//! individually, which is the whole bound argument for the bytes. Three
//! identities make the round cheap:
//!
//! - **The big sigmas nest.** `Σ0(a) = ROTR2(a ^ ROTR11(a ^ ROTR9(a)))` and
//!   `Σ1(e) = ROTR6(e ^ ROTR5(e ^ ROTR14(e)))`, rotation distributing over
//!   XOR, so every XOR has a plain byte column at tuple position 1 and the
//!   outer rotation is taken on the **word**, where it splits one byte only:
//!   17 obligations a sigma, where three rotations XORed directly are 20.
//! - **A rotation is a literal-weighted combination of bytes and masks.**
//!   Splitting a byte at bit `s` is one XOR against the literal `2^s − 1`,
//!   which pins `v & (2^s − 1) = (v + 2^s − 1 − m)/2` as a linear form —
//!   `KECCAK_F`'s rho, with right rotations.
//! - **`Ch` and `Maj` are sums.** `Ch = (e & f) + (¬e & g)` and
//!   `Maj = (a + b + c − (a ^ b ^ c))/2`, bit-disjoint and per-bit exact, so
//!   each is two obligations a byte and a linear form over the words.
//!
//! The small sigmas carry a shift, which does not nest; each commits the
//! shifted bytes and XORs once against them (16 and 15 obligations).
//!
//! A sum's carry is one obligation `(0, c, c)` on the same channel, which bounds
//! it below 256 and so makes every round and schedule equation an integer
//! equation. The two working variables and the two schedule words a call writes
//! without reading them in-row carry a `RANGE16` pair, as every word of
//! `EC_ADD`'s frame does; every other value it writes is a byte sum.
//!
//! ```text
//! M[0..104]       cycle live base anchor_value, then 25 words x 4 fields
//! W[0..50]        gap chunks, two a frame read
//! W[50..54]       base_low, base_low_hi, base_room, base_room_hi
//! W[54..70]       group_sel, 16 one-hot round-group selectors
//! W[70..118]      the bytes of A_{-2..3} and E_{-2..3}
//! W[118..150]     the bytes of the six window words and two derived words
//!                 the schedule's sigmas read
//! W[150..358]     the four rounds, 52 a round
//! W[358..514]     the four schedule words, 39 a word
//! W[514..518]     the high halfwords of the four written words that carry a pair
//! W[518..520]     the RANGE16 and XOR8 multiplicity columns
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::{address_space, lookup_channel, sha256 as f};
use field::Fr;

use crate::delegation as d;
use crate::lookup::ChannelSpec;
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

// ---------------------------------------------------------------------------
// The shape
// ---------------------------------------------------------------------------

/// Frame words: the group, the eight working variables and the window.
const WORDS: usize = f::FRAME_WORDS;

/// Rounds a call runs, and schedule words it derives.
const R: usize = f::ROUNDS_PER_CALL;

/// Bytes in a word.
const BYTES: usize = 4;

/// The window words whose **bytes** the schedule's sigmas read: `sigma0` reads
/// `W_{t-15}`, window words 1 to 4, and `sigma1` reads `W_{t-2}`, window words
/// 14 and 15 for the first two derived words. The last two read the first two
/// derived words themselves, which [`n_byte`] holds.
const WINDOW_DECODED: [usize; 6] = [1, 2, 3, 4, 14, 15];

/// `M[0]`: the requesting cycle, which stamps every write the invocation makes.
pub const CYCLE: PolyAddress = d::CYCLE;
/// `M[1]`: the row mask, and the one mask every leaf and every obligation carries.
pub const LIVE: PolyAddress = d::LIVE;
/// `M[2]`: the frame base pointer, and the anchor tuple's address.
pub const BASE: PolyAddress = d::BASE;
/// `M[3]`: the value the request wrote back on its mirror query.
pub const ANCHOR_VALUE: PolyAddress = d::ANCHOR_VALUE;

/// A frame word's field: the address it reads and writes.
pub const WORD_ADDR: u32 = d::WORD_ADDR;
/// A frame word's field: the timestamp of the write it reads.
pub const WORD_READ_TS: u32 = d::WORD_READ_TS;
/// A frame word's field: the word before the call.
pub const WORD_READ_VALUE: u32 = d::WORD_READ_VALUE;
/// A frame word's field: the word after it.
pub const WORD_WRITE_VALUE: u32 = d::WORD_WRITE_VALUE;

/// `M[4 + 4j + field]`: one field of frame word `j`.
pub fn word(j: usize, field: u32) -> PolyAddress {
    d::word(j, field)
}

/// `M` columns: the four head columns and four a frame word.
pub const MEMORY_COLUMNS: usize = d::HEAD_COLUMNS + 4 * WORDS;

// ---------------------------------------------------------------------------
// The per-round and per-schedule-word blocks
// ---------------------------------------------------------------------------

/// One round's columns, in layout order. A variant is four bytes wide but the
/// two single mask cells and the two carries.
///
/// `Bs0*` is `Σ0(a) = ROTR2(x)` with `y = a ^ ROTR9(a)` and
/// `x = a ^ ROTR11(y)`; `Bs1*` is `Σ1(e) = ROTR6(x)` with `y = e ^ ROTR14(e)`
/// and `x = e ^ ROTR5(y)`. Each `M*` is the byte XORed with the low mask its
/// rotation splits at, which is what makes the rotation linear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Round {
    /// `a ^ 0x01`, a byte each: ROTR9 splits at bit 1.
    Bs0M1,
    /// `a ^ ROTR9(a)`.
    Bs0Y,
    /// `y ^ 0x07`: ROTR11 splits at bit 3.
    Bs0M3,
    /// `a ^ ROTR11(y)`, whose word rotated right by two is `Σ0(a)`.
    Bs0X,
    /// `x_0 ^ 0x03`, the one byte the word rotation splits.
    Bs0Mx,
    /// `e ^ 0x3f`: ROTR14 splits at bit 6.
    Bs1M6,
    /// `e ^ ROTR14(e)`.
    Bs1Y,
    /// `y ^ 0x1f`: ROTR5 splits at bit 5.
    Bs1M5,
    /// `e ^ ROTR5(y)`, whose word rotated right by six is `Σ1(e)`.
    Bs1X,
    /// `x_0 ^ 0x3f`.
    Bs1Mx,
    /// `e ^ f`, from which `e & f` is linear.
    ChEf,
    /// `e ^ g`, from which `(¬e) & g` is linear.
    ChEg,
    /// `a ^ b`.
    MajAb,
    /// `c ^ a ^ b`, from which `Maj(a, b, c)` is linear.
    MajCab,
    /// `A_{k+1}`'s carry.
    CarryA,
    /// `E_{k+1}`'s carry.
    CarryE,
}

/// The round blocks in layout order.
const ROUND_BLOCKS: [Round; 16] = [
    Round::Bs0M1,
    Round::Bs0Y,
    Round::Bs0M3,
    Round::Bs0X,
    Round::Bs0Mx,
    Round::Bs1M6,
    Round::Bs1Y,
    Round::Bs1M5,
    Round::Bs1X,
    Round::Bs1Mx,
    Round::ChEf,
    Round::ChEg,
    Round::MajAb,
    Round::MajCab,
    Round::CarryA,
    Round::CarryE,
];

impl Round {
    fn width(self) -> usize {
        match self {
            Round::Bs0Mx | Round::Bs1Mx | Round::CarryA | Round::CarryE => 1,
            _ => BYTES,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Round::Bs0M1 => "bs0_m1",
            Round::Bs0Y => "bs0_y",
            Round::Bs0M3 => "bs0_m3",
            Round::Bs0X => "bs0_x",
            Round::Bs0Mx => "bs0_mx",
            Round::Bs1M6 => "bs1_m6",
            Round::Bs1Y => "bs1_y",
            Round::Bs1M5 => "bs1_m5",
            Round::Bs1X => "bs1_x",
            Round::Bs1Mx => "bs1_mx",
            Round::ChEf => "ch_ef",
            Round::ChEg => "ch_eg",
            Round::MajAb => "maj_ab",
            Round::MajCab => "maj_cab",
            Round::CarryA => "carry_a",
            Round::CarryE => "carry_e",
        }
    }
}

/// One derived schedule word's columns, in layout order.
///
/// `Ss0*` is `sigma0(x) = ROTR7(y) ^ SHR3(x)` with `y = x ^ ROTR11(x)`;
/// `Ss1*` is `sigma1(x) = ROTR17(y) ^ SHR10(x)` with `y = x ^ ROTR2(x)`. The
/// shift is committed byte by byte, because two derived forms cannot both sit
/// in one tuple; `SHR10`'s top byte is zero, so `sigma1` commits and XORs
/// three bytes and reads its fourth straight off `ROTR17(y)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sched {
    /// `x ^ 0x07`: ROTR11 and SHR3 both split at bit 3.
    Ss0M3,
    /// `x ^ ROTR11(x)`.
    Ss0Y,
    /// `y ^ 0x7f`: ROTR7 splits at bit 7.
    Ss0M7,
    /// `SHR3(x)`, a byte each.
    Ss0Shr,
    /// `ROTR7(y) ^ SHR3(x)`: `sigma0(x)`'s bytes.
    Ss0Z,
    /// `x ^ 0x03`: ROTR2 and SHR10 both split at bit 2.
    Ss1M2,
    /// `x ^ ROTR2(x)`.
    Ss1Y,
    /// `y ^ 0x01`: ROTR17 splits at bit 1.
    Ss1M1,
    /// `SHR10(x)`'s three nonzero bytes.
    Ss1Shr,
    /// `ROTR17(y) ^ SHR10(x)`'s low three bytes.
    Ss1Z,
    /// The derived word's carry.
    CarryW,
}

/// The schedule blocks in layout order.
const SCHED_BLOCKS: [Sched; 11] = [
    Sched::Ss0M3,
    Sched::Ss0Y,
    Sched::Ss0M7,
    Sched::Ss0Shr,
    Sched::Ss0Z,
    Sched::Ss1M2,
    Sched::Ss1Y,
    Sched::Ss1M1,
    Sched::Ss1Shr,
    Sched::Ss1Z,
    Sched::CarryW,
];

impl Sched {
    fn width(self) -> usize {
        match self {
            Sched::Ss1Shr | Sched::Ss1Z => BYTES - 1,
            Sched::CarryW => 1,
            _ => BYTES,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Sched::Ss0M3 => "ss0_m3",
            Sched::Ss0Y => "ss0_y",
            Sched::Ss0M7 => "ss0_m7",
            Sched::Ss0Shr => "ss0_shr",
            Sched::Ss0Z => "ss0_z",
            Sched::Ss1M2 => "ss1_m2",
            Sched::Ss1Y => "ss1_y",
            Sched::Ss1M1 => "ss1_m1",
            Sched::Ss1Shr => "ss1_shr",
            Sched::Ss1Z => "ss1_z",
            Sched::CarryW => "carry_w",
        }
    }
}

/// Columns one round takes.
const ROUND_COLUMNS: usize = round_columns();
/// Columns one derived schedule word takes.
const SCHED_COLUMNS: usize = sched_columns();

const fn round_columns() -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < ROUND_BLOCKS.len() {
        n += match ROUND_BLOCKS[i] {
            Round::Bs0Mx | Round::Bs1Mx | Round::CarryA | Round::CarryE => 1,
            _ => BYTES,
        };
        i += 1;
    }
    n
}

const fn sched_columns() -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < SCHED_BLOCKS.len() {
        n += match SCHED_BLOCKS[i] {
            Sched::Ss1Shr | Sched::Ss1Z => BYTES - 1,
            Sched::CarryW => 1,
            _ => BYTES,
        };
        i += 1;
    }
    n
}

// ---------------------------------------------------------------------------
// The witness layout, in order
// ---------------------------------------------------------------------------

const fn w(i: usize) -> PolyAddress {
    PolyAddress::Witness(i as u32)
}

const fn gap_block() -> usize {
    0
}
const fn base_block() -> usize {
    gap_block() + d::GAP_CHUNKS * WORDS
}
const fn group_block() -> usize {
    base_block() + 4
}
const fn a_block() -> usize {
    group_block() + f::GROUPS
}
const fn e_block() -> usize {
    a_block() + 6 * BYTES
}
const fn window_block() -> usize {
    e_block() + 6 * BYTES
}
const fn new_block() -> usize {
    window_block() + WINDOW_DECODED.len() * BYTES
}
const fn round_block() -> usize {
    new_block() + 2 * BYTES
}
const fn sched_block() -> usize {
    round_block() + R * ROUND_COLUMNS
}
const fn hi_block() -> usize {
    sched_block() + R * SCHED_COLUMNS
}
const fn multiplicity_block() -> usize {
    hi_block() + 4
}

/// `W` columns: the layout above, and the two multiplicity columns last.
pub const WITNESS_COLUMNS: usize = multiplicity_block() + 2;

/// Chunk `c` of frame word `j`'s timestamp gap, `c < 2`, the low part derived.
pub fn gap_chunk(j: usize, c: usize) -> PolyAddress {
    w(gap_block() + d::GAP_CHUNKS * j + c)
}

/// `(base − RAM_ORIGIN) / 4`.
pub fn base_low() -> PolyAddress {
    w(base_block())
}

/// [`base_low`]'s high halfword.
pub fn base_low_hi() -> PolyAddress {
    w(base_block() + 1)
}

/// `2^31 − frame bytes − base`.
pub fn base_room() -> PolyAddress {
    w(base_block() + 2)
}

/// [`base_room`]'s high halfword.
pub fn base_room_hi() -> PolyAddress {
    w(base_block() + 3)
}

/// The one-hot selector of round group `r`: one degree-1 gate pins the frame's
/// group word to them and one holds their sum to `live`, which makes the group
/// `[0, 16)` **structurally** and supplies the round constants as literals.
pub fn group_sel(r: usize) -> PolyAddress {
    w(group_block() + r)
}

/// Byte `b` of `A_j`, `-2 <= j <= 3`: `j <= 0` decodes a read value, `j >= 1`
/// encodes a written one.
pub fn a_byte(j: isize, b: usize) -> PolyAddress {
    assert!((-2..=3).contains(&j), "sha256: A_{j} has no byte columns");
    w(a_block() + BYTES * (j + 2) as usize + b)
}

/// Byte `b` of `E_j`, `-2 <= j <= 3`.
pub fn e_byte(j: isize, b: usize) -> PolyAddress {
    assert!((-2..=3).contains(&j), "sha256: E_{j} has no byte columns");
    w(e_block() + BYTES * (j + 2) as usize + b)
}

/// Byte `b` of window word `i`, for an `i` the schedule's sigmas read.
pub fn w_byte(i: usize, b: usize) -> PolyAddress {
    let slot = WINDOW_DECODED
        .iter()
        .position(|x| *x == i)
        .unwrap_or_else(|| panic!("sha256: window word {i} has no byte columns"));
    w(window_block() + BYTES * slot + b)
}

/// Byte `b` of the derived schedule word `m`, `m < 2`: the two the call itself
/// reads back through `sigma1`.
pub fn n_byte(m: usize, b: usize) -> PolyAddress {
    assert!(m < 2, "sha256: derived word {m} has no byte columns");
    w(new_block() + BYTES * m + b)
}

/// Column `b` of round `k`'s block `block`.
pub fn round_col(k: usize, block: Round, b: usize) -> PolyAddress {
    assert!(
        k < R && b < block.width(),
        "sha256: round {k} {block:?} {b}"
    );
    let mut offset = 0;
    for x in ROUND_BLOCKS {
        if x == block {
            break;
        }
        offset += x.width();
    }
    w(round_block() + ROUND_COLUMNS * k + offset + b)
}

/// Column `b` of derived schedule word `m`'s block `block`.
pub fn sched_col(m: usize, block: Sched, b: usize) -> PolyAddress {
    assert!(m < R && b < block.width(), "sha256: word {m} {block:?} {b}");
    let mut offset = 0;
    for x in SCHED_BLOCKS {
        if x == block {
            break;
        }
        offset += x.width();
    }
    w(sched_block() + SCHED_COLUMNS * m + offset + b)
}

/// The high halfword of the written word that carries a `RANGE16` pair:
/// slot 0 is `A_4` (word `a`), 1 is `E_4` (word `e`), 2 and 3 the derived
/// schedule words 2 and 3 (window words 14 and 15).
pub fn written_hi(slot: usize) -> PolyAddress {
    assert!(slot < 4, "sha256: written word {slot} has no pair");
    w(hi_block() + slot)
}

/// The frame words [`written_hi`] bounds, in its slot order.
pub const PAIRED_WORDS: [usize; 4] = [
    f::STATE_WORD,
    f::STATE_WORD + 4,
    f::WINDOW_WORD + 14,
    f::WINDOW_WORD + 15,
];

/// The `RANGE16` channel's multiplicity column.
pub fn range16_multiplicity() -> PolyAddress {
    w(multiplicity_block())
}

/// The `XOR8` channel's multiplicity column.
pub fn xor8_multiplicity() -> PolyAddress {
    w(multiplicity_block() + 1)
}

// ---------------------------------------------------------------------------
// The words, as columns
// ---------------------------------------------------------------------------

fn read(j: usize) -> PolyAddress {
    word(j, WORD_READ_VALUE)
}

fn write(j: usize) -> PolyAddress {
    word(j, WORD_WRITE_VALUE)
}

/// `A_j`'s one column, `-3 <= j <= 4`: the state word it is read from or
/// written to. Word `a` is `A_0` going in and `A_4` coming out, `b` is `A_{-1}`
/// and `A_3`, and so on down to `d`.
fn a_word(j: isize) -> PolyAddress {
    assert!((-3..=4).contains(&j), "sha256: A_{j} is not in this call");
    match j <= 0 {
        true => read(f::STATE_WORD + (-j) as usize),
        false => write(f::STATE_WORD + 4 - j as usize),
    }
}

/// `E_j`'s one column, `-3 <= j <= 4`.
fn e_word(j: isize) -> PolyAddress {
    assert!((-3..=4).contains(&j), "sha256: E_{j} is not in this call");
    match j <= 0 {
        true => read(f::STATE_WORD + 4 + (-j) as usize),
        false => write(f::STATE_WORD + 8 - j as usize),
    }
}

/// Window word `i`'s read value: `W_{4r+i}`.
fn window(i: usize) -> PolyAddress {
    read(f::WINDOW_WORD + i)
}

/// The column derived word `m` is written to: window word `12 + m`.
fn derived(m: usize) -> PolyAddress {
    write(f::WINDOW_WORD + 12 + m)
}

/// The four byte columns of `A_j`.
fn a_bytes(j: isize) -> [PolyAddress; BYTES] {
    core::array::from_fn(|b| a_byte(j, b))
}

/// The four byte columns of `E_j`.
fn e_bytes(j: isize) -> [PolyAddress; BYTES] {
    core::array::from_fn(|b| e_byte(j, b))
}

/// The four columns of round `k`'s byte block `block`.
fn round_bytes(k: usize, block: Round) -> [PolyAddress; BYTES] {
    core::array::from_fn(|b| round_col(k, block, b))
}

/// The four columns of schedule word `m`'s byte block `block`.
fn sched_bytes(m: usize, block: Sched) -> [PolyAddress; BYTES] {
    core::array::from_fn(|b| sched_col(m, block, b))
}

/// The bytes `sigma0` reads for derived word `m`: window word `1 + m`.
fn sigma0_input(m: usize) -> [PolyAddress; BYTES] {
    core::array::from_fn(|b| w_byte(1 + m, b))
}

/// The bytes `sigma1` reads for derived word `m`: window word `14 + m`, or the
/// derived word `m − 2` once the window has run out.
fn sigma1_input(m: usize) -> [PolyAddress; BYTES] {
    core::array::from_fn(|b| match m < 2 {
        true => w_byte(14 + m, b),
        false => n_byte(m - 2, b),
    })
}

// ---------------------------------------------------------------------------
// Linear forms
// ---------------------------------------------------------------------------

/// A linear form over committed columns plus a constant: what a byte, a word
/// or a sum of this circuit is before it becomes a gate or a tuple position.
#[derive(Clone, Debug)]
struct Form {
    terms: Vec<(Fr, PolyAddress)>,
    constant: Fr,
}

impl Form {
    /// The zero form.
    fn zero() -> Form {
        Form::constant(Fr::ZERO)
    }

    fn constant(c: Fr) -> Form {
        Form {
            terms: Vec::new(),
            constant: c,
        }
    }

    fn col(x: PolyAddress) -> Form {
        Form {
            terms: vec![(Fr::ONE, x)],
            constant: Fr::ZERO,
        }
    }

    /// `self + c·x`, merging a column already present.
    fn plus_col(mut self, c: Fr, x: PolyAddress) -> Form {
        match self.terms.iter_mut().find(|(_, y)| *y == x) {
            Some(t) => t.0 += c,
            None => self.terms.push((c, x)),
        }
        self
    }

    /// `c·self`.
    fn times(mut self, c: Fr) -> Form {
        for t in self.terms.iter_mut() {
            t.0 *= c;
        }
        self.constant *= c;
        self
    }

    /// `self + c·other`.
    fn plus(mut self, c: Fr, other: &Form) -> Form {
        for (k, x) in &other.terms {
            self = self.plus_col(c * *k, *x);
        }
        self.constant += c * other.constant;
        self
    }

    /// The form as one tuple position of a lookup: literal coefficients and a
    /// literal constant, which the gating multiplies by the selector.
    fn tuple(&self) -> GateDef {
        GateDef::Linear {
            terms: self
                .terms
                .iter()
                .filter(|(c, _)| *c != Fr::ZERO)
                .map(|(c, x)| (Coeff::Literal(*c), *x))
                .collect(),
            constant: Coeff::Literal(self.constant),
        }
    }

    /// The form as an enforcing gate `form = 0`, its constant riding `live`.
    ///
    /// A padding row is an all-zero row, so a bare nonzero constant could not
    /// hold on one and `build::zero_on_zero_row` would refuse the circuit; on a
    /// live row `live` is 1 and the gate is the form. `KECCAK_F`'s rotation
    /// constants ride `live` for the same reason.
    fn gate(&self) -> GateDef {
        let lifted = Form {
            terms: self.terms.clone(),
            constant: Fr::ZERO,
        }
        .plus_col(self.constant, LIVE);
        d::linear(
            lifted
                .terms
                .iter()
                .filter(|(c, _)| *c != Fr::ZERO)
                .map(|(c, x)| (Coeff::Literal(*c), *x))
                .collect(),
        )
    }
}

fn fr(v: u64) -> Fr {
    Fr::from_u64(v)
}

/// `2^-n`.
fn inv_pow2(n: u32) -> Fr {
    d::pow2(n).inverse().expect("a power of two is invertible")
}

/// `Σ 2^{8b}·x_b`: a word from its four bytes.
fn word_of(x: &[PolyAddress; BYTES]) -> Form {
    let mut out = Form::zero();
    for (b, xb) in x.iter().enumerate() {
        out = out.plus_col(d::pow2(8 * b as u32), *xb);
    }
    out
}

/// `v & (2^s − 1)` for a byte `v` whose mask column is `m = v ^ (2^s − 1)`:
/// `(v + 2^s − 1 − m) / 2`, exact because the obligation pins `m` to the true
/// XOR.
fn lo(v: PolyAddress, m: PolyAddress, s: u32) -> Form {
    let half = inv_pow2(1);
    Form::constant(fr((1 << s) - 1) * half)
        .plus_col(half, v)
        .plus_col(-half, m)
}

/// `v >> s` for the same byte: `(v − lo) / 2^s`.
fn hi(v: PolyAddress, m: PolyAddress, s: u32) -> Form {
    Form::col(v).plus(-Fr::ONE, &lo(v, m, s)).times(inv_pow2(s))
}

/// Byte `j` of `ROTR_r(V)`, over `V`'s bytes and their masks at `r mod 8`.
///
/// With `r = 8q + s` and `0 < s < 8`, byte `j` is bits `[8j + r, 8j + r + 8)`
/// of `V`, which straddle bytes `u = (j + q) mod 4` and `u + 1`:
/// `hi(v_u) + 2^{8−s}·lo(v_{u+1})`.
fn rotr_byte(v: &[PolyAddress; BYTES], m: &[PolyAddress; BYTES], r: u32, j: usize) -> Form {
    let (q, s) = ((r / 8) as usize, r % 8);
    assert!(s != 0, "sha256: a whole-byte rotation needs no mask");
    let u = (j + q) % BYTES;
    let next = (u + 1) % BYTES;
    hi(v[u], m[u], s).plus(d::pow2(8 - s), &lo(v[next], m[next], s))
}

/// Byte `j` of `SHR_r(V)`: [`rotr_byte`] with the bytes past the top zero.
fn shr_byte(v: &[PolyAddress; BYTES], m: &[PolyAddress; BYTES], r: u32, j: usize) -> Form {
    let (q, s) = ((r / 8) as usize, r % 8);
    assert!(s != 0, "sha256: a whole-byte shift needs no mask");
    let u = j + q;
    let mut out = Form::zero();
    if u < BYTES {
        out = out.plus(Fr::ONE, &hi(v[u], m[u], s));
    }
    if u + 1 < BYTES {
        out = out.plus(d::pow2(8 - s), &lo(v[u + 1], m[u + 1], s));
    }
    out
}

/// The word `ROTR_s(V)` for `s < 8`, over `V`'s bytes and byte 0's mask:
/// `(V − lo) / 2^s + 2^{32−s}·lo`, which splits byte 0 and nothing else.
fn rotr_word(v: &[PolyAddress; BYTES], m0: PolyAddress, s: u32) -> Form {
    let low = lo(v[0], m0, s);
    word_of(v)
        .plus(-Fr::ONE, &low)
        .times(inv_pow2(s))
        .plus(d::pow2(32 - s), &low)
}

/// `Σ0(A_k)` as a word: `ROTR2(x)`.
fn big_sigma0(k: usize) -> Form {
    rotr_word(
        &round_bytes(k, Round::Bs0X),
        round_col(k, Round::Bs0Mx, 0),
        2,
    )
}

/// `Σ1(E_k)` as a word: `ROTR6(x)`.
fn big_sigma1(k: usize) -> Form {
    rotr_word(
        &round_bytes(k, Round::Bs1X),
        round_col(k, Round::Bs1Mx, 0),
        6,
    )
}

/// `Ch(e, f, g) = (e & f) + (¬e & g) = (f + g − (e ^ f) + (e ^ g)) / 2`.
fn ch(k: usize) -> Form {
    let half = inv_pow2(1);
    Form::zero()
        .plus_col(half, e_word(k as isize - 1))
        .plus_col(half, e_word(k as isize - 2))
        .plus(-half, &word_of(&round_bytes(k, Round::ChEf)))
        .plus(half, &word_of(&round_bytes(k, Round::ChEg)))
}

/// `Maj(a, b, c) = (a + b + c − (a ^ b ^ c)) / 2`.
fn maj(k: usize) -> Form {
    let half = inv_pow2(1);
    let k = k as isize;
    Form::zero()
        .plus_col(half, a_word(k))
        .plus_col(half, a_word(k - 1))
        .plus_col(half, a_word(k - 2))
        .plus(-half, &word_of(&round_bytes(k as usize, Round::MajCab)))
}

/// `K_{4r+k}` as a linear form over the group selectors.
fn round_constant(k: usize) -> Form {
    let mut out = Form::zero();
    for r in 0..f::GROUPS {
        out = out.plus_col(fr(f::ROUND_CONSTANTS[R * r + k] as u64), group_sel(r));
    }
    out
}

/// `T1 = h + Σ1(e) + Ch(e, f, g) + K + W` for round `k`.
fn t1(k: usize) -> Form {
    Form::col(e_word(k as isize - 3))
        .plus(Fr::ONE, &big_sigma1(k))
        .plus(Fr::ONE, &ch(k))
        .plus(Fr::ONE, &round_constant(k))
        .plus_col(Fr::ONE, window(k))
}

/// `sigma0` of derived word `m`'s input, as a word: `z`'s four bytes.
fn small_sigma0(m: usize) -> Form {
    word_of(&sched_bytes(m, Sched::Ss0Z))
}

/// `sigma1` of derived word `m`'s input, as a word: `z`'s three committed
/// bytes and the fourth read off `ROTR17(y)`, `SHR10`'s top byte being zero.
fn small_sigma1(m: usize) -> Form {
    let mut out = Form::zero();
    for b in 0..BYTES - 1 {
        out = out.plus_col(d::pow2(8 * b as u32), sched_col(m, Sched::Ss1Z, b));
    }
    let top = rotr_byte(
        &sched_bytes(m, Sched::Ss1Y),
        &sched_bytes(m, Sched::Ss1M1),
        17,
        BYTES - 1,
    );
    out.plus(d::pow2(24), &top)
}

// ---------------------------------------------------------------------------
// The enforcing gates
// ---------------------------------------------------------------------------

/// The group selector, and the frame word it is pinned to.
///
/// `one_group_a_live_row` is load-bearing for `keccak::one_round_a_live_row`'s
/// reason: the codes are `0..16`, so a pair of selectors sums to another
/// group's code — `1 + 2 = 3` — and without it a row could claim two groups,
/// satisfy `group_rule`, and add two round constants into one round.
fn selector_gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for r in 0..f::GROUPS {
        out.push((format!("group{r}_boolean"), d::booleanity(group_sel(r))));
    }
    let mut rule = Form::col(read(f::GROUP_WORD));
    let mut live = Form::col(LIVE).times(-Fr::ONE);
    for r in 0..f::GROUPS {
        rule = rule.plus_col(-fr(r as u64), group_sel(r));
        live = live.plus_col(Fr::ONE, group_sel(r));
    }
    out.push(("group_rule".to_string(), rule.gate()));
    out.push(("one_group_a_live_row".to_string(), live.gate()));
    out
}

/// The frame's words and their bytes, in both directions.
///
/// Every gate here is **ungated and degree 1**: both sides are zero on the
/// all-zero padding row, and each is a word's byte decomposition and its
/// 32-bit bound at once, the bytes being bounded by the `XOR8` obligations
/// that read them.
fn frame_value_gates() -> Vec<(String, GateDef)> {
    let equal = |name: String, x: PolyAddress, y: &Form| -> (String, GateDef) {
        (name, Form::col(x).plus(-Fr::ONE, y).gate())
    };
    let mut out: Vec<(String, GateDef)> = vec![equal(
        format!("writes_back_w{}", f::GROUP_WORD),
        write(f::GROUP_WORD),
        &Form::col(read(f::GROUP_WORD)),
    )];
    for j in -2..=3isize {
        let tag = index_name(j);
        let verb = if j <= 0 { "decode" } else { "encode" };
        out.push(equal(
            format!("a{tag}_{verb}"),
            a_word(j),
            &word_of(&a_bytes(j)),
        ));
        out.push(equal(
            format!("e{tag}_{verb}"),
            e_word(j),
            &word_of(&e_bytes(j)),
        ));
    }
    for i in WINDOW_DECODED {
        out.push(equal(
            format!("w{i}_decode"),
            window(i),
            &word_of(&core::array::from_fn(|b| w_byte(i, b))),
        ));
    }
    for m in 0..2 {
        out.push(equal(
            format!("n{m}_encode"),
            derived(m),
            &word_of(&core::array::from_fn(|b| n_byte(m, b))),
        ));
    }
    // The window moves down four words: word `i` after the call is word
    // `i + 4` before it.
    for i in 0..f::BLOCK_WORDS - R {
        out.push(equal(
            format!("w{i}_shift"),
            write(f::WINDOW_WORD + i),
            &Form::col(window(i + R)),
        ));
    }
    out
}

/// The four rounds' two sums each, and the four derived words', every one an
/// integer equation because its carry is a byte.
fn sum_gates() -> Vec<(String, GateDef)> {
    let two32 = d::pow2(32);
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for k in 0..R {
        let t1 = t1(k);
        // A_{k+1} = T1 + T2 − 2^32·carry_a, T2 = Σ0(a) + Maj(a, b, c).
        let a = Form::col(a_word(k as isize + 1))
            .plus_col(two32, round_col(k, Round::CarryA, 0))
            .plus(-Fr::ONE, &t1)
            .plus(-Fr::ONE, &big_sigma0(k))
            .plus(-Fr::ONE, &maj(k));
        out.push((format!("r{k}_a"), a.gate()));
        // E_{k+1} = d + T1 − 2^32·carry_e.
        let e = Form::col(e_word(k as isize + 1))
            .plus_col(two32, round_col(k, Round::CarryE, 0))
            .plus_col(-Fr::ONE, a_word(k as isize - 3))
            .plus(-Fr::ONE, &t1);
        out.push((format!("r{k}_e"), e.gate()));
    }
    for m in 0..R {
        // W_t = sigma1(W_{t-2}) + W_{t-7} + sigma0(W_{t-15}) + W_{t-16}.
        let sum = Form::col(derived(m))
            .plus_col(two32, sched_col(m, Sched::CarryW, 0))
            .plus(-Fr::ONE, &small_sigma1(m))
            .plus_col(-Fr::ONE, window(9 + m))
            .plus(-Fr::ONE, &small_sigma0(m))
            .plus_col(-Fr::ONE, window(m));
        out.push((format!("s{m}_sum"), sum.gate()));
    }
    out
}

/// The small sigmas' shifted bytes, pinned to the forms they stand for.
///
/// Committed rather than derived because the XOR that reads them already has
/// a derived form at position 0, and a tuple holds one.
fn shift_gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for m in 0..R {
        let x = sigma0_input(m);
        let masks = sched_bytes(m, Sched::Ss0M3);
        for b in 0..BYTES {
            let form = Form::col(sched_col(m, Sched::Ss0Shr, b))
                .plus(-Fr::ONE, &shr_byte(&x, &masks, 3, b));
            out.push((format!("s{m}_shr3_b{b}"), form.gate()));
        }
        let x = sigma1_input(m);
        let masks = sched_bytes(m, Sched::Ss1M2);
        for b in 0..BYTES - 1 {
            let form = Form::col(sched_col(m, Sched::Ss1Shr, b))
                .plus(-Fr::ONE, &shr_byte(&x, &masks, 10, b));
            out.push((format!("s{m}_shr10_b{b}"), form.gate()));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The rounds and the schedule, as obligations
// ---------------------------------------------------------------------------

/// One `XOR8` obligation: `(e0, x, out)` is a row of `(a, b, a ^ b)`.
///
/// Position 0 may be any literal-weighted form, which is what lets a rotated
/// byte be an operand without a column of its own; positions 1 and 2 are
/// single columns, `β^j·c` not being one `Coeff`.
fn xor8(name: String, e0: &Form, x: PolyAddress, out: PolyAddress) -> LookupExpr {
    LookupExpr {
        name,
        channel: lookup_channel::XOR8,
        selector: LIVE,
        tuple: vec![e0.tuple(), Form::col(x).tuple(), Form::col(out).tuple()],
    }
}

/// `x ^ (2^s − 1) = m` for each of four bytes: the split a rotation at `s`
/// needs.
fn masks(
    out: &mut Vec<LookupExpr>,
    stem: &str,
    x: &[PolyAddress; BYTES],
    m: &[PolyAddress; BYTES],
    s: u32,
) {
    for b in 0..BYTES {
        out.push(xor8(
            format!("{stem}_b{b}_xor"),
            &Form::constant(fr((1 << s) - 1)),
            x[b],
            m[b],
        ));
    }
}

/// A byte bounded below 256: `(0, c, c)` is a row of the table exactly when `c`
/// is a byte.
fn byte_range(name: String, c: PolyAddress) -> LookupExpr {
    xor8(name, &Form::zero(), c, c)
}

/// Round `k`'s 52 obligations: `Σ0`, `Σ1`, `Ch`, `Maj` and the two carries.
fn round_lookups(k: usize, out: &mut Vec<LookupExpr>) {
    let a = a_bytes(k as isize);
    let e = e_bytes(k as isize);
    let p = |stem: &str| format!("r{k}_{stem}");

    // Σ0: y = a ^ ROTR9(a), x = a ^ ROTR11(y), Σ0 = ROTR2(x).
    let (m1, y, m3, x) = (
        round_bytes(k, Round::Bs0M1),
        round_bytes(k, Round::Bs0Y),
        round_bytes(k, Round::Bs0M3),
        round_bytes(k, Round::Bs0X),
    );
    masks(out, &p("bs0_m1"), &a, &m1, 1);
    for b in 0..BYTES {
        out.push(xor8(
            p(&format!("bs0_y_b{b}_xor")),
            &rotr_byte(&a, &m1, 9, b),
            a[b],
            y[b],
        ));
    }
    masks(out, &p("bs0_m3"), &y, &m3, 3);
    for b in 0..BYTES {
        out.push(xor8(
            p(&format!("bs0_x_b{b}_xor")),
            &rotr_byte(&y, &m3, 11, b),
            a[b],
            x[b],
        ));
    }
    out.push(xor8(
        p("bs0_mx_xor"),
        &Form::constant(fr(3)),
        x[0],
        round_col(k, Round::Bs0Mx, 0),
    ));

    // Σ1: y = e ^ ROTR14(e), x = e ^ ROTR5(y), Σ1 = ROTR6(x).
    let (m6, y, m5, x) = (
        round_bytes(k, Round::Bs1M6),
        round_bytes(k, Round::Bs1Y),
        round_bytes(k, Round::Bs1M5),
        round_bytes(k, Round::Bs1X),
    );
    masks(out, &p("bs1_m6"), &e, &m6, 6);
    for b in 0..BYTES {
        out.push(xor8(
            p(&format!("bs1_y_b{b}_xor")),
            &rotr_byte(&e, &m6, 14, b),
            e[b],
            y[b],
        ));
    }
    masks(out, &p("bs1_m5"), &y, &m5, 5);
    for b in 0..BYTES {
        out.push(xor8(
            p(&format!("bs1_x_b{b}_xor")),
            &rotr_byte(&y, &m5, 5, b),
            e[b],
            x[b],
        ));
    }
    out.push(xor8(
        p("bs1_mx_xor"),
        &Form::constant(fr(63)),
        x[0],
        round_col(k, Round::Bs1Mx, 0),
    ));

    // Ch: e ^ f and e ^ g.
    let f_ = e_bytes(k as isize - 1);
    let g = e_bytes(k as isize - 2);
    let (ef, eg) = (round_bytes(k, Round::ChEf), round_bytes(k, Round::ChEg));
    for b in 0..BYTES {
        out.push(xor8(
            p(&format!("ch_ef_b{b}_xor")),
            &Form::col(e[b]),
            f_[b],
            ef[b],
        ));
        out.push(xor8(
            p(&format!("ch_eg_b{b}_xor")),
            &Form::col(e[b]),
            g[b],
            eg[b],
        ));
    }

    // Maj: a ^ b, then c ^ (a ^ b).
    let bb = a_bytes(k as isize - 1);
    let c = a_bytes(k as isize - 2);
    let (ab, cab) = (round_bytes(k, Round::MajAb), round_bytes(k, Round::MajCab));
    for b in 0..BYTES {
        out.push(xor8(
            p(&format!("maj_ab_b{b}_xor")),
            &Form::col(a[b]),
            bb[b],
            ab[b],
        ));
        out.push(xor8(
            p(&format!("maj_cab_b{b}_xor")),
            &Form::col(c[b]),
            ab[b],
            cab[b],
        ));
    }

    out.push(byte_range(p("carry_a_xor"), round_col(k, Round::CarryA, 0)));
    out.push(byte_range(p("carry_e_xor"), round_col(k, Round::CarryE, 0)));
}

/// Derived word `m`'s 32 obligations: `sigma0`, `sigma1` and the carry.
fn sched_lookups(m: usize, out: &mut Vec<LookupExpr>) {
    let p = |stem: &str| format!("s{m}_{stem}");

    // sigma0(x) = ROTR7(y) ^ SHR3(x), y = x ^ ROTR11(x).
    let x = sigma0_input(m);
    let (m3, y, m7, shr, z) = (
        sched_bytes(m, Sched::Ss0M3),
        sched_bytes(m, Sched::Ss0Y),
        sched_bytes(m, Sched::Ss0M7),
        sched_bytes(m, Sched::Ss0Shr),
        sched_bytes(m, Sched::Ss0Z),
    );
    masks(out, &p("ss0_m3"), &x, &m3, 3);
    for b in 0..BYTES {
        out.push(xor8(
            p(&format!("ss0_y_b{b}_xor")),
            &rotr_byte(&x, &m3, 11, b),
            x[b],
            y[b],
        ));
    }
    masks(out, &p("ss0_m7"), &y, &m7, 7);
    for b in 0..BYTES {
        out.push(xor8(
            p(&format!("ss0_z_b{b}_xor")),
            &rotr_byte(&y, &m7, 7, b),
            shr[b],
            z[b],
        ));
    }

    // sigma1(x) = ROTR17(y) ^ SHR10(x), y = x ^ ROTR2(x).
    let x = sigma1_input(m);
    let (m2, y, m1) = (
        sched_bytes(m, Sched::Ss1M2),
        sched_bytes(m, Sched::Ss1Y),
        sched_bytes(m, Sched::Ss1M1),
    );
    masks(out, &p("ss1_m2"), &x, &m2, 2);
    for b in 0..BYTES {
        out.push(xor8(
            p(&format!("ss1_y_b{b}_xor")),
            &rotr_byte(&x, &m2, 2, b),
            x[b],
            y[b],
        ));
    }
    masks(out, &p("ss1_m1"), &y, &m1, 1);
    for b in 0..BYTES - 1 {
        out.push(xor8(
            p(&format!("ss1_z_b{b}_xor")),
            &rotr_byte(&y, &m1, 17, b),
            sched_col(m, Sched::Ss1Shr, b),
            sched_col(m, Sched::Ss1Z, b),
        ));
    }

    out.push(byte_range(p("carry_w_xor"), sched_col(m, Sched::CarryW, 0)));
}

/// Every obligation of the circuit: the frame's over `RANGE16` — the gaps, the
/// base's two decompositions and the four written words' pairs — then the
/// rounds' and the schedule's over `XOR8`.
fn lookups() -> Vec<LookupExpr> {
    let mut out = d::gap_lookups_range16(WORDS, &gap_chunk);
    out.extend(d::bound_chunked(
        "base_low",
        vec![(d::lit(1), base_low())],
        &[base_low_hi()],
        d::BASE_LOW_BITS as u32,
        LIVE,
        d::lit(0),
    ));
    out.extend(d::bound_chunked(
        "base_room",
        vec![(d::lit(1), base_room())],
        &[base_room_hi()],
        d::BASE_ROOM_BITS as u32,
        LIVE,
        d::lit(0),
    ));
    for (slot, j) in PAIRED_WORDS.iter().enumerate() {
        out.extend(d::bound32(
            &format!("w{j}_written"),
            write(*j),
            written_hi(slot),
            LIVE,
        ));
    }
    for k in 0..R {
        round_lookups(k, &mut out);
    }
    for m in 0..R {
        sched_lookups(m, &mut out);
    }
    out
}

/// Every copower-scaled column, with the selector its scaled obligation
/// carries: each gap's top chunk and the two base decompositions' high
/// halfwords, all under `live`.
fn scaled_columns() -> Vec<(PolyAddress, PolyAddress)> {
    let mut out: Vec<(PolyAddress, PolyAddress)> = (0..WORDS)
        .map(|j| (gap_chunk(j, d::GAP_CHUNKS - 1), LIVE))
        .collect();
    out.push((base_low_hi(), LIVE));
    out.push((base_room_hi(), LIVE));
    out
}

// ---------------------------------------------------------------------------
// The artifact
// ---------------------------------------------------------------------------

/// The family's lookup channels: `RANGE16` for the frame, and `XOR8` for the
/// rounds and the schedule.
///
/// Both tables are **virtual**, so neither costs a commitment, a setup column
/// or a movement of the SRS digest. Each is complete only at 16 variables or
/// more, which `crate::lookup::table_vars` reports and `family_circuit`'s
/// derived floor enforces before this function is ever called.
pub fn channels() -> Vec<ChannelSpec> {
    vec![
        ChannelSpec {
            channel: lookup_channel::RANGE16,
            table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
            multiplicity: range16_multiplicity(),
        },
        ChannelSpec {
            channel: lookup_channel::XOR8,
            table: crate::lookup::xor8_table(),
            multiplicity: xor8_multiplicity(),
        },
    ]
}

/// The circuit: four rounds and four schedule words a row, flat.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    let mut enforcing =
        d::frame_gates_range16(WORDS, f::FRAME_BYTES as u64, base_low(), base_room());
    enforcing.extend(selector_gates());
    enforcing.extend(frame_value_gates());
    enforcing.extend(sum_gates());
    enforcing.extend(shift_gates());

    let artifact = crate::memory::assemble(
        trace_vars,
        [d::memory_names(WORDS), witness_names(), Vec::new()],
        vec![
            (VirtualKind::Range16, "range16".to_string()),
            (VirtualKind::Xor8A, "xor8_a".to_string()),
            (VirtualKind::Xor8B, "xor8_b".to_string()),
            (VirtualKind::Xor8Out, "xor8_out".to_string()),
        ],
        d::leaves(address_space::DELEGATION_SHA256_COMP, WORDS),
        enforcing,
        lookups(),
        &channels(),
    );
    if let Err(e) = crate::lookup::check_copowers(&artifact, &scaled_columns()) {
        panic!("sha256: {e}");
    }
    check_shape(&artifact);
    artifact
}

/// `<stem><j>` for a sequence index, a negative one spelled `m<|j|>`: an
/// artifact name is `[a-z0-9_]` and a minus sign is not in it.
fn index_name(j: isize) -> String {
    match j < 0 {
        true => format!("m{}", -j),
        false => format!("{j}"),
    }
}

/// The `W` column names, mirroring the layout above name for name.
fn witness_names() -> Vec<String> {
    let mut out = Vec::with_capacity(WITNESS_COLUMNS);
    for j in 0..WORDS {
        for c in 0..d::GAP_CHUNKS {
            out.push(format!("gap{j}_c{c}"));
        }
    }
    for name in ["base_low", "base_low_hi", "base_room", "base_room_hi"] {
        out.push(name.to_string());
    }
    for r in 0..f::GROUPS {
        out.push(format!("group{r}"));
    }
    for stem in ["a", "e"] {
        for j in -2..=3isize {
            for b in 0..BYTES {
                out.push(format!("{stem}{}_b{b}", index_name(j)));
            }
        }
    }
    for i in WINDOW_DECODED {
        for b in 0..BYTES {
            out.push(format!("w{i}_b{b}"));
        }
    }
    for m in 0..2 {
        for b in 0..BYTES {
            out.push(format!("n{m}_b{b}"));
        }
    }
    for k in 0..R {
        for block in ROUND_BLOCKS {
            for b in 0..block.width() {
                out.push(match block.width() {
                    1 => format!("r{k}_{}", block.name()),
                    _ => format!("r{k}_{}_b{b}", block.name()),
                });
            }
        }
    }
    for m in 0..R {
        for block in SCHED_BLOCKS {
            for b in 0..block.width() {
                out.push(match block.width() {
                    1 => format!("s{m}_{}", block.name()),
                    _ => format!("s{m}_{}_b{b}", block.name()),
                });
            }
        }
    }
    for j in PAIRED_WORDS {
        out.push(format!("w{j}_written_hi"));
    }
    out.push("range16_multiplicity".to_string());
    out.push("xor8_multiplicity".to_string());
    out
}

/// Obligations a row carries on `RANGE16`: four a frame gap, three each for
/// the base's two decompositions, and two for each of the four paired words.
const RANGE16_OBLIGATIONS: usize = 4 * WORDS + 6 + 2 * PAIRED_WORDS.len();

/// Obligations a row carries on `XOR8`: 52 a round and 32 a derived word.
const XOR8_OBLIGATIONS: usize = 52 * R + 32 * R;

/// The shape, asserted on every artifact this module emits.
///
/// The two obligation counts are the cost model's inputs: a fraction tree has
/// `(lookups + 1).next_power_of_two()` leaves, so `RANGE16`'s 114 sit under a
/// 128-leaf tree with 13 to spare and `XOR8`'s 336 under a 512-leaf one with
/// 175.
pub fn check_shape(a: &CircuitArtifact) {
    assert_eq!(a.memory.len(), MEMORY_COLUMNS, "sha256: M columns");
    assert_eq!(a.witness.len(), WITNESS_COLUMNS, "sha256: W columns");
    assert_eq!(WITNESS_COLUMNS, 520, "sha256: the manifest's W width");
    assert_eq!(ROUND_COLUMNS, 52, "sha256: a round's columns");
    assert_eq!(SCHED_COLUMNS, 39, "sha256: a derived word's columns");
    assert!(
        a.setup.is_empty(),
        "sha256: this family has no setup column"
    );
    assert_eq!(a.virtuals.len(), 4, "sha256: range16 and XOR8's three");
    assert_eq!(a.outputs.len(), 6, "sha256: two roots and two channels");
    let count = |channel: u32| a.lookups.iter().filter(|l| l.channel == channel).count();
    assert_eq!(
        count(lookup_channel::RANGE16),
        RANGE16_OBLIGATIONS,
        "sha256: RANGE16 obligations"
    );
    assert_eq!(
        count(lookup_channel::XOR8),
        XOR8_OBLIGATIONS,
        "sha256: XOR8 obligations"
    );
    assert_eq!(RANGE16_OBLIGATIONS, 114);
    assert_eq!(XOR8_OBLIGATIONS, 336);
    assert_eq!((RANGE16_OBLIGATIONS + 1).next_power_of_two(), 128);
    assert_eq!((XOR8_OBLIGATIONS + 1).next_power_of_two(), 512);

    let named = |name: &str| a.relations.iter().any(|r| r.name == name);
    for name in [
        "live_boolean",
        "base_aligned",
        "base_in_window",
        "group_rule",
        "one_group_a_live_row",
        "writes_back_w0",
    ] {
        assert!(named(name), "sha256: gate `{name}` is missing");
    }
    let count = |prefix: &str| {
        a.relations
            .iter()
            .filter(|r| r.name.starts_with(prefix))
            .count()
    };
    assert_eq!(count("addr_w"), WORDS, "sha256: one addr gate a frame word");
    assert_eq!(count("group"), f::GROUPS + 1, "sha256: the selector");
    for k in 0..R {
        assert!(named(&format!("r{k}_a")) && named(&format!("r{k}_e")));
    }
    for m in 0..R {
        assert!(named(&format!("s{m}_sum")), "sha256: schedule word {m}");
    }
    // `writes_back_w0`, a decode for each window word the sigmas read, and the
    // window's twelve-word shift.
    assert_eq!(
        count("w"),
        1 + WINDOW_DECODED.len() + (f::BLOCK_WORDS - R),
        "sha256: the window's gates"
    );
    assert!(
        a.layers[1..].iter().all(|l| l.enforcing.is_empty()),
        "sha256: a flat circuit enforces on gate list 0 alone"
    );
    assert!(
        a.padding.zero_row_valid,
        "sha256: the all-zero row is a valid padding row"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A witness column's position in the `W` subtree.
    fn at(x: PolyAddress) -> usize {
        match x {
            PolyAddress::Witness(i) => i as usize,
            other => panic!("{other} is not a witness column"),
        }
    }

    /// The witness names are exactly the layout, each once.
    #[test]
    fn the_witness_names_are_the_layout() {
        let names = witness_names();
        assert_eq!(names.len(), WITNESS_COLUMNS);
        let mut sorted = names.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "a name is used twice");
        assert_eq!(names[at(round_col(1, Round::Bs1Mx, 0))], "r1_bs1_mx");
        assert_eq!(names[at(sched_col(3, Sched::Ss1Z, 2))], "s3_ss1_z_b2");
        assert_eq!(names[at(a_byte(-2, 1))], "am2_b1");
        assert_eq!(names[at(w_byte(14, 3))], "w14_b3");
        assert_eq!(names[at(written_hi(3))], "w24_written_hi");
    }

    /// The circuit builds at its channel floor, and at no lower height.
    #[test]
    fn the_circuit_builds_at_its_channel_floor_and_no_lower() {
        let a = artifact(16);
        assert_eq!(a.trace_vars, 16);
        assert!(crate::family_circuit(constants::family::SHA256_COMP, 14).is_none());
        assert!(crate::family_circuit(constants::family::SHA256_COMP, 16).is_some());
    }
}
