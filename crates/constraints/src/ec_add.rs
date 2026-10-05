//! The `EC_ADD` family's circuit: one third of a complete elliptic-curve point
//! addition a row, invoked by the `ecall::PRECOMPILE_EC_ADD` ecall and never
//! decoded.
//!
//! `docs/spec/delegation-circuits.md` §7 is normative.
//!
//! # The formula, and why it is projective
//!
//! Renes-Costello-Batina 2015 Algorithm 7 for `a = 0`, in homogeneous
//! projective coordinates. **Complete**: `P + P`, `P + (-P)`, `P + O` and a
//! non-normalized `Z` all come out right, so the guest branches on nothing and
//! the circuit has no degenerate row and needs no inverse witness.
//!
//! It is projective because `guests/vendor/k256`'s `ProjectivePoint` already is
//! (`projective.rs:96`, this same algorithm), and the owner's rule is that a
//! delegation understands the representation its caller already uses rather
//! than the caller being rewritten around the circuit. BN254 comes in affine at
//! revm's `Crypto::bn254_g1_add` boundary and the guest lifts it with `Z = 1`,
//! which is free.
//!
//! Twelve multiplications, in three groups of three reductions:
//!
//! ```text
//! group 0    xx = X1*X2        yy = Y1*Y2        zz = Z1*Z2
//! group 1    m4 = (X1+Y1)(X2+Y2)   m5 = (Y1+Z1)(Y2+Z2)   m6 = (X1+Z1)(X2+Z2)
//! group 2    X3 = xy*ym - byz3*xz
//!            Y3 = yp*ym + bxx9*xz
//!            Z3 = yz*yp + xx3*xy
//! ```
//!
//! with the linear combinations
//!
//! ```text
//! xy = m4 - xx - yy     yz = m5 - yy - zz     xz = m6 - xx - zz
//! bzz3 = b3*zz          ym = yy - bzz3        yp = yy + bzz3
//! byz3 = b3*yz          xx3 = 3*xx            bxx9 = 3*b3*xx
//! ```
//!
//! **Nine reductions, not twelve**: each of the three outputs is two products
//! under one quotient, which is what the limb identity's shape allows for free.
//!
//! # Why three invocations
//!
//! Peak memory is the forward pass — every layer at its own height — plus the
//! committed base and the half-height `Fr` table transition 0's first bind
//! builds, so it is **linear in the row's width**. Nine reductions on one row
//! would be some three times this one's and beyond any machine; three rows of
//! three is 1,420 committed columns, 8,772 inner, and a computed **20.5 GB** a
//! shard at `2^16`.
//!
//! **That is above an execution shard's ~11 GB, and it made this family the
//! peak-setting one in a block until `KECCAK_F` took `2^18`** — ~60 GB a shard
//! against this family's 20.5. An earlier draft of this comment said 10.5
//! GiB; the figure was wrong by a factor of two, and the arithmetic is
//! `crates/constraints/tests/` — 18.3 GB of forward pass, 0.7 GB of committed
//! base, 1.5 GB of first bind. `2^16` is nonetheless forced rather than chosen:
//! the `RANGE16` channel needs sixteen variables, Mercury needs an even count,
//! and `2^18` is four times worse. The lever that remains is the **group
//! count** — five groups of two reductions would be about two-thirds the width
//! at two more invocations an addition — and `docs/handoff/S26c-sha256-ec.md`
//! records the measurement a deferred run produces against this estimate.
//!
//! The three rows are glued by the **frame**, not by a bus: group 0 leaves
//! `xx`, `yy` and `zz` in frame words 49..73 and group 2 reads them there, as
//! ordinary RAM words on an ordinary RAM chain. Nothing new carries them — no
//! new address space, no new presence rule, and `checker::memory_columns_from_log`
//! still covers every column.
//!
//! # The lookup channel this family carries
//!
//! `RANGE16`, which `docs/spec/delegation.md` §9 forbade until §10.3 amended
//! it. It is worth 32 MSMs and ~5 wire bytes per bound: a 32-bit bound is one
//! committed column and two obligations where a bit decomposition is 32
//! columns, and the frame's 38-bit timestamp gap is two columns where it is 38.
//! Without it this family's row is 3,746 columns of gap bits alone.
//!
//! `TIMESTAMP` would be the natural channel for a gap and it does **not** fit:
//! its table needs 19 variables and this family is `2^16`. So the gap takes
//! `RANGE16` in three chunks with a scaled obligation on the top one, which is
//! exact at `2^38` — [`gap_lookups`] is the arithmetic.
//!
//! # Soundness, in one paragraph
//!
//! The six selectors are boolean and sum to `live`, so a live row claims
//! exactly one (curve, group) pair; `selector_rule` ties that claim to the
//! frame word the guest wrote. `m_limb{k}_rule` and `b3_rule` fix the curve's
//! constants to that claim's literals, which is also their `2^32` bound. Every
//! frame word carries a 32-bit bound, and the twelve frame values the row's
//! group reads carry a `< m` borrow chain gated on that group. Each of the
//! three slots' operands is a committed column pinned by a degree-2 gate to a
//! bounded linear combination of those values, so every term of the limb
//! identity is a small integer far below `p` — the widest position is `2^78`
//! against `p`'s `2^254` — and the `Fr` equation **is** the integer equation.
//! The sixteen limb equations telescope to `A*B + C*D + 1024*m^2 = q*m + out`
//! exactly when the last carry is zero, which the last equation forces by
//! having no outgoing carry; `out`'s own chain puts it below `m`. Integer
//! division being unique, `out` is the reduction and nothing else.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::ec_add as f;
use constants::{address_space, lookup_channel};

use crate::delegation as d;
use crate::lookup::ChannelSpec;
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

/// The frame's words: the selector, two points, and six intermediates.
const WORDS: usize = f::FRAME_WORDS;

/// `M` columns: the frame's four head columns and four per word.
pub const MEMORY_COLUMNS: usize = d::HEAD_COLUMNS + 4 * WORDS;

/// Reductions one invocation performs.
const SLOTS: usize = 3;

/// Limbs in a coordinate.
const LIMBS: usize = f::LIMBS;

const fn w(i: usize) -> PolyAddress {
    PolyAddress::Witness(i as u32)
}

// The frame's committed addresses, re-exported so a fill, a checker or a
// tamper twin names a column rather than a number.

/// `M[0]`: the requesting cycle.
pub const CYCLE: PolyAddress = d::CYCLE;
/// `M[1]`: the row's one mask.
pub const LIVE: PolyAddress = d::LIVE;
/// `M[2]`: the frame base pointer.
pub const BASE: PolyAddress = d::BASE;
/// `M[3]`: the anchor teardown's value, free on both sides.
pub const ANCHOR_VALUE: PolyAddress = d::ANCHOR_VALUE;

/// `M` column `4 + 4j + field` of frame word `j`.
pub fn word(j: usize, field: u32) -> PolyAddress {
    d::word(j, field)
}

// ---------------------------------------------------------------------------
// The frame's twelve values
// ---------------------------------------------------------------------------

/// The twelve eight-limb values the frame carries, in frame order, with the
/// groups that **read** them.
///
/// A value's `< m` chain is gated on those groups and on nothing else: on a
/// group-0 row the six intermediate words hold whatever the guest's scratch
/// held, which is a `u32` each and need not be below `m` at all.
const VALUES: [(&str, usize, &[usize]); 12] = [
    ("x1", f::X1_WORD, &[0, 1]),
    ("y1", f::Y1_WORD, &[0, 1]),
    ("z1", f::Z1_WORD, &[0, 1]),
    ("x2", f::X2_WORD, &[0, 1]),
    ("y2", f::Y2_WORD, &[0, 1]),
    ("z2", f::Z2_WORD, &[0, 1]),
    ("xx", f::XX_WORD, &[2]),
    ("yy", f::YY_WORD, &[2]),
    ("zz", f::ZZ_WORD, &[2]),
    ("m4", f::M4_WORD, &[2]),
    ("m5", f::M5_WORD, &[2]),
    ("m6", f::M6_WORD, &[2]),
];

/// The value index of each name, so an operand names a value rather than a
/// number.
const X1: usize = 0;
const Y1: usize = 1;
const Z1: usize = 2;
const X2: usize = 3;
const Y2: usize = 4;
const Z2: usize = 5;
const XX: usize = 6;
const YY: usize = 7;
const ZZ: usize = 8;
const M4: usize = 9;
const M5: usize = 10;
const M6: usize = 11;

/// Limb `k` of frame value `v`, as its read-value `M` column.
fn limb(v: usize, k: usize) -> PolyAddress {
    word(VALUES[v].1 + k, d::WORD_READ_VALUE)
}

// ---------------------------------------------------------------------------
// The witness layout, in order
// ---------------------------------------------------------------------------

use crate::delegation::GAP_CHUNKS;

/// Chunks a signed carry's unsigned value takes beside the value itself.
const CARRY_CHUNKS: usize = 2;

fn gap_chunks() -> usize {
    0
}
fn base_q() -> usize {
    gap_chunks() + GAP_CHUNKS * WORDS
}
fn word_hi() -> usize {
    base_q() + 4
}
fn selectors() -> usize {
    word_hi() + WORDS
}
fn m_limbs() -> usize {
    selectors() + f::CODES.len()
}
fn b3_col() -> usize {
    m_limbs() + LIMBS
}
fn bzz3() -> usize {
    b3_col() + 1
}
fn byz3() -> usize {
    bzz3() + LIMBS
}
fn bxx9() -> usize {
    byz3() + LIMBS
}
fn chains() -> usize {
    bxx9() + LIMBS
}
/// Columns one `< m` chain takes: eight differences, their high halfwords, and
/// eight borrows.
const CHAIN_COLUMNS: usize = 3 * LIMBS;
fn slot_base() -> usize {
    chains() + VALUES.len() * CHAIN_COLUMNS
}
/// Columns one reduction slot takes.
const SLOT_COLUMNS: usize = 4 * LIMBS            // the four operands
    + 2 * LIMBS                                  // out and its high halfwords
    + 2 * f::QUOTIENT_LIMBS                      // q and its high halfwords
    + (1 + CARRY_CHUNKS) * f::CARRIES            // each carry and its chunks
    + CHAIN_COLUMNS; // out's own `< m` chain
fn multiplicity() -> usize {
    slot_base() + SLOTS * SLOT_COLUMNS
}

/// `W[…]`: chunk `c` of frame word `j`'s timestamp gap, weight `2^{16(c+1)}`.
pub fn gap_chunk(j: usize, c: usize) -> PolyAddress {
    w(gap_chunks() + GAP_CHUNKS * j + c)
}

/// `W[…]`: `(base - RAM_ORIGIN) / 4`, and its high halfword.
pub fn base_low() -> PolyAddress {
    w(base_q())
}
/// `W[…]`: [`base_low`]'s high halfword.
pub fn base_low_hi() -> PolyAddress {
    w(base_q() + 1)
}
/// `W[…]`: `2^31 - frame bytes - base`.
pub fn base_room() -> PolyAddress {
    w(base_q() + 2)
}
/// `W[…]`: [`base_room`]'s high halfword.
pub fn base_room_hi() -> PolyAddress {
    w(base_q() + 3)
}

/// `W[…]`: frame word `j`'s read value's high halfword, its 32-bit bound.
pub fn word_high(j: usize) -> PolyAddress {
    w(word_hi() + j)
}

/// `W[…]`: selector `i`, indexing [`constants::ec_add::CODES`].
pub fn selector(i: usize) -> PolyAddress {
    w(selectors() + i)
}

/// `W[…]`: limb `k` of the selected curve's modulus.
pub fn m_limb(k: usize) -> PolyAddress {
    w(m_limbs() + k)
}

/// `W[…]`: the selected curve's `b3 = 3b`.
pub fn b3() -> PolyAddress {
    w(b3_col())
}

/// `W[…]`: limb `k` of `b3 * zz`.
pub fn bzz3_limb(k: usize) -> PolyAddress {
    w(bzz3() + k)
}
/// `W[…]`: limb `k` of `b3 * (m5 - yy - zz)`.
pub fn byz3_limb(k: usize) -> PolyAddress {
    w(byz3() + k)
}
/// `W[…]`: limb `k` of `3 * b3 * xx`.
pub fn bxx9_limb(k: usize) -> PolyAddress {
    w(bxx9() + k)
}

/// `W[…]`: difference limb `i` of value `v`'s `< m` chain, and its halfword.
pub fn diff(v: usize, i: usize) -> PolyAddress {
    w(chains() + v * CHAIN_COLUMNS + i)
}
/// `W[…]`: [`diff`]'s high halfword.
pub fn diff_hi(v: usize, i: usize) -> PolyAddress {
    w(chains() + v * CHAIN_COLUMNS + LIMBS + i)
}
/// `W[…]`: borrow `i` of value `v`'s `< m` chain.
pub fn borrow(v: usize, i: usize) -> PolyAddress {
    w(chains() + v * CHAIN_COLUMNS + 2 * LIMBS + i)
}

fn slot(r: usize) -> usize {
    slot_base() + r * SLOT_COLUMNS
}

/// `W[…]`: limb `k` of slot `r`'s operand `which`, `0..4` for `A`, `B`, `C`,
/// `D`.
pub fn operand(r: usize, which: usize, k: usize) -> PolyAddress {
    w(slot(r) + which * LIMBS + k)
}
/// `W[…]`: limb `k` of slot `r`'s reduced result.
pub fn out_limb(r: usize, k: usize) -> PolyAddress {
    w(slot(r) + 4 * LIMBS + k)
}
/// `W[…]`: [`out_limb`]'s high halfword.
pub fn out_hi(r: usize, k: usize) -> PolyAddress {
    w(slot(r) + 5 * LIMBS + k)
}
/// `W[…]`: limb `i` of slot `r`'s quotient.
pub fn q_limb(r: usize, i: usize) -> PolyAddress {
    w(slot(r) + 6 * LIMBS + i)
}
/// `W[…]`: [`q_limb`]'s high halfword.
pub fn q_hi(r: usize, i: usize) -> PolyAddress {
    w(slot(r) + 6 * LIMBS + f::QUOTIENT_LIMBS + i)
}
fn carry_base(r: usize) -> usize {
    slot(r) + 6 * LIMBS + 2 * f::QUOTIENT_LIMBS
}
/// `W[…]`: slot `r`'s carry `c`, as the **unsigned** value `carry + 2^46`.
pub fn carry(r: usize, c: usize) -> PolyAddress {
    w(carry_base(r) + c)
}
/// `W[…]`: chunk `j` of [`carry`]'s range decomposition, weight
/// `2^{16(j+1)}`.
pub fn carry_chunk(r: usize, c: usize, j: usize) -> PolyAddress {
    w(carry_base(r) + f::CARRIES + CARRY_CHUNKS * c + j)
}
fn out_chain(r: usize) -> usize {
    carry_base(r) + (1 + CARRY_CHUNKS) * f::CARRIES
}
/// `W[…]`: difference limb `i` of slot `r`'s `out < m` chain.
pub fn out_diff(r: usize, i: usize) -> PolyAddress {
    w(out_chain(r) + i)
}
/// `W[…]`: [`out_diff`]'s high halfword.
pub fn out_diff_hi(r: usize, i: usize) -> PolyAddress {
    w(out_chain(r) + LIMBS + i)
}
/// `W[…]`: borrow `i` of slot `r`'s `out < m` chain.
pub fn out_borrow(r: usize, i: usize) -> PolyAddress {
    w(out_chain(r) + 2 * LIMBS + i)
}

/// `W[…]`: the `RANGE16` channel's multiplicity, last in the witness subtree.
pub fn multiplicity_column() -> PolyAddress {
    w(multiplicity())
}

/// The family's `W` columns.
pub const WITNESS_COLUMNS: usize = GAP_CHUNKS * WORDS
    + 4
    + WORDS
    + f::CODES.len()
    + LIMBS
    + 1
    + 3 * LIMBS
    + VALUES.len() * CHAIN_COLUMNS
    + SLOTS * SLOT_COLUMNS
    + 1;

// ---------------------------------------------------------------------------
// The schedule, as data
// ---------------------------------------------------------------------------

/// One operand of one slot, as a bounded linear combination.
///
/// `Frame(v, c)` is `c` times limb `k` of frame value `v`; `Bzz3`, `Byz3` and
/// `Bxx9` are the three curve-scaled helper columns. A slot's operand is a
/// short sum of these, and the sum's coefficient magnitudes are what
/// [`the_carry_offset_covers_every_slot`] bounds.
#[derive(Clone, Copy)]
enum Term {
    Frame(usize, i64),
    Bzz3(i64),
    Byz3(i64),
    Bxx9(i64),
}

impl Term {
    fn column(self, k: usize) -> PolyAddress {
        match self {
            Term::Frame(v, _) => limb(v, k),
            Term::Bzz3(_) => bzz3_limb(k),
            Term::Byz3(_) => byz3_limb(k),
            Term::Bxx9(_) => bxx9_limb(k),
        }
    }
    fn coefficient(self) -> i64 {
        match self {
            Term::Frame(_, c) | Term::Bzz3(c) | Term::Byz3(c) | Term::Bxx9(c) => c,
        }
    }
}

/// The four operands and the output word of one slot of one group.
struct Slot {
    /// `A`, `B`, `C`, `D`: the identity is `A*B + C*D + 1024*m^2 = q*m + out`.
    /// `C` and `D` are empty for groups 0 and 1, whose second product is zero.
    operands: [&'static [Term]; 4],
    /// The frame word the reduction's result is written to.
    out_word: usize,
}

/// Group `g`'s three slots.
///
/// **`D` carries the sign, not the identity.** Group 2's slot 0 is
/// `xy*ym - byz3*xz`, and a per-group sign on a product's coefficient is not
/// expressible — a coefficient is one literal or one challenge — so the minus
/// rides `D`, which is `xx + zz - m6` where the other two slots' is
/// `m6 - xx - zz`. The identity stays one shape for every group.
fn group(g: usize) -> [Slot; SLOTS] {
    // The linear combinations, written once.
    const XY: &[Term] = &[Term::Frame(M4, 1), Term::Frame(XX, -1), Term::Frame(YY, -1)];
    const YZ: &[Term] = &[Term::Frame(M5, 1), Term::Frame(YY, -1), Term::Frame(ZZ, -1)];
    const XZ: &[Term] = &[Term::Frame(M6, 1), Term::Frame(XX, -1), Term::Frame(ZZ, -1)];
    const NXZ: &[Term] = &[Term::Frame(XX, 1), Term::Frame(ZZ, 1), Term::Frame(M6, -1)];
    const YM: &[Term] = &[Term::Frame(YY, 1), Term::Bzz3(-1)];
    const YP: &[Term] = &[Term::Frame(YY, 1), Term::Bzz3(1)];
    const BYZ3: &[Term] = &[Term::Byz3(1)];
    const BXX9: &[Term] = &[Term::Bxx9(1)];
    const XX3: &[Term] = &[Term::Frame(XX, 3)];
    const NONE: &[Term] = &[];

    match g {
        0 => [
            Slot {
                operands: [&[Term::Frame(X1, 1)], &[Term::Frame(X2, 1)], NONE, NONE],
                out_word: f::XX_WORD,
            },
            Slot {
                operands: [&[Term::Frame(Y1, 1)], &[Term::Frame(Y2, 1)], NONE, NONE],
                out_word: f::YY_WORD,
            },
            Slot {
                operands: [&[Term::Frame(Z1, 1)], &[Term::Frame(Z2, 1)], NONE, NONE],
                out_word: f::ZZ_WORD,
            },
        ],
        1 => [
            Slot {
                operands: [
                    &[Term::Frame(X1, 1), Term::Frame(Y1, 1)],
                    &[Term::Frame(X2, 1), Term::Frame(Y2, 1)],
                    NONE,
                    NONE,
                ],
                out_word: f::M4_WORD,
            },
            Slot {
                operands: [
                    &[Term::Frame(Y1, 1), Term::Frame(Z1, 1)],
                    &[Term::Frame(Y2, 1), Term::Frame(Z2, 1)],
                    NONE,
                    NONE,
                ],
                out_word: f::M5_WORD,
            },
            Slot {
                operands: [
                    &[Term::Frame(X1, 1), Term::Frame(Z1, 1)],
                    &[Term::Frame(X2, 1), Term::Frame(Z2, 1)],
                    NONE,
                    NONE,
                ],
                out_word: f::M6_WORD,
            },
        ],
        _ => [
            Slot {
                operands: [XY, YM, BYZ3, NXZ],
                out_word: f::X1_WORD,
            },
            Slot {
                operands: [YP, YM, BXX9, XZ],
                out_word: f::Y1_WORD,
            },
            Slot {
                operands: [YZ, YP, XX3, XY],
                out_word: f::Z1_WORD,
            },
        ],
    }
}

/// The group selector `g`, as a linear form over the six code selectors: the
/// two codes — one a curve — that name that group.
fn group_terms(g: usize) -> Vec<(Coeff, PolyAddress)> {
    (0..f::CODES.len())
        .filter(|i| f::CODE_GROUP[*i] == g)
        .map(|i| (d::lit(1), selector(i)))
        .collect()
}

/// The family's circuit over `2^trace_vars` rows.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    the_offset_covers_every_slot();
    the_carry_offset_covers_every_slot();

    let mut enforcing =
        d::frame_gates_range16(WORDS, f::FRAME_BYTES as u64, base_low(), base_room());
    enforcing.extend(selector_gates());
    enforcing.extend(helper_gates());
    enforcing.extend(chain_gates());
    enforcing.extend(operand_gates());
    enforcing.extend(product_gates());
    enforcing.extend(write_back_gates());

    let artifact = crate::memory::assemble(
        trace_vars,
        [d::memory_names(WORDS), witness_names(), Vec::new()],
        vec![(VirtualKind::Range16, "range16".to_string())],
        d::leaves(address_space::DELEGATION_EC_ADD, WORDS),
        enforcing,
        lookups(),
        &channels(),
    );
    if let Err(e) = crate::lookup::check_copowers(&artifact, &scaled_columns()) {
        panic!("ec_add: {e}");
    }
    check_shape(&artifact);
    artifact
}

/// The selector: six booleans, one-hot on a live row, naming the curve and the
/// group of three reductions.
fn selector_gates() -> Vec<(String, GateDef)> {
    // Two codes summing to a third is what makes `one_code_a_live_row`
    // necessary rather than decorative, exactly as in `mod_mul`: 1 + 3 = 4 and
    // 2 + 4 = 6, so a row claiming two codes spells a third's word.
    const _: () = assert!(f::SECP256K1_G1 + f::SECP256K1_G3 == f::BN254_G1);

    let mut out: Vec<(String, GateDef)> = Vec::new();
    for (i, code) in f::CODES.iter().enumerate() {
        out.push((
            format!("selector{code}_boolean"),
            d::booleanity(selector(i)),
        ));
    }
    {
        let mut terms = vec![(d::lit(1), word(f::SELECTOR_WORD, d::WORD_READ_VALUE))];
        for (i, code) in f::CODES.iter().enumerate() {
            terms.push((d::neg(*code as u64), selector(i)));
        }
        out.push(("selector_rule".to_string(), d::linear(terms)));
    }
    {
        let mut terms: Vec<(Coeff, PolyAddress)> = (0..f::CODES.len())
            .map(|i| (d::lit(1), selector(i)))
            .collect();
        terms.push((d::neg(1), LIVE));
        out.push(("one_code_a_live_row".to_string(), d::linear(terms)));
    }
    // The curve's constants are the selector's literals, which is also their
    // `2^32` bound: `m` and `b3` need no range check at all.
    for k in 0..LIMBS {
        let mut terms = vec![(d::lit(1), m_limb(k))];
        for (i, _) in f::CODES.iter().enumerate() {
            let modulus = f::CURVE_MODULI[f::CODE_CURVE[i]];
            terms.push((d::neg(modulus[k] as u64), selector(i)));
        }
        out.push((format!("m_limb{k}_rule"), d::linear(terms)));
    }
    {
        let mut terms = vec![(d::lit(1), b3())];
        for (i, _) in f::CODES.iter().enumerate() {
            terms.push((d::neg(f::CURVE_B3[f::CODE_CURVE[i]] as u64), selector(i)));
        }
        out.push(("b3_rule".to_string(), d::linear(terms)));
    }
    out
}

/// The three curve-scaled helpers, each a degree-2 pin.
///
/// `bzz3 = b3*zz`, `byz3 = b3*(m5 - yy - zz)` and `bxx9 = 3*b3*xx`. They exist
/// because `b3` is a **column** — the curve is a frame word — so `b3` times a
/// frame limb inside a product's operand would be degree 3. Pinned rather than
/// range-checked: the gate bounds them, `|bzz3_k| < 21 * 2^32`.
fn helper_gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for k in 0..LIMBS {
        out.push((
            format!("bzz3_{k}_rule"),
            d::quadratic(
                vec![(d::lit(1), bzz3_limb(k))],
                vec![(d::neg(1), b3(), limb(ZZ, k))],
            ),
        ));
        out.push((
            format!("byz3_{k}_rule"),
            d::quadratic(
                vec![(d::lit(1), byz3_limb(k))],
                vec![
                    (d::neg(1), b3(), limb(M5, k)),
                    (d::lit(1), b3(), limb(YY, k)),
                    (d::lit(1), b3(), limb(ZZ, k)),
                ],
            ),
        ));
        out.push((
            format!("bxx9_{k}_rule"),
            d::quadratic(
                vec![(d::lit(1), bxx9_limb(k))],
                vec![(d::neg(3), b3(), limb(XX, k))],
            ),
        ));
    }
    out
}

/// One `< m` borrow chain per frame value, gated on the groups that read it,
/// and one per slot's result, gated on `live`.
///
/// ```text
/// v_i - m_i - b_{i-1} + 2^32 b_i = d_i,   d_i < 2^32,   b_i boolean
/// ```
///
/// telescopes to `v - m + 2^256 b_7 = D` with `D` below `2^256`, so `b_7 = 1`
/// says the subtraction borrowed out and `v < m`.
///
/// **Which is soundness and which is totality.** A slot's `out < m` is the
/// reduction: without it a prover answers `r + m` with the quotient one lower
/// and the identity holds over the integers just as well. A frame value's
/// `< m` is what bounds the honest quotient below nine limbs, so that every
/// frame the circuit accepts is one an honest prover can fill — `docs/spec/
/// delegation-circuits.md` §5.3's lesson, applied to twelve values instead of two.
fn chain_gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for (v, (name, _, groups)) in VALUES.into_iter().enumerate() {
        let mut reads: Vec<(Coeff, PolyAddress)> = Vec::new();
        for g in groups {
            reads.extend(group_terms(*g));
        }
        out.extend(one_chain(
            name,
            &|k| limb(v, k),
            &|i| diff(v, i),
            &|i| borrow(v, i),
            reads,
        ));
    }
    for r in 0..SLOTS {
        out.extend(one_chain(
            &format!("out{r}"),
            &|k| out_limb(r, k),
            &|i| out_diff(r, i),
            &|i| out_borrow(r, i),
            vec![(d::lit(1), LIVE)],
        ));
    }
    out
}

/// One borrow chain, over whatever supplies its limbs.
fn one_chain(
    name: &str,
    value: &dyn Fn(usize) -> PolyAddress,
    difference: &dyn Fn(usize) -> PolyAddress,
    borrow_of: &dyn Fn(usize) -> PolyAddress,
    enable: Vec<(Coeff, PolyAddress)>,
) -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for i in 0..LIMBS {
        out.push((
            format!("{name}_borrow{i}_boolean"),
            d::booleanity(borrow_of(i)),
        ));
    }
    // The chain is **ungated**: `m_i` is 0 on a row whose selectors are all 0,
    // by `m_limb{k}_rule`, and so is every other term.
    for i in 0..LIMBS {
        let mut terms = vec![
            (d::lit(1), value(i)),
            (d::neg(1), m_limb(i)),
            (Coeff::Literal(d::pow2(32)), borrow_of(i)),
            (d::neg(1), difference(i)),
        ];
        if let Some(prev) = i.checked_sub(1) {
            terms.push((d::neg(1), borrow_of(prev)));
        }
        out.push((format!("{name}_canonical{i}"), d::linear(terms)));
    }
    // `enable * (1 - b_7) = 0`: below the modulus **on the rows that read it**,
    // and unconstrained on the rest.
    //
    // **Not `enable - b_7 = 0`**, which is what S26c first wrote and which is a
    // different statement: it forces `b_7 = 0` where `enable` is 0, so a value
    // that *is* below the modulus on a row that does not read it becomes
    // unprovable. Every lane is such a value — `EcAddFrame::of` zeroes the six
    // intermediates, and a group-2 row's `X1..Z2` are ordinary coordinates — so
    // that spelling made **every row of this family** unprovable while every
    // shape test, the executor and the guests all passed. What catches it is an
    // honest witness evaluated against the gates, which is
    // `crates/checker/tests/ec_add.rs`.
    //
    // Degree 2: a selector column times a borrow column, both committed.
    let products: Vec<(Coeff, PolyAddress, PolyAddress)> = enable
        .iter()
        .map(|(c, x)| {
            let Coeff::Literal(v) = c else {
                panic!("ec_add: a chain's enable coefficient is a literal")
            };
            (Coeff::Literal(-*v), *x, borrow_of(LIMBS - 1))
        })
        .collect();
    out.push((
        format!("{name}_below_modulus"),
        d::quadratic(enable, products),
    ));
    out
}

/// Each slot's four operand limb vectors, pinned to the group's expression.
///
/// ```text
/// operand[r][which][k] - sum_g g_sel * (group g's expression at limb k) = 0
/// ```
///
/// Degree 2: a selector column times a frame limb or a helper column. The pin
/// is also the operand's **bound** — every term of the sum is below `2^32` in
/// magnitude with a small literal coefficient — so an operand needs no range
/// check of its own, which is what keeps this family's witness at 1,028
/// columns.
fn operand_gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for r in 0..SLOTS {
        for which in 0..4 {
            for k in 0..LIMBS {
                let mut products: Vec<(Coeff, PolyAddress, PolyAddress)> = Vec::new();
                for g in 0..SLOTS {
                    let slots = group(g);
                    for term in slots[r].operands[which] {
                        let c = term.coefficient();
                        for (_, sel) in group_terms(g) {
                            products.push((
                                if c < 0 {
                                    d::lit((-c) as u64)
                                } else {
                                    d::neg(c as u64)
                                },
                                sel,
                                term.column(k),
                            ));
                        }
                    }
                }
                out.push((
                    format!("operand{r}_{which}_{k}_rule"),
                    d::quadratic(vec![(d::lit(1), operand(r, which, k))], products),
                ));
            }
        }
    }
    out
}

/// The sixteen limb equations of `A*B + C*D + 1024*m^2 = q*m + out`, per slot.
///
/// At position `k`, writing `P_k` for `sum_{i+j=k} (A_i B_j + C_i D_j)`,
/// `O_k` for `256 * sum_{i+j=k} m_i m_j` and `S_k` for `sum_{i+j=k} q_i m_j`:
///
/// ```text
/// P_k + O_k - S_k - out_k + c_{k-1} - 2^32 c_k = 0
/// ```
///
/// `out_k` is zero past limb 7, `c_{-1}` is zero, and the last position has no
/// outgoing carry — which is the closing condition: summing the sixteen
/// equations weighted by `2^{32k}` gives the identity exactly when that last
/// carry is zero.
///
/// **The offset is what makes the quotient unsigned.** The binding slot is
/// group 2's slot 1, `yp*ym + bxx9*xz`, as low as `-673 m^2` — the operand
/// ceilings' products, `22*22 + 63*3` — and a signed quotient would need a
/// `live`-gated offset of `1024*m`, which is degree 3, `m` being a column.
/// `1024*m^2` on the left is degree 2 and costs the first two groups nothing but
/// a larger honest quotient.
///
/// **It read `-189 m^2` and named slot 0 until S26c, and that was a shipped
/// bug.** Slot 0's floor is the smaller of the two; sizing the offset against it
/// left slot 1's honest quotient negative on about a quarter of rows, which no
/// executor, guest or shape test could see. [`the_offset_covers_every_slot`]
/// derives the floor now, from the same ceiling table the carry's width uses.
fn product_gates() -> Vec<(String, GateDef)> {
    let offset = f::OFFSET_MULTIPLE;
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for r in 0..SLOTS {
        for k in 0..f::POSITIONS {
            let mut products: Vec<(Coeff, PolyAddress, PolyAddress)> = Vec::new();
            for i in 0..LIMBS {
                let Some(j) = k.checked_sub(i) else { continue };
                if j >= LIMBS {
                    continue;
                }
                products.push((d::lit(1), operand(r, 0, i), operand(r, 1, j)));
                products.push((d::lit(1), operand(r, 2, i), operand(r, 3, j)));
                products.push((d::lit(offset), m_limb(i), m_limb(j)));
            }
            for i in 0..f::QUOTIENT_LIMBS {
                let Some(j) = k.checked_sub(i) else { continue };
                if j >= LIMBS {
                    continue;
                }
                products.push((d::neg(1), q_limb(r, i), m_limb(j)));
            }
            let mut terms: Vec<(Coeff, PolyAddress)> = Vec::new();
            if k < LIMBS {
                terms.push((d::neg(1), out_limb(r, k)));
            }
            if let Some(prev) = k.checked_sub(1) {
                terms.extend(carry_terms(r, prev));
            }
            for (c, x) in carry_terms(r, k) {
                let Coeff::Literal(c) = c else {
                    panic!("ec_add: a carry coefficient is a literal")
                };
                terms.push((Coeff::Literal(-(c * d::pow2(32))), x));
            }
            out.push((format!("slot{r}_limb{k}"), d::quadratic(terms, products)));
        }
    }
    out
}

/// Carry `c` of slot `r` as a linear form: the committed unsigned value less a
/// literal offset times `live`, or the empty form past the last carry.
///
/// The `live` factor is what makes a padding row's carry **0** rather than
/// `-2^46`.
fn carry_terms(r: usize, c: usize) -> Vec<(Coeff, PolyAddress)> {
    if c >= f::CARRIES {
        return Vec::new();
    }
    vec![
        (d::lit(1), carry(r, c)),
        (Coeff::Literal(-d::pow2(f::CARRY_OFFSET_BITS)), LIVE),
    ]
}

/// Every frame word is written back unchanged unless the row's group computes
/// it.
///
/// ```text
/// write_j - read_j - sum g_sel * (out[r][k] - read_j) = 0
/// ```
///
/// over the one `(group, slot, limb)` triple that writes word `j`, if any.
/// Degree 2. A word no group writes — the selector, and the two input points'
/// `X2..Z2` — gets the plain `write_j = read_j`, so the guest's operands
/// survive every call.
fn write_back_gates() -> Vec<(String, GateDef)> {
    let mut out: Vec<(String, GateDef)> = Vec::new();
    for j in 0..WORDS {
        let mut products: Vec<(Coeff, PolyAddress, PolyAddress)> = Vec::new();
        for g in 0..SLOTS {
            let slots = group(g);
            for (r, s) in slots.iter().enumerate() {
                if j >= s.out_word && j < s.out_word + LIMBS {
                    let k = j - s.out_word;
                    for (_, sel) in group_terms(g) {
                        products.push((d::neg(1), sel, out_limb(r, k)));
                        products.push((d::lit(1), sel, word(j, d::WORD_READ_VALUE)));
                    }
                }
            }
        }
        out.push((
            format!("writes_back_w{j}"),
            d::quadratic(
                vec![
                    (d::lit(1), word(j, d::WORD_WRITE_VALUE)),
                    (d::neg(1), word(j, d::WORD_READ_VALUE)),
                ],
                products,
            ),
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// The lookups
// ---------------------------------------------------------------------------

/// Every obligation the circuit carries.
fn lookups() -> Vec<LookupExpr> {
    let mut out = d::gap_lookups_range16(WORDS, &|j, c| gap_chunk(j, c));
    out.extend(d::bound_chunked(
        "base_low",
        vec![(d::lit(1), base_low())],
        &[base_low_hi()],
        29,
        LIVE,
        d::lit(0),
    ));
    out.extend(d::bound_chunked(
        "base_room",
        vec![(d::lit(1), base_room())],
        &[base_room_hi()],
        31,
        LIVE,
        d::lit(0),
    ));
    for j in 0..WORDS {
        out.extend(d::bound32(
            &format!("word{j}"),
            word(j, d::WORD_READ_VALUE),
            word_high(j),
            LIVE,
        ));
    }
    for (v, (name, ..)) in VALUES.into_iter().enumerate() {
        for i in 0..LIMBS {
            out.extend(d::bound32(
                &format!("{name}_diff{i}"),
                diff(v, i),
                diff_hi(v, i),
                LIVE,
            ));
        }
    }
    for r in 0..SLOTS {
        for k in 0..LIMBS {
            out.extend(d::bound32(
                &format!("out{r}_{k}"),
                out_limb(r, k),
                out_hi(r, k),
                LIVE,
            ));
            out.extend(d::bound32(
                &format!("out{r}_diff{k}"),
                out_diff(r, k),
                out_diff_hi(r, k),
                LIVE,
            ));
        }
        for i in 0..f::QUOTIENT_LIMBS {
            out.extend(d::bound32(
                &format!("q{r}_{i}"),
                q_limb(r, i),
                q_hi(r, i),
                LIVE,
            ));
        }
        for c in 0..f::CARRIES {
            let chunks: Vec<PolyAddress> =
                (0..CARRY_CHUNKS).map(|j| carry_chunk(r, c, j)).collect();
            out.extend(d::bound_chunked(
                &format!("carry{r}_{c}"),
                vec![(d::lit(1), carry(r, c))],
                &chunks,
                f::CARRY_BITS,
                LIVE,
                d::lit(0),
            ));
        }
    }
    out
}

/// Every scaled obligation's column, with the selector it carries, for
/// `lookup::check_copowers`.
fn scaled_columns() -> Vec<(PolyAddress, PolyAddress)> {
    let mut out: Vec<(PolyAddress, PolyAddress)> = Vec::new();
    for j in 0..WORDS {
        out.push((gap_chunk(j, GAP_CHUNKS - 1), LIVE));
    }
    out.push((base_low_hi(), LIVE));
    out.push((base_room_hi(), LIVE));
    for r in 0..SLOTS {
        for c in 0..f::CARRIES {
            out.push((carry_chunk(r, c, CARRY_CHUNKS - 1), LIVE));
        }
    }
    out
}

/// The family's lookup channels: `RANGE16`, and it is the first a delegation
/// family has ever carried (`docs/spec/delegation.md` §9).
pub fn channels() -> Vec<ChannelSpec> {
    vec![ChannelSpec {
        channel: lookup_channel::RANGE16,
        table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
        multiplicity: multiplicity_column(),
    }]
}

/// The `W` column names, in layout order.
fn witness_names() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for j in 0..WORDS {
        for c in 0..GAP_CHUNKS {
            out.push(format!("gap{j}_c{c}"));
        }
    }
    out.push("base_low".to_string());
    out.push("base_low_hi".to_string());
    out.push("base_room".to_string());
    out.push("base_room_hi".to_string());
    for j in 0..WORDS {
        out.push(format!("word{j}_hi"));
    }
    for code in f::CODES {
        out.push(format!("selector{code}"));
    }
    for k in 0..LIMBS {
        out.push(format!("m_limb{k}"));
    }
    out.push("b3".to_string());
    for k in 0..LIMBS {
        out.push(format!("bzz3_{k}"));
    }
    for k in 0..LIMBS {
        out.push(format!("byz3_{k}"));
    }
    for k in 0..LIMBS {
        out.push(format!("bxx9_{k}"));
    }
    for (name, ..) in VALUES {
        for i in 0..LIMBS {
            out.push(format!("{name}_diff{i}"));
        }
        for i in 0..LIMBS {
            out.push(format!("{name}_diff{i}_hi"));
        }
        for i in 0..LIMBS {
            out.push(format!("{name}_borrow{i}"));
        }
    }
    for r in 0..SLOTS {
        for which in ["a", "b", "c", "d"] {
            for k in 0..LIMBS {
                out.push(format!("slot{r}_{which}{k}"));
            }
        }
        for k in 0..LIMBS {
            out.push(format!("out{r}_{k}"));
        }
        for k in 0..LIMBS {
            out.push(format!("out{r}_{k}_hi"));
        }
        for i in 0..f::QUOTIENT_LIMBS {
            out.push(format!("q{r}_{i}"));
        }
        for i in 0..f::QUOTIENT_LIMBS {
            out.push(format!("q{r}_{i}_hi"));
        }
        for c in 0..f::CARRIES {
            out.push(format!("carry{r}_{c}"));
        }
        for c in 0..f::CARRIES {
            for j in 0..CARRY_CHUNKS {
                out.push(format!("carry{r}_{c}_c{j}"));
            }
        }
        for i in 0..LIMBS {
            out.push(format!("out{r}_diff{i}"));
        }
        for i in 0..LIMBS {
            out.push(format!("out{r}_diff{i}_hi"));
        }
        for i in 0..LIMBS {
            out.push(format!("out{r}_borrow{i}"));
        }
    }
    out.push("range16_multiplicity".to_string());
    out
}
/// Each slot's four operand ceilings, as multiples of `m`, in
/// `group * SLOTS + slot` order.
///
/// `|A| <= a*m`, and so on. **One table, two derivations**: the carry's width
/// needs the largest `a*b + c*d` and [`OFFSET_MULTIPLE`] needs it too, because
/// the same product bounds how far below zero a left-hand side can reach. They
/// were two separate arguments until S26c derived only the first and shipped an
/// offset the second refutes.
const CEILINGS: [[u64; 4]; SLOTS * SLOTS] = [
    [1, 1, 0, 0],
    [1, 1, 0, 0],
    [1, 1, 0, 0],
    [2, 2, 0, 0],
    [2, 2, 0, 0],
    [2, 2, 0, 0],
    [3, 22, 63, 3],
    [22, 22, 63, 3],
    [3, 22, 3, 3],
];

/// `OFFSET_MULTIPLE` is large enough that **no** slot's left-hand side is
/// negative.
///
/// `A*B + C*D` is as low as `-(a*b + c*d) * m^2` — each product is minimised
/// when one factor is at its positive ceiling and the other at its negative one
/// — so the offset has to be at least that, or the honest quotient of such a row
/// is negative, `q_limb` cannot hold it, and the row is **unprovable**.
///
/// It is a completeness bug and not a soundness one, which is exactly why
/// nothing else catches it: the emulator computes the right answer, the guest
/// agrees with its own software path, and the only thing that fails is an
/// honest prover — intermittently, on about a quarter of group-2 rows, hours
/// into a block proof.
fn the_offset_covers_every_slot() {
    let mut worst = 0u64;
    for [a, b, c, d] in CEILINGS {
        let low = a * b + c * d;
        if low > worst {
            worst = low;
        }
    }
    assert!(
        f::OFFSET_MULTIPLE >= worst,
        "ec_add: a left-hand side reaches -{worst} m^2, which an offset of {} does not cover",
        f::OFFSET_MULTIPLE
    );
}

/// The carry offset covers every slot's position bound — computed, not
/// asserted.
///
/// Each slot's widest position is `8 * (a*b + c*d + OFFSET_MULTIPLE) * 2^64`
/// against `q*m`'s `9 * 2^64`, where `a`, `b`, `c`, `d` are the operands'
/// ceilings as multiples of `2^32`. The carry is the fixed point of
/// `C = (position + C) / 2^32`, and `2^CARRY_OFFSET_BITS` must cover it.
///
/// The group-2 `Y3` slot is the binding one — `yp*ym + bxx9*xz` at
/// `22*22 + 63*3` — and it is why this constant is 45 and not the 44 every
/// other slot needs.
fn the_carry_offset_covers_every_slot() {
    // Operand ceilings, as multiples of 2^32, in the order `group` builds them.
    let base = 1u128 << 32;
    let mut worst = 0u128;
    for [a, b, c, dd] in CEILINGS {
        let positive = (LIMBS as u128)
            * base
            * base
            * (a as u128 * b as u128 + c as u128 * dd as u128 + f::OFFSET_MULTIPLE as u128);
        let negative = (f::QUOTIENT_LIMBS as u128 + 1) * base * base;
        let bound = if positive > negative {
            positive
        } else {
            negative
        };
        let mut carry = 0u128;
        for _ in 0..80 {
            carry = (bound + carry) / base + 1;
        }
        if carry > worst {
            worst = carry;
        }
    }
    assert!(
        worst < (1u128 << f::CARRY_OFFSET_BITS),
        "ec_add: a carry reaches {worst}, which 2^{} does not cover",
        f::CARRY_OFFSET_BITS
    );
}

/// The shape this module intends, checked on every artifact it emits.
pub fn check_shape(a: &CircuitArtifact) {
    assert_eq!(a.memory.len(), MEMORY_COLUMNS, "ec_add: M width");
    assert_eq!(a.witness.len(), WITNESS_COLUMNS, "ec_add: W width");
    assert!(a.setup.is_empty(), "ec_add: no setup column");
    assert_eq!(a.lookups.len(), lookups().len(), "ec_add: obligations");
    assert_eq!(channels().len(), 1, "ec_add: one channel, RANGE16");
    // Every group's schedule writes three distinct frame words, and no group
    // writes the selector.
    for g in 0..SLOTS {
        let words: Vec<usize> = group(g).iter().map(|s| s.out_word).collect();
        for (i, x) in words.iter().enumerate() {
            assert_ne!(*x, f::SELECTOR_WORD, "ec_add: group {g} writes word 0");
            for y in words.iter().skip(i + 1) {
                assert!(
                    x.abs_diff(*y) >= LIMBS,
                    "ec_add: group {g}'s outputs overlap"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The circuit builds, validates, passes `check_memory` and satisfies the
    /// copower rule at its default height. Every one of those panics on
    /// refusal, so construction is the test.
    #[test]
    fn the_circuit_builds_at_its_default_height() {
        let a = artifact(16);
        assert_eq!(a.trace_vars, 16);
        // Two memory roots, then the one channel's numerator and denominator.
        assert_eq!(a.outputs.len(), 4, "two roots and one channel's pair");
    }

    /// `RANGE16` needs sixteen variables, so the family's floor is `2^16` and
    /// `family_circuit` must return `None` below it rather than reaching
    /// `channel_trees`' assertion.
    #[test]
    fn the_channel_sets_the_family_floor() {
        assert_eq!(
            crate::minimum_trace_vars(&channels()),
            constants::lookup_channel::BITS[lookup_channel::RANGE16 as usize]
        );
        assert!(crate::family_circuit(constants::family::EC_ADD, 8).is_none());
        assert!(crate::family_circuit(constants::family::EC_ADD, 16).is_some());
    }

    /// Nine reductions, three a group, and the twelve multiplications the
    /// formula names.
    #[test]
    fn the_schedule_is_nine_reductions_of_twelve_products() {
        let mut products = 0;
        for g in 0..SLOTS {
            for s in group(g).iter() {
                // `A*B` always, `C*D` only where both are non-empty.
                products += 1;
                if !s.operands[2].is_empty() && !s.operands[3].is_empty() {
                    products += 1;
                }
            }
        }
        assert_eq!(products, 12, "twelve multiplications");
        assert_eq!(SLOTS * SLOTS, 9, "nine reductions, three a group");
    }

    /// Every group writes three distinct eight-word runs, none of them the
    /// selector, and group 2 writes the words group 0 and group 1 read as the
    /// two input points — which is what makes the result land in place.
    #[test]
    fn the_groups_write_where_the_next_reads() {
        check_shape(&artifact(16));
        let g2: Vec<usize> = group(2).iter().map(|s| s.out_word).collect();
        assert_eq!(g2, vec![f::X1_WORD, f::Y1_WORD, f::Z1_WORD]);
        let g0: Vec<usize> = group(0).iter().map(|s| s.out_word).collect();
        assert_eq!(g0, vec![f::XX_WORD, f::YY_WORD, f::ZZ_WORD]);
        let g1: Vec<usize> = group(1).iter().map(|s| s.out_word).collect();
        assert_eq!(g1, vec![f::M4_WORD, f::M5_WORD, f::M6_WORD]);
    }

    /// The carry offset covers every slot — the derivation, run as a test as
    /// well as at construction, because it is the one constant a new operand
    /// ceiling would silently invalidate.
    #[test]
    fn the_carry_offset_covers_every_slot_is_computed() {
        the_carry_offset_covers_every_slot();
    }
}
