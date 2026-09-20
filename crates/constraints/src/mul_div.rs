//! The `MUL_DIV` family's circuit: the eight M-extension operations — `mul`,
//! `mulh`, `mulhsu`, `mulhu`, `div`, `divu`, `rem`, `remu`.
//!
//! `docs/spec/mul-div.md` is normative: the columns, the gates, the lookups
//! and the argument. This file is that document as data, assembled by S15's
//! `memory::frame_with_channels_artifact` beside S14's frame, with S17's
//! is-zero gadget from `crate::gadgets`.
//!
//! ```text
//! frame     M[0..21], W[0..7]: pc rs1 rs2 rd at slots 0..4
//! W[7..12]  the claimed decoded row: next_pc rs1 rs2 rd mask (no imm)
//! W[12..20] the mask's eight bits, extra_mask::mul_div order
//! W[20]     f_div: the division half, two is-zero gadgets' enable
//! W[21..27] rs1_hi, rs1_top, rs2_hi, rs2_top, s1, s2: the operands' signs
//! W[27..34] mx, my, p_low, p_low_hi, p_high, p_high_hi, p_sign: one product
//! W[34..40] q, q_hi, q_sign, r, r_hi, r_sign: the division witness
//! W[40..45] r_inv, rz, d1, d_inv, dz: rem ≠ 0 and divisor = 0
//! W[45..49] abs_r, abs_d, gap, gap_hi: |rem| < |divisor|
//! W[49]     rd_hi
//! W[50..54] one multiplicity per channel: timestamp, range16, generic, decoder
//! S[0..6]   the decoded table, program::lookup_tuple order — six columns
//! S[6..9]   the packed generic table, constants::generic_table
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::extra_mask::mul_div as kind;
use constants::{family, generic_table, lookup_channel};
use field::Fr;

use crate::gadgets::is_zero;
use crate::lookup::ChannelSpec;
use crate::memory::{
    frame, frame_queries, frame_with_channels_artifact, rd_selected, FamilySpec, FIELD_ADDR,
    FIELD_MASK, FIELD_READ_VALUE, FIELD_WRITE_VALUE, PC, RD, RS1, RS2,
};
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

/// The family's queries, in slot order: its frame is `memory::frame_queries`'
/// list, and this file addresses its columns by these slots.
const QUERIES: [usize; 4] = [PC, RS1, RS2, RD];
const SLOT_PC: usize = 0;
const SLOT_RS1: usize = 1;
const SLOT_RS2: usize = 2;
const SLOT_RD: usize = 3;

/// The frame's own witness columns: four gap chunks, then the x0 gadget's
/// three. Everything this file adds follows them.
const FRAME_WITNESS: u32 = 4 + 3;

/// The word the family's arithmetic is over. Every gate that carries it takes
/// it as a parameter, so the exhaustive reduced-width check of the division
/// encoding evaluates these gates and not a transcription of them.
pub const WORD_BITS: u32 = 32;

const fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(FRAME_WITNESS + i)
}

/// `W[7..12]`: the claimed decoded row, `next_pc, rs1, rs2, rd, mask` —
/// `program::lookup_tuple` after `pc`, which the frame's own pc column is.
/// **Five columns, not six**: this family's tuple has no `imm`, every one of
/// its instructions being R-type.
pub const DECODED: [PolyAddress; 5] = [w(0), w(1), w(2), w(3), w(4)];
const SEQ: PolyAddress = DECODED[0];
const DECODED_RS1: PolyAddress = DECODED[1];
const DECODED_RS2: PolyAddress = DECODED[2];
const DECODED_RD: PolyAddress = DECODED[3];
const DECODED_MASK: PolyAddress = DECODED[4];

/// `W[12..20]`: the packed mask's bits, bit `k` at index `k` —
/// `constants::extra_mask::mul_div`'s order: mul, mulh, mulhsu, mulhu, div,
/// divu, rem, remu.
pub const KINDS: [PolyAddress; 8] = [w(5), w(6), w(7), w(8), w(9), w(10), w(11), w(12)];
const MUL: PolyAddress = KINDS[kind::MUL as usize];
const MULH: PolyAddress = KINDS[kind::MULH as usize];
const MULHSU: PolyAddress = KINDS[kind::MULHSU as usize];
const MULHU: PolyAddress = KINDS[kind::MULHU as usize];
const DIV: PolyAddress = KINDS[kind::DIV as usize];
const DIVU: PolyAddress = KINDS[kind::DIVU as usize];
const REM: PolyAddress = KINDS[kind::REM as usize];
const REMU: PolyAddress = KINDS[kind::REMU as usize];

/// The four multiplies, whose product is `rs1_adj·rs2_adj`.
const MULS: [PolyAddress; 4] = [MUL, MULH, MULHSU, MULHU];
/// The four divisions, whose sum is [`F_DIV`].
const DIVS: [PolyAddress; 4] = [DIV, DIVU, REM, REMU];
/// The kinds that read `rs1` signed. `mulhu`, `divu` and `remu` do not, and
/// `mul`'s low half is the same either way — it is here so that one product
/// identity covers all four multiplies.
const LHS_SIGNED: [PolyAddress; 5] = [MUL, MULH, MULHSU, DIV, REM];
/// The kinds that read `rs2` signed. `mulhsu` is the asymmetric one: its `rs1`
/// is signed and its `rs2` is not.
const RHS_SIGNED: [PolyAddress; 4] = [MUL, MULH, DIV, REM];
/// The kinds whose `rd` is the product's high half.
const TAKES_HIGH: [PolyAddress; 3] = [MULH, MULHSU, MULHU];
/// The kinds whose `rd` is the quotient.
const TAKES_QUOTIENT: [PolyAddress; 2] = [DIV, DIVU];
/// The kinds whose `rd` is the remainder.
const TAKES_REMAINDER: [PolyAddress; 2] = [REM, REMU];

/// `W[20]`: 1 exactly on a live division row. The enable of both is-zero
/// gadgets, so it carries a booleanity gate of its own.
pub const F_DIV: PolyAddress = w(13);
/// `W[21]`, `W[22]`: `rs1`'s high halfword and its top bit, the bit from
/// `U16GetSign` over the halfword.
pub const RS1_HI: PolyAddress = w(14);
pub const RS1_TOP: PolyAddress = w(15);
/// `W[23]`, `W[24]`: `rs2`'s high halfword and its top bit.
pub const RS2_HI: PolyAddress = w(16);
pub const RS2_TOP: PolyAddress = w(17);
/// `W[25]`, `W[26]`: the sign *adjustments*, `s = kind_reads_it_signed·top`.
/// An unsigned position forces its flag to 0, which is what keeps the
/// selection degree 2.
pub const S1: PolyAddress = w(18);
pub const S2: PolyAddress = w(19);
/// `W[27]`, `W[28]`: the one product's two multiplicands — the two operands on
/// a multiply row, the divisor and the quotient on a division row.
pub const MX: PolyAddress = w(20);
pub const MY: PolyAddress = w(21);
/// `W[29..34]`: the product's two halves with their high halfwords, and its
/// sign.
pub const P_LOW: PolyAddress = w(22);
pub const P_LOW_HI: PolyAddress = w(23);
pub const P_HIGH: PolyAddress = w(24);
pub const P_HIGH_HI: PolyAddress = w(25);
pub const P_SIGN: PolyAddress = w(26);
/// `W[34..37]`: the quotient word, its high halfword, and its sign adjustment.
///
/// `q_sign` is a **free** boolean, pinned only by `q`'s own range: tying it to
/// bit `WORD_BITS − 1` of `q` would make `−2^31 ÷ −1` unprovable, that case
/// being exactly the one whose quotient is `+2^31` with the word's top bit
/// set (`docs/spec/mul-div.md` §5.3).
pub const Q: PolyAddress = w(27);
pub const Q_HI: PolyAddress = w(28);
pub const Q_SIGN: PolyAddress = w(29);
/// `W[37..40]`: the remainder word, its high halfword, and its sign
/// adjustment, which is 1 exactly where the dividend is negative and the
/// remainder is not zero.
pub const R: PolyAddress = w(30);
pub const R_HI: PolyAddress = w(31);
pub const R_SIGN: PolyAddress = w(32);
/// `W[40..42]`: the is-zero gadget over `r`, enabled by `f_div`.
pub const R_INV: PolyAddress = w(33);
pub const RZ: PolyAddress = w(34);
/// `W[42]`: `f_div·s1`, the negative-dividend flag a division row carries.
pub const D1: PolyAddress = w(35);
/// `W[43]`, `W[44]`: the is-zero gadget over `rs2`, enabled by `f_div`: `dz`
/// is 1 exactly on a division row whose divisor is zero.
pub const D_INV: PolyAddress = w(36);
pub const DZ: PolyAddress = w(37);
/// `W[45]`, `W[46]`: the magnitudes `|rem|` and `|divisor|`.
pub const ABS_R: PolyAddress = w(38);
pub const ABS_D: PolyAddress = w(39);
/// `W[47]`, `W[48]`: `|divisor| − |rem| − 1`, corrected by `2^32` on a
/// zero divisor so that it imposes no bound, and its high halfword.
pub const GAP: PolyAddress = w(40);
pub const GAP_HI: PolyAddress = w(41);
/// `W[49]`: the written `rd` value's high halfword.
pub const RD_HI: PolyAddress = w(42);
/// `W[50..54]`: the channels' multiplicities, in channel order — timestamp,
/// range16, generic, decoder — last in the witness subtree
/// (`docs/spec/lookup.md` §7).
pub const MULTIPLICITIES: [PolyAddress; 4] = [w(43), w(44), w(45), w(46)];

/// The decoded table's width, `program::lookup_tuple(MUL_DIV)`:
/// `pc next_pc rs1 rs2 rd extra_mask`, at `S[0..6]`. **Six, not seven**: this
/// family's tuple carries no `imm`.
pub const TABLE_WIDTH: usize = 6;

/// `S[6..9]`: the packed generic table's columns, key first, after the decoded
/// table. A verifying key's commitments for them follow identity's
/// (`docs/spec/shard-proof.md` §7).
pub const GENERIC_TABLE: [PolyAddress; generic_table::WIDTH] = [
    PolyAddress::Setup(TABLE_WIDTH as u32),
    PolyAddress::Setup(TABLE_WIDTH as u32 + 1),
    PolyAddress::Setup(TABLE_WIDTH as u32 + 2),
];

/// The decoded masks a live row of this family can carry: one bit per
/// instruction, in `constants::extra_mask::mul_div` order. `rd = x0` is not a
/// mask of its own — the table's `rd` column says it, and the frame's x0 rule
/// acts on it — so this is the whole legal set, and the table's domain is what
/// enforces it (`docs/spec/lookup.md` §10).
pub const LEGAL_MASKS: [u32; 8] = [
    1 << kind::MUL,
    1 << kind::MULH,
    1 << kind::MULHSU,
    1 << kind::MULHU,
    1 << kind::DIV,
    1 << kind::DIVU,
    1 << kind::REM,
    1 << kind::REMU,
];

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn neg(v: u64) -> Coeff {
    Coeff::Literal(-Fr::from_u64(v))
}

/// `2^bits`, for a `bits` below 64.
fn two_to(bits: u32) -> Fr {
    Fr::from_u64(1u64 << bits)
}

/// `2^(2·bits)`, the square of [`two_to`], which at 32 bits is `2^64`.
fn two_to_double(bits: u32) -> Fr {
    two_to(bits) * two_to(bits)
}

/// `Σ a·x + Σ b·y·z`, constant 0.
fn quadratic(
    linear: Vec<(Coeff, PolyAddress)>,
    products: Vec<(Coeff, PolyAddress, PolyAddress)>,
) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear,
        products,
    }
}

fn linear(terms: Vec<(Coeff, PolyAddress)>) -> GateDef {
    GateDef::Linear {
        terms,
        constant: lit(0),
    }
}

/// `x − x·x`.
fn booleanity(x: PolyAddress) -> GateDef {
    quadratic(vec![(lit(1), x)], vec![(neg(1), x, x)])
}

/// `x` alone, a lookup expression.
fn column(x: PolyAddress) -> GateDef {
    linear(vec![(lit(1), x)])
}

/// `m_q − m_pc·Σ uses`: query `q` is present exactly on a live row whose kind
/// uses it.
fn mask_rule(mask: PolyAddress, uses: &[PolyAddress]) -> GateDef {
    let m_pc = frame(SLOT_PC, FIELD_MASK);
    quadratic(
        vec![(lit(1), mask)],
        uses.iter().map(|u| (neg(1), m_pc, *u)).collect(),
    )
}

/// `m_q·(a_q − decoded)`: a present query's address is the decoded one.
fn addr_rule(slot: usize, decoded: PolyAddress) -> GateDef {
    let m = frame(slot, FIELD_MASK);
    quadratic(
        vec![],
        vec![(lit(1), m, frame(slot, FIELD_ADDR)), (neg(1), m, decoded)],
    )
}

/// `v_q − m_q·v_q`: an absent operand reads 0.
fn value_masked(slot: usize) -> GateDef {
    let (m, v) = (frame(slot, FIELD_MASK), frame(slot, FIELD_READ_VALUE));
    quadratic(vec![(lit(1), v)], vec![(neg(1), m, v)])
}

/// A `RANGE16` obligation under the row's pc mask.
fn range16(name: &str, expression: GateDef) -> LookupExpr {
    LookupExpr {
        name: name.to_string(),
        channel: lookup_channel::RANGE16,
        selector: frame(SLOT_PC, FIELD_MASK),
        tuple: vec![expression],
    }
}

/// The 16+16 pair that bounds `value` to a 32-bit word, under `m_pc`.
fn range32(name: &str, value: PolyAddress, hi: PolyAddress) -> [LookupExpr; 2] {
    [
        range16(&format!("{name}_hi_range"), column(hi)),
        range16(
            &format!("{name}_lo_range"),
            linear(vec![
                (lit(1), value),
                (Coeff::Literal(-Fr::from_u64(1 << 16)), hi),
            ]),
        ),
    ]
}

/// A `U16GetSign` lookup of the packed table: the halfword's top bit.
fn get_sign(name: &str, hi: PolyAddress, bit: PolyAddress) -> LookupExpr {
    LookupExpr {
        name: name.to_string(),
        channel: lookup_channel::GENERIC,
        selector: frame(SLOT_PC, FIELD_MASK),
        tuple: vec![
            GateDef::Linear {
                terms: vec![(lit(1), hi)],
                constant: lit(generic_table::SIGN_BASE as u64),
            },
            column(bit),
            linear(vec![]),
        ],
    }
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The family's arithmetic over a `word_bits`-bit word: every gate whose
/// formula carries the width, plus the two is-zero gadgets and the flags and
/// booleanity the arithmetic reads. The frame plumbing — the query masks,
/// addresses and values, the decoded mask bits and `next_pc` — is not here,
/// having no width.
///
/// [`family_spec`] calls this at [`WORD_BITS`], which is the only width a
/// proof uses. The width is a parameter so that the exhaustive reduced-width
/// check of the division encoding (S18 acceptance 5) evaluates these gates and
/// not a transcription of them. The kind bits' booleanity is not here, being
/// frame plumbing; that check supplies one-hot bits, as a live row's decoder
/// lookup does.
///
/// Panics unless `word_bits` is between 1 and 32: `2^word_bits` is a `u64`
/// only up to 32, and `2^(2·word_bits)` is its square in `Fr`.
pub fn arithmetic_gates(word_bits: u32) -> Vec<(String, GateDef)> {
    assert!(
        (1..=32).contains(&word_bits),
        "the mul/div word is 1 to 32 bits wide, not {word_bits}"
    );
    let v_rs1 = frame(SLOT_RS1, FIELD_READ_VALUE);
    let v_rs2 = frame(SLOT_RS2, FIELD_READ_VALUE);
    let sel = rd_selected(QUERIES.len());
    let word = two_to(word_bits);
    let double = two_to_double(word_bits);
    let mut gates: Vec<(String, GateDef)> = Vec::new();

    // f_div is the is-zero gadgets' enable, so it is a committed column with a
    // booleanity gate; every other flag is a linear form over the kind bits.
    let mut f_div = vec![(lit(1), F_DIV)];
    f_div.extend(DIVS.iter().map(|b| (neg(1), *b)));
    gates.push(("f_div_rule".into(), linear(f_div)));
    gates.push(("f_div_boolean".into(), booleanity(F_DIV)));

    // Each operand's sign adjustment: its top bit where the kind reads it
    // signed, and 0 where it does not.
    for (name, flags, top, s) in [
        ("s1_rule", LHS_SIGNED.as_slice(), RS1_TOP, S1),
        ("s2_rule", RHS_SIGNED.as_slice(), RS2_TOP, S2),
    ] {
        gates.push((
            name.into(),
            quadratic(
                vec![(lit(1), s)],
                flags.iter().map(|b| (neg(1), *b, top)).collect(),
            ),
        ));
    }
    for (name, x) in [
        ("rs1_top_boolean", RS1_TOP),
        ("rs2_top_boolean", RS2_TOP),
        ("s1_boolean", S1),
        ("s2_boolean", S2),
        ("p_sign_boolean", P_SIGN),
        ("q_sign_boolean", Q_SIGN),
        ("r_sign_boolean", R_SIGN),
    ] {
        gates.push((name.into(), booleanity(x)));
    }

    // The one product's multiplicands: the two sign-adjusted operands on a
    // multiply row, the sign-adjusted divisor and quotient on a division one.
    let mut mx = Vec::new();
    let mut my = Vec::new();
    for b in MULS {
        mx.push((neg(1), b, v_rs1));
        mx.push((Coeff::Literal(word), b, S1));
        my.push((neg(1), b, v_rs2));
        my.push((Coeff::Literal(word), b, S2));
    }
    mx.push((neg(1), F_DIV, v_rs2));
    mx.push((Coeff::Literal(word), F_DIV, S2));
    my.push((neg(1), F_DIV, Q));
    my.push((Coeff::Literal(word), F_DIV, Q_SIGN));
    gates.push(("mx_rule".into(), quadratic(vec![(lit(1), MX)], mx)));
    gates.push(("my_rule".into(), quadratic(vec![(lit(1), MY)], my)));

    // ONE product identity, for all four multiplies and the division alike:
    // mx·my = p_low + 2^w·p_high − 2^(2w)·p_sign. Both halves are range
    // checked and p_sign is boolean, so the decomposition is the unique one;
    // the field identity is the integer identity because both sides are ≪ r.
    gates.push((
        "product_rule".into(),
        quadratic(
            vec![
                (neg(1), P_LOW),
                (Coeff::Literal(-word), P_HIGH),
                (Coeff::Literal(double), P_SIGN),
            ],
            vec![(lit(1), MX, MY)],
        ),
    ));

    // The division identity: on a division row the product above is
    // divisor·quotient, so this is divisor·quotient + rem = dividend. It is
    // gated, and must be — ungated it reads rem = dividend on a multiply row
    // whose rs2 is 0, which no non-negative rem satisfies where the dividend
    // is negative, and `mul t0, t1, x0` with a negative t1 would be
    // unprovable (`docs/spec/mul-div.md` §4.3).
    gates.push((
        "division_rule".into(),
        quadratic(
            vec![],
            vec![
                (lit(1), F_DIV, P_LOW),
                (Coeff::Literal(word), F_DIV, P_HIGH),
                (Coeff::Literal(-double), F_DIV, P_SIGN),
                (lit(1), F_DIV, R),
                (Coeff::Literal(-word), F_DIV, R_SIGN),
                (neg(1), F_DIV, v_rs1),
                (Coeff::Literal(word), F_DIV, S1),
            ],
        ),
    ));

    // rem ≠ 0 and divisor = 0, both enabled by f_div so that a multiply row
    // leaves q and r free.
    let [rz_inverse, rz_at_nonzero] = is_zero(&[(lit(1), R)], R_INV, RZ, F_DIV);
    gates.push(("rz_inverse".into(), rz_inverse));
    gates.push(("rz_at_nonzero".into(), rz_at_nonzero));
    let [dz_inverse, dz_at_nonzero] = is_zero(&[(lit(1), v_rs2)], D_INV, DZ, F_DIV);
    gates.push(("dz_inverse".into(), dz_inverse));
    gates.push(("dz_at_nonzero".into(), dz_at_nonzero));

    // (a) rem ≠ 0 ⇒ sign(rem) = sign(dividend), as a definition rather than an
    // implication: r_sign is 1 exactly where the dividend is negative and the
    // remainder is not zero. It is what separates truncated division from
    // floored — without it DIV(−7, 2) takes −4 as readily as −3 — and on an
    // unsigned row, where d1 is 0, it is what forces a non-negative
    // remainder.
    gates.push((
        "d1_rule".into(),
        quadratic(vec![(lit(1), D1)], vec![(neg(1), F_DIV, S1)]),
    ));
    gates.push((
        "r_sign_rule".into(),
        quadratic(vec![(lit(1), R_SIGN), (neg(1), D1)], vec![(lit(1), D1, RZ)]),
    ));

    // (b) |rem| < |divisor|, with the zero-divisor correction inside the gap
    // so that a zero divisor imposes no bound, as it must. |x| is
    // x + 2^w·sign − 2·x·sign, degree 2, and both magnitudes are bounded by
    // their operands' own ranges, so the gap is the whole check.
    for (name, abs, value, sign) in [
        ("abs_r_rule", ABS_R, R, R_SIGN),
        ("abs_d_rule", ABS_D, v_rs2, S2),
    ] {
        gates.push((
            name.into(),
            quadratic(
                vec![
                    (lit(1), abs),
                    (neg(1), value),
                    (Coeff::Literal(-word), sign),
                ],
                vec![(lit(2), value, sign)],
            ),
        ));
    }
    gates.push((
        "gap_rule".into(),
        quadratic(
            vec![(lit(1), GAP), (lit(1), F_DIV), (Coeff::Literal(-word), DZ)],
            vec![(neg(1), F_DIV, ABS_D), (lit(1), F_DIV, ABS_R)],
        ),
    ));

    // Division by zero is pinned to a quotient of all ones; the remainder is
    // the dividend already, the identity's product being zero. The signed
    // overflow −2^(w−1) ÷ −1 needs no pin of its own: |rem| < 1 forces
    // rem = 0, the identity forces the quotient's adjusted value to 2^(w−1),
    // and q's own range forces the word (`docs/spec/mul-div.md` §5.3).
    gates.push((
        "zero_divisor_quotient".into(),
        quadratic(
            vec![(Coeff::Literal(Fr::ONE - word), DZ)],
            vec![(lit(1), DZ, Q)],
        ),
    ));

    // rd is the product's low half, its high half, the quotient or the
    // remainder, selected by sums of committed family bits and never by a
    // bare decoder output.
    let mut rd = vec![(neg(1), MUL, P_LOW)];
    for (bits, source) in [
        (TAKES_HIGH.as_slice(), P_HIGH),
        (TAKES_QUOTIENT.as_slice(), Q),
        (TAKES_REMAINDER.as_slice(), R),
    ] {
        rd.extend(bits.iter().map(|b| (neg(1), *b, source)));
    }
    gates.push(("rd_value_rule".into(), quadratic(vec![(lit(1), sel)], rd)));
    gates
}

/// The family's circuit over `2^trace_vars` rows, `docs/spec/mul-div.md`.
/// `trace_vars` is at least 19, the timestamp channel's width, which the
/// assembly refuses below; a Mercury opening needs it even as well, and at 19
/// or more the generic table's rows fit.
///
/// Panics if the family's frame is not the four queries this file addresses,
/// if any channel's obligation count is not the document's — 8 timestamp, 16
/// `RANGE16`, 2 generic, 1 decoder — if a gate is nonzero on the all-zero
/// padding row, and on every refusal of the assembly.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    assemble(trace_vars, family_spec())
}

/// The family's sub-circuit: its columns, gates, lookups and channels, before
/// the assembly onto the frame.
fn family_spec() -> FamilySpec {
    assert_eq!(
        frame_queries(family::MUL_DIV),
        &QUERIES,
        "mul_div: the family's frame is the four queries this circuit addresses by slot"
    );
    let m_pc = frame(SLOT_PC, FIELD_MASK);
    let pc = frame(SLOT_PC, FIELD_READ_VALUE);
    let next_pc = frame(SLOT_PC, FIELD_WRITE_VALUE);
    let v_rs1 = frame(SLOT_RS1, FIELD_READ_VALUE);
    let v_rs2 = frame(SLOT_RS2, FIELD_READ_VALUE);
    let sel = rd_selected(QUERIES.len());

    let kind_names = [
        "mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu",
    ];
    let mut witness = names(&[
        "decoded_next_pc",
        "decoded_rs1",
        "decoded_rs2",
        "decoded_rd",
        "decoded_mask",
    ]);
    witness.extend(kind_names.iter().map(|k| format!("kind_{k}")));
    witness.extend(names(&[
        "f_div",
        "rs1_hi",
        "rs1_top",
        "rs2_hi",
        "rs2_top",
        "s1",
        "s2",
        "mx",
        "my",
        "p_low",
        "p_low_hi",
        "p_high",
        "p_high_hi",
        "p_sign",
        "q",
        "q_hi",
        "q_sign",
        "r",
        "r_hi",
        "r_sign",
        "r_inv",
        "rz",
        "d1",
        "d_inv",
        "dz",
        "abs_r",
        "abs_d",
        "gap",
        "gap_hi",
        "rd_hi",
    ]));
    witness.extend(
        [
            lookup_channel::TIMESTAMP,
            lookup_channel::RANGE16,
            lookup_channel::GENERIC,
            lookup_channel::DECODER,
        ]
        .iter()
        .map(|c| format!("mult_{}", lookup_channel::NAMES[*c as usize])),
    );
    let setup = names(&[
        "table_pc",
        "table_next_pc",
        "table_rs1",
        "table_rs2",
        "table_rd",
        "table_extra_mask",
        "generic_key",
        "generic_value",
        "generic_result",
    ]);

    let mut enforcing: Vec<(String, GateDef)> = Vec::new();
    for (k, bit) in KINDS.iter().enumerate() {
        enforcing.push((format!("kind_{}_boolean", kind_names[k]), booleanity(*bit)));
    }
    // One degree-1 constraint ties the packed mask to its bits; one-hotness is
    // the decoder table's domain and nothing else (`docs/spec/lookup.md` §10).
    let mut bits: Vec<(Coeff, PolyAddress)> = KINDS
        .iter()
        .enumerate()
        .map(|(k, bit)| (lit(1 << k), *bit))
        .collect();
    bits.push((neg(1), DECODED_MASK));
    enforcing.push(("decoded_mask_bits".into(), linear(bits)));

    // Every one of the eight is R-type: it reads rs1 and rs2 and writes rd.
    enforcing.push((
        "rs1_mask_rule".into(),
        mask_rule(frame(SLOT_RS1, FIELD_MASK), &KINDS),
    ));
    enforcing.push((
        "rs2_mask_rule".into(),
        mask_rule(frame(SLOT_RS2, FIELD_MASK), &KINDS),
    ));
    enforcing.push((
        "rd_mask_rule".into(),
        mask_rule(frame(SLOT_RD, FIELD_MASK), &KINDS),
    ));
    enforcing.push(("rs1_addr_rule".into(), addr_rule(SLOT_RS1, DECODED_RS1)));
    enforcing.push(("rs2_addr_rule".into(), addr_rule(SLOT_RS2, DECODED_RS2)));
    enforcing.push(("rd_addr_rule".into(), addr_rule(SLOT_RD, DECODED_RD)));
    enforcing.push(("rs1_value_masked".into(), value_masked(SLOT_RS1)));
    enforcing.push(("rs2_value_masked".into(), value_masked(SLOT_RS2)));

    // No kind here computes a pc: next_pc is the decoded fall-through, which
    // the decoder lookup binds to the identity-committed table, so it needs
    // neither a wrap bit nor a bound of its own.
    enforcing.push((
        "next_pc_rule".into(),
        linear(vec![(lit(1), next_pc), (neg(1), SEQ)]),
    ));

    enforcing.extend(arithmetic_gates(WORD_BITS));

    let mut lookups = Vec::new();
    lookups.extend(range32("rs1", v_rs1, RS1_HI));
    lookups.extend(range32("rs2", v_rs2, RS2_HI));
    lookups.extend(range32("p_low", P_LOW, P_LOW_HI));
    lookups.extend(range32("p_high", P_HIGH, P_HIGH_HI));
    lookups.extend(range32("q", Q, Q_HI));
    lookups.extend(range32("r", R, R_HI));
    lookups.extend(range32("gap", GAP, GAP_HI));
    lookups.extend(range32("rd", sel, RD_HI));
    lookups.push(get_sign("rs1_get_sign", RS1_HI, RS1_TOP));
    lookups.push(get_sign("rs2_get_sign", RS2_HI, RS2_TOP));

    let mut decode = vec![column(pc)];
    decode.extend(DECODED.iter().map(|x| column(*x)));
    lookups.push(LookupExpr {
        name: "decode_row".into(),
        channel: lookup_channel::DECODER,
        selector: m_pc,
        tuple: decode,
    });

    FamilySpec {
        witness,
        setup,
        virtuals: vec![
            (VirtualKind::Range19, "range19".into()),
            (VirtualKind::Range16, "range16".into()),
        ],
        enforcing,
        lookups,
        channels: channels(),
    }
}

/// `family_spec` over the family's frame at `trace_vars`, held to the checks
/// [`artifact`] documents; a seam so a test can hand it a broken circuit.
fn assemble(trace_vars: u32, family_spec: FamilySpec) -> CircuitArtifact {
    let a = frame_with_channels_artifact(&QUERIES, trace_vars, family_spec);
    // Every obligation is built above and then handed over, so a count is
    // what shows none was dropped on the way (S14 must-be-exact 5, S15's
    // per-channel form).
    for (channel, want) in [
        (lookup_channel::TIMESTAMP, 2 * QUERIES.len()),
        (lookup_channel::RANGE16, 16),
        (lookup_channel::GENERIC, 2),
        (lookup_channel::DECODER, 1),
    ] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(
            got,
            want,
            "mul_div: channel `{}` carries {got} obligations, not {want}",
            lookup_channel::NAMES[channel as usize]
        );
    }
    // A shard's padding rows are all zero, which every gate must accept.
    assert!(
        a.padding.zero_row_valid,
        "mul_div: a gate is nonzero on the all-zero row"
    );
    a
}

/// The family's four channels, in output order: the timestamp gaps over
/// `V[range19]`, the halfwords over `V[range16]`, the two operand signs over
/// the packed generic table at `S[6..9]`, and the decoder over the family's
/// decoded table at `S[0..6]`.
pub fn channels() -> Vec<ChannelSpec> {
    vec![
        ChannelSpec {
            channel: lookup_channel::TIMESTAMP,
            table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
            multiplicity: MULTIPLICITIES[0],
        },
        ChannelSpec {
            channel: lookup_channel::RANGE16,
            table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
            multiplicity: MULTIPLICITIES[1],
        },
        ChannelSpec {
            channel: lookup_channel::GENERIC,
            table: GENERIC_TABLE.to_vec(),
            multiplicity: MULTIPLICITIES[2],
        },
        ChannelSpec {
            channel: lookup_channel::DECODER,
            table: (0..TABLE_WIDTH as u32).map(PolyAddress::Setup).collect(),
            multiplicity: MULTIPLICITIES[3],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The legal masks are eight distinct single bits, one per instruction the
    /// family owns.
    #[test]
    fn the_legal_masks_are_eight_distinct_single_bits() {
        for (i, m) in LEGAL_MASKS.iter().enumerate() {
            assert_eq!(m.count_ones(), 1);
            assert!(LEGAL_MASKS[..i].iter().all(|n| n != m));
        }
    }

    /// The multiplies and the divisions partition the eight kinds.
    #[test]
    fn the_two_halves_partition_the_kinds() {
        let mut all: Vec<PolyAddress> = MULS.to_vec();
        all.extend(DIVS);
        all.sort_by_key(|a| format!("{a}"));
        let mut kinds = KINDS.to_vec();
        kinds.sort_by_key(|a| format!("{a}"));
        assert_eq!(all, kinds);
    }

    /// The arithmetic is built at 1 and 32 bits, and at no other width.
    #[test]
    fn the_word_is_1_to_32_bits() {
        arithmetic_gates(1);
        arithmetic_gates(32);
    }

    #[test]
    #[should_panic(expected = "the mul/div word is 1 to 32 bits wide, not 0")]
    fn a_word_of_no_bits_is_refused() {
        arithmetic_gates(0);
    }

    #[test]
    #[should_panic(expected = "the mul/div word is 1 to 32 bits wide, not 33")]
    fn a_word_of_33_bits_is_refused() {
        arithmetic_gates(33);
    }

    /// The honest family spec assembles, at the lowest height the registry
    /// builds.
    #[test]
    fn the_seam_assembles_the_family() {
        assert_eq!(assemble(19, family_spec()), artifact(19));
    }

    /// An obligation dropped on the way to the assembly is refused by its
    /// channel's count.
    #[test]
    #[should_panic(expected = "channel `range16` carries 15 obligations, not 16")]
    fn a_dropped_obligation_fails_the_build() {
        let mut e = family_spec();
        e.lookups.retain(|l| l.name != "gap_hi_range");
        assemble(20, e);
    }

    /// A gate that is nonzero on the all-zero row is refused: a shard's
    /// padding rows are all zero.
    #[test]
    #[should_panic(expected = "a gate is nonzero on the all-zero row")]
    fn a_gate_nonzero_on_the_zero_row_fails_the_build() {
        let mut e = family_spec();
        e.enforcing.push((
            "q_is_one".into(),
            GateDef::Linear {
                terms: vec![(lit(1), Q)],
                constant: neg(1),
            },
        ));
        assemble(20, e);
    }
}
