//! The `SHIFT_BITWISE` family's circuit: the six shifts — `sll`, `slli`,
//! `srl`, `srli`, `sra`, `srai` — and the six bitwise operations — `and`,
//! `andi`, `or`, `ori`, `xor`, `xori`.
//!
//! `docs/spec/shift-bitwise.md` is normative: the columns, the gates, the
//! lookups and the argument. This file is that document as data, assembled by
//! S15's `memory::frame_with_channels_artifact` beside S14's frame.
//!
//! ```text
//! frame     M[0..21], W[0..7]: pc rs1 rs2 rd at slots 0..4
//! W[7..13]  the claimed decoded row: next_pc rs1 rs2 rd imm mask
//! W[13..25] the mask's twelve bits, extra_mask::shift_bitwise order
//! W[25..27] f_shift, f_bitwise: the two halves, each a lookup selector
//! W[27..30] rs1_hi, rs1_sign, src2_hi
//! W[30..35] amount, pow, copow, high, high_hi: the truncated shift amount
//! W[35..44] se, shift_in, shift_prod, ovf, ovf_hi, residue, residue_hi,
//!           scaled, scaled_hi: the one product both shift directions share
//! W[44..56] a0..a3, b0..b3, and0..and3: the bytes and their AND
//! W[56]     rd_hi
//! W[57..61] one multiplicity per channel: timestamp, range16, generic, decoder
//!
//! Every generic key is bounded before it is looked up: the packed table holds
//! three sub-tables in one channel, so an unbounded key does not miss the
//! table, it reads another sub-table's row (`docs/spec/shift-bitwise.md` §3.3).
//! S[0..7]   the decoded table, program::lookup_tuple order
//! S[7..10]  the packed generic table, constants::generic_table
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::extra_mask::shift_bitwise as kind;
use constants::{family, generic_table, lookup_channel};
use field::Fr;

use crate::lookup::{check_copowers, ChannelSpec};
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

const fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(FRAME_WITNESS + i)
}

/// `W[7..13]`: the claimed decoded row, `next_pc, rs1, rs2, rd, imm, mask` —
/// `program::lookup_tuple` after `pc`, which the frame's own pc column is.
pub const DECODED: [PolyAddress; 6] = [w(0), w(1), w(2), w(3), w(4), w(5)];
const SEQ: PolyAddress = DECODED[0];
const DECODED_RS1: PolyAddress = DECODED[1];
const DECODED_RS2: PolyAddress = DECODED[2];
const DECODED_RD: PolyAddress = DECODED[3];
const IMM: PolyAddress = DECODED[4];
const DECODED_MASK: PolyAddress = DECODED[5];

/// `W[13..25]`: the packed mask's bits, bit `k` at index `k` —
/// `constants::extra_mask::shift_bitwise`'s order: slli, xori, srli, srai,
/// ori, andi, sll, xor, srl, sra, or, and.
pub const KINDS: [PolyAddress; 12] = [
    w(6),
    w(7),
    w(8),
    w(9),
    w(10),
    w(11),
    w(12),
    w(13),
    w(14),
    w(15),
    w(16),
    w(17),
];
const SLLI: PolyAddress = KINDS[kind::SLLI as usize];
const XORI: PolyAddress = KINDS[kind::XORI as usize];
const SRLI: PolyAddress = KINDS[kind::SRLI as usize];
const SRAI: PolyAddress = KINDS[kind::SRAI as usize];
const ORI: PolyAddress = KINDS[kind::ORI as usize];
const ANDI: PolyAddress = KINDS[kind::ANDI as usize];
const SLL: PolyAddress = KINDS[kind::SLL as usize];
const XOR: PolyAddress = KINDS[kind::XOR as usize];
const SRL: PolyAddress = KINDS[kind::SRL as usize];
const SRA: PolyAddress = KINDS[kind::SRA as usize];
const OR: PolyAddress = KINDS[kind::OR as usize];
const AND: PolyAddress = KINDS[kind::AND as usize];

/// The six shift kinds, whose sum is [`F_SHIFT`].
const SHIFTS: [PolyAddress; 6] = [SLLI, SRLI, SRAI, SLL, SRL, SRA];
/// The six bitwise kinds, whose sum is [`F_BITWISE`].
const BITWISE: [PolyAddress; 6] = [XORI, ORI, ANDI, XOR, OR, AND];
/// The two left shifts.
const LEFT: [PolyAddress; 2] = [SLLI, SLL];
/// The four right shifts.
const RIGHT: [PolyAddress; 4] = [SRLI, SRAI, SRL, SRA];
/// The two arithmetic right shifts, the only kinds whose `se` can be 1.
const ARITHMETIC: [PolyAddress; 2] = [SRAI, SRA];
/// The kinds that read `rs2`: the R-type half of each group.
const READS_RS2: [PolyAddress; 6] = [SLL, SRL, SRA, AND, OR, XOR];

/// `W[25]`: 1 exactly on a live shift row. A lookup selector, so it carries a
/// booleanity gate of its own.
pub const F_SHIFT: PolyAddress = w(18);
/// `W[26]`: 1 exactly on a live bitwise row. Likewise a lookup selector.
pub const F_BITWISE: PolyAddress = w(19);
/// `W[27]`, `W[28]`: `rs1`'s high halfword and its sign, the sign from
/// `U16GetSign` over the halfword.
pub const RS1_HI: PolyAddress = w(20);
pub const RS1_SIGN: PolyAddress = w(21);
/// `W[29]`: the high halfword of the second operand `rs2 + imm`, which bounds
/// that sum to a 32-bit word on every live row.
pub const SRC2_HI: PolyAddress = w(22);
/// `W[30]`: the truncated shift amount, bounded to `[0, 32)` by `ShiftPowers`'
/// domain and by nothing else.
pub const AMOUNT: PolyAddress = w(23);
/// `W[31]`, `W[32]`: `2^amount` and `2^(31 − amount)`, the `ShiftPowers` row
/// `amount` keys.
pub const POW: PolyAddress = w(24);
pub const COPOW: PolyAddress = w(25);
/// `W[33]`, `W[34]`: the second operand's bits above the amount,
/// `(rs2 + imm) >> 5`, and its high halfword.
pub const HIGH: PolyAddress = w(26);
pub const HIGH_HI: PolyAddress = w(27);
/// `W[35]`: the sign-extension term, `is_arithmetic·rs1_sign` — committed so
/// that the line it appears on stays degree 2.
pub const SE: PolyAddress = w(28);
/// `W[36]`, `W[37]`: the one product both directions share — `rs1` on a left
/// shift, the sign-adjusted result on a right one — and `shift_in·pow`.
pub const SHIFT_IN: PolyAddress = w(29);
pub const SHIFT_PROD: PolyAddress = w(30);
/// `W[38]`, `W[39]`: a left shift's discarded high bits, and their high
/// halfword.
pub const OVF: PolyAddress = w(31);
pub const OVF_HI: PolyAddress = w(32);
/// `W[40]`, `W[41]`: a right shift's discarded low bits, and their high
/// halfword. The direct bound the copower pattern needs.
pub const RESIDUE: PolyAddress = w(33);
pub const RESIDUE_HI: PolyAddress = w(34);
/// `W[42]`, `W[43]`: `residue·2^(32 − amount)`, and its high halfword. Bounded
/// to `[0, 2^32)`, which is what says `residue < 2^amount`.
pub const SCALED: PolyAddress = w(35);
pub const SCALED_HI: PolyAddress = w(36);
/// `W[44..48]`: `rs1`'s four bytes, low first.
pub const BYTES_A: [PolyAddress; 4] = [w(37), w(38), w(39), w(40)];
/// `W[48..52]`: the second operand's four bytes, low first.
pub const BYTES_B: [PolyAddress; 4] = [w(41), w(42), w(43), w(44)];
/// `W[52..56]`: the two operands' bytewise AND, from the byte table.
pub const BYTES_AND: [PolyAddress; 4] = [w(45), w(46), w(47), w(48)];
/// `W[56]`: the written `rd` value's high halfword.
pub const RD_HI: PolyAddress = w(49);
/// `W[57..61]`: the channels' multiplicities, in channel order — timestamp,
/// range16, generic, decoder — last in the witness subtree
/// (`docs/spec/lookup.md` §7).
pub const MULTIPLICITIES: [PolyAddress; 4] = [w(50), w(51), w(52), w(53)];

/// The decoded table's width, `program::lookup_tuple(SHIFT_BITWISE)`:
/// `pc next_pc rs1 rs2 rd imm extra_mask`, at `S[0..7]`.
pub const TABLE_WIDTH: usize = 7;

/// `S[7..10]`: the packed generic table's columns, key first, after the
/// decoded table. A verifying key's commitments for them follow identity's
/// (`docs/spec/shard-proof.md` §7).
pub const GENERIC_TABLE: [PolyAddress; generic_table::WIDTH] = [
    PolyAddress::Setup(TABLE_WIDTH as u32),
    PolyAddress::Setup(TABLE_WIDTH as u32 + 1),
    PolyAddress::Setup(TABLE_WIDTH as u32 + 2),
];

/// The decoded masks a live row of this family can carry: one bit per
/// instruction, in `constants::extra_mask::shift_bitwise` order. `rd = x0` is
/// not a mask of its own — the table's `rd` column says it, and the frame's x0
/// rule acts on it — so this is the whole legal set, and the table's domain is
/// what enforces it (`docs/spec/lookup.md` §10).
pub const LEGAL_MASKS: [u32; 12] = [
    1 << kind::SLLI,
    1 << kind::XORI,
    1 << kind::SRLI,
    1 << kind::SRAI,
    1 << kind::ORI,
    1 << kind::ANDI,
    1 << kind::SLL,
    1 << kind::XOR,
    1 << kind::SRL,
    1 << kind::SRA,
    1 << kind::OR,
    1 << kind::AND,
];

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn neg(v: u64) -> Coeff {
    Coeff::Literal(-Fr::from_u64(v))
}

fn two_32() -> Fr {
    Fr::from_u64(1 << 32)
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

/// `flag − Σ bits`: a committed column equal to a sum of kind bits, so that a
/// lookup can select on it and a gate can multiply by it.
fn flag_rule(flag: PolyAddress, bits: &[PolyAddress]) -> GateDef {
    let mut terms = vec![(lit(1), flag)];
    terms.extend(bits.iter().map(|b| (neg(1), *b)));
    linear(terms)
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

/// `x − 2^16·hi`, the low halfword of a value bounded by the range convention
/// of `docs/spec/memory.md` §7.
fn low_half(terms: Vec<(Coeff, PolyAddress)>, hi: PolyAddress) -> GateDef {
    let mut terms = terms;
    terms.push((Coeff::Literal(-Fr::from_u64(1 << 16)), hi));
    linear(terms)
}

/// The 16+16 pair that bounds `value` to a 32-bit word, under `m_pc`:
/// `<name>_hi_range` on the high chunk and `<name>_lo_range` on the remainder.
fn range32(name: &str, value: Vec<(Coeff, PolyAddress)>, hi: PolyAddress) -> [LookupExpr; 2] {
    [
        range16(&format!("{name}_hi_range"), column(hi)),
        range16(&format!("{name}_lo_range"), low_half(value, hi)),
    ]
}

/// The two obligations that bound a generic-channel key to `[0, 2^bits)` with
/// `bits` below 16, under `selector`: the direct halfword check, and the same
/// column scaled by `2^(16 − bits)`, which is in range only below `2^bits`.
///
/// **Every key a family looks up must be bounded** (`docs/spec/lookup.md` §4).
/// The packed generic table holds three sub-tables in one channel, so a key
/// outside its own sub-table's range does not miss the table — it lands on
/// another sub-table's row, and the lookup holds while the row means something
/// else entirely. The direct check is the other half of the pair: a scaled
/// bound alone admits `k·2^(bits − 16)` for a small `k`, which is not a small
/// integer at all (S15's copower rule, `lookup::check_copowers`).
fn key_bound(name: &str, x: PolyAddress, bits: u32, selector: PolyAddress) -> [LookupExpr; 2] {
    let scale = 1u64 << (16 - bits);
    let range = |name: String, tuple: GateDef| LookupExpr {
        name,
        channel: lookup_channel::RANGE16,
        selector,
        tuple: vec![tuple],
    };
    [
        range(format!("{name}_range"), column(x)),
        range(format!("{name}_scaled"), linear(vec![(lit(scale), x)])),
    ]
}

/// A `GENERIC` lookup of the packed table, `(key + base, value, result)` under
/// `selector`. `docs/spec/lookup.md` §4 adds the `+ 1` that keeps a real entry
/// off the `ZeroEntry`.
fn generic(
    name: &str,
    selector: PolyAddress,
    base: u32,
    key: PolyAddress,
    value: GateDef,
    result: GateDef,
) -> LookupExpr {
    LookupExpr {
        name: name.to_string(),
        channel: lookup_channel::GENERIC,
        selector,
        tuple: vec![
            GateDef::Linear {
                terms: vec![(lit(1), key)],
                constant: lit(base as u64),
            },
            value,
            result,
        ],
    }
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The second operand every kind of this family takes: `rs2 + imm`. An I-type
/// row's absent `rs2` reads 0 and an R-type row's `imm` is 0, so one
/// expression is the shift amount's source and the bitwise right operand
/// alike, and the immediate never enters the permutation-tied `rs2` column.
fn src2() -> Vec<(Coeff, PolyAddress)> {
    vec![(lit(1), frame(SLOT_RS2, FIELD_READ_VALUE)), (lit(1), IMM)]
}

/// The family's circuit over `2^trace_vars` rows,
/// `docs/spec/shift-bitwise.md`. `trace_vars` is at least 19, the timestamp
/// channel's width, which the assembly refuses below; a Mercury opening needs
/// it even as well, and at 19 or more the generic table's rows fit.
///
/// Panics if the family's frame is not the four queries this file addresses,
/// if any channel's obligation count is not the document's — 8 timestamp, 24
/// `RANGE16`, 6 generic, 1 decoder — if any column this circuit bounds by
/// scaling lacks its own direct range check under the same selector, if a gate
/// is nonzero on the all-zero padding row, and on every refusal of the
/// assembly.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    assemble(trace_vars, family_spec())
}

/// The family's sub-circuit: its columns, gates, lookups and channels, before
/// the assembly onto the frame.
fn family_spec() -> FamilySpec {
    assert_eq!(
        frame_queries(family::SHIFT_BITWISE),
        &QUERIES,
        "shift_bitwise: the family's frame is the four queries this circuit addresses by slot"
    );
    let m_pc = frame(SLOT_PC, FIELD_MASK);
    let pc = frame(SLOT_PC, FIELD_READ_VALUE);
    let next_pc = frame(SLOT_PC, FIELD_WRITE_VALUE);
    let v_rs1 = frame(SLOT_RS1, FIELD_READ_VALUE);
    let sel = rd_selected(QUERIES.len());

    let kind_names = [
        "slli", "xori", "srli", "srai", "ori", "andi", "sll", "xor", "srl", "sra", "or", "and",
    ];
    let mut witness = names(&[
        "decoded_next_pc",
        "decoded_rs1",
        "decoded_rs2",
        "decoded_rd",
        "decoded_imm",
        "decoded_mask",
    ]);
    witness.extend(kind_names.iter().map(|k| format!("kind_{k}")));
    witness.extend(names(&[
        "f_shift",
        "f_bitwise",
        "rs1_hi",
        "rs1_sign",
        "src2_hi",
        "amount",
        "pow",
        "copow",
        "high",
        "high_hi",
        "se",
        "shift_in",
        "shift_prod",
        "ovf",
        "ovf_hi",
        "residue",
        "residue_hi",
        "scaled",
        "scaled_hi",
        "byte_a0",
        "byte_a1",
        "byte_a2",
        "byte_a3",
        "byte_b0",
        "byte_b1",
        "byte_b2",
        "byte_b3",
        "byte_and0",
        "byte_and1",
        "byte_and2",
        "byte_and3",
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
        "table_imm",
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

    // The two halves. Each is a lookup selector, so each carries the
    // booleanity gate `validate` refuses a selector without.
    enforcing.push(("f_shift_rule".into(), flag_rule(F_SHIFT, &SHIFTS)));
    enforcing.push(("f_shift_boolean".into(), booleanity(F_SHIFT)));
    enforcing.push(("f_bitwise_rule".into(), flag_rule(F_BITWISE, &BITWISE)));
    enforcing.push(("f_bitwise_boolean".into(), booleanity(F_BITWISE)));

    // Every kind reads rs1 and writes rd; only the R-type half reads rs2.
    enforcing.push((
        "rs1_mask_rule".into(),
        mask_rule(frame(SLOT_RS1, FIELD_MASK), &KINDS),
    ));
    enforcing.push((
        "rs2_mask_rule".into(),
        mask_rule(frame(SLOT_RS2, FIELD_MASK), &READS_RS2),
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

    // rs2 + imm = 32·high + amount. `amount` is bounded to [0, 32) by
    // ShiftPowers' domain and `high` by its own range pair, so the split is
    // the unique one and `amount` really is the low five bits: never leave the
    // shamt free, or `sll` with rs2 = 4 shifts by 8.
    let mut split = src2();
    split.push((neg(32), HIGH));
    split.push((neg(1), AMOUNT));
    enforcing.push(("amount_split".into(), linear(split)));

    // pow·copow = 2^31 on a shift row, and 0 on every other. The lookup
    // already says it; this says it again from the circuit's side, so a
    // ShiftPowers row generated wrong stops the honest prover here rather than
    // licensing a residue bound that is not one.
    enforcing.push((
        "copower_rule".into(),
        quadratic(
            vec![(
                Coeff::Literal(-Fr::from_u64(1 << generic_table::SHIFT_COPOWER_BITS)),
                F_SHIFT,
            )],
            vec![(lit(1), POW, COPOW)],
        ),
    ));

    // se = is_arithmetic·rs1_sign: 0 for every logical shift and every bitwise
    // row, and rs1's sign bit on `sra`/`srai`. Committing it is what keeps the
    // two lines that read it degree 2.
    enforcing.push((
        "se_rule".into(),
        quadratic(
            vec![(lit(1), SE)],
            ARITHMETIC.iter().map(|b| (neg(1), *b, RS1_SIGN)).collect(),
        ),
    ));

    // Every boolean this family produces carries its booleanity: rs1's sign
    // bit, and `se`, its sign-weighted form. `se_boolean` is implied by
    // `se_rule` over a boolean `rs1_sign` and one-hot kind bits; it is written
    // anyway, because S18 must-be-exact 5 asks for a sign bit's
    // sign-weighted form to carry one and a reader should not have to derive
    // it.
    enforcing.push(("rs1_sign_boolean".into(), booleanity(RS1_SIGN)));
    enforcing.push(("se_boolean".into(), booleanity(SE)));

    // shift_in = rs1 on a left shift, rd − 2^32·se on a right one, 0
    // elsewhere; shift_prod = shift_in·pow. One product serves both
    // directions.
    let mut shift_in_products = Vec::new();
    for b in LEFT {
        shift_in_products.push((neg(1), b, v_rs1));
    }
    for b in RIGHT {
        shift_in_products.push((neg(1), b, sel));
        shift_in_products.push((Coeff::Literal(two_32()), b, SE));
    }
    enforcing.push((
        "shift_in_rule".into(),
        quadratic(vec![(lit(1), SHIFT_IN)], shift_in_products),
    ));
    enforcing.push((
        "shift_prod_rule".into(),
        quadratic(vec![(lit(1), SHIFT_PROD)], vec![(neg(1), SHIFT_IN, POW)]),
    ));

    // A left shift:  rs1·2^s = rd + 2^32·ovf.
    // A right shift: rs1 − 2^32·se = (rd − 2^32·se)·2^s + residue.
    // Both read the one shift_prod; both arms are zero on a bitwise row.
    let mut out = Vec::new();
    for b in LEFT {
        out.push((lit(1), b, SHIFT_PROD));
        out.push((neg(1), b, sel));
        out.push((Coeff::Literal(-two_32()), b, OVF));
    }
    for b in RIGHT {
        out.push((lit(1), b, SHIFT_PROD));
        out.push((lit(1), b, RESIDUE));
        out.push((neg(1), b, v_rs1));
        out.push((Coeff::Literal(two_32()), b, SE));
    }
    enforcing.push(("shift_out_rule".into(), quadratic(vec![], out)));

    // scaled = residue·2^(32 − s), the copower half of the residue bound. The
    // table stores half of 2^(32 − s), so the coefficient is 2.
    enforcing.push((
        "scaled_rule".into(),
        quadratic(vec![(lit(1), SCALED)], vec![(neg(2), RESIDUE, COPOW)]),
    ));

    // Both operands as four bytes each, low first. Ungated and degree 1: on a
    // shift row the bytes carry no table lookup, so the decomposition is free
    // and satisfiable; on a bitwise row the byte table's domain bounds each of
    // them and the decomposition is the unique one.
    let byte_weights = [1u64, 1 << 8, 1 << 16, 1 << 24];
    let mut rs1_bytes = vec![(lit(1), v_rs1)];
    let mut src2_bytes = src2();
    for (j, weight) in byte_weights.iter().enumerate() {
        rs1_bytes.push((neg(*weight), BYTES_A[j]));
        src2_bytes.push((neg(*weight), BYTES_B[j]));
    }
    enforcing.push(("rs1_bytes".into(), linear(rs1_bytes)));
    enforcing.push(("src2_bytes".into(), linear(src2_bytes)));

    // rd = t1·(rs1 + rs2 + imm) + t2·Σ 2^(8j)·and_j, with
    // t1 = or + ori + xor + xori and t2 = (and + andi) − (or + ori)
    // − 2·(xor + xori): AND is the accumulator alone, OR is a + b − and and
    // XOR is a + b − 2·and, summed over the four bytes by linearity. The rd
    // term is gated by the family bit, not by the bracket: the op selectors
    // are zero on a shift row, and a bare rd would force rd = 0 there.
    let mut bitwise = vec![(lit(1), F_BITWISE, sel)];
    for b in [OR, ORI, XOR, XORI] {
        // `−t1·(rs1 + rs2 + imm)`, in `src2`'s own order then `rs1`.
        for x in [frame(SLOT_RS2, FIELD_READ_VALUE), IMM, v_rs1] {
            bitwise.push((neg(1), b, x));
        }
    }
    for (j, weight) in byte_weights.iter().enumerate() {
        for b in [AND, ANDI] {
            bitwise.push((neg(*weight), b, BYTES_AND[j]));
        }
        for b in [OR, ORI] {
            bitwise.push((lit(*weight), b, BYTES_AND[j]));
        }
        for b in [XOR, XORI] {
            bitwise.push((lit(2 * *weight), b, BYTES_AND[j]));
        }
    }
    enforcing.push(("bitwise_out_rule".into(), quadratic(vec![], bitwise)));

    let mut lookups = Vec::new();
    lookups.extend(range32("rs1", vec![(lit(1), v_rs1)], RS1_HI));
    lookups.extend(range32("src2", src2(), SRC2_HI));
    lookups.extend(range32("high", vec![(lit(1), HIGH)], HIGH_HI));
    lookups.extend(range32("ovf", vec![(lit(1), OVF)], OVF_HI));
    lookups.extend(range32("residue", vec![(lit(1), RESIDUE)], RESIDUE_HI));
    lookups.extend(range32("scaled", vec![(lit(1), SCALED)], SCALED_HI));
    lookups.extend(range32("rd", vec![(lit(1), sel)], RD_HI));

    // Every generic key this family looks up is bounded to its own sub-table's
    // range before it is looked up: `rs1_hi` by the range pair above, the
    // shift amount to `[0, 32)` and each of `rs1`'s bytes to `[0, 256)` here.
    // Without them a key lands on another sub-table's row — a byte of 65,823
    // reads `ShiftPowers` row 31 and proves `a & b = 1` where it is 0.
    lookups.extend(key_bound("amount", AMOUNT, 5, F_SHIFT));
    for (j, byte) in BYTES_A.iter().enumerate() {
        lookups.extend(key_bound(&format!("byte_a{j}"), *byte, 8, F_BITWISE));
    }

    lookups.push(generic(
        "rs1_get_sign",
        m_pc,
        generic_table::SIGN_BASE,
        RS1_HI,
        column(RS1_SIGN),
        linear(vec![]),
    ));
    lookups.push(generic(
        "shift_powers",
        F_SHIFT,
        generic_table::SHIFT_BASE,
        AMOUNT,
        column(POW),
        column(COPOW),
    ));
    for j in 0..4 {
        lookups.push(generic(
            &format!("and_byte_{j}"),
            F_BITWISE,
            generic_table::AND_BASE,
            BYTES_A[j],
            column(BYTES_B[j]),
            column(BYTES_AND[j]),
        ));
    }

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
        (lookup_channel::RANGE16, 24),
        (lookup_channel::GENERIC, 6),
        (lookup_channel::DECODER, 1),
    ] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(
            got,
            want,
            "shift_bitwise: channel `{}` carries {got} obligations, not {want}",
            lookup_channel::NAMES[channel as usize]
        );
    }
    // Every column this circuit bounds by scaling needs its own direct check
    // under the same selector: `residue`, whose scale is the looked-up
    // copower, and the four byte keys and the shift amount, whose scales are
    // literals.
    let mut scaled = vec![(RESIDUE, frame(SLOT_PC, FIELD_MASK)), (AMOUNT, F_SHIFT)];
    scaled.extend(BYTES_A.iter().map(|x| (*x, F_BITWISE)));
    if let Err(e) = check_copowers(&a, &scaled) {
        panic!("shift_bitwise: {e}");
    }
    // A shard's padding rows are all zero, which every gate must accept.
    assert!(
        a.padding.zero_row_valid,
        "shift_bitwise: a gate is nonzero on the all-zero row"
    );
    a
}

/// The family's four channels, in output order: the timestamp gaps over
/// `V[range19]`, the halfwords over `V[range16]`, the sign, the shift powers
/// and the four AND bytes over the packed generic table at `S[7..10]`, and the
/// decoder over the family's decoded table at `S[0..7]`.
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

    /// The legal masks are twelve distinct single bits, one per instruction the
    /// family owns.
    #[test]
    fn the_legal_masks_are_twelve_distinct_single_bits() {
        for (i, m) in LEGAL_MASKS.iter().enumerate() {
            assert_eq!(m.count_ones(), 1);
            assert!(LEGAL_MASKS[..i].iter().all(|n| n != m));
        }
    }

    /// The two halves partition the twelve kinds.
    #[test]
    fn the_two_halves_partition_the_kinds() {
        let mut all: Vec<PolyAddress> = SHIFTS.to_vec();
        all.extend(BITWISE);
        all.sort_by_key(|a| format!("{a}"));
        let mut kinds = KINDS.to_vec();
        kinds.sort_by_key(|a| format!("{a}"));
        assert_eq!(all, kinds);
        let mut directions: Vec<PolyAddress> = LEFT.to_vec();
        directions.extend(RIGHT);
        directions.sort_by_key(|a| format!("{a}"));
        let mut shifts = SHIFTS.to_vec();
        shifts.sort_by_key(|a| format!("{a}"));
        assert_eq!(directions, shifts);
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
    #[should_panic(expected = "channel `generic` carries 5 obligations, not 6")]
    fn a_dropped_obligation_fails_the_build() {
        let mut e = family_spec();
        e.lookups.retain(|l| l.name != "and_byte_2");
        assemble(20, e);
    }

    /// `residue`'s own range check moved under a narrower selector than the
    /// scaled obligation's: the count holds, and the copower check refuses it.
    #[test]
    #[should_panic(expected = "copower pairing")]
    fn a_residue_bound_under_a_narrower_selector_fails_the_build() {
        let mut e = family_spec();
        for l in e.lookups.iter_mut() {
            if l.name == "residue_hi_range" || l.name == "residue_lo_range" {
                l.selector = F_SHIFT;
            }
        }
        assemble(20, e);
    }

    /// A gate that is nonzero on the all-zero row is refused: a shard's
    /// padding rows are all zero.
    #[test]
    #[should_panic(expected = "a gate is nonzero on the all-zero row")]
    fn a_gate_nonzero_on_the_zero_row_fails_the_build() {
        let mut e = family_spec();
        e.enforcing.push((
            "amount_is_one".into(),
            GateDef::Linear {
                terms: vec![(lit(1), AMOUNT)],
                constant: neg(1),
            },
        ));
        assemble(20, e);
    }
}
