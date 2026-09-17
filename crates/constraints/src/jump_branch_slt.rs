//! The `JUMP_BRANCH_SLT` family's circuit: `jal`, `jalr`, the six branches,
//! `slt`, `sltu`, `slti` and `sltiu`.
//!
//! `docs/spec/jump-branch-slt.md` is normative: the columns, the gates, the
//! lookups and the argument. This file is that document as data, assembled by
//! S15's `memory::frame_with_channels_artifact` beside S14's frame, with S17's
//! two gadgets from `crate::gadgets`.
//!
//! ```text
//! frame     M[0..21], W[0..7]: pc rs1 rs2 rd at slots 0..4
//! W[7..13]  the claimed decoded row: next_pc rs1 rs2 rd imm mask
//! W[13..25] the mask's twelve bits, extra_mask::jump_branch_slt order
//! W[25..33] the comparison: cmp_rhs, rs1_hi, rs1_sign, cmp_rhs_hi,
//!           cmp_rhs_sign, lt, cmp_gap, cmp_gap_hi
//! W[33..35] eq, eq_inv
//! W[35..40] taken, jalr_drop, pc_wrap, next_pc_hi, rd_hi
//! W[40..44] one multiplicity per channel: timestamp, range16, generic, decoder
//! S[0..7]   the decoded table, program::lookup_tuple order
//! S[7..10]  the packed generic table, constants::generic_table
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::extra_mask::jump_branch_slt as kind;
use constants::{family, generic_table, lookup_channel};
use field::Fr;

use crate::gadgets::{comparison, is_zero, Comparison};
use crate::lookup::{check_copowers, ChannelSpec};
use crate::memory::{
    frame, frame_queries, frame_with_channels_artifact, rd_selected, Extras, FIELD_ADDR,
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
    PolyAddress::Witness(i)
}

/// `W[7..13]`: the claimed decoded row, `next_pc, rs1, rs2, rd, imm, mask` —
/// `program::lookup_tuple` after `pc`, which the frame's own pc column is.
pub const DECODED: [PolyAddress; 6] = [
    w(FRAME_WITNESS),
    w(FRAME_WITNESS + 1),
    w(FRAME_WITNESS + 2),
    w(FRAME_WITNESS + 3),
    w(FRAME_WITNESS + 4),
    w(FRAME_WITNESS + 5),
];
const SEQ: PolyAddress = DECODED[0];
const DECODED_RS1: PolyAddress = DECODED[1];
const DECODED_RS2: PolyAddress = DECODED[2];
const DECODED_RD: PolyAddress = DECODED[3];
const IMM: PolyAddress = DECODED[4];
const DECODED_MASK: PolyAddress = DECODED[5];

/// `W[13..25]`: the packed mask's bits, bit `k` at index `k` —
/// `constants::extra_mask::jump_branch_slt`'s order: slti, sltiu, slt, sltu,
/// beq, bne, blt, bge, bltu, bgeu, jalr, jal.
pub const KINDS: [PolyAddress; 12] = [
    w(FRAME_WITNESS + 6),
    w(FRAME_WITNESS + 7),
    w(FRAME_WITNESS + 8),
    w(FRAME_WITNESS + 9),
    w(FRAME_WITNESS + 10),
    w(FRAME_WITNESS + 11),
    w(FRAME_WITNESS + 12),
    w(FRAME_WITNESS + 13),
    w(FRAME_WITNESS + 14),
    w(FRAME_WITNESS + 15),
    w(FRAME_WITNESS + 16),
    w(FRAME_WITNESS + 17),
];
const SLTI: PolyAddress = KINDS[kind::SLTI as usize];
const SLTIU: PolyAddress = KINDS[kind::SLTIU as usize];
const SLT: PolyAddress = KINDS[kind::SLT as usize];
const SLTU: PolyAddress = KINDS[kind::SLTU as usize];
const BEQ: PolyAddress = KINDS[kind::BEQ as usize];
const BNE: PolyAddress = KINDS[kind::BNE as usize];
const BLT: PolyAddress = KINDS[kind::BLT as usize];
const BGE: PolyAddress = KINDS[kind::BGE as usize];
const BLTU: PolyAddress = KINDS[kind::BLTU as usize];
const BGEU: PolyAddress = KINDS[kind::BGEU as usize];
const JALR: PolyAddress = KINDS[kind::JALR as usize];
const JAL: PolyAddress = KINDS[kind::JAL as usize];

/// `W[25]`: the comparison's right operand, `rs2 + cmp_imm`, where `cmp_imm`
/// is the immediate on an `slti`/`sltiu` row and 0 on every other.
pub const CMP_RHS: PolyAddress = w(FRAME_WITNESS + 18);
/// `W[26]`, `W[27]`: `rs1`'s high halfword and its sign.
pub const RS1_HI: PolyAddress = w(FRAME_WITNESS + 19);
pub const RS1_SIGN: PolyAddress = w(FRAME_WITNESS + 20);
/// `W[28]`, `W[29]`: `cmp_rhs`'s high halfword and its sign.
pub const CMP_RHS_HI: PolyAddress = w(FRAME_WITNESS + 21);
pub const CMP_RHS_SIGN: PolyAddress = w(FRAME_WITNESS + 22);
/// `W[30]`: 1 exactly when `rs1 < cmp_rhs` in the ordering the row selects.
pub const LT: PolyAddress = w(FRAME_WITNESS + 23);
/// `W[31]`, `W[32]`: the comparison's gap and its high halfword.
pub const CMP_GAP: PolyAddress = w(FRAME_WITNESS + 24);
pub const CMP_GAP_HI: PolyAddress = w(FRAME_WITNESS + 25);
/// `W[33]`, `W[34]`: 1 exactly on a live row where `rs1 = cmp_rhs`, and the
/// inverse of their difference.
pub const EQ: PolyAddress = w(FRAME_WITNESS + 26);
pub const EQ_INV: PolyAddress = w(FRAME_WITNESS + 27);
/// `W[35]`: 1 exactly on a taken branch.
pub const TAKEN: PolyAddress = w(FRAME_WITNESS + 28);
/// `W[36]`: bit 0 of `rs1 + imm` on a `jalr` row, which the target drops.
pub const JALR_DROP: PolyAddress = w(FRAME_WITNESS + 29);
/// `W[37]`: the wrap of whichever sum `next_pc` is.
pub const PC_WRAP: PolyAddress = w(FRAME_WITNESS + 30);
/// `W[38]`: `next_pc`'s high halfword.
pub const NEXT_PC_HI: PolyAddress = w(FRAME_WITNESS + 31);
/// `W[39]`: the written `rd` value's high halfword.
pub const RD_HI: PolyAddress = w(FRAME_WITNESS + 32);
/// `W[40..44]`: the channels' multiplicities, in channel order — timestamp,
/// range16, generic, decoder — last in the witness subtree
/// (`docs/spec/lookup.md` §7).
pub const MULTIPLICITIES: [PolyAddress; 4] = [
    w(FRAME_WITNESS + 33),
    w(FRAME_WITNESS + 34),
    w(FRAME_WITNESS + 35),
    w(FRAME_WITNESS + 36),
];

/// The decoded table's width, `program::lookup_tuple(JUMP_BRANCH_SLT)`:
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
/// instruction, in `constants::extra_mask::jump_branch_slt` order. `rd = x0`
/// is not a mask of its own — the table's `rd` column says it, and the frame's
/// x0 rule acts on it — so this is the whole legal set, and the table's domain
/// is what enforces it (`docs/spec/lookup.md` §10).
pub const LEGAL_MASKS: [u32; 12] = [
    1 << kind::SLTI,
    1 << kind::SLTIU,
    1 << kind::SLT,
    1 << kind::SLTU,
    1 << kind::BEQ,
    1 << kind::BNE,
    1 << kind::BLT,
    1 << kind::BGE,
    1 << kind::BLTU,
    1 << kind::BGEU,
    1 << kind::JALR,
    1 << kind::JAL,
];

/// The kinds that compare signed: `sc`, the signed-compare flag, is their sum.
const SIGNED: [PolyAddress; 4] = [SLTI, SLT, BLT, BGE];

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
fn low_half(x: PolyAddress, hi: PolyAddress) -> GateDef {
    linear(vec![
        (lit(1), x),
        (Coeff::Literal(-Fr::from_u64(1 << 16)), hi),
    ])
}

/// `(x − 2^16·hi)/2`, the low halfword halved: in `[0, 2^16)` only when the
/// low halfword is even, since an odd one halves to `(lo + p)/2`.
fn low_half_halved(x: PolyAddress, hi: PolyAddress) -> GateDef {
    let half = Fr::from_u64(2).inverse().expect("2 is a unit");
    linear(vec![
        (Coeff::Literal(half), x),
        (Coeff::Literal(-Fr::from_u64(1 << 15)), hi),
    ])
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The family's comparison, `rs1 < cmp_rhs`, signed on `slti`, `slt`, `blt`
/// and `bge` rows: `docs/spec/jump-branch-slt.md` §3.2.
fn the_comparison() -> Comparison {
    Comparison {
        prefix: "cmp".into(),
        selector: frame(SLOT_PC, FIELD_MASK),
        signed: SIGNED.to_vec(),
        lhs: frame(SLOT_RS1, FIELD_READ_VALUE),
        lhs_hi: RS1_HI,
        lhs_sign: RS1_SIGN,
        rhs: CMP_RHS,
        rhs_hi: CMP_RHS_HI,
        rhs_sign: CMP_RHS_SIGN,
        lt: LT,
        gap: CMP_GAP,
        gap_hi: CMP_GAP_HI,
    }
}

/// The family's circuit over `2^trace_vars` rows,
/// `docs/spec/jump-branch-slt.md`. `trace_vars` is at least 19, the timestamp
/// channel's width, which the assembly refuses below; a Mercury opening needs
/// it even as well, and at 19 or more the generic table's `2^17 + 1` rows fit.
///
/// Panics if the family's frame is not the four queries this file addresses,
/// if any channel's obligation count is not the document's — 8 timestamp, 11
/// `RANGE16`, 2 generic, 1 decoder — if `next_pc`, which the evenness
/// obligation scales by `1/2`, lacks its direct range check, if a gate is
/// nonzero on the all-zero padding row, and on every refusal of the assembly.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    assert_eq!(
        frame_queries(family::JUMP_BRANCH_SLT),
        &QUERIES,
        "jump_branch_slt: the family's frame is the four queries this circuit addresses by slot"
    );
    let m_pc = frame(SLOT_PC, FIELD_MASK);
    let pc = frame(SLOT_PC, FIELD_READ_VALUE);
    let next_pc = frame(SLOT_PC, FIELD_WRITE_VALUE);
    let v_rs1 = frame(SLOT_RS1, FIELD_READ_VALUE);
    let v_rs2 = frame(SLOT_RS2, FIELD_READ_VALUE);
    let sel = rd_selected(QUERIES.len());

    let kind_names = [
        "slti", "sltiu", "slt", "sltu", "beq", "bne", "blt", "bge", "bltu", "bgeu", "jalr", "jal",
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
        "cmp_rhs",
        "rs1_hi",
        "rs1_sign",
        "cmp_rhs_hi",
        "cmp_rhs_sign",
        "lt",
        "cmp_gap",
        "cmp_gap_hi",
        "eq",
        "eq_inv",
        "taken",
        "jalr_drop",
        "pc_wrap",
        "next_pc_hi",
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

    let branches = [BEQ, BNE, BLT, BGE, BLTU, BGEU];
    let slts = [SLTI, SLTIU, SLT, SLTU];
    let mut rs1_uses = slts.to_vec();
    rs1_uses.extend(branches);
    rs1_uses.push(JALR);
    let mut rs2_uses = vec![SLT, SLTU];
    rs2_uses.extend(branches);
    let mut rd_uses = slts.to_vec();
    rd_uses.extend([JALR, JAL]);
    enforcing.push((
        "rs1_mask_rule".into(),
        mask_rule(frame(SLOT_RS1, FIELD_MASK), &rs1_uses),
    ));
    enforcing.push((
        "rs2_mask_rule".into(),
        mask_rule(frame(SLOT_RS2, FIELD_MASK), &rs2_uses),
    ));
    enforcing.push((
        "rd_mask_rule".into(),
        mask_rule(frame(SLOT_RD, FIELD_MASK), &rd_uses),
    ));
    enforcing.push(("rs1_addr_rule".into(), addr_rule(SLOT_RS1, DECODED_RS1)));
    enforcing.push(("rs2_addr_rule".into(), addr_rule(SLOT_RS2, DECODED_RS2)));
    enforcing.push(("rd_addr_rule".into(), addr_rule(SLOT_RD, DECODED_RD)));
    enforcing.push(("rs1_value_masked".into(), value_masked(SLOT_RS1)));
    enforcing.push(("rs2_value_masked".into(), value_masked(SLOT_RS2)));

    // cmp_rhs = rs2 + (slti + sltiu)·imm: the immediate reaches the
    // comparison on an I-type row alone, whose absent rs2 reads 0, and never
    // on a branch row, whose imm is the displacement.
    enforcing.push((
        "cmp_rhs_rule".into(),
        quadratic(
            vec![(lit(1), CMP_RHS), (neg(1), v_rs2)],
            vec![(neg(1), SLTI, IMM), (neg(1), SLTIU, IMM)],
        ),
    ));
    let cmp = the_comparison();
    let (cmp_gates, cmp_lookups) = comparison(&cmp);
    enforcing.extend(cmp_gates);
    // eq = [rs1 = cmp_rhs] on a live row, 0 on every other.
    let [eq_inverse, eq_at_nonzero] =
        is_zero(&[(lit(1), v_rs1), (neg(1), CMP_RHS)], EQ_INV, EQ, m_pc);
    enforcing.push(("eq_inverse".into(), eq_inverse));
    enforcing.push(("eq_at_nonzero".into(), eq_at_nonzero));

    // taken = (bne + bge + bgeu) + (beq − bne)·eq + (blt + bltu − bge − bgeu)·lt:
    // the branch linear form, each weight triple a sum of kind bits, all zero
    // on a row that is not a branch.
    enforcing.push((
        "taken_rule".into(),
        quadratic(
            vec![
                (lit(1), TAKEN),
                (neg(1), BNE),
                (neg(1), BGE),
                (neg(1), BGEU),
            ],
            vec![
                (neg(1), BEQ, EQ),
                (lit(1), BNE, EQ),
                (neg(1), BLT, LT),
                (neg(1), BLTU, LT),
                (lit(1), BGE, LT),
                (lit(1), BGEU, LT),
            ],
        ),
    ));
    enforcing.push(("taken_boolean".into(), booleanity(TAKEN)));
    enforcing.push(("jalr_drop_boolean".into(), booleanity(JALR_DROP)));
    enforcing.push(("pc_wrap_boolean".into(), booleanity(PC_WRAP)));
    // next_pc + 2^32·pc_wrap = (1 − taken − jal − jalr)·seq
    //                        + (taken + jal)·(pc + imm)
    //                        + jalr·(rs1 + imm − drop)
    // The wrap is ungated and applies to whichever sum the selectors chose;
    // the default arm is the decoded fall-through.
    enforcing.push((
        "next_pc_rule".into(),
        quadratic(
            vec![
                (lit(1), next_pc),
                (Coeff::Literal(two_32()), PC_WRAP),
                (neg(1), SEQ),
            ],
            vec![
                (lit(1), TAKEN, SEQ),
                (lit(1), JAL, SEQ),
                (lit(1), JALR, SEQ),
                (neg(1), TAKEN, pc),
                (neg(1), TAKEN, IMM),
                (neg(1), JAL, pc),
                (neg(1), JAL, IMM),
                (neg(1), JALR, v_rs1),
                (neg(1), JALR, IMM),
                (lit(1), JALR, JALR_DROP),
            ],
        ),
    ));
    // sel = (jal + jalr)·seq + (slti + sltiu + slt + sltu)·lt: the link is the
    // decoded fall-through, and every slt kind writes the one lt the branches
    // read.
    let mut rd_value = vec![(neg(1), JAL, SEQ), (neg(1), JALR, SEQ)];
    rd_value.extend(slts.iter().map(|b| (neg(1), *b, LT)));
    enforcing.push((
        "rd_value_rule".into(),
        quadratic(vec![(lit(1), sel)], rd_value),
    ));

    let mut lookups = cmp_lookups;
    lookups.push(range16("rd_hi_range", column(RD_HI)));
    lookups.push(range16("rd_lo_range", low_half(sel, RD_HI)));
    lookups.push(range16("next_pc_hi_range", column(NEXT_PC_HI)));
    lookups.push(range16("next_pc_lo_range", low_half(next_pc, NEXT_PC_HI)));
    lookups.push(range16(
        "next_pc_even",
        low_half_halved(next_pc, NEXT_PC_HI),
    ));
    let mut decode = vec![column(pc)];
    decode.extend(DECODED.iter().map(|x| column(*x)));
    lookups.push(LookupExpr {
        name: "decode_row".into(),
        channel: lookup_channel::DECODER,
        selector: m_pc,
        tuple: decode,
    });

    let a = frame_with_channels_artifact(
        &QUERIES,
        trace_vars,
        Extras {
            witness,
            setup,
            virtuals: vec![
                (VirtualKind::Range19, "range19".into()),
                (VirtualKind::Range16, "range16".into()),
            ],
            enforcing,
            lookups,
            channels: channels(),
        },
    );
    // Every obligation is built above and then handed over, so a count is
    // what shows none was dropped on the way (S14 must-be-exact 5, S15's
    // per-channel form).
    for (channel, want) in [
        (lookup_channel::TIMESTAMP, 2 * QUERIES.len()),
        (lookup_channel::RANGE16, 11),
        (lookup_channel::GENERIC, 2),
        (lookup_channel::DECODER, 1),
    ] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(
            got,
            want,
            "jump_branch_slt: channel `{}` carries {got} obligations, not {want}",
            lookup_channel::NAMES[channel as usize]
        );
    }
    // The evenness obligation scales next_pc's low halfword by 1/2, which
    // bounds nothing unless next_pc is bounded directly too.
    if let Err(e) = check_copowers(&a, &[next_pc]) {
        panic!("jump_branch_slt: {e}");
    }
    // A shard's padding rows are all zero, which every gate must accept.
    assert!(
        a.padding.zero_row_valid,
        "jump_branch_slt: a gate is nonzero on the all-zero row"
    );
    a
}

/// The family's four channels, in output order: the timestamp gaps over
/// `V[range19]`, the halfwords over `V[range16]`, the two signs over the
/// packed generic table at `S[7..10]`, and the decoder over the family's
/// decoded table at `S[0..7]`.
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
}
