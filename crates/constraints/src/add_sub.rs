//! The `ADD_SUB_LUI_AUIPC` family's circuit: `add`, `sub`, `addi`, `lui`,
//! `auipc`, and the system row kind with its two provable ecalls, `exit` and
//! the keccak-f delegation request of `docs/spec/delegation.md` §5.
//!
//! `docs/spec/shard-proof.md` §8 is normative: the columns, the gates, the
//! lookups and the argument. This file is that section as data, assembled by
//! S15's `memory::frame_with_channels_artifact` beside S14's frame.
//!
//! ```text
//! frame     M[0..41], W[0..11]: pc rs1 rs2 arg1 arg2 ram rd deleg at slots 0..8
//! W[11..17] the claimed decoded row: next_pc rs1 rs2 rd imm mask
//! W[17..23] the mask's six bits; W[23], W[24] is_ecall, is_fence
//! W[25]     is_keccak: the delegation request selector
//! W[26..30] wrap, rd_hi, pc_wrap, next_pc_hi
//! W[30..33] one multiplicity per channel: timestamp, range16, decoder
//! S[0..7]   the decoded table, program::lookup_tuple order
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::extra_mask::add_sub_lui_auipc as kind;
use constants::extra_mask::system_code;
use constants::{family, lookup_channel, memory as mem};
use field::Fr;

use crate::lookup::ChannelSpec;
use crate::memory::{
    frame, frame_queries, frame_with_channels_artifact, rd_selected, FamilySpec, ARG1, ARG2, DELEG,
    FIELD_ADDR, FIELD_MASK, FIELD_READ_TS, FIELD_READ_VALUE, FIELD_WRITE_VALUE, PC, RAM, RD, RS1,
    RS2,
};
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

/// The family's queries, in slot order: its frame is `memory::frame_queries`'
/// list, and this file addresses its columns by these slots.
const QUERIES: [usize; 8] = [PC, RS1, RS2, ARG1, ARG2, RAM, RD, DELEG];
const SLOT_PC: usize = 0;
const SLOT_RS1: usize = 1;
const SLOT_RS2: usize = 2;
const SLOT_ARG1: usize = 3;
const SLOT_ARG2: usize = 4;
const SLOT_RAM: usize = 5;
const SLOT_RD: usize = 6;
const SLOT_DELEG: usize = 7;

/// The frame's own witness columns: eight gap chunks, then the x0 gadget's
/// three. Everything this file adds follows them.
const FRAME_WITNESS: u32 = 8 + 3;

const fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(i)
}

/// `W[10..16]`: the claimed decoded row, `next_pc, rs1, rs2, rd, imm, mask` —
/// `program::lookup_tuple` after `pc`, which the frame's own pc column is.
pub const DECODED: [PolyAddress; 6] = [
    w(FRAME_WITNESS),
    w(FRAME_WITNESS + 1),
    w(FRAME_WITNESS + 2),
    w(FRAME_WITNESS + 3),
    w(FRAME_WITNESS + 4),
    w(FRAME_WITNESS + 5),
];
const DECODED_NEXT_PC: PolyAddress = DECODED[0];
const DECODED_RS1: PolyAddress = DECODED[1];
const DECODED_RS2: PolyAddress = DECODED[2];
const DECODED_RD: PolyAddress = DECODED[3];
const DECODED_IMM: PolyAddress = DECODED[4];
const DECODED_MASK: PolyAddress = DECODED[5];

/// `W[16..22]`: the packed mask's bits, bit `k` at index `k` —
/// `constants::extra_mask::add_sub_lui_auipc`'s order: system, addi, auipc,
/// add, sub, lui.
pub const KINDS: [PolyAddress; 6] = [
    w(FRAME_WITNESS + 6),
    w(FRAME_WITNESS + 7),
    w(FRAME_WITNESS + 8),
    w(FRAME_WITNESS + 9),
    w(FRAME_WITNESS + 10),
    w(FRAME_WITNESS + 11),
];
const KIND_SYSTEM: PolyAddress = KINDS[kind::SYSTEM as usize];
const KIND_ADDI: PolyAddress = KINDS[kind::ADDI as usize];
const KIND_AUIPC: PolyAddress = KINDS[kind::AUIPC as usize];
const KIND_ADD: PolyAddress = KINDS[kind::ADD as usize];
const KIND_SUB: PolyAddress = KINDS[kind::SUB as usize];
const KIND_LUI: PolyAddress = KINDS[kind::LUI as usize];

/// `W[22]`: 1 exactly on a system row whose code is `ecall`.
pub const IS_ECALL: PolyAddress = w(FRAME_WITNESS + 12);
/// `W[24]`: 1 exactly on a system row whose code is `fence`.
pub const IS_FENCE: PolyAddress = w(FRAME_WITNESS + 13);
/// `W[25]`: 1 exactly on an ecall row whose `a7` is the keccak-f delegation
/// number — the **delegation request** selector (`docs/spec/delegation.md`
/// §5.1). A free boolean, pinned by the two number gates below: an ecall row
/// is an exit or a delegation request, and its `a7` is that call's number.
pub const IS_KECCAK: PolyAddress = w(FRAME_WITNESS + 14);
/// `W[26]`: the sum's carry, or the difference's borrow.
pub const WRAP: PolyAddress = w(FRAME_WITNESS + 15);
/// `W[27]`: the computed `rd` value's high halfword.
pub const RD_HI: PolyAddress = w(FRAME_WITNESS + 16);
/// `W[28]`: `next_pc`'s wrap, 0 on every honest row.
pub const PC_WRAP: PolyAddress = w(FRAME_WITNESS + 17);
/// `W[29]`: `next_pc`'s high halfword.
pub const NEXT_PC_HI: PolyAddress = w(FRAME_WITNESS + 18);
/// `W[30..33]`: the channels' multiplicities, in channel order — timestamp,
/// range16, decoder — last in the witness subtree (`docs/spec/lookup.md` §7).
pub const MULTIPLICITIES: [PolyAddress; 3] = [
    w(FRAME_WITNESS + 19),
    w(FRAME_WITNESS + 20),
    w(FRAME_WITNESS + 21),
];

/// The decoded table's width, `program::lookup_tuple(ADD_SUB_LUI_AUIPC)`:
/// `pc next_pc rs1 rs2 rd imm extra_mask`, at `S[0..7]`.
pub const TABLE_WIDTH: usize = 7;

/// `ecall_code` is `is_ecall·imm`, which says "the code is `ECALL`" only
/// because that code is 0.
const _: () = assert!(system_code::ECALL == 0);

/// `a7`'s register, which an ecall row reads as its `rs1`.
const A7: u64 = 17;
/// `a0`'s register, which an ecall row reads as its `rs2` and writes as its
/// `rd`.
const A0: u64 = 10;

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn neg(v: u64) -> Coeff {
    Coeff::Literal(-Fr::from_u64(v))
}

fn two_32() -> Fr {
    Fr::from_u64(1 << 32)
}

/// `Σ a·x + Σ b·y·z`, constant 0, literal coefficients.
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

/// `m_q·(a_q − decoded − register·is_ecall)`: a present query's address is the
/// decoded one, or `register` on an ecall row, whose decoded registers are 0.
fn addr_rule(slot: usize, decoded: PolyAddress, register: u64) -> GateDef {
    let m = frame(slot, FIELD_MASK);
    quadratic(
        vec![],
        vec![
            (lit(1), m, frame(slot, FIELD_ADDR)),
            (neg(1), m, decoded),
            (neg(register), m, IS_ECALL),
        ],
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

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The family's circuit over `2^trace_vars` rows, `docs/spec/shard-proof.md`
/// §8. `trace_vars` is at least 19, the timestamp channel's width, which the
/// assembly refuses below; a Mercury opening needs it even as well.
///
/// Panics if the family's frame is not the seven queries this file addresses,
/// or if any obligation count is not §8.3's — 14 timestamp, 4 `RANGE16`, 1
/// decoder — and on every refusal of the assembly.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    assert_eq!(
        frame_queries(family::ADD_SUB_LUI_AUIPC),
        &QUERIES,
        "add_sub: the family's frame is the eight queries this circuit addresses by slot"
    );
    let m_pc = frame(SLOT_PC, FIELD_MASK);
    let pc = frame(SLOT_PC, FIELD_READ_VALUE);
    let next_pc = frame(SLOT_PC, FIELD_WRITE_VALUE);
    let v_rs1 = frame(SLOT_RS1, FIELD_READ_VALUE);
    let v_rs2 = frame(SLOT_RS2, FIELD_READ_VALUE);
    let v_rd = frame(SLOT_RD, FIELD_READ_VALUE);
    let sel = rd_selected(QUERIES.len());

    let mut witness = names(&[
        "decoded_next_pc",
        "decoded_rs1",
        "decoded_rs2",
        "decoded_rd",
        "decoded_imm",
        "decoded_mask",
        "kind_system",
        "kind_addi",
        "kind_auipc",
        "kind_add",
        "kind_sub",
        "kind_lui",
        "is_ecall",
        "is_fence",
        "is_keccak",
        "wrap",
        "rd_hi",
        "pc_wrap",
        "next_pc_hi",
    ]);
    witness.extend(
        [
            lookup_channel::TIMESTAMP,
            lookup_channel::RANGE16,
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
    ]);

    let kind_names = ["system", "addi", "auipc", "add", "sub", "lui"];
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
    enforcing.push(("is_ecall_boolean".into(), booleanity(IS_ECALL)));
    enforcing.push(("is_fence_boolean".into(), booleanity(IS_FENCE)));
    enforcing.push((
        "system_split".into(),
        linear(vec![
            (lit(1), IS_ECALL),
            (lit(1), IS_FENCE),
            (neg(1), KIND_SYSTEM),
        ]),
    ));
    enforcing.push((
        "ecall_code".into(),
        quadratic(vec![], vec![(lit(1), IS_ECALL, DECODED_IMM)]),
    ));
    enforcing.push((
        "fence_code".into(),
        quadratic(
            vec![(neg(system_code::FENCE as u64), IS_FENCE)],
            vec![(lit(1), IS_FENCE, DECODED_IMM)],
        ),
    ));
    // An ecall row is an exit or a delegation request, and `a7` is that
    // call's number. `is_keccak` is a free boolean and `is_exit` is
    // `is_ecall - is_keccak`, so the two pins below leave `a7` no third
    // value: a row claiming both would need `a7` to be 93 and the delegation
    // number at once (`docs/spec/delegation.md` §5.1).
    enforcing.push(("is_keccak_boolean".into(), booleanity(IS_KECCAK)));
    enforcing.push((
        "keccak_is_an_ecall".into(),
        quadratic(
            vec![(lit(1), IS_KECCAK)],
            vec![(neg(1), IS_KECCAK, IS_ECALL)],
        ),
    ));
    // is_exit·(a7 - EXIT) = 0, with is_exit written out as is_ecall - is_keccak.
    enforcing.push((
        "ecall_is_exit".into(),
        quadratic(
            vec![
                (neg(constants::ecall::EXIT as u64), IS_ECALL),
                (lit(constants::ecall::EXIT as u64), IS_KECCAK),
            ],
            vec![(lit(1), IS_ECALL, v_rs1), (neg(1), IS_KECCAK, v_rs1)],
        ),
    ));
    enforcing.push((
        "keccak_number".into(),
        quadratic(
            vec![(
                neg(constants::ecall::PRECOMPILE_KECCAK_F as u64),
                IS_KECCAK,
            )],
            vec![(lit(1), IS_KECCAK, v_rs1)],
        ),
    ));

    enforcing.push((
        "rs1_mask_rule".into(),
        mask_rule(
            frame(SLOT_RS1, FIELD_MASK),
            &[KIND_ADD, KIND_SUB, KIND_ADDI, IS_ECALL],
        ),
    ));
    enforcing.push((
        "rs2_mask_rule".into(),
        mask_rule(frame(SLOT_RS2, FIELD_MASK), &[KIND_ADD, KIND_SUB, IS_ECALL]),
    ));
    for (name, slot) in [
        ("arg1_mask_rule", SLOT_ARG1),
        ("arg2_mask_rule", SLOT_ARG2),
        ("ram_mask_rule", SLOT_RAM),
    ] {
        enforcing.push((name.into(), linear(vec![(lit(1), frame(slot, FIELD_MASK))])));
    }
    enforcing.push((
        "rd_mask_rule".into(),
        mask_rule(
            frame(SLOT_RD, FIELD_MASK),
            &[
                KIND_ADD, KIND_SUB, KIND_ADDI, KIND_AUIPC, KIND_LUI, IS_ECALL,
            ],
        ),
    ));
    enforcing.push((
        "deleg_mask_rule".into(),
        mask_rule(frame(SLOT_DELEG, FIELD_MASK), &[IS_KECCAK]),
    ));
    enforcing.push(("rs1_addr_rule".into(), addr_rule(SLOT_RS1, DECODED_RS1, A7)));
    enforcing.push(("rs2_addr_rule".into(), addr_rule(SLOT_RS2, DECODED_RS2, A0)));
    enforcing.push(("rd_addr_rule".into(), addr_rule(SLOT_RD, DECODED_RD, A0)));
    enforcing.push(("rs1_value_masked".into(), value_masked(SLOT_RS1)));
    enforcing.push(("rs2_value_masked".into(), value_masked(SLOT_RS2)));

    // (add + addi + auipc)·(rs1 + rs2 + imm − sel − 2^32·wrap) + auipc·pc: an
    // R-type row's imm is 0, an I-type or U-type row's absent rs2 reads 0, and
    // an auipc row's absent rs1 reads 0, so each kind sees its own two addends.
    let mut sum = Vec::new();
    for bit in [KIND_ADD, KIND_ADDI, KIND_AUIPC] {
        sum.push((lit(1), bit, v_rs1));
        sum.push((lit(1), bit, v_rs2));
        sum.push((lit(1), bit, DECODED_IMM));
        sum.push((neg(1), bit, sel));
        sum.push((Coeff::Literal(-two_32()), bit, WRAP));
    }
    sum.push((lit(1), KIND_AUIPC, pc));
    enforcing.push(("add_addi_auipc".into(), quadratic(vec![], sum)));
    enforcing.push((
        "sub".into(),
        quadratic(
            vec![],
            vec![
                (lit(1), KIND_SUB, v_rs1),
                (neg(1), KIND_SUB, v_rs2),
                (neg(1), KIND_SUB, sel),
                (Coeff::Literal(two_32()), KIND_SUB, WRAP),
            ],
        ),
    ));
    enforcing.push((
        "lui".into(),
        quadratic(
            vec![],
            vec![(lit(1), KIND_LUI, DECODED_IMM), (neg(1), KIND_LUI, sel)],
        ),
    ));
    // The exit row's `a0` write is its read. A delegation request's is not:
    // it writes 0, which is the first of the three request-side zeroings.
    enforcing.push((
        "exit_status".into(),
        quadratic(
            vec![],
            vec![
                (lit(1), IS_ECALL, v_rd),
                (neg(1), IS_ECALL, sel),
                (neg(1), IS_KECCAK, v_rd),
                (lit(1), IS_KECCAK, sel),
            ],
        ),
    ));
    // The three request-side zeroings of `docs/spec/delegation.md` §5.2, each
    // gated on the mirror query's own mask. All three, and not two: without
    // the rd zeroing a request writes a register the ABI says it does not;
    // without the timestamp zeroing the requests chain, and N of them close
    // the permutation against one invocation; without the value zeroing the
    // request's read and the invocation's write are different tuples and
    // never cancel.
    let m_deleg = frame(SLOT_DELEG, FIELD_MASK);
    enforcing.push((
        "deleg_writes_no_register".into(),
        quadratic(vec![], vec![(lit(1), m_deleg, sel)]),
    ));
    enforcing.push((
        "deleg_read_ts_zero".into(),
        quadratic(
            vec![],
            vec![(lit(1), m_deleg, frame(SLOT_DELEG, FIELD_READ_TS))],
        ),
    ));
    enforcing.push((
        "deleg_read_value_zero".into(),
        quadratic(
            vec![],
            vec![(lit(1), m_deleg, frame(SLOT_DELEG, FIELD_READ_VALUE))],
        ),
    ));
    // The anchor's address is the frame base the request handed over in `a0`,
    // which is this row's `rs2` read (`docs/spec/delegation.md` §5.2).
    enforcing.push((
        "deleg_addr_rule".into(),
        quadratic(
            vec![],
            vec![
                (lit(1), m_deleg, frame(SLOT_DELEG, FIELD_ADDR)),
                (neg(1), m_deleg, v_rs2),
            ],
        ),
    ));
    enforcing.push(("wrap_boolean".into(), booleanity(WRAP)));
    enforcing.push(("pc_wrap_boolean".into(), booleanity(PC_WRAP)));
    // next_pc + 2^32·pc_wrap = decoded_next_pc, or HALT_PC on the exit row.
    // A delegation request is not an exit: its next_pc is the fall-through,
    // so `is_exit = is_ecall - is_keccak` is what carries the sentinel.
    enforcing.push((
        "next_pc_rule".into(),
        quadratic(
            vec![
                (lit(1), next_pc),
                (Coeff::Literal(two_32()), PC_WRAP),
                (neg(1), DECODED_NEXT_PC),
                (neg(mem::HALT_PC as u64), IS_ECALL),
                (lit(mem::HALT_PC as u64), IS_KECCAK),
            ],
            vec![
                (lit(1), IS_ECALL, DECODED_NEXT_PC),
                (neg(1), IS_KECCAK, DECODED_NEXT_PC),
            ],
        ),
    ));

    let mut decode = vec![column(pc)];
    decode.extend(DECODED.iter().map(|x| column(*x)));
    let lookups = vec![
        range16("rd_hi_range", column(RD_HI)),
        range16("rd_lo_range", low_half(sel, RD_HI)),
        range16("next_pc_hi_range", column(NEXT_PC_HI)),
        range16("next_pc_lo_range", low_half(next_pc, NEXT_PC_HI)),
        LookupExpr {
            name: "decode_row".into(),
            channel: lookup_channel::DECODER,
            selector: m_pc,
            tuple: decode,
        },
    ];

    let a = frame_with_channels_artifact(
        &QUERIES,
        trace_vars,
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
        },
    );
    // Every obligation is built above and then handed over, so a count is
    // what shows none was dropped on the way (S14 must-be-exact 5, S15's
    // per-channel form).
    for (channel, want) in [
        (lookup_channel::TIMESTAMP, 2 * QUERIES.len()),
        (lookup_channel::RANGE16, 4),
        (lookup_channel::DECODER, 1),
    ] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(
            got,
            want,
            "add_sub: channel `{}` carries {got} obligations, not {want}",
            lookup_channel::NAMES[channel as usize]
        );
    }
    a
}

/// The family's three channels, in output order: the timestamp gaps over
/// `V[range19]`, the 16-bit halves over `V[range16]`, and the decoder over the
/// family's decoded table at `S[0..7]`.
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
            channel: lookup_channel::DECODER,
            table: (0..TABLE_WIDTH as u32).map(PolyAddress::Setup).collect(),
            multiplicity: MULTIPLICITIES[2],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ebreak`'s code is neither the ecall code nor the fence code, which is
    /// what makes `system_split` with `ecall_code` and `fence_code` refuse every
    /// `ebreak` row.
    #[test]
    fn no_system_code_is_both_or_neither_but_ebreak() {
        assert_ne!(system_code::EBREAK, system_code::ECALL);
        assert_ne!(system_code::EBREAK, system_code::FENCE);
        assert_ne!(system_code::ECALL, system_code::FENCE);
    }
}
