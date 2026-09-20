//! The `ATOMICS` family's circuit: `lr.w`, `sc.w` and the nine AMOs.
//!
//! `docs/spec/memory-ops.md` is normative: the columns, the gates, the lookups
//! and the argument. This file is that document as data, assembled by S15's
//! `memory::frame_with_channels_artifact` beside S14's frame, with S17's
//! comparison gadget and S18's byte AND table.
//!
//! One row is one read-modify-write: the RAM query at slot 3 carries the old
//! word as its read and the new word as its write, and `rd` at the same slot
//! takes the old word. That is why the A extension is the one family with two
//! queries in a single Δ slot, so one of its rows makes five
//! (`docs/spec/execution-trace.md` §4).
//!
//! ```text
//! frame      M[0..26], W[0..8]: pc rs1 rs2 ram rd at slots 0..5
//! W[8..13]   the claimed decoded row: next_pc rs1 rs2 rd mask — five, no imm
//! W[13..24]  the mask's eleven bits, extra_mask::atomics order
//! W[24..26]  word_index, word_index_hi
//! W[26..29]  sum, sum_hi, add_wrap — the amoadd result
//! W[29]      f_bitwise, the AND lookups' selector
//! W[30..42]  the two operands' bytes and their AND, four each
//! W[42..49]  the comparison: old_hi, old_sign, src_hi, src_sign, lt,
//!            cmp_gap, cmp_gap_hi
//! W[49]      lo, the smaller of the two operands
//! W[50..54]  one multiplicity per channel: timestamp, range16, generic, decoder
//! S[0..6]    the decoded table, program::lookup_tuple order — six, no imm
//! S[6..9]    the packed generic table, constants::generic_table
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::extra_mask::atomics as kind;
use constants::{family, generic_table, lookup_channel};
use field::Fr;

use crate::gadgets::{comparison, Comparison};
use crate::lookup::{check_copowers, ChannelSpec};
use crate::memory::{
    frame, frame_queries, frame_with_channels_artifact, rd_selected, FamilySpec, FIELD_ADDR,
    FIELD_MASK, FIELD_READ_VALUE, FIELD_WRITE_VALUE, PC, RAM, RD, RS1, RS2,
};
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

/// The family's queries, in slot order: its frame is `memory::frame_queries`'
/// list, and this file addresses its columns by these slots. The whole A
/// extension keeps its RAM query at slot 3, `lr.w` included, so there is no
/// `load` query (`docs/spec/execution-trace.md` §7).
const QUERIES: [usize; 5] = [PC, RS1, RS2, RAM, RD];
const SLOT_PC: usize = 0;
const SLOT_RS1: usize = 1;
const SLOT_RS2: usize = 2;
const SLOT_RAM: usize = 3;
const SLOT_RD: usize = 4;

/// The frame's own witness columns: five gap chunks, then the x0 gadget's
/// three. Everything this file adds follows them.
const FRAME_WITNESS: u32 = 5 + 3;

const fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(FRAME_WITNESS + i)
}

/// `W[8..13]`: the claimed decoded row, `next_pc, rs1, rs2, rd, mask` —
/// `program::lookup_tuple` after `pc`, which the frame's own pc column is.
/// **Five, not six**: every A instruction is R-type, so the tuple carries no
/// `imm` and an atomic's address is `rs1` alone.
pub const DECODED: [PolyAddress; 5] = [w(0), w(1), w(2), w(3), w(4)];
const SEQ: PolyAddress = DECODED[0];
const DECODED_RS1: PolyAddress = DECODED[1];
const DECODED_RS2: PolyAddress = DECODED[2];
const DECODED_RD: PolyAddress = DECODED[3];
const DECODED_MASK: PolyAddress = DECODED[4];

/// `W[13..24]`: the packed mask's bits, bit `k` at index `k` —
/// `constants::extra_mask::atomics`' order, which is ascending `funct5`:
/// `amoadd`, `amoswap`, `lr`, `sc`, `amoxor`, `amoor`, `amoand`, `amomin`,
/// `amomax`, `amominu`, `amomaxu`. **Not the stage prompt's listing order**,
/// which transposes `amoand` and `amoor`; every arm below indexes this array
/// through its constant, never by position.
pub const KINDS: [PolyAddress; 11] = [
    w(5),
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
];
const AMOADD: PolyAddress = KINDS[kind::AMOADD_W as usize];
const AMOSWAP: PolyAddress = KINDS[kind::AMOSWAP_W as usize];
const LR: PolyAddress = KINDS[kind::LR_W as usize];
const SC: PolyAddress = KINDS[kind::SC_W as usize];
const AMOXOR: PolyAddress = KINDS[kind::AMOXOR_W as usize];
const AMOOR: PolyAddress = KINDS[kind::AMOOR_W as usize];
const AMOAND: PolyAddress = KINDS[kind::AMOAND_W as usize];
const AMOMIN: PolyAddress = KINDS[kind::AMOMIN_W as usize];
const AMOMAX: PolyAddress = KINDS[kind::AMOMAX_W as usize];
const AMOMINU: PolyAddress = KINDS[kind::AMOMINU_W as usize];
const AMOMAXU: PolyAddress = KINDS[kind::AMOMAXU_W as usize];

/// The two kinds that order signed, whose sum is the comparison's `sc`.
const SIGNED: [PolyAddress; 2] = [AMOMIN, AMOMAX];

/// `W[24]`, `W[25]`: the accessed word's index — the memory tuple's address is
/// `4·word_index` — and its high halfword.
pub const WORD_INDEX: PolyAddress = w(16);
pub const WORD_INDEX_HI: PolyAddress = w(17);
/// `W[26..29]`: `amoadd`'s reduced sum, its high halfword and its wrap bit.
pub const SUM: PolyAddress = w(18);
pub const SUM_HI: PolyAddress = w(19);
pub const ADD_WRAP: PolyAddress = w(20);
/// `W[29]`: 1 on an `amoand`, `amoor` or `amoxor` row — the AND lookups'
/// selector, which is why it is a column and carries a booleanity gate.
pub const F_BITWISE: PolyAddress = w(21);
/// `W[30..42]`: the old word's bytes, `rs2`'s bytes, and their AND. One AND
/// table serves all three bitwise operations; OR and XOR are derived from the
/// accumulator by linearity, with no table of their own
/// (`docs/spec/shift-bitwise.md` §4.4).
pub const BYTES_A: [PolyAddress; 4] = [w(22), w(23), w(24), w(25)];
pub const BYTES_B: [PolyAddress; 4] = [w(26), w(27), w(28), w(29)];
pub const BYTES_AND: [PolyAddress; 4] = [w(30), w(31), w(32), w(33)];
/// `W[42..49]`: the comparison of the old word against `rs2` — each operand's
/// high halfword and sign, the ordering bit, and the gap with its halfword.
pub const OLD_HI: PolyAddress = w(34);
pub const OLD_SIGN: PolyAddress = w(35);
pub const SRC_HI: PolyAddress = w(36);
pub const SRC_SIGN: PolyAddress = w(37);
pub const LT: PolyAddress = w(38);
pub const CMP_GAP: PolyAddress = w(39);
pub const CMP_GAP_HI: PolyAddress = w(40);
/// `W[49]`: the smaller of the old word and `rs2` under the ordering the row
/// selects. The larger is the linear form `old + rs2 − lo`, so it needs no
/// column.
pub const LO: PolyAddress = w(41);
/// `W[50..54]`: the channels' multiplicities, in channel order — timestamp,
/// range16, generic, decoder — last in the witness subtree
/// (`docs/spec/lookup.md` §7).
pub const MULTIPLICITIES: [PolyAddress; 4] = [w(42), w(43), w(44), w(45)];

/// The decoded table's width, `program::lookup_tuple(ATOMICS)`:
/// `pc next_pc rs1 rs2 rd extra_mask`, at `S[0..6]`. **Six, not seven** — as
/// `MUL_DIV`'s is — so the packed generic table sits at `S[6..9]`.
pub const TABLE_WIDTH: usize = 6;

/// `S[6..9]`: the packed generic table's columns, key first, after the decoded
/// table.
pub const GENERIC_TABLE: [PolyAddress; generic_table::WIDTH] = [
    PolyAddress::Setup(TABLE_WIDTH as u32),
    PolyAddress::Setup(TABLE_WIDTH as u32 + 1),
    PolyAddress::Setup(TABLE_WIDTH as u32 + 2),
];

/// The decoded masks a live row of this family can carry: one bit per
/// instruction, in `constants::extra_mask::atomics` order. `aq` and `rl` are
/// not recorded — on one hart they order nothing — so `lr.w.aq` and `lr.w` are
/// one kind.
pub const LEGAL_MASKS: [u32; 11] = [
    1 << kind::AMOADD_W,
    1 << kind::AMOSWAP_W,
    1 << kind::LR_W,
    1 << kind::SC_W,
    1 << kind::AMOXOR_W,
    1 << kind::AMOOR_W,
    1 << kind::AMOAND_W,
    1 << kind::AMOMIN_W,
    1 << kind::AMOMAX_W,
    1 << kind::AMOMINU_W,
    1 << kind::AMOMAXU_W,
];

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn neg(v: u64) -> Coeff {
    Coeff::Literal(-Fr::from_u64(v))
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

/// `m_q·(a_q − decoded)`: a present register query's address is the decoded
/// one.
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

/// A `RANGE16` obligation under `selector`.
fn range16_under(name: &str, selector: PolyAddress, expression: GateDef) -> LookupExpr {
    LookupExpr {
        name: name.to_string(),
        channel: lookup_channel::RANGE16,
        selector,
        tuple: vec![expression],
    }
}

/// A `RANGE16` obligation under the row's pc mask.
fn range16(name: &str, expression: GateDef) -> LookupExpr {
    range16_under(name, frame(SLOT_PC, FIELD_MASK), expression)
}

/// The 16+16 pair that bounds `value` to a 32-bit word, under `m_pc`.
fn range32(name: &str, value: PolyAddress, hi: PolyAddress) -> [LookupExpr; 2] {
    [
        range16(&format!("{name}_hi_range"), column(hi)),
        range16(
            &format!("{name}_lo_range"),
            linear(vec![(lit(1), value), (neg(1 << 16), hi)]),
        ),
    ]
}

/// The two obligations that bound a byte key below 256 under `f_bitwise`: the
/// direct halfword check, and the same column scaled by `2^8`, which is a
/// halfword only below 256. Both are needed — a scaled bound alone bounds
/// nothing (`docs/spec/lookup.md` §11) — and both must sit under one selector
/// (`docs/spec/shift-bitwise.md` §3.4).
fn byte_key_bound(name: &str, x: PolyAddress, selector: PolyAddress) -> [LookupExpr; 2] {
    [
        range16_under(&format!("{name}_range"), selector, column(x)),
        range16_under(
            &format!("{name}_scaled"),
            selector,
            linear(vec![(lit(1 << 8), x)]),
        ),
    ]
}

/// A `GENERIC` lookup of the packed table, `(key + base, value, result)` under
/// `selector`. The `+ 1` that keeps a real entry off the `ZeroEntry` is the
/// channel's, added by `lookup::Gating::ZeroEntry`; writing it here would shift
/// every key one row.
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

/// The family's comparison, the old word against `rs2`, ordered signed on
/// `amomin` and `amomax` rows and unsigned on every other. Its four
/// parameters are the whole defence of four of the eleven kinds, so
/// [`assemble`] asserts each of them.
fn the_comparison() -> Comparison {
    Comparison {
        prefix: "cmp".into(),
        selector: frame(SLOT_PC, FIELD_MASK),
        signed: SIGNED.to_vec(),
        lhs: frame(SLOT_RAM, FIELD_READ_VALUE),
        lhs_hi: OLD_HI,
        lhs_sign: OLD_SIGN,
        rhs: frame(SLOT_RS2, FIELD_READ_VALUE),
        rhs_hi: SRC_HI,
        rhs_sign: SRC_SIGN,
        lt: LT,
        gap: CMP_GAP,
        gap_hi: CMP_GAP_HI,
    }
}

/// The family's circuit over `2^trace_vars` rows, `docs/spec/memory-ops.md`
/// §6. `trace_vars` is at least 19, the timestamp channel's width, which the
/// registry refuses below; a Mercury opening needs it even as well, and at 19
/// or more the generic table's rows fit.
///
/// Panics if the family's frame is not the five queries this file addresses,
/// if the comparison is not the one over the old word and `rs2` signed on the
/// two signed kinds, if any channel's obligation count is not the document's —
/// 10 timestamp, 19 `RANGE16`, 6 generic, 1 decoder — if a scaled column lacks
/// its direct range check, if a gate is nonzero on the all-zero padding row,
/// and on every refusal of the assembly.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    assemble(trace_vars, family_spec())
}

/// The family's sub-circuit: its columns, gates, lookups and channels, before
/// the assembly onto the frame.
fn family_spec() -> FamilySpec {
    assert_eq!(
        frame_queries(family::ATOMICS),
        &QUERIES,
        "atomics: the family's frame is the five queries this circuit addresses by slot"
    );
    let m_pc = frame(SLOT_PC, FIELD_MASK);
    let m_ram = frame(SLOT_RAM, FIELD_MASK);
    let pc = frame(SLOT_PC, FIELD_READ_VALUE);
    let next_pc = frame(SLOT_PC, FIELD_WRITE_VALUE);
    let v_rs1 = frame(SLOT_RS1, FIELD_READ_VALUE);
    let src = frame(SLOT_RS2, FIELD_READ_VALUE);
    let old = frame(SLOT_RAM, FIELD_READ_VALUE);
    let new = frame(SLOT_RAM, FIELD_WRITE_VALUE);
    let sel = rd_selected(QUERIES.len());

    let kind_names = [
        "amoadd", "amoswap", "lr", "sc", "amoxor", "amoor", "amoand", "amomin", "amomax",
        "amominu", "amomaxu",
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
        "word_index",
        "word_index_hi",
        "sum",
        "sum_hi",
        "add_wrap",
        "f_bitwise",
    ]));
    for j in 0..4 {
        witness.push(format!("byte_a{j}"));
    }
    for j in 0..4 {
        witness.push(format!("byte_b{j}"));
    }
    for j in 0..4 {
        witness.push(format!("byte_and{j}"));
    }
    witness.extend(names(&[
        "old_hi",
        "old_sign",
        "src_hi",
        "src_sign",
        "lt",
        "cmp_gap",
        "cmp_gap_hi",
        "lo",
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
    let mut bits: Vec<(Coeff, PolyAddress)> = KINDS
        .iter()
        .enumerate()
        .map(|(k, bit)| (lit(1 << k), *bit))
        .collect();
    bits.push((neg(1), DECODED_MASK));
    enforcing.push(("decoded_mask_bits".into(), linear(bits)));

    // Every kind reads rs1, rewrites the word and writes rd; every kind but
    // `lr.w`, whose form has no rs2, also reads rs2.
    let all = KINDS.to_vec();
    let not_lr: Vec<PolyAddress> = KINDS.iter().copied().filter(|b| *b != LR).collect();
    enforcing.push((
        "rs1_mask_rule".into(),
        mask_rule(frame(SLOT_RS1, FIELD_MASK), &all),
    ));
    enforcing.push((
        "rs2_mask_rule".into(),
        mask_rule(frame(SLOT_RS2, FIELD_MASK), &not_lr),
    ));
    enforcing.push(("ram_mask_rule".into(), mask_rule(m_ram, &all)));
    enforcing.push((
        "rd_mask_rule".into(),
        mask_rule(frame(SLOT_RD, FIELD_MASK), &all),
    ));
    enforcing.push(("rs1_addr_rule".into(), addr_rule(SLOT_RS1, DECODED_RS1)));
    enforcing.push(("rs2_addr_rule".into(), addr_rule(SLOT_RS2, DECODED_RS2)));
    enforcing.push(("rd_addr_rule".into(), addr_rule(SLOT_RD, DECODED_RD)));
    enforcing.push((
        "ram_addr_rule".into(),
        quadratic(
            vec![],
            vec![
                (lit(1), m_ram, frame(SLOT_RAM, FIELD_ADDR)),
                (neg(4), m_ram, WORD_INDEX),
            ],
        ),
    ));
    enforcing.push(("rs1_value_masked".into(), value_masked(SLOT_RS1)));
    enforcing.push(("rs2_value_masked".into(), value_masked(SLOT_RS2)));
    // An atomic's address is `rs1` alone — the A extension has no immediate —
    // so there is no wrap bit and no offset bits. `word_index < 2^30` from its
    // three obligations is what makes `rs1 = 4·word_index` an integer
    // equation, and so what makes a misaligned atomic unprovable; it also
    // derives `rs1 < 2^32` rather than assuming it.
    enforcing.push((
        "addr_word".into(),
        linear(vec![(lit(1), v_rs1), (neg(4), WORD_INDEX)]),
    ));

    // amoadd: the reduced sum and its carry. Ungated, so `sum` is the true
    // reduced sum on every live row and its range pair is under `m_pc`.
    enforcing.push(("add_wrap_boolean".into(), booleanity(ADD_WRAP)));
    enforcing.push((
        "add_rule".into(),
        linear(vec![
            (lit(1), old),
            (lit(1), src),
            (neg(1), SUM),
            (Coeff::Literal(-Fr::from_u64(1 << 32)), ADD_WRAP),
        ]),
    ));
    // f_bitwise selects the four AND lookups, so it is a column with a
    // booleanity gate of its own, and it is the three bitwise kinds — not
    // `amoand` alone, which would leave `amoor` and `amoxor` reading free
    // columns.
    enforcing.push(("f_bitwise_boolean".into(), booleanity(F_BITWISE)));
    enforcing.push((
        "f_bitwise_rule".into(),
        linear(vec![
            (lit(1), F_BITWISE),
            (neg(1), AMOAND),
            (neg(1), AMOOR),
            (neg(1), AMOXOR),
        ]),
    ));
    let byte_terms = |x: PolyAddress, bytes: &[PolyAddress; 4]| {
        let mut terms = vec![(lit(1), x)];
        for (j, b) in bytes.iter().enumerate() {
            terms.push((neg(1 << (8 * j)), *b));
        }
        linear(terms)
    };
    enforcing.push(("old_bytes_rule".into(), byte_terms(old, &BYTES_A)));
    enforcing.push(("src_bytes_rule".into(), byte_terms(src, &BYTES_B)));

    let cmp = the_comparison();
    let (cmp_gates, cmp_lookups) = comparison(&cmp);
    enforcing.extend(cmp_gates);
    // lo = rs2 + lt·(old − rs2): the smaller under whichever ordering `lt`
    // settled. The larger is `old + rs2 − lo`, exact over the integers in both
    // orderings, so `amomax` needs no second column.
    enforcing.push((
        "lo_rule".into(),
        quadratic(
            vec![(lit(1), LO), (neg(1), src)],
            vec![(neg(1), LT, old), (lit(1), LT, src)],
        ),
    ));

    // The eleven arms, each a kind bit times a column or a linear form. The
    // AND accumulator `A = Σ 2^(8j)·byte_and_j` is inlined; OR is
    // `old + rs2 − A` and XOR `old + rs2 − 2A`, each exact over the integers
    // because no carry crosses a byte.
    let mut new_products = vec![
        (neg(1), LR, old),
        (neg(1), SC, src),
        (neg(1), AMOSWAP, src),
        (neg(1), AMOADD, SUM),
        (neg(1), AMOOR, old),
        (neg(1), AMOOR, src),
        (neg(1), AMOXOR, old),
        (neg(1), AMOXOR, src),
        (neg(1), AMOMIN, LO),
        (neg(1), AMOMINU, LO),
        (neg(1), AMOMAX, old),
        (neg(1), AMOMAX, src),
        (lit(1), AMOMAX, LO),
        (neg(1), AMOMAXU, old),
        (neg(1), AMOMAXU, src),
        (lit(1), AMOMAXU, LO),
    ];
    for (j, b) in BYTES_AND.iter().enumerate() {
        let weight = 1u64 << (8 * j);
        new_products.push((neg(weight), AMOAND, *b));
        new_products.push((lit(weight), AMOOR, *b));
        new_products.push((lit(2 * weight), AMOXOR, *b));
    }
    enforcing.push((
        "ram_value_rule".into(),
        quadratic(vec![(lit(1), new)], new_products),
    ));
    // rd takes the old word for every kind but `sc.w`, which writes 0 because
    // it always succeeds (`docs/spec/memory-ops.md` §6.3).
    enforcing.push((
        "rd_value_rule".into(),
        quadratic(
            vec![(lit(1), sel)],
            KINDS
                .iter()
                .filter(|b| **b != SC)
                .map(|b| (neg(1), *b, old))
                .collect(),
        ),
    ));
    enforcing.push((
        "next_pc_rule".into(),
        linear(vec![(lit(1), next_pc), (neg(1), SEQ)]),
    ));

    let mut lookups = cmp_lookups;
    lookups.extend(range32("word_index", WORD_INDEX, WORD_INDEX_HI));
    lookups.push(range16(
        "word_index_hi_scaled",
        linear(vec![(lit(4), WORD_INDEX_HI)]),
    ));
    lookups.extend(range32("sum", SUM, SUM_HI));
    for (j, a) in BYTES_A.iter().enumerate() {
        lookups.extend(byte_key_bound(&format!("byte_a{j}"), *a, F_BITWISE));
    }
    for (j, a) in BYTES_A.iter().enumerate() {
        lookups.push(generic(
            &format!("and_byte_{j}"),
            F_BITWISE,
            generic_table::AND_BASE,
            *a,
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
    // The comparison's four parameters are not derivable from anything else in
    // the artifact, and each wrong choice is a silent, total break of the four
    // min/max kinds (`docs/spec/memory-ops.md` §6.4), so they are asserted
    // here rather than only read. The selector carries a second thing besides:
    // the gadget's `lhs` range pair, under `m_pc`, is the only 32-bit bound on
    // the old word, and so the only bound on `rd_selected`, which is that word
    // on ten of the eleven kinds (`memory-ops.md` §5.1). Narrowing it to the
    // min/max bits would leave every other kind's `rd` write unbounded.
    let cmp = the_comparison();
    assert_eq!(
        (cmp.selector, cmp.lhs, cmp.rhs),
        (
            frame(SLOT_PC, FIELD_MASK),
            frame(SLOT_RAM, FIELD_READ_VALUE),
            frame(SLOT_RS2, FIELD_READ_VALUE)
        ),
        "atomics: the comparison is the old word against rs2, selected on every live row"
    );
    assert_eq!(
        cmp.signed, SIGNED,
        "atomics: only amomin and amomax order signed"
    );
    let a = frame_with_channels_artifact(&QUERIES, trace_vars, family_spec);
    assert!(
        a.padding.zero_row_valid,
        "atomics: a gate is nonzero on the all-zero row"
    );
    for (channel, want) in [
        (lookup_channel::TIMESTAMP, 2 * QUERIES.len()),
        (lookup_channel::RANGE16, 19),
        (lookup_channel::GENERIC, 6),
        (lookup_channel::DECODER, 1),
    ] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(
            got,
            want,
            "atomics: channel `{}` carries {got} obligations, not {want}",
            lookup_channel::NAMES[channel as usize]
        );
    }
    assert_eq!(
        a.layers[0].enforcing.len(),
        46,
        "atomics: the circuit's enforcing gates are the frame's 11 and this family's 35"
    );
    let mut scaled = vec![(WORD_INDEX_HI, frame(SLOT_PC, FIELD_MASK))];
    scaled.extend(BYTES_A.iter().map(|x| (*x, F_BITWISE)));
    if let Err(e) = check_copowers(&a, &scaled) {
        panic!("atomics: {e}");
    }
    a
}

/// The family's four channels, in output order: the timestamp gaps over
/// `V[range19]`, the halfwords over `V[range16]`, the two signs and four byte
/// ANDs over the packed generic table at `S[6..9]`, and the decoder over the
/// family's decoded table at `S[0..6]`.
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

    /// The legal masks are eleven distinct single bits, one per instruction the
    /// family owns, each the bit its `extra_mask` constant names — so the
    /// circuit's arms are keyed by `constants::extra_mask::atomics` and never
    /// by a list written in source order.
    #[test]
    fn the_legal_masks_are_the_instruction_list() {
        assert_eq!(LEGAL_MASKS.len(), 11);
        for (k, m) in LEGAL_MASKS.iter().enumerate() {
            assert_eq!(*m, 1 << k, "mask {k}");
        }
        // The four arms a transposed bit list would silently swap.
        assert_eq!(AMOAND, KINDS[6]);
        assert_eq!(AMOOR, KINDS[5]);
        assert_eq!(AMOXOR, KINDS[4]);
        assert_eq!(LR, KINDS[2]);
        assert_eq!(SC, KINDS[3]);
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
    #[should_panic(expected = "channel `range16` carries 18 obligations, not 19")]
    fn a_dropped_obligation_fails_the_build() {
        let mut e = family_spec();
        e.lookups.retain(|l| l.name != "byte_a0_range");
        assemble(20, e);
    }

    /// A byte key's direct bound moved under a selector its scaled obligation
    /// does not carry: the count holds, and the copower check refuses it.
    #[test]
    #[should_panic(expected = "copower pairing")]
    fn a_byte_key_without_its_direct_bound_fails_the_build() {
        let mut e = family_spec();
        let l = e
            .lookups
            .iter_mut()
            .find(|l| l.name == "byte_a0_range")
            .expect("the direct bound");
        l.selector = AMOAND;
        assemble(20, e);
    }

    /// A gate that is nonzero on the all-zero row is refused: a shard's
    /// padding rows are all zero.
    #[test]
    #[should_panic(expected = "a gate is nonzero on the all-zero row")]
    fn a_gate_nonzero_on_the_zero_row_fails_the_build() {
        let mut e = family_spec();
        e.enforcing.push((
            "lt_is_one".into(),
            GateDef::Linear {
                terms: vec![(lit(1), LT)],
                constant: neg(1),
            },
        ));
        assemble(20, e);
    }
}
