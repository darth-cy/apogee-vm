//! The `MEM_SUBWORD` family's circuit: `lb`, `lh`, `lbu`, `lhu`, `sb`, `sh`.
//!
//! `docs/spec/memory-ops.md` is normative: the columns, the gates, the lookups
//! and the argument. This file is that document as data, assembled by S15's
//! `memory::frame_with_channels_artifact` beside S14's frame.
//!
//! Memory is word-addressed, so a sub-word access names the same
//! `4·word_index` cell `mem_word` names, and the byte position lives only in
//! the splice `word = high·(w·p) + sub·p + low`. The splice power `p` and its
//! copower come from two degree-2 gates over the address's low two bits, not
//! from a table (`docs/spec/memory-ops.md` §4.1).
//!
//! ```text
//! frame      M[0..32], W[0..9]: pc rs1 rs2 load ram rd at slots 0..6,
//!            then M[31] load_space, the load's address space for this row
//! W[9..15]   the claimed decoded row: next_pc rs1 rs2 rd imm mask
//! W[15..21]  the mask's six bits, extra_mask::mem_subword order
//! W[21..26]  wrap, word_index, word_index_hi, bit0, bit1
//! W[26..30]  p, pcopow, wph, p_ram
//! W[30]      word, the memory word this row splices
//! W[31..42]  high, high_hi, high_scaled, high_scaled_hi, sub, sub_scaled,
//!            sub_scaled_hi, low, low_hi, low_scaled, low_scaled_hi
//! W[42..47]  src_sub, src_sub_scaled, src_sub_scaled_hi, src_high, src_high_hi
//! W[47..50]  sign_in, sign, se
//! W[50]      rd_hi
//! W[51..53]  is_advice, word_index_hi_rest -- the advice selector, S25b
//! W[53..57]  one multiplicity per channel: timestamp, range16, generic, decoder
//! S[0..7]    the decoded table, program::lookup_tuple order
//! S[7..10]   the packed generic table, constants::generic_table
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::extra_mask::mem_subword as kind;
use constants::{address_space, family, generic_table, lookup_channel};
use field::Fr;

use crate::lookup::{check_copowers, ChannelSpec};
use crate::memory::{
    frame, frame_queries, frame_with_channels_artifact, load_space, rd_selected, FamilySpec,
    FIELD_ADDR, FIELD_MASK, FIELD_READ_VALUE, FIELD_WRITE_VALUE, LOAD, PC, RAM, RD, RS1, RS2,
};
use crate::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};

/// The family's queries, in slot order: its frame is `memory::frame_queries`'
/// list, and this file addresses its columns by these slots.
const QUERIES: [usize; 6] = [PC, RS1, RS2, LOAD, RAM, RD];
const SLOT_PC: usize = 0;
const SLOT_RS1: usize = 1;
const SLOT_RS2: usize = 2;
const SLOT_LOAD: usize = 3;
const SLOT_RAM: usize = 4;
const SLOT_RD: usize = 5;

/// The frame's own witness columns: six gap chunks, then the x0 gadget's
/// three. Everything this file adds follows them.
const FRAME_WITNESS: u32 = 6 + 3;

/// Bits to a byte. The one place the width of a sub-word access is written:
/// every literal of [`splice_gates`] is derived from it, so the reduced-width
/// acceptance check evaluates the family's own gates rather than a
/// transcription of them (S17's `gadgets::comparison_equation` precedent).
pub const BYTE_BITS: u32 = 8;

const fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(FRAME_WITNESS + i)
}

/// `W[9..15]`: the claimed decoded row, `next_pc, rs1, rs2, rd, imm, mask` —
/// `program::lookup_tuple` after `pc`, which the frame's own pc column is.
pub const DECODED: [PolyAddress; 6] = [w(0), w(1), w(2), w(3), w(4), w(5)];
const SEQ: PolyAddress = DECODED[0];
const DECODED_RS1: PolyAddress = DECODED[1];
const DECODED_RS2: PolyAddress = DECODED[2];
const DECODED_RD: PolyAddress = DECODED[3];
const IMM: PolyAddress = DECODED[4];
const DECODED_MASK: PolyAddress = DECODED[5];

/// `W[15..21]`: the packed mask's bits, bit `k` at index `k` —
/// `constants::extra_mask::mem_subword`'s order: `lb`, `lh`, `lbu`, `lhu`,
/// `sb`, `sh`.
pub const KINDS: [PolyAddress; 6] = [w(6), w(7), w(8), w(9), w(10), w(11)];
const LB: PolyAddress = KINDS[kind::LB as usize];
const LH: PolyAddress = KINDS[kind::LH as usize];
const LBU: PolyAddress = KINDS[kind::LBU as usize];
const LHU: PolyAddress = KINDS[kind::LHU as usize];
const SB: PolyAddress = KINDS[kind::SB as usize];
const SH: PolyAddress = KINDS[kind::SH as usize];

/// The kinds that load, that store, that access one byte, that access a
/// halfword, and that sign-extend. Each is a linear form over the committed
/// one-hot bits, which is what the stage prompt's STORE, BYTE and SIGNEXTEND
/// modifier bits are here: S11's mask is not rebuilt
/// (`docs/spec/memory-ops.md` §1).
const LOADS: [PolyAddress; 4] = [LB, LH, LBU, LHU];
const STORES: [PolyAddress; 2] = [SB, SH];
const BYTES: [PolyAddress; 3] = [LB, LBU, SB];
const HALVES: [PolyAddress; 3] = [LH, LHU, SH];
const SIGNED: [PolyAddress; 2] = [LB, LH];

/// `W[21]`: the wrap of `rs1 + imm`, the effective address before reduction.
pub const WRAP: PolyAddress = w(12);
/// `W[22]`, `W[23]`: the accessed word's index — the memory tuple's address is
/// `4·word_index` — and its high halfword.
pub const WORD_INDEX: PolyAddress = w(13);
pub const WORD_INDEX_HI: PolyAddress = w(14);
/// `W[24]`, `W[25]`: the effective address's low two bits, the byte offset.
pub const BIT0: PolyAddress = w(15);
pub const BIT1: PolyAddress = w(16);

/// `W[26]`: the splice power `2^(8·offset)`, a function of the two offset bits.
pub const P: PolyAddress = w(17);
/// `W[27]`: its copower, **halved**: `2^31/p`, so that the column fits `u32` at
/// `p = 1` where the copower itself is `2^32`. `low_scaled_rule` carries the
/// compensating factor 2, the `ShiftPowers` pattern of
/// `docs/spec/shift-bitwise.md` §3.1.
pub const PCOPOW: PolyAddress = w(18);
/// `W[28]`: the high part's multiplier `w·p`, **halved** for the same reason —
/// `w·p` is `2^32` on a byte access at offset 3 and on a halfword at offset 2.
pub const WPH: PolyAddress = w(19);
/// `W[29]`: `p` on a store row and 0 elsewhere, which is what keeps
/// `store_rule` at degree 2.
pub const P_RAM: PolyAddress = w(20);

/// `W[30]`: the memory word this row splices — the word a load read, or the
/// word a store is rewriting.
pub const WORD: PolyAddress = w(21);
/// `W[31..35]`: the bytes above the accessed sub-word, and the same scaled by
/// `w·p`, each with its high halfword.
pub const HIGH: PolyAddress = w(22);
pub const HIGH_HI: PolyAddress = w(23);
pub const HIGH_SCALED: PolyAddress = w(24);
pub const HIGH_SCALED_HI: PolyAddress = w(25);
/// `W[35..38]`: the accessed sub-word, and the same scaled by `2^32/w`, whose
/// range is what holds `sub` below the access width.
pub const SUB: PolyAddress = w(26);
pub const SUB_SCALED: PolyAddress = w(27);
pub const SUB_SCALED_HI: PolyAddress = w(28);
/// `W[38..42]`: the bytes below the accessed sub-word, and the same scaled by
/// `2^32/p`, whose range is what holds `low` below `p`.
pub const LOW: PolyAddress = w(29);
pub const LOW_HI: PolyAddress = w(30);
pub const LOW_SCALED: PolyAddress = w(31);
pub const LOW_SCALED_HI: PolyAddress = w(32);

/// `W[42..45]`: the stored source truncated to the access width, and the same
/// scaled by `2^32/w`.
pub const SRC_SUB: PolyAddress = w(33);
pub const SRC_SUB_SCALED: PolyAddress = w(34);
pub const SRC_SUB_SCALED_HI: PolyAddress = w(35);
/// `W[45]`, `W[46]`: the rest of `rs2`, and its high halfword.
pub const SRC_HIGH: PolyAddress = w(36);
pub const SRC_HIGH_HI: PolyAddress = w(37);

/// `W[47]`: the sub-word shifted so that its sign bit is bit 15 —
/// `256·sub` for a byte, `sub` for a halfword — which is what lets one
/// `U16GetSign` lookup serve both widths.
pub const SIGN_IN: PolyAddress = w(38);
/// `W[48]`: that sign bit, from the packed table.
pub const SIGN: PolyAddress = w(39);
/// `W[49]`: the sign-extension term, `sign` on an `lb` or `lh` row and 0
/// elsewhere.
pub const SE: PolyAddress = w(40);
/// `W[50]`: the written `rd` value's high halfword.
pub const RD_HI: PolyAddress = w(41);
/// `W[51]`: whether the accessed address is in the **advice** region — bit 31
/// of the byte address, which is bit 13 of [`WORD_INDEX_HI`]. `mem_word`'s
/// column of the same name, for the same reason and pinned the same way
/// (`docs/spec/advice.md` §3.1).
pub const IS_ADVICE: PolyAddress = w(42);
/// `W[52]`: [`WORD_INDEX_HI`] with bit 13 removed, bounded below `2^13` by its
/// own scaled obligation.
pub const WORD_INDEX_HI_REST: PolyAddress = w(43);
/// `W[53..57]`: the channels' multiplicities, in channel order — timestamp,
/// range16, generic, decoder — last in the witness subtree
/// (`docs/spec/lookup.md` §7).
pub const MULTIPLICITIES: [PolyAddress; 4] = [w(44), w(45), w(46), w(47)];

/// The decoded table's width, `program::lookup_tuple(MEM_SUBWORD)`:
/// `pc next_pc rs1 rs2 rd imm extra_mask`, at `S[0..7]`.
pub const TABLE_WIDTH: usize = 7;

/// `S[7..10]`: the packed generic table's columns, key first, after the
/// decoded table.
pub const GENERIC_TABLE: [PolyAddress; generic_table::WIDTH] = [
    PolyAddress::Setup(TABLE_WIDTH as u32),
    PolyAddress::Setup(TABLE_WIDTH as u32 + 1),
    PolyAddress::Setup(TABLE_WIDTH as u32 + 2),
];

/// The decoded masks a live row of this family can carry: one bit per
/// instruction, in `constants::extra_mask::mem_subword` order. The stage
/// prompt's modifier-bit masks `{0, 1, 2, 3, 4, 6}` are **not** the encoding:
/// S11 froze this table one-hot per mnemonic and append-only, and STORE, BYTE
/// and SIGNEXTEND are linear forms over these six bits
/// (`docs/spec/memory-ops.md` §1).
pub const LEGAL_MASKS: [u32; 6] = [
    1 << kind::LB,
    1 << kind::LH,
    1 << kind::LBU,
    1 << kind::LHU,
    1 << kind::SB,
    1 << kind::SH,
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

/// `c·(Σ bits)·x`, as one product per bit: a linear form over the one-hot kind
/// bits times a column is degree 2, which is why no modifier bit needs a
/// column of its own.
fn form_times(
    c: Coeff,
    bits: &[PolyAddress],
    x: PolyAddress,
) -> Vec<(Coeff, PolyAddress, PolyAddress)> {
    bits.iter().map(|b| (c, *b, x)).collect()
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

/// `m_q·(a_q − 4·word_index)`: a present RAM query's address is the accessed
/// word's byte address. The byte position is in the splice and never in a
/// memory tuple, so a sub-word access and a word access name one cell
/// (`docs/spec/memory-ops.md` §2).
fn word_addr_rule(slot: usize) -> GateDef {
    let m = frame(slot, FIELD_MASK);
    quadratic(
        vec![],
        vec![
            (lit(1), m, frame(slot, FIELD_ADDR)),
            (neg(4), m, WORD_INDEX),
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

/// The 16+16 pair that bounds `value` to a 32-bit word, under `m_pc`
/// (`docs/spec/memory.md` §7).
fn range32(name: &str, value: PolyAddress, hi: PolyAddress) -> [LookupExpr; 2] {
    [
        range16(&format!("{name}_hi_range"), column(hi)),
        range16(
            &format!("{name}_lo_range"),
            linear(vec![(lit(1), value), (neg(1 << 16), hi)]),
        ),
    ]
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The splice, at `byte_bits` bits to a byte and `4·byte_bits` to a word: the
/// **twelve** gates whose literals depend on that width, or that read a column
/// one of them defines, over this family's own columns. `family_spec` calls it
/// at [`BYTE_BITS`]; the reduced-width acceptance check calls it at 1 and
/// evaluates *these* gates, so the check runs the circuit and not a copy of
/// it.
///
/// With `W = 4·byte_bits`, `offset = 2·bit1 + bit0`, `p = 2^(byte_bits·offset)`
/// and `w` the access width — `2^byte_bits` for a byte, `2^(2·byte_bits)` for a
/// halfword:
///
/// ```text
/// p_rule                p = m_pc + (2^b − 1)·bit0 + (2^2b − 1)·bit1 + K·bit0·bit1
/// pcopow_rule           p·pcopow = 2^(W−1)·m_pc
/// wph_rule              wph = w·p/2
/// splice_rule           word = high_scaled + sub·p + low
/// high_scaled_rule      high_scaled = 2·high·wph
/// sub_scaled_rule       sub_scaled = (2^W/w)·sub
/// low_scaled_rule       low_scaled = 2·low·pcopow
/// src_sub_rule          rs2 = src_sub + w·src_high
/// src_sub_scaled_rule   src_sub_scaled = (2^W/w)·src_sub
/// sign_in_rule          sign_in = sub·2^b for a byte, sub for a halfword
/// rd_value_rule         rd_selected = LOADK·sub + (2^W − w)·se
/// store_rule            ram_write_value = m_ram·word + (src_sub − sub)·p_ram
/// ```
///
/// `K = 2^3b − 2^2b − 2^b + 1` makes `p_rule` the unique degree-2 form taking
/// the four offsets to the four powers, and `m_pc` in place of a constant is
/// what keeps every gate zero on the all-zero padding row.
///
/// Panics unless `1 <= byte_bits <= 8`: at 0 there is no sub-word, and above 8
/// a word does not fit 32 bits.
pub fn splice_gates(byte_bits: u32) -> Vec<(String, GateDef)> {
    assert!(
        (1..=8).contains(&byte_bits),
        "mem_subword: a byte is 1 to 8 bits wide, not {byte_bits}"
    );
    let b = byte_bits;
    let (m_pc, m_ram) = (frame(SLOT_PC, FIELD_MASK), frame(SLOT_RAM, FIELD_MASK));
    let v_rs2 = frame(SLOT_RS2, FIELD_READ_VALUE);
    let sel = rd_selected(QUERIES.len());
    // The five widths every literal below is built from.
    let byte = 1u64 << b; // the access width of a byte
    let half = 1u64 << (2 * b); // the access width of a halfword
    let cube = 1u64 << (3 * b); // p at offset 3
    let word = 1u64 << (4 * b); // the whole word
    let k = cube - half - byte + 1;

    // p = 2^(b·offset), the unique degree-2 form over the two offset bits.
    let mut gates: Vec<(String, GateDef)> = vec![(
        "p_rule".into(),
        quadratic(
            vec![
                (lit(1), P),
                (neg(1), m_pc),
                (neg(byte - 1), BIT0),
                (neg(half - 1), BIT1),
            ],
            vec![(neg(k), BIT0, BIT1)],
        ),
    )];
    // p·pcopow = 2^(W−1) on a live row, so pcopow is the halved copower; on a
    // padding row p is 0 and the gate reads 0 = 0.
    gates.push((
        "pcopow_rule".into(),
        quadratic(vec![(neg(word / 2), m_pc)], vec![(lit(1), P, PCOPOW)]),
    ));
    // wph = w·p/2, with w = 2^2b − (2^2b − 2^b)·BYTE: halved so that the
    // column fits `u32` where w·p is the whole word.
    gates.push((
        "wph_rule".into(),
        quadratic(
            vec![(lit(1), WPH), (neg(half / 2), P)],
            form_times(lit((half - byte) / 2), &BYTES, P),
        ),
    ));
    // word = high·(w·p) + sub·p + low, the one decomposition both a load and a
    // store read.
    gates.push((
        "splice_rule".into(),
        quadratic(
            vec![(lit(1), WORD), (neg(1), HIGH_SCALED), (neg(1), LOW)],
            vec![(neg(1), SUB, P)],
        ),
    ));
    gates.push((
        "high_scaled_rule".into(),
        quadratic(vec![(lit(1), HIGH_SCALED)], vec![(neg(2), HIGH, WPH)]),
    ));
    // sub_scaled = (2^W/w)·sub, in range only where sub < w.
    gates.push((
        "sub_scaled_rule".into(),
        quadratic(
            vec![(lit(1), SUB_SCALED), (neg(word / half), SUB)],
            form_times(neg(word / byte - word / half), &BYTES, SUB),
        ),
    ));
    gates.push((
        "low_scaled_rule".into(),
        quadratic(vec![(lit(1), LOW_SCALED)], vec![(neg(2), LOW, PCOPOW)]),
    ));
    // rs2 = src_sub + w·src_high: the stored source truncated to the access
    // width, which is what keeps `sb` from storing a byte unrelated to rs2.
    gates.push((
        "src_sub_rule".into(),
        quadratic(
            vec![(lit(1), v_rs2), (neg(1), SRC_SUB), (neg(half), SRC_HIGH)],
            form_times(lit(half - byte), &BYTES, SRC_HIGH),
        ),
    ));
    gates.push((
        "src_sub_scaled_rule".into(),
        quadratic(
            vec![(lit(1), SRC_SUB_SCALED), (neg(word / half), SRC_SUB)],
            form_times(neg(word / byte - word / half), &BYTES, SRC_SUB),
        ),
    ));
    // sign_in = sub·2^b on a byte row and sub on a halfword row, so bit 2b−1
    // of sign_in is the sub-word's sign bit at either width.
    gates.push((
        "sign_in_rule".into(),
        quadratic(
            vec![(lit(1), SIGN_IN), (neg(1), SUB)],
            form_times(neg(byte - 1), &BYTES, SUB),
        ),
    ));
    // rd = sub + (2^W − w)·se: the sign extension, which at se = 1 is
    // sub − w + 2^W, the two's-complement word.
    let mut rd_products = form_times(neg(1), &LOADS, SUB);
    rd_products.extend(form_times(neg(half - byte), &BYTES, SE));
    gates.push((
        "rd_value_rule".into(),
        quadratic(vec![(lit(1), sel), (neg(word - half), SE)], rd_products),
    ));
    // The store's merge, `new = old + (src_sub − old_sub)·p`, written over
    // p_ram so that the gate stays degree 2 and so that a row with no RAM
    // query writes 0.
    gates.push((
        "store_rule".into(),
        quadratic(
            vec![(lit(1), frame(SLOT_RAM, FIELD_WRITE_VALUE))],
            vec![
                (neg(1), m_ram, WORD),
                (neg(1), SRC_SUB, P_RAM),
                (lit(1), SUB, P_RAM),
            ],
        ),
    ));
    gates
}

/// The family's circuit over `2^trace_vars` rows, `docs/spec/memory-ops.md`
/// §4. `trace_vars` is at least 19, the timestamp channel's width, which the
/// registry refuses below; a Mercury opening needs it even as well, and at 19
/// or more the generic table's rows fit.
///
/// Panics if the family's frame is not the six queries this file addresses, if
/// any channel's obligation count is not the document's — 12 timestamp, 22
/// `RANGE16`, 1 generic, 1 decoder — if any of the five columns a copower or a
/// literal scales lacks its direct range check, if a gate is nonzero on the
/// all-zero padding row, and on every refusal of the assembly.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    assemble(trace_vars, family_spec())
}

/// The family's sub-circuit: its columns, gates, lookups and channels, before
/// the assembly onto the frame.
fn family_spec() -> FamilySpec {
    assert_eq!(
        frame_queries(family::MEM_SUBWORD),
        &QUERIES,
        "mem_subword: the family's frame is the six queries this circuit addresses by slot"
    );
    let m_pc = frame(SLOT_PC, FIELD_MASK);
    let pc = frame(SLOT_PC, FIELD_READ_VALUE);
    let next_pc = frame(SLOT_PC, FIELD_WRITE_VALUE);
    let v_rs1 = frame(SLOT_RS1, FIELD_READ_VALUE);
    let sel = rd_selected(QUERIES.len());

    let kind_names = ["lb", "lh", "lbu", "lhu", "sb", "sh"];
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
        "wrap",
        "word_index",
        "word_index_hi",
        "bit0",
        "bit1",
        "p",
        "pcopow",
        "wph",
        "p_ram",
        "word",
        "high",
        "high_hi",
        "high_scaled",
        "high_scaled_hi",
        "sub",
        "sub_scaled",
        "sub_scaled_hi",
        "low",
        "low_hi",
        "low_scaled",
        "low_scaled_hi",
        "src_sub",
        "src_sub_scaled",
        "src_sub_scaled_hi",
        "src_high",
        "src_high_hi",
        "sign_in",
        "sign",
        "se",
        "rd_hi",
        "is_advice",
        "word_index_hi_rest",
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
    let mut bits: Vec<(Coeff, PolyAddress)> = KINDS
        .iter()
        .enumerate()
        .map(|(k, bit)| (lit(1 << k), *bit))
        .collect();
    bits.push((neg(1), DECODED_MASK));
    enforcing.push(("decoded_mask_bits".into(), linear(bits)));
    enforcing.push(("wrap_boolean".into(), booleanity(WRAP)));
    enforcing.push(("bit0_boolean".into(), booleanity(BIT0)));
    enforcing.push(("bit1_boolean".into(), booleanity(BIT1)));

    let mut all = LOADS.to_vec();
    all.extend(STORES);
    enforcing.push((
        "rs1_mask_rule".into(),
        mask_rule(frame(SLOT_RS1, FIELD_MASK), &all),
    ));
    enforcing.push((
        "rs2_mask_rule".into(),
        mask_rule(frame(SLOT_RS2, FIELD_MASK), &STORES),
    ));
    enforcing.push((
        "load_mask_rule".into(),
        mask_rule(frame(SLOT_LOAD, FIELD_MASK), &LOADS),
    ));
    enforcing.push((
        "ram_mask_rule".into(),
        mask_rule(frame(SLOT_RAM, FIELD_MASK), &STORES),
    ));
    enforcing.push((
        "rd_mask_rule".into(),
        mask_rule(frame(SLOT_RD, FIELD_MASK), &LOADS),
    ));
    enforcing.push(("rs1_addr_rule".into(), addr_rule(SLOT_RS1, DECODED_RS1)));
    enforcing.push(("rs2_addr_rule".into(), addr_rule(SLOT_RS2, DECODED_RS2)));
    enforcing.push(("rd_addr_rule".into(), addr_rule(SLOT_RD, DECODED_RD)));
    enforcing.push(("load_addr_rule".into(), word_addr_rule(SLOT_LOAD)));
    enforcing.push(("ram_addr_rule".into(), word_addr_rule(SLOT_RAM)));
    // The advice selector and its two consequences, `docs/spec/advice.md` §3
    // and §4. `mem_word` carries the same four gates; the only difference here
    // is which selectors make up a store.
    enforcing.push((
        "advice_split".into(),
        linear(vec![
            (lit(1), WORD_INDEX_HI),
            (neg(1 << 13), IS_ADVICE),
            (neg(1), WORD_INDEX_HI_REST),
        ]),
    ));
    enforcing.push(("is_advice_boolean".into(), booleanity(IS_ADVICE)));
    let m_load = frame(SLOT_LOAD, FIELD_MASK);
    enforcing.push((
        "load_space_rule".into(),
        quadratic(
            vec![
                (lit(1), load_space(QUERIES.len())),
                (neg(address_space::RAM as u64), m_load),
            ],
            vec![(
                neg((address_space::ADVICE - address_space::RAM) as u64),
                m_load,
                IS_ADVICE,
            )],
        ),
    ));
    enforcing.push((
        "no_store_to_advice".into(),
        quadratic(
            vec![],
            vec![(lit(1), frame(SLOT_RAM, FIELD_MASK), IS_ADVICE)],
        ),
    ));
    enforcing.push(("rs1_value_masked".into(), value_masked(SLOT_RS1)));
    enforcing.push(("rs2_value_masked".into(), value_masked(SLOT_RS2)));

    // addr = 4·word_index + 2·bit1 + bit0, over ℤ and not over Fr: the range
    // check on `word_index` is what makes the split genuinely base-4
    // (`docs/spec/memory-ops.md` §2).
    enforcing.push((
        "addr_split".into(),
        linear(vec![
            (lit(1), v_rs1),
            (lit(1), IMM),
            (Coeff::Literal(-Fr::from_u64(1 << 32)), WRAP),
            (neg(4), WORD_INDEX),
            (neg(2), BIT1),
            (neg(1), BIT0),
        ]),
    ));
    // A halfword access has bit 0 clear. Nothing else gives bit 0 any effect
    // at that width, and without this gate `w·p` reaches 2^40, which is what
    // the whole write-side bound of §5.2 rests on not happening.
    enforcing.push((
        "half_aligned".into(),
        quadratic(vec![], form_times(lit(1), &HALVES, BIT0)),
    ));
    // word = the word a load read, or the word a store is rewriting.
    let mut word_terms = form_times(neg(1), &LOADS, frame(SLOT_LOAD, FIELD_READ_VALUE));
    word_terms.extend(form_times(
        neg(1),
        &STORES,
        frame(SLOT_RAM, FIELD_READ_VALUE),
    ));
    enforcing.push((
        "word_rule".into(),
        quadratic(vec![(lit(1), WORD)], word_terms),
    ));
    enforcing.push((
        "p_ram_rule".into(),
        quadratic(
            vec![(lit(1), P_RAM)],
            vec![(neg(1), frame(SLOT_RAM, FIELD_MASK), P)],
        ),
    ));
    enforcing.push((
        "se_rule".into(),
        quadratic(vec![(lit(1), SE)], form_times(neg(1), &SIGNED, SIGN)),
    ));
    enforcing.extend(splice_gates(BYTE_BITS));
    enforcing.push((
        "next_pc_rule".into(),
        linear(vec![(lit(1), next_pc), (neg(1), SEQ)]),
    ));

    let mut lookups = Vec::new();
    lookups.extend(range32("word_index", WORD_INDEX, WORD_INDEX_HI));
    lookups.push(range16(
        "word_index_hi_rest_range",
        column(WORD_INDEX_HI_REST),
    ));
    lookups.push(range16(
        "word_index_hi_rest_scaled",
        linear(vec![(lit(8), WORD_INDEX_HI_REST)]),
    ));

    lookups.extend(range32("high", HIGH, HIGH_HI));
    lookups.extend(range32("high_scaled", HIGH_SCALED, HIGH_SCALED_HI));
    // `sub` and `src_sub` are below the access width, at most a halfword, so
    // one halfword obligation is their exact direct bound and a 16+16 pair
    // would be two obligations saying the same thing.
    lookups.push(range16("sub_range", column(SUB)));
    lookups.extend(range32("sub_scaled", SUB_SCALED, SUB_SCALED_HI));
    lookups.extend(range32("low", LOW, LOW_HI));
    lookups.extend(range32("low_scaled", LOW_SCALED, LOW_SCALED_HI));
    lookups.push(range16("src_sub_range", column(SRC_SUB)));
    lookups.extend(range32("src_sub_scaled", SRC_SUB_SCALED, SRC_SUB_SCALED_HI));
    lookups.extend(range32("src_high", SRC_HIGH, SRC_HIGH_HI));
    // The `U16GetSign` key's own bound: `sign_in < 2^16` puts the gated key
    // inside that sub-table's range and nowhere else (`docs/spec/lookup.md`
    // §4). The sub-table's key range is exactly a halfword wide, so this
    // single obligation is the exact bound and needs no scaled partner.
    lookups.push(range16("sign_in_range", column(SIGN_IN)));
    lookups.extend(range32("rd", sel, RD_HI));
    // The `+ 1` that keeps a real entry off the ZeroEntry is the channel's,
    // added by `lookup::Gating::ZeroEntry`; writing it here would shift every
    // key one row.
    lookups.push(LookupExpr {
        name: "sub_get_sign".into(),
        channel: lookup_channel::GENERIC,
        selector: m_pc,
        tuple: vec![
            GateDef::Linear {
                terms: vec![(lit(1), SIGN_IN)],
                constant: lit(generic_table::SIGN_BASE as u64),
            },
            column(SIGN),
            linear(vec![]),
        ],
    });
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
    assert!(
        a.padding.zero_row_valid,
        "mem_subword: a gate is nonzero on the all-zero row"
    );
    for (channel, want) in [
        (lookup_channel::TIMESTAMP, 2 * QUERIES.len()),
        (lookup_channel::RANGE16, 23),
        (lookup_channel::GENERIC, 1),
        (lookup_channel::DECODER, 1),
    ] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(
            got,
            want,
            "mem_subword: channel `{}` carries {got} obligations, not {want}",
            lookup_channel::NAMES[channel as usize]
        );
    }
    assert_eq!(
        a.layers[0].enforcing.len(),
        57,
        "mem_subword: the circuit's enforcing gates are the frame's 13 and this family's 44"
    );
    // Every column a copower or a literal scales carries its own direct bound
    // under the same selector; a scaled bound alone bounds nothing
    // (`docs/spec/lookup.md` §11).
    let m_pc = frame(SLOT_PC, FIELD_MASK);
    if let Err(e) = check_copowers(
        &a,
        &[
            (WORD_INDEX_HI_REST, m_pc),
            (HIGH, m_pc),
            (SUB, m_pc),
            (LOW, m_pc),
            (SRC_SUB, m_pc),
        ],
    ) {
        panic!("mem_subword: {e}");
    }
    a
}

/// The family's four channels, in output order: the timestamp gaps over
/// `V[range19]`, the halfwords over `V[range16]`, the one sign lookup over the
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

    /// The legal masks are six distinct single bits, one per instruction the
    /// family owns, each the bit its `extra_mask` constant names.
    #[test]
    fn the_legal_masks_are_the_instruction_list() {
        assert_eq!(LEGAL_MASKS, [1, 2, 4, 8, 16, 32]);
        for (k, m) in LEGAL_MASKS.iter().enumerate() {
            assert_eq!(*m, 1 << k);
        }
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
    #[should_panic(expected = "channel `range16` carries 22 obligations, not 23")]
    fn a_dropped_obligation_fails_the_build() {
        let mut e = family_spec();
        e.lookups.retain(|l| l.name != "low_lo_range");
        assemble(20, e);
    }

    /// `sub`'s direct bound moved under a selector the scaled obligation does
    /// not carry: the count holds, and the copower check refuses it.
    #[test]
    #[should_panic(expected = "copower pairing")]
    fn a_direct_bound_under_a_narrower_selector_fails_the_build() {
        let mut e = family_spec();
        let l = e
            .lookups
            .iter_mut()
            .find(|l| l.name == "sub_range")
            .expect("the direct bound");
        l.selector = KINDS[kind::LB as usize];
        assemble(20, e);
    }

    /// A gate that is nonzero on the all-zero row is refused: a shard's
    /// padding rows are all zero.
    #[test]
    #[should_panic(expected = "a gate is nonzero on the all-zero row")]
    fn a_gate_nonzero_on_the_zero_row_fails_the_build() {
        let mut e = family_spec();
        e.enforcing.push((
            "bit0_is_one".into(),
            GateDef::Linear {
                terms: vec![(lit(1), BIT0)],
                constant: neg(1),
            },
        ));
        assemble(20, e);
    }

    /// The width seam refuses a width with no sub-word and one whose word
    /// would not fit 32 bits.
    #[test]
    #[should_panic(expected = "a byte is 1 to 8 bits wide")]
    fn the_splice_seam_refuses_a_zero_width() {
        splice_gates(0);
    }

    #[test]
    #[should_panic(expected = "a byte is 1 to 8 bits wide")]
    fn the_splice_seam_refuses_a_width_past_a_word() {
        splice_gates(9);
    }
}
