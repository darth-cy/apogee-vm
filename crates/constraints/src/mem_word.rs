//! The `MEM_WORD` family's circuit: `lw` and `sw`.
//!
//! `docs/spec/memory-ops.md` is normative: the columns, the gates, the lookups
//! and the argument. This file is that document as data, assembled by S15's
//! `memory::frame_with_channels_artifact` beside S14's frame.
//!
//! The whole family is the addressing of `docs/spec/memory-ops.md` §2 plus two
//! one-line semantics: a load copies the word it read into `rd`, a store copies
//! `rs2` into the word. There is no splice — a word access takes the whole
//! word — and no generic lookup, so this is the only S19 family whose setup
//! columns are the decoded table alone.
//!
//! ```text
//! frame     M[0..31], W[0..9]: pc rs1 rs2 load ram rd at slots 0..6
//! W[9..15]  the claimed decoded row: next_pc rs1 rs2 rd imm mask
//! W[15..17] the mask's two bits, extra_mask::mem_word order
//! W[17..20] wrap, word_index, word_index_hi
//! W[20]     rd_hi
//! W[21..24] one multiplicity per channel: timestamp, range16, decoder
//! S[0..7]   the decoded table, program::lookup_tuple order
//! ```

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use constants::extra_mask::mem_word as kind;
use constants::{family, lookup_channel};
use field::Fr;

use crate::lookup::{check_copowers, ChannelSpec};
use crate::memory::{
    frame, frame_queries, frame_with_channels_artifact, rd_selected, FamilySpec, FIELD_ADDR,
    FIELD_MASK, FIELD_READ_VALUE, FIELD_WRITE_VALUE, LOAD, PC, RAM, RD, RS1, RS2,
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

/// `W[15..17]`: the packed mask's bits, bit `k` at index `k` —
/// `constants::extra_mask::mem_word`'s order: `lw`, `sw`.
pub const KINDS: [PolyAddress; 2] = [w(6), w(7)];
const LW: PolyAddress = KINDS[kind::LW as usize];
const SW: PolyAddress = KINDS[kind::SW as usize];

/// `W[17]`: the wrap of `rs1 + imm`, the effective address before reduction.
pub const WRAP: PolyAddress = w(8);
/// `W[18]`, `W[19]`: the accessed word's index — the memory tuple's address is
/// `4·word_index` — and its high halfword.
pub const WORD_INDEX: PolyAddress = w(9);
pub const WORD_INDEX_HI: PolyAddress = w(10);
/// `W[20]`: the written `rd` value's high halfword.
pub const RD_HI: PolyAddress = w(11);
/// `W[21..24]`: the channels' multiplicities, in channel order — timestamp,
/// range16, decoder — last in the witness subtree (`docs/spec/lookup.md` §7).
/// There is no generic channel: this family looks nothing up in the packed
/// table.
pub const MULTIPLICITIES: [PolyAddress; 3] = [w(12), w(13), w(14)];

/// The decoded table's width, `program::lookup_tuple(MEM_WORD)`:
/// `pc next_pc rs1 rs2 rd imm extra_mask`, at `S[0..7]`.
pub const TABLE_WIDTH: usize = 7;

/// The decoded masks a live row of this family can carry: one bit per
/// instruction, in `constants::extra_mask::mem_word` order. The table's domain
/// is what enforces the set (`docs/spec/lookup.md` §10).
pub const LEGAL_MASKS: [u32; 2] = [1 << kind::LW, 1 << kind::SW];

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

/// `m_q·(a_q − 4·word_index)`: a present RAM query's address is the accessed
/// word's byte address, `docs/spec/memory-ops.md` §2. No byte offset reaches a
/// memory tuple: sub-word and word accesses name the same cell.
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

/// The family's circuit over `2^trace_vars` rows,
/// `docs/spec/memory-ops.md` §3. `trace_vars` is at least 19, the timestamp
/// channel's width, which the registry refuses below; a Mercury opening needs
/// it even as well.
///
/// Panics if the family's frame is not the six queries this file addresses, if
/// any channel's obligation count is not the document's — 12 timestamp, 5
/// `RANGE16`, 1 decoder — if `word_index_hi`, which the alignment obligation
/// scales by 4, lacks its direct range check, if a gate is nonzero on the
/// all-zero padding row, and on every refusal of the assembly.
pub fn artifact(trace_vars: u32) -> CircuitArtifact {
    assemble(trace_vars, family_spec())
}

/// The family's sub-circuit: its columns, gates, lookups and channels, before
/// the assembly onto the frame.
fn family_spec() -> FamilySpec {
    assert_eq!(
        frame_queries(family::MEM_WORD),
        &QUERIES,
        "mem_word: the family's frame is the six queries this circuit addresses by slot"
    );
    let m_pc = frame(SLOT_PC, FIELD_MASK);
    let pc = frame(SLOT_PC, FIELD_READ_VALUE);
    let next_pc = frame(SLOT_PC, FIELD_WRITE_VALUE);
    let v_rs1 = frame(SLOT_RS1, FIELD_READ_VALUE);
    let v_rs2 = frame(SLOT_RS2, FIELD_READ_VALUE);
    let loaded = frame(SLOT_LOAD, FIELD_READ_VALUE);
    let stored = frame(SLOT_RAM, FIELD_WRITE_VALUE);
    let sel = rd_selected(QUERIES.len());

    let kind_names = ["lw", "sw"];
    let mut witness = names(&[
        "decoded_next_pc",
        "decoded_rs1",
        "decoded_rs2",
        "decoded_rd",
        "decoded_imm",
        "decoded_mask",
    ]);
    witness.extend(kind_names.iter().map(|k| format!("kind_{k}")));
    witness.extend(names(&["wrap", "word_index", "word_index_hi", "rd_hi"]));
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
    enforcing.push(("wrap_boolean".into(), booleanity(WRAP)));

    // Presence: a load reads rs1 and the word and writes rd; a store reads rs1
    // and rs2 and rewrites the word. Each mask is `m_pc` times its kind's use,
    // so a padding row reaches no memory event (`docs/spec/memory.md` §2.1).
    enforcing.push((
        "rs1_mask_rule".into(),
        mask_rule(frame(SLOT_RS1, FIELD_MASK), &[LW, SW]),
    ));
    enforcing.push((
        "rs2_mask_rule".into(),
        mask_rule(frame(SLOT_RS2, FIELD_MASK), &[SW]),
    ));
    enforcing.push((
        "load_mask_rule".into(),
        mask_rule(frame(SLOT_LOAD, FIELD_MASK), &[LW]),
    ));
    enforcing.push((
        "ram_mask_rule".into(),
        mask_rule(frame(SLOT_RAM, FIELD_MASK), &[SW]),
    ));
    enforcing.push((
        "rd_mask_rule".into(),
        mask_rule(frame(SLOT_RD, FIELD_MASK), &[LW]),
    ));
    enforcing.push(("rs1_addr_rule".into(), addr_rule(SLOT_RS1, DECODED_RS1)));
    enforcing.push(("rs2_addr_rule".into(), addr_rule(SLOT_RS2, DECODED_RS2)));
    enforcing.push(("rd_addr_rule".into(), addr_rule(SLOT_RD, DECODED_RD)));
    enforcing.push(("load_addr_rule".into(), word_addr_rule(SLOT_LOAD)));
    enforcing.push(("ram_addr_rule".into(), word_addr_rule(SLOT_RAM)));
    enforcing.push(("rs1_value_masked".into(), value_masked(SLOT_RS1)));
    enforcing.push(("rs2_value_masked".into(), value_masked(SLOT_RS2)));

    // addr_split: rs1 + imm − 2^32·wrap = 4·word_index, with no room for a
    // byte offset. `word_index < 2^30` from its three obligations makes the
    // right side a 32-bit integer, so the field identity is the integer one:
    // `wrap` is the true carry and a misaligned `lw` or `sw` has no witness at
    // all (`docs/spec/memory-ops.md` §2).
    enforcing.push((
        "addr_split".into(),
        linear(vec![
            (lit(1), v_rs1),
            (lit(1), IMM),
            (Coeff::Literal(-Fr::from_u64(1 << 32)), WRAP),
            (neg(4), WORD_INDEX),
        ]),
    ));
    // A load writes the word it read; a store writes rs2 into the word. Each
    // is a copy, so the frame's own bound on the source is the only one there
    // is — except that `rd_selected` carries a range pair of its own, which is
    // what keeps every register value in this VM locally 32-bit
    // (`docs/spec/memory-ops.md` §5.1).
    enforcing.push((
        "rd_value_rule".into(),
        quadratic(vec![(lit(1), sel)], vec![(neg(1), LW, loaded)]),
    ));
    enforcing.push((
        "store_value_rule".into(),
        quadratic(
            vec![(lit(1), stored)],
            vec![(neg(1), frame(SLOT_RAM, FIELD_MASK), v_rs2)],
        ),
    ));
    // No kind here computes a pc, so `next_pc` is the decoded fall-through,
    // degree 1, with no wrap bit and no bound of its own — S18's reading, which
    // `crates/constraints/src/shift_bitwise.rs` states in full.
    enforcing.push((
        "next_pc_rule".into(),
        linear(vec![(lit(1), next_pc), (neg(1), SEQ)]),
    ));

    let mut lookups = Vec::new();
    lookups.extend(range32("word_index", WORD_INDEX, WORD_INDEX_HI));
    // `4·word_index_hi < 2^16` is `word_index_hi < 2^14`, so `word_index` is
    // below `2^30` and `4·word_index` is a 32-bit byte address. This is the
    // one obligation that makes the base-4 split genuinely base-4.
    lookups.push(range16(
        "word_index_hi_scaled",
        linear(vec![(lit(4), WORD_INDEX_HI)]),
    ));
    lookups.extend(range32("rd", sel, RD_HI));
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
    // A shard's padding rows are all zero, which every gate must accept. It is
    // checked first so that a gate breaking it is named as that rather than as
    // a wrong count.
    assert!(
        a.padding.zero_row_valid,
        "mem_word: a gate is nonzero on the all-zero row"
    );
    // Every obligation is built above and then handed over, so a count is what
    // shows none was dropped on the way (S14 must-be-exact 5, S15's per-channel
    // form).
    for (channel, want) in [
        (lookup_channel::TIMESTAMP, 2 * QUERIES.len()),
        (lookup_channel::RANGE16, 5),
        (lookup_channel::DECODER, 1),
    ] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(
            got,
            want,
            "mem_word: channel `{}` carries {got} obligations, not {want}",
            lookup_channel::NAMES[channel as usize]
        );
    }
    assert_eq!(
        a.layers[0].enforcing.len(),
        33,
        "mem_word: the circuit's enforcing gates are the frame's 13 and this family's 20"
    );
    // The alignment obligation scales `word_index_hi` by 4, which bounds
    // nothing unless `word_index_hi` is bounded directly too.
    if let Err(e) = check_copowers(&a, &[(WORD_INDEX_HI, frame(SLOT_PC, FIELD_MASK))]) {
        panic!("mem_word: {e}");
    }
    a
}

/// The family's three channels, in output order: the timestamp gaps over
/// `V[range19]`, the halfwords over `V[range16]`, and the decoder over the
/// family's decoded table at `S[0..7]`. There is no generic channel.
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

    /// The legal masks are two distinct single bits, one per instruction the
    /// family owns, and each is the bit its `extra_mask` constant names.
    #[test]
    fn the_legal_masks_are_the_instruction_list() {
        assert_eq!(LEGAL_MASKS, [1, 2]);
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
    #[should_panic(expected = "channel `range16` carries 4 obligations, not 5")]
    fn a_dropped_obligation_fails_the_build() {
        let mut e = family_spec();
        e.lookups.retain(|l| l.name != "word_index_hi_scaled");
        assemble(20, e);
    }

    /// `word_index_hi`'s direct bound replaced by one that bounds nothing the
    /// scaled obligation needs: the count holds, and the copower check refuses
    /// it.
    #[test]
    #[should_panic(expected = "copower pairing")]
    fn word_index_without_its_direct_bound_fails_the_build() {
        let mut e = family_spec();
        let l = e
            .lookups
            .iter_mut()
            .find(|l| l.name == "word_index_hi_range")
            .expect("the direct bound");
        l.tuple = vec![linear(vec![(lit(2), WORD_INDEX_HI)])];
        assemble(20, e);
    }

    /// A gate that is nonzero on the all-zero row is refused: a shard's
    /// padding rows are all zero.
    #[test]
    #[should_panic(expected = "a gate is nonzero on the all-zero row")]
    fn a_gate_nonzero_on_the_zero_row_fails_the_build() {
        let mut e = family_spec();
        e.enforcing.push((
            "wrap_is_one".into(),
            GateDef::Linear {
                terms: vec![(lit(1), WRAP)],
                constant: neg(1),
            },
        ));
        assemble(20, e);
    }
}
