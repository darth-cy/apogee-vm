//! S19's `MEM_SUBWORD` circuit — `lb`, `lh`, `lbu`, `lhu`, `sb`, `sh` — row by
//! row, in ordinary CI.
//!
//! No forward pass over `2^20` rows: each row is built by hand from what the
//! instruction computes — Rust's own `u32` and `u64` arithmetic, not the
//! circuit's — and evaluated alone through `checker::violated_relations` and
//! `violated_lookups`, its row-local scratch computed by `gkr::gate_values`.
//! The two table channels, which `violated_lookups` does not read, are held
//! here to the tables themselves: a row's gated generic tuple to
//! `program::lookup_tables`' entries, its gated decoder tuple to the table
//! columns the row carries. The fills of the same three families over a real
//! trace are `crates/checker/tests/mem_fill.rs`', and the proofs are
//! `crates/prover/tests/mem.rs`'.
//!
//! Acceptance 2 is here in full, as
//! [`the_splice_admits_exactly_one_witness_at_a_reduced_width`]: the width seam
//! `mem_subword::splice_gates` called at one bit to a byte, and every candidate
//! decomposition of every four-bit word enumerated through `gkr::eval_gate`
//! over the family's own gates. The negative half is the rows below it — a
//! sub-word read from the wrong position, a byte that is not one, a free
//! `high`, a store source unrelated to `rs2` and a sign that is not the
//! sub-word's.

use std::collections::{BTreeMap, BTreeSet};

use checker::{
    check_laws, check_lookup_discharge, check_padding, check_padding_identity, violated_lookups,
    violated_relations, WitnessRow,
};
use constants::extra_mask::mem_subword as kind;
use constants::{challenge_slot, family, generic_table, lookup_channel};
use constraints::lookup::{check_discharge, ChannelSpec};
use constraints::memory::{
    check_memory, frame, frame_queries, rd_selected, FIELD_MASK, FIELD_READ_VALUE,
    FIELD_WRITE_VALUE, PC, RAM, RS2,
};
use constraints::{
    family_circuit, mem_subword, CircuitArtifact, GateDef, PolyAddress, VirtualKind,
};
use field::Fr;
use gkr::{eval_gate, gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use program::lookup_tables::generic_entries;
use test_support::{sha256, to_hex};

const VARS: u32 = 20;
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/mem_subword.bin"
);
const FIXTURE_SHA256: &str = "2c423eb1c5dc9b8a3c326dcb32b57f2a0edecffbb5ca9041e1a6cc9f9f596181";

/// The cycle every hand-built row runs at, and the row it is evaluated at.
const CYCLE: u64 = 7;
const AT_ROW: usize = 1 << 15;

/// The RAM word every hand-built access lands on: its four bytes are `0x01`,
/// `0x7f`, `0xfe` and `0x88` and its two halfwords `0x7f01` and `0x88fe`, so
/// one word carries a positive and a negative byte and a positive and a
/// negative halfword.
const MEM: u32 = 0x88FE_7F01;

/// The base address a row computes from: `x5` holds it and the displacement
/// picks the offset within its word.
const BASE: u32 = 0x2000_0000;

/// The word a store's source register holds. Its high bytes are nonzero, so
/// `src_sub` is a real truncation of `rs2` and not a copy of it.
const SOURCE: u32 = 0xDEAD_BEEF;

fn artifact() -> CircuitArtifact {
    mem_subword::artifact(VARS)
}

fn f(v: u64) -> Fr {
    Fr::from_u64(v)
}

fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn challenges(a: &CircuitArtifact) -> ExternalChallenges {
    let mut ch = ExternalChallenges::new();
    for (slot, v) in [
        (challenge_slot::MEM_GAMMA, 11),
        (challenge_slot::MEM_ALPHA_ADDR, 13),
        (challenge_slot::MEM_ALPHA_TS, 17),
        (challenge_slot::MEM_ALPHA_VAL, 19),
    ] {
        ch.insert(slot, f(v));
    }
    insert_lookup_challenges(&mut ch, f(23), f(29), a);
    ch
}

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// A row by column name; a column not named is 0.
#[derive(Clone, Debug, Default)]
struct Row(BTreeMap<&'static str, Fr>);

/// `<q>_<field>`, a column name, leaked to `'static` for the map.
fn name(q: &str, field: &str) -> &'static str {
    leak(format!("{q}_{field}"))
}

impl Row {
    fn set(&mut self, name: &'static str, v: Fr) -> &mut Row {
        self.0.insert(name, v);
        self
    }

    fn get(&self, name: &str) -> Fr {
        self.0.get(name).copied().unwrap_or(Fr::ZERO)
    }

    /// Set the query `q`'s five columns, reading a write made eight timestamps
    /// before its own.
    fn query(&mut self, q: &'static str, delta: u64, addr: u64, read: u64, write: u64) {
        self.set(name(q, "mask"), Fr::ONE)
            .set(name(q, "addr"), f(addr))
            .set(name(q, "read_ts"), f(4 * CYCLE + delta - 8))
            .set(name(q, "read_value"), f(read))
            .set(name(q, "write_value"), f(write));
    }

    /// Remove every one of the query `q`'s five columns.
    fn drop_query(&mut self, q: &'static str) {
        for field in ["mask", "addr", "read_ts", "read_value", "write_value"] {
            self.0.remove(name(q, field));
        }
    }

    /// The row's committed values in layout order.
    fn committed(&self, a: &CircuitArtifact) -> Vec<Fr> {
        let names: Vec<&str> = a
            .memory
            .iter()
            .chain(&a.witness)
            .chain(&a.setup)
            .map(|s| s.as_str())
            .collect();
        for key in self.0.keys() {
            assert!(names.contains(key), "the circuit has no column `{key}`");
        }
        names.iter().map(|n| self.get(n)).collect()
    }

    /// The row as a witness row of `a`, its scratch computed row-locally.
    fn witness(&self, a: &CircuitArtifact, row: usize) -> WitnessRow {
        let committed = self.committed(a);
        let virtuals: Vec<Fr> = a
            .virtuals
            .iter()
            .map(|(k, _)| virtual_at_row(*k, row))
            .collect();
        let ch = challenges(a);
        let mut scratch = vec![Fr::ZERO; a.scratch.len()];
        let mut lower = committed.clone();
        for k in 0..a.depth() {
            if a.layers[k].halving {
                break;
            }
            let v: &[Fr] = if k == 0 { &virtuals } else { &[] };
            let values = gate_values(a, k, &lower, &[], v, &ch);
            let produced = values[..a.layers[k].producing.len()].to_vec();
            for (j, value) in produced.iter().enumerate() {
                let address = PolyAddress::Inner {
                    layer: k as u32 + 1,
                    offset: j as u32,
                };
                let slot = a.scratch.iter().position(|s| s.address == address);
                scratch[slot.expect("every inner column has a scratch slot")] = *value;
            }
            lower = produced;
        }
        WitnessRow {
            committed,
            row,
            scratch,
        }
    }
}

/// One instruction of the family, as a decoded table row and its operands.
#[derive(Clone, Copy, Debug)]
struct Instr {
    bit: u32,
    pc: u32,
    rs1: u32,
    rs2: u32,
    rd: u32,
    /// The decoded immediate: the displacement, two's complement, as S11's
    /// table holds it.
    imm: u32,
    compressed: bool,
}

impl Instr {
    /// The kind at displacement `imm`, over `x5` as the base register, `x6` as
    /// a store's source and `x7` as a load's destination. A load's decoded
    /// `rs2` and a store's decoded `rd` are 0, the form having no such field.
    fn new(bit: u32, imm: u32) -> Instr {
        Instr {
            bit,
            pc: 0x1000,
            rs1: 5,
            rs2: if is_load(bit) { 0 } else { 6 },
            rd: if is_load(bit) { 7 } else { 0 },
            imm,
            compressed: false,
        }
    }
}

/// Whether the kind reads a word and writes a register.
fn is_load(bit: u32) -> bool {
    matches!(bit, kind::LB | kind::LH | kind::LBU | kind::LHU)
}

/// Whether the kind accesses one byte rather than a halfword.
fn is_byte(bit: u32) -> bool {
    matches!(bit, kind::LB | kind::LBU | kind::SB)
}

/// Whether the kind sign-extends what it loaded.
fn sign_extends(bit: u32) -> bool {
    matches!(bit, kind::LB | kind::LH)
}

fn mnemonic(bit: u32) -> &'static str {
    ["lb", "lh", "lbu", "lhu", "sb", "sh"][bit as usize]
}

/// The splice of `word` at access width `w` and splice power `p`: the three
/// parts, each with the column whose range bounds it, and the two derived
/// constants. Rust's own integer division does the work — the copower and the
/// high multiplier are halved, as the columns are.
fn splice(r: &mut Row, word: u64, w: u64, p: u64) {
    let (low, sub, high) = (word % p, (word / p) % w, word / (w * p));
    for (column, v) in [
        ("p", p),
        ("pcopow", (1u64 << 31) / p),
        ("wph", w * p / 2),
        ("word", word),
        ("high", high),
        ("high_hi", high >> 16),
        ("high_scaled", high * w * p),
        ("high_scaled_hi", (high * w * p) >> 16),
        ("sub", sub),
        ("sub_scaled", sub * ((1u64 << 32) / w)),
        ("sub_scaled_hi", (sub * ((1u64 << 32) / w)) >> 16),
        ("low", low),
        ("low_hi", low >> 16),
        ("low_scaled", low * ((1u64 << 32) / p)),
        ("low_scaled_hi", (low * ((1u64 << 32) / p)) >> 16),
    ] {
        r.set(leak(column.to_string()), f(v));
    }
}

/// An honest row: every column what the instruction computes, by Rust's own
/// arithmetic, over the base register value `rs1v`, the source register value
/// `rs2v`, the word `mem` already at the accessed address and the register
/// value `rd_old` a load overwrites.
///
/// The alignment of a halfword access is **not** asserted here: an odd one is
/// a row the splice is perfectly consistent on, and `half_aligned` is the one
/// gate that refuses it (`a_halfword_at_an_odd_address_is_unprovable`).
fn honest(i: Instr, rs1v: u32, rs2v: u32, mem: u32, rd_old: u32) -> Row {
    let (byte, load) = (is_byte(i.bit), is_load(i.bit));
    let sum = rs1v as u64 + i.imm as u64;
    let (address, wrap) = (sum as u32, sum >> 32);
    let (bit0, bit1) = ((address & 1) as u64, ((address >> 1) & 1) as u64);
    let word_index = (address / 4) as u64;
    let p = 1u64 << (8 * (address & 3));
    let w = if byte { 1u64 << 8 } else { 1u64 << 16 };
    let word = mem as u64;
    let (low, sub, high) = (word % p, (word / p) % w, word / (w * p));
    // A load makes no `rs2` query, so the source the row reads is 0.
    let src = if load { 0 } else { rs2v as u64 };
    let (src_sub, src_high) = (src % w, src / w);
    let sign_in = sub * if byte { 1 << 8 } else { 1 };
    let sign = sign_in >> 15;
    let se = (sign_extends(i.bit) && sign == 1) as u64;
    let sel = match load {
        true => sub + se * ((1u64 << 32) - w),
        false => 0,
    };
    let stored = high * w * p + src_sub * p + low;
    let seq = i.pc + if i.compressed { 2 } else { 4 };

    let mut r = Row::default();
    r.set("cycle", f(CYCLE));
    r.set("pc_mask", Fr::ONE)
        .set("pc_read_ts", f(4 * (CYCLE - 1)))
        .set("pc_read_value", f(i.pc as u64))
        .set("pc_write_value", f(seq as u64));
    r.query("rs1", 1, i.rs1 as u64, rs1v as u64, rs1v as u64);
    match load {
        true => {
            r.query("load", 2, 4 * word_index, word, word);
            let write = if i.rd == 0 { 0 } else { sel };
            r.query("rd", 3, i.rd as u64, rd_old as u64, write);
            match i.rd {
                0 => r.set("rd_is_zero", Fr::ONE),
                d => r.set("rd_inv", f(d as u64).inverse().expect("nonzero")),
            };
        }
        false => {
            r.query("rs2", 2, i.rs2 as u64, src, src);
            r.query("ram", 3, 4 * word_index, word, stored);
        }
    }
    r.set("rd_selected", f(sel));

    // The decoded row, in both places it appears: the claimed witness columns
    // and the table columns the decoder lookup matches them against.
    let mask = 1u32 << i.bit;
    for (witness, table, v) in [
        ("decoded_next_pc", "table_next_pc", seq),
        ("decoded_rs1", "table_rs1", i.rs1),
        ("decoded_rs2", "table_rs2", i.rs2),
        ("decoded_rd", "table_rd", i.rd),
        ("decoded_imm", "table_imm", i.imm),
        ("decoded_mask", "table_extra_mask", mask),
    ] {
        r.set(witness, f(v as u64)).set(table, f(v as u64));
    }
    r.set("table_pc", f(i.pc as u64));
    r.set(name("kind", mnemonic(i.bit)), Fr::ONE);

    splice(&mut r, word, w, p);
    for (column, v) in [
        ("wrap", wrap),
        ("word_index", word_index),
        ("word_index_hi", word_index >> 16),
        ("bit0", bit0),
        ("bit1", bit1),
        ("p_ram", if load { 0 } else { p }),
        ("src_sub", src_sub),
        ("src_sub_scaled", src_sub * ((1u64 << 32) / w)),
        ("src_sub_scaled_hi", (src_sub * ((1u64 << 32) / w)) >> 16),
        ("src_high", src_high),
        ("src_high_hi", src_high >> 16),
        ("sign_in", sign_in),
        ("sign", sign),
        ("se", se),
        ("rd_hi", sel >> 16),
    ] {
        r.set(leak(column.to_string()), f(v));
    }
    r
}

/// A lookup expression's value on the committed row.
fn expression(a: &CircuitArtifact, committed: &[Fr], gate: &GateDef) -> Fr {
    let layout = a.committed();
    let values: Vec<Fr> = gate
        .operands()
        .iter()
        .map(|op| {
            committed[layout
                .iter()
                .position(|x| x == op)
                .expect("a committed operand")]
        })
        .collect();
    eval_gate(gate, &values, &ExternalChallenges::new())
}

/// The canonical integer of a field element, if it is below `2^64`.
fn small_int(v: Fr) -> Option<u64> {
    let bytes = v.to_bytes();
    bytes[8..]
        .iter()
        .all(|b| *b == 0)
        .then(|| u64::from_le_bytes(bytes[..8].try_into().expect("eight bytes")))
}

/// The names of the **table**-channel lookups the row violates — the two
/// channels `violated_lookups` does not read. Each lookup is read under its
/// own selector: a selector moved to another column is a different circuit,
/// and this is what sees it.
fn violated_tables(a: &CircuitArtifact, r: &Row) -> Vec<String> {
    let committed = r.committed(a);
    let layout = a.committed();
    let entries: BTreeSet<[u64; generic_table::WIDTH]> = generic_entries()
        .iter()
        .map(|e| e.map(|x| x as u64))
        .collect();
    let mut out = Vec::new();
    for l in &a.lookups {
        let at = layout
            .iter()
            .position(|x| *x == l.selector)
            .expect("a selector is a committed column");
        let s = committed[at];
        let values: Vec<Fr> = l
            .tuple
            .iter()
            .map(|e| expression(a, &committed, e))
            .collect();
        let holds = match l.channel {
            lookup_channel::GENERIC => {
                let gated = [s * (values[0] + Fr::ONE), s * values[1], s * values[2]];
                gated.iter().all(|v| *v == Fr::ZERO)
                    || gated
                        .iter()
                        .map(|v| small_int(*v))
                        .collect::<Option<Vec<u64>>>()
                        .is_some_and(|t| entries.contains(&[t[0], t[1], t[2]]))
            }
            lookup_channel::DECODER => {
                let table: Vec<Fr> = (0..mem_subword::TABLE_WIDTH)
                    .map(|j| committed[a.memory.len() + a.witness.len() + j])
                    .collect();
                let gated: Vec<Fr> = values
                    .iter()
                    .map(|v| s * (*v + Fr::ONE) - Fr::ONE)
                    .collect();
                gated == table || gated.iter().all(|v| *v == Fr::MINUS_ONE)
            }
            _ => continue,
        };
        if !holds {
            out.push(l.name.clone());
        }
    }
    out
}

/// `(relations, range lookups, table lookups)` the row violates.
fn violated(a: &CircuitArtifact, r: &Row) -> (Vec<String>, Vec<String>, Vec<String>) {
    let w = r.witness(a, AT_ROW);
    (
        violated_relations(a, &w, &challenges(a)),
        violated_lookups(a, &w),
        violated_tables(a, r),
    )
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

fn none() -> Vec<String> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// The circuit
// ---------------------------------------------------------------------------

/// The committed fixture is the constructor's bytes, and the circuit passes
/// both enforcement points — `validate`, which built it, and `checker`'s
/// independent validators — plus the memory and lookup construction rules.
#[test]
fn the_circuit_is_the_fixture_and_keeps_every_rule() {
    let bytes = std::fs::read(FIXTURE).expect("the mem_subword fixture");
    assert_eq!(to_hex(&sha256(&bytes)), FIXTURE_SHA256);
    assert_eq!(mem_subword::artifact(22).to_bytes(), bytes);
    assert_eq!(
        CircuitArtifact::from_bytes(&bytes).expect("the fixture decodes"),
        mem_subword::artifact(22)
    );

    let a = artifact();
    a.validate().expect("the circuit is lawful");
    check_laws(&a).expect("the checker's validators agree");
    check_padding(&a).expect("the padding contract");
    check_padding_identity(&a).expect("the padding identity");
    check_memory(&a).expect("the memory rules");
    let channels = mem_subword::channels();
    check_discharge(&a, &channels).expect("every obligation is discharged once");
    check_lookup_discharge(&a, &channels).expect("the checker's discharge agrees");
}

/// The registry holds the family at 19 variables and up and nowhere below, and
/// what it returns is this constructor's. It reads the generic channel, so a
/// shard of it opens its last three setup columns against the verifying key's
/// generic-table commitments.
#[test]
fn the_registry_holds_the_family() {
    let c = family_circuit(family::MEM_SUBWORD, VARS).expect("the family at 2^20");
    assert_eq!(c.family, family::MEM_SUBWORD);
    assert_eq!(c.artifact, artifact());
    assert_eq!(c.channels, mem_subword::channels());
    assert!(
        c.reads_generic_table(),
        "the family reads U16GetSign for a sub-word's sign bit"
    );
    assert_eq!(family_circuit(family::MEM_SUBWORD, 18), None);
    let at_19 = family_circuit(family::MEM_SUBWORD, 19).expect("the family at 2^19");
    assert_eq!(at_19.artifact, mem_subword::artifact(19));
}

/// The layout, the gates and the obligations by name and in order. The lists
/// are literal because only a literal list catches a silent reordering: a
/// column's position is what the fill writes to and what a verifying key
/// commits, and a lookup's position is what `beta`'s derived powers weight.
#[test]
fn the_layout_and_the_gates_are_the_spec() {
    let a = artifact();
    assert_eq!(
        a.memory,
        names(&[
            "cycle",
            "pc_mask",
            "pc_addr",
            "pc_read_ts",
            "pc_read_value",
            "pc_write_value",
            "rs1_mask",
            "rs1_addr",
            "rs1_read_ts",
            "rs1_read_value",
            "rs1_write_value",
            "rs2_mask",
            "rs2_addr",
            "rs2_read_ts",
            "rs2_read_value",
            "rs2_write_value",
            "load_mask",
            "load_addr",
            "load_read_ts",
            "load_read_value",
            "load_write_value",
            "ram_mask",
            "ram_addr",
            "ram_read_ts",
            "ram_read_value",
            "ram_write_value",
            "rd_mask",
            "rd_addr",
            "rd_read_ts",
            "rd_read_value",
            "rd_write_value",
        ])
    );
    assert_eq!(
        a.witness,
        names(&[
            "pc_gap_hi",
            "rs1_gap_hi",
            "rs2_gap_hi",
            "load_gap_hi",
            "ram_gap_hi",
            "rd_gap_hi",
            "rd_inv",
            "rd_is_zero",
            "rd_selected",
            "decoded_next_pc",
            "decoded_rs1",
            "decoded_rs2",
            "decoded_rd",
            "decoded_imm",
            "decoded_mask",
            "kind_lb",
            "kind_lh",
            "kind_lbu",
            "kind_lhu",
            "kind_sb",
            "kind_sh",
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
            "mult_timestamp",
            "mult_range16",
            "mult_generic",
            "mult_decoder",
        ])
    );
    assert_eq!(
        a.setup,
        names(&[
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
        ])
    );
    // 31 memory, 55 witness, 10 setup: a six-query frame's `1 + 5w` and
    // `w + 3`, then this family's own 46 and the two tables.
    assert_eq!(a.memory.len(), 1 + 5 * 6);
    assert_eq!(a.witness.len(), 6 + 3 + 46);
    assert_eq!(a.committed().len(), 96);
    assert_eq!(
        a.virtuals,
        vec![
            (VirtualKind::Range19, "range19".to_string()),
            (VirtualKind::Range16, "range16".to_string()),
        ]
    );

    // The fifty-three enforcing gates: the frame's thirteen, then this
    // family's forty.
    let enforcing: Vec<String> = a.layers[0]
        .enforcing
        .iter()
        .map(|e| a.relations[e.relation as usize].name.clone())
        .collect();
    assert_eq!(
        enforcing,
        names(&[
            "pc_mask_boolean",
            "rs1_mask_boolean",
            "rs2_mask_boolean",
            "load_mask_boolean",
            "ram_mask_boolean",
            "rd_mask_boolean",
            "rs1_writes_back",
            "rs2_writes_back",
            "load_writes_back",
            "rd_is_zero_inverse",
            "rd_is_zero_at_nonzero",
            "rd_is_zero_boolean",
            "rd_write_masked",
            "kind_lb_boolean",
            "kind_lh_boolean",
            "kind_lbu_boolean",
            "kind_lhu_boolean",
            "kind_sb_boolean",
            "kind_sh_boolean",
            "decoded_mask_bits",
            "wrap_boolean",
            "bit0_boolean",
            "bit1_boolean",
            "rs1_mask_rule",
            "rs2_mask_rule",
            "load_mask_rule",
            "ram_mask_rule",
            "rd_mask_rule",
            "rs1_addr_rule",
            "rs2_addr_rule",
            "rd_addr_rule",
            "load_addr_rule",
            "ram_addr_rule",
            "rs1_value_masked",
            "rs2_value_masked",
            "addr_split",
            "half_aligned",
            "word_rule",
            "p_ram_rule",
            "se_rule",
            "p_rule",
            "pcopow_rule",
            "wph_rule",
            "splice_rule",
            "high_scaled_rule",
            "sub_scaled_rule",
            "low_scaled_rule",
            "src_sub_rule",
            "src_sub_scaled_rule",
            "sign_in_rule",
            "rd_value_rule",
            "store_rule",
            "next_pc_rule",
        ])
    );
    assert_eq!(enforcing.len(), 53);
    // The eleven gates the width seam owns are the eleven of its documented
    // list plus the store's merge, and they are the tail of the family's own
    // gates but for `next_pc_rule`.
    let seam: Vec<String> = mem_subword::splice_gates(mem_subword::BYTE_BITS)
        .iter()
        .map(|(n, _)| n.clone())
        .collect();
    assert_eq!(
        seam,
        names(&[
            "p_rule",
            "pcopow_rule",
            "wph_rule",
            "splice_rule",
            "high_scaled_rule",
            "sub_scaled_rule",
            "low_scaled_rule",
            "src_sub_rule",
            "src_sub_scaled_rule",
            "sign_in_rule",
            "rd_value_rule",
            "store_rule",
        ])
    );

    // The thirty-six obligations, each with the channel it is read on and the
    // selector it is read under. A selector moved to another column is a
    // different circuit, so each one is written out. Every obligation of this
    // family but the frame's twelve gaps is read under `m_pc`: this family
    // gates nothing by a kind flag, the splice being one decomposition
    // whatever the row does.
    let m = PolyAddress::Memory;
    let (timestamp, range, generic, decoder) = (
        lookup_channel::TIMESTAMP,
        lookup_channel::RANGE16,
        lookup_channel::GENERIC,
        lookup_channel::DECODER,
    );
    let lookups: Vec<(&str, u32, PolyAddress)> = a
        .lookups
        .iter()
        .map(|l| (l.name.as_str(), l.channel, l.selector))
        .collect();
    assert_eq!(
        lookups,
        vec![
            ("gap_hi_pc", timestamp, m(1)),
            ("gap_lo_pc", timestamp, m(1)),
            ("gap_hi_rs1", timestamp, m(6)),
            ("gap_lo_rs1", timestamp, m(6)),
            ("gap_hi_rs2", timestamp, m(11)),
            ("gap_lo_rs2", timestamp, m(11)),
            ("gap_hi_load", timestamp, m(16)),
            ("gap_lo_load", timestamp, m(16)),
            ("gap_hi_ram", timestamp, m(21)),
            ("gap_lo_ram", timestamp, m(21)),
            ("gap_hi_rd", timestamp, m(26)),
            ("gap_lo_rd", timestamp, m(26)),
            ("word_index_hi_range", range, m(1)),
            ("word_index_lo_range", range, m(1)),
            // `4·word_index` is the memory tuple's address, so the word index
            // is bounded a second time, scaled by the four bytes of a word.
            ("word_index_hi_scaled", range, m(1)),
            ("high_hi_range", range, m(1)),
            ("high_lo_range", range, m(1)),
            ("high_scaled_hi_range", range, m(1)),
            ("high_scaled_lo_range", range, m(1)),
            // `sub` and `src_sub` are at most a halfword wide, so one
            // halfword obligation is their exact direct bound; the scaled
            // partner is what holds each below the row's own access width.
            ("sub_range", range, m(1)),
            ("sub_scaled_hi_range", range, m(1)),
            ("sub_scaled_lo_range", range, m(1)),
            ("low_hi_range", range, m(1)),
            ("low_lo_range", range, m(1)),
            ("low_scaled_hi_range", range, m(1)),
            ("low_scaled_lo_range", range, m(1)),
            ("src_sub_range", range, m(1)),
            ("src_sub_scaled_hi_range", range, m(1)),
            ("src_sub_scaled_lo_range", range, m(1)),
            ("src_high_hi_range", range, m(1)),
            ("src_high_lo_range", range, m(1)),
            // The `U16GetSign` key's own bound (`docs/spec/lookup.md` §4).
            ("sign_in_range", range, m(1)),
            ("rd_hi_range", range, m(1)),
            ("rd_lo_range", range, m(1)),
            ("sub_get_sign", generic, m(1)),
            ("decode_row", decoder, m(1)),
        ]
    );
    assert_eq!(lookups.len(), 36);
    // The per-channel counts the constructor asserts when it builds the
    // circuit; here they are read off the artifact instead.
    for (channel, want) in [(timestamp, 12), (range, 22), (generic, 1), (decoder, 1)] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(got, want, "channel {channel}");
    }

    // The four channels in output order: the two range tables, then the
    // packed generic table at `S[7..10]` and the decoded table at `S[0..7]`.
    let w = PolyAddress::Witness;
    assert_eq!(
        mem_subword::channels(),
        vec![
            ChannelSpec {
                channel: timestamp,
                table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
                multiplicity: w(51),
            },
            ChannelSpec {
                channel: range,
                table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
                multiplicity: w(52),
            },
            ChannelSpec {
                channel: generic,
                table: (7..10).map(PolyAddress::Setup).collect(),
                multiplicity: w(53),
            },
            ChannelSpec {
                channel: decoder,
                table: (0..7).map(PolyAddress::Setup).collect(),
                multiplicity: w(54),
            },
        ]
    );
    assert_eq!(mem_subword::MULTIPLICITIES, [w(51), w(52), w(53), w(54)]);
    assert_eq!(mem_subword::GENERIC_TABLE.len(), generic_table::WIDTH);
    assert_eq!(mem_subword::TABLE_WIDTH, 7);

    // The leaves: six product-tree leaves a side padded to eight, then one
    // `(num, den)` pair per fraction, each channel's tree padded to a power of
    // two — 16 + 2·(16 + 32 + 2 + 2) = 120. The `range16` tree is the widest,
    // its 22 obligations and its table fraction padding to 32.
    assert_eq!(a.layers[0].width, 120);
    assert_eq!(a.outputs.len(), 2 + 2 * 4);
    // The leaves, five row-wise levels and one halving level per variable.
    assert_eq!(a.depth(), 1 + 5 + VARS as usize);
}

/// The legal masks are the six instructions, and nothing else: every row kind
/// `program::row_kind` routes here, with and without `rd = x0`, gives one of
/// them.
#[test]
fn the_legal_masks_are_the_instruction_list() {
    let mut seen: Vec<u32> = Vec::new();
    for (bit, instr) in instruction_corpus() {
        let (fam, k) = program::row_kind(&instr);
        assert_eq!(fam, family::MEM_SUBWORD, "{instr:?}");
        assert_eq!(k, bit, "{instr:?}");
        if !seen.contains(&(1 << k)) {
            seen.push(1 << k);
        }
    }
    seen.sort_unstable();
    let mut legal = mem_subword::LEGAL_MASKS.to_vec();
    legal.sort_unstable();
    assert_eq!(seen, legal);
    assert_eq!(legal.len(), 6);
}

/// Every instruction of the family, as `crates/isa` models it, with `rd = x0`
/// and with a real destination, and at a positive and a negative displacement.
fn instruction_corpus() -> Vec<(u32, isa::Instr)> {
    use isa::Instr::*;
    let mut out = Vec::new();
    for rd in [0u8, 7] {
        for imm in [-4i32, 0, 3] {
            out.extend([
                (kind::LB, Lb { rd, rs1: 5, imm }),
                (kind::LH, Lh { rd, rs1: 5, imm }),
                (kind::LBU, Lbu { rd, rs1: 5, imm }),
                (kind::LHU, Lhu { rd, rs1: 5, imm }),
                (
                    kind::SB,
                    Sb {
                        rs1: 5,
                        rs2: 6,
                        imm,
                    },
                ),
                (
                    kind::SH,
                    Sh {
                        rs1: 5,
                        rs2: 6,
                        imm,
                    },
                ),
            ]);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Honest rows
// ---------------------------------------------------------------------------

/// The catalogue of honest rows: every kind at every offset its width allows,
/// both signs at both widths, `rd = x0`, an `x0` base, a wrapping address, a
/// compressed row and the all-zero padding row.
fn honest_rows() -> Vec<(&'static str, Row)> {
    let mut out: Vec<(&'static str, Row)> = Vec::new();
    let mut push = |what: &'static str, r: Row| out.push((what, r));

    // The two byte loads at all four offsets. `MEM`'s byte 0 is `0x01`, a
    // positive byte, and its byte 3 is `0x88`, a negative one, so `lb` runs
    // over both signs and `lbu` over the same bytes without extending them.
    for (what, bit, offset) in [
        ("lbu at 0", kind::LBU, 0),
        ("lbu at 1", kind::LBU, 1),
        ("lbu at 2", kind::LBU, 2),
        ("lbu at 3", kind::LBU, 3),
        ("lb at 0", kind::LB, 0),
        ("lb at 1", kind::LB, 1),
        ("lb at 2", kind::LB, 2),
        ("lb at 3", kind::LB, 3),
    ] {
        push(
            what,
            honest(Instr::new(bit, offset), BASE, 0, MEM, 0x1111_1111),
        );
    }
    // The two halfword loads at both aligned offsets: `0x7f01` is positive and
    // `0x88fe` negative.
    for (what, bit, offset) in [
        ("lhu at 0", kind::LHU, 0),
        ("lhu at 2", kind::LHU, 2),
        ("lh at 0", kind::LH, 0),
        ("lh at 2", kind::LH, 2),
    ] {
        push(
            what,
            honest(Instr::new(bit, offset), BASE, 0, MEM, 0x1111_1111),
        );
    }
    // The stores, at every offset their width allows. `SOURCE` has nonzero
    // high bytes, so each row truncates its source rather than copying it.
    for (what, bit, offset) in [
        ("sb at 0", kind::SB, 0),
        ("sb at 1", kind::SB, 1),
        ("sb at 2", kind::SB, 2),
        ("sb at 3", kind::SB, 3),
        ("sh at 0", kind::SH, 0),
        ("sh at 2", kind::SH, 2),
    ] {
        push(what, honest(Instr::new(bit, offset), BASE, SOURCE, MEM, 0));
    }
    // A store whose source byte is the byte already there, so the word it
    // writes back is the word it read.
    push(
        "sb storing the byte already there",
        honest(Instr::new(kind::SB, 0), BASE, 0xDEAD_BE01, MEM, 0),
    );

    // An `lb` into `x0`, which computes a sign-extended byte and discards it.
    let mut i = Instr::new(kind::LB, 3);
    i.rd = 0;
    push("lb into x0", honest(i, BASE, 0, MEM, 0));

    // A base of `x0`, whose displacement is the whole address.
    let mut i = Instr::new(kind::LBU, 0x14);
    i.rs1 = 0;
    push("lbu through x0", honest(i, 0, 0, MEM, 0x1111_1111));

    // A wrapping effective address: `0xffffffff + 4` is 3, with the wrap bit
    // carrying the `2^32` the split drops.
    push(
        "a wrapping lbu",
        honest(Instr::new(kind::LBU, 4), 0xFFFF_FFFF, 0, MEM, 0),
    );
    // A negative displacement, which is the same wrap seen from the other end.
    push(
        "lhu at a negative displacement",
        honest(Instr::new(kind::LHU, 0xFFFF_FFFC), BASE, 0, MEM, 0),
    );

    // A two-byte instruction, whose fall-through is pc + 2.
    let mut i = Instr::new(kind::LH, 0);
    i.compressed = true;
    push("a compressed lh", honest(i, BASE, 0, MEM, 0));

    push("padding", Row::default());
    out
}

/// Every row kind the family proves satisfies every gate, every range
/// obligation and both table channels — and the catalogue really is what it
/// says it is: every kind at every offset its width allows, both signs at both
/// widths, and a sub-word that is a genuine truncation on every row, of the
/// word a load read and of the register a store stores.
#[test]
fn every_row_kind_satisfies_every_gate_and_every_bound() {
    let a = artifact();
    let rows = honest_rows();
    assert_eq!(rows.len(), 25);
    let mut offsets: BTreeSet<(u32, u64)> = BTreeSet::new();
    let mut signs: BTreeSet<(bool, u64)> = BTreeSet::new();
    for (what, r) in &rows {
        assert_eq!(violated(&a, r), (none(), none(), none()), "{what}");
        // The padding row claims no kind and is covered by its own test.
        let Some(bit) = (0..6u32).find(|b| r.get(name("kind", mnemonic(*b))) == Fr::ONE) else {
            continue;
        };
        let offset = small_int(r.get("bit0") + f(2) * r.get("bit1")).expect("the offset bits");
        offsets.insert((bit, offset));
        signs.insert((is_byte(bit), small_int(r.get("sign")).expect("a sign bit")));
        assert_ne!(
            r.get("sub"),
            r.get("word"),
            "{what}: the word is its sub-word"
        );
        if !is_load(bit) {
            assert_ne!(
                r.get("src_sub"),
                r.get("rs2_read_value"),
                "{what}: the source is stored whole"
            );
        }
    }
    for bit in 0..6u32 {
        let want: &[u64] = if is_byte(bit) { &[0, 1, 2, 3] } else { &[0, 2] };
        for offset in want {
            assert!(
                offsets.contains(&(bit, *offset)),
                "no {} at offset {offset}",
                mnemonic(bit)
            );
        }
    }
    for byte in [true, false] {
        for sign in [0, 1] {
            assert!(
                signs.contains(&(byte, sign)),
                "no sub-word of sign {sign} at byte {byte}"
            );
        }
    }
}

/// The all-zero padding row is valid, and the circuit says so in its own
/// padding contract.
#[test]
fn the_padding_row_is_the_all_zero_row() {
    let a = artifact();
    assert!(a.padding.zero_row_valid);
    assert!(a.padding.row.iter().all(|v| *v == Fr::ZERO));
    assert_eq!(
        violated(&a, &Row::default()),
        (none(), none(), none()),
        "the all-zero row"
    );
}

/// A row named by [`honest_rows`].
fn row(what: &str) -> Row {
    honest_rows()
        .into_iter()
        .find(|(name, _)| *name == what)
        .unwrap_or_else(|| panic!("no honest row `{what}`"))
        .1
}

// ---------------------------------------------------------------------------
// Each gate refuses its row
// ---------------------------------------------------------------------------

/// Each tamper beside the gates it breaks, exactly: an edit to an honest row
/// that the gates listed, and only they, refuse. Most are one gate, which is
/// what says that gate is load-bearing on the row shape it exists for; where
/// more are listed, they read the same column and the comment says so.
#[test]
fn each_gate_is_the_one_that_refuses_its_row() {
    let a = artifact();
    let mut cases: Vec<(&str, Row, Vec<&str>)> = Vec::new();

    // The mask and its bits.
    let mut r = row("lbu at 0");
    r.set("decoded_mask", f(1 << kind::LB));
    cases.push((
        "an lbu whose packed mask says lb",
        r,
        vec!["decoded_mask_bits"],
    ));

    // Presence. Every kind reads rs1; only a store reads rs2 and writes RAM,
    // and only a load reads a word and writes rd.
    let mut r = row("lbu through x0");
    r.drop_query("rs1");
    cases.push((
        "an lbu through x0 making no rs1 query",
        r,
        vec!["rs1_mask_rule"],
    ));
    let mut r = row("lbu at 0");
    r.query("rs2", 2, 0, 0, 0);
    cases.push(("an lbu reading rs2", r, vec!["rs2_mask_rule"]));
    let mut r = row("sb at 0");
    let addr = small_int(r.get("ram_addr")).expect("a word address");
    r.query("load", 2, addr, 0, 0);
    cases.push(("an sb making a load query", r, vec!["load_mask_rule"]));
    // A load making a RAM query, dressed so that the store's own merge still
    // holds: `p_ram` follows the mask and the word written back is the word
    // read with its accessed byte cleared.
    let mut r = row("lbu at 0");
    let addr = small_int(r.get("load_addr")).expect("a word address");
    let kept = MEM as u64 - (MEM as u64 & 0xFF);
    r.query("ram", 3, addr, 0, kept);
    r.set("p_ram", Fr::ONE);
    cases.push(("an lbu making a ram query", r, vec!["ram_mask_rule"]));

    // Addresses.
    let mut r = row("lbu at 0");
    let addr = r.get("rs1_addr") + Fr::ONE;
    r.set("rs1_addr", addr);
    cases.push((
        "a load reading the wrong base register",
        r,
        vec!["rs1_addr_rule"],
    ));
    let mut r = row("sb at 0");
    let addr = r.get("rs2_addr") + Fr::ONE;
    r.set("rs2_addr", addr);
    cases.push((
        "a store reading the wrong source register",
        r,
        vec!["rs2_addr_rule"],
    ));
    let mut r = row("lbu at 0");
    r.set("rd_addr", f(8))
        .set("rd_inv", f(8).inverse().expect("nonzero"));
    cases.push(("an lbu writing the wrong register", r, vec!["rd_addr_rule"]));
    let mut r = row("lbu at 0");
    let addr = r.get("load_addr") + f(4);
    r.set("load_addr", addr);
    cases.push((
        "an lbu reading the next word along",
        r,
        vec!["load_addr_rule"],
    ));
    let mut r = row("sb at 0");
    let addr = r.get("ram_addr") + f(4);
    r.set("ram_addr", addr);
    cases.push((
        "an sb storing into the next word along",
        r,
        vec!["ram_addr_rule"],
    ));

    // Absent operands read 0. Every live row queries rs1, so the gate's target
    // is a padding row that pretends to have read one; rs2 is absent on every
    // load, and there the forgery is a live row.
    let mut r = Row::default();
    r.set("rs1_read_value", f(4))
        .set("rs1_write_value", f(4))
        .set("word_index", Fr::ONE);
    cases.push((
        "a padding row whose absent rs1 reads 4",
        r,
        vec!["rs1_value_masked"],
    ));
    let mut r = row("lbu at 0");
    r.set("rs2_read_value", f(5))
        .set("rs2_write_value", f(5))
        .set("src_sub", f(5))
        .set("src_sub_scaled", f(5 << 24))
        .set("src_sub_scaled_hi", f(5 << 8));
    cases.push((
        "an lbu whose absent rs2 reads 5",
        r,
        vec!["rs2_value_masked"],
    ));

    // The address split, whose word index moved with the address it names, so
    // that the memory query is consistent and only the split is not.
    let mut r = row("lbu at 0");
    let index = r.get("word_index") + Fr::ONE;
    let addr = r.get("load_addr") + f(4);
    r.set("word_index", index).set("load_addr", addr);
    cases.push((
        "an lbu splitting its address one word too high",
        r,
        vec!["addr_split"],
    ));

    // A halfword at an odd address, whose splice is otherwise consistent:
    // `a_halfword_at_an_odd_address_is_unprovable` is this row in full.
    cases.push((
        "an lhu at an odd address",
        honest(Instr::new(kind::LHU, 1), BASE, 0, MEM, 0),
        vec!["half_aligned"],
    ));

    // The word this row splices is the word it read. `low` moves with it, so
    // the splice still holds and only its provenance is wrong.
    let mut r = row("lbu at 1");
    r.set("word", f(MEM as u64 + 1))
        .set("low", f(2))
        .set("low_scaled", f(2 << 24))
        .set("low_scaled_hi", f(2 << 8));
    cases.push((
        "an lbu whose word is not the word it read",
        r,
        vec!["word_rule"],
    ));

    // The store's splice power. On the row whose source byte is the byte
    // already there the merge writes the word back unchanged, so switching
    // `p_ram` off leaves `store_rule` holding and its own rule alone.
    let mut r = row("sb storing the byte already there");
    r.set("p_ram", Fr::ZERO);
    cases.push((
        "an sb switching its splice power off",
        r,
        vec!["p_ram_rule"],
    ));

    // The sign-extension term. An `lbu` carrying `lb`'s answer: the value
    // written moves with it, so every arithmetic gate holds and only the rule
    // tying `se` to the two signed kinds refuses it.
    let mut r = row("lbu at 3");
    let extended = 0xFFFF_FF88u64;
    r.set("se", Fr::ONE)
        .set("rd_selected", f(extended))
        .set("rd_write_value", f(extended))
        .set("rd_hi", f(0xFFFF));
    cases.push(("an lbu sign-extending like an lb", r, vec!["se_rule"]));

    // The splice power, read from the offset bits. The row below is the
    // honest `lbu at 1` re-spliced at offset 0 —
    // `a_sub_word_read_from_the_wrong_position_is_refused` is it in full.
    cases.push((
        "an lbu at offset one splicing at offset zero",
        spliced_at_offset_zero(),
        vec!["p_rule"],
    ));

    // The copower. On a row whose low bytes are empty `low_scaled` is 0
    // however it is scaled, so the rule pinning `p·pcopow` is the lone
    // refusal — and it is what keeps the residue bound honest elsewhere.
    let mut r = row("lbu at 0");
    r.set("pcopow", f(1 << 30));
    cases.push(("an lbu halving its copower", r, vec!["pcopow_rule"]));

    // The high multiplier, on a row where `w·p` is the whole word and `high`
    // is therefore 0: `high_scaled` is 0 however `wph` moves.
    let mut r = row("lbu at 3");
    r.set("wph", f((1u64 << 31) + 1));
    cases.push((
        "an lbu at offset three moving its high multiplier",
        r,
        vec!["wph_rule"],
    ));

    // The splice itself: one unit of `low` that the word does not carry.
    let mut r = row("lbu at 1");
    r.set("low", f(2))
        .set("low_scaled", f(2 << 24))
        .set("low_scaled_hi", f(2 << 8));
    cases.push((
        "an lbu whose parts do not sum to its word",
        r,
        vec!["splice_rule"],
    ));
    // A unit moved from the low bytes into the high ones, so the splice still
    // sums and only the high part's own scaling is wrong.
    let mut r = row("lbu at 1");
    let scaled = r.get("high_scaled") + Fr::ONE;
    r.set("high_scaled", scaled)
        .set("low", Fr::ZERO)
        .set("low_scaled", Fr::ZERO)
        .set("low_scaled_hi", Fr::ZERO);
    cases.push((
        "an lbu shifting a unit from its low bytes into its high ones",
        r,
        vec!["high_scaled_rule"],
    ));

    // The three scaled columns, each one too large: nothing but its own rule
    // reads any of them, the ranges being membership and not equations.
    let mut r = row("lbu at 0");
    let scaled = r.get("sub_scaled") + Fr::ONE;
    r.set("sub_scaled", scaled);
    cases.push((
        "an lbu whose scaled sub-word is one too large",
        r,
        vec!["sub_scaled_rule"],
    ));
    let mut r = row("lbu at 1");
    let scaled = r.get("low_scaled") + Fr::ONE;
    r.set("low_scaled", scaled);
    cases.push((
        "an lbu whose scaled low bytes are one too large",
        r,
        vec!["low_scaled_rule"],
    ));
    let mut r = row("sb at 0");
    let scaled = r.get("src_sub_scaled") + Fr::ONE;
    r.set("src_sub_scaled", scaled);
    cases.push((
        "an sb whose scaled source is one too large",
        r,
        vec!["src_sub_scaled_rule"],
    ));

    // The store's source, stored consistently but taken from nowhere:
    // `a_store_source_unrelated_to_rs2_is_refused` is this row in full.
    cases.push((
        "an sb storing a byte unrelated to rs2",
        stored_byte(f(0x42), f(SOURCE as u64 / 256)),
        vec!["src_sub_rule"],
    ));

    // The sign lookup's key. `0x101` is a halfword whose sign bit is the
    // sub-word's, so the packed table still answers and the rule tying the key
    // to `sub` is the lone refusal.
    let mut r = row("lbu at 0");
    r.set("sign_in", f(0x101));
    cases.push((
        "an lbu whose sign key is not its sub-word",
        r,
        vec!["sign_in_rule"],
    ));

    // The written value, one above the byte the row spliced.
    let mut r = row("lbu at 0");
    r.set("rd_selected", f(2)).set("rd_write_value", f(2));
    cases.push((
        "an lbu writing one more than the byte it read",
        r,
        vec!["rd_value_rule"],
    ));

    // The store's merge.
    let mut r = row("sb at 0");
    let written = r.get("ram_write_value") + Fr::ONE;
    r.set("ram_write_value", written);
    cases.push((
        "an sb storing one more than it spliced",
        r,
        vec!["store_rule"],
    ));

    // The pc. No kind here computes one.
    let mut r = row("lbu at 0");
    r.set("pc_write_value", f(0x1008));
    cases.push(("an lbu jumping four ahead", r, vec!["next_pc_rule"]));

    // S14's control C8 on this frame: a padding row whose `rd` query rewrites
    // a register after the program has exited. Nothing in the frame ties a
    // query's mask to the row's pc mask, so the family's own mask rule is what
    // refuses it — together with the address rule, the decoded `rd` being 0 on
    // a row that decodes nothing, and the value rule, which reads no kind bit
    // there and so pins the written value to 0.
    let mut r = Row::default();
    r.query("rd", 3, 10, 42, 43);
    r.set("rd_inv", f(10).inverse().expect("nonzero"))
        .set("rd_selected", f(43));
    cases.push((
        "a padding row rewriting x10",
        r,
        vec!["rd_mask_rule", "rd_addr_rule", "rd_value_rule"],
    ));
    // The same forgery dressed to satisfy every other gate: the free kind bits
    // claim `lbu`, the decoded row names x10, and the value written is the
    // sub-word the splice carries, which on a row with no word and no power is
    // free. Only the `m_pc` factor of the mask rule is left.
    let mut r = Row::default();
    r.set("kind_lbu", Fr::ONE)
        .set("decoded_mask", f(1 << kind::LBU))
        .set("decoded_rd", f(10))
        .set("sub", f(43))
        .set("sub_scaled", f(43 << 24))
        .set("sub_scaled_hi", f(43 << 8))
        .set("sign_in", f(43 << 8))
        .set("rd_selected", f(43));
    r.query("rd", 3, 10, 42, 43);
    r.set("rd_inv", f(10).inverse().expect("nonzero"));
    cases.push((
        "a padding row claiming lbu and rewriting x10",
        r,
        vec!["rd_mask_rule"],
    ));

    // Every gate this family adds is named by some row above. The frame's
    // thirteen are S14's and covered by `crates/checker/tests/memory.rs`, and
    // a booleanity gate is `every_booleanity_gate_refuses_a_value_of_two`'s,
    // so the two are set aside; what is left is this family's own semantics,
    // and a gate added with no forgery beside it fails here rather than
    // silently.
    let named: Vec<&str> = cases
        .iter()
        .flat_map(|(_, _, want)| want.iter().copied())
        .collect();
    let frame = [
        "pc_mask_boolean",
        "rs1_mask_boolean",
        "rs2_mask_boolean",
        "load_mask_boolean",
        "ram_mask_boolean",
        "rd_mask_boolean",
        "rs1_writes_back",
        "rs2_writes_back",
        "load_writes_back",
        "rd_is_zero_inverse",
        "rd_is_zero_at_nonzero",
        "rd_is_zero_boolean",
        "rd_write_masked",
    ];
    let owed: Vec<&str> = a.layers[0]
        .enforcing
        .iter()
        .map(|e| a.relations[e.relation as usize].name.as_str())
        .filter(|n| !frame.contains(n) && !n.ends_with("_boolean"))
        .collect();
    assert_eq!(owed.len(), 31);
    for gate in owed {
        assert!(named.contains(&gate), "no row above is refused by `{gate}`");
    }

    let order: Vec<&str> = a.relations.iter().map(|r| r.name.as_str()).collect();
    for (what, r, want) in cases {
        let (relations, _, _) = violated(&a, &r);
        let mut want: Vec<String> = names(&want);
        want.sort_by_key(|n| order.iter().position(|o| o == n));
        assert_eq!(relations, want, "{what}");
    }
}

/// The honest `lbu at 1` re-spliced as if the address named offset 0: the word
/// is the same word, decomposed at the power the row does not have.
fn spliced_at_offset_zero() -> Row {
    let mut r = row("lbu at 1");
    let word = MEM as u64;
    splice(&mut r, word, 1 << 8, 1);
    let sub = word % (1 << 8);
    r.set("sign_in", f(sub << 8))
        .set("sign", Fr::ZERO)
        .set("se", Fr::ZERO)
        .set("rd_selected", f(sub))
        .set("rd_write_value", f(sub))
        .set("rd_hi", Fr::ZERO);
    r
}

/// The honest `sb at 0` storing `src_sub` out of a source register holding
/// `SOURCE`, with `src_high` claimed as given and the merged word recomputed
/// so that the store's own gate still holds.
fn stored_byte(src_sub: Fr, src_high: Fr) -> Row {
    let mut r = row("sb at 0");
    let byte = small_int(src_sub).expect("a byte");
    let kept = MEM as u64 - (MEM as u64 & 0xFF);
    let high_hi = small_int(src_high).map_or(0, |v| v >> 16);
    r.set("src_sub", src_sub)
        .set("src_sub_scaled", src_sub * f(1 << 24))
        .set("src_sub_scaled_hi", f((byte << 24) >> 16))
        .set("src_high", src_high)
        .set("src_high_hi", f(high_hi))
        .set("ram_write_value", f(kept + byte));
    r
}

/// Every booleanity gate the family adds refuses a 2: the six kind bits, the
/// wrap and the two offset bits. Each is read as a 0 or a 1 by a gate above
/// it, and a value of two there is a different statement — so the membership
/// is what matters, not the whole violated set.
#[test]
fn every_booleanity_gate_refuses_a_value_of_two() {
    let a = artifact();
    for (column, gate) in [
        ("wrap", "wrap_boolean"),
        ("bit0", "bit0_boolean"),
        ("bit1", "bit1_boolean"),
    ] {
        let mut r = Row::default();
        r.set(column, f(2));
        let (relations, _, _) = violated(&a, &r);
        assert!(
            relations.contains(&gate.to_string()),
            "{column} = 2: {relations:?}"
        );
    }
    for bit in 0..6u32 {
        let mut r = Row::default();
        r.set(name("kind", mnemonic(bit)), f(2));
        let (relations, _, _) = violated(&a, &r);
        let gate = format!("kind_{}_boolean", mnemonic(bit));
        assert!(
            relations.contains(&gate),
            "kind_{} = 2: {relations:?}",
            mnemonic(bit)
        );
    }
}

// ---------------------------------------------------------------------------
// The two table channels
// ---------------------------------------------------------------------------

/// Each table lookup as the lone refusal of a row every gate and every range
/// obligation accepts.
///
/// The sign lookup: an `lh` of the positive halfword `0x7f01` claiming that
/// its sign bit is set, with the sign-extension term and the written word
/// moved to match. Every gate holds — `se_rule` reads the claimed sign, not
/// the halfword — and the packed table, which holds `U16GetSign`'s real answer
/// for that halfword, is what refuses it.
///
/// The decoder: an `lbu` whose decoded displacement is four larger than the
/// one its own table row carries. Every gate reads the decoded columns, so the
/// row is internally consistent; only the tuple it looks up is not the table's.
#[test]
fn each_table_lookup_is_the_one_that_refuses_its_row() {
    let a = artifact();

    let mut r = row("lh at 0");
    let extended = 0xFFFF_0000u64 + 0x7F01;
    r.set("sign", Fr::ONE)
        .set("se", Fr::ONE)
        .set("rd_selected", f(extended))
        .set("rd_write_value", f(extended))
        .set("rd_hi", f(0xFFFF));
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["sub_get_sign"])),
        "an lh calling 0x7f01 negative"
    );

    let mut r = honest(Instr::new(kind::LBU, 4), BASE, 0, MEM, 0x1111_1111);
    r.set("table_imm", Fr::ZERO);
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["decode_row"])),
        "an lbu four bytes past its table row"
    );
}

/// A sign that is not the sub-word's sign bit, refused by the packed table and
/// by nothing else. The row is the honest `lb` of `0x88` — a negative byte —
/// claiming a sign of 0, so `se_rule` lets the sign extension go and the byte
/// is written as if it were unsigned. This is the whole reason the sign comes
/// from a committed table: with a whole word in one column, nothing else in
/// the circuit knows bit 15 of `sign_in` from bit 14.
#[test]
fn a_sign_that_is_not_the_sub_words_sign_bit_is_refused() {
    let a = artifact();
    let base = row("lb at 3");
    assert_eq!(
        violated(&a, &base),
        (none(), none(), none()),
        "the honest lb"
    );
    assert_eq!(base.get("rd_write_value"), f(0xFFFF_FF88));

    let mut r = base;
    r.set("sign", Fr::ZERO)
        .set("se", Fr::ZERO)
        .set("rd_selected", f(0x88))
        .set("rd_write_value", f(0x88))
        .set("rd_hi", Fr::ZERO);
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["sub_get_sign"])),
        "an lb refusing to sign-extend"
    );
}

/// The key this family looks up stays inside `U16GetSign`'s rows, and
/// `sign_in_range` is what puts it there.
///
/// `docs/spec/lookup.md` §4: a table channel's only claim is membership, and
/// the packed table holds three sub-tables in one channel, so an unbounded key
/// does not miss the table — it lands on another sub-table's row. Here the one
/// obligation on `sign_in` bounds the key by construction: `sign_in < 2^16`
/// puts `SIGN_BASE + sign_in + 1` in `[SIGN_BASE + 1, SIGN_BASE + 2^16]`,
/// which is exactly `U16GetSign`'s key range, above the AND table's last key
/// and below `ShiftPowers`' first.
#[test]
fn the_generic_key_stays_inside_its_sub_table() {
    let a = artifact();

    // The bound: one `RANGE16` obligation over `sign_in` alone, under the
    // row's pc mask.
    let bound = a
        .lookups
        .iter()
        .find(|l| l.name == "sign_in_range")
        .expect("the key's bound");
    assert_eq!(bound.channel, lookup_channel::RANGE16);
    assert_eq!(bound.selector, frame(0, FIELD_MASK));
    assert_eq!(bound.tuple.len(), 1);
    assert_eq!(bound.tuple[0].operands(), vec![mem_subword::SIGN_IN]);

    // The keys a bounded `sign_in` can produce, and the three sub-tables'
    // ranges as `constants::generic_table` fixes them.
    let (lowest, highest) = (
        generic_table::SIGN_BASE as u64 + 1,
        generic_table::SIGN_BASE as u64 + (1 << 16),
    );
    let and_last = generic_table::AND_BASE as u64 + 256;
    let shift_first = generic_table::SHIFT_BASE as u64 + 1;
    assert!(and_last < lowest, "the AND table ends below the first key");
    assert!(
        highest < shift_first,
        "ShiftPowers begins above the last key"
    );

    // And the keys really are that sub-table's rows: every one of them is an
    // entry whose value is bit 15 of the halfword it names and whose result is
    // 0, and no key above the last is an entry at all.
    let entries: BTreeMap<u64, (u64, u64)> = generic_entries()
        .iter()
        .map(|e| (e[0] as u64, (e[1] as u64, e[2] as u64)))
        .collect();
    for h in 0..1u64 << 16 {
        let key = generic_table::SIGN_BASE as u64 + h + 1;
        assert_eq!(entries.get(&key), Some(&(h >> 15, 0)), "the row at {key}");
    }
    // And one key past the last is not a miss but `ShiftPowers`' first row,
    // `(2^0, 2^31)`, which is exactly why the bound is load-bearing: an
    // unbounded `sign_in` would read a foreign sub-table's answer as a sign.
    assert_eq!(entries.get(&(highest + 1)), Some(&(1, 1 << 31)));
}

// ---------------------------------------------------------------------------
// Acceptance 2: the splice at a reduced width
// ---------------------------------------------------------------------------

/// A gate over a map of column values.
fn eval(gate: &GateDef, values: &BTreeMap<PolyAddress, Fr>) -> Fr {
    let operands: Vec<Fr> = gate
        .operands()
        .iter()
        .map(|address| {
            *values
                .get(address)
                .unwrap_or_else(|| panic!("the case gives {address} no value"))
        })
        .collect();
    eval_gate(gate, &operands, &ExternalChallenges::new())
}

/// The one value below `window` that zeroes the gate named `name`, or `None`
/// where the gate has no solution there. Every column solved this way enters
/// its gate linearly with coefficient 1, so at most one value of the whole
/// field zeroes it and the assertion inside is a check of that, not a
/// convenience.
fn solve(
    gates: &[(String, GateDef)],
    name: &str,
    address: PolyAddress,
    values: &mut BTreeMap<PolyAddress, Fr>,
    window: u64,
) -> Option<u64> {
    let gate = &gates
        .iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("the seam has no gate `{name}`"))
        .1;
    let mut found = None;
    for candidate in 0..window {
        values.insert(address, f(candidate));
        if eval(gate, values) == Fr::ZERO {
            assert!(found.is_none(), "`{name}` is solved twice below {window}");
            found = Some(candidate);
        }
    }
    match found {
        Some(v) => {
            values.insert(address, f(v));
        }
        None => {
            values.remove(&address);
        }
    }
    found
}

/// Acceptance 2: at a reduced width the splice admits exactly one witness.
///
/// `mem_subword::splice_gates` is the seam the family's own gates come from,
/// and this calls it at **one bit to a byte**: a word is then 4 bits, a "byte"
/// 1 bit and a "halfword" 2 bits, and every literal of the twelve gates — the
/// splice power, the copower, the high multiplier, the two scalings and the
/// sign key's shift — is derived from that width by the circuit, not
/// transcribed here. The gates evaluated below are those gates, through
/// `gkr::eval_gate` over a hand-built map of column values.
///
/// The cases are every `(word, bit0, bit1, BYTE)` the circuit admits: all four
/// offsets for a byte access and the two even ones for a halfword, `bit0 = 0`
/// there being `half_aligned`'s doing. For each, every `(high, sub, low)` in
/// `[0, 16)^3` is a candidate, and a candidate is a witness when every one of
/// the twelve gates holds on it **and** every column a bound covers — the
/// three parts and the three scaled columns — is below `2^4`. The scaled
/// column of each part is found by solving its own gate inside the bound, so a
/// part with no in-range partner is refused by the bound exactly as the
/// `range16` channel would refuse it.
///
/// The three columns the splice does not determine are set to the values that
/// make their gates vacuous — no RAM query, no source, no sign extension — and
/// the two that follow the sub-word, the sign key and the written value, are
/// solved from their own gates like the rest.
#[test]
fn the_splice_admits_exactly_one_witness_at_a_reduced_width() {
    use mem_subword::{
        BIT0, BIT1, HIGH, HIGH_SCALED, KINDS, LOW, LOW_SCALED, P, PCOPOW, P_RAM, SE, SIGN_IN,
        SRC_HIGH, SRC_SUB, SRC_SUB_SCALED, SUB, SUB_SCALED, WORD, WPH,
    };

    const B: u32 = 1;
    let full = 1u64 << (4 * B); // a whole word, 16
    let gates = mem_subword::splice_gates(B);
    assert_eq!(gates.len(), 12);

    // The frame columns the seam reads, by slot rather than by position.
    let queries = frame_queries(family::MEM_SUBWORD);
    let at = |q: usize| queries.iter().position(|&x| x == q).expect("the query");
    let m_pc = frame(at(PC), FIELD_MASK);
    let m_ram = frame(at(RAM), FIELD_MASK);
    let v_rs2 = frame(at(RS2), FIELD_READ_VALUE);
    let ram_write = frame(at(RAM), FIELD_WRITE_VALUE);
    let sel = rd_selected(queries.len());

    let (mut cases, mut pairs, mut bounded) = (0usize, 0usize, 0usize);
    for byte in [true, false] {
        let width = if byte { 1u64 << B } else { 1u64 << (2 * B) };
        for offset in 0..4u64 {
            // A halfword access has bit 0 clear, so the circuit admits no odd
            // offset at that width.
            if !byte && offset % 2 == 1 {
                continue;
            }
            let p = 1u64 << (B * offset as u32);
            for word in 0..full {
                cases += 1;
                let mut base: BTreeMap<PolyAddress, Fr> = BTreeMap::new();
                base.insert(m_pc, Fr::ONE);
                for k in KINDS {
                    base.insert(k, Fr::ZERO);
                }
                // A byte load and a halfword load: one kind bit each, which is
                // what the BYTE and the LOAD forms read.
                let bit = KINDS[if byte { kind::LB } else { kind::LH } as usize];
                base.insert(bit, Fr::ONE);
                base.insert(BIT0, f(offset & 1));
                base.insert(BIT1, f(offset >> 1));
                base.insert(WORD, f(word));
                // No RAM query, no source and no sign extension: the three
                // gates that read them are then satisfied by zero.
                for address in [
                    m_ram,
                    ram_write,
                    v_rs2,
                    P_RAM,
                    SRC_SUB,
                    SRC_HIGH,
                    SRC_SUB_SCALED,
                    SE,
                ] {
                    base.insert(address, Fr::ZERO);
                }
                // The three constants the offset fixes, each solved from its
                // own gate rather than written down here.
                for (gate, address) in [("p_rule", P), ("pcopow_rule", PCOPOW), ("wph_rule", WPH)] {
                    let v = solve(&gates, gate, address, &mut base, 2 * full)
                        .unwrap_or_else(|| panic!("`{gate}` has no solution below {}", 2 * full));
                    base.insert(address, f(v));
                }
                assert_eq!(base[&P], f(p), "the offset's power");

                // Each part's scaled column, in range or not at all: the bound
                // on the part, read off the gate that defines its partner.
                let partners = |value: PolyAddress, scaled: PolyAddress, gate: &str| {
                    (0..full)
                        .map(|x| {
                            let mut v = base.clone();
                            v.insert(value, f(x));
                            solve(&gates, gate, scaled, &mut v, full)
                        })
                        .collect::<Vec<Option<u64>>>()
                };
                let highs = partners(HIGH, HIGH_SCALED, "high_scaled_rule");
                let subs = partners(SUB, SUB_SCALED, "sub_scaled_rule");
                let lows = partners(LOW, LOW_SCALED, "low_scaled_rule");

                let mut witnesses: Vec<(u64, u64, u64)> = Vec::new();
                for (high, hs) in highs.iter().enumerate() {
                    for (sub, ss) in subs.iter().enumerate() {
                        for (low, ls) in lows.iter().enumerate() {
                            pairs += 1;
                            let (Some(hs), Some(ss), Some(ls)) = (hs, ss, ls) else {
                                continue;
                            };
                            bounded += 1;
                            let mut v = base.clone();
                            for (address, x) in [
                                (HIGH, high as u64),
                                (HIGH_SCALED, *hs),
                                (SUB, sub as u64),
                                (SUB_SCALED, *ss),
                                (LOW, low as u64),
                                (LOW_SCALED, *ls),
                            ] {
                                v.insert(address, f(x));
                            }
                            // The two columns the sub-word feeds. A sub-word
                            // below the word and no sign extension put both
                            // inside the window, and each is unique in it.
                            for (gate, address) in
                                [("sign_in_rule", SIGN_IN), ("rd_value_rule", sel)]
                            {
                                let x = solve(&gates, gate, address, &mut v, 2 * full)
                                    .unwrap_or_else(|| panic!("`{gate}` has no small solution"));
                                v.insert(address, f(x));
                            }
                            if gates.iter().all(|(_, g)| eval(g, &v) == Fr::ZERO) {
                                witnesses.push((high as u64, sub as u64, low as u64));
                            }
                        }
                    }
                }
                assert_eq!(
                    witnesses.len(),
                    1,
                    "word {word} at offset {offset}, byte {byte}"
                );
                assert_eq!(
                    witnesses[0],
                    (word / (width * p), (word / p) % width, word % p),
                    "word {word} at offset {offset}, byte {byte}"
                );
            }
        }
    }
    // 16 words at each of six offsets, and every triple of a four-bit word
    // against each.
    assert_eq!(cases, 96);
    assert_eq!(pairs, 96 * 4096);
    // The bounds alone leave `w·p·(2^4/(w·p))` triples a case, of which the
    // splice keeps one.
    assert_eq!(bounded, 96 * 16);
}

// ---------------------------------------------------------------------------
// Acceptance 2's negative half
// ---------------------------------------------------------------------------

/// A halfword access at an odd address is unprovable, and `half_aligned` is
/// the lone refusal.
///
/// It has to be a gate of its own because the splice is perfectly consistent
/// there: at offset 1 the word decomposes into a byte below, a halfword and a
/// byte above, and at offset 3 the high multiplier `w·p` reaches `2^40` — no
/// range obligation covers it — with `high` therefore 0 and the accessed
/// "halfword" a single byte. Both rows below satisfy every other gate, every
/// range obligation and both table channels.
#[test]
fn a_halfword_at_an_odd_address_is_unprovable() {
    let a = artifact();
    for (what, bit, offset) in [
        ("lhu at offset 1", kind::LHU, 1),
        ("lh at offset 3", kind::LH, 3),
        ("sh at offset 1", kind::SH, 1),
    ] {
        let r = honest(Instr::new(bit, offset), BASE, SOURCE, MEM, 0);
        assert_eq!(
            violated(&a, &r),
            (names(&["half_aligned"]), none(), none()),
            "{what}"
        );
    }
    // And the aligned twin of each, which differs only in the offset.
    for (bit, offset) in [(kind::LHU, 0), (kind::LH, 2), (kind::SH, 2)] {
        let r = honest(Instr::new(bit, offset), BASE, SOURCE, MEM, 0);
        assert_eq!(violated(&a, &r), (none(), none(), none()));
    }
}

/// A sub-word read from the wrong position is refused, and `p_rule` is what
/// refuses it.
///
/// The row is the honest `lbu` at offset 1 — which loads `0x7f` — re-spliced
/// as if its address named offset 0, so that it loads `0x01` instead. Every
/// part of the new splice is consistent: the word is the same word, the three
/// parts sum to it, each scaled column is in range, the sign key follows the
/// new sub-word and the packed table answers it. What the row cannot move is
/// the two offset bits, which are the address's own, and `p_rule` is the
/// degree-2 form that ties the power to them.
#[test]
fn a_sub_word_read_from_the_wrong_position_is_refused() {
    let a = artifact();
    let base = row("lbu at 1");
    assert_eq!(violated(&a, &base), (none(), none(), none()));
    assert_eq!(base.get("rd_write_value"), f(0x7F));

    let r = spliced_at_offset_zero();
    assert_eq!(r.get("rd_write_value"), f(0x01));
    assert_eq!(
        violated(&a, &r),
        (names(&["p_rule"]), none(), none()),
        "an lbu at offset 1 reading byte 0"
    );
}

/// An `lbu` that yields more than a byte is refused, and the **scaled** bound
/// on `sub` is what refuses it.
///
/// `sub`'s own direct obligation is a halfword, which is the exact bound at
/// the wider of the two access widths and no bound at all at the narrower one.
/// The row below loads `0x7f01` — two bytes — through a byte access, with
/// `high` moved so that the splice still sums and `high`'s own pair still
/// holds. `sub_range` accepts it. `sub_scaled`, which is `2^24·sub` on a byte
/// row, does not fit a word, and the sign key `256·sub` no longer fits a
/// halfword either, so the packed table has no row for it.
#[test]
fn an_lbu_that_yields_more_than_a_byte_is_refused() {
    let a = artifact();
    let word = MEM as u64;
    let (sub, high) = (0x7F01u64, (word - 0x7F01) / 256);
    assert_eq!(high * 256 + sub, word, "the forged splice really sums");

    let mut r = row("lbu at 0");
    r.set("sub", f(sub))
        .set("sub_scaled", f(sub << 24))
        .set("sub_scaled_hi", f((sub << 24) >> 16))
        .set("high", f(high))
        .set("high_hi", f(high >> 16))
        .set("high_scaled", f(high * 256))
        .set("high_scaled_hi", f((high * 256) >> 16))
        .set("sign_in", f(sub << 8))
        .set("rd_selected", f(sub))
        .set("rd_write_value", f(sub))
        .set("rd_hi", f(sub >> 16));
    assert_eq!(
        violated(&a, &r),
        (
            none(),
            names(&["sub_scaled_hi_range", "sign_in_range"]),
            names(&["sub_get_sign"])
        ),
        "an lbu loading a halfword"
    );
    // The direct bound really does accept it: what says "a byte" is the
    // scaling, not the halfword obligation.
    assert!(sub < 1 << 16);
}

/// A free `high` is refused by `high`'s own direct pair, which is the whole
/// reason it carries one.
///
/// The row below is an `lbu` at offset 0 claiming to load `0x02`, a byte the
/// word does not hold at that position. The splice can be made to sum — set
/// `high_scaled` to `word − 2` and the equation closes — and `high_scaled`'s
/// own pair accepts that, `word − 2` being a perfectly ordinary word. But
/// `high_scaled = 2·high·wph` then forces `high` to be `(word − 2)/256`, which
/// is no integer at all over `Fr`, and the direct pair on `high` is what sees
/// it. Without that pair a load would return any byte-sized value it liked.
#[test]
fn a_free_high_is_refused() {
    let a = artifact();
    let word = MEM as u64;
    let claimed = 2u64;
    assert_ne!(word % 256, claimed, "the word does not hold that byte");
    assert_ne!((word - claimed) % 256, 0, "and high is no integer");

    let mut r = row("lbu at 0");
    r.set(
        "high",
        (f(word) - f(claimed)) * f(256).inverse().expect("nonzero"),
    )
    .set("high_hi", Fr::ZERO)
    .set("high_scaled", f(word - claimed))
    .set("high_scaled_hi", f((word - claimed) >> 16))
    .set("sub", f(claimed))
    .set("sub_scaled", f(claimed << 24))
    .set("sub_scaled_hi", f((claimed << 24) >> 16))
    .set("sign_in", f(claimed << 8))
    .set("rd_selected", f(claimed))
    .set("rd_write_value", f(claimed));
    assert_eq!(
        violated(&a, &r),
        (none(), names(&["high_lo_range"]), none()),
        "an lbu reading a byte the word does not hold"
    );
}

/// A store source unrelated to `rs2` is refused, whichever of the two columns
/// the truncation names is moved.
///
/// `sb` stores `rs2`'s low byte, and the only thing saying so is
/// `src_sub_rule`, `rs2 = src_sub + w·src_high`. Move `src_sub` alone, with
/// the merged word recomputed so that the store's own gate still holds, and
/// that rule is the lone refusal. Move `src_high` with it so that the rule
/// closes, and `src_high` is a field fraction, which its own direct pair
/// refuses.
#[test]
fn a_store_source_unrelated_to_rs2_is_refused() {
    let a = artifact();
    let base = row("sb at 0");
    assert_eq!(violated(&a, &base), (none(), none(), none()));
    assert_eq!(base.get("src_sub"), f(SOURCE as u64 & 0xFF));

    let honest_high = f(SOURCE as u64 / 256);
    let r = stored_byte(f(0x42), honest_high);
    assert_eq!(
        violated(&a, &r),
        (names(&["src_sub_rule"]), none(), none()),
        "an sb storing 0x42 out of a register holding 0xdeadbeef"
    );

    // The same forgery with `src_high` solved for: `0xdeadbeef − 0x42` is odd,
    // so the quotient is no integer and the halfword pair on `src_high` sees
    // it.
    let solved = (f(SOURCE as u64) - f(0x42)) * f(256).inverse().expect("nonzero");
    let r = stored_byte(f(0x42), solved);
    assert_eq!(
        violated(&a, &r),
        (none(), names(&["src_high_lo_range"]), none()),
        "an sb solving its truncation for a fractional high"
    );
}
