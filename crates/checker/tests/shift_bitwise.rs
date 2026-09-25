//! S18's `SHIFT_BITWISE` circuit (`docs/spec/shift-bitwise.md`), row by row,
//! in ordinary CI.
//!
//! No forward pass over `2^20` rows: each row is built by hand from what the
//! instruction computes — Rust's own `u32` and `i32` arithmetic, not the
//! circuit's — and evaluated alone through `checker::violated_relations` and
//! `violated_lookups`, its row-local scratch computed by `gkr::gate_values`.
//! The two table channels, which `violated_lookups` does not read, are held
//! here to the tables themselves: a row's gated generic tuple to
//! `program::lookup_tables`' entries, its gated decoder tuple to the table
//! columns the row carries. The proofs of the same rows are
//! `crates/prover/tests/alu.rs`' and `crates/checker/tests/tamper.rs`'.
//!
//! Acceptance 2 is here in full — its honest half as the shift-edge rows of
//! [`honest_rows`], its negative half as the forgeries the truncation, the
//! free shamt, the residue and the sign extension each admit — and so is
//! acceptance 7, the AND table read over its whole domain with `or` and `xor`
//! derived from it. Acceptance 6, that table against an independent
//! recomputation over the ceremony's SRS, is
//! `crates/program/tests/lookup_tables.rs`'.

use std::collections::{BTreeMap, BTreeSet};

use checker::{
    check_laws, check_lookup_discharge, check_padding, check_padding_identity, violated_lookups,
    violated_relations, WitnessRow,
};
use constants::extra_mask::shift_bitwise as kind;
use constants::{challenge_slot, family, generic_table, lookup_channel};
use constraints::lookup::{check_discharge, ChannelSpec};
use constraints::memory::check_memory;
use constraints::{
    family_circuit, shift_bitwise, CircuitArtifact, GateDef, PolyAddress, VirtualKind,
};
use field::Fr;
use gkr::{eval_gate, gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use program::lookup_tables::generic_entries;
use test_support::{sha256, to_hex};

const VARS: u32 = 20;
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/shift_bitwise.bin"
);
const FIXTURE_SHA256: &str = "b0af932594af665ca82f2ecd35fba64f8eeecc96fb50a9002466628265e3fd4c";

/// The cycle every hand-built row runs at, and the row it is evaluated at.
const CYCLE: u64 = 7;
const AT_ROW: usize = 1 << 15;

fn artifact() -> CircuitArtifact {
    shift_bitwise::artifact(VARS)
}

fn f(v: u64) -> Fr {
    Fr::from_u64(v)
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
    Box::leak(format!("{q}_{field}").into_boxed_str())
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
    /// The decoded immediate: the raw shamt on an immediate shift, the
    /// sign-extended immediate on an immediate bitwise op, 0 on an R-type row.
    imm: u32,
    compressed: bool,
}

impl Instr {
    fn new(bit: u32, imm: u32) -> Instr {
        Instr {
            bit,
            pc: 0x1000,
            rs1: 5,
            rs2: if is_r_type(bit) { 6 } else { 0 },
            rd: 7,
            imm,
            compressed: false,
        }
    }
}

/// Whether the kind reads `rs2`: the R-type half of each group.
fn is_r_type(bit: u32) -> bool {
    matches!(
        bit,
        kind::SLL | kind::SRL | kind::SRA | kind::AND | kind::OR | kind::XOR
    )
}

fn is_shift(bit: u32) -> bool {
    matches!(
        bit,
        kind::SLLI | kind::SRLI | kind::SRAI | kind::SLL | kind::SRL | kind::SRA
    )
}

/// An honest row: every column what the instruction computes, by Rust's own
/// arithmetic.
fn honest(i: Instr, rs1v: u32, rs2v: u32, rd_old: u32) -> Row {
    let a = rs1v;
    let b = if is_r_type(i.bit) { rs2v } else { 0 };
    let src2 = b + i.imm;
    let amount = src2 & 31;
    let (pow, copow) = (1u32 << amount, 1u32 << (31 - amount));
    let arithmetic = matches!(i.bit, kind::SRAI | kind::SRA);
    let se = (arithmetic && a >> 31 == 1) as u32;
    let value = match i.bit {
        kind::SLLI | kind::SLL => a << amount,
        kind::SRLI | kind::SRL => a >> amount,
        kind::SRAI | kind::SRA => ((a as i32) >> amount) as u32,
        kind::ANDI | kind::AND => a & src2,
        kind::ORI | kind::OR => a | src2,
        kind::XORI | kind::XOR => a ^ src2,
        other => panic!("kind bit {other} is not this family's"),
    };
    let word = 1i64 << 32;
    let (input, ovf, residue) = match i.bit {
        kind::SLLI | kind::SLL => (a as i64, ((a as i64 * pow as i64) >> 32) as u32, 0),
        kind::SRLI | kind::SRL | kind::SRAI | kind::SRA => {
            let rd_adj = value as i64 - se as i64 * word;
            let rs1_adj = a as i64 - se as i64 * word;
            (rd_adj, 0, (rs1_adj - rd_adj * pow as i64) as u32)
        }
        _ => (0, 0, 0),
    };
    let (pow, copow) = match is_shift(i.bit) {
        true => (pow, copow),
        false => (0, 0),
    };
    let product = input * pow as i64;
    let scaled = 2 * residue as u64 * copow as u64;
    let seq = i.pc + if i.compressed { 2 } else { 4 };

    let mut r = Row::default();
    r.set("cycle", f(CYCLE));
    r.set("pc_mask", Fr::ONE)
        .set("pc_read_ts", f(4 * (CYCLE - 1)))
        .set("pc_read_value", f(i.pc as u64))
        .set("pc_write_value", f(seq as u64));
    r.query("rs1", 1, i.rs1 as u64, a as u64, a as u64);
    if is_r_type(i.bit) {
        r.query("rs2", 2, i.rs2 as u64, b as u64, b as u64);
    }
    let write = if i.rd == 0 { 0 } else { value };
    r.query("rd", 3, i.rd as u64, rd_old as u64, write as u64);
    match i.rd {
        0 => r.set("rd_is_zero", Fr::ONE),
        d => r.set("rd_inv", f(d as u64).inverse().expect("nonzero")),
    };
    r.set("rd_selected", f(value as u64));

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

    r.set("f_shift", f(is_shift(i.bit) as u64));
    r.set("f_bitwise", f(!is_shift(i.bit) as u64));
    for (column, v) in [
        ("rs1_hi", (a >> 16) as u64),
        ("rs1_sign", (a >> 31) as u64),
        ("src2_hi", (src2 >> 16) as u64),
        ("amount", amount as u64),
        ("pow", pow as u64),
        ("copow", copow as u64),
        ("high", (src2 >> 5) as u64),
        ("high_hi", (src2 >> 5 >> 16) as u64),
        ("se", se as u64),
        ("ovf", ovf as u64),
        ("ovf_hi", (ovf >> 16) as u64),
        ("residue", residue as u64),
        ("residue_hi", (residue >> 16) as u64),
        ("scaled", scaled & 0xFFFF_FFFF),
        ("scaled_hi", (scaled >> 16) & 0xFFFF),
        ("rd_hi", (value >> 16) as u64),
    ] {
        r.set(Box::leak(column.to_string().into_boxed_str()), f(v));
    }
    r.set("shift_in", signed(input as i128));
    r.set("shift_prod", signed(product as i128));
    for j in 0..4 {
        let (byte_a, byte_b) = ((a >> (8 * j)) & 0xff, (src2 >> (8 * j)) & 0xff);
        let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
        r.set(leak(format!("byte_a{j}")), f(byte_a as u64));
        r.set(leak(format!("byte_b{j}")), f(byte_b as u64));
        r.set(leak(format!("byte_and{j}")), f((byte_a & byte_b) as u64));
    }
    r
}

/// A signed integer as a field element.
fn signed(v: i128) -> Fr {
    let magnitude = |m: u128| {
        let shift = f(1 << 32) * f(1 << 32);
        f((m >> 64) as u64) * shift + f(m as u64)
    };
    match v < 0 {
        true => -magnitude(v.unsigned_abs()),
        false => magnitude(v as u128),
    }
}

fn mnemonic(bit: u32) -> &'static str {
    [
        "slli", "xori", "srli", "srai", "ori", "andi", "sll", "xor", "srl", "sra", "or", "and",
    ][bit as usize]
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
                let table: Vec<Fr> = (0..shift_bitwise::TABLE_WIDTH)
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
    let bytes = std::fs::read(FIXTURE).expect("the shift/bitwise fixture");
    assert_eq!(to_hex(&sha256(&bytes)), FIXTURE_SHA256);
    assert_eq!(shift_bitwise::artifact(22).to_bytes(), bytes);
    assert_eq!(
        CircuitArtifact::from_bytes(&bytes).expect("the fixture decodes"),
        shift_bitwise::artifact(22)
    );

    let a = artifact();
    a.validate().expect("the circuit is lawful");
    check_laws(&a).expect("the checker's validators agree");
    check_padding(&a).expect("the padding contract");
    check_padding_identity(&a).expect("the padding identity");
    check_memory(&a).expect("the memory rules");
    let channels = shift_bitwise::channels();
    check_discharge(&a, &channels).expect("every obligation is discharged once");
    check_lookup_discharge(&a, &channels).expect("the checker's discharge agrees");
}

/// The registry holds the family at 19 variables and up and nowhere below, and
/// what it returns is this constructor's.
#[test]
fn the_registry_holds_the_family() {
    let c = family_circuit(family::SHIFT_BITWISE, VARS).expect("the family at 2^20");
    assert_eq!(c.family, family::SHIFT_BITWISE);
    assert_eq!(c.artifact, artifact());
    assert_eq!(c.channels, shift_bitwise::channels());
    assert!(
        c.reads_generic_table(),
        "the family reads AND, U16GetSign and ShiftPowers"
    );
    assert_eq!(family_circuit(family::SHIFT_BITWISE, 18), None);
    let at_19 = family_circuit(family::SHIFT_BITWISE, 19).expect("the family at 2^19");
    assert_eq!(at_19.artifact, shift_bitwise::artifact(19));
}

/// The layout is `docs/spec/shift-bitwise.md` §2's and the gates and lookups
/// are §4's, by name and in order. The lists are literal because only a
/// literal list catches a silent reordering: a column's position is what the
/// fill writes to and what a verifying key commits, and a lookup's position is
/// what `beta`'s derived powers weight.
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
            "kind_slli",
            "kind_xori",
            "kind_srli",
            "kind_srai",
            "kind_ori",
            "kind_andi",
            "kind_sll",
            "kind_xor",
            "kind_srl",
            "kind_sra",
            "kind_or",
            "kind_and",
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
    // 21 memory, 61 witness, 10 setup: the document's 92 committed columns.
    assert_eq!(a.memory.len() + a.witness.len() + a.setup.len(), 92);
    assert_eq!(a.committed().len(), 92);
    assert_eq!(
        a.virtuals,
        vec![
            (VirtualKind::Range19, "range19".to_string()),
            (VirtualKind::Range16, "range16".to_string()),
        ]
    );

    // The forty-eight enforcing gates: the frame's ten, then this family's
    // thirty-eight.
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
            "rd_mask_boolean",
            "rs1_writes_back",
            "rs2_writes_back",
            "rd_is_zero_inverse",
            "rd_is_zero_at_nonzero",
            "rd_is_zero_boolean",
            "rd_write_masked",
            "kind_slli_boolean",
            "kind_xori_boolean",
            "kind_srli_boolean",
            "kind_srai_boolean",
            "kind_ori_boolean",
            "kind_andi_boolean",
            "kind_sll_boolean",
            "kind_xor_boolean",
            "kind_srl_boolean",
            "kind_sra_boolean",
            "kind_or_boolean",
            "kind_and_boolean",
            "decoded_mask_bits",
            "f_shift_rule",
            "f_shift_boolean",
            "f_bitwise_rule",
            "f_bitwise_boolean",
            "rs1_mask_rule",
            "rs2_mask_rule",
            "rd_mask_rule",
            "rs1_addr_rule",
            "rs2_addr_rule",
            "rd_addr_rule",
            "rs1_value_masked",
            "rs2_value_masked",
            "next_pc_rule",
            "amount_split",
            "copower_rule",
            "se_rule",
            "rs1_sign_boolean",
            "se_boolean",
            "shift_in_rule",
            "shift_prod_rule",
            "shift_out_rule",
            "scaled_rule",
            "rs1_bytes",
            "src2_bytes",
            "bitwise_out_rule",
        ])
    );
    assert_eq!(enforcing.len(), 48);

    // The thirty-nine obligations, each with the channel it is read on and
    // the selector it is read under. A selector moved to another column is a
    // different circuit, so each one is written out.
    let m = PolyAddress::Memory;
    let w = PolyAddress::Witness;
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
            ("gap_hi_rd", timestamp, m(16)),
            ("gap_lo_rd", timestamp, m(16)),
            ("rs1_hi_range", range, m(1)),
            ("rs1_lo_range", range, m(1)),
            ("src2_hi_range", range, m(1)),
            ("src2_lo_range", range, m(1)),
            ("high_hi_range", range, m(1)),
            ("high_lo_range", range, m(1)),
            ("ovf_hi_range", range, m(1)),
            ("ovf_lo_range", range, m(1)),
            ("residue_hi_range", range, m(1)),
            ("residue_lo_range", range, m(1)),
            ("scaled_hi_range", range, m(1)),
            ("scaled_lo_range", range, m(1)),
            ("rd_hi_range", range, m(1)),
            ("rd_lo_range", range, m(1)),
            // The generic keys' own bounds, each a direct check and a scaled
            // one, under the selector of the lookup they bound
            // (`docs/spec/shift-bitwise.md` §3.3). Without them a byte column
            // of 65,823 reads a `ShiftPowers` row and `and` writes a wrong
            // word.
            ("amount_range", range, w(25)),
            ("amount_scaled", range, w(25)),
            ("byte_a0_range", range, w(26)),
            ("byte_a0_scaled", range, w(26)),
            ("byte_a1_range", range, w(26)),
            ("byte_a1_scaled", range, w(26)),
            ("byte_a2_range", range, w(26)),
            ("byte_a2_scaled", range, w(26)),
            ("byte_a3_range", range, w(26)),
            ("byte_a3_scaled", range, w(26)),
            ("rs1_get_sign", generic, m(1)),
            ("shift_powers", generic, w(25)),
            ("and_byte_0", generic, w(26)),
            ("and_byte_1", generic, w(26)),
            ("and_byte_2", generic, w(26)),
            ("and_byte_3", generic, w(26)),
            ("decode_row", decoder, m(1)),
        ]
    );
    assert_eq!(lookups.len(), 39);
    // §4.5's per-channel counts, which `artifact` asserts when it builds the
    // circuit; here they are read off the artifact instead.
    for (channel, want) in [(timestamp, 8), (range, 24), (generic, 6), (decoder, 1)] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(got, want, "channel {channel}");
    }
    // Every obligation that is not read under `m_pc` is read under one of the
    // two half flags — the key bounds of §3.3 and the two gated tables — which
    // is why those two columns exist at all, and what the list above pins.
    // Every selector is a frame mask but the fifteen read under one of the two
    // half flags: §3.3's ten key bounds, `shift_powers`, and the four AND
    // bytes.
    let gated: Vec<&(&str, u32, PolyAddress)> = lookups
        .iter()
        .filter(|(_, _, s)| matches!(s, PolyAddress::Witness(_)))
        .collect();
    assert_eq!(gated.len(), 15);
    assert!(gated
        .iter()
        .all(|(_, _, s)| *s == shift_bitwise::F_SHIFT || *s == shift_bitwise::F_BITWISE));

    // The four channels in output order: the two range tables, then the
    // packed generic table at `S[7..10]` and the decoded table at `S[0..7]`.
    assert_eq!(
        shift_bitwise::channels(),
        vec![
            ChannelSpec {
                channel: timestamp,
                table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
                multiplicity: w(57),
            },
            ChannelSpec {
                channel: range,
                table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
                multiplicity: w(58),
            },
            ChannelSpec {
                channel: generic,
                table: (7..10).map(PolyAddress::Setup).collect(),
                multiplicity: w(59),
            },
            ChannelSpec {
                channel: decoder,
                table: (0..7).map(PolyAddress::Setup).collect(),
                multiplicity: w(60),
            },
        ]
    );
    assert_eq!(shift_bitwise::MULTIPLICITIES, [w(57), w(58), w(59), w(60)]);
    assert_eq!(shift_bitwise::GENERIC_TABLE.len(), generic_table::WIDTH);

    // The leaves: four product-tree leaves a side, then one `(num, den)` pair
    // per fraction, each channel's tree padded to a power of two —
    // 8 + 2·(16 + 32 + 8 + 2) = 124. The `range16` tree is the widest: its 24
    // obligations and its table fraction pad to 32, where every other family's
    // fit in 16.
    assert_eq!(a.layers[0].width, 124);
    assert_eq!(a.outputs.len(), 2 + 2 * 4);
    // One deeper than add/sub and the jump family, for that reason: the
    // leaves, five row-wise levels and one halving level per variable.
    assert_eq!(a.depth(), 1 + 5 + VARS as usize);
}

/// The legal masks are the twelve instructions, and nothing else: every row
/// kind `program::row_kind` routes here, with and without `rd = x0`, gives one
/// of them.
#[test]
fn the_legal_masks_are_the_instruction_list() {
    let mut seen: Vec<u32> = Vec::new();
    for (bit, instr) in instruction_corpus() {
        let (fam, k) = program::row_kind(&instr);
        assert_eq!(fam, family::SHIFT_BITWISE, "{instr:?}");
        assert_eq!(k, bit, "{instr:?}");
        if !seen.contains(&(1 << k)) {
            seen.push(1 << k);
        }
    }
    seen.sort_unstable();
    let mut legal = shift_bitwise::LEGAL_MASKS.to_vec();
    legal.sort_unstable();
    assert_eq!(seen, legal);
}

/// Every instruction of the family, as `crates/isa` models it, with `rd = x0`
/// and with a real destination.
fn instruction_corpus() -> Vec<(u32, isa::Instr)> {
    use isa::Instr::*;
    let mut out = Vec::new();
    for rd in [0u8, 7] {
        out.extend([
            (
                kind::SLLI,
                Slli {
                    rd,
                    rs1: 5,
                    shamt: 3,
                },
            ),
            (
                kind::SRLI,
                Srli {
                    rd,
                    rs1: 5,
                    shamt: 3,
                },
            ),
            (
                kind::SRAI,
                Srai {
                    rd,
                    rs1: 5,
                    shamt: 3,
                },
            ),
            (
                kind::XORI,
                Xori {
                    rd,
                    rs1: 5,
                    imm: -1,
                },
            ),
            (kind::ORI, Ori { rd, rs1: 5, imm: 7 }),
            (kind::ANDI, Andi { rd, rs1: 5, imm: 7 }),
            (kind::SLL, Sll { rd, rs1: 5, rs2: 6 }),
            (kind::SRL, Srl { rd, rs1: 5, rs2: 6 }),
            (kind::SRA, Sra { rd, rs1: 5, rs2: 6 }),
            (kind::XOR, Xor { rd, rs1: 5, rs2: 6 }),
            (kind::OR, Or { rd, rs1: 5, rs2: 6 }),
            (kind::AND, And { rd, rs1: 5, rs2: 6 }),
        ]);
    }
    out
}

// ---------------------------------------------------------------------------
// Honest rows
// ---------------------------------------------------------------------------

/// The catalogue of honest rows: every kind, the shift edges S18's acceptance
/// 2 names, `rd = x0`, a compressed row, and the all-zero padding row.
fn honest_rows() -> Vec<(&'static str, Row)> {
    let mut out: Vec<(&'static str, Row)> = Vec::new();
    let mut push = |what: &'static str, r: Row| out.push((what, r));

    // Every kind once, over operands that exercise it.
    for (what, bit, imm, a, b) in [
        ("slli 3", kind::SLLI, 3, 0x1234_5679, 0),
        ("srli 3", kind::SRLI, 3, 0x1234_5679, 0),
        ("srai 3", kind::SRAI, 3, 0xFEDC_BA98, 0),
        ("xori -1", kind::XORI, 0xFFFF_FFFF, 0x1234_5678, 0),
        ("ori", kind::ORI, 0x0000_07FF, 0x1234_5678, 0),
        ("andi -1", kind::ANDI, 0xFFFF_FFFF, 0x1234_5678, 0),
        ("sll", kind::SLL, 0, 0x1234_5679, 4),
        ("srl", kind::SRL, 0, 0xFEDC_BA98, 4),
        ("sra", kind::SRA, 0, 0xFEDC_BA98, 4),
        ("xor", kind::XOR, 0, 0xF0F0_0FF0, 0x0FF0_F00F),
        ("or", kind::OR, 0, 0xF0F0_0FF0, 0x0FF0_F00F),
        ("and", kind::AND, 0, 0xF0F0_0FF0, 0x0FF0_F00F),
        // Two patterns with no bit in common, so the AND is 0 and the row
        // writes 0: the base every tamper below needs whose `rd` term must
        // stay satisfied while something else moves.
        ("and to zero", kind::AND, 0, 0xF0F0_0FF0, 0x0F0F_F00F),
    ] {
        push(what, honest(Instr::new(bit, imm), a, b, 0x1111_1111));
    }

    // Acceptance 2: shamt 0, 1 and 31, both directions and both operand
    // shapes; rs2 = 32 and 33, which truncate to 0 and 1; sra of a negative;
    // srai against srli on the same negative operand.
    for (what, bit, shamt) in [
        ("slli 0", kind::SLLI, 0),
        ("slli 1", kind::SLLI, 1),
        ("slli 31", kind::SLLI, 31),
        ("srli 0", kind::SRLI, 0),
        ("srli 1", kind::SRLI, 1),
        ("srli 31", kind::SRLI, 31),
        ("srai 0", kind::SRAI, 0),
        ("srai 1", kind::SRAI, 1),
        ("srai 31", kind::SRAI, 31),
    ] {
        push(what, honest(Instr::new(bit, shamt), 0xFEDC_BA99, 0, 0));
    }
    for (what, bit, amount) in [
        ("sll by rs2 = 32", kind::SLL, 32),
        ("sll by rs2 = 33", kind::SLL, 33),
        ("srl by rs2 = 32", kind::SRL, 32),
        ("srl by rs2 = 33", kind::SRL, 33),
        ("sra by rs2 = 32", kind::SRA, 32),
        ("sra by rs2 = 33", kind::SRA, 33),
        ("sra by rs2 = 0xffffffff", kind::SRA, 0xFFFF_FFFF),
    ] {
        push(what, honest(Instr::new(bit, 0), 0xFEDC_BA99, amount, 0));
    }
    // The same truncation on a small operand. `0xfedcba99 << 1` overflows a
    // 32-bit `ovf`, so the untruncated forgery of
    // `an_untruncated_amount_is_refused_by_its_scaled_bound_and_the_table`
    // needs a base whose doubled word still fits one — otherwise `ovf`'s own
    // range pair refuses the row besides the two the test is there to name.
    push(
        "sll by rs2 = 33, small rs1",
        honest(Instr::new(kind::SLL, 0), 0x1234_5679, 33, 0),
    );

    // rd = x0 in each half, computing a value it discards.
    for (what, bit, imm) in [
        ("slli into x0", kind::SLLI, 3),
        ("andi into x0", kind::ANDI, 7),
    ] {
        let mut i = Instr::new(bit, imm);
        i.rd = 0;
        push(what, honest(i, 0x1234_5679, 0, 0));
    }

    // A two-byte instruction, whose fall-through is pc + 2.
    let mut i = Instr::new(kind::SRLI, 1);
    i.compressed = true;
    push("a compressed srli", honest(i, 0xFEDC_BA98, 0, 0));

    // An x0 operand, which reads 0.
    let mut i = Instr::new(kind::OR, 0);
    i.rs1 = 0;
    push("or with an x0 operand", honest(i, 0, 0x0FF0_F00F, 0));

    push("padding", Row::default());
    out
}

/// Every row kind the family proves satisfies every gate, every range
/// obligation and both table channels.
#[test]
fn every_row_kind_satisfies_every_gate_and_every_bound() {
    let a = artifact();
    for (what, r) in honest_rows() {
        assert_eq!(violated(&a, &r), (none(), none(), none()), "{what}");
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
/// two are listed, the second reads the same column and the comment says so.
#[test]
fn each_gate_is_the_one_that_refuses_its_row() {
    let a = artifact();
    let mut cases: Vec<(&str, Row, Vec<&str>)> = Vec::new();

    // The mask and its bits.
    let mut r = row("slli 3");
    r.set("decoded_mask", f(1 << kind::SRLI));
    cases.push((
        "an slli whose packed mask says srli",
        r,
        vec!["decoded_mask_bits"],
    ));

    // The two halves. `f_shift` selects the ShiftPowers lookup and the key
    // bound on `amount` alike, so switching it off is what would free the
    // amount from both. Two gates refuse it: its own rule, and the copower
    // identity, which reads `f_shift` as its right-hand side.
    let mut r = row("slli 3");
    r.set("f_shift", Fr::ZERO);
    cases.push((
        "an slli switching its ShiftPowers lookup off",
        r,
        vec!["f_shift_rule", "copower_rule"],
    ));
    // `f_bitwise` is the byte table's selector, and switching it off would
    // free the eight byte columns from the table's domain. On a row whose AND
    // is 0 the output gate still holds, so its own rule is the lone refusal.
    let mut r = row("and to zero");
    r.set("f_bitwise", Fr::ZERO);
    cases.push((
        "an and switching its byte table off",
        r,
        vec!["f_bitwise_rule"],
    ));

    // Presence. Every kind reads rs1 and writes rd; only the R-type half
    // reads rs2.
    let mut r = row("or with an x0 operand");
    r.drop_query("rs1");
    cases.push(("an or making no rs1 query", r, vec!["rs1_mask_rule"]));
    let mut r = row("slli 3");
    r.query("rs2", 2, 0, 0, 0);
    cases.push(("an slli reading rs2", r, vec!["rs2_mask_rule"]));
    let mut r = row("and to zero");
    r.drop_query("rd");
    r.set("rd_inv", Fr::ZERO);
    cases.push(("an and making no rd query", r, vec!["rd_mask_rule"]));

    // Addresses.
    for (q, rule) in [("rs1", "rs1_addr_rule"), ("rs2", "rs2_addr_rule")] {
        let mut r = row("sll");
        let addr = r.get(name(q, "addr")) + Fr::ONE;
        r.set(name(q, "addr"), addr);
        cases.push(("a register query at the wrong register", r, vec![rule]));
    }
    let mut r = row("slli 3");
    r.set("rd_addr", f(5))
        .set("rd_inv", f(5).inverse().expect("nonzero"));
    cases.push((
        "an slli writing the wrong register",
        r,
        vec!["rd_addr_rule"],
    ));

    // Absent operands read 0. Every live row queries rs1, so the gate's
    // target is a padding row that pretends to have read one; rs2 is absent
    // on every I-type row, and there the forgery is a live one.
    let mut r = Row::default();
    r.set("rs1_read_value", f(5))
        .set("rs1_write_value", f(5))
        .set("byte_a0", f(5));
    cases.push((
        "a padding row whose absent rs1 reads 5",
        r,
        vec!["rs1_value_masked"],
    ));
    // `slli 0` shifts by the low five bits of 32, which are 0, so the claimed
    // register value changes nothing the row computes: only the mask rule
    // stands between an I-type shift and a register it never queried.
    let mut r = row("slli 0");
    r.set("rs2_read_value", f(32))
        .set("rs2_write_value", f(32))
        .set("high", Fr::ONE)
        .set("byte_b0", f(32));
    cases.push((
        "an slli whose absent rs2 reads 32",
        r,
        vec!["rs2_value_masked"],
    ));

    // The pc. No kind here computes one.
    let mut r = row("slli 3");
    r.set("pc_write_value", f(0x1008));
    cases.push(("an slli jumping four ahead", r, vec!["next_pc_rule"]));

    // The shift amount. Leaving the shamt free is the pitfall §4.2 names: the
    // row below shifts by 2 while its immediate says 3, every column that
    // depends on the amount moved to match, and the split is the only gate
    // that sees it.
    let mut r = row("slli 3");
    let (rs1, amount) = (0x1234_5679u32, 2u32);
    let product = rs1 as u64 * (1u64 << amount);
    r.set("amount", f(amount as u64))
        .set("pow", f(1 << amount))
        .set("copow", f(1 << (31 - amount)))
        .set("shift_prod", f(product))
        .set("ovf", f(product >> 32))
        .set("ovf_hi", f(product >> 48))
        .set("rd_selected", f(product & 0xFFFF_FFFF))
        .set("rd_write_value", f(product & 0xFFFF_FFFF))
        .set("rd_hi", f((product >> 16) & 0xFFFF));
    cases.push((
        "an slli shifting by two under an immediate of three",
        r,
        vec!["amount_split"],
    ));

    // The copower. Halving it would halve the residue bound §4.3 rests on,
    // and `scaled` moves with it so that its own pair still holds; the
    // circuit's own reading of the ShiftPowers row is what refuses it.
    let mut r = row("srli 3");
    r.set("copow", f(1 << 27))
        .set("scaled", f(1 << 28))
        .set("scaled_hi", f(1 << 12));
    cases.push((
        "an srli halving its copower, and its residue bound with it",
        r,
        vec!["copower_rule"],
    ));

    // The sign-extension term. An `srl` carrying `sra`'s answer: the row is
    // the honest `sra` with the kind bit and the packed mask swapped, so
    // every arithmetic gate still holds and only `se_rule`, which reads the
    // two arithmetic bits, refuses it.
    let mut r = honest(Instr::new(kind::SRA, 0), 0xFEDC_BA98, 4, 0);
    r.set("kind_sra", Fr::ZERO)
        .set("kind_srl", Fr::ONE)
        .set("decoded_mask", f(1 << kind::SRL))
        .set("table_extra_mask", f(1 << kind::SRL));
    cases.push(("an srl sign-extending like an sra", r, vec!["se_rule"]));

    // The one product. On a bitwise row `pow` is 0, so a multiplicand there
    // multiplies into nothing and only the rule that holds it to 0 sees it.
    let mut r = row("and");
    r.set("shift_in", f(5));
    cases.push((
        "an and carrying a shift multiplicand",
        r,
        vec!["shift_in_rule"],
    ));
    let mut r = row("and");
    r.set("shift_prod", f(5));
    cases.push((
        "an and carrying a shift product",
        r,
        vec!["shift_prod_rule"],
    ));
    // A product eight too large, carried into the result so that the output
    // gate still splits: the product gate is the only multiplication by `pow`
    // and the only thing that refuses it.
    let value = 0x1234_5679u32 << 3;
    let mut r = row("slli 3");
    r.set("shift_prod", f(value as u64 + 8))
        .set("rd_selected", f(value as u64 + 8))
        .set("rd_write_value", f(value as u64 + 8));
    cases.push((
        "an slli whose product is eight too large",
        r,
        vec!["shift_prod_rule"],
    ));
    // A result 2^16 above the product, its high halfword moved with it so
    // that the range pair still holds.
    let mut r = row("slli 3");
    r.set("rd_selected", f(value as u64 + 0x1_0000))
        .set("rd_write_value", f(value as u64 + 0x1_0000))
        .set("rd_hi", f((value >> 16) as u64 + 1));
    cases.push((
        "an slli writing 2^16 above its product",
        r,
        vec!["shift_out_rule"],
    ));
    let mut r = row("srli 3");
    let scaled = r.get("scaled") + Fr::ONE;
    r.set("scaled", scaled);
    cases.push(("an srli scaling its residue wrong", r, vec!["scaled_rule"]));

    // The byte decompositions. Neither is read by the output gate, which
    // reads the AND bytes alone, so each is its own refusal.
    let mut r = row("and");
    let byte = r.get("byte_a0") + Fr::ONE;
    r.set("byte_a0", byte);
    cases.push(("an and whose rs1 bytes do not sum", r, vec!["rs1_bytes"]));
    let mut r = row("and");
    let byte = r.get("byte_b0") + Fr::ONE;
    r.set("byte_b0", byte);
    cases.push(("an and whose src2 bytes do not sum", r, vec!["src2_bytes"]));

    // The bitwise output: an `or` answering with the AND accumulator alone.
    let mut r = row("or");
    let and = 0xF0F0_0FF0u32 & 0x0FF0_F00F;
    r.set("rd_selected", f(and as u64))
        .set("rd_write_value", f(and as u64))
        .set("rd_hi", f((and >> 16) as u64));
    cases.push(("an or answering with the AND", r, vec!["bitwise_out_rule"]));

    // S14's control C8 on this frame: a padding row whose `rd` query rewrites
    // a register after the program has exited. Nothing in the frame ties a
    // query's mask to the row's pc mask, so the family's own mask rule is
    // what refuses it — together with the address rule, the decoded `rd`
    // being 0 on a row that decodes nothing.
    let mut r = Row::default();
    r.query("rd", 3, 10, 42, 43);
    r.set("rd_inv", f(10).inverse().expect("nonzero"))
        .set("rd_selected", f(43));
    cases.push((
        "a padding row rewriting x10",
        r,
        vec!["rd_mask_rule", "rd_addr_rule"],
    ));
    // The same forgery dressed to satisfy every other gate: the free kind
    // bits claim `or`, the decoded row names x10, and the value written is
    // the bitwise answer over two absent operands, which is 0. Only the
    // `m_pc` factor of the mask rule is left.
    let mut r = Row::default();
    r.set("kind_or", Fr::ONE)
        .set("decoded_mask", f(1 << kind::OR))
        .set("decoded_rd", f(10))
        .set("f_bitwise", Fr::ONE);
    r.query("rd", 3, 10, 42, 0);
    r.set("rd_inv", f(10).inverse().expect("nonzero"));
    cases.push((
        "a padding row claiming or and zeroing x10",
        r,
        vec!["rd_mask_rule"],
    ));

    // Every gate this family adds is named by some row above. The frame's ten
    // are S14's and covered by `crates/checker/tests/memory.rs`, and a
    // booleanity gate is `every_booleanity_gate_refuses_a_value_of_two`'s, so
    // the two are set aside; what is left is this family's own semantics, and
    // a gate added with no forgery beside it fails here rather than silently.
    let named: Vec<&str> = cases
        .iter()
        .flat_map(|(_, _, want)| want.iter().copied())
        .collect();
    let frame = [
        "pc_mask_boolean",
        "rs1_mask_boolean",
        "rs2_mask_boolean",
        "rd_mask_boolean",
        "rs1_writes_back",
        "rs2_writes_back",
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
    assert_eq!(owed.len(), 22);
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

/// Every booleanity gate the family adds refuses a 2: the twelve kind bits,
/// the two half flags, `rs1_sign` and `se`. Each is read as a 0 or a 1 by a
/// gate or a selector above it, and a value of two there is a different
/// statement — so the membership is what matters, not the whole violated set.
#[test]
fn every_booleanity_gate_refuses_a_value_of_two() {
    let a = artifact();
    for (base, column, gate) in [
        ("slli 3", "f_shift", "f_shift_boolean"),
        ("and", "f_bitwise", "f_bitwise_boolean"),
        ("slli 3", "rs1_sign", "rs1_sign_boolean"),
        ("srai 3", "se", "se_boolean"),
    ] {
        let mut r = row(base);
        r.set(column, f(2));
        let (relations, _, _) = violated(&a, &r);
        assert!(
            relations.contains(&gate.to_string()),
            "{column} = 2: {relations:?}"
        );
    }
    for bit in 0..12u32 {
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
// Acceptance 2's negative half
// ---------------------------------------------------------------------------

/// The shift amount is bounded twice over, and this is the row that shows
/// both. `sll` by `rs2 = 33` shifts by 1; the forgery claims 33 instead, with
/// `pow = 2^33`, a copower of `2^-2` so that `pow·copow` is still `2^31`, an
/// overflow of `rs1·2` and a result of 0. Every gate holds — the operand is
/// small enough that `rs1·2` is still a 32-bit `ovf` — and two obligations do
/// not: `amount_scaled`, 33 being a halfword itself but not once multiplied by
/// `2^11`, and the `ShiftPowers` lookup, the packed table having no row at all
/// for a key past that sub-table's last.
#[test]
fn an_untruncated_amount_is_refused_by_its_scaled_bound_and_the_table() {
    let a = artifact();
    let base = row("sll by rs2 = 33, small rs1");
    assert_eq!(
        violated(&a, &base),
        (none(), none(), none()),
        "the honest row"
    );

    let rs1 = 0x1234_5679u32;
    let mut r = base;
    r.set("amount", f(33))
        .set("pow", f(1 << 33))
        .set("copow", f(4).inverse().expect("nonzero"))
        .set("high", Fr::ZERO)
        .set("high_hi", Fr::ZERO)
        .set("shift_prod", f(rs1 as u64) * f(1 << 33))
        .set("ovf", f(rs1 as u64 * 2))
        .set("ovf_hi", f((rs1 as u64 * 2) >> 16))
        .set("rd_selected", Fr::ZERO)
        .set("rd_write_value", Fr::ZERO)
        .set("rd_hi", Fr::ZERO);
    assert_eq!(
        violated(&a, &r),
        (none(), names(&["amount_scaled"]), names(&["shift_powers"])),
        "an amount of 33"
    );
}

/// The byte keys are not free either, and this is the row an earlier draft of
/// this circuit proved.
///
/// The packed generic table holds three sub-tables in one channel
/// (`docs/spec/lookup.md` §9), so a byte column outside `[0, 256)` does not
/// *miss* the table — it lands on another sub-table's row and the lookup
/// holds. What refuses it is §3.3's bound on the key, and nothing else.
///
/// Two keys, one per neighbouring sub-table:
///
/// - `byte_a0 = 256` gates to `257`, `U16GetSign`'s row for the halfword 0,
///   `(257, 0, 0)`. It is **below `2^16`, so the direct half of the bound
///   accepts it** and the scaled half alone refuses it — which is what that
///   half is for. `and(256, 256)` is 256, and the forgery writes 0.
/// - `byte_a0 = 65_823` gates to `65_824`, `ShiftPowers`' row for `s = 31`,
///   `(65_824, 2^31, 1)`. `and(65_823, 2^31)` is 0, and the forgery writes 1.
///   Both halves refuse this one.
#[test]
fn a_byte_key_outside_the_and_table_is_refused_by_its_own_bound() {
    let a = artifact();

    // The `U16GetSign` key, which only the scaled half of the bound sees.
    let honest_row = honest(Instr::new(kind::AND, 0), 256, 256, 0);
    assert_eq!(
        violated(&a, &honest_row),
        (none(), none(), none()),
        "the honest and"
    );
    assert_eq!(honest_row.get("rd_selected"), f(256));

    let mut r = honest_row.clone();
    // `rs1 = 256` decomposed as `byte_a0 = 256` rather than `byte_a1 = 1`, so
    // byte 0's lookup reads the sign row `(257, 0, 0)` and byte 1's reads the
    // AND row `(1, 1, 0)` — and the accumulator loses the bit that is set.
    r.set("byte_a0", f(256))
        .set("byte_a1", Fr::ZERO)
        .set("byte_and0", Fr::ZERO)
        .set("byte_and1", Fr::ZERO)
        .set("rd_selected", Fr::ZERO)
        .set("rd_write_value", Fr::ZERO)
        .set("rd_hi", Fr::ZERO);
    assert_eq!(
        violated(&a, &r),
        (none(), names(&["byte_a0_scaled"]), none()),
        "a byte key reading a U16GetSign row"
    );

    // The `ShiftPowers` key, which both halves see.
    let (rs1, rs2) = (65_823u32, 1u32 << 31);
    let honest_row = honest(Instr::new(kind::AND, 0), rs1, rs2, 0);
    assert_eq!(
        violated(&a, &honest_row),
        (none(), none(), none()),
        "the second honest and"
    );
    assert_eq!(honest_row.get("rd_selected"), f((rs1 & rs2) as u64));

    let mut r = honest_row.clone();
    r.set("byte_a0", f(65_823))
        .set("byte_a1", Fr::ZERO)
        .set("byte_a2", Fr::ZERO)
        .set("byte_a3", Fr::ZERO)
        .set("byte_b0", f(1 << 31))
        .set("byte_b1", Fr::ZERO)
        .set("byte_b2", Fr::ZERO)
        .set("byte_b3", Fr::ZERO)
        .set("byte_and0", Fr::ONE)
        .set("byte_and1", Fr::ZERO)
        .set("byte_and2", Fr::ZERO)
        .set("byte_and3", Fr::ZERO)
        .set("rd_selected", Fr::ONE)
        .set("rd_write_value", Fr::ONE)
        .set("rd_hi", Fr::ZERO);
    assert_eq!(
        violated(&a, &r),
        (none(), names(&["byte_a0_range", "byte_a0_scaled"]), none()),
        "a byte key reading a ShiftPowers row"
    );
}

/// The shamt is not free: `amount` is a lookup key, so the prover chooses it,
/// and `amount_split` with `high` bounded is what makes it the low five bits
/// of the whole word. `sll` by `rs2 = 4` claiming to shift by 8 satisfies the
/// split exactly once — at `high = −1/8` — and that is not an integer, so one
/// of `high`'s 16+16 pair refuses it. With the high chunk left at 0 it is the
/// low one; either way the pair is what closes the hole §4.2 names.
#[test]
fn the_shamt_is_not_free_and_the_high_chunks_bound_is_what_closes_it() {
    let a = artifact();
    let rs1 = 0x1234_5679u32;
    let base = honest(Instr::new(kind::SLL, 0), rs1, 8, 0);
    assert_eq!(
        violated(&a, &base),
        (none(), none(), none()),
        "sll by rs2 = 8"
    );

    let mut r = base;
    r.set("rs2_read_value", f(4))
        .set("rs2_write_value", f(4))
        .set("byte_b0", f(4))
        .set("high", -f(8).inverse().expect("nonzero"));
    assert_eq!(
        violated(&a, &r),
        (none(), names(&["high_lo_range"]), none()),
        "sll by rs2 = 4 shifting by 8"
    );
}

/// A right shift whose residue is at or above `2^amount` is refused by the
/// copower pattern and by nothing else. The row below claims a quotient one
/// too low and a residue of 24 on a shift by 4, which the residue's own
/// direct pair accepts — 24 is a perfectly good 32-bit word — and the
/// identity `rs1 = rd·2^s + residue` accepts too. `scaled = residue·2^(32−s)`
/// is then `3·2^31`, past a word, and whichever half of its pair the prover
/// leaves honest, the other one refuses it.
#[test]
fn a_residue_at_or_above_its_power_is_refused_by_the_scaled_bound() {
    let a = artifact();
    let (rs1, quotient, residue) = (0xFEDC_BA98u32, 0x0FED_CBA8u32, 24u64);
    let scaled = 2 * residue * (1 << 27);
    let forged = |scaled_hi: u64| {
        let mut r = row("srl");
        r.set("rd_selected", f(quotient as u64))
            .set("rd_write_value", f(quotient as u64))
            .set("shift_in", f(quotient as u64))
            .set("shift_prod", f(quotient as u64 * 16))
            .set("residue", f(residue))
            .set("scaled", f(scaled))
            .set("scaled_hi", f(scaled_hi));
        r
    };
    // The row really is the floor-division identity, on a quotient that is
    // not the floor: 0x0fedcba8·16 + 24 = 0xfedcba98.
    assert_eq!(quotient as u64 * 16 + residue, rs1 as u64);
    assert_eq!(
        violated(&a, &forged(scaled >> 16)),
        (none(), names(&["scaled_hi_range"]), none()),
        "the honest split of a scaled residue past a word"
    );
    assert_eq!(
        violated(&a, &forged(0x8000)),
        (none(), names(&["scaled_lo_range"]), none()),
        "the high chunk held down instead"
    );
}

/// `check_copowers`' reason for existing. `scaled`'s bound says
/// `residue < 2^amount` only where `residue` is an integer at all: over `Fr`,
/// `2^-28` scales by `2·2^28` to the perfectly ordinary word 2, and the scaled
/// pair accepts it on both rows below.
///
/// On a left shift `shift_out` does not read the residue, so the direct pair
/// `check_copowers` insists on is the lone refusal. On a right shift the
/// residue is tied to what the row writes, so a residue that is not an integer
/// drags `rd_selected` out of the word with it and the two direct pairs fire
/// together — which is why the assertion is the exact set, not a membership:
/// what is being pinned is that the scaled pair is in neither of them.
#[test]
fn a_residue_that_is_not_an_integer_is_refused_by_its_own_bound() {
    let a = artifact();
    let residue = f(1 << 28).inverse().expect("nonzero");

    let mut r = row("slli 3");
    r.set("residue", residue).set("scaled", f(2));
    assert_eq!(
        violated(&a, &r),
        (none(), names(&["residue_lo_range"]), none()),
        "a left shift, where shift_out does not read the residue"
    );

    // The right shift, solved backwards from the residue: `shift_out` fixes
    // the product, `shift_prod_rule` the multiplicand, and `shift_in_rule`
    // the written value, which is then no word at all.
    let rs1 = f(0x1234_5679);
    let shift_prod = rs1 - residue;
    let shift_in = shift_prod * f(8).inverse().expect("nonzero");
    let mut r = row("srli 3");
    r.set("residue", residue)
        .set("scaled", f(2))
        .set("scaled_hi", Fr::ZERO)
        .set("shift_prod", shift_prod)
        .set("shift_in", shift_in)
        .set("rd_selected", shift_in)
        .set("rd_write_value", shift_in)
        .set("rd_hi", Fr::ZERO);
    assert_eq!(
        violated(&a, &r),
        (none(), names(&["residue_lo_range", "rd_lo_range"]), none()),
        "a right shift, where the written value moves with the residue"
    );
}

/// An `srai` of a negative operand carrying `srli`'s answer, consistently:
/// the row is the honest `srli` of `0xfedcba98` by 3 with the kind bit and the
/// packed mask swapped, so its quotient, residue, product and ranges are all
/// self-consistent and the decoder lookup holds. `se_rule`, which ties the
/// sign-extension term to the two arithmetic kind bits, is the only thing
/// between it and an arithmetic shift that does not sign-extend.
#[test]
fn an_srai_carrying_srlis_answer_is_refused_by_se_rule_alone() {
    let a = artifact();
    let mut r = honest(Instr::new(kind::SRLI, 3), 0xFEDC_BA98, 0, 0);
    r.set("kind_srli", Fr::ZERO)
        .set("kind_srai", Fr::ONE)
        .set("decoded_mask", f(1 << kind::SRAI))
        .set("table_extra_mask", f(1 << kind::SRAI));
    assert_eq!(
        violated(&a, &r),
        (names(&["se_rule"]), none(), none()),
        "an srai answering 0x1fdb9753"
    );

    // The whole attack: flip the operand's claimed sign too, and `se_rule`
    // holds — `se` is then `is_arithmetic·0`. The sign is read from the
    // packed table over a range-checked halfword, and that lookup is what is
    // left.
    r.set("rs1_sign", Fr::ZERO);
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["rs1_get_sign"])),
        "an srai calling 0xfedcba98 non-negative"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 7: the byte table
// ---------------------------------------------------------------------------

/// Acceptance 7, over the whole 8-bit by 8-bit domain. Every one of the 65,536
/// `(a, b)` pairs has a row of the packed table whose result is Rust's own
/// `a & b`, and the two forms the circuit derives from that one accumulator —
/// `or = a + b − and` and `xor = a + b − 2·and`, §4.4's, which is why there is
/// no OR table and no XOR table — are Rust's own `a | b` and `a ^ b` exactly.
/// This is the table read as data. Acceptance 6, the same table against an
/// independent recomputation and its commitments over the ceremony's SRS, is
/// `crates/program/tests/lookup_tables.rs`'.
#[test]
fn acceptance_7_the_byte_table_is_and_and_or_and_xor_are_derived_from_it() {
    let rows: BTreeMap<(u32, u32), u32> = generic_entries()
        .iter()
        .filter(|e| e[0] > generic_table::AND_BASE && e[0] <= generic_table::AND_BASE + 256)
        .map(|e| ((e[0] - generic_table::AND_BASE - 1, e[1]), e[2]))
        .collect();
    assert_eq!(rows.len(), 1 << 16, "the AND sub-table's rows");
    for a in 0..256u32 {
        for b in 0..256u32 {
            let and = *rows
                .get(&(a, b))
                .unwrap_or_else(|| panic!("the table has no row for ({a}, {b})"));
            assert_eq!(and, a & b, "and({a}, {b})");
            assert_eq!(a + b - and, a | b, "or({a}, {b})");
            assert_eq!(a + b - 2 * and, a ^ b, "xor({a}, {b})");
        }
    }
}

// ---------------------------------------------------------------------------
// The guest: the acceptance matrix in its trace, and the prover's own fill
// ---------------------------------------------------------------------------

/// `guests/alu`, decoded with all four of S18's execution families at `2^20`
/// and every other family at `2^16`, as `crates/prover/tests/common` decodes
/// it for its proof, and traced into an archive. The exit status is 96, the
/// number of checks the guest made and passed.
fn alu() -> (prover::Program, trace::TraceArchive) {
    let elf = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../loader/tests/vectors/alu.elf"
    ))
    .expect("the alu guest");
    let image = loader::load_elf(&elf).expect("alu loads");
    let mut params = program::ProgramParams::defaults();
    params.heights = [1 << 16; family::COUNT as usize];
    for f in [
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::SHIFT_BITWISE,
        family::MUL_DIV,
    ] {
        params.heights[f as usize] = 1 << VARS;
    }
    let (tables, config) = program::decode_program(&image, &params).expect("the image decodes");
    // Every family the image puts in the config is one S18 proves: an
    // instruction of any other would put a family there that no circuit has.
    let families: Vec<u32> = config.families.iter().map(|(f, _)| *f).collect();
    assert_eq!(
        families,
        [
            family::ADD_SUB_LUI_AUIPC,
            family::JUMP_BRANCH_SLT,
            family::SHIFT_BITWISE,
            family::MUL_DIV,
            family::INIT_TEARDOWN,
            family::ZERO_WINDOWS,
            family::ADVICE_WINDOWS,
        ]
    );
    let io = emulator::GuestIo {
        input: Vec::new(),
        hint: Vec::new(),
        advice: Vec::new(),
    };
    let (traces, log, profile, execution) =
        emulator::trace_run(&image, &io, &tables, &config).expect("the image traces");
    assert_eq!(execution.exit_code, 96, "alu passes its 96 checks");
    let archive = trace::TraceArchive::from_execution(
        traces,
        log,
        profile,
        trace::IoStreams {
            input: execution.io.input,
            output: execution.io.output,
        },
        trace::PhaseTiming { wall_nanos: 0 },
    );
    (
        prover::Program {
            image,
            tables,
            config,
        },
        archive,
    )
}

/// One executed row of the family, with the decoded fields its pc claims.
struct Ran {
    bit: u32,
    imm: u32,
    rs1: u32,
    rs2: Option<u32>,
    rd: Option<u32>,
}

fn ran(program: &prover::Program, archive: &trace::TraceArchive) -> Vec<Ran> {
    use trace::Role;
    let table = program
        .tables
        .family(family::SHIFT_BITWISE)
        .expect("the family's table");
    let traces = archive.family_traces();
    let buffer = traces
        .family(family::SHIFT_BITWISE)
        .expect("the family's buffer");
    (0..buffer.len())
        .map(|i| {
            let r = buffer.row(i);
            let field = |c| table.get(c, r.pc as usize / 2).expect("a live row");
            Ran {
                bit: field(6).trailing_zeros(),
                imm: field(5),
                rs1: r.query(Role::Rs1).map_or(0, |q| q.read_value),
                rs2: r.query(Role::Rs2).map(|q| q.read_value),
                rd: r.query(Role::Rd).map(|q| q.write_value),
            }
        })
        .collect()
}

/// What the instruction computes, by Rust's own arithmetic — the second
/// reading the trace is held to.
fn rv32(bit: u32, a: u32, src2: u32) -> u32 {
    let s = src2 & 31;
    match bit {
        kind::SLLI | kind::SLL => a << s,
        kind::SRLI | kind::SRL => a >> s,
        kind::SRAI | kind::SRA => ((a as i32) >> s) as u32,
        kind::ANDI | kind::AND => a & src2,
        kind::ORI | kind::OR => a | src2,
        kind::XORI | kind::XOR => a ^ src2,
        other => panic!("kind bit {other} is not this family's"),
    }
}

/// S18's acceptance 2 read from the trace a proof is about
/// (`crates/prover/tests/alu.rs` proves it): every one of the twelve
/// instructions runs; each immediate shift runs at shamt 0, 1 and 31;
/// `rs2 = 32` and `rs2 = 33` both run, shifting by 0 and by 1, which is what
/// the truncation is for; `sra` runs on a negative operand; `srai` and `srli`
/// run on the same negative operand at the same shamt and answer differently;
/// and every row's written value is what Rust computes for it.
#[test]
fn the_guest_runs_the_acceptance_matrix() {
    let (program, archive) = alu();
    let rows = ran(&program, &archive);

    // Every kind, and no other.
    let mut kinds: Vec<u32> = rows.iter().map(|r| r.bit).collect();
    kinds.sort_unstable();
    kinds.dedup();
    assert_eq!(kinds, (0..12).collect::<Vec<u32>>(), "every kind runs");

    // Each row's written value is the instruction's, computed here.
    for r in &rows {
        let src2 = r.rs2.unwrap_or(r.imm);
        // One of the two addends is always zero, so the second operand is one
        // expression for both forms.
        assert!(r.rs2.is_none() || r.imm == 0, "kind {} carries both", r.bit);
        let want = rv32(r.bit, r.rs1, src2);
        match r.rd {
            Some(0) => {} // an x0 destination, which discards the answer
            Some(v) => assert_eq!(v, want, "kind {} on {:#x}", r.bit, r.rs1),
            None => panic!("kind {} made no rd query", r.bit),
        }
    }

    // Acceptance 2's edges, each read off the rows that ran.
    let shamts = |bit: u32| -> Vec<u32> {
        let mut v: Vec<u32> = rows
            .iter()
            .filter(|r| r.bit == bit)
            .map(|r| r.imm)
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    };
    for bit in [kind::SLLI, kind::SRLI, kind::SRAI] {
        let got = shamts(bit);
        for shamt in [0, 1, 31] {
            assert!(got.contains(&shamt), "kind {bit} at shamt {shamt}: {got:?}");
        }
    }
    let register_amounts: Vec<u32> = rows
        .iter()
        .filter(|r| matches!(r.bit, kind::SLL | kind::SRL | kind::SRA))
        .filter_map(|r| r.rs2)
        .collect();
    for amount in [32, 33] {
        assert!(
            register_amounts.contains(&amount),
            "a register shift by {amount}: {register_amounts:?}"
        );
    }
    // The truncation really truncates: rs2 = 32 leaves the word alone and
    // rs2 = 33 shifts by one.
    for r in rows.iter().filter(|r| r.rs2 == Some(32)) {
        assert_eq!(r.rd, Some(r.rs1), "a shift by rs2 = 32 leaves the word");
    }
    assert!(
        rows.iter().any(|r| r.bit == kind::SRA && r.rs1 >> 31 == 1),
        "sra of a negative operand"
    );

    // `srai` against `srli` on one negative operand at one shamt: the same
    // input, different answers, and each the ISA's.
    let pair = rows
        .iter()
        .filter(|r| r.bit == kind::SRAI && r.rs1 >> 31 == 1)
        .find_map(|arith| {
            rows.iter()
                .find(|r| r.bit == kind::SRLI && r.rs1 == arith.rs1 && r.imm == arith.imm)
                .map(|logical| (arith, logical))
        })
        .expect("an srai and an srli on one negative operand at one shamt");
    let (arith, logical) = pair;
    assert_eq!(arith.rd, Some(((arith.rs1 as i32) >> arith.imm) as u32));
    assert_eq!(logical.rd, Some(logical.rs1 >> logical.imm));
    assert_ne!(arith.rd, logical.rd, "the sign is replicated, or it is not");
}

/// The prover's own fill of the family's shard, `prover::family_fill`, over
/// the guest's real trace: every channel's multiplicities count — so every
/// gated tuple of the shard is a row of its table — and every live row, the
/// two padding rows after them and the last row of the shard satisfy every
/// gate and every range obligation. The fill and the circuit agree, in
/// ordinary CI, without a proof.
#[test]
fn the_fill_satisfies_every_gate_and_every_table() {
    let (program, archive) = alu();
    let live = ran(&program, &archive).len();
    let columns = filled(&program, &archive, 0, VARS, true);
    let rows: Vec<usize> = (0..live + 2).chain([(1 << VARS) - 1]).collect();
    assert_rows_hold(&columns, &rows);
}

/// The family's fill of shard `index` at `2^vars` rows — its setup columns
/// held to the program's decoded table and to the packed generic table row for
/// row — with every channel's multiplicities counted over it when `count`, and
/// zero columns in their place otherwise: a height below the timestamp
/// channel's `2^19` has no count, and no gate or range obligation reads one.
fn filled(
    program: &prover::Program,
    archive: &trace::TraceArchive,
    index: u32,
    vars: u32,
    count: bool,
) -> Vec<(PolyAddress, poly::MultilinearPoly)> {
    let a = artifact();
    let fill = prover::family_fill(family::SHIFT_BITWISE).expect("the family's fill");
    let source = prover::ShardSource {
        program,
        archive,
        family: family::SHIFT_BITWISE,
        index,
        height: 1 << vars,
        window: 0,
    };
    let mut columns = fill(&source).expect("the fill");
    let column = |columns: &[(PolyAddress, poly::MultilinearPoly)], address: PolyAddress| {
        columns
            .iter()
            .find(|(c, _)| *c == address)
            .unwrap_or_else(|| panic!("the fill has no {address}"))
            .1
            .clone()
    };
    // The setup columns are the tables the key's commitments are of: the
    // decoded table identity binds, then the packed table the SRS digest
    // covers.
    let table = program
        .tables
        .family(family::SHIFT_BITWISE)
        .expect("the family's table");
    let generic = program::lookup_tables::generic_table(vars);
    for j in 0..shift_bitwise::TABLE_WIDTH + generic_table::WIDTH {
        let filled = column(&columns, PolyAddress::Setup(j as u32));
        let want = match j.checked_sub(shift_bitwise::TABLE_WIDTH) {
            None => table.column_poly(j),
            Some(g) => generic[g].clone(),
        };
        assert_eq!(filled.len(), 1 << vars, "S[{j}]'s height");
        assert!(
            (0..1 << vars).all(|i| filled.get(i) == want.get(i)),
            "S[{j}] is not its table"
        );
    }
    if count {
        let counts = trace::build_multiplicities(&a, &columns, &shift_bitwise::channels())
            .expect("every tuple of the shard is a row of its table");
        columns.extend(counts);
    } else {
        for m in shift_bitwise::MULTIPLICITIES {
            let zero = poly::MultilinearPoly::new(poly::PolyBacking::U32(vec![0; 1 << vars]));
            columns.push((m, zero));
        }
    }
    assert_eq!(
        columns.len(),
        a.committed().len(),
        "one column per committed address"
    );
    columns
}

/// Every gate and every range obligation holds on each of `rows` of
/// `columns`, a filled shard.
fn assert_rows_hold(columns: &[(PolyAddress, poly::MultilinearPoly)], rows: &[usize]) {
    let a = artifact();
    let column = |address: PolyAddress| {
        &columns
            .iter()
            .find(|(c, _)| *c == address)
            .unwrap_or_else(|| panic!("the fill has no {address}"))
            .1
    };
    let ordered: Vec<&poly::MultilinearPoly> = a.committed().iter().map(|x| column(*x)).collect();
    let ch = challenges(&a);
    for &row in rows {
        let mut r = Row::default();
        let committed: Vec<Fr> = ordered.iter().map(|c| c.get(row)).collect();
        // Through the named row, so the scratch is computed exactly as the
        // hand-built rows' is.
        for (name, value) in a
            .memory
            .iter()
            .chain(&a.witness)
            .chain(&a.setup)
            .zip(&committed)
        {
            r.set(Box::leak(name.clone().into_boxed_str()), *value);
        }
        let w = r.witness(&a, row);
        assert_eq!(w.committed, committed);
        assert_eq!(violated_relations(&a, &w, &ch), none(), "row {row}");
        assert_eq!(violated_lookups(&a, &w), none(), "row {row}");
    }
}
