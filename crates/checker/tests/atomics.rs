//! S19's `ATOMICS` circuit (`docs/spec/memory-ops.md`), row by row, in
//! ordinary CI.
//!
//! No forward pass over `2^20` rows: each row is built by hand from what the
//! instruction computes — Rust's own `u32` and `i32` arithmetic, not the
//! circuit's — and evaluated alone through `checker::violated_relations` and
//! `violated_lookups`, its row-local scratch computed by `gkr::gate_values`.
//! The two table channels, which `violated_lookups` does not read, are held
//! here to the tables themselves: a row's gated generic tuple to
//! `program::lookup_tables`' entries, its gated decoder tuple to the table
//! columns the row carries. The same family's fill over `guests/mem`'s real
//! trace is `crates/checker/tests/mem_fill.rs`'.
//!
//! Acceptance 5 is here as rows — the four min/max kinds over the one operand
//! pair where the signed and the unsigned orderings disagree, each answer
//! proved and the other refused by the gap's range pair — and so is the byte-key
//! hole S18 found, which this family inherits together with the AND table.

use std::collections::{BTreeMap, BTreeSet};

use checker::{
    check_laws, check_lookup_discharge, check_padding, check_padding_identity, violated_lookups,
    violated_relations, WitnessRow,
};
use constants::extra_mask::atomics as kind;
use constants::{challenge_slot, family, generic_table, lookup_channel};
use constraints::lookup::{check_discharge, ChannelSpec};
use constraints::memory::check_memory;
use constraints::{
    atomics, family_circuit, CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind,
};
use field::Fr;
use gkr::{eval_gate, gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use program::lookup_tables::generic_entries;
use test_support::{sha256, to_hex};

const VARS: u32 = 20;
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/atomics.bin"
);
const FIXTURE_SHA256: &str = "ae58b1ca82916f6d519636836c889f31266bc694e7929e43c65ba574643d3108";

/// The cycle every hand-built row runs at, and the row it is evaluated at.
const CYCLE: u64 = 7;
const AT_ROW: usize = 1 << 15;

/// The two words the whole sign boundary is argued over: `0x7fffffff` is the
/// largest signed and `0x80000000` the smallest, and they are in the opposite
/// order unsigned.
const POS: u32 = 0x7FFF_FFFF;
const NEG: u32 = 0x8000_0000;

fn artifact() -> CircuitArtifact {
    atomics::artifact(VARS)
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

/// One instruction of the family, as a decoded table row and its registers.
/// Every A instruction is four bytes and R-type, so there is no `compressed`
/// flag and no immediate.
#[derive(Clone, Copy, Debug)]
struct Instr {
    bit: u32,
    pc: u32,
    rs1: u32,
    rs2: u32,
    rd: u32,
}

impl Instr {
    fn new(bit: u32) -> Instr {
        Instr {
            bit,
            pc: 0x1000,
            rs1: 5,
            // `lr.w`'s form has no rs2, so its decoded column is x0.
            rs2: if bit == kind::LR_W { 0 } else { 6 },
            rd: 7,
        }
    }
}

/// The column-name suffix of each kind bit, `constants::extra_mask::atomics`
/// order.
fn mnemonic(bit: u32) -> &'static str {
    [
        "amoadd", "amoswap", "lr", "sc", "amoxor", "amoor", "amoand", "amomin", "amomax",
        "amominu", "amomaxu",
    ][bit as usize]
}

/// The word the instruction leaves in memory, by Rust's own operators over the
/// old word and the source — never by the circuit's algebra.
fn rv32a(bit: u32, old: u32, src: u32) -> u32 {
    match bit {
        // `lr.w` reserves and rewrites the word it read.
        kind::LR_W => old,
        // `sc.w` always succeeds here, so it always stores.
        kind::SC_W | kind::AMOSWAP_W => src,
        kind::AMOADD_W => old.wrapping_add(src),
        kind::AMOAND_W => old & src,
        kind::AMOOR_W => old | src,
        kind::AMOXOR_W => old ^ src,
        kind::AMOMIN_W => (old as i32).min(src as i32) as u32,
        kind::AMOMAX_W => (old as i32).max(src as i32) as u32,
        kind::AMOMINU_W => old.min(src),
        kind::AMOMAXU_W => old.max(src),
        other => panic!("kind bit {other} is not this family's"),
    }
}

/// An honest row: every column what the instruction computes, by Rust's own
/// arithmetic. `address` is the word address the atomic runs at — the value
/// `rs1` holds — `old` the word already there, `src` the value `rs2` holds and
/// `rd_old` whatever the destination register held before.
fn honest(i: Instr, address: u32, old: u32, src: u32, rd_old: u32) -> Row {
    assert_eq!(address % 4, 0, "an atomic's address is word-aligned");
    // `lr.w` makes no rs2 query at all, so its second operand is 0.
    let b = if i.bit == kind::LR_W { 0 } else { src };
    let (sum, add_wrap) = old.overflowing_add(b);
    let signed_order = matches!(i.bit, kind::AMOMIN_W | kind::AMOMAX_W);
    let lt = match signed_order {
        true => (old as i32) < (b as i32),
        false => old < b,
    };
    // The smaller of the two under that ordering, and the distance between
    // them read as a 32-bit word — `gap = D + 2^32·lt` is exactly the
    // wrapping difference in both orderings.
    let lo = if lt { old } else { b };
    let gap = old.wrapping_sub(b);
    let new = rv32a(i.bit, old, b);
    // `sc.w` writes its success code, which is always 0; every other kind
    // writes the word it found.
    let sel = if i.bit == kind::SC_W { 0 } else { old };
    let bitwise = matches!(i.bit, kind::AMOAND_W | kind::AMOOR_W | kind::AMOXOR_W);
    let seq = i.pc + 4;

    let mut r = Row::default();
    r.set("cycle", f(CYCLE));
    r.set("pc_mask", Fr::ONE)
        .set("pc_read_ts", f(4 * (CYCLE - 1)))
        .set("pc_read_value", f(i.pc as u64))
        .set("pc_write_value", f(seq as u64));
    r.query("rs1", 1, i.rs1 as u64, address as u64, address as u64);
    if i.bit != kind::LR_W {
        r.query("rs2", 2, i.rs2 as u64, b as u64, b as u64);
    }
    r.query("ram", 3, address as u64, old as u64, new as u64);
    let write = if i.rd == 0 { 0 } else { sel };
    r.query("rd", 3, i.rd as u64, rd_old as u64, write as u64);
    match i.rd {
        0 => r.set("rd_is_zero", Fr::ONE),
        d => r.set("rd_inv", f(d as u64).inverse().expect("nonzero")),
    };
    r.set("rd_selected", f(sel as u64));

    // The decoded row, in both places it appears: the claimed witness columns
    // and the table columns the decoder lookup matches them against. Five, not
    // six: this family's tuple carries no immediate.
    let mask = 1u32 << i.bit;
    for (witness, table, v) in [
        ("decoded_next_pc", "table_next_pc", seq),
        ("decoded_rs1", "table_rs1", i.rs1),
        ("decoded_rs2", "table_rs2", i.rs2),
        ("decoded_rd", "table_rd", i.rd),
        ("decoded_mask", "table_extra_mask", mask),
    ] {
        r.set(witness, f(v as u64)).set(table, f(v as u64));
    }
    r.set("table_pc", f(i.pc as u64));
    r.set(name("kind", mnemonic(i.bit)), Fr::ONE);

    for (column, v) in [
        ("word_index", (address / 4) as u64),
        ("word_index_hi", ((address / 4) >> 16) as u64),
        ("sum", sum as u64),
        ("sum_hi", (sum >> 16) as u64),
        ("add_wrap", add_wrap as u64),
        ("f_bitwise", bitwise as u64),
        ("old_hi", (old >> 16) as u64),
        ("old_sign", (old >> 31) as u64),
        ("src_hi", (b >> 16) as u64),
        ("src_sign", (b >> 31) as u64),
        ("lt", lt as u64),
        ("cmp_gap", gap as u64),
        ("cmp_gap_hi", (gap >> 16) as u64),
        ("lo", lo as u64),
    ] {
        r.set(column, f(v));
    }
    let leak = |s: String| -> &'static str { Box::leak(s.into_boxed_str()) };
    for j in 0..4 {
        let (byte_a, byte_b) = ((old >> (8 * j)) & 0xff, (b >> (8 * j)) & 0xff);
        r.set(leak(format!("byte_a{j}")), f(byte_a as u64));
        r.set(leak(format!("byte_b{j}")), f(byte_b as u64));
        r.set(leak(format!("byte_and{j}")), f((byte_a & byte_b) as u64));
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
                let table: Vec<Fr> = (0..atomics::TABLE_WIDTH)
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

/// The enforcing gate `name`, by name.
fn relation<'a>(a: &'a CircuitArtifact, name: &str) -> &'a GateDef {
    &a.relations
        .iter()
        .find(|r| r.name == name)
        .unwrap_or_else(|| panic!("no relation `{name}`"))
        .gate
}

/// The obligation `name`, by name.
fn lookup<'a>(a: &'a CircuitArtifact, name: &str) -> &'a LookupExpr {
    a.lookups
        .iter()
        .find(|l| l.name == name)
        .unwrap_or_else(|| panic!("no lookup `{name}`"))
}

// ---------------------------------------------------------------------------
// The circuit
// ---------------------------------------------------------------------------

/// The committed fixture is the constructor's bytes, and the circuit passes
/// both enforcement points — `validate`, which built it, and `checker`'s
/// independent validators — plus the memory and lookup construction rules.
#[test]
fn the_circuit_is_the_fixture_and_keeps_every_rule() {
    let bytes = std::fs::read(FIXTURE).expect("the atomics fixture");
    assert_eq!(to_hex(&sha256(&bytes)), FIXTURE_SHA256);
    assert_eq!(atomics::artifact(22).to_bytes(), bytes);
    assert_eq!(
        CircuitArtifact::from_bytes(&bytes).expect("the fixture decodes"),
        atomics::artifact(22)
    );

    let a = artifact();
    a.validate().expect("the circuit is lawful");
    check_laws(&a).expect("the checker's validators agree");
    check_padding(&a).expect("the padding contract");
    check_padding_identity(&a).expect("the padding identity");
    check_memory(&a).expect("the memory rules");
    let channels = atomics::channels();
    check_discharge(&a, &channels).expect("every obligation is discharged once");
    check_lookup_discharge(&a, &channels).expect("the checker's discharge agrees");
}

/// The registry holds the family at 19 variables and up and nowhere below, and
/// what it returns is this constructor's. It reads the packed generic table —
/// two sign lookups and four byte ANDs — so a shard of it opens its last three
/// setup columns against the verifying key's generic-table commitments.
#[test]
fn the_registry_holds_the_family() {
    let c = family_circuit(family::ATOMICS, VARS).expect("the family at 2^20");
    assert_eq!(c.family, family::ATOMICS);
    assert_eq!(c.artifact, artifact());
    assert_eq!(c.channels, atomics::channels());
    assert!(
        c.reads_generic_table(),
        "the family reads U16GetSign and the AND table"
    );
    assert_eq!(family_circuit(family::ATOMICS, 18), None);
    let at_19 = family_circuit(family::ATOMICS, 19).expect("the family at 2^19");
    assert_eq!(at_19.artifact, atomics::artifact(19));
}

/// The layout is `docs/spec/memory-ops.md` §6's and the gates and lookups are
/// its §6.2 and §6.5, by name and in order. The lists are literal because only
/// a literal list catches a silent reordering: a column's position is what the
/// fill writes to and what a verifying key commits, and a lookup's position is
/// what `beta`'s derived powers weight.
#[test]
fn the_layout_and_the_gates_are_the_spec() {
    let a = artifact();
    // Five queries — and `ram` and `rd` both sit at Δ 3, in different address
    // spaces, which is why this family fills all four of S14's slots.
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
            "ram_gap_hi",
            "rd_gap_hi",
            "rd_inv",
            "rd_is_zero",
            "rd_selected",
            "decoded_next_pc",
            "decoded_rs1",
            "decoded_rs2",
            "decoded_rd",
            "decoded_mask",
            "kind_amoadd",
            "kind_amoswap",
            "kind_lr",
            "kind_sc",
            "kind_amoxor",
            "kind_amoor",
            "kind_amoand",
            "kind_amomin",
            "kind_amomax",
            "kind_amominu",
            "kind_amomaxu",
            "word_index",
            "word_index_hi",
            "sum",
            "sum_hi",
            "add_wrap",
            "f_bitwise",
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
            "old_hi",
            "old_sign",
            "src_hi",
            "src_sign",
            "lt",
            "cmp_gap",
            "cmp_gap_hi",
            "lo",
            "mult_timestamp",
            "mult_range16",
            "mult_generic",
            "mult_decoder",
        ])
    );
    // Six setup columns of decoded table, not seven: every A instruction is
    // R-type, so the tuple carries no immediate and the packed table follows
    // at `S[6..9]`.
    assert_eq!(
        a.setup,
        names(&[
            "table_pc",
            "table_next_pc",
            "table_rs1",
            "table_rs2",
            "table_rd",
            "table_extra_mask",
            "generic_key",
            "generic_value",
            "generic_result",
        ])
    );
    assert_eq!(a.memory.len(), 26);
    assert_eq!(a.witness.len(), 54);
    assert_eq!(a.setup.len(), 9);
    assert_eq!(a.committed().len(), 89);
    assert_eq!(atomics::TABLE_WIDTH, 6);
    assert_eq!(
        a.virtuals,
        vec![
            (VirtualKind::Range19, "range19".to_string()),
            (VirtualKind::Range16, "range16".to_string()),
        ]
    );

    // The forty-six enforcing gates: the frame's eleven, then this family's
    // thirty-five.
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
            "ram_mask_boolean",
            "rd_mask_boolean",
            "rs1_writes_back",
            "rs2_writes_back",
            "rd_is_zero_inverse",
            "rd_is_zero_at_nonzero",
            "rd_is_zero_boolean",
            "rd_write_masked",
            "kind_amoadd_boolean",
            "kind_amoswap_boolean",
            "kind_lr_boolean",
            "kind_sc_boolean",
            "kind_amoxor_boolean",
            "kind_amoor_boolean",
            "kind_amoand_boolean",
            "kind_amomin_boolean",
            "kind_amomax_boolean",
            "kind_amominu_boolean",
            "kind_amomaxu_boolean",
            "decoded_mask_bits",
            "rs1_mask_rule",
            "rs2_mask_rule",
            "ram_mask_rule",
            "rd_mask_rule",
            "rs1_addr_rule",
            "rs2_addr_rule",
            "rd_addr_rule",
            "ram_addr_rule",
            "rs1_value_masked",
            "rs2_value_masked",
            "addr_word",
            "add_wrap_boolean",
            "add_rule",
            "f_bitwise_boolean",
            "f_bitwise_rule",
            "old_bytes_rule",
            "src_bytes_rule",
            "cmp_order",
            "cmp_lt_boolean",
            "lo_rule",
            "ram_value_rule",
            "rd_value_rule",
            "next_pc_rule",
        ])
    );
    assert_eq!(enforcing.len(), 46);

    // The thirty-six obligations, each with the channel it is read on and the
    // selector it is read under. A selector moved to another column is a
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
            ("gap_hi_ram", timestamp, m(16)),
            ("gap_lo_ram", timestamp, m(16)),
            ("gap_hi_rd", timestamp, m(21)),
            ("gap_lo_rd", timestamp, m(21)),
            ("cmp_lhs_hi_range", range, m(1)),
            ("cmp_lhs_lo_range", range, m(1)),
            ("cmp_rhs_hi_range", range, m(1)),
            ("cmp_rhs_lo_range", range, m(1)),
            ("cmp_gap_hi_range", range, m(1)),
            ("cmp_gap_lo_range", range, m(1)),
            ("cmp_lhs_get_sign", generic, m(1)),
            ("cmp_rhs_get_sign", generic, m(1)),
            ("word_index_hi_range", range, m(1)),
            ("word_index_lo_range", range, m(1)),
            // `4·word_index_hi` below `2^16` puts the word index below `2^30`,
            // so `rs1 = 4·word_index` is a 32-bit address and no misaligned
            // atomic has a witness at all.
            ("word_index_hi_scaled", range, m(1)),
            ("sum_hi_range", range, m(1)),
            ("sum_lo_range", range, m(1)),
            // The AND keys' own bounds, each a direct check and a scaled one,
            // under the selector of the lookups they bound. Without them a
            // byte column of 65,823 reads a `ShiftPowers` row and the family
            // stores a wrong word.
            ("byte_a0_range", range, w(29)),
            ("byte_a0_scaled", range, w(29)),
            ("byte_a1_range", range, w(29)),
            ("byte_a1_scaled", range, w(29)),
            ("byte_a2_range", range, w(29)),
            ("byte_a2_scaled", range, w(29)),
            ("byte_a3_range", range, w(29)),
            ("byte_a3_scaled", range, w(29)),
            ("and_byte_0", generic, w(29)),
            ("and_byte_1", generic, w(29)),
            ("and_byte_2", generic, w(29)),
            ("and_byte_3", generic, w(29)),
            ("decode_row", decoder, m(1)),
        ]
    );
    assert_eq!(lookups.len(), 36);
    // The per-channel counts, which `artifact` asserts when it builds the
    // circuit; here they are read off the artifact instead.
    for (channel, want) in [(timestamp, 10), (range, 19), (generic, 6), (decoder, 1)] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(got, want, "channel {channel}");
    }
    // Every selector is a frame mask but the twelve read under `f_bitwise`:
    // the four AND keys' bounds and the four AND lookups themselves.
    let gated: Vec<&(&str, u32, PolyAddress)> = lookups
        .iter()
        .filter(|(_, _, s)| matches!(s, PolyAddress::Witness(_)))
        .collect();
    assert_eq!(gated.len(), 12);
    assert!(gated.iter().all(|(_, _, s)| *s == atomics::F_BITWISE));

    // The four channels in output order: the two range tables, then the packed
    // generic table at `S[6..9]` and the decoded table at `S[0..6]`.
    assert_eq!(
        atomics::channels(),
        vec![
            ChannelSpec {
                channel: timestamp,
                table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
                multiplicity: w(50),
            },
            ChannelSpec {
                channel: range,
                table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
                multiplicity: w(51),
            },
            ChannelSpec {
                channel: generic,
                table: (6..9).map(PolyAddress::Setup).collect(),
                multiplicity: w(52),
            },
            ChannelSpec {
                channel: decoder,
                table: (0..6).map(PolyAddress::Setup).collect(),
                multiplicity: w(53),
            },
        ]
    );
    assert_eq!(atomics::MULTIPLICITIES, [w(50), w(51), w(52), w(53)]);
    assert_eq!(atomics::GENERIC_TABLE.len(), generic_table::WIDTH);

    // The leaves: five queries a side padded to eight, then one `(num, den)`
    // pair per fraction, each channel's tree padded to a power of two —
    // 16 + 2·(16 + 32 + 8 + 2) = 132.
    assert_eq!(a.layers[0].width, 132);
    assert_eq!(a.outputs.len(), 2 + 2 * 4);
    // The leaves, five row-wise levels — the `range16` tree's twenty fractions
    // pad to thirty-two, and nothing here is wider — and one halving level per
    // variable.
    assert_eq!(a.depth(), 1 + 5 + VARS as usize);
}

/// The eleven kind bits are `constants::extra_mask::atomics`' bits, read
/// through `program::row_kind` for each of the A extension's eleven `isa::Instr`
/// variants and asserted by mnemonic.
///
/// This is the test that catches a transposed bit list. `amoand` and `amoor`
/// are the pair at risk — the prose that lists the instructions puts them in
/// the opposite order to the constants — and a swap there is silent: both arms
/// exist, both are degree 2, every gate still holds, and `amoand` simply
/// computes an `or`. So each mnemonic's bit index is asserted by name, the
/// column at that bit's address is asserted to be that mnemonic's, and the
/// mask-recomposition gate is asserted to weight it by `2^bit`.
#[test]
fn the_kind_bits_are_the_extra_mask_constants() {
    use isa::Instr::*;
    let a = artifact();
    let (rd, rs1, rs2) = (7u8, 5u8, 6u8);
    let corpus: [(&str, u32, isa::Instr); 11] = [
        (
            "amoadd",
            kind::AMOADD_W,
            AmoaddW {
                rd,
                rs1,
                rs2,
                aq: false,
                rl: false,
            },
        ),
        (
            "amoswap",
            kind::AMOSWAP_W,
            AmoswapW {
                rd,
                rs1,
                rs2,
                aq: false,
                rl: false,
            },
        ),
        (
            "lr",
            kind::LR_W,
            LrW {
                rd,
                rs1,
                aq: false,
                rl: false,
            },
        ),
        (
            "sc",
            kind::SC_W,
            ScW {
                rd,
                rs1,
                rs2,
                aq: false,
                rl: false,
            },
        ),
        (
            "amoxor",
            kind::AMOXOR_W,
            AmoxorW {
                rd,
                rs1,
                rs2,
                aq: false,
                rl: false,
            },
        ),
        (
            "amoor",
            kind::AMOOR_W,
            AmoorW {
                rd,
                rs1,
                rs2,
                aq: false,
                rl: false,
            },
        ),
        (
            "amoand",
            kind::AMOAND_W,
            AmoandW {
                rd,
                rs1,
                rs2,
                aq: false,
                rl: false,
            },
        ),
        (
            "amomin",
            kind::AMOMIN_W,
            AmominW {
                rd,
                rs1,
                rs2,
                aq: false,
                rl: false,
            },
        ),
        (
            "amomax",
            kind::AMOMAX_W,
            AmomaxW {
                rd,
                rs1,
                rs2,
                aq: false,
                rl: false,
            },
        ),
        (
            "amominu",
            kind::AMOMINU_W,
            AmominuW {
                rd,
                rs1,
                rs2,
                aq: false,
                rl: false,
            },
        ),
        (
            "amomaxu",
            kind::AMOMAXU_W,
            AmomaxuW {
                rd,
                rs1,
                rs2,
                aq: false,
                rl: false,
            },
        ),
    ];

    // The bit each mnemonic owns, written out rather than derived.
    let expected: [(&str, u32); 11] = [
        ("amoadd", 0),
        ("amoswap", 1),
        ("lr", 2),
        ("sc", 3),
        ("amoxor", 4),
        ("amoor", 5),
        ("amoand", 6),
        ("amomin", 7),
        ("amomax", 8),
        ("amominu", 9),
        ("amomaxu", 10),
    ];
    for (mnemonic, bit) in expected {
        let (_, k, _) = corpus
            .iter()
            .find(|(m, _, _)| *m == mnemonic)
            .unwrap_or_else(|| panic!("no `{mnemonic}` in the corpus"));
        assert_eq!(*k, bit, "`{mnemonic}` is bit {k}, not {bit}");
    }

    let mask_bits = relation(&a, "decoded_mask_bits");
    let GateDef::Linear { terms, .. } = mask_bits else {
        panic!("decoded_mask_bits is a Linear gate");
    };
    for (mnemonic, bit, instr) in &corpus {
        // The routing: every form of the instruction lands in this family at
        // this bit.
        let (fam, k) = program::row_kind(instr);
        assert_eq!(fam, family::ATOMICS, "{mnemonic}");
        assert_eq!(k, *bit, "{mnemonic}");
        assert_eq!(atomics::LEGAL_MASKS[*bit as usize], 1 << bit, "{mnemonic}");

        // The circuit's arm: the bit's own column is named after this
        // mnemonic, and the recomposition gate weights it by `2^bit`.
        let address = atomics::KINDS[*bit as usize];
        let PolyAddress::Witness(at) = address else {
            panic!("a kind bit is a witness column");
        };
        assert_eq!(
            a.witness[at as usize],
            format!("kind_{mnemonic}"),
            "bit {bit} is not `{mnemonic}`'s column"
        );
        assert_eq!(
            terms[*bit as usize],
            (Coeff::Literal(f(1 << bit)), address),
            "the mask's bit {bit} is not `{mnemonic}`'s column at 2^{bit}"
        );
    }
    // And the mnemonic table this file indexes by agrees with all of it.
    for (name, bit) in expected {
        assert_eq!(mnemonic(bit), name);
    }
}

/// The comparison's four parameters, read off the artifact.
///
/// They are not derivable from anything else in the circuit, and each wrong
/// choice is a silent, total break of the four min/max kinds and of nothing
/// else: `amomin` against the wrong left operand still satisfies every gate,
/// still range-checks, and still stores a word. So the selector, the two
/// operands and the signed bits are asserted here by the operands the gate and
/// the lookups carry.
#[test]
fn the_comparison_is_over_the_old_word_and_rs2() {
    let a = artifact();
    let m = PolyAddress::Memory;
    // The two operands, named: the RAM query's read value is the old word,
    // and the rs2 query's is the source.
    assert_eq!(a.memory[19], "ram_read_value");
    assert_eq!(a.memory[14], "rs2_read_value");
    let (old, src) = (m(19), m(14));
    let w = PolyAddress::Witness;
    let (old_sign, src_sign) = (w(43), w(45));
    let (lt, gap, gap_hi) = (w(46), w(47), w(48));
    let (old_hi, src_hi) = (w(42), w(44));
    let (amomin, amomax) = (
        atomics::KINDS[kind::AMOMIN_W as usize],
        atomics::KINDS[kind::AMOMAX_W as usize],
    );
    assert_eq!(a.witness[42], "old_hi");
    assert_eq!(a.witness[43], "old_sign");
    assert_eq!(a.witness[44], "src_hi");
    assert_eq!(a.witness[45], "src_sign");
    assert_eq!(a.witness[46], "lt");
    assert_eq!(a.witness[47], "cmp_gap");
    assert_eq!(a.witness[48], "cmp_gap_hi");

    // The one equation, in the gadget's own operand order: the two operands,
    // the ordering bit and the gap, then one `(bit, sign)` product per signed
    // kind. Exactly two kinds appear, and they are `amomin` and `amomax` — a
    // third would put an unsigned kind under a signed ordering, and a missing
    // one would leave a signed kind ordering unsigned.
    assert_eq!(
        relation(&a, "cmp_order").operands(),
        vec![
            old, src, lt, gap, amomin, old_sign, amomin, src_sign, amomax, old_sign, amomax,
            src_sign,
        ]
    );
    assert_eq!(relation(&a, "cmp_lt_boolean").operands(), vec![lt, lt, lt]);

    // The six range obligations and the two sign lookups, each under the pc
    // mask — the row's liveness — and each over the operand it bounds.
    for (obligation, want) in [
        ("cmp_lhs_hi_range", vec![old_hi]),
        ("cmp_lhs_lo_range", vec![old, old_hi]),
        ("cmp_rhs_hi_range", vec![src_hi]),
        ("cmp_rhs_lo_range", vec![src, src_hi]),
        ("cmp_gap_hi_range", vec![gap_hi]),
        ("cmp_gap_lo_range", vec![gap, gap_hi]),
    ] {
        let l = lookup(&a, obligation);
        assert_eq!(l.selector, m(1), "{obligation}");
        assert_eq!(l.channel, lookup_channel::RANGE16, "{obligation}");
        assert_eq!(l.tuple.len(), 1, "{obligation}");
        assert_eq!(l.tuple[0].operands(), want, "{obligation}");
    }
    for (obligation, hi, sign) in [
        ("cmp_lhs_get_sign", old_hi, old_sign),
        ("cmp_rhs_get_sign", src_hi, src_sign),
    ] {
        let l = lookup(&a, obligation);
        assert_eq!(l.selector, m(1), "{obligation}");
        assert_eq!(l.channel, lookup_channel::GENERIC, "{obligation}");
        assert_eq!(l.tuple.len(), generic_table::WIDTH, "{obligation}");
        assert_eq!(l.tuple[0].operands(), vec![hi], "{obligation}");
        assert_eq!(l.tuple[1].operands(), vec![sign], "{obligation}");
        assert!(l.tuple[2].operands().is_empty(), "{obligation}");
    }

    // The smaller operand is selected from the same two columns, so a
    // comparison over the wrong pair would write the wrong word too.
    assert_eq!(
        relation(&a, "lo_rule").operands(),
        vec![w(49), src, lt, old, lt, src]
    );
}

// ---------------------------------------------------------------------------
// Honest rows
// ---------------------------------------------------------------------------

/// Where every hand-built row runs, unless it says otherwise.
const ADDRESS: u32 = 0x2000;

/// The catalogue of honest rows: every kind, the carry and the `x0`
/// destination, `lr.w`'s missing rs2 query, `sc.w`'s zero, the sign boundary in
/// both operand orders for all four min/max kinds, the bitwise trio over two
/// patterns, and the all-zero padding row.
fn honest_rows() -> Vec<(&'static str, Row)> {
    let mut out: Vec<(&'static str, Row)> = Vec::new();
    let mut push = |what: &'static str, r: Row| out.push((what, r));

    // Every kind once, over operands that exercise it.
    for (what, bit, old, src) in [
        ("amoadd", kind::AMOADD_W, 0x1234_5678, 0x0000_1111),
        ("amoswap", kind::AMOSWAP_W, 0x1234_5678, 0x8765_4321),
        ("lr.w", kind::LR_W, 0x1234_5678, 0),
        ("sc.w", kind::SC_W, 0x1234_5678, 0xDEAD_BEEF),
        ("amoxor", kind::AMOXOR_W, 0xF0F0_0FF0, 0x0FF0_F00F),
        ("amoor", kind::AMOOR_W, 0xF0F0_0FF0, 0x0FF0_F00F),
        ("amoand", kind::AMOAND_W, 0xF0F0_0FF0, 0x0FF0_F00F),
        ("amomin", kind::AMOMIN_W, 0x0000_0005, 0x0000_0009),
        ("amomax", kind::AMOMAX_W, 0x0000_0005, 0x0000_0009),
        ("amominu", kind::AMOMINU_W, 0x0000_0005, 0x0000_0009),
        ("amomaxu", kind::AMOMAXU_W, 0x0000_0005, 0x0000_0009),
    ] {
        push(
            what,
            honest(Instr::new(bit), ADDRESS, old, src, 0x1111_1111),
        );
    }

    // The carry: a sum past `2^32`, which `add_wrap` absorbs.
    push(
        "amoadd past 2^32",
        honest(
            Instr::new(kind::AMOADD_W),
            ADDRESS,
            0xFFFF_FFF0,
            0x0000_0020,
            0,
        ),
    );
    // An `x0` destination: the row computes the old word and discards it.
    let mut i = Instr::new(kind::AMOADD_W);
    i.rd = 0;
    push(
        "amoadd into x0",
        honest(i, ADDRESS, 0x1234_5678, 0x0000_1111, 0),
    );

    // The sign boundary, both operand orders, all four min/max kinds: the one
    // operand pair where the signed and the unsigned orderings disagree.
    for (what, bit, old, src) in [
        ("amomin pos neg", kind::AMOMIN_W, POS, NEG),
        ("amomin neg pos", kind::AMOMIN_W, NEG, POS),
        ("amomax pos neg", kind::AMOMAX_W, POS, NEG),
        ("amomax neg pos", kind::AMOMAX_W, NEG, POS),
        ("amominu pos neg", kind::AMOMINU_W, POS, NEG),
        ("amominu neg pos", kind::AMOMINU_W, NEG, POS),
        ("amomaxu pos neg", kind::AMOMAXU_W, POS, NEG),
        ("amomaxu neg pos", kind::AMOMAXU_W, NEG, POS),
    ] {
        push(what, honest(Instr::new(bit), ADDRESS, old, src, 0));
    }

    // The bitwise trio over the second pattern too, and over one with no bit
    // in common so the AND is 0 and the row stores 0 — the base a tamper needs
    // when its `rd` term must stay satisfied while something else moves.
    for (what, bit) in [
        ("amoand to zero", kind::AMOAND_W),
        ("amoor to all ones", kind::AMOOR_W),
    ] {
        push(
            what,
            honest(Instr::new(bit), ADDRESS, 0xF0F0_0FF0, 0x0F0F_F00F, 0),
        );
    }

    // A row at word zero, whose rs1 value, word index and RAM address are all
    // 0 — the base for the presence tampers, which must leave `addr_word`
    // alone.
    push(
        "amoswap at word zero",
        honest(Instr::new(kind::AMOSWAP_W), 0, 0, 0, 0),
    );
    // A row at the top of the addressable window, whose word index is the
    // widest the three obligations allow.
    push(
        "amoswap high in memory",
        honest(
            Instr::new(kind::AMOSWAP_W),
            0xFFFF_FFFC,
            0x0000_0001,
            0x0000_0002,
            0,
        ),
    );

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

    // The catalogue really is every kind, and each of the rows the stage's
    // acceptance names is really the shape it claims.
    let rows = honest_rows();
    for bit in 0..11u32 {
        let column = name("kind", mnemonic(bit));
        assert!(
            rows.iter().any(|(_, r)| r.get(column) == Fr::ONE),
            "no honest row of kind `{}`",
            mnemonic(bit)
        );
    }
    // `lr.w` makes no rs2 query at all: its form has no rs2 register.
    let lr = row("lr.w");
    assert_eq!(lr.get("rs2_mask"), Fr::ZERO);
    assert_eq!(lr.get("rs2_read_value"), Fr::ZERO);
    // `sc.w` writes 0 to rd, and stores rs2.
    let sc = row("sc.w");
    assert_eq!(sc.get("rd_selected"), Fr::ZERO);
    assert_eq!(sc.get("rd_write_value"), Fr::ZERO);
    assert_eq!(sc.get("ram_write_value"), f(0xDEAD_BEEF));
    // The carry row really carries.
    assert_eq!(row("amoadd past 2^32").get("add_wrap"), Fr::ONE);
    assert_eq!(row("amoadd past 2^32").get("ram_write_value"), f(0x10));
    // The `x0` row computes the old word and writes nothing.
    let x0 = row("amoadd into x0");
    assert_eq!(x0.get("rd_selected"), f(0x1234_5678));
    assert_eq!(x0.get("rd_write_value"), Fr::ZERO);
    assert_eq!(x0.get("rd_is_zero"), Fr::ONE);
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
/// more are listed, the comment says which other gate reads the same column.
#[test]
fn each_gate_is_the_one_that_refuses_its_row() {
    let a = artifact();
    let mut cases: Vec<(&str, Row, Vec<&str>)> = Vec::new();

    // The mask and its bits.
    let mut r = row("amoadd");
    r.set("decoded_mask", f(1 << kind::AMOSWAP_W));
    cases.push((
        "an amoadd whose packed mask says amoswap",
        r,
        vec!["decoded_mask_bits"],
    ));

    // Presence. Every kind reads rs1, rewrites the word and writes rd; only
    // `lr.w` skips rs2. The base is the row at word zero, so dropping the rs1
    // query leaves `addr_word` — which reads rs1's value — satisfied.
    let mut r = row("amoswap at word zero");
    r.drop_query("rs1");
    cases.push(("an amoswap making no rs1 query", r, vec!["rs1_mask_rule"]));
    let mut r = row("lr.w");
    r.query("rs2", 2, 0, 0, 0);
    cases.push(("an lr.w reading rs2", r, vec!["rs2_mask_rule"]));
    let mut r = row("amoswap at word zero");
    r.drop_query("ram");
    cases.push(("an amoswap touching no RAM word", r, vec!["ram_mask_rule"]));
    let mut r = row("amoswap at word zero");
    r.drop_query("rd");
    r.set("rd_inv", Fr::ZERO);
    cases.push(("an amoswap making no rd query", r, vec!["rd_mask_rule"]));

    // Addresses.
    for (q, rule) in [("rs1", "rs1_addr_rule"), ("rs2", "rs2_addr_rule")] {
        let mut r = row("amoswap");
        let addr = r.get(name(q, "addr")) + Fr::ONE;
        r.set(name(q, "addr"), addr);
        cases.push(("a register query at the wrong register", r, vec![rule]));
    }
    let mut r = row("amoswap");
    r.set("rd_addr", f(5))
        .set("rd_inv", f(5).inverse().expect("nonzero"));
    cases.push((
        "an amoswap writing the wrong register",
        r,
        vec!["rd_addr_rule"],
    ));
    // The RAM address is `4·word_index`, and `word_index` is `rs1`; a query
    // one word along is a query at an address the instruction did not name.
    let mut r = row("amoswap");
    r.set("ram_addr", f(ADDRESS as u64 + 4));
    cases.push((
        "an amoswap rewriting the next word along",
        r,
        vec!["ram_addr_rule"],
    ));

    // Absent operands read 0. Every live row queries rs1, so the gate's target
    // is a padding row that pretends to have read one; the word index moves
    // with it so `addr_word`, which is ungated, still holds.
    let mut r = Row::default();
    r.set("rs1_read_value", f(4))
        .set("rs1_write_value", f(4))
        .set("word_index", Fr::ONE);
    cases.push((
        "a padding row whose absent rs1 reads 4",
        r,
        vec!["rs1_value_masked"],
    ));
    // rs2 is absent on an `lr.w` row alone, and there the forgery is a live
    // one: every column the claimed value feeds moves with it.
    let old = 0x1234_5678u32;
    let mut r = row("lr.w");
    r.set("rs2_read_value", f(4))
        .set("rs2_write_value", f(4))
        .set("byte_b0", f(4))
        .set("sum", f(old as u64 + 4))
        .set("sum_hi", f((old as u64 + 4) >> 16))
        .set("cmp_gap", f(old.wrapping_sub(4) as u64))
        .set("cmp_gap_hi", f((old.wrapping_sub(4) >> 16) as u64))
        .set("lo", f(4));
    cases.push((
        "an lr.w whose absent rs2 reads 4",
        r,
        vec!["rs2_value_masked"],
    ));

    // The address. `rs1 = 4·word_index` is what makes the access aligned, and
    // a value four bytes on with the word index left alone breaks it and
    // nothing else.
    let mut r = row("amoswap");
    r.set("rs1_read_value", f(ADDRESS as u64 + 4))
        .set("rs1_write_value", f(ADDRESS as u64 + 4));
    cases.push((
        "an amoswap whose rs1 is not four times its word index",
        r,
        vec!["addr_word"],
    ));

    // The sum, carried into the word the row stores so that the value rule
    // still holds: the addition gate is the only thing between `amoadd` and an
    // arbitrary result.
    let (old, src) = (0x1234_5678u32, 0x0000_1111u32);
    let forged = old.wrapping_add(src) + 1;
    let mut r = row("amoadd");
    r.set("sum", f(forged as u64))
        .set("sum_hi", f((forged >> 16) as u64))
        .set("ram_write_value", f(forged as u64));
    cases.push(("an amoadd whose sum is one too large", r, vec!["add_rule"]));

    // The bitwise flag selects the four AND lookups and the four key bounds
    // alike, so switching it off is what would free the byte columns from the
    // table's domain. On an `amoand` row the value rule reads the AND bytes,
    // not the flag, so the flag's own rule is the lone refusal.
    let mut r = row("amoand");
    r.set("f_bitwise", Fr::ZERO);
    cases.push((
        "an amoand switching its byte table off",
        r,
        vec!["f_bitwise_rule"],
    ));

    // The byte decompositions. Neither is read by the value rule, which reads
    // the AND bytes alone, so each is its own refusal.
    let mut r = row("amoand");
    let byte = r.get("byte_a0") + Fr::ONE;
    r.set("byte_a0", byte);
    cases.push((
        "an amoand whose old bytes do not sum",
        r,
        vec!["old_bytes_rule"],
    ));
    let mut r = row("amoand");
    let byte = r.get("byte_b0") + Fr::ONE;
    r.set("byte_b0", byte);
    cases.push((
        "an amoand whose rs2 bytes do not sum",
        r,
        vec!["src_bytes_rule"],
    ));

    // The comparison. An `amoadd` row's value rule does not read `lo`, so the
    // ordering bit can be flipped there with `lo` moved to match, and the one
    // equation is what sees it.
    let mut r = row("amoadd");
    r.set("lt", Fr::ONE).set("lo", f(0x1234_5678));
    cases.push((
        "an amoadd claiming its old word is the smaller",
        r,
        vec!["cmp_order"],
    ));
    // The selection. An `amomin` storing the larger of the two: the value rule
    // still holds, because it reads `lo` and `lo` moved.
    let mut r = row("amomin");
    r.set("lo", f(9)).set("ram_write_value", f(9));
    cases.push(("an amomin storing the larger word", r, vec!["lo_rule"]));

    // The stored word. An `amoor` answering with the AND accumulator alone.
    let mut r = row("amoor");
    let and = 0xF0F0_0FF0u32 & 0x0FF0_F00F;
    r.set("ram_write_value", f(and as u64));
    cases.push(("an amoor storing the AND", r, vec!["ram_value_rule"]));
    // The returned word. Every kind but `sc.w` hands back what it found.
    let new = 0x8765_4321u32;
    let mut r = row("amoswap");
    r.set("rd_selected", f(new as u64))
        .set("rd_write_value", f(new as u64));
    cases.push((
        "an amoswap returning the word it stored",
        r,
        vec!["rd_value_rule"],
    ));

    // The pc. No kind here computes one.
    let mut r = row("amoadd");
    r.set("pc_write_value", f(0x1008));
    cases.push(("an amoadd jumping four ahead", r, vec!["next_pc_rule"]));

    // S14's control C8 on this frame, which has a RAM query as well as an
    // `rd` one. A padding row storing 42 into a stack word after the program
    // has exited: nothing in the frame ties a query's mask to the row's pc
    // mask, so the family's own mask rule refuses it — together with the
    // address rule, the word index being 0 on a row that decodes nothing, and
    // the value rule, which holds the stored word to 0 where no kind bit is
    // set.
    let mut r = Row::default();
    r.query("ram", 3, 0x3000, 0, 42);
    cases.push((
        "a padding row storing 42 into a stack word",
        r,
        vec!["ram_mask_rule", "ram_addr_rule", "ram_value_rule"],
    ));
    // And the register half of C8: a padding row zeroing x10.
    let mut r = Row::default();
    r.query("rd", 3, 10, 42, 0);
    r.set("rd_inv", f(10).inverse().expect("nonzero"));
    cases.push((
        "a padding row zeroing x10",
        r,
        vec!["rd_mask_rule", "rd_addr_rule"],
    ));
    // The same forgery dressed to satisfy the address rule: the decoded row
    // names x10, and the value written is 0, which is what the value rule asks
    // of a row with no kind bit. Only the `m_pc` factor of the mask rule is
    // left.
    let mut r = Row::default();
    r.query("rd", 3, 10, 42, 0);
    r.set("rd_inv", f(10).inverse().expect("nonzero"))
        .set("decoded_rd", f(10))
        .set("decoded_mask", Fr::ZERO);
    cases.push((
        "a padding row naming x10 and zeroing it",
        r,
        vec!["rd_mask_rule"],
    ));

    // Every gate this family adds is named by some row above. The frame's
    // eleven are S14's and covered by `crates/checker/tests/memory.rs`, and a
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
        "ram_mask_boolean",
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
    assert_eq!(owed.len(), 21);
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

/// Every booleanity gate the family adds refuses a 2: the eleven kind bits,
/// the carry, the bitwise flag and the ordering bit. Each is read as a 0 or a 1
/// by a gate or a selector above it, and a value of two there is a different
/// statement — so the membership is what matters, not the whole violated set.
#[test]
fn every_booleanity_gate_refuses_a_value_of_two() {
    let a = artifact();
    for (base, column, gate) in [
        ("amoadd", "add_wrap", "add_wrap_boolean"),
        ("amoand", "f_bitwise", "f_bitwise_boolean"),
        ("amomin", "lt", "cmp_lt_boolean"),
    ] {
        let mut r = row(base);
        r.set(column, f(2));
        let (relations, _, _) = violated(&a, &r);
        assert!(
            relations.contains(&gate.to_string()),
            "{column} = 2: {relations:?}"
        );
    }
    for bit in 0..11u32 {
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
// The table channels
// ---------------------------------------------------------------------------

/// Each table lookup is the lone refusal of a row every gate and every range
/// obligation accepts. These are the forgeries nothing else in the circuit can
/// see: a sign read from the packed table, and a byte AND read from it.
#[test]
fn each_table_lookup_is_the_one_that_refuses_its_row() {
    let a = artifact();

    // `amomin(-2^31, 1)`. Called non-negative, the old word is the larger, so
    // the row selects 1 and stores it; the comparison is consistent at
    // `lt = 0` with the gap it already had, and `U16GetSign` is what says
    // `0x8000`'s sign is 1.
    let base = honest(Instr::new(kind::AMOMIN_W), ADDRESS, NEG, 1, 0);
    assert_eq!(
        violated(&a, &base),
        (none(), none(), none()),
        "the honest amomin"
    );
    assert_eq!(base.get("ram_write_value"), f(NEG as u64));
    let mut r = base;
    r.set("old_sign", Fr::ZERO)
        .set("lt", Fr::ZERO)
        .set("lo", Fr::ONE)
        .set("ram_write_value", Fr::ONE);
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["cmp_lhs_get_sign"])),
        "an amomin calling 0x80000000 non-negative"
    );

    // `amomin(1, -2^31)`, the same forgery on the other operand.
    let base = honest(Instr::new(kind::AMOMIN_W), ADDRESS, 1, NEG, 0);
    assert_eq!(
        violated(&a, &base),
        (none(), none(), none()),
        "the second honest amomin"
    );
    assert_eq!(base.get("ram_write_value"), f(NEG as u64));
    let mut r = base;
    r.set("src_sign", Fr::ZERO)
        .set("lt", Fr::ONE)
        .set("lo", Fr::ONE)
        .set("ram_write_value", Fr::ONE);
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["cmp_rhs_get_sign"])),
        "an amomin calling rs2's 0x80000000 non-negative"
    );

    // The four AND lookups, each over its own byte of the word. One bit added
    // to a byte's AND, and the stored word moved by that byte's weight so the
    // value rule still holds: the byte columns are in range, every gate holds,
    // and the table is the only thing that knows the answer is wrong.
    let and = 0xF0F0_0FF0u32 & 0x0FF0_F00F;
    for j in 0..4u32 {
        let mut r = row("amoand");
        let column = Box::leak(format!("byte_and{j}").into_boxed_str());
        let byte = r.get(column) + Fr::ONE;
        r.set(column, byte)
            .set("ram_write_value", f(and as u64 + (1 << (8 * j))));
        assert_eq!(
            violated(&a, &r),
            (none(), none(), names(&[&format!("and_byte_{j}")])),
            "an amoand whose byte {j} claims one bit too many"
        );
    }

    // The decoder. A row reading x6 where the instruction at its pc names x5:
    // the address rule holds, because the query moved with the claim, and the
    // decoded tuple no longer matches any row of the table.
    let mut r = row("amoadd");
    r.set("decoded_rs1", f(6)).set("rs1_addr", f(6));
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["decode_row"])),
        "an amoadd reading a register its pc does not name"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 5: the sign boundary
// ---------------------------------------------------------------------------

/// Acceptance 5. `0x7fffffff` and `0x80000000` are the one pair the signed and
/// the unsigned orderings disagree about, and the four min/max kinds answer
/// four different ways:
///
/// ```text
/// amomin   signed     0x80000000     amominu  unsigned   0x7fffffff
/// amomax   signed     0x7fffffff     amomaxu  unsigned   0x80000000
/// ```
///
/// Each answer is proved as a row, and each row claiming the other kind's
/// answer is refused. The refusal is always the gap's range pair, and that is
/// the point: `lo` is free, so a forged answer fixes `lt` through `lo_rule`,
/// and `lt` fixes the gap through the one comparison equation. Swapping the
/// ordering moves the gap by `2^32` — to `2^33 − 1` where the forgery wants
/// `lt = 1`, and to `−1` where it wants `lt = 0` — and neither is a word.
#[test]
fn the_min_and_max_kinds_disagree_across_the_sign_boundary() {
    let a = artifact();
    // The four answers, each proved.
    for (what, bit, want) in [
        ("amomin", kind::AMOMIN_W, NEG),
        ("amominu", kind::AMOMINU_W, POS),
        ("amomax", kind::AMOMAX_W, POS),
        ("amomaxu", kind::AMOMAXU_W, NEG),
    ] {
        let r = honest(Instr::new(bit), ADDRESS, POS, NEG, 0);
        assert_eq!(violated(&a, &r), (none(), none(), none()), "{what}");
        assert_eq!(r.get("ram_write_value"), f(want as u64), "{what}");
        // And the trio agrees with Rust's own operators, which is where the
        // expected word came from.
        assert_eq!(rv32a(bit, POS, NEG), want, "{what}");
    }
    // The signed and the unsigned kinds really do disagree, in both
    // directions.
    assert_ne!(
        rv32a(kind::AMOMIN_W, POS, NEG),
        rv32a(kind::AMOMINU_W, POS, NEG)
    );
    assert_ne!(
        rv32a(kind::AMOMAX_W, POS, NEG),
        rv32a(kind::AMOMAXU_W, POS, NEG)
    );

    // Each row claiming the other ordering's answer. `lo` is what the value
    // rule reads, so it is solved from the claimed word; `lt` from `lo_rule`;
    // the gap from the comparison equation.
    //
    // `amomin` and `amomax` want `lt = 1` where the honest row has 0, which
    // adds `2^32` to a gap that was already `2^32 − 1`.
    let two_pow_33_minus_1 = (1u64 << 33) - 1;
    for (what, bit, lo, stored) in [
        ("amomin claiming 0x7fffffff", kind::AMOMIN_W, POS, POS),
        ("amomax claiming 0x80000000", kind::AMOMAX_W, POS, NEG),
    ] {
        let mut r = honest(Instr::new(bit), ADDRESS, POS, NEG, 0);
        r.set("lt", Fr::ONE)
            .set("lo", f(lo as u64))
            .set("ram_write_value", f(stored as u64))
            .set("cmp_gap", f(two_pow_33_minus_1))
            .set("cmp_gap_hi", f(two_pow_33_minus_1 >> 16));
        assert_eq!(
            violated(&a, &r),
            (none(), names(&["cmp_gap_hi_range"]), none()),
            "{what}"
        );
    }
    // The two unsigned kinds want `lt = 0` where the honest row has 1, which
    // takes `2^32` off a gap of `2^32 − 1` and leaves `−1`, a field element no
    // 16+16 split reaches.
    for (what, bit, lo, stored) in [
        ("amominu claiming 0x80000000", kind::AMOMINU_W, NEG, NEG),
        ("amomaxu claiming 0x7fffffff", kind::AMOMAXU_W, NEG, POS),
    ] {
        let mut r = honest(Instr::new(bit), ADDRESS, POS, NEG, 0);
        r.set("lt", Fr::ZERO)
            .set("lo", f(lo as u64))
            .set("ram_write_value", f(stored as u64))
            .set("cmp_gap", Fr::MINUS_ONE)
            .set("cmp_gap_hi", Fr::ZERO);
        assert_eq!(
            violated(&a, &r),
            (none(), names(&["cmp_gap_lo_range"]), none()),
            "{what}"
        );
    }
}

// ---------------------------------------------------------------------------
// The byte-key hole, inherited with the AND table
// ---------------------------------------------------------------------------

/// The byte keys are not free, and this is the row an unbounded one proves.
///
/// The packed generic table holds three sub-tables in one channel
/// (`docs/spec/lookup.md` §9), so a byte column outside `[0, 256)` does not
/// *miss* the table — it lands on another sub-table's row and the lookup
/// holds. `byte_a0 = 65_823` gates to the key `65_824`, which is
/// `ShiftPowers`' row for `s = 31`: `(65_824, 2^31, 1)`. So with
/// `byte_b0 = 2^31` and `byte_and0 = 1` the generic lookup holds, and so does
/// every gate — the byte sums are satisfied because `old` is `65_823` and
/// `rs2` is `2^31`, both carried in byte 0 alone.
///
/// What that row proves is `65_823 AND 0x80000000 = 1`, where the answer is 0.
/// Bit 0 of the stored word is set where no bit is set in either operand: the
/// same accumulator would have made `amoor` store `old | src` minus one and
/// `amoxor` store `old ^ src` minus two, so all three bitwise kinds are wrong
/// together. Nothing but `byte_a0`'s own range pair, read under `f_bitwise`,
/// refuses it — and here it is both halves, 65,823 being above `2^16` as well
/// as above 256.
#[test]
fn a_byte_key_outside_the_and_table_is_refused() {
    let a = artifact();
    let (old, src) = (65_823u32, 1u32 << 31);
    let honest_row = honest(Instr::new(kind::AMOAND_W), ADDRESS, old, src, 0);
    assert_eq!(
        violated(&a, &honest_row),
        (none(), none(), none()),
        "the honest amoand"
    );
    assert_eq!(old & src, 0);
    assert_eq!(honest_row.get("ram_write_value"), Fr::ZERO);

    let mut r = honest_row;
    // `old` decomposed as `byte_a0 = 65_823` rather than
    // `(0x1f, 0x01, 0x01, 0)`, and
    // `src` as `byte_b0 = 2^31` rather than `byte_b3 = 0x80`: byte 0's lookup
    // then reads `ShiftPowers`' last row, and the other three read the AND
    // table's `(1, 0, 0)`.
    r.set("byte_a0", f(65_823))
        .set("byte_a1", Fr::ZERO)
        .set("byte_a2", Fr::ZERO)
        .set("byte_b0", f(1 << 31))
        .set("byte_b3", Fr::ZERO)
        .set("byte_and0", Fr::ONE)
        .set("ram_write_value", Fr::ONE);
    assert_eq!(
        violated(&a, &r),
        (none(), names(&["byte_a0_range", "byte_a0_scaled"]), none()),
        "an amoand whose byte key reads a ShiftPowers row"
    );

    // The row the bound is protecting against really is in the table, and its
    // values really are the ones the forgery used.
    let key = generic_table::SHIFT_BASE + 31 + 1;
    assert_eq!(key, 65_824);
    assert!(
        generic_entries().contains(&[key, 1 << 31, 1]),
        "the ShiftPowers row for s = 31"
    );
}

// ---------------------------------------------------------------------------
// The word, the address and the success code
// ---------------------------------------------------------------------------

/// An AMO hands back the word it found, and a row that hands back anything
/// else is refused by the one gate that says so. This is the whole of the
/// family's return value: `rd_selected` is the frame's, and the x0 gadget
/// masks it, so the only thing tying it to memory is `rd_value_rule`.
#[test]
fn an_amo_whose_rd_is_not_the_old_word_is_refused() {
    let a = artifact();
    for (what, bit, old, src) in [
        ("amoadd", kind::AMOADD_W, 0x1234_5678u32, 0x0000_1111u32),
        ("amoswap", kind::AMOSWAP_W, 0x1234_5678, 0x8765_4321),
        ("amoand", kind::AMOAND_W, 0xF0F0_0FF0, 0x0FF0_F00F),
        ("lr.w", kind::LR_W, 0x1234_5678, 0),
    ] {
        let base = honest(Instr::new(bit), ADDRESS, old, src, 0x2222_2222);
        assert_eq!(violated(&a, &base), (none(), none(), none()), "{what}");
        assert_eq!(base.get("rd_write_value"), f(old as u64), "{what}");
        // The new word, handed back instead of the old one.
        let new = rv32a(bit, old, if bit == kind::LR_W { 0 } else { src });
        let mut r = base;
        r.set("rd_selected", f(new as u64))
            .set("rd_write_value", f(new as u64));
        let expected = match new == old {
            // `lr.w` stores what it read, so there is nothing else to hand
            // back and the row is the honest one.
            true => (none(), none(), none()),
            false => (names(&["rd_value_rule"]), none(), none()),
        };
        assert_eq!(violated(&a, &r), expected, "{what} returning its new word");

        // A forgery that is not a no-op for any kind, `lr.w` included: the old
        // word plus one. Without it the `lr.w` iteration above asserts only
        // that the honest row is honest, and a `rd_value_rule` that had lost
        // the `lr` arm from its ten-kind sum would be caught by the fixture's
        // digest alone.
        let mut r = honest(Instr::new(bit), ADDRESS, old, src, 0x2222_2222);
        r.set("rd_selected", f(old.wrapping_add(1) as u64))
            .set("rd_write_value", f(old.wrapping_add(1) as u64));
        assert_eq!(
            violated(&a, &r),
            (names(&["rd_value_rule"]), none(), none()),
            "{what} returning a word that is neither the old one nor the new"
        );
    }
}

/// A misaligned atomic has no witness at all. The A extension has no
/// immediate, so the address is `rs1` alone and `addr_word` makes it
/// `4·word_index` over the integers — `word_index` being below `2^30` by its
/// three obligations. There are two ways to try, and each is refused by one
/// thing:
///
/// - solve the equation exactly, and `word_index` is `0x2002/4`, which is not
///   an integer at all: its own 16+16 split refuses it;
/// - round the word index down, and the access lands at `0x2000` while `rs1`
///   still says `0x2002`: `addr_word` refuses that.
///
/// The emulator refuses a misaligned atomic as a fatal guest error, so no
/// honest trace has such a row; this is the statement that no dishonest one
/// does either.
#[test]
fn a_misaligned_atomic_is_unprovable() {
    let a = artifact();
    let misaligned = ADDRESS + 2;
    let base = row("amoswap");
    assert_eq!(
        violated(&a, &base),
        (none(), none(), none()),
        "the honest row"
    );

    // The exact solution over the field.
    let mut r = base.clone();
    r.set("rs1_read_value", f(misaligned as u64))
        .set("rs1_write_value", f(misaligned as u64))
        .set("ram_addr", f(misaligned as u64))
        .set(
            "word_index",
            f(misaligned as u64) * f(4).inverse().expect("nonzero"),
        )
        .set("word_index_hi", Fr::ZERO);
    assert_eq!(
        violated(&a, &r),
        (none(), names(&["word_index_lo_range"]), none()),
        "a word index that is not an integer"
    );

    // The rounded-down one: the row then touches the aligned word, and the
    // value it claims to have read the address from no longer matches.
    let mut r = base;
    r.set("rs1_read_value", f(misaligned as u64))
        .set("rs1_write_value", f(misaligned as u64));
    assert_eq!(
        violated(&a, &r),
        (names(&["addr_word"]), none(), none()),
        "a word index rounded down"
    );
}

/// `sc.w` always succeeds here, and the circuit says so in one gate.
///
/// This is a documented conformance deviation, not a soundness one: the
/// emulator's `sc.w` never fails, so the family holds every `sc.w` row to a
/// success code of 0 and a store of `rs2`. A row claiming failure — `rd = 1`
/// and the word left alone — is refused, which is what makes the deviation a
/// property of the proved statement rather than a hole in it. Real RISC-V
/// leaves the outcome to the reservation set; a guest that branches on it sees
/// success every time, on the host, under QEMU and in the proof alike.
#[test]
fn sc_w_always_succeeds() {
    let a = artifact();
    let (old, src) = (0x1234_5678u32, 0xDEAD_BEEFu32);
    let base = honest(Instr::new(kind::SC_W), ADDRESS, old, src, 0x3333_3333);
    assert_eq!(
        violated(&a, &base),
        (none(), none(), none()),
        "the honest sc.w"
    );
    // Success: rd takes 0, and the word takes rs2.
    assert_eq!(base.get("rd_selected"), Fr::ZERO);
    assert_eq!(base.get("rd_write_value"), Fr::ZERO);
    assert_eq!(base.get("ram_write_value"), f(src as u64));

    // Failure, as the ISA allows and this family does not: a nonzero code.
    let mut r = base.clone();
    r.set("rd_selected", Fr::ONE).set("rd_write_value", Fr::ONE);
    assert_eq!(
        violated(&a, &r),
        (names(&["rd_value_rule"]), none(), none()),
        "an sc.w claiming failure"
    );

    // And the other half of failure — the word left as it was — is refused by
    // the value rule, `sc.w` storing rs2 on every row.
    let mut r = base;
    r.set("ram_write_value", f(old as u64));
    assert_eq!(
        violated(&a, &r),
        (names(&["ram_value_rule"]), none(), none()),
        "an sc.w leaving the word alone"
    );
}
