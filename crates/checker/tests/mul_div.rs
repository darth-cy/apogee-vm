//! S18's `MUL_DIV` circuit (`docs/spec/mul-div.md`), row by row, in ordinary
//! CI.
//!
//! No forward pass over `2^20` rows: each row is built by hand from what the
//! instruction computes — Rust's own `u32`, `i32` and `i128` arithmetic, not
//! the circuit's — and evaluated alone through `checker::violated_relations`
//! and `violated_lookups`, its row-local scratch computed by
//! `gkr::gate_values`. The two table channels, which `violated_lookups` does
//! not read, are held here to the tables themselves. The proofs of the same
//! rows are `crates/prover/tests/alu.rs`' and `crates/checker/tests/tamper.rs`'.

use std::collections::{BTreeMap, BTreeSet};

use checker::{
    check_laws, check_lookup_discharge, check_padding, check_padding_identity, violated_lookups,
    violated_relations, WitnessRow,
};
use constants::extra_mask::mul_div as kind;
use constants::{challenge_slot, family, generic_table, lookup_channel};
use constraints::lookup::{check_discharge, ChannelSpec};
use constraints::memory::{self, check_memory};
use constraints::{family_circuit, mul_div, CircuitArtifact, GateDef, PolyAddress, VirtualKind};
use field::Fr;
use gkr::{eval_gate, gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use program::lookup_tables::generic_entries;
use test_support::{sha256, to_hex};

const VARS: u32 = 20;
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/mul_div.bin"
);
const FIXTURE_SHA256: &str = "98f9f3bdd532b9459bb6a5b155d3a0c3e93667fbb6deb34af6e13b5ea30c357a";

/// The cycle every hand-built row runs at, and the row it is evaluated at.
const CYCLE: u64 = 7;
const AT_ROW: usize = 1 << 15;
/// `2^32`, the width the family's arithmetic is over.
const WORD: i128 = 1 << 32;

fn artifact() -> CircuitArtifact {
    mul_div::artifact(VARS)
}

fn f(v: u64) -> Fr {
    Fr::from_u64(v)
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

/// One instruction of the family: every one is R-type.
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
            rs2: 6,
            rd: 7,
        }
    }
}

fn lhs_signed(bit: u32) -> bool {
    matches!(
        bit,
        kind::MUL | kind::MULH | kind::MULHSU | kind::DIV | kind::REM
    )
}

fn rhs_signed(bit: u32) -> bool {
    matches!(bit, kind::MUL | kind::MULH | kind::DIV | kind::REM)
}

fn is_div(bit: u32) -> bool {
    matches!(bit, kind::DIV | kind::DIVU | kind::REM | kind::REMU)
}

/// The RV32M answer, exactly: the emulator's arms, written again here from the
/// unprivileged spec's table.
fn rv32m(bit: u32, a: u32, b: u32) -> u32 {
    let (x, y) = (a as i32, b as i32);
    match bit {
        kind::MUL => a.wrapping_mul(b),
        kind::MULH => ((x as i64 * y as i64) >> 32) as u32,
        kind::MULHSU => ((x as i64 * b as i64) >> 32) as u32,
        kind::MULHU => ((a as u64 * b as u64) >> 32) as u32,
        kind::DIV if b == 0 => u32::MAX,
        kind::DIV => x.wrapping_div(y) as u32,
        kind::DIVU => a.checked_div(b).unwrap_or(u32::MAX),
        kind::REM if b == 0 => a,
        kind::REM => x.wrapping_rem(y) as u32,
        kind::REMU => a.checked_rem(b).unwrap_or(a),
        other => panic!("kind bit {other} is not this family's"),
    }
}

/// The sign readings a row claims: each operand's top bit, which a
/// `U16GetSign` lookup of the packed table pins, and the sign **adjustment**
/// the kind derives from it (`docs/spec/mul-div.md` §3).
#[derive(Clone, Copy, Debug)]
struct Signs {
    top1: u32,
    top2: u32,
    s1: u32,
    s2: u32,
}

impl Signs {
    /// The honest reading: each operand's own top bit, kept where the kind
    /// reads that operand signed and 0 where it does not.
    fn of(bit: u32, a: u32, b: u32) -> Signs {
        let (top1, top2) = (a >> 31, b >> 31);
        Signs {
            top1,
            top2,
            s1: lhs_signed(bit) as u32 * top1,
            s2: rhs_signed(bit) as u32 * top2,
        }
    }
}

/// The division witness a row carries: the quotient and the remainder as
/// words, each with its own sign adjustment. Neither adjustment is its word's
/// top bit — `docs/spec/mul-div.md` §5.3 — so both are columns of their own.
#[derive(Clone, Copy, Debug)]
struct Witness {
    q: u32,
    q_sign: u32,
    r: u32,
    r_sign: u32,
}

impl Witness {
    /// The witness the instruction computes, by Rust's own arithmetic: zeros
    /// on a multiply row, all ones and the dividend back on a zero divisor,
    /// and the truncating pair otherwise. `r_sign` is 1 exactly where the
    /// dividend is negative and the remainder is not zero; `q_sign` is the
    /// adjustment that puts the quotient's adjusted value into the word.
    fn of(bit: u32, a: u32, b: u32, signs: Signs) -> Witness {
        let div = is_div(bit);
        let signed_div = matches!(bit, kind::DIV | kind::REM);
        let (q, r) = match (div, b, signed_div) {
            (false, _, _) => (0, 0),
            (true, 0, _) => (u32::MAX, a),
            (true, _, true) => (
                (a as i32).wrapping_div(b as i32) as u32,
                (a as i32).wrapping_rem(b as i32) as u32,
            ),
            (true, _, false) => (a / b, a % b),
        };
        let rz = (div && r == 0) as u32;
        let r_sign = div as u32 * signs.s1 * (1 - rz);
        // On a zero divisor the identity says nothing about the quotient, and
        // the fill leaves the flag 0; everywhere else the identity determines
        // the adjusted value and the word's range determines the flag.
        let q_sign = match (div, b) {
            (false, _) | (true, 0) => 0,
            (true, _) => {
                let r_adj = r as i128 - r_sign as i128 * WORD;
                let rs1_adj = a as i128 - signs.s1 as i128 * WORD;
                let rs2_adj = b as i128 - signs.s2 as i128 * WORD;
                let q_adj = (rs1_adj - r_adj) / rs2_adj;
                assert_eq!(
                    q as i128,
                    q_adj + (q_adj < 0) as i128 * WORD,
                    "the quotient's word is not its adjusted value"
                );
                (q_adj < 0) as u32
            }
        };
        Witness {
            q,
            q_sign,
            r,
            r_sign,
        }
    }
}

/// An honest row: every column what the instruction computes, by Rust's own
/// arithmetic, with the value it writes held to [`rv32m`] — the ISA's table,
/// not this circuit's selection.
fn honest(i: Instr, a: u32, b: u32, rd_old: u32) -> Row {
    let signs = Signs::of(i.bit, a, b);
    let r = build(i, a, b, rd_old, signs, Witness::of(i.bit, a, b, signs));
    assert_eq!(
        small_int(r.get("rd_selected")),
        Some(rv32m(i.bit, a, b) as u64),
        "{} {a:#x} {b:#x} writes what RV32M defines",
        mnemonic(i.bit)
    );
    r
}

/// A division row of `i` over `a` and `b` carrying `w` rather than the witness
/// the instruction computes, with every column that witness determines
/// recomputed from it — the product and its halves, the two is-zero gadgets,
/// the magnitudes, the gap and the written value — so that only a gate judging
/// the witness itself can refuse the row.
fn forged_division(i: Instr, a: u32, b: u32, w: Witness) -> Row {
    build(i, a, b, 0x3333_3333, Signs::of(i.bit, a, b), w)
}

/// The high halfword of `v` where `v` is a word, and 0 where it is not, which
/// leaves the low half of a 16+16 pair the obligation that refuses it.
fn hi(v: i128) -> u64 {
    match (0..WORD).contains(&v) {
        true => (v >> 16) as u64,
        false => 0,
    }
}

/// A row of `i` over `a` and `b` claiming the sign readings `signs` and the
/// division witness `w`, with every column those two determine computed from
/// them: the one product with its halves and sign, the two is-zero gadgets,
/// the magnitudes and the gap, and the value written to `rd`.
fn build(i: Instr, a: u32, b: u32, rd_old: u32, signs: Signs, w: Witness) -> Row {
    let (s1, s2) = (signs.s1, signs.s2);
    let rs1_adj = a as i128 - s1 as i128 * WORD;
    let rs2_adj = b as i128 - s2 as i128 * WORD;
    let div = is_div(i.bit);
    let (q_word, r_word) = (w.q, w.r);
    let rz = (div && r_word == 0) as u32;
    let dz = (div && b == 0) as u32;
    let d1 = div as u32 * s1;
    let r_sign = w.r_sign;
    let r_adj = r_word as i128 - r_sign as i128 * WORD;
    let q_sign = w.q_sign;
    let q_adj = q_word as i128 - q_sign as i128 * WORD;
    let (mx, my) = match div {
        true => (rs2_adj, q_adj),
        false => (rs1_adj, rs2_adj),
    };
    let product = mx * my;
    let p_sign = (product < 0) as u32;
    let shifted = product + p_sign as i128 * (WORD * WORD);
    let (p_low, p_high) = (shifted as u32, (shifted >> 32) as u32);
    let abs_r = r_adj.unsigned_abs() as u64;
    let abs_d = rs2_adj.unsigned_abs() as u64;
    let gap = div as i128 * (abs_d as i128 - abs_r as i128 - 1) + dz as i128 * WORD;
    // The value the selection writes, which on an honest row is the ISA's.
    let value = match i.bit {
        kind::MUL => p_low,
        kind::MULH | kind::MULHSU | kind::MULHU => p_high,
        kind::DIV | kind::DIVU => q_word,
        kind::REM | kind::REMU => r_word,
        other => panic!("kind bit {other} is not this family's"),
    };
    let seq = i.pc + 4;

    let mut r = Row::default();
    r.set("cycle", f(CYCLE));
    r.set("pc_mask", Fr::ONE)
        .set("pc_read_ts", f(4 * (CYCLE - 1)))
        .set("pc_read_value", f(i.pc as u64))
        .set("pc_write_value", f(seq as u64));
    r.query("rs1", 1, i.rs1 as u64, a as u64, a as u64);
    r.query("rs2", 2, i.rs2 as u64, b as u64, b as u64);
    let write = if i.rd == 0 { 0 } else { value };
    r.query("rd", 3, i.rd as u64, rd_old as u64, write as u64);
    match i.rd {
        0 => r.set("rd_is_zero", Fr::ONE),
        d => r.set("rd_inv", f(d as u64).inverse().expect("nonzero")),
    };
    r.set("rd_selected", f(value as u64));

    // The decoded row, in both places it appears. This family's tuple has no
    // immediate: five claimed columns, six table columns with the pc.
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
        ("f_div", div as u64),
        ("rs1_hi", (a >> 16) as u64),
        ("rs1_top", signs.top1 as u64),
        ("rs2_hi", (b >> 16) as u64),
        ("rs2_top", signs.top2 as u64),
        ("s1", s1 as u64),
        ("s2", s2 as u64),
        ("p_low", p_low as u64),
        ("p_low_hi", (p_low >> 16) as u64),
        ("p_high", p_high as u64),
        ("p_high_hi", (p_high >> 16) as u64),
        ("p_sign", p_sign as u64),
        ("q", q_word as u64),
        ("q_hi", (q_word >> 16) as u64),
        ("q_sign", q_sign as u64),
        ("r", r_word as u64),
        ("r_hi", (r_word >> 16) as u64),
        ("r_sign", r_sign as u64),
        ("rz", rz as u64),
        ("d1", d1 as u64),
        ("dz", dz as u64),
        ("abs_r", abs_r),
        ("abs_d", abs_d),
        ("gap_hi", hi(gap)),
        ("rd_hi", (value >> 16) as u64),
    ] {
        r.set(Box::leak(column.to_string().into_boxed_str()), f(v));
    }
    // The gap is the one column a forged witness can push below 0, so it is
    // set as a signed value rather than as a word.
    r.set("gap", signed(gap));
    r.set("mx", signed(mx));
    r.set("my", signed(my));
    let unit = |on: bool, x: u32| match on {
        true => f(x as u64).inverse().unwrap_or(Fr::ZERO),
        false => Fr::ZERO,
    };
    r.set("r_inv", unit(div, r_word));
    r.set("d_inv", unit(div, b));
    r
}

fn mnemonic(bit: u32) -> &'static str {
    [
        "mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu",
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

/// The names of the **table**-channel lookups the row violates, each read
/// under its own selector.
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
                let table: Vec<Fr> = (0..mul_div::TABLE_WIDTH)
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
/// both enforcement points plus the memory and lookup construction rules.
#[test]
fn the_circuit_is_the_fixture_and_keeps_every_rule() {
    let bytes = std::fs::read(FIXTURE).expect("the mul/div fixture");
    assert_eq!(to_hex(&sha256(&bytes)), FIXTURE_SHA256);
    assert_eq!(mul_div::artifact(22).to_bytes(), bytes);
    assert_eq!(
        CircuitArtifact::from_bytes(&bytes).expect("the fixture decodes"),
        mul_div::artifact(22)
    );

    let a = artifact();
    a.validate().expect("the circuit is lawful");
    check_laws(&a).expect("the checker's validators agree");
    check_padding(&a).expect("the padding contract");
    check_padding_identity(&a).expect("the padding identity");
    check_memory(&a).expect("the memory rules");
    let channels = mul_div::channels();
    check_discharge(&a, &channels).expect("every obligation is discharged once");
    check_lookup_discharge(&a, &channels).expect("the checker's discharge agrees");
}

/// The registry holds the family at 19 variables and up and nowhere below, and
/// what it returns is this constructor's.
#[test]
fn the_registry_holds_the_family() {
    let c = family_circuit(family::MUL_DIV, VARS).expect("the family at 2^20");
    assert_eq!(c.family, family::MUL_DIV);
    assert_eq!(c.artifact, artifact());
    assert_eq!(c.channels, mul_div::channels());
    assert!(c.reads_generic_table(), "the family reads U16GetSign");
    assert_eq!(family_circuit(family::MUL_DIV, 18), None);
    let at_19 = family_circuit(family::MUL_DIV, 19).expect("the family at 2^19");
    assert_eq!(at_19.artifact, mul_div::artifact(19));
}

/// The layout is `docs/spec/mul-div.md` §2's, the gates §4's and the lookups
/// §4.7's, by name and in order: 21 memory columns, 54 witness, 9 setup, two
/// range tables, 54 enforcing gates, 27 obligations over four channels, and a
/// circuit 26 transitions deep at `2^20`.
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
            "decoded_mask",
            "kind_mul",
            "kind_mulh",
            "kind_mulhsu",
            "kind_mulhu",
            "kind_div",
            "kind_divu",
            "kind_rem",
            "kind_remu",
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
            "mult_timestamp",
            "mult_range16",
            "mult_generic",
            "mult_decoder",
        ])
    );
    // Six setup columns of decoded table, not seven: no immediate.
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
    assert_eq!(
        a.virtuals,
        vec![
            (VirtualKind::Range19, "range19".to_string()),
            (VirtualKind::Range16, "range16".to_string()),
        ]
    );
    assert_eq!(
        (a.memory.len(), a.witness.len(), a.setup.len()),
        (21, 54, 9)
    );

    // The enforcing gates: the frame's ten, then the family's forty-four,
    // which are `family_spec`'s plumbing and `arithmetic_gates`' arithmetic.
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
            "kind_mul_boolean",
            "kind_mulh_boolean",
            "kind_mulhsu_boolean",
            "kind_mulhu_boolean",
            "kind_div_boolean",
            "kind_divu_boolean",
            "kind_rem_boolean",
            "kind_remu_boolean",
            "decoded_mask_bits",
            "rs1_mask_rule",
            "rs2_mask_rule",
            "rd_mask_rule",
            "rs1_addr_rule",
            "rs2_addr_rule",
            "rd_addr_rule",
            "rs1_value_masked",
            "rs2_value_masked",
            "next_pc_rule",
            "f_div_rule",
            "f_div_boolean",
            "s1_rule",
            "s2_rule",
            "rs1_top_boolean",
            "rs2_top_boolean",
            "s1_boolean",
            "s2_boolean",
            "p_sign_boolean",
            "q_sign_boolean",
            "r_sign_boolean",
            "mx_rule",
            "my_rule",
            "product_rule",
            "division_rule",
            "rz_inverse",
            "rz_at_nonzero",
            "dz_inverse",
            "dz_at_nonzero",
            "d1_rule",
            "r_sign_rule",
            "abs_r_rule",
            "abs_d_rule",
            "gap_rule",
            "zero_divisor_quotient",
            "rd_value_rule",
        ])
    );
    assert_eq!(enforcing.len(), 54);
    // The width seam carries the arithmetic half and nothing else: the tail of
    // the enforcing list, in order, is exactly what it returns.
    let arithmetic: Vec<String> = mul_div::arithmetic_gates(mul_div::WORD_BITS)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    assert_eq!(enforcing[54 - arithmetic.len()..], arithmetic[..]);

    // The obligations: eight timestamp gaps under their own queries' masks,
    // then sixteen halfword pairs, two sign lookups and one decoder row, each
    // under the row's pc mask.
    let lookups: Vec<(&str, u32, PolyAddress)> = a
        .lookups
        .iter()
        .map(|l| (l.name.as_str(), l.channel, l.selector))
        .collect();
    let (ts, range) = (lookup_channel::TIMESTAMP, lookup_channel::RANGE16);
    let (generic, decoder) = (lookup_channel::GENERIC, lookup_channel::DECODER);
    let m = |slot: u32| PolyAddress::Memory(1 + 5 * slot);
    let m_pc = m(0);
    assert_eq!(
        lookups,
        vec![
            ("gap_hi_pc", ts, m(0)),
            ("gap_lo_pc", ts, m(0)),
            ("gap_hi_rs1", ts, m(1)),
            ("gap_lo_rs1", ts, m(1)),
            ("gap_hi_rs2", ts, m(2)),
            ("gap_lo_rs2", ts, m(2)),
            ("gap_hi_rd", ts, m(3)),
            ("gap_lo_rd", ts, m(3)),
            ("rs1_hi_range", range, m_pc),
            ("rs1_lo_range", range, m_pc),
            ("rs2_hi_range", range, m_pc),
            ("rs2_lo_range", range, m_pc),
            ("p_low_hi_range", range, m_pc),
            ("p_low_lo_range", range, m_pc),
            ("p_high_hi_range", range, m_pc),
            ("p_high_lo_range", range, m_pc),
            ("q_hi_range", range, m_pc),
            ("q_lo_range", range, m_pc),
            ("r_hi_range", range, m_pc),
            ("r_lo_range", range, m_pc),
            ("gap_hi_range", range, m_pc),
            ("gap_lo_range", range, m_pc),
            ("rd_hi_range", range, m_pc),
            ("rd_lo_range", range, m_pc),
            ("rs1_get_sign", generic, m_pc),
            ("rs2_get_sign", generic, m_pc),
            ("decode_row", decoder, m_pc),
        ]
    );
    for (channel, want) in [(ts, 8), (range, 16), (generic, 2), (decoder, 1)] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(got, want, "channel {channel}");
    }

    // The channels in output order, the generic table at `S[6..9]` and the
    // decoder's at `S[0..6]`.
    let mult = |i: u32| PolyAddress::Witness(50 + i);
    assert_eq!(
        mul_div::channels(),
        vec![
            ChannelSpec {
                channel: ts,
                table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
                multiplicity: mult(0),
            },
            ChannelSpec {
                channel: range,
                table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
                multiplicity: mult(1),
            },
            ChannelSpec {
                channel: generic,
                table: (6..9).map(PolyAddress::Setup).collect(),
                multiplicity: mult(2),
            },
            ChannelSpec {
                channel: decoder,
                table: (0..6).map(PolyAddress::Setup).collect(),
                multiplicity: mult(3),
            },
        ]
    );
    assert_eq!(
        mul_div::MULTIPLICITIES,
        [mult(0), mult(1), mult(2), mult(3)]
    );
    assert_eq!(
        mul_div::GENERIC_TABLE.to_vec(),
        (6..9).map(PolyAddress::Setup).collect::<Vec<_>>()
    );

    // Four product-tree leaves a side, then one fraction tree per channel:
    // 8 + 32 + 64 + 8 + 4, the range16 tree the widest with 17 leaves.
    assert_eq!(a.layers[0].width, 116);
    assert_eq!(a.outputs.len(), 2 + 2 * 4);
    // The leaves, five row-wise levels and one halving level per variable.
    assert_eq!(a.depth(), 1 + 5 + VARS as usize);
}

/// The decoded tuple this family reads has **no immediate**: six columns, not
/// seven, and the circuit's claimed row is five.
#[test]
fn the_decoded_tuple_has_no_immediate() {
    use program::RowField::*;
    assert_eq!(
        program::lookup_tuple(family::MUL_DIV),
        &[Pc, NextPc, Rs1, Rs2, Rd, ExtraMask]
    );
    assert_eq!(mul_div::TABLE_WIDTH, 6);
    assert_eq!(mul_div::DECODED.len(), mul_div::TABLE_WIDTH - 1);
}

/// The legal masks are the eight instructions, and nothing else.
#[test]
fn the_legal_masks_are_the_instruction_list() {
    let mut seen: Vec<u32> = Vec::new();
    for (bit, instr) in instruction_corpus() {
        let (fam, k) = program::row_kind(&instr);
        assert_eq!(fam, family::MUL_DIV, "{instr:?}");
        assert_eq!(k, bit, "{instr:?}");
        if !seen.contains(&(1 << k)) {
            seen.push(1 << k);
        }
    }
    seen.sort_unstable();
    let mut legal = mul_div::LEGAL_MASKS.to_vec();
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
            (kind::MUL, Mul { rd, rs1: 5, rs2: 6 }),
            (kind::MULH, Mulh { rd, rs1: 5, rs2: 6 }),
            (kind::MULHSU, Mulhsu { rd, rs1: 5, rs2: 6 }),
            (kind::MULHU, Mulhu { rd, rs1: 5, rs2: 6 }),
            (kind::DIV, Div { rd, rs1: 5, rs2: 6 }),
            (kind::DIVU, Divu { rd, rs1: 5, rs2: 6 }),
            (kind::REM, Rem { rd, rs1: 5, rs2: 6 }),
            (kind::REMU, Remu { rd, rs1: 5, rs2: 6 }),
        ]);
    }
    out
}

// ---------------------------------------------------------------------------
// Honest rows
// ---------------------------------------------------------------------------

/// The four sign quadrants, as words.
const QUADRANTS: [(u32, u32); 4] = [
    (7, 3),
    (0xFFFF_FFF9, 3),
    (7, 0xFFFF_FFFD),
    (0xFFFF_FFF9, 0xFFFF_FFFD),
];

/// The catalogue of honest rows: every kind over every sign quadrant, the
/// multiply and division edge cases S18's acceptance 3 and 4 name, `rd = x0`,
/// and the all-zero padding row.
fn honest_rows() -> Vec<(String, Row)> {
    let mut out: Vec<(String, Row)> = Vec::new();

    for bit in 0..8u32 {
        for (a, b) in QUADRANTS {
            out.push((
                format!("{} {a:#x} {b:#x}", mnemonic(bit)),
                honest(Instr::new(bit), a, b, 0x1111_1111),
            ));
        }
    }

    // Acceptance 3's named cases, and acceptance 4's.
    for (bit, a, b) in [
        (kind::MUL, 0x8000_0000, 0x8000_0000),
        (kind::MULH, 0x8000_0000, 0x8000_0000),
        (kind::MULHSU, 0x8000_0000, 0xFFFF_FFFF),
        (kind::MULHU, 0x8000_0000, 0xFFFF_FFFF),
        (kind::MULHU, 0xFFFF_FFFF, 0xFFFF_FFFF),
        (kind::MULHSU, 0xFFFF_FFFF, 0x0000_0001),
        (kind::MULH, 0x8000_0000, 0x7FFF_FFFF),
        (kind::MUL, 0, 0),
        (kind::MULHU, 0, 0xFFFF_FFFF),
        // The floored-quotient rows: -7/2 is -3 remainder -1, never -4 and 1.
        (kind::DIV, 0xFFFF_FFF9, 2),
        (kind::REM, 0xFFFF_FFF9, 2),
        (kind::DIV, 0xFFFF_FFFA, 2),
        (kind::REM, 0xFFFF_FFFA, 2),
        // Division by zero, all four.
        (kind::DIV, 0xDEAD_BEEF, 0),
        (kind::DIVU, 0xDEAD_BEEF, 0),
        (kind::REM, 0xDEAD_BEEF, 0),
        (kind::REMU, 0xDEAD_BEEF, 0),
        (kind::DIV, 0x8000_0000, 0),
        (kind::REM, 0, 0),
        // The one signed overflow.
        (kind::DIV, 0x8000_0000, 0xFFFF_FFFF),
        (kind::REM, 0x8000_0000, 0xFFFF_FFFF),
        // Unsigned division with a remainder whose top bit is set.
        (kind::DIVU, 0xFFFF_FFFF, 0xFFFF_FFFE),
        (kind::REMU, 0xFFFF_FFFF, 0xFFFF_FFFE),
        (kind::DIVU, 3, 7),
        (kind::REMU, 3, 7),
        (kind::DIVU, 0xFFFF_FFFF, 1),
        (kind::DIV, 0x8000_0000, 1),
        (kind::REM, 0x8000_0000, 1),
    ] {
        out.push((
            format!("{} {a:#x} {b:#x}", mnemonic(bit)),
            honest(Instr::new(bit), a, b, 0x2222_2222),
        ));
    }

    // rd = x0, computing a value it discards, in each half.
    for bit in [kind::MUL, kind::DIV] {
        let mut i = Instr::new(bit);
        i.rd = 0;
        out.push((
            format!("{} into x0", mnemonic(bit)),
            honest(i, 0xFFFF_FFF9, 3, 0),
        ));
    }
    // An x0 operand, which reads 0 — and makes the divisor zero.
    let mut i = Instr::new(kind::DIVU);
    i.rs2 = 0;
    out.push(("divu by x0".into(), honest(i, 42, 0, 0)));

    out.push(("padding".into(), Row::default()));
    out
}

/// Every row kind the family proves satisfies every gate, every range
/// obligation and both table channels — and the value it writes is the one
/// RV32M defines.
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
        .find(|(name, _)| name == what)
        .unwrap_or_else(|| panic!("no honest row `{what}`"))
        .1
}

// ---------------------------------------------------------------------------
// Each gate refuses its row
// ---------------------------------------------------------------------------

/// Each tamper beside the gates it breaks, exactly: an edit to an honest row
/// that the gates listed, and only they, refuse. Most are one gate — that gate
/// is load-bearing on the row shape it exists for — and where a cell is read by
/// more than one formula the whole set is written down, because a single-cell
/// edit is what a tampering prover makes.
#[test]
fn each_gate_is_the_one_that_refuses_its_row() {
    let a = artifact();
    let mut cases: Vec<(&str, Row, Vec<&str>)> = Vec::new();

    // The mask and its bits.
    let mut r = row("mul 0x7 0x3");
    r.set("decoded_mask", f(1 << kind::MULH));
    cases.push((
        "a mul whose packed mask says mulh",
        r,
        vec!["decoded_mask_bits"],
    ));

    // The division half. `f_div` is read by six formulas, so a multiply row
    // that claims it is refused by all of them at once.
    let mut r = row("mul 0x7 0x3");
    r.set("f_div", Fr::ONE);
    cases.push((
        "a multiply row claiming the division half",
        r,
        vec![
            "f_div_rule",
            "mx_rule",
            "division_rule",
            "rz_inverse",
            "dz_inverse",
            "gap_rule",
        ],
    ));

    // The sign adjustments. Each forgery is a whole row computed from the
    // claimed adjustment, so every column that reads it agrees and only the
    // rule tying it to the kind's signedness refuses it.
    let unsigned_lhs = Instr::new(kind::MULHU);
    cases.push((
        "a mulhu reading its rs1 signed",
        build(
            unsigned_lhs,
            0xFFFF_FFF9,
            3,
            0,
            Signs {
                top1: 1,
                top2: 0,
                s1: 1,
                s2: 0,
            },
            Witness {
                q: 0,
                q_sign: 0,
                r: 0,
                r_sign: 0,
            },
        ),
        vec!["s1_rule"],
    ));
    let asymmetric = Instr::new(kind::MULHSU);
    cases.push((
        "a mulhsu reading its rs2 signed",
        build(
            asymmetric,
            7,
            0xFFFF_FFFD,
            0,
            Signs {
                top1: 0,
                top2: 1,
                s1: 0,
                s2: 1,
            },
            Witness {
                q: 0,
                q_sign: 0,
                r: 0,
                r_sign: 0,
            },
        ),
        vec!["s2_rule"],
    ));

    // Presence: every one of the eight is R-type, so a query present on a row
    // whose pc mask is 0 is present on no row of the family at all.
    let mut r = Row::default();
    r.query("rs1", 1, 0, 0, 0);
    cases.push(("a padding row reading rs1", r, vec!["rs1_mask_rule"]));
    let mut r = Row::default();
    r.query("rs2", 2, 0, 0, 0);
    cases.push(("a padding row reading rs2", r, vec!["rs2_mask_rule"]));
    let mut r = Row::default();
    r.query("rd", 3, 0, 0, 0);
    r.set("rd_is_zero", Fr::ONE);
    cases.push(("a padding row writing x0", r, vec!["rd_mask_rule"]));
    // S14's control C8 on this frame: a padding row rewriting x10 after the
    // program has exited. Its pc mask is 0, so the mask rule's `m_pc` factor
    // is what refuses the write, and the decoded address and value with it.
    let mut r = Row::default();
    r.query("rd", 3, 10, 42, 43);
    r.set("rd_inv", f(10).inverse().expect("nonzero"))
        .set("rd_selected", f(43));
    cases.push((
        "a padding row rewriting x10",
        r,
        vec!["rd_mask_rule", "rd_addr_rule", "rd_value_rule"],
    ));

    // Addresses.
    for (q, rule) in [("rs1", "rs1_addr_rule"), ("rs2", "rs2_addr_rule")] {
        let mut r = row("mul 0x7 0x3");
        let addr = r.get(name(q, "addr")) + Fr::ONE;
        r.set(name(q, "addr"), addr);
        cases.push(("an operand read from the wrong register", r, vec![rule]));
    }
    let mut r = row("mul 0x7 0x3");
    r.set("rd_addr", f(5))
        .set("rd_inv", f(5).inverse().expect("nonzero"));
    cases.push((
        "a product written to the wrong register",
        r,
        vec!["rd_addr_rule"],
    ));

    // Absent operands. Both are present on every live row, so the forgery is a
    // padding row whose unmasked operand carries a value; the columns that
    // read it are set to match, which leaves the masking rule alone.
    let mut r = Row::default();
    r.set("rs1_read_value", f(5)).set("rs1_write_value", f(5));
    cases.push((
        "a padding row whose absent rs1 reads 5",
        r,
        vec!["rs1_value_masked"],
    ));
    let mut r = Row::default();
    r.set("rs2_read_value", f(5))
        .set("rs2_write_value", f(5))
        .set("abs_d", f(5));
    cases.push((
        "a padding row whose absent rs2 reads 5",
        r,
        vec!["rs2_value_masked"],
    ));

    // The pc. This family computes none: `next_pc` is the decoded row's.
    let mut r = row("mul 0x7 0x3");
    r.set("pc_write_value", f(0x1008));
    cases.push(("a mul jumping four ahead", r, vec!["next_pc_rule"]));

    // The one product.
    let mut r = row("mul 0x7 0x3");
    r.set("mx", f(8));
    cases.push((
        "a multiply whose first multiplicand is not its rs1",
        r,
        vec!["mx_rule", "product_rule"],
    ));
    let mut r = row("mul 0x7 0x3");
    r.set("my", f(4));
    cases.push((
        "a multiply whose second multiplicand is not its rs2",
        r,
        vec!["my_rule", "product_rule"],
    ));
    let mut r = row("mul 0x7 0x3");
    r.set("p_high", Fr::ONE);
    cases.push((
        "a product with 2^32 added to its high half",
        r,
        vec!["product_rule"],
    ));

    // The division identity: a quotient of 2 with no remainder is not 7 / 3.
    cases.push((
        "a division claiming no remainder where there is one",
        forged_division(
            Instr::new(kind::DIV),
            7,
            3,
            Witness {
                q: 2,
                q_sign: 0,
                r: 0,
                r_sign: 0,
            },
        ),
        vec!["division_rule"],
    ));

    // The two is-zero gadgets.
    let mut r = row("divu 0xffffffff 0x1");
    r.set("rz", Fr::ZERO);
    cases.push((
        "an exact division claiming a nonzero remainder",
        r,
        vec!["rz_inverse"],
    ));
    let mut r = row("divu 0x7 0x3");
    r.set("rz", Fr::ONE).set("r_inv", Fr::ZERO);
    cases.push((
        "an inexact division claiming a zero remainder",
        r,
        vec!["rz_at_nonzero"],
    ));
    let mut r = row("divu 0xdeadbeef 0x0");
    r.set("dz", Fr::ZERO);
    cases.push((
        "a zero divisor claimed nonzero",
        r,
        vec!["dz_inverse", "gap_rule"],
    ));
    // A nonzero divisor claimed zero is what would buy a free gap, and three
    // gates refuse it: the gadget, the gap it was for, and the pin on `q`.
    let mut r = row("divu 0x7 0x3");
    r.set("dz", Fr::ONE).set("d_inv", Fr::ZERO);
    cases.push((
        "a nonzero divisor claimed zero",
        r,
        vec!["dz_at_nonzero", "gap_rule", "zero_divisor_quotient"],
    ));

    // The remainder's sign, and the negative-dividend flag it is built on.
    let mut r = row("div 0x80000000 0xffffffff");
    r.set("d1", Fr::ZERO);
    cases.push((
        "a negative dividend whose division row does not say so",
        r,
        vec!["d1_rule"],
    ));
    cases.push((
        "DIV(-7, 2) with the floored quotient and remainder",
        floored_minus_seven_over_two(),
        vec!["r_sign_rule"],
    ));

    // The magnitudes and the gap.
    let mut r = row("divu 0x7 0x3");
    r.set("abs_r", f(2));
    cases.push((
        "a remainder whose magnitude is one too large",
        r,
        vec!["abs_r_rule", "gap_rule"],
    ));
    let mut r = row("divu 0x7 0x3");
    r.set("abs_d", f(4));
    cases.push((
        "a divisor whose magnitude is one too large",
        r,
        vec!["abs_d_rule", "gap_rule"],
    ));
    let mut r = row("divu 0x7 0x3");
    r.set("gap", f(2));
    cases.push((
        "a gap one wider than the magnitudes leave",
        r,
        vec!["gap_rule"],
    ));

    // The div-by-zero pin.
    cases.push((
        "a zero divisor whose quotient is 0 rather than all ones",
        forged_division(
            Instr::new(kind::DIVU),
            0xDEAD_BEEF,
            0,
            Witness {
                q: 0,
                q_sign: 0,
                r: 0xDEAD_BEEF,
                r_sign: 0,
            },
        ),
        vec!["zero_divisor_quotient"],
    ));

    // The selection.
    let mut r = row("mul 0x7 0x3");
    r.set("rd_selected", f(22)).set("rd_write_value", f(22));
    cases.push(("a mul writing one too many", r, vec!["rd_value_rule"]));
    let mut r = row("mul 0x7 0x3");
    r.drop_query("rd");
    r.set("rd_inv", Fr::ZERO);
    cases.push((
        "a mul whose write is masked off",
        r,
        vec!["rd_write_masked", "rd_mask_rule"],
    ));

    // Every gate the family adds beside its frame, booleanity apart — which
    // `every_booleanity_gate_refuses_a_value_of_two` owns — is named by some
    // row above: a gate added with no forgery beside it fails here.
    let named: BTreeSet<&str> = cases
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
    assert_eq!(owed.len(), 28);
    for gate in owed {
        assert!(named.contains(gate), "no row above is refused by `{gate}`");
    }

    let order: Vec<&str> = a.relations.iter().map(|r| r.name.as_str()).collect();
    for (what, r, want) in cases {
        let (relations, _, _) = violated(&a, &r);
        let mut want: Vec<String> = names(&want);
        want.sort_by_key(|n| order.iter().position(|o| o == n));
        assert_eq!(relations, want, "{what}");
    }
}

/// `DIV(−7, 2)` carrying the **floored** answer, `q = −4` and `rem = 1`,
/// rather than the truncated `q = −3` and `rem = −1`: the row a bare division
/// identity cannot tell from the honest one (`docs/spec/mul-div.md` §4.4).
fn floored_minus_seven_over_two() -> Row {
    forged_division(
        Instr::new(kind::DIV),
        (-7i32) as u32,
        2,
        Witness {
            q: (-4i32) as u32,
            q_sign: 1,
            r: 1,
            r_sign: 0,
        },
    )
}

/// Every booleanity gate the family adds refuses a 2: the eight kind bits,
/// `f_div`, both operands' top bits, both sign adjustments, and the product's,
/// quotient's and remainder's sign flags. A value of 2 in any of them is what
/// would let a selection or a sign adjustment weigh a column by something
/// other than 0 or 1.
#[test]
fn every_booleanity_gate_refuses_a_value_of_two() {
    let a = artifact();
    for (base, column, gate) in [
        ("mul 0x7 0x3", "f_div", "f_div_boolean"),
        ("mul 0x7 0x3", "rs1_top", "rs1_top_boolean"),
        ("mul 0x7 0x3", "rs2_top", "rs2_top_boolean"),
        ("mul 0x7 0x3", "s1", "s1_boolean"),
        ("mul 0x7 0x3", "s2", "s2_boolean"),
        ("mul 0x7 0x3", "p_sign", "p_sign_boolean"),
        ("divu 0x7 0x3", "q_sign", "q_sign_boolean"),
        ("divu 0x7 0x3", "r_sign", "r_sign_boolean"),
    ] {
        let mut r = row(base);
        r.set(column, f(2));
        let (relations, _, _) = violated(&a, &r);
        assert!(
            relations.contains(&gate.to_string()),
            "{column} = 2: {relations:?}"
        );
    }
    for bit in 0..8u32 {
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
// Acceptance 5: the division encoding, exhaustively at a reduced width
// ---------------------------------------------------------------------------

/// The reduced word the exhaustive check runs at. Four bits: 256 operand
/// pairs, and a free witness of 8,192 assignments per pair and kind.
const REDUCED_BITS: u32 = 4;
const REDUCED: i128 = 1 << REDUCED_BITS;

/// The division answer RV32M defines at a `bits`-wide word, written here from
/// `docs/spec/mul-div.md` §5.2 and §5.3 and not from the circuit: the quotient
/// truncates toward zero and the remainder takes the dividend's sign; a zero
/// divisor gives all ones with the dividend as the remainder; and the one
/// signed overflow, `−2^(bits−1) ÷ −1`, gives `−2^(bits−1)` back with no
/// remainder. Both halves are returned as words of the reduced field.
fn truncated(signed_op: bool, a: i128, b: i128, bits: u32) -> (i128, i128) {
    let word = 1i128 << bits;
    let as_signed = |v: i128| match v >> (bits - 1) {
        1 => v - word,
        _ => v,
    };
    if b == 0 {
        return (word - 1, a);
    }
    if !signed_op {
        return (a / b, a % b);
    }
    let (x, y) = (as_signed(a), as_signed(b));
    if x == -(word / 2) && y == -1 {
        return (a, 0);
    }
    // Rust's `/` and `%` on integers truncate toward zero, which is the ISA's
    // rule; the remainder takes the dividend's sign.
    ((x / y).rem_euclid(word), (x % y).rem_euclid(word))
}

/// **Acceptance 5.** At a four-bit word, for every `(dividend, divisor)` pair
/// and each of `DIV`, `DIVU`, `REM` and `REMU`, the constraint set determines
/// the division witness up to exactly one freedom, and what survives is the
/// ISA's answer.
///
/// The method. The gates evaluated are
/// `constraints::mul_div::arithmetic_gates(4)` themselves, through
/// `gkr::eval_gate` — the width seam exists so that this check reads the
/// circuit rather than a transcription of it. Of the family's columns, seven
/// are enumerated freely: `q`, `r`, `q_sign`, `rz`, `dz`, `r_sign` and
/// `p_sign`. Every other column the gates read is *computed from those* by the
/// gate that defines it — `mx`, `my`, the product's two halves, `d1`, the two
/// magnitudes, the gap, the two gadget inverses and the selected `rd` value —
/// so no assignment a gate admits is missed: an inverse appears only as
/// `r·r_inv`, so where `r` is nonzero exactly one value satisfies the gadget
/// and where it is zero none is distinguishable. The two operands' top bits
/// are **not** enumerated: they are pinned by a `U16GetSign` lookup, a fact of
/// the packed table and not of any gate, so they are supplied from the table's
/// own semantics — the operands' true top bits at width four — exactly as the
/// lookup forces at width 32. A candidate survives when every gate is zero on
/// it and every range-checked column is below `2^4`.
///
/// What is asserted. For every pair and kind there is **exactly one**
/// satisfying `(q, r)`, and it is the width-four RV32M answer: truncated
/// toward zero, all ones with the dividend back on a zero divisor, and
/// `−2^3 ÷ −1` giving `−2^3` with no remainder. Where the divisor is nonzero
/// the whole witness is unique — one `q_sign` and one of everything else.
/// Where the divisor is zero **both** values of `q_sign` satisfy and nothing
/// else varies: the identity's product is zero either way and `rd` reads the
/// word `q`, never `q_adj`, so that freedom is harmless and is why `q_sign`
/// may not be tied to a sign lookup (`docs/spec/mul-div.md` §5.3).
#[test]
fn the_division_encoding_admits_exactly_one_witness_at_a_reduced_width() {
    let gates = mul_div::arithmetic_gates(REDUCED_BITS);
    let v_rs1 = memory::frame(1, memory::FIELD_READ_VALUE);
    let v_rs2 = memory::frame(2, memory::FIELD_READ_VALUE);
    // The cells the seam's gates read, in this check's own order.
    let mut cells = vec![v_rs1, v_rs2, memory::rd_selected(4)];
    cells.extend(mul_div::KINDS);
    cells.extend([
        mul_div::F_DIV,
        mul_div::RS1_TOP,
        mul_div::RS2_TOP,
        mul_div::S1,
        mul_div::S2,
        mul_div::MX,
        mul_div::MY,
        mul_div::P_LOW,
        mul_div::P_HIGH,
        mul_div::P_SIGN,
        mul_div::Q,
        mul_div::Q_SIGN,
        mul_div::R,
        mul_div::R_SIGN,
        mul_div::R_INV,
        mul_div::RZ,
        mul_div::D1,
        mul_div::D_INV,
        mul_div::DZ,
        mul_div::ABS_R,
        mul_div::ABS_D,
        mul_div::GAP,
    ]);
    let at = |address: PolyAddress| {
        cells
            .iter()
            .position(|c| *c == address)
            .unwrap_or_else(|| panic!("this check does not set {address}"))
    };
    // Every operand of every gate is one of them: a gate that grew a column
    // fails here rather than going unenumerated.
    let reads: Vec<Vec<usize>> = gates
        .iter()
        .map(|(name, g)| {
            g.operands()
                .iter()
                .map(|op| {
                    cells.iter().position(|c| c == op).unwrap_or_else(|| {
                        panic!("gate `{name}` reads {op}, which this check does not set")
                    })
                })
                .collect()
        })
        .collect();
    let (i_rs1, i_rs2, i_sel) = (at(v_rs1), at(v_rs2), at(memory::rd_selected(4)));
    let i_kind: Vec<usize> = mul_div::KINDS.iter().map(|k| at(*k)).collect();
    let (i_f_div, i_top1, i_top2) = (
        at(mul_div::F_DIV),
        at(mul_div::RS1_TOP),
        at(mul_div::RS2_TOP),
    );
    let (i_s1, i_s2) = (at(mul_div::S1), at(mul_div::S2));
    let (i_mx, i_my) = (at(mul_div::MX), at(mul_div::MY));
    let (i_p_low, i_p_high, i_p_sign) =
        (at(mul_div::P_LOW), at(mul_div::P_HIGH), at(mul_div::P_SIGN));
    let (i_q, i_q_sign) = (at(mul_div::Q), at(mul_div::Q_SIGN));
    let (i_r, i_r_sign) = (at(mul_div::R), at(mul_div::R_SIGN));
    let (i_r_inv, i_rz) = (at(mul_div::R_INV), at(mul_div::RZ));
    let (i_d1, i_d_inv, i_dz) = (at(mul_div::D1), at(mul_div::D_INV), at(mul_div::DZ));
    let (i_abs_r, i_abs_d, i_gap) = (at(mul_div::ABS_R), at(mul_div::ABS_D), at(mul_div::GAP));

    let empty = ExternalChallenges::new();
    let square = REDUCED * REDUCED;
    // The gadgets' inverses, one per value of the reduced word; 0 has none,
    // and the gadget does not read one there.
    let inverse: Vec<Fr> = (0..REDUCED)
        .map(|v| f(v as u64).inverse().unwrap_or(Fr::ZERO))
        .collect();
    let mut values = vec![Fr::ZERO; cells.len()];
    let mut buf: Vec<Fr> = Vec::new();
    let mut quadrants: BTreeSet<(bool, i128, i128)> = BTreeSet::new();

    for bit in [kind::DIV, kind::DIVU, kind::REM, kind::REMU] {
        let signed_op = matches!(bit, kind::DIV | kind::REM);
        let takes_quotient = matches!(bit, kind::DIV | kind::DIVU);
        for (k, index) in i_kind.iter().enumerate() {
            values[*index] = f((k as u32 == bit) as u64);
        }
        values[i_f_div] = Fr::ONE;
        for dividend in 0..REDUCED {
            for divisor in 0..REDUCED {
                // Determined by the kind and the operands alone: the top bits
                // the sign lookups pin, the adjustments the kind derives from
                // them, the negative-dividend flag, the divisor's magnitude
                // and the product's first multiplicand.
                let top1 = dividend >> (REDUCED_BITS - 1);
                let top2 = divisor >> (REDUCED_BITS - 1);
                let s1 = lhs_signed(bit) as i128 * top1;
                let s2 = rhs_signed(bit) as i128 * top2;
                let rs2_adj = divisor - s2 * REDUCED;
                let abs_d = rs2_adj.unsigned_abs() as i128;
                let mx = rs2_adj;
                for (index, v) in [
                    (i_rs1, dividend),
                    (i_rs2, divisor),
                    (i_top1, top1),
                    (i_top2, top2),
                    (i_s1, s1),
                    (i_s2, s2),
                    (i_d1, s1),
                    (i_abs_d, abs_d),
                    (i_mx, mx),
                ] {
                    values[index] = signed(v);
                }
                quadrants.insert((signed_op, top1, top2));

                let mut solutions: Vec<[i128; 7]> = Vec::new();
                for q in 0..REDUCED {
                    for q_sign in 0..2 {
                        let my = q - q_sign * REDUCED;
                        let product = mx * my;
                        values[i_q] = signed(q);
                        values[i_q_sign] = signed(q_sign);
                        values[i_my] = signed(my);
                        for p_sign in 0..2 {
                            // The one decomposition the product identity
                            // admits; out of the word, no in-range pair
                            // exists, and the range conditions refuse it.
                            let shifted = product + p_sign * square;
                            let (p_low, p_high) = match (0..square).contains(&shifted) {
                                true => (shifted % REDUCED, shifted / REDUCED),
                                false => (shifted, 0),
                            };
                            values[i_p_sign] = signed(p_sign);
                            values[i_p_low] = signed(p_low);
                            values[i_p_high] = signed(p_high);
                            for r in 0..REDUCED {
                                values[i_r] = signed(r);
                                values[i_sel] = signed(match takes_quotient {
                                    true => q,
                                    false => r,
                                });
                                for rz in 0..2 {
                                    // The gadget reads the inverse only as
                                    // `r·r_inv`, so this is the one value that
                                    // can satisfy it at this `rz` — and where
                                    // `r` is 0 no value is distinguishable.
                                    values[i_r_inv] =
                                        (Fr::ONE - f(rz as u64)) * inverse[r as usize];
                                    values[i_rz] = f(rz as u64);
                                    for dz in 0..2 {
                                        values[i_d_inv] =
                                            (Fr::ONE - f(dz as u64)) * inverse[divisor as usize];
                                        values[i_dz] = f(dz as u64);
                                        for r_sign in 0..2 {
                                            let r_adj = r - r_sign * REDUCED;
                                            let abs_r = r_adj.unsigned_abs() as i128;
                                            let gap = abs_d - abs_r - 1 + dz * REDUCED;
                                            values[i_r_sign] = signed(r_sign);
                                            values[i_abs_r] = signed(abs_r);
                                            values[i_gap] = signed(gap);
                                            // Every gate the seam returns,
                                            // evaluated on the candidate, and
                                            // the range conditions beside
                                            // them: a witness survives only
                                            // when all of both hold.
                                            let mut refused = 0;
                                            for (operands, (_, gate)) in reads.iter().zip(&gates) {
                                                buf.clear();
                                                buf.extend(operands.iter().map(|i| values[*i]));
                                                refused += (eval_gate(gate, &buf, &empty)
                                                    != Fr::ZERO)
                                                    as usize;
                                            }
                                            let in_range = [p_low, p_high, q, r, gap]
                                                .iter()
                                                .all(|v| (0..REDUCED).contains(v));
                                            if refused == 0 && in_range {
                                                solutions
                                                    .push([q, r, q_sign, rz, dz, r_sign, p_sign]);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                let what = format!("{} {dividend} / {divisor}", mnemonic(bit));
                let want = truncated(signed_op, dividend, divisor, REDUCED_BITS);
                let pairs: BTreeSet<(i128, i128)> =
                    solutions.iter().map(|s| (s[0], s[1])).collect();
                assert_eq!(
                    pairs,
                    BTreeSet::from([want]),
                    "{what}: the quotient and remainder the gates admit"
                );
                // The rest of the witness, `q_sign` apart.
                let rest: BTreeSet<[i128; 6]> = solutions
                    .iter()
                    .map(|s| [s[0], s[1], s[3], s[4], s[5], s[6]])
                    .collect();
                assert_eq!(rest.len(), 1, "{what}: more than one witness but q_sign");
                let q_signs: BTreeSet<i128> = solutions.iter().map(|s| s[2]).collect();
                match divisor {
                    // The identity's product is zero either way and `rd` reads
                    // the word, so both flags satisfy and nothing else moves.
                    0 => {
                        assert_eq!(q_signs, BTreeSet::from([0, 1]), "{what}: q_sign is free");
                        assert_eq!(solutions.len(), 2, "{what}");
                    }
                    _ => {
                        assert_eq!(q_signs.len(), 1, "{what}: q_sign is determined");
                        assert_eq!(solutions.len(), 1, "{what}: one witness");
                    }
                }
                // The named cases, at this width: the signed overflow, the
                // zero divisor's pin, and the row a floored quotient would
                // also satisfy the bare identity on.
                if signed_op && dividend == REDUCED / 2 && divisor == REDUCED - 1 {
                    assert_eq!(want, (REDUCED / 2, 0), "{what}: the signed overflow");
                }
                if divisor == 0 {
                    assert_eq!(
                        want,
                        (REDUCED - 1, dividend),
                        "{what}: the zero-divisor pin"
                    );
                }
            }
        }
    }
    // Every sign quadrant is reached, signed and unsigned.
    let mut every = BTreeSet::new();
    for signed_op in [false, true] {
        for top1 in 0..2 {
            for top2 in 0..2 {
                every.insert((signed_op, top1, top2));
            }
        }
    }
    assert_eq!(quadrants, every);
}

// ---------------------------------------------------------------------------
// Acceptance 4, as rows
// ---------------------------------------------------------------------------

/// The value of the relation `name`'s gate on `r`, through the kernel. Every
/// gate read this way is over committed columns and literal coefficients, so
/// it needs neither scratch nor a challenge.
fn relation_at(a: &CircuitArtifact, r: &Row, name: &str) -> Fr {
    let relation = a
        .relations
        .iter()
        .find(|x| x.name == name)
        .unwrap_or_else(|| panic!("no relation `{name}`"));
    expression(a, &r.committed(a), &relation.gate)
}

/// Acceptance 4's negative half: the division identity alone proves nothing,
/// and each of the three gates beside it is what refuses a witness the
/// identity admits.
///
/// `DIV(−7, 2)` is −3 remainder −1. The **floored** answer, −4 remainder 1,
/// satisfies the bare identity — `2·(−4) + 1 = −7` — and the magnitude bound
/// with it, `|1| < |2|`; the remainder's sign rule is the only thing between
/// it and a proof, which is `docs/spec/mul-div.md` §4.4's claim as a row.
#[test]
fn the_floored_quotient_satisfies_the_identity_and_is_refused_by_the_sign_rule() {
    let a = artifact();
    let floored = floored_minus_seven_over_two();
    assert_eq!(
        relation_at(&a, &floored, "division_rule"),
        Fr::ZERO,
        "the bare division identity holds on the floored witness"
    );
    assert_eq!(
        relation_at(&a, &floored, "gap_rule"),
        Fr::ZERO,
        "and so does the magnitude bound"
    );
    assert_eq!(
        violated(&a, &floored),
        (names(&["r_sign_rule"]), none(), none()),
        "only the remainder's sign rule refuses it"
    );
    // The honest row beside it: −3 remainder −1, every gate and bound held.
    let honest = row("div 0xfffffff9 0x2");
    assert_eq!(violated(&a, &honest), (none(), none(), none()));
    assert_eq!(small_int(honest.get("q")), Some((-3i32) as u32 as u64));
    assert_eq!(small_int(honest.get("r")), Some((-1i32) as u32 as u64));
}

/// The unsigned pair, where the dividend's sign is 0 and the magnitude bound
/// is the whole of the pin. `DIVU(7, 3)` is 2 remainder 1. A quotient one too
/// small leaves a remainder as large as the divisor, which every gate admits
/// and the gap's range refuses. A quotient one too large has no remainder in
/// the word at all — the identity forces `7 − 3·3 = −2`, and a prover can only
/// offer its wrapped word — so the identity refuses it, and the magnitude the
/// wrapped word carries refuses it again.
#[test]
fn a_quotient_off_by_one_is_refused_by_the_gap_or_by_the_identity() {
    let a = artifact();
    let divu = Instr::new(kind::DIVU);
    let too_small = forged_division(
        divu,
        7,
        3,
        Witness {
            q: 1,
            q_sign: 0,
            r: 4,
            r_sign: 0,
        },
    );
    assert_eq!(
        relation_at(&a, &too_small, "division_rule"),
        Fr::ZERO,
        "3·1 + 4 = 7: the identity holds"
    );
    assert_eq!(
        violated(&a, &too_small),
        (none(), names(&["gap_lo_range"]), none()),
        "a remainder as large as the divisor is refused by the gap alone"
    );
    let too_large = forged_division(
        divu,
        7,
        3,
        Witness {
            q: 3,
            q_sign: 0,
            r: (-2i32) as u32,
            r_sign: 0,
        },
    );
    assert_eq!(
        violated(&a, &too_large),
        (names(&["division_rule"]), names(&["gap_lo_range"]), none()),
        "a wrapped remainder is off by 2^32 in the identity and past the gap"
    );
}

/// Division by zero is pinned by one gate, and nothing else needs to be. The
/// remainder is already the dividend — with `rs2_adj = 0` the identity gives
/// it — so a zero-divisor row whose quotient is anything but all ones breaks
/// `zero_divisor_quotient` and no other gate, range or table.
#[test]
fn a_zero_divisor_whose_quotient_is_not_all_ones_is_refused_by_the_pin_alone() {
    let a = artifact();
    let forged = forged_division(
        Instr::new(kind::DIV),
        0x8000_0000,
        0,
        Witness {
            q: 0,
            q_sign: 0,
            r: 0x8000_0000,
            r_sign: 1,
        },
    );
    assert_eq!(
        relation_at(&a, &forged, "division_rule"),
        Fr::ZERO,
        "the identity gives the dividend back whatever the quotient"
    );
    assert_eq!(
        violated(&a, &forged),
        (names(&["zero_divisor_quotient"]), none(), none())
    );
    // And the honest row, whose quotient is all ones.
    let honest = row("div 0x80000000 0x0");
    assert_eq!(violated(&a, &honest), (none(), none(), none()));
    assert_eq!(small_int(honest.get("q")), Some(u32::MAX as u64));
    assert_eq!(small_int(honest.get("r")), Some(0x8000_0000));
}

/// The one signed overflow, `DIV(−2^31, −1)`, has exactly the pinned answer
/// and needs no pin: `|rem| < |−1|` forces a zero remainder, the identity then
/// forces the quotient's adjusted value to `+2^31`, and `q`'s own range forces
/// `q_sign = 0` and the word `0x80000000` (`docs/spec/mul-div.md` §5.3). Two
/// other quotients show the two halves of that argument: the same word with
/// `q_sign` flipped — which is what a circuit taking `q_sign` from a sign
/// lookup would force — is refused by the identity, and a quotient of 0 with
/// the whole dividend left over is refused by the magnitude bound.
#[test]
fn the_signed_overflow_has_exactly_the_pinned_answer() {
    let a = artifact();
    let overflow = row("div 0x80000000 0xffffffff");
    assert_eq!(violated(&a, &overflow), (none(), none(), none()));
    assert_eq!(small_int(overflow.get("q")), Some(0x8000_0000));
    assert_eq!(small_int(overflow.get("q_sign")), Some(0));
    assert_eq!(small_int(overflow.get("r")), Some(0));
    assert_eq!(small_int(overflow.get("rd_write_value")), Some(0x8000_0000));
    // REM of the same pair leaves no remainder.
    let rem = row("rem 0x80000000 0xffffffff");
    assert_eq!(violated(&a, &rem), (none(), none(), none()));
    assert_eq!(small_int(rem.get("rd_write_value")), Some(0));

    let div = Instr::new(kind::DIV);
    let negated = forged_division(
        div,
        0x8000_0000,
        0xFFFF_FFFF,
        Witness {
            q: 0x8000_0000,
            q_sign: 1,
            r: 0,
            r_sign: 0,
        },
    );
    assert_eq!(
        violated(&a, &negated),
        (names(&["division_rule"]), none(), none()),
        "a quotient of −2^31 does not divide −2^31 by −1"
    );
    let nothing = forged_division(
        div,
        0x8000_0000,
        0xFFFF_FFFF,
        Witness {
            q: 0,
            q_sign: 0,
            r: 0x8000_0000,
            r_sign: 1,
        },
    );
    assert_eq!(
        relation_at(&a, &nothing, "division_rule"),
        Fr::ZERO,
        "a quotient of 0 with the dividend left over satisfies the identity"
    );
    assert_eq!(
        violated(&a, &nothing),
        (none(), names(&["gap_lo_range"]), none()),
        "and the magnitude bound is what refuses it"
    );
}

/// The sign readings, which no gate can check. `rs1_top` and `rs2_top` are
/// pinned by a `U16GetSign` lookup of the packed table and by nothing else, so
/// a row that reads a negative operand as positive — and recomputes its whole
/// product from that reading — breaks no gate and no range: the lookup of the
/// operand whose bit was forged is the one refusal. The sign **adjustment** is
/// a gate's business, and a `mulhsu` claiming its unsigned `rs2` is negative
/// is refused by `s2_rule` alone.
#[test]
fn a_forged_operand_sign_is_refused_by_its_lookup_alone() {
    let a = artifact();
    let zeros = Witness {
        q: 0,
        q_sign: 0,
        r: 0,
        r_sign: 0,
    };
    let flat = Signs {
        top1: 0,
        top2: 0,
        s1: 0,
        s2: 0,
    };
    // A mulhsu whose signed rs1 is read as unsigned: the high half becomes 2
    // rather than all ones, and only the sign lookup says so.
    let lhs = build(Instr::new(kind::MULHSU), 0xFFFF_FFF9, 3, 0, flat, zeros);
    assert_eq!(
        violated(&a, &lhs),
        (none(), none(), names(&["rs1_get_sign"])),
    );
    assert_eq!(small_int(lhs.get("rd_write_value")), Some(2));
    // A mulh whose signed rs2 is read as unsigned.
    let rhs = build(Instr::new(kind::MULH), 7, 0xFFFF_FFFD, 0, flat, zeros);
    assert_eq!(
        violated(&a, &rhs),
        (none(), none(), names(&["rs2_get_sign"])),
    );
    assert_eq!(small_int(rhs.get("rd_write_value")), Some(6));
    // The adjustment, which is a gate's: mulhsu reads rs2 unsigned whatever
    // its top bit, so a row claiming otherwise is refused by `s2_rule` and
    // passes both sign lookups, the bits themselves being the operands'.
    let claimed = build(
        Instr::new(kind::MULHSU),
        7,
        0xFFFF_FFFD,
        0,
        Signs {
            top1: 0,
            top2: 1,
            s1: 0,
            s2: 1,
        },
        zeros,
    );
    assert_eq!(
        violated(&a, &claimed),
        (names(&["s2_rule"]), none(), none())
    );
}

// ---------------------------------------------------------------------------
// The guest, and the prover's fill of its shard
// ---------------------------------------------------------------------------

/// `guests/alu`, decoded with all four of its execution families at `2^20`
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
    // Only the families S18 proves: an instruction of any other family would
    // put a family in the config that no circuit proves.
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
            family::PUBLIC_INPUT,
            family::PUBLIC_OUTPUT,
            family::ADVICE_WINDOWS,
        ]
    );
    let io = emulator::GuestIo {
        stdin: Vec::new(),
        advice: Vec::new(),
        input: Vec::new(),
        hint: Vec::new(),
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
        Vec::new(),
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

/// One executed row of the family, with its decoded fields and the values its
/// queries saw.
struct Ran {
    bit: u32,
    rd: u32,
    rs1: u32,
    rs2: u32,
    write: Option<u32>,
}

fn ran(program: &prover::Program, archive: &trace::TraceArchive) -> Vec<Ran> {
    use trace::Role;
    let table = program
        .tables
        .family(family::MUL_DIV)
        .expect("the family's table");
    let traces = archive.family_traces();
    let buffer = traces.family(family::MUL_DIV).expect("the family's buffer");
    (0..buffer.len())
        .map(|i| {
            let row = buffer.row(i);
            let field = |c| table.get(c, row.pc as usize / 2).expect("a live row");
            let read = |role| row.query(role).map(|q| q.read_value).expect("an operand");
            Ran {
                // pc next_pc rs1 rs2 rd extra_mask: the mask is column 5, this
                // family's tuple having no immediate.
                bit: field(5).trailing_zeros(),
                rd: field(4),
                rs1: read(Role::Rs1),
                rs2: read(Role::Rs2),
                write: row.query(Role::Rd).map(|q| q.write_value),
            }
        })
        .collect()
}

/// S18's acceptance 1, 3, 4 and 9 read from the trace a proof is about: every
/// one of the eight instructions runs; every row writes what RV32M defines,
/// computed here from the ISA's table and not from the circuit; `div` and
/// `rem` run in all four sign quadrants; all four divisions by zero run, and
/// the one signed overflow; `−2^31 × −2^31`, the asymmetric `mulhsu` corner
/// and `mulhu` just under `2^64` run; and a multiply and a division run with
/// `rd = x0`, whose write is 0 while the value it computes is not.
#[test]
fn the_guest_runs_the_acceptance_matrix() {
    use kind::*;
    let (program, archive) = alu();
    let rows = ran(&program, &archive);
    for bit in 0..8u32 {
        assert!(
            rows.iter().any(|r| r.bit == bit),
            "the guest runs no {}",
            mnemonic(bit)
        );
    }
    // Every row's write is the ISA's answer.
    for r in &rows {
        let want = match r.rd {
            0 => 0,
            _ => rv32m(r.bit, r.rs1, r.rs2),
        };
        assert_eq!(
            r.write,
            Some(want),
            "{} {:#x} {:#x} into x{}",
            mnemonic(r.bit),
            r.rs1,
            r.rs2,
            r.rd
        );
    }
    let has = |what: &str, p: &dyn Fn(&Ran) -> bool| {
        assert!(rows.iter().any(p), "the guest runs no {what}");
    };
    // All four sign quadrants of div and rem.
    for bit in [DIV, REM] {
        for (lhs, rhs) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
            has(
                &format!("{} with signs {lhs}{rhs}", mnemonic(bit)),
                &|r: &Ran| r.bit == bit && r.rs1 >> 31 == lhs && r.rs2 >> 31 == rhs && r.rs2 != 0,
            );
        }
    }
    // Division by zero, all four.
    for bit in [DIV, DIVU, REM, REMU] {
        has(&format!("{} by zero", mnemonic(bit)), &|r: &Ran| {
            r.bit == bit && r.rs2 == 0
        });
    }
    // The one signed overflow, both halves of it.
    for bit in [DIV, REM] {
        has(&format!("{}(-2^31, -1)", mnemonic(bit)), &|r: &Ran| {
            r.bit == bit && r.rs1 == 0x8000_0000 && r.rs2 == u32::MAX
        });
    }
    // The multiply corners acceptance 3 names.
    for bit in [MUL, MULH] {
        has(&format!("{}(-2^31, -2^31)", mnemonic(bit)), &|r: &Ran| {
            r.bit == bit && r.rs1 == 0x8000_0000 && r.rs2 == 0x8000_0000
        });
    }
    has("the asymmetric mulhsu corner", &|r: &Ran| {
        r.bit == MULHSU && r.rs1 == 0x8000_0000 && r.rs2 == u32::MAX
    });
    has("a mulhu just under 2^64", &|r: &Ran| {
        r.bit == MULHU && r.rs1 == u32::MAX && r.rs2 == u32::MAX
    });
    // rd = x0 in each half: the row is proven and x0 keeps its zero, while
    // the value the instruction computes is not zero.
    for bit in [MUL, DIV] {
        has(&format!("{} into x0", mnemonic(bit)), &|r: &Ran| {
            r.bit == bit && r.rd == 0 && r.write == Some(0) && rv32m(r.bit, r.rs1, r.rs2) != 0
        });
    }
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
    let columns = filled(&program, &archive, 0, VARS);
    let rows: Vec<usize> = (0..live + 2).chain([(1 << VARS) - 1]).collect();
    assert_rows_hold(&columns, &rows);
}

/// The family's fill of shard `index` at `2^vars` rows, with its setup columns
/// held to the program's decoded table — six columns, not seven — and to the
/// packed generic table row for row, and every channel's multiplicities
/// counted over it.
fn filled(
    program: &prover::Program,
    archive: &trace::TraceArchive,
    index: u32,
    vars: u32,
) -> Vec<(PolyAddress, poly::MultilinearPoly)> {
    let a = artifact();
    let fill = prover::family_fill(family::MUL_DIV).expect("the family's fill");
    let source = prover::ShardSource {
        program,
        archive,
        family: family::MUL_DIV,
        index,
        height: 1 << vars,
        window: 0,
    };
    let mut columns = fill(&source).expect("the fill");
    let column = |address: PolyAddress| {
        columns
            .iter()
            .find(|(c, _)| *c == address)
            .unwrap_or_else(|| panic!("the fill has no {address}"))
            .1
            .clone()
    };
    // The setup columns are the tables the key's commitments are of: the
    // decoded table identity binds, then the packed table the SRS digest does.
    let table = program
        .tables
        .family(family::MUL_DIV)
        .expect("the family's table");
    let generic = program::lookup_tables::generic_table(vars);
    for j in 0..mul_div::TABLE_WIDTH + generic_table::WIDTH {
        let filled = column(PolyAddress::Setup(j as u32));
        let want = match j.checked_sub(mul_div::TABLE_WIDTH) {
            None => table.column_poly(j),
            Some(g) => generic[g].clone(),
        };
        assert_eq!(filled.len(), 1 << vars, "S[{j}]'s height");
        assert!(
            (0..1 << vars).all(|i| filled.get(i) == want.get(i)),
            "S[{j}] is not its table"
        );
    }
    let counts = trace::build_multiplicities(&a, &columns, &mul_div::channels())
        .expect("every tuple of the shard is a row of its table");
    assert_eq!(counts.len(), mul_div::MULTIPLICITIES.len());
    columns.extend(counts);
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
