//! S17's `JUMP_BRANCH_SLT` circuit (`docs/spec/jump-branch-slt.md`), row by
//! row, in ordinary CI.
//!
//! No forward pass over `2^20` rows: each row is built by hand from what the
//! instruction computes — Rust's own `u32` and `i32` arithmetic, not the
//! circuit's — and evaluated alone through `checker::violated_relations` and
//! `violated_lookups`, its row-local scratch computed by `gkr::gate_values`.
//! The two table channels, which `violated_lookups` does not read, are held
//! here to the tables themselves: a row's gated generic tuple to
//! `program::lookup_tables`' entries, its gated decoder tuple to the table
//! columns the row carries. The proofs of the same rows are
//! `crates/prover/tests/control.rs`' and `crates/checker/tests/tamper.rs`'.
//!
//! Acceptance 2 (the comparison, exhaustively at a reduced width and pinned at
//! full width), 4 (the SLTI defect), 8 (padding) and 9 (the legal masks) are
//! here in full; 3 and 5 as rows and in the guest's trace, whose proof is
//! `crates/prover/tests/control.rs`'; 6 as the honest prover's refusal to count
//! the decoder channel over a jump into the middle of an instruction, whose
//! proof is the tamper file's; and 7's forged `lt` as rows.

use std::collections::{BTreeMap, BTreeSet};

use checker::{
    check_laws, check_lookup_discharge, check_padding, check_padding_identity, violated_lookups,
    violated_relations, WitnessRow,
};
use constants::extra_mask::jump_branch_slt as kind;
use constants::{challenge_slot, family, generic_table, lookup_channel};
use constraints::gadgets::{comparison_equation, Comparison};
use constraints::lookup::{check_discharge, ChannelSpec};
use constraints::memory::check_memory;
use constraints::{family_circuit, jump_branch_slt, CircuitArtifact, PolyAddress, VirtualKind};
use field::Fr;
use gkr::{eval_gate, gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use isa::Instr as Isa;
use program::lookup_tables::generic_entries;
use test_support::{sha256, to_hex};

const VARS: u32 = 20;
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/jump_branch_slt.bin"
);
const FIXTURE_SHA256: &str = "99094d63daa97a1a1cfa5f61f0b9124fa376e8c7e045cdfa0c213ae7742c1305";

fn artifact() -> CircuitArtifact {
    jump_branch_slt::artifact(VARS)
}

fn challenges(a: &CircuitArtifact) -> ExternalChallenges {
    let mut ch = ExternalChallenges::new();
    for (slot, v) in [
        (challenge_slot::MEM_GAMMA, 11),
        (challenge_slot::MEM_ALPHA_ADDR, 13),
        (challenge_slot::MEM_ALPHA_TS, 17),
        (challenge_slot::MEM_ALPHA_VAL, 19),
    ] {
        ch.insert(slot, Fr::from_u64(v));
    }
    insert_lookup_challenges(&mut ch, Fr::from_u64(23), Fr::from_u64(29), a);
    ch
}

fn f(v: u64) -> Fr {
    Fr::from_u64(v)
}

const TWO_32: u64 = 1 << 32;
const INT_MIN: u32 = 0x8000_0000;

// ---------------------------------------------------------------------------
// Rows
// ---------------------------------------------------------------------------

/// A row by column name; a column not named is 0.
#[derive(Clone, Debug, Default)]
struct Row(BTreeMap<&'static str, Fr>);

impl Row {
    fn set(&mut self, name: &'static str, v: Fr) -> &mut Row {
        self.0.insert(name, v);
        self
    }

    fn get(&self, name: &str) -> Fr {
        self.0.get(name).copied().unwrap_or(Fr::ZERO)
    }

    /// Set the query `q`'s five columns, reading a write made eight
    /// timestamps before its own.
    fn query(&mut self, q: &'static str, delta: u64, addr: u64, read: u64, write: u64) {
        self.set(name(q, "mask"), Fr::ONE)
            .set(name(q, "addr"), f(addr))
            .set(name(q, "read_ts"), f(4 * CYCLE + delta - 8))
            .set(name(q, "read_value"), f(read))
            .set(name(q, "write_value"), f(write));
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

/// `<q>_<field>`, a column name, leaked to `'static` for the map.
fn name(q: &str, field: &str) -> &'static str {
    Box::leak(format!("{q}_{field}").into_boxed_str())
}

/// The kind bits' column names, in `extra_mask::jump_branch_slt` order.
const KINDS: [&str; 12] = [
    "slti", "sltiu", "slt", "sltu", "beq", "bne", "blt", "bge", "bltu", "bgeu", "jalr", "jal",
];

/// One instruction of the family, as the decoded table holds it.
#[derive(Clone, Copy, Debug)]
struct Instr {
    bit: u32,
    pc: u32,
    compressed: bool,
    rs1: u32,
    rs2: u32,
    rd: u32,
    imm: u32,
}

fn instr(bit: u32, rs1: u32, rs2: u32, rd: u32, imm: i32) -> Instr {
    Instr {
        bit,
        pc: 0x1_0100,
        compressed: false,
        rs1,
        rs2,
        rd,
        imm: imm as u32,
    }
}

const CYCLE: u64 = 9;

fn uses_rs1(bit: u32) -> bool {
    bit != kind::JAL
}

fn uses_rs2(bit: u32) -> bool {
    matches!(
        bit,
        kind::SLT
            | kind::SLTU
            | kind::BEQ
            | kind::BNE
            | kind::BLT
            | kind::BGE
            | kind::BLTU
            | kind::BGEU
    )
}

fn uses_rd(bit: u32) -> bool {
    matches!(
        bit,
        kind::SLTI | kind::SLTIU | kind::SLT | kind::SLTU | kind::JALR | kind::JAL
    )
}

/// The honest row of `i` on cycle 9, its reads seeing `rs1v` and `rs2v` — the
/// row reads only the operands its form has — and its `rd` read seeing
/// `rd_old`. Every value from Rust's own arithmetic.
fn honest(i: Instr, rs1v: u32, rs2v: u32, rd_old: u32) -> Row {
    let bit = i.bit;
    let a = if uses_rs1(bit) { rs1v } else { 0 };
    let c = if uses_rs2(bit) { rs2v } else { 0 };
    let rhs = match bit {
        kind::SLTI | kind::SLTIU => i.imm,
        _ => c,
    };
    let lt = match bit {
        kind::SLTI | kind::SLT | kind::BLT | kind::BGE => (a as i32) < (rhs as i32),
        _ => a < rhs,
    };
    let eq = a == rhs;
    let taken = match bit {
        kind::BEQ => eq,
        kind::BNE => !eq,
        kind::BLT | kind::BLTU => lt,
        kind::BGE | kind::BGEU => !lt,
        _ => false,
    };
    let seq = i.pc + if i.compressed { 2 } else { 4 };
    let (next, wrap, drop) = if bit == kind::JAL || taken {
        let (t, w) = i.pc.overflowing_add(i.imm);
        (t, w, 0)
    } else if bit == kind::JALR {
        let (s, w) = a.overflowing_add(i.imm);
        (s & !1, w, s & 1)
    } else {
        (seq, false, 0)
    };
    let sel = match bit {
        kind::JAL | kind::JALR => seq,
        kind::SLTI | kind::SLTIU | kind::SLT | kind::SLTU => lt as u32,
        _ => 0,
    };
    let gap = a.wrapping_sub(rhs);

    let mut r = Row::default();
    r.set("cycle", f(CYCLE));
    r.set("pc_mask", Fr::ONE)
        .set("pc_read_ts", f(4 * (CYCLE - 1)))
        .set("pc_read_value", f(i.pc as u64))
        .set("pc_write_value", f(next as u64));
    if uses_rs1(bit) {
        r.query("rs1", 1, i.rs1 as u64, a as u64, a as u64);
    }
    if uses_rs2(bit) {
        r.query("rs2", 2, i.rs2 as u64, c as u64, c as u64);
    }
    if uses_rd(bit) {
        let write = if i.rd == 0 { 0 } else { sel };
        r.query("rd", 3, i.rd as u64, rd_old as u64, write as u64);
        match i.rd {
            0 => r.set("rd_is_zero", Fr::ONE),
            d => r.set("rd_inv", f(d as u64).inverse().expect("nonzero")),
        };
    }
    let table = [
        ("next_pc", seq),
        ("rs1", i.rs1),
        ("rs2", i.rs2),
        ("rd", i.rd),
        ("imm", i.imm),
        ("mask", 1 << bit),
    ];
    for (field, v) in table {
        r.set(name("decoded", field), f(v as u64));
    }
    r.set("table_pc", f(i.pc as u64))
        .set("table_next_pc", f(seq as u64))
        .set("table_rs1", f(i.rs1 as u64))
        .set("table_rs2", f(i.rs2 as u64))
        .set("table_rd", f(i.rd as u64))
        .set("table_imm", f(i.imm as u64))
        .set("table_extra_mask", f(1 << bit));
    r.set(name("kind", KINDS[bit as usize]), Fr::ONE);
    r.set("cmp_rhs", f(rhs as u64))
        .set("rs1_hi", f(a as u64 >> 16))
        .set("rs1_sign", f(a as u64 >> 31))
        .set("cmp_rhs_hi", f(rhs as u64 >> 16))
        .set("cmp_rhs_sign", f(rhs as u64 >> 31))
        .set("lt", f(lt as u64))
        .set("cmp_gap", f(gap as u64))
        .set("cmp_gap_hi", f(gap as u64 >> 16))
        .set("eq", f(eq as u64))
        .set(
            "eq_inv",
            (f(a as u64) - f(rhs as u64)).inverse().unwrap_or(Fr::ZERO),
        )
        .set("taken", f(taken as u64))
        .set("jalr_drop", f(drop as u64))
        .set("pc_wrap", f(wrap as u64))
        .set("next_pc_hi", f(next as u64 >> 16))
        .set("rd_selected", f(sel as u64))
        .set("rd_hi", f(sel as u64 >> 16));
    r
}

/// Every honest row this file names.
fn honest_rows() -> Vec<(&'static str, Row)> {
    use kind::*;
    let mut c_jal = instr(JAL, 0, 0, 1, 0x40);
    c_jal.compressed = true;
    let mut c_beqz = instr(BEQ, 10, 0, 0, -6);
    c_beqz.compressed = true;
    let mut c_bnez = instr(BNE, 10, 0, 0, 0x18);
    c_bnez.compressed = true;
    let far = instr(JAL, 0, 0, 1, 0x7fffe);
    vec![
        (
            "slt INT_MIN < 1",
            honest(instr(SLT, 5, 6, 28, 0), INT_MIN, 1, 0),
        ),
        (
            "slt 1 < INT_MIN",
            honest(instr(SLT, 6, 5, 28, 0), 1, INT_MIN, 7),
        ),
        (
            "slt -1 < 1",
            honest(instr(SLT, 7, 6, 28, 0), u32::MAX, 1, 0),
        ),
        (
            "slt 1 < -1",
            honest(instr(SLT, 6, 7, 28, 0), 1, u32::MAX, 0),
        ),
        ("slt equal", honest(instr(SLT, 6, 6, 28, 0), 5, 5, 0)),
        (
            "slt rd = rs1",
            honest(instr(SLT, 5, 6, 5, 0), INT_MIN, 1, INT_MIN),
        ),
        (
            "sltu INT_MIN < 1",
            honest(instr(SLTU, 5, 6, 28, 0), INT_MIN, 1, 0),
        ),
        (
            "sltu 1 < INT_MIN",
            honest(instr(SLTU, 6, 5, 28, 0), 1, INT_MIN, 0),
        ),
        (
            "sltu 1 < -1",
            honest(instr(SLTU, 6, 7, 28, 0), 1, u32::MAX, 0),
        ),
        ("slti 5 < -1", honest(instr(SLTI, 6, 0, 5, -1), 5, 0, 0)),
        (
            "slti -5 < -1",
            honest(instr(SLTI, 6, 0, 5, -1), (-5i32) as u32, 0, 0),
        ),
        (
            "slti -1 < -1",
            honest(instr(SLTI, 5, 0, 5, -1), u32::MAX, 0, u32::MAX),
        ),
        (
            "slti -5 < 2047",
            honest(instr(SLTI, 6, 0, 5, 2047), (-5i32) as u32, 0, 1),
        ),
        ("sltiu 5 < -1", honest(instr(SLTIU, 6, 0, 5, -1), 5, 0, 0)),
        (
            "sltiu -1 < -1",
            honest(instr(SLTIU, 5, 0, 5, -1), u32::MAX, 0, u32::MAX),
        ),
        (
            "sltiu -5 < 2047",
            honest(instr(SLTIU, 6, 0, 5, 2047), (-5i32) as u32, 0, 0),
        ),
        ("slt to x0", honest(instr(SLT, 0, 6, 0, 0), 0, 1, 0)),
        ("sltu to x0", honest(instr(SLTU, 0, 6, 0, 0), 0, 1, 0)),
        ("slti to x0", honest(instr(SLTI, 0, 0, 0, 1), 0, 0, 0)),
        ("sltiu to x0", honest(instr(SLTIU, 0, 0, 0, 1), 0, 0, 0)),
        ("beq taken", honest(instr(BEQ, 6, 6, 0, 8), 1, 1, 0)),
        (
            "beq not taken",
            honest(instr(BEQ, 5, 6, 0, 8), INT_MIN, 1, 0),
        ),
        ("bne taken", honest(instr(BNE, 5, 6, 0, 8), INT_MIN, 1, 0)),
        ("bne not taken", honest(instr(BNE, 6, 6, 0, 8), 1, 1, 0)),
        (
            "blt(INT_MIN, 1) taken",
            honest(instr(BLT, 5, 6, 0, 8), INT_MIN, 1, 0),
        ),
        (
            "blt(1, INT_MIN) not taken",
            honest(instr(BLT, 6, 5, 0, 8), 1, INT_MIN, 0),
        ),
        (
            "blt equal not taken",
            honest(instr(BLT, 6, 6, 0, 8), 1, 1, 0),
        ),
        (
            "bge(1, INT_MIN) taken",
            honest(instr(BGE, 6, 5, 0, 8), 1, INT_MIN, 0),
        ),
        (
            "bge(INT_MIN, 1) not taken",
            honest(instr(BGE, 5, 6, 0, 8), INT_MIN, 1, 0),
        ),
        ("bge equal taken", honest(instr(BGE, 6, 6, 0, 8), 1, 1, 0)),
        (
            "bltu(INT_MIN, 1) not taken",
            honest(instr(BLTU, 5, 6, 0, 8), INT_MIN, 1, 0),
        ),
        (
            "bltu(1, INT_MIN) taken",
            honest(instr(BLTU, 6, 5, 0, 8), 1, INT_MIN, 0),
        ),
        (
            "bgeu(INT_MIN, 1) taken",
            honest(instr(BGEU, 5, 6, 0, 8), INT_MIN, 1, 0),
        ),
        (
            "bgeu(1, INT_MIN) not taken",
            honest(instr(BGEU, 6, 5, 0, 8), 1, INT_MIN, 0),
        ),
        (
            "bne backward -16 taken",
            honest(instr(BNE, 5, 0, 0, -16), 3, 0, 0),
        ),
        (
            "bne backward -16 not taken",
            honest(instr(BNE, 5, 0, 0, -16), 0, 0, 0),
        ),
        (
            "beq to the fall-through",
            honest(instr(BEQ, 0, 0, 0, 4), 0, 0, 0),
        ),
        ("jal forward", honest(instr(JAL, 0, 0, 1, 0xa4), 0, 0, 9)),
        ("jal backward", honest(instr(JAL, 0, 0, 1, -0x14), 0, 0, 0)),
        ("jal x0", honest(instr(JAL, 0, 0, 0, 0x18), 0, 0, 0)),
        ("jal to 2^19 ahead", honest(far, 0, 0, 0)),
        (
            "jalr rs1 = rd, imm -2, bit 0 set",
            honest(instr(JALR, 7, 0, 7, -2), 0x1_01ab, 0, 0x1_01ab),
        ),
        (
            "jalr wrapping",
            honest(instr(JALR, 5, 0, 1, -4), 0x1_0000, 0, 0),
        ),
        (
            "jalr x0 (ret)",
            honest(instr(JALR, 1, 0, 0, 0), 0x1_0178, 0, 0),
        ),
        ("c.jal, two bytes", honest(c_jal, 0, 0, 0)),
        ("c.beqz taken backward", honest(c_beqz, 0, 0, 0)),
        ("c.bnez not taken", honest(c_bnez, 0, 0, 0)),
        ("padding", Row::default()),
    ]
}

fn row(what: &str) -> Row {
    honest_rows()
        .into_iter()
        .find(|(w, _)| *w == what)
        .unwrap_or_else(|| panic!("no row `{what}`"))
        .1
}

/// A lookup expression's value on the committed row: `eval_gate` over the
/// expression's operands, read from the layout.
fn expression(a: &CircuitArtifact, committed: &[Fr], gate: &constraints::GateDef) -> Fr {
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

/// The two table channels' lookups the row does not hold, by name: a generic
/// lookup whose gated tuple — `s·(e_0 + 1), s·e_1, s·e_2`
/// (`docs/spec/lookup.md` §4) — is neither the `ZeroEntry` nor an entry of the
/// packed table, and a decoder lookup whose gated tuple — `s·(e_j + 1) − 1` —
/// is neither the table row the row carries in its own `S` columns nor the
/// `MINUS_ONE` padding row, which every decoded table holds (S11's height
/// rule).
fn violated_tables(a: &CircuitArtifact, r: &Row) -> Vec<String> {
    let committed = r.committed(a);
    let layout = a.committed();
    let entries: BTreeSet<[u64; generic_table::WIDTH]> = generic_entries()
        .iter()
        .map(|e| e.map(|x| x as u64))
        .collect();
    let mut out = Vec::new();
    for l in &a.lookups {
        // Each lookup's own selector, read from the row: a selector moved to
        // another column is a different circuit, and this is what sees it.
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
                        .map(|v| small_int_opt(*v))
                        .collect::<Option<Vec<u64>>>()
                        .is_some_and(|t| entries.contains(&[t[0], t[1], t[2]]))
            }
            lookup_channel::DECODER => {
                let table: Vec<Fr> = (0..7)
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
    let w = r.witness(a, 1 << 15);
    (
        violated_relations(a, &w, &challenges(a)),
        violated_lookups(a, &w),
        violated_tables(a, r),
    )
}

fn small_int_opt(v: Fr) -> Option<u64> {
    let b = v.to_bytes();
    b[8..]
        .iter()
        .all(|x| *x == 0)
        .then(|| u64::from_le_bytes(b[..8].try_into().unwrap()))
}

fn small_int(v: Fr) -> u64 {
    small_int_opt(v).unwrap_or_else(|| panic!("{v:?} is not a small integer"))
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

/// The committed fixture is the constructor at the family's default height,
/// and the circuit keeps every rule both enforcement points hold it to: the
/// laws, the padding contract and its product-tree clause, S14's memory rules,
/// and S15's discharge rule — by `constraints` and, sharing no code, by this
/// crate.
#[test]
fn the_circuit_is_the_fixture_and_keeps_every_rule() {
    let bytes = std::fs::read(FIXTURE).expect("the jump/branch/slt fixture");
    assert_eq!(to_hex(&sha256(&bytes)), FIXTURE_SHA256);
    assert_eq!(jump_branch_slt::artifact(22).to_bytes(), bytes);
    assert_eq!(
        CircuitArtifact::from_bytes(&bytes),
        Ok(jump_branch_slt::artifact(22))
    );

    let a = artifact();
    let specs = jump_branch_slt::channels();
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(check_memory(&a), Ok(()));
    assert_eq!(check_discharge(&a, &specs), Ok(()));
    assert_eq!(check_laws(&a), Ok(()));
    assert_eq!(check_padding(&a), Ok(()));
    assert_eq!(check_padding_identity(&a), Ok(()));
    assert_eq!(check_lookup_discharge(&a, &specs), Ok(()));
    assert!(
        a.padding.zero_row_valid,
        "every gate is 0 on the all-zero row"
    );
    // The depth is add/sub's: the leaves, four row-wise levels — the widest
    // fraction tree has 16 leaves — and one halving level per variable.
    assert_eq!(a.depth(), 1 + 4 + VARS as usize);
}

/// The layout is `docs/spec/jump-branch-slt.md` §2's, and the gates, lookups
/// and channels are §4's and §5's, by name and in order.
#[test]
fn the_layout_and_the_gates_are_the_specs() {
    let a = artifact();
    assert_eq!(a.memory.len(), 21);
    let mut witness = names(&[
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
    ]);
    witness.extend(KINDS.iter().map(|k| format!("kind_{k}")));
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
        "mult_timestamp",
        "mult_range16",
        "mult_generic",
        "mult_decoder",
    ]));
    assert_eq!(a.witness, witness);
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
    assert_eq!(
        a.virtuals,
        vec![
            (VirtualKind::Range19, "range19".to_string()),
            (VirtualKind::Range16, "range16".to_string())
        ]
    );
    let enforcing: Vec<String> = a.layers[0]
        .enforcing
        .iter()
        .map(|e| a.relations[e.relation as usize].name.clone())
        .collect();
    let mut want = names(&[
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
    ]);
    want.extend(KINDS.iter().map(|k| format!("kind_{k}_boolean")));
    want.extend(names(&[
        "decoded_mask_bits",
        "rs1_mask_rule",
        "rs2_mask_rule",
        "rd_mask_rule",
        "rs1_addr_rule",
        "rs2_addr_rule",
        "rd_addr_rule",
        "rs1_value_masked",
        "rs2_value_masked",
        "cmp_rhs_rule",
        "cmp_order",
        "cmp_lt_boolean",
        "eq_inverse",
        "eq_at_nonzero",
        "taken_rule",
        "taken_boolean",
        "jalr_drop_boolean",
        "pc_wrap_boolean",
        "next_pc_rule",
        "rd_value_rule",
    ]));
    assert_eq!(enforcing, want);

    let lookups: Vec<(String, u32)> = a
        .lookups
        .iter()
        .map(|l| (l.name.clone(), l.channel))
        .collect();
    let range = lookup_channel::RANGE16;
    let generic = lookup_channel::GENERIC;
    assert_eq!(lookups.len(), 8 + 14);
    assert!(lookups[..8]
        .iter()
        .all(|(_, c)| *c == lookup_channel::TIMESTAMP));
    let family: Vec<(&str, u32)> = lookups[8..].iter().map(|(n, c)| (n.as_str(), *c)).collect();
    assert_eq!(
        family,
        vec![
            ("cmp_lhs_hi_range", range),
            ("cmp_lhs_lo_range", range),
            ("cmp_rhs_hi_range", range),
            ("cmp_rhs_lo_range", range),
            ("cmp_gap_hi_range", range),
            ("cmp_gap_lo_range", range),
            ("cmp_lhs_get_sign", generic),
            ("cmp_rhs_get_sign", generic),
            ("rd_hi_range", range),
            ("rd_lo_range", range),
            ("next_pc_hi_range", range),
            ("next_pc_lo_range", range),
            ("next_pc_even", range),
            ("decode_row", lookup_channel::DECODER),
        ]
    );
    // The frame's gap obligations are each under their own query's mask; the
    // family's fourteen are under the row's.
    let pc_mask = PolyAddress::Memory(1);
    for (at, l) in a.lookups[..8].iter().enumerate() {
        assert_eq!(
            l.selector,
            PolyAddress::Memory(1 + 5 * (at as u32 / 2)),
            "{}",
            l.name
        );
    }
    assert!(
        a.lookups[8..].iter().all(|l| l.selector == pc_mask),
        "every new obligation is the row's"
    );
    // The ordering gate is the gadget's equation at 32 bits over the family's
    // own columns, which is what the reduced-width check evaluates.
    let order = a
        .relations
        .iter()
        .find(|r| r.name == "cmp_order")
        .expect("the ordering gate");
    let k = |b: u32| jump_branch_slt::KINDS[b as usize];
    let family_comparison = Comparison {
        prefix: "cmp".into(),
        selector: PolyAddress::Memory(1),
        signed: vec![k(kind::SLTI), k(kind::SLT), k(kind::BLT), k(kind::BGE)],
        lhs: constraints::memory::frame(1, constraints::memory::FIELD_READ_VALUE),
        lhs_hi: jump_branch_slt::RS1_HI,
        lhs_sign: jump_branch_slt::RS1_SIGN,
        rhs: jump_branch_slt::CMP_RHS,
        rhs_hi: jump_branch_slt::CMP_RHS_HI,
        rhs_sign: jump_branch_slt::CMP_RHS_SIGN,
        lt: jump_branch_slt::LT,
        gap: jump_branch_slt::CMP_GAP,
        gap_hi: jump_branch_slt::CMP_GAP_HI,
    };
    assert_eq!(order.gate, comparison_equation(&family_comparison, 32));
    // A sign lookup's tuple: the high halfword keyed into U16GetSign, the
    // sign, and a zero.
    let w = |i| PolyAddress::Witness(i);
    let sign = &a.lookups[14];
    assert_eq!(
        sign.tuple,
        vec![
            constraints::GateDef::Linear {
                terms: vec![(constraints::Coeff::Literal(Fr::ONE), w(26))],
                constant: constraints::Coeff::Literal(f(generic_table::SIGN_BASE as u64)),
            },
            constraints::GateDef::Linear {
                terms: vec![(constraints::Coeff::Literal(Fr::ONE), w(27))],
                constant: constraints::Coeff::Literal(Fr::ZERO),
            },
            constraints::GateDef::Linear {
                terms: vec![],
                constant: constraints::Coeff::Literal(Fr::ZERO),
            },
        ]
    );

    let mult = |i: u32| w(40 + i);
    assert_eq!(
        jump_branch_slt::channels(),
        vec![
            ChannelSpec {
                channel: lookup_channel::TIMESTAMP,
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
                table: (7..10).map(PolyAddress::Setup).collect(),
                multiplicity: mult(2),
            },
            ChannelSpec {
                channel: lookup_channel::DECODER,
                table: (0..7).map(PolyAddress::Setup).collect(),
                multiplicity: mult(3),
            },
        ]
    );
    // Four product-tree leaves a side, then one fraction tree per channel:
    // 8 + 32 + 32 + 8 + 4.
    assert_eq!(a.layers[0].width, 84);
    assert_eq!(a.outputs.len(), 2 + 2 * 4);
}

/// The registry: this family from 19 variables, the timestamp channel's width,
/// the constructor it names — a provable height being 20 and up, Mercury's
/// even count — and nothing below 19.
#[test]
fn the_registry_holds_the_family() {
    let c = family_circuit(family::JUMP_BRANCH_SLT, VARS).expect("the family at 2^20");
    assert_eq!(
        (c.family, c.artifact, c.channels),
        (
            family::JUMP_BRANCH_SLT,
            artifact(),
            jump_branch_slt::channels()
        )
    );
    assert_eq!(family_circuit(family::JUMP_BRANCH_SLT, 18), None);
    let at_19 = family_circuit(family::JUMP_BRANCH_SLT, 19).expect("the family at 2^19");
    assert_eq!(at_19.artifact, jump_branch_slt::artifact(19));
    // Since S19 every execution family is registered, each in its own suite;
    // what is still `None` for all of them is a height below the timestamp
    // channel's width.
    for id in [family::MEM_WORD, family::MEM_SUBWORD, family::ATOMICS] {
        assert!(family_circuit(id, VARS).is_some(), "family {id}");
        assert_eq!(family_circuit(id, 18), None, "family {id} at 18");
    }
}

// ---------------------------------------------------------------------------
// Honest rows
// ---------------------------------------------------------------------------

/// Every row kind the family proves satisfies every gate, every range
/// obligation and both table channels: each comparison at full width and at
/// mixed signs, each branch taken and not taken — backward too, and to its own
/// fall-through — each jump forward, backward and to `x0`, a `jalr` whose sum
/// wraps and one whose bit 0 it drops, the compressed forms, `rd = x0` for all
/// four comparisons (acceptance 5), and the all-zero padding row.
#[test]
fn every_row_kind_satisfies_every_gate_and_every_bound() {
    let a = artifact();
    for (what, row) in honest_rows() {
        assert_eq!(violated(&a, &row), (none(), none(), none()), "{what}");
    }
    // The rows really are what their names say.
    let get = |what: &str, col: &str| small_int(row(what).get(col));
    assert_eq!(get("blt(INT_MIN, 1) taken", "taken"), 1);
    assert_eq!(get("bge(1, INT_MIN) taken", "taken"), 1);
    assert_eq!(get("bltu(INT_MIN, 1) not taken", "taken"), 0);
    assert_eq!(get("slt -1 < 1", "rd_write_value"), 1);
    assert_eq!(get("bne backward -16 taken", "pc_wrap"), 1);
    assert_eq!(get("bne backward -16 taken", "pc_write_value"), 0x1_00f0);
    assert_eq!(get("jal backward", "pc_wrap"), 1);
    assert_eq!(get("jal forward", "rd_write_value"), 0x1_0104);
    let jalr = row("jalr rs1 = rd, imm -2, bit 0 set");
    assert_eq!(small_int(jalr.get("jalr_drop")), 1);
    assert_eq!(small_int(jalr.get("pc_write_value")), 0x1_01a8);
    assert_eq!(small_int(jalr.get("rs1_read_value")), 0x1_01ab);
    assert_eq!(small_int(jalr.get("rd_write_value")), 0x1_0104);
    assert_eq!(get("jalr wrapping", "pc_wrap"), 1);
    assert_eq!(get("jalr wrapping", "pc_write_value"), 0xfffc);
    assert_eq!(get("c.jal, two bytes", "rd_write_value"), 0x1_0102);
    for x0 in ["slt to x0", "sltu to x0", "slti to x0", "sltiu to x0"] {
        assert_eq!(get(x0, "rd_selected"), 1, "{x0} computes 1");
        assert_eq!(get(x0, "rd_write_value"), 0, "{x0} writes 0");
    }
    assert_eq!(get("jal x0", "rd_write_value"), 0);
    assert_ne!(get("jal x0", "rd_selected"), 0);
}

// ---------------------------------------------------------------------------
// Each gate refuses its row
// ---------------------------------------------------------------------------

/// Each tamper beside the gates it breaks, exactly: an edit to an honest row
/// that the gates listed, and only they, refuse. Most are one gate: that gate
/// is load-bearing on the row shape it exists for.
#[test]
fn each_gate_is_the_one_that_refuses_its_row() {
    let a = artifact();
    let mut cases: Vec<(&str, Row, Vec<&str>)> = Vec::new();

    // The mask.
    let mut r = row("beq taken");
    r.set("decoded_mask", f(1 << kind::BNE));
    cases.push((
        "a beq whose packed mask says bne",
        r,
        vec!["decoded_mask_bits"],
    ));

    // Presence.
    let mut r = row("jal forward");
    r.query("rs1", 1, 0, 0, 0);
    cases.push(("a jal reading rs1", r, vec!["rs1_mask_rule"]));
    let mut r = row("slti 5 < -1");
    r.query("rs2", 2, 0, 0, 0);
    cases.push(("an slti reading rs2", r, vec!["rs2_mask_rule"]));
    let mut r = row("beq taken");
    r.query("rd", 3, 0, 0, 0);
    r.set("rd_is_zero", Fr::ONE);
    cases.push(("a branch writing x0", r, vec!["rd_mask_rule"]));
    let mut r = row("slt INT_MIN < 1");
    for field in ["mask", "addr", "read_ts", "read_value", "write_value"] {
        r.0.remove(name("rd", field));
    }
    r.set("rd_inv", Fr::ZERO);
    cases.push((
        "an slt whose write is masked off",
        r,
        vec!["rd_write_masked", "rd_mask_rule"],
    ));
    // S14's control C8 on this family: a padding row rewriting x10, and one
    // whose free kind bits claim jal to make the write look owed — every
    // other gate then holds, its pc and immediate being 0, so the mask rule's
    // m_pc factor is the one thing that refuses it.
    let mut r = Row::default();
    r.query("rd", 3, 10, 42, 43);
    r.set("rd_inv", f(10).inverse().unwrap())
        .set("rd_selected", f(43));
    cases.push((
        "a padding row rewriting x10",
        r,
        vec!["rd_mask_rule", "rd_addr_rule", "rd_value_rule"],
    ));
    let mut r = Row::default();
    r.set("kind_jal", Fr::ONE)
        .set("decoded_mask", f(1 << kind::JAL))
        .set("decoded_rd", f(10))
        .set("decoded_next_pc", f(43));
    r.query("rd", 3, 10, 42, 43);
    r.set("rd_inv", f(10).inverse().unwrap())
        .set("rd_selected", f(43))
        .set("pc_write_value", f(0));
    cases.push((
        "a padding row claiming jal and rewriting x10",
        r,
        vec!["rd_mask_rule"],
    ));

    // Addresses.
    for (q, rule) in [("rs1", "rs1_addr_rule"), ("rs2", "rs2_addr_rule")] {
        let mut r = row("bne taken");
        let addr = r.get(name(q, "addr")) + Fr::ONE;
        r.set(name(q, "addr"), addr);
        cases.push(("a register query at the wrong register", r, vec![rule]));
    }
    let mut r = row("jal forward");
    r.set("rd_addr", f(5))
        .set("rd_inv", f(5).inverse().unwrap());
    cases.push(("a link to the wrong register", r, vec!["rd_addr_rule"]));

    // Absent operands.
    let mut r = row("jal forward");
    r.set("rs1_read_value", f(5))
        .set("rs1_write_value", f(5))
        .set("cmp_gap", f(5))
        .set("eq", Fr::ZERO)
        .set("eq_inv", f(5).inverse().unwrap());
    cases.push(("a jal's absent rs1 reading 5", r, vec!["rs1_value_masked"]));
    let mut r = row("slti 5 < -1");
    r.set("rs2_read_value", f(5)).set("rs2_write_value", f(5));
    cases.push((
        "an slti's absent rs2 reading 5",
        r,
        vec!["rs2_value_masked", "cmp_rhs_rule"],
    ));

    // The right operand: the immediate on an I-type row, rs2 on the rest.
    let mut r = row("slti -5 < 2047");
    let lhs = (-5i32) as u32;
    r.set("cmp_rhs", f(2046))
        .set("cmp_gap", f(lhs.wrapping_sub(2046) as u64))
        .set("eq_inv", (f(lhs as u64) - f(2046)).inverse().unwrap());
    cases.push(("an slti comparing against imm − 1", r, vec!["cmp_rhs_rule"]));
    // The pitfall the prompt names: a branch comparing rs1 against rs2 plus
    // its displacement, every value computed from that operand refreshed.
    let mut r = row("beq not taken");
    let rhs = 1 + 8;
    let gap = INT_MIN.wrapping_sub(rhs);
    r.set("cmp_rhs", f(rhs as u64))
        .set("cmp_rhs_hi", Fr::ZERO)
        .set("cmp_gap", f(gap as u64))
        .set("cmp_gap_hi", f(gap as u64 >> 16))
        .set(
            "eq_inv",
            (f(INT_MIN as u64) - f(rhs as u64)).inverse().unwrap(),
        );
    cases.push((
        "a branch comparing against rs2 + its displacement",
        r,
        vec!["cmp_rhs_rule"],
    ));

    // The comparison.
    let mut r = row("jalr x0 (ret)");
    r.set("lt", Fr::ONE);
    cases.push(("a jalr's unread lt flipped", r, vec!["cmp_order"]));
    let mut r = row("slt 1 < INT_MIN");
    r.set("lt", Fr::ONE)
        .set("rd_selected", Fr::ONE)
        .set("rd_write_value", Fr::ONE);
    cases.push((
        "an slt answering 1 with its gap unchanged",
        r,
        vec!["cmp_order"],
    ));

    // Equality.
    let mut r = row("bne taken");
    let inv = r.get("eq_inv") + Fr::ONE;
    r.set("eq_inv", inv);
    cases.push(("a wrong inverse", r, vec!["eq_inverse"]));
    let mut r = row("slt INT_MIN < 1");
    r.set("eq", Fr::ONE).set("eq_inv", Fr::ZERO);
    cases.push((
        "an slt calling unequal operands equal",
        r,
        vec!["eq_at_nonzero"],
    ));
    let mut r = row("beq taken");
    r.set("eq", Fr::ZERO);
    cases.push((
        "a beq calling equal operands unequal",
        r,
        vec!["eq_inverse", "taken_rule"],
    ));

    // Taken.
    let mut r = row("blt(1, INT_MIN) not taken");
    let target = f(0x1_0108);
    r.set("taken", Fr::ONE)
        .set("pc_write_value", target)
        .set("next_pc_hi", f(1));
    cases.push(("a not-taken blt taking itself", r, vec!["taken_rule"]));
    let mut r = row("beq taken");
    r.set("taken", Fr::ZERO).set("pc_write_value", f(0x1_0104));
    cases.push(("a taken beq falling through", r, vec!["taken_rule"]));

    // next_pc.
    let mut r = row("slt INT_MIN < 1");
    r.set("pc_write_value", f(0x1_0108));
    cases.push(("an slt jumping four ahead", r, vec!["next_pc_rule"]));
    let mut r = row("jal forward");
    r.set("pc_write_value", f(0x1_0104));
    cases.push(("a jal falling through", r, vec!["next_pc_rule"]));
    let mut r = row("jalr wrapping");
    r.set("pc_wrap", Fr::ZERO);
    cases.push(("a jalr dropping its wrap", r, vec!["next_pc_rule"]));
    let mut r = row("jalr rs1 = rd, imm -2, bit 0 set");
    r.set("jalr_drop", Fr::ZERO);
    cases.push((
        "a jalr keeping bit 0 in the sum only",
        r,
        vec!["next_pc_rule"],
    ));
    // A wrap bit that is not a bit: with pc_wrap a field element, a jal or a
    // taken branch lands on any even pc in the word, and only the wrap's
    // booleanity refuses it.
    let mut r = row("jal forward");
    let (landing, target) = (0x1_0200u64, 0x1_01a4u64);
    let wrap = (f(target) - f(landing)) * f(TWO_32).inverse().unwrap();
    r.set("pc_write_value", f(landing))
        .set("next_pc_hi", f(landing >> 16))
        .set("pc_wrap", wrap);
    cases.push((
        "a jal landing anywhere by its wrap",
        r,
        vec!["pc_wrap_boolean"],
    ));
    // A dropped bit of −1: a jalr lands one above its sum instead of one below.
    let mut r = row("jalr rs1 = rd, imm -2, bit 0 set");
    r.set("jalr_drop", Fr::MINUS_ONE)
        .set("pc_write_value", f(0x1_01aa));
    cases.push((
        "a jalr rounding its target up",
        r,
        vec!["jalr_drop_boolean"],
    ));
    // S14's truncation target: a row of this family writing HALT_PC.
    let mut r = row("bne not taken");
    r.set("pc_write_value", Fr::ONE).set("next_pc_hi", Fr::ZERO);
    cases.push(("a branch writing HALT_PC", r, vec!["next_pc_rule"]));

    // The written value.
    let mut r = row("slt -1 < 1");
    r.set("rd_selected", f(2)).set("rd_write_value", f(2));
    cases.push(("an slt writing 2", r, vec!["rd_value_rule"]));
    let mut r = row("jal forward");
    r.set("rd_selected", f(0x1_0100))
        .set("rd_write_value", f(0x1_0100));
    cases.push(("a jal linking to itself", r, vec!["rd_value_rule"]));

    let order: Vec<&str> = a.relations.iter().map(|r| r.name.as_str()).collect();
    for (what, r, want) in cases {
        let (relations, _, _) = violated(&a, &r);
        let mut want: Vec<String> = names(&want);
        want.sort_by_key(|n| order.iter().position(|o| o == n));
        assert_eq!(relations, want, "{what}");
    }
}

/// Every booleanity gate the family adds refuses a 2: the twelve kind bits,
/// `lt`, `taken`, `jalr_drop` and `pc_wrap`. `eq` needs none — the is-zero
/// gadget leaves it `[x = 0]` times a boolean — and a 2 there is refused by
/// the gadget itself.
#[test]
fn every_booleanity_gate_refuses_a_value_of_two() {
    let a = artifact();
    for (base, column, gate) in [
        ("slt INT_MIN < 1", "lt", "cmp_lt_boolean"),
        ("beq taken", "taken", "taken_boolean"),
        ("jalr wrapping", "jalr_drop", "jalr_drop_boolean"),
        ("jalr wrapping", "pc_wrap", "pc_wrap_boolean"),
        ("beq taken", "eq", "eq_inverse"),
    ] {
        let mut r = row(base);
        r.set(column, f(2));
        let (relations, _, _) = violated(&a, &r);
        assert!(
            relations.contains(&gate.to_string()),
            "{column} = 2: {relations:?}"
        );
    }
    for k in KINDS {
        let mut r = Row::default();
        r.set(name("kind", k), f(2));
        let (relations, _, _) = violated(&a, &r);
        let gate = format!("kind_{k}_boolean");
        assert!(relations.contains(&gate), "kind_{k} = 2: {relations:?}");
    }
}

// ---------------------------------------------------------------------------
// Acceptance 2: the comparison
// ---------------------------------------------------------------------------

/// A comparison over plain columns, for evaluating the gadget's equation
/// alone: operands `M[0]` and `M[1]`, signs `W[0]` and `W[1]`, `sc` as
/// `W[2]`, `lt` `W[3]`, `gap` `W[4]`.
fn bare_comparison() -> Comparison {
    let w = |i| PolyAddress::Witness(i);
    Comparison {
        prefix: "c".into(),
        selector: PolyAddress::Memory(2),
        signed: vec![w(2)],
        lhs: PolyAddress::Memory(0),
        lhs_hi: w(5),
        lhs_sign: w(0),
        rhs: PolyAddress::Memory(1),
        rhs_hi: w(6),
        rhs_sign: w(1),
        lt: w(3),
        gap: w(4),
        gap_hi: w(7),
    }
}

/// The equation's value at `(lhs, rhs, signs, sc, lt, gap)`, through the
/// kernel over the gadget's own gate.
fn equation_at(gate: &constraints::GateDef, c: &Comparison, cells: [(PolyAddress, Fr); 7]) -> Fr {
    let values: Vec<Fr> = gate
        .operands()
        .iter()
        .map(|op| {
            cells
                .iter()
                .find(|(a, _)| a == op)
                .unwrap_or_else(|| panic!("the equation reads {op}, which {c:?} does not set"))
                .1
        })
        .collect();
    eval_gate(gate, &values, &ExternalChallenges::new())
}

/// Acceptance 2, exhaustively: at a 6-bit word, for every operand pair, signed
/// and unsigned, exactly one `(lt, gap)` with `lt` boolean and `gap` in the
/// word satisfies `constraints::gadgets::comparison_equation` — and its `lt` is
/// the ordering Rust computes — in every sign quadrant; and each `lt` has a
/// field solution outside the word, so the range bound on `gap` is what
/// leaves one.
#[test]
fn exactly_one_lt_and_gap_satisfy_the_comparison_at_a_reduced_width() {
    const BITS: u32 = 6;
    let c = bare_comparison();
    let gate = comparison_equation(&c, BITS);
    let word = 1u64 << BITS;
    let mut quadrants = BTreeSet::new();
    for sc in [0u64, 1] {
        for lhs in 0..word {
            for rhs in 0..word {
                let (ls, rs) = (lhs >> (BITS - 1), rhs >> (BITS - 1));
                let signed = |v: u64| v as i64 - ((v >> (BITS - 1)) << BITS) as i64;
                let want = match sc {
                    1 => signed(lhs) < signed(rhs),
                    _ => lhs < rhs,
                };
                let at = |lt: u64, gap: Fr| {
                    equation_at(
                        &gate,
                        &c,
                        [
                            (c.lhs, f(lhs)),
                            (c.rhs, f(rhs)),
                            (c.lhs_sign, f(ls)),
                            (c.rhs_sign, f(rs)),
                            (c.signed[0], f(sc)),
                            (c.lt, f(lt)),
                            (c.gap, gap),
                        ],
                    )
                };
                let mut solutions = Vec::new();
                for lt in [0u64, 1] {
                    for gap in 0..word {
                        if at(lt, f(gap)) == Fr::ZERO {
                            solutions.push(lt);
                        }
                    }
                    // The field solution for this lt: D + 2^w·lt, which is in
                    // the word for exactly one lt.
                    let d = f(lhs) - f(rhs) - f(word) * f(sc) * (f(ls) - f(rs));
                    assert_eq!(at(lt, d + f(word) * f(lt)), Fr::ZERO);
                }
                assert_eq!(
                    solutions,
                    vec![want as u64],
                    "lhs {lhs}, rhs {rhs}, signed {sc}"
                );
                quadrants.insert((sc, ls, rs, want));
            }
        }
    }
    // Every sign quadrant is reached, signed and unsigned, with each answer
    // the quadrant admits: both where the signs agree, and where they differ
    // the one the ordering forces — the unsigned one where lhs's top bit is
    // clear, the signed one where it is set.
    let mut want = BTreeSet::new();
    for sc in [0u64, 1] {
        for (ls, rs) in [(0, 0), (1, 1)] {
            want.insert((sc, ls, rs, false));
            want.insert((sc, ls, rs, true));
        }
        want.insert((sc, 0, 1, sc == 0));
        want.insert((sc, 1, 0, sc == 1));
    }
    assert_eq!(quadrants, want);
}

/// Acceptance 2 at full width: `BLT(0x80000000, 1)` is taken,
/// `BGE(1, 0x80000000)` is taken, `BLTU(0x80000000, 1)` is not, and a
/// mixed-sign `slt` answers 1 — each an honest row that holds, and each with
/// its answer flipped refused: through the equation when the gap is left, and
/// through the gap's range when the gap is moved to match.
#[test]
fn the_pinned_full_width_comparisons_answer_correctly() {
    let a = artifact();
    for (what, lt) in [
        ("blt(INT_MIN, 1) taken", 1),
        ("bge(1, INT_MIN) taken", 0),
        ("bltu(INT_MIN, 1) not taken", 0),
        ("slt -1 < 1", 1),
    ] {
        let honest = row(what);
        assert_eq!(small_int(honest.get("lt")), lt, "{what}");
        assert_eq!(violated(&a, &honest), (none(), none(), none()), "{what}");

        // The flipped answer, carried through to what it decides, with the
        // gap left where it was: the equation refuses it.
        let flip = |r: &mut Row| {
            let other = f(1 - lt);
            r.set("lt", other);
            match what {
                "slt -1 < 1" => {
                    r.set("rd_selected", other).set("rd_write_value", other);
                }
                _ => {
                    let taken = Fr::ONE - r.get("taken");
                    let next = if taken == Fr::ONE { 0x1_0108 } else { 0x1_0104 };
                    r.set("taken", taken)
                        .set("pc_write_value", f(next))
                        .set("next_pc_hi", f(1));
                }
            }
        };
        let mut r = honest.clone();
        flip(&mut r);
        assert_eq!(
            violated(&a, &r),
            (names(&["cmp_order"]), none(), none()),
            "{what}, flipped"
        );
        // The gap moved by 2^32 the other way, so the equation holds: the
        // gap's high halfword leaves the range.
        let gap = r.get("cmp_gap");
        let hi = r.get("cmp_gap_hi");
        match lt {
            0 => r
                .set("cmp_gap", gap + f(TWO_32))
                .set("cmp_gap_hi", hi + f(1 << 16)),
            _ => r
                .set("cmp_gap", gap - f(TWO_32))
                .set("cmp_gap_hi", hi - f(1 << 16)),
        };
        assert_eq!(
            violated(&a, &r),
            (none(), names(&["cmp_gap_hi_range"]), none()),
            "{what}, flipped with its gap"
        );
    }
}

// ---------------------------------------------------------------------------
// Acceptance 4: the SLTI defect
// ---------------------------------------------------------------------------

/// Acceptance 4. `slti x5, x6, -1` with `x6 = 5` answers 0, and `sltiu`
/// answers 1; with `x6 = -5`, both answer 1. The retired table read SLTI's
/// sign from `rs2`'s high halfword alone — 0, `rs2` being absent — and so
/// compared `5` against `0xffffffff` unsigned and answered 1. That reading
/// satisfies every gate here: only the `U16GetSign` lookup refuses its sign,
/// and the `cmp_rhs` range pair refuses its halfword.
#[test]
fn the_slti_defect_has_no_analogue() {
    let a = artifact();
    let get = |what: &str, col: &str| small_int(row(what).get(col));
    assert_eq!(get("slti 5 < -1", "rd_write_value"), 0);
    assert_eq!(get("sltiu 5 < -1", "rd_write_value"), 1);
    assert_eq!(get("slti -5 < -1", "rd_write_value"), 1);
    assert_eq!(get("slti -5 < -1", "cmp_rhs_sign"), 1);
    assert_eq!(get("slti 5 < -1", "cmp_rhs_sign"), 1);

    // The defect: the immediate's sign read as 0, so 5 < 0xffffffff.
    let mut r = row("slti 5 < -1");
    let gap = 5u32.wrapping_sub(u32::MAX);
    r.set("cmp_rhs_sign", Fr::ZERO)
        .set("lt", Fr::ONE)
        .set("cmp_gap", f(gap as u64))
        .set("cmp_gap_hi", f(gap as u64 >> 16))
        .set("rd_selected", Fr::ONE)
        .set("rd_write_value", Fr::ONE);
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["cmp_rhs_get_sign"]))
    );
    // Its other half: the sign taken from rs2's halfword, 0, and the
    // halfword with it.
    r.set("cmp_rhs_hi", Fr::ZERO);
    assert_eq!(
        violated(&a, &r),
        (none(), names(&["cmp_rhs_lo_range"]), none())
    );
}

/// Each table lookup is the lone refusal of a row that every gate and range
/// accepts: a sign the generic table does not give, on either operand, and a
/// `jal` whose claimed row is not the table's — every lookup under its own
/// selector, which a `jal`, reading no `rs1`, must not escape.
#[test]
fn each_table_lookup_is_the_one_that_refuses_its_row() {
    let a = artifact();
    // slt(-1, 1) answering 0: rs1's sign read as 0, and the gap unchanged.
    let mut r = row("slt -1 < 1");
    assert_eq!(small_int(r.get("cmp_gap")), 0xffff_fffe);
    r.set("rs1_sign", Fr::ZERO)
        .set("lt", Fr::ZERO)
        .set("rd_selected", Fr::ZERO)
        .set("rd_write_value", Fr::ZERO);
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["cmp_lhs_get_sign"]))
    );
    // slt(1, -1) answering 1: rs2's sign read as 0.
    let mut r = row("slt 1 < -1");
    assert_eq!(small_int(r.get("cmp_gap")), 2);
    r.set("cmp_rhs_sign", Fr::ZERO)
        .set("lt", Fr::ONE)
        .set("rd_selected", Fr::ONE)
        .set("rd_write_value", Fr::ONE);
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["cmp_rhs_get_sign"]))
    );
    // A jal four bytes further than its table row says.
    let mut r = row("jal forward");
    assert_eq!(small_int(r.get("decoded_imm")), 0xa4);
    r.set("decoded_imm", f(0xa8))
        .set("pc_write_value", f(0x1_01a8));
    assert_eq!(small_int(r.get("next_pc_hi")), 1);
    assert_eq!(violated(&a, &r), (none(), none(), names(&["decode_row"])));
}

// ---------------------------------------------------------------------------
// Acceptance 3 as rows: the pc, the halting sentinel and the decoder's domain
// ---------------------------------------------------------------------------

/// The halting sentinel. A `jalr` with `rs1 + imm = 2^32 + 1` jumps to 0 with
/// bit 0 dropped. Keeping the bit makes `next_pc` `HALT_PC`: every gate still
/// holds, and so does every range and table lookup but the evenness
/// obligation — which is therefore the only thing between this row and a
/// statement that ends in a clean exit where the program would crash. An odd
/// target elsewhere is refused the same way, and an unreduced jump or branch
/// target by the high halfword.
#[test]
fn only_the_evenness_obligation_refuses_a_jalr_that_fakes_an_exit() {
    let a = artifact();
    let honest = honest(instr(kind::JALR, 5, 0, 0, -2), 3, 0, 0);
    assert_eq!(violated(&a, &honest), (none(), none(), none()));
    assert_eq!(small_int(honest.get("pc_write_value")), 0);
    assert_eq!(small_int(honest.get("jalr_drop")), 1);

    let mut fake = honest.clone();
    fake.set("jalr_drop", Fr::ZERO)
        .set("pc_write_value", f(constants::memory::HALT_PC as u64));
    assert_eq!(
        violated(&a, &fake),
        (none(), names(&["next_pc_even"]), none())
    );

    let mut odd = row("jalr rs1 = rd, imm -2, bit 0 set");
    odd.set("jalr_drop", Fr::ZERO)
        .set("pc_write_value", f(0x1_01a9));
    assert_eq!(
        violated(&a, &odd),
        (none(), names(&["next_pc_even"]), none())
    );

    let mut unreduced = row("jal backward");
    let next = unreduced.get("pc_write_value") + f(TWO_32);
    let hi = unreduced.get("next_pc_hi") + f(1 << 16);
    unreduced
        .set("pc_wrap", Fr::ZERO)
        .set("pc_write_value", next)
        .set("next_pc_hi", hi);
    assert_eq!(
        violated(&a, &unreduced),
        (none(), names(&["next_pc_hi_range"]), none())
    );
    // A branch has no `rd` query, and its target is bounded all the same.
    let mut unreduced = row("bne backward -16 taken");
    assert_eq!(small_int(unreduced.get("pc_wrap")), 1);
    let next = unreduced.get("pc_write_value") + f(TWO_32);
    let hi = unreduced.get("next_pc_hi") + f(1 << 16);
    unreduced
        .set("pc_wrap", Fr::ZERO)
        .set("pc_write_value", next)
        .set("next_pc_hi", hi);
    assert_eq!(
        violated(&a, &unreduced),
        (none(), names(&["next_pc_hi_range"]), none())
    );
}

/// Acceptance 3 as rows: a backward branch of −16 lands 16 below its pc with
/// the wrap set; a `jal` links the fall-through and lands at `pc + imm`; a
/// `jalr` with `rs1 = rd` forms its target from the old `rs1` — read at slot 1,
/// before the link is written at slot 3 — with bit 0 cleared.
#[test]
fn the_control_flow_matrix_lands_where_the_isa_says() {
    let get = |what: &str, col: &str| small_int(row(what).get(col));
    let pc = 0x1_0100;
    assert_eq!(get("bne backward -16 taken", "pc_write_value"), pc - 16);
    assert_eq!(get("bne backward -16 not taken", "pc_write_value"), pc + 4);
    assert_eq!(get("beq taken", "pc_write_value"), pc + 8);
    assert_eq!(get("beq not taken", "pc_write_value"), pc + 4);
    assert_eq!(get("beq to the fall-through", "pc_write_value"), pc + 4);
    assert_eq!(get("beq to the fall-through", "taken"), 1);
    assert_eq!(get("jal forward", "pc_write_value"), pc + 0xa4);
    assert_eq!(get("jal forward", "rd_write_value"), pc + 4);
    assert_eq!(get("jal backward", "pc_write_value"), pc - 0x14);
    assert_eq!(get("jal to 2^19 ahead", "pc_write_value"), pc + 0x7fffe);
    let jalr = row("jalr rs1 = rd, imm -2, bit 0 set");
    assert_eq!(jalr.get("rs1_addr"), jalr.get("rd_addr"));
    let (old, target) = (small_int(jalr.get("rs1_read_value")), 0x1_01a8);
    assert_eq!(old + TWO_32 - 2 - 1, TWO_32 + target);
    assert_eq!(small_int(jalr.get("pc_write_value")), target);
    assert_eq!(small_int(jalr.get("rd_read_value")), old);
    assert_eq!(small_int(jalr.get("rd_write_value")), pc + 4);
}

/// The decoder table's domain on this family — S15's and S16's control: an
/// all-zero mask on a live row breaks no gate and no range, its `rd` query
/// and every operand dropped to match, so the decoder channel is the only
/// thing that refuses it.
#[test]
fn an_all_zero_mask_is_refused_by_the_decoder_domain_alone() {
    let a = artifact();
    let mut r = row("jal x0");
    r.set("decoded_mask", Fr::ZERO)
        .set("kind_jal", Fr::ZERO)
        .set("rd_selected", Fr::ZERO)
        .set("rd_hi", Fr::ZERO)
        .set("pc_write_value", f(0x1_0104))
        .set("next_pc_hi", f(1));
    for field in ["mask", "addr", "read_ts", "read_value", "write_value"] {
        r.0.remove(name("rd", field));
    }
    r.set("rd_is_zero", Fr::ZERO);
    assert_eq!(violated(&a, &r), (none(), none(), names(&["decode_row"])));
}

// ---------------------------------------------------------------------------
// Acceptance 8: padding
// ---------------------------------------------------------------------------

/// Acceptance 8. The canonical padding row — all zero — passes every
/// validator (`the_circuit_is_the_fixture_and_keeps_every_rule`) and every
/// gate; and a mask-zero row advances the pc to its claimed fall-through
/// rather than to 0: any `seq` with `next_pc = seq` holds, and `next_pc = 0`
/// beside a nonzero `seq` is refused.
#[test]
fn a_padding_row_advances_the_pc() {
    let a = artifact();
    assert_eq!(violated(&a, &Row::default()), (none(), none(), none()));
    // A padding row looks up the table's MINUS_ONE row.
    let mut padding = Row::default();
    for column in [
        "table_pc",
        "table_next_pc",
        "table_rs1",
        "table_rs2",
        "table_rd",
        "table_imm",
        "table_extra_mask",
    ] {
        padding.set(column, Fr::MINUS_ONE);
    }
    assert_eq!(violated(&a, &padding), (none(), none(), none()));
    let mut r = Row::default();
    r.set("decoded_next_pc", f(0x1_0200))
        .set("pc_write_value", f(0x1_0200));
    assert_eq!(violated(&a, &r).0, none());
    r.set("pc_write_value", Fr::ZERO);
    assert_eq!(violated(&a, &r).0, names(&["next_pc_rule"]));
}

// ---------------------------------------------------------------------------
// Acceptance 9: the legal masks
// ---------------------------------------------------------------------------

/// Acceptance 9. The legal masks are exactly the family's instructions, each
/// with `rd = x0` and without where its form has an `rd`: every one routed by
/// `program::row_kind` to this family gives one of `LEGAL_MASKS`, all twelve
/// are reached, and nothing else is. A mask set with an extra or a missing
/// entry fails here, and so does a routing change.
#[test]
fn the_legal_masks_are_the_instruction_list() {
    use Isa::*;
    let mut instructions = Vec::new();
    for rd in [0u8, 5] {
        instructions.extend([
            Slti {
                rd,
                rs1: 6,
                imm: -1,
            },
            Sltiu {
                rd,
                rs1: 6,
                imm: -1,
            },
            Slt { rd, rs1: 6, rs2: 7 },
            Sltu { rd, rs1: 6, rs2: 7 },
            Jalr {
                rd,
                rs1: 6,
                imm: -2,
            },
            Jal { rd, imm: 8 },
        ]);
    }
    instructions.extend([
        Beq {
            rs1: 6,
            rs2: 7,
            imm: 8,
        },
        Bne {
            rs1: 6,
            rs2: 7,
            imm: 8,
        },
        Blt {
            rs1: 6,
            rs2: 7,
            imm: 8,
        },
        Bge {
            rs1: 6,
            rs2: 7,
            imm: 8,
        },
        Bltu {
            rs1: 6,
            rs2: 7,
            imm: 8,
        },
        Bgeu {
            rs1: 6,
            rs2: 7,
            imm: 8,
        },
    ]);
    let mut masks = BTreeSet::new();
    for i in &instructions {
        let (family, bit) = program::row_kind(i);
        assert_eq!(family, family::JUMP_BRANCH_SLT, "{i:?}");
        masks.insert(1u32 << bit);
    }
    let legal: BTreeSet<u32> = jump_branch_slt::LEGAL_MASKS.into_iter().collect();
    assert_eq!(masks, legal);
    assert_eq!(legal.len(), 12);
    // And the circuit recomposes the packed mask from exactly those twelve
    // bits, bit k weighted 2^k.
    let a = artifact();
    let bits = a
        .relations
        .iter()
        .find(|r| r.name == "decoded_mask_bits")
        .expect("the recomposition gate");
    let mut terms: Vec<(constraints::Coeff, PolyAddress)> = jump_branch_slt::KINDS
        .iter()
        .enumerate()
        .map(|(k, b)| (constraints::Coeff::Literal(f(1 << k)), *b))
        .collect();
    terms.push((
        constraints::Coeff::Literal(Fr::MINUS_ONE),
        jump_branch_slt::DECODED[5],
    ));
    assert_eq!(
        bits.gate,
        constraints::GateDef::Linear {
            terms,
            constant: constraints::Coeff::Literal(Fr::ZERO),
        }
    );
    // The masks of the instructions the guest runs, from its decoded table.
    let elf = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../loader/tests/vectors/control.elf"
    ))
    .expect("the control guest");
    let image = loader::load_elf(&elf).expect("control loads");
    let (tables, _) =
        program::decode_program(&image, &program::ProgramParams::defaults()).expect("decodes");
    let table = tables.family(family::JUMP_BRANCH_SLT).expect("its table");
    let guest: BTreeSet<u32> = (0..table.height as usize)
        .filter_map(|r| table.get(6, r))
        .collect();
    assert_eq!(
        guest, legal,
        "the guest runs every instruction of the family"
    );
}

// ---------------------------------------------------------------------------
// The guest: acceptance 1, 3, 4 and 5 in its trace, the fill, and 6
// ---------------------------------------------------------------------------

/// `guests/control`, decoded with both of its execution families at `2^20`
/// and every other family at `2^16`, as `crates/prover/tests/common` decodes
/// it for its proof, and traced into an archive. The exit status is 16, the
/// number of checks the guest made and passed.
fn control() -> (prover::Program, trace::TraceArchive) {
    let elf = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../loader/tests/vectors/control.elf"
    ))
    .expect("the control guest");
    let image = loader::load_elf(&elf).expect("control loads");
    let (program, archive, exit_code) = traced(image, 1 << VARS);
    assert_eq!(exit_code, 16, "control passes its 16 checks");
    (program, archive)
}

/// `image` decoded with both of S17's execution families at `height` and
/// every other family at `2^16`, and traced into an archive; and the exit
/// status.
fn traced(image: loader::ProgramImage, height: u32) -> (prover::Program, trace::TraceArchive, i32) {
    let mut params = program::ProgramParams::defaults();
    params.heights = [1 << 16; family::COUNT as usize];
    params.heights[family::ADD_SUB_LUI_AUIPC as usize] = height;
    params.heights[family::JUMP_BRANCH_SLT as usize] = height;
    let (tables, config) = program::decode_program(&image, &params).expect("the image decodes");
    // Only the families S17 proves: an instruction of any other family
    // would put a family in the config that no circuit proves.
    let families: Vec<u32> = config.families.iter().map(|(f, _)| *f).collect();
    assert_eq!(
        families,
        [
            family::ADD_SUB_LUI_AUIPC,
            family::JUMP_BRANCH_SLT,
            family::INIT_TEARDOWN,
            family::ZERO_WINDOWS
        ]
    );
    let io = emulator::GuestIo {
        input: Vec::new(),
        hint: Vec::new(),
        advice: Vec::new(),
    };
    let (traces, log, profile, execution) =
        emulator::trace_run(&image, &io, &tables, &config).expect("the image traces");
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
        execution.exit_code,
    )
}

/// One executed row of the family, with its decoded fields.
struct Ran {
    bit: u32,
    pc: u32,
    /// The table's fall-through: `pc + 2` for a compressed instruction.
    seq: u32,
    next_pc: u32,
    rd: u32,
    imm: u32,
    rs1: Option<u32>,
    rs2: Option<u32>,
    link: Option<u32>,
}

fn ran(program: &prover::Program, archive: &trace::TraceArchive) -> Vec<Ran> {
    use trace::Role;
    let table = program
        .tables
        .family(family::JUMP_BRANCH_SLT)
        .expect("the family's table");
    let traces = archive.family_traces();
    let buffer = traces
        .family(family::JUMP_BRANCH_SLT)
        .expect("the family's buffer");
    (0..buffer.len())
        .map(|i| {
            let row = buffer.row(i);
            let field = |c| table.get(c, row.pc as usize / 2).expect("a live row");
            Ran {
                bit: field(6).trailing_zeros(),
                pc: row.pc,
                seq: field(1),
                next_pc: row.next_pc,
                rd: field(4),
                imm: field(5),
                rs1: row.query(Role::Rs1).map(|q| q.read_value),
                rs2: row.query(Role::Rs2).map(|q| q.read_value),
                link: row.query(Role::Rd).map(|q| q.write_value),
            }
        })
        .collect()
}

/// Acceptance 1's coverage and acceptance 3, 4 and 5, read from the trace a
/// proof is about (`crates/prover/tests/control.rs` proves it): every one of
/// the twelve instructions runs; the pinned comparisons answer as the ISA
/// says; branches are taken and not taken, forward and — at −16, closing a
/// loop — backward; `jal` links the fall-through and lands at `pc + imm`,
/// backwards too, and in its compressed form links `pc + 2`; the `jalr` whose
/// `rs1` is its `rd`, with a negative immediate and bit 0 of the sum set,
/// lands on the sum with bit 0 cleared and writes the link; `slti` and
/// `sltiu` write `x5` against −1 for a positive and a negative `rs1`; and
/// `jal`, `slt`, `sltu`, `slti` and `sltiu` each run with `rd = x0`, whose
/// every read in the whole trace is 0.
#[test]
fn the_guest_runs_the_acceptance_matrix() {
    use kind::*;
    let (program, archive) = control();
    let rows = ran(&program, &archive);
    for k in 0..12 {
        assert!(rows.iter().any(|r| r.bit == k), "no row of kind {k}");
    }
    let branch = |b: u32| matches!(b, BEQ | BNE | BLT | BGE | BLTU | BGEU);

    // The pinned comparisons.
    let int_min = Some(INT_MIN);
    assert!(
        rows.iter().any(|r| {
            r.bit == BLT
                && r.rs1 == int_min
                && r.rs2 == Some(1)
                && r.next_pc == r.pc.wrapping_add(r.imm)
        }),
        "the guest runs no {}",
        "taken BLT(0x80000000, 1)"
    );
    assert!(
        rows.iter().any(|r| {
            r.bit == BGE
                && r.rs1 == Some(1)
                && r.rs2 == int_min
                && r.next_pc == r.pc.wrapping_add(r.imm)
        }),
        "the guest runs no {}",
        "taken BGE(1, 0x80000000)"
    );
    assert!(
        rows.iter().any(|r| {
            r.bit == BLTU && r.rs1 == int_min && r.rs2 == Some(1) && r.next_pc == r.pc + 4
        }),
        "the guest runs no {}",
        "not-taken BLTU(0x80000000, 1)"
    );
    assert!(
        rows.iter().any(|r| {
            r.bit == SLT && r.rs1 == Some(u32::MAX) && r.rs2 == Some(1) && r.link == Some(1)
        }),
        "the guest runs no {}",
        "mixed-sign slt answering 1"
    );
    assert!(
        rows.iter().any(|r| {
            r.bit == SLT && r.rs1 == Some(1) && r.rs2 == Some(u32::MAX) && r.link == Some(0)
        }),
        "the guest runs no {}",
        "mixed-sign slt answering 0"
    );

    // Acceptance 3: the control-flow matrix.
    assert!(
        rows.iter()
            .any(|r| { branch(r.bit) && (r.imm as i32) > 4 && r.next_pc == r.pc + r.imm }),
        "the guest runs no {}",
        "taken forward branch"
    );
    // Not taken: the fall-through, from a branch whose target is elsewhere.
    let not_taken =
        |r: &&Ran| branch(r.bit) && r.next_pc == r.seq && r.pc.wrapping_add(r.imm) != r.seq;
    let taken = |r: &&Ran| branch(r.bit) && r.next_pc == r.pc.wrapping_add(r.imm);
    let compressed = |r: &&Ran| r.seq == r.pc + 2;
    assert!(
        rows.iter().any(|r| not_taken(&r) && !compressed(&r)),
        "the guest runs no not-taken branch"
    );
    assert!(
        rows.iter().any(|r| not_taken(&r) && compressed(&r)),
        "the guest runs no not-taken compressed branch"
    );
    assert!(
        rows.iter().any(|r| taken(&r) && compressed(&r)),
        "the guest runs no taken compressed branch"
    );
    assert!(
        rows.iter()
            .any(|r| taken(&r) && r.imm == 4 && r.next_pc == r.seq),
        "the guest runs no branch taken to its own fall-through"
    );
    assert!(
        rows.iter()
            .any(|r| r.bit == JAL && r.rd == 0 && compressed(&r)),
        "the guest runs no c.j"
    );
    assert!(
        rows.iter()
            .any(|r| r.bit == JALR && r.rd == 0 && compressed(&r)),
        "the guest runs no c.jr"
    );
    let loop_rows: Vec<&Ran> = rows
        .iter()
        .filter(|r| r.bit == BNE && r.imm == (-16i32) as u32)
        .collect();
    assert_eq!(loop_rows.len(), 5, "the loop's back edge runs five times");
    assert!(loop_rows[..4].iter().all(|r| r.next_pc == r.pc - 16));
    assert_eq!(loop_rows[4].next_pc, loop_rows[4].pc + 4);
    assert!(
        rows.iter().any(|r| {
            r.bit == JAL
                && r.rd == 1
                && (r.imm as i32) > 0
                && r.link == Some(r.pc + 4)
                && r.next_pc == r.pc + r.imm
        }),
        "the guest runs no {}",
        "jal linking and landing forward"
    );
    assert!(
        rows.iter().any(|r| {
            r.bit == JAL && (r.imm as i32) < 0 && r.next_pc == r.pc.wrapping_add(r.imm)
        }),
        "the guest runs no {}",
        "jal landing backward"
    );
    assert!(
        rows.iter()
            .any(|r| { r.bit == JAL && r.rd == 1 && r.link == Some(r.pc + 2) }),
        "the guest runs no {}",
        "c.jal linking pc + 2"
    );
    assert!(
        rows.iter()
            .any(|r| { r.bit == JALR && r.rd == 1 && r.link == Some(r.pc + 2) }),
        "the guest runs no {}",
        "c.jalr linking pc + 2"
    );
    let jalr: Vec<&Ran> = rows
        .iter()
        .filter(|r| r.bit == JALR && r.rd != 0 && r.rs1.is_some() && (r.imm as i32) < 0)
        .collect();
    assert_eq!(
        jalr.len(),
        1,
        "one jalr with rd = rs1 and a negative immediate"
    );
    let j = jalr[0];
    let sum = j.rs1.unwrap().wrapping_add(j.imm);
    assert_eq!(sum & 1, 1, "bit 0 of rs1 + imm is set");
    assert_eq!(
        j.next_pc,
        sum & !1,
        "the target is the old rs1's sum, bit 0 cleared"
    );
    assert_eq!(j.link, Some(j.pc + 4), "the link is written after");
    let table = program.tables.family(family::JUMP_BRANCH_SLT).unwrap();
    assert_eq!(table.get(2, j.pc as usize / 2), Some(j.rd), "rs1 is rd");

    // Acceptance 4: x5 against -1.
    let minus_one = u32::MAX;
    for (bit, rs1, answer) in [
        (SLTI, 5, 0),
        (SLTI, (-5i32) as u32, 1),
        (SLTIU, 5, 1),
        (SLTIU, (-5i32) as u32, 1),
    ] {
        assert!(
            rows.iter().any(|r| {
                r.bit == bit
                    && r.rd == 5
                    && r.imm == minus_one
                    && r.rs1 == Some(rs1)
                    && r.link == Some(answer)
            }),
            "the guest runs no {}",
            "slti/sltiu x5 against -1"
        );
    }

    // Acceptance 5: rd = x0, each comparison's operands making it compute 1
    // — 0 < 1 — so the x0 rule masks a nonzero value, and x0 still reads 0.
    assert!(
        rows.iter()
            .any(|r| r.bit == JAL && r.rd == 0 && r.link == Some(0)),
        "the guest runs no jal x0"
    );
    for bit in [SLT, SLTU] {
        assert!(
            rows.iter().any(|r| r.bit == bit
                && r.rd == 0
                && r.rs1 == Some(0)
                && r.rs2 == Some(1)
                && r.link == Some(0)),
            "the guest runs no comparison of kind {bit} computing 1 into x0"
        );
    }
    for bit in [SLTI, SLTIU] {
        assert!(
            rows.iter().any(|r| r.bit == bit
                && r.rd == 0
                && r.rs1 == Some(0)
                && r.imm == 1
                && r.link == Some(0)),
            "the guest runs no comparison of kind {bit} computing 1 into x0"
        );
    }
    for e in archive.memory_log().events() {
        if e.space == trace::AddressSpace::Reg && e.addr == 0 {
            assert_eq!(
                (e.read_value, e.write_value),
                (0, 0),
                "x0 at cycle {}",
                e.cycle()
            );
        }
    }
}

/// Acceptance 6, the honest prover's half, in ordinary CI. `control`'s `jalr
/// t2, -2(t2)` re-run on an `rs1` two higher lands two bytes into the 32-bit
/// `sltiu` it jumps to — a pc whose row is `MINUS_ONE` in every family's table
/// — and the next row is moved there with it, every gate still holding. The
/// decoder channel cannot be counted over that shard, and the refusal names
/// the channel; the honest columns count. The proof the harness makes anyway is
/// refused as `Lookup { DECODER }` (`crates/checker/tests/tamper.rs`).
#[test]
fn a_jump_to_a_pc_holding_no_instruction_cannot_be_counted() {
    let (program, archive) = control();
    let a = artifact();
    let fill = prover::family_fill(family::JUMP_BRANCH_SLT).expect("the family's fill");
    let source = prover::ShardSource {
        program: &program,
        archive: &archive,
        family: family::JUMP_BRANCH_SLT,
        index: 0,
        height: 1 << VARS,
        window: 0,
    };
    let mut columns = fill(&source).expect("the fill");
    let decoder: Vec<ChannelSpec> = jump_branch_slt::channels()
        .into_iter()
        .filter(|spec| spec.channel == lookup_channel::DECODER)
        .collect();
    assert!(trace::build_multiplicities(&a, &columns, &decoder).is_ok());

    let rows = ran(&program, &archive);
    let r = rows
        .iter()
        .position(|r| r.bit == kind::JALR && r.rd != 0 && (r.imm as i32) < 0)
        .expect("the jalr");
    let (v, next) = (rows[r].rs1.expect("its rs1") as u64, rows[r].next_pc as u64);
    assert_eq!(
        rows[r + 1].pc as u64,
        next,
        "it lands on this family's next row"
    );
    for t in &program.tables.families {
        assert!(
            !t.is_live(next as usize / 2 + 1),
            "pc {:#x} holds no instruction",
            next + 2
        );
    }
    let frame = constraints::memory::frame;
    use constraints::memory::{FIELD_READ_VALUE, FIELD_WRITE_VALUE};
    let moved = v + 2;
    let cells = [
        (frame(1, FIELD_READ_VALUE), r, f(moved)),
        (frame(1, FIELD_WRITE_VALUE), r, f(moved)),
        (frame(3, FIELD_READ_VALUE), r, f(moved)),
        (frame(0, FIELD_WRITE_VALUE), r, f(next + 2)),
        (jump_branch_slt::EQ_INV, r, f(moved).inverse().unwrap()),
        (jump_branch_slt::CMP_GAP, r, f(moved)),
        (frame(0, FIELD_READ_VALUE), r + 1, f(next + 2)),
    ];
    for (address, row, value) in cells {
        let column = &mut columns
            .iter_mut()
            .find(|(c, _)| *c == address)
            .expect("a filled column")
            .1;
        let mut values: Vec<Fr> = (0..column.len()).map(|i| column.get(i)).collect();
        values[row] = value;
        *column = poly::MultilinearPoly::new(poly::PolyBacking::Fr(values));
    }
    let refusal = trace::build_multiplicities(&a, &columns, &decoder)
        .expect_err("a live row at a pc no table holds cannot be counted");
    assert!(refusal.contains("channel `decoder`"), "{refusal}");
    // Every other channel still counts: the tamper breaks the fetch alone.
    let others: Vec<ChannelSpec> = jump_branch_slt::channels()
        .into_iter()
        .filter(|spec| spec.channel != lookup_channel::DECODER)
        .collect();
    assert!(trace::build_multiplicities(&a, &columns, &others).is_ok());
}

/// The prover's own fill of the family's shard, `prover::family_fill`, over the
/// guest's real trace: every channel's multiplicities count — so every gated
/// tuple of the shard is a row of its table — and every live row, and the
/// padding rows after them, satisfy every gate and every range obligation.
/// The fill and the circuit agree, in ordinary CI, without a proof.
#[test]
fn the_fill_satisfies_every_gate_and_every_table() {
    let (program, archive) = control();
    let live = ran(&program, &archive).len();
    let columns = filled(&program, &archive, 0, VARS, true);
    let rows: Vec<usize> = (0..live + 2).chain([(1 << VARS) - 1]).collect();
    assert_rows_hold(&columns, &rows);
}

/// The family's fill of shard `index` at `2^vars` rows — its setup columns
/// held to the program's decoded table and the packed generic table row for
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
    let fill = prover::family_fill(family::JUMP_BRANCH_SLT).expect("the family's fill");
    let source = prover::ShardSource {
        program,
        archive,
        family: family::JUMP_BRANCH_SLT,
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
    // The setup columns are the tables the key's commitments are of.
    let table = program
        .tables
        .family(family::JUMP_BRANCH_SLT)
        .expect("the family's table");
    let generic = program::lookup_tables::generic_table(vars);
    for j in 0..jump_branch_slt::TABLE_WIDTH + generic_table::WIDTH {
        let filled = column(&columns, PolyAddress::Setup(j as u32));
        let want = match j.checked_sub(jump_branch_slt::TABLE_WIDTH) {
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
        let counts = trace::build_multiplicities(&a, &columns, &jump_branch_slt::channels())
            .expect("every tuple of the shard is a row of its table");
        columns.extend(counts);
    } else {
        for m in jump_branch_slt::MULTIPLICITIES {
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

// Three instruction formats, for the programs below built by hand; each word
// is read back through `isa::decode` where it is used.

fn i_word(opcode: u32, rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (rd << 7) | opcode
}

fn b_word(funct3: u32, rs1: u32, rs2: u32, imm: i32) -> u32 {
    let i = imm as u32;
    ((i >> 12 & 1) << 31)
        | ((i >> 5 & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | ((i >> 1 & 0xf) << 8)
        | ((i >> 11 & 1) << 7)
        | 0x63
}

fn j_word(rd: u32, imm: i32) -> u32 {
    let i = imm as u32;
    ((i >> 20 & 1) << 31)
        | ((i >> 1 & 0x3ff) << 21)
        | ((i >> 11 & 1) << 20)
        | ((i >> 12 & 0xff) << 12)
        | (rd << 7)
        | 0x6f
}

const ADDI: u32 = 0x13;
const JALR: u32 = 0x67;
const LUI: u32 = 0x37;
const BNE: u32 = 1;
const NOP: u32 = 0x13;
const ECALL: u32 = 0x73;

/// A one-segment image of 32-bit `words` at `at`, entered there, each word
/// the mnemonic named beside it.
fn image_of(at: u32, words: &[(u32, &str)]) -> loader::ProgramImage {
    let mut slots = Vec::new();
    for (word, mnemonic) in words {
        assert_eq!(
            isa::decode(*word).expect("the word decodes").mnemonic(),
            *mnemonic
        );
        slots.push(loader::Slot::Instruction {
            word: *word,
            compressed: false,
        });
        slots.push(loader::Slot::MidInstruction);
    }
    let bytes: Vec<u8> = words.iter().flat_map(|(w, _)| w.to_le_bytes()).collect();
    loader::ProgramImage {
        entry: at,
        segments: vec![loader::Segment {
            vaddr: at,
            mem_len: bytes.len() as u32,
            bytes,
        }],
        slot_base: at,
        slots,
    }
}

/// A taken branch, a `jal` and a `jalr`, each landing in another `2^16`-byte
/// page than its fall-through — which no committed guest does, `control`'s
/// code lying in one page — fill and hold: `next_pc`'s high halfword is the
/// target's, not the fall-through's.
#[test]
fn jumps_across_a_halfword_page_fill_and_hold() {
    let image = image_of(
        0x1_fff0,
        &[
            (i_word(ADDI, 5, 0, 1), "addi"),   // 0x1fff0  t0 = 1
            (b_word(BNE, 5, 0, 16), "bne"),    // 0x1fff4  taken: 0x20004
            (i_word(JALR, 0, 1, 4), "jalr"),   // 0x1fff8  to ra + 4 = 0x2000c
            (NOP, "addi"),                     // 0x1fffc
            (NOP, "addi"),                     // 0x20000
            (j_word(1, -12), "jal"),           // 0x20004  to 0x1fff8, ra = 0x20008
            (NOP, "addi"),                     // 0x20008
            (i_word(ADDI, 17, 0, 93), "addi"), // 0x2000c  a7 = exit
            (ECALL, "ecall"),                  // 0x20010
        ],
    );
    let (program, archive, exit_code) = traced(image, 1 << VARS);
    assert_eq!(exit_code, 0);
    let rows = ran(&program, &archive);
    let steps: Vec<(u32, u32, u32)> = rows.iter().map(|r| (r.pc, r.seq, r.next_pc)).collect();
    assert_eq!(
        steps,
        [
            (0x1_fff4, 0x1_fff8, 0x2_0004),
            (0x2_0004, 0x2_0008, 0x1_fff8),
            (0x1_fff8, 0x1_fffc, 0x2_000c),
        ]
    );
    let columns = filled(&program, &archive, 0, VARS, true);
    assert_rows_hold(&columns, &[0, 1, 2, 3]);
}

/// A family buffer longer than its height fills one shard at a time: shard 0
/// its first `2^18` cycles and shard 1 the rest, each holding every gate. A
/// branch loops `2^18 + 5` times. At `2^18` there is no timestamp table to
/// count against, so the rows are checked and the counts are not.
#[test]
fn a_second_shard_fills_the_cycles_after_the_first() {
    const LOG: u32 = 18;
    let h = 1usize << LOG;
    let image = image_of(
        0x1_0000,
        &[
            ((0x40 << 12) | (5 << 7) | LUI, "lui"), // t0 = 2^18
            (i_word(ADDI, 5, 5, 5), "addi"),        // t0 = 2^18 + 5
            (i_word(ADDI, 5, 5, -1), "addi"),       // loop: t0 -= 1
            (b_word(BNE, 5, 0, -4), "bne"),         // until t0 = 0
            (i_word(ADDI, 17, 0, 93), "addi"),
            (ECALL, "ecall"),
        ],
    );
    let (program, archive, exit_code) = traced(image, 1 << LOG);
    assert_eq!(exit_code, 0);
    let traces = archive.family_traces();
    let buffer = traces
        .family(family::JUMP_BRANCH_SLT)
        .expect("the family's buffer");
    assert_eq!(buffer.len(), h + 5);
    let cycles = |columns: &[(PolyAddress, poly::MultilinearPoly)]| {
        let c = &columns
            .iter()
            .find(|(c, _)| *c == constraints::memory::CYCLE)
            .expect("the cycle column")
            .1;
        (0..h).map(|i| c.get(i)).collect::<Vec<Fr>>()
    };

    let first = filled(&program, &archive, 0, LOG, false);
    let want: Vec<Fr> = buffer.cycle[..h].iter().map(|c| f(*c)).collect();
    assert_eq!(cycles(&first), want);
    assert_rows_hold(&first, &[0, 1, h - 1]);

    let second = filled(&program, &archive, 1, LOG, false);
    let mut want: Vec<Fr> = buffer.cycle[h..].iter().map(|c| f(*c)).collect();
    want.resize(h, Fr::ZERO);
    assert_eq!(cycles(&second), want);
    assert_rows_hold(&second, &[0, 1, 4, 5, 6, h - 1]);
}

/// `program` with the instruction at `pc` rewritten by `edit` and its tables
/// decoded again: a program `archive` was not traced from.
fn retabled(program: &prover::Program, pc: u32, edit: fn(u32) -> u32) -> prover::Program {
    let mut image = program.image.clone();
    let slot = ((pc - image.slot_base) / 2) as usize;
    let loader::Slot::Instruction { word, compressed } = image.slots[slot] else {
        panic!("pc {pc:#x} holds no instruction");
    };
    assert!(!compressed, "the edit is to a 32-bit instruction");
    image.slots[slot] = loader::Slot::Instruction {
        word: edit(word),
        compressed,
    };
    let segment = image
        .segments
        .iter_mut()
        .find(|s| s.vaddr <= pc && pc + 4 <= s.vaddr + s.bytes.len() as u32)
        .expect("the instruction's bytes");
    let at = (pc - segment.vaddr) as usize;
    segment.bytes[at..at + 4].copy_from_slice(&edit(word).to_le_bytes());
    let mut params = program::ProgramParams::defaults();
    for (f, height) in &program.config.families {
        params.heights[*f as usize] = *height;
    }
    let (tables, config) = program::decode_program(&image, &params).expect("the edit decodes");
    assert_eq!(config, program.config);
    prover::Program {
        image,
        tables,
        config,
    }
}

/// The fill refuses a trace whose `next_pc` is not what the decoded row
/// computes, which the emulator cannot produce and the archive cannot tell:
/// `control`'s trace filled against a table whose first `jal` jumps four
/// bytes further.
#[test]
#[should_panic(expected = "the trace's next_pc is not the family's")]
fn the_fill_refuses_a_next_pc_the_row_does_not_compute() {
    let (program, archive) = control();
    let jal = ran(&program, &archive)
        .into_iter()
        .find(|r| r.bit == kind::JAL && r.seq == r.pc + 4)
        .expect("a 32-bit jal");
    let other = retabled(&program, jal.pc, |word| {
        let isa::Instr::Jal { rd, imm } = isa::decode(word).expect("a jal") else {
            panic!("not a jal");
        };
        j_word(rd as u32, imm + 4)
    });
    filled(&other, &archive, 0, VARS, true);
}

/// And an `rd` write that is not what the row computes: the `slt` that finds
/// `-1 < 1`, read as the `sltu` that does not.
#[test]
#[should_panic(expected = "the trace's rd write is not what the instruction computes")]
fn the_fill_refuses_an_rd_write_the_row_does_not_compute() {
    let (program, archive) = control();
    let slt = ran(&program, &archive)
        .into_iter()
        .find(|r| r.bit == kind::SLT && r.rs1 == Some(u32::MAX) && r.rs2 == Some(1))
        .expect("slt -1, 1");
    let other = retabled(&program, slt.pc, |word| {
        let sltu = word | 1 << 12;
        assert_eq!(isa::decode(sltu).expect("an sltu").mnemonic(), "sltu");
        sltu
    });
    filled(&other, &archive, 0, VARS, true);
}
