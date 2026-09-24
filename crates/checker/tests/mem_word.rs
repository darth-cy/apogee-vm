//! S19's `MEM_WORD` circuit (`docs/spec/memory-ops.md`), row by row, in
//! ordinary CI.
//!
//! No forward pass over `2^20` rows: each row is built by hand from what the
//! instruction computes — Rust's own `u32` arithmetic, not the circuit's — and
//! evaluated alone through `checker::violated_relations` and
//! `violated_lookups`, its row-local scratch computed by `gkr::gate_values`.
//! The one table channel, which `violated_lookups` does not read, is held here
//! to the table itself: a row's gated decoder tuple to the table columns the
//! row carries. There is no generic channel — this family looks nothing up in
//! the packed table — so its setup columns are the decoded table alone.
//!
//! The family is two instructions and one idea. `lw` and `sw` name a word by
//! `rs1 + imm`, and the whole of the addressing is the prompt's must-be-exact
//! 1: `addr = 4·word_index` is an alignment statement over the integers and
//! **nothing at all over `Fr`**, where 4 is a unit. What makes the split
//! genuinely base-4 is the bound on `word_index`, and
//! [`a_misaligned_word_access_is_unprovable`] and
//! [`a_word_index_above_2_to_the_30_is_refused`] are the two halves of that
//! claim as rows. The fill of the same circuit over `guests/mem`'s real trace
//! is `crates/checker/tests/mem_fill.rs`'.

use std::collections::BTreeMap;

use checker::{
    check_laws, check_lookup_discharge, check_padding, check_padding_identity, violated_lookups,
    violated_relations, WitnessRow,
};
use constants::extra_mask::mem_word as kind;
use constants::{address_space, challenge_slot, family, lookup_channel};
use constraints::lookup::{check_discharge, ChannelSpec};
use constraints::memory::check_memory;
use constraints::{family_circuit, mem_word, CircuitArtifact, GateDef, PolyAddress, VirtualKind};
use field::Fr;
use gkr::{eval_gate, gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use test_support::{sha256, to_hex};

const VARS: u32 = 20;
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/mem_word.bin"
);
const FIXTURE_SHA256: &str = "887d979fa6d46d77e7b83a1e346fe1267204df9cb4fb60fcbc4e28c3ad911fc9";

/// The cycle every hand-built row runs at, and the row it is evaluated at.
const CYCLE: u64 = 7;
const AT_ROW: usize = 1 << 15;

/// The `lw` row most of the forgeries below start from: `x5` holds
/// `0x0002_0000`, the displacement is 4, and the word at `0x0002_0004` is read
/// into `x7`.
const LW_RS1V: u32 = 0x0002_0000;
const LW_IMM: u32 = 4;
const LW_ADDR: u32 = LW_RS1V + LW_IMM;
const LW_WORD: u32 = 0xDEAD_BEEF;
const LW_RD_OLD: u32 = 0x1111_1111;

/// The `sw` row: `x6` into the word at `0x0002_0008`, which held
/// `0x1234_5678`.
const SW_RS1V: u32 = 0x0002_0000;
const SW_IMM: u32 = 8;
const SW_ADDR: u32 = SW_RS1V + SW_IMM;
const SW_WORD: u32 = 0x1234_5678;
const SW_RS2V: u32 = 0xCAFE_BABE;

fn artifact() -> CircuitArtifact {
    mem_word::artifact(VARS)
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
#[derive(Clone, Copy, Debug)]
struct Instr {
    bit: u32,
    pc: u32,
    rs1: u32,
    /// The store's source register; 0 on a load, which the decoded table also
    /// leaves at 0.
    rs2: u32,
    /// The load's destination; 0 on a store.
    rd: u32,
    /// The decoded immediate, sign-extended into a `u32` as S11's table holds
    /// it.
    imm: u32,
    compressed: bool,
}

impl Instr {
    fn lw(imm: u32) -> Instr {
        Instr {
            bit: kind::LW,
            pc: 0x1000,
            rs1: 5,
            rs2: 0,
            rd: 7,
            imm,
            compressed: false,
        }
    }

    fn sw(imm: u32) -> Instr {
        Instr {
            bit: kind::SW,
            pc: 0x1000,
            rs1: 5,
            rs2: 6,
            rd: 0,
            imm,
            compressed: false,
        }
    }
}

fn mnemonic(bit: u32) -> &'static str {
    ["lw", "sw"][bit as usize]
}

/// An honest row: every column what the instruction computes, by Rust's own
/// `u32` arithmetic. `word` is the word at the effective address — what a load
/// reads, what a store overwrites — and `rd_old` the destination's previous
/// value.
fn honest(i: Instr, rs1v: u32, rs2v: u32, word: u32, rd_old: u32) -> Row {
    let is_load = i.bit == kind::LW;
    // The effective address, and the carry the circuit witnesses as `wrap`.
    let sum = rs1v as u64 + i.imm as u64;
    let (address, wrap) = (sum as u32, (sum >> 32) as u32);
    assert_eq!(address % 4, 0, "an honest word access is word-aligned");
    let word_index = address / 4;
    // A load copies the word into `rd`; a store writes no register at all, so
    // the x0 gadget's selected value is 0 there.
    let sel = match is_load {
        true => word,
        false => 0,
    };
    let seq = i.pc + if i.compressed { 2 } else { 4 };

    let mut r = Row::default();
    r.set("cycle", f(CYCLE));
    r.set("pc_mask", Fr::ONE)
        .set("pc_read_ts", f(4 * (CYCLE - 1)))
        .set("pc_read_value", f(i.pc as u64))
        .set("pc_write_value", f(seq as u64));
    r.query("rs1", 1, i.rs1 as u64, rs1v as u64, rs1v as u64);
    if is_load {
        // The word at slot 2, read and written back, and the register at slot
        // 3, which an `x0` destination leaves at 0.
        r.query("load", 2, address as u64, word as u64, word as u64);
        let write = match i.rd {
            0 => 0,
            _ => sel,
        };
        r.query("rd", 3, i.rd as u64, rd_old as u64, write as u64);
        match i.rd {
            0 => r.set("rd_is_zero", Fr::ONE),
            d => r.set("rd_inv", f(d as u64).inverse().expect("nonzero")),
        };
    } else {
        r.query("rs2", 2, i.rs2 as u64, rs2v as u64, rs2v as u64);
        r.query("ram", 3, address as u64, word as u64, rs2v as u64);
    }
    r.set("rd_selected", f(sel as u64));

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

    for (column, v) in [
        ("wrap", wrap as u64),
        ("word_index", word_index as u64),
        ("word_index_hi", (word_index >> 16) as u64),
        ("rd_hi", (sel >> 16) as u64),
        // The advice bit is the address's bit 31, which is bit 13 of
        // `word_index_hi`, and the rest is what is left (`docs/spec/advice.md`
        // §3.1). Derived rather than assumed zero: since S25b the top half of
        // the address space is the advice region, so a row up there is an
        // advice load and says so.
        ("is_advice", (word_index >> 16 >> 13) as u64),
        (
            "word_index_hi_rest",
            ((word_index >> 16) & ((1 << 13) - 1)) as u64,
        ),
        // A load names its space through `load_space`; a store makes no load,
        // so the column is 0 there.
        (
            "load_space",
            if i.bit == kind::LW {
                if word_index >> 16 >> 13 == 1 {
                    address_space::ADVICE as u64
                } else {
                    address_space::RAM as u64
                }
            } else {
                0
            },
        ),
    ] {
        r.set(column, f(v));
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

/// The names of the **table**-channel lookups the row violates — the one
/// channel `violated_lookups` does not read. The lookup is read under its own
/// selector: a selector moved to another column is a different circuit, and
/// this is what sees it. The gating is `docs/spec/lookup.md` §4's decoder
/// convention, re-derived here rather than read off the circuit.
fn violated_tables(a: &CircuitArtifact, r: &Row) -> Vec<String> {
    let committed = r.committed(a);
    let layout = a.committed();
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
            lookup_channel::DECODER => {
                let table: Vec<Fr> = (0..mem_word::TABLE_WIDTH)
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
    let bytes = std::fs::read(FIXTURE).expect("the mem_word fixture");
    assert_eq!(to_hex(&sha256(&bytes)), FIXTURE_SHA256);
    assert_eq!(mem_word::artifact(22).to_bytes(), bytes);
    assert_eq!(
        CircuitArtifact::from_bytes(&bytes).expect("the fixture decodes"),
        mem_word::artifact(22)
    );

    let a = artifact();
    a.validate().expect("the circuit is lawful");
    check_laws(&a).expect("the checker's validators agree");
    check_padding(&a).expect("the padding contract");
    check_padding_identity(&a).expect("the padding identity");
    check_memory(&a).expect("the memory rules");
    let channels = mem_word::channels();
    check_discharge(&a, &channels).expect("every obligation is discharged once");
    check_lookup_discharge(&a, &channels).expect("the checker's discharge agrees");
}

/// The registry holds the family at 19 variables and up and nowhere below, and
/// what it returns is this constructor's.
#[test]
fn the_registry_holds_the_family() {
    let c = family_circuit(family::MEM_WORD, VARS).expect("the family at 2^20");
    assert_eq!(c.family, family::MEM_WORD);
    assert_eq!(c.artifact, artifact());
    assert_eq!(c.channels, mem_word::channels());
    assert!(
        !c.reads_generic_table(),
        "a word access takes the whole word: there is nothing to splice and no packed table to read"
    );
    assert_eq!(family_circuit(family::MEM_WORD, 18), None);
    let at_19 = family_circuit(family::MEM_WORD, 19).expect("the family at 2^19");
    assert_eq!(at_19.artifact, mem_word::artifact(19));
}

/// The layout and the gates are `docs/spec/memory-ops.md` §2 and §3, by name
/// and in order. The lists are literal because only a literal list catches a
/// silent reordering: a column's position is what the fill writes to and what
/// a verifying key commits, and a lookup's position is what `beta`'s derived
/// powers weight.
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
            // The load's address space, per row: `RAM` or `ADVICE` by the
            // address, and 0 on a row that makes no load. A leaf may read no
            // `W` column, so the bit crosses into it through this `M` one
            // (`docs/spec/advice.md` §3.2).
            "load_space",
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
            "kind_lw",
            "kind_sw",
            "wrap",
            "word_index",
            "word_index_hi",
            "rd_hi",
            "is_advice",
            "word_index_hi_rest",
            "mult_timestamp",
            "mult_range16",
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
        ])
    );
    // 32 memory, 26 witness, 7 setup: the document's 65 committed columns, and
    // the narrowest of the execution families — a word access has no splice.
    // S25b added three: `load_space`, which the load's leaf reads, and the
    // two the advice selector is split into (`docs/spec/advice.md` §3).
    assert_eq!(a.memory.len(), 32);
    assert_eq!(a.witness.len(), 26);
    assert_eq!(a.setup.len(), mem_word::TABLE_WIDTH);
    assert_eq!(a.committed().len(), 65);
    assert_eq!(
        a.virtuals,
        vec![
            (VirtualKind::Range19, "range19".to_string()),
            (VirtualKind::Range16, "range16".to_string()),
        ]
    );

    // The thirty-three enforcing gates: the frame's thirteen — six mask
    // booleanities, three write-backs for the three read-only queries, and the
    // four x0 gates — then this family's twenty.
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
            "kind_lw_boolean",
            "kind_sw_boolean",
            "decoded_mask_bits",
            "wrap_boolean",
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
            "advice_split",
            "is_advice_boolean",
            "load_space_rule",
            "no_store_to_advice",
            "rs1_value_masked",
            "rs2_value_masked",
            "addr_split",
            "rd_value_rule",
            "store_value_rule",
            "next_pc_rule",
        ])
    );
    assert_eq!(enforcing.len(), 37);

    // The eighteen obligations, each with the channel it is read on and the
    // selector it is read under. Every gap is read under its own query's mask;
    // everything else under the row's pc mask, this family having no half
    // flag to gate anything by.
    let m = PolyAddress::Memory;
    let (timestamp, range, decoder) = (
        lookup_channel::TIMESTAMP,
        lookup_channel::RANGE16,
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
            // The three that cap `word_index` at `2^30 − 1`: the 16+16 pair,
            // then the scaled one, which is the whole of the alignment
            // argument (`docs/spec/memory-ops.md` §2).
            ("word_index_hi_range", range, m(1)),
            ("word_index_lo_range", range, m(1)),
            ("word_index_hi_rest_range", range, m(1)),
            ("word_index_hi_rest_scaled", range, m(1)),
            // The written register value, which is a copy of a word read from
            // memory and bounded here all the same.
            ("rd_hi_range", range, m(1)),
            ("rd_lo_range", range, m(1)),
            ("decode_row", decoder, m(1)),
        ]
    );
    assert_eq!(lookups.len(), 19);
    // The per-channel counts the constructor asserts when it builds the
    // circuit; here they are read off the artifact instead.
    for (channel, want) in [(timestamp, 12), (range, 6), (decoder, 1)] {
        let got = a.lookups.iter().filter(|l| l.channel == channel).count();
        assert_eq!(got, want, "channel {channel}");
    }
    assert!(
        !a.lookups
            .iter()
            .any(|l| l.channel == lookup_channel::GENERIC),
        "this family has no generic obligation"
    );

    // The three channels in output order: the two range tables, then the
    // decoded table at `S[0..7]`. No generic channel, so the decoder's table
    // is the whole of the setup subtree.
    let w = PolyAddress::Witness;
    assert_eq!(
        mem_word::channels(),
        vec![
            ChannelSpec {
                channel: timestamp,
                table: vec![PolyAddress::Virtual(VirtualKind::Range19)],
                multiplicity: w(23),
            },
            ChannelSpec {
                channel: range,
                table: vec![PolyAddress::Virtual(VirtualKind::Range16)],
                multiplicity: w(24),
            },
            ChannelSpec {
                channel: decoder,
                table: (0..7).map(PolyAddress::Setup).collect(),
                multiplicity: w(25),
            },
        ]
    );
    assert_eq!(mem_word::MULTIPLICITIES, [w(23), w(24), w(25)]);

    // The leaves: eight product-tree leaves a side — six queries padded to
    // eight with leaves that are literally 1 — then one `(num, den)` pair per
    // fraction, each channel's tree padded to a power of two:
    // 16 + 2·(16 + 8 + 2) = 68.
    assert_eq!(a.layers[0].width, 68);
    assert_eq!(a.outputs.len(), 2 + 2 * 3);
    // The leaves, four row-wise levels and one halving level per variable.
    assert_eq!(a.depth(), 1 + 4 + VARS as usize);
}

/// The legal masks are the two instructions, and nothing else: every row kind
/// `program::row_kind` routes here, with and without `rd = x0`, gives one of
/// them.
#[test]
fn the_legal_masks_are_the_instruction_list() {
    assert_eq!(mem_word::LEGAL_MASKS, [1, 2]);
    let mut seen: Vec<u32> = Vec::new();
    for (bit, instr) in instruction_corpus() {
        let (fam, k) = program::row_kind(&instr);
        assert_eq!(fam, family::MEM_WORD, "{instr:?}");
        assert_eq!(k, bit, "{instr:?}");
        if !seen.contains(&(1 << k)) {
            seen.push(1 << k);
        }
    }
    seen.sort_unstable();
    let mut legal = mem_word::LEGAL_MASKS.to_vec();
    legal.sort_unstable();
    assert_eq!(seen, legal);
    assert_eq!(seen.len(), 2, "lw and sw, and no third instruction");
}

/// Every instruction of the family, as `crates/isa` models it, with `rd = x0`
/// and with a real destination, and at a negative displacement.
fn instruction_corpus() -> Vec<(u32, isa::Instr)> {
    use isa::Instr::*;
    let mut out = Vec::new();
    for imm in [4i32, -16] {
        for rd in [0u8, 7] {
            out.push((kind::LW, Lw { rd, rs1: 5, imm }));
        }
        out.push((
            kind::SW,
            Sw {
                rs1: 5,
                rs2: 6,
                imm,
            },
        ));
        out.push((
            kind::SW,
            Sw {
                rs1: 5,
                rs2: 0,
                imm,
            },
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// Honest rows
// ---------------------------------------------------------------------------

/// The catalogue of honest rows: both instructions, the `x0` shapes, a
/// compressed load, the two ends of the address space the split admits, a
/// wrapping effective address, a negative displacement, and the all-zero
/// padding row.
///
/// Which addresses a guest may *touch* is the memory argument's business — the
/// window list of `docs/spec/memory.md` §3 — and none of this circuit's, so a
/// row here is judged only on the addressing and the two copies.
fn honest_rows() -> Vec<(&'static str, Row)> {
    let mut out: Vec<(&'static str, Row)> = Vec::new();
    let mut push = |what: &'static str, r: Row| out.push((what, r));

    push(
        "lw",
        honest(Instr::lw(LW_IMM), LW_RS1V, 0, LW_WORD, LW_RD_OLD),
    );
    push(
        "sw",
        honest(Instr::sw(SW_IMM), SW_RS1V, SW_RS2V, SW_WORD, 0),
    );

    // An `x0` destination: the load runs, the word is read, and the register
    // file keeps its zero. `rd_selected` still carries the loaded word, which
    // is what `rd_value_rule` ties it to and what its range pair bounds.
    let mut i = Instr::lw(LW_IMM);
    i.rd = 0;
    push("lw into x0", honest(i, LW_RS1V, 0, LW_WORD, 0));
    // An `x0` source: the store runs and writes a zero word.
    let mut i = Instr::sw(SW_IMM);
    i.rs2 = 0;
    push("sw from x0", honest(i, SW_RS1V, 0, SW_WORD, 0));

    // A two-byte instruction, whose fall-through is pc + 2.
    let mut i = Instr::lw(LW_IMM);
    i.compressed = true;
    push("a compressed lw", honest(i, LW_RS1V, 0, LW_WORD, LW_RD_OLD));

    // The two ends. `0xfffffffc` is the last word the base-4 split admits:
    // `word_index = 2^30 − 1`, whose high chunk is `0x3fff` and whose scaled
    // obligation is `0xfffc`, just inside `2^16`.
    push(
        "lw at the top of the address space",
        honest(Instr::lw(0), 0xFFFF_FFFC, 0, LW_WORD, LW_RD_OLD),
    );
    push(
        "lw at RAM_ORIGIN",
        honest(
            Instr::lw(0),
            constants::guest_memory::RAM_ORIGIN,
            0,
            LW_WORD,
            LW_RD_OLD,
        ),
    );

    // `rs1 + imm` past `2^32`: the carry is the witnessed `wrap`, and the
    // effective address is the reduced sum.
    push(
        "a store whose address wraps",
        honest(Instr::sw(16), 0xFFFF_FFF8, SW_RS2V, SW_WORD, 0),
    );
    // A negative displacement, which is a wrap whenever it is smaller in
    // magnitude than `rs1`: `0x0002_0010 − 16`.
    push(
        "a load at a negative displacement",
        honest(Instr::lw(0xFFFF_FFF0), 0x0002_0010, 0, LW_WORD, LW_RD_OLD),
    );
    // And a negative displacement that is not: `8 − 16` reduces to
    // `0xfffffff8` with no carry at all.
    push(
        "a load below zero",
        honest(Instr::lw(0xFFFF_FFF0), 8, 0, LW_WORD, LW_RD_OLD),
    );

    // An `x0` base register, which reads 0, so the displacement is the whole
    // address.
    let mut i = Instr::lw(0x7FC);
    i.rs1 = 0;
    push("a load through x0", honest(i, 0, 0, LW_WORD, LW_RD_OLD));

    // `0xfffffffc + 4` is exactly `2^32`: the honest row carries the wrap and
    // reads word 0. `a_word_index_above_2_to_the_30_is_refused` is the same
    // row with the wrap dropped.
    push(
        "lw at the address space's end, wrapping to zero",
        honest(Instr::lw(4), 0xFFFF_FFFC, 0, LW_WORD, LW_RD_OLD),
    );

    push("padding", Row::default());
    out
}

/// Every row kind the family proves satisfies every gate, every range
/// obligation and the decoder channel.
#[test]
fn every_row_kind_satisfies_every_gate_and_every_bound() {
    let a = artifact();
    for (what, r) in honest_rows() {
        assert_eq!(violated(&a, &r), (none(), none(), none()), "{what}");
    }
    // The catalogue really covers the shapes the doc comment claims: both
    // kinds, an `x0` destination and an `x0` source, a compressed row, a
    // wrapping address and a `word_index` at each end of its range.
    let rows = honest_rows();
    let has = |p: fn(&Row) -> bool| rows.iter().any(|(_, r)| p(r));
    assert!(has(|r| r.get("kind_lw") == Fr::ONE));
    assert!(has(|r| r.get("kind_sw") == Fr::ONE));
    assert!(has(|r| r.get("wrap") == Fr::ONE));
    assert!(has(|r| r.get("word_index") == f((1 << 30) - 1)));
    assert!(has(
        |r| r.get("word_index") == Fr::ZERO && r.get("pc_mask") == Fr::ONE
    ));
    assert!(has(|r| r.get("rd_mask") == Fr::ONE
        && r.get("rd_addr") == Fr::ZERO
        && r.get("rd_selected") != Fr::ZERO));
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
/// two are listed, the comment says why the second reads the same cell.
#[test]
fn each_gate_is_the_one_that_refuses_its_row() {
    let a = artifact();
    let mut cases: Vec<(&str, Row, Vec<&str>)> = Vec::new();

    // The kind bits. A padding row is where a bit is free of every other gate
    // — the mask rules all carry `m_pc` — so it is where booleanity alone
    // stands between a 2 and the rest of the circuit. The packed mask moves
    // with the bit so that the recomposition still holds.
    let mut r = Row::default();
    r.set("kind_lw", f(2)).set("decoded_mask", f(2));
    cases.push((
        "a padding row whose lw bit is two",
        r,
        vec!["kind_lw_boolean"],
    ));
    let mut r = Row::default();
    r.set("kind_sw", f(2)).set("decoded_mask", f(4));
    cases.push((
        "a padding row whose sw bit is two",
        r,
        vec!["kind_sw_boolean"],
    ));

    // The packed mask against its bits. Nothing else reads `decoded_mask`:
    // one-hotness is the decoder table's domain, not a gate.
    let mut r = row("lw");
    r.set("decoded_mask", f(1 << kind::SW));
    cases.push((
        "an lw whose packed mask says sw",
        r,
        vec!["decoded_mask_bits"],
    ));

    // The wrap bit, which is worth `2^32` in the address split. A wrap of two
    // moves the effective address down by `2^33`, and the row below carries
    // that through `word_index` and the query's own address so that both the
    // split and the address rule still hold. Its own booleanity is what is
    // left — and what keeps the split an integer statement.
    let mut r = row("lw");
    let moved = f(LW_ADDR as u64) - f(1 << 32) * f(2);
    r.set("wrap", f(2))
        .set("word_index", moved * f(4).inverse().expect("nonzero"))
        .set("word_index_hi", Fr::ZERO)
        .set("load_addr", moved);
    cases.push(("an lw claiming a wrap of two", r, vec!["wrap_boolean"]));

    // Presence. Every kind reads rs1; a load reads the word and writes rd, a
    // store reads rs2 and rewrites the word. The rs1 forgery has to be made on
    // a row whose base register holds 0, or the address split notices the
    // dropped operand first.
    let mut r = row("a load through x0");
    r.drop_query("rs1");
    cases.push(("a load making no rs1 query", r, vec!["rs1_mask_rule"]));
    let mut r = row("lw");
    r.query("rs2", 2, 0, 0, 0);
    cases.push(("a load reading rs2", r, vec!["rs2_mask_rule"]));
    let mut r = row("sw");
    r.query("load", 2, SW_ADDR as u64, SW_WORD as u64, SW_WORD as u64);
    // Two gates, and they read the same column: `load_space_rule` is
    // `load_space = m_load·(RAM + …)`, so a row that switches the load query
    // on without a load breaks it as surely as the mask rule does.
    cases.push((
        "a store reading a load's word",
        r,
        vec!["load_mask_rule", "load_space_rule"],
    ));
    // A load that also rewrites the word it read. `store_value_rule` holds
    // only because the row has no rs2 to store, so the forgery can write 0 and
    // nothing else; the mask rule is the refusal.
    let mut r = row("lw");
    r.query("ram", 3, LW_ADDR as u64, LW_WORD as u64, 0);
    cases.push(("a load zeroing the word it read", r, vec!["ram_mask_rule"]));
    // A store that also writes a register. `rd_value_rule` ties what it writes
    // to a load query it does not have, so the value must be 0 and the address
    // x0, or two further gates fire; the mask rule refuses even that.
    let mut r = row("sw");
    r.query("rd", 3, 0, LW_RD_OLD as u64, 0);
    r.set("rd_is_zero", Fr::ONE);
    cases.push(("a store writing x0", r, vec!["rd_mask_rule"]));

    // The advice selector, `docs/spec/advice.md` §3 and §4. Four gates, one
    // tamper each, and between them they are the whole of read-only advice on
    // the circuit side.
    //
    // A bit that does not match the address: the split is an equation over
    // `word_index_hi`, so claiming the advice region from a RAM address moves
    // it and `advice_split` is what says so. This is the forgery that would
    // otherwise let a prover read a free value at an ordinary RAM address.
    let mut r = row("lw");
    r.set("is_advice", Fr::ONE);
    cases.push((
        "a RAM load claiming to be an advice load",
        r,
        vec!["advice_split", "load_space_rule"],
    ));
    // A bit that is neither 0 nor 1. `advice_split` is kept satisfied so the
    // booleanity gate is alone with the job; without it the bit could be any
    // field element and the space term would be any multiple of the tag.
    let mut r = row("lw");
    let hi = r.get("word_index_hi");
    r.set("is_advice", f(2))
        .set("word_index_hi", hi + f(2 << 13))
        .set("word_index_hi_rest", hi);
    // `advice_split` is kept satisfied so the booleanity gate is alone with
    // the job; `load_space_rule` follows because the space term is then a
    // multiple of the tag rather than the tag.
    cases.push((
        "an advice bit that is neither 0 nor 1",
        r,
        vec!["is_advice_boolean", "load_space_rule"],
    ));
    // The space column moved on its own: the leaf would name `ADVICE` while
    // the address is a RAM one, which is the forgery `load_space_rule` exists
    // for. Nothing else reads the column, so it is alone.
    let mut r = row("lw");
    r.set("load_space", f(address_space::ADVICE as u64));
    cases.push((
        "a load naming the advice space with a RAM address",
        r,
        vec!["load_space_rule"],
    ));
    // **A store into the advice region.** `m_ram` is `m_pc·sw`, so this is the
    // gate that makes advice read-only locally rather than leaving it to the
    // multiset (`docs/spec/advice.md` §4).
    let mut r = row("sw");
    let hi = r.get("word_index_hi");
    let index = r.get("word_index");
    let ram_addr = r.get("ram_addr");
    r.set("is_advice", Fr::ONE)
        .set("word_index_hi", hi + f(1 << 13))
        .set("word_index", index + f(1 << 29))
        .set("ram_addr", ram_addr + f(1 << 31));
    cases.push((
        "a store into the advice region",
        r,
        vec!["no_store_to_advice", "addr_split"],
    ));

    // Addresses. Each register query's address is the decoded one.
    let mut r = row("lw");
    let addr = r.get("rs1_addr") + Fr::ONE;
    r.set("rs1_addr", addr);
    cases.push((
        "a load reading the wrong base register",
        r,
        vec!["rs1_addr_rule"],
    ));
    let mut r = row("sw");
    let addr = r.get("rs2_addr") + Fr::ONE;
    r.set("rs2_addr", addr);
    cases.push((
        "a store reading the wrong source register",
        r,
        vec!["rs2_addr_rule"],
    ));
    let mut r = row("lw");
    r.set("rd_addr", f(5))
        .set("rd_inv", f(5).inverse().expect("nonzero"));
    cases.push(("a load writing the wrong register", r, vec!["rd_addr_rule"]));

    // The RAM queries' addresses, which are `4·word_index` and carry no byte
    // offset at all: sub-word and word accesses name the same cell.
    let mut r = row("lw");
    let addr = r.get("load_addr") + f(4);
    r.set("load_addr", addr);
    cases.push(("a load reading the next word", r, vec!["load_addr_rule"]));
    let mut r = row("sw");
    let addr = r.get("ram_addr") + f(4);
    r.set("ram_addr", addr);
    cases.push(("a store writing the next word", r, vec!["ram_addr_rule"]));

    // Absent operands read 0. Every live row queries rs1, so the gate's target
    // is a padding row that pretends to have read one — and the address split
    // reads that value, so the forgery pays for it in `word_index`.
    let mut r = Row::default();
    r.set("rs1_read_value", f(4))
        .set("rs1_write_value", f(4))
        .set("word_index", Fr::ONE);
    cases.push((
        "a padding row whose absent rs1 reads 4",
        r,
        vec!["rs1_value_masked"],
    ));
    // rs2 is absent on every load, and nothing a load computes reads it, so
    // there the forgery is a live one.
    let mut r = row("lw");
    r.set("rs2_read_value", f(5)).set("rs2_write_value", f(5));
    cases.push((
        "a load whose absent rs2 reads 5",
        r,
        vec!["rs2_value_masked"],
    ));

    // The address split itself: a load reading one word further, with the
    // query's address moved to match so that the address rule still holds.
    let mut r = row("lw");
    let index = r.get("word_index") + Fr::ONE;
    let addr = r.get("load_addr") + f(4);
    r.set("word_index", index).set("load_addr", addr);
    cases.push((
        "a load whose word index is one past its operands",
        r,
        vec!["addr_split"],
    ));

    // The two copies. A load copies the word it read into rd; a store copies
    // rs2 into the word.
    let mut r = row("lw");
    let forged = LW_WORD as u64 + 1;
    r.set("rd_selected", f(forged))
        .set("rd_write_value", f(forged))
        .set("rd_hi", f(forged >> 16));
    cases.push((
        "a load writing a word it did not read",
        r,
        vec!["rd_value_rule"],
    ));
    let mut r = row("sw");
    r.set("ram_write_value", f(SW_RS2V as u64 + 1));
    cases.push((
        "a store writing a value rs2 does not hold",
        r,
        vec!["store_value_rule"],
    ));

    // The pc. No kind here computes one, so `next_pc` is the decoded
    // fall-through and nothing else.
    let mut r = row("lw");
    r.set("pc_write_value", f(0x1008));
    cases.push(("an lw jumping four ahead", r, vec!["next_pc_rule"]));

    // S14's control C8 on this frame: a padding row whose `rd` query rewrites
    // a register after the program has exited. Nothing in the frame ties a
    // query's mask to the row's pc mask, so the family's mask rule is what
    // refuses it — together with the address rule, the decoded `rd` being 0 on
    // a row that decodes nothing. What this family *cannot* forge even so is a
    // nonzero write: `rd_value_rule` holds the written value to a load query
    // the padding row has no kind bit for, so the value below is 0.
    let mut r = Row::default();
    r.query("rd", 3, 10, 42, 0);
    r.set("rd_inv", f(10).inverse().expect("nonzero"));
    cases.push((
        "a padding row zeroing x10",
        r,
        vec!["rd_mask_rule", "rd_addr_rule"],
    ));

    // Every gate this family adds is named by some row above. The frame's
    // thirteen are S14's and covered by `crates/checker/tests/memory.rs`, so
    // they are set aside; what is left is this family's own semantics, and a
    // gate added with no forgery beside it fails here rather than silently.
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
        .filter(|n| !frame.contains(n))
        .collect();
    assert_eq!(owed.len(), 24);
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

/// Every booleanity gate the family adds refuses a 2: the two kind bits and
/// the wrap. Each is read as a 0 or a 1 by a gate above it — the kind bits by
/// five mask rules, the wrap by the address split, where a 2 is worth `2^33` —
/// and a value of two there is a different statement, so the membership is
/// what matters, not the whole violated set.
#[test]
fn every_booleanity_gate_refuses_a_value_of_two() {
    let a = artifact();
    for (base, column, gate) in [
        ("lw", "kind_lw", "kind_lw_boolean"),
        ("sw", "kind_sw", "kind_sw_boolean"),
        ("lw", "wrap", "wrap_boolean"),
    ] {
        let mut r = row(base);
        r.set(column, f(2));
        let (relations, _, _) = violated(&a, &r);
        assert!(
            relations.contains(&gate.to_string()),
            "{column} = 2: {relations:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The decoder channel
// ---------------------------------------------------------------------------

/// The decoder lookup is the lone refusal of rows every gate and every range
/// obligation accepts. Three of them: a row reading the instruction four bytes
/// on, a row writing into a register its table row does not name, and a live
/// row whose packed mask is all zero — the control S15, S16 and S17 each
/// carry, because on an all-zero mask every gated constraint goes vacuous and
/// only the table's domain is left.
#[test]
fn each_table_lookup_is_the_one_that_refuses_its_row() {
    let a = artifact();

    // The key is the frame's own `pc_read_value`, so a row claiming another pc
    // than the table row it carries is refused by the channel alone: no gate
    // reads that column.
    let mut r = row("lw");
    r.set("pc_read_value", f(0x1004));
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["decode_row"])),
        "an lw reading the pc four bytes on"
    );

    // A load into x11 where the table says x7, with the query's address and
    // the x0 gadget's inverse moved with it so that `rd_addr_rule` and the
    // gadget still hold. The table is what says which register a pc writes.
    let mut r = row("lw");
    r.set("decoded_rd", f(11))
        .set("rd_addr", f(11))
        .set("rd_inv", f(11).inverse().expect("nonzero"));
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["decode_row"])),
        "an lw writing x11 where its table row says x7"
    );

    // The all-zero mask: a live row that decodes nothing, its queries all
    // dropped so that every mask rule reads `m_pc·0`, its address split
    // trivial and its copies zero. Nothing but the decoder table's domain
    // stands in its way.
    let mut r = Row::default();
    r.set("cycle", f(CYCLE));
    r.set("pc_mask", Fr::ONE)
        .set("pc_read_ts", f(4 * (CYCLE - 1)))
        .set("pc_read_value", f(0x1000))
        .set("pc_write_value", f(0x1004));
    r.set("decoded_next_pc", f(0x1004));
    for (column, v) in [
        ("table_pc", 0x1000u64),
        ("table_next_pc", 0x1004),
        ("table_rs1", 5),
        ("table_rs2", 0),
        ("table_rd", 7),
        ("table_imm", LW_IMM as u64),
        ("table_extra_mask", 1 << kind::LW),
    ] {
        r.set(column, f(v));
    }
    assert_eq!(
        violated(&a, &r),
        (none(), none(), names(&["decode_row"])),
        "a live row carrying an all-zero mask"
    );
}

// ---------------------------------------------------------------------------
// Alignment: the prompt's must-be-exact 1
// ---------------------------------------------------------------------------

/// A misaligned word access is unprovable, and the range check is the whole of
/// why.
///
/// `addr = 4·word_index` says nothing over `Fr`: 4 is a unit there, so
/// `word_index := addr·4⁻¹` satisfies the split for *any* address, and the
/// rows below are exactly that witness. Every **gate** holds on them — the
/// split, the query's address rule, the copies, the mask rules, the decoder —
/// and what refuses each one is `word_index_lo_range`, the low half of the
/// 16+16 pair, because `addr·4⁻¹` is not a 32-bit integer and is not even a
/// 64-bit one. No choice of high chunk rescues it: the scaled obligation holds
/// the high chunk below `2^14` and the pair holds the remainder below `2^16`,
/// so the three together admit `word_index < 2^30` and nothing above, and this
/// element is nowhere near an integer that small.
#[test]
fn a_misaligned_word_access_is_unprovable() {
    let a = artifact();
    let quarter = f(4).inverse().expect("nonzero");
    for offset in [1u32, 2, 3] {
        let address = LW_ADDR + offset;
        assert_eq!(address % 4, offset, "the address really is misaligned");
        let word_index = f(address as u64) * quarter;
        // The witness the field admits is not an integer at all, so neither
        // chunk of a 16+16 split can hold it.
        assert!(
            small_int(word_index).is_none(),
            "addr·4⁻¹ is below 2^64 at offset {offset}"
        );

        let mut r = row("lw");
        r.set("decoded_imm", f((LW_IMM + offset) as u64))
            .set("table_imm", f((LW_IMM + offset) as u64))
            .set("load_addr", f(address as u64))
            .set("word_index", word_index)
            .set("word_index_hi", Fr::ZERO);
        assert_eq!(
            violated(&a, &r),
            (none(), names(&["word_index_lo_range"]), none()),
            "an lw at {address:#x}, which is {offset} past a word boundary"
        );
    }
}

/// `4·word_index < 2^16` — the third obligation — is what caps `word_index` at
/// `2^30 − 1`, and so caps the byte address at 32 bits.
///
/// The honest row is `lw` at `0xfffffffc + 4`, which is `2^32` exactly: it
/// carries the wrap and reads word 0. The forgery drops the wrap and claims
/// `word_index = 2^30` instead, so the query's address is the field element
/// `2^32` — a cell no 32-bit address can name, one the memory argument would
/// happily chain against nothing. The 16+16 pair accepts it: `0x4000` is a
/// halfword and the remainder is 0. `word_index_hi_scaled` is the lone
/// refusal.
#[test]
fn a_word_index_above_2_to_the_30_is_refused() {
    let a = artifact();
    let honest_row = row("lw at the address space's end, wrapping to zero");
    assert_eq!(honest_row.get("wrap"), Fr::ONE);
    assert_eq!(honest_row.get("word_index"), Fr::ZERO);
    assert_eq!(
        violated(&a, &honest_row),
        (none(), none(), none()),
        "the honest wrap to word 0"
    );

    let mut r = honest_row;
    let index = 1u64 << 30;
    r.set("wrap", Fr::ZERO)
        .set("word_index", f(index))
        .set("word_index_hi", f(index >> 16))
        // The split is kept honest — `is_advice` stays boolean and the rest
        // is the whole of `word_index_hi` — so that what refuses the row is
        // the scaled obligation and not `advice_split` or its booleanity.
        .set("is_advice", Fr::ZERO)
        .set("word_index_hi_rest", f(index >> 16))
        .set("load_addr", f(1 << 32));
    // The two halves of the 16+16 pair really do accept it, and so does
    // `word_index_hi_rest`'s own direct bound — `0x4000 < 2^16` — which is
    // what leaves the scaled obligation alone with the job.
    assert_eq!(index >> 16, 0x4000);
    assert_eq!(index - ((index >> 16) << 16), 0);
    assert_eq!(
        violated(&a, &r),
        (none(), names(&["word_index_hi_rest_scaled"]), none()),
        "a word index of 2^30"
    );
}

// ---------------------------------------------------------------------------
// The two copies
// ---------------------------------------------------------------------------

/// What a load writes is the word the memory argument pins, and `rd_value_rule`
/// is the tie.
///
/// The load's `read_value` is not bounded here — a value read from memory is
/// exempt, on the write-side induction S19 rests on — so what makes it a word
/// at all is the multiset: some earlier write put it there, and that write was
/// bounded. The gate is what carries the pinning into `rd`, and
/// `rd_selected`'s own range pair is what keeps every register value in this
/// VM locally 32-bit (`docs/spec/memory-ops.md` §5.1).
///
/// The cell on the other side is the one **no gate reads**: a store's
/// `ram_read_value`, the word it is about to overwrite. Nothing row-local has
/// an opinion on it, and the row below shows that directly. Only the
/// permutation product pins it, which is why the prompt's acceptance 8 makes
/// exactly that cell this family's tamper twin: the refusal has to surface
/// from the memory argument or from nowhere.
#[test]
fn the_loaded_value_is_the_word_the_memory_argument_pins() {
    let a = artifact();
    let base = row("lw");
    assert_eq!(base.get("rd_selected"), f(LW_WORD as u64));
    assert_eq!(
        violated(&a, &base),
        (none(), none(), none()),
        "the honest load"
    );

    // A load whose destination does not hold the word it read.
    let mut r = base;
    let forged = (LW_WORD ^ 1) as u64;
    r.set("rd_selected", f(forged))
        .set("rd_write_value", f(forged))
        .set("rd_hi", f(forged >> 16));
    assert_eq!(
        violated(&a, &r),
        (names(&["rd_value_rule"]), none(), none()),
        "a load writing a word it did not read"
    );

    // The same forgery on an `x0` destination, where the register write is
    // masked off and `rd_selected` is all that is left: the gate still holds
    // it to the word.
    let mut r = row("lw into x0");
    r.set("rd_selected", f(forged))
        .set("rd_hi", f(forged >> 16));
    assert_eq!(
        violated(&a, &r),
        (names(&["rd_value_rule"]), none(), none()),
        "an x0 load selecting a word it did not read"
    );

    // And the cell nothing row-local reads.
    let mut r = row("sw");
    assert_eq!(r.get("ram_read_value"), f(SW_WORD as u64));
    r.set("ram_read_value", f(0x0BAD_0BAD));
    assert_eq!(
        violated(&a, &r),
        (none(), none(), none()),
        "a store's overwritten word is pinned by the multiset alone"
    );
}
