//! S19's three families' fills over `guests/mem`'s real trace: every live row,
//! two padding rows after it and the shard's last row, evaluated through
//! `checker::violated_relations` and `violated_lookups`, with every channel's
//! multiplicities counted over the filled columns.
//!
//! This runs in ordinary CI and is the cheapest end-to-end signal the three
//! families get: it holds the circuits to the fills, the fills to the emulator's
//! trace, and every gated tuple to its table — `trace::build_multiplicities`
//! refuses a tuple no table row answers.

use std::collections::BTreeMap;

use checker::{violated_lookups, violated_relations, WitnessRow};
use constants::{challenge_slot, family, generic_table};
use constraints::{
    atomics, family_circuit, mem_subword, mem_word, CircuitArtifact, Coeff, GateDef, PolyAddress,
};
use field::Fr;
use gkr::{gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use poly::MultilinearPoly;

#[path = "../../prover/tests/common/mod.rs"]
mod common;

/// The height every execution family of this statement is proved at.
const VARS: u32 = 20;

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

/// `guests/mem` decoded and traced once, shared by the three cases.
fn guest() -> (prover::Program, trace::TraceArchive) {
    let program = common::mem_program();
    let archive = common::mem_archive(&program);
    (program, archive)
}

/// The family's fill of shard 0, its setup columns held to the program's
/// decoded table and — where the circuit reads the generic channel — to the
/// packed table row for row, with every channel's multiplicities counted over
/// it.
fn filled(
    program: &prover::Program,
    archive: &trace::TraceArchive,
    family: u32,
    table_width: usize,
    generic: bool,
) -> (CircuitArtifact, Vec<(PolyAddress, MultilinearPoly)>) {
    let circuit = family_circuit(family, VARS).expect("the family's circuit");
    let fill = prover::family_fill(family).expect("the family's fill");
    let source = prover::ShardSource {
        program,
        archive,
        family,
        index: 0,
        height: 1 << VARS,
        window: 0,
    };
    let mut columns = fill(&source).expect("the fill");
    let at = |columns: &[(PolyAddress, MultilinearPoly)], address: PolyAddress| {
        columns
            .iter()
            .find(|(c, _)| *c == address)
            .unwrap_or_else(|| panic!("the fill has no {address}"))
            .1
            .clone()
    };
    let table = program.tables.family(family).expect("the family's table");
    let packed = program::lookup_tables::generic_table(VARS);
    let width = table_width + if generic { generic_table::WIDTH } else { 0 };
    for j in 0..width {
        let got = at(&columns, PolyAddress::Setup(j as u32));
        let want = match j.checked_sub(table_width) {
            None => table.column_poly(j),
            Some(g) => packed[g].clone(),
        };
        assert_eq!(got.len(), 1 << VARS, "family {family}: S[{j}]'s height");
        assert!(
            (0..1 << VARS).all(|i| got.get(i) == want.get(i)),
            "family {family}: S[{j}] is not its table"
        );
    }
    let counts = trace::build_multiplicities(&circuit.artifact, &columns, &circuit.channels)
        .unwrap_or_else(|e| panic!("family {family}: {e}"));
    columns.extend(counts);
    assert_eq!(
        columns.len(),
        circuit.artifact.committed().len(),
        "family {family}: one column per committed address"
    );
    (circuit.artifact, columns)
}

/// Every gate and every range obligation of `a` holds on each of `rows`.
fn assert_rows_hold(
    a: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    rows: &[usize],
    what: &str,
) {
    let at = |address: PolyAddress| {
        &columns
            .iter()
            .find(|(c, _)| *c == address)
            .unwrap_or_else(|| panic!("{what}: the fill has no {address}"))
            .1
    };
    let ordered: Vec<&MultilinearPoly> = a.committed().iter().map(|x| at(*x)).collect();
    let ch = challenges(a);
    let names: Vec<&str> = a
        .memory
        .iter()
        .chain(&a.witness)
        .chain(&a.setup)
        .map(|s| s.as_str())
        .collect();
    for &row in rows {
        let committed: Vec<Fr> = ordered.iter().map(|c| c.get(row)).collect();
        let virtuals: Vec<Fr> = a
            .virtuals
            .iter()
            .map(|(k, _)| virtual_at_row(*k, row))
            .collect();
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
        let w = WitnessRow {
            committed,
            row,
            scratch,
        };
        let broken = violated_relations(a, &w, &ch);
        let out_of_range = violated_lookups(a, &w);
        if !broken.is_empty() || !out_of_range.is_empty() {
            let mut named: BTreeMap<&str, Fr> = BTreeMap::new();
            for (name, value) in names.iter().zip(&w.committed) {
                named.insert(name, *value);
            }
            panic!("{what}: row {row} breaks {broken:?} / {out_of_range:?}\n{named:?}");
        }
    }
}

/// Every `RANGE16` obligation of `a` whose expression scales its column by
/// anything but 1 names a column that also carries a direct bound under the
/// same selector — which is what `lookup::check_copowers` asks of the list its
/// caller hands it, asserted here over the artifact so that a scaled column
/// added later and left out of that list is caught.
fn assert_every_scaled_column_is_bounded(a: &CircuitArtifact, what: &str) {
    use constants::lookup_channel;
    let mut scaled: Vec<(PolyAddress, PolyAddress)> = Vec::new();
    for l in &a.lookups {
        if l.channel != lookup_channel::RANGE16 {
            continue;
        }
        let GateDef::Linear { terms, .. } = &l.tuple[0] else {
            panic!("{what}: a range obligation is one Linear");
        };
        // A 16+16 pair's low half has two terms and is the direct bound
        // itself; a scaled obligation is one column with a coefficient.
        if terms.len() != 1 {
            continue;
        }
        let (c, x) = terms[0];
        if c != Coeff::Literal(Fr::ONE) {
            scaled.push((x, l.selector));
        }
    }
    assert!(
        !scaled.is_empty(),
        "{what}: no scaled obligation at all, so this check is vacuous"
    );
    if let Err(e) = constraints::lookup::check_copowers(a, &scaled) {
        panic!("{what}: {e}");
    }
}

/// How many rows of `family` the guest ran.
fn live(archive: &trace::TraceArchive, family: u32) -> usize {
    archive
        .family_traces()
        .family(family)
        .expect("the family's buffer")
        .len()
}

/// The value `address` holds at `row` of a filled shard.
fn at(columns: &[(PolyAddress, MultilinearPoly)], address: PolyAddress, row: usize) -> Fr {
    columns
        .iter()
        .find(|(a, _)| *a == address)
        .unwrap_or_else(|| panic!("no {address}"))
        .1
        .get(row)
}

/// Acceptance 1's in-CI half for `MEM_WORD`: the fill of the guest's shard
/// satisfies every gate and every bound on every live row, on the two padding
/// rows after them and on the shard's last row.
///
/// It also holds the guest to reaching the one addressing shape the rest of it
/// does not: a **negative displacement**, whose effective address wraps past
/// `2^32` because `imm` is sign-extended, so `wrap` is 1. Every compiled guest
/// emits them, and without a check here no fill test would run one.
#[test]
fn the_mem_word_fill_satisfies_every_gate_and_every_table() {
    let (program, archive) = guest();
    let n = live(&archive, family::MEM_WORD);
    assert!(n > 0, "guests/mem runs lw and sw");
    let (a, columns) = filled(
        &program,
        &archive,
        family::MEM_WORD,
        mem_word::TABLE_WIDTH,
        false,
    );
    let rows: Vec<usize> = (0..n + 2).chain([(1 << VARS) - 1]).collect();
    assert_rows_hold(&a, &columns, &rows, "MEM_WORD");
    assert_every_scaled_column_is_bounded(&a, "MEM_WORD");
    assert!(
        (0..n).any(|r| at(&columns, mem_word::WRAP, r) == Fr::ONE),
        "no MEM_WORD row of guests/mem wraps: its negative displacement is gone"
    );
}

/// The same for `MEM_SUBWORD`.
#[test]
fn the_mem_subword_fill_satisfies_every_gate_and_every_table() {
    let (program, archive) = guest();
    let n = live(&archive, family::MEM_SUBWORD);
    assert!(n > 0, "guests/mem runs the six sub-word instructions");
    let (a, columns) = filled(
        &program,
        &archive,
        family::MEM_SUBWORD,
        mem_subword::TABLE_WIDTH,
        true,
    );
    let rows: Vec<usize> = (0..n + 2).chain([(1 << VARS) - 1]).collect();
    assert_rows_hold(&a, &columns, &rows, "MEM_SUBWORD");
    assert_every_scaled_column_is_bounded(&a, "MEM_SUBWORD");
    assert!(
        (0..n).any(|r| at(&columns, mem_subword::WRAP, r) == Fr::ONE),
        "no MEM_SUBWORD row of guests/mem wraps"
    );
}

/// The same for `ATOMICS`.
#[test]
fn the_atomics_fill_satisfies_every_gate_and_every_table() {
    let (program, archive) = guest();
    let n = live(&archive, family::ATOMICS);
    assert!(n > 0, "guests/mem runs the eleven atomics");
    let (a, columns) = filled(
        &program,
        &archive,
        family::ATOMICS,
        atomics::TABLE_WIDTH,
        true,
    );
    let rows: Vec<usize> = (0..n + 2).chain([(1 << VARS) - 1]).collect();
    assert_rows_hold(&a, &columns, &rows, "ATOMICS");
    assert_every_scaled_column_is_bounded(&a, "ATOMICS");
}

// ---------------------------------------------------------------------------
// The advice path, which no committed guest takes
// ---------------------------------------------------------------------------

/// A hand-encoded program that loads one **advice** word and one RAM word,
/// entered at `RAM_ORIGIN`, with `scratch` bytes of RAM after the code.
///
/// Hand-encoded rather than compiled because the property is the address map:
/// no committed guest reaches `0x8000_0000`, and one that did would drop out of
/// the QEMU suites (`docs/spec/advice.md` §9). `crates/emulator/tests/advice.rs`
/// builds its programs the same way and for the same reason.
fn advice_and_ram_program() -> loader::ProgramImage {
    const OP_LOAD: u32 = 0x03;
    const OP_STORE: u32 = 0x23;
    const OP_OP_IMM: u32 = 0x13;
    const OP_LUI: u32 = 0x37;
    const OP_SYSTEM: u32 = 0x73;
    let i_type = |op: u32, funct3: u32, rd: u32, rs1: u32, imm: i32| {
        ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | op
    };
    let s_type = |funct3: u32, rs1: u32, rs2: u32, imm: i32| {
        let imm = imm as u32;
        ((imm >> 5 & 0x7f) << 25)
            | (rs2 << 20)
            | (rs1 << 15)
            | (funct3 << 12)
            | ((imm & 0x1f) << 7)
            | OP_STORE
    };
    let lui = |rd: u32, imm20: u32| (imm20 << 12) | (rd << 7) | OP_LUI;
    let words = [
        lui(1, constants::guest_memory::ADVICE_ORIGIN >> 12), // x1 = ADVICE_ORIGIN
        i_type(OP_LOAD, 2, 10, 1, 0),                         // lw x10, 0(x1): advice
        lui(2, 0x11),                                         // x2 = 0x11000: RAM
        s_type(2, 2, 10, 0),                                  // sw x10, 0(x2)
        i_type(OP_LOAD, 2, 11, 2, 0),                         // lw x11, 0(x2): RAM
        i_type(OP_OP_IMM, 0, 17, 0, constants::ecall::EXIT as i32),
        OP_SYSTEM,
    ];
    let at = constants::guest_memory::RAM_ORIGIN;
    let mut slots = Vec::new();
    for word in words {
        slots.push(loader::Slot::Instruction {
            word,
            compressed: false,
        });
        slots.push(loader::Slot::MidInstruction);
    }
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    loader::ProgramImage {
        entry: at,
        segments: vec![loader::Segment {
            vaddr: at,
            mem_len: bytes.len() as u32 + 4096,
            bytes,
        }],
        slot_base: at,
        slots,
    }
}

/// **`MEM_WORD`'s fill on an advice load**, which is the one branch of it no
/// committed guest reaches and whose only other coverage is the deferred
/// `crates/prover/tests/revm.rs`.
///
/// The program loads one advice word and one RAM word, so the family's two live
/// rows exercise both sides of `advice_split` in one trace: `is_advice` is 1 on
/// the advice row and 0 on the RAM row, `load_space` is `ADVICE` and then `RAM`,
/// and every gate and obligation holds on both. A fill that read the space from
/// the slot rather than the address, or that forgot the re-split, fails here
/// rather than in a suite that takes forty minutes.
#[test]
fn the_mem_word_fill_reads_advice_and_ram_in_one_trace() {
    use constants::address_space;

    let image = advice_and_ram_program();
    let mut params = program::ProgramParams::defaults();
    params.heights = [1 << VARS; family::COUNT as usize];
    for f in [family::KECCAK_F, family::POSEIDON2, family::FR_ARITH] {
        params.heights[f as usize] = 1 << 8;
    }
    let (tables, config) = program::decode_program(&image, &params).expect("it decodes");
    let io = emulator::GuestIo {
        advice: vec![7, 0, 0, 0],
        ..emulator::GuestIo::default()
    };
    let (traces, log, profile, execution) =
        emulator::trace_run(&image, &io, &tables, &config).expect("it traces");
    assert_eq!(execution.exit_code, 7, "the advice word reached x10 and a0");
    log.self_check(&image).expect("the log balances");
    let archive = trace::TraceArchive::from_execution(
        traces,
        log,
        profile,
        trace::IoStreams {
            input: Vec::new(),
            output: Vec::new(),
        },
        trace::PhaseTiming { wall_nanos: 0 },
    );
    let program = prover::Program {
        image,
        tables,
        config,
    };

    let (a, columns) = filled(
        &program,
        &archive,
        family::MEM_WORD,
        mem_word::TABLE_WIDTH,
        false,
    );
    let n = live(&archive, family::MEM_WORD);
    assert_eq!(n, 3, "two loads and one store are MEM_WORD's");

    // Row 0 is the advice load, row 2 the RAM load; row 1 is the store. The
    // space column and the selector agree with the address on each.
    let space = constraints::memory::load_space(6);
    assert_eq!(at(&columns, mem_word::IS_ADVICE, 0), Fr::ONE);
    assert_eq!(
        at(&columns, space, 0),
        Fr::from_u64(address_space::ADVICE as u64)
    );
    assert_eq!(at(&columns, mem_word::IS_ADVICE, 2), Fr::ZERO);
    assert_eq!(
        at(&columns, space, 2),
        Fr::from_u64(address_space::RAM as u64)
    );
    // The store neither loads nor names a space.
    assert_eq!(at(&columns, mem_word::IS_ADVICE, 1), Fr::ZERO);
    assert_eq!(at(&columns, space, 1), Fr::ZERO);

    let rows: Vec<usize> = (0..n + 2).chain([(1 << VARS) - 1]).collect();
    assert_rows_hold(&a, &columns, &rows, "MEM_WORD over advice");
    assert_every_scaled_column_is_bounded(&a, "MEM_WORD over advice");
}
