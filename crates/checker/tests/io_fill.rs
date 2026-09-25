//! The **add/sub family's fill over a `read` and a `write` row**, which no
//! guest in the fast suites reaches.
//!
//! S25 made `read` and `write` provable ecalls. Both put their answer in `a0`,
//! the register that also carried their first argument, so the `rd` query on
//! such a row reads a **descriptor** and writes a **byte count** — the one
//! place in the machine where a query's read and its write differ and neither
//! is computed from the decoded table. The frame's `rd_write_masked` gate holds
//! `rd_selected` to the write; a fill that took the read instead is a shard no
//! verifier accepts, and an honest prover that cannot prove its own trace.
//!
//! Nothing else in `cargo test --workspace` runs one. Every guest the fast
//! suites trace — `addsub`, `control`, `alu`, `mem`, `shards`, `keccak-test`,
//! `recursion-ops` — exits with a status and links no SDK, so it issues no
//! `read` and no `write`; the only statement that has such a row is
//! `crates/prover/tests/revm.rs`', which is `# DEFERRED`. Hence a program built
//! by hand here, in the spirit of `mem_fill.rs`: eleven instructions, one of
//! each I/O call, filled and evaluated gate by gate.

use std::collections::BTreeMap;

use checker::{violated_lookups, violated_relations, WitnessRow};
use constants::{challenge_slot, ecall, family, guest_memory};
use constraints::{add_sub, family_circuit, memory::frame_queries, memory::rd_selected};
use constraints::{CircuitArtifact, PolyAddress};
use emulator::{trace_run, GuestIo};
use field::Fr;
use gkr::{gate_values, insert_lookup_challenges, virtual_at_row, ExternalChallenges};
use loader::{ProgramImage, Segment, Slot};
use poly::MultilinearPoly;
use program::{decode_program, ProgramParams};
use trace::{IoStreams, PhaseTiming, TraceArchive};

/// The height the add/sub family is proved at. `2^20` is the floor for any
/// family with a `TIMESTAMP` obligation, whose table is `2^19` deep
/// (`docs/spec/lookup.md` §3).
const VARS: u32 = 20;

/// The four bytes the guest reads from fd 0 and writes back to fd 1.
const PAYLOAD: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];

const OP_OP_IMM: u32 = 0x13;
const OP_LUI: u32 = 0x37;
const OP_SYSTEM: u32 = 0x73;

fn i_type(op: u32, funct3: u32, rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | op
}

fn addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    i_type(OP_OP_IMM, 0, rd, rs1, imm)
}

/// `rd = value`, in one or two instructions.
fn load_imm(rd: u32, value: u32) -> Vec<u32> {
    let lo = value & 0xfff;
    let hi = (value >> 12) + u32::from(lo >= 0x800);
    let mut out = Vec::new();
    if hi != 0 {
        out.push(((hi & 0xf_ffff) << 12) | (rd << 7) | OP_LUI);
    }
    if lo != 0 || hi == 0 {
        out.push(addi(rd, if hi == 0 { 0 } else { rd }, lo as i32));
    }
    out
}

/// `read(0, buf, 4)`, then `write(1, buf, 4)`, then `exit(0)`.
///
/// `a1` and `a2` are set once and survive both calls; `a0` is reloaded before
/// each, which is the whole point — the first call leaves the byte count there
/// and the descriptor of the second has to overwrite it.
fn io_program() -> ProgramImage {
    let mut words = vec![addi(17, 0, ecall::READ as i32), addi(10, 0, 0)];
    // The buffer, one word past the last instruction this function emits.
    let buffer_at = guest_memory::RAM_ORIGIN + 4 * 16;
    words.extend(load_imm(11, buffer_at));
    words.push(addi(12, 0, ecall::READ_WORD_BYTES as i32));
    words.push(OP_SYSTEM);
    words.push(addi(17, 0, ecall::WRITE as i32));
    words.push(addi(10, 0, 1));
    words.push(OP_SYSTEM);
    words.push(addi(17, 0, ecall::EXIT as i32));
    words.push(addi(10, 0, 0));
    words.push(OP_SYSTEM);
    // Pad up to, and not into, the buffer: it sits in the zero bytes the
    // segment reserves past the code, so the word the `read` overwrites is
    // not an instruction.
    while guest_memory::RAM_ORIGIN + 4 * (words.len() as u32) < buffer_at {
        words.push(addi(0, 0, 0));
    }
    assert_eq!(
        guest_memory::RAM_ORIGIN + 4 * (words.len() as u32),
        buffer_at,
        "the code ends exactly where the buffer begins"
    );
    let mut slots = Vec::new();
    for word in &words {
        slots.push(Slot::Instruction {
            word: *word,
            compressed: false,
        });
        slots.push(Slot::MidInstruction);
    }
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    ProgramImage {
        entry: guest_memory::RAM_ORIGIN,
        segments: vec![Segment {
            vaddr: guest_memory::RAM_ORIGIN,
            mem_len: bytes.len() as u32 + 16,
            bytes,
        }],
        slot_base: guest_memory::RAM_ORIGIN,
        slots,
    }
}

/// The program run once on [`PAYLOAD`], exiting 0.
fn traced() -> (prover::Program, TraceArchive) {
    let image = io_program();
    let mut params = ProgramParams::defaults();
    params.heights = [1 << VARS; family::COUNT as usize];
    for f in [family::KECCAK_F, family::POSEIDON2, family::FR_ARITH] {
        params.heights[f as usize] = constants::family::DEFAULT_HEIGHTS[f as usize];
    }
    let (tables, config) = decode_program(&image, &params).expect("the program decodes");
    let io = GuestIo {
        input: PAYLOAD.to_vec(),
        hint: Vec::new(),
    };
    let (traces, log, profile, execution) =
        trace_run(&image, &io, &tables, &config).expect("the program runs");
    assert_eq!(execution.exit_code, 0);
    assert_eq!(
        execution.io.input, PAYLOAD,
        "the run consumed the whole of fd 0"
    );
    assert_eq!(
        execution.io.output, PAYLOAD,
        "the run wrote what it read to fd 1"
    );
    let archive = TraceArchive::from_execution(
        traces,
        log,
        profile,
        IoStreams {
            input: execution.io.input,
            output: execution.io.output,
        },
        PhaseTiming { wall_nanos: 0 },
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

/// The add/sub family's fill of shard 0, with every channel's multiplicities
/// counted over it.
fn filled(
    program: &prover::Program,
    archive: &TraceArchive,
) -> (CircuitArtifact, Vec<(PolyAddress, MultilinearPoly)>) {
    let fam = family::ADD_SUB_LUI_AUIPC;
    let circuit = family_circuit(fam, VARS).expect("the add/sub circuit");
    let fill = prover::family_fill(fam).expect("the add/sub fill");
    let source = prover::ShardSource {
        program,
        archive,
        family: fam,
        index: 0,
        height: 1 << VARS,
        window: 0,
    };
    let mut columns = fill(&source).expect("the fill");
    let counts = trace::build_multiplicities(&circuit.artifact, &columns, &circuit.channels)
        .expect("the multiplicities");
    columns.extend(counts);
    assert_eq!(
        columns.len(),
        circuit.artifact.committed().len(),
        "one column per committed address"
    );
    (circuit.artifact, columns)
}

/// The value `address` holds at `row`.
fn at(columns: &[(PolyAddress, MultilinearPoly)], address: PolyAddress, row: usize) -> Fr {
    columns
        .iter()
        .find(|(a, _)| *a == address)
        .unwrap_or_else(|| panic!("no {address}"))
        .1
        .get(row)
}

/// Every gate and every range obligation of `a` holds on each of `rows`.
fn assert_rows_hold(
    a: &CircuitArtifact,
    columns: &[(PolyAddress, MultilinearPoly)],
    rows: &[usize],
) {
    let get = |address: PolyAddress| {
        &columns
            .iter()
            .find(|(c, _)| *c == address)
            .unwrap_or_else(|| panic!("the fill has no {address}"))
            .1
    };
    let ordered: Vec<&MultilinearPoly> = a.committed().iter().map(|x| get(*x)).collect();
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
            panic!("row {row} breaks {broken:?} / {out_of_range:?}\n{named:?}");
        }
    }
}

/// An ecall row's `rd_selected` is the byte count `a0` was **written**, not
/// the descriptor `a0` held when the call was made.
///
/// This is the whole of what the fix is. Both values are on the row — the
/// descriptor as the `rs2` query's read, the count as the `rd` query's write —
/// so taking the wrong one produces a column that looks plausible and breaks
/// `rd_write_masked` (`write_value − sel + z·sel = 0`), which
/// [`the_io_fill_satisfies_every_gate`] then catches. Asserted separately here
/// so that a failure says *which* value was taken rather than naming a gate.
#[test]
fn a_read_and_a_write_select_the_byte_count_and_not_the_descriptor() {
    let (program, archive) = traced();
    let (_, columns) = filled(&program, &archive);
    let sel = rd_selected(frame_queries(family::ADD_SUB_LUI_AUIPC).len());
    let n = archive
        .family_traces()
        .family(family::ADD_SUB_LUI_AUIPC)
        .expect("the add/sub buffer")
        .len();

    let rows = |which: PolyAddress| -> Vec<usize> {
        (0..n)
            .filter(|r| at(&columns, which, *r) == Fr::ONE)
            .collect()
    };
    let reads = rows(add_sub::IS_READ);
    let writes = rows(add_sub::IS_WRITE);
    assert_eq!(reads.len(), 1, "the program makes one `read`");
    assert_eq!(writes.len(), 1, "the program makes one `write`");

    let four = Fr::from_u64(ecall::READ_WORD_BYTES as u64);
    assert_eq!(
        at(&columns, sel, reads[0]),
        four,
        "the `read` row selects the byte count it wrote to a0, not the fd 0 it read"
    );
    assert_eq!(
        at(&columns, sel, writes[0]),
        four,
        "the `write` row selects the byte count it wrote to a0, not the fd 1 it read"
    );
    // And the two descriptors are values the row really did hold, so a fill
    // reading `a0` instead would have produced them and not the count.
    assert_ne!(four, Fr::ZERO, "fd 0 and the count are distinguishable");
    assert_ne!(four, Fr::ONE, "fd 1 and the count are distinguishable");
}

/// The filled shard satisfies every gate and every bound on every live row, on
/// the two padding rows after them and on the shard's last row — the same
/// shape `mem_fill.rs` holds S19's families to, over the one family whose rows
/// include the provable I/O ecalls.
#[test]
fn the_io_fill_satisfies_every_gate() {
    let (program, archive) = traced();
    let (a, columns) = filled(&program, &archive);
    let n = archive
        .family_traces()
        .family(family::ADD_SUB_LUI_AUIPC)
        .expect("the add/sub buffer")
        .len();
    assert!(n > 0, "the program runs add/sub rows");
    let rows: Vec<usize> = (0..n + 2).chain([(1 << VARS) - 1]).collect();
    assert_rows_hold(&a, &columns, &rows);
}
