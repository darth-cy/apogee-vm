//! Shared plumbing for the emulator's suites.
//!
//! Every guest here is the committed ELF under `crates/loader/tests/vectors`,
//! pinned by digest in `crates/loader/tests/common/mod.rs` — the same bytes
//! QEMU runs in `tests/differential.rs`.

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

use constants::family;
use emulator::{trace_run, Execution, GuestIo};
use isa::{decode, Instr};
use loader::{load_elf, ProgramImage, Slot};
use program::{decode_program, DecodedTables, ProgramParams, VmConfig};
use trace::{CycleProfile, FamilyTraces, MemoryEventLog};

pub fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../loader/tests/vectors")
}

pub fn elf(name: &str) -> Vec<u8> {
    let path = vectors().join(format!("{name}.elf"));
    fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

pub fn image(name: &str) -> ProgramImage {
    load_elf(&elf(name)).unwrap_or_else(|e| panic!("{name}: {e:?}"))
}

pub fn io(input: &[u8]) -> GuestIo {
    GuestIo {
        input: input.to_vec(),
        hint: Vec::new(),
    }
}

/// Every family at the smallest height: every committed guest's code fits,
/// and a table costs 2^16 rows rather than 2^22.
pub fn smallest() -> ProgramParams {
    ProgramParams {
        heights: [1 << 16; family::COUNT as usize],
        ..ProgramParams::defaults()
    }
}

pub fn preprocess(image: &ProgramImage) -> (DecodedTables, VmConfig) {
    decode_program(image, &smallest()).unwrap_or_else(|e| panic!("{e}"))
}

/// The instruction at `pc`.
pub fn instr_at(image: &ProgramImage, pc: u32) -> Instr {
    match image.slot_at(pc) {
        Some(Slot::Instruction { word, .. }) => decode(word).expect("a traced pc decodes"),
        other => panic!("{pc:#010x} is {other:?}"),
    }
}

/// fib's committed public-I/O record: `(input, output)`.
pub fn fib_record() -> (Vec<u8>, Vec<u8>) {
    let text = fs::read_to_string(vectors().join("fib_io.txt")).expect("reading fib_io.txt");
    let field = |key: &str| {
        let line = text
            .lines()
            .find(|l| l.split_whitespace().next() == Some(key))
            .unwrap_or_else(|| panic!("fib_io.txt has no {key}"));
        let value = line.split_whitespace().nth(1).expect("a key has a value");
        test_support::hex_to_bytes(value).expect("fib_io.txt values are hex")
    };
    (field("input"), field("output"))
}

/// `opcodes` in mode 0, with the six payload bytes `cover_ecall` reads.
pub fn opcodes_input() -> Vec<u8> {
    vec![0, 0, 0, 0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6]
}

/// The input each traced guest runs on here.
pub fn input_of(name: &str) -> Vec<u8> {
    match name {
        "fib" => fib_record().0,
        "opcodes" => opcodes_input(),
        "heap" => 40u32.to_le_bytes().to_vec(),
        "atomics" => 37u32.to_le_bytes().to_vec(),
        "rvc-dense" => 7u32.to_le_bytes().to_vec(),
        other => panic!("no input chosen for {other}"),
    }
}

/// One guest, preprocessed and traced.
pub struct Traced {
    pub image: ProgramImage,
    pub tables: DecodedTables,
    pub config: VmConfig,
    pub traces: FamilyTraces,
    pub log: MemoryEventLog,
    pub profile: CycleProfile,
    pub execution: Execution,
}

pub fn traced(name: &str) -> Traced {
    let image = image(name);
    let (tables, config) = preprocess(&image);
    let (traces, log, profile, execution) =
        trace_run(&image, &io(&input_of(name)), &tables, &config)
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(
        execution.exit_code, 0,
        "{name} exited {}",
        execution.exit_code
    );
    Traced {
        image,
        tables,
        config,
        traces,
        log,
        profile,
        execution,
    }
}

/// The guests the trace suites run.
pub const TRACED: [&str; 5] = ["fib", "heap", "atomics", "opcodes", "rvc-dense"];
