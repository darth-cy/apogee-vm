//! The statements the proving suites prove, over a toy SRS whose `tau` is
//! written down here. Test-only.
//!
//! - S16's: `guests/addsub`'s committed ELF, decoded with its execution family
//!   at `2^20` rows — the timestamp channel's floor — and everything else at
//!   `2^16`, traced into an archive.
//! - S17's: `guests/control`'s, the same way, with both of its execution
//!   families — add/sub and jump/branch/slt — at `2^20`.
//! - S18's: `guests/alu`'s, with all four of its execution families — those
//!   two, shift/bitwise and mul/div — at `2^20`.
//! - S19's: `guests/mem`'s, with five — add/sub, jump/branch/slt and the three
//!   families S19 proves — at `2^20`. It is the first statement whose rows
//!   touch RAM, so it is also the first with a `ZERO_WINDOWS` shard.

#![allow(dead_code)]

use std::path::PathBuf;

use constants::family;
use emulator::{trace_run, GuestIo};
use field::Fr;
use loader::load_elf;
use program::{decode_program, ProgramParams};
use prover::{Program, ProverSetup};
use trace::{IoStreams, PhaseTiming, TraceArchive};

/// The execution family's height: `2^20`, the smallest a family carrying a
/// timestamp obligation can have (`docs/spec/lookup.md` §3).
pub const ADD_VARS: u32 = 20;

/// Every other family's, and the RAM windows': `2^16`. The image of `addsub`
/// ends far below `4·2^16`.
pub const WINDOW_VARS: u32 = 16;

/// `guests/addsub`'s exit status.
pub const RESULT: u32 = 42;

/// `guests/alu`'s exit status: the number of its checks.
pub const ALU_RESULT: u32 = 96;

/// `guests/control`'s exit status: the number of its checks.
pub const CONTROL_RESULT: u32 = 16;

/// `guests/mem`'s exit status: the number of its checks.
pub const MEM_RESULT: u32 = 50;

/// The committed ELF of guest `name`.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../loader/tests/vectors/{name}.elf"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

pub fn elf() -> Vec<u8> {
    fixture("addsub")
}

/// Every family at `2^16` but `executed`, at `2^20`.
fn heights(executed: &[u32]) -> ProgramParams {
    let mut heights = [1 << WINDOW_VARS; family::COUNT as usize];
    for f in executed {
        heights[*f as usize] = 1 << ADD_VARS;
    }
    ProgramParams {
        heights,
        ..ProgramParams::defaults()
    }
}

pub fn params() -> ProgramParams {
    heights(&[family::ADD_SUB_LUI_AUIPC])
}

/// S17's heights: both of `control`'s execution families at `2^20`.
pub fn control_params() -> ProgramParams {
    heights(&[family::ADD_SUB_LUI_AUIPC, family::JUMP_BRANCH_SLT])
}

/// S18's heights: all four of `alu`'s execution families at `2^20`.
pub fn alu_params() -> ProgramParams {
    heights(&[
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::SHIFT_BITWISE,
        family::MUL_DIV,
    ])
}

/// S19's heights: all five of `mem`'s execution families at `2^20`.
pub fn mem_params() -> ProgramParams {
    heights(&[
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::MEM_WORD,
        family::MEM_SUBWORD,
        family::ATOMICS,
    ])
}

fn program_of(name: &str, params: &ProgramParams) -> Program {
    let image = load_elf(&fixture(name)).unwrap_or_else(|e| panic!("{name} loads: {e:?}"));
    let (tables, config) =
        decode_program(&image, params).unwrap_or_else(|e| panic!("{name} decodes: {e}"));
    Program {
        image,
        tables,
        config,
    }
}

pub fn program() -> Program {
    program_of("addsub", &params())
}

pub fn control_program() -> Program {
    program_of("control", &control_params())
}

pub fn alu_program() -> Program {
    program_of("alu", &alu_params())
}

pub fn mem_program() -> Program {
    program_of("mem", &mem_params())
}

/// The post-execution archive of `addsub`'s one run.
pub fn archive(program: &Program) -> TraceArchive {
    trace(program, RESULT)
}

/// The post-execution archive of `control`'s one run.
pub fn control_archive(program: &Program) -> TraceArchive {
    trace(program, CONTROL_RESULT)
}

/// The post-execution archive of `alu`'s one run.
pub fn alu_archive(program: &Program) -> TraceArchive {
    trace(program, ALU_RESULT)
}

/// The post-execution archive of `mem`'s one run.
pub fn mem_archive(program: &Program) -> TraceArchive {
    trace(program, MEM_RESULT)
}

/// A run with no input and no hint, which must exit with `status`.
fn trace(program: &Program, status: u32) -> TraceArchive {
    let io = GuestIo {
        input: Vec::new(),
        hint: Vec::new(),
    };
    let (traces, log, profile, execution) =
        trace_run(&program.image, &io, &program.tables, &program.config).expect("the guest traces");
    assert_eq!(execution.exit_code, status as i32);
    TraceArchive::from_execution(
        traces,
        log,
        profile,
        IoStreams {
            input: execution.io.input,
            output: execution.io.output,
        },
        PhaseTiming { wall_nanos: 0 },
    )
}

pub fn setup() -> ProverSetup {
    ProverSetup::new(program(), toy_srs(ADD_VARS)).expect("addsub registers")
}

pub fn control_setup() -> ProverSetup {
    ProverSetup::new(control_program(), toy_srs(ADD_VARS)).expect("control registers")
}

pub fn alu_setup() -> ProverSetup {
    ProverSetup::new(alu_program(), toy_srs(ADD_VARS)).expect("alu registers")
}

pub fn mem_setup() -> ProverSetup {
    ProverSetup::new(mem_program(), toy_srs(ADD_VARS)).expect("mem registers")
}

/// The toy SRS's `tau`.
pub fn toy_tau() -> Fr {
    Fr::from_hex("0x0000000000000000000000000000000000000000000000000000000000c0ffee")
        .expect("a canonical literal")
}

/// An SRS of `2^power` powers of a `tau` written down here: real, structurally
/// valid and completely insecure, built the way `crates/pcs`' suite builds one
/// and loaded through `Srs::load`. The archive is kept under cargo's
/// workspace-wide integration-test directory (`CARGO_TARGET_TMPDIR`,
/// `<target>/tmp`), so every suite that includes this module — the prover's,
/// the verifier's and the checker's — loads it instead of building it again;
/// its content is a function of `power` alone, and a file that does not load
/// is rebuilt.
pub fn toy_srs(power: u32) -> srs::Srs {
    use curve::{G1Projective, G2Affine};
    use rayon::prelude::*;

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join(format!("s16-toy-{power}.srs"));
    if let Ok(srs) = srs::Srs::load(&path) {
        return srs;
    }
    let tau = toy_tau();
    let count = 1usize << power;
    let mut scalars = Vec::with_capacity(count);
    let mut acc = Fr::ONE;
    for _ in 0..count {
        scalars.push(acc);
        acc *= tau;
    }
    let projective: Vec<G1Projective> = scalars
        .par_iter()
        .map(|s| G1Projective::GENERATOR.mul(s))
        .collect();
    let g1 = G1Projective::batch_to_affine(&projective);
    let g2_tau = G2Affine::GENERATOR.mul(&tau);

    let mut bytes = Vec::with_capacity(280 + count * 64);
    bytes.extend_from_slice(b"APOGESRS");
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&power.to_le_bytes());
    bytes.extend_from_slice(&(count as u64).to_le_bytes());
    bytes.extend_from_slice(&G2Affine::GENERATOR.to_bytes());
    bytes.extend_from_slice(&g2_tau.to_bytes());
    for p in &g1 {
        bytes.extend_from_slice(&p.to_bytes());
    }
    std::fs::create_dir_all(&dir).expect("the test directory");
    // Written aside and renamed, so a suite running beside this one never
    // reads half a file.
    let partial = dir.join(format!("s16-toy-{power}.{}.partial", std::process::id()));
    std::fs::write(&partial, &bytes).expect("writing the toy archive");
    std::fs::rename(&partial, &path).expect("placing the toy archive");
    srs::Srs::load(&path).expect("the toy archive loads")
}
