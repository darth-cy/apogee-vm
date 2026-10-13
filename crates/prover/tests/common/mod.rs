//! The statements the proving suites prove. Test-only.
//!
//! - `guests/addsub`, built from source, decoded with its execution family at
//!   `2^20` rows — the timestamp channel's floor — and everything else at
//!   `2^16`, traced into an archive.
//! - `guests/control`'s, the same way, with both of its execution families —
//!   add/sub and jump/branch/slt — at `2^20`.
//! - `guests/alu`'s, with all four of its execution families — those two,
//!   shift/bitwise and mul/div — at `2^20`.
//! - `guests/mem`'s, with five — add/sub, jump/branch/slt and the three
//!   memory-op families — at `2^20`. Its rows touch RAM, so it has a
//!   `ZERO_WINDOWS` shard.
//! - `guests/shards`', with add/sub and jump/branch/slt at `2^20`. Its add/sub
//!   family runs 1,064,970 cycles, past `2^20`, so it has **two shards of one
//!   family** — and it touches no RAM, so it has a family the config carries
//!   and no shard proves.
//!
//! Every guest here is built from `guests/` by `test_support::guest_elf`;
//! `crates/checker`'s and `crates/verifier`'s suites include this module too,
//! and depend on `test-support` for it.

#![allow(dead_code)]

use constants::family;
use emulator::{trace_run, GuestIo};
use loader::load_elf;
use program::{decode_program, ProgramParams};
use prover::{Program, ProverSetup};
use trace::{IoStreams, PhaseTiming, TraceArchive};
use verifier_core::{BlockProof, PublicInputs, ShardProof};

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

/// `guests/shards`' exit status: the number of its checks.
pub const SHARDS_RESULT: u32 = 2;

/// `guests/shards`' add/sub occupancy, which is what makes it two shards.
pub const SHARDS_ADD_CYCLES: u64 = 1_064_970;

/// Guest `name`'s ELF, built from `guests/`.
pub fn fixture(name: &str) -> Vec<u8> {
    test_support::guest_elf(name)
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

/// `control`'s heights: both of its execution families at `2^20`.
pub fn control_params() -> ProgramParams {
    heights(&[family::ADD_SUB_LUI_AUIPC, family::JUMP_BRANCH_SLT])
}

/// `alu`'s heights: all four of its execution families at `2^20`.
pub fn alu_params() -> ProgramParams {
    heights(&[
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::SHIFT_BITWISE,
        family::MUL_DIV,
    ])
}

/// `mem`'s heights: all five of its execution families at `2^20`.
pub fn mem_params() -> ProgramParams {
    heights(&[
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::MEM_WORD,
        family::MEM_SUBWORD,
        family::ATOMICS,
    ])
}

/// `shards`' heights: both of its execution families at `2^20`.
pub fn shards_params() -> ProgramParams {
    heights(&[family::ADD_SUB_LUI_AUIPC, family::JUMP_BRANCH_SLT])
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

pub fn shards_program() -> Program {
    program_of("shards", &shards_params())
}

/// `guests/public-io`, which reads its public input and its
/// advice with ordinary loads and writes its journal with ordinary stores
/// (`docs/spec/public-values.md`). Its execution families at `2^20`, the rest
/// at `2^16`.
pub fn public_io_program() -> Program {
    program_of(
        "public-io",
        &heights(&[
            family::ADD_SUB_LUI_AUIPC,
            family::JUMP_BRANCH_SLT,
            family::SHIFT_BITWISE,
            family::MUL_DIV,
            family::MEM_WORD,
            family::MEM_SUBWORD,
        ]),
    )
}

pub fn public_io_setup() -> ProverSetup {
    ProverSetup::new(public_io_program()).expect("public-io registers")
}

/// The eight public input bytes `guests/public-io` reads: the advice's length
/// and the checksum it must have.
pub fn public_io_input(advice: &[u8]) -> Vec<u8> {
    let mut sum = 0u32;
    for (i, byte) in advice.iter().enumerate() {
        sum = sum.wrapping_add((*byte as u32).wrapping_mul(i as u32 + 1));
    }
    let mut input = (advice.len() as u32).to_le_bytes().to_vec();
    input.extend_from_slice(&sum.to_le_bytes());
    input
}

/// The journal `guests/public-io` commits for `advice`: the checksum, then the
/// first eight advice bytes.
pub fn public_io_journal(advice: &[u8]) -> Vec<u8> {
    let mut out = public_io_input(advice)[4..].to_vec();
    out.extend_from_slice(&advice[..8.min(advice.len())]);
    out
}

/// The post-execution archive of one `guests/public-io` run on `advice`, with
/// the public input that advice checks against.
pub fn public_io_archive(program: &Program, advice: &[u8]) -> TraceArchive {
    let io = GuestIo {
        input: public_io_input(advice),
        advice: advice.to_vec(),
    };
    let (traces, log, profile, execution) =
        trace_run(&program.image, &io, &program.tables, &program.config).expect("the guest traces");
    assert_eq!(execution.exit_code, 0, "the guest accepted its advice");
    assert_eq!(
        execution.io.output,
        public_io_journal(advice),
        "the journal is what the guest committed"
    );
    TraceArchive::from_execution(
        traces,
        log,
        profile,
        IoStreams {
            input: execution.io.input,
            output: execution.io.output,
        },
        io.advice,
        PhaseTiming { wall_nanos: 0 },
    )
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

/// The post-execution archive of `shards`' one run.
pub fn shards_archive(program: &Program) -> TraceArchive {
    trace(program, SHARDS_RESULT)
}

/// A run with no input and no hint, which must exit with `status`.
pub fn trace(program: &Program, status: u32) -> TraceArchive {
    let io = GuestIo {
        input: Vec::new(),
        advice: Vec::new(),
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
        Vec::new(),
        PhaseTiming { wall_nanos: 0 },
    )
}

/// **The one proving path's backpressure, for the suites.**
///
/// `prover::prove_block_streaming` proves at most this many shards at once,
/// so it is what bounds a suite's peak (`docs/spec/streaming.md` §5). Four
/// rather than eight: an `#[ignore]`d suite is run for its verdict and not for
/// its wall clock, and the measured difference between the two is 14% of the
/// time against 6.8 GiB of peak. The block does not depend on it —
/// `tests/streaming.rs` proves the bytes equal at 1 and 8 — so no test's
/// assertion rests on the number.
pub const IN_FLIGHT: usize = 4;

/// A run with nothing on any stream: what every committed guest but
/// `public-io` takes.
pub fn empty_io() -> GuestIo {
    GuestIo {
        input: Vec::new(),
        advice: Vec::new(),
    }
}

/// `guests/public-io`'s run over `advice`, with the public input that advice
/// checks against.
pub fn public_io_io(advice: &[u8]) -> GuestIo {
    GuestIo {
        input: public_io_input(advice),
        advice: advice.to_vec(),
    }
}

/// **Prove one execution as a block, the only way this repository proves.**
///
/// `prover::prove_block_streaming` at [`IN_FLIGHT`]. No suite calls
/// `prover::prove_block`: the archived path's per-shard component serves
/// `checker`'s column-fill suites and `checker::TamperHarness`, which build
/// their columns from a `TraceArchive` (`docs/spec/streaming.md` §6).
pub fn streamed(setup: &ProverSetup, io: &GuestIo) -> BlockProof {
    let (block, report) =
        prover::prove_block_streaming(setup, io, IN_FLIGHT).expect("the block proves");
    assert!(
        report.peak_in_flight <= IN_FLIGHT,
        "{} shards in flight above the bound {IN_FLIGHT}",
        report.peak_in_flight
    );
    block
}

/// The statement and its shard proofs, which is what `prover::finish` hands
/// back on the archived path.
///
/// A `BlockProof` carries both, in statement order, so a suite that verifies
/// loose shards takes them from the block rather than from a second proving
/// run (`docs/spec/proof.md` §1.3).
pub fn streamed_shards(setup: &ProverSetup, io: &GuestIo) -> (PublicInputs, Vec<ShardProof>) {
    let block = streamed(setup, io);
    (block.statement, block.shards)
}

pub fn setup() -> ProverSetup {
    ProverSetup::new(program()).expect("addsub registers")
}

pub fn control_setup() -> ProverSetup {
    ProverSetup::new(control_program()).expect("control registers")
}

pub fn alu_setup() -> ProverSetup {
    ProverSetup::new(alu_program()).expect("alu registers")
}

pub fn mem_setup() -> ProverSetup {
    ProverSetup::new(mem_program()).expect("mem registers")
}

pub fn shards_setup() -> ProverSetup {
    ProverSetup::new(shards_program()).expect("shards registers")
}
