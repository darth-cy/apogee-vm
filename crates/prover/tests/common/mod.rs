//! The S16 statement every suite proves: `guests/addsub`'s committed ELF,
//! decoded with its execution family at `2^20` rows — the timestamp channel's
//! floor — and everything else at `2^16`, traced into an archive, over a toy
//! SRS whose `tau` is written down here. Test-only.

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

pub fn elf() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../loader/tests/vectors/addsub.elf");
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

pub fn params() -> ProgramParams {
    let mut heights = [1 << WINDOW_VARS; family::COUNT as usize];
    heights[family::ADD_SUB_LUI_AUIPC as usize] = 1 << ADD_VARS;
    ProgramParams {
        heights,
        ..ProgramParams::defaults()
    }
}

pub fn program() -> Program {
    let image = load_elf(&elf()).expect("addsub loads");
    let (tables, config) = decode_program(&image, &params()).expect("addsub decodes");
    Program {
        image,
        tables,
        config,
    }
}

/// The post-execution archive of `addsub`'s one run.
pub fn archive(program: &Program) -> TraceArchive {
    let io = GuestIo {
        input: Vec::new(),
        hint: Vec::new(),
    };
    let (traces, log, profile, execution) =
        trace_run(&program.image, &io, &program.tables, &program.config).expect("addsub traces");
    assert_eq!(execution.exit_code, RESULT as i32);
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
    let tau = Fr::from_hex("0x0000000000000000000000000000000000000000000000000000000000c0ffee")
        .expect("a canonical literal");
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
