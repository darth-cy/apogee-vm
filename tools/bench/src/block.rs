//! `cargo run --release -p bench -- prove <fixture> [options]` — the proving
//! job behind [`crate::report::BenchReport`].
//!
//! This is a **verb**, not a routine: every other entry in `ROUTINES` is a
//! micro-measurement over a synthetic input that takes no arguments, and a
//! proving job needs to be told which block and what the hardware costs. Adding
//! a parameter to the routine table would have meant changing eight signatures
//! for one caller; `main` matches this verb first and falls through to the
//! table, which is the smaller change.
//!
//! # What it measures, and what it does not
//!
//! It proves the pinned fixture end to end and verifies the result, filling
//! every field of the report from the run. The per-stage timings are the
//! `TraceArchive`'s own phase sections — must-be-exact 5 — and the crate's
//! standing rule still holds: **no assertions, no thresholds**. The one thing
//! it does assert is that the proof verifies, because a timing for a proof that
//! does not verify is not a measurement of anything.
//!
//! # The SRS
//!
//! A proving key needs powers of tau. The ceremony file is 19 GB and gitignored
//! (`docs/spec/srs.md`), and the `msm` and `mercury` routines here already
//! print a line and return when it is absent — the established pattern for a
//! routine whose input may be missing. This one does the same, except that it
//! can also run over a **toy** SRS when asked: the timings are identical, the
//! identity is not, and the report says which was used so that nobody reads a
//! toy-SRS identity as a published one.

use std::path::PathBuf;
use std::time::Instant;

use constants::family;
use host::fixture::{self, Mode, Pin};
use program::ProgramParams;
use srs::Srs;

use crate::report::{self, BenchReport, Phases};

/// Where the fixtures live.
fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/host/tests/vectors")
}

/// The ceremony file, and the power a `2^20` statement needs from it.
///
/// One file at power 24, as `tools/kat-gen/src/program.rs` and
/// `crates/program/tests` already name it; `Srs::from_ptau` reads the first
/// `2^POWER` points of it, so the 19 GB on disk costs about 268 MB of reading
/// rather than all of it.
const PTAU: &str = "assets/ptau/ppot_0080_24.ptau";
const POWER: u32 = 22;

fn ceremony() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(PTAU);
    path.exists().then_some(path)
}

/// What the verb was asked for.
pub struct Options {
    /// The fixture stem, e.g. `mini-block`.
    pub fixture: String,
    /// Where to write the JSON, if anywhere.
    pub json: Option<PathBuf>,
    /// The hardware's on-demand price per hour.
    pub hourly_usd: Option<f64>,
    /// Use a toy SRS rather than the ceremony. Same timings, different
    /// identity.
    pub toy_srs: bool,
}

pub fn run(options: &Options) {
    let dir = vectors();
    let pin_bytes = match std::fs::read(dir.join(fixture::pin_file(&options.fixture))) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!(
                "prove: no fixture `{}` under {} ({e}). \
                 `cargo run -p kat-gen -- block` records one; it needs ETH_RPC_URL.",
                options.fixture,
                dir.display()
            );
            return;
        }
    };
    let pin = Pin::from_bytes(&pin_bytes).expect("the pin decodes");
    let witness = match std::fs::read(dir.join(fixture::witness_file(&options.fixture))) {
        Ok(bytes) => bytes,
        Err(e) => {
            println!(
                "prove: the `{}` pin is committed but its witness is not ({e}). \
                 The full block's witness is megabytes and is regenerated rather than \
                 carried; `cargo run -p kat-gen -- block` writes it.",
                options.fixture
            );
            return;
        }
    };
    if let Err(e) = pin.check(&witness, &[]) {
        // The journal is checked below against what the run produces, so only
        // the witness half is checked here.
        if !e.contains("journal") {
            println!("prove: {e}");
            return;
        }
    }

    let srs = match load_srs(options.toy_srs) {
        Some(srs) => srs,
        None => return,
    };

    let elf = build_guest(pin.mode);
    let params = heights();

    let setup_started = Instant::now();
    let setup = match host::setup(&elf, &params, srs.0) {
        Ok(setup) => setup,
        Err(e) => {
            println!("prove: the guest does not register: {e}");
            return;
        }
    };
    let setup_ms = millis(setup_started.elapsed().as_nanos() as u64);

    let io = emulator::GuestIo {
        stdin: Vec::new(),
        input: Vec::new(),
        advice: witness,
        hint: Vec::new(),
    };
    let proven = match host::prove(&setup, &io) {
        Ok(proven) => proven,
        Err(e) => {
            println!("prove: {e}");
            return;
        }
    };
    assert_eq!(
        proven.exit_code, 0,
        "the guest exited {}; a timing for a run that did not produce a journal \
         is not a measurement of anything",
        proven.exit_code
    );

    let verify_started = Instant::now();
    host::verify(&setup.vk, &proven.block).expect("the block verifies");
    let verify_ms = millis(verify_started.elapsed().as_nanos() as u64);

    let phases = Phases {
        execution_ms: phase_ms(&proven.archive, trace::Phase::PostExecution),
        commit_ms: phase_ms(&proven.archive, trace::Phase::PostCommit),
        gkr_ms: phase_ms(&proven.archive, trace::Phase::PostGkr),
        opening_ms: phase_ms(&proven.archive, trace::Phase::PostOpening),
        final_ms: phase_ms(&proven.archive, trace::Phase::Final),
    };
    let proving_ms = millis(proven.wall_nanos);
    let (peak_rss_bytes, peak_rss_source) = report::peak_rss();
    let statement = proven.block.statement();

    let mut out = BenchReport {
        fixture: options.fixture.clone(),
        mode: match pin.mode {
            Mode::Mini => "mini".to_string(),
            Mode::Stateless => "stateless".to_string(),
        },
        block_number: pin.block_number,
        block_hash: pin.block_hash.clone(),
        txs: pin.txs_recorded,
        gas_used: pin.gas_used,
        program_identity: hex(&setup.vk.identity.to_bytes()),
        srs: srs.1,
        guest_cycles: proven.cycles,
        cycles_per_gas: if pin.gas_used == 0 {
            0.0
        } else {
            proven.cycles as f64 / pin.gas_used as f64
        },
        shards: setup
            .program
            .config
            .families
            .iter()
            .zip(statement.shard_counts.iter())
            .map(|((f, _), count)| (family_name(*f), *count))
            .collect(),
        total_shards: statement.shard_counts.iter().sum(),
        proof_bytes: proven.block.to_bytes().len(),
        statement_bytes: statement.to_bytes().len(),
        setup_ms,
        phases,
        proving_ms,
        unattributed_ms: proving_ms - phases.total_ms(),
        verify_ms,
        peak_rss_bytes,
        peak_rss_source,
        hourly_price_usd: None,
        cost_usd: None,
        cost_per_mgas_usd: None,
        cost_basis: String::new(),
        hardware: report::hardware(),
    };
    out.price(options.hourly_usd);

    // The journal the proof binds is the one the fixture pins.
    let journal = std::fs::read(dir.join(fixture::journal_file(&options.fixture)))
        .expect("the pinned journal");
    assert_eq!(
        proven.journal, journal,
        "the proved journal is not the pinned one, so the fixture is stale"
    );

    print!("{}", out.to_table());
    if let Some(path) = &options.json {
        std::fs::write(path, out.to_json()).unwrap_or_else(|e| {
            panic!("writing {}: {e}", path.display());
        });
        println!("\n  json written to {}", path.display());
    }
}

/// The SRS, and what to call it in the report.
fn load_srs(toy: bool) -> Option<(Srs, String)> {
    if !toy {
        match ceremony() {
            Some(path) => {
                let srs = Srs::from_ptau(&path, POWER).unwrap_or_else(|e| {
                    panic!("reading {}: {e:?}", path.display());
                });
                return Some((
                    srs,
                    format!("PSE perpetual powers of tau, contribution 80, 2^{POWER} of {PTAU}"),
                ));
            }
            None => {
                println!(
                    "prove: {PTAU} is absent, so no key can be built over the ceremony. \
                     Pass --toy-srs for a run whose timings are the same and whose identity \
                     is not a published one."
                );
                return None;
            }
        }
    }
    Some((
        toy_srs(),
        "a toy SRS with a written-down tau, NOT the ceremony".into(),
    ))
}

/// A structurally valid SRS over a tau written down in this file.
///
/// Completely insecure, and that is the point of saying so in the report: a
/// timing does not depend on which powers of tau a key was built over, and an
/// identity does. `crates/prover/tests/common/mod.rs` has the same constructor
/// for the same reason; the two are copies because a test module cannot be
/// shared across a crate boundary, which is the arrangement this repository
/// already has for the guest-build helper.
fn toy_srs() -> Srs {
    use curve::{G1Projective, G2Affine};
    use field::Fr;
    use rayon::prelude::*;

    let power = POWER;
    let dir = std::env::temp_dir();
    let path = dir.join(format!("apogee-bench-toy-{power}.srs"));
    if let Ok(srs) = Srs::load(&path) {
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
    let partial = dir.join(format!(
        "apogee-bench-toy-{power}.{}.partial",
        std::process::id()
    ));
    std::fs::write(&partial, &bytes).expect("writing the toy archive");
    std::fs::rename(&partial, &path).expect("placing the toy archive");
    Srs::load(&path).expect("the toy archive loads")
}

/// The heights this workload is preprocessed under.
fn heights() -> ProgramParams {
    let mut heights = [revm_block::TRACE_HEIGHT_RELEASE; family::COUNT as usize];
    for (f, h) in heights.iter_mut().enumerate() {
        if program::delegation_ecall(f as u32).is_some() {
            *h = family::DEFAULT_HEIGHTS[f];
        }
    }
    ProgramParams {
        heights,
        bytecode_size_words: revm_block::BYTECODE_SIZE_WORDS,
        ..ProgramParams::defaults()
    }
}

/// The guest binary for a mode, built from source at `--release`.
///
/// Always `--release`, whatever `APOGEE_GUEST_PROFILE` says, for the reason
/// `crates/prover/tests/revm.rs` gives: the heights are pinned to the release
/// image, and the debug image needs `2^22` — four times the rows in every
/// shard, for a build nothing proves.
fn build_guest(mode: Mode) -> Vec<u8> {
    let bin = mode.binary();
    let guest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../guests/revm-block");
    let target_dir = std::env::temp_dir().join(format!("apogee-bench-{bin}"));
    let _ = std::fs::remove_dir_all(&target_dir);
    let mut command =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(&guest_dir)
        .args([
            "build",
            "--release",
            "--target",
            "riscv32imac-unknown-none-elf",
            "--bin",
            bin,
        ])
        .env("CARGO_TARGET_DIR", &target_dir);
    for key in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        command.env_remove(key);
    }
    let out = command.output().expect("running cargo for the guest");
    assert!(
        out.status.success(),
        "{bin}: guest build failed\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let elf = target_dir
        .join("riscv32imac-unknown-none-elf/release")
        .join(bin);
    let bytes = std::fs::read(&elf).unwrap_or_else(|e| panic!("reading {}: {e}", elf.display()));
    let _ = std::fs::remove_dir_all(&target_dir);
    bytes
}

fn phase_ms(archive: &trace::TraceArchive, phase: trace::Phase) -> f64 {
    archive
        .timing(phase)
        .map(|t| millis(t.wall_nanos))
        .unwrap_or(0.0)
}

fn millis(nanos: u64) -> f64 {
    nanos as f64 / 1e6
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A family's name, as `constants::family` spells it.
fn family_name(id: u32) -> String {
    let name = match id {
        family::ADD_SUB_LUI_AUIPC => "ADD_SUB_LUI_AUIPC",
        family::JUMP_BRANCH_SLT => "JUMP_BRANCH_SLT",
        family::SHIFT_BITWISE => "SHIFT_BITWISE",
        family::MUL_DIV => "MUL_DIV",
        family::MEM_WORD => "MEM_WORD",
        family::MEM_SUBWORD => "MEM_SUBWORD",
        family::ATOMICS => "ATOMICS",
        family::INIT_TEARDOWN => "INIT_TEARDOWN",
        family::ZERO_WINDOWS => "ZERO_WINDOWS",
        family::KECCAK_F => "KECCAK_F",
        family::POSEIDON2 => "POSEIDON2",
        family::FR_ARITH => "FR_ARITH",
        family::PUBLIC_INPUT => "PUBLIC_INPUT",
        family::PUBLIC_OUTPUT => "PUBLIC_OUTPUT",
        family::ADVICE_WINDOWS => "ADVICE_WINDOWS",
        _ => return format!("family {id}"),
    };
    name.to_string()
}

/// `--help` for this verb.
pub fn usage() -> &'static str {
    "  prove <fixture> [--json <path>] [--hourly-usd <price>] [--toy-srs]\n\
     \x20     prove a recorded block and emit a BenchReport as a table and, with\n\
     \x20     --json, as JSON. <fixture> is a stem under crates/host/tests/vectors,\n\
     \x20     e.g. mini-block. --hourly-usd is the machine's on-demand price, which\n\
     \x20     is what the cost estimate is computed from."
}

/// Parse the verb's arguments.
pub fn parse(args: &[String]) -> Result<Options, String> {
    let mut fixture = None;
    let mut json = None;
    let mut hourly_usd = None;
    let mut toy_srs = false;
    let mut at = 0;
    while at < args.len() {
        match args[at].as_str() {
            "--json" => {
                at += 1;
                json = Some(PathBuf::from(
                    args.get(at).ok_or("--json needs a path")?.clone(),
                ));
            }
            "--hourly-usd" => {
                at += 1;
                hourly_usd = Some(
                    args.get(at)
                        .ok_or("--hourly-usd needs a price")?
                        .parse::<f64>()
                        .map_err(|e| format!("--hourly-usd is not a number: {e}"))?,
                );
            }
            "--toy-srs" => toy_srs = true,
            other if other.starts_with("--") => return Err(format!("unknown option `{other}`")),
            other if fixture.is_none() => fixture = Some(other.to_string()),
            other => return Err(format!("unexpected argument `{other}`")),
        }
        at += 1;
    }
    Ok(Options {
        fixture: fixture.ok_or("prove needs a fixture stem, e.g. `mini-block`")?,
        json,
        hourly_usd,
        toy_srs,
    })
}
