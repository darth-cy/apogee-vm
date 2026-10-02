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
//! streaming run's own four clocks (`prover::StreamingReport`) — since
//! S-STREAM there is no `TraceArchive` and so no phase sections — and the
//! crate's standing rule still holds: **no assertions, no thresholds**. The one
//! thing it does assert is that the proof verifies, because a timing for a
//! proof that does not verify is not a measurement of anything.
//!
//! # Failure
//!
//! **Every way the verb fails is a non-zero exit.** The ordinary failures come
//! back from [`run`] as an error that `main` prints to stderr before exiting 1:
//! a fixture or witness that is not there, no ceremony without `--toy-srs`, a
//! guest that does not build or register, a block that does not prove, and an
//! `--out` directory the proof does not write to. That last one fails only
//! after the report is printed, because the measurement is still good and it
//! cost the whole run. What the verb asserts still panics, and a usage error
//! still exits 2. Until S-STREAM's review the ordinary failures each printed a
//! line and exited 0, so a script waiting on a proof could not tell that none
//! had been made.
//!
//! # The SRS
//!
//! A proving key needs powers of tau. The ceremony file is 19 GB and gitignored
//! (`docs/spec/srs.md`), and the `msm` and `mercury` routines here print a line
//! and return when it is absent — the established pattern for a *routine* whose
//! input may be missing. This verb is a job someone asked for by name, so it
//! fails instead; what it can do that they cannot is run over a **toy** SRS
//! when asked: the timings are identical, the identity is not, and the report
//! says which was used so that nobody reads a toy-SRS identity as a published
//! one.

use std::path::PathBuf;
use std::time::Instant;

use host::fixture::{self, Mode, Pin};
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
    /// How many shards the **streaming** prover proves at once
    /// (`docs/spec/streaming.md` §5), which is what bounds the peak.
    ///
    /// Not an `Option` since S-STREAM: streaming is the only proving path, so
    /// there is no second arm for this to select and the flag only tunes the
    /// one. [`DEFAULT_IN_FLIGHT`] is what an unset `--in-flight` means.
    pub in_flight: usize,
    /// Where to write the proved block's four files, if anywhere
    /// (`verifier::proof_archive`). **The only thing a proving run archives.**
    pub out: Option<PathBuf>,
}

/// `--in-flight`'s default: eight shards at once.
///
/// Measured on a 51-shard mini-block at 247 GiB: four in flight peaked at
/// 77.10 GiB and eight at 83.91, and the extra four were worth 14% of the
/// wall clock — 6.8 GiB for 214 s. Eight is therefore the better default on
/// any machine that can hold it, and a machine that cannot says so with the
/// flag. The block does not depend on it
/// (`crates/prover/tests/streaming.rs`).
pub const DEFAULT_IN_FLIGHT: usize = 8;

/// Prove the fixture, verify it and print the report.
///
/// Every ordinary failure comes back as an error naming what failed, which
/// `main` prints and exits 1 on (`# Failure` above); what the verb asserts
/// still panics.
pub fn run(options: &Options) -> Result<(), String> {
    let dir = vectors();
    let pin_bytes = std::fs::read(dir.join(fixture::pin_file(&options.fixture))).map_err(|e| {
        format!(
            "no fixture `{}` under {} ({e}). \
             `cargo run -p kat-gen -- block` records one; it needs ETH_RPC_URL.",
            options.fixture,
            dir.display()
        )
    })?;
    let pin = Pin::from_bytes(&pin_bytes).expect("the pin decodes");
    let witness =
        std::fs::read(dir.join(fixture::witness_file(&options.fixture))).map_err(|e| {
            format!(
                "the `{}` pin is committed but its witness is not ({e}). \
                 The full block's witness is megabytes and is regenerated rather than \
                 carried; `cargo run -p kat-gen -- block` writes it.",
                options.fixture
            )
        })?;
    if let Err(e) = pin.check(&witness, &[]) {
        // The journal is checked below against what the run produces, so only
        // the witness half is checked here.
        if !e.contains("journal") {
            return Err(e);
        }
    }

    let srs = load_srs(options.toy_srs)?;

    let elf = fixture::build_revm_guest(pin.mode)?;
    let params = fixture::revm_params();

    let setup_started = Instant::now();
    let setup = host::setup(&elf, &params, srs.0)
        .map_err(|e| format!("the guest does not register: {e}"))?;
    let setup_ms = millis(setup_started.elapsed().as_nanos() as u64);

    let io = emulator::GuestIo {
        input: Vec::new(),
        advice: witness,
    };
    // **One proving path** (S-STREAM). There is no archive and so no five
    // phase sections: the four clocks the `StreamingReport` carries are mapped
    // onto the four names the report already has, and the printed table says
    // how (`crate::report::BenchReport::in_flight`). `opening_ms` and
    // `final_ms` are 0.0 because the streaming prover does not separate them
    // from `gkr_ms` — one shard's GKR and its opening are one interval there.
    let proving_started = Instant::now();
    let proven = host::prove(&setup, &io, options.in_flight)?;
    let report = proven.report;
    let phases = Phases {
        execution_ms: millis(report.pass1_execute_ns + report.pass2_execute_ns),
        commit_ms: millis(report.pass1_commit_ns),
        gkr_ms: millis(report.pass2_prove_ns),
        opening_ms: 0.0,
        final_ms: 0.0,
    };
    let (block, exit_code, cycles) = (proven.block, proven.exit_code, proven.cycles);
    let proving_ms = millis(proving_started.elapsed().as_nanos() as u64);
    assert_eq!(
        exit_code, 0,
        "the guest exited {exit_code}; a timing for a run that did not produce a journal \
         is not a measurement of anything"
    );

    let verify_started = Instant::now();
    host::verify(&setup.vk, &block).expect("the block verifies");
    let verify_ms = millis(verify_started.elapsed().as_nanos() as u64);

    // **The one thing a proving run archives**, and only after it verified:
    // a proof that does not verify is not worth a reader's disk, and a reader
    // is the point — recursion development loads these four back through
    // `verifier::proof_archive::read_proof` (S-STREAM). A write that fails
    // fails the run, but only once the report is out: the measurement below is
    // still good, and it cost the whole run.
    let archived = match &options.out {
        Some(dir) => {
            match host::proof_archive::write_proof(dir, &options.fixture, &setup.vk, &block) {
                Ok(paths) => {
                    println!("wrote {}", paths.block.display());
                    Ok(())
                }
                Err(e) => Err(format!("the proof does not write: {e}")),
            }
        }
        None => Ok(()),
    };
    let (peak_rss_bytes, peak_rss_source) = report::peak_rss();
    let statement = block.statement();

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
        in_flight: Some(options.in_flight),
        guest_cycles: cycles,
        cycles_per_gas: if pin.gas_used == 0 {
            0.0
        } else {
            cycles as f64 / pin.gas_used as f64
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
        proof_bytes: block.to_bytes().len(),
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
        statement.output, journal,
        "the proved journal is not the pinned one, so the fixture is stale"
    );

    print!("{}", out.to_table());
    if let Some(path) = &options.json {
        std::fs::write(path, out.to_json()).unwrap_or_else(|e| {
            panic!("writing {}: {e}", path.display());
        });
        println!("\n  json written to {}", path.display());
    }
    archived
}

/// The SRS, and what to call it in the report.
fn load_srs(toy: bool) -> Result<(Srs, String), String> {
    if !toy {
        match ceremony() {
            Some(path) => {
                let srs = Srs::from_ptau(&path, POWER).unwrap_or_else(|e| {
                    panic!("reading {}: {e:?}", path.display());
                });
                return Ok((
                    srs,
                    format!("PSE perpetual powers of tau, contribution 80, 2^{POWER} of {PTAU}"),
                ));
            }
            None => {
                return Err(format!(
                    "{PTAU} is absent, so no key can be built over the ceremony. \
                     Pass --toy-srs for a run whose timings are the same and whose identity \
                     is not a published one."
                ));
            }
        }
    }
    Ok((
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

fn millis(nanos: u64) -> f64 {
    nanos as f64 / 1e6
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A family's name, as `program::family_name` spells it.
///
/// One source: this file carried its own table until S-STREAM, and it was a
/// stale one — it stopped at `MOD_MUL`, so a report printed "family 16" and
/// "family 17" where S26c's `SHA256_COMP` and `EC_ADD` belonged. The defect
/// was the second source of one fact, not the two missing arms.
fn family_name(id: u32) -> String {
    program::family_name(id).to_string()
}

/// `--help` for this verb.
pub fn usage() -> &'static str {
    "  prove <fixture> [--json <path>] [--hourly-usd <price>] [--toy-srs]\n\
     \x20            [--in-flight <n>] [--out <dir>]\n\
     \x20     prove a recorded block and emit a BenchReport as a table and, with\n\
     \x20     --json, as JSON. <fixture> is a stem under crates/host/tests/vectors,\n\
     \x20     e.g. mini-block. --hourly-usd is the machine's on-demand price, which\n\
     \x20     is what the cost estimate is computed from. Proving is always the\n\
     \x20     STREAMING prover; --in-flight <n> is how many shards it proves at\n\
     \x20     once, which is what bounds the peak (default 8,\n\
     \x20     docs/spec/streaming.md). --out <dir> writes the verified block's\n\
     \x20     four files there -- <fixture>.vk, .identity, .public and .block.\n\
     \x20     `verifier block` reads the .vk, .public and .block; its identity\n\
     \x20     is 64 hex digits from your own channel, and .identity is only what\n\
     \x20     the run claimed. Exits 1 if anything fails, --out included."
}

/// Parse the verb's arguments.
pub fn parse(args: &[String]) -> Result<Options, String> {
    let mut fixture = None;
    let mut json = None;
    let mut hourly_usd = None;
    let mut toy_srs = false;
    let mut in_flight = DEFAULT_IN_FLIGHT;
    let mut out = None;
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
            "--in-flight" => {
                at += 1;
                let n = args
                    .get(at)
                    .ok_or("--in-flight needs a count")?
                    .parse::<usize>()
                    .map_err(|e| format!("--in-flight is not a count: {e}"))?;
                if n == 0 {
                    return Err("--in-flight must be at least 1".into());
                }
                in_flight = n;
            }
            "--out" => {
                at += 1;
                out = Some(PathBuf::from(
                    args.get(at).ok_or("--out needs a directory")?.clone(),
                ));
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
        in_flight,
        out,
    })
}
