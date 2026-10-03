//! `cargo run --release -p bench -- prove <fixture> [options]` — the proving
//! job behind [`crate::report::BenchReport`] — and `prove --stateless <file>`,
//! the same job over one canonical stateless input.
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
//! streaming run's own clocks (`prover::StreamingReport`) — since S-STREAM
//! there is no `TraceArchive` and so no phase sections — and the
//! crate's standing rule still holds: **no assertions, no thresholds**. The one
//! thing it does assert is that the proof verifies, because a timing for a
//! proof that does not verify is not a measurement of anything.
//!
//! # A stateless input
//!
//! `--stateless <file>` proves `revm-block-stateless` over one
//! `statelessInputBytes`: an EEST fixture JSON's — a `tests-zkevm` release, or
//! the zkEVM benchmark's devnet datasets — or a file holding nothing but those
//! bytes. **The bytes reach the guest's advice exactly as the file holds
//! them**: the guest is given a canonical stateless input and nothing about
//! where it came from. A fixture's `statelessOutputBytes` is the journal the
//! proof must bind — checked natively first, because the library is the guest's
//! own code and a mismatch it already shows would cost a whole proof to learn,
//! and then on the proof. A raw file has nothing to check against, so the
//! journal is printed for the reader.
//!
//! # Failure
//!
//! **Every way the verb fails is a non-zero exit.** The ordinary failures come
//! back from [`run`] as an error that `main` prints to stderr before exiting 1:
//! a fixture, witness, journal or stateless input that is not there, an input
//! that is empty or that `--case` does not pick out of its file, no ceremony
//! without `--toy-srs`, a guest that does not build or register, a block that
//! does not prove, a proved journal that is not the expected one, and an
//! `--out` directory the proof does not write to. The last two fail only after
//! the report is printed, because the measurement is still good and it cost
//! the whole run. What the verb asserts still panics, and a usage error still
//! exits 2. Until S-STREAM's review the ordinary failures each printed a line
//! and exited 0, so a script waiting on a proof could not tell that none had
//! been made.
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

use std::path::{Path, PathBuf};
use std::time::Instant;

use host::fixture::{self, Mode, Pin};
use host::zkevm;
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

/// Which block the verb proves.
pub enum Source {
    /// A recorded block's stem under `crates/host/tests/vectors`, e.g.
    /// `mini-block`: its pinned witness, proved by the guest its pin names.
    Fixture(String),
    /// One stateless input, proved by `revm-block-stateless`: an EEST fixture
    /// JSON's `statelessInputBytes`, or a file of nothing else. `case` picks
    /// one input out of a JSON holding several.
    Stateless { path: PathBuf, case: Option<String> },
}

/// What the verb was asked for.
pub struct Options {
    /// The block.
    pub source: Source,
    /// Where to write the JSON, if anywhere.
    pub json: Option<PathBuf>,
    /// The hardware's on-demand price per hour.
    pub hourly_usd: Option<f64>,
    /// Use a toy SRS rather than the ceremony. Same timings, different
    /// identity.
    pub toy_srs: bool,
    /// How many workers the **streaming** prover runs, each holding one shard
    /// at a time (`docs/spec/streaming.md` §5), which is what bounds the peak.
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

/// One proving job, wherever its block came from.
struct Job {
    /// What the report and `--out`'s files call it: the fixture's stem, or the
    /// stateless input file's.
    name: String,
    mode: Mode,
    /// The guest's advice, exactly as the source holds it.
    advice: Vec<u8>,
    /// The journal the proof must bind, when the source says what it is.
    journal: Option<Vec<u8>>,
    block_number: u64,
    block_hash: String,
    txs: usize,
    gas_used: u64,
}

/// A recorded block: its pinned witness, and the journal its pin names.
fn fixture_job(stem: &str) -> Result<Job, String> {
    let dir = vectors();
    let pin_bytes = std::fs::read(dir.join(fixture::pin_file(stem))).map_err(|e| {
        format!(
            "no fixture `{stem}` under {} ({e}). \
             `cargo run -p kat-gen -- block` records one; it needs ETH_RPC_URL.",
            dir.display()
        )
    })?;
    let pin = Pin::from_bytes(&pin_bytes).expect("the pin decodes");
    let committed = |file: String, what: &str| {
        std::fs::read(dir.join(file)).map_err(|e| {
            format!(
                "the `{stem}` pin is committed but its {what} is not ({e}); \
                 `cargo run -p kat-gen -- block` re-records it."
            )
        })
    };
    let witness = committed(fixture::witness_file(stem), "witness")?;
    let journal = committed(fixture::journal_file(stem), "journal")?;
    pin.check(&witness, &journal)?;
    Ok(Job {
        name: stem.to_string(),
        mode: pin.mode,
        advice: witness,
        journal: Some(journal),
        block_number: pin.block_number,
        block_hash: pin.block_hash,
        txs: pin.txs_recorded,
        gas_used: pin.gas_used,
    })
}

/// One stateless input, handed on exactly as the file holds it. A `.json`
/// file is an EEST fixture, read with `host::zkevm`'s reader, and its
/// `statelessOutputBytes` is the journal the proof must bind; any other file
/// is the raw `statelessInputBytes`, with nothing to hold the journal to.
fn stateless_job(path: &Path, case: Option<&str>) -> Result<Job, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let (advice, journal) = if path.extension().is_some_and(|e| e == "json") {
        let fixture: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
        let mut pairs = zkevm::pairs_in(&fixture);
        pairs.retain(|pair| case.is_none_or(|case| pair.name.contains(case)));
        if pairs.len() != 1 {
            let names: Vec<&str> = pairs.iter().take(4).map(|p| p.name.as_str()).collect();
            return Err(format!(
                "{} holds {} stateless inputs{}; --case picks one by part of its name{}",
                path.display(),
                pairs.len(),
                case.map_or(String::new(), |case| format!(" matching `{case}`")),
                if names.is_empty() {
                    String::new()
                } else {
                    format!(": {} ...", names.join(", "))
                },
            ));
        }
        let pair = pairs.remove(0);
        (pair.input, Some(pair.output))
    } else if case.is_some() {
        return Err(format!(
            "--case picks an input out of a fixture JSON, and {} is a raw input",
            path.display()
        ));
    } else {
        (bytes, None)
    };
    if advice.is_empty() {
        return Err(
            "an empty input cannot be given to the guest: a run with no advice has \
                    no advice region (docs/spec/public-values.md §6), and the library \
                    answers it with the sentinel natively"
                .into(),
        );
    }
    if let Some(expected) = &journal {
        let native = revm_block::stateless::run(&advice);
        if native[..] != expected[..] {
            return Err(format!(
                "the library publishes {} ({}) where {} expects {}, and proving it would not \
                 change that",
                hex(&native),
                zkevm::verdict(&advice),
                path.display(),
                hex(expected)
            ));
        }
    }
    let (block_number, block_hash, txs, gas_used) = match revm_block::ssz::decode(&advice) {
        Some(input) => {
            let p = &input.request.payload;
            let hash = format!("0x{}", hex(&p.block_hash));
            (p.block_number, hash, p.transactions.len(), p.gas_used)
        }
        None => (0, String::new(), 0, 0),
    };
    Ok(Job {
        name: path.file_stem().map_or("stateless".into(), |stem| {
            stem.to_string_lossy().into_owned()
        }),
        mode: Mode::Stateless,
        advice,
        journal,
        block_number,
        block_hash,
        txs,
        gas_used,
    })
}

/// Prove the block, verify it and print the report.
///
/// Every ordinary failure comes back as an error naming what failed, which
/// `main` prints and exits 1 on (`# Failure` above); what the verb asserts
/// still panics.
pub fn run(options: &Options) -> Result<(), String> {
    let job = match &options.source {
        Source::Fixture(stem) => fixture_job(stem)?,
        Source::Stateless { path, case } => stateless_job(path, case.as_deref())?,
    };

    let srs = load_srs(options.toy_srs)?;

    let elf = fixture::build_revm_guest(job.mode)?;
    let params = fixture::revm_params();

    let setup_started = Instant::now();
    let setup = host::setup(&elf, &params, srs.0)
        .map_err(|e| format!("the guest does not register: {e}"))?;
    let setup_ms = millis(setup_started.elapsed().as_nanos() as u64);

    let io = emulator::GuestIo {
        input: Vec::new(),
        advice: job.advice,
    };
    // **One proving path** (S-STREAM), and since S-PIPELINE a pipelined one.
    // There is no archive and so no five phase sections: the `StreamingReport`'s
    // clocks are mapped onto the names the report already has, and the printed
    // table says how (`crate::report::Phases`). `commit_ms` and `gkr_ms` are
    // the two passes' wall clocks; `execution_ms` is the executor's time in
    // both, which runs inside them while the workers commit and prove, so it is
    // not a third slice of the wall. `opening_ms` and `final_ms` are 0.0
    // because the streaming prover does not separate them from `gkr_ms` — one
    // shard's GKR and its opening are one interval there.
    let proving_started = Instant::now();
    let proven = host::prove(&setup, &io, options.in_flight)?;
    let report = proven.report;
    let phases = Phases {
        execution_ms: millis(report.pass1_execute_ns + report.pass2_execute_ns),
        commit_ms: millis(report.pass1_ns),
        gkr_ms: millis(report.pass2_ns),
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
        Some(dir) => match host::proof_archive::write_proof(dir, &job.name, &setup.vk, &block) {
            Ok(paths) => {
                println!("wrote {}", paths.block.display());
                Ok(())
            }
            Err(e) => Err(format!("the proof does not write: {e}")),
        },
        None => Ok(()),
    };
    let (peak_rss_bytes, peak_rss_source) = report::peak_rss();
    let statement = block.statement();

    let mut out = BenchReport {
        fixture: job.name.clone(),
        mode: match job.mode {
            Mode::Mini => "mini".to_string(),
            Mode::Stateless => "stateless".to_string(),
        },
        block_number: job.block_number,
        block_hash: job.block_hash.clone(),
        txs: job.txs,
        gas_used: job.gas_used,
        program_identity: hex(&setup.vk.identity.to_bytes()),
        srs: srs.1,
        in_flight: Some(options.in_flight),
        guest_cycles: cycles,
        cycles_per_gas: if job.gas_used == 0 {
            0.0
        } else {
            cycles as f64 / job.gas_used as f64
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

    print!("{}", out.to_table());
    if let Some(path) = &options.json {
        std::fs::write(path, out.to_json()).unwrap_or_else(|e| {
            panic!("writing {}: {e}", path.display());
        });
        println!("\n  json written to {}", path.display());
    }

    // The journal the proof binds, against the one the source expects. Like a
    // failed `--out`, a mismatch fails after the report: the proof is good, but
    // it is a proof of something other than what was asked.
    let bound = match &job.journal {
        Some(expected) if statement.output == *expected => {
            println!(
                "\n  journal: the {} bytes {} expects",
                expected.len(),
                job.name
            );
            Ok(())
        }
        Some(expected) => Err(format!(
            "the proved journal {} is not the {} that {} expects",
            hex(&statement.output),
            hex(expected),
            job.name
        )),
        None => {
            println!(
                "\n  journal: {}, with nothing to hold it to",
                hex(&statement.output)
            );
            Ok(())
        }
    };
    bound.and(archived)
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
     \x20     STREAMING prover; --in-flight <n> is how many shards it holds at\n\
     \x20     once, which is what bounds the peak (default 8,\n\
     \x20     docs/spec/streaming.md). --out <dir> writes the verified block's\n\
     \x20     four files there -- <fixture>.vk, .identity, .public and .block.\n\
     \x20     `verifier block` reads the .vk, .public and .block; its identity\n\
     \x20     is 64 hex digits from your own channel, and .identity is only what\n\
     \x20     the run claimed. Exits 1 if anything fails, --out included.\n\
     \x20 prove --stateless <file> [--case <name>] [the options above]\n\
     \x20     the same job over one stateless input, proved by revm-block-stateless.\n\
     \x20     <file> is an EEST fixture JSON, whose statelessInputBytes reach the\n\
     \x20     guest unchanged and whose statelessOutputBytes the proved journal must\n\
     \x20     equal, or a file of raw statelessInputBytes, with nothing to compare.\n\
     \x20     --case picks one input, by part of its name, out of a JSON holding\n\
     \x20     several."
}

/// Parse the verb's arguments.
pub fn parse(args: &[String]) -> Result<Options, String> {
    let mut fixture = None;
    let mut stateless = None;
    let mut case = None;
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
            "--stateless" => {
                at += 1;
                stateless = Some(PathBuf::from(
                    args.get(at).ok_or("--stateless needs a file")?.clone(),
                ));
            }
            "--case" => {
                at += 1;
                case = Some(args.get(at).ok_or("--case needs a name")?.clone());
            }
            "--toy-srs" => toy_srs = true,
            other if other.starts_with("--") => return Err(format!("unknown option `{other}`")),
            other if fixture.is_none() => fixture = Some(other.to_string()),
            other => return Err(format!("unexpected argument `{other}`")),
        }
        at += 1;
    }
    let source = match (fixture, stateless) {
        (Some(_), Some(_)) => return Err("a fixture and --stateless name two blocks".into()),
        (Some(_), None) if case.is_some() => {
            return Err("--case picks an input out of --stateless's file".into())
        }
        (Some(stem), None) => Source::Fixture(stem),
        (None, Some(path)) => Source::Stateless { path, case },
        (None, None) => {
            return Err(
                "prove needs a fixture stem, e.g. `mini-block`, or --stateless <file>".into(),
            )
        }
    };
    Ok(Options {
        source,
        json,
        hourly_usd,
        toy_srs,
        in_flight,
        out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `bytes` in a file of this test run's own, removed when dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(name: &str, bytes: &[u8]) -> Scratch {
            let path =
                std::env::temp_dir().join(format!("apogee-bench-{}-{name}", std::process::id()));
            std::fs::write(&path, bytes).expect("a scratch file");
            Scratch(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// The committed subset's non-empty inputs and their outputs.
    fn pairs() -> Vec<zkevm::Pair> {
        zkevm::pairs(&vectors().join("zkevm-subset.json"))
            .into_iter()
            .filter(|pair| !pair.input.is_empty())
            .collect()
    }

    fn block(input: &[u8], output: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "statelessInputBytes": format!("0x{}", hex(input)),
            "statelessOutputBytes": format!("0x{}", hex(output)),
        })
    }

    #[test]
    fn a_fixture_s_input_reaches_the_guest_byte_for_byte() {
        let pairs = pairs();
        let (a, b, c) = (&pairs[0], &pairs[1], &pairs[2]);
        let mut wrong = a.output.clone();
        wrong[32] ^= 1;
        let fixture = serde_json::json!({
            "test_a": { "blocks": [block(&a.input, &a.output)] },
            "test_b": { "blocks": [block(&b.input, &b.output), block(&c.input, &c.output)] },
            "test_wrong": { "blocks": [block(&a.input, &wrong)] },
        });
        let file = Scratch::new("fixture.json", fixture.to_string().as_bytes());

        let job = stateless_job(&file.0, Some("test_a")).expect("one input");
        assert_eq!(job.mode, Mode::Stateless);
        assert_eq!(
            (job.advice, job.journal),
            (a.input.clone(), Some(a.output.clone()))
        );
        let job = stateless_job(&file.0, Some("test_b/blocks[1]")).expect("one input");
        assert_eq!(
            (job.advice, job.journal),
            (c.input.clone(), Some(c.output.clone()))
        );
        for case in [None, Some("test_b"), Some("test_c")] {
            assert!(
                stateless_job(&file.0, case).is_err(),
                "{case:?} picks no one input"
            );
        }
        // The library already publishes something else, before any proving.
        assert!(stateless_job(&file.0, Some("test_wrong")).is_err());
    }

    #[test]
    fn a_raw_file_is_the_input_itself() {
        let pair = &pairs()[0];
        let file = Scratch::new("input.bin", &pair.input);
        let job = stateless_job(&file.0, None).expect("a raw input");
        assert_eq!((job.advice, job.journal), (pair.input.clone(), None));
        assert!(
            stateless_job(&file.0, Some("x")).is_err(),
            "a raw file is one input"
        );
        let empty = Scratch::new("empty.bin", &[]);
        assert!(
            stateless_job(&empty.0, None).is_err(),
            "no advice, no advice region"
        );
    }

    #[test]
    fn a_stateless_file_and_a_fixture_are_exclusive() {
        let args = |list: &[&str]| list.iter().map(|a| a.to_string()).collect::<Vec<_>>();
        assert!(matches!(
            parse(&args(&["--stateless", "x.json", "--case", "a"])).map(|o| o.source),
            Ok(Source::Stateless { case: Some(_), .. })
        ));
        assert!(matches!(
            parse(&args(&["mini-block"])).map(|o| o.source),
            Ok(Source::Fixture(_))
        ));
        for wrong in [
            &["mini-block", "--stateless", "x.json"][..],
            &["mini-block", "--case", "a"],
            &[],
        ] {
            assert!(parse(&args(wrong)).is_err(), "{wrong:?}");
        }
    }
}
