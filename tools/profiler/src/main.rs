//! `cargo run --release -p profiler -- <verb> …` — where a guest's cycles go.
//!
//! ```text
//! profiler elf <file> [--advice <file>] [--input <file>] [--top <n>] [--json <path>]
//!     profile any guest ELF over the bytes given.
//!
//! profiler block <fixture> [--top <n>] [--json <path>]
//!     profile the revm guest over a RECORDED block fixture under
//!     crates/host/tests/vectors. No network.
//!
//! profiler record <number|latest> [--txs <n>] [--top <n>] [--json <path>] [--cache <dir>]
//!     record a mainnet block from ETH_RPC_URL and profile the revm guest over
//!     it. This is the one verb that touches the network, and it is opt-in for
//!     the same reason `kat-gen -- block` is.
//! ```
//!
//! Nothing here invokes the prover, the verifier, an SRS or a commitment.
//! `docs/spec/profiling.md` is the design and the reading guide.

use std::path::PathBuf;

use host::fixture::{self, Mode, Pin};
use host::recorder::{self, TxRange};
use host::rpc::{self, Rpc};
use profiler::report::ProfileReport;

fn usage() -> &'static str {
    "profiler — where a guest's RV32 cycles go\n\
     \n\
     profiler elf <file> [--advice <f>] [--input <f>] [--top <n>] [--json <p>]\n\
     profiler block <fixture> [--top <n>] [--json <p>]\n\
     profiler record <number|latest> [--txs <n>] [--top <n>] [--json <p>] [--cache <d>]\n\
     \n\
     `block` reads a recorded fixture and touches no network. `record` reads\n\
     ETH_RPC_URL. Neither invokes anything proving-related."
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    let result = match verb {
        "elf" => elf(rest),
        "block" => block(rest),
        "record" => record(rest),
        "--help" | "-h" | "" => {
            println!("{}", usage());
            return;
        }
        other => Err(format!("no verb `{other}`")),
    };
    if let Err(why) = result {
        eprintln!("profiler: {why}\n\n{}", usage());
        std::process::exit(2);
    }
}

/// The options every verb shares.
struct Common {
    top: usize,
    json: Option<PathBuf>,
}

/// Pull `--top` and `--json` out of `args`, leaving the positional arguments and
/// any verb-specific option in the returned list.
fn common(args: &[String]) -> Result<(Common, Vec<String>), String> {
    let mut out = Common {
        top: 30,
        json: None,
    };
    let mut rest = Vec::new();
    let mut at = 0;
    while at < args.len() {
        match args[at].as_str() {
            "--top" => {
                at += 1;
                out.top = args
                    .get(at)
                    .ok_or("--top needs a count")?
                    .parse()
                    .map_err(|e| format!("--top is not a count: {e}"))?;
            }
            "--json" => {
                at += 1;
                out.json = Some(PathBuf::from(args.get(at).ok_or("--json needs a path")?));
            }
            other => rest.push(other.to_string()),
        }
        at += 1;
    }
    Ok((out, rest))
}

/// Emit the report, and the JSON if asked.
fn emit(report: &ProfileReport, common: &Common) -> Result<(), String> {
    print!("{}", report.to_table());
    if let Some(path) = &common.json {
        std::fs::write(path, report.to_json()).map_err(|e| format!("writing {path:?}: {e}"))?;
        println!("\nwrote {}", path.display());
    }
    Ok(())
}

/// `profiler elf <file>`: any guest, any bytes.
fn elf(args: &[String]) -> Result<(), String> {
    let (common, rest) = common(args)?;
    let mut path = None;
    let (mut advice, mut input) = (Vec::new(), Vec::new());
    let mut at = 0;
    while at < rest.len() {
        match rest[at].as_str() {
            "--advice" => {
                at += 1;
                let p = rest.get(at).ok_or("--advice needs a path")?;
                advice = std::fs::read(p).map_err(|e| format!("reading {p}: {e}"))?;
            }
            "--input" => {
                at += 1;
                let p = rest.get(at).ok_or("--input needs a path")?;
                input = std::fs::read(p).map_err(|e| format!("reading {p}: {e}"))?;
            }
            other if other.starts_with("--") => return Err(format!("unknown option `{other}`")),
            other if path.is_none() => path = Some(PathBuf::from(other)),
            other => return Err(format!("unexpected argument `{other}`")),
        }
        at += 1;
    }
    let path = path.ok_or("elf needs a file")?;
    let bytes = std::fs::read(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let io = emulator::GuestIo {
        input,
        advice,
        stdin: Vec::new(),
        hint: Vec::new(),
    };
    let report = run(&bytes, &name, &name, &io, None, common.top)?;
    emit(&report, &common)
}

/// `profiler block <fixture>`: the revm guest over a recorded block.
fn block(args: &[String]) -> Result<(), String> {
    let (common, rest) = common(args)?;
    let stem = rest.first().ok_or("block needs a fixture stem")?;
    let dir = vectors();
    let pin = Pin::from_bytes(
        &std::fs::read(dir.join(fixture::pin_file(stem)))
            .map_err(|e| format!("no `{stem}` pin under {}: {e}", dir.display()))?,
    )?;
    let witness = std::fs::read(dir.join(fixture::witness_file(stem))).map_err(|e| {
        format!(
            "the `{stem}` pin is committed and its witness is not ({e}); \
             `cargo run -p kat-gen -- block` writes one, and it needs ETH_RPC_URL"
        )
    })?;
    profile_revm(
        stem,
        pin.mode,
        &witness,
        Some((pin.block_number, pin.txs_recorded, pin.gas_used)),
        &common,
    )
}

/// `profiler record <number|latest>`: record from mainnet, then profile.
///
/// The one verb that touches the network. `--txs` is how many of the block's
/// transactions to record and run: the default is **all** of them, which is the
/// whole-block profile the recommendations are made from.
fn record(args: &[String]) -> Result<(), String> {
    let (common, rest) = common(args)?;
    let mut which = None;
    let mut txs = None;
    let mut cache = None;
    let mut at = 0;
    while at < rest.len() {
        match rest[at].as_str() {
            "--txs" => {
                at += 1;
                txs = Some(
                    rest.get(at)
                        .ok_or("--txs needs a count")?
                        .parse::<usize>()
                        .map_err(|e| format!("--txs is not a count: {e}"))?,
                );
            }
            "--cache" => {
                at += 1;
                cache = Some(PathBuf::from(rest.get(at).ok_or("--cache needs a path")?));
            }
            other if other.starts_with("--") => return Err(format!("unknown option `{other}`")),
            other if which.is_none() => which = Some(other.to_string()),
            other => return Err(format!("unexpected argument `{other}`")),
        }
        at += 1;
    }
    let which = which.ok_or("record needs a block number, or `latest`")?;
    // The scratch cache, not the committed one: a profiling session records
    // whole blocks, and `eth_getProof` answers for hundreds of accounts would
    // dwarf the fixture directory (`crates/host/src/fixture.rs`).
    let cache = cache.unwrap_or_else(|| {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/profiler-cache")
    });
    let mut rpc = Rpc::new(cache);
    if !rpc.online() {
        return Err(format!(
            "{} is unset, so there is nothing to record from",
            rpc::ENDPOINT_VAR
        ));
    }
    let number = match which.as_str() {
        "latest" | "finalized" => {
            let head = rpc.call(
                "eth_getBlockByNumber",
                serde_json::json!(["finalized", false]),
            )?;
            rpc::u64_of(&head["number"], "the finalized block number")?
        }
        other => other
            .parse::<u64>()
            .map_err(|e| format!("`{other}` is not a block number: {e}"))?,
    };
    let range = match txs {
        Some(n) => TxRange::First(n),
        None => TxRange::All,
    };
    println!("recording block {number} ({range:?}) …");
    let recording = recorder::record(rpc, number, range)?;
    let witness = recording.witness.encode();
    let ran = match txs {
        Some(n) => n.min(recording.txs_in_block),
        None => recording.txs_in_block,
    };
    println!(
        "  {} of {} transactions, {} bytes of witness, {} rpc hits and {} misses",
        ran,
        recording.txs_in_block,
        witness.len(),
        recording.rpc_hits,
        recording.rpc_misses
    );
    // The gas a whole-block recording is against is the header's own
    // `gasUsed`, which the witness does not carry; the sum of the transactions'
    // limits capped at the block's is the closest number this has in hand, and
    // it is an upper bound rather than the header's figure. `profiler block`
    // over a pinned fixture has the exact number and uses it.
    let gas: u64 = recording
        .witness
        .txs
        .iter()
        .map(|tx| tx.gas_limit)
        .sum::<u64>()
        .min(recording.witness.env.gas_limit);
    profile_revm(
        &format!("block-{number}"),
        Mode::Mini,
        &witness,
        Some((number, ran, gas)),
        &common,
    )
}

/// Build the revm guest for `mode` and profile it over `witness` as advice.
fn profile_revm(
    label: &str,
    mode: Mode,
    witness: &[u8],
    block: Option<(u64, usize, u64)>,
    common: &Common,
) -> Result<(), String> {
    println!("building the revm guest ({}) …", mode.binary());
    let elf = fixture::build_revm_guest(mode)?;
    let io = emulator::GuestIo {
        input: Vec::new(),
        advice: witness.to_vec(),
        stdin: Vec::new(),
        hint: Vec::new(),
    };
    let report = run(
        &elf,
        mode.binary(),
        label,
        &io,
        Some(fixture::revm_params()),
        common.top,
    )?;
    let report = match block {
        Some((number, txs, gas)) => report.with_block(number, txs, gas),
        None => report,
    };
    emit(&report, common)
}

/// Load, decode and profile.
fn run(
    elf: &[u8],
    guest: &str,
    label: &str,
    io: &emulator::GuestIo,
    params: Option<program::ProgramParams>,
    top: usize,
) -> Result<ProfileReport, String> {
    let image = loader::load_elf(elf).map_err(|e| format!("the guest does not load: {e:?}"))?;
    let params = match params {
        Some(params) => params,
        // The smallest menu height the guest's code fits: a decoded table's rows
        // are absolute pcs, one per halfword, so the height has to reach past
        // the last instruction.
        None => smallest(&image)?,
    };
    let (tables, config) = program::decode_program(&image, &params)
        .map_err(|e| format!("the guest does not decode: {e}"))?;
    let profile = profiler::profile(elf, &image, io, &tables, &config)?;
    Ok(ProfileReport::of(label, guest, &profile, top))
}

fn smallest(image: &loader::ProgramImage) -> Result<program::ProgramParams, String> {
    let mut refused = None;
    for &height in &constants::family::HEIGHT_MENU {
        let params = program::ProgramParams {
            heights: [height; constants::family::COUNT as usize],
            ..program::ProgramParams::defaults()
        };
        match program::decode_program(image, &params) {
            Ok(_) => return Ok(params),
            Err(e) => refused = Some(e),
        }
    }
    Err(match refused {
        Some(e) => e.to_string(),
        None => "the height menu is empty".to_string(),
    })
}

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/host/tests/vectors")
}
