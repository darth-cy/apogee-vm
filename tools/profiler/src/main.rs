//! `cargo run --release -p profiler -- <verb> …` — where a guest's cycles go.
//!
//! ```text
//! profiler elf <file> [--advice <file>] [--input <file>] [--top <n>] [--json <path>]
//!     profile any guest ELF over the bytes given.
//! ```
//!
//! Nothing here invokes the prover or the verifier. `docs/tools.md` §2 is the
//! design and the reading guide.

use std::path::PathBuf;

use profiler::report::ProfileReport;

fn usage() -> &'static str {
    "profiler — where a guest's RV32 cycles go\n\
     \n\
     profiler elf <file> [--advice <f>] [--input <f>] [--top <n>] [--json <p>]\n\
     \n\
     Nothing it runs is proving-related."
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let verb = args.first().map(String::as_str).unwrap_or("");
    let rest = args.get(1..).unwrap_or(&[]);
    let result = match verb {
        "elf" => elf(rest),
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
    let io = emulator::GuestIo { input, advice };
    let report = run(&bytes, &name, &name, &io, common.top)?;
    emit(&report, &common)
}

/// Load, decode and profile.
fn run(
    elf: &[u8],
    guest: &str,
    label: &str,
    io: &emulator::GuestIo,
    top: usize,
) -> Result<ProfileReport, String> {
    let image = loader::load_elf(elf).map_err(|e| format!("the guest does not load: {e:?}"))?;
    // The smallest menu height the guest's code fits: a decoded table's rows are
    // absolute pcs, one per halfword, so the height has to reach past the last
    // instruction.
    let params = smallest(&image)?;
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
