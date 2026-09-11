//! Export a guest ELF as the `ProgramImage` artifact later stages consume, and
//! a report of that artifact a person can read — or print its decoded tables.
//!
//!     cargo run -p artifact-dump -- guests/target/riscv32imac-unknown-none-elf/debug/fib
//!     cargo run -p artifact-dump -- <elf> --out artifacts/
//!     cargo run --release -p artifact-dump -- tables <elf> [--ptau <file>]
//!
//! The first form writes two files into the output directory, both named
//! after the ELF:
//!
//! | File | What |
//! | --- | --- |
//! | `<name>.img` | the artifact: the frozen `postcard` wire form, nothing else |
//! | `<name>.img.txt` | the report of that artifact |
//!
//! `tables` prints to stdout instead: every instruction's pc, mnemonic, decoded
//! fields and owning family, the derived `VmConfig`, and — given PSE's ceremony
//! file with `--ptau` — the program identity at the frozen default parameters.
//!
//! `docs/guest-program-manual.md` is the walkthrough, from an empty crate to
//! these files.

use std::fs;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("tables") {
        tables(&args[1..]);
        return;
    }
    let (elf_path, out_dir) = match parse(&args) {
        Ok(parsed) => parsed,
        Err(why) => usage(&why),
    };

    let elf = match fs::read(&elf_path) {
        Ok(bytes) => bytes,
        Err(e) => fail(&format!("reading {}: {e}", elf_path.display())),
    };

    // The artifact is named after the ELF, so two guests dumped into one
    // directory do not overwrite each other.
    let stem = elf_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "program".to_string());
    let artifact_name = format!("{stem}.img");

    let dump = match artifact_dump::dump(&elf, &elf_path.display().to_string(), &artifact_name) {
        Ok(dump) => dump,
        Err(why) => fail(&why),
    };

    if let Err(e) = fs::create_dir_all(&out_dir) {
        fail(&format!("creating {}: {e}", out_dir.display()));
    }
    let artifact_path = out_dir.join(&artifact_name);
    let report_path = out_dir.join(format!("{artifact_name}.txt"));
    if let Err(e) = fs::write(&artifact_path, &dump.artifact) {
        fail(&format!("writing {}: {e}", artifact_path.display()));
    }
    if let Err(e) = fs::write(&report_path, dump.report.as_bytes()) {
        fail(&format!("writing {}: {e}", report_path.display()));
    }

    // The summary is the report's header, so the terminal says the same thing
    // the file does; the digests are here because pinning one is the reason to
    // run this twice.
    let instructions = dump
        .image
        .slots
        .iter()
        .filter(|slot| matches!(slot, loader::Slot::Instruction { .. }))
        .count();
    println!(
        "{}\n  entry {:#010x}, {} segments, {instructions} instructions\n  \
         artifact {} ({} bytes, sha256 {})\n  report   {}",
        elf_path.display(),
        dump.image.entry,
        dump.image.segments.len(),
        artifact_path.display(),
        dump.artifact.len(),
        test_support::to_hex(&test_support::sha256(&dump.artifact)),
        report_path.display(),
    );
}

/// `tables <elf> [--ptau <file>]`: print the decoded tables at the frozen
/// default parameters.
fn tables(args: &[String]) {
    let mut elf: Option<PathBuf> = None;
    let mut ptau: Option<PathBuf> = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--ptau" => match rest.next() {
                Some(path) => ptau = Some(PathBuf::from(path)),
                None => usage("`--ptau` needs a file"),
            },
            other if other.starts_with('-') => usage(&format!("unknown flag `{other}`")),
            other => {
                if elf.replace(PathBuf::from(other)).is_some() {
                    usage("one ELF at a time");
                }
            }
        }
    }
    let Some(elf_path) = elf else {
        usage("no ELF given")
    };
    let bytes = match fs::read(&elf_path) {
        Ok(bytes) => bytes,
        Err(e) => fail(&format!("reading {}: {e}", elf_path.display())),
    };

    let params = program::ProgramParams::defaults();
    // The SRS needs as many powers as the tallest table has rows.
    let power = params
        .heights
        .iter()
        .max()
        .expect("eight heights")
        .trailing_zeros();
    let srs = ptau.map(|path| {
        srs::Srs::from_ptau(&path, power)
            .unwrap_or_else(|e| fail(&format!("reading {}: {e:?}", path.display())))
    });
    match artifact_dump::tables::render(
        &bytes,
        &elf_path.display().to_string(),
        &params,
        srs.as_ref(),
    ) {
        Ok(page) => print!("{page}"),
        Err(why) => fail(&why),
    }
}

/// `(elf, out_dir)`. The output directory defaults to the working directory,
/// not the ELF's: the ELF lives in a target directory, which `cargo clean`
/// deletes, and an artifact worth exporting is one worth keeping.
fn parse(args: &[String]) -> Result<(PathBuf, PathBuf), String> {
    let mut elf: Option<PathBuf> = None;
    let mut out = PathBuf::from(".");
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--out" => {
                let dir = rest.next().ok_or("`--out` needs a directory")?;
                out = PathBuf::from(dir);
            }
            "-h" | "--help" => return Err("".to_string()),
            other if other.starts_with('-') => return Err(format!("unknown flag `{other}`")),
            other => {
                if elf.replace(PathBuf::from(other)).is_some() {
                    return Err("one ELF at a time".to_string());
                }
            }
        }
    }
    Ok((elf.ok_or("no ELF given")?, out))
}

fn usage(why: &str) -> ! {
    if !why.is_empty() {
        eprintln!("artifact-dump: {why}");
    }
    eprintln!("usage: cargo run -p artifact-dump -- <guest.elf> [--out <dir>]");
    eprintln!("       cargo run --release -p artifact-dump -- tables <guest.elf> [--ptau <file>]");
    eprintln!();
    eprintln!("The first writes <name>.img -- the frozen ProgramImage wire form, which is");
    eprintln!("the artifact later stages read -- and <name>.img.txt, a report of it.");
    eprintln!("`tables` prints the decoded per-family tables, the VmConfig and, with the");
    eprintln!("PSE ceremony file, the program identity. See docs/guest-program-manual.md.");
    std::process::exit(if why.is_empty() { 0 } else { 2 });
}

fn fail(why: &str) -> ! {
    eprintln!("artifact-dump: {why}");
    std::process::exit(1);
}
