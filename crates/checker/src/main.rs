//! The standalone checkers, over a committed `CircuitArtifact` file or over a
//! verifying key and a statement.
//!
//!     cargo run -p checker -- laws <artifact>      # Laws 1-4 and the lookup rules, §4.2
//!     cargo run -p checker -- padding <artifact>   # the padding contract, §4.3
//!     cargo run -p checker -- dump <artifact>      # the readable page
//!     cargo run -p checker -- tape <verifying-key> <public-inputs>
//!                                                  # the global commit phase's absorb
//!                                                  # sequence, diffed against the frozen
//!                                                  # pre-fork order
//!
//! Exit 0 when the check holds (or the dump or the tape is printed), 1 with the
//! reason on stderr when it does not or a file is not what it should be, 2 on a
//! usage error. What each check does not cover is on its function in
//! `src/lib.rs`.

use std::fs;

use constraints::CircuitArtifact;
use verifier_core::PublicInputs;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [command, key, public] if command == "tape" => tape(key, public),
        [command, path] if matches!(command.as_str(), "laws" | "padding" | "dump") => {
            artifact(command, path)
        }
        [command, ..] => usage(&format!("unknown command `{command}`, or wrong arguments")),
        [] => usage("expected a command"),
    }
}

/// The three artifact checks.
fn artifact(command: &str, path: &str) {
    let bytes = read(path);
    let artifact = match CircuitArtifact::from_bytes(&bytes) {
        Ok(artifact) => artifact,
        Err(e) => fail(&format!("{path} is not a circuit artifact: {e}")),
    };
    match command {
        "laws" => match checker::check_laws(&artifact) {
            Ok(()) => println!("{path}: Laws 1-4 and the lookup rules hold"),
            Err(e) => fail(&format!("{path}: {e}")),
        },
        "padding" => match checker::check_padding(&artifact) {
            Ok(()) => println!("{path}: the padding contract holds"),
            Err(e) => fail(&format!("{path}: {e}")),
        },
        _ => print!("{}", checker::dump(&artifact)),
    }
}

/// The transcript tape: the global commit phase over this key and this
/// statement, diffed against the frozen pre-fork order and printed.
fn tape(key: &str, public: &str) {
    let vk = match verifier::load_verifying_key(&read(key)) {
        Ok(vk) => vk,
        Err(e) => fail(&format!("{key}: {e}")),
    };
    let statement = match PublicInputs::from_bytes(&read(public)) {
        Ok(statement) => statement,
        Err(e) => fail(&format!("{public}: {e}")),
    };
    // A statement the key does not describe would panic inside the global
    // commit phase, whose contract is that its caller checked first.
    if let Err(e) = verifier_core::derive_global_phase(&vk, &statement) {
        fail(&format!("{public}: {e}"));
    }
    match checker::check_global_tape(&vk, &statement) {
        Ok(lines) => {
            for line in lines {
                println!("{line}");
            }
        }
        Err(e) => fail(&e),
    }
}

fn read(path: &str) -> Vec<u8> {
    match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => fail(&format!("reading {path}: {e}")),
    }
}

fn usage(why: &str) -> ! {
    eprintln!("checker: {why}");
    eprintln!("usage: checker laws <artifact>");
    eprintln!("       checker padding <artifact>");
    eprintln!("       checker dump <artifact>");
    eprintln!("       checker tape <verifying-key> <public-inputs>");
    std::process::exit(2);
}

fn fail(why: &str) -> ! {
    eprintln!("checker: {why}");
    std::process::exit(1);
}
