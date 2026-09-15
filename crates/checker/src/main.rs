//! The standalone checkers over a committed `CircuitArtifact` file.
//!
//!     cargo run -p checker -- laws <artifact>      # Laws 1-4 and the lookup rules, §4.2
//!     cargo run -p checker -- padding <artifact>   # the padding contract, §4.3
//!     cargo run -p checker -- dump <artifact>      # the readable page
//!
//! Exit 0 when the check holds (or the dump is printed), 1 with the reason on
//! stderr when it does not or the file is not an artifact, 2 on a usage error.
//! What each check does not cover is on its function in `src/lib.rs`.

use std::fs;

use constraints::CircuitArtifact;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [command, path] = args.as_slice() else {
        usage("expected a command and one artifact");
    };
    if !matches!(command.as_str(), "laws" | "padding" | "dump") {
        usage(&format!("unknown command `{command}`"));
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => fail(&format!("reading {path}: {e}")),
    };
    let artifact = match CircuitArtifact::from_bytes(&bytes) {
        Ok(artifact) => artifact,
        Err(e) => fail(&format!("{path} is not a circuit artifact: {e}")),
    };
    match command.as_str() {
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

fn usage(why: &str) -> ! {
    eprintln!("checker: {why}");
    eprintln!("usage: checker laws <artifact>");
    eprintln!("       checker padding <artifact>");
    eprintln!("       checker dump <artifact>");
    std::process::exit(2);
}

fn fail(why: &str) -> ! {
    eprintln!("checker: {why}");
    std::process::exit(1);
}
