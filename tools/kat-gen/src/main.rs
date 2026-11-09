//! Writes the committed reference vectors (`docs/tools.md` §7): known answers
//! from arkworks' field and polynomial crates, listings from the pinned
//! toolchain's LLVM tools, and hand-built ELFs.
//!
//!     cargo run -p kat-gen              # every group
//!     cargo run -p kat-gen -- poly      # just crates/poly's vectors
//!
//! Deterministic: same toolchain and same arkworks version produce
//! byte-identical output. It links nothing of the repository's but
//! `test-support`, so no implementation change can move what it writes, and
//! nothing runs it for you: run it when you change a generator.
//!
//! One module per group, one `generate()` each:
//!
//! | Subcommand | Files |
//! | --- | --- |
//! | `poly`    | `crates/poly/tests/vectors/*` |
//! | `loader`  | `crates/loader/tests/vectors/*` (the synthetic ELFs and fib's public-I/O record) |
//! | `isa`     | `crates/isa/tests/vectors/*` (the hand-encoded corpus, via llvm-objdump) |
//! | `program` | `crates/program/tests/vectors/*` |
//!
//! No guest ELF and no circuit is generated or committed: `guests/` is source,
//! a suite that runs a guest builds it (`test_support::guest_elf`), and a suite
//! that needs a circuit calls its constructor.

use std::fs;
use std::path::PathBuf;

mod ark_a64_c5;
mod isa;
mod loader;
mod poly;
mod program;

/// Every group, in the order a reader of the stack would meet them.
const GROUPS: [(&str, fn()); 4] = [
    ("poly", poly::generate),
    ("loader", loader::generate),
    ("isa", isa::generate),
    ("program", program::generate),
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let chosen: Vec<&str> = match args.len() {
        0 => GROUPS.iter().map(|(name, _)| *name).collect(),
        1 => vec![args[0].as_str()],
        _ => {
            usage("one subcommand at a time, or none for all of them");
            return;
        }
    };
    for name in &chosen {
        match GROUPS.iter().find(|(group, _)| group == name) {
            Some((_, generate)) => generate(),
            None => {
                usage(&format!("unknown group `{name}`"));
                return;
            }
        }
    }
}

fn usage(why: &str) {
    eprintln!("kat-gen: {why}");
    eprintln!("usage: cargo run -p kat-gen [-- <group>]");
    eprintln!(
        "groups: {}",
        GROUPS
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(", ")
    );
    std::process::exit(1);
}

/// Write one vector file, relative to the workspace root.
pub fn write_vectors(relative_path: &str, contents: &str) {
    write_bytes(relative_path, contents.as_bytes());
}

/// Write one binary vector file, relative to the workspace root.
pub fn write_bytes(relative_path: &str, contents: &[u8]) {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative_path);
    fs::write(&path, contents).expect("writing a vector file");
    println!("wrote {relative_path}");
}

/// A generator whose input stream had collapsed would still write a thousand
/// lines that all "match".
pub fn assert_distinct(values: &[String], what: &str) {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), values.len(), "{what} must not repeat");
}
