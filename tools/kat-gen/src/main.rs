//! Regenerates the committed fixtures (`docs/tools.md` §7): known-answer
//! vectors from arkworks' field and polynomial crates, listings from the pinned
//! toolchain's LLVM tools, and regression pins of this repository's own
//! constructions.
//!
//!     cargo run -p kat-gen              # the default groups, which is what CI runs
//!     cargo run -p kat-gen -- field     # just crates/field's Fr vectors
//!
//! Deterministic: same toolchain and same arkworks version produce
//! byte-identical output, so a refresh is `cargo run -p kat-gen && git diff`.
//! Freshness is a manual step; CI only reads the committed files, and diffs a
//! regeneration against them.
//!
//! One module per group, one `generate()` each:
//!
//! | Subcommand | Files |
//! | --- | --- |
//! | `field`   | `crates/field/tests/vectors/fr_kats.txt` |
//! | `poly`    | `crates/poly/tests/vectors/*` |
//! | `loader`  | `crates/loader/tests/vectors/*` (from the committed guest ELFs) |
//! | `isa`     | `crates/isa/tests/vectors/*` (the hand-encoded corpus, via llvm-objdump) |
//! | `program` | `crates/program/tests/vectors/*` |
//! | `gkr`     | `crates/constraints/tests/vectors/toy_*` (the toy circuit, cached and cache-free) |
//! | `memory`  | `crates/constraints/tests/vectors/{memory_frame_*,image_window,zero_window}.bin` (the three distinct execution-family frames and two window circuits) |
//! | `lookup`  | `crates/constraints/tests/vectors/lookup_toy.bin` (the combined lookup toy) |
//! | `family`  | `crates/constraints/tests/vectors/{add_sub,jump_branch_slt,shift_bitwise,mul_div,mem_word,mem_subword,atomics}.bin` (the seven execution-family circuits) |
//! | `tape`    | `crates/checker/tests/vectors/global_tape.txt` (the global commit phase's absorb sequence) |
//! | `guests`  | the guest ELFs themselves -- opt-in only, see `DEFAULT_GROUPS` |

use std::fs;
use std::path::PathBuf;

use test_support::{sha256, to_hex};

mod ark_fr;
mod family;
mod field;
mod gkr;
mod guests;
mod isa;
mod loader;
mod lookup;
mod memory;
mod poly;
mod program;
mod tape;

/// Every group, in the order a reader of the stack would meet them.
const GROUPS: [(&str, fn()); 11] = [
    ("field", field::generate),
    ("poly", poly::generate),
    ("loader", loader::generate),
    ("isa", isa::generate),
    ("program", program::generate),
    ("gkr", gkr::generate),
    ("memory", memory::generate),
    ("lookup", lookup::generate),
    ("family", family::generate),
    ("tape", tape::generate),
    ("guests", guests::generate),
];

/// The groups a bare `cargo run -p kat-gen` runs, which is what CI runs.
///
/// `guests` is not one of them. It rebuilds the guest ELFs, and a guest ELF is
/// **not** reproducible across machines: rustc embeds absolute paths in the
/// panic-location strings of every crate outside the guest workspace, and of
/// `core` itself, and the guest build does not remap them. Two clean builds on
/// one machine agree exactly -- `crates/loader/tests/reproducible.rs` checks
/// it -- but a CI regeneration would diff against fixtures built elsewhere and
/// fail every time. So the ELFs are refreshed deliberately, on one machine,
/// with `cargo run -p kat-gen -- guests`, and everything CI can reproduce from
/// them -- the objdump and nm listings -- is in `loader`, which does run by
/// default.
const DEFAULT_GROUPS: [&str; 10] = [
    "field", "poly", "loader", "isa", "program", "gkr", "memory", "lookup", "family", "tape",
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let chosen: Vec<&str> = match args.len() {
        0 => DEFAULT_GROUPS.to_vec(),
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

/// Write one vector file, relative to the workspace root, and print its digest.
///
/// The digest is what `crates/*/tests` pin, so printing it here is how a
/// deliberate refresh hands the new value to the test that has to be updated.
pub fn write_vectors(relative_path: &str, contents: &str) {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative_path);
    let digest = to_hex(&sha256(contents.as_bytes()));
    fs::write(&path, contents).expect("writing a vector file");
    println!("wrote {relative_path} (sha256 {digest})");
}

/// Write one binary fixture, relative to the workspace root, and print its
/// digest. The text sibling of [`write_vectors`].
pub fn write_bytes(relative_path: &str, contents: &[u8]) {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative_path);
    let digest = to_hex(&sha256(contents));
    fs::write(&path, contents).expect("writing a fixture file");
    println!("wrote {relative_path} (sha256 {digest})");
}

/// A generator whose input stream had collapsed would still write a thousand
/// lines that all "match".
pub fn assert_distinct(values: &[String], what: &str) {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), values.len(), "{what} must not repeat");
}
