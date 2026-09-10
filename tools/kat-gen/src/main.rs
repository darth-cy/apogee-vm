//! Regenerates every committed known-answer vector file from arkworks.
//!
//!     cargo run -p kat-gen              # every group, which is what CI runs
//!     cargo run -p kat-gen -- tower     # just crates/curve's Fq6/Fq12 vectors
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
//! | `curve`   | `crates/curve/tests/vectors/{fq,g1,g2}_kats.txt` |
//! | `tower`   | `crates/curve/tests/vectors/{fq6,fq12}_kats.txt` |
//! | `pairing` | `crates/curve/tests/vectors/pairing_kats.txt` |
//! | `msm`     | `crates/curve/tests/vectors/msm_kats.txt` |
//! | `srs`     | `crates/srs/tests/vectors/*` (needs the gitignored ceremony file) |
//! | `pcs`     | `crates/pcs/tests/vectors/*` |
//! | `loader`  | `crates/loader/tests/vectors/*` (from the committed guest ELFs) |
//! | `guests`  | the guest ELFs themselves -- opt-in only, see `DEFAULT_GROUPS` |

use std::fs;
use std::path::PathBuf;

use test_support::{sha256, to_hex};

mod curve;
mod field;
mod guests;
mod loader;
mod msm;
mod pairing;
mod pcs;
mod poly;
mod shared;
mod srs;
mod tower;

/// Every group, in the order a reader of the tower would meet them.
const GROUPS: [(&str, fn()); 10] = [
    ("field", field::generate),
    ("poly", poly::generate),
    ("curve", curve::generate),
    ("tower", tower::generate),
    ("pairing", pairing::generate),
    ("msm", msm::generate),
    ("srs", srs::generate),
    ("pcs", pcs::generate),
    ("loader", loader::generate),
    ("guests", guests::generate),
];

/// The groups a bare `cargo run -p kat-gen` runs, which is what CI runs.
///
/// `guests` is not one of them. It rebuilds the guest ELFs, and a guest ELF is
/// **not** reproducible across machines: rustc embeds absolute paths in the
/// panic-location strings of every crate outside the guest workspace, and of
/// `core` itself, and stable Rust has no way to remap them (`trim-paths` is
/// still unstable in the pinned cargo). Two clean builds on one machine agree
/// exactly -- `crates/loader/tests/reproducible.rs` proves it, and that is what
/// acceptance 2 asks -- but a CI regeneration would diff against fixtures built
/// elsewhere and fail every time. So the ELFs are refreshed deliberately, on
/// one machine, with `cargo run -p kat-gen -- guests`, and everything CI can
/// reproduce from them -- the objdump and nm listings -- is in `loader`, which
/// does run by default.
const DEFAULT_GROUPS: [&str; 9] = [
    "field", "poly", "curve", "tower", "pairing", "msm", "srs", "pcs", "loader",
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
