//! **Conformance**: every stateless input of a `tests-zkevm` release through
//! the stateless guest's library, held to the release's own output bytes.
//!
//! `ethereum/execution-specs`' zkEVM releases fill `statelessInputBytes` and
//! `statelessOutputBytes` into their blockchain and engine fixtures, and the
//! benchmark compares a guest's 43 output bytes to the latter exactly. This
//! test is that comparison, natively, over a whole release: it walks the
//! extracted tarball, finds every object carrying both fields, runs
//! `revm_block::stateless::run` on the input and counts the outputs that are
//! not the expected bytes — and, because the first 32 bytes are the request
//! root and the 33rd the verdict, it says which half disagreed.
//!
//! **The whole release is not in CI**: `tests-zkevm@v21.0.1` is a 620 MB
//! tarball, 5.9 GB of JSON extracted. Run by hand with the extracted
//! `fixtures/` directory named:
//!
//! ```text
//! APOGEE_ZKEVM_FIXTURES=/path/to/fixtures \
//!   cargo test --release -p host --test conformance -- --ignored --nocapture
//! ```
//!
//! **What CI runs is a subset of it**, `tests/vectors/zkevm-subset.json`, cut
//! by `cargo run --release -p kat-gen -- zkevm` from the same release: one
//! case for every rule the validator refuses by, the smallest valid one, every
//! undecodable one and the cases this stage's fixes were found by. Each is
//! held to its output bytes and to the rule it names.

use host::zkevm::{self, FIXTURES_VAR, RELEASE_COMMIT};
use rayon::prelude::*;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[test]
fn the_committed_subset_is_the_release_s() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/zkevm-subset.json");
    let text = std::fs::read_to_string(&path).expect("the committed subset");
    let subset: Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!(subset["commit"], RELEASE_COMMIT, "cut from another release");
    let cases = subset["cases"].as_array().expect("a case list");
    assert!(!cases.is_empty(), "an empty subset holds nothing");
    for case in cases {
        let field = |key: &str| case[key].as_str().unwrap_or_else(|| panic!("no {key}"));
        let hex = |key: &str| {
            test_support::hex_to_bytes(field(key).strip_prefix("0x").expect("0x")).expect("hex")
        };
        let (name, input) = (field("name"), hex("statelessInputBytes"));
        assert_eq!(
            revm_block::stateless::run(&input)[..],
            hex("statelessOutputBytes")[..],
            "{name}"
        );
        assert_eq!(zkevm::verdict(&input), field("rule"), "{name}");
    }
}

#[test]
#[ignore = "needs an extracted tests-zkevm release, named by APOGEE_ZKEVM_FIXTURES"]
fn every_stateless_output_is_the_release_s() {
    let dir = PathBuf::from(std::env::var(FIXTURES_VAR).expect(FIXTURES_VAR));
    let files = zkevm::files(&dir);

    // Per file: (pairs, root mismatches, failure lines).
    let results: Vec<(usize, usize, Vec<String>)> = files
        .par_iter()
        .map(|path| {
            let mut root_wrong = 0;
            let mut failures = Vec::new();
            let pairs = zkevm::pairs(path);
            let count = pairs.len();
            for pair in pairs {
                let output = revm_block::stateless::run(&pair.input);
                if output[..] != pair.output[..] {
                    let root = output[..32] != pair.output[..32];
                    root_wrong += root as usize;
                    failures.push(format!(
                        "{}{}: expected {} got {} ({}){}",
                        path.strip_prefix(&dir).unwrap_or(path).display(),
                        pair.name,
                        pair.output.get(32).copied().unwrap_or(0xff),
                        output[32],
                        zkevm::verdict(&pair.input),
                        if root { ", ROOT WRONG" } else { "" },
                    ));
                }
            }
            (count, root_wrong, failures)
        })
        .collect();

    let total: usize = results.iter().map(|r| r.0).sum();
    let roots: usize = results.iter().map(|r| r.1).sum();
    let failures: Vec<&String> = results.iter().flat_map(|r| r.2.iter()).collect();
    println!(
        "{total} pairs over {} files: {} wrong, {roots} of them with a wrong root",
        files.len(),
        failures.len()
    );
    for failure in &failures {
        println!("  {failure}");
    }
    assert!(
        total > 0,
        "no fixture under {} carries statelessInputBytes",
        dir.display()
    );
    assert!(
        failures.is_empty(),
        "{} of {total} outputs differ",
        failures.len()
    );
}
