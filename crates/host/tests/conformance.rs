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
//! **Not in CI**: `tests-zkevm@v21.0.1` is a 620 MB tarball, 5.9 GB of JSON
//! extracted. Run by hand with the extracted `fixtures/` directory named:
//!
//! ```text
//! APOGEE_ZKEVM_FIXTURES=/path/to/fixtures \
//!   cargo test --release -p host --test conformance -- --ignored --nocapture
//! ```

use rayon::prelude::*;
use serde_json::Value;
use std::path::{Path, PathBuf};

const FIXTURES_VAR: &str = "APOGEE_ZKEVM_FIXTURES";

fn json_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            json_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

/// Every `(input, output)` pair in one fixture file, named by where it sits.
fn pairs(path: &Path) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let value: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = Vec::new();
    collect(&value, &mut String::new(), &mut out);
    out
}

fn collect(value: &Value, name: &mut String, out: &mut Vec<(String, Vec<u8>, Vec<u8>)>) {
    match value {
        Value::Object(map) => {
            if let (Some(Value::String(input)), Some(Value::String(output))) = (
                map.get("statelessInputBytes"),
                map.get("statelessOutputBytes"),
            ) {
                out.push((name.clone(), hex(input), hex(output)));
                return;
            }
            for (key, child) in map {
                let len = name.len();
                name.push('/');
                name.push_str(key);
                collect(child, name, out);
                name.truncate(len);
            }
        }
        Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                let len = name.len();
                name.push_str(&format!("[{i}]"));
                collect(child, name, out);
                name.truncate(len);
            }
        }
        _ => {}
    }
}

fn hex(text: &str) -> Vec<u8> {
    test_support::hex_to_bytes(text.strip_prefix("0x").unwrap_or(text)).expect("hex")
}

/// What the validator made of an input, for a failure line: the rule it
/// broke, `valid`, or `undecodable`.
fn verdict_of(input: &[u8]) -> String {
    match revm_block::ssz::decode(input) {
        None => "undecodable".into(),
        Some(decoded) => match revm_block::stateless::verify(&decoded) {
            Ok(()) => "valid".into(),
            Err(invalid) => format!("{invalid:?}"),
        },
    }
}

#[test]
#[ignore = "needs an extracted tests-zkevm release, named by APOGEE_ZKEVM_FIXTURES"]
fn every_stateless_output_is_the_release_s() {
    let dir = PathBuf::from(std::env::var(FIXTURES_VAR).expect(FIXTURES_VAR));
    let mut files = Vec::new();
    json_files(&dir, &mut files);
    files.sort();

    // Per file: (pairs, root mismatches, failure lines).
    let results: Vec<(usize, usize, Vec<String>)> = files
        .par_iter()
        .map(|path| {
            let mut root_wrong = 0;
            let mut failures = Vec::new();
            let pairs = pairs(path);
            let count = pairs.len();
            for (name, input, expected) in pairs {
                let output = revm_block::stateless::run(&input);
                if output[..] != expected[..] {
                    let root = output[..32] != expected[..32];
                    root_wrong += root as usize;
                    failures.push(format!(
                        "{}{name}: expected {} got {} ({}){}",
                        path.strip_prefix(&dir).unwrap_or(path).display(),
                        expected.get(32).copied().unwrap_or(0xff),
                        output[32],
                        verdict_of(&input),
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
