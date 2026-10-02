//! A `tests-zkevm` release on disk, as the stateless guest is held to it.
//!
//! `ethereum/execution-specs`' zkEVM releases fill `statelessInputBytes` and
//! `statelessOutputBytes` into their blockchain and engine fixtures, and the
//! zkEVM benchmark compares a guest's 43 output bytes to the latter exactly.
//! This is the one reader of that format here: `tests/conformance.rs` walks a
//! whole extracted release with it, and `tools/kat-gen`'s `zkevm` group cuts
//! the subset CI runs with it.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// Names the extracted release's `fixtures/` directory.
pub const FIXTURES_VAR: &str = "APOGEE_ZKEVM_FIXTURES";

/// The release the stateless guest implements: `tests-zkevm@v21.0.1`, filled
/// from this `ethereum/execution-specs` commit.
pub const RELEASE_COMMIT: &str = "3ebcb5d02126918eb2aad599b3cf286200d4f458";

/// One stateless input and the output the release expects of it, named by
/// its file and its path inside that file.
pub struct Pair {
    pub name: String,
    pub input: Vec<u8>,
    pub output: Vec<u8>,
}

/// Every `.json` file under `dir`, sorted, so a walk is the same walk on any
/// machine.
pub fn files(dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "json") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

/// Every pair in one file, in the file's key order: any object carrying both
/// fields, at any depth.
pub fn pairs(path: &Path) -> Vec<Pair> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let value: Value =
        serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = Vec::new();
    collect(&value, &mut String::new(), &mut out);
    out
}

fn collect(value: &Value, name: &mut String, out: &mut Vec<Pair>) {
    match value {
        Value::Object(map) => {
            if let (Some(Value::String(input)), Some(Value::String(output))) = (
                map.get("statelessInputBytes"),
                map.get("statelessOutputBytes"),
            ) {
                out.push(Pair {
                    name: name.clone(),
                    input: hex(input),
                    output: hex(output),
                });
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

/// The execution-specs commit a release was filled from, as its
/// `.meta/fixtures.ini` records it.
pub fn release_commit(dir: &Path) -> Option<String> {
    let ini = std::fs::read_to_string(dir.join(".meta/fixtures.ini")).ok()?;
    ini.lines()
        .find_map(|line| line.strip_prefix("commit = "))
        .map(|commit| commit.trim().to_string())
}

/// What the validator makes of an input: the rule `stateless::verify` refuses
/// it by, `valid`, or `undecodable`.
pub fn verdict(input: &[u8]) -> String {
    match revm_block::ssz::decode(input) {
        None => "undecodable".into(),
        Some(decoded) => match revm_block::stateless::verify(&decoded) {
            Ok(()) => "valid".into(),
            Err(invalid) => format!("{invalid:?}"),
        },
    }
}
