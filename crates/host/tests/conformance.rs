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
//! The zkEVM benchmark's own datasets take the same command: an extracted
//! `glamsterdam-devnet-8` batch is real devnet blocks in the same fixture
//! shape, in ere-guests' layout, with a public key per transaction.
//!
//! **What CI runs is a subset of it**, `tests/vectors/zkevm-subset.json`, cut
//! by `cargo run --release -p kat-gen -- zkevm` from the same release: one
//! case for every rule the validator refuses by, the smallest valid one, every
//! undecodable one and the cases this stage's fixes were found by. Each is
//! held to its output bytes and to the rule it names.

use host::fixture::{build_revm_guest, Mode};
use host::zkevm::{self, FIXTURES_VAR, RELEASE_COMMIT};
use rayon::prelude::*;
use revm_block::{ssz, stateless, tx};
use serde_json::Value;
use std::path::{Path, PathBuf};

/// One committed case: its name, the rule it names, its input and its output.
struct Case {
    name: String,
    rule: String,
    input: Vec<u8>,
    output: Vec<u8>,
}

/// The committed subset, held to the release the guest implements.
fn subset() -> Vec<Case> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/zkevm-subset.json");
    let text = std::fs::read_to_string(&path).expect("the committed subset");
    let subset: Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!(subset["commit"], RELEASE_COMMIT, "cut from another release");
    let cases: Vec<Case> = subset["cases"]
        .as_array()
        .expect("a case list")
        .iter()
        .map(|case| {
            let field = |key: &str| case[key].as_str().unwrap_or_else(|| panic!("no {key}"));
            let hex = |key: &str| {
                test_support::hex_to_bytes(field(key).strip_prefix("0x").expect("0x")).expect("hex")
            };
            Case {
                name: field("name").into(),
                rule: field("rule").into(),
                input: hex("statelessInputBytes"),
                output: hex("statelessOutputBytes"),
            }
        })
        .collect();
    assert!(!cases.is_empty(), "an empty subset holds nothing");
    cases
}

#[test]
fn the_committed_subset_is_the_release_s() {
    for case in subset() {
        let name = &case.name;
        assert_eq!(
            revm_block::stateless::run(&case.input)[..],
            case.output[..],
            "{name}"
        );
        assert_eq!(zkevm::verdict(&case.input), case.rule, "{name}");
    }
}

/// **ere-guests' layout**, which the zkEVM benchmark's datasets carry, is v21's
/// with a public key per transaction after the chain id. With each signer's
/// own key it is the same validation, to the byte, for every case the subset
/// decodes. Keys that are too few, too many, another signer's or not
/// `0x04 ‖ x ‖ y` are refused, and a list that is not whole keys does not
/// decode.
#[test]
fn the_keyed_layout_is_the_same_validation() {
    let cases: Vec<Case> = subset()
        .into_iter()
        .filter(|case| ssz::decode(&case.input).is_some())
        .collect();
    for case in &cases {
        let twin = keyed(&case.input, &signers(&case.input));
        assert_eq!(
            stateless::run(&twin),
            stateless::run(&case.input),
            "{}",
            case.name
        );
    }

    let case = cases
        .iter()
        .find(|case| case.rule == "valid" && !signers(&case.input).is_empty())
        .expect("a valid case with a transaction");
    let keys = signers(&case.input);
    let mut another = keys.clone();
    another[0][1] ^= 1;
    let mut compressed = keys.clone();
    compressed[0][0] = 0x02;
    let too_many = [keys.clone(), vec![keys[0]]].concat();
    for (what, keys) in [
        ("too few", Vec::new()),
        ("too many", too_many),
        ("another signer's", another),
        ("not uncompressed", compressed),
    ] {
        let twin = keyed(&case.input, &keys);
        assert_eq!(zkevm::verdict(&twin), "PublicKeys", "{what}");
    }
    let mut ragged = keyed(&case.input, &keys);
    ragged.pop();
    assert_eq!(zkevm::verdict(&ragged), "undecodable");
}

/// Each transaction's signer's uncompressed key, or a stand-in where it has
/// none: a transaction that does not decode or recover is refused before any
/// key is read.
fn signers(input: &[u8]) -> Vec<[u8; 65]> {
    let decoded = ssz::decode(input).expect("a decodable case");
    decoded
        .request
        .payload
        .transactions
        .iter()
        .map(|bytes| {
            tx::decode(bytes)
                .ok()
                .and_then(|t| tx::recover_key(&t.signing_hash, &t.r, &t.s, t.y_odd))
                .unwrap_or([0x04; 65])
        })
        .collect()
}

/// A v21 input in ere-guests' layout: the same three fields, then `keys`.
fn keyed(input: &[u8], keys: &[[u8; 65]]) -> Vec<u8> {
    let (schema, body) = input.split_at(2);
    let moved = |at: usize| {
        (u32::from_le_bytes(body[at..at + 4].try_into().expect("an offset")) + 4).to_le_bytes()
    };
    let end = (body.len() as u32 + 4).to_le_bytes();
    [
        schema,
        &moved(0),
        &moved(4),
        &body[8..16],
        &end,
        &body[16..],
        &keys.concat(),
    ]
    .concat()
}

/// The **guest** publishes the subset's outputs: every case through the
/// `revm-block-stateless` image in the emulator, its journal held to the
/// release's 43 bytes. The library's answer is the program's only if the
/// binary a proof would be about agrees with it.
///
/// One case is not run: the empty input, which a run cannot be given, a run
/// with no advice having no advice region (`src/stateless_main.rs`).
/// `#[ignore]`d because it builds the 2 MB image from source. It prints each
/// case's cycles, which are what proving it costs.
#[test]
#[ignore = "builds the revm stateless guest from source"]
fn the_guest_publishes_the_subset_s_outputs() {
    through_the_guest(
        subset()
            .into_iter()
            .map(|case| (case.name, case.input, case.output)),
    );
}

/// The same through the binary for every pair under `APOGEE_ZKEVM_FIXTURES`:
/// an extracted benchmark batch, whose devnet blocks are a few hundred million
/// cycles each.
#[test]
#[ignore = "needs an extracted fixtures directory, named by APOGEE_ZKEVM_FIXTURES"]
fn every_output_of_a_directory_is_the_binary_s() {
    let dir = PathBuf::from(std::env::var(FIXTURES_VAR).expect(FIXTURES_VAR));
    through_the_guest(
        zkevm::files(&dir)
            .iter()
            .flat_map(|path| zkevm::pairs(path))
            .map(|pair| (pair.name, pair.input, pair.output)),
    );
}

/// Each `(name, input, output)` through the stateless image in the emulator:
/// exit 0, and the journal the expected bytes.
fn through_the_guest(cases: impl Iterator<Item = (String, Vec<u8>, Vec<u8>)>) {
    let elf = build_revm_guest(Mode::Stateless).expect("the stateless guest builds");
    let image = loader::load_elf(&elf).expect("the stateless guest loads");
    for (name, input, output) in cases.filter(|(_, input, _)| !input.is_empty()) {
        let verdict = zkevm::verdict(&input);
        let io = emulator::GuestIo {
            input: Vec::new(),
            advice: input,
        };
        let execution = emulator::run(&image, &io).expect("the guest runs");
        assert_eq!(execution.exit_code, 0, "{name}");
        assert_eq!(execution.io.output, output, "{name}");
        println!(
            "{:>12} cycles  {:<24} {name}",
            execution.cycle_count, verdict
        );
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
