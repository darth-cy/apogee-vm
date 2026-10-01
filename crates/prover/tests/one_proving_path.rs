//! **Streaming is the only proving path, enforced** (owner's decision,
//! S-STREAM).
//!
//! `prover::prove_block` and the phase machinery around it — `advance`,
//! `finish`, the five section codecs and the snapshots — still compile and are
//! deliberately kept: `checker::TamperHarness` writes a cell into a shard's
//! columns and re-proves that one shard, which has no streaming seam (pass 1
//! commits the memory columns, pass 2 re-executes, so a tamper applied in one
//! pass contradicts the other), and the root `CLAUDE.md` says the harness is
//! not optional. What they are *not* is a path anything runs. Every block and
//! every statement in this repository is proved by
//! `prover::prove_block_streaming`.
//!
//! The rule is a grep because the alternative is deletion, and deletion would
//! take the tamper harness with it. A grep is also exactly what
//! `tests/one_feature.rs` does for master anti-goal 1, and for the same
//! reason: the property is about the whole repository, so the test has to read
//! the whole repository.
//!
//! # What is forbidden, and what is not
//!
//! Forbidden outside `crates/prover/src`: calling `prove_block`, and naming
//! `advance`, `finish` or `prove_block` in a `use prover::…` list. The
//! `*_metered` variants were deleted with the `metrics` feature at S-STREAM
//! and so cannot be called at all; they are not listed here, because a needle
//! that can never match is a needle nobody maintains.
//!
//! **Not** forbidden, and used by several suites: the per-shard component the
//! tamper harness is built on — `statement_inputs`, `global_commit_phase`,
//! `shard_columns`, `prove_shard`, `prove_shard_columns` — and `TraceArchive`
//! itself, which is a post-execution container that `crates/checker`'s
//! column-fill suites read and `crates/emulator/tests/archive.rs` round-trips.
//! Holding an execution is not proving from one.

use std::fs;
use std::path::{Path, PathBuf};

/// The repository root: this crate is `<root>/crates/prover`.
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crates/prover sits two levels below the root")
        .to_path_buf()
}

/// The two places the archived block path may be named: where it is defined,
/// and this file, which has to spell the forbidden tokens out to look for
/// them.
const EXEMPT: [&str; 2] = [
    "crates/prover/src",
    "crates/prover/tests/one_proving_path.rs",
];

/// Directories that are not source of ours to police.
const SKIP: [&str; 5] = ["target", ".git", "assets", "guests/vendor", "docs"];

/// Every `.rs` file under `dir`, recursively, skipping [`SKIP`].
fn sources(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy();
        if SKIP.iter().any(|s| rel.starts_with(s)) {
            continue;
        }
        if path.is_dir() {
            sources(root, &path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// A line that is only a comment says nothing about what runs.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with('*')
}

#[test]
fn nothing_proves_through_the_archived_path() {
    let root = root();
    let mut files = Vec::new();
    sources(&root, &root, &mut files);
    assert!(files.len() > 100, "the sweep found almost nothing");

    let mut offences = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy();
        if EXEMPT.iter().any(|e| rel.starts_with(e)) {
            continue;
        }
        let Ok(text) = fs::read_to_string(file) else {
            continue;
        };
        for (n, line) in text.lines().enumerate() {
            if is_comment(line) {
                continue;
            }
            // `prove_block_streaming(` does not contain `prove_block(`, so
            // this literal is exact and needs no word-boundary machinery.
            for call in ["prove_block("] {
                if line.contains(call) {
                    offences.push(format!("{rel}:{}: calls {call}", n + 1));
                }
            }
            if let Some(rest) = line.split("use prover::").nth(1) {
                for name in ["advance", "finish", "prove_block"] {
                    let imported = rest
                        .split(|c: char| !c.is_alphanumeric() && c != '_')
                        .any(|t| t == name);
                    if imported {
                        offences.push(format!("{rel}:{}: imports prover::{name}", n + 1));
                    }
                }
            }
            for qualified in ["prover::advance", "prover::finish", "prover::prove_block("] {
                if line.contains(qualified) {
                    offences.push(format!("{rel}:{}: names {qualified}", n + 1));
                }
            }
        }
    }
    assert!(
        offences.is_empty(),
        "streaming is the only proving path (S-STREAM), and these reach the archived one:\n  {}\n\
         Prove with `prover::prove_block_streaming`. If a test needs a shard's columns \
         rather than a block, `statement_inputs` + `shard_columns` + `prove_shard` are \
         the component the tamper harness uses and they are not forbidden.",
        offences.join("\n  ")
    );
}

/// And the archived path is still *there*, which is the other half of the
/// decision: it was retained rather than deleted, so the tamper harness keeps
/// working. A stage that deletes it must delete this test and say why.
#[test]
fn the_archived_path_is_retained() {
    let src = fs::read_to_string(root().join("crates/prover/src/phases.rs"))
        .expect("crates/prover/src/phases.rs");
    assert!(
        src.contains("pub fn prove_block("),
        "prove_block was deleted; `checker::TamperHarness` and the checker's \
         column-fill suites are built on the archive it reads, and the root \
         CLAUDE.md says the harness is not optional"
    );
}
