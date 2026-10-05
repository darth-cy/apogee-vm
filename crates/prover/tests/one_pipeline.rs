//! **Master anti-goal 7, with its one exception, enforced.** The rule is "No
//! async, no threads, no interior mutability. Parallelism is `rayon` over data,
//! and nothing else"; the owner granted the streaming prover's shard pipeline
//! at S-PIPELINE, and this test is what keeps it exactly that one site, in
//! exactly that one shape.
//!
//! **Why the exception exists.** A shard's proof is several gigabytes of
//! columns and forward pass, so the number alive at once has to be bounded
//! below the core count, and the shards must be produced on demand rather than
//! ahead of it. With that bound, fork-join can only run them in lock-step
//! batches, each waiting for its slowest shard. What it cannot say is *start
//! the next shard when any one finishes*. That takes one point where workers
//! coordinate, and rayon offers it only inside `par_bridge`, whose bound would
//! rest on one of rayon's own internals. So
//! `crates/prover/src/streaming.rs` runs `max_in_flight` workers under
//! `std::thread::scope`, sharing one `std::sync::Mutex` around the executor,
//! and everything inside a shard is still rayon over data
//! (`docs/spec/streaming.md` §5).
//!
//! **What is swept.** Every `.rs` file under `crates/*/src` and `tools/*/src`:
//! the proving stack and its tools, which is what the anti-goal governs. Not
//! the test suites, where one process-wide counter names temporary
//! directories (`tests/common`'s `SEQ`), and not `guests/`, whose atomics are
//! the RISC-V A extension `guests/atomics` exists to prove — a guest is the
//! workload, not the prover. A comment-only line says nothing about what runs
//! and is skipped, as `tests/one_proving_path.rs` skips it.
//!
//! What is benign and allowed everywhere: `std::thread::sleep` (the RPC
//! client's backoff), `available_parallelism` (the bench report's hardware
//! line), and `std::thread::panicking`. None of them starts a thread or shares
//! a value.

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

/// The one file the exception covers.
const PIPELINE: &str = "crates/prover/src/streaming.rs";

/// What anti-goal 7 names, as source text: starting a thread, a lock or a
/// condition, a channel, an atomic, a lazily-initialized global, and async.
/// `Atomic` alone would match the word in prose, so the atomics are the module
/// path and the type-name prefixes.
const FORBIDDEN: [&str; 15] = [
    "thread::spawn",
    "thread::scope",
    "thread::Builder",
    "spawn_scoped",
    "Mutex",
    "RwLock",
    "Condvar",
    "Barrier",
    "mpsc",
    "sync::atomic",
    "AtomicBool",
    "AtomicUsize",
    "AtomicU64",
    "OnceLock",
    "async fn",
];

/// Every `.rs` file under `dir`, recursively.
fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every `.rs` file under each `<root>/<group>/<crate>/src`.
fn swept(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for group in ["crates", "tools"] {
        let Ok(crates) = fs::read_dir(root.join(group)) else {
            continue;
        };
        for krate in crates.flatten() {
            sources(&krate.path().join("src"), &mut files);
        }
    }
    files
}

/// A line that is only a comment says nothing about what runs.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//") || t.starts_with('*')
}

/// Every `(line number, needle)` of `text`'s code lines that names one of
/// [`FORBIDDEN`].
fn offences(text: &str) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if is_comment(line) {
            continue;
        }
        for needle in FORBIDDEN {
            if line.contains(needle) {
                found.push((n + 1, needle));
            }
        }
    }
    found
}

#[test]
fn no_thread_lock_channel_or_atomic_outside_the_shard_pipeline() {
    let root = root();
    let files = swept(&root);
    assert!(files.len() > 100, "the sweep found almost nothing");
    assert!(
        files.iter().any(|f| f.ends_with(PIPELINE)),
        "the sweep did not reach {PIPELINE}"
    );

    let mut found = Vec::new();
    for file in &files {
        let rel = file.strip_prefix(&root).unwrap().to_string_lossy();
        if rel == PIPELINE {
            continue;
        }
        let text = fs::read_to_string(file).unwrap_or_else(|_| panic!("{rel} reads"));
        for (n, needle) in offences(&text) {
            found.push(format!("{rel}:{n}: {needle}"));
        }
    }
    assert!(
        found.is_empty(),
        "master anti-goal 7 bans threads, locks, channels, atomics, OnceLock and async, \
         and its one exception is {PIPELINE}'s shard pipeline (S-PIPELINE):\n  {}\n\
         Parallelism is rayon over data. A second exception is the owner's decision and \
         nobody else's; this file is where it would have to be written.",
        found.join("\n  ")
    );
}

/// The exception itself, held to its shape: **one scope of workers and one
/// lock**, and nothing else from the list. A second lock is a second thing to
/// order and a channel is a queue the executor could run ahead into, so either
/// would be a different design and not a change to this one.
#[test]
fn the_pipeline_is_one_scope_of_workers_and_one_lock() {
    let text = fs::read_to_string(root().join(PIPELINE)).expect("the pipeline reads");
    let code = |needle: &str| {
        text.lines()
            .filter(|line| !is_comment(line))
            .map(|line| line.matches(needle).count())
            .sum::<usize>()
    };
    assert_eq!(
        code("std::thread::scope("),
        1,
        "the pipeline starts its workers in exactly one std::thread::scope"
    );
    assert_eq!(
        code("Mutex::new("),
        1,
        "the pipeline shares exactly one lock, around the executor"
    );
    let mut shape = Vec::new();
    for (n, needle) in offences(&text) {
        if !matches!(needle, "thread::scope" | "Mutex") {
            shape.push(format!("{PIPELINE}:{n}: {needle}"));
        }
    }
    assert!(
        shape.is_empty(),
        "the exception is one std::thread::scope and one Mutex, and nothing else from \
         anti-goal 7's list:\n  {}",
        shape.join("\n  ")
    );
}
