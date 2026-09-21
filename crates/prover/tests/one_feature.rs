//! **Master anti-goal 1, enforced.** The rule is "No cargo features. Zero.";
//! the owner granted exactly one exception at S20, `prover/metrics`, and this
//! test is what keeps it exactly one.
//!
//! It reads every `Cargo.toml` under the repository — the workspace, and the
//! three manifests deliberately outside it (`crates/guest-sdk`, `guests`,
//! `tools/transcript-ref`) — and refuses any `[features]` table but this
//! crate's, and any key in this crate's but `metrics`.
//!
//! A `features = [...]` **key** inside a dependency entry is a different
//! thing: it selects an upstream crate's features, which anti-goal 1 permits
//! and the workspace manifest already does for `ark-ec` and `ark-ff`. Only a
//! `[features]` **table header** declares a feature of ours, so only a table
//! header is what this test looks for.

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

/// Every `Cargo.toml` in the tree, `target` and `.git` skipped.
fn manifests(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if name == "target" || name == ".git" || name.starts_with('.') {
                continue;
            }
            manifests(&path, out);
        } else if name == "Cargo.toml" {
            out.push(path);
        }
    }
}

/// The `[features]` table's keys, if the manifest has one. A table ends at the
/// next table header.
fn feature_keys(text: &str) -> Option<Vec<String>> {
    let mut lines = text.lines().map(str::trim);
    lines.by_ref().find(|l| *l == "[features]")?;
    let mut keys = Vec::new();
    for line in lines {
        if line.starts_with('[') {
            break;
        }
        let line = match line.split_once('#') {
            Some((before, _)) => before.trim(),
            None => line,
        };
        if line.is_empty() {
            continue;
        }
        if let Some((key, _)) = line.split_once('=') {
            keys.push(key.trim().to_string());
        }
    }
    Some(keys)
}

#[test]
fn the_metrics_feature_is_the_only_cargo_feature_in_the_repository() {
    let root = root();
    let mut found = Vec::new();
    manifests(&root, &mut found);
    assert!(
        found.len() > 20,
        "the sweep found only {} manifests, which cannot be the whole tree",
        found.len()
    );

    let ours = root.join("crates/prover/Cargo.toml");
    let mut with_features = Vec::new();
    for manifest in &found {
        let text = fs::read_to_string(manifest).expect("a manifest reads");
        if let Some(keys) = feature_keys(&text) {
            with_features.push((manifest.clone(), keys));
        }
    }

    let names: Vec<String> = with_features
        .iter()
        .map(|(p, _)| {
            p.strip_prefix(&root)
                .unwrap_or(p)
                .to_string_lossy()
                .to_string()
        })
        .collect();
    assert_eq!(
        names,
        vec!["crates/prover/Cargo.toml".to_string()],
        "master anti-goal 1: `crates/prover`'s `metrics` is the repository's ONE cargo \
         feature, granted by the owner at S20 for the proving harness and nothing else. \
         A manifest listed here that is not it has declared a second one. Delete it: \
         if code is optional, delete the code"
    );
    assert_eq!(
        with_features[0].0, ours,
        "the one `[features]` table is this crate's"
    );
    assert_eq!(
        with_features[0].1,
        vec!["metrics".to_string()],
        "the one `[features]` table declares `metrics` and nothing else"
    );
}

/// The exception is documented where a future stage will read it, not only in
/// the manifest that takes it. Each of these says so in its own words; this
/// holds them to saying it at all.
#[test]
fn the_exception_is_written_down_where_the_rules_are() {
    let root = root();
    for (path, needle) in [
        ("CLAUDE.md", "metrics"),
        ("docs/spec/metrics.md", "anti-goal 1"),
        ("crates/prover/CLAUDE.md", "metrics"),
    ] {
        let text = fs::read_to_string(root.join(path))
            .unwrap_or_else(|_| panic!("{path} exists and is readable"));
        assert!(
            text.contains(needle),
            "{path} does not mention {needle:?}: the one cargo feature in the repository \
             must be documented where the next stage looks for the rules"
        );
    }
}
