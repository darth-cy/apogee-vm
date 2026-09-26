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
//!
//! **One directory is exempt, and it is not an exception to the rule.**
//! `guests/vendor` holds upstream crates vendored so that a guest can patch
//! them — S26 vendored `k256` to route its field multiply through the `MOD_MUL`
//! delegation — and an upstream crate's own `[features]` table is that crate's,
//! not ours. It was already invisible to this test when the same crate came
//! from crates.io; vendoring moved the bytes into the tree and changed nothing
//! about whose features they are. What keeps the exemption honest is the second
//! test below: every vendored crate must be one `guests/Cargo.toml` actually
//! patches in, so a directory nothing uses fails rather than sitting there.

use std::fs;
use std::path::{Path, PathBuf};

/// Repository-relative directories whose manifests are upstream crates', not
/// ours. See the module doc; `the_vendored_crates_are_the_ones_a_guest_patches`
/// holds each to being a crate the repository really patches in.
const VENDORED: [&str; 1] = ["guests/vendor"];

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

/// Is this manifest an upstream crate's, vendored under one of [`VENDORED`]?
fn vendored(root: &Path, manifest: &Path) -> bool {
    let rel = manifest.strip_prefix(root).unwrap_or(manifest);
    VENDORED.iter().any(|dir| rel.starts_with(dir))
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
        if vendored(&root, manifest) {
            continue;
        }
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

/// The exemption, checked in both directions: every directory in [`VENDORED`]
/// exists and holds at least one manifest, and every crate it holds is one
/// `guests/Cargo.toml` patches in. A vendored crate nothing patches is either
/// dead weight or a crate that is being compiled from a copy nobody reviews,
/// and the exemption should not cover either.
#[test]
fn the_vendored_crates_are_the_ones_a_guest_patches() {
    let root = root();
    let patches = fs::read_to_string(root.join("guests/Cargo.toml")).expect("guests/Cargo.toml");
    let patches = patches
        .split_once("[patch.crates-io]")
        .expect("guests/Cargo.toml declares [patch.crates-io], or nothing needs vendoring")
        .1;
    // The table ends at the next header; each line is `name = { path = ... }`.
    let patched: Vec<&str> = patches
        .lines()
        .map(str::trim)
        .take_while(|l| !l.starts_with('['))
        .filter_map(|l| l.split_once('='))
        .map(|(name, _)| name.trim())
        .collect();

    for dir in VENDORED {
        let mut found = Vec::new();
        manifests(&root.join(dir), &mut found);
        assert!(
            !found.is_empty(),
            "{dir} is exempt from the one-feature sweep and holds no manifest: delete the \
             exemption with the directory"
        );
        for manifest in &found {
            let crate_dir = manifest
                .parent()
                .and_then(Path::file_name)
                .expect("a manifest has a parent directory")
                .to_string_lossy()
                .to_string();
            assert!(
                patched.contains(&crate_dir.as_str()),
                "{dir}/{crate_dir} is vendored but `guests/Cargo.toml`'s [patch.crates-io] \
                 does not name it, so nothing compiles it: patched = {patched:?}"
            );
        }
    }
}
