//! **Master anti-goal 1, enforced.** The rule is "No cargo features. Zero.";
//! the owner granted `prover/debug-info` at S-DEBUG, and this test is what
//! keeps it exactly that one.
//!
//! It reads every `Cargo.toml` under the repository — the workspace, and the
//! three manifests deliberately outside it (`crates/guest-sdk`, `guests`,
//! `tools/transcript-ref`) — and refuses any `[features]` table but this
//! crate's, and any key in this crate's but [`EXPECTED`]'s one.
//!
//! **The exception turns on a module that is deliberately liberal** —
//! `debug-info` scans every live row of a delegation shard — and that may not
//! sit in the path of a real proving run. It is off by default, it enables no
//! dependency, and it changes no proof byte: `tests/debug_info.rs` proves the
//! last of those. A second feature is not a precedent it establishes; it is a
//! decision only the owner may take, and [`EXPECTED`] is where it would have
//! to be written.
//!
//! **There was a second, and it was retired rather than kept.**
//! `prover/metrics` was granted at S20 for the proving harness: stage timing,
//! byte accounting and a modelled memory peak over the *archived* proving
//! path. At S-STREAM the streaming prover became the only path a block is
//! proved down, which left the harness measuring a path nothing runs — and a
//! configuration nobody builds is precisely the hazard anti-goal 1 exists to
//! forbid. So the feature, its module, its suite and its spec were deleted
//! rather than ported, and the count here went from two back to one.
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

/// **The repository's cargo features, in `crates/prover/Cargo.toml`'s order.**
///
/// One entry, `debug-info`, granted by the owner at S-DEBUG. `metrics` was the
/// other, granted at S20 and **retired at S-STREAM** when the archived path it
/// measured stopped being run.
///
/// Adding a name here is the whole of adding a feature to this workspace, and it
/// is the owner's decision and nobody else's (master anti-goal 1). Each entry
/// owes four things: a `[features]` comment saying who granted it and for what,
/// a spec document, a CI job that builds and clippies the configuration on, and
/// a test that the feature changes no proof byte.
const EXPECTED: [&str; 1] = ["debug-info"];

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
fn the_granted_features_are_the_only_cargo_features_in_the_repository() {
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
        "master anti-goal 1: `crates/prover`'s {EXPECTED:?} is the repository's ONLY \
         cargo feature, granted by the owner for one harness and nothing else. \
         A manifest listed here that is not it has declared another. Delete it: \
         if code is optional, delete the code"
    );
    assert_eq!(
        with_features[0].0, ours,
        "the one `[features]` table is this crate's"
    );
    assert_eq!(
        with_features[0].1,
        EXPECTED.map(String::from).to_vec(),
        "the one `[features]` table declares exactly {EXPECTED:?}, in that order, and \
         nothing else. A second feature is the owner's decision, not a stage's"
    );
}

/// The exception is documented where a future stage will read it, not only in
/// the manifest that takes it. Each of these says so in its own words; this
/// holds them to saying it at all — including the anti-goal itself, which has to
/// record that it has an exception and name it.
#[test]
fn the_exception_is_written_down_where_the_rules_are() {
    let root = root();
    for (path, needle) in [
        ("CLAUDE.md", "debug-info"),
        ("docs/spec/debug-info.md", "anti-goal 1"),
        ("crates/prover/CLAUDE.md", "debug-info"),
        ("prompts/00-master.md", "debug-info"),
    ] {
        let text = fs::read_to_string(root.join(path))
            .unwrap_or_else(|_| panic!("{path} exists and is readable"));
        assert!(
            text.contains(needle),
            "{path} does not mention {needle:?}: each cargo feature in the repository \
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

/// **The guest profiles differ only in `opt-level`**, and neither turns
/// `overflow-checks` or `debug-assertions` off.
///
/// This is not tidiness. In a zkVM the journal is the *committed public
/// output*, so a guest that wraps a `u32` under cargo's default release
/// profile commits `00000000` where the dev build panics and exits 101 — which
/// would make the optimisation level part of the statement being proven.
/// Cargo's dev defaults already have both checks on, so only `[profile.release]`
/// has to spell them; what the dev table must not do is switch either off.
/// Neither table spells `opt-level`, so each takes its default — 0 and 3 — and
/// that is the one difference between them.
///
/// It is asserted over the manifest rather than witnessed by running the
/// guests twice. Until the POSIX layer was deleted, CI ran
/// `crates/loader/tests/qemu.rs` at both profiles and compared fd 1 byte for
/// byte, and the pin was what that comparison rested on; the comparison went
/// with QEMU, and a manifest assertion is both cheaper and more direct than
/// re-running fifteen guests to infer one boolean. The mutation it catches —
/// deleting either line from `[profile.release]`, switching one off in
/// `[profile.dev]`, or letting the two drift apart on anything else — is
/// caught by nothing else in the repository.
#[test]
fn the_guest_profiles_differ_only_in_opt_level() {
    let text = fs::read_to_string(root().join("guests/Cargo.toml"))
        .expect("guests/Cargo.toml is readable");

    // The keys of one `[profile.<name>]` table, as `key = value` pairs.
    let table = |name: &str| -> Vec<(String, String)> {
        let header = format!("[profile.{name}]");
        let at = text
            .find(&header)
            .unwrap_or_else(|| panic!("guests/Cargo.toml has no {header}"));
        let rest = &text[at + header.len()..];
        let end = rest.find("\n[").map_or(rest.len(), |i| i + 1);
        rest[..end]
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| {
                let (k, v) = l
                    .split_once('=')
                    .unwrap_or_else(|| panic!("not an assignment: {l}"));
                (k.trim().to_string(), v.trim().to_string())
            })
            .collect()
    };

    let (dev, release) = (table("dev"), table("release"));
    let value =
        |t: &[(String, String)], k: &str| t.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone());

    for key in ["overflow-checks", "debug-assertions"] {
        assert_eq!(
            value(&release, key).as_deref(),
            Some("true"),
            "guests/Cargo.toml's [profile.release] must pin {key} = true: a \
             guest's journal is the committed public output, and the \
             optimisation level must not change it"
        );
        assert_ne!(
            value(&dev, key).as_deref(),
            Some("false"),
            "guests/Cargo.toml's [profile.dev] switches {key} off"
        );
    }

    // No table spells `opt-level`: each takes cargo's default, which is the
    // one difference the two profiles are allowed.
    for (name, t) in [("dev", &dev), ("release", &release)] {
        assert_eq!(
            value(t, "opt-level"),
            None,
            "[profile.{name}] spells opt-level; the profiles take cargo's \
             defaults, and this test can no longer say what differs"
        );
    }

    // Every other key either table spells must agree with the other, where the
    // other spells it at all.
    for (k, v) in dev.iter().chain(&release) {
        if k == "overflow-checks" || k == "debug-assertions" {
            continue;
        }
        if let (Some(d), Some(r)) = (value(&dev, k), value(&release, k)) {
            assert_eq!(&d, &r, "the guest profiles disagree on {k}");
        }
        let _ = v;
    }
}
