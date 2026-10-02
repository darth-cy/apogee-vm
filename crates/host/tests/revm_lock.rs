//! **revm is the reference stateless guest's revm, crate for crate.**
//!
//! The owner's decision for the canonical stateless guest: run exactly the EVM
//! that `paradigmxyz/stateless` — reth's stateless validator, the reference
//! guest the zkEVM benchmark compares against — runs, which is the revm set its
//! `Cargo.lock` pins. That set is not "revm 43.0.1": the `revm` crate is a
//! facade over a dozen sub-crates, and the EVM's semantics live in those —
//! `revm-handler` 43.0.1 carries the EIP-8037 system-call state-gas reservoir
//! that `revm` 43.0.2 reverted, which is why 43.0.1 is the version the
//! reference guest and `tests-zkevm@v21.0.1`'s Amsterdam agree on.
//!
//! **Why this is a test and not a manifest pin.** `revm` 43.0.1,
//! `revm-handler` 43.0.1 and `revm-inspector` 43.0.1 are yanked on crates.io,
//! and cargo refuses to *select* a yanked version for a fresh resolution — so
//! the repository's usual `=` requirement can only hold the facade, once a
//! lockfile already contains it, and the sub-crates exist only in the two
//! lockfiles. A `cargo update` would move them silently. This test is what
//! makes that move a refusal instead: both lockfiles must hold [`REFERENCE`]
//! exactly, each crate once.
//!
//! To reproduce the lock from scratch, set each manifest's `revm` requirement
//! to a caret `43.0.1`, run `cargo update -p <crate> --precise <version>` over
//! [`REFERENCE`] until it stops changing (the yanked crates' siblings have to
//! come down first), then restore `=43.0.1`.

use std::fs;
use std::path::PathBuf;

/// `paradigmxyz/stateless`'s `Cargo.lock` at the commit pushed 2026-09-29,
/// every `revm` crate in it. `revm-precompile` is the version
/// `guests/vendor/revm-precompile` is vendored at; the guest workspace patches
/// that copy in, and the root workspace resolves the same version from
/// crates.io.
const REFERENCE: [(&str, &str); 12] = [
    ("revm", "43.0.1"),
    ("revm-bytecode", "43.0.0"),
    ("revm-context", "43.0.2"),
    ("revm-context-interface", "43.0.1"),
    ("revm-database", "43.0.0"),
    ("revm-database-interface", "43.0.0"),
    ("revm-handler", "43.0.1"),
    ("revm-inspector", "43.0.1"),
    ("revm-interpreter", "43.0.1"),
    ("revm-precompile", "43.0.2"),
    ("revm-primitives", "43.0.0"),
    ("revm-state", "43.0.0"),
];

/// Every `(name, version)` a lockfile records, in file order.
fn packages(lockfile: &str) -> Vec<(String, String)> {
    let text = fs::read_to_string(lockfile).unwrap_or_else(|e| panic!("{lockfile}: {e}"));
    let mut out = Vec::new();
    let mut name: Option<String> = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("name = ") {
            name = Some(value.trim_matches('"').to_string());
        } else if let Some(value) = line.strip_prefix("version = ") {
            if let Some(name) = name.take() {
                out.push((name, value.trim_matches('"').to_string()));
            }
        }
    }
    out
}

#[test]
fn both_lockfiles_hold_the_reference_revm_set() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for lockfile in ["Cargo.lock", "guests/Cargo.lock"] {
        let path = root.join(lockfile);
        let path = path.to_str().expect("a UTF-8 path");
        // `revm-block` is this repository's guest crate, not one of revm's.
        let revm: Vec<(String, String)> = packages(path)
            .into_iter()
            .filter(|(name, _)| name == "revm" || name.starts_with("revm-"))
            .filter(|(name, _)| name != "revm-block")
            .collect();
        for (name, version) in REFERENCE {
            let found: Vec<&String> = revm
                .iter()
                .filter(|(n, _)| n == name)
                .map(|(_, v)| v)
                .collect();
            assert_eq!(
                found,
                vec![version],
                "{lockfile}: {name} must be locked once, at the reference guest's {version}"
            );
        }
        assert_eq!(
            revm.len(),
            REFERENCE.len(),
            "{lockfile} carries a revm crate the reference guest does not: {revm:?}"
        );
    }
}
