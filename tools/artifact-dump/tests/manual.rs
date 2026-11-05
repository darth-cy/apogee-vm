//! `docs/guest-program-manual.md`, run.
//!
//! The manual tells a guest author to write a crate under `guests/`, build it
//! from that crate's own directory with nothing but `--target`, export it with
//! this tool, and then check the result by rebuilding into a fresh target
//! directory and comparing the two artifacts. Those are sections 2, 4, 5 and 7,
//! and this file is them: the same commands, in the same order, over every
//! guest the workspace has.
//!
//! It exists because a manual is the one artifact nothing else in a repository
//! holds to account. `dump.rs` proves the tool agrees with `crates/loader`;
//! `crates/loader/tests/layout.rs` proves the images are host loadable; neither
//! notices when the *procedure a person is told to follow* stops working.
//!
//! The guest list is read out of `guests/Cargo.toml` rather than written down
//! here, so this cannot go stale by omission: a guest that exists is a guest
//! that gets walked.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use artifact_dump::dump;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The names in the first `members = [...]` line of `text`.
///
/// A line scan rather than a TOML crate, because the workspace takes no
/// dependency it does not need and this is one line whose shape is fixed.
///
/// A `members` line that stops looking like this is a change worth failing on
/// rather than parsing around, so the callers assert on what comes back.
fn members_in(text: &str, what: &str) -> Vec<String> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("members"))
        .unwrap_or_else(|| panic!("{what} has no `members` line"));
    let list = line
        .split_once('[')
        .and_then(|(_, rest)| rest.split_once(']'))
        .unwrap_or_else(|| panic!("{what}'s members line is not a single-line array"))
        .0;
    let names: Vec<String> = list
        .split(',')
        .map(|f| f.trim().trim_matches('"').to_string())
        .filter(|f| !f.is_empty())
        .collect();
    assert!(
        names.len() >= 3,
        "{what} lists only {names:?}, which cannot be right"
    );
    names
}

/// The `members` of the guest workspace, in the order the manifest lists them.
fn guest_members() -> Vec<String> {
    let manifest = repo_root().join("guests/Cargo.toml");
    let text = fs::read_to_string(&manifest)
        .unwrap_or_else(|e| panic!("reading {}: {e}", manifest.display()));
    members_in(&text, "guests/Cargo.toml")
}

/// Build one guest the way section 4 says to, into a fresh target directory.
///
/// The command is the manual's, typed out: `cargo build --target
/// riscv32imac-unknown-none-elf`, run from the guest's own directory, with the
/// target and the two linker flags coming from `guests/.cargo/config.toml` and
/// nothing coming from here.
///
/// This is a near-copy of `crates/loader/tests/common/mod.rs`'s `build`, and it
/// is a copy on purpose: a test module belongs to its crate, and the alternative
/// is a shared crate that exists only so two test suites can shell out to cargo
/// the same way. The environment scrub is the load-bearing half — a stray
/// `RUSTFLAGS` inherited from whoever ran `cargo test` would put a different
/// compiler invocation on each side of the comparison below.
fn build(name: &str, slot: &str) -> PathBuf {
    let guest_dir = repo_root().join("guests").join(name);
    let target_dir = std::env::temp_dir().join(format!("apogee-manual-{slot}-{name}"));
    let _ = fs::remove_dir_all(&target_dir);

    let mut command = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(&guest_dir)
        .args(["build", "--target", "riscv32imac-unknown-none-elf"])
        .env("CARGO_TARGET_DIR", &target_dir);
    for key in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        command.env_remove(key);
    }
    let out = command.output().expect("running cargo for a guest");
    assert!(
        out.status.success(),
        "{name}: the manual's build command failed\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    let elf = target_dir
        .join("riscv32imac-unknown-none-elf/debug")
        .join(name);
    assert!(
        elf.is_file(),
        "{name}: section 4 says the ELF lands at {}, and it did not",
        elf.display()
    );
    elf
}

// ---------------------------------------------------------------------------
// The walkthrough
// ---------------------------------------------------------------------------

/// Sections 4, 5 and 7, for every guest, from an empty target directory.
///
/// Build, export, build again somewhere else, export again, and compare. The
/// manual promises three things about that and this checks all three.
///
/// **The artifact is byte-identical.** That is section 7's first check and the
/// property a reader is told to pin a digest against. It holds per machine, not
/// across machines, for the embedded-path reason section 5 gives; both builds
/// here are on one machine, which is exactly the claim.
///
/// **The report is the same page**, except for the one line that records where
/// the ELF was read from — which differs because the two target directories do.
/// A second difference anywhere else would mean the report carries something
/// that is not a function of the artifact, which is the one thing it must not
/// do.
///
/// **The export refuses rather than lies.** `dump` serializes, reads back
/// through the reader that re-checks every invariant, and compares; it is given
/// no chance to write a file it could not prove correct. Reaching `Ok` here is
/// that round trip having passed twice per guest.
///
/// Nothing is written to disk. The manual's `--out` is the CLI's business and
/// `dump` is the same code path underneath it, so the comparison is over the
/// bytes that would have been written.
#[test]
fn every_guest_walks_the_manuals_procedure() {
    for name in guest_members() {
        let first = build(&name, "a");
        let second = build(&name, "b");

        let artifact = format!("{name}.img");
        let a = dump(
            &fs::read(&first).expect("the first build's ELF"),
            &first.display().to_string(),
            &artifact,
        )
        .unwrap_or_else(|e| panic!("{name}: the first export failed: {e}"));
        let b = dump(
            &fs::read(&second).expect("the second build's ELF"),
            &second.display().to_string(),
            &artifact,
        )
        .unwrap_or_else(|e| panic!("{name}: the second export failed: {e}"));

        assert_eq!(
            a.artifact, b.artifact,
            "{name}: two clean builds exported different artifacts, so the digest \
             section 7 tells a reader to pin is not stable"
        );
        assert_eq!(
            a.image, b.image,
            "{name}: the two images differ even though the artifacts do not"
        );

        let differing: Vec<(&str, &str)> = a
            .report
            .lines()
            .zip(b.report.lines())
            .filter(|(x, y)| x != y)
            .collect();
        assert_eq!(
            a.report.lines().count(),
            b.report.lines().count(),
            "{name}: the two reports are different lengths"
        );
        for (x, y) in &differing {
            assert!(
                x.starts_with("source ELF") && y.starts_with("source ELF"),
                "{name}: the reports differ somewhere other than the source path:\n\
                 {x}\n{y}"
            );
        }
        assert_eq!(
            differing.len(),
            1,
            "{name}: exactly one line records the source path, and {} differ",
            differing.len()
        );

        cleanup(&first);
        cleanup(&second);
    }
}

/// Remove the target directory a build left behind.
///
/// `build` returns the ELF's path, so the target directory is four components
/// above it. Failure is ignored: a leftover directory under the system temp dir
/// is not worth failing a passing test over, and the next run removes it before
/// building anyway.
fn cleanup(elf: &Path) {
    if let Some(target) = elf.ancestors().nth(3) {
        let _ = fs::remove_dir_all(target);
    }
}
