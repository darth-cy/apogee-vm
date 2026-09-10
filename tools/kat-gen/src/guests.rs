//! Rebuild the committed guest ELFs.
//!
//! Deliberately **not** part of a bare `cargo run -p kat-gen`: see the comment
//! on `DEFAULT_GROUPS` in `main.rs`. Refreshing these is a manual, one-machine
//! step:
//!
//!     cargo run -p kat-gen -- guests
//!
//! Each guest is built twice into two fresh target directories and the two
//! results compared before either is copied in, so a fixture that lands here is
//! one the toolchain produced the same way twice.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use test_support::{sha256, to_hex};

use crate::loader::ELF_FIXTURES;

pub fn generate() {
    for (name, why) in ELF_FIXTURES {
        let a = build(name, "a");
        let b = build(name, "b");
        assert_eq!(
            sha256(&a),
            sha256(&b),
            "{name}: two clean builds with fresh target directories disagree, \
             so this guest is not reproducible"
        );
        crate::write_bytes(&format!("crates/loader/tests/vectors/{name}.elf"), &a);
        println!("  {name}.elf: {} bytes -- {why}", a.len());
    }
}

/// Build one guest into a fresh target directory and return its ELF bytes.
///
/// The command is acceptance 1's, typed out: nothing but `cargo build
/// --target riscv32imac-unknown-none-elf`, run from the guest's own directory,
/// with the target, the runner and the linker flags coming from
/// `guests/.cargo/config.toml`.
fn build(name: &str, slot: &str) -> Vec<u8> {
    let guest_dir = repo_root().join("guests").join(name);
    let target_dir = std::env::temp_dir().join(format!("apogee-guest-{name}-{slot}"));
    let _ = fs::remove_dir_all(&target_dir);

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut command = Command::new(cargo);
    command
        .current_dir(&guest_dir)
        .args(["build", "--target", "riscv32imac-unknown-none-elf"])
        .env("CARGO_TARGET_DIR", &target_dir);
    // Anything that could reach rustc from the ambient environment is cleared:
    // a guest ELF is an artifact whose bytes are compared, and a stray
    // RUSTFLAGS would make the comparison meaningless.
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

    let status = command.status().expect("running cargo for a guest");
    assert!(status.success(), "{name}: guest build failed");

    let elf = target_dir
        .join("riscv32imac-unknown-none-elf/debug")
        .join(name);
    let bytes = fs::read(&elf).unwrap_or_else(|e| panic!("reading {}: {e}", elf.display()));
    let _ = fs::remove_dir_all(&target_dir);
    println!(
        "  built {name} ({} bytes, sha256 {})",
        bytes.len(),
        to_hex(&sha256(&bytes))
    );
    bytes
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace root exists")
}
