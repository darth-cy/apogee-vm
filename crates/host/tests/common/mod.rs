//! What the proving suites in this crate share: a toy SRS and a guest build.
//!
//! Both are copies of code that already exists — `crates/prover/tests/common`
//! has the first and four crates have the second. They are copies on purpose:
//! a test module cannot be shared across a crate boundary, and this repository
//! has made that trade four times already rather than promote a test helper
//! into a shipped crate.

#![allow(dead_code)]

use std::path::PathBuf;

use curve::{G1Projective, G2Affine};
use field::Fr;

/// An SRS over a tau written down in this file.
///
/// Structurally valid and **completely insecure**, which is the right trade for
/// a test: a proof's timings and its shape do not depend on which powers of tau
/// the key was built over, and its *identity* does — so a suite that asks
/// whether a statement proves and verifies wants the cheap one, and anything
/// claiming a published identity wants the ceremony. Every proving test in this
/// repository uses this.
///
/// Cached under `CARGO_TARGET_TMPDIR`, which cargo sets for integration tests,
/// because building `2^20` powers takes seconds and every test here wants the
/// same one.
pub fn toy_srs(power: u32) -> srs::Srs {
    use rayon::prelude::*;

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join(format!("s25-toy-{power}.srs"));
    if let Ok(srs) = srs::Srs::load(&path) {
        return srs;
    }
    let tau = Fr::from_hex("0x0000000000000000000000000000000000000000000000000000000000c0ffee")
        .expect("a canonical literal");
    let count = 1usize << power;
    let mut scalars = Vec::with_capacity(count);
    let mut acc = Fr::ONE;
    for _ in 0..count {
        scalars.push(acc);
        acc *= tau;
    }
    let projective: Vec<G1Projective> = scalars
        .par_iter()
        .map(|s| G1Projective::GENERATOR.mul(s))
        .collect();
    let g1 = G1Projective::batch_to_affine(&projective);
    let g2_tau = G2Affine::GENERATOR.mul(&tau);

    let mut bytes = Vec::with_capacity(280 + count * 64);
    bytes.extend_from_slice(b"APOGESRS");
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&power.to_le_bytes());
    bytes.extend_from_slice(&(count as u64).to_le_bytes());
    bytes.extend_from_slice(&G2Affine::GENERATOR.to_bytes());
    bytes.extend_from_slice(&g2_tau.to_bytes());
    for p in &g1 {
        bytes.extend_from_slice(&p.to_bytes());
    }
    std::fs::create_dir_all(&dir).expect("the test directory");
    // Written aside and renamed, so a suite running beside this one never reads
    // half a file.
    let partial = dir.join(format!("s25-toy-{power}.{}.partial", std::process::id()));
    std::fs::write(&partial, &bytes).expect("writing the toy archive");
    std::fs::rename(&partial, &path).expect("placing the toy archive");
    srs::Srs::load(&path).expect("the toy archive loads")
}

/// One binary of `guests/revm-block`, built from source at `--release`.
///
/// **Always `--release`, whatever `APOGEE_GUEST_PROFILE` says**, for the reason
/// `crates/prover/tests/revm.rs` gives: the heights are pinned to the release
/// image, which fits `2^20`, and the debug image is 3.3 times larger and would
/// need `2^22` — four times the rows in every shard, for a build nothing proves.
///
/// Everything that could reach rustc from the ambient environment is cleared,
/// because a guest ELF is an artifact whose bytes decide an identity.
pub fn build_guest_bin(bin: &str, slot: &str) -> Vec<u8> {
    let guest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../guests/revm-block");
    let target_dir =
        std::env::temp_dir().join(format!("apogee-host-{bin}-{slot}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&target_dir);
    let mut command =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(&guest_dir)
        .args([
            "build",
            "--release",
            "--target",
            "riscv32imac-unknown-none-elf",
            "--bin",
            bin,
        ])
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
        "{bin}: guest build failed\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let elf = target_dir
        .join("riscv32imac-unknown-none-elf/release")
        .join(bin);
    let bytes = std::fs::read(&elf).unwrap_or_else(|e| panic!("reading {}: {e}", elf.display()));
    let _ = std::fs::remove_dir_all(&target_dir);
    bytes
}
