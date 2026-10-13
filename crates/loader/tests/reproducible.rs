//! Two clean builds of a guest give byte-identical ELFs.
//!
//! This lives in a test rather than in a CI script so that it runs wherever
//! `cargo test` does, and so that a regression is a failing test rather than a
//! line of shell nobody reads.
//!
//! **What it does not claim.** Byte-identity holds for two builds of the same
//! source on the same machine. It does *not* hold across machines: rustc
//! embeds absolute paths in the panic-location strings of every crate outside
//! the guest workspace and of `core` itself, and the guest build does not
//! remap them — no `--remap-path-prefix` is passed, and `trim-paths` is
//! unstable in the pinned cargo. That is why no guest ELF is committed: every
//! suite builds the guests it runs from `guests/` (`test_support::guest_elf`).

mod common;

use common::build;
use test_support::{sha256, to_hex};

#[test]
fn two_clean_builds_agree() {
    for name in [
        "fib",
        "echo",
        "rvc-dense",
        "amm",
        "orderbook",
        "vault",
        "atomics",
        "opcodes",
        "heap",
        "addsub",
        "control",
        "alu",
    ] {
        let a = build(name, "repro-a");
        let b = build(name, "repro-b");
        assert_eq!(
            to_hex(&sha256(&a)),
            to_hex(&sha256(&b)),
            "{name}: two clean builds with fresh target directories disagree"
        );
        assert!(a.len() > 1024, "{name}: the ELF is implausibly small");
    }
}
