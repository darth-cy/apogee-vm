//! Acceptance 2: two clean builds of a guest give byte-identical ELFs.
//!
//! This lives in a test rather than in a CI script so that it runs wherever
//! `cargo test` does, and so that a regression is a failing test rather than a
//! line of shell nobody reads.
//!
//! **What it does not claim.** Byte-identity holds for two builds of the same
//! source on the same machine. It does *not* hold across machines: rustc
//! embeds absolute paths in the panic-location strings of every crate outside
//! the guest workspace and of `core` itself, and stable Rust has no way to
//! remap them — `trim-paths` is still unstable in the pinned cargo. That is
//! why `crates/loader/tests/vectors/*.elf` are refreshed on one machine, by
//! `cargo run -p kat-gen -- guests`, and are not regenerated in CI. Everything
//! derived from them is.

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
        "portability",
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

/// The committed RVC fixture is a build of the current assembly.
///
/// Not a byte comparison of the whole ELF — the module docs say why that
/// cannot hold across machines. What is compared is the two paired regions,
/// which are hand-written assembly with no relocations into `.rodata`, so
/// their bytes *and* their addresses are the same on any machine. They are
/// also exactly what `differential.rs`'s expansion oracle reads, so this is the
/// staleness guard where staleness would matter.
#[test]
fn the_committed_rvc_regions_are_the_current_assembly() {
    let fresh =
        loader::load_elf(&build("rvc-dense", "repro-fresh")).expect("the fresh build loads");
    let committed =
        loader::load_elf(&common::bytes("rvc-dense.elf")).expect("the committed fixture loads");
    let nm = common::nm("rvc-dense");

    for (begin, end) in [
        ("__rvcpair_begin", "__rvcpair_end"),
        ("__norvcpair_begin", "__norvcpair_end"),
    ] {
        assert_eq!(
            common::instructions_in(&fresh, nm[begin], nm[end]),
            common::instructions_in(&committed, nm[begin], nm[end]),
            "{begin}..{end} has moved or changed. Rerun \
             `cargo run -p kat-gen -- guests` and then `-- loader`."
        );
    }
}
