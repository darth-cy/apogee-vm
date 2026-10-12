//! The proving debug log, `docs/tools.md` §3. The whole file is behind
//! the feature, so a default `cargo test --workspace` compiles none of it; CI
//! runs it a second time with `--features debug-info`.
//!
//! The log's own unit tests — the level parser, the family filter, the report
//! builders — live in `src/debug.rs` beside what they test, and CI runs
//! `--features debug-info --lib` for them. What belongs *here* is the pair of
//! properties no unit test can reach:
//!
//! - the **grep markers** `docs/tools.md` §3 tells a reader to search
//!   for are the ones the sources actually emit, so the documented recipe keeps
//!   working when a line is reworded;
//! - the feature **changes no proof byte**, which is `#[ignore]`d with the
//!   other proving suites because the only honest way to show it is to prove
//!   one statement twice.
#![cfg(feature = "debug-info")]

use prover::debug::{circuit, Level};

mod common;

/// The levels are ordered, and `off` is below everything: the one property every
/// `dlog!` site depends on.
#[test]
fn the_levels_are_ordered_with_off_at_the_bottom() {
    assert!(Level::Off < Level::Phase);
    assert!(Level::Phase < Level::Detail);
    assert!(Level::Detail < Level::Deep);
}

/// A registered family's circuit inventory is the line every later `layer=` is
/// read against, so it has to carry the layer count and the channels. Built from
/// the registry rather than a fixture, because the numbers only mean anything if
/// they are the real circuit's.
#[test]
fn a_circuit_inventory_carries_what_a_later_failure_is_read_against() {
    let height: u32 = 1 << 20;
    let c = constraints::family_circuit(constants::family::SHIFT_BITWISE, height.trailing_zeros())
        .expect("SHIFT_BITWISE is registered at 2^20");
    let text = circuit(&c, height);
    assert!(text.contains("h=2^20"), "{text}");
    assert!(
        text.contains(&format!("layers={}", c.artifact.depth())),
        "{text}"
    );
    assert!(
        text.contains("range16(16)"),
        "SHIFT_BITWISE carries RANGE16: {text}"
    );
    assert!(text.contains("generic=true"), "{text}");
    // Widths, so a shard whose fill wrote nothing is legible against them.
    for key in ["M=", "W=", "S=", "V=", "committed=", "gates=", "outputs="] {
        assert!(text.contains(key), "{key} missing from {text}");
    }
}

/// **Every marker the documented grep looks for exists in the sources.**
///
/// `docs/tools.md` §3 hands a reader `grep -E` alternations, and their markers
/// come from `format!` strings in `src/lib.rs` and `src/streaming.rs` rather
/// than from a builder a unit test can call: a scan's verdict fires only on the
/// failure it is looking for, and no cheap fixture produces a guest that
/// aborted or a gate that fails.
///
/// So they are pinned where they are written. The mutation this catches is the
/// one the spec calls the worst failure mode a debugging tool has — a line
/// reworded without updating the recipe, so the documented grep finds nothing
/// and the run reads as "no problems".
#[test]
fn every_documented_grep_marker_is_in_the_sources() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources: String = ["src/lib.rs", "src/streaming.rs", "src/debug.rs"]
        .iter()
        .map(|f| std::fs::read_to_string(root.join(f)).expect("a source file reads"))
        .collect();

    for marker in [
        "ABORTED",
        "OUTPUT-LAYOUT-BREAK",
        "self_check FAILED",
        "ALL ZERO",
    ] {
        assert!(
            sources.contains(marker),
            "the documented grep in docs/tools.md §3 looks for {marker:?} and no \
             source emits it: either restore the marker or update the recipe in \
             docs/tools.md"
        );
    }

    // And the two line prefixes the recipe counts begin/done pairs with.
    for marker in ["begin h=", "gkr done"] {
        assert!(
            sources.contains(marker),
            "the begin/done pairing in docs/tools.md §3 counts {marker:?}"
        );
    }
}

/// **The feature changes no proof byte.** The add/sub statement proved twice in
/// the one build, once with `APOGEE_DEBUG=off` and once at `deep` — which runs
/// `gkr::self_check` over every shard and scans every frame — and the two blocks
/// compared on the wire. This is the property that makes it safe to build the
/// prover with the feature on and believe the result.
///
/// `set_var` is sound here on edition 2021 and this is the only test in the
/// binary that touches the environment, so the two runs cannot race a reader.
///
/// `#[ignore]`d: it proves the add/sub statement twice, about 8.6 GB a time,
/// and the `deep` run adds a self-check pass per shard.
#[test]
#[ignore]
fn a_logged_block_is_the_block_the_prover_makes() {
    let setup = common::setup();
    let io = common::empty_io();

    std::env::set_var(prover::debug::VAR, "off");
    let silent = prover::prove_block_streaming(&setup, &io, common::IN_FLIGHT)
        .expect("the block")
        .0;

    std::env::set_var(prover::debug::VAR, "deep");
    let logged = prover::prove_block_streaming(&setup, &io, common::IN_FLIGHT)
        .expect("the block")
        .0;
    std::env::remove_var(prover::debug::VAR);

    assert_eq!(
        silent.to_bytes(),
        logged.to_bytes(),
        "the logged block is the silent one, byte for byte: the log reads and never writes"
    );
}
