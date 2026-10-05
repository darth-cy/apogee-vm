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
//!   for are the ones the builders actually emit, so the documented recipe keeps
//!   working when a line is reworded;
//! - the feature **changes no proof byte**, which is `#[ignore]`d with the
//!   other proving suites because the only honest way to show it is to prove
//!   one statement twice.
#![cfg(feature = "debug-info")]

use prover::debug::{
    canonical, circuit, ec_add_groups, histogram, range, Level, EC_ADD_SELECTORS, MOD_MUL_SELECTORS,
};

mod common;

/// **The documented greps keep working.**
///
/// `docs/tools.md` §3 hands a reader greps like these, and they are the
/// whole interface for "what went wrong in this run":
///
/// ```console
/// $ grep '^apogee shard' run.log | grep begin | tail -1
/// $ grep -E 'FAIL|NOT CANONICAL|UNBALANCED|OVER the|NAMES NO' run.log
/// ```
///
/// Every marker in the second is produced by a builder here, and a line
/// reworded without updating the spec would silently make the recipe find
/// nothing — the worst failure mode a debugging tool has, because it reads as
/// "no problems". This test is what makes that a build failure instead.
#[test]
fn the_documented_grep_markers_are_the_ones_the_log_prints() {
    // NOT CANONICAL: a frame value at or above its modulus.
    let bad = canonical("y2", 1893, &[(41, "0xdead".into(), "0xbeef".into())]);
    assert!(bad.contains("NOT CANONICAL"), "{bad}");
    assert!(bad.contains("first invocation 41"), "{bad}");
    // And the clean case says nothing the grep would catch.
    let clean = canonical("y2", 1893, &[]);
    for marker in ["NOT CANONICAL", "UNBALANCED", "OVER the", "FAIL"] {
        assert!(
            !clean.contains(marker),
            "a clean scan matched {marker}: {clean}"
        );
    }

    // UNBALANCED: a point addition missing one of its three thirds.
    let short = ec_add_groups(&[7, 7, 6, 0, 0, 0]);
    assert!(short.contains("UNBALANCED"), "{short}");
    assert!(!ec_add_groups(&[7, 7, 7, 0, 0, 0]).contains("UNBALANCED"));

    // OVER the: a timestamp gap above what its decomposition holds.
    let over = range("ts-gap", &[1u64 << 38], 38);
    assert!(over.contains("OVER the 38-bit ceiling"), "{over}");
    assert!(!range("ts-gap", &[7u64], 38).contains("OVER the"));
}

/// The two selector histograms name every code their family can carry, so a
/// wrong-field or wrong-curve caller is one line rather than a hunt. A code
/// appended without a name would print a column short, and
/// `src/debug.rs`'s `every_selector_code_has_a_name` is what holds the arrays
/// to the constants; this holds the rendering to being readable.
#[test]
fn a_selector_histogram_names_every_code() {
    let mm = histogram("modulus", &MOD_MUL_SELECTORS, &[1893, 0, 2, 0]);
    assert!(mm.contains("secp256k1_p:1893"), "{mm}");
    assert!(mm.contains("bn254_p:2"), "{mm}");
    // One `name:count` pair per code, and the label is joined with `=`.
    assert_eq!(mm.matches(':').count(), MOD_MUL_SELECTORS.len());
    assert!(mm.starts_with("modulus=["), "{mm}");

    let ea = histogram("curve/group", &EC_ADD_SELECTORS, &[631; 6]);
    assert!(
        ea.contains("secp256k1_g1:631") && ea.contains("bn254_g3:631"),
        "{ea}"
    );
}

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
    let height: u32 = 1 << 16;
    let c = constraints::family_circuit(constants::family::EC_ADD, height.trailing_zeros())
        .expect("EC_ADD is registered at 2^16");
    let text = circuit(&c, height);
    assert!(text.contains("h=2^16"), "{text}");
    assert!(
        text.contains(&format!("layers={}", c.artifact.depth())),
        "{text}"
    );
    assert!(
        text.contains("range16(16)"),
        "EC_ADD carries RANGE16: {text}"
    );
    assert!(text.contains("generic=false"), "{text}");
    // Widths, so a shard whose fill wrote nothing is legible against them.
    for key in ["M=", "W=", "S=", "V=", "committed=", "gates=", "outputs="] {
        assert!(text.contains(key), "{key} missing from {text}");
    }
}

/// **Every marker the documented grep looks for exists in the sources.**
///
/// `docs/tools.md` §3 hands a reader `grep -E` alternations, and six of their
/// markers come from `format!` strings in `src/lib.rs` and `src/fill.rs`
/// rather than from a builder a unit test can call: a scan's verdict fires only
/// on the failure it is looking for, and no cheap fixture produces a guest that
/// aborted or a frame that disagrees.
///
/// So they are pinned where they are written. The mutation this catches is the
/// one the spec calls the worst failure mode a debugging tool has — a line
/// reworded without updating the recipe, so the documented grep finds nothing
/// and the run reads as "no problems".
#[test]
fn every_documented_grep_marker_is_in_the_sources() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sources: String = ["src/lib.rs", "src/fill.rs", "src/debug.rs"]
        .iter()
        .map(|f| std::fs::read_to_string(root.join(f)).expect("a source file reads"))
        .collect();

    for marker in [
        // From the builders in `src/debug.rs`.
        "NOT CANONICAL",
        "UNBALANCED",
        "OVER the",
        "DECLARED BUT NEVER INVOKED",
        // From `format!` strings, which nothing else here can reach.
        "NAMES NO MODULUS",
        "DISAGREES",
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
    for marker in ["begin h=", "gkr done", "open begin", "open done"] {
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
