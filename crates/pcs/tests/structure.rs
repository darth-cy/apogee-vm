//! Acceptance 10: the structural claims, checked rather than asserted in a
//! comment.
//!
//! * **No transform larger than `2b` is reachable in `open`.** The type makes
//!   this true — `fft::Domain::for_product(half)` is the only constructor and
//!   it builds a domain of size `2 * half` — so what is left to check is that
//!   `open` calls it with `b` and that nothing else in the crate calls it at
//!   all. That is a fact about the source, so the source is what the test
//!   reads.
//! * **The proof byte length does not depend on `n`, or on `k`.** It is a
//!   constant, which is stronger than "constant per instance", and the round
//!   trip at four heights and two batch widths shows the constant is the real
//!   length.
//! * **There is one verification path.** Every transcript operation of a
//!   verification lives in the shared core; the four public entry points touch
//!   the transcript not at all, and differ only in whether they execute the
//!   pairings or hand back their terms.
//! * **The pairing-merge challenge is squeezed last and is what merges.**
//!   Must-be-exact 4 pins the squeeze position. Since S09 the *use* is
//!   observable — `rho` is the scalar of an accumulator entry, and
//!   `tests/accumulator.rs` pins all twelve against an independent replay — so
//!   what is left here is the position, and that exactly one pairing check and
//!   two MSMs exist to merge into.
//!
//! A committed fixture covers the rest: the proof vectors pin
//! `Transcript::sample()` after the opening, so a squeeze moved within the
//! schedule — even one nothing reads back — moves the pin.

mod common;

use pcs::{batch_open, commit, open, MercuryCommitment, MercuryProof, PROOF_BYTES};
use test_support::Rng;
use transcript::Transcript;

const LIB: &str = include_str!("../src/lib.rs");
const FFT: &str = include_str!("../src/fft.rs");
const UNI: &str = include_str!("../src/uni.rs");
const BDFG: &str = include_str!("../src/bdfg.rs");
const ACCUMULATOR: &str = include_str!("../src/accumulator.rs");

/// Lines of `text` that are neither blank, nor a `//` comment, nor inside the
/// unit-test module — the code a build actually ships.
fn code_lines(text: &str) -> Vec<&str> {
    text.lines()
        .take_while(|l| !l.starts_with("#[cfg(test)]"))
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
        .collect()
}

/// One function's body: from its signature to whichever comes first of the
/// next section rule, the next item, or the next doc comment.
///
/// Statements, not lines: rustfmt wraps a long call across several lines and
/// nothing here may depend on where it chose to break.
fn body(text: &str, function: &str) -> String {
    let after = text
        .split_once(&format!("fn {function}("))
        .unwrap_or_else(|| panic!("{function} must exist"))
        .1;
    let end = ["\n// ----", "\nfn ", "\npub fn ", "\n/// "]
        .iter()
        .filter_map(|marker| after.find(marker))
        .min()
        .unwrap_or(after.len());
    code_lines(&after[..end]).join(" ")
}

/// The transform is constructed once, in `open`'s witness routine, at `b`.
#[test]
fn the_only_transform_is_the_one_at_two_b() {
    let calls: Vec<&str> = code_lines(LIB)
        .into_iter()
        .filter(|l| l.contains("for_product"))
        .collect();
    assert_eq!(
        calls,
        vec!["let domain = fft::Domain::for_product(b);"],
        "`open` must build exactly one domain, and it must be at b"
    );

    for (name, text) in [
        ("uni.rs", UNI),
        ("bdfg.rs", BDFG),
        ("accumulator.rs", ACCUMULATOR),
    ] {
        assert!(
            !code_lines(text).iter().any(|l| l.contains("for_product")),
            "{name} must not build a transform"
        );
    }

    // And `fft.rs` is the only module that has one to build: the butterflies
    // live there and nowhere else.
    assert!(FFT.contains("fn butterflies"));
    for (name, text) in [
        ("lib.rs", LIB),
        ("uni.rs", UNI),
        ("bdfg.rs", BDFG),
        ("accumulator.rs", ACCUMULATOR),
    ] {
        assert!(
            !text.contains("fn butterflies"),
            "{name} must not have its own transform"
        );
    }

    // `for_product` is the only way to get a `Domain`, so no caller can ask for
    // a size that is not twice its operand.
    let constructors: Vec<&str> = code_lines(FFT)
        .into_iter()
        .filter(|l| l.starts_with("pub fn ") && l.contains("-> Domain"))
        .collect();
    assert_eq!(
        constructors,
        vec!["pub fn for_product(half: usize) -> Domain {"]
    );
}

/// The proof is the same length at every height and at every batch width, and
/// that length is `PROOF_BYTES`: 8 uncompressed G1 points and 6 canonical `Fr`
/// values. A batched proof is a `MercuryProof` and nothing else.
///
/// `to_bytes` returns `[u8; PROOF_BYTES]`, so its *length* is a fact about the
/// type and asserting it proves nothing. What each case asserts instead is a
/// round trip through `from_bytes`, which validates every point and every value
/// and so can fail; the constant itself is checked once, against the shape it
/// claims to be.
#[test]
fn the_proof_length_does_not_depend_on_n_or_on_k() {
    assert_eq!(PROOF_BYTES, 8 * 64 + 6 * 32);

    let srs = common::toy_srs(12);
    for num_vars in [2usize, 4, 8, 12] {
        let mut rng = Rng::new(0x5009_0900 + num_vars as u64);
        let f = common::random_poly(&mut rng, num_vars);
        let u = common::random_point(&mut rng, num_vars);
        let cm = commit(&srs, &f).expect("commit");
        let mut tr = Transcript::new();
        let (_, proof) = open(&srs, &f, &cm, &u, &mut tr).expect("open");
        assert_eq!(
            MercuryProof::from_bytes(&proof.to_bytes()),
            Some(proof),
            "n = 2^{num_vars}"
        );
    }

    for k in [1usize, 5, 8] {
        let mut rng = Rng::new(0x5009_0910 + k as u64);
        let cols: Vec<_> = (0..k).map(|_| common::random_poly(&mut rng, 8)).collect();
        let cms: Vec<MercuryCommitment> = cols
            .iter()
            .map(|f| commit(&srs, f).expect("commit"))
            .collect();
        let u = common::random_point(&mut rng, 8);
        let mut tr = Transcript::new();
        let (vs, proof) = batch_open(&srs, &cols, &cms, &u, &mut tr).expect("batch_open");
        assert_eq!(vs.len(), k);
        assert_eq!(
            MercuryProof::from_bytes(&proof.to_bytes()),
            Some(proof),
            "k = {k}"
        );
    }
}

/// The transcript schedule of one function, read out of the source as
/// `(kind, tag)` pairs in order.
///
/// This is `docs/spec/mercury.md` §5's and §11's tables, and the sides must
/// produce them. Reading tags rather than whole lines keeps the test about the
/// schedule and not about how a local is spelled.
fn schedule(function: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for line in body(LIB, function).split(';') {
        // `challenge_z` is the resample-on-zero wrapper of MERCURY_Z; the tag
        // is inside the helper, so it is named here.
        if line.contains("challenge_z(tr)") {
            out.push(("squeeze", "MERCURY_Z".to_string()));
            continue;
        }
        let touches = line.contains("tr.append_")
            || line.contains("tr.challenge_scalar")
            || line.contains("append_g1(tr,")
            || line.contains("append_g1_list(tr,");
        if !touches {
            continue;
        }
        let tag = line
            .split_once("tags::")
            .unwrap_or_else(|| panic!("{function}: `{line}` names no tag"))
            .1;
        let tag: String = tag
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || *c == '_')
            .collect();
        let kind = if line.contains("challenge_scalar") {
            "squeeze"
        } else {
            "absorb"
        };
        out.push((kind, tag));
    }
    out
}

/// `docs/spec/mercury.md` §5, transcribed. Sixteen steps, in this order.
const SCHEDULE: [(&str, &str); 16] = [
    ("absorb", "MERCURY_INSTANCE"),
    ("absorb", "COMMITMENT"),
    ("absorb", "EVALUATION_CLAIM"),
    ("absorb", "PCS_OPENING"),
    ("squeeze", "MERCURY_ALPHA"),
    ("absorb", "PCS_OPENING"),
    ("squeeze", "MERCURY_GAMMA"),
    ("absorb", "PCS_OPENING"),
    ("squeeze", "MERCURY_Z"),
    ("absorb", "PCS_OPENING"),
    ("absorb", "PCS_OPENING"),
    ("squeeze", "BDFG_BATCH"),
    ("absorb", "PCS_OPENING"),
    ("squeeze", "BDFG_POINT"),
    ("absorb", "PCS_OPENING"),
    ("squeeze", "PAIRING_MERGE"),
];

/// `docs/spec/mercury.md` §11, transcribed. Three steps, before the opening.
const BATCH_SCHEDULE: [(&str, &str); 3] = [
    ("absorb", "COMMITMENT"),
    ("absorb", "EVALUATION_CLAIM"),
    ("squeeze", "MERCURY_BATCH"),
];

/// Must-be-exact 4: the prover and the verification core run the one frozen
/// schedule, and `rho` is the last thing either takes from the transcript.
#[test]
fn both_sides_run_the_frozen_schedule() {
    let expected: Vec<(&str, String)> = SCHEDULE
        .iter()
        .map(|(kind, tag)| (*kind, tag.to_string()))
        .collect();
    for function in ["open", "accumulate"] {
        assert_eq!(
            schedule(function),
            expected,
            "{function} must run docs/spec/mercury.md section 5's schedule"
        );
    }
    // Said against the source, because it is the one step no proof and no
    // transcript state can reveal on its own: the merge challenge is squeezed
    // after everything, exactly once.
    let core = schedule("accumulate");
    assert_eq!(
        core.last(),
        Some(&("squeeze", "PAIRING_MERGE".to_string())),
        "the merge challenge is the last thing the core takes"
    );
    assert_eq!(
        core.iter().filter(|(_, t)| t == "PAIRING_MERGE").count(),
        1,
        "and it is squeezed exactly once"
    );
}

/// Must-be-exact 2: both sides of a batch run §11's preamble, and it is the
/// only place a batch touches the transcript before the opening.
#[test]
fn both_sides_run_the_frozen_batch_schedule() {
    let expected: Vec<(&str, String)> = BATCH_SCHEDULE
        .iter()
        .map(|(kind, tag)| (*kind, tag.to_string()))
        .collect();
    assert_eq!(
        schedule("batch_preamble"),
        expected,
        "the batch preamble must run docs/spec/mercury.md section 11's schedule"
    );
    // Said against the source rather than against the constant above: the
    // batching challenge is the LAST thing the preamble takes, so a squeeze
    // moved ahead of either message fails here.
    assert_eq!(
        schedule("batch_preamble").last(),
        Some(&("squeeze", "MERCURY_BATCH".to_string())),
        "rho is squeezed after both messages, never before either"
    );

    // And the two batch entry points reach the transcript only through it.
    for function in ["batch_open", "batch_accumulate"] {
        assert!(
            schedule(function).is_empty(),
            "{function} must not touch the transcript itself"
        );
        assert_eq!(
            body(LIB, function).matches("batch_preamble(").count(),
            1,
            "{function} must run the preamble exactly once"
        );
    }
}

/// Must-be-exact 5: one verification path. Every transcript operation of a
/// verification is in the core, so the four entry points cannot drift apart —
/// there is nothing in them to drift.
#[test]
fn the_verifier_entry_points_are_the_core_plus_one_branch() {
    for function in [
        "verify",
        "verify_deferred",
        "batch_verify",
        "batch_verify_deferred",
    ] {
        assert!(
            schedule(function).is_empty(),
            "{function} must reach the transcript only through the core"
        );
    }

    // The branch itself: the two deferred entry points hand the terms back, and
    // the two native ones spend them on the one pairing check.
    for (function, spends) in [
        ("verify", true),
        ("verify_deferred", false),
        ("batch_verify", true),
        ("batch_verify_deferred", false),
    ] {
        let text = body(LIB, function);
        assert_eq!(
            text.contains("check_pairings("),
            spends,
            "{function} spends the terms: {spends}"
        );
    }
}

/// And `rho` is squeezed where the schedule says. What it *does* is pinned by
/// `tests/accumulator.rs`, which recomputes all twelve entry scalars from an
/// independent replay; what is left here is that there is exactly one pairing
/// check and one MSM per side for it to merge into.
#[test]
fn the_merge_challenge_is_squeezed_last_and_spent_once() {
    let core = body(LIB, "accumulate");
    assert_eq!(
        core.matches("challenge_scalar(tags::PAIRING_MERGE)")
            .count(),
        1,
        "the merge challenge is squeezed exactly once"
    );

    let checks: Vec<&str> = code_lines(ACCUMULATOR)
        .into_iter()
        .filter(|l| l.contains("pairing_check(") && !l.starts_with("use "))
        .collect();
    assert_eq!(
        checks,
        vec!["if curve::pairing::pairing_check(&[(a, vsrs.g2_gen), (-b, vsrs.g2_tau)]) {"],
        "there is exactly one pairing check, over the two merged terms"
    );
    assert!(
        !LIB.contains("pairing_check("),
        "lib.rs must reach the pairing only through the accumulator"
    );

    // Acceptance 9: one MSM per side, and no third.
    let merge = body(ACCUMULATOR, "check_pairings");
    assert_eq!(
        merge.matches("msm(&").count(),
        2,
        "the merge is one MSM per side"
    );
}

/// Where the per-check merge challenge comes from, read out of the source.
///
/// `docs/spec/accumulator.md` §6 pins `nu` to a sponge seeded with the digest of
/// the accumulator's own words, and the powers of `nu` to the group weights. No
/// black-box test can see any of that: a `discharge` that hard-codes `nu`, or
/// digests the wrong grouping, or seeds the sponge with the words instead of
/// their digest, or applies the weights in reverse, accepts and rejects exactly
/// what the honest one does on every list a test can construct — because the
/// only list that could tell them apart is one whose balancing scalar is
/// `-1/nu`, and that scalar is itself one of the words `nu` is derived from.
///
/// So the derivation is pinned here, the same way and for the same reason S08
/// pinned the pairing-merge challenge's use.
/// `tests/accumulator.rs::a_predictable_merge_challenge_would_be_forgeable`
/// covers the half that *is* observable: a guessable `nu` is forgeable.
#[test]
fn the_merge_challenge_is_derived_from_the_digest() {
    let text = body(ACCUMULATOR, "discharge");

    // The digest is over the words of THIS entry list under THIS grouping.
    assert_eq!(
        text.matches("accumulator_words(entries, checks)").count(),
        1,
        "the digest must cover the grouping, so it is taken over `checks`"
    );
    assert_eq!(
        text.matches("accumulator_digest(&words)").count(),
        1,
        "and over the words, once"
    );

    // The merge sponge is seeded with the digest — not with the words, and not
    // with nothing — and `nu` is a challenge under its own tag.
    assert!(
        text.contains("append_scalar(tags::ACCUMULATOR_DIGEST, digest)"),
        "the merge sponge is seeded with the digest"
    );
    assert_eq!(
        text.matches("challenge_scalar(tags::ACCUMULATOR_MERGE)")
            .count(),
        1,
        "nu is squeezed once, under its own tag"
    );

    // And the weights are the powers of `nu` in group order, handed to the
    // merge untouched. Asserted as the whole call rather than as a fragment,
    // because anything between `powers` and `check_pairings` — a reversal, a
    // rotation, a shift — is a different weighting that nothing else can see.
    assert!(
        text.contains("check_pairings(vsrs, entries, checks, &crate::powers(nu, checks.len()))"),
        "group j is weighted by nu^j, passed straight to the merge"
    );

    // `nu` reaches nothing else: it exists to weight the checks.
    assert_eq!(
        text.matches("nu").count(),
        2,
        "nu is drawn once and spent once"
    );
}
