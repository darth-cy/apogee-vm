//! Acceptance 10: the two structural claims, checked rather than asserted in a
//! comment.
//!
//! * **No transform larger than `2b` is reachable in `open`.** The type makes
//!   this true — `fft::Domain::for_product(half)` is the only constructor and
//!   it builds a domain of size `2 * half` — so what is left to check is that
//!   `open` calls it with `b` and that nothing else in the crate calls it at
//!   all. That is a fact about the source, so the source is what the test
//!   reads.
//! * **The proof byte length does not depend on `n`.** It is a constant, which
//!   is stronger than "constant per `n`", and the round trip at four heights
//!   shows the constant is the real length.
//! * **The pairing-merge challenge is squeezed last and is what merges.**
//!   Must-be-exact 4 pins the squeeze position, and no black-box test can see
//!   it: an implementation that squeezes `rho` where the spec says and then
//!   ignores it in favour of a constant produces exactly the same transcript
//!   and exactly the same proof, and only an adversary who exploits the
//!   unrandomized sum can tell the difference. So the position and the use are
//!   read out of the source, the same way the transform's size is.
//!
//! A committed fixture covers the half of this that *is* observable: the proof
//! vectors pin `Transcript::sample()` after the opening, so a squeeze moved
//! within the schedule — even one nothing reads back — moves the pin.

mod common;

use pcs::{commit, open, PROOF_BYTES};
use test_support::Rng;
use transcript::Transcript;

const LIB: &str = include_str!("../src/lib.rs");
const FFT: &str = include_str!("../src/fft.rs");
const UNI: &str = include_str!("../src/uni.rs");
const BDFG: &str = include_str!("../src/bdfg.rs");

/// Lines of `text` that are neither blank, nor a `//` comment, nor inside the
/// unit-test module — the code a build actually ships.
fn code_lines(text: &str) -> Vec<&str> {
    text.lines()
        .take_while(|l| !l.starts_with("#[cfg(test)]"))
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("//"))
        .collect()
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

    for (name, text) in [("uni.rs", UNI), ("bdfg.rs", BDFG)] {
        assert!(
            !code_lines(text).iter().any(|l| l.contains("for_product")),
            "{name} must not build a transform"
        );
    }

    // And `fft.rs` is the only module that has one to build: the butterflies
    // live there and nowhere else.
    assert!(FFT.contains("fn butterflies"));
    for (name, text) in [("lib.rs", LIB), ("uni.rs", UNI), ("bdfg.rs", BDFG)] {
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

/// The proof is the same length at every height, and that length is
/// `PROOF_BYTES`: 8 uncompressed G1 points and 6 canonical `Fr` values.
#[test]
fn the_proof_length_does_not_depend_on_n() {
    assert_eq!(PROOF_BYTES, 8 * 64 + 6 * 32);

    let srs = common::toy_srs(12);
    for num_vars in [2usize, 4, 8, 12] {
        let mut rng = Rng::new(0x5008_0900 + num_vars as u64);
        let f = common::random_poly(&mut rng, num_vars);
        let u = common::random_point(&mut rng, num_vars);
        let cm = commit(&srs, &f).expect("commit");
        let mut tr = Transcript::new();
        let (_, proof) = open(&srs, &f, &cm, &u, &mut tr).expect("open");
        assert_eq!(proof.to_bytes().len(), PROOF_BYTES, "n = 2^{num_vars}");
    }
}

/// The transcript schedule of one function, read out of the source as
/// `(kind, tag)` pairs in order.
///
/// This is `docs/spec/mercury.md` §5's table, and both sides must produce it.
/// Reading tags rather than whole lines keeps the test about the schedule and
/// not about how a local is spelled.
fn schedule(function: &str) -> Vec<(&'static str, String)> {
    let body = LIB
        .split_once(&format!("pub fn {function}("))
        .unwrap_or_else(|| panic!("{function} must exist"))
        .1;
    let body = body
        .split("\n// ----")
        .next()
        .expect("a section rule follows");

    // Statements, not lines: rustfmt wraps a long call across several lines and
    // the schedule must not depend on where it chose to break.
    let joined = code_lines(body).join(" ");
    let mut out = Vec::new();
    for line in joined.split(';') {
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

/// Must-be-exact 4: both sides run the frozen schedule, and `rho` is the last
/// thing either takes from the transcript.
#[test]
fn both_sides_run_the_frozen_schedule() {
    let expected: Vec<(&str, String)> = SCHEDULE
        .iter()
        .map(|(kind, tag)| (*kind, tag.to_string()))
        .collect();
    for function in ["open", "verify"] {
        assert_eq!(
            schedule(function),
            expected,
            "{function} must run docs/spec/mercury.md section 5's schedule"
        );
    }
    // Said again, because it is the one step no proof and no transcript state
    // can reveal on its own: the merge challenge is squeezed after everything.
    assert_eq!(SCHEDULE[15], ("squeeze", "PAIRING_MERGE"));
    assert_eq!(
        SCHEDULE
            .iter()
            .filter(|(_, t)| *t == "PAIRING_MERGE")
            .count(),
        1
    );
}

/// And `rho` is what merges: both relations enter the pairing check scaled by
/// it, so an unrandomized sum would have to change these lines.
#[test]
fn the_merge_challenge_is_what_merges() {
    let uses: Vec<&str> = code_lines(LIB)
        .into_iter()
        .filter(|l| l.contains("rho"))
        .collect();
    assert_eq!(
        uses,
        vec![
            "let rho = tr.challenge_scalar(tags::PAIRING_MERGE);",
            "let left = a1.add(&a2.mul(&rho)).to_affine();",
            "let right = b1.add(&b2.mul(&rho)).to_affine();",
        ],
        "rho must be squeezed once and used in both halves of the merge"
    );
    let checks: Vec<&str> = code_lines(LIB)
        .into_iter()
        .filter(|l| l.contains("pairing_check(") && !l.starts_with("use "))
        .collect();
    assert_eq!(
        checks,
        vec!["if pairing_check(&[(left, vsrs.g2_gen), (-right, vsrs.g2_tau)]) {"],
        "there is exactly one pairing check, over the two merged terms"
    );
}
