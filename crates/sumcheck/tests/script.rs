//! The frozen transcript script and the frozen witness-digest encoding, pinned
//! against a reconstruction built from raw `observe`/`sample` calls.
//!
//! Every other test in this crate drives both sides of the protocol through the
//! same code, so a change to the script changes the prover and the verifier
//! together and nothing notices — `prove_then_verify`'s log and snapshot
//! comparison is symmetric and cannot see it. Mutation testing confirmed the
//! hole: deleting the `final_evals` absorb from both sides, splitting one round
//! message into four, framing the digest under the wrong tag, dropping the
//! digest sponge's header, absorbing the columns or their cells in reverse
//! order, and even omitting column 0 from the digest entirely all left the whole
//! suite green.
//!
//! These tests close it. They rebuild the absorbed stream element by element
//! from the spec — `docs/spec/transcript.md` §9 says a scalar message is
//! `observe(tag), observe(len), observe(x)...` and §11 says a challenge is
//! `observe(tag), sample()` — and compare the resulting sponge to the real one.
//! Master rule 8 wants every checker to have a negative control, so each is
//! followed by a battery of near-miss reconstructions that must *not* match.

mod common;

use common::{bound_transcript, eq_randomizers, square_gate, square_witness, wide_witness};
use constants::transcript_tags as tags;
use field::Fr;
use poly::MultilinearPoly;
use sumcheck::{prove_zerocheck, verify_zerocheck, witness_digest};
use transcript::Transcript;

/// The tag values themselves are frozen. Renumbering one is a protocol-version
/// change, and the reconstructions below would silently follow the constants if
/// this were not pinned to literals.
#[test]
fn the_tag_values_this_stage_uses_are_frozen() {
    assert_eq!(tags::SUMCHECK_ROUND, 4);
    assert_eq!(tags::SUMCHECK_CHALLENGE, 5);
    assert_eq!(tags::WITNESS_DIGEST, 8);
    assert_eq!(tags::SUMCHECK_FINAL_EVALS, 9);
}

// ---------------------------------------------------------------------------
// The witness digest (must-be-exact 7)
// ---------------------------------------------------------------------------

/// One scalar message, spelled out: `tag, length, payload...`.
fn message(sponge: &mut Transcript, tag: u64, payload: &[Fr]) {
    sponge.observe(Fr::from_u64(tag));
    sponge.observe(Fr::from_u64(payload.len() as u64));
    for x in payload {
        sponge.observe(*x);
    }
}

fn cells(column: &MultilinearPoly) -> Vec<Fr> {
    (0..column.len()).map(|i| column.get(i)).collect()
}

/// The digest, rebuilt from must-be-exact 7's wording alone: a sponge of its
/// own, the column count and `n` as one framed message, then one
/// length-delimited message per column in declaration order with cells in
/// hypercube index order, then a raw squeeze.
fn rebuilt_digest(columns: &[MultilinearPoly]) -> Fr {
    let mut sponge = Transcript::new();
    message(
        &mut sponge,
        tags::WITNESS_DIGEST,
        &[
            Fr::from_u64(columns.len() as u64),
            Fr::from_u64(columns[0].num_vars() as u64),
        ],
    );
    for column in columns {
        message(&mut sponge, tags::WITNESS_DIGEST, &cells(column));
    }
    sponge.sample()
}

#[test]
fn the_witness_digest_is_the_documented_encoding() {
    for columns in [square_witness(4, 0x5343_5249_5054_0001), wide_witness(3, 2)] {
        assert_eq!(
            witness_digest(&columns),
            rebuilt_digest(&columns),
            "the digest must be exactly the encoding must-be-exact 7 describes"
        );
    }
}

/// The negative control on the test above: every near miss must produce a
/// different digest, so the match is a real constraint and not an accident of
/// two identical mistakes.
#[test]
fn near_miss_digest_encodings_are_all_different() {
    let columns = wide_witness(3, 0x4e45_4152_4d49_5353);
    let real = witness_digest(&columns);
    assert_eq!(real, rebuilt_digest(&columns));

    // No header message at all.
    let mut s = Transcript::new();
    for c in &columns {
        message(&mut s, tags::WITNESS_DIGEST, &cells(c));
    }
    assert_ne!(real, s.sample(), "the header must be part of the digest");

    // Columns in reverse declaration order.
    let mut s = Transcript::new();
    message(
        &mut s,
        tags::WITNESS_DIGEST,
        &[
            Fr::from_u64(columns.len() as u64),
            Fr::from_u64(columns[0].num_vars() as u64),
        ],
    );
    for c in columns.iter().rev() {
        message(&mut s, tags::WITNESS_DIGEST, &cells(c));
    }
    assert_ne!(real, s.sample(), "column order must matter");

    // Cells in reverse hypercube index order.
    let mut s = Transcript::new();
    message(
        &mut s,
        tags::WITNESS_DIGEST,
        &[
            Fr::from_u64(columns.len() as u64),
            Fr::from_u64(columns[0].num_vars() as u64),
        ],
    );
    for c in &columns {
        let mut v = cells(c);
        v.reverse();
        message(&mut s, tags::WITNESS_DIGEST, &v);
    }
    assert_ne!(real, s.sample(), "cell order must matter");

    // Column 0 never absorbed: the first column would not be bound at all.
    let mut s = Transcript::new();
    message(
        &mut s,
        tags::WITNESS_DIGEST,
        &[
            Fr::from_u64(columns.len() as u64),
            Fr::from_u64(columns[0].num_vars() as u64),
        ],
    );
    for c in &columns[1..] {
        message(&mut s, tags::WITNESS_DIGEST, &cells(c));
    }
    assert_ne!(real, s.sample(), "every column must be bound");

    // A different framing tag.
    let mut s = Transcript::new();
    message(
        &mut s,
        tags::SUMCHECK_ROUND,
        &[
            Fr::from_u64(columns.len() as u64),
            Fr::from_u64(columns[0].num_vars() as u64),
        ],
    );
    for c in &columns {
        message(&mut s, tags::WITNESS_DIGEST, &cells(c));
    }
    assert_ne!(real, s.sample(), "the framing tag must matter");

    // A challenge_scalar squeeze instead of a raw one — the very thing the
    // one-tag-one-kind rule forbids, and it must not be what we do.
    let mut s = Transcript::new();
    message(
        &mut s,
        tags::WITNESS_DIGEST,
        &[
            Fr::from_u64(columns.len() as u64),
            Fr::from_u64(columns[0].num_vars() as u64),
        ],
    );
    for c in &columns {
        message(&mut s, tags::WITNESS_DIGEST, &cells(c));
    }
    assert_ne!(real, s.challenge_scalar(tags::WITNESS_DIGEST));

    // One changed cell changes the digest: the binding actually binds.
    let mut other = wide_witness(3, 0x4e45_4152_4d49_5353);
    other[0] = MultilinearPoly::new(poly::PolyBacking::Fr({
        let mut v = cells(&other[0]);
        v[5] += Fr::ONE;
        v
    }));
    assert_ne!(real, witness_digest(&other));
}

// ---------------------------------------------------------------------------
// The protocol script (must-be-exact 1, 3, 4, 5 and 6)
// ---------------------------------------------------------------------------

/// One point in the space of scripts a plausible implementation might drive.
/// The frozen script is [`frozen`]; every neighbour of it below must leave a
/// different sponge, which is what makes the equality test a real constraint.
struct Script {
    digest_tag: u64,
    round_tag: u64,
    challenge_tag: u64,
    /// Core algorithm step 2: the eq-randomizers are drawn before round 0.
    randomizers_first: bool,
    /// Must-be-exact 1: a round is ONE message of four scalars, not four of one.
    round_as_one_message: bool,
    /// Must-be-exact 6.
    absorb_final_evals: bool,
}

fn frozen() -> Script {
    Script {
        digest_tag: tags::WITNESS_DIGEST,
        round_tag: tags::SUMCHECK_ROUND,
        challenge_tag: tags::SUMCHECK_CHALLENGE,
        randomizers_first: true,
        round_as_one_message: true,
        absorb_final_evals: true,
    }
}

/// Drive `script` with nothing but `observe` and `sample`, from the spec's own
/// pseudocode. Returns the eq-randomizers, the round challenges, and the sponge
/// left behind.
fn run(
    script: &Script,
    digest: Fr,
    rounds: &[[Fr; 4]],
    final_evals: &[Fr],
) -> (Vec<Fr>, Vec<Fr>, Transcript) {
    let mut t = Transcript::new();
    message(&mut t, script.digest_tag, &[digest]);

    let challenge = |t: &mut Transcript| {
        t.observe(Fr::from_u64(script.challenge_tag));
        t.sample()
    };
    let mut randomizers = Vec::new();
    if script.randomizers_first {
        for _ in 0..rounds.len() {
            randomizers.push(challenge(&mut t));
        }
    }

    let mut challenges = Vec::new();
    for g in rounds {
        if script.round_as_one_message {
            message(&mut t, script.round_tag, g);
        } else {
            for c in g {
                message(&mut t, script.round_tag, &[*c]);
            }
        }
        challenges.push(challenge(&mut t));
    }

    if !script.randomizers_first {
        for _ in 0..rounds.len() {
            randomizers.push(challenge(&mut t));
        }
    }
    if script.absorb_final_evals {
        message(&mut t, tags::SUMCHECK_FINAL_EVALS, final_evals);
    }
    (randomizers, challenges, t)
}

#[test]
fn the_transcript_script_is_the_documented_one() {
    let n = 5;
    let gate = square_gate();
    let columns = square_witness(n, 0x5343_5249_5054_0002);
    let digest = witness_digest(&columns);

    let mut working: Vec<MultilinearPoly> = columns.to_vec();
    let mut prover = bound_transcript(digest);
    let proof = prove_zerocheck(&gate, &mut working, &mut prover);

    let mut verifier = bound_transcript(digest);
    let claim = verify_zerocheck(&gate, n, &proof, &mut verifier).expect("honest");

    let (r, challenges, rebuilt) = run(&frozen(), digest, &proof.rounds, &proof.final_evals);

    // The sponge the frozen script leaves behind is the sponge both sides leave
    // behind. Nothing may be absorbed that the script does not name, and nothing
    // it names may be skipped, reordered, or framed differently.
    assert_eq!(
        rebuilt.snapshot(),
        prover.snapshot(),
        "the prover must drive exactly the frozen script"
    );
    assert_eq!(
        rebuilt.snapshot(),
        verifier.snapshot(),
        "the verifier must drive exactly the frozen script"
    );

    // And the challenges land where the script says they do.
    assert_eq!(r, eq_randomizers(digest, n));
    assert_eq!(
        challenges, claim.point,
        "round i's challenge is what binds variable i"
    );
}

/// The negative control: every neighbour of the frozen script must leave a
/// different sponge, so the equality above is a constraint and not a
/// coincidence of two identical mistakes.
#[test]
fn near_miss_scripts_are_all_different() {
    let n = 4;
    let gate = square_gate();
    let columns = square_witness(n, 0x5343_5249_5054_0003);
    let digest = witness_digest(&columns);

    let mut working: Vec<MultilinearPoly> = columns.to_vec();
    let mut prover = bound_transcript(digest);
    let proof = prove_zerocheck(&gate, &mut working, &mut prover);
    let real = prover.snapshot();

    let sponge = |s: &Script| {
        run(s, digest, &proof.rounds, &proof.final_evals)
            .2
            .snapshot()
    };
    assert_eq!(sponge(&frozen()), real);

    for (what, script) in [
        (
            "the digest's framing tag",
            Script {
                digest_tag: tags::EVALUATION_CLAIM,
                ..frozen()
            },
        ),
        (
            "the round's framing tag",
            Script {
                round_tag: tags::EVALUATION_CLAIM,
                ..frozen()
            },
        ),
        (
            "the challenge tag",
            Script {
                challenge_tag: tags::EVALUATION_CLAIM,
                ..frozen()
            },
        ),
        (
            "drawing the eq-randomizers after the rounds",
            Script {
                randomizers_first: false,
                ..frozen()
            },
        ),
        (
            "splitting a round into four one-scalar messages",
            Script {
                round_as_one_message: false,
                ..frozen()
            },
        ),
        (
            "not absorbing final_evals",
            Script {
                absorb_final_evals: false,
                ..frozen()
            },
        ),
    ] {
        assert_ne!(sponge(&script), real, "{what} must matter");
    }
}
