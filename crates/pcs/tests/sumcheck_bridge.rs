//! Acceptance 4: the sumcheck-to-Mercury bridge, which is where the variable
//! order gets reversed if it is going to be.
//!
//! S04's zerocheck reduces a gate to one claim: a point `r` and the columns'
//! evaluations there. S08's Mercury opens a commitment at a point. Joining them
//! is the whole of what a shard proof does at its base layer, and the join has
//! exactly one place to go wrong — the two crates must mean the same thing by
//! "variable `j`".
//!
//! They do, and nothing here reverses anything. Sumcheck round `i` binds
//! variable `i`, so `claim.point[j]` is variable `j`; `crates/poly` puts
//! variable `j` at bit `j` of the index; and `docs/spec/mercury.md` §2 splits
//! that index as `i + j*b` with `u1` the **first** `t` coordinates. So the
//! reduced point is handed to `open` exactly as it comes out, and the value it
//! returns is both the sumcheck's claimed evaluation and
//! `MultilinearPoly::evaluate(r)`.
//!
//! The negative control is the same point with its halves transposed. A reader
//! who takes `u1` for the *last* `t` coordinates writes a verifier that accepts
//! it; this one rejects.

mod common;

use constants::transcript_tags as tags;
use field::Fr;
use pcs::{batch_open, batch_verify, commit, open, verify, MercuryCommitment, PcsError};
use poly::{MultilinearPoly, PolyBacking};
use sumcheck::{
    absorb_witness_digest, prove_zerocheck, verify_zerocheck, witness_digest, Gate, GateTerm,
    PolyAddress,
};
use test_support::Rng;
use transcript::Transcript;

/// Mercury needs an even variable count, and `2^8` is small enough for the toy
/// SRS and large enough that a coordinate swap is not a coincidence.
const NUM_VARS: usize = 8;

/// `A * A - B` over inputs `[A, B]`: S04's gate, transcribed rather than
/// imported, because this file is about the two crates agreeing.
fn square_gate() -> Gate {
    let a = PolyAddress(0);
    let b = PolyAddress(1);
    Gate::new(
        &[&a, &b],
        vec![
            GateTerm {
                coef: Fr::ONE,
                a: 0,
                b: Some(0),
            },
            GateTerm {
                coef: Fr::MINUS_ONE,
                a: 1,
                b: None,
            },
        ],
    )
    .expect("A * A - B is a well formed degree-2 gate")
}

/// `A` random in `U16` and `B = A^2` in `U32`: a satisfying witness.
fn witness(seed: u64) -> Vec<MultilinearPoly> {
    let mut rng = Rng::new(seed);
    let a: Vec<u16> = (0..1usize << NUM_VARS)
        .map(|_| rng.next_u64() as u16)
        .collect();
    let b: Vec<u32> = a.iter().map(|x| (*x as u32) * (*x as u32)).collect();
    vec![
        MultilinearPoly::new(PolyBacking::U16(a)),
        MultilinearPoly::new(PolyBacking::U32(b)),
    ]
}

/// Acceptance 4: prove a zerocheck, then open the committed column at the point
/// the zerocheck reduced to, on the same transcript both sides drive.
#[test]
fn a_reduced_sumcheck_claim_opens_at_its_own_point() {
    let srs = common::toy_srs(NUM_VARS as u32);
    let columns = witness(0x5009_0200);
    let digest = witness_digest(&columns);
    let gate = square_gate();
    let cm = commit(&srs, &columns[0]).expect("commit");

    // -- the prover ---------------------------------------------------------
    let mut prover = Transcript::new();
    absorb_witness_digest(&mut prover, digest);
    let mut working = columns.clone();
    let proof = prove_zerocheck(&gate, &mut working, &mut prover);
    let (value, opening) = open(
        &srs,
        &columns[0],
        &cm,
        &reduced_point(digest, &proof),
        &mut prover,
    )
    .expect("the reduced point is a Mercury opening point");

    // -- the verifier -------------------------------------------------------
    let mut verifier = Transcript::new();
    absorb_witness_digest(&mut verifier, digest);
    let claim = verify_zerocheck(&gate, NUM_VARS, &proof, &mut verifier).expect("the zerocheck");
    verify(
        &srs.verifier(),
        &cm,
        &claim.point,
        value,
        &opening,
        &mut verifier,
    )
    .expect("the opening at the reduced point");

    // -- the three values that must be one value ----------------------------
    let r = claim.point;
    assert_eq!(r.len(), NUM_VARS, "one bound coordinate per variable");
    assert_eq!(
        value, claim.final_evals[0],
        "the opened value is the sumcheck's claimed evaluation"
    );
    assert_eq!(
        value,
        columns[0].evaluate(&r),
        "and it is the multilinear evaluation at the same point, unreversed"
    );

    assert_eq!(
        prover.snapshot(),
        verifier.snapshot(),
        "the two sides end on the same transcript"
    );

    // -- the negative control ----------------------------------------------
    //
    // The same point with `u1` and `u2` transposed. It is a different point, so
    // it is a different statement, and the verifier must say so.
    let t = NUM_VARS / 2;
    let mut transposed = r[t..].to_vec();
    transposed.extend_from_slice(&r[..t]);
    assert_ne!(transposed, r, "the two halves must actually differ");
    let mut tr = Transcript::new();
    absorb_witness_digest(&mut tr, digest);
    let _ = verify_zerocheck(&gate, NUM_VARS, &proof, &mut tr).expect("the zerocheck");
    assert_eq!(
        verify(&srs.verifier(), &cm, &transposed, value, &opening, &mut tr),
        Err(PcsError::VerificationFailed),
        "a transposed opening point must be rejected"
    );

    // And the transposed point really is a different evaluation of `f`, so the
    // rejection is not an accident of the transcript.
    assert_ne!(
        columns[0].evaluate(&transposed),
        value,
        "the halves are not interchangeable in the polynomial either"
    );
}

/// The same bridge with both columns opened as one batch, which is what a shard
/// prover actually does: one `batch_open` per shard at the point its final
/// claim-merging sumcheck reduced to.
#[test]
fn a_reduced_claim_opens_every_column_as_one_batch() {
    let srs = common::toy_srs(NUM_VARS as u32);
    let columns = witness(0x5009_0201);
    let digest = witness_digest(&columns);
    let gate = square_gate();
    let cms: Vec<MercuryCommitment> = columns
        .iter()
        .map(|c| commit(&srs, c).expect("commit"))
        .collect();

    let mut prover = Transcript::new();
    absorb_witness_digest(&mut prover, digest);
    let mut working = columns.clone();
    let proof = prove_zerocheck(&gate, &mut working, &mut prover);
    let r = reduced_point(digest, &proof);
    let (values, opening) =
        batch_open(&srs, &columns, &cms, &r, &mut prover).expect("batch_open at the reduced point");

    let mut verifier = Transcript::new();
    absorb_witness_digest(&mut verifier, digest);
    let claim = verify_zerocheck(&gate, NUM_VARS, &proof, &mut verifier).expect("the zerocheck");
    batch_verify(
        &srs.verifier(),
        &cms,
        &claim.point,
        &values,
        &opening,
        &mut verifier,
    )
    .expect("the batched opening at the reduced point");

    assert_eq!(
        values, claim.final_evals,
        "every opened value is the sumcheck's claim for that column"
    );
    assert_eq!(prover.snapshot(), verifier.snapshot());

    // The transposed control, for the batch.
    let t = NUM_VARS / 2;
    let mut transposed = claim.point[t..].to_vec();
    transposed.extend_from_slice(&claim.point[..t]);
    let mut tr = Transcript::new();
    absorb_witness_digest(&mut tr, digest);
    let _ = verify_zerocheck(&gate, NUM_VARS, &proof, &mut tr).expect("the zerocheck");
    assert_eq!(
        batch_verify(
            &srs.verifier(),
            &cms,
            &transposed,
            &values,
            &opening,
            &mut tr
        ),
        Err(PcsError::VerificationFailed),
        "a transposed batch opening point must be rejected"
    );
}

/// The reduced point, from the proof's round messages.
///
/// `prove_zerocheck` returns the proof, not the point, so a prover that needs
/// the point replays S04's schedule to get it: the `n` eq-randomizers first,
/// then each round's cubic absorbed and its challenge drawn. Round `i`'s
/// challenge binds variable `i`, so the sequence *is* the point in variable
/// order — which is the convention this whole file exists to check.
///
/// Transcribed from `crates/sumcheck` rather than imported, so that a change to
/// either side's schedule shows up here as a disagreement.
fn reduced_point(digest: Fr, proof: &sumcheck::SumcheckProof) -> Vec<Fr> {
    let mut tr = Transcript::new();
    absorb_witness_digest(&mut tr, digest);
    for _ in 0..proof.rounds.len() {
        let _ = tr.challenge_scalar(tags::SUMCHECK_CHALLENGE);
    }
    proof
        .rounds
        .iter()
        .map(|round| {
            tr.append_scalars(tags::SUMCHECK_ROUND, round);
            tr.challenge_scalar(tags::SUMCHECK_CHALLENGE)
        })
        .collect()
}
