//! End-to-end zerochecks, honest and tampered.
//!
//! Acceptance 1, 2, 3, 4, 6, 7 and 8. Acceptance 5's independent oracle lives
//! in `oracle.rs`; `Gate` construction lives in `gate.rs`.

mod common;

use common::{
    bound_transcript, discharge, eq_randomizers, round_challenges, square_gate, square_witness,
    square_witness_with_bumped_b, square_witness_with_row, wide_gate, wide_witness,
    wide_witness_with_bumped_e, wide_witness_with_row,
};
use field::Fr;
use poly::{eq_table, MultilinearPoly, PolyBacking};
use sumcheck::{
    prove_zerocheck, verify_zerocheck, witness_digest, Gate, SumcheckClaim, SumcheckError,
    SumcheckProof,
};

/// Prove over `columns` on a transcript bound to `digest`, and check the proof
/// on a *fresh* transcript bound to the same digest. Returns the proof, the
/// verifier's answer, and both transcripts' event logs so a caller can hold the
/// two sides to must-be-exact 4.
fn prove_then_verify(
    gate: &Gate,
    columns: &[MultilinearPoly],
    digest: Fr,
) -> (SumcheckProof, Result<SumcheckClaim, SumcheckError>) {
    let n = columns[0].num_vars();

    let mut working: Vec<MultilinearPoly> = columns.to_vec();
    let mut prover = bound_transcript(digest);
    let proof = prove_zerocheck(gate, &mut working, &mut prover);

    let mut verifier = bound_transcript(digest);
    let outcome = verify_zerocheck(gate, n, &proof, &mut verifier);

    if outcome.is_ok() {
        // Must-be-exact 4: the two sides drove the transcript identically. The
        // event log is the typed-message sequence and the snapshot is the
        // sponge itself, so equal logs and equal snapshots leave no room for a
        // challenge to have been passed out of band.
        assert_eq!(
            prover.event_log(),
            verifier.event_log(),
            "prover and verifier must absorb the same typed messages in the same order"
        );
        assert_eq!(
            prover.snapshot(),
            verifier.snapshot(),
            "prover and verifier must end on the same sponge state"
        );
    }
    (proof, outcome)
}

// ---------------------------------------------------------------------------
// Acceptance 1 and 7
// ---------------------------------------------------------------------------

/// Acceptance 1: `A * A - B = 0` over `2^20` rows, `A` in `U16` and `B` in
/// `U32`, so the first round reads both through the lazy lift and every later
/// round reads the lifted `Fr` tables. Acceptance 7's structural assertions ride
/// along on the same real proof.
#[test]
fn honest_run_over_two_to_the_twenty_rows() {
    let n = 20;
    let gate = square_gate();
    let columns = square_witness(n, 0x5044_4f57_4e00_0001);

    // The lazy lift is only exercised if the columns really start small.
    assert!(matches!(columns[0].backing(), PolyBacking::U16(_)));
    assert!(matches!(columns[1].backing(), PolyBacking::U32(_)));

    let digest = witness_digest(&columns);
    let (proof, outcome) = prove_then_verify(&gate, &columns, digest);
    let claim = outcome.expect("an honest proof over a satisfying witness verifies");

    // Acceptance 7.
    assert_eq!(proof.rounds.len(), n, "one round per variable");
    for round in &proof.rounds {
        assert_eq!(round.len(), 4, "a round message is always 4 coefficients");
    }
    assert_eq!(proof.final_evals.len(), 2, "one final eval per gate input");
    assert_eq!(claim.point.len(), n, "one bound coordinate per variable");

    // Acceptance 1's discharge: the claimed evaluations are what the witness
    // really evaluates to at the bound point.
    assert_eq!(claim.final_evals[0], columns[0].evaluate(&claim.point));
    assert_eq!(claim.final_evals[1], columns[1].evaluate(&claim.point));
    discharge(&columns, &claim).expect("the honest witness discharges the claim");
}

/// The binding really is one-way and the lift really happened: after proving,
/// the prover's working columns are fully bound `Fr` tables holding exactly the
/// claimed evaluations.
#[test]
fn proving_binds_every_column_to_the_challenge_point() {
    let n = 12;
    let gate = square_gate();
    let columns = square_witness(n, 0x4249_4e44_0000_0001);
    let digest = witness_digest(&columns);

    let mut working: Vec<MultilinearPoly> = columns.to_vec();
    let mut t = bound_transcript(digest);
    let proof = prove_zerocheck(&gate, &mut working, &mut t);

    for (k, column) in working.iter().enumerate() {
        assert_eq!(column.num_vars(), 0, "column {k} is fully bound");
        assert!(
            matches!(column.backing(), PolyBacking::Fr(_)),
            "column {k} lifted on its first bind and stayed lifted"
        );
        assert_eq!(column.get(0), proof.final_evals[k]);
    }
}

// ---------------------------------------------------------------------------
// Acceptance 2
// ---------------------------------------------------------------------------

/// Acceptance 2, as intended: the digest is taken over one witness and the
/// proof is produced over another that *also* satisfies the gate. The zerocheck
/// cannot see the swap — the swapped witness is perfectly valid — so the proof
/// verifies, and the failure surfaces exactly where the stage says it must, in
/// the final-evals discharge against the digest-bound witness. An error class,
/// not a panic.
///
/// This is the check that will become "open the commitment" once Mercury lands.
#[test]
fn a_witness_swapped_after_the_digest_fails_the_discharge() {
    let n = 12;
    let gate = square_gate();
    let seed = 0x5357_4150_0000_0001;

    let bound = square_witness(n, seed);
    let digest = witness_digest(&bound);

    // One row changed, and `B` changed with it so the swap stays satisfying.
    let row = 0x0b3d % (1usize << n);
    let swapped = square_witness_with_row(n, seed, row, 0xa5a5);
    assert_ne!(
        swapped[0].get(row),
        bound[0].get(row),
        "the swap must actually change the witness"
    );

    let (_, outcome) = prove_then_verify(&gate, &swapped, digest);
    let claim = outcome.expect("the swapped witness satisfies the gate, so the sumcheck passes");

    let failure = discharge(&bound, &claim)
        .expect_err("the digest-bound witness must not discharge a proof about another witness");
    assert!(failure.contains("column 0"), "{failure}");

    // The control: the same claim discharges against the witness it was
    // actually proved over, so the rejection above is about the binding and not
    // about a broken discharge.
    discharge(&swapped, &claim).expect("the proved witness does discharge its own claim");
}

/// Acceptance 2 read literally — `B[i] += 1` after the honest digest is
/// absorbed — recorded for what it actually does. That tamper leaves the
/// witness *unsatisfying*, so the zerocheck catches it at round 0 and the
/// discharge check the stage names is never reached. The stage's stated intent
/// is the test above; this is its twin, so both readings are covered.
#[test]
fn the_literal_acceptance_two_tamper_is_caught_by_round_zero_instead() {
    let n = 12;
    let gate = square_gate();
    let seed = 0x4c49_5445_5241_4c01;

    let honest = square_witness(n, seed);
    let digest = witness_digest(&honest);

    let row = 0x0777 % (1usize << n);
    let corrupted = square_witness_with_bumped_b(n, seed, row);

    let (_, outcome) = prove_then_verify(&gate, &corrupted, digest);
    assert_eq!(
        outcome,
        Err(SumcheckError::RoundSumMismatch { round: 0 }),
        "a witness that does not satisfy the gate fails the zerocheck at round 0"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 3
// ---------------------------------------------------------------------------

/// Acceptance 3: one corrupted round-polynomial coefficient in an otherwise
/// honest proof. Every single-coefficient change moves `g(0) + g(1)`, which is
/// `2*c0 + c1 + c2 + c3`, so the verifier rejects at that very round.
#[test]
fn a_tampered_round_coefficient_is_rejected() {
    let n = 12;
    let gate = square_gate();
    let columns = square_witness(n, 0x524f_554e_4400_0001);
    let digest = witness_digest(&columns);

    let (proof, outcome) = prove_then_verify(&gate, &columns, digest);
    outcome.expect("the honest proof verifies before anything is tampered with");

    for round in [0usize, 1, 5, n - 1] {
        for coefficient in 0..4 {
            let mut tampered = proof.clone();
            tampered.rounds[round][coefficient] += Fr::ONE;

            let mut t = bound_transcript(digest);
            assert_eq!(
                verify_zerocheck(&gate, n, &tampered, &mut t),
                Err(SumcheckError::RoundSumMismatch { round }),
                "round {round} coefficient {coefficient} must be caught at that round"
            );
        }
    }
}

/// The other half of the proof is checked too: tampering `final_evals` survives
/// every round-sum check and is caught by the last-layer identity.
#[test]
fn tampered_final_evals_are_rejected() {
    let n = 10;
    let gate = square_gate();
    let columns = square_witness(n, 0x4649_4e41_4c00_0001);
    let digest = witness_digest(&columns);

    let (proof, outcome) = prove_then_verify(&gate, &columns, digest);
    outcome.expect("the honest proof verifies");

    for k in 0..proof.final_evals.len() {
        let mut tampered = proof.clone();
        tampered.final_evals[k] += Fr::ONE;
        let mut t = bound_transcript(digest);
        assert_eq!(
            verify_zerocheck(&gate, n, &tampered, &mut t),
            Err(SumcheckError::FinalEvalMismatch),
            "a tampered final eval {k} must fail the last-layer check"
        );
    }
}

/// Structural rejections: a proof of the wrong shape never reaches the sponge.
#[test]
fn a_proof_of_the_wrong_shape_is_rejected() {
    let n = 8;
    let gate = square_gate();
    let columns = square_witness(n, 0x5348_4150_4500_0001);
    let digest = witness_digest(&columns);
    let (proof, outcome) = prove_then_verify(&gate, &columns, digest);
    outcome.expect("the honest proof verifies");

    let mut short = proof.clone();
    short.rounds.pop();
    let mut t = bound_transcript(digest);
    assert_eq!(
        verify_zerocheck(&gate, n, &short, &mut t),
        Err(SumcheckError::RoundCountMismatch {
            expected: n,
            found: n - 1
        })
    );

    let mut wide = proof.clone();
    wide.final_evals.push(Fr::ONE);
    let mut t = bound_transcript(digest);
    assert_eq!(
        verify_zerocheck(&gate, n, &wide, &mut t),
        Err(SumcheckError::FinalEvalCountMismatch {
            expected: 2,
            found: 3
        })
    );

    // And an honest proof checked against the wrong variable count.
    let mut t = bound_transcript(digest);
    assert_eq!(
        verify_zerocheck(&gate, n + 1, &proof, &mut t),
        Err(SumcheckError::RoundCountMismatch {
            expected: n + 1,
            found: n
        })
    );
}

/// A verifier whose transcript was bound to a different digest rejects an
/// otherwise untouched proof: the challenges it draws are not the ones the
/// prover used.
#[test]
fn a_proof_checked_against_the_wrong_digest_is_rejected() {
    let n = 8;
    let gate = square_gate();
    let columns = square_witness(n, 0x4449_4745_5354_0001);
    let digest = witness_digest(&columns);
    let (proof, outcome) = prove_then_verify(&gate, &columns, digest);
    outcome.expect("the honest proof verifies against its own digest");

    // Round 0 still passes, and must: an honest proof over a *satisfying*
    // witness has `g_0(0) + g_0(1) == 0` for every `r`, so the eq-randomizers
    // are invisible there. The divergence shows up one round later, where the
    // claim carried forward is `g_0` at a challenge the prover never saw.
    let mut t = bound_transcript(digest + Fr::ONE);
    assert_eq!(
        verify_zerocheck(&gate, n, &proof, &mut t),
        Err(SumcheckError::RoundSumMismatch { round: 1 }),
        "a transcript bound to another digest draws other challenges"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 4
// ---------------------------------------------------------------------------

/// Acceptance 4: the witness digest is binding, so witnesses differing in one
/// cell diverge before round 0 even exists — the eq-randomizers already differ
/// — and every round challenge differs with them.
#[test]
fn the_digest_makes_the_challenges_witness_dependent() {
    let n = 10;
    let gate = square_gate();
    let seed = 0x4249_4e44_494e_4701;

    // Exactly one cell apart: `B[row] += 1`, `A` untouched.
    let row = 0x0155 % (1usize << n);
    let one = square_witness(n, seed);
    let two = square_witness_with_bumped_b(n, seed, row);
    let differing: Vec<usize> = (0..1usize << n)
        .filter(|&i| one[0].get(i) != two[0].get(i) || one[1].get(i) != two[1].get(i))
        .collect();
    assert_eq!(differing, vec![row], "the two witnesses differ in one cell");

    let digest_one = witness_digest(&one);
    let digest_two = witness_digest(&two);
    assert_ne!(digest_one, digest_two, "the digest sees the changed cell");

    let r_one = eq_randomizers(digest_one, n);
    let r_two = eq_randomizers(digest_two, n);
    for j in 0..n {
        assert_ne!(r_one[j], r_two[j], "eq-randomizer {j} must differ");
    }

    // And the round challenges themselves, for that same one-cell pair. Both
    // proofs are produced honestly; the second's witness does not satisfy the
    // gate, so it would not verify and its challenges have to be read from the
    // script rather than from a `SumcheckClaim`.
    let proof_one = {
        let mut w: Vec<MultilinearPoly> = one.to_vec();
        let mut t = bound_transcript(digest_one);
        prove_zerocheck(&gate, &mut w, &mut t)
    };
    let proof_two = {
        let mut w: Vec<MultilinearPoly> = two.to_vec();
        let mut t = bound_transcript(digest_two);
        prove_zerocheck(&gate, &mut w, &mut t)
    };
    let c_one = round_challenges(digest_one, &proof_one);
    let c_two = round_challenges(digest_two, &proof_two);
    for j in 0..n {
        assert_ne!(
            c_one[j], c_two[j],
            "round challenge {j} must differ, starting at round 0"
        );
    }

    // And the round challenges the verifier reports, on a pair that both
    // verify: one row of `A` changed with `B` following it, so both witnesses
    // satisfy the gate and both proofs check out.
    let a = square_witness(n, seed);
    let b = square_witness_with_row(n, seed, row, 0x1234);
    assert_ne!(a[0].get(row), b[0].get(row));

    let claim_a = prove_then_verify(&gate, &a, witness_digest(&a))
        .1
        .expect("honest");
    let claim_b = prove_then_verify(&gate, &b, witness_digest(&b))
        .1
        .expect("honest");
    for j in 0..n {
        assert_ne!(
            claim_a.point[j], claim_b.point[j],
            "round challenge {j} must differ, starting at round 0"
        );
    }

    // The control on the replay helper used above: on a proof that verifies, the
    // challenges it reconstructs are the verifier's own.
    let (proof_a, outcome_a) = prove_then_verify(&gate, &a, witness_digest(&a));
    outcome_a.expect("honest");
    assert_eq!(
        round_challenges(witness_digest(&a), &proof_a),
        claim_a.point
    );
}

// ---------------------------------------------------------------------------
// Acceptance 6
// ---------------------------------------------------------------------------

/// Acceptance 6: the witness does not satisfy the gate and the digest is taken
/// over that same witness, so the transcript binding is intact and the
/// zerocheck itself is what must catch it — at round 0's `g(0) + g(1) == 0`.
#[test]
fn a_non_satisfying_witness_fails_round_zero() {
    let n = 12;
    let gate = square_gate();
    let seed = 0x554e_5341_5400_0001;
    let row = 0x0321 % (1usize << n);

    let columns = square_witness_with_bumped_b(n, seed, row);
    let digest = witness_digest(&columns);

    // The digest matches the witness proved over: this is not a binding
    // failure.
    let mut working: Vec<MultilinearPoly> = columns.to_vec();
    let mut prover = bound_transcript(digest);
    let proof = prove_zerocheck(&gate, &mut working, &mut prover);

    let mut verifier = bound_transcript(digest);
    assert_eq!(
        verify_zerocheck(&gate, n, &proof, &mut verifier),
        Err(SumcheckError::RoundSumMismatch { round: 0 }),
        "the zerocheck's own round-0 check must reject an unsatisfying witness"
    );

    // ...and the prover was honest: `g_0(0) + g_0(1)` is not junk, it is the
    // gate's defect exactly. `G` is zero on every row but `row`, where
    // `A^2 - B = -1`, so the whole sum is `-eq(r, row)` — computed here from the
    // eq-randomizers alone, sharing nothing with the prover.
    let r = eq_randomizers(digest, n);
    let g = proof.rounds[0];
    assert_eq!(
        g[0] + g[0] + g[1] + g[2] + g[3],
        -eq_table(&r)[row],
        "round 0's sum must be the gate's defect, not an arbitrary nonzero"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 8
// ---------------------------------------------------------------------------

/// Acceptance 8: a second, structurally different gate — five inputs, three
/// terms, and a formula that is not a square — at `n = 12`. `Gate` is general,
/// not hardcoded to `A * A - B`.
#[test]
fn the_wide_gate_proves_and_verifies() {
    let n = 12;
    let gate = wide_gate();
    let seed = 0x5749_4445_0000_0001;
    let columns = wide_witness(n, seed);

    let digest = witness_digest(&columns);
    let (proof, outcome) = prove_then_verify(&gate, &columns, digest);
    let claim = outcome.expect("an honest proof over a satisfying witness verifies");

    assert_eq!(proof.rounds.len(), n);
    assert_eq!(proof.final_evals.len(), 5);
    for (k, column) in columns.iter().enumerate() {
        assert_eq!(claim.final_evals[k], column.evaluate(&claim.point));
    }
    discharge(&columns, &claim).expect("the honest witness discharges the claim");
}

/// Acceptance 8's tamper half, both kinds: a witness swapped after the digest
/// (caught by the discharge) and a witness that does not satisfy the gate
/// (caught by the zerocheck).
#[test]
fn the_wide_gate_catches_both_tampers() {
    let n = 12;
    let gate = wide_gate();
    let seed = 0x5749_4445_0000_0002;
    let row = 0x0abc % (1usize << n);

    let bound = wide_witness(n, seed);
    let digest = witness_digest(&bound);

    let swapped = wide_witness_with_row(n, seed, row, 0x1357_9bdf);
    assert_ne!(swapped[0].get(row), bound[0].get(row));
    let claim = prove_then_verify(&gate, &swapped, digest)
        .1
        .expect("the swapped witness still satisfies the gate");
    discharge(&bound, &claim).expect_err("the digest-bound witness must reject the swap");
    discharge(&swapped, &claim).expect("the control: the proved witness discharges");

    let broken = wide_witness_with_bumped_e(n, seed, row);
    let broken_digest = witness_digest(&broken);
    assert_eq!(
        prove_then_verify(&gate, &broken, broken_digest).1,
        Err(SumcheckError::RoundSumMismatch { round: 0 }),
        "a witness that does not satisfy the wide gate fails the zerocheck"
    );
}

// ---------------------------------------------------------------------------
// Edges
// ---------------------------------------------------------------------------

/// The degenerate cube: `n = 0` is one row and no rounds. The proof is empty,
/// the point is empty, and the last-layer identity is the whole check.
#[test]
fn a_constant_witness_is_a_zero_round_proof() {
    let gate = square_gate();
    let columns = vec![
        MultilinearPoly::new(PolyBacking::U16(vec![7])),
        MultilinearPoly::new(PolyBacking::U32(vec![49])),
    ];
    let digest = witness_digest(&columns);

    let (proof, outcome) = prove_then_verify(&gate, &columns, digest);
    assert!(proof.rounds.is_empty());
    let claim = outcome.expect("7 * 7 - 49 == 0");
    assert!(claim.point.is_empty());
    assert_eq!(claim.final_evals, vec![Fr::from_u64(7), Fr::from_u64(49)]);

    let broken = vec![
        MultilinearPoly::new(PolyBacking::U16(vec![7])),
        MultilinearPoly::new(PolyBacking::U32(vec![50])),
    ];
    let broken_digest = witness_digest(&broken);
    assert_eq!(
        prove_then_verify(&gate, &broken, broken_digest).1,
        Err(SumcheckError::FinalEvalMismatch),
        "with no rounds, the last-layer identity is the only place to catch it"
    );
}

/// `n = 1` is the smallest cube with a round in it, and the one where an
/// off-by-one in the round loop would still typecheck.
#[test]
fn one_variable_proves_and_verifies() {
    let gate = square_gate();
    let columns = vec![
        MultilinearPoly::new(PolyBacking::U16(vec![3, 9])),
        MultilinearPoly::new(PolyBacking::U32(vec![9, 81])),
    ];
    let digest = witness_digest(&columns);
    let (proof, outcome) = prove_then_verify(&gate, &columns, digest);
    assert_eq!(proof.rounds.len(), 1);
    let claim = outcome.expect("both rows satisfy the gate");
    assert_eq!(claim.final_evals[0], columns[0].evaluate(&claim.point));
    assert_eq!(claim.final_evals[1], columns[1].evaluate(&claim.point));
}
