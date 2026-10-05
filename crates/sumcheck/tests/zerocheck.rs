//! End-to-end zerochecks, honest and tampered.
//!
//! The independent oracle lives in `oracle.rs`; `Gate` construction lives in
//! `gate.rs`.

mod common;

use common::{
    bound_transcript, discharge, eq_randomizers, square_gate, square_witness,
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
/// on a *fresh* transcript bound to the same digest. Returns the proof and the
/// verifier's answer.
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

    (proof, outcome)
}

// ---------------------------------------------------------------------------
// An honest proof binds every column
// ---------------------------------------------------------------------------

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
// A witness swapped after the digest
// ---------------------------------------------------------------------------

/// The digest is taken over one witness and the proof is produced over another
/// that *also* satisfies the gate. The zerocheck cannot see the swap — the
/// swapped witness is perfectly valid — so the proof verifies, and the failure
/// surfaces where it must, in the final-evals discharge against the
/// digest-bound witness. An error class, not a panic.
///
/// In a proof over commitments, this check is the opening.
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

// ---------------------------------------------------------------------------
// Tampered proofs
// ---------------------------------------------------------------------------

/// One corrupted round-polynomial coefficient in an otherwise
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

// ---------------------------------------------------------------------------
// A witness that does not satisfy the gate
// ---------------------------------------------------------------------------

/// The witness does not satisfy the gate and the digest is taken
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
// A second gate
// ---------------------------------------------------------------------------

/// A second, structurally different gate — five inputs, three
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

/// The second gate's tamper half, both kinds: a witness swapped after the digest
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
