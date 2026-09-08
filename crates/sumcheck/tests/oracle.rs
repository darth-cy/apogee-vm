//! Acceptance 5: an independent computation of the round polynomials.
//!
//! Nothing here calls the prover's round machinery, its interpolation, or
//! `Gate::evaluate`. Each round polynomial is recomputed from the definition —
//! a direct sum over the remaining cube of `eq(r, y) * G(y)`, with `G` written
//! out by hand and every column read through `MultilinearPoly::evaluate`, the
//! S03 routine that was checked against arkworks. Four values at four distinct
//! nodes determine a cubic, so matching there is matching coefficient for
//! coefficient.
//!
//! The stage asks for round 0 at `n <= 4`. Every round is checked instead: it
//! is the same code and strictly more coverage.

mod common;

use common::{
    bound_transcript, eq_randomizers, square_gate, square_witness, wide_gate, wide_witness,
};
use field::Fr;
use poly::{eq_eval, MultilinearPoly};
use sumcheck::{prove_zerocheck, verify_zerocheck, witness_digest, Gate};

/// The two formulas under test, written out as the stage writes them —
/// including `A * (B + C)` unexpanded, where the gate carries the expansion
/// `A*B + A*C`. A transcription error in either direction shows up here.
enum Formula {
    SquareMinus,
    WideProduct,
}

impl Formula {
    fn apply(&self, v: &[Fr]) -> Fr {
        match self {
            Formula::SquareMinus => v[0] * v[0] - v[1],
            Formula::WideProduct => v[0] * (v[1] + v[2]) - v[3] * v[4],
        }
    }
}

/// `sum_y eq(r, (bound, x, y)) * G(columns at (bound, x, y))`, over the whole
/// remaining sub-cube `y`. This is the round polynomial's definition, evaluated
/// at one node.
fn naive_round_value(
    columns: &[MultilinearPoly],
    formula: &Formula,
    r: &[Fr],
    bound: &[Fr],
    x: Fr,
) -> Fr {
    let rest = r.len() - bound.len() - 1;
    let mut acc = Fr::ZERO;
    for y in 0..1usize << rest {
        let mut point: Vec<Fr> = bound.to_vec();
        point.push(x);
        for j in 0..rest {
            // Variable `bound.len() + 1 + j` is bit `j` of `y`, matching the
            // frozen index convention.
            point.push(if (y >> j) & 1 == 1 { Fr::ONE } else { Fr::ZERO });
        }
        let values: Vec<Fr> = columns.iter().map(|c| c.evaluate(&point)).collect();
        acc += eq_eval(r, &point) * formula.apply(&values);
    }
    acc
}

/// Horner, written here so the oracle does not borrow the verifier's copy.
fn cubic_at(g: &[Fr; 4], x: Fr) -> Fr {
    g[0] + x * (g[1] + x * (g[2] + x * g[3]))
}

/// Prove honestly, then hold every round polynomial to the definition.
fn check_every_round(gate: &Gate, formula: &Formula, columns: &[MultilinearPoly]) {
    let n = columns[0].num_vars();
    let digest = witness_digest(columns);

    let mut working: Vec<MultilinearPoly> = columns.to_vec();
    let mut prover = bound_transcript(digest);
    let proof = prove_zerocheck(gate, &mut working, &mut prover);

    let mut verifier = bound_transcript(digest);
    let claim = verify_zerocheck(gate, n, &proof, &mut verifier)
        .expect("the oracle only checks honest proofs");

    // `r` is replayed from the frozen script; the challenges come from the
    // verifier's own output, not from the prover.
    let r = eq_randomizers(digest, n);

    for round in 0..n {
        let bound = &claim.point[..round];
        for node in 0..4u64 {
            let x = Fr::from_u64(node);
            assert_eq!(
                cubic_at(&proof.rounds[round], x),
                naive_round_value(columns, formula, &r, bound, x),
                "round {round} at X = {node}"
            );
        }
    }

    // The zerocheck's own claim, from the definition: an honest proof over a
    // satisfying witness sums to zero over the whole cube.
    assert_eq!(
        naive_round_value(columns, formula, &r, &[], Fr::ZERO)
            + naive_round_value(columns, formula, &r, &[], Fr::ONE),
        Fr::ZERO
    );
}

#[test]
fn the_square_gate_matches_the_definition_at_every_small_size() {
    let gate = square_gate();
    for n in 1..=4 {
        check_every_round(
            &gate,
            &Formula::SquareMinus,
            &square_witness(n, 0x4f52_4143_4c45_0000 + n as u64),
        );
    }
}

#[test]
fn the_wide_gate_matches_the_definition_at_every_small_size() {
    let gate = wide_gate();
    for n in 1..=4 {
        check_every_round(
            &gate,
            &Formula::WideProduct,
            &wide_witness(n, 0x4f52_4143_4c45_1000 + n as u64),
        );
    }
}

/// The oracle can fail. Perturbing one coefficient of one round breaks the
/// match, so a passing run above is not a pair of empty loops.
#[test]
fn the_oracle_rejects_a_perturbed_round() {
    let n = 3;
    let gate = square_gate();
    let columns = square_witness(n, 0x4e45_4741_5449_5645);
    let digest = witness_digest(&columns);

    let mut working: Vec<MultilinearPoly> = columns.to_vec();
    let mut t = bound_transcript(digest);
    let proof = prove_zerocheck(&gate, &mut working, &mut t);
    let r = eq_randomizers(digest, n);

    let mut broken = proof.rounds[0];
    broken[2] += Fr::ONE;
    let mismatches = (0..4u64)
        .filter(|&node| {
            let x = Fr::from_u64(node);
            cubic_at(&broken, x) != naive_round_value(&columns, &Formula::SquareMinus, &r, &[], x)
        })
        .count();
    assert_eq!(
        mismatches, 3,
        "a bumped X^2 coefficient agrees only at X = 0"
    );
}
