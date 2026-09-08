//! `Gate` construction and evaluation.
//!
//! Must-be-exact 2 puts the degree-≤2 check at construction. Here it is
//! structural: a [`GateTerm`] names at most two factors, so no value of the
//! type can express a cubic — there is no degree to check at prove time because
//! there is no way to have built a gate with one. What construction *can*
//! reject is a malformed declaration, and that is what these tests pin.

mod common;

use common::{square_gate, wide_gate};
use field::Fr;
use sumcheck::{Gate, GateError, GateTerm, PolyAddress};

fn term(coef: u64, a: usize, b: Option<usize>) -> GateTerm {
    GateTerm {
        coef: Fr::from_u64(coef),
        a,
        b,
    }
}

#[test]
fn a_gate_needs_at_least_one_input() {
    assert_eq!(Gate::new(&[], Vec::new()).unwrap_err(), GateError::NoInputs);
}

#[test]
fn an_address_may_not_be_declared_twice() {
    let a = PolyAddress(7);
    let b = PolyAddress(9);
    assert_eq!(
        Gate::new(&[&a, &b, &a], Vec::new()).unwrap_err(),
        GateError::DuplicateInput { input: 2 }
    );
    // The same *slot* used twice in a term is the legal way to square a column,
    // and it is how `A * A - B` is written.
    assert!(Gate::new(&[&a, &b], vec![term(1, 0, Some(0))]).is_ok());
}

#[test]
fn a_term_may_not_name_an_undeclared_input() {
    let a = PolyAddress(0);
    let b = PolyAddress(1);
    assert_eq!(
        Gate::new(&[&a, &b], vec![term(1, 0, None), term(1, 2, None)]).unwrap_err(),
        GateError::TermIndexOutOfRange { term: 1, index: 2 }
    );
    assert_eq!(
        Gate::new(&[&a, &b], vec![term(1, 0, Some(5))]).unwrap_err(),
        GateError::TermIndexOutOfRange { term: 0, index: 5 }
    );
    // The control on the controls: the legal edges are accepted, so the check
    // cannot pass by rejecting everything.
    assert!(Gate::new(&[&a, &b], vec![term(1, 1, Some(1))]).is_ok());
}

#[test]
fn the_empty_formula_is_the_zero_gate() {
    let a = PolyAddress(0);
    let gate = Gate::new(&[&a], Vec::new()).expect("a gate with no terms is legal");
    assert_eq!(gate.evaluate(&[Fr::from_u64(11)]), Fr::ZERO);
}

#[test]
fn the_square_gate_evaluates_its_formula() {
    let gate = square_gate();
    for (a, b) in [(0u64, 0u64), (1, 1), (3, 9), (5, 24), (7, 50)] {
        let want = Fr::from_u64(a) * Fr::from_u64(a) - Fr::from_u64(b);
        assert_eq!(gate.evaluate(&[Fr::from_u64(a), Fr::from_u64(b)]), want);
    }
}

/// The wide gate is declared as the expansion `A*B + A*C - D*E`; it must agree
/// with the unexpanded `A * (B + C) - D * E` at every point.
#[test]
fn the_wide_gate_evaluates_its_formula() {
    let gate = wide_gate();
    for k in 0..16u64 {
        let v: Vec<Fr> = (0..5).map(|i| Fr::from_u64(1 + k * 7 + i * 13)).collect();
        let want = v[0] * (v[1] + v[2]) - v[3] * v[4];
        assert_eq!(gate.evaluate(&v), want);
    }
}

#[test]
#[should_panic(expected = "Gate::evaluate: 1 values for a gate with 2 inputs")]
fn evaluating_with_the_wrong_number_of_values_panics() {
    square_gate().evaluate(&[Fr::ONE]);
}

// ---------------------------------------------------------------------------
// The prover's own preconditions. These are programmer errors — a caller that
// pairs the wrong columns with a gate — so they panic, per master rule 8.
// ---------------------------------------------------------------------------

#[test]
#[should_panic(expected = "prove_zerocheck: 1 columns for a gate with 2 inputs")]
fn proving_with_the_wrong_column_count_panics() {
    let mut columns = common::square_witness(3, 1);
    columns.pop();
    let mut t = common::bound_transcript(Fr::ONE);
    sumcheck::prove_zerocheck(&square_gate(), &mut columns, &mut t);
}

#[test]
#[should_panic(expected = "column 1 has 2 variables, column 0 has 3")]
fn proving_with_ragged_columns_panics() {
    let mut columns = common::square_witness(3, 1);
    columns[1] = poly::MultilinearPoly::new(poly::PolyBacking::U32(vec![0, 1, 4, 9]));
    let mut t = common::bound_transcript(Fr::ONE);
    sumcheck::prove_zerocheck(&square_gate(), &mut columns, &mut t);
}

#[test]
#[should_panic(expected = "witness_digest: a witness has at least one column")]
fn digesting_no_columns_panics() {
    sumcheck::witness_digest(&[]);
}

#[test]
#[should_panic(expected = "column 1 has 2 variables, column 0 has 3")]
fn digesting_ragged_columns_panics() {
    let mut columns = common::square_witness(3, 1);
    columns[1] = poly::MultilinearPoly::new(poly::PolyBacking::U32(vec![0, 1, 4, 9]));
    sumcheck::witness_digest(&columns);
}
