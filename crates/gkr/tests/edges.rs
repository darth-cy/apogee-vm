//! Circuits at the edges of what `docs/spec/gkr.md` calls legal, which the toy
//! never reaches: transitions with no rounds, `trace_vars = 1`, a 0-variable
//! layer, a list of enforcing gates only under a width-0 top, and two enforcing
//! gates in one list.

mod common;

use common::{bind, discharge, fr_base, honest, opposed_circuit, root_circuit};
use field::Fr;
use gkr::{gate_values, self_check, GkrError, SelfCheckError};

fn fr(v: u64) -> Fr {
    Fr::from_u64(v)
}

/// `root_circuit`: `trace_vars` 1, a halving list down to a 0-variable layer,
/// and above it a row-wise list over 0 variables holding one enforcing gate and
/// nothing else, under a width-0 top with no outputs. Transitions 1 and 2 have
/// no rounds.
///
/// The honest base `a = [0, 1]` verifies and its one base claim discharges.
/// `a = [2, 2]` gives `sq = [2, 2]` and `root = 4`, breaking `0 = root`; with a
/// proof honest over those values, the only check that can see it is transition
/// 2's final check, `0 = S_2(4)`, with no round before it. Kills the mutant
/// that skips the final check of a transition with no rounds.
#[test]
fn a_transition_with_no_rounds_still_runs_its_final_check() {
    let artifact = root_circuit();
    let base = fr_base(&artifact, vec![vec![fr(0), fr(1)]]);
    let (values, proof, result) = honest(&artifact, &base);
    let (_, challenges) = bind(&artifact, &base);
    assert_eq!(self_check(&artifact, &values, &challenges), Ok(()));
    let rounds: Vec<usize> = proof.layers.iter().map(|l| l.rounds.len()).collect();
    let claims: Vec<usize> = proof.layers.iter().map(|l| l.final_evals.len()).collect();
    assert_eq!(rounds, vec![1, 0, 0], "rounds per transition");
    assert_eq!(claims, vec![1, 2, 1], "claims per transition");
    assert!(values.layers[2].is_empty(), "the top has width 0");
    let base_claims = result.expect("the honest run verifies");
    assert_eq!(base_claims.len(), 1);
    assert_eq!(base_claims[0].point.len(), 1);
    discharge(&base, &base_claims).expect("its base claim discharges");

    let base = fr_base(&artifact, vec![vec![fr(2), fr(2)]]);
    let (values, _, result) = honest(&artifact, &base);
    assert_eq!(values.layers[1][0].get(0), fr(4), "the root");
    let (_, challenges) = bind(&artifact, &base);
    assert_eq!(
        self_check(&artifact, &values, &challenges),
        Err(SelfCheckError {
            layer: 2,
            row: 0,
            relation: "root_is_zero".into(),
        })
    );
    assert_eq!(result, Err(GkrError::LayerInconsistency { layer: 2 }));
}

/// `opposed_circuit`: `0 = a − b` and `0 = b − a` in one list. With `a ≠ b`
/// on row 1 their residuals cancel on every row, so a summand giving both
/// enforcing gates one weight is zero on this base and verifies it; the
/// distinct weights `λ^{w+0}` and `λ^{w+1}` keep the violation. Acceptance 3's
/// control is cancellation across rows of one gate; this is cancellation across
/// gates, which the toy, with one enforcing gate, cannot show. Kills the mutant
/// that weights every enforcing gate by the first enforcing weight.
#[test]
fn opposed_enforcing_gates_do_not_cancel() {
    let artifact = opposed_circuit();
    let a: Vec<Fr> = (0..4).map(|i| fr(10 + i)).collect();
    let base = fr_base(&artifact, vec![a.clone(), a.clone()]);
    let (values, _, result) = honest(&artifact, &base);
    let (_, challenges) = bind(&artifact, &base);
    assert_eq!(self_check(&artifact, &values, &challenges), Ok(()));
    discharge(&base, &result.expect("a = b verifies")).expect("and discharges");

    let mut b = a.clone();
    b[1] += Fr::ONE;
    let base = fr_base(&artifact, vec![a.clone(), b.clone()]);
    let (values, _, result) = honest(&artifact, &base);
    let (_, challenges) = bind(&artifact, &base);
    for (y, (av, bv)) in a.iter().zip(&b).enumerate() {
        let gates = gate_values(&artifact, 0, &[*av, *bv], &[], &[], &challenges);
        assert_eq!(
            gates[1] + gates[2],
            Fr::ZERO,
            "row {y}: the residuals cancel"
        );
        assert_eq!(
            gates[1] != Fr::ZERO,
            y == 1,
            "row {y}: violated only on row 1"
        );
    }
    assert_eq!(
        self_check(&artifact, &values, &challenges),
        Err(SelfCheckError {
            layer: 0,
            row: 1,
            relation: "a_eq_b".into(),
        })
    );
    assert_eq!(result, Err(GkrError::LayerInconsistency { layer: 0 }));
}
