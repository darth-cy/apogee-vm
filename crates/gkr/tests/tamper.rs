//! What `verify` rejects: the tamper twin (acceptance 2), the cancellation
//! control (acceptance 3), a forged output table, a wrong child pair, and every
//! malformed shape — each as a returned error, never a panic.

mod common;

use common::{bind, honest, output_claims, run, toy, toy_base, toy_columns, with_column, TOY_ROWS};
use constants::transcript_tags;
use constraints::PolyAddress;
use field::Fr;
use gkr::{forward, gate_values, self_check, verify, GkrError, LayerValues, OutputClaims};
use poly::{eq_eval, eq_table, MultilinearPoly, PolyBacking};

fn fr(v: u32) -> Fr {
    Fr::from_u64(v as u64)
}

/// `values` with one cell of inner layer `layer`, column `column`, bumped by one.
fn bump(values: &LayerValues, layer: usize, column: usize, row: usize) -> LayerValues {
    let mut out = values.clone();
    let c = &values.layers[layer - 1][column];
    let mut table: Vec<Fr> = (0..c.len()).map(|i| c.get(i)).collect();
    table[row] += Fr::ONE;
    out.layers[layer - 1][column] = MultilinearPoly::new(PolyBacking::Fr(table));
    out
}

/// Acceptance 2, first half: one inner-layer value flipped after the forward
/// pass. The proof is honest over the flipped values, the outputs are the
/// honest ones, and the transition that reads the flipped column rejects.
#[test]
fn a_flipped_inner_value_is_rejected_at_the_transition_reading_it() {
    let artifact = toy();
    let cols = toy_columns(0x5313_0300);
    let base = toy_base(&cols);
    let (values, _, result) = honest(&artifact, &base);
    result.expect("the untampered run verifies");
    let outputs = output_claims(&artifact, &values);

    // L{2}[0] is abm, read by list 2's tree step: flipping row 3 moves the
    // product by abm[11], which this seed makes nonzero.
    let partner = values.layers[1][0].get(3 + TOY_ROWS / 2);
    assert_ne!(partner, Fr::ZERO, "the flip must move the tree product");
    let (_, flipped) = run(&artifact, &base, &bump(&values, 2, 0, 3), &outputs);
    assert_eq!(flipped, Err(GkrError::LayerInconsistency { layer: 2 }));

    // L{1}[1] is fingerprint, read by list 1 as fingerprint + 3.
    let (_, flipped) = run(&artifact, &base, &bump(&values, 1, 1, 5), &outputs);
    assert_eq!(flipped, Err(GkrError::LayerInconsistency { layer: 1 }));
}

/// Acceptance 2, second half: `e` is read by the enforcing gate
/// `(e − a)·s = 0` and by nothing else. Flipping it on an active row, with the
/// digest, the forward pass and the proof all honest over the flipped base,
/// breaks the gate — the self-check names it — and `verify` rejects at the
/// transition carrying the enforcing claim.
///
/// Both halves fail as `LayerInconsistency`, at different layers: the
/// repository owner's decision, because a verifier cannot tell a wrong
/// descending claim from a violated enforcing gate inside one batched sum.
#[test]
fn a_flipped_enforcing_only_cell_is_rejected_at_the_enforcing_layer() {
    let artifact = toy();
    let mut cols = toy_columns(0x5313_0400);
    let active = (0..TOY_ROWS)
        .find(|&y| cols.s[y] == 1)
        .expect("some row is active");
    let inactive = (0..TOY_ROWS)
        .find(|&y| cols.s[y] == 0)
        .expect("some row is inactive");

    // Control: on an inactive row the gate holds whatever e is.
    cols.e[inactive] ^= 0x5a5a;
    let base = toy_base(&cols);
    let (_, _, result) = honest(&artifact, &base);
    result.expect("e is free where s = 0");

    cols.e[active] = cols.e[active].wrapping_add(1);
    let base = toy_base(&cols);
    let (_, challenges) = bind(&artifact, &base);
    let values = forward(&artifact, &base, &challenges);
    let broken = self_check(&artifact, &values, &challenges).expect_err("the gate is broken");
    assert_eq!((broken.layer, broken.row), (0, active));
    assert_eq!(broken.relation, "gated_equality");
    let (_, result) = run(
        &artifact,
        &base,
        &values,
        &output_claims(&artifact, &values),
    );
    assert_eq!(result, Err(GkrError::LayerInconsistency { layer: 0 }));
}

/// Acceptance 3: a base violating the enforcing gate by `+v` on one row and
/// `−v` on another. Its bare sum over the cube is exactly zero — a verifier
/// summing `G(y)` unweighted would accept — while its eq-weighted sum at a
/// random point is not, and `verify` rejects.
#[test]
fn a_cancelling_violation_is_rejected() {
    let artifact = toy();
    let cols = toy_columns(0x5313_0500);
    let active: Vec<usize> = (0..TOY_ROWS).filter(|&y| cols.s[y] == 1).collect();
    assert!(active.len() >= 2, "two active rows");
    let v = Fr::from_u64(0x1234_5678_9abc);
    let mut e: Vec<Fr> = cols.e.iter().map(|x| fr(*x)).collect();
    e[active[0]] += v;
    e[active[1]] -= v;
    let base = with_column(&toy_base(&cols), &artifact, PolyAddress::Witness(3), e);

    let (_, challenges) = bind(&artifact, &base);
    let values = forward(&artifact, &base, &challenges);
    let residual: Vec<Fr> = (0..TOY_ROWS)
        .map(|y| {
            let lower: Vec<Fr> = artifact
                .committed()
                .iter()
                .map(|a| values.base.get(*a).unwrap().get(y))
                .collect();
            gate_values(&artifact, 0, &lower, &[], &[fr(y as u32)], &challenges)[3]
        })
        .collect();
    assert_eq!(residual[active[0]], v);
    assert_eq!(residual[active[1]], -v);
    let bare: Fr = residual.iter().fold(Fr::ZERO, |acc, r| acc + *r);
    assert_eq!(bare, Fr::ZERO, "the violations cancel in a bare sum");
    let r: Vec<Fr> = (0..4).map(|i| Fr::from_u64(0x77 + i)).collect();
    let weighted = eq_table(&r)
        .iter()
        .zip(&residual)
        .fold(Fr::ZERO, |acc, (w, g)| acc + *w * *g);
    assert_ne!(weighted, Fr::ZERO, "eq(r, y) separates them");

    let (_, result) = run(
        &artifact,
        &base,
        &values,
        &output_claims(&artifact, &values),
    );
    assert_eq!(result, Err(GkrError::LayerInconsistency { layer: 0 }));
}

/// The outputs are absorbed before the point they are evaluated at. A forged
/// output table agreeing with the true one at the point the honest transcript
/// draws — which a prover can compute in advance — is rejected, because
/// absorbing the forgery moves the point.
#[test]
fn a_forged_output_table_is_rejected() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_0600));
    let (values, proof, result) = honest(&artifact, &base);
    result.expect("the honest run verifies");
    let outputs = output_claims(&artifact, &values);

    // The point an honest verifier draws, replayed from the frozen schedule.
    let (mut t, challenges) = bind(&artifact, &base);
    let message: Vec<Fr> = outputs
        .tables
        .iter()
        .flat_map(|tbl| (0..tbl.len()).map(|i| tbl.get(i)).collect::<Vec<_>>())
        .collect();
    t.append_scalars(transcript_tags::GKR_OUTPUTS, &message);
    let r: Vec<Fr> = (0..3)
        .map(|_| t.challenge_scalar(transcript_tags::GKR_OUTPUT_POINT))
        .collect();

    // Move row 1 by delta and row 6 by what keeps the evaluation at r.
    let honest_table = &outputs.tables[0];
    let mut forged: Vec<Fr> = (0..honest_table.len())
        .map(|i| honest_table.get(i))
        .collect();
    let bit = |i: usize| -> Vec<Fr> {
        (0..3)
            .map(|j| Fr::from_u64(((i >> j) & 1) as u64))
            .collect()
    };
    let delta = Fr::from_u64(99);
    let shift = delta * eq_eval(&r, &bit(1)) * eq_eval(&r, &bit(6)).inverse().unwrap();
    forged[1] += delta;
    forged[6] -= shift;
    let forged = MultilinearPoly::new(PolyBacking::Fr(forged));
    assert_eq!(
        forged.evaluate(&r),
        honest_table.evaluate(&r),
        "same value at r"
    );

    let claims = OutputClaims {
        tables: vec![forged, outputs.tables[1].clone()],
    };
    let (mut verifier, _) = bind(&artifact, &base);
    assert_eq!(
        verify(&artifact, &proof, &claims, &challenges, &mut verifier),
        Err(GkrError::LayerInconsistency { layer: 2 })
    );
}

/// A halving transition's children: a bumped child fails that transition's
/// final check; a pair with the right product but the wrong line passes it and
/// fails the transition below, where `τ` lands.
#[test]
fn a_wrong_child_pair_is_rejected() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_0700));
    let (values, proof, _) = honest(&artifact, &base);
    let outputs = output_claims(&artifact, &values);
    let check = |proof: &gkr::GkrProof| {
        let (mut t, challenges) = bind(&artifact, &base);
        verify(&artifact, proof, &outputs, &challenges, &mut t)
    };

    let mut bumped = proof.clone();
    bumped.layers[2].final_evals[0] += Fr::ONE;
    assert_eq!(
        check(&bumped),
        Err(GkrError::LayerInconsistency { layer: 2 })
    );

    let mut rescaled = proof.clone();
    let two = Fr::from_u64(2);
    rescaled.layers[2].final_evals[0] *= two;
    rescaled.layers[2].final_evals[1] *= two.inverse().unwrap();
    assert_eq!(
        check(&rescaled),
        Err(GkrError::LayerInconsistency { layer: 1 })
    );
    assert_eq!(
        check(&proof),
        Ok(check(&proof).unwrap()),
        "the control verifies"
    );
}

/// Every malformed shape is an error before the transcript is touched, in the
/// frozen order: challenges, then outputs, then the proof.
#[test]
fn malformed_shapes_are_errors_in_order() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_0800));
    let (values, proof, _) = honest(&artifact, &base);
    let outputs = output_claims(&artifact, &values);
    let (_, challenges) = bind(&artifact, &base);
    let check = |proof: &gkr::GkrProof, outputs: &OutputClaims, ch: &gkr::ExternalChallenges| {
        let (mut t, _) = bind(&artifact, &base);
        let before = t.snapshot();
        let result = verify(&artifact, proof, outputs, ch, &mut t);
        if result.is_err() && !matches!(result, Err(GkrError::LayerInconsistency { .. })) {
            assert_eq!(t.snapshot(), before, "a shape error touches no transcript");
        }
        result
    };

    let mut short = proof.clone();
    short.layers[0].rounds.pop();
    assert_eq!(
        check(&short, &outputs, &challenges),
        Err(GkrError::ProofShape { layer: 0 })
    );
    let mut long = proof.clone();
    long.layers[1].final_evals.push(Fr::ZERO);
    assert_eq!(
        check(&long, &outputs, &challenges),
        Err(GkrError::ProofShape { layer: 1 })
    );
    let mut shallow = proof.clone();
    shallow.layers.pop();
    assert_eq!(
        check(&shallow, &outputs, &challenges),
        Err(GkrError::ProofShape { layer: 3 })
    );

    let one = OutputClaims {
        tables: vec![outputs.tables[0].clone()],
    };
    assert_eq!(check(&proof, &one, &challenges), Err(GkrError::OutputShape));
    let wide = OutputClaims {
        tables: vec![values.layers[1][0].clone(), outputs.tables[1].clone()],
    };
    assert_eq!(
        check(&proof, &wide, &challenges),
        Err(GkrError::OutputShape)
    );

    let none = gkr::ExternalChallenges::new();
    assert_eq!(
        check(&shallow, &one, &none),
        Err(GkrError::MissingChallenge { slot: 0 })
    );
    assert_eq!(
        check(&shallow, &one, &challenges),
        Err(GkrError::OutputShape)
    );
    assert!(
        check(&proof, &outputs, &challenges).is_ok(),
        "the control verifies"
    );
}
