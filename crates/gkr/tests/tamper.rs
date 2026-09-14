//! What `verify` rejects: the tamper twin (acceptance 2), the cancellation
//! control (acceptance 3), a forged output table, a wrong child pair, a lying
//! row-wise final eval, every malformed shape and every missing slot — each as
//! a returned error, never a panic — and what the self-check names.

mod common;

use std::panic::{catch_unwind, AssertUnwindSafe};

use common::{
    bind, honest, output_claims, run, toy, toy_base, toy_cache_free, toy_columns, with_column,
    TOY_ROWS,
};
use constants::{challenge_slot, transcript_tags};
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress};
use field::Fr;
use gkr::{
    forward, gate_values, self_check, verify, ExternalChallenges, GkrError, LayerValues,
    OutputClaims, SelfCheckError,
};
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

/// The self-check compares every producing gate with the column it writes,
/// halving lists included, and names the first that disagrees: `abm` bumped on
/// row 3 is `define_abm` at list 1, and `fingerprint3_product` bumped on row 2
/// is its tree step at list 2. Kills M1 and M14b (producing gates never
/// compared) and M14c (halving lists skipped).
#[test]
fn the_self_check_names_a_broken_producing_gate() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_0300));
    let (_, challenges) = bind(&artifact, &base);
    let values = forward(&artifact, &base, &challenges);
    assert_eq!(self_check(&artifact, &values, &challenges), Ok(()));
    assert_eq!(
        self_check(&artifact, &bump(&values, 2, 0, 3), &challenges),
        Err(SelfCheckError {
            layer: 1,
            row: 3,
            relation: "define_abm".into(),
        })
    );
    assert_eq!(
        self_check(&artifact, &bump(&values, 3, 1, 2), &challenges),
        Err(SelfCheckError {
            layer: 2,
            row: 2,
            relation: "define_fingerprint3_product".into(),
        })
    );
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

/// O1, the outputs absorbed before their point, is what stops this forgery.
/// Without O1 the output point is what a transcript bound to the base draws
/// next, so a prover knows it before choosing a table, and can choose one that
/// differs from the true table yet agrees with it there. The forgery is built
/// at exactly that point, so a verifier that never absorbs the outputs accepts
/// it: this test fails under the mutant deleting the `GKR_OUTPUTS` absorb from
/// both sides. The real verifier absorbs the forged table, draws another
/// point, and rejects.
#[test]
fn a_forged_output_table_is_rejected() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_0600));
    let (values, proof, result) = honest(&artifact, &base);
    result.expect("the honest run verifies");
    let outputs = output_claims(&artifact, &values);

    // The point a transcript without O1 draws: the binding, then O2 at once.
    let (mut t, challenges) = bind(&artifact, &base);
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

/// A row-wise transition's final check, alone: one of its final evals bumped,
/// every round untouched. The rounds still sum, so only the final check of
/// that transition can reject — at transition 1 before the lie descends, and
/// at transition 0 before it comes back as an accepted `BaseClaim`. Kills
/// mutant A, the verifier that runs the final check on halving transitions
/// only: there transition 1's lie is caught a layer late, and transition 0's
/// verifies.
#[test]
fn a_lying_row_wise_final_eval_is_rejected_at_its_transition() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_0a00));
    let (values, proof, result) = honest(&artifact, &base);
    result.expect("the control verifies");
    let outputs = output_claims(&artifact, &values);
    let check = |proof: &gkr::GkrProof| {
        let (mut t, challenges) = bind(&artifact, &base);
        verify(&artifact, proof, &outputs, &challenges, &mut t)
    };

    for k in [0, 1] {
        assert!(!artifact.layers[k].halving, "transition {k} is row-wise");
        for j in 0..proof.layers[k].final_evals.len() {
            let mut lying = proof.clone();
            lying.layers[k].final_evals[j] += Fr::ONE;
            assert_eq!(
                check(&lying),
                Err(GkrError::LayerInconsistency { layer: k }),
                "final eval {j} of transition {k}"
            );
        }
    }
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

    // Too long, not only too short: a layer beyond the depth is refused
    // before anything reads the artifact at it.
    let mut deep = proof.clone();
    deep.layers.push(proof.layers[2].clone());
    assert_eq!(
        check(&deep, &outputs, &challenges),
        Err(GkrError::ProofShape { layer: 3 })
    );
    // Two malformed transitions: the lowest is reported.
    let mut twice = proof.clone();
    twice.layers[0].rounds.pop();
    twice.layers[2].final_evals.push(Fr::ZERO);
    assert_eq!(
        check(&twice, &outputs, &challenges),
        Err(GkrError::ProofShape { layer: 0 })
    );

    let one = OutputClaims {
        tables: vec![outputs.tables[0].clone()],
    };
    assert_eq!(check(&proof, &one, &challenges), Err(GkrError::OutputShape));
    let three = OutputClaims {
        tables: vec![
            outputs.tables[0].clone(),
            outputs.tables[1].clone(),
            outputs.tables[0].clone(),
        ],
    };
    assert_eq!(
        check(&proof, &three, &challenges),
        Err(GkrError::OutputShape)
    );
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

/// How many gates of each kind — cached, producing, enforcing — name a
/// challenge slot.
fn challenge_sites(artifact: &CircuitArtifact) -> [usize; 3] {
    let names = |gate: &GateDef| {
        gate.coefficients()
            .iter()
            .any(|c| matches!(c, Coeff::Challenge(_)))
    };
    let count = |gates: Vec<&GateDef>| gates.into_iter().filter(|g| names(g)).count();
    let lists = &artifact.layers;
    [
        count(
            lists
                .iter()
                .flat_map(|l| &l.cached)
                .map(|e| &e.gate)
                .collect(),
        ),
        count(
            lists
                .iter()
                .flat_map(|l| &l.producing)
                .map(|e| &e.gate)
                .collect(),
        ),
        count(
            lists
                .iter()
                .flat_map(|l| &l.enforcing)
                .map(|e| &e.gate)
                .collect(),
        ),
    ]
}

/// `MissingChallenge` wherever the slot is named, not only in a cached entry,
/// where the toy names it: in a producing gate (the cache-free toy, where `γ`
/// sits in fingerprint's `AffineProduct`) and in an enforcing gate alone (the
/// toy with `γ` moved out of `shifted_a` and onto `s` in the gated equality,
/// written for that as `(e − a)·(γ·s)`, relations to match). Each verifies with its slot, and without it returns
/// the error, untouched transcript and all, where a verifier that checked
/// cached entries only would panic inside the kernel. Kills Mutant C and M10b.
#[test]
fn a_slot_named_by_a_producing_or_enforcing_gate_is_checked() {
    let (one, gamma) = (
        Coeff::Literal(Fr::ONE),
        Coeff::Challenge(challenge_slot::TOY),
    );
    let mut enforcing = toy();
    let set = |gate: &mut GateDef, left: bool, to: Coeff| match gate {
        GateDef::Linear { terms, .. } => terms[0].0 = to,
        GateDef::AffineProduct {
            left: l, right: r, ..
        } => {
            if left {
                l[0].0 = to
            } else {
                r[0].0 = to
            }
        }
        other => panic!("not a toy gate: {other:?}"),
    };
    set(&mut enforcing.layers[0].cached[0].gate, true, one);
    set(&mut enforcing.relations[1].gate, true, one);
    // The toy spells the gated equality as a `Quadratic`, whose two product
    // coefficients `γ` and `−γ` no single `Coeff` can both be; `(e − a)·(γ·s)`
    // is the same relation with one challenge.
    let gated = GateDef::AffineProduct {
        left: vec![
            (one, PolyAddress::Witness(3)),
            (Coeff::Literal(-Fr::ONE), PolyAddress::Witness(0)),
        ],
        left_constant: Coeff::Literal(Fr::ZERO),
        right: vec![(one, PolyAddress::Setup(0))],
        right_constant: Coeff::Literal(Fr::ZERO),
    };
    enforcing.layers[0].enforcing[0].gate = gated.clone();
    enforcing.relations[3].gate = gated;
    set(&mut enforcing.layers[0].enforcing[0].gate, false, gamma);
    set(&mut enforcing.relations[3].gate, false, gamma);
    assert_eq!(enforcing.relations[3].name, "gated_equality");
    enforcing
        .validate()
        .expect("γ on s in the gated equality is legal");

    let producing = toy_cache_free();
    assert_eq!(challenge_sites(&producing), [0, 1, 0]);
    assert_eq!(challenge_sites(&enforcing), [0, 0, 1]);
    for artifact in [producing, enforcing] {
        let base = toy_base(&toy_columns(0x5313_0b00));
        let (values, proof, result) = honest(&artifact, &base);
        result.expect("the control verifies with its slot supplied");
        let outputs = output_claims(&artifact, &values);
        let (mut t, _) = bind(&artifact, &base);
        let before = t.snapshot();
        let result = catch_unwind(AssertUnwindSafe(|| {
            verify(
                &artifact,
                &proof,
                &outputs,
                &ExternalChallenges::new(),
                &mut t,
            )
        }));
        assert_eq!(
            result.ok(),
            Some(Err(GkrError::MissingChallenge { slot: 0 })),
            "an error, not a panic"
        );
        assert_eq!(t.snapshot(), before, "a missing slot touches no transcript");
    }
}
