//! Rounds after round 0. `verify_sumcheck` holds every round's `g(0) + g(1)` to
//! the claim it inherits from the round before. A verifier that checked round 0
//! alone would let a prover send anything after it and repair the chain in the
//! last round — and the final check, which sees only that last round, cannot
//! tell.

mod common;

use common::{base_layer, bind, discharge, honest, opposed_circuit};
use constants::transcript_tags as tags;
use constraints::PolyAddress;
use field::{Fp, Fp2};
use gkr::{verify, verify_sumcheck, GkrError, GkrProof, SumcheckProof};
use poly::eq_eval;
use transcript::Transcript;

fn cubic(g: &[Fp2; 4], x: Fp2) -> Fp2 {
    g[0] + x * (g[1] + x * (g[2] + x * g[3]))
}

fn inv(k: u64) -> Fp {
    Fp::from_u64(k)
        .inverse()
        .expect("2, 3 and 6 are invertible")
}

/// The cubic through `(x, v[x])`, `x = 0..4`, by Newton's forward differences.
fn interpolate(v: &[Fp2]) -> [Fp2; 4] {
    let d1 = v[1] - v[0];
    let d2 = v[2] - v[1] - v[1] + v[0];
    let d3 = v[3] - v[2] - v[2] - v[2] + v[1] + v[1] + v[1] - v[0];
    [
        v[0],
        d1 - d2 * inv(2) + d3 * inv(3),
        (d2 - d3) * inv(2),
        d3 * inv(6),
    ]
}

/// Rounds with the given `c1, c2, c3`, each `c0` chosen so the round sums to
/// the claim it inherits, replayed on a fresh transcript: the rounds, the
/// point they bind, and the last claim.
fn chain(claim: Fp2, upper: &[[u64; 3]]) -> (Vec<[Fp2; 4]>, Vec<Fp2>, Fp2) {
    let mut t = Transcript::new();
    let (mut claim, mut rounds, mut point) = (claim, Vec::new(), Vec::new());
    for c in upper {
        let [c1, c2, c3] = c.map(|x| Fp2::from(Fp::from_u64(x)));
        let g = [(claim - c1 - c2 - c3) * inv(2), c1, c2, c3];
        t.append_ext(tags::SUMCHECK_ROUND, &g);
        let r = t.challenge(tags::SUMCHECK_CHALLENGE);
        claim = cubic(&g, r);
        rounds.push(g);
        point.push(r);
    }
    (rounds, point, claim)
}

/// A three-round chain that sums at every round verifies, to exactly the point
/// and last claim it replays. The same chain with one round moved off its
/// inherited claim by one returns `None`, at every round: `c1` counts once in
/// `g(1)` and not in `g(0)`. Rounds 1 and 2 leave round 0 intact, so kills
/// mutant B, the verifier that checks only round 0.
#[test]
fn every_round_is_held_to_the_claim_it_inherits() {
    let claim = Fp2::from(Fp::from_u64(0x5313_1400));
    let (rounds, point, last) = chain(claim, &[[3, 5, 7], [11, 13, 17], [19, 23, 29]]);
    assert_eq!(
        verify_sumcheck(claim, &rounds, &mut Transcript::new()),
        Some((point, last))
    );
    for i in 0..rounds.len() {
        let mut broken = rounds.clone();
        broken[i][1] += Fp2::ONE;
        assert_eq!(
            verify_sumcheck(claim, &broken, &mut Transcript::new()),
            None,
            "round {i} does not sum to its claim"
        );
    }
}

/// Mutant B end to end: a forged output on `opposed_circuit`, over an honest
/// base. The forger carries its root down through the two halving transitions,
/// meeting each final check by its choice of children: transition 2 has no
/// round, and transition 1's one round is its round 0, flat at half the claim.
/// At transition 0 its round 0 is flat at half the forged claim, so it sums to
/// it; round 1, the last, is the true cubic `eq(p, (ρ0, X))·S(ρ0, X)`, so it
/// ends exactly where the final check wants and leaves true base claims. Only
/// round 1's own check — against the claim round 0 hands it — sees the seam.
/// Under mutant B this proof verifies and its base claims discharge.
#[test]
fn a_repaired_last_round_does_not_forge_an_output() {
    let artifact = opposed_circuit();
    let column: Vec<Fp> = (0..4).map(|i| Fp::from_u64(0x5313_1500 + i)).collect();
    let base = base_layer(&artifact, vec![column.clone(), column.clone()]);
    let (values, _, result) = honest(&artifact, &base);
    discharge(&base, &result.expect("the honest run verifies")).expect("and discharges");
    let truth = &values.layers[0][0];
    let outputs = [values.layers[2][0].get(0) + Fp2::ONE];

    // The forger follows the schedule. O1, then transition 2, with no round:
    // its final check asks only that the two children multiply to the root.
    let (mut t, _) = bind(&artifact, &base);
    t.append_ext(tags::GKR_OUTPUTS, &outputs);
    t.challenge(tags::GKR_BATCH);
    let top = [Fp2::ONE, outputs[0]];
    t.append_ext(tags::GKR_LAYER_CLAIMS, &top);
    let tau = t.challenge(tags::GKR_CHILD);
    let claim = top[0] + tau * (top[1] - top[0]);

    // Transition 1: its one round flat at half the claim, then children whose
    // product meets the final check at the round's challenge.
    t.challenge(tags::GKR_BATCH);
    let flat = [claim * inv(2), Fp2::ZERO, Fp2::ZERO, Fp2::ZERO];
    t.append_ext(tags::SUMCHECK_ROUND, &flat);
    let r = t.challenge(tags::SUMCHECK_CHALLENGE);
    let eq = eq_eval(&[tau], &[r])
        .inverse()
        .expect("eq(τ, r) is nonzero");
    let middle = [Fp2::ONE, cubic(&flat, r) * eq];
    t.append_ext(tags::GKR_LAYER_CLAIMS, &middle);
    let p = [r, t.challenge(tags::GKR_CHILD)];
    let claim = middle[0] + p[1] * (middle[1] - middle[0]);
    assert_ne!(claim, truth.evaluate(&p), "the forged claim is wrong");

    // Transition 0.
    let lambda = t.challenge(tags::GKR_BATCH);
    let round0 = [claim * inv(2), Fp2::ZERO, Fp2::ZERO, Fp2::ZERO];
    t.append_ext(tags::SUMCHECK_ROUND, &round0);
    let rho0 = t.challenge(tags::SUMCHECK_CHALLENGE);

    // S = copy + λ·(a − b) + λ²·(b − a), written out.
    let (a, b) = (
        base.get(PolyAddress::Witness(0)).unwrap(),
        base.get(PolyAddress::Witness(1)).unwrap(),
    );
    let true_round = |x: Fp2| {
        let y = [rho0, x];
        let (av, bv) = (a.evaluate(&y), b.evaluate(&y));
        eq_eval(&p, &y) * (av + lambda * (av - bv) + lambda * lambda * (bv - av))
    };
    let nodes: Vec<Fp2> = (0..4)
        .map(|x| true_round(Fp2::from(Fp::from_u64(x))))
        .collect();
    let round1 = interpolate(&nodes);
    for (x, v) in nodes.iter().enumerate() {
        assert_eq!(
            cubic(&round1, Fp2::from(Fp::from_u64(x as u64))),
            *v,
            "node {x}"
        );
    }
    t.append_ext(tags::SUMCHECK_ROUND, &round1);
    let rho1 = t.challenge(tags::SUMCHECK_CHALLENGE);
    let rho = [rho0, rho1];
    let proof = GkrProof {
        layers: vec![
            SumcheckProof {
                rounds: vec![round0, round1],
                final_evals: vec![a.evaluate(&rho), b.evaluate(&rho)],
            },
            SumcheckProof {
                rounds: vec![flat],
                final_evals: middle.to_vec(),
            },
            SumcheckProof {
                rounds: vec![],
                final_evals: top.to_vec(),
            },
        ],
    };
    assert_eq!(
        cubic(&round1, rho1),
        true_round(rho1),
        "the last claim is what the final check wants"
    );
    assert_ne!(
        cubic(&round1, Fp2::ZERO) + cubic(&round1, Fp2::ONE),
        cubic(&round0, rho0),
        "round 1 does not sum to the claim round 0 leaves"
    );

    let (mut verifier, challenges) = bind(&artifact, &base);
    assert_eq!(
        verify(&artifact, &proof, &outputs, &challenges, &mut verifier),
        Err(GkrError::LayerInconsistency { layer: 0 })
    );
}
