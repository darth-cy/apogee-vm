//! Rounds after round 0. `verify_sumcheck` holds every round's `g(0) + g(1)` to
//! the claim it inherits from the round before. A verifier that checked round 0
//! alone would let a prover send anything after it and repair the chain in the
//! last round — and the final check, which sees only that last round, cannot
//! tell.

mod common;

use common::{bind, discharge, fr_base, honest, opposed_circuit};
use constants::transcript_tags as tags;
use constraints::PolyAddress;
use field::Fr;
use gkr::{verify, verify_sumcheck, GkrError, GkrProof, OutputClaims, SumcheckProof};
use poly::{eq_eval, MultilinearPoly, PolyBacking};
use transcript::Transcript;

fn cubic(g: &[Fr; 4], x: Fr) -> Fr {
    g[0] + x * (g[1] + x * (g[2] + x * g[3]))
}

fn inv(k: u64) -> Fr {
    Fr::from_u64(k)
        .inverse()
        .expect("2, 3 and 6 are invertible")
}

/// The cubic through `(x, v[x])`, `x = 0..4`, by Newton's forward differences.
fn interpolate(v: &[Fr]) -> [Fr; 4] {
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
fn chain(claim: Fr, upper: &[[u64; 3]]) -> (Vec<[Fr; 4]>, Vec<Fr>, Fr) {
    let mut t = Transcript::new();
    let (mut claim, mut rounds, mut point) = (claim, Vec::new(), Vec::new());
    for c in upper {
        let [c1, c2, c3] = c.map(Fr::from_u64);
        let g = [(claim - c1 - c2 - c3) * inv(2), c1, c2, c3];
        t.append_scalars(tags::SUMCHECK_ROUND, &g);
        let r = t.challenge_scalar(tags::SUMCHECK_CHALLENGE);
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
    let claim = Fr::from_u64(0x5313_1400);
    let (rounds, point, last) = chain(claim, &[[3, 5, 7], [11, 13, 17], [19, 23, 29]]);
    assert_eq!(
        verify_sumcheck(claim, &rounds, &mut Transcript::new()),
        Some((point, last))
    );
    for i in 0..rounds.len() {
        let mut broken = rounds.clone();
        broken[i][1] += Fr::ONE;
        assert_eq!(
            verify_sumcheck(claim, &broken, &mut Transcript::new()),
            None,
            "round {i} does not sum to its claim"
        );
    }
}

/// Mutant B end to end: a forged output table on `opposed_circuit`, over an
/// honest base. The forger's round 0 is flat at half the forged claim, so it
/// sums to it; round 1, the last, is the true cubic `eq(p, (ρ0, X))·S(ρ0, X)`,
/// so it ends exactly where the final check wants and leaves true base claims.
/// Only round 1's own check — against the claim round 0 hands it — sees the
/// seam. Under mutant B this proof verifies and its base claims discharge.
#[test]
fn a_repaired_last_round_does_not_forge_an_output() {
    let artifact = opposed_circuit();
    let column: Vec<Fr> = (0..4).map(|i| Fr::from_u64(0x5313_1500 + i)).collect();
    let base = fr_base(&artifact, vec![column.clone(), column.clone()]);
    let (values, _, result) = honest(&artifact, &base);
    discharge(&base, &result.expect("the honest run verifies")).expect("and discharges");
    let truth = &values.layers[0][0];

    let mut forged = column.clone();
    forged[0] += Fr::ONE;
    let outputs = OutputClaims {
        tables: vec![MultilinearPoly::new(PolyBacking::Fr(forged.clone()))],
    };

    // The forger follows the schedule, O1 through L3.
    let (mut t, _) = bind(&artifact, &base);
    t.append_scalars(tags::GKR_OUTPUTS, &forged);
    let p: Vec<Fr> = (0..2)
        .map(|_| t.challenge_scalar(tags::GKR_OUTPUT_POINT))
        .collect();
    let lambda = t.challenge_scalar(tags::GKR_BATCH);
    let claim = outputs.tables[0].evaluate(&p);
    assert_ne!(claim, truth.evaluate(&p), "the forged claim is wrong");
    let round0 = [claim * inv(2), Fr::ZERO, Fr::ZERO, Fr::ZERO];
    t.append_scalars(tags::SUMCHECK_ROUND, &round0);
    let rho0 = t.challenge_scalar(tags::SUMCHECK_CHALLENGE);

    // S = copy + λ·(a − b) + λ²·(b − a), written out.
    let (a, b) = (
        base.get(PolyAddress::Witness(0)).unwrap(),
        base.get(PolyAddress::Witness(1)).unwrap(),
    );
    let true_round = |x: Fr| {
        let y = [rho0, x];
        let (av, bv) = (a.evaluate(&y), b.evaluate(&y));
        eq_eval(&p, &y) * (av + lambda * (av - bv) + lambda * lambda * (bv - av))
    };
    let nodes: Vec<Fr> = (0..4).map(|x| true_round(Fr::from_u64(x))).collect();
    let round1 = interpolate(&nodes);
    for (x, v) in nodes.iter().enumerate() {
        assert_eq!(cubic(&round1, Fr::from_u64(x as u64)), *v, "node {x}");
    }
    t.append_scalars(tags::SUMCHECK_ROUND, &round1);
    let rho1 = t.challenge_scalar(tags::SUMCHECK_CHALLENGE);
    let rho = [rho0, rho1];
    let proof = GkrProof {
        layers: vec![SumcheckProof {
            rounds: vec![round0, round1],
            final_evals: vec![a.evaluate(&rho), b.evaluate(&rho)],
        }],
    };
    assert_eq!(
        cubic(&round1, rho1),
        true_round(rho1),
        "the last claim is what the final check wants"
    );
    assert_ne!(
        cubic(&round1, Fr::ZERO) + cubic(&round1, Fr::ONE),
        cubic(&round0, rho0),
        "round 1 does not sum to the claim round 0 leaves"
    );

    let (mut verifier, challenges) = bind(&artifact, &base);
    assert_eq!(
        verify(&artifact, &proof, &outputs, &challenges, &mut verifier),
        Err(GkrError::LayerInconsistency { layer: 0 })
    );
}
