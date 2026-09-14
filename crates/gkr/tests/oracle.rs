//! Every round polynomial of every transition, recomputed from the definition.
//!
//! Nothing here calls the engine's kernel, `gate_values`, the prover's round
//! machinery or its interpolation. The toy's layers are rebuilt by hand from
//! its description, each transition's summand is written out as the toy's
//! formulas, and each round's cubic is recomputed at its four nodes as a direct
//! sum over the remaining cube of `eq(p, point) · S(point)`, every column read
//! through `MultilinearPoly::evaluate`. The challenges are replayed from the
//! frozen schedule of `docs/spec/gkr.md` §5.2, a second transcription of it.

mod common;

use common::{bind, toy, toy_base, toy_columns, ToyColumns, TOY_ROWS};
use constants::transcript_tags as tags;
use field::Fr;
use gkr::{forward, prove, GkrProof};
use poly::{eq_eval, MultilinearPoly, PolyBacking};
use transcript::Transcript;

fn poly(values: Vec<Fr>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(values))
}

fn fr(v: u32) -> Fr {
    Fr::from_u64(v as u64)
}

fn bits(i: usize, n: usize) -> Vec<Fr> {
    (0..n)
        .map(|j| Fr::from_u64(((i >> j) & 1) as u64))
        .collect()
}

fn cubic_at(g: &[Fr; 4], x: Fr) -> Fr {
    g[0] + x * (g[1] + x * (g[2] + x * g[3]))
}

fn table(p: &MultilinearPoly) -> Vec<Fr> {
    (0..p.len()).map(|i| p.get(i)).collect()
}

/// The toy, by hand: the description in `tools/kat-gen/src/gkr.rs`'s module
/// docs, not its code.
struct Hand {
    base: [MultilinearPoly; 6], // m a b c e s, layout order
    ab: MultilinearPoly,
    fingerprint: MultilinearPoly,
    masked_m: MultilinearPoly,
    abm: MultilinearPoly,
    fingerprint3: MultilinearPoly,
    abm_product: MultilinearPoly,
    fingerprint3_product: MultilinearPoly,
}

fn hand(cols: &ToyColumns, gamma: Fr) -> Hand {
    let col = |v: &[u32]| -> Vec<Fr> { v.iter().map(|x| fr(*x)).collect() };
    let (m, a, b, c, e, s) = (
        col(&cols.m),
        col(&cols.a),
        col(&cols.b),
        col(&cols.c),
        col(&cols.e),
        col(&cols.s),
    );
    let rows = 0..TOY_ROWS;
    let ab: Vec<Fr> = rows.clone().map(|y| a[y] * b[y]).collect();
    let fingerprint: Vec<Fr> = rows
        .clone()
        .map(|y| (gamma * a[y] + Fr::from_u64(y as u64)) * c[y])
        .collect();
    let masked_m: Vec<Fr> = rows.clone().map(|y| m[y] * s[y] + Fr::ONE - s[y]).collect();
    let abm: Vec<Fr> = rows.clone().map(|y| ab[y] * masked_m[y]).collect();
    let fingerprint3: Vec<Fr> = rows.map(|y| fingerprint[y] + Fr::from_u64(3)).collect();
    let half = TOY_ROWS / 2;
    let tree = |v: &[Fr]| -> Vec<Fr> { (0..half).map(|i| v[i] * v[i + half]).collect() };
    Hand {
        abm_product: poly(tree(&abm)),
        fingerprint3_product: poly(tree(&fingerprint3)),
        base: [poly(m), poly(a), poly(b), poly(c), poly(e), poly(s)],
        ab: poly(ab),
        fingerprint: poly(fingerprint),
        masked_m: poly(masked_m),
        abm: poly(abm),
        fingerprint3: poly(fingerprint3),
    }
}

/// One transition's summand, with the challenges it is weighted by.
#[derive(Clone, Copy)]
enum Summand {
    /// Transition 2, halving: `abm(x,0)·abm(x,1) + λ·fp3(x,0)·fp3(x,1)`.
    Two { lambda: Fr },
    /// Transition 1: `ab·masked_m + λ·(fingerprint + 3)`.
    One { lambda: Fr },
    /// Transition 0: `a·b + λ·(γ·a + row)·c + λ²·(m·s + 1 − s) + λ³·(e − a)·s`.
    Zero { lambda: Fr, gamma: Fr },
}

impl Hand {
    fn summand(&self, s: Summand, y: &[Fr]) -> Fr {
        match s {
            Summand::Two { lambda } => {
                let child = |p: &MultilinearPoly, b: u64| {
                    let mut point = y.to_vec();
                    point.push(Fr::from_u64(b));
                    p.evaluate(&point)
                };
                child(&self.abm, 0) * child(&self.abm, 1)
                    + lambda * child(&self.fingerprint3, 0) * child(&self.fingerprint3, 1)
            }
            Summand::One { lambda } => {
                self.ab.evaluate(y) * self.masked_m.evaluate(y)
                    + lambda * (self.fingerprint.evaluate(y) + Fr::from_u64(3))
            }
            Summand::Zero { lambda, gamma } => {
                let v: Vec<Fr> = self.base.iter().map(|c| c.evaluate(y)).collect();
                let (m, a, b, c, e, s) = (v[0], v[1], v[2], v[3], v[4], v[5]);
                // `row`'s multilinear extension, Σ 2^j·y_j, written out here.
                let row = y
                    .iter()
                    .enumerate()
                    .fold(Fr::ZERO, |acc, (j, yj)| acc + Fr::from_u64(1 << j) * *yj);
                let l2 = lambda * lambda;
                a * b
                    + lambda * (gamma * a + row) * c
                    + l2 * (m * s + Fr::ONE - s)
                    + l2 * lambda * (e - a) * s
            }
        }
    }

    /// `Σ_rest eq(p, (bound, X, rest)) · S(bound, X, rest)`.
    fn naive(&self, s: Summand, p: &[Fr], bound: &[Fr], x: Fr) -> Fr {
        let rest = p.len() - bound.len() - 1;
        (0..1usize << rest).fold(Fr::ZERO, |acc, i| {
            let mut point = bound.to_vec();
            point.push(x);
            point.extend(bits(i, rest));
            acc + eq_eval(p, &point) * self.summand(s, &point)
        })
    }

    /// Replay one transition's rounds, holding each cubic to `naive` at its
    /// four nodes; returns the bound point and adds the nodes compared.
    fn rounds(
        &self,
        s: Summand,
        t: &mut Transcript,
        p: &[Fr],
        proof_rounds: &[[Fr; 4]],
        compared: &mut usize,
    ) -> Vec<Fr> {
        let mut bound: Vec<Fr> = Vec::new();
        for (i, g) in proof_rounds.iter().enumerate() {
            for node in 0..4u64 {
                let x = Fr::from_u64(node);
                assert_eq!(
                    cubic_at(g, x),
                    self.naive(s, p, &bound, x),
                    "round {i} at X = {node}"
                );
                *compared += 1;
            }
            t.append_scalars(tags::SUMCHECK_ROUND, g);
            bound.push(t.challenge_scalar(tags::SUMCHECK_CHALLENGE));
        }
        bound
    }

    /// O1 and O2, replayed: the output map is `L{3}[1], L{3}[0]`.
    fn output_point(&self, t: &mut Transcript) -> Vec<Fr> {
        let mut outputs = table(&self.fingerprint3_product);
        outputs.extend(table(&self.abm_product));
        t.append_scalars(tags::GKR_OUTPUTS, &outputs);
        (0..3)
            .map(|_| t.challenge_scalar(tags::GKR_OUTPUT_POINT))
            .collect()
    }
}

/// An honest proof of the toy, and a fresh transcript bound exactly as the
/// prover's was, to replay the schedule on.
fn prove_toy(seed: u64) -> (ToyColumns, GkrProof, Transcript, Fr) {
    let artifact = toy();
    let cols = toy_columns(seed);
    let base = toy_base(&cols);
    let (mut prover, challenges) = bind(&artifact, &base);
    let values = forward(&artifact, &base, &challenges);
    let proof = prove(&artifact, &values, &challenges, &mut prover);
    let (replay, challenges) = bind(&artifact, &base);
    let gamma = challenges.get(constants::challenge_slot::TOY).unwrap();
    (cols, proof, replay, gamma)
}

#[test]
fn every_round_of_every_transition_matches_the_definition() {
    for seed in 0..3u64 {
        let (cols, proof, mut t, gamma) = prove_toy(0x5313_1200 + seed);
        let h = hand(&cols, gamma);
        let mut compared = 0;
        let r = h.output_point(&mut t);

        // Transition 2, halving.
        let lambda = t.challenge_scalar(tags::GKR_BATCH);
        let s = Summand::Two { lambda };
        let rho = h.rounds(s, &mut t, &r, &proof.layers[2].rounds, &mut compared);
        let child = |p: &MultilinearPoly, b: u64| {
            let mut point = rho.clone();
            point.push(Fr::from_u64(b));
            p.evaluate(&point)
        };
        let claims = vec![
            child(&h.abm, 0),
            child(&h.abm, 1),
            child(&h.fingerprint3, 0),
            child(&h.fingerprint3, 1),
        ];
        assert_eq!(proof.layers[2].final_evals, claims, "the child claims");
        t.append_scalars(tags::GKR_LAYER_CLAIMS, &claims);
        let mut p = rho;
        p.push(t.challenge_scalar(tags::GKR_CHILD));

        // Transition 1.
        let lambda = t.challenge_scalar(tags::GKR_BATCH);
        let s = Summand::One { lambda };
        let rho = h.rounds(s, &mut t, &p, &proof.layers[1].rounds, &mut compared);
        let claims = vec![
            h.ab.evaluate(&rho),
            h.fingerprint.evaluate(&rho),
            h.masked_m.evaluate(&rho),
        ];
        assert_eq!(proof.layers[1].final_evals, claims, "layer 1's claims");
        t.append_scalars(tags::GKR_LAYER_CLAIMS, &claims);

        // Transition 0.
        let lambda = t.challenge_scalar(tags::GKR_BATCH);
        let s = Summand::Zero { lambda, gamma };
        let rho = h.rounds(s, &mut t, &rho, &proof.layers[0].rounds, &mut compared);
        let claims: Vec<Fr> = h.base.iter().map(|c| c.evaluate(&rho)).collect();
        assert_eq!(proof.layers[0].final_evals, claims, "the base claims");

        assert_eq!(compared, 4 * (3 + 4 + 4), "every node of every round");
    }
}

/// The oracle can fail: one bumped coefficient of one round disagrees with the
/// definition at every node but `X = 0`.
#[test]
fn the_oracle_rejects_a_perturbed_round() {
    let (cols, proof, mut t, gamma) = prove_toy(0x5313_1300);
    let h = hand(&cols, gamma);
    let r = h.output_point(&mut t);
    let s = Summand::Two {
        lambda: t.challenge_scalar(tags::GKR_BATCH),
    };
    assert_eq!(
        cubic_at(&proof.layers[2].rounds[0], Fr::from_u64(2)),
        h.naive(s, &r, &[], Fr::from_u64(2)),
        "the unperturbed round matches"
    );
    let mut broken = proof.layers[2].rounds[0];
    broken[1] += Fr::ONE;
    let mismatches = (0..4u64)
        .filter(|&node| {
            let x = Fr::from_u64(node);
            cubic_at(&broken, x) != h.naive(s, &r, &[], x)
        })
        .count();
    assert_eq!(mismatches, 3, "a bumped X coefficient agrees only at X = 0");
}
