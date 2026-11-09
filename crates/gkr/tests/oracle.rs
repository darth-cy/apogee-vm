//! Every round polynomial of every transition, recomputed from the definition.
//!
//! Nothing here calls the engine's kernel, `gate_values`, the prover's round
//! machinery or its interpolation. The toy's layers are rebuilt by hand from
//! its description, each transition's summand is written out as the toy's
//! formulas, and each round's cubic is recomputed at its four nodes as a direct
//! sum over the remaining cube of `eq(p, point) · S(point)`, every column read
//! through `MultilinearPoly::evaluate`. The challenges are replayed from the
//! schedule of `docs/spec/gkr.md` §5.2, a second transcription of it.

mod common;

use common::{bind, toy, toy_base, toy_columns, ToyColumns, TOY_ROWS};
use constants::transcript_tags as tags;
use field::{Fp, Fp2};
use gkr::{forward, prove, GkrProof};
use poly::{eq_eval, MultilinearPoly, PolyBacking};
use transcript::Transcript;

fn poly(values: Vec<Fp2>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fp2(values))
}

fn fr(v: u32) -> Fp2 {
    ext(v as u64)
}

/// An integer, embedded in `Fp2`.
fn ext(v: u64) -> Fp2 {
    Fp::from_u64(v).into()
}

fn bits(i: usize, n: usize) -> Vec<Fp2> {
    (0..n).map(|j| ext(((i >> j) & 1) as u64)).collect()
}

fn cubic_at(g: &[Fp2; 4], x: Fp2) -> Fp2 {
    g[0] + x * (g[1] + x * (g[2] + x * g[3]))
}

fn table(p: &MultilinearPoly) -> Vec<Fp2> {
    (0..p.len()).map(|i| p.get(i)).collect()
}

/// The toy, by hand: the description in `constraints/tests/common/toy.rs`'s
/// module docs, not its code.
struct Hand {
    base: [MultilinearPoly; 6], // m a b c e s, layout order
    ab: MultilinearPoly,
    fingerprint: MultilinearPoly,
    masked_m: MultilinearPoly,
    /// The `abm` tree, level by level: level `j` is layer `2 + j`'s first
    /// column, level 0 `abm` itself and level 4 its root.
    abm: Vec<MultilinearPoly>,
    /// The `fingerprint3` tree, likewise: layer `2 + j`'s second column.
    fingerprint3: Vec<MultilinearPoly>,
}

/// `column` and every level of its product tree above it: level `j + 1`'s row
/// `i` is level `j`'s rows `i` and `i + half` multiplied, the child bit being
/// the highest variable, down to one row.
fn tree(column: Vec<Fp2>) -> Vec<MultilinearPoly> {
    let mut levels = vec![column];
    while let Some(below) = levels.last().filter(|level| level.len() > 1) {
        let half = below.len() / 2;
        let above: Vec<Fp2> = (0..half).map(|i| below[i] * below[i + half]).collect();
        levels.push(above);
    }
    levels.into_iter().map(poly).collect()
}

fn hand(cols: &ToyColumns, gamma: Fp2) -> Hand {
    let col = |v: &[u32]| -> Vec<Fp2> { v.iter().map(|x| fr(*x)).collect() };
    let (m, a, b, c, e, s) = (
        col(&cols.m),
        col(&cols.a),
        col(&cols.b),
        col(&cols.c),
        col(&cols.e),
        col(&cols.s),
    );
    let rows = 0..TOY_ROWS;
    let ab: Vec<Fp2> = rows.clone().map(|y| a[y] * b[y]).collect();
    let fingerprint: Vec<Fp2> = rows
        .clone()
        .map(|y| (gamma * a[y] + ext(y as u64)) * c[y])
        .collect();
    let masked_m: Vec<Fp2> = rows
        .clone()
        .map(|y| m[y] * s[y] + Fp2::ONE - s[y])
        .collect();
    let abm: Vec<Fp2> = rows.clone().map(|y| ab[y] * masked_m[y]).collect();
    let fingerprint3: Vec<Fp2> = rows.map(|y| fingerprint[y] + ext(3)).collect();
    Hand {
        abm: tree(abm),
        fingerprint3: tree(fingerprint3),
        base: [poly(m), poly(a), poly(b), poly(c), poly(e), poly(s)],
        ab: poly(ab),
        fingerprint: poly(fingerprint),
        masked_m: poly(masked_m),
    }
}

/// One transition's summand, with the challenges it is weighted by.
#[derive(Clone, Copy)]
enum Summand {
    /// Transition `2 + level`, halving the trees' level `level`:
    /// `abm(x,0)·abm(x,1) + λ·fp3(x,0)·fp3(x,1)`.
    Halving { level: usize, lambda: Fp2 },
    /// Transition 1: `ab·masked_m + λ·(fingerprint + 3)`.
    One { lambda: Fp2 },
    /// Transition 0: `a·b + λ·(γ·a + row)·c + λ²·(m·s + 1 − s) + λ³·(e − a)·s`.
    Zero { lambda: Fp2, gamma: Fp2 },
}

impl Hand {
    /// A halving transition's four claims at `y`: level `level` of the `abm`
    /// tree at `(y, 0)` and `(y, 1)`, then the `fingerprint3` tree's.
    fn children(&self, level: usize, y: &[Fp2]) -> Vec<Fp2> {
        let child = |column: &MultilinearPoly, b: u64| {
            let mut point = y.to_vec();
            point.push(ext(b));
            column.evaluate(&point)
        };
        let (abm, fp3) = (&self.abm[level], &self.fingerprint3[level]);
        vec![child(abm, 0), child(abm, 1), child(fp3, 0), child(fp3, 1)]
    }

    fn summand(&self, s: Summand, y: &[Fp2]) -> Fp2 {
        match s {
            Summand::Halving { level, lambda } => {
                let c = self.children(level, y);
                c[0] * c[1] + lambda * c[2] * c[3]
            }
            Summand::One { lambda } => {
                self.ab.evaluate(y) * self.masked_m.evaluate(y)
                    + lambda * (self.fingerprint.evaluate(y) + ext(3))
            }
            Summand::Zero { lambda, gamma } => {
                let v: Vec<Fp2> = self.base.iter().map(|c| c.evaluate(y)).collect();
                let (m, a, b, c, e, s) = (v[0], v[1], v[2], v[3], v[4], v[5]);
                // `row`'s multilinear extension, Σ 2^j·y_j, written out here.
                let row = y
                    .iter()
                    .enumerate()
                    .fold(Fp2::ZERO, |acc, (j, yj)| acc + ext(1 << j) * *yj);
                let l2 = lambda * lambda;
                a * b
                    + lambda * (gamma * a + row) * c
                    + l2 * (m * s + Fp2::ONE - s)
                    + l2 * lambda * (e - a) * s
            }
        }
    }

    /// `Σ_rest eq(p, (bound, X, rest)) · S(bound, X, rest)`.
    fn naive(&self, s: Summand, p: &[Fp2], bound: &[Fp2], x: Fp2) -> Fp2 {
        let rest = p.len() - bound.len() - 1;
        (0..1usize << rest).fold(Fp2::ZERO, |acc, i| {
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
        p: &[Fp2],
        proof_rounds: &[[Fp2; 4]],
        compared: &mut usize,
    ) -> Vec<Fp2> {
        let mut bound: Vec<Fp2> = Vec::new();
        for (i, g) in proof_rounds.iter().enumerate() {
            for node in 0..4u64 {
                let x = ext(node);
                assert_eq!(
                    cubic_at(g, x),
                    self.naive(s, p, &bound, x),
                    "round {i} at X = {node}"
                );
                *compared += 1;
            }
            t.append_ext(tags::SUMCHECK_ROUND, g);
            bound.push(t.challenge(tags::SUMCHECK_CHALLENGE));
        }
        bound
    }

    /// O1, replayed: the output map is `L{6}[1], L{6}[0]`, the two roots. The
    /// top has no variables, so the point they are claimed at is empty.
    fn absorb_outputs(&self, t: &mut Transcript) {
        let mut outputs = table(&self.fingerprint3[4]);
        outputs.extend(table(&self.abm[4]));
        t.append_ext(tags::GKR_OUTPUTS, &outputs);
    }
}

/// An honest proof of the toy, and a fresh transcript bound exactly as the
/// prover's was, to replay the schedule on.
fn prove_toy(seed: u64) -> (ToyColumns, GkrProof, Transcript, Fp2) {
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
        h.absorb_outputs(&mut t);
        let mut p: Vec<Fp2> = Vec::new();

        // Transitions 5 down to 2, halving the trees' levels 3 down to 0.
        for k in (2..6).rev() {
            let level = k - 2;
            let lambda = t.challenge(tags::GKR_BATCH);
            let s = Summand::Halving { level, lambda };
            let rho = h.rounds(s, &mut t, &p, &proof.layers[k].rounds, &mut compared);
            let claims = h.children(level, &rho);
            assert_eq!(
                proof.layers[k].final_evals, claims,
                "transition {k}'s child claims"
            );
            t.append_ext(tags::GKR_LAYER_CLAIMS, &claims);
            p = rho;
            p.push(t.challenge(tags::GKR_CHILD));
        }

        // Transition 1.
        let lambda = t.challenge(tags::GKR_BATCH);
        let s = Summand::One { lambda };
        let rho = h.rounds(s, &mut t, &p, &proof.layers[1].rounds, &mut compared);
        let claims = vec![
            h.ab.evaluate(&rho),
            h.fingerprint.evaluate(&rho),
            h.masked_m.evaluate(&rho),
        ];
        assert_eq!(proof.layers[1].final_evals, claims, "layer 1's claims");
        t.append_ext(tags::GKR_LAYER_CLAIMS, &claims);

        // Transition 0.
        let lambda = t.challenge(tags::GKR_BATCH);
        let s = Summand::Zero { lambda, gamma };
        let rho = h.rounds(s, &mut t, &rho, &proof.layers[0].rounds, &mut compared);
        let claims: Vec<Fp2> = h.base.iter().map(|c| c.evaluate(&rho)).collect();
        assert_eq!(proof.layers[0].final_evals, claims, "the base claims");

        // The halving transitions' 0, 1, 2 and 3 rounds, then 4 and 4.
        assert_eq!(
            compared,
            4 * (1 + 2 + 3 + 4 + 4),
            "every node of every round"
        );
    }
}

/// The oracle can fail: one bumped coefficient of one round disagrees with the
/// definition at every node but `X = 0`. The round is transition 4's one,
/// reached through O1 and transition 5, which has none.
#[test]
fn the_oracle_rejects_a_perturbed_round() {
    let (cols, proof, mut t, gamma) = prove_toy(0x5313_1300);
    let h = hand(&cols, gamma);
    h.absorb_outputs(&mut t);
    t.challenge(tags::GKR_BATCH);
    t.append_ext(tags::GKR_LAYER_CLAIMS, &h.children(3, &[]));
    let p = [t.challenge(tags::GKR_CHILD)];
    let s = Summand::Halving {
        level: 2,
        lambda: t.challenge(tags::GKR_BATCH),
    };
    assert_eq!(
        cubic_at(&proof.layers[4].rounds[0], ext(2)),
        h.naive(s, &p, &[], ext(2)),
        "the unperturbed round matches"
    );
    let mut broken = proof.layers[4].rounds[0];
    broken[1] += Fp2::ONE;
    let mismatches = (0..4u64)
        .filter(|&node| {
            let x = ext(node);
            cubic_at(&broken, x) != h.naive(s, &p, &[], x)
        })
        .count();
    assert_eq!(mismatches, 3, "a bumped X coefficient agrees only at X = 0");
}
