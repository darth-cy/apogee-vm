#![no_std]
//! Gate-based zerocheck: prove that a degree-≤2 formula over multilinear
//! columns vanishes on the whole boolean hypercube.
//!
//! # What is proven
//!
//! A [`Gate`] `G` is a sum of terms `coef * x_a * x_b`, where `x_a` and `x_b`
//! name input columns and the second factor is optional. Every column is a
//! multilinear polynomial in the same `n` variables, so `G` has degree at most
//! **2 in each variable** — the ceiling the master prompt fixes.
//!
//! The zerocheck claim is `G(y) = 0 for every y in {0,1}^n`. It is discharged
//! as the sumcheck
//!
//! ```text
//! 0 = sum_{y in {0,1}^n} eq(r, y) * G(y)
//! ```
//!
//! for `r` drawn from the transcript after the witness is bound to it. `eq`
//! is multilinear, so `eq * G` has degree at most 3 per variable and a round
//! polynomial is a **cubic: exactly 4 coefficients, always**. If some `G(y)`
//! is nonzero the sum is a nonzero polynomial in `r` of degree `n`, so it
//! vanishes for at most `n / |Fr|` of the `r` a transcript can produce.
//!
//! # The transcript script (frozen)
//!
//! Prover and verifier drive the transcript with the same typed messages in the
//! same order; no challenge is ever passed out of band.
//!
//! 1. The caller absorbs the witness digest — [`witness_digest`] on the prover
//!    side, the scalar it was handed on the verifier side — through
//!    [`absorb_witness_digest`]. Everything after this point is bound to the
//!    columns.
//! 2. `n` eq-randomizers `r`, each a `SUMCHECK_CHALLENGE`.
//! 3. Per round `i`: the 4 coefficients as one `SUMCHECK_ROUND` message, then
//!    one `SUMCHECK_CHALLENGE`. The challenge binds **variable `i`**, so
//!    [`SumcheckClaim::point`]`[j]` is the value bound to variable `j`.
//! 4. `final_evals` as one `SUMCHECK_FINAL_EVALS` message, absorbed by both
//!    sides so that any later challenge is bound to them.
//!
//! # What this does not do
//!
//! Nothing here checks `final_evals` against a commitment: the Mercury PCS
//! arrives in a later stage. [`verify_zerocheck`] returns the
//! [`SumcheckClaim`] and the caller discharges the openings.

extern crate alloc;

use alloc::vec::Vec;

use constants::transcript_tags;
use field::Fr;
use poly::{eq_eval, eq_table, MultilinearPoly, PolyBacking};
use transcript::Transcript;

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

/// The identifier of a polynomial.
///
/// In production proving there is one registry mapping addresses to columns;
/// a gate names its inputs by address rather than holding them. This stage has
/// no registry — [`prove_zerocheck`] takes the columns positionally, in the
/// gate's declaration order — so the address is carried, checked for
/// duplicates, and otherwise inert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolyAddress(pub u32);

/// One term of a gate formula: `coef * inputs[a] * inputs[b]`, with `b`
/// optional. `a` and `b` index the gate's declared inputs, and `b == Some(a)`
/// is how a square is written.
///
/// A term names **at most two factors**, so no formula this type can express
/// exceeds degree 2. That is what enforces the degree ceiling, and it is
/// enforced by construction rather than by an assertion that could be skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GateTerm {
    pub coef: Fr,
    pub a: usize,
    pub b: Option<usize>,
}

/// Why a gate could not be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateError {
    /// A gate with no inputs has no variables, so nothing to sum over.
    NoInputs,
    /// The same address was declared twice. Two slots for one column is a
    /// construction mistake; a formula that uses a column twice repeats the
    /// *index* in its terms instead.
    DuplicateInput { input: usize },
    /// `term`'s factor names input `index`, which was never declared.
    TermIndexOutOfRange { term: usize, index: usize },
}

/// A degree-≤2 formula over named multilinear inputs.
#[derive(Clone, Debug)]
pub struct Gate {
    inputs: Vec<PolyAddress>,
    terms: Vec<GateTerm>,
}

impl Gate {
    /// Declare a gate. `inputs` fixes the order every later slice is read in:
    /// the columns handed to [`prove_zerocheck`], the values handed to
    /// [`Gate::evaluate`], and [`SumcheckProof::final_evals`].
    ///
    /// An empty `terms` list is legal and means the zero formula.
    pub fn new(inputs: &[&PolyAddress], terms: Vec<GateTerm>) -> Result<Gate, GateError> {
        if inputs.is_empty() {
            return Err(GateError::NoInputs);
        }
        for i in 0..inputs.len() {
            for j in 0..i {
                if inputs[i] == inputs[j] {
                    return Err(GateError::DuplicateInput { input: i });
                }
            }
        }
        for (t, term) in terms.iter().enumerate() {
            for index in [Some(term.a), term.b].into_iter().flatten() {
                if index >= inputs.len() {
                    return Err(GateError::TermIndexOutOfRange { term: t, index });
                }
            }
        }
        Ok(Gate {
            inputs: inputs.iter().map(|a| **a).collect(),
            terms,
        })
    }

    /// The number of declared inputs. Deliberately not public: the frozen API
    /// is the stage's list, and a caller building a gate already knows its
    /// arity.
    fn arity(&self) -> usize {
        self.inputs.len()
    }

    /// The formula at one point. `input_values` is in declaration order.
    pub fn evaluate(&self, input_values: &[Fr]) -> Fr {
        assert_eq!(
            input_values.len(),
            self.inputs.len(),
            "Gate::evaluate: {} values for a gate with {} inputs",
            input_values.len(),
            self.inputs.len()
        );
        let mut acc = Fr::ZERO;
        for term in &self.terms {
            let mut v = term.coef * input_values[term.a];
            if let Some(b) = term.b {
                v *= input_values[b];
            }
            acc += v;
        }
        acc
    }
}

// ---------------------------------------------------------------------------
// Proof shape
// ---------------------------------------------------------------------------

/// A zerocheck proof. Its shape is fixed by `n` and the gate's arity alone:
/// one cubic per variable, always 4 coefficients, and one claimed evaluation
/// per input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SumcheckProof {
    /// Round `i`'s cubic in **ascending** coefficient order:
    /// `g(X) = c[0] + c[1] X + c[2] X^2 + c[3] X^3`.
    pub rounds: Vec<[Fr; 4]>,
    /// Each input polynomial's claimed value at the fully bound point,
    /// in gate-input declaration order.
    pub final_evals: Vec<Fr>,
}

/// What a verified zerocheck leaves for the caller to discharge: the point the
/// rounds bound, and the evaluations claimed there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SumcheckClaim {
    /// `point[j]` is the challenge bound to variable `j`.
    pub point: Vec<Fr>,
    pub final_evals: Vec<Fr>,
}

/// Why a zerocheck was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SumcheckError {
    /// The proof does not carry one round per variable.
    RoundCountMismatch { expected: usize, found: usize },
    /// The proof does not carry one final evaluation per gate input.
    FinalEvalCountMismatch { expected: usize, found: usize },
    /// `g(0) + g(1)` did not equal the claim this round inherited — zero in
    /// round 0, which is the zerocheck itself, and the previous round's cubic
    /// at its challenge thereafter.
    RoundSumMismatch { round: usize },
    /// The last round's claim did not equal `eq(r, point) * G(final_evals)`.
    FinalEvalMismatch,
}

// ---------------------------------------------------------------------------
// Witness digest
// ---------------------------------------------------------------------------

/// The binding digest of a witness's columns, squeezed from a sponge of its
/// own so that the protocol transcript never sees the columns.
///
/// The sponge absorbs the column count and the variable count as one framed
/// message, then one length-delimited message per column — columns in
/// gate-input declaration order, cells in hypercube index order, each lifted to
/// `Fr`. The header pins both counts, so the absorbed stream determines the
/// witness. The squeeze is raw: the framing tag names scalar messages, and
/// drawing a challenge under it would be the same tag in two kinds.
///
/// Panics unless there is at least one column and every column has the same
/// number of variables.
pub fn witness_digest(columns: &[MultilinearPoly]) -> Fr {
    assert!(
        !columns.is_empty(),
        "witness_digest: a witness has at least one column"
    );
    let n_vars = columns[0].num_vars();
    for (k, c) in columns.iter().enumerate() {
        assert_eq!(
            c.num_vars(),
            n_vars,
            "witness_digest: column {k} has {} variables, column 0 has {n_vars}",
            c.num_vars()
        );
    }

    let mut sponge = Transcript::new();
    sponge.append_scalars(
        transcript_tags::WITNESS_DIGEST,
        &[
            Fr::from_u64(columns.len() as u64),
            Fr::from_u64(n_vars as u64),
        ],
    );
    for c in columns {
        let cells: Vec<Fr> = (0..c.len()).map(|i| c.get(i)).collect();
        sponge.append_scalars(transcript_tags::WITNESS_DIGEST, &cells);
    }
    sponge.sample()
}

/// Bind a witness digest to the protocol transcript. Both sides call this —
/// the prover with [`witness_digest`] of its columns, the verifier with the
/// scalar it was handed — so the two cannot disagree about the tag or the
/// framing.
pub fn absorb_witness_digest(t: &mut Transcript, digest: Fr) {
    t.append_scalar(transcript_tags::WITNESS_DIGEST, digest);
}

// ---------------------------------------------------------------------------
// Cubic helpers
// ---------------------------------------------------------------------------

/// `[1/2, 1/3, 1/6]`: everything [`interpolate_cubic`] needs, derived once per
/// proof rather than transcribed, so there is no literal to get wrong. Three
/// inversions per proof is nothing beside the round loop.
fn interpolation_constants() -> [Fr; 3] {
    let inv = |k: u64| {
        Fr::from_u64(k)
            .inverse()
            .expect("2, 3 and 6 are invertible in Fr")
    };
    [inv(2), inv(3), inv(6)]
}

/// The ascending coefficients of the unique cubic through `(0, v[0])`,
/// `(1, v[1])`, `(2, v[2])`, `(3, v[3])`.
///
/// Newton's forward-difference form on the nodes `0, 1, 2, 3`,
///
/// ```text
/// g(X) = v0 + d1 X + d2 X(X-1)/2 + d3 X(X-1)(X-2)/6
/// ```
///
/// expanded once — `X(X-1)/2 = (X^2 - X)/2` and
/// `X(X-1)(X-2)/6 = (X^3 - 3X^2 + 2X)/6` — which gives
/// `c0 = v0`, `c1 = d1 - d2/2 + d3/3`, `c2 = d2/2 - d3/2`, `c3 = d3/6`.
fn interpolate_cubic(v: &[Fr; 4], c: &[Fr; 3]) -> [Fr; 4] {
    let [inv2, inv3, inv6] = *c;
    let d1 = v[1] - v[0];
    let d2 = (v[2] - v[1]) - d1;
    let d3 = ((v[3] - v[2]) - (v[2] - v[1])) - d2;
    [
        v[0],
        d1 - d2 * inv2 + d3 * inv3,
        (d2 - d3) * inv2,
        d3 * inv6,
    ]
}

/// Horner evaluation of an ascending-coefficient cubic.
fn eval_cubic(g: &[Fr; 4], x: Fr) -> Fr {
    ((g[3] * x + g[2]) * x + g[1]) * x + g[0]
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

/// Round `i`'s cubic at `X = 0, 1, 2, 3`.
///
/// The current variable is variable 0 of every live table, so the pair
/// `(2j, 2j+1)` holds that variable's values at `X = 0` and `X = 1` and its
/// line is `lo + X * (hi - lo)`. Walking `X` upwards by one is therefore one
/// addition of the step per column, which is why no multiplication by the node
/// appears below. The four point-evaluations accumulate across the hypercube in
/// a single pass over `j`.
fn round_evaluations(gate: &Gate, polys: &[MultilinearPoly], eq: &MultilinearPoly) -> [Fr; 4] {
    let half = eq.len() / 2;
    let mut acc = [Fr::ZERO; 4];
    let mut cur: Vec<Fr> = (0..polys.len()).map(|_| Fr::ZERO).collect();
    let mut step: Vec<Fr> = cur.clone();

    for j in 0..half {
        for (k, p) in polys.iter().enumerate() {
            let lo = p.get(2 * j);
            cur[k] = lo;
            step[k] = p.get(2 * j + 1) - lo;
        }
        let eq_lo = eq.get(2 * j);
        let eq_step = eq.get(2 * j + 1) - eq_lo;
        let mut eq_cur = eq_lo;

        for a in acc.iter_mut() {
            *a += eq_cur * gate.evaluate(&cur);
            eq_cur += eq_step;
            for (c, s) in cur.iter_mut().zip(step.iter()) {
                *c += *s;
            }
        }
    }
    acc
}

/// Prove that `gate` vanishes on the whole hypercube of `polys`.
///
/// `polys` is consumed in place: every column is left fully bound to the
/// challenge point, which is where `final_evals` are read from. The caller must
/// already have absorbed the witness digest into `t` — see the module docs.
///
/// Panics unless there is one column per gate input and every column has the
/// same number of variables.
pub fn prove_zerocheck(
    gate: &Gate,
    polys: &mut [MultilinearPoly],
    t: &mut Transcript,
) -> SumcheckProof {
    assert_eq!(
        polys.len(),
        gate.arity(),
        "prove_zerocheck: {} columns for a gate with {} inputs",
        polys.len(),
        gate.arity()
    );
    let n = polys[0].num_vars();
    for (k, p) in polys.iter().enumerate() {
        assert_eq!(
            p.num_vars(),
            n,
            "prove_zerocheck: column {k} has {} variables, column 0 has {n}",
            p.num_vars()
        );
    }

    let r: Vec<Fr> = (0..n)
        .map(|_| t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE))
        .collect();
    // Built once and bound each round alongside the witness, rather than
    // rebuilt per round.
    let mut eq = MultilinearPoly::new(PolyBacking::Fr(eq_table(&r)));

    let constants = interpolation_constants();
    let mut rounds: Vec<[Fr; 4]> = Vec::new();
    for _ in 0..n {
        let coefficients = interpolate_cubic(&round_evaluations(gate, polys, &eq), &constants);
        t.append_scalars(transcript_tags::SUMCHECK_ROUND, &coefficients);
        rounds.push(coefficients);

        let c = t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE);
        for p in polys.iter_mut() {
            p.bind(c);
        }
        eq.bind(c);
    }

    let final_evals: Vec<Fr> = polys.iter().map(|p| p.get(0)).collect();
    t.append_scalars(transcript_tags::SUMCHECK_FINAL_EVALS, &final_evals);
    SumcheckProof {
        rounds,
        final_evals,
    }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Check a zerocheck proof, returning the claim its caller must discharge.
///
/// `t` must have been driven exactly as the prover's was up to this point —
/// same typed messages, same order, the witness digest included.
pub fn verify_zerocheck(
    gate: &Gate,
    n_vars: usize,
    proof: &SumcheckProof,
    t: &mut Transcript,
) -> Result<SumcheckClaim, SumcheckError> {
    if proof.rounds.len() != n_vars {
        return Err(SumcheckError::RoundCountMismatch {
            expected: n_vars,
            found: proof.rounds.len(),
        });
    }
    if proof.final_evals.len() != gate.arity() {
        return Err(SumcheckError::FinalEvalCountMismatch {
            expected: gate.arity(),
            found: proof.final_evals.len(),
        });
    }

    let r: Vec<Fr> = (0..n_vars)
        .map(|_| t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE))
        .collect();

    // The zerocheck itself: round 0 inherits the claim that the sum is zero.
    let mut claim = Fr::ZERO;
    let mut point: Vec<Fr> = Vec::new();
    for (round, g) in proof.rounds.iter().enumerate() {
        if eval_cubic(g, Fr::ZERO) + eval_cubic(g, Fr::ONE) != claim {
            return Err(SumcheckError::RoundSumMismatch { round });
        }
        t.append_scalars(transcript_tags::SUMCHECK_ROUND, g);
        let c = t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE);
        claim = eval_cubic(g, c);
        point.push(c);
    }

    // Absorbed before the check, and before any challenge a later stage draws:
    // the values are never trusted silently.
    t.append_scalars(transcript_tags::SUMCHECK_FINAL_EVALS, &proof.final_evals);
    if eq_eval(&r, &point) * gate.evaluate(&proof.final_evals) != claim {
        return Err(SumcheckError::FinalEvalMismatch);
    }

    Ok(SumcheckClaim {
        point,
        final_evals: proof.final_evals.clone(),
    })
}
