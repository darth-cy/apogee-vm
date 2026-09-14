#![no_std]
//! The verifier half of the GKR engine: the gate kernel every pass evaluates,
//! the layer sumcheck's verifier, and `verify`, which reduces a circuit's
//! output claims to claims about its committed base columns.
//!
//! `docs/spec/gkr.md` §5 is normative. `#![no_std]` + `alloc`: the recursion
//! guest links this crate. `crates/gkr` is the prover half and re-exports
//! everything here.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use constants::transcript_tags;
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};
use field::Fr;
use poly::{eq_eval, MultilinearPoly};
use transcript::Transcript;

pub use sumcheck::SumcheckProof;

// ---------------------------------------------------------------------------
// The containers
// ---------------------------------------------------------------------------

/// Named external challenge slots, `slot -> Fr`, with slots from
/// `constants::challenge_slot`. The caller supplies them on both sides; a
/// verifier takes its values from its own transcript replay or global phase,
/// never from a proof. Open: later stages add slots, not fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalChallenges {
    /// Sorted by slot, one entry per slot.
    slots: Vec<(u32, Fr)>,
}

// A `Default` would be a second name for `new` with no caller.
#[allow(clippy::new_without_default)]
impl ExternalChallenges {
    pub fn new() -> ExternalChallenges {
        ExternalChallenges { slots: Vec::new() }
    }

    /// Set `slot`. Panics if it is already set: a slot has one value.
    pub fn insert(&mut self, slot: u32, value: Fr) {
        match self.slots.binary_search_by_key(&slot, |(s, _)| *s) {
            Ok(_) => panic!("ExternalChallenges::insert: slot {slot} is already set"),
            Err(at) => self.slots.insert(at, (slot, value)),
        }
    }

    pub fn get(&self, slot: u32) -> Option<Fr> {
        self.slots
            .binary_search_by_key(&slot, |(s, _)| *s)
            .ok()
            .map(|i| self.slots[i].1)
    }
}

/// What the verifier is told the top layer holds: one table per output-map
/// entry, in output-map order. A tree root is a table of one value.
#[derive(Clone, Debug)]
pub struct OutputClaims {
    pub tables: Vec<MultilinearPoly>,
}

/// A claim about a committed base column, left for the caller to discharge.
/// `point[j]` is the value bound to variable `j`, so it is exactly what
/// `MultilinearPoly::evaluate` and a Mercury opening take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseClaim {
    pub address: PolyAddress,
    pub point: Vec<Fr>,
    pub value: Fr,
}

/// One layer transition's sumcheck per gate list, indexed by gate list:
/// `layers[k].rounds` binds layer `k + 1`'s variables and
/// `layers[k].final_evals` is the claims it leaves on layer `k`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GkrProof {
    pub layers: Vec<SumcheckProof>,
}

/// Why a proof was rejected. `docs/spec/gkr.md` §5.5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GkrError {
    /// A gate names a challenge slot the caller did not supply.
    MissingChallenge { slot: u32 },
    /// `OutputClaims` does not match the output map in count or variables.
    OutputShape,
    /// Transition `layer` has the wrong round or claim count; `layer` equal to
    /// the circuit's depth means the proof has the wrong number of layers.
    ProofShape { layer: usize },
    /// A round or the final check of transition `layer` failed.
    LayerInconsistency { layer: usize },
}

impl fmt::Display for GkrError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            GkrError::MissingChallenge { slot } => {
                write!(f, "no value for external challenge slot {slot}")
            }
            GkrError::OutputShape => write!(f, "the output claims do not match the output map"),
            GkrError::ProofShape { layer } => write!(f, "transition {layer} has the wrong shape"),
            GkrError::LayerInconsistency { layer } => {
                write!(f, "transition {layer} is inconsistent")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The kernel
// ---------------------------------------------------------------------------

/// A coefficient's value. Panics on a slot `challenges` does not hold; the
/// entry points check every slot first.
fn coefficient(c: Coeff, challenges: &ExternalChallenges) -> Fr {
    match c {
        Coeff::Literal(v) => v,
        Coeff::Challenge(slot) => challenges
            .get(slot)
            .unwrap_or_else(|| panic!("external challenge slot {slot} has no value")),
    }
}

/// **The** gate kernel: `gate` at one point, given one value per operand in
/// `GateDef::operands` order — two for `TreeProduct`, its input's children.
/// Every pass evaluates gates through this function and no other, so it is the
/// semantic authority: where a comment and this disagree, this wins.
pub fn eval_gate(gate: &GateDef, values: &[Fr], challenges: &ExternalChallenges) -> Fr {
    let arity = match gate {
        GateDef::TreeProduct { .. } => 2,
        _ => gate.operands().len(),
    };
    assert_eq!(
        values.len(),
        arity,
        "eval_gate: {} values for a gate reading {arity}",
        values.len()
    );
    let c = |x: &Coeff| coefficient(*x, challenges);
    let affine = |terms: &[(Coeff, PolyAddress)], constant: &Coeff, values: &[Fr]| {
        terms
            .iter()
            .zip(values)
            .fold(c(constant), |acc, ((k, _), v)| acc + c(k) * *v)
    };
    match gate {
        GateDef::Linear { terms, constant } => affine(terms, constant, values),
        GateDef::Product { coeff, .. } => c(coeff) * values[0] * values[1],
        GateDef::MaskIntoIdentity { .. } => values[0] * values[1] + Fr::ONE - values[1],
        GateDef::AffineProduct {
            left,
            left_constant,
            right,
            right_constant,
        } => {
            let t = left.len();
            affine(left, left_constant, &values[..t]) * affine(right, right_constant, &values[t..])
        }
        GateDef::TreeProduct { .. } => values[0] * values[1],
    }
}

/// A virtual table's value at row `row`.
pub fn virtual_at_row(kind: VirtualKind, row: usize) -> Fr {
    match kind {
        VirtualKind::RowIndex => Fr::from_u64(row as u64),
    }
}

/// A virtual table's closed form — its multilinear extension — at `point`.
pub fn virtual_at_point(kind: VirtualKind, point: &[Fr]) -> Fr {
    match kind {
        // Σ_j 2^j · y_j, by Horner from the highest variable.
        VirtualKind::RowIndex => point.iter().rev().fold(Fr::ZERO, |acc, y| acc + acc + *y),
    }
}

/// Every gate of list `k` at one point: one value per producing gate, then one
/// per enforcing gate, cached entries evaluated once and substituted.
///
/// `lower` holds one value per column of layer `k` — offset order, or layout
/// order at `k = 0` — and, for a halving list, `upper` the matching child-1
/// values (child 0 being `lower`); `upper` is empty otherwise. `virtuals` holds
/// one value per `artifact.virtuals` entry. The forward pass, the self-check
/// and both sides of the layer sumcheck all read gates through this function,
/// which reads them through [`eval_gate`].
pub fn gate_values(
    artifact: &CircuitArtifact,
    k: usize,
    lower: &[Fr],
    upper: &[Fr],
    virtuals: &[Fr],
    challenges: &ExternalChallenges,
) -> Vec<Fr> {
    let list = &artifact.layers[k];
    if list.halving {
        assert_eq!(
            upper.len(),
            lower.len(),
            "gate_values: halving gate list {k} needs both children of every column"
        );
        return list
            .producing
            .iter()
            .map(|entry| {
                let x = column_index(artifact, k, &entry.gate.operands()[0]);
                eval_gate(&entry.gate, &[lower[x], upper[x]], challenges)
            })
            .collect();
    }
    let read = |op: &PolyAddress, cached: &[Fr]| match *op {
        PolyAddress::Virtual(kind) => {
            let i = artifact
                .virtuals
                .iter()
                .position(|(v, _)| *v == kind)
                .expect("a validated artifact lists every virtual table it reads");
            virtuals[i]
        }
        PolyAddress::Cached { offset, .. } => cached[offset as usize],
        other => lower[column_index(artifact, k, &other)],
    };
    let eval = |gate: &GateDef, cached: &[Fr]| {
        let values: Vec<Fr> = gate.operands().iter().map(|op| read(op, cached)).collect();
        eval_gate(gate, &values, challenges)
    };
    let cached: Vec<Fr> = list.cached.iter().map(|e| eval(&e.gate, &[])).collect();
    list.producing
        .iter()
        .map(|e| &e.gate)
        .chain(list.enforcing.iter().map(|e| &e.gate))
        .map(|gate| eval(gate, &cached))
        .collect()
}

/// Transition `k`'s summand `S_k` at one point, `docs/spec/gkr.md` §5.3:
/// [`gate_values`] weighted by `weights`, which is `λ^0, λ^1, ...` — one per
/// producing gate, then one per enforcing gate.
pub fn summand(
    artifact: &CircuitArtifact,
    k: usize,
    weights: &[Fr],
    lower: &[Fr],
    upper: &[Fr],
    virtuals: &[Fr],
    challenges: &ExternalChallenges,
) -> Fr {
    let values = gate_values(artifact, k, lower, upper, virtuals, challenges);
    assert_eq!(
        values.len(),
        weights.len(),
        "summand: {} weights for {} gates",
        weights.len(),
        values.len()
    );
    values
        .iter()
        .zip(weights)
        .fold(Fr::ZERO, |acc, (v, w)| acc + *v * *w)
}

/// Where a column operand of gate list `k` sits in layer `k`'s value order.
fn column_index(artifact: &CircuitArtifact, k: usize, op: &PolyAddress) -> usize {
    let (m, w) = (artifact.memory.len(), artifact.witness.len());
    match *op {
        PolyAddress::Memory(i) => i as usize,
        PolyAddress::Witness(i) => m + i as usize,
        PolyAddress::Setup(i) => m + w + i as usize,
        PolyAddress::Inner { offset, .. } => offset as usize,
        other => panic!("gate list {k} of a validated artifact cannot read {other} as a column"),
    }
}

/// `λ^0, λ^1, ..., λ^{n-1}`.
pub fn powers(lambda: Fr, n: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(n);
    let mut acc = Fr::ONE;
    for _ in 0..n {
        out.push(acc);
        acc *= lambda;
    }
    out
}

/// The number of claim values transition `k` leaves on layer `k`: one per
/// column, or two per column for a halving list.
fn claim_count(artifact: &CircuitArtifact, k: usize) -> usize {
    let width = artifact.layer_width(k) as usize;
    if artifact.layers[k].halving {
        2 * width
    } else {
        width
    }
}

/// `MissingChallenge` for the first slot a gate names that `challenges` lacks.
pub fn check_challenges(
    artifact: &CircuitArtifact,
    challenges: &ExternalChallenges,
) -> Result<(), GkrError> {
    for list in &artifact.layers {
        let gates = list
            .cached
            .iter()
            .map(|e| &e.gate)
            .chain(list.producing.iter().map(|e| &e.gate))
            .chain(list.enforcing.iter().map(|e| &e.gate));
        for gate in gates {
            for c in gate.coefficients() {
                if let Coeff::Challenge(slot) = c {
                    if challenges.get(slot).is_none() {
                        return Err(GkrError::MissingChallenge { slot });
                    }
                }
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The layer sumcheck, verifier half
// ---------------------------------------------------------------------------

/// Horner evaluation of an ascending-coefficient cubic.
fn cubic(g: &[Fr; 4], x: Fr) -> Fr {
    ((g[3] * x + g[2]) * x + g[1]) * x + g[0]
}

/// The rounds of one layer sumcheck: each `g(0) + g(1)` against the claim it
/// inherits, each cubic absorbed as `SUMCHECK_ROUND` and followed by a
/// `SUMCHECK_CHALLENGE` binding the next variable. Returns the bound point and
/// the last claim, which the caller holds to `eq(p, point) · S(values)` — or
/// `None` at the first round that does not sum.
pub fn verify_sumcheck(claim: Fr, rounds: &[[Fr; 4]], t: &mut Transcript) -> Option<(Vec<Fr>, Fr)> {
    let mut claim = claim;
    let mut point = Vec::with_capacity(rounds.len());
    for g in rounds {
        if cubic(g, Fr::ZERO) + cubic(g, Fr::ONE) != claim {
            return None;
        }
        t.append_scalars(transcript_tags::SUMCHECK_ROUND, g);
        let r = t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE);
        claim = cubic(g, r);
        point.push(r);
    }
    Some((point, claim))
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

/// Reduce `outputs` to claims about the committed base columns, or reject.
///
/// `t` must already be bound to the base layer, exactly as the prover's was;
/// this function absorbs nothing of the base. It checks every shape and every
/// challenge slot before it touches `t`, and never panics on anything `proof`
/// or `outputs` carries. Panics if `artifact` breaks a law: the artifact is the
/// verifier's own, not the prover's.
pub fn verify(
    artifact: &CircuitArtifact,
    proof: &GkrProof,
    outputs: &OutputClaims,
    challenges: &ExternalChallenges,
    t: &mut Transcript,
) -> Result<Vec<BaseClaim>, GkrError> {
    if let Err(e) = artifact.validate() {
        panic!("gkr_verify::verify: the artifact is not a circuit: {e}");
    }
    check_challenges(artifact, challenges)?;

    let depth = artifact.depth();
    let top_vars = artifact.layer_vars(depth) as usize;
    if outputs.tables.len() != artifact.outputs.len()
        || outputs.tables.iter().any(|t| t.num_vars() != top_vars)
    {
        return Err(GkrError::OutputShape);
    }
    if proof.layers.len() != depth {
        return Err(GkrError::ProofShape { layer: depth });
    }
    for (k, layer) in proof.layers.iter().enumerate() {
        if layer.rounds.len() != artifact.layer_vars(k + 1) as usize
            || layer.final_evals.len() != claim_count(artifact, k)
        {
            return Err(GkrError::ProofShape { layer: k });
        }
    }

    // O1, O2: the outputs, then the point they are claimed at.
    let mut message: Vec<Fr> = Vec::new();
    for table in &outputs.tables {
        message.extend((0..table.len()).map(|i| table.get(i)));
    }
    t.append_scalars(transcript_tags::GKR_OUTPUTS, &message);
    let mut point: Vec<Fr> = (0..top_vars)
        .map(|_| t.challenge_scalar(transcript_tags::GKR_OUTPUT_POINT))
        .collect();
    let mut values = vec![Fr::ZERO; artifact.outputs.len()];
    for (table, out) in outputs.tables.iter().zip(&artifact.outputs) {
        if let PolyAddress::Inner { offset, .. } = *out {
            values[offset as usize] = table.evaluate(&point);
        }
    }

    for k in (0..depth).rev() {
        let list = &artifact.layers[k];
        let layer = &proof.layers[k];

        // L1: the batch, drawn after every claim it batches is absorbed.
        let lambda = t.challenge_scalar(transcript_tags::GKR_BATCH);
        let weights = powers(lambda, list.producing.len() + list.enforcing.len());
        let claim = values
            .iter()
            .zip(&weights)
            .fold(Fr::ZERO, |acc, (v, w)| acc + *v * *w);

        // L2, L3, and the final check.
        let (rho, last) = verify_sumcheck(claim, &layer.rounds, t)
            .ok_or(GkrError::LayerInconsistency { layer: k })?;
        t.append_scalars(transcript_tags::GKR_LAYER_CLAIMS, &layer.final_evals);
        let evals = &layer.final_evals;
        let s = if list.halving {
            let lower: Vec<Fr> = evals.iter().step_by(2).copied().collect();
            let upper: Vec<Fr> = evals.iter().skip(1).step_by(2).copied().collect();
            summand(artifact, k, &weights, &lower, &upper, &[], challenges)
        } else {
            let virtuals: Vec<Fr> = artifact
                .virtuals
                .iter()
                .map(|(kind, _)| virtual_at_point(*kind, &rho))
                .collect();
            summand(artifact, k, &weights, evals, &[], &virtuals, challenges)
        };
        if last != eq_eval(&point, &rho) * s {
            return Err(GkrError::LayerInconsistency { layer: k });
        }

        // L4: a halving transition's children meet on one line.
        if list.halving {
            let tau = t.challenge_scalar(transcript_tags::GKR_CHILD);
            values = evals
                .chunks(2)
                .map(|pair| pair[0] + tau * (pair[1] - pair[0]))
                .collect();
            point = rho;
            point.push(tau);
        } else {
            values = evals.clone();
            point = rho;
        }
    }

    Ok(artifact
        .committed()
        .into_iter()
        .zip(values)
        .map(|(address, value)| BaseClaim {
            address,
            point: point.clone(),
            value,
        })
        .collect())
}
