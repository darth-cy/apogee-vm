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
use constraints::ecrecover::schedule_data as sched_data;
use constraints::ecrecover::tables as sched;
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};
use field::Fr;
use poly::{eq_eval, MultilinearPoly};
use transcript::Transcript;

pub use sumcheck::SumcheckProof;

mod lookup;
mod memory;

pub use lookup::{channel_holds, insert_lookup_challenges};
pub use memory::{boundary_factors, reconciles, window_challenges, BoundaryFinals};

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

/// A coefficient's value. Panics on a slot `challenges` does not hold: `verify`
/// checks every slot first, and the prover leaves a missing slot to panic here.
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
    // A debugging aid, not a runtime check: one value per operand. Every caller
    // gathers exactly `operands()`'s count — `ResolvedList` from the resolved
    // operands, the checker from `operands()` itself — so it cannot fail there,
    // and this is the hottest path in the prover: every gate at every row and
    // at every sumcheck node. Too few values panic on an index or leave terms
    // out of a sum; `values` never comes from a proof.
    // let arity = match gate {
    //     GateDef::Linear { terms, .. } => terms.len(),
    //     GateDef::Product { .. }
    //     | GateDef::MaskIntoIdentity { .. }
    //     | GateDef::TreeProduct { .. } => 2,
    //     GateDef::TreeCross { .. } => 4,
    //     GateDef::AffineProduct { left, right, .. } => left.len() + right.len(),
    //     GateDef::Quadratic {
    //         linear, products, ..
    //     } => linear.len() + 2 * products.len(),
    // };
    // assert_eq!(
    //     values.len(),
    //     arity,
    //     "eval_gate: {} values for a gate reading {arity}",
    //     values.len()
    // );
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
        // p(·,0)·q(·,1) + p(·,1)·q(·,0), the operands being p then q and each
        // read at child 0 then child 1.
        GateDef::TreeCross { .. } => values[0] * values[3] + values[1] * values[2],
        GateDef::Quadratic {
            constant,
            linear,
            products,
        } => {
            let t = linear.len();
            products.iter().zip(values[t..].chunks_exact(2)).fold(
                affine(linear, constant, &values[..t]),
                |acc, ((b, _, _), yz)| acc + c(b) * yz[0] * yz[1],
            )
        }
    }
}

/// A virtual table's value at row `row`.
pub fn virtual_at_row(kind: VirtualKind, row: usize) -> Fr {
    match kind {
        VirtualKind::RowIndex => Fr::from_u64(row as u64),
        VirtualKind::RamLive => {
            if row >= 1 << constants::memory::RAM_LIVE_BIT {
                Fr::ONE
            } else {
                Fr::ZERO
            }
        }
        // The low `bits` bits of the row index: at a height of `2^bits` rows or
        // more the table is exactly `[0, 2^bits)`, each value once per
        // `2^bits` rows.
        VirtualKind::Range19 | VirtualKind::Range16 => {
            let bits = range_bits(kind);
            Fr::from_u64((row as u64) & ((1u64 << bits) - 1))
        }
        // Step-periodic: the row's step is its index within the invocation's
        // block, and the schedule is the same for every invocation
        // (`docs/spec/ecrecover.md` §6.2).
        VirtualKind::Schedule(k) => {
            let k = k as usize;
            let step = row % constants::ecrecover::ROWS_PER_INVOCATION;
            signed(sched::at(sched_data::SPARSE[k], sched::MODAL[k], step))
        }
    }
}

/// A schedule constant as a field element. Every one of them is a small signed
/// integer or a 64-bit limb, so the magnitude fits `u64` and the sign is the
/// only thing to carry.
fn signed(v: i128) -> Fr {
    let magnitude = Fr::from_u64(v.unsigned_abs() as u64);
    if v < 0 {
        -magnitude
    } else {
        magnitude
    }
}

/// `eq(y, i) = Π_j (y_j if bit j of i is set, else 1 − y_j)`, at one point of
/// the cube.
fn eq_at(point: &[Fr], i: usize) -> Fr {
    let mut acc = Fr::ONE;
    for (j, y) in point.iter().enumerate() {
        acc *= if (i >> j) & 1 == 1 { *y } else { Fr::ONE - *y };
    }
    acc
}

fn range_bits(kind: VirtualKind) -> u32 {
    match kind {
        VirtualKind::Range19 => 19,
        VirtualKind::Range16 => 16,
        other => panic!("{other:?} is not a range table"),
    }
}

/// A virtual table's closed form — its multilinear extension — at `point`.
pub fn virtual_at_point(kind: VirtualKind, point: &[Fr]) -> Fr {
    match kind {
        // Σ_j 2^j · y_j, by Horner from the highest variable.
        VirtualKind::RowIndex => point.iter().rev().fold(Fr::ZERO, |acc, y| acc + acc + *y),
        // 1 − Π_{j >= RAM_LIVE_BIT} (1 − y_j): on the cube, 0 exactly when every
        // bit from RAM_LIVE_BIT up is clear; over RAM_LIVE_BIT variables or
        // fewer the product is empty and the table is 0.
        VirtualKind::RamLive => {
            let high = &point[point.len().min(constants::memory::RAM_LIVE_BIT as usize)..];
            Fr::ONE - high.iter().fold(Fr::ONE, |acc, y| acc * (Fr::ONE - *y))
        }
        // Σ_{j < bits} 2^j · y_j, the same Horner over the low variables alone.
        VirtualKind::Range19 | VirtualKind::Range16 => {
            let low = &point[..point.len().min(range_bits(kind) as usize)];
            low.iter().rev().fold(Fr::ZERO, |acc, y| acc + acc + *y)
        }
        // `Σ_{i < 2^b} eq(y_0..y_{b−1}, i) · c_k[i]` over the low `b`
        // variables, `b = log2(ROWS_PER_INVOCATION)`, and nothing above them:
        // that independence is what "step-periodic" means.
        //
        // The table is stored offset by its modal value, and that costs
        // exactly one addition here rather than a second pass: `eq` sums to 1
        // over the whole cube, so
        //
        // ```text
        // Σ_i eq(y, i)·(MODAL + offset_i) = MODAL + Σ_i eq(y, i)·offset_i
        // ```
        //
        // and an entry equal to the mode has `offset_i = 0` and is not stored
        // at all. That is the whole of §6.2's saving: 24,882 stored pairs
        // against 163,840 dense.
        //
        // `eq` is evaluated per stored pair rather than tabulated over the
        // block. Every table here is far sparser than its 4,096 steps -- the
        // window columns are live on 172 and the frame columns on seven -- so
        // a 4,096-entry table would cost more than the pairs do, and it would
        // allocate.
        VirtualKind::Schedule(k) => {
            let k = k as usize;
            let bits = constants::ecrecover::ROWS_PER_INVOCATION.trailing_zeros() as usize;
            assert!(
                point.len() >= bits,
                "a schedule column needs the {bits} variables of an invocation block, and this                  circuit has {}; `family_circuit` refuses a height below the block",
                point.len()
            );
            let low = &point[..bits];
            let mut acc = signed(sched::MODAL[k]);
            for (step, offset) in sched_data::SPARSE[k] {
                acc += eq_at(low, *step as usize) * signed(*offset);
            }
            acc
        }
    }
}

/// Where one operand of a [`ResolvedList`] is read at a point.
#[derive(Clone, Copy, Debug)]
enum Source {
    /// `lower[i]`: a column of layer `k`, or child 0 of one.
    Lower(usize),
    /// `upper[i]`: child 1 of a column of layer `k`.
    Upper(usize),
    /// `virtuals[i]`.
    Virtual(usize),
    /// Cached entry `i`, evaluated at the same point.
    Cached(usize),
}

/// Gate list `k` with every operand resolved, once, to the index its value is
/// read at: a column of the lower layer, a child-1 value, a virtual table or a
/// cached entry. [`gate_values`] and [`summand`] go through it, and the prover
/// holds one per gate list per call, so every pass evaluates the same gates
/// through [`eval_gate`] in the same order.
///
/// Evaluating allocates nothing. The caller owns a scratch buffer from
/// [`ResolvedList::scratch`] — one per thread of work, reused point after point
/// — and at each point calls [`ResolvedList::cache`] before reading gates with
/// [`ResolvedList::gate`], or calls [`ResolvedList::summand`], which does both.
/// `lower`, `upper` and `virtuals` are as [`gate_values`] takes them.
///
/// It is public because the prover half is another crate; the verifier's
/// [`gate_values`] and [`summand`] are wrappers over it.
pub struct ResolvedList<'a> {
    challenges: &'a ExternalChallenges,
    /// The cached entries, then the producing gates, then the enforcing gates.
    gates: Vec<&'a GateDef>,
    /// Gate `i` reads `sources[bounds[i]..bounds[i + 1]]`, in [`eval_gate`]'s
    /// value order.
    sources: Vec<Source>,
    bounds: Vec<usize>,
    cached: usize,
    producing: usize,
    enforcing: usize,
    /// The cached values, then room for the widest gate's operands.
    scratch: usize,
}

impl<'a> ResolvedList<'a> {
    /// Resolve gate list `k` of `artifact`. A halving gate reads each of its
    /// operands at both children — column `x` gives `lower[x]` then
    /// `upper[x]`, in operand order — and a halving list's cached and
    /// enforcing lists are not read. Panics on an operand a validated artifact
    /// cannot hold.
    pub fn new(
        artifact: &'a CircuitArtifact,
        k: usize,
        challenges: &'a ExternalChallenges,
    ) -> ResolvedList<'a> {
        let list = &artifact.layers[k];
        let mut gates: Vec<&'a GateDef> = Vec::new();
        let mut sources: Vec<Source> = Vec::new();
        let mut bounds = vec![0];
        let (cached, enforcing) = if list.halving {
            for entry in &list.producing {
                gates.push(&entry.gate);
                for op in entry.gate.operands() {
                    let x = column_index(artifact, k, &op);
                    sources.extend([Source::Lower(x), Source::Upper(x)]);
                }
                bounds.push(sources.len());
            }
            (0, 0)
        } else {
            let resolve = |op: PolyAddress| match op {
                PolyAddress::Virtual(kind) => Source::Virtual(
                    artifact
                        .virtuals
                        .iter()
                        .position(|(v, _)| *v == kind)
                        .expect("a validated artifact lists every virtual table it reads"),
                ),
                PolyAddress::Cached { offset, .. } => Source::Cached(offset as usize),
                other => Source::Lower(column_index(artifact, k, &other)),
            };
            let all = list
                .cached
                .iter()
                .map(|e| &e.gate)
                .chain(list.producing.iter().map(|e| &e.gate))
                .chain(list.enforcing.iter().map(|e| &e.gate));
            for gate in all {
                gates.push(gate);
                sources.extend(gate.operands().into_iter().map(resolve));
                bounds.push(sources.len());
            }
            (list.cached.len(), list.enforcing.len())
        };
        let widest = bounds.windows(2).map(|w| w[1] - w[0]).max().unwrap_or(0);
        ResolvedList {
            challenges,
            gates,
            sources,
            bounds,
            cached,
            producing: list.producing.len(),
            enforcing,
            scratch: cached + widest,
        }
    }

    /// The producing gates, which [`ResolvedList::gate`] numbers first.
    pub fn producing(&self) -> usize {
        self.producing
    }

    /// The enforcing gates, numbered after the producing ones.
    pub fn enforcing(&self) -> usize {
        self.enforcing
    }

    /// A scratch buffer of the length evaluation needs.
    pub fn scratch(&self) -> Vec<Fr> {
        vec![Fr::ZERO; self.scratch]
    }

    /// Evaluate every cached entry at the point into `scratch`, where
    /// [`ResolvedList::gate`] substitutes them.
    pub fn cache(&self, lower: &[Fr], upper: &[Fr], virtuals: &[Fr], scratch: &mut [Fr]) {
        for i in 0..self.cached {
            let value = self.eval(i, lower, upper, virtuals, scratch);
            scratch[i] = value;
        }
    }

    /// Gate `j` at the point — producing gates first, then enforcing — with
    /// the cached values [`ResolvedList::cache`] last left in `scratch`.
    pub fn gate(
        &self,
        j: usize,
        lower: &[Fr],
        upper: &[Fr],
        virtuals: &[Fr],
        scratch: &mut [Fr],
    ) -> Fr {
        self.eval(self.cached + j, lower, upper, virtuals, scratch)
    }

    /// `S_k` at the point: the cached entries, then every gate weighted by
    /// `weights`, as [`summand`] defines it.
    pub fn summand(
        &self,
        weights: &[Fr],
        lower: &[Fr],
        upper: &[Fr],
        virtuals: &[Fr],
        scratch: &mut [Fr],
    ) -> Fr {
        // A debugging aid, not a runtime check: one weight per gate. Both callers
        // build `weights` with `powers` over exactly this count — `verify` two
        // lines before it calls — and the prover reaches this at every sumcheck
        // node.
        // let gates = self.producing + self.enforcing;
        // assert_eq!(
        //     gates,
        //     weights.len(),
        //     "summand: {} weights for {gates} gates",
        //     weights.len()
        // );
        self.cache(lower, upper, virtuals, scratch);
        weights.iter().enumerate().fold(Fr::ZERO, |acc, (j, w)| {
            acc + self.gate(j, lower, upper, virtuals, scratch) * *w
        })
    }

    /// Gate `i` of the whole list — cached entries included — through the
    /// kernel, its operands gathered into `scratch` past the cached values.
    fn eval(
        &self,
        i: usize,
        lower: &[Fr],
        upper: &[Fr],
        virtuals: &[Fr],
        scratch: &mut [Fr],
    ) -> Fr {
        let (cached, operands) = scratch.split_at_mut(self.cached);
        let sources = &self.sources[self.bounds[i]..self.bounds[i + 1]];
        let operands = &mut operands[..sources.len()];
        for (slot, source) in operands.iter_mut().zip(sources) {
            *slot = match *source {
                Source::Lower(x) => lower[x],
                Source::Upper(x) => upper[x],
                Source::Virtual(x) => virtuals[x],
                Source::Cached(x) => cached[x],
            };
        }
        eval_gate(self.gates[i], operands, self.challenges)
    }
}

/// Every gate of list `k` at one point: one value per producing gate, then one
/// per enforcing gate, cached entries evaluated once and substituted.
///
/// `lower` holds one value per column of layer `k` — offset order, or layout
/// order at `k = 0` — and, for a halving list, `upper` the matching child-1
/// values (child 0 being `lower`); `upper` is empty otherwise. `virtuals` holds
/// one value per `artifact.virtuals` entry. It resolves the list through a
/// [`ResolvedList`], which the forward pass, the self-check and the prover's
/// layer sumcheck use directly, and which reads every gate through
/// [`eval_gate`].
pub fn gate_values(
    artifact: &CircuitArtifact,
    k: usize,
    lower: &[Fr],
    upper: &[Fr],
    virtuals: &[Fr],
    challenges: &ExternalChallenges,
) -> Vec<Fr> {
    check_children(artifact, k, lower, upper, "gate_values");
    let resolved = ResolvedList::new(artifact, k, challenges);
    let mut scratch = resolved.scratch();
    resolved.cache(lower, upper, virtuals, &mut scratch);
    (0..resolved.producing() + resolved.enforcing())
        .map(|j| resolved.gate(j, lower, upper, virtuals, &mut scratch))
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
    // The message `summand` has always panicked with, when it called
    // `gate_values`.
    check_children(artifact, k, lower, upper, "gate_values");
    let resolved = ResolvedList::new(artifact, k, challenges);
    let mut scratch = resolved.scratch();
    resolved.summand(weights, lower, upper, virtuals, &mut scratch)
}

/// A halving list reads both children of every column.
fn check_children(artifact: &CircuitArtifact, k: usize, lower: &[Fr], upper: &[Fr], what: &str) {
    if artifact.layers[k].halving {
        assert_eq!(
            upper.len(),
            lower.len(),
            "{what}: halving gate list {k} needs both children of every column"
        );
    }
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
/// this function absorbs nothing of the base. It checks every challenge slot
/// and every shape before it touches `t`, and, for an artifact that has passed
/// [`CircuitArtifact::validate`], never panics on anything `proof` or `outputs`
/// carries.
///
/// The artifact is the circuit part of a verifying key: the verifier's own
/// data, not the prover's. `verify` assumes it has passed
/// [`CircuitArtifact::validate`] and does not check it again, because
/// validation belongs to a key, once, not to every proof. The routine that
/// loads a verifying key does not exist yet; the stage that introduces
/// `VerifyingKey` must call `validate` there. On an artifact that breaks a law
/// `verify`'s answer means nothing: it may panic, and it may accept.
pub fn verify(
    artifact: &CircuitArtifact,
    proof: &GkrProof,
    outputs: &OutputClaims,
    challenges: &ExternalChallenges,
    t: &mut Transcript,
) -> Result<Vec<BaseClaim>, GkrError> {
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
