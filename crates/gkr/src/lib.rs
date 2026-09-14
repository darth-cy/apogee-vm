//! The prover half of the GKR engine: the forward pass, which materializes
//! every layer from the committed base; its self-check, which recomputes every
//! gate from those layers so a broken gate is caught before proving; and the
//! backward pass, which proves the output claims down to claims about the base.
//!
//! `docs/spec/gkr.md` is normative. The verifier half is `crates/gkr-verify`,
//! re-exported here whole, so `gkr::verify` and `gkr::GkrProof` are its. Every
//! gate is evaluated through a `gkr_verify::ResolvedList`, the resolution
//! `gate_values` and `summand` go through, so the same `G` serves the forward
//! and the backward pass.
//!
//! Per-row work — a gate list's rows, a round's row pairs — is split over
//! rayon. Field arithmetic is exact, so no split and no reduction order can
//! change a value. Nothing is allocated per row, per row pair or per node:
//! each rayon task owns its buffers and overwrites them (`crates/gkr/CLAUDE.md`).
//!
//! Nothing here checks its inputs at run time. The artifact is assumed to have
//! passed `CircuitArtifact::validate` where its key is loaded, and the base, the
//! layer values, the tables and the challenge slots to have the artifact's
//! shape. Soundness is `verify`'s alone — a cheating prover runs none of this
//! code — so a malformed input can only cost the honest prover: a panic when a
//! missing column or slot is read, or a proof or base claims that fail
//! downstream. The shape checks this crate used to run are kept, uncalled, as
//! debugging aids: `check_slots` and the functions beside it.

use std::sync::Arc;

use rayon::prelude::*;

use constants::transcript_tags;
use constraints::{CircuitArtifact, PolyAddress, VirtualKind};
use field::Fr;
use poly::{eq_table, MultilinearPoly, PolyBacking};
use transcript::Transcript;

pub use gkr_verify::*;

// ---------------------------------------------------------------------------
// The containers
// ---------------------------------------------------------------------------

/// The committed base columns, by address. A clone shares the columns rather
/// than copying them.
#[derive(Clone, Debug)]
pub struct BaseLayer {
    columns: Arc<Vec<(PolyAddress, MultilinearPoly)>>,
}

impl BaseLayer {
    /// A base layer from its `address -> column` mapping, taken as given: one
    /// column per committed `M`, `W` or `S` address. Virtual tables are never
    /// materialized in a layer. Nothing is checked — a repeated address is
    /// shadowed by its first column and any other address is never read.
    pub fn new(columns: Vec<(PolyAddress, MultilinearPoly)>) -> BaseLayer {
        // A debugging aid, not a runtime check (see `check_slots`):
        // for (i, (address, _)) in columns.iter().enumerate() {
        //     assert!(
        //         matches!(
        //             address,
        //             PolyAddress::Memory(_) | PolyAddress::Witness(_) | PolyAddress::Setup(_)
        //         ),
        //         "BaseLayer::new: {address} is not a committed column"
        //     );
        //     assert!(
        //         !columns[..i].iter().any(|(a, _)| a == address),
        //         "BaseLayer::new: {address} is given twice"
        //     );
        // }
        BaseLayer {
            columns: Arc::new(columns),
        }
    }

    pub fn get(&self, address: PolyAddress) -> Option<&MultilinearPoly> {
        self.columns
            .iter()
            .find(|(a, _)| *a == address)
            .map(|(_, c)| c)
    }
}

/// Every layer of one forward pass: the base, then `layers[k - 1]` for layer
/// `k = 1..=N`, each in offset order. Cached entries are not columns and are
/// not here.
#[derive(Clone, Debug)]
pub struct LayerValues {
    pub base: BaseLayer,
    pub layers: Vec<Vec<MultilinearPoly>>,
}

/// Where the forward pass's own values break a gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfCheckError {
    /// The gate list whose gate failed.
    pub layer: usize,
    /// The first failing row of the layer the gate list writes (a producing
    /// gate) or reads (an enforcing gate).
    pub row: usize,
    /// The failing gate's relation.
    pub relation: String,
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

fn fr_poly(values: Vec<Fr>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(values))
}

/// Layer `k`'s columns, read in place at their own width: the committed
/// columns in layout order at `k = 0`, the layer's columns in offset order
/// above.
fn layer_columns<'v>(
    artifact: &CircuitArtifact,
    base: &'v BaseLayer,
    layers: &'v [Vec<MultilinearPoly>],
    k: usize,
) -> Vec<&'v MultilinearPoly> {
    if k == 0 {
        artifact
            .committed()
            .iter()
            .map(|a| {
                base.get(*a)
                    .unwrap_or_else(|| panic!("the base has no column {a}"))
            })
            .collect()
    } else {
        layers[k - 1].iter().collect()
    }
}

// ---------------------------------------------------------------------------
// Debugging aids
// ---------------------------------------------------------------------------

// `check_slots`, `check_base` and `check_values` are debugging aids, never
// runtime checks: no entry point calls them. Each refuses, with a message
// naming the culprit and before any work is done, an input the prover would
// otherwise panic on later or turn into a proof or base claims that fail
// downstream. None of them bears on soundness — that is `verify`'s, and a
// cheating prover runs none of this code — and none of them catches a wrong
// value, only a wrong shape. Uncomment a call at the top of an entry point to
// get the early message while debugging.

/// Every challenge slot a gate names is in `challenges`. Without it, a missing
/// slot panics at the first gate evaluation that reads it.
#[allow(dead_code)]
fn check_slots(artifact: &CircuitArtifact, challenges: &ExternalChallenges, what: &str) {
    if let Err(e) = check_challenges(artifact, challenges) {
        panic!("{what}: {e}");
    }
}

/// `base` is exactly the committed layout at the trace's height. Without it, a
/// missing column panics where it is first read, a column taller than the
/// trace is read only up to the trace's height, and a column shorter panics
/// on a read past its end.
#[allow(dead_code)]
fn check_base(artifact: &CircuitArtifact, base: &BaseLayer, what: &str) {
    let committed = artifact.committed();
    assert_eq!(
        base.columns.len(),
        committed.len(),
        "{what}: the base has {} columns, the layout {}",
        base.columns.len(),
        committed.len()
    );
    for address in committed {
        let column = base
            .get(address)
            .unwrap_or_else(|| panic!("{what}: the base has no column {address}"));
        assert_eq!(
            column.num_vars(),
            artifact.trace_vars as usize,
            "{what}: {address} has {} variables, the trace {}",
            column.num_vars(),
            artifact.trace_vars
        );
    }
}

// ---------------------------------------------------------------------------
// Row by row
// ---------------------------------------------------------------------------

/// Rows per rayon task in the forward pass and the self-check.
const BLOCK: usize = 1 << 10;

/// What gate list `k` reads, row by row: layer `k`'s columns in place, and the
/// virtual tables' closed forms for a row-wise list.
struct RowReader<'v> {
    columns: Vec<&'v MultilinearPoly>,
    halving: bool,
    kinds: Vec<VirtualKind>,
    /// The rows the list defines: layer `k`'s, or half of them for a halving
    /// list, whose row `i` reads rows `i` and `i + rows` of layer `k`.
    rows: usize,
}

/// One rayon task's buffers for [`RowReader::load`], overwritten row after row.
struct RowScratch {
    lower: Vec<Fr>,
    upper: Vec<Fr>,
    virtuals: Vec<Fr>,
    gates: Vec<Fr>,
}

impl<'v> RowReader<'v> {
    fn new(
        artifact: &CircuitArtifact,
        base: &'v BaseLayer,
        layers: &'v [Vec<MultilinearPoly>],
        k: usize,
    ) -> RowReader<'v> {
        let halving = artifact.layers[k].halving;
        let rows_in = 1usize << artifact.layer_vars(k);
        RowReader {
            columns: layer_columns(artifact, base, layers, k),
            halving,
            kinds: if halving {
                Vec::new()
            } else {
                artifact.virtuals.iter().map(|(kind, _)| *kind).collect()
            },
            rows: if halving { rows_in / 2 } else { rows_in },
        }
    }

    fn scratch(&self, resolved: &ResolvedList) -> RowScratch {
        let width = self.columns.len();
        RowScratch {
            lower: vec![Fr::ZERO; width],
            upper: vec![Fr::ZERO; if self.halving { width } else { 0 }],
            virtuals: vec![Fr::ZERO; self.kinds.len()],
            gates: resolved.scratch(),
        }
    }

    /// Row `y`'s inputs into `s` — both children for a halving list, the
    /// virtual tables for a row-wise one — and its cached entries evaluated.
    fn load(&self, y: usize, resolved: &ResolvedList, s: &mut RowScratch) {
        if self.halving {
            for (column, (lo, hi)) in self
                .columns
                .iter()
                .zip(s.lower.iter_mut().zip(&mut s.upper))
            {
                *lo = column.get(y);
                *hi = column.get(y + self.rows);
            }
        } else {
            for (column, value) in self.columns.iter().zip(s.lower.iter_mut()) {
                *value = column.get(y);
            }
            // A virtual table is never materialized: its closed form, per row.
            for (kind, value) in self.kinds.iter().zip(s.virtuals.iter_mut()) {
                *value = virtual_at_row(*kind, y);
            }
        }
        resolved.cache(&s.lower, &s.upper, &s.virtuals, &mut s.gates);
    }
}

// ---------------------------------------------------------------------------
// The forward pass
// ---------------------------------------------------------------------------

/// Materialize every layer from `base`, gate list by gate list, row by row.
///
/// Checks nothing about its inputs (the crate doc says why): `base` is assumed
/// to be the committed layout at the trace's height, and `challenges` to hold
/// every slot a producing gate or cached entry names.
///
/// `artifact` is the circuit part of a proving key, assumed to have passed
/// `CircuitArtifact::validate` where the key is loaded, and not checked again;
/// on one that breaks a law the values mean nothing, and the call may panic.
pub fn forward(
    artifact: &CircuitArtifact,
    base: &BaseLayer,
    challenges: &ExternalChallenges,
) -> LayerValues {
    // Debugging aids, not runtime checks (see `check_slots`):
    // check_slots(artifact, challenges, "gkr::forward");
    // check_base(artifact, base, "gkr::forward");
    let mut layers: Vec<Vec<MultilinearPoly>> = Vec::with_capacity(artifact.depth());
    for k in 0..artifact.depth() {
        let columns = produce(artifact, base, &layers, k, challenges);
        layers.push(columns);
    }
    LayerValues {
        base: base.clone(),
        layers,
    }
}

/// The columns gate list `k` writes. Each is allocated once, at its height,
/// and filled in place: the rows are cut into blocks, every column's slice of
/// a block goes to one rayon task, and the task writes its producing gates row
/// by row. Enforcing gates are not evaluated here.
fn produce(
    artifact: &CircuitArtifact,
    base: &BaseLayer,
    layers: &[Vec<MultilinearPoly>],
    k: usize,
    challenges: &ExternalChallenges,
) -> Vec<MultilinearPoly> {
    let width = artifact.layer_width(k + 1) as usize;
    if width == 0 {
        return Vec::new();
    }
    let reader = RowReader::new(artifact, base, layers, k);
    let resolved = ResolvedList::new(artifact, k, challenges);
    let mut out: Vec<Vec<Fr>> = (0..width).map(|_| vec![Fr::ZERO; reader.rows]).collect();
    let mut blocks: Vec<Vec<&mut [Fr]>> = (0..reader.rows.div_ceil(BLOCK))
        .map(|_| Vec::with_capacity(width))
        .collect();
    for column in out.iter_mut() {
        for (block, chunk) in blocks.iter_mut().zip(column.chunks_mut(BLOCK)) {
            block.push(chunk);
        }
    }
    blocks.into_par_iter().enumerate().for_each_init(
        || reader.scratch(&resolved),
        |s, (b, mut block)| {
            for i in 0..block[0].len() {
                reader.load(b * BLOCK + i, &resolved, s);
                for (j, column) in block.iter_mut().enumerate() {
                    column[i] = resolved.gate(j, &s.lower, &s.upper, &s.virtuals, &mut s.gates);
                }
            }
        },
    );
    out.into_iter().map(fr_poly).collect()
}

/// Recompute every gate from the materialized layers: every producing gate
/// against the column it writes, every enforcing gate against 0, on every
/// row. The first failure found, lowest gate list and row first.
///
/// A debugging hook, not a step of proving. `prove` does not call it: it
/// proves whatever `values` holds, and a verifier rejects what is wrong. On
/// `forward`'s own output every producing gate holds by construction — the same
/// kernel over the same inputs — so what it adds is the enforcing gates and the
/// name and row of the first broken relation, which `verify`'s one
/// `LayerInconsistency` cannot give. It costs as much as `forward`; a
/// production prover does not run it per proof.
///
/// Checks nothing about its inputs, as `forward` does not. Like `forward`, it
/// assumes `artifact` has passed `CircuitArtifact::validate` and does not
/// check it again; on one that breaks a law its answer means nothing, and the
/// call may panic.
pub fn self_check(
    artifact: &CircuitArtifact,
    values: &LayerValues,
    challenges: &ExternalChallenges,
) -> Result<(), SelfCheckError> {
    // Debugging aids, not runtime checks (see `check_slots`):
    // check_slots(artifact, challenges, "gkr::self_check");
    // check_values(artifact, values, "gkr::self_check");
    for k in 0..artifact.depth() {
        let list = &artifact.layers[k];
        let reader = RowReader::new(artifact, &values.base, &values.layers, k);
        let resolved = ResolvedList::new(artifact, k, challenges);
        let written = &values.layers[k];
        let producing = resolved.producing();
        let enforcing = resolved.enforcing();
        let rows = reader.rows;
        // Blocks in parallel, rows in order within one, and within a row the
        // producing gates before the enforcing ones: the first failure of the
        // first failing block is the first failure.
        let first = (0..rows.div_ceil(BLOCK))
            .into_par_iter()
            .map_init(
                || reader.scratch(&resolved),
                |s, b| {
                    for y in b * BLOCK..rows.min((b + 1) * BLOCK) {
                        reader.load(y, &resolved, s);
                        for (j, column) in written.iter().enumerate().take(producing) {
                            let value =
                                resolved.gate(j, &s.lower, &s.upper, &s.virtuals, &mut s.gates);
                            if value != column.get(y) {
                                return Some((y, j));
                            }
                        }
                        for j in producing..producing + enforcing {
                            let value =
                                resolved.gate(j, &s.lower, &s.upper, &s.virtuals, &mut s.gates);
                            if value != Fr::ZERO {
                                return Some((y, j));
                            }
                        }
                    }
                    None
                },
            )
            .find_map_first(|failure| failure);
        if let Some((row, j)) = first {
            let relation = if j < producing {
                list.producing[j].relation
            } else {
                list.enforcing[j - producing].relation
            };
            return Err(SelfCheckError {
                layer: k,
                row,
                relation: artifact.relations[relation as usize].name.clone(),
            });
        }
    }
    Ok(())
}

/// `values` has the artifact's shape: the base as [`check_base`] holds it, one
/// layer per gate list, each of the artifact's width and height. Without it, a
/// missing layer or column panics where it is first read, an extra column below
/// the top makes a proof whose claim count `verify` refuses, and an extra
/// column of the top is never read.
#[allow(dead_code)]
fn check_values(artifact: &CircuitArtifact, values: &LayerValues, what: &str) {
    check_base(artifact, &values.base, what);
    assert_eq!(
        values.layers.len(),
        artifact.depth(),
        "{what}: {} layers for a circuit of depth {}",
        values.layers.len(),
        artifact.depth()
    );
    for k in 1..=artifact.depth() {
        let columns = &values.layers[k - 1];
        assert_eq!(
            columns.len(),
            artifact.layer_width(k) as usize,
            "{what}: layer {k} has {} columns, the artifact {}",
            columns.len(),
            artifact.layer_width(k)
        );
        for c in columns {
            assert_eq!(
                c.num_vars(),
                artifact.layer_vars(k) as usize,
                "{what}: a column of layer {k} has {} variables, the artifact {}",
                c.num_vars(),
                artifact.layer_vars(k)
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The layer sumcheck, prover half
// ---------------------------------------------------------------------------

/// One transition's summand, `docs/spec/gkr.md` §5.3: gate list `layer` of
/// `artifact`, its gates weighted by `weights` — the descending claim's
/// columns first, then the enforcing side claims.
pub struct LayerSummand<'a> {
    pub artifact: &'a CircuitArtifact,
    pub layer: usize,
    pub weights: Vec<Fr>,
    pub challenges: &'a ExternalChallenges,
}

/// The tables a layer sumcheck binds, all with the eq point's variable count:
/// layer `k`'s columns — child 0 of each, for a halving list — and, for a
/// halving list, child 1 of each. Virtual tables are not here: they are never
/// materialized, and the driver evaluates their closed form where it needs one.
pub struct LayerTables {
    pub lower: Vec<MultilinearPoly>,
    pub upper: Vec<MultilinearPoly>,
}

/// `[1/2, 1/3, 1/6]`, derived rather than transcribed.
fn interpolation_constants() -> [Fr; 3] {
    let inv = |k: u64| {
        Fr::from_u64(k)
            .inverse()
            .expect("2, 3 and 6 are invertible in Fr")
    };
    [inv(2), inv(3), inv(6)]
}

/// The ascending coefficients of the cubic through `(i, v[i])`, `i = 0..4`:
/// Newton's forward differences, `g(X) = v0 + d1·X + d2·X(X-1)/2 +
/// d3·X(X-1)(X-2)/6`, expanded — S04's `interpolate_cubic`, which is private to
/// `crates/sumcheck`.
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

/// One rayon task's buffers for a round's row pairs, overwritten pair after
/// pair: the line of every table and every virtual table as `(value, step)`,
/// the point a virtual table's closed form is evaluated at, and the resolved
/// list's scratch.
struct PairScratch {
    lower: Vec<Fr>,
    lower_step: Vec<Fr>,
    upper: Vec<Fr>,
    upper_step: Vec<Fr>,
    virtuals: Vec<Fr>,
    virtuals_step: Vec<Fr>,
    /// The round's bound challenges first; the rest is written per pair.
    point: Vec<Fr>,
    gates: Vec<Fr>,
}

/// The line `lo + X·(hi − lo)` of pair `i` of every table, into `lo` and `step`.
fn lines(tables: &[MultilinearPoly], i: usize, lo: &mut [Fr], step: &mut [Fr]) {
    for (t, (lo, step)) in tables.iter().zip(lo.iter_mut().zip(step.iter_mut())) {
        *lo = t.get(2 * i);
        *step = t.get(2 * i + 1) - *lo;
    }
}

/// The line of pair `i` of every virtual table after `bound` rounds, from the
/// closed form alone: `point` already holds the bound challenges; this writes
/// `X` and the bits of `i` after them and evaluates at `X = 0` and `X = 1`.
fn virtual_lines(
    kinds: &[VirtualKind],
    bound: usize,
    i: usize,
    point: &mut [Fr],
    lo: &mut [Fr],
    step: &mut [Fr],
) {
    for (j, y) in point[bound + 1..].iter_mut().enumerate() {
        *y = Fr::from_u64(((i >> j) & 1) as u64);
    }
    point[bound] = Fr::ZERO;
    for (kind, lo) in kinds.iter().zip(lo.iter_mut()) {
        *lo = virtual_at_point(*kind, point);
    }
    point[bound] = Fr::ONE;
    for (kind, (lo, step)) in kinds.iter().zip(lo.iter().zip(step.iter_mut())) {
        *step = virtual_at_point(*kind, point) - *lo;
    }
}

fn step(values: &mut [Fr], steps: &[Fr]) {
    for (v, s) in values.iter_mut().zip(steps) {
        *v += *s;
    }
}

/// Prove `claim = Σ_y eq(eq_point, y) · S(y)` for the summand and tables
/// given: one cubic per variable of the eq point, each absorbed as
/// `SUMCHECK_ROUND` and followed by the `SUMCHECK_CHALLENGE` that binds it.
/// Returns the rounds and the bound point; every table is left bound to it.
///
/// The claim itself is not an input: an honest round 0 sums to it by
/// construction, and a claim the tables do not support is the verifier's to
/// reject.
pub fn prove_sumcheck(
    eq_point: &[Fr],
    summand: &LayerSummand,
    tables: &mut LayerTables,
    t: &mut Transcript,
) -> (Vec<[Fr; 4]>, Vec<Fr>) {
    let n = eq_point.len();
    let artifact = summand.artifact;
    let kinds: Vec<VirtualKind> = if artifact.layers[summand.layer].halving {
        Vec::new()
    } else {
        artifact.virtuals.iter().map(|(kind, _)| *kind).collect()
    };
    // Debugging aids, not runtime checks (see `check_slots`). Without them a
    // table shorter than the eq point, or a halving list missing a child table,
    // panics on a read past its end; a taller table is read only in part, and
    // an extra child table is bound and never read.
    // for table in tables.lower.iter().chain(&tables.upper) {
    //     assert_eq!(
    //         table.num_vars(),
    //         n,
    //         "prove_sumcheck: a table has {} variables, the eq point {n}",
    //         table.num_vars()
    //     );
    // }
    // if artifact.layers[summand.layer].halving {
    //     assert_eq!(
    //         tables.upper.len(),
    //         tables.lower.len(),
    //         "prove_sumcheck: halving gate list {} needs both children of every column",
    //         summand.layer
    //     );
    // }
    let resolved = ResolvedList::new(artifact, summand.layer, summand.challenges);
    let mut eq = fr_poly(eq_table(eq_point));
    let constants = interpolation_constants();
    let mut rounds = Vec::with_capacity(n);
    let mut point = Vec::with_capacity(n);
    for _ in 0..n {
        let half = eq.len() / 2;
        let bound = point.len();
        let at_nodes = (0..half)
            .into_par_iter()
            .map_init(
                || {
                    let mut at = vec![Fr::ZERO; n];
                    at[..bound].copy_from_slice(&point);
                    PairScratch {
                        lower: vec![Fr::ZERO; tables.lower.len()],
                        lower_step: vec![Fr::ZERO; tables.lower.len()],
                        upper: vec![Fr::ZERO; tables.upper.len()],
                        upper_step: vec![Fr::ZERO; tables.upper.len()],
                        virtuals: vec![Fr::ZERO; kinds.len()],
                        virtuals_step: vec![Fr::ZERO; kinds.len()],
                        point: at,
                        gates: resolved.scratch(),
                    }
                },
                |s, i| {
                    lines(&tables.lower, i, &mut s.lower, &mut s.lower_step);
                    lines(&tables.upper, i, &mut s.upper, &mut s.upper_step);
                    if !kinds.is_empty() {
                        virtual_lines(
                            &kinds,
                            bound,
                            i,
                            &mut s.point,
                            &mut s.virtuals,
                            &mut s.virtuals_step,
                        );
                    }
                    let (eq_lo, eq_hi) = (eq.get(2 * i), eq.get(2 * i + 1));
                    let eq_step = eq_hi - eq_lo;
                    let mut eq_at = eq_lo;
                    let mut acc = [Fr::ZERO; 4];
                    for node in acc.iter_mut() {
                        *node = eq_at
                            * resolved.summand(
                                &summand.weights,
                                &s.lower,
                                &s.upper,
                                &s.virtuals,
                                &mut s.gates,
                            );
                        eq_at += eq_step;
                        step(&mut s.lower, &s.lower_step);
                        step(&mut s.upper, &s.upper_step);
                        step(&mut s.virtuals, &s.virtuals_step);
                    }
                    acc
                },
            )
            .reduce(
                || [Fr::ZERO; 4],
                |a, b| [a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3]],
            );
        let g = interpolate_cubic(&at_nodes, &constants);
        t.append_scalars(transcript_tags::SUMCHECK_ROUND, &g);
        let r = t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE);
        for table in tables.lower.iter_mut().chain(tables.upper.iter_mut()) {
            table.bind(r);
        }
        eq.bind(r);
        rounds.push(g);
        point.push(r);
    }
    (rounds, point)
}

// ---------------------------------------------------------------------------
// prove
// ---------------------------------------------------------------------------

/// A halving list's two child tables of `column`, each copied once, straight
/// from the column: child 0 is the first `half` rows, child 1 the rest, the
/// child bit being the highest variable. A halving list never reads the base,
/// so its column is one `forward` wrote, in `Fr`; any other backing is read
/// through `get`.
fn children(column: &MultilinearPoly, half: usize) -> (MultilinearPoly, MultilinearPoly) {
    let (lo, hi) = match column.backing() {
        PolyBacking::Fr(v) => (v[..half].to_vec(), v[half..].to_vec()),
        _ => (
            (0..half).map(|i| column.get(i)).collect(),
            (half..2 * half).map(|i| column.get(i)).collect(),
        ),
    };
    (fr_poly(lo), fr_poly(hi))
}

/// Prove the circuit's outputs, as `values` holds them, down to its committed
/// base columns, on `t` — which the caller has already bound to the base.
/// Absorbs nothing of the base. Follows `docs/spec/gkr.md` §5.2 step for step,
/// exactly as `verify` does.
///
/// Checks nothing about its inputs, as `forward` does not. It does not check
/// that `values` satisfies the gates either — `self_check` does — so a proof
/// over wrong values is a proof a verifier rejects.
///
/// Like `forward`, it assumes `artifact` — the circuit part of a proving key —
/// has passed `CircuitArtifact::validate` and does not check it again; on one
/// that breaks a law the proof means nothing, and the call may panic.
pub fn prove(
    artifact: &CircuitArtifact,
    values: &LayerValues,
    challenges: &ExternalChallenges,
    t: &mut Transcript,
) -> GkrProof {
    // Debugging aids, not runtime checks (see `check_slots`):
    // check_slots(artifact, challenges, "gkr::prove");
    // check_values(artifact, values, "gkr::prove");
    let depth = artifact.depth();

    // O1, O2.
    let top = &values.layers[depth - 1];
    let mut message: Vec<Fr> = Vec::new();
    for out in &artifact.outputs {
        if let PolyAddress::Inner { offset, .. } = *out {
            let column = &top[offset as usize];
            message.extend((0..column.len()).map(|i| column.get(i)));
        }
    }
    t.append_scalars(transcript_tags::GKR_OUTPUTS, &message);
    let mut point: Vec<Fr> = (0..artifact.layer_vars(depth))
        .map(|_| t.challenge_scalar(transcript_tags::GKR_OUTPUT_POINT))
        .collect();

    let mut layers: Vec<Option<SumcheckProof>> = vec![None; depth];
    for k in (0..depth).rev() {
        let list = &artifact.layers[k];

        // L1.
        let lambda = t.challenge_scalar(transcript_tags::GKR_BATCH);
        let summand = LayerSummand {
            artifact,
            layer: k,
            weights: powers(lambda, list.producing.len() + list.enforcing.len()),
            challenges,
        };

        // L2: one binding copy per column, at the column's width. The first
        // bind folds a narrow copy straight into a half-size `Fr` table.
        let columns = layer_columns(artifact, &values.base, &values.layers, k);
        let mut tables = if list.halving {
            let half = 1usize << (artifact.layer_vars(k) - 1);
            let (lower, upper) = columns.iter().map(|c| children(c, half)).unzip();
            LayerTables { lower, upper }
        } else {
            LayerTables {
                lower: columns.into_iter().cloned().collect(),
                upper: Vec::new(),
            }
        };
        let (rounds, rho) = prove_sumcheck(&point, &summand, &mut tables, t);

        // L3: every table is bound to rho, one value each.
        let final_evals: Vec<Fr> = if list.halving {
            tables
                .lower
                .iter()
                .zip(&tables.upper)
                .flat_map(|(lo, hi)| [lo.get(0), hi.get(0)])
                .collect()
        } else {
            tables.lower.iter().map(|c| c.get(0)).collect()
        };
        t.append_scalars(transcript_tags::GKR_LAYER_CLAIMS, &final_evals);

        // L4.
        point = rho;
        if list.halving {
            point.push(t.challenge_scalar(transcript_tags::GKR_CHILD));
        }
        layers[k] = Some(SumcheckProof {
            rounds,
            final_evals,
        });
    }

    GkrProof {
        layers: layers
            .into_iter()
            .map(|l| l.expect("every transition was proven"))
            .collect(),
    }
}
