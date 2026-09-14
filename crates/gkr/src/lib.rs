//! The prover half of the GKR engine: the forward pass, which materializes
//! every layer from the committed base; its self-check, which recomputes every
//! gate from those layers so a broken gate is caught before proving; and the
//! backward pass, which proves the output claims down to claims about the base.
//!
//! `docs/spec/gkr.md` is normative. The verifier half is `crates/gkr-verify`,
//! re-exported here whole, so `gkr::verify` and `gkr::GkrProof` are its. Every
//! gate is evaluated through `gkr_verify::gate_values`, on both sides, so the
//! same `G` serves the forward and the backward pass.
//!
//! Per-row work — a gate list's rows, a round's row pairs — is split over
//! rayon. Field arithmetic is exact, so no split and no reduction order can
//! change a value.

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

/// The committed base columns, by address.
#[derive(Clone, Debug)]
pub struct BaseLayer {
    columns: Vec<(PolyAddress, MultilinearPoly)>,
}

impl BaseLayer {
    /// A base layer from its `address -> column` mapping. Panics on an
    /// address twice, or one that is not a committed `M`, `W` or `S` column —
    /// virtual tables are never materialized in a layer.
    pub fn new(columns: Vec<(PolyAddress, MultilinearPoly)>) -> BaseLayer {
        for (i, (address, _)) in columns.iter().enumerate() {
            assert!(
                matches!(
                    address,
                    PolyAddress::Memory(_) | PolyAddress::Witness(_) | PolyAddress::Setup(_)
                ),
                "BaseLayer::new: {address} is not a committed column"
            );
            assert!(
                !columns[..i].iter().any(|(a, _)| a == address),
                "BaseLayer::new: {address} is given twice"
            );
        }
        BaseLayer { columns }
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

fn table(column: &MultilinearPoly) -> Vec<Fr> {
    (0..column.len()).map(|i| column.get(i)).collect()
}

fn fr_poly(values: Vec<Fr>) -> MultilinearPoly {
    MultilinearPoly::new(PolyBacking::Fr(values))
}

/// Layer `k`'s columns as `Fr` tables: the committed columns in layout order
/// at `k = 0`, the layer's columns in offset order above.
fn layer_tables(artifact: &CircuitArtifact, values: &LayerValues, k: usize) -> Vec<Vec<Fr>> {
    if k == 0 {
        artifact
            .committed()
            .iter()
            .map(|a| table(values.base.get(*a).expect("the base was checked")))
            .collect()
    } else {
        values.layers[k - 1].iter().map(table).collect()
    }
}

/// Row `y` of every table.
fn row(tables: &[Vec<Fr>], y: usize) -> Vec<Fr> {
    tables.iter().map(|t| t[y]).collect()
}

fn check_artifact(artifact: &CircuitArtifact, challenges: &ExternalChallenges, what: &str) {
    if let Err(e) = artifact.validate() {
        panic!("{what}: the artifact is not a circuit: {e}");
    }
    if let Err(e) = check_challenges(artifact, challenges) {
        panic!("{what}: {e}");
    }
}

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
// The forward pass
// ---------------------------------------------------------------------------

/// Materialize every layer from `base`, gate list by gate list, row by row.
///
/// Panics if the artifact breaks a law, a slot is missing, or `base` is not
/// exactly the committed layout at the trace's height.
pub fn forward(
    artifact: &CircuitArtifact,
    base: &BaseLayer,
    challenges: &ExternalChallenges,
) -> LayerValues {
    check_artifact(artifact, challenges, "gkr::forward");
    check_base(artifact, base, "gkr::forward");
    let mut values = LayerValues {
        base: base.clone(),
        layers: Vec::new(),
    };
    for k in 0..artifact.depth() {
        let rows_out = 1usize << artifact.layer_vars(k + 1);
        let width = artifact.layer_width(k + 1) as usize;
        let rows: Vec<Vec<Fr>> = gate_rows(artifact, &values, k, challenges)
            .into_iter()
            .map(|mut gates| {
                gates.truncate(width);
                gates
            })
            .collect();
        debug_assert_eq!(rows.len(), rows_out);
        let columns = (0..width)
            .map(|j| fr_poly(rows.iter().map(|r| r[j]).collect()))
            .collect();
        values.layers.push(columns);
    }
    values
}

/// Every gate of list `k` on every row it defines — `gate_values` per row of
/// the layer the list writes, over the layer it reads.
fn gate_rows(
    artifact: &CircuitArtifact,
    values: &LayerValues,
    k: usize,
    challenges: &ExternalChallenges,
) -> Vec<Vec<Fr>> {
    let lower = layer_tables(artifact, values, k);
    let rows_in = 1usize << artifact.layer_vars(k);
    if artifact.layers[k].halving {
        let half = rows_in / 2;
        (0..half)
            .into_par_iter()
            .map(|i| {
                gate_values(
                    artifact,
                    k,
                    &row(&lower, i),
                    &row(&lower, i + half),
                    &[],
                    challenges,
                )
            })
            .collect()
    } else {
        (0..rows_in)
            .into_par_iter()
            .map(|y| {
                // A virtual table is never materialized: its closed form, per row.
                let virtuals: Vec<Fr> = artifact
                    .virtuals
                    .iter()
                    .map(|(kind, _)| virtual_at_row(*kind, y))
                    .collect();
                gate_values(artifact, k, &row(&lower, y), &[], &virtuals, challenges)
            })
            .collect()
    }
}

/// Recompute every gate from the materialized layers: every producing gate
/// against the column it writes, every enforcing gate against 0, on every
/// row. The first failure found, lowest gate list and row first.
///
/// `prove` does not call this: it proves whatever `values` holds, and a
/// verifier rejects what is wrong. The caller runs it after `forward`.
pub fn self_check(
    artifact: &CircuitArtifact,
    values: &LayerValues,
    challenges: &ExternalChallenges,
) -> Result<(), SelfCheckError> {
    check_artifact(artifact, challenges, "gkr::self_check");
    check_values(artifact, values, "gkr::self_check");
    for k in 0..artifact.depth() {
        let list = &artifact.layers[k];
        let width = list.producing.len();
        let written = layer_tables(artifact, values, k + 1);
        let rows = gate_rows(artifact, values, k, challenges);
        for (y, gates) in rows.iter().enumerate() {
            let broken = (0..width)
                .find(|&j| gates[j] != written[j][y])
                .map(|j| list.producing[j].relation)
                .or_else(|| {
                    (width..gates.len())
                        .find(|&e| gates[e] != Fr::ZERO)
                        .map(|e| list.enforcing[e - width].relation)
                });
            if let Some(relation) = broken {
                return Err(SelfCheckError {
                    layer: k,
                    row: y,
                    relation: artifact.relations[relation as usize].name.clone(),
                });
            }
        }
    }
    Ok(())
}

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

/// The line `lo + X·(hi − lo)` of pair `i` of every table, as `(lo, step)`.
fn lines(tables: &[MultilinearPoly], i: usize) -> (Vec<Fr>, Vec<Fr>) {
    tables
        .iter()
        .map(|t| {
            let lo = t.get(2 * i);
            (lo, t.get(2 * i + 1) - lo)
        })
        .unzip()
}

/// The line of pair `i` of every virtual table after `bound.len()` rounds of
/// an `n`-variable sumcheck, from the closed form alone: the point
/// `(bound, X, bits of i)` at `X = 0` and `X = 1`.
fn virtual_lines(kinds: &[VirtualKind], bound: &[Fr], n: usize, i: usize) -> (Vec<Fr>, Vec<Fr>) {
    if kinds.is_empty() {
        return (Vec::new(), Vec::new());
    }
    let at = |x: Fr| {
        let mut point = bound.to_vec();
        point.push(x);
        let rest = n - bound.len() - 1;
        point.extend((0..rest).map(|j| Fr::from_u64(((i >> j) & 1) as u64)));
        point
    };
    let (p0, p1) = (at(Fr::ZERO), at(Fr::ONE));
    kinds
        .iter()
        .map(|kind| {
            let lo = virtual_at_point(*kind, &p0);
            (lo, virtual_at_point(*kind, &p1) - lo)
        })
        .unzip()
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
    for table in tables.lower.iter().chain(&tables.upper) {
        assert_eq!(
            table.num_vars(),
            n,
            "prove_sumcheck: a table has {} variables, the eq point {n}",
            table.num_vars()
        );
    }
    let mut eq = fr_poly(eq_table(eq_point));
    let constants = interpolation_constants();
    let mut rounds = Vec::with_capacity(n);
    let mut point = Vec::with_capacity(n);
    for _ in 0..n {
        let half = eq.len() / 2;
        let at_nodes = (0..half)
            .into_par_iter()
            .map(|i| {
                let (mut lower, lower_step) = lines(&tables.lower, i);
                let (mut upper, upper_step) = lines(&tables.upper, i);
                let (mut virtuals, virtuals_step) = virtual_lines(&kinds, &point, n, i);
                let (eq_lo, eq_hi) = (eq.get(2 * i), eq.get(2 * i + 1));
                let eq_step = eq_hi - eq_lo;
                let mut eq_at = eq_lo;
                let mut acc = [Fr::ZERO; 4];
                for node in acc.iter_mut() {
                    *node = eq_at
                        * gkr_verify::summand(
                            summand.artifact,
                            summand.layer,
                            &summand.weights,
                            &lower,
                            &upper,
                            &virtuals,
                            summand.challenges,
                        );
                    eq_at += eq_step;
                    step(&mut lower, &lower_step);
                    step(&mut upper, &upper_step);
                    step(&mut virtuals, &virtuals_step);
                }
                acc
            })
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

/// Prove the circuit's outputs, as `values` holds them, down to its committed
/// base columns, on `t` — which the caller has already bound to the base.
/// Absorbs nothing of the base. Follows `docs/spec/gkr.md` §5.2 step for step,
/// exactly as `verify` does.
///
/// Panics if the artifact breaks a law, a slot is missing, or `values` does not
/// have the artifact's shape. It does not check that `values` satisfies the
/// gates — `self_check` does — so a proof over wrong values is a proof a
/// verifier rejects.
pub fn prove(
    artifact: &CircuitArtifact,
    values: &LayerValues,
    challenges: &ExternalChallenges,
    t: &mut Transcript,
) -> GkrProof {
    check_artifact(artifact, challenges, "gkr::prove");
    check_values(artifact, values, "gkr::prove");
    let depth = artifact.depth();

    // O1, O2.
    let top = &values.layers[depth - 1];
    let mut message: Vec<Fr> = Vec::new();
    for out in &artifact.outputs {
        if let PolyAddress::Inner { offset, .. } = *out {
            message.extend(table(&top[offset as usize]));
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

        // L2.
        let columns = layer_tables(artifact, values, k);
        let mut tables = if list.halving {
            let half = 1usize << (artifact.layer_vars(k) - 1);
            LayerTables {
                lower: columns
                    .iter()
                    .map(|c| fr_poly(c[..half].to_vec()))
                    .collect(),
                upper: columns
                    .iter()
                    .map(|c| fr_poly(c[half..].to_vec()))
                    .collect(),
            }
        } else {
            LayerTables {
                lower: columns.into_iter().map(fr_poly).collect(),
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
