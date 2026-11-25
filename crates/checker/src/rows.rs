//! A whole shard against its circuit, row by row: [`evaluate_rows`].
//!
//! Every row-local relation of the flat list is evaluated on every row through
//! the kernel, as [`crate::violated_relations`] evaluates one row's, and the
//! halving lists are folded over the rows rather than materialized, so a
//! shard costs its committed columns and a few buffers a thread, never the
//! inner layers `gkr::forward` holds.

use constraints::{CircuitArtifact, GateDef, PolyAddress, VirtualKind};
use field::Fp2;
use gkr::{eval_gate, virtual_at_row, BaseLayer, ExternalChallenges};
use poly::MultilinearPoly;
use rayon::prelude::*;

use crate::{layout_index, row_local_order};

/// The rows one rayon task evaluates in turn.
const BLOCK: usize = 1 << 12;

/// Why [`evaluate_rows`] refuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowFailure {
    /// The lowest row on which a row-local enforcing relation does not
    /// vanish, and the first such relation on it in relation order.
    Relation { row: usize, relation: String },
    /// An artifact or a base this evaluator cannot read: a column the base
    /// does not hold, an operand no row supplies, or halving lists that do not
    /// keep their columns' offsets.
    Shape(String),
}

/// Where a relation's operand is read on a row.
#[derive(Clone, Copy)]
enum Src {
    /// A committed column, by its place in the layout.
    Committed(usize),
    /// A virtual table, by its place in the evaluator's list of kinds.
    Virtual(usize),
    /// A scratch slot, written by a relation earlier in the order.
    Scratch(usize),
}

/// One row-local relation, its operands resolved.
struct Step<'a> {
    relation: usize,
    gate: &'a GateDef,
    sources: Vec<Src>,
    output: Option<usize>,
}

/// How the halving lists combine two rows at one output offset.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Fold {
    /// `TreeProduct`: the product of the offset's values.
    Product,
    /// `TreeCross` over the offset and `den`: `n_a·d_b + n_b·d_a`.
    Cross { den: usize },
}

/// One halving gate's shape at output offset `j`: `None` unless it reads
/// offset `j` of the layer below, as a halving list that keeps its columns'
/// offsets does.
fn fold_of(gate: &GateDef, layer: u32, j: usize) -> Option<Fold> {
    let at = |a: &PolyAddress| match *a {
        PolyAddress::Inner { layer: l, offset } if l == layer => Some(offset as usize),
        _ => None,
    };
    match gate {
        GateDef::TreeProduct { input } if at(input) == Some(j) => Some(Fold::Product),
        GateDef::TreeCross { left, right } if at(left) == Some(j) => {
            at(right).map(|den| Fold::Cross { den })
        }
        _ => None,
    }
}

/// The evaluator, resolved once per artifact.
struct Rows<'a> {
    challenges: &'a ExternalChallenges,
    layout: Vec<&'a MultilinearPoly>,
    kinds: Vec<VirtualKind>,
    steps: Vec<Step<'a>>,
    scratch: usize,
    widest: usize,
    /// Per output offset of the first halving list, the scratch slot of the
    /// row-wise column it reads and how two rows combine there.
    folds: Vec<(usize, Fold)>,
}

impl<'a> Rows<'a> {
    fn new(
        a: &'a CircuitArtifact,
        base: &'a BaseLayer,
        challenges: &'a ExternalChallenges,
    ) -> Result<Rows<'a>, RowFailure> {
        let shape = RowFailure::Shape;
        let rows = 1usize << a.trace_vars;
        let layout = a
            .committed()
            .into_iter()
            .map(|address| match base.get(address) {
                Some(column) if column.len() == rows => Ok(column),
                Some(column) => Err(shape(format!(
                    "the base's column {address} has {} rows, not {rows}",
                    column.len()
                ))),
                None => Err(shape(format!("the base has no column {address}"))),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut kinds: Vec<VirtualKind> = Vec::new();
        let mut steps = Vec::new();
        for r in row_local_order(a) {
            let rel = &a.relations[r];
            let mut sources = Vec::new();
            for op in rel.gate.operands() {
                sources.push(match op {
                    PolyAddress::Virtual(kind) => {
                        if !kinds.contains(&kind) {
                            kinds.push(kind);
                        }
                        Src::Virtual(kinds.iter().position(|k| *k == kind).expect("just added"))
                    }
                    PolyAddress::Scratch(i) => Src::Scratch(i as usize),
                    other => Src::Committed(layout_index(a, other).ok_or_else(|| {
                        shape(format!(
                            "relation {}: {other} cannot be read on a row",
                            rel.name
                        ))
                    })?),
                });
            }
            steps.push(Step {
                relation: r,
                gate: &rel.gate,
                sources,
                output: rel.output.map(|i| i as usize),
            });
        }
        let widest = steps.iter().map(|s| s.sources.len()).max().unwrap_or(0);

        // The halving lists: every one combines the same offsets the same
        // way, the first's input being the last row-wise layer, whose columns
        // are scratch slots.
        let first = a
            .layers
            .iter()
            .position(|list| list.halving)
            .ok_or_else(|| shape("the artifact has no halving list".to_string()))?;
        let mut folds = Vec::new();
        for (j, entry) in a.layers[first].producing.iter().enumerate() {
            let fold = fold_of(&entry.gate, first as u32, j).ok_or_else(|| {
                shape(format!(
                    "halving gate {j} of list {first} does not keep its offset"
                ))
            })?;
            let slot = a
                .scratch
                .iter()
                .position(|s| {
                    s.address
                        == PolyAddress::Inner {
                            layer: first as u32,
                            offset: j as u32,
                        }
                })
                .ok_or_else(|| shape(format!("layer {first}'s column {j} is no scratch slot")))?;
            folds.push((slot, fold));
        }
        for (k, list) in a.layers.iter().enumerate().skip(first) {
            let same = list.halving
                && list.producing.len() == folds.len()
                && list
                    .producing
                    .iter()
                    .enumerate()
                    .all(|(j, e)| fold_of(&e.gate, k as u32, j) == Some(folds[j].1));
            if !same {
                return Err(shape(format!(
                    "gate list {k} is not the halving list {first} again"
                )));
            }
        }
        if a.layer_vars(a.depth()) != 0 {
            return Err(shape("the top layer has variables".to_string()));
        }
        for (j, (_, fold)) in folds.iter().enumerate() {
            if let Fold::Cross { den } = fold {
                if folds.get(*den).map(|(_, f)| *f) != Some(Fold::Product) {
                    return Err(shape(format!(
                        "halving gate {j}'s denominator {den} is not a product"
                    )));
                }
            }
        }
        Ok(Rows {
            challenges,
            layout,
            kinds,
            steps,
            scratch: a.scratch.len(),
            widest,
            folds,
        })
    }

    /// Rows `range`, in order: the folded halving inputs, or the first
    /// violation's row and relation.
    fn block(&self, range: std::ops::Range<usize>) -> Result<Vec<Fp2>, (usize, usize)> {
        let mut committed = vec![Fp2::ZERO; self.layout.len()];
        let mut virtuals = vec![Fp2::ZERO; self.kinds.len()];
        let mut scratch = vec![Fp2::ZERO; self.scratch];
        let mut values = vec![Fp2::ZERO; self.widest];
        let mut here = vec![Fp2::ZERO; self.folds.len()];
        let mut next = vec![Fp2::ZERO; self.folds.len()];
        let mut acc: Option<Vec<Fp2>> = None;
        for row in range {
            for (value, column) in committed.iter_mut().zip(&self.layout) {
                *value = column.get(row);
            }
            for (value, kind) in virtuals.iter_mut().zip(&self.kinds) {
                *value = virtual_at_row(*kind, row).into();
            }
            let mut broken: Option<usize> = None;
            for step in &self.steps {
                for (value, src) in values.iter_mut().zip(&step.sources) {
                    *value = match *src {
                        Src::Committed(i) => committed[i],
                        Src::Virtual(i) => virtuals[i],
                        Src::Scratch(i) => scratch[i],
                    };
                }
                let value = eval_gate(step.gate, &values[..step.sources.len()], self.challenges);
                match step.output {
                    Some(i) => scratch[i] = value,
                    None if value != Fp2::ZERO => {
                        broken = Some(broken.map_or(step.relation, |r| r.min(step.relation)));
                    }
                    None => {}
                }
            }
            if let Some(relation) = broken {
                return Err((row, relation));
            }
            for (value, (slot, _)) in here.iter_mut().zip(&self.folds) {
                *value = scratch[*slot];
            }
            match acc.as_mut() {
                None => acc = Some(here.clone()),
                Some(acc) => {
                    self.combine(acc, &here, &mut next);
                    std::mem::swap(acc, &mut next);
                }
            }
        }
        Ok(acc.expect("a block has a row"))
    }

    /// Two folds combined into `out`, at every offset as the halving gates
    /// combine two rows: exact field arithmetic, associative and commutative,
    /// so the order of the rows reaches no value.
    fn combine(&self, a: &[Fp2], b: &[Fp2], out: &mut [Fp2]) {
        for (j, (value, (_, fold))) in out.iter_mut().zip(&self.folds).enumerate() {
            *value = match *fold {
                Fold::Product => a[j] * b[j],
                Fold::Cross { den } => a[j] * b[den] + b[j] * a[den],
            };
        }
    }
}

/// A shard's witness against its circuit: `a.outputs` evaluated over `base`,
/// every row checked on the way.
///
/// On every row, every row-local relation of the flat list is evaluated
/// through the kernel `gkr::eval_gate`, in [`crate::violated_relations`]'
/// order: a producing one written into its scratch slot, an enforcing one
/// required to vanish. So every row, padding rows among them, is held to the
/// family's gates. Then the halving lists, whose gates combine two rows at one
/// offset — a `TreeProduct` by `a·b`, a `TreeCross` by `n_a·d_b + n_b·d_a`
/// over its denominator's offset — are folded over the rows in order instead
/// of halved: the combinations are exact and associative, so the fold is the
/// tree's top, the memory roots and every channel's `(num, den)` pair, as the
/// verifier reads them off a proof's outputs. Rows are split over rayon in
/// blocks; nothing is materialized but each block's buffers.
///
/// Refuses the lowest row breaking a relation, naming the first it breaks in
/// relation order; and an artifact whose halving lists do not each keep their
/// columns' offsets, or a base not shaped to it, as [`RowFailure::Shape`].
///
/// Does NOT cover: what the outputs must satisfy — a channel holding
/// (`gkr::channel_holds`), the roots reconciling (`gkr::reconciles`), which
/// the caller checks; whether the circuit's layered gates are its flat list,
/// which construction and [`crate::check_laws`] hold; the laws and the lookup
/// rules, which it assumes.
pub fn evaluate_rows(
    a: &CircuitArtifact,
    base: &BaseLayer,
    challenges: &ExternalChallenges,
) -> Result<Vec<Fp2>, RowFailure> {
    let rows = Rows::new(a, base, challenges)?;
    let n = 1usize << a.trace_vars;
    let blocks: Vec<Result<Vec<Fp2>, (usize, usize)>> = (0..n.div_ceil(BLOCK))
        .into_par_iter()
        .map(|b| rows.block(b * BLOCK..n.min((b + 1) * BLOCK)))
        .collect();
    let mut top: Option<Vec<Fp2>> = None;
    for block in blocks {
        match block {
            Err((row, r)) => {
                return Err(RowFailure::Relation {
                    row,
                    relation: a.relations[r].name.clone(),
                })
            }
            Ok(fold) => {
                top = Some(match top {
                    None => fold,
                    Some(top) => {
                        let mut out = vec![Fp2::ZERO; top.len()];
                        rows.combine(&top, &fold, &mut out);
                        out
                    }
                })
            }
        }
    }
    let top = top.expect("a shard has a row");
    a.outputs
        .iter()
        .map(|output| match *output {
            PolyAddress::Inner { layer, offset }
                if layer as usize == a.depth() && (offset as usize) < top.len() =>
            {
                Ok(top[offset as usize])
            }
            other => Err(RowFailure::Shape(format!(
                "output {other} is not a column of the top layer"
            ))),
        })
        .collect()
}
