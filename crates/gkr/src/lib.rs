//! The prover half of the GKR engine: the forward pass, which materializes
//! every layer from the committed base; its self-check, which recomputes every
//! gate from those layers so a broken gate is caught before proving; and the
//! backward pass, which proves the output claims down to claims about the base.
//!
//! `docs/spec/gkr.md` specifies it. The verifier half is `crates/gkr-verify`,
//! re-exported here whole, so `gkr::verify` and `gkr::GkrProof` are its. Every
//! gate is evaluated through a `gkr_verify::ResolvedList`, the resolution
//! `gate_values` and `summand` go through, so the same `G` serves the forward
//! and the backward pass.
//!
//! Per-row work — a gate list's rows, a round's row pairs — is split over
//! rayon. Field arithmetic is exact, so no split and no reduction order can
//! change a value. Nothing is allocated per row, per row pair or per node:
//! each rayon task owns its buffers and overwrites them. And nothing is copied
//! to be read: a gate reads each operand where it is held — in its column, in a
//! row of layer 0 lifted once, or in a round's line — and no layer is copied to
//! be bound.
//!
//! Nothing here checks its inputs at run time. The artifact is assumed to have
//! passed `CircuitArtifact::validate` where its key is loaded, and the base, the
//! layer values, the tables and the challenge slots to have the artifact's
//! shape. Soundness is `verify`'s alone — a cheating prover runs none of this
//! code — so a malformed input can only cost the honest prover: a panic when a
//! missing column or slot is read, or a proof or base claims that fail
//! downstream. Shape checks are kept, uncalled, as debugging aids:
//! `check_slots` and the functions beside it.

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
/// not here. [`prove`] consumes it, a layer at a time.
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

/// What gate list `k` reads, row by row: layer `k`'s columns, read where they
/// are held, and for list 0 the virtual tables' closed forms, which no other
/// list reads (Law 1).
///
/// **Only a row of layer 0 is lifted first.** Its columns are narrow — bits,
/// bytes, words — and list 0's gates read each one about six times a row, so
/// each is lifted to `Fr` once per row into a buffer of the rayon task's own,
/// beside the virtual tables' values. Every layer above is `Fr` already, and
/// its gates read each column about one and a half times a row: they read it
/// where the forward pass wrote it, and no row of it is copied.
struct RowReader<'v> {
    columns: Vec<&'v MultilinearPoly>,
    /// List 0's: whether rows are lifted, and the virtual tables it lists.
    lifted: bool,
    kinds: Vec<VirtualKind>,
    /// The rows the list defines: layer `k`'s, or half of them for a halving
    /// list, whose row `i` reads rows `i` and `i + rows` of layer `k`.
    rows: usize,
}

/// One rayon task's row of layer 0, lifted, overwritten row after row: one
/// value per column and per virtual table. Empty above layer 0.
struct LiftedRow {
    columns: Vec<Fr>,
    virtuals: Vec<Fr>,
}

impl<'v> RowReader<'v> {
    fn new(
        artifact: &CircuitArtifact,
        base: &'v BaseLayer,
        layers: &'v [Vec<MultilinearPoly>],
        k: usize,
    ) -> RowReader<'v> {
        let rows_in = 1usize << artifact.layer_vars(k);
        RowReader {
            columns: layer_columns(artifact, base, layers, k),
            lifted: k == 0,
            kinds: match k {
                0 => artifact.virtuals.iter().map(|(kind, _)| *kind).collect(),
                _ => Vec::new(),
            },
            rows: match artifact.layers[k].halving {
                true => rows_in / 2,
                false => rows_in,
            },
        }
    }

    /// A task's buffer for [`RowReader::lift`]: a row of layer 0, or nothing.
    fn row(&self) -> LiftedRow {
        let width = if self.lifted { self.columns.len() } else { 0 };
        LiftedRow {
            columns: vec![Fr::ZERO; width],
            virtuals: vec![Fr::ZERO; self.kinds.len()],
        }
    }

    /// Row `y` of layer 0 into `row`, each column lifted once and each virtual
    /// table at its closed form. Nothing above layer 0.
    fn lift(&self, y: usize, row: &mut LiftedRow) {
        if !self.lifted {
            return;
        }
        for (column, value) in self.columns.iter().zip(row.columns.iter_mut()) {
            *value = column.get(y);
        }
        // A virtual table is never materialized: its closed form, per row.
        for (kind, value) in self.kinds.iter().zip(row.virtuals.iter_mut()) {
            *value = virtual_at_row(*kind, y);
        }
    }

    /// Operand `op` at row `y`: out of the lifted row at layer 0, out of its
    /// column above it — child 1 of a halving list's row `y` being the
    /// column's row `y + rows`.
    fn read(&self, op: Operand, y: usize, row: &LiftedRow) -> Fr {
        match (self.lifted, op) {
            (true, Operand::Lower(x)) => row.columns[x],
            (true, Operand::Virtual(x)) => row.virtuals[x],
            (false, Operand::Lower(x)) => self.columns[x].get(y),
            (false, Operand::Upper(x)) => self.columns[x].get(y + self.rows),
            (_, other) => panic!("a validated gate list cannot read {other:?} at its layer"),
        }
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
        || reader.row(),
        |row, (b, mut block)| {
            for i in 0..block[0].len() {
                let y = b * BLOCK + i;
                reader.lift(y, row);
                let read = |op: Operand| reader.read(op, y, row);
                for (j, column) in block.iter_mut().enumerate() {
                    column[i] = resolved.gate(j, &read);
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
                || reader.row(),
                |row, b| {
                    for y in b * BLOCK..rows.min((b + 1) * BLOCK) {
                        reader.lift(y, row);
                        let read = |op: Operand| reader.read(op, y, row);
                        for (j, column) in written.iter().enumerate().take(producing) {
                            if resolved.gate(j, &read) != column.get(y) {
                                return Some((y, j));
                            }
                        }
                        for j in producing..producing + enforcing {
                            if resolved.gate(j, &read) != Fr::ZERO {
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

/// A [`self_check`] failure, explained: the gate that disagrees, and every
/// value it read to get there.
///
/// [`SelfCheckError`] names the gate list, the row and the relation, which is
/// enough to find the constraint in `checker dump` and not enough to see *why*
/// it failed. This returns the rest: the gate's operands, each by address, by
/// the name the artifact gives that column, and by its value at that row; and
/// the two sides of the disagreement — what the gate computes against what the
/// forward pass wrote, or against the zero an enforcing gate owes.
///
/// It is what closes the distance between cause and symptom. A wrong fill, a
/// frame value at or above its modulus, a gated conclusion written
/// `b = enable` where it had to be `enable · (1 − b) = 0`, all reach a reader
/// of `verify`'s error as one layer number; each of them reaches a reader
/// through this as a named relation whose `live` column is 1 and whose borrow
/// column is 0.
///
/// **Recomputes exactly one row**, so it costs nothing worth measuring and may
/// be called on any failure. It finds the failing gate itself rather than
/// taking one, because `SelfCheckError` does not carry the gate index and this
/// way the two never disagree. Returns the lines to print, outermost first;
/// an empty vector means the row no longer disagrees, which can only happen if
/// `values` is not the `values` the failure came from.
///
/// Compiled unconditionally, and called from `prover`'s `debug-info` build.
/// `crates/gkr/tests/explain.rs` is what keeps it honest in the default build,
/// which every run exercises.
pub fn explain_self_check(
    artifact: &CircuitArtifact,
    values: &LayerValues,
    challenges: &ExternalChallenges,
    failure: &SelfCheckError,
) -> Vec<String> {
    let (k, y) = (failure.layer, failure.row);
    if k >= artifact.depth() {
        return vec![format!(
            "explain: layer {k} is outside a circuit of depth {}",
            artifact.depth()
        )];
    }
    let list = &artifact.layers[k];
    let reader = RowReader::new(artifact, &values.base, &values.layers, k);
    if y >= reader.rows {
        return vec![format!(
            "explain: row {y} is outside gate list {k}'s {} rows",
            reader.rows
        )];
    }
    let resolved = ResolvedList::new(artifact, k, challenges);
    let mut row = reader.row();
    reader.lift(y, &mut row);
    let read = |op: Operand| reader.read(op, y, &row);
    let (producing, enforcing) = (resolved.producing(), resolved.enforcing());
    let written = &values.layers[k];

    // The first disagreement, in `self_check`'s own order: the producing gates
    // of the row before its enforcing ones.
    let mut failing = None;
    for (j, column) in written.iter().enumerate().take(producing) {
        let value = resolved.gate(j, &read);
        if value != column.get(y) {
            failing = Some((j, value, Some(column.get(y))));
            break;
        }
    }
    if failing.is_none() {
        for j in producing..producing + enforcing {
            let value = resolved.gate(j, &read);
            if value != Fr::ZERO {
                failing = Some((j, value, None));
                break;
            }
        }
    }
    let (j, computed, expected) = match failing {
        Some(f) => f,
        None => return Vec::new(),
    };

    let (gate, relation) = if j < producing {
        (&list.producing[j].gate, list.producing[j].relation)
    } else {
        let e = &list.enforcing[j - producing];
        (&e.gate, e.relation)
    };
    let name = artifact
        .relations
        .get(relation as usize)
        .map_or("<no such relation>", |r| r.name.as_str());
    let kind = if j < producing {
        "producing"
    } else {
        "enforcing"
    };
    let mut out = vec![format!(
        "gate list {k} row {y}: {kind} gate {j}, relation {relation} {name}"
    )];
    out.push(match expected {
        Some(w) => format!(
            "  computed {} but the layer holds {}",
            show(computed),
            show(w)
        ),
        None => format!(
            "  computed {}, and an enforcing gate owes 0",
            show(computed)
        ),
    });

    // Every operand, in the kernel's own value order, so the line numbers line
    // up with the formula `checker dump` prints for the same relation.
    let halving = list.halving;
    for op in gate.operands() {
        let label = operand_name(artifact, k, &op);
        match op {
            PolyAddress::Virtual(kind) => {
                let i = artifact
                    .virtuals
                    .iter()
                    .position(|(v, _)| *v == kind)
                    .expect("a validated artifact lists every virtual table it reads");
                out.push(format!(
                    "  {op} = {}   {label}",
                    show(read(Operand::Virtual(i)))
                ));
            }
            PolyAddress::Cached { offset, .. } => {
                out.push(format!(
                    "  {op} = {}   {label}",
                    show(resolved.cached(offset as usize, &read))
                ));
            }
            other => {
                let i = explain_column_index(artifact, k, &other);
                if halving {
                    out.push(format!(
                        "  {op} = ({}, {})   {label}, the two children",
                        show(read(Operand::Lower(i))),
                        show(read(Operand::Upper(i)))
                    ));
                } else {
                    out.push(format!(
                        "  {op} = {}   {label}",
                        show(read(Operand::Lower(i)))
                    ));
                }
            }
        }
    }
    out
}

/// An `Fr` as a debugging line wants it: a small value in decimal, anything
/// else as its 32 canonical bytes in hex, **in `to_bytes` order**.
///
/// Decimal for a small value because most of what a failing gate reads is a
/// bit, a limb, a row index or a count, and `1` reads better than 56 zeros and
/// a digit. `to_bytes` order for the rest because that is the one encoding this
/// repository puts on a wire, and `prover`'s debug log prints field elements
/// the same way, so a value here greps against a value there.
fn show(x: Fr) -> String {
    let le = x.to_bytes();
    // Below 2^32: the canonical little-endian bytes above the low four are 0.
    if le[4..].iter().all(|b| *b == 0) {
        return format!("{}", u32::from_le_bytes([le[0], le[1], le[2], le[3]]));
    }
    le.iter().map(|b| format!("{b:02x}")).collect()
}

/// What the artifact calls the column an operand names.
///
/// A committed column has a name of its own. An inner column does not — it is a
/// gate's output — so it is named by **the relation that wrote it**, which is
/// what makes a failure at layer 9 of a deep circuit legible at all.
fn operand_name(artifact: &CircuitArtifact, k: usize, op: &PolyAddress) -> String {
    match *op {
        PolyAddress::Memory(i) => artifact
            .memory
            .get(i as usize)
            .cloned()
            .unwrap_or_else(|| "<unnamed>".to_string()),
        PolyAddress::Witness(i) => artifact
            .witness
            .get(i as usize)
            .cloned()
            .unwrap_or_else(|| "<unnamed>".to_string()),
        PolyAddress::Setup(i) => artifact
            .setup
            .get(i as usize)
            .cloned()
            .unwrap_or_else(|| "<unnamed>".to_string()),
        PolyAddress::Virtual(_) => "virtual table".to_string(),
        PolyAddress::Cached { layer, offset } => artifact
            .layers
            .get(layer as usize)
            .and_then(|l| l.cached.get(offset as usize))
            .map_or_else(|| "<unnamed>".to_string(), |e| e.name.clone()),
        PolyAddress::Inner { layer, offset } => {
            // Layer `layer` is written by gate list `layer - 1`.
            let written_by = (layer as usize)
                .checked_sub(1)
                .and_then(|list| artifact.layers.get(list))
                .and_then(|l| l.producing.get(offset as usize))
                .and_then(|e| artifact.relations.get(e.relation as usize));
            match written_by {
                Some(r) => format!("written by {}", r.name),
                None => "<no producing gate>".to_string(),
            }
        }
        PolyAddress::Scratch(i) => {
            let _ = k;
            artifact
                .scratch
                .get(i as usize)
                .map_or_else(|| "<unnamed>".to_string(), |slot| slot.name.clone())
        }
    }
}

/// Where a column operand of gate list `k` sits in layer `k`'s value order.
///
/// A deliberate literal duplicate of `gkr_verify`'s own `column_index`, which
/// is private to that crate and on its hottest path. Keeping this copy beside
/// the one caller that needs it costs eight lines; making the original public
/// would widen the verifier half's API for a debugging aid.
fn explain_column_index(artifact: &CircuitArtifact, k: usize, op: &PolyAddress) -> usize {
    let (m, w) = (artifact.memory.len(), artifact.witness.len());
    match *op {
        PolyAddress::Memory(i) => i as usize,
        PolyAddress::Witness(i) => m + i as usize,
        PolyAddress::Setup(i) => m + w + i as usize,
        PolyAddress::Inner { offset, .. } => offset as usize,
        other => panic!("gate list {k} of a validated artifact cannot read {other} as a column"),
    }
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

/// One column of layer `k` as transition `k`'s sumcheck binds it, at the
/// column's own height. A halving list's child 0 is the column's low half and
/// child 1 its high half: the child bit is the highest variable, so binding the
/// low variables binds both children at once and the column is never split.
/// Virtual tables are not tables here: they are never materialized, and the
/// driver evaluates their closed form where it needs one.
pub enum LayerTable<'v> {
    /// A committed column, read where the base holds it until its first bind
    /// folds it into a half-size table of its own. The base is never written.
    Base(&'v MultilinearPoly),
    /// A column the sumcheck owns — an inner layer's, taken from the forward
    /// pass, or a base column after its first bind — bound in place.
    Owned(MultilinearPoly),
}

impl LayerTable<'_> {
    fn column(&self) -> &MultilinearPoly {
        match self {
            LayerTable::Base(column) => column,
            LayerTable::Owned(column) => column,
        }
    }

    fn bind(&mut self, r: Fr) {
        match self {
            LayerTable::Base(column) => *self = LayerTable::Owned(column.bound(r)),
            LayerTable::Owned(column) => column.bind(r),
        }
    }
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
/// d3·X(X-1)(X-2)/6`, expanded — the sumcheck's `interpolate_cubic`, which is
/// private to `crates/sumcheck`.
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
/// which the gates read at each node in place, and the point a virtual table's
/// closed form is evaluated at.
struct PairScratch {
    lower: Vec<Fr>,
    lower_step: Vec<Fr>,
    upper: Vec<Fr>,
    upper_step: Vec<Fr>,
    virtuals: Vec<Fr>,
    virtuals_step: Vec<Fr>,
    /// The round's bound challenges first; the rest is written per pair.
    point: Vec<Fr>,
}

/// The line `lo + X·(hi − lo)` of pair `i` of every table, into `lo` and `step`,
/// the pair read `offset` rows into each table: 0 for a row-wise list's columns
/// and a halving list's child 0, the child's length for its child 1.
fn lines(tables: &[LayerTable], offset: usize, i: usize, lo: &mut [Fr], step: &mut [Fr]) {
    for (t, (lo, step)) in tables.iter().zip(lo.iter_mut().zip(step.iter_mut())) {
        let column = t.column();
        *lo = column.get(offset + 2 * i);
        *step = column.get(offset + 2 * i + 1) - *lo;
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
/// given — layer `k`'s columns in its value order, a row-wise list's with the
/// eq point's variable count and a halving list's with one more, the child
/// bit — one cubic per variable of the eq point, each absorbed as
/// `SUMCHECK_ROUND` and followed by the `SUMCHECK_CHALLENGE` that binds it.
/// Returns the rounds and the bound point; every table is left bound to it,
/// one value each, or a halving list's two: child 0, then child 1.
///
/// The claim itself is not an input: an honest round 0 sums to it by
/// construction, and a claim the tables do not support is the verifier's to
/// reject.
pub fn prove_sumcheck(
    eq_point: &[Fr],
    summand: &LayerSummand,
    tables: &mut [LayerTable],
    t: &mut Transcript,
) -> (Vec<[Fr; 4]>, Vec<Fr>) {
    let n = eq_point.len();
    let artifact = summand.artifact;
    let halving = artifact.layers[summand.layer].halving;
    // Only list 0 reads a virtual table (Law 1), and it is row-wise.
    let kinds: Vec<VirtualKind> = match summand.layer {
        0 => artifact.virtuals.iter().map(|(kind, _)| *kind).collect(),
        _ => Vec::new(),
    };
    // A debugging aid, not a runtime check (see `check_slots`). Without it a
    // table shorter than its list needs panics on a read past its end, and a
    // taller one is read only in part.
    // for table in tables.iter() {
    //     assert_eq!(
    //         table.column().num_vars(),
    //         n + halving as usize,
    //         "prove_sumcheck: a table has {} variables, the eq point {n}",
    //         table.column().num_vars()
    //     );
    // }
    let resolved = ResolvedList::new(artifact, summand.layer, summand.challenges);
    let mut eq = fr_poly(eq_table(eq_point));
    let constants = interpolation_constants();
    let width = tables.len();
    let children = if halving { width } else { 0 };
    let mut rounds = Vec::with_capacity(n);
    let mut point = Vec::with_capacity(n);
    for _ in 0..n {
        let half = eq.len() / 2;
        let bound = point.len();
        // A halving column is its two children end to end, each as long as
        // the eq table: child 1's pairs start that far in.
        let child = eq.len();
        let read: &[LayerTable] = tables;
        let at_nodes = (0..half)
            .into_par_iter()
            .map_init(
                || {
                    let mut at = vec![Fr::ZERO; n];
                    at[..bound].copy_from_slice(&point);
                    PairScratch {
                        lower: vec![Fr::ZERO; width],
                        lower_step: vec![Fr::ZERO; width],
                        upper: vec![Fr::ZERO; children],
                        upper_step: vec![Fr::ZERO; children],
                        virtuals: vec![Fr::ZERO; kinds.len()],
                        virtuals_step: vec![Fr::ZERO; kinds.len()],
                        point: at,
                    }
                },
                |s, i| {
                    lines(read, 0, i, &mut s.lower, &mut s.lower_step);
                    if halving {
                        lines(read, child, i, &mut s.upper, &mut s.upper_step);
                    }
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
                                &read_slices(&s.lower, &s.upper, &s.virtuals),
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
        for table in tables.iter_mut() {
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
/// **Consumes the forward pass.** Each inner layer is read by one transition
/// alone, so its columns are taken from `values`, bound in place and dropped
/// once that transition is proven: the backward pass copies no layer, and what
/// it holds shrinks as it descends. The base is shared with the caller and only
/// read; each of its columns becomes a half-size table of the transition's own
/// at its first bind.
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
    values: LayerValues,
    challenges: &ExternalChallenges,
    t: &mut Transcript,
) -> GkrProof {
    // Debugging aids, not runtime checks (see `check_slots`):
    // check_slots(artifact, challenges, "gkr::prove");
    // check_values(artifact, &values, "gkr::prove");
    let depth = artifact.depth();
    let LayerValues { base, mut layers } = values;

    // O1: the top has no variables (Law 3), so each output is its column's
    // one value, claimed at the empty point. Nothing reads the top again.
    let top = layers.pop().expect("a circuit has a top layer");
    let mut message: Vec<Fr> = Vec::new();
    for out in &artifact.outputs {
        if let PolyAddress::Inner { offset, .. } = *out {
            message.push(top[offset as usize].get(0));
        }
    }
    drop(top);
    t.append_scalars(transcript_tags::GKR_OUTPUTS, &message);
    let mut point: Vec<Fr> = Vec::new();

    let mut proofs: Vec<Option<SumcheckProof>> = vec![None; depth];
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

        // L2: layer `k`'s columns, bound where they are. An inner layer's are
        // the forward pass's own, the last layer it still holds; the base's
        // are read in place.
        let mut tables: Vec<LayerTable> = if k == 0 {
            artifact
                .committed()
                .iter()
                .map(|a| {
                    LayerTable::Base(
                        base.get(*a)
                            .unwrap_or_else(|| panic!("the base has no column {a}")),
                    )
                })
                .collect()
        } else {
            layers
                .pop()
                .expect("one layer per gate list")
                .into_iter()
                .map(LayerTable::Owned)
                .collect()
        };
        let (rounds, rho) = prove_sumcheck(&point, &summand, &mut tables, t);

        // L3: every table is bound to rho: one value each, or a halving
        // column's two, child 0 then child 1. The layer goes with its tables.
        let final_evals: Vec<Fr> = if list.halving {
            tables
                .iter()
                .flat_map(|c| [c.column().get(0), c.column().get(1)])
                .collect()
        } else {
            tables.iter().map(|c| c.column().get(0)).collect()
        };
        drop(tables);
        t.append_scalars(transcript_tags::GKR_LAYER_CLAIMS, &final_evals);

        // L4.
        point = rho;
        if list.halving {
            point.push(t.challenge_scalar(transcript_tags::GKR_CHILD));
        }
        proofs[k] = Some(SumcheckProof {
            rounds,
            final_evals,
        });
    }

    GkrProof {
        layers: proofs
            .into_iter()
            .map(|l| l.expect("every transition was proven"))
            .collect(),
    }
}
