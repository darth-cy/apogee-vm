//! One assembly for every circuit built in this crate: a set of **trees** over
//! gate list 0's columns, reduced pairwise by row-wise lists until each is at
//! its combine's width, then `trace_vars` halving lists down to a
//! zero-variable top whose columns are the roots.
//!
//! A tree is a *product* tree, whose combine is multiplication and whose
//! identity is 1 (`docs/spec/memory.md` §2.3), or a *fraction* tree, whose
//! columns come in `(num, den)` pairs, whose combine is
//! `a/b + c/d = (ad + cb)/(bd)` and whose identity is `(0, 1)`
//! (`docs/spec/lookup.md` §6). Trees of unequal depth are levelled with copy
//! gates so that every one reaches the halving phase together.
//!
//! The flat relation list and the scratch bijection mirror every gate, list by
//! list and column by column, producing before enforcing.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use field::Fr;

use crate::{
    CircuitArtifact, Coeff, EnforcingEntry, GateDef, LayerSpec, LookupExpr, Padding, PolyAddress,
    ProducingEntry, Relation, ScratchSlot, VirtualKind, COEFFICIENT_ENCODING_CANONICAL_LE,
    FORMAT_VERSION,
};

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn inner(layer: u32, offset: u32) -> PolyAddress {
    PolyAddress::Inner { layer, offset }
}

/// How a tree's siblings combine, which fixes its width per node, its gates
/// and the identity an idle level copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Combine {
    /// One column per node: `out = a·b`, halving as `TreeProduct`.
    Product,
    /// Two columns per node, `num` then `den`:
    /// `out = (num_a·den_b + num_b·den_a, den_a·den_b)`, halving as
    /// `TreeCross` over the pair and `TreeProduct` over the denominator.
    Fraction,
}

impl Combine {
    /// The columns one node of this tree occupies.
    fn width(self) -> usize {
        match self {
            Combine::Product => 1,
            Combine::Fraction => 2,
        }
    }
}

/// One tree of a circuit: its combine, the columns gate list 0 writes for its
/// leaves, and the prefix its inner nodes are named with.
pub(crate) struct Tree {
    pub combine: Combine,
    /// `(name, gate)` per column of the leaf level, in column order: one per
    /// leaf for a product tree, `num` then `den` per leaf for a fraction tree.
    /// The leaf count is a power of two.
    pub leaves: Vec<(String, GateDef)>,
    /// `<prefix>_<layer>_<i>` names an inner node, `<prefix>_root` a product
    /// tree's root and `<prefix>_num_root` / `<prefix>_den_root` a fraction
    /// tree's.
    pub prefix: String,
}

impl Tree {
    /// The tree's leaf count: its column count divided by its node width.
    fn leaf_count(&self) -> usize {
        self.leaves.len() / self.combine.width()
    }

    /// How many row-wise lists reduce this tree to one node.
    fn depth(&self) -> u32 {
        self.leaf_count().trailing_zeros()
    }

    /// The columns of node `i` at `layer`, named.
    fn node_names(&self, layer: u32, i: usize, top: bool) -> Vec<String> {
        let p = &self.prefix;
        match (self.combine, top) {
            (Combine::Product, true) => vec![format!("{p}_root")],
            (Combine::Product, false) => vec![format!("{p}_{layer}_{i}")],
            (Combine::Fraction, true) => vec![format!("{p}_num_root"), format!("{p}_den_root")],
            (Combine::Fraction, false) => {
                vec![
                    format!("{p}_{layer}_{i}_num"),
                    format!("{p}_{layer}_{i}_den"),
                ]
            }
        }
    }
}

/// One producing gate, in both encodings: over inner addresses for the layered
/// list and over scratch addresses for the flat one.
struct Written {
    name: String,
    gate: GateDef,
    flat: GateDef,
}

/// `a·b` over the two addresses a mapper produces.
fn product(a: PolyAddress, b: PolyAddress) -> GateDef {
    GateDef::Product {
        coeff: lit(1),
        left: a,
        right: b,
    }
}

/// `num_a·den_b + num_b·den_a`.
fn cross(
    num_a: PolyAddress,
    den_a: PolyAddress,
    num_b: PolyAddress,
    den_b: PolyAddress,
) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear: Vec::new(),
        products: vec![(lit(1), num_a, den_b), (lit(1), num_b, den_a)],
    }
}

/// `x`, copied one layer up.
fn copy(x: PolyAddress) -> GateDef {
    GateDef::Linear {
        terms: vec![(lit(1), x)],
        constant: lit(0),
    }
}

/// The columns one row-wise list writes for `tree`, given its columns at the
/// layer below. `columns` is that tree's slice of layer `k`, and `k` the layer
/// being written.
fn reduce(tree: &Tree, columns: &[PolyAddress], layer: u32, top: bool) -> Vec<Written> {
    let w = tree.combine.width();
    let nodes = columns.len() / w;
    // A tree already at one node copies itself up, so every tree reaches the
    // halving phase at the same layer.
    let (out_nodes, idle) = if nodes == 1 {
        (1, true)
    } else {
        (nodes / 2, false)
    };
    let mut out = Vec::new();
    for i in 0..out_nodes {
        let names = tree.node_names(layer, i, top);
        let gates: Vec<GateDef> = match (tree.combine, idle) {
            (_, true) => columns.iter().map(|x| copy(*x)).collect(),
            (Combine::Product, false) => vec![product(columns[2 * i], columns[2 * i + 1])],
            (Combine::Fraction, false) => {
                let (a, b) = (4 * i, 4 * i + 2);
                vec![
                    cross(columns[a], columns[a + 1], columns[b], columns[b + 1]),
                    product(columns[a + 1], columns[b + 1]),
                ]
            }
        };
        for (name, gate) in names.into_iter().zip(gates) {
            out.push(Written {
                name,
                flat: gate.clone(),
                gate,
            });
        }
    }
    out
}

/// The columns one halving list writes for `tree`: `TreeProduct` of each
/// column of a product tree, and `TreeCross` over the pair then `TreeProduct`
/// of the denominator for a fraction tree.
fn halve(tree: &Tree, columns: &[PolyAddress], layer: u32, top: bool) -> Vec<Written> {
    let names = tree.node_names(layer, 0, top);
    let gates: Vec<GateDef> = match tree.combine {
        Combine::Product => vec![GateDef::TreeProduct { input: columns[0] }],
        Combine::Fraction => vec![
            GateDef::TreeCross {
                left: columns[0],
                right: columns[1],
            },
            GateDef::TreeProduct { input: columns[1] },
        ],
    };
    names
        .into_iter()
        .zip(gates)
        .map(|(name, gate)| Written {
            name,
            flat: gate.clone(),
            gate,
        })
        .collect()
}

/// A whole circuit, as a struct literal of complete vectors.
///
/// `layout` is the `M`, `W`, `S` names and `virtuals` the tables gate list 0
/// reads. `trees` are the circuit's trees in output order; gate list 0 writes
/// their leaves, in tree order, beside `enforcing`, its enforcing gates. Then
/// row-wise lists reduce every tree to one node, `trace_vars` halving lists
/// bring it to a zero-variable top, and `outputs` is that top in tree order.
/// The padding row is all zeros, and `zero_row_valid` is decided by
/// `zero_on_zero_row` over the enforcing gates.
///
/// Validates and panics on refusal: an artifact this returns is a circuit.
/// The caller runs whatever further construction rules it owns.
pub(crate) fn assemble(
    trace_vars: u32,
    layout: [Vec<String>; 3],
    virtuals: Vec<(VirtualKind, String)>,
    trees: Vec<Tree>,
    enforcing: Vec<(String, GateDef)>,
    lookups: Vec<LookupExpr>,
    zero_row_valid: bool,
) -> CircuitArtifact {
    assert!(!trees.is_empty(), "a circuit has at least one tree");
    for tree in &trees {
        let leaves = tree.leaf_count();
        assert!(
            leaves.is_power_of_two() && tree.leaves.len() == leaves * tree.combine.width(),
            "tree `{}`: {} columns is not a power of two of {}-column nodes",
            tree.prefix,
            tree.leaves.len(),
            tree.combine.width()
        );
    }
    // The row-wise phase is as deep as the deepest tree; every shallower one
    // copies itself up to meet it.
    let reduction = trees.iter().map(Tree::depth).max().expect("a tree");
    let depth = 1 + reduction + trace_vars;

    let mut relations: Vec<Relation> = Vec::new();
    let mut scratch: Vec<ScratchSlot> = Vec::new();
    let mut layers: Vec<LayerSpec> = Vec::new();

    // Gate list 0: every tree's leaves, then the enforcing gates.
    let leaves: Vec<Written> = trees
        .iter()
        .flat_map(|t| t.leaves.iter())
        .map(|(name, gate)| Written {
            name: name.clone(),
            gate: gate.clone(),
            flat: gate.clone(),
        })
        .collect();
    let mut written: Vec<Vec<PolyAddress>> = Vec::new();
    push_list(
        &mut layers,
        &mut relations,
        &mut scratch,
        &mut written,
        1,
        false,
        trace_vars,
        leaves,
        enforcing,
    );

    // The row-wise reduction, then the halving phase. `widths` tracks each
    // tree's window of the layer below, which shrinks as it reduces.
    let mut widths: Vec<usize> = trees.iter().map(|t| t.leaves.len()).collect();
    let mut vars = trace_vars;
    for k in 1..depth {
        let halving = k > reduction;
        if halving {
            vars -= 1;
        }
        let below = &written[k as usize - 1];
        let top = k + 1 == depth;
        let mut at = 0;
        let mut produced: Vec<Written> = Vec::new();
        for (tree, width) in trees.iter().zip(widths.iter_mut()) {
            let columns = &below[at..at + *width];
            at += *width;
            let up = if halving {
                halve(tree, columns, k + 1, top)
            } else {
                reduce(tree, columns, k + 1, top)
            };
            *width = up.len();
            produced.extend(up);
        }
        assert_eq!(
            at,
            below.len(),
            "every column of layer {k} belongs to a tree"
        );
        push_list(
            &mut layers,
            &mut relations,
            &mut scratch,
            &mut written,
            k + 1,
            halving,
            vars,
            produced,
            Vec::new(),
        );
    }

    let [memory, witness, setup] = layout;
    let committed = memory.len() + witness.len() + setup.len();
    let artifact = CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars,
        memory,
        witness,
        setup,
        virtuals,
        layers,
        relations,
        lookups,
        scratch,
        outputs: written[depth as usize - 1].clone(),
        padding: Padding {
            row: vec![Fr::ZERO; committed],
            zero_row_valid,
        },
    };
    if let Err(e) = artifact.validate() {
        panic!("assembled circuit is not a circuit: {e}");
    }
    artifact
}

/// Push one gate list, its relations and its scratch slots, and record the
/// addresses it wrote.
#[allow(clippy::too_many_arguments)]
fn push_list(
    layers: &mut Vec<LayerSpec>,
    relations: &mut Vec<Relation>,
    scratch: &mut Vec<ScratchSlot>,
    written: &mut Vec<Vec<PolyAddress>>,
    layer: u32,
    halving: bool,
    num_vars: u32,
    producing: Vec<Written>,
    enforcing: Vec<(String, GateDef)>,
) {
    // The flat encoding names the layer below through the scratch bijection,
    // which the previous lists have already filled.
    let below: Vec<PolyAddress> = scratch.iter().map(|s| s.address).collect();
    let slot_of = |address: PolyAddress| -> PolyAddress {
        let i = below
            .iter()
            .position(|a| *a == address)
            .expect("an inner column already has its scratch slot");
        PolyAddress::Scratch(i as u32)
    };
    let mut entries = Vec::new();
    let mut addresses = Vec::new();
    for (j, w) in producing.into_iter().enumerate() {
        let output = inner(layer, j as u32);
        let mut flat = w.flat;
        if layer > 1 {
            for op in operands_mut(&mut flat) {
                *op = slot_of(*op);
            }
        }
        entries.push(ProducingEntry {
            relation: relations.len() as u32,
            output,
            gate: w.gate,
        });
        relations.push(Relation {
            name: format!("define_{}", w.name),
            output: Some(scratch.len() as u32),
            gate: flat,
        });
        scratch.push(ScratchSlot {
            name: w.name,
            address: output,
        });
        addresses.push(output);
    }
    let mut enforcing_entries = Vec::new();
    for (name, gate) in enforcing {
        enforcing_entries.push(EnforcingEntry {
            relation: relations.len() as u32,
            gate: gate.clone(),
        });
        relations.push(Relation {
            name,
            output: None,
            gate,
        });
    }
    layers.push(LayerSpec {
        halving,
        num_vars,
        width: addresses.len() as u32,
        cached: Vec::new(),
        producing: entries,
        enforcing: enforcing_entries,
    });
    written.push(addresses);
}

/// Every operand of `gate`, mutably, so a layered gate can be rewritten into
/// its flat spelling. The shapes this module builds above gate list 0 are
/// `Linear`, `Product`, `Quadratic`, `TreeProduct` and `TreeCross`; the other
/// two never reach it.
fn operands_mut(gate: &mut GateDef) -> Vec<&mut PolyAddress> {
    match gate {
        GateDef::Linear { terms, .. } => terms.iter_mut().map(|t| &mut t.1).collect(),
        GateDef::Product { left, right, .. } => vec![left, right],
        GateDef::TreeProduct { input } => vec![input],
        GateDef::TreeCross { left, right } => vec![left, right],
        GateDef::Quadratic {
            linear, products, ..
        } => {
            let mut ops: Vec<&mut PolyAddress> = linear.iter_mut().map(|t| &mut t.1).collect();
            for (_, y, z) in products.iter_mut() {
                ops.push(y);
                ops.push(z);
            }
            ops
        }
        other => panic!("assemble writes no {other:?} above gate list 0"),
    }
}

/// Whether `gate` is 0 on the all-zero committed row, for every challenge value
/// and row index: a `Linear` or `Quadratic` over committed columns is its
/// constant there. Panics on any other gate, for which `zero_row_valid` is not
/// decided.
pub(crate) fn zero_on_zero_row(name: &str, gate: &GateDef) -> bool {
    let committed = gate.operands().iter().all(|op| {
        matches!(
            op,
            PolyAddress::Memory(_) | PolyAddress::Witness(_) | PolyAddress::Setup(_)
        )
    });
    match gate {
        GateDef::Linear { constant, .. } | GateDef::Quadratic { constant, .. } if committed => {
            *constant == lit(0)
        }
        _ => panic!(
            "enforcing gate `{name}` is not a Linear or Quadratic gate over committed columns, \
             so zero_row_valid is not decided for it"
        ),
    }
}

/// The names of a tree's leaf columns, for a caller that builds its own.
pub(crate) fn name(s: &str) -> String {
    s.to_string()
}
