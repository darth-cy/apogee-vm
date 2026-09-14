//! The construction-time checks: Laws 1–4, the degree ceiling, and every
//! other rule of `docs/spec/gkr.md` §4.2 — and the cache-free compilation,
//! which is checked by the same rules on its way out.
//!
//! `crates/checker` enforces the four laws a second time with code of its own;
//! nothing here is shared with it.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;

use constants::challenge_slot;
use field::Fr;

use crate::{
    CachedEntry, CircuitArtifact, Coeff, GateDef, LayerSpec, PolyAddress,
    COEFFICIENT_ENCODING_CANONICAL_LE, FORMAT_VERSION, MAX_TRACE_VARS,
};

/// Why an artifact is not a circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConstraintError {
    /// Law 1: `gate`, in gate list `layer`, reads `operand`, which that list
    /// may not read.
    Locality {
        layer: u32,
        gate: String,
        operand: PolyAddress,
    },
    /// Law 2: layer `layer`'s stored width or variable count is not what the
    /// gates below it produce.
    DerivedWidth { layer: u32, detail: String },
    /// Law 3: the top layer is not exactly the output map.
    TopLayer { detail: String },
    /// Law 4: the flat list and the gates disagree, in count or in meaning.
    SingleSource { detail: String },
    /// `gate` is degree `degree` in the layer it reads, above the ceiling of 2.
    Degree { gate: String, degree: u32 },
    /// The cache-free compilation cannot write `gate` in one shape.
    NotInlinable { gate: String },
    /// Any other construction rule of `docs/spec/gkr.md` §4.2.
    Malformed { detail: String },
}

impl fmt::Display for ConstraintError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ConstraintError::Locality {
                layer,
                gate,
                operand,
            } => write!(
                f,
                "law 1 (locality): `{gate}` in gate list {layer} reads {operand}"
            ),
            ConstraintError::DerivedWidth { layer, detail } => {
                write!(f, "law 2 (derived width): layer {layer}: {detail}")
            }
            ConstraintError::TopLayer { detail } => write!(f, "law 3 (top layer): {detail}"),
            ConstraintError::SingleSource { detail } => {
                write!(f, "law 4 (single source of truth): {detail}")
            }
            ConstraintError::Degree { gate, degree } => write!(
                f,
                "`{gate}` is degree {degree} in the layer it reads; the ceiling is 2"
            ),
            ConstraintError::NotInlinable { gate } => write!(
                f,
                "`{gate}` names a cached entry the cache-free compilation cannot inline"
            ),
            ConstraintError::Malformed { detail } => write!(f, "malformed circuit: {detail}"),
        }
    }
}

fn malformed(detail: String) -> ConstraintError {
    ConstraintError::Malformed { detail }
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

pub(crate) fn validate(a: &CircuitArtifact) -> Result<(), ConstraintError> {
    header(a)?;
    names(a)?;
    let shapes = shapes(a)?;
    for (k, list) in a.layers.iter().enumerate() {
        gate_list(a, k, list, shapes[k].1)?;
    }
    relations(a, &shapes)?;
    top_layer(a, &shapes)?;
    challenge_slots(a)?;
    single_source(a)?;
    nothing_dropped(a, &shapes)
}

/// Every inner column below the top is read by the gate list above it, and
/// every cached entry is named by a gate of its list. A column nothing reads —
/// or a cached entry nothing names — is a relation constructed and then
/// dropped: nothing downstream depends on it, so it constrains nothing the
/// circuit's outputs or enforcing gates can see. The top layer is Law 3's; a
/// committed column nothing reads is still opened.
///
/// "Reads" is decided on the gates' normalized expansions, cached entries
/// substituted, so a term that cancels — `x − x`, or `0·x` — reads nothing. An
/// enforcing gate whose expansion is zero is dropped in the same sense: it
/// holds on every row whatever it names, so it constrains nothing.
fn nothing_dropped(a: &CircuitArtifact, shapes: &[(u32, u32)]) -> Result<(), ConstraintError> {
    let inverse: BTreeMap<PolyAddress, u32> = a
        .scratch
        .iter()
        .enumerate()
        .map(|(i, s)| (s.address, i as u32))
        .collect();
    for (k, list) in a.layers.iter().enumerate() {
        let layered = Namespace {
            layered: true,
            cached: &list.cached,
            inverse: &inverse,
        };
        for entry in &list.enforcing {
            if layered.expand(&entry.gate).is_empty() {
                return Err(malformed(format!(
                    "enforcing gate `{}` in gate list {k} is identically zero, so it constrains \
                     nothing",
                    a.relations[entry.relation as usize].name
                )));
            }
        }
        let gates: Vec<&GateDef> = list
            .producing
            .iter()
            .map(|e| &e.gate)
            .chain(list.enforcing.iter().map(|e| &e.gate))
            .collect();
        let named: Vec<PolyAddress> = gates.iter().flat_map(|g| g.operands()).collect();
        for (j, entry) in list.cached.iter().enumerate() {
            if !named.contains(&entry.address) {
                return Err(malformed(format!(
                    "cached entry `{}` (C{{{k}}}[{j}]) is named by no gate",
                    entry.name
                )));
            }
        }
        if k == 0 {
            continue;
        }
        let mut read: Vec<PolyAddress> = Vec::new();
        for gate in &gates {
            for (monomial, _) in layered.expand(gate) {
                for symbol in monomial {
                    if let Symbol::Column(PolyAddress::Scratch(s))
                    | Symbol::Child(PolyAddress::Scratch(s), _) = symbol
                    {
                        read.push(a.scratch[s as usize].address);
                    }
                }
            }
        }
        for j in 0..shapes[k].1 {
            let column = PolyAddress::Inner {
                layer: k as u32,
                offset: j,
            };
            if !read.contains(&column) {
                return Err(malformed(format!(
                    "{column} is written but gate list {k} never reads it, so the relation \
                     defining it constrains nothing"
                )));
            }
        }
    }
    Ok(())
}

fn header(a: &CircuitArtifact) -> Result<(), ConstraintError> {
    if a.format_version != FORMAT_VERSION {
        return Err(malformed(format!(
            "format version {}, expected {FORMAT_VERSION}",
            a.format_version
        )));
    }
    if a.coefficient_encoding != COEFFICIENT_ENCODING_CANONICAL_LE {
        return Err(malformed(format!(
            "coefficient encoding {}; the only one is {COEFFICIENT_ENCODING_CANONICAL_LE}, \
             canonical 32-byte little-endian",
            a.coefficient_encoding
        )));
    }
    if a.trace_vars > MAX_TRACE_VARS {
        return Err(malformed(format!(
            "trace_vars {} is above {MAX_TRACE_VARS}",
            a.trace_vars
        )));
    }
    if a.layers.is_empty() {
        return Err(malformed(String::from(
            "a circuit has at least one gate list",
        )));
    }
    if !a.lookups.is_empty() {
        return Err(malformed(String::from(
            "the lookup-expression list must be empty until a stage gives lookups meaning",
        )));
    }
    if a.padding.row.len() != a.committed().len() {
        return Err(malformed(format!(
            "the padding row has {} values for {} committed columns",
            a.padding.row.len(),
            a.committed().len()
        )));
    }
    for (i, (kind, _)) in a.virtuals.iter().enumerate() {
        if a.virtuals[..i].iter().any(|(k, _)| k == kind) {
            return Err(malformed(format!("virtual table {kind:?} is listed twice")));
        }
    }
    Ok(())
}

/// Every polynomial, relation and lookup name: non-empty, `[a-z0-9_]`, and
/// distinct from every other name in the artifact. A name is documentation,
/// stored beside what it names rather than derived from its position, so no
/// name can drift with a layer index.
fn names(a: &CircuitArtifact) -> Result<(), ConstraintError> {
    let mut all: Vec<&str> = Vec::new();
    all.extend(a.memory.iter().map(String::as_str));
    all.extend(a.witness.iter().map(String::as_str));
    all.extend(a.setup.iter().map(String::as_str));
    all.extend(a.virtuals.iter().map(|(_, n)| n.as_str()));
    for list in &a.layers {
        all.extend(list.cached.iter().map(|c| c.name.as_str()));
    }
    all.extend(a.relations.iter().map(|r| r.name.as_str()));
    all.extend(a.lookups.iter().map(|l| l.name.as_str()));
    all.extend(a.scratch.iter().map(|s| s.name.as_str()));
    for name in &all {
        let legal = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !legal {
            return Err(malformed(format!(
                "name {name:?} is not a non-empty [a-z0-9_] string"
            )));
        }
    }
    all.sort_unstable();
    for pair in all.windows(2) {
        if pair[0] == pair[1] {
            return Err(malformed(format!("name {:?} is used twice", pair[0])));
        }
    }
    Ok(())
}

/// Law 2, and the variable counts: `(n_k, w_k)` for every layer `0..=N`, each
/// stored value held to what the gates imply.
fn shapes(a: &CircuitArtifact) -> Result<Vec<(u32, u32)>, ConstraintError> {
    let mut shapes = vec![(a.trace_vars, a.committed().len() as u32)];
    for (k, list) in a.layers.iter().enumerate() {
        let above = k as u32 + 1;
        let vars = shapes[k].0;
        let derived_vars = if list.halving {
            if vars == 0 {
                return Err(malformed(format!(
                    "gate list {k} halves layer {k}, which has no variable to halve"
                )));
            }
            vars - 1
        } else {
            vars
        };
        if list.num_vars != derived_vars {
            return Err(ConstraintError::DerivedWidth {
                layer: above,
                detail: format!(
                    "stored num_vars {} but gate list {k} writes {derived_vars} variables",
                    list.num_vars
                ),
            });
        }
        if list.width as usize != list.producing.len() {
            return Err(ConstraintError::DerivedWidth {
                layer: above,
                detail: format!(
                    "stored width {} but gate list {k} has {} producing gates",
                    list.width,
                    list.producing.len()
                ),
            });
        }
        for (j, entry) in list.producing.iter().enumerate() {
            let expected = PolyAddress::Inner {
                layer: above,
                offset: j as u32,
            };
            if entry.output != expected {
                return Err(ConstraintError::DerivedWidth {
                    layer: above,
                    detail: format!(
                        "producing entry {j} writes {}, not {expected}",
                        entry.output
                    ),
                });
            }
        }
        shapes.push((derived_vars, list.producing.len() as u32));
    }
    Ok(shapes)
}

/// How a gate is named in a diagnostic: by its relation where it has one.
fn gate_name(a: &CircuitArtifact, k: usize, kind: &str, j: usize, relation: u32) -> String {
    match a.relations.get(relation as usize) {
        Some(r) => r.name.clone(),
        None => format!("gate list {k} {kind} entry {j}"),
    }
}

/// Law 1, the halving rules, and the degree ceiling, for gate list `k`.
fn gate_list(
    a: &CircuitArtifact,
    k: usize,
    list: &LayerSpec,
    width_k: u32,
) -> Result<(), ConstraintError> {
    let layer = k as u32;
    let readable = |op: &PolyAddress, allow_cached: bool| -> bool {
        match *op {
            PolyAddress::Memory(i) => k == 0 && (i as usize) < a.memory.len(),
            PolyAddress::Witness(i) => k == 0 && (i as usize) < a.witness.len(),
            PolyAddress::Setup(i) => k == 0 && (i as usize) < a.setup.len(),
            PolyAddress::Virtual(kind) => k == 0 && a.virtuals.iter().any(|(v, _)| *v == kind),
            PolyAddress::Inner {
                layer: l,
                offset: o,
            } => k >= 1 && l == layer && o < width_k,
            PolyAddress::Cached {
                layer: l,
                offset: o,
            } => allow_cached && l == layer && (o as usize) < list.cached.len(),
            PolyAddress::Scratch(_) => false,
        }
    };
    let locality = |gate: &GateDef, name: String, allow_cached: bool| match gate
        .operands()
        .iter()
        .find(|op| !readable(op, allow_cached))
    {
        Some(op) => Err(ConstraintError::Locality {
            layer,
            gate: name,
            operand: *op,
        }),
        None => Ok(()),
    };

    if list.halving {
        if k == 0 {
            return Err(malformed(String::from(
                "gate list 0 reads the base and cannot be a halving list",
            )));
        }
        if !list.cached.is_empty() || !list.enforcing.is_empty() {
            return Err(malformed(format!(
                "halving gate list {k} has cached or enforcing entries"
            )));
        }
        // A halving list halves every column of its layer, in order: entry j is
        // `TreeProduct { L{k}[j] }`. That is what lets transition k's claims be
        // two children per column of layer k, and its batch weight j be both
        // output j's and input j's.
        for (j, entry) in list.producing.iter().enumerate() {
            let name = gate_name(a, k, "producing", j, entry.relation);
            locality(&entry.gate, name.clone(), false)?;
            let halves_column_j = GateDef::TreeProduct {
                input: PolyAddress::Inner {
                    layer,
                    offset: j as u32,
                },
            };
            if entry.gate != halves_column_j {
                return Err(malformed(format!(
                    "`{name}` in halving gate list {k} is not TreeProduct of L{{{k}}}[{j}]"
                )));
            }
        }
        if list.producing.len() != width_k as usize {
            return Err(malformed(format!(
                "halving gate list {k} writes {} columns from {width_k}; it must halve every one",
                list.producing.len()
            )));
        }
        return Ok(());
    }

    for (j, entry) in list.cached.iter().enumerate() {
        let expected = PolyAddress::Cached {
            layer,
            offset: j as u32,
        };
        if entry.address != expected {
            return Err(malformed(format!(
                "cached entry `{}` is at {}, not {expected}",
                entry.name, entry.address
            )));
        }
        row_wise_shape(&entry.gate, &entry.name, k)?;
        locality(&entry.gate, entry.name.clone(), false)?;
    }
    for (j, entry) in list.producing.iter().enumerate() {
        let name = gate_name(a, k, "producing", j, entry.relation);
        row_wise_shape(&entry.gate, &name, k)?;
        locality(&entry.gate, name, true)?;
    }
    for (j, entry) in list.enforcing.iter().enumerate() {
        let name = gate_name(a, k, "enforcing", j, entry.relation);
        row_wise_shape(&entry.gate, &name, k)?;
        locality(&entry.gate, name, true)?;
    }

    // Degree, now that every cached reference is known to resolve.
    for entry in &list.cached {
        ceiling(&entry.gate, &[], entry.name.clone())?;
    }
    for (j, entry) in list.producing.iter().enumerate() {
        ceiling(
            &entry.gate,
            &list.cached,
            gate_name(a, k, "producing", j, entry.relation),
        )?;
    }
    for (j, entry) in list.enforcing.iter().enumerate() {
        ceiling(
            &entry.gate,
            &list.cached,
            gate_name(a, k, "enforcing", j, entry.relation),
        )?;
    }
    Ok(())
}

fn row_wise_shape(gate: &GateDef, name: &str, k: usize) -> Result<(), ConstraintError> {
    if matches!(gate, GateDef::TreeProduct { .. }) {
        return Err(malformed(format!(
            "`{name}` is a TreeProduct in row-wise gate list {k}"
        )));
    }
    Ok(())
}

/// A gate's degree in the layer it reads, cached entries substituted: a column
/// is 1, a challenge 0, `C{k}[j]` its expression's degree. Read from the shape,
/// never from a simplification of it.
fn degree(gate: &GateDef, cached: &[CachedEntry]) -> u32 {
    let d = |op: &PolyAddress| match *op {
        PolyAddress::Cached { offset, .. } => degree(&cached[offset as usize].gate, &[]),
        _ => 1,
    };
    let widest =
        |terms: &[(Coeff, PolyAddress)]| terms.iter().map(|(_, x)| d(x)).max().unwrap_or(0);
    match gate {
        GateDef::Linear { terms, .. } => widest(terms),
        GateDef::Product { left, right, .. } => d(left) + d(right),
        GateDef::MaskIntoIdentity { input, mask } => (d(input) + d(mask)).max(d(mask)),
        GateDef::AffineProduct { left, right, .. } => widest(left) + widest(right),
        GateDef::TreeProduct { .. } => 2,
        GateDef::Quadratic {
            linear, products, ..
        } => {
            let pairs = products.iter().map(|(_, y, z)| d(y) + d(z)).max();
            widest(linear).max(pairs.unwrap_or(0))
        }
    }
}

fn ceiling(gate: &GateDef, cached: &[CachedEntry], name: String) -> Result<(), ConstraintError> {
    let deg = degree(gate, cached);
    if deg > 2 {
        return Err(ConstraintError::Degree {
            gate: name,
            degree: deg,
        });
    }
    Ok(())
}

/// The flat list's operands and outputs, and the scratch bijection.
fn relations(a: &CircuitArtifact, shapes: &[(u32, u32)]) -> Result<(), ConstraintError> {
    let mut defined = vec![0usize; a.scratch.len()];
    for r in &a.relations {
        for op in r.gate.operands() {
            let ok = match op {
                PolyAddress::Memory(i) => (i as usize) < a.memory.len(),
                PolyAddress::Witness(i) => (i as usize) < a.witness.len(),
                PolyAddress::Setup(i) => (i as usize) < a.setup.len(),
                PolyAddress::Virtual(kind) => a.virtuals.iter().any(|(v, _)| *v == kind),
                PolyAddress::Scratch(i) => (i as usize) < a.scratch.len(),
                PolyAddress::Inner { .. } | PolyAddress::Cached { .. } => false,
            };
            if !ok {
                return Err(malformed(format!(
                    "relation `{}` reads {op}, which the flat list cannot name",
                    r.name
                )));
            }
        }
        if let Some(s) = r.output {
            match defined.get_mut(s as usize) {
                Some(count) => *count += 1,
                None => {
                    return Err(malformed(format!(
                        "relation `{}` defines scratch[{s}], which does not exist",
                        r.name
                    )))
                }
            }
        }
        ceiling(&r.gate, &[], r.name.clone())?;
    }
    if let Some(s) = defined.iter().position(|&n| n != 1) {
        return Err(malformed(format!(
            "scratch[{s}] is defined by {} relations, not exactly one",
            defined[s]
        )));
    }

    let inner: usize = shapes[1..].iter().map(|(_, w)| *w as usize).sum();
    if a.scratch.len() != inner {
        return Err(malformed(format!(
            "{} scratch slots for {inner} inner-layer columns",
            a.scratch.len()
        )));
    }
    let mut seen: Vec<PolyAddress> = Vec::new();
    for (i, slot) in a.scratch.iter().enumerate() {
        let in_range = match slot.address {
            PolyAddress::Inner { layer, offset } => {
                layer >= 1 && (layer as usize) < shapes.len() && offset < shapes[layer as usize].1
            }
            _ => false,
        };
        if !in_range || seen.contains(&slot.address) {
            return Err(malformed(format!(
                "scratch[{i}] is {}, which is not a fresh inner-layer column",
                slot.address
            )));
        }
        seen.push(slot.address);
    }
    Ok(())
}

/// Law 3.
fn top_layer(a: &CircuitArtifact, shapes: &[(u32, u32)]) -> Result<(), ConstraintError> {
    let n = a.layers.len() as u32;
    let width = shapes[n as usize].1;
    if a.outputs.len() != width as usize {
        return Err(ConstraintError::TopLayer {
            detail: format!(
                "layer {n} has {width} columns but the output map has {}",
                a.outputs.len()
            ),
        });
    }
    for (i, out) in a.outputs.iter().enumerate() {
        let top =
            matches!(*out, PolyAddress::Inner { layer, offset } if layer == n && offset < width);
        if !top || a.outputs[..i].contains(out) {
            return Err(ConstraintError::TopLayer {
                detail: format!("output {i} is {out}, not a distinct column of layer {n}"),
            });
        }
    }
    Ok(())
}

fn challenge_slots(a: &CircuitArtifact) -> Result<(), ConstraintError> {
    let mut gates: Vec<&GateDef> = Vec::new();
    for list in &a.layers {
        gates.extend(list.cached.iter().map(|e| &e.gate));
        gates.extend(list.producing.iter().map(|e| &e.gate));
        gates.extend(list.enforcing.iter().map(|e| &e.gate));
    }
    gates.extend(a.relations.iter().map(|r| &r.gate));
    for gate in gates {
        for c in gate.coefficients() {
            if let Coeff::Challenge(slot) = c {
                if slot as usize >= challenge_slot::NAMES.len() {
                    return Err(malformed(format!(
                        "challenge slot {slot} is not in constants::challenge_slot"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Law 4.
fn single_source(a: &CircuitArtifact) -> Result<(), ConstraintError> {
    let inverse: BTreeMap<PolyAddress, u32> = a
        .scratch
        .iter()
        .enumerate()
        .map(|(i, s)| (s.address, i as u32))
        .collect();
    let mut encoded = vec![false; a.relations.len()];
    let mut entries = 0usize;
    let mut claim = |index: u32| -> Result<usize, ConstraintError> {
        entries += 1;
        let i = index as usize;
        match encoded.get_mut(i) {
            Some(false) => {
                encoded[i] = true;
                Ok(i)
            }
            Some(true) => Err(ConstraintError::SingleSource {
                detail: format!("relation `{}` is encoded by two gates", a.relations[i].name),
            }),
            None => Err(ConstraintError::SingleSource {
                detail: format!("a gate names relation {index}, which does not exist"),
            }),
        }
    };

    for (k, list) in a.layers.iter().enumerate() {
        for entry in &list.producing {
            let r = &a.relations[claim(entry.relation)?];
            let defines = r
                .output
                .map(|s| a.scratch[s as usize].address == entry.output)
                .unwrap_or(false);
            if !defines {
                return Err(ConstraintError::SingleSource {
                    detail: format!(
                        "the gate writing {} encodes relation `{}`, which does not define it",
                        entry.output, r.name
                    ),
                });
            }
            same_polynomial(&r.gate, &entry.gate, &r.name, k, &list.cached, &inverse)?;
        }
        for entry in &list.enforcing {
            let r = &a.relations[claim(entry.relation)?];
            if r.output.is_some() {
                return Err(ConstraintError::SingleSource {
                    detail: format!(
                        "an enforcing gate encodes relation `{}`, which is producing",
                        r.name
                    ),
                });
            }
            same_polynomial(&r.gate, &entry.gate, &r.name, k, &list.cached, &inverse)?;
        }
    }
    if entries != a.relations.len() {
        return Err(ConstraintError::SingleSource {
            detail: format!(
                "{} relations in the flat list but {entries} gates",
                a.relations.len()
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Expansion: a gate as a polynomial over symbols, for Law 4
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Symbol {
    /// A column, in the flat list's namespace: inner-layer addresses are
    /// already mapped to their scratch slots.
    Column(PolyAddress),
    /// A column's child 0 or 1, as a `TreeProduct` reads it.
    Child(PolyAddress, u8),
    Challenge(u32),
}

/// `Σ coefficient · Π symbols`, kept normalized: every sum and product below
/// merges as it goes, so a gate's expansion never holds more monomials than the
/// polynomial has — quadratic in the gate's distinct operands, never quartic.
type Expansion = Vec<(Vec<Symbol>, Fr)>;

/// Where a gate's operands live: the flat list, or gate list `k` of the
/// layered encoding.
struct Namespace<'a> {
    layered: bool,
    cached: &'a [CachedEntry],
    inverse: &'a BTreeMap<PolyAddress, u32>,
}

impl Namespace<'_> {
    fn column(&self, op: PolyAddress) -> PolyAddress {
        match op {
            PolyAddress::Inner { .. } if self.layered => PolyAddress::Scratch(self.inverse[&op]),
            other => other,
        }
    }

    fn operand(&self, op: PolyAddress) -> Expansion {
        match op {
            PolyAddress::Cached { offset, .. } if self.layered => {
                let flat = Namespace {
                    layered: true,
                    cached: &[],
                    inverse: self.inverse,
                };
                flat.expand(&self.cached[offset as usize].gate)
            }
            other => vec![(vec![Symbol::Column(self.column(other))], Fr::ONE)],
        }
    }

    fn affine(&self, terms: &[(Coeff, PolyAddress)], constant: Coeff) -> Expansion {
        let mut out = coefficient(constant);
        for (c, x) in terms {
            out.extend(product(&coefficient(*c), &self.operand(*x)));
        }
        normalize(out)
    }

    fn expand(&self, gate: &GateDef) -> Expansion {
        match gate {
            GateDef::Linear { terms, constant } => self.affine(terms, *constant),
            GateDef::Product { coeff, left, right } => product(
                &product(&coefficient(*coeff), &self.operand(*left)),
                &self.operand(*right),
            ),
            GateDef::MaskIntoIdentity { input, mask } => {
                let mut out = product(&self.operand(*input), &self.operand(*mask));
                out.push((Vec::new(), Fr::ONE));
                out.extend(product(
                    &[(Vec::new(), Fr::MINUS_ONE)],
                    &self.operand(*mask),
                ));
                normalize(out)
            }
            GateDef::AffineProduct {
                left,
                left_constant,
                right,
                right_constant,
            } => product(
                &self.affine(left, *left_constant),
                &self.affine(right, *right_constant),
            ),
            GateDef::TreeProduct { input } => {
                let x = self.column(*input);
                vec![(vec![Symbol::Child(x, 0), Symbol::Child(x, 1)], Fr::ONE)]
            }
            GateDef::Quadratic {
                constant,
                linear,
                products,
            } => {
                let mut out = self.affine(linear, *constant);
                for (b, y, z) in products {
                    out.extend(product(
                        &product(&coefficient(*b), &self.operand(*y)),
                        &self.operand(*z),
                    ));
                }
                normalize(out)
            }
        }
    }
}

fn coefficient(c: Coeff) -> Expansion {
    match c {
        Coeff::Literal(v) => vec![(Vec::new(), v)],
        Coeff::Challenge(slot) => vec![(vec![Symbol::Challenge(slot)], Fr::ONE)],
    }
}

fn product(a: &[(Vec<Symbol>, Fr)], b: &[(Vec<Symbol>, Fr)]) -> Expansion {
    let mut out = Vec::new();
    for (ma, ca) in a {
        for (mb, cb) in b {
            let mut m = ma.clone();
            m.extend_from_slice(mb);
            out.push((m, *ca * *cb));
        }
    }
    normalize(out)
}

/// One polynomial, one representation: monomials sorted, equal ones merged,
/// zero coefficients dropped.
fn normalize(mut terms: Expansion) -> Expansion {
    for (m, _) in terms.iter_mut() {
        m.sort_unstable();
    }
    terms.sort_by(|x, y| x.0.cmp(&y.0));
    let mut out: Expansion = Vec::new();
    for (m, c) in terms {
        match out.last_mut() {
            Some((last, total)) if *last == m => *total += c,
            _ => out.push((m, c)),
        }
    }
    out.retain(|(_, c)| *c != Fr::ZERO);
    out
}

fn same_polynomial(
    relation: &GateDef,
    gate: &GateDef,
    name: &str,
    k: usize,
    cached: &[CachedEntry],
    inverse: &BTreeMap<PolyAddress, u32>,
) -> Result<(), ConstraintError> {
    let flat = Namespace {
        layered: false,
        cached: &[],
        inverse,
    };
    let layered = Namespace {
        layered: true,
        cached,
        inverse,
    };
    if normalize(flat.expand(relation)) != normalize(layered.expand(gate)) {
        return Err(ConstraintError::SingleSource {
            detail: format!(
                "relation `{name}` and its gate in gate list {k} are different polynomials"
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The cache-free compilation
// ---------------------------------------------------------------------------

pub(crate) fn inline_cached(a: &CircuitArtifact) -> Result<CircuitArtifact, ConstraintError> {
    validate(a)?;
    let mut out = a.clone();
    for list in out.layers.iter_mut() {
        let cached = core::mem::take(&mut list.cached);
        for entry in list.producing.iter_mut() {
            let name = a.relations[entry.relation as usize].name.clone();
            entry.gate = inline(&entry.gate, &cached, name)?;
        }
        for entry in list.enforcing.iter_mut() {
            let name = a.relations[entry.relation as usize].name.clone();
            entry.gate = inline(&entry.gate, &cached, name)?;
        }
    }
    validate(&out)?;
    Ok(out)
}

/// `Product { c, C, y }` over a `Linear` cached `C` is
/// `AffineProduct { C.terms, C.constant; [(c, y)], 0 }`, and symmetrically;
/// a gate naming no cached entry is itself; nothing else inlines — a
/// `Quadratic` naming a cached entry included.
fn inline(
    gate: &GateDef,
    cached: &[CachedEntry],
    name: String,
) -> Result<GateDef, ConstraintError> {
    let linear = |op: &PolyAddress| match *op {
        PolyAddress::Cached { offset, .. } => match &cached[offset as usize].gate {
            GateDef::Linear { terms, constant } => Some(Some((terms.clone(), *constant))),
            _ => Some(None),
        },
        _ => None,
    };
    if !gate
        .operands()
        .iter()
        .any(|op| matches!(op, PolyAddress::Cached { .. }))
    {
        return Ok(gate.clone());
    }
    let zero = Coeff::Literal(Fr::ZERO);
    if let GateDef::Product { coeff, left, right } = gate {
        match (linear(left), linear(right)) {
            (Some(Some((terms, constant))), None) => {
                return Ok(GateDef::AffineProduct {
                    left: terms,
                    left_constant: constant,
                    right: vec![(*coeff, *right)],
                    right_constant: zero,
                })
            }
            (None, Some(Some((terms, constant)))) => {
                return Ok(GateDef::AffineProduct {
                    left: vec![(*coeff, *left)],
                    left_constant: zero,
                    right: terms,
                    right_constant: constant,
                })
            }
            _ => {}
        }
    }
    Err(ConstraintError::NotInlinable { gate: name })
}
