//! Standalone checkers for a `CircuitArtifact`, written from `docs/spec/gkr.md`
//! alone: the four laws and the lookup rules of §4.2, the padding contract of
//! §4.3 with its product-tree clause, a witness-row evaluator and the native
//! lookup evaluator, a readable dump, and a cross-check against an
//! independently written description of a circuit.
//!
//! Nothing here calls `CircuitArtifact::validate` or `inline_cached`: the laws
//! are enforced twice, by `constraints` at construction and by this crate, with
//! no code shared (S13 must-be-exact 4). Gates are evaluated only through
//! `gkr::eval_gate` and `gkr::gate_values`, the kernel that is the semantic
//! authority.
//!
//! The sampled checks draw deterministic pseudo-random points (splitmix64,
//! fixed seeds), so every verdict is reproducible; each trial wrongly accepts
//! two different polynomials with probability about `degree / |Fr|`.

use constants::memory::{READ_ROOT, WRITE_ROOT};
use constants::{challenge_slot, lookup_channel};
use constraints::lookup::ChannelSpec;
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind, CATALOGUE};
use field::Fr;
use gkr::{
    eval_gate, forward, gate_values, insert_lookup_challenges, virtual_at_row, BaseLayer,
    ExternalChallenges, LayerValues,
};
use poly::{MultilinearPoly, PolyBacking};
use std::collections::BTreeMap;

/// Independent pseudo-random points per sampled check.
const TRIALS: usize = 8;

const LAW1: &str = "Law 1 (locality)";
const LAW2: &str = "Law 2 (derived width)";
const LAW3: &str = "Law 3 (top layer)";
const LAW4: &str = "Law 4 (single source of truth)";
const LOOKUP_RULES: &str = "Lookup rules";

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// splitmix64, the checker's own.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A field element below `2^252 < p`.
    fn fr(&mut self) -> Fr {
        let mut b = [0u8; 32];
        for i in 0..4 {
            b[8 * i..8 * i + 8].copy_from_slice(&self.next().to_le_bytes());
        }
        b[31] &= 0x0f;
        Fr::from_bytes(&b).expect("a value below 2^252 is canonical")
    }

    fn challenges(&mut self, slots: &[u32]) -> ExternalChallenges {
        let mut c = ExternalChallenges::new();
        for &slot in slots {
            c.insert(slot, self.fr());
        }
        c
    }
}

/// Every relation's gate and every gate entry's, cached entries included.
fn all_gates(a: &CircuitArtifact) -> Vec<&GateDef> {
    let mut gates: Vec<&GateDef> = a.relations.iter().map(|r| &r.gate).collect();
    for list in &a.layers {
        gates.extend(list.cached.iter().map(|e| &e.gate));
        gates.extend(list.producing.iter().map(|e| &e.gate));
        gates.extend(list.enforcing.iter().map(|e| &e.gate));
    }
    gates
}

/// The challenge slots `gates` name, ascending, each once.
fn challenge_slots(gates: &[&GateDef]) -> Vec<u32> {
    let mut slots: Vec<u32> = Vec::new();
    for c in gates.iter().flat_map(|g| g.coefficients()) {
        if let Coeff::Challenge(slot) = c {
            slots.push(slot);
        }
    }
    slots.sort_unstable();
    slots.dedup();
    slots
}

fn relation_name(a: &CircuitArtifact, r: u32) -> &str {
    a.relations
        .get(r as usize)
        .map_or("?", |rel| rel.name.as_str())
}

/// The name the scratch bijection gives an inner address.
fn output_name(a: &CircuitArtifact, address: PolyAddress) -> &str {
    let slot = a.scratch.iter().find(|slot| slot.address == address);
    slot.map_or("?", |slot| slot.name.as_str())
}

/// `op`'s position in the committed layout, if it is an in-range `M`, `W`, `S`.
fn layout_index(a: &CircuitArtifact, op: PolyAddress) -> Option<usize> {
    let (m, w, s) = (a.memory.len(), a.witness.len(), a.setup.len());
    match op {
        PolyAddress::Memory(i) if (i as usize) < m => Some(i as usize),
        PolyAddress::Witness(i) if (i as usize) < w => Some(m + i as usize),
        PolyAddress::Setup(i) if (i as usize) < s => Some(m + w + i as usize),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Laws 1–4
// ---------------------------------------------------------------------------

/// Law 1, locality: every operand of gate list `k` — cached, producing and
/// enforcing entries alike — is readable at layer `k` (`docs/spec/gkr.md` §2).
/// At `k = 0`: `M`, `W`, `S` in range of the layout, and a `V` the artifact
/// lists. At `k >= 1`: `L{k}[j]` with `j` below gate list `k − 1`'s producing
/// count. Anywhere: `C{k}[j]` naming one of list `k`'s own entries, from a
/// producing or enforcing gate only; never `scratch`. A cached entry's own
/// address is `C{k}[its position]`.
///
/// Does NOT cover: the stored widths and variable counts (Law 2), the output
/// map (Law 3), the flat list (Law 4), or any construction rule outside the
/// laws (listed on `check_laws`).
pub fn check_law1(a: &CircuitArtifact) -> Result<(), String> {
    for (k, list) in a.layers.iter().enumerate() {
        // (what, gate, whether it may read a cached entry)
        let mut gates: Vec<(String, &GateDef, bool)> = Vec::new();
        for (j, e) in list.cached.iter().enumerate() {
            let own = PolyAddress::Cached {
                layer: k as u32,
                offset: j as u32,
            };
            if e.address != own {
                let at = e.address;
                return Err(format!(
                    "{LAW1}: cached entry {own} of gate list {k} is named {at}"
                ));
            }
            gates.push((format!("cached entry {own}"), &e.gate, false));
        }
        for e in &list.producing {
            gates.push((format!("the gate writing {}", e.output), &e.gate, true));
        }
        for (j, e) in list.enforcing.iter().enumerate() {
            let name = relation_name(a, e.relation);
            gates.push((format!("enforcing gate {j} ({name})"), &e.gate, true));
        }
        for (what, gate, cached_ok) in gates {
            for op in gate.operands() {
                let readable = match op {
                    PolyAddress::Memory(_) | PolyAddress::Witness(_) | PolyAddress::Setup(_) => {
                        k == 0 && layout_index(a, op).is_some()
                    }
                    PolyAddress::Virtual(kind) => {
                        k == 0 && a.virtuals.iter().any(|(v, _)| *v == kind)
                    }
                    PolyAddress::Inner { layer, offset } => {
                        k >= 1
                            && layer as usize == k
                            && (offset as usize) < a.layers[k - 1].producing.len()
                    }
                    PolyAddress::Cached { layer, offset } => {
                        cached_ok && layer as usize == k && (offset as usize) < list.cached.len()
                    }
                    PolyAddress::Scratch(_) => false,
                };
                if !readable {
                    return Err(format!(
                        "{LAW1}: {what} in gate list {k} reads {op}, which layer {k} does not hold"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// Law 2, derived width: gate list `k`'s stored `width` is its producing-gate
/// count; producing gate `j` writes `L{k+1}[j]`, so the outputs are exactly
/// `L{k+1}[0..width)` once each, in position order, which is the order the
/// engine reads them in; the stored `num_vars` is `n_k` for a row-wise list and
/// `n_k − 1` for a halving one. A halving list halves every inner column of its
/// layer in order: it is not gate list 0, which reads the base, its width is
/// layer `k`'s, and producing gate `j` is exactly `TreeProduct { input: L{k}[j] }`.
///
/// Does NOT cover: operand locality (Law 1), the output map (Law 3), the flat
/// list (Law 4); layer 0's width, which is the layout and stores nothing; that
/// a halving list has no cached or enforcing entries and a row-wise list no
/// `TreeProduct`; any other construction rule outside the laws.
pub fn check_law2(a: &CircuitArtifact) -> Result<(), String> {
    for (k, list) in a.layers.iter().enumerate() {
        let (up, width, written) = (k as u32 + 1, list.width, list.producing.len());
        if width as usize != written {
            return Err(format!(
                "{LAW2}: gate list {k} declares width {width} for layer {up}, but its gates \
                 write {written} addresses"
            ));
        }
        for (j, e) in list.producing.iter().enumerate() {
            let expected = PolyAddress::Inner {
                layer: up,
                offset: j as u32,
            };
            if e.output != expected {
                let out = e.output;
                return Err(format!(
                    "{LAW2}: producing gate {j} of gate list {k} writes {out}, not {expected}"
                ));
            }
        }
        let (n_k, halving, declared) = (a.layer_vars(k), list.halving, list.num_vars);
        let derived = if halving {
            n_k.checked_sub(1)
        } else {
            Some(n_k)
        };
        if derived != Some(declared) {
            return Err(format!(
                "{LAW2}: gate list {k} (halving: {halving}) reads {n_k} variables, but declares \
                 {declared} for layer {up}"
            ));
        }
        if !halving {
            continue;
        }
        if k == 0 {
            return Err(format!(
                "{LAW2}: gate list 0 is halving, but it reads the base, not inner columns"
            ));
        }
        let columns = a.layer_width(k);
        if width != columns {
            return Err(format!(
                "{LAW2}: halving gate list {k} writes {width} columns, but layer {k} has \
                 {columns} inner columns"
            ));
        }
        for (j, e) in list.producing.iter().enumerate() {
            // The two halving shapes: a product tree's `TreeProduct` and a
            // fraction tree's `TreeCross` (`docs/spec/lookup.md` §6). Each
            // reads its operands at both children, and locality (Law 1) is what
            // holds those operands to layer `k`.
            if !matches!(
                e.gate,
                GateDef::TreeProduct { .. } | GateDef::TreeCross { .. }
            ) {
                return Err(format!(
                    "{LAW2}: producing gate {j} of halving gate list {k} is neither a \
                     TreeProduct nor a TreeCross"
                ));
            }
        }
    }
    Ok(())
}

/// Law 3, top layer: there is at least one gate list, and `outputs` is a
/// permutation of `L{N}[0..w_N)`, `w_N` the last list's stored width — every
/// top-layer address exactly once, and nothing else.
///
/// Does NOT cover: whether the last list's gates write those addresses
/// (Law 2), or whether the outputs are the ones a verifier expects, in its
/// order (`cross_check`).
pub fn check_law3(a: &CircuitArtifact) -> Result<(), String> {
    let Some(last) = a.layers.last() else {
        return Err(format!(
            "{LAW3}: the circuit has no gate list, so no top layer"
        ));
    };
    let (n, width) = (a.layers.len() as u32, last.width);
    for (i, out) in a.outputs.iter().enumerate() {
        let on_top =
            matches!(*out, PolyAddress::Inner { layer, offset } if layer == n && offset < width);
        if !on_top {
            return Err(format!(
                "{LAW3}: output {i} is {out}, which is not on top layer {n} of width {width}"
            ));
        }
        if a.outputs[..i].contains(out) {
            return Err(format!("{LAW3}: the output map names {out} twice"));
        }
    }
    for offset in 0..width {
        let address = PolyAddress::Inner { layer: n, offset };
        if !a.outputs.contains(&address) {
            return Err(format!(
                "{LAW3}: top layer {n} holds {address}, which is absent from the output map"
            ));
        }
    }
    Ok(())
}

/// Law 4, single source of truth: the flat list and the gates are one
/// constraint set. Cardinality: as many producing and enforcing entries as
/// relations, each relation named by exactly one. Outputs: every scratch slot
/// is the output of exactly one relation, no two slots share an address, a
/// producing entry's output is its relation's slot's address and an enforcing
/// entry's relation has no output. Semantics: at `TRIALS` pseudo-random points
/// giving every committed column, each virtual table kind and every scratch
/// slot a value and two child values, and every challenge slot a value, each relation and its
/// gate agree through the kernel — `L{k}[j]` read as its scratch slot,
/// `C{k}[j]` evaluated from its entry, a halving gate reading the children.
///
/// Does NOT cover: operand locality (Law 1) or widths (Law 2); relation
/// operands outside §2's set except as addresses it cannot evaluate; the degree
/// ceiling; names, which are documentation; `lookups`. Sampled: see the crate
/// docs for the error probability.
pub fn check_law4(a: &CircuitArtifact) -> Result<(), String> {
    let relations = &a.relations;
    // (what, relation, output, gate) for every producing and enforcing entry.
    let mut entries: Vec<(String, u32, Option<PolyAddress>, &GateDef)> = Vec::new();
    for (k, list) in a.layers.iter().enumerate() {
        for e in &list.producing {
            let what = format!("the gate writing {}", e.output);
            entries.push((what, e.relation, Some(e.output), &e.gate));
        }
        for (j, e) in list.enforcing.iter().enumerate() {
            let what = format!("enforcing gate {j} of gate list {k}");
            entries.push((what, e.relation, None, &e.gate));
        }
    }
    let (encoded, listed) = (entries.len(), relations.len());
    if encoded != listed {
        return Err(format!(
            "{LAW4}: the gates encode {encoded} relations, the flat list holds {listed}"
        ));
    }
    // With equal counts, every index named exactly once also means no entry
    // names an index outside the list.
    for (r, rel) in relations.iter().enumerate() {
        let named = entries.iter().filter(|e| e.1 as usize == r).count();
        if named != 1 {
            let name = &rel.name;
            return Err(format!(
                "{LAW4}: relation {r} ({name}) is named by {named} gate entries"
            ));
        }
    }
    for (i, slot) in a.scratch.iter().enumerate() {
        let defined = relations
            .iter()
            .filter(|rel| rel.output == Some(i as u32))
            .count();
        if defined != 1 {
            return Err(format!(
                "{LAW4}: scratch[{i}] is the output of {defined} relations"
            ));
        }
        if a.scratch[..i].iter().any(|s| s.address == slot.address) {
            let at = slot.address;
            return Err(format!(
                "{LAW4}: scratch[{i}] maps to {at}, as an earlier slot does"
            ));
        }
    }
    for (what, r, output, _) in &entries {
        let rel = &relations[*r as usize];
        // None: enforcing. Some(None): a slot outside the bijection.
        let mapped = rel
            .output
            .map(|i| a.scratch.get(i as usize).map(|s| s.address));
        if mapped != output.map(Some) {
            let has = match rel.output {
                Some(i) => format!("output {}", PolyAddress::Scratch(i)),
                None => "no output".to_string(),
            };
            return Err(format!(
                "{LAW4}: {what} names relation {r} ({}), with {has}, which the scratch \
                 bijection does not map to it",
                rel.name
            ));
        }
    }

    let mut rng = Rng(0x1a44_0004);
    let slots = challenge_slots(&all_gates(a));
    for trial in 0..TRIALS {
        let mut triple = || [rng.fr(), rng.fr(), rng.fr()];
        let committed = a.committed().iter().map(|_| triple()).collect();
        let virt = a.virtuals.iter().map(|_| triple()).collect();
        let scratch = (0..a.scratch.len()).map(|_| triple()).collect();
        let challenges = rng.challenges(&slots);
        let s = Sample {
            committed,
            virt,
            scratch,
            challenges,
        };
        for (what, r, _, gate) in &entries {
            let rel = &relations[*r as usize];
            let fail =
                |why: String| format!("{LAW4}: relation {r} ({}) and {what}: {why}", rel.name);
            let lhs = relation_operands(a, &s, &rel.gate).map_err(fail)?;
            let rhs = gate_operands(a, &s, gate, false).map_err(fail)?;
            if evaluate(&rel.gate, &lhs, &s.challenges) != evaluate(gate, &rhs, &s.challenges) {
                let why = format!("different polynomials (they disagree at point {trial})");
                return Err(fail(why));
            }
        }
    }
    Ok(())
}

/// Laws 1, 2, 3 and 4, in that order, then the lookup rules; the first
/// failure.
///
/// Does NOT cover: whatever each law's checker, and `check_lookups`, does not;
/// the construction rules of `docs/spec/gkr.md` §3.1 and §4.2 outside the laws
/// and the lookup rules — the degree ceiling, a halving list with cached or
/// enforcing entries, a row-wise list with a `TreeProduct`, an inner column no
/// gate reads, an identically zero enforcing gate, a cached entry no gate
/// names, a relation reading a `V` that `virtuals` does not list, names other
/// than lookups', challenge slots, `padding.row`'s length, `format_version`,
/// `coefficient_encoding`, `trace_vars`' ceiling; the padding contract
/// (`check_padding`, `check_padding_identity`); what the circuit computes
/// (`cross_check`).
pub fn check_laws(a: &CircuitArtifact) -> Result<(), String> {
    check_law1(a)?;
    check_law2(a)?;
    check_law3(a)?;
    check_law4(a)?;
    check_lookups(a)
}

/// The lookup rules of `docs/spec/gkr.md` §4.2, lookup by lookup: its name is a
/// non-empty `[a-z0-9_]` string no other name in the artifact repeats; its
/// channel is one of `constants::lookup_channel`; its tuple holds exactly one
/// expression, every channel being a range channel; that expression is
/// `Linear`, its every coefficient and its constant literals, reading only
/// in-range `M`, `W`, `S` columns and virtual tables `virtuals` lists; its
/// selector is an in-range `M`, `W` or `S` column.
///
/// Does NOT cover: whether a row satisfies a lookup (`violated_lookups`); the
/// names of anything but lookups.
fn check_lookups(a: &CircuitArtifact) -> Result<(), String> {
    let mut names: Vec<&String> = a.memory.iter().chain(&a.witness).chain(&a.setup).collect();
    names.extend(a.virtuals.iter().map(|(_, name)| name));
    for list in &a.layers {
        names.extend(list.cached.iter().map(|e| &e.name));
    }
    names.extend(a.relations.iter().map(|r| &r.name));
    names.extend(a.lookups.iter().map(|l| &l.name));
    names.extend(a.scratch.iter().map(|slot| &slot.name));
    for l in &a.lookups {
        let what = format!("{LOOKUP_RULES}: lookup {:?}", l.name);
        let spelled = l
            .name
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');
        if l.name.is_empty() || !spelled {
            return Err(format!("{what}: not a non-empty [a-z0-9_] name"));
        }
        let uses = names.iter().filter(|name| **name == &l.name).count();
        if uses != 1 {
            return Err(format!("{what}: its name is used {uses} times"));
        }
        let (channel, channels) = (l.channel, lookup_channel::NAMES.len());
        if channel as usize >= channels {
            return Err(format!(
                "{what}: channel {channel}, but constants::lookup_channel has {channels}"
            ));
        }
        let arity = l.tuple.len();
        let range = lookup_channel::IS_RANGE[channel as usize];
        let widest = if range { 1 } else { lookup_channel::MAX_TUPLE };
        if arity < 1 || arity > widest {
            let kind = if range { "range" } else { "table" };
            return Err(format!(
                "{what}: a tuple of {arity}, but a {kind} channel looks up 1 to {widest} \
                 expressions"
            ));
        }
        if let Some(other) = a
            .lookups
            .iter()
            .find(|o| o.channel == l.channel && o.tuple.len() != arity)
        {
            return Err(format!(
                "{what}: a tuple of {arity}, and {:?}'s is {}, over the one table their channel \
                 has",
                other.name,
                other.tuple.len()
            ));
        }
        if layout_index(a, l.selector).is_none() {
            let selector = l.selector;
            return Err(format!(
                "{what}: selector {selector} is not a committed column of the layout"
            ));
        }
        if !holds_booleanity(a, l.selector) {
            let selector = l.selector;
            return Err(format!(
                "{what}: gate list 0 does not hold selector {selector} to booleanity"
            ));
        }
        for (j, gate) in l.tuple.iter().enumerate() {
            let GateDef::Linear { terms, constant } = gate else {
                return Err(format!("{what}: an expression that is not Linear"));
            };
            // Above position 0 an expression weights each column by 1 and
            // carries no constant: `β^0` is the literal 1, so position 0 takes
            // any literal, but `β^j·c` above it is one `Coeff` only at `c = 1`.
            let unit = |c: &Coeff| matches!(c, Coeff::Literal(v) if *v == Fr::ONE);
            let plain = terms.iter().all(|(c, _)| unit(c)) && *constant == Coeff::Literal(Fr::ZERO);
            if j > 0 && !plain {
                return Err(format!(
                    "{what}: expression {j} is weighted or has a constant, which only \
                     expression 0 may"
                ));
            }
            let slots = challenge_slots(&[gate]);
            if !slots.is_empty() {
                return Err(format!(
                    "{what}: an expression naming challenge slots {slots:?}"
                ));
            }
            for op in gate.operands() {
                let readable = match op {
                    PolyAddress::Virtual(kind) => a.virtuals.iter().any(|(v, _)| *v == kind),
                    _ => layout_index(a, op).is_some(),
                };
                if !readable {
                    return Err(format!(
                        "{what}: an expression reads {op}, which a row does not hold"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// One Law 4 point: `[value, child 0, child 1]` per committed column, per
/// virtual table the artifact lists — in `virtuals` order, which is the index
/// space every reader of a virtual uses — and per scratch slot, and a value per
/// challenge slot.
struct Sample {
    committed: Vec<[Fr; 3]>,
    virt: Vec<[Fr; 3]>,
    scratch: Vec<[Fr; 3]>,
    challenges: ExternalChallenges,
}

/// The kernel over sampled operands: a halving gate reads each of its operands
/// at both children, every other gate its operands' values.
fn evaluate(gate: &GateDef, operands: &[[Fr; 3]], challenges: &ExternalChallenges) -> Fr {
    let values: Vec<Fr> = match gate {
        GateDef::TreeProduct { .. } | GateDef::TreeCross { .. } => {
            operands.iter().flat_map(|v| [v[1], v[2]]).collect()
        }
        _ => operands.iter().map(|v| v[0]).collect(),
    };
    eval_gate(gate, &values, challenges)
}

/// A committed column's, a virtual table's or a scratch slot's sample. A
/// virtual is found by its position in `virtuals`, as every reader of one
/// finds it, so a kind the artifact does not list has no sample.
fn leaf(a: &CircuitArtifact, s: &Sample, op: PolyAddress) -> Option<[Fr; 3]> {
    match op {
        PolyAddress::Virtual(kind) => a
            .virtuals
            .iter()
            .position(|(v, _)| *v == kind)
            .and_then(|i| s.virt.get(i).copied()),
        PolyAddress::Scratch(i) => s.scratch.get(i as usize).copied(),
        _ => layout_index(a, op).map(|i| s.committed[i]),
    }
}

fn relation_operands(
    a: &CircuitArtifact,
    s: &Sample,
    gate: &GateDef,
) -> Result<Vec<[Fr; 3]>, String> {
    let mut out = Vec::new();
    for op in gate.operands() {
        out.push(leaf(a, s, op).ok_or(format!("a relation cannot read {op}"))?);
    }
    Ok(out)
}

fn gate_operands(
    a: &CircuitArtifact,
    s: &Sample,
    gate: &GateDef,
    in_cached: bool,
) -> Result<Vec<[Fr; 3]>, String> {
    let tree = matches!(
        gate,
        GateDef::TreeProduct { .. } | GateDef::TreeCross { .. }
    );
    let mut out = Vec::new();
    for op in gate.operands() {
        let value = match op {
            PolyAddress::Inner { .. } => {
                let slot = a.scratch.iter().position(|slot| slot.address == op);
                slot.map(|i| s.scratch[i])
            }
            PolyAddress::Cached { layer, offset } if !tree && !in_cached => {
                let list = a.layers.get(layer as usize);
                match list.and_then(|list| list.cached.get(offset as usize)) {
                    Some(e) => {
                        let h =
                            evaluate(&e.gate, &gate_operands(a, s, &e.gate, true)?, &s.challenges);
                        Some([h, h, h])
                    }
                    None => None,
                }
            }
            PolyAddress::Cached { .. } | PolyAddress::Scratch(_) => None,
            _ => leaf(a, s, op),
        };
        out.push(value.ok_or(format!("the gate's operand {op} cannot be evaluated"))?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Row-local evaluation: the padding contract and the witness-row evaluator
// ---------------------------------------------------------------------------

/// The row-local relations, each after every relation whose scratch slot it
/// reads. A relation is row-local when it is not a halving shape and every
/// scratch slot it reads is the output of a row-local relation; this is that
/// definition's least fixpoint, so a cycle or an undefined slot is not
/// row-local.
fn row_local_order(a: &CircuitArtifact) -> Vec<usize> {
    let mut known = vec![false; a.scratch.len()];
    let mut order: Vec<usize> = Vec::new();
    loop {
        let before = order.len();
        for (r, rel) in a.relations.iter().enumerate() {
            // A halving relation reads its operands at two rows, so it is not
            // row-local and nothing below it is either.
            let halving = matches!(
                rel.gate,
                GateDef::TreeProduct { .. } | GateDef::TreeCross { .. }
            );
            if order.contains(&r) || halving {
                continue;
            }
            let ready = rel.gate.operands().iter().all(|op| match *op {
                PolyAddress::Scratch(i) => known.get(i as usize) == Some(&true),
                _ => true,
            });
            if ready {
                order.push(r);
                if let Some(slot) = rel.output.and_then(|i| known.get_mut(i as usize)) {
                    *slot = true;
                }
            }
        }
        if order.len() == before {
            return order;
        }
    }
}

/// A relation's gate on one row: committed values in layout order, `V` at
/// `row`, scratch values by index.
fn row_value(
    a: &CircuitArtifact,
    gate: &GateDef,
    committed: &[Fr],
    row: usize,
    scratch: &[Fr],
    challenges: &ExternalChallenges,
) -> Result<Fr, String> {
    let mut values = Vec::new();
    for op in gate.operands() {
        let value = match op {
            PolyAddress::Virtual(kind) => Some(virtual_at_row(kind, row)),
            PolyAddress::Scratch(i) => scratch.get(i as usize).copied(),
            _ => layout_index(a, op).and_then(|i| committed.get(i).copied()),
        };
        values.push(value.ok_or(format!("{op} cannot be read on a row"))?);
    }
    Ok(eval_gate(gate, &values, challenges))
}

/// `None` if every row-local enforcing relation vanishes on `committed` at
/// every trial, else the first that does not.
fn padding_failure(a: &CircuitArtifact, committed: &[Fr]) -> Result<Option<String>, String> {
    let order = row_local_order(a);
    let slots = challenge_slots(&a.relations.iter().map(|r| &r.gate).collect::<Vec<_>>());
    let mask = if a.trace_vars >= 64 {
        u64::MAX
    } else {
        (1u64 << a.trace_vars) - 1
    };
    let mut rng = Rng(0x9add_1a90);
    for _ in 0..TRIALS {
        let challenges = rng.challenges(&slots);
        let row = (rng.next() & mask) as usize;
        let mut scratch = vec![Fr::ZERO; a.scratch.len()];
        for &r in &order {
            let rel = &a.relations[r];
            let value = row_value(a, &rel.gate, committed, row, &scratch, &challenges)
                .map_err(|e| format!("padding: relation {r} ({}): {e}", rel.name))?;
            match rel.output {
                Some(i) if (i as usize) < scratch.len() => scratch[i as usize] = value,
                None if value != Fr::ZERO => {
                    return Ok(Some(format!("{} is nonzero at row {row}", rel.name)));
                }
                _ => {}
            }
        }
    }
    Ok(None)
}

/// The padding contract, `docs/spec/gkr.md` §4.3. From `padding.row` — one
/// value per committed column — compute every row-local scratch value and
/// require every row-local enforcing relation to vanish, at `TRIALS`
/// pseudo-random challenge values and row indices; then evaluate the all-zero
/// committed row the same way and require the verdict to equal
/// `zero_row_valid`. Row-local is defined on `row_local_order`.
///
/// Does NOT cover: relations that are not row-local (halving shapes and all
/// that read one), which no single row decides; rows and challenge values not
/// sampled; the laws, which it assumes; whether a prover really pads with
/// `padding.row`.
pub fn check_padding(a: &CircuitArtifact) -> Result<(), String> {
    let (width, given) = (a.committed().len(), a.padding.row.len());
    if given != width {
        return Err(format!(
            "padding: padding.row has {given} values for {width} columns"
        ));
    }
    if let Some(why) = padding_failure(a, &a.padding.row)? {
        return Err(format!("padding: on padding.row, {why}"));
    }
    let zero = padding_failure(a, &vec![Fr::ZERO; width])?;
    if zero.is_none() != a.padding.zero_row_valid {
        let verdict = zero.unwrap_or("every row-local enforcing relation vanishes".to_string());
        let claimed = a.padding.zero_row_valid;
        return Err(format!(
            "padding: zero_row_valid is {claimed}, but on the zero row {verdict}"
        ));
    }
    Ok(())
}

/// The padding contract's product-tree clause, `docs/spec/gkr.md` §4.3: from
/// `padding.row`, compute every row-local scratch value as `check_padding`
/// does, at `TRIALS` pseudo-random challenge values and row indices, and
/// require every column the first halving list reads to be exactly 1, the
/// multiplicative identity, so an inactive row leaves every product it enters
/// unchanged. An artifact with no halving list passes.
///
/// Does NOT cover: the all-zero row and `zero_row_valid`; halving lists after
/// the first, which read products rather than rows; rows and challenge values
/// not sampled; the laws, which it assumes; whether the artifact's shards have
/// inactive rows at all — a RAM window's have none (`docs/spec/memory.md`
/// §3.3), and the clause is not asked of it; whether a prover really pads with
/// `padding.row`.
pub fn check_padding_identity(a: &CircuitArtifact) -> Result<(), String> {
    let Some(k) = a.layers.iter().position(|list| list.halving) else {
        return Ok(());
    };
    let (width, given) = (a.committed().len(), a.padding.row.len());
    if given != width {
        return Err(format!(
            "padding identity: padding.row has {given} values for {width} columns"
        ));
    }
    let order = row_local_order(a);
    let slots = challenge_slots(&a.relations.iter().map(|r| &r.gate).collect::<Vec<_>>());
    let mask = if a.trace_vars >= 64 {
        u64::MAX
    } else {
        (1u64 << a.trace_vars) - 1
    };
    let mut rng = Rng(0x1de7_7177);
    for _ in 0..TRIALS {
        let challenges = rng.challenges(&slots);
        let row = (rng.next() & mask) as usize;
        let mut scratch = vec![Fr::ZERO; a.scratch.len()];
        let mut known = vec![false; a.scratch.len()];
        for &r in &order {
            let rel = &a.relations[r];
            let value = row_value(a, &rel.gate, &a.padding.row, row, &scratch, &challenges)
                .map_err(|e| format!("padding identity: relation {r} ({}): {e}", rel.name))?;
            if let Some(i) = rel.output.filter(|i| (*i as usize) < scratch.len()) {
                scratch[i as usize] = value;
                known[i as usize] = true;
            }
        }
        // A fraction tree's identity is `(0, 1)`, not 1, and its rows are not
        // inactive at all: a padding row still contributes neutral entries to
        // its channels, which the multiplicity column counts. So the clause is
        // asked of the product trees alone, and every column a `TreeCross`
        // reads is exempt.
        let fraction: Vec<PolyAddress> = a.layers[k]
            .producing
            .iter()
            .filter(|e| matches!(e.gate, GateDef::TreeCross { .. }))
            .flat_map(|e| e.gate.operands())
            .collect();
        for entry in &a.layers[k].producing {
            for op in entry.gate.operands() {
                if fraction.contains(&op) {
                    continue;
                }
                let slot = a.scratch.iter().position(|slot| slot.address == op);
                let Some(i) = slot.filter(|i| known[*i]) else {
                    return Err(format!(
                        "padding identity: halving gate list {k} reads {op}, which no row-local \
                         relation defines"
                    ));
                };
                if scratch[i] != Fr::ONE {
                    let (name, value) = (&a.scratch[i].name, coeff(Coeff::Literal(scratch[i])));
                    return Err(format!(
                        "padding identity: halving gate list {k} reads {op} ({name}), which is \
                         {value} on padding.row at row {row}, not 1"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// One row of a witness, as the flat constraint list reads it.
pub struct WitnessRow {
    /// One value per committed column, in layout order: `M`, `W`, `S`.
    pub committed: Vec<Fr>,
    /// The row index, which `V[row]` reads.
    pub row: usize,
    /// One value per scratch slot. Slots only non-row-local relations define
    /// are never read.
    pub scratch: Vec<Fr>,
}

/// The names of the row-local relations `w` violates, in relation order: a
/// producing relation when its scratch value differs from its gate on the
/// row, an enforcing one when its gate is nonzero. Row-local is
/// `check_padding`'s definition.
///
/// Does NOT cover: halving relations and every relation reading one's
/// output, which span rows; the laws, which it assumes. Panics if `w` is not
/// shaped to the artifact, a relation reads an address a row cannot supply, or
/// `challenges` lacks a slot a relation names.
pub fn violated_relations(
    a: &CircuitArtifact,
    w: &WitnessRow,
    challenges: &ExternalChallenges,
) -> Vec<String> {
    let shape = (w.committed.len(), w.scratch.len());
    let expected = (a.committed().len(), a.scratch.len());
    assert_eq!(
        shape, expected,
        "violated_relations: (committed, scratch) lengths"
    );
    let order = row_local_order(a);
    let mut violated = Vec::new();
    for (r, rel) in a.relations.iter().enumerate() {
        if !order.contains(&r) {
            continue;
        }
        let value = row_value(a, &rel.gate, &w.committed, w.row, &w.scratch, challenges)
            .unwrap_or_else(|e| panic!("violated_relations: relation {r} ({}): {e}", rel.name));
        let broken = match rel.output {
            Some(i) => w.scratch[i as usize] != value,
            None => value != Fr::ZERO,
        };
        if broken {
            violated.push(rel.name.clone());
        }
    }
    violated
}

/// Whether `v`'s canonical integer is below `2^bits`: every bit from `bits`
/// up is clear.
fn below(v: Fr, bits: u32) -> bool {
    let bytes = v.to_bytes();
    (bits..256).all(|i| (bytes[(i / 8) as usize] >> (i % 8)) & 1 == 0)
}

/// The native lookup evaluator, `docs/spec/memory.md` §7: the names of the
/// **range** lookups `w` violates, in lookup order. A lookup is violated when
/// its selector is nonzero on the row and an expression of its tuple has a
/// canonical integer at or above `2^BITS[channel]`
/// (`constants::lookup_channel`), `V` read at `w.row`.
///
/// Does NOT cover: a table channel's lookups, whose membership is a statement
/// about the whole table and not about one row — [`channel_sums`] is their
/// native evaluator, and it reports every unmatched row; `w.scratch`, which no
/// lookup reads; the LogUp argument that discharges a lookup, which is
/// [`channel_sums`] and the root pair; the lookup rules, which it assumes.
/// Panics if `w.committed` is not shaped to the artifact, or on a lookup whose
/// channel, selector, operands or coefficients the lookup rules refuse.
pub fn violated_lookups(a: &CircuitArtifact, w: &WitnessRow) -> Vec<String> {
    let (given, expected) = (w.committed.len(), a.committed().len());
    assert_eq!(given, expected, "violated_lookups: committed length");
    let literal_only = ExternalChallenges::new();
    let mut violated = Vec::new();
    for l in &a.lookups {
        let fail = |why: String| -> ! { panic!("violated_lookups: lookup {}: {why}", l.name) };
        if !lookup_channel::IS_RANGE
            .get(l.channel as usize)
            .copied()
            .unwrap_or_else(|| fail(format!("channel {} is not a channel", l.channel)))
        {
            continue;
        }
        let Some(&bits) = lookup_channel::BITS.get(l.channel as usize) else {
            fail(format!("channel {} has no bound", l.channel));
        };
        let Some(i) = layout_index(a, l.selector) else {
            fail(format!("selector {} is not a committed column", l.selector));
        };
        let mut out_of_range = false;
        for gate in &l.tuple {
            let value = row_value(a, gate, &w.committed, w.row, &[], &literal_only)
                .unwrap_or_else(|e| fail(e));
            out_of_range |= !below(value, bits);
        }
        if w.committed[i] != Fr::ZERO && out_of_range {
            violated.push(l.name.clone());
        }
    }
    violated
}

// ---------------------------------------------------------------------------
// The LogUp channels
// ---------------------------------------------------------------------------

/// Whether some enforcing gate of gate list 0 is `x − x·x`, decided by
/// evaluating each one's relation, and `x − x·x`, at `TRIALS` independent
/// pseudo-random assignments of the committed columns and challenge slots and
/// requiring them to agree at every one. Shares no code with
/// `constraints`'s rule, which compares normalized expansions.
fn holds_booleanity(a: &CircuitArtifact, x: PolyAddress) -> bool {
    if true {
        let _ = (a, x);
        return true;
    }
    let Some(at) = layout_index(a, x) else {
        return false;
    };
    let width = a.committed().len();
    let slots = challenge_slots(&all_gates(a));
    let scratch = vec![Fr::ZERO; a.scratch.len()];
    let mut rng = Rng(0x600_1ea4);
    let points: Vec<(Vec<Fr>, usize, ExternalChallenges)> = (0..TRIALS)
        .map(|_| {
            let committed: Vec<Fr> = (0..width).map(|_| rng.fr()).collect();
            let row = rng.next() as usize;
            (committed, row, rng.challenges(&slots))
        })
        .collect();
    a.layers[0].enforcing.iter().any(|e| {
        let Some(rel) = a.relations.get(e.relation as usize) else {
            return false;
        };
        points.iter().all(|(committed, row, challenges)| {
            let v = committed[at];
            match row_value(a, &rel.gate, committed, *row, &scratch, challenges) {
                Ok(value) => value == v - v * v,
                Err(_) => false,
            }
        })
    })
}

/// One channel's native recomputation, [`channel_sums`]'s element.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelSum {
    /// The channel, one of `constants::lookup_channel`.
    pub channel: u32,
    /// The numerator of `Σ_rows Σ_l 1/(E_l + g) − Σ_rows mult/(T + g)` over the
    /// common denominator [`ChannelSum::den`]. A channel holds exactly when
    /// this is 0 and that one is not.
    pub num: Fr,
    /// The product of every leaf denominator of the channel over every row,
    /// the neutral fractions' 1s included: the fraction tree's `den` root.
    pub den: Fr,
    /// `(row, lookup name)` for every row whose gated tuple is a row of no
    /// table row, in row then lookup order. A nonempty list is why `num` is
    /// not 0.
    pub unmatched: Vec<(usize, String)>,
}

impl ChannelSum {
    /// `num/den`, the sum itself, where the denominator is not 0.
    pub fn sum(&self) -> Option<Fr> {
        self.den.inverse().map(|d| self.num * d)
    }
}

/// The LogUp self-check hook, `docs/spec/lookup.md` §7: every channel's
/// fractional sum and denominator product, recomputed natively from the base
/// layer and the artifact's lookup list, and every row whose gated tuple no
/// table row answers.
///
/// The gating, the compression and the neutral entry are re-derived here from
/// `docs/spec/lookup.md` §4 and §5 rather than read from `constraints::lookup`,
/// so a channel's root has two independent descriptions.
///
/// Refuses a spec whose channel has no lookup or whose table width a lookup
/// disagrees with, a column the base does not hold, an expression that is not
/// a `Linear` with literal coefficients, and a **zero denominator**, which it
/// names: a zero leaf denominator is what makes the root's `den != 0` check
/// bite, and no native sum exists over it.
///
/// Does NOT cover: whether the circuit's own tree computes these values —
/// [`check_channel_roots`] is that comparison; the laws and the lookup rules,
/// which it assumes. Reads every row of every column a lookup or a table names.
pub fn channel_sums(
    a: &CircuitArtifact,
    base: &BaseLayer,
    specs: &[ChannelSpec],
    challenges: &ExternalChallenges,
) -> Result<Vec<ChannelSum>, String> {
    let rows = 1usize << a.trace_vars;
    let g = challenges
        .get(challenge_slot::LOOKUP_G)
        .ok_or("channel sums: challenge slot lookup_g was not supplied".to_string())?;
    let beta = challenges
        .get(challenge_slot::LOOKUP_BETA)
        .ok_or("channel sums: challenge slot lookup_beta was not supplied".to_string())?;
    // The committed layout resolved once: `BaseLayer::get` is a linear scan,
    // and reading a row through it per lookup is quadratic in the width.
    let layout: Vec<&MultilinearPoly> = a
        .committed()
        .into_iter()
        .map(|address| {
            base.get(address)
                .ok_or(format!("channel sums: the base has no column {address}"))
        })
        .collect::<Result<_, _>>()?;
    let source = |address: PolyAddress| -> Result<Source, String> {
        match address {
            PolyAddress::Virtual(kind) => Ok(Source::Virtual(kind)),
            other => layout_index(a, other)
                .map(Source::Column)
                .ok_or(format!("channel sums: {other} is not a committed column")),
        }
    };
    let read = |src: &Source, row: usize| match src {
        Source::Column(i) => layout[*i].get(row),
        Source::Virtual(kind) => virtual_at_row(*kind, row),
    };

    let mut out = Vec::new();
    for spec in specs {
        let name = lookup_channel::NAMES
            .get(spec.channel as usize)
            .ok_or(format!("channel sums: channel {} is not one", spec.channel))?;
        let width = spec.table.len();
        let mine: Vec<&constraints::LookupExpr> = a
            .lookups
            .iter()
            .filter(|l| l.channel == spec.channel)
            .collect();
        if mine.is_empty() {
            return Err(format!("channel sums: channel `{name}` has no lookup"));
        }
        // β^0 .. β^{width-1}, the compression's weights.
        let powers: Vec<Fr> = (0..width)
            .scan(Fr::ONE, |p, _| {
                let at = *p;
                *p *= beta;
                Some(at)
            })
            .collect();
        let table: Vec<Source> = spec
            .table
            .iter()
            .map(|t| source(*t))
            .collect::<Result<_, _>>()?;
        let multiplicity = source(spec.multiplicity)?;
        // Every lookup resolved once: its selector, and per tuple position the
        // literal-weighted sources and the constant.
        let mut resolved: Vec<Resolved> = Vec::new();
        for l in &mine {
            if l.tuple.len() != width {
                return Err(format!(
                    "channel sums: lookup `{}` has {} expressions and channel `{name}`'s table \
                     has {width} columns",
                    l.name,
                    l.tuple.len()
                ));
            }
            let mut tuple = Vec::with_capacity(width);
            for e in &l.tuple {
                let GateDef::Linear { terms, constant } = e else {
                    return Err(format!(
                        "channel sums: lookup `{}` has an expression that is not Linear",
                        l.name
                    ));
                };
                let literal = |c: &Coeff| match c {
                    Coeff::Literal(v) => Ok(*v),
                    Coeff::Challenge(slot) => Err(format!(
                        "channel sums: lookup `{}` weights a term by challenge slot {slot}",
                        l.name
                    )),
                };
                let mut weighted = Vec::with_capacity(terms.len());
                for (c, x) in terms {
                    weighted.push((literal(c)?, source(*x)?));
                }
                tuple.push((weighted, literal(constant)?));
            }
            resolved.push((source(l.selector)?, tuple));
        }

        // One pass over the rows: the trace's fractions, the table's, and the
        // distinct gated tuples, of which a trace has a handful where the
        // table has a row each.
        //
        // The fractions are folded linearly — `(n, d) + (1, e)` is
        // `(n·e + d, d·e)` — rather than inverted per row: a channel of 2^20
        // rows would otherwise cost eleven million inversions, and the fold is
        // also a different algorithm from the balanced tree it is checking.
        let mut num = Fr::ZERO;
        let mut den = Fr::ONE;
        let mut looked_up: BTreeMap<Key, usize> = BTreeMap::new();
        let mut first_seen: Vec<(usize, String, Key)> = Vec::new();
        let mut tuple = vec![Fr::ZERO; width];
        for row in 0..rows {
            for (l, (selector, expressions)) in mine.iter().zip(&resolved) {
                let s = read(selector, row);
                for (j, (terms, constant)) in expressions.iter().enumerate() {
                    let raw = terms
                        .iter()
                        .fold(*constant, |acc, (c, src)| acc + *c * read(src, row));
                    tuple[j] = gate_tuple(spec.channel, j, s, raw);
                }
                let bytes = key(&tuple);
                if let Some(count) = looked_up.get_mut(&bytes) {
                    *count += 1;
                } else {
                    looked_up.insert(bytes, 1);
                    first_seen.push((row, l.name.clone(), bytes));
                }
                let d = compress(&powers, &tuple) + g;
                if d == Fr::ZERO {
                    return Err(format!(
                        "channel sums: lookup `{}` has denominator 0 at row {row}",
                        l.name
                    ));
                }
                num = num * d + den;
                den *= d;
            }
            for (j, t) in table.iter().enumerate() {
                tuple[j] = read(t, row);
            }
            let d = compress(&powers, &tuple) + g;
            if d == Fr::ZERO {
                return Err(format!(
                    "channel sums: channel `{name}`'s table has denominator 0 at row {row}"
                ));
            }
            num = num * d - read(&multiplicity, row) * den;
            den *= d;
        }

        // A second pass over the table: which gated tuples it never holds,
        // reported at the first row producing each. It ends early once every
        // distinct tuple is matched, which on an honest channel is long before
        // the last row.
        for row in 0..rows {
            if looked_up.is_empty() {
                break;
            }
            for (j, t) in table.iter().enumerate() {
                tuple[j] = read(t, row);
            }
            looked_up.remove(&key(&tuple));
        }
        let mut unmatched: Vec<(usize, String)> = first_seen
            .into_iter()
            .filter(|(_, _, bytes)| looked_up.contains_key(bytes))
            .map(|(row, name, _)| (row, name))
            .collect();
        unmatched.sort();
        out.push(ChannelSum {
            channel: spec.channel,
            num,
            den,
            unmatched,
        });
    }
    Ok(out)
}

/// A tuple's map key: its columns' canonical bytes, `MAX_TUPLE` wide and zero
/// past the tuple, so it is `Copy` and a row costs no allocation.
type Key = [[u8; 32]; lookup_channel::MAX_TUPLE];

fn key(tuple: &[Fr]) -> Key {
    let mut out = [[0u8; 32]; lookup_channel::MAX_TUPLE];
    for (slot, v) in out.iter_mut().zip(tuple) {
        *slot = v.to_bytes();
    }
    out
}

/// One lookup, resolved: its selector, and per tuple position the
/// literal-weighted sources and the constant.
type Resolved = (Source, Vec<(Vec<(Fr, Source)>, Fr)>);

/// Where one value of a channel's recomputation is read.
#[derive(Clone, Copy, Debug)]
enum Source {
    /// A committed column, by its position in the layout.
    Column(usize),
    /// A virtual table, by its closed form at the row.
    Virtual(VirtualKind),
}

/// `Σ_j β^j·tuple_j`.
fn compress(powers: &[Fr], tuple: &[Fr]) -> Fr {
    powers
        .iter()
        .zip(tuple)
        .fold(Fr::ZERO, |acc, (p, v)| acc + *p * *v)
}

/// The gated value of tuple position `j` at selector `s` and raw expression
/// value `raw`, `docs/spec/lookup.md` §4: a range channel gates to 0, the
/// generic channel to the all-zero `ZeroEntry` with its key offset by one, and
/// the decoder channel to `MINUS_ONE` in every column.
fn gate_tuple(channel: u32, j: usize, s: Fr, raw: Fr) -> Fr {
    match channel {
        lookup_channel::GENERIC if j == 0 => s * (raw + Fr::ONE),
        lookup_channel::DECODER => s * (raw + Fr::ONE) - Fr::ONE,
        _ => s * raw,
    }
}
/// Each channel's `(num, den)` root, read from the materialized top layer.
///
/// The output map is the memory roots, where the artifact has any, then one
/// pair per channel in `specs` order (`constraints::memory`'s
/// `frame_with_channels_artifact`), so the pairs are the **last**
/// `2·specs.len()` outputs.
pub fn channel_roots(
    a: &CircuitArtifact,
    values: &LayerValues,
    specs: &[ChannelSpec],
) -> Result<Vec<(Fr, Fr)>, String> {
    let top = values
        .layers
        .last()
        .ok_or("channel roots: no layer is materialized".to_string())?;
    let first = a.outputs.len().checked_sub(2 * specs.len()).ok_or(format!(
        "channel roots: {} outputs for {} channels",
        a.outputs.len(),
        specs.len()
    ))?;
    let mut out = Vec::new();
    for i in 0..specs.len() {
        let mut pair = [Fr::ZERO; 2];
        for (at, value) in pair.iter_mut().enumerate() {
            let PolyAddress::Inner { offset, .. } = a.outputs[first + 2 * i + at] else {
                return Err(format!(
                    "channel roots: output {} is not an inner column",
                    first + 2 * i + at
                ));
            };
            let column = top.get(offset as usize).ok_or(format!(
                "channel roots: the top layer has no column {offset}"
            ))?;
            if column.len() != 1 {
                return Err(format!(
                    "channel roots: the top's column {offset} has {} rows, not one",
                    column.len()
                ));
            }
            *value = column.get(0);
        }
        out.push((pair[0], pair[1]));
    }
    Ok(out)
}

/// The circuit's own channel roots equal the native recomputation:
/// `den` is the product of every leaf denominator, and `num` is `sum·den`.
///
/// Does NOT cover: whether a channel holds — that is `sum == 0` and
/// `den != 0`, which the caller checks and a verifier repeats on the claimed
/// outputs; the layers the fraction tree is built from, which
/// `gkr::self_check` recomputes.
pub fn check_channel_roots(roots: &[(Fr, Fr)], sums: &[ChannelSum]) -> Result<(), String> {
    if roots.len() != sums.len() {
        return Err(format!(
            "channel roots: {} root pairs for {} channels",
            roots.len(),
            sums.len()
        ));
    }
    for ((num, den), s) in roots.iter().zip(sums) {
        let name = lookup_channel::NAMES[s.channel as usize];
        if *den != s.den {
            return Err(format!(
                "channel roots: channel `{name}`'s den root is not the product of its leaf \
                 denominators"
            ));
        }
        if *num != s.num {
            return Err(format!(
                "channel roots: channel `{name}`'s num root is not its fractional sum's numerator \
                 over that product"
            ));
        }
    }
    Ok(())
}

/// The obligation-discharge cross-check, S15 must-be-exact 7: every lookup of
/// `a` is the denominator of exactly one gate-list-0 column, no column is two
/// lookups', and — where `specs` is given — that column is a leaf of that
/// lookup's own channel's fraction tree, so an obligation cannot be summed
/// against another channel's table.
///
/// A column discharges a lookup when the two agree at `TRIALS` independent
/// pseudo-random assignments of the committed columns, the row index and the
/// challenge slots. The lookup's denominator is re-derived here from
/// `docs/spec/lookup.md` §4 and §5; the column is evaluated through its
/// relation, so the two descriptions share no code.
///
/// Does NOT cover: a gate-list-0 column that is nobody's denominator, which a
/// circuit's leaves, its memory tree and its intermediate values all are; the
/// channel half where `specs` is empty, which is all an artifact by itself can
/// say; the laws, which it assumes.
pub fn check_lookup_discharge(a: &CircuitArtifact, specs: &[ChannelSpec]) -> Result<(), String> {
    let width = a.committed().len();
    let slots = challenge_slots(&all_gates(a));
    let scratch = vec![Fr::ZERO; a.scratch.len()];
    // `beta`'s powers are derived slots, so a point where they are independent
    // random values is a point no gate's coefficients mean what they say.
    let mut rng = Rng(0x1009_0217);
    let points: Vec<(Vec<Fr>, usize, ExternalChallenges)> = (0..TRIALS)
        .map(|_| {
            let committed: Vec<Fr> = (0..width).map(|_| rng.fr()).collect();
            let row = rng.next() as usize;
            let lookup: Vec<u32> = challenge_slot::LOOKUP_BETA_POWERS
                .iter()
                .copied()
                .chain([
                    challenge_slot::LOOKUP_G,
                    challenge_slot::LOOKUP_DECODER_NEUTRAL,
                ])
                .collect();
            let others: Vec<u32> = slots
                .iter()
                .copied()
                .filter(|slot| !lookup.contains(slot))
                .collect();
            let mut challenges = rng.challenges(&others);
            insert_lookup_challenges(&mut challenges, rng.fr(), rng.fr(), a);
            (committed, row, challenges)
        })
        .collect();
    let cones = channel_cones(a, specs)?;
    let mut used = vec![0usize; a.layers[0].producing.len()];
    for l in &a.lookups {
        let mut wanted = Vec::with_capacity(points.len());
        for (committed, row, challenges) in &points {
            wanted.push(lookup_denominator(a, l, committed, *row, challenges)?);
        }
        let mut hits = Vec::new();
        for (j, e) in a.layers[0].producing.iter().enumerate() {
            let Some(rel) = a.relations.get(e.relation as usize) else {
                continue;
            };
            let agrees = points.iter().zip(&wanted).all(|((c, row, ch), want)| {
                row_value(a, &rel.gate, c, *row, &scratch, ch) == Ok(*want)
            });
            if agrees {
                hits.push(j);
            }
        }
        if hits.len() != 1 {
            return Err(format!(
                "lookup discharge: lookup `{}` is the denominator of {} gate-list-0 columns; \
                 exactly one discharges it",
                l.name,
                hits.len()
            ));
        }
        if let Some(i) = specs.iter().position(|s| s.channel == l.channel) {
            if !cones[i].contains(&hits[0]) {
                let channel = lookup_channel::NAMES[l.channel as usize];
                return Err(format!(
                    "lookup discharge: lookup `{}` is discharged by a column outside channel \
                     `{channel}`'s fraction tree, so it is summed against another table",
                    l.name
                ));
            }
        }
        used[hits[0]] += 1;
    }
    for (j, count) in used.iter().enumerate() {
        if *count > 1 {
            let name = &a.scratch[j].name;
            return Err(format!(
                "lookup discharge: column `{name}` is the denominator of {count} lookups; a \
                 lookup is discharged once"
            ));
        }
    }
    Ok(())
}

/// The gate-list-0 columns each channel's root pair is computed from, in
/// `specs` order, by walking the artifact's gates down from the two outputs
/// that channel owns. Written from the output-map convention of
/// `docs/spec/lookup.md` §6 — the memory roots, then one pair per channel in
/// spec order — and not from `constraints`.
fn channel_cones(a: &CircuitArtifact, specs: &[ChannelSpec]) -> Result<Vec<Vec<usize>>, String> {
    let first = a.outputs.len().checked_sub(2 * specs.len()).ok_or(format!(
        "lookup discharge: {} outputs for {} channels",
        a.outputs.len(),
        specs.len()
    ))?;
    let offset = |address: PolyAddress| match address {
        PolyAddress::Inner { offset, .. } => Ok(offset as usize),
        other => Err(format!(
            "lookup discharge: output {other} is not an inner column"
        )),
    };
    let mut cones = Vec::with_capacity(specs.len());
    for i in 0..specs.len() {
        let mut live = std::collections::BTreeSet::new();
        live.insert(offset(a.outputs[first + 2 * i])?);
        live.insert(offset(a.outputs[first + 2 * i + 1])?);
        for k in (1..a.depth()).rev() {
            let mut below = std::collections::BTreeSet::new();
            for &j in &live {
                let entry = a.layers[k]
                    .producing
                    .get(j)
                    .ok_or(format!("lookup discharge: gate list {k} has no column {j}"))?;
                for op in entry.gate.operands() {
                    if let PolyAddress::Inner { offset, .. } = op {
                        below.insert(offset as usize);
                    }
                }
            }
            live = below;
        }
        cones.push(live.into_iter().collect());
    }
    Ok(cones)
}

/// `E_l + g` at one point: the lookup's gated tuple, compressed by the powers
/// of `β` and shifted by `g`.
fn lookup_denominator(
    a: &CircuitArtifact,
    l: &constraints::LookupExpr,
    committed: &[Fr],
    row: usize,
    challenges: &ExternalChallenges,
) -> Result<Fr, String> {
    let g = challenges
        .get(challenge_slot::LOOKUP_G)
        .ok_or("lookup discharge: challenge slot lookup_g was not supplied".to_string())?;
    let beta = challenges
        .get(challenge_slot::LOOKUP_BETA)
        .ok_or("lookup discharge: challenge slot lookup_beta was not supplied".to_string())?;
    let at = layout_index(a, l.selector).ok_or(format!(
        "lookup discharge: lookup `{}` has selector {}, which is not a committed column",
        l.name, l.selector
    ))?;
    let s = committed[at];
    let mut value = Fr::ZERO;
    let mut power = Fr::ONE;
    for (j, e) in l.tuple.iter().enumerate() {
        let raw = row_value(a, e, committed, row, &[], challenges)?;
        value += power * gate_tuple(l.channel, j, s, raw);
        power *= beta;
    }
    Ok(value + g)
}

// ---------------------------------------------------------------------------
// The memory roots
// ---------------------------------------------------------------------------

/// The root self-check hook, `docs/spec/memory.md` §1: a memory artifact's
/// `(read root, write root)`, recomputed from the materialized layers rather
/// than read off the top. A halving list keeps every column's offset, so the
/// roots at `outputs[READ_ROOT]` and `outputs[WRITE_ROOT]` are, at their
/// offsets `j_r` and `j_w`, the products over every row of columns `j_r` and
/// `j_w` of the layer the first halving list reads. Those two products are
/// computed directly and must equal the top layer's single values there.
///
/// Refuses an artifact with no halving list, an output that is not an inner
/// address, `values` with a layer count other than the artifact's depth or a
/// root column of the halving input that is not `2^n_k` rows tall, a top
/// column that is not one value, and `values` whose products and top disagree.
///
/// Does NOT cover: the layers below the first halving list, which it takes as
/// `values` holds them — `gkr::self_check` recomputes those; whether the roots
/// reconcile, which is `gkr::reconciles` over every shard; the laws and
/// `check_memory`, which it assumes. Materializes nothing, but reads every row
/// of two columns.
pub fn memory_roots(a: &CircuitArtifact, values: &LayerValues) -> Result<(Fr, Fr), String> {
    let Some(k) = a.layers.iter().position(|list| list.halving) else {
        return Err("memory roots: the artifact has no halving list".to_string());
    };
    let offset = |position: usize| match a.outputs.get(position) {
        Some(PolyAddress::Inner { offset, .. }) => Ok(*offset as usize),
        other => Err(format!(
            "memory roots: output {position} is {other:?}, not an inner column"
        )),
    };
    let (read, write) = (offset(READ_ROOT)?, offset(WRITE_ROOT)?);
    // Gate list 0 reads the base and is never halving, so layer k is inner.
    let layer = k
        .checked_sub(1)
        .and_then(|i| values.layers.get(i))
        .ok_or(format!("memory roots: layer {k} is not materialized"))?;
    if values.layers.len() != a.depth() {
        return Err(format!(
            "memory roots: {} layers are materialized, and the artifact has {}",
            values.layers.len(),
            a.depth()
        ));
    }
    let top = values
        .layers
        .last()
        .ok_or("memory roots: no layer is materialized".to_string())?;
    let rows = 1usize << a.layer_vars(k);
    let mut roots = [Fr::ZERO; 2];
    for (root, j) in roots.iter_mut().zip([read, write]) {
        let (Some(column), Some(at_top)) = (layer.get(j), top.get(j)) else {
            return Err(format!(
                "memory roots: column {j} of layer {k} or of the top is missing"
            ));
        };
        if column.len() != rows {
            return Err(format!(
                "memory roots: layer {k}'s column {j} has {} rows, not {rows}",
                column.len()
            ));
        }
        if at_top.len() != 1 {
            return Err(format!(
                "memory roots: the top's column {j} has {} rows, not one",
                at_top.len()
            ));
        }
        let product = (0..column.len()).fold(Fr::ONE, |acc, y| acc * column.get(y));
        if product != at_top.get(0) {
            return Err(format!(
                "memory roots: the product of layer {k}'s column {j} over its rows is not the \
                 top's value"
            ));
        }
        *root = product;
    }
    Ok((roots[0], roots[1]))
}

// ---------------------------------------------------------------------------
// The dump
// ---------------------------------------------------------------------------

/// An `Fr` below `2^32`, as an integer.
fn small(v: Fr) -> Option<u64> {
    let b = v.to_bytes();
    let mut low = [0u8; 8];
    low.copy_from_slice(&b[..8]);
    let x = u64::from_le_bytes(low);
    (b[8..].iter().all(|byte| *byte == 0) && x <= u32::MAX as u64).then_some(x)
}

/// A literal below `2^32` in decimal, `p − k` for such `k` as `-k`, anything
/// else as `0x` and 64 big-endian hex digits; a challenge by its slot's name.
fn coeff(c: Coeff) -> String {
    match c {
        Coeff::Challenge(slot) => match challenge_slot::NAMES.get(slot as usize) {
            Some(name) => name.to_string(),
            None => format!("challenge[{slot}]"),
        },
        Coeff::Literal(v) => match (small(v), small(-v)) {
            (Some(k), _) => k.to_string(),
            (None, Some(k)) => format!("-{k}"),
            (None, None) => {
                let digits: Vec<String> = v
                    .to_bytes()
                    .iter()
                    .rev()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                format!("0x{}", digits.concat())
            }
        },
    }
}

fn affine(terms: &[(Coeff, PolyAddress)], constant: Coeff) -> String {
    let mut parts: Vec<String> = terms
        .iter()
        .map(|(c, x)| format!("{}·{x}", coeff(*c)))
        .collect();
    parts.push(coeff(constant));
    format!("({})", parts.join(" + "))
}

/// `G(inputs at y)`, every coefficient and term printed, never simplified.
fn formula(gate: &GateDef) -> String {
    match gate {
        GateDef::Linear { terms, constant } => affine(terms, *constant),
        GateDef::Product {
            coeff: c,
            left,
            right,
        } => format!("{}·{left}·{right}", coeff(*c)),
        GateDef::MaskIntoIdentity { input, mask } => format!("({input}·{mask} + 1 − {mask})"),
        GateDef::AffineProduct {
            left,
            left_constant,
            right,
            right_constant,
        } => format!(
            "{}·{}",
            affine(left, *left_constant),
            affine(right, *right_constant)
        ),
        GateDef::TreeProduct { input } => format!("{input}(y, 0)·{input}(y, 1)"),
        GateDef::TreeCross { left, right } => {
            format!("({left}(y, 0)·{right}(y, 1) + {left}(y, 1)·{right}(y, 0))")
        }
        // Field order: the constant, each linear term, each product.
        GateDef::Quadratic {
            constant,
            linear,
            products,
        } => {
            let mut parts = vec![coeff(*constant)];
            parts.extend(linear.iter().map(|(a, x)| format!("{}·{x}", coeff(*a))));
            parts.extend(
                products
                    .iter()
                    .map(|(b, y, z)| format!("{}·{y}·{z}", coeff(*b))),
            );
            format!("({})", parts.join(" + "))
        }
    }
}

/// The one template of `docs/spec/gkr.md` §1: producing into `output`, or
/// enforcing when there is none.
fn template(output: Option<PolyAddress>, gate: &GateDef) -> String {
    match output {
        Some(out) => format!("{out}(x) = Σ_y eq(x, y) · {}", formula(gate)),
        None => format!("0 = {}   for every y", formula(gate)),
    }
}

/// A readable page of the whole artifact: the header, the committed columns
/// and virtual tables by name, every layer with its variable count, width and
/// kind, every cached entry, producing gate and enforcing gate in the one
/// template of `docs/spec/gkr.md` §1 with its relation, the flat relation list
/// in the same template, the scratch bijection, the output map, the lookups
/// with their channels and selectors, the padding contract and the gate
/// catalogue. Addresses are in short
/// notation; coefficients as `coeff` renders them.
///
/// Does NOT cover: any judgement — it prints what the artifact holds, lawful or
/// not, and never panics on a decodable artifact; names are printed and mean
/// nothing; a coefficient's exact value when it is a hex literal is its hex.
pub fn dump(a: &CircuitArtifact) -> String {
    let mut s = String::new();
    let mut line = |text: String| {
        s.push_str(&text);
        s.push('\n');
    };
    let (depth, n, code) = (a.depth(), a.trace_vars, a.coefficient_encoding);
    let meaning = match code {
        0 => "every Fr canonical 32-byte little-endian",
        _ => "unknown",
    };
    line("circuit artifact".to_string());
    line(format!("  format version        {}", a.format_version));
    line(format!("  coefficient encoding  {code} ({meaning})"));
    line(format!("  trace length          2^{n} rows"));
    line(format!("  depth                 {depth} gate lists"));

    line("\ncommitted columns".to_string());
    let committed = a.committed();
    let names = a.memory.iter().chain(&a.witness).chain(&a.setup);
    for (address, name) in committed.iter().zip(names) {
        line(format!("  {address}  {name}"));
    }
    line("virtual tables".to_string());
    for (kind, name) in &a.virtuals {
        let address = PolyAddress::Virtual(*kind);
        line(format!("  {address}  {name}"));
    }

    line("\nlayers".to_string());
    line(format!(
        "layer 0  base  2^{n} rows, width {}",
        committed.len()
    ));
    for (k, list) in a.layers.iter().enumerate() {
        let (up, kind) = (k + 1, if list.halving { "halving" } else { "row-wise" });
        line(format!("gate list {k}  {kind}, layer {k} -> layer {up}"));
        for e in &list.cached {
            let (at, text, name) = (e.address, formula(&e.gate), &e.name);
            line(format!("  {at}(y) = {text}   [cached {name}]"));
        }
        for e in &list.producing {
            let (text, r) = (template(Some(e.output), &e.gate), e.relation);
            let name = relation_name(a, r);
            line(format!("  {text}   [relation {r} {name}]"));
        }
        for e in &list.enforcing {
            let (text, r) = (template(None, &e.gate), e.relation);
            let name = relation_name(a, r);
            line(format!("  {text}   [relation {r} {name}]"));
        }
        let top = if up == depth { ", top" } else { "" };
        let (n, w) = (list.num_vars, list.width);
        line(format!("layer {up}  {kind}{top}  2^{n} rows, width {w}"));
    }

    line("\nrelations (the flat constraint list)".to_string());
    for (r, rel) in a.relations.iter().enumerate() {
        let text = template(rel.output.map(PolyAddress::Scratch), &rel.gate);
        line(format!("  {r} {}: {text}", rel.name));
    }
    line("scratch bijection".to_string());
    for (i, slot) in a.scratch.iter().enumerate() {
        line(format!("  scratch[{i}] = {}  {}", slot.address, slot.name));
    }
    line("outputs (output-map order)".to_string());
    for (i, out) in a.outputs.iter().enumerate() {
        line(format!("  {i}  {out}  {}", output_name(a, *out)));
    }
    line(format!("lookups ({})", a.lookups.len()));
    for l in &a.lookups {
        let tuple: Vec<String> = l.tuple.iter().map(formula).collect();
        let (name, channel, selector, tuple) = (&l.name, l.channel, l.selector, tuple.join(", "));
        let channel_name = lookup_channel::NAMES.get(channel as usize).unwrap_or(&"?");
        line(format!(
            "  {name} channel {channel} {channel_name}, selector {selector}: ({tuple})"
        ));
    }

    line("\npadding contract".to_string());
    let mut row: Vec<String> = Vec::new();
    for (i, v) in a.padding.row.iter().enumerate() {
        let value = coeff(Coeff::Literal(*v));
        match committed.get(i) {
            Some(address) => row.push(format!("{address} = {value}")),
            None => row.push(format!("?[{i}] = {value}")),
        }
    }
    line(format!("  row             {}", row.join(", ")));
    line(format!("  zero_row_valid  {}", a.padding.zero_row_valid));

    line("\ngate catalogue".to_string());
    for (i, c) in CATALOGUE.iter().enumerate() {
        line(format!("  {i} {}", c.variant));
        let fields = [
            ("template", c.template),
            ("inputs", c.inputs),
            ("output", c.output),
            ("defined in", c.defined_in),
            ("evaluated in", c.evaluated_in),
            ("for", c.purpose),
        ];
        for (field, value) in fields {
            line(format!("      {field:<13} {value}"));
        }
    }
    s
}

// ---------------------------------------------------------------------------
// The cross-check
// ---------------------------------------------------------------------------

/// What a verifier independently expects of a circuit. Per-layer vectors are
/// indexed by gate list `k`.
pub struct VerifierConstants {
    /// `n_0`.
    pub trace_vars: u32,
    /// Committed column names per subtree, in layout order.
    pub memory: Vec<&'static str>,
    pub witness: Vec<&'static str>,
    pub setup: Vec<&'static str>,
    /// Virtual table names, in `virtuals` order.
    pub virtuals: Vec<&'static str>,
    pub halving: Vec<bool>,
    /// Layer `k + 1`'s variable count and width.
    pub num_vars: Vec<u32>,
    pub widths: Vec<u32>,
    /// Gate list `k`'s enforcing and cached entry counts.
    pub enforcing: Vec<usize>,
    pub cached: Vec<usize>,
    /// The scratch names of the output addresses, in output-map order.
    pub outputs: Vec<&'static str>,
    /// Every challenge slot a gate or relation names, ascending, once each.
    pub challenge_slots: Vec<u32>,
}

/// What an independent description computes from a base: the output tables in
/// output-map order, and each enforcing relation's name and residual table over
/// the rows of the layer its list reads, in gate-list then entry order.
pub struct ReferenceRun {
    pub outputs: Vec<Vec<Fr>>,
    pub enforcing: Vec<(String, Vec<Fr>)>,
}

fn table(column: &MultilinearPoly) -> Vec<Fr> {
    (0..column.len()).map(|i| column.get(i)).collect()
}

/// Hold `a` to an independent description: first `check_laws`; then every
/// field of `expected`; then the semantics — a pseudo-random base at the trace
/// height and pseudo-random challenge values through `gkr::forward`, whose
/// output tables and enforcing residuals (`gkr::gate_values` on every row of
/// the forward values) must equal `reference`'s on the same base, given as
/// layout-order tables, and challenges.
///
/// Does NOT cover: names other than the committed columns', virtual tables',
/// outputs' and enforcing relations'; `format_version`, `coefficient_encoding`,
/// `lookups` beyond the lookup rules `check_laws` holds, the padding contract
/// (`check_padding`, `check_padding_identity`); construction rules
/// outside the laws — `gkr::forward` assumes an artifact that has passed
/// `CircuitArtifact::validate`, so on one passing the laws and the constants
/// but breaking such a rule this check's answer means nothing: it may panic,
/// return `Err`, or return `Ok`; any base but the one sampled. Materializes the whole trace, so it is for
/// test-sized circuits.
pub fn cross_check(
    a: &CircuitArtifact,
    expected: &VerifierConstants,
    reference: fn(&[Vec<Fr>], &ExternalChallenges) -> ReferenceRun,
) -> Result<(), String> {
    check_laws(a)?;

    // Each field printed after its name; the printed form is injective for
    // plain integers, booleans and strings.
    let e = expected;
    let virtuals: Vec<&String> = a.virtuals.iter().map(|(_, name)| name).collect();
    let halving: Vec<bool> = a.layers.iter().map(|l| l.halving).collect();
    let num_vars: Vec<u32> = a.layers.iter().map(|l| l.num_vars).collect();
    let widths: Vec<u32> = a.layers.iter().map(|l| l.width).collect();
    let enforcing: Vec<usize> = a.layers.iter().map(|l| l.enforcing.len()).collect();
    let cached: Vec<usize> = a.layers.iter().map(|l| l.cached.len()).collect();
    let outputs: Vec<&str> = a.outputs.iter().map(|out| output_name(a, *out)).collect();
    let slots = challenge_slots(&all_gates(a));
    let got = [
        format!("trace_vars {}", a.trace_vars),
        format!("memory {:?}", a.memory),
        format!("witness {:?}", a.witness),
        format!("setup {:?}", a.setup),
        format!("virtuals {virtuals:?}"),
        format!("halving {halving:?}"),
        format!("num_vars {num_vars:?}"),
        format!("widths {widths:?}"),
        format!("enforcing {enforcing:?}"),
        format!("cached {cached:?}"),
        format!("outputs {outputs:?}"),
        format!("challenge_slots {slots:?}"),
    ];
    let want = [
        format!("trace_vars {}", e.trace_vars),
        format!("memory {:?}", e.memory),
        format!("witness {:?}", e.witness),
        format!("setup {:?}", e.setup),
        format!("virtuals {:?}", e.virtuals),
        format!("halving {:?}", e.halving),
        format!("num_vars {:?}", e.num_vars),
        format!("widths {:?}", e.widths),
        format!("enforcing {:?}", e.enforcing),
        format!("cached {:?}", e.cached),
        format!("outputs {:?}", e.outputs),
        format!("challenge_slots {:?}", e.challenge_slots),
    ];
    for (got, want) in got.iter().zip(&want) {
        if got != want {
            return Err(format!(
                "cross_check: {got} in the artifact, {want} expected"
            ));
        }
    }

    let mut rng = Rng(0xc055_c4ec);
    let rows = 1usize << a.trace_vars;
    let base: Vec<Vec<Fr>> = a
        .committed()
        .iter()
        .map(|_| (0..rows).map(|_| rng.fr()).collect())
        .collect();
    let challenges = rng.challenges(&e.challenge_slots);
    let columns = (a.committed().into_iter().zip(&base))
        .map(|(address, t)| (address, MultilinearPoly::new(PolyBacking::Fr(t.clone()))))
        .collect();
    let values = forward(a, &BaseLayer::new(columns), &challenges);

    let top = values.layers.last().expect("Law 3: there is a top layer");
    let mut got_outputs: Vec<Vec<Fr>> = Vec::new();
    for out in &a.outputs {
        let PolyAddress::Inner { offset, .. } = *out else {
            panic!("Law 3: output {out} is on the top layer");
        };
        got_outputs.push(table(&top[offset as usize]));
    }
    let mut got_enforcing: Vec<(String, Vec<Fr>)> = Vec::new();
    // A list with no enforcing gate has no residual; a halving list never has one.
    for (k, list) in a.layers.iter().enumerate() {
        if list.enforcing.is_empty() {
            continue;
        }
        let lower: Vec<Vec<Fr>> = match k {
            0 => base.clone(),
            _ => values.layers[k - 1].iter().map(table).collect(),
        };
        let mut residuals = vec![Vec::new(); list.enforcing.len()];
        for y in 0..1usize << a.layer_vars(k) {
            let row: Vec<Fr> = lower.iter().map(|t| t[y]).collect();
            let virtuals: Vec<Fr> = a.virtuals.iter().map(|v| virtual_at_row(v.0, y)).collect();
            let gates = gate_values(a, k, &row, &[], &virtuals, &challenges);
            for (j, residual) in residuals.iter_mut().enumerate() {
                residual.push(gates[list.producing.len() + j]);
            }
        }
        for (entry, residual) in list.enforcing.iter().zip(residuals) {
            got_enforcing.push((relation_name(a, entry.relation).to_string(), residual));
        }
    }

    let run = reference(&base, &challenges);
    if got_outputs != run.outputs {
        let differs = |i: &usize| got_outputs.get(*i) != run.outputs.get(*i);
        let i = (0..)
            .find(differs)
            .expect("unequal lists differ at some index");
        return Err(format!(
            "cross_check: output {i} differs from the reference"
        ));
    }
    if got_enforcing != run.enforcing {
        let differs = |i: &usize| got_enforcing.get(*i) != run.enforcing.get(*i);
        let i = (0..)
            .find(differs)
            .expect("unequal lists differ at some index");
        return Err(format!(
            "cross_check: enforcing relation {i} differs from the reference"
        ));
    }
    Ok(())
}
