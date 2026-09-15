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

use constants::{challenge_slot, lookup_channel};
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind, CATALOGUE};
use field::Fr;
use gkr::{eval_gate, forward, gate_values, virtual_at_row, BaseLayer, ExternalChallenges};
use poly::{MultilinearPoly, PolyBacking};

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
            let input = PolyAddress::Inner {
                layer: k as u32,
                offset: j as u32,
            };
            if e.gate != (GateDef::TreeProduct { input }) {
                return Err(format!(
                    "{LAW2}: producing gate {j} of halving gate list {k} is not \
                     TreeProduct {{ input: {input} }}"
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
/// `C{k}[j]` evaluated from its entry, a `TreeProduct` reading the children.
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
        let virt = [triple(), triple()];
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
        if arity != 1 {
            return Err(format!(
                "{what}: a tuple of {arity}, but a range channel looks up one expression"
            ));
        }
        if layout_index(a, l.selector).is_none() {
            let selector = l.selector;
            return Err(format!(
                "{what}: selector {selector} is not a committed column of the layout"
            ));
        }
        for gate in &l.tuple {
            if !matches!(gate, GateDef::Linear { .. }) {
                return Err(format!("{what}: an expression that is not Linear"));
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
/// virtual table kind (`RowIndex`, then `RamLive`) and per scratch slot, and a
/// value per challenge slot.
struct Sample {
    committed: Vec<[Fr; 3]>,
    virt: [[Fr; 3]; 2],
    scratch: Vec<[Fr; 3]>,
    challenges: ExternalChallenges,
}

/// The kernel over sampled operands: a `TreeProduct` reads its operand's
/// children, every other gate its operands' values.
fn evaluate(gate: &GateDef, operands: &[[Fr; 3]], challenges: &ExternalChallenges) -> Fr {
    let values: Vec<Fr> = match gate {
        GateDef::TreeProduct { .. } => vec![operands[0][1], operands[0][2]],
        _ => operands.iter().map(|v| v[0]).collect(),
    };
    eval_gate(gate, &values, challenges)
}

/// A committed column's, a virtual table's or a scratch slot's sample.
fn leaf(a: &CircuitArtifact, s: &Sample, op: PolyAddress) -> Option<[Fr; 3]> {
    match op {
        PolyAddress::Virtual(VirtualKind::RowIndex) => Some(s.virt[0]),
        PolyAddress::Virtual(VirtualKind::RamLive) => Some(s.virt[1]),
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
    let tree = matches!(gate, GateDef::TreeProduct { .. });
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
/// reads. A relation is row-local when it is not a `TreeProduct` and every
/// scratch slot it reads is the output of a row-local relation; this is that
/// definition's least fixpoint, so a cycle or an undefined slot is not
/// row-local.
fn row_local_order(a: &CircuitArtifact) -> Vec<usize> {
    let mut known = vec![false; a.scratch.len()];
    let mut order: Vec<usize> = Vec::new();
    loop {
        let before = order.len();
        for (r, rel) in a.relations.iter().enumerate() {
            if order.contains(&r) || matches!(rel.gate, GateDef::TreeProduct { .. }) {
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
/// Does NOT cover: relations that are not row-local (`TreeProduct`s and all
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
        for entry in &a.layers[k].producing {
            for op in entry.gate.operands() {
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
/// Does NOT cover: `TreeProduct` relations and every relation reading one's
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
/// lookups `w` violates, in lookup order. A lookup is violated when its
/// selector is nonzero on the row and an expression of its tuple has a
/// canonical integer at or above `2^BITS[channel]`
/// (`constants::lookup_channel`), `V` read at `w.row`.
///
/// Does NOT cover: `w.scratch`, which no lookup reads; the LogUp argument that
/// discharges a lookup, which S15 builds — this is membership, natively, on one
/// row; the lookup rules, which it assumes. Panics if `w.committed` is not
/// shaped to the artifact, or on a lookup whose channel, selector, operands or
/// coefficients the lookup rules refuse.
pub fn violated_lookups(a: &CircuitArtifact, w: &WitnessRow) -> Vec<String> {
    let (given, expected) = (w.committed.len(), a.committed().len());
    assert_eq!(given, expected, "violated_lookups: committed length");
    let literal_only = ExternalChallenges::new();
    let mut violated = Vec::new();
    for l in &a.lookups {
        let fail = |why: String| -> ! { panic!("violated_lookups: lookup {}: {why}", l.name) };
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
