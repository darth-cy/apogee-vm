//! Must-be-exact 4's construction-time half, must-be-exact 5 and 14, and
//! acceptances 5 and 6: `CircuitArtifact::validate` refuses every law and rule
//! of `docs/spec/gkr.md` §4.2, and `inline_cached` refuses what §3.1 says it
//! cannot inline.
//!
//! Every test starts from the decoded toy — its fields are public — and makes
//! one mutation, keeping everything else consistent so the error asserted is
//! the one that mutation causes. Where a rule cannot be broken alone, the
//! test's doc comment says what else breaks and why the asserted error is
//! still the first reported. Each refusal has a control beside it: the nearest
//! legal artifact, built by the same code, which validates.
//!
//! `Locality`, `Degree` and `NotInlinable` are matched as whole values. The
//! variants carrying a prose `detail` are matched by variant, by `layer` where
//! they have one, and by the part of the detail naming the rule and the
//! object — the address, name or count — so a refusal for the right law but
//! the wrong reason still fails.

mod common;

use common::*;
use constants::{challenge_slot, lookup_channel};
use constraints::{
    CachedEntry, CircuitArtifact, Coeff, ConstraintError, EnforcingEntry, GateDef, LayerSpec,
    LookupExpr, Padding, PolyAddress, ProducingEntry, Relation, ScratchSlot, VirtualKind,
    COEFFICIENT_ENCODING_CANONICAL_LE, FORMAT_VERSION,
};
use field::Fr;
use std::time::{Duration, Instant};

fn linear(terms: &[(Coeff, PolyAddress)], constant: Coeff) -> GateDef {
    GateDef::Linear {
        terms: terms.to_vec(),
        constant,
    }
}

fn product(left: PolyAddress, right: PolyAddress) -> GateDef {
    GateDef::Product {
        coeff: lit(1),
        left,
        right,
    }
}

fn tree(input: PolyAddress) -> GateDef {
    GateDef::TreeProduct { input }
}

fn cached_entry(name: &str, offset: u32, gate: GateDef) -> CachedEntry {
    cached_entry_in(0, name, offset, gate)
}

/// `C{layer}[offset] = gate`, for a cached entry of a list other than 0.
fn cached_entry_in(layer: u32, name: &str, offset: u32, gate: GateDef) -> CachedEntry {
    CachedEntry {
        name: name.into(),
        address: cached(layer, offset),
        gate,
    }
}

fn affine(
    left: &[(Coeff, PolyAddress)],
    left_constant: Coeff,
    right: &[(Coeff, PolyAddress)],
    right_constant: Coeff,
) -> GateDef {
    GateDef::AffineProduct {
        left: left.to_vec(),
        left_constant,
        right: right.to_vec(),
        right_constant,
    }
}

/// The literal 0, as a coefficient.
fn zero() -> Coeff {
    Coeff::Literal(Fr::ZERO)
}

#[track_caller]
fn assert_malformed(a: &CircuitArtifact, needle: &str) {
    match a.validate() {
        Err(ConstraintError::Malformed { detail }) if detail.contains(needle) => {}
        other => panic!("expected Malformed naming {needle:?}, got {other:?}"),
    }
}

#[track_caller]
fn assert_derived_width(a: &CircuitArtifact, layer: u32, needle: &str) {
    match a.validate() {
        Err(ConstraintError::DerivedWidth { layer: l, detail })
            if l == layer && detail.contains(needle) => {}
        other => panic!("expected DerivedWidth at layer {layer} naming {needle:?}, got {other:?}"),
    }
}

#[track_caller]
fn assert_top_layer(a: &CircuitArtifact, needle: &str) {
    match a.validate() {
        Err(ConstraintError::TopLayer { detail }) if detail.contains(needle) => {}
        other => panic!("expected TopLayer naming {needle:?}, got {other:?}"),
    }
}

#[track_caller]
fn assert_single_source(a: &CircuitArtifact, needle: &str) {
    match a.validate() {
        Err(ConstraintError::SingleSource { detail }) if detail.contains(needle) => {}
        other => panic!("expected SingleSource naming {needle:?}, got {other:?}"),
    }
}

/// The control every refusal below leans on: the committed toy, unmutated, is
/// a circuit, and so is its committed cache-free compilation.
#[test]
fn the_toy_and_its_cache_free_compilation_validate() {
    assert_eq!(toy().validate(), Ok(()));
    assert_eq!(toy_cache_free().validate(), Ok(()));
}

// ---------------------------------------------------------------------------
// Law 1: locality
// ---------------------------------------------------------------------------

/// Law 1, acceptance 5: gate list 2 reads layer 2 and nothing else. Its first
/// tree rewritten to halve `L{1}[0]`, two layers down, is refused as locality
/// in list 2, naming the gate's relation and the operand. Relation 6 moves with
/// it, to `scratch[0]`, so the flat list still says what the gate says.
///
/// Not fully isolable: a halving list's entry `j` must be `TreeProduct` of
/// `L{2}[j]`, so any other operand also breaks the halving rule, and `L{2}[0]`
/// is then read by nothing. Locality is checked first, which is what this pins.
#[test]
fn law1_refuses_a_gate_reading_two_layers_down() {
    assert_eq!(toy().validate(), Ok(()));

    let mut a = toy();
    a.layers[2].producing[0].gate = tree(inner(1, 0));
    a.relations[6].gate = tree(scratch(0));
    assert_eq!(
        a.validate(),
        Err(ConstraintError::Locality {
            layer: 2,
            gate: "define_abm_product".into(),
            operand: inner(1, 0),
        })
    );
}

/// Law 1: gate list 1 reads layer 1. `fingerprint3 = fingerprint + 3` given a
/// second term: `L{1}[0]` validates (the relation gains `scratch[0]`); `W[0]`,
/// a base column, is refused as locality in list 1 (the relation gains `a`, its
/// flat spelling, so the operand is the one thing wrong).
///
/// The other addresses list 1 cannot read are refused the same way — `M[0]`,
/// `S[0]` and `V[row]` from the base, `L{2}[0]` from the layer it writes,
/// `L{1}[3]` past layer 1's width, `C{1}[0]` which list 1 does not have, and a
/// `scratch` slot, which only the flat list names. For these the relation keeps
/// the control's `scratch[0]`, since most have no flat spelling; Law 4 would
/// fail too, and locality is reported first.
#[test]
fn law1_refuses_a_list_one_gate_reading_outside_layer_one() {
    let with_term = |gate_term: PolyAddress, flat_term: PolyAddress| {
        let mut a = toy();
        a.layers[1].producing[1].gate =
            linear(&[(lit(1), inner(1, 1)), (lit(1), gate_term)], lit(3));
        a.relations[5].gate = linear(&[(lit(1), scratch(1)), (lit(1), flat_term)], lit(3));
        a
    };
    let refused = |operand: PolyAddress| ConstraintError::Locality {
        layer: 1,
        gate: "define_fingerprint3".into(),
        operand,
    };

    assert_eq!(with_term(inner(1, 0), scratch(0)).validate(), Ok(()));
    assert_eq!(with_term(A, A).validate(), Err(refused(A)));

    for operand in [
        M,
        S,
        ROW,
        inner(2, 0),
        inner(1, 3),
        cached(1, 0),
        scratch(0),
    ] {
        assert_eq!(
            with_term(operand, scratch(0)).validate(),
            Err(refused(operand)),
            "{operand}"
        );
    }
}

/// Law 1: a cached entry reads layer-`k` columns, never another cached entry. A
/// second cached entry of list 0, named by `ab`'s gate `C{0}[1]·b`: as
/// `C{0}[1] = a` it validates; as `C{0}[1] = C{0}[0]` it is refused as locality,
/// naming the entry and `C{0}[0]`. In the refused artifact relation 0 is
/// rewritten to what the nested substitution would mean, `(γ·a + row)·b`, so
/// the flat list still agrees with the gate.
#[test]
fn law1_refuses_a_cached_entry_reading_another() {
    let with_alias = |alias: GateDef, relation: GateDef| {
        let mut a = toy();
        a.layers[0].cached.push(cached_entry("alias", 1, alias));
        a.layers[0].producing[0].gate = product(cached(0, 1), B);
        a.relations[0].gate = relation;
        a
    };

    assert_eq!(
        with_alias(linear(&[(lit(1), A)], lit(0)), product(A, B)).validate(),
        Ok(())
    );
    let nested = with_alias(
        linear(&[(lit(1), cached(0, 0))], lit(0)),
        GateDef::AffineProduct {
            left: vec![(GAMMA, A), (lit(1), ROW)],
            left_constant: lit(0),
            right: vec![(lit(1), B)],
            right_constant: lit(0),
        },
    );
    assert_eq!(
        nested.validate(),
        Err(ConstraintError::Locality {
            layer: 0,
            gate: "alias".into(),
            operand: cached(0, 0),
        })
    );
}

/// Law 1: a cached operand is one of the reading list's own entries, not an
/// entry at the same offset of another list. `fingerprint`'s gate in list 0
/// written `Product { 1, C{7}[0], c }` — a list the toy does not have — or
/// `Product { 1, C{1}[0], c }`, in place of its own `C{0}[0]`, is refused as
/// locality in list 0, naming the gate and the operand. The toy's spelling,
/// `C{0}[0]`, validates.
///
/// Kills L20 (the cached arm's `l == layer` made vacuous): `C{7}[0]` then
/// resolves to list 0's entry by offset alone, Law 4 finds the same
/// polynomial, and the artifact is refused only later, as `shifted_a` named by
/// no gate — `Malformed`, not this `Locality`.
#[test]
fn law1_refuses_a_cached_operand_of_another_list() {
    assert_eq!(toy().layers[0].producing[1].gate, product(cached(0, 0), C));
    assert_eq!(toy().validate(), Ok(()));

    for operand in [cached(7, 0), cached(1, 0)] {
        let mut a = toy();
        a.layers[0].producing[1].gate = product(operand, C);
        assert_eq!(
            a.validate(),
            Err(ConstraintError::Locality {
                layer: 0,
                gate: "define_fingerprint".into(),
                operand,
            }),
            "{operand}"
        );
    }
}

// ---------------------------------------------------------------------------
// Law 2: derived width
// ---------------------------------------------------------------------------

/// Law 2, acceptance 5 — the keccak_special5 defect class: list 1 produces two
/// columns, so a stored width of 3, or of 1, is refused at layer 2, the layer
/// the width describes.
#[test]
fn law2_refuses_a_declared_width_the_gates_do_not_produce() {
    assert_eq!(toy().layers[1].width, 2);
    for width in [1u32, 3] {
        let mut a = toy();
        a.layers[1].width = width;
        assert_derived_width(
            &a,
            2,
            &format!("stored width {width} but gate list 1 has 2 producing gates"),
        );
    }
}

/// Law 2: a stored `num_vars` is `n_k` for a row-wise list and `n_k − 1` for a
/// halving one. List 2 halves layer 2's four variables to three, so a stored 4
/// is refused at layer 3; list 1 is row-wise over four, so a stored 3 is
/// refused at layer 2.
#[test]
fn law2_refuses_a_declared_variable_count_the_list_does_not_write() {
    let mut a = toy();
    a.layers[2].num_vars = 4;
    assert_derived_width(
        &a,
        3,
        "stored num_vars 4 but gate list 2 writes 3 variables",
    );

    let mut a = toy();
    a.layers[1].num_vars = 3;
    assert_derived_width(
        &a,
        2,
        "stored num_vars 3 but gate list 1 writes 4 variables",
    );
}

/// The toy with list 1's two columns in the other order, renumbered through
/// everything that names them: list 1's outputs and their scratch slots, and
/// list 2's trees — entry `j` halves column `j`, so the two trees trade
/// relations — and their scratch slots. A legal circuit, and the control for
/// the two out-of-order refusals.
fn toy_with_list_1_reordered() -> CircuitArtifact {
    let mut a = toy();
    a.layers[1].producing.swap(0, 1);
    a.layers[1].producing[0].output = inner(2, 0);
    a.layers[1].producing[1].output = inner(2, 1);
    a.scratch[3].address = inner(2, 1); // abm
    a.scratch[4].address = inner(2, 0); // fingerprint3
    a.layers[2].producing[0].relation = 7; // halves L{2}[0], now fingerprint3
    a.layers[2].producing[1].relation = 6; // halves L{2}[1], now abm
    a.scratch[5].address = inner(3, 1); // abm_product
    a.scratch[6].address = inner(3, 0); // fingerprint3_product
    a
}

/// Law 2: a list's outputs are exactly `L{k+1}[0..width)` in order. List 1's two
/// entries swapped whole — each keeps its relation, output and gate — are
/// refused at layer 2, naming the entry that writes out of place; the same
/// reordering renumbered through the circuit validates.
#[test]
fn law2_refuses_outputs_out_of_order() {
    assert_eq!(toy_with_list_1_reordered().validate(), Ok(()));

    let mut a = toy();
    a.layers[1].producing.swap(0, 1);
    assert_derived_width(&a, 2, "producing entry 0 writes L{2}[1], not L{2}[0]");
}

// ---------------------------------------------------------------------------
// Law 3: the top layer
// ---------------------------------------------------------------------------

/// Law 3, acceptance 5: the output map is a permutation of layer 3, nothing
/// more and nothing less. The reversed order validates. Refused: an output
/// dropped (the top layer then holds a column absent from the map), an output
/// replaced by `L{2}[0]` from below the top, an output duplicated, a third
/// output `L{3}[2]` past the top layer's width, and — with the count right —
/// `[L{3}[1], L{3}[2]]`, whose second output is past the width.
///
/// The last case kills L15 (the top-layer `offset < width` test made
/// vacuous): the third-output case is refused by the count before the offset
/// is looked at, so only a map of the right length can see it, and under L15
/// that map validates.
#[test]
fn law3_refuses_an_output_map_that_is_not_the_top_layer() {
    let mut reversed = toy();
    reversed.outputs.reverse();
    assert_eq!(reversed.validate(), Ok(()));

    let mut dropped = toy();
    dropped.outputs.pop();
    assert_top_layer(&dropped, "layer 3 has 2 columns but the output map has 1");

    let mut replaced = toy();
    replaced.outputs[0] = inner(2, 0);
    assert_top_layer(
        &replaced,
        "output 0 is L{2}[0], not a distinct column of layer 3",
    );

    let mut duplicated = toy();
    duplicated.outputs[1] = duplicated.outputs[0];
    assert_top_layer(
        &duplicated,
        "output 1 is L{3}[1], not a distinct column of layer 3",
    );

    let mut extra = toy();
    extra.outputs.push(inner(3, 2));
    assert_top_layer(&extra, "layer 3 has 2 columns but the output map has 3");

    let mut past = toy();
    past.outputs[1] = inner(3, 2);
    assert_eq!(past.outputs, [inner(3, 1), inner(3, 2)]);
    assert_top_layer(
        &past,
        "output 1 is L{3}[2], not a distinct column of layer 3",
    );
}

// ---------------------------------------------------------------------------
// Law 4: single source of truth
// ---------------------------------------------------------------------------

/// Law 4, acceptance 5 (semantics): the relation and its gate are one
/// polynomial. `define_fingerprint3`'s constant 3 changed to 4 in the flat list
/// alone is refused, naming the relation and the list; changed in both it
/// validates. `define_ab` with coefficient 2 is refused; spelled as the same
/// polynomial in another shape, `(b)·(a)` as an `AffineProduct`, it validates —
/// the comparison is of meaning, not of shape.
#[test]
fn law4_refuses_a_relation_that_says_something_else() {
    let mut both = toy();
    both.relations[5].gate = linear(&[(lit(1), scratch(1))], lit(4));
    both.layers[1].producing[1].gate = linear(&[(lit(1), inner(1, 1))], lit(4));
    assert_eq!(both.validate(), Ok(()));

    let mut flat_only = toy();
    flat_only.relations[5].gate = linear(&[(lit(1), scratch(1))], lit(4));
    assert_single_source(
        &flat_only,
        "relation `define_fingerprint3` and its gate in gate list 1 are different polynomials",
    );

    let mut reshaped = toy();
    reshaped.relations[0].gate = GateDef::AffineProduct {
        left: vec![(lit(1), B)],
        left_constant: lit(0),
        right: vec![(lit(1), A)],
        right_constant: lit(0),
    };
    assert_eq!(reshaped.validate(), Ok(()));

    let mut doubled = toy();
    doubled.relations[0].gate = GateDef::Product {
        coeff: lit(2),
        left: A,
        right: B,
    };
    assert_single_source(
        &doubled,
        "relation `define_ab` and its gate in gate list 0 are different polynomials",
    );
}

/// Law 4 compares normal forms across shapes, `MaskIntoIdentity` included.
/// `masked_m`'s gate rewritten as `AffineProduct { [(1, m)], −1 ; [(1, s)], 0 }`,
/// which is `(m − 1)·s`, while its relation stays `MaskIntoIdentity { m, s }`,
/// `m·s + (1 − s)`: the two differ by the constant 1, and are refused, naming
/// the relation and the list. Written as `(m − 1)·s` on both sides, it
/// validates.
///
/// Kills L24 (the `1` dropped from `MaskIntoIdentity`'s expansion), under which
/// the mask expands to `m·s − s` and matches the affine gate.
#[test]
fn law4_refuses_an_affine_product_that_is_a_mask_missing_its_one() {
    let m_minus_one_times_s = affine(&[(lit(1), M)], neg(1), &[(lit(1), S)], lit(0));

    let mut both = toy();
    both.relations[2].gate = m_minus_one_times_s.clone();
    both.layers[0].producing[2].gate = m_minus_one_times_s.clone();
    assert_eq!(both.validate(), Ok(()));

    let mut gate_only = toy();
    assert_eq!(
        gate_only.relations[2].gate,
        GateDef::MaskIntoIdentity { input: M, mask: S }
    );
    gate_only.layers[0].producing[2].gate = m_minus_one_times_s;
    assert_single_source(
        &gate_only,
        "relation `define_masked_m` and its gate in gate list 0 are different polynomials",
    );
}

/// Law 4's normal form merges equal monomials. `fingerprint3`'s relation
/// spelled `1·scratch[1] + 1·scratch[1] + 3`, two terms, against the gate
/// `2·L{1}[1] + 3`, one: the same polynomial, which validates. The same
/// relation against the toy's gate, `1·L{1}[1] + 3`, is a different polynomial,
/// refused naming the relation and the list.
///
/// Kills L05 (equal monomials never merged in `normalize`), under which the
/// lawful pair's expansions have three monomials and two, and are refused.
#[test]
fn law4_merges_equal_monomials_before_comparing() {
    let twice = linear(&[(lit(1), scratch(1)), (lit(1), scratch(1))], lit(3));

    let mut merged = toy();
    merged.relations[5].gate = twice.clone();
    merged.layers[1].producing[1].gate = linear(&[(lit(2), inner(1, 1))], lit(3));
    assert_eq!(merged.validate(), Ok(()));

    let mut once = toy();
    once.relations[5].gate = twice;
    assert_single_source(
        &once,
        "relation `define_fingerprint3` and its gate in gate list 1 are different polynomials",
    );
}

/// Law 4: every relation is named by exactly one gate. `fingerprint3`'s gate
/// renamed to relation 4, which `abm`'s gate already names, is refused as a
/// relation encoded twice.
///
/// Not isolable: with eight gates over eight relations, a relation named twice
/// leaves another named by none, and `fingerprint3`'s gate no longer writes the
/// column its relation defines. The duplicate is reported first.
#[test]
fn law4_refuses_two_gates_naming_one_relation() {
    let mut a = toy();
    a.layers[1].producing[1].relation = 4;
    assert_single_source(&a, "relation `define_abm` is encoded by two gates");
}

/// Law 4: an enforcing gate's relation defines no column. List 0's enforcing
/// gate and `abm`'s producing gate trade relations, so the enforcing gate
/// names `define_abm`; refused as an enforcing gate encoding a producing
/// relation.
///
/// Not isolable: every producing relation defines a scratch slot, and the one
/// producing gate writing that slot's column must name it, so an enforcing gate
/// naming it leaves that producing gate naming something else. List 0 is
/// checked before list 1, so the enforcing error is reported first.
#[test]
fn law4_refuses_an_enforcing_gate_naming_a_producing_relation() {
    let mut a = toy();
    a.layers[0].enforcing[0].relation = 4;
    a.layers[1].producing[0].relation = 3;
    assert_single_source(
        &a,
        "an enforcing gate encodes relation `define_abm`, which is producing",
    );
}

/// Law 4: a producing gate's relation defines the column the gate writes.
/// `ab`'s and `fingerprint`'s gates trade relations; refused, naming the column
/// and the relation that does not define it. Not isolable, for the same
/// pigeonhole reason as the enforcing case; the first gate is reported.
#[test]
fn law4_refuses_a_producing_gate_naming_another_columns_relation() {
    let mut a = toy();
    a.layers[0].producing[0].relation = 1;
    a.layers[0].producing[1].relation = 0;
    assert_single_source(
        &a,
        "the gate writing L{1}[0] encodes relation `define_fingerprint`, which does not define it",
    );
}

/// Every relation index past `removed` shifted down by one, in every gate.
fn shift_relations_after(a: &mut CircuitArtifact, removed: u32) {
    for list in &mut a.layers {
        for e in &mut list.producing {
            if e.relation > removed {
                e.relation -= 1;
            }
        }
        for e in &mut list.enforcing {
            if e.relation > removed {
                e.relation -= 1;
            }
        }
    }
}

/// Law 4, acceptance 5 (count): the flat list and the gates have equal
/// cardinality. List 0's enforcing gate deleted, its relation `gated_equality`
/// left in the flat list, is refused as eight relations against seven gates.
/// Deleting both, with every later relation index fixed up, validates (`e` is
/// then read by nothing, which is legal for a committed column: it is still
/// opened).
#[test]
fn law4_refuses_a_flat_list_longer_than_the_gates() {
    let mut both = toy();
    both.relations.remove(3);
    both.layers[0].enforcing.clear();
    shift_relations_after(&mut both, 3);
    assert_eq!(both.validate(), Ok(()));

    let mut a = toy();
    a.layers[0].enforcing.clear();
    assert_single_source(&a, "8 relations in the flat list but 7 gates");
}

/// Law 4 (count), from the other side: `gated_equality` deleted from the flat
/// list with every later relation index fixed up, its enforcing gate left.
///
/// This cannot be refused *as a count*. The count compares the gates to the
/// relations only once every gate has named a distinct, existing relation, and
/// eight gates cannot do that over seven relations — so the orphaned gate is
/// refused first, by what it now names. Left at index 3, it names `define_abm`,
/// which is producing; pointed past the end, at 7, it names nothing. Both are
/// `SingleSource`, and the control is the previous test's legal deletion.
#[test]
fn law4_refuses_a_relation_deleted_under_its_gate() {
    let mut orphaned = toy();
    orphaned.relations.remove(3);
    shift_relations_after(&mut orphaned, 3);
    assert_eq!(orphaned.layers[0].enforcing[0].relation, 3);
    assert_single_source(
        &orphaned,
        "an enforcing gate encodes relation `define_abm`, which is producing",
    );

    orphaned.layers[0].enforcing[0].relation = 7;
    assert_single_source(&orphaned, "a gate names relation 7, which does not exist");
}

/// The review's cost artifact at `t` terms, made not to vanish: one committed
/// column `m`; a cached entry `C{0}[0]` of `t` alternating `±1·m` terms plus one
/// more `1·m`, so it is `m` for even `t`; one enforcing gate
/// `(Σ_t 1·C{0}[0] + 0)·(Σ_t 1·C{0}[0] + 0)`, which is `t²·m²`; and its relation
/// spelled `t²·m·m`, the same polynomial. Every law holds and the gate is
/// degree 2. (The review's own spelling was identically zero, which an
/// enforcing gate may no longer be.)
fn cancelling_square(t: usize) -> CircuitArtifact {
    let mut alternating: Vec<(Coeff, PolyAddress)> = (0..t)
        .map(|i| (if i % 2 == 0 { lit(1) } else { neg(1) }, M))
        .collect();
    alternating.push((lit(1), M));
    let factor = vec![(lit(1), cached(0, 0)); t];
    CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars: 4,
        memory: vec!["m".into()],
        witness: vec![],
        setup: vec![],
        virtuals: vec![],
        layers: vec![LayerSpec {
            halving: false,
            num_vars: 4,
            width: 0,
            cached: vec![cached_entry("alternating", 0, linear(&alternating, lit(0)))],
            producing: vec![],
            enforcing: vec![EnforcingEntry {
                relation: 0,
                gate: affine(&factor, lit(0), &factor, lit(0)),
            }],
        }],
        relations: vec![Relation {
            name: "square_is_zero".into(),
            output: None,
            gate: GateDef::Product {
                coeff: lit((t * t) as u64),
                left: M,
                right: M,
            },
        }],
        lookups: vec![],
        scratch: vec![],
        outputs: vec![],
        padding: Padding {
            row: vec![Fr::ZERO],
            zero_row_valid: true,
        },
    }
}

/// Law 4's expansion is normalized as it is built — every intermediate sum and
/// product merged — so its cost follows the polynomial, not its spelling.
/// `cancelling_square` at `t` = 48 and 128 validates, each in under two
/// seconds.
///
/// Kills reverting that normalization (c94cff1's `expand`, which multiplied
/// out about `(t·(t+1))²` monomials before merging any): the review measured
/// 434 ms at `t` = 48 and extrapolated about 20 s at `t` = 128 in a release
/// build, where the normalized expansion takes milliseconds. `t` = 128 is the
/// case that fails under the revert; the two-second bound sits far from both
/// costs, so CI noise cannot flake it.
#[test]
fn law4_expansion_cost_follows_the_polynomial_not_its_spelling() {
    for t in [48usize, 128] {
        let a = cancelling_square(t);
        let start = Instant::now();
        let result = a.validate();
        let elapsed = start.elapsed();
        assert_eq!(result, Ok(()), "t = {t}");
        assert!(
            elapsed < Duration::from_secs(2),
            "t = {t}: validate took {elapsed:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// The degree ceiling
// ---------------------------------------------------------------------------

/// The toy with a second cached entry in list 0, `ab_cached = a·b`, degree 2,
/// and `ab`'s gate replaced by `gate`.
fn toy_with_ab_cached(gate: GateDef) -> CircuitArtifact {
    let mut a = toy();
    a.layers[0]
        .cached
        .push(cached_entry("ab_cached", 1, product(A, B)));
    a.layers[0].producing[0].gate = gate;
    a
}

/// Acceptance 6, must-be-exact 5: a gate of degree 3 in the layer it reads is
/// refused at construction, with the gate's name and its degree. `ab_cached`
/// is `a·b`, degree 2. Named by `ab`'s gate as `Linear { 1·C{0}[1] }` it is
/// degree 2, the flat list's `a·b` agrees, and the circuit validates. Named as
/// `Product { 1, C{0}[1], c }` it is `a·b·c`, degree 3, and refused as exactly
/// that.
///
/// Relation 0 stays `a·b` in the refused artifact. It cannot say `a·b·c`: no
/// shape over base columns has degree 3, which is the ceiling doing its job on
/// the flat side. Law 4 therefore fails too; the degree is checked in the gate
/// list, before the laws that compare encodings, and is what is reported.
///
/// The same entry makes an enforcing gate degree 3 as the left factor of the
/// gated equality, and a `MaskIntoIdentity` degree 3 as its input.
#[test]
fn a_degree_three_gate_is_refused_at_construction() {
    let named_linearly = linear(&[(lit(1), cached(0, 1))], lit(0));
    assert_eq!(
        toy_with_ab_cached(named_linearly.clone()).validate(),
        Ok(())
    );

    assert_eq!(
        toy_with_ab_cached(product(cached(0, 1), C)).validate(),
        Err(ConstraintError::Degree {
            gate: "define_ab".into(),
            degree: 3,
        })
    );

    let mut enforcing = toy_with_ab_cached(named_linearly.clone());
    enforcing.layers[0].enforcing[0].gate = GateDef::AffineProduct {
        left: vec![(lit(1), cached(0, 1))],
        left_constant: lit(0),
        right: vec![(lit(1), S)],
        right_constant: lit(0),
    };
    assert_eq!(
        enforcing.validate(),
        Err(ConstraintError::Degree {
            gate: "gated_equality".into(),
            degree: 3,
        })
    );

    let mut masked = toy_with_ab_cached(named_linearly);
    masked.layers[0].producing[2].gate = GateDef::MaskIntoIdentity {
        input: cached(0, 1),
        mask: S,
    };
    assert_eq!(
        masked.validate(),
        Err(ConstraintError::Degree {
            gate: "define_masked_m".into(),
            degree: 3,
        })
    );
}

// ---------------------------------------------------------------------------
// Terms that read nothing
// ---------------------------------------------------------------------------

/// The toy with one extra term of coefficient `c` in each of four places, the
/// term written into the gate and into its relation alike, so for any `c` the
/// two sides are one polynomial: `fingerprint3 = 1·L{1}[1] + c·L{1}[0] + 3`
/// (a `Linear` term), `gated_equality = (e − a + c·m)·s` (an `AffineProduct`
/// left term), `gated_equality = (e − a)·(s + c·m)` (a right term), and
/// `ab = c·a·b` (a `Product`'s coefficient). Each case is named by the gate the
/// refusal names.
fn toy_with_coefficient(c: Coeff) -> [(&'static str, CircuitArtifact); 4] {
    let mut linear_term = toy();
    linear_term.layers[1].producing[1].gate =
        linear(&[(lit(1), inner(1, 1)), (c, inner(1, 0))], lit(3));
    linear_term.relations[5].gate = linear(&[(lit(1), scratch(1)), (c, scratch(0))], lit(3));

    let mut left_term = toy();
    let left = affine(
        &[(lit(1), E), (neg(1), A), (c, M)],
        lit(0),
        &[(lit(1), S)],
        lit(0),
    );
    left_term.layers[0].enforcing[0].gate = left.clone();
    left_term.relations[3].gate = left;

    let mut right_term = toy();
    let right = affine(
        &[(lit(1), E), (neg(1), A)],
        lit(0),
        &[(lit(1), S), (c, M)],
        lit(0),
    );
    right_term.layers[0].enforcing[0].gate = right.clone();
    right_term.relations[3].gate = right;

    let mut product_coeff = toy();
    let scaled = GateDef::Product {
        coeff: c,
        left: A,
        right: B,
    };
    product_coeff.layers[0].producing[0].gate = scaled.clone();
    product_coeff.relations[0].gate = scaled;

    [
        ("define_fingerprint3", linear_term),
        ("gated_equality", left_term),
        ("gated_equality", right_term),
        ("define_ab", product_coeff),
    ]
}

/// `docs/spec/gkr.md` §4.2: a zero-coefficient term reads nothing, because
/// "reads" is decided on the normalized expansion — but it is not refused for
/// that alone. In each of `toy_with_coefficient`'s four places — a `Linear`
/// term, an `AffineProduct` left term, an `AffineProduct` right term, a
/// `Product` coefficient — a coefficient of 0 (or 2) validates: both sides stay
/// one polynomial, and every column is still read elsewhere.
///
/// What is refused is what a zero term can hide. A column named only through
/// `0·x` is unread: `fingerprint3 = 0·L{1}[1] + 3` is refused as
/// `L{1}[1]` never read. And an enforcing gate whose expansion is zero —
/// `gated_equality = (e − a)·(0)`, the right factor emptied to its zero
/// constant — holds on every row whatever it names, and is refused as
/// constraining nothing; the toy's own gated equality is the control.
///
/// Kills deciding "read" from operands rather than the expansion (the `0·L{1}[1]`
/// case validates), and deleting the identically-zero enforcing check.
#[test]
fn a_term_that_reads_nothing_hides_neither_a_column_nor_a_constraint() {
    for c in [zero(), lit(2)] {
        for (name, a) in toy_with_coefficient(c) {
            assert_eq!(a.validate(), Ok(()), "{name}");
        }
    }

    let mut zero_read = toy();
    zero_read.layers[1].producing[1].gate = linear(&[(zero(), inner(1, 1))], lit(3));
    zero_read.relations[5].gate = linear(&[], lit(3));
    assert_malformed(
        &zero_read,
        "L{1}[1] is written but gate list 1 never reads it",
    );

    let mut vacuous = toy();
    let emptied = affine(
        &[(lit(1), E), (Coeff::Literal(Fr::MINUS_ONE), A)],
        lit(0),
        &[],
        lit(0),
    );
    vacuous.layers[0].enforcing[0].gate = emptied.clone();
    vacuous.relations[3].gate = emptied;
    assert_malformed(
        &vacuous,
        "enforcing gate `gated_equality` in gate list 0 is identically zero",
    );
    assert_eq!(toy().validate(), Ok(()));
}

/// The review's L21 and L22 scenarios, which used a zero-coefficient term to
/// name an operand Law 4 cannot see. Law 1 range-checks every operand whatever
/// its coefficient, so both are refused as locality:
/// - `shifted_a = γ·a + 1·row + 0·M[5]`, past the one-column memory layout, is
///   refused as locality in list 0 naming `shifted_a` and `M[5]`;
/// - `shifted_a = γ·a + 0·row` with the virtual list emptied (relation 1 then
///   `γ·a·c`, reading no `V`) is refused as locality naming `V[row]`.
///
/// Brought back in range — `0·M[0]`, and `0·row` with `row` listed — Law 1
/// holds, the zero term normalizes away, and each validates; so does the
/// in-range spelling with coefficient 1 and the relation to match.
///
/// Kills L21 (Law 1's memory range widened) and L22 (Law 1's virtual-listed
/// test dropped): under either, the out-of-range artifact validates.
#[test]
fn a_zero_coefficient_operand_is_still_range_checked_first() {
    let with_shifted_a = |terms: &[(Coeff, PolyAddress)], fingerprint: GateDef| {
        let mut a = toy();
        a.layers[0].cached[0].gate = linear(terms, lit(0));
        a.relations[1].gate = fingerprint;
        a
    };
    let fingerprint =
        |terms: &[(Coeff, PolyAddress)]| affine(terms, lit(0), &[(lit(1), C)], lit(0));
    let shifted_a_and = |c: Coeff, x: PolyAddress| [(GAMMA, A), (lit(1), ROW), (c, x)];

    // L21: a memory column past the layout.
    let past = with_shifted_a(
        &shifted_a_and(zero(), PolyAddress::Memory(5)),
        fingerprint(&[(GAMMA, A), (lit(1), ROW)]),
    );
    assert_eq!(
        past.validate(),
        Err(ConstraintError::Locality {
            layer: 0,
            gate: "shifted_a".into(),
            operand: PolyAddress::Memory(5),
        })
    );
    let in_range = with_shifted_a(
        &shifted_a_and(zero(), M),
        fingerprint(&[(GAMMA, A), (lit(1), ROW)]),
    );
    assert_eq!(in_range.validate(), Ok(()));
    let read = with_shifted_a(
        &shifted_a_and(lit(1), M),
        fingerprint(&shifted_a_and(lit(1), M)),
    );
    assert_eq!(read.validate(), Ok(()));

    // L22: a virtual table the artifact does not list.
    let mut unlisted = with_shifted_a(&[(GAMMA, A), (zero(), ROW)], fingerprint(&[(GAMMA, A)]));
    unlisted.virtuals.clear();
    assert_eq!(
        unlisted.validate(),
        Err(ConstraintError::Locality {
            layer: 0,
            gate: "shifted_a".into(),
            operand: ROW,
        })
    );
    let listed = with_shifted_a(&[(GAMMA, A), (zero(), ROW)], fingerprint(&[(GAMMA, A)]));
    assert_eq!(
        listed.virtuals,
        [(VirtualKind::RowIndex, String::from("row"))]
    );
    assert_eq!(listed.validate(), Ok(()));
}

// ---------------------------------------------------------------------------
// Halving lists
// ---------------------------------------------------------------------------

/// A halving list halves every column of its layer, in order. List 2's two
/// trees swapped — entry 0 halving `L{2}[1]` — are refused, naming the entry
/// and the column it must halve. Relations 6 and 7 are swapped with them, so
/// the flat list agrees and only the order is wrong; the legal spelling of this
/// reordering is `toy_with_list_1_reordered`, which validates.
#[test]
fn a_halving_list_refuses_its_trees_out_of_order() {
    assert_eq!(toy_with_list_1_reordered().validate(), Ok(()));

    let mut a = toy();
    a.layers[2].producing[0].gate = tree(inner(2, 1));
    a.layers[2].producing[1].gate = tree(inner(2, 0));
    a.relations[6].gate = tree(scratch(4));
    a.relations[7].gate = tree(scratch(3));
    assert_malformed(
        &a,
        "`define_abm_product` in halving gate list 2 is not TreeProduct of L{2}[0]",
    );
}

/// Gate list 0 reads the base and cannot halve. Marked halving with nothing
/// else changed, its stored variable count no longer matches and Law 2 refuses
/// it at layer 1. With every variable count fixed through (3, 3, 2), Law 2 is
/// satisfied and the halving rule itself refuses it.
///
/// Not isolable beyond that: list 0 also has a cached entry, an enforcing gate
/// and gates that are not trees, each forbidden in a halving list. The base
/// check comes first.
#[test]
fn gate_list_zero_cannot_halve() {
    let mut flagged = toy();
    flagged.layers[0].halving = true;
    assert_derived_width(
        &flagged,
        1,
        "stored num_vars 4 but gate list 0 writes 3 variables",
    );

    for (list, vars) in [3, 3, 2].into_iter().enumerate() {
        flagged.layers[list].num_vars = vars;
    }
    assert_malformed(
        &flagged,
        "gate list 0 reads the base and cannot be a halving list",
    );
}

/// A halving list has no enforcing gates. The same enforcing gate, `0 = ab`
/// with its relation appended to the flat list, validates in row-wise list 1
/// and is refused in halving list 2 (reading `L{2}[0]` there, `scratch[3]` in
/// the flat list).
#[test]
fn a_halving_list_refuses_an_enforcing_gate() {
    let with_enforcing = |k: usize, column: PolyAddress, slot: PolyAddress| {
        let mut a = toy();
        a.relations.push(Relation {
            name: "extra_zero".into(),
            output: None,
            gate: linear(&[(lit(1), slot)], lit(0)),
        });
        a.layers[k].enforcing.push(EnforcingEntry {
            relation: 8,
            gate: linear(&[(lit(1), column)], lit(0)),
        });
        a
    };
    assert_eq!(
        with_enforcing(1, inner(1, 0), scratch(0)).validate(),
        Ok(())
    );
    assert_malformed(
        &with_enforcing(2, inner(2, 0), scratch(3)),
        "halving gate list 2 has cached or enforcing entries",
    );
}

/// A row-wise list has no `TreeProduct`. `fingerprint3` as a tree of
/// `L{1}[1]`, its relation a tree of `scratch[1]`, is refused in row-wise
/// gate list 1: the list's kind is unchanged, so its variable count still
/// holds and the shape is the one thing wrong.
#[test]
fn a_row_wise_list_refuses_a_tree() {
    let mut a = toy();
    a.layers[1].producing[1].gate = tree(inner(1, 1));
    a.relations[5].gate = tree(scratch(1));
    assert_malformed(
        &a,
        "`define_fingerprint3` is a TreeProduct in row-wise gate list 1",
    );
}

// ---------------------------------------------------------------------------
// Nothing constructed and then dropped
// ---------------------------------------------------------------------------

/// The toy with a fourth list-0 column `L{1}[3] = a_copy = W[0]`: its relation,
/// scratch slot and list-0 width all consistent. If `read`, list 1 reads it, as
/// a second term of `fingerprint3` (its relation gaining `scratch[7]`).
fn toy_with_a_copy(read: bool) -> CircuitArtifact {
    let mut a = toy();
    a.relations.push(Relation {
        name: "define_a_copy".into(),
        output: Some(7),
        gate: linear(&[(lit(1), A)], lit(0)),
    });
    a.scratch.push(ScratchSlot {
        name: "a_copy".into(),
        address: inner(1, 3),
    });
    a.layers[0].producing.push(ProducingEntry {
        relation: 8,
        output: inner(1, 3),
        gate: linear(&[(lit(1), A)], lit(0)),
    });
    a.layers[0].width = 4;
    if read {
        a.layers[1].producing[1].gate =
            linear(&[(lit(1), inner(1, 1)), (lit(1), inner(1, 3))], lit(3));
        a.relations[5].gate = linear(&[(lit(1), scratch(1)), (lit(1), scratch(7))], lit(3));
    }
    a
}

/// Must-be-exact 14: no relation is constructed and then dropped. A column
/// `L{1}[3]` that list 1 never reads constrains nothing — a trace breaking its
/// relation still verifies — and is refused, naming the column. Read by list 1,
/// the same column validates.
#[test]
fn an_inner_column_nothing_reads_is_refused() {
    assert_eq!(toy_with_a_copy(true).validate(), Ok(()));
    assert_malformed(
        &toy_with_a_copy(false),
        "L{1}[3] is written but gate list 1 never reads it",
    );
}

/// Must-be-exact 14: a cached entry no gate names is refused, naming the entry
/// and its address. Named by `ab`'s gate as `a·C{0}[1]`, the same entry
/// validates.
#[test]
fn a_cached_entry_no_gate_names_is_refused() {
    let mut a = toy();
    a.layers[0]
        .cached
        .push(cached_entry("b_alias", 1, linear(&[(lit(1), B)], lit(0))));
    assert_malformed(&a, "cached entry `b_alias` (C{0}[1]) is named by no gate");

    a.layers[0].producing[0].gate = product(A, cached(0, 1));
    assert_eq!(a.validate(), Ok(()));
}

/// §4.2: "read" is decided on the gates' normalized expansions, so a term that
/// cancels reads nothing. `toy_with_a_copy(false)` — `L{1}[3]` written, nothing
/// reading it — with `fingerprint3 = 1·L{1}[1] + 1·L{1}[3] − 1·L{1}[3] + 3`,
/// its relation spelled the same way over `scratch[7]`: the gate names
/// `L{1}[3]` twice and reads it not at all, and is refused, naming the column.
/// The same gate with the cancelling term removed, `1·L{1}[1] + 1·L{1}[3] + 3`,
/// reads it and validates.
///
/// Kills deciding "read" from `GateDef::operands` rather than the expansion
/// (c94cff1's `nothing_dropped`), which counts the named column as read and
/// accepts the cancelling artifact.
#[test]
fn a_column_read_only_by_cancelling_terms_is_refused() {
    let with_terms = |gate: &[(Coeff, PolyAddress)], flat: &[(Coeff, PolyAddress)]| {
        let mut a = toy_with_a_copy(false);
        a.layers[1].producing[1].gate = linear(gate, lit(3));
        a.relations[5].gate = linear(flat, lit(3));
        a
    };

    let cancelling = with_terms(
        &[
            (lit(1), inner(1, 1)),
            (lit(1), inner(1, 3)),
            (neg(1), inner(1, 3)),
        ],
        &[
            (lit(1), scratch(1)),
            (lit(1), scratch(7)),
            (neg(1), scratch(7)),
        ],
    );
    assert!(cancelling.layers[1]
        .producing
        .iter()
        .any(|e| e.gate.operands().contains(&inner(1, 3))));
    assert_malformed(
        &cancelling,
        "L{1}[3] is written but gate list 1 never reads it",
    );

    let reading = with_terms(
        &[(lit(1), inner(1, 1)), (lit(1), inner(1, 3))],
        &[(lit(1), scratch(1)), (lit(1), scratch(7))],
    );
    assert_eq!(reading.validate(), Ok(()));
}

/// §3.1 allows a cached entry in any row-wise list, and a column read only
/// through one is read. In list 1, which reads inner columns, so its entries
/// read `L{1}` addresses that Law 4 maps to scratch slots:
/// - `fingerprint_copy = C{1}[0] = 1·L{1}[1] + 0`, named by `fingerprint3`'s
///   gate as `1·C{1}[0] + 3` with the relation unchanged, validates — no gate
///   reads `L{1}[1]` except through the entry;
/// - `abm_cached = C{1}[0] = 1·L{1}[0]·L{1}[2]`, degree 2, named by `abm`'s gate
///   as `1·C{1}[0] + 0` with the relation unchanged, validates — likewise for
///   `L{1}[0]` and `L{1}[2]`.
///
/// The refusal beside them: `fingerprint_copy` added with `fingerprint3`'s gate
/// left as the toy's is refused as named by no gate, at `C{1}[0]`.
///
/// Kills L08 (a cached entry's operands not counted as read, so `L{1}[1]` is
/// refused as never read) and L25 (a cached entry's operands expanded in the
/// flat namespace, so its `L{1}` columns are not mapped to scratch and Law 4
/// refuses the gate).
#[test]
fn a_column_read_through_a_cached_entry_of_list_one_is_read() {
    let mut linear_entry = toy();
    linear_entry.layers[1].cached.push(cached_entry_in(
        1,
        "fingerprint_copy",
        0,
        linear(&[(lit(1), inner(1, 1))], lit(0)),
    ));
    assert_malformed(
        &linear_entry,
        "cached entry `fingerprint_copy` (C{1}[0]) is named by no gate",
    );
    linear_entry.layers[1].producing[1].gate = linear(&[(lit(1), cached(1, 0))], lit(3));
    assert_eq!(
        linear_entry.relations[5].gate,
        linear(&[(lit(1), scratch(1))], lit(3))
    );
    assert_eq!(linear_entry.validate(), Ok(()));

    let mut product_entry = toy();
    product_entry.layers[1].cached.push(cached_entry_in(
        1,
        "abm_cached",
        0,
        product(inner(1, 0), inner(1, 2)),
    ));
    product_entry.layers[1].producing[0].gate = linear(&[(lit(1), cached(1, 0))], lit(0));
    assert_eq!(
        product_entry.relations[4].gate,
        product(scratch(0), scratch(2))
    );
    assert_eq!(product_entry.validate(), Ok(()));
}

// ---------------------------------------------------------------------------
// Names, header and the other construction rules
// ---------------------------------------------------------------------------

/// Must-be-exact 14: names are non-empty `[a-z0-9_]` and injective across the
/// whole artifact. `a_0` is a legal rename. Refused: scratch slot `ab` renamed
/// `a`, which a witness column already is; relation `define_ab` renamed
/// `shifted_a`, which a cached entry already is; `A`; `masked-m`; and the empty
/// name.
#[test]
fn names_are_nonempty_lowercase_and_used_once() {
    let mut legal = toy();
    legal.witness[0] = "a_0".into();
    assert_eq!(legal.validate(), Ok(()));

    let mut a = toy();
    a.scratch[0].name = "a".into();
    assert_malformed(&a, "name \"a\" is used twice");

    let mut a = toy();
    a.relations[0].name = "shifted_a".into();
    assert_malformed(&a, "name \"shifted_a\" is used twice");

    let mut a = toy();
    a.witness[0] = "A".into();
    assert_malformed(&a, "name \"A\" is not a non-empty [a-z0-9_] string");

    let mut a = toy();
    a.scratch[2].name = "masked-m".into();
    assert_malformed(&a, "name \"masked-m\" is not a non-empty [a-z0-9_] string");

    let mut a = toy();
    a.relations[3].name = String::new();
    assert_malformed(&a, "name \"\" is not a non-empty [a-z0-9_] string");
}

/// Must-be-exact 14: the name rules cover setup columns and virtual tables too.
/// `s_0` and `row_index` are legal renames. Refused: the virtual table renamed
/// `a`, which a witness column already is; the virtual table renamed `Row`; the
/// setup column renamed `a`; and the setup column renamed `S`.
///
/// Kills L12 (virtual-table names left out of the name check) and L13 (setup
/// names left out): under either, that subtree's refusals validate.
#[test]
fn setup_and_virtual_names_obey_the_name_rules() {
    let mut legal = toy();
    legal.setup[0] = "s_0".into();
    legal.virtuals[0].1 = "row_index".into();
    assert_eq!(legal.validate(), Ok(()));

    let mut a = toy();
    a.virtuals[0].1 = "a".into();
    assert_malformed(&a, "name \"a\" is used twice");

    let mut a = toy();
    a.virtuals[0].1 = "Row".into();
    assert_malformed(&a, "name \"Row\" is not a non-empty [a-z0-9_] string");

    let mut a = toy();
    a.setup[0] = "a".into();
    assert_malformed(&a, "name \"a\" is used twice");

    let mut a = toy();
    a.setup[0] = "S".into();
    assert_malformed(&a, "name \"S\" is not a non-empty [a-z0-9_] string");
}

/// Each virtual table is listed once. A second `RowIndex` entry, under a fresh
/// legal name so the kind is the one thing wrong, is refused naming the kind;
/// the toy's one entry validates.
///
/// Kills L14 (the listed-twice check disabled), under which the duplicate
/// validates.
#[test]
fn a_virtual_table_listed_twice_is_refused() {
    assert_eq!(
        toy().virtuals,
        [(VirtualKind::RowIndex, String::from("row"))]
    );
    assert_eq!(toy().validate(), Ok(()));

    let mut a = toy();
    a.virtuals.push((VirtualKind::RowIndex, "row_again".into()));
    assert_malformed(&a, "virtual table RowIndex is listed twice");
}

/// The toy with one lookup, `range`: `4·m − row − 1` on the timestamp channel
/// under selector `s`, edited by `edit`.
fn toy_with_lookup(edit: fn(&mut LookupExpr)) -> CircuitArtifact {
    let mut lookup = LookupExpr {
        name: "range".into(),
        channel: lookup_channel::TIMESTAMP,
        selector: S,
        tuple: vec![linear(&[(lit(4), M), (neg(1), ROW)], neg(1))],
    };
    edit(&mut lookup);
    let mut a = toy();
    a.lookups.push(lookup);
    a
}

/// The lookup rules of `docs/spec/gkr.md` §4.2 (`docs/spec/memory.md` §7). A
/// lookup over a committed column and a listed virtual table, under a committed
/// selector, validates, and so do two. Each rule broken alone is refused naming
/// the lookup: a channel past `constants::lookup_channel`; a tuple of no
/// expression or of two; a `Product` expression; a challenge coefficient, on a
/// term and as the constant; an operand that is `L{1}[0]`, `scratch[0]`,
/// `C{0}[0]`, `W[4]` past the layout, or `V[ram_live]`, which the toy does not
/// list; a selector that is `V[row]`, `W[4]` or `L{1}[0]`. Its name is held to
/// the artifact's rule: `a`, a witness column's, and `Range` are refused.
#[test]
fn a_lookup_is_refused_unless_it_keeps_the_lookup_rules() {
    assert!(toy().lookups.is_empty());
    assert_eq!(toy_with_lookup(|_| {}).validate(), Ok(()));
    let mut two = toy_with_lookup(|_| {});
    let mut second = two.lookups[0].clone();
    second.name = "range_2".into();
    second.selector = A;
    two.lookups.push(second);
    assert_eq!(two.validate(), Ok(()));

    let refused = |edit: fn(&mut LookupExpr), needle: &str| {
        assert_malformed(&toy_with_lookup(edit), &format!("lookup `range` {needle}"))
    };
    refused(
        |l| l.channel = lookup_channel::NAMES.len() as u32,
        "names channel 1, which is not in constants::lookup_channel",
    );
    refused(|l| l.tuple.clear(), "has 0 expressions");
    refused(|l| l.tuple.push(l.tuple[0].clone()), "has 2 expressions");
    refused(
        |l| l.tuple[0] = product(M, S),
        "has an expression that is not Linear",
    );
    refused(
        |l| l.tuple[0] = linear(&[(GAMMA, M)], lit(0)),
        "has a coefficient that is not a literal",
    );
    refused(
        |l| l.tuple[0] = linear(&[(lit(1), M)], GAMMA),
        "has a coefficient that is not a literal",
    );
    refused(
        |l| l.tuple[0] = linear(&[(lit(1), inner(1, 0))], lit(0)),
        "reads L{1}[0]",
    );
    refused(
        |l| l.tuple[0] = linear(&[(lit(1), scratch(0))], lit(0)),
        "reads scratch[0]",
    );
    refused(
        |l| l.tuple[0] = linear(&[(lit(1), cached(0, 0))], lit(0)),
        "reads C{0}[0]",
    );
    refused(
        |l| l.tuple[0] = linear(&[(lit(1), PolyAddress::Witness(4))], lit(0)),
        "reads W[4]",
    );
    refused(
        |l| {
            let live = PolyAddress::Virtual(VirtualKind::RamLive);
            l.tuple[0] = linear(&[(lit(1), live)], lit(0));
        },
        "reads V[ram_live]",
    );
    refused(|l| l.selector = ROW, "has selector V[row]");
    refused(
        |l| l.selector = PolyAddress::Witness(4),
        "has selector W[4]",
    );
    refused(|l| l.selector = inner(1, 0), "has selector L{1}[0]");

    assert_malformed(
        &toy_with_lookup(|l| l.name = "a".into()),
        "name \"a\" is used twice",
    );
    assert_malformed(
        &toy_with_lookup(|l| l.name = "Range".into()),
        "name \"Range\" is not a non-empty [a-z0-9_] string",
    );
}

/// A coefficient names a slot of `constants::challenge_slot`. `γ` moved to the
/// first slot past the table, in both the cached entry and the relation that
/// spells it, is refused naming the slot; the toy's own slot validates.
#[test]
fn an_unknown_challenge_slot_is_refused() {
    assert_eq!(GAMMA, Coeff::Challenge(challenge_slot::TOY));
    let unknown = challenge_slot::NAMES.len() as u32;
    let moved = Coeff::Challenge(unknown);

    let mut a = toy();
    a.layers[0].cached[0].gate = linear(&[(moved, A), (lit(1), ROW)], lit(0));
    a.relations[1].gate = GateDef::AffineProduct {
        left: vec![(moved, A), (lit(1), ROW)],
        left_constant: lit(0),
        right: vec![(lit(1), C)],
        right_constant: lit(0),
    };
    assert_malformed(
        &a,
        &format!("challenge slot {unknown} is not in constants::challenge_slot"),
    );
}

/// Must-be-exact 14: the padding row names one value per committed column. Six
/// values validate, whatever they are — whether they satisfy the relations is
/// the checker's to say; five and seven are refused.
#[test]
fn a_padding_row_of_the_wrong_length_is_refused() {
    let mut ones = toy();
    ones.padding.row = vec![Fr::ONE; 6];
    assert_eq!(ones.validate(), Ok(()));

    for len in [5usize, 7] {
        let mut a = toy();
        a.padding.row = vec![Fr::ZERO; len];
        assert_malformed(
            &a,
            &format!("the padding row has {len} values for 6 committed columns"),
        );
    }
}

/// A trace is at most `2^30` rows. With every list's variable count fixed
/// through, `trace_vars` 30 validates and 31 is refused.
#[test]
fn trace_vars_above_thirty_is_refused() {
    let with_vars = |n: u32| {
        let mut a = toy();
        a.trace_vars = n;
        a.layers[0].num_vars = n;
        a.layers[1].num_vars = n;
        a.layers[2].num_vars = n - 1;
        a
    };
    assert_eq!(constraints::MAX_TRACE_VARS, 30);
    assert_eq!(with_vars(30).validate(), Ok(()));
    assert_malformed(&with_vars(31), "trace_vars 31 is above 30");
}

/// The first two words of the artifact are 1 and 0, and nothing else: a format
/// version of 0 or 2 and a coefficient encoding of 1 are each refused.
#[test]
fn a_wrong_format_version_or_coefficient_encoding_is_refused() {
    assert_eq!(constraints::FORMAT_VERSION, 1);
    for version in [0, 2] {
        let mut a = toy();
        a.format_version = version;
        assert_malformed(&a, &format!("format version {version}, expected 1"));
    }

    let mut a = toy();
    a.coefficient_encoding = 1;
    assert_malformed(&a, "coefficient encoding 1;");
}

// ---------------------------------------------------------------------------
// The cache-free compilation
// ---------------------------------------------------------------------------

/// `docs/spec/gkr.md` §3.1: the toy inlines to exactly the committed cache-free
/// artifact, which validates, and whose one rewritten gate is §3.1's
/// `Product { c, C, y } → AffineProduct { C.terms, C.constant ; [(c, y)], 0 }`.
/// Inlining an artifact with no cached entries is the identity.
#[test]
fn the_toy_inlines_to_the_committed_cache_free_compilation() {
    let inlined = toy().inline_cached().expect("the toy inlines");
    assert_eq!(inlined, toy_cache_free());
    assert_eq!(inlined.validate(), Ok(()));
    assert_eq!(
        inlined.layers[0].producing[1].gate,
        GateDef::AffineProduct {
            left: vec![(GAMMA, A), (lit(1), ROW)],
            left_constant: lit(0),
            right: vec![(lit(1), C)],
            right_constant: lit(0),
        }
    );
    assert_eq!(toy_cache_free().inline_cached(), Ok(toy_cache_free()));
}

/// §3.1's second rule: `Product { c, x, C } → AffineProduct { [(c, x)], 0 ;
/// C.terms, C.constant }` — a cached factor on the right inlines on the right.
/// `fingerprint`'s gate written `Product { 1, c, shifted_a }` validates, and
/// inlines to exactly the committed cache-free compilation with that one gate
/// `AffineProduct { [(1, c)], 0 ; [(γ, a), (1, row)], 0 }`, which validates.
///
/// Kills L19 (the right-factor branch emitting the left-factor spelling,
/// `AffineProduct { C.terms, C.constant ; [(c, x)], 0 }`): the same
/// polynomial, so it would still validate, but a different artifact.
#[test]
fn a_right_cached_factor_inlines_on_the_right() {
    let shifted_a = linear(&[(GAMMA, A), (lit(1), ROW)], lit(0));
    assert_eq!(toy().layers[0].cached[0].gate, shifted_a);

    let mut a = toy();
    a.layers[0].producing[1].gate = product(C, cached(0, 0));
    assert_eq!(a.validate(), Ok(()));

    let mut expected = toy_cache_free();
    expected.layers[0].producing[1].gate =
        affine(&[(lit(1), C)], lit(0), &[(GAMMA, A), (lit(1), ROW)], lit(0));
    let inlined = a.inline_cached();
    assert_eq!(inlined, Ok(expected));
    assert_eq!(inlined.map(|out| out.validate()), Ok(Ok(())));
}

/// §3.1: a `Product` inlines when exactly one factor is a cached `Linear`.
/// `fingerprint`'s gate rewritten as `shifted_a · c_alias`, both cached
/// `Linear`s, is a legal circuit — it validates — and refuses to inline, naming
/// the gate.
#[test]
fn a_product_of_two_cached_linears_is_not_inlinable() {
    let mut a = toy();
    a.layers[0]
        .cached
        .push(cached_entry("c_alias", 1, linear(&[(lit(1), C)], lit(0))));
    a.layers[0].producing[1].gate = product(cached(0, 0), cached(0, 1));
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(
        a.inline_cached(),
        Err(ConstraintError::NotInlinable {
            gate: "define_fingerprint".into(),
        })
    );
}

/// §3.1: only a `Linear` cached entry inlines. `ab`'s gate as `a_affine · b`,
/// where `a_affine = (1·a + 0)·(1)` is a degree-1 `AffineProduct`, validates and
/// refuses to inline.
///
/// A cached `Product` named by a `Product` — the case one would write first —
/// can never reach the inliner: a `Product` is degree 2, so naming it from a
/// `Product` is degree 3, and `inline_cached` validates its input first. That
/// artifact is refused with the degree error, which is asserted here too.
#[test]
fn a_product_over_a_cached_non_linear_is_not_inlinable() {
    let mut a = toy();
    a.layers[0].cached.push(cached_entry(
        "a_affine",
        1,
        GateDef::AffineProduct {
            left: vec![(lit(1), A)],
            left_constant: lit(0),
            right: vec![],
            right_constant: lit(1),
        },
    ));
    a.layers[0].producing[0].gate = product(cached(0, 1), B);
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(
        a.inline_cached(),
        Err(ConstraintError::NotInlinable {
            gate: "define_ab".into(),
        })
    );

    assert_eq!(
        toy_with_ab_cached(product(cached(0, 1), C)).inline_cached(),
        Err(ConstraintError::Degree {
            gate: "define_ab".into(),
            degree: 3,
        })
    );
}

/// §3.1: a reference from any shape but `Product` refuses to inline.
/// `masked_m` as `MaskIntoIdentity { m_alias, s }`, with `m_alias = m` a cached
/// `Linear`, validates and refuses to inline. So does `ab`'s gate as
/// `Linear { 1·ab_cached }`.
#[test]
fn a_cached_reference_from_another_shape_is_not_inlinable() {
    let mut a = toy();
    a.layers[0]
        .cached
        .push(cached_entry("m_alias", 1, linear(&[(lit(1), M)], lit(0))));
    a.layers[0].producing[2].gate = GateDef::MaskIntoIdentity {
        input: cached(0, 1),
        mask: S,
    };
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(
        a.inline_cached(),
        Err(ConstraintError::NotInlinable {
            gate: "define_masked_m".into(),
        })
    );

    let linear_ref = toy_with_ab_cached(linear(&[(lit(1), cached(0, 1))], lit(0)));
    assert_eq!(linear_ref.validate(), Ok(()));
    assert_eq!(
        linear_ref.inline_cached(),
        Err(ConstraintError::NotInlinable {
            gate: "define_ab".into(),
        })
    );
}

// ---------------------------------------------------------------------------
// Totality
// ---------------------------------------------------------------------------

/// A decoded artifact may break every law, and `validate` must say so rather
/// than panic: over every single-bit flip of the cached toy that still decodes,
/// `validate` and `inline_cached` both return. Whatever inlines validated, and
/// its output validates too. The counts are reported, not required.
#[test]
fn validate_and_inline_return_on_every_decodable_bit_flip() {
    let bytes = toy_cached_bytes();
    let (mut decoded, mut valid, mut inlined) = (0usize, 0usize, 0usize);
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut flipped = bytes.clone();
            flipped[i] ^= 1 << bit;
            let Ok(a) = CircuitArtifact::from_bytes(&flipped) else {
                continue;
            };
            decoded += 1;
            let validates = a.validate().is_ok();
            valid += usize::from(validates);
            if let Ok(out) = a.inline_cached() {
                inlined += 1;
                assert!(validates, "byte {i} bit {bit} inlined without validating");
                assert_eq!(out.validate(), Ok(()), "byte {i} bit {bit}");
            }
        }
    }
    assert!(
        inlined <= valid && valid <= decoded && decoded > 0,
        "of {} flips, {decoded} decode, {valid} validate, {inlined} inline",
        bytes.len() * 8
    );
    eprintln!(
        "of {} flips, {decoded} decode, {valid} validate, {inlined} inline",
        bytes.len() * 8
    );
}

// ---------------------------------------------------------------------------
// The Quadratic shape
// ---------------------------------------------------------------------------

fn quadratic(
    constant: Coeff,
    linear: &[(Coeff, PolyAddress)],
    products: &[(Coeff, PolyAddress, PolyAddress)],
) -> GateDef {
    GateDef::Quadratic {
        constant,
        linear: linear.to_vec(),
        products: products.to_vec(),
    }
}

/// The toy's gated equality, `e·s − a·s`, as its products.
fn gated_products() -> Vec<(Coeff, PolyAddress, PolyAddress)> {
    vec![(lit(1), E, S), (neg(1), A, S)]
}

/// A `Quadratic`'s degree is its widest term, cached entries substituted.
/// `ab_cached = a·b` is degree 2. As a factor of a product in the gated
/// equality, `e·s − a·s + ab_cached·s`, it makes the gate degree 3, refused as
/// exactly that before Law 4 is reached. As a linear term,
/// `ab_cached + e·s − a·s − a·b`, it is degree 2 and still the flat list's
/// `e·s − a·s`, and the circuit validates.
///
/// Kills a degree that counts a product as its wider factor alone (the
/// degree-3 gate then reaches Law 4 and is refused as `SingleSource`), and one
/// that counts a linear term as a product with the constant (the degree-2 gate
/// is then refused as degree 3).
#[test]
fn a_quadratic_is_as_wide_as_its_widest_term() {
    let named_linearly = linear(&[(lit(1), cached(0, 1))], lit(0));

    let mut in_product = toy_with_ab_cached(named_linearly.clone());
    let mut products = gated_products();
    products.push((lit(1), cached(0, 1), S));
    in_product.layers[0].enforcing[0].gate = quadratic(lit(0), &[], &products);
    assert_eq!(
        in_product.validate(),
        Err(ConstraintError::Degree {
            gate: "gated_equality".into(),
            degree: 3,
        })
    );

    let mut in_linear = toy_with_ab_cached(named_linearly);
    let mut products = gated_products();
    products.push((neg(1), A, B));
    in_linear.layers[0].enforcing[0].gate = quadratic(lit(0), &[(lit(1), cached(0, 1))], &products);
    assert_eq!(in_linear.validate(), Ok(()));
}

/// An enforcing `Quadratic` whose products cancel, `e·s − s·e` in the gate and
/// its relation alike, is identically zero and refused as constraining nothing;
/// the toy's own `e·s − a·s` is the control.
///
/// Kills a `Quadratic` expansion that does not normalize its sum: the two
/// products are one monomial, `e·s`, and only the merge makes them cancel.
#[test]
fn an_enforcing_quadratic_whose_products_cancel_is_refused() {
    let mut a = toy();
    let cancels = quadratic(lit(0), &[], &[(lit(1), E, S), (neg(1), S, E)]);
    a.layers[0].enforcing[0].gate = cancels.clone();
    a.relations[3].gate = cancels;
    assert_malformed(
        &a,
        "enforcing gate `gated_equality` in gate list 0 is identically zero",
    );
    assert_eq!(toy().validate(), Ok(()));
}

/// An inner column read only through `Quadratic` terms that cancel is unread.
/// `abm` rewritten `ab·masked_m + k·fingerprint·ab − ab·fingerprint` and
/// `fingerprint3` rewritten to the constant 3, gates and relations alike: at
/// `k = 1` `L{1}[1]` is named twice and read by nothing, and is refused; at
/// `k = 2` it is read, and the circuit validates.
///
/// Kills a `Quadratic` expansion that does not normalize its sum, under which
/// the two `ab·fingerprint` monomials stay apart and each reads `L{1}[1]`.
#[test]
fn a_column_read_only_through_cancelling_quadratic_terms_is_unread() {
    let with_k = |k: u64| {
        let mut a = toy();
        let (ab, fp, masked) = (inner(1, 0), inner(1, 1), inner(1, 2));
        a.layers[1].producing[0].gate = quadratic(
            lit(0),
            &[],
            &[(lit(1), ab, masked), (lit(k), fp, ab), (neg(1), ab, fp)],
        );
        a.relations[4].gate = quadratic(
            lit(0),
            &[],
            &[
                (lit(1), scratch(0), scratch(2)),
                (lit(k), scratch(1), scratch(0)),
                (neg(1), scratch(0), scratch(1)),
            ],
        );
        a.layers[1].producing[1].gate = linear(&[], lit(3));
        a.relations[5].gate = linear(&[], lit(3));
        a
    };
    assert_malformed(
        &with_k(1),
        "L{1}[1] is written but gate list 1 never reads it",
    );
    assert_eq!(with_k(2).validate(), Ok(()));
}

/// Law 4 compares polynomials, not shapes: the toy's `Quadratic` gate
/// `e·s − a·s` against its relation rewritten `(e − a)·s` as an
/// `AffineProduct` validates; the gate with `−2·a·s` in place of `−1·a·s` is a
/// different polynomial and is refused.
///
/// Kills a `Quadratic` expansion that ignores its product coefficients: the
/// gate is then `e·s + a·s`, and the matching pair is refused.
#[test]
fn law4_holds_a_quadratic_to_the_polynomial_its_relation_spells() {
    let mut a = toy();
    a.relations[3].gate = affine(&[(lit(1), E), (neg(1), A)], lit(0), &[(lit(1), S)], lit(0));
    assert_eq!(a.validate(), Ok(()));

    a.layers[0].enforcing[0].gate = quadratic(lit(0), &[], &[(lit(1), E, S), (neg(2), A, S)]);
    assert_single_source(
        &a,
        "relation `gated_equality` and its gate in gate list 0 are different polynomials",
    );
}

/// §3.1: a `Quadratic` naming a cached entry does not inline. The gated
/// equality with `shifted_a` added as a linear term, `shifted_a + e·s − a·s`,
/// its relation `γ·a + row + e·s − a·s`, validates and refuses to inline,
/// naming the gate. A `Quadratic` naming none passes through: the toy's own
/// gated equality is unchanged in its cache-free compilation.
///
/// Kills an inliner passing every `Quadratic` through unchanged: the output
/// then names a cached entry its emptied list no longer has, and is refused as
/// locality instead.
#[test]
fn a_quadratic_naming_a_cached_entry_is_not_inlinable() {
    let mut a = toy();
    a.layers[0].enforcing[0].gate = quadratic(lit(0), &[(lit(1), cached(0, 0))], &gated_products());
    a.relations[3].gate = quadratic(lit(0), &[(GAMMA, A), (lit(1), ROW)], &gated_products());
    assert_eq!(a.validate(), Ok(()));
    assert_eq!(
        a.inline_cached(),
        Err(ConstraintError::NotInlinable {
            gate: "gated_equality".into(),
        })
    );

    let gated = quadratic(lit(0), &[], &gated_products());
    assert_eq!(toy().layers[0].enforcing[0].gate, gated);
    assert_eq!(
        toy()
            .inline_cached()
            .map(|out| out.layers[0].enforcing[0].gate.clone()),
        Ok(gated)
    );
}
