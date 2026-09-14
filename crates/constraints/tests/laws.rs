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
use constants::challenge_slot;
use constraints::{
    CachedEntry, CircuitArtifact, Coeff, ConstraintError, EnforcingEntry, GateDef, LookupExpr,
    PolyAddress, ProducingEntry, Relation, ScratchSlot,
};
use field::Fr;

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
    CachedEntry {
        name: name.into(),
        address: cached(0, offset),
        gate,
    }
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
/// replaced by `L{2}[0]` from below the top, an output duplicated, and a third
/// output `L{3}[2]` past the top layer's width.
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

/// Must-be-exact 7: the lookup-expression list exists and is empty at S13; one
/// expression is refused.
#[test]
fn a_nonempty_lookup_list_is_refused() {
    assert!(toy().lookups.is_empty());
    let mut a = toy();
    a.lookups.push(LookupExpr {
        name: "lookup".into(),
        channel: 0,
        tuple: vec![],
    });
    assert_malformed(&a, "the lookup-expression list must be empty");
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

/// The first two words of the artifact are 0, and nothing else: a format
/// version of 1 and a coefficient encoding of 1 are each refused.
#[test]
fn a_nonzero_format_version_or_coefficient_encoding_is_refused() {
    let mut a = toy();
    a.format_version = 1;
    assert_malformed(&a, "format version 1, expected 0");

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
