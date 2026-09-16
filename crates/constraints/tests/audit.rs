//! Acceptance 11, must-be-exact 3 and 13: the dead-variant audit over every
//! compilation of the toy, the gate catalogue, and the claim that the cached
//! and cache-free compilations are one circuit in two spellings.

mod common;

use common::{fixture_bytes, toy, toy_cache_free};
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress, CATALOGUE};

/// The variant count, and each variant's name, written as an exhaustive match
/// with no wildcard: a variant appended to `GateDef` stops this file compiling
/// until the audit accounts for it. The names are this file's, not the
/// catalogue's, so the catalogue is checked against something.
const VARIANTS: usize = 7;

fn variant_name(g: &GateDef) -> &'static str {
    match g {
        GateDef::Linear { .. } => "Linear",
        GateDef::Product { .. } => "Product",
        GateDef::MaskIntoIdentity { .. } => "MaskIntoIdentity",
        GateDef::AffineProduct { .. } => "AffineProduct",
        GateDef::TreeProduct { .. } => "TreeProduct",
        GateDef::Quadratic { .. } => "Quadratic",
        GateDef::TreeCross { .. } => "TreeCross",
    }
}

/// The catalogue row describing `g`'s variant: the one whose `variant` is this
/// file's name for it. A variant with no row, or with two, fails here.
#[track_caller]
fn catalogue_row(g: &GateDef) -> usize {
    let rows: Vec<usize> = (0..CATALOGUE.len())
        .filter(|&i| CATALOGUE[i].variant == variant_name(g))
        .collect();
    assert_eq!(
        rows.len(),
        1,
        "catalogue rows for {}: {rows:?}",
        variant_name(g)
    );
    rows[0]
}

/// The wire tag `to_bytes` writes for `g`: the first byte of its encoding.
fn wire_tag(g: &GateDef) -> u8 {
    postcard::to_extend(g, Vec::new()).expect("encoding into a Vec cannot fail")[0]
}

/// One gate of every variant, in wire-tag order.
fn one_of_each() -> [GateDef; VARIANTS] {
    let one = Coeff::Literal(field::Fr::ONE);
    let x = PolyAddress::Witness(0);
    let y = PolyAddress::Witness(1);
    [
        GateDef::Linear {
            terms: vec![(one, x)],
            constant: one,
        },
        GateDef::Product {
            coeff: one,
            left: x,
            right: y,
        },
        GateDef::MaskIntoIdentity { input: x, mask: y },
        GateDef::AffineProduct {
            left: vec![(one, x)],
            left_constant: one,
            right: vec![(one, y)],
            right_constant: one,
        },
        GateDef::TreeProduct { input: x },
        GateDef::Quadratic {
            constant: one,
            linear: vec![(one, x)],
            products: vec![(one, x, y)],
        },
        GateDef::TreeCross { left: x, right: y },
    ]
}

/// Every gate the artifact carries: every list's cached, producing and
/// enforcing entries, then every relation of the flat list.
fn every_gate(a: &CircuitArtifact) -> Vec<&GateDef> {
    let mut gates: Vec<&GateDef> = Vec::new();
    for list in &a.layers {
        gates.extend(list.cached.iter().map(|e| &e.gate));
        gates.extend(list.producing.iter().map(|e| &e.gate));
        gates.extend(list.enforcing.iter().map(|e| &e.gate));
    }
    gates.extend(a.relations.iter().map(|r| &r.gate));
    gates
}

/// How many gates of each variant, indexed by catalogue row.
fn variant_counts(a: &CircuitArtifact) -> [usize; VARIANTS] {
    let mut counts = [0usize; VARIANTS];
    for g in every_gate(a) {
        counts[catalogue_row(g)] += 1;
    }
    counts
}

/// S15's combined toy, the one committed circuit with a fraction tree in it.
fn lookup_toy() -> CircuitArtifact {
    let bytes = fixture_bytes(
        "lookup_toy.bin",
        "975ee4d572a09399c30987eb2a8e8ad9d2b66a2445c8888d331d34343f9409d6",
    );
    CircuitArtifact::from_bytes(&bytes).expect("the S15 toy decodes")
}

/// Acceptance 11: across every committed circuit — the audit runs over all of
/// them, since a variant absent from one may be the one another uses —
/// every `GateDef` variant is emitted, so none is dead and none needs to be
/// documented as reserved. Each emitted gate is mapped to its catalogue row by
/// this file's own variant names, so a catalogue row renamed away from its
/// variant fails here too.
///
/// `TreeCross` is S15's, and the S13 toy emits none: a fraction tree is the one
/// thing that halves two columns together, and only the S15 toy has one.
#[test]
fn the_audit_over_every_committed_circuit_emits_every_variant() {
    let mut emitted = [false; VARIANTS];
    for a in [toy(), toy_cache_free(), lookup_toy()] {
        for g in every_gate(&a) {
            emitted[catalogue_row(g)] = true;
        }
    }
    let dead: Vec<&str> = (0..VARIANTS)
        .filter(|&i| !emitted[i])
        .map(|i| CATALOGUE[i].variant)
        .collect();
    assert!(dead.is_empty(), "variants no test circuit emits: {dead:?}");
}

/// Each compilation's per-variant counts, written down from the toy's
/// description (`tests/common/mod.rs`) rather than read back from the files.
///
/// Cached: `Linear` is `shifted_a`, `fingerprint3`'s gate and its relation;
/// `Product` is the gates of `ab`, `fingerprint` (`shifted_a·c`) and `abm` and
/// the relations of `ab` and `abm`; `MaskIntoIdentity` is `masked_m`'s gate and
/// relation; `AffineProduct` is the relation of `fingerprint` alone;
/// `TreeProduct` is the two halving gates and their relations; `Quadratic` is
/// the gated equality, `e·s − a·s`, as the enforcing gate and as its relation.
///
/// Cache-free: `shifted_a` is gone and `fingerprint`'s `Product` over it is now
/// an `AffineProduct`, so `Linear` and `Product` each lose one and
/// `AffineProduct` gains one. The two compilations emit different mixes of
/// `Product` and `AffineProduct`, which is why the audit unions them. (At the
/// toy's size each compilation alone still covers all six variants, because
/// the flat list carries the `AffineProduct` the cached gates do not.)
#[test]
fn each_compilation_reports_its_own_variant_counts() {
    //                  Linear Product Mask Affine Tree Quadratic Cross
    let cached_counts = [3, 5, 2, 1, 4, 2, 0];
    let cache_free_counts = [2, 4, 2, 2, 4, 2, 0];

    assert_eq!(variant_counts(&toy()), cached_counts, "toy_cached.bin");
    assert_eq!(
        variant_counts(&toy_cache_free()),
        cache_free_counts,
        "toy_cache_free.bin"
    );

    let product = 1;
    let affine = 3;
    assert_eq!(CATALOGUE[product].variant, "Product");
    assert_eq!(CATALOGUE[affine].variant, "AffineProduct");
    assert_ne!(cached_counts[product], cache_free_counts[product]);
    assert_ne!(cached_counts[affine], cache_free_counts[affine]);
    // Inlining rewrites a gate's shape and removes cached entries; it never
    // adds or removes a producing, enforcing or relation entry.
    let entries = |a: &CircuitArtifact| {
        every_gate(a).len() - a.layers.iter().map(|l| l.cached.len()).sum::<usize>()
    };
    assert_eq!(entries(&toy()), entries(&toy_cache_free()));
}

/// Must-be-exact 3 and 13: the catalogue has one row per variant, in wire-tag
/// order, named for the variant it describes, and no field of any row is empty.
/// Row `i` is the variant `to_bytes` tags `i` — the tag is read from the
/// encoding, not from `one_of_each`'s order — so two rows swapped, or a row
/// renamed, is refused.
#[test]
fn the_catalogue_has_one_row_per_variant_in_wire_tag_order() {
    assert_eq!(CATALOGUE.len(), VARIANTS);
    for (i, g) in one_of_each().iter().enumerate() {
        assert_eq!(usize::from(wire_tag(g)), i, "{g:?}");
        assert_eq!(catalogue_row(g), i, "{g:?}");
        let row = &CATALOGUE[i];
        assert_eq!(row.variant, variant_name(g));
        for (field, value) in [
            ("variant", row.variant),
            ("defined_in", row.defined_in),
            ("evaluated_in", row.evaluated_in),
            ("inputs", row.inputs),
            ("output", row.output),
            ("template", row.template),
            ("purpose", row.purpose),
        ] {
            assert!(
                !value.trim().is_empty(),
                "{}'s {field} is empty",
                row.variant
            );
        }
        // Every template is written in the one producing shape.
        assert!(
            row.template.starts_with("out(x) = Σ_y eq(x,y)·"),
            "{}'s template is {:?}",
            row.variant,
            row.template
        );
    }
    let mut names: Vec<&str> = CATALOGUE.iter().map(|r| r.variant).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), VARIANTS, "catalogue variants are distinct");
}

/// Must-be-exact 3: the cached and cache-free compilations have the same depth,
/// the same width and variable count at every layer, and the same producing and
/// enforcing totals per list; only the cached one has cached entries. Beyond
/// that, the cache-free compilation differs only in the gates that named a
/// cached entry: the flat list, scratch bijection, outputs, layout and padding
/// are identical, and so is every gate that named none.
#[test]
fn cached_and_cache_free_compilations_have_the_same_shape() {
    let cached = toy();
    let free = toy_cache_free();

    assert_eq!(cached.depth(), 3);
    assert_eq!(cached.depth(), free.depth());
    for k in 0..=cached.depth() {
        assert_eq!(cached.layer_width(k), free.layer_width(k), "w_{k}");
        assert_eq!(cached.layer_vars(k), free.layer_vars(k), "n_{k}");
    }
    let totals = |a: &CircuitArtifact| -> Vec<(usize, usize)> {
        a.layers
            .iter()
            .map(|l| (l.producing.len(), l.enforcing.len()))
            .collect()
    };
    assert_eq!(totals(&cached), vec![(3, 1), (2, 0), (2, 0)]);
    assert_eq!(totals(&cached), totals(&free));

    let cached_entries: usize = cached.layers.iter().map(|l| l.cached.len()).sum();
    assert_eq!(cached_entries, 1, "the toy has one cached expression");
    assert!(free.layers.iter().all(|l| l.cached.is_empty()));

    assert_eq!(cached.relations, free.relations);
    assert_eq!(cached.scratch, free.scratch);
    assert_eq!(cached.outputs, free.outputs);
    assert_eq!(cached.committed(), free.committed());
    assert_eq!(cached.virtuals, free.virtuals);
    assert_eq!(cached.padding, free.padding);

    let names_cached = |g: &GateDef| {
        g.operands()
            .iter()
            .any(|op| matches!(op, PolyAddress::Cached { .. }))
    };
    let mut rewritten = 0;
    for (lc, lf) in cached.layers.iter().zip(&free.layers) {
        assert_eq!(
            (lc.halving, lc.num_vars, lc.width),
            (lf.halving, lf.num_vars, lf.width)
        );
        let pairs = lc
            .producing
            .iter()
            .map(|e| (&e.gate, e.relation, Some(e.output)))
            .zip(
                lf.producing
                    .iter()
                    .map(|e| (&e.gate, e.relation, Some(e.output))),
            )
            .chain(
                lc.enforcing
                    .iter()
                    .map(|e| (&e.gate, e.relation, None))
                    .zip(lf.enforcing.iter().map(|e| (&e.gate, e.relation, None))),
            );
        for ((gc, rc, oc), (gf, rf, of)) in pairs {
            assert_eq!((rc, oc), (rf, of));
            if names_cached(gc) {
                rewritten += 1;
                assert_ne!(gc, gf);
                assert!(!names_cached(gf));
            } else {
                assert_eq!(gc, gf);
            }
        }
    }
    assert_eq!(rewritten, 1, "only `fingerprint`'s gate names `shifted_a`");
}
