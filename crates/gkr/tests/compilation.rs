//! Acceptance 7, and the prover's side of cached entries: the cached and
//! cache-free compilations of the toy are the same circuit — same shape, same
//! forward values, the same proof byte for byte — and a degree-2 cached entry,
//! which cannot be inlined, is evaluated at every round node rather than bound
//! as a table.

mod common;

use common::{discharge, honest, toy, toy_base, toy_cache_free, toy_columns};
use constraints::{CachedEntry, Coeff, ConstraintError, GateDef, PolyAddress};
use field::Fr;

#[test]
fn cached_and_cache_free_are_one_circuit() {
    let cached = toy();
    let free = toy_cache_free();
    assert_eq!(cached.depth(), free.depth(), "layer count");
    for k in 0..=cached.depth() {
        assert_eq!(
            cached.layer_width(k),
            free.layer_width(k),
            "width of layer {k}"
        );
        assert_eq!(
            cached.layer_vars(k),
            free.layer_vars(k),
            "variables of layer {k}"
        );
    }
    let totals = |a: &constraints::CircuitArtifact| -> Vec<(usize, usize)> {
        a.layers
            .iter()
            .map(|l| (l.producing.len(), l.enforcing.len()))
            .collect()
    };
    assert_eq!(totals(&cached), totals(&free), "gate totals");
    assert_eq!(cached.layers[0].cached.len(), 1);
    assert!(free.layers.iter().all(|l| l.cached.is_empty()));
    assert_ne!(cached.layers, free.layers, "the gate encodings do differ");

    for seed in 0..4u64 {
        let base = toy_base(&toy_columns(0x5313_1000 + seed));
        let (cached_values, cached_proof, cached_result) = honest(&cached, &base);
        let (free_values, free_proof, free_result) = honest(&free, &base);
        for k in 0..cached.depth() {
            for (c, f) in cached_values.layers[k].iter().zip(&free_values.layers[k]) {
                let table =
                    |p: &poly::MultilinearPoly| (0..p.len()).map(|i| p.get(i)).collect::<Vec<_>>();
                assert_eq!(table(c), table(f), "forward values of layer {}", k + 1);
            }
        }
        assert_eq!(cached_proof, free_proof, "the proofs are identical");
        assert_eq!(cached_result, free_result, "and so are the base claims");
    }
}

/// The toy with `ab` computed through a degree-2 cached entry: `C{0}[1] = a·b`,
/// `ab = 1·C{0}[1] + 0`. Legal, and not inlinable. A prover that tabulated
/// `a·b` per row and bound the table would fail the final check here — the
/// multilinear extension of `a·b` is not `a·b` of the extensions — while
/// passing on the toy, whose cached entry is linear.
#[test]
fn a_degree_two_cached_entry_proves_and_verifies() {
    let mut artifact = toy();
    let (a, b) = (PolyAddress::Witness(0), PolyAddress::Witness(1));
    let list = &mut artifact.layers[0];
    list.cached.push(CachedEntry {
        name: "ab_cached".into(),
        address: PolyAddress::Cached {
            layer: 0,
            offset: 1,
        },
        gate: GateDef::Product {
            coeff: Coeff::Literal(Fr::ONE),
            left: a,
            right: b,
        },
    });
    list.producing[0].gate = GateDef::Linear {
        terms: vec![(
            Coeff::Literal(Fr::ONE),
            PolyAddress::Cached {
                layer: 0,
                offset: 1,
            },
        )],
        constant: Coeff::Literal(Fr::ZERO),
    };
    artifact
        .validate()
        .expect("a degree-2 cached entry inside a linear gate is legal");
    assert!(matches!(
        artifact.inline_cached(),
        Err(ConstraintError::NotInlinable { .. })
    ));

    let base = toy_base(&toy_columns(0x5313_1100));
    let (_, proof, result) = honest(&artifact, &base);
    let claims = result.expect("an honest proof verifies");
    discharge(&base, &claims).expect("its base claims discharge");
    let (_, toy_proof, _) = honest(&toy(), &base);
    assert_eq!(proof, toy_proof, "the same circuit, so the same proof");
}
