//! `VirtualKind::RamLive`, `V[ram_live]`, `docs/spec/gkr.md` §2.1: its closed
//! form is the multilinear extension of its table, and a circuit reading it
//! proves, verifies, and is rejected when broken on the last row below the
//! boundary.
//!
//! ```text
//! base        W[0] a                                              2^16 rows
//! list 0      L{1}[0] live_a = a·ram_live + 1 − ram_live          (MaskIntoIdentity)
//!             0 = a − a·ram_live                                  (enforcing, Quadratic)
//! lists 1–16  L{k+1}[0] = L{k}[0](·,0)·L{k}[0](·,1)              (halving)
//! outputs     L{17}[0] = Π_{y ≥ 2^14} a_y
//! ```
//!
//! 16 variables, so the closed form has two factors, `(1 − y_14)(1 − y_15)`; at
//! 15 it is `y_14` alone, which a wrong closed form could agree with.

mod common;

use common::{discharge, fr_base, honest};
use constants::memory::RAM_LIVE_BIT;
use constraints::{
    CircuitArtifact, Coeff, EnforcingEntry, GateDef, LayerSpec, Padding, PolyAddress,
    ProducingEntry, Relation, ScratchSlot, VirtualKind, COEFFICIENT_ENCODING_CANONICAL_LE,
    FORMAT_VERSION,
};
use field::Fr;
use gkr::{
    self_check, virtual_at_point, virtual_at_row, ExternalChallenges, GkrError, SelfCheckError,
};
use poly::{MultilinearPoly, PolyBacking};
use test_support::Rng;

const LIVE: VirtualKind = VirtualKind::RamLive;

/// A pseudo-random field element below `2^252`.
fn fr(rng: &mut Rng) -> Fr {
    let mut b = rng.next_le32();
    b[31] &= 0x0f;
    Fr::from_bytes(&b).expect("below 2^252")
}

/// For `n` in {14, 15, 16, 18}: the table written from its definition — 1 at
/// rows `y >= 2^14`, else 0 — is `virtual_at_row` on every row and
/// `virtual_at_point` at every cube point, and `virtual_at_point` equals
/// `MultilinearPoly::evaluate` of that table at eight pseudo-random points. At
/// `n = 14` the table is all zero, the closed form's empty product.
#[test]
fn the_closed_form_is_the_extension_of_the_table() {
    let mut rng = Rng::new(0x5714_0001);
    for n in [14usize, 15, 16, 18] {
        let table: Vec<Fr> = (0..1usize << n)
            .map(|y| {
                if y >= 1 << RAM_LIVE_BIT {
                    Fr::ONE
                } else {
                    Fr::ZERO
                }
            })
            .collect();
        let mut bits = vec![Fr::ZERO; n];
        for (y, value) in table.iter().enumerate() {
            for (j, bit) in bits.iter_mut().enumerate() {
                *bit = Fr::from_u64(((y >> j) & 1) as u64);
            }
            assert_eq!(virtual_at_row(LIVE, y), *value, "n = {n}, row {y}");
            assert_eq!(
                virtual_at_point(LIVE, &bits),
                *value,
                "n = {n}, cube point {y}"
            );
        }
        let extension = MultilinearPoly::new(PolyBacking::Fr(table));
        for trial in 0..8 {
            let point: Vec<Fr> = (0..n).map(|_| fr(&mut rng)).collect();
            assert_eq!(
                virtual_at_point(LIVE, &point),
                extension.evaluate(&point),
                "n = {n}, point {trial}"
            );
        }
    }
}

const VARS: u32 = 16;

fn inner(layer: u32, offset: u32) -> PolyAddress {
    PolyAddress::Inner { layer, offset }
}

/// The header's circuit, validated.
fn ram_live_circuit() -> CircuitArtifact {
    let a = PolyAddress::Witness(0);
    let live = PolyAddress::Virtual(LIVE);
    let leaf = GateDef::MaskIntoIdentity {
        input: a,
        mask: live,
    };
    let below_ram = GateDef::Quadratic {
        constant: Coeff::Literal(Fr::ZERO),
        linear: vec![(Coeff::Literal(Fr::ONE), a)],
        products: vec![(Coeff::Literal(Fr::MINUS_ONE), a, live)],
    };
    let mut layers = vec![LayerSpec {
        halving: false,
        num_vars: VARS,
        width: 1,
        cached: vec![],
        producing: vec![ProducingEntry {
            relation: 0,
            output: inner(1, 0),
            gate: leaf.clone(),
        }],
        enforcing: vec![EnforcingEntry {
            relation: 1,
            gate: below_ram.clone(),
        }],
    }];
    let mut relations = vec![
        Relation {
            name: "define_live_a".into(),
            output: Some(0),
            gate: leaf,
        },
        Relation {
            name: "a_is_zero_below_ram".into(),
            output: None,
            gate: below_ram,
        },
    ];
    let mut scratch = vec![ScratchSlot {
        name: "live_a".into(),
        address: inner(1, 0),
    }];
    for k in 1..=VARS {
        layers.push(LayerSpec {
            halving: true,
            num_vars: VARS - k,
            width: 1,
            cached: vec![],
            producing: vec![ProducingEntry {
                relation: k + 1,
                output: inner(k + 1, 0),
                gate: GateDef::TreeProduct { input: inner(k, 0) },
            }],
            enforcing: vec![],
        });
        relations.push(Relation {
            name: format!("define_product_{k}"),
            output: Some(k),
            gate: GateDef::TreeProduct {
                input: PolyAddress::Scratch(k - 1),
            },
        });
        scratch.push(ScratchSlot {
            name: format!("product_{k}"),
            address: inner(k + 1, 0),
        });
    }
    let artifact = CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars: VARS,
        memory: vec![],
        witness: vec!["a".into()],
        setup: vec![],
        virtuals: vec![(LIVE, "ram_live".into())],
        layers,
        relations,
        lookups: vec![],
        scratch,
        outputs: vec![inner(VARS + 1, 0)],
        padding: Padding {
            row: vec![Fr::ZERO],
            zero_row_valid: true,
        },
    };
    if let Err(e) = artifact.validate() {
        panic!("the ram_live circuit is not a circuit: {e}");
    }
    artifact
}

/// The honest base — `a` 0 on every row below `2^14`, nonzero from it, and 7
/// on row `2^14` itself — passes the self-check, proves, verifies and
/// discharges, and its root is `Π_{y ≥ 2^14} a_y`, computed here: every row
/// below the boundary contributes the identity. Then `a = 1` on row `2^14 − 1`
/// breaks the enforcing gate there, which the self-check names and `verify`
/// rejects at transition 0.
///
/// Kills a `virtual_at_row` off by one at the boundary — row `2^14` masked
/// breaks the enforcing gate on the honest base there, and row `2^14 − 1` live
/// takes its 0 into the root — and a `virtual_at_point` that disagrees with it,
/// on the cube or only off it: the prover's rounds, built from the closed form,
/// then stop matching the claims the forward pass's values make, and the honest
/// run does not verify.
#[test]
fn a_circuit_reading_ram_live_proves_and_rejects_a_violation_below_the_boundary() {
    let artifact = ram_live_circuit();
    let boundary = 1usize << RAM_LIVE_BIT;
    let mut rng = Rng::new(0x5714_0002);
    let mut a: Vec<Fr> = (0..1usize << VARS)
        .map(|y| {
            if y < boundary {
                Fr::ZERO
            } else {
                Fr::from_u64(rng.next_u64() | 1)
            }
        })
        .collect();
    a[boundary] = Fr::from_u64(7);
    // The circuit names no challenge slot.
    let none = ExternalChallenges::new();

    let base = fr_base(&artifact, vec![a.clone()]);
    let (values, _, result) = honest(&artifact, &base);
    assert_eq!(self_check(&artifact, &values, &none), Ok(()));
    let root = a[boundary..].iter().fold(Fr::ONE, |acc, v| acc * *v);
    assert_eq!(values.layers[VARS as usize][0].get(0), root, "the root");
    discharge(&base, &result.expect("the honest run verifies")).expect("and discharges");

    a[boundary - 1] = Fr::ONE;
    let base = fr_base(&artifact, vec![a]);
    let (values, _, result) = honest(&artifact, &base);
    assert_eq!(
        self_check(&artifact, &values, &none),
        Err(SelfCheckError {
            layer: 0,
            row: boundary - 1,
            relation: "a_is_zero_below_ram".into(),
        })
    );
    assert_eq!(result, Err(GkrError::LayerInconsistency { layer: 0 }));
}
