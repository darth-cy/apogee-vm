//! The `Quadratic` shape end to end: the owner's example of a relation no
//! other single shape expresses, enforced, beside a producing `Quadratic` whose
//! column a later gate list reads.
//!
//! ```text
//! base      W[0] a   W[1] b   W[2] c   W[3] d   W[4] e   W[5] f          4 rows
//! list 0    L{1}[0] mixed = 7 + γ·a + 3·b·c                  (Quadratic)
//!           0 = a·b + c·d − e·f                              (enforcing, Quadratic)
//! list 1    L{2}[0] squared = mixed·mixed
//! outputs   L{2}[0]
//! ```
//!
//! `a·b + c·d − e·f` fits no other shape: `Linear` is degree 1, `Product` one
//! monomial, `MaskIntoIdentity` and `TreeProduct` fixed forms, and an
//! `AffineProduct` is a product of two affine forms, whose quadratic part has
//! rank at most 2 as a symmetric bilinear form — this one has rank 6. It would
//! otherwise take intermediate columns and a layer of its own.

mod common;

use common::{bind, circuit, discharge, fr_base, honest, output_claims, run};
use constants::challenge_slot::TOY;
use constraints::{
    CircuitArtifact, Coeff, EnforcingEntry, GateDef, LayerSpec, PolyAddress, ProducingEntry,
    Relation,
};
use field::Fr;
use gkr::{forward, self_check, GkrError};
use test_support::Rng;

const ROWS: usize = 4;

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn w(i: u32) -> PolyAddress {
    PolyAddress::Witness(i)
}

/// `7 + γ·a + 3·b·c` over `a`, `b`, `c`.
fn mixed(a: PolyAddress, b: PolyAddress, c: PolyAddress) -> GateDef {
    GateDef::Quadratic {
        constant: lit(7),
        linear: vec![(Coeff::Challenge(TOY), a)],
        products: vec![(lit(3), b, c)],
    }
}

/// `a·b + c·d − e·f` over the base.
fn balance() -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear: vec![],
        products: vec![
            (lit(1), w(0), w(1)),
            (lit(1), w(2), w(3)),
            (Coeff::Literal(-Fr::ONE), w(4), w(5)),
        ],
    }
}

fn balance_circuit() -> CircuitArtifact {
    let (l1, l2) = (
        PolyAddress::Inner {
            layer: 1,
            offset: 0,
        },
        PolyAddress::Inner {
            layer: 2,
            offset: 0,
        },
    );
    let square = |x: PolyAddress| GateDef::Product {
        coeff: lit(1),
        left: x,
        right: x,
    };
    let relation = |name: &str, output: Option<u32>, gate: GateDef| Relation {
        name: name.into(),
        output,
        gate,
    };
    circuit(
        2,
        &["a", "b", "c", "d", "e", "f"],
        vec![
            LayerSpec {
                halving: false,
                num_vars: 2,
                width: 1,
                cached: vec![],
                producing: vec![ProducingEntry {
                    relation: 0,
                    output: l1,
                    gate: mixed(w(0), w(1), w(2)),
                }],
                enforcing: vec![EnforcingEntry {
                    relation: 1,
                    gate: balance(),
                }],
            },
            LayerSpec {
                halving: false,
                num_vars: 2,
                width: 1,
                cached: vec![],
                producing: vec![ProducingEntry {
                    relation: 2,
                    output: l2,
                    gate: square(l1),
                }],
                enforcing: vec![],
            },
        ],
        vec![
            relation("define_mixed", Some(0), mixed(w(0), w(1), w(2))),
            relation("ab_plus_cd_is_ef", None, balance()),
            relation("define_squared", Some(1), square(PolyAddress::Scratch(0))),
        ],
        &[("mixed", l1), ("squared", l2)],
        vec![l2],
    )
}

/// `a, b, c, d` random, `e` random and nonzero, `f = (a·b + c·d)/e`: the
/// columns in layout order.
fn satisfying(seed: u64) -> Vec<Vec<Fr>> {
    let mut rng = Rng::new(seed);
    let mut draw = || -> Vec<Fr> {
        (0..ROWS)
            .map(|_| Fr::from_u64(rng.next_u64() >> 1))
            .collect()
    };
    let (a, b, c, d) = (draw(), draw(), draw(), draw());
    let e: Vec<Fr> = draw().iter().map(|x| *x + Fr::ONE).collect();
    let f = (0..ROWS)
        .map(|y| (a[y] * b[y] + c[y] * d[y]) * e[y].inverse().expect("e is nonzero"))
        .collect();
    vec![a, b, c, d, e, f]
}

/// Honest: the forward pass writes `7 + γ·a + 3·b·c` into `mixed` — checked
/// against arithmetic written here, not the kernel — the self-check passes,
/// and the proof, whose transition 0 carries `mixed`'s claim down from list 1,
/// verifies with every base claim discharged against its column.
///
/// Kills a kernel that reads a `Quadratic`'s products from the start of its
/// values rather than after its linear operands: every pass would share the
/// mistake and the proof would still verify, but `mixed` would be
/// `7 + γ·a + 3·a·b`.
#[test]
fn an_honest_quadratic_circuit_proves_and_verifies() {
    let artifact = balance_circuit();
    for seed in 0..4u64 {
        let columns = satisfying(0x5313_0a00 + seed);
        let base = fr_base(&artifact, columns.clone());
        let (_, challenges) = bind(&artifact, &base);
        let gamma = challenges.get(TOY).expect("bind sets the toy's slot");
        let values = forward(&artifact, &base, &challenges);
        let [a, b, c, ..] = &columns[..] else {
            unreachable!("six columns")
        };
        for y in 0..ROWS {
            assert_eq!(
                values.layers[0][0].get(y),
                Fr::from_u64(7) + gamma * a[y] + Fr::from_u64(3) * b[y] * c[y],
                "mixed at row {y}"
            );
        }
        self_check(&artifact, &values, &challenges).expect("the base satisfies every gate");

        let (_, proof, result) = honest(&artifact, &base);
        assert_eq!(
            proof.layers.len(),
            2,
            "mixed's claim descends through list 1"
        );
        let claims = result.expect("an honest proof verifies");
        assert_eq!(claims.len(), 6);
        discharge(&base, &claims).expect("every base claim is the column's evaluation");
    }
}

/// Tampered: one cell of `f` moved by one, so `a·b + c·d − e·f` is `−e` on that
/// row and zero elsewhere. The self-check names the relation at that row, and a
/// proof over those forward values — the digest bound to the tampered base — is
/// rejected at transition 0, where the enforcing gate is.
///
/// Kills a kernel that returns a `Quadratic`'s constant and linear part alone:
/// the relation would then be identically zero, the self-check would pass and
/// the proof would verify.
#[test]
fn a_broken_quadratic_relation_is_named_and_rejected() {
    let artifact = balance_circuit();
    let mut columns = satisfying(0x5313_0b10);
    columns[5][1] += Fr::ONE;
    let base = fr_base(&artifact, columns);
    let (_, challenges) = bind(&artifact, &base);
    let values = forward(&artifact, &base, &challenges);
    let broken = self_check(&artifact, &values, &challenges).expect_err("row 1 is broken");
    assert_eq!(
        (broken.layer, broken.row, broken.relation.as_str()),
        (0, 1, "ab_plus_cd_is_ef")
    );
    let (_, result) = run(
        &artifact,
        &base,
        &values,
        &output_claims(&artifact, &values),
    );
    assert_eq!(result, Err(GkrError::LayerInconsistency { layer: 0 }));
}
