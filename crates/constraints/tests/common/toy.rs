//! The toy circuit, written directly as a `CircuitArtifact`, and its cache-free
//! compilation. Test-only: `crates/gkr`'s and `crates/checker`'s suites include
//! this file by `#[path]`, so the toy has this one definition. The independent
//! description it is held to is `crates/checker/tests/cross_check.rs`.
//!
//! ```text
//! base      M[0] m   W[0] a   W[1] b   W[2] c   W[3] e   S[0] s   V[row]      16 rows
//! list 0    C{0}[0] shifted_a = γ·a + row                 (cached)
//!           L{1}[0] ab          = a·b
//!           L{1}[1] fingerprint = shifted_a·c
//!           L{1}[2] masked_m    = m·s + (1 − s)
//!           0 = e·s − a·s                                  (enforcing, Quadratic)
//! list 1    L{2}[0] abm          = ab·masked_m
//!           L{2}[1] fingerprint3 = fingerprint + 3
//! list 2    L{3}[0] abm_product          = abm(·,0)·abm(·,1)                    (halving)
//!           L{3}[1] fingerprint3_product = fingerprint3(·,0)·fingerprint3(·,1)  (halving)
//! list 3    L{4}[0] abm_product_2, L{4}[1] fingerprint3_product_2: list 2's two
//!           trees halved again                                        (halving)
//! list 4    L{5}[0] abm_product_3, L{5}[1] fingerprint3_product_3     (halving)
//! list 5    L{6}[0] abm_root          = Π abm                         (halving)
//!           L{6}[1] fingerprint3_root = Π fingerprint3                (halving)
//! outputs   L{6}[1], L{6}[0]: the top, of no variables
//! ```

use constants::challenge_slot;
use constraints::{
    CachedEntry, CircuitArtifact, Coeff, EnforcingEntry, GateDef, LayerSpec, Padding, PolyAddress,
    ProducingEntry, Relation, ScratchSlot, VirtualKind, COEFFICIENT_ENCODING_CANONICAL_LE,
    FORMAT_VERSION,
};
use field_a64_c5::Fp;

/// The toy's cache-free compilation.
pub fn toy_cache_free() -> CircuitArtifact {
    toy()
        .inline_cached()
        .unwrap_or_else(|e| panic!("the toy circuit does not compile cache-free: {e}"))
}

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fp::from_u64(v))
}

fn neg(v: u64) -> Coeff {
    Coeff::Literal(-Fp::from_u64(v))
}

fn inner(layer: u32, offset: u32) -> PolyAddress {
    PolyAddress::Inner { layer, offset }
}

/// `e·s − a·s`, the same polynomial as `(e − a)·s`, written as a `Quadratic`
/// so the toy emits every shape. The flat list and the gate list spell it
/// alike.
fn gated_equality(a: PolyAddress, e: PolyAddress, s: PolyAddress) -> GateDef {
    GateDef::Quadratic {
        constant: lit(0),
        linear: vec![],
        products: vec![(lit(1), e, s), (neg(1), a, s)],
    }
}

fn names(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

/// The toy, cached.
pub fn toy() -> CircuitArtifact {
    let m = PolyAddress::Memory(0);
    let (a, b, c, e) = (
        PolyAddress::Witness(0),
        PolyAddress::Witness(1),
        PolyAddress::Witness(2),
        PolyAddress::Witness(3),
    );
    let s = PolyAddress::Setup(0);
    let row = PolyAddress::Virtual(VirtualKind::RowIndex);
    let gamma = Coeff::Challenge(challenge_slot::TOY);
    let scratch = PolyAddress::Scratch;

    // The flat list, over base and scratch addresses. Its index is what a gate
    // names in `relation`.
    let mut relations = vec![
        Relation {
            name: "define_ab".into(),
            output: Some(0),
            gate: GateDef::Product {
                coeff: lit(1),
                left: a,
                right: b,
            },
        },
        Relation {
            name: "define_fingerprint".into(),
            output: Some(1),
            gate: GateDef::AffineProduct {
                left: vec![(gamma, a), (lit(1), row)],
                left_constant: lit(0),
                right: vec![(lit(1), c)],
                right_constant: lit(0),
            },
        },
        Relation {
            name: "define_masked_m".into(),
            output: Some(2),
            gate: GateDef::MaskIntoIdentity { input: m, mask: s },
        },
        Relation {
            name: "gated_equality".into(),
            output: None,
            gate: gated_equality(a, e, s),
        },
        Relation {
            name: "define_abm".into(),
            output: Some(3),
            gate: GateDef::Product {
                coeff: lit(1),
                left: scratch(0),
                right: scratch(2),
            },
        },
        Relation {
            name: "define_fingerprint3".into(),
            output: Some(4),
            gate: GateDef::Linear {
                terms: vec![(lit(1), scratch(1))],
                constant: lit(3),
            },
        },
        Relation {
            name: "define_abm_product".into(),
            output: Some(5),
            gate: GateDef::TreeProduct { input: scratch(3) },
        },
        Relation {
            name: "define_fingerprint3_product".into(),
            output: Some(6),
            gate: GateDef::TreeProduct { input: scratch(4) },
        },
    ];

    let mut layers = vec![
        LayerSpec {
            halving: false,
            num_vars: 4,
            width: 3,
            cached: vec![CachedEntry {
                name: "shifted_a".into(),
                address: PolyAddress::Cached {
                    layer: 0,
                    offset: 0,
                },
                gate: GateDef::Linear {
                    terms: vec![(gamma, a), (lit(1), row)],
                    constant: lit(0),
                },
            }],
            producing: vec![
                ProducingEntry {
                    relation: 0,
                    output: inner(1, 0),
                    gate: GateDef::Product {
                        coeff: lit(1),
                        left: a,
                        right: b,
                    },
                },
                ProducingEntry {
                    relation: 1,
                    output: inner(1, 1),
                    gate: GateDef::Product {
                        coeff: lit(1),
                        left: PolyAddress::Cached {
                            layer: 0,
                            offset: 0,
                        },
                        right: c,
                    },
                },
                ProducingEntry {
                    relation: 2,
                    output: inner(1, 2),
                    gate: GateDef::MaskIntoIdentity { input: m, mask: s },
                },
            ],
            enforcing: vec![EnforcingEntry {
                relation: 3,
                gate: gated_equality(a, e, s),
            }],
        },
        LayerSpec {
            halving: false,
            num_vars: 4,
            width: 2,
            cached: vec![],
            producing: vec![
                ProducingEntry {
                    relation: 4,
                    output: inner(2, 0),
                    gate: GateDef::Product {
                        coeff: lit(1),
                        left: inner(1, 0),
                        right: inner(1, 2),
                    },
                },
                ProducingEntry {
                    relation: 5,
                    output: inner(2, 1),
                    gate: GateDef::Linear {
                        terms: vec![(lit(1), inner(1, 1))],
                        constant: lit(3),
                    },
                },
            ],
            enforcing: vec![],
        },
        LayerSpec {
            halving: true,
            num_vars: 3,
            width: 2,
            cached: vec![],
            producing: vec![
                ProducingEntry {
                    relation: 6,
                    output: inner(3, 0),
                    gate: GateDef::TreeProduct { input: inner(2, 0) },
                },
                ProducingEntry {
                    relation: 7,
                    output: inner(3, 1),
                    gate: GateDef::TreeProduct { input: inner(2, 1) },
                },
            ],
            enforcing: vec![],
        },
    ];

    let slot = |name: &str, layer: u32, offset: u32| ScratchSlot {
        name: name.into(),
        address: inner(layer, offset),
    };
    let mut slots = vec![
        slot("ab", 1, 0),
        slot("fingerprint", 1, 1),
        slot("masked_m", 1, 2),
        slot("abm", 2, 0),
        slot("fingerprint3", 2, 1),
        slot("abm_product", 3, 0),
        slot("fingerprint3_product", 3, 1),
    ];

    // Lists 3, 4 and 5 halve both trees again, down to the roots at layer 6:
    // list `k`'s entry `j` halves `L{k}[j]`, its relation the tree of that
    // column's scratch slot, `scratch[2k − 1 + j]`.
    for (k, pair) in (3u32..).zip([
        ["abm_product_2", "fingerprint3_product_2"],
        ["abm_product_3", "fingerprint3_product_3"],
        ["abm_root", "fingerprint3_root"],
    ]) {
        let mut producing = Vec::new();
        for (j, name) in (0u32..).zip(pair) {
            producing.push(ProducingEntry {
                relation: relations.len() as u32,
                output: inner(k + 1, j),
                gate: GateDef::TreeProduct { input: inner(k, j) },
            });
            relations.push(Relation {
                name: format!("define_{name}"),
                output: Some(slots.len() as u32),
                gate: GateDef::TreeProduct {
                    input: scratch(2 * k - 1 + j),
                },
            });
            slots.push(slot(name, k + 1, j));
        }
        layers.push(LayerSpec {
            halving: true,
            num_vars: 5 - k,
            width: 2,
            cached: vec![],
            producing,
            enforcing: vec![],
        });
    }

    CircuitArtifact {
        format_version: FORMAT_VERSION,
        coefficient_encoding: COEFFICIENT_ENCODING_CANONICAL_LE,
        trace_vars: 4,
        memory: names(&["m"]),
        witness: names(&["a", "b", "c", "e"]),
        setup: names(&["s"]),
        virtuals: vec![(VirtualKind::RowIndex, "row".into())],
        layers,
        relations,
        lookups: vec![],
        scratch: slots,
        outputs: vec![inner(6, 1), inner(6, 0)],
        // The inactive row is all zero: with s = 0, masked_m is the product
        // tree's identity and the gated equality holds whatever e and a are.
        padding: Padding {
            row: vec![Fp::ZERO; 6],
            zero_row_valid: true,
        },
    }
}
