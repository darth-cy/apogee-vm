//! The `gkr` group: S13's toy circuit, written directly as a
//! `CircuitArtifact`, and its cache-free compilation.
//!
//! This function is the toy's only definition. The prover and verifier never
//! see it: they read the two committed files. Neither file is an oracle — both
//! are this code's output — so what they pin is the artifact's bytes, and CI
//! regenerates and diffs them. The independent description the artifact is
//! held to is `crates/checker/tests/cross_check.rs`, written separately.
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
//! list 2    L{3}[0] abm_product          = Π abm           (halving)
//!           L{3}[1] fingerprint3_product = Π fingerprint3  (halving)
//! outputs   L{3}[1], L{3}[0]
//! ```

use constants::challenge_slot;
use constraints::{
    CachedEntry, CircuitArtifact, Coeff, EnforcingEntry, GateDef, LayerSpec, Padding, PolyAddress,
    ProducingEntry, Relation, ScratchSlot, VirtualKind, COEFFICIENT_ENCODING_CANONICAL_LE,
    FORMAT_VERSION,
};
use field::Fr;

use crate::write_bytes;

const CACHED: &str = "crates/constraints/tests/vectors/toy_cached.bin";
const CACHE_FREE: &str = "crates/constraints/tests/vectors/toy_cache_free.bin";

pub fn generate() {
    let cached = toy();
    if let Err(e) = cached.validate() {
        panic!("the toy circuit is not a circuit: {e}");
    }
    let cache_free = cached
        .inline_cached()
        .unwrap_or_else(|e| panic!("the toy circuit does not compile cache-free: {e}"));
    write_bytes(CACHED, &cached.to_bytes());
    write_bytes(CACHE_FREE, &cache_free.to_bytes());
}

fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

fn neg(v: u64) -> Coeff {
    Coeff::Literal(-Fr::from_u64(v))
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

fn toy() -> CircuitArtifact {
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
    let relations = vec![
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

    let layers = vec![
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
        scratch: vec![
            slot("ab", 1, 0),
            slot("fingerprint", 1, 1),
            slot("masked_m", 1, 2),
            slot("abm", 2, 0),
            slot("fingerprint3", 2, 1),
            slot("abm_product", 3, 0),
            slot("fingerprint3_product", 3, 1),
        ],
        outputs: vec![inner(3, 1), inner(3, 0)],
        // The inactive row is all zero: with s = 0, masked_m is the product
        // tree's identity and the gated equality holds whatever e and a are.
        padding: Padding {
            row: vec![Fr::ZERO; 6],
            zero_row_valid: true,
        },
    }
}
