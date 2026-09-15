//! The two committed toy artifacts, pinned by digest, and the small editing
//! helpers the suites share. Test-only.
//!
//! The toy, as `tools/kat-gen/src/gkr.rs`'s header describes it: base columns
//! `M[0] m, W[0] a, W[1] b, W[2] c, W[3] e, S[0] s` and `V[row]` over 16 rows;
//! list 0 writes `ab = a·b`, `fingerprint = (γ·a + row)·c` (the parenthesis a
//! cached entry in one compilation, inline in the other) and
//! `masked_m = m·s + (1 − s)`, and enforces `0 = e·s − a·s` (a `Quadratic`); list 1 writes
//! `abm = ab·masked_m` and `fingerprint3 = fingerprint + 3`; list 2 halves
//! both into their products; the outputs are `L{3}[1]` then `L{3}[0]`.

#![allow(dead_code)]

use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};
use field::Fr;
use test_support::{sha256, to_hex, Rng};

pub const CACHED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/toy_cached.bin"
);
pub const CACHE_FREE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../constraints/tests/vectors/toy_cache_free.bin"
);
const CACHED_SHA256: &str = "ee27e1192c4bcf9afa003509f6c06fead29628b02a4c17f86e381bf5609f1c70";
const CACHE_FREE_SHA256: &str = "5318afeb5b5ba5d09871358c89db36a0db12680fa9559a70c67c50b41181251d";

/// The committed layout's positions: `m, a, b, c, e, s`.
pub const M: usize = 0;
pub const A: usize = 1;
pub const B: usize = 2;
pub const C: usize = 3;
pub const E: usize = 4;
pub const S: usize = 5;

pub const M0: PolyAddress = PolyAddress::Memory(0);
pub const W0: PolyAddress = PolyAddress::Witness(0);
pub const W1: PolyAddress = PolyAddress::Witness(1);
pub const W2: PolyAddress = PolyAddress::Witness(2);
pub const W3: PolyAddress = PolyAddress::Witness(3);
pub const V: PolyAddress = PolyAddress::Virtual(VirtualKind::RowIndex);

pub fn inner(layer: u32, offset: u32) -> PolyAddress {
    PolyAddress::Inner { layer, offset }
}

pub fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

/// Read a fixture, check its pin, decode it.
pub fn load(path: &str) -> CircuitArtifact {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    let pin = if path == CACHED {
        CACHED_SHA256
    } else {
        CACHE_FREE_SHA256
    };
    assert_eq!(
        to_hex(&sha256(&bytes)),
        pin,
        "{path} is not the pinned fixture"
    );
    CircuitArtifact::from_bytes(&bytes).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Both compilations, cached first, with a label for messages.
pub fn toys() -> [(&'static str, CircuitArtifact); 2] {
    [("cached", load(CACHED)), ("cache-free", load(CACHE_FREE))]
}

pub fn relation(a: &CircuitArtifact, name: &str) -> usize {
    a.relations
        .iter()
        .position(|r| r.name == name)
        .unwrap_or_else(|| panic!("the toy has no relation {name}"))
}

pub fn slot(a: &CircuitArtifact, name: &str) -> usize {
    a.scratch
        .iter()
        .position(|s| s.name == name)
        .unwrap_or_else(|| panic!("the toy has no scratch slot {name}"))
}

/// A pseudo-random field element below `2^252`.
pub fn fr(rng: &mut Rng) -> Fr {
    let mut b = rng.next_le32();
    b[31] &= 0x0f;
    Fr::from_bytes(&b).expect("below 2^252")
}

/// A `Linear` gate's terms and constant.
pub fn linear(gate: &mut GateDef) -> (&mut Vec<(Coeff, PolyAddress)>, &mut Coeff) {
    match gate {
        GateDef::Linear { terms, constant } => (terms, constant),
        other => panic!("not a Linear gate: {other:?}"),
    }
}

/// Every term of `gate` reading `operand` gets coefficient `c`; the count. A
/// `Quadratic` product is such a term when either of its factors is `operand`.
pub fn set_coefficient(gate: &mut GateDef, operand: PolyAddress, c: Coeff) -> usize {
    let terms: Vec<&mut (Coeff, PolyAddress)> = match gate {
        GateDef::Linear { terms, .. } => terms.iter_mut().collect(),
        GateDef::AffineProduct { left, right, .. } => left.iter_mut().chain(right).collect(),
        GateDef::Quadratic {
            linear, products, ..
        } => {
            let mut changed = 0;
            for (b, y, z) in products.iter_mut() {
                if *y == operand || *z == operand {
                    *b = c;
                    changed += 1;
                }
            }
            linear.iter_mut().for_each(|term| {
                if term.1 == operand {
                    term.0 = c;
                    changed += 1;
                }
            });
            return changed;
        }
        _ => Vec::new(),
    };
    let mut changed = 0;
    for term in terms {
        if term.1 == operand {
            term.0 = c;
            changed += 1;
        }
    }
    changed
}

/// Every read of `from` in `gate` becomes a read of `to`; the count.
pub fn set_operand(gate: &mut GateDef, from: PolyAddress, to: PolyAddress) -> usize {
    let operands: Vec<&mut PolyAddress> = match gate {
        GateDef::Linear { terms, .. } => terms.iter_mut().map(|t| &mut t.1).collect(),
        GateDef::Product { left, right, .. } => vec![left, right],
        GateDef::MaskIntoIdentity { input, mask } => vec![input, mask],
        GateDef::AffineProduct { left, right, .. } => {
            left.iter_mut().chain(right).map(|t| &mut t.1).collect()
        }
        GateDef::TreeProduct { input } => vec![input],
        GateDef::Quadratic {
            linear, products, ..
        } => {
            let mut ops: Vec<&mut PolyAddress> = linear.iter_mut().map(|t| &mut t.1).collect();
            for (_, y, z) in products.iter_mut() {
                ops.push(y);
                ops.push(z);
            }
            ops
        }
    };
    let mut changed = 0;
    for op in operands {
        if *op == from {
            *op = to;
            changed += 1;
        }
    }
    changed
}
