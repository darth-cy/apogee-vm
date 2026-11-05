//! The toy circuits, and the short constructors the suites build mutations
//! from. Test-only; never compiled into the library.
//!
//! The toy's structure is the doc comment at the top of `toy.rs`, reproduced
//! here because every mutation below is written against it:
//!
//! ```text
//! base      M[0] m   W[0] a   W[1] b   W[2] c   W[3] e   S[0] s   V[row]      16 rows
//! list 0    C{0}[0] shifted_a = γ·a + row                 (cached)
//!           L{1}[0] ab          = a·b                      relation 0, scratch[0]
//!           L{1}[1] fingerprint = shifted_a·c              relation 1, scratch[1]
//!           L{1}[2] masked_m    = m·s + (1 − s)            relation 2, scratch[2]
//!           0 = e·s − a·s                                  relation 3 (enforcing, Quadratic)
//! list 1    L{2}[0] abm          = ab·masked_m             relation 4, scratch[3]
//!           L{2}[1] fingerprint3 = fingerprint + 3         relation 5, scratch[4]
//! list 2    L{3}[0] abm_product            = abm(·,0)·abm(·,1)   relation 6, scratch[5] (halving)
//!           L{3}[1] fingerprint3_product   likewise              relation 7, scratch[6] (halving)
//! list 3    L{4}[0] abm_product_2          halving L{3}[0]       relation 8, scratch[7]
//!           L{4}[1] fingerprint3_product_2 halving L{3}[1]       relation 9, scratch[8]
//! list 4    L{5}[0] abm_product_3                                relation 10, scratch[9]
//!           L{5}[1] fingerprint3_product_3                       relation 11, scratch[10]
//! list 5    L{6}[0] abm_root               = Π abm               relation 12, scratch[11]
//!           L{6}[1] fingerprint3_root      = Π fingerprint3      relation 13, scratch[12]
//! outputs   L{6}[1], L{6}[0]: the top, of no variables
//! ```
#![allow(dead_code)]

use constants::challenge_slot;
use constraints::{Coeff, PolyAddress, VirtualKind};
use field::Fr;

mod lookup_toy;
mod toy;

#[allow(unused_imports)]
pub use lookup_toy::lookup_toy;
#[allow(unused_imports)]
pub use toy::{toy, toy_cache_free};

pub fn toy_cached_bytes() -> Vec<u8> {
    toy().to_bytes()
}

pub fn toy_cache_free_bytes() -> Vec<u8> {
    toy_cache_free().to_bytes()
}

// ---------------------------------------------------------------------------
// Constructors, in the toy's own notation
// ---------------------------------------------------------------------------

pub const M: PolyAddress = PolyAddress::Memory(0);
pub const A: PolyAddress = PolyAddress::Witness(0);
pub const B: PolyAddress = PolyAddress::Witness(1);
pub const C: PolyAddress = PolyAddress::Witness(2);
pub const E: PolyAddress = PolyAddress::Witness(3);
pub const S: PolyAddress = PolyAddress::Setup(0);
pub const ROW: PolyAddress = PolyAddress::Virtual(VirtualKind::RowIndex);

/// The toy's one challenge, `γ`.
pub const GAMMA: Coeff = Coeff::Challenge(challenge_slot::TOY);

pub fn lit(v: u64) -> Coeff {
    Coeff::Literal(Fr::from_u64(v))
}

pub fn neg(v: u64) -> Coeff {
    Coeff::Literal(-Fr::from_u64(v))
}

/// `L{layer}[offset]`.
pub fn inner(layer: u32, offset: u32) -> PolyAddress {
    PolyAddress::Inner { layer, offset }
}

/// `C{layer}[offset]`.
pub fn cached(layer: u32, offset: u32) -> PolyAddress {
    PolyAddress::Cached { layer, offset }
}

/// `scratch[i]`.
pub fn scratch(i: u32) -> PolyAddress {
    PolyAddress::Scratch(i)
}
