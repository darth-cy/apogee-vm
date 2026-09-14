//! The two committed toy artifacts, pinned by SHA-256 before they are decoded,
//! and the short constructors the suites build mutations from. Hex and SHA-256
//! are shared with the other suites and live in `tools/test-support`.
//! Test-only; never compiled into the library.
//!
//! The toy's structure is the doc comment at the top of
//! `tools/kat-gen/src/gkr.rs`, reproduced here because every mutation below is
//! written against it:
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
//! list 2    L{3}[0] abm_product          = Π abm           relation 6, scratch[5] (halving)
//!           L{3}[1] fingerprint3_product = Π fingerprint3  relation 7, scratch[6] (halving)
//! outputs   L{3}[1], L{3}[0]
//! ```
#![allow(dead_code)]

use constants::challenge_slot;
use constraints::{CircuitArtifact, Coeff, PolyAddress, VirtualKind};
use field::Fr;
use test_support::{sha256, to_hex};

pub const TOY_CACHED_SHA256: &str =
    "9ad63a54eef4fbd9c808f6db52ad27038202200a5e56be9576c2c52e4cd9aa35";
pub const TOY_CACHE_FREE_SHA256: &str =
    "8025412caae28c09ca9dcff6bd242961097bd59446c539d7f173dcb01b45ff91";

/// A committed artifact's bytes, pinned before anything reads them.
pub fn fixture_bytes(name: &str, digest: &str) -> Vec<u8> {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("reading {path}: {e}"));
    assert_eq!(
        to_hex(&sha256(&bytes)),
        digest,
        "{name} changed. Regenerate it with `cargo run -p kat-gen -- gkr`, review the \
         diff, then update the pinned digest deliberately."
    );
    bytes
}

pub fn toy_cached_bytes() -> Vec<u8> {
    fixture_bytes("toy_cached.bin", TOY_CACHED_SHA256)
}

pub fn toy_cache_free_bytes() -> Vec<u8> {
    fixture_bytes("toy_cache_free.bin", TOY_CACHE_FREE_SHA256)
}

fn decode(name: &str, bytes: &[u8]) -> CircuitArtifact {
    CircuitArtifact::from_bytes(bytes).unwrap_or_else(|e| panic!("decoding {name}: {e}"))
}

/// The cached toy, decoded. Its fields are public, which is what lets a test
/// break exactly one law.
pub fn toy() -> CircuitArtifact {
    decode("toy_cached.bin", &toy_cached_bytes())
}

/// The toy's cache-free compilation, decoded.
pub fn toy_cache_free() -> CircuitArtifact {
    decode("toy_cache_free.bin", &toy_cache_free_bytes())
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
