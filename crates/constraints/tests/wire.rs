//! Acceptance 10's round-trip half and must-be-exact 15: the artifact's
//! `postcard` wire form, `docs/spec/gkr.md` §4.1.
//!
//! `from_bytes` accepts exactly the bytes `to_bytes` writes and is total: it
//! returns an error, and never panics, whatever it is handed. Its errors come
//! from two places, and each refusal below is pinned to the one that should
//! catch it — postcard reporting a buffer that ends early, a hand-written
//! visitor refusing a shape (postcard reduces every such message to
//! "Serde Deserialization Error"), or the re-encode comparison refusing bytes
//! that decode but are not canonical.

mod common;

use common::{toy, toy_cache_free, toy_cache_free_bytes, toy_cached_bytes};
use constraints::{CircuitArtifact, Coeff, GateDef, PolyAddress, VirtualKind};
use field::Fr;
use serde::Serialize;

const ENDS_EARLY: &str = "malformed circuit artifact: Hit the end of buffer, expected more data";
const SHAPE_REFUSED: &str = "malformed circuit artifact: Serde Deserialization Error";
const NOT_CANONICAL: &str =
    "malformed circuit artifact: not the canonical encoding of what it decodes to";

fn encode<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    postcard::to_extend(value, Vec::new()).expect("encoding into a Vec cannot fail")
}

/// A coefficient as its three wire fields, so a test can write one no `Coeff`
/// value encodes to.
type RawCoeff = (u8, u32, [u8; 32]);
/// An address as its three wire fields.
type RawAddress = (u8, u32, u32);

fn raw_gate(tag: u8, split: u32, coeffs: &[RawCoeff], operands: &[RawAddress]) -> Vec<u8> {
    encode(&(tag, split, coeffs, operands))
}

const ZERO: [u8; 32] = [0; 32];

fn one() -> [u8; 32] {
    Fr::ONE.to_bytes()
}

/// A literal whose 32 bytes appear nowhere else in the toy, so its gate can be
/// found in the file by search.
fn marker() -> Fr {
    Fr::from_u64(0x0123_4567_89ab_cdef)
}

/// The toy's bytes with relation 5's gate replaced by `gate`, which may be any
/// byte string at all. The replacement is found by writing a marker gate into
/// relation 5 and locating its unique encoding, not by counting offsets.
fn with_gate_bytes(gate: &[u8]) -> Vec<u8> {
    let mut a = toy();
    let marker_gate = GateDef::Linear {
        terms: vec![],
        constant: Coeff::Literal(marker()),
    };
    a.relations[5].gate = marker_gate.clone();
    let bytes = a.to_bytes();
    let needle = encode(&marker_gate);
    let hits: Vec<usize> = bytes
        .windows(needle.len())
        .enumerate()
        .filter(|(_, w)| *w == needle.as_slice())
        .map(|(i, _)| i)
        .collect();
    assert_eq!(hits.len(), 1, "the marker gate must occur exactly once");
    let at = hits[0];
    [&bytes[..at], gate, &bytes[at + needle.len()..]].concat()
}

/// The toy with relation 5's gate replaced by `gate`, as a value.
fn toy_with_gate(gate: GateDef) -> CircuitArtifact {
    let mut a = toy();
    a.relations[5].gate = gate;
    a
}

// ---------------------------------------------------------------------------
// The round trip
// ---------------------------------------------------------------------------

/// Acceptance 10: both committed artifacts decode, re-encode to exactly the
/// file's bytes, decode again to an equal struct, and are circuits. postcard is
/// deterministic and not self-describing, so byte identity here tests the
/// artifact's layout, not a formatter.
#[test]
fn both_fixtures_round_trip_byte_identically() {
    for (name, bytes) in [
        ("toy_cached.bin", toy_cached_bytes()),
        ("toy_cache_free.bin", toy_cache_free_bytes()),
    ] {
        let decoded = CircuitArtifact::from_bytes(&bytes)
            .unwrap_or_else(|e| panic!("{name} must decode: {e}"));
        let written = decoded.to_bytes();
        assert_eq!(written, bytes, "{name} must re-encode byte for byte");
        let again = CircuitArtifact::from_bytes(&written)
            .unwrap_or_else(|e| panic!("{name}'s re-encoding must decode: {e}"));
        assert_eq!(
            again, decoded,
            "{name} must decode to the same artifact twice"
        );
        assert_eq!(decoded.validate(), Ok(()), "{name} must be a circuit");
    }
    // The two files are two different compilations, not one file twice.
    assert_ne!(toy(), toy_cache_free());
}

/// Every `Fr` on the wire is its canonical 32 little-endian bytes with no
/// length prefix, must-be-exact 15. The file ends with the padding contract:
/// the row's one-byte count, 6, then six zeros in 192 bytes, then the one
/// `zero_row_valid` byte.
#[test]
fn a_field_element_is_32_canonical_bytes_with_no_prefix() {
    let bytes = toy_cached_bytes();
    let a = toy();
    assert_eq!(a.padding.row.len(), 6);
    assert!(a.padding.zero_row_valid);
    let tail = &bytes[bytes.len() - 194..];
    assert_eq!(tail[0], 6, "the padding row's element count");
    assert!(
        tail[1..193].iter().all(|&b| b == 0),
        "six zeros, 32 bytes each"
    );
    assert_eq!(tail[193], 1, "zero_row_valid is one byte");
    // The literal 3 of `define_fingerprint3` is `03` then 31 zeros.
    let three = Fr::from_u64(3).to_bytes();
    assert_eq!(three[0], 3);
    assert!(bytes.windows(32).any(|w| w == three));
}

// ---------------------------------------------------------------------------
// Refusals of the artifact as a whole
// ---------------------------------------------------------------------------

/// One artifact is one byte string: postcard itself would ignore a trailing
/// byte, so the reader's re-encode comparison is what refuses it.
#[test]
fn a_trailing_byte_is_refused() {
    let bytes = toy_cached_bytes();
    assert!(CircuitArtifact::from_bytes(&bytes).is_ok());

    for extra in [0x00u8, 0x01, 0xff] {
        let mut longer = bytes.clone();
        longer.push(extra);
        // postcard alone reads the artifact and stops.
        assert_eq!(
            postcard::from_bytes::<CircuitArtifact>(&longer).as_ref(),
            Ok(&toy())
        );
        assert_eq!(
            CircuitArtifact::from_bytes(&longer),
            Err(NOT_CANONICAL.into()),
            "trailing byte {extra:#04x}"
        );
    }
}

/// A varint written longer than it needs to be is refused. The leading
/// `format_version`, 0, is re-encoded as `0x80 0x00`: postcard reads that as 0,
/// so the artifact decodes to the toy, and only the canonical comparison stands
/// between the reader and two byte strings for one artifact.
#[test]
fn an_overlong_varint_is_refused() {
    let bytes = toy_cached_bytes();
    assert_eq!(bytes[0], 0x00, "the file starts with format_version 0");
    let overlong = [&[0x80u8, 0x00][..], &bytes[1..]].concat();

    assert_eq!(postcard::from_bytes::<u32>(&[0x80, 0x00]), Ok(0));
    assert_eq!(
        postcard::from_bytes::<CircuitArtifact>(&overlong).as_ref(),
        Ok(&toy())
    );
    assert_eq!(
        CircuitArtifact::from_bytes(&overlong),
        Err(NOT_CANONICAL.into())
    );
}

/// Every proper prefix of each file is refused as a buffer that ends early,
/// from the empty string to the file less its last byte.
#[test]
fn every_truncation_is_refused() {
    for (name, bytes) in [
        ("toy_cached.bin", toy_cached_bytes()),
        ("toy_cache_free.bin", toy_cache_free_bytes()),
    ] {
        for len in 0..bytes.len() {
            assert_eq!(
                CircuitArtifact::from_bytes(&bytes[..len]),
                Err(ENDS_EARLY.into()),
                "{name} truncated to {len} of {} bytes",
                bytes.len()
            );
        }
        assert!(CircuitArtifact::from_bytes(&bytes).is_ok());
    }
}

/// A sequence length is untrusted: a varint claiming 2^32 names in the memory
/// layout, with nothing behind it, is a buffer that ends early — refused
/// without reserving 2^32 of anything first. The same claim as a gate's operand
/// count, with nothing behind it, is refused the same way.
#[test]
fn a_length_prefix_claiming_two_to_the_32_is_refused() {
    let huge = encode(&(1u64 << 32));
    assert_eq!(huge, [0x80, 0x80, 0x80, 0x80, 0x10]);

    // format_version 0, coefficient_encoding 0, trace_vars 4, then the memory
    // layout's length.
    let bytes = toy_cached_bytes();
    assert_eq!(&bytes[..4], &[0, 0, 4, 1], "the toy has one memory column");
    let claim = [&[0u8, 0, 4][..], &huge].concat();
    assert_eq!(CircuitArtifact::from_bytes(&claim), Err(ENDS_EARLY.into()));

    // tag 0, split 0, one coefficient, then 2^32 operands.
    let mut gate = raw_gate(0, 0, &[(0, 0, ZERO)], &[]);
    gate.pop(); // the empty operand list's length, 0
    gate.extend_from_slice(&huge);
    assert_eq!(
        postcard::from_bytes::<GateDef>(&gate),
        Err(postcard::Error::DeserializeUnexpectedEnd)
    );
    // The artifact cut off right after that claim.
    let whole = with_gate_bytes(&gate);
    let cut = whole
        .windows(gate.len())
        .position(|w| w == gate.as_slice())
        .expect("the spliced gate is in the artifact")
        + gate.len();
    assert_eq!(
        CircuitArtifact::from_bytes(&whole[..cut]),
        Err(ENDS_EARLY.into())
    );
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

/// Every unused field of an address is 0 on the wire. `(0, 3, 1)` would be
/// `M[3]` with a stray 1 in the second field; refused, where `(0, 3, 0)` is
/// `M[3]`. Every tag with an unused field is checked the same way, and the
/// refusal holds inside a whole artifact.
#[test]
fn a_nonzero_unused_address_field_is_refused() {
    assert_eq!(
        postcard::from_bytes::<PolyAddress>(&encode(&(0u8, 3u32, 1u32))),
        Err(postcard::Error::SerdeDeCustom)
    );
    assert_eq!(
        postcard::from_bytes::<PolyAddress>(&encode(&(0u8, 3u32, 0u32))),
        Ok(PolyAddress::Memory(3))
    );

    let legal: [(RawAddress, PolyAddress); 7] = [
        ((0, 3, 0), PolyAddress::Memory(3)),
        ((1, 3, 0), PolyAddress::Witness(3)),
        ((2, 3, 0), PolyAddress::Setup(3)),
        ((3, 0, 0), PolyAddress::Virtual(VirtualKind::RowIndex)),
        ((4, 3, 1), common::inner(3, 1)),
        ((5, 3, 0), PolyAddress::Scratch(3)),
        ((6, 3, 1), common::cached(3, 1)),
    ];
    for (raw, address) in legal {
        assert_eq!(
            postcard::from_bytes::<PolyAddress>(&encode(&raw)),
            Ok(address)
        );
        assert_eq!(encode(&address), encode(&raw), "{address} writes {raw:?}");
    }
    let stray: [RawAddress; 6] = [
        (0, 3, 1),
        (1, 3, 1),
        (2, 3, 1),
        (3, 1, 0),
        (3, 0, 1),
        (5, 3, 1),
    ];
    for raw in stray {
        assert_eq!(
            postcard::from_bytes::<PolyAddress>(&encode(&raw)),
            Err(postcard::Error::SerdeDeCustom),
            "{raw:?}"
        );
    }

    // Inside the artifact: relation 5 as `Linear { [(1, x)], 0 }`.
    let gate = |x: RawAddress| raw_gate(0, 0, &[(0, 0, one()), (0, 0, ZERO)], &[x]);
    let control = CircuitArtifact::from_bytes(&with_gate_bytes(&gate((0, 3, 0))));
    assert_eq!(
        control,
        Ok(toy_with_gate(GateDef::Linear {
            terms: vec![(common::lit(1), PolyAddress::Memory(3))],
            constant: common::lit(0),
        }))
    );
    assert_eq!(
        CircuitArtifact::from_bytes(&with_gate_bytes(&gate((0, 3, 1)))),
        Err(SHAPE_REFUSED.into())
    );
}

/// Address tags are 0 to 6 and append-only; 7 and 255 are refused, alone and
/// inside an artifact.
#[test]
fn an_unknown_address_tag_is_refused() {
    for tag in [7u8, 8, 255] {
        assert_eq!(
            postcard::from_bytes::<PolyAddress>(&encode(&(tag, 0u32, 0u32))),
            Err(postcard::Error::SerdeDeCustom),
            "tag {tag}"
        );
    }
    let gate = |x: RawAddress| raw_gate(0, 0, &[(0, 0, one()), (0, 0, ZERO)], &[x]);
    assert!(CircuitArtifact::from_bytes(&with_gate_bytes(&gate((6, 0, 0)))).is_ok());
    assert_eq!(
        CircuitArtifact::from_bytes(&with_gate_bytes(&gate((7, 0, 0)))),
        Err(SHAPE_REFUSED.into())
    );
}

// ---------------------------------------------------------------------------
// Coefficients
// ---------------------------------------------------------------------------

/// Coefficient tags are 0 (literal) and 1 (challenge); 2 is refused, alone and
/// inside an artifact.
#[test]
fn an_unknown_coefficient_tag_is_refused() {
    assert_eq!(
        postcard::from_bytes::<Coeff>(&encode(&(0u8, 0u32, ZERO))),
        Ok(Coeff::Literal(Fr::ZERO))
    );
    assert_eq!(
        postcard::from_bytes::<Coeff>(&encode(&(1u8, 0u32, ZERO))),
        Ok(Coeff::Challenge(0))
    );
    for tag in [2u8, 255] {
        assert_eq!(
            postcard::from_bytes::<Coeff>(&encode(&(tag, 0u32, ZERO))),
            Err(postcard::Error::SerdeDeCustom),
            "tag {tag}"
        );
    }
    let gate = |c: RawCoeff| raw_gate(0, 0, &[c], &[]);
    assert_eq!(
        CircuitArtifact::from_bytes(&with_gate_bytes(&gate((1, 0, ZERO)))),
        Ok(toy_with_gate(GateDef::Linear {
            terms: vec![],
            constant: Coeff::Challenge(0),
        }))
    );
    assert_eq!(
        CircuitArtifact::from_bytes(&with_gate_bytes(&gate((2, 0, ZERO)))),
        Err(SHAPE_REFUSED.into())
    );
}

/// A challenge carries no value, and a literal no slot: `Challenge(0)` with the
/// value 1 is refused, as is `Literal` with slot 1, alone and inside an
/// artifact.
#[test]
fn a_coefficient_with_a_nonzero_unused_field_is_refused() {
    assert_eq!(
        postcard::from_bytes::<Coeff>(&encode(&(1u8, 0u32, one()))),
        Err(postcard::Error::SerdeDeCustom)
    );
    assert_eq!(
        postcard::from_bytes::<Coeff>(&encode(&(0u8, 1u32, ZERO))),
        Err(postcard::Error::SerdeDeCustom)
    );
    assert_eq!(
        postcard::from_bytes::<Coeff>(&encode(&(0u8, 0u32, one()))),
        Ok(Coeff::Literal(Fr::ONE))
    );
    let gate = |c: RawCoeff| raw_gate(0, 0, &[c], &[]);
    assert!(CircuitArtifact::from_bytes(&with_gate_bytes(&gate((0, 0, one())))).is_ok());
    assert_eq!(
        CircuitArtifact::from_bytes(&with_gate_bytes(&gate((1, 0, one())))),
        Err(SHAPE_REFUSED.into())
    );
}

/// One coefficient encoding: canonical. 32 bytes of `0xff`, and the modulus
/// itself, are refused in a `Coeff::Literal`; the modulus less one is the
/// largest literal there is.
#[test]
fn a_non_canonical_field_element_is_refused() {
    let largest = Fr::MINUS_ONE.to_bytes();
    let mut modulus = largest;
    assert_eq!(modulus[0] & 1, 0, "the modulus is odd, so p − 1 ends even");
    modulus[0] += 1;

    assert_eq!(
        postcard::from_bytes::<Coeff>(&encode(&(0u8, 0u32, largest))),
        Ok(Coeff::Literal(Fr::MINUS_ONE))
    );
    for bad in [modulus, [0xff; 32]] {
        assert_eq!(
            postcard::from_bytes::<Coeff>(&encode(&(0u8, 0u32, bad))),
            Err(postcard::Error::SerdeDeCustom)
        );
    }

    let gate = |v: [u8; 32]| raw_gate(0, 0, &[(0, 0, v)], &[]);
    assert!(CircuitArtifact::from_bytes(&with_gate_bytes(&gate(largest))).is_ok());
    for bad in [modulus, [0xff; 32]] {
        assert_eq!(
            CircuitArtifact::from_bytes(&with_gate_bytes(&gate(bad))),
            Err(SHAPE_REFUSED.into())
        );
    }
}

// ---------------------------------------------------------------------------
// Gates
// ---------------------------------------------------------------------------

/// Gate tags are 0 to 4 and append-only; 5 and 255 are refused, alone and
/// inside an artifact.
#[test]
fn an_unknown_gate_tag_is_refused() {
    let tree = raw_gate(4, 0, &[], &[(4, 1, 0)]);
    assert_eq!(
        postcard::from_bytes::<GateDef>(&tree),
        Ok(GateDef::TreeProduct {
            input: common::inner(1, 0)
        })
    );
    for tag in [5u8, 255] {
        let unknown = raw_gate(tag, 0, &[], &[(4, 1, 0)]);
        assert_eq!(
            postcard::from_bytes::<GateDef>(&unknown),
            Err(postcard::Error::SerdeDeCustom),
            "tag {tag}"
        );
        assert_eq!(
            CircuitArtifact::from_bytes(&with_gate_bytes(&unknown)),
            Err(SHAPE_REFUSED.into()),
            "tag {tag}"
        );
    }
    assert!(CircuitArtifact::from_bytes(&with_gate_bytes(&tree)).is_ok());
}

/// `AffineProduct`'s split `t` is the length of its left factor, so it is at
/// most the operand count: two operands with split 2 is `(a·x + a_0)·(b_0)`,
/// split 3 is refused, and so is a split near `u32::MAX`.
#[test]
fn an_affine_product_whose_split_exceeds_its_operands_is_refused() {
    let coeffs = [(0, 0, one()); 4];
    let operands = [(1, 0, 0), (1, 1, 0)];

    let whole_left = raw_gate(3, 2, &coeffs, &operands);
    let expected = GateDef::AffineProduct {
        left: vec![(common::lit(1), common::A), (common::lit(1), common::B)],
        left_constant: common::lit(1),
        right: vec![],
        right_constant: common::lit(1),
    };
    assert_eq!(
        postcard::from_bytes::<GateDef>(&whole_left),
        Ok(expected.clone())
    );
    assert_eq!(
        CircuitArtifact::from_bytes(&with_gate_bytes(&whole_left)),
        Ok(toy_with_gate(expected))
    );

    for split in [3u32, u32::MAX] {
        let over = raw_gate(3, split, &coeffs, &operands);
        assert_eq!(
            postcard::from_bytes::<GateDef>(&over),
            Err(postcard::Error::SerdeDeCustom),
            "split {split}"
        );
        assert_eq!(
            CircuitArtifact::from_bytes(&with_gate_bytes(&over)),
            Err(SHAPE_REFUSED.into()),
            "split {split}"
        );
    }
}

/// `Linear` carries one coefficient per operand and then its constant. Two
/// operands with three coefficients decode; two, four, or none at all (where a
/// reader that indexed first would panic) are refused.
#[test]
fn a_linear_whose_coefficient_count_is_not_operands_plus_one_is_refused() {
    let operands = [(1, 0, 0), (1, 1, 0)];
    let right = raw_gate(0, 0, &[(0, 0, one()); 3], &operands);
    assert_eq!(
        postcard::from_bytes::<GateDef>(&right),
        Ok(GateDef::Linear {
            terms: vec![(common::lit(1), common::A), (common::lit(1), common::B)],
            constant: common::lit(1),
        })
    );
    assert!(CircuitArtifact::from_bytes(&with_gate_bytes(&right)).is_ok());

    for count in [0usize, 2, 4] {
        let wrong = raw_gate(0, 0, &vec![(0, 0, one()); count], &operands);
        assert_eq!(
            postcard::from_bytes::<GateDef>(&wrong),
            Err(postcard::Error::SerdeDeCustom),
            "{count} coefficients"
        );
        assert_eq!(
            CircuitArtifact::from_bytes(&with_gate_bytes(&wrong)),
            Err(SHAPE_REFUSED.into()),
            "{count} coefficients"
        );
    }
    // No operands and no coefficients: the constant is missing.
    assert_eq!(
        postcard::from_bytes::<GateDef>(&raw_gate(0, 0, &[], &[])),
        Err(postcard::Error::SerdeDeCustom)
    );
}

// ---------------------------------------------------------------------------
// Totality
// ---------------------------------------------------------------------------

/// `from_bytes` is total over every single-bit corruption of the cached toy:
/// each of the file's bit flips returns, never panics. A flip that still
/// decodes must decode to an artifact other than the toy, and re-encode to the
/// flipped bytes — the canonical check makes the wire form injective. How many
/// flips decode is reported, not required: a flipped letter in a name is still
/// a name.
#[test]
fn every_single_bit_flip_returns_without_panicking() {
    let bytes = toy_cached_bytes();
    let original = toy();
    let total = bytes.len() * 8;
    let mut decoded = 0usize;
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut flipped = bytes.clone();
            flipped[i] ^= 1 << bit;
            match CircuitArtifact::from_bytes(&flipped) {
                Ok(a) => {
                    decoded += 1;
                    assert_ne!(a, original, "byte {i} bit {bit} decoded to the toy");
                    assert_eq!(a.to_bytes(), flipped, "byte {i} bit {bit}");
                }
                Err(e) => assert!(
                    e.starts_with("malformed circuit artifact: "),
                    "byte {i} bit {bit}: {e}"
                ),
            }
        }
    }
    assert!(
        0 < decoded && decoded < total,
        "{decoded} of {total} single-bit flips of toy_cached.bin still decode"
    );
    eprintln!("{decoded} of {total} single-bit flips of toy_cached.bin still decode");
}
