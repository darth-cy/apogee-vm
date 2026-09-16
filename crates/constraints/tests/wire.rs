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
use constraints::{CircuitArtifact, Coeff, GateDef, LookupExpr, PolyAddress, VirtualKind};
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
/// `format_version`, 1, is re-encoded as `0x81 0x00`: postcard reads that as 1,
/// so the artifact decodes to the toy, and only the canonical comparison stands
/// between the reader and two byte strings for one artifact.
#[test]
fn an_overlong_varint_is_refused() {
    let bytes = toy_cached_bytes();
    assert_eq!(bytes[0], 0x01, "the file starts with format_version 1");
    let overlong = [&[0x81u8, 0x00][..], &bytes[1..]].concat();

    assert_eq!(postcard::from_bytes::<u32>(&[0x81, 0x00]), Ok(1));
    assert_eq!(
        postcard::from_bytes::<CircuitArtifact>(&overlong).as_ref(),
        Ok(&toy())
    );
    assert_eq!(
        CircuitArtifact::from_bytes(&overlong),
        Err(NOT_CANONICAL.into())
    );
}

/// The format version is read first, and no other version is decoded. The
/// cached toy's bytes with their first word 2, or 128 (two varint bytes), are
/// refused naming the version, where under 1 they decode to the toy; and so is
/// an S13 file — format 0, whose lookup element had no selector — holding one
/// lookup `(name, channel, tuple)`.
///
/// Kills a reader that checks the version only after decoding the rest: that
/// reader takes the S13 lookup's tuple length for a selector, misreads the gate
/// after it, and refuses the file as a malformed gate rather than as format 0.
#[test]
fn a_format_version_other_than_one_is_refused() {
    let bytes = toy_cached_bytes();
    assert_eq!(CircuitArtifact::from_bytes(&bytes), Ok(toy()));
    let refused = |version: u32| {
        Err(format!(
            "malformed circuit artifact: format version {version}, but this reader reads 1 only"
        ))
    };
    let two = [&[2u8][..], &bytes[1..]].concat();
    assert_eq!(CircuitArtifact::from_bytes(&two), refused(2));
    let wide = [&[0x80u8, 0x01][..], &bytes[1..]].concat();
    assert_eq!(postcard::from_bytes::<u32>(&[0x80, 0x01]), Ok(128));
    assert_eq!(CircuitArtifact::from_bytes(&wide), refused(128));

    let mut a = toy();
    a.lookups.push(LookupExpr {
        name: "s13".into(),
        channel: 0,
        selector: PolyAddress::Memory(0),
        tuple: vec![GateDef::Linear {
            terms: vec![],
            constant: common::lit(0),
        }],
    });
    let s14 = a.to_bytes();
    // The name `s13`, channel 0, selector `M[0]`, then the tuple's length, 1.
    let lookup = [3u8, b's', b'1', b'3', 0, 0, 0, 0, 1];
    let at = s14
        .windows(lookup.len())
        .position(|w| w == lookup)
        .expect("the lookup is in the file");
    let s13 = [&[0u8][..], &s14[1..at + 5], &s14[at + 8..]].concat();
    assert_eq!(s13.len(), s14.len() - 3);
    assert_eq!(CircuitArtifact::from_bytes(&s13), refused(0));
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
/// layout, with nothing behind it, is refused as a buffer that ends early, and
/// `from_bytes` returns rather than panicking or aborting. The same claim as a
/// gate's operand count, with nothing behind it, is refused the same way.
///
/// This shows the refusal, not the absence of a reservation: postcard's
/// `size_hint` is `None` whenever a declared length exceeds the bytes left, so
/// a visitor that reserved from the hint would pass this test too. No
/// allocation is measured here.
#[test]
fn a_length_prefix_claiming_two_to_the_32_is_refused() {
    let huge = encode(&(1u64 << 32));
    assert_eq!(huge, [0x80, 0x80, 0x80, 0x80, 0x10]);

    // format_version 1, coefficient_encoding 0, trace_vars 4, then the memory
    // layout's length.
    let bytes = toy_cached_bytes();
    assert_eq!(&bytes[..4], &[1, 0, 4, 1], "the toy has one memory column");
    let claim = [&[1u8, 0, 4][..], &huge].concat();
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

    let legal: [(RawAddress, PolyAddress); 8] = [
        ((0, 3, 0), PolyAddress::Memory(3)),
        ((1, 3, 0), PolyAddress::Witness(3)),
        ((2, 3, 0), PolyAddress::Setup(3)),
        ((3, 0, 0), PolyAddress::Virtual(VirtualKind::RowIndex)),
        ((3, 1, 0), PolyAddress::Virtual(VirtualKind::RamLive)),
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
    let stray: [RawAddress; 8] = [
        (0, 3, 1),
        (1, 3, 1),
        (2, 3, 1),
        (3, 4, 0),
        (3, 0, 1),
        (3, 1, 1),
        (3, 3, 1),
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

/// Virtual kinds are 0 (`V[row]`), 1 (`V[ram_live]`), 2 (`V[range19]`) and
/// 3 (`V[range16]`), append-only, and a kind is printed by its short name.
#[test]
fn virtual_kind_tags_are_append_only() {
    let kinds = [
        (VirtualKind::RowIndex, 0u8, "V[row]"),
        (VirtualKind::RamLive, 1, "V[ram_live]"),
        (VirtualKind::Range19, 2, "V[range19]"),
        (VirtualKind::Range16, 3, "V[range16]"),
    ];
    for (kind, tag, name) in kinds {
        assert_eq!(encode(&kind), [tag], "{kind:?}");
        assert_eq!(postcard::from_bytes::<VirtualKind>(&[tag]), Ok(kind));
        assert_eq!(PolyAddress::Virtual(kind).to_string(), name);
    }
    assert_eq!(
        postcard::from_bytes::<VirtualKind>(&[kinds.len() as u8]),
        Err(postcard::Error::SerdeDeCustom),
        "the first tag no kind has"
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

/// Gate tags are 0 to 5 and append-only; 6 and 255 are refused, alone and
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
    for tag in [6u8, 255] {
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

/// A `Quadratic` with `t` linear terms and `u` products, every coefficient and
/// address distinct, beside its encoding written field by field from
/// `docs/spec/gkr.md` §4.1: tag 5, split `t`, coefficients
/// `c_0, a_1..a_t, b_1..b_u`, operands `x_1..x_t, y_1, z_1, .., y_u, z_u`.
fn quadratic(t: u32, u: u32) -> (GateDef, Vec<RawCoeff>, Vec<RawAddress>) {
    let lit = |v: u32| Coeff::Literal(Fr::from_u64(v as u64));
    let raw = |v: u32| (0u8, 0u32, Fr::from_u64(v as u64).to_bytes());
    let gate = GateDef::Quadratic {
        constant: lit(100),
        linear: (0..t)
            .map(|i| (lit(200 + i), PolyAddress::Witness(i)))
            .collect(),
        products: (0..u)
            .map(|j| {
                let (y, z) = (
                    PolyAddress::Witness(10 + 2 * j),
                    PolyAddress::Setup(11 + 2 * j),
                );
                (lit(300 + j), y, z)
            })
            .collect(),
    };
    let mut coeffs = vec![raw(100)];
    coeffs.extend((0..t).map(|i| raw(200 + i)));
    coeffs.extend((0..u).map(|j| raw(300 + j)));
    let mut operands: Vec<RawAddress> = (0..t).map(|i| (1, i, 0)).collect();
    for j in 0..u {
        operands.push((1, 10 + 2 * j, 0));
        operands.push((2, 11 + 2 * j, 0));
    }
    (gate, coeffs, operands)
}

/// `Quadratic` encodes to exactly its hand-written bytes and decodes back, alone
/// and inside an artifact, for no terms at all, linear terms only, products
/// only, and both. Kills an encoder writing the product count as the split: the
/// decoder reading it would round-trip, but not match these bytes.
#[test]
fn a_quadratic_round_trips_byte_for_byte() {
    for (t, u) in [(0, 0), (2, 0), (0, 2), (2, 3)] {
        let (gate, coeffs, operands) = quadratic(t, u);
        let bytes = raw_gate(5, t, &coeffs, &operands);
        assert_eq!(encode(&gate), bytes, "({t}, {u})");
        assert_eq!(
            postcard::from_bytes::<GateDef>(&bytes),
            Ok(gate.clone()),
            "({t}, {u})"
        );
        let file = with_gate_bytes(&bytes);
        let decoded = CircuitArtifact::from_bytes(&file);
        assert_eq!(decoded, Ok(toy_with_gate(gate)), "({t}, {u})");
        assert_eq!(decoded.map(|a| a.to_bytes()), Ok(file), "({t}, {u})");
    }
}

/// Every malformed `Quadratic` is an error, never a panic, alone and inside an
/// artifact: from a well-formed `t = 2, u = 3`, a split past the operands (9
/// and `u32::MAX`), an odd number of product operands (the last removed, the
/// coefficients one fewer to match), one coefficient too many and one too
/// few; and, where a reader that indexed first would panic, a gate with no
/// coefficients at all. Kills a decoder that does not require the product
/// operands to pair up: it builds two products from five operands and returns
/// `Ok`.
#[test]
fn a_malformed_quadratic_is_refused() {
    let (gate, coeffs, operands) = quadratic(2, 3);
    assert_eq!((coeffs.len(), operands.len()), (6, 8));
    assert!(postcard::from_bytes::<GateDef>(&raw_gate(5, 2, &coeffs, &operands)) == Ok(gate));

    let mut bad: Vec<(&str, Vec<u8>)> = vec![
        ("split 9", raw_gate(5, 9, &coeffs, &operands)),
        ("split u32::MAX", raw_gate(5, u32::MAX, &coeffs, &operands)),
        (
            "an odd product operand count",
            raw_gate(5, 2, &coeffs[..5], &operands[..7]),
        ),
        (
            "one coefficient too few",
            raw_gate(5, 2, &coeffs[..5], &operands),
        ),
        ("no coefficients at all", raw_gate(5, 0, &[], &[])),
    ];
    let mut extra = coeffs.clone();
    extra.push(coeffs[0]);
    bad.push((
        "one coefficient too many",
        raw_gate(5, 2, &extra, &operands),
    ));

    for (what, bytes) in &bad {
        assert_eq!(
            postcard::from_bytes::<GateDef>(bytes),
            Err(postcard::Error::SerdeDeCustom),
            "{what}"
        );
        assert_eq!(
            CircuitArtifact::from_bytes(&with_gate_bytes(bytes)),
            Err(SHAPE_REFUSED.into()),
            "{what}"
        );
    }
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

/// A `LookupExpr` is `(name, channel, selector, tuple)`, `docs/spec/gkr.md`
/// §4.1: the name's length and its bytes, the channel's varint, the selector's
/// three address fields, the tuple's length and its gates. `gap_lo` below —
/// channel 0, selector `M[2]`, one expression `4·M[0] + 1·V[ram_live] − 1` —
/// encodes to exactly its hand-written bytes and decodes back, alone and as a
/// lookup of the toy.
///
/// Kills an encoder that writes the selector after the tuple, or leaves it
/// out: both round-trip through their own decoder, and neither matches these
/// bytes.
#[test]
fn a_lookup_round_trips_byte_for_byte() {
    let lookup = LookupExpr {
        name: "gap_lo".into(),
        channel: 0,
        selector: PolyAddress::Memory(2),
        tuple: vec![GateDef::Linear {
            terms: vec![
                (common::lit(4), PolyAddress::Memory(0)),
                (common::lit(1), PolyAddress::Virtual(VirtualKind::RamLive)),
            ],
            constant: common::neg(1),
        }],
    };
    let mut bytes = vec![6u8];
    bytes.extend_from_slice(b"gap_lo");
    bytes.push(0); // channel 0
    bytes.extend_from_slice(&[0, 2, 0]); // selector M[2]
    bytes.push(1); // one expression
    bytes.extend(raw_gate(
        0,
        0,
        &[
            (0, 0, Fr::from_u64(4).to_bytes()),
            (0, 0, one()),
            (0, 0, Fr::MINUS_ONE.to_bytes()),
        ],
        &[(0, 0, 0), (3, 1, 0)],
    ));
    assert_eq!(encode(&lookup), bytes);
    assert_eq!(
        postcard::from_bytes::<LookupExpr>(&bytes),
        Ok(lookup.clone())
    );

    let mut a = toy();
    a.lookups.push(lookup);
    let file = a.to_bytes();
    assert!(file.windows(bytes.len()).any(|w| w == bytes.as_slice()));
    assert_eq!(CircuitArtifact::from_bytes(&file), Ok(a));
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
