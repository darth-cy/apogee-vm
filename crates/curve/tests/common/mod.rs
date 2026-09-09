//! Test support specific to this crate: samplers, the arkworks bridge, and the
//! hex codec the committed vector files are written in. The RNG, SHA-256 and
//! the byte-level hex helpers are shared with the other suites and live in
//! `tools/test-support`. Test-only; never compiled into the library.
#![allow(dead_code)]

use curve::{Fq, Fq12, Fq2, Fq6, G1Affine, G2Affine};
use field::Fr;
use test_support::{hex_to_bytes, to_hex, Rng};

// ---------------------------------------------------------------------------
// Sampling
//
// Rejection, not reduction: a comparison against arkworks has to feed both
// sides the same value, and `from_bytes` refuses anything `>= q`.
// ---------------------------------------------------------------------------

pub fn next_fq(rng: &mut Rng) -> Fq {
    loop {
        let mut b = rng.next_le32();
        b[31] &= 0x3f; // q < 2^254, so clearing two bits keeps rejection rare
        if let Some(x) = Fq::from_bytes(&b) {
            return x;
        }
    }
}

pub fn next_fq2(rng: &mut Rng) -> Fq2 {
    Fq2::new(next_fq(rng), next_fq(rng))
}

pub fn next_fr(rng: &mut Rng) -> Fr {
    loop {
        let mut b = rng.next_le32();
        b[31] &= 0x3f;
        if let Some(x) = Fr::from_bytes(&b) {
            return x;
        }
    }
}

// ---------------------------------------------------------------------------
// arkworks bridge. Every comparison crosses through the canonical wire form,
// which also exercises `to_bytes` on every result.
// ---------------------------------------------------------------------------

pub fn to_ark_fq(x: &Fq) -> ark_bn254::Fq {
    ark_ff::PrimeField::from_le_bytes_mod_order(&x.to_bytes())
}

pub fn ark_fq_bytes(x: &ark_bn254::Fq) -> [u8; 32] {
    let v = ark_ff::BigInteger::to_bytes_le(&ark_ff::PrimeField::into_bigint(*x));
    let mut b = [0u8; 32];
    assert_eq!(v.len(), 32, "ark Fq must serialize to 32 bytes");
    b.copy_from_slice(&v);
    b
}

pub fn to_ark_fq2(x: &Fq2) -> ark_bn254::Fq2 {
    ark_bn254::Fq2::new(to_ark_fq(&x.c0), to_ark_fq(&x.c1))
}

pub fn ark_fq2_bytes(x: &ark_bn254::Fq2) -> [u8; 64] {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(&ark_fq_bytes(&x.c0));
    b[32..].copy_from_slice(&ark_fq_bytes(&x.c1));
    b
}

pub fn to_ark_fq6(x: &Fq6) -> ark_bn254::Fq6 {
    ark_bn254::Fq6::new(to_ark_fq2(&x.c0), to_ark_fq2(&x.c1), to_ark_fq2(&x.c2))
}

pub fn to_ark_fq12(x: &Fq12) -> ark_bn254::Fq12 {
    ark_bn254::Fq12::new(to_ark_fq6(&x.c0), to_ark_fq6(&x.c1))
}

pub fn from_ark_fq(x: &ark_bn254::Fq) -> Fq {
    Fq::from_bytes(&ark_fq_bytes(x)).expect("arkworks emits a canonical Fq")
}

pub fn from_ark_fq12(x: &ark_bn254::Fq12) -> Fq12 {
    let f2 = |v: &ark_bn254::Fq2| Fq2::new(from_ark_fq(&v.c0), from_ark_fq(&v.c1));
    let f6 = |v: &ark_bn254::Fq6| Fq6::new(f2(&v.c0), f2(&v.c1), f2(&v.c2));
    Fq12::new(f6(&x.c0), f6(&x.c1))
}

pub fn to_ark_g1(p: &G1Affine) -> ark_bn254::G1Affine {
    if p.infinity {
        ark_bn254::G1Affine::identity()
    } else {
        ark_bn254::G1Affine::new_unchecked(to_ark_fq(&p.x), to_ark_fq(&p.y))
    }
}

pub fn to_ark_g2(p: &G2Affine) -> ark_bn254::G2Affine {
    if p.infinity {
        ark_bn254::G2Affine::identity()
    } else {
        ark_bn254::G2Affine::new_unchecked(to_ark_fq2(&p.x), to_ark_fq2(&p.y))
    }
}

/// arkworks' affine G1 in our wire form, so the two can be compared as bytes.
pub fn ark_g1_bytes(p: &ark_bn254::G1Affine) -> [u8; 64] {
    let mut b = [0u8; 64];
    if *p == ark_bn254::G1Affine::identity() {
        return b;
    }
    b[..32].copy_from_slice(&ark_fq_bytes(&p.x));
    b[32..].copy_from_slice(&ark_fq_bytes(&p.y));
    b
}

pub fn ark_g2_bytes(p: &ark_bn254::G2Affine) -> [u8; 128] {
    let mut b = [0u8; 128];
    if *p == ark_bn254::G2Affine::identity() {
        return b;
    }
    b[..64].copy_from_slice(&ark_fq2_bytes(&p.x));
    b[64..].copy_from_slice(&ark_fq2_bytes(&p.y));
    b
}

pub fn to_ark_fr(x: &Fr) -> ark_bn254::Fr {
    ark_ff::PrimeField::from_le_bytes_mod_order(&x.to_bytes())
}

// ---------------------------------------------------------------------------
// The vector-file codec
//
// A field element is 64 hex characters, a G1 point 128 and a G2 point 256:
// exactly the bytes `to_bytes` emits, so a fixture pins the wire format on
// every line it appears in. Points are parsed *without* `from_bytes`, since
// the off-curve and out-of-subgroup fixtures are values `from_bytes` must
// reject and the test still has to build them.
// ---------------------------------------------------------------------------

pub fn fq_from_hex(s: &str) -> Result<Fq, String> {
    let b = hex_to_bytes(s)?;
    let mut buf = [0u8; 32];
    if b.len() != 32 {
        return Err(format!("expected 32 bytes of Fq, got {}", b.len()));
    }
    buf.copy_from_slice(&b);
    Fq::from_bytes(&buf).ok_or_else(|| format!("Fq value {s} is not canonical"))
}

pub fn fq_to_hex(x: &Fq) -> String {
    to_hex(&x.to_bytes())
}

pub fn fq2_to_hex(x: &Fq2) -> String {
    to_hex(&x.to_bytes())
}

// The tower's wider tokens: coefficient order, each `Fq` in its canonical
// 32-byte little-endian wire form. `Fq6` is 384 hex characters and `Fq12` is
// 768. Neither type has a `to_bytes` of its own -- nothing in the protocol
// serializes one -- so the codec lives here with the fixtures that need it.

pub fn fq6_to_hex(x: &Fq6) -> String {
    format!(
        "{}{}{}",
        fq2_to_hex(&x.c0),
        fq2_to_hex(&x.c1),
        fq2_to_hex(&x.c2)
    )
}

pub fn fq12_to_hex(x: &Fq12) -> String {
    format!("{}{}", fq6_to_hex(&x.c0), fq6_to_hex(&x.c1))
}

pub fn fq2_from_hex(s: &str) -> Result<Fq2, String> {
    if s.len() != 128 {
        return Err(format!(
            "expected 128 hex characters of Fq2, got {}",
            s.len()
        ));
    }
    Ok(Fq2::new(fq_from_hex(&s[..64])?, fq_from_hex(&s[64..])?))
}

pub fn fq6_from_hex(s: &str) -> Result<Fq6, String> {
    if s.len() != 384 {
        return Err(format!(
            "expected 384 hex characters of Fq6, got {}",
            s.len()
        ));
    }
    Ok(Fq6::new(
        fq2_from_hex(&s[..128])?,
        fq2_from_hex(&s[128..256])?,
        fq2_from_hex(&s[256..])?,
    ))
}

pub fn fq12_from_hex(s: &str) -> Result<Fq12, String> {
    if s.len() != 768 {
        return Err(format!(
            "expected 768 hex characters of Fq12, got {}",
            s.len()
        ));
    }
    Ok(Fq12::new(
        fq6_from_hex(&s[..384])?,
        fq6_from_hex(&s[384..])?,
    ))
}

pub fn g1_bytes_from_hex(s: &str) -> Result<[u8; 64], String> {
    let b = hex_to_bytes(s)?;
    if b.len() != 64 {
        return Err(format!("expected 64 bytes of G1 point, got {}", b.len()));
    }
    let mut buf = [0u8; 64];
    buf.copy_from_slice(&b);
    Ok(buf)
}

pub fn g2_bytes_from_hex(s: &str) -> Result<[u8; 128], String> {
    let b = hex_to_bytes(s)?;
    if b.len() != 128 {
        return Err(format!("expected 128 bytes of G2 point, got {}", b.len()));
    }
    let mut buf = [0u8; 128];
    buf.copy_from_slice(&b);
    Ok(buf)
}

/// A G1 point straight from its coordinate bytes, with no validation beyond
/// canonicity. All-zero is infinity, as on the wire.
pub fn g1_raw(s: &str) -> Result<G1Affine, String> {
    let bytes = g1_bytes_from_hex(s)?;
    if bytes == [0u8; 64] {
        return Ok(G1Affine::IDENTITY);
    }
    let (x, y) = (&s[..64], &s[64..]);
    Ok(G1Affine {
        x: fq_from_hex(x)?,
        y: fq_from_hex(y)?,
        infinity: false,
    })
}

/// A G2 point straight from its coordinate bytes. Same contract as [`g1_raw`].
pub fn g2_raw(s: &str) -> Result<G2Affine, String> {
    let bytes = g2_bytes_from_hex(s)?;
    if bytes == [0u8; 128] {
        return Ok(G2Affine::IDENTITY);
    }
    Ok(G2Affine {
        x: Fq2::new(fq_from_hex(&s[..64])?, fq_from_hex(&s[64..128])?),
        y: Fq2::new(fq_from_hex(&s[128..192])?, fq_from_hex(&s[192..])?),
        infinity: false,
    })
}

pub fn g1_to_hex(p: &G1Affine) -> String {
    to_hex(&p.to_bytes())
}

pub fn g2_to_hex(p: &G2Affine) -> String {
    to_hex(&p.to_bytes())
}

pub fn fr_from_hex(s: &str) -> Result<Option<Fr>, String> {
    let b = hex_to_bytes(s)?;
    if b.len() != 32 {
        return Err(format!("expected 32 bytes of Fr, got {}", b.len()));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&b);
    Ok(Fr::from_bytes(&buf))
}
