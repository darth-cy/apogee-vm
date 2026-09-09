//! The structured reference string: snarkjs `.ptau` ingestion, an archive
//! format for reloading it, and the univariate KZG core Mercury is built on.
//!
//! The normative document is `docs/spec/srs.md`. This crate holds three things
//! and nothing else:
//!
//! - [`Srs::from_ptau`], the **one** ingestion path — a perpetual-powers-of-tau
//!   / Hermez `.ptau` container, and no other ceremony format in v1;
//! - [`Srs::save`] / [`Srs::load`], a flat archive so a prover does not re-read
//!   a 19 GB ceremony file to get 2^24 points;
//! - [`kzg`], commit / open / verify over those powers.
//!
//! # SRS integrity is presumed
//!
//! **There is no SRS digest.** S07 originally specified a Poseidon2 digest over
//! every point, absorbed in statement binding and re-verified by [`Srs::load`];
//! that requirement was dropped, and the SRS handed to this crate is *assumed*
//! to be the right one. See `docs/spec/srs.md` §6 and the S07 handoff note —
//! this is load-bearing for anything downstream that expected the statement to
//! bind an SRS identity, and it must be reinstated before the protocol is
//! sound against SRS substitution.
//!
//! What remains is structural, not identifying: every point is validated at
//! decode time with S05's `from_bytes` (canonical, on-curve, in-subgroup), and
//! [`Srs::validate`] checks the powers really are consecutive powers of one
//! `tau` under the two G2 points. Neither tells you *which* SRS you have.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;

use curve::msm::msm;
use curve::pairing::pairing_check;
use curve::{G1Affine, G2Affine};
use field::Fr;

pub mod kzg;
mod ptau;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way this crate refuses. One flat enum, one variant per failure class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SrsError {
    /// The filesystem said no. The message is `std::io::Error`'s.
    Io(String),
    /// Not a `.ptau` container, or not one of our archives.
    BadMagic,
    /// A container version this crate does not read.
    BadVersion(u32),
    /// A section is missing, duplicated, or the wrong size for the declared
    /// power. The string names which.
    BadSection(&'static str),
    /// The `.ptau` header names a field that is not BN254's `Fq`.
    WrongCurve,
    /// A section runs past the end of the file.
    Truncated,
    /// The file does not hold as many powers as were asked for.
    PowerTooLarge { requested: u32, available: u32 },
    /// A point failed S05's decode: non-canonical coordinate, off-curve, or
    /// outside the order-`r` subgroup. The index is *a* failing point, not
    /// necessarily the first — decoding runs in parallel.
    InvalidPoint { index: usize },
    /// A polynomial with more coefficients than the SRS has powers.
    DegreeTooLarge { degree: usize, max: usize },
    /// `validate`: `g1[0]` is not the G1 generator, or `g2_gen` is not the G2
    /// generator. Both are `tau^0`, so both are pinned.
    NotGenerator,
    /// `validate`: the powers are not consecutive powers of the `tau` the two
    /// G2 points name, or the SRS is degenerate — some point is the identity,
    /// which means `tau = 0` and would make the pairing check vacuous.
    TauMismatch,
}

impl From<std::io::Error> for SrsError {
    fn from(e: std::io::Error) -> SrsError {
        SrsError::Io(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Srs
// ---------------------------------------------------------------------------

/// `[x^0]_1 .. [x^(n-1)]_1` together with `[1]_2` and `[x]_2`.
///
/// The whole thing is prover-side. A verifier gets [`SrsVerifier`], which is
/// four points' worth of material and cannot commit to anything.
///
/// `PartialEq` is here so `save` / `load` can be stated as a round trip.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Srs {
    g1: Vec<G1Affine>,
    g2_gen: G2Affine,
    g2_tau: G2Affine,
}

impl Srs {
    /// Ingest the first `2^power` G1 powers and the first two G2 powers from a
    /// snarkjs `.ptau` file.
    ///
    /// The container is read, never trusted: magic, version, section table,
    /// header field, and every section size are checked against the declared
    /// power before a point is decoded, and each point then goes through S05's
    /// `from_bytes`. Nothing here panics on a malformed file.
    ///
    /// Only sections 1 (header), 2 (tauG1) and 3 (tauG2) are read. A ceremony
    /// file's alpha/beta and Lagrange sections are Groth16's business and are
    /// skipped, which is why this reads about 2 GB of a 19 GB file.
    pub fn from_ptau(path: &Path, power: u32) -> Result<Srs, SrsError> {
        ptau::from_ptau(path, power)
    }

    /// Check that the powers really are consecutive powers of one `tau`.
    ///
    /// Three structural facts, and no identity claim: `g1[0]` and `g2_gen` are
    /// the two generators, no point is the identity, and one random linear
    /// combination satisfies
    /// `e(sum c_i [x^i], [x]_2) = e(sum c_i [x^(i+1)], [1]_2)`. A single wrong
    /// point breaks the second with probability `1 - 1/|Fr|`.
    ///
    /// The coefficients come from `/dev/urandom`. Fixed coefficients would let
    /// a file be built to pass, and this is not a transcript — nothing about
    /// it needs to be reproducible.
    pub fn validate(&self) -> Result<(), SrsError> {
        if self.g1[0] != G1Affine::GENERATOR || self.g2_gen != G2Affine::GENERATOR {
            return Err(SrsError::NotGenerator);
        }

        // No SRS point may be the point at infinity, and this check is
        // load-bearing rather than tidy.
        //
        // `[x^i]_1` and `[x]_2` are the identity only when `x = 0`, so an SRS
        // that contains one is degenerate. The reason it has to be *rejected*
        // rather than left to the pairing check below is that
        // `pairing_check` contributes the identity for a pair at infinity
        // instead of failing on it: with `g2_tau` at infinity the first pair
        // vanishes, with the tail of `g1` at infinity the second does too, and
        // an empty product is 1. The check would pass **vacuously**, and
        // `kzg_verify` over that SRS then accepts an arbitrary opening at an
        // arbitrary value — every pairing it forms is skipped as well.
        //
        // With the SRS digest dropped, `validate` is the only structural gate
        // there is, so it does not get to be vacuous.
        if self.g2_tau.infinity || self.g1.iter().any(|p| p.infinity) {
            return Err(SrsError::TauMismatch);
        }

        // One power says nothing about tau; there is no consecutive pair.
        if self.g1.len() < 2 {
            return Ok(());
        }

        let pairs = self.g1.len() - 1;
        let c = random_scalars(pairs)?;
        let lo = msm(&self.g1[..pairs], &c).expect("one coefficient per power");
        let hi = msm(&self.g1[1..], &c).expect("one coefficient per power");

        if pairing_check(&[
            (lo.to_affine(), self.g2_tau),
            (-hi.to_affine(), self.g2_gen),
        ]) {
            Ok(())
        } else {
            Err(SrsError::TauMismatch)
        }
    }

    /// The highest polynomial degree these powers can commit to.
    pub fn max_degree(&self) -> usize {
        self.g1.len() - 1
    }

    /// Write the archive described in `docs/spec/srs.md` §5.
    pub fn save(&self, path: &Path) -> Result<(), SrsError> {
        let mut out = BufWriter::with_capacity(ARCHIVE_BUFFER, File::create(path)?);
        out.write_all(ARCHIVE_MAGIC)?;
        out.write_all(&ARCHIVE_VERSION.to_le_bytes())?;
        out.write_all(&self.power().to_le_bytes())?;
        out.write_all(&(self.g1.len() as u64).to_le_bytes())?;
        out.write_all(&self.g2_gen.to_bytes())?;
        out.write_all(&self.g2_tau.to_bytes())?;
        for p in &self.g1 {
            out.write_all(&p.to_bytes())?;
        }
        out.flush()?;
        Ok(())
    }

    /// Read an archive back, validating every point on the way in.
    ///
    /// With the digest requirement dropped, this decode *is* the integrity
    /// check: a flipped byte in a coordinate almost always leaves a point off
    /// the curve, and one that does not still leaves a point unrelated to the
    /// ceremony, which [`Srs::validate`] catches. Neither notices a whole
    /// archive swapped for another valid one.
    pub fn load(path: &Path) -> Result<Srs, SrsError> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        let mut input = BufReader::with_capacity(ARCHIVE_BUFFER, file);

        let mut head = [0u8; ARCHIVE_HEADER];
        if len < ARCHIVE_HEADER as u64 {
            return Err(SrsError::Truncated);
        }
        input.read_exact(&mut head)?;
        if &head[..8] != ARCHIVE_MAGIC {
            return Err(SrsError::BadMagic);
        }
        let version = u32::from_le_bytes(head[8..12].try_into().expect("4 bytes"));
        if version != ARCHIVE_VERSION {
            return Err(SrsError::BadVersion(version));
        }
        let power = u32::from_le_bytes(head[12..16].try_into().expect("4 bytes"));
        let count = u64::from_le_bytes(head[16..24].try_into().expect("8 bytes"));
        // The power is capped before it is shifted. Without the cap,
        // `count * 64` below wraps to zero for any power at or above 58, the
        // length check degenerates to `len != 280`, and a 280-byte header with
        // no point block at all reaches `Vec::with_capacity(1 << 58)`.
        if power > MAX_POWER || count != 1u64 << power {
            return Err(SrsError::BadSection("archive G1 count is not 2^power"));
        }
        if len != ARCHIVE_HEADER as u64 + count * 64 {
            return Err(SrsError::Truncated);
        }

        // G1 powers are indexed 0..count, so the two G2 points continue the
        // numbering rather than colliding with power 0 and power 1.
        let count = count as usize;
        let g2_gen = G2Affine::from_bytes(&head[24..152].try_into().expect("128 bytes"))
            .ok_or(SrsError::InvalidPoint { index: count })?;
        let g2_tau = G2Affine::from_bytes(&head[152..280].try_into().expect("128 bytes"))
            .ok_or(SrsError::InvalidPoint { index: count + 1 })?;

        let g1 = ptau::read_canonical_g1(&mut input, count)?;

        Ok(Srs { g1, g2_gen, g2_tau })
    }

    /// The G1 powers, `[x^0]_1` first.
    pub fn g1(&self) -> &[G1Affine] {
        &self.g1
    }

    /// `[1]_2`.
    pub fn g2_gen(&self) -> G2Affine {
        self.g2_gen
    }

    /// `[x]_2`.
    pub fn g2_tau(&self) -> G2Affine {
        self.g2_tau
    }

    /// Everything a verifier may require, and nothing more.
    pub fn verifier(&self) -> SrsVerifier {
        SrsVerifier {
            g1_gen: self.g1[0],
            g2_gen: self.g2_gen,
            g2_tau: self.g2_tau,
        }
    }

    /// `log2` of the power count, which the archive stores instead of the
    /// count so a malformed one cannot claim a non-power-of-two length.
    fn power(&self) -> u32 {
        self.g1.len().trailing_zeros()
    }
}

/// The only SRS material a verifier path may require.
///
/// Frozen in S07. A verifier that wants more than these three points is
/// asking for the prover's SRS, and that is a design error rather than a
/// missing accessor.
///
/// S07 also specified a `digest: [u8; 32]` field here, absorbed in statement
/// binding. It was dropped with the rest of the SRS hashing; see this crate's
/// module docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrsVerifier {
    pub g1_gen: G1Affine,
    pub g2_gen: G2Affine,
    pub g2_tau: G2Affine,
}

/// Canonical little-endian, per master rule 3: the same 64 and 128 byte point
/// encodings `curve` writes, concatenated in declaration order.
///
/// Hand-written, so no derive macro enters the build and so deserialisation
/// goes back through the validating `from_bytes` rather than reconstructing
/// coordinates. The wire shape is ten 32-byte words because that is the widest
/// array `serde` implements without its `alloc` feature, and the workspace
/// keeps `serde` at `default-features = false` for the guest.
const VERIFIER_WORDS: usize = 320 / 32;

impl serde::Serialize for SrsVerifier {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut flat = [0u8; 320];
        flat[..64].copy_from_slice(&self.g1_gen.to_bytes());
        flat[64..192].copy_from_slice(&self.g2_gen.to_bytes());
        flat[192..].copy_from_slice(&self.g2_tau.to_bytes());

        let mut words = [[0u8; 32]; VERIFIER_WORDS];
        for (word, src) in words.iter_mut().zip(flat.chunks_exact(32)) {
            word.copy_from_slice(src);
        }
        serde::Serialize::serialize(&words, s)
    }
}

impl<'de> serde::Deserialize<'de> for SrsVerifier {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<SrsVerifier, D::Error> {
        let words = <[[u8; 32]; VERIFIER_WORDS] as serde::Deserialize>::deserialize(d)?;
        let mut flat = [0u8; 320];
        for (dst, word) in flat.chunks_exact_mut(32).zip(words.iter()) {
            dst.copy_from_slice(word);
        }

        let bad = |what: &str| {
            <D::Error as serde::de::Error>::custom(format!(
                "SrsVerifier: {what} is not a valid point"
            ))
        };
        Ok(SrsVerifier {
            g1_gen: G1Affine::from_bytes(&flat[..64].try_into().expect("64 bytes"))
                .ok_or_else(|| bad("g1_gen"))?,
            g2_gen: G2Affine::from_bytes(&flat[64..192].try_into().expect("128 bytes"))
                .ok_or_else(|| bad("g2_gen"))?,
            g2_tau: G2Affine::from_bytes(&flat[192..].try_into().expect("128 bytes"))
                .ok_or_else(|| bad("g2_tau"))?,
        })
    }
}

// ---------------------------------------------------------------------------
// The archive
// ---------------------------------------------------------------------------

/// No BN254 powers-of-tau ceremony goes past 28.
///
/// This is a cap on a *declared* value, not a protocol constant. Both readers
/// take the power from the file, and both then compute a section length from
/// it; the cap is what keeps `count * 64` from wrapping `u64` and handing a
/// short file a length check it passes. `1 << 31` powers would already be a
/// 137 GB section.
pub(crate) const MAX_POWER: u32 = 30;

/// `docs/spec/srs.md` §5. Changing any of these is an archive-format change.
const ARCHIVE_MAGIC: &[u8; 8] = b"APOGESRS";
const ARCHIVE_VERSION: u32 = 1;
/// magic 8, version 4, power 4, count 8, two G2 points 128 each.
const ARCHIVE_HEADER: usize = 8 + 4 + 4 + 8 + 128 + 128;
const ARCHIVE_BUFFER: usize = 1 << 20;

// ---------------------------------------------------------------------------
// Local randomness
// ---------------------------------------------------------------------------

/// `count` uniform-enough `Fr` values from the OS.
///
/// 31 bytes each, zero-extended: `2^248 < p`, so every draw is canonical
/// without rejection and the loop cannot spin. This is local file validation,
/// never a protocol challenge — those come from the transcript and only from
/// the transcript.
fn random_scalars(count: usize) -> Result<Vec<Fr>, SrsError> {
    let mut raw = vec![0u8; count * 31];
    File::open("/dev/urandom")?.read_exact(&mut raw)?;
    Ok(raw
        .chunks_exact(31)
        .map(|c| {
            let mut le = [0u8; 32];
            le[..31].copy_from_slice(c);
            Fr::from_bytes(&le).expect("31 bytes is below 2^248 < p")
        })
        .collect())
}
