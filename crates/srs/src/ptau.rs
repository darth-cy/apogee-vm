//! The snarkjs `.ptau` container, and the archive's point block.
//!
//! `docs/spec/srs.md` §2-§4 is the normative description; this is the reader.
//! Layout, from the format itself:
//!
//! ```text
//!   0   4   magic "ptau"
//!   4   4   version, u32 LE, 1
//!   8   4   section count, u32 LE
//!  12   ..  sections: [ id u32 LE | size u64 LE | payload ]
//!
//!   section 1  header:  n8 u32 | q (n8 bytes LE) | power u32 | ceremonyPower u32
//!   section 2  tauG1:   2^(power+1) - 1 points
//!   section 3  tauG2:   2^power points
//! ```
//!
//! Points are **little-endian Montgomery**, uncompressed affine: 64 bytes
//! `x || y` for G1 and 128 bytes `x.c0 || x.c1 || y.c0 || y.c1` for G2, each
//! coordinate 32 bytes holding `coord * R mod q`. That is ffjavascript's
//! internal representation written straight out (`toRprLEM`), and it is *not*
//! the canonical form every other file in this workspace uses — which is the
//! single thing about this format worth remembering.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use rayon::prelude::*;

use curve::{Fq, G1Affine, G2Affine};

use crate::{Srs, SrsError, MAX_POWER};

/// The only container version snarkjs has ever written.
const PTAU_VERSION: u32 = 1;

/// A prepared ceremony file has 11 sections. The cap exists so a corrupt
/// section count cannot turn the table scan into a long walk off the end.
const MAX_SECTIONS: u32 = 64;

/// Points decoded per read. 4 MiB of G1 at a time keeps the buffer small
/// while giving rayon enough work per chunk to be worth the fan-out.
const POINTS_PER_CHUNK: usize = 1 << 16;

/// See [`crate::Srs::from_ptau`].
pub(crate) fn from_ptau(path: &Path, power: u32) -> Result<Srs, SrsError> {
    let file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut input = BufReader::with_capacity(1 << 20, file);

    // -- prologue ----------------------------------------------------------
    if file_len < 12 {
        return Err(SrsError::Truncated);
    }
    let mut prologue = [0u8; 12];
    input.read_exact(&mut prologue)?;
    if &prologue[..4] != b"ptau" {
        return Err(SrsError::BadMagic);
    }
    let version = le_u32(&prologue[4..8]);
    if version != PTAU_VERSION {
        return Err(SrsError::BadVersion(version));
    }
    let sections = le_u32(&prologue[8..12]);
    if sections > MAX_SECTIONS {
        return Err(SrsError::BadSection("implausible section count"));
    }

    // -- section table -----------------------------------------------------
    // `pos <= file_len` is an invariant of this loop: each step proves the
    // 12-byte header and then the payload both fit before advancing past them.
    let mut table: Vec<(u32, u64, u64)> = Vec::with_capacity(sections as usize);
    let mut pos = 12u64;
    for _ in 0..sections {
        if file_len - pos < 12 {
            return Err(SrsError::Truncated);
        }
        input.seek(SeekFrom::Start(pos))?;
        let mut head = [0u8; 12];
        input.read_exact(&mut head)?;
        pos += 12;
        let size = le_u64(&head[4..12]);
        if file_len - pos < size {
            return Err(SrsError::Truncated);
        }
        table.push((le_u32(&head[..4]), pos, size));
        pos += size;
    }

    // -- header ------------------------------------------------------------
    let (header_at, header_size) = unique(&table, 1, "header")?;
    if header_size != 44 {
        return Err(SrsError::BadSection("header is not 44 bytes"));
    }
    input.seek(SeekFrom::Start(header_at))?;
    let mut header = [0u8; 44];
    input.read_exact(&mut header)?;
    // n8 is the field-element width; anything but 32 is another curve.
    if le_u32(&header[..4]) != 32 || header[4..36] != fq_modulus_le() {
        return Err(SrsError::WrongCurve);
    }
    let file_power = le_u32(&header[36..40]);
    // header[40..44] is ceremonyPower — provenance, not structure.
    if file_power > MAX_POWER {
        return Err(SrsError::BadSection("declared power is implausible"));
    }
    if power > file_power {
        return Err(SrsError::PowerTooLarge {
            requested: power,
            available: file_power,
        });
    }
    // `[x]_2` is tauG2[1], so a ceremony with one G2 power is unusable here.
    if file_power < 1 {
        return Err(SrsError::BadSection("tauG2 holds no [x]_2"));
    }

    // -- section sizes are a function of the declared power ----------------
    let (tau_g1_at, tau_g1_size) = unique(&table, 2, "tauG1")?;
    if tau_g1_size != ((2u64 << file_power) - 1) * 64 {
        return Err(SrsError::BadSection("tauG1 size disagrees with the power"));
    }
    let (tau_g2_at, tau_g2_size) = unique(&table, 3, "tauG2")?;
    if tau_g2_size != (1u64 << file_power) * 128 {
        return Err(SrsError::BadSection("tauG2 size disagrees with the power"));
    }

    // -- points ------------------------------------------------------------
    let r_inv = montgomery_r_inverse();
    let count = 1usize << power;

    input.seek(SeekFrom::Start(tau_g1_at))?;
    let g1 = read_montgomery_g1(&mut input, count, &r_inv)?;

    input.seek(SeekFrom::Start(tau_g2_at))?;
    let mut g2 = [0u8; 256];
    input.read_exact(&mut g2)?;
    let g2_gen =
        g2_from_montgomery(&g2[..128], &r_inv).ok_or(SrsError::InvalidPoint { index: count })?;
    let g2_tau = g2_from_montgomery(&g2[128..], &r_inv)
        .ok_or(SrsError::InvalidPoint { index: count + 1 })?;

    Ok(Srs { g1, g2_gen, g2_tau })
}

/// The one section with this id, or which way the file is malformed.
fn unique(table: &[(u32, u64, u64)], id: u32, what: &'static str) -> Result<(u64, u64), SrsError> {
    let mut hits = table.iter().filter(|(section, _, _)| *section == id);
    let first = hits.next().ok_or(SrsError::BadSection(what))?;
    if hits.next().is_some() {
        return Err(SrsError::BadSection(what));
    }
    Ok((first.1, first.2))
}

// ---------------------------------------------------------------------------
// Point blocks
//
// Two readers, one for each encoding, rather than one reader parameterised by
// which. They are the same nine-line chunk loop over `BufReader<File>`; the
// three lines that differ are the point of each function.
// ---------------------------------------------------------------------------

/// `count` G1 points in the `.ptau` Montgomery encoding.
fn read_montgomery_g1(
    input: &mut BufReader<File>,
    count: usize,
    r_inv: &Fq,
) -> Result<Vec<G1Affine>, SrsError> {
    let mut points = Vec::with_capacity(count);
    let mut buf = vec![0u8; POINTS_PER_CHUNK * 64];
    while points.len() < count {
        let take = POINTS_PER_CHUNK.min(count - points.len());
        input.read_exact(&mut buf[..take * 64])?;
        let base = points.len();
        let decoded: Result<Vec<G1Affine>, usize> = buf[..take * 64]
            .par_chunks_exact(64)
            .enumerate()
            .map(|(i, raw)| g1_from_montgomery(raw, r_inv).ok_or(base + i))
            .collect();
        points.extend(decoded.map_err(|index| SrsError::InvalidPoint { index })?);
    }
    Ok(points)
}

/// `count` G1 points in the canonical encoding the archive stores.
pub(crate) fn read_canonical_g1(
    input: &mut BufReader<File>,
    count: usize,
) -> Result<Vec<G1Affine>, SrsError> {
    let mut points = Vec::with_capacity(count);
    let mut buf = vec![0u8; POINTS_PER_CHUNK * 64];
    while points.len() < count {
        let take = POINTS_PER_CHUNK.min(count - points.len());
        input.read_exact(&mut buf[..take * 64])?;
        let base = points.len();
        let decoded: Result<Vec<G1Affine>, usize> = buf[..take * 64]
            .par_chunks_exact(64)
            .enumerate()
            .map(|(i, raw)| {
                let fixed: &[u8; 64] = raw.try_into().expect("a 64-byte chunk");
                G1Affine::from_bytes(fixed).ok_or(base + i)
            })
            .collect();
        points.extend(decoded.map_err(|index| SrsError::InvalidPoint { index })?);
    }
    Ok(points)
}

// ---------------------------------------------------------------------------
// Montgomery decoding
// ---------------------------------------------------------------------------

/// `R^-1 mod q`, with `R = 2^256` the Montgomery radix.
///
/// Derived rather than pinned as a literal: `constants::FQ_R` *is* `R mod q`
/// as an integer, so reading it as a canonical `Fq` and inverting gives
/// `R^-1` with nothing new to get wrong. One inversion per ingestion.
fn montgomery_r_inverse() -> Fq {
    let mut le = [0u8; 32];
    for (i, limb) in constants::FQ_R.iter().enumerate() {
        le[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
    }
    Fq::from_bytes(&le)
        .expect("R mod q is reduced by construction")
        .inverse()
        .expect("R mod q is nonzero")
}

/// One coordinate: read `coord * R mod q` as a canonical `Fq`, multiply by
/// `R^-1`, and write the canonical bytes back out. `None` if the stored value
/// is not below `q` — which is the canonicity rejection the ceremony file has
/// to pass just like anything else.
fn canonicalize(src: &[u8], dst: &mut [u8], r_inv: &Fq) -> Option<()> {
    let mut le = [0u8; 32];
    le.copy_from_slice(src);
    dst.copy_from_slice(&(Fq::from_bytes(&le)? * r_inv).to_bytes());
    Some(())
}

/// Decode a G1 point, then hand it to S05's validating `from_bytes`.
///
/// Re-encoding into the canonical form rather than building the struct
/// directly is what makes "S05 `from_bytes` validation semantics apply to
/// every point" literally true: there is one decoder, and this is a translator
/// in front of it.
fn g1_from_montgomery(bytes: &[u8], r_inv: &Fq) -> Option<G1Affine> {
    let mut canonical = [0u8; 64];
    for (src, dst) in bytes.chunks_exact(32).zip(canonical.chunks_exact_mut(32)) {
        canonicalize(src, dst, r_inv)?;
    }
    G1Affine::from_bytes(&canonical)
}

/// The same for G2, whose four coordinate halves are stored in the same order
/// `G2Affine::to_bytes` writes them.
fn g2_from_montgomery(bytes: &[u8], r_inv: &Fq) -> Option<G2Affine> {
    let mut canonical = [0u8; 128];
    for (src, dst) in bytes.chunks_exact(32).zip(canonical.chunks_exact_mut(32)) {
        canonicalize(src, dst, r_inv)?;
    }
    G2Affine::from_bytes(&canonical)
}

// ---------------------------------------------------------------------------
// Little-endian scalars
// ---------------------------------------------------------------------------

fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().expect("4 bytes"))
}

fn le_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().expect("8 bytes"))
}

/// `q` as the header stores it: 32 canonical little-endian bytes.
fn fq_modulus_le() -> [u8; 32] {
    let mut le = [0u8; 32];
    for (i, limb) in constants::FQ_MODULUS.iter().enumerate() {
        le[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
    }
    le
}
