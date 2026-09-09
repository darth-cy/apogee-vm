//! Neither reader panics on a hostile file.
//!
//! Every other test in this crate needs the gitignored ceremony assets. This
//! one builds its own bytes, so it is the only `srs` suite CI actually runs —
//! and it is the one that matters most for a parser, because "returns an
//! error" is a claim about *all* inputs and the rejection-class tests only
//! cover the ones somebody thought of.
//!
//! The assertion is deliberately weak: no panic, and any `Ok` is a structurally
//! sound SRS. A fuzzer that also predicted the right error would be a second
//! parser, and a wrong second parser is worse than none.

mod common;

use std::fs;

use curve::{G1Affine, G2Affine};
use srs::Srs;
use test_support::Rng;

/// Enough to walk the whole rejection surface many times over: the container
/// has four fields worth corrupting before the section table even starts.
const ROUNDS: usize = 20_000;

/// Semi-structured `.ptau` containers: a real prologue, a plausible section
/// table, then sizes and payloads chosen to sit on every boundary the reader
/// has — including `u64::MAX`-adjacent sizes, which are what an overflow in
/// the table walk would need.
#[test]
fn from_ptau_never_panics() {
    let mut rng = Rng::new(20260960);
    let path = common::scratch("fuzz.ptau");

    for _ in 0..ROUNDS {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(b"ptau");
        bytes.extend_from_slice(&1u32.to_le_bytes());

        let sections = (rng.next_u64() % 6) as u32;
        bytes.extend_from_slice(&sections.to_le_bytes());
        for _ in 0..sections {
            bytes.extend_from_slice(&((rng.next_u64() % 5) as u32).to_le_bytes());
            let size = match rng.next_u64() % 4 {
                // A well-formed header length, a short payload, a size that is
                // one wrapping-add away from the end of the address space, and
                // a merely enormous one.
                0 => 44,
                1 => rng.next_u64() % 200,
                2 => u64::MAX - (rng.next_u64() % 4),
                _ => rng.next_u64() % (1 << 40),
            };
            bytes.extend_from_slice(&size.to_le_bytes());
            for _ in 0..size.min(300) {
                bytes.push(rng.next_u64() as u8);
            }
        }

        // Cut anywhere, including past the end, then sometimes corrupt a byte
        // so the prologue itself is in play.
        let cut = (rng.next_u64() as usize) % (bytes.len() + 4);
        bytes.truncate(cut);
        if rng.next_u64().is_multiple_of(8) && !bytes.is_empty() {
            let at = (rng.next_u64() as usize) % bytes.len();
            bytes[at] ^= 0xff;
        }

        fs::write(&path, &bytes).expect("writing the scratch file");
        // Powers past the container's cap are part of the input too.
        let power = (rng.next_u64() % 34) as u32;
        if let Ok(srs) = Srs::from_ptau(&path, power) {
            assert_eq!(srs.g1().len(), 1usize << power);
        }
    }
}

/// Every declared power, against a header-only file.
///
/// This is the regression test for a real bug: `count * 64` wraps `u64` for
/// any power at or above 58, which turned the length check into `len != 280`
/// and let a 280-byte file with no point block at all reach
/// `Vec::with_capacity(1 << 58)`. Random bit flips will not find that — it
/// needs `power` and `count` moved together — so it gets its own sweep.
#[test]
fn every_declared_power_is_rejected_on_a_header_only_archive() {
    let path = common::scratch("powers.srs");
    for power in 0..64u32 {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(b"APOGESRS");
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&power.to_le_bytes());
        bytes.extend_from_slice(&(1u64 << power).to_le_bytes());
        bytes.extend_from_slice(&G2Affine::GENERATOR.to_bytes());
        bytes.extend_from_slice(&G2Affine::GENERATOR.to_bytes());
        assert_eq!(bytes.len(), 280, "header only, no point block");

        fs::write(&path, &bytes).expect("writing the scratch file");
        // Power 0 is the one file here that is complete: one power, and the
        // header says so, so it is short by exactly 64 bytes.
        assert!(
            Srs::load(&path).is_err(),
            "a header-only archive claiming 2^{power} powers loaded"
        );
    }
}

/// The archive reader, over its own header rather than the container's.
#[test]
fn load_never_panics() {
    let mut rng = Rng::new(20260961);
    let path = common::scratch("fuzz.srs");

    // A structurally valid one-power archive, which every round then damages:
    // starting from noise would almost never get past the magic.
    let mut good: Vec<u8> = Vec::new();
    good.extend_from_slice(b"APOGESRS");
    good.extend_from_slice(&1u32.to_le_bytes());
    good.extend_from_slice(&0u32.to_le_bytes());
    good.extend_from_slice(&1u64.to_le_bytes());
    good.extend_from_slice(&[0u8; 256]);
    good.extend_from_slice(&G1Affine::GENERATOR.to_bytes());

    for _ in 0..ROUNDS {
        let mut bytes = good.clone();
        for _ in 0..1 + rng.next_u64() % 4 {
            let at = (rng.next_u64() as usize) % bytes.len();
            bytes[at] ^= rng.next_u64() as u8;
        }
        match rng.next_u64() % 4 {
            0 => bytes.truncate((rng.next_u64() as usize) % (bytes.len() + 1)),
            1 => bytes.extend_from_slice(&[0u8; 17]),
            _ => {}
        }

        fs::write(&path, &bytes).expect("writing the scratch file");
        if let Ok(srs) = Srs::load(&path) {
            assert!(srs.g1().len().is_power_of_two());
        }
    }
}
