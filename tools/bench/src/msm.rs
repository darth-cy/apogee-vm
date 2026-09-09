//! S07 acceptance 9 and 10: the MSM performance gate.
//!
//! Two measurements at `2^22` points, the master trace-height ceiling, over
//! **real ceremony bases** read from the powers-of-tau file:
//!
//! 1. the owned general `msm` against `ark_ec::VariableBaseMSM`, on the same
//!    machine, the same bases and the same scalars, in one process. The gate
//!    is 2x;
//! 2. the small-scalar path against the general one on `u32`-bounded scalars,
//!    where the gate is simply that the small path wins.
//!
//! Both arkworks and this workspace parallelise with rayon — `ark-ec` and
//! `ark-ff` carry their `parallel` feature in the workspace manifest — so the
//! comparison is between two implementations rather than between a threaded
//! one and a serial one.
//!
//! Nothing here asserts a threshold. A number that must not regress belongs in
//! a test; this prints what the machine did, and the S07 handoff records it.

use std::path::PathBuf;
use std::time::Instant;

use ark_ec::{CurveGroup, VariableBaseMSM};
use curve::msm::{msm, msm_small_u32};
use curve::G1Affine;
use field::Fr;
use srs::Srs;
use test_support::Rng;

use crate::timing::{ms, next_canonical, Best, REPS, SEED};

/// The master's trace-height ceiling, which is the size the prover's MSM runs
/// at.
const LOG_N: u32 = 22;

/// Bases come from the real ceremony, because "fast on random points" is not
/// the claim anyone cares about.
fn ceremony_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/ptau/ppot_0080_24.ptau")
}

pub fn run() {
    let n = 1usize << LOG_N;
    let path = ceremony_path();
    if !path.exists() {
        println!("no ceremony file at {}", path.display());
        println!("this routine measures the MSM over real SRS bases; it does not substitute random ones.");
        return;
    }

    // -- setup, outside every timed region --------------------------------
    let t = Instant::now();
    let srs = Srs::from_ptau(&path, LOG_N).expect("the ceremony file ingests");
    let bases: &[G1Affine] = srs.g1();
    println!(
        "setup: {} ceremony powers read and validated in {:.0} ms",
        bases.len(),
        ms(t.elapsed())
    );

    let mut rng = Rng::new(SEED);
    let scalars: Vec<Fr> = (0..n)
        .map(|_| Fr::from_bytes(&next_canonical(&mut rng)).expect("canonical by construction"))
        .collect();
    let small: Vec<u32> = (0..n).map(|_| rng.next_u64() as u32).collect();

    let ark_bases: Vec<ark_bn254::G1Affine> = bases.iter().map(to_ark_g1).collect();
    let ark_scalars: Vec<ark_bn254::Fr> = scalars.iter().map(to_ark_fr).collect();

    // The window rule, restated for the record. This is a copy of
    // `curve::msm`'s private heuristic; it is printed, never used, so a drift
    // misreports a line rather than changing a measurement.
    let w = (LOG_N as usize * 69) / 100 + 2;
    println!(
        "config: n = 2^{LOG_N}, window width {w}, {} windows for Fr and {} for u32",
        255usize.div_ceil(w),
        33usize.div_ceil(w)
    );

    // -- both implementations agree before either is timed ----------------
    let ours = msm(bases, &scalars).expect("equal lengths").to_affine();
    let theirs = ark_bn254::G1Projective::msm(&ark_bases, &ark_scalars)
        .expect("equal lengths")
        .into_affine();
    assert_eq!(
        ours.to_bytes(),
        ark_g1_bytes(&theirs),
        "the two MSMs disagree; there is nothing here worth timing"
    );
    let small_ours = msm_small_u32(bases, &small).expect("equal lengths");
    let lifted: Vec<Fr> = small.iter().map(|s| Fr::from_u64(*s as u64)).collect();
    assert_eq!(
        small_ours,
        msm(bases, &lifted).expect("equal lengths"),
        "the small path disagrees with the general one"
    );

    // -- acceptance 9: general path against arkworks ----------------------
    let mut mine = Best::new();
    let mut ark = Best::new();
    for _ in 0..REPS {
        let t = Instant::now();
        let a = msm(bases, &scalars).expect("equal lengths");
        mine.record(t.elapsed());

        let t = Instant::now();
        let b = ark_bn254::G1Projective::msm(&ark_bases, &ark_scalars).expect("equal lengths");
        ark.record(t.elapsed());

        // Keep both results alive, so neither call can be optimised away.
        assert_eq!(a.to_affine().to_bytes(), ark_g1_bytes(&b.into_affine()));
    }

    // -- acceptance 10: the small path against the general one ------------
    let general_on_small = crate::timing::best(|| {
        msm(bases, &lifted).expect("equal lengths");
    });
    let small_path = crate::timing::best(|| {
        msm_small_u32(bases, &small).expect("equal lengths");
    });

    println!("\nbest of {REPS}, n = 2^{LOG_N} over real ceremony bases\n");
    println!("| measurement | ours (ms) | reference (ms) | ratio |");
    println!("| --- | --- | --- | --- |");
    println!(
        "| general msm, random Fr | {:.0} | {:.0} | {:.2}x |",
        ms(mine.get()),
        ms(ark.get()),
        mine.get().as_secs_f64() / ark.get().as_secs_f64()
    );
    println!(
        "| small path, u32 scalars | {:.0} | {:.0} | {:.2}x |",
        ms(small_path),
        ms(general_on_small),
        small_path.as_secs_f64() / general_on_small.as_secs_f64()
    );
    println!(
        "\nreference is ark-bn254 VariableBaseMSM on row one and the owned general\n\
         path on row two; both rows share this run's bases and scalars."
    );
}

// ---------------------------------------------------------------------------
// The arkworks bridge. Every crossing goes through the canonical wire form, so
// a mismatch is a mismatch of values rather than of representations.
// ---------------------------------------------------------------------------

fn to_ark_fq(x: &curve::Fq) -> ark_bn254::Fq {
    ark_ff::PrimeField::from_le_bytes_mod_order(&x.to_bytes())
}

fn to_ark_g1(p: &G1Affine) -> ark_bn254::G1Affine {
    if p.infinity {
        ark_ec::AffineRepr::zero()
    } else {
        ark_bn254::G1Affine::new_unchecked(to_ark_fq(&p.x), to_ark_fq(&p.y))
    }
}

fn to_ark_fr(x: &Fr) -> ark_bn254::Fr {
    ark_ff::PrimeField::from_le_bytes_mod_order(&x.to_bytes())
}

fn ark_g1_bytes(p: &ark_bn254::G1Affine) -> [u8; 64] {
    let mut b = [0u8; 64];
    if *p == <ark_bn254::G1Affine as ark_ec::AffineRepr>::zero() {
        return b;
    }
    let f = |x: &ark_bn254::Fq| -> [u8; 32] {
        let v = ark_ff::BigInteger::to_bytes_le(&ark_ff::PrimeField::into_bigint(*x));
        let mut o = [0u8; 32];
        o.copy_from_slice(&v);
        o
    };
    b[..32].copy_from_slice(&f(&p.x));
    b[32..].copy_from_slice(&f(&p.y));
    b
}
