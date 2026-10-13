//! `Fr` arithmetic against arkworks' Montgomery field over the same modulus,
//! element for element.
//!
//! Both libraries are handed the same canonical bytes, so the ratio is a
//! statement about the implementations and not about the inputs.

// `#[derive(MontConfig)]` emits a `cfg(feature = "asm")` this crate does not
// declare.
#![allow(unexpected_cfgs)]

use std::hint::black_box;

use ark_ff::fields::{Fp256, MontBackend, MontConfig};
use ark_ff::Field as _;
use test_support::Rng;

use crate::timing::{best, next_canonical, ns_per_op, REPS, SEED};

/// arkworks' field over `Fr`'s modulus, derived from it.
#[derive(MontConfig)]
#[modulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[generator = "5"]
struct FrConfig;
type ArkFr = Fp256<MontBackend<FrConfig, 4>>;

const N: usize = 1 << 20;
/// One inversion is ~380 muls; `N` of them would take minutes.
const N_INVERSE: usize = 1 << 14;

pub fn run() {
    let mut rng = Rng::new(SEED);
    let bytes: Vec<[u8; 32]> = (0..N).map(|_| next_canonical(&mut rng)).collect();
    let bytes_b: Vec<[u8; 32]> = (0..N).map(|_| next_canonical(&mut rng)).collect();

    let xs: Vec<field::Fr> = bytes
        .iter()
        .map(|b| field::Fr::from_bytes(b).unwrap())
        .collect();
    let ys: Vec<field::Fr> = bytes_b
        .iter()
        .map(|b| field::Fr::from_bytes(b).unwrap())
        .collect();
    let axs: Vec<ArkFr> = bytes
        .iter()
        .map(|b| ark_ff::PrimeField::from_le_bytes_mod_order(b))
        .collect();
    let ays: Vec<ArkFr> = bytes_b
        .iter()
        .map(|b| ark_ff::PrimeField::from_le_bytes_mod_order(b))
        .collect();

    let mut out = vec![field::Fr::ZERO; N];
    let mut aout = vec![ArkFr::from(0u64); N];

    let mul = best(|| {
        for i in 0..N {
            out[i] = xs[i] * ys[i];
        }
        black_box(&out);
    });
    let amul = best(|| {
        for i in 0..N {
            aout[i] = axs[i] * ays[i];
        }
        black_box(&aout);
    });

    let sqr = best(|| {
        for i in 0..N {
            out[i] = xs[i].square();
        }
        black_box(&out);
    });
    let asqr = best(|| {
        for i in 0..N {
            aout[i] = axs[i].square();
        }
        black_box(&aout);
    });

    let inv = best(|| {
        for i in 0..N_INVERSE {
            out[i] = xs[i].inverse().unwrap();
        }
        black_box(&out);
    });
    let ainv = best(|| {
        for i in 0..N_INVERSE {
            aout[i] = axs[i].inverse().unwrap();
        }
        black_box(&aout);
    });

    let batch = best(|| {
        out.copy_from_slice(&xs);
        field::batch_inverse(&mut out);
        black_box(&out);
    });
    let abatch = best(|| {
        aout.copy_from_slice(&axs);
        ark_ff::fields::batch_inversion(&mut aout);
        black_box(&aout);
    });

    println!("Fr microbenchmarks (best of {REPS}); ns/op");
    println!(
        "{:<28} {:>12} {:>12} {:>8}",
        "op", "ours", "arkworks", "ratio"
    );
    let rows = [
        ("mul", N, mul, amul),
        ("square", N, sqr, asqr),
        ("inverse", N_INVERSE, inv, ainv),
        ("batch_inverse / element", N, batch, abatch),
    ];
    for (name, n, ours, ark) in rows {
        let (o, a) = (ns_per_op(ours, n), ns_per_op(ark, n));
        println!("{:<28} {:>12.2} {:>12.2} {:>8.2}", name, o, a, o / a);
    }
    println!("n = {N} (inverse: {N_INVERSE}).");
}
