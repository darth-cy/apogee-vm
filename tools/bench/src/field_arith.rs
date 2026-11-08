//! `Fp` and `Fp2` arithmetic against arkworks' fields over the same prime and
//! the same extension, element for element.
//!
//! Both libraries are handed the same canonical values, so the ratio is a
//! statement about the implementations and not about the inputs.

// `#[derive(MontConfig)]` emits a `cfg(feature = "asm")` this crate does not
// declare.
#![allow(unexpected_cfgs)]

use std::hint::black_box;

use ark_ff::{Field as _, Fp2Config, Fp64, MontBackend, MontConfig, MontFp};
use field_a64_c5::{Fp, Fp2};
use test_support::Rng;

use crate::timing::{best, next_fp2, ns_per_op, REPS, SEED};

/// arkworks' field over the A64-C5 prime, derived from it.
#[derive(MontConfig)]
#[modulus = "18446744073709551557"]
#[generator = "2"]
struct A64C5Config;
type ArkFp = Fp64<MontBackend<A64C5Config, 1>>;

/// arkworks' `F_p[x]/(x^2 − 2)`.
struct Fp2Cfg;
impl Fp2Config for Fp2Cfg {
    type Fp = ArkFp;
    const NONRESIDUE: ArkFp = MontFp!("2");
    const FROBENIUS_COEFF_FP2_C1: &[ArkFp] = &[MontFp!("1"), MontFp!("-1")];
}
type ArkFp2 = ark_ff::Fp2<Fp2Cfg>;

const N: usize = 1 << 20;
const N_INVERSE: usize = 1 << 16;

pub fn run() {
    let mut rng = Rng::new(SEED);
    let xs: Vec<Fp2> = (0..N).map(|_| next_fp2(&mut rng)).collect();
    let ys: Vec<Fp2> = (0..N).map(|_| next_fp2(&mut rng)).collect();
    let ark = |x: &Fp2| ArkFp2::new(x.c0.to_u64().into(), x.c1.to_u64().into());
    let (axs, ays): (Vec<ArkFp2>, Vec<ArkFp2>) =
        (xs.iter().map(ark).collect(), ys.iter().map(ark).collect());

    let mut base = vec![Fp::ZERO; N];
    let mut abase = vec![ArkFp::from(0u64); N];
    let mut out = vec![Fp2::ZERO; N];
    let mut aout = vec![ArkFp2::from(0u64); N];

    let mul = best(|| {
        for i in 0..N {
            base[i] = xs[i].c0 * ys[i].c0;
        }
        black_box(&base);
    });
    let amul = best(|| {
        for i in 0..N {
            abase[i] = axs[i].c0 * ays[i].c0;
        }
        black_box(&abase);
    });
    let mul2 = best(|| {
        for i in 0..N {
            out[i] = xs[i] * ys[i];
        }
        black_box(&out);
    });
    let amul2 = best(|| {
        for i in 0..N {
            aout[i] = axs[i] * ays[i];
        }
        black_box(&aout);
    });
    let mixed = best(|| {
        for i in 0..N {
            out[i] = xs[i] * ys[i].c0;
        }
        black_box(&out);
    });
    let amixed = best(|| {
        for i in 0..N {
            aout[i] = axs[i];
            aout[i].mul_assign_by_basefield(&ays[i].c0);
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

    println!("Fp and Fp2 microbenchmarks (best of {REPS}); ns/op");
    println!(
        "{:<28} {:>12} {:>12} {:>8}",
        "op", "ours", "arkworks", "ratio"
    );
    let rows = [
        ("Fp mul", N, mul, amul),
        ("Fp2 mul", N, mul2, amul2),
        ("Fp2 · Fp", N, mixed, amixed),
        ("Fp2 inverse", N_INVERSE, inv, ainv),
    ];
    for (name, n, ours, ark) in rows {
        let (o, a) = (ns_per_op(ours, n), ns_per_op(ark, n));
        println!("{:<28} {:>12.2} {:>12.2} {:>8.2}", name, o, a, o / a);
    }
    println!("n = {N} (inverse: {N_INVERSE}).");
}
