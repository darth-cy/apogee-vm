//! Comparative microbenchmark for `Fr` against ark-bn254.
//!
//!     cargo run --release -p bench
//!
//! Numbers are internal only. Machine-dependent; make no public claims.

use std::hint::black_box;
use std::time::{Duration, Instant};

use ark_ff::Field as _;

const N: usize = 1 << 20;
const N_INVERSE: usize = 1 << 14; // one inversion is ~380 muls; 2^20 would take minutes
const REPS: usize = 3;
const SEED: u64 = 20260903;

struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Canonical bytes of a nonzero element, so both libraries get the same value.
    fn next_canonical(&mut self) -> [u8; 32] {
        loop {
            let mut b = [0u8; 32];
            for i in 0..4 {
                b[8 * i..8 * i + 8].copy_from_slice(&self.next_u64().to_le_bytes());
            }
            b[31] &= 0x3f;
            match field::Fr::from_bytes(&b) {
                Some(x) if x != field::Fr::ZERO => return b,
                _ => continue,
            }
        }
    }
}

/// Best of `REPS` runs, to blunt scheduler noise.
fn best<F: FnMut()>(mut f: F) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..REPS {
        let t = Instant::now();
        f();
        best = best.min(t.elapsed());
    }
    best
}

fn ns_per_op(d: Duration, ops: usize) -> f64 {
    d.as_secs_f64() * 1e9 / ops as f64
}

fn main() {
    let mut rng = Rng(SEED);
    let bytes: Vec<[u8; 32]> = (0..N).map(|_| rng.next_canonical()).collect();
    let bytes_b: Vec<[u8; 32]> = (0..N).map(|_| rng.next_canonical()).collect();

    let xs: Vec<field::Fr> = bytes
        .iter()
        .map(|b| field::Fr::from_bytes(b).unwrap())
        .collect();
    let ys: Vec<field::Fr> = bytes_b
        .iter()
        .map(|b| field::Fr::from_bytes(b).unwrap())
        .collect();
    let axs: Vec<ark_bn254::Fr> = bytes
        .iter()
        .map(|b| ark_ff::PrimeField::from_le_bytes_mod_order(b))
        .collect();
    let ays: Vec<ark_bn254::Fr> = bytes_b
        .iter()
        .map(|b| ark_ff::PrimeField::from_le_bytes_mod_order(b))
        .collect();

    let mut out = vec![field::Fr::ZERO; N];
    let mut aout = vec![ark_bn254::Fr::from(0u64); N];

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
    println!("\nn = {N} (inverse: {N_INVERSE}). Machine-dependent; internal use only.");
}
