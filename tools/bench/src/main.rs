//! Comparative microbenchmark for `Fr` against ark-bn254, plus the
//! `crates/poly` number acceptance 10 of S03 asks to be recorded and the
//! `crates/sumcheck` numbers acceptance 9 of S04 asks to be recorded.
//!
//!     cargo run --release -p bench
//!
//! Numbers are internal only. Machine-dependent; make no public claims.

use std::hint::black_box;
use std::time::{Duration, Instant};

use ark_ff::Field as _;
use test_support::Rng;

const N: usize = 1 << 20;
/// The polynomial size S03 asks for: 2^20 u32 evaluations, lifted and bound
/// all the way down.
const POLY_VARS: usize = 20;
const N_INVERSE: usize = 1 << 14; // one inversion is ~380 muls; 2^20 would take minutes
const REPS: usize = 3;
const SEED: u64 = 20260903;

/// Canonical bytes of a nonzero element, so both libraries get the same value.
/// Nonzero because an inversion benchmark must not measure the zero path.
fn next_canonical(rng: &mut Rng) -> [u8; 32] {
    loop {
        let mut b = rng.next_le32();
        b[31] &= 0x3f; // p < 2^254, so clearing two bits keeps rejection rare
        match field::Fr::from_bytes(&b) {
            Some(x) if x != field::Fr::ZERO => return b,
            _ => continue,
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

    poly_bind_chain(&mut rng);
    zerocheck_prove();
}

/// The lift plus the full bind chain of a `U32`-backed polynomial at
/// `POLY_VARS` variables. No threshold: the number is recorded, not asserted.
/// The table is built and cloned outside the timed region, so what is measured
/// is the first bind's lift and the 20 folds.
fn poly_bind_chain(rng: &mut Rng) {
    let values: Vec<u32> = (0..1usize << POLY_VARS)
        .map(|_| rng.next_u64() as u32)
        .collect();
    let point: Vec<field::Fr> = (0..POLY_VARS)
        .map(|_| field::Fr::from_bytes(&next_canonical(rng)).unwrap())
        .collect();

    let mut best_time = Duration::MAX;
    for _ in 0..REPS {
        let mut p = poly::MultilinearPoly::new(poly::PolyBacking::U32(values.clone()));
        let t = Instant::now();
        for r in &point {
            p.bind(*r);
        }
        best_time = best_time.min(t.elapsed());
        black_box(&p);
    }

    println!(
        "\npoly: lift + full bind chain, u32 backing, n = {POLY_VARS} ({} evaluations): {:.2} ms",
        1usize << POLY_VARS,
        best_time.as_secs_f64() * 1e3
    );
}

// ---------------------------------------------------------------------------
// S04 acceptance 9: prove wall-clock and peak polynomial memory at 2^20.
// ---------------------------------------------------------------------------

/// The rows acceptance 1 proves over.
const ZEROCHECK_VARS: usize = 20;

/// The bytes a polynomial's table occupies, by width. Vec capacity equals
/// length for every table built here, so this is the allocation.
fn table_bytes(backing: &poly::PolyBacking) -> usize {
    match backing {
        poly::PolyBacking::U1(limbs, _) => 8 * limbs.len(),
        poly::PolyBacking::U8(v) => v.len(),
        poly::PolyBacking::U16(v) => 2 * v.len(),
        poly::PolyBacking::U32(v) => 4 * v.len(),
        poly::PolyBacking::Fr(v) => 32 * v.len(),
    }
}

/// Peak live polynomial bytes inside `prove_zerocheck`, computed from the
/// tables the algorithm holds. It is not an allocator measurement: reading peak
/// RSS portably needs either a dependency or `unsafe`, and both are banned.
///
/// The model: `eq` is a full `Fr` table for the whole proof; `bind` truncates a
/// column's length without releasing its capacity, so from its first bind each
/// column costs a full `Fr` table too. The peak is the instant some column `k`
/// lifts, when its small backing and its fresh `Fr` table are both alive and
/// the columns after it still hold theirs.
fn peak_poly_bytes(small: &[usize], rows: usize) -> usize {
    let fr = 32 * rows;
    (0..small.len())
        .map(|k| fr + fr * (k + 1) + small[k] + small[k + 1..].iter().sum::<usize>())
        .max()
        .unwrap_or(fr)
}

/// Acceptance 9: `A * A - B` over `2^20` rows, `A` in `U16` and `B` in `U32` —
/// acceptance 1's witness exactly. No threshold; the numbers are recorded.
fn zerocheck_prove() {
    let rows = 1usize << ZEROCHECK_VARS;
    let mut rng = Rng::new(SEED ^ 0x5330_3400);
    let a: Vec<u16> = (0..rows).map(|_| rng.next_u64() as u16).collect();
    let b: Vec<u32> = a.iter().map(|&x| (x as u32) * (x as u32)).collect();
    let columns = || {
        vec![
            poly::MultilinearPoly::new(poly::PolyBacking::U16(a.clone())),
            poly::MultilinearPoly::new(poly::PolyBacking::U32(b.clone())),
        ]
    };

    let addr_a = sumcheck::PolyAddress(0);
    let addr_b = sumcheck::PolyAddress(1);
    let gate = sumcheck::Gate::new(
        &[&addr_a, &addr_b],
        vec![
            sumcheck::GateTerm {
                coef: field::Fr::ONE,
                a: 0,
                b: Some(0),
            },
            sumcheck::GateTerm {
                coef: field::Fr::MINUS_ONE,
                a: 1,
                b: None,
            },
        ],
    )
    .unwrap();

    let witness = columns();
    let small: Vec<usize> = witness.iter().map(|p| table_bytes(p.backing())).collect();

    let digest_start = Instant::now();
    let digest = sumcheck::witness_digest(&witness);
    let digest_time = digest_start.elapsed();
    drop(witness);

    let mut best_time = Duration::MAX;
    for _ in 0..REPS {
        let mut working = columns();
        let mut t = transcript::Transcript::new();
        sumcheck::absorb_witness_digest(&mut t, digest);
        let start = Instant::now();
        let proof = sumcheck::prove_zerocheck(&gate, &mut working, &mut t);
        best_time = best_time.min(start.elapsed());
        black_box(&proof);
    }

    let peak = peak_poly_bytes(&small, rows);
    println!("\nsumcheck: A*A - B, n = {ZEROCHECK_VARS} ({rows} rows), best of {REPS}");
    println!(
        "  prove_zerocheck                      {:>10.1} ms",
        best_time.as_secs_f64() * 1e3
    );
    println!(
        "  witness_digest (once, not in prove)  {:>10.1} ms",
        digest_time.as_secs_f64() * 1e3
    );
    println!(
        "  peak polynomial memory (computed)    {:>10.1} MiB",
        peak as f64 / (1024.0 * 1024.0)
    );
}
