//! S03 acceptance 10: the lift plus the full bind chain of a `u32`-backed
//! polynomial.
//!
//! No threshold — the number is recorded, not asserted. The table is built and
//! cloned outside the timed region, so what is measured is the first bind's
//! lift and the `VARS` folds.

use std::hint::black_box;
use std::time::Instant;

use test_support::Rng;

use crate::timing::{ms, next_canonical, Best, REPS, SEED};

/// The polynomial size S03 asks for.
const VARS: usize = 20;

pub fn run() {
    let mut rng = Rng::new(SEED ^ 0x5330_3300);
    let values: Vec<u32> = (0..1usize << VARS).map(|_| rng.next_u64() as u32).collect();
    let point: Vec<field::Fr> = (0..VARS)
        .map(|_| field::Fr::from_bytes(&next_canonical(&mut rng)).unwrap())
        .collect();

    let mut best = Best::new();
    for _ in 0..REPS {
        let mut p = poly::MultilinearPoly::new(poly::PolyBacking::U32(values.clone()));
        let t = Instant::now();
        for r in &point {
            p.bind(*r);
        }
        best.record(t.elapsed());
        black_box(&p);
    }

    println!("poly: lift + full bind chain, u32 backing (best of {REPS})");
    println!(
        "  n = {VARS} ({} evaluations)          {:>10.2} ms",
        1usize << VARS,
        ms(best.get())
    );
}
