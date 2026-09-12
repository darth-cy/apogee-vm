//! S04 acceptance 9: prove wall-clock and peak polynomial memory at 2^20.

use std::hint::black_box;
use std::time::Instant;

use crate::square::Square;
use crate::timing::{ms, Best, REPS};

/// The rows acceptance 1 proves over.
const VARS: usize = 20;

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
/// RSS on every platform needs either a dependency or `unsafe`, and both are banned.
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

pub fn run() {
    let inst = Square::new(VARS);
    let rows = inst.rows();

    let witness = inst.columns();
    let small: Vec<usize> = witness.iter().map(|p| table_bytes(p.backing())).collect();

    let digest_start = Instant::now();
    let digest = sumcheck::witness_digest(&witness);
    let digest_time = digest_start.elapsed();
    drop(witness);

    let mut best = Best::new();
    for _ in 0..REPS {
        let mut working = inst.columns();
        let mut t = transcript::Transcript::new();
        sumcheck::absorb_witness_digest(&mut t, digest);
        let start = Instant::now();
        let proof = sumcheck::prove_zerocheck(&inst.gate, &mut working, &mut t);
        best.record(start.elapsed());
        black_box(&proof);
    }

    let peak = peak_poly_bytes(&small, rows);
    println!("sumcheck prove: A*A - B, n = {VARS} ({rows} rows), best of {REPS}");
    println!(
        "  prove_zerocheck                      {:>10.1} ms",
        ms(best.get())
    );
    println!(
        "  witness_digest (once, not in prove)  {:>10.1} ms",
        ms(digest_time)
    );
    println!(
        "  peak polynomial memory (computed)    {:>10.1} MiB",
        peak as f64 / (1024.0 * 1024.0)
    );
}
