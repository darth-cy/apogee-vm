//! S08 acceptance 11: Mercury commit, open and verify at `2^22`.
//!
//! Three things, all over **real ceremony bases** read from the powers-of-tau
//! file, because "fast over random points" is not the claim anyone cares about:
//!
//! 1. wall-clock for `commit`, `open` and `verify` at the master's trace-height
//!    ceiling;
//! 2. the scalar-multiplication accounting for an opening — the sizes of every
//!    MSM it runs, which is what "`2n + O(sqrt n)`" means concretely;
//! 3. `commit` on a `u32`-backed column against an `Fr`-backed column *of the
//!    same values*, where the only thing that differs is which MSM path
//!    must-be-exact 10 routes the backing to.
//!
//! Nothing here asserts a threshold. A number that must not regress belongs in
//! a test; this prints what the machine did, and the S08 handoff records it.

use std::path::PathBuf;
use std::time::Instant;

use field::Fr;
use pcs::{commit, open, verify};
use poly::{MultilinearPoly, PolyBacking};
use srs::Srs;
use test_support::Rng;
use transcript::Transcript;

use crate::timing::{ms, next_canonical, Best, REPS, SEED};

/// The master's trace-height ceiling, and the largest instance Mercury has to
/// open.
const LOG_N: u32 = 22;

fn ceremony_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/ptau/ppot_0080_24.ptau")
}

pub fn run() {
    let num_vars = LOG_N as usize;
    let n = 1usize << num_vars;
    let b = 1usize << (num_vars / 2);

    let path = ceremony_path();
    if !path.exists() {
        println!("no ceremony file at {}", path.display());
        println!("this routine measures Mercury over real SRS bases; it does not substitute random ones.");
        return;
    }

    // -- setup, outside every timed region --------------------------------
    let t = Instant::now();
    let srs = Srs::from_ptau(&path, LOG_N).expect("the ceremony file ingests");
    println!(
        "setup: {} ceremony powers read and validated in {:.0} ms",
        srs.g1().len(),
        ms(t.elapsed())
    );

    let mut rng = Rng::new(SEED);
    let values: Vec<Fr> = (0..n)
        .map(|_| Fr::from_bytes(&next_canonical(&mut rng)).expect("canonical by construction"))
        .collect();
    let point: Vec<Fr> = (0..num_vars)
        .map(|_| Fr::from_bytes(&next_canonical(&mut rng)).expect("canonical by construction"))
        .collect();
    let f = MultilinearPoly::new(PolyBacking::Fr(values));

    println!(
        "config: n = 2^{LOG_N}, b = 2^{}, best of {REPS}",
        num_vars / 2
    );

    // -- 1. the three operations -------------------------------------------
    let mut commit_best = Best::new();
    for _ in 0..REPS {
        let t = Instant::now();
        let cm = commit(&srs, &f).expect("commit");
        commit_best.record(t.elapsed());
        std::hint::black_box(cm);
    }
    let cm = commit(&srs, &f).expect("commit");

    let mut open_best = Best::new();
    let mut claim = Fr::ZERO;
    for _ in 0..REPS {
        let mut tr = Transcript::new();
        let t = Instant::now();
        let (v, proof) = open(&srs, &f, &cm, &point, &mut tr).expect("open");
        open_best.record(t.elapsed());
        claim = v;
        std::hint::black_box(proof);
    }
    let mut tr = Transcript::new();
    let (_, proof) = open(&srs, &f, &cm, &point, &mut tr).expect("open");

    let vsrs = srs.verifier();
    let mut verify_best = Best::new();
    for _ in 0..REPS {
        let mut tr = Transcript::new();
        let t = Instant::now();
        let ok = verify(&vsrs, &cm, &point, claim, &proof, &mut tr);
        verify_best.record(t.elapsed());
        ok.expect("the honest proof verifies");
    }

    println!("\n  operation      time");
    println!("  ---------  --------");
    println!("  commit     {:7.0} ms", ms(commit_best.get()));
    println!("  open       {:7.0} ms", ms(open_best.get()));
    println!("  verify     {:9.2} ms", ms(verify_best.get()));

    // -- 2. the scalar-multiplication accounting ---------------------------
    //
    // The sizes below restate `pcs::open`'s shape. They are printed, never
    // used, so a drift misreports a line rather than changing a measurement —
    // the same hazard `msm.rs`'s window rule carries.
    let sizes = [
        ("h   = [h(x)]", b),
        ("q   = [q(x)]", n - b),
        ("g   = [g(x)]", b),
        ("s   = [S(x)]", b - 1),
        ("d   = [D(x)]", b),
        ("pi_z= [H(x)]", n - 1),
        ("w   = BDFG W", b - 1),
        ("w'  = BDFG W'", b - 1),
    ];
    let total: usize = sizes.iter().map(|(_, size)| *size).sum();
    println!("\n  opening MSMs   scalar mults");
    println!("  ------------   ------------");
    for (name, size) in sizes {
        println!("  {name}   {size:>12}");
    }
    println!("  {:<12}   {total:>12}", "total");
    println!(
        "  that is 2n + {} = 2n + {:.1} sqrt(n), against n = {n}",
        total - 2 * n,
        (total - 2 * n) as f64 / b as f64
    );
    println!("  commitment: {n} scalar mults, one MSM.");

    // -- 3. the narrow-backing commit path ---------------------------------
    //
    // The same values twice: once as `u32` words, once lifted into `Fr`. Only
    // the backing differs, so only the MSM path does.
    let mut rng = Rng::new(SEED + 1);
    let words: Vec<u32> = (0..n).map(|_| rng.next_u64() as u32).collect();
    let narrow = MultilinearPoly::new(PolyBacking::U32(words.clone()));
    let wide = MultilinearPoly::new(PolyBacking::Fr(
        words.iter().map(|w| Fr::from_u64(*w as u64)).collect(),
    ));

    let narrow_point = commit(&srs, &narrow).expect("commit");
    let wide_point = commit(&srs, &wide).expect("commit");
    assert_eq!(
        narrow_point, wide_point,
        "the two backings must agree before either is timed"
    );

    let mut narrow_best = Best::new();
    let mut wide_best = Best::new();
    for _ in 0..REPS {
        let t = Instant::now();
        std::hint::black_box(commit(&srs, &narrow).expect("commit"));
        narrow_best.record(t.elapsed());

        let t = Instant::now();
        std::hint::black_box(commit(&srs, &wide).expect("commit"));
        wide_best.record(t.elapsed());
    }
    println!("\n  commit at 2^{LOG_N}, one column of u32 values      time     ratio");
    println!("  --------------------------------------------  --------  --------");
    println!(
        "  U32 backing (msm_small_u32)                   {:7.0} ms  {:8.2}",
        ms(narrow_best.get()),
        narrow_best.get().as_secs_f64() / wide_best.get().as_secs_f64()
    );
    println!(
        "  Fr backing  (general msm)                     {:7.0} ms  {:8.2}",
        ms(wide_best.get()),
        1.0
    );
}
