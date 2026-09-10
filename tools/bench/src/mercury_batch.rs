//! S09 acceptance 11: 16 columns of `2^20` opened as one batch, and as 16
//! single openings.
//!
//! The comparison the shard prover cares about. A batch is one opening of
//! `f* = sum rho^i f_i`, so it pays for the combination — `k` multiply-adds per
//! coefficient, and one `k`-point MSM for `cm*` — and then opens once. Sixteen
//! single openings pay for sixteen openings, each of which is `2n + O(sqrt n)`
//! scalar multiplications.
//!
//! Verification is where the difference is starkest, and it is printed too: a
//! batch is one `MercuryProof` and one pairing check however many columns went
//! into it.
//!
//! Nothing here asserts a threshold. A number that must not regress belongs in
//! a test; this prints what the machine did.

use std::path::PathBuf;
use std::time::Instant;

use field::Fr;
use pcs::{batch_open, batch_verify, commit, open, verify, MercuryCommitment};
use poly::{MultilinearPoly, PolyBacking};
use srs::Srs;
use test_support::Rng;
use transcript::Transcript;

/// The stage's numbers: sixteen columns at `2^20`.
const LOG_N: u32 = 20;
const COLUMNS: usize = 16;

fn ceremony_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../assets/ptau/ppot_0080_24.ptau")
}

pub fn run() {
    let num_vars = LOG_N as usize;
    let n = 1usize << num_vars;

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
        crate::timing::ms(t.elapsed())
    );

    let mut rng = Rng::new(crate::timing::SEED);
    let columns: Vec<MultilinearPoly> = (0..COLUMNS)
        .map(|_| {
            let values: Vec<Fr> = (0..n)
                .map(|_| {
                    Fr::from_bytes(&crate::timing::next_canonical(&mut rng))
                        .expect("canonical by construction")
                })
                .collect();
            MultilinearPoly::new(PolyBacking::Fr(values))
        })
        .collect();
    let point: Vec<Fr> = (0..num_vars)
        .map(|_| {
            Fr::from_bytes(&crate::timing::next_canonical(&mut rng))
                .expect("canonical by construction")
        })
        .collect();

    let t = Instant::now();
    let cms: Vec<MercuryCommitment> = columns
        .iter()
        .map(|f| commit(&srs, f).expect("commit"))
        .collect();
    let commit_all = t.elapsed();
    println!(
        "config: {COLUMNS} columns at n = 2^{LOG_N}, one point; committing all {COLUMNS} took {:.0} ms",
        crate::timing::ms(commit_all)
    );

    let vsrs = srs.verifier();

    // -- one batch ----------------------------------------------------------
    let t = Instant::now();
    let mut tr = Transcript::new();
    let (values, batched) = batch_open(&srs, &columns, &cms, &point, &mut tr).expect("batch_open");
    let batch_prove = t.elapsed();

    let t = Instant::now();
    let mut tr = Transcript::new();
    batch_verify(&vsrs, &cms, &point, &values, &batched, &mut tr).expect("batch_verify");
    let batch_check = t.elapsed();

    // -- sixteen single openings -------------------------------------------
    let t = Instant::now();
    let mut singles = Vec::with_capacity(COLUMNS);
    for (f, cm) in columns.iter().zip(&cms) {
        let mut tr = Transcript::new();
        singles.push(open(&srs, f, cm, &point, &mut tr).expect("open"));
    }
    let single_prove = t.elapsed();

    let t = Instant::now();
    for ((v, proof), cm) in singles.iter().zip(&cms) {
        let mut tr = Transcript::new();
        verify(&vsrs, cm, &point, *v, proof, &mut tr).expect("verify");
    }
    let single_check = t.elapsed();

    // The two routes must agree on every value before either is reported.
    for (i, (v, _)) in singles.iter().enumerate() {
        assert_eq!(
            *v, values[i],
            "the batch and the single openings must claim the same value for column {i}"
        );
    }

    let ms = crate::timing::ms;
    println!("\n  route                     open        verify   proof bytes");
    println!("  ---------------------  ---------  ------------  -----------");
    println!(
        "  one batch of {COLUMNS:<2}         {:7.0} ms  {:9.2} ms  {:11}",
        ms(batch_prove),
        ms(batch_check),
        pcs::PROOF_BYTES
    );
    println!(
        "  {COLUMNS} single openings     {:7.0} ms  {:9.2} ms  {:11}",
        ms(single_prove),
        ms(single_check),
        COLUMNS * pcs::PROOF_BYTES
    );
    println!(
        "  ratio                     {:7.2}x  {:10.2}x  {:10.2}x",
        batch_prove.as_secs_f64() / single_prove.as_secs_f64(),
        batch_check.as_secs_f64() / single_check.as_secs_f64(),
        1.0 / COLUMNS as f64
    );
    println!(
        "\n  Both routes commit first; that cost is shared and is the {:.0} ms above.",
        ms(commit_all)
    );
}
