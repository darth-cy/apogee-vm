//! Sumcheck verification against naive verification, on the same claim:
//! `A * A - B = 0` on every one of `2^VARS` rows.
//!
//! The naive verifier holds the witness and recomputes every row in `Fr`. The
//! sumcheck verifier holds a digest and a proof — 4 coefficients per round plus
//! one eval per gate input — and never sees a row. That is the comparison: the
//! work is `O(2^n)` on one side and `O(n)` on the other, and this routine says
//! what the constants make of it at the size S04 proves over.
//!
//! Two things stay outside both timed regions, and both are named in the
//! output. Proving and the witness digest are the prover's cost and the
//! commitment's, not the verifier's. And discharging the claim
//! `verify_zerocheck` returns — opening `final_evals` against a commitment — is
//! the Mercury PCS's job and does not exist yet, so the sumcheck number here is
//! a floor, not the finished verifier's cost.

use std::hint::black_box;
use std::time::Instant;

use constants::transcript_tags;
use field::Fr;
use sumcheck::SumcheckProof;
use transcript::Transcript;

use crate::square::Square;
use crate::timing::{ms, Best, REPS};

/// Four times the rows S04 acceptance 1 proves over. The separation this
/// routine measures is `O(2^n)` against `O(n)`, so it is worth reading at a
/// size the acceptance does not have to pay for: every doubling of `n` doubles
/// the naive verifier's work and adds one round to the sumcheck verifier's.
/// The price is setup: the digest is tens of seconds at this size, which is
/// the reason routines are individually selectable.
const VARS: usize = 22;

/// Inner iterations per timed run on the sumcheck side, so a millisecond-scale
/// measurement is not competing with the clock's own noise.
const VERIFY_ITERS: usize = 500;

/// Recompute every row. There is no early return on the first bad row: an
/// honest verifier on a satisfying witness sweeps the whole table anyway, and
/// that sweep is the cost being compared.
fn naive_verify(a: &[Fr], b: &[Fr]) -> bool {
    let mut ok = true;
    for i in 0..a.len() {
        ok &= a[i] * a[i] - b[i] == Fr::ZERO;
    }
    ok
}

/// The sumcheck verifier's whole session for this claim: a fresh transcript,
/// the digest it is handed, and the proof. Building the transcript is inside
/// the measurement because the verifier really does pay for it.
fn sumcheck_verify(inst: &Square, digest: Fr, proof: &SumcheckProof) -> bool {
    let mut t = Transcript::new();
    sumcheck::absorb_witness_digest(&mut t, digest);
    sumcheck::verify_zerocheck(&inst.gate, VARS, proof, &mut t).is_ok()
}

/// The transcript half of `sumcheck_verify` with the arithmetic removed: the
/// same messages in the same order, and nothing else.
///
/// This is a second copy of the frozen transcript script, which is exactly the
/// thing `crates/sumcheck/CLAUDE.md` warns about — so the caller checks it
/// against the real verifier's sponge and refuses to report a number if the two
/// have drifted apart.
fn transcript_only(proof: &SumcheckProof, digest: Fr) -> Transcript {
    let mut t = Transcript::new();
    sumcheck::absorb_witness_digest(&mut t, digest);
    for _ in 0..proof.rounds.len() {
        t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE);
    }
    for g in &proof.rounds {
        t.append_scalars(transcript_tags::SUMCHECK_ROUND, g);
        t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE);
    }
    t.append_scalars(transcript_tags::SUMCHECK_FINAL_EVALS, &proof.final_evals);
    t
}

pub fn run() {
    let inst = Square::new(VARS);
    let rows = inst.rows();
    let (a, b) = inst.lifted();

    // Setup: everything the verifier is handed rather than computes.
    let setup = Instant::now();
    let digest = sumcheck::witness_digest(&inst.columns());
    let digest_time = setup.elapsed();
    let mut working = inst.columns();
    let mut t = Transcript::new();
    sumcheck::absorb_witness_digest(&mut t, digest);
    let prove_start = Instant::now();
    let proof = sumcheck::prove_zerocheck(&inst.gate, &mut working, &mut t);
    let prove_time = prove_start.elapsed();

    // Negative controls. A benchmark of two checkers is worth nothing until
    // both have been shown to accept this input and to reject a broken one.
    assert!(
        naive_verify(&a, &b),
        "the witness being timed must satisfy the gate"
    );
    let mut bad_b = b.clone();
    bad_b[0] += Fr::ONE; // A^2 - B - 1, nonzero for every A
    assert!(
        !naive_verify(&a, &bad_b),
        "the naive verifier must reject a corrupted row"
    );
    drop(bad_b);
    assert!(
        sumcheck_verify(&inst, digest, &proof),
        "the honest proof being timed must verify"
    );
    let mut bad_proof = proof.clone();
    bad_proof.rounds[0][0] += Fr::ONE; // g(0)+g(1) shifts by 2
    assert!(
        !sumcheck_verify(&inst, digest, &bad_proof),
        "the sumcheck verifier must reject a corrupted round"
    );
    drop(bad_proof);

    let mut naive = Best::new();
    for _ in 0..REPS {
        let start = Instant::now();
        let ok = naive_verify(&a, &b);
        naive.record(start.elapsed());
        black_box(ok);
    }

    let mut verify = Best::new();
    for _ in 0..REPS {
        let start = Instant::now();
        for _ in 0..VERIFY_ITERS {
            black_box(sumcheck_verify(&inst, digest, &proof));
        }
        verify.record(start.elapsed() / VERIFY_ITERS as u32);
    }

    // The same schedule with no arithmetic, only if it really is the same
    // schedule: the sponge state after the replay must equal the sponge state
    // after the real verifier's run.
    let mut real = Transcript::new();
    sumcheck::absorb_witness_digest(&mut real, digest);
    sumcheck::verify_zerocheck(&inst.gate, VARS, &proof, &mut real)
        .expect("the honest proof verifies");
    let replay_is_faithful = transcript_only(&proof, digest).snapshot() == real.snapshot();

    let mut sponge = Best::new();
    for _ in 0..REPS {
        let start = Instant::now();
        for _ in 0..VERIFY_ITERS {
            black_box(transcript_only(&proof, digest));
        }
        sponge.record(start.elapsed() / VERIFY_ITERS as u32);
    }

    let naive_bytes = 2 * rows * 32;
    let proof_bytes = (4 * proof.rounds.len() + proof.final_evals.len()) * 32;
    let mib = |n: usize| n as f64 / (1024.0 * 1024.0);

    println!("sumcheck verify vs naive verify: A*A - B = 0, n = {VARS} ({rows} rows)");
    println!("best of {REPS}; the sumcheck side is the mean of {VERIFY_ITERS} runs per rep");
    println!("{:<38} {:>10} {:>14}", "verifier", "time", "input read");
    println!(
        "{:<38} {:>10.3} ms {:>11.1} MiB",
        "naive: recompute every row in Fr",
        ms(naive.get()),
        mib(naive_bytes)
    );
    println!(
        "{:<38} {:>10.3} ms {:>11} B",
        "sumcheck: verify_zerocheck",
        ms(verify.get()),
        proof_bytes
    );
    println!(
        "{:<38} {:>10.1}x {:>11.0}x",
        "speedup",
        naive.get().as_secs_f64() / verify.get().as_secs_f64(),
        naive_bytes as f64 / proof_bytes as f64
    );

    if replay_is_faithful {
        let arith = verify.get().saturating_sub(sponge.get());
        println!(
            "\n  of which Poseidon2 transcript        {:>10.3} ms  ({:.1}% of verify_zerocheck)",
            ms(sponge.get()),
            100.0 * sponge.get().as_secs_f64() / verify.get().as_secs_f64()
        );
        println!(
            "  the rest, i.e. the arithmetic        {:>10.3} ms  ({:.1}% of verify_zerocheck)",
            ms(arith),
            100.0 * arith.as_secs_f64() / verify.get().as_secs_f64()
        );
        println!("  The second line is the difference of two separate measurements, not a");
        println!("  measurement, and it is small enough that it moves by a few percent");
        println!("  between runs — so no speedup is derived from it here. What it says is");
        println!("  solid without one: the arithmetic this verifier does is a rounding");
        println!("  error next to the sponge it drives, so the permutation, not the");
        println!("  protocol, is what caps the ratio in the table above.");
    } else {
        println!("\n  transcript share: not reported — the replay in this file no longer");
        println!("  matches the verifier's message schedule. Fix it or delete it.");
    }

    println!("\n  outside both measurements, and not the verifier's work:");
    println!(
        "    prove_zerocheck                    {:>10.1} ms",
        ms(prove_time)
    );
    println!(
        "    witness_digest                     {:>10.1} ms",
        ms(digest_time)
    );
    println!("  outside the sumcheck measurement, and not yet implemented:");
    println!("    opening final_evals against a commitment (Mercury PCS). Until that");
    println!("    lands the sumcheck figure is a floor, and the naive verifier is the");
    println!("    only one of the two that is complete.");
}
