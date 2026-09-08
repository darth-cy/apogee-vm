//! The two gates the acceptance list names, their satisfying witnesses, and the
//! harness both sides of the protocol share.

#![allow(dead_code)]

use constants::transcript_tags;
use field::Fr;
use poly::{MultilinearPoly, PolyBacking};
use sumcheck::{absorb_witness_digest, Gate, GateTerm, PolyAddress, SumcheckClaim, SumcheckProof};
use test_support::Rng;
use transcript::Transcript;

/// A fresh transcript with one witness digest bound to it. Both the prover and
/// the verifier start here. The digest is a parameter rather than being taken
/// from the columns, because the tamper tests bind one witness and prove
/// another.
pub fn bound_transcript(digest: Fr) -> Transcript {
    let mut t = Transcript::new();
    absorb_witness_digest(&mut t, digest);
    t
}

/// The `n` eq-randomizers a proof over `digest` is built on, replayed from the
/// frozen transcript script. They are drawn before any round message exists, so
/// no proof is needed to read them.
pub fn eq_randomizers(digest: Fr, n: usize) -> Vec<Fr> {
    let mut t = bound_transcript(digest);
    (0..n)
        .map(|_| t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE))
        .collect()
}

/// The `n` round challenges a proof over `digest` was built on, replayed from
/// the frozen script. Unlike `SumcheckClaim::point` this needs no verification,
/// so it reads the challenges of a proof over a witness that does not satisfy
/// the gate — which is what acceptance 4's one-cell pair is.
///
/// `script.rs` pins that this replay really is the protocol's script, and
/// `the_digest_makes_the_challenges_witness_dependent` checks it against the
/// verifier's own `claim.point` on a proof that does verify.
pub fn round_challenges(digest: Fr, proof: &SumcheckProof) -> Vec<Fr> {
    let mut t = bound_transcript(digest);
    for _ in 0..proof.rounds.len() {
        t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE);
    }
    proof
        .rounds
        .iter()
        .map(|g| {
            t.append_scalars(transcript_tags::SUMCHECK_ROUND, g);
            t.challenge_scalar(transcript_tags::SUMCHECK_CHALLENGE)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Gate 1: A * A - B
// ---------------------------------------------------------------------------

/// `A * A - B` over inputs `[A, B]`.
pub fn square_gate() -> Gate {
    let a = PolyAddress(0);
    let b = PolyAddress(1);
    Gate::new(
        &[&a, &b],
        vec![
            GateTerm {
                coef: Fr::ONE,
                a: 0,
                b: Some(0),
            },
            GateTerm {
                coef: Fr::MINUS_ONE,
                a: 1,
                b: None,
            },
        ],
    )
    .expect("A * A - B is a well formed degree-2 gate")
}

/// `A` seeded random in `U16`, `B = A^2` in `U32`: a satisfying witness for
/// [`square_gate`]. `65535^2 = 4294836225` fits a `u32`, so the square is
/// exact and no reduction hides a mistake.
pub fn square_witness(n: usize, seed: u64) -> Vec<MultilinearPoly> {
    let (a, b) = square_columns(n, seed);
    vec![
        MultilinearPoly::new(PolyBacking::U16(a)),
        MultilinearPoly::new(PolyBacking::U32(b)),
    ]
}

/// Rebuild a [`square_witness`] with row `row` changed — `A[row] ^= mask`, and
/// `B[row]` its new square, so the result still satisfies the gate. This is the
/// swap a prover would attempt after the digest is already bound. A nonzero
/// mask always changes the row, whatever the seed drew.
pub fn square_witness_with_row(n: usize, seed: u64, row: usize, mask: u16) -> Vec<MultilinearPoly> {
    assert_ne!(mask, 0, "a swap must change the witness");
    let (mut col_a, mut col_b) = square_columns(n, seed);
    let a = col_a[row] ^ mask;
    col_a[row] = a;
    col_b[row] = (a as u32) * (a as u32);
    vec![
        MultilinearPoly::new(PolyBacking::U16(col_a)),
        MultilinearPoly::new(PolyBacking::U32(col_b)),
    ]
}

/// Rebuild a [`square_witness`] with `B[row]` bumped by one and `A` untouched,
/// so the witness no longer satisfies `A * A - B` anywhere but row `row`.
pub fn square_witness_with_bumped_b(n: usize, seed: u64, row: usize) -> Vec<MultilinearPoly> {
    let (a, mut b) = square_columns(n, seed);
    b[row] += 1;
    vec![
        MultilinearPoly::new(PolyBacking::U16(a)),
        MultilinearPoly::new(PolyBacking::U32(b)),
    ]
}

/// The raw tables behind [`square_witness`], for the builders above.
fn square_columns(n: usize, seed: u64) -> (Vec<u16>, Vec<u32>) {
    let mut rng = Rng::new(seed);
    let a: Vec<u16> = (0..1usize << n).map(|_| rng.next_u64() as u16).collect();
    let b: Vec<u32> = a.iter().map(|&x| (x as u32) * (x as u32)).collect();
    (a, b)
}

// ---------------------------------------------------------------------------
// Gate 2: A * (B + C) - D * E
// ---------------------------------------------------------------------------

/// `A * (B + C) - D * E` over inputs `[A, B, C, D, E]`, written out as the
/// three degree-2 terms `A*B + A*C - D*E`.
pub fn wide_gate() -> Gate {
    let addrs = [
        PolyAddress(10),
        PolyAddress(11),
        PolyAddress(12),
        PolyAddress(13),
        PolyAddress(14),
    ];
    let inputs: Vec<&PolyAddress> = addrs.iter().collect();
    Gate::new(
        &inputs,
        vec![
            GateTerm {
                coef: Fr::ONE,
                a: 0,
                b: Some(1),
            },
            GateTerm {
                coef: Fr::ONE,
                a: 0,
                b: Some(2),
            },
            GateTerm {
                coef: Fr::MINUS_ONE,
                a: 3,
                b: Some(4),
            },
        ],
    )
    .expect("A * (B + C) - D * E is a well formed degree-2 gate")
}

/// A satisfying witness for [`wide_gate`]: `A`, `B`, `C` seeded random `U32`,
/// `D` seeded random *odd* `U32` so it is invertible, and
/// `E = A * (B + C) / D` in `Fr`. Four small backings and one `Fr` backing.
pub fn wide_witness(n: usize, seed: u64) -> Vec<MultilinearPoly> {
    wide_polys(wide_columns(n, seed))
}

/// A satisfying [`wide_witness`] with row `row` of `A` changed by `mask` and
/// `E` recomputed, so the swap stays satisfying.
pub fn wide_witness_with_row(n: usize, seed: u64, row: usize, mask: u32) -> Vec<MultilinearPoly> {
    assert_ne!(mask, 0, "a swap must change the witness");
    let mut cols = wide_columns(n, seed);
    cols.a[row] ^= mask;
    cols.e[row] = quotient(cols.a[row], cols.b[row], cols.c[row], cols.d[row]);
    wide_polys(cols)
}

/// A [`wide_witness`] with `E[row]` bumped by one, which breaks the gate at
/// exactly that row.
pub fn wide_witness_with_bumped_e(n: usize, seed: u64, row: usize) -> Vec<MultilinearPoly> {
    let mut cols = wide_columns(n, seed);
    cols.e[row] += Fr::ONE;
    wide_polys(cols)
}

/// The raw tables behind [`wide_witness`], so a tamper builder can edit one row
/// before they are wrapped.
struct WideColumns {
    a: Vec<u32>,
    b: Vec<u32>,
    c: Vec<u32>,
    d: Vec<u32>,
    e: Vec<Fr>,
}

/// `E = A * (B + C) / D`, the value that makes the gate vanish on a row.
fn quotient(a: u32, b: u32, c: u32, d: u32) -> Fr {
    Fr::from_u64(a as u64)
        * (Fr::from_u64(b as u64) + Fr::from_u64(c as u64))
        * Fr::from_u64(d as u64)
            .inverse()
            .expect("D is odd, hence nonzero")
}

fn wide_columns(n: usize, seed: u64) -> WideColumns {
    let mut rng = Rng::new(seed);
    let rows = 1usize << n;
    let a: Vec<u32> = (0..rows).map(|_| rng.next_u64() as u32).collect();
    let b: Vec<u32> = (0..rows).map(|_| rng.next_u64() as u32).collect();
    let c: Vec<u32> = (0..rows).map(|_| rng.next_u64() as u32).collect();
    let d: Vec<u32> = (0..rows).map(|_| (rng.next_u64() as u32) | 1).collect();
    let e: Vec<Fr> = (0..rows)
        .map(|i| quotient(a[i], b[i], c[i], d[i]))
        .collect();
    WideColumns { a, b, c, d, e }
}

fn wide_polys(cols: WideColumns) -> Vec<MultilinearPoly> {
    vec![
        MultilinearPoly::new(PolyBacking::U32(cols.a)),
        MultilinearPoly::new(PolyBacking::U32(cols.b)),
        MultilinearPoly::new(PolyBacking::U32(cols.c)),
        MultilinearPoly::new(PolyBacking::U32(cols.d)),
        MultilinearPoly::new(PolyBacking::Fr(cols.e)),
    ]
}

// ---------------------------------------------------------------------------
// Discharge
// ---------------------------------------------------------------------------

/// The final-evals discharge, done here by direct evaluation because the
/// Mercury PCS that will do it against commitments arrives in a later stage.
///
/// `columns` must be the witness the transcript's digest was taken over. An
/// error, never a panic: a prover that swapped its witness after the digest
/// must be *rejected*, and a rejection is a value.
pub fn discharge(columns: &[MultilinearPoly], claim: &SumcheckClaim) -> Result<(), String> {
    if columns.len() != claim.final_evals.len() {
        return Err(format!(
            "the digest-bound witness has {} columns, the claim has {} final evals",
            columns.len(),
            claim.final_evals.len()
        ));
    }
    for (k, column) in columns.iter().enumerate() {
        let bound = column.evaluate(&claim.point);
        if bound != claim.final_evals[k] {
            return Err(format!(
                "column {k}: the proof claims {:?}, the digest-bound witness evaluates to {bound:?}",
                claim.final_evals[k]
            ));
        }
    }
    Ok(())
}
