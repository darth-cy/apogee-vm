#![no_std]
//! The verifier half of Mercury: everything a verification computes that is
//! not a curve operation.
//!
//! `docs/spec/mercury.md` §3.2 to §4 and §5, and `docs/spec/mercury.md` §6.1,
//! §3 and §5, are normative. `#![no_std]` + `alloc`: the recursion guest links
//! this crate. `crates/pcs` is the `std` half — commit, open, point validation,
//! the `cm*` MSM and the pairings — and re-exports everything public here, so a
//! native verification and a guest's run one definition of the transcript
//! schedule, the two derived values and the twelve accumulator terms.
//!
//! A point here is its 64-byte encoding, `crates/curve`'s uncompressed affine
//! form, because that is all the transcript reads (`transcript::g1_limbs`).
//! Nothing here checks that a point is on the curve: whoever spends a term
//! does, and `pcs::discharge` does it for every entry it is handed
//! (`docs/spec/mercury.md` §6.3).

extern crate alloc;

use alloc::vec::Vec;

use constants::{transcript_tags as tags, FR_TWO_ADICITY};
use field::Fr;
use transcript::{append_g1_points, g1_limbs, Transcript};

pub mod bdfg;
pub mod uni;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way Mercury refuses, native or deferred. One flat enum, one variant
/// per failure class; `pcs` re-exports it.
///
/// Nothing here is a panic: a malformed instance, a malformed proof and a
/// failed check are all data errors a caller can act on. Panics are reserved
/// for broken internal invariants, and each one names the invariant it broke.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcsError {
    /// The multilinear does not have `2t` variables for an integer `t >= 1`:
    /// an odd variable count, or the single-evaluation polynomial. Mercury is
    /// defined for `n = 2^(2t)` and never pads to reach it.
    UnsupportedNumVars { num_vars: usize },
    /// The opening point's length is not the polynomial's variable count.
    PointLengthMismatch { point: usize, num_vars: usize },
    /// The SRS holds fewer than `n` powers, so `f` cannot be committed.
    SrsTooSmall { needed: usize, available: usize },
    /// A point supplied to a native verification is off the curve or outside
    /// the order-`r` subgroup. The string names which one.
    InvalidPoint { field: &'static str },
    /// The transcript produced `{z, 1/z, alpha}` with fewer than three distinct
    /// members, which leaves the BDFG20 batch undefined. Probability about
    /// `2^-252`; `docs/spec/mercury.md` §3.4.
    DegenerateChallenge,
    /// A batch with no columns. There is no `cm*` and no `v*` to open, and no
    /// statement to make. `docs/spec/mercury.md` §5.
    EmptyBatch,
    /// A batch's commitment list and the list paired with it differ in length:
    /// the columns of `batch_open`, the claimed values of a batch verification.
    BatchLengthMismatch { commitments: usize, paired: usize },
    /// A batch's columns do not all have the same number of variables. Mercury
    /// batches one instance size at a time and never pads to reach it.
    MixedColumnSizes { expected: usize, found: usize },
    /// An accumulator's per-check counts do not partition it, or a count word is
    /// not a length. `length` is how long the thing being read is and `at` is
    /// how far the counts got — in **entries** when the counts were handed in
    /// beside an entry list, in **words** when they were read off a word array,
    /// which is why neither field names a unit. `docs/spec/mercury.md` §6.3.
    MalformedAccumulator { length: usize, at: usize },
    /// The pairing check failed. There is one, so there is one variant.
    VerificationFailed,
}

// ---------------------------------------------------------------------------
// The instance rule
// ---------------------------------------------------------------------------

/// The largest instance Mercury can express.
///
/// The opening's transform needs a `2b`-th root of unity, so `t + 1` may not
/// exceed `Fr`'s two-adicity and `num_vars = 2t` may not exceed 54. That bound
/// is also what keeps `1 << num_vars` in range: a verifier takes `u` straight
/// from a caller, so `u.len()` is adversarial input and must not be allowed to
/// shift a word off its end — with `overflow-checks` on that is a panic out of
/// a verifier, and with them off it is a silently wrong `n`. The word is a
/// `u64` and not a `usize` because the recursion guest's `usize` is 32 bits,
/// and the rule must be the same on every target.
pub const MAX_NUM_VARS: usize = 2 * (FR_TWO_ADICITY as usize - 1);
const _: () = assert!(MAX_NUM_VARS < u64::BITS as usize);

/// `n = 2^num_vars`, or the reason it is not a Mercury instance.
///
/// `n = 2^(2t)` with `1 <= t <= FR_TWO_ADICITY - 1`. Odd counts are rejected
/// rather than padded, and so is the single-evaluation polynomial, whose
/// `b = 1` leaves `S` and the degree check with no room to exist.
pub fn check_num_vars(num_vars: usize) -> Result<u64, PcsError> {
    if !(2..=MAX_NUM_VARS).contains(&num_vars) || !num_vars.is_multiple_of(2) {
        return Err(PcsError::UnsupportedNumVars { num_vars });
    }
    Ok(1u64 << num_vars)
}

/// The shape rule of a batch of `k` commitments with `values` claimed values at
/// a point of `num_vars` coordinates: at least one column, one value per
/// commitment, and a Mercury instance. `docs/spec/mercury.md` §5.
pub fn check_batch(k: usize, values: usize, num_vars: usize) -> Result<(), PcsError> {
    if k == 0 {
        return Err(PcsError::EmptyBatch);
    }
    if k != values {
        return Err(PcsError::BatchLengthMismatch {
            commitments: k,
            paired: values,
        });
    }
    check_num_vars(num_vars).map(|_| ())
}

// ---------------------------------------------------------------------------
// Shared pieces, prover and verifier
// ---------------------------------------------------------------------------

/// `sum_i a[i] * b[i]`, over equal-length slices.
pub fn dot(a: &[Fr], b: &[Fr]) -> Fr {
    debug_assert_eq!(a.len(), b.len());
    let mut acc = Fr::ZERO;
    for (x, y) in a.iter().zip(b) {
        acc += *x * *y;
    }
    acc
}

/// `[1, x, x^2, ..., x^(k-1)]`, the weights of a geometric batch.
///
/// Index `i` carries `x^i`, so the first element of a batched list carries `1`.
pub fn powers(x: Fr, k: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(k);
    let mut acc = Fr::ONE;
    for _ in 0..k {
        out.push(acc);
        acc *= x;
    }
    out
}

/// Draw `z` under `MERCURY_Z`, taking the first squeeze that is not `reject`
/// and squeezing again under the same tag while it is.
///
/// `docs/spec/mercury.md` §3.4 pins `reject = 0`, so that `1/z` exists, and
/// [`challenge_z`] is that rule. The rejected value is a parameter because the
/// loop is otherwise unreachable and so untestable: a transcript squeezes zero
/// with probability about `2^-254`, and no test can wait for that. A test names
/// a value the sponge really does produce instead, and watches the next squeeze
/// be taken.
fn challenge_z_rejecting(tr: &mut Transcript, reject: Fr) -> Fr {
    loop {
        let z = tr.challenge_scalar(tags::MERCURY_Z);
        if z != reject {
            return z;
        }
    }
}

/// Draw `z`, resampling under the same tag while it is zero so that `1/z`
/// exists. `docs/spec/mercury.md` §3.4.
pub fn challenge_z(tr: &mut Transcript) -> Fr {
    challenge_z_rejecting(tr, Fr::ZERO)
}

/// Whether `{z, 1/z, alpha}` has fewer than three distinct members, which would
/// leave `Z_T` with a repeated root and the interpolation of `h` undefined.
///
/// `z != 0` is already guaranteed by [`challenge_z`] and is repeated here so
/// the predicate stands alone. `docs/spec/mercury.md` §3.4.
pub fn degenerate(alpha: Fr, z: Fr) -> bool {
    z == Fr::ZERO || z.square() == Fr::ONE || z == alpha || z * alpha == Fr::ONE
}

/// `P_u(X) = prod_k (u_k X^(2^k) + 1 - u_k)`, the `O(t)` product formula.
///
/// Equal to `sum_i eq(i, u) X^i`, whose coefficient vector is `eq_table(u)`:
/// the prover uses the table, the verifier uses this, and
/// `crates/pcs/tests/identities.rs` holds them to each other.
fn tensor_eval(u: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::ONE;
    let mut power = x;
    for uk in u {
        acc *= *uk * power + (Fr::ONE - *uk);
        power = power.square();
    }
    acc
}

/// `h(alpha)`, from the symmetrized identity evaluated at `z`.
///
/// `2 h(alpha) = g_z P_u1(1/z) + g_1/z P_u1(z)
///             + gamma (h_z P_u2(1/z) + h_1/z P_u2(z) - 2v) - z S(z) - S(1/z)/z`.
///
/// The prover computes it this way too, so that the value it builds the batch
/// around is the value the verifier will use.
///
/// `evals` is the six sent values in the proof's field order:
/// `g_z, g_1/z, h_z, h_1/z, s_z, s_1/z`.
pub fn derive_h_alpha(
    u1: &[Fr],
    u2: &[Fr],
    z: Fr,
    z_inv: Fr,
    gamma: Fr,
    v: Fr,
    evals: &[Fr; 6],
) -> Fr {
    let [g_z, g_inv_z, h_z, h_inv_z, s_z, s_inv_z] = *evals;
    let two_inv = Fr::from_u64(2)
        .inverse()
        .expect("2 is invertible in a field of odd characteristic");
    let inner = g_z * tensor_eval(u1, z_inv)
        + g_inv_z * tensor_eval(u1, z)
        + gamma * (h_z * tensor_eval(u2, z_inv) + h_inv_z * tensor_eval(u2, z) - v - v)
        - z * s_z
        - z_inv * s_inv_z;
    inner * two_inv
}

// ---------------------------------------------------------------------------
// The accumulator's words
// ---------------------------------------------------------------------------

/// Which of the two fixed `G2` arguments an accumulator term pairs against.
///
/// Every deferred relation in this protocol has the shape
/// `e(A, [1]_2) = e(B, [x]_2)`, so a term is on the `A` side or the `B` side
/// and there is no third possibility. **Frozen forever**, including the wire
/// values: `G2One` is `0` and `G2X` is `1`. `pcs` re-exports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingSide {
    /// Pairs against `[1]_2` — a term of `A`.
    G2One,
    /// Pairs against `[x]_2` — a term of `B`.
    G2X,
}

impl PairingSide {
    /// The tag word this side is written as. `docs/spec/mercury.md` §6.1.
    pub fn word(self) -> Fr {
        match self {
            PairingSide::G2One => Fr::ZERO,
            PairingSide::G2X => Fr::ONE,
        }
    }

    /// The inverse of [`PairingSide::word`]; anything else is malformed.
    pub fn from_word(w: Fr) -> Option<PairingSide> {
        if w == Fr::ZERO {
            Some(PairingSide::G2One)
        } else if w == Fr::ONE {
            Some(PairingSide::G2X)
        } else {
            None
        }
    }
}

/// The words one entry occupies: the side tag, the scalar, and the point's four
/// `Fr` limbs. `6 * 32 = 192` bytes, for every entry, forever.
pub const ENTRY_WORDS: usize = 6;

/// The entries one deferred Mercury verification emits.
///
/// Ten `G2One` terms — the statement's commitment, the eight proof points in
/// their frozen field order, and `[1]_1` — and two `G2X` terms. The count does
/// not depend on `n`, and it does not depend on a batch's `k`, because a batch
/// derives `cm*` before it reaches the verification core.
pub const ENTRIES_PER_CHECK: usize = 12;

/// Entry `i`'s side, and which point it carries as an index into
/// `[cm, h, q, g, s, d, pi_z, w, w_prime, [1]_1]` — the statement's commitment,
/// the proof's eight points in field order, then the generator.
/// `docs/spec/mercury.md` §6.1's table, as the one definition both the native
/// verifier and the recursion guest build their entries from.
pub const ENTRY_POINTS: [(PairingSide, usize); ENTRIES_PER_CHECK] = [
    (PairingSide::G2One, 0),
    (PairingSide::G2One, 1),
    (PairingSide::G2One, 2),
    (PairingSide::G2One, 3),
    (PairingSide::G2One, 4),
    (PairingSide::G2One, 5),
    (PairingSide::G2One, 6),
    (PairingSide::G2One, 7),
    (PairingSide::G2One, 8),
    (PairingSide::G2One, 9),
    (PairingSide::G2X, 6),
    (PairingSide::G2X, 8),
];

/// One entry's six words: the side tag, the scalar, then the point's four
/// transcript limbs, infinity as four sentinels. `docs/spec/mercury.md` §6.3.
pub fn entry_words(side: PairingSide, scalar: Fr, point: &[u8; 64]) -> [Fr; ENTRY_WORDS] {
    let [x_lo, x_hi, y_lo, y_hi] = g1_limbs(point);
    [side.word(), scalar, x_lo, x_hi, y_lo, y_hi]
}

/// The accumulator digest: Poseidon2 over the words of the entry list.
///
/// The hash-binding rule, frozen once here and cited by every later stage: a
/// proof that carries an accumulator binds it by absorbing exactly these words
/// under `ACCUMULATOR_DIGEST` in a sponge of its own and squeezing once.
///
/// The squeeze is a raw `sample`, **not** a `challenge_scalar`, for the reason
/// `sumcheck::witness_digest`'s is: the tag frames a scalar message, and a
/// challenge under the same tag would be one tag in two kinds.
/// `docs/spec/mercury.md` §6.3.
pub fn accumulator_digest(words: &[Fr]) -> Fr {
    let mut sponge = Transcript::new();
    sponge.append_scalars(tags::ACCUMULATOR_DIGEST, words);
    sponge.sample()
}

// ---------------------------------------------------------------------------
// The verification's field side
// ---------------------------------------------------------------------------

/// The batch preamble's transcript half, `docs/spec/mercury.md` §5: absorb
/// the `k` commitments **as passed** as one message of `4k` limbs, then `u`
/// followed by all `k` claimed values, then squeeze `rho`.
///
/// Returns the weights `rho^0 .. rho^(k-1)` and `v* = sum_i rho^i v_i`. The
/// caller owes `cm* = sum_i rho^i cm_i`: `pcs` computes it with an MSM, and a
/// guest takes it as a hint whose correctness it defers
/// (`docs/spec/recursion.md` §8.3). [`check_batch`] runs first.
pub fn batch_preamble(cms: &[[u8; 64]], u: &[Fr], vs: &[Fr], tr: &mut Transcript) -> (Vec<Fr>, Fr) {
    append_g1_points(tr, tags::COMMITMENT, cms);
    let mut claim: Vec<Fr> = u.to_vec();
    claim.extend_from_slice(vs);
    tr.append_scalars(tags::EVALUATION_CLAIM, &claim);
    let rho = tr.challenge_scalar(tags::MERCURY_BATCH);
    let weights = powers(rho, cms.len());
    let v_star = dot(&weights, vs);
    (weights, v_star)
}

/// One Mercury verification's field side: `docs/spec/mercury.md` §3.2's schedule
/// over the instance `(cm, u, v)` and a proof given as its eight points'
/// encodings and its six values, both in field order; §7's challenge rule; the
/// two derived values; and the BDFG20 batch at `z'`.
///
/// Returns the twelve scalars of `docs/spec/mercury.md` §6.1 in entry order.
/// Entry `i` pairs its scalar with the point [`ENTRY_POINTS`] names, so the
/// relation the verifier would check is
/// `e(sum of the G2One terms, [1]_2) = e(sum of the G2X terms, [x]_2)`. The
/// ten `G2One` scalars sum to `A1 + rho A2` of §8.2 and the two `G2X` scalars
/// to `B1 + rho B2`.
pub fn scalars(
    cm: &[u8; 64],
    u: &[Fr],
    v: Fr,
    points: &[[u8; 64]; 8],
    evals: &[Fr; 6],
    tr: &mut Transcript,
) -> Result<[Fr; ENTRIES_PER_CHECK], PcsError> {
    check_num_vars(u.len())?;
    let t = u.len() / 2;
    let b = 1usize << t;
    let [h, q, g, s, d, pi_z, w, w_prime] = points;

    // The transcript schedule, mirroring `pcs::open` step for step.
    tr.append_scalar(tags::MERCURY_INSTANCE, Fr::from_u64(1u64 << u.len()));
    append_g1_points(tr, tags::COMMITMENT, &[*cm]);
    let mut claim: Vec<Fr> = u.to_vec();
    claim.push(v);
    tr.append_scalars(tags::EVALUATION_CLAIM, &claim);
    append_g1_points(tr, tags::PCS_OPENING, &[*h]);
    let alpha = tr.challenge_scalar(tags::MERCURY_ALPHA);
    append_g1_points(tr, tags::PCS_OPENING, &[*q, *g]);
    let gamma = tr.challenge_scalar(tags::MERCURY_GAMMA);
    append_g1_points(tr, tags::PCS_OPENING, &[*s, *d]);
    let z = challenge_z(tr);
    if degenerate(alpha, z) {
        return Err(PcsError::DegenerateChallenge);
    }
    let z_inv = z.inverse().expect("a nonzero challenge is invertible");
    tr.append_scalars(tags::PCS_OPENING, evals);
    append_g1_points(tr, tags::PCS_OPENING, &[*pi_z]);
    let delta = tr.challenge_scalar(tags::BDFG_BATCH);
    append_g1_points(tr, tags::PCS_OPENING, &[*w]);
    let z_prime = tr.challenge_scalar(tags::BDFG_POINT);
    append_g1_points(tr, tags::PCS_OPENING, &[*w_prime]);
    let rho = tr.challenge_scalar(tags::PAIRING_MERGE);

    // The two values the verifier derives rather than receives.
    let [g_z, g_inv_z, h_z, h_inv_z, s_z, s_inv_z] = *evals;
    let claims = bdfg::Claims {
        g_z,
        g_inv_z,
        h_z,
        h_inv_z,
        s_z,
        s_inv_z,
        h_alpha: derive_h_alpha(&u[..t], &u[t..], z, z_inv, gamma, v, evals),
        d_z: uni::pow_usize(z, b - 1) * g_inv_z,
    };

    // The BDFG20 batch at `z'`, from the one definition both sides read: `c[i]`
    // is `delta^i Z_{T \ S_i}(z')` and `constant` is `sum_i c[i] r_i(z')`.
    let t_set = bdfg::point_set(alpha, z, z_inv);
    let items = bdfg::items(alpha, z, z_inv, &claims);
    let mut c = [Fr::ZERO; 4];
    let mut constant = Fr::ZERO;
    for (i, item) in items.iter().enumerate() {
        c[i] = uni::pow_usize(delta, i) * uni::eval(&item.z_complement, z_prime);
        constant += c[i] * uni::eval(&item.r, z_prime);
    }
    let z_t = uni::eval(&uni::vanishing(&t_set), z_prime);
    let z_pow_b = uni::pow_usize(z, b);

    // Check A is the fold identity at `z`; check B is the BDFG20 batch; `rho`
    // merges them, which is why every check-B term carries it and no check-A
    // term does. `docs/spec/mercury.md` §4 and §4.
    Ok([
        Fr::ONE,
        rho * c[1],
        -(z_pow_b - alpha),
        rho * c[0],
        rho * c[2],
        rho * c[3],
        z,
        -(rho * z_t),
        rho * z_prime,
        -(g_z + rho * constant),
        Fr::ONE,
        rho,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    use poly::eq_table;

    /// The instance rule: `2t` variables for `1 <= t <= FR_TWO_ADICITY - 1`,
    /// and nothing else.
    ///
    /// The upper bound is not decoration. A verifier takes `u` straight from a
    /// caller, so without it `1usize << u.len()` shifts off the end of a
    /// `usize` — a panic out of a verifier where `overflow-checks` are on, and
    /// a silently wrong `n` where they are not.
    #[test]
    fn only_even_variable_counts_in_range_are_instances() {
        for num_vars in 0..=256usize {
            let got = check_num_vars(num_vars);
            let legal = (2..=MAX_NUM_VARS).contains(&num_vars) && num_vars % 2 == 0;
            if legal {
                assert_eq!(got, Ok(1u64 << num_vars), "num_vars {num_vars}");
            } else {
                assert_eq!(
                    got,
                    Err(PcsError::UnsupportedNumVars { num_vars }),
                    "num_vars {num_vars}"
                );
            }
        }
        assert_eq!(MAX_NUM_VARS, 54);
        assert!(check_num_vars(MAX_NUM_VARS).is_ok());
        assert!(check_num_vars(MAX_NUM_VARS + 2).is_err());
        // The bound really is what keeps the shift in range.
        assert!(MAX_NUM_VARS < u64::BITS as usize);
    }

    /// Acceptance 5, and `docs/spec/mercury.md` §3.4's `z in F*` rule: a rejected
    /// squeeze is discarded and the **next** squeeze under the same tag is
    /// used.
    ///
    /// The rule rejects zero, which a sponge produces with probability about
    /// `2^-254`, so the loop is undrivable as written. Naming the rejected
    /// value instead makes it drivable with a value the sponge really does
    /// produce, and what is then checked is the whole rule: the first draw is
    /// discarded, the second is returned, and the transcript is left where two
    /// squeezes under `MERCURY_Z` leave it — not one, and not a squeeze under
    /// some other tag.
    #[test]
    fn a_rejected_z_draw_takes_the_next_squeeze() {
        // What the sponge really produces under this tag, in order.
        let mut tr = Transcript::new();
        let draws: Vec<Fr> = (0..3)
            .map(|_| tr.challenge_scalar(tags::MERCURY_Z))
            .collect();
        assert!(draws.iter().all(|z| *z != Fr::ZERO), "and none is zero");
        assert_ne!(draws[0], draws[1]);

        // The production rule rejects zero, so it takes the first draw.
        let mut tr = Transcript::new();
        assert_eq!(challenge_z(&mut tr), draws[0]);
        assert_eq!(tr.challenge_scalar(tags::MERCURY_Z), draws[1]);

        // Rejecting the first draw takes the second, and leaves the transcript
        // two squeezes in rather than one.
        let mut tr = Transcript::new();
        assert_eq!(challenge_z_rejecting(&mut tr, draws[0]), draws[1]);
        assert_eq!(tr.challenge_scalar(tags::MERCURY_Z), draws[2]);
        assert_eq!(
            tr.event_log(),
            &[transcript::TranscriptEvent::Challenge {
                tag: tags::MERCURY_Z
            }; 3],
            "the resample is a squeeze under the same tag, not a different one"
        );

        // And the production rule is exactly this helper at zero.
        let mut plain = Transcript::new();
        let mut named = Transcript::new();
        assert_eq!(
            challenge_z(&mut plain),
            challenge_z_rejecting(&mut named, Fr::ZERO)
        );
        assert_eq!(plain.snapshot(), named.snapshot());
    }

    /// `docs/spec/mercury.md` §3.4. The transcript reaches this with probability
    /// about `2^-252`, so it is the one predicate no end-to-end test can drive:
    /// it gets its negative control here.
    #[test]
    fn the_degenerate_challenge_set_is_exactly_the_four_cases() {
        let alpha = Fr::from_u64(11);
        assert!(degenerate(alpha, Fr::ZERO), "z = 0 has no inverse");
        assert!(degenerate(alpha, Fr::ONE), "z = 1/z");
        assert!(degenerate(alpha, Fr::MINUS_ONE), "z = 1/z");
        assert!(degenerate(alpha, alpha), "z = alpha");
        assert!(
            degenerate(alpha, alpha.inverse().expect("nonzero")),
            "1/z = alpha"
        );
        for z in [2u64, 3, 5, 7, 12, 1 << 40] {
            assert!(!degenerate(alpha, Fr::from_u64(z)), "z = {z} is fine");
        }
        // alpha = 0 is not degenerate on its own: Z_{T \ S} is then just X.
        assert!(!degenerate(Fr::ZERO, Fr::from_u64(3)));
    }

    /// The `P_u` product formula is the coefficient vector `eq_table` builds.
    #[test]
    fn the_tensor_product_formula_matches_the_eq_table() {
        for t in 0..8usize {
            let u: Vec<Fr> = (0..t).map(|k| Fr::from_u64(3 * k as u64 + 1)).collect();
            let table = eq_table(&u);
            for x in [2u64, 5, 9, 1 << 20] {
                let x = Fr::from_u64(x);
                let mut expected = Fr::ZERO;
                let mut power = Fr::ONE;
                for c in &table {
                    expected += *c * power;
                    power *= x;
                }
                assert_eq!(tensor_eval(&u, x), expected, "t = {t}");
            }
        }
    }
}
