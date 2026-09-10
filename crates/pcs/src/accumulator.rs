//! The deferred-pairing accumulator: entries, their wire form, and discharge.
//!
//! A Mercury verification ends in one pairing relation `e(A, [1]_2) =
//! e(B, [x]_2)`, and both `A` and `B` are small multi-scalar multiplications of
//! points the verifier already holds against scalars it has just derived
//! (`docs/spec/mercury.md` §8.2 and §8.3). **Deferring** a verification means
//! emitting those terms instead of running the pairings: twelve
//! [`AccumulatorEntry`] items, each a `(side, scalar, point)` triple, whose
//! weighted sums are `A` and `B`.
//!
//! A downstream verifier concatenates entry lists and does nothing else with
//! them. [`discharge`] is where they are finally spent: one RLC weight per
//! deferred check, one MSM per side, one two-pairing check.
//!
//! `docs/spec/accumulator.md` is normative for everything in this module — the
//! entry order, the word layout, the digest and the discharge equation.

use constants::transcript_tags as tags;
use curve::msm::msm;
use curve::G1Affine;
use field::Fr;
use srs::SrsVerifier;
use transcript::Transcript;

use crate::{g1_limbs, infinity_sentinel, PcsError};

// ---------------------------------------------------------------------------
// The entry
// ---------------------------------------------------------------------------

/// Which of the two fixed `G2` arguments an accumulator term pairs against.
///
/// Every deferred relation in this protocol has the shape
/// `e(A, [1]_2) = e(B, [x]_2)`, so a term is on the `A` side or the `B` side
/// and there is no third possibility. **Frozen forever**, including the wire
/// values in [`AccumulatorEntry`]'s word form: `G2One` is `0` and `G2X` is `1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingSide {
    /// Pairs against `[1]_2` — a term of `A`.
    G2One,
    /// Pairs against `[x]_2` — a term of `B`.
    G2X,
}

impl PairingSide {
    /// The tag word this side is written as. `docs/spec/accumulator.md` §2.
    fn word(self) -> Fr {
        match self {
            PairingSide::G2One => Fr::ZERO,
            PairingSide::G2X => Fr::ONE,
        }
    }

    /// The inverse of [`PairingSide::word`]; anything else is malformed.
    fn from_word(w: Fr) -> Option<PairingSide> {
        if w == Fr::ZERO {
            Some(PairingSide::G2One)
        } else if w == Fr::ONE {
            Some(PairingSide::G2X)
        } else {
            None
        }
    }
}

/// One term of one deferred pairing relation: `scalar * point`, on `side`.
///
/// **Frozen forever**, in this field order, which is also the word order of
/// `docs/spec/accumulator.md` §2. A list of these is the whole accumulator;
/// there is no header, no length prefix and no other kind of entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccumulatorEntry {
    pub side: PairingSide,
    pub scalar: Fr,
    pub point: G1Affine,
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

// ---------------------------------------------------------------------------
// The wire form
// ---------------------------------------------------------------------------

/// The words of an entry list, grouped per deferred check.
///
/// `checks[j]` is the entry count of deferred check `j`, and the groups
/// partition `entries` in order. Each group is written as its count word
/// followed by its entries, so the words carry the grouping and a byte
/// concatenation of two lists is itself a valid list.
///
/// `docs/spec/accumulator.md` §2 and §3.
pub fn accumulator_words(
    entries: &[AccumulatorEntry],
    checks: &[usize],
) -> Result<Vec<Fr>, PcsError> {
    partition(entries, checks)?;

    let mut words = Vec::with_capacity(checks.len() + entries.len() * ENTRY_WORDS);
    let mut offset = 0;
    for &count in checks {
        words.push(Fr::from_u64(count as u64));
        for entry in &entries[offset..offset + count] {
            words.push(entry.side.word());
            words.push(entry.scalar);
            words.extend_from_slice(&g1_limbs(&entry.point));
        }
        offset += count;
    }
    Ok(words)
}

/// The inverse of [`accumulator_words`]: the entries and the group counts.
///
/// Every word is validated. A count that overruns the list, a side tag that is
/// neither `0` nor `1`, a limb at or above `2^128`, a partial infinity
/// sentinel, the all-zero quadruple, and a point off the curve are all errors.
///
/// The all-zero quadruple is rejected rather than read as infinity: in this
/// format infinity is `constants::G1_INFINITY_SENTINEL` in all four lanes and
/// nothing else, so admitting `curve`'s own all-zero-is-infinity byte rule here
/// would give the point at infinity two spellings and make the encoding
/// non-injective.
pub fn accumulator_from_words(
    words: &[Fr],
) -> Result<(Vec<AccumulatorEntry>, Vec<usize>), PcsError> {
    let malformed = |at: usize| PcsError::MalformedAccumulator {
        length: words.len(),
        at,
    };

    let mut entries = Vec::new();
    let mut checks = Vec::new();
    let mut at = 0;
    while at < words.len() {
        let count = small_usize(words[at]).ok_or_else(|| malformed(at))?;
        at += 1;
        // Written as a subtraction because `at + count * ENTRY_WORDS` can wrap.
        if count > (words.len() - at) / ENTRY_WORDS {
            return Err(malformed(at));
        }
        for _ in 0..count {
            let side = PairingSide::from_word(words[at]).ok_or_else(|| malformed(at))?;
            let limbs = [words[at + 2], words[at + 3], words[at + 4], words[at + 5]];
            entries.push(AccumulatorEntry {
                side,
                scalar: words[at + 1],
                point: g1_from_limbs(&limbs)?,
            });
            at += ENTRY_WORDS;
        }
        checks.push(count);
    }
    Ok((entries, checks))
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
/// `docs/spec/accumulator.md` §5.
pub fn accumulator_digest(words: &[Fr]) -> Fr {
    let mut sponge = Transcript::new();
    sponge.append_scalars(tags::ACCUMULATOR_DIGEST, words);
    sponge.sample()
}

// ---------------------------------------------------------------------------
// discharge
// ---------------------------------------------------------------------------

/// Spend an accumulator: one RLC weight per deferred check, one MSM per side,
/// one two-pairing check.
///
/// ```text
///   nu    = the merge challenge, from the accumulator digest
///   A     = sum_j nu^j * (sum of check j's G2One terms)
///   B     = sum_j nu^j * (sum of check j's G2X terms)
///   accept iff e(A, [1]_2) * e(-B, [x]_2) == 1
/// ```
///
/// `nu` is drawn from a sponge seeded with the digest of these very words,
/// because the frozen signature takes no transcript: a discharge must be a
/// deterministic function of the entries and nothing else. The weight is what
/// keeps the checks separate — a concatenation summed with weight `1` each is
/// satisfied by two relations whose errors cancel.
///
/// Every entry's point is validated here, on the curve and in the order-`r`
/// subgroup. `docs/spec/accumulator.md` §4 is normative for why that obligation
/// lands here and nowhere else.
pub fn discharge(
    vsrs: &SrsVerifier,
    entries: &[AccumulatorEntry],
    checks: &[usize],
) -> Result<(), PcsError> {
    // First, before the digest and before the merge challenge: an entry's point
    // is a claim, and this is the last place anyone looks at it.
    validate(entries)?;

    let words = accumulator_words(entries, checks)?;
    let digest = accumulator_digest(&words);

    let mut sponge = Transcript::new();
    sponge.append_scalar(tags::ACCUMULATOR_DIGEST, digest);
    let nu = sponge.challenge_scalar(tags::ACCUMULATOR_MERGE);

    check_pairings(vsrs, entries, checks, &crate::powers(nu, checks.len()))
}

/// The two merged pairings, over `entries` grouped by `checks` and weighted by
/// `weights`.
///
/// The one place a deferred relation is executed. [`discharge`] reaches it with
/// the powers of the merge challenge; [`crate::verify`] and
/// [`crate::batch_verify`] reach it with a single group and the weight `1`,
/// which is the same computation their S08 predecessor did by hand.
pub(crate) fn check_pairings(
    vsrs: &SrsVerifier,
    entries: &[AccumulatorEntry],
    checks: &[usize],
    weights: &[Fr],
) -> Result<(), PcsError> {
    partition(entries, checks)?;
    assert_eq!(
        checks.len(),
        weights.len(),
        "check_pairings: one weight per deferred check"
    );
    // [`discharge`] has validated already; `verify` and `batch_verify` reach
    // here directly, so the check lives on both paths rather than on neither.
    validate(entries)?;

    let mut a_bases: Vec<G1Affine> = Vec::new();
    let mut a_scalars: Vec<Fr> = Vec::new();
    let mut b_bases: Vec<G1Affine> = Vec::new();
    let mut b_scalars: Vec<Fr> = Vec::new();
    let mut offset = 0;
    for (&count, weight) in checks.iter().zip(weights) {
        for entry in &entries[offset..offset + count] {
            let scalar = *weight * entry.scalar;
            match entry.side {
                PairingSide::G2One => {
                    a_bases.push(entry.point);
                    a_scalars.push(scalar);
                }
                PairingSide::G2X => {
                    b_bases.push(entry.point);
                    b_scalars.push(scalar);
                }
            }
        }
        offset += count;
    }

    let a = msm(&a_bases, &a_scalars)
        .expect("one scalar per base")
        .to_affine();
    let b = msm(&b_bases, &b_scalars)
        .expect("one scalar per base")
        .to_affine();
    if curve::pairing::pairing_check(&[(a, vsrs.g2_gen), (-b, vsrs.g2_tau)]) {
        Ok(())
    } else {
        Err(PcsError::VerificationFailed)
    }
}

// ---------------------------------------------------------------------------
// Shared pieces
// ---------------------------------------------------------------------------

/// Every entry's point is on the curve and in the order-`r` subgroup.
///
/// An entry's point is a **claim**: transcript and digest absorption bind the
/// limbs a party wrote down (`docs/spec/mercury.md` §4), an entry built in
/// memory has been through no decoder, and the in-VM replay does no curve
/// arithmetic at all. `docs/spec/accumulator.md` §4 is the rule; this is it.
///
/// On G1 the subgroup check *is* the curve check — the cofactor is 1 — and both
/// are called anyway so this call site reads like every other one in the crate.
fn validate(entries: &[AccumulatorEntry]) -> Result<(), PcsError> {
    for entry in entries {
        if !entry.point.is_on_curve() || !entry.point.is_in_subgroup() {
            return Err(PcsError::InvalidPoint {
                field: "accumulator entry",
            });
        }
    }
    Ok(())
}

/// Check that `checks` partitions `entries`, in order.
///
/// A group of zero entries is legal — it contributes `nu^j` times an empty sum
/// — and is what the wire form's count word of `0` means. A count that
/// overruns, or counts that do not exhaust the list, is malformed. Written
/// without an addition that could wrap, because this runs on data.
fn partition(entries: &[AccumulatorEntry], checks: &[usize]) -> Result<(), PcsError> {
    let mut offset = 0usize;
    for &count in checks {
        if count > entries.len() - offset {
            return Err(PcsError::MalformedAccumulator {
                length: entries.len(),
                at: offset.saturating_add(count),
            });
        }
        offset += count;
    }
    if offset != entries.len() {
        return Err(PcsError::MalformedAccumulator {
            length: entries.len(),
            at: offset,
        });
    }
    Ok(())
}

/// An `Fr` that is a small non-negative integer, as a `usize`.
///
/// A count word is a length, so anything wider than 64 bits — or wider than a
/// `usize` on this machine — is malformed rather than truncated.
fn small_usize(x: Fr) -> Option<usize> {
    let bytes = x.to_bytes();
    if bytes[8..].iter().any(|b| *b != 0) {
        return None;
    }
    let mut low = [0u8; 8];
    low.copy_from_slice(&bytes[..8]);
    usize::try_from(u64::from_le_bytes(low)).ok()
}

/// The point four accumulator limbs name, or an error.
///
/// The exact inverse of `crate::g1_limbs`: four sentinels are infinity, four
/// 128-bit halves reassemble into the 64-byte affine encoding S05 froze, and
/// everything else is malformed. `curve::G1Affine::from_bytes` then validates
/// canonicity, the curve equation and subgroup membership.
fn g1_from_limbs(limbs: &[Fr; 4]) -> Result<G1Affine, PcsError> {
    let invalid = PcsError::InvalidPoint {
        field: "accumulator entry",
    };
    let sentinel = infinity_sentinel();
    if limbs.iter().all(|limb| *limb == sentinel) {
        return Ok(G1Affine::IDENTITY);
    }
    if limbs.contains(&sentinel) {
        return Err(invalid);
    }

    let mut bytes = [0u8; 64];
    for (k, limb) in limbs.iter().enumerate() {
        let raw = limb.to_bytes();
        if raw[16..].iter().any(|b| *b != 0) {
            return Err(invalid);
        }
        let at = 32 * (k / 2) + 16 * (k % 2);
        bytes[at..at + 16].copy_from_slice(&raw[..16]);
    }
    // `curve` reads all-zero bytes as infinity; this format does not, because
    // infinity is the sentinel here and two spellings would break injectivity.
    if bytes == [0u8; 64] {
        return Err(invalid);
    }
    G1Affine::from_bytes(&bytes).ok_or(invalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(side: PairingSide, scalar: u64, point: G1Affine) -> AccumulatorEntry {
        AccumulatorEntry {
            side,
            scalar: Fr::from_u64(scalar),
            point,
        }
    }

    fn sample() -> Vec<AccumulatorEntry> {
        vec![
            entry(PairingSide::G2One, 7, G1Affine::GENERATOR),
            entry(PairingSide::G2X, 9, G1Affine::IDENTITY),
        ]
    }

    /// The words round trip, and the group counts come back with them.
    #[test]
    fn the_word_form_round_trips() {
        let entries = sample();
        let words = accumulator_words(&entries, &[1, 1]).expect("a valid partition");
        assert_eq!(words.len(), 2 + 2 * ENTRY_WORDS);
        assert_eq!(
            accumulator_from_words(&words).expect("the words decode"),
            (entries.clone(), vec![1, 1])
        );

        // And one group of two is a different list from two groups of one.
        let together = accumulator_words(&entries, &[2]).expect("a valid partition");
        assert_ne!(together, words);
        assert_eq!(
            accumulator_from_words(&together).expect("the words decode"),
            (entries, vec![2])
        );
    }

    /// Byte concatenation of two lists is a valid list, and its digest is
    /// neither half's.
    #[test]
    fn concatenation_is_a_list() {
        let entries = sample();
        let words = accumulator_words(&entries, &[2]).expect("a valid partition");
        let mut joined = words.clone();
        joined.extend_from_slice(&words);

        let (back, checks) = accumulator_from_words(&joined).expect("the words decode");
        assert_eq!(checks, vec![2, 2]);
        assert_eq!(back.len(), 4);
        assert_eq!(accumulator_words(&back, &checks).expect("valid"), joined);

        let half = accumulator_digest(&words);
        assert_ne!(accumulator_digest(&joined), half);
        assert_ne!(accumulator_digest(&joined), Fr::ZERO);
    }

    /// A group of zero entries is legal, and the empty list is the empty list.
    #[test]
    fn an_empty_group_is_legal() {
        assert_eq!(
            accumulator_words(&[], &[0, 0]).expect("legal"),
            vec![Fr::ZERO, Fr::ZERO]
        );
        assert_eq!(
            accumulator_from_words(&[Fr::ZERO, Fr::ZERO]).expect("decodes"),
            (Vec::new(), vec![0, 0])
        );
        assert_eq!(
            accumulator_words(&[], &[]).expect("legal"),
            Vec::<Fr>::new()
        );
    }

    /// Counts that do not partition the entries are an error, never a panic.
    #[test]
    fn a_bad_partition_is_an_error() {
        let entries = sample();
        for checks in [
            vec![1],
            vec![3],
            vec![1, 2],
            vec![usize::MAX],
            vec![0, usize::MAX],
            vec![],
        ] {
            assert!(
                matches!(
                    accumulator_words(&entries, &checks),
                    Err(PcsError::MalformedAccumulator { .. })
                ),
                "checks {checks:?}"
            );
        }
        assert!(accumulator_words(&entries, &[2]).is_ok());
        assert!(accumulator_words(&entries, &[1, 1]).is_ok());
        assert!(accumulator_words(&entries, &[0, 2]).is_ok());
    }

    /// Every malformed word sequence is rejected: a count that overruns, a
    /// count that is not a small integer, a bad side tag, a truncated group.
    #[test]
    fn malformed_words_are_rejected() {
        let entries = sample();
        let words = accumulator_words(&entries, &[2]).expect("a valid partition");
        assert!(accumulator_from_words(&words).is_ok(), "the control");

        let mut overrun = words.clone();
        overrun[0] = Fr::from_u64(3);
        assert!(matches!(
            accumulator_from_words(&overrun),
            Err(PcsError::MalformedAccumulator { .. })
        ));

        let mut huge = words.clone();
        huge[0] = -Fr::ONE;
        assert!(matches!(
            accumulator_from_words(&huge),
            Err(PcsError::MalformedAccumulator { .. })
        ));

        let mut side = words.clone();
        side[1] = Fr::from_u64(2);
        assert!(matches!(
            accumulator_from_words(&side),
            Err(PcsError::MalformedAccumulator { .. })
        ));

        assert!(matches!(
            accumulator_from_words(&words[..words.len() - 1]),
            Err(PcsError::MalformedAccumulator { .. })
        ));

        // A count word of exactly `2^64`: the smallest one a 64-bit truncation
        // would read as an empty group instead of rejecting.
        let mut wide = words.clone();
        wide[0] = Fr::from_u64(u64::MAX) + Fr::ONE;
        assert!(matches!(
            accumulator_from_words(&wide),
            Err(PcsError::MalformedAccumulator { .. })
        ));
    }

    /// The limb decoder: infinity is the sentinel and nothing else, and a
    /// corrupted infinity encoding is an error rather than a different point.
    #[test]
    fn the_limb_decoder_admits_one_spelling_of_infinity() {
        let sentinel = infinity_sentinel();
        assert_eq!(
            g1_from_limbs(&[sentinel; 4]).expect("four sentinels are infinity"),
            G1Affine::IDENTITY
        );
        assert_eq!(
            g1_from_limbs(&g1_limbs(&G1Affine::GENERATOR)).expect("a real point"),
            G1Affine::GENERATOR
        );

        // A partial sentinel, in every lane.
        for lane in 0..4 {
            let mut limbs = g1_limbs(&G1Affine::GENERATOR);
            limbs[lane] = sentinel;
            assert!(g1_from_limbs(&limbs).is_err(), "lane {lane}");

            let mut limbs = [sentinel; 4];
            limbs[lane] = Fr::ZERO;
            assert!(g1_from_limbs(&limbs).is_err(), "lane {lane}");
        }

        // The all-zero quadruple is `(0, 0)`, which is off the curve — and
        // must not come back as infinity the way `curve`'s byte form would.
        assert!(g1_from_limbs(&[Fr::ZERO; 4]).is_err());

        // A limb at or above 2^128 that is not the sentinel.
        let mut limbs = g1_limbs(&G1Affine::GENERATOR);
        limbs[0] = sentinel + Fr::ONE;
        assert!(g1_from_limbs(&limbs).is_err());

        // An on-curve-looking point that is not on the curve.
        let mut limbs = g1_limbs(&G1Affine::GENERATOR);
        limbs[2] += Fr::ONE;
        assert!(g1_from_limbs(&limbs).is_err());
    }

    /// A count word is a length: nothing wider than a `usize` is one.
    #[test]
    fn only_small_integers_are_counts() {
        assert_eq!(small_usize(Fr::ZERO), Some(0));
        assert_eq!(small_usize(Fr::from_u64(12)), Some(12));
        assert_eq!(
            small_usize(Fr::from_u64(u64::MAX)),
            usize::try_from(u64::MAX).ok()
        );
        assert_eq!(small_usize(-Fr::ONE), None);
        assert_eq!(small_usize(Fr::from_u64(1) + infinity_sentinel()), None);

        // The bound is at 64 bits, and `2^64` is where that bites: anything
        // wider truncates to a *plausible* count rather than an absurd one, so
        // the interval just above the bound is the one that has to be pinned.
        let two_to_the_64 = Fr::from_u64(u64::MAX) + Fr::ONE;
        assert_eq!(small_usize(two_to_the_64), None);
        assert_eq!(small_usize(two_to_the_64 + Fr::ONE), None);
        assert_eq!(small_usize(two_to_the_64 * Fr::from_u64(1 << 32)), None);
    }
}
