//! Windowed Pippenger multi-scalar multiplication over G1.
//!
//! Two entry points, and they never dispatch into one another:
//! [`msm`] always runs the general 254-bit path, and [`msm_small_u32`] is the
//! only way into the small-scalar path. S03 backs trace columns with `u8`,
//! `u16` and `u32`, so the small case is the prover's common one and it is
//! worth its own code rather than a branch inside the general one.
//!
//! # The algorithm
//!
//! For window width `w`, each scalar is recoded into signed digits in
//! `[-2^(w-1), 2^(w-1)]`, one per window. Window `i` accumulates each base into
//! the bucket named by the magnitude of its digit — negated when the digit is
//! negative, which costs one `Fq` negation — reduces the buckets by a running
//! sum, and the windows are then combined by doublings. Signed digits halve the
//! bucket count for free; that is the only trick here.
//!
//! The window width follows arkworks' rule, so the benchmark against arkworks
//! compares like with like.

use rayon::prelude::*;

use field::Fr;

use crate::g1::{G1Affine, G1Projective};

/// The one way [`msm`] and [`msm_small_u32`] can fail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MsmError {
    /// A scalar per base, or nothing. Every other input — an empty slice, a
    /// zero scalar, a base at infinity, one element — is answerable.
    LengthMismatch { bases: usize, scalars: usize },
}

/// Bits in an `Fr` scalar. The modulus is below `2^254`, and the recoding
/// leans on that: see [`window_count`].
const FR_BITS: usize = 254;

/// Bits in a `u32` scalar.
const U32_BITS: usize = 32;

/// `sum_i scalars[i] * bases[i]`, by windowed Pippenger over the full 254-bit
/// scalars.
///
/// This never inspects the magnitude of a scalar: small inputs go through the
/// general path exactly like any other, and [`msm_small_u32`] is the only door
/// to the cheaper one. Empty input is the identity.
pub fn msm(bases: &[G1Affine], scalars: &[Fr]) -> Result<G1Projective, MsmError> {
    if bases.len() != scalars.len() {
        return Err(MsmError::LengthMismatch {
            bases: bases.len(),
            scalars: scalars.len(),
        });
    }
    if bases.is_empty() {
        return Ok(G1Projective::IDENTITY);
    }

    let w = window_bits(bases.len());
    let windows = window_count(FR_BITS, w);

    let mut digits = vec![0i32; bases.len() * windows];
    digits
        .par_chunks_mut(windows)
        .zip(scalars.par_iter())
        .for_each(|(out, scalar)| recode(&canonical_limbs(scalar), w, out));

    Ok(pippenger(bases, &digits, windows, w))
}

/// `sum_i scalars[i] * bases[i]` for scalars that fit in a `u32`.
///
/// Identical in value to [`msm`] on the same scalars lifted into `Fr`, and
/// cheaper for two reasons: a 32-bit scalar needs a fifth of the windows a
/// 254-bit one does, and its digits come straight off the integer with no
/// Montgomery reduction to canonical form first. `u8` and `u16` columns come
/// through here too; there is no narrower entry point, because the window
/// count is what costs, and it is already 2 or 3.
pub fn msm_small_u32(bases: &[G1Affine], scalars: &[u32]) -> Result<G1Projective, MsmError> {
    if bases.len() != scalars.len() {
        return Err(MsmError::LengthMismatch {
            bases: bases.len(),
            scalars: scalars.len(),
        });
    }
    if bases.is_empty() {
        return Ok(G1Projective::IDENTITY);
    }

    let w = window_bits(bases.len());
    let windows = window_count(U32_BITS, w);

    let mut digits = vec![0i32; bases.len() * windows];
    digits
        .par_chunks_mut(windows)
        .zip(scalars.par_iter())
        .for_each(|(out, scalar)| recode_u32(*scalar, w, out));

    Ok(pippenger(bases, &digits, windows, w))
}

// ---------------------------------------------------------------------------
// Sizing
// ---------------------------------------------------------------------------

/// The window width for `n` points.
///
/// arkworks' heuristic verbatim — `3` below 32 points, `ln(n) + 2` above it,
/// with the natural log done in integers as `log2(n) * 69 / 100`. Copying the
/// rule rather than inventing one is what makes the S07 acceptance-9 benchmark
/// a comparison of implementations rather than of window choices.
fn window_bits(n: usize) -> usize {
    if n < 32 {
        3
    } else {
        (log2(n) * 69) / 100 + 2
    }
}

/// arkworks' `log2`: the exponent for a power of two, the bit length otherwise.
fn log2(n: usize) -> usize {
    if n.is_power_of_two() {
        n.trailing_zeros() as usize
    } else {
        (usize::BITS - n.leading_zeros()) as usize
    }
}

/// Windows needed to recode a `bits`-bit scalar with every digit in
/// `[-2^(w-1), 2^(w-1)]`.
///
/// The recoding carries a 1 out of any window whose value reaches `2^(w-1)`,
/// so the top window must have room to swallow the carry instead of emitting
/// one. Its raw value is below `2^(bits - (d-1)w)`, so `+1` still fits in
/// `2^(w-1)` exactly when `bits - (d-1)w <= w - 1`, i.e. `d*w >= bits + 1`.
///
/// That is one more bit than the obvious `ceil(bits / w)` asks for, and for
/// every width this crate can pick it is the same number: `w` in `3..=29`
/// never divides 254 or 32.
fn window_count(bits: usize, w: usize) -> usize {
    (bits + 1).div_ceil(w)
}

// ---------------------------------------------------------------------------
// Scalar recoding
// ---------------------------------------------------------------------------

/// A scalar's canonical (non-Montgomery) value as four little-endian limbs.
fn canonical_limbs(scalar: &Fr) -> [u64; 4] {
    let bytes = scalar.to_bytes();
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut w = [0u8; 8];
        w.copy_from_slice(chunk);
        *limb = u64::from_le_bytes(w);
    }
    limbs
}

/// `w` bits of `limbs` starting at bit `offset`, which is always below 256.
#[inline]
fn window_of(limbs: &[u64; 4], offset: usize, w: usize) -> u64 {
    let limb = offset / 64;
    let shift = offset % 64;
    let mut v = limbs[limb] >> shift;
    // A shift of exactly 64 is undefined, hence the `shift > 0` guard rather
    // than a `wrapping_shl`.
    if shift > 0 && limb + 1 < 4 {
        v |= limbs[limb + 1] << (64 - shift);
    }
    v & ((1u64 << w) - 1)
}

/// Recode one 254-bit scalar into `out`, one signed digit per window.
///
/// Digit `i` is `raw_i + carry_i - 2^w * carry_{i+1}`, where the carry is set
/// whenever that sum reaches `2^(w-1)`. The top window emits no carry — by
/// [`window_count`] its sum cannot exceed `2^(w-1)` — so the digits sum back to
/// the scalar exactly and every one of them has magnitude at most `2^(w-1)`.
fn recode(limbs: &[u64; 4], w: usize, out: &mut [i32]) {
    let half = 1u64 << (w - 1);
    let radix = 1i64 << w;
    let last = out.len() - 1;
    let mut carry = 0u64;
    for (i, digit) in out.iter_mut().enumerate() {
        let coef = window_of(limbs, i * w, w) + carry;
        if i == last {
            debug_assert!(coef <= half, "the top window swallowed no carry");
            *digit = coef as i32;
        } else if coef >= half {
            *digit = (coef as i64 - radix) as i32;
            carry = 1;
        } else {
            *digit = coef as i32;
            carry = 0;
        }
    }
}

/// Recode one 32-bit scalar. The same rule as [`recode`], minus the machinery
/// for a window that straddles two limbs: every window of a `u32` lives inside
/// one `u64` shift.
fn recode_u32(scalar: u32, w: usize, out: &mut [i32]) {
    let half = 1u64 << (w - 1);
    let radix = 1i64 << w;
    let mask = (1u64 << w) - 1;
    let value = scalar as u64;
    let last = out.len() - 1;
    let mut carry = 0u64;
    for (i, digit) in out.iter_mut().enumerate() {
        // `window_count(32, w)` keeps `i * w` at 32 or below.
        let coef = ((value >> (i * w)) & mask) + carry;
        if i == last {
            debug_assert!(coef <= half, "the top window swallowed no carry");
            *digit = coef as i32;
        } else if coef >= half {
            *digit = (coef as i64 - radix) as i32;
            carry = 1;
        } else {
            *digit = coef as i32;
            carry = 0;
        }
    }
}

// ---------------------------------------------------------------------------
// The bucket machinery, shared by both paths
// ---------------------------------------------------------------------------

/// Accumulate, reduce and combine. `digits` is scalar-major: digit `i` of
/// scalar `j` sits at `digits[j * windows + i]`.
fn pippenger(bases: &[G1Affine], digits: &[i32], windows: usize, w: usize) -> G1Projective {
    let n = bases.len();
    let buckets = 1usize << (w - 1);

    // One task per (window, input chunk). Windows alone leave cores idle
    // exactly where it hurts most: the small-scalar path has two or three of
    // them. Chunking the input splits a window's work further, and it is
    // exact — bucket sums are group elements, so splitting the inputs and
    // adding the partial sums gives the same point on any core count. The
    // second clamp keeps a chunk from being smaller than its own bucket array.
    let chunks = rayon::current_num_threads()
        .div_ceil(windows)
        .clamp(1, (n / buckets).max(1));
    let chunk_len = n.div_ceil(chunks);

    let partials: Vec<G1Projective> = (0..windows * chunks)
        .into_par_iter()
        .map(|task| {
            let start = ((task % chunks) * chunk_len).min(n);
            let end = (start + chunk_len).min(n);
            window_sum(
                &bases[start..end],
                &digits[start * windows..end * windows],
                windows,
                task / chunks,
                buckets,
            )
        })
        .collect();

    // Horner over the windows, most significant first. Doubling the identity
    // is a no-op, so the first pass needs no special case.
    let mut acc = G1Projective::IDENTITY;
    for window in (0..windows).rev() {
        for _ in 0..w {
            acc = acc.double();
        }
        for chunk in 0..chunks {
            acc = acc.add(&partials[window * chunks + chunk]);
        }
    }
    acc
}

/// One window's contribution over one slice of the input.
fn window_sum(
    bases: &[G1Affine],
    digits: &[i32],
    windows: usize,
    window: usize,
    buckets: usize,
) -> G1Projective {
    if bases.is_empty() {
        return G1Projective::IDENTITY;
    }

    let mut bucket = vec![G1Projective::IDENTITY; buckets];
    for (j, base) in bases.iter().enumerate() {
        let digit = digits[j * windows + window];
        if digit == 0 {
            continue;
        }
        // `1 <= |digit| <= 2^(w-1)`, so this index is in range by construction.
        let slot = &mut bucket[digit.unsigned_abs() as usize - 1];
        *slot = if digit > 0 {
            slot.add_affine(base)
        } else {
            slot.add_affine(&-*base)
        };
    }

    // Running sum from the top: `sum_k (k+1) * bucket[k]` in two adds each.
    let mut running = G1Projective::IDENTITY;
    let mut total = G1Projective::IDENTITY;
    for b in bucket.iter().rev() {
        running = running.add(b);
        total = total.add(&running);
    }
    total
}
