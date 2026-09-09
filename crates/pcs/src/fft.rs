//! The radix-2 FFT over `Fr`'s two-adic subgroup, at size `2b` and no larger.
//!
//! Mercury needs exactly one thing from a transform: the two products of
//! degree-`< b` polynomials that make up `S(X)`. `2b` points determine a
//! product of degree `2b - 2`, so `2b` is both the size used and the ceiling —
//! `crates/pcs/tests/structure.rs` asserts no larger transform is reachable.
//!
//! Serial on purpose. At the largest supported height, `n = 2^22`, this is a
//! 4,096-point transform sitting beside two 2^22-point MSMs; parallelising it
//! would buy nothing and would put a scheduling-dependent code path in the
//! middle of a proof.

use constants::{FR_TWO_ADICITY, FR_TWO_ADIC_ROOT_OF_UNITY};
use field::Fr;

/// The evaluation domain of size `m = 2^k`: its generator's powers, and the
/// same table for the inverse transform.
pub struct Domain {
    /// `omega^0 .. omega^(m/2 - 1)`, the twiddles a forward transform reads.
    forward: Vec<Fr>,
    /// The same for `omega^-1`.
    inverse: Vec<Fr>,
    /// `m^-1`, the scaling an inverse transform ends with.
    m_inverse: Fr,
}

impl Domain {
    /// The domain for multiplying two polynomials of at most `half`
    /// coefficients each: size `2 * half`, and there is no other way to ask for
    /// one.
    ///
    /// The size is a function of the operand size rather than a free
    /// parameter, which is what makes "no transform in this crate exceeds
    /// `2b`" a property of the type and not of a comment.
    ///
    /// The generator is `FR_TWO_ADIC_ROOT_OF_UNITY` squared down to order `m`.
    pub fn for_product(half: usize) -> Domain {
        assert!(
            half.is_power_of_two(),
            "fft::Domain::for_product: operand size {half} is not a power of two"
        );
        let m = 2 * half;
        let k = m.trailing_zeros();
        assert!(
            k <= FR_TWO_ADICITY,
            "fft::Domain::for_product: size 2^{k} exceeds Fr's two-adic subgroup, 2^{FR_TWO_ADICITY}"
        );

        let mut omega = Fr::from_hex(FR_TWO_ADIC_ROOT_OF_UNITY)
            .expect("the frozen two-adic root is a canonical hex literal");
        for _ in k..FR_TWO_ADICITY {
            omega = omega.square();
        }
        let omega_inv = omega
            .inverse()
            .expect("a root of unity is nonzero for every m >= 1");

        Domain {
            forward: powers(omega, m / 2),
            inverse: powers(omega_inv, m / 2),
            m_inverse: Fr::from_u64(m as u64)
                .inverse()
                .expect("m is a power of two below the field characteristic"),
        }
    }

    /// In place, `a[k] <- a(omega^k)`. `a` must have exactly `m` coefficients.
    pub fn fft(&self, a: &mut [Fr]) {
        butterflies(a, &self.forward);
    }

    /// The inverse of [`Domain::fft`].
    pub fn ifft(&self, a: &mut [Fr]) {
        butterflies(a, &self.inverse);
        for x in a.iter_mut() {
            *x *= self.m_inverse;
        }
    }
}

/// `[x^0, .., x^(count-1)]`.
fn powers(x: Fr, count: usize) -> Vec<Fr> {
    let mut out = Vec::with_capacity(count);
    let mut acc = Fr::ONE;
    for _ in 0..count {
        out.push(acc);
        acc *= x;
    }
    out
}

/// Iterative decimation-in-time Cooley-Tukey: bit-reverse, then `log2(m)`
/// passes of butterflies over precomputed twiddles.
///
/// `twiddles[k]` is `w^k` for `k < m/2`, and the pass at half-width `half`
/// strides the table by `m / (2 * half)`, which is how one table serves every
/// pass.
fn butterflies(a: &mut [Fr], twiddles: &[Fr]) {
    let m = a.len();
    assert_eq!(
        twiddles.len() * 2,
        m,
        "fft: the twiddle table does not match the transform size"
    );
    if m <= 1 {
        return;
    }

    // The bit-reversal permutation, swapping each pair exactly once.
    let bits = m.trailing_zeros();
    for i in 0..m {
        let j = i.reverse_bits() >> (usize::BITS - bits);
        if i < j {
            a.swap(i, j);
        }
    }

    let mut half = 1;
    while half < m {
        let step = m / (2 * half);
        let mut start = 0;
        while start < m {
            for k in 0..half {
                let w = twiddles[k * step];
                let lo = a[start + k];
                let hi = a[start + k + half] * w;
                a[start + k] = lo + hi;
                a[start + k + half] = lo - hi;
            }
            start += 2 * half;
        }
        half *= 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::Rng;

    /// The `2^k`-th root of unity, re-derived from the smallest multiplicative
    /// generator of `Fr^*` rather than read out of `constants`.
    fn root(k: u32) -> Fr {
        // (p - 1) >> k, as a 256-bit little-endian integer.
        let mut e = constants::FR_MODULUS;
        let mut borrow = 1u64;
        for limb in e.iter_mut() {
            let (v, b) = limb.overflowing_sub(borrow);
            *limb = v;
            borrow = u64::from(b);
        }
        for _ in 0..k {
            let mut carry = 0u64;
            for limb in e.iter_mut().rev() {
                let next = *limb << 63;
                *limb = (*limb >> 1) | carry;
                carry = next;
            }
        }
        Fr::from_u64(5).pow(&e)
    }

    #[test]
    fn the_frozen_root_has_exactly_the_claimed_order() {
        let omega = Fr::from_hex(FR_TWO_ADIC_ROOT_OF_UNITY).expect("canonical");
        assert_eq!(
            omega,
            root(FR_TWO_ADICITY),
            "5^((p-1)/2^28) is the constant"
        );

        let mut x = omega;
        for _ in 0..FR_TWO_ADICITY - 1 {
            assert_ne!(x, Fr::ONE, "the order is not smaller than 2^28");
            x = x.square();
        }
        assert_eq!(x, Fr::MINUS_ONE, "the last square before one is -1");
        assert_eq!(x.square(), Fr::ONE, "the order divides 2^28");
    }

    fn next_fr(rng: &mut Rng) -> Fr {
        loop {
            let mut b = rng.next_le32();
            b[31] &= 0x3f;
            if let Some(x) = Fr::from_bytes(&b) {
                return x;
            }
        }
    }

    /// The transform really is evaluation at the powers of `omega`, checked
    /// against the `O(m^2)` definition.
    #[test]
    fn the_transform_is_the_naive_one() {
        let mut rng = Rng::new(0x5008_0700);
        for k in 1..=8u32 {
            let half = 1usize << (k - 1);
            let m = 2 * half;
            let omega = root(k);

            let a: Vec<Fr> = (0..m).map(|_| next_fr(&mut rng)).collect();
            let mut got = a.clone();
            Domain::for_product(half).fft(&mut got);

            let mut point = Fr::ONE;
            for expected in got.iter().take(m) {
                let mut naive = Fr::ZERO;
                let mut power = Fr::ONE;
                for coefficient in &a {
                    naive += *coefficient * power;
                    power *= point;
                }
                assert_eq!(*expected, naive, "size {m}");
                point *= omega;
            }
        }
    }

    #[test]
    fn the_inverse_undoes_the_transform() {
        let mut rng = Rng::new(0x5008_0701);
        for k in 1..=10u32 {
            let half = 1usize << (k - 1);
            let domain = Domain::for_product(half);
            let a: Vec<Fr> = (0..2 * half).map(|_| next_fr(&mut rng)).collect();
            let mut work = a.clone();
            domain.fft(&mut work);
            domain.ifft(&mut work);
            assert_eq!(work, a, "size {}", 2 * half);
        }
    }

    /// Pointwise multiplication in the evaluation domain is polynomial
    /// multiplication, which is the only thing this transform is for.
    #[test]
    fn the_transform_multiplies_polynomials() {
        let mut rng = Rng::new(0x5008_0702);
        for k in 0..7u32 {
            let b = 1usize << k;
            let domain = Domain::for_product(b);
            let mut x = vec![Fr::ZERO; 2 * b];
            let mut y = vec![Fr::ZERO; 2 * b];
            for i in 0..b {
                x[i] = next_fr(&mut rng);
                y[i] = next_fr(&mut rng);
            }
            let (a, c) = (x.clone(), y.clone());
            domain.fft(&mut x);
            domain.fft(&mut y);
            let mut product: Vec<Fr> = x.iter().zip(&y).map(|(p, q)| *p * *q).collect();
            domain.ifft(&mut product);

            let mut naive = vec![Fr::ZERO; 2 * b];
            for i in 0..b {
                for j in 0..b {
                    naive[i + j] += a[i] * c[j];
                }
            }
            assert_eq!(product, naive, "b = {b}");
            assert_eq!(product[2 * b - 1], Fr::ZERO, "degree < 2b - 1");
        }
    }

    #[test]
    #[should_panic(expected = "is not a power of two")]
    fn a_non_power_of_two_operand_is_refused() {
        Domain::for_product(3);
    }

    #[test]
    #[should_panic(expected = "two-adic subgroup")]
    fn a_size_past_the_two_adic_subgroup_is_refused() {
        Domain::for_product(1usize << FR_TWO_ADICITY);
    }
}
