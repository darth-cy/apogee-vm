//! Dense univariate polynomials, as plain `Vec<Fr>` coefficient vectors.
//!
//! `c[i]` multiplies `X^i` — little-endian in the degree, the same order
//! `srs::kzg` uses and the same order `crates/poly` indexes a multilinear's
//! evaluation table in. A polynomial's length is its coefficient count, not
//! its degree; trailing zeros are allowed and never trimmed, because every
//! length here is fixed by `n` and `b` rather than by the data.
//!
//! Everything in this module runs on polynomials of size `O(b)` except
//! [`div_by_linear`], which the opening also calls once at size `n`.

use field::Fr;

/// `c(x)`, by Horner. The empty polynomial is the zero polynomial.
pub fn eval(c: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::ZERO;
    for a in c.iter().rev() {
        acc = acc * x + *a;
    }
    acc
}

/// `(quotient, remainder)` for `c(X) / (X - r)`, by synthetic division.
///
/// Running Horner from the top coefficient down, the value carried into step
/// `i` *is* the quotient's coefficient of `X^i`, and what falls out at the
/// bottom is `c(r)`. The quotient has one coefficient fewer than `c`; an empty
/// `c` divides to an empty quotient and a zero remainder.
pub fn div_by_linear(c: &[Fr], r: Fr) -> (Vec<Fr>, Fr) {
    if c.is_empty() {
        return (Vec::new(), Fr::ZERO);
    }
    let mut q = vec![Fr::ZERO; c.len() - 1];
    let mut acc = c[c.len() - 1];
    for i in (0..c.len() - 1).rev() {
        q[i] = acc;
        acc = c[i] + acc * r;
    }
    (q, acc)
}

/// Schoolbook product. Used only on a factor of degree at most two, so this is
/// `O(b)` at every call site.
pub fn mul(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut out = vec![Fr::ZERO; a.len() + b.len() - 1];
    for (i, ai) in a.iter().enumerate() {
        for (j, bj) in b.iter().enumerate() {
            out[i + j] += *ai * *bj;
        }
    }
    out
}

/// `acc += c * src`, growing `acc` as needed.
pub fn add_scaled(acc: &mut Vec<Fr>, src: &[Fr], c: Fr) {
    if src.len() > acc.len() {
        acc.resize(src.len(), Fr::ZERO);
    }
    for (a, s) in acc.iter_mut().zip(src) {
        *a += c * *s;
    }
}

/// `prod_i (X - roots[i])`, the vanishing polynomial of a point list.
pub fn vanishing(roots: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::ONE];
    for r in roots {
        out = mul(&out, &[-*r, Fr::ONE]);
    }
    out
}

/// The unique polynomial of degree `< points.len()` through `points`, by the
/// Lagrange formula.
///
/// Panics if two abscissae coincide, which names a broken invariant: the caller
/// is required to have rejected a degenerate challenge set first.
pub fn interpolate(points: &[(Fr, Fr)]) -> Vec<Fr> {
    let mut out = vec![Fr::ZERO; points.len()];
    for (i, (xi, yi)) in points.iter().enumerate() {
        let mut num = vec![Fr::ONE];
        let mut den = Fr::ONE;
        for (j, (xj, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            num = mul(&num, &[-*xj, Fr::ONE]);
            den *= *xi - *xj;
        }
        let den = den
            .inverse()
            .expect("interpolate: the abscissae must be distinct");
        add_scaled(&mut out, &num, *yi * den);
    }
    out
}

/// `x^e`, by square-and-multiply over a `usize` exponent.
pub fn pow_usize(x: Fr, mut e: usize) -> Fr {
    let mut acc = Fr::ONE;
    let mut base = x;
    while e > 0 {
        if e & 1 == 1 {
            acc *= base;
        }
        base = base.square();
        e >>= 1;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_support::Rng;

    fn next_fr(rng: &mut Rng) -> Fr {
        loop {
            let mut b = rng.next_le32();
            b[31] &= 0x3f;
            if let Some(x) = Fr::from_bytes(&b) {
                return x;
            }
        }
    }

    fn random(rng: &mut Rng, len: usize) -> Vec<Fr> {
        (0..len).map(|_| next_fr(rng)).collect()
    }

    /// `eval` is the sum of `c[i] x^i`, written the other way round.
    #[test]
    fn eval_is_the_definition() {
        let mut rng = Rng::new(0x5008_0800);
        for len in 0..12 {
            let c = random(&mut rng, len);
            let x = next_fr(&mut rng);
            let mut expected = Fr::ZERO;
            let mut power = Fr::ONE;
            for a in &c {
                expected += *a * power;
                power *= x;
            }
            assert_eq!(eval(&c, x), expected, "len {len}");
        }
        assert_eq!(eval(&[], Fr::ONE), Fr::ZERO);
    }

    /// `c = q * (X - r) + rem`, reassembled.
    #[test]
    fn division_reassembles() {
        let mut rng = Rng::new(0x5008_0801);
        for len in 1..12 {
            let c = random(&mut rng, len);
            let r = next_fr(&mut rng);
            let (q, rem) = div_by_linear(&c, r);
            assert_eq!(q.len(), len - 1);
            assert_eq!(rem, eval(&c, r), "the remainder is c(r)");

            let mut back = mul(&q, &[-r, Fr::ONE]);
            if back.is_empty() {
                back = vec![Fr::ZERO];
            }
            back[0] += rem;
            back.resize(len, Fr::ZERO);
            assert_eq!(back, c, "len {len}");
        }
        assert_eq!(div_by_linear(&[], Fr::ONE), (Vec::new(), Fr::ZERO));
    }

    /// The product agrees with evaluation at random points.
    #[test]
    fn multiplication_is_pointwise() {
        let mut rng = Rng::new(0x5008_0802);
        for (n, m) in [(1, 1), (1, 5), (3, 4), (7, 2), (6, 6)] {
            let a = random(&mut rng, n);
            let b = random(&mut rng, m);
            let product = mul(&a, &b);
            assert_eq!(product.len(), n + m - 1);
            for _ in 0..4 {
                let x = next_fr(&mut rng);
                assert_eq!(eval(&product, x), eval(&a, x) * eval(&b, x));
            }
        }
        assert!(mul(&[], &[Fr::ONE]).is_empty());
    }

    /// `vanishing` really vanishes, and only there.
    #[test]
    fn the_vanishing_polynomial_vanishes() {
        let mut rng = Rng::new(0x5008_0803);
        assert_eq!(vanishing(&[]), vec![Fr::ONE]);
        for count in 1..5 {
            let roots = random(&mut rng, count);
            let z = vanishing(&roots);
            assert_eq!(z.len(), count + 1);
            assert_eq!(*z.last().expect("monic"), Fr::ONE, "monic");
            for r in &roots {
                assert_eq!(eval(&z, *r), Fr::ZERO);
            }
            assert_ne!(eval(&z, next_fr(&mut rng)), Fr::ZERO);
        }
    }

    /// The interpolant passes through its points and has the right degree.
    #[test]
    fn interpolation_passes_through_its_points() {
        let mut rng = Rng::new(0x5008_0804);
        for count in 1..4 {
            let xs = random(&mut rng, count);
            let ys = random(&mut rng, count);
            let points: Vec<(Fr, Fr)> = xs.iter().copied().zip(ys.iter().copied()).collect();
            let r = interpolate(&points);
            assert_eq!(r.len(), count);
            for (x, y) in &points {
                assert_eq!(eval(&r, *x), *y);
            }
        }
        // A polynomial of degree < count is its own interpolant.
        let c = random(&mut rng, 3);
        let xs = random(&mut rng, 3);
        let points: Vec<(Fr, Fr)> = xs.iter().map(|x| (*x, eval(&c, *x))).collect();
        assert_eq!(interpolate(&points), c);
    }

    #[test]
    #[should_panic(expected = "distinct")]
    fn interpolating_through_a_repeated_point_panics() {
        let x = Fr::from_u64(7);
        interpolate(&[(x, Fr::ONE), (x, Fr::ZERO)]);
    }

    #[test]
    fn pow_usize_is_repeated_multiplication() {
        let mut rng = Rng::new(0x5008_0805);
        let x = next_fr(&mut rng);
        let mut expected = Fr::ONE;
        for e in 0..40usize {
            assert_eq!(pow_usize(x, e), expected, "exponent {e}");
            expected *= x;
        }
        assert_eq!(pow_usize(Fr::ZERO, 0), Fr::ONE);
        assert_eq!(pow_usize(Fr::ZERO, 1), Fr::ZERO);
    }

    #[test]
    fn add_scaled_grows_and_accumulates() {
        let mut acc = vec![Fr::ONE, Fr::ONE];
        add_scaled(&mut acc, &[Fr::ONE, Fr::ONE, Fr::ONE], Fr::from_u64(2));
        assert_eq!(acc, vec![Fr::from_u64(3), Fr::from_u64(3), Fr::from_u64(2)]);
        add_scaled(&mut acc, &[Fr::ONE], -Fr::ONE);
        assert_eq!(acc[0], Fr::from_u64(2));
    }
}
