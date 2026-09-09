//! Acceptance 7: every polynomial the protocol builds, rebuilt from its
//! definition and compared against the proof.
//!
//! Nothing here calls into the crate's internals. The transcript schedule is
//! transcribed from `docs/spec/mercury.md` §5 a second time, which recovers
//! every challenge; each of `h`, `q`, `g`, `S`, `D`, `H`, `W` and `W'` is then
//! built the slow, obvious way — schoolbook multiplication, one Horner division
//! per column, `eq` from its product definition — and committed with S07's
//! KZG. A proof whose points match all eight is a proof of the right
//! polynomials, because two polynomials of degree `< n` collide under `kzg_commit`
//! with probability `n/|Fr|`.
//!
//! The routes really are different: the crate computes `S` through a size-`2b`
//! FFT and the fold through one interleaved pass over rows, and this file does
//! neither.

mod common;

use constants::transcript_tags as tags;
use field::Fr;
use pcs::{append_g1, append_g1_list, commit, open};
use poly::{MultilinearPoly, PolyBacking};
use srs::kzg::kzg_commit;
use srs::Srs;
use test_support::Rng;
use transcript::Transcript;

// ---------------------------------------------------------------------------
// Naive univariate arithmetic, written from the definitions
// ---------------------------------------------------------------------------

fn eval(c: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::ZERO;
    let mut power = Fr::ONE;
    for a in c {
        acc += *a * power;
        power *= x;
    }
    acc
}

fn mul(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::ZERO; a.len() + b.len() - 1];
    for (i, x) in a.iter().enumerate() {
        for (j, y) in b.iter().enumerate() {
            out[i + j] += *x * *y;
        }
    }
    out
}

fn add(a: &[Fr], b: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::ZERO; a.len().max(b.len())];
    for (i, x) in a.iter().enumerate() {
        out[i] += *x;
    }
    for (i, y) in b.iter().enumerate() {
        out[i] += *y;
    }
    out
}

fn scale(a: &[Fr], c: Fr) -> Vec<Fr> {
    a.iter().map(|x| *x * c).collect()
}

fn rev(a: &[Fr]) -> Vec<Fr> {
    a.iter().rev().copied().collect()
}

/// `(quotient, remainder)` of `c(X) / (X - r)`, by long division from the top.
fn divide(c: &[Fr], r: Fr) -> (Vec<Fr>, Fr) {
    let mut work = c.to_vec();
    let mut q = vec![Fr::ZERO; c.len().saturating_sub(1)];
    for i in (1..c.len()).rev() {
        let lead = work[i];
        q[i - 1] = lead;
        work[i] = Fr::ZERO;
        work[i - 1] += lead * r;
    }
    (q, work.first().copied().unwrap_or(Fr::ZERO))
}

fn vanishing(roots: &[Fr]) -> Vec<Fr> {
    let mut out = vec![Fr::ONE];
    for r in roots {
        out = mul(&out, &[-*r, Fr::ONE]);
    }
    out
}

/// Lagrange, written out.
fn interpolate(points: &[(Fr, Fr)]) -> Vec<Fr> {
    let mut out = vec![Fr::ZERO; points.len()];
    for (i, (xi, yi)) in points.iter().enumerate() {
        let mut num = vec![Fr::ONE];
        let mut den = Fr::ONE;
        for (j, (xj, _)) in points.iter().enumerate() {
            if i != j {
                num = mul(&num, &[-*xj, Fr::ONE]);
                den *= *xi - *xj;
            }
        }
        out = add(&out, &scale(&num, *yi * den.inverse().expect("distinct")));
    }
    out
}

/// `eq(i, u)` straight from `prod_k (u_k i_k + (1 - u_k)(1 - i_k))`, with `i`
/// read little-endian. Deliberately not `poly::eq_table`.
fn eq_at(i: usize, u: &[Fr]) -> Fr {
    let mut acc = Fr::ONE;
    for (k, uk) in u.iter().enumerate() {
        let bit = Fr::from_u64(((i >> k) & 1) as u64);
        acc *= *uk * bit + (Fr::ONE - *uk) * (Fr::ONE - bit);
    }
    acc
}

/// `P_u(X) = sum_i eq(i, u) X^i`, as a coefficient vector.
fn tensor(u: &[Fr]) -> Vec<Fr> {
    (0..1usize << u.len()).map(|i| eq_at(i, u)).collect()
}

// ---------------------------------------------------------------------------
// The schedule, transcribed a second time
// ---------------------------------------------------------------------------

/// Every challenge the schedule draws, recovered by replaying it.
struct Challenges {
    alpha: Fr,
    gamma: Fr,
    z: Fr,
    delta: Fr,
    z_prime: Fr,
    /// One raw duplex sample past the end of the schedule: a function of the
    /// terminal sponge state, and so of every step, including the ones this
    /// file does not read back.
    probe: Fr,
}

fn replay(cm: &pcs::MercuryCommitment, u: &[Fr], v: Fr, p: &pcs::MercuryProof) -> Challenges {
    let mut tr = Transcript::new();
    tr.append_scalar(tags::MERCURY_INSTANCE, Fr::from_u64(1u64 << u.len()));
    append_g1(&mut tr, tags::COMMITMENT, &cm.0);
    let mut claim = u.to_vec();
    claim.push(v);
    tr.append_scalars(tags::EVALUATION_CLAIM, &claim);
    append_g1(&mut tr, tags::PCS_OPENING, &p.h);
    let alpha = tr.challenge_scalar(tags::MERCURY_ALPHA);
    append_g1_list(&mut tr, tags::PCS_OPENING, &[p.q, p.g]);
    let gamma = tr.challenge_scalar(tags::MERCURY_GAMMA);
    append_g1_list(&mut tr, tags::PCS_OPENING, &[p.s, p.d]);
    let z = loop {
        let z = tr.challenge_scalar(tags::MERCURY_Z);
        if z != Fr::ZERO {
            break z;
        }
    };
    tr.append_scalars(
        tags::PCS_OPENING,
        &[p.g_z, p.g_inv_z, p.h_z, p.h_inv_z, p.s_z, p.s_inv_z],
    );
    append_g1(&mut tr, tags::PCS_OPENING, &p.pi_z);
    let delta = tr.challenge_scalar(tags::BDFG_BATCH);
    append_g1(&mut tr, tags::PCS_OPENING, &p.w);
    let z_prime = tr.challenge_scalar(tags::BDFG_POINT);
    append_g1(&mut tr, tags::PCS_OPENING, &p.w_prime);
    let _rho = tr.challenge_scalar(tags::PAIRING_MERGE);
    Challenges {
        alpha,
        gamma,
        z,
        delta,
        z_prime,
        probe: tr.sample(),
    }
}

// ---------------------------------------------------------------------------
// The reconstruction
// ---------------------------------------------------------------------------

/// Rebuild every polynomial of a Mercury opening from its definition and check
/// the proof against it, at `n = 2^(2t)`.
fn reconstruct(t: usize, seed: u64) {
    let num_vars = 2 * t;
    let b = 1usize << t;
    let n = 1usize << num_vars;

    let srs: Srs = common::toy_srs(num_vars as u32);
    let mut rng = Rng::new(seed);
    let values: Vec<Fr> = (0..n).map(|_| common::next_fr(&mut rng)).collect();
    let f = MultilinearPoly::new(PolyBacking::Fr(values.clone()));
    let u = common::random_point(&mut rng, num_vars);
    let (u1, u2) = (&u[..t], &u[t..]);

    let cm = commit(&srs, &f).expect("commit");
    let mut tr = Transcript::new();
    let (v, proof) = open(&srs, &f, &cm, &u, &mut tr).expect("open");
    let c = replay(&cm, &u, v, &proof);

    let com = |p: &[Fr]| kzg_commit(&srs, p).expect("the SRS covers every polynomial here");

    // -- h, the restriction ------------------------------------------------
    let h: Vec<Fr> = (0..b)
        .map(|j| {
            (0..b)
                .map(|i| eq_at(i, u1) * values[i + j * b])
                .fold(Fr::ZERO, |a, x| a + x)
        })
        .collect();
    assert_eq!(com(&h), proof.h, "t={t}: h");

    // hhat(u2) = fhat(u) = v, and h's coefficients are fhat(u1, j).
    assert_eq!(v, f.evaluate(&u));
    assert_eq!(
        (0..b)
            .map(|j| eq_at(j, u2) * h[j])
            .fold(Fr::ZERO, |a, x| a + x),
        v,
        "t={t}: hhat(u2) = v"
    );
    for (j, hj) in h.iter().enumerate() {
        let mut point = u1.to_vec();
        point.extend((0..t).map(|k| Fr::from_u64(((j >> k) & 1) as u64)));
        assert_eq!(*hj, f.evaluate(&point), "t={t}: h_j = fhat(u1, j)");
    }

    // -- g and q, the fold -------------------------------------------------
    let mut g = vec![Fr::ZERO; b];
    let mut q = vec![Fr::ZERO; n - b];
    for i in 0..b {
        let column: Vec<Fr> = (0..b).map(|j| values[i + j * b]).collect();
        let (qi, remainder) = divide(&column, c.alpha);
        assert_eq!(remainder, eval(&column, c.alpha), "t={t}: g_i = f_i(alpha)");
        g[i] = remainder;
        for (j, coefficient) in qi.iter().enumerate() {
            q[i + j * b] = *coefficient;
        }
    }
    assert_eq!(com(&g), proof.g, "t={t}: g");
    assert_eq!(com(&q), proof.q, "t={t}: q");

    // f(X) = (X^b - alpha) q(X) + g(X), as polynomials.
    let mut x_pow_b_minus_alpha = vec![Fr::ZERO; b + 1];
    x_pow_b_minus_alpha[0] = -c.alpha;
    x_pow_b_minus_alpha[b] = Fr::ONE;
    let rebuilt = add(&mul(&x_pow_b_minus_alpha, &q), &g);
    assert_eq!(
        rebuilt.len(),
        n,
        "t={t}: the fold has exactly n coefficients"
    );
    assert_eq!(rebuilt, values, "t={t}: f = (X^b - alpha) q + g");

    // ghat(u1) = h(alpha).
    let h_alpha = eval(&h, c.alpha);
    assert_eq!(
        (0..b)
            .map(|i| eq_at(i, u1) * g[i])
            .fold(Fr::ZERO, |a, x| a + x),
        h_alpha,
        "t={t}: ghat(u1) = h(alpha)"
    );

    // -- S and D -----------------------------------------------------------
    let p1 = tensor(u1);
    let p2 = tensor(u2);
    let big = add(
        &add(&mul(&g, &rev(&p1)), &mul(&rev(&g), &p1)),
        &scale(&add(&mul(&h, &rev(&p2)), &mul(&rev(&h), &p2)), c.gamma),
    );
    assert_eq!(big.len(), 2 * b - 1);
    assert_eq!(
        big[b - 1],
        (h_alpha + c.gamma * v) + (h_alpha + c.gamma * v),
        "t={t}: the constant coefficient of the symmetrised identity"
    );
    for k in 0..2 * b - 1 {
        assert_eq!(
            big[k],
            big[2 * b - 2 - k],
            "t={t}: the identity is symmetric"
        );
    }
    let s: Vec<Fr> = big[b..].to_vec();
    assert_eq!(s.len(), b - 1);
    assert_eq!(com(&s), proof.s, "t={t}: S");

    let d = rev(&g);
    assert_eq!(com(&d), proof.d, "t={t}: D");

    // The two identities S and D exist to prove, at points of their own.
    for round in 0..4u64 {
        let w = common::next_fr(&mut rng) + Fr::from_u64(round);
        let wi = w.inverse().expect("a random point is nonzero");
        let lhs = eval(&g, w) * eval(&p1, wi)
            + eval(&g, wi) * eval(&p1, w)
            + c.gamma * (eval(&h, w) * eval(&p2, wi) + eval(&h, wi) * eval(&p2, w));
        let rhs =
            (h_alpha + c.gamma * v) + (h_alpha + c.gamma * v) + w * eval(&s, w) + wi * eval(&s, wi);
        assert_eq!(lhs, rhs, "t={t}: the symmetrised inner-product identity");
        assert_eq!(
            eval(&d, w),
            pow(w, b - 1) * eval(&g, wi),
            "t={t}: D(X) = X^(b-1) g(1/X)"
        );
        // And the verifier's O(t) product formula agrees with the coefficients.
        assert_eq!(eval(&p1, w), product_formula(u1, w));
        assert_eq!(eval(&p2, w), product_formula(u2, w));
    }

    // -- the six values and pi_z -------------------------------------------
    let z_inv = c.z.inverse().expect("z is nonzero");
    assert_eq!(proof.g_z, eval(&g, c.z), "t={t}: g_z");
    assert_eq!(proof.g_inv_z, eval(&g, z_inv), "t={t}: g_1/z");
    assert_eq!(proof.h_z, eval(&h, c.z), "t={t}: h_z");
    assert_eq!(proof.h_inv_z, eval(&h, z_inv), "t={t}: h_1/z");
    assert_eq!(proof.s_z, eval(&s, c.z), "t={t}: s_z");
    assert_eq!(proof.s_inv_z, eval(&s, z_inv), "t={t}: s_1/z");

    let z_pow_b = pow(c.z, b);
    let numerator = add(
        &add(&values, &scale(&q, -(z_pow_b - c.alpha))),
        &[-proof.g_z],
    );
    let (big_h, remainder) = divide(&numerator, c.z);
    assert_eq!(
        remainder,
        Fr::ZERO,
        "t={t}: the fold numerator vanishes at z"
    );
    assert_eq!(com(&big_h), proof.pi_z, "t={t}: pi_z");

    // -- the BDFG20 batch ---------------------------------------------------
    let d_z = pow(c.z, b - 1) * proof.g_inv_z;
    let two_inv = Fr::from_u64(2).inverse().expect("2 is invertible");
    let derived_h_alpha = (proof.g_z * product_formula(u1, z_inv)
        + proof.g_inv_z * product_formula(u1, c.z)
        + c.gamma
            * (proof.h_z * product_formula(u2, z_inv) + proof.h_inv_z * product_formula(u2, c.z)
                - v
                - v)
        - c.z * proof.s_z
        - z_inv * proof.s_inv_z)
        * two_inv;
    assert_eq!(
        derived_h_alpha, h_alpha,
        "t={t}: the verifier re-derives h(alpha)"
    );
    assert_eq!(d_z, eval(&d, c.z), "t={t}: the verifier re-derives D(z)");

    let t_set = [c.z, z_inv, c.alpha];
    let items: [(Vec<Fr>, Vec<Fr>, Vec<Fr>); 4] = [
        (
            g.clone(),
            vanishing(&[c.alpha]),
            interpolate(&[(c.z, proof.g_z), (z_inv, proof.g_inv_z)]),
        ),
        (
            h.clone(),
            vec![Fr::ONE],
            interpolate(&[(c.z, proof.h_z), (z_inv, proof.h_inv_z), (c.alpha, h_alpha)]),
        ),
        (
            s.clone(),
            vanishing(&[c.alpha]),
            interpolate(&[(c.z, proof.s_z), (z_inv, proof.s_inv_z)]),
        ),
        (d.clone(), vanishing(&[z_inv, c.alpha]), vec![d_z]),
    ];

    let mut batched = vec![Fr::ZERO];
    for (i, (poly, complement, r)) in items.iter().enumerate() {
        let shifted = add(poly, &scale(r, -Fr::ONE));
        batched = add(
            &batched,
            &scale(&mul(complement, &shifted), pow(c.delta, i)),
        );
    }
    let mut w_poly = batched;
    for root in t_set {
        let (quotient, remainder) = divide(&w_poly, root);
        assert_eq!(remainder, Fr::ZERO, "t={t}: F is divisible by Z_T");
        w_poly = quotient;
    }
    assert_eq!(com(&w_poly), proof.w, "t={t}: W");

    let z_t = eval(&vanishing(&t_set), c.z_prime);
    let mut l = scale(&w_poly, -z_t);
    for (i, (poly, complement, r)) in items.iter().enumerate() {
        let coefficient = pow(c.delta, i) * eval(complement, c.z_prime);
        l = add(&l, &scale(poly, coefficient));
        l = add(&l, &[-(coefficient * eval(r, c.z_prime))]);
    }
    let (w_prime_poly, remainder) = divide(&l, c.z_prime);
    assert_eq!(remainder, Fr::ZERO, "t={t}: L vanishes at z'");
    assert_eq!(com(&w_prime_poly), proof.w_prime, "t={t}: W'");

    // The replayed schedule is the same schedule `open` ran: the transcript it
    // left behind and the one this file rebuilt yield the same next sample.
    // That is what makes every challenge above the real one, `rho` included —
    // `rho` itself is used only by the verifier's merge, which
    // `tests/structure.rs` pins at source level because no proof can show it.
    assert_eq!(
        tr.sample(),
        c.probe,
        "t={t}: the replayed schedule must end where open's did"
    );
}

fn pow(x: Fr, e: usize) -> Fr {
    let mut acc = Fr::ONE;
    for _ in 0..e {
        acc *= x;
    }
    acc
}

/// The verifier's `O(t)` route to `P_u(x)`.
fn product_formula(u: &[Fr], x: Fr) -> Fr {
    let mut acc = Fr::ONE;
    let mut power = x;
    for uk in u {
        acc *= *uk * power + (Fr::ONE - *uk);
        power = power.square();
    }
    acc
}

/// Acceptance 7's differential oracle: at `t = 1` the whole protocol is a naive
/// reimplementation away, so every identity is checked against one.
#[test]
fn the_whole_protocol_reconstructs_at_t_one() {
    for seed in 0..4 {
        reconstruct(1, 0x5008_0500 + seed);
    }
}

/// The same reconstruction at every small `t` the stage names.
#[test]
fn the_whole_protocol_reconstructs_at_small_t() {
    for t in [2usize, 3] {
        for seed in 0..2 {
            reconstruct(t, 0x5008_0510 + (t as u64) * 16 + seed);
        }
    }
}
