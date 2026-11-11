//! The cyclotomic ring `R_d = F_q[X]/(X^d + 1)` over A64-C5, its balanced
//! gadget digits, the embedding of `E = F_{q^2}` in it, and Hachi's trace
//! packing. `docs/spec/pcs.md` §1.
//!
//! A ring element is its `d` coefficients, lowest first. `q ≡ 5 (mod 8)`, so
//! `X^d + 1` splits into two irreducible factors and every nonzero element of
//! infinity norm below `√q/√2 ≈ 2^31.5` is a unit (paper §3.1).

use alloc::vec;
use alloc::vec::Vec;

use field::{Fp, Fp2, A64_C5};

/// `x` as a field element, for a signed integer of any width the scheme uses.
#[inline]
pub fn fp(x: i64) -> Fp {
    if x >= 0 {
        Fp::from_u64(x as u64)
    } else {
        -Fp::from_u64(x.unsigned_abs())
    }
}

/// The centered representative of `x`, in `(−q/2, q/2]`.
#[inline]
pub fn centered(x: Fp) -> i64 {
    let v = x.to_u64();
    if v > A64_C5 / 2 {
        -((A64_C5 - v) as i64)
    } else {
        v as i64
    }
}

/// `a·b` in `R_d`, schoolbook.
pub fn mul(a: &[Fp], b: &[Fp]) -> Vec<Fp> {
    let d = a.len();
    debug_assert_eq!(b.len(), d);
    let mut out = vec![Fp::ZERO; d];
    for (i, &x) in a.iter().enumerate() {
        if x == Fp::ZERO {
            continue;
        }
        for (j, &y) in b.iter().enumerate() {
            let k = i + j;
            if k < d {
                out[k] += x * y;
            } else {
                out[k - d] -= x * y;
            }
        }
    }
    out
}

/// A sparse ring element: the folding challenges of `crate::sample`. Its
/// coefficients sit at `pos` in `R_{d_c}`, of magnitude 1 or 2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sparse {
    pub pos: Vec<u32>,
    pub coef: Vec<i8>,
}

impl Sparse {
    /// `acc += ι(c)·x` in `R_d`, where `ι` places coefficient `k` of `c` at
    /// `k·stride` (paper (38)): the identity for `stride = 1`.
    pub fn mul_acc(&self, stride: usize, x: &[Fp], acc: &mut [Fp]) {
        let d = x.len();
        for (&p, &c) in self.pos.iter().zip(&self.coef) {
            let shift = p as usize * stride;
            let c = fp(c as i64);
            for (j, &y) in x.iter().enumerate() {
                let k = j + shift;
                if k < d {
                    acc[k] += c * y;
                } else {
                    acc[k - d] -= c * y;
                }
            }
        }
    }

    /// `c(β)` for `β ∈ E`, given `β^k` for every position `k`.
    pub fn eval(&self, pows: &[Fp2]) -> Fp2 {
        let mut acc = Fp2::ZERO;
        for (&p, &c) in self.pos.iter().zip(&self.coef) {
            acc += pows[p as usize] * fp(c as i64);
        }
        acc
    }

    /// The `‖·‖_1` mass.
    pub fn l1(&self) -> u64 {
        self.coef.iter().map(|c| c.unsigned_abs() as u64).sum()
    }
}

/// `1, β, …, β^(n−1)`.
pub fn powers(beta: Fp2, n: usize) -> Vec<Fp2> {
    let mut out = Vec::with_capacity(n);
    let mut x = Fp2::ONE;
    for _ in 0..n {
        out.push(x);
        x *= beta;
    }
    out
}

/// `a(β) = Σ_j a_j β^j`, given the powers.
pub fn eval(a: &[Fp], pows: &[Fp2]) -> Fp2 {
    let (mut c0, mut c1) = (Fp::ZERO, Fp::ZERO);
    for (&x, p) in a.iter().zip(pows) {
        c0 += x * p.c0;
        c1 += x * p.c1;
    }
    Fp2 { c0, c1 }
}

// ---------------------------------------------------------------------------
// Balanced digits (paper §3.3)
// ---------------------------------------------------------------------------

/// The number of balanced base-`2^log` digits every lifted residue of `q`
/// needs: `⌈64 / log⌉`, since `2^63 < q < 2^64`.
pub fn full_digits(log: u32) -> usize {
    64usize.div_ceil(log as usize)
}

/// `T_k = (b/2 − 1)(b^k − 1)/(b − 1)`, the largest integer `k` balanced
/// base-`b` digits write.
pub fn digit_top(log: u32, k: usize) -> u128 {
    let b = 1u128 << log;
    let geometric = (0..k).fold(0u128, |acc, _| acc * b + 1);
    (b / 2 - 1) * geometric
}

/// The lift of a residue to the integer its digits write: `x` if
/// `x ≤ min(T_k, ⌊q/2⌋)`, else `x − q` (paper §3.3).
pub fn lift(x: Fp, log: u32, k: usize) -> i128 {
    let top = digit_top(log, k).min((A64_C5 / 2) as u128);
    let v = x.to_u64() as u128;
    if v <= top {
        v as i128
    } else {
        v as i128 - A64_C5 as i128
    }
}

/// The `k` balanced base-`2^log` digits of the integer `x`, lowest first, each
/// in `[−2^(log−1), 2^(log−1))`. Panics if `x` needs more than `k`.
pub fn digits(mut x: i128, log: u32, k: usize, out: &mut [i32]) {
    let b = 1i128 << log;
    for d in out[..k].iter_mut() {
        let r = (x + b / 2).rem_euclid(b) - b / 2;
        *d = r as i32;
        x = (x - r) >> log;
    }
    assert_eq!(x, 0, "a value needs more than {k} base-2^{log} digits");
}

/// `Σ_i 2^(log·i) d_i mod q`.
pub fn recompose(ds: &[i32], log: u32) -> Fp {
    let b = Fp::from_u64(1 << log);
    ds.iter()
        .rev()
        .fold(Fp::ZERO, |acc, &d| acc * b + fp(d as i64))
}

// ---------------------------------------------------------------------------
// E = F_q[x]/(x^2 − 2) inside R_d, and the trace packing (paper §3.1)
// ---------------------------------------------------------------------------

/// `λ·a` in `R_d` for `λ ∈ E`, embedded as `λ.c0 + λ.c1·e_1` with
/// `e_1 = X^(d/4) − X^(3d/4)`, the ring-subfield basis element whose square
/// is 2. Requires `d ≥ 4`.
pub fn embed_mul(lambda: Fp2, a: &[Fp]) -> Vec<Fp> {
    let d = a.len();
    let m = d / 4;
    let mut out: Vec<Fp> = a.iter().map(|&x| lambda.c0 * x).collect();
    if lambda.c1 != Fp::ZERO {
        for (shift, sign) in [(m, Fp::ONE), (3 * m, -Fp::ONE)] {
            let c = lambda.c1 * sign;
            for (j, &x) in a.iter().enumerate() {
                let k = j + shift;
                if k < d {
                    out[k] += c * x;
                } else {
                    out[k - d] -= c * x;
                }
            }
        }
    }
    out
}

/// `λ(β)` for `λ ∈ E` embedded in `R_d`, given `β^(d/4)` and `β^(3d/4)`.
pub fn embed_eval(lambda: Fp2, quarter: Fp2, three_quarters: Fp2) -> Fp2 {
    lambda.c1 * (quarter - three_quarters) + lambda.c0
}

/// The trace-packed coefficients `ψ(f̄)` of `d` base-field values: the `E`
/// values `f̄_u = w_{2u} + x·w_{2u+1}`, `u < d/2`, in Hachi's two banks of
/// `m = d/4` (paper (21), (22) at `k = 2`): coefficients `t`, `t + m`, `t + 2m`
/// and `t + 3m` are `a_{t,0}`, `a_{t,1} + b_{t,1}`, `b_{t,0}` and
/// `−a_{t,1} + b_{t,1}`, where `a_t = f̄_t` and `b_t = f̄_{m+t}`.
pub fn trace_pack(w: &[i64]) -> Vec<i64> {
    let d = w.len();
    let m = d / 4;
    let mut c = vec![0i64; d];
    for t in 0..m {
        let (a0, a1) = (w[2 * t], w[2 * t + 1]);
        let (b0, b1) = (w[2 * (m + t)], w[2 * (m + t) + 1]);
        c[t] = a0;
        c[t + m] = a1 + b1;
        c[t + 2 * m] = b0;
        c[t + 3 * m] = b1 - a1;
    }
    c
}

/// `T(X^ν)` for every `ν < d`, the trace functional's weights at the packed
/// point `χ_u = eq(ρ_pack, u)`, `u < d/2`: `T(Z) = ⟨ψ⁻¹(Z), χ⟩`, which is
/// the paper's `(k/d)·Tr_H(Z·σ₋₁(ψ(χ)))` (97) by its trace identity (10).
pub fn trace_weights(chi: &[Fp2]) -> Vec<Fp2> {
    let m = chi.len() / 2;
    let x = Fp2 {
        c0: Fp::ZERO,
        c1: Fp::ONE,
    };
    let half = Fp::from_u64(2).inverse().expect("2 is a unit");
    let mut out = vec![Fp2::ZERO; 4 * m];
    for t in 0..m {
        let (a, b) = (chi[t], chi[m + t]);
        out[t] = a;
        out[t + m] = x * (a + b) * half;
        out[t + 2 * m] = b;
        out[t + 3 * m] = x * (b - a) * half;
    }
    out
}
