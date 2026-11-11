//! The sumcheck prover every stage of an opening runs: low variable first,
//! each round sent at `0, 2, …, degree` (the verifier recovers 1), tables zero
//! outside a window and small integers until their first binding, and an
//! `eq(τ, ·)` factor computed on the fly from two half-size tables.
//! `docs/spec/pcs.md` §7.

use field::Fp2;
use pcs_verify::proof::Round;
use pcs_verify::ring::fp;
use pcs_verify::verify::absorb_round;
use poly::eq_table;
use rayon::prelude::*;
use transcript::Transcript;

/// A table's entries.
pub enum Vals {
    Small(Vec<i16>),
    Ext(Vec<Fp2>),
}

/// A multilinear table over `{0,1}^μ`: `vals` at `[start, start + len)`, zero
/// elsewhere.
pub struct Table {
    pub start: usize,
    pub vals: Vals,
}

impl Table {
    pub fn small(start: usize, v: Vec<i16>) -> Table {
        Table {
            start,
            vals: Vals::Small(v),
        }
    }

    pub fn ext(start: usize, v: Vec<Fp2>) -> Table {
        Table {
            start,
            vals: Vals::Ext(v),
        }
    }

    fn len(&self) -> usize {
        match &self.vals {
            Vals::Small(v) => v.len(),
            Vals::Ext(v) => v.len(),
        }
    }

    #[inline]
    pub fn get(&self, i: usize) -> Fp2 {
        if i < self.start || i >= self.start + self.len() {
            return Fp2::ZERO;
        }
        match &self.vals {
            Vals::Small(v) => Fp2::from(fp(v[i - self.start] as i64)),
            Vals::Ext(v) => v[i - self.start],
        }
    }

    fn bind(&mut self, r: Fp2) {
        let lo = self.start / 2;
        let hi = (self.start + self.len()).div_ceil(2);
        let out: Vec<Fp2> = (lo..hi)
            .into_par_iter()
            .map(|i| {
                let a = self.get(2 * i);
                a + r * (self.get(2 * i + 1) - a)
            })
            .collect();
        *self = Table::ext(lo, out);
    }
}

/// The widest summand: a range stage over eight child nodes and its norm table.
const MAX_TABLES: usize = 12;

/// `eq(τ, ·)` over the variables a round has not bound, as two half tables.
struct SplitEq {
    lo: Vec<Fp2>,
    hi: Vec<Fp2>,
    bits: usize,
}

impl SplitEq {
    fn new(tau: &[Fp2]) -> SplitEq {
        let bits = tau.len() / 2;
        SplitEq {
            lo: eq_table(&tau[..bits]),
            hi: eq_table(&tau[bits..]),
            bits,
        }
    }

    #[inline]
    fn at(&self, i: usize) -> Fp2 {
        self.lo[i & ((1 << self.bits) - 1)] * self.hi[i >> self.bits]
    }
}

/// Prove `Σ_{x ∈ {0,1}^μ} f(e(x), tables(x)) = claim`, `e(x) = eq(τ, x)` when
/// `tau` is given and 1 otherwise; `f` applies `e` to whichever terms carry
/// it. With `dense` false, pairs outside every table's window are skipped,
/// which is sound only where `f` vanishes at all-zero tables. Returns the
/// rounds and the point; the tables end bound, each value at `get(0)`.
pub fn prove(
    t: &mut Transcript,
    mu: usize,
    tables: &mut [Table],
    tau: Option<&[Fp2]>,
    degree: usize,
    dense: bool,
    f: impl Fn(Fp2, &[Fp2]) -> Fp2 + Sync,
) -> (Vec<Round>, Vec<Fp2>) {
    let n = tables.len();
    assert!(
        n <= MAX_TABLES,
        "a sumcheck reads at most {MAX_TABLES} tables"
    );
    let mut rounds = Vec::with_capacity(mu);
    let mut point = Vec::with_capacity(mu);
    let mut prefix = Fp2::ONE;
    for j in 0..mu {
        let pairs = 1usize << (mu - j - 1);
        let (lo, hi) = if dense {
            (0, pairs)
        } else {
            let lo = tables.iter().map(|tb| tb.start / 2).min().unwrap_or(0);
            let hi = tables
                .iter()
                .map(|tb| (tb.start + tb.len()).div_ceil(2))
                .max()
                .unwrap_or(0)
                .min(pairs);
            (lo.min(hi), hi)
        };
        let rest = tau.map(|tau| SplitEq::new(&tau[j + 1..]));
        let tj = tau.map(|tau| tau[j]);
        let g: Vec<Fp2> = (lo..hi)
            .into_par_iter()
            .fold(
                || vec![Fp2::ZERO; degree + 1],
                |mut acc, p| {
                    let e_rest = rest.as_ref().map_or(Fp2::ONE, |s| s.at(p));
                    let mut v = [Fp2::ZERO; MAX_TABLES];
                    let mut d = [Fp2::ZERO; MAX_TABLES];
                    for (i, tb) in tables.iter().enumerate() {
                        v[i] = tb.get(2 * p);
                        d[i] = tb.get(2 * p + 1) - v[i];
                    }
                    let (v, d) = (&mut v[..n], &d[..n]);
                    for (x, slot) in acc.iter_mut().enumerate() {
                        let e = match tj {
                            Some(tj) => {
                                let xe = fp(x as i64);
                                // eq(τ_j, X) = (1 − τ_j)(1 − X) + τ_j·X.
                                prefix
                                    * ((Fp2::ONE - tj) * (Fp2::ONE - Fp2::from(xe)) + tj * xe)
                                    * e_rest
                            }
                            None => Fp2::ONE,
                        };
                        *slot += f(e, v);
                        for (vi, &di) in v.iter_mut().zip(d) {
                            *vi += di;
                        }
                    }
                    acc
                },
            )
            .reduce(
                || vec![Fp2::ZERO; degree + 1],
                |mut a, b| {
                    for (x, y) in a.iter_mut().zip(b) {
                        *x += y;
                    }
                    a
                },
            );
        let round: Round = core::iter::once(g[0])
            .chain(g[2..].iter().copied())
            .collect();
        let r = absorb_round(t, &round);
        for tb in tables.iter_mut() {
            tb.bind(r);
        }
        if let Some(tj) = tj {
            prefix *= (Fp2::ONE - tj) * (Fp2::ONE - r) + tj * r;
        }
        rounds.push(round);
        point.push(r);
    }
    (rounds, point)
}
