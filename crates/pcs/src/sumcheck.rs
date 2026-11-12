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

/// `eq(τ_j, X) = (1 − τ_j)(1 − X) + τ_j·X` at the integer `x`.
fn eq_at_int(tj: Fp2, x: usize) -> Fp2 {
    let xe = fp(x as i64);
    (Fp2::ONE - tj) * (Fp2::ONE - Fp2::from(xe)) + tj * xe
}

/// Round 0 of [`prove`] for `Σ_x eq(τ, x)·h(s(x))`, one small table `s` from
/// 0 whose every entry is in `alphabet`, and `h(0) = 0`: each pair
/// `(s(2p), s(2p+1))` is one of `|alphabet|²` classes, so the round is
/// `eq(τ₀, X)·Σ_c W_c·h(a_c + X·(b_c − a_c))`, `W_c` the class's summed
/// `eq(τ[1..], p)`, and `h` runs once per class and point rather than once per
/// pair and point. Its evaluations at `0, 1, …, degree`, which [`prove`]
/// takes as `first`; they are the ones its own round 0 would compute.
pub fn first_round(
    s: &[i16],
    tau: &[Fp2],
    alphabet: &[i16],
    degree: usize,
    h: impl Fn(Fp2) -> Fp2,
) -> Vec<Fp2> {
    debug_assert_eq!(h(Fp2::ZERO), Fp2::ZERO, "the pairs past s are skipped");
    let k = alphabet.len();
    let mut class = vec![u8::MAX; *alphabet.iter().max().expect("a letter") as usize + 1];
    for (c, &a) in alphabet.iter().enumerate() {
        class[a as usize] = c as u8;
    }
    let at = |i: usize| match class.get(s.get(i).map_or(0, |&v| v as usize)) {
        Some(&c) if c != u8::MAX => c as usize,
        _ => panic!("a table entry outside the alphabet"),
    };
    // `eq(τ[1..], p) = lo(p mod 2^bits)·hi(p >> bits)`: sum the low factor by
    // class within each run of one high index, then weigh the run by it.
    let rest = SplitEq::new(&tau[1..]);
    let run = 1usize << rest.bits;
    let pairs = s.len().div_ceil(2);
    let mass = (0..pairs.div_ceil(run))
        .into_par_iter()
        .fold(
            || vec![Fp2::ZERO; k * k],
            |mut acc, hi| {
                let mut part = vec![Fp2::ZERO; k * k];
                for p in hi * run..((hi + 1) * run).min(pairs) {
                    part[at(2 * p) * k + at(2 * p + 1)] += rest.lo[p - hi * run];
                }
                for (a, x) in acc.iter_mut().zip(part) {
                    *a += rest.hi[hi] * x;
                }
                acc
            },
        )
        .reduce(
            || vec![Fp2::ZERO; k * k],
            |mut a, b| {
                for (x, y) in a.iter_mut().zip(b) {
                    *x += y;
                }
                a
            },
        );
    (0..=degree)
        .map(|x| {
            let xe = Fp2::from(fp(x as i64));
            let sum = mass.iter().enumerate().fold(Fp2::ZERO, |acc, (c, &w)| {
                let (a, b) = (alphabet[c / k] as i64, alphabet[c % k] as i64);
                acc + w * h(Fp2::from(fp(a)) + xe * fp(b - a))
            });
            eq_at_int(tau[0], x) * sum
        })
        .collect()
}

/// Prove `Σ_{x ∈ {0,1}^μ} f(e(x), tables(x)) = claim`, `e(x) = eq(τ, x)` when
/// `tau` is given and 1 otherwise; `f` applies `e` to whichever terms carry
/// it. With `dense` false, pairs outside every table's window are skipped,
/// which is sound only where `f` vanishes at all-zero tables. `first`, when
/// given, is round 0's evaluations at `0, 1, …, degree`, computed by the
/// caller ([`first_round`]). Returns the rounds and the point; the tables end
/// bound, each value at `get(0)`.
#[allow(clippy::too_many_arguments)]
pub fn prove(
    t: &mut Transcript,
    mu: usize,
    tables: &mut [Table],
    tau: Option<&[Fp2]>,
    degree: usize,
    dense: bool,
    mut first: Option<Vec<Fp2>>,
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
        let tj = tau.map(|tau| tau[j]);
        let g = first.take().unwrap_or_else(|| {
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
            (lo..hi)
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
                            let e = tj.map_or(Fp2::ONE, |tj| prefix * eq_at_int(tj, x) * e_rest);
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
                )
        });
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
