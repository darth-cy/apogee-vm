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

/// The rounds [`prove_packed`] runs on its packed letters before it binds a
/// table: one entry per sixteen of the original's.
const PACKED_ROUNDS: usize = 4;

/// `eq(τ_j, X) = (1 − τ_j)(1 − X) + τ_j·X` at the integer `x`.
fn eq_at_int(tj: Fp2, x: usize) -> Fp2 {
    let xe = fp(x as i64);
    (Fp2::ONE - tj) * (Fp2::ONE - Fp2::from(xe)) + tj * xe
}

/// `Σ_c w_c·h(a_c + X·(b_c − a_c))` at `X = 0, 1, …, degree`, class `c` the
/// line from `bound[c mod k]` to `bound[c / k]`, `k = |bound|`.
fn class_sums(
    w: &[Fp2],
    bound: &[Fp2],
    degree: usize,
    h: &(impl Fn(Fp2) -> Fp2 + Sync),
) -> Vec<Fp2> {
    let k = bound.len();
    (0..=degree)
        .map(|x| {
            let xe = Fp2::from(fp(x as i64));
            w.par_iter()
                .enumerate()
                .filter(|(_, &wc)| wc != Fp2::ZERO)
                .map(|(c, &wc)| {
                    let (a, b) = (bound[c % k], bound[c / k]);
                    wc * h(a + xe * (b - a))
                })
                .reduce(|| Fp2::ZERO, |x, y| x + y)
        })
        .collect()
}

/// The table one round binds a table of `bound`'s classes into: class
/// `c = lo + k·hi` takes `bound[lo] + r·(bound[hi] − bound[lo])`.
fn bind_classes(bound: &[Fp2], r: Fp2) -> Vec<Fp2> {
    let k = bound.len();
    (0..k * k)
        .map(|c| bound[c % k] + r * (bound[c / k] - bound[c % k]))
        .collect()
}

/// [`prove`] for `Σ_x eq(τ, x)·h(s(x))` over a table `s` whose every entry is
/// one of four `letters`, given as its 2-bit letter indices packed eight to a
/// `u16` (entry `8i + t` at bits `2t`) and letter 0 past the end; `letters[0]`
/// and `h(0)` are zero. Returns the rounds, the point and `s` bound there:
/// those [`prove`] returns over `s` itself, dense off.
///
/// The first four rounds bind no table. At round `j < 3` a pair spans
/// `2^(j+1)` entries, one of `4^(2^(j+1))` classes (16, 256, 65536), so the
/// round runs `h` once per class and point, weighed by the class's summed
/// `eq(τ[j+1..], p)`; every class mass is a sum over the octets' masses, one
/// pass over the codes. At round 3 a pair is two octets, each bound by a
/// lookup. Only then is a table built, one entry per sixteen of `s`'s.
pub fn prove_packed(
    t: &mut Transcript,
    mu: usize,
    codes: &[u16],
    tau: &[Fp2],
    letters: [Fp2; 4],
    degree: usize,
    h: impl Fn(Fp2) -> Fp2 + Sync,
) -> (Vec<Round>, Vec<Fp2>, Fp2) {
    assert!(mu >= PACKED_ROUNDS, "a packed table spans sixteen entries");
    assert!(codes.len() <= 1 << (mu - 3), "the codes fit the cube");
    debug_assert_eq!((letters[0], h(Fp2::ZERO)), (Fp2::ZERO, Fp2::ZERO));
    // Octet q's mass, `eq(τ[3..], q)`, by code. A round-0 pair is the octet's
    // `u`-th pair of entries, weighed `eq(τ[1..3], u)·eq(τ[3..], q)`, and a
    // round-1 pair its `v`-th half, `eq(τ[2], v)·eq(τ[3..], q)`.
    let octet = SplitEq::new(&tau[3..]);
    let run = codes.len().div_ceil(rayon::current_num_threads()).max(1);
    let w2 = codes
        .par_chunks(run)
        .enumerate()
        .map(|(i, cs)| {
            let mut acc = vec![Fp2::ZERO; 1 << 16];
            for (k, &c) in cs.iter().enumerate() {
                acc[c as usize] += octet.at(i * run + k);
            }
            acc
        })
        .reduce(
            || vec![Fp2::ZERO; 1 << 16],
            |mut a, b| {
                a.iter_mut().zip(b).for_each(|(x, y)| *x += y);
                a
            },
        );
    let (pair, half) = (eq_table(&tau[1..3]), eq_table(&tau[2..3]));
    let (mut w0, mut w1) = (vec![Fp2::ZERO; 16], vec![Fp2::ZERO; 256]);
    for (c, &m) in w2.iter().enumerate().filter(|(_, &m)| m != Fp2::ZERO) {
        for (u, &e) in pair.iter().enumerate() {
            w0[(c >> (4 * u)) & 0xf] += e * m;
        }
        for (v, &e) in half.iter().enumerate() {
            w1[(c >> (8 * v)) & 0xff] += e * m;
        }
    }
    let mut rounds = Vec::with_capacity(mu);
    let mut point = Vec::with_capacity(mu);
    let mut prefix = Fp2::ONE;
    let mut bound = letters.to_vec();
    let mut absorb = |j: usize, sums: Vec<Fp2>, rounds: &mut Vec<Round>, point: &mut Vec<Fp2>| {
        let g: Vec<Fp2> = sums
            .iter()
            .enumerate()
            .map(|(x, &s)| prefix * eq_at_int(tau[j], x) * s)
            .collect();
        let round: Round = core::iter::once(g[0])
            .chain(g[2..].iter().copied())
            .collect();
        let r = absorb_round(t, &round);
        prefix *= (Fp2::ONE - tau[j]) * (Fp2::ONE - r) + tau[j] * r;
        rounds.push(round);
        point.push(r);
        r
    };
    for (j, w) in [w0, w1, w2].iter().enumerate() {
        let r = absorb(
            j,
            class_sums(w, &bound, degree, &h),
            &mut rounds,
            &mut point,
        );
        bound = bind_classes(&bound, r);
    }
    // Round 3: octets 2p and 2p + 1, each its code's bound value.
    let octet_at = |i: usize| bound[codes.get(i).map_or(0, |&c| c as usize)];
    let pairs = codes.len().div_ceil(2);
    let rest = SplitEq::new(&tau[PACKED_ROUNDS..]);
    let sums = (0..pairs)
        .into_par_iter()
        .fold(
            || vec![Fp2::ZERO; degree + 1],
            |mut acc, p| {
                let (a, b) = (octet_at(2 * p), octet_at(2 * p + 1));
                let (e, d) = (rest.at(p), b - a);
                let mut v = a;
                for slot in acc.iter_mut() {
                    *slot += e * h(v);
                    v += d;
                }
                acc
            },
        )
        .reduce(
            || vec![Fp2::ZERO; degree + 1],
            |mut a, b| {
                a.iter_mut().zip(b).for_each(|(x, y)| *x += y);
                a
            },
        );
    let r = absorb(3, sums, &mut rounds, &mut point);
    let mut tables = [Table::ext(
        0,
        (0..pairs)
            .into_par_iter()
            .map(|p| octet_at(2 * p) + r * (octet_at(2 * p + 1) - octet_at(2 * p)))
            .collect(),
    )];
    let (more, at) = prove(
        t,
        mu - PACKED_ROUNDS,
        &mut tables,
        Some(&tau[PACKED_ROUNDS..]),
        degree,
        false,
        |e, v| prefix * e * h(v[0]),
    );
    rounds.extend(more);
    point.extend(at);
    (rounds, point, tables[0].get(0))
}
