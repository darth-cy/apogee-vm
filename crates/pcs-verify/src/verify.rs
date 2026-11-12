//! The opening verifier, and the pieces of the transcript program both sides
//! run. `docs/spec/pcs.md` §3, §7.

use alloc::vec;
use alloc::vec::Vec;

use constants::transcript_tags::{PCS_CHALLENGE, PCS_DIGEST, PCS_MESSAGE};
use field::{Fp, Fp2};
use poly::{eq_eval, eq_table};
use transcript::Transcript;

use crate::params::{Level, Method, Schedule, Terminal, D_C, D_F2, FAMILY_64};
use crate::proof::{Commitment, Fold, Proof, Round, Tensor};
use crate::relation::{
    norm_binding, relation, view, Claim, Layout, Opening, Pat, Patterns, Public, CHUNK,
};
use crate::ring::{embed_mul, fp, mul, trace_weights, Sparse};
use crate::sample::fold_challenges;

/// Why an opening was refused: the check that failed.
pub type Error = &'static str;

fn check(ok: bool, why: Error) -> Result<(), Error> {
    if ok {
        Ok(())
    } else {
        Err(why)
    }
}

// ---------------------------------------------------------------------------
// Sumcheck rounds
// ---------------------------------------------------------------------------

/// `g(r)` for the polynomial through `(0, g₀), (1, g₁), …, (n, gₙ)`.
pub fn interpolate(values: &[Fp2], r: Fp2) -> Fp2 {
    let n = values.len();
    let mut acc = Fp2::ZERO;
    for (i, &v) in values.iter().enumerate() {
        let (mut num, mut den) = (Fp2::ONE, Fp::ONE);
        for j in 0..n {
            if j != i {
                num *= r - Fp::from_u64(j as u64);
                den *= fp(i as i64 - j as i64);
            }
        }
        acc += v * num * den.inverse().expect("distinct nodes");
    }
    acc
}

/// One round's full evaluations from its message and the running claim:
/// `g(1) = claim − g(0)`.
pub fn round_values(round: &Round, claim: Fp2) -> Vec<Fp2> {
    let mut v = Vec::with_capacity(round.len() + 1);
    v.push(round[0]);
    v.push(claim - round[0]);
    v.extend_from_slice(&round[1..]);
    v
}

/// Absorb a round message and draw its challenge.
pub fn absorb_round(t: &mut Transcript, round: &Round) -> Fp2 {
    t.append_ext(PCS_MESSAGE, round);
    t.challenge(PCS_CHALLENGE)
}

/// Absorb `rounds` of degree `degree`, drawing the point. A round's
/// challenge reads its message alone, so the claims can be replayed after.
fn absorb_rounds(t: &mut Transcript, rounds: &[Round], degree: usize) -> Result<Vec<Fp2>, Error> {
    check(
        rounds.iter().all(|r| r.len() == degree),
        "a sumcheck round has the wrong degree",
    )?;
    Ok(rounds.iter().map(|r| absorb_round(t, r)).collect())
}

/// The final claim of `rounds` from `claim` at `point`.
fn replay(rounds: &[Round], point: &[Fp2], mut claim: Fp2) -> Fp2 {
    for (r, &x) in rounds.iter().zip(point) {
        claim = interpolate(&round_values(r, claim), x);
    }
    claim
}

/// Verify `rounds` of degree `degree` from `claim`: the point and final claim.
fn rounds(
    t: &mut Transcript,
    rounds: &[Round],
    degree: usize,
    claim: Fp2,
) -> Result<(Vec<Fp2>, Fp2), Error> {
    let point = absorb_rounds(t, rounds, degree)?;
    let fin = replay(rounds, &point, claim);
    Ok((point, fin))
}

/// `eq(r, i)` at the integer `i`.
pub fn eq_at(r: &[Fp2], i: usize) -> Fp2 {
    r.iter().enumerate().fold(Fp2::ONE, |acc, (j, &x)| {
        acc * if (i >> j) & 1 == 1 { x } else { Fp2::ONE - x }
    })
}

/// `n` field challenges.
pub fn challenges(t: &mut Transcript, n: usize) -> Vec<Fp2> {
    (0..n).map(|_| t.challenge(PCS_CHALLENGE)).collect()
}

/// `⌈log2 n⌉`.
pub fn log2_ceil(n: usize) -> usize {
    (usize::BITS - (n.max(1) - 1).leading_zeros()) as usize
}

// ---------------------------------------------------------------------------
// The tensor reduction (paper §3.7, §5.2)
// ---------------------------------------------------------------------------

/// `A + B·y` in `E ⊗ E = E[y]/(y² − 2)`, `y = 1 ⊗ x`.
#[derive(Clone, Copy)]
struct Tensor2(Fp2, Fp2);

impl Tensor2 {
    fn mul(self, o: Tensor2) -> Tensor2 {
        let two = Fp::from_u64(2);
        Tensor2(
            self.0 * o.0 + self.1 * o.1 * two,
            self.0 * o.1 + self.1 * o.0,
        )
    }
    fn sub_from_one(self) -> Tensor2 {
        Tensor2(Fp2::ONE - self.0, -self.1)
    }
    fn add(self, o: Tensor2) -> Tensor2 {
        Tensor2(self.0 + o.0, self.1 + o.1)
    }
}

/// `A_η(ρ)`: from `e = Π_j eq(φ₀(r_j), φ₁(ρ_j)) = Σ_u β_u ⊗ e_u`,
/// `Σ_u η_u e_u` with `η₀ = 1 − η`, `η₁ = η`.
pub fn tensor_factor(r_tail: &[Fp2], rho: &[Fp2], eta: Fp2) -> Fp2 {
    let mut e = Tensor2(Fp2::ONE, Fp2::ZERO);
    for (&a, &b) in r_tail.iter().zip(rho) {
        let x = Tensor2(a, Fp2::ZERO);
        let y = Tensor2(Fp2::from(b.c0), Fp2::from(b.c1));
        e = e.mul(x.mul(y).add(x.sub_from_one().mul(y.sub_from_one())));
    }
    let x = Fp2 {
        c0: Fp::ZERO,
        c1: Fp::ONE,
    };
    let e0 = x * e.1.c0 + e.0.c0;
    let e1 = x * e.1.c1 + e.0.c1;
    (Fp2::ONE - eta) * e0 + eta * e1
}

/// The row partials `row_u = S_{u,0} + x·S_{u,1}`, batched by `η`.
pub fn tensor_claim(s: &[Fp2; 2], eta: Fp2) -> Fp2 {
    let x = Fp2 {
        c0: Fp::ZERO,
        c1: Fp::ONE,
    };
    let row0 = x * s[1].c0 + s[0].c0;
    let row1 = x * s[1].c1 + s[0].c1;
    (Fp2::ONE - eta) * row0 + eta * row1
}

/// Reduce the claim `w̃(r) = v` to `θ·f̄(ρ) = value`: `(ρ, θ, value)`.
fn tensor(
    t: &mut Transcript,
    p: &Tensor,
    r: &[Fp2],
    v: Fp2,
) -> Result<(Vec<Fp2>, Fp2, Fp2), Error> {
    check(
        p.rounds.len() + 1 == r.len(),
        "the tensor reduction has the wrong rounds",
    )?;
    check(
        (Fp2::ONE - r[0]) * p.partials[0] + r[0] * p.partials[1] == v,
        "the column partials do not give the claimed value",
    )?;
    t.append_ext(PCS_MESSAGE, &p.partials);
    let eta = t.challenge(PCS_CHALLENGE);
    let (rho, value) = rounds(t, &p.rounds, 2, tensor_claim(&p.partials, eta))?;
    let theta = tensor_factor(&r[1..], &rho, eta);
    check(theta != Fp2::ZERO, "the tensor factor vanishes")?;
    Ok((rho, theta, value))
}

// ---------------------------------------------------------------------------
// The digit range tree (paper §6.1) and the norm (§6.2)
// ---------------------------------------------------------------------------

/// The range tree's fan-ins, root first, for `b⋆ = 2^log_b`: the leaves are
/// `s − j(j+1)` for `j < b⋆/2`, four to a bottom node.
pub fn tree(log_b: u32) -> Vec<usize> {
    match log_b {
        3 => vec![4],
        4 => vec![2, 4],
        5 => vec![4, 4],
        6 => vec![2, 4, 4],
        _ => panic!("no range tree for b⋆ = 2^{log_b}"),
    }
}

/// Node counts per tree level, root first, leaves last.
pub fn levels(log_b: u32) -> Vec<usize> {
    let mut out = vec![1];
    for f in tree(log_b) {
        out.push(out.last().expect("root") * f);
    }
    out
}

/// The leaves `s − j(j+1)` at `s`.
pub fn leaves(log_b: u32, s: Fp2) -> Vec<Fp2> {
    (0..1u64 << (log_b - 1))
        .map(|j| s - Fp::from_u64(j * (j + 1)))
        .collect()
}

/// `Σ_c λ^c Π_{g ∈ children(c)} child_g`, children in order, `fan` each.
pub fn node_sum(children: &[Fp2], fan: usize, lambda: Fp2) -> Fp2 {
    let mut acc = Fp2::ZERO;
    let mut w = Fp2::ONE;
    for group in children.chunks(fan) {
        acc += w * group.iter().fold(Fp2::ONE, |a, &x| a * x);
        w *= lambda;
    }
    acc
}

/// What the range tree leaves: `r_virt`, `s̃(r_virt)` and on the Euclidean
/// route `z̃_int(r_virt)`.
pub struct RangeOut {
    pub point: Vec<Fp2>,
    pub s: Fp2,
    pub z: Option<Fp2>,
}

fn range(t: &mut Transcript, l: &Level, f: &Fold, tau0: &[Fp2]) -> Result<RangeOut, Error> {
    let fans = tree(l.log_b);
    check(
        f.range.len() == fans.len(),
        "the range tree has the wrong stages",
    )?;
    check(
        f.norm.is_some() == l.s_max.is_some(),
        "the norm claim does not match the route",
    )?;
    let counts = levels(l.log_b);
    let mut point = tau0.to_vec();
    let mut claims = vec![Fp2::ZERO];
    let mut out = None;
    for (i, (st, &fan)) in f.range.iter().zip(&fans).enumerate() {
        let last = i + 1 == fans.len();
        let lambda = if i == 0 {
            Fp2::ONE
        } else {
            t.challenge(PCS_CHALLENGE)
        };
        let mut claim = node_sum(&claims, 1, lambda);
        let mut zeta = Fp2::ZERO;
        if last {
            if let (Some(s_max), Some(norm)) = (l.s_max, f.norm) {
                check(
                    norm.to_u64() as u128 <= s_max,
                    "the response norm exceeds its bound",
                )?;
                t.append_scalar(PCS_MESSAGE, norm);
                zeta = t.challenge(PCS_CHALLENGE);
                claim += zeta * norm;
            }
        }
        // Every stage sums over the witness's cube, `τ₀`'s variables.
        check(
            st.rounds.len() == tau0.len(),
            "a range stage has the wrong rounds",
        )?;
        let degree = (fan + 1).max(2);
        let (next, fin) = rounds(t, &st.rounds, degree, claim)?;
        let want = if last {
            1 + l.s_max.is_some() as usize
        } else {
            counts[i + 1]
        };
        check(
            st.claims.len() == want,
            "a range stage leaves the wrong claims",
        )?;
        t.append_ext(PCS_MESSAGE, &st.claims);
        let children = if last {
            leaves(l.log_b, st.claims[0])
        } else {
            st.claims.clone()
        };
        let mut expect = eq_eval(&point, &next) * node_sum(&children, fan, lambda);
        if last && l.s_max.is_some() {
            expect += zeta * st.claims[1] * st.claims[1];
        }
        check(fin == expect, "a range stage does not close")?;
        if last {
            out = Some(RangeOut {
                point: next.clone(),
                s: st.claims[0],
                z: l.s_max.map(|_| st.claims[1]),
            });
        }
        point = next;
        claims = st.claims.clone();
    }
    out.ok_or("the range tree is empty")
}

// ---------------------------------------------------------------------------
// One fold
// ---------------------------------------------------------------------------

/// A claim entering a fold: its point and value, the input commitment's
/// payloads, and for the root, its groups.
pub struct Incoming<'a> {
    pub point: Vec<Fp2>,
    /// Root: one value per column, group-major, every column `2^point.len()`
    /// entries. Later: the one value of the whole witness.
    pub values: Vec<Fp2>,
    /// Blocks per group: the root's groups, or the witness's one.
    pub group_blocks: Vec<usize>,
    pub payloads: Vec<&'a [Fp]>,
}

/// The packing claims of a fold: per column at the root, one otherwise.
pub fn pack_claims(
    l: &Level,
    inc: &Incoming,
    weights: &[Fp2],
) -> (Vec<Fp2>, Vec<Fp2>, Vec<Fp2>, Vec<Claim>) {
    let log_stride = l.stride().trailing_zeros() as usize;
    let log_dc = l.family.dim.trailing_zeros() as usize;
    let log_m = l.m.trailing_zeros() as usize;
    let r = &inc.point;
    let r_pack = r[..log_stride].to_vec();
    let r_tail = r[log_stride..log_stride + log_dc].to_vec();
    let lo = log_stride + log_dc;
    let r_pos = r[lo..lo + log_m].to_vec();
    let r_blk = r[lo + log_m..].to_vec();
    let columns = inc.values.len();
    let per_column = l.blocks / columns;
    let claims = (0..columns)
        .map(|c| Claim {
            first: c * per_column,
            blocks: per_column,
            r_blk: r_blk.clone(),
            weight: weights[c],
            value: inc.values[c],
        })
        .collect();
    (r_pack, r_tail, r_pos, claims)
}

/// The batching weights: `1` for one claim, else `ζ^c` (paper (71)).
pub fn batch_weights(t: &mut Transcript, n: usize) -> Vec<Fp2> {
    if n == 1 {
        return vec![Fp2::ONE];
    }
    let zeta = t.challenge(PCS_CHALLENGE);
    let mut w = Fp2::ONE;
    (0..n)
        .map(|_| {
            let x = w;
            w *= zeta;
            x
        })
        .collect()
}

/// The successor's payload lengths: per slice of level `next`, or the
/// terminal's inner images.
pub fn successor_shape(s: &Schedule, h: usize, input_len: usize) -> (usize, usize) {
    match s.levels.get(h + 1) {
        Some(n) => {
            let lay = Layout::new(n, &[n.blocks]);
            let each = if n.compress { D_F2 } else { n.n_b * D_C };
            (lay.slices.len(), each)
        }
        None => {
            let tm = &s.terminal;
            let blocks = input_len.div_ceil(tm.d_a * tm.m);
            (blocks - 1, tm.n_a * tm.d_a)
        }
    }
}

/// The fused sumcheck's `κ̃(r₂) = γ·eq(r_virt, r₂) + ζ_bin·eq_Ibin(r_virt, r₂)`.
pub fn kappa_at(lay: &Layout, r_virt: &[Fp2], r2: &[Fp2], gamma: Fp2, zeta: Fp2) -> Fp2 {
    let mut bin = Fp2::ZERO;
    let low = eq_eval(&r_virt[..6], &r2[..6]);
    for s in lay.binary() {
        for c in s.start / CHUNK..(s.start + s.len) / CHUNK {
            bin += eq_at(&r_virt[6..], c) * eq_at(&r2[6..], c);
        }
    }
    gamma * eq_eval(r_virt, r2) + zeta * bin * low
}

/// Verify fold `h`; returns the claim it passes on: `(r₂, w̃(r₂))`.
#[allow(clippy::too_many_arguments)]
fn fold(
    t: &mut Transcript,
    setup: &[Fp],
    s: &Schedule,
    h: usize,
    inc: &Incoming,
    f: &Fold,
) -> Result<(Vec<Fp2>, Fp2), Error> {
    let l = &s.levels[h];
    let lay = Layout::new(l, &inc.group_blocks);
    check(
        inc.payloads.len() == lay.slices.len(),
        "the input commitment has the wrong slices",
    )?;
    let payload_len = if l.compress { D_F2 } else { l.n_b * D_C };
    check(
        inc.payloads.iter().all(|p| p.len() == payload_len),
        "a commitment payload has the wrong length",
    )?;
    check(
        f.tensor.is_some() == (l.method == Method::Trace),
        "the tensor reduction does not match the level",
    )?;
    // 0. The tensor reduction of an evaluation-trace level.
    let traced = match &f.tensor {
        Some(tp) => Some(tensor(t, tp, &inc.point, inc.values[0])?),
        None => None,
    };
    // 1. The opening payload.
    let open_len = if l.compress { D_F2 } else { l.n_d * D_C };
    check(
        f.opening.len() == open_len,
        "the opening payload has the wrong length",
    )?;
    t.append_scalars(PCS_MESSAGE, &f.opening);
    // 2. The scalar weights, then the fold challenges under the nonce.
    let opening = match traced {
        None => {
            let weights = batch_weights(t, inc.values.len());
            let (r_pack, r_tail, r_pos, claims) = pack_claims(l, inc, &weights);
            Opening::Pack {
                r_pack,
                r_tail,
                r_pos,
                claims,
            }
        }
        Some((rho, theta, value)) => {
            let log_m = l.m.trailing_zeros() as usize;
            let lp = (l.d_a / 2).trailing_zeros() as usize;
            Opening::Trace {
                rho_pack: rho[..lp].to_vec(),
                rho_pos: rho[lp..lp + log_m].to_vec(),
                rho_blk: rho[lp + log_m..].to_vec(),
                theta,
                value,
            }
        }
    };
    check(f.nonce < crate::params::NONCES, "the nonce is out of range")?;
    t.append_scalar(PCS_MESSAGE, Fp::from_u64(f.nonce as u64));
    let root = t.challenge(PCS_CHALLENGE);
    let chal = fold_challenges(root, f.nonce, l.family, l.blocks);
    // 3. The successor.
    let (count, each) = successor_shape(s, h, lay.len);
    check(
        f.successor.len() == count,
        "the successor has the wrong slices",
    )?;
    check(
        f.successor.iter().all(|p| p.len() == each),
        "a successor payload has the wrong length",
    )?;
    check(
        f.digest.is_some() == (h + 1 == s.folds()),
        "the successor's digest does not match the level",
    )?;
    for p in &f.successor {
        t.append_scalars(PCS_MESSAGE, p);
    }
    if let Some(d) = &f.digest {
        t.append_scalars(PCS_MESSAGE, d);
    }
    // 4. Ring reduction, range, norm, relation (paper Fig. 6).
    let mu = log2_ceil(lay.len);
    let rows = lay.rows(l);
    let alpha = t.challenge(PCS_CHALLENGE);
    let tau0 = challenges(t, mu);
    let tau1 = challenges(t, log2_ceil(rows));
    let rg = range(t, l, f, &tau0)?;
    let eta_norm = if l.s_max.is_some() {
        t.challenge(PCS_CHALLENGE)
    } else {
        Fp2::ZERO
    };
    let zeta_bin = if l.compress {
        t.challenge(PCS_CHALLENGE)
    } else {
        Fp2::ZERO
    };
    let gamma = t.challenge(PCS_CHALLENGE);
    let mut payloads: Vec<Vec<Fp>> = inc.payloads.iter().map(|p| p.to_vec()).collect();
    payloads.push(f.opening.clone());
    let public = Public {
        level: l,
        layout: &lay,
        setup,
        challenges: &chal,
        alpha,
        opening: &opening,
        payloads: &payloads,
    };
    // The fused sumcheck (paper (125), (93)): its challenges first, then one
    // pass of the relation for both its target and its weight at r₂.
    check(
        f.fused.len() == mu,
        "the fused sumcheck has the wrong rounds",
    )?;
    let r2 = absorb_rounds(t, &f.fused, 3)?;
    t.append_ext(PCS_MESSAGE, &[f.value]);
    let eq_rows = eq_table(&tau1);
    let mut contraction = Contraction::new(&public, rg.z.map(|_| rg.point.as_slice()), &r2);
    let targets = relation(&public, &mut |row, c, p, w| {
        contraction.add(eq_rows[row] * w, c, p)
    });
    if l.s_max.is_some() {
        norm_binding(l, &lay, eta_norm, &rg.point, &mut |c, p, w| {
            contraction.add(w, c, p)
        });
    }
    let target = targets
        .iter()
        .zip(&eq_rows)
        .fold(Fp2::ZERO, |a, (&y, &e)| a + y * e);
    let claim = target + gamma * rg.s + eta_norm * rg.z.unwrap_or(Fp2::ZERO);
    let fin = replay(&f.fused, &r2, claim);
    let kappa = kappa_at(&lay, &rg.point, &r2, gamma, zeta_bin);
    let v = f.value;
    check(
        fin == v * contraction.acc + kappa * v * (v + Fp2::ONE),
        "the fused sumcheck does not close",
    )?;
    Ok((r2, v))
}

/// The verifier's sink: `Σ weight·eq(r₂, chunk·64 + k)·pattern(k)`, as
/// `Σ weight·eq(r₂[6..], chunk)·G(pattern)` with `G(p) = Σ_k p(k)·eq(r₂[..6], k)`.
struct Contraction {
    hi: Vec<Fp2>,
    g: [Fp2; Pat::COUNT],
    acc: Fp2,
}

impl Contraction {
    fn new(p: &Public, r_virt: Option<&[Fp2]>, r2: &[Fp2]) -> Contraction {
        let pats = Patterns::new(p, r_virt);
        let lo = eq_table(&r2[..6]);
        let mut g = [Fp2::ZERO; Pat::COUNT];
        for pat in Pat::ALL {
            g[pat.index()] = (0..CHUNK).fold(Fp2::ZERO, |a, k| a + pats.get(pat, k) * lo[k]);
        }
        Contraction {
            hi: eq_table(&r2[6..]),
            g,
            acc: Fp2::ZERO,
        }
    }

    fn add(&mut self, w: Fp2, chunk: usize, p: Pat) {
        self.acc += w * self.hi[chunk] * self.g[p.index()];
    }
}

// ---------------------------------------------------------------------------
// The terminal (paper §8.2)
// ---------------------------------------------------------------------------

/// The last-block digest: a Poseidon2-A64-C5 sponge over the coefficients
/// (paper (131), `H_dig`).
pub fn digest(coeffs: &[Fp]) -> [Fp; 8] {
    let mut t = Transcript::new();
    t.append_scalars(PCS_DIGEST, coeffs);
    t.digest()
}

/// The Rice parameter of the terminal's response: `⌊log2 σ⌋` for the
/// per-coefficient scale `σ² = S_max / N_z`.
pub fn rice_k(tm: &Terminal) -> u32 {
    let per = (tm.s_max / (tm.m * tm.d_a) as u128).max(1);
    (127 - per.leading_zeros()) / 2
}

/// Decode `n` signed Rice-coded coefficients with parameter `k`: zigzag, `k`
/// low bits, the rest in unary. Refuses an unterminated or overlong code and
/// nonzero padding.
pub fn rice_decode(bytes: &[u8], n: usize, k: u32, max_unary: usize) -> Result<Vec<i64>, Error> {
    let total = bytes.len() * 8;
    let mut at = 0;
    let bit = |i: usize| (bytes[i / 8] >> (i % 8)) & 1;
    let mut out = Vec::with_capacity(n);
    let mut unary = 0;
    for _ in 0..n {
        let mut q = 0u64;
        loop {
            check(at < total, "the response code ends early")?;
            let b = bit(at);
            at += 1;
            if b == 0 {
                break;
            }
            q += 1;
            unary += 1;
            check(unary <= max_unary, "the response code is too long")?;
        }
        let mut r = 0u64;
        for i in 0..k {
            check(at < total, "the response code ends early")?;
            r |= (bit(at) as u64) << i;
            at += 1;
        }
        let zz = (q << k) | r;
        out.push(((zz >> 1) as i64) ^ -((zz & 1) as i64));
    }
    check(
        at.div_ceil(8) == bytes.len(),
        "the response code has trailing bytes",
    )?;
    check(
        (at..total).all(|i| bit(i) == 0),
        "the response code has nonzero padding",
    )?;
    Ok(out)
}

/// The inverse of `c` in `R_d`, by Gaussian elimination on its negacyclic
/// matrix. `None` if `c` is not a unit.
pub fn inverse(c: &[Fp]) -> Option<Vec<Fp>> {
    let d = c.len();
    // Column j of the matrix is X^j·c; solve M·x = e₀.
    let mut m: Vec<Vec<Fp>> = (0..d)
        .map(|i| {
            let mut row: Vec<Fp> = (0..d)
                .map(|j| if i >= j { c[i - j] } else { -c[d + i - j] })
                .collect();
            row.push(if i == 0 { Fp::ONE } else { Fp::ZERO });
            row
        })
        .collect();
    for col in 0..d {
        let piv = (col..d).find(|&r| m[r][col] != Fp::ZERO)?;
        m.swap(col, piv);
        let inv = m[col][col].inverse()?;
        for x in m[col].iter_mut() {
            *x *= inv;
        }
        let pivot = m[col].clone();
        for (r, row) in m.iter_mut().enumerate() {
            if r != col && row[col] != Fp::ZERO {
                let f = row[col];
                for (x, &p) in row.iter_mut().zip(&pivot) {
                    *x -= f * p;
                }
            }
        }
    }
    Some(m.into_iter().map(|row| row[d]).collect())
}

/// `Σ_λ c_λ·x_λ` over `R_64` elements.
fn fold_sum(chal: &[Sparse], xs: &[&[Fp]]) -> Vec<Fp> {
    let mut acc = vec![Fp::ZERO; xs.first().map_or(0, |x| x.len())];
    for (c, x) in chal.iter().zip(xs) {
        c.mul_acc(1, x, &mut acc);
    }
    acc
}

#[allow(clippy::too_many_arguments)]
fn terminal(
    t: &mut Transcript,
    setup: &[Fp],
    tm: &Terminal,
    point: &[Fp2],
    value: Fp2,
    len: usize,
    images: &[Vec<Fp>],
    image_digest: &[Fp; 8],
    p: &crate::proof::Terminal,
) -> Result<(), Error> {
    let d = tm.d_a;
    let blocks = len.div_ceil(d * tm.m);
    let (rho, theta, fin) = tensor(t, &p.tensor, point, value)?;
    check(
        p.partials.len() + 1 == blocks,
        "the terminal has the wrong partials",
    )?;
    check(
        p.partials.iter().all(|e| e.len() == d),
        "a terminal partial has the wrong length",
    )?;
    for e in &p.partials {
        t.append_scalars(PCS_MESSAGE, e);
    }
    t.append_scalars(PCS_MESSAGE, &p.digest);
    check(p.nonce < crate::params::NONCES, "the nonce is out of range")?;
    t.append_scalar(PCS_MESSAGE, Fp::from_u64(p.nonce as u64));
    let root = t.challenge(PCS_CHALLENGE);
    let chal = fold_challenges(root, p.nonce, FAMILY_64, blocks);
    // The response, and its Euclidean bound (paper Lemma 10.34, terminal).
    let n = tm.m * d;
    let k = rice_k(tm);
    let max_unary = ((2 * isqrt(n as u128 * tm.s_max)) >> k) as usize + n;
    let z = rice_decode(&p.response, n, k, max_unary)?;
    let norm: u128 = z.iter().map(|&x| (x as i128 * x as i128) as u128).sum();
    check(norm <= tm.s_max, "the terminal response exceeds its bound")?;
    let zf: Vec<Fp> = z.iter().map(|&x| fp(x)).collect();
    t.append_scalars(PCS_MESSAGE, &zf);
    let zs: Vec<&[Fp]> = zf.chunks(d).collect();
    let last = &chal[blocks - 1];
    let mut dense = vec![Fp::ZERO; d];
    for (&p, &c) in last.pos.iter().zip(&last.coef) {
        dense[p as usize] = fp(c as i64);
    }
    let inv = inverse(&dense).ok_or("the last challenge is not a unit")?;
    // (128) and (131): the last inner image, per A row.
    let mut last_image = Vec::with_capacity(tm.n_a * d);
    for a in 0..tm.n_a {
        let mut az = vec![Fp::ZERO; d];
        for (x, zx) in zs.iter().enumerate() {
            for (o, v) in az.iter_mut().zip(mul(view(setup, tm.m, d, a, x), zx)) {
                *o += v;
            }
        }
        let rows: Vec<&[Fp]> = images.iter().map(|i| &i[a * d..(a + 1) * d]).collect();
        let known = fold_sum(&chal[..blocks - 1], &rows);
        let rest: Vec<Fp> = az.iter().zip(&known).map(|(&x, &y)| x - y).collect();
        let solved = mul(&inv, &rest);
        check(
            mul(&dense, &solved) == rest,
            "the last inner image does not solve",
        )?;
        last_image.extend(solved);
    }
    check(
        digest(&last_image) == *image_digest,
        "the last inner image does not match its digest",
    )?;
    // (129) and (131): the last partial.
    let lp = (d / 2).trailing_zeros() as usize;
    let log_m = tm.m.trailing_zeros() as usize;
    let eq_pos = eq_table(&rho[lp..lp + log_m]);
    let mut az = vec![Fp::ZERO; d];
    for (x, zx) in zs.iter().enumerate() {
        for (o, v) in az.iter_mut().zip(embed_mul(eq_pos[x], zx)) {
            *o += v;
        }
    }
    let parts: Vec<&[Fp]> = p.partials.iter().map(|e| e.as_slice()).collect();
    let known = fold_sum(&chal[..blocks - 1], &parts);
    let rest: Vec<Fp> = az.iter().zip(&known).map(|(&x, &y)| x - y).collect();
    let last_partial = mul(&inv, &rest);
    check(
        mul(&dense, &last_partial) == rest,
        "the last partial does not solve",
    )?;
    check(
        digest(&last_partial) == p.digest,
        "the last partial does not match its digest",
    )?;
    // (130): θ·Σ_λ eq(ρ_blk, λ)·T(e_λ) = the tensor reduction's value.
    let weights = trace_weights(&eq_table(&rho[..lp]));
    let eq_blk = eq_table(&rho[lp + log_m..]);
    let mut sum = Fp2::ZERO;
    for (lam, e) in p
        .partials
        .iter()
        .map(|e| e.as_slice())
        .chain([last_partial.as_slice()])
        .enumerate()
    {
        let te = e
            .iter()
            .zip(&weights)
            .fold(Fp2::ZERO, |a, (&c, &w)| a + w * c);
        sum += eq_blk[lam] * te;
    }
    check(theta * sum == fin, "the terminal evaluation does not match")?;
    Ok(())
}

/// `⌊√n⌋`.
pub fn isqrt(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x = 1u128 << (128 - n.leading_zeros()).div_ceil(2);
    loop {
        let y = (x + n / x) / 2;
        if y >= x {
            return x;
        }
        x = y;
    }
}

// ---------------------------------------------------------------------------
// The opening
// ---------------------------------------------------------------------------

/// Verify that the columns the `groups` commit — each a commitment and its
/// column count, all of `2^point.len()` entries — take `values` at `point`,
/// group-major. `t` is the caller's live transcript, which every commitment
/// and claim has already been absorbed into.
pub fn verify(
    t: &mut Transcript,
    setup: &[Fp],
    groups: &[(&Commitment, usize)],
    point: &[Fp2],
    values: &[Fp2],
    proof: &Proof,
) -> Result<(), Error> {
    let columns: Vec<usize> = groups.iter().map(|g| g.1).collect();
    check(
        values.len() == columns.iter().sum::<usize>(),
        "one value per committed column",
    )?;
    check(
        columns.iter().all(|&c| c > 0) && point.len() >= 12,
        "an opening's shape is out of range",
    )?;
    let s = Schedule::new(point.len() as u32, &columns);
    check(
        proof.folds.len() == s.folds(),
        "the proof has the wrong folds",
    )?;
    check(
        setup.len() >= setup_need(&s),
        "the setup is too short for this opening",
    )?;
    let per_column = (1usize << point.len()) / s.levels[0].block_len();
    let mut inc = Incoming {
        point: point.to_vec(),
        values: values.to_vec(),
        group_blocks: groups.iter().map(|g| g.1 * per_column).collect(),
        payloads: groups
            .iter()
            .flat_map(|g| g.0 .0.iter().map(|p| p.as_slice()))
            .collect(),
    };
    let mut len = 0;
    for (h, f) in proof.folds.iter().enumerate() {
        let (r2, v) = fold(t, setup, &s, h, &inc, f)?;
        len = Layout::new(&s.levels[h], &inc.group_blocks).len;
        let next_blocks = s.levels.get(h + 1).map_or(0, |n| n.blocks);
        inc = Incoming {
            point: r2,
            values: vec![v],
            group_blocks: vec![next_blocks],
            payloads: f.successor.iter().map(|p| p.as_slice()).collect(),
        };
    }
    let last = proof
        .folds
        .last()
        .ok_or("an opening has at least one fold")?;
    let digest = last
        .digest
        .as_ref()
        .ok_or("the final fold sends a digest")?;
    terminal(
        t,
        setup,
        &s.terminal,
        &inc.point,
        inc.values[0],
        len,
        &last.successor,
        digest,
        &proof.terminal,
    )
}

/// The setup prefix every view of a schedule reads.
pub fn setup_need(s: &Schedule) -> usize {
    let levels = s
        .levels
        .iter()
        .map(crate::relation::setup_len)
        .max()
        .unwrap_or(0);
    levels.max(s.terminal.n_a * s.terminal.m * s.terminal.d_a)
}
