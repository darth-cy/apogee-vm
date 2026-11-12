//! The opening prover: every fold, then the terminal, message for message
//! what `pcs_verify::verify` replays. `docs/spec/pcs.md` §7.

use constants::transcript_tags::{PCS_CHALLENGE, PCS_MESSAGE};
use field::{Fp, Fp2};
use pcs_verify::params::{
    Level, Method, Schedule, Terminal as TerminalParams, D_C, D_F1, D_F2, NONCES,
};
use pcs_verify::proof::{Fold, Proof, Stage, Tensor, Terminal};
use pcs_verify::relation::{
    norm_binding, open_width, relation, view, Layout, Opening, Patterns, Public, CHUNK,
};
use pcs_verify::ring::{digit_top, digits, embed_mul, fp, full_digits, lift, Sparse};
use pcs_verify::sample::fold_challenges;
use pcs_verify::verify::{
    batch_weights, challenges, digest, eq_at, leaves, levels, log2_ceil, node_sum, pack_claims,
    rice_k, successor_shape, tree, Incoming,
};
use poly::eq_table;
use rayon::prelude::*;
use transcript::Transcript;

use crate::commit::{
    commit, compress, full_field_digits, image_digits, inner_images, outer_product, Digits, Opener,
    Source,
};
use crate::ntt::Crt;
use crate::sumcheck::{prove as sumcheck, Table};

/// Open: prove that the columns the `groups` commit — each an opener and its
/// source columns, all of `2^point.len()` entries — take `values` at `point`,
/// group-major, in the caller's live transcript `t`.
pub fn open(
    t: &mut Transcript,
    setup: &[Fp],
    groups: &[(&Opener, Source)],
    point: &[Fp2],
    values: &[Fp2],
) -> Proof {
    let columns: Vec<usize> = groups
        .iter()
        .map(|(_, s)| match s {
            Source::Columns(cs) => cs.len(),
            Source::Digits(_) => panic!("a root group is columns"),
        })
        .collect();
    let s = Schedule::new(point.len() as u32, &columns);
    let per_column = (1usize << point.len()) / s.levels[0].block_len();
    let mut group_blocks: Vec<usize> = groups
        .iter()
        .map(|(_, src)| (src.len() >> point.len()) * per_column)
        .collect();
    let mut point = point.to_vec();
    let mut values = values.to_vec();
    let mut folds = Vec::new();
    let mut owned: Option<(Opener, Vec<i8>)> = None;
    let mut last: Option<(Vec<Vec<Fp>>, Vec<i8>)> = None;
    for h in 0..s.folds() {
        let next = {
            let inputs: Vec<(&Opener, Source)> = match &owned {
                None => groups.to_vec(),
                Some((o, w)) => vec![(o, Source::Digits(w))],
            };
            fold(t, setup, &s, h, &inputs, &point, &values, &group_blocks)
        };
        folds.push(next.proof);
        point = next.point;
        values = vec![next.value];
        group_blocks = vec![s.levels.get(h + 1).map_or(0, |n| n.blocks)];
        match next.successor {
            Successor::Commit(o) => owned = Some((o, next.witness)),
            Successor::Terminal(images) => last = Some((images, next.witness)),
        }
    }
    let (images, w) = last.expect("the final fold binds the terminal state");
    let _ = images;
    let terminal = terminal(t, &s.terminal, &point, &w);
    Proof { folds, terminal }
}

enum Successor {
    Commit(Opener),
    Terminal(Vec<Vec<Fp>>),
}

struct Next {
    proof: Fold,
    point: Vec<Fp2>,
    value: Fp2,
    witness: Vec<i8>,
    successor: Successor,
}

/// `acc += ι(c)·x` over integers in `Z[X]/(X^d + 1)`. Each term is a rotation
/// by `pos·stride`, cut at the wrap into two runs: the entries that stay land
/// `shift` higher, the ones that wrap land `d` lower, negated.
fn sparse_ints(c: &Sparse, stride: usize, x: &[i64], acc: &mut [i64]) {
    let d = x.len();
    for (&p, &v) in c.pos.iter().zip(&c.coef) {
        let shift = p as usize * stride;
        let (stay, wrap) = x.split_at(d - shift);
        let (low, high) = acc.split_at_mut(shift);
        let v = v as i64;
        match v {
            1 => {
                high.iter_mut().zip(stay).for_each(|(o, &y)| *o += y);
                low.iter_mut().zip(wrap).for_each(|(o, &y)| *o -= y);
            }
            -1 => {
                high.iter_mut().zip(stay).for_each(|(o, &y)| *o -= y);
                low.iter_mut().zip(wrap).for_each(|(o, &y)| *o += y);
            }
            _ => {
                high.iter_mut().zip(stay).for_each(|(o, &y)| *o += v * y);
                low.iter_mut().zip(wrap).for_each(|(o, &y)| *o -= v * y);
            }
        }
    }
}

/// `hi += high half of the unreduced ι(c)·x`.
fn sparse_high<T: Copy + core::ops::AddAssign + core::ops::Mul<Fp, Output = T>>(
    c: &Sparse,
    stride: usize,
    x: &[T],
    hi: &mut [T],
) {
    let d = x.len();
    for (&p, &v) in c.pos.iter().zip(&c.coef) {
        let shift = p as usize * stride;
        for (j, &y) in x.iter().enumerate() {
            if j + shift >= d {
                hi[j + shift - d] += y * fp(v as i64);
            }
        }
    }
}

/// The balanced base-`2^log` interval `δ` digits write: `[−M, T]`.
fn interval(log: u32, delta: usize) -> (i128, i128) {
    let t = digit_top(log, delta) as i128;
    let geometric = (0..delta).fold(0i128, |acc, _| acc * (1 << log) + 1);
    (-((1i128 << (log - 1)) * geometric), t)
}

/// The full-field digits of short rows of dimension `d < 64`,
/// `(row·δ + u)·d + k` (the compression quotients').
fn small_digits(x: &[Fp], log: u32, d: usize) -> Vec<i8> {
    let delta = full_digits(log);
    let mut out = vec![0i8; x.len() * delta];
    let mut ds = vec![0i32; delta];
    for (i, &v) in x.iter().enumerate() {
        digits(lift(v, log, delta), log, delta, &mut ds);
        let (row, k) = (i / d, i % d);
        for (u, &dv) in ds.iter().enumerate() {
            out[(row * delta + u) * d + k] = dv as i8;
        }
    }
    out
}

fn put(w: &mut [i8], start: usize, digits: &[i8]) {
    w[start..start + digits.len()].copy_from_slice(digits);
}

#[allow(clippy::too_many_arguments)]
fn fold(
    t: &mut Transcript,
    setup: &[Fp],
    s: &Schedule,
    h: usize,
    inputs: &[(&Opener, Source)],
    point: &[Fp2],
    values: &[Fp2],
    group_blocks: &[usize],
) -> Next {
    let l = &s.levels[h];
    let lay = Layout::new(l, group_blocks);
    let starts: Vec<usize> = group_blocks
        .iter()
        .scan(0, |acc, &b| {
            let s = *acc;
            *acc += b;
            Some(s)
        })
        .collect();
    let locate = |lam: usize| {
        let g = starts
            .iter()
            .rposition(|&s| s <= lam)
            .expect("block 0 is group 0's");
        (g, lam - starts[g])
    };
    // 0. The tensor reduction (evaluation trace).
    let (tensor_proof, traced) = match l.method {
        Method::Pack => (None, None),
        Method::Trace => {
            let Source::Digits(w) = inputs[0].1 else {
                panic!("a trace level opens a witness")
            };
            let (p, rho, theta, value) = tensor(t, w, point);
            (Some(p), Some((rho, theta, value)))
        }
    };
    // 1. The partials, their digits, the opening image and payload.
    let inc = Incoming {
        point: point.to_vec(),
        values: values.to_vec(),
        group_blocks: group_blocks.to_vec(),
        payloads: Vec::new(),
    };
    let (r_pack, _, r_pos, _) = match l.method {
        Method::Pack => pack_claims(l, &inc, &vec![Fp2::ZERO; values.len()]),
        Method::Trace => (Vec::new(), Vec::new(), Vec::new(), Vec::new()),
    };
    let partials: Vec<Vec<Fp>> = (0..l.blocks)
        .into_par_iter()
        .map(|lam| {
            let (g, b) = locate(lam);
            let src = &inputs[g].1;
            match &traced {
                None => {
                    let eq_pos = eq_table(&r_pos);
                    let eq_pack = eq_table(&r_pack);
                    let mut sum = vec![Fp2::ZERO; l.d_a];
                    for (x, &e) in eq_pos.iter().enumerate() {
                        for (o, v) in sum.iter_mut().zip(src.values(l, b * l.m + x)) {
                            *o += e * v;
                        }
                    }
                    let stride = l.stride();
                    let e: Vec<Fp2> = (0..l.family.dim)
                        .map(|j| {
                            (0..stride)
                                .fold(Fp2::ZERO, |acc, a| acc + eq_pack[a] * sum[a + stride * j])
                        })
                        .collect();
                    e.iter()
                        .map(|x| x.c0)
                        .chain(e.iter().map(|x| x.c1))
                        .collect()
                }
                Some((rho, _, _)) => {
                    let lp = (l.d_a / 2).trailing_zeros() as usize;
                    let eq_pos = eq_table(&rho[lp..lp + l.m.trailing_zeros() as usize]);
                    let mut e = vec![Fp::ZERO; l.d_a];
                    for (x, &a) in eq_pos.iter().enumerate() {
                        for (o, v) in e.iter_mut().zip(embed_mul(a, &src.values(l, b * l.m + x))) {
                            *o += v;
                        }
                    }
                    e
                }
            }
        })
        .collect();
    let e_digits: Vec<i8> = partials
        .par_iter()
        .flat_map(|e| full_field_digits(e, l.log_b))
        .collect();
    let (v_image, q_open) = outer_product(setup, l.n_d, open_width(l), D_C, &e_digits);
    let v_chain = l.compress.then(|| compress(setup, &v_image));
    let opening_payload = v_chain
        .as_ref()
        .map_or_else(|| v_image.clone(), |c| c.payload.clone());
    t.append_scalars(PCS_MESSAGE, &opening_payload);
    // 2. The scalar weights, the nonce, the challenges and the response.
    let opening = match &traced {
        None => {
            let weights = batch_weights(t, values.len());
            let (r_pack, r_tail, r_pos, claims) = pack_claims(l, &inc, &weights);
            Opening::Pack {
                r_pack,
                r_tail,
                r_pos,
                claims,
            }
        }
        Some((rho, theta, value)) => {
            let lp = (l.d_a / 2).trailing_zeros() as usize;
            let lm = l.m.trailing_zeros() as usize;
            Opening::Trace {
                rho_pack: rho[..lp].to_vec(),
                rho_pos: rho[lp..lp + lm].to_vec(),
                rho_blk: rho[lp + lm..].to_vec(),
                theta: *theta,
                value: *value,
            }
        }
    };
    let (lo, hi) = interval(l.log_b, l.fold_digits);
    let m_a = l.m * l.src_digits;
    let snap = t.snapshot();
    let (nonce, chal, z) = (0..NONCES)
        .find_map(|nonce| {
            let mut tt = Transcript::restore(&snap);
            tt.append_scalar(PCS_MESSAGE, Fp::from_u64(nonce as u64));
            let chal = fold_challenges(tt.challenge(PCS_CHALLENGE), nonce, l.family, l.blocks);
            let z: Vec<Vec<i64>> = (0..l.m)
                .into_par_iter()
                .flat_map(|x| {
                    let mut acc = vec![vec![0i64; l.d_a]; l.src_digits];
                    let mut ds = Digits::new(l);
                    for (lam, c) in chal.iter().enumerate() {
                        let (g, b) = locate(lam);
                        inputs[g].1.digits_into(l, b * l.m + x, &mut ds);
                        for (lc, plane) in ds.planes() {
                            sparse_ints(c, l.stride(), plane, &mut acc[lc]);
                        }
                    }
                    acc
                })
                .collect();
            let fits = z
                .iter()
                .flatten()
                .all(|&v| (lo..=hi).contains(&(v as i128)));
            let norm: u128 = z
                .iter()
                .flatten()
                .map(|&v| (v as i128 * v as i128) as u128)
                .sum();
            let small = l.s_max.is_none_or(|smax| norm <= smax);
            (fits && small).then_some((nonce, chal, z))
        })
        .expect("some nonce admits the honest response");
    t.append_scalar(PCS_MESSAGE, Fp::from_u64(nonce as u64));
    let _ = t.challenge(PCS_CHALLENGE);
    let mut z_digits = vec![0i8; lay.z.len];
    let mut ds = vec![0i32; l.fold_digits];
    for (xp, zx) in z.iter().enumerate() {
        for (k, &v) in zx.iter().enumerate() {
            digits(v as i128, l.log_b, l.fold_digits, &mut ds);
            for (u, &dv) in ds.iter().enumerate() {
                z_digits[(l.fold_digits * xp + u) * l.d_a + k] = dv as i8;
            }
        }
    }
    // 3. The quotients of every ring row (paper (111)).
    let blocks_of = |lam: usize| {
        let (g, b) = locate(lam);
        &inputs[g].0.inner[b]
    };
    let q_fold: Vec<Fp> = match l.method {
        Method::Pack => {
            let dc = l.family.dim;
            let mut q = vec![Fp2::ZERO; dc];
            for (c, e) in chal.iter().zip(&partials) {
                let ext: Vec<Fp2> = (0..dc)
                    .map(|j| Fp2 {
                        c0: e[j],
                        c1: e[dc + j],
                    })
                    .collect();
                sparse_high(c, 1, &ext, &mut q);
            }
            q.iter()
                .map(|x| x.c0)
                .chain(q.iter().map(|x| x.c1))
                .collect()
        }
        Method::Trace => {
            let d = l.d_a;
            let mut q = vec![Fp::ZERO; d];
            for (c, e) in chal.iter().zip(&partials) {
                sparse_high(c, 1, e, &mut q);
            }
            let Opening::Trace { rho_pos, .. } = &opening else {
                unreachable!()
            };
            let eq_pos = eq_table(rho_pos);
            // −high(Σ_x a_x·z_x), a_x = c0 + c1·(X^(d/4) − X^(3d/4)).
            for (x, zx) in z.iter().enumerate() {
                let a = eq_pos[x];
                for (shift, coef) in [(d / 4, a.c1), (3 * d / 4, -a.c1)] {
                    for (j, &v) in zx.iter().enumerate() {
                        if j + shift >= d {
                            q[j + shift - d] -= coef * fp(v);
                        }
                    }
                }
            }
            q
        }
    };
    let q_inner: Vec<Fp> = {
        let d = l.d_a;
        let crt = Crt::new(2 * d, false);
        let pad = |v: &[Fp]| {
            let mut o = v.to_vec();
            o.resize(2 * d, Fp::ZERO);
            o
        };
        let zspec: Vec<_> = (0..m_a)
            .into_par_iter()
            .map(|xp| {
                let mut v: Vec<i64> = z[xp].clone();
                v.resize(2 * d, 0);
                crt.of_ints(&v)
            })
            .collect();
        let rows: Vec<Vec<Fp>> = (0..l.n_a)
            .into_par_iter()
            .map(|a| {
                let mut acc = crt.zero();
                for (xp, zs) in zspec.iter().enumerate() {
                    crt.mul_acc(
                        &mut acc,
                        &crt.of_field(&pad(view(setup, m_a, d, a, xp))),
                        zs,
                    );
                }
                let full = crt.back(acc);
                let mut q: Vec<Fp> = full[d..].iter().map(|&x| -x).collect();
                for (lam, c) in chal.iter().enumerate() {
                    sparse_high(c, l.stride(), &blocks_of(lam)[a * d..(a + 1) * d], &mut q);
                }
                q
            })
            .collect();
        rows.concat()
    };
    // 4. The successor witness (paper (75), (76)).
    let mut w = vec![0i8; lay.len];
    put(&mut w, lay.z.start, &z_digits);
    put(&mut w, lay.e.start, &e_digits);
    let t_digits: Vec<i8> = (0..l.blocks)
        .into_par_iter()
        .flat_map(|lam| image_digits(l, blocks_of(lam)))
        .collect();
    put(&mut w, lay.t.start, &t_digits);
    put(
        &mut w,
        lay.q_fold.start,
        &full_field_digits(&q_fold, l.log_b),
    );
    put(
        &mut w,
        lay.q_inner.start,
        &full_field_digits(&q_inner, l.log_b),
    );
    let slices: Vec<&crate::commit::Slice> =
        inputs.iter().flat_map(|(o, _)| o.slices.iter()).collect();
    let q_outer: Vec<Fp> = slices
        .iter()
        .flat_map(|s| s.quotient.iter().copied())
        .collect();
    put(
        &mut w,
        lay.q_outer.start,
        &full_field_digits(&q_outer, l.log_b),
    );
    put(
        &mut w,
        lay.q_open.start,
        &full_field_digits(&q_open, l.log_b),
    );
    if l.compress {
        let chains: Vec<&crate::commit::Chain> = slices
            .iter()
            .map(|s| {
                s.chain
                    .as_ref()
                    .expect("a compressed level's slices carry chains")
            })
            .chain(v_chain.as_ref())
            .collect();
        let (mut c1, mut q1, mut c2, mut q2) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for c in &chains {
            c1.extend_from_slice(&c.bits1);
            q1.extend(small_digits(&c.q1, l.log_b, D_F1));
            c2.extend_from_slice(&c.bits2);
            q2.extend(small_digits(&c.q2, l.log_b, D_F2));
        }
        put(&mut w, lay.c1.start, &c1);
        put(&mut w, lay.q1.start, &q1);
        put(&mut w, lay.c2.start, &c2);
        put(&mut w, lay.q2.start, &q2);
    }
    // 5. Commit to it, or at the final fold bind the terminal's inner state.
    let (successor, succ_msg, digest_msg) = match s.levels.get(h + 1) {
        Some(n) => {
            let o = commit(setup, n, &Source::Digits(&w));
            let payloads = o.commitment.0.clone();
            (Successor::Commit(o), payloads, None)
        }
        None => {
            let images = terminal_images(setup, &s.terminal, &w);
            let (head, tail) = images.split_at(images.len() - 1);
            let d = digest(&tail[0]);
            (Successor::Terminal(images.clone()), head.to_vec(), Some(d))
        }
    };
    debug_assert_eq!(
        successor_shape(s, h, lay.len),
        (succ_msg.len(), succ_msg.first().map_or(0, |p| p.len()))
    );
    for p in &succ_msg {
        t.append_scalars(PCS_MESSAGE, p);
    }
    if let Some(d) = &digest_msg {
        t.append_scalars(PCS_MESSAGE, d);
    }
    // 6. Ring reduction, range, norm (paper Fig. 6).
    let mu = log2_ceil(lay.len);
    let rows = lay.rows(l);
    let alpha = t.challenge(PCS_CHALLENGE);
    let tau0 = challenges(t, mu);
    let tau1 = challenges(t, log2_ceil(rows));
    let response: Option<Vec<i64>> = l.s_max.map(|_| z.iter().flatten().copied().collect());
    let (range_stages, norm, r_virt) = range(t, l, &w, mu, &tau0, response.as_deref());
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
    // 7. The fused sumcheck over the relation's dense weights (paper (125)).
    let mut payloads: Vec<Vec<Fp>> = inputs
        .iter()
        .flat_map(|(o, _)| o.commitment.0.iter().cloned())
        .collect();
    payloads.push(opening_payload.clone());
    let public = Public {
        level: l,
        layout: &lay,
        setup,
        challenges: &chal,
        alpha,
        opening: &opening,
        payloads: &payloads,
    };
    let pats = Patterns::new(&public, response.as_ref().map(|_| r_virt.as_slice()));
    let eq_rows = eq_table(&tau1);
    let mut m = vec![Fp2::ZERO; lay.len];
    let mut add = |c: usize, p, wgt: Fp2| {
        for (k, slot) in m[c * CHUNK..(c + 1) * CHUNK].iter_mut().enumerate() {
            *slot += wgt * pats.get(p, k);
        }
    };
    let _ = relation(&public, &mut |row, c, p, wgt| add(c, p, eq_rows[row] * wgt));
    if l.s_max.is_some() {
        norm_binding(l, &lay, eta_norm, &r_virt, &mut |c, p, wgt| add(c, p, wgt));
    }
    // The binariness weight is the extension of x ↦ 1_bin(x)·eq(r_virt, x)
    // itself, one table (paper Remark 6.2): not the product of eq's extension
    // and the indicator's, which agree only on the cube.
    let lo = eq_table(&r_virt[..6]);
    let mut bin = vec![Fp2::ZERO; lay.len - lay.c1.start];
    for sg in lay.binary() {
        for c in sg.start / CHUNK..(sg.start + sg.len) / CHUNK {
            let hi = zeta_bin * eq_at(&r_virt[6..], c);
            for (k, &e) in lo.iter().enumerate() {
                bin[c * CHUNK + k - lay.c1.start] = hi * e;
            }
        }
    }
    let mut tables = vec![
        Table::small(0, w.iter().map(|&x| x as i16).collect()),
        Table::ext(0, m),
        Table::ext(lay.c1.start, bin),
    ];
    let (fused, r2) = sumcheck(t, mu, &mut tables, Some(&r_virt), 3, false, |e, v| {
        v[0] * v[1] + (e * gamma + v[2]) * v[0] * (v[0] + Fp2::ONE)
    });
    let value = tables[0].get(0);
    t.append_ext(PCS_MESSAGE, &[value]);
    Next {
        proof: Fold {
            tensor: tensor_proof,
            opening: opening_payload,
            nonce,
            successor: succ_msg,
            digest: digest_msg,
            norm,
            range: range_stages,
            fused,
            value,
        },
        point: r2,
        value,
        witness: w,
        successor,
    }
}

/// The tensor reduction of `w̃(r) = v` (paper §3.7): `(proof, ρ, θ, θ·f̄(ρ))`.
fn tensor(t: &mut Transcript, w: &[i8], r: &[Fp2]) -> (Tensor, Vec<Fp2>, Fp2, Fp2) {
    let eq = eq_table(&r[1..]);
    let half = w.len().div_ceil(2);
    let at = |i: usize| w.get(i).map_or(Fp::ZERO, |&x| fp(x as i64));
    let s0 = (0..half).fold(Fp2::ZERO, |acc, i| acc + eq[i] * at(2 * i));
    let s1 = (0..half).fold(Fp2::ZERO, |acc, i| acc + eq[i] * at(2 * i + 1));
    let partials = [s0, s1];
    t.append_ext(PCS_MESSAGE, &partials);
    let eta = t.challenge(PCS_CHALLENGE);
    let a: Vec<Fp2> = eq
        .iter()
        .map(|e| (Fp2::ONE - eta) * e.c0 + eta * e.c1)
        .collect();
    let fbar: Vec<Fp2> = (0..half)
        .map(|i| Fp2 {
            c0: at(2 * i),
            c1: at(2 * i + 1),
        })
        .collect();
    let mut tables = vec![Table::ext(0, a), Table::ext(0, fbar)];
    let (rounds, rho) = sumcheck(t, r.len() - 1, &mut tables, None, 2, false, |_, v| {
        v[0] * v[1]
    });
    let theta = tables[0].get(0);
    let value = theta * tables[1].get(0);
    (Tensor { partials, rounds }, rho, theta, value)
}

/// The digit range tree over `w` (paper §6.1), the norm fused into its last
/// stage on the Euclidean route (§6.2). Returns the stages, the norm claim
/// and `r_virt`; `z̃_int(r_virt)` is the last stage's second claim.
fn range(
    t: &mut Transcript,
    l: &Level,
    w: &[i8],
    mu: usize,
    tau0: &[Fp2],
    response: Option<&[i64]>,
) -> (Vec<Stage>, Option<Fp>, Vec<Fp2>) {
    let fans = tree(l.log_b);
    let counts = levels(l.log_b);
    let half = 1i16 << (l.log_b - 1);
    let s_of = |x: i8| (x as i16) * (x as i16 + 1);
    // The leaf constants j(j+1), and every node's value by digit: a node's
    // value at a point is a function of the one digit there.
    let consts: Vec<Fp2> = leaves(l.log_b, Fp2::ZERO).iter().map(|&x| -x).collect();
    let leaf_count = consts.len();
    let leaf_sum = |s: Fp2, fan: usize, lambda: Fp2| {
        let (mut acc, mut wgt) = (Fp2::ZERO, Fp2::ONE);
        for g in consts.chunks(fan) {
            acc += wgt * g.iter().fold(Fp2::ONE, |p, &c| p * (s - c));
            wgt *= lambda;
        }
        acc
    };
    let mut point = tau0.to_vec();
    let mut stages = Vec::new();
    let mut norm = None;
    let mut out = None;
    for (i, &fan) in fans.iter().enumerate() {
        let last = i + 1 == fans.len();
        let lambda = if i == 0 {
            Fp2::ONE
        } else {
            t.challenge(PCS_CHALLENGE)
        };
        let mut zeta = Fp2::ZERO;
        if last {
            if let Some(z) = response {
                let n: u128 = z.iter().map(|&v| (v as i128 * v as i128) as u128).sum();
                let nf = Fp::from_u128(n);
                t.append_scalar(PCS_MESSAGE, nf);
                zeta = t.challenge(PCS_CHALLENGE);
                norm = Some(nf);
            }
        }
        // The children's tables: s at the leaves, else node values over the
        // whole domain (off the witness, a node is its value at digit 0).
        let mut tables: Vec<Table> = if last {
            vec![Table::small(0, w.iter().map(|&x| s_of(x)).collect())]
        } else {
            let group = leaf_count / counts[i + 1];
            (0..counts[i + 1])
                .map(|c| {
                    let by_digit: Vec<Fp2> = (-half..half)
                        .map(|x| {
                            let s = Fp2::from(fp(s_of(x as i8) as i64));
                            consts[c * group..(c + 1) * group]
                                .iter()
                                .fold(Fp2::ONE, |p, &k| p * (s - k))
                        })
                        .collect();
                    let mut v: Vec<Fp2> = w
                        .par_iter()
                        .map(|&x| by_digit[(x as i16 + half) as usize])
                        .collect();
                    v.resize(1 << mu, by_digit[half as usize]);
                    Table::ext(0, v)
                })
                .collect()
        };
        if let (true, Some(z)) = (last, response) {
            tables.push(Table::ext(0, z.iter().map(|&v| Fp2::from(fp(v))).collect()));
        }
        let dense = !(last && i == 0);
        let degree = (fan + 1).max(2);
        let norm_term = last && response.is_some();
        let (rounds, next) = sumcheck(t, mu, &mut tables, Some(&point), degree, dense, |e, v| {
            let mut acc = if last {
                e * leaf_sum(v[0], fan, lambda)
            } else {
                e * node_sum(v, fan, lambda)
            };
            if norm_term {
                acc += zeta * v[1] * v[1];
            }
            acc
        });
        let claims: Vec<Fp2> = tables.iter().map(|tb| tb.get(0)).collect();
        t.append_ext(PCS_MESSAGE, &claims);
        if last {
            out = Some(next.clone());
        }
        stages.push(Stage {
            rounds,
            claims: claims.clone(),
        });
        point = next;
    }
    let r_virt = out.expect("a range tree has a stage");
    (stages, norm, r_virt)
}

/// The terminal's inner state `t'_λ = A_T·s'_λ` of the trace-packed blocks of `w`.
fn terminal_images(setup: &[Fp], tm: &TerminalParams, w: &[i8]) -> Vec<Vec<Fp>> {
    let l = terminal_level(tm, w.len());
    inner_images(setup, &l, &Source::Digits(w), l.blocks)
}

/// The terminal as a level, for the commitment code it shares.
fn terminal_level(tm: &TerminalParams, len: usize) -> Level {
    Level {
        method: Method::Trace,
        d_a: tm.d_a,
        family: tm.family,
        m: tm.m,
        input_len: len,
        blocks: len.div_ceil(tm.d_a * tm.m),
        src_log: 0,
        src_digits: 1,
        n_a: tm.n_a,
        n_b: 0,
        n_d: 0,
        log_b: 6,
        open_digits: 0,
        fold_digits: 0,
        slice_blocks: 1,
        compress: false,
        s_max: Some(tm.s_max),
    }
}

/// Signed Rice coding with parameter `k`: zigzag, then the quotient in unary
/// and `k` low bits, least significant first.
fn rice_encode(z: &[i64], k: u32) -> Vec<u8> {
    let mut bits: Vec<bool> = Vec::new();
    for &v in z {
        let zz = ((v << 1) ^ (v >> 63)) as u64;
        bits.extend(core::iter::repeat_n(true, (zz >> k) as usize));
        bits.push(false);
        for i in 0..k {
            bits.push((zz >> i) & 1 == 1);
        }
    }
    let mut out = vec![0u8; bits.len().div_ceil(8)];
    for (i, b) in bits.into_iter().enumerate() {
        if b {
            out[i / 8] |= 1 << (i % 8);
        }
    }
    out
}

fn terminal(t: &mut Transcript, tm: &TerminalParams, point: &[Fp2], w: &[i8]) -> Terminal {
    let l = terminal_level(tm, w.len());
    let d = tm.d_a;
    let (tensor_proof, rho, _, _) = tensor(t, w, point);
    let lp = (d / 2).trailing_zeros() as usize;
    let eq_pos = eq_table(&rho[lp..lp + tm.m.trailing_zeros() as usize]);
    let src = Source::Digits(w);
    let partials: Vec<Vec<Fp>> = (0..l.blocks)
        .into_par_iter()
        .map(|lam| {
            let mut e = vec![Fp::ZERO; d];
            for (x, &a) in eq_pos.iter().enumerate() {
                for (o, v) in e
                    .iter_mut()
                    .zip(embed_mul(a, &src.values(&l, lam * tm.m + x)))
                {
                    *o += v;
                }
            }
            e
        })
        .collect();
    let (head, tail) = partials.split_at(l.blocks - 1);
    for e in head {
        t.append_scalars(PCS_MESSAGE, e);
    }
    let pd = digest(&tail[0]);
    t.append_scalars(PCS_MESSAGE, &pd);
    let snap = t.snapshot();
    let (nonce, z) = (0..NONCES)
        .find_map(|nonce| {
            let mut tt = Transcript::restore(&snap);
            tt.append_scalar(PCS_MESSAGE, Fp::from_u64(nonce as u64));
            let chal = fold_challenges(tt.challenge(PCS_CHALLENGE), nonce, tm.family, l.blocks);
            let z: Vec<i64> = (0..tm.m)
                .into_par_iter()
                .flat_map(|x| {
                    let mut acc = vec![0i64; d];
                    let mut ds = Digits::new(&l);
                    for (lam, c) in chal.iter().enumerate() {
                        src.digits_into(&l, lam * tm.m + x, &mut ds);
                        for (_, plane) in ds.planes() {
                            sparse_ints(c, 1, plane, &mut acc);
                        }
                    }
                    acc
                })
                .collect();
            let n: u128 = z.iter().map(|&v| (v as i128 * v as i128) as u128).sum();
            (n <= tm.s_max).then_some((nonce, z))
        })
        .expect("some nonce admits the honest terminal response");
    t.append_scalar(PCS_MESSAGE, Fp::from_u64(nonce as u64));
    let _ = t.challenge(PCS_CHALLENGE);
    let zf: Vec<Fp> = z.iter().map(|&v| fp(v)).collect();
    t.append_scalars(PCS_MESSAGE, &zf);
    Terminal {
        tensor: tensor_proof,
        partials: head.to_vec(),
        digest: pd,
        nonce,
        response: rice_encode(&z, rice_k(tm)),
    }
}
