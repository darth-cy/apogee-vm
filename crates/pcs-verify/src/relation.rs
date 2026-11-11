//! A fold's successor witness and the rows that check it (paper §5.5, §7,
//! Fig. 5): one definition both sides read. `docs/spec/pcs.md` §4.
//!
//! The witness is a sequence of 64-entry chunks. Every ring row, reduced at
//! `α` by quotient lifting (paper (111)–(115)), weighs each chunk it reads by
//! a scalar times one of a few fixed 64-entry patterns; [`relation`] walks the
//! rows and hands each `(row, chunk, pattern, weight)` to a sink. The prover's
//! sink expands them into the dense weight table of the fused sumcheck, the
//! verifier's contracts them against `eq(r₂, ·)`.

use alloc::vec;
use alloc::vec::Vec;

use field::{Fp, Fp2};
use poly::eq_table;

use crate::params::{Level, D_C, D_F1, D_F2, Q_BITS};
use crate::ring::{embed_eval, eval, powers, trace_weights, Sparse};

/// Entries per chunk.
pub const CHUNK: usize = 64;

/// A span of the witness, in entries.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Seg {
    pub start: usize,
    pub len: usize,
}

/// Where everything of a fold's successor witness sits, every segment
/// starting on a chunk, and the fold's outer slices.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layout {
    /// `(first block, blocks)` of every slice: each group's blocks cut into
    /// runs of `slice_blocks`, groups in order.
    pub slices: Vec<(usize, usize)>,
    /// Response digits: `(δ_f·(δ_com·x + l) + u)·d_A + k` (paper (347)).
    pub z: Seg,
    /// Partial digits: `((λ·s + y)·δ + u)·64 + k`, `s = d_op/64` (paper (346)).
    pub e: Seg,
    /// Inner-image digits: `(((λ·n_A + a)·s + y)·δ + u)·64 + k`, `s = d_A/64`.
    pub t: Seg,
    /// Quotient digits, like every full-field segment in native 64-coefficient
    /// blocks, `(block·δ + u)·64 + k`: the fold row (a packing carrier's two
    /// planes in turn), the `n_A` inner rows, each slice's `n_B` outer rows,
    /// the `n_D` opening rows.
    pub q_fold: Seg,
    pub q_inner: Seg,
    pub q_outer: Seg,
    pub q_open: Seg,
    /// Compression chains (paper §4.5, (47)), slices then the opening: first
    /// binary digits, first-map quotients `(chain·δ + u)·32 + k`, second
    /// binary digits, second-map quotients `(chain·δ + u)·16 + k`.
    pub c1: Seg,
    pub q1: Seg,
    pub c2: Seg,
    pub q2: Seg,
    pub len: usize,
}

fn seg(at: &mut usize, len: usize) -> Seg {
    let s = Seg { start: *at, len };
    *at = (*at + len).next_multiple_of(CHUNK);
    s
}

impl Layout {
    /// The layout of `l`'s successor, its blocks split into groups of
    /// `groups` blocks each (one group but at the root).
    pub fn new(l: &Level, groups: &[usize]) -> Layout {
        debug_assert_eq!(groups.iter().sum::<usize>(), l.blocks);
        let mut slices = Vec::new();
        let mut first = 0;
        for &g in groups {
            let mut left = g;
            while left > 0 {
                let n = left.min(l.slice_blocks);
                slices.push((first, n));
                first += n;
                left -= n;
            }
        }
        let s = slices.len();
        let delta = l.open_digits;
        let mut at = 0;
        let z = seg(&mut at, l.m * l.src_digits * l.fold_digits * l.d_a);
        let e = seg(&mut at, l.blocks * l.d_op() * delta);
        let t = seg(&mut at, l.blocks * l.n_a * l.d_a * delta);
        let q_fold = seg(&mut at, l.d_op() * delta);
        let q_inner = seg(&mut at, l.n_a * l.d_a * delta);
        let q_outer = seg(&mut at, s * l.n_b * D_C * delta);
        let q_open = seg(&mut at, l.n_d * D_C * delta);
        let none = Seg { start: at, len: 0 };
        let (c1, q1, c2, q2) = if l.compress {
            let c1 = seg(&mut at, (s * l.n_b + l.n_d) * D_C * Q_BITS);
            let q1 = seg(&mut at, (s + 1) * D_F1 * delta);
            let c2 = seg(&mut at, (s + 1) * D_F1 * Q_BITS);
            let q2 = seg(&mut at, (s + 1) * D_F2 * delta);
            (c1, q1, c2, q2)
        } else {
            (none, none, none, none)
        };
        Layout {
            slices,
            z,
            e,
            t,
            q_fold,
            q_inner,
            q_outer,
            q_open,
            c1,
            q1,
            c2,
            q2,
            len: at,
        }
    }

    /// The binary digits, which the fused sumcheck restricts to `{−1, 0}`.
    pub fn binary(&self) -> [Seg; 2] {
        [self.c1, self.c2]
    }

    /// The rows: the fold row, `n_A` inner, `n_B` outer per slice, `n_D`
    /// opening, with compression a first-map row and then a second-map row
    /// per chain, and last the scalar row.
    pub fn rows(&self, l: &Level) -> usize {
        let chains = if l.compress {
            2 * (self.slices.len() + 1)
        } else {
            0
        };
        1 + l.n_a + self.slices.len() * l.n_b + l.n_d + chains + 1
    }

    /// The first binary digit of chain `chain` (slices, then the opening) in
    /// the `c1` segment, and its image's rank.
    fn chain(&self, l: &Level, chain: usize) -> (usize, usize) {
        let first = chain.min(self.slices.len()) * l.n_b * D_C * Q_BITS;
        let rank = if chain < self.slices.len() {
            l.n_b
        } else {
            l.n_d
        };
        (first, rank)
    }
}

/// A slice's B view width in `R_64` elements.
pub fn slice_width(l: &Level) -> usize {
    l.slice_blocks * l.n_a * l.open_digits * l.d_a / D_C
}

/// The D view width in `R_64` elements.
pub fn open_width(l: &Level) -> usize {
    l.blocks * l.d_op() * l.open_digits / D_C
}

/// The setup prefix every matrix view of `l` reads.
pub fn setup_len(l: &Level) -> usize {
    let views = [
        l.n_a * l.m * l.src_digits * l.d_a,
        l.n_b * slice_width(l) * D_C,
        l.n_d * open_width(l) * D_C,
        l.n_b.max(l.n_d) * D_C * Q_BITS,
        D_F1 * Q_BITS,
    ];
    views.into_iter().max().expect("five views")
}

/// The matrix view `M ∈ R_d^{n×m}` at `(i, j)`: setup entries from
/// `(i·m + j)·d` (paper (35)).
pub fn view(setup: &[Fp], m: usize, d: usize, i: usize, j: usize) -> &[Fp] {
    let at = (i * m + j) * d;
    &setup[at..at + d]
}

/// A 64-entry weight pattern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pat {
    /// `α^k`.
    Alpha,
    /// `α^(k − 32i)` on half `i`, zero elsewhere: one element of `R_32`.
    Half(usize),
    /// `α^(k − 16i)` on quarter `i`: one element of `R_16`.
    Quarter(usize),
    /// The packing contraction on a response chunk:
    /// `eq(r_pack, k mod stride)·α^(k / stride)`.
    Pack,
    /// The packing scalar row on a partial chunk: `eq(r_tail[..6], k)`.
    Tail,
    /// The trace scalar row: `T(X^k)`.
    Trace,
    /// The response-norm binding: `eq(r_virt[..6], k)`.
    Virt,
}

impl Pat {
    /// A dense index, for tables of per-pattern values.
    pub fn index(self) -> usize {
        match self {
            Pat::Alpha => 0,
            Pat::Half(i) => 1 + i,
            Pat::Quarter(i) => 3 + i,
            Pat::Pack => 7,
            Pat::Tail => 8,
            Pat::Trace => 9,
            Pat::Virt => 10,
        }
    }

    pub const COUNT: usize = 11;

    pub const ALL: [Pat; Pat::COUNT] = [
        Pat::Alpha,
        Pat::Half(0),
        Pat::Half(1),
        Pat::Quarter(0),
        Pat::Quarter(1),
        Pat::Quarter(2),
        Pat::Quarter(3),
        Pat::Pack,
        Pat::Tail,
        Pat::Trace,
        Pat::Virt,
    ];
}

/// How a fold's claims reach its partials.
pub enum Opening {
    /// Packing: the shared point segments, and per claim its blocks, block
    /// point, batching weight and value (paper (59), (71), (72)).
    Pack {
        r_pack: Vec<Fp2>,
        r_tail: Vec<Fp2>,
        r_pos: Vec<Fp2>,
        claims: Vec<Claim>,
    },
    /// Evaluation trace after the tensor reduction: the packed point's
    /// segments, `θ` and the reduction's final value (paper (98), (101)).
    Trace {
        rho_pack: Vec<Fp2>,
        rho_pos: Vec<Fp2>,
        rho_blk: Vec<Fp2>,
        theta: Fp2,
        value: Fp2,
    },
}

/// One packing claim: blocks `[first, first + blocks)` hold a vector whose
/// value at `(r_pack, r_tail, r_pos, r_blk)` is `value`.
#[derive(Clone, Debug)]
pub struct Claim {
    pub first: usize,
    pub blocks: usize,
    pub r_blk: Vec<Fp2>,
    pub weight: Fp2,
    pub value: Fp2,
}

/// Everything public one fold's relation reads.
pub struct Public<'a> {
    pub level: &'a Level,
    pub layout: &'a Layout,
    pub setup: &'a [Fp],
    /// One per block.
    pub challenges: &'a [Sparse],
    pub alpha: Fp2,
    pub opening: &'a Opening,
    /// Per slice, then the opening: the second map's image (compressed) or
    /// the raw image.
    pub payloads: &'a [Vec<Fp>],
}

/// The 64-entry patterns of one fold.
pub struct Patterns {
    alpha: Vec<Fp2>,
    pack: Vec<Fp2>,
    tail: Vec<Fp2>,
    trace: Vec<Fp2>,
    virt: Vec<Fp2>,
}

impl Patterns {
    pub fn new(p: &Public, r_virt: Option<&[Fp2]>) -> Patterns {
        let alpha = powers(p.alpha, CHUNK);
        let zero = vec![Fp2::ZERO; CHUNK];
        let (mut pack, mut tail, mut trace) = (zero.clone(), zero.clone(), zero.clone());
        match p.opening {
            Opening::Pack { r_pack, r_tail, .. } => {
                let stride = p.level.stride();
                let eq_pack = eq_table(r_pack);
                pack = (0..CHUNK)
                    .map(|k| eq_pack[k % stride] * alpha[k / stride])
                    .collect();
                tail = eq_table(&r_tail[..6]);
            }
            Opening::Trace { rho_pack, .. } => trace = trace_weights(&eq_table(rho_pack)),
        }
        let virt = r_virt.map_or(zero, |r| eq_table(&r[..6]));
        Patterns {
            alpha,
            pack,
            tail,
            trace,
            virt,
        }
    }

    pub fn get(&self, p: Pat, k: usize) -> Fp2 {
        let within = |i: usize, w: usize| {
            if k / w == i {
                self.alpha[k % w]
            } else {
                Fp2::ZERO
            }
        };
        match p {
            Pat::Alpha => self.alpha[k],
            Pat::Half(i) => within(i, 32),
            Pat::Quarter(i) => within(i, 16),
            Pat::Pack => self.pack[k],
            Pat::Tail => self.tail[k],
            Pat::Trace => self.trace[k],
            Pat::Virt => self.virt[k],
        }
    }
}

/// `b^u` for `u < n`, `b = 2^log`.
fn base_powers(log: u32, n: usize) -> Vec<Fp> {
    let b = Fp::from_u64(1 << log);
    let mut out = Vec::with_capacity(n);
    let mut x = Fp::ONE;
    for _ in 0..n {
        out.push(x);
        x *= b;
    }
    out
}

/// `α^n` by squaring.
fn pow(alpha: Fp2, mut n: usize) -> Fp2 {
    let (mut x, mut acc) = (alpha, Fp2::ONE);
    while n > 0 {
        if n & 1 == 1 {
            acc *= x;
        }
        x *= x;
        n >>= 1;
    }
    acc
}

const BETA: [Fp2; 2] = [
    Fp2::ONE,
    Fp2 {
        c0: Fp::ZERO,
        c1: Fp::ONE,
    },
];

/// Walk every row of the relation, handing `(row, chunk, pattern, weight)` to
/// `sink`; returns every row's public target `Y_r(α)`, zero where none.
// The loops index by the layout's own variables, each an index of a weight and
// a term of an offset formula at once.
#[allow(clippy::needless_range_loop)]
pub fn relation(p: &Public, sink: &mut impl FnMut(usize, usize, Pat, Fp2)) -> Vec<Fp2> {
    let l = p.level;
    let lay = p.layout;
    let delta = l.open_digits;
    let b = base_powers(l.log_b, delta.max(l.fold_digits));
    let src = base_powers(l.src_log, l.src_digits);
    let alpha = powers(p.alpha, l.d_a.max(l.family.dim) + 1);
    let a64 = |i: usize| pow(p.alpha, CHUNK * i);
    let wrap = |d: usize| pow(p.alpha, d) + Fp2::ONE;
    let at = |s: Seg, off: usize| (s.start + off) / CHUNK;
    let mut targets = vec![Fp2::ZERO; lay.rows(l)];
    let (s_op, s_a) = (l.d_op() / CHUNK, l.d_a / CHUNK);
    // ι(c_λ)(α) = c_λ(α^stride) (paper (114)).
    let chal: Vec<Fp2> = {
        let ladder = powers(pow(p.alpha, l.stride()), l.family.dim);
        p.challenges.iter().map(|c| c.eval(&ladder)).collect()
    };
    let mut row = 0;

    // Row 0: the fold row (paper (102)/(103), quotient-lifted (113)/(115)).
    match p.opening {
        Opening::Pack { r_pos, .. } => {
            // In the carrier E[Y]/(Y^dc + 1): Σ c_λ(α)·e_λ(α) − L(G·z)(α).
            let dc = l.family.dim;
            let carrier = powers(p.alpha, dc);
            let halves = dc / CHUNK;
            for (lam, c) in p.challenges.iter().enumerate() {
                let c = c.eval(&carrier);
                for (t, &bt) in BETA.iter().enumerate() {
                    for (u, &bu) in b[..delta].iter().enumerate() {
                        for h in 0..halves {
                            let y = t * halves + h;
                            let off = ((lam * s_op + y) * delta + u) * CHUNK;
                            sink(row, at(lay.e, off), Pat::Alpha, c * bt * bu * a64(h));
                        }
                    }
                }
            }
            let eq_pos = eq_table(r_pos);
            let shift = CHUNK / l.stride();
            for x in 0..l.m {
                for lc in 0..l.src_digits {
                    for u in 0..l.fold_digits {
                        let w = -(eq_pos[x] * (src[lc] * b[u]));
                        let base = (l.fold_digits * (l.src_digits * x + lc) + u) * l.d_a;
                        for i in 0..s_a {
                            sink(
                                row,
                                at(lay.z, base + i * CHUNK),
                                Pat::Pack,
                                w * pow(p.alpha, shift * i),
                            );
                        }
                    }
                }
            }
            // The carrier quotient's planes, in native 64-coefficient blocks.
            for (t, &bt) in BETA.iter().enumerate() {
                for h in 0..halves {
                    for u in 0..delta {
                        let off = ((t * halves + h) * delta + u) * CHUNK;
                        sink(
                            row,
                            at(lay.q_fold, off),
                            Pat::Alpha,
                            -(wrap(dc) * bt * b[u] * a64(h)),
                        );
                    }
                }
            }
        }
        Opening::Trace { rho_pos, .. } => {
            // In R_dA: Σ c_λ(α)·e_λ(α) − Σ_x a_x(α)·z_x(α).
            let eq_pos = eq_table(rho_pos);
            let (q1, q3) = (alpha[l.d_a / 4], alpha[3 * l.d_a / 4]);
            for (lam, &c) in chal.iter().enumerate() {
                for (u, &bu) in b[..delta].iter().enumerate() {
                    sink(
                        row,
                        at(lay.e, (lam * delta + u) * CHUNK),
                        Pat::Alpha,
                        c * bu,
                    );
                }
            }
            for x in 0..l.m {
                let ax = embed_eval(eq_pos[x], q1, q3);
                for u in 0..l.fold_digits {
                    sink(
                        row,
                        at(lay.z, (l.fold_digits * x + u) * CHUNK),
                        Pat::Alpha,
                        -(ax * b[u]),
                    );
                }
            }
            for u in 0..delta {
                sink(
                    row,
                    at(lay.q_fold, u * CHUNK),
                    Pat::Alpha,
                    -(wrap(l.d_a) * b[u]),
                );
            }
        }
    }
    row += 1;

    // Rows 1 ..= n_A: Σ ι(c_λ)·t_λ = A·z (paper (104), (114)).
    let m_a = l.m * l.src_digits;
    for a in 0..l.n_a {
        for (lam, &c) in chal.iter().enumerate() {
            for y in 0..s_a {
                for u in 0..delta {
                    let off = (((lam * l.n_a + a) * s_a + y) * delta + u) * CHUNK;
                    sink(row, at(lay.t, off), Pat::Alpha, c * b[u] * a64(y));
                }
            }
        }
        for xp in 0..m_a {
            let ae = eval(view(p.setup, m_a, l.d_a, a, xp), &alpha);
            for u in 0..l.fold_digits {
                let base = (l.fold_digits * xp + u) * l.d_a;
                for i in 0..s_a {
                    sink(
                        row,
                        at(lay.z, base + i * CHUNK),
                        Pat::Alpha,
                        -(ae * b[u] * a64(i)),
                    );
                }
            }
        }
        for i in 0..s_a {
            for u in 0..delta {
                let off = ((a * s_a + i) * delta + u) * CHUNK;
                sink(
                    row,
                    at(lay.q_inner, off),
                    Pat::Alpha,
                    -(wrap(l.d_a) * b[u] * a64(i)),
                );
            }
        }
        row += 1;
    }

    // Outer rows: every slice's B·t̂ equals its image (paper (105)).
    let width = slice_width(l);
    let per_block = l.n_a * s_a * delta;
    let b_eval: Vec<Fp2> = (0..l.n_b * width)
        .map(|rj| eval(view(p.setup, width, D_C, rj / width, rj % width), &alpha))
        .collect();
    for (sl, &(first, blocks)) in lay.slices.iter().enumerate() {
        for r in 0..l.n_b {
            for j in 0..blocks * per_block {
                let off = (first * per_block + j) * CHUNK;
                sink(row, at(lay.t, off), Pat::Alpha, b_eval[r * width + j]);
            }
            image(p, sl, r, row, &mut targets, sink);
            for u in 0..delta {
                let off = ((sl * l.n_b + r) * delta + u) * D_C;
                sink(row, at(lay.q_outer, off), Pat::Alpha, -(wrap(D_C) * b[u]));
            }
            row += 1;
        }
    }

    // Opening rows: D·ê equals the opening image (paper (106)).
    let d_width = open_width(l);
    for r in 0..l.n_d {
        for j in 0..d_width {
            let de = eval(view(p.setup, d_width, D_C, r, j), &alpha);
            sink(row, at(lay.e, j * CHUNK), Pat::Alpha, de);
        }
        image(p, lay.slices.len(), r, row, &mut targets, sink);
        for u in 0..delta {
            let off = (r * delta + u) * D_C;
            sink(row, at(lay.q_open, off), Pat::Alpha, -(wrap(D_C) * b[u]));
        }
        row += 1;
    }

    // Compression (paper (47)), per chain: F1·û₁ = G(û₂), then F2·û₂ = payload.
    if l.compress {
        let chains = lay.slices.len() + 1;
        for ch in 0..chains {
            let (first, rank) = lay.chain(l, ch);
            let m1 = rank * D_C * Q_BITS / D_F1;
            for j in 0..m1 {
                let fe = eval(view(p.setup, m1, D_F1, 0, j), &alpha);
                sink(row, at(lay.c1, first + j * D_F1), Pat::Half(j % 2), fe);
            }
            for i in 0..Q_BITS {
                let off = (ch * Q_BITS + i) * D_F1;
                sink(
                    row,
                    at(lay.c2, off),
                    Pat::Half(i % 2),
                    -Fp2::from(Fp::from_u64(1 << i)),
                );
            }
            for u in 0..delta {
                let k = ch * delta + u;
                sink(
                    row,
                    at(lay.q1, k * D_F1),
                    Pat::Half(k % 2),
                    -(wrap(D_F1) * b[u]),
                );
            }
            row += 1;
        }
        for ch in 0..chains {
            let m2 = D_F1 * Q_BITS / D_F2;
            for j in 0..m2 {
                let fe = eval(view(p.setup, m2, D_F2, 0, j), &alpha);
                let off = ch * D_F1 * Q_BITS + j * D_F2;
                sink(row, at(lay.c2, off), Pat::Quarter(j % 4), fe);
            }
            targets[row] = eval(&p.payloads[ch], &alpha);
            for u in 0..delta {
                let k = ch * delta + u;
                sink(
                    row,
                    at(lay.q2, k * D_F2),
                    Pat::Quarter(k % 4),
                    -(wrap(D_F2) * b[u]),
                );
            }
            row += 1;
        }
    }

    // The scalar row (paper (100), (101)).
    match p.opening {
        Opening::Pack { r_tail, claims, .. } => {
            let top = r_tail[6];
            let hi = [Fp2::ONE - top, top];
            for cl in claims {
                let eq_blk = eq_table(&cl.r_blk);
                for lb in 0..cl.blocks {
                    let lam = cl.first + lb;
                    for (t, &bt) in BETA.iter().enumerate() {
                        for (u, &bu) in b[..delta].iter().enumerate() {
                            for (h, &eh) in hi.iter().enumerate() {
                                let off = ((lam * s_op + 2 * t + h) * delta + u) * CHUNK;
                                let w = cl.weight * eq_blk[lb] * bt * bu * eh;
                                sink(row, at(lay.e, off), Pat::Tail, w);
                            }
                        }
                    }
                }
                targets[row] += cl.weight * cl.value;
            }
        }
        Opening::Trace {
            rho_blk,
            theta,
            value,
            ..
        } => {
            let eq_blk = eq_table(rho_blk);
            for lam in 0..l.blocks {
                for (u, &bu) in b[..delta].iter().enumerate() {
                    let off = (lam * delta + u) * CHUNK;
                    sink(row, at(lay.e, off), Pat::Trace, *theta * eq_blk[lam] * bu);
                }
            }
            targets[row] = *value;
        }
    }
    debug_assert_eq!(row + 1, lay.rows(l));
    targets
}

/// The image of chain `ch` (a slice, or the opening at `ch == slices`), its
/// row `r`: with compression the recomposition `G(û₁)` of its first binary
/// digits, a witness term (paper L.1: digit `i` of coefficient `v` at
/// `v + rank·64·i`); without, its raw payload, a target.
#[allow(clippy::needless_range_loop)]
fn image(
    p: &Public,
    ch: usize,
    r: usize,
    row: usize,
    targets: &mut [Fp2],
    sink: &mut impl FnMut(usize, usize, Pat, Fp2),
) {
    let (l, lay) = (p.level, p.layout);
    if l.compress {
        let (first, rank) = lay.chain(l, ch);
        for i in 0..Q_BITS {
            let chunk = (lay.c1.start + first + (r + rank * i) * D_C) / CHUNK;
            sink(row, chunk, Pat::Alpha, -Fp2::from(Fp::from_u64(1 << i)));
        }
    } else {
        let alpha = powers(p.alpha, D_C);
        targets[row] = eval(&p.payloads[ch][r * D_C..(r + 1) * D_C], &alpha);
    }
}

/// The Euclidean route's binding of the response-norm evaluation to the
/// response digits (paper (91)): `η_norm·b^a·eq(r_virt, u)` on digit `a` of
/// response coefficient `u = x·d_A + k`. Not a batched row: the fused sumcheck
/// adds it as is.
#[allow(clippy::needless_range_loop)]
pub fn norm_binding(
    l: &Level,
    lay: &Layout,
    eta: Fp2,
    r_virt: &[Fp2],
    sink: &mut impl FnMut(usize, Pat, Fp2),
) {
    debug_assert_eq!(l.d_a, CHUNK);
    let b = base_powers(l.log_b, l.fold_digits);
    let bits = l.m.trailing_zeros() as usize;
    let low = eq_table(&r_virt[6..6 + bits]);
    let rest: Fp2 = r_virt[6 + bits..]
        .iter()
        .fold(Fp2::ONE, |acc, &r| acc * (Fp2::ONE - r));
    for x in 0..l.m {
        for (a, &ba) in b.iter().enumerate() {
            let chunk = (lay.z.start + (l.fold_digits * x + a) * CHUNK) / CHUNK;
            sink(chunk, Pat::Virt, eta * low[x] * rest * ba);
        }
    }
}
