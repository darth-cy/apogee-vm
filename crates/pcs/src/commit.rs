//! Commitments (paper §4.5): inner images `t_λ = A·s_λ`, sliced outer images
//! `u_σ = B·t̂_σ` and their compression chains, and what an opener keeps of
//! them. `docs/spec/pcs.md` §3.

use field::Fp;
use pcs_verify::params::{Level, Method, D_C, D_F1, D_F2, Q_BITS, ROOT_DIGITS, ROOT_LOG};
use pcs_verify::relation::{slice_width, view};
use pcs_verify::ring::{digits, fp, full_digits, lift, trace_pack};
use pcs_verify::Commitment;
use poly::{MultilinearPoly, PolyBacking};
use rayon::prelude::*;

use crate::ntt::Crt;

/// What a commitment commits.
#[derive(Clone, Copy)]
pub enum Source<'a> {
    /// A root group: its columns, each of the same power-of-two length.
    Columns(&'a [&'a MultilinearPoly]),
    /// A recursive witness: its digits.
    Digits(&'a [i8]),
}

impl Source<'_> {
    /// Base-field entries.
    pub fn len(&self) -> usize {
        match self {
            Source::Columns(cs) => cs.len() * cs[0].len(),
            Source::Digits(w) => w.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The `d` entries of ring element `r`, as integers: a column entry is its
    /// canonical value, beyond the end zero.
    fn raw(&self, r: usize, d: usize) -> Vec<i128> {
        let mut out = vec![0i128; d];
        match self {
            Source::Columns(cs) => {
                let per = cs[0].len() / d;
                if r / per < cs.len() {
                    column_values(cs[r / per], (r % per) * d, &mut out);
                }
            }
            Source::Digits(w) => {
                for (o, &x) in out.iter_mut().zip(w.iter().skip(r * d)) {
                    *o = x as i128;
                }
            }
        }
        out
    }

    /// Ring element `r`'s coefficients under `l`'s packing: a column entry as
    /// itself, a witness's digits directly (packing) or trace-packed (§3.1).
    pub fn ring(&self, l: &Level, r: usize) -> Vec<i128> {
        let raw = self.raw(r, l.d_a);
        match (self, l.method) {
            (Source::Digits(_), Method::Trace) => {
                let w: Vec<i64> = raw.iter().map(|&x| x as i64).collect();
                trace_pack(&w).into_iter().map(|x| x as i128).collect()
            }
            _ => raw,
        }
    }

    /// The source digits of ring element `r` into `out` (paper §4.5,
    /// `s_i = G⁻¹(f_i)` or the identity), its zero planes marked.
    ///
    /// A root column's entries are read by backing: a bit or a byte is its own
    /// single digit, a 16- or 32-bit word splits by masks into two or three,
    /// and a field element is lifted and split by [`digits`]. An all-zero run
    /// of bits, 32-bit words or field elements is marked zero unsplit.
    pub fn digits_into(&self, l: &Level, r: usize, out: &mut Digits) {
        let d = l.d_a;
        out.live = 0;
        let Source::Columns(cs) = self else {
            assert_eq!(l.src_log, 0, "a witness is its own source digits");
            let ring = self.ring(l, r);
            for (o, &v) in out.coefs.iter_mut().zip(&ring) {
                *o = v as i64;
            }
            out.live = ring.iter().any(|&v| v != 0) as u32;
            return;
        };
        assert!(
            (l.src_log, l.src_digits) == (ROOT_LOG, ROOT_DIGITS),
            "a root column splits into the root's source digits"
        );
        let per = cs[0].len() / d;
        let Some(c) = cs.get(r / per) else {
            return;
        };
        let start = (r % per) * d;
        let (p0, rest) = out.coefs.split_at_mut(d);
        let (p1, rest) = rest.split_at_mut(d);
        let (p2, p3) = rest.split_at_mut(d);
        // [`digits`]' balanced digit of a word, `((v + 2^15) mod 2^16) − 2^15`.
        const HALF: i64 = 1 << (ROOT_LOG - 1);
        const MASK: i64 = (1 << ROOT_LOG) - 1;
        let low = |v: i64| ((v + HALF) & MASK) - HALF;
        let mut nonzero = [0i64; 4];
        match c.backing() {
            PolyBacking::U1(limbs, _) => {
                let limbs = &limbs[start / 64..(start + d) / 64];
                if limbs.iter().all(|&w| w == 0) {
                    return;
                }
                for (k, o) in p0.iter_mut().enumerate() {
                    *o = ((limbs[k / 64] >> (k % 64)) & 1) as i64;
                }
                nonzero[0] = 1;
            }
            PolyBacking::U8(v) => {
                for (o, &x) in p0.iter_mut().zip(&v[start..start + d]) {
                    *o = x as i64;
                    nonzero[0] |= *o;
                }
            }
            PolyBacking::U16(v) => {
                for (k, &x) in v[start..start + d].iter().enumerate() {
                    let x = x as i64;
                    let d0 = low(x);
                    p0[k] = d0;
                    p1[k] = (x - d0) >> ROOT_LOG;
                    nonzero[0] |= p0[k];
                    nonzero[1] |= p1[k];
                }
            }
            PolyBacking::U32(v) => {
                let v = &v[start..start + d];
                if v.iter().all(|&x| x == 0) {
                    return;
                }
                for (k, &x) in v.iter().enumerate() {
                    let x = x as i64;
                    let d0 = low(x);
                    let x1 = (x - d0) >> ROOT_LOG;
                    let d1 = low(x1);
                    p0[k] = d0;
                    p1[k] = d1;
                    // The carry out of the second digit: 0 or 1, as at 2^32 − 1.
                    p2[k] = (x1 - d1) >> ROOT_LOG;
                    nonzero[0] |= d0;
                    nonzero[1] |= d1;
                    nonzero[2] |= p2[k];
                }
            }
            PolyBacking::Fp(v) => {
                let v = &v[start..start + d];
                if v.iter().all(|&x| x == Fp::ZERO) {
                    return;
                }
                let mut ds = [0i32; ROOT_DIGITS];
                for (k, x) in v.iter().enumerate() {
                    digits(
                        lift(*x, ROOT_LOG, ROOT_DIGITS),
                        ROOT_LOG,
                        ROOT_DIGITS,
                        &mut ds,
                    );
                    let [d0, d1, d2, d3] = ds.map(i64::from);
                    (p0[k], p1[k], p2[k], p3[k]) = (d0, d1, d2, d3);
                    for (n, dv) in nonzero.iter_mut().zip([d0, d1, d2, d3]) {
                        *n |= dv;
                    }
                }
            }
            PolyBacking::Fp2(_) => panic!("a committed column is a base table"),
        }
        for (i, &n) in nonzero.iter().enumerate() {
            out.live |= ((n != 0) as u32) << i;
        }
    }

    /// Ring element `r`'s coefficients as field elements.
    pub fn values(&self, l: &Level, r: usize) -> Vec<Fp> {
        self.ring(l, r)
            .into_iter()
            .map(|x| {
                if x >= 0 {
                    Fp::from_u128(x as u128)
                } else {
                    fp(x as i64)
                }
            })
            .collect()
    }
}

/// One ring element's source digits: `src_digits` planes of `d_A`
/// coefficients, plane `i` at `[i·d_A, (i + 1)·d_A)`, and which of them are
/// nonzero. A plane whose bit is clear in `live` is zero, whatever `coefs`
/// holds there: the buffer is refilled for every ring element.
pub struct Digits {
    coefs: Vec<i64>,
    live: u32,
    d: usize,
}

impl Digits {
    pub fn new(l: &Level) -> Digits {
        Digits {
            coefs: vec![0; l.src_digits * l.d_a],
            live: 0,
            d: l.d_a,
        }
    }

    /// The nonzero planes and their indices.
    pub fn planes(&self) -> impl Iterator<Item = (usize, &[i64])> {
        self.coefs
            .chunks(self.d)
            .enumerate()
            .filter(|(i, _)| (self.live >> i) & 1 == 1)
    }
}

/// `out[k] = column[start + k]`, by backing, without a dispatch per entry.
fn column_values(c: &MultilinearPoly, start: usize, out: &mut [i128]) {
    let n = out.len();
    match c.backing() {
        PolyBacking::U1(limbs, _) => {
            for (k, o) in out.iter_mut().enumerate() {
                let i = start + k;
                *o = ((limbs[i / 64] >> (i % 64)) & 1) as i128;
            }
        }
        PolyBacking::U8(v) => out
            .iter_mut()
            .zip(&v[start..start + n])
            .for_each(|(o, &x)| *o = x as i128),
        PolyBacking::U16(v) => out
            .iter_mut()
            .zip(&v[start..start + n])
            .for_each(|(o, &x)| *o = x as i128),
        PolyBacking::U32(v) => out
            .iter_mut()
            .zip(&v[start..start + n])
            .for_each(|(o, &x)| *o = x as i128),
        PolyBacking::Fp(v) => out
            .iter_mut()
            .zip(&v[start..start + n])
            .for_each(|(o, x)| *o = x.to_u64() as i128),
        PolyBacking::Fp2(_) => panic!("a committed column is a base table"),
    }
}

/// What an opener keeps of one outer slice.
#[derive(Clone, Debug)]
pub struct Slice {
    /// The image `B·t̂_σ`, `n_B` rows of 64.
    pub image: Vec<Fp>,
    /// The outer rows' quotient: the high half of the unreduced `B·t̂_σ`.
    pub quotient: Vec<Fp>,
    /// With compression, the chain from the image to the payload.
    pub chain: Option<Chain>,
}

/// A compression chain (paper (47)): the image's negative-binary digits, the
/// first map's quotient, the first image's digits, the second's quotient.
#[derive(Clone, Debug)]
pub struct Chain {
    pub bits1: Vec<i8>,
    pub q1: Vec<Fp>,
    pub bits2: Vec<i8>,
    pub q2: Vec<Fp>,
    pub payload: Vec<Fp>,
}

/// A commitment and everything its opening needs beyond the source.
#[derive(Clone, Debug)]
pub struct Opener {
    pub commitment: Commitment,
    /// Per block, its inner image: `n_A` rows of `d_A`.
    pub inner: Vec<Vec<Fp>>,
    pub slices: Vec<Slice>,
}

/// `Σ_j M_{i,j}·x_j` for every row of an `n × m` view over `R_d`, `x` the
/// concatenated digit inputs (shorter is zero-padded): the reduced images and
/// the high halves of the unreduced products, both `n·d`.
pub fn outer_product(setup: &[Fp], n: usize, m: usize, d: usize, x: &[i8]) -> (Vec<Fp>, Vec<Fp>) {
    let rows: Vec<(Vec<Fp>, Vec<Fp>)> = (0..n)
        .into_par_iter()
        .map(|i| {
            let mut acc = vec![0i128; 2 * d];
            for (j, xs) in x.chunks(d).enumerate().take(m) {
                let a = view(setup, m, d, i, j);
                for (p, av) in a.iter().enumerate() {
                    let av = av.to_u64() as i128;
                    for (k, &xv) in xs.iter().enumerate() {
                        if xv != 0 {
                            acc[p + k] += av * xv as i128;
                        }
                    }
                }
            }
            let f = |v: i128| {
                if v >= 0 {
                    Fp::from_u128(v as u128)
                } else {
                    -Fp::from_u128((-v) as u128)
                }
            };
            let image = (0..d).map(|k| f(acc[k]) - f(acc[d + k])).collect();
            let high = (0..d).map(|k| f(acc[d + k])).collect();
            (image, high)
        })
        .collect();
    let mut image = Vec::with_capacity(n * d);
    let mut high = Vec::with_capacity(n * d);
    for (a, b) in rows {
        image.extend(a);
        high.extend(b);
    }
    (image, high)
}

/// `x = Σ_i 2^i ξ_i` with `ξ_i ∈ {−1, 0}`: the binary digits of `−x`, negated
/// (paper §4.5).
fn neg_binary(x: Fp) -> [i8; Q_BITS] {
    let y = (-x).to_u64();
    core::array::from_fn(|i| -(((y >> i) & 1) as i8))
}

/// The digits of `image`, digit `i` of coefficient `v` at `v + len·i` (paper L.1).
fn plane_bits(image: &[Fp]) -> Vec<i8> {
    let s = image.len();
    let mut out = vec![0i8; s * Q_BITS];
    for (v, &x) in image.iter().enumerate() {
        for (i, &b) in neg_binary(x).iter().enumerate() {
            out[v + s * i] = b;
        }
    }
    out
}

/// The two-stage compression of an image to its payload.
pub fn compress(setup: &[Fp], image: &[Fp]) -> Chain {
    let bits1 = plane_bits(image);
    let (y1, q1) = outer_product(setup, 1, bits1.len() / D_F1, D_F1, &bits1);
    let bits2 = plane_bits(&y1);
    let (payload, q2) = outer_product(setup, 1, bits2.len() / D_F2, D_F2, &bits2);
    Chain {
        bits1,
        q1,
        bits2,
        q2,
        payload,
    }
}

/// The balanced base-`2^log` digits of every coefficient of `x`, `k` each,
/// digit-major within each 64-coefficient native block (paper (346)):
/// `((y·k + u)·64 + c)` for coefficient `y·64 + c`.
pub fn full_field_digits(x: &[Fp], log: u32) -> Vec<i8> {
    let k = full_digits(log);
    let mut out = vec![0i8; x.len() * k];
    let mut ds = vec![0i32; k];
    for (i, &v) in x.iter().enumerate() {
        digits(lift(v, log, k), log, k, &mut ds);
        let (y, c) = (i / D_C, i % D_C);
        for (u, &d) in ds.iter().enumerate() {
            out[(y * k + u) * D_C + c] = d as i8;
        }
    }
    out
}

/// The inner images `t_λ = A·s_λ` of every block of `src` under `l`.
pub fn inner_images(setup: &[Fp], l: &Level, src: &Source, blocks: usize) -> Vec<Vec<Fp>> {
    let crt = Crt::new(l.d_a, true);
    let m_a = l.m * l.src_digits;
    let a: Vec<_> = (0..l.n_a * m_a)
        .into_par_iter()
        .map(|i| crt.of_field(view(setup, m_a, l.d_a, i / m_a, i % m_a)))
        .collect();
    (0..blocks)
        .into_par_iter()
        .map(|lam| {
            let mut acc: Vec<_> = (0..l.n_a).map(|_| crt.zero()).collect();
            let mut ds = Digits::new(l);
            for x in 0..l.m {
                src.digits_into(l, lam * l.m + x, &mut ds);
                for (lc, plane) in ds.planes() {
                    let s = crt.of_ints(plane);
                    for (ai, acc) in acc.iter_mut().enumerate() {
                        crt.mul_acc(acc, &a[ai * m_a + l.src_digits * x + lc], &s);
                    }
                }
            }
            acc.into_iter().flat_map(|s| crt.back(s)).collect()
        })
        .collect()
}

/// The inner-image digits of one block, `((a·s + y)·δ + u)·64 + k` (paper L.1).
pub fn image_digits(l: &Level, t: &[Fp]) -> Vec<i8> {
    full_field_digits(t, l.log_b)
}

/// Commit `src` under level `l`'s shape, its blocks cut into slices of
/// `l.slice_blocks`.
pub fn commit(setup: &[Fp], l: &Level, src: &Source) -> Opener {
    let blocks = src.len().div_ceil(l.block_len());
    let inner = inner_images(setup, l, src, blocks);
    let width = slice_width(l);
    let starts: Vec<usize> = (0..blocks).step_by(l.slice_blocks).collect();
    let slices: Vec<Slice> = starts
        .par_iter()
        .map(|&first| {
            let last = (first + l.slice_blocks).min(blocks);
            let x: Vec<i8> = (first..last)
                .flat_map(|lam| image_digits(l, &inner[lam]))
                .collect();
            let (image, quotient) = outer_product(setup, l.n_b, width, D_C, &x);
            let chain = l.compress.then(|| compress(setup, &image));
            Slice {
                image,
                quotient,
                chain,
            }
        })
        .collect();
    let payloads = slices
        .iter()
        .map(|s| {
            s.chain
                .as_ref()
                .map_or_else(|| s.image.clone(), |c| c.payload.clone())
        })
        .collect();
    Opener {
        commitment: Commitment(payloads),
        inner,
        slices,
    }
}
