//! v1.2's signer in `f64`: the secret key expanded, its Falcon tree,
//! ffSampling and SamplerZ.

use std::f64::consts::{LN_2, PI};

use num_complex::Complex64 as C;
use rand::Rng;

use crate::{
    bits, center, compress, encode_public_key, hash_to_point, mul, read, N, Q, SALT_BYTES,
    SECRET_KEY_BYTES, SQBETA,
};

/// Falcon-512's `σ`, which the tree's leaves are normalized to, and SamplerZ's
/// `σ_min` and `σ_max`.
const SIGMA: f64 = 165.7366171829776;
const SIGMA_MIN: f64 = 1.2778336969128337;
const SIGMA_MAX: f64 = 1.8205;

/// BaseSampler's reverse cumulative distribution table (Table 3.1), scaled by
/// `2^72`, but for its last entry, zero.
#[rustfmt::skip]
const RCDT: [u128; 18] = [
    3024686241123004913666, 1564742784480091954050, 636254429462080897535, 199560484645026482916,
    47667343854657281903, 8595902006365044063, 1163297957344668388, 117656387352093658,
    8867391802663976, 496969357462633, 20680885154299, 638331848991,
    14602316184, 247426747, 3104126, 28824, 198, 1,
];

/// ApproxExp's polynomial (Algorithm 13).
#[rustfmt::skip]
const EXP: [u64; 13] = [
    0x00000004741183A3, 0x00000036548CFC06, 0x0000024FDCBF140A, 0x0000171D939DE045,
    0x0000D00CF58F6F84, 0x000680681CF796E3, 0x002D82D8305B0FEA, 0x011111110E066FD0,
    0x0555555555070F00, 0x155555555581FF00, 0x400000000002B400, 0x7FFFFFFFFFFF4800,
    0x8000000000000000,
];

/// A primitive 1024th root of unity mod `q`: its odd powers are the roots of
/// `x^512 + 1`.
const PSI: i64 = 49;
const _: () = assert!(pow(PSI, N as i64) == Q - 1);

/// A signature of `msg` under `sk`: v1.2's Sign (Algorithm 10), with a fresh
/// random salt and `c` from [`hash_to_point`] of the public key `sk` implies,
/// the salt and `msg`.
///
/// Panics unless `sk` is a secret key: [`SECRET_KEY_BYTES`] bytes, the header
/// `0x59`, no coefficient `−2^(bits−1)`, `f` invertible mod `q`, and
/// `fG − gF = q` for the `G` recomputed.
pub fn sign(sk: &[u8], msg: &[u8]) -> Vec<u8> {
    let (basis, pk) = expand(sk).expect("sk is a secret key");
    let mut rng = rand::rng();
    let mut salt = [0; SALT_BYTES];
    rng.fill_bytes(&mut salt);
    let c = hash_to_point(&pk, &salt, msg).map(i64::from);
    let [f, g, big_f, big_g] = basis.map(|p| fft(&p));
    // The tree of B = [[g, −f], [G, −F]]'s Gram matrix, and t = (c, 0)·B⁻¹.
    let gram =
        |a: &[C], b: &[C], x: &[C], y: &[C]| each(N, |i| a[i] * b[i].conj() + x[i] * y[i].conj());
    let tree = ffldl(
        &gram(&g, &g, &f, &f),
        &gram(&g, &big_g, &f, &big_f),
        &gram(&big_g, &big_g, &big_f, &big_f),
    );
    let c_fft = fft(&c);
    let t0 = each(N, |i| -c_fft[i] * big_f[i] / Q as f64);
    let t1 = each(N, |i| c_fft[i] * f[i] / Q as f64);
    loop {
        let (z0, z1) = ff_sampling(&t0, &t1, &tree, &mut || rng.next_u32() as u8);
        // s = (c, 0) − zB, exactly: s1 = c − (z0·g + z1·G), s2 = z0·f + z1·F.
        let combine = |a: &[C], b: &[C]| ifft(&each(N, |i| z0[i] * a[i] + z1[i] * b[i]));
        let s1 = c.iter().zip(combine(&g, &big_g)).map(|(&c, v)| c - v);
        let s2 = combine(&f, &big_f);
        if s1.chain(s2.iter().copied()).map(|x| x * x).sum::<i64>() <= SQBETA {
            if let Some(compressed) = compress(&s2) {
                return [&[0x39], &salt[..], &compressed].concat();
            }
        }
    }
}

/// `[f, g, F, G]` and the public key's bytes from a secret key's bytes: `f`,
/// `g` and `F` decoded, `G = gF/f mod q`, centered, and `h = g/f mod q`;
/// `None` unless they are a secret key, as [`sign`] says.
pub(crate) fn expand(sk: &[u8]) -> Option<([Vec<i64>; 4], Vec<u8>)> {
    let (Some(0x59), SECRET_KEY_BYTES) = (sk.first(), sk.len()) else {
        return None;
    };
    let mut bits = bits(&sk[1..]);
    let mut decode = |width: u32| {
        let half = 1 << (width - 1);
        let x = (0..N).map(|_| read(&mut bits, width).filter(|&x| x != half));
        x.map(|x| x.map(|x| if x > half { x - 2 * half } else { x }))
            .collect::<Option<Vec<_>>>()
    };
    let (f, g, big_f) = (decode(6)?, decode(6)?, decode(8)?);
    let f_ntt = ntt(&f, false);
    if f_ntt.contains(&0) {
        return None;
    }
    let over_f = |a: &[i64]| {
        let a = ntt(a, false);
        ntt(&each(N, |i| a[i] * pow(f_ntt[i], Q - 2) % Q), true)
    };
    let big_g: Vec<i64> = over_f(&mul(&g, &big_f)).into_iter().map(center).collect();
    let (fg, gf) = (mul(&f, &big_g), mul(&g, &big_f));
    let ntru = (0..N).all(|i| fg[i] - gf[i] == if i == 0 { Q } else { 0 });
    let pk = encode_public_key(&over_f(&g));
    ntru.then_some(([f, g, big_f, big_g], pk))
}

/// `[f(0), …, f(n − 1)]`.
fn each<T>(n: usize, f: impl FnMut(usize) -> T) -> Vec<T> {
    (0..n).map(f).collect()
}

/// `x^e mod q`.
const fn pow(x: i64, e: i64) -> i64 {
    match e {
        0 => 1,
        _ => pow(x * x % Q, e / 2) * (if e % 2 == 1 { x } else { 1 }) % Q,
    }
}

/// `a`'s values mod `q` at the roots `ψ^(2k+1)` of `x^512 + 1`, `k < 512`, or,
/// `inverse`, the polynomial with the values `a`: coefficient `i` is
/// `Σ_k a_k ψ^(−(2k+1)i) / n`.
fn ntt(a: &[i64], inverse: bool) -> Vec<i64> {
    let psi = pow(PSI, if inverse { 2 * N as i64 - 1 } else { 1 });
    let powers = each(2 * N, |e| pow(psi, e as i64));
    let scale = pow(N as i64, if inverse { Q - 2 } else { 0 });
    each(N, |j| {
        // Output j and input m as the root k and the coefficient i.
        let ki = |m: usize| if inverse { (m, j) } else { (j, m) };
        let power = |(k, i): (usize, usize)| powers[(2 * k + 1) * i % (2 * N)];
        let sum: i64 = (0..N).map(|m| a[m].rem_euclid(Q) * power(ki(m))).sum();
        sum % Q * scale % Q
    })
}

/// The arguments of the roots of `x^n + 1` in the FFT's order: root `2i + 1`
/// is minus root `2i`, whose square is root `i` of `x^(n/2) + 1`.
fn angles(n: usize) -> Vec<f64> {
    if n == 1 {
        return vec![PI];
    }
    let halves = angles(n / 2).into_iter();
    halves.flat_map(|a| [a / 2.0, a / 2.0 + PI]).collect()
}

/// mergefft (Algorithm 2): the FFT of `f0(x²) + x·f1(x²)`.
fn merge(f0: &[C], f1: &[C]) -> Vec<C> {
    let roots = angles(f0.len()).into_iter().map(|a| C::cis(a / 2.0));
    let pairs = roots.zip(f0.iter().zip(f1));
    pairs
        .flat_map(|(w, (&a, &b))| [a + w * b, a - w * b])
        .collect()
}

/// splitfft (Algorithm 1), [`merge`]'s inverse.
fn split(f: &[C]) -> (Vec<C>, Vec<C>) {
    let roots = angles(f.len() / 2).into_iter().map(|a| C::cis(-a / 2.0));
    let half = |(w, p): (C, &[C])| ((p[0] + p[1]) / 2.0, (p[0] - p[1]) * w / 2.0);
    roots.zip(f.chunks(2)).map(half).unzip()
}

/// The FFT: the polynomial's values at the roots.
fn fft(f: &[i64]) -> Vec<C> {
    if f.len() == 1 {
        return vec![C::from(f[0] as f64)];
    }
    let (even, odd): (Vec<i64>, Vec<i64>) = f.chunks(2).map(|p| (p[0], p[1])).unzip();
    merge(&fft(&even), &fft(&odd))
}

/// The inverse FFT, the coefficients rounded to integers.
fn ifft(f: &[C]) -> Vec<i64> {
    if f.len() == 1 {
        return vec![f[0].re.round() as i64];
    }
    let (f0, f1) = split(f);
    let pairs = ifft(&f0).into_iter().zip(ifft(&f1));
    pairs.flat_map(|(a, b)| [a, b]).collect()
}

/// A Falcon tree: `L10` of an LDL* decomposition and the trees of `D00` and
/// `D11`, down to degree one, where the matrix is `D` times the identity and
/// the leaf holds `σ' = σ/√D` for both coordinates.
enum Tree {
    Node(Vec<C>, Box<Tree>, Box<Tree>),
    Leaf(f64),
}

/// ffLDL* (Algorithm 9) of the self-adjoint `[[g00, g01], [g01*, g11]]`, the
/// leaves normalized (Algorithm 4, steps 6 and 7).
fn ffldl(g00: &[C], g01: &[C], g11: &[C]) -> Tree {
    if g00.len() == 1 {
        return Tree::Leaf(SIGMA / g00[0].re.sqrt());
    }
    let l10 = each(g00.len(), |i| g01[i].conj() / g00[i]);
    let d11 = each(g00.len(), |i| g11[i] - l10[i] * l10[i].conj() * g00[i]);
    let ((d0, d1), (e0, e1)) = (split(g00), split(&d11));
    let (tree0, tree1) = (ffldl(&d0, &d1, &d0), ffldl(&e0, &e1, &e0));
    Tree::Node(l10, Box::new(tree0), Box::new(tree1))
}

/// ffSampling (Algorithm 11): `z` near `t = (t0, t1)`, by the tree.
fn ff_sampling(t0: &[C], t1: &[C], tree: &Tree, byte: &mut impl FnMut() -> u8) -> (Vec<C>, Vec<C>) {
    match tree {
        Tree::Leaf(sigma) => {
            let z0 = C::from(sampler_z(t0[0].re, *sigma, byte));
            (vec![z0], vec![C::from(sampler_z(t1[0].re, *sigma, byte))])
        }
        Tree::Node(l10, tree0, tree1) => {
            let (a, b) = split(t1);
            let (a, b) = ff_sampling(&a, &b, tree1, byte);
            let z1 = merge(&a, &b);
            let (a, b) = split(&each(t0.len(), |i| t0[i] + (t1[i] - z1[i]) * l10[i]));
            let (a, b) = ff_sampling(&a, &b, tree0, byte);
            (merge(&a, &b), z1)
        }
    }
}

/// SamplerZ (Algorithm 15): an integer from `D_{Z,μ,σ'}`, `σ'` in
/// `[σ_min, σ_max]`, drawing bytes as Table 3.2's vectors do.
fn sampler_z(mu: f64, sigma: f64, byte: &mut impl FnMut() -> u8) -> f64 {
    let s = mu.floor();
    loop {
        // BaseSampler (Algorithm 12), on 72 bits big-endian.
        let u = (0..9).fold(0u128, |u, _| u << 8 | byte() as u128);
        let z0 = RCDT.iter().filter(|&&x| u < x).count() as f64;
        let b = (byte() & 1) as f64;
        let z = b + (2.0 * b - 1.0) * z0;
        let x = (z - (mu - s)).powi(2) / (2.0 * sigma * sigma)
            - z0 * z0 / (2.0 * SIGMA_MAX * SIGMA_MAX);
        if ber_exp(x, SIGMA_MIN / sigma, byte) {
            return z + s;
        }
    }
}

/// BerExp (Algorithm 14): true with probability about `ccs·exp(−x)`.
fn ber_exp(x: f64, ccs: f64, byte: &mut impl FnMut() -> u8) -> bool {
    let s = (x / LN_2).floor();
    let z = ((2 * approx_exp(x - s * LN_2, ccs) as u128 - 1) >> (s as u32).min(63)) as u64;
    // A uniform 64-bit integer against `z`, a byte at a time from the top.
    let mut i = 64;
    loop {
        i -= 8;
        let w = byte() as i32 - (z >> i & 0xff) as i32;
        if w != 0 || i == 0 {
            return w < 0;
        }
    }
}

/// ApproxExp (Algorithm 13): about `2^63·ccs·exp(−x)`, `x` in `[0, ln 2]`.
fn approx_exp(x: f64, ccs: f64) -> u64 {
    let z = (x * 2f64.powi(63)) as u128;
    let step = |y, &c| c as u128 - ((z * y) >> 63);
    let y = EXP[1..].iter().fold(EXP[0] as u128, step);
    (((ccs * 2f64.powi(63)) as u128 * y) >> 63) as u64
}
