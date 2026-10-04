//! Groth16 over BN254, as the recursion tree's last proof takes it.
//!
//! A circuit is a function that writes rank-1 constraints into a [`Sink`], so
//! no matrix is ever held: [`setup`] runs it for the key and [`prove`] for a
//! witness. Three things are not the textbook's.
//!
//! - **Bound wires.** A circuit returns the wires its verifier must know the
//!   values of — here thousands, a public input apiece being an elliptic-curve
//!   multiplication a verifier cannot afford. They are committed instead: the
//!   proof carries `D = Σ w_j·[(β·A_j + α·B_j + C_j)/η]`, a fifth trapdoor `η`
//!   keeping it apart from the public inputs' `γ` and the witness's `δ` (the
//!   commit-carrying Groth16 of LegoSNARK), and one more pairing checks it.
//!   A challenge `c` is hashed from `D` and the verifier's own data, and the
//!   circuit ends by evaluating the bound wires' polynomial at `c`: the two
//!   public inputs are `c` and that value, which the verifier computes from
//!   its data in field operations. `D` is fixed before `c` is, so wires that
//!   differ from the data agree with it at `c` with probability `len/r`.
//! - **No blinding.** A proof hides nothing, so `r = s = 0` and it is a
//!   function of the witness.
//! - **The setup is not a ceremony.** [`setup`] derives its trapdoors from a
//!   seed, so whoever knows the seed can forge: a development key, to be
//!   replaced by a ceremony's before a proof it checks is worth anything.

use constants::{FR_TWO_ADICITY, FR_TWO_ADIC_ROOT_OF_UNITY};
use curve::pairing::pairing_check;
use curve::{G1Affine, G1Projective, G2Affine, G2Projective};
use field::{batch_inverse, Fr};
use rayon::prelude::*;

/// A wire.
pub type Var = u32;
/// The wire that is 1.
pub const ONE: Var = 0;
/// The two public inputs: the binding challenge, and the bound wires'
/// polynomial at it.
const CHALLENGE: Var = 1;
const VALUE: Var = 2;

/// `Σ k·wire`.
pub type Lc<'a> = &'a [(Var, Fr)];

/// What a circuit writes itself into.
pub trait Sink {
    /// A new wire, holding `value` in a witness.
    fn alloc(&mut self, value: Fr) -> Var;
    /// `a·b = c`.
    fn enforce(&mut self, a: Lc, b: Lc, c: Lc);
    /// A wire's value in a witness, 0 where there is none.
    fn value(&self, _: Var) -> Fr {
        Fr::ZERO
    }
}

/// A circuit: its constraints into the sink, and its bound wires, in the
/// order its verifier holds their values. The same wires, constraints and
/// order every run.
pub type Circuit<'a> = &'a mut dyn FnMut(&mut dyn Sink) -> Vec<Var>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    pub alpha: G1Affine,
    pub beta: G2Affine,
    pub gamma: G2Affine,
    pub delta: G2Affine,
    pub eta: G2Affine,
    /// The public wires' points: 1's, the challenge's, the value's.
    pub ic: [G1Affine; 3],
}

pub struct ProvingKey {
    pub vk: VerifyingKey,
    /// The circuit's constraints, and the domain's size: the power of two
    /// they fit.
    constraints: usize,
    n: usize,
    /// `[A_i(τ)]_1` a wire, and `[B_i(τ)]_2` for the wires that have one.
    a: Vec<G1Affine>,
    b: Vec<(Var, G2Affine)>,
    /// `[(β·A_i + α·B_i + C_i)/x]_1` a wire: `x` is `γ` for a public wire,
    /// `η` for a bound one and `δ` for the rest.
    l: Vec<G1Affine>,
    /// `[τ^k·Z(τ)/δ]_1`.
    h: Vec<G1Affine>,
    /// The bound wires, each once, ascending.
    bound: Vec<Var>,
}

impl ProvingKey {
    /// The circuit's constraints and its wires.
    pub fn size(&self) -> (usize, usize) {
        (self.constraints, self.a.len())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
    /// The bound wires' commitment.
    pub d: G1Affine,
}

// ---------------------------------------------------------------------------
// The three sinks
// ---------------------------------------------------------------------------

/// The public wires every sink starts with.
const PUBLIC: usize = 3;

struct Count {
    wires: u32,
    constraints: usize,
}

impl Sink for Count {
    fn alloc(&mut self, _: Fr) -> Var {
        self.wires += 1;
        self.wires - 1
    }
    fn enforce(&mut self, _: Lc, _: Lc, _: Lc) {
        self.constraints += 1;
    }
}

/// Each wire's `A_i`, `B_i` and `C_i` at `τ`: constraint `j` adds its
/// coefficients times the `j`th Lagrange polynomial there.
struct Accumulate<'a> {
    lagrange: &'a [Fr],
    at: usize,
    abc: [Vec<Fr>; 3],
}

impl Sink for Accumulate<'_> {
    fn alloc(&mut self, _: Fr) -> Var {
        for p in &mut self.abc {
            p.push(Fr::ZERO);
        }
        self.abc[0].len() as Var - 1
    }
    fn enforce(&mut self, a: Lc, b: Lc, c: Lc) {
        let l = self.lagrange[self.at];
        self.at += 1;
        for (p, lc) in self.abc.iter_mut().zip([a, b, c]) {
            for (v, k) in lc {
                p[*v as usize] += *k * l;
            }
        }
    }
}

/// A witness, and each constraint's three sides over it.
struct Witness {
    w: Vec<Fr>,
    abc: [Vec<Fr>; 3],
    /// The first constraint the witness does not satisfy.
    broken: Option<usize>,
}

impl Sink for Witness {
    fn alloc(&mut self, value: Fr) -> Var {
        self.w.push(value);
        self.w.len() as Var - 1
    }
    fn enforce(&mut self, a: Lc, b: Lc, c: Lc) {
        let side = |lc: Lc| {
            lc.iter()
                .fold(Fr::ZERO, |s, (v, k)| s + *k * self.w[*v as usize])
        };
        let (a, b, c) = (side(a), side(b), side(c));
        if a * b != c {
            self.broken.get_or_insert(self.abc[0].len());
        }
        for (p, v) in self.abc.iter_mut().zip([a, b, c]) {
            p.push(v);
        }
    }
    fn value(&self, v: Var) -> Fr {
        self.w[v as usize]
    }
}

/// The circuit's end: `acc ← (acc + wire)·c` over the bound wires from 0, the
/// last being the public value.
fn bind(sink: &mut dyn Sink, bound: &[Var]) {
    let c = sink.value(CHALLENGE);
    let mut acc: Option<(Var, Fr)> = None;
    for (k, wire) in bound.iter().enumerate() {
        let value = (acc.map_or(Fr::ZERO, |a| a.1) + sink.value(*wire)) * c;
        let next = if k + 1 == bound.len() {
            VALUE
        } else {
            sink.alloc(value)
        };
        let mut sum = vec![(*wire, Fr::ONE)];
        sum.extend(acc.map(|a| (a.0, Fr::ONE)));
        sink.enforce(&sum, &[(CHALLENGE, Fr::ONE)], &[(next, Fr::ONE)]);
        acc = Some((next, value));
    }
}

/// [`bind`]'s value over `data` at `c`, as a verifier computes it.
fn horner(data: &[Fr], c: Fr) -> Fr {
    data.iter().fold(Fr::ZERO, |acc, d| (acc + *d) * c)
}

/// 32 big-endian bytes, as a contract's word.
pub fn word(v: &[u8; 32]) -> [u8; 32] {
    let mut out = *v;
    out.reverse();
    out
}

/// The binding challenge: SHA-256 of `D`'s coordinates and the data, each a
/// 32-byte big-endian word, reduced.
fn challenge(d: &G1Affine, data: &[Fr]) -> Fr {
    let point = d.to_bytes();
    let mut bytes = Vec::with_capacity(64 + 32 * data.len());
    for half in point.chunks_exact(32) {
        bytes.extend(word(half.try_into().expect("32 bytes")));
    }
    for v in data {
        bytes.extend(word(&v.to_bytes()));
    }
    let hash = test_support::sha256(&bytes);
    hash.chunks_exact(8).fold(Fr::ZERO, |acc, limb| {
        let limb = u64::from_be_bytes(limb.try_into().expect("8 bytes"));
        acc * Fr::from_u64(1 << 32) * Fr::from_u64(1 << 32) + Fr::from_u64(limb)
    })
}

// ---------------------------------------------------------------------------
// The groups
// ---------------------------------------------------------------------------

trait Group: Copy + Send + Sync {
    type Affine: Copy + Send + Sync;
    const IDENTITY: Self;
    const GENERATOR: Self;
    fn add(&self, other: &Self) -> Self;
    fn add_affine(&self, other: &Self::Affine) -> Self;
    fn double(&self) -> Self;
    fn normalize(points: &[Self]) -> Vec<Self::Affine>;
}

impl Group for G1Projective {
    type Affine = G1Affine;
    const IDENTITY: Self = G1Projective::IDENTITY;
    const GENERATOR: Self = G1Projective::GENERATOR;
    fn add(&self, other: &Self) -> Self {
        G1Projective::add(self, other)
    }
    fn add_affine(&self, other: &G1Affine) -> Self {
        G1Projective::add_affine(self, other)
    }
    fn double(&self) -> Self {
        G1Projective::double(self)
    }
    fn normalize(points: &[Self]) -> Vec<G1Affine> {
        points
            .par_chunks(1 << 12)
            .flat_map_iter(G1Projective::batch_to_affine)
            .collect()
    }
}

impl Group for G2Projective {
    type Affine = G2Affine;
    const IDENTITY: Self = G2Projective::IDENTITY;
    const GENERATOR: Self = G2Projective::GENERATOR;
    fn add(&self, other: &Self) -> Self {
        G2Projective::add(self, other)
    }
    fn add_affine(&self, other: &G2Affine) -> Self {
        G2Projective::add_affine(self, other)
    }
    fn double(&self) -> Self {
        G2Projective::double(self)
    }
    fn normalize(points: &[Self]) -> Vec<G2Affine> {
        points.par_iter().map(|p| p.to_affine()).collect()
    }
}

/// A scalar's bits `[at, at + width)`, `width` at most 16.
fn digit(scalar: &[u8; 32], at: usize, width: usize) -> usize {
    let byte = |i: usize| scalar.get(i).copied().unwrap_or(0) as usize;
    let word = byte(at / 8) | byte(at / 8 + 1) << 8 | byte(at / 8 + 2) << 16;
    (word >> (at % 8)) & ((1 << width) - 1)
}

/// The generator's multiples `d·2^(16w)·G`, for a scalar multiplication of
/// it in sixteen additions: a key is tens of millions of them.
struct Table<G: Group>(Vec<G::Affine>);

impl<G: Group> Table<G> {
    fn new() -> Table<G> {
        let mut bases = vec![G::GENERATOR];
        for w in 1..16 {
            let mut next = bases[w - 1];
            for _ in 0..16 {
                next = next.double();
            }
            bases.push(next);
        }
        let rows: Vec<G> = bases
            .par_iter()
            .flat_map_iter(|base| {
                let mut acc = G::IDENTITY;
                (0..1usize << 16).map(move |_| {
                    let out = acc;
                    acc = acc.add(base);
                    out
                })
            })
            .collect();
        Table(G::normalize(&rows))
    }

    fn mul(&self, scalar: &Fr) -> G {
        let bytes = scalar.to_bytes();
        (0..16).fold(G::IDENTITY, |acc, w| match digit(&bytes, 16 * w, 16) {
            0 => acc,
            d => acc.add_affine(&self.0[w << 16 | d]),
        })
    }

    fn mul_all(&self, scalars: &[Fr]) -> Vec<G::Affine> {
        scalars
            .par_chunks(1 << 12)
            .flat_map_iter(|chunk| {
                let points: Vec<G> = chunk.iter().map(|s| self.mul(s)).collect();
                G::normalize(&points)
            })
            .collect()
    }
}

/// `Σ scalars_i·bases_i` by buckets, a window a task: G2's, `curve::msm` being
/// G1's.
fn msm<G: Group>(bases: &[G::Affine], scalars: &[Fr]) -> G {
    const WIDTH: usize = 13;
    let scalars: Vec<[u8; 32]> = scalars.par_iter().map(|s| s.to_bytes()).collect();
    let windows: Vec<G> = (0..254usize.div_ceil(WIDTH))
        .into_par_iter()
        .map(|w| {
            // On the heap: G2's are a megabyte and a half, a task's stack less.
            #[allow(clippy::useless_vec)]
            let mut buckets = vec![G::IDENTITY; (1 << WIDTH) - 1];
            for (base, scalar) in bases.iter().zip(&scalars) {
                let d = digit(scalar, WIDTH * w, WIDTH);
                if d != 0 {
                    buckets[d - 1] = buckets[d - 1].add_affine(base);
                }
            }
            let (mut running, mut sum) = (G::IDENTITY, G::IDENTITY);
            for bucket in buckets.iter().rev() {
                running = running.add(bucket);
                sum = sum.add(&running);
            }
            sum
        })
        .collect();
    windows.iter().rev().fold(G::IDENTITY, |mut acc, window| {
        for _ in 0..WIDTH {
            acc = acc.double();
        }
        acc.add(window)
    })
}

fn msm_g1(bases: &[G1Affine], scalars: &[Fr]) -> G1Projective {
    curve::msm::msm(bases, scalars).expect("a scalar a base")
}

// ---------------------------------------------------------------------------
// The domain
// ---------------------------------------------------------------------------

/// The domain's generator: a root of unity of order `n`, a power of two.
fn root(n: usize) -> Fr {
    let k = n.trailing_zeros();
    assert!(
        n.is_power_of_two() && k <= FR_TWO_ADICITY,
        "groth16: a domain of {n}"
    );
    let mut omega = Fr::from_hex(FR_TWO_ADIC_ROOT_OF_UNITY).expect("a canonical literal");
    for _ in k..FR_TWO_ADICITY {
        omega = omega.square();
    }
    omega
}

fn inverse(x: Fr) -> Fr {
    x.inverse().expect("groth16: an inverse of zero")
}

/// `x^(2^k)`.
fn pow2(x: Fr, k: u32) -> Fr {
    (0..k).fold(x, |x, _| x.square())
}

/// In place, `a[k] ← a(omega^k)`, `omega` of order `a.len()`.
fn fft(a: &mut [Fr], omega: Fr) {
    let n = a.len();
    let bits = n.trailing_zeros();
    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS - bits);
        if i < j {
            a.swap(i, j);
        }
    }
    let mut twiddles = Vec::with_capacity(n / 2);
    let mut power = Fr::ONE;
    for _ in 0..n / 2 {
        twiddles.push(power);
        power *= omega;
    }
    let butterfly = |lo: &mut Fr, hi: &mut Fr, twiddle: Fr| {
        let t = *hi * twiddle;
        *hi = *lo - t;
        *lo += t;
    };
    let mut half = 1;
    while half < n {
        let stride = n / (2 * half);
        // Many chunks, each one a task; few, each one's butterflies split.
        if stride >= 64 {
            a.par_chunks_mut(2 * half).for_each(|chunk| {
                let (lo, hi) = chunk.split_at_mut(half);
                for k in 0..half {
                    butterfly(&mut lo[k], &mut hi[k], twiddles[k * stride]);
                }
            });
        } else {
            for chunk in a.chunks_mut(2 * half) {
                let (lo, hi) = chunk.split_at_mut(half);
                lo.par_iter_mut()
                    .zip(hi)
                    .enumerate()
                    .for_each(|(k, (lo, hi))| butterfly(lo, hi, twiddles[k * stride]));
            }
        }
        half *= 2;
    }
}

/// `a[i] ← a[i]·k·g^i`.
fn scale(a: &mut [Fr], k: Fr, g: Fr) {
    const CHUNK: usize = 1 << 12;
    let step = pow2(g, CHUNK.trailing_zeros());
    let mut starts = Vec::with_capacity(a.len() / CHUNK + 1);
    let mut power = k;
    for _ in 0..a.len().div_ceil(CHUNK) {
        starts.push(power);
        power *= step;
    }
    a.par_chunks_mut(CHUNK)
        .zip(starts)
        .for_each(|(chunk, mut power)| {
            for x in chunk {
                *x *= power;
                power *= g;
            }
        });
}

/// The coset's shift: 5 generates `Fr*`, so `5·H` misses the domain `H`.
const SHIFT: u64 = 5;

/// `H = (A·B − C)/Z`'s coefficients, from the three sides over the domain:
/// each side's coefficients, then its values on the coset `5·H`, where `Z`
/// is the constant `5^n − 1`.
fn quotient(abc: [Vec<Fr>; 3], n: usize) -> Vec<Fr> {
    let omega = root(n);
    let (omega_inv, n_inv) = (inverse(omega), inverse(Fr::from_u64(n as u64)));
    let shift = Fr::from_u64(SHIFT);
    let [a, b, c] = abc.map(|mut side| {
        side.resize(n, Fr::ZERO);
        fft(&mut side, omega_inv);
        scale(&mut side, n_inv, shift);
        fft(&mut side, omega);
        side
    });
    let z_inv = inverse(pow2(shift, n.trailing_zeros()) - Fr::ONE);
    let mut h = a;
    h.par_iter_mut()
        .zip(&b)
        .zip(&c)
        .for_each(|((h, b), c)| *h = (*h * *b - *c) * z_inv);
    fft(&mut h, omega_inv);
    scale(&mut h, n_inv, inverse(shift));
    h
}

// ---------------------------------------------------------------------------
// Setup, prove, verify
// ---------------------------------------------------------------------------

/// The trapdoors `τ, α, β, γ, δ, η` a seed gives: **known to whoever knows
/// the seed**.
fn trapdoors(seed: &[u8]) -> [Fr; 6] {
    core::array::from_fn(|i| {
        let mut bytes = test_support::sha256(&[seed, &[i as u8]].concat());
        bytes[31] &= 0x1f;
        Fr::from_bytes(&bytes).expect("below 2^253")
    })
}

/// The key of `circuit`, its trapdoors derived from `seed`.
pub fn setup(circuit: Circuit, seed: &[u8]) -> ProvingKey {
    let mut count = Count {
        wires: PUBLIC as u32,
        constraints: 0,
    };
    let bound = circuit(&mut count);
    assert!(!bound.is_empty(), "groth16: a circuit binds a wire");
    bind(&mut count, &bound);
    let n = count.constraints.next_power_of_two().max(2);
    let [tau, alpha, beta, gamma, delta, eta] = trapdoors(seed);

    // The Lagrange polynomials at τ: `ω^j·(τ^n − 1)/(n·(τ − ω^j))`.
    let omega = root(n);
    let z = pow2(tau, n.trailing_zeros()) - Fr::ONE;
    let mut powers = Vec::with_capacity(n);
    let mut power = Fr::ONE;
    for _ in 0..n {
        powers.push(power);
        power *= omega;
    }
    let mut lagrange: Vec<Fr> = powers.par_iter().map(|w| tau - *w).collect();
    batch_inverse(&mut lagrange);
    let factor = z * inverse(Fr::from_u64(n as u64));
    lagrange
        .par_iter_mut()
        .zip(&powers)
        .for_each(|(l, w)| *l = *l * *w * factor);
    drop(powers);

    let mut sink = Accumulate {
        lagrange: &lagrange,
        at: 0,
        abc: core::array::from_fn(|_| vec![Fr::ZERO; PUBLIC]),
    };
    assert_eq!(
        circuit(&mut sink),
        bound,
        "groth16: a circuit is one circuit"
    );
    bind(&mut sink, &bound);
    assert_eq!(
        sink.at, count.constraints,
        "groth16: a circuit is one circuit"
    );
    let [a, b, c] = sink.abc;
    drop(lagrange);

    let mut bound = bound;
    bound.sort_unstable();
    bound.dedup();
    let mut divisor = vec![inverse(delta); a.len()];
    divisor[..PUBLIC].fill(inverse(gamma));
    for wire in &bound {
        divisor[*wire as usize] = inverse(eta);
    }
    let l: Vec<Fr> = (0..a.len())
        .into_par_iter()
        .map(|i| (beta * a[i] + alpha * b[i] + c[i]) * divisor[i])
        .collect();
    let mut h = Vec::with_capacity(n - 1);
    let mut power = z * inverse(delta);
    for _ in 0..n - 1 {
        h.push(power);
        power *= tau;
    }

    let g1 = Table::<G1Projective>::new();
    let g2 = Table::<G2Projective>::new();
    let l = g1.mul_all(&l);
    let in_b: Vec<Var> = (0..b.len() as Var)
        .filter(|i| b[*i as usize] != Fr::ZERO)
        .collect();
    let b: Vec<Fr> = in_b.iter().map(|i| b[*i as usize]).collect();
    let [beta, gamma, delta, eta] = [beta, gamma, delta, eta].map(|x| g2.mul(&x).to_affine());
    ProvingKey {
        vk: VerifyingKey {
            alpha: g1.mul(&alpha).to_affine(),
            beta,
            gamma,
            delta,
            eta,
            ic: [l[0], l[1], l[2]],
        },
        constraints: count.constraints,
        n,
        a: g1.mul_all(&a),
        b: in_b.into_iter().zip(g2.mul_all(&b)).collect(),
        l,
        h: g1.mul_all(&h),
        bound,
    }
}

/// A proof that `circuit` is satisfied, and its bound wires' values: what
/// [`verify`] takes as `data`. An unsatisfied constraint is an error naming
/// it.
pub fn prove(pk: &ProvingKey, circuit: Circuit) -> Result<(Proof, Vec<Fr>), String> {
    let mut s = Witness {
        w: vec![Fr::ONE, Fr::ZERO, Fr::ZERO],
        abc: core::array::from_fn(|_| Vec::with_capacity(pk.n)),
        broken: None,
    };
    let order = circuit(&mut s);
    let mut bound = order.clone();
    bound.sort_unstable();
    bound.dedup();
    if bound != pk.bound {
        return Err("the circuit is not the key's: its bound wires differ".into());
    }
    let data: Vec<Fr> = order.iter().map(|v| s.w[*v as usize]).collect();
    let pick =
        |from: &[G1Affine]| -> Vec<G1Affine> { bound.iter().map(|v| from[*v as usize]).collect() };
    let values: Vec<Fr> = bound.iter().map(|v| s.w[*v as usize]).collect();
    let d = msm_g1(&pick(&pk.l), &values).to_affine();
    s.w[CHALLENGE as usize] = challenge(&d, &data);
    s.w[VALUE as usize] = horner(&data, s.w[CHALLENGE as usize]);
    bind(&mut s, &order);
    if let Some(j) = s.broken {
        return Err(format!("constraint {j} is not satisfied"));
    }
    if s.w.len() != pk.a.len() || s.abc[0].len() > pk.n {
        return Err("the circuit is not the key's: its size differs".into());
    }

    let h = quotient(s.abc, pk.n);
    let a = G1Projective::from(pk.vk.alpha).add(&msm_g1(&pk.a, &s.w));
    let (bases, scalars): (Vec<G2Affine>, Vec<Fr>) =
        pk.b.iter()
            .map(|(v, base)| (*base, s.w[*v as usize]))
            .unzip();
    let b = G2Projective::from(pk.vk.beta).add(&msm::<G2Projective>(&bases, &scalars));
    // The witness's part: the public wires are the verifier's and the bound
    // ones are `D`.
    let mut private = s.w;
    private[..PUBLIC].fill(Fr::ZERO);
    for v in &bound {
        private[*v as usize] = Fr::ZERO;
    }
    let c = msm_g1(&pk.l, &private).add(&msm_g1(&pk.h, &h[..pk.n - 1]));
    let proof = Proof {
        a: a.to_affine(),
        b: b.to_affine(),
        c: c.to_affine(),
        d,
    };
    Ok((proof, data))
}

/// The two public inputs `data` and a proof's `D` give: the challenge, and
/// the data's polynomial at it.
pub fn public_inputs(proof: &Proof, data: &[Fr]) -> [Fr; 2] {
    let c = challenge(&proof.d, data);
    [c, horner(data, c)]
}

/// Whether `proof` proves the key's circuit satisfied with its bound wires
/// holding `data`:
/// `e(A, B) = e(α, β)·e(IC, γ)·e(C, δ)·e(D, η)`.
pub fn verify(vk: &VerifyingKey, proof: &Proof, data: &[Fr]) -> bool {
    let [c, v] = public_inputs(proof, data);
    let ic = G1Projective::from(vk.ic[0])
        .add(&G1Projective::from(vk.ic[1]).mul(&c))
        .add(&G1Projective::from(vk.ic[2]).mul(&v))
        .to_affine();
    pairing_check(&[
        (-proof.a, proof.b),
        (vk.alpha, vk.beta),
        (ic, vk.gamma),
        (proof.c, vk.delta),
        (proof.d, vk.eta),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `x³ + x + 5 = y` with `x` and `y` bound, `y` twice: proved, verified
    /// against the bound values, and refused against any other, with a wrong
    /// witness refused before a proof is made.
    #[test]
    fn a_small_circuit_proves_and_binds() {
        let circuit = |x: u64| {
            move |s: &mut dyn Sink| {
                let f = Fr::from_u64;
                let [x, x2, x3, y] =
                    [x, x * x, x * x * x, x * x * x + x + 5].map(|v| s.alloc(f(v)));
                let one = Fr::ONE;
                s.enforce(&[(x, one)], &[(x, one)], &[(x2, one)]);
                s.enforce(&[(x2, one)], &[(x, one)], &[(x3, one)]);
                s.enforce(
                    &[(x3, one), (x, one), (ONE, f(5))],
                    &[(ONE, one)],
                    &[(y, one)],
                );
                vec![y, x, y]
            }
        };
        let pk = setup(&mut circuit(3), b"test");
        let (proof, data) = prove(&pk, &mut circuit(3)).expect("it proves");
        assert_eq!(data, [35, 3, 35].map(Fr::from_u64));
        assert!(verify(&pk.vk, &proof, &data));
        assert!(!verify(&pk.vk, &proof, &[35, 4, 35].map(Fr::from_u64)));
        let (other, data) = prove(&pk, &mut circuit(4)).expect("it proves");
        assert!(verify(&pk.vk, &other, &data) && !verify(&pk.vk, &proof, &data));
        let mut broken = |s: &mut dyn Sink| {
            let x = s.alloc(Fr::from_u64(3));
            let rest = [9, 27, 36].map(|v| s.alloc(Fr::from_u64(v)));
            let one = Fr::ONE;
            s.enforce(&[(x, one)], &[(x, one)], &[(rest[0], one)]);
            s.enforce(&[(rest[0], one)], &[(x, one)], &[(rest[1], one)]);
            let sum = [(rest[1], one), (x, one), (ONE, Fr::from_u64(5))];
            s.enforce(&sum, &[(ONE, one)], &[(rest[2], one)]);
            vec![rest[2], x, rest[2]]
        };
        assert_eq!(
            prove(&pk, &mut broken).err(),
            Some("constraint 2 is not satisfied".into())
        );
    }
}
