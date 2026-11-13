//! Exact ring products by a CRT-NTT: `q ≡ 5 (mod 8)` has no deep roots of
//! unity, so products in `Z[X]/(X^d ± 1)` of a matrix entry (below `q`) and a
//! short vector are computed modulo two NTT primes and lifted back to the
//! integers, which are below `2^123` in magnitude for every product the
//! prover forms. `docs/spec/pcs.md` §8.

use field::Fp;

/// The NTT primes: `k·2^20 + 1` below `2^62`, both with 3 a non-residue.
const PRIMES: [u64; 2] = [0x3fff_ffff_feb0_0001, 0x3fff_ffff_fa00_0001];

/// Arithmetic modulo one prime, in Montgomery form with `R = 2^64`.
#[derive(Clone)]
struct Prime {
    p: u64,
    /// `−p⁻¹ mod 2^64`.
    neg_inv: u64,
    /// `R² mod p`.
    r2: u64,
}

impl Prime {
    fn new(p: u64) -> Prime {
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(p.wrapping_mul(inv)));
        }
        let r = ((1u128 << 64) % p as u128) as u64;
        let r2 = ((r as u128 * r as u128) % p as u128) as u64;
        Prime {
            p,
            neg_inv: inv.wrapping_neg(),
            r2,
        }
    }

    #[inline]
    fn mul(&self, a: u64, b: u64) -> u64 {
        let t = a as u128 * b as u128;
        let m = (t as u64).wrapping_mul(self.neg_inv);
        let u = ((t + m as u128 * self.p as u128) >> 64) as u64;
        if u >= self.p {
            u - self.p
        } else {
            u
        }
    }

    #[inline]
    fn add(&self, a: u64, b: u64) -> u64 {
        let s = a + b;
        if s >= self.p {
            s - self.p
        } else {
            s
        }
    }

    #[inline]
    fn sub(&self, a: u64, b: u64) -> u64 {
        if a >= b {
            a - b
        } else {
            a + self.p - b
        }
    }

    fn to_mont(&self, a: u64) -> u64 {
        self.mul(a % self.p, self.r2)
    }

    fn unmont(&self, a: u64) -> u64 {
        self.mul(a, 1)
    }

    fn signed(&self, x: i64) -> u64 {
        let v = x.rem_euclid(self.p as i64) as u64;
        self.to_mont(v)
    }

    fn pow(&self, base: u64, mut e: u64) -> u64 {
        let (mut b, mut acc) = (self.to_mont(base), self.to_mont(1));
        while e > 0 {
            if e & 1 == 1 {
                acc = self.mul(acc, b);
            }
            b = self.mul(b, b);
            e >>= 1;
        }
        acc
    }
}

/// One prime's transforms of size `n`.
#[derive(Clone)]
struct Plan {
    f: Prime,
    n: usize,
    /// `ω^i` for the bit-reversed butterflies, `ω` a primitive `n`-th root.
    roots: Vec<u64>,
    inv_roots: Vec<u64>,
    /// `ψ^i` and `ψ^{-i}·n⁻¹`, `ψ² = ω`: the negacyclic twist.
    twist: Vec<u64>,
    untwist: Vec<u64>,
    n_inv: u64,
}

impl Plan {
    fn new(p: u64, n: usize) -> Plan {
        let f = Prime::new(p);
        // A primitive 2n-th root ψ: 3 is a non-residue, so 3^((p−1)/2n) has order 2n.
        let psi = f.pow(3, (p - 1) / (2 * n as u64));
        let omega = f.mul(psi, psi);
        let inv = |x: u64| {
            let raw = f.unmont(x);
            f.pow(raw, p - 2)
        };
        let (psi_inv, omega_inv) = (inv(psi), inv(omega));
        let ladder = |g: u64| {
            let mut v = Vec::with_capacity(n);
            let mut x = f.to_mont(1);
            for _ in 0..n {
                v.push(x);
                x = f.mul(x, g);
            }
            v
        };
        let n_inv = inv(f.to_mont(n as u64));
        let untwist = ladder(psi_inv)
            .into_iter()
            .map(|x| f.mul(x, n_inv))
            .collect();
        Plan {
            roots: ladder(omega),
            inv_roots: ladder(omega_inv),
            twist: ladder(psi),
            untwist,
            n_inv,
            f,
            n,
        }
    }

    /// In-place cyclic transform (iterative Cooley–Tukey on bit-reversed input).
    fn transform(&self, a: &mut [u64], roots: &[u64]) {
        let n = self.n;
        let mut j = 0;
        for i in 1..n {
            let mut bit = n >> 1;
            while j & bit != 0 {
                j ^= bit;
                bit >>= 1;
            }
            j |= bit;
            if i < j {
                a.swap(i, j);
            }
        }
        let mut len = 2;
        while len <= n {
            let step = n / len;
            for start in (0..n).step_by(len) {
                for k in 0..len / 2 {
                    let w = roots[k * step];
                    let u = a[start + k];
                    let v = self.f.mul(a[start + k + len / 2], w);
                    a[start + k] = self.f.add(u, v);
                    a[start + k + len / 2] = self.f.sub(u, v);
                }
            }
            len <<= 1;
        }
    }

    fn forward(&self, a: &mut [u64], nega: bool) {
        if nega {
            for (x, &t) in a.iter_mut().zip(&self.twist) {
                *x = self.f.mul(*x, t);
            }
        }
        self.transform(a, &self.roots);
    }

    fn inverse(&self, a: &mut [u64], nega: bool) {
        self.transform(a, &self.inv_roots);
        if nega {
            for (x, &t) in a.iter_mut().zip(&self.untwist) {
                *x = self.f.mul(*x, t);
            }
        } else {
            for x in a.iter_mut() {
                *x = self.f.mul(*x, self.n_inv);
            }
        }
    }
}

/// Exact products in `Z[X]/(X^d + 1)` (negacyclic) or `Z[X]/(X^d − 1)`
/// (cyclic), reduced mod `q` at the end.
#[derive(Clone)]
pub struct Crt {
    plans: [Plan; 2],
    nega: bool,
    /// `p₁⁻¹ mod p₂`.
    p1_inv: u64,
}

/// A transformed ring element: its spectrum modulo each prime.
pub type Spectrum = [Vec<u64>; 2];

impl Crt {
    pub fn new(d: usize, nega: bool) -> Crt {
        let plans = PRIMES.map(|p| Plan::new(p, d));
        let p1_inv = {
            let f2 = &plans[1].f;
            f2.unmont(f2.pow(PRIMES[0] % PRIMES[1], PRIMES[1] - 2))
        };
        Crt {
            plans,
            nega,
            p1_inv,
        }
    }

    pub fn dim(&self) -> usize {
        self.plans[0].n
    }

    /// The spectrum of a field element vector, entries taken as integers in
    /// `[0, q)`.
    pub fn of_field(&self, a: &[Fp]) -> Spectrum {
        core::array::from_fn(|i| {
            let pl = &self.plans[i];
            let mut v: Vec<u64> = a.iter().map(|x| pl.f.to_mont(x.to_u64())).collect();
            pl.forward(&mut v, self.nega);
            v
        })
    }

    /// The spectrum of a short integer vector.
    pub fn of_ints(&self, a: &[i64]) -> Spectrum {
        core::array::from_fn(|i| {
            let pl = &self.plans[i];
            let mut v: Vec<u64> = a.iter().map(|&x| pl.f.signed(x)).collect();
            pl.forward(&mut v, self.nega);
            v
        })
    }

    pub fn zero(&self) -> Spectrum {
        core::array::from_fn(|_| vec![0; self.dim()])
    }

    /// `acc += a ⊙ b`.
    pub fn mul_acc(&self, acc: &mut Spectrum, a: &Spectrum, b: &Spectrum) {
        for i in 0..2 {
            let f = &self.plans[i].f;
            for ((o, &x), &y) in acc[i].iter_mut().zip(&a[i]).zip(&b[i]) {
                *o = f.add(*o, f.mul(x, y));
            }
        }
    }

    /// `acc += b`.
    pub fn add(&self, acc: &mut Spectrum, b: &Spectrum) {
        for (pl, (o, y)) in self.plans.iter().zip(acc.iter_mut().zip(b)) {
            o.iter_mut().zip(y).for_each(|(o, &y)| *o = pl.f.add(*o, y));
        }
    }

    /// Back to coefficients: the exact integers, centered, reduced mod `q`.
    pub fn back(&self, mut s: Spectrum) -> Vec<Fp> {
        for (pl, v) in self.plans.iter().zip(s.iter_mut()) {
            pl.inverse(v, self.nega);
        }
        let (p1, p2) = (PRIMES[0] as u128, PRIMES[1] as u128);
        let big = p1 * p2;
        let f2 = &self.plans[1].f;
        (0..self.dim())
            .map(|k| {
                let x1 = self.plans[0].f.unmont(s[0][k]);
                let x2 = f2.unmont(s[1][k]);
                let diff = ((x2 as u128 + p2 - (x1 as u128 % p2)) % p2) as u64;
                let h = diff as u128 * self.p1_inv as u128 % p2;
                let x = x1 as u128 + p1 * h;
                if x > big / 2 {
                    -Fp::from_u128(big - x)
                } else {
                    Fp::from_u128(x)
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcs_verify::ring::{fp, mul};

    /// The CRT-NTT's negacyclic product is the ring product, and its cyclic
    /// product of zero-padded inputs the full one, at every size the prover uses.
    #[test]
    fn products_match_schoolbook() {
        let mut rng = test_support::Rng::new(7);
        for d in [16, 64, 256, 2048] {
            let a: Vec<Fp> = (0..d).map(|_| Fp::from_u64(rng.next_u64())).collect();
            let b: Vec<i64> = (0..d)
                .map(|_| (rng.next_u64() % (1 << 16)) as i64 - (1 << 15))
                .collect();
            let nega = Crt::new(d, true);
            let mut acc = nega.zero();
            nega.mul_acc(&mut acc, &nega.of_field(&a), &nega.of_ints(&b));
            let bf: Vec<Fp> = b.iter().map(|&x| fp(x)).collect();
            assert_eq!(nega.back(acc), mul(&a, &bf), "negacyclic at d = {d}");
            let cyc = Crt::new(2 * d, false);
            let (mut ap, mut bp) = (a.clone(), b.clone());
            ap.resize(2 * d, Fp::ZERO);
            bp.resize(2 * d, 0);
            let mut acc = cyc.zero();
            cyc.mul_acc(&mut acc, &cyc.of_field(&ap), &cyc.of_ints(&bp));
            let full = cyc.back(acc);
            let mut want = vec![Fp::ZERO; 2 * d];
            for i in 0..d {
                for j in 0..d {
                    want[i + j] += a[i] * bf[j];
                }
            }
            assert_eq!(full, want, "full product at d = {d}");
        }
    }
}
