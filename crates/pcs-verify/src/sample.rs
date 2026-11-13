//! Lane streams, the public setup and the folding challenges.
//! `docs/spec/pcs.md` §2.
//!
//! A [`Stream`] is Poseidon2-A64-C5 in counter mode: block `j` of a stream
//! keyed by `key` is the rate of one permutation of
//! `[key₀ … key₃, j, domain, 0, …]`, so every lane is a uniform residue mod
//! `q` in the ideal-permutation model. The setup is one stream; each folding
//! challenge coordinate reads its own (paper §10.1, "coordinate streams").

use alloc::vec::Vec;

use field::Fp;
use transcript::{poseidon2_permute, RATE, WIDTH};

use crate::ring::Sparse;

/// Domain constants, one per kind of stream. Never reassigned.
pub const SETUP_DOMAIN: u64 = 1;
pub const CHALLENGE_DOMAIN: u64 = 2;

/// The public setup seed, packed seven bytes to a lane, little-endian.
pub const SETUP_SEED: &[u8] = b"apogee-vm/akita/v1";

fn seed_key() -> [Fp; 4] {
    let mut key = [Fp::ZERO; 4];
    for (lane, chunk) in key.iter_mut().zip(SETUP_SEED.chunks(7)) {
        let mut le = [0u8; 8];
        le[..chunk.len()].copy_from_slice(chunk);
        *lane = Fp::from_u64(u64::from_le_bytes(le));
    }
    key
}

/// An endless stream of uniform lanes.
pub struct Stream {
    key: [Fp; 4],
    domain: u64,
    block: u64,
    buf: [Fp; RATE],
    used: usize,
}

impl Stream {
    pub fn new(key: [Fp; 4], domain: u64) -> Stream {
        Stream {
            key,
            domain,
            block: 0,
            buf: [Fp::ZERO; RATE],
            used: RATE,
        }
    }

    /// The `RATE` lanes of block `j`.
    pub fn block(key: [Fp; 4], domain: u64, j: u64) -> [Fp; RATE] {
        let mut s = [Fp::ZERO; WIDTH];
        s[..4].copy_from_slice(&key);
        s[4] = Fp::from_u64(j);
        s[5] = Fp::from_u64(domain);
        poseidon2_permute(&mut s);
        core::array::from_fn(|i| s[i])
    }

    pub fn lane(&mut self) -> Fp {
        if self.used == RATE {
            self.buf = Stream::block(self.key, self.domain, self.block);
            self.block += 1;
            self.used = 0;
        }
        self.used += 1;
        self.buf[self.used - 1]
    }

    /// A uniform integer below `n`, by rejection on lanes: a lane below
    /// `n·⌊q/n⌋` is accepted, mod `n`.
    pub fn below(&mut self, n: u64) -> u64 {
        let limit = (field::A64_C5 / n) * n;
        loop {
            let v = self.lane().to_u64();
            if v < limit {
                return v % n;
            }
        }
    }
}

/// The setup's coefficient `i`: lane `i % RATE` of block `i / RATE` of the
/// setup stream. A prefix of any length is a prefix of every longer one.
pub fn setup_prefix(len: usize) -> Vec<Fp> {
    let mut out = Vec::with_capacity(len);
    let mut j = 0;
    while out.len() < len {
        out.extend_from_slice(&setup_block(j)[..(len - out.len()).min(RATE)]);
        j += 1;
    }
    out
}

/// Block `j` of the setup stream: coefficients `RATE·j` to `RATE·j + RATE − 1`.
pub fn setup_block(j: u64) -> [Fp; RATE] {
    Stream::block(seed_key(), SETUP_DOMAIN, j)
}

/// A folding-challenge family (paper §3.2): `ones` coefficients `±1` and
/// `twos` coefficients `±2` on a uniform support in `R_dim`, each sign
/// uniform. Every member has `‖c‖_1 = ones + 2·twos`, and every difference of
/// two members is a unit (norm at most 4, below `√q/√2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Family {
    pub dim: usize,
    pub ones: usize,
    pub twos: usize,
}

impl Family {
    /// `‖c‖_1`, the `ω` of the response and collision bounds.
    pub fn l1(&self) -> u64 {
        (self.ones + 2 * self.twos) as u64
    }

    /// `Σ c_k²`, the Hoeffding variance factor.
    pub fn l2_sq(&self) -> u64 {
        (self.ones + 4 * self.twos) as u64
    }

    /// One member, uniform, from `stream`: a partial Fisher–Yates shuffle
    /// draws the support, its first `twos` positions take magnitude 2, and
    /// every position takes an independent sign.
    pub fn sample(&self, stream: &mut Stream) -> Sparse {
        let s = self.ones + self.twos;
        let mut perm: Vec<u32> = (0..self.dim as u32).collect();
        for i in 0..s {
            let j = i + stream.below((self.dim - i) as u64) as usize;
            perm.swap(i, j);
        }
        let pos = perm[..s].to_vec();
        let coef = (0..s)
            .map(|i| {
                let mag = if i < self.twos { 2 } else { 1 };
                if stream.below(2) == 1 {
                    -mag
                } else {
                    mag
                }
            })
            .collect();
        Sparse { pos, coef }
    }
}

/// The folding challenges of one round: coordinate `i` from its own stream,
/// keyed by the round's root challenge, the nonce and `i`.
pub fn fold_challenges(root: field::Fp2, nonce: u32, family: Family, count: usize) -> Vec<Sparse> {
    (0..count)
        .map(|i| {
            let key = [
                root.c0,
                root.c1,
                Fp::from_u64(nonce as u64),
                Fp::from_u64(i as u64),
            ];
            family.sample(&mut Stream::new(key, CHALLENGE_DOMAIN))
        })
        .collect()
}

/// The expanded public setup a verifier reads: a prefix of the setup stream
/// at least as long as every opening it checks needs. A function of its
/// length alone, so its `Debug` prints that.
#[derive(Clone, PartialEq, Eq)]
pub struct Setup(pub Vec<Fp>);

impl Setup {
    pub fn expand(len: usize) -> Setup {
        Setup(setup_prefix(len))
    }
}

impl core::fmt::Debug for Setup {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Setup({} coefficients)", self.0.len())
    }
}
