//! Falcon-512 with Poseidon2's HashToPoint: Falcon-512 as v1.2 of its
//! specification (the NIST round-3 submission) defines it, keys, encodings,
//! the signer's sampler and the acceptance rule, except for HashToPoint, the
//! map from the public key, the salt and the message to the point `c`, which is
//! a Poseidon2-A64-C5 sponge ([`hash_to_point`]) instead of SHAKE256 of the
//! salt and the message. A standard Falcon signature does not verify here, nor
//! the reverse.
//!
//! The host's half, for the test suites: keys from a seed, signatures, and the
//! verifier the guest SDK's is held to. **The signer is not constant time** and
//! draws on the thread RNG: it is test infrastructure, never a signer of
//! anything that matters.

use std::iter;

use field::{Fp, A64_C5};
use transcript::{poseidon2_permute, RATE, WIDTH};

mod sign;

pub use sign::sign;

/// A public key's bytes: the header `0x09`, then `h`'s 512 coefficients, 14
/// bits each, packed big-endian.
pub const PUBLIC_KEY_BYTES: usize = 897;

/// A secret key's bytes: the header `0x59`, then `f`, `g` and `F`, 6, 6 and 8
/// bits a coefficient in two's complement, packed big-endian.
pub const SECRET_KEY_BYTES: usize = 1281;

/// A signature's bytes: the header `0x39`, the salt, then `s2` compressed and
/// zero-padded to 625 bytes.
pub const SIGNATURE_BYTES: usize = 666;

/// The salt's bytes, v1.2's nonce `r`.
pub const SALT_BYTES: usize = 40;

/// The degree: polynomials are of `Z[x]/(x^512 + 1)`.
const N: usize = 512;

/// The modulus `q`.
const Q: i64 = 12289;

/// `⌊β²⌋`: a signature verifies when `‖s1‖² + ‖s2‖²` is at most this.
const SQBETA: i64 = 34_034_726;

/// The sponge's first field, which names the construction.
const CONTEXT: &[u8] = b"apogee/falcon512/hash-to-point/v1";

/// The largest multiple of `q^4` below `p`: a lane under it is four uniform
/// coefficients, and one at or above it, about one in a thousand, is skipped.
const T: u64 = A64_C5 / Q4 * Q4;
const Q4: u64 = (Q as u64).pow(4);

/// A key pair from `seed`, `(secret key, public key)`: `falcon-rust`'s keygen,
/// deterministic in `seed`, in v1.2's encodings.
///
/// Panics if the key does not fit them (`f` or `g` beyond ±31, `F` beyond
/// ±127), which v1.2's keygen would have redrawn and `falcon-rust`'s does not.
pub fn keygen(seed: [u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (sk, pk) = falcon_rust::falcon512::keygen(seed);
    let (sk, pk) = (sk.to_bytes(), pk.to_bytes());
    let fits = sign::expand(&sk).is_some_and(|(_, h)| h == pk);
    assert!(fits, "falcon-rust's key fits v1.2's encoding");
    (sk, pk)
}

/// Whether `sig` is a signature of `msg` under `pk`: `pk` exactly
/// [`PUBLIC_KEY_BYTES`], `0x09` and coefficients below `q`; `sig` exactly
/// [`SIGNATURE_BYTES`], `0x39`, the salt, then `s2` compressed, each
/// coefficient `s` its sign, the low 7 bits of `|s|`, then `|s| >> 7` zeros
/// and a one, none `−0` and none above 2047 in size, within the 5,000 bits and
/// only zeros after them; and `‖s1‖² + ‖s2‖² ≤ ⌊β²⌋`, where `s1 = c − s2·h`
/// mod `q`, centered, and `c` is [`hash_to_point`] of `pk`, the salt and `msg`.
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    let Some(salt) = sig.get(1..).and_then(<[u8]>::first_chunk) else {
        return false;
    };
    verify_point(pk, &hash_to_point(pk, salt, msg), sig)
}

/// [`verify`] with the point `c` given: the decoding and the norm, whatever
/// hash `c` came from.
#[doc(hidden)]
pub fn verify_point(pk: &[u8], c: &[u16; N], sig: &[u8]) -> bool {
    let (Some(h), Some(s2)) = (decode_public_key(pk), decompress(sig)) else {
        return false;
    };
    let s1 = c.iter().zip(mul(&s2, &h));
    let s1 = s1.map(|(&c, x)| center((c as i64 - x).rem_euclid(Q)));
    s1.chain(s2.iter().copied()).map(|x| x * x).sum::<i64>() <= SQBETA
}

/// HashToPoint: `c` from the encoded public key `pk`, the salt and `msg`.
///
/// The `sponge` of the fields `(1, CONTEXT)`, `(2, pk)`, `(3, salt)` and
/// `(4, msg)`; a lane `x` of its squeeze stream below `T` is the next four
/// coefficients, `⌊x / q^j⌋ mod q` for `j < 4`, and the others are skipped.
pub fn hash_to_point(pk: &[u8], salt: &[u8; SALT_BYTES], msg: &[u8]) -> [u16; N] {
    let lanes = sponge(&[(1, CONTEXT), (2, pk), (3, salt), (4, msg)]);
    let mut c = [0; N];
    for (four, mut x) in c.chunks_exact_mut(4).zip(lanes.filter(|&x| x < T)) {
        for ci in four {
            *ci = (x % Q as u64) as u16;
            x /= Q as u64;
        }
    }
    c
}

/// KeyDigest, an account's fingerprint: the first eight lanes of the
/// `sponge` of `(1, CONTEXT)`, `(2, pk)` and an empty field tagged 5. Defined
/// for any bytes, a key that does not decode included.
pub fn key_digest(pk: &[u8]) -> [u64; 8] {
    let mut lanes = sponge(&[(1, CONTEXT), (2, pk), (5, &[])]);
    std::array::from_fn(|_| lanes.next().unwrap())
}

/// The squeeze stream of Poseidon2-A64-C5's overwrite duplex from the zero
/// state, rate 8, after absorbing `fields`. A field is its tag, its length in
/// bytes, then its bytes seven to a lane, little-endian, the last chunk
/// shorter; each lane overwrites the next rate lane, the rate permuted first
/// when it is full. The stream is a permutation then the rate, again and again.
fn sponge(fields: &[(u64, &[u8])]) -> impl Iterator<Item = u64> {
    let mut state = [Fp::ZERO; WIDTH];
    let lanes = fields.iter().flat_map(|&(tag, bytes)| {
        let le = |chunk: &[u8]| chunk.iter().rev().fold(0, |x, &b| x << 8 | b as u64);
        let chunks = bytes.chunks(7).map(le);
        [tag, bytes.len() as u64].into_iter().chain(chunks)
    });
    for (i, x) in lanes.enumerate() {
        if i > 0 && i % RATE == 0 {
            poseidon2_permute(&mut state);
        }
        state[i % RATE] = Fp::from_u64(x);
    }
    let rates = iter::repeat_with(move || {
        poseidon2_permute(&mut state);
        state
    });
    rates.flat_map(|state| state.into_iter().take(RATE).map(Fp::to_u64))
}

/// `h` from a public key's bytes, if they are one.
fn decode_public_key(pk: &[u8]) -> Option<Vec<i64>> {
    let (Some(0x09), PUBLIC_KEY_BYTES) = (pk.first(), pk.len()) else {
        return None;
    };
    let mut bits = bits(&pk[1..]);
    let h: Vec<i64> = (0..N).map(|_| read(&mut bits, 14).unwrap()).collect();
    h.iter().all(|&x| x < Q).then_some(h)
}

/// `h`'s encoding, `0x09` then 14 bits a coefficient.
fn encode_public_key(h: &[i64]) -> Vec<u8> {
    pack(bits_of(0x09, 8).chain(h.iter().flat_map(|&x| bits_of(x, 14))))
}

/// Decompress (Algorithm 18): `s2` from a signature's bytes, if they are one.
fn decompress(sig: &[u8]) -> Option<Vec<i64>> {
    if sig.len() != SIGNATURE_BYTES || sig[0] != 0x39 {
        return None;
    }
    let mut bits = bits(&sig[1 + SALT_BYTES..]);
    let mut s2 = Vec::with_capacity(N);
    for _ in 0..N {
        let negative = bits.next()?;
        let mut size = read(&mut bits, 7)?;
        while !bits.next()? {
            size += 128;
            if size > 2047 {
                return None;
            }
        }
        if negative && size == 0 {
            return None;
        }
        s2.push(if negative { -size } else { size });
    }
    bits.all(|bit| !bit).then_some(s2)
}

/// Compress (Algorithm 17): `s2` as [`decompress`] reads it, `None` if it
/// does not fit or a coefficient is above 2047 in size.
fn compress(s2: &[i64]) -> Option<Vec<u8>> {
    let length = 8 * (SIGNATURE_BYTES - 1 - SALT_BYTES);
    let mut bits = Vec::with_capacity(length);
    for &s in s2 {
        let size = s.abs();
        if size > 2047 {
            return None;
        }
        bits.push(s < 0);
        bits.extend(bits_of(size, 7));
        bits.extend(iter::repeat_n(false, (size >> 7) as usize));
        bits.push(true);
    }
    if bits.len() > length {
        return None;
    }
    bits.resize(length, false);
    Some(pack(bits))
}

/// The bits of `bytes`, most significant first.
fn bits(bytes: &[u8]) -> impl Iterator<Item = bool> + '_ {
    bytes.iter().flat_map(|&b| bits_of(b as i64, 8))
}

/// The low `width` bits of `x`, most significant first.
fn bits_of(x: i64, width: u32) -> impl Iterator<Item = bool> {
    (0..width).rev().map(move |i| x >> i & 1 == 1)
}

/// The next `width` bits as an unsigned integer, most significant first.
fn read(bits: &mut impl Iterator<Item = bool>, width: u32) -> Option<i64> {
    (0..width).try_fold(0, |x, _| Some(x << 1 | bits.next()? as i64))
}

/// Whole bytes of `bits`, most significant first.
fn pack(bits: impl IntoIterator<Item = bool>) -> Vec<u8> {
    let bits: Vec<bool> = bits.into_iter().collect();
    let byte = |eight: &[bool]| eight.iter().fold(0, |b, &bit| b << 1 | bit as u8);
    bits.chunks(8).map(byte).collect()
}

/// `x mod q`, from `[0, q)`, into `[−(q − 1)/2, (q − 1)/2]`.
fn center(x: i64) -> i64 {
    x - Q * (x > Q / 2) as i64
}

/// `a·b` in `Z[x]/(x^512 + 1)`.
fn mul(a: &[i64], b: &[i64]) -> Vec<i64> {
    let mut c = vec![0; N];
    for (i, &x) in a.iter().enumerate() {
        for (j, &y) in b.iter().enumerate() {
            if i + j < N {
                c[i + j] += x * y;
            } else {
                c[i + j - N] -= x * y;
            }
        }
    }
    c
}
