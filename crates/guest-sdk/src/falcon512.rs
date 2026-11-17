//! Falcon-512 with Poseidon2's HashToPoint: v1.2 of its specification (the
//! NIST round-3 submission) in all but HashToPoint, the map from the public
//! key, the salt and the message to the point `c`, which is a Poseidon2-A64-C5
//! sponge (`docs/spec/precompiles.md` §7.7). The lattice check is the
//! precompile's (`constants::delegation::falcon`, §7), the sponge's
//! permutations [`poseidon2_permute`]'s, and the rest is here, in software:
//! the public key's and the signature's encodings, HashToPoint's sponge and
//! sampler, and KeyDigest.

use constants::delegation::falcon::{self, C, FRAME, H, N, NORM_HI, NORM_LO, S2};

use crate::{poseidon2_permute, Digest};

/// The modulus `q`.
pub const Q: u16 = falcon::Q as u16;

/// `⌊β²⌋`: a signature verifies when `‖s1‖² + ‖s2‖²` is at most this.
pub const SQBETA: u64 = 34_034_726;

/// A public key's bytes: the header `0x09`, then `h`'s 512 coefficients, 14
/// bits each, packed big-endian.
pub const PUBLIC_KEY_BYTES: usize = 897;

/// A signature's bytes: the header `0x39`, the 40-byte salt, then `s2`
/// compressed and padded with zeros.
pub const SIGNATURE_BYTES: usize = 666;

/// A signature's bytes after its header and salt: 5,000 bits, `s2`
/// compressed and the padding.
const COMPRESSED: usize = SIGNATURE_BYTES - 41;

/// The sponge's first field, which names the construction.
const CONTEXT: &[u8] = b"apogee/falcon512/hash-to-point/v1";

/// The largest multiple of `q^4` below `p`, `808·q^4`: a lane below it is
/// four uniform coefficients, and one at or above it, about one in a
/// thousand, is skipped.
const T: u64 = field::A64_C5 / Q4 * Q4;
const Q4: u64 = falcon::Q.pow(4);

/// A polynomial of `Z_q[x]/(x^512 + 1)`, `q = 12289`: coefficient `i` at
/// `self.0[i]`, read mod `q` by [`s1_norm`], so any 512 `u16` are one.
/// Word-aligned, as the call reads an array a word at a time: coefficient `2i`
/// is word `i`'s low halfword and `2i + 1` its high one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct Poly(pub [u16; N]);

/// A Falcon-512 public key: the polynomial `h`, each coefficient below `q`,
/// and its bytes absorbed, the sponge HashToPoint and KeyDigest continue from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    h: Poly,
    prefix: Sponge,
}

impl PublicKey {
    /// The key `bytes` encode: exactly [`PUBLIC_KEY_BYTES`], the header
    /// `0x09`, then `h`'s coefficients in order, 14 bits each, packed
    /// big-endian, each below `q`. `None` for any other bytes, so a key has
    /// one encoding. The bytes are read first and absorbed only once they
    /// decode: 17 permutations, once a key.
    // Inline: the key is then built in the caller's frame, not copied there.
    #[inline]
    pub fn decode(bytes: &[u8]) -> Option<PublicKey> {
        let mut key = PublicKey {
            h: Poly([0; N]),
            prefix: Sponge::ZERO,
        };
        if !unpack(bytes, &mut key.h) {
            return None;
        }
        key.prefix.prefix(bytes);
        Some(key)
    }

    /// The key's KeyDigest, [`key_digest`] of its bytes: from its prefix, one
    /// permutation.
    pub fn digest(&self) -> Digest {
        self.prefix.clone().digest()
    }

    /// Whether `sig` is a signature of `msg` under this key: exactly
    /// [`SIGNATURE_BYTES`], the header `0x39`, the salt, then `s2`
    /// compressed, each coefficient `s` its sign bit, the low 7 bits of `|s|`,
    /// then `|s| >> 7` zeros and a one, none `−0` and none above 2047 in size,
    /// and zeros to the end; and `‖s1‖² + ‖s2‖²` at most [`SQBETA`], where
    /// `s1 = c − s2·h` and `c` is HashToPoint of the key, the salt and `msg`.
    /// The lattice check is [`s1_norm`]'s, the rest is read here.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Some(([0x39, salt @ ..], compressed)) = sig.split_first_chunk::<41>() else {
            return false;
        };
        let Ok(compressed) = <&[u8; COMPRESSED]>::try_from(compressed) else {
            return false;
        };
        let mut s2 = Poly([0; N]);
        let Some(s2_norm) = decompress(compressed, &mut s2) else {
            return false;
        };
        let mut c = Poly([0; N]);
        hash_to_point(&self.prefix, salt, msg, &mut c);
        s1_norm(&self.h, &s2, &c) + s2_norm as u64 <= SQBETA
    }
}

/// KeyDigest of `bytes`, an account's fingerprint (`docs/spec/precompiles.md`
/// §7.7): defined for any bytes, a key that does not decode included. A
/// decoded key's is [`PublicKey::digest`], which does not absorb it again.
pub fn key_digest(bytes: &[u8]) -> Digest {
    let mut sponge = Sponge::ZERO;
    sponge.prefix(bytes);
    sponge.digest()
}

/// [`PublicKey::decode`]'s `h` into `h`: whether `bytes` encode one.
fn unpack(bytes: &[u8], h: &mut Poly) -> bool {
    let Some(([0x09], packed)) = bytes.split_first_chunk() else {
        return false;
    };
    if packed.len() != PUBLIC_KEY_BYTES - 1 {
        return false;
    }
    // Seven bytes are four coefficients.
    for (seven, four) in packed.chunks_exact(7).zip(h.0.chunks_exact_mut(4)) {
        let bits = seven.iter().fold(0u64, |bits, &b| bits << 8 | b as u64);
        for (k, x) in four.iter_mut().enumerate() {
            *x = (bits >> (42 - 14 * k)) as u16 & 0x3fff;
            if *x >= Q {
                return false;
            }
        }
    }
    true
}

// Five bytes a load, so the loads land on the end of the compressed bytes.
const _: () = assert!(COMPRESSED.is_multiple_of(5));

/// `s2` from its compressed bytes into `s2`, a coefficient `s` as `s mod q`,
/// and `‖s2‖²`; `None` unless `bytes` are 512 coefficients, none `−0` and none
/// above 2047 in size, then zeros.
fn decompress(bytes: &[u8; COMPRESSED], s2: &mut Poly) -> Option<u32> {
    let mut reader = Reader {
        bytes,
        bits: 0,
        have: 0,
        at: 0,
        norm: 0,
    };
    // Two a pass, which share its count and its address.
    for [x, y] in s2.0.as_chunks_mut().0 {
        *x = reader.coefficient()?;
        *y = reader.coefficient()?;
    }
    // Every bit after the last coefficient is zero: those loaded, and the
    // bytes not.
    let rest = bytes.get(reader.at..).unwrap_or_default();
    (reader.bits == 0 && rest.iter().all(|&b| b == 0)).then_some(reader.norm)
}

/// [`decompress`]'s place in the compressed bytes.
struct Reader<'a> {
    bytes: &'a [u8; COMPRESSED],
    /// The bits not yet read, the next at bit 63 and zeros below them.
    bits: u64,
    /// How many: the bytes', then zeros past their end.
    have: u32,
    /// The next five bytes to load: at most `5 · 512`.
    at: usize,
    /// `‖s2‖²` so far.
    norm: u32,
}

impl Reader<'_> {
    /// The next coefficient `s`, as `s mod q`; `None` if it is `−0`, above
    /// 2047 in size, or reaches past the bytes.
    #[inline(always)]
    fn coefficient(&mut self) -> Option<u16> {
        // A coefficient is at most 24 bits: 8, then at most 15 zeros and a one.
        if self.have < 24 {
            if let Some(&[b0, b1, b2, b3, b4]) =
                self.bytes.get(self.at..).and_then(<[u8]>::first_chunk)
            {
                let five = (b0 as u64) << 32
                    | (b1 as u64) << 24
                    | (b2 as u64) << 16
                    | (b3 as u64) << 8
                    | b4 as u64;
                self.bits |= five << (24 - self.have);
            }
            self.at = self.at.wrapping_add(5);
            self.have += 40;
        }
        let top = (self.bits >> 56) as u32;
        let mut bits = self.bits << 8;
        // A one within the next 16 bits, or `|s| > 2047`. Past the end there
        // is none, so a coefficient reaching it is refused here.
        if bits >> 48 == 0 {
            return None;
        }
        // At most 15 zeros: `size` stays at most 2047, `have` at least 0, and
        // `norm` below `512 · 2047² < 2^32`.
        let mut size = top & 0x7f;
        while (bits as i64) >= 0 {
            bits <<= 1;
            size = size.wrapping_add(128);
            self.have = self.have.wrapping_sub(1);
        }
        self.bits = bits << 1;
        self.have = self.have.wrapping_sub(9);
        self.norm = self.norm.wrapping_add(size.wrapping_mul(size));
        match (top >> 7, size) {
            (0, _) => Some(size as u16),
            (_, 0) => None,
            _ => Some(Q.wrapping_sub(size as u16)),
        }
    }
}

/// Poseidon2-A64-C5's overwrite duplex from the zero state, rate 8 and
/// capacity 8, without padding: HashToPoint's sponge and KeyDigest's. A lane
/// absorbed overwrites the next rate lane, the state permuted first when the
/// rate is full; the squeeze stream is a permutation then the rate's eight
/// lanes, again and again.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Sponge {
    state: [u64; 16],
    /// The rate lanes absorbed since the last permutation: at most 8.
    at: usize,
}

impl Sponge {
    /// The zero state, nothing absorbed.
    const ZERO: Sponge = Sponge {
        state: [0; 16],
        at: 0,
    };

    /// A key's prefix from the zero state: the fields `(1, CONTEXT)` and
    /// `(2, key)`, where HashToPoint and KeyDigest both begin.
    fn prefix(&mut self, key: &[u8]) {
        self.field(1, CONTEXT);
        self.field(2, key);
    }

    /// The field `tag`, `bytes`: the tag, the length in bytes, then the bytes
    /// seven to a lane, little-endian, the last chunk shorter, each lane below
    /// `2^56 < p`.
    fn field(&mut self, tag: u64, bytes: &[u8]) {
        let (sevens, rest) = bytes.as_chunks::<7>();
        let sevens = sevens.iter().map(|seven| lane(seven));
        let rest = (!rest.is_empty()).then(|| lane(rest));
        let header = [tag, bytes.len() as u64];
        self.absorb(header.into_iter().chain(sevens).chain(rest));
    }

    /// Each of `lanes` into the next rate lane, the state permuted first when
    /// the rate is full.
    #[inline(always)]
    fn absorb(&mut self, lanes: impl Iterator<Item = u64>) {
        // Held apart from `self`, which the call may write, so in a register;
        // at most 8, and below it after the test, so the index is unchecked.
        let mut at = self.at;
        lanes.for_each(|x| {
            if at >= 8 {
                poseidon2_permute(&mut self.state);
                at = 0;
            }
            self.state[at] = x;
            at += 1;
        });
        self.at = at;
    }

    /// KeyDigest from a key's prefix: an empty field tagged 5, then the
    /// squeeze stream's first eight lanes, canonical as the call writes them.
    fn digest(mut self) -> Digest {
        self.field(5, &[]);
        poseidon2_permute(&mut self.state);
        Digest(core::array::from_fn(|i| self.state[i]))
    }
}

/// HashToPoint into `c`: from a key's prefix, the fields `(3, salt)` and
/// `(4, msg)`, then each lane `x` of the squeeze stream below [`T`] the next
/// four coefficients, `⌊x / q^j⌋ mod q` for `j < 4`, the others skipped, until
/// 512.
fn hash_to_point(prefix: &Sponge, salt: &[u8; 40], msg: &[u8], c: &mut Poly) {
    let mut sponge = prefix.clone();
    sponge.field(3, salt);
    sponge.field(4, msg);
    let mut fours = c.0.as_chunks_mut::<4>().0.iter_mut();
    loop {
        poseidon2_permute(&mut sponge.state);
        for &x in &sponge.state[..8] {
            if x < T {
                let Some(four) = fours.next() else {
                    return;
                };
                digits(x, four);
            }
        }
        // No permutation once the point is whole.
        if fours.len() == 0 {
            return;
        }
    }
}

/// Up to seven bytes as a lane, little-endian: below `2^56`.
#[inline(always)]
fn lane(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0, |x, &b| x << 8 | b as u64)
}

/// `x`'s four least significant base-`q` digits into `four`, `⌊x / q^j⌋ mod q`
/// for `j < 4`: `x_j − q·x_(j+1)` where `x_j = ⌊x / q^j⌋`, and `x_3 mod q`
/// last. No subtraction wraps; `wrapping_sub` drops only the checks.
#[inline(always)]
fn digits(x: u64, four: &mut [u16; 4]) {
    const Q: u64 = falcon::Q;
    let (x1, x2, x3) = (x / Q, x / (Q * Q), x / (Q * Q * Q));
    four[0] = x.wrapping_sub(Q * x1) as u16;
    four[1] = x1.wrapping_sub(Q * x2) as u16;
    four[2] = x2.wrapping_sub(Q * x3) as u16;
    four[3] = (x3 % Q) as u16;
}

/// `‖s1‖²` by the precompile, `s1 = (c − s2·h) mod (q, x^512 + 1)` with each
/// coefficient centered to `[−6144, 6144]`: Falcon-512 verification's lattice
/// check, which accepts the signature `s2` of the hashed message `c` under
/// the public key `h` when this and `‖s2‖²` sum to at most [`SQBETA`]. Below
/// `2^35`.
///
/// The three are read in place, anywhere a load reaches, the advice included.
/// Panics unless they are apart: the call reads every word of them at once.
pub fn s1_norm(h: &Poly, s2: &Poly, c: &Poly) -> u64 {
    // SAFETY: each borrow is 512 `u16`, word-aligned.
    unsafe { s1_norm_at(h.0.as_ptr(), s2.0.as_ptr(), c.0.as_ptr()) }
}

/// [`s1_norm`] over the 512 coefficients at each of `h`, `s2` and `c`. Panics
/// unless each is word-aligned and the three are apart.
///
/// # Safety
/// `h`, `s2` and `c` are each valid for reads of 512 `u16`.
pub(crate) unsafe fn s1_norm_at(h: *const u16, s2: *const u16, c: *const u16) -> u64 {
    let at = [h, s2, c].map(|p| p as usize);
    let apart = |i: usize, j: usize| at[i].abs_diff(at[j]) >= 2 * N;
    assert!(
        at.iter().all(|a| a.is_multiple_of(4)) && apart(0, 1) && apart(0, 2) && apart(1, 2),
        "falcon512::s1_norm: three word-aligned arrays, apart"
    );
    let mut frame = [0u32; FRAME];
    frame[H] = at[0] as u32;
    frame[S2] = at[1] as u32;
    frame[C] = at[2] as u32;
    // SAFETY: the frame is five words on the stack, below the advice region
    // and apart from the arrays, each readable for 1,024 bytes.
    super::delegate(&super::FALCON512, frame.as_mut_ptr());
    frame[NORM_LO] as u64 | (frame[NORM_HI] as u64) << 32
}
