//! Falcon-512, v1.2 of its specification (the NIST round-3 submission): the
//! lattice check by the precompile (`constants::delegation::falcon`,
//! `docs/spec/precompiles.md`), and the verifier around it, the public key's
//! and the signature's encodings and HashToPoint, in software.

use constants::delegation::falcon::{self, C, FRAME, H, N, NORM_HI, NORM_LO, S2};

use crate::Shake256;

/// The modulus `q`.
pub const Q: u16 = falcon::Q as u16;

/// `⌊β²⌋`: a signature verifies when `‖s1‖² + ‖s2‖²` is at most this.
pub const SQBETA: u64 = 34_034_726;

/// A public key's bytes: the header `0x09`, then `h`'s 512 coefficients, 14
/// bits each, packed big-endian.
pub const PUBLIC_KEY_BYTES: usize = 897;

/// A signature's bytes: the header `0x39`, the 40-byte nonce, then `s2`
/// compressed and padded with zeros.
pub const SIGNATURE_BYTES: usize = 666;

/// A signature's bytes after its header and nonce: 5,000 bits, `s2`
/// compressed and the padding.
const COMPRESSED: usize = SIGNATURE_BYTES - 41;

/// A polynomial of `Z_q[x]/(x^512 + 1)`, `q = 12289`: coefficient `i` at
/// `self.0[i]`, read mod `q` by [`s1_norm`], so any 512 `u16` are one.
/// Word-aligned, as the call reads an array a word at a time: coefficient `2i`
/// is word `i`'s low halfword and `2i + 1` its high one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C, align(4))]
pub struct Poly(pub [u16; N]);

/// A Falcon-512 public key: the polynomial `h`, each coefficient below `q`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(Poly);

impl PublicKey {
    /// The key `bytes` encode: exactly [`PUBLIC_KEY_BYTES`], the header
    /// `0x09`, then `h`'s coefficients in order, 14 bits each, packed
    /// big-endian, each below `q`. `None` for any other bytes, so a key has
    /// one encoding.
    // Inline: the caller's key is then `h` copied a word at a time.
    #[inline]
    pub fn decode(bytes: &[u8]) -> Option<PublicKey> {
        let mut h = Poly([0; N]);
        unpack(bytes, &mut h).then_some(PublicKey(h))
    }

    /// Whether `sig` is a signature of `msg` under this key: exactly
    /// [`SIGNATURE_BYTES`], the header `0x39`, the nonce, then `s2`
    /// compressed, each coefficient `s` its sign bit, the low 7 bits of `|s|`,
    /// then `|s| >> 7` zeros and a one, none `−0` and none above 2047 in size,
    /// and zeros to the end; and `‖s1‖² + ‖s2‖²` at most [`SQBETA`], where
    /// `s1 = c − s2·h` and `c` is HashToPoint of the nonce and `msg`. The
    /// lattice check is [`s1_norm`]'s, the rest is read here.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let Some(([0x39, nonce @ ..], compressed)) = sig.split_first_chunk::<41>() else {
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
        hash_to_point(nonce, msg, &mut c);
        s1_norm(&self.0, &s2, &c) + s2_norm as u64 <= SQBETA
    }
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

/// HashToPoint of `nonce ‖ msg` into `c`: SHAKE256's output read as 16-bit
/// big-endian samples `t`, each below `5q = 61445` taken in turn, until 512.
/// Coefficient `i` is `t mod q`, held as `t`: a [`Poly`] is read mod `q`.
fn hash_to_point(nonce: &[u8; 40], msg: &[u8], c: &mut Poly) {
    const SAMPLES: usize = Shake256::RATE / 2;
    let mut sponge = Shake256::new();
    sponge.absorb(nonce);
    sponge.absorb(msg);
    sponge.finalize();
    let mut i = 0;
    loop {
        let rate = sponge.squeeze_lanes();
        match c.0[i..].first_chunk_mut::<SAMPLES>() {
            // Room for all the rate's samples: none checks a count.
            Some(room) => {
                let mut slots = room.iter_mut();
                for &lane in rate {
                    for t in samples(lane) {
                        if t < 5 * Q {
                            if let Some(x) = slots.next() {
                                *x = t;
                            }
                        }
                    }
                }
                i += SAMPLES - slots.len();
            }
            None => {
                for &lane in rate {
                    for t in samples(lane) {
                        if t < 5 * Q {
                            c.0[i] = t;
                            i += 1;
                            if i == N {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// The four 16-bit samples of an output lane: sample `j` its bytes `2j` and
/// `2j + 1`, the first the high one.
#[inline(always)]
fn samples(lane: u64) -> [u16; 4] {
    let swapped = (lane & 0x00ff_00ff_00ff_00ff) << 8 | (lane >> 8) & 0x00ff_00ff_00ff_00ff;
    [0, 16, 32, 48].map(|shift| (swapped >> shift) as u16)
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
