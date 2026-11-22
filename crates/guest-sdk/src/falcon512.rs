//! Falcon-512 with Poseidon2's HashToPoint: v1.2 of its specification (the
//! NIST round-3 submission) in all but HashToPoint, the map to the point `c`,
//! which is a Poseidon2-A64-C5 sponge over the key digest K, the salt, the
//! application's context and the message (`docs/spec/precompiles.md` §7.7). K
//! is a sponge over the key's v1.2 encoding, and the key's address K's first
//! 32 bytes.
//!
//! Precompiles do the work (`constants::delegation`, §7–§9): `FALCON512_DECODE`
//! decodes a public key's `h` and a signature's `s2`, refusing every stream
//! that is not one; `FALCON512_SAMPLE` turns HashToPoint's accepted lanes
//! into coefficients; `FALCON512` is the lattice check, [`s1_norm`]; and the
//! sponges' permutations are [`poseidon2_permute`]'s. Here are the advised
//! forms' lengths, K's and HashToPoint's sponges, and HashToPoint's
//! rejection, a lane compared with the sampler's bound.
//!
//! **The advised forms are compact**: each a whole number of words, read in
//! place a word at a time, and nothing a verification does not read. A key
//! is `h`'s 896 bytes, its v1.2 encoding without the header `0x09`, which K
//! hashes as the constant it is; a signature is its 40-byte salt, then `s2`
//! compressed through the word holding its last bit, its v1.2 encoding
//! without the header `0x39` and the padding. A host converts v1.2's 897 and
//! 666 bytes to them (`tools/falcon512`, `key_advice` and
//! `signature_advice`).
//!
//! **Every failure panics.** A key or a signature that is not one of these
//! forms, and a signature that does not verify, end the execution: a panic
//! here, or the decode call's refusal. Nothing answers a verdict a caller
//! could pass over, so a guest past [`PublicKey::decode`] holds a valid key,
//! and past [`PublicKey::verify`] a valid signature.

use core::mem::MaybeUninit;

use constants::delegation::falcon::{self, C, FRAME, H, N, NORM_HI, NORM_LO, S2};
use constants::delegation::falcon_decode::{self, KEY_END, SIGNATURE_BITS};

use crate::{poseidon2_permute, Digest};

/// The modulus `q`.
pub const Q: u16 = falcon::Q as u16;

/// `⌊β²⌋`: a signature verifies when `‖s1‖² + ‖s2‖²` is at most this.
pub const SQBETA: u64 = 34_034_726;

/// A public key's advised form: `h`'s 512 coefficients, 14 bits each, packed
/// big-endian, 896 bytes.
pub const KEY_BYTES: usize = KEY_END as usize / 8;

/// A signature's salt, its first bytes.
pub const SALT_BYTES: usize = 40;

/// The longest signature: the salt, then `s2` compressed in at most 5,000
/// bits, through the word holding the last, 668 bytes.
pub const MAX_SIGNATURE_BYTES: usize = SALT_BYTES + 4 * SIGNATURE_BITS.div_ceil(32) as usize;

/// The header of a key's v1.2 encoding, before `h`: K hashes it, and as a
/// constant it is not advised.
const KEY_HEADER: u64 = 0x09;

/// K's first fields, its use and then the key's scheme, and HashToPoint's,
/// which names the construction.
const KEY_DOMAIN: &[u8] = b"apogee/key/v1";
const SCHEME_ID: &[u8] = b"falcon512-poseidon2/v1";
const SIGNATURE_DOMAIN: &[u8] = b"apogee/falcon512/hash-to-point/v1";

/// A context's most bytes, FIPS 204's and 206's bound.
const MAX_CONTEXT_BYTES: usize = 255;

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

/// A Falcon-512 public key: the polynomial `h`, each coefficient below `q`;
/// K, the key digest of its v1.2 encoding; and HashToPoint's sponge after
/// the two fields every signature under the key begins with,
/// `(1, SIGNATURE_DOMAIN)` and `(2, K)`, its 64 bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    h: Poly,
    k: Digest,
    prefix: Sponge,
}

impl PublicKey {
    /// The key whose advised form is `h`, or a panic: exactly [`KEY_BYTES`],
    /// word-aligned, `h`'s coefficients in order, 14 bits each, packed
    /// big-endian, each below `q`, so a key has one form. The length and the
    /// alignment are checked here; the `FALCON512_DECODE` call reads `h` in
    /// place, a word at a time and no further, and writes the coefficients
    /// into the key, refusing one at or above `q`, which ends the execution.
    /// Then K from the key's v1.2 encoding, the header `0x09` and then `h`,
    /// 18 permutations, and HashToPoint's per-key prefix from K: once a key.
    // Inline: the key is then built in the caller's frame, not copied there.
    #[inline]
    pub fn decode(h: &[u8]) -> PublicKey {
        let mut key = MaybeUninit::<PublicKey>::uninit();
        PublicKey::decode_into(h, &mut key);
        // SAFETY: `decode_into` has written the key whole.
        unsafe { key.assume_init() }
    }

    /// [`PublicKey::decode`] into `key`, a slot of the caller's, which it
    /// returns written: the call writes `h` there and K and the prefix are
    /// written beside it, so a key kept for later, in an arena of keys say,
    /// is never copied there. Panics, or the call refuses, as `decode` does.
    #[inline]
    pub fn decode_into<'k>(h: &[u8], key: &'k mut MaybeUninit<PublicKey>) -> &'k mut PublicKey {
        assert!(
            h.len() == KEY_BYTES,
            "falcon512::PublicKey::decode: a key is 896 bytes"
        );
        assert!(
            h.as_ptr().addr().is_multiple_of(4),
            "falcon512::PublicKey::decode: a key is word-aligned"
        );
        let at = key.as_mut_ptr();
        // SAFETY: `h` is 224 words, word-aligned, a key's whole stream; the
        // key's `h` is 256 words, word-aligned, which the call writes whole.
        unsafe { decode_at(falcon_decode::KEY, h.as_ptr(), (&raw mut (*at).h).cast()) };
        let mut sponge = Sponge::ZERO;
        sponge.field(1, KEY_DOMAIN);
        sponge.field(2, SCHEME_ID);
        sponge.encoded_key(h);
        poseidon2_permute(&mut sponge.state);
        let k = Digest(core::array::from_fn(|i| sponge.state[i]));
        // SAFETY: `h` is the call's, and the rest of the key is written here,
        // the prefix absorbed in place once it is written zero.
        unsafe {
            (&raw mut (*at).k).write(k);
            let prefix = &raw mut (*at).prefix;
            prefix.write(Sponge::ZERO);
            (*prefix).field(1, SIGNATURE_DOMAIN);
            (*prefix).field(2, &le_bytes::<64>(&k));
            key.assume_init_mut()
        }
    }

    /// K, the key digest of the key's v1.2 encoding.
    pub fn key_digest(&self) -> &Digest {
        &self.k
    }

    /// The key's address: K's first 32 bytes.
    pub fn address(&self) -> [u8; 32] {
        le_bytes(&self.k)
    }

    /// The length in bytes of the signature `sig` begins with, where it is a
    /// signature of `msg` under this key and `context`; otherwise the
    /// execution ends. `context` is at most 255 bytes. `sig` is word-aligned
    /// and begins with a signature's advised form: the salt, then `s2`
    /// compressed, each coefficient `s` its sign bit, the low 7 bits of
    /// `|s|`, then `|s| >> 7` zeros and a one, none `−0` and none above 2047
    /// in size, within 5,000 bits, and zeros to the end of the word holding
    /// the last bit: `40 + 4·⌈end/32⌉` bytes, `end` the bit after the last
    /// coefficient, at most [`MAX_SIGNATURE_BYTES`], which `sig` holds and may
    /// follow with anything. And `‖s1‖² + ‖s2‖²` is at most [`SQBETA`], where
    /// `s1 = c − s2·h` and `c` is HashToPoint of K, the salt, `context` and
    /// `msg`. The `FALCON512_DECODE` call decodes `s2`, refusing every stream
    /// that is not one, a bit set after `end` in its last word among them;
    /// the rest are checked here, a panic; and the lattice check is
    /// [`s1_norm`]'s.
    ///
    /// The call reads the stream in place, a word at a time, through the
    /// word holding its last bit: where that is past `sig`, the words after
    /// `sig` must be readable, in RAM or in the advice, or the execution
    /// fails, and otherwise the length is a panic.
    pub fn verify(&self, msg: &[u8], sig: &[u8], context: &[u8]) -> usize {
        assert!(
            context.len() <= MAX_CONTEXT_BYTES,
            "falcon512::PublicKey::verify: a context is at most 255 bytes"
        );
        assert!(
            sig.as_ptr().addr().is_multiple_of(4),
            "falcon512::PublicKey::verify: a signature is word-aligned"
        );
        // Written whole by the calls, so neither is zeroed first.
        let mut s2 = MaybeUninit::<Poly>::uninit();
        let mut c = MaybeUninit::<[u64; N / 4]>::uninit();
        // SAFETY: the stream, 40 bytes into `sig`, is word-aligned and read
        // through the word holding its last bit, which the length below finds
        // within `sig`, or panics; `s2` is 256 words on the stack,
        // word-aligned, which the call writes whole.
        let (s2_norm, end) = unsafe {
            decode_at(
                falcon_decode::SIGNATURE,
                sig.as_ptr().wrapping_add(SALT_BYTES),
                s2.as_mut_ptr().cast(),
            )
        };
        let length = SALT_BYTES + 4 * end.div_ceil(32) as usize;
        assert!(
            length <= sig.len(),
            "falcon512::PublicKey::verify: a signature runs past its bytes"
        );
        hash_to_point(&self.prefix, &sig[..SALT_BYTES], context, msg, &mut c);
        // SAFETY: `h`, `s2` and `c` are 512 coefficients each, word-aligned,
        // `s2` and `c` written whole by the calls.
        let s1_norm =
            unsafe { s1_norm_at(self.h.0.as_ptr(), s2.as_ptr().cast(), c.as_ptr().cast()) };
        assert!(
            s1_norm + s2_norm as u64 <= SQBETA,
            "falcon512::PublicKey::verify: the signature does not verify"
        );
        length
    }
}

/// `k`'s first `B / 8` lanes, each little-endian: its 64 canonical bytes, or
/// the address.
fn le_bytes<const B: usize>(k: &Digest) -> [u8; B] {
    let mut bytes = [0; B];
    for (eight, lane) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(k.lanes()) {
        *eight = lane.to_le_bytes();
    }
    bytes
}

/// The `FALCON512_DECODE` call: the stream at `src` decoded in `mode`,
/// `falcon_decode::KEY` or `SIGNATURE`, into the 512 coefficients at `dst`,
/// each below `q`, a signature's `s` as `s mod q`; `(‖s2‖², end)`, the norm 0
/// for a key, `end` the bit after the last coefficient, counted from `src`'s
/// first, its bytes MSB first. The call refuses every stream that is not one,
/// a key's field at or above `q`, a signature's `−0`, more than 15 zeros,
/// more than 5,000 bits and a bit set after `end` in its last word, and
/// anything misplaced, ending the execution.
///
/// # Safety
/// `src` and `dst` are word-aligned; `src` is readable through the word
/// holding the stream's last bit, a key's 224 words and a signature's at most
/// 157, and `dst` is writable for 512 `u16`, apart from them.
pub(crate) unsafe fn decode_at(mode: u32, src: *const u8, dst: *mut u16) -> (u32, u32) {
    let mut frame = [0u32; falcon_decode::FRAME];
    frame[falcon_decode::SRC] = src as u32;
    frame[falcon_decode::DST] = dst as u32;
    frame[falcon_decode::MODE] = mode;
    // SAFETY: the frame is four words on the stack, below the advice region
    // and apart from the source and the polynomial.
    super::delegate(&super::FALCON512_DECODE, frame.as_mut_ptr());
    (frame[falcon_decode::MODE], frame[falcon_decode::END])
}

/// Poseidon2-A64-C5's overwrite duplex from the zero state, rate 8 and
/// capacity 8, without padding: K's sponge and HashToPoint's. A lane
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

    /// The field `tag`, `bytes`: the tag, the length in bytes, then the bytes
    /// seven to a lane, little-endian, the last chunk shorter, each lane below
    /// `2^56 < p`. Word-aligned `bytes` are read 28 at a time, four lanes from
    /// seven word loads; other bytes, and those after the last 28, a byte at a
    /// time.
    // Inline: most fields are a few lanes, and a call's overhead a large part
    // of their cost.
    #[inline(always)]
    fn field(&mut self, tag: u64, bytes: &[u8]) {
        // Held apart from `self`, which the call may write, so in a register.
        let mut at = self.at;
        self.absorb(&mut at, tag);
        self.absorb(&mut at, bytes.len() as u64);
        let (fours, rest) = if bytes.as_ptr().addr().is_multiple_of(4) {
            bytes.as_chunks::<28>()
        } else {
            (&[][..], bytes)
        };
        for four in fours {
            // SAFETY: 28 bytes, word-aligned, as `bytes` are and 28 is a
            // multiple of 4: seven words.
            let w = |i: usize| unsafe { four.as_ptr().cast::<u32>().add(i).read() } as u64;
            self.absorb(&mut at, w(0) | (w(1) & 0xff_ffff) << 32);
            self.absorb(&mut at, w(1) >> 24 | w(2) << 8 | (w(3) & 0xffff) << 40);
            self.absorb(&mut at, w(3) >> 16 | w(4) << 16 | (w(5) & 0xff) << 48);
            self.absorb(&mut at, w(5) >> 8 | w(6) << 24);
        }
        let (sevens, rest) = rest.as_chunks::<7>();
        for seven in sevens {
            self.absorb(&mut at, lane(seven));
        }
        if !rest.is_empty() {
            self.absorb(&mut at, lane(rest));
        }
        self.at = at;
    }

    /// K's last field, `(3, 0x09 ‖ h)`: the key's v1.2 encoding, 897 bytes,
    /// the header then `h`'s 896, word-aligned, in the lanes [`Sponge::field`]
    /// packs them in. Four lanes from seven word loads, as a word-aligned
    /// field's, but a byte behind: each four begins with the byte before its
    /// 28, the header or the last of the 28 before, and `h`'s last byte is a
    /// lane of its own.
    #[inline(always)]
    fn encoded_key(&mut self, h: &[u8]) {
        let mut at = self.at;
        self.absorb(&mut at, 3);
        self.absorb(&mut at, 1 + KEY_BYTES as u64);
        let mut last = KEY_HEADER;
        for four in h.as_chunks::<28>().0 {
            // SAFETY: 28 bytes, word-aligned, as `h` is: seven words.
            let w = |i: usize| unsafe { four.as_ptr().cast::<u32>().add(i).read() } as u64;
            self.absorb(&mut at, last | w(0) << 8 | (w(1) & 0xffff) << 40);
            self.absorb(&mut at, w(1) >> 16 | w(2) << 16 | (w(3) & 0xff) << 48);
            self.absorb(&mut at, w(3) >> 8 | w(4) << 24);
            self.absorb(&mut at, w(5) | (w(6) & 0xff_ffff) << 32);
            last = w(6) >> 24;
        }
        self.absorb(&mut at, last);
        self.at = at;
    }

    /// `x` into rate lane `at`, the state permuted first when the rate is
    /// full, and `at` the next.
    #[inline(always)]
    fn absorb(&mut self, at: &mut usize, x: u64) {
        // At most 8, and below it after the test, so the index is unchecked.
        if *at >= 8 {
            poseidon2_permute(&mut self.state);
            *at = 0;
        }
        self.state[*at] = x;
        *at += 1;
    }
}

/// HashToPoint into `c`: from a key's prefix, the fields `(3, salt)`,
/// `(4, context)` and `(5, msg)`, then each lane `x` of the squeeze stream
/// below [`T`] the next of `c`'s 128 lanes, the others skipped, every eight
/// rewritten in place by the `FALCON512_SAMPLE` call as their four base-`q`
/// digits `⌊x / q^j⌋ mod q`, `j < 4`: the point's 512 coefficients, as `u16`.
fn hash_to_point(
    prefix: &Sponge,
    salt: &[u8],
    context: &[u8],
    msg: &[u8],
    c: &mut MaybeUninit<[u64; N / 4]>,
) {
    let mut sponge = prefix.clone();
    sponge.field(3, salt);
    sponge.field(4, context);
    sponge.field(5, msg);
    let c = c.as_mut_ptr().cast::<u64>();
    let mut n = 0;
    loop {
        poseidon2_permute(&mut sponge.state);
        for &x in &sponge.state[..8] {
            // The rejection is this compare, proven as the guest's: the call
            // sees only lanes below `T`, and would refuse another.
            if x < T {
                // SAFETY: `n` is below 128, as the point is whole, and the
                // loop over, at 128.
                unsafe { c.add(n).write(x) };
                n += 1;
                if n.is_multiple_of(8) {
                    // SAFETY: the eight lanes before `n`, each below `T`,
                    // 8-aligned on the stack.
                    unsafe { sample_at(c.add(n - 8)) };
                    // No permutation once the point is whole.
                    if n == N / 4 {
                        return;
                    }
                }
            }
        }
    }
}

/// Up to seven bytes as a lane, little-endian: below `2^56`.
#[inline(always)]
fn lane(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0, |x, &b| x << 8 | b as u64)
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

/// HashToPoint's sampler by the precompile: each of `lanes`, `x`, rewritten
/// in place as its four base-`q` digits `⌊x / q^j⌋ mod q`, `j < 4`, `d_0 +
/// 2^16·d_1 + 2^32·d_2 + 2^48·d_3`, so lane `l` is coefficients `4l` to `4l +
/// 3` of the 32 `u16` the lanes' bytes are. Panics unless every lane is below
/// `808·q^4`, the largest multiple of `q^4` below `p`: the call refuses one at
/// or above it.
pub fn sample(lanes: &mut [u64; 8]) {
    assert!(
        lanes.iter().all(|&x| x < T),
        "falcon512::sample: eight lanes below 808·q^4"
    );
    // SAFETY: a `[u64; 8]` is 16 words, 8-aligned, and the whole frame.
    unsafe { sample_at(lanes.as_mut_ptr()) }
}

/// [`sample`] over the eight lanes at `lanes`, unchecked: the caller has
/// compared each with `808·q^4`, as the call refuses one at or above it.
///
/// # Safety
/// `lanes` is 8-aligned, below the advice region, and valid for reads and
/// writes of 8 `u64`.
unsafe fn sample_at(lanes: *mut u64) {
    super::delegate(&super::FALCON512_SAMPLE, lanes.cast())
}
