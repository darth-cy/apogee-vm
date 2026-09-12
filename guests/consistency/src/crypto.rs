//! Crypto: the code a zkVM guest spends its time in. A guest proving an
//! Ethereum block hashes with Keccak-256 and SHA-256, checks MACs and Merkle
//! paths, and — in this repository — runs the BN254 scalar field and the
//! Poseidon2 permutation. All of it is bit-twiddling on `u32` and `u64` words
//! and wide multiplication, which is exactly where a 32-bit target compiles the
//! same source most differently from a 64-bit one: on RV32 a `u64` rotate is a
//! pair of 32-bit shifts, a `u64` product is `mul` beside `mulhu`, a `u128`
//! product or remainder is a call into compiler-builtins, and an overflow check
//! on any of them is a sequence LLVM writes out by hand.
//!
//! Every primitive is written here from its specification and held to a
//! published known answer by an `assert!` that runs on both legs. That is not
//! what the suite compares — a wrong implementation would panic identically on
//! the host and the guest — it is what makes the bytes worth comparing: with
//! each primitive known to be right on the host, a section the guest computes
//! differently is the target computing something else.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::hint::black_box;

use field::{batch_inverse, Fr};
use transcript::{poseidon2_permute, Transcript};

use crate::{Ctx, Digest, Fault};

pub const TAGS: (u8, u8) = (0x60, 0x6f);

const TAG_SHA256: u8 = 0x60;
const TAG_HMAC: u8 = 0x61;
const TAG_KECCAK: u8 = 0x62;
const TAG_CHACHA20: u8 = 0x63;
const TAG_POLY1305: u8 = 0x64;
const TAG_SIPHASH_XXHASH: u8 = 0x65;
const TAG_CHECKSUMS: u8 = 0x66;
const TAG_MERKLE: u8 = 0x67;
const TAG_FIELD: u8 = 0x68;
const TAG_POSEIDON2: u8 = 0x69;
const TAG_PRIMES: u8 = 0x6a;
const TAG_GCD: u8 = 0x6b;
const TAG_ROOTS: u8 = 0x6c;

const FAULT_ZERO_INVERSE: u8 = 0x60;
const FAULT_FORGED_MAC: u8 = 0x61;
const FAULT_PROOF_INDEX: u8 = 0x62;
const FAULT_NARROW_MULMOD: u8 = 0x63;

pub const FAULTS: &[Fault] = &[
    Fault {
        code: FAULT_ZERO_INVERSE,
        what: "`expect` on the inverse of a field element that is zero by computation",
    },
    Fault {
        code: FAULT_FORGED_MAC,
        what: "`assert!` that an HMAC tag with one bit flipped verifies",
    },
    Fault {
        code: FAULT_PROOF_INDEX,
        what: "a Merkle proof asked for a leaf index past the last leaf",
    },
    Fault {
        code: FAULT_NARROW_MULMOD,
        what: "a `u64` modular product taken without widening, on operands whose product overflows",
    },
];

pub fn run(cx: &mut Ctx) {
    sha256_section(cx);
    hmac_section(cx);
    keccak_section(cx);
    chacha20_section(cx);
    poly1305_section(cx);
    siphash_xxhash_section(cx);
    checksum_section(cx);
    merkle_section(cx);
    field_section(cx);
    poseidon2_section(cx);
    primes_section(cx);
    gcd_section(cx);
    roots_section(cx);
}

/// The payload prefix each primitive reads. Hashing all of a 4 KiB payload
/// with every primitive would cost more than `MAX_SCALE`'s generated data, and
/// what the payload adds — bytes nobody chose — a prefix already carries.
fn window<'a>(cx: &Ctx<'a>) -> &'a [u8] {
    let payload = cx.payload();
    let len = payload.len().min(32 + 16 * cx.scale() as usize);
    &payload[..len]
}

/// A known answer, from the lowercase hex it is published in.
fn unhex<const N: usize>(hex: &str) -> [u8; N] {
    assert_eq!(hex.len(), 2 * N, "a known answer of the wrong length");
    let digit = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("{:?} is not a lowercase hex digit", c as char),
    };
    let mut out = [0u8; N];
    for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        *byte = (digit(pair[0]) << 4) | digit(pair[1]);
    }
    out
}

/// Lowercase hex, by table: `write!` per byte is the formatting machinery
/// once per byte, which at opt-level 0 costs more than the hash it prints.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(2 * bytes.len());
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0xf)]));
    }
    s
}

// ---------------------------------------------------------------------------
// A 256-bit hash, three ways
// ---------------------------------------------------------------------------

/// A streaming hash with a 32-byte output: SHA-256, Keccak-256 and SHA3-256
/// behind one interface, so HMAC is written once and run over both block
/// sizes.
trait Hash256: Clone {
    /// Bytes per compression: what HMAC pads its key to.
    const BLOCK: usize;
    fn new() -> Self;
    fn update(&mut self, data: &[u8]);
    fn finish(self) -> [u8; 32];

    fn digest(data: &[u8]) -> [u8; 32] {
        let mut h = Self::new();
        h.update(data);
        h.finish()
    }
}

const SHA256_H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// FIPS 180-4's compression function over one 64-byte block.
fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (word, bytes) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    let mut i = 16;
    while i < 64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
        i += 1;
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    let mut i = 0;
    while i < 64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i += 1;
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
}

#[derive(Clone)]
struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    filled: usize,
    /// Bytes absorbed, for the length the padding ends with.
    length: u64,
}

impl Hash256 for Sha256 {
    const BLOCK: usize = 64;

    fn new() -> Sha256 {
        Sha256 {
            state: SHA256_H0,
            block: [0; 64],
            filled: 0,
            length: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.length += data.len() as u64;
        while !data.is_empty() {
            let take = (64 - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled == 64 {
                sha256_compress(&mut self.state, &self.block);
                self.filled = 0;
            }
        }
    }

    fn finish(mut self) -> [u8; 32] {
        let bits = self.length * 8;
        // 0x80, then zeros until 8 bytes short of a block boundary, then the
        // bit length: one block more when fewer than 9 bytes were free.
        let zeros = (119 - self.filled) % 64;
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        pad[1 + zeros..9 + zeros].copy_from_slice(&bits.to_be_bytes());
        self.update(&pad[..9 + zeros]);
        debug_assert_eq!(self.filled, 0, "the padding ends on a block boundary");
        let mut out = [0u8; 32];
        for (bytes, word) in out.chunks_exact_mut(4).zip(self.state) {
            bytes.copy_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Keccak's rate at a 256-bit capacity's complement: 1600 - 512 bits.
const KECCAK_RATE: usize = 136;

/// The round constants: bit `2^j - 1` of round `i` is output `7i + j` of the
/// LFSR `x^8 + x^6 + x^5 + x^4 + 1` (the Keccak reference's `LFSR86540`).
/// A `const fn`, so the compiler evaluates it for [`KECCAK_RC`] and the
/// target evaluates it again in [`keccak_section`], and the two must agree.
const fn keccak_round_constants() -> [u64; 24] {
    let mut rc = [0u64; 24];
    let mut lfsr: u8 = 1;
    let mut round = 0;
    while round < 24 {
        let mut j = 0;
        while j < 7 {
            if lfsr & 1 != 0 {
                rc[round] ^= 1u64 << ((1 << j) - 1);
            }
            lfsr = if lfsr & 0x80 != 0 {
                (lfsr << 1) ^ 0x71
            } else {
                lfsr << 1
            };
            j += 1;
        }
        round += 1;
    }
    rc
}

/// ρ and π as one cycle through the lanes. π moves lane `(x, y)` to
/// `(y, 2x + 3y)`; from `(1, 0)` that walk visits the other 24 lanes once
/// each, and the `t`-th lane on it rotates by the `t+1`-th triangular number.
/// Returns, for each step, the index `x + 5y` the lane moves to and its
/// rotation.
const fn keccak_cycle() -> ([usize; 24], [u32; 24]) {
    let mut to = [0usize; 24];
    let mut rho = [0u32; 24];
    let (mut x, mut y) = (1usize, 0usize);
    let mut t = 0;
    while t < 24 {
        rho[t] = (((t + 1) * (t + 2) / 2) % 64) as u32;
        let next = (2 * x + 3 * y) % 5;
        x = y;
        y = next;
        to[t] = x + 5 * y;
        t += 1;
    }
    (to, rho)
}

const KECCAK_RC: [u64; 24] = keccak_round_constants();
const KECCAK_CYCLE: ([usize; 24], [u32; 24]) = keccak_cycle();

/// Keccak-f[1600] over 25 `u64` lanes, lane `x + 5y`: every rotate here is two
/// shifts and an or on each half of the lane on RV32.
///
/// `while` over indices rather than iterators, in this and the other hot
/// loops: at opt-level 0 every iterator `next` is a call, and written with
/// nested ranges this function cost 500k guest cycles a permutation.
fn keccak_f(a: &mut [u64; 25]) {
    let (to, rho) = &KECCAK_CYCLE;
    let mut round = 0;
    while round < 24 {
        // θ: every lane takes the parity of the two columns beside it.
        let c = [
            a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20],
            a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21],
            a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22],
            a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23],
            a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24],
        ];
        let d = [
            c[4] ^ c[1].rotate_left(1),
            c[0] ^ c[2].rotate_left(1),
            c[1] ^ c[3].rotate_left(1),
            c[2] ^ c[4].rotate_left(1),
            c[3] ^ c[0].rotate_left(1),
        ];
        let mut i = 0;
        while i < 25 {
            a[i] ^= d[i % 5];
            i += 1;
        }
        // ρ and π, in place along the cycle.
        let mut carried = a[1];
        let mut t = 0;
        while t < 24 {
            let displaced = a[to[t]];
            a[to[t]] = carried.rotate_left(rho[t]);
            carried = displaced;
            t += 1;
        }
        // χ, a row at a time.
        let mut y = 0;
        while y < 25 {
            let row = [a[y], a[y + 1], a[y + 2], a[y + 3], a[y + 4]];
            a[y] = row[0] ^ (!row[1] & row[2]);
            a[y + 1] = row[1] ^ (!row[2] & row[3]);
            a[y + 2] = row[2] ^ (!row[3] & row[4]);
            a[y + 3] = row[3] ^ (!row[4] & row[0]);
            a[y + 4] = row[4] ^ (!row[0] & row[1]);
            y += 5;
        }
        // ι
        a[0] ^= KECCAK_RC[round];
        round += 1;
    }
}

/// The Keccak sponge at a 256-bit output, told apart by the domain byte its
/// padding starts with: `0x01` is Keccak-256, Ethereum's hash; `0x06` is
/// FIPS 202's SHA3-256.
#[derive(Clone)]
struct Sponge<const DOMAIN: u8> {
    lanes: [u64; 25],
    block: [u8; KECCAK_RATE],
    filled: usize,
}

type Keccak256 = Sponge<0x01>;
type Sha3_256 = Sponge<0x06>;

impl<const DOMAIN: u8> Sponge<DOMAIN> {
    fn absorb_block(&mut self) {
        for (lane, bytes) in self.lanes.iter_mut().zip(self.block.chunks_exact(8)) {
            *lane ^= u64::from_le_bytes(bytes.try_into().expect("chunks of 8"));
        }
        keccak_f(&mut self.lanes);
        self.filled = 0;
    }
}

impl<const DOMAIN: u8> Hash256 for Sponge<DOMAIN> {
    const BLOCK: usize = KECCAK_RATE;

    fn new() -> Self {
        Sponge {
            lanes: [0; 25],
            block: [0; KECCAK_RATE],
            filled: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (KECCAK_RATE - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled == KECCAK_RATE {
                self.absorb_block();
            }
        }
    }

    fn finish(mut self) -> [u8; 32] {
        self.block[self.filled..].fill(0);
        self.block[self.filled] ^= DOMAIN;
        self.block[KECCAK_RATE - 1] ^= 0x80;
        self.absorb_block();
        let mut out = [0u8; 32];
        for (bytes, lane) in out.chunks_exact_mut(8).zip(self.lanes) {
            bytes.copy_from_slice(&lane.to_le_bytes());
        }
        out
    }
}

/// SHA-256 at the lengths its padding treats differently, and over the payload.
///
/// One message is hashed at every prefix length up to 130 by a running hasher,
/// cloned and finished at each: 55 is the last length whose padding fits its
/// block, 56 the first that spills into a second, 64 the first full block,
/// 119 and 120 the same boundary one block on.
fn sha256_section(cx: &mut Ctx) {
    assert_eq!(
        Sha256::digest(b"abc"),
        unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        "SHA-256(\"abc\"), FIPS 180-2 appendix B.1"
    );
    assert_eq!(
        Sha256::digest(b""),
        unhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "SHA-256 of nothing"
    );
    assert_eq!(
        Sha256::digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        unhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
        "SHA-256 of 56 bytes, FIPS 180-2 appendix B.2"
    );

    // The lengths where the padding changes shape, most interesting first: 55
    // is the last that fits beside its length word, 56 the first that spills
    // into a second block, 64 the first full block, and 119, 120 and 128 the
    // same three a block later. A compression is 50k guest cycles at
    // opt-level 0, so how many of these a run takes is the scale's business.
    const BOUNDARIES: [usize; 12] = [55, 56, 64, 0, 1, 57, 63, 65, 119, 120, 127, 128];
    let taken = (1 + cx.scale() as usize / 4).min(BOUNDARIES.len());
    let message = cx.rng().bytes(130);
    let mut d = Digest::new();
    for &len in &BOUNDARIES[..taken] {
        d.bytes(&Sha256::digest(&message[..len]));
    }

    // Fed a byte at a time, which is every partial-buffer path in `update`.
    let streamed = &message[..BOUNDARIES[0]];
    let mut running = Sha256::new();
    for byte in streamed {
        running.update(core::slice::from_ref(byte));
    }
    assert_eq!(
        running.finish(),
        Sha256::digest(streamed),
        "a message streamed byte by byte and hashed at once"
    );

    let mut body = Vec::with_capacity(40);
    body.extend_from_slice(&Sha256::digest(window(cx)));
    body.extend_from_slice(&d.finish().to_le_bytes());
    cx.section(TAG_SHA256, &body);
}

// ---------------------------------------------------------------------------
// HMAC
// ---------------------------------------------------------------------------

/// RFC 2104 over any [`Hash256`]. A key longer than a block is hashed first.
fn hmac<H: Hash256>(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut pad = [0u8; KECCAK_RATE];
    let pad = &mut pad[..H::BLOCK];
    if key.len() > H::BLOCK {
        pad[..32].copy_from_slice(&H::digest(key));
    } else {
        pad[..key.len()].copy_from_slice(key);
    }
    pad.iter_mut().for_each(|b| *b ^= 0x36);
    let mut inner = H::new();
    inner.update(pad);
    inner.update(message);
    let inner = inner.finish();
    pad.iter_mut().for_each(|b| *b ^= 0x36 ^ 0x5c);
    let mut outer = H::new();
    outer.update(pad);
    outer.update(&inner);
    outer.finish()
}

/// Whether `tag` is the MAC of `message`, comparing every byte whatever the
/// first difference: the fold's length does not depend on the data.
fn hmac_verify<H: Hash256>(key: &[u8], message: &[u8], tag: &[u8; 32]) -> bool {
    let expected = hmac::<H>(key, message);
    expected
        .iter()
        .zip(tag)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

/// HMAC-SHA256 against RFC 4231, then over generated keys — some longer than a
/// block, so the key is hashed first — and the payload, with every tag
/// verified and a one-bit forgery of it refused; HMAC-Keccak256 beside it
/// runs the same code at a 136-byte block.
fn hmac_section(cx: &mut Ctx) {
    assert_eq!(
        hmac::<Sha256>(b"Jefe", b"what do ya want for nothing?"),
        unhex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        "HMAC-SHA256, RFC 4231 case 2"
    );

    let s = cx.scale();
    let payload = window(cx);
    // Past a block the key is hashed first, which is the other half of RFC
    // 2104 and a compression more.
    let key_len = if s >= 4 {
        Sha256::BLOCK + 1 + cx.rng().index(70)
    } else {
        cx.rng().index(40)
    };
    let key = cx.rng().bytes(key_len);
    let tag = hmac::<Sha256>(&key, payload);
    let mut d = Digest::new();
    d.count(key.len()).bytes(&tag);

    if s >= 1 {
        let mut forged = tag;
        let at = cx.rng().index(forged.len());
        forged[at] ^= 1 << cx.rng().below(8);
        assert!(!hmac_verify::<Sha256>(&key, payload, &forged));
        if cx.fault(FAULT_FORGED_MAC) {
            assert!(hmac_verify::<Sha256>(&key, payload, &forged));
        }
    }
    if s >= 12 {
        // The same generic code at Keccak's 136-byte block.
        d.bytes(&hmac::<Keccak256>(&key, payload));
    }
    let body = format!("{} {:016x}", hex(&tag), d.finish());
    cx.section(TAG_HMAC, body.as_bytes());
}

// ---------------------------------------------------------------------------
// Keccak
// ---------------------------------------------------------------------------

/// An Ethereum address in EIP-55's mixed case: a hex letter is upper case
/// where the Keccak-256 of the lower-case address has a nibble of 8 or more.
fn eip55(address: &[u8; 20]) -> String {
    let lower = hex(address);
    let hash = Keccak256::digest(lower.as_bytes());
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for (i, c) in lower.chars().enumerate() {
        let nibble = if i.is_multiple_of(2) {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0xf
        };
        out.push(if nibble >= 8 {
            c.to_ascii_uppercase()
        } else {
            c
        });
    }
    out
}

/// Keccak-256 and SHA3-256 against their known answers, at the lengths around
/// the 136-byte rate, streamed in uneven pieces, and as Ethereum uses it: a
/// function selector and a checksummed address.
fn keccak_section(cx: &mut Ctx) {
    // A function pointer through `black_box`, so this call is compiled code
    // on the target rather than the compiler's evaluation again.
    let round_constants: fn() -> [u64; 24] = black_box(keccak_round_constants);
    let cycle: fn() -> ([usize; 24], [u32; 24]) = black_box(keccak_cycle);
    assert_eq!(
        round_constants(),
        KECCAK_RC,
        "the round constants, const and run-time"
    );
    assert_eq!(cycle(), KECCAK_CYCLE, "the lane cycle, const and run-time");

    assert_eq!(
        Keccak256::digest(b""),
        unhex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
        "Keccak-256 of nothing"
    );
    assert_eq!(
        Sha3_256::digest(b"abc"),
        unhex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"),
        "SHA3-256(\"abc\"), FIPS 202"
    );
    assert_eq!(
        Keccak256::digest(b"transfer(address,uint256)")[..4],
        [0xa9, 0x05, 0x9c, 0xbb],
        "the ERC-20 transfer selector"
    );
    assert_eq!(
        eip55(&unhex("5aaeb6053f3e94c9b9a09f33669435e7ef1beaed")),
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "EIP-55's first example"
    );

    let mut d = Digest::new();
    let message = cx.rng().bytes(2 * KECCAK_RATE + 1);
    let lengths = [135, 136, 0, 1, 137, 271, 272, 273];
    let count = (2 + cx.scale() as usize).min(lengths.len());
    for &len in &lengths[..count] {
        d.bytes(&Keccak256::digest(&message[..len]));
        d.bytes(&Sha3_256::digest(&message[..len]));
    }

    let streamed_len = (40 + 16 * cx.scale() as usize).min(message.len());
    let mut streamed = Keccak256::new();
    let mut rest = &message[..streamed_len];
    while !rest.is_empty() {
        let piece = 1 + cx.rng().index(rest.len().min(48));
        streamed.update(&rest[..piece]);
        rest = &rest[piece..];
    }
    assert_eq!(
        streamed.finish(),
        Keccak256::digest(&message[..streamed_len]),
        "Keccak-256 streamed in pieces and at once"
    );

    let public_key = cx.rng().bytes(64);
    let hash = Keccak256::digest(&public_key);
    let address: [u8; 20] = hash[12..].try_into().expect("the low 20 bytes");
    let body = format!(
        "{} {} {:016x}",
        hex(&Keccak256::digest(window(cx))),
        eip55(&address),
        d.finish()
    );
    cx.section(TAG_KECCAK, body.as_bytes());
}

// ---------------------------------------------------------------------------
// ChaCha20 and Poly1305
// ---------------------------------------------------------------------------

fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// RFC 8439's block function: 64 bytes of keystream for one counter value.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let word = |bytes: &[u8]| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for (s, bytes) in state[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *s = word(bytes);
    }
    state[12] = counter;
    for (s, bytes) in state[13..].iter_mut().zip(nonce.chunks_exact(4)) {
        *s = word(bytes);
    }
    let mut w = state;
    for _ in 0..10 {
        quarter_round(&mut w, 0, 4, 8, 12);
        quarter_round(&mut w, 1, 5, 9, 13);
        quarter_round(&mut w, 2, 6, 10, 14);
        quarter_round(&mut w, 3, 7, 11, 15);
        quarter_round(&mut w, 0, 5, 10, 15);
        quarter_round(&mut w, 1, 6, 11, 12);
        quarter_round(&mut w, 2, 7, 8, 13);
        quarter_round(&mut w, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for ((bytes, w), s) in out.chunks_exact_mut(4).zip(w).zip(state) {
        bytes.copy_from_slice(&w.wrapping_add(s).to_le_bytes());
    }
    out
}

/// XOR `data` with the keystream from block `counter` on. The counter is 32
/// bits and wraps, as RFC 8439 leaves to the caller.
fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut counter = counter;
    for chunk in data.chunks_mut(64) {
        let keystream = chacha20_block(key, counter, nonce);
        for (b, k) in chunk.iter_mut().zip(keystream) {
            *b ^= k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// ChaCha20 against RFC 8439 §2.3.2, then a round trip over generated data
/// whose block counter starts within three of `u32::MAX`, so it wraps.
fn chacha20_section(cx: &mut Ctx) {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let nonce = [0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0];
    assert_eq!(
        chacha20_block(&key, 1, &nonce),
        unhex(
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        ),
        "the ChaCha20 block, RFC 8439 2.3.2"
    );

    let mut key = [0u8; 32];
    cx.rng().fill(&mut key);
    let mut nonce = [0u8; 12];
    cx.rng().fill(&mut nonce);
    let counter = u32::MAX - cx.rng().below(3) as u32;
    let len = 64 + 48 * cx.scale() as usize + cx.rng().index(64);
    let mut plain = cx.rng().bytes(len);
    plain.extend_from_slice(window(cx));
    let mut data = plain.clone();
    chacha20_xor(&key, &nonce, counter, &mut data);
    let mut d = Digest::new();
    d.count(data.len()).bytes(&data);
    let head = hex(&data[..16]);
    chacha20_xor(&key, &nonce, counter, &mut data);
    assert_eq!(data, plain, "ChaCha20 undoes itself");
    let body = format!("{head} {:016x}", d.finish());
    cx.section(TAG_CHACHA20, body.as_bytes());
}

const MASK26: u32 = 0x03ff_ffff;

/// Poly1305 in five 26-bit limbs, so every product is a `u32` by `u32` into a
/// `u64`: on RV32 a `mul` and a `mulhu`, where a 64-bit host does one `mul`.
fn poly1305(key: &[u8; 32], message: &[u8]) -> [u8; 16] {
    let le = |bytes: &[u8], at: usize| {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    };
    // r, clamped as the RFC says, then split into limbs.
    let r = [
        le(key, 0) & 0x03ff_ffff,
        (le(key, 3) >> 2) & 0x03ff_ff03,
        (le(key, 6) >> 4) & 0x03ff_c0ff,
        (le(key, 9) >> 6) & 0x03f0_3fff,
        (le(key, 12) >> 8) & 0x000f_ffff,
    ];
    // 2^130 = 5 mod p, so a limb product past the top wraps around times 5.
    let s = [0, r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];
    let mut h = [0u32; 5];
    for chunk in message.chunks(16) {
        // The block as a 17-byte number with a 1 above its last byte.
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1;
        h[0] += le(&block, 0) & MASK26;
        h[1] += (le(&block, 3) >> 2) & MASK26;
        h[2] += (le(&block, 6) >> 4) & MASK26;
        h[3] += (le(&block, 9) >> 6) & MASK26;
        h[4] += (le(&block, 12) >> 8) | (u32::from(block[16]) << 24);

        let m = |a: u32, b: u32| u64::from(a) * u64::from(b);
        let d = [
            m(h[0], r[0]) + m(h[1], s[4]) + m(h[2], s[3]) + m(h[3], s[2]) + m(h[4], s[1]),
            m(h[0], r[1]) + m(h[1], r[0]) + m(h[2], s[4]) + m(h[3], s[3]) + m(h[4], s[2]),
            m(h[0], r[2]) + m(h[1], r[1]) + m(h[2], r[0]) + m(h[3], s[4]) + m(h[4], s[3]),
            m(h[0], r[3]) + m(h[1], r[2]) + m(h[2], r[1]) + m(h[3], r[0]) + m(h[4], s[4]),
            m(h[0], r[4]) + m(h[1], r[3]) + m(h[2], r[2]) + m(h[3], r[1]) + m(h[4], r[0]),
        ];
        let mut carry = 0u64;
        for (limb, d) in h.iter_mut().zip(d) {
            let t = d + carry;
            *limb = (t as u32) & MASK26;
            carry = t >> 26;
        }
        let t = u64::from(h[0]) + carry * 5;
        h[0] = (t as u32) & MASK26;
        h[1] += (t >> 26) as u32;
    }

    // Carry through, then take h - p if h >= p: h + 5 carries out of bit 130
    // exactly then.
    let mut c = 0;
    for limb in h[1..].iter_mut() {
        *limb += c;
        c = *limb >> 26;
        *limb &= MASK26;
    }
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= MASK26;
    h[1] += c;
    let mut g = [0u32; 5];
    let mut c = 5;
    for (g, h) in g.iter_mut().zip(h) {
        let t = h + c;
        *g = t & MASK26;
        c = t >> 26;
    }
    let h = if c != 0 { g } else { h };

    let words = [
        h[0] | (h[1] << 26),
        (h[1] >> 6) | (h[2] << 20),
        (h[2] >> 12) | (h[3] << 14),
        (h[3] >> 18) | (h[4] << 8),
    ];
    let mut tag = [0u8; 16];
    let mut carry = 0u64;
    for (i, (bytes, w)) in tag.chunks_exact_mut(4).zip(words).enumerate() {
        let t = u64::from(w) + u64::from(le(key, 16 + 4 * i)) + carry;
        bytes.copy_from_slice(&(t as u32).to_le_bytes());
        carry = t >> 32;
    }
    tag
}

/// RFC 8439's AEAD tag: Poly1305 keyed by keystream block 0, over the AAD and
/// the ciphertext, each zero-padded to 16 bytes, then both lengths.
fn aead_tag(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let block = chacha20_block(key, 0, nonce);
    let one_time: &[u8; 32] = block[..32].try_into().expect("32 bytes");
    let mut mac = Vec::with_capacity(aad.len() + ciphertext.len() + 48);
    mac.extend_from_slice(aad);
    mac.resize(mac.len().next_multiple_of(16), 0);
    mac.extend_from_slice(ciphertext);
    mac.resize(mac.len().next_multiple_of(16), 0);
    mac.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    poly1305(one_time, &mac)
}

fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plain: &[u8]) -> (Vec<u8>, [u8; 16]) {
    let mut ciphertext = plain.to_vec();
    chacha20_xor(key, nonce, 1, &mut ciphertext);
    let tag = aead_tag(key, nonce, aad, &ciphertext);
    (ciphertext, tag)
}

fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Option<Vec<u8>> {
    if aead_tag(key, nonce, aad, ciphertext) != *tag {
        return None;
    }
    let mut plain = ciphertext.to_vec();
    chacha20_xor(key, nonce, 1, &mut plain);
    Some(plain)
}

/// Poly1305 against RFC 8439 §2.5.2, ChaCha20-Poly1305 against §2.8.2, then
/// sealed and opened over generated data, with a flipped ciphertext bit and a
/// flipped AAD bit each refused.
fn poly1305_section(cx: &mut Ctx) {
    assert_eq!(
        poly1305(
            &unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"),
            b"Cryptographic Forum Research Group"
        ),
        unhex("a8061dc1305136c6c22b8baf0c0127a9"),
        "Poly1305, RFC 8439 2.5.2"
    );
    let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
    let nonce = [7, 0, 0, 0, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47];
    let aad = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let plain: &[u8] = b"Ladies and Gentlemen of the class of '99: If I could offer you only \
                         one tip for the future, sunscreen would be it.";
    let (ciphertext, tag) = aead_seal(&key, &nonce, &aad, plain);
    assert_eq!(
        tag,
        unhex("1ae10b594f09e26a7e902ecbd0600691"),
        "ChaCha20-Poly1305, RFC 8439 2.8.2"
    );
    assert_eq!(
        aead_open(&key, &nonce, &aad, &ciphertext, &tag).as_deref(),
        Some(plain)
    );

    let mut d = Digest::new();
    for _ in 0..1 + cx.scale() / 2 {
        let mut key = [0u8; 32];
        cx.rng().fill(&mut key);
        let mut nonce = [0u8; 12];
        cx.rng().fill(&mut nonce);
        let aad_len = cx.rng().index(20);
        let mut aad = cx.rng().bytes(aad_len);
        let len = 1 + cx.rng().index(100);
        let mut plain = cx.rng().bytes(len);
        plain.extend_from_slice(window(cx));
        let (mut ciphertext, tag) = aead_seal(&key, &nonce, &aad, &plain);
        assert_eq!(
            aead_open(&key, &nonce, &aad, &ciphertext, &tag),
            Some(plain),
            "an AEAD round trip"
        );
        d.bytes(&tag).count(ciphertext.len()).bytes(&ciphertext);

        let at = cx.rng().index(ciphertext.len());
        ciphertext[at] ^= 0x80;
        assert_eq!(aead_open(&key, &nonce, &aad, &ciphertext, &tag), None);
        ciphertext[at] ^= 0x80;
        if !aad.is_empty() {
            aad[0] ^= 1;
            assert_eq!(aead_open(&key, &nonce, &aad, &ciphertext, &tag), None);
        }
    }
    cx.digest(TAG_POLY1305, &d);
}

// ---------------------------------------------------------------------------
// SipHash and xxHash32
// ---------------------------------------------------------------------------

fn sip_round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13) ^ v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16) ^ v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21) ^ v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17) ^ v[2];
    v[2] = v[2].rotate_left(32);
}

/// SipHash-2-4, what Rust's own `HashMap` keyed its hasher with for years.
fn siphash24(key: &[u8; 16], data: &[u8]) -> u64 {
    let k0 = u64::from_le_bytes(key[..8].try_into().expect("8 bytes"));
    let k1 = u64::from_le_bytes(key[8..].try_into().expect("8 bytes"));
    let mut v = [
        k0 ^ 0x736f_6d65_7073_6575,
        k1 ^ 0x646f_7261_6e64_6f6d,
        k0 ^ 0x6c79_6765_6e65_7261,
        k1 ^ 0x7465_6462_7974_6573,
    ];
    let mut words = data.chunks_exact(8);
    for word in &mut words {
        let m = u64::from_le_bytes(word.try_into().expect("chunks of 8"));
        v[3] ^= m;
        sip_round(&mut v);
        sip_round(&mut v);
        v[0] ^= m;
    }
    let mut last = [0u8; 8];
    let rest = words.remainder();
    last[..rest.len()].copy_from_slice(rest);
    // The length mod 256, by definition: a truncation, the same everywhere.
    last[7] = data.len() as u8;
    let m = u64::from_le_bytes(last);
    v[3] ^= m;
    sip_round(&mut v);
    sip_round(&mut v);
    v[0] ^= m;
    v[2] ^= 0xff;
    for _ in 0..4 {
        sip_round(&mut v);
    }
    v[0] ^ v[1] ^ v[2] ^ v[3]
}

const XXH_PRIME: [u32; 5] = [
    0x9e37_79b1,
    0x85eb_ca77,
    0xc2b2_ae3d,
    0x27d4_eb2f,
    0x1656_67b1,
];

/// xxHash32: 32-bit multiplies and rotates, four lanes over 16-byte stripes,
/// then the tail a word and a byte at a time.
fn xxh32(data: &[u8], seed: u32) -> u32 {
    let [p1, p2, p3, p4, p5] = XXH_PRIME;
    let word = |bytes: &[u8]| u32::from_le_bytes(bytes.try_into().expect("4 bytes"));
    let mut stripes = data.chunks_exact(16);
    let mut h = if data.len() >= 16 {
        let mut v = [
            seed.wrapping_add(p1).wrapping_add(p2),
            seed.wrapping_add(p2),
            seed,
            seed.wrapping_sub(p1),
        ];
        for stripe in &mut stripes {
            for (lane, bytes) in v.iter_mut().zip(stripe.chunks_exact(4)) {
                *lane = lane
                    .wrapping_add(word(bytes).wrapping_mul(p2))
                    .rotate_left(13)
                    .wrapping_mul(p1);
            }
        }
        v[0].rotate_left(1)
            .wrapping_add(v[1].rotate_left(7))
            .wrapping_add(v[2].rotate_left(12))
            .wrapping_add(v[3].rotate_left(18))
    } else {
        seed.wrapping_add(p5)
    };
    // The length mod 2^32, by definition.
    h = h.wrapping_add(data.len() as u32);
    let mut words = stripes.remainder().chunks_exact(4);
    for bytes in &mut words {
        h = h
            .wrapping_add(word(bytes).wrapping_mul(p3))
            .rotate_left(17)
            .wrapping_mul(p4);
    }
    for &b in words.remainder() {
        h = h
            .wrapping_add(u32::from(b).wrapping_mul(p5))
            .rotate_left(11)
            .wrapping_mul(p1);
    }
    h ^= h >> 15;
    h = h.wrapping_mul(p2);
    h ^= h >> 13;
    h = h.wrapping_mul(p3);
    h ^ (h >> 16)
}

/// SipHash-2-4 and xxHash32 against their reference vectors, then the use a
/// keyed hash is for: an open-addressed table of generated keys, whose probe
/// counts depend on every hash; and xxHash32 at every length through two
/// stripes, which is every path through its tail.
fn siphash_xxhash_section(cx: &mut Ctx) {
    let key: [u8; 16] = core::array::from_fn(|i| i as u8);
    assert_eq!(
        siphash24(&key, b""),
        0x726f_db47_dd0e_0e31,
        "SipHash-2-4 of nothing"
    );
    let fifteen: [u8; 15] = core::array::from_fn(|i| i as u8);
    assert_eq!(
        siphash24(&key, &fifteen),
        0xa129_ca61_49be_45e5,
        "SipHash-2-4, the paper's appendix A"
    );
    assert_eq!(xxh32(b"", 0), 0x02cc_5d05, "xxHash32 of nothing");
    assert_eq!(xxh32(b"abc", 0), 0x32d1_53ff, "xxHash32(\"abc\")");

    let mut d = Digest::new();
    let mut key = [0u8; 16];
    cx.rng().fill(&mut key);
    const SLOTS: usize = 64;
    let mut table: [Option<u64>; SLOTS] = [None; SLOTS];
    let mut probes = 0u32;
    for _ in 0..16 + 2 * cx.scale() {
        let value = cx.rng().next_u64() >> cx.rng().below(40);
        let mut slot = (siphash24(&key, &value.to_le_bytes()) % SLOTS as u64) as usize;
        loop {
            probes += 1;
            match table[slot] {
                None => {
                    table[slot] = Some(value);
                    break;
                }
                Some(held) if held == value => break,
                Some(_) => slot = (slot + 1) % SLOTS,
            }
        }
    }
    for entry in table {
        d.u64(entry.map_or(u64::MAX, |v| v));
    }

    let message = cx.rng().bytes(40);
    let seed = cx.rng().next_u32();
    for len in 0..=message.len() {
        d.u32(xxh32(&message[..len], seed));
    }
    let payload = window(cx);
    let body = format!(
        "sip {:016x} xxh32 {:08x} probes {probes} {:016x}",
        siphash24(&key, payload),
        xxh32(payload, seed),
        d.finish()
    );
    cx.section(TAG_SIPHASH_XXHASH, body.as_bytes());
}

// ---------------------------------------------------------------------------
// CRC-32 and Adler-32
// ---------------------------------------------------------------------------

/// The reflected CRC-32 table for the polynomial `0xedb88320`, built at run
/// time into an array on the stack.
fn crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut n = 0;
    while n < 256 {
        let mut c = n as u32;
        let mut bit = 0;
        while bit < 8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            bit += 1;
        }
        table[n] = c;
        n += 1;
    }
    table
}

/// CRC-32 continuing from `crc`, a byte per table lookup.
fn crc32(table: &[u32; 256], crc: u32, data: &[u8]) -> u32 {
    let mut c = !crc;
    for &b in data {
        c = table[usize::from((c as u8) ^ b)] ^ (c >> 8);
    }
    !c
}

/// CRC-32 a bit at a time, no table: the definition the table is a cache of.
fn crc32_bitwise(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            let mask = (c & 1).wrapping_neg();
            c = (c >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !c
}

const ADLER_MOD: u32 = 65_521;

/// Adler-32, reducing after every byte.
fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % ADLER_MOD;
        b = (b + a) % ADLER_MOD;
    }
    (b << 16) | a
}

/// Adler-32 as zlib computes it: reduce once per 5552 bytes, the most that
/// cannot overflow `u32`.
fn adler32_deferred(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for run in data.chunks(5552) {
        for &byte in run {
            a += u32::from(byte);
            b += a;
        }
        a %= ADLER_MOD;
        b %= ADLER_MOD;
    }
    (b << 16) | a
}

/// CRC-32 and Adler-32 against their check values, the table against the
/// bit-at-a-time definition, CRC-32 continued across a split, and Adler-32's
/// deferred reduction against its per-byte one — over the payload, readable,
/// and generated data.
fn checksum_section(cx: &mut Ctx) {
    let table = crc32_table();
    assert_eq!(
        crc32(&table, 0, b"123456789"),
        0xcbf4_3926,
        "the CRC-32 check value"
    );
    assert_eq!(
        adler32(b"Wikipedia"),
        0x11e6_0398,
        "Adler-32(\"Wikipedia\")"
    );

    let payload = cx.payload();
    let len = 200 + 100 * cx.scale() as usize;
    let mut data = cx.rng().bytes(len);
    // Runs of 0xff push Adler-32's sums as fast as they can go.
    let run = cx.rng().index(len);
    data[run..].iter_mut().step_by(3).for_each(|b| *b = 0xff);
    let mut d = Digest::new();
    for message in [payload, &data[..]] {
        let crc = crc32(&table, 0, message);
        let short = &message[..message.len().min(64)];
        assert_eq!(
            crc32(&table, 0, short),
            crc32_bitwise(short),
            "CRC-32 by table and by bit"
        );
        let split = message.len() / 3;
        assert_eq!(
            crc32(
                &table,
                crc32(&table, 0, &message[..split]),
                &message[split..]
            ),
            crc,
            "CRC-32 continued across a split"
        );
        assert_eq!(
            adler32(message),
            adler32_deferred(message),
            "Adler-32 two ways"
        );
        d.u32(crc).u32(adler32(message));
    }
    let body = format!(
        "crc32 {:08x} adler32 {:08x} over {} payload bytes {:016x}",
        crc32(&table, 0, payload),
        adler32(payload),
        payload.len(),
        d.finish()
    );
    cx.section(TAG_CHECKSUMS, body.as_bytes());
}

// ---------------------------------------------------------------------------
// Merkle trees
// ---------------------------------------------------------------------------

/// A binary Merkle tree, every level kept, leaves first. A level of odd length
/// pairs its last node with itself.
struct Merkle<N> {
    levels: Vec<Vec<N>>,
}

impl<N: Copy + PartialEq> Merkle<N> {
    fn build(leaves: Vec<N>, compress: impl Fn(&N, &N) -> N) -> Merkle<N> {
        assert!(!leaves.is_empty(), "a Merkle tree needs a leaf");
        let mut levels = vec![leaves];
        while let Some(level) = levels.last().filter(|level| level.len() > 1) {
            let next = level
                .chunks(2)
                .map(|pair| compress(&pair[0], pair.last().expect("a chunk is never empty")))
                .collect();
            levels.push(next);
        }
        Merkle { levels }
    }

    fn root(&self) -> N {
        self.levels.last().expect("at least the leaves")[0]
    }

    /// The leaf at `index` and its siblings, leaf level first.
    fn proof(&self, index: usize) -> (N, Vec<N>) {
        let leaf = self.levels[0][index];
        let mut siblings = Vec::with_capacity(self.levels.len());
        let mut i = index;
        for level in &self.levels[..self.levels.len() - 1] {
            siblings.push(*level.get(i ^ 1).unwrap_or(&level[i]));
            i /= 2;
        }
        (leaf, siblings)
    }
}

fn merkle_verify<N: Copy + PartialEq>(
    root: &N,
    leaf: N,
    index: usize,
    siblings: &[N],
    compress: impl Fn(&N, &N) -> N,
) -> bool {
    let mut node = leaf;
    let mut i = index;
    for sibling in siblings {
        node = if i.is_multiple_of(2) {
            compress(&node, sibling)
        } else {
            compress(sibling, &node)
        };
        i /= 2;
    }
    node == *root
}

/// SHA-256 of `prefix ‖ parts`: the domain byte keeps a leaf from ever
/// hashing like an inner node.
fn tagged_sha256(prefix: u8, parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&[prefix]);
    for part in parts {
        h.update(part);
    }
    h.finish()
}

fn sha256_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    tagged_sha256(1, &[left, right])
}

/// A SHA-256 Merkle tree over the payload's 32-byte chunks and generated
/// leaves, every inclusion proof verified, and a proof with a flipped sibling
/// bit or the wrong index refused.
fn merkle_section(cx: &mut Ctx) {
    let mut leaves: Vec<[u8; 32]> = window(cx)
        .chunks(32)
        .map(|chunk| tagged_sha256(0, &[chunk]))
        .collect();
    let generated = 3 + cx.scale() as usize + cx.rng().index(3);
    for _ in 0..generated {
        let mut leaf = [0u8; 32];
        cx.rng().fill(&mut leaf);
        leaves.push(tagged_sha256(0, &[&leaf]));
    }
    let count = leaves.len();
    let tree = Merkle::build(leaves, sha256_node);
    let root = tree.root();

    let mut d = Digest::new();
    d.count(count).count(tree.levels.len());
    for index in 0..count {
        let (leaf, siblings) = tree.proof(index);
        assert!(
            merkle_verify(&root, leaf, index, &siblings, sha256_node),
            "the inclusion proof of leaf {index} of {count}"
        );
        let mut bent = siblings.clone();
        let at = cx.rng().index(bent.len());
        bent[at][cx.rng().index(32)] ^= 1;
        assert!(!merkle_verify(&root, leaf, index, &bent, sha256_node));
        let other = (index + 1 + cx.rng().index(count - 1)) % count;
        if tree.proof(other).0 != leaf {
            assert!(!merkle_verify(&root, leaf, other, &siblings, sha256_node));
        }
        for sibling in &siblings {
            d.bytes(sibling);
        }
    }
    if cx.fault(FAULT_PROOF_INDEX) {
        let past = count + cx.rng().index(4);
        tree.proof(black_box(past));
    }
    let body = format!(
        "root {} over {count} leaves {:016x}",
        hex(&root),
        d.finish()
    );
    cx.section(TAG_MERKLE, body.as_bytes());
}

// ---------------------------------------------------------------------------
// The repository's field and permutation
// ---------------------------------------------------------------------------

/// A field element from generated bytes, cleared to 253 bits so it is always
/// below the modulus.
fn random_fr(cx: &mut Ctx) -> Fr {
    let mut bytes = [0u8; 32];
    cx.rng().fill(&mut bytes);
    bytes[31] &= 0x1f;
    Fr::from_bytes(&bytes).expect("below 2^253 < p")
}

/// `field::Fr`: the canonical wire form and its refusals, ring identities over
/// generated elements, and inversion two ways — Fermat per element and
/// Montgomery's batch trick — each held to `a * a^-1 = 1`.
fn field_section(cx: &mut Ctx) {
    let minus_one = Fr::MINUS_ONE.to_bytes();
    let mut modulus = minus_one;
    // p - 1 ends in a zero byte, so p is it with that byte 1.
    modulus[0] += 1;
    assert_eq!(
        Fr::from_bytes(&minus_one),
        Some(Fr::MINUS_ONE),
        "p - 1 is canonical"
    );
    assert_eq!(Fr::from_bytes(&modulus), None, "p is not");
    assert_eq!(Fr::ONE.to_bytes()[..2], [1, 0], "one is 1, not R");

    // Uniform 32-byte strings: about one in five is below p.
    let mut canonical = 0u32;
    for _ in 0..8 {
        let mut bytes = [0u8; 32];
        cx.rng().fill(&mut bytes);
        canonical += u32::from(Fr::from_bytes(&bytes).is_some());
    }

    let count = 3 + cx.scale() as usize;
    let elements: Vec<Fr> = (0..count)
        .map(|k| {
            if k % 2 == 0 {
                Fr::from_u64(cx.rng().next_u64())
            } else {
                random_fr(cx)
            }
        })
        .collect();

    let mut d = Digest::new();
    let mut sum = Fr::ZERO;
    let mut product = Fr::ONE;
    for (k, pair) in elements.windows(2).enumerate() {
        let (a, b) = (pair[0], pair[1]);
        let ab = a * b;
        assert_eq!(
            (a + b).square(),
            a.square() + ab + ab + b.square(),
            "(a + b)^2"
        );
        assert_eq!((a + b) * (a - b), a.square() - b.square(), "(a + b)(a - b)");
        assert_eq!(a + (-a), Fr::ZERO, "a + -a");
        // `pow` walks all 256 bits of its exponent, which on the guest's
        // opt-level-0 build is millions of cycles: once is the check that it
        // agrees with multiplication, not once a pair.
        if k == 0 {
            assert_eq!(a.pow(&[3, 0, 0, 0]), a * a * a, "a^3");
        }
        sum += ab;
        product *= a - b;
        d.bytes(&ab.to_bytes());
    }

    let mut inverses = elements.clone();
    inverses.push(Fr::ZERO);
    batch_inverse(&mut inverses);
    assert_eq!(
        inverses.last(),
        Some(&Fr::ZERO),
        "batch inversion leaves zero alone"
    );
    for (x, inverse) in elements.iter().zip(&inverses) {
        assert_eq!(*x * inverse, Fr::ONE, "a * a^-1");
        d.bytes(&inverse.to_bytes());
    }
    // Fermat's inversion against the batch trick: a second full 256-bit
    // exponentiation, so from scale 1 up rather than on every run.
    if cx.scale() > 0 {
        assert_eq!(
            elements[0].inverse().as_ref(),
            inverses.first(),
            "Fermat and the batch trick"
        );
    }

    if cx.fault(FAULT_ZERO_INVERSE) {
        // Zero by computation: an element less its own round trip through
        // the wire form.
        let a = elements[cx.rng().index(count)];
        let zero = black_box(a) - Fr::from_bytes(&a.to_bytes()).expect("canonical");
        zero.inverse()
            .expect("a field element that is zero has no inverse");
    }

    let mut body = Vec::with_capacity(73);
    body.extend_from_slice(&sum.to_bytes());
    body.extend_from_slice(&product.to_bytes());
    body.push(canonical as u8);
    body.extend_from_slice(&d.finish().to_le_bytes());
    cx.section(TAG_FIELD, &body);
}

/// Two field elements to one: the permutation's first lane over `[l, r, 0]`.
fn poseidon2_node(left: &Fr, right: &Fr) -> Fr {
    let mut state = [*left, *right, Fr::ZERO];
    poseidon2_permute(&mut state);
    state[0]
}

/// `transcript::poseidon2_permute` against its `[0, 1, 2]` known answer, a
/// Poseidon2 Merkle tree — the shape `guests/vault` verifies — with every
/// proof checked, and the payload absorbed into the repository's own duplex
/// sponge, 31 bytes a limb as `append_bytes` packs it.
fn poseidon2_section(cx: &mut Ctx) {
    let mut state = [0, 1, 2].map(Fr::from_u64);
    poseidon2_permute(&mut state);
    let expected = [
        "33304a4f0560f747f8a48ea94d333481320f65829a92b1bcee55cada241db60b",
        "7035d0f87ffede924965ca743f5da17702a3264f2180cccbbf43d0867c6f3b30",
        "c86e76cf42622986cc27449945b160e6527cbac3617361f8ee122b549451d21e",
    ];
    for (lane, hex) in state.iter().zip(expected) {
        assert_eq!(lane.to_bytes(), unhex(hex), "Poseidon2([0, 1, 2])");
    }

    // One Poseidon2 permutation is millions of cycles at opt-level 0: a tree of
    // `count` leaves is `count - 1` of them and verifying a proof is as many
    // again. The known answer above already covers the permutation, so the tree
    // runs from scale 1 up, and grows slowly from there.
    let root = if cx.scale() > 0 {
        let count = 2 + cx.scale() as usize / 4;
        let leaves: Vec<Fr> = (0..count).map(|_| random_fr(cx)).collect();
        let tree = Merkle::build(leaves, poseidon2_node);
        let root = tree.root();
        let index = cx.rng().index(count);
        let (leaf, siblings) = tree.proof(index);
        assert!(merkle_verify(&root, leaf, index, &siblings, poseidon2_node));
        root
    } else {
        // Not a permutation, but not a constant either: a section whose whole
        // body is fixed says nothing about the input it was given, and scale 0
        // is what the cheapest corpus inputs use.
        let len = cx.payload().len() as u64 + 1;
        random_fr(cx) * Fr::from_u64(len)
    };

    // Squeezing the duplex sponge costs another permutation, so the payload
    // goes through it from scale 1 up.
    let squeezed = if cx.scale() > 0 {
        let mut sponge = Transcript::new();
        let payload = window(cx);
        sponge.observe(Fr::from_u64(payload.len() as u64));
        for chunk in payload.chunks(31) {
            let mut limb = [0u8; 32];
            limb[..chunk.len()].copy_from_slice(chunk);
            sponge.observe(Fr::from_bytes(&limb).expect("below 2^248"));
        }
        sponge.sample()
    } else {
        Fr::ZERO
    };

    let mut body = Vec::with_capacity(96);
    body.extend_from_slice(&state[0].to_bytes());
    body.extend_from_slice(&root.to_bytes());
    body.extend_from_slice(&squeezed.to_bytes());
    cx.section(TAG_POSEIDON2, &body);
}

// ---------------------------------------------------------------------------
// 64-bit modular arithmetic
// ---------------------------------------------------------------------------

/// `a * b mod m` through `u128`: on RV32 a `__multi3` and a `__umodti3`.
fn mul_mod(a: u64, b: u64, m: u64) -> u64 {
    (u128::from(a) * u128::from(b) % u128::from(m)) as u64
}

/// `a + b mod m` for `a, b < m`, where the sum may pass `u64::MAX`.
fn add_mod(a: u64, b: u64, m: u64) -> u64 {
    let (sum, wrapped) = a.overflowing_add(b);
    if wrapped || sum >= m {
        sum.wrapping_sub(m)
    } else {
        sum
    }
}

/// `a * b mod m` by doubling and adding, no wider type at all: the
/// cross-check on [`mul_mod`].
fn mul_mod_doubling(a: u64, b: u64, m: u64) -> u64 {
    let (mut a, mut b, mut product) = (a % m, b, 0);
    while b != 0 {
        if b & 1 == 1 {
            product = add_mod(product, a, m);
        }
        a = add_mod(a, a, m);
        b >>= 1;
    }
    product
}

fn pow_mod(base: u64, exp: u64, m: u64) -> u64 {
    let (mut base, mut exp, mut acc) = (base % m, exp, 1 % m);
    while exp != 0 {
        if exp & 1 == 1 {
            acc = mul_mod(acc, base, m);
        }
        base = mul_mod(base, base, m);
        exp >>= 1;
    }
    acc
}

/// Arithmetic modulo an odd `n < 2^63` in Montgomery form: the shape primality
/// code is actually written in, because it replaces the `u128` remainder in
/// [`mul_mod`] — a `__umodti3` call on RV32, and a tenth of a Miller-Rabin
/// round's cost — with two wide products and a conditional subtraction.
struct Montgomery {
    n: u64,
    /// `-n^-1 mod 2^64`.
    neg_inv: u64,
    /// `R^2 mod n`, for entering the form.
    r2: u64,
}

impl Montgomery {
    /// `n` must be odd and below `2^63`, which is what keeps `t + m n` inside
    /// `u128` in [`Montgomery::mul`].
    fn new(n: u64) -> Montgomery {
        assert!(
            n % 2 == 1 && n < 1 << 63,
            "a Montgomery modulus is odd and below 2^63"
        );
        // n^-1 mod 2^64 by Newton: n * n = 1 mod 8, and each step doubles the
        // correct low bits, so five steps carry 3 bits to 96.
        let mut inv = n;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(n.wrapping_mul(inv)));
        }
        debug_assert_eq!(n.wrapping_mul(inv), 1, "the inverse mod 2^64");
        let r = (u128::from(u64::MAX) + 1) % u128::from(n);
        Montgomery {
            n,
            neg_inv: inv.wrapping_neg(),
            r2: mul_mod(r as u64, r as u64, n),
        }
    }

    /// REDC: `a b R^-1 mod n`.
    fn mul(&self, a: u64, b: u64) -> u64 {
        let t = u128::from(a) * u128::from(b);
        let m = (t as u64).wrapping_mul(self.neg_inv);
        let u = ((t + u128::from(m) * u128::from(self.n)) >> 64) as u64;
        if u >= self.n {
            u - self.n
        } else {
            u
        }
    }

    fn to_form(&self, a: u64) -> u64 {
        self.mul(a % self.n, self.r2)
    }

    fn pow(&self, base: u64, exp: u64) -> u64 {
        let (mut acc, mut base, mut exp) = (self.to_form(1), self.to_form(base), exp);
        while exp != 0 {
            if exp & 1 == 1 {
                acc = self.mul(acc, base);
            }
            base = self.mul(base, base);
            exp >>= 1;
        }
        acc
    }
}

/// Deterministic Miller-Rabin for all of `u64`: these seven bases leave no
/// strong pseudoprime below 2^64 (Jim Sinclair's set).
fn is_prime(n: u64) -> bool {
    const SMALL: [u64; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
    assert!(
        n < 1 << 63,
        "primality here stops where Montgomery's bound does"
    );
    if n < 2 {
        return false;
    }
    if let Some(p) = SMALL.iter().find(|&&p| n.is_multiple_of(p)) {
        return n == *p;
    }
    let m = Montgomery::new(n);
    let (one, minus_one) = (m.to_form(1), m.to_form(n - 1));
    let s = (n - 1).trailing_zeros();
    let d = (n - 1) >> s;
    'bases: for base in [2, 325, 9375, 28178, 450_775, 9_780_504, 1_795_265_022] {
        let base = base % n;
        if base == 0 {
            continue;
        }
        let mut x = m.pow(base, d);
        if x == one || x == minus_one {
            continue;
        }
        for _ in 1..s {
            x = m.mul(x, x);
            if x == minus_one {
                continue 'bases;
            }
        }
        return false;
    }
    true
}

/// `u64` modular arithmetic through `u128` against a doubling cross-check,
/// Miller-Rabin against known primes and pseudoprimes, and a search for the
/// next prime after generated odd numbers.
fn primes_section(cx: &mut Ctx) {
    for (n, prime) in [
        (0, false),
        (1, false),
        (2, true),
        (3, true),
        // A Carmichael number, and the least strong pseudoprime to base 2:
        // the two a weaker test gets wrong.
        (561, false),
        (2_047, false),
        (65_537, true),
        (1_000_000_007, true),
        // Strong pseudoprime to bases 2, 3, 5 and 7 at once.
        (3_215_031_751, false),
        // The Mersenne prime 2^61 - 1.
        ((1u64 << 61) - 1, true),
    ] {
        assert_eq!(is_prime(n), prime, "is_prime({n})");
    }

    let mut d = Digest::new();
    for _ in 0..4 + 2 * cx.scale() {
        let m = (cx.rng().next_u64() >> 1) | 1;
        let (a, b) = (cx.rng().next_u64(), cx.rng().next_u64());
        let product = mul_mod(a, b, m);
        assert_eq!(product, mul_mod_doubling(a, b, m), "a * b mod m, two ways");
        d.u64(product);
    }

    let mut lines = String::new();
    for _ in 0..1 + cx.scale() / 4 {
        let bits = 20 + cx.rng().below(44);
        let start = (cx.rng().next_u64() >> (64 - bits)) | 1;
        let mut candidate = start;
        while !is_prime(candidate) {
            candidate += 2;
        }
        // Fermat: a^(p-1) = 1 for a prime p and any a it does not divide.
        // `.max(1)`: the search can land on 3, and `below(0)` asserts.
        let a = 2 + cx.rng().below((candidate - 3).max(1));
        assert_eq!(
            pow_mod(a, candidate - 1, candidate),
            1,
            "Fermat's little theorem"
        );
        lines.push_str(&format!("{start} -> {candidate}\n"));
    }

    if cx.fault(FAULT_NARROW_MULMOD) {
        let m = (1 << 61) - 1;
        let (a, b) = (cx.rng().next_u64() % m, cx.rng().next_u64() % m);
        black_box(black_box(a | (1 << 40)) * black_box(b | (1 << 40)) % m);
    }

    lines.push_str(&format!("{:016x}", d.finish()));
    cx.section(TAG_PRIMES, lines.as_bytes());
}

fn gcd_euclid(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// Stein's binary gcd: shifts and subtractions, `trailing_zeros` for the
/// powers of two.
fn gcd_binary(mut a: u64, mut b: u64) -> u64 {
    if a == 0 || b == 0 {
        return a | b;
    }
    let shift = (a | b).trailing_zeros();
    a >>= a.trailing_zeros();
    loop {
        b >>= b.trailing_zeros();
        if a > b {
            core::mem::swap(&mut a, &mut b);
        }
        b -= a;
        if b == 0 {
            return a << shift;
        }
    }
}

/// `(g, x, y)` with `a x + b y = g`, in `i128` so the coefficients of two
/// `u64`s fit.
fn extended_gcd(a: u64, b: u64) -> (i128, i128, i128) {
    let (mut r0, mut r1) = (i128::from(a), i128::from(b));
    let (mut x0, mut x1) = (1i128, 0i128);
    let (mut y0, mut y1) = (0i128, 1i128);
    while r1 != 0 {
        let q = r0 / r1;
        (r0, r1) = (r1, r0 - q * r1);
        (x0, x1) = (x1, x0 - q * x1);
        (y0, y1) = (y1, y0 - q * y1);
    }
    (r0, x0, y0)
}

fn inverse_mod(a: u64, m: u64) -> Option<u64> {
    let (g, x, _) = extended_gcd(a, m);
    (g == 1).then(|| x.rem_euclid(i128::from(m)) as u64)
}

/// gcd two ways, Bézout's identity checked in `i128`, modular inverses from
/// the extended algorithm against Fermat's, and `lcm` through `checked_mul`.
fn gcd_section(cx: &mut Ctx) {
    let mut d = Digest::new();
    let mut overflowed = 0u32;
    let prime = u64::MAX - 58;
    // Each round is two gcds, an extended gcd and a Bézout check in `i128`,
    // whose division is a compiler-builtins call on RV32: about a million
    // cycles a round at opt-level 0.
    for _ in 0..2 + cx.scale() {
        let shared = 1 + cx.rng().below(1000);
        let a = (cx.rng().next_u64() >> cx.rng().below(60)) / shared * shared;
        let b = (cx.rng().next_u64() >> cx.rng().below(60)) / shared * shared;
        let g = gcd_euclid(a, b);
        assert_eq!(g, gcd_binary(a, b), "gcd({a}, {b}) two ways");
        let (eg, x, y) = extended_gcd(a, b);
        assert_eq!(eg, i128::from(g), "the extended gcd's gcd");
        assert_eq!(
            i128::from(a) * x + i128::from(b) * y,
            eg,
            "Bézout for ({a}, {b})"
        );
        // lcm(a, b) = a / g * b, which overflows `u64` for most pairs; g is
        // zero only when both are.
        match a.checked_div(g).map(|q| q.checked_mul(b)) {
            Some(Some(lcm)) => {
                d.u64(lcm);
            }
            Some(None) => overflowed += 1,
            None => {}
        }
        if !a.is_multiple_of(prime) {
            let inverse = inverse_mod(a, prime);
            assert_eq!(inverse, Some(pow_mod(a, prime - 2, prime)), "a^-1 two ways");
        }
        d.u64(g).i128(x).i128(y);
    }
    let body = format!("lcm overflowed {overflowed} {:016x}", d.finish());
    cx.section(TAG_GCD, body.as_bytes());
}

// ---------------------------------------------------------------------------
// Integer roots
// ---------------------------------------------------------------------------

/// `floor(cbrt(n))`, a bit at a time from the top: every cube is a `u128`
/// product, checked.
fn icbrt(n: u128) -> u128 {
    let mut root = 0u128;
    for bit in (0..43).rev() {
        let candidate = root | (1 << bit);
        let cube = candidate
            .checked_mul(candidate)
            .and_then(|square| square.checked_mul(candidate));
        if cube.is_some_and(|cube| cube <= n) {
            root = candidate;
        }
    }
    root
}

/// `floor(sqrt(n))` by Newton's iteration from above, in `u128` division.
fn isqrt_newton(n: u128) -> u128 {
    if n < 2 {
        return n;
    }
    let mut x = 1u128 << (128 - n.leading_zeros()).div_ceil(2);
    loop {
        let next = (x + n / x) / 2;
        if next >= x {
            return x;
        }
        x = next;
    }
}

/// SHA-256's constants from their definition — the first 32 fractional bits
/// of the square roots of the first 8 primes, and of the cube roots of the
/// first 64 — by integer roots of `p * 2^64` and `p * 2^96` in `u128`, held to
/// the tables [`sha256_section`]'s known answers already vouch for; and
/// `u128::isqrt` against Newton's iteration on generated values.
fn roots_section(cx: &mut Ctx) {
    let primes: Vec<u64> = (2u64..).filter(|&n| is_prime(n)).take(64).collect();
    for (h, p) in SHA256_H0.iter().zip(&primes) {
        assert_eq!(
            isqrt_newton(u128::from(*p) << 64) as u32,
            *h,
            "the square root of {p}"
        );
    }
    let derived = (8 + 4 * cx.scale() as usize).min(64);
    for (k, p) in SHA256_K.iter().zip(&primes).take(derived) {
        assert_eq!(
            icbrt(u128::from(*p) << 96) as u32,
            *k,
            "the cube root of {p}"
        );
    }

    let mut d = Digest::new();
    for _ in 0..4 + cx.scale() {
        let n =
            u128::from(cx.rng().next_u64()) << cx.rng().below(64) | u128::from(cx.rng().next_u32());
        let root = n.isqrt();
        assert_eq!(root, isqrt_newton(n), "isqrt({n}) two ways");
        assert!(root * root <= n && (root + 1).checked_mul(root + 1).is_none_or(|s| s > n));
        d.u128(root).u128(icbrt(n));
    }
    let body = format!("H0 and K[..{derived}] re-derived {:016x}", d.finish());
    cx.section(TAG_ROOTS, body.as_bytes());
}
