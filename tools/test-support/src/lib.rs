//! Fixture plumbing shared by the test suites and the fixture generators:
//! a seeded RNG, SHA-256, and the hex codec that turns a digest or a field
//! element into the text a committed vector file holds.
//!
//! Master rule 11 pins every committed fixture by hash and wants fixtures that
//! regenerate byte for byte, so every crate that writes or reads one needs the
//! same three things. This crate is where they live, once.
//!
//! **It has no dependencies, and must never acquire any.** That is what lets
//! `tools/transcript-ref` — the reference oracle, deliberately outside the
//! workspace so its Plonky3 and `zkhash` graphs cannot unify a feature into
//! `crates/field` — link it without linking anything of ours that it is
//! supposed to be checking. `no_dependencies` below is the executable form of
//! that rule.

// ---------------------------------------------------------------------------
// Deterministic RNG
// ---------------------------------------------------------------------------

/// splitmix64. Owned so that a committed fixture's input stream cannot move
/// under it when some RNG crate changes its algorithm in a minor release.
///
/// Only the raw stream lives here. Turning it into a field element is the
/// caller's job, because every caller wants something different: rejection
/// sampling to canonical bytes, reduction mod p, a nonzero value, or the
/// unreduced limbs of an exponent.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Four limbs, little-endian: a 256-bit integer, unreduced. Used as a `pow`
    /// exponent, where reduction would defeat the point.
    pub fn next_exp(&mut self) -> [u64; 4] {
        [
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
            self.next_u64(),
        ]
    }

    /// The same four limbs as bytes — a 256-bit little-endian integer, and the
    /// raw material every caller's field-element sampler starts from.
    pub fn next_le32(&mut self) -> [u8; 32] {
        let mut b = [0u8; 32];
        for (i, limb) in self.next_exp().iter().enumerate() {
            b[8 * i..8 * i + 8].copy_from_slice(&limb.to_le_bytes());
        }
        b
    }

    /// One byte per draw. Deliberately wasteful of the stream, and frozen that
    /// way: the committed transcript cases were generated with it.
    pub fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next_u64() as u8).collect()
    }
}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

/// Lowercase hex, the form every committed vector file is written in.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 * bytes.len());
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// A fixed 32-byte value: a field element on the wire, or a digest.
pub fn hex_to_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", s.len()));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16)
            .map_err(|_| format!("bad hex byte at {i}"))?;
    }
    Ok(out)
}

/// A variable-length byte string.
pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd hex length {}", s.len()));
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| format!("bad hex byte at {i}"))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// SHA-256 (FIPS 180-4). Pins committed fixture files by content.
//
// Owned rather than taken as a dependency: it is 60 lines, it is checked
// against the NIST vectors below, and a fixture pin that depends on a crates.io
// version is a fixture pin with a moving part in it.
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let mut msg = data.to_vec();
    let bitlen = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v = [
                t1.wrapping_add(t2),
                v[0],
                v[1],
                v[2],
                v[3].wrapping_add(t1),
                v[4],
                v[5],
                v[6],
            ];
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }

    let mut out = [0u8; 32];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The published splitmix64 reference stream for seed 0. This is the
    /// generator every committed fixture's input sequence comes out of, so it
    /// is pinned against the algorithm, not against our own output.
    #[test]
    fn rng_is_splitmix64() {
        let mut r = Rng::new(0);
        assert_eq!(
            [r.next_u64(), r.next_u64(), r.next_u64(), r.next_u64()],
            [
                0xe220_a839_7b1d_cdaf,
                0x6e78_9e6a_a1b9_65f4,
                0x06c4_5d18_8009_454f,
                0xf88b_b8a8_724c_81ec
            ]
        );
        // The two seeds the committed fixtures are generated from.
        assert_eq!(Rng::new(20260903).next_u64(), 0x2e76_1edb_4a84_3ed2);
        assert_eq!(Rng::new(20260907).next_u64(), 0xad2e_a8a7_7120_2a78);
    }

    /// `next_le32` must be exactly `next_exp` written out little-endian: the
    /// callers that sample a field element and the callers that sample an
    /// exponent have to be drawing from the same stream, in the same order.
    #[test]
    fn next_le32_is_next_exp_little_endian() {
        let limbs = Rng::new(7).next_exp();
        let bytes = Rng::new(7).next_le32();
        for (i, limb) in limbs.iter().enumerate() {
            assert_eq!(bytes[8 * i..8 * i + 8], limb.to_le_bytes());
        }
    }

    /// A generator that repeats, or that ignores its seed, would silently
    /// hollow out every fixture built on it.
    #[test]
    fn rng_is_seeded_and_does_not_repeat() {
        let mut r = Rng::new(20260903);
        let draws: Vec<u64> = (0..1000).map(|_| r.next_u64()).collect();
        let mut sorted = draws.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), draws.len(), "1000 draws must be distinct");
        assert_ne!(Rng::new(1).next_u64(), Rng::new(2).next_u64());
        assert_eq!(Rng::new(1).next_bytes(16), Rng::new(1).next_bytes(16));
    }

    /// Every dependency this manifest declares, or `Err` if it has no
    /// `[dependencies]` table at all — which would make an empty answer a lie.
    /// Table headers only: the manifest's own prose mentions
    /// `[dev-dependencies]`, and a substring scan would trip over it.
    fn declared_dependencies(manifest: &str) -> Result<Vec<String>, String> {
        let header = |l: &str| {
            let l = l.trim();
            l.starts_with('[') && l.ends_with(']')
        };
        let mut saw_dependencies = false;
        let mut declared = Vec::new();
        let mut table = "";
        for line in manifest.lines() {
            if header(line) {
                table = line.trim();
                if table.ends_with("dependencies]") {
                    if table == "[dependencies]" {
                        saw_dependencies = true;
                    } else {
                        return Err(format!("unexpected dependency table {table}"));
                    }
                }
                continue;
            }
            let body = line.trim();
            if table == "[dependencies]" && !body.is_empty() && !body.starts_with('#') {
                declared.push(body.to_string());
            }
        }
        if !saw_dependencies {
            return Err("no [dependencies] table to check".to_string());
        }
        Ok(declared)
    }

    /// The load-bearing property of this crate, per the module docs: nothing in
    /// `[dependencies]`. `tools/transcript-ref` links it, and anything added
    /// here would reach the reference oracle.
    #[test]
    fn no_dependencies() {
        assert_eq!(
            declared_dependencies(include_str!("../Cargo.toml")),
            Ok(Vec::new()),
            "test-support must stay dependency-free"
        );
    }

    /// Negative control: the check above has to be able to fail.
    #[test]
    fn a_declared_dependency_is_caught() {
        assert_eq!(
            declared_dependencies("[package]\nname = \"x\"\n\n[dependencies]\nfield = \"1\"\n"),
            Ok(vec!["field = \"1\"".to_string()])
        );
        assert!(
            declared_dependencies("[package]\n\n[dev-dependencies]\nfield = \"1\"\n").is_err(),
            "a dependency smuggled into another table is still a dependency"
        );
        assert!(
            declared_dependencies("[package]\nname = \"x\"\n").is_err(),
            "a manifest with no [dependencies] table cannot answer the question"
        );
    }

    /// Every fixture pin in the repository is only as good as this hash.
    /// FIPS 180-4 appendix B, plus the empty string.
    #[test]
    fn sha256_matches_nist_vectors() {
        assert_eq!(
            to_hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            to_hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // 56 bytes: the padding spills into a second block, so this is the one
        // that exercises the multi-block path the other two never reach.
        assert_eq!(
            to_hex(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    /// The block boundary itself, either side of it, and a length that needs a
    /// whole extra block for the padding alone.
    #[test]
    fn sha256_pads_every_block_boundary() {
        // NIST's 1,000,000-'a' vector, which is 15625 whole blocks plus padding.
        assert_eq!(
            to_hex(&sha256(&[b'a'; 1_000_000])),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
        // 55 is the largest length whose padding still fits its own block; 56
        // is the smallest that does not; 64 is a whole block of message.
        for len in [55usize, 56, 63, 64, 65, 119, 120] {
            let digest = sha256(&vec![0u8; len]);
            assert_ne!(digest, [0u8; 32], "length {len} must hash to something");
        }
    }

    #[test]
    fn hex_round_trips() {
        let bytes: Vec<u8> = (0..=255u8).collect();
        assert_eq!(hex_to_bytes(&to_hex(&bytes)).unwrap(), bytes);

        let mut digest = [0u8; 32];
        digest.copy_from_slice(&bytes[..32]);
        assert_eq!(hex_to_32(&to_hex(&digest)).unwrap(), digest);

        assert_eq!(to_hex(&[0x0f, 0xa0]), "0fa0");
        assert_eq!(to_hex(&[]), "");
        assert_eq!(hex_to_bytes("").unwrap(), Vec::<u8>::new());
    }

    /// The parsers exist to reject a malformed vector file, so they have to.
    #[test]
    fn hex_rejects_malformed_input() {
        assert!(hex_to_32("00").is_err(), "short");
        assert!(hex_to_32(&"0".repeat(65)).is_err(), "odd length");
        assert!(hex_to_32(&"g".repeat(64)).is_err(), "not a hex digit");
        assert!(hex_to_bytes("abc").is_err(), "odd length");
        assert!(hex_to_bytes("zz").is_err(), "not a hex digit");
    }
}
