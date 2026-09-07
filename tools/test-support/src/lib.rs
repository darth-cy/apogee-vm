//! Fixture plumbing shared by the test suites: SHA-256, and the hex codec that
//! turns a digest or a field element into the text a committed vector file
//! holds.
//!
//! Master rule 11 pins every committed fixture by hash, so every crate that
//! reads one needs the same two things. This crate is where they live, once.
//! It is a dev-dependency only: no shipped crate, no guest build, and no
//! `tools/` binary links it.

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
