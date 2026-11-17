//! HashToPoint and KeyDigest: functions of their inputs, into their ranges,
//! and moved by any bit of them.

use apogee_falcon512::{hash_to_point, key_digest, keygen};

/// `p = 2^64 − 59`.
const P: u64 = 0xFFFF_FFFF_FFFF_FFC5;

fn flip(bytes: &[u8], at: usize, bit: u32) -> Vec<u8> {
    let mut bytes = bytes.to_vec();
    bytes[at] ^= 1 << bit;
    bytes
}

/// The same inputs give the same point, each coefficient below `q`.
#[test]
fn the_point_is_a_function_into_z_q() {
    let (_, pk) = keygen([0x5a; 32]);
    let c = hash_to_point(&pk, &[7; 40], b"a message");
    assert_eq!(c, hash_to_point(&pk, &[7; 40], b"a message"));
    assert!(c.iter().all(|&x| x < 12289));
}

/// The first or the last bit of the key, the salt or the message flipped, or a
/// zero byte appended to the message, which the length tells apart: each moves
/// the point.
#[test]
fn any_input_bit_moves_the_point() {
    let (_, pk) = keygen([0x5a; 32]);
    let salt = [7; 40];
    let msg: Vec<u8> = (0..64).collect();
    let c = hash_to_point(&pk, &salt, &msg);
    for (at, bit) in [(0, 7), (896, 0)] {
        assert_ne!(hash_to_point(&flip(&pk, at, bit), &salt, &msg), c);
    }
    for (at, bit) in [(0, 7), (39, 0)] {
        let salt = flip(&salt, at, bit).try_into().unwrap();
        assert_ne!(hash_to_point(&pk, &salt, &msg), c);
    }
    for (at, bit) in [(0, 7), (63, 0)] {
        assert_ne!(hash_to_point(&pk, &salt, &flip(&msg, at, bit)), c);
    }
    assert_ne!(hash_to_point(&pk, &salt, &[&msg[..], &[0]].concat()), c);
}

/// A key's digest is eight canonical lanes, and a key one bit off has another.
#[test]
fn the_key_digest_is_canonical_and_binds_the_key() {
    let (_, pk) = keygen([0x5a; 32]);
    let digest = key_digest(&pk);
    assert!(digest.iter().all(|&x| x < P));
    assert_ne!(key_digest(&flip(&pk, 500, 0)), digest);
}
