//! Keys from a seed, signatures, and the verifier: what is signed verifies
//! under its context, and nothing altered does.

use apogee_falcon512::{
    hash_to_point, keygen, sign, verify, verify_point, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES,
    SIGNATURE_BYTES,
};

/// The message of `len` bytes under `seed`.
fn message(seed: &[u8; 32], len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(29) ^ seed[0])
        .collect()
}

/// Keys from two seeds, and their signatures of messages of 0, 92 and 200
/// bytes under an empty context, a 255-byte one and a short one: each
/// verifies.
#[test]
fn signatures_verify() {
    for seed in [[0x5a; 32], [0xc3; 32]] {
        let (sk, pk) = keygen(seed);
        assert_eq!((sk.len(), pk.len()), (SECRET_KEY_BYTES, PUBLIC_KEY_BYTES));
        let cases: [(usize, &[u8]); 3] = [(0, &[]), (92, &[0xa5; 255]), (200, b"a context")];
        for (len, context) in cases {
            let msg = message(&seed, len);
            let sig = sign(&sk, &msg, context);
            assert_eq!((sig.len(), sig[0]), (SIGNATURE_BYTES, 0x39));
            assert!(verify(&pk, &msg, &sig, context));
        }
    }
}

/// A bit of the signature's salt or `s2`, of the message, of the context or
/// of the key flipped, or the context left out: none verifies. Signing is
/// randomized: two signatures of one message differ.
#[test]
fn an_altered_signature_message_context_or_key_does_not_verify() {
    let seed = [0x5a; 32];
    let (sk, pk) = keygen(seed);
    let (msg, context) = (message(&seed, 92), b"a context");
    let sig = sign(&sk, &msg, context);
    let flip = |bytes: &[u8], at: usize, bit: u32| {
        let mut bytes = bytes.to_vec();
        bytes[at] ^= 1 << bit;
        bytes
    };
    assert!(verify(&pk, &msg, &sig, context));
    assert!(!verify(&pk, &msg, &flip(&sig, 20, 2), context));
    assert!(!verify(&pk, &msg, &flip(&sig, 100, 6), context));
    assert!(!verify(&pk, &flip(&msg, 91, 7), &sig, context));
    assert!(!verify(&pk, &msg, &sig, &flip(context, 8, 0)));
    assert!(!verify(&pk, &msg, &sig, &[]));
    assert!(!verify(&flip(&pk, 500, 0), &msg, &sig, context));
    assert_ne!(sign(&sk, &msg, context), sig);
}

/// Signing refuses a context over 255 bytes.
#[test]
#[should_panic(expected = "a context is at most 255 bytes")]
fn signing_refuses_a_context_over_255_bytes() {
    let (sk, _) = keygen([0x5a; 32]);
    sign(&sk, b"", &[0; 256]);
}

/// Coefficient `i` of an encoded key's `h`: the 14 bits from bit `8 + 14i`,
/// most significant first.
fn coefficient(pk: &[u8], i: usize) -> u16 {
    (8 + 14 * i..8 + 14 * (i + 1)).fold(0, |x, bit| {
        x << 1 | (pk[bit / 8] >> (7 - bit % 8) & 1) as u16
    })
}

/// The key with one coefficient `h_i` written `h_i + q`, the same `h` mod `q`,
/// does not decode: for the same point, the signature that verifies under the
/// key does not under it.
#[test]
fn a_coefficient_at_least_q_does_not_decode() {
    let seed = [0xc3; 32];
    let (sk, pk) = keygen(seed);
    let msg = message(&seed, 92);
    let sig = sign(&sk, &msg, &[]);
    let c = hash_to_point(&pk, sig[1..41].try_into().unwrap(), &msg, &[]);
    let i = (0..512)
        .find(|&i| coefficient(&pk, i) < (1 << 14) - 12289)
        .unwrap();
    let mut key = pk.clone();
    for (k, bit) in (8 + 14 * i..8 + 14 * (i + 1)).enumerate() {
        let one = (coefficient(&pk, i) + 12289) >> (13 - k) & 1;
        key[bit / 8] = key[bit / 8] & !(1 << (7 - bit % 8)) | (one as u8) << (7 - bit % 8);
    }
    assert_eq!(coefficient(&key, i), coefficient(&pk, i) + 12289);
    assert!(verify_point(&pk, &c, &sig));
    assert!(!verify_point(&key, &c, &sig));
}
