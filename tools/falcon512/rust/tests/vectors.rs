//! The shared vectors, `tools/falcon512/vectors.json`, which the JS and
//! Python suites read too: HashToPoint's points and KeyDigest's digests as all
//! three implementations compute them, signatures each made, and malformed
//! signatures and keys every verifier refuses. `standard_kat` is `kat.rs`'s.

use apogee_falcon512::{hash_to_point, key_digest, verify};
use serde_json::Value;

/// The entries of one section, at least one.
fn vectors(section: &str) -> Vec<Value> {
    let vectors: Value =
        serde_json::from_str(include_str!("../../vectors.json")).expect("the vectors are JSON");
    let entries = vectors[section].as_array().expect("a section is an array");
    assert!(!entries.is_empty(), "{section} is empty");
    entries.clone()
}

fn bytes(hex: &Value) -> Vec<u8> {
    test_support::hex_to_bytes(hex.as_str().expect("a hex string")).expect("hex")
}

/// A digest lane, `0x` and hex digits.
fn lane(x: &Value) -> u64 {
    let hex = x.as_str().and_then(|x| x.strip_prefix("0x"));
    u64::from_str_radix(hex.expect("a 0x lane"), 16).expect("a 64-bit lane")
}

#[test]
fn hash_to_point_gives_the_vectors_points() {
    for v in vectors("hash_to_point") {
        let (pk, msg) = (bytes(&v["pk"]), bytes(&v["msg"]));
        let salt = bytes(&v["salt"]).try_into().expect("a 40-byte salt");
        let c: Vec<u16> = serde_json::from_value(v["c"].clone()).expect("c");
        assert_eq!(hash_to_point(&pk, &salt, &msg).to_vec(), c);
    }
}

#[test]
fn key_digest_gives_the_vectors_digests() {
    for v in vectors("key_digest") {
        let lanes = v["digest"].as_array().expect("lanes");
        let digest: Vec<u64> = lanes.iter().map(lane).collect();
        assert_eq!(key_digest(&bytes(&v["pk"])).to_vec(), digest);
    }
}

/// Signatures made by each implementation verify here.
#[test]
fn every_implementations_signatures_verify() {
    for v in vectors("signatures") {
        let (pk, msg, sig) = (bytes(&v["pk"]), bytes(&v["msg"]), bytes(&v["sig"]));
        assert!(verify(&pk, &msg, &sig), "{}", v["signer"]);
    }
}

/// A valid signature, or its key, with one departure from the encodings: none
/// verifies.
#[test]
fn malformed_signatures_and_keys_do_not_verify() {
    for v in vectors("malformed") {
        let (pk, msg, sig) = (bytes(&v["pk"]), bytes(&v["msg"]), bytes(&v["sig"]));
        assert!(!verify(&pk, &msg, &sig), "{}", v["case"]);
    }
}
