//! The shared vectors, `tools/falcon512/vectors.json`, which the JS and
//! Python suites read too: HashToPoint's points, the key digests, addresses
//! and their texts as all three implementations compute them, address texts
//! every parser reads or refuses, signatures each made, and malformed
//! signatures, keys and contexts every verifier refuses. `standard_kat` is
//! `kat.rs`'s.

use apogee_falcon512::{address, format_address, hash_to_point, key_digest, parse_address, verify};
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

#[test]
fn hash_to_point_gives_the_vectors_points() {
    for v in vectors("hash_to_point") {
        let (pk, msg, context) = (bytes(&v["pk"]), bytes(&v["msg"]), bytes(&v["context"]));
        let salt = bytes(&v["salt"]).try_into().expect("a 40-byte salt");
        let c: Vec<u16> = serde_json::from_value(v["c"].clone()).expect("c");
        assert_eq!(hash_to_point(&pk, &salt, &msg, &context).to_vec(), c);
    }
}

#[test]
fn key_digest_gives_the_vectors_digests_addresses_and_texts() {
    for v in vectors("key_digest") {
        let (pk, text) = (bytes(&v["pk"]), v["address_text"].as_str().expect("a text"));
        assert_eq!(key_digest(&pk).to_vec(), bytes(&v["key_digest"]));
        assert_eq!(address(&pk).to_vec(), bytes(&v["address"]));
        assert_eq!(format_address(&address(&pk)), text);
        assert_eq!(parse_address(text), Some(address(&pk)));
    }
}

/// Each text reads as its address, or, with none, is refused.
#[test]
fn address_texts_read_as_the_vectors_say() {
    for v in vectors("address_text") {
        let address = (!v["address"].is_null()).then(|| bytes(&v["address"]).try_into().unwrap());
        let text = v["text"].as_str().expect("a text");
        assert_eq!(parse_address(text), address, "{}", v["case"]);
    }
}

/// Signatures made by each implementation verify here.
#[test]
fn every_implementations_signatures_verify() {
    for v in vectors("signatures") {
        let (pk, msg, sig) = (bytes(&v["pk"]), bytes(&v["msg"]), bytes(&v["sig"]));
        assert!(
            verify(&pk, &msg, &sig, &bytes(&v["context"])),
            "{}",
            v["signer"]
        );
    }
}

/// A valid signature, or its key or context, with one departure: none
/// verifies.
#[test]
fn malformed_signatures_keys_and_contexts_do_not_verify() {
    for v in vectors("malformed") {
        let (pk, msg, sig) = (bytes(&v["pk"]), bytes(&v["msg"]), bytes(&v["sig"]));
        assert!(
            !verify(&pk, &msg, &sig, &bytes(&v["context"])),
            "{}",
            v["case"]
        );
    }
}
