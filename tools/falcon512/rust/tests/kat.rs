//! The NIST round-3 KAT through the verifier with standard Falcon's
//! HashToPoint in place of this crate's: the decoding and the norm are v1.2's.

use apogee_falcon512::{verify, verify_point};
use serde_json::Value;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

type Case = (Vec<u8>, Vec<u8>, Vec<u8>);

/// `standard_kat` of the shared vectors, `tools/falcon512/vectors.json`:
/// entries of the NIST round-3 KAT's Falcon-512 file (`falcon512-KAT.rsp`),
/// `pk`, `msg`, and `sm` converted to the padded v1.2 signature, `0x39 ‖ salt
/// ‖ compressed s2 ‖ zero padding`, 666 bytes.
fn kat() -> Vec<Case> {
    let vectors: Value =
        serde_json::from_str(include_str!("../../vectors.json")).expect("the vectors are JSON");
    let bytes = |hex: &Value| {
        test_support::hex_to_bytes(hex.as_str().expect("a hex string")).expect("the KAT is hex")
    };
    let entries = vectors["standard_kat"].as_array().expect("standard_kat");
    assert!(!entries.is_empty(), "standard_kat is empty");
    let case = |e: &Value| (bytes(&e["pk"]), bytes(&e["msg"]), bytes(&e["sig"]));
    entries.iter().map(case).collect()
}

/// Standard Falcon's HashToPoint: SHAKE256 of the salt and the message, read
/// as 16-bit big-endian samples `t`, each below `5q = 61445` taken in turn,
/// coefficient `i` the `i`-th one mod `q`.
fn shake_point(salt: &[u8], msg: &[u8]) -> [u16; 512] {
    let mut xof = Shake256::default().chain(salt).chain(msg).finalize_xof();
    let mut c = [0; 512];
    let mut i = 0;
    while i < 512 {
        let mut t = [0; 2];
        xof.read(&mut t);
        let t = u16::from_be_bytes(t);
        if t < 61445 {
            c[i] = t % 12289;
            i += 1;
        }
    }
    c
}

/// Whether `sig` verifies, its point from its salt and `msg` by SHAKE256.
fn verifies((pk, msg, sig): &Case) -> bool {
    verify_point(pk, &shake_point(&sig[1..41], msg), sig)
}

/// Each entry verifies, and, signed under SHAKE256, is not a signature under
/// this crate's HashToPoint.
#[test]
fn the_round_3_kat_verifies() {
    for case in kat() {
        let (pk, msg, sig) = &case;
        assert!(verifies(&case));
        assert!(!verify(pk, msg, sig, &[]));
    }
}

/// A bit of the message, of the salt, of `s2` and of the padding flipped: none
/// verifies.
#[test]
fn an_altered_entry_does_not_verify() {
    let flip = |bytes: &[u8], at: usize, bit: u32| {
        let mut bytes = bytes.to_vec();
        bytes[at] ^= 1 << bit;
        bytes
    };
    for (pk, msg, sig) in kat() {
        assert!(!verifies(&(pk.clone(), flip(&msg, 16, 0), sig.clone())));
        assert!(!verifies(&(pk.clone(), msg.clone(), flip(&sig, 18, 3))));
        assert!(!verifies(&(pk.clone(), msg.clone(), flip(&sig, 141, 5))));
        assert!(!verifies(&(pk, msg, flip(&sig, 665, 0))));
    }
}
