//! The stateless input's SSZ against a second implementation, for the layout
//! no release holds the guest to.
//!
//! `tests-zkevm@v21.0.1` fills only Amsterdam, and `tests/conformance.rs` holds
//! the guest's decoder and request root to it there. Osaka, BPO1 and BPO2 share
//! Electra/Fulu's request instead, and its oracle is `tools/stateless-ref`:
//! `eth-act/ere-guests`' `stateless-validator-common` at v0.17.1 over `libssz`,
//! which encoded every input in `vectors/stateless_ref.txt`, rooted its
//! request, and decoded each broken one to a refusal or a root. This holds the
//! guest's [`ssz::decode`] and [`ssz::request_root`] to every line.

use revm_block::ssz;
use test_support::{hex_to_bytes, to_hex};

#[test]
fn every_input_decodes_and_roots_as_ere_guests_does() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/stateless_ref.txt"
    );
    let text = std::fs::read_to_string(path).expect("the reference vectors");
    let mut count = 0;
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let [name, expected, input] = line.split(' ').collect::<Vec<_>>()[..] else {
            panic!("a malformed line: {line}");
        };
        let input = hex_to_bytes(input).expect("hex");
        let got = ssz::decode(&input).map_or_else(
            || "reject".to_string(),
            |decoded| to_hex(&ssz::request_root(&decoded.request, decoded.fork.amsterdam)),
        );
        assert_eq!(got, expected, "{name}");
        count += 1;
    }
    assert!(count > 0, "no vectors");
}
