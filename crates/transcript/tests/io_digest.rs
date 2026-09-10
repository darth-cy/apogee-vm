//! The public I/O digest: the value the statement-binding order absorbs as
//! "public I/O digest", frozen at S10.
//!
//! The committed vectors come from `tools/transcript-ref`, which transcribes
//! `docs/spec/ecall-abi.md` section 6 over Plonky3's permutation and never
//! links this crate. The sensitivity properties are asserted directly, because
//! what they say is "these two inputs differ", and a committed pair only shows
//! it for one pair.

mod common;

use field::Fr;
use test_support::{hex_to_bytes, sha256, to_hex};

const VECTORS: &str = "tests/vectors/io_digest.txt";
use transcript::io_digest;

/// Master rule 11: the fixture is what it was when the digest was written down.
const IO_DIGEST_SHA256: &str = "314578e795a351c766c8c9c10dd890082149fb94401c955fe4641c2c19a315cd";

/// Acceptance 10: every committed case, replayed.
#[test]
fn every_committed_case_matches() {
    let cases = committed();
    assert!(cases.len() >= 12, "the vector file has shrunk");

    for (name, input, output, want) in &cases {
        assert_eq!(
            to_hex(&io_digest(input, output).to_bytes()),
            to_hex(&want.to_bytes()),
            "io_digest case {name}"
        );
    }

    // The four shapes acceptance 10 names are all present.
    for required in ["empty_empty", "input_only", "output_only", "multi_block"] {
        assert!(
            cases.iter().any(|(name, ..)| name == required),
            "the vector file no longer covers {required}"
        );
    }
}

/// The empty cases are defined, and distinct from each other.
#[test]
fn the_empty_cases_are_defined_and_distinct() {
    let empty = io_digest(&[], &[]);
    let input_only = io_digest(b"apogee", &[]);
    let output_only = io_digest(&[], b"apogee");

    assert_ne!(empty, input_only);
    assert_ne!(empty, output_only);
    assert_ne!(
        input_only, output_only,
        "the two streams must be domain-separated even when one is empty"
    );
    // An empty stream contributes its tag and a zero length and no limbs, so
    // the empty/empty digest is a fixed value and not, say, the zero element.
    assert_ne!(empty, Fr::ZERO);
}

/// Must-be-exact 10: swapping unequal streams changes the digest.
#[test]
fn swapping_the_streams_changes_the_digest() {
    let cases: [(&[u8], &[u8]); 4] = [
        (b"apogee", b"tenacity"),
        (b"", b"x"),
        (b"a", b"aa"),
        (&[0u8; 31], &[0u8; 32]),
    ];
    for (a, b) in cases {
        assert_ne!(
            io_digest(a, b),
            io_digest(b, a),
            "swapping {a:?} and {b:?} left the digest alone"
        );
    }
    // Equal streams are the one case where a swap is not a change, and saying
    // so is the point: the property is about *unequal* streams.
    assert_eq!(io_digest(b"same", b"same"), io_digest(b"same", b"same"));
}

/// Must-be-exact 10: appending a zero byte changes the digest.
///
/// This is the property the byte length buys. Without it the zero-extended
/// final limb would make `x` and `x || 0x00` absorb identically whenever `x`
/// does not fill a limb.
#[test]
fn appending_a_zero_byte_changes_the_digest() {
    for n in [0usize, 1, 30, 31, 32, 61, 62, 63] {
        let x: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(31)).collect();
        let extended = [x.clone(), vec![0u8]].concat();
        assert_ne!(
            io_digest(&x, b"out"),
            io_digest(&extended, b"out"),
            "appending a zero byte to a {n}-byte input left the digest alone"
        );
        assert_ne!(
            io_digest(b"in", &x),
            io_digest(b"in", &extended),
            "appending a zero byte to a {n}-byte output left the digest alone"
        );
    }
}

/// Must-be-exact 10: flipping one bit changes the digest.
#[test]
fn flipping_one_bit_changes_the_digest() {
    let base: Vec<u8> = (0..40).map(|i| (i as u8).wrapping_mul(31)).collect();
    let reference = io_digest(&base, b"tenacity");
    for byte in 0..base.len() {
        for bit in 0..8 {
            let mut flipped = base.clone();
            flipped[byte] ^= 1 << bit;
            assert_ne!(
                io_digest(&flipped, b"tenacity"),
                reference,
                "flipping bit {bit} of byte {byte} left the digest alone"
            );
        }
    }
}

/// It is a pure function: same bytes in, same `Fr` out, every time.
#[test]
fn the_digest_is_a_pure_function_of_the_two_streams() {
    for (name, input, output, want) in committed() {
        let a = io_digest(&input, &output);
        let b = io_digest(&input, &output);
        assert_eq!(a, b, "{name}: two calls disagreed");
        assert_eq!(a, want, "{name}");
    }
}

/// The negative control for the vector file itself.
#[test]
fn a_corrupted_vector_file_is_rejected() {
    let good = common::read_vectors(VECTORS);
    common::assert_sha256(VECTORS, &good, IO_DIGEST_SHA256);

    let mut bad = good.clone().into_bytes();
    let at = bad.len() - 4;
    bad[at] ^= 1;
    assert_ne!(
        to_hex(&sha256(&bad)),
        IO_DIGEST_SHA256,
        "the pin cannot detect a changed file"
    );

    // ... and a flipped expected value fails the replay, not just the pin.
    let mut cases = parse(&good);
    let (_, input, output, want) = cases.pop().expect("the file has cases");
    let mut wrong = want.to_bytes();
    wrong[0] ^= 1;
    assert_ne!(
        io_digest(&input, &output),
        Fr::from_bytes(&wrong).expect("a one-bit change stays canonical here"),
        "the replay cannot detect a flipped expected value"
    );
}

// ---------------------------------------------------------------------------

type Case = (String, Vec<u8>, Vec<u8>, Fr);

fn committed() -> Vec<Case> {
    let text = common::read_vectors(VECTORS);
    common::assert_sha256(VECTORS, &text, IO_DIGEST_SHA256);
    parse(&text)
}

fn parse(text: &str) -> Vec<Case> {
    let stream = |token: &str| -> Vec<u8> {
        if token == "-" {
            Vec::new()
        } else {
            hex_to_bytes(token).expect("a stream is hex")
        }
    };
    text.lines()
        .filter(|l| l.starts_with("io "))
        .map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            assert_eq!(f.len(), 5, "an io line is `io name input output digest`");
            let mut want = [0u8; 32];
            want.copy_from_slice(&hex_to_bytes(f[4]).expect("a digest is hex"));
            (
                f[1].to_string(),
                stream(f[2]),
                stream(f[3]),
                Fr::from_bytes(&want).expect("a committed digest is canonical"),
            )
        })
        .collect()
}
