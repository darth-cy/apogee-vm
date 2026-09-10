//! The public I/O digest over a real guest's recorded streams.
//!
//! `crates/transcript/tests/io_digest.rs` is where the digest is checked against
//! its committed vectors and where its sensitivity properties are proven. This
//! is the other half of acceptance 10: the fd 0 and fd 1 bytes that
//! `guests/fib` actually produces, digested, and digested again.
//!
//! It lives here because the record does: `fib_io.txt` is a guest artifact, and
//! `crates/loader` is the host-side crate that owns those.

mod common;

use test_support::{hex_to_bytes, to_hex};
use transcript::io_digest;

/// The two streams the committed record holds.
fn fib_streams() -> (Vec<u8>, Vec<u8>) {
    let record = common::rows("fib_io.txt");
    let field = |key: &str| {
        record
            .iter()
            .find(|f| f[0] == key)
            .unwrap_or_else(|| panic!("fib_io.txt has no {key}"))[1]
            .clone()
    };
    (
        hex_to_bytes(&field("input")).expect("fib_io input is hex"),
        hex_to_bytes(&field("output")).expect("fib_io output is hex"),
    )
}

/// Acceptance 10's last clause: the fib fixture's digest, twice, identical.
#[test]
fn the_fib_record_digests_to_the_same_value_twice() {
    let (input, output) = fib_streams();
    assert_eq!(input.len(), 4, "fd 0 is one little-endian u32");
    assert_eq!(output.len(), 4, "fd 1 is one little-endian u32");

    let first = io_digest(&input, &output);
    let second = io_digest(&input, &output);
    assert_eq!(
        to_hex(&first.to_bytes()),
        to_hex(&second.to_bytes()),
        "io_digest is not a pure function of the two streams"
    );
}

/// ... and it is a digest of *these* streams, not of nothing.
///
/// Without this the test above would pass on a function that ignored its
/// arguments.
#[test]
fn the_fib_digest_depends_on_both_streams() {
    let (input, output) = fib_streams();
    let reference = io_digest(&input, &output);

    assert_ne!(reference, io_digest(&[], &output), "fd 0 does not reach it");
    assert_ne!(reference, io_digest(&input, &[]), "fd 1 does not reach it");
    assert_ne!(
        reference,
        io_digest(&output, &input),
        "the two streams are not domain-separated"
    );

    let mut nudged = input.clone();
    nudged[0] ^= 1;
    assert_ne!(
        reference,
        io_digest(&nudged, &output),
        "a flipped input bit"
    );
}
