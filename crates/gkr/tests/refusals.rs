//! What the prover half still refuses by panicking. The entry points check
//! nothing about their inputs — not the artifact, which is assumed validated
//! (`docs/spec/gkr.md` §5.1), and not the base, the layer values, the tables or
//! the challenge slots, whose shape checks are kept in `crates/gkr/src/lib.rs`
//! as uncalled debugging aids. Soundness is `verify`'s alone, and
//! `tests/tamper.rs` holds it to rejecting what a prover gets wrong.

use std::panic::{catch_unwind, AssertUnwindSafe};

use field::Fr;
use gkr::ExternalChallenges;

/// Run `f`, which must panic, and return its message.
fn panic_message<R>(f: impl FnOnce() -> R) -> String {
    let payload = match catch_unwind(AssertUnwindSafe(f)) {
        Ok(_) => panic!("the call returned; it should have panicked"),
        Err(payload) => payload,
    };
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .expect("a panic carries a message")
}

/// A challenge slot has one value: inserting it again panics rather than
/// overwriting. This is not an input check but the map's meaning, and the
/// verifier's challenges live in the same type. Kills M37.
#[test]
fn a_challenge_slot_is_set_once() {
    let mut challenges = ExternalChallenges::new();
    challenges.insert(0, Fr::from_u64(5));
    challenges.insert(1, Fr::from_u64(6));
    assert_eq!(challenges.get(0), Some(Fr::from_u64(5)));
    assert_eq!(
        panic_message(|| challenges.insert(0, Fr::from_u64(7))),
        "ExternalChallenges::insert: slot 0 is already set"
    );
}
