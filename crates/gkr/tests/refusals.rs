//! What the entry points refuse by panicking: an artifact that breaks a law, at
//! `verify` and at `prove`, and every documented refusal of the prover's inputs.
//! Each panic's message is matched, beside the same call on well-formed input
//! returning normally.

mod common;

use std::panic::{catch_unwind, AssertUnwindSafe};

use common::{bind, honest, output_claims, toy, toy_base, toy_columns, with_column, TOY_ROWS};
use constraints::{CircuitArtifact, Coeff, ConstraintError, GateDef, PolyAddress};
use field::Fr;
use gkr::{forward, prove, self_check, verify, BaseLayer, ExternalChallenges};
use poly::{MultilinearPoly, PolyBacking};

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

/// The toy with `define_fingerprint3` saying `scratch[1] + 4` while its gate
/// says `L{1}[1] + 3`: a Law 4 break in the flat list, which no pass of the
/// engine reads, so only an entry point's own `validate` can refuse it.
fn lawless() -> CircuitArtifact {
    let mut artifact = toy();
    let relation = artifact
        .relations
        .iter_mut()
        .find(|r| r.name == "define_fingerprint3")
        .expect("the toy defines fingerprint3");
    match &mut relation.gate {
        GateDef::Linear { constant, .. } => *constant = Coeff::Literal(Fr::from_u64(4)),
        other => panic!("define_fingerprint3 is Linear, not {other:?}"),
    }
    assert!(matches!(
        artifact.validate(),
        Err(ConstraintError::SingleSource { .. })
    ));
    artifact
}

/// `verify` asserts the laws before anything else. Kills M27, which deletes
/// that assertion: the lawless toy then verifies the toy's honest proof.
#[test]
fn verify_panics_on_an_artifact_that_breaks_a_law() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_1600));
    let (values, proof, result) = honest(&artifact, &base);
    result.expect("the lawful toy verifies");
    let outputs = output_claims(&artifact, &values);

    let lawless = lawless();
    let (mut t, challenges) = bind(&lawless, &base);
    let message = panic_message(|| verify(&lawless, &proof, &outputs, &challenges, &mut t));
    assert!(
        message.starts_with("gkr_verify::verify: the artifact is not a circuit: law 4"),
        "{message}"
    );
}

/// `prove` asserts the laws too. Kills M28, which deletes the assertion from
/// the check `prove`, `forward` and `self_check` share.
#[test]
fn prove_panics_on_an_artifact_that_breaks_a_law() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_1700));
    let (values, _, result) = honest(&artifact, &base);
    result.expect("the lawful toy proves and verifies");

    let lawless = lawless();
    let (mut t, challenges) = bind(&lawless, &base);
    let message = panic_message(|| prove(&lawless, &values, &challenges, &mut t));
    assert!(
        message.starts_with("gkr::prove: the artifact is not a circuit: law 4"),
        "{message}"
    );
}

/// `BaseLayer::new` refuses an address given twice. Kills M36.
#[test]
fn a_base_layer_refuses_an_address_twice() {
    let column = || MultilinearPoly::new(PolyBacking::U32(vec![1, 2]));
    let (a, b) = (PolyAddress::Witness(0), PolyAddress::Witness(1));
    let base = BaseLayer::new(vec![(a, column()), (b, column())]);
    assert!(base.get(a).is_some() && base.get(b).is_some());
    assert_eq!(
        panic_message(|| BaseLayer::new(vec![(a, column()), (b, column()), (a, column())])),
        "BaseLayer::new: W[0] is given twice"
    );
}

/// A challenge slot has one value: inserting it again panics rather than
/// overwriting. Kills M37.
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

/// `forward` refuses a base column taller than the trace. Kills M42: without
/// the check it reads the first 16 rows of a 32-row column, while a digest
/// would bind all 32.
#[test]
fn forward_refuses_a_column_of_the_wrong_height() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_1800));
    let (_, challenges) = bind(&artifact, &base);
    assert_eq!(forward(&artifact, &base, &challenges).layers.len(), 3);

    let tall: Vec<Fr> = (0..2 * TOY_ROWS as u64).map(Fr::from_u64).collect();
    let tall = with_column(&base, &artifact, PolyAddress::Witness(0), tall);
    let message = panic_message(|| forward(&artifact, &tall, &challenges));
    assert!(
        message.contains(": gkr::forward: W[0] has 5 variables, the trace 4\n"),
        "{message}"
    );
}

/// `prove` and `self_check` refuse layer values missing a column of layer 1,
/// with their own message rather than an index out of bounds. Kills M39 and
/// M40, which drop the shape check from each.
#[test]
fn prove_and_self_check_refuse_a_missing_column() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_1900));
    let (values, _, result) = honest(&artifact, &base);
    result.expect("the full values prove and verify");
    let (mut t, challenges) = bind(&artifact, &base);
    assert_eq!(self_check(&artifact, &values, &challenges), Ok(()));

    let mut narrow = values.clone();
    narrow.layers[0].pop();
    // An `assert_eq!` message, so the engine's text sits after the
    // assertion's own preamble and before the operands.
    let message = panic_message(|| prove(&artifact, &narrow, &challenges, &mut t));
    assert!(
        message.contains(": gkr::prove: layer 1 has 2 columns, the artifact 3\n"),
        "{message}"
    );
    let message = panic_message(|| self_check(&artifact, &narrow, &challenges));
    assert!(
        message.contains(": gkr::self_check: layer 1 has 2 columns, the artifact 3\n"),
        "{message}"
    );
}
