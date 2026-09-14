//! What the entry points refuse by panicking: every documented refusal of the
//! prover's inputs. Each panic's message is matched, beside the same call on
//! well-formed input returning normally. An artifact that breaks a law is not
//! among them: the entry points assume one that has passed `validate`
//! (`docs/spec/gkr.md` §5.1).

mod common;

use std::panic::{catch_unwind, AssertUnwindSafe};

use common::{bind, honest, toy, toy_base, toy_columns, with_column, TOY_ROWS};
use constraints::PolyAddress;
use field::Fr;
use gkr::{
    forward, prove, prove_sumcheck, self_check, BaseLayer, ExternalChallenges, LayerSummand,
    LayerTables,
};
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

/// `prove_sumcheck` refuses a halving list's tables whose children do not pair
/// up, with its own message: more `upper` tables than `lower` would otherwise
/// be bound and ignored, and fewer an index out of bounds. Kills the mutant
/// that drops the check, under which the call with one `upper` table too many
/// returns rounds.
#[test]
fn prove_sumcheck_refuses_unpaired_children() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_1a00));
    let (mut t, challenges) = bind(&artifact, &base);
    let k = 2;
    let list = &artifact.layers[k];
    assert!(list.halving, "the toy's list 2 halves");
    let width = artifact.layers[k - 1].width as usize;
    let summand = LayerSummand {
        artifact: &artifact,
        layer: k,
        weights: vec![Fr::ONE; list.producing.len() + list.enforcing.len()],
        challenges: &challenges,
    };
    let eq_point = [Fr::from_u64(3), Fr::from_u64(5), Fr::from_u64(7)];
    let tables = |count: usize| -> Vec<MultilinearPoly> {
        (0..count as u64)
            .map(|c| {
                MultilinearPoly::new(PolyBacking::Fr(
                    (0..8).map(|i| Fr::from_u64(c * 8 + i)).collect(),
                ))
            })
            .collect()
    };
    let mut paired = LayerTables {
        lower: tables(width),
        upper: tables(width),
    };
    let (rounds, point) = prove_sumcheck(&eq_point, &summand, &mut paired, &mut t);
    assert_eq!((rounds.len(), point.len()), (3, 3));

    for upper in [width + 1, width - 1] {
        let mut unpaired = LayerTables {
            lower: tables(width),
            upper: tables(upper),
        };
        let message = panic_message(|| prove_sumcheck(&eq_point, &summand, &mut unpaired, &mut t));
        assert!(
            message.contains(
                ": prove_sumcheck: halving gate list 2 needs both children of every column\n"
            ),
            "{message}"
        );
    }
}
