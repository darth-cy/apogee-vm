//! `gkr::explain_self_check`, the failure-time post-mortem of a `self_check`
//! failure. `docs/tools.md` §3.
//!
//! **This file is why the explainer is compiled unconditionally.** It is called
//! only from `prover`'s `debug-info` build, and `gkr` may not have a feature of
//! its own — that would be a second `[features]` table, which master anti-goal 1
//! still forbids — so the function sits in the default build with no caller in
//! it. Master anti-goal 1's stated hazard is "a configuration nobody builds is
//! broken and undiscovered"; this is the file that makes it built and exercised
//! by `cargo test --workspace`.
//!
//! The two circuits here are the ones `edges.rs` already fails on, so the
//! failures are real `self_check` failures rather than a fixture invented for
//! this test — and between them they cover the two operand kinds that matter:
//! **committed** columns, which the artifact names, and **inner** columns,
//! which it does not and which are therefore named by the relation that wrote
//! them.

mod common;

use common::{bind, fr_base, honest, opposed_circuit, root_circuit};
use field::Fr;
use gkr::{explain_self_check, self_check, SelfCheckError};

fn fr(v: u64) -> Fr {
    Fr::from_u64(v)
}

/// Every line joined, for the `contains` assertions below: what a reader sees.
fn joined(lines: &[String]) -> String {
    lines.join("\n")
}

/// **A committed operand is named by the artifact's own column name.**
///
/// `opposed_circuit` enforces `0 = a − b` over two witness columns named `a`
/// and `b`. With `b[1]` one above `a[1]`, `self_check` reports gate list 0, row
/// 1, relation `a_eq_b` — and that is everything a reader gets today. The
/// explanation adds the two values, by name, which is the difference between
/// "something is wrong at row 1" and "`a` is 11 and `b` is 12".
#[test]
fn a_committed_operand_is_named_and_valued() {
    let artifact = opposed_circuit();
    let a: Vec<Fr> = (0..4).map(|i| fr(10 + i)).collect();
    let mut b = a.clone();
    b[1] += Fr::ONE;
    let base = fr_base(&artifact, vec![a, b]);
    let (values, _, _) = honest(&artifact, &base);
    let (_, challenges) = bind(&artifact, &base);

    let failure = self_check(&artifact, &values, &challenges).expect_err("row 1 disagrees");
    assert_eq!(
        failure,
        SelfCheckError {
            layer: 0,
            row: 1,
            relation: "a_eq_b".into(),
        }
    );

    let lines = explain_self_check(&artifact, &values, &challenges, &failure);
    let text = joined(&lines);
    assert!(
        text.contains("gate list 0 row 1"),
        "the explanation names the gate list and the row: {text}"
    );
    assert!(
        text.contains("enforcing gate") && text.contains("a_eq_b"),
        "and the gate's kind and its relation: {text}"
    );
    assert!(
        text.contains("an enforcing gate owes 0"),
        "an enforcing gate's expectation is 0, not a written value: {text}"
    );
    // The two operands, by the names `circuit(1, &["a", "b"], ..)` gave them,
    // with their values at row 1 in decimal.
    assert!(
        text.contains("W[0] = 11") && text.contains("   a"),
        "operand `a`: {text}"
    );
    assert!(
        text.contains("W[1] = 12") && text.contains("   b"),
        "operand `b`: {text}"
    );
}

/// **An inner operand is named by the relation that wrote it.**
///
/// `root_circuit`'s top gate list enforces `0 = root`, and `root` is
/// `L{2}[0]` — a gate's output, which the artifact gives no name of its own.
/// Naming it `written by define_root` is what makes a failure deep in a
/// delegation circuit legible: layer 12 of `EC_ADD` is unreadable as a number
/// and readable as the relation that produced it.
///
/// With `a = [2, 2]`, `sq = [2, 2]` and `root = 4`, so the enforcing gate
/// computes 4 where it owes 0.
#[test]
fn an_inner_operand_is_named_by_the_relation_that_wrote_it() {
    let artifact = root_circuit();
    let base = fr_base(&artifact, vec![vec![fr(2), fr(2)]]);
    let (values, _, _) = honest(&artifact, &base);
    let (_, challenges) = bind(&artifact, &base);

    let failure = self_check(&artifact, &values, &challenges).expect_err("root is 4");
    assert_eq!(failure.layer, 2);
    assert_eq!(failure.relation, "root_is_zero");

    let lines = explain_self_check(&artifact, &values, &challenges, &failure);
    let text = joined(&lines);
    assert!(
        text.contains("gate list 2 row 0") && text.contains("root_is_zero"),
        "{text}"
    );
    assert!(
        text.contains("computed 4"),
        "the value it computed, in decimal: {text}"
    );
    assert!(
        text.contains("L{2}[0]") && text.contains("written by define_root"),
        "an inner column is named by its producing relation: {text}"
    );
}

/// **A producing gate reports both sides.** Row 0 of `root_circuit`'s first
/// gate list squares `a`; overwriting the layer it wrote makes the gate and the
/// layer disagree, which is the other half of what `self_check` compares and
/// the half an enforcing gate has no analogue of.
#[test]
fn a_producing_gate_reports_what_the_layer_holds() {
    let artifact = root_circuit();
    let base = fr_base(&artifact, vec![vec![fr(0), fr(1)]]);
    let (mut values, _, _) = honest(&artifact, &base);
    let (_, challenges) = bind(&artifact, &base);
    assert_eq!(
        self_check(&artifact, &values, &challenges),
        Ok(()),
        "a = [0, 1] is the honest base"
    );

    // Replace layer 1's single column with a wrong value. `sq` is
    // `a·(a − 1)`, which is 0 on both rows of the honest base, so 7 is wrong
    // on row 0 and the producing gate is what sees it.
    values.layers[0][0] = poly::MultilinearPoly::new(poly::PolyBacking::Fr(vec![fr(7), Fr::ZERO]));
    let failure = self_check(&artifact, &values, &challenges).expect_err("layer 1 row 0 is 7");
    assert_eq!(failure.layer, 0);
    assert_eq!(failure.row, 0);
    assert_eq!(failure.relation, "define_sq");

    let lines = explain_self_check(&artifact, &values, &challenges, &failure);
    let text = joined(&lines);
    assert!(text.contains("producing gate"), "{text}");
    assert!(
        text.contains("computed 0 but the layer holds 7"),
        "both sides of the disagreement, and which is which: {text}"
    );
    assert!(text.contains("W[0] = 0") && text.contains("   a"), "{text}");
}

/// A failure the values no longer show explains nothing, and says so by being
/// empty rather than by naming an arbitrary gate. Only reachable by handing the
/// explainer a `SelfCheckError` from a different run, which is exactly the case
/// where a confident answer would be a wrong one.
#[test]
fn an_explanation_of_a_row_that_agrees_is_empty() {
    let artifact = opposed_circuit();
    let a: Vec<Fr> = (0..4).map(|i| fr(10 + i)).collect();
    let base = fr_base(&artifact, vec![a.clone(), a]);
    let (values, _, _) = honest(&artifact, &base);
    let (_, challenges) = bind(&artifact, &base);
    assert_eq!(self_check(&artifact, &values, &challenges), Ok(()));

    let stale = SelfCheckError {
        layer: 0,
        row: 1,
        relation: "a_eq_b".into(),
    };
    assert!(explain_self_check(&artifact, &values, &challenges, &stale).is_empty());
}

/// Out-of-range coordinates are answered with a line, not a panic: the
/// explainer runs on a failure path and must not become the failure.
#[test]
fn coordinates_outside_the_circuit_are_answered_not_panicked() {
    let artifact = opposed_circuit();
    let a: Vec<Fr> = (0..4).map(|i| fr(10 + i)).collect();
    let base = fr_base(&artifact, vec![a.clone(), a]);
    let (values, _, _) = honest(&artifact, &base);
    let (_, challenges) = bind(&artifact, &base);

    let bad_layer = SelfCheckError {
        layer: 99,
        row: 0,
        relation: "nowhere".into(),
    };
    let text = joined(&explain_self_check(
        &artifact,
        &values,
        &challenges,
        &bad_layer,
    ));
    assert!(text.contains("layer 99 is outside"), "{text}");

    let bad_row = SelfCheckError {
        layer: 0,
        row: 1 << 20,
        relation: "a_eq_b".into(),
    };
    let text = joined(&explain_self_check(
        &artifact,
        &values,
        &challenges,
        &bad_row,
    ));
    assert!(text.contains("is outside gate list 0"), "{text}");
}
