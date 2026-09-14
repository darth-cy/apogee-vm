//! Acceptance 8: the witness-row evaluator. A satisfying row of the toy passes,
//! and perturbing any single committed cell, the row index, or any scratch cell
//! by one reports exactly the relations that cell feeds, by name.
//!
//! The satisfying rows and the expected sets are derived by hand from the toy's
//! description (`tests/common/mod.rs`), never from the evaluator. An evaluator
//! that reports nothing, or everything, fails the same checks.

mod common;

use checker::{violated_relations, WitnessRow};
use common::*;
use constants::challenge_slot;
use constraints::CircuitArtifact;
use field::Fr;
use gkr::ExternalChallenges;
use test_support::Rng;

type Evaluator = fn(&CircuitArtifact, &WitnessRow, &ExternalChallenges) -> Vec<String>;

/// A satisfying row: active is s = 1 and e = a, inactive is s = 0 and a free e.
/// The scratch values follow the toy's formulas; the two products span rows, so
/// their slots are left at zero.
fn satisfying(
    a: &CircuitArtifact,
    active: bool,
    rng: &mut Rng,
) -> (WitnessRow, ExternalChallenges) {
    let gamma = fr(rng);
    let row = (rng.next_u64() % 15) as usize; // so that row + 1 is still a row
    let mut committed: Vec<Fr> = (0..6).map(|_| fr(rng)).collect();
    committed[S] = if active { Fr::ONE } else { Fr::ZERO };
    if active {
        committed[E] = committed[A];
    }
    let (m, x, b, c, s) = (
        committed[M],
        committed[A],
        committed[B],
        committed[C],
        committed[S],
    );
    let ab = x * b;
    let fingerprint = (gamma * x + Fr::from_u64(row as u64)) * c;
    let masked_m = m * s + Fr::ONE - s;
    let mut scratch = vec![Fr::ZERO; a.scratch.len()];
    let values = [
        ("ab", ab),
        ("fingerprint", fingerprint),
        ("masked_m", masked_m),
        ("abm", ab * masked_m),
        ("fingerprint3", fingerprint + Fr::from_u64(3)),
    ];
    for (name, value) in values {
        scratch[slot(a, name)] = value;
    }
    let mut challenges = ExternalChallenges::new();
    challenges.insert(challenge_slot::TOY, gamma);
    let w = WitnessRow {
        committed,
        row,
        scratch,
    };
    (w, challenges)
}

enum Cell {
    Committed(usize),
    Row,
    Scratch(&'static str),
}

/// The cell, and the relations its +1 breaks on an active row and on an
/// inactive one, in relation order. Why, case by case:
/// - `m` feeds `masked_m = m·s + 1 − s`, which ignores it when s = 0.
/// - `a` feeds `ab`, `fingerprint` and `(e − a)·s`, the last only when s = 1.
/// - `e` feeds only the gated equality, which s = 0 switches off.
/// - `s` at 2 makes `masked_m = 2m − 1 != m`, while e = a keeps the equality; at
///   1 it makes `masked_m = m != 1`, and with e != a the equality breaks.
/// - `row` feeds `fingerprint` through `V[row]`.
/// - a scratch cell breaks its own definition and every row-local relation
///   reading it; the product slots are not row-local, so nothing is reported.
const CASES: [(Cell, &[&str], &[&str]); 14] = [
    (Cell::Committed(M), &["define_masked_m"], &[]),
    (
        Cell::Committed(A),
        &["define_ab", "define_fingerprint", "gated_equality"],
        &["define_ab", "define_fingerprint"],
    ),
    (Cell::Committed(B), &["define_ab"], &["define_ab"]),
    (
        Cell::Committed(C),
        &["define_fingerprint"],
        &["define_fingerprint"],
    ),
    (Cell::Committed(E), &["gated_equality"], &[]),
    (
        Cell::Committed(S),
        &["define_masked_m"],
        &["define_masked_m", "gated_equality"],
    ),
    (Cell::Row, &["define_fingerprint"], &["define_fingerprint"]),
    (
        Cell::Scratch("ab"),
        &["define_ab", "define_abm"],
        &["define_ab", "define_abm"],
    ),
    (
        Cell::Scratch("fingerprint"),
        &["define_fingerprint", "define_fingerprint3"],
        &["define_fingerprint", "define_fingerprint3"],
    ),
    (
        Cell::Scratch("masked_m"),
        &["define_masked_m", "define_abm"],
        &["define_masked_m", "define_abm"],
    ),
    (Cell::Scratch("abm"), &["define_abm"], &["define_abm"]),
    (
        Cell::Scratch("fingerprint3"),
        &["define_fingerprint3"],
        &["define_fingerprint3"],
    ),
    (Cell::Scratch("abm_product"), &[], &[]),
    (Cell::Scratch("fingerprint3_product"), &[], &[]),
];

/// Every case, on both compilations, on an active and an inactive row.
fn run(evaluate: Evaluator) -> Result<(), String> {
    let mut rng = Rng::new(0x5713_0008);
    for (label, a) in toys() {
        for active in [true, false] {
            let (w, challenges) = satisfying(&a, active, &mut rng);
            let clean = evaluate(&a, &w, &challenges);
            if !clean.is_empty() {
                return Err(format!(
                    "{label}, active {active}: a satisfying row reports {clean:?}"
                ));
            }
            for (cell, on_active, on_inactive) in &CASES {
                let mut bad = WitnessRow {
                    committed: w.committed.clone(),
                    row: w.row,
                    scratch: w.scratch.clone(),
                };
                let what = match cell {
                    Cell::Committed(i) => {
                        bad.committed[*i] += Fr::ONE;
                        format!("committed[{i}]")
                    }
                    Cell::Row => {
                        bad.row += 1;
                        "the row index".to_string()
                    }
                    Cell::Scratch(name) => {
                        bad.scratch[slot(&a, name)] += Fr::ONE;
                        name.to_string()
                    }
                };
                let want = if active { *on_active } else { *on_inactive };
                let got = evaluate(&a, &bad, &challenges);
                if got != want {
                    return Err(format!(
                        "{label}, active {active}: {what} + 1 reports {got:?}, not {want:?}"
                    ));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn each_perturbation_reports_exactly_the_relations_it_breaks() {
    assert_eq!(run(violated_relations), Ok(()));
}

#[test]
fn an_evaluator_reporting_nothing_fails_the_same_checks() {
    assert!(run(|_, _, _| Vec::new()).is_err());
}

#[test]
fn an_evaluator_reporting_everything_fails_the_same_checks() {
    let everything: Evaluator = |a, _, _| a.relations.iter().map(|r| r.name.clone()).collect();
    assert!(run(everything).is_err());
}
