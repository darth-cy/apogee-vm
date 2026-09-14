//! The padding contract, `docs/spec/gkr.md` §4.3: `check_padding` holds both
//! committed toys to it, and rejects a contract the relations contradict.

mod common;

use checker::check_padding;
use common::*;
use constraints::{Coeff, GateDef};
use field::Fr;

#[test]
fn both_fixtures_keep_their_padding_contract() {
    for (label, a) in toys() {
        assert_eq!(check_padding(&a), Ok(()), "{label}");
    }
}

#[test]
fn a_flipped_zero_row_verdict_is_rejected() {
    for (label, mut a) in toys() {
        a.padding.zero_row_valid = !a.padding.zero_row_valid;
        let e = check_padding(&a).unwrap_err();
        assert!(e.contains("zero_row_valid"), "{label}: {e}");
    }
}

/// An active padding row (s = 1) with e != a breaks `0 = (e − a)·s`; the same
/// row with e = a does not.
#[test]
fn a_padding_row_breaking_the_gated_equality_is_rejected() {
    for (label, mut a) in toys() {
        a.padding.row[S] = Fr::ONE;
        a.padding.row[A] = Fr::from_u64(5);
        a.padding.row[E] = Fr::from_u64(6);
        let e = check_padding(&a).unwrap_err();
        assert!(e.contains("gated_equality"), "{label}: {e}");
        a.padding.row[E] = Fr::from_u64(5);
        assert_eq!(check_padding(&a), Ok(()), "{label}");
    }
}

/// With the enforcing relation replaced by `0 = e − a − 1`, the all-zero row is
/// invalid: the contract then holds only with a padding row where e = a + 1 and
/// with `zero_row_valid` saying so.
#[test]
fn an_invalid_zero_row_must_be_declared_invalid() {
    for (label, mut a) in toys() {
        let r = relation(&a, "gated_equality");
        let minus_one = Coeff::Literal(-Fr::ONE);
        a.relations[r].gate = GateDef::Linear {
            terms: vec![(lit(1), W3), (minus_one, W0)],
            constant: minus_one,
        };
        a.padding.row[E] = Fr::ONE;
        a.padding.zero_row_valid = false;
        assert_eq!(check_padding(&a), Ok(()), "{label}");
        a.padding.zero_row_valid = true;
        let e = check_padding(&a).unwrap_err();
        assert!(e.contains("zero_row_valid"), "{label}: {e}");
    }
}

#[test]
fn a_padding_row_of_the_wrong_length_is_rejected() {
    let mut a = load(CACHED);
    a.padding.row.pop();
    assert!(check_padding(&a)
        .unwrap_err()
        .contains("5 values for 6 columns"));
}
