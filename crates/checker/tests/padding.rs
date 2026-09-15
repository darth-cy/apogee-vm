//! The padding contract, `docs/spec/gkr.md` §4.3: `check_padding` holds both
//! committed toys to it, and rejects a contract the relations contradict; and
//! `check_padding_identity` holds the product-tree clause, which the toy does
//! not keep and a small edit of it does.

mod common;

use checker::{check_laws, check_padding, check_padding_identity};
use common::*;
use constraints::{
    CircuitArtifact, Coeff, GateDef, LayerSpec, PolyAddress, ProducingEntry, Relation, ScratchSlot,
};
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

/// The product-tree clause, pinned on the toy as it is: `Err`, naming `abm`.
/// The toy predates the clause and does not keep it. Its padding row is all
/// zero, so `abm = a·b·masked_m = 0`, and `fingerprint3 = (γ·a + row)·c + 3` is
/// 3 whatever the row — no mask reaches `fingerprint3` at all, so no padding
/// row could make it 1. The first column its halving list reads, `L{2}[0]`, is
/// the one named.
#[test]
fn the_toy_does_not_keep_the_product_tree_clause() {
    for (label, a) in toys() {
        let e = check_padding_identity(&a).unwrap_err();
        let named = "halving gate list 2 reads L{2}[0] (abm), which is 0 on padding.row";
        assert!(e.contains(named), "{label}: {e}");
    }
}

/// The toy with `fingerprint3 = fingerprint + 1`, relation and gate alike,
/// padded with `a = b = 1` and every other column 0: `masked_m` is 1 at
/// `s = 0`, so `abm = 1`, and `fingerprint3 = (γ·1 + row)·0 + 1 = 1`.
fn identity_padded(mut a: CircuitArtifact) -> CircuitArtifact {
    let r = relation(&a, "define_fingerprint3");
    *linear(&mut a.relations[r].gate).1 = lit(1);
    *linear(&mut a.layers[1].producing[1].gate).1 = lit(1);
    a.padding.row = vec![Fr::ZERO; 6];
    a.padding.row[A] = Fr::ONE;
    a.padding.row[B] = Fr::ONE;
    a
}

/// That edit keeps the laws, the padding contract and the product-tree clause.
/// Moving one leaf off 1 fails, naming it: `b = 2` makes `abm` 2; `s = 1` makes
/// `masked_m = m = 0` and `abm` 0; `c = 1` makes `fingerprint3 = γ + row + 1`,
/// which is 1 only where `γ + row = 0`, so only a sampler that draws its
/// challenge and its row catches it.
///
/// Kills a clause checked at the challenge 0 and row 0 alone (the `c = 1`
/// row then passes), and one that reads the halving list's outputs rather than
/// its inputs (no row-local relation defines those, so the edited toy then
/// fails).
#[test]
fn a_padding_row_whose_leaves_are_one_passes_and_each_moved_leaf_fails() {
    for (label, a) in toys() {
        let a = identity_padded(a);
        assert_eq!(check_laws(&a), Ok(()), "{label}");
        assert_eq!(check_padding(&a), Ok(()), "{label}");
        assert_eq!(check_padding_identity(&a), Ok(()), "{label}");

        let moved: [(usize, u64, &str); 3] = [
            (B, 2, "(abm), which is 2 on padding.row"),
            (S, 1, "(abm), which is 0 on padding.row"),
            (C, 1, "(fingerprint3), which is "),
        ];
        for (cell, value, named) in moved {
            let mut b = a.clone();
            b.padding.row[cell] = Fr::from_u64(value);
            let e = check_padding_identity(&b).unwrap_err();
            assert!(e.contains(named), "{label}, cell {cell} = {value}: {e}");
        }
    }
}

/// That edit with a second halving list stacked on the first — list 3 halves
/// `L{3}[0]` and `L{3}[1]` again into `L{4}[0]` and `L{4}[1]`, the new outputs —
/// keeps the laws and still passes, and moving a leaf off 1 still fails naming
/// list 2's operand. The clause is about the first halving list alone: every
/// later one reads a `TreeProduct`'s output, which no row-local relation defines.
///
/// Kills a clause reading the last halving list instead of the first, and one
/// reading every halving list: both refuse the lawful two-level tree.
#[test]
fn a_second_halving_list_is_not_read() {
    for (label, a) in toys() {
        let mut a = identity_padded(a);
        let (abm_product, fingerprint3_product) = (inner(3, 0), inner(3, 1));
        let tree = |input| GateDef::TreeProduct { input };
        let first = a.relations.len() as u32;
        a.relations.push(Relation {
            name: "define_abm_product_2".into(),
            output: Some(7),
            gate: tree(PolyAddress::Scratch(5)),
        });
        a.relations.push(Relation {
            name: "define_fingerprint3_product_2".into(),
            output: Some(8),
            gate: tree(PolyAddress::Scratch(6)),
        });
        a.layers.push(LayerSpec {
            halving: true,
            num_vars: 2,
            width: 2,
            cached: vec![],
            producing: vec![
                ProducingEntry {
                    relation: first,
                    output: inner(4, 0),
                    gate: tree(abm_product),
                },
                ProducingEntry {
                    relation: first + 1,
                    output: inner(4, 1),
                    gate: tree(fingerprint3_product),
                },
            ],
            enforcing: vec![],
        });
        for (name, offset) in [("abm_product_2", 0), ("fingerprint3_product_2", 1)] {
            a.scratch.push(ScratchSlot {
                name: name.into(),
                address: inner(4, offset),
            });
        }
        a.outputs = vec![inner(4, 1), inner(4, 0)];
        assert_eq!(check_laws(&a), Ok(()), "{label}");
        assert_eq!(check_padding_identity(&a), Ok(()), "{label}");

        a.padding.row[B] = Fr::from_u64(2);
        let e = check_padding_identity(&a).unwrap_err();
        let named = "halving gate list 2 reads L{2}[0] (abm), which is 2 on padding.row";
        assert!(e.contains(named), "{label}: {e}");
    }
}

/// An artifact with no halving list has no product tree over its rows, and
/// passes whatever its padding row: the toy cut below its halving list — list
/// 2, its two relations and its two scratch slots removed, the outputs
/// `L{2}[0]` and `L{2}[1]` — keeps the laws and passes, with the zero padding
/// row the whole toy fails on.
#[test]
fn an_artifact_with_no_halving_list_passes() {
    for (label, mut a) in toys() {
        a.layers.pop();
        a.relations.truncate(relation(&a, "define_abm_product"));
        a.scratch.truncate(slot(&a, "abm_product"));
        a.outputs = vec![inner(2, 0), inner(2, 1)];
        assert_eq!(check_laws(&a), Ok(()), "{label}");
        assert_eq!(check_padding_identity(&a), Ok(()), "{label}");
    }
}
