//! The backward pass over the committed toy circuit: the honest run
//! (acceptance 1), its proof shape (must-be-exact 5), and base claims that
//! check against the base.

mod common;

use common::{discharge, honest, toy, toy_base, toy_cache_free, toy_columns};
use gkr::self_check;

/// Acceptance 1: forward, self-check, prove and verify the toy, and hold every
/// returned base claim to a direct evaluation of the column it names.
#[test]
fn an_honest_toy_run_verifies_and_its_base_claims_discharge() {
    for artifact in [toy(), toy_cache_free()] {
        for seed in 0..8u64 {
            let base = toy_base(&toy_columns(0x5313_0100 + seed));
            let (values, _, result) = honest(&artifact, &base);
            let (_, challenges) = common::bind(&artifact, &base);
            self_check(&artifact, &values, &challenges)
                .expect("the forward pass satisfies its gates");
            let claims = result.expect("an honest proof verifies");
            assert_eq!(claims.len(), 6, "one claim per committed column");
            let point = &claims[0].point;
            assert_eq!(
                point.len(),
                4,
                "a base claim point has the trace's variables"
            );
            assert!(
                claims.iter().all(|c| &c.point == point),
                "all base claims share one point"
            );
            assert_eq!(
                claims.iter().map(|c| c.address).collect::<Vec<_>>(),
                artifact.committed(),
                "base claims come in layout order"
            );
            discharge(&base, &claims).expect("every base claim is the column's evaluation");
        }
    }
}

/// Must-be-exact 5: four coefficients per round, one round per variable of
/// the layer each transition writes, and one claim per column it reads — two
/// per column for the halving list.
#[test]
fn the_proof_has_the_frozen_shape() {
    let artifact = toy();
    let base = toy_base(&toy_columns(0x5313_0200));
    let (_, proof, result) = honest(&artifact, &base);
    result.expect("an honest proof verifies");
    let rounds: Vec<usize> = proof.layers.iter().map(|l| l.rounds.len()).collect();
    let claims: Vec<usize> = proof.layers.iter().map(|l| l.final_evals.len()).collect();
    assert_eq!(
        rounds,
        vec![4, 4, 3],
        "rounds are the written layer's variable count"
    );
    assert_eq!(
        claims,
        vec![6, 3, 4],
        "claims per read column, doubled when halving"
    );
}

/// A zero claim is legal. With `b = 0` every `abm` is 0, and with `a = 0` and
/// `c = −3/row` on the upper half of the rows every `fingerprint3` there is 0,
/// so both output tables — and the first batched claim — are exactly zero, and
/// the honest proof of it verifies.
#[test]
fn an_all_zero_output_verifies() {
    let artifact = toy();
    let mut cols = toy_columns(0x5313_0250);
    cols.b = vec![0; common::TOY_ROWS];
    let half = common::TOY_ROWS / 2;
    for y in half..common::TOY_ROWS {
        cols.a[y] = 0;
        if cols.s[y] == 1 {
            cols.e[y] = 0;
        }
    }
    let c: Vec<field::Fr> = (0..common::TOY_ROWS)
        .map(|y| {
            if y < half {
                field::Fr::from_u64(cols.c[y] as u64)
            } else {
                -field::Fr::from_u64(3) * field::Fr::from_u64(y as u64).inverse().unwrap()
            }
        })
        .collect();
    let base = common::with_column(
        &toy_base(&cols),
        &artifact,
        constraints::PolyAddress::Witness(2),
        c,
    );
    let (values, _, result) = honest(&artifact, &base);
    for table in &common::output_claims(&artifact, &values).tables {
        assert!(
            (0..table.len()).all(|i| table.get(i) == field::Fr::ZERO),
            "every output is zero"
        );
    }
    let claims = result.expect("an honest proof of zero outputs verifies");
    discharge(&base, &claims).expect("and its base claims discharge");
}
