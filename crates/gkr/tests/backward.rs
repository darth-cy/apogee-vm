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
