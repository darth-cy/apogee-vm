//! The verifying key's construction, in ordinary CI: `ProverSetup::new` over
//! `guests/control` and the toy SRS, and the packed generic table's
//! commitments against a reference computed from the toy SRS's `tau`. Nothing
//! is proved here; `tests/control.rs` proves the statement.

mod common;

use curve::G1Projective;
use field::Fr;
use program::lookup_tables::{generic_commitments, generic_table, GENERIC_LOG_HEIGHT};
use verifier_core::srs_digest;

/// The key `ProverSetup::new` builds carries the generic table's commitments
/// over its SRS, its SRS digest is over them and its `SrsVerifier`, and it
/// loads.
#[test]
fn the_key_carries_the_generic_table_its_digest_covers() {
    let setup = common::control_setup();
    let table = generic_commitments(&setup.srs).map(|p| p.to_bytes());
    assert_eq!(setup.vk.generic_table, table);
    assert_eq!(
        setup.vk.srs_digest,
        srs_digest(&setup.vk.srs_verifier, &table)
    );
    assert_eq!(
        verifier::load_verifying_key(&setup.vk.to_bytes()),
        Ok(setup.vk.clone())
    );
}

/// Each commitment is `[Σ_i c_i·τ^i]_1` over its column read as
/// coefficients — computed here by Horner's rule from the toy SRS's `τ`, not
/// through `pcs` — the three are distinct, and an SRS of `2^18` powers, the
/// least the table needs, gives the same three as one of `2^20`.
#[test]
fn the_generic_table_commits_to_its_columns_at_every_height() {
    let tau = common::toy_tau();
    let small = generic_commitments(&common::toy_srs(GENERIC_LOG_HEIGHT));
    for (j, column) in generic_table(GENERIC_LOG_HEIGHT).iter().enumerate() {
        let mut acc = Fr::ZERO;
        for i in (0..1usize << GENERIC_LOG_HEIGHT).rev() {
            acc = acc * tau + column.get(i);
        }
        assert_eq!(
            small[j],
            G1Projective::GENERATOR.mul(&acc).to_affine(),
            "column {j}"
        );
    }
    assert!(small[0] != small[1] && small[1] != small[2] && small[0] != small[2]);
    assert_eq!(small, generic_commitments(&common::toy_srs(20)));
}
