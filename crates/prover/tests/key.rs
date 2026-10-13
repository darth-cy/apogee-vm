//! The verifying key's construction, in ordinary CI: `ProverSetup::new` over
//! `guests/control`. Nothing is proved here; `tests/control.rs` proves the
//! statement.
//!
//! **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** The key
//! carries no commitment: not the decoded tables', not the image column's, not
//! the generic table's. What a commitment scheme puts in it must be tested here
//! once one exists (`docs/architecture.md` §0).

mod common;

/// The key `ProverSetup::new` builds carries the program's identity and one
/// circuit per config family, round-trips through its wire form and loads.
#[test]
fn the_key_round_trips_and_loads() {
    let setup = common::control_setup();
    let vk = &setup.vk;
    assert_eq!(
        vk.identity,
        program::program_identity(
            &setup.program.image,
            &setup.program.tables,
            &setup.program.config
        )
    );
    assert_eq!(vk.circuits.len(), vk.config.families.len());
    assert_eq!(verifier::load_verifying_key(&vk.to_bytes()), Ok(vk.clone()));
}
