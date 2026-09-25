//! S23's acceptance: one execution with **both** recursion delegation shards,
//! proved as a block.
//!
//! `#[ignore]`d and deferred out of CI under master rule 7: the statement is
//! several `2^20` execution shards, two `2^16` window shards and one `2^8`
//! shard of each delegation family. Run it with
//!
//! ```text
//! cargo test --release -p prover --test recursion -- --include-ignored --test-threads=1
//! ```
//!
//! The statement is `guests/recursion-ops`' (`tests/common/mod.rs`): ordinary
//! `field::Fr` arithmetic and `transcript::poseidon2_permute`, which the
//! guest-target backends inside those two crates route through the two
//! delegations. The guest names no shim, which is the point — S26's verifier
//! guest will write the same ordinary arithmetic.
//!
//! `guests/recursion-unused` is the other half of acceptance 9: the same
//! declarations, zero invocations, zero shards.

mod common;

use constants::family;
use prover::prove_block;
use trace::plan_shards;
use verifier::{verify_block, verify_shard};
use verifier_core::{statement_shards, BlockProof};

const POSEIDON2: u32 = family::POSEIDON2;
const FR_ARITH: u32 = family::FR_ARITH;
const ADD: u32 = family::ADD_SUB_LUI_AUIPC;
const INIT: u32 = family::INIT_TEARDOWN;

/// Acceptance 4: the statement proves to a `BlockProof` with at least one
/// shard of **each** new family, `verify_block` returns `Ok`, and the
/// read/write roots reconcile across the CPU shards and both delegation
/// shards together.
#[test]
#[ignore]
fn a4_the_block_with_both_delegation_shards_proves_and_verifies() {
    let setup = common::recursion_setup();
    let mut archive = common::recursion_archive(&setup.program);

    // The family set: both delegation families are in it in id order, each at
    // the delegation height, after every family that claims a pc and after the
    // two RAM window families. They are **not** last since S-IO, whose three
    // families take the highest ids. Every other family is there because it
    // claims a pc.
    let families: Vec<u32> = setup
        .program
        .config
        .families
        .iter()
        .map(|(f, _)| *f)
        .collect();
    assert_eq!(
        &families[families.len() - 5..],
        &[
            POSEIDON2,
            FR_ARITH,
            family::PUBLIC_INPUT,
            family::PUBLIC_OUTPUT,
            family::ADVICE_WINDOWS
        ],
        "the two delegation families sort after the execution ones and before S-IO's three"
    );
    for f in [POSEIDON2, FR_ARITH] {
        assert_eq!(
            setup.program.config.height(f),
            Some(1 << common::DELEGATION_VARS)
        );
    }

    let plan = plan_shards(archive.cycle_profile(), &setup.program.config);
    let shards = |f: u32| {
        plan.shards
            .iter()
            .find(|(g, _)| *g == f)
            .expect("a config family")
            .1
    };
    for f in [POSEIDON2, FR_ARITH] {
        assert_eq!(shards(f), 1, "one shard of each");
        let invocations = archive
            .cycle_profile()
            .counts
            .iter()
            .find(|(g, _)| *g == f)
            .expect("the profile counts every config family")
            .1;
        assert!(invocations > 0, "at least one invocation");
    }
    // An invocation is not a cycle: the profile's total is the execution's
    // cycle count and the invocations are outside it
    // (`docs/spec/delegation.md` §8).
    assert_eq!(
        archive.cycle_profile().total(),
        archive
            .cycle_profile()
            .counts
            .iter()
            .filter(|(f, _)| *f != POSEIDON2 && *f != FR_ARITH)
            .map(|(_, n)| n)
            .sum::<u64>()
    );

    let block = prove_block(&setup, &mut archive, &plan).expect("the block proves");
    assert_eq!(
        verify_block(&setup.vk, &block, block.statement()),
        Ok(()),
        "the block verifies"
    );

    // One shard per planned shard, in statement order: the two delegation
    // shards, then S-IO's two public value ones. This guest has no advice, so
    // `ADVICE_WINDOWS` proves no shard.
    let expected = statement_shards(&setup.program.config, block.shard_counts());
    assert_eq!(block.shards.len(), expected.len());
    assert_eq!(
        &expected[expected.len() - 4..],
        &[
            (POSEIDON2, 0),
            (FR_ARITH, 0),
            (family::PUBLIC_INPUT, 0),
            (family::PUBLIC_OUTPUT, 0)
        ]
    );

    // Each delegation shard's ts window overlaps the add/sub family's, which
    // is exactly why the block asks no disjointness of a family that owns no
    // cycles.
    let add = block
        .shards
        .iter()
        .find(|s| s.family == ADD)
        .expect("an add/sub shard");
    for f in [POSEIDON2, FR_ARITH] {
        let shard = block
            .shards
            .iter()
            .find(|s| s.family == f)
            .unwrap_or_else(|| panic!("a shard of {}", program::family_name(f)));
        assert!(
            shard.ts_window[0] < shard.ts_window[1],
            "a delegation window is non-empty"
        );
        assert!(
            shard.ts_window[0] >= add.ts_window[0] && shard.ts_window[1] <= add.ts_window[1],
            "the invocations ride cycles the add/sub family owns"
        );
    }

    // Every shard verifies on its own too, through the one entry point.
    for shard in &block.shards {
        assert_eq!(
            verify_shard(&setup.vk, shard, block.statement()),
            Ok(()),
            "family {} shard {}",
            shard.family,
            shard.shard_index
        );
    }

    // The statement reads back through the serialized block alone.
    let bytes = block.to_bytes();
    let read = BlockProof::from_bytes(&bytes).expect("the block round-trips");
    assert_eq!(read.statement().exit_status, common::RECURSION_RESULT);
    assert_eq!(verify_block(&setup.vk, &read, read.statement()), Ok(()));
}

/// Acceptance 9's second half: a guest that **links** both backends and
/// reaches neither declares both families, proves **zero** shards of each, and
/// verifies.
#[test]
#[ignore]
fn a9_declared_families_with_no_invocation_prove_zero_shards() {
    let setup = common::recursion_unused_setup();
    let mut archive = common::recursion_unused_archive(&setup.program);
    for f in [POSEIDON2, FR_ARITH] {
        assert!(
            setup.program.config.height(f).is_some(),
            "the image declares {}",
            program::family_name(f)
        );
    }
    let plan = plan_shards(archive.cycle_profile(), &setup.program.config);
    for f in [POSEIDON2, FR_ARITH] {
        assert_eq!(
            plan.shards.iter().find(|(g, _)| *g == f),
            Some(&(f, 0)),
            "no invocation, no shard"
        );
    }
    let block = prove_block(&setup, &mut archive, &plan).expect("the block proves");
    assert!(
        !block
            .shards
            .iter()
            .any(|s| s.family == POSEIDON2 || s.family == FR_ARITH),
        "a family with zero shards proves none"
    );
    assert!(
        block.shards.iter().any(|s| s.family == INIT),
        "and the window families still do"
    );
    assert_eq!(verify_block(&setup.vk, &block, block.statement()), Ok(()));
    assert_eq!(
        block.statement().exit_status,
        common::RECURSION_UNUSED_RESULT
    );
}
