//! One execution with **both** `Fr` delegation shards, `POSEIDON2` and
//! `FR_ARITH`, proved as a block.
//!
//! `#[ignore]`d, and CI does not run it: the statement is several `2^20`
//! execution shards, two `2^16` window shards and one `2^8` shard of each
//! delegation family. Run it with
//!
//! ```text
//! cargo test --release -p prover --test recursion -- --include-ignored --test-threads=1
//! ```
//!
//! The statement is `guests/recursion-ops`' (`tests/common/mod.rs`): ordinary
//! `field::Fr` arithmetic and `transcript::poseidon2_permute`, which the
//! guest-target backends inside those two crates route through the two
//! delegations. The guest names no shim, which is the point: ordinary
//! arithmetic reaches the delegations.

mod common;

use constants::family;
use trace::plan_shards;
use verifier::{verify_block, verify_shard};
use verifier_core::{statement_shards, BlockProof};

const POSEIDON2: u32 = family::POSEIDON2;
const FR_ARITH: u32 = family::FR_ARITH;
const ADD: u32 = family::ADD_SUB_LUI_AUIPC;
/// The statement proves to a `BlockProof` with at least one shard of **each**
/// of the two delegation families, `verify_block` returns `Ok`, and the
/// read/write roots reconcile across the CPU shards and both delegation
/// shards together.
#[test]
#[ignore]
fn a4_the_block_with_both_delegation_shards_proves_and_verifies() {
    let setup = common::recursion_setup();
    let archive = common::recursion_archive(&setup.program);

    // The family set: both delegation families are in it in id order, each at
    // the delegation height, after every family that claims a pc and after
    // `INIT_TEARDOWN` and `ZERO_WINDOWS`. They are **not** last: the
    // public-value and advice families take higher ids. Every other family is
    // there because it claims a pc.
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
        "the two delegation families sort after the execution ones and before the \
         public-value and advice families"
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

    let block = common::streamed(&setup, &common::empty_io());
    assert_eq!(
        verify_block(&setup.vk, &block, block.statement()),
        Ok(()),
        "the block verifies"
    );

    // One shard per planned shard, in statement order: the two delegation
    // shards, then the two public value ones. This guest has no advice, so
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
