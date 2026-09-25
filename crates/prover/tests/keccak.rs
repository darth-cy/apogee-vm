//! S21's acceptance: one execution with a **delegation shard**, proved as a
//! block.
//!
//! `#[ignore]`d and deferred out of CI under master rule 7: the statement is
//! six `2^20` execution shards, two `2^16` window shards and one `2^8` keccak
//! shard, and the circuit is what makes it big — a keccak row is a whole
//! keccak-f[1600] permutation, 354,762 inner columns
//! (`docs/spec/delegation.md` §9). Run it with
//!
//! ```text
//! cargo test --release -p prover --test keccak -- --include-ignored --test-threads=1
//! ```
//!
//! The statement is `guests/keccak-test`'s (`tests/common/mod.rs`):
//! `guest_sdk::keccak256` over the sponge's six shapes, ten permutations in
//! all. Its `VmConfig` holds `KECCAK_F` because its **image declares it**, not
//! because any pc claims it — the third presence rule, and the one this stage
//! adds (`docs/spec/delegation.md` §7).
//!
//! `guests/keccak-unused` is the other half of acceptance 8: the same
//! declaration, zero invocations, zero shards.

mod common;

use constants::{delegation, family, memory as mem};
use prover::prove_block;
use trace::plan_shards;
use verifier::{verify_block, verify_shard};
use verifier_core::{statement_shards, BlockProof};

const KECCAK: u32 = family::KECCAK_F;
const ADD: u32 = family::ADD_SUB_LUI_AUIPC;
const INIT: u32 = family::INIT_TEARDOWN;

/// `docs/spec/shard-proof.md` §9's length formula over a circuit's own shape —
/// `crates/prover/tests/mem.rs`' `proof_bytes`, restated here so a shard of a
/// family with no channel is measured by the same rule as one with three.
fn proof_bytes(a: &constraints::CircuitArtifact) -> usize {
    let transitions: usize = (0..a.depth())
        .map(|k| {
            let claims = a.layer_width(k) as usize * if a.layers[k].halving { 2 } else { 1 };
            4 + 128 * a.layer_vars(k + 1) as usize + 4 + 32 * claims
        })
        .sum();
    4 + 4
        + 16
        + 32
        + (4 + 64 * a.witness.len())
        + (4 + 32 * a.outputs.len())
        + 4
        + transitions
        + 704
}

/// Acceptance 4: the statement proves to a `BlockProof` with one keccak shard,
/// `verify_block` returns `Ok`, and the read/write roots reconcile across the
/// CPU shards and the delegation shard together.
#[test]
#[ignore]
fn a4_the_block_with_a_delegation_shard_proves_and_verifies() {
    let setup = common::keccak_setup();
    let mut archive = common::keccak_archive(&setup.program);

    // The family set: `KECCAK_F` is in it at the delegation height, after every
    // family that claims a pc and after the two RAM window families. It is
    // **not** last since S-IO, whose three families take the highest ids; what
    // the position says is that a delegation family is not an execution one.
    let families: Vec<u32> = setup
        .program
        .config
        .families
        .iter()
        .map(|(f, _)| *f)
        .collect();
    assert_eq!(
        &families[families.len() - 4..],
        &[
            KECCAK,
            family::PUBLIC_INPUT,
            family::PUBLIC_OUTPUT,
            family::ADVICE_WINDOWS
        ]
    );
    assert_eq!(
        setup.program.config.height(KECCAK),
        Some(1 << common::KECCAK_VARS)
    );

    // The plan: one shard of the delegation family, from its invocations.
    let plan = plan_shards(archive.cycle_profile(), &setup.program.config);
    let shards = |f: u32| {
        plan.shards
            .iter()
            .find(|(g, _)| *g == f)
            .expect("a config family")
            .1
    };
    let invocations = archive
        .cycle_profile()
        .counts
        .iter()
        .find(|(f, _)| *f == KECCAK)
        .expect("the profile counts every config family")
        .1;
    assert_eq!(invocations, common::KECCAK_INVOCATIONS);
    assert_eq!(shards(KECCAK), 1);
    // An invocation is not a cycle: the profile's total is the execution's
    // cycle count and the invocations are outside it
    // (`docs/spec/delegation.md` §8).
    assert_eq!(
        archive.cycle_profile().total(),
        archive
            .cycle_profile()
            .counts
            .iter()
            .filter(|(f, _)| *f != KECCAK)
            .map(|(_, n)| n)
            .sum::<u64>()
    );

    let block = prove_block(&setup, &mut archive, &plan).expect("the block proves");
    assert_eq!(
        verify_block(&setup.vk, &block, block.statement()),
        Ok(()),
        "the block verifies"
    );

    // One shard per planned shard, in statement order, with the delegation
    // family's last.
    let expected = statement_shards(&setup.program.config, block.shard_counts());
    assert_eq!(block.shards.len(), expected.len());
    assert_eq!(
        &expected[expected.len() - 3..],
        &[
            (KECCAK, 0),
            (family::PUBLIC_INPUT, 0),
            (family::PUBLIC_OUTPUT, 0)
        ],
        "the delegation shard, then S-IO's two; this guest has no advice, so          `ADVICE_WINDOWS` proves no shard"
    );

    // Its ts window is the min and max invocation timestamp, not the trivial
    // one the two window families take.
    let keccak = block
        .shards
        .iter()
        .find(|s| s.family == KECCAK)
        .expect("a keccak shard");
    let buffer = archive
        .family_traces()
        .delegation(KECCAK)
        .expect("the archive has the delegation buffer");
    let ts = |c: u64| mem::TS_STEP * c + delegation::FRAME_DELTA;
    assert_eq!(
        keccak.ts_window,
        [
            ts(buffer.cycle[0]) - delegation::FRAME_DELTA,
            ts(buffer.cycle[buffer.len() - 1]) - delegation::FRAME_DELTA + mem::TS_STEP
        ],
        "the delegation shard's window is its invocations'"
    );
    // It overlaps the add/sub family's window, which is exactly why the block
    // asks for no disjointness from a family that owns no cycles.
    let add = block
        .shards
        .iter()
        .find(|s| s.family == ADD)
        .expect("an add/sub shard");
    assert!(
        keccak.ts_window[0] >= add.ts_window[0] && keccak.ts_window[1] <= add.ts_window[1],
        "the invocations ride cycles the add/sub family owns"
    );

    // The delegation shard's proof has its circuit's shape:
    // `docs/spec/shard-proof.md` §9's layout over `keccak::artifact(8)`, which
    // is `docs/spec/constraint-manifest.md` §1.2's 11,880,012 bytes. Almost
    // all of it is final claims — 358,540 of them — which is what a circuit
    // whose row is a whole permutation costs on the wire.
    let circuit = constraints::family_circuit(KECCAK, common::KECCAK_VARS)
        .expect("the registry has the keccak circuit");
    assert_eq!(
        keccak.to_bytes().len(),
        proof_bytes(&circuit.artifact),
        "the keccak shard's proof is its circuit's shape"
    );
    assert_eq!(keccak.to_bytes().len(), 11_880_012);

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
    assert_eq!(read.statement().exit_status, common::KECCAK_RESULT);
    assert_eq!(verify_block(&setup.vk, &read, read.statement()), Ok(()));
}

/// Acceptance 8's second half: a guest that **links** the shim and never calls
/// it declares the family, proves **zero** keccak shards, and verifies.
///
/// Zero-shard skipping needs no code of its own — `plan_shards`' `ceil(0 / h)`
/// is 0 — and this is what says so end to end, with the family in the config,
/// in the statement descriptor and in the global transcript's group list all
/// the same.
#[test]
#[ignore]
fn a8_a_declared_family_with_no_invocation_proves_zero_shards() {
    let setup = common::keccak_unused_setup();
    let mut archive = common::keccak_unused_archive(&setup.program);
    assert!(
        setup.program.config.height(KECCAK).is_some(),
        "the image declares the family"
    );
    let plan = plan_shards(archive.cycle_profile(), &setup.program.config);
    assert_eq!(
        plan.shards.iter().find(|(f, _)| *f == KECCAK),
        Some(&(KECCAK, 0)),
        "no invocation, no shard"
    );
    let block = prove_block(&setup, &mut archive, &plan).expect("the block proves");
    assert!(
        !block.shards.iter().any(|s| s.family == KECCAK),
        "a family with zero shards proves none"
    );
    assert!(
        block.shards.iter().any(|s| s.family == INIT),
        "and the window families still do"
    );
    assert_eq!(verify_block(&setup.vk, &block, block.statement()), Ok(()));
    assert_eq!(block.statement().exit_status, common::KECCAK_UNUSED_RESULT);
}
