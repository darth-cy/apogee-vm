//! **`max_in_flight` is a resource setting and nothing else.**
//!
//! `docs/spec/streaming.md` specifies the streaming prover. It changes *when* a
//! column exists: pass 1 runs the execution to its end and G1–G9 over the
//! statement, pass 2 re-executes and proves each shard as it fills, holding at
//! most `max_in_flight` of them, one per worker. Every absorption and every
//! challenge is a function of the statement and the shard's own columns, so
//! the worker count cannot reach one — and that is the claim here.
//!
//! Pass 1 commits each shard's `M` columns as the shard fills, and the global
//! transcript absorbs the ordered list before the memory challenges.
//!
//! # What holds the streamed block
//!
//! No test runs `prover::prove_block`, so no test holds a whole streamed block
//! equal to an independently assembled one, and a change that moved the prover
//! and the verifier together would pass. What holds it is every other oracle:
//!
//! - `verify_block` on every statement every proving suite proves, which is a
//!   self-consistency check over the whole of `docs/spec/proof.md`;
//! - `crates/emulator/tests/streaming.rs` — the executor's chunks against
//!   `trace_run`'s buffers, row for row, and its final state against the log's;
//! - `crates/checker/tests/memory.rs`'
//!   `the_row_reading_and_the_log_reading_of_a_frame_agree`, the two column
//!   readings compared over eight guests;
//! - `crates/prover/tests/block.rs`'s `a7` and
//!   `the_block_does_not_depend_on_the_thread_count`, which rebuild the global
//!   commit phase from a `TraceArchive` and hold its digest — and, in the
//!   second, every shard's proof made from the archive — to the **streamed**
//!   block's: where an archived construction and a streamed one are held to
//!   the same bytes.
//!
//! The three `ShardRows` arms are each proved and verified by the suites that
//! are about them: `tests/block.rs` and `tests/acceptance.rs` the `Cycles` arm,
//! `tests/public_io.rs` the `Window` arm, and `a2` here the `Invocations` arm.
//! Re-proving them here would be the same mutation set at twice the cost.
//!
//! Every test here is `#[ignore]`d and proves real statements: run with
//! `cargo test --release -p prover --test streaming -- --include-ignored
//! --test-threads=1`.

mod common;

use common::{empty_io, setup};
use emulator::GuestIo;
use prover::{prove_block_streaming, ProverSetup, StreamingReport};

/// The same statement at one shard in flight and at eight is the same block.
///
/// Shards are placed by their statement position and each proof is a function
/// of the global state and its own columns, so the schedule cannot reach a
/// challenge — the same argument `docs/spec/streaming.md` §5 makes about
/// the thread count, and the same one that makes `max_in_flight` safe to tune.
/// `tests/block.rs`'s `the_block_does_not_depend_on_the_thread_count` is the
/// other half: this one varies the worker count, that one the pool.
fn same_at_one_and_eight(label: &str, setup: &ProverSetup, io: &GuestIo) -> StreamingReport {
    let (one, r1) = prove_block_streaming(setup, io, 1).expect("one at a time");
    let (eight, r8) = prove_block_streaming(setup, io, 8).expect("eight at a time");
    assert_eq!(
        one.to_bytes(),
        eight.to_bytes(),
        "{label}: the block depends on max_in_flight"
    );
    // And it is a block a verifier accepts, which is a different claim from
    // equality: two runs of a broken prover would agree and neither verify.
    verifier::verify_block(&setup.vk, &one, one.statement()).expect("the streamed block verifies");
    assert_eq!(r1.peak_in_flight, 1, "{label}: one shard at a time");
    assert!(
        r8.peak_in_flight >= 1 && r8.peak_in_flight <= 8,
        "{label}: {} shards in flight above the bound 8",
        r8.peak_in_flight
    );
    assert_eq!(r1.cycles, r8.cycles, "{label}: the cycle count");
    assert_eq!(r1.shards, r8.shards, "{label}: the shard count");
    assert_eq!(
        r1.shards,
        one.shard_proofs().len(),
        "{label}: the report's shard count is the block's"
    );
    r8
}

/// `guests/addsub`'s statement: `INIT_TEARDOWN`, one add/sub shard and the two
/// public windows — the `Cycles` arm, and the cheapest real statement there is.
#[test]
#[ignore = "proves the addsub statement twice"]
fn a1_the_streamed_block_does_not_depend_on_max_in_flight() {
    let r8 = same_at_one_and_eight("addsub", &setup(), &empty_io());
    // Its one add/sub shard is a partial buffer, proved alone at exit, and its
    // three window shards are one batch after it — so the peak is the window
    // batch, which `peak_in_flight` counts.
    assert_eq!(
        r8.peak_in_flight, 3,
        "addsub: the window families' batch is the largest"
    );
}

/// `guests/precompiles`' statement: the three precompiles, so the `Invocations`
/// arm — each of their six families a shard — beside
/// its execution and window shards; proved once at the default in flight and verified,
/// its journal the run's. `crates/checker/tests/precompiles.rs` holds that
/// journal to the host's and the statement's multiset to its circuits.
#[test]
#[ignore = "proves the precompiles statement"]
fn a2_a_statement_with_precompile_calls_streams_and_verifies() {
    let setup = ProverSetup::new(common::precompiles_program()).expect("precompiles registers");
    let io = GuestIo {
        input: [
            1u32.to_le_bytes().as_slice(),
            &[0u8; 64],
            &0u32.to_le_bytes(),
            &16u32.to_le_bytes(),
            &[0u8; 64 * 16],
            &0u32.to_le_bytes(),
        ]
        .concat(),
        advice: Vec::new(),
    };
    let (block, _) =
        prove_block_streaming(&setup, &io, prover::DEFAULT_MAX_IN_FLIGHT).expect("it proves");
    verifier::verify_block(&setup.vk, &block, block.statement()).expect("it verifies");
    let run = emulator::run(&setup.program.image, &io).expect("it runs");
    assert_eq!(
        block.statement().output,
        run.io.output,
        "the journal is the run's"
    );
    for family in [
        constants::family::POSEIDON2,
        constants::family::POSEIDON2_ROUNDS,
        constants::family::MUL_DIV_U256,
        constants::family::MERKLE_ROOT,
        constants::family::MERKLE_LEVELS,
        constants::family::MERKLE_ROUNDS,
    ] {
        let at = setup
            .program
            .config
            .families
            .iter()
            .position(|(f, _)| *f == family);
        let count = at.map(|i| block.statement().shard_counts[i]);
        assert_eq!(count, Some(1), "one shard of family {family}");
    }
}
