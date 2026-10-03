//! **`max_in_flight` is a resource setting and nothing else.**
//!
//! `docs/spec/streaming.md` is normative and this file is what is left of its
//! acceptance. The streaming prover changes *when* a column exists: pass 1
//! commits each shard's `M` columns as the shard fills and runs G1–G11 over the
//! ordered list at the end, pass 2 re-executes and proves each shard as it
//! fills, holding at most `max_in_flight` of them — since S-PIPELINE, one per
//! worker. Every commitment, every absorption and every challenge is a
//! function of the statement and the shard's own columns, so the worker count
//! cannot reach one — and that is the claim here.
//!
//! # What this file lost at S-STREAM, and why it is not replaced
//!
//! Until S-STREAM these tests held the streamed block equal to
//! `prover::prove_block`'s, byte for byte, over the three arms of
//! `prover::ShardRows`. The archived path is no longer a proving path
//! (`docs/spec/streaming.md` §1) and a test may not run it, so that comparison
//! is gone and **nothing replaces it**: the owner's decision, taken with the
//! loss stated. What is genuinely lost is "two independent constructions
//! agree" — a change that moved the prover and the verifier together would now
//! pass. What survives is every other oracle, and between them they are not
//! weak:
//!
//! - `verify_block` on every statement every proving suite proves, which is a
//!   self-consistency check over the whole of `docs/spec/shard-proof.md`;
//! - `crates/emulator/tests/streaming.rs` — the executor's chunks against
//!   `trace_run`'s buffers, row for row, and its final state against the log's;
//! - `crates/checker/tests/memory.rs`'
//!   `the_row_reading_and_the_log_reading_of_a_frame_agree`, the two column
//!   readings compared over eight guests;
//! - `crates/prover/tests/block.rs`'s `a7`, which rebuilds the global commit
//!   phase from a `TraceArchive` and asserts its digest is the **streamed**
//!   block's first shard's — the one surviving place where an archived
//!   construction and a streamed one are held to the same bytes, and it costs
//!   no extra proof.
//!
//! The three `ShardRows` arms are each still proved and verified, by the suites
//! that are about them: `tests/block.rs` and `tests/acceptance.rs` the `Rows`
//! arm, `tests/keccak.rs` the `Invocations` arm, `tests/public_io.rs` the
//! `Window` arm. Re-proving them here would be the same mutation set at twice
//! the cost, which the root `CLAUDE.md`'s test-discipline rule forbids.
//!
//! Every test here is `#[ignore]`d and proves real statements: run with
//! `cargo test --release -p prover --test streaming -- --include-ignored
//! --test-threads=1`.

mod common;

use common::{empty_io, keccak_setup, setup};
use emulator::GuestIo;
use prover::{prove_block_streaming, ProverSetup, StreamingReport};

/// The same statement at one shard in flight and at eight is the same block.
///
/// Shards are placed by their statement position and each proof is a function
/// of the global state and its own columns, so the schedule cannot reach a
/// challenge — the same argument `docs/spec/block-proof.md` §5.2 makes about
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

/// S16's statement: `INIT_TEARDOWN`, one add/sub shard and the two public
/// windows — the `Rows` arm, and the cheapest real statement there is.
#[test]
#[ignore = "proves S16's statement twice"]
fn a1_the_streamed_block_does_not_depend_on_max_in_flight() {
    let r8 = same_at_one_and_eight("addsub", &setup(), &empty_io());
    // Its one add/sub shard is a partial buffer, proved alone at exit, and its
    // three window shards are one batch after it — so the peak is the window
    // batch, which `peak_in_flight` did not count until S-STREAM's review.
    assert_eq!(
        r8.peak_in_flight, 3,
        "addsub: the window families' batch is the largest"
    );
}

/// `guests/keccak-test`: a **delegation** shard, so the `Invocations` arm — and
/// the statement whose order puts a family the executor fills first *last*
/// (`docs/spec/delegation.md` §8).
///
/// That ordering is the one place where the worker count could plausibly reach
/// a proof: pass 2's workers finish shards in whatever order the schedule
/// picks, while the statement is in ascending-`FamilyId` order, so a block
/// whose two orders disagree is the case worth varying the bound over. The
/// `Window` arm needs no second run — a window family's shard is built after
/// the pipeline, over the final state, at any bound.
#[test]
#[ignore = "proves a delegation block twice"]
fn a2_a_block_with_a_delegation_shard_does_not_depend_on_max_in_flight() {
    same_at_one_and_eight("keccak-test", &keccak_setup(), &empty_io());
}
