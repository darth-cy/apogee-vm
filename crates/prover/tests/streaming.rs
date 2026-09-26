//! **The streamed block is the block `prove_block` makes, byte for byte.**
//!
//! `docs/spec/streaming.md` is normative and this file is its acceptance. The
//! streaming prover changes *when* a column exists and nothing else: pass 1
//! commits each shard's `M` columns as the shard fills and runs G1–G11 over the
//! ordered list at the end, pass 2 re-executes and proves each shard as it
//! fills. Every commitment, every absorption, every challenge and every proof
//! byte must therefore be the archived path's.
//!
//! Three statements, chosen for the three arms of `prover::ShardRows`:
//!
//! - `guests/addsub` — S16's statement: `INIT_TEARDOWN`, one add/sub shard and
//!   the two public value windows. The cheapest real statement there is.
//! - `guests/keccak-test` — a **delegation** shard, so the `Invocations` arm,
//!   and the one whose statement order puts a family the executor fills first
//!   *last* (`docs/spec/delegation.md` §8).
//! - `guests/public-io` — a **public input** and an **advice** window, so the
//!   `Window` arm over a state the execution chose, and the statement whose
//!   `input` and `output` are not empty.
//!
//! Every test here is `#[ignore]`d and proves a real statement: run with
//! `cargo test --release -p prover --test streaming -- --include-ignored
//! --test-threads=1`. **What runs in ordinary CI instead** is
//! `crates/emulator/tests/streaming.rs` — the executor's chunks against
//! `trace_run`'s buffers, row for row, and its final state against the log's —
//! and `crates/checker/tests/memory.rs`'
//! `the_row_reading_and_the_log_reading_of_a_frame_agree`, the two column
//! readings compared over seven guests. Between them they cover everything the
//! streaming path does differently; what only these tests can add is that the
//! *bytes* come out the same, which needs a proof.

mod common;

use common::{
    archive, keccak_archive, keccak_program, keccak_setup, program, public_io_archive,
    public_io_input, public_io_program, public_io_setup, setup,
};
use emulator::GuestIo;
use prover::{prove_block, prove_block_streaming, ProverSetup};
use trace::{plan_shards, TraceArchive};
use verifier_core::BlockProof;

/// A run with nothing on any stream: what every committed guest but
/// `public-io` takes.
fn empty_io() -> GuestIo {
    GuestIo {
        stdin: Vec::new(),
        input: Vec::new(),
        advice: Vec::new(),
        hint: Vec::new(),
    }
}

/// The archived block, for comparison.
fn archived(setup: &ProverSetup, mut archive: TraceArchive) -> BlockProof {
    let plan = plan_shards(archive.cycle_profile(), &setup.program.config);
    prove_block(setup, &mut archive, &plan).expect("the archived block proves")
}

/// The two blocks, and the assertion that they are one block.
fn same_block(
    label: &str,
    setup: &ProverSetup,
    io: &GuestIo,
    archive: TraceArchive,
    in_flight: usize,
) {
    let want = archived(setup, archive);
    let (got, report) =
        prove_block_streaming(setup, io, in_flight).expect("the streamed block proves");
    assert_eq!(
        got.to_bytes(),
        want.to_bytes(),
        "{label}: the streamed block is not the archived one"
    );
    // And it is a block a verifier accepts, which is a different claim from
    // equality: if `prove_block` were broken the two could agree and neither
    // verify.
    verifier::verify_block(&setup.vk, &got, got.statement()).expect("the streamed block verifies");
    assert_eq!(
        report.shards,
        got.shard_proofs().len(),
        "{label}: the report's shard count"
    );
    assert!(
        report.peak_in_flight <= in_flight,
        "{label}: {} shards in flight above the bound {in_flight}",
        report.peak_in_flight
    );
    assert_eq!(
        report.cycles,
        archive_cycles(setup, io),
        "{label}: the report's cycle count"
    );
}

/// The execution's cycle count, from a plain run: the report's own number has
/// to come from somewhere independent.
fn archive_cycles(setup: &ProverSetup, io: &GuestIo) -> u64 {
    emulator::run(&setup.program.image, io)
        .expect("the guest runs")
        .cycle_count
}

#[test]
#[ignore = "proves S16's statement twice"]
fn a1_the_streamed_block_is_the_archived_block() {
    let setup = setup();
    let program = program();
    same_block("addsub", &setup, &empty_io(), archive(&program), 4);
}

#[test]
#[ignore = "proves a nine-shard block with a delegation shard twice"]
fn a2_a_block_with_a_delegation_shard_streams_identically() {
    let setup = keccak_setup();
    let program = keccak_program();
    same_block(
        "keccak-test",
        &setup,
        &empty_io(),
        keccak_archive(&program),
        4,
    );
}

#[test]
#[ignore = "proves S-IO's statement twice"]
fn a3_the_public_value_and_advice_windows_stream_identically() {
    let setup = public_io_setup();
    let program = public_io_program();
    let advice: Vec<u8> = (0..64u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect();
    let io = GuestIo {
        stdin: Vec::new(),
        input: public_io_input(&advice),
        advice: advice.clone(),
        hint: Vec::new(),
    };
    same_block(
        "public-io",
        &setup,
        &io,
        public_io_archive(&program, &advice),
        4,
    );
}

/// The backpressure bound is a resource setting and nothing else: a block
/// streamed one shard at a time and eight at a time is the same block.
///
/// Shards are placed by their statement position and each proof is a function of
/// the global state and its own columns, so the schedule cannot reach a
/// challenge — the same argument `docs/spec/block-proof.md` §5.2 makes about the
/// thread count, and the same one that makes `max_in_flight` safe to tune.
#[test]
#[ignore = "proves S16's statement twice more"]
fn a4_the_streamed_block_does_not_depend_on_max_in_flight() {
    let setup = setup();
    let io = empty_io();
    let (one, r1) = prove_block_streaming(&setup, &io, 1).expect("one at a time");
    let (eight, r8) = prove_block_streaming(&setup, &io, 8).expect("eight at a time");
    assert_eq!(
        one.to_bytes(),
        eight.to_bytes(),
        "the block depends on max_in_flight"
    );
    assert_eq!(r1.peak_in_flight, 1, "one shard at a time");
    assert!(r8.peak_in_flight >= 1 && r8.peak_in_flight <= 8);
    assert_eq!(r1.cycles, r8.cycles);
    assert_eq!(r1.shards, r8.shards);
}
