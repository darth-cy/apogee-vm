//! **The mini-block gate**: the pinned real-mainnet mini-block, proved and
//! verified, and the tamper twin that says what the proof binds.
//!
//! S25's acceptances 4 and 5. Both are `#[ignore]`d and CI asks for them by
//! name, for the two reasons every proving suite in this repository is: they
//! build a 2 MB `revm` image from source, and they prove a statement whose
//! shards are `2^20` rows each. §7 of `docs/handoff/S25-block.md` carries the
//! measurements.
//!
//! # What a mini-block proof says, exactly
//!
//! *"This VM executed `revm_block::run` over this canonical `BlockWitness` and
//! the journal is these bytes."* It does **not** say the witness is block
//! 26,057,509's real pre-state — nothing binds advice
//! (`docs/spec/public-values.md` §6) — and it makes **no state-root claim**,
//! which is what "mini-block" means. What connects the proof to the chain is
//! the fixture's pin, which a reader checks against a node themselves.
//!
//! `a5_a_corrupted_advice_cell_is_refused` is where that stops being a caveat
//! and becomes a measured fact: a corrupted advice cell is refused by the
//! memory argument, and a *consistently* corrupted one verifies.

mod common;

use std::path::PathBuf;

use checker::{Cell, Tamper, TamperHarness};
use constants::family;
use constraints::PolyAddress;
use field::Fr;
use host::fixture::{self, Mode, Pin};
use program::ProgramParams;
use prover::ProverSetup;
use verifier_core::VerifyError;

/// The fixture this suite proves.
const STEM: &str = "mini-block";

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn read(name: String) -> Vec<u8> {
    let path = vectors().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn pin() -> Pin {
    Pin::from_bytes(&read(fixture::pin_file(STEM))).expect("the pin decodes")
}

/// The heights this workload is preprocessed under: every family but a
/// delegation one at `2^20`, with `revm-block`'s own span ceiling.
///
/// `crates/prover/tests/revm.rs` says why this statement takes `2^20` for the
/// window families too, where every other statement in the repository takes
/// `2^16`: the image's file-backed bytes end well past the 256 KiB a `2^16`
/// window 0 covers.
fn params() -> ProgramParams {
    let mut heights = [revm_block::TRACE_HEIGHT_RELEASE; family::COUNT as usize];
    for (f, h) in heights.iter_mut().enumerate() {
        if program::delegation_ecall(f as u32).is_some() {
            *h = family::DEFAULT_HEIGHTS[f];
        }
    }
    ProgramParams {
        heights,
        bytecode_size_words: revm_block::BYTECODE_SIZE_WORDS,
        ..ProgramParams::defaults()
    }
}

/// The setup, built from a guest compiled at `--release`.
fn setup() -> ProverSetup {
    let elf = common::build_guest_bin(Mode::Mini.binary(), "gate");
    host::setup(&elf, &params(), common::toy_srs(20)).expect("revm-block registers")
}

fn advice() -> Vec<u8> {
    read(fixture::witness_file(STEM))
}

fn io() -> emulator::GuestIo {
    emulator::GuestIo {
        stdin: Vec::new(),
        input: Vec::new(),
        advice: advice(),
        hint: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Acceptance 4 — the mini-block gate
// ---------------------------------------------------------------------------

/// Prove the mini-block fixture and get `verify` Ok.
///
/// The gate the stage's testing ladder names, and the thing everything else in
/// this stage waited on: *"Do not attempt the full block before the mini-block
/// gate passes."*
#[test]
#[ignore = "builds the revm guest from source and proves a 2^20 statement"]
fn a4_the_mini_block_proves_and_verifies() {
    let pin = pin();
    let setup = setup();
    let proven = host::prove(&setup, &io()).expect("the block proves");

    assert_eq!(proven.exit_code, 0, "the guest did not run to completion");
    assert_eq!(
        proven.journal,
        read(fixture::journal_file(STEM)),
        "the proved journal is not the pinned one"
    );
    host::verify(&setup.vk, &proven.block).expect("the block verifies");

    // The statement carries the journal, which is the whole point of S-IO: a
    // verifier reads the block's result off the proof rather than being told
    // it.
    assert_eq!(
        proven.block.statement().output,
        proven.journal,
        "the statement does not carry the journal"
    );
    assert_eq!(
        proven.block.statement().exit_status,
        0,
        "the statement does not carry the exit status"
    );

    // Advice really is what fed it: this is the one statement shape in the
    // repository where the advice family proves more than nothing.
    let counts = proven.block.shard_counts();
    let at = setup
        .program
        .config
        .families
        .iter()
        .position(|(f, _)| *f == family::ADVICE_WINDOWS)
        .expect("ADVICE_WINDOWS is in every VmConfig");
    assert!(
        counts[at] >= 1,
        "the witness reached the guest as advice, so the advice family proves a shard"
    );

    println!(
        "a4: block {} proved, {} cycles, {} shards, {} proof bytes, journal {} bytes",
        pin.block_number,
        proven.cycles,
        counts.iter().sum::<u32>(),
        proven.block.to_bytes().len(),
        proven.journal.len()
    );
}

/// A statement that claims a different journal is refused.
///
/// The cheap half of the binding, and the one that does not need the tamper
/// harness: the honest proof is kept and the *claimed* bytes are changed. The
/// global phase is derived from the honest statement, so step 5 passes and step
/// 10c — the public output window's committed column against the verifier's own
/// extension of the claimed bytes — is the only thing left to refuse it.
#[test]
#[ignore = "builds the revm guest from source and proves a 2^20 statement"]
fn a4_a_claimed_journal_that_is_not_the_proved_one_is_refused() {
    let setup = setup();
    let proven = host::prove(&setup, &io()).expect("the block proves");
    host::verify(&setup.vk, &proven.block).expect("the honest block verifies");

    let mut block = proven.block.clone();
    let last = block.statement.output.len() - 1;
    block.statement.output[last] ^= 1;
    match host::verify(&setup.vk, &block) {
        Err(VerifyError::MemoryArgument(_)) => {}
        Err(VerifyError::Statement(_)) => {}
        other => panic!("a changed journal was not refused: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Acceptance 5 — the tamper twin
// ---------------------------------------------------------------------------

/// One corrupted witness cell, argument-pinned.
///
/// The witness reaches the guest as **advice**, whose family is
/// `constraints::memory::value_window_artifact`: two leaves, a product tree, no
/// enforcing gate, no lookup, no channel. So `Constraint` and `Lookup` are
/// *structurally* unreachable from an advice shard, and the harness recommits
/// the memory columns it changed, which rules out `Statement` and `Opening`.
/// Exactly one class is left, and it is the right one: the global memory
/// multiset. The execution's load of that advice word read the honest value, so
/// the read tuple matches no write and the roots do not reconcile.
///
/// **The negative control is the interesting half.** `build_value_window_columns`
/// leaves an untouched row at `(ts 0, value initial[y])` so that its init and
/// teardown tuples cancel — so moving `M[2]` *and* `M[1]` together on a row the
/// guest never read still verifies. That is the cell-level demonstration that
/// **nothing binds advice**, which is why the guest checks its witness itself
/// and why a mini-block proof is a claim about a witness rather than about the
/// chain.
#[test]
#[ignore = "builds the revm guest from source and proves a 2^20 statement, twice"]
fn a5_a_corrupted_advice_cell_is_refused() {
    let setup = setup();
    let io = io();
    let (traces, log, profile, execution) = emulator::trace_run(
        &setup.program.image,
        &io,
        &setup.program.tables,
        &setup.program.config,
    )
    .expect("the guest traces");
    assert_eq!(execution.exit_code, 0);
    let archive = trace::TraceArchive::from_execution(
        traces,
        log,
        profile,
        trace::IoStreams {
            input: execution.io.input,
            output: execution.io.output,
        },
        io.advice.clone(),
        trace::PhaseTiming { wall_nanos: 0 },
    );

    let harness = TamperHarness::new(&setup, &archive);
    let shard = (family::ADVICE_WINDOWS, 0u32);

    // `M[2]` is the advice window's committed init column: word `y` of the
    // region. Row 1 is the first payload word — row 0 is the length word — and
    // the guest reads every one of them while decoding the witness, so any of
    // them is a cell the execution depends on.
    let init = PolyAddress::Memory(2);
    let teardown = PolyAddress::Memory(1);
    let row = 1usize;
    let honest_init = harness.cell(shard.0, shard.1, init, row);
    let honest_teardown = harness.cell(shard.0, shard.1, teardown, row);
    assert_eq!(
        honest_init, honest_teardown,
        "a row the guest only reads has equal init and teardown values"
    );

    // One cell, and the memory argument is what refuses it.
    harness.assert_block_rejects(
        &Tamper {
            cells: vec![Cell {
                family: shard.0,
                shard: shard.1,
                address: init,
                row,
                value: honest_init + Fr::ONE,
            }],
            boundary: None,
        },
        VerifyError::MemoryArgument(""),
    );

    // The control: move both halves of an untouched row and the statement
    // balances again. Advice is bound by nothing, and this is what that means
    // in cells rather than in prose.
    let far = last_row(&harness, shard);
    let far_init = harness.cell(shard.0, shard.1, init, far);
    let far_teardown = harness.cell(shard.0, shard.1, teardown, far);
    assert_eq!(far_init, far_teardown, "row {far} is untouched");
    harness.assert_block_verifies(&Tamper {
        cells: vec![
            Cell {
                family: shard.0,
                shard: shard.1,
                address: init,
                row: far,
                value: far_init + Fr::ONE,
            },
            Cell {
                family: shard.0,
                shard: shard.1,
                address: teardown,
                row: far,
                value: far_teardown + Fr::ONE,
            },
        ],
        boundary: None,
    });
}

/// The last row of the advice window's shard: past the witness, so the guest
/// never read it.
fn last_row(harness: &TamperHarness, shard: (u32, u32)) -> usize {
    let height = revm_block::TRACE_HEIGHT_RELEASE as usize;
    let row = height - 1;
    // It really is untouched: an untouched row's timestamp is zero.
    assert_eq!(
        harness.cell(shard.0, shard.1, PolyAddress::Memory(0), row),
        Fr::ZERO,
        "row {row} was written by the execution, so it is not the control this test needs"
    );
    row
}
