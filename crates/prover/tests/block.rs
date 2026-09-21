//! S20's acceptance: one execution proved as a **block**.
//!
//! `#[ignore]`d and deferred out of CI under master rule 7: the statement is
//! three `2^20` shards and one `2^16` one, and the circuit is what makes it
//! big. Run it with
//!
//! ```text
//! cargo test --release -p prover --test block -- --include-ignored --test-threads=1
//! ```
//!
//! The statement is `guests/shards`' (`tests/common/mod.rs`): a counted loop
//! whose `ADD_SUB_LUI_AUIPC` family runs 1,064,970 cycles, so the plan cuts it
//! into **two shards of one family** — S20's stage gate — with
//! `JUMP_BRANCH_SLT` in one shard, `INIT_TEARDOWN` in one, and `ZERO_WINDOWS`
//! in none, because nothing in the guest touches RAM.

mod common;

use std::io::Cursor;

use constants::family;
use field::Fr;
use prover::{
    advance, finish, global_commit_phase, prove_block, prove_shard_columns, public_inputs,
    shard_columns, statement_inputs, ProverSetup, ProvingContext,
};
use trace::{plan_shards, Phase, TraceArchive};
use verifier::{verify_block, verify_shard};
use verifier_core::{statement_shards, BlockProof, ShardProof, VerifyError, TRIVIAL_TS_WINDOW};

const ADD: u32 = family::ADD_SUB_LUI_AUIPC;
const JBS: u32 = family::JUMP_BRANCH_SLT;
const INIT: u32 = family::INIT_TEARDOWN;
const ZERO: u32 = family::ZERO_WINDOWS;

/// The honest block, and everything it was proved from.
fn proved() -> (ProverSetup, TraceArchive, BlockProof) {
    let setup = common::shards_setup();
    let mut archive = common::shards_archive(&setup.program);
    let plan = plan_shards(archive.cycle_profile(), &setup.program.config);
    let block = prove_block(&setup, &mut archive, &plan).expect("the block proves");
    (setup, archive, block)
}

/// Acceptance 1, 3's positive half, 8 and 9: one execution split across two
/// shards of one family proves to a `BlockProof` and verifies; the global
/// challenges are squeezed exactly once, after every commitment; nothing
/// chains a pc across the shard boundary; a family with zero shards is valid;
/// and the public data reads through the serialized proof alone.
#[test]
#[ignore]
fn a1_a3_a8_a9_the_two_shard_block_proves_and_verifies() {
    let (setup, archive, block) = proved();

    // The plan: two shards of ADD_SUB_LUI_AUIPC, one of JUMP_BRANCH_SLT, one
    // INIT_TEARDOWN, no ZERO_WINDOWS. **Why** there are two is the occupancy:
    // the guest's add/sub family runs past its height, and there is no smaller
    // height a cycle-owning family can have.
    assert_eq!(
        setup.program.config.families,
        vec![
            (ADD, 1 << 20),
            (JBS, 1 << 20),
            (INIT, 1 << 16),
            (ZERO, 1 << 16)
        ]
    );
    let occupancy = |f: u32| {
        archive
            .cycle_profile()
            .counts
            .iter()
            .find(|(g, _)| *g == f)
            .expect("a config family")
            .1
    };
    assert_eq!(occupancy(ADD), common::SHARDS_ADD_CYCLES);
    assert!(
        occupancy(ADD) > 1 << 20 && occupancy(ADD) <= 2 << 20,
        "the add/sub family spills into exactly one more shard"
    );
    assert!(occupancy(JBS) <= 1 << 20, "the jump family fits one shard");
    assert_eq!(block.shard_counts(), &[2, 1, 1, 0]);
    assert_eq!(
        block.reconciliation().records.len(),
        4,
        "one record per statement shard"
    );
    assert_eq!(
        block
            .reconciliation()
            .records
            .iter()
            .map(|r| (r.family, r.shard_index))
            .collect::<Vec<_>>(),
        statement_shards(&setup.program.config, block.shard_counts()),
        "records in statement order"
    );

    // The stage gate.
    assert_eq!(verify_block(&setup.vk, &block, block.statement()), Ok(()));

    // Every shard of the block also verifies on the S16 path, which is the
    // path `verify_block` composes.
    for shard in block.shard_proofs() {
        assert_eq!(verify_shard(&setup.vk, shard, block.statement()), Ok(()));
    }

    // Acceptance 8: a family in the VmConfig with zero occurrences proves zero
    // shards, and the count reads 0 through the stable API.
    assert_eq!(block.shard_count(ZERO), 0);
    assert!(
        block
            .reconciliation()
            .records
            .iter()
            .all(|r| r.family != ZERO),
        "a zero-shard family has no record"
    );

    // Acceptance 9: the public-data contract, through the wire form only.
    let bytes = block.to_bytes();
    let read = BlockProof::from_bytes(&bytes).expect("a block round-trips");
    assert_eq!(read.to_bytes(), bytes, "byte for byte");
    assert_eq!(read.config(), &setup.program.config);
    assert_eq!(read.shard_counts(), &[2, 1, 1, 0]);
    assert_eq!(read.shard_count(ADD), 2);
    assert_eq!(read.shard_count(ZERO), 0);
    assert_eq!(read.shard_proofs().len(), 4);
    assert_eq!(read.reconciliation(), block.reconciliation());
    assert_eq!(verify_block(&setup.vk, &read, read.statement()), Ok(()));

    // Acceptance 1's structural schema assertion: **no field of a shard's or a
    // block's public data is a boundary or successor pc**. These two
    // destructurings are exhaustive, so a field added to either type fails to
    // compile here rather than passing unexamined.
    let ShardProof {
        family: _,
        shard_index: _,
        ts_window: _,
        global_digest: _,
        witness_commitments: _,
        outputs: _,
        gkr: _,
        opening: _,
    } = block.shard_proofs()[0].clone();
    let BlockProof {
        config: _,
        statement: _,
        shards: _,
    } = block.clone();

    // Acceptance 3's positive half and acceptance 1's challenge assertion: the
    // global commit phase's tape is the frozen pre-fork order and the
    // committed fixture, its four memory challenges and its digest are drawn
    // once each and strictly after every absorb, and no line of it carries a
    // tag that could chain a pc.
    let tape = checker::check_global_tape(&setup.vk, block.statement())
        .expect("the phase keeps the frozen pre-fork order");
    let fixture: Vec<String> = include_str!("../../checker/tests/vectors/global_tape.txt")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(str::to_string)
        .collect();
    assert_eq!(tape, fixture, "the run's tape is the committed fixture");
    let squeezes: Vec<&String> = tape.iter().filter(|l| l.starts_with("squeeze")).collect();
    assert_eq!(squeezes.len(), 5, "four memory challenges and the digest");
    assert_eq!(
        tape.iter().position(|l| l.starts_with("squeeze")),
        Some(tape.len() - 5),
        "every squeeze follows every absorb"
    );
    let tags: Vec<&str> = tape
        .iter()
        .map(|l| l.split(' ').nth(1).expect("a tag name"))
        .collect();
    for tag in &tags {
        assert!(
            [
                "PROTOCOL_SUITE",
                "SRS_DIGEST",
                "VM_CONFIG",
                "SHARD_COUNTS",
                "MEMORY_WINDOWS",
                "PROGRAM_IDENTITY",
                "PUBLIC_INPUTS",
                "MEMORY_GROUP",
                "COMMITMENT",
                "MEMORY_BOUNDARY",
                "MEMORY_CHALLENGE",
                "GLOBAL_STATE_DIGEST",
            ]
            .contains(tag),
            "the global tape carries {tag}, which G1-G11 does not"
        );
    }

    // The windows the plan claims: within the family, ordered and disjoint;
    // across families, freely overlapping, because cycle numbers are global
    // and two families interleave.
    let records = block.reconciliation().records;
    let window = |f: u32, i: u32| {
        records
            .iter()
            .find(|r| (r.family, r.shard_index) == (f, i))
            .expect("a record")
            .ts_window
    };
    assert_eq!(
        window(INIT, 0),
        TRIVIAL_TS_WINDOW,
        "a family with no cycles"
    );
    let (first, second) = (window(ADD, 0), window(ADD, 1));
    assert!(first[0] < first[1] && first[1] <= second[0] && second[0] < second[1]);
    assert_eq!(first[0], 4, "row 0 of shard 0 is cycle 1");
    let jump = window(JBS, 0);
    assert!(
        jump[0] < first[1] && jump[1] > second[0],
        "the jump family's window overlaps both add/sub windows: {jump:?}"
    );
}

/// Acceptance 4 and 6: every statement-binding twin and the swapped-window
/// twin is refused, each with the class the check that caught it names.
#[test]
#[ignore]
fn a4_a6_every_block_twin_is_refused() {
    let (setup, _, block) = proved();
    let honest = block.statement().clone();
    let statement = |e: &'static str| Err(VerifyError::Statement(e));

    // 4(a) A `PublicInputs` with a one-bit-different public I/O digest. The
    // block carries the statement it bound, so the mismatch is caught before
    // anything is replayed.
    let mut flipped = honest.clone();
    flipped.output.push(1);
    assert_eq!(
        verify_block(&setup.vk, &block, &flipped),
        statement("the block's statement is not the one given")
    );
    // ... and with the block's own copy moved to match, so checks 1 and 2 pass
    // and the digest is what has to catch it.
    //
    // **The block's answer is check 5's, not the shard loop's**, and that is
    // S20's split working: the four memory challenges are drawn from the
    // statement's own transcript (G10), so re-deriving them from a different
    // statement makes the honest roots' two products disagree, and
    // `verify_global_memory` runs before any shard is verified
    // (`verify_block`'s doc comment). The seed is still named, one level down:
    // the same proof under the same statement through `verify_shard` is
    // `Statement`, which is where `tests/acceptance.rs` pins it.
    let mut twin = block.clone();
    twin.statement = flipped.clone();
    assert_eq!(
        verify_block(&setup.vk, &twin, &flipped),
        Err(VerifyError::MemoryArgument(
            "the statement's roots do not reconcile"
        ))
    );
    assert_eq!(
        verify_shard(&setup.vk, &twin.shards[0], &flipped),
        statement("the proof was made for another statement"),
        "the per-shard path still names the seed"
    );

    // 4(b) Another `ProgramIdentity`. An in-memory edit: such a key would not
    // load (`docs/spec/shard-proof.md` §7.2), and checks 1 to 5 refuse it
    // anyway because G6 absorbs the identity.
    let mut other = setup.vk.clone();
    other.identity.0 += Fr::ONE;
    assert_eq!(
        verify_block(&other, &block, &honest),
        Err(VerifyError::MemoryArgument(
            "the statement's roots do not reconcile"
        )),
        "G6 absorbs the identity, so check 5's challenges move with it"
    );
    assert_eq!(
        verify_shard(&other, &block.shards[0], &honest),
        statement("the proof was made for another statement"),
        "and the per-shard path names the seed"
    );
    // A key for another program refuses at the descriptor.
    let mut narrowed = setup.vk.clone();
    narrowed.config.bytecode_size_words += 1;
    assert_eq!(
        verify_block(&narrowed, &block, &honest),
        statement("the block's VmConfig is not the key's")
    );

    // 4(c) A descriptor with one family's shard count altered, the lists
    // padded so the totals still line up: the count is absorbed at G4, so the
    // digest moves, and the shard set the counts describe is no longer the
    // proofs'.
    let mut counted = block.clone();
    counted.statement.shard_counts[1] = 2;
    let last = counted
        .statement
        .memory_commitments
        .last()
        .cloned()
        .unwrap();
    counted.statement.memory_commitments.push(last);
    let root = *counted.statement.memory_roots.last().unwrap();
    counted.statement.memory_roots.push(root);
    let claimed = counted.statement.clone();
    assert_eq!(
        verify_block(&setup.vk, &counted, &claimed),
        statement("the block has not one proof, commitment list and root pair per shard")
    );
    // The same count change without the padding is refused earlier still.
    let mut bare = block.clone();
    bare.statement.shard_counts[1] = 2;
    let bare_statement = bare.statement.clone();
    assert_eq!(
        verify_block(&setup.vk, &bare, &bare_statement),
        statement("the statement has not one commitment list per shard")
    );

    // Acceptance 6: exchange two shards' claimed windows. The block's window
    // rule catches it before any shard is verified.
    let mut swapped = block.clone();
    let (a, b) = (swapped.shards[1].ts_window, swapped.shards[2].ts_window);
    swapped.shards[1].ts_window = b;
    swapped.shards[2].ts_window = a;
    assert_eq!(
        verify_block(&setup.vk, &swapped, &honest),
        statement("a family's shard time windows are not ordered and disjoint")
    );
    // The window is absorbed at S2, so the swap is refused a second,
    // independent way: each shard's own transcript is a different one.
    assert!(
        matches!(
            verify_shard(&setup.vk, &swapped.shards[1], &honest),
            Err(VerifyError::Constraint { .. }) | Err(VerifyError::Lookup { .. })
        ),
        "a shard proved under one window does not verify under another"
    );
}

/// Acceptance 5: omit one shard, **as an honest prover would prove the
/// truncated statement** — its counts, its commitment lists and its roots all
/// adjusted, its global commit phase rerun, its remaining shards proved
/// against it. Verification then fails on the global read/write root product,
/// because the omitted shard's tuples are missing from one side of the
/// multiset.
#[test]
#[ignore]
fn a5_a_block_missing_a_shard_does_not_reconcile() {
    let setup = common::shards_setup();
    let archive = common::shards_archive(&setup.program);

    // The statement without `(ADD_SUB_LUI_AUIPC, 1)`: the last add/sub shard.
    let mut inputs = statement_inputs(&setup, &archive).expect("the statement");
    let shards = statement_shards(&setup.program.config, &inputs.shard_counts);
    let dropped = shards
        .iter()
        .position(|s| *s == (ADD, 1))
        .expect("the second add/sub shard");
    inputs.memory_columns.remove(dropped);
    inputs.shard_counts[0] = 1;

    let global = global_commit_phase(&setup.vk, &setup.srs, &inputs);
    let ctx = ProvingContext {
        setup: &setup,
        global,
    };
    let kept = statement_shards(&setup.program.config, &ctx.global.statement.shard_counts);
    assert_eq!(kept.len(), 3, "one shard fewer");
    let proofs: Vec<ShardProof> = kept
        .iter()
        .map(|&(f, i)| prover::prove_shard(&ctx, &archive, f, i))
        .collect();
    let statement = public_inputs(&ctx.global, &proofs);
    let truncated = BlockProof {
        config: setup.program.config.clone(),
        statement: statement.clone(),
        shards: proofs,
    };
    assert_eq!(truncated.shard_count(ADD), 1, "the counts match the proofs");
    assert_eq!(
        verify_block(&setup.vk, &truncated, &statement),
        Err(VerifyError::MemoryArgument(
            "the statement's roots do not reconcile"
        )),
        "the omitted shard's memory events are missing from one side"
    );
}

/// Acceptance 7: re-prove one shard with ONE corrupted trace cell and
/// reassemble the block. The cell is in the **second** add/sub shard, so what
/// the block catches is a defect in a shard the first one says nothing about.
/// The honest twin passes.
#[test]
#[ignore]
fn a7_a_corrupted_cell_in_the_second_shard_refuses_the_block() {
    let (setup, archive, honest) = proved();
    assert_eq!(verify_block(&setup.vk, &honest, honest.statement()), Ok(()));

    // A witness column is committed inside the shard, after the global phase,
    // so tampering one leaves the statement and the global state exactly where
    // they were. The rerun's digest being the honest proofs' is the assertion
    // that says so, and it is what lets the twin reuse three honest shards.
    let inputs = statement_inputs(&setup, &archive).expect("the statement");
    let mut global = global_commit_phase(&setup.vk, &setup.srs, &inputs);
    assert_eq!(
        global.digest,
        honest.shard_proofs()[0].global_digest,
        "a witness cell is not committed before the challenges"
    );
    // The honest statement, whose roots the shards' proofs filled in.
    global.statement = honest.statement().clone();
    let ctx = ProvingContext {
        setup: &setup,
        global,
    };

    // `wrap`, the add/sub family's carry bit, on a live row of shard 1. No
    // lookup tuple reads it, so an honest prover recounts nothing; the sum
    // gate is what refuses it.
    let windows = honest.statement().windows.clone();
    let mut columns =
        shard_columns(&setup, &archive, ADD, 1, &windows).expect("the shard's columns");
    let wrap = constraints::add_sub::WRAP;
    let at = columns
        .iter()
        .position(|(a, _)| *a == wrap)
        .expect("the wrap column");
    let mut values: Vec<Fr> = (0..columns[at].1.len())
        .map(|i| columns[at].1.get(i))
        .collect();
    assert_eq!(values[0], Fr::ZERO, "row 0 of shard 1 carries no wrap");
    values[0] = Fr::ONE;
    columns[at].1 = poly::MultilinearPoly::new(poly::PolyBacking::Fr(values));

    let (tampered, _) = prove_shard_columns(&ctx, ADD, 1, columns);
    let mut twin = honest.clone();
    let position = statement_shards(&setup.program.config, twin.shard_counts())
        .iter()
        .position(|s| *s == (ADD, 1))
        .expect("the shard");
    twin.shards[position] = tampered;
    let statement = twin.statement().clone();
    assert!(
        matches!(
            verify_block(&setup.vk, &twin, &statement),
            Err(VerifyError::Constraint { .. })
        ),
        "one cell of one shard refuses the block"
    );
    // The honest twin, unchanged, still passes.
    assert_eq!(verify_block(&setup.vk, &honest, honest.statement()), Ok(()));
}

/// Acceptance 10: killed and resumed at the post-commit and post-GKR
/// boundaries, the block prover produces a byte-identical `BlockProof`.
#[test]
#[ignore]
fn a10_a_resumed_block_is_byte_identical() {
    let (setup, whole, reference) = proved();

    let setup2 = common::shards_setup();
    let mut archive = common::shards_archive(&setup2.program);
    let plan = plan_shards(archive.cycle_profile(), &setup2.program.config);
    for stop in [Phase::PostCommit, Phase::PostGkr] {
        advance(&setup2, &mut archive, stop).expect("the phase runs");
        assert!(archive.is_filled(stop), "{stop:?} is filled");
        let mut bytes = Vec::new();
        archive.export(&mut bytes).expect("the archive exports");
        archive = TraceArchive::import(Cursor::new(bytes)).expect("it imports");
    }
    let resumed = prove_block(&setup2, &mut archive, &plan).expect("the resumed block proves");
    assert_eq!(
        resumed.to_bytes(),
        reference.to_bytes(),
        "a resumed block is the uninterrupted one, byte for byte"
    );
    assert_eq!(
        archive.deterministic_payload(),
        whole.deterministic_payload(),
        "and so is every phase section"
    );
    assert_eq!(
        finish(&archive).expect("the final phase").0,
        *reference.statement()
    );
    assert_eq!(
        verify_block(&setup.vk, &resumed, resumed.statement()),
        Ok(())
    );
}

/// Must-be-exact 8: the assembled block is byte-identical for any thread
/// count. Shard proving is the only parallel step and each shard forks its own
/// transcript from the global state, so the schedule cannot reach a challenge.
#[test]
#[ignore]
fn the_block_does_not_depend_on_the_thread_count() {
    let (_, _, reference) = proved();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .expect("a one-thread pool");
    let serial = pool.install(|| {
        let setup = common::shards_setup();
        let mut archive = common::shards_archive(&setup.program);
        let plan = plan_shards(archive.cycle_profile(), &setup.program.config);
        prove_block(&setup, &mut archive, &plan).expect("the block proves on one thread")
    });
    assert_eq!(serial.to_bytes(), reference.to_bytes());
}

/// Acceptance 2: a multi-family block. `guests/mem` touches five execution
/// families — add/sub, jump/branch/slt and S19's three — and writes near the
/// top of RAM, so its block also carries a `ZERO_WINDOWS` shard.
#[test]
#[ignore]
fn a2_a_multi_family_block_proves_and_verifies() {
    let setup = common::mem_setup();
    let mut archive = common::mem_archive(&setup.program);
    let plan = plan_shards(archive.cycle_profile(), &setup.program.config);
    let block = prove_block(&setup, &mut archive, &plan).expect("the block proves");

    let execution: Vec<u32> = setup
        .program
        .config
        .families
        .iter()
        .map(|(f, _)| *f)
        .filter(|f| family::CYCLE_OWNING[*f as usize])
        .collect();
    assert!(
        execution.len() >= 3,
        "a block over at least three breadth families, not {execution:?}"
    );
    for f in &execution {
        assert_eq!(block.shard_count(*f), 1, "family {f}");
    }
    assert_eq!(block.shard_count(INIT), 1);
    assert_eq!(block.shard_count(ZERO), 1, "mem writes above window 0");

    let records = block.reconciliation().records;
    assert_eq!(records.len(), execution.len() + 2);
    for r in &records {
        assert_eq!(
            r.memory_commitments.len(),
            setup
                .vk
                .circuit(r.family)
                .expect("a config family")
                .artifact
                .memory
                .len(),
            "every record carries its family's memory commitments"
        );
        assert_ne!(r.roots[0], Fr::ZERO, "a read root is present");
        assert_ne!(r.roots[1], Fr::ZERO, "a write root is present");
    }
    assert_eq!(verify_block(&setup.vk, &block, block.statement()), Ok(()));
}
