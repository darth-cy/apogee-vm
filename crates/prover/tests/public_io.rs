//! S-IO's acceptance over the real statement: `guests/public-io` proved and
//! verified, with its witness in the advice region, its commitment in the
//! public input and its result in the journal.
//!
//! This is the end-to-end evidence for `docs/spec/public-values.md` — the
//! first statement in the repository whose public input and public output are
//! **bound to the execution**. What can be checked without a proof is
//! `crates/checker/tests/public_values.rs` and runs in ordinary CI; what is
//! here needs one.
//!
//! **Every test is `#[ignore]`d, and runs by name with `--include-ignored
//! --test-threads=1`**: the guest's execution families are `2^20` rows, the
//! timestamp channel's floor. Master rule 7; the command is in
//! `.github/workflows/ci.yml` under `# DEFERRED:`.

mod common;

use constants::family;
use prover::{prove_block, ProverSetup};
use trace::{plan_shards, TraceArchive};
use verifier::{load_verifying_key, verify_block, VerifyError};
use verifier_core::{BlockProof, PublicInputs};

/// The advice this suite proves over: 64 bytes, enough to span several words
/// and to make the position-dependent checksum mean something.
fn advice() -> Vec<u8> {
    (0..64u8)
        .map(|i| i.wrapping_mul(37).wrapping_add(11))
        .collect()
}

/// One proved block of `guests/public-io` over [`advice`].
fn proved() -> (ProverSetup, TraceArchive, BlockProof) {
    let setup = common::public_io_setup();
    let mut archive = common::public_io_archive(&setup.program, &advice());
    let block = prove(&setup, &mut archive);
    (setup, archive, block)
}

fn prove(setup: &ProverSetup, archive: &mut TraceArchive) -> BlockProof {
    let plan = plan_shards(archive.cycle_profile(), &setup.program.config);
    prove_block(setup, archive, &plan).expect("the statement proves")
}

fn verify(setup: &ProverSetup, block: &BlockProof) -> Result<(), VerifyError> {
    let vk = load_verifying_key(&setup.vk.to_bytes()).expect("the key loads");
    verify_block(&vk, block, block.statement())
}

/// Acceptance 1: the whole architecture, end to end.
///
/// The guest reads a commitment out of the **public input**, checks the
/// **advice** against it, and publishes its result in the **journal** — and the
/// proof binds the first and the last while binding nothing at all about the
/// second. It issues no ecall but `EXIT`, which is what makes it provable at
/// all.
#[test]
#[ignore = "a 2^20 statement; run with --include-ignored --test-threads=1"]
fn a1_the_public_values_are_bound_and_the_advice_is_not() {
    let (setup, _, block) = proved();
    let public = block.statement();

    assert_eq!(
        public.input,
        common::public_io_input(&advice()),
        "the statement's input is what the host put in the window"
    );
    assert_eq!(
        public.output,
        common::public_io_journal(&advice()),
        "the statement's output is what the guest's stores left behind"
    );
    assert_eq!(public.exit_status, 0, "the guest accepted its advice");
    assert_eq!(verify(&setup, &block), Ok(()));

    // The three families are in the statement, and their shard counts are the
    // rule: one each for the two public windows, and one advice window for 68
    // bytes of region at the window height (`docs/spec/public-values.md` §4).
    assert_eq!(block.shard_count(family::PUBLIC_INPUT), 1);
    assert_eq!(block.shard_count(family::PUBLIC_OUTPUT), 1);
    assert_eq!(block.shard_count(family::ADVICE_WINDOWS), 1);
}

/// Acceptance 2: **the statement's public values cannot be changed.**
///
/// The two halves are different mechanisms and both are load-bearing.
///
/// A changed `input` or `output` moves `io_digest`, which G7 absorbs before
/// any challenge exists, so the global digest moves and every shard's proof is
/// refused at step 5 as `Statement` — without step 10c ever running. That is
/// the *statement* binding, and it is S10's, unchanged.
///
/// What step 10c adds is the other direction: it is what stops a prover from
/// honestly re-proving the *same execution* under a *different* claimed input
/// or output. There is no such proof to build, because the committed columns
/// are the execution's and the verifier compares them with its own extension
/// of the claimed bytes — which is what [`a3_a_claimed_public_value_is_the_committed_column`]
/// isolates.
#[test]
#[ignore = "a 2^20 statement; run with --include-ignored --test-threads=1"]
fn a2_a_changed_public_value_is_refused() {
    let (setup, _, block) = proved();
    let vk = load_verifying_key(&setup.vk.to_bytes()).expect("the key loads");

    for edit in ["input", "output"] {
        let mut public = block.statement().clone();
        match edit {
            "input" => public.input[0] ^= 1,
            _ => public.output[0] ^= 1,
        }
        let forged = BlockProof {
            config: block.config().clone(),
            statement: public,
            shards: block.shard_proofs().to_vec(),
        };
        match verify_block(&vk, &forged, &forged.statement) {
            Err(VerifyError::Statement(_)) => {}
            other => panic!("a changed {edit} was answered with {other:?}"),
        }
    }

    // A trailing zero byte is the case the window's length word exists for: it
    // fills the same payload words, and it is still a different statement.
    let mut public = block.statement().clone();
    public.output.push(0);
    let forged = BlockProof {
        config: block.config().clone(),
        statement: public,
        shards: block.shard_proofs().to_vec(),
    };
    assert!(
        matches!(
            verify_block(&vk, &forged, &forged.statement),
            Err(VerifyError::Statement(_))
        ),
        "a journal with a trailing zero byte was admitted"
    );
}

/// Acceptance 3: **step 10c is what holds the claimed bytes to the committed
/// column**, isolated from the transcript.
///
/// The global phase is derived from the honest statement and handed to
/// `verify_shard_local` beside a statement whose public values differ, so step
/// 5 — "the proof was made for another statement" — passes and the public
/// value check is the only thing left to refuse it. Without this test,
/// deleting step 10c would leave every test in this file green.
#[test]
#[ignore = "a 2^20 statement; run with --include-ignored --test-threads=1"]
fn a3_a_claimed_public_value_is_the_committed_column() {
    let (setup, _, block) = proved();
    let vk = load_verifying_key(&setup.vk.to_bytes()).expect("the key loads");
    let honest = block.statement();
    let global =
        verifier_core::derive_global_phase(&vk, honest).expect("the honest statement derives");

    let shard = |id: u32| {
        block
            .shard_proofs()
            .iter()
            .find(|p| p.family == id)
            .expect("the family has a shard")
    };

    // The control: against its own statement, each shard reduces.
    for id in [family::PUBLIC_INPUT, family::PUBLIC_OUTPUT] {
        assert!(
            verifier_core::verify_shard_local(&vk, &global, shard(id), honest).is_ok(),
            "the honest shard of {id} was refused"
        );
    }

    for (id, edit) in [
        (family::PUBLIC_INPUT, "input"),
        (family::PUBLIC_OUTPUT, "output"),
    ] {
        let mut public: PublicInputs = honest.clone();
        match edit {
            "input" => public.input[0] ^= 1,
            _ => public.output[0] ^= 1,
        }
        match verifier_core::verify_shard_local(&vk, &global, shard(id), &public) {
            Err(VerifyError::MemoryArgument(why)) => assert!(
                why.contains(edit),
                "{id}: refused as MemoryArgument, but for {why:?}"
            ),
            Err(other) => panic!("a claimed {edit} was answered with {other:?}"),
            Ok(_) => panic!("a claimed {edit} was admitted"),
        }
        // And the other window's shard does not care: each holds its own.
        let other = match id {
            family::PUBLIC_INPUT => family::PUBLIC_OUTPUT,
            _ => family::PUBLIC_INPUT,
        };
        assert!(
            verifier_core::verify_shard_local(&vk, &global, shard(other), &public).is_ok(),
            "the {other} shard was refused for the other window's bytes"
        );
    }
}

/// Acceptance 4: **nothing binds the advice, and the guest is what stands in
/// for the binding.**
///
/// A different advice is a different execution and proves perfectly well —
/// that is what "advice" means — but it publishes a *different journal*, and
/// only an advice matching the public input's checksum gets exit status 0 at
/// all. So a prover who swaps the advice either fails the run or publishes the
/// swap (`docs/spec/public-values.md` §6).
#[test]
#[ignore = "a 2^20 statement; run with --include-ignored --test-threads=1"]
fn a4_the_advice_is_unbound_and_the_guest_checks_it() {
    let setup = common::public_io_setup();

    // Honest advice, and the statement it produces.
    let mine = advice();
    let mut archive = common::public_io_archive(&setup.program, &mine);
    let block = prove(&setup, &mut archive);
    assert_eq!(verify(&setup, &block), Ok(()));

    // A different advice, with its own public input: a different execution,
    // equally provable, publishing a different journal.
    let mut other = mine.clone();
    other[0] ^= 0xFF;
    let mut other_archive = common::public_io_archive(&setup.program, &other);
    let other_block = prove(&setup, &mut other_archive);
    assert_eq!(verify(&setup, &other_block), Ok(()));
    assert_ne!(
        block.statement().output,
        other_block.statement().output,
        "two different advices published the same journal"
    );
    assert_ne!(
        block.statement().input,
        other_block.statement().input,
        "two different advices checked against the same public input"
    );

    // And swapping the advice under a *fixed* public input does not produce a
    // clean run at all: the guest refuses it.
    let io = emulator::GuestIo {
        stdin: Vec::new(),
        input: common::public_io_input(&mine),
        advice: other,
        hint: Vec::new(),
    };
    let (_, _, _, execution) = emulator::trace_run(
        &setup.program.image,
        &io,
        &setup.program.tables,
        &setup.program.config,
    )
    .expect("the guest traces");
    assert_eq!(
        execution.exit_code, 62,
        "the guest accepted advice its public input does not commit to"
    );
    assert!(
        execution.io.output.is_empty(),
        "a refused run published a journal"
    );
}

/// Acceptance 5: a guest that publishes nothing publishes nothing, and still
/// pays exactly two shards for saying so.
///
/// `guests/addsub` reads no public input and commits no journal. Its statement
/// carries two empty byte strings, its two public shards prove that the
/// windows held them, and no advice window exists at all.
#[test]
#[ignore = "a 2^20 statement; run with --include-ignored --test-threads=1"]
fn a5_a_guest_that_publishes_nothing_still_binds_that() {
    let setup = common::setup();
    let mut archive = common::archive(&setup.program);
    let block = prove(&setup, &mut archive);
    assert_eq!(verify(&setup, &block), Ok(()));

    let public = block.statement();
    assert!(public.input.is_empty() && public.output.is_empty());
    assert_eq!(public.exit_status, common::RESULT);
    assert_eq!(block.shard_count(family::PUBLIC_INPUT), 1);
    assert_eq!(block.shard_count(family::PUBLIC_OUTPUT), 1);
    assert_eq!(
        block.shard_count(family::ADVICE_WINDOWS),
        0,
        "a program with no advice pays no advice window"
    );

    // Claiming a journal it did not write is refused, which is the property
    // that makes "it published nothing" a statement worth anything.
    let vk = load_verifying_key(&setup.vk.to_bytes()).expect("the key loads");
    let global = verifier_core::derive_global_phase(&vk, public).expect("derives");
    let mut forged = public.clone();
    forged.output = b"a result it never computed".to_vec();
    let shard = block
        .shard_proofs()
        .iter()
        .find(|p| p.family == family::PUBLIC_OUTPUT)
        .expect("the journal has a shard");
    assert!(matches!(
        verifier_core::verify_shard_local(&vk, &global, shard, &forged),
        Err(VerifyError::MemoryArgument(_))
    ));
}
