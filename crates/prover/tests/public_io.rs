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
use prover::ProverSetup;
use trace::TraceArchive;
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
///
/// The archive is the execution, read for its log and never proved from; the
/// block comes from the one proving path (`docs/spec/streaming.md` §1).
fn proved() -> (ProverSetup, TraceArchive, BlockProof) {
    let setup = common::public_io_setup();
    let archive = common::public_io_archive(&setup.program, &advice());
    let block = common::streamed(&setup, &common::public_io_io(&advice()));
    (setup, archive, block)
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
