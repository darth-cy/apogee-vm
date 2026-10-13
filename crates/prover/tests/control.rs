//! The jump/branch/slt statement end to end: `guests/control`, proved and
//! verified shard by shard.
//!
//! **Every test here is `#[ignore]`d, and runs by name with
//! `--include-ignored --test-threads=1`**, for `tests/acceptance.rs`' reason:
//! both execution families' shards are `2^20` rows, and CI does not run them.
//! The circuit row by row, the reduced-width comparison and everything else
//! that needs no proof is `crates/checker/tests/jump_branch_slt.rs`, in
//! ordinary CI.

mod common;

use constants::family;
use prover::ProverSetup;
use trace::TraceArchive;
use verifier::{verify_shard, PublicInputs, ShardProof};
use verifier_core::reduce_shard;

const ADD: u32 = family::ADD_SUB_LUI_AUIPC;
const JBS: u32 = family::JUMP_BRANCH_SLT;
const INIT: u32 = family::INIT_TEARDOWN;
const ZERO: u32 = family::ZERO_WINDOWS;

/// The whole statement, proved by the one proving path.
fn proved() -> (ProverSetup, TraceArchive, PublicInputs, Vec<ShardProof>) {
    let setup = common::control_setup();
    // The archive is built and **not** proved from: the log's self-check below
    // reads it, which is a reading of the execution and not a proving path
    // (`docs/spec/streaming.md` §1).
    let archive = common::control_archive(&setup.program);
    let (public, proofs) = common::streamed_shards(&setup, &common::empty_io());
    (setup, archive, public, proofs)
}

/// The byte length a proof of `artifact` has: `docs/spec/proof.md` §9's
/// layout, every count read off the circuit.
fn proof_bytes(a: &constraints::CircuitArtifact) -> usize {
    let transitions: usize = (0..a.depth())
        .map(|k| {
            let claims = a.layer_width(k) as usize * if a.layers[k].halving { 2 } else { 1 };
            4 + 128 * a.layer_vars(k + 1) as usize + 4 + 32 * claims
        })
        .sum();
    4 + 4 + 16 + 32 + (4 + 32 * a.outputs.len()) + 4 + transitions
}

/// The guest decodes into the add/sub family, the jump/branch/slt family and
/// the window families; its trace self-checks; the streaming prover proves one
/// shard of each family that has one; `verify_shard` accepts every one against
/// one statement, whose result is the guest's 16 passed checks; and every proof
/// has its circuit's shape. What the trace holds — the twelve instructions and
/// the branch matrix — is `crates/checker/tests/jump_branch_slt.rs`'
/// `the_guest_runs_the_acceptance_matrix`, over the same fixture, and the
/// emulator's reading of it is `crates/emulator/tests/guests.rs`', which checks
/// the exit status and the journal and nothing below that.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks near 10 GB"]
fn a1_the_guest_proves_and_every_shard_verifies() {
    let (setup, archive, public, proofs) = proved();
    let config = &setup.program.config;
    assert_eq!(
        config.families,
        vec![
            (ADD, 1 << 20),
            (JBS, 1 << 20),
            (INIT, 1 << 16),
            (ZERO, 1 << 16),
            (family::PUBLIC_INPUT, family::PUBLIC_WINDOW_HEIGHT),
            (family::PUBLIC_OUTPUT, family::PUBLIC_WINDOW_HEIGHT),
            (family::ADVICE_WINDOWS, 1 << 16)
        ]
    );
    let live = |f: u32| {
        let table = setup.program.tables.family(f).expect("a table");
        (0..table.height as usize)
            .filter(|r| table.is_live(*r))
            .count()
    };
    assert_eq!((live(ADD), live(JBS)), (57, 90));
    assert_eq!(
        archive.memory_log().self_check(&trace::InitialMemory {
            image: &setup.program.image,
            public_input: &archive.io_streams().input,
            advice: archive.advice(),
        }),
        Ok(())
    );
    assert_eq!(public.shard_counts, vec![1, 1, 1, 0, 1, 1, 0]);
    assert!(public.windows.is_empty(), "control touches no RAM");
    assert_eq!(public.exit_status, common::CONTROL_RESULT);
    assert!(public.input.is_empty() && public.output.is_empty());
    let shards: Vec<(u32, u32)> = proofs.iter().map(|p| (p.family, p.shard_index)).collect();
    assert_eq!(
        shards,
        vec![
            (INIT, 0),
            (ADD, 0),
            (JBS, 0),
            (family::PUBLIC_INPUT, 0),
            (family::PUBLIC_OUTPUT, 0)
        ]
    );

    for proof in &proofs {
        assert_eq!(verify_shard(&setup.vk, proof, &public), Ok(()));
        let circuit = setup.vk.circuit(proof.family).expect("a circuit");
        let a = &circuit.artifact;
        assert_eq!(proof.gkr.layers.len(), a.depth());
        for (k, layer) in proof.gkr.layers.iter().enumerate() {
            assert_eq!(layer.rounds.len(), a.layer_vars(k + 1) as usize);
            let claims = a.layer_width(k) as usize * if a.layers[k].halving { 2 } else { 1 };
            assert_eq!(layer.final_evals.len(), claims);
        }
        assert_eq!(proof.outputs.len(), 2 + 2 * circuit.channels.len());
        assert_eq!(proof.to_bytes().len(), proof_bytes(a));
    }
    let jbs = &proofs[2];
    assert_eq!(jbs.gkr.layers.len(), 25);
    assert_eq!(jbs.gkr.layers[0].rounds.len(), 20);
    assert_eq!(jbs.gkr.layers[0].final_evals.len(), 21 + 44 + 10);
    assert_eq!(jbs.outputs.len(), 2 + 2 * 4);
    assert_eq!(jbs.to_bytes().len(), 58_088);

    // Each shard reduces to one claim per committed column, in layout order:
    // memory, witness, setup.
    //
    // ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME. Those claims
    // are meant to be opened against the statement's memory commitments, the
    // shard's witness commitments and the key's setup and generic-table
    // commitments. Nothing is opened, so these lengths are all that can be
    // held (`docs/architecture.md` §0).
    for (proof, (m, w, s)) in [(jbs, (21, 44, 10)), (&proofs[1], (21, 28, 7))] {
        let claim = match reduce_shard(&setup.vk, proof, &public) {
            Ok(claim) => claim,
            Err(e) => panic!("the honest shard reduces: {e}"),
        };
        let a = &setup.vk.circuit(proof.family).expect("a circuit").artifact;
        assert_eq!(claim.columns, a.committed());
        assert_eq!(
            (a.memory.len(), a.witness.len(), a.setup.len()),
            (m, w, s),
            "family {}",
            proof.family
        );
        assert_eq!(claim.values.len(), m + w + s);
        assert_eq!(claim.point.len(), 20);
    }
}

/// **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** The generic
/// table's binding: a key whose generic table is another table's is another
/// statement, and every honest shard is refused under it. Nothing commits the
/// table, so no key names one and there is nothing to swap. This is held here,
/// disabled, as the property a commitment scheme must restore
/// (`docs/architecture.md` §0).
#[test]
#[ignore = "UNFINISHED: the key commits no generic table until a commitment scheme exists \
            (docs/architecture.md §0)"]
#[allow(non_snake_case)]
fn UNFINISHED_a_key_with_another_generic_table_is_another_statement() {
    todo!("UNFINISHED: no commitment scheme commits the generic table (docs/architecture.md §0)")
}
