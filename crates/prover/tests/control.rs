//! The jump/branch/slt statement end to end: `guests/control`, proved and
//! verified shard by shard.
//!
//! **Every test here is `#[ignore]`d, and runs by name with
//! `--include-ignored --test-threads=1`**, for `tests/acceptance.rs`' reason:
//! its three execution families' shards are `2^20` rows, and CI does not run
//! them. The circuits row by row, the flipped comparison and everything else
//! that needs no proof is `crates/checker/tests/families.rs`, in ordinary CI.

mod common;

use constants::family;
use prover::ProverSetup;
use trace::TraceArchive;
use verifier::{verify_shard, PublicInputs, ShardProof};
use verifier_core::reduce_shard;

const ADD: u32 = family::ADD_SUB_LUI_AUIPC;
const JBS: u32 = family::JUMP_BRANCH_SLT;
const MD: u32 = family::MUL_DIV;
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
/// layout, every count read off the circuit and its opening schedule, but the
/// opening's, whose Rice-coded response is as long as it codes.
fn proof_bytes(a: &constraints::CircuitArtifact, p: &ShardProof) -> usize {
    let transitions: usize = (0..a.depth())
        .map(|k| {
            let claims = a.layer_width(k) as usize * if a.layers[k].halving { 2 } else { 1 };
            4 + 64 * a.layer_vars(k + 1) as usize + 4 + 16 * claims
        })
        .sum();
    let (slices, len) = verifier_core::opening_schedule(a).commitment_shape(a.witness.len());
    let mut opening = verifier_core::wire::Writer::new();
    verifier_core::write_opening(&mut opening, &p.opening);
    4 + 4
        + 16
        + 16
        + (4 + slices * (4 + 8 * len))
        + (4 + 16 * a.outputs.len())
        + 4
        + transitions
        + opening.bytes.len()
}

/// The guest decodes into the add/sub, jump/branch/slt and mul/div families —
/// the last for the shifts that build its 64-bit constants — and the window
/// families; its trace self-checks; the streaming prover proves one shard of
/// each family that has one; `verify_shard` accepts every one against one
/// statement, whose result is the guest's 17 passed checks; and every proof
/// has its circuit's shape. What the trace holds, row by row, is
/// `crates/checker/tests/families.rs` over the same fixture, and the
/// emulator's reading of it is `crates/emulator/tests/guests.rs`', which checks
/// the exit status and the journal and nothing below that.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.7 GB"]
fn a1_the_guest_proves_and_every_shard_verifies() {
    let (setup, archive, public, proofs) = proved();
    let config = &setup.program.config;
    assert_eq!(
        config.families,
        vec![
            (ADD, 1 << 20),
            (JBS, 1 << 20),
            (MD, 1 << 20),
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
    assert_eq!((live(ADD), live(JBS), live(MD)), (65, 99, 3));
    assert_eq!(
        archive.memory_log().self_check(&trace::InitialMemory {
            image: &setup.program.image,
            public_input: &archive.io_streams().input,
            advice: archive.advice(),
        }),
        Ok(())
    );
    assert_eq!(public.shard_counts, vec![1, 1, 1, 1, 0, 1, 1, 0]);
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
            (MD, 0),
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
        assert_eq!(proof.to_bytes().len(), proof_bytes(a, proof));
    }

    // Each shard reduces to one claim per committed column, in layout order —
    // memory, witness, setup — and the claims open against the statement's,
    // the proof's and the key's commitments.
    for proof in [&proofs[1], &proofs[2]] {
        if let Err(e) = reduce_shard(&setup.vk, proof, &public) {
            panic!("the honest shard verifies: {e}");
        }
    }
}

/// The generic table's binding: a key whose generic table is another table's
/// is another statement, and every honest shard is refused under it. The
/// other key commits jump/branch/slt's setup columns with one packed-table
/// cell poisoned — `37 AND 45` answering 0 — and its identity digests that.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks at 8.7 GB"]
fn a_key_with_another_generic_table_is_another_statement() {
    use poly::{MultilinearPoly, PolyBacking};
    let (setup, _, public, proofs) = proved();
    let mut vk = setup.vk.clone();
    let at = vk
        .config
        .families
        .iter()
        .position(|(f, _)| *f == JBS)
        .unwrap();
    let circuit = &vk.circuits[at];
    let mut columns = program::setup_columns(&setup.program.image, &setup.program.tables, circuit);
    // The packed table's last column holds an entry's second value.
    let value = columns.last().unwrap();
    let mut poisoned: Vec<u32> = (0..value.len())
        .map(|i| value.get_base(i).to_u64() as u32)
        .collect();
    let and_row = 1 + 37 * 256 + 45;
    assert_eq!(poisoned[and_row], 37 & 45);
    poisoned[and_row] = 0;
    *columns.last_mut().unwrap() = MultilinearPoly::new(PolyBacking::U32(poisoned));
    let refs: Vec<&MultilinearPoly> = columns.iter().collect();
    let root = &verifier_core::opening_schedule(&circuit.artifact).levels[0];
    vk.setup_commitments[at] =
        pcs::commit(&vk.pcs.0, root, &pcs::Source::Columns(&refs)).commitment;
    vk.identity = verifier_core::identity_digest(
        vk.code_version,
        &vk.config,
        vk.entry_pc,
        &vk.setup_commitments,
    );
    assert_ne!(vk.identity, setup.vk.identity);
    for proof in &proofs {
        assert!(
            matches!(
                verify_shard(&vk, proof, &public),
                Err(verifier::VerifyError::Statement(_))
            ),
            "shard ({}, {}) under another generic table",
            proof.family,
            proof.shard_index
        );
    }
}
