//! S17's acceptance over the real statement: `guests/control`, proved and
//! verified shard by shard.
//!
//! **Every test here is `#[ignore]`d, and runs by name with
//! `--include-ignored --test-threads=1`**, for `tests/acceptance.rs`' reason:
//! both execution families' shards are `2^20` rows. Master rule 7: the stage's
//! PR runs it locally, and `.github/workflows/ci.yml` carries the command under
//! `# DEFERRED:`. The circuit row by row, the reduced-width comparison and
//! everything else that needs no proof is `crates/checker/tests/
//! jump_branch_slt.rs`, in ordinary CI.

mod common;

use constants::family;
use program::lookup_tables::generic_commitments;
use prover::{advance, finish, ProverSetup};
use trace::{Phase, TraceArchive};
use verifier::{verify_shard, PublicInputs, ShardProof, VerifyError};
use verifier_core::{reduce_shard, srs_digest};

const ADD: u32 = family::ADD_SUB_LUI_AUIPC;
const JBS: u32 = family::JUMP_BRANCH_SLT;
const INIT: u32 = family::INIT_TEARDOWN;
const ZERO: u32 = family::ZERO_WINDOWS;

/// The whole statement, proved through `advance`.
fn proved() -> (ProverSetup, TraceArchive, PublicInputs, Vec<ShardProof>) {
    let setup = common::control_setup();
    let mut archive = common::control_archive(&setup.program);
    advance(&setup, &mut archive, Phase::Final).expect("the statement proves");
    let (public, proofs) = finish(&archive).expect("the final phase decodes");
    (setup, archive, public, proofs)
}

/// The byte length a proof of `artifact` has: `docs/spec/shard-proof.md` §9's
/// layout, every count read off the circuit.
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

/// Acceptance 1 (and 7's honest twin): the guest decodes into the add/sub
/// family, the jump/branch/slt family and the two RAM window families; its
/// trace self-checks; `advance` proves one shard of each family that runs;
/// `verify_shard` accepts every one against one statement, whose result is the
/// guest's 16 passed checks; and every proof has its circuit's shape. What the
/// trace holds — the twelve instructions and the acceptance matrix — is
/// `crates/checker/tests/jump_branch_slt.rs`' `the_guest_runs_the_acceptance_matrix`,
/// over the same fixture, and its QEMU differential is
/// `crates/emulator/tests/differential.rs`'.
///
/// The generic table, which this family is the first to read, is bound: the key
/// carries the packed table's commitments — the ones
/// `program::lookup_tables::generic_commitments` makes over this SRS at `2^18`
/// — its SRS digest covers them, and the family's opening claim ends with
/// them, so its `2^20`-row `S[7..10]` open against exactly those; the add/sub
/// family's claim does not carry them.
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
            (ZERO, 1 << 16)
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
        archive.memory_log().self_check(&setup.program.image),
        Ok(())
    );
    assert_eq!(public.shard_counts, vec![1, 1, 1, 0]);
    assert!(public.windows.is_empty(), "control touches no RAM");
    assert_eq!(public.exit_status, common::CONTROL_RESULT);
    assert!(public.input.is_empty() && public.output.is_empty());
    let shards: Vec<(u32, u32)> = proofs.iter().map(|p| (p.family, p.shard_index)).collect();
    assert_eq!(shards, vec![(INIT, 0), (ADD, 0), (JBS, 0)]);

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
    assert_eq!(jbs.to_bytes().len(), 61_612);

    // The generic table's binding.
    let table = generic_commitments(&setup.srs).map(|p| p.to_bytes());
    assert_eq!(setup.vk.generic_table, table);
    assert_eq!(
        setup.vk.srs_digest,
        srs_digest(&setup.vk.srs_verifier, &table)
    );
    let reduced = |proof: &ShardProof| match reduce_shard(&setup.vk, proof, &public) {
        Ok(claim) => claim.commitments,
        Err(e) => panic!("the honest shard reduces: {e}"),
    };
    let claim = reduced(jbs);
    assert_eq!(claim.len(), 21 + 44 + 10);
    assert_eq!(&claim[..21], &public.memory_commitments[2][..]);
    assert_eq!(&claim[21..65], &jbs.witness_commitments[..]);
    assert_eq!(&claim[65..72], &setup.vk.setup_commitments[1][..]);
    assert_eq!(&claim[72..], &table[..]);
    let add = reduced(&proofs[1]);
    assert_eq!(add.len(), 36 + 31 + 7);
    assert_eq!(&add[67..], &setup.vk.setup_commitments[0][..]);
}

/// The generic table's binding from the other side. A key whose table
/// commitments are another table's — its value and result commitments swapped, every
/// point still the SRS's — does not load under the SRS digest the honest key
/// carries, which is the one trusted value that pins the table. Given its own
/// digest, it loads, and a verifier comparing that digest with the trusted one
/// refuses it; the honest proofs are refused under it on every shard as made
/// for another statement, the digest being G2's.
#[test]
#[ignore = "2^20 rows: one statement's proof peaks near 10 GB"]
fn a_key_with_another_generic_table_is_another_statement() {
    let (setup, _, public, proofs) = proved();
    let mut other = setup.vk.clone();
    other.generic_table.swap(1, 2);
    assert!(
        other.check().is_err(),
        "the trusted SRS digest pins the table"
    );
    other.srs_digest = srs_digest(&other.srs_verifier, &other.generic_table);
    assert_eq!(other.check(), Ok(()));
    assert_ne!(other.srs_digest, setup.vk.srs_digest);
    for proof in &proofs {
        assert_eq!(
            verify_shard(&other, proof, &public),
            Err(VerifyError::Statement(
                "the proof was made for another statement"
            )),
            "shard {:?}",
            (proof.family, proof.shard_index)
        );
    }
}
