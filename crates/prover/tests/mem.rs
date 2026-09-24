//! S19's acceptance over the real statement: `guests/mem`, proved and verified
//! shard by shard.
//!
//! **Every test here is `#[ignore]`d, and runs by name with
//! `--include-ignored --test-threads=1`**, for `tests/acceptance.rs`' reason:
//! five execution families' shards are `2^20` rows. Master rule 7: the stage's
//! PR runs it locally, and `.github/workflows/ci.yml` carries the command under
//! `# DEFERRED:`. The circuits row by row, the reduced-width splice check and
//! everything else that needs no proof is `crates/checker/tests/mem_word.rs`,
//! `mem_subword.rs`, `atomics.rs` and `mem_fill.rs`, in ordinary CI.
//!
//! This is also the **first statement whose rows touch RAM**, so it is the
//! first with a `ZERO_WINDOWS` shard: the guest writes near the top of RAM as
//! well as inside window 0.

mod common;

use constants::family;
use program::lookup_tables::generic_commitments;
use prover::{advance, finish, ProverSetup};
use trace::{Phase, TraceArchive};
use verifier::{verify_shard, PublicInputs, ShardProof};
use verifier_core::{reduce_shard, srs_digest};

const ADD: u32 = family::ADD_SUB_LUI_AUIPC;
const JBS: u32 = family::JUMP_BRANCH_SLT;
const MW: u32 = family::MEM_WORD;
const MS: u32 = family::MEM_SUBWORD;
const AT: u32 = family::ATOMICS;
const INIT: u32 = family::INIT_TEARDOWN;
const ZERO: u32 = family::ZERO_WINDOWS;

/// The whole statement, proved through `advance`.
fn proved() -> (ProverSetup, TraceArchive, PublicInputs, Vec<ShardProof>) {
    let setup = common::mem_setup();
    let mut archive = common::mem_archive(&setup.program);
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

/// Acceptance 1: the guest decodes into the five execution families it runs —
/// add/sub and jump/branch/slt beside the three S19 proves — and the two RAM
/// window families; its trace self-checks and exits with the number of checks
/// it ran, 48; `advance` proves one shard of each, seven of them, the
/// `ZERO_WINDOWS` one being the first any acceptance statement has had;
/// `verify_shard` accepts every one against the one statement; and every proof
/// has its circuit's shape.
///
/// The three new families' shapes are pinned twice — as the literals
/// `docs/spec/memory-ops.md` §7 states, and as the numbers read off the
/// registry's circuit — so a change to any of them shows on both sides. What
/// the trace holds, instruction by instruction, is the three row suites in
/// `crates/checker/tests` over the same fixture; that QEMU reaches the same
/// exit status is `crates/emulator/tests/qemu_outputs.rs`'.
#[test]
#[ignore = "five 2^20-row execution shards: one statement's proof is the heaviest in the repository"]
fn a1_the_guest_proves_and_every_shard_verifies() {
    let (setup, archive, public, proofs) = proved();
    let config = &setup.program.config;
    assert_eq!(
        config.families,
        vec![
            (ADD, 1 << 20),
            (JBS, 1 << 20),
            (MW, 1 << 20),
            (MS, 1 << 20),
            (AT, 1 << 20),
            (INIT, 1 << 16),
            (ZERO, 1 << 16)
        ],
        "the guest runs no shift/bitwise and no mul/div, so neither is derived"
    );
    let live = |f: u32| {
        let table = setup.program.tables.family(f).expect("a table");
        (0..table.height as usize)
            .filter(|r| table.is_live(*r))
            .count()
    };
    assert_eq!((live(ADD), live(JBS)), (180, 56));
    assert_eq!((live(MW), live(MS), live(AT)), (53, 21, 15));
    assert_eq!(
        archive.memory_log().self_check(&setup.program.image),
        Ok(())
    );
    assert_eq!(public.shard_counts, vec![1, 1, 1, 1, 1, 1, 1]);
    assert_eq!(
        public.windows,
        vec![8191],
        "the guest writes near the top of RAM, which is the last window at 2^16"
    );
    assert_eq!(public.exit_status, common::MEM_RESULT);
    assert!(public.input.is_empty() && public.output.is_empty());
    let shards: Vec<(u32, u32)> = proofs.iter().map(|p| (p.family, p.shard_index)).collect();
    assert_eq!(
        shards,
        vec![
            (INIT, 0),
            (ZERO, 0),
            (ADD, 0),
            (JBS, 0),
            (MW, 0),
            (MS, 0),
            (AT, 0)
        ],
        "one shard per family that runs, in the global transcript's group order"
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

    // The three families' committed widths and channel counts, as
    // `docs/spec/memory-ops.md` §7 states them: `mem_word` reads no generic
    // channel, so it carries three channels and seven setup columns; the other
    // two carry four and name the packed table as their last three.
    let by_family = |f: u32| proofs.iter().find(|p| p.family == f).expect("a shard");
    // Each length is pinned twice — as the literal `docs/spec/memory-ops.md` §7 and
    // `docs/spec/constraint-manifest.md` §1.2 and §1.3 state, and as the number the
    // formula above reads off the circuit — so a change to a family shows on both sides.
    let mw = by_family(MW);
    assert_eq!(mw.gkr.layers.len(), 25);
    assert_eq!(mw.gkr.layers[0].rounds.len(), 20);
    assert_eq!(mw.gkr.layers[0].final_evals.len(), 31 + 24 + 7);
    assert_eq!(mw.outputs.len(), 2 + 2 * 3);
    assert_eq!(mw.to_bytes().len(), 56_268);
    let ms = by_family(MS);
    assert_eq!(ms.gkr.layers.len(), 26);
    assert_eq!(ms.gkr.layers[0].final_evals.len(), 31 + 55 + 10);
    assert_eq!(ms.outputs.len(), 2 + 2 * 4);
    assert_eq!(ms.to_bytes().len(), 68_116);
    let at = by_family(AT);
    assert_eq!(at.gkr.layers.len(), 26);
    assert_eq!(at.gkr.layers[0].final_evals.len(), 26 + 54 + 9);
    assert_eq!(at.outputs.len(), 2 + 2 * 4);
    assert_eq!(at.to_bytes().len(), 68_468);

    // The generic table's binding (`docs/spec/jump-branch-slt.md` §6): the two
    // families that read the channel open the key's three table commitments
    // after their own identity-committed setup columns; `mem_word`, which
    // reads none, opens identity's list alone.
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
    let claim = reduced(mw);
    assert_eq!(claim.len(), 31 + 24 + 7);
    assert_eq!(&claim[55..], &setup.vk.setup_commitments[2][..]);
    let claim = reduced(ms);
    assert_eq!(claim.len(), 31 + 55 + 10);
    assert_eq!(&claim[86..93], &setup.vk.setup_commitments[3][..]);
    assert_eq!(&claim[93..], &table[..]);
    let claim = reduced(at);
    assert_eq!(claim.len(), 26 + 54 + 9);
    assert_eq!(&claim[80..86], &setup.vk.setup_commitments[4][..]);
    assert_eq!(&claim[86..], &table[..]);
}
