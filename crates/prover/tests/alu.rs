//! S18's acceptance over the real statement: `guests/alu`, proved and verified
//! shard by shard.
//!
//! **Every test here is `#[ignore]`d, and runs by name with
//! `--include-ignored --test-threads=1`**, for `tests/acceptance.rs`' reason:
//! all four execution families' shards are `2^20` rows. Master rule 7: the
//! stage's PR runs it locally, and `.github/workflows/ci.yml` carries the
//! command under `# DEFERRED:`. The circuits row by row, the reduced-width
//! division check and everything else that needs no proof is
//! `crates/checker/tests/shift_bitwise.rs` and `crates/checker/tests/
//! mul_div.rs`, in ordinary CI.

mod common;

use constants::family;
use program::lookup_tables::generic_commitments;
use prover::{advance, finish, ProverSetup};
use trace::{Phase, TraceArchive};
use verifier::{verify_shard, PublicInputs, ShardProof};
use verifier_core::{reduce_shard, srs_digest};

const ADD: u32 = family::ADD_SUB_LUI_AUIPC;
const JBS: u32 = family::JUMP_BRANCH_SLT;
const SHB: u32 = family::SHIFT_BITWISE;
const MD: u32 = family::MUL_DIV;
const INIT: u32 = family::INIT_TEARDOWN;
const ZERO: u32 = family::ZERO_WINDOWS;

/// The whole statement, proved through `advance`.
fn proved() -> (ProverSetup, TraceArchive, PublicInputs, Vec<ShardProof>) {
    let setup = common::alu_setup();
    let mut archive = common::alu_archive(&setup.program);
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

/// Acceptance 1: the guest decodes into the four execution families S18 can
/// prove — add/sub, jump/branch/slt, shift/bitwise and mul/div — and the two
/// RAM window families; its trace self-checks and exits with the number of
/// checks it ran; `advance` proves one shard of each family that runs, five of
/// them, `ZERO_WINDOWS` among them being the one that does not; `verify_shard`
/// accepts every one against the one statement; and every proof has its
/// circuit's shape.
///
/// The two new families' shapes are pinned twice — as the literals
/// `docs/spec/shift-bitwise.md` §6 and `docs/spec/mul-div.md` §6 state, and as
/// the numbers read off the registry's circuit — so that a change to either
/// family shows up on both sides. What the trace holds, instruction by
/// instruction, is `crates/checker/tests/shift_bitwise.rs` and `crates/checker/
/// tests/mul_div.rs` over the same fixture, and QEMU's reading of it is
/// `crates/emulator/tests/qemu_outputs.rs`', which compares the exit status and
/// fd 1 and nothing below that.
#[test]
#[ignore = "four 2^20-row execution shards: one statement's proof peaks at 14.1 GB"]
fn a1_the_guest_proves_and_every_shard_verifies() {
    let (setup, archive, public, proofs) = proved();
    let config = &setup.program.config;
    assert_eq!(
        config.families,
        vec![
            (ADD, 1 << 20),
            (JBS, 1 << 20),
            (SHB, 1 << 20),
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
    assert_eq!((live(ADD), live(JBS)), (452, 96));
    assert_eq!((live(SHB), live(MD)), (45, 54));
    assert_eq!(
        archive.memory_log().self_check(&trace::InitialMemory {
            image: &setup.program.image,
            public_input: &archive.io_streams().input,
            advice: archive.advice(),
        }),
        Ok(())
    );
    assert_eq!(public.shard_counts, vec![1, 1, 1, 1, 1, 0, 1, 1, 0]);
    assert!(public.windows.is_empty(), "alu touches no RAM");
    assert_eq!(public.exit_status, common::ALU_RESULT);
    assert!(public.input.is_empty() && public.output.is_empty());
    let shards: Vec<(u32, u32)> = proofs.iter().map(|p| (p.family, p.shard_index)).collect();
    assert_eq!(
        shards,
        vec![
            (INIT, 0),
            (ADD, 0),
            (JBS, 0),
            (SHB, 0),
            (MD, 0),
            (family::PUBLIC_INPUT, 0),
            (family::PUBLIC_OUTPUT, 0)
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

    // The shift/bitwise family: 26 transitions — its `range16` tree's 24
    // obligations and its table fraction pad to 32 leaves, one row-wise level
    // more than any other family's — 20 rounds on the widest, and a base claim
    // per committed column: 21 memory, 61 witness, 10 setup.
    let shb = &proofs[3];
    assert_eq!(shb.gkr.layers.len(), 26);
    assert_eq!(shb.gkr.layers[0].rounds.len(), 20);
    assert_eq!(shb.gkr.layers[0].final_evals.len(), 21 + 61 + 10);
    assert_eq!(shb.outputs.len(), 2 + 2 * 4);
    assert_eq!(shb.to_bytes().len(), 68_564);

    // The mul/div family: the same depth for the same reason — its widest tree
    // is the 16-fraction timestamp one plus a level — its base claim
    // 21 + 54 + 9.
    let md = &proofs[4];
    assert_eq!(md.gkr.layers.len(), 26);
    assert_eq!(md.gkr.layers[0].rounds.len(), 20);
    assert_eq!(md.gkr.layers[0].final_evals.len(), 21 + 54 + 9);
    assert_eq!(md.outputs.len(), 2 + 2 * 4);
    assert_eq!(md.to_bytes().len(), 67_412);

    // The generic table's binding. Both new families read the channel — the
    // shift family for `U16GetSign`, the shift powers and the four AND bytes,
    // the mul/div family for its two operand signs — so each opens the key's
    // three table commitments after its own identity-committed setup columns.
    // The add/sub family reads no generic lookup and opens none of them.
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

    let claim = reduced(shb);
    assert_eq!(claim.len(), 21 + 61 + 10);
    assert_eq!(&claim[..21], &public.memory_commitments[3][..]);
    assert_eq!(&claim[21..82], &shb.witness_commitments[..]);
    assert_eq!(&claim[82..89], &setup.vk.setup_commitments[2][..]);
    assert_eq!(&claim[89..], &table[..]);

    let claim = reduced(md);
    assert_eq!(claim.len(), 21 + 54 + 9);
    assert_eq!(&claim[..21], &public.memory_commitments[4][..]);
    assert_eq!(&claim[21..75], &md.witness_commitments[..]);
    assert_eq!(&claim[75..81], &setup.vk.setup_commitments[3][..]);
    assert_eq!(&claim[81..], &table[..]);

    let claim = reduced(&proofs[1]);
    // 41 + 33 since S21's eighth frame query (`deleg`), 42 + 35 since S23 gave
    // that query its `deleg_space` column and one selector per delegation type.
    assert_eq!(claim.len(), 42 + 35 + 7);
    assert_eq!(&claim[77..], &setup.vk.setup_commitments[0][..]);
}
