//! S-RECURSION: `guests/field-ops`, the one committed guest in the recursion
//! format, proved as a block and verified (`docs/spec/recursion.md`).
//!
//! `#[ignore]`d and deferred out of CI under master rule 7: the statement is
//! several `2^20` execution shards, three `2^16` field family shards and a field
//! window, over a `2^24` SRS — the stacked commitments' ceiling. Run it with
//!
//! ```text
//! cargo test --release -p prover --test field_ops -- --include-ignored --test-threads=1
//! ```
//!
//! What only a whole proof reaches: the recursion registry's `ADD_SUB` holding
//! the three field ecalls, the field window's derived constant on both sides,
//! the anchors and `FIELD_IO`'s RAM data words in the global multiset, and the
//! stacked opening — `σ` challenges after the GKR pass, stacks of columns
//! committed at their slots' powers, and a batch that opens them at `u ‖ r` —
//! agreeing between the prover and `verify_block`. And the recursion verifier's
//! tape over every one of the block's shards, held to the native verifier's
//! reading of the same proof. Row by row, the three circuits are
//! `crates/checker/tests/recursion.rs`', in CI; the tape's GKR and Mercury
//! halves are `crates/gkr/tests` and `crates/pcs-verify/tests/tape.rs`.

mod common;

use constants::family;
use curve::{msm::msm, G1Affine};
use field::Fr;
use pcs::{batch_verify_deferred, MercuryCommitment, MercuryProof};
use prover::ProverSetup;
use transcript::g1_limbs;
use verifier::verify_block;
use verifier_core::tape::{self, Cell};
use verifier_core::{
    derive_global_phase, shard_window, stack_count, statement_shards, verify_shard_local,
    BlockProof,
};

#[test]
#[ignore]
fn the_recursion_format_proves_and_verifies() {
    let program = common::field_ops_program();
    assert!(program.config.is_recursion());
    let setup = ProverSetup::new(program, common::toy_srs(verifier_core::STACK_LOG))
        .expect("field-ops registers");
    let block = common::streamed(&setup, &common::empty_io());
    assert_eq!(verify_block(&setup.vk, &block, block.statement()), Ok(()));

    // Every shard's witness commitments are its stacks, and an execution
    // family's are fewer than its columns.
    for shard in &block.shards {
        let circuit = setup.vk.circuit(shard.family).expect("a key family");
        let sigma = setup.vk.config.stack_vars(&circuit.artifact);
        assert_eq!(
            shard.witness_commitments.len(),
            stack_count(circuit.artifact.witness.len(), sigma)
        );
        if shard.family == family::ADD_SUB_LUI_AUIPC {
            assert!(sigma > 0 && shard.witness_commitments.len() < circuit.artifact.witness.len());
        }
    }
    // One shard of each field family and one field window.
    for f in [
        family::FR_OP,
        family::P2_FIELD,
        family::FIELD_IO,
        family::FIELD_WINDOWS,
    ] {
        assert_eq!(block.shards.iter().filter(|s| s.family == f).count(), 1);
    }
    every_tape_reads_its_shard_as_the_verifier_does(&setup, &block);
}

/// `docs/spec/recursion.md` §7: each shard's tape, compiled for its family and
/// height, its slots filled from the statement and the key and its blob laid
/// out from the proof, replays with no assertion failing, and leaves what the
/// native verifier computes — `ts_window`, the twelve Mercury scalars of
/// `pcs::batch_verify_deferred`, and batch weights under which the
/// commitments' MSM is that call's `cm*`, which is the deferred batch check a
/// fold makes.
fn every_tape_reads_its_shard_as_the_verifier_does(setup: &ProverSetup, block: &BlockProof) {
    let (vk, public) = (&setup.vk, block.statement());
    let global = derive_global_phase(vk, public).expect("the statement derives");
    let shards = statement_shards(&vk.config, &public.shard_counts);
    for proof in &block.shards {
        let name = program::family_name(proof.family);
        let claim = verify_shard_local(vk, &global, proof, public).expect("the shard verifies");
        let cms: Vec<G1Affine> = claim
            .commitments
            .iter()
            .map(|b| G1Affine::from_bytes(b).expect("a commitment is a point"))
            .collect();
        let mercury = MercuryProof::from_bytes(&proof.opening).expect("the opening decodes");
        let mut transcript = claim.transcript;
        let entries = batch_verify_deferred(
            &setup.srs.verifier(),
            &cms.iter()
                .map(|p| MercuryCommitment(*p))
                .collect::<Vec<_>>(),
            &claim.point,
            &claim.values,
            &mercury,
            &mut transcript,
        )
        .expect("the opening's field side holds");
        let cm_star = entries[0].point;

        let fi = vk
            .config
            .families
            .iter()
            .position(|(f, _)| *f == proof.family)
            .expect("a key family");
        let circuit = &vk.circuits[fi];
        let mut setup_cms = vk.setup_commitments[fi].clone();
        if circuit.reads_generic_table() {
            setup_cms.extend(vk.generic_table);
        }
        let st = tape::shard_tape(&vk.config, circuit, setup_cms.len(), 3);
        let blob = tape::shard_blob(&st.inputs, proof, &cm_star.to_bytes());
        let position = shards
            .iter()
            .position(|s| *s == (proof.family, proof.shard_index))
            .expect("a statement shard");
        let mut memory = tape::Memory::default();
        let mut set = |c: Cell, v: Fr| memory.set(c, v);
        set(st.slots.digest, global.digest);
        for (c, v) in st.slots.memory.iter().zip(global.memory) {
            set(*c, v);
        }
        set(st.slots.index, Fr::from_u64(proof.shard_index as u64));
        let window = shard_window(
            proof.family,
            proof.shard_index,
            &public.windows,
            circuit.artifact.trace_vars,
        );
        set(st.slots.window, Fr::from_u64(window.unwrap_or(0) as u64));
        for (c, v) in st.slots.roots.iter().zip(public.memory_roots[position]) {
            set(*c, v);
        }
        let lists = [
            (
                &st.slots.memory_commitments,
                &public.memory_commitments[position],
            ),
            (&st.slots.setup, &setup_cms),
        ];
        for (cells, points) in lists {
            assert_eq!(cells.len(), points.len(), "{name}");
            for (limbs, point) in cells.iter().zip(points) {
                for (c, v) in limbs.iter().zip(g1_limbs(point)) {
                    set(*c, v);
                }
            }
        }

        tape::run(&st.ops, &mut memory, &blob)
            .unwrap_or_else(|op| panic!("{name}: the tape's op {op} refuses an honest shard"));
        let read = |c: &Cell| memory.get(*c);
        let ts: Vec<Fr> = st.outputs.ts_window.iter().map(read).collect();
        assert_eq!(ts, proof.ts_window.map(Fr::from_u64), "{name}");
        let scalars: Vec<Fr> = st.outputs.mercury.iter().map(read).collect();
        let want: Vec<Fr> = entries.iter().map(|e| e.scalar).collect();
        assert_eq!(scalars, want, "{name}: the Mercury scalars");
        let weights: Vec<Fr> = st.outputs.batch.iter().map(read).collect();
        let folded = msm(&cms, &weights)
            .expect("one weight a commitment")
            .to_affine();
        assert_eq!(
            folded, cm_star,
            "{name}: the batch weights do not fold to cm*"
        );
        println!("{name}: {} ops, {} inputs", st.ops.len(), st.inputs.len());
    }
}
