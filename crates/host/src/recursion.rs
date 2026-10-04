//! The recursion guest's host side: what `guests/recursion` is handed.
//!
//! [`leaf_advice`] lays out a leaf's advice for a slice of a base block: one
//! encoded tape a family the slice holds (`verifier_core::tape`), then each
//! shard's slots and its tape's input blob. A blob's `cm*` is the batch's
//! combined commitment, entry 0 of the native deferred verification
//! (`docs/spec/accumulator.md` §2), so building the advice verifies every
//! shard it carries natively, but for the pairings — and replays each shard's
//! tape natively too, so a tape that would refuse a shard does so here, by
//! name, before any guest runs.
//!
//! ```text
//!   u32 t;  t x { words: the imports' cells;  words: the body }
//!   u32 n;  n x { u32 tape;  words: the slots' cells;  bytes: their values;
//!                 bytes: the blob }
//! ```
//!
//! `words` is a little-endian `u32` count and that many `u32`s; `bytes` a
//! `u32` length, the bytes, and zero padding to a word.

use std::ops::Range;

use curve::G1Affine;
use field::Fr;
use pcs::{batch_verify_deferred, MercuryCommitment, MercuryProof};
use transcript::g1_limbs;
use verifier_core::tape::{encode, run, shard_blob, shard_tape, Cell, Encoded, Memory, ShardTape};
use verifier_core::{
    derive_global_phase, shard_window, verify_shard_local, BlockProof, VerifyingKey,
};

/// Every tape's first scratch cell: cells `0..3` are the zero state.
const FIRST: Cell = 3;

/// `guests/recursion`'s advice for shards `shards` of `block`, in statement
/// order, verified against `vk`.
pub fn leaf_advice(
    vk: &VerifyingKey,
    block: &BlockProof,
    shards: Range<usize>,
) -> Result<Vec<u8>, String> {
    let public = block.statement();
    let proofs = block.shard_proofs().get(shards.clone()).ok_or_else(|| {
        format!(
            "the block has {} shards, so no slice {shards:?}",
            block.shard_proofs().len()
        )
    })?;
    let global = derive_global_phase(vk, public).map_err(|e| e.to_string())?;
    let vsrs = verifier::decode_srs_verifier(&vk.srs_verifier)
        .ok_or("the key's SrsVerifier holds a point that is not one")?;

    let mut families: Vec<u32> = Vec::new();
    let mut tapes: Vec<(ShardTape, Encoded)> = Vec::new();
    let mut out = Vec::new();
    let mut shard_words = Vec::new();
    for (i, proof) in proofs.iter().enumerate() {
        let position = shards.start + i;
        let name = program::family_name(proof.family);
        let claim = verify_shard_local(vk, &global, proof, public).map_err(|e| e.to_string())?;
        let cms = claim
            .commitments
            .iter()
            .map(|b| G1Affine::from_bytes(b).map(MercuryCommitment))
            .collect::<Option<Vec<_>>>()
            .ok_or("a commitment is not a point")?;
        let opening =
            MercuryProof::from_bytes(&proof.opening).ok_or("the opening does not decode")?;
        let mut transcript = claim.transcript;
        let entries = batch_verify_deferred(
            &vsrs,
            &cms,
            &claim.point,
            &claim.values,
            &opening,
            &mut transcript,
        )
        .map_err(|e| format!("the opening is refused: {e:?}"))?;

        let fi = vk
            .config
            .families
            .iter()
            .position(|(f, _)| *f == proof.family)
            .ok_or("a proof names a family the key has not")?;
        let circuit = &vk.circuits[fi];
        let mut setup = vk.setup_commitments[fi].clone();
        if circuit.reads_generic_table() {
            setup.extend(vk.generic_table);
        }
        let t = match families.iter().position(|f| *f == proof.family) {
            Some(t) => t,
            None => {
                let tape = shard_tape(&vk.config, circuit, setup.len(), FIRST);
                let encoded = encode(&tape.ops);
                families.push(proof.family);
                tapes.push((tape, encoded));
                tapes.len() - 1
            }
        };
        let tape = &tapes[t].0;
        let blob = shard_blob(&tape.inputs, proof, &entries[0].point.to_bytes());

        let mut slots: Vec<(Cell, Fr)> = vec![(tape.slots.digest, global.digest)];
        slots.extend(tape.slots.memory.iter().copied().zip(global.memory));
        slots.push((tape.slots.index, Fr::from_u64(proof.shard_index as u64)));
        let window = shard_window(
            proof.family,
            proof.shard_index,
            &public.windows,
            circuit.artifact.trace_vars,
        );
        slots.push((tape.slots.window, Fr::from_u64(window.unwrap_or(0) as u64)));
        slots.extend(
            tape.slots
                .roots
                .iter()
                .copied()
                .zip(public.memory_roots[position]),
        );
        let lists = [
            (
                &tape.slots.memory_commitments,
                &public.memory_commitments[position],
            ),
            (&tape.slots.setup, &setup),
        ];
        for (cells, points) in lists {
            for (limbs, point) in cells.iter().zip(points) {
                slots.extend(limbs.iter().copied().zip(g1_limbs(point)));
            }
        }

        // The native replay: what the guest is about to do, refused here first.
        let mut memory = Memory::default();
        for (cell, value) in &slots {
            memory.set(*cell, *value);
        }
        run(&tape.ops, &mut memory, &blob)
            .map_err(|op| format!("shard {position} ({name}): the tape refuses at op {op}"))?;

        shard_words.push((t, slots, blob));
    }

    out.extend_from_slice(&(tapes.len() as u32).to_le_bytes());
    for (_, encoded) in &tapes {
        words(&mut out, &encoded.imports);
        words(&mut out, &encoded.body);
    }
    out.extend_from_slice(&(shard_words.len() as u32).to_le_bytes());
    for (t, slots, blob) in shard_words {
        out.extend_from_slice(&(t as u32).to_le_bytes());
        let cells: Vec<u32> = slots.iter().map(|(c, _)| *c).collect();
        words(&mut out, &cells);
        let values: Vec<u8> = slots.iter().flat_map(|(_, v)| v.to_bytes()).collect();
        bytes(&mut out, &values);
        bytes(&mut out, &blob);
    }
    Ok(out)
}

/// A little-endian `u32` count and the words.
fn words(out: &mut Vec<u8>, words: &[u32]) {
    out.extend_from_slice(&(words.len() as u32).to_le_bytes());
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
}

/// A little-endian `u32` length, the bytes, and zero padding to a word.
fn bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out.resize(out.len().next_multiple_of(4), 0);
}
