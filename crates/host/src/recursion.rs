//! The recursion guest's host side: what `guests/recursion` is handed.
//!
//! [`leaf_advice`] lays out a leaf's advice for a slice of a block: the key,
//! the statement, then each shard's proof and its `cm*` hint, in the layout
//! that guest's crate doc gives. The hint is the batch's
//! `cm* = sum rho^i cm_i`, which a guest cannot compute without curve
//! arithmetic; it is entry 0 of the native deferred verification
//! (`docs/spec/accumulator.md` §2), so building the advice also verifies every
//! shard it carries natively, but for the pairings.

use std::ops::Range;

use curve::G1Affine;
use pcs::{batch_verify_deferred, MercuryCommitment, MercuryProof};
use verifier_core::{derive_global_phase, verify_shard_local, BlockProof, VerifyingKey};

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

    let mut out = Vec::new();
    blob(&mut out, &vk.to_bytes());
    blob(&mut out, &public.to_bytes());
    out.extend_from_slice(&(proofs.len() as u32).to_le_bytes());
    for proof in proofs {
        let mut claim =
            verify_shard_local(vk, &global, proof, public).map_err(|e| e.to_string())?;
        let cms = claim
            .commitments
            .iter()
            .map(|b| G1Affine::from_bytes(b).map(MercuryCommitment))
            .collect::<Option<Vec<_>>>()
            .ok_or("a commitment is not a point")?;
        let opening =
            MercuryProof::from_bytes(&proof.opening).ok_or("the opening does not decode")?;
        let entries = batch_verify_deferred(
            &vsrs,
            &cms,
            &claim.point,
            &claim.values,
            &opening,
            &mut claim.transcript,
        )
        .map_err(|e| format!("the opening is refused: {e:?}"))?;
        blob(&mut out, &proof.to_bytes());
        out.extend_from_slice(&entries[0].point.to_bytes());
    }
    Ok(out)
}

/// A little-endian `u32` length, the bytes, and zero padding to a word.
fn blob(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    out.resize(out.len().next_multiple_of(4), 0);
}
