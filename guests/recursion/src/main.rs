#![no_std]
#![no_main]
//! The recursion guest's leaf: a slice of a base block's shards, each verified
//! in full but for its Mercury pairings, which it defers as accumulator
//! entries (`docs/spec/accumulator.md`).
//!
//! **A measurement guest, not yet a recursion node.** It runs everything a
//! leaf must run — the statement's global phase and memory reconciliation
//! once, then every shard it is handed through `verify_shard_local` and
//! Mercury's field side (`pcs_verify`) — and publishes digests of the results.
//! It does **not** bind the verifying key it is handed, which it decodes
//! without the key's load rules: what a leaf binds, and the journal a parent
//! reads, are the recursion stage's design and not this guest's.
//!
//! # Advice
//!
//! ```text
//!   blob    the verifying key, VerifyingKey::to_bytes
//!   blob    the statement, PublicInputs::to_bytes
//!   u32     n
//!   n x {   blob      a shard's proof, ShardProof::to_bytes
//!           [u8; 64]  that shard's cm* = sum rho^i cm_i, a hint }
//! ```
//!
//! A blob is a little-endian `u32` length, then that many bytes, padded to a
//! word. Nothing checks the hint here: the second deferred check below does,
//! at discharge.
//!
//! # The accumulator
//!
//! Per shard, two deferred checks, in this order: the twelve terms of
//! `docs/spec/accumulator.md` §2 for the instance `(cm*, u, v*)`, then
//! `cm* - sum rho^i cm_i = O` as `k + 1` `G2One` terms and no `G2X` term,
//! which is that document's §8 option 1. Every point is a claim until
//! `pcs::discharge` validates it (§4).
//!
//! # Journal and exit status
//!
//! The statement's global digest, the accumulator's §5 digest, and `n`
//! (32 + 32 + 4 bytes, little-endian). Exit 0, or 10 if the advice does not
//! decode, or `11 + c` for the first refusal of class `c` in
//! `docs/spec/shard-proof.md` §6's order: statement, malformed, constraint,
//! lookup, memory argument, opening.

extern crate alloc;

use alloc::vec::Vec;

use field::Fr;
use guest_sdk::{advice, commit, entry, exit};
use pcs_verify::{
    accumulator_digest, batch_preamble, check_batch, entry_words, scalars, PairingSide,
    ENTRIES_PER_CHECK, ENTRY_POINTS,
};
use verifier_core::{
    derive_global_phase, verify_global_memory, verify_shard_local, OpeningClaim, PublicInputs,
    ShardProof, VerifyError, VerifyingKey, OPENING_BYTES,
};

entry!(main);

/// The advice does not decode.
const EXIT_INPUT: i32 = 10;

/// `11 + c` for refusal class `c`, in `docs/spec/shard-proof.md` §6's order.
fn refusal(e: VerifyError) -> i32 {
    match e {
        VerifyError::Statement(_) => 11,
        VerifyError::Malformed(_) => 12,
        VerifyError::Constraint { .. } => 13,
        VerifyError::Lookup { .. } => 14,
        VerifyError::MemoryArgument(_) => 15,
        VerifyError::Opening => 16,
    }
}

/// A cursor over the advice; any read past its end is [`EXIT_INPUT`].
struct Advice {
    bytes: &'static [u8],
    at: usize,
}

impl Advice {
    fn take(&mut self, n: usize) -> &'static [u8] {
        let end = self.at.checked_add(n).unwrap_or_else(|| exit(EXIT_INPUT));
        let out = self
            .bytes
            .get(self.at..end)
            .unwrap_or_else(|| exit(EXIT_INPUT));
        self.at = end.next_multiple_of(4);
        out
    }

    fn u32(&mut self) -> u32 {
        let mut word = [0u8; 4];
        word.copy_from_slice(self.take(4));
        u32::from_le_bytes(word)
    }

    fn blob(&mut self) -> &'static [u8] {
        let n = self.u32() as usize;
        self.take(n)
    }
}

fn main() {
    let mut input = Advice {
        bytes: advice(),
        at: 0,
    };
    let vk = VerifyingKey::decode(input.blob()).unwrap_or_else(|_| exit(EXIT_INPUT));
    let public = PublicInputs::from_bytes(input.blob()).unwrap_or_else(|_| exit(EXIT_INPUT));

    // The statement's half, once: the global transcript and the memory
    // argument's reconciliation over every shard's roots.
    let global = derive_global_phase(&vk, &public).unwrap_or_else(|e| exit(refusal(e)));
    verify_global_memory(&vk, &global, &public).unwrap_or_else(|e| exit(refusal(e)));
    let mut generator = [0u8; 64];
    generator.copy_from_slice(&vk.srs_verifier[..64]);

    let n = input.u32();
    let mut words: Vec<Fr> = Vec::new();
    for _ in 0..n {
        let proof = ShardProof::from_bytes(input.blob()).unwrap_or_else(|_| exit(EXIT_INPUT));
        let mut hint = [0u8; 64];
        hint.copy_from_slice(input.take(64));
        let claim =
            verify_shard_local(&vk, &global, &proof, &public).unwrap_or_else(|e| exit(refusal(e)));
        defer_opening(claim, &proof.opening, &hint, &generator, &mut words)
            .unwrap_or_else(|| exit(refusal(VerifyError::Opening)));
    }

    commit(&global.digest.to_bytes());
    commit(&accumulator_digest(&words).to_bytes());
    commit(&n.to_le_bytes());
}

/// A shard's batched opening, run to its pairings and deferred as the two
/// checks the crate doc names, appended to `words` in the word form of
/// `docs/spec/accumulator.md` §3.
fn defer_opening(
    claim: OpeningClaim,
    opening: &[u8; OPENING_BYTES],
    hint: &[u8; 64],
    generator: &[u8; 64],
    words: &mut Vec<Fr>,
) -> Option<()> {
    let OpeningClaim {
        commitments,
        point,
        values,
        mut transcript,
    } = claim;
    check_batch(commitments.len(), values.len(), point.len()).ok()?;
    let (weights, v_star) = batch_preamble(&commitments, &point, &values, &mut transcript);

    // The proof's eight points as encoded and its six values, which must be
    // canonical. `docs/spec/mercury.md` §8.1's field order.
    let mut points = [[0u8; 64]; 8];
    for (slot, raw) in points.iter_mut().zip(opening.chunks_exact(64)) {
        slot.copy_from_slice(raw);
    }
    let mut evals = [Fr::ZERO; 6];
    for (slot, raw) in evals.iter_mut().zip(opening[8 * 64..].chunks_exact(32)) {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(raw);
        *slot = Fr::from_bytes(&bytes)?;
    }
    let terms = scalars(hint, &point, v_star, &points, &evals, &mut transcript).ok()?;

    let [h, q, g, s, d, pi_z, w, w_prime] = points;
    let at = [*hint, h, q, g, s, d, pi_z, w, w_prime, *generator];
    words.push(Fr::from_u64(ENTRIES_PER_CHECK as u64));
    for ((side, index), scalar) in ENTRY_POINTS.iter().zip(terms) {
        words.extend_from_slice(&entry_words(*side, scalar, &at[*index]));
    }

    words.push(Fr::from_u64(commitments.len() as u64 + 1));
    words.extend_from_slice(&entry_words(PairingSide::G2One, Fr::ONE, hint));
    for (cm, weight) in commitments.iter().zip(&weights) {
        words.extend_from_slice(&entry_words(PairingSide::G2One, -*weight, cm));
    }
    Some(())
}
