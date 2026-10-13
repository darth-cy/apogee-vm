//! The transcript-tape validator: the global commit phase's absorb sequence,
//! rendered, and the pre-fork order it must be.
//!
//! [`tape`] turns a `Transcript`'s event log into one line per message. The log
//! records a message's **tag and payload length**, never its values
//! (`crates/transcript`), so a tape is a statement about the *script* a
//! transcript ran, which is exactly what the order is about.
//!
//! [`expected_global_tape`] writes that order out from the statement's shape
//! alone — the family count and the window list — **sharing no code with
//! `verifier_core::global_commit`**, which is the point: the laws are enforced
//! twice by independent code, and so is this order. Every message's position
//! and length is written out here.
//!
//! [`check_global_tape`] runs the real phase and diffs the two, naming the
//! first line that differs.
//!
//! The order is `docs/spec/proof.md` §2's, G1 to G9.
//!
//! **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** The order has
//! no commitment message: nothing of any shard's columns is absorbed before the
//! memory challenges, so this tape passing says nothing about binding. When a
//! commitment scheme fills the void (`docs/architecture.md` §0), its messages
//! join the order between G6 and G7, and here.

use constants::transcript_tags as tags;
use transcript::TranscriptEvent;
use verifier_core::{global_commit, PublicInputs, VerifyingKey};

/// `tag`'s name, or `"?"` for a number no tag has. `constants` holds the
/// table and no logic, so the lookup is here.
fn tag_name(tag: u64) -> &'static str {
    match tag.checked_sub(1).and_then(|i| tags::NAMES.get(i as usize)) {
        Some(name) => name,
        None => "?",
    }
}

/// One line per event, in order: `absorb <TAG> <n>` for a message of `n`
/// payload field elements — the scalar count, or the 31-byte chunk count of a
/// bytes message — and `squeeze <TAG>` for a challenge.
pub fn tape(events: &[TranscriptEvent]) -> Vec<String> {
    events
        .iter()
        .map(|e| match e {
            TranscriptEvent::Absorb { tag, n_scalars } => {
                format!("absorb {} {n_scalars}", tag_name(*tag))
            }
            TranscriptEvent::Challenge { tag } => format!("squeeze {}", tag_name(*tag)),
        })
        .collect()
}

/// The tape the global commit phase actually runs over `vk` and `statement`.
///
/// `statement` must be one `vk` describes — one shard count per config family
/// — as `global_commit`'s contract requires; anything else panics there.
pub fn global_tape(vk: &VerifyingKey, statement: &PublicInputs) -> Vec<String> {
    let global = global_commit(vk, statement);
    tape(global.transcript.event_log())
}

/// The tape the pre-fork order requires, written from the statement's
/// shape: G1 to G9 of `docs/spec/proof.md` §2.
///
/// | # | line |
/// | --- | --- |
/// | G1 | `absorb PROTOCOL_SUITE 1` — the suite tag, the version its payload |
/// | G2 | `absorb VM_CONFIG 2k+1` — `k` family ids, `k` heights, the bytecode ceiling |
/// | G3 | `absorb SHARD_COUNTS k` — one per family, a detached-in-this-run family's 0 included |
/// | G4 | `absorb MEMORY_WINDOWS w` — `ZERO_WINDOWS`' window ids |
/// | G5 | `absorb PROGRAM_IDENTITY 1` |
/// | G6 | `absorb PUBLIC_INPUTS 2` — the I/O digest's 32 bytes, two 31-byte chunks |
/// | — | **UNFINISHED**: the shards' memory-column commitments, absent |
/// | G7 | `absorb MEMORY_BOUNDARY 64` |
/// | G8 | `squeeze MEMORY_CHALLENGE` ×4 |
/// | G9 | `squeeze GLOBAL_STATE_DIGEST` |
pub fn expected_global_tape(vk: &VerifyingKey, statement: &PublicInputs) -> Vec<String> {
    let name = |tag: u64| tag_name(tag);
    let mut lines = Vec::new();
    let mut absorb = |tag: u64, n: usize| lines.push(format!("absorb {} {n}", name(tag)));
    let k = vk.config.families.len();
    absorb(tags::PROTOCOL_SUITE, 1);
    absorb(tags::VM_CONFIG, 2 * k + 1);
    absorb(tags::SHARD_COUNTS, k);
    absorb(tags::MEMORY_WINDOWS, statement.windows.len());
    absorb(tags::PROGRAM_IDENTITY, 1);
    // A bytes message of 32 bytes is two 31-byte chunks.
    absorb(tags::PUBLIC_INPUTS, 32usize.div_ceil(31));
    // ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME. The shards'
    // memory-column commitments belong here, and no line is expected for them
    // because none is absorbed (`docs/architecture.md` §0).
    absorb(tags::MEMORY_BOUNDARY, 64);
    for _ in 0..4 {
        lines.push(format!("squeeze {}", name(tags::MEMORY_CHALLENGE)));
    }
    lines.push(format!("squeeze {}", name(tags::GLOBAL_STATE_DIGEST)));
    lines
}

/// The global commit phase's tape, or the first line at which it leaves the
/// pre-fork order.
///
/// This does **not** check the values absorbed — the event log carries none —
/// so it is a check on the script, not on the statement. What binds the values
/// is that the same `global_commit` produces the digest every shard is seeded
/// with (`docs/spec/proof.md` §2).
pub fn check_global_tape(
    vk: &VerifyingKey,
    statement: &PublicInputs,
) -> Result<Vec<String>, String> {
    let actual = global_tape(vk, statement);
    let expected = expected_global_tape(vk, statement);
    for (i, (got, want)) in actual.iter().zip(&expected).enumerate() {
        if got != want {
            return Err(format!(
                "the global commit phase's tape leaves the pre-fork order at line \
                 {}: `{got}`, where the order has `{want}`",
                i + 1
            ));
        }
    }
    if actual.len() != expected.len() {
        return Err(format!(
            "the global commit phase's tape is {} lines, where the pre-fork order \
             has {}",
            actual.len(),
            expected.len()
        ));
    }
    Ok(actual)
}
