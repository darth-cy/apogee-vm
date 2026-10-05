#![no_std]
#![no_main]
//! The heap fixture: an echo of the advice region into the journal, run
//! through the bump allocator, plus the one delegation call that is not an
//! echo.
//!
//! Its buffers are heap-allocated on purpose. Almost nothing else in `guests/`
//! needs `alloc`, so without this the bump allocator would be dead-stripped
//! out of every small binary and the largest `unsafe` surface in the workspace
//! would run nowhere. Here it is linked and exercised at two alignments — a
//! `Vec<u8>` and a `Vec<u32>` — on an allocator whose `dealloc` does nothing.
//!
//! # The advice
//!
//! Any number of bytes, with no structure of any kind. They are copied 64 at a
//! time into a heap buffer and appended to the journal from it, so the echo is
//! a real allocation and a real copy rather than a slice handed straight on.
//!
//! **This guest cannot run without advice.** Asking for advice a run was not
//! given is a fatal executor error rather than an empty slice, and zero bytes
//! of advice make no region (`docs/spec/public-values.md` §6), so a run of
//! this guest supplies at least one byte.
//!
//! # The journal
//!
//! The advice, byte for byte, truncated to what a journal holds. A journal is
//! at most [`guest_memory::PUBLIC_PAYLOAD_BYTES`] bytes and advice has no such
//! bound, so the echo stops there rather than exiting 70 on the first `commit`
//! that would not fit.
//!
//! **Nothing binds the advice**, so this journal is a byte string the prover
//! chose. That is what the guest is for — it is the allocator's fixture, not a
//! statement about anything — and it is the one shape
//! `docs/spec/public-values.md` §6 tells a real program not to have.
//!
//! # The public input
//!
//! Unused.
//!
//! # The delegation
//!
//! One `poseidon2_permute` over a three-lane state, compared against the same
//! permutation reached through `crates/transcript`. Both entry points are
//! linked here, which is what makes this guest's image declare the `POSEIDON2`
//! and `FR_ARITH` families (`docs/spec/delegation.md` §7) — `crates/program/
//! tests/delegation.rs` holds it to exactly those two — and what proves those
//! two `no_std` crates compile and run on RV32.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use constants::guest_memory;
use field::Fr;

guest_sdk::entry!(main);

/// How many bytes of advice one heap buffer carries at a time.
const CHUNK: usize = 64;

fn main() {
    // The advice, into the journal, through the heap. A fresh `Vec<u8>` and a
    // copy per chunk: the point is the allocation and the copy, not the
    // shortest path from one region to the other.
    let advice = guest_sdk::advice();
    let echoed = advice
        .len()
        .min(guest_memory::PUBLIC_PAYLOAD_BYTES as usize);
    let mut buf: Vec<u8> = vec![0u8; CHUNK];
    let mut at = 0;
    while at < echoed {
        let take = CHUNK.min(echoed - at);
        buf[..take].copy_from_slice(&advice[at..at + take]);
        guest_sdk::commit(&buf[..take]);
        at += take;
    }

    // A four-byte-aligned allocation as well as the byte ones above, so the
    // allocator's alignment rounding runs.
    let mut words: Vec<u32> = vec![0u32; 4];
    words[3] = 0xdead_beef;
    assert_eq!(
        words[3], 0xdead_beef,
        "the heap did not hand back what it was given"
    );

    // The delegation and the software twin, behind one signature. On an
    // executor with the circuit both reach it; on one without, both take the
    // software path inside `transcript`. The states agree either way, which is
    // the property the fallback exists to have.
    let mut state = [0u8; 96];
    state[0] = 1;
    state[32] = 2;
    state[64] = 3;
    let mut want = state;
    software_poseidon2(&mut want);
    if !guest_sdk::poseidon2_permute(&mut state) {
        software_poseidon2(&mut state);
    }
    assert_eq!(
        state, want,
        "the delegated permutation is not the software permutation"
    );
}

/// The delegation's software twin: `transcript`'s permutation, over the same
/// 96-byte canonical little-endian state the ecall takes.
fn software_poseidon2(bytes: &mut [u8; 96]) {
    let mut state = [Fr::ZERO; 3];
    for (i, lane) in state.iter_mut().enumerate() {
        let mut w = [0u8; 32];
        w.copy_from_slice(&bytes[32 * i..32 * (i + 1)]);
        *lane = Fr::from_bytes(&w).expect("precompile state lanes are canonical");
    }
    transcript::poseidon2_permute(&mut state);
    for (i, lane) in state.iter().enumerate() {
        bytes[32 * i..32 * (i + 1)].copy_from_slice(&lane.to_bytes());
    }
}
