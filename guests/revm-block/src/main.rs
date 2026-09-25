#![no_std]
#![no_main]
//! S25b's guest: a compact public header off fd 0, the bulk `BlockWitness` out
//! of the **advice** region, revm over it, the output commitment onto fd 1.
//!
//! # What is public and what is not
//!
//! ```text
//! fd 0    advice_len, chain id, block number, parent hash   public, bound by io_digest
//! ADVICE  the whole BlockWitness                            private, UNVALIDATED
//! fd 1    the output commitment                             public, bound by io_digest
//! ```
//!
//! The witness used to come in on fd 0, which meant a Poseidon2 sponge over
//! every byte of it at exit and a copy of it in RAM. It comes out of the
//! advice region now: ordinary loads, no ecall per word, no second copy, and
//! nothing of it in `io_digest` (`docs/spec/advice.md` §7).
//!
//! The price is that **nothing outside this guest says what those bytes are**.
//! The one check made here is [`BlockWitness::matches`] against the public
//! header, which fixes the chain, the height and the parent and fixes nothing
//! about the state. This proof therefore says "there exist accounts, storage,
//! code and transactions under which this block executes to this commitment",
//! and it does **not** say those accounts are Ethereum's. Closing that gap
//! needs a state root to validate against and a Merkle-Patricia validator
//! here; `docs/spec/advice.md` §10 is the standing note.
//!
//! # The exit status
//!
//! `0` when the block ran. Anything else is a failure with a cause, and the
//! cause is named rather than folded into one code, because the statuses are
//! all a failing run leaves behind:
//!
//! | status | what happened |
//! | --- | --- |
//! | 0 | the block ran and its commitment is on fd 1 |
//! | 60 | fd 0 did not carry a whole public header |
//! | 61 | the advice region's bytes are not a canonical `BlockWitness` |
//! | 62 | a transaction is not executable, so the witness is not a block |
//! | 63 | the witness is not the block the public header names |

extern crate alloc;

use revm_block::{BlockWitness, PublicHeader, PUBLIC_HEADER_BYTES};

guest_sdk::entry!(main);

/// fd 0 did not carry a whole [`PublicHeader`].
const EXIT_HEADER_SHORT: i32 = 60;
/// The advice region's bytes are not a canonical `BlockWitness`.
const EXIT_WITNESS_MALFORMED: i32 = 61;
/// A transaction is not executable: revm refused it outright, or it does not
/// fit in the gas the block has left (`docs/spec/revm-block.md` §1.4).
const EXIT_NOT_EXECUTABLE: i32 = 62;
/// The advice decodes, but it is a different block from the public header's.
const EXIT_NOT_THE_BLOCK: i32 = 63;

fn main() {
    // One `read` of a fixed 76 bytes. A short read is the end of the stream,
    // so it means fd 0 does not carry a header at all.
    let mut bytes = [0u8; PUBLIC_HEADER_BYTES];
    if guest_sdk::read_input(&mut bytes) != PUBLIC_HEADER_BYTES {
        transcript::exit_with_io_digest(EXIT_HEADER_SHORT);
    }
    let header = PublicHeader::decode(&bytes).expect("a full buffer is a whole header");

    // No buffer, no copy, no ecall: the witness is decoded out of the advice
    // region where it lies. `decode` refuses trailing bytes, so the region's
    // declared length is checked by the decode itself.
    let advice = guest_sdk::advice(header.advice_len as usize);
    let Ok(witness) = BlockWitness::decode(advice) else {
        transcript::exit_with_io_digest(EXIT_WITNESS_MALFORMED);
    };
    if !witness.matches(&header) {
        transcript::exit_with_io_digest(EXIT_NOT_THE_BLOCK);
    }
    let Ok(output) = revm_block::run(&witness) else {
        transcript::exit_with_io_digest(EXIT_NOT_EXECUTABLE);
    };
    guest_sdk::commit(&output);
    // Publish the public I/O digest of the two streams this run moved, in
    // `x24..x31`, which is what binds fd 0 and fd 1 to the execution
    // (`docs/spec/memory.md` §10). It covers the 76-byte header and the
    // commitment, and no advice byte. The four failure exits above publish it
    // too: each happens after the `read`, so each has a non-empty fd 0 stream.
    transcript::exit_with_io_digest(0)
}
