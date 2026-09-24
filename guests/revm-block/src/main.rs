#![no_std]
#![no_main]
//! S24's guest: one `BlockWitness` off fd 0, revm over it, the output
//! commitment onto fd 1. Every byte in and every byte out passes through
//! S10's frozen `io_digest`, and there is no other channel: no fd 3 hint, no
//! embedded input, no clock.
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
//! | 60 | fd 0 filled the whole buffer, so the witness may be truncated |
//! | 61 | fd 0's bytes are not a canonical `BlockWitness` |
//! | 62 | a transaction is not executable, so the witness is not a block |

extern crate alloc;

use alloc::vec;

use revm_block::{BlockWitness, WITNESS_CAPACITY};

guest_sdk::entry!(main);

/// fd 0 filled the buffer: the witness may have been cut short.
const EXIT_WITNESS_TOO_LARGE: i32 = 60;
/// fd 0's bytes are not a canonical `BlockWitness`.
const EXIT_WITNESS_MALFORMED: i32 = 61;
/// A transaction is not executable: revm refused it outright, or it does not
/// fit in the gas the block has left (`docs/spec/revm-block.md` §1.4).
const EXIT_NOT_EXECUTABLE: i32 = 62;

fn main() {
    // One `read`, into one buffer, sized once: `read_input` returns short only
    // at the end of the stream, so a full buffer is the case that cannot be
    // told apart from a truncated witness, and it exits rather than decoding a
    // prefix.
    let mut buffer = vec![0u8; WITNESS_CAPACITY];
    let len = guest_sdk::read_input(&mut buffer);
    if len == buffer.len() {
        transcript::exit_with_io_digest(EXIT_WITNESS_TOO_LARGE);
    }
    let Ok(witness) = BlockWitness::decode(&buffer[..len]) else {
        transcript::exit_with_io_digest(EXIT_WITNESS_MALFORMED);
    };
    let Ok(output) = revm_block::run(&witness) else {
        transcript::exit_with_io_digest(EXIT_NOT_EXECUTABLE);
    };
    guest_sdk::commit(&output);
    // Publish the public I/O digest of the two streams this run moved, in
    // `x24..x31`, which is what binds fd 0 and fd 1 to the execution
    // (`docs/spec/memory.md` §10). The three failure exits above publish it too:
    // each happens after the `read`, so each has a non-empty fd 0 stream.
    transcript::exit_with_io_digest(0)
}
