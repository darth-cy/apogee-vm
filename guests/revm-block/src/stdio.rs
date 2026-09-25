#![no_std]
#![no_main]
//! The **compatibility** binary: one `BlockWitness` off fd 0, revm over it,
//! the output commitment onto fd 1.
//!
//! `src/main.rs` is the guest a proof is about; this one exists for the
//! executors that have no advice region and no public windows —
//! `qemu-riscv32`, which maps only the image's `PT_LOAD` segments — so that
//! `crates/emulator/tests/revm.rs` can hold the same `revm_block::run` against
//! native revm on the same witness. `read` and `write` are not provable ecalls
//! (`docs/spec/public-values.md` §1), so this binary is not provable, and it
//! does not need to be: what it covers is the computation, not the binding.
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
    // One `read`, into one buffer, sized once: `read_stdin` returns short only
    // at the end of the stream, so a full buffer is the case that cannot be
    // told apart from a truncated witness, and it exits rather than decoding a
    // prefix.
    let mut buffer = vec![0u8; WITNESS_CAPACITY];
    let len = guest_sdk::read_stdin(&mut buffer);
    if len == buffer.len() {
        guest_sdk::exit(EXIT_WITNESS_TOO_LARGE);
    }
    let Ok(witness) = BlockWitness::decode(&buffer[..len]) else {
        guest_sdk::exit(EXIT_WITNESS_MALFORMED);
    };
    let Ok(output) = revm_block::run(&witness) else {
        guest_sdk::exit(EXIT_NOT_EXECUTABLE);
    };
    guest_sdk::write_stdout(&output);
}
