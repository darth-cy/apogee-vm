#![no_std]
#![no_main]
//! The same program as `src/main.rs`, with its witness in the image and its
//! output digest in the register boundary — which is what makes it provable.
//!
//! # Why it exists
//!
//! `read` and `write` are not provable ecalls. The add/sub family's circuit
//! holds every ecall row to `a7 = EXIT` or a registered delegation number
//! (`crates/constraints/src/add_sub.rs`, the `ecall_is_exit` gate), and
//! `prover::fill::add_sub` refuses a `read` row, a `write` row and their
//! transfer cycles by name. Binding fd 0 and fd 1 is the deferred I/O-binding
//! stage's work, which `prompts/00-master.md` lists among its frozen
//! invariants, and S24 does not do it: see `docs/handoff/S24-revm.md`.
//!
//! So this binary calls neither, and binds the same two streams by the two
//! means the machine already has:
//!
//! - **The input** is [`WITNESS`], a `.rodata` constant. Program identity
//!   commits the image window word by word (`docs/spec/memory.md` §6.2), so a
//!   changed witness is a changed identity, which the verifier takes from a
//!   channel the prover does not control.
//! - **The output** is `keccak256` of the commitment, left in `x24..x31` by
//!   [`guest_sdk::exit_with_public_words`]. The statement carries the final
//!   value of every register, so those eight words are public and the memory
//!   argument binds them to the execution that produced them.
//!
//! **The words mean the digest only on the success path.** The two failure
//! exits below go through `guest_sdk::exit`, which touches no register but
//! `a0`, so `x24..x31` then hold whatever the code generator last left there.
//! A reader of the statement takes the exit status and the words together, and
//! never the words alone.
//!
//! The *normative* guest is `src/main.rs`, and this one runs the same
//! [`revm_block::run`] over the same committed witness: whatever the two bind
//! differently, they compute identically, and `crates/emulator/tests/revm.rs`
//! holds their output commitments equal.
//!
//! # The exit status
//!
//! `0`, with the digest in `x24..x31`. `61` for a witness the decoder refuses
//! and `62` for a block revm will not execute — neither of which the committed
//! witness is, and a test says so.

extern crate alloc;

use revm_block::BlockWitness;

guest_sdk::entry!(main);

/// The committed witness, in this image's `.rodata`.
///
/// `crates/emulator/tests/vectors/revm_block_witness.bin` is written by
/// `cargo run -p kat-gen -- revm` and is the same file `src/main.rs` is handed
/// on fd 0, so the two binaries execute the same block.
const WITNESS: &[u8] =
    include_bytes!("../../../crates/emulator/tests/vectors/revm_block_witness.bin");

/// The committed witness is not a canonical `BlockWitness`.
const EXIT_WITNESS_MALFORMED: i32 = 61;
/// revm refused a transaction outright.
const EXIT_NOT_EXECUTABLE: i32 = 62;

fn main() {
    let Ok(witness) = BlockWitness::decode(WITNESS) else {
        guest_sdk::exit(EXIT_WITNESS_MALFORMED);
    };
    let Ok(output) = revm_block::run(&witness) else {
        guest_sdk::exit(EXIT_NOT_EXECUTABLE);
    };
    guest_sdk::exit_with_public_words(0, revm_block::output_digest_words(&output));
}
