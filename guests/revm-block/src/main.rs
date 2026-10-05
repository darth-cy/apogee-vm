#![no_std]
#![no_main]
//! The provable guest: one `BlockWitness` out of the **advice** region, revm
//! over it, the output commitment into the **journal**.
//!
//! This is the shape the three memory regions are for
//! (`docs/spec/public-values.md`):
//!
//! ```text
//! large Ethereum witness -> ADVICE          prover-supplied, bound by nothing
//! compact statement input -> PUBLIC INPUT   the verifier's own bytes
//! result/commitment       -> PUBLIC OUTPUT  what the proof publishes
//! ```
//!
//! The witness is megabytes and the verifier has no business reading it, so it
//! is advice: ordinary loads from `guest_memory::ADVICE_ORIGIN`, costing the
//! statement nothing. **Nothing binds it.** [`revm_block::BlockWitness::decode`]
//! refuses a non-canonical encoding, and the journal is what the execution did
//! (`docs/spec/ethereum.md` §3) — but no state root is checked or published,
//! so a proof covers these transactions over the witness's state, not that this
//! is Ethereum's state. `src/stateless_main.rs` is the binary that checks it.
//!
//! The witness is data, not code, so the program identity is the same for
//! every block. A witness baked into `.rodata` would move the identity with
//! every block.
//!
//! # The exit status
//!
//! | status | what happened |
//! | --- | --- |
//! | 0 | the block ran and its commitment is in the journal |
//! | 61 | the advice is not a canonical `BlockWitness` |
//! | 62 | a transaction is not executable, so the witness is not a block |

extern crate alloc;

use revm_block::BlockWitness;

guest_sdk::entry!(main);

/// The advice is not a canonical `BlockWitness`.
const EXIT_WITNESS_MALFORMED: i32 = 61;
/// A transaction is not executable: revm refused it outright, or it does not
/// fit in the gas the block has left (`docs/spec/ethereum.md` §2.2).
const EXIT_NOT_EXECUTABLE: i32 = 62;

fn main() {
    // No buffer, no copy, no length guess: the advice region is memory, and
    // `advice()` is a slice over the bytes the host put there.
    let Ok(witness) = BlockWitness::decode(guest_sdk::advice()) else {
        guest_sdk::exit(EXIT_WITNESS_MALFORMED);
    };
    let Ok(output) = revm_block::run(&witness) else {
        guest_sdk::exit(EXIT_NOT_EXECUTABLE);
    };
    guest_sdk::commit(&output);
}
