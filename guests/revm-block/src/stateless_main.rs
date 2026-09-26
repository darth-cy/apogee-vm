#![no_std]
#![no_main]
//! The **stateless** guest: a whole block, authenticated against the parent's
//! state root and checked against the header's.
//!
//! ```text
//! the block witness + its trie nodes  -> ADVICE          prover-supplied, bound by nothing
//! the header's state root (32 bytes)  -> PUBLIC INPUT    the verifier's own bytes
//! the stateless journal (148 bytes)   -> PUBLIC OUTPUT   what the proof publishes
//! ```
//!
//! S25's must-be-exact 2: *"The two modes are SEPARATE guest binary paths. Use
//! two identities for two modes."* This is the second binary and it has its own
//! program identity, so a verifier holding a journal never has to ask which of
//! two meanings it has. `src/main.rs` is the mini mode, which executes a prefix
//! of a block and **claims no state root**.
//!
//! # Why the header's root arrives as public input
//!
//! Because the comparison has to be against something the prover did not
//! choose. The witness is advice and nothing binds it
//! (`docs/spec/public-values.md` §6), so a root carried *in* the witness would
//! be a value compared against itself — the guest would assert that the prover
//! agreed with the prover. The public input window is the statement's own bytes
//! (§5.1), so a verifier puts the header's `stateRoot` there and the proof says
//! the block reaches it.
//!
//! The journal publishes both roots anyway, so a reader who has the proof has
//! the claim whole: **from the state whose root is `parent_state_root`, this
//! block produced the state whose root is `post_state_root`**.
//!
//! # The exit status
//!
//! | status | what happened |
//! | --- | --- |
//! | 0 | the block ran, the root matched, and the journal holds the result |
//! | 61 | the advice is not a canonical `BlockWitness` |
//! | 62 | a transaction is not executable, so the witness is not a block |
//! | 63 | the witness carries no stateless section — this is the wrong binary |
//! | 64 | the public input is not a 32-byte state root |
//! | 65 | a trie node is missing or malformed, or the sparse trie does not re-hash to the parent root |
//! | 66 | a recorded account or slot is not what the authenticated trie says |
//! | 67 | the recomputed post-state root is not the header's |

extern crate alloc;

use revm_block::stateless::{self, StatelessError};
use revm_block::BlockWitness;

guest_sdk::entry!(main);

/// The advice is not a canonical `BlockWitness`.
const EXIT_WITNESS_MALFORMED: i32 = 61;
/// A transaction is not executable.
const EXIT_NOT_EXECUTABLE: i32 = 62;
/// The witness carries no stateless section.
const EXIT_NOT_STATELESS: i32 = 63;
/// The public input is not a 32-byte state root.
const EXIT_BAD_PUBLIC_INPUT: i32 = 64;
/// A trie node is missing or malformed.
const EXIT_TRIE: i32 = 65;
/// A recorded value is not what the authenticated trie says.
const EXIT_UNAUTHENTICATED: i32 = 66;
/// The recomputed root is not the header's.
const EXIT_ROOT_MISMATCH: i32 = 67;

fn main() {
    let input = guest_sdk::public_input();
    if input.len() != 32 {
        guest_sdk::exit(EXIT_BAD_PUBLIC_INPUT);
    }
    let mut claimed = [0u8; 32];
    claimed.copy_from_slice(input);

    let Ok(witness) = BlockWitness::decode(guest_sdk::advice()) else {
        guest_sdk::exit(EXIT_WITNESS_MALFORMED);
    };
    match stateless::run_stateless(&witness, &claimed) {
        Ok(journal) => guest_sdk::commit(&journal),
        Err(StatelessError::NotStateless) => guest_sdk::exit(EXIT_NOT_STATELESS),
        Err(StatelessError::Trie(_)) => guest_sdk::exit(EXIT_TRIE),
        Err(StatelessError::Unauthenticated { .. })
        | Err(StatelessError::UnauthenticatedSlot { .. }) => guest_sdk::exit(EXIT_UNAUTHENTICATED),
        Err(StatelessError::RootMismatch { .. }) => guest_sdk::exit(EXIT_ROOT_MISMATCH),
        Err(StatelessError::NotExecutable(_)) => guest_sdk::exit(EXIT_NOT_EXECUTABLE),
    }
}
