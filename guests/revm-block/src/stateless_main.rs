#![no_std]
#![no_main]
//! The **stateless** guest: the canonical stateless validator, the program the
//! zkEVM benchmark compares across zkVMs.
//!
//! ```text
//! statelessInputBytes   -> ADVICE          schema id ‖ SSZ(StatelessInput)
//! statelessOutputBytes  -> PUBLIC OUTPUT   SSZ(StatelessValidationResult), 43 bytes
//! ```
//!
//! The input is `tests-zkevm@v21.0.1`'s wire format byte for byte and the
//! output is the spec's result byte for byte: `(new_payload_request_root,
//! successful_validation, chain_id, schema_id)`. `src/stateless.rs` is the
//! whole computation and says what each field means.
//!
//! **Why the input can be advice.** Nothing binds advice, and nothing needs
//! to: the result publishes the SSZ root of the payload request it validated,
//! which fixes every byte of the payload, and the witness is held to the
//! payload by hashes — the parent header must hash to the payload's
//! `parent_hash`, every trie node to the hash its parent names, every code to
//! the code hash its account names. A witness that is wrong or incomplete
//! cannot make an invalid payload valid; it can only make the result `false`.
//!
//! **The guest always exits 0**, a failed validation included: the verdict is
//! the second field of the journal, as the spec's guest returns it. The one
//! input this binary cannot be given is the empty one, a run with no advice
//! having no advice region at all (`docs/spec/public-values.md` §6); the
//! library answers it with the sentinel natively.

extern crate alloc;

guest_sdk::entry!(main);

fn main() {
    guest_sdk::commit(&revm_block::stateless::run(guest_sdk::advice()));
}
