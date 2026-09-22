#![no_std]
#![no_main]
//! S23's zero-shard fixture: a guest that **links** both delegation backends
//! and reaches neither.
//!
//! Static detachment is a property of the linked binary, not of the execution
//! (`docs/spec/delegation.md` §7): the declaration records are in the image
//! because `Fr`'s arithmetic and `poseidon2_permute` are reachable, so
//! `decode_program` puts `FR_ARITH` and `POSEIDON2` in the `VmConfig` — and
//! the run invokes them zero times, so the plan proves zero shards of each.
//! Acceptance 9's second half is that this proves and verifies.
//!
//! The calls sit behind `black_box(0) == 1`, which the optimiser cannot fold:
//! without it `opt-level = 3` would prove the branch dead, drop the calls,
//! drop the shims and drop the records with them.
//!
//! # fd 0, fd 1, fd 2, fd 3
//!
//! Unused.
//!
//! # The result
//!
//! The exit status, `a0`: 11.

use field::Fr;
use guest_sdk::{entry, exit};
use transcript::poseidon2_permute;

entry!(main);

fn main() {
    let mut status = 11i32;
    if core::hint::black_box(0u32) == 1 {
        // Unreachable, and the linker cannot know that.
        let mut state = [Fr::ZERO; 3];
        poseidon2_permute(&mut state);
        status = (state[0] == Fr::ONE) as i32;
    }
    exit(status);
}
