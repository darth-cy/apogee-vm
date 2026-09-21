#![no_std]
#![no_main]
//! S21's zero-shard fixture: a guest that **links** the keccak shim and never
//! calls it.
//!
//! Static detachment is a property of the linked binary, not of the execution
//! (`docs/spec/delegation.md` §7): the declaration record is in the image
//! because `keccak256` is reachable, so `decode_program` puts `KECCAK_F` in the
//! `VmConfig` — and the run invokes it zero times, so the plan proves zero
//! shards of it. Acceptance 8's second half is that this proves and verifies.
//!
//! The call sits behind `black_box(0) == 1`, which the optimiser cannot fold:
//! without it `opt-level = 3` would prove the branch dead, drop the call, drop
//! the shim and drop the record with it — and the guest would be
//! `guests/addsub` with extra steps.
//!
//! # fd 0, fd 1, fd 2, fd 3
//!
//! Unused.
//!
//! # The result
//!
//! The exit status, `a0`: 7.

use guest_sdk::{entry, exit, keccak256};

entry!(main);

fn main() {
    let mut status = 7i32;
    if core::hint::black_box(0u32) == 1 {
        // Unreachable, and the linker cannot know that.
        status = keccak256(&[0u8; 1])[0] as i32;
    }
    exit(status);
}
