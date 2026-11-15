#![no_std]
//! The verifier core: everything a shard's and a block's verification does.
//! `#![no_std]` + `alloc`.
//!
//! `docs/spec/proof.md` specifies it. The core holds statement binding
//! (the `VmConfig`, its descriptor and window rules, the identity digest, the
//! global transcript), the shard transcript's replay, the GKR claim chain
//! through `gkr-verify`, the LogUp root checks, the memory argument's
//! reconciliation, and the opening of every committed column through
//! `pcs-verify`; [`reduce_shard`] runs them in order.

extern crate alloc;

mod block;
mod reduce;
mod statement;
mod types;
pub mod wire;

pub use block::{check_ts_windows, BlockProof, BlockReconciliation, ShardRecord};
pub use reduce::{
    derive_global_phase, reduce_shard, verify_global_memory, verify_shard_local, GlobalChallenges,
};
pub use statement::{
    absorb_commitment, absorb_statement_descriptor, advice_first_window, boundary_scalars,
    check_memory_windows, global_commit, identity_digest, memory_slots, public_io_words,
    shard_challenges, shard_transcript, shard_window, statement_shards, window_height,
    GlobalTranscript, ProgramIdentity, VmConfig, MEMORY_CHALLENGES, TRIVIAL_TS_WINDOW,
};
pub use types::{
    committed_groups, opening_schedule, pcs_setup_len, read_commitment, read_gkr, read_opening,
    write_commitment, write_gkr, write_opening, PublicInputs, ShardProof, VerifyError,
    VerifyingKey,
};

// The types a key and a proof are built from, so a caller needs no second
// dependency to name them.
pub use constraints::FamilyCircuit;
pub use gkr_verify::{BoundaryFinals, GkrProof};
pub use pcs_verify::{Commitment, Setup};
