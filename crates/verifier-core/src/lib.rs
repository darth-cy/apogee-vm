#![no_std]
//! The verifier core: everything a shard's verification does except its one
//! Mercury opening. `#![no_std]` + `alloc`, because the recursion guest links
//! it and re-implementation is forbidden; CI builds it for
//! `riscv32imac-unknown-none-elf`.
//!
//! `docs/spec/shard-proof.md` is normative. The core holds statement binding
//! (the `VmConfig`, its descriptor and window rules, the identity and SRS
//! digests, the global transcript), the shard transcript's replay, the GKR
//! claim chain through `gkr-verify`, the LogUp root checks, and the memory
//! argument's reconciliation; [`reduce_shard`] runs them in order and returns
//! the opening claim. `crates/verifier` decodes the curve points and runs that
//! opening through `pcs::batch_verify`: a Mercury proof's field-side logic is
//! not factored out of `pcs` (the owner's decision, S16), and a curve point is
//! held here as its 64 canonical bytes and absorbed through
//! `transcript::append_g1_points`.

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
    absorb_statement_descriptor, boundary_scalars, check_memory_windows, global_commit,
    identity_digest, memory_slots, shard_challenges, shard_transcript, srs_digest,
    statement_shards, window_height, GlobalTranscript, ProgramIdentity, VmConfig,
    TRIVIAL_TS_WINDOW,
};
pub use types::{
    read_gkr, write_gkr, OpeningClaim, PublicInputs, ShardProof, VerifyError, VerifyingKey,
    OPENING_BYTES, SRS_VERIFIER_BYTES,
};

// The types a key and a proof are built from, so a caller needs no second
// dependency to name them.
pub use constraints::FamilyCircuit;
pub use gkr_verify::{BoundaryFinals, GkrProof};
