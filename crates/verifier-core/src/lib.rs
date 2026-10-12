#![no_std]
//! The verifier core: everything a shard's and a block's verification does.
//! `#![no_std]` + `alloc`.
//!
//! `docs/spec/proof.md` specifies it. The core holds statement binding
//! (the `VmConfig`, its descriptor and window rules, the identity digest, the
//! global transcript), the shard transcript's replay, the GKR claim chain
//! through `gkr-verify`, the LogUp root checks, and the memory argument's
//! reconciliation; [`reduce_shard`] runs them in order and returns the column
//! claims.
//!
//! **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** The protocol
//! this crate verifies is **UNCOMMITTED** and therefore **UNSOUND**: no column
//! a GKR pass reduces to is committed, the transcripts absorb no commitment
//! before the challenges that depend on one, the identity binds no code, and
//! the [`ColumnClaims`] every shard ends in are discharged by nothing. Every
//! place a commitment belongs is marked `UNFINISHED` in this crate; a later
//! commitment scheme must fill each one (`docs/architecture.md` §0).

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
    absorb_statement_descriptor, advice_first_window, boundary_scalars, check_memory_windows,
    global_commit, identity_digest, memory_slots, public_io_words, shard_challenges,
    shard_transcript, shard_window, statement_shards, window_height, GlobalTranscript,
    ProgramIdentity, VmConfig, TRIVIAL_TS_WINDOW,
};
pub use types::{
    read_gkr, write_gkr, ColumnClaims, PublicInputs, ShardProof, VerifyError, VerifyingKey,
};

// The types a key and a proof are built from, so a caller needs no second
// dependency to name them.
pub use constraints::FamilyCircuit;
pub use gkr_verify::{BoundaryFinals, GkrProof};
