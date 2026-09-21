//! The prover's metrics harness, behind the `metrics` cargo feature.
//!
//! **This feature is the workspace's one and only cargo feature**, and the one
//! and only exception to master anti-goal 1 (owner's decision, S20). It exists
//! because the harness is deliberately liberal — it sizes every committed
//! column and every forward-pass layer, which is work proportional to the
//! trace — and that must not sit in the path of a real proving run. No later
//! stage may add a second feature: see the root `CLAUDE.md`, and
//! `tests/one_feature.rs`, which fails if any other `[features]` table appears
//! in the workspace or if this one grows a second key.
//!
//! # The seam
//!
//! [`Stage`], [`ByteClass`] and [`ShardId`] are plain data and are compiled in
//! both builds. The collector is not: two modules provide the same names,
//!
//! - `on` (feature on) — the real collector, its data model and its report;
//! - `off` (feature off) — [`Recorder`] and [`Span`] as zero-sized types whose
//!   every method is an empty `#[inline(always)]` body.
//!
//! so the prover's internals take `&mut Recorder` unconditionally and the
//! default build compiles that away: a ZST argument is not passed and an empty
//! inlined call emits no code. **Timing needs no `cfg` at a call site** —
//! `let s = rec.start(Stage::X); …; rec.end(s);` costs nothing with the
//! feature off, because `start` does not read the clock there.
//!
//! What *does* need gating is a measurement whose **arguments** are expensive:
//! sizing a `MultilinearPoly` walks its backing, and sizing a forward pass
//! walks every layer of every column. Those call sites use `metric!`, which
//! expands to nothing at all with the feature off, so the argument is never
//! evaluated.
//!
//! # What it does not do
//!
//! It does not measure resident set size. Reading peak RSS in-process needs
//! libc FFI or a `GlobalAlloc` wrapper, both `unsafe` and so banned by master
//! anti-goal 4 (owner's decision, S20). Instead the harness accounts for **the
//! bytes the prover asks for**, attributed to a cause, and models the peak
//! from them; `/usr/bin/time -l` remains the ground truth for true RSS, as it
//! is in every handoff note. `docs/spec/metrics.md` §4 states exactly what the
//! model counts, what it misses, and how it compares with the measured figure
//! on the statements in this repository.

// ---------------------------------------------------------------------------
// The shared vocabulary: compiled in both builds, code in neither
// ---------------------------------------------------------------------------

/// One shard of the statement, as every per-shard sample names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShardId {
    pub family: u32,
    pub index: u32,
}

impl ShardId {
    pub fn new(family: u32, index: u32) -> ShardId {
        ShardId { family, index }
    }
}

/// **The stages of proving, frozen in this order.** Each is a span the prover
/// opens and closes exactly where the work happens; [`Stage::parent`] gives
/// the tree the report prints, and a parent's time is measured in its own
/// right rather than summed, so the gap between a parent and its children is
/// visible and is itself a finding.
///
/// Appending is allowed; renumbering is not, because
/// `tests/metrics.rs` pins the order and the report's column widths follow it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Stage {
    /// `ProverSetup::new` end to end.
    SetupTotal = 0,
    /// `register`: every family's circuit compiled from the registry.
    SetupRegister = 1,
    /// Identity's setup commitments and the generic table's — MSM.
    SetupCommit = 2,
    /// `VerifyingKey::check`, the key held to its own load rules.
    SetupKeyCheck = 3,

    /// `statement_inputs`: every shard's `M` columns built from the archive.
    StatementColumns = 4,
    /// One shard's fill inside `statement_inputs`, for its `M` columns alone.
    /// It does **not** count multiplicities — the statement commits `M` and
    /// nothing else — which is why this is a stage of its own and not a
    /// `ShardColumnsTotal` sample.
    StatementShardFill = 33,

    /// `global_commit_phase` end to end.
    GlobalCommitTotal = 5,
    /// Committing every shard's memory columns — MSM, the phase's bulk.
    GlobalCommitMsm = 6,
    /// G1–G11: the statement absorbed and the five challenges drawn.
    GlobalTranscript = 7,

    /// `shard_columns` end to end, once per call — **twice per shard** on a
    /// full block, once in each of `advance`'s two parallel regions, which
    /// drop the columns in between so that a killed run can resume from the
    /// archive (`docs/spec/shard-proof.md` §10). That is the resume design's
    /// price and is deliberate; it is not three, because `statement_inputs`
    /// takes the cheaper [`Stage::StatementShardFill`] path for the `M`
    /// columns it alone needs.
    ShardColumnsTotal = 8,
    /// The family's own fill over the archive.
    ShardFill = 9,
    /// `trace::build_multiplicities` over the shard's channels.
    ShardMultiplicities = 10,

    /// `gkr_part` end to end: S1 to S5 of the shard transcript.
    ShardGkrTotal = 11,
    /// `BaseLayer::new`.
    ShardBaseLayer = 12,
    /// Committing the witness columns — MSM.
    ShardWitnessCommit = 13,
    /// The shard seed, `g`, `β` and the external challenge table.
    ShardSeed = 14,
    /// `gkr::forward`: the forward pass, which materializes every layer.
    ShardForward = 15,
    /// `gkr::prove`: every layer's sumcheck.
    ShardSumcheck = 16,
    /// `replay_point`: the schedule replayed to read the base claims' point.
    ShardReplay = 17,

    /// `opening_part` end to end: S6.
    ShardOpeningTotal = 18,
    /// Cloning the committed columns the opening reads.
    ShardOpeningColumns = 19,
    /// Decoding the commitment bytes back to curve points.
    ShardOpeningDecode = 20,
    /// `pcs::batch_open`: the one batched Mercury opening.
    ShardBatchOpen = 21,

    /// `prove_block` end to end.
    BlockTotal = 22,
    /// The shard plan checked against the archive's cycle profile.
    BlockPlanCheck = 23,
    /// The GKR parallel region's **wall** time — one span for the whole
    /// region, against which the `ShardGkrTask` sum gives the speedup the
    /// thread count bought.
    BlockGkrRegion = 24,
    /// The opening parallel region's wall time, likewise.
    BlockOpeningRegion = 25,
    /// The final phase section: `public_inputs` and its encoding.
    BlockFinalSection = 26,
    /// `finish`: the final section decoded back.
    BlockFinish = 27,
    /// Assembling the `BlockProof` and checking its shape.
    BlockAssemble = 28,

    /// Encoding a phase section into the archive.
    ArchiveEncode = 29,
    /// Decoding a phase section a resumed archive already held.
    ArchiveDecode = 30,

    /// **One rayon task's whole body in the GKR region**: this shard's columns
    /// built, its base layer assembled and `gkr_part` run. The region's wall
    /// against the sum of these is the speedup the thread count bought —
    /// against `ShardGkrTotal` alone it is understated, because the region
    /// waits for the column building too.
    ShardGkrTask = 31,
    /// One rayon task's whole body in the opening region, likewise.
    ShardOpeningTask = 32,
}

/// Every stage, in order. `Stage as usize` indexes this.
pub const STAGES: [Stage; 34] = [
    Stage::SetupTotal,
    Stage::SetupRegister,
    Stage::SetupCommit,
    Stage::SetupKeyCheck,
    Stage::StatementColumns,
    Stage::GlobalCommitTotal,
    Stage::GlobalCommitMsm,
    Stage::GlobalTranscript,
    Stage::ShardColumnsTotal,
    Stage::ShardFill,
    Stage::ShardMultiplicities,
    Stage::ShardGkrTotal,
    Stage::ShardBaseLayer,
    Stage::ShardWitnessCommit,
    Stage::ShardSeed,
    Stage::ShardForward,
    Stage::ShardSumcheck,
    Stage::ShardReplay,
    Stage::ShardOpeningTotal,
    Stage::ShardOpeningColumns,
    Stage::ShardOpeningDecode,
    Stage::ShardBatchOpen,
    Stage::BlockTotal,
    Stage::BlockPlanCheck,
    Stage::BlockGkrRegion,
    Stage::BlockOpeningRegion,
    Stage::BlockFinalSection,
    Stage::BlockFinish,
    Stage::BlockAssemble,
    Stage::ArchiveEncode,
    Stage::ArchiveDecode,
    Stage::ShardGkrTask,
    Stage::ShardOpeningTask,
    Stage::StatementShardFill,
];

impl Stage {
    /// The stage this one is measured inside, or `None` for a root.
    pub fn parent(self) -> Option<Stage> {
        use Stage::*;
        match self {
            SetupTotal | StatementColumns | GlobalCommitTotal | ShardColumnsTotal
            | ShardGkrTotal | ShardOpeningTotal | BlockTotal | ArchiveEncode | ArchiveDecode
            | ShardGkrTask | ShardOpeningTask => None,
            SetupRegister | SetupCommit | SetupKeyCheck => Some(SetupTotal),
            StatementShardFill => Some(StatementColumns),
            GlobalCommitMsm | GlobalTranscript => Some(GlobalCommitTotal),
            ShardFill | ShardMultiplicities => Some(ShardColumnsTotal),
            ShardBaseLayer | ShardWitnessCommit | ShardSeed | ShardForward | ShardSumcheck
            | ShardReplay => Some(ShardGkrTotal),
            ShardOpeningColumns | ShardOpeningDecode | ShardBatchOpen => Some(ShardOpeningTotal),
            BlockPlanCheck | BlockGkrRegion | BlockOpeningRegion | BlockFinalSection
            | BlockFinish | BlockAssemble => Some(BlockTotal),
        }
    }

    /// The report's label: the enum's name in `snake_case`.
    pub fn name(self) -> &'static str {
        use Stage::*;
        match self {
            SetupTotal => "setup_total",
            SetupRegister => "setup_register",
            SetupCommit => "setup_commit",
            SetupKeyCheck => "setup_key_check",
            StatementColumns => "statement_columns",
            GlobalCommitTotal => "global_commit_total",
            GlobalCommitMsm => "global_commit_msm",
            GlobalTranscript => "global_transcript",
            ShardColumnsTotal => "shard_columns_total",
            ShardFill => "shard_fill",
            ShardMultiplicities => "shard_multiplicities",
            ShardGkrTotal => "shard_gkr_total",
            ShardBaseLayer => "shard_base_layer",
            ShardWitnessCommit => "shard_witness_commit",
            ShardSeed => "shard_seed",
            ShardForward => "shard_forward",
            ShardSumcheck => "shard_sumcheck",
            ShardReplay => "shard_replay",
            ShardOpeningTotal => "shard_opening_total",
            ShardOpeningColumns => "shard_opening_columns",
            ShardOpeningDecode => "shard_opening_decode",
            ShardBatchOpen => "shard_batch_open",
            BlockTotal => "block_total",
            BlockPlanCheck => "block_plan_check",
            BlockGkrRegion => "block_gkr_region",
            BlockOpeningRegion => "block_opening_region",
            BlockFinalSection => "block_final_section",
            BlockFinish => "block_finish",
            BlockAssemble => "block_assemble",
            ArchiveEncode => "archive_encode",
            ArchiveDecode => "archive_decode",
            ShardGkrTask => "shard_gkr_task",
            ShardOpeningTask => "shard_opening_task",
            StatementShardFill => "statement_shard_fill",
        }
    }
}

/// **What a counted byte is for.** The harness sizes the structures the prover
/// builds rather than the allocations it makes, so every class here is a real
/// buffer with a name, and their sum is what a run asks the allocator for — a
/// lower bound on resident set size, never an estimate of it
/// (`docs/spec/metrics.md` §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ByteClass {
    /// A shard's `M` columns: the memory frame, built once per statement and
    /// held for the whole global commit phase.
    MemoryColumns = 0,
    /// A shard's `W` columns, multiplicities excluded.
    WitnessColumns = 1,
    /// The multiplicity columns `build_multiplicities` appends.
    Multiplicities = 2,
    /// The `S` columns a shard reads: identity's, and the generic table's for
    /// a family that reads the channel.
    SetupColumns = 3,
    /// The base layer a shard proves over — its `M`, `W` and `S` columns as
    /// `BaseLayer` holds them.
    BaseLayer = 4,
    /// **The forward pass's materialized layers**, the prover's largest single
    /// structure and the one that makes a shard's peak.
    ForwardLayers = 5,
    /// The opening's clone of the committed columns.
    OpeningColumns = 6,
    /// Commitment bytes: 64 a point, in the statement and in the proof.
    Commitments = 7,
    /// A shard's GKR proof on the wire.
    GkrProof = 8,
    /// A shard's Mercury opening on the wire.
    Opening = 9,
    /// The statement's own bytes.
    Statement = 10,
    /// A phase section stored in the trace archive.
    ArchiveSection = 11,
}

/// Every byte class, in order.
pub const BYTE_CLASSES: [ByteClass; 12] = [
    ByteClass::MemoryColumns,
    ByteClass::WitnessColumns,
    ByteClass::Multiplicities,
    ByteClass::SetupColumns,
    ByteClass::BaseLayer,
    ByteClass::ForwardLayers,
    ByteClass::OpeningColumns,
    ByteClass::Commitments,
    ByteClass::GkrProof,
    ByteClass::Opening,
    ByteClass::Statement,
    ByteClass::ArchiveSection,
];

impl ByteClass {
    pub fn name(self) -> &'static str {
        use ByteClass::*;
        match self {
            MemoryColumns => "memory_columns",
            WitnessColumns => "witness_columns",
            Multiplicities => "multiplicities",
            SetupColumns => "setup_columns",
            BaseLayer => "base_layer",
            ForwardLayers => "forward_layers",
            OpeningColumns => "opening_columns",
            Commitments => "commitments",
            GkrProof => "gkr_proof",
            Opening => "opening",
            Statement => "statement",
            ArchiveSection => "archive_section",
        }
    }

    /// Whether the class is **live at a shard's peak**: the base layer and the
    /// forward pass exist at the same moment, inside `gkr_part`, and that is
    /// the moment a shard is largest. The proof-side classes are orders of
    /// magnitude smaller and are not part of the model
    /// (`docs/spec/metrics.md` §4.2).
    pub fn resident_at_shard_peak(self) -> bool {
        matches!(self, ByteClass::BaseLayer | ByteClass::ForwardLayers)
    }
}

#[cfg(feature = "metrics")]
pub mod on;
#[cfg(feature = "metrics")]
pub use on::*;

#[cfg(not(feature = "metrics"))]
pub mod off;
#[cfg(not(feature = "metrics"))]
pub use off::*;
