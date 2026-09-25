//! The prover: a program's verifying key, the statement an execution proves,
//! the global commit phase, and each shard's proof. `docs/spec/shard-proof.md`
//! is normative.
//!
//! ```text
//! ProverSetup::new        register every family of the program's VmConfig, build its key
//! statement_inputs        an archive's shard counts, windows, boundary and memory columns
//! global_commit_phase     commit every shard's memory columns, run the global transcript
//! prove_shard             one shard: witness commitments, lookup challenges, GKR, opening
//! public_inputs           the statement, its roots read from the shards' proofs
//! advance                 all of it, filling the trace archive's phases, resumable
//! ```
//!
//! The prover checks nothing a verifier does not: a malformed input costs the
//! honest prover a panic or a proof that fails (S13). What it does check is its
//! own program: a trace S16 cannot prove, a family no circuit proves, is
//! refused by name before any work.

/// Run the enclosed statements only in a build with the `metrics` feature.
///
/// Crate-private and deliberately not `#[macro_export]`ed: a `macro_rules!` at
/// the crate root is textually in scope for every module declared after it,
/// which is all this needs, and exporting it would put it in the public API
/// for nothing.
///
/// Use it wherever the *arguments* of a measurement cost something to compute:
/// every `rec.bytes(..)` whose value walks a column, every `rec.note_*(..)`
/// that walks a circuit. Plain `rec.start`/`rec.end` timing does not need it,
/// because `Recorder::start` does not read the clock with the feature off.
macro_rules! metric {
    ($($t:tt)*) => {
        #[cfg(feature = "metrics")]
        {
            $($t)*
        }
    };
}

mod fill;
pub mod metrics;
mod phases;

use constants::family;
use constants::transcript_tags as tags;
use constraints::PolyAddress;
use curve::G1Affine;
use field::Fr;
use gkr::{forward, prove, BaseLayer};
use loader::ProgramImage;
use pcs::{batch_open, commit, MercuryCommitment};
use poly::MultilinearPoly;
use program::lookup_tables::generic_commitments;
use program::{setup_commitments, DecodedTables, FamilyId};
use rayon::prelude::*;
use srs::Srs;
use trace::{
    advice_window_count, build_boundary_finals, build_multiplicities, init_windows, plan_shards,
    TraceArchive,
};
use transcript::{Transcript, TranscriptEvent, TranscriptSnapshot};
use verifier_core::{
    advice_first_window, global_commit, identity_digest, shard_challenges, shard_transcript,
    srs_digest, statement_shards, window_height, BoundaryFinals, FamilyCircuit, GkrProof,
    PublicInputs, ShardProof, VerifyingKey, VmConfig, TRIVIAL_TS_WINDOW,
};

pub use fill::{family_fill, Fill, ShardSource};
pub use phases::{advance, finish, prove_block};

#[cfg(feature = "metrics")]
pub use phases::{advance_metered, prove_block_metered};

use metrics::{Recorder, Stage};
// Used only inside `metric!`, which is nothing at all in the default build.
#[cfg(feature = "metrics")]
use metrics::{ByteClass, ShardId};

/// Every way the prover refuses. One flat enum.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProverError {
    /// A family of the program's config that no circuit proves at its height.
    Unregistered { family: FamilyId, height: u32 },
    /// The verifying key the setup built does not pass its own load rules.
    Key(String),
    /// A trace this prover cannot prove, or a column it cannot build.
    Trace(String),
    /// A trace archive whose phases do not decode.
    Archive(String),
}

impl std::fmt::Display for ProverError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ProverError::Unregistered { family, height } => write!(
                f,
                "no circuit proves family {} at height {height}",
                program::family_name(*family)
            ),
            ProverError::Key(e) => write!(f, "the verifying key: {e}"),
            ProverError::Trace(e) => write!(f, "the trace: {e}"),
            ProverError::Archive(e) => write!(f, "the trace archive: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Registration and the verifying key
// ---------------------------------------------------------------------------

/// A program as the prover holds it: the image, and the decoded tables and
/// config `program::decode_program` derived from it.
#[derive(Clone, Debug)]
pub struct Program {
    pub image: ProgramImage,
    pub tables: DecodedTables,
    pub config: VmConfig,
}

/// One family as a statement registers it: its id and height from the
/// `VmConfig`, its circuit from `constraints::family_circuit`, and the fill
/// that routes its trace buffer into the circuit's columns.
///
/// **The family-registration surface**, `docs/spec/shard-proof.md` §11: a later
/// family adds a circuit to `constraints::family_circuit` and a fill to
/// [`family_fill`], and nothing in `global_commit_phase`, `prove_shard` or the
/// verifier changes.
#[derive(Clone, Debug)]
pub struct FamilyRegistration {
    pub family: FamilyId,
    pub height: u32,
    pub circuit: FamilyCircuit,
    pub fill: Fill,
}

/// Every family of `config`, registered in its order, or the first one S16
/// cannot prove.
pub fn register(config: &VmConfig) -> Result<Vec<FamilyRegistration>, ProverError> {
    config
        .families
        .iter()
        .map(|&(family, height)| {
            let unregistered = ProverError::Unregistered { family, height };
            let circuit = constraints::family_circuit(family, height.trailing_zeros())
                .ok_or(unregistered.clone())?;
            let fill = family_fill(family).ok_or(unregistered)?;
            Ok(FamilyRegistration {
                family,
                height,
                circuit,
                fill,
            })
        })
        .collect()
}

/// Everything proving one program needs that no execution changes: the
/// program, its registered families, its verifying key, and the prover's SRS.
pub struct ProverSetup {
    pub program: Program,
    pub families: Vec<FamilyRegistration>,
    pub vk: VerifyingKey,
    pub srs: Srs,
}

impl ProverSetup {
    /// Register every family of `program`'s config and build its verifying
    /// key over `srs`: identity's setup commitments, the generic table's, the
    /// SRS digest over both SRS constants, and every circuit, held to the key's
    /// own load rules (`docs/spec/shard-proof.md` §7.2) before it is returned.
    /// `srs` holds at least as many powers as the tallest family has rows, and
    /// at least the generic table's `2^18`.
    pub fn new(program: Program, srs: Srs) -> Result<ProverSetup, ProverError> {
        ProverSetup::build(program, srs, &mut Recorder::new())
    }

    /// [`ProverSetup::new`] recording into `rec`: the registry's compilation,
    /// the setup MSMs and the key's own load rules, each timed, and every
    /// registered family's circuit shape noted.
    #[cfg(feature = "metrics")]
    pub fn new_metered(
        program: Program,
        srs: Srs,
        rec: &mut Recorder,
    ) -> Result<ProverSetup, ProverError> {
        ProverSetup::build(program, srs, rec)
    }

    fn build(program: Program, srs: Srs, rec: &mut Recorder) -> Result<ProverSetup, ProverError> {
        let total = rec.start(Stage::SetupTotal);
        let span = rec.start(Stage::SetupRegister);
        let families = register(&program.config)?;
        rec.end(span);
        metric!(for f in &families {
            rec.note_family(metrics::family_shape(&f.circuit, f.height));
        });
        let span = rec.start(Stage::SetupCommit);
        let setup = setup_commitments(&program.image, &program.tables, &program.config, &srs);
        let setup: Vec<Vec<[u8; 64]>> = setup
            .iter()
            .map(|points| points.iter().map(G1Affine::to_bytes).collect())
            .collect();
        let generic_table = generic_commitments(&srs).map(|p| p.to_bytes());
        rec.end(span);
        metric!(rec.bytes(
            ByteClass::Commitments,
            64 * (setup.iter().map(Vec::len).sum::<usize>() + generic_table.len()) as u64
        ));
        let code_version = program.tables.code_version;
        let srs_verifier = verifier::encode_srs_verifier(&srs.verifier());
        let vk = VerifyingKey {
            code_version,
            config: program.config.clone(),
            entry_pc: program.image.entry,
            identity: identity_digest(code_version, &program.config, program.image.entry, &setup),
            setup_commitments: setup,
            srs_verifier,
            generic_table,
            srs_digest: srs_digest(&srs_verifier, &generic_table),
            circuits: families.iter().map(|f| f.circuit.clone()).collect(),
        };
        let span = rec.start(Stage::SetupKeyCheck);
        vk.check().map_err(ProverError::Key)?;
        rec.end(span);
        metric!(rec.note_program(metrics::ProgramShape {
            code_version,
            entry_pc: program.image.entry,
            bytecode_size_words: program.config.bytecode_size_words,
            identity: metrics::digest_hex(vk.identity.to_bytes()),
            srs_digest: metrics::digest_hex(vk.srs_digest.to_bytes()),
            families: program.config.families.clone(),
            ..Default::default()
        }));
        rec.end(total);
        Ok(ProverSetup {
            program,
            families,
            vk,
            srs,
        })
    }

    fn registration(&self, family: FamilyId) -> &FamilyRegistration {
        self.families
            .iter()
            .find(|f| f.family == family)
            .unwrap_or_else(|| panic!("family {family} is not registered for this program"))
    }
}

// ---------------------------------------------------------------------------
// The statement and the global commit phase
// ---------------------------------------------------------------------------

/// What the global commit phase takes: the statement descriptor, the public
/// streams and result, the boundary, and every shard's memory columns.
#[derive(Clone, Debug)]
pub struct StatementInputs {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub exit_status: u32,
    pub shard_counts: Vec<u32>,
    pub windows: Vec<u32>,
    pub boundary: BoundaryFinals,
    /// Per shard, in statement order, its `M` columns in layout order.
    pub memory_columns: Vec<Vec<MultilinearPoly>>,
}

/// What the global commit phase yields, and every shard's proof starts from:
/// the statement it committed — a `PublicInputs` with no roots yet — the
/// global transcript after its last squeeze, the four memory challenges and
/// the global state digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalCommitState {
    pub statement: PublicInputs,
    pub transcript: TranscriptSnapshot,
    pub memory_challenges: [Fr; 4],
    pub digest: Fr,
}

/// The shard counts of an execution: one per config family, in its order —
/// exactly one for `INIT_TEARDOWN`, one per touched window above 0 for
/// `ZERO_WINDOWS`, one each for the two public value families, one per advice
/// window the host supplied, and `ceil(cycles / height)` for every other.
fn shard_counts(
    config: &VmConfig,
    archive: &TraceArchive,
    windows: &[u32],
    height: u32,
) -> Vec<u32> {
    let plan = plan_shards(archive.cycle_profile(), config);
    plan.shards
        .iter()
        .map(|&(f, count)| match f {
            family::INIT_TEARDOWN => 1,
            family::ZERO_WINDOWS => windows.len() as u32,
            // Always one each, whether or not this execution used them: a
            // count a prover could drop is a way to publish nothing while
            // having published something (`docs/spec/public-values.md` §4).
            family::PUBLIC_INPUT | family::PUBLIC_OUTPUT => 1,
            family::ADVICE_WINDOWS => advice_window_count(archive.advice(), height),
            _ => count,
        })
        .collect()
}

/// The RAM window shard `(family, index)` covers: 0 for `INIT_TEARDOWN`,
/// `windows[index]` for `ZERO_WINDOWS`, the two constants for the public value
/// families, the `index`-th window from the advice origin up for
/// `ADVICE_WINDOWS`, and 0 (unused) for every other family. `height` is the
/// family's own.
fn window_of(family: FamilyId, index: u32, windows: &[u32], height: u32) -> u32 {
    match family {
        family::ZERO_WINDOWS => windows[index as usize],
        family::PUBLIC_INPUT => family::PUBLIC_INPUT_WINDOW,
        family::PUBLIC_OUTPUT => family::PUBLIC_OUTPUT_WINDOW,
        family::ADVICE_WINDOWS => advice_first_window(height) + index,
        _ => 0,
    }
}

/// The statement an archived execution proves: its streams, its exit status
/// (`x10`'s final value), its shard counts and window list, its boundary, and
/// every shard's memory columns, filled by the shard's family.
pub fn statement_inputs(
    setup: &ProverSetup,
    archive: &TraceArchive,
) -> Result<StatementInputs, ProverError> {
    statement_inputs_rec(setup, archive, &mut Recorder::new())
}

/// [`statement_inputs`] recording into `rec`.
#[cfg(feature = "metrics")]
pub fn statement_inputs_metered(
    setup: &ProverSetup,
    archive: &TraceArchive,
    rec: &mut Recorder,
) -> Result<StatementInputs, ProverError> {
    statement_inputs_rec(setup, archive, rec)
}

fn statement_inputs_rec(
    setup: &ProverSetup,
    archive: &TraceArchive,
    rec: &mut Recorder,
) -> Result<StatementInputs, ProverError> {
    let total = rec.start(Stage::StatementColumns);
    let config = &setup.program.config;
    let log = archive.memory_log();
    let h = window_height(config).map_err(|e| ProverError::Trace(e.to_string()))?;
    let windows = init_windows(log, h);
    let counts = shard_counts(config, archive, &windows, h);
    let boundary = build_boundary_finals(log);
    let mut memory_columns = Vec::new();
    for (family, index) in statement_shards(config, &counts) {
        // `M` alone, moved out of the fill: the statement commits nothing else,
        // and asking `shard_columns` for the whole set here counted every
        // channel's multiplicities only to drop them.
        memory_columns.push(shard_memory_columns_rec(
            setup, archive, family, index, &windows, rec,
        )?);
    }
    metric!({
        // The circuits are the setup's, whoever built it: a block metered here
        // did not build its own, and its report would otherwise name no family.
        for f in &setup.families {
            rec.note_family(metrics::family_shape(&f.circuit, f.height));
        }
        let profile = archive.cycle_profile();
        rec.note_program(metrics::ProgramShape {
            code_version: setup.vk.code_version,
            entry_pc: setup.vk.entry_pc,
            bytecode_size_words: config.bytecode_size_words,
            identity: metrics::digest_hex(setup.vk.identity.to_bytes()),
            srs_digest: metrics::digest_hex(setup.vk.srs_digest.to_bytes()),
            families: config.families.clone(),
            cycles: profile.counts.clone(),
            total_cycles: profile.total(),
            shard_counts: counts.clone(),
            windows: windows.clone(),
        });
    });
    rec.end(total);
    let io = archive.io_streams();
    Ok(StatementInputs {
        input: io.input.clone(),
        output: io.output.clone(),
        exit_status: boundary.reg_values[9],
        shard_counts: counts,
        windows,
        boundary,
        memory_columns,
    })
}

/// `[f(x)]_1` of every column, in order, as 64-byte encodings. Parallel over
/// the columns; the order of the result is the order of `columns`.
fn commit_all(srs: &Srs, columns: &[&MultilinearPoly]) -> Vec<[u8; 64]> {
    columns
        .par_iter()
        .map(|c| {
            commit(srs, c)
                .unwrap_or_else(|e| panic!("committing a column: {e:?}"))
                .0
                .to_bytes()
        })
        .collect()
}

/// The global commit phase, `docs/spec/shard-proof.md` §2: every shard's
/// memory columns committed, then the global transcript over the statement.
/// Shard-count generic: `inputs` holds any number of shards per family.
pub fn global_commit_phase(
    vk: &VerifyingKey,
    srs: &Srs,
    inputs: &StatementInputs,
) -> GlobalCommitState {
    global_commit_phase_rec(vk, srs, inputs, &mut Recorder::new())
}

/// [`global_commit_phase`] recording into `rec`: the memory columns' MSMs and
/// the global transcript timed apart, which is the phase's one real split.
#[cfg(feature = "metrics")]
pub fn global_commit_phase_metered(
    vk: &VerifyingKey,
    srs: &Srs,
    inputs: &StatementInputs,
    rec: &mut Recorder,
) -> GlobalCommitState {
    global_commit_phase_rec(vk, srs, inputs, rec)
}

fn global_commit_phase_rec(
    vk: &VerifyingKey,
    srs: &Srs,
    inputs: &StatementInputs,
    rec: &mut Recorder,
) -> GlobalCommitState {
    let total = rec.start(Stage::GlobalCommitTotal);
    let msm = rec.start(Stage::GlobalCommitMsm);
    let memory_commitments: Vec<Vec<[u8; 64]>> = inputs
        .memory_columns
        .iter()
        .map(|columns| commit_all(srs, &columns.iter().collect::<Vec<_>>()))
        .collect();
    rec.end(msm);
    metric!(rec.bytes(
        ByteClass::Commitments,
        64 * memory_commitments.iter().map(Vec::len).sum::<usize>() as u64
    ));
    let statement = PublicInputs {
        input: inputs.input.clone(),
        output: inputs.output.clone(),
        exit_status: inputs.exit_status,
        shard_counts: inputs.shard_counts.clone(),
        windows: inputs.windows.clone(),
        boundary: inputs.boundary,
        memory_commitments,
        memory_roots: Vec::new(),
    };
    let span = rec.start(Stage::GlobalTranscript);
    let global = global_commit(vk, &statement);
    rec.end(span);
    rec.end(total);
    GlobalCommitState {
        statement,
        transcript: global.transcript.snapshot(),
        memory_challenges: global.memory,
        digest: global.digest,
    }
}

/// The statement complete: the global state's, with every shard's two memory
/// roots read from its proof. `proofs` is one per statement shard, in
/// statement order.
pub fn public_inputs(global: &GlobalCommitState, proofs: &[ShardProof]) -> PublicInputs {
    let mut statement = global.statement.clone();
    statement.memory_roots = proofs
        .iter()
        .map(|p| {
            [
                p.outputs[constants::memory::READ_ROOT],
                p.outputs[constants::memory::WRITE_ROOT],
            ]
        })
        .collect();
    statement
}

// ---------------------------------------------------------------------------
// Shards
// ---------------------------------------------------------------------------

/// Everything a shard's proof starts from: the program's setup, and the
/// statement's global commit state. Cross-shard only: one context serves every
/// shard of every family.
pub struct ProvingContext<'a> {
    pub setup: &'a ProverSetup,
    pub global: GlobalCommitState,
}

/// Every committed column of shard `(family, index)` — its `M`, `W` and `S`
/// columns, multiplicities last — as the honest prover fills them: the
/// family's fill over the archive, then `trace::build_multiplicities` over the
/// family's channels.
pub fn shard_columns(
    setup: &ProverSetup,
    archive: &TraceArchive,
    family: FamilyId,
    index: u32,
    windows: &[u32],
) -> Result<Vec<(PolyAddress, MultilinearPoly)>, ProverError> {
    shard_columns_rec(setup, archive, family, index, windows, &mut Recorder::new())
}

/// [`shard_columns`] recording into `rec`. Its sample count against the shard
/// count is how you see that `advance` builds every shard's columns **twice**,
/// once for the GKR phase and once for the opening phase.
#[cfg(feature = "metrics")]
pub fn shard_columns_metered(
    setup: &ProverSetup,
    archive: &TraceArchive,
    family: FamilyId,
    index: u32,
    windows: &[u32],
    rec: &mut Recorder,
) -> Result<Vec<(PolyAddress, MultilinearPoly)>, ProverError> {
    shard_columns_rec(setup, archive, family, index, windows, rec)
}

/// What a family's fill reads for shard `(family, index)`.
fn shard_source<'a>(
    setup: &'a ProverSetup,
    archive: &'a TraceArchive,
    family: FamilyId,
    index: u32,
    windows: &[u32],
) -> ShardSource<'a> {
    ShardSource {
        program: &setup.program,
        archive,
        family,
        index,
        height: setup.registration(family).height as usize,
        window: window_of(family, index, windows, setup.registration(family).height),
    }
}

/// Shard `(family, index)`'s **`M` columns alone**, in layout order, as the
/// statement commits them: the family's fill over the archive, and the memory
/// columns moved out of its result.
///
/// [`shard_columns`] is the whole committed set and counts the channels'
/// multiplicities on top of the fill. **The statement commits `M` and nothing
/// else**, and `build_multiplicities` is about 99% of what `shard_columns`
/// costs — 880 ms against 16 ms for the fill, on one `2^20` shard — so
/// counting them here only to drop them was a third of every block's column
/// building and a tenth of its wall clock. `crates/prover/CLAUDE.md`.
///
/// A multiplicity is a **witness** column by construction
/// (`constraints::lookup` asserts it at every channel), so nothing this drops
/// could have been an `M` column; the loop below panics rather than commit a
/// short list if a family's fill ever disagrees.
pub fn shard_memory_columns(
    setup: &ProverSetup,
    archive: &TraceArchive,
    family: FamilyId,
    index: u32,
    windows: &[u32],
) -> Result<Vec<MultilinearPoly>, ProverError> {
    shard_memory_columns_rec(setup, archive, family, index, windows, &mut Recorder::new())
}

/// [`shard_memory_columns`] recording into `rec`.
#[cfg(feature = "metrics")]
pub fn shard_memory_columns_metered(
    setup: &ProverSetup,
    archive: &TraceArchive,
    family: FamilyId,
    index: u32,
    windows: &[u32],
    rec: &mut Recorder,
) -> Result<Vec<MultilinearPoly>, ProverError> {
    shard_memory_columns_rec(setup, archive, family, index, windows, rec)
}

fn shard_memory_columns_rec(
    setup: &ProverSetup,
    archive: &TraceArchive,
    family: FamilyId,
    index: u32,
    windows: &[u32],
    rec: &mut Recorder,
) -> Result<Vec<MultilinearPoly>, ProverError> {
    let span = rec.start(Stage::StatementShardFill);
    let source = shard_source(setup, archive, family, index, windows);
    let columns = (setup.registration(family).fill)(&source).map_err(ProverError::Trace)?;
    let width = setup.registration(family).circuit.artifact.memory.len();
    let mut memory: Vec<Option<MultilinearPoly>> = (0..width).map(|_| None).collect();
    for (address, column) in columns {
        if let PolyAddress::Memory(i) = address {
            let i = i as usize;
            assert!(
                i < width,
                "shard ({family}, {index}): the fill wrote M[{i}] and the circuit has {width}"
            );
            memory[i] = Some(column);
        }
    }
    let memory: Vec<MultilinearPoly> = memory
        .into_iter()
        .enumerate()
        .map(|(i, column)| {
            column.unwrap_or_else(|| panic!("shard ({family}, {index}): the fill wrote no M[{i}]"))
        })
        .collect();
    rec.end(span);
    metric!(rec.shard_bytes(
        ShardId::new(family, index),
        ByteClass::MemoryColumns,
        metrics::polys_bytes(&memory)
    ));
    Ok(memory)
}

fn shard_columns_rec(
    setup: &ProverSetup,
    archive: &TraceArchive,
    family: FamilyId,
    index: u32,
    windows: &[u32],
    rec: &mut Recorder,
) -> Result<Vec<(PolyAddress, MultilinearPoly)>, ProverError> {
    let total = rec.start(Stage::ShardColumnsTotal);
    let reg = setup.registration(family);
    let source = shard_source(setup, archive, family, index, windows);
    let span = rec.start(Stage::ShardFill);
    let mut columns = (reg.fill)(&source).map_err(ProverError::Trace)?;
    rec.end(span);
    metric!({
        // By address, and without materializing anything: sizing the columns
        // must not itself allocate a copy of them.
        let id = ShardId::new(family, index);
        let of = |want: fn(&PolyAddress) -> bool| -> u64 {
            columns
                .iter()
                .filter(|(a, _)| want(a))
                .map(|(_, c)| metrics::poly_bytes(c))
                .sum()
        };
        rec.shard_bytes(
            id,
            ByteClass::WitnessColumns,
            of(|a| matches!(a, PolyAddress::Witness(_))),
        );
        rec.shard_bytes(
            id,
            ByteClass::SetupColumns,
            of(|a| matches!(a, PolyAddress::Setup(_))),
        );
    });
    let span = rec.start(Stage::ShardMultiplicities);
    let counted = build_multiplicities(&reg.circuit.artifact, &columns, &reg.circuit.channels)
        .map_err(ProverError::Trace)?;
    rec.end(span);
    metric!(rec.shard_bytes(
        ShardId::new(family, index),
        ByteClass::Multiplicities,
        metrics::columns_bytes(&counted)
    ));
    columns.extend(counted);
    rec.end(total);
    Ok(columns)
}

/// The low 64 bits of a field element's canonical encoding. The cycle column
/// holds cycle numbers, so an honest column's entries are far below `2^64`;
/// a tampered one is read as its low bits rather than refused, because the
/// prover checks nothing (S13) and a wrong window is a proof the verifier
/// refuses.
fn low64(v: Fr) -> u64 {
    let b = v.to_bytes();
    u64::from_le_bytes(b[..8].try_into().expect("8 bytes"))
}

/// The shard's claimed time window, `docs/spec/block-proof.md` §4.
///
/// For a **cycle-owning** family it is read off the shard's own `M[0]` cycle
/// column: `[4·cycle(row 0), 4·max cycle + 4)`, the timestamps of the row-0 pc
/// write and one past the last row's last slot (`docs/spec/execution-trace.md`
/// §1, the clock's four slots, and §3, a query's write at `4·cycle + Δ`). Row 0
/// is live in every shard a plan cuts, and padding rows carry cycle 0, so the
/// maximum is the last live row's. The honest prover's window is
/// therefore the one its committed rows say; nothing in the circuit holds it
/// there (§4.1).
///
/// For a **delegation** family it is the same expression over the same column,
/// and means something else: the shard's rows are invocations, each stamped
/// with the cycle that requested it, so the window is the **min and max
/// invocation timestamp** the shard holds (`docs/spec/delegation.md` §8). The
/// block asks nothing of it — no emptiness, no disjointness — because
/// invocations interleave with the cycles that request them and two delegation
/// shards are consecutive invocations, not consecutive times.
///
/// For a family whose rows are words rather than cycles — the two RAM window
/// families — it is [`TRIVIAL_TS_WINDOW`]: such a family owns no part of the
/// execution's time at all, and there is no column to read one off.
fn ts_window(family: FamilyId, base: &BaseLayer) -> [u64; 2] {
    let delegation = program::delegation_frame_words(family).is_some();
    if !constants::family::CYCLE_OWNING[family as usize] && !delegation {
        return TRIVIAL_TS_WINDOW;
    }
    let cycles = base
        .get(PolyAddress::Memory(0))
        .expect("a family with a time window has its cycle column at M[0]");
    let mut top = 0u64;
    for i in 0..cycles.len() {
        top = top.max(low64(cycles.get(i)));
    }
    let ts = |c: u64| c.saturating_mul(constants::memory::TS_STEP);
    [ts(low64(cycles.get(0))), ts(top).saturating_add(4)]
}

/// A shard after its GKR proof: what the opening needs, and the live shard
/// transcript. `docs/spec/shard-proof.md` §10's `PostGkr` entry.
pub(crate) struct ShardGkr {
    pub(crate) family: FamilyId,
    pub(crate) index: u32,
    pub(crate) ts_window: [u64; 2],
    pub(crate) witness_commitments: Vec<[u8; 64]>,
    pub(crate) outputs: Vec<Fr>,
    pub(crate) gkr: GkrProof,
    /// The base claims' one point.
    pub(crate) point: Vec<Fr>,
    pub(crate) transcript: Transcript,
}

impl ProvingContext<'_> {
    /// Shard `(family, index)`'s position in statement order.
    fn position(&self, family: FamilyId, index: u32) -> usize {
        let counts = &self.global.statement.shard_counts;
        statement_shards(&self.setup.vk.config, counts)
            .iter()
            .position(|s| *s == (family, index))
            .unwrap_or_else(|| panic!("the statement has no shard ({family}, {index})"))
    }

    /// The shard's steps up to its opening, `docs/spec/shard-proof.md` §4, S1
    /// to S5: commit the witness columns, seed the transcript, draw the lookup
    /// challenges, run the forward pass and the GKR proof. The base claims'
    /// one point is read back by replaying the schedule over the proof, which
    /// checks nothing: a tampered witness still gets its proof.
    pub(crate) fn gkr_part(
        &self,
        family: FamilyId,
        index: u32,
        base: &BaseLayer,
        rec: &mut Recorder,
    ) -> ShardGkr {
        let total = rec.start(Stage::ShardGkrTotal);
        let reg = self.setup.registration(family);
        let artifact = &reg.circuit.artifact;
        let witness: Vec<&MultilinearPoly> = (0..artifact.witness.len() as u32)
            .map(|i| base.get(PolyAddress::Witness(i)).expect("a witness column"))
            .collect();
        let span = rec.start(Stage::ShardWitnessCommit);
        let witness_commitments = commit_all(&self.setup.srs, &witness);
        rec.end(span);
        metric!(rec.bytes(
            ByteClass::Commitments,
            64 * witness_commitments.len() as u64
        ));
        let span = rec.start(Stage::ShardSeed);
        let ts_window = ts_window(family, base);
        let (mut t, g, beta) = shard_transcript(
            self.global.digest,
            family,
            index,
            ts_window,
            &witness_commitments,
        );
        let challenges = shard_challenges(
            &reg.circuit,
            index,
            &self.global.statement.windows,
            &self.global.memory_challenges,
            g,
            beta,
        );
        rec.end(span);
        let (outputs, gkr, replay_from) = {
            let span = rec.start(Stage::ShardForward);
            let values = forward(artifact, base, &challenges);
            rec.end(span);
            metric!(rec.bytes(
                ByteClass::ForwardLayers,
                metrics::layer_values_bytes(&values)
            ));
            let top = &values.layers[artifact.depth() - 1];
            let outputs: Vec<Fr> = artifact
                .outputs
                .iter()
                .map(|out| match *out {
                    PolyAddress::Inner { offset, .. } => top[offset as usize].get(0),
                    other => panic!("an output is an inner column, not {other}"),
                })
                .collect();
            let replay_from = t.snapshot();
            let span = rec.start(Stage::ShardSumcheck);
            let gkr = prove(artifact, &values, &challenges, &mut t);
            rec.end(span);
            (outputs, gkr, replay_from)
        };
        let span = rec.start(Stage::ShardReplay);
        let (point, replayed) = replay_point(artifact, &gkr, &outputs, &replay_from);
        rec.end(span);
        assert_eq!(
            replayed,
            t.snapshot(),
            "the replayed schedule ends where the prover's transcript does"
        );
        metric!({
            rec.bytes(ByteClass::GkrProof, metrics::gkr_proof_bytes(&gkr));
            rec.note_shard(metrics::ShardShape {
                shard: ShardId::new(family, index),
                height: reg.height,
                ts_window,
                gkr_layers: gkr.layers.len(),
                sumcheck_rounds: gkr.layers.iter().map(|l| l.rounds.len()).sum(),
                final_evals: gkr.layers.iter().map(|l| l.final_evals.len()).sum(),
                witness_commitments: witness_commitments.len(),
                proof_bytes: 0,
            });
        });
        rec.end(total);
        ShardGkr {
            family,
            index,
            ts_window,
            witness_commitments,
            outputs,
            gkr,
            point,
            transcript: t,
        }
    }

    /// The shard's one batched opening, `docs/spec/shard-proof.md` §5 and §4's
    /// S6, and its proof. Returns the proof and the shard transcript's event
    /// log.
    pub(crate) fn opening_part(
        &self,
        shard: ShardGkr,
        base: &BaseLayer,
        rec: &mut Recorder,
    ) -> (ShardProof, Vec<TranscriptEvent>) {
        let total = rec.start(Stage::ShardOpeningTotal);
        let ShardGkr {
            family,
            index,
            ts_window,
            witness_commitments,
            outputs,
            gkr,
            point,
            mut transcript,
        } = shard;
        let reg = self.setup.registration(family);
        let artifact = &reg.circuit.artifact;
        let span = rec.start(Stage::ShardOpeningColumns);
        let columns: Vec<MultilinearPoly> = artifact
            .committed()
            .into_iter()
            .map(|a| base.get(a).expect("a committed column").clone())
            .collect();
        rec.end(span);
        metric!(rec.bytes(ByteClass::OpeningColumns, metrics::polys_bytes(&columns)));
        let family_index = self
            .setup
            .vk
            .config
            .families
            .iter()
            .position(|(f, _)| *f == family)
            .expect("a registered family");
        let mut encoded =
            self.global.statement.memory_commitments[self.position(family, index)].clone();
        encoded.extend_from_slice(&witness_commitments);
        encoded.extend_from_slice(&self.setup.vk.setup_commitments[family_index]);
        if reg.circuit.reads_generic_table() {
            encoded.extend_from_slice(&self.setup.vk.generic_table);
        }
        let span = rec.start(Stage::ShardOpeningDecode);
        let cms: Vec<MercuryCommitment> = encoded
            .iter()
            .map(|b| MercuryCommitment(G1Affine::from_bytes(b).expect("the prover's own point")))
            .collect();
        rec.end(span);
        let span = rec.start(Stage::ShardBatchOpen);
        let (values, mercury) =
            batch_open(&self.setup.srs, &columns, &cms, &point, &mut transcript)
                .unwrap_or_else(|e| panic!("opening shard ({family}, {index}): {e:?}"));
        rec.end(span);
        metric!(rec.bytes(ByteClass::Opening, mercury.to_bytes().len() as u64));
        assert_eq!(
            values, gkr.layers[0].final_evals,
            "the opened values are the base claims"
        );
        let proof = ShardProof {
            family,
            shard_index: index,
            ts_window,
            global_digest: self.global.digest,
            witness_commitments,
            outputs,
            gkr,
            opening: mercury.to_bytes(),
        };
        metric!(rec.note_shard(metrics::ShardShape {
            shard: ShardId::new(family, index),
            height: reg.height,
            ts_window,
            gkr_layers: proof.gkr.layers.len(),
            sumcheck_rounds: proof.gkr.layers.iter().map(|l| l.rounds.len()).sum(),
            final_evals: proof.gkr.layers.iter().map(|l| l.final_evals.len()).sum(),
            witness_commitments: proof.witness_commitments.len(),
            proof_bytes: proof.to_bytes().len(),
        }));
        rec.end(total);
        (proof, transcript.event_log().to_vec())
    }
}

/// The point every base claim of `proof` sits at, and the transcript's state
/// after it: `docs/spec/gkr.md` §5.2's schedule replayed over the proof from
/// `from`, absorbing and squeezing exactly as `gkr::verify` does and checking
/// nothing. Layer 0's transition is row-wise, so the point is its sumcheck's
/// challenges, one per base variable. The prover asserts the state it ends in
/// is its own, which is what holds this copy of the schedule to the engine's.
fn replay_point(
    artifact: &constraints::CircuitArtifact,
    proof: &GkrProof,
    outputs: &[Fr],
    from: &TranscriptSnapshot,
) -> (Vec<Fr>, TranscriptSnapshot) {
    let mut t = Transcript::restore(from);
    t.append_scalars(tags::GKR_OUTPUTS, outputs);
    let top = artifact.layer_vars(artifact.depth());
    let mut point: Vec<Fr> = (0..top)
        .map(|_| t.challenge_scalar(tags::GKR_OUTPUT_POINT))
        .collect();
    for k in (0..artifact.depth()).rev() {
        t.challenge_scalar(tags::GKR_BATCH);
        let layer = &proof.layers[k];
        point = layer
            .rounds
            .iter()
            .map(|round| {
                t.append_scalars(tags::SUMCHECK_ROUND, round);
                t.challenge_scalar(tags::SUMCHECK_CHALLENGE)
            })
            .collect();
        t.append_scalars(tags::GKR_LAYER_CLAIMS, &layer.final_evals);
        if artifact.layers[k].halving {
            point.push(t.challenge_scalar(tags::GKR_CHILD));
        }
    }
    (point, t.snapshot())
}

/// Prove shard `(family, shard_idx)` of the statement `ctx` committed, from
/// the archived execution: the frozen per-shard entry point. Only shard-local
/// steps; the global phase is `global_commit_phase`, whose state `ctx` holds.
pub fn prove_shard(
    ctx: &ProvingContext,
    archive: &TraceArchive,
    family: FamilyId,
    shard_idx: u32,
) -> ShardProof {
    prove_shard_rec(ctx, archive, family, shard_idx, &mut Recorder::new())
}

/// [`prove_shard`] recording into `rec`.
#[cfg(feature = "metrics")]
pub fn prove_shard_metered(
    ctx: &ProvingContext,
    archive: &TraceArchive,
    family: FamilyId,
    shard_idx: u32,
    rec: &mut Recorder,
) -> ShardProof {
    prove_shard_rec(ctx, archive, family, shard_idx, rec)
}

fn prove_shard_rec(
    ctx: &ProvingContext,
    archive: &TraceArchive,
    family: FamilyId,
    shard_idx: u32,
    rec: &mut Recorder,
) -> ShardProof {
    let windows = &ctx.global.statement.windows;
    let columns = shard_columns_rec(ctx.setup, archive, family, shard_idx, windows, rec)
        .unwrap_or_else(|e| panic!("shard ({family}, {shard_idx}): {e}"));
    prove_shard_columns_rec(ctx, family, shard_idx, columns, rec).0
}

/// [`prove_shard`] over columns the caller supplies — the honest ones from
/// [`shard_columns`], or a tampered copy — with the shard transcript's event
/// log. The prover checks nothing about them: a wrong column makes a proof the
/// verifier refuses.
pub fn prove_shard_columns(
    ctx: &ProvingContext,
    family: FamilyId,
    shard_idx: u32,
    columns: Vec<(PolyAddress, MultilinearPoly)>,
) -> (ShardProof, Vec<TranscriptEvent>) {
    prove_shard_columns_rec(ctx, family, shard_idx, columns, &mut Recorder::new())
}

/// [`prove_shard_columns`] recording into `rec`.
#[cfg(feature = "metrics")]
pub fn prove_shard_columns_metered(
    ctx: &ProvingContext,
    family: FamilyId,
    shard_idx: u32,
    columns: Vec<(PolyAddress, MultilinearPoly)>,
    rec: &mut Recorder,
) -> (ShardProof, Vec<TranscriptEvent>) {
    prove_shard_columns_rec(ctx, family, shard_idx, columns, rec)
}

fn prove_shard_columns_rec(
    ctx: &ProvingContext,
    family: FamilyId,
    shard_idx: u32,
    columns: Vec<(PolyAddress, MultilinearPoly)>,
    rec: &mut Recorder,
) -> (ShardProof, Vec<TranscriptEvent>) {
    let span = rec.start(Stage::ShardBaseLayer);
    metric!(rec.shard_bytes(
        ShardId::new(family, shard_idx),
        ByteClass::BaseLayer,
        metrics::columns_bytes(&columns)
    ));
    let base = BaseLayer::new(columns);
    rec.end(span);
    let gkr = ctx.gkr_part(family, shard_idx, &base, rec);
    ctx.opening_part(gkr, &base, rec)
}
