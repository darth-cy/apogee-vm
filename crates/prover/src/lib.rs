//! The prover: a program's verifying key, the statement an execution proves,
//! the global commit phase, and each shard's proof. `docs/spec/proof.md`
//! specifies what it proves, and `docs/spec/streaming.md` how a block is proved.
//!
//! ```text
//! ProverSetup::new        register every family of the program's VmConfig, build its key
//! prove_block_streaming   one execution as a block, in two passes: how every block is proved
//! statement_inputs        an archive's shard counts, windows and boundary
//! global_commit_phase     run the global transcript over the statement
//! prove_shard             one shard: lookup challenges, GKR
//! public_inputs           the statement, its roots read from the shards' proofs
//! advance                 all of it over an archive, filling its phase sections, resumable
//! ```
//!
//! Every committed column is committed by Akita (`crates/pcs`): the setup
//! columns once, in the key; each shard's `M` columns in the statement, before
//! the memory challenges; its `W` columns in its proof, before its lookup
//! challenges; and all three groups opened at once at the GKR pass's point.
//!
//! The prover checks nothing a verifier does not: a malformed input costs the
//! honest prover a panic or a proof that fails (`docs/spec/gkr.md` §5.1). What
//! it does check is its own program: a trace this prover cannot prove, a family
//! no circuit proves, is refused by name before any work.

/// Emit one debug-log line, in a build with the `debug-info` feature.
///
/// Crate-private and deliberately not `#[macro_export]`ed: a `macro_rules!` at
/// the crate root is textually in scope for every module declared after it,
/// which is all this needs, and exporting it would put it in the public API
/// for nothing.
///
/// Two arms. `dlog!(Level, "…", args)` is a line that belongs to no one family
/// — the block's spine — and `dlog!(Level, family = f, "…", args)` is a line
/// that belongs to family `f`, which `APOGEE_DEBUG=deep:FAMILY` filters on. The
/// second arm spells `family =` rather than taking a bare expression because a
/// string literal is itself an expression, so the two arms would otherwise be
/// ambiguous and every spine line would be read as a family's.
///
/// **The whole expansion is inside the `cfg`**, so with the feature off the
/// format arguments are never evaluated and a scan written as an argument costs
/// nothing.
macro_rules! dlog {
    ($level:ident, family = $family:expr, $($t:tt)*) => {
        #[cfg(feature = "debug-info")]
        {
            if $crate::debug::enabled_for($crate::debug::Level::$level, $family) {
                $crate::debug::line(&format!($($t)*));
            }
        }
    };
    ($level:ident, $($t:tt)*) => {
        #[cfg(feature = "debug-info")]
        {
            if $crate::debug::enabled($crate::debug::Level::$level) {
                $crate::debug::line(&format!($($t)*));
            }
        }
    };
}

/// Run the enclosed statements only in a build with the `debug-info` feature.
///
/// [`dlog!`]'s counterpart, for the same reason: a scan that walks a shard's
/// rows costs something, and a loop that emits one line per family should not
/// run at all in a build that emits none. A single line goes through `dlog!`,
/// which is itself inside the `cfg`; this is for the scans that compute what
/// such a line says.
macro_rules! debug_only {
    ($($t:tt)*) => {
        #[cfg(feature = "debug-info")]
        {
            $($t)*
        }
    };
}

#[cfg(feature = "debug-info")]
pub mod debug;
mod fill;
mod phases;
mod streaming;

use constants::family;
use constants::transcript_tags as tags;
use constraints::PolyAddress;
use field::Fp2;
use gkr::{forward, prove, BaseLayer};
use loader::ProgramImage;
use pcs::{Commitment, Opener, Source};
use poly::MultilinearPoly;
use program::{setup_commitment, setup_openers, DecodedTables, FamilyId};
use rayon::prelude::*;
use trace::{
    advice_window_count, build_boundary_finals, build_multiplicities, init_windows, plan_shards,
    TraceArchive,
};
use transcript::{Transcript, TranscriptEvent, TranscriptSnapshot};
use verifier_core::{
    advice_first_window, committed_groups, global_commit, identity_digest, opening_schedule,
    pcs_setup_len, shard_challenges, shard_transcript, statement_shards, window_height,
    BoundaryFinals, FamilyCircuit, GkrProof, PublicInputs, ShardProof, VerifyingKey, VmConfig,
    TRIVIAL_TS_WINDOW,
};

pub use fill::{family_fill, Fill, ShardRows, ShardSource};
pub use phases::{advance, finish, prove_block};
pub use streaming::{prove_block_streaming, StreamingReport};

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
/// `VmConfig`, its circuit from `VmConfig::circuit`, and the fill that routes
/// its trace buffer into the circuit's columns.
///
/// **The family-registration surface**, `docs/spec/circuits.md` §1 and §2: a
/// family is a circuit in the registry and a fill in [`family_fill`], and adding
/// one changes nothing in `global_commit_phase`, `prove_shard` or the verifier.
#[derive(Clone, Debug)]
pub struct FamilyRegistration {
    pub family: FamilyId,
    pub height: u32,
    pub circuit: FamilyCircuit,
    pub fill: Fill,
}

/// Every family of `config`, registered in its order, or the first one with no
/// circuit at its height or no fill.
pub fn register(config: &VmConfig) -> Result<Vec<FamilyRegistration>, ProverError> {
    config
        .families
        .iter()
        .map(|&(family, height)| {
            let unregistered = ProverError::Unregistered { family, height };
            let circuit = config
                .circuit(family, height.trailing_zeros())
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
/// program, its registered families, its verifying key, and the openers of
/// the key's setup commitments.
pub struct ProverSetup {
    pub program: Program,
    pub families: Vec<FamilyRegistration>,
    pub vk: VerifyingKey,
    /// One per config family, in its order; `None` for a family with no setup
    /// column.
    pub setup_openers: Vec<Option<Opener>>,
}

impl ProverSetup {
    /// Register every family of `program`'s config and build its verifying
    /// key: every circuit, the setup columns' commitments and the identity
    /// that digests them, held to the key's own load rules
    /// (`docs/spec/proof.md` §7.2) before it is returned.
    pub fn new(program: Program) -> Result<ProverSetup, ProverError> {
        let families = register(&program.config)?;
        debug_only!(for f in &families {
            dlog!(
                Detail,
                family = f.family,
                "apogee setup    {:<18} {}",
                debug::family_name(f.family),
                debug::circuit(&f.circuit, f.height)
            );
            // **The output layout, which two conventions read two ways.**
            // `verifier_core::reduce_shard` step 9 takes channel `j`'s root pair
            // at `outputs[2 + 2j]`, counting UP past the two memory roots;
            // `constraints::lookup::channel_cones` takes it at
            // `outputs[len - 2·channels + 2j]`, counting DOWN. They name the
            // same pair exactly when `outputs.len() == 2 + 2·channels`, and
            // nothing central asserts it — `reduce.rs` only checks the length
            // against the artifact's and `check_discharge` only needs `>=`. Every
            // registered circuit satisfies it, and each family's own suite is
            // what pins it. A family whose top layer grew one more output
            // would have the discharge validating one pair and the verifier
            // reading another, and it would surface as `Lookup { channel }` on a
            // channel that is innocent. One integer, printed every run.
            let want = 2 + 2 * f.circuit.channels.len();
            if f.circuit.artifact.outputs.len() != want {
                dlog!(
                    Phase,
                    "apogee setup    {} OUTPUT-LAYOUT-BREAK outputs={} want={want} \
                     (2 memory roots + 2 per channel): reduce_shard step 9 and \
                     constraints::lookup::channel_cones index from opposite ends and \
                     disagree",
                    debug::family_name(f.family),
                    f.circuit.artifact.outputs.len()
                );
            }
        });
        let code_version = program.tables.code_version;
        let circuits: Vec<FamilyCircuit> = families.iter().map(|f| f.circuit.clone()).collect();
        let pcs = pcs::expand_setup(pcs_setup_len(&circuits));
        let setup_openers = setup_openers(&program.image, &program.tables, &circuits, &pcs);
        let setup_commitments: Vec<Commitment> = setup_openers
            .iter()
            .map(|o| setup_commitment(o.as_ref()))
            .collect();
        let vk = VerifyingKey {
            code_version,
            config: program.config.clone(),
            entry_pc: program.image.entry,
            identity: identity_digest(
                code_version,
                &program.config,
                program.image.entry,
                &setup_commitments,
            ),
            setup_commitments,
            circuits,
            pcs,
        };
        vk.check().map_err(ProverError::Key)?;
        // Identity in full, not truncated: it is the value the `verifier` CLI
        // is handed (`docs/tools.md` §6).
        dlog!(
            Phase,
            "apogee setup    key ok families={} entry_pc={:#x} identity={}",
            families.len(),
            program.image.entry,
            debug::hex(&vk.identity.to_bytes())
        );
        Ok(ProverSetup {
            program,
            families,
            vk,
            setup_openers,
        })
    }

    fn registration(&self, family: FamilyId) -> &FamilyRegistration {
        &self.families[self.position(family)]
    }

    /// `family`'s place in the config.
    fn position(&self, family: FamilyId) -> usize {
        self.families
            .iter()
            .position(|f| f.family == family)
            .unwrap_or_else(|| panic!("family {family} is not registered for this program"))
    }

    /// Group `g` — 0, 1, 2 for `M`, `W`, `S` — of a shard's columns, committed
    /// at its family's schedule root, or `None` for an empty group.
    fn commit_group(&self, family: FamilyId, base: &BaseLayer, g: usize) -> Option<Opener> {
        let artifact = &self.registration(family).circuit.artifact;
        let columns = group(artifact, base, g);
        let root = &opening_schedule(artifact).levels[0];
        (!columns.is_empty()).then(|| pcs::commit(&self.vk.pcs.0, root, &Source::Columns(&columns)))
    }
}

/// Group `g` of a shard's committed columns, in address order: what a group's
/// commitment commits and its opening opens.
fn group<'a>(
    artifact: &constraints::CircuitArtifact,
    base: &'a BaseLayer,
    g: usize,
) -> Vec<&'a MultilinearPoly> {
    let address = [
        PolyAddress::Memory,
        PolyAddress::Witness,
        PolyAddress::Setup,
    ][g];
    (0..committed_groups(artifact)[g] as u32)
        .map(|i| {
            base.get(address(i))
                .unwrap_or_else(|| panic!("the shard has no column {}", address(i)))
        })
        .collect()
}

/// An opener's commitment, or the empty one of an empty group.
fn commitment_of(opener: Option<&Opener>) -> Commitment {
    setup_commitment(opener)
}

// ---------------------------------------------------------------------------
// The statement and the global commit phase
// ---------------------------------------------------------------------------

/// What the global commit phase takes: the statement descriptor, the public
/// streams and result, the boundary, and every statement shard's memory
/// commitment.
#[derive(Clone, Debug)]
pub struct StatementInputs {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
    pub exit_status: u32,
    pub shard_counts: Vec<u32>,
    pub windows: Vec<u32>,
    pub boundary: BoundaryFinals,
    /// Per statement shard, in statement order.
    pub memory_commitments: Vec<Commitment>,
}

/// What the global commit phase yields, and every shard's proof starts from:
/// the statement it committed — a `PublicInputs` with no roots yet — the
/// global transcript after its last squeeze, the five memory challenges and
/// the global state digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GlobalCommitState {
    pub statement: PublicInputs,
    pub transcript: TranscriptSnapshot,
    pub memory_challenges: [Fp2; verifier_core::MEMORY_CHALLENGES],
    pub digest: Fp2,
}

/// The shard counts of an execution: one per config family, in its order —
/// exactly one for `INIT_TEARDOWN`, one per touched window above 0 for
/// `ZERO_WINDOWS`, one each for the two public value families, one per advice
/// window the host supplied, and the plan's `ceil(rows / height)` for every
/// other.
pub(crate) fn shard_counts(
    config: &VmConfig,
    profile: &trace::CycleProfile,
    advice: &[u8],
    windows: &[u32],
    height: u32,
) -> Vec<u32> {
    let plan = plan_shards(profile, config);
    plan.shards
        .iter()
        .map(|&(f, count)| match f {
            family::INIT_TEARDOWN => 1,
            family::ZERO_WINDOWS => windows.len() as u32,
            // Always one each, whether or not this execution used them: a
            // count a prover could drop is a way to publish nothing while
            // having published something (`docs/spec/public-values.md` §4).
            family::PUBLIC_INPUT | family::PUBLIC_OUTPUT => 1,
            family::ADVICE_WINDOWS => advice_window_count(advice, height),
            _ => count,
        })
        .collect()
}

/// The window shard `(family, index)` covers: 0 for `INIT_TEARDOWN`,
/// `windows[index]` for `ZERO_WINDOWS`, the two constants for the public value
/// families, the `index`-th window from the advice origin up for
/// `ADVICE_WINDOWS`, and 0 (unused) for every other family. `height` is the
/// family's own.
pub(crate) fn window_of(family: FamilyId, index: u32, windows: &[u32], height: u32) -> u32 {
    match family {
        family::ZERO_WINDOWS => windows[index as usize],
        family::PUBLIC_INPUT => family::PUBLIC_INPUT_WINDOW,
        family::PUBLIC_OUTPUT => family::PUBLIC_OUTPUT_WINDOW,
        family::ADVICE_WINDOWS => advice_first_window(height) + index,
        _ => 0,
    }
}

/// The statement an archived execution proves: its streams, its exit status
/// (`x10`'s final value), its shard counts and window list, and its boundary.
pub fn statement_inputs(
    setup: &ProverSetup,
    archive: &TraceArchive,
) -> Result<StatementInputs, ProverError> {
    let config = &setup.program.config;
    let log = archive.memory_log();
    let h = window_height(config).map_err(|e| ProverError::Trace(e.to_string()))?;
    let windows = init_windows(log.state(), h);
    let counts = shard_counts(
        config,
        archive.cycle_profile(),
        archive.advice(),
        &windows,
        h,
    );
    let boundary = build_boundary_finals(log.state());
    dlog!(
        Phase,
        "apogee stmt     shards={} counts={} windows={:?} input={}B output={}B exit={} cycles={}",
        verifier_core::statement_shards(config, &counts).len(),
        debug::counts(&config.families, &counts),
        windows,
        archive.io_streams().input.len(),
        archive.io_streams().output.len(),
        (boundary.reg_values[9] as u32),
        archive.cycle_profile().total()
    );
    // **A nonzero exit status, on a line of its own.** It is one field among
    // seven on the line above, and a guest that panicked exits 101 having
    // published whatever it had committed so far — a journal that decodes, a
    // proof that verifies, and an answer to a different question. A run whose
    // guest aborted should not need a careful reading of a dense line to say so.
    if (boundary.reg_values[9] as u32) != 0 {
        dlog!(
            Phase,
            "apogee ABORTED  the guest exited {} (x10), journal={}B: this proves an \
             execution that failed, not one that succeeded",
            (boundary.reg_values[9] as u32),
            archive.io_streams().output.len()
        );
    }
    // Every statement shard's `M` columns, filled and committed, each in its
    // own rayon task.
    let shards = statement_shards(config, &counts);
    let memory_commitments = shards
        .par_iter()
        .map(|&(family, index)| {
            let source = shard_source(setup, archive, family, index, &windows)?;
            memory_commitment(setup, family, &source)
        })
        .collect::<Vec<_>>()
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let io = archive.io_streams();
    Ok(StatementInputs {
        input: io.input.clone(),
        output: io.output.clone(),
        exit_status: (boundary.reg_values[9] as u32),
        shard_counts: counts,
        windows,
        boundary,
        memory_commitments,
    })
}

/// The commitment to a shard's `M` columns, from its fill's source: what the
/// global transcript absorbs for it (`docs/spec/proof.md` §2).
pub(crate) fn memory_commitment(
    setup: &ProverSetup,
    family: FamilyId,
    source: &ShardSource,
) -> Result<Commitment, ProverError> {
    let columns = (setup.registration(family).fill)(source).map_err(ProverError::Trace)?;
    Ok(memory_commitment_of(setup, family, columns))
}

/// The commitment to the `M` columns among a shard's `columns`, honest or
/// not: the statement's entry for a shard of these columns.
pub fn memory_commitment_of(
    setup: &ProverSetup,
    family: FamilyId,
    columns: Vec<(PolyAddress, MultilinearPoly)>,
) -> Commitment {
    let memory: Vec<_> = columns
        .into_iter()
        .filter(|(a, _)| matches!(a, PolyAddress::Memory(_)))
        .collect();
    commitment_of(
        setup
            .commit_group(family, &BaseLayer::new(memory), 0)
            .as_ref(),
    )
}

/// The global commit phase, `docs/spec/proof.md` §2: the global transcript
/// over the statement, every shard's memory commitment absorbed before the
/// memory challenges. Shard-count generic: `inputs` holds any number of
/// shards per family.
pub fn global_commit_phase(vk: &VerifyingKey, inputs: &StatementInputs) -> GlobalCommitState {
    let statement = PublicInputs {
        input: inputs.input.clone(),
        output: inputs.output.clone(),
        exit_status: inputs.exit_status,
        shard_counts: inputs.shard_counts.clone(),
        windows: inputs.windows.clone(),
        boundary: inputs.boundary,
        memory_commitments: inputs.memory_commitments.clone(),
        memory_roots: Vec::new(),
    };
    global_commit_of(vk, statement)
}

/// The global transcript, `docs/spec/proof.md` §2, over a statement with no
/// roots yet: the archived path's and the streaming prover's one way into it.
pub(crate) fn global_commit_of(vk: &VerifyingKey, statement: PublicInputs) -> GlobalCommitState {
    let global = global_commit(vk, &statement);
    // The five values every shard's transcript is forked from. Two runs that
    // should have produced one block and did not diverge here or nowhere, which
    // is the first question to ask of any non-determinism: everything
    // downstream is a function of these.
    dlog!(
        Phase,
        "apogee commit   done digest={} memory-challenges={}",
        debug::hex(&global.digest.to_bytes()),
        debug::fp2s(&global.memory, verifier_core::MEMORY_CHALLENGES)
    );
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
    let source = shard_source(setup, archive, family, index, windows)?;
    shard_columns_of(setup, family, &source)
}

/// What a family's fill reads for shard `(family, index)`: the program, the
/// execution's two unbound inputs, and **this shard's rows**, cut out of the
/// archive by `docs/spec/streaming.md` §4's rule.
///
/// Which arm of [`ShardRows`] a family takes: a delegation family takes its
/// cut of its invocations, a family that owns cycles its cut of them, and
/// every other is a window family whose rows are addresses.
fn shard_source<'a>(
    setup: &'a ProverSetup,
    archive: &'a TraceArchive,
    family: FamilyId,
    index: u32,
    windows: &[u32],
) -> Result<ShardSource<'a>, ProverError> {
    let height = setup.registration(family).height;
    ShardSource::archived(
        &setup.program,
        archive,
        family,
        index,
        height,
        window_of(family, index, windows, height),
    )
    .map_err(ProverError::Trace)
}

/// [`shard_columns`] over a source the caller built: the streaming prover's.
pub(crate) fn shard_columns_of(
    setup: &ProverSetup,
    family: FamilyId,
    source: &ShardSource,
) -> Result<Vec<(PolyAddress, MultilinearPoly)>, ProverError> {
    let reg = setup.registration(family);
    let mut columns = (reg.fill)(source).map_err(ProverError::Trace)?;
    let counted = build_multiplicities(&reg.circuit.artifact, &columns, &reg.circuit.channels)
        .map_err(ProverError::Trace)?;
    columns.extend(counted);
    Ok(columns)
}

/// The shard's claimed time window, `docs/spec/proof.md` §8.
///
/// For a **cycle-owning** family it is read off the shard's own `M[0]` cycle
/// column: `[4·cycle(row 0), 4·max cycle + 4)`, the timestamps of the row-0 pc
/// write and one past the last row's last slot (`docs/spec/execution-trace.md`
/// §1, the clock's four slots, and §3, a query's write at `4·cycle + Δ`). Row 0
/// is live in every shard a plan cuts, and padding rows carry cycle 0, so the
/// maximum is the last live row's. The honest prover's window is
/// therefore the one its rows say; nothing in the circuit holds it there
/// (`docs/spec/proof.md` §8).
///
/// For a family whose rows are words rather than cycles — the window
/// families — it is [`TRIVIAL_TS_WINDOW`]: such a family owns no part of the
/// execution's time at all, and there is no column to read one off.
fn ts_window(family: FamilyId, base: &BaseLayer) -> [u64; 2] {
    if !constants::family::CYCLE_OWNING[family as usize] {
        return TRIVIAL_TS_WINDOW;
    }
    let cycles = base
        .get(PolyAddress::Memory(0))
        .expect("a family with a time window has its cycle column at M[0]");
    // A tampered cycle is read as its canonical value rather than refused: the
    // prover checks nothing (`docs/spec/gkr.md` §5.1), and a wrong window is a
    // proof the verifier refuses.
    let cycle = |i: usize| cycles.get_base(i).to_u64();
    let top = (0..cycles.len()).map(cycle).max().unwrap_or(0);
    let ts = |c: u64| c.saturating_mul(constants::memory::TS_STEP);
    [ts(cycle(0)), ts(top).saturating_add(4)]
}

/// A shard after its GKR proof: what its opening needs but its columns, and
/// the live shard transcript. `docs/spec/streaming.md` §6's `PostGkr` entry.
pub(crate) struct ShardGkr {
    pub(crate) family: FamilyId,
    pub(crate) index: u32,
    pub(crate) ts_window: [u64; 2],
    pub(crate) witness_commitment: Commitment,
    pub(crate) outputs: Vec<Fp2>,
    pub(crate) gkr: GkrProof,
    /// The base claims' one point.
    pub(crate) point: Vec<Fp2>,
    pub(crate) transcript: Transcript,
}

impl ProvingContext<'_> {
    /// Shard `(family, index)`'s position in statement order, for the debug log.
    #[cfg(feature = "debug-info")]
    fn position(&self, family: FamilyId, index: u32) -> usize {
        let counts = &self.global.statement.shard_counts;
        verifier_core::statement_shards(&self.setup.vk.config, counts)
            .iter()
            .position(|s| *s == (family, index))
            .unwrap_or_else(|| panic!("the statement has no shard ({family}, {index})"))
    }

    /// The shard's steps, `docs/spec/proof.md` §4: seed the transcript with
    /// the shard's `witness` commitment, draw the lookup challenges, run the
    /// forward pass and the GKR proof. The base claims' one point is read back
    /// by replaying the schedule over the proof, which checks nothing: a
    /// tampered witness still gets its proof.
    pub(crate) fn gkr_part(
        &self,
        family: FamilyId,
        index: u32,
        base: &BaseLayer,
        witness: &Commitment,
    ) -> ShardGkr {
        let reg = self.setup.registration(family);
        let artifact = &reg.circuit.artifact;
        // The begin line, before any work, and **the one line the whole log is
        // built around**: shards are proved concurrently, so a run that is
        // killed, OOMs or hangs leaves its last `begin` without a `done`, and
        // that pair names the shard that died. `docs/tools.md` §3.
        dlog!(
            Phase,
            family = family,
            "apogee shard    {:<22} [{}/{}] begin h={} witness-cols={}",
            debug::shard(family, index),
            self.position(family, index) + 1,
            verifier_core::statement_shards(
                &self.setup.vk.config,
                &self.global.statement.shard_counts
            )
            .len(),
            debug::height(reg.height),
            artifact.witness.len()
        );
        // Declared under the `cfg` and read only inside one, so the default
        // build has neither the binding nor the `Instant::now` behind it.
        #[cfg(feature = "debug-info")]
        let clock = debug::Clock::start();
        let ts_window = ts_window(family, base);
        let (mut t, g, beta) =
            shard_transcript(self.global.digest, family, index, ts_window, witness);
        let challenges = shard_challenges(
            &reg.circuit,
            index,
            &self.global.statement.windows,
            &self.global.memory_challenges,
            g,
            beta,
        );
        dlog!(
            Detail,
            family = family,
            "apogee shard    {:<22} ts={} g={} beta={}",
            debug::shard(family, index),
            debug::ts_window(ts_window),
            debug::fp2(&g),
            debug::fp2(&beta)
        );
        let (outputs, gkr, replay_from) = {
            let values = forward(artifact, base, &challenges);
            // **`self_check` before the backward pass, and only here.** A
            // fill or a circuit the forward pass cannot satisfy is otherwise a
            // proof that fails `verify` with `LayerInconsistency { layer }` —
            // one number, from a verifier that cannot say whose shard it was or
            // what the gate meant. Running it here costs another pass over the
            // shard, which is why it is behind the feature and behind `Detail`,
            // and buys the gate list, the row, the relation's name and every
            // value that relation read (`gkr::explain_self_check`).
            debug_only!(if debug::enabled_for(debug::Level::Detail, family) {
                let who = debug::shard(family, index);
                let checked = debug::Clock::start();
                match gkr::self_check(artifact, &values, &challenges) {
                    Ok(()) => debug::line(&format!(
                        "apogee gkr      {who:<22} self_check ok layers={} ms={}",
                        artifact.depth(),
                        checked.ms()
                    )),
                    Err(failure) => {
                        // At `Phase`, not `Detail`: a reader who asked for the
                        // skeleton and got a failed self-check wants the whole
                        // explanation, not a hint that one exists.
                        debug::line(&format!(
                            "apogee gkr      {who:<22} self_check FAILED layer={} row={} relation={}",
                            failure.layer, failure.row, failure.relation
                        ));
                        for text in
                            gkr::explain_self_check(artifact, &values, &challenges, &failure)
                        {
                            debug::line(&format!("apogee gkr      {who:<22}   {text}"));
                        }
                    }
                }
            });
            // Per layer: the width the forward pass wrote, and whether the
            // layer is row-wise or halving. A layer whose columns are all zero
            // is a fill that wrote nothing into the cone below it, and a
            // reader who has the failing layer's number from `self_check`
            // reads its shape off this.
            debug_only!(if debug::enabled_for(debug::Level::Deep, family) {
                let who = debug::shard(family, index);
                // Per layer: the shape the forward pass wrote, and the bytes it
                // is holding. **No per-cell scan here.** Sweeping every column
                // of every layer for an all-zero test is ~90M `MultilinearPoly::get` calls on
                // one shard — it would make `deep` change what it is measuring,
                // which is the one thing a debugging aid may not do. The top
                // layer alone gets that test, below, where it is a handful of
                // columns and where an all-zero column is a root of 0.
                let mut cumulative = 0u64;
                for (k, columns) in values.layers.iter().enumerate() {
                    let list = &artifact.layers[k];
                    let bytes = columns.len() as u64 * (1u64 << list.num_vars) * 32;
                    cumulative += bytes;
                    debug::line(&format!(
                        "apogee gkr      {who:<22} layer {}/{} vars={} width={} {} {:.2} GiB \
                         cumulative {:.2} GiB",
                        k + 1,
                        artifact.depth(),
                        list.num_vars,
                        columns.len(),
                        if list.halving { "halving" } else { "row-wise" },
                        bytes as f64 / (1u64 << 30) as f64,
                        cumulative as f64 / (1u64 << 30) as f64,
                    ));
                }
                // The top layer, cell by cell: its columns are the outputs, so
                // an all-zero one is a root of 0 — a channel or a memory side
                // that proved nothing — and there are a handful of them.
                if let Some(top) = values.layers.last() {
                    let zero: Vec<usize> = top
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| debug::all_zero(c))
                        .map(|(i, _)| i)
                        .collect();
                    if !zero.is_empty() {
                        debug::line(&format!(
                            "apogee gkr      {who:<22} top layer columns {zero:?} are ALL ZERO \
                             -- a root of 0 proves nothing"
                        ));
                    }
                }
            });
            let top = &values.layers[artifact.depth() - 1];
            let outputs: Vec<Fp2> = artifact
                .outputs
                .iter()
                .map(|out| match *out {
                    PolyAddress::Inner { offset, .. } => top[offset as usize].get(0),
                    other => panic!("an output is an inner column, not {other}"),
                })
                .collect();
            let replay_from = t.snapshot();
            let gkr = prove(artifact, &values, &challenges, &mut t);
            (outputs, gkr, replay_from)
        };
        let (point, replayed) = replay_point(artifact, &gkr, &outputs, &replay_from);
        assert_eq!(
            replayed,
            t.snapshot(),
            "the replayed schedule ends where the prover's transcript does"
        );
        // The GKR output roots, which are what `verify_shard_local` step 10a
        // holds against the statement and what the block's cross-shard product
        // multiplies. A root of 0 or 1 where the circuit computes a fraction
        // tree is the visible end of a channel that proved nothing.
        dlog!(
            Detail,
            family = family,
            "apogee shard    {:<22} outputs={} read_root={} write_root={}",
            debug::shard(family, index),
            outputs.len(),
            debug::fp2(&outputs[constants::memory::READ_ROOT]),
            debug::fp2(&outputs[constants::memory::WRITE_ROOT])
        );
        dlog!(
            Phase,
            family = family,
            "apogee shard    {:<22} gkr done layers={} rounds={} ms={}",
            debug::shard(family, index),
            gkr.layers.len(),
            gkr.layers.iter().map(|l| l.rounds.len()).sum::<usize>(),
            clock.ms()
        );
        ShardGkr {
            family,
            index,
            ts_window,
            witness_commitment: witness.clone(),
            outputs,
            gkr,
            point,
            transcript: t,
        }
    }

    /// The shard's proof, and the shard transcript's event log: the shard's
    /// one opening (`docs/spec/proof.md` §5) — every committed column, `M`,
    /// `W` and `S` in layout order, opened at `point` in the live shard
    /// transcript — from its columns `base` and the openers of its `memory`
    /// and `witness` commitments; the setup's are the key's.
    pub(crate) fn proof_part(
        &self,
        shard: ShardGkr,
        base: &BaseLayer,
        memory: Option<&Opener>,
        witness: Option<&Opener>,
    ) -> (ShardProof, Vec<TranscriptEvent>) {
        let ShardGkr {
            family,
            index,
            ts_window,
            witness_commitment,
            outputs,
            gkr,
            point,
            mut transcript,
        } = shard;
        let artifact = &self.setup.registration(family).circuit.artifact;
        let setup = self.setup.setup_openers[self.setup.position(family)].as_ref();
        let columns: [Vec<&MultilinearPoly>; 3] =
            core::array::from_fn(|g| group(artifact, base, g));
        let groups: Vec<(&Opener, Source)> = [memory, witness, setup]
            .into_iter()
            .zip(&columns)
            .filter_map(|(opener, columns)| {
                assert_eq!(
                    opener.is_some(),
                    !columns.is_empty(),
                    "an opener per nonempty group"
                );
                opener.map(|o| (o, Source::Columns(columns)))
            })
            .collect();
        // Layer 0 is row-wise, so its final evaluations are the base claims, one
        // per committed column in layout order (`gkr_verify::verify`).
        let values = &gkr.layers[0].final_evals;
        let opening = pcs::open(
            &mut transcript,
            &self.setup.vk.pcs.0,
            &groups,
            &point,
            values,
        );
        let proof = ShardProof {
            family,
            shard_index: index,
            ts_window,
            global_digest: self.global.digest,
            witness_commitment,
            outputs,
            gkr,
            opening,
        };
        dlog!(
            Phase,
            family = family,
            "apogee shard    {:<22} done bytes={}",
            debug::shard(proof.family, proof.shard_index),
            proof.to_bytes().len()
        );
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
    outputs: &[Fp2],
    from: &TranscriptSnapshot,
) -> (Vec<Fp2>, TranscriptSnapshot) {
    let mut t = Transcript::restore(from);
    t.append_ext(tags::GKR_OUTPUTS, outputs);
    let mut point: Vec<Fp2> = Vec::new();
    for k in (0..artifact.depth()).rev() {
        t.challenge(tags::GKR_BATCH);
        let layer = &proof.layers[k];
        point = layer
            .rounds
            .iter()
            .map(|round| {
                t.append_ext(tags::SUMCHECK_ROUND, round);
                t.challenge(tags::SUMCHECK_CHALLENGE)
            })
            .collect();
        t.append_ext(tags::GKR_LAYER_CLAIMS, &layer.final_evals);
        if artifact.layers[k].halving {
            point.push(t.challenge(tags::GKR_CHILD));
        }
    }
    (point, t.snapshot())
}

/// Prove shard `(family, shard_idx)` of the statement `ctx` committed, from
/// the archived execution: the per-shard entry point. Only shard-local
/// steps; the global phase is `global_commit_phase`, whose state `ctx` holds.
pub fn prove_shard(
    ctx: &ProvingContext,
    archive: &TraceArchive,
    family: FamilyId,
    shard_idx: u32,
) -> ShardProof {
    let windows = &ctx.global.statement.windows;
    let columns = shard_columns(ctx.setup, archive, family, shard_idx, windows)
        .unwrap_or_else(|e| panic!("shard ({family}, {shard_idx}): {e}"));
    prove_shard_columns(ctx, family, shard_idx, columns).0
}

/// [`prove_shard`] over columns the caller supplies — the honest ones from
/// [`shard_columns`], or a tampered copy — with the shard transcript's event
/// log. The prover checks nothing about them: a wrong column makes a proof the
/// verifier refuses, a wrong `M` column one whose opening fails against the
/// statement's commitment.
pub fn prove_shard_columns(
    ctx: &ProvingContext,
    family: FamilyId,
    shard_idx: u32,
    columns: Vec<(PolyAddress, MultilinearPoly)>,
) -> (ShardProof, Vec<TranscriptEvent>) {
    let base = BaseLayer::new(columns);
    let memory = ctx.setup.commit_group(family, &base, 0);
    let witness = ctx.setup.commit_group(family, &base, 1);
    let gkr = ctx.gkr_part(family, shard_idx, &base, &commitment_of(witness.as_ref()));
    ctx.proof_part(gkr, &base, memory.as_ref(), witness.as_ref())
}
