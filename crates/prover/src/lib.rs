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

mod fill;
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
use trace::{build_boundary_finals, build_multiplicities, init_windows, plan_shards, TraceArchive};
use transcript::{Transcript, TranscriptEvent, TranscriptSnapshot};
use verifier_core::{
    global_commit, identity_digest, shard_challenges, shard_transcript, srs_digest,
    statement_shards, window_height, BoundaryFinals, FamilyCircuit, GkrProof, PublicInputs,
    ShardProof, VerifyingKey, VmConfig, TRIVIAL_TS_WINDOW,
};

pub use fill::{family_fill, Fill, ShardSource};
pub use phases::{advance, finish};

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
        let families = register(&program.config)?;
        let setup = setup_commitments(&program.image, &program.tables, &program.config, &srs);
        let setup: Vec<Vec<[u8; 64]>> = setup
            .iter()
            .map(|points| points.iter().map(G1Affine::to_bytes).collect())
            .collect();
        let generic_table = generic_commitments(&srs).map(|p| p.to_bytes());
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
        vk.check().map_err(ProverError::Key)?;
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
/// `ZERO_WINDOWS`, and `ceil(cycles / height)` for every other.
fn shard_counts(config: &VmConfig, archive: &TraceArchive, windows: &[u32]) -> Vec<u32> {
    let plan = plan_shards(archive.cycle_profile(), config);
    plan.shards
        .iter()
        .map(|&(f, count)| match f {
            family::INIT_TEARDOWN => 1,
            family::ZERO_WINDOWS => windows.len() as u32,
            _ => count,
        })
        .collect()
}

/// The RAM window shard `(family, index)` covers: 0 for `INIT_TEARDOWN`,
/// `windows[index]` for `ZERO_WINDOWS`, 0 (unused) for every other family.
fn window_of(family: FamilyId, index: u32, windows: &[u32]) -> u32 {
    match family {
        family::ZERO_WINDOWS => windows[index as usize],
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
    let config = &setup.program.config;
    let log = archive.memory_log();
    let h = window_height(config).map_err(|e| ProverError::Trace(e.to_string()))?;
    let windows = init_windows(log, h);
    let counts = shard_counts(config, archive, &windows);
    let boundary = build_boundary_finals(log);
    let mut memory_columns = Vec::new();
    for (family, index) in statement_shards(config, &counts) {
        let columns = shard_columns(setup, archive, family, index, &windows)?;
        let reg = setup.registration(family);
        let memory = (0..reg.circuit.artifact.memory.len() as u32)
            .map(|i| column_at(&columns, PolyAddress::Memory(i)).clone())
            .collect();
        memory_columns.push(memory);
    }
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

fn column_at(columns: &[(PolyAddress, MultilinearPoly)], address: PolyAddress) -> &MultilinearPoly {
    columns
        .iter()
        .find(|(a, _)| *a == address)
        .map(|(_, c)| c)
        .unwrap_or_else(|| panic!("a shard's columns have no {address}"))
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
    let statement = PublicInputs {
        input: inputs.input.clone(),
        output: inputs.output.clone(),
        exit_status: inputs.exit_status,
        shard_counts: inputs.shard_counts.clone(),
        windows: inputs.windows.clone(),
        boundary: inputs.boundary,
        memory_commitments: inputs
            .memory_columns
            .iter()
            .map(|columns| commit_all(srs, &columns.iter().collect::<Vec<_>>()))
            .collect(),
        memory_roots: Vec::new(),
    };
    let global = global_commit(vk, &statement);
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
    let reg = setup.registration(family);
    let source = ShardSource {
        program: &setup.program,
        archive,
        family,
        index,
        height: reg.height as usize,
        window: window_of(family, index, windows),
    };
    let mut columns = (reg.fill)(&source).map_err(ProverError::Trace)?;
    let counted = build_multiplicities(&reg.circuit.artifact, &columns, &reg.circuit.channels)
        .map_err(ProverError::Trace)?;
    columns.extend(counted);
    Ok(columns)
}

/// A shard after its GKR proof: what the opening needs, and the live shard
/// transcript. `docs/spec/shard-proof.md` §10's `PostGkr` entry.
pub(crate) struct ShardGkr {
    pub(crate) family: FamilyId,
    pub(crate) index: u32,
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
    pub(crate) fn gkr_part(&self, family: FamilyId, index: u32, base: &BaseLayer) -> ShardGkr {
        let reg = self.setup.registration(family);
        let artifact = &reg.circuit.artifact;
        let witness: Vec<&MultilinearPoly> = (0..artifact.witness.len() as u32)
            .map(|i| base.get(PolyAddress::Witness(i)).expect("a witness column"))
            .collect();
        let witness_commitments = commit_all(&self.setup.srs, &witness);
        let (mut t, g, beta) = shard_transcript(
            self.global.digest,
            family,
            index,
            TRIVIAL_TS_WINDOW,
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
        let (outputs, gkr, replay_from) = {
            let values = forward(artifact, base, &challenges);
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
            (
                outputs,
                prove(artifact, &values, &challenges, &mut t),
                replay_from,
            )
        };
        let (point, replayed) = replay_point(artifact, &gkr, &outputs, &replay_from);
        assert_eq!(
            replayed,
            t.snapshot(),
            "the replayed schedule ends where the prover's transcript does"
        );
        ShardGkr {
            family,
            index,
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
    ) -> (ShardProof, Vec<TranscriptEvent>) {
        let ShardGkr {
            family,
            index,
            witness_commitments,
            outputs,
            gkr,
            point,
            mut transcript,
        } = shard;
        let reg = self.setup.registration(family);
        let artifact = &reg.circuit.artifact;
        let columns: Vec<MultilinearPoly> = artifact
            .committed()
            .into_iter()
            .map(|a| base.get(a).expect("a committed column").clone())
            .collect();
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
        let cms: Vec<MercuryCommitment> = encoded
            .iter()
            .map(|b| MercuryCommitment(G1Affine::from_bytes(b).expect("the prover's own point")))
            .collect();
        let (values, mercury) =
            batch_open(&self.setup.srs, &columns, &cms, &point, &mut transcript)
                .unwrap_or_else(|e| panic!("opening shard ({family}, {index}): {e:?}"));
        assert_eq!(
            values, gkr.layers[0].final_evals,
            "the opened values are the base claims"
        );
        let proof = ShardProof {
            family,
            shard_index: index,
            ts_window: TRIVIAL_TS_WINDOW,
            global_digest: self.global.digest,
            witness_commitments,
            outputs,
            gkr,
            opening: mercury.to_bytes(),
        };
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
    let windows = &ctx.global.statement.windows;
    let columns = shard_columns(ctx.setup, archive, family, shard_idx, windows)
        .unwrap_or_else(|e| panic!("shard ({family}, {shard_idx}): {e}"));
    prove_shard_columns(ctx, family, shard_idx, columns).0
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
    let base = BaseLayer::new(columns);
    let gkr = ctx.gkr_part(family, shard_idx, &base);
    ctx.opening_part(gkr, &base)
}
