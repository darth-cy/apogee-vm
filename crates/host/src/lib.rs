//! The host SDK: a guest ELF and its inputs in, a `BlockProof` out, and the
//! witness recorder that produces a real Ethereum block's `BlockWitness`.
//!
//! `prompts/00-master.md`'s projected workspace layout froze this crate's name
//! and its charter — *"host SDK: prove/verify API, input building, witness
//! recorder"* — and S25 fills it in.
//!
//! # What is here, and what is not
//!
//! [`prove`] and [`verify`] are **convenience wrappers and nothing more**.
//! `prover::prove_block` and `verifier::verify_block` remain the protocol entry
//! points and every test still calls them; what these two save a caller is the
//! eight-step preamble that every end-to-end path in this repository writes out
//! by hand today. Master rule 6's verifier signature discipline holds exactly:
//! [`verify`] takes `(&VerifyingKey, &BlockProof)` and reads the statement out
//! of the proof, which is what `verifier::verify_block`'s own callers already
//! do. It adds nothing to the verifier's inputs — there is no witness, no
//! trace, no prover state, and no second copy of the statement to disagree with
//! the first.
//!
//! [`prove`] does add one thing, and it is a measurement rather than an input:
//! it times `emulator::trace_run` and hands the elapsed nanoseconds to
//! `TraceArchive::from_execution`. S12 froze a per-phase timing field on the
//! archive's post-execution section and **every caller in the repository passed
//! zero**, because nothing timed the executor. S25's must-be-exact 5 requires
//! the bench report's per-stage timings to come from those sections rather than
//! from stopwatches sprinkled through the prover, so the execution phase's
//! number has to be real. It is measured here, in the one place that runs the
//! executor on the proving path.
//!
//! # The modules
//!
//! - [`rpc`] — the minimal JSON-RPC client and its content-addressed cache.
//!   Manual paths only; CI never reaches it.
//! - [`recorder`] — [`recorder::WitnessRecorder`], which pre-executes a block's
//!   transactions with native revm against an RPC-backed database, harvests the
//!   touch set, and emits the `BlockWitness` the guest reads as advice.
//! - [`fixture`] — what a recorded block is on disk, and how it is pinned.

pub mod fixture;
pub mod recorder;
pub mod rpc;

use std::time::Instant;

use emulator::GuestIo;
use loader::load_elf;
use program::{decode_program, ProgramParams};
use prover::{Program, ProverSetup};
use srs::Srs;
use trace::{IoStreams, PhaseTiming, TraceArchive};
use verifier_core::{BlockProof, VerifyError, VerifyingKey};

/// Everything one proving run produced, beside the proof itself.
///
/// The archive is returned rather than dropped because it is where the
/// per-phase wall-clock lives: `tools/bench` reads `archive.timing(phase)` for
/// the execution, commit, GKR and opening numbers, which is the source
/// must-be-exact 5 names. The proof does not carry them and never should — a
/// timing is not evidence.
pub struct Proven {
    /// The block proof, which carries its own statement and `VmConfig`.
    pub block: BlockProof,
    /// The archive the block was proved from, with all five phases filled.
    pub archive: TraceArchive,
    /// The guest's exit status, which is `x10`'s final value.
    pub exit_code: i32,
    /// Cycles the execution took, as `emulator::Execution::cycle_count`
    /// reports them.
    pub cycles: u64,
    /// The journal, which is also `block.statement().output`.
    pub journal: Vec<u8>,
    /// Wall-clock of the whole call, executor included.
    pub wall_nanos: u64,
}

/// A guest ELF and the heights it is preprocessed under, as a `ProverSetup`.
///
/// This is steps 1 to 4 of the path `crates/prover`'s module documentation
/// describes. The SRS is moved in: a `ProverSetup` owns it for the run.
pub fn setup(elf: &[u8], params: &ProgramParams, srs: Srs) -> Result<ProverSetup, String> {
    let image = load_elf(elf).map_err(|e| format!("the guest ELF does not load: {e:?}"))?;
    let (tables, config) =
        decode_program(&image, params).map_err(|e| format!("the guest does not decode: {e}"))?;
    ProverSetup::new(
        Program {
            image,
            tables,
            config,
        },
        srs,
    )
    .map_err(|e| format!("the program does not register: {e:?}"))
}

/// Execute the guest over `io`, then prove the block.
///
/// Steps 5 to 8: trace, archive, plan, `prover::prove_block`. A guest whose run
/// is fatal — a misaligned access, a read outside the addressable window, a
/// journal past its window — returns the executor's error and no proof, which
/// is the executor's contract and not this function's choice.
///
/// The exit status is **not** checked here. A failing guest is still a provable
/// execution and its journal is still bound; whether exit 0 was required is the
/// caller's statement to make, and `Proven::exit_code` is how it makes it.
pub fn prove(setup: &ProverSetup, io: &GuestIo) -> Result<Proven, String> {
    let started = Instant::now();
    let (traces, log, profile, execution) = emulator::trace_run(
        &setup.program.image,
        io,
        &setup.program.tables,
        &setup.program.config,
    )
    .map_err(|e| format!("the guest run is fatal: {e:?}"))?;
    // The executor is the first thing this function does, so the elapsed
    // time here is the execution phase's and nothing else's.
    let execution_nanos = started.elapsed().as_nanos() as u64;

    let exit_code = execution.exit_code;
    let cycles = execution.cycle_count;
    let journal = execution.io.output.clone();
    let mut archive = TraceArchive::from_execution(
        traces,
        log,
        profile,
        IoStreams {
            input: execution.io.input,
            output: execution.io.output,
        },
        io.advice.clone(),
        PhaseTiming {
            wall_nanos: execution_nanos,
        },
    );
    let plan = trace::plan_shards(archive.cycle_profile(), &setup.program.config);
    let block = prover::prove_block(setup, &mut archive, &plan)
        .map_err(|e| format!("the block does not prove: {e:?}"))?;
    Ok(Proven {
        block,
        archive,
        exit_code,
        cycles,
        journal,
        wall_nanos: started.elapsed().as_nanos() as u64,
    })
}

/// `verifier::verify_block`, with the statement read out of the proof.
///
/// The one verification path, unchanged: this is a two-line call into
/// `verifier::verify_block(vk, block, block.statement())`, which is what every
/// caller of that function in this repository already writes. It exists so that
/// a host-side caller cannot accidentally pass a statement that is not the
/// proof's — `verify_block`'s own check 1 refuses that with
/// `VerifyError::Statement`, so the mistake is caught either way, but a wrapper
/// that cannot make it is better than an error that names it.
///
/// **Identity is not checked here and cannot be.** A key recomputes its own
/// identity when it loads, so it is not its own authority for it: what makes a
/// proof a proof *of a particular program* is `vk.identity.to_bytes()` compared
/// against a value from a channel the prover does not control. That is one
/// comparison and the caller writes it, exactly as the `verifier` CLI makes it
/// a separate argument.
pub fn verify(vk: &VerifyingKey, block: &BlockProof) -> Result<(), VerifyError> {
    verifier::verify_block(vk, block, block.statement())
}
