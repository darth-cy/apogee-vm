//! The host SDK: what a caller outside the proving stack uses.
//!
//! Three things, and deliberately no more:
//!
//! - [`WitnessRecorder`], which turns a mainnet block and a transaction range
//!   into a [`revm_block::BlockWitness`] by executing it once with native revm
//!   against an RPC-backed database and harvesting the touch-set;
//! - [`rpc`], the minimal JSON-RPC client that feeds it, with a
//!   content-addressed cache in front so that everything downstream of a
//!   refresh runs offline;
//! - [`prove`] and [`verify`], two convenience wrappers around S20's entry
//!   points.
//!
//! # What the wrappers are, and what they are not
//!
//! `prover::prove_block` and `verifier::verify_block` remain **the** protocol
//! entry points, and [`verify`] is `verifier::verify_block` with its arguments
//! unchanged: `(&VerifyingKey, &BlockProof, &PublicInputs)` and nothing else.
//! Master rule 6 is a rule about the verifier's inputs, and a wrapper that
//! added one — a witness, an expected digest, a policy — would be a second
//! verification path wearing the first one's name. So it adds none.
//!
//! [`prove`] is the other half of the same discipline: it is the three calls
//! every proving test already makes, in the one order they may be made, with
//! the execution phase's wall clock actually measured. That last part is not
//! cosmetic — `docs/spec/metrics.md` and S25's must-be-exact 5 read the
//! per-phase timings out of the archive, and every caller in the repository
//! before this one filled the execution phase's with a literal 0.

pub mod json;
pub mod recorder;
pub mod rpc;

pub use recorder::{Job, Recording, WitnessRecorder};
pub use rpc::Rpc;

use std::time::Instant;

use emulator::{trace_run, GuestIo};
use prover::{prove_block, Program, ProverSetup};
use trace::{plan_shards, IoStreams, PhaseTiming, TraceArchive};
use verifier::{BlockProof, PublicInputs, VerifyError, VerifyingKey};

/// Trace `setup`'s program on `input` and `hint`, then prove the block.
///
/// Returns the proof and the archive it was proved from. The archive is the
/// second half of the answer on purpose: it carries the cycle profile, the
/// fd 0 and fd 1 streams and the five per-phase wall clocks, which is
/// everything `tools/bench`'s report needs and everything a resumed run needs.
///
/// The execution phase's timing is measured here. Nothing else in the
/// repository measures it: `TraceArchive::from_execution` takes a
/// [`PhaseTiming`] from its caller, and every caller before this one was a
/// test passing 0.
pub fn prove(
    setup: &ProverSetup,
    input: &[u8],
    hint: &[u8],
) -> Result<(BlockProof, TraceArchive), String> {
    let mut archive = execute(&setup.program, input, hint)?;
    let plan = plan_shards(archive.cycle_profile(), &setup.program.config);
    let proof = prove_block(setup, &mut archive, &plan).map_err(|e| format!("{e:?}"))?;
    Ok((proof, archive))
}

/// Run `program` on `input` and `hint` and snapshot it as a post-execution
/// archive, with the execution's wall clock in the phase's timing field.
///
/// A nonzero exit status is **not** an error here: a guest that exits 62 has
/// executed, and proving that it did is a statement about the program as much
/// as a clean exit is. The caller reads the status out of the archive's
/// statement.
pub fn execute(program: &Program, input: &[u8], hint: &[u8]) -> Result<TraceArchive, String> {
    let io = GuestIo {
        input: input.to_vec(),
        hint: hint.to_vec(),
        advice: Vec::new(),
    };
    let started = Instant::now();
    let (traces, log, profile, execution) =
        trace_run(&program.image, &io, &program.tables, &program.config)
            .map_err(|e| format!("host: the guest did not run: {e:?}"))?;
    let wall_nanos = started.elapsed().as_nanos() as u64;
    Ok(TraceArchive::from_execution(
        traces,
        log,
        profile,
        IoStreams {
            input: execution.io.input,
            output: execution.io.output,
        },
        PhaseTiming { wall_nanos },
    ))
}

/// Verify a block. This is `verifier::verify_block`, and its arguments are
/// that function's, unchanged.
pub fn verify(
    vk: &VerifyingKey,
    proof: &BlockProof,
    public: &PublicInputs,
) -> Result<(), VerifyError> {
    verifier::verify_block(vk, proof, public)
}
