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
//! `prover::prove_block_streaming` and `verifier::verify_block` remain the
//! protocol entry points and every test still calls them; what these two save a
//! caller is the preamble that every end-to-end path in this repository writes
//! out by hand. Master rule 6's verifier signature discipline holds exactly:
//! [`verify`] takes `(&VerifyingKey, &BlockProof)` and reads the statement out
//! of the proof, which is what `verifier::verify_block`'s own callers already
//! do. It adds nothing to the verifier's inputs — there is no witness, no
//! trace, no prover state, and no second copy of the statement to disagree with
//! the first.
//!
//! # **Streaming is the only proving path** (S-STREAM)
//!
//! [`prove`] calls `prover::prove_block_streaming` and nothing else. The
//! archived path — `prover::prove_block` over a `TraceArchive` — still compiles
//! and is still what `checker`'s column-fill suites and the tamper harness
//! build their columns from, but **nothing proves through it**, here or
//! anywhere (`docs/spec/streaming.md` §1). Two consequences a caller sees:
//!
//! - `max_in_flight` is an argument. It is the backpressure that bounds the
//!   peak, and the caller is the only one that knows the machine.
//! - **There is no archive to return**, so there are no per-phase section
//!   clocks either. [`Proven::report`] carries the streaming run's own four
//!   clocks instead, and they are *sums of disjoint intervals* — execution and
//!   proving interleave, and the guest is executed twice. A reader comparing
//!   one against a pre-S-STREAM archived number is comparing two different
//!   quantities.
//!
//! The guest's execution is no longer timed separately here. It does not need
//! to be: `StreamingReport`'s `pass1_execute_ns` and `pass2_execute_ns` are
//! measured inside the prover, around the executor itself, which is a tighter
//! interval than this function could take.
//!
//! # The modules
//!
//! - [`proof_archive`] — the four files a proved block leaves on disk, which
//!   are exactly what the `verifier` CLI reads back. **The proof is the only
//!   thing a proving run archives.** It is `verifier::proof_archive`,
//!   re-exported: the format's reader is the CLI, so its writer lives beside
//!   the reader and there is one definition of it.
//! - [`rpc`] — the minimal JSON-RPC client and its content-addressed cache.
//!   Manual paths only; CI never reaches it.
//! - [`recorder`] — [`recorder::WitnessRecorder`], which pre-executes a block's
//!   transactions with native revm against an RPC-backed database, harvests the
//!   touch set, and emits the `BlockWitness` the guest reads as advice.
//! - [`fixture`] — what a recorded block is on disk, and how it is pinned.
//! - [`canonical`] — JSON-RPC objects back to the bytes the chain hashes:
//!   headers, transactions, withdrawals and receipts.
//! - [`zkevm`] — a `tests-zkevm` release on disk: its stateless input/output
//!   pairs, and the verdict the stateless guest gives each.

pub mod canonical;
pub mod fixture;
pub mod recorder;
pub mod rpc;
pub mod zkevm;

pub use verifier::proof_archive;

use std::time::Instant;

use emulator::GuestIo;
use loader::load_elf;
use program::{decode_program, ProgramParams};
use prover::{Program, ProverSetup, StreamingReport};
use srs::Srs;
use verifier_core::{BlockProof, VerifyError, VerifyingKey};

/// Everything one proving run produced, beside the proof itself.
///
/// All of it is a measurement, and none of it is evidence: the block is
/// byte-identical whatever this says, and nothing in a proof reads it.
pub struct Proven {
    /// The block proof, which carries its own statement and `VmConfig`.
    pub block: BlockProof,
    /// What the streaming run measured about itself: the four clocks, the
    /// shard count, and the largest batch it proved at once.
    pub report: StreamingReport,
    /// The guest's exit status, which is `x10`'s final value.
    pub exit_code: i32,
    /// Cycles the execution took.
    pub cycles: u64,
    /// The journal, which is also `block.statement().output`.
    pub journal: Vec<u8>,
    /// Wall-clock of the whole call, both executions included.
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

/// Execute the guest over `io` and prove the block, streaming.
///
/// One call into `prover::prove_block_streaming`, which executes the guest
/// twice — once to commit each shard's memory columns as it fills, once to
/// prove them — and never proves more than `max_in_flight` shards at once.
/// `max_in_flight` must be at least 1; `docs/spec/streaming.md` §5 is what it
/// bounds and why the caller chooses it.
///
/// A guest whose run is fatal — a misaligned access, a read outside the
/// addressable window, a journal past its window — returns the executor's
/// error and no proof, which is the executor's contract and not this
/// function's choice.
///
/// The exit status is **not** checked here. A failing guest is still a provable
/// execution and its journal is still bound; whether exit 0 was required is the
/// caller's statement to make, and `Proven::exit_code` is how it makes it.
pub fn prove(setup: &ProverSetup, io: &GuestIo, max_in_flight: usize) -> Result<Proven, String> {
    let started = Instant::now();
    let (block, report) = prover::prove_block_streaming(setup, io, max_in_flight)
        .map_err(|e| format!("the block does not prove: {e:?}"))?;
    // The statement is where the execution's own facts live now: there is no
    // `Execution` to read them off, and these are the values the proof binds
    // rather than a second reading of them.
    // `x10`'s final value, which the statement carries as a `u32` and the
    // executor reported as an `i32`: the same 32 bits, and `exit(-1)` has to
    // read back as `-1` here as it did before.
    let exit_code = block.statement().exit_status as i32;
    let journal = block.statement().output.clone();
    Ok(Proven {
        block,
        cycles: report.cycles,
        report,
        exit_code,
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
