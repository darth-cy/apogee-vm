//! The host SDK: a guest ELF and its inputs in, a `BlockProof` out.
//!
//! **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** A block this
//! SDK proves binds none of its columns, so one that [`verify`] accepts is
//! **UNSOUND** evidence of the execution until a commitment scheme fills the
//! voids marked `UNFINISHED` (`docs/architecture.md` §0).
//!
//! # What is here, and what is not
//!
//! [`prove`] and [`verify`] are **convenience wrappers and nothing more**.
//! `prover::prove_block_streaming` and `verifier::verify_block` remain the
//! protocol entry points and every test calls them; what these two save a
//! caller is the preamble that every end-to-end path in this repository writes
//! out by hand. The verifier's `(key, proof, public inputs)` signature holds
//! exactly: [`verify`] takes `(&VerifyingKey, &BlockProof)` and reads the
//! statement out of the proof, which is what `verifier::verify_block`'s own
//! callers already do. It adds nothing to the verifier's inputs — there is no
//! witness, no trace, no prover state, and no second copy of the statement to
//! disagree with the first.
//!
//! # **Streaming is the only proving path**
//!
//! [`prove`] calls `prover::prove_block_streaming` and nothing else. The
//! archived path — `prover::prove_block` over a `TraceArchive` — compiles and
//! is what `checker`'s column-fill suites and the tamper harness build their
//! columns from, but **nothing proves through it**, here or anywhere
//! (`docs/spec/streaming.md` §6). Two consequences a caller sees:
//!
//! - `max_in_flight` is an argument. It is the backpressure that bounds the
//!   peak — the prover's worker count, each worker holding one shard at a
//!   time — and the caller is the only one that knows the machine.
//! - **There is no archive to return**, so there are no per-phase section
//!   clocks either. [`Proven::report`] carries the streaming run's own clocks
//!   instead: one wall clock per pass, and the executor's time inside each.
//!   The guest is stepped by whichever worker needs the next shard while the
//!   others prove theirs, so the executor's time overlaps the rest and is not
//!   a slice of the wall.
//!
//! The guest's execution is not timed separately here. It does not need
//! to be: `StreamingReport`'s `pass1_execute_ns` and `pass2_execute_ns` are
//! measured inside the prover, around the executor itself, which is a tighter
//! interval than this function could take.
//!
//! # The proof archive
//!
//! [`proof_archive`] is the four files a proved block leaves on disk, which are
//! exactly what the `verifier` CLI reads back. **The proof is the only thing a
//! proving run archives.** It is `verifier::proof_archive`, re-exported: the
//! format's reader is the CLI, so its writer lives beside the reader and there
//! is one definition of it.

pub use verifier::proof_archive;

use std::time::Instant;

use emulator::GuestIo;
use loader::load_elf;
use program::{decode_program, ProgramParams};
use prover::{Program, ProverSetup, StreamingReport};
use verifier_core::{BlockProof, VerifyError, VerifyingKey};

/// Everything one proving run produced, beside the proof itself.
///
/// All of it is a measurement, and none of it is evidence: the block is
/// byte-identical whatever this says, and nothing in a proof reads it.
pub struct Proven {
    /// The block proof, which carries its own statement and `VmConfig`.
    pub block: BlockProof,
    /// What the streaming run measured about itself: the two passes' wall
    /// clocks and the executor's time in each, the shard count, and the most
    /// shards it held at once.
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
/// describes.
pub fn setup(elf: &[u8], params: &ProgramParams) -> Result<ProverSetup, String> {
    let image = load_elf(elf).map_err(|e| format!("the guest ELF does not load: {e:?}"))?;
    let (tables, config) =
        decode_program(&image, params).map_err(|e| format!("the guest does not decode: {e}"))?;
    ProverSetup::new(Program {
        image,
        tables,
        config,
    })
    .map_err(|e| format!("the program does not register: {e:?}"))
}

/// Execute the guest over `io` and prove the block, streaming.
///
/// One call into `prover::prove_block_streaming`, which executes the guest
/// twice — once to its statement, once to prove each shard as it fills — and
/// never holds more than `max_in_flight` shards at once, one per worker.
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
    // The statement is where the execution's own facts live: there is no
    // `Execution` to read them off, and these are the values the proof binds
    // rather than a second reading of them.
    // `x10`'s final value, which the statement carries as a `u32` and the
    // executor reports as an `i32`: the same 32 bits, so `exit(-1)` reads back
    // as `-1` here.
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
/// The one block verification path: this is a two-line call into
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
///
/// **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** An `Ok` here
/// is **UNSOUND**: nothing commits the columns, so the verifier accepts the
/// prover's word for every value (`docs/architecture.md` §0).
pub fn verify(vk: &VerifyingKey, block: &BlockProof) -> Result<(), VerifyError> {
    verifier::verify_block(vk, block, block.statement())
}
