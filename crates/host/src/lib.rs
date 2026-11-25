//! The host SDK: a guest ELF and its inputs in, a `BlockProof` out.
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
//!   [`DEFAULT_MAX_IN_FLIGHT`], 8, is what every caller here passes.
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
//! interval than this function could take. [`prove`]'s own untraced run, the
//! exit-status check before the prover starts, is in `Proven::wall_nanos`
//! alone.
//!
//! # Checking before proving
//!
//! [`check`] runs the execution [`prove`] would prove, under a cycle cap, and
//! holds every shard's witness — built by the prover's own fills — to its
//! circuit, committing and proving nothing: what a Prover Host runs on a
//! candidate batch so that one whose proof would fail is refused before any
//! proving starts (`docs/spec/streaming.md` §7). [`CheckFailure`] names what
//! failed: the executor's error, the exit status, or the family, shard, row
//! and relation or channel.
//!
//! # The proof archive
//!
//! [`proof_archive`] is the four files a proved block leaves on disk, which are
//! exactly what the `verifier` CLI reads back. **The proof is the only thing a
//! proving run archives.** It is `verifier::proof_archive`, re-exported: the
//! format's reader is the CLI, so its writer lives beside the reader and there
//! is one definition of it.

pub use check::{check, CheckFailure, CheckReport};
pub use prover::DEFAULT_MAX_IN_FLIGHT;
pub use verifier::proof_archive;

mod check;

use std::time::Instant;

use emulator::GuestIo;
use loader::load_elf;
use program::{decode_program, ProgramParams};
use prover::{Program, ProverError, ProverSetup, StreamingReport};
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
    /// The guest's exit status, which is `x10`'s final value: always 0, the
    /// only status [`prove`] proves.
    pub exit_code: i32,
    /// Cycles the execution took.
    pub cycles: u64,
    /// The journal, which is also `block.statement().output`.
    pub journal: Vec<u8>,
    /// Wall-clock of the whole call, all three executions included.
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
/// One untraced execution of the guest, then one call into
/// `prover::prove_block_streaming`, which executes the guest
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
/// **Only an execution that exits 0 is proved.** Any other status — a panic's
/// 101, the SDK's 70 and 71, any `exit(n)` — is a failed execution, which no
/// verifier accepts (`docs/spec/proof.md` §6, step 0), and is refused with
/// `ProverError::NonzeroExit`, naming the status, before any proving work.
/// That is what the first execution is for: the prover refuses such a run
/// too, but the status exists only at the exit, so it learns it only after
/// its first pass has committed every shard the execution filled. The cost is
/// one run of the guest with no tracer, the cheapest of the three.
pub fn prove(setup: &ProverSetup, io: &GuestIo, max_in_flight: usize) -> Result<Proven, String> {
    let started = Instant::now();
    let refused = |e: ProverError| format!("the block does not prove: {e:?}");
    // A fatal run is the error the prover would have returned for it, from the
    // same executor over the same `(image, io)`.
    let execution = emulator::run(&setup.program.image, io)
        .map_err(|e| refused(ProverError::Trace(e.to_string())))?;
    if execution.exit_code != 0 {
        return Err(refused(ProverError::NonzeroExit {
            status: execution.exit_code as u32,
        }));
    }
    let (block, report) =
        prover::prove_block_streaming(setup, io, max_in_flight).map_err(refused)?;
    // The statement is where the execution's own facts live: these are the
    // values the proof binds rather than the check's reading of them.
    // `x10`'s final value, which the statement carries as a `u32` and the
    // executor reports as an `i32`: the same 32 bits, and 0, the one status
    // the check above lets through.
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
pub fn verify(vk: &VerifyingKey, block: &BlockProof) -> Result<(), VerifyError> {
    verifier::verify_block(vk, block, block.statement())
}
