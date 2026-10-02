//! The statements the proving suites prove, over a toy SRS whose `tau` is
//! written down here. Test-only.
//!
//! - S16's: `guests/addsub`'s committed ELF, decoded with its execution family
//!   at `2^20` rows — the timestamp channel's floor — and everything else at
//!   `2^16`, traced into an archive.
//! - S17's: `guests/control`'s, the same way, with both of its execution
//!   families — add/sub and jump/branch/slt — at `2^20`.
//! - S18's: `guests/alu`'s, with all four of its execution families — those
//!   two, shift/bitwise and mul/div — at `2^20`.
//! - S19's: `guests/mem`'s, with five — add/sub, jump/branch/slt and the three
//!   families S19 proves — at `2^20`. It is the first statement whose rows
//!   touch RAM, so it is also the first with a `ZERO_WINDOWS` shard.
//!
//! S24's statement is the one that is **not** here: `guests/revm-block`'s is
//! built from source rather than from a committed ELF, so it lives in
//! `tests/revm.rs` beside the suite that proves it, and this module stays free
//! of the guest workspace — `crates/checker`'s suites include it too.
//! - S20's: `guests/shards`', with add/sub and jump/branch/slt at `2^20`. Its
//!   add/sub family runs 1,064,970 cycles, past `2^20`, so it is the first
//!   statement with **two shards of one family** — and it touches no RAM, so
//!   it is also the first with a family the config carries and no shard
//!   proves.

#![allow(dead_code)]

use std::path::PathBuf;

use constants::family;
use emulator::{trace_run, GuestIo};
use field::Fr;
use loader::load_elf;
use program::{decode_program, ProgramParams};
use prover::{Program, ProverSetup};
use trace::{IoStreams, PhaseTiming, TraceArchive};
use verifier_core::{BlockProof, PublicInputs, ShardProof};

/// The execution family's height: `2^20`, the smallest a family carrying a
/// timestamp obligation can have (`docs/spec/lookup.md` §3).
pub const ADD_VARS: u32 = 20;

/// Every other family's, and the RAM windows': `2^16`. The image of `addsub`
/// ends far below `4·2^16`.
pub const WINDOW_VARS: u32 = 16;

/// `guests/addsub`'s exit status.
pub const RESULT: u32 = 42;

/// `guests/alu`'s exit status: the number of its checks.
pub const ALU_RESULT: u32 = 96;

/// `guests/control`'s exit status: the number of its checks.
pub const CONTROL_RESULT: u32 = 16;

/// `guests/mem`'s exit status: the number of its checks.
pub const MEM_RESULT: u32 = 50;

/// `guests/shards`' exit status: the number of its checks.
pub const SHARDS_RESULT: u32 = 2;

/// `guests/shards`' add/sub occupancy, which is what makes it two shards.
pub const SHARDS_ADD_CYCLES: u64 = 1_064_970;

/// `guests/keccak-test`'s exit status: the number of its checks.
pub const KECCAK_RESULT: u32 = 6;

/// How many keccak-f **permutations** `guests/keccak-test` computes: one per
/// block of its six inputs, `docs/spec/delegation.md`'s corpus.
pub const KECCAK_PERMUTATIONS: u64 = 10;

/// How many `KECCAK_F` **invocations** that is. Since S26d one invocation is one
/// round, so a permutation is 24 of them (`docs/spec/delegation.md` §6).
pub const KECCAK_INVOCATIONS: u64 = KECCAK_PERMUTATIONS * constants::keccak::ROUNDS as u64;

/// The delegation family's height. `RANGE16`'s table and `XOR8`'s each need 16
/// variables, so `constraints::family_circuit` returns `None` below `2^16` — but
/// 16 is the **floor and not the choice**: the family is at `2^18`, one menu
/// entry up and four times the cost a shard, so that a stateless block's keccak
/// load is fewer, fatter shards (`docs/spec/delegation.md` §6.5, §9.2).
///
/// This must equal `constants::family::DEFAULT_HEIGHTS[KECCAK_F]`'s exponent:
/// `crates/prover/tests/revm.rs` derives its delegation heights from that array
/// and then asserts the config's keccak height is `1 << KECCAK_VARS`, so the two
/// disagreeing is a red suite rather than a slow one.
pub const KECCAK_VARS: u32 = 18;

/// `guests/keccak-unused`'s exit status.
pub const KECCAK_UNUSED_RESULT: u32 = 7;

/// `guests/recursion-ops`' exit status: the number of checks it passed.
pub const RECURSION_RESULT: u32 = 9;

/// `guests/recursion-unused`'s exit status.
pub const RECURSION_UNUSED_RESULT: u32 = 11;

/// `guests/mod-mul-ops`' exit status: the number of checks it passed.
pub const MOD_MUL_RESULT: u32 = 28;

/// S21's and S23's delegation heights. **Not `MOD_MUL`'s**, which is `2^16`
/// (`constants::family::DEFAULT_HEIGHTS`, `docs/spec/delegation.md` §9.1).
pub const DELEGATION_VARS: u32 = 8;

/// The height the two **channel-carrying** delegation families are proved at
/// here, and the only one they have: `RANGE16`'s table needs sixteen variables,
/// so `constraints::family_circuit` returns `None` below `2^16`
/// (`docs/spec/delegation.md` §10.3).
///
/// **This was `MOD_MUL_FIXTURE_VARS = 8` until S26c**, chosen so the fixture
/// would be multi-shard: at `2^8` this family's 1,443 invocations are six
/// shards, and a last shard is the only place padding rows appeared. The
/// re-shape closed that option and made it unnecessary in the same move — at
/// `2^16` a single shard is 98% padding, so padding rows are covered in shard 0
/// and more richly than six `2^8` shards ever covered them.
///
/// What it did cost is the **forward pass**: 4.7 GB for `MOD_MUL` at `2^16` and
/// 10.5 GB for `EC_ADD`, which is a deferred-suite figure. So the fill checks
/// in `tests/fills.rs` evaluate sampled rows row-locally rather than running a
/// pass, which is the same statement per row — and the end-to-end proof of both
/// families at this height is the deferred `prover::revm` and `host::prove`
/// suites, whose params read `DEFAULT_HEIGHTS`.
pub const DELEGATION_CHANNEL_VARS: u32 = 16;

/// The committed ELF of guest `name`.
pub fn fixture(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../loader/tests/vectors/{name}.elf"));
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

pub fn elf() -> Vec<u8> {
    fixture("addsub")
}

/// Every family at `2^16` but `executed`, at `2^20`.
fn heights(executed: &[u32]) -> ProgramParams {
    let mut heights = [1 << WINDOW_VARS; family::COUNT as usize];
    for f in executed {
        heights[*f as usize] = 1 << ADD_VARS;
    }
    ProgramParams {
        heights,
        ..ProgramParams::defaults()
    }
}

pub fn params() -> ProgramParams {
    heights(&[family::ADD_SUB_LUI_AUIPC])
}

/// S17's heights: both of `control`'s execution families at `2^20`.
pub fn control_params() -> ProgramParams {
    heights(&[family::ADD_SUB_LUI_AUIPC, family::JUMP_BRANCH_SLT])
}

/// S18's heights: all four of `alu`'s execution families at `2^20`.
pub fn alu_params() -> ProgramParams {
    heights(&[
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::SHIFT_BITWISE,
        family::MUL_DIV,
    ])
}

/// S19's heights: all five of `mem`'s execution families at `2^20`.
pub fn mem_params() -> ProgramParams {
    heights(&[
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::MEM_WORD,
        family::MEM_SUBWORD,
        family::ATOMICS,
    ])
}

/// S20's heights: both of `shards`' execution families at `2^20`.
pub fn shards_params() -> ProgramParams {
    heights(&[family::ADD_SUB_LUI_AUIPC, family::JUMP_BRANCH_SLT])
}

/// S21's heights: the five execution families `keccak-test` runs at `2^20`,
/// and the delegation family at `2^16`, which since S26d is its only one.
pub fn keccak_params() -> ProgramParams {
    let mut params = heights(&[
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::SHIFT_BITWISE,
        family::MUL_DIV,
        family::MEM_WORD,
        family::MEM_SUBWORD,
    ]);
    params.heights[family::KECCAK_F as usize] = 1 << KECCAK_VARS;
    params
}

/// S26's heights: the six execution families `mod-mul-ops` runs at `2^20`,
/// `MOD_MUL` and `EC_ADD` at [`DELEGATION_CHANNEL_VARS`], which is the only
/// height either has, and the window families at `2^18` — see
/// [`mod_mul_program`] for why `2^16` does not fit them.
pub fn mod_mul_params() -> ProgramParams {
    let mut heights = [1 << 18; family::COUNT as usize];
    for f in [
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::SHIFT_BITWISE,
        family::MUL_DIV,
        family::MEM_WORD,
        family::MEM_SUBWORD,
    ] {
        heights[f as usize] = 1 << ADD_VARS;
    }
    for f in [family::MOD_MUL, family::EC_ADD] {
        heights[f as usize] = 1 << DELEGATION_CHANNEL_VARS;
    }
    ProgramParams {
        heights,
        ..ProgramParams::defaults()
    }
}

/// S23's heights: the execution families `recursion-ops` runs at `2^20`, and
/// the two delegation families at `2^8`.
pub fn recursion_params() -> ProgramParams {
    let mut params = heights(&[
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::SHIFT_BITWISE,
        family::MUL_DIV,
        family::MEM_WORD,
        family::MEM_SUBWORD,
    ]);
    for f in [family::POSEIDON2, family::FR_ARITH] {
        params.heights[f as usize] = 1 << DELEGATION_VARS;
    }
    params
}

fn program_of(name: &str, params: &ProgramParams) -> Program {
    let image = load_elf(&fixture(name)).unwrap_or_else(|e| panic!("{name} loads: {e:?}"));
    let (tables, config) =
        decode_program(&image, params).unwrap_or_else(|e| panic!("{name} decodes: {e}"));
    Program {
        image,
        tables,
        config,
    }
}

pub fn program() -> Program {
    program_of("addsub", &params())
}

pub fn control_program() -> Program {
    program_of("control", &control_params())
}

pub fn alu_program() -> Program {
    program_of("alu", &alu_params())
}

pub fn mem_program() -> Program {
    program_of("mem", &mem_params())
}

pub fn shards_program() -> Program {
    program_of("shards", &shards_params())
}

pub fn keccak_program() -> Program {
    program_of("keccak-test", &keccak_params())
}

pub fn keccak_unused_program() -> Program {
    program_of("keccak-unused", &keccak_params())
}

pub fn recursion_program() -> Program {
    program_of("recursion-ops", &recursion_params())
}

pub fn recursion_unused_program() -> Program {
    program_of("recursion-unused", &recursion_params())
}

/// S26's guest: `guests/mod-mul-ops`, which calls the `MOD_MUL` delegation by
/// name over all four moduli and reaches it a second time through
/// `guests/vendor/k256`'s patched field and scalar multiplies — and, since
/// S26c, reaches `EC_ADD` too through that crate's patched `ProjectivePoint`,
/// which this guest's own source names not at all.
///
/// Its six execution families run at `2^20` and its two delegation families at
/// [`DELEGATION_CHANNEL_VARS`], but its **window** families need `2^18` rather
/// than `2^16`: the guest's `.text`
/// reaches pc `0x452c6` and `decode_program` refuses an image byte past RAM
/// window 0, which at `2^16` ends at `0x40000` — that one fits, but the decoded
/// tables do not, a table's row `i` being pc `2i`.
pub fn mod_mul_program() -> Program {
    program_of("mod-mul-ops", &mod_mul_params())
}

/// S-IO's guest: `guests/public-io`, which reads its public input and its
/// advice with ordinary loads and writes its journal with ordinary stores
/// (`docs/spec/public-values.md`). Its execution families at `2^20`, the rest
/// at `2^16`.
pub fn public_io_program() -> Program {
    program_of(
        "public-io",
        &heights(&[
            family::ADD_SUB_LUI_AUIPC,
            family::JUMP_BRANCH_SLT,
            family::SHIFT_BITWISE,
            family::MUL_DIV,
            family::MEM_WORD,
            family::MEM_SUBWORD,
        ]),
    )
}

pub fn public_io_setup() -> ProverSetup {
    ProverSetup::new(public_io_program(), toy_srs(ADD_VARS)).expect("public-io registers")
}

/// The eight public input bytes `guests/public-io` reads: the advice's length
/// and the checksum it must have.
pub fn public_io_input(advice: &[u8]) -> Vec<u8> {
    let mut sum = 0u32;
    for (i, byte) in advice.iter().enumerate() {
        sum = sum.wrapping_add((*byte as u32).wrapping_mul(i as u32 + 1));
    }
    let mut input = (advice.len() as u32).to_le_bytes().to_vec();
    input.extend_from_slice(&sum.to_le_bytes());
    input
}

/// The journal `guests/public-io` commits for `advice`: the checksum, then the
/// first eight advice bytes.
pub fn public_io_journal(advice: &[u8]) -> Vec<u8> {
    let mut out = public_io_input(advice)[4..].to_vec();
    out.extend_from_slice(&advice[..8.min(advice.len())]);
    out
}

/// The post-execution archive of one `guests/public-io` run on `advice`, with
/// the public input that advice checks against.
pub fn public_io_archive(program: &Program, advice: &[u8]) -> TraceArchive {
    let io = GuestIo {
        input: public_io_input(advice),
        advice: advice.to_vec(),
    };
    let (traces, log, profile, execution) =
        trace_run(&program.image, &io, &program.tables, &program.config).expect("the guest traces");
    assert_eq!(execution.exit_code, 0, "the guest accepted its advice");
    assert_eq!(
        execution.io.output,
        public_io_journal(advice),
        "the journal is what the guest committed"
    );
    TraceArchive::from_execution(
        traces,
        log,
        profile,
        IoStreams {
            input: execution.io.input,
            output: execution.io.output,
        },
        io.advice,
        PhaseTiming { wall_nanos: 0 },
    )
}

/// The post-execution archive of `addsub`'s one run.
pub fn archive(program: &Program) -> TraceArchive {
    trace(program, RESULT)
}

/// The post-execution archive of `control`'s one run.
pub fn control_archive(program: &Program) -> TraceArchive {
    trace(program, CONTROL_RESULT)
}

/// The post-execution archive of `alu`'s one run.
pub fn alu_archive(program: &Program) -> TraceArchive {
    trace(program, ALU_RESULT)
}

/// The post-execution archive of `mem`'s one run.
pub fn mem_archive(program: &Program) -> TraceArchive {
    trace(program, MEM_RESULT)
}

/// The post-execution archive of `shards`' one run.
pub fn shards_archive(program: &Program) -> TraceArchive {
    trace(program, SHARDS_RESULT)
}

/// The post-execution archive of `keccak-test`'s one run.
pub fn keccak_archive(program: &Program) -> TraceArchive {
    trace(program, KECCAK_RESULT)
}

/// The post-execution archive of `keccak-unused`'s one run.
pub fn keccak_unused_archive(program: &Program) -> TraceArchive {
    trace(program, KECCAK_UNUSED_RESULT)
}

/// The post-execution archive of `recursion-ops`' one run.
pub fn recursion_archive(program: &Program) -> TraceArchive {
    trace(program, RECURSION_RESULT)
}

/// The post-execution archive of `recursion-unused`'s one run.
pub fn recursion_unused_archive(program: &Program) -> TraceArchive {
    trace(program, RECURSION_UNUSED_RESULT)
}

/// The post-execution archive of `mod-mul-ops`' one run.
pub fn mod_mul_archive(program: &Program) -> TraceArchive {
    trace(program, MOD_MUL_RESULT)
}

/// S26c's guest: `guests/sha256-ops`, which calls the `SHA256_COMP` delegation
/// by name and through `guest_sdk::sha256`'s block loop, 33 compressions in all.
///
/// `SHA256_COMP` stays at its `2^8` default — it carries no channel, so no floor
/// applies, and one row is 20,000 inner columns, which is why `2^16` is not open
/// to it (`docs/spec/delegation.md` §9.2). Its window families need `2^18` for
/// `mod_mul_program`'s reason.
pub fn sha256_program() -> Program {
    let mut heights = [1 << 18; family::COUNT as usize];
    for f in [
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::SHIFT_BITWISE,
        family::MUL_DIV,
        family::MEM_WORD,
        family::MEM_SUBWORD,
    ] {
        heights[f as usize] = 1 << ADD_VARS;
    }
    heights[family::SHA256_COMP as usize] = 1 << DELEGATION_VARS;
    program_of(
        "sha256-ops",
        &ProgramParams {
            heights,
            ..ProgramParams::defaults()
        },
    )
}

/// The post-execution archive of `sha256-ops`' one run: exit 12, one per check
/// but the first.
pub fn sha256_archive(program: &Program) -> TraceArchive {
    trace(program, 12)
}

/// A run with no input and no hint, which must exit with `status`.
pub fn trace(program: &Program, status: u32) -> TraceArchive {
    let io = GuestIo {
        input: Vec::new(),
        advice: Vec::new(),
    };
    let (traces, log, profile, execution) =
        trace_run(&program.image, &io, &program.tables, &program.config).expect("the guest traces");
    assert_eq!(execution.exit_code, status as i32);
    TraceArchive::from_execution(
        traces,
        log,
        profile,
        IoStreams {
            input: execution.io.input,
            output: execution.io.output,
        },
        Vec::new(),
        PhaseTiming { wall_nanos: 0 },
    )
}

/// **The one proving path's backpressure, for the suites.**
///
/// `prover::prove_block_streaming` proves at most this many shards at once,
/// so it is what bounds a suite's peak (`docs/spec/streaming.md` §5). Four
/// rather than eight: a deferred suite is run for its verdict and not for its
/// wall clock, and the measured difference between the two is 14% of the time
/// against 6.8 GiB of peak. The block does not depend on it —
/// `tests/streaming.rs` proves the bytes equal at 1 and 8 — so no test's
/// assertion rests on the number.
pub const IN_FLIGHT: usize = 4;

/// A run with nothing on any stream: what every committed guest but
/// `public-io` takes.
pub fn empty_io() -> GuestIo {
    GuestIo {
        input: Vec::new(),
        advice: Vec::new(),
    }
}

/// `guests/public-io`'s run over `advice`, with the public input that advice
/// checks against.
pub fn public_io_io(advice: &[u8]) -> GuestIo {
    GuestIo {
        input: public_io_input(advice),
        advice: advice.to_vec(),
    }
}

/// **Prove one execution as a block, the only way this repository proves.**
///
/// `prover::prove_block_streaming` at [`IN_FLIGHT`]. Since S-STREAM nothing in
/// any suite reaches `prover::prove_block`: the archived path still compiles,
/// because `checker`'s column-fill suites and `checker::TamperHarness` build
/// their columns from a `TraceArchive`, but it proves nothing anywhere
/// (`docs/spec/streaming.md` §1).
pub fn streamed(setup: &ProverSetup, io: &GuestIo) -> BlockProof {
    let (block, report) =
        prover::prove_block_streaming(setup, io, IN_FLIGHT).expect("the block proves");
    assert!(
        report.peak_in_flight <= IN_FLIGHT,
        "{} shards in flight above the bound {IN_FLIGHT}",
        report.peak_in_flight
    );
    block
}

/// The statement and its shard proofs, which is what `prover::finish` handed
/// back on the archived path.
///
/// A `BlockProof` carries both, in statement order, so a suite that verifies
/// loose shards takes them from the block rather than from a second proving
/// run (`docs/spec/block-proof.md` §2).
pub fn streamed_shards(setup: &ProverSetup, io: &GuestIo) -> (PublicInputs, Vec<ShardProof>) {
    let block = streamed(setup, io);
    (block.statement, block.shards)
}

pub fn setup() -> ProverSetup {
    ProverSetup::new(program(), toy_srs(ADD_VARS)).expect("addsub registers")
}

pub fn control_setup() -> ProverSetup {
    ProverSetup::new(control_program(), toy_srs(ADD_VARS)).expect("control registers")
}

pub fn alu_setup() -> ProverSetup {
    ProverSetup::new(alu_program(), toy_srs(ADD_VARS)).expect("alu registers")
}

pub fn mem_setup() -> ProverSetup {
    ProverSetup::new(mem_program(), toy_srs(ADD_VARS)).expect("mem registers")
}

pub fn shards_setup() -> ProverSetup {
    ProverSetup::new(shards_program(), toy_srs(ADD_VARS)).expect("shards registers")
}

pub fn keccak_setup() -> ProverSetup {
    ProverSetup::new(keccak_program(), toy_srs(ADD_VARS)).expect("keccak-test registers")
}

pub fn keccak_unused_setup() -> ProverSetup {
    ProverSetup::new(keccak_unused_program(), toy_srs(ADD_VARS)).expect("keccak-unused registers")
}

pub fn recursion_setup() -> ProverSetup {
    ProverSetup::new(recursion_program(), toy_srs(ADD_VARS)).expect("recursion-ops registers")
}

pub fn recursion_unused_setup() -> ProverSetup {
    ProverSetup::new(recursion_unused_program(), toy_srs(ADD_VARS))
        .expect("recursion-unused registers")
}

pub fn mod_mul_setup() -> ProverSetup {
    ProverSetup::new(mod_mul_program(), toy_srs(ADD_VARS)).expect("mod-mul-ops registers")
}

/// The toy SRS's `tau`.
pub fn toy_tau() -> Fr {
    Fr::from_hex("0x0000000000000000000000000000000000000000000000000000000000c0ffee")
        .expect("a canonical literal")
}

/// An SRS of `2^power` powers of a `tau` written down here: real, structurally
/// valid and completely insecure, built the way `crates/pcs`' suite builds one
/// and loaded through `Srs::load`. The archive is kept under cargo's
/// workspace-wide integration-test directory (`CARGO_TARGET_TMPDIR`,
/// `<target>/tmp`), so every suite that includes this module — the prover's,
/// the verifier's and the checker's — loads it instead of building it again;
/// its content is a function of `power` alone, and a file that does not load
/// is rebuilt.
pub fn toy_srs(power: u32) -> srs::Srs {
    use curve::{G1Projective, G2Affine};
    use rayon::prelude::*;

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    let path = dir.join(format!("s16-toy-{power}.srs"));
    if let Ok(srs) = srs::Srs::load(&path) {
        return srs;
    }
    let tau = toy_tau();
    let count = 1usize << power;
    let mut scalars = Vec::with_capacity(count);
    let mut acc = Fr::ONE;
    for _ in 0..count {
        scalars.push(acc);
        acc *= tau;
    }
    let projective: Vec<G1Projective> = scalars
        .par_iter()
        .map(|s| G1Projective::GENERATOR.mul(s))
        .collect();
    let g1 = G1Projective::batch_to_affine(&projective);
    let g2_tau = G2Affine::GENERATOR.mul(&tau);

    let mut bytes = Vec::with_capacity(280 + count * 64);
    bytes.extend_from_slice(b"APOGESRS");
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&power.to_le_bytes());
    bytes.extend_from_slice(&(count as u64).to_le_bytes());
    bytes.extend_from_slice(&G2Affine::GENERATOR.to_bytes());
    bytes.extend_from_slice(&g2_tau.to_bytes());
    for p in &g1 {
        bytes.extend_from_slice(&p.to_bytes());
    }
    std::fs::create_dir_all(&dir).expect("the test directory");
    // Written aside and renamed, so nothing ever reads half a file. The name
    // must be unique per *call*, not per process: two tests in one binary are
    // two threads of one process, so a pid alone gave both the same scratch
    // path — one renamed it away and the other's rename found nothing, or a
    // reader opened it mid-write and got `Truncated`. `rename` is atomic on
    // POSIX and the content is a function of `power` alone, so two callers
    // racing to place identical bytes is harmless once the scratch names
    // differ.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let partial = dir.join(format!(
        "s16-toy-{power}.{}.{}.partial",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::write(&partial, &bytes).expect("writing the toy archive");
    std::fs::rename(&partial, &path).expect("placing the toy archive");
    srs::Srs::load(&path).expect("the toy archive loads")
}
