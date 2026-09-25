//! S24's acceptance 6, 7 and 8: the revm block proved, verified and tampered.
//!
//! `#[ignore]`d and deferred out of CI under master rule 7: the statement is
//! seven `2^20` execution shards, two `2^20` RAM window shards, one `2^8`
//! keccak shard and S25's three — two `2^8` public value shards and one
//! `2^20` advice window — over a `--release` guest this suite builds from
//! source. Run it with
//!
//! ```text
//! cargo test --release -p prover --test revm -- --include-ignored --test-threads=1
//! ```
//!
//! # What is proved, and what changed at S25
//!
//! The binary is `guests/revm-block`'s **own** one, and since S25 that is the
//! whole program: its `BlockWitness` arrives in the **advice** region and its
//! output commitment leaves in the **journal**, both ordinary loads and stores
//! (`docs/spec/public-values.md`). It issues no ecall but `EXIT`.
//!
//! S24 could not prove that program. `read` and `write` are not provable
//! ecalls, so it proved a second binary with the witness baked into `.rodata`
//! — which identity commits, and which therefore moved the identity with every
//! block — and published `keccak256` of the commitment in `x24..x31`, where the
//! register boundary carries it. Both of those stopgaps are gone:
//!
//! - the **witness** is advice, so one identity serves every block;
//! - the **output** is the journal, so the statement carries the commitment's
//!   bytes and not a digest of them.
//!
//! What binds the witness is no longer identity but the guest: the commitment
//! names the state roots the block began and ended on, so a witness describing
//! a different block publishes a different journal rather than the same one
//! (`docs/spec/public-values.md` §6).

mod common;

use std::path::PathBuf;

use constants::family;
use loader::load_elf;
use program::{decode_program, ProgramParams};
use prover::prove_block;
use prover::{Program, ProverSetup};
use trace::plan_shards;
use trace::TraceArchive;
use verifier::{verify_block, verify_shard};
use verifier_core::{statement_shards, BlockProof, VerifyError};

const KECCAK: u32 = family::KECCAK_F;
const INIT: u32 = family::INIT_TEARDOWN;
const ZERO: u32 = family::ZERO_WINDOWS;

// ---------------------------------------------------------------------------
// The statement
// ---------------------------------------------------------------------------

/// `guests/revm-block` exits 0 with its output commitment in the journal.
const REVM_RESULT: u32 = 0;

/// The binary proved here: the guest itself, provable since S25.
/// `src/stdio.rs` is the fd 0 / fd 1 compatibility binary, which is not.
const REVM_BIN: &str = "revm-block";

/// S24's heights: every family but the delegation one at `2^20`, with
/// `revm-block`'s own span ceiling.
///
/// Unlike every other statement here this one takes `2^20` for the two window
/// families too, and it has to: its image ends at `0x1c48d4`, past the
/// `4 * 2^16` bytes a `2^16` window 0 covers.
fn revm_params() -> ProgramParams {
    let mut heights = [revm_block::TRACE_HEIGHT_RELEASE; family::COUNT as usize];
    heights[family::KECCAK_F as usize] = 1 << common::KECCAK_VARS;
    heights[family::POSEIDON2 as usize] = 1 << common::DELEGATION_VARS;
    heights[family::FR_ARITH as usize] = 1 << common::DELEGATION_VARS;
    ProgramParams {
        heights,
        bytecode_size_words: revm_block::BYTECODE_SIZE_WORDS,
        ..ProgramParams::defaults()
    }
}

/// S24's program, built from source at `--release`.
///
/// **Always `--release`, whatever `APOGEE_GUEST_PROFILE` says**: the
/// statement's heights are pinned to the release image, which fits `2^20`,
/// and the debug image is 3.3 times larger and would need `2^22` — four times
/// the rows in every shard, for a build nothing proves.
fn revm_program() -> Program {
    let elf = build_guest_bin("revm-block", REVM_BIN);
    let image = load_elf(&elf).unwrap_or_else(|e| panic!("{REVM_BIN} loads: {e:?}"));
    let params = revm_params();
    let (tables, config) =
        decode_program(&image, &params).unwrap_or_else(|e| panic!("{REVM_BIN} decodes: {e}"));
    Program {
        image,
        tables,
        config,
    }
}

/// One traced run of the guest over the committed witness, which reaches it
/// as **advice**.
fn revm_archive(program: &Program) -> TraceArchive {
    let io = emulator::GuestIo {
        stdin: Vec::new(),
        input: Vec::new(),
        advice: witness_bytes(),
        hint: Vec::new(),
    };
    let (traces, log, profile, execution) =
        emulator::trace_run(&program.image, &io, &program.tables, &program.config)
            .expect("the guest traces");
    assert_eq!(execution.exit_code, REVM_RESULT as i32);
    TraceArchive::from_execution(
        traces,
        log,
        profile,
        trace::IoStreams {
            input: execution.io.input,
            output: execution.io.output,
        },
        io.advice,
        trace::PhaseTiming { wall_nanos: 0 },
    )
}

fn revm_setup() -> ProverSetup {
    ProverSetup::new(revm_program(), common::toy_srs(common::ADD_VARS))
        .expect("revm-block registers")
}

/// Build one binary of `guests/<name>` at `--release`, into a fresh target
/// directory, and return its ELF bytes.
///
/// The command is `docs/guest-program-manual.md`'s, with everything that could
/// reach rustc from the ambient environment cleared, because a guest ELF is an
/// artifact whose bytes decide an identity. Every test crate that builds a
/// guest carries this function; they are copies on purpose, since a test
/// module cannot be shared across crate boundaries.
fn build_guest_bin(name: &str, bin: &str) -> Vec<u8> {
    build_guest_bin_in(name, bin, "one")
}

/// The same, into a target directory named by `slot`, so two clean builds of
/// one binary can be compared.
fn build_guest_bin_in(name: &str, bin: &str, slot: &str) -> Vec<u8> {
    let guest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../guests")
        .join(name);
    let target_dir =
        std::env::temp_dir().join(format!("apogee-prover-{bin}-{slot}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&target_dir);
    let mut command =
        std::process::Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(&guest_dir)
        .args([
            "build",
            "--release",
            "--target",
            "riscv32imac-unknown-none-elf",
        ])
        .env("CARGO_TARGET_DIR", &target_dir);
    for key in [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_BUILD_TARGET",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
    ] {
        command.env_remove(key);
    }
    let out = command.output().expect("running cargo for a guest");
    assert!(
        out.status.success(),
        "{name}: guest build failed\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let elf = target_dir
        .join("riscv32imac-unknown-none-elf/release")
        .join(bin);
    let bytes = std::fs::read(&elf).unwrap_or_else(|e| panic!("reading {}: {e}", elf.display()));
    let _ = std::fs::remove_dir_all(&target_dir);
    bytes
}

/// The committed witness, which is also the binary's `.rodata` constant.
fn witness_bytes() -> Vec<u8> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../emulator/tests/vectors/revm_block_witness.bin");
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The output commitment the same library computes on the host, over the same
/// committed witness: what the journal must hold.
fn host_output() -> Vec<u8> {
    let witness = revm_block::BlockWitness::decode(&witness_bytes()).expect("the witness decodes");
    revm_block::run(&witness).expect("the block executes on the host")
}

/// Acceptance 1: two clean builds of the guest give one `ProgramIdentity`.
///
/// Identity is what a verifier takes from a channel the prover does not
/// control — so a build that is not reproducible is a program nobody can name.
/// Since S25 it binds the program and nothing else: the witness is advice, so
/// one identity serves every block, which is the whole point of the change.
/// Two builds into two fresh target directories, each preprocessed and
/// committed on its own, and the two digests compared.
///
/// Over the **toy SRS**, deliberately. Identity is a digest over commitments
/// to the program's own columns, and what acceptance 1 asks about is the
/// *build*: that the same source twice gives the same program. Any structurally
/// valid SRS answers that, and taking the toy one means this runs on a machine
/// with no 19 GB ceremony file. `crates/program/tests/identity.rs` is where a
/// *pinned* identity over the real ceremony lives.
///
/// The ELF bytes are compared too. They are the stronger statement — equal
/// bytes make equal identities trivially — and comparing both is what tells a
/// reader which half broke if this ever fails.
#[test]
#[ignore]
fn a1_two_clean_builds_give_one_identity() {
    let srs = common::toy_srs(common::ADD_VARS);
    let params = revm_params();
    let mut elves = Vec::new();
    let mut identities = Vec::new();
    for slot in ["a", "b"] {
        let elf = build_guest_bin_in("revm-block", REVM_BIN, slot);
        let image = load_elf(&elf).unwrap_or_else(|e| panic!("{REVM_BIN} loads: {e:?}"));
        let (tables, config) =
            decode_program(&image, &params).unwrap_or_else(|e| panic!("{REVM_BIN} decodes: {e}"));
        identities.push(program::program_identity(&image, &tables, &config, &srs));
        elves.push(elf);
    }
    assert_eq!(
        elves[0], elves[1],
        "two clean builds of the guest gave different ELF bytes"
    );
    assert_eq!(
        identities[0], identities[1],
        "two clean builds of the guest gave different program identities"
    );
    println!(
        "revm-block identity over the toy SRS: {}",
        test_support::to_hex(&identities[0].to_bytes())
    );
}

/// Acceptance 6 and 8: the block proves, every shard verifies, the keccak
/// family has a shard, and the digest the guest published is the digest of
/// what the same program computes on the host.
#[test]
#[ignore]
fn a6_the_revm_block_proves_and_verifies() {
    let setup = revm_setup();
    let mut archive = revm_archive(&setup.program);

    // Acceptance 2, restated on the statement the proof is about: the family
    // set is derived, `KECCAK_F` is in it at the delegation height, and S23's
    // two families are not — nothing in this image does `Fr` arithmetic.
    let families: Vec<u32> = setup
        .program
        .config
        .families
        .iter()
        .map(|(f, _)| *f)
        .collect();
    assert_eq!(families.last(), Some(&KECCAK));
    assert!(!families.contains(&family::POSEIDON2));
    assert!(!families.contains(&family::FR_ARITH));
    assert_eq!(
        setup.program.config.height(KECCAK),
        Some(1 << common::KECCAK_VARS)
    );

    let plan = plan_shards(archive.cycle_profile(), &setup.program.config);
    let shards = |f: u32| {
        plan.shards
            .iter()
            .find(|(g, _)| *g == f)
            .expect("a config family is planned")
            .1
    };
    // Acceptance 8: the delegation family has at least one shard on the honest
    // run. A revm block hashes — contract code, the log list, the post-state
    // summary — so a zero here would mean the shim was never reached and the
    // `native-keccak` hook had silently fallen back to `alloy-primitives`'
    // own Keccak.
    assert!(shards(KECCAK) >= 1, "the workload delegates keccak");
    // Every cycle-owning family runs in this workload and fits one shard.
    for f in 0..=family::ATOMICS {
        assert_eq!(
            shards(f),
            1,
            "family {} is one shard",
            program::family_name(f)
        );
    }

    let block = prove_block(&setup, &mut archive, &plan).expect("the block proves");
    assert_eq!(
        verify_block(&setup.vk, &block, block.statement()),
        Ok(()),
        "the block verifies"
    );

    // The structural counts: one shard per planned shard, in statement order,
    // with the two window families' overriding the plan's zeroes and the
    // delegation family's last.
    let expected = statement_shards(&setup.program.config, block.shard_counts());
    assert_eq!(block.shards.len(), expected.len());
    assert_eq!(expected.last(), Some(&(KECCAK, 0)));
    assert_eq!(
        block.shard_counts()[families.iter().position(|f| *f == INIT).unwrap()],
        1,
        "exactly one window-0 shard"
    );
    assert_eq!(
        block.shard_counts()[families.iter().position(|f| *f == ZERO).unwrap()] as usize,
        block.statement().windows.len(),
        "one shard per touched window above 0"
    );

    // Every shard verifies through the one entry point too.
    for shard in &block.shards {
        assert_eq!(
            verify_shard(&setup.vk, shard, block.statement()),
            Ok(()),
            "family {} shard {}",
            shard.family,
            shard.shard_index
        );
    }

    // The public output: the statement's journal is the output commitment the
    // same program computes on the host, byte for byte — not a digest of it,
    // which is what S24 had to settle for.
    assert_eq!(
        block.statement().output,
        host_output(),
        "the statement's journal is not native revm's output commitment"
    );
    assert!(
        block.statement().input.is_empty(),
        "this guest reads no public input: its whole input is advice"
    );
    assert_eq!(block.statement().exit_status, REVM_RESULT);

    // The advice region is a statement shard like any other, and the witness
    // it carries is 716 bytes: one window at the window height.
    assert_eq!(block.shard_count(family::PUBLIC_INPUT), 1);
    assert_eq!(block.shard_count(family::PUBLIC_OUTPUT), 1);
    assert_eq!(block.shard_count(family::ADVICE_WINDOWS), 1);

    // And it all reads back through the serialized block alone.
    let bytes = block.to_bytes();
    let read = BlockProof::from_bytes(&bytes).expect("the block round-trips");
    assert_eq!(read.statement().output, block.statement().output);
    assert_eq!(verify_block(&setup.vk, &read, read.statement()), Ok(()));
}

/// Acceptance 7: the statement is what the proof is about.
///
/// Three twins, and each one is carried **past `verify_block`'s first two
/// checks** before it is judged. That is the point of the test and it is easy
/// to get wrong: `verify_block` compares the block's own `VmConfig` to the
/// key's and its own statement to the one it was handed, and returns
/// `Statement` on either. So handing a *changed* `PublicInputs` beside an
/// untouched block proves nothing about binding — it proves two structs
/// differ, which `PartialEq` already said. Each twin below therefore moves the
/// block's own copy to match, so checks 1 and 2 pass and the twin is refused
/// by the mechanism it is about.
///
/// The public I/O digest is `transcript::io_digest` over the fd 0 and fd 1
/// streams, and `PublicInputs` carries those streams rather than the digest,
/// so "a digest differing in one byte" is a stream differing in one byte —
/// the same absorption, at G7, and the same consequence.
#[test]
#[ignore]
fn a7_a_changed_statement_is_refused() {
    let setup = revm_setup();
    let mut archive = revm_archive(&setup.program);
    let plan = plan_shards(archive.cycle_profile(), &setup.program.config);
    let block = prove_block(&setup, &mut archive, &plan).expect("the block proves");
    let honest = block.statement().clone();
    assert_eq!(verify_block(&setup.vk, &block, &honest), Ok(()));

    // The guest reads no public input, so the statement's input is empty; its
    // output is the commitment, which is what `io_digest` now binds to the
    // execution through the journal window (`docs/spec/public-values.md` §5.1).
    assert!(honest.input.is_empty());
    assert_eq!(honest.output, host_output());

    // 7(a) A public I/O digest differing in one byte. First the shape a
    // verifier faces — the statement it was given is not the one the block
    // bound — and then the same change pushed into the block too, so that what
    // refuses it is G7's absorption and not a struct comparison.
    let mut flipped = honest.clone();
    flipped.output.push(1);
    assert_eq!(
        verify_block(&setup.vk, &block, &flipped),
        Err(VerifyError::Statement(
            "the block's statement is not the one given"
        ))
    );
    let mut twin = block.clone();
    twin.statement = flipped.clone();
    assert_eq!(
        verify_block(&setup.vk, &twin, &flipped),
        Err(VerifyError::MemoryArgument(
            "the statement's roots do not reconcile"
        )),
        "the memory challenges are drawn from the statement's own transcript"
    );
    assert_eq!(
        verify_shard(&setup.vk, &twin.shards[0], &flipped),
        Err(VerifyError::Statement(
            "the proof was made for another statement"
        )),
        "and the per-shard path names the seed"
    );

    // 7(b) A different `ProgramIdentity`, with the key's `VmConfig` left alone
    // so the descriptor check cannot be what catches it. G6 absorbs the
    // identity, so the challenges move with it.
    let mut other = setup.vk.clone();
    other.identity.0 += field::Fr::ONE;
    assert_eq!(other.config, setup.vk.config, "only the identity moved");
    assert_eq!(
        verify_block(&other, &block, &honest),
        Err(VerifyError::MemoryArgument(
            "the statement's roots do not reconcile"
        ))
    );

    // 7(c) What the guest published. Since S25 that is the **journal**, and a
    // changed journal is a changed statement twice over: `io_digest` absorbs
    // it at G7 before the memory challenges are squeezed, and step 10c holds
    // the journal window's committed teardown column to those same bytes
    // (`docs/spec/public-values.md` §5).
    let mut edited = honest.clone();
    edited.output[0] ^= 1;
    let mut reworded = block.clone();
    reworded.statement = edited.clone();
    assert!(
        verify_block(&setup.vk, &reworded, &edited).is_err(),
        "a changed journal is refused"
    );

    // A boundary register final moves it too, for the older reason: the
    // `MEMORY_BOUNDARY` message is absorbed before the squeeze as well.
    let mut word = honest.clone();
    word.boundary.reg_values[23] ^= 1;
    let mut reworded = block.clone();
    reworded.statement = word.clone();
    assert!(
        verify_block(&setup.vk, &reworded, &word).is_err(),
        "a changed boundary value is refused"
    );
}
