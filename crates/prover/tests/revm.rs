//! S24's acceptance 6, 7 and 8: the revm block proved, verified and tampered.
//!
//! `#[ignore]`d and deferred out of CI under master rule 7: the statement is
//! seven `2^20` execution shards, two `2^20` window shards and one `2^8`
//! keccak shard, over a `--release` guest this suite builds from source. Run
//! it with
//!
//! ```text
//! cargo test --release -p prover --test revm -- --include-ignored --test-threads=1
//! ```
//!
//! # What is proved, and what is not
//!
//! The binary is `guests/revm-block`'s **embedded-witness** one, and that is
//! the stage's one deviation from must-be-exact 1. The normative guest reads
//! its `BlockWitness` on fd 0 and commits its output on fd 1, and **neither
//! is a provable ecall**: the add/sub family's circuit holds every ecall row
//! to `a7 = EXIT` or a registered delegation number
//! (`crates/constraints/src/add_sub.rs`, `ecall_is_exit`), and
//! `prover::fill::add_sub` refuses a `read` row, a `write` row and their
//! transfer cycles by name. Binding fd 0 and fd 1 is the deferred I/O-binding
//! stage's work — `prompts/00-master.md` lists it among the frozen invariants
//! — and it is not a gate or two: a transfer row that is permitted but not
//! tied to its ecall's buffer and length can write any value to any RAM word.
//! `docs/handoff/S24-revm.md` is the full account.
//!
//! So the binary proved here binds the same two streams by the two means the
//! machine already has, and both are checked below:
//!
//! - the **input** is a `.rodata` constant, which program identity commits;
//! - the **output** is `keccak256` of the commitment, left in `x24..x31`,
//!   which the statement's register boundary carries.

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
use verifier_core::{statement_shards, BlockProof, PublicInputs, VerifyError};

const KECCAK: u32 = family::KECCAK_F;
const INIT: u32 = family::INIT_TEARDOWN;
const ZERO: u32 = family::ZERO_WINDOWS;

// ---------------------------------------------------------------------------
// The statement
// ---------------------------------------------------------------------------

/// `guests/revm-block`'s embedded-witness binary, which exits 0 with
/// `keccak256` of its output commitment in `x24..x31`.
const REVM_RESULT: u32 = 0;

/// The binary S24 proves. The normative guest reads fd 0 and writes fd 1, and
/// neither is a provable ecall yet; this one runs the same program over the
/// same committed witness with the witness in its image.
/// `docs/handoff/S24-revm.md` is the whole argument.
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

/// The guest's run **over its witness on fd 0**, which is what S25 made
/// provable. `common::trace` runs a guest with empty streams and this one has
/// two, so it builds the archive itself.
fn revm_archive(program: &Program) -> TraceArchive {
    let archive = host::execute(program, &witness_bytes(), &[]).expect("the guest traces");
    assert_eq!(
        archive.io_streams().input,
        witness_bytes(),
        "the guest consumed the whole witness"
    );
    archive
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

/// `x24..x31` of a statement's boundary, as the guest left them.
fn public_words(public: &PublicInputs) -> [u32; 8] {
    core::array::from_fn(|i| public.boundary.reg_values[23 + i])
}

/// Acceptance 1: two clean builds of the guest give one `ProgramIdentity`.
///
/// Identity is what a verifier takes from a channel the prover does not
/// control, and for the embedded binary it is also what binds the witness —
/// so a build that is not reproducible is a program nobody can name. Two
/// builds into two fresh target directories, each preprocessed and committed
/// on its own, and the two digests compared.
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
        "revm-block-embedded identity over the toy SRS: {}",
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

    // **The statement says what the block executed and what it produced.**
    // Since S25 that is the whole point of the proof rather than a
    // demonstration beside it: fd 0 is the committed witness, fd 1 is the
    // output commitment native revm computes from it, and `x24..x31` are
    // `io_digest` of the pair — which `verify_block` has already recomputed
    // and compared above, so what this asserts is that the streams the
    // statement carries are the ones the fixture names.
    let witness = revm_block::BlockWitness::decode(&witness_bytes()).expect("the witness decodes");
    let output = revm_block::run(&witness).expect("the block executes on the host");
    assert_eq!(block.statement().input, witness_bytes(), "fd 0");
    assert_eq!(block.statement().output, output, "fd 1");
    assert_eq!(
        public_words(block.statement()),
        transcript::io_digest_words(&witness_bytes(), &output),
        "the proof's register boundary is not the public I/O digest"
    );
    assert_eq!(block.statement().exit_status, REVM_RESULT);

    // And it all reads back through the serialized block alone.
    let bytes = block.to_bytes();
    let read = BlockProof::from_bytes(&bytes).expect("the block round-trips");
    assert_eq!(
        public_words(read.statement()),
        public_words(block.statement())
    );
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

    // The embedded binary reads no fd 0 and writes no fd 1, so its streams are
    // empty and its public I/O digest is `io_digest(&[], &[])`.
    assert!(honest.input.is_empty());
    assert!(honest.output.is_empty());

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

    // 7(c) The word the guest published. `x24..x31` are the output commitment's
    // digest and they are ordinary register finals, absorbed in the
    // `MEMORY_BOUNDARY` message before the memory challenges are squeezed — so
    // a changed one is a changed statement, not a changed opinion about one.
    let mut word = honest.clone();
    word.boundary.reg_values[23] ^= 1;
    let mut reworded = block.clone();
    reworded.statement = word.clone();
    assert!(
        verify_block(&setup.vk, &reworded, &word).is_err(),
        "a changed public word is refused"
    );
}
