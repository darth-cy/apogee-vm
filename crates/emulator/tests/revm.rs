//! S24's acceptance, everything short of the proof.
//!
//! The workload is `guests/revm-block`: revm over a synthetic pre-state with
//! one funded account, two transactions, and a counter contract that writes a
//! storage slot and emits a log. `tools/kat-gen/src/revm.rs` builds the
//! witness and the answer; this suite is what holds the guest to them.
//!
//! | Acceptance | Test |
//! | --- | --- |
//! | 2 family set and partition | [`a2_the_family_set_is_the_program_s`] |
//! | 3 emulator against QEMU | [`a3_the_two_executors_commit_the_same_bytes`] |
//! | 4 guest against native host revm | [`a4_the_guest_agrees_with_native_revm`] |
//! | 5 the delegated keccak against the software one | [`a5_every_delegated_permutation_is_the_reference`] |
//! | 9 cycles and occupancy | [`a9_the_cycle_and_occupancy_report`] |
//! | 10 image size against the ceiling | [`a10_the_image_fits_its_declared_ceiling`] |
//!
//! Acceptance 1 (a reproducible identity), 6, 7 and 8 need an SRS or a proof
//! and live in `crates/prover/tests/revm.rs`.
//!
//! **The guest is built from source, never from a committed ELF.** It is
//! 2.2 MB at `--release` and 7.8 MB at `debug`, and the only thing derived
//! from its bytes is its identity, which this suite does not need; committing
//! it would also enrol it in the suites that decode every committed guest,
//! whose cost at this guest's height is measured in minutes.
//! `docs/handoff/S24-revm.md` records the decision. Every test that needs a
//! build is therefore `#[ignore]`d and CI asks for it by name, which is what
//! `crates/program/tests/delegation.rs` does for the same reason.

mod common;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use constants::{family, guest_memory, keccak};
use emulator::{lanes_of, trace_run, GuestIo};
use loader::{load_elf, ProgramImage, Slot};
use program::{decode_program, DecodedTables, ProgramParams, VmConfig};
use revm_block::BlockWitness;
use trace::plan_shards;

/// The normative guest: its witness arrives on fd 0.
const GUEST: &str = "revm-block";

/// The provable guest: the same program with its witness in the image.
const EMBEDDED: &str = "revm-block-embedded";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn vector(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// fd 0's committed bytes.
fn witness_bytes() -> Vec<u8> {
    vector("revm_block_witness.bin")
}

/// fd 1's committed bytes: what native revm makes of the witness.
fn output_bytes() -> Vec<u8> {
    vector("revm_block_output.bin")
}

/// Every keccak-f frame the committed run delegated, as 50-word states.
fn committed_frames() -> Vec<[u32; keccak::FRAME_WORDS]> {
    let bytes = vector("revm_block_keccak.bin");
    let width = 4 * keccak::FRAME_WORDS;
    assert_eq!(
        bytes.len() % width,
        0,
        "the frame fixture is whole 200-byte states"
    );
    bytes
        .chunks_exact(width)
        .map(|chunk| {
            core::array::from_fn(|i| {
                u32::from_le_bytes([
                    chunk[4 * i],
                    chunk[4 * i + 1],
                    chunk[4 * i + 2],
                    chunk[4 * i + 3],
                ])
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Preprocessing
// ---------------------------------------------------------------------------

/// Every family but a delegation family at `height`, with this program's
/// pinned span ceiling.
///
/// A delegation family keeps its default `2^8`: its rows are invocations, not
/// halfwords, and it is the only height whose forward pass a machine holds
/// (`docs/spec/delegation.md` §9).
fn params(height: u32) -> ProgramParams {
    let mut heights = ProgramParams::defaults().heights;
    for (f, h) in heights.iter_mut().enumerate() {
        if program::delegation_ecall(f as u32).is_none() {
            *h = height;
        }
    }
    ProgramParams {
        heights,
        bytecode_size_words: revm_block::BYTECODE_SIZE_WORDS,
        ..ProgramParams::defaults()
    }
}

/// The image at whichever of this program's two heights holds its code.
///
/// `--release` fits `2^20`; `debug` is 3.3 times larger and needs `2^22`.
/// Asking in that order is how a test decides without knowing which profile
/// it built.
fn preprocess(image: &ProgramImage) -> (DecodedTables, VmConfig) {
    let mut refused = None;
    for height in [
        revm_block::TRACE_HEIGHT_RELEASE,
        revm_block::TRACE_HEIGHT_DEBUG,
    ] {
        match decode_program(image, &params(height)) {
            Ok(decoded) => return decoded,
            Err(e) => refused = Some(e),
        }
    }
    panic!("{}", refused.expect("the two heights are tried"))
}

/// One binary of `guests/revm-block`, built once per test binary per name.
///
/// The build is 25 s at `--release`, which is why it is cached: every test
/// that needs one is `#[ignore]`d, and the ones CI asks for share the build.
fn guest(bin: &str) -> &'static ProgramImage {
    static NORMATIVE: OnceLock<ProgramImage> = OnceLock::new();
    static EMBED: OnceLock<ProgramImage> = OnceLock::new();
    let cell = if bin == GUEST { &NORMATIVE } else { &EMBED };
    cell.get_or_init(|| load_elf(&guest_elf(bin)).unwrap_or_else(|e| panic!("{bin} loads: {e:?}")))
}

fn guest_elf(bin: &str) -> Vec<u8> {
    common::build_bin(GUEST, bin, &common::guest_profile())
}

/// One traced run: `(tables, config, traces, profile, execution)`.
fn traced(bin: &str, input: &[u8]) -> Traced {
    let image = guest(bin);
    let (tables, config) = preprocess(image);
    let io = GuestIo {
        input: input.to_vec(),
        hint: Vec::new(),
    };
    let (traces, log, profile, execution) =
        trace_run(image, &io, &tables, &config).unwrap_or_else(|e| panic!("{bin}: {e}"));
    assert_eq!(
        execution.exit_code,
        0,
        "{bin} exited {}: fd 2 said {}",
        execution.exit_code,
        String::from_utf8_lossy(&execution.stderr)
    );
    log.self_check(image).expect("the memory log balances");
    Traced {
        config,
        traces,
        log,
        profile,
        execution,
    }
}

struct Traced {
    config: VmConfig,
    traces: trace::FamilyTraces,
    log: trace::MemoryEventLog,
    profile: trace::CycleProfile,
    execution: emulator::Execution,
}

// ---------------------------------------------------------------------------
// The witness, which needs no guest
// ---------------------------------------------------------------------------

/// Must-be-exact 5 and 6: the committed bytes are a canonical witness, and
/// the same logical state has exactly one encoding.
#[test]
fn the_committed_witness_is_canonical() {
    let bytes = witness_bytes();
    assert_eq!(
        bytes.len(),
        revm_block::COMMITTED_WITNESS_BYTES,
        "revm_block::COMMITTED_WITNESS_BYTES is stale; the guest's fd 0 buffer is twice it"
    );
    let witness = BlockWitness::decode(&bytes).expect("the committed witness decodes");
    assert_eq!(witness.encode(), bytes, "re-encoding is the same bytes");

    // What is checked here is what the *decoder does not*: the decoder enforces
    // the ordering rules, so re-deriving them from a witness it just accepted
    // would be checking it against itself. The negative controls below are
    // where those rules are proved. These are the fixture's own properties.
    assert_eq!(witness.txs.len(), 2, "one transfer and one call");
    assert!(
        witness.stateless.is_none(),
        "the synthetic mode carries no stateless section"
    );
    assert!(witness.env.spec().is_some(), "the spec id names a hardfork");
}

/// A witness out of canonical order is refused, each rule by name. Without
/// this, "canonical" would be a comment: `postcard` is happy to decode any
/// order at all.
#[test]
fn a_witness_out_of_canonical_order_is_refused() {
    let good = BlockWitness::decode(&witness_bytes()).expect("the committed witness decodes");

    let mut swapped = good.clone();
    swapped.accounts.swap(0, 1);
    assert!(
        matches!(
            BlockWitness::decode(&postcard::to_allocvec(&swapped).unwrap()),
            Err(revm_block::WitnessError::AccountsNotSorted { .. })
        ),
        "accounts out of order are refused"
    );

    let mut repeated = good.clone();
    let first = repeated.accounts[0].clone();
    repeated.accounts.insert(1, first);
    assert!(matches!(
        BlockWitness::decode(&postcard::to_allocvec(&repeated).unwrap()),
        Err(revm_block::WitnessError::AccountsNotSorted { .. })
    ));

    let mut slots = good.clone();
    let account = slots
        .accounts
        .iter_mut()
        .find(|a| !a.slots.is_empty())
        .expect("one account has storage");
    account.slots.push(account.slots[0]);
    assert!(
        matches!(
            BlockWitness::decode(&postcard::to_allocvec(&slots).unwrap()),
            Err(revm_block::WitnessError::SlotsNotSorted { .. })
        ),
        "a repeated slot key is refused"
    );

    let mut spec = good.clone();
    spec.env.spec_id = u8::MAX;
    assert!(matches!(
        BlockWitness::decode(&postcard::to_allocvec(&spec).unwrap()),
        Err(revm_block::WitnessError::UnknownSpec { spec_id: 255 })
    ));

    let mut truncated = witness_bytes();
    truncated.pop();
    assert_eq!(
        BlockWitness::decode(&truncated),
        Err(revm_block::WitnessError::Malformed)
    );

    // Trailing bytes, which is the canonicity failure that does not look like
    // one: `postcard::from_bytes` decodes a prefix and ignores the rest, so a
    // padded witness would be a second encoding of one state — a second
    // `io_digest` for one execution, chosen by whoever writes fd 0.
    for tail in [&witness_bytes()[..], &[0u8][..]] {
        let mut padded = witness_bytes();
        padded.extend_from_slice(tail);
        assert_eq!(
            BlockWitness::decode(&padded),
            Err(revm_block::WitnessError::Malformed),
            "a witness with {} bytes appended is not a witness",
            tail.len()
        );
    }

    // The other padding channel, and the one that hides *inside* the message:
    // `postcard`'s varint decoder never requires the shortest form, so `81 00`
    // reads as 1 exactly as `01` does. Every byte of the fixture whose
    // continuation bit is clear and which is a varint's last byte is a place a
    // prover could widen; widening any of them must be refused. The sweep is
    // over the whole fixture rather than one hand-picked offset, so a decoder
    // that pinned only the first field would fail here.
    let base = witness_bytes();
    let mut widened = 0;
    for at in 0..base.len() {
        if base[at] & 0x80 != 0 {
            continue;
        }
        let mut padded = base[..at].to_vec();
        padded.push(base[at] | 0x80);
        padded.push(0);
        padded.extend_from_slice(&base[at + 1..]);
        if postcard::from_bytes::<BlockWitness>(&padded).as_ref()
            != postcard::from_bytes::<BlockWitness>(&base).as_ref()
        {
            // Widening that byte did not leave the value alone, so it was not
            // a varint's last byte: nothing to prove about it here.
            continue;
        }
        widened += 1;
        assert_eq!(
            BlockWitness::decode(&padded),
            Err(revm_block::WitnessError::Malformed),
            "a non-minimal varint at offset {at} decodes to the same witness and is accepted"
        );
    }
    assert!(
        widened >= 30,
        "only {widened} non-minimal forms were found, so the sweep is not \
         exercising the varints it was written for"
    );
}

/// Half of acceptance 4, and the half that needs no guest: native host revm
/// over the committed witness produces the committed output.
///
/// It is also the regression pin on revm itself — a version bump that changed
/// a gas schedule would land here first.
#[test]
fn native_revm_produces_the_committed_output() {
    let witness = BlockWitness::decode(&witness_bytes()).expect("the witness decodes");
    assert_eq!(
        revm_block::run(&witness).expect("the synthetic block executes"),
        output_bytes()
    );
}

/// Must-be-exact 7: the output commitment's shape, read back field by field.
///
/// The numbers are the workload's: a 21,000-gas ether transfer that spends
/// exactly the intrinsic cost, and a call that increments the counter from 5
/// to 6 and returns it. A change to either is a change to what this stage
/// proves, and it fails here rather than silently in a digest.
#[test]
fn the_output_commitment_has_the_frozen_shape() {
    let bytes = output_bytes();
    let mut at = 0;
    let mut take = |n: usize| {
        let slice = bytes[at..at + n].to_vec();
        at += n;
        slice
    };
    let mut records = Vec::new();
    for _ in 0..2 {
        let status = take(1)[0];
        let gas = u64::from_le_bytes(take(8).try_into().unwrap());
        let len = u32::from_le_bytes(take(4).try_into().unwrap()) as usize;
        records.push((status, gas, take(len)));
    }
    // 2 = Success, in `revm_block`'s encoding.
    assert_eq!(records[0].0, 2, "the transfer succeeds");
    assert_eq!(
        records[0].1, 21_000,
        "and spends the intrinsic cost exactly"
    );
    assert!(records[0].2.is_empty(), "a transfer returns nothing");
    assert_eq!(records[1].0, 2, "the call succeeds");
    assert_eq!(
        records[1].1, 29_340,
        "the call's gas: the intrinsic cost, the access list, a warm non-zero \
         SSTORE and one log"
    );
    assert_eq!(
        records[1].2,
        {
            let mut word = [0u8; 32];
            word[31] = 6;
            word.to_vec()
        },
        "the counter returns its new value, 5 + 1"
    );
    let logs = take(32);
    let post_state = take(32);
    assert_eq!(at, bytes.len(), "three sections and nothing after them");

    // Pinned, not merely non-zero. These are `keccak256` of the encodings in
    // `docs/spec/revm-block.md` §2.1 and §2.2, and those encodings are frozen:
    // without the literals here, changing one and regenerating the fixture
    // would leave every test in this file green, because every one of them
    // reads the regenerated fixture. A deliberate change edits these two lines
    // and says so in the spec.
    assert_eq!(
        test_support::to_hex(&logs),
        "5c3d64188bff0ac36b5fd75fe606a5f647bde688ac632d9d486b6c12746e877c",
        "the logs commitment"
    );
    assert_eq!(
        test_support::to_hex(&post_state),
        "ba19b113ca39ae7bb3f7aacabebca642a63029dac677c0c10fe88c07b8d8b2f5",
        "the post-state summary"
    );
}

/// Acceptance 5, over the committed frames: what the delegation computes on
/// every keccak input this workload produces is what an outside
/// implementation computes.
///
/// `emulator::keccak_f` **is the delegation**: it is the function the executor
/// runs for the ecall and the one the `KECCAK_F` circuit's forward pass is
/// checked against. `tiny-keccak` is the outside implementation. So what this
/// pins is the delegated answer against a reference, on the inputs this
/// workload actually produced — and it runs in the fast gate, without a guest.
///
/// The **software fallback** is a different function — `guest-sdk`'s own, which
/// no host test can link — and what holds it to the delegation on this workload
/// is [`a3_the_two_executors_commit_the_same_bytes`], where one binary runs
/// under both executors and commits the same bytes. The two together are the
/// chain: delegation against a reference here, delegation against fallback
/// there.
#[test]
fn a5_every_delegated_permutation_is_the_reference() {
    let frames = committed_frames();
    assert!(
        !frames.is_empty(),
        "the workload delegated no permutation, so the fixture proves nothing"
    );
    for (i, frame) in frames.iter().enumerate() {
        let start = lanes_of(frame);
        let (mut ours, mut theirs) = (start, start);
        emulator::keccak_f(&mut ours);
        tiny_keccak::keccakf(&mut theirs);
        assert_eq!(ours, theirs, "frame {i} diverges");
    }
}

// ---------------------------------------------------------------------------
// The guest
// ---------------------------------------------------------------------------

/// Acceptance 2: the derived `VmConfig` is the program's own.
///
/// `KECCAK_F` is in it because the image declares it — the guest reaches
/// `guest_sdk::keccak256` through `alloy-primitives`' `native-keccak` hook —
/// and S23's two delegation families are **not**, because nothing in this
/// image does `Fr` arithmetic. That is static detachment doing its job on a
/// program nobody wrote for it (`docs/spec/delegation.md` §7).
///
/// The partition is checked inside `decode_program`, which panics on a pc two
/// families claim; what is asserted here is the other half, that every
/// instruction in the image is a live row of exactly one family.
#[test]
#[ignore = "builds the revm guest from source"]
fn a2_the_family_set_is_the_program_s() {
    let image = guest(GUEST);
    let (tables, config) = preprocess(image);
    let families: Vec<u32> = config.families.iter().map(|(f, _)| *f).collect();

    for f in 0..family::COUNT {
        let present = families.contains(&f);
        let expected = f != family::POSEIDON2 && f != family::FR_ARITH;
        assert_eq!(
            present,
            expected,
            "family {} ({}) is {}present",
            f,
            program::family_name(f),
            if present { "" } else { "not " }
        );
    }
    assert_eq!(
        config.height(family::KECCAK_F),
        Some(1 << 8),
        "a delegation family keeps the delegation height"
    );

    let instructions = image
        .slots
        .iter()
        .filter(|s| matches!(s, Slot::Instruction { .. }))
        .count();
    let live: usize = tables
        .families
        .iter()
        .map(|t| (0..t.height as usize).filter(|r| t.is_live(*r)).count())
        .sum();
    assert_eq!(
        live, instructions,
        "every instruction is a live row of exactly one family"
    );
}

/// Acceptance 4: the guest's committed output is native host revm's.
///
/// This is the target differential the stage asks for, run live rather than
/// through a fixture: the same `revm_block::run`, compiled for a 64-bit host
/// and for `riscv32imac`, over the same witness. What it catches is everything
/// the two builds do not share — 32-bit `usize`, the bump allocator, and the
/// keccak hook, which is a delegation on one side and `alloy-primitives`'
/// software Keccak on the other.
#[test]
#[ignore = "builds the revm guest from source"]
fn a4_the_guest_agrees_with_native_revm() {
    let input = witness_bytes();
    let run = traced(GUEST, &input);
    let witness = BlockWitness::decode(&input).expect("the witness decodes");
    assert_eq!(
        run.execution.io.output,
        revm_block::run(&witness).expect("the block executes on the host"),
        "the guest and native revm disagree on the same witness"
    );
    assert_eq!(run.execution.io.output, output_bytes());
    assert_eq!(
        run.execution.io.input, input,
        "the guest consumed the whole witness"
    );

    // The embedded-witness binary is the same program over the same witness,
    // so it computes the same commitment -- it publishes the digest of it
    // rather than the bytes. `crates/prover/tests/revm.rs` proves that one.
    let embedded = traced(EMBEDDED, &[]);
    assert!(
        embedded.execution.io.output.is_empty(),
        "the embedded binary writes no fd 1"
    );
    assert_eq!(
        embedded.execution.regs[24..32],
        revm_block::output_digest_words(&run.execution.io.output),
        "the embedded binary leaves keccak256 of the same commitment in x24..x31"
    );
}

/// Acceptance 5, end to end: the delegation and the software fallback are the
/// same function behind one signature.
///
/// The harvested frames are what the delegation was handed on this workload,
/// and they are the committed fixture the fast test above checks. Harvesting
/// them here is also what keeps that fixture honest: a changed workload that
/// hashed different bytes would fail here, not silently pass there.
#[test]
#[ignore = "builds the revm guest from source"]
fn a5_the_harvested_frames_are_the_committed_ones() {
    let run = traced(GUEST, &witness_bytes());
    let buffer = run
        .traces
        .delegation(family::KECCAK_F)
        .expect("the guest declares the keccak family");
    let harvested: Vec<Vec<u32>> = (0..buffer.len())
        .map(|i| buffer.frame(i).iter().map(|q| q.read_value).collect())
        .collect();
    let committed = committed_frames();
    assert_eq!(
        harvested.len(),
        committed.len(),
        "the run delegated {} permutations, the fixture holds {}",
        harvested.len(),
        committed.len()
    );
    for (i, (ours, theirs)) in harvested.iter().zip(&committed).enumerate() {
        assert_eq!(ours.as_slice(), theirs.as_slice(), "frame {i}");
    }
}

/// Acceptance 3: the same binary under both executors commits the same bytes.
///
/// Under `crates/emulator` the delegation ecall runs the circuit's
/// permutation; under `qemu-riscv32`, which has no circuit, it answers
/// `-ENOSYS` and the SDK's software fallback runs. Neither the witness nor the
/// commitment changes, which is the whole claim.
///
/// The comparison is at the level of fd 1 and the exit status, not
/// instruction by instruction: `crates/emulator/tests/differential.rs` logs a
/// register file per instruction, and this workload runs two hundred thousand
/// of them (`docs/handoff/S20-orchestration.md` kept `guests/shards` out of
/// that suite for the same reason).
#[test]
#[ignore = "needs qemu-riscv32, and builds the revm guest from source"]
fn a3_the_two_executors_commit_the_same_bytes() {
    let input = witness_bytes();
    let ours = traced(GUEST, &input);
    let (code, theirs) = under_qemu(&guest_elf(GUEST), &input);
    assert_eq!(code, 0, "qemu ran the guest to a clean exit");
    assert_eq!(
        theirs, ours.execution.io.output,
        "the delegated and the software keccak give different commitments"
    );
    assert_eq!(theirs, output_bytes());
}

/// Run one guest under `qemu-riscv32` with `input` on fd 0, returning its exit
/// status and fd 1.
fn under_qemu(elf: &[u8], input: &[u8]) -> (i32, Vec<u8>) {
    let dir = std::env::temp_dir().join(format!("apogee-revm-qemu-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("creating the run directory");
    let path = dir.join(GUEST);
    fs::write(&path, elf).expect("writing the guest");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("marking the guest");
    let mut child = Command::new(common::qemu_binary())
        .arg(&path)
        .current_dir(&dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning qemu");
    child
        .stdin
        .take()
        .expect("stdin was piped")
        .write_all(input)
        .expect("writing fd 0");
    let out = child.wait_with_output().expect("waiting for qemu");
    let _ = fs::remove_dir_all(&dir);
    let code = out.status.code().unwrap_or_else(|| {
        panic!(
            "qemu ended on a signal: {}",
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (code, out.stdout)
}

/// Acceptance 9: the cycle count, the per-family occupancy and the shard plan,
/// printed for the handoff and asserted where a number is load-bearing.
#[test]
#[ignore = "builds the revm guest from source"]
fn a9_the_cycle_and_occupancy_report() {
    let run = traced(GUEST, &witness_bytes());
    let plan = plan_shards(&run.profile, &run.config);
    println!("revm-block at {}", common::guest_profile());
    println!("  cycles: {}", run.profile.total());
    // The provable binary's, beside it: the same program, its witness in the
    // image instead of on fd 0 and its output digest in `x24..x31` instead of
    // on fd 1, which is what `crates/prover/tests/revm.rs` proves.
    let embedded = traced(EMBEDDED, &[]);
    println!(
        "  {EMBEDDED} cycles: {} ({} keccak invocations against {})",
        embedded.profile.total(),
        embedded
            .traces
            .delegation(family::KECCAK_F)
            .expect("the keccak family")
            .len(),
        run.traces
            .delegation(family::KECCAK_F)
            .expect("the keccak family")
            .len()
    );
    println!(
        "  {:<22} {:>10} {:>10} {:>9}  shards",
        "family", "rows", "height", "occupancy"
    );
    for (f, height) in &run.config.families {
        let rows = run
            .traces
            .family(*f)
            .map(|t| t.len() as u64)
            .or_else(|| run.traces.delegation(*f).map(|t| t.len() as u64))
            .unwrap_or(0);
        let shards = plan.shards.iter().find(|(g, _)| g == f).expect("planned").1;
        println!(
            "  {:<22} {:>10} {:>10} {:>8.2}%  {shards}",
            program::family_name(*f),
            rows,
            height,
            100.0 * rows as f64 / *height as f64
        );
    }
    let windows = trace::init_windows(
        &run.log,
        run.config
            .height(family::INIT_TEARDOWN)
            .expect("a window family"),
    );
    println!("  RAM windows above 0: {windows:?}");

    assert!(run.profile.total() > 0);
    assert_eq!(
        plan.shards
            .iter()
            .find(|(f, _)| *f == family::KECCAK_F)
            .expect("the keccak family is planned")
            .1,
        1,
        "the workload's permutations fit one delegation shard"
    );
}

/// Acceptance 10: the image against the two ceilings it has to fit, reported
/// and asserted.
///
/// Both are consequences of the same rule — a decoded table is pc/2-indexed
/// and absolute — and they are what decides the height this program is proven
/// at. `2^20` rows reach pc `0x1ffffc`, so `.text` may run to 1.9375 MiB from
/// `RAM_ORIGIN`; the span ceiling is `revm_block::BYTECODE_SIZE_WORDS`.
#[test]
#[ignore = "builds the revm guest from source"]
fn a10_the_image_fits_its_declared_ceiling() {
    // Both binaries: the normative one is what the stage reports, and the
    // embedded one is what is *proved*, so it is the one whose image has to fit
    // window 0 and whose last instruction has to fit a `2^20` table.
    for bin in [GUEST, EMBEDDED] {
        measure(bin);
    }
}

fn measure(bin: &str) {
    let image = guest(bin);
    let text: usize = image
        .segments
        .iter()
        .map(|s| s.bytes.len())
        .max()
        .expect("the image has a segment");
    let file_end = image
        .segments
        .iter()
        .filter(|s| !s.bytes.is_empty())
        .map(|s| s.vaddr as u64 + s.bytes.len() as u64)
        .max()
        .expect("the image has file bytes");
    let span = (file_end - guest_memory::RAM_ORIGIN as u64).div_ceil(4);
    let slots = image.slots.len();
    let instructions = image
        .slots
        .iter()
        .filter(|s| matches!(s, Slot::Instruction { .. }))
        .count();
    let top = image
        .slots
        .iter()
        .rposition(|s| matches!(s, Slot::Instruction { .. }))
        .map(|i| image.slot_base as u64 + 2 * i as u64)
        .expect("the image has instructions");

    println!("{bin} at {}", common::guest_profile());
    println!("  .text bytes:          {text}");
    println!("  file-backed end:      {file_end:#x}");
    println!(
        "  span words:           {span} of {} ({:.1}%)",
        revm_block::BYTECODE_SIZE_WORDS,
        100.0 * span as f64 / revm_block::BYTECODE_SIZE_WORDS as f64
    );
    println!("  expanded slots:       {slots}");
    println!("  instruction slots:    {instructions}");
    println!("  last instruction pc:  {top:#x}");

    assert!(
        span <= revm_block::BYTECODE_SIZE_WORDS as u64,
        "{bin} spans {span} words, past the declared ceiling"
    );
    let config = preprocess(image).1;
    let height = config
        .height(family::ADD_SUB_LUI_AUIPC)
        .expect("the add/sub family is present");
    // The other ceiling, and the one that is easy to forget: window 0 is the
    // init family's `4 * height` bytes, and the image's file-backed bytes have
    // to end inside it or `decode_program` refuses the program outright.
    let window = 4 * config
        .height(family::INIT_TEARDOWN)
        .expect("a window family") as u64;
    assert!(
        file_end <= window,
        "{bin}'s file bytes end at {file_end:#x}, past window 0's {window:#x}"
    );
    assert!(
        top <= 2 * height as u64 - 4,
        "{bin}: pc {top:#x} is past what a {height}-row table reaches"
    );
    if common::guest_profile() == "release" {
        assert_eq!(
            height,
            revm_block::TRACE_HEIGHT_RELEASE,
            "the release image is proven at the height it declares"
        );
    }
}
