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
use std::path::PathBuf;
use std::sync::OnceLock;

use constants::{family, guest_memory, keccak};
use emulator::{lanes_of, trace_run, GuestIo};
use loader::{load_elf, ProgramImage, Slot};
use program::{decode_program, DecodedTables, ProgramParams, VmConfig};
use revm_block::{AccountWitness, BlockWitness, TxWitness};
use trace::plan_shards;

/// The guest: its witness arrives in the advice region and its output
/// commitment leaves in the journal.
const GUEST: &str = "revm-block";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn vector(name: &str) -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The committed witness: the bytes the guest is handed as advice.
fn witness_bytes() -> Vec<u8> {
    vector("revm_block_witness.bin")
}

/// The committed journal: what native revm makes of that witness.
fn output_bytes() -> Vec<u8> {
    vector("revm_block_output.bin")
}

/// Every keccak-f permutation the committed run delegated, as 50-word input
/// states — the frames of its **round-0** invocations, whose state word is the
/// permutation's input. Since S26d one invocation is one round, so harvesting
/// every frame would give 24 records per permutation and 23 of them would be
/// mid-permutation states; `tools/kat-gen/src/revm.rs` filters on the round
/// word, which is what keeps this fixture 200 bytes a permutation.
/// The output commitment's `count` per-transaction records, and the offset the
/// two 32-byte commitments begin at. `docs/spec/revm-block.md` §2.
fn tx_records(bytes: &[u8], count: usize) -> (Vec<(u8, u64, Vec<u8>)>, usize) {
    let mut at = 0;
    let mut records = Vec::new();
    for _ in 0..count {
        let status = bytes[at];
        let gas = u64::from_le_bytes(bytes[at + 1..at + 9].try_into().unwrap());
        let len = u32::from_le_bytes(bytes[at + 9..at + 13].try_into().unwrap()) as usize;
        at += 13;
        records.push((status, gas, bytes[at..at + len].to_vec()));
        at += len;
    }
    (records, at)
}

fn committed_frames() -> Vec<[u32; keccak::STATE_WORDS]> {
    let bytes = vector("revm_block_keccak.bin");
    let width = 4 * keccak::STATE_WORDS;
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

/// `guests/revm-block`, built once per test binary.
///
/// The build is 25 s at `--release`, which is why it is cached: every test
/// that needs it is `#[ignore]`d, and the ones CI asks for share the build.
fn guest() -> &'static ProgramImage {
    static IMAGE: OnceLock<ProgramImage> = OnceLock::new();
    IMAGE.get_or_init(|| load_elf(&guest_elf()).unwrap_or_else(|e| panic!("{GUEST} loads: {e:?}")))
}

fn guest_elf() -> Vec<u8> {
    common::build_guest(GUEST, &common::guest_profile())
}

/// One traced run: `(tables, config, traces, profile, execution)`.
///
/// The witness is **advice**, which is the only provable way in: it is
/// megabytes, and a statement has no room for it
/// (`docs/spec/public-values.md` §6). A guest that refuses it exits 61 or 62,
/// so a nonzero status is the whole diagnosis there is.
fn traced(input: &[u8]) -> Traced {
    let image = guest();
    let (tables, config) = preprocess(image);
    let io = GuestIo {
        input: Vec::new(),
        advice: input.to_vec(),
    };
    let (traces, log, profile, execution) =
        trace_run(image, &io, &tables, &config).unwrap_or_else(|e| panic!("{GUEST}: {e}"));
    assert_eq!(
        execution.exit_code, 0,
        "{GUEST} exited {}",
        execution.exit_code
    );
    log.self_check(&trace::InitialMemory {
        image,
        public_input: &io.input,
        advice: &io.advice,
    })
    .expect("the memory log balances");
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
        "revm_block::COMMITTED_WITNESS_BYTES is stale"
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
    // padded witness would be a second encoding of one state — a second advice
    // region for one execution, chosen by whoever fills it.
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
    let (records, mut at) = tx_records(&bytes, 2);
    let mut take = |n: usize| {
        let slice = bytes[at..at + n].to_vec();
        at += n;
        slice
    };
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

// ---------------------------------------------------------------------------
// What the synthetic mode does not carry
// ---------------------------------------------------------------------------

/// The fixture's header, one funded sender, one account holding `code`, and
/// one transaction per entry of `gas_limits` calling it.
///
/// Built here rather than committed: these are blocks the workload does not
/// contain, written to pin behaviour the committed fixture cannot reach. The
/// addresses lead with `0xee` for the reason `docs/spec/revm-block.md` §1.3
/// gives — every precompile's address is nineteen zero bytes and a label.
fn synthetic_witness(block_gas_limit: u64, code: Vec<u8>, gas_limits: &[u64]) -> BlockWitness {
    let committed = BlockWitness::decode(&witness_bytes()).expect("the committed witness decodes");
    let (mut sender, mut callee) = ([0xeeu8; 20], [0xeeu8; 20]);
    sender[19] = 1;
    callee[19] = 2;
    let mut balance = [0u8; 32];
    balance[23] = 1; // 2^64 wei, far above anything this block can spend

    let mut env = committed.env.clone();
    env.gas_limit = block_gas_limit;

    // Three accounts, not two: the **beneficiary** is read by every block that
    // pays a fee, and since S25 an address the witness does not carry is an
    // error rather than an empty account. It is recorded with every field zero,
    // which is how the witness says "asked about, and not there" — revm creates
    // it when the fee lands, exactly as it would on chain.
    let mut accounts = vec![
        AccountWitness {
            address: sender,
            nonce: 0,
            balance,
            code: Vec::new(),
            slots: Vec::new(),
        },
        AccountWitness {
            address: callee,
            nonce: 0,
            balance: [0u8; 32],
            code,
            slots: Vec::new(),
        },
        AccountWitness {
            address: env.beneficiary,
            nonce: 0,
            balance: [0u8; 32],
            code: Vec::new(),
            slots: Vec::new(),
        },
    ];
    accounts.sort_by_key(|a| a.address);

    BlockWitness {
        env,
        accounts,
        txs: gas_limits
            .iter()
            .enumerate()
            .map(|(i, limit)| TxWitness {
                caller: sender,
                to: Some(callee),
                value: [0u8; 32],
                data: Vec::new(),
                gas_limit: *limit,
                gas_price: 10,
                gas_priority_fee: None,
                nonce: i as u64,
                chain_id: Some(committed.env.chain_id),
                access_list: Vec::new(),
                blob_hashes: Vec::new(),
                max_fee_per_blob_gas: None,
                authorizations: Vec::new(),
            })
            .collect(),
        stateless: None,
    }
}

/// The block's gas limit is a **running** bound, and `revm_block::run` is what
/// enforces it.
///
/// revm checks `tx.gas_limit <= block.gas_limit` per transaction and can check
/// no more — `transact_one` is one transaction and revm keeps nothing across a
/// block — so without the accumulator in `run` a witness may carry any number
/// of transactions that individually fit and together do not. That is a block
/// no Ethereum node would accept, and the guest would commit an output for it.
#[test]
fn a_block_past_its_gas_limit_is_refused() {
    // A plain transfer to a codeless account: 21,000 gas, the intrinsic cost
    // exactly, so the arithmetic below is the test's and not a gas schedule's.
    const TRANSFER: u64 = 21_000;

    // The control, and it comes first: two transactions that fit, execute.
    let ok = synthetic_witness(50_000, Vec::new(), &[TRANSFER, TRANSFER]);
    let output = revm_block::run(&ok).expect("two transfers inside a 50,000-gas block execute");
    let (records, _) = tx_records(&output, 2);
    assert_eq!(
        records.iter().map(|r| r.1).sum::<u64>(),
        2 * TRANSFER,
        "and together they spend what the block had room for"
    );

    // One transaction over the whole block limit. revm refuses this one too,
    // with `CallerGasLimitMoreThanBlock`; `run` reaches it first and says so
    // in the block's terms.
    let over = synthetic_witness(20_000, Vec::new(), &[TRANSFER]);
    let refused = revm_block::run(&over).expect_err("a transaction may not exceed the block");
    assert!(
        refused.contains("does not fit in the block's remaining"),
        "unexpected refusal: {refused}"
    );

    // The one revm cannot see: each transaction fits the block's limit, and
    // the second does not fit what the first left. This is the case the
    // accumulator exists for.
    let cumulative = synthetic_witness(30_000, Vec::new(), &[TRANSFER, TRANSFER]);
    let refused = revm_block::run(&cumulative)
        .expect_err("the second transfer does not fit in the 9,000 gas the first left");
    assert!(
        refused.starts_with("transaction 1's gas limit 21000"),
        "unexpected refusal: {refused}"
    );
}
/// `BLOCKHASH` reads what the witness recorded, and **refuses what it did
/// not** — S24's one acknowledged gap, closed at S25.
///
/// S24 gave revm a `CacheDB<EmptyDB>` with an empty block-hash cache, so every
/// lookup fell through to `EmptyDB`, which returns `keccak256` of the block
/// number's decimal string. The old shape of this test asserted that
/// placeholder *on purpose*, so that closing the gap would have to be a
/// decision rather than an accident. This is that decision:
/// `BlockEnvWitness::block_hashes` carries the ancestors and
/// `WitnessDb::block_hash` errors on any other, which reaches the caller as a
/// refusal to execute rather than as a made-up word.
///
/// Both directions, because only the pair is the property: a recorded ancestor
/// is answered with the recorded hash, and an unrecorded one is refused.
#[test]
fn blockhash_reads_the_recorded_ancestor_and_refuses_the_rest() {
    let number = {
        let committed =
            BlockWitness::decode(&witness_bytes()).expect("the committed witness decodes");
        u64::from_be_bytes(committed.env.number[24..].try_into().unwrap())
    };
    let previous = number - 1;

    // PUSH4 <previous> ‖ BLOCKHASH ‖ PUSH0 ‖ MSTORE ‖ PUSH1 0x20 ‖ PUSH0 ‖ RETURN
    let mut code = vec![0x63];
    code.extend_from_slice(&(previous as u32).to_be_bytes());
    code.extend_from_slice(&[0x40, 0x5f, 0x52, 0x60, 0x20, 0x5f, 0xf3]);

    // Nothing recorded: the ancestor read is refused and the block does not
    // execute at all.
    let bare = synthetic_witness(1_000_000, code.clone(), &[100_000]);
    assert!(
        revm_block::run(&bare).is_err(),
        "an ancestor hash the witness does not carry was answered rather than refused"
    );

    // Recorded: the opcode reads exactly what was recorded, and nothing else.
    let mut ancestor = [0u8; 32];
    ancestor[0] = 0xa1;
    ancestor[31] = 0x5e;
    let mut witness = bare.clone();
    witness.env.block_hashes = vec![(previous, ancestor)];
    let output = revm_block::run(&witness).expect("the blockhash block executes");
    let (records, _) = tx_records(&output, 1);
    assert_eq!(records[0].0, 2, "the call succeeds");
    assert_eq!(
        records[0].2,
        ancestor.to_vec(),
        "BLOCKHASH answered something other than the recorded ancestor"
    );
    assert_ne!(
        records[0].2,
        revm_block::keccak(previous.to_string().as_bytes()).to_vec(),
        "BLOCKHASH is still answering EmptyDB's placeholder"
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
/// no host test can link — and this workload does not reach it: the executor
/// has the circuit, so every keccak in the image is the delegation. What holds
/// the fallback to the delegation is `guests/keccak-test`, which computes the
/// same corpus both ways and checks itself.
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
    let image = guest();
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
        Some(1 << 16),
        "a delegation family keeps its own height, and since S26d keccak's is 2^16"
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
    let run = traced(&input);
    let witness = BlockWitness::decode(&input).expect("the witness decodes");
    assert_eq!(
        run.execution.io.output,
        revm_block::run(&witness).expect("the block executes on the host"),
        "the guest and native revm disagree on the same witness"
    );
    assert_eq!(run.execution.io.output, output_bytes());
}

/// Acceptance 5, end to end: the delegation and the software fallback are the
/// same function behind one signature.
///
/// The harvested frames are what the delegation was handed on this workload,
/// and they are the committed fixture the fast test above checks. Harvesting
/// them here is also what keeps that fixture honest: a changed workload that
/// hashed different bytes would fail here, not silently pass there.
///
/// **Since S26d one invocation is one round**, so the fixture holds a
/// permutation's *input state*: the frame of each round-0 invocation with the
/// round word itself dropped. `tools/kat-gen/src/revm.rs`'s `guest_frames`
/// harvests exactly that, and this is the same reading over the same run.
///
/// The round count is the other half, and it is the only end-to-end evidence
/// that the guest shim really issues all 24 calls on a real workload: every
/// other check of the loop is row-local or in the fill. An invocation count that
/// is not `24 x` the permutation count means the shim stopped early, and the
/// frame comparison below would still pass on the prefix it did write.
#[test]
#[ignore = "builds the revm guest from source"]
fn a5_the_harvested_frames_are_the_committed_ones() {
    let run = traced(&witness_bytes());
    let buffer = run
        .traces
        .delegation(family::KECCAK_F)
        .expect("the guest declares the keccak family");
    let harvested: Vec<Vec<u32>> = (0..buffer.len())
        .filter(|i| buffer.frame(*i)[keccak::ROUND_WORD].read_value == 0)
        .map(|i| {
            buffer.frame(i)[keccak::STATE_WORD..]
                .iter()
                .map(|q| q.read_value)
                .collect()
        })
        .collect();
    let committed = committed_frames();
    assert_eq!(
        harvested.len(),
        committed.len(),
        "the run delegated {} permutations, the fixture holds {}",
        harvested.len(),
        committed.len()
    );
    assert_eq!(
        buffer.len(),
        committed.len() * keccak::ROUNDS,
        "one permutation is {} invocations: {} rounds delegated over {} permutations",
        keccak::ROUNDS,
        buffer.len(),
        committed.len()
    );
    for (i, (ours, theirs)) in harvested.iter().zip(&committed).enumerate() {
        assert_eq!(ours.as_slice(), theirs.as_slice(), "frame {i}");
    }
}

/// Acceptance 9: the cycle count, the per-family occupancy and the shard plan,
/// printed for the handoff and asserted where a number is load-bearing.
#[test]
#[ignore = "builds the revm guest from source"]
fn a9_the_cycle_and_occupancy_report() {
    let run = traced(&witness_bytes());
    let plan = plan_shards(&run.profile, &run.config);
    println!("revm-block at {}", common::guest_profile());
    println!("  cycles: {}", run.profile.total());
    println!(
        "  keccak invocations: {}",
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
        run.log.state(),
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
    let image = guest();
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

    println!("{GUEST} at {}", common::guest_profile());
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
        "{GUEST} spans {span} words, past the declared ceiling"
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
        "{GUEST}'s file bytes end at {file_end:#x}, past window 0's {window:#x}"
    );
    assert!(
        top <= 2 * height as u64 - 4,
        "{GUEST}: pc {top:#x} is past what a {height}-row table reaches"
    );
    if common::guest_profile() == "release" {
        assert_eq!(
            height,
            revm_block::TRACE_HEIGHT_RELEASE,
            "the release image is proven at the height it declares"
        );
    }
}
