//! S24's fixtures: the synthetic block, what native revm makes of it, and the
//! keccak-f frames the guest's delegation hands over.
//!
//! This module is the **host-side fixture builder** the stage asks for. It
//! constructs the pre-state and the two transactions from the named constants
//! below, serializes the witness, runs `revm_block::run` natively over it, and
//! then builds and traces the guest and holds the two to one answer — so a
//! regeneration *is* the guest-versus-native-revm differential, and CI's
//! regenerate-and-diff re-runs it on every push.
//!
//! Three files, all under `crates/emulator/tests/vectors/`:
//!
//! | File | What |
//! | --- | --- |
//! | `revm_block_witness.bin` | the `BlockWitness`, `postcard`, fd 0's bytes |
//! | `revm_block_output.bin` | the output commitment, fd 1's bytes |
//! | `revm_block_keccak.bin` | every keccak-f frame the run delegated |
//!
//! Unlike `guests`, this group *is* run by a bare `cargo run -p kat-gen`. It
//! builds a guest, which that group is opt-in for, but for a reason that does
//! not apply here: what is committed is not the ELF's bytes but the run's
//! behaviour, and a keccak preimage never sees the panic-location strings that
//! make an ELF machine-dependent.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use constants::family;
use loader::ProgramImage;
use program::{decode_program, DecodedTables, ProgramParams, VmConfig};
use revm_block::{AccountWitness, BlockEnvWitness, BlockWitness, SpecId, TxWitness, Word32};

// ---------------------------------------------------------------------------
// The synthetic block
// ---------------------------------------------------------------------------

/// The chain the block is on.
const CHAIN_ID: u64 = 1;

/// The hardfork it runs under. The witness carries the discriminant, so it is
/// taken from the enum rather than written out; `revm_block`'s decoder turns
/// it back into a `SpecId` and refuses one no fork takes.
const SPEC_ID: u8 = SpecId::PRAGUE as u8;

/// The block height.
const BLOCK_NUMBER: u64 = 21_000_000;

/// The block timestamp, seconds since the epoch.
const BLOCK_TIMESTAMP: u64 = 1_735_689_600;

/// The block gas limit: mainnet's.
const BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// The base fee per gas, in wei.
const BASEFEE: u64 = 7;

/// What every transaction here pays per gas: above the base fee, so both are
/// payable and the beneficiary is actually credited.
const GAS_PRICE: u128 = 10;

/// The sender: one funded externally-owned account, and the only account with
/// a balance in the pre-state.
const SENDER: [u8; 20] = address(0x01);

/// Transaction 1's destination: an empty account that receives ether.
const RECIPIENT: [u8; 20] = address(0x02);

/// Transaction 2's destination: the deployed counter contract.
const COUNTER: [u8; 20] = address(0xc0);

/// The block's beneficiary, which collects every transaction's fee.
const BENEFICIARY: [u8; 20] = address(0xbe);

/// The sender's starting balance: one ether, which covers both transactions'
/// value and gas many times over.
const SENDER_BALANCE: u128 = 1_000_000_000_000_000_000;

/// What transaction 1 transfers: 0.001 ether.
const TRANSFER_VALUE: u128 = 1_000_000_000_000_000;

/// Transaction 1's gas limit: exactly an ether transfer's intrinsic cost, so
/// the transaction is payable and spends all of it.
const TRANSFER_GAS_LIMIT: u64 = 21_000;

/// Transaction 2's gas limit: enough for the intrinsic cost, a warm `SSTORE`
/// over a non-zero slot and one log, with room to spare.
const CALL_GAS_LIMIT: u64 = 200_000;

/// The counter's one storage slot.
const COUNTER_SLOT: u64 = 0;

/// What that slot holds before the block: a non-zero value, so transaction 2's
/// `SSTORE` is a warm non-zero-to-non-zero write rather than the zero-slot
/// special case, and so the witness's slot list is not empty.
const COUNTER_BEFORE: u64 = 5;

/// The counter's event, whose `keccak256` is the log's one topic.
const COUNTER_EVENT: &[u8] = b"Incremented(uint256)";

/// An address carrying `label` in its last byte, `0xee` in its first and zero
/// between: the addresses here are labels, and a label that reads as a number
/// in a dump is easier to follow than twenty bytes of noise.
///
/// **The leading `0xee` is load-bearing.** Every precompile lives at an
/// address whose first nineteen bytes are zero — `0x..01` is `ecrecover`,
/// `0x..02` is SHA-256, and the list grows with each fork — so a "just put the
/// label in the last byte" scheme picks one of them. The first draft of this
/// fixture sent transaction 1 to `0x..02` and got `OutOfGas(Precompile)`
/// instead of a transfer, because SHA-256 charges for a call the 21,000-gas
/// intrinsic left nothing for. A nonzero leading byte cannot collide with any
/// precompile at any fork, and [`synthetic_block`] asserts it.
const fn address(label: u8) -> [u8; 20] {
    let mut out = [0u8; 20];
    out[0] = 0xee;
    out[19] = label;
    out
}

/// A 32-byte big-endian word holding `value`.
fn word(value: u128) -> Word32 {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

/// The counter contract: `slot 0 += 1`, one log carrying the new value, and
/// the new value returned.
///
/// Hand-written EVM, so that what the block executes is exactly what is
/// written here and not what some compiler made of a source file:
///
/// ```text
///   5f      PUSH0                 [0]
///   54      SLOAD                 [old]
///   6001    PUSH1 0x01            [old, 1]
///   01      ADD                   [new]
///   80      DUP1                  [new, new]
///   5f      PUSH0                 [new, new, 0]
///   55      SSTORE                [new]          key 0, value new
///   5f      PUSH0                 [new, 0]
///   52      MSTORE                []             memory[0..32] = new
///   7f..    PUSH32 <topic>        [topic]
///   6020    PUSH1 0x20            [topic, 32]
///   5f      PUSH0                 [topic, 32, 0]
///   a1      LOG1                  []             offset 0, size 32, topic
///   6020    PUSH1 0x20            [32]
///   5f      PUSH0                 [32, 0]
///   f3      RETURN                               offset 0, size 32
/// ```
///
/// `PUSH0` is Shanghai's, which [`SPEC_ID`] is well past.
fn counter_code() -> Vec<u8> {
    let topic = revm_block::keccak(COUNTER_EVENT);
    let mut code = vec![
        0x5f, 0x54, 0x60, 0x01, 0x01, 0x80, 0x5f, 0x55, 0x5f, 0x52, 0x7f,
    ];
    code.extend_from_slice(&topic);
    code.extend_from_slice(&[0x60, 0x20, 0x5f, 0xa1, 0x60, 0x20, 0x5f, 0xf3]);
    code
}

/// The synthetic block: four accounts and two transactions, in the canonical
/// order `BlockWitness::decode` requires.
pub fn synthetic_block() -> BlockWitness {
    let mut accounts = vec![
        AccountWitness {
            address: SENDER,
            nonce: 0,
            balance: word(SENDER_BALANCE),
            code: Vec::new(),
            slots: Vec::new(),
        },
        AccountWitness {
            address: RECIPIENT,
            nonce: 0,
            balance: word(0),
            code: Vec::new(),
            slots: Vec::new(),
        },
        AccountWitness {
            address: BENEFICIARY,
            nonce: 0,
            balance: word(0),
            code: Vec::new(),
            slots: Vec::new(),
        },
        AccountWitness {
            address: COUNTER,
            nonce: 1,
            balance: word(0),
            code: counter_code(),
            slots: vec![(word(COUNTER_SLOT as u128), word(COUNTER_BEFORE as u128))],
        },
    ];
    accounts.sort_by_key(|a| a.address);
    for account in &accounts {
        assert_ne!(
            account.address[0], 0,
            "an address whose leading byte is zero may be a precompile"
        );
    }

    BlockWitness {
        env: BlockEnvWitness {
            chain_id: CHAIN_ID,
            spec_id: SPEC_ID,
            number: word(BLOCK_NUMBER as u128),
            beneficiary: BENEFICIARY,
            timestamp: word(BLOCK_TIMESTAMP as u128),
            gas_limit: BLOCK_GAS_LIMIT,
            basefee: BASEFEE,
            difficulty: word(0),
            // Post-merge, so `prevrandao` is present and `difficulty` is not
            // read. Zero is a legal beacon output and this block is synthetic.
            prevrandao: Some(word(0)),
            // Cancun and later require it, and this block carries no blob,
            // so the excess is zero and the blob gas price is its floor.
            excess_blob_gas: Some(0),
            // The price at zero excess is the EIP's minimum, whatever the update
            // fraction is: `fake_exponential(1, 0, f) = 1`.
            blob_gasprice: Some(1),
            slot_num: 0,
            // The synthetic block's two transactions read no ancestor hash, so
            // nothing is recorded here. S25 added the field and closed
            // `docs/spec/revm-block.md` §1.2's `BLOCKHASH` gap: an ancestor the
            // witness does not carry is now `DbError::UnknownBlockHash` rather
            // than `keccak256` of the block number's decimal string.
            block_hashes: Vec::new(),
        },
        accounts,
        txs: vec![
            // 1: a plain ether transfer to an empty account.
            TxWitness {
                caller: SENDER,
                to: Some(RECIPIENT),
                value: word(TRANSFER_VALUE),
                data: Vec::new(),
                gas_limit: TRANSFER_GAS_LIMIT,
                gas_price: GAS_PRICE,
                gas_priority_fee: None,
                nonce: 0,
                chain_id: Some(CHAIN_ID),
                access_list: Vec::new(),
                blob_hashes: Vec::new(),
                max_fee_per_blob_gas: None,
                authorizations: Vec::new(),
            },
            // 2: a call into the counter, with the slot it writes warmed by an
            // EIP-2930 access list -- which is what puts a non-empty access
            // list in the committed witness.
            TxWitness {
                caller: SENDER,
                to: Some(COUNTER),
                value: word(0),
                data: Vec::new(),
                gas_limit: CALL_GAS_LIMIT,
                gas_price: GAS_PRICE,
                gas_priority_fee: None,
                nonce: 1,
                chain_id: Some(CHAIN_ID),
                access_list: vec![(COUNTER, vec![word(COUNTER_SLOT as u128)])],
                blob_hashes: Vec::new(),
                max_fee_per_blob_gas: None,
                authorizations: Vec::new(),
            },
        ],
        stateless: None,
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

pub fn generate() {
    let witness = synthetic_block();
    let encoded = witness.encode();
    assert_eq!(
        BlockWitness::decode(&encoded).as_ref(),
        Ok(&witness),
        "the witness this builder writes is one its decoder accepts"
    );
    crate::write_bytes(
        "crates/emulator/tests/vectors/revm_block_witness.bin",
        &encoded,
    );
    println!("  BlockWitness: {} bytes", encoded.len());
    println!(
        "  revm_block::COMMITTED_WITNESS_BYTES must be {}",
        encoded.len()
    );

    let output = revm_block::run(&witness).expect("the synthetic block executes");
    crate::write_bytes(
        "crates/emulator/tests/vectors/revm_block_output.bin",
        &output,
    );

    let frames = guest_frames(&encoded, &output);
    let mut bytes = Vec::with_capacity(frames.len() * 4 * constants::keccak::FRAME_WORDS);
    for frame in &frames {
        for word in frame {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
    }
    crate::write_bytes(
        "crates/emulator/tests/vectors/revm_block_keccak.bin",
        &bytes,
    );
    println!("  keccak-f invocations: {}", frames.len());

    // S25's stateless mode, over a block built here rather than recorded: a
    // recorded one cannot have a complete node set, `eth_getProof` returning no
    // siblings (`src/stateless.rs`).
    crate::stateless::generate();
}

/// Build and trace the guest on this witness, hold its **journal** to native
/// revm's answer, and return every keccak-f frame its delegation handed over.
///
/// The build is the manual's, with everything that could reach rustc from the
/// ambient environment cleared, because this is the same command every other
/// from-source guest build in the repository runs.
fn guest_frames(input: &[u8], want_output: &[u8]) -> Vec<Vec<u32>> {
    let elf = build_guest("revm-block");
    let image = loader::load_elf(&elf).expect("the guest loads");
    let (tables, config) = preprocess(&image);
    // The witness is advice: the provable binary reads it with ordinary loads
    // from `guest_memory::ADVICE_ORIGIN` (`docs/spec/public-values.md` §6).
    let io = emulator::GuestIo {
        stdin: Vec::new(),
        input: Vec::new(),
        advice: input.to_vec(),
        hint: Vec::new(),
    };
    let (traces, _log, profile, execution) =
        emulator::trace_run(&image, &io, &tables, &config).expect("the guest runs");
    assert_eq!(execution.exit_code, 0, "the guest exits 0");
    assert_eq!(
        execution.io.output, want_output,
        "the guest's journal is not what native revm computed from the same witness"
    );
    println!("  guest cycles: {}", profile.total());
    let trace = traces
        .delegation(family::KECCAK_F)
        .expect("the guest declares the keccak family");
    assert!(
        !trace.is_empty(),
        "the workload delegated no keccak-f permutation, so the shim was not reached"
    );
    (0..trace.len())
        .map(|i| trace.frame(i).iter().map(|q| q.read_value).collect())
        .collect()
}

/// The guest, preprocessed at the smallest menu height its code fits.
///
/// `revm_block::BYTECODE_SIZE_WORDS` is the program's pinned span ceiling;
/// the height is whichever of `TRACE_HEIGHT_RELEASE` and `TRACE_HEIGHT_DEBUG`
/// this build needs, and asking the menu in order is how that is decided
/// without the caller having to know which profile it built.
fn preprocess(image: &ProgramImage) -> (DecodedTables, VmConfig) {
    let mut refused = None;
    for &height in &[
        revm_block::TRACE_HEIGHT_RELEASE,
        revm_block::TRACE_HEIGHT_DEBUG,
    ] {
        // Every family but a delegation family at `height`; a delegation
        // family keeps its default `2^8`, because its rows are invocations and
        // not halfwords and that is the only height whose forward pass a
        // machine holds (`docs/spec/delegation.md` §9).
        let mut heights = ProgramParams::defaults().heights;
        for (f, h) in heights.iter_mut().enumerate() {
            if program::delegation_ecall(f as u32).is_none() {
                *h = height;
            }
        }
        let params = ProgramParams {
            heights,
            bytecode_size_words: revm_block::BYTECODE_SIZE_WORDS,
            ..ProgramParams::defaults()
        };
        match decode_program(image, &params) {
            Ok(decoded) => return decoded,
            Err(e) => refused = Some(e),
        }
    }
    panic!("{}", refused.expect("the two heights are tried"))
}

/// One guest, built from source into a fresh target directory.
fn build_guest(name: &str) -> Vec<u8> {
    build_guest_bin(name, name)
}

/// One *binary* of one guest package, built from source into a fresh target
/// directory keyed on the binary rather than the package — so two binaries of
/// `guests/revm-block` do not wipe each other's work and pay two cold builds.
///
/// Public because the `block` group runs the same guest over recorded
/// witnesses; the two groups share one build helper rather than keeping two
/// copies equal.
pub fn build_guest_bin(name: &str, bin: &str) -> Vec<u8> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let target_dir = std::env::temp_dir().join(format!("apogee-kat-gen-{bin}"));
    let _ = fs::remove_dir_all(&target_dir);
    let mut command = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    command
        .current_dir(root.join("guests").join(name))
        .args(["build", "--target", "riscv32imac-unknown-none-elf"])
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
        .join("riscv32imac-unknown-none-elf/debug")
        .join(bin);
    let bytes = fs::read(&elf).unwrap_or_else(|e| panic!("reading {}: {e}", elf.display()));
    let _ = fs::remove_dir_all(&target_dir);
    bytes
}
