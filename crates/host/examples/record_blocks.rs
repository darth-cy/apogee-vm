//! Record the most recent finalized mini-blocks as `bench prove` fixtures.
//!
//!     ETH_RPC_URL=… cargo run --release -p host --example record_blocks -- <count>
//!
//! # Why this exists
//!
//! `tools/kat-gen`'s `block` group is the *fixture refresh*: it records one
//! block to the one committed stem `mini-block`, checks three more without
//! committing them, and re-records the pinned one from the cache. That is the
//! right shape for a fixture nobody may churn, and the wrong shape for a
//! measurement session, which wants **N different blocks each addressable by
//! `bench prove`**.
//!
//! `tools/bench`'s prove verb already takes a fixture stem
//! (`tools/bench/src/block.rs`'s `Options::fixture`) and already reports peak
//! RSS from `/proc/self/status` `VmHWM`, the shard plan, the proof bytes and the
//! five phase clocks. So the only missing piece is a writer that puts a *pin, a
//! witness and a journal* under an arbitrary stem, which is what this is. It
//! adds no dependency: `crates/host` already takes `revm-block`, `emulator`,
//! `loader` and `constants`.
//!
//! # What one run does, per block
//!
//! 1. Records the block's first `--txs` transactions against its parent state
//!    (`host::recorder::record`), into a **scratch** RPC cache under `target/`
//!    rather than the committed one, so a measurement session does not touch
//!    `crates/host/tests/vectors/rpc-cache`.
//! 2. Executes the witness under **native revm** for the journal
//!    (`revm_block::run`) — the oracle, running upstream's software field
//!    multiply because the root workspace is not patched.
//! 3. Executes the **guest** over the same witness in the emulator and requires
//!    the same journal. This is the cheap pre-flight: it costs seconds, it
//!    reports the cycle count that predicts the shard plan, and it rejects a
//!    block the prover would have spent a quarter of an hour rejecting.
//! 4. Writes `blk-<number>.json`, `blk-<number>-witness.bin` and
//!    `blk-<number>-journal.bin` beside the committed fixtures.
//!
//! A block that fails any step is **skipped with its reason** and the walk
//! continues downward, because recording an arbitrary recent block is
//! probabilistic: `docs/handoff/S25-block.md` §4 measures `MptError::
//! BlindedCollapse` at 29% of randomized deletion trials, and the mini mode's
//! journal is a per-transaction record against a 1,020-byte window
//! (`docs/spec/revm-block.md` §2), which a data-heavy transaction overruns.
//!
//! Nothing here is committed and nothing here is on a proving path.

use std::path::{Path, PathBuf};

use host::fixture::{self, Mode, Pin};
use host::recorder::{self, TxRange};
use host::rpc::{self, Rpc};

/// The mini-block's transaction count, as `tools/kat-gen/src/block.rs` pins it:
/// two, so inter-transaction state carry is exercised.
const MINI_TXS: usize = 2;

/// How far below the head to keep trying before giving up on a target count.
const OVERSAMPLE: u64 = 4;

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn scratch_cache() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/apogee-latest-blocks-cache")
}

/// One block's outcome, for the summary table.
struct Recorded {
    number: u64,
    txs_in_block: usize,
    gas_used: u64,
    cycles: u64,
    accounts: usize,
    slots: usize,
    witness_bytes: usize,
    journal_bytes: usize,
    rpc_misses: u64,
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut want = 5usize;
    let mut txs = MINI_TXS;
    let mut from: Option<u64> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--txs" => {
                txs = args[i + 1].parse().expect("--txs takes a number");
                i += 2;
            }
            "--from" => {
                from = Some(args[i + 1].parse().expect("--from takes a block number"));
                i += 2;
            }
            other => {
                want = other.parse().unwrap_or_else(|_| {
                    panic!("usage: record_blocks <count> [--from <block>] [--txs <n>]")
                });
                i += 1;
            }
        }
    }

    let cache = scratch_cache();
    let mut probe = Rpc::new(cache.clone());
    if !probe.online() {
        eprintln!(
            "record_blocks: {} is not set, so nothing was recorded.",
            rpc::ENDPOINT_VAR
        );
        std::process::exit(2);
    }

    let head = match from {
        Some(n) => n,
        None => finalized(&mut probe).expect("the endpoint answers for the finalized block"),
    };
    println!("record_blocks: walking down from {head}, want {want} blocks of {txs} txs each");

    // One guest build for the whole session, as the fixture refresh does: every
    // block below is pre-flighted on this image.
    let elf = fixture::build_revm_guest(Mode::Mini).expect("the revm guest builds");
    let image = loader::load_elf(&elf).expect("the guest ELF loads");
    println!("record_blocks: guest built, {} bytes of ELF\n", elf.len());

    let mut done: Vec<Recorded> = Vec::new();
    let mut skipped: Vec<(u64, String)> = Vec::new();
    let ceiling = want as u64 * OVERSAMPLE;
    let mut below = 0u64;
    while done.len() < want && below < ceiling {
        let number = head - below;
        below += 1;
        match record_one(&image, &cache, number, txs) {
            Ok(r) => {
                println!(
                    "  {:>10}  ok      {:>4} txs in block, {:>10} gas, {:>12} cycles, \
                     {:>4} accounts, {:>4} slots, {:>7} witness B, {:>4} journal B, \
                     {:>4} rpc",
                    r.number,
                    r.txs_in_block,
                    r.gas_used,
                    r.cycles,
                    r.accounts,
                    r.slots,
                    r.witness_bytes,
                    r.journal_bytes,
                    r.rpc_misses
                );
                done.push(r);
            }
            Err(why) => {
                println!("  {number:>10}  SKIP    {why}");
                skipped.push((number, why));
            }
        }
    }

    println!(
        "\nrecord_blocks: {} recorded, {} skipped",
        done.len(),
        skipped.len()
    );
    if done.len() < want {
        println!(
            "record_blocks: wanted {want} and got {} after {below} candidates; \
             raise OVERSAMPLE or pass --from lower",
            done.len()
        );
    }
    println!("\nstems, in the order they were recorded:");
    for r in &done {
        println!("blk-{}", r.number);
    }
    // A machine-readable line per block, for the report's own table. Tab
    // separated, so `cut` works and no quoting question arises.
    println!("\nTSV\tnumber\ttxs_in_block\tgas_used\tcycles\tcycles_per_gas\taccounts\tslots\twitness_bytes\tjournal_bytes");
    for r in &done {
        println!(
            "TSV\t{}\t{}\t{}\t{}\t{:.2}\t{}\t{}\t{}\t{}",
            r.number,
            r.txs_in_block,
            r.gas_used,
            r.cycles,
            if r.gas_used == 0 {
                0.0
            } else {
                r.cycles as f64 / r.gas_used as f64
            },
            r.accounts,
            r.slots,
            r.witness_bytes,
            r.journal_bytes
        );
    }
}

/// Record, pre-flight and write one block. `Err` is a reason to skip it.
fn record_one(
    image: &loader::ProgramImage,
    cache: &Path,
    number: u64,
    txs: usize,
) -> Result<Recorded, String> {
    let recording = recorder::record(Rpc::new(cache.to_path_buf()), number, TxRange::First(txs))
        .map_err(|e| format!("does not record: {e}"))?;
    let witness_bytes = recording.witness.encode();
    let journal =
        revm_block::run(&recording.witness).map_err(|e| format!("native revm refuses it: {e}"))?;

    let window = constants::guest_memory::PUBLIC_PAYLOAD_BYTES as usize;
    if journal.len() > window {
        return Err(format!(
            "journal is {} bytes and a public window holds {window} \
             (docs/spec/revm-block.md §2 carries a record per transaction)",
            journal.len()
        ));
    }

    // The pre-flight: the guest over the same witness, in the emulator. Cheap,
    // and it yields the cycle count that predicts the shard plan.
    let io = emulator::GuestIo {
        input: Vec::new(),
        advice: witness_bytes.clone(),
    };
    let execution = emulator::run(image, &io).map_err(|e| format!("the guest faults: {e:?}"))?;
    if execution.exit_code != 0 {
        return Err(format!("the guest exits {}", execution.exit_code));
    }
    if execution.io.output != journal {
        return Err("the guest's journal is not what native revm computed".to_string());
    }

    let gas_used = tx_gas(&journal, recording.witness.txs.len());
    let pin = Pin {
        mode: Mode::Mini,
        block_number: number,
        block_hash: rpc::hex_data(&recording.block_hash),
        parent_hash: rpc::hex_data(&recording.parent_hash),
        parent_state_root: rpc::hex_data(&recording.parent_state_root),
        state_root: rpc::hex_data(&recording.state_root),
        spec_id: recording.witness.env.spec_id,
        txs_recorded: recording.witness.txs.len(),
        txs_in_block: recording.txs_in_block,
        gas_used,
        accounts: recording.witness.accounts.len(),
        slots: recording
            .witness
            .accounts
            .iter()
            .map(|a| a.slots.len())
            .sum(),
        witness_bytes: witness_bytes.len(),
        witness_sha256: test_support::to_hex(&test_support::sha256(&witness_bytes)),
        journal_bytes: journal.len(),
        journal_sha256: test_support::to_hex(&test_support::sha256(&journal)),
    };

    let stem = format!("blk-{number}");
    let dir = vectors();
    write(&dir.join(fixture::witness_file(&stem)), &witness_bytes);
    write(&dir.join(fixture::journal_file(&stem)), &journal);
    write(&dir.join(fixture::pin_file(&stem)), &pin.to_bytes());

    Ok(Recorded {
        number,
        txs_in_block: pin.txs_in_block,
        gas_used,
        cycles: execution.cycle_count,
        accounts: pin.accounts,
        slots: pin.slots,
        witness_bytes: pin.witness_bytes,
        journal_bytes: pin.journal_bytes,
        rpc_misses: recording.rpc_misses,
    })
}

fn write(path: &std::path::Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap_or_else(|e| panic!("writing {}: {e}", path.display()));
}

/// Gas the recorded transactions used, read off the journal's per-transaction
/// records exactly as `tools/kat-gen/src/block.rs`'s `tx_gas` does:
/// `status ‖ gas_used(8) ‖ len(4) ‖ output`.
fn tx_gas(journal: &[u8], txs: usize) -> u64 {
    let mut at = 0usize;
    let mut total = 0u64;
    for _ in 0..txs {
        if at + 13 > journal.len() {
            return total;
        }
        let gas = u64::from_le_bytes(journal[at + 1..at + 9].try_into().expect("eight bytes"));
        let len = u32::from_le_bytes(journal[at + 9..at + 13].try_into().expect("four bytes"));
        total += gas;
        at += 13 + len as usize;
    }
    total
}

/// The block number of the most recent finalized block. Not cached: "finalized"
/// moves, and everything downstream names an explicit height.
fn finalized(rpc: &mut Rpc) -> Result<u64, String> {
    let header = rpc.call_uncached(
        "eth_getBlockByNumber",
        serde_json::json!(["finalized", false]),
    )?;
    rpc::u64_of(&header["number"], "the finalized block number")
}
