//! The `block` group: **the manual refresh command**, and the one place in
//! this repository that talks to the network.
//!
//!     ETH_RPC_URL=https://… cargo run -p kat-gen -- block
//!
//! It is **not in `DEFAULT_GROUPS`**, for the same reason `guests` is not: a
//! bare `cargo run -p kat-gen` is what CI runs before diffing every committed
//! vector directory, and S25's must-be-exact 4 says CI never touches RPC. Asking
//! for this group by name is the opt-in, and without `ETH_RPC_URL` it explains
//! itself and writes nothing.
//!
//! # What one refresh session does
//!
//! 1. Finds the most recent **finalized** block, which is what the stage's core
//!    algorithm names as the fixture's source.
//! 2. Records its first [`MINI_TXS`] transactions against the parent state and
//!    writes the mini-block fixture — the pin, the witness and the journal
//!    native revm computes from it.
//! 3. Repeats the recording for the [`REPEATED_BLOCKS`] blocks below it and
//!    holds each one's guest output to native revm's, **without committing
//!    them** — their RPC responses go to a scratch cache under `target/`. That is acceptance 2's *"Check the fixture block AND ≥3 recent
//!    mainnet blocks during one manual refresh session"* — the check that the
//!    recorder works on blocks nobody tuned it against, which one pinned
//!    fixture cannot demonstrate.
//! 4. Re-records the fixture block a second time, from the cache alone, and
//!    requires byte-identical witness bytes and zero network calls. That is
//!    acceptance 1, run at refresh time as well as in
//!    `crates/host/tests/witness.rs`, because a recorder that is deterministic
//!    only against a cache somebody curated is not the property that was asked
//!    for.
//!
//! The guest is built once and traced for every block checked, which is what
//! makes step 3 a *guest* differential and not a host one.

use std::path::{Path, PathBuf};

use host::fixture::{self, Mode, Pin};
use host::recorder::{self, TxRange};
use host::rpc::{self, Rpc};
use loader::load_elf;

/// The mini-block's transaction count.
///
/// **Two, and the stage says why**: *"The mini-block tx count is two, so
/// inter-tx state carry is exercised."* One transaction would prove the
/// recorder can read a pre-state; two proves the second sees the first's
/// writes, which is the only part of a block a single transaction cannot test.
pub const MINI_TXS: usize = 2;

/// How many further recent blocks a refresh session checks beyond the pinned
/// one. Three, which is acceptance 2's floor.
pub const REPEATED_BLOCKS: u64 = 3;

/// The fixture directory, under `crates/host/tests/vectors/`.
fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/host/tests/vectors")
}

/// The mini-block fixture's file stem.
pub const MINI_STEM: &str = "mini-block";

pub fn generate() {
    let cache = rpc::cache_dir(&vectors());
    let mut probe = Rpc::new(cache.clone());
    if !probe.online() {
        println!(
            "block: {} is not set, so nothing was recorded.",
            rpc::ENDPOINT_VAR
        );
        println!("       This group is the manual refresh and is the only thing in this");
        println!("       repository that talks to the network. CI never runs it.");
        return;
    }

    // **Idempotent.** A refresh re-records the block the committed pin already
    // names, so running it twice does not churn the fixture and does not
    // invalidate a proof measured against it. Picking a *new* block is the
    // deliberate act: delete the pin first.
    //
    //     rm crates/host/tests/vectors/mini-block.json
    //     ETH_RPC_URL=... cargo run -p kat-gen -- block
    let pinned = std::fs::read(vectors().join(fixture::pin_file(MINI_STEM)))
        .ok()
        .and_then(|bytes| Pin::from_bytes(&bytes).ok())
        .map(|pin| pin.block_number);
    let head = match pinned {
        Some(number) => {
            println!("block: refreshing the pinned block {number}; delete the pin to move on");
            number
        }
        None => {
            let head = finalized(&mut probe).expect("the endpoint answers for the finalized block");
            println!("block: no pin, so recording the finalized head {head}");
            head
        }
    };

    // One guest build for the whole session: every block checked below is run
    // on this image.
    let elf = crate::revm::build_guest_bin("revm-block", Mode::Mini.binary());
    let image = load_elf(&elf).expect("the guest ELF loads");

    // 1 and 2: the pinned fixture.
    let pin = record_mini(&image, &cache, head);

    // 3: the repeated-blocks check, on blocks nobody tuned the recorder against.
    //
    // Their responses go to a scratch cache under `target/`, not the committed
    // one: what is committed is the snapshot that re-records the *pinned*
    // block, and adding three more blocks' `eth_getProof` answers to it would
    // quadruple a fixture directory for evidence a reader cannot re-derive
    // anyway. These three are checked live, at refresh time, and reported.
    let scratch =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/apogee-block-refresh-cache");
    for below in 1..=REPEATED_BLOCKS {
        let number = head - below;
        let recording =
            recorder::record(Rpc::new(scratch.clone()), number, TxRange::First(MINI_TXS))
                .unwrap_or_else(|e| panic!("block {number} does not record: {e}"));
        let journal = revm_block::run(&recording.witness)
            .unwrap_or_else(|e| panic!("block {number} does not execute natively: {e}"));
        let guest = guest_journal(&image, &recording.witness.encode());
        assert_eq!(
            guest, journal,
            "block {number}: the guest's journal is not what native revm computed"
        );
        println!(
            "block: {number} agrees, {} accounts, {} bytes of witness, {} bytes of journal",
            recording.witness.accounts.len(),
            recording.witness.encode().len(),
            journal.len()
        );
    }

    // 4: determinism, from the cache alone.
    let again = recorder::record(
        Rpc::cached(cache.clone()),
        pin.block_number,
        TxRange::First(MINI_TXS),
    )
    .expect("the pinned block re-records from the cache");
    assert_eq!(
        again.rpc_misses, 0,
        "a second recording reached the network {} times, so the cache is incomplete",
        again.rpc_misses
    );
    let witness = std::fs::read(vectors().join(fixture::witness_file(MINI_STEM)))
        .expect("the witness that was just written");
    assert_eq!(
        again.witness.encode(),
        witness,
        "a second recording of the same block produced different bytes"
    );
    println!(
        "block: the recording is deterministic, {} cache hits",
        again.rpc_hits
    );
}

/// Record, check and write the pinned mini-block fixture.
fn record_mini(image: &loader::ProgramImage, cache: &Path, number: u64) -> Pin {
    let recording = recorder::record(
        Rpc::new(cache.to_path_buf()),
        number,
        TxRange::First(MINI_TXS),
    )
    .unwrap_or_else(|e| panic!("block {number} does not record: {e}"));
    let witness_bytes = recording.witness.encode();
    let journal = revm_block::run(&recording.witness)
        .unwrap_or_else(|e| panic!("block {number} does not execute natively: {e}"));
    assert!(
        journal.len() <= constants::guest_memory::PUBLIC_PAYLOAD_BYTES as usize,
        "the journal is {} bytes and a public window holds {}; \
         the mini mode's output commitment is `docs/spec/revm-block.md` §2, which \
         carries a record per transaction, so a block whose first {MINI_TXS} \
         transactions return a lot of data does not fit",
        journal.len(),
        constants::guest_memory::PUBLIC_PAYLOAD_BYTES
    );
    let guest = guest_journal(image, &witness_bytes);
    assert_eq!(
        guest, journal,
        "block {number}: the guest's journal is not what native revm computed"
    );

    // The stateless pass over the same touch set: the trie nodes that
    // authenticate every recorded account and slot against the **real** parent
    // state root. Committed beside the witness as `mini-block-nodes.bin`, and
    // what makes `crates/host/tests/stateless.rs` an external check of the
    // guest's Merkle-Patricia code rather than a check of it against itself.
    //
    // It is deliberately NOT a complete stateless witness: `eth_getProof`
    // carries the nodes on each key's own path and no siblings, so a block that
    // deletes a key cannot be applied from it. Authentication needs only the
    // paths, which is why this half is real data and the recomputation half is
    // synthetic (`docs/handoff/S25-block.md` §4).
    let parent = number - 1;
    let (nodes, _, misses) =
        recorder::collect_nodes(Rpc::new(cache.to_path_buf()), parent, &recording.witness)
            .unwrap_or_else(|e| panic!("block {number}'s proofs do not collect: {e}"));
    let stateless = revm_block::StatelessWitness {
        parent_state_root: recording.parent_state_root,
        parent_hash: recording.parent_hash,
        parent_beacon_block_root: None,
        withdrawals: Vec::new(),
        nodes,
    };
    let stateless_bytes = postcard::to_allocvec(&stateless).expect("a StatelessWitness encodes");
    println!(
        "block: {} authenticating trie nodes, {} bytes, {misses} more network calls",
        stateless.nodes.len(),
        stateless_bytes.len()
    );

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
    let dir = vectors();
    crate::write_bytes_at(&dir.join(fixture::witness_file(MINI_STEM)), &witness_bytes);
    crate::write_bytes_at(&dir.join(fixture::journal_file(MINI_STEM)), &journal);
    crate::write_bytes_at(
        &dir.join(format!("{MINI_STEM}-nodes.bin")),
        &stateless_bytes,
    );
    crate::write_bytes_at(&dir.join(fixture::pin_file(MINI_STEM)), &pin.to_bytes());
    println!(
        "block: pinned {number}, {} accounts, {} slots, {} witness bytes, {} journal bytes, \
         {} network calls",
        pin.accounts, pin.slots, pin.witness_bytes, pin.journal_bytes, recording.rpc_misses
    );
    pin
}

/// The block number of the most recent finalized block.
fn finalized(rpc: &mut Rpc) -> Result<u64, String> {
    // Not cached under a height, because "finalized" moves: this is the one
    // request whose answer is time-dependent, and caching it would pin a
    // refresh to whatever the chain looked like the first time anybody ran it.
    // Everything downstream names an explicit height and caches.
    let header = rpc.call_uncached(
        "eth_getBlockByNumber",
        serde_json::json!(["finalized", false]),
    )?;
    rpc::u64_of(&header["number"], "the finalized block number")
}

/// The gas the recorded transactions used, read back out of the journal.
///
/// The journal is `docs/spec/revm-block.md` §2 and its per-transaction records
/// carry `gas_used` already, so the total is derivable from bytes the proof
/// binds rather than something the recorder has to be trusted about.
fn tx_gas(journal: &[u8], txs: usize) -> u64 {
    let mut at = 0usize;
    let mut total = 0u64;
    for i in 0..txs {
        assert!(
            at + 13 <= journal.len(),
            "the journal is short of record {i}"
        );
        let gas = u64::from_le_bytes(journal[at + 1..at + 9].try_into().expect("eight bytes"));
        let len = u32::from_le_bytes(journal[at + 9..at + 13].try_into().expect("four bytes"));
        total += gas;
        at += 13 + len as usize;
    }
    total
}

/// The journal the **guest** produces for one witness.
///
/// The witness reaches it as advice and the journal comes back out of the
/// public output window, which is the arrangement S-IO built and the one a
/// proof binds. `emulator::run` needs only the image — the decoded tables are
/// a tracing concern and this check is about the answer, not the trace.
fn guest_journal(image: &loader::ProgramImage, witness: &[u8]) -> Vec<u8> {
    let io = emulator::GuestIo {
        stdin: Vec::new(),
        input: Vec::new(),
        advice: witness.to_vec(),
        hint: Vec::new(),
    };
    let execution = emulator::run(image, &io).expect("the guest runs");
    assert_eq!(
        execution.exit_code, 0,
        "the guest exited {} rather than 0",
        execution.exit_code
    );
    execution.io.output
}
