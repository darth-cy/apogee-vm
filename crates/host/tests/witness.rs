//! S25's recorder, against the committed mini-block fixture.
//!
//! Acceptances 1, 2 and 3 live here. None of them touches the network:
//! [`Rpc::cached`] refuses to, whatever `ETH_RPC_URL` says, so a machine with
//! an endpoint configured runs the same test as a machine without one. The
//! committed `rpc-cache/` directory is the snapshot they record against, and
//! it is exactly the responses the pinned block's recording read — the three
//! further blocks a refresh session checks are checked live and cached under
//! `target/`, never committed.
//!
//! The guest halves are `#[ignore]`d, because they build a 2 MB `revm`
//! image from source; CI asks for them by name, as it does for
//! `crates/emulator/tests/revm.rs`. Everything that can be asserted against
//! native revm alone runs in `cargo test --workspace`.

use std::path::PathBuf;

use host::fixture::{self, Mode, Pin};
use host::recorder::{self, TxRange};
use host::rpc::{self, Rpc};
use revm_block::BlockWitness;

/// The mini-block fixture's stem, as `tools/kat-gen/src/block.rs` writes it.
const STEM: &str = "mini-block";

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn read(name: String) -> Vec<u8> {
    let path = vectors().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn pin() -> Pin {
    Pin::from_bytes(&read(fixture::pin_file(STEM))).expect("the pin decodes")
}

fn witness_bytes() -> Vec<u8> {
    read(fixture::witness_file(STEM))
}

fn journal_bytes() -> Vec<u8> {
    read(fixture::journal_file(STEM))
}

/// A cache-only client over the committed snapshot.
fn cached() -> Rpc {
    Rpc::cached(rpc::cache_dir(&vectors()))
}

// ---------------------------------------------------------------------------
// The fixture itself
// ---------------------------------------------------------------------------

#[test]
fn the_fixture_is_what_its_pin_says() {
    let pin = pin();
    pin.check(&witness_bytes(), &journal_bytes())
        .expect("the committed files are the pinned ones");
    assert_eq!(pin.mode, Mode::Mini);
    assert_eq!(
        pin.txs_recorded, 2,
        "the mini-block records two transactions, so that inter-transaction \
         state carry is exercised"
    );
    assert!(
        pin.txs_in_block > pin.txs_recorded,
        "a mini-block is a prefix of a real block; this one is the whole of it, \
         so nothing about the prefix is being tested"
    );
}

#[test]
fn the_committed_witness_is_canonical() {
    let bytes = witness_bytes();
    let witness = BlockWitness::decode(&bytes).expect("the witness is canonical");
    assert_eq!(witness.encode(), bytes, "decode and encode are not inverse");
    assert_eq!(witness.txs.len(), 2);
    assert!(
        witness.stateless.is_none(),
        "the mini mode makes no state-root claim and carries no stateless section"
    );
    // Every account the execution touched is here, including the ones that do
    // not exist. An absent address is an error in `WitnessDb`, not an empty
    // account, so a witness that dropped one could not run at all.
    assert!(
        witness.accounts.len() >= 3,
        "a real block touches more than this"
    );
}

#[test]
fn the_spec_is_the_one_the_block_ran_under() {
    let pin = pin();
    let spec = recorder::mainnet_spec(pin.block_number).expect("a post-merge block");
    assert_eq!(
        spec as u8, pin.spec_id,
        "the fork table and the pin disagree about which hardfork block {} ran under",
        pin.block_number
    );
}

#[test]
fn the_fork_table_refuses_a_block_it_does_not_know() {
    assert!(
        recorder::mainnet_spec(1).is_err(),
        "a pre-merge block is refused rather than run under the newest rules"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 1 — recorder determinism
// ---------------------------------------------------------------------------

/// Record the same `(block, tx range)` twice against the cached snapshot; the
/// `BlockWitness` bytes are identical.
///
/// Both recordings are cache-only, so "identical" is a property of the
/// recorder — its `BTreeMap` ordering and the canonical encoding — and not of
/// the chain having stayed still. The third assertion is the one that makes
/// the first two mean something: neither recording reached the network, so
/// nothing outside this repository was consulted.
#[test]
fn a1_the_recorder_is_deterministic() {
    let pin = pin();
    let first = recorder::record(cached(), pin.block_number, TxRange::First(2))
        .expect("the first recording");
    let second = recorder::record(cached(), pin.block_number, TxRange::First(2))
        .expect("the second recording");
    assert_eq!(
        first.rpc_misses, 0,
        "the first recording reached the network"
    );
    assert_eq!(
        second.rpc_misses, 0,
        "the second recording reached the network"
    );
    assert_eq!(
        first.witness.encode(),
        second.witness.encode(),
        "two recordings of one block produced different bytes"
    );
    assert_eq!(
        first.witness.encode(),
        witness_bytes(),
        "the recording is not the committed fixture, so the fixture is stale"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 2 — the differential, native half
// ---------------------------------------------------------------------------

/// Native revm over the recorded witness produces the committed journal.
///
/// This is the half of acceptance 2 that needs no guest: the recorded witness
/// is *complete enough* that `revm_block::run`, reading nothing but the
/// witness through the strict [`revm_block::WitnessDb`], reproduces what the
/// recording computed while reading the live chain. The guest half —
/// `a2_the_guest_agrees_with_native_revm` below — is the same claim through the
/// emulator.
#[test]
fn a2_the_witness_alone_reproduces_the_journal() {
    let witness = BlockWitness::decode(&witness_bytes()).expect("the witness decodes");
    let journal = revm_block::run(&witness).expect("the block executes from the witness alone");
    assert_eq!(
        journal,
        journal_bytes(),
        "the witness does not reproduce the committed journal"
    );
}

#[test]
fn the_journal_fits_a_public_window() {
    assert!(
        journal_bytes().len() <= constants::guest_memory::PUBLIC_PAYLOAD_BYTES as usize,
        "the journal is {} bytes and a public window holds {}",
        journal_bytes().len(),
        constants::guest_memory::PUBLIC_PAYLOAD_BYTES
    );
}

// ---------------------------------------------------------------------------
// Acceptance 3 — the witness-completeness negative control
// ---------------------------------------------------------------------------

/// Delete one recorded storage slot and the run fails loudly.
///
/// This is the test that makes every other claim about the witness worth
/// something. Until S25 an absent slot read as zero and an absent account read
/// as empty, so a witness with a slot deleted from it ran happily and committed
/// a journal for a state nobody supplied — and since S-IO nothing binds the
/// witness, so "nobody supplied" means "the prover chose". `WitnessDb` refuses
/// instead, and this is the proof that the refusal reaches the execution rather
/// than sitting unused in a type.
///
/// Every slot is tried, not one hand-picked one: a database that refused only
/// the first account's slots would pass a single-case test.
#[test]
fn a3_a_deleted_slot_is_refused() {
    let witness = BlockWitness::decode(&witness_bytes()).expect("the witness decodes");
    let mut tried = 0;
    let mut refused = 0;
    for (a, account) in witness.accounts.iter().enumerate() {
        for s in 0..account.slots.len() {
            tried += 1;
            let mut damaged = witness.clone();
            damaged.accounts[a].slots.remove(s);
            // The witness is still canonical — the remaining slots still
            // ascend — so this is not a decoding failure. It is a reading
            // failure, which is the point, and `decode` of its own encoding is
            // how that is checked without making `canonical` public.
            BlockWitness::decode(&damaged.encode())
                .expect("deleting a slot leaves a canonical witness");
            if revm_block::run(&damaged).is_err() {
                refused += 1;
            }
        }
    }
    assert!(tried > 0, "the fixture records no storage slots to delete");
    assert_eq!(
        refused,
        tried,
        "{} of {tried} deleted slots were not noticed; the touch set is not load-bearing",
        tried - refused
    );
}

/// Delete one recorded account and the run fails loudly.
///
/// The same control one level up. S24 read an absent account as empty, which is
/// the more dangerous of the two defaults: a deleted contract reads as an EOA
/// with no code, so a `CALL` into it succeeds trivially rather than running its
/// code.
#[test]
fn a3_a_deleted_account_is_refused() {
    let witness = BlockWitness::decode(&witness_bytes()).expect("the witness decodes");
    let mut refused = 0;
    for a in 0..witness.accounts.len() {
        let mut damaged = witness.clone();
        damaged.accounts.remove(a);
        if revm_block::run(&damaged).is_err() {
            refused += 1;
        }
    }
    assert_eq!(
        refused,
        witness.accounts.len(),
        "{} of {} deleted accounts were not noticed",
        witness.accounts.len() - refused,
        witness.accounts.len()
    );
}

/// Changing what the witness says about an account changes the journal.
///
/// The complement of the two controls above, and the reason they are not the
/// whole story: a witness can be *complete* and still be wrong. Nothing binds
/// advice, so what a mini-block proof says is "this VM ran revm over this
/// canonical witness and got this journal" — and the journal has to move when
/// the witness does, or the pairing says nothing.
///
/// A **balance** is the right cell to move, and a storage slot is not. Every
/// account the execution touches is in the output commitment's post-state
/// summary with its balance and nonce verbatim (`docs/spec/revm-block.md`
/// §2.2), so a one-wei change is always visible. A storage slot is not always:
/// on this very fixture, one of the thirty-seven recorded slots is read by the
/// callee and then **overwritten unconditionally**, so its original value
/// reaches nothing observable and changing it leaves the journal identical.
/// That is a true fact about the workload rather than a gap in the binding, and
/// it is worth stating rather than asserting away: **the mini mode's journal
/// does not distinguish every witness**, only every witness the execution can
/// tell apart. `docs/handoff/S25-block.md` records it.
#[test]
fn a_changed_balance_changes_the_journal() {
    let witness = BlockWitness::decode(&witness_bytes()).expect("the witness decodes");
    let honest = revm_block::run(&witness).expect("the honest run");
    let mut moved = 0;
    let mut tried = 0;
    for a in 0..witness.accounts.len() {
        // Only accounts that exist: a non-existent one is recorded as all
        // zeros and giving it a balance makes it a different account, which is
        // a different test.
        if witness.accounts[a].nonce == 0
            && witness.accounts[a].balance == [0u8; 32]
            && witness.accounts[a].code.is_empty()
        {
            continue;
        }
        tried += 1;
        let mut damaged = witness.clone();
        // One wei more, which cannot overflow: no account holds 2^256 - 1 wei.
        for byte in damaged.accounts[a].balance.iter_mut().rev() {
            let (next, carried) = byte.overflowing_add(1);
            *byte = next;
            if !carried {
                break;
            }
        }
        match revm_block::run(&damaged) {
            Ok(journal) if journal != honest => moved += 1,
            // A sender who can no longer pay, or one who now can: still a
            // refusal to produce the honest journal, which is the claim.
            Err(_) => moved += 1,
            Ok(_) => {}
        }
    }
    assert!(tried > 0, "the fixture records no existing accounts");
    assert_eq!(
        moved,
        tried,
        "{} of {tried} one-wei balance changes left the journal identical",
        tried - moved
    );
}
