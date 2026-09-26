//! The **stateless** block transition: the pre-state authenticated against the
//! parent's state root, the whole block run — system calls, transactions,
//! withdrawals — and the post-state root recomputed and checked.
//!
//! This is the second of S25's two modes, and must-be-exact 2 says why they are
//! two: *"The two modes are SEPARATE guest binary paths. Use two identities for
//! two modes."* The mini mode ([`crate::run`]) executes a prefix of a block
//! against its real pre-state and **claims no state root**; this one drives the
//! complete transition and claims one. They are separate binaries because they
//! publish different things and because a verifier reading a journal should not
//! have to ask which of two meanings it has.
//!
//! # What the journal says, and why it is not §2's
//!
//! `docs/spec/revm-block.md` §2's output commitment carries a record per
//! transaction. That is 45 bytes each on this workload, so a 246-transaction
//! block's would be about 11 KB against a public window's 1,020
//! (`docs/spec/public-values.md` §3). §2 is **frozen** and this mode does not
//! amend it: it publishes a journal of its own instead, [`STATELESS_JOURNAL_BYTES`] long
//! whatever the block, which digests §2's record stream rather than carrying
//! it. `docs/spec/public-values.md` §9 recommends exactly that —
//! *"public values are what a verifier reads, and a per-transaction record is
//! not"*.
//!
//! The two roots are what make it worth reading. Nothing binds advice, so a
//! witness is a byte string the prover chose; what a stateless proof says is
//! **"from the state whose root is P, this block produced the state whose root
//! is Q"**, and a verifier who knows the real P for this height — from a header
//! they trust, which is outside the proof, exactly as program identity is —
//! learns that Q is this block's post-state.
//!
//! # The order, which is consensus and not a choice
//!
//! 1. EIP-4788's beacon-roots system call, from Cancun.
//! 2. EIP-2935's block-hash history system call, from Prague.
//! 3. Every transaction, in order, under the block's running gas bound.
//! 4. EIP-4895's withdrawals.
//!
//! System calls are gas-free and are **not** added to the block's `gasUsed`;
//! `run_stateless` keeps the running bound over transactions alone, which is
//! what the Yellow Paper's `gasUsed <= gasLimit` is about.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use revm::context::{BlockEnv, CfgEnv};
use revm::context_interface::result::ExecutionResult;
use revm::context_interface::{ContextTr, JournalTr};
use revm::primitives::{address, keccak256, Address, Bytes, Log, U256};
use revm::state::EvmState;
use revm::{Context, ExecuteEvm, MainBuilder, MainContext, SystemCallEvm};

use crate::mpt::{self, MptError, Node, NodeMap, EMPTY_TRIE_ROOT};
use crate::{
    block_env, encode_logs, tx_env, AccountWitness, Address20, BlockWitness, SpecId,
    StatelessWitness, WitnessDb, Word32,
};

/// EIP-4788's beacon-roots contract.
///
/// The four system-contract addresses are not public constants anywhere in the
/// revm 42 tree — they live in `alloy-eips`, which is in neither of this
/// repository's lockfiles — so they are written here. Each is checked against
/// its EIP in `crates/host/tests/stateless.rs`.
const BEACON_ROOTS: Address = address!("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02");

/// EIP-2935's block-hash history contract.
const HISTORY_STORAGE: Address = address!("0x0000F90827F1C53a10cb7A02335B175320002935");

/// EIP-7002's withdrawal-request predeploy.
const WITHDRAWAL_REQUESTS: Address = address!("0x00000961Ef480Eb55e80D19ad83579A64c007002");

/// EIP-7251's consolidation-request predeploy.
const CONSOLIDATION_REQUESTS: Address = address!("0x0000BBdDc7CE488642fb579F8B00f3a590007251");

/// Gwei to wei. A withdrawal's amount is the consensus layer's unit.
const GWEI: u64 = 1_000_000_000;

/// The stateless mode's journal: 148 bytes, whatever the block.
///
/// ```text
///   parent_state_root     32 bytes   what the pre-state was authenticated against
///   post_state_root       32 bytes   what this execution recomputed
///   block_number           8 bytes LE
///   gas_used               8 bytes LE  transactions only; system calls are gas-free
///   tx_count               4 bytes LE
///   receipts_commitment   32 bytes   keccak256 of `docs/spec/revm-block.md` §2's
///                                    per-transaction record stream
///   logs_commitment       32 bytes   keccak256 of §2.1
/// ```
///
/// The two commitments are §2's own encodings, digested rather than carried, so
/// a reader who wants the records can recompute them from the witness and check
/// the digest. There is no post-state *summary* (§2.2): the post-state **root**
/// supersedes it, being a commitment to the whole state rather than to the part
/// this execution touched.
pub const STATELESS_JOURNAL_BYTES: usize = 148;

/// Everything [`run_stateless`] refuses.
///
/// One variant per thing that can be wrong with a witness, because the guest's
/// exit status is all a failing run leaves behind and "the block did not run"
/// is not a useful thing to publish.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatelessError {
    /// The witness carries no stateless section, so it is a mini-block witness
    /// and this is the wrong binary for it.
    NotStateless,
    /// A trie node is malformed, missing, or the sparse trie does not re-hash
    /// to the root the witness claims.
    Trie(MptError),
    /// A recorded account is not what the state trie says it is at
    /// `parent_state_root`. **The witness is unauthenticated and the run
    /// stops** — must-be-exact 3.
    Unauthenticated { address: Address20 },
    /// A recorded storage slot is not what the account's storage trie says.
    UnauthenticatedSlot { address: Address20, key: Word32 },
    /// The recomputed post-state root is not the one the block claims.
    RootMismatch { computed: Word32, claimed: Word32 },
    /// revm refused something, or the block's gas bound did.
    NotExecutable(String),
}

impl From<MptError> for StatelessError {
    fn from(e: MptError) -> StatelessError {
        StatelessError::Trie(e)
    }
}

/// Run the whole block statelessly and return the journal's bytes.
///
/// `claimed_state_root` is the header's, and the run fails if the
/// recomputation does not equal it. It is an argument rather than a witness
/// field on purpose: a value the witness carried would be a value the prover
/// chose to be compared against itself. The caller — `src/stateless_main.rs` —
/// takes it from the **public input**, which the statement binds
/// (`docs/spec/public-values.md` §5.1), so the comparison is against something
/// outside the advice.
pub fn run_stateless(
    witness: &BlockWitness,
    claimed_state_root: &Word32,
) -> Result<Vec<u8>, StatelessError> {
    let stateless = witness
        .stateless
        .as_ref()
        .ok_or(StatelessError::NotStateless)?;
    let spec = witness
        .env
        .spec()
        .ok_or_else(|| StatelessError::NotExecutable(format!("spec id {}", witness.env.spec_id)))?;

    // 1. Build the sparse state trie and authenticate it against the parent's
    //    root. One assertion, and it is the one that catches every parse or
    //    encode bug at the moment it appears: a blinded subtree re-encodes to
    //    its own hash verbatim, so an untouched trie round-trips exactly.
    let db = NodeMap::new(&stateless.nodes);
    let mut state = mpt::build(&db, &stateless.parent_state_root)?;
    mpt::check_root(&state, &stateless.parent_state_root)?;

    // 2. Every recorded value is what the authenticated trie says it is.
    //    Resolving a reference through the node map *is* the authentication, so
    //    what is left is to check that the witness agrees with what the walk
    //    finds — and an unauthenticated entry is a hard stop, never a default.
    let mut storage: Vec<Node> = Vec::with_capacity(witness.accounts.len());
    for account in &witness.accounts {
        storage.push(authenticate(&db, &state, account)?);
    }

    // 3. The execution, against the witness's own values — which step 2 has now
    //    tied to the parent state root.
    let (results, evm_state, gas_used) = execute(witness, spec, stateless)?;

    // 4. The post-state, applied to the tries.
    let post = apply(&mut state, &mut storage, witness, &evm_state, spec)?;
    if post != *claimed_state_root {
        return Err(StatelessError::RootMismatch {
            computed: post,
            claimed: *claimed_state_root,
        });
    }

    Ok(journal(
        &stateless.parent_state_root,
        &post,
        &witness.env.number,
        gas_used,
        &results,
    ))
}

/// One account's recorded values against the state trie, and its storage trie
/// built and authenticated.
fn authenticate(
    db: &NodeMap,
    state: &Node,
    account: &AccountWitness,
) -> Result<Node, StatelessError> {
    let key = keccak256(account.address).0;
    let leaf = mpt::get(state, &mpt::nibbles(&key))?;
    let empty_code_hash = keccak256([]).0;
    let code_hash = if account.code.is_empty() {
        empty_code_hash
    } else {
        keccak256(&account.code).0
    };

    let storage_root = match leaf {
        None => {
            // The trie proves the account absent, so the witness must say so
            // too — with every field zero, which is the one shape `WitnessDb`
            // reports to revm as `None`.
            // Every field zero, `slots` included: an account the trie does not
            // have has no storage either, and a recorded slot on one would be
            // a value `WitnessDb` served that nothing authenticated.
            if account.nonce != 0
                || account.balance != [0u8; 32]
                || !account.code.is_empty()
                || !account.slots.is_empty()
            {
                return Err(StatelessError::Unauthenticated {
                    address: account.address,
                });
            }
            EMPTY_TRIE_ROOT
        }
        Some(bytes) => {
            let (nonce, balance, storage_root, trie_code_hash) = mpt::decode_account(&bytes)?;
            if nonce != account.nonce || balance != account.balance || trie_code_hash != code_hash {
                return Err(StatelessError::Unauthenticated {
                    address: account.address,
                });
            }
            storage_root
        }
    };

    // **Only materialise a storage trie when there is something in it to
    // authenticate.** An account whose slots the execution never reads needs no
    // storage node, and a witness that carried them would be carrying weight
    // nobody checks — `eth_getProof` does not return them either, which is how
    // this was found. `Blinded` is the representation for exactly that: it
    // re-encodes to its own hash, so the account's leaf keeps the storage root
    // it had, and any attempt to *update* it is `MissingNode` rather than a
    // silently empty trie. A slot written is a slot read first, so an account
    // with no recorded slots has no storage change either.
    if account.slots.is_empty() {
        return Ok(if storage_root == EMPTY_TRIE_ROOT {
            Node::Empty
        } else {
            Node::Blinded(storage_root)
        });
    }
    let trie = mpt::build(db, &storage_root)?;
    mpt::check_root(&trie, &storage_root)?;
    for (slot, value) in &account.slots {
        let key = keccak256(slot).0;
        let found = match mpt::get(&trie, &mpt::nibbles(&key))? {
            // A slot absent from the trie is zero, which is not a default: the
            // walk *proved* it absent, and a missing node would have been
            // `MptError::MissingNode` rather than `None`.
            None => [0u8; 32],
            Some(bytes) => mpt::decode_slot(&bytes)?,
        };
        if found != *value {
            return Err(StatelessError::UnauthenticatedSlot {
                address: account.address,
                key: *slot,
            });
        }
    }
    Ok(trie)
}

/// The system calls, the transactions and the withdrawals, in consensus order.
fn execute(
    witness: &BlockWitness,
    spec: SpecId,
    stateless: &StatelessWitness,
) -> Result<(Vec<ExecutionResult>, EvmState, u64), StatelessError> {
    let mut cfg = CfgEnv::new_with_spec(spec);
    cfg.chain_id = witness.env.chain_id;
    let block: BlockEnv = block_env(&witness.env);
    let mut evm = Context::mainnet()
        .with_db(WitnessDb::new(witness))
        .with_block(block)
        .with_cfg(cfg)
        .build_mainnet();

    // 1. EIP-4788, from Cancun: the parent beacon block root into the
    //    beacon-roots contract. `system_call_one` and not `system_call`,
    //    because the latter finalizes and this block keeps one journal across
    //    every call and transaction and finalizes exactly once.
    if spec.is_enabled_in(SpecId::CANCUN) {
        if let Some(root) = stateless.parent_beacon_block_root {
            evm.system_call_one(BEACON_ROOTS, Bytes::copy_from_slice(&root))
                .map_err(|e| StatelessError::NotExecutable(format!("the 4788 system call: {e}")))?;
        }
    }
    // 2. EIP-2935, from Prague: the parent hash into the history contract.
    if spec.is_enabled_in(SpecId::PRAGUE) {
        evm.system_call_one(
            HISTORY_STORAGE,
            Bytes::copy_from_slice(&stateless.parent_hash),
        )
        .map_err(|e| StatelessError::NotExecutable(format!("the 2935 system call: {e}")))?;
    }

    // 3. The transactions, under the block's running gas bound — the same rule
    //    `crate::run` applies and for the same reason (`docs/spec/revm-block.md`
    //    §1.4): revm checks one transaction against the header and has no
    //    cumulative gas of its own, and this function is the block executor.
    let mut results = Vec::with_capacity(witness.txs.len());
    let mut gas_used: u64 = 0;
    for (i, tx) in witness.txs.iter().enumerate() {
        let remaining = witness.env.gas_limit - gas_used;
        if tx.gas_limit > remaining {
            return Err(StatelessError::NotExecutable(format!(
                "transaction {i}'s gas limit {} does not fit in the block's remaining {remaining}",
                tx.gas_limit
            )));
        }
        let result: ExecutionResult = evm
            .transact_one(tx_env(tx))
            .map_err(|e| StatelessError::NotExecutable(format!("transaction {i}: {e}")))?;
        gas_used = gas_used
            .checked_add(result.tx_gas_used())
            .filter(|total| *total <= witness.env.gas_limit)
            .ok_or_else(|| {
                StatelessError::NotExecutable(format!(
                    "transaction {i} took the block past its gas limit"
                ))
            })?;
        results.push(result);
    }

    // 4. EIP-7002 and 5. EIP-7251, both from Prague and both **post**-block:
    //    the withdrawal-request and consolidation-request predeploys. revm
    //    makes neither for you -- `revm-handler`'s `SystemCallEvm` says in as
    //    many words that the client should make the calls an EIP requires
    //    before or after block execution -- and each dequeues its request queue
    //    and rewrites the queue head and tail, the excess counter and the
    //    per-block count. A block with either queue non-empty reaches a root
    //    the header does not carry without them.
    //
    //    They are called with **empty** input: an empty calldata is the system
    //    call, where a non-empty one is a user's request submission, and the
    //    two are different code paths in the same predeploy.
    //
    //    Here rather than after the withdrawals because that is the order
    //    go-ethereum's `Process` uses. Nothing rests on it: the two predeploys
    //    and the withdrawal recipients are disjoint accounts, so the two
    //    orderings give the same root.
    if spec.is_enabled_in(SpecId::PRAGUE) {
        evm.system_call_one(WITHDRAWAL_REQUESTS, Bytes::new())
            .map_err(|e| StatelessError::NotExecutable(format!("the 7002 system call: {e}")))?;
        evm.system_call_one(CONSOLIDATION_REQUESTS, Bytes::new())
            .map_err(|e| StatelessError::NotExecutable(format!("the 7251 system call: {e}")))?;
    }

    // 6. EIP-4895's withdrawals. revm models none of this — a grep for
    //    `withdrawal` across all twelve revm 42 crates finds nothing — so the
    //    block executor credits them itself. Through the **journal**, not the
    //    database: `finalize` returns the journal's own state map, so a credit
    //    made straight to the database would change every later read and be
    //    invisible in the post-state.
    for withdrawal in &stateless.withdrawals {
        let wei = U256::from(withdrawal.amount_gwei) * U256::from(GWEI);
        evm.ctx
            .journal_mut()
            .balance_incr(Address::from(withdrawal.address), wei)
            .map_err(|e| {
                StatelessError::NotExecutable(format!("withdrawal {}: {e}", withdrawal.index))
            })?;
    }
    // Seal them: a later failure would otherwise run `discard_tx` and silently
    // revert the credits.
    evm.ctx.journal_mut().commit_tx();

    let state = evm.finalize();
    Ok((results, state, gas_used))
}

/// Apply the finalized state to the tries and return the new state root.
fn apply(
    state: &mut Node,
    storage: &mut [Node],
    witness: &BlockWitness,
    evm_state: &EvmState,
    spec: SpecId,
) -> Result<Word32, StatelessError> {
    // revm's state is a hash map, whose order is neither stable across runs nor
    // the same on a 32-bit guest as on a 64-bit host. Sorting is what makes the
    // recomputation deterministic — the same reason
    // `docs/spec/revm-block.md` §2.2 sorts.
    let mut touched: Vec<(&Address, &revm::state::Account)> = evm_state.iter().collect();
    touched.sort_unstable_by_key(|(address, _)| **address);

    for (address, account) in touched {
        if !account.is_touched() {
            // Loaded and read, never written: the trie does not move.
            continue;
        }
        let key = keccak256(address).0;
        let path = mpt::nibbles(&key);

        // EIP-161: an account that is touched and **empty at the end of the
        // block** is removed. Emptiness is the whole test, and
        // `is_selfdestructed()` is deliberately not part of it: revm's
        // `SelfDestructed` bit is block-global and `commit_tx` leaves it set,
        // so once any transaction destroys an address, every later
        // transaction's view of that address still reads as destroyed. Reading
        // it here deleted an account a later transaction had refunded or
        // recreated -- one real Ethereum keeps, a non-zero balance not being
        // empty -- and deleted it before the `is_created()` branch below could
        // rebuild its storage.
        //
        // Emptiness reaches the same answer without the flag. An account
        // destroyed and not refunded finalizes with a zero balance, a zero
        // nonce and no code, so it is empty and goes; one refunded or recreated
        // is not empty and stays; and post-Cancun EIP-6780 leaves a
        // pre-existing contract's code in place, so sweeping its balance never
        // made it empty to begin with.
        if account.state_clear_aware_is_empty(spec) {
            *state = mpt::remove(core::mem::replace(state, Node::Empty), &path)?;
            continue;
        }

        // The account's storage trie, updated. A slot set to **zero is a
        // deletion**: there is no stored zero in a storage trie, and writing
        // one would give a wrong root that looks almost right.
        let at = witness
            .accounts
            .binary_search_by(|a| a.address.cmp(&address.0 .0))
            .map_err(|_| StatelessError::Unauthenticated {
                address: address.0 .0,
            })?;
        // A **created** account starts with an empty storage trie, whatever
        // the address held before. That can only differ from the authenticated
        // trie on the selfdestruct-then-recreate path, which EIP-6780 made rare
        // — but reading the old trie there would carry slots the account does
        // not have and give a wrong root, so the case is handled rather than
        // assumed away.
        // Before Cancun a selfdestruct wiped the account's storage outright, so
        // an address destroyed and then refunded -- but not recreated, which
        // would set `is_created()` -- must start from an empty trie too, or the
        // authenticated pre-state's slots survive a destruction that removed
        // them. EIP-6780 closed that path from Cancun on, where only a
        // same-transaction creation is destroyed and `is_created()` covers the
        // recreate.
        let wiped = account.is_created()
            || (!spec.is_enabled_in(SpecId::CANCUN) && account.is_selfdestructed());
        let mut trie = if wiped {
            Node::Empty
        } else {
            core::mem::replace(&mut storage[at], Node::Empty)
        };
        let mut slots: Vec<(&revm::primitives::StorageKey, &revm::state::EvmStorageSlot)> =
            account.storage.iter().collect();
        slots.sort_unstable_by_key(|(key, _)| **key);
        for (slot, cell) in slots {
            let value = cell.present_value;
            let key = keccak256(slot.to_be_bytes::<32>()).0;
            let path = mpt::nibbles(&key);
            trie = if value.is_zero() {
                mpt::remove(trie, &path)?
            } else {
                mpt::insert(trie, &path, mpt::encode_slot(&value.to_be_bytes::<32>()))?
            };
        }
        let storage_root = trie.root();
        storage[at] = trie;

        let value = mpt::encode_account(
            account.info.nonce,
            &account.info.balance.to_be_bytes::<32>(),
            &storage_root,
            &account.info.code_hash.0,
        );
        *state = mpt::insert(core::mem::replace(state, Node::Empty), &path, value)?;
    }
    Ok(state.root())
}

/// The journal's 148 bytes.
fn journal(
    parent_state_root: &Word32,
    post_state_root: &Word32,
    number: &Word32,
    gas_used: u64,
    results: &[ExecutionResult],
) -> Vec<u8> {
    // The per-transaction records, exactly as `docs/spec/revm-block.md` §2
    // writes them — digested rather than carried, because a real block's would
    // not fit a public window.
    let mut records = Vec::new();
    let mut logs: Vec<&Log> = Vec::new();
    for result in results {
        crate::push_record(&mut records, result);
        logs.extend(result.logs());
    }

    let mut out = Vec::with_capacity(STATELESS_JOURNAL_BYTES);
    out.extend_from_slice(parent_state_root);
    out.extend_from_slice(post_state_root);
    // The block number is a `u256` in the header and a `u64` everywhere a block
    // number is used; the low eight bytes are the number, and a chain that
    // outgrows them has other problems.
    out.extend_from_slice(&number[24..]);
    out.extend_from_slice(&gas_used.to_le_bytes());
    out.extend_from_slice(&(results.len() as u32).to_le_bytes());
    out.extend_from_slice(keccak256(&records).as_slice());
    out.extend_from_slice(keccak256(encode_logs(&logs)).as_slice());
    debug_assert_eq!(out.len(), STATELESS_JOURNAL_BYTES);
    out
}

/// A contract address named by an EIP, for a test that checks this file's
/// literals against the EIPs.
pub fn system_contracts() -> [(&'static str, Address20); 4] {
    [
        ("EIP-4788 beacon roots", BEACON_ROOTS.0 .0),
        ("EIP-2935 history storage", HISTORY_STORAGE.0 .0),
        ("EIP-7002 withdrawal requests", WITHDRAWAL_REQUESTS.0 .0),
        (
            "EIP-7251 consolidation requests",
            CONSOLIDATION_REQUESTS.0 .0,
        ),
    ]
}
