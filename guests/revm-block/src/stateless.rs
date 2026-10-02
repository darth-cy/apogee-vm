//! The canonical stateless validator: `statelessInputBytes` in, the 43-byte
//! `statelessOutputBytes` out, exactly as `ethereum/execution-specs`'
//! `verify_stateless_new_payload` computes them at `tests-zkevm@v21.0.1`.
//!
//! **What a result says.** `(new_payload_request_root, successful_validation,
//! chain_id, schema_id)`: that the payload request whose SSZ root is the first
//! field is, or is not, valid on the chain `chain_id` under the fork
//! `schema_id` names, against the state its witness proves. Every input this
//! guest can decode produces a result, a failed validation included; an input
//! it cannot decode, or whose fork it does not validate, produces the all-zero
//! sentinel. The guest itself always exits 0.
//!
//! **What validation is**, in the spec's order (`stateless.py`,
//! `execution_engine/new_payload.py`, `fork.py`):
//!
//! 1. The ancestor headers decode and chain by `parent_hash`; the last is the
//!    parent, its state root the pre-state's, their hashes `BLOCKHASH`'s.
//! 2. No empty transaction; the header the payload implies hashes to the
//!    payload's `block_hash`; the blob transactions' versioned hashes are the
//!    request's; in ere-guests' layout, there is a public key per transaction.
//! 3. The block is under EIP-7934's size and its header obeys its parent.
//! 4. The block runs: EIP-4788 and EIP-2935's system calls, every transaction
//!    — signer recovered and any key held to it, chain id checked, admitted
//!    against the block's remaining gas and blob gas — then the withdrawals,
//!    then the requests: deposit logs and the checked system calls of
//!    EIP-7002, EIP-7251 and, from Amsterdam, EIP-8282.
//! 5. Gas used, receipts root, logs bloom, blob gas used, requests hash, the
//!    block access list's size and hash (Amsterdam) and the post-state root are
//!    the header's.
//!
//! **How it runs is reth's** (`paradigmxyz/stateless` over `alloy-evm`, the
//! reference stateless guest): the pre-state behind revm's `State`, and the
//! block access list index bumped between the system calls before the
//! transactions, each transaction, and the withdrawals and requests after
//! them. Each index is one commit, its baselines the committed state's
//! (`commit_index`), where the reference commits per call. **Where reth and
//! the spec differ, this is the spec's**, because the canonical result is the
//! spec's: system contracts must have code, deposit events are parsed to the
//! byte, withdrawals precede requests, and an Amsterdam transaction's gas
//! limit is bounded by `TX_MAX_TOTAL_GAS_LIMIT`.

use alloc::vec::Vec;

use revm::context::{BlockEnv, CfgEnv, TxEnv};
use revm::context_interface::block::BlobExcessGasAndPrice;
use revm::context_interface::either::Either;
use revm::context_interface::result::{ExecutionResult, Output};
use revm::context_interface::transaction::{
    AccessList, AccessListItem, Authorization, RecoveredAuthority, RecoveredAuthorization,
};
use revm::context_interface::JournalTr;
use revm::database::states::bundle_state::BundleRetention;
use revm::database::{BundleState, State};
use revm::handler::system_call::SYSTEM_ADDRESS;
use revm::handler::MainnetContext;
use revm::primitives::{address, Address, Bytes, TxKind, B256, KECCAK_EMPTY, U256};
use revm::{
    Context, Database, ExecuteCommitEvm, ExecuteEvm, MainBuilder, MainContext, MainnetEvm,
    SystemCallEvm,
};

use crate::block::{self, Header, HeaderError, Log};
use crate::mpt::{self, MptError, Node, EMPTY_TRIE_ROOT};
use crate::ssz::{self, ExecutionWitness, NewPayloadRequest, StatelessInput};
use crate::tx::{self, Tx};
use crate::witness::{WitnessDb, WitnessError};
use crate::{keccak, Address20, Word32};

/// EIP-4788's beacon-roots contract.
const BEACON_ROOTS: Address = address!("0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02");
/// EIP-2935's block-hash history contract.
const HISTORY_STORAGE: Address = address!("0x0000F90827F1C53a10cb7A02335B175320002935");
/// The checked system calls, in the spec's order, each with the request type
/// its output becomes. The last two are Amsterdam's (EIP-8282).
const REQUEST_CONTRACTS: [(Address, u8); 4] = [
    (address!("0x00000961Ef480Eb55e80D19ad83579A64c007002"), 1),
    (address!("0x0000BBdDc7CE488642fb579F8B00f3a590007251"), 2),
    (address!("0x0000BFF46984E3725691FA540A8C7589300D8282"), 3),
    (address!("0x000064D678505AD48F8CCB093BC65613800E8282"), 4),
];

/// Gwei to wei.
const GWEI: u128 = 1_000_000_000;

/// EIP-7825's per-transaction execution-gas cap.
const TX_MAX_GAS_LIMIT: u64 = 1 << 24;
/// EIP-8037's per-transaction gas-limit cap, from Amsterdam.
const TX_MAX_TOTAL_GAS_LIMIT: u64 = u32::MAX as u64;
/// EIP-7928's gas per block-access-list item.
const BAL_ITEM_COST: u64 = 2000;

/// The one thing that made a payload invalid — for a test to name; the guest
/// publishes only that it was.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// No parent, or an ancestor that does not decode or does not chain.
    Ancestors,
    EmptyTransaction,
    /// A base fee past `u64`, or a blob gas price past `u128`, which revm
    /// cannot represent and no real block holds.
    Unrepresentable,
    BlockHash,
    /// Transaction `i` does not decode.
    Transaction(usize),
    VersionedHashes,
    BlockSize,
    Header(HeaderError),
    Witness(WitnessError),
    /// Transaction `i`'s signature does not recover.
    Signature(usize),
    /// The input carries public keys, and they are not one per transaction,
    /// each `0x04 ‖ x ‖ y` naming the sender its signature recovers.
    PublicKeys,
    ChainId(usize),
    /// Transaction `i` does not fit the block's remaining gas, state gas or
    /// blob gas, or exceeds Amsterdam's total cap.
    Capacity(usize),
    /// revm refused transaction `i`, or read a witness that failed it.
    Execution(usize),
    /// A system call errored, or a checked one had no code or did not succeed.
    SystemCall,
    Deposits,
    GasUsed,
    ReceiptsRoot,
    Bloom,
    BlobGasUsed,
    RequestsHash,
    /// The block access list exceeds its gas limit or is not the header's.
    AccessList,
    StateRoot,
}

impl From<WitnessError> for Invalid {
    fn from(e: WitnessError) -> Invalid {
        Invalid::Witness(e)
    }
}

impl From<MptError> for Invalid {
    fn from(e: MptError) -> Invalid {
        Invalid::Witness(WitnessError::Trie(e))
    }
}

/// The guest's whole computation: `statelessInputBytes` to
/// `statelessOutputBytes`.
pub fn run(input: &[u8]) -> [u8; 43] {
    let Some(input) = ssz::decode(input) else {
        return ssz::SENTINEL;
    };
    let root = ssz::request_root(&input.request, input.fork.amsterdam);
    let valid = verify(&input).is_ok();
    ssz::result(&root, valid, input.chain_id, input.fork.schema_id)
}

/// Validate a decoded input; `Err` names the first rule it breaks.
pub fn verify(input: &StatelessInput<'_>) -> Result<(), Invalid> {
    let fork = &input.fork;
    let request = &input.request;
    let payload = &request.payload;

    // 1. The ancestor chain.
    let (parent, parent_hash, block_hashes) =
        ancestors(&input.witness, fork.amsterdam, payload.block_number)?;

    // 2. The header the payload implies, its hash, and the versioned hashes.
    if payload.transactions.iter().any(|t| t.is_empty()) {
        return Err(Invalid::EmptyTransaction);
    }
    let header = payload_header(request)?;
    let header_rlp = header.encode();
    if keccak(&header_rlp) != payload.block_hash {
        return Err(Invalid::BlockHash);
    }
    let txs = payload
        .transactions
        .iter()
        .enumerate()
        .map(|(i, bytes)| tx::decode(bytes).map_err(|_| Invalid::Transaction(i)))
        .collect::<Result<Vec<Tx<'_>>, Invalid>>()?;
    if input
        .public_keys
        .as_ref()
        .is_some_and(|keys| keys.len() != txs.len())
    {
        return Err(Invalid::PublicKeys);
    }
    let blob_hashes: Vec<Word32> = txs
        .iter()
        .filter(|t| t.tx_type == 3)
        .flat_map(|t| t.blob_hashes.iter().copied())
        .collect();
    if blob_hashes != request.versioned_hashes {
        return Err(Invalid::VersionedHashes);
    }

    // 3. Size, and the header against its parent.
    let withdrawals: Vec<Vec<u8>> = payload
        .withdrawals
        .iter()
        .map(block::encode_withdrawal)
        .collect();
    if block::block_rlp_len(&header_rlp, &payload.transactions, &withdrawals)
        > block::MAX_RLP_BLOCK_SIZE
    {
        return Err(Invalid::BlockSize);
    }
    block::validate_header(fork, &parent, &parent_hash, &header).map_err(Invalid::Header)?;
    let blob_price =
        block::blob_gas_price(fork, header.excess_blob_gas).ok_or(Invalid::Unrepresentable)?;

    // 4. The block.
    let db = WitnessDb::new(
        &parent.state_root,
        &input.witness.state,
        &input.witness.codes,
        block_hashes,
    )?;
    let mut state = State::builder()
        .with_database(db)
        .with_bundle_update()
        .with_bal_builder_if(fork.amsterdam)
        .build();
    let out = execute(input, &header, &txs, &mut state, blob_price)?;

    // 5. What the header claims.
    if out.gas_used != header.gas_used {
        return Err(Invalid::GasUsed);
    }
    if block::ordered_root(&out.receipts) != header.receipts_root {
        return Err(Invalid::ReceiptsRoot);
    }
    if block::logs_bloom(&out.logs) != header.bloom {
        return Err(Invalid::Bloom);
    }
    if out.blob_gas_used != header.blob_gas_used {
        return Err(Invalid::BlobGasUsed);
    }
    if block::requests_hash(&out.requests) != header.requests_hash {
        return Err(Invalid::RequestsHash);
    }
    if fork.amsterdam {
        let bal = state.take_built_alloy_bal().ok_or(Invalid::AccessList)?;
        if alloy_eip7928::total_bal_items(&bal) > header.gas_limit / BAL_ITEM_COST {
            return Err(Invalid::AccessList);
        }
        if Some(alloy_eip7928::compute_block_access_list_hash(&bal).0)
            != header.block_access_list_hash
        {
            return Err(Invalid::AccessList);
        }
    }
    state.merge_transitions(BundleRetention::PlainState);
    let bundle = state.take_bundle();
    if post_state_root(&mut state.database, &bundle)? != header.state_root {
        return Err(Invalid::StateRoot);
    }
    Ok(())
}

/// `(number, hash)` for every ancestor, ascending: what `BLOCKHASH` reads.
type BlockHashes = Vec<(u64, Word32)>;

/// The ancestor headers, decoded and chained: the parent, its hash, and the
/// `(number, hash)` every ancestor answers `BLOCKHASH` with.
///
/// A header's number for `BLOCKHASH` is its **position**, counted back from
/// the block's own, as the spec indexes `block_hashes`; on a chain that
/// validates, that is also the number each header carries.
fn ancestors(
    witness: &ExecutionWitness<'_>,
    amsterdam: bool,
    number: u64,
) -> Result<(Header, Word32, BlockHashes), Invalid> {
    let mut hashes: Vec<Word32> = Vec::with_capacity(witness.headers.len());
    let mut parent = None;
    for bytes in &witness.headers {
        let header = Header::decode(bytes, amsterdam).map_err(|_| Invalid::Ancestors)?;
        if let Some(previous) = hashes.last() {
            if header.parent_hash != *previous {
                return Err(Invalid::Ancestors);
            }
        }
        hashes.push(keccak(bytes));
        parent = Some(header);
    }
    let parent = parent.ok_or(Invalid::Ancestors)?;
    let n = hashes.len() as u64;
    let block_hashes = hashes
        .iter()
        .enumerate()
        .filter_map(|(i, hash)| Some((number.checked_sub(n - i as u64)?, *hash)))
        .collect();
    Ok((parent, *hashes.last().expect("a parent"), block_hashes))
}

/// `validation_helpers.py::_payload_header`: the header a payload request
/// implies, its three derived roots computed from the request.
fn payload_header(request: &NewPayloadRequest<'_>) -> Result<Header, Invalid> {
    let p = &request.payload;
    // A `uint256`, little-endian; revm's base fee is a `u64`.
    if p.base_fee_per_gas[8..].iter().any(|b| *b != 0) {
        return Err(Invalid::Unrepresentable);
    }
    let base_fee = u64::from_le_bytes(p.base_fee_per_gas[..8].try_into().expect("eight bytes"));
    let withdrawals: Vec<Vec<u8>> = p.withdrawals.iter().map(block::encode_withdrawal).collect();
    // `encode_execution_requests`: each non-empty list as `type ‖ items`, in
    // type order.
    let mut requests = Vec::new();
    for (kind, items) in request.requests.iter().enumerate() {
        if !items.is_empty() {
            let mut typed = Vec::with_capacity(1 + items.len());
            typed.push(kind as u8);
            typed.extend_from_slice(items);
            requests.push(typed);
        }
    }
    let transactions: Vec<Vec<u8>> = p.transactions.iter().map(|t| t.to_vec()).collect();
    Ok(Header {
        parent_hash: p.parent_hash,
        ommers_hash: block::EMPTY_OMMER_HASH,
        coinbase: p.fee_recipient,
        state_root: p.state_root,
        transactions_root: block::ordered_root(&transactions),
        receipts_root: p.receipts_root,
        bloom: p.logs_bloom,
        difficulty: [0u8; 32],
        number: p.block_number,
        gas_limit: p.gas_limit,
        gas_used: p.gas_used,
        timestamp: p.timestamp,
        extra_data: p.extra_data.to_vec(),
        prev_randao: p.prev_randao,
        nonce: [0u8; 8],
        base_fee_per_gas: base_fee,
        withdrawals_root: block::ordered_root(&withdrawals),
        blob_gas_used: p.blob_gas_used,
        excess_blob_gas: p.excess_blob_gas,
        parent_beacon_block_root: request.parent_beacon_block_root,
        requests_hash: block::requests_hash(&requests),
        block_access_list_hash: p.block_access_list.map(keccak),
        slot_number: p.slot_number,
    })
}

/// What a block's execution produced, for step 5.
struct Executed {
    gas_used: u64,
    receipts: Vec<Vec<u8>>,
    logs: Vec<Log>,
    blob_gas_used: u64,
    requests: Vec<Vec<u8>>,
}

/// `fork.py::apply_body`, on revm, at reth's commit granularity.
fn execute(
    input: &StatelessInput<'_>,
    header: &Header,
    txs: &[Tx<'_>],
    state: &mut State<WitnessDb<'_>>,
    blob_price: u128,
) -> Result<Executed, Invalid> {
    let (fork, chain_id, payload) = (&input.fork, input.chain_id, &input.request.payload);
    let mut cfg = CfgEnv::new_with_spec(fork.spec);
    cfg.chain_id = chain_id;
    cfg.set_max_blobs_per_tx(block::MAX_BLOBS_PER_TX);
    let block_env = BlockEnv {
        number: U256::from(header.number),
        beneficiary: Address::from(header.coinbase),
        timestamp: U256::from(header.timestamp),
        gas_limit: header.gas_limit,
        basefee: header.base_fee_per_gas,
        difficulty: U256::ZERO,
        prevrandao: Some(B256::new(header.prev_randao)),
        blob_excess_gas_and_price: Some(BlobExcessGasAndPrice {
            excess_blob_gas: header.excess_blob_gas,
            blob_gasprice: blob_price,
        }),
        slot_num: header.slot_number.unwrap_or(0),
    };
    let mut evm = Context::mainnet()
        .with_db(&mut *state)
        .with_block(block_env)
        .with_cfg(cfg)
        .build_mainnet();

    // Before the transactions, at block access index 0: unchecked, so a
    // reverting call is committed like any other and only an error fails.
    for (contract, data) in [
        (BEACON_ROOTS, header.parent_beacon_block_root),
        (HISTORY_STORAGE, header.parent_hash),
    ] {
        evm.system_call_one_with_caller(SYSTEM_ADDRESS, contract, Bytes::copy_from_slice(&data))
            .map_err(|_| Invalid::SystemCall)?;
    }
    commit_index(&mut evm)?;

    let mut cumulative: u64 = 0;
    let mut regular: u64 = 0;
    let mut state_gas: u64 = 0;
    let mut blob_gas_used: u64 = 0;
    let mut receipts = Vec::with_capacity(txs.len());
    let mut logs: Vec<Log> = Vec::new();
    let max_blob_gas = fork.blob_max * block::GAS_PER_BLOB;
    for (i, tx) in txs.iter().enumerate() {
        evm.ctx.journaled_state.database.bump_bal_index();
        if tx.chain_id.is_some_and(|c| c != chain_id) {
            return Err(Invalid::ChainId(i));
        }
        let sender = tx::sender(tx).ok_or(Invalid::Signature(i))?;
        // A key is checked, never trusted: the sender is the one recovered,
        // and the key must name it, as ere-guests' reth guest holds it.
        if let Some(keys) = &input.public_keys {
            let key = keys.get(i).ok_or(Invalid::PublicKeys)?;
            if key[0] != 0x04 || tx::address_of(key) != sender {
                return Err(Invalid::PublicKeys);
            }
        }
        let blob_gas = tx.blob_hashes.len() as u64 * block::GAS_PER_BLOB;
        let fits = if fork.amsterdam {
            tx.gas_limit <= TX_MAX_TOTAL_GAS_LIMIT
                && tx.gas_limit.min(TX_MAX_GAS_LIMIT) <= header.gas_limit.saturating_sub(regular)
                && tx.gas_limit <= header.gas_limit.saturating_sub(state_gas)
        } else {
            tx.gas_limit <= header.gas_limit.saturating_sub(cumulative)
        };
        if !fits || blob_gas > max_blob_gas.saturating_sub(blob_gas_used) {
            return Err(Invalid::Capacity(i));
        }
        let result = evm
            .transact_commit(tx_env(tx, sender))
            .map_err(|_| Invalid::Execution(i))?;
        let gas = result.gas();
        cumulative = cumulative.saturating_add(gas.tx_gas_used());
        regular = regular.saturating_add(gas.block_regular_gas_used());
        state_gas = state_gas.saturating_add(gas.block_state_gas_used());
        blob_gas_used += blob_gas;
        let tx_logs: Vec<Log> = result
            .logs()
            .iter()
            .map(|log| Log {
                address: log.address.0 .0,
                topics: log.topics().iter().map(|t| t.0).collect(),
                data: log.data.data.to_vec(),
            })
            .collect();
        receipts.push(block::encode_receipt(
            tx.tx_type,
            result.is_success(),
            cumulative,
            &tx_logs,
        ));
        logs.extend(tx_logs);
    }

    // After the transactions, at block access index N + 1: the withdrawals,
    // then the requests. A zero-amount withdrawal still touches its recipient,
    // which puts it in the access list and, empty, keeps it out of the state.
    evm.ctx.journaled_state.database.bump_bal_index();
    for w in &payload.withdrawals {
        evm.ctx
            .journaled_state
            .balance_incr(
                Address::from(w.address),
                U256::from(u128::from(w.amount) * GWEI),
            )
            .map_err(|_| Invalid::SystemCall)?;
    }

    let mut requests = Vec::new();
    let deposits = block::deposit_requests(&logs).ok_or(Invalid::Deposits)?;
    if !deposits.is_empty() {
        requests.push([&[0u8][..], &deposits].concat());
    }
    let checked = if fork.amsterdam { 4 } else { 2 };
    for (contract, kind) in &REQUEST_CONTRACTS[..checked] {
        // The spec refuses a block whose system contract has no code, read at
        // the current state; revm alone would call it and succeed.
        let code_hash = Database::basic(&mut *evm.ctx.journaled_state.database, *contract)
            .map_err(|_| Invalid::SystemCall)?
            .map_or(KECCAK_EMPTY, |info| info.code_hash);
        if code_hash == KECCAK_EMPTY {
            return Err(Invalid::SystemCall);
        }
        let output = match evm.system_call_one_with_caller(SYSTEM_ADDRESS, *contract, Bytes::new())
        {
            Ok(ExecutionResult::Success { output, .. }) => match output {
                Output::Call(data) => data,
                Output::Create(data, _) => data,
            },
            _ => return Err(Invalid::SystemCall),
        };
        if !output.is_empty() {
            requests.push([&[*kind][..], &output].concat());
        }
    }
    commit_index(&mut evm)?;

    let gas_used = if fork.amsterdam {
        regular.max(state_gas)
    } else {
        cumulative
    };
    Ok(Executed {
        gas_used,
        receipts,
        logs,
        blob_gas_used,
        requests,
    })
}

/// The EVM a block runs on.
type BlockEvm<'s, 'w> = MainnetEvm<MainnetContext<&'s mut State<WitnessDb<'w>>>>;

/// Commit the journal as one block access index: the system calls before the
/// transactions, or the withdrawals and the system calls after them.
///
/// **One commit per index, and every baseline the index's.** revm's
/// access-list builder records a value written at an index when it differs
/// from the baseline the commit carries, and revm moves each value's baseline
/// to the start of every call that touches it — EIP-2200 meters a slot against
/// it. An index of several calls committed as revm finalizes it would net each
/// value against the call that last touched it, so a slot one call toggles and
/// the next restores, or a withdrawal a dequeue forwards on, would be a write
/// where the spec's list has none. Each baseline is set back to the committed
/// state — what the index began with — which is also what `State`'s own commit
/// assumes a baseline to be.
fn commit_index(evm: &mut BlockEvm<'_, '_>) -> Result<(), Invalid> {
    let mut changes = evm.finalize();
    let db = &mut *evm.ctx.journaled_state.database;
    for (address, account) in changes.iter_mut() {
        *account.original_info_mut() = Database::basic(db, *address)
            .map_err(|_| Invalid::SystemCall)?
            .unwrap_or_default();
        for (key, slot) in account.storage.iter_mut() {
            slot.original_value =
                Database::storage(db, *address, *key).map_err(|_| Invalid::SystemCall)?;
        }
    }
    evm.commit(changes);
    Ok(())
}

/// One decoded transaction as revm's `TxEnv`, field by field.
///
/// Built directly rather than through `TxEnvBuilder::build_fill`, which
/// *fills* a missing field: given type 4 and no authorization, it inserts a
/// dummy one, and an invalid empty-list transaction would pass revm's
/// `EmptyAuthorizationList` check.
fn tx_env(tx: &Tx<'_>, sender: Address20) -> TxEnv {
    TxEnv {
        tx_type: tx.tx_type,
        caller: Address::from(sender),
        gas_limit: tx.gas_limit,
        gas_price: tx.gas_price,
        kind: match tx.to {
            Some(to) => TxKind::Call(Address::from(to)),
            None => TxKind::Create,
        },
        value: U256::from_be_bytes(tx.value),
        data: Bytes::copy_from_slice(tx.data),
        nonce: tx.nonce,
        chain_id: tx.chain_id,
        access_list: AccessList(
            tx.access_list
                .iter()
                .map(|(address, keys)| AccessListItem {
                    address: Address::from(*address),
                    storage_keys: keys.iter().map(|k| B256::new(*k)).collect(),
                })
                .collect(),
        ),
        gas_priority_fee: tx.priority_fee,
        blob_hashes: tx.blob_hashes.iter().map(|h| B256::new(*h)).collect(),
        max_fee_per_blob_gas: tx.max_fee_per_blob_gas.unwrap_or(0),
        authorization_list: tx
            .authorizations
            .iter()
            .map(|auth| {
                Either::Right(RecoveredAuthorization::new_unchecked(
                    Authorization {
                        chain_id: U256::from_be_bytes(auth.chain_id),
                        address: Address::from(auth.address),
                        nonce: auth.nonce,
                    },
                    match tx::authority(auth) {
                        Some(authority) => RecoveredAuthority::Valid(Address::from(authority)),
                        None => RecoveredAuthority::Invalid,
                    },
                ))
            })
            .collect(),
    }
}

/// The bundle's changes applied to the witness's tries: the post-state root.
///
/// What reth's stateless validator does with the same bundle: an account with
/// no info, or an empty one (EIP-161), leaves the state trie; a destroyed one
/// starts from an empty storage trie; every changed slot is set, zero being a
/// deletion. An account whose storage was never read and is not destroyed
/// keeps its storage root, as a blinded node that re-hashes to itself.
///
/// **Every write precedes every deletion**, in each storage trie and in the
/// state trie, as the spec replays a block (`mpt_set_storage_slots`). A
/// deletion that leaves a branch one child needs that child's node, which is
/// on no changed key's path; the witness carries the ones the spec's order
/// needs, and writing first needs a subset of them — a branch collapses only
/// if it ends collapsed, and then every order needs its survivor.
fn post_state_root(db: &mut WitnessDb<'_>, bundle: &BundleState) -> Result<Word32, Invalid> {
    let mut accounts: Vec<_> = bundle.state.iter().collect();
    accounts.sort_unstable_by_key(|(address, _)| **address);
    let mut removed = Vec::new();
    for (address, account) in accounts {
        let address = address.0 .0;
        let path = mpt::nibbles(&keccak(&address));
        let info = match &account.info {
            Some(info) if !info.is_empty() => info,
            _ => {
                removed.push(path);
                continue;
            }
        };
        let mut trie = if account.status.was_destroyed() {
            Node::Empty
        } else {
            match db.storage.binary_search_by(|(a, _)| a.cmp(&address)) {
                Ok(at) => core::mem::replace(&mut db.storage[at].1, Node::Empty),
                Err(_) => match db.account(&address)? {
                    Some((_, _, root, _)) if root != EMPTY_TRIE_ROOT => Node::Blinded(root),
                    _ => Node::Empty,
                },
            }
        };
        let mut slots: Vec<_> = account
            .storage
            .iter()
            .map(|(key, slot)| (slot.present_value, *key))
            .collect();
        slots.sort_unstable_by_key(|(value, key)| (value.is_zero(), *key));
        for (value, key) in slots {
            let path = mpt::nibbles(&keccak(&key.to_be_bytes::<32>()));
            trie = if value.is_zero() {
                mpt::remove(trie, &path)?
            } else {
                mpt::insert(trie, &path, mpt::encode_slot(&value.to_be_bytes::<32>()))?
            };
        }
        let leaf = mpt::encode_account(
            info.nonce,
            &info.balance.to_be_bytes::<32>(),
            &trie.root(),
            &info.code_hash.0,
        );
        let state = core::mem::replace(&mut db.state, Node::Empty);
        db.state = mpt::insert(state, &path, leaf)?;
    }
    for path in removed {
        let state = core::mem::replace(&mut db.state, Node::Empty);
        db.state = mpt::remove(state, &path)?;
    }
    Ok(db.state.root())
}
