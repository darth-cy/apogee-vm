//! [`WitnessRecorder`]: a real Ethereum block in, a `BlockWitness` out.
//!
//! The method is the one S25's core algorithm names. A thin database wrapper
//! answers revm's reads from a cached JSON-RPC endpoint pinned at the **parent**
//! block — which is the state the block's transactions begin from — and records
//! every answer as it goes. The transactions are then executed once, natively,
//! through the very same [`revm_block::run`] the guest runs; whatever the
//! wrapper was asked for is, by construction, exactly what the guest will need.
//! That touch set becomes the witness.
//!
//! # Why the execution is what discovers the touch set
//!
//! Nothing short of running the block knows which accounts and slots an EVM
//! execution reads. A recorder that guessed — "every address in the access
//! lists, plus every `to`" — would miss every `SLOAD` of a dynamic key and
//! every `CALL` to an address computed at run time. So the recorder runs it,
//! and the completeness of the witness is a property of the run rather than of
//! a list somebody wrote down. `crates/host/tests/witness.rs`'s completeness
//! control is the check that it is load-bearing: delete one recorded slot and
//! the guest must fail loudly.
//!
//! # Determinism
//!
//! Must-be-exact 1: the same `(block, tx range)` produces byte-identical
//! witness bytes. Three things make that true and none of them is luck.
//!
//! - The touch set lives in [`BTreeMap`]s keyed by address and by slot, so its
//!   order is the canonical order the witness needs and not a hash map's.
//! - Every RPC answer is content-addressed in the cache, so a second recording
//!   reads the same bytes rather than asking the chain again.
//! - `BlockWitness::encode` refuses a witness that is not in canonical order,
//!   and `decode` re-encodes and compares. A recorder that produced two
//!   encodings of one state could not get either of them past the guest.

use std::collections::BTreeMap;

use revm::primitives::{Address, StorageKey, B256, U256};
use revm::state::{AccountInfo, Bytecode};
use revm::Database;
use revm_block::{
    AccountWitness, Address20, AuthorizationWitness, BlockEnvWitness, BlockWitness, SpecId,
    TxWitness, Word32,
};
use serde_json::{json, Value};

use crate::rpc::{self, Rpc};

/// The root an empty Merkle-Patricia trie has, which is what `eth_getProof`
/// reports as `storageHash` for an account with no storage. The guest's, not a
/// second copy: one constant, one definition.
use revm_block::mpt::EMPTY_TRIE_ROOT;

/// Which of a block's transactions to record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxRange {
    /// The first `n` transactions. S25's mini-block mode, where `n` is two so
    /// that inter-transaction state carry is exercised.
    First(usize),
    /// Every transaction in the block. The stateless mode's range.
    All,
}

/// What one recording produced.
pub struct Recording {
    /// The witness, canonical and ready to encode.
    pub witness: BlockWitness,
    /// The block's own header hash.
    pub block_hash: Word32,
    /// Its parent's header hash.
    pub parent_hash: Word32,
    /// The parent's state root: what these values were read at, and what a
    /// stateless witness authenticates against.
    pub parent_state_root: Word32,
    /// This block's state root, from the header.
    pub state_root: Word32,
    /// How many transactions the block has, whatever was recorded.
    pub txs_in_block: usize,
    /// Cache hits and network calls over the whole recording. A second
    /// recording of one block makes zero network calls, which is what makes
    /// the determinism test a test.
    pub rpc_hits: u64,
    /// Network calls.
    pub rpc_misses: u64,
}

/// The recorder: an RPC-backed `revm::Database` that remembers what it was
/// asked.
///
/// It is the Database itself rather than a layer over one, which is what the
/// stage's core algorithm asks for — *"Layer that wrapper once, as an on-disk
/// cache implementing revm's Database trait."* The on-disk cache is
/// [`Rpc`]'s, one layer, shared by every method here.
pub struct WitnessRecorder {
    rpc: Rpc,
    /// The block whose state is read: the parent of the block being executed.
    at: u64,
    /// Accounts the execution asked about, whether or not they exist.
    accounts: BTreeMap<Address20, Recorded>,
    /// Ancestor hashes the execution asked for.
    block_hashes: BTreeMap<u64, Word32>,
}

/// One account as the chain answered for it.
#[derive(Clone, Debug, Default)]
struct Recorded {
    nonce: u64,
    balance: Word32,
    code: Vec<u8>,
    /// Slots read, including the ones that read zero. A zero here is a
    /// recorded fact and not an absence.
    slots: BTreeMap<Word32, Word32>,
    /// Whether the account exists on chain. A non-existent one is still
    /// recorded, with every field zero, because the witness must be able to
    /// say "this address was asked about and is not there".
    exists: bool,
}

impl WitnessRecorder {
    /// A recorder reading the state at the end of block `at`.
    pub fn new(rpc: Rpc, at: u64) -> WitnessRecorder {
        WitnessRecorder {
            rpc,
            at,
            accounts: BTreeMap::new(),
            block_hashes: BTreeMap::new(),
        }
    }

    /// The accounts recorded so far, in canonical order.
    fn harvest(&self) -> Vec<AccountWitness> {
        self.accounts
            .iter()
            .map(|(address, recorded)| AccountWitness {
                address: *address,
                nonce: recorded.nonce,
                balance: recorded.balance,
                code: recorded.code.clone(),
                slots: recorded.slots.iter().map(|(k, v)| (*k, *v)).collect(),
            })
            .collect()
    }

    /// Cache hits and network calls so far.
    pub fn rpc_counts(&self) -> (u64, u64) {
        (self.rpc.hits, self.rpc.misses)
    }

    /// Fetch and remember one account.
    ///
    /// `eth_getProof` with no storage keys is the one call that answers nonce,
    /// balance and code hash together, and it is the call a stateless
    /// recording needs anyway — so the mini and stateless paths ask the chain
    /// the same question and a cache serves both.
    fn load(&mut self, address: Address20) -> Result<(), String> {
        if self.accounts.contains_key(&address) {
            return Ok(());
        }
        let proof = self.rpc.call(
            "eth_getProof",
            json!([
                rpc::hex_data(&address),
                Vec::<String>::new(),
                rpc::hex_quantity(self.at)
            ]),
        )?;
        let nonce = rpc::u64_of(&proof["nonce"], "the account nonce")?;
        let balance = rpc::word_of(&proof["balance"], "the account balance")?;
        let code_hash = rpc::word_of(&proof["codeHash"], "the account code hash")?;
        // An account that does not exist answers with zeros and the empty code
        // hash; `eth_getProof` gives no explicit flag, and the inclusion proof
        // it returns is an exclusion proof. The stateless mode checks that
        // proof; the mini mode takes the values, which is the whole of what it
        // claims to.
        let empty_code_hash = revm::primitives::KECCAK_EMPTY.0;
        // An account exists when any of the four things the state trie holds
        // for it is not its empty value. `storageHash` is in the test because
        // an account can hold storage with a zero nonce and balance and no
        // code — EIP-161 cannot clear it, having never touched it — and
        // reading that as an absence would hand revm `None` for an account
        // whose slots the witness then serves.
        let storage_hash = rpc::word_of(&proof["storageHash"], "the account storage hash")?;
        // go-ethereum answers for an address with no state object out of a
        // zero-valued `common.Hash`, so **both** hashes arrive as the zero word
        // rather than as `keccak256("")` and the empty-trie root. That is the
        // shape of an absence and not of an account: no byte string hashes to
        // zero, so taking it literally made `exists` true and then failed the
        // `eth_getCode` cross-check below with an error naming a code hash no
        // code can have. Seen on Geth v10 and on one of 1rpc's backends; reth
        // answers with the canonical empty values.
        //
        // The two are normalised **together**. Repairing `codeHash` alone
        // would leave `exists` true through `storage_hash != EMPTY_TRIE_ROOT`,
        // which hands revm `Some(AccountInfo)` where it must see `None` -- and
        // that failure is silent, where this one at least stopped.
        let absent = code_hash == [0u8; 32] && storage_hash == [0u8; 32];
        let code_hash = if absent { empty_code_hash } else { code_hash };
        let storage_hash = if absent {
            EMPTY_TRIE_ROOT
        } else {
            storage_hash
        };
        let exists = nonce != 0
            || balance != [0u8; 32]
            || code_hash != empty_code_hash
            || storage_hash != EMPTY_TRIE_ROOT;
        let code = if code_hash == empty_code_hash {
            Vec::new()
        } else {
            let answer = self.rpc.call(
                "eth_getCode",
                json!([rpc::hex_data(&address), rpc::hex_quantity(self.at)]),
            )?;
            let code = rpc::bytes_of(&answer, "the account code")?;
            let actual = revm::primitives::keccak256(&code).0;
            if actual != code_hash {
                return Err(format!(
                    "eth_getCode for {} hashes to {} where eth_getProof says {}",
                    rpc::hex_data(&address),
                    rpc::hex_data(&actual),
                    rpc::hex_data(&code_hash)
                ));
            }
            code
        };
        self.accounts.insert(
            address,
            Recorded {
                nonce,
                balance,
                code,
                slots: BTreeMap::new(),
                exists,
            },
        );
        Ok(())
    }

    /// Fetch and remember one storage slot.
    fn load_slot(&mut self, address: Address20, key: Word32) -> Result<Word32, String> {
        self.load(address)?;
        if let Some(value) = self.accounts[&address].slots.get(&key) {
            return Ok(*value);
        }
        let answer = self.rpc.call(
            "eth_getStorageAt",
            json!([
                rpc::hex_data(&address),
                rpc::hex_data(&key),
                rpc::hex_quantity(self.at)
            ]),
        )?;
        let value = rpc::word_of(&answer, "the storage value")?;
        self.accounts
            .get_mut(&address)
            .expect("the account was just loaded")
            .slots
            .insert(key, value);
        Ok(value)
    }

    /// Fetch and remember one ancestor's hash.
    fn load_block_hash(&mut self, number: u64) -> Result<Word32, String> {
        if let Some(hash) = self.block_hashes.get(&number) {
            return Ok(*hash);
        }
        let header = self.rpc.call(
            "eth_getBlockByNumber",
            json!([rpc::hex_quantity(number), false]),
        )?;
        let hash = rpc::word_of(&header["hash"], "the ancestor hash")?;
        self.block_hashes.insert(number, hash);
        Ok(hash)
    }
}

/// The recorder's own failures, as a `Database::Error`.
///
/// One variant: everything that goes wrong here is "the chain could not be
/// asked", and the message says which question. Master anti-goal 8 —
/// no error-type architecture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecorderError(pub String);

impl std::fmt::Display for RecorderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RecorderError {}
impl revm::database_interface::DBErrorMarker for RecorderError {}

impl Database for WitnessRecorder {
    type Error = RecorderError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, RecorderError> {
        self.load(address.0 .0).map_err(RecorderError)?;
        let recorded = &self.accounts[&address.0 .0];
        if !recorded.exists {
            return Ok(None);
        }
        let code = revm::primitives::Bytes::copy_from_slice(&recorded.code);
        // `new_raw_checked`, not `new_raw`: the latter panics on code that
        // begins `0xef01` and is not a 23-byte EIP-7702 delegation, and a few
        // such accounts predate EIP-3541. Refusing at record time is what keeps
        // the guest from meeting the same bytes.
        let bytecode = Bytecode::new_raw_checked(code.clone()).map_err(|e| {
            RecorderError(format!(
                "{}'s code is not bytecode revm accepts: {e}",
                rpc::hex_data(&address.0 .0)
            ))
        })?;
        Ok(Some(AccountInfo {
            balance: U256::from_be_bytes(recorded.balance),
            nonce: recorded.nonce,
            code_hash: revm::primitives::keccak256(&code),
            account_id: None,
            code: Some(bytecode),
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, RecorderError> {
        // Unreachable: every `AccountInfo` above carries its code inline.
        Err(RecorderError(format!(
            "code was asked for by hash {code_hash}, which the recorder never serves"
        )))
    }

    fn storage(&mut self, address: Address, index: StorageKey) -> Result<U256, RecorderError> {
        let value = self
            .load_slot(address.0 .0, index.to_be_bytes::<32>())
            .map_err(RecorderError)?;
        Ok(U256::from_be_bytes(value))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, RecorderError> {
        let hash = self.load_block_hash(number).map_err(RecorderError)?;
        Ok(B256::new(hash))
    }
}

/// Record one block's transactions and emit the witness.
///
/// The whole recording, from the header down. `rpc` is moved in and its
/// hit/miss counters come back on the [`Recording`], because "the second run
/// made no network calls" is the determinism property and a caller should be
/// able to assert it.
pub fn record(rpc: Rpc, block_number: u64, range: TxRange) -> Result<Recording, String> {
    let mut rpc = rpc;
    let header = rpc.call(
        "eth_getBlockByNumber",
        json!([rpc::hex_quantity(block_number), true]),
    )?;
    let chain_id = rpc::u64_of(&rpc.call("eth_chainId", json!([]))?, "the chain id")?;

    let transactions = header["transactions"]
        .as_array()
        .ok_or("the block carries no transaction list")?
        .clone();
    let txs_in_block = transactions.len();
    let take = match range {
        TxRange::First(n) => n.min(txs_in_block),
        TxRange::All => txs_in_block,
    };

    let spec = mainnet_spec(block_number)?;
    let blob_gasprice = match header.get("excessBlobGas") {
        Some(Value::Null) | None => None,
        Some(_) => Some(blob_gasprice(&mut rpc, block_number)?),
    };
    let mut env = block_env(&header, chain_id, spec, blob_gasprice)?;
    let mut txs = Vec::with_capacity(take);
    for (i, tx) in transactions.iter().take(take).enumerate() {
        txs.push(tx_witness(tx).map_err(|e| format!("transaction {i}: {e}"))?);
    }

    let block_hash = rpc::word_of(&header["hash"], "the block hash")?;
    let parent_hash = rpc::word_of(&header["parentHash"], "the parent hash")?;
    let state_root = rpc::word_of(&header["stateRoot"], "the state root")?;
    let parent = block_number
        .checked_sub(1)
        .ok_or("the genesis block has no parent to read state from")?;
    let parent_header = rpc.call(
        "eth_getBlockByNumber",
        json!([rpc::hex_quantity(parent), false]),
    )?;
    let parent_state_root = rpc::word_of(&parent_header["stateRoot"], "the parent state root")?;

    // Execute once, against the chain, and harvest whatever it asked for.
    let mut recorder = WitnessRecorder::new(rpc, parent);
    // The beneficiary is read by every transaction that pays a priority fee,
    // but revm loads it lazily and a zero-tip block would not touch it. Load it
    // up front so the witness does not depend on that.
    recorder.load(env.beneficiary)?;
    for tx in &txs {
        recorder.load(tx.caller)?;
        if let Some(to) = tx.to {
            recorder.load(to)?;
        }
    }
    let harvested = execute_recording(&mut recorder, &env, &txs)?;
    env.block_hashes = recorder
        .block_hashes
        .iter()
        .map(|(number, hash)| (*number, *hash))
        .collect();

    let witness = BlockWitness {
        env,
        accounts: harvested,
        txs,
        stateless: None,
    };
    // The recorder's own output must be what the guest will accept, and the
    // cheapest way to know is to put it through the guest's own decoder.
    let encoded = witness.encode();
    BlockWitness::decode(&encoded)
        .map_err(|e| format!("the recorded witness is not canonical: {e:?}"))?;

    Ok(Recording {
        witness,
        block_hash,
        parent_hash,
        parent_state_root,
        state_root,
        txs_in_block,
        rpc_hits: recorder.rpc_counts().0,
        rpc_misses: recorder.rpc_counts().1,
    })
}

/// Run the transactions against the recorder and return the harvest.
///
/// This is deliberately *not* `revm_block::run`: that function takes a
/// `BlockWitness`, and the witness is what this is producing. What it must
/// share with `run` is the environment — the same `BlockEnv`, the same
/// `CfgEnv`, the same `TxEnv` per transaction — and it does, because both build
/// them from the same [`BlockEnvWitness`] and [`TxWitness`] through
/// `revm_block`'s own constructors. The differential in
/// `crates/host/tests/witness.rs` is what holds the two together: the guest,
/// reading only the harvest, must produce what `revm_block::run` produces.
fn execute_recording(
    recorder: &mut WitnessRecorder,
    env: &BlockEnvWitness,
    txs: &[TxWitness],
) -> Result<Vec<AccountWitness>, String> {
    let witness = BlockWitness {
        env: env.clone(),
        accounts: Vec::new(),
        txs: txs.to_vec(),
        stateless: None,
    };
    revm_block::run_against(&witness, &mut *recorder)
        .map_err(|e| format!("the block does not execute against the chain: {e}"))?;
    Ok(recorder.harvest())
}

/// The mainnet hardfork a block runs under, by activation block number.
///
/// A table rather than a guess, and it **refuses a block past the last fork it
/// knows** rather than running it under the newest rules it has heard of. A
/// recording made under the wrong hardfork is not a recording that fails; it is
/// one that quietly computes a different block, and the only thing that would
/// notice is a state root the mini mode does not check.
///
/// The activation heights are revm's own, from the doc comments on
/// `revm::primitives::hardfork::SpecId`, so the table and the `SpecId` it names
/// come from one place.
pub fn mainnet_spec(block_number: u64) -> Result<SpecId, String> {
    const SCHEDULE: [(u64, SpecId); 5] = [
        (15_537_394, SpecId::MERGE),
        (17_034_870, SpecId::SHANGHAI),
        (19_426_587, SpecId::CANCUN),
        (22_431_084, SpecId::PRAGUE),
        (23_935_694, SpecId::OSAKA),
    ];
    if block_number < SCHEDULE[0].0 {
        return Err(format!(
            "block {block_number} is before the merge, which this recorder does not record"
        ));
    }
    let mut spec = SCHEDULE[0].1;
    for (from, id) in SCHEDULE {
        if block_number >= from {
            spec = id;
        }
    }
    Ok(spec)
}

/// The header fields revm reads, as a [`BlockEnvWitness`].
///
/// `block_hashes` is left empty here and filled from the recorder afterwards:
/// which ancestors a block reads is a property of its execution, and nothing
/// but running it knows.
///
/// `blob_gasprice` is the one field that is **not** in the header:
/// `revm_block::BlockEnvWitness::blob_gasprice` is the whole argument, and the
/// short version is that the price derives from the excess through a fork
/// parameter revm 42 does not know past Prague, so it is read off a receipt
/// instead.
fn block_env(
    header: &Value,
    chain_id: u64,
    spec: SpecId,
    blob_gasprice: Option<u128>,
) -> Result<BlockEnvWitness, String> {
    Ok(BlockEnvWitness {
        chain_id,
        spec_id: spec as u8,
        number: rpc::word_of(&header["number"], "the block number")?,
        beneficiary: rpc::address_of(&header["miner"], "the beneficiary")?,
        timestamp: rpc::word_of(&header["timestamp"], "the timestamp")?,
        gas_limit: rpc::u64_of(&header["gasLimit"], "the gas limit")?,
        basefee: rpc::u64_of(&header["baseFeePerGas"], "the base fee")?,
        difficulty: rpc::word_of(&header["difficulty"], "the difficulty")?,
        // Post-merge `mixHash` *is* `prevrandao`; a node still reports it under
        // the pre-merge name.
        prevrandao: Some(rpc::word_of(&header["mixHash"], "prevrandao")?),
        // Present from Cancun on and absent before it, so its presence in the
        // header is the answer rather than the hardfork being consulted twice.
        excess_blob_gas: match header.get("excessBlobGas") {
            Some(Value::Null) | None => None,
            Some(value) => Some(rpc::u64_of(value, "the excess blob gas")?),
        },
        blob_gasprice,
        // EIP-7843's slot number is not a header field and no JSON-RPC method
        // serves it: it is the beacon chain's slot, which an execution-layer
        // node does not carry. Zero, as S24's synthetic block has it, until a
        // workload reads the opcode.
        slot_num: 0,
        block_hashes: Vec::new(),
    })
}

/// One JSON-RPC transaction object as a [`TxWitness`].
fn tx_witness(tx: &Value) -> Result<TxWitness, String> {
    let to = match tx.get("to") {
        Some(Value::Null) | None => None,
        Some(value) => Some(rpc::address_of(value, "the callee")?),
    };
    let tx_type = tx
        .get("type")
        .map(|v| rpc::u64_of(v, "the transaction type"))
        .transpose()?
        .unwrap_or(0);
    // `gasPrice` on a type-2 transaction is the *effective* price the node
    // computed, not the envelope's cap. revm wants the cap.
    let gas_price = match tx.get("maxFeePerGas") {
        Some(value) => rpc::u128_of(value, "the max fee per gas")?,
        None => rpc::u128_of(
            tx.get("gasPrice")
                .ok_or("the transaction has no gas price")?,
            "the gas price",
        )?,
    };
    let gas_priority_fee = match tx.get("maxPriorityFeePerGas") {
        Some(Value::Null) | None => None,
        Some(value) => Some(rpc::u128_of(value, "the max priority fee")?),
    };
    let chain_id = match tx.get("chainId") {
        Some(Value::Null) | None => None,
        Some(value) => Some(rpc::u64_of(value, "the chain id")?),
    };
    let access_list = match tx.get("accessList") {
        Some(Value::Array(items)) => {
            let mut list = Vec::with_capacity(items.len());
            for item in items {
                let address = rpc::address_of(&item["address"], "an access-list address")?;
                let keys = item["storageKeys"]
                    .as_array()
                    .ok_or("an access-list entry has no storageKeys")?
                    .iter()
                    .map(|k| rpc::word_of(k, "an access-list key"))
                    .collect::<Result<Vec<Word32>, String>>()?;
                list.push((address, keys));
            }
            list
        }
        _ => Vec::new(),
    };
    let blob_hashes = match tx.get("blobVersionedHashes") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|h| rpc::word_of(h, "a blob versioned hash"))
            .collect::<Result<Vec<Word32>, String>>()?,
        _ => Vec::new(),
    };
    let max_fee_per_blob_gas = match tx.get("maxFeePerBlobGas") {
        Some(Value::Null) | None => None,
        Some(value) => Some(rpc::u128_of(value, "the max fee per blob gas")?),
    };
    let authorizations = match tx.get("authorizationList") {
        Some(Value::Array(items)) => items
            .iter()
            .map(authorization_witness)
            .collect::<Result<Vec<AuthorizationWitness>, String>>()?,
        _ => Vec::new(),
    };
    // A type-3 or type-4 transaction whose defining field did not arrive would
    // be recorded as a type-2 one and would run under different rules. The
    // envelope decides the type in revm (`TxEnv::derive_tx_type`), so this is
    // the one place the node's own `type` field is checked against it.
    // revm keys on a *positive* blob fee and not on the field's presence
    // (`TxEnv::derive_tx_type`), so a provider that writes
    // `maxFeePerBlobGas: "0x0"` on a transaction carrying no blobs must not
    // make it a type-3 one here.
    let blob_fee_set = max_fee_per_blob_gas.is_some_and(|fee| fee != 0);
    let derived = if !blob_hashes.is_empty() || blob_fee_set {
        3
    } else if !authorizations.is_empty() {
        4
    } else if gas_priority_fee.is_some() {
        2
    } else if !access_list.is_empty() {
        1
    } else {
        0
    };
    // What the check is for is the **narrowing** direction: a type-3 whose blob
    // hashes did not arrive would be recorded as a type-2 one and would run
    // under different rules. Equality over-reached into the widening direction
    // and refused a whole block for a shape that is harmless -- EIP-2930
    // permits an empty access list, so a type-1 transaction carrying one
    // derives 0, and it then executes exactly as a legacy transaction does,
    // same intrinsic gas and same gas-price mechanics. That is why `TxWitness`
    // carries no type at all and the guest derives its own.
    //
    // That one shape is exempt and nothing else is. A declared type-2 whose
    // `maxPriorityFeePerGas` did not arrive is still refused, because it
    // changes the effective gas price -- which is why this is not the blanket
    // "accept any node type at or above the derived one" it might look like.
    let widened_harmlessly = tx_type == 1 && derived == 0;
    if derived != tx_type && !widened_harmlessly {
        return Err(format!(
            "the node calls this a type-{tx_type} transaction and its fields make it type-{derived}"
        ));
    }
    Ok(TxWitness {
        caller: rpc::address_of(&tx["from"], "the sender")?,
        to,
        value: rpc::word_of(&tx["value"], "the value")?,
        data: rpc::bytes_of(&tx["input"], "the calldata")?,
        gas_limit: rpc::u64_of(&tx["gas"], "the gas limit")?,
        gas_price,
        gas_priority_fee,
        nonce: rpc::u64_of(&tx["nonce"], "the nonce")?,
        chain_id,
        access_list,
        blob_hashes,
        max_fee_per_blob_gas,
        authorizations,
    })
}

/// The block's **blob gas price**, from `eth_feeHistory`.
///
/// `eth_feeHistory`'s `baseFeePerBlobGas` is the block's own price and is served
/// for every post-Cancun block, whether or not the block carries a blob
/// transaction — which a receipt's `blobGasPrice` is **not**: a node reports that
/// field only on the receipts of type-3 transactions, so a block with none has
/// no receipt carrying it. That was the second thing this had to learn, and it
/// matters because the `BLOBBASEFEE` opcode can read the price in any block.
///
/// One call, `blockCount = 1` and `newestBlock = block_number`, so
/// `baseFeePerBlobGas[0]` is this block's and `oldestBlock` says so.
fn blob_gasprice(rpc: &mut Rpc, block_number: u64) -> Result<u128, String> {
    let history = rpc.call(
        "eth_feeHistory",
        json!(["0x1", rpc::hex_quantity(block_number), []]),
    )?;
    let oldest = rpc::u64_of(&history["oldestBlock"], "the fee history's oldest block")?;
    if oldest != block_number {
        return Err(format!(
            "eth_feeHistory answered for block {oldest} and not {block_number}"
        ));
    }
    let fees = history["baseFeePerBlobGas"]
        .as_array()
        .ok_or_else(|| format!("block {block_number}'s fee history has no baseFeePerBlobGas"))?;
    let price = fees.first().ok_or_else(|| {
        format!("block {block_number}'s fee history carries an empty baseFeePerBlobGas")
    })?;
    rpc::u128_of(price, "the blob gas price")
}

/// One JSON-RPC authorization-list entry as an [`AuthorizationWitness`].
///
/// The node reports the signature; this VM cannot recover it, so the recorder
/// recovers it here. `alloy-eip7702`'s own recovery is behind its `k256`
/// feature, which the guest workspace does not enable, so the recovery is
/// revm's `secp256k1` precompile path — the same code the EVM itself uses for
/// `ecrecover`, which is already in this crate's graph through
/// `revm-precompile`.
fn authorization_witness(entry: &Value) -> Result<AuthorizationWitness, String> {
    let chain_id = rpc::word_of(&entry["chainId"], "an authorization chain id")?;
    let address = rpc::address_of(&entry["address"], "an authorization address")?;
    let nonce = rpc::u64_of(&entry["nonce"], "an authorization nonce")?;
    let y_parity = rpc::u64_of(
        entry
            .get("yParity")
            .or_else(|| entry.get("v"))
            .ok_or("an authorization has no yParity")?,
        "an authorization y parity",
    )?;
    let r = rpc::word_of(&entry["r"], "an authorization r")?;
    let s = rpc::word_of(&entry["s"], "an authorization s")?;
    let authority = recover_authority(chain_id, address, nonce, y_parity, r, s);
    Ok(AuthorizationWitness {
        chain_id,
        address,
        nonce,
        authority,
    })
}

/// The address an EIP-7702 authorization recovers to, or `None`.
///
/// `SignedAuthorization::recover_authority` does exactly this and is behind
/// `alloy-eip7702`'s `k256` feature. `revm-precompile` turns that feature on
/// for its own `ecrecover`, so in this crate's graph the method is available;
/// the guest's graph does not enable it, which is why the *witness* carries the
/// answer rather than the signature.
fn recover_authority(
    chain_id: Word32,
    address: Address20,
    nonce: u64,
    y_parity: u64,
    r: Word32,
    s: Word32,
) -> Option<Address20> {
    use revm::context_interface::transaction::{Authorization, SignedAuthorization};
    let parity = u8::try_from(y_parity).ok()?;
    let signed = SignedAuthorization::new_unchecked(
        Authorization {
            chain_id: U256::from_be_bytes(chain_id),
            address: Address::from(address),
            nonce,
        },
        parity,
        U256::from_be_bytes(r),
        U256::from_be_bytes(s),
    );
    signed.recover_authority().ok().map(|a| a.0 .0)
}

/// The **stateless pass**: the trie nodes that authenticate a recording's touch
/// set against the state root it was read at.
///
/// One `eth_getProof(address, slots, at)` per recorded account, and the union
/// of every `accountProof` and every `storageProof[].proof`, sorted by
/// `keccak256` and deduplicated — which is the canonical order
/// `StatelessWitness::nodes` requires, a node being named by its hash and
/// nothing else.
///
/// # What this does NOT give you, and it matters
///
/// **It is not a complete stateless witness.** `docs/spec/revm-block.md` §1.5
/// requires `nodes` to carry every node needed to apply the block's updates
/// *deterministically*, siblings and boundary nodes included. A proof carries
/// the nodes on its own key's path and no others, so a block that **deletes** a
/// key — which writing zero to a storage slot is — collapses a branch into a
/// sibling that appears in no proof. Measured over 300 randomised trials, 29 %
/// needed at least one such node.
///
/// This function returns what `eth_getProof` can give. Where that is not
/// enough, the guest says so by name (`mpt::MptError::BlindedCollapse`) rather
/// than guessing a shape nobody authenticated, and the producer has to complete
/// the set from a source that can supply it — an execution-layer client serving
/// `debug_executionWitness`, which this endpoint does not.
/// `docs/handoff/S25-block.md` §4 is the account.
pub fn collect_nodes(
    rpc: Rpc,
    at: u64,
    witness: &BlockWitness,
) -> Result<(Vec<Vec<u8>>, u64, u64), String> {
    let mut rpc = rpc;
    let mut nodes: Vec<Vec<u8>> = Vec::new();
    for account in &witness.accounts {
        let keys: Vec<String> = account
            .slots
            .iter()
            .map(|(k, _)| rpc::hex_data(k))
            .collect();
        let proof = rpc.call(
            "eth_getProof",
            json!([rpc::hex_data(&account.address), keys, rpc::hex_quantity(at)]),
        )?;
        push_proof(&mut nodes, &proof["accountProof"], "an account proof node")?;
        if let Some(Value::Array(slots)) = proof.get("storageProof") {
            for slot in slots {
                push_proof(&mut nodes, &slot["proof"], "a storage proof node")?;
            }
        }
    }
    // Sorted by hash and deduplicated: one node set, one encoding.
    nodes.sort_unstable_by_key(|n| revm::primitives::keccak256(n).0);
    nodes.dedup();
    Ok((nodes, rpc.hits, rpc.misses))
}

fn push_proof(nodes: &mut Vec<Vec<u8>>, value: &Value, what: &str) -> Result<(), String> {
    let Value::Array(items) = value else {
        return Err(format!("{what} list is not an array"));
    };
    for item in items {
        nodes.push(rpc::bytes_of(item, what)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A cache directory of this test's own, seeded by the same key `call`
    /// reads with, so `Rpc::cached` answers without any endpoint.
    fn cache(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("apogee-recorder-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a cache directory");
        dir
    }

    fn seed(dir: &std::path::Path, method: &str, params: Value, result: Value) {
        let body = crate::rpc::request_body(method, &params);
        let path = dir.join(format!("{}.json", rpc::digest_hex(body.as_bytes())));
        let text = serde_json::to_string_pretty(&result).expect("re-encodable");
        std::fs::write(path, text).expect("a seeded cache entry");
    }

    /// go-ethereum answers for an address with no state object out of a
    /// zero-valued `common.Hash`, so both hashes come back as the zero word.
    /// That is an absence, and the recorder must read it as one.
    ///
    /// Before the fix it read `exists = true` — no byte string hashes to zero,
    /// so `codeHash` was "not empty" — and then failed the `eth_getCode`
    /// cross-check with an error naming a code hash no code can have.
    #[test]
    fn geths_zero_hashes_are_an_absent_account_and_not_a_failure() {
        let dir = cache("zero-hashes");
        let address: Address20 = [0x7c; 20];
        let zero = format!("0x{}", "00".repeat(32));
        seed(
            &dir,
            "eth_getProof",
            json!([
                rpc::hex_data(&address),
                Vec::<String>::new(),
                rpc::hex_quantity(21_000_000)
            ]),
            json!({
                "nonce": "0x0",
                "balance": "0x0",
                "codeHash": zero,
                "storageHash": zero,
                "accountProof": Vec::<String>::new(),
                "storageProof": Vec::<String>::new(),
            }),
        );
        let mut recorder = WitnessRecorder::new(Rpc::cached(dir), 21_000_000);
        let info = revm::Database::basic(&mut recorder, Address::from(address))
            .expect("the zero shape is an absence, not an error");
        assert!(
            info.is_none(),
            "an account geth has no state object for must reach revm as `None`"
        );
    }

    /// The canonical empty values still read as an absence, which is the
    /// control: the normalisation must not be the only path to `None`.
    #[test]
    fn the_canonical_empty_values_are_also_an_absent_account() {
        let dir = cache("canonical-empty");
        let address: Address20 = [0x7d; 20];
        seed(
            &dir,
            "eth_getProof",
            json!([
                rpc::hex_data(&address),
                Vec::<String>::new(),
                rpc::hex_quantity(21_000_000)
            ]),
            json!({
                "nonce": "0x0",
                "balance": "0x0",
                "codeHash": rpc::hex_data(&revm::primitives::KECCAK_EMPTY.0),
                "storageHash": rpc::hex_data(&EMPTY_TRIE_ROOT),
                "accountProof": Vec::<String>::new(),
                "storageProof": Vec::<String>::new(),
            }),
        );
        let mut recorder = WitnessRecorder::new(Rpc::cached(dir), 21_000_000);
        assert!(revm::Database::basic(&mut recorder, Address::from(address))
            .expect("a well-formed answer")
            .is_none());
    }

    /// A minimal transaction body, to which each test adds what it is about.
    fn tx(kind: u64) -> Value {
        json!({
            "type": format!("0x{kind:x}"),
            "from": "0x0000000000000000000000000000000000000001",
            "to": "0x0000000000000000000000000000000000000002",
            "value": "0x0",
            "input": "0x",
            "gas": "0x5208",
            "gasPrice": "0x1",
            "nonce": "0x0",
            "chainId": "0x1",
            "accessList": Vec::<String>::new(),
        })
    }

    /// EIP-2930 permits an empty access list, and such a transaction executes
    /// exactly as a legacy one does. Refusing it aborted the whole recording.
    #[test]
    fn a_type_one_transaction_with_an_empty_access_list_is_recorded() {
        let witness = tx_witness(&tx(1)).expect("an empty access list is legal in a type-1");
        assert!(witness.access_list.is_empty());
    }

    /// The exemption is that one shape and no other. A declared type-2 whose
    /// `maxPriorityFeePerGas` did not arrive changes the effective gas price,
    /// so it is still refused — this is what a blanket "node type at or above
    /// the derived one" would have wrongly accepted.
    #[test]
    fn a_type_two_transaction_missing_its_priority_fee_is_still_refused() {
        let error = tx_witness(&tx(2)).expect_err("a type-2 without its defining field");
        assert!(
            error.contains("type-2") && error.contains("type-0"),
            "{error}"
        );
    }

    /// revm derives the type from a *positive* blob fee, not from the field's
    /// presence, so a provider that writes `0x0` on a transaction carrying no
    /// blobs must not turn it into a type-3 one.
    #[test]
    fn a_zero_blob_fee_does_not_make_a_type_three_transaction() {
        let mut body = tx(0);
        body["maxFeePerBlobGas"] = json!("0x0");
        assert!(tx_witness(&body).is_ok(), "a zero blob fee is not a blob");

        // And a real one still is.
        let mut body = tx(3);
        body["maxFeePerBlobGas"] = json!("0x1");
        body["blobVersionedHashes"] = json!([format!("0x{}", "01".repeat(32))]);
        body["maxPriorityFeePerGas"] = json!("0x1");
        body["maxFeePerGas"] = json!("0x1");
        assert!(tx_witness(&body).is_ok(), "a real type-3 still records");
    }
}
