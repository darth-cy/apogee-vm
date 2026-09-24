//! `WitnessRecorder`: a mainnet block and a transaction range in, a
//! `BlockWitness` out.
//!
//! The recorder executes the chosen transactions **once, natively**, against a
//! database backed by `eth_getProof` / `eth_getCode` / `eth_getStorageAt`, and
//! harvests the touch-set from the database wrapper. What it emits is exactly
//! the state those transactions read, and nothing else: a witness with a
//! surplus entry is larger than it needs to be, and a witness with a missing
//! one makes the guest fail loudly rather than default (S25 acceptance 3).
//!
//! **Determinism** (must-be-exact 1) comes from three things and is worth
//! naming, because it is the property the whole pipeline rests on:
//!
//! 1. every lookup goes through [`crate::rpc::Rpc`]'s content-addressed cache,
//!    so a second recording asks for the same files and gets the same bytes;
//! 2. the touch-set is held in `BTreeMap`s keyed by address and by slot, so
//!    serialization order is the map's and not a hash map's;
//! 3. nothing here reads a clock, an environment variable other than the
//!    endpoint, or the live chain head — the block is named by hash.

use std::collections::{BTreeMap, BTreeSet};

use revm::database::DBErrorMarker;
use revm::primitives::{keccak256, Address, Bytes, StorageKey, StorageValue, B256, U256};
use revm::state::{AccountInfo, Bytecode};
use revm::Database;

use revm_block::{
    AccountWitness, Address20, BlockEnvWitness, BlockWitness, SpecId, TxWitness, Word32,
};

use crate::json::{hex_address, hex_bytes, hex_u128, hex_u64, hex_word, Json};
use crate::rpc::Rpc;

/// What to record: a block, named by hash so a reorg cannot change it, and a
/// half-open range of its transactions.
///
/// The hash is **checked** against the node's answer rather than trusted, so a
/// recording cannot silently be of a different block from the one pinned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Job {
    /// The block's number, which is what the RPC calls take.
    pub number: u64,
    /// The block's hash, as the fixture pins it.
    pub hash: Word32,
    /// Which of the block's transactions to execute, `[first, end)`.
    pub first_tx: usize,
    pub end_tx: usize,
}

impl Job {
    /// A mini-block: the first `count` transactions of `number`.
    pub fn mini_block(number: u64, hash: Word32, count: usize) -> Job {
        Job {
            number,
            hash,
            first_tx: 0,
            end_tx: count,
        }
    }
}

/// What a recording produced: the witness, and what native revm made of it.
///
/// The second half is the differential oracle of acceptance 2 — the guest is
/// held to `native_output` — and it is returned rather than recomputed so that
/// the comparison is against the *live-database* execution, not against a
/// second run over the witness.
#[derive(Clone, Debug)]
pub struct Recording {
    pub witness: BlockWitness,
    /// The output commitment native revm produced over the live database.
    pub native_output: Vec<u8>,
    /// The parent block's state root, for the stateless mode's authentication.
    pub parent_state_root: Word32,
    /// This block's state root, as its header carries it.
    pub state_root: Word32,
}

/// The recorder. One RPC client, and no state of its own.
pub struct WitnessRecorder {
    rpc: Rpc,
}

impl WitnessRecorder {
    pub fn new(rpc: Rpc) -> WitnessRecorder {
        WitnessRecorder { rpc }
    }

    /// The RPC client, for a caller that wants to reach the same cache.
    pub fn rpc(&self) -> &Rpc {
        &self.rpc
    }

    /// Record `job`.
    ///
    /// The transactions execute against the state at the **parent** block,
    /// which is the pre-state of the block being recorded. The mini-block mode
    /// makes no claim about the state root and applies none of the block's
    /// system operations — EIP-4788's beacon-root write, EIP-2935's history
    /// write, the withdrawals — which is what `prompts/S25-block.md` calls the
    /// "pseudo next-state". A mode that recomputes a root must apply them.
    pub fn record(&self, job: &Job) -> Result<Recording, String> {
        let header = self.block_header(job)?;
        let env = self.block_env_witness(&header)?;
        let txs = self.tx_witnesses(&header, job)?;

        let parent = job
            .number
            .checked_sub(1)
            .ok_or_else(|| String::from("recorder: the genesis block has no parent state"))?;
        let mut db = RpcDb::new(&self.rpc, parent);

        // The *same* block executor the guest runs, against a live database.
        // Running a second copy of that loop here is how the recorder and the
        // guest would come to disagree about the gas rule, the environment or
        // the output encoding, and the differential that compares them would
        // then be comparing two programs.
        let native_output = revm_block::execute(&env, &txs, &mut db)
            .map_err(|e| format!("recorder: the live-database execution failed: {e}"))?;

        let witness = BlockWitness {
            env: BlockEnvWitness {
                block_hashes: db.block_hashes.iter().map(|(n, h)| (*n, *h)).collect(),
                ..env
            },
            accounts: db.accounts(),
            txs,
            stateless: None,
        };
        // The recorder's own guard: what it emits must decode, which is the
        // canonicity contract of `docs/spec/revm-block.md` §1.1 checked at the
        // point the bytes are made rather than at the point they are read.
        let bytes = witness.encode();
        BlockWitness::decode(&bytes)
            .map_err(|e| format!("recorder: the witness it wrote does not decode: {e:?}"))?;

        Ok(Recording {
            witness,
            native_output,
            parent_state_root: self.parent_state_root(&header)?,
            state_root: hex_word(field_str(&header, "stateRoot")?)?,
        })
    }

    /// The block's header, with its transactions, checked against `job.hash`.
    fn block_header(&self, job: &Job) -> Result<Json, String> {
        let header = self.rpc.call(
            "eth_getBlockByNumber",
            &format!(r#"["{:#x}",true]"#, job.number),
        )?;
        if header.is_null() {
            return Err(format!(
                "recorder: block {} is not on this node",
                job.number
            ));
        }
        let hash = hex_word(field_str(&header, "hash")?)?;
        if hash != job.hash {
            return Err(format!(
                "recorder: block {} hashes to 0x{} on this node, not the pinned 0x{}",
                job.number,
                hex(&hash),
                hex(&job.hash)
            ));
        }
        Ok(header)
    }

    fn parent_state_root(&self, header: &Json) -> Result<Word32, String> {
        let parent_hash = field_str(header, "parentHash")?;
        let parent = self
            .rpc
            .call("eth_getBlockByHash", &format!(r#"["{parent_hash}",false]"#))?;
        if parent.is_null() {
            return Err(format!(
                "recorder: the parent {parent_hash} is not on this node"
            ));
        }
        hex_word(field_str(&parent, "stateRoot")?)
    }

    fn block_env_witness(&self, header: &Json) -> Result<BlockEnvWitness, String> {
        let chain_id = hex_u64(
            self.rpc
                .call("eth_chainId", "[]")?
                .as_str()
                .ok_or_else(|| String::from("recorder: eth_chainId is not a string"))?,
        )?;
        let spec = spec_of(header)?;
        Ok(BlockEnvWitness {
            chain_id,
            spec_id: spec as u8,
            number: hex_word(field_str(header, "number")?)?,
            beneficiary: hex_address(field_str(header, "miner")?)?,
            timestamp: hex_word(field_str(header, "timestamp")?)?,
            gas_limit: hex_u64(field_str(header, "gasLimit")?)?,
            basefee: optional_u64(header, "baseFeePerGas")?.unwrap_or(0),
            difficulty: hex_word(field_str(header, "difficulty")?)?,
            // Post-merge every mainnet block carries `mixHash` as the beacon
            // chain's randomness, which is what `prevrandao` is.
            prevrandao: Some(hex_word(field_str(header, "mixHash")?)?),
            excess_blob_gas: optional_u64(header, "excessBlobGas")?,
            // EIP-7843's slot number is not a header field; a block that needs
            // it carries it as a recording input, and no mainnet block this
            // stage records reads it.
            slot_num: 0,
            block_hashes: Vec::new(),
        })
    }

    fn tx_witnesses(&self, header: &Json, job: &Job) -> Result<Vec<TxWitness>, String> {
        let all = header
            .get("transactions")
            .and_then(Json::as_array)
            .ok_or_else(|| String::from("recorder: the header carries no transaction list"))?;
        if job.end_tx > all.len() || job.first_tx > job.end_tx {
            return Err(format!(
                "recorder: transactions [{}, {}) of a block with {}",
                job.first_tx,
                job.end_tx,
                all.len()
            ));
        }
        all[job.first_tx..job.end_tx]
            .iter()
            .enumerate()
            .map(|(i, tx)| tx_witness(tx).map_err(|e| format!("recorder: transaction {i}: {e}")))
            .collect()
    }
}

/// One transaction object from `eth_getBlockByNumber`.
///
/// `caller` is the node's recovered `from`. Recovery is the witness producer's
/// job — this VM has no `ecrecover` delegation (`prompts/00-master.md`, "Stage
/// register") and revm's own `TxEnv` takes a recovered caller for the same
/// reason (`docs/spec/revm-block.md` §1.2).
fn tx_witness(tx: &Json) -> Result<TxWitness, String> {
    let kind = optional_u64(tx, "type")?.unwrap_or(0);
    if kind > 2 {
        // Types 3 (EIP-4844) and 4 (EIP-7702) need fields `TxWitness` does not
        // carry, and guessing at them is worse than refusing: a blob
        // transaction priced without its blob hashes is a different
        // transaction. `docs/spec/revm-block.md` §1.2.
        return Err(format!("transaction type {kind} is not expressible yet"));
    }
    Ok(TxWitness {
        caller: hex_address(field_str(tx, "from")?)?,
        to: match tx.get("to") {
            None | Some(Json::Null) => None,
            Some(value) => Some(hex_address(
                value
                    .as_str()
                    .ok_or_else(|| String::from("`to` is not a string"))?,
            )?),
        },
        value: hex_word(field_str(tx, "value")?)?,
        data: hex_bytes(field_str(tx, "input")?)?,
        gas_limit: hex_u64(field_str(tx, "gas")?)?,
        // An EIP-1559 transaction prices with `maxFeePerGas`; a legacy or
        // EIP-2930 one with `gasPrice`, which the node reports in both fields.
        gas_price: hex_u128(field_str(tx, "gasPrice").or_else(|_| field_str(tx, "maxFeePerGas"))?)?,
        gas_priority_fee: match tx.get("maxPriorityFeePerGas") {
            None | Some(Json::Null) => None,
            Some(value) => {
                Some(hex_u128(value.as_str().ok_or_else(|| {
                    String::from("`maxPriorityFeePerGas` is not a string")
                })?)?)
            }
        },
        nonce: hex_u64(field_str(tx, "nonce")?)?,
        chain_id: match tx.get("chainId") {
            None | Some(Json::Null) => None,
            Some(value) => Some(hex_u64(
                value
                    .as_str()
                    .ok_or_else(|| String::from("`chainId` is not a string"))?,
            )?),
        },
        access_list: access_list(tx)?,
    })
}

fn access_list(tx: &Json) -> Result<Vec<(Address20, Vec<Word32>)>, String> {
    let list = match tx.get("accessList") {
        None | Some(Json::Null) => return Ok(Vec::new()),
        Some(value) => value
            .as_array()
            .ok_or_else(|| String::from("`accessList` is not an array"))?,
    };
    list.iter()
        .map(|item| {
            let address = hex_address(field_str(item, "address")?)?;
            let keys = item
                .get("storageKeys")
                .and_then(Json::as_array)
                .ok_or_else(|| String::from("an access-list item has no storageKeys"))?
                .iter()
                .map(|key| {
                    hex_word(
                        key.as_str()
                            .ok_or_else(|| String::from("a storage key is not a string"))?,
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((address, keys))
        })
        .collect()
}

/// The hardfork a block ran under.
///
/// Picked from the header's own fields rather than from a block-number table:
/// a table is a second place the fork schedule lives and it goes stale. The
/// three post-merge forks this stage can meet are told apart by the fields
/// their EIPs added.
fn spec_of(header: &Json) -> Result<SpecId, String> {
    let has = |name: &str| !matches!(header.get(name), None | Some(Json::Null));
    Ok(if has("requestsHash") {
        // EIP-7685, Prague.
        SpecId::PRAGUE
    } else if has("parentBeaconBlockRoot") {
        // EIP-4788, Cancun.
        SpecId::CANCUN
    } else if has("withdrawalsRoot") {
        // EIP-4895, Shanghai.
        SpecId::SHANGHAI
    } else {
        return Err(String::from(
            "recorder: the header is older than Shanghai, which this recorder does not record",
        ));
    })
}

// ---------------------------------------------------------------------------
// The RPC-backed database, and the touch-set it harvests
// ---------------------------------------------------------------------------

/// The error an RPC-backed lookup can fail with. revm requires the marker.
#[derive(Clone, Debug)]
pub struct DbError(pub String);

impl DBErrorMarker for DbError {}

impl core::fmt::Display for DbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DbError {}

/// What one account contributed to the touch-set.
#[derive(Clone, Debug, Default)]
struct Touched {
    nonce: u64,
    balance: Word32,
    code: Vec<u8>,
    slots: BTreeMap<Word32, Word32>,
}

/// revm's `Database`, answered from `eth_getProof` / `eth_getCode` at a fixed
/// block, recording every distinct account, slot and block hash it was asked
/// for.
///
/// The recording is of the **pre-state value**: a lookup is answered once and
/// cached, so a slot revm reads after writing it is answered from revm's own
/// journal and never reaches here. That is what makes the harvest a pre-state
/// witness rather than a mixture.
struct RpcDb<'a> {
    rpc: &'a Rpc,
    /// The block the state is read at: the parent of the one being recorded.
    at: u64,
    touched: BTreeMap<Address20, Touched>,
    /// Addresses looked up and found not to exist. They are recorded too: a
    /// witness that omits them makes the guest's lookup a miss, and a miss is
    /// an error, not an empty account.
    absent: BTreeSet<Address20>,
    block_hashes: BTreeMap<u64, Word32>,
}

impl<'a> RpcDb<'a> {
    fn new(rpc: &'a Rpc, at: u64) -> RpcDb<'a> {
        RpcDb {
            rpc,
            at,
            touched: BTreeMap::new(),
            absent: BTreeSet::new(),
            block_hashes: BTreeMap::new(),
        }
    }

    /// The touch-set as the witness's account list: ascending by address, each
    /// account's slots ascending by key, which is
    /// `docs/spec/revm-block.md` §1's canonical order.
    ///
    /// An absent account is carried as all-zero with no code and no slots,
    /// which is precisely what `WitnessDb` reads back as "does not exist" —
    /// EIP-161's notion of an empty account, and the one revm uses.
    fn accounts(&self) -> Vec<AccountWitness> {
        let mut out: Vec<AccountWitness> = self
            .touched
            .iter()
            .map(|(address, touched)| AccountWitness {
                address: *address,
                nonce: touched.nonce,
                balance: touched.balance,
                code: touched.code.clone(),
                slots: touched.slots.iter().map(|(k, v)| (*k, *v)).collect(),
            })
            .collect();
        for address in &self.absent {
            if !self.touched.contains_key(address) {
                out.push(AccountWitness {
                    address: *address,
                    nonce: 0,
                    balance: [0u8; 32],
                    code: Vec::new(),
                    slots: Vec::new(),
                });
            }
        }
        out.sort_by_key(|a| a.address);
        out
    }

    /// `eth_getProof` with no storage keys: the account's nonce, balance,
    /// code hash and storage root at [`Self::at`].
    fn account(&self, address: Address20) -> Result<Option<(u64, Word32, Word32)>, DbError> {
        let value = self
            .rpc
            .call(
                "eth_getProof",
                &format!(r#"["0x{}",[],"{:#x}"]"#, hex(&address), self.at),
            )
            .map_err(DbError)?;
        let nonce = hex_u64(field_str(&value, "nonce").map_err(DbError)?).map_err(DbError)?;
        let balance = hex_word(field_str(&value, "balance").map_err(DbError)?).map_err(DbError)?;
        let code_hash =
            hex_word(field_str(&value, "codeHash").map_err(DbError)?).map_err(DbError)?;
        let empty = keccak256([]);
        if nonce == 0
            && balance == [0u8; 32]
            && (code_hash == [0u8; 32] || code_hash == <[u8; 32]>::from(empty))
        {
            return Ok(None);
        }
        Ok(Some((nonce, balance, code_hash)))
    }

    fn code(&self, address: Address20) -> Result<Vec<u8>, DbError> {
        let value = self
            .rpc
            .call(
                "eth_getCode",
                &format!(r#"["0x{}","{:#x}"]"#, hex(&address), self.at),
            )
            .map_err(DbError)?;
        hex_bytes(
            value
                .as_str()
                .ok_or_else(|| DbError(String::from("eth_getCode is not a string")))?,
        )
        .map_err(DbError)
    }
}

impl Database for &mut RpcDb<'_> {
    type Error = DbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, DbError> {
        let key: Address20 = address.into();
        if let Some(touched) = self.touched.get(&key) {
            return Ok(Some(info(touched)));
        }
        if self.absent.contains(&key) {
            return Ok(None);
        }
        match self.account(key)? {
            None => {
                self.absent.insert(key);
                Ok(None)
            }
            Some((nonce, balance, _)) => {
                let code = self.code(key)?;
                let touched = Touched {
                    nonce,
                    balance,
                    code,
                    slots: BTreeMap::new(),
                };
                let out = info(&touched);
                self.touched.insert(key, touched);
                Ok(Some(out))
            }
        }
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, DbError> {
        // Never reached: every `AccountInfo` above carries its code inline.
        Err(DbError(format!(
            "recorder: code_by_hash({code_hash}) — an account was loaded without its code"
        )))
    }

    fn storage(&mut self, address: Address, index: StorageKey) -> Result<StorageValue, DbError> {
        let key: Address20 = address.into();
        let slot: Word32 = index.to_be_bytes();
        if let Some(value) = self.touched.get(&key).and_then(|t| t.slots.get(&slot)) {
            return Ok(U256::from_be_bytes(*value));
        }
        // A slot of an account revm has not loaded: load it first, so the
        // witness carries the account the slot belongs to.
        if !self.touched.contains_key(&key) && !self.absent.contains(&key) {
            self.basic(address)?;
        }
        let answer = self
            .rpc
            .call(
                "eth_getStorageAt",
                &format!(r#"["0x{}","0x{}","{:#x}"]"#, hex(&key), hex(&slot), self.at),
            )
            .map_err(DbError)?;
        let value = hex_word(
            answer
                .as_str()
                .ok_or_else(|| DbError(String::from("eth_getStorageAt is not a string")))?,
        )
        .map_err(DbError)?;
        // An absent account can still be asked for a slot; it reads zero, and
        // the witness records the account so the guest's lookup is a hit.
        self.touched
            .entry(key)
            .or_default()
            .slots
            .insert(slot, value);
        Ok(U256::from_be_bytes(value))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, DbError> {
        if let Some(hash) = self.block_hashes.get(&number) {
            return Ok(B256::from(*hash));
        }
        let value = self
            .rpc
            .call("eth_getBlockByNumber", &format!(r#"["{number:#x}",false]"#))
            .map_err(DbError)?;
        if value.is_null() {
            return Err(DbError(format!(
                "recorder: block {number} is not on this node"
            )));
        }
        let hash = hex_word(field_str(&value, "hash").map_err(DbError)?).map_err(DbError)?;
        self.block_hashes.insert(number, hash);
        Ok(B256::from(hash))
    }
}

fn info(touched: &Touched) -> AccountInfo {
    let code = Bytes::copy_from_slice(&touched.code);
    AccountInfo {
        balance: U256::from_be_bytes(touched.balance),
        nonce: touched.nonce,
        code_hash: keccak256(&code),
        account_id: None,
        code: Some(Bytecode::new_raw(code)),
    }
}

// ---------------------------------------------------------------------------
// Small readers
// ---------------------------------------------------------------------------

fn field_str<'a>(value: &'a Json, name: &str) -> Result<&'a str, String> {
    value
        .get(name)
        .and_then(Json::as_str)
        .ok_or_else(|| format!("no string field `{name}`"))
}

fn optional_u64(value: &Json, name: &str) -> Result<Option<u64>, String> {
    match value.get(name) {
        None | Some(Json::Null) => Ok(None),
        Some(field) => {
            Ok(Some(hex_u64(field.as_str().ok_or_else(|| {
                format!("field `{name}` is not a string")
            })?)?))
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_hash_that_does_not_match_is_refused() {
        // Offline, so the failure is the cache miss naming the call — which is
        // itself the property must-be-exact 6 asks for: no test reaches RPC.
        let recorder = WitnessRecorder::new(Rpc::offline(std::env::temp_dir().join("apogee-none")));
        let job = Job::mini_block(1, [0u8; 32], 2);
        let error = recorder.record(&job).expect_err("offline");
        assert!(error.contains("eth_getBlockByNumber"), "{error}");
    }

    #[test]
    fn a_transaction_type_this_witness_cannot_express_is_refused() {
        let tx =
            crate::json::parse(r#"{"type":"0x3","from":"0x00","value":"0x0"}"#).expect("parses");
        let error = tx_witness(&tx).expect_err("type 3");
        assert!(error.contains("type 3"), "{error}");
    }
}
