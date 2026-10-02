//! The pre-state, read the way the canonical stateless validator reads it: from
//! the trie the witness's nodes build under the parent's state root, code by
//! its hash, ancestors from the validated header chain.
//!
//! **There are no recorded values to trust.** The canonical `ExecutionWitness`
//! carries trie-node preimages, code preimages and ancestor headers, and
//! nothing else (`forks/amsterdam/stateless.py`); every account, slot and code
//! revm asks for is answered by walking a trie whose every node was looked up
//! by the hash its parent names, so a read *is* its own authentication. A node
//! the walk needs and the witness lacks is [`WitnessError::Trie`]'s
//! `MissingNode` — never an absence, which is how a truncated witness would
//! otherwise prove any key empty.
//!
//! The tries are parsed once and kept: the state trie when the database is
//! built, a storage trie the first time an account's slot is read. The block's
//! writes are applied to the same structures afterwards (`crate::stateless`),
//! which is what makes authentication and the post-state root one code path.

use alloc::vec::Vec;

use revm::primitives::{Address, Bytes, StorageKey, B256, KECCAK_EMPTY, U256};
use revm::state::{AccountInfo, Bytecode};

use crate::mpt::{self, MptError, Node, NodeMap, EMPTY_TRIE_ROOT};
use crate::{keccak, Address20, Word32};

/// Everything a read can find wrong with the witness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessError {
    /// A node the walk needs is missing or malformed — a storage leaf that
    /// does not decode included, which `tests-zkevm@v21.0.1` made a failure
    /// rather than a zero.
    Trie(MptError),
    /// revm asked for code the witness does not carry.
    MissingCode { code_hash: Word32 },
    /// `BLOCKHASH` asked for an ancestor the header chain does not reach.
    MissingBlockHash { number: u64 },
}

impl From<MptError> for WitnessError {
    fn from(e: MptError) -> WitnessError {
        WitnessError::Trie(e)
    }
}

impl core::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

impl core::error::Error for WitnessError {}
impl revm::database_interface::DBErrorMarker for WitnessError {}

/// The pre-state as revm's database.
pub struct WitnessDb<'a> {
    nodes: NodeMap<'a>,
    /// Code preimages keyed by their `keccak256`, ascending.
    codes: Vec<(Word32, &'a [u8])>,
    /// The state trie under the parent's state root.
    pub state: Node,
    /// Storage tries parsed on first read, ascending by address.
    pub storage: Vec<(Address20, Node)>,
    /// `(number, hash)` for every ancestor the header chain names, ascending.
    block_hashes: Vec<(u64, Word32)>,
}

impl<'a> WitnessDb<'a> {
    /// The database over a witness, its state trie rooted at `state_root` —
    /// the parent header's.
    pub fn new(
        state_root: &Word32,
        state_nodes: &[&'a [u8]],
        codes: &[&'a [u8]],
        block_hashes: Vec<(u64, Word32)>,
    ) -> Result<WitnessDb<'a>, WitnessError> {
        let nodes = NodeMap::new(state_nodes);
        let state = mpt::build(&nodes, state_root)?;
        let mut codes: Vec<(Word32, &'a [u8])> = codes.iter().map(|c| (keccak(c), *c)).collect();
        codes.sort_unstable_by_key(|c| c.0);
        codes.dedup_by(|a, b| a.0 == b.0);
        Ok(WitnessDb {
            nodes,
            codes,
            state,
            storage: Vec::new(),
            block_hashes,
        })
    }

    /// The account at `address` in the pre-state: `(nonce, balance,
    /// storage_root, code_hash)`, or `None` when the trie proves it absent.
    pub fn account(
        &self,
        address: &Address20,
    ) -> Result<Option<(u64, Word32, Word32, Word32)>, WitnessError> {
        let path = mpt::nibbles(&keccak(address));
        match mpt::get(&self.state, &path)? {
            None => Ok(None),
            Some(leaf) => Ok(Some(mpt::decode_account(&leaf)?)),
        }
    }

    /// The storage trie of `address`, parsed the first time it is asked for.
    pub fn storage_trie(&mut self, address: &Address20) -> Result<&Node, WitnessError> {
        let at = match self.storage.binary_search_by(|(a, _)| a.cmp(address)) {
            Ok(at) => at,
            Err(at) => {
                let root = match self.account(address)? {
                    Some((_, _, storage_root, _)) => storage_root,
                    None => EMPTY_TRIE_ROOT,
                };
                let trie = mpt::build(&self.nodes, &root)?;
                self.storage.insert(at, (*address, trie));
                at
            }
        };
        Ok(&self.storage[at].1)
    }
}

impl revm::Database for WitnessDb<'_> {
    type Error = WitnessError;

    /// The account without its code, which revm then asks [`Self::code_by_hash`]
    /// for only when it runs or inspects it. The witness carries exactly the
    /// codes the spec's execution read — a block's coinbase may be a contract
    /// whose code nothing reads — so a database that loaded every account's
    /// code with it would refuse valid blocks for code they never needed.
    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, WitnessError> {
        let Some((nonce, balance, _, code_hash)) = self.account(&address.0 .0)? else {
            return Ok(None);
        };
        Ok(Some(AccountInfo {
            balance: U256::from_be_bytes(balance),
            nonce,
            code_hash: B256::new(code_hash),
            account_id: None,
            code: None,
        }))
    }

    /// Code by its hash. Bytes that begin with EIP-7702's `0xef01` and are not
    /// a 23-byte delegation are ordinary code, as the spec reads them
    /// (`is_valid_delegation`), and revm runs them as legacy: their first
    /// opcode is invalid either way.
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, WitnessError> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        let at = self
            .codes
            .binary_search_by(|(h, _)| h.cmp(&code_hash.0))
            .map_err(|_| WitnessError::MissingCode {
                code_hash: code_hash.0,
            })?;
        let bytes = Bytes::copy_from_slice(self.codes[at].1);
        Ok(
            Bytecode::new_raw_checked(bytes.clone())
                .unwrap_or_else(|_| Bytecode::new_legacy(bytes)),
        )
    }

    fn storage(&mut self, address: Address, index: StorageKey) -> Result<U256, WitnessError> {
        let path = mpt::nibbles(&keccak(&index.to_be_bytes::<32>()));
        let trie = self.storage_trie(&address.0 .0)?;
        match mpt::get(trie, &path)? {
            None => Ok(U256::ZERO),
            Some(leaf) => Ok(U256::from_be_bytes(mpt::decode_slot(&leaf)?)),
        }
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, WitnessError> {
        let at = self
            .block_hashes
            .binary_search_by(|(n, _)| n.cmp(&number))
            .map_err(|_| WitnessError::MissingBlockHash { number })?;
        Ok(B256::new(self.block_hashes[at].1))
    }
}
