#![no_std]
//! The revm block workload: `BlockWitness` in, the output commitment out.
//!
//! This file is the program, and it compiles from one source twice — for the
//! host, where `crates/emulator/tests/revm.rs` calls [`run`] directly as the
//! native-revm oracle, and for `riscv32imac-unknown-none-elf`, where
//! `src/main.rs` hands it fd 0 and commits what it returns to fd 1. The two
//! halves differ in exactly two ways and in nothing else:
//!
//! - **keccak256.** `revm::primitives::keccak256` is `alloy-primitives`'
//!   one-shot hash. On the guest this crate enables that crate's
//!   `native-keccak`, which turns every such call into the `extern "C"` hook
//!   [`native_keccak256`] below, which is `guest_sdk::keccak256` — the S21
//!   delegation, with its own bit-identical software fallback behind it. On
//!   the host the same call is `alloy-primitives`' own software Keccak. Every
//!   keccak this workload performs — revm's `KECCAK256` opcode, a contract's
//!   code hash, this file's two commitments — goes through that one call.
//! - **The allocator.** `guest-sdk`'s bump allocator on the guest, the host's
//!   on the host. The bump allocator never frees, so what bounds a guest run
//!   is the *total* it allocates.
//!
//! # Why revm is a dependency here and nowhere else
//!
//! Master rule 2 keeps the proving stack's cryptography in this repository and
//! admits reference implementations as dev-dependencies alone. This crate is
//! neither: it is the **workload being proven**, the thing the VM runs, and
//! `prompts/S24-revm.md` names revm a permitted guest dependency for exactly
//! that reason. It is reachable from no prover, no verifier and no other
//! guest. `revm-precompile` brings arkworks, `k256`, `p256`, `sha2` and
//! `ripemd` in with it, for the EVM's own precompiles; the same reading covers
//! them, and `docs/handoff/S24-revm.md` records it.
//!
//! # The two wire formats this file owns
//!
//! [`BlockWitness`] is fd 0 and the output commitment is fd 1, and S10's
//! frozen `io_digest` binds both. Neither carries an `Fr`, so the workspace's
//! little-endian rule for field elements does not reach them: an EVM word is
//! Ethereum's **big-endian** 32 bytes here, as it is everywhere else in
//! Ethereum, and the small integers around them are little-endian, as
//! `postcard` and the rest of this repository write them.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use revm::context::{BlockEnv, CfgEnv, TxEnv};
use revm::context_interface::block::BlobExcessGasAndPrice;
use revm::context_interface::result::{ExecutionResult, Output};
use revm::context_interface::transaction::{AccessList, AccessListItem};
use revm::database::DBErrorMarker;
use revm::primitives::eip4844::{
    BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN, BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE,
};
use revm::primitives::{
    keccak256, Address, Bytes, Log, StorageKey, StorageValue, TxKind, B256, U256,
};
use revm::state::{AccountInfo, Bytecode};
use revm::{Context, Database, ExecuteEvm, MainBuilder, MainContext};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// The keccak hook
// ---------------------------------------------------------------------------

/// `alloy-primitives`' `native-keccak` hook: every `keccak256` in this image,
/// revm's own included, arrives here.
///
/// # The `unsafe`
///
/// The repository keeps every `unsafe` block in `crates/guest-sdk/src/lib.rs`
/// and says so. This is the one exception, and it exists because the hook's
/// signature is upstream's: a raw pointer, a length and a raw output pointer,
/// which no safe function can implement. Putting it in `guest-sdk` instead
/// would be worse — a `#[no_mangle]` export there is linked into every guest,
/// and the declaration record it reaches would declare `KECCAK_F` for `fib`,
/// which is precisely the hazard the `#[used]` comment in that file describes.
/// Master rule 13 applies: must-be-exact 2 requires the routing, so the stage
/// wins and `docs/handoff/S24-revm.md` records the deviation.
///
/// # Safety
///
/// The caller guarantees `bytes` is valid for reading `len` bytes and `output`
/// is valid for writing 32, which is `native-keccak`'s documented contract and
/// is what `alloy-primitives` passes: a live slice and a `MaybeUninit<B256>`.
#[cfg(target_arch = "riscv32")]
#[no_mangle]
pub unsafe extern "C" fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8) {
    let digest = guest_sdk::keccak256(core::slice::from_raw_parts(bytes, len));
    core::ptr::copy_nonoverlapping(digest.as_ptr(), output, digest.len());
}

// ---------------------------------------------------------------------------
// The witness
// ---------------------------------------------------------------------------

/// A 20-byte Ethereum address.
pub type Address20 = [u8; 20];

/// A 256-bit EVM word, **big-endian** — Ethereum's order, not `Fr`'s.
pub type Word32 = [u8; 32];

/// The committed synthetic witness's length in bytes, pinned here and
/// asserted against `crates/emulator/tests/vectors/revm_block_witness.bin` by
/// `crates/emulator/tests/revm.rs`.
pub const COMMITTED_WITNESS_BYTES: usize = 717;

/// The hardfork enum a witness's `spec_id` names, re-exported so that a
/// fixture builder can write `SpecId::PRAGUE as u8` rather than a number.
pub use revm::primitives::hardfork::SpecId;

/// `keccak256`, as this image computes it: the S21 delegation on the guest,
/// `alloy-primitives`' own Keccak on the host.
///
/// Exported because the fixture builder needs the same hash the workload uses
/// — the counter contract's log topic is one — and because a second Keccak in
/// this repository would be a second definition to keep equal.
pub fn keccak(bytes: &[u8]) -> Word32 {
    keccak256(bytes).0
}

/// The `bytecode_size_words` this program is preprocessed under.
///
/// The frozen default is `2^20` words, a 4 MiB span from `RAM_ORIGIN`, and the
/// **debug** build of this guest is past it: revm at `opt-level = 0` spans
/// 1,370,853 words where `--release` spans 430,706. One value covers both
/// profiles, so the two builds differ in their code and in nothing else. It is
/// a declared ceiling that no circuit reads, but `VM_CONFIG` absorbs it and
/// therefore so does program identity, which is why it is pinned here rather
/// than derived per build.
pub const BYTECODE_SIZE_WORDS: u32 = 1 << 21;

/// The trace height every family takes for this program at `--release`.
///
/// A decoded table is pc/2-indexed and absolute, so a family's height must
/// reach past its own last instruction: `2^20` rows hold code up to pc
/// `0x1ffffc`, and this guest's `--release` image ends well below it. That is
/// also the floor for a cycle-owning family
/// (`docs/spec/lookup.md` §3), so it is the cheapest height this program can
/// be proven at.
pub const TRACE_HEIGHT_RELEASE: u32 = 1 << 20;

/// The trace height every family takes at `debug`, where the image is 3.3
/// times larger and its last instruction sits above `2^20` rows' reach.
///
/// Nothing is proven at this height — a `2^22` shard is four times a `2^20`
/// one — but the from-source suites trace the debug build, and a trace needs
/// a table that holds the code.
pub const TRACE_HEIGHT_DEBUG: u32 = 1 << 22;

/// The fd 0 buffer the guest reads its witness into, in one `read`.
///
/// **A tunable**, and the one number here that is a policy rather than a
/// fact: twice the largest committed witness, so a witness that grows by less
/// than half again still fits and a larger one exits loudly rather than
/// decoding a prefix. The bump allocator never frees, so this is also the
/// largest single allocation the guest makes.
///
/// **Rounded up to a whole number of words.** fd 0 is word-granular since S25
/// — one `read` moves one 4-aligned word — so a buffer whose length is not a
/// multiple of four would make the last call keep part of a word and drop the
/// rest, and `guest_sdk::read_input` refuses one rather than dropping bytes
/// silently. The `const` assertion below is what makes that a compile error
/// here instead of an exit 70 at run time.
pub const WITNESS_CAPACITY: usize = (2 * COMMITTED_WITNESS_BYTES).next_multiple_of(4);

const _: () = assert!(WITNESS_CAPACITY.is_multiple_of(4));
const _: () = assert!(WITNESS_CAPACITY >= 2 * COMMITTED_WITNESS_BYTES);

/// Everything one block's execution needs, and nothing an execution derives.
///
/// **Not frozen** (owner's decision, S24). `prompts/S24-revm.md` asked for this
/// type to be frozen here and the owner withdrew that before the stage closed,
/// because a field this stage cannot fill is already known to be missing —
/// see "The `BLOCKHASH` gap" below. A later stage adds fields and this
/// type's shape moves with them. What *is* settled is the two rules a
/// change must keep: `postcard` writes a struct's fields in
/// declaration order, so the field order below is the canonical order, and
/// [`BlockWitness::decode`] refuses a witness that is not in it — one logical
/// state has exactly one encoding, whatever the fields are.
///
/// Nothing here is synthetic-specific: S25's witness recorder produces this
/// same type for a real block, which is why an account carries general code
/// and storage entries and a transaction carries the full EIP-1559/2930
/// envelope rather than the subset this stage's two transactions use.
///
/// # The `BLOCKHASH` gap
///
/// A `block_hashes` field does not exist here, and that is the concrete
/// reason this type is not frozen. revm answers the `BLOCKHASH` opcode from
/// its `Database`, and [`run`] gives it a `CacheDB<EmptyDB>` whose block-hash
/// cache is empty, so every miss falls through to `EmptyDB`, which returns
/// **`keccak256` of the block number's decimal string** — a deterministic
/// placeholder, not any block's hash. A contract reading `BLOCKHASH(n)` for an
/// `n` in the last 256 blocks therefore gets a made-up word today, the guest
/// and the host agree on it, and the block still "executes". The witness is
/// where a real one would have to come from, as a
/// `block_hashes: Vec<(u64, Word32)>` loaded into `CacheDB`'s cache before
/// execution. `docs/spec/revm-block.md` §1.2 is the standing note;
/// `crates/emulator/tests/revm.rs::blockhash_reads_a_placeholder_today` pins
/// the current behaviour so the gap cannot close by accident.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockWitness {
    /// The header fields revm reads.
    pub env: BlockEnvWitness,
    /// Every account the execution may touch, **sorted by address**, each
    /// with its slots **sorted by key**. An account absent from this list
    /// reads as empty.
    pub accounts: Vec<AccountWitness>,
    /// The transactions, in execution order.
    pub txs: Vec<TxWitness>,
    /// Reserved for the stateless mode: a later stage defines these bytes and
    /// what they prove about [`BlockWitness::accounts`]. S24 runs over a
    /// synthetic pre-state, so it is `None` here, and its absence changes the
    /// encoding of nothing before it.
    pub stateless: Option<Vec<u8>>,
}

/// The header fields revm reads, one per `revm::context::BlockEnv` field plus
/// the chain id and the hardfork, which live in its `CfgEnv`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockEnvWitness {
    /// EIP-155 chain id.
    pub chain_id: u64,
    /// The hardfork, as `revm::primitives::hardfork::SpecId`'s `repr(u8)`
    /// discriminant. [`BlockEnvWitness::spec`] refuses an unknown one.
    pub spec_id: u8,
    /// Block height.
    pub number: Word32,
    /// The coinbase: every transaction's gas is paid to it.
    pub beneficiary: Address20,
    /// Seconds since the epoch.
    pub timestamp: Word32,
    /// The block gas limit.
    ///
    /// [`run`] enforces it as a **running** bound — a transaction's gas limit
    /// must fit in what the block has left — which is the consensus rule and
    /// is more than revm checks on its own. See [`run`]'s note.
    pub gas_limit: u64,
    /// EIP-1559 base fee per gas.
    pub basefee: u64,
    /// Pre-merge difficulty.
    pub difficulty: Word32,
    /// Post-merge `prevrandao`, which replaces `difficulty`.
    pub prevrandao: Option<Word32>,
    /// EIP-4844 excess blob gas; the blob gas price derives from it.
    pub excess_blob_gas: Option<u64>,
    /// EIP-7843 slot number.
    pub slot_num: u64,
    /// The block hashes the `BLOCKHASH` opcode may read, **ascending by
    /// number, without repeats**.
    ///
    /// S24 had no such field and answered the opcode from an empty database,
    /// which returned `keccak256` of the block number's decimal string — a
    /// placeholder, agreed on by the guest and the host and equal to no
    /// block's hash. `docs/spec/revm-block.md` §1.2 called it the one *gap*
    /// rather than a decision, and named this field as what closes it. S25
    /// adds it: [`WitnessDb::block_hash`] answers from here, and a number this
    /// list does not carry is an error rather than a made-up word.
    ///
    /// The recorder fills it with exactly the numbers the execution asked
    /// for, so a block whose transactions never read `BLOCKHASH` carries an
    /// empty list.
    pub block_hashes: Vec<(u64, Word32)>,
}

/// One pre-state account.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountWitness {
    /// The account's address.
    pub address: Address20,
    /// Its nonce.
    pub nonce: u64,
    /// Its balance in wei.
    pub balance: Word32,
    /// Its deployed code; empty for an externally-owned account. The code
    /// hash is *not* carried: it is `keccak256(code)`, which the guest
    /// recomputes, so the witness cannot claim one the code does not have.
    pub code: Vec<u8>,
    /// Its non-zero storage, **sorted by key**. A slot absent here reads 0.
    pub slots: Vec<(Word32, Word32)>,
}

/// One transaction, already recovered: `caller` is the sender, because this VM
/// has no `ecrecover` delegation and signature recovery is not this stage's
/// workload (`prompts/00-master.md`, "Stage register").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxWitness {
    /// The sender.
    pub caller: Address20,
    /// The callee, or `None` for a contract creation.
    pub to: Option<Address20>,
    /// The value transferred, in wei.
    pub value: Word32,
    /// The calldata, or the init code of a creation.
    pub data: Vec<u8>,
    /// The gas limit.
    pub gas_limit: u64,
    /// The gas price; for an EIP-1559 transaction, the max fee per gas.
    pub gas_price: u128,
    /// EIP-1559 max priority fee per gas.
    pub gas_priority_fee: Option<u128>,
    /// The sender's nonce for this transaction.
    pub nonce: u64,
    /// EIP-155 chain id, or `None` for a pre-155 transaction.
    pub chain_id: Option<u64>,
    /// EIP-2930 access list: an address and the slots of it being warmed.
    pub access_list: Vec<(Address20, Vec<Word32>)>,
}

impl BlockEnvWitness {
    /// The hardfork this block runs under, or `None` for a discriminant no
    /// `SpecId` takes.
    pub fn spec(&self) -> Option<SpecId> {
        SpecId::try_from_u8(self.spec_id)
    }
}

/// Every way [`BlockWitness::decode`] refuses bytes. Each names what it
/// refused; there is no recovery from any of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessError {
    /// The bytes are not exactly [`BlockWitness::encode`]'s output for the
    /// witness they describe: they do not parse, they carry something after
    /// the witness, or some varint in them is not in its shortest form. One
    /// error for all three because all three are "these are not the bytes of
    /// one witness", and none leaves a caller anything to do.
    Malformed,
    /// Two accounts share an address, or the accounts are not ascending by
    /// address. `at` is the offending index.
    AccountsNotSorted { at: usize },
    /// Two slots of one account share a key, or the slots are not ascending
    /// by key. `account` and `at` name it.
    SlotsNotSorted { account: usize, at: usize },
    /// Two block hashes share a number, or they are not ascending by number.
    /// `at` is the offending index.
    BlockHashesNotSorted { at: usize },
    /// `spec_id` is a discriminant no `SpecId` takes.
    UnknownSpec { spec_id: u8 },
}

impl BlockWitness {
    /// This witness as fd 0's bytes.
    ///
    /// Panics on a witness that is not in canonical order, because an encoder
    /// that emitted one would be writing bytes [`BlockWitness::decode`]
    /// refuses — a broken caller, not bad data.
    pub fn encode(&self) -> Vec<u8> {
        assert!(
            self.canonical().is_ok(),
            "a BlockWitness is encoded in canonical order or not at all"
        );
        postcard::to_allocvec(self).expect("a BlockWitness encodes into an allocated vector")
    }

    /// fd 0's bytes as a witness, or the rule they break.
    ///
    /// Canonicity is checked here rather than assumed, so that the same
    /// logical state has exactly one encoding: the guest and the host agree on
    /// what the prover handed over, and two encodings of one state cannot
    /// produce two `io_digest`s.
    ///
    /// **The bytes must be exactly what [`BlockWitness::encode`] would write**,
    /// which is checked by re-encoding and comparing, because nothing cheaper
    /// pins `postcard`'s byte-level form. Two padding channels are open
    /// otherwise, and both are a second encoding of one state — a second
    /// `io_digest` for one execution, chosen by whoever writes fd 0:
    ///
    /// - **Trailing bytes.** `postcard::from_bytes` decodes a prefix and
    ///   ignores whatever follows, so a witness with a byte appended, or with
    ///   a second witness appended, decodes to the value of the first alone.
    /// - **Non-minimal varints.** `postcard`'s varint decoder accumulates
    ///   continuation bytes and rejects only an overflowing *last* byte; it
    ///   never requires the shortest form. So `81 00` reads as 1 exactly as
    ///   `01` does, and every length, `Option` tag, nonce and gas field in this
    ///   type is a varint. On the committed witness alone, 32 byte positions
    ///   take a two-byte non-minimal form and the widest field takes nine
    ///   extra forms — far more than `2^32` distinct fd 0 streams for one
    ///   block, every one of them a different digest.
    ///
    /// The re-encode subsumes both, and the ordering rules in [`canonical`]
    /// are checked first so that a witness out of order is refused by the rule
    /// it breaks rather than as a byte mismatch.
    ///
    /// [`canonical`]: BlockWitness::canonical
    pub fn decode(bytes: &[u8]) -> Result<BlockWitness, WitnessError> {
        let witness: BlockWitness =
            postcard::from_bytes(bytes).map_err(|_| WitnessError::Malformed)?;
        witness.canonical()?;
        let reencoded = postcard::to_allocvec(&witness).map_err(|_| WitnessError::Malformed)?;
        if reencoded != bytes {
            return Err(WitnessError::Malformed);
        }
        Ok(witness)
    }

    /// `Ok` when this witness is in must-be-exact 6's canonical order.
    fn canonical(&self) -> Result<(), WitnessError> {
        if self.env.spec().is_none() {
            return Err(WitnessError::UnknownSpec {
                spec_id: self.env.spec_id,
            });
        }
        for (i, pair) in self.env.block_hashes.windows(2).enumerate() {
            if pair[0].0 >= pair[1].0 {
                return Err(WitnessError::BlockHashesNotSorted { at: i + 1 });
            }
        }
        for (i, pair) in self.accounts.windows(2).enumerate() {
            if pair[0].address >= pair[1].address {
                return Err(WitnessError::AccountsNotSorted { at: i + 1 });
            }
        }
        for (a, account) in self.accounts.iter().enumerate() {
            for (i, pair) in account.slots.windows(2).enumerate() {
                if pair[0].0 >= pair[1].0 {
                    return Err(WitnessError::SlotsNotSorted {
                        account: a,
                        at: i + 1,
                    });
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

/// A transaction's outcome, as [`encode_output`] writes it.
const STATUS_HALT: u8 = 0;
/// Reverted by the `REVERT` opcode.
const STATUS_REVERT: u8 = 1;
/// Ran to completion.
const STATUS_SUCCESS: u8 = 2;

/// Run the block and return fd 1's bytes.
///
/// One in-memory database built from the pre-state, one `transact_one` per
/// transaction against one journal — so transaction 2 sees transaction 1's
/// writes — and one `finalize` at the end, whose accumulated state is the
/// post-state summary. A transaction revm refuses outright (a bad nonce, an
/// unpayable gas limit) is a broken witness, not an outcome: it returns `Err`
/// rather than a record, because the fixture builder's whole job is to hand
/// over a block whose transactions are executable.
///
/// # The block's gas limit is enforced here, because revm cannot
///
/// revm validates `tx.gas_limit <= block.gas_limit` for every transaction and
/// that is the most it can do: `transact_one` is *one* transaction and revm
/// carries no state across a block, so it has no cumulative gas to check
/// against. The consensus rule is the stronger one — the Yellow Paper's
/// intrinsic validity requires a transaction's gas limit to fit in what the
/// block has **left**, which is what makes the header's `gasUsed <= gasLimit`
/// true — and in a real client it is the block executor, not the EVM, that
/// applies it. This function is that block executor, so it applies it: without
/// the running total below, a witness carrying two hundred transactions of
/// twenty million gas each under a thirty-million-gas header executes happily
/// and commits a block no Ethereum node would accept.
/// # One executor, two databases
///
/// The body is [`execute`], which takes the database as an argument. That is
/// not generality for its own sake: S25's `host::WitnessRecorder` runs the
/// *same* block executor against a live, RPC-backed database to harvest the
/// touch-set, and if it ran a second copy of this loop the two could drift —
/// in the gas rule, in the environment, or in the output encoding — and the
/// differential that compares them would be comparing two programs. One
/// function, two callers, one block executor.
pub fn run(witness: &BlockWitness) -> Result<Vec<u8>, String> {
    execute(&witness.env, &witness.txs, WitnessDb::new(witness))
}

/// The block executor: one journal, one `transact_one` per transaction — so
/// transaction 2 sees transaction 1's writes — one `finalize`, and the block's
/// running gas bound.
///
/// `db` is the pre-state oracle and nothing else; revm's journal holds every
/// write. [`run`] passes a [`WitnessDb`]; S25's recorder passes one backed by
/// JSON-RPC.
pub fn execute<DB: Database>(
    env: &BlockEnvWitness,
    txs: &[TxWitness],
    db: DB,
) -> Result<Vec<u8>, String>
where
    DB::Error: core::fmt::Display,
{
    let spec = env
        .spec()
        .ok_or_else(|| alloc::format!("spec id {} is not a hardfork", env.spec_id))?;

    let mut cfg = CfgEnv::new_with_spec(spec);
    cfg.chain_id = env.chain_id;
    let mut evm = Context::mainnet()
        .with_db(db)
        .with_block(block_env(env, spec))
        .with_cfg(cfg)
        .build_mainnet();

    let mut results = Vec::with_capacity(txs.len());
    // The invariant this loop keeps: `gas_used <= env.gas_limit`, so the
    // subtraction below never wraps. It holds at 0 and is re-established by
    // the checked accumulation after every transaction.
    let mut gas_used: u64 = 0;
    for (i, tx) in txs.iter().enumerate() {
        let remaining = env.gas_limit - gas_used;
        if tx.gas_limit > remaining {
            return Err(alloc::format!(
                "transaction {i}'s gas limit {} does not fit in the block's remaining {remaining}",
                tx.gas_limit
            ));
        }
        let result = evm
            .transact_one(tx_env(tx))
            .map_err(|e| alloc::format!("transaction {i} is not executable: {e}"))?;
        // `tx_gas_used` is the receipt's `gasUsed`, which is what a block's
        // `gasUsed` accumulates, and it is bounded by the transaction's own
        // gas limit and hence by `remaining`. The checked form is here anyway:
        // a revm whose accounting changed should be a refusal, not a wrapped
        // `u64` — or, in a guest built with `overflow-checks`, a panic.
        gas_used = gas_used
            .checked_add(result.tx_gas_used())
            .filter(|total| *total <= env.gas_limit)
            .ok_or_else(|| {
                alloc::format!(
                    "transaction {i} took the block past its gas limit of {}",
                    env.gas_limit
                )
            })?;
        results.push(result);
    }
    let state = evm.finalize();

    Ok(encode_output(&results, &state))
}

// ---------------------------------------------------------------------------
// The witness database
// ---------------------------------------------------------------------------

/// Why a lookup failed. Every variant is "the witness does not carry this",
/// which is a broken witness and never an empty answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MissingState {
    /// No account at this address.
    Account(Address20),
    /// The account exists in the witness but not this slot of it.
    Slot(Address20, Word32),
    /// `BLOCKHASH` was asked for a number the witness does not carry.
    BlockHash(u64),
    /// An account was loaded without its code, which cannot happen: every
    /// [`AccountInfo`] this database returns carries its code inline.
    Code,
}

impl DBErrorMarker for MissingState {}

// `DBErrorMarker` requires `core::error::Error`, which requires `Display`.
// Both are one line here and neither is an error-type architecture: master
// anti-goal 8 bans hierarchies and source chains, and this is a flat `enum`
// that an upstream trait bound asks to be nameable.
impl core::error::Error for MissingState {}

impl core::fmt::Display for MissingState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MissingState::Account(a) => {
                write!(f, "the witness has no account {}", Address::from(*a))
            }
            MissingState::Slot(a, k) => write!(
                f,
                "the witness has no slot {} of account {}",
                B256::from(*k),
                Address::from(*a)
            ),
            MissingState::BlockHash(n) => write!(f, "the witness has no hash for block {n}"),
            MissingState::Code => f.write_str("an account was loaded without its code"),
        }
    }
}

/// revm's `Database`, answered from a [`BlockWitness`] and **nothing else**.
///
/// # A miss is an error, not an empty account
///
/// This is the whole reason the type exists, and it is a change from S24,
/// which handed revm a `CacheDB<EmptyDB>`. `EmptyDB` answers every miss: a
/// missing account reads as non-existent, a missing slot as zero, a missing
/// block hash as `keccak256` of the number's decimal string. So a witness with
/// a storage slot deleted from it executed happily against the wrong state and
/// committed an output for it — the guest could not tell an incomplete witness
/// from a complete one, and S25 acceptance 3 is exactly the demand that it
/// can. Here every lookup the witness does not answer is a
/// [`MissingState`], the block executor returns `Err`, and the guest exits
/// nonzero.
///
/// What is *not* an error is an account the witness carries as empty — nonce
/// 0, no balance, no code. That reads back as "does not exist", which is
/// EIP-161's notion of an empty account and the one revm uses, and it is how a
/// recording writes down an address it looked up and did not find.
pub struct WitnessDb<'a> {
    witness: &'a BlockWitness,
}

impl<'a> WitnessDb<'a> {
    pub fn new(witness: &'a BlockWitness) -> WitnessDb<'a> {
        WitnessDb { witness }
    }

    /// The witness's account at `address`, by binary search: the accounts are
    /// ascending by address and `decode` refuses a witness where they are not.
    fn account(&self, address: &Address20) -> Option<&AccountWitness> {
        self.witness
            .accounts
            .binary_search_by(|a| a.address.cmp(address))
            .ok()
            .map(|i| &self.witness.accounts[i])
    }
}

impl Database for WitnessDb<'_> {
    type Error = MissingState;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, MissingState> {
        let key: Address20 = address.into();
        let account = self.account(&key).ok_or(MissingState::Account(key))?;
        if account.nonce == 0 && account.balance == [0u8; 32] && account.code.is_empty() {
            // An empty account, which post-EIP-161 is indistinguishable from
            // one that does not exist. This is how a recording writes down an
            // address it looked up and did not find.
            return Ok(None);
        }
        let code = Bytes::copy_from_slice(&account.code);
        Ok(Some(AccountInfo {
            balance: U256::from_be_bytes(account.balance),
            nonce: account.nonce,
            code_hash: keccak256(&code),
            // A hint the journal uses to skip an address lookup; a witness has
            // no such hint to give.
            account_id: None,
            code: Some(Bytecode::new_raw(code)),
        }))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, MissingState> {
        Err(MissingState::Code)
    }

    fn storage(
        &mut self,
        address: Address,
        index: StorageKey,
    ) -> Result<StorageValue, MissingState> {
        let key: Address20 = address.into();
        let slot: Word32 = index.to_be_bytes();
        let account = self.account(&key).ok_or(MissingState::Account(key))?;
        account
            .slots
            .binary_search_by(|(k, _)| k.cmp(&slot))
            .map(|i| U256::from_be_bytes(account.slots[i].1))
            .map_err(|_| MissingState::Slot(key, slot))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, MissingState> {
        self.witness
            .env
            .block_hashes
            .binary_search_by(|(n, _)| n.cmp(&number))
            .map(|i| B256::from(self.witness.env.block_hashes[i].1))
            .map_err(|_| MissingState::BlockHash(number))
    }
}

/// The witness's header fields as revm's `BlockEnv`.
///
/// The blob base fee's update fraction is the **fork's**, not a constant:
/// EIP-4844 set it at Cancun and EIP-7691 raised it at Prague, and a block
/// priced with the wrong one charges the wrong blob gas. It is picked here
/// rather than in the witness because it is a property of the hardfork the
/// witness already names.
fn block_env(env: &BlockEnvWitness, spec: SpecId) -> BlockEnv {
    let fraction = if spec.is_enabled_in(SpecId::PRAGUE) {
        BLOB_BASE_FEE_UPDATE_FRACTION_PRAGUE
    } else {
        BLOB_BASE_FEE_UPDATE_FRACTION_CANCUN
    };
    BlockEnv {
        number: U256::from_be_bytes(env.number),
        beneficiary: Address::from(env.beneficiary),
        timestamp: U256::from_be_bytes(env.timestamp),
        gas_limit: env.gas_limit,
        basefee: env.basefee,
        difficulty: U256::from_be_bytes(env.difficulty),
        prevrandao: env.prevrandao.map(B256::new),
        blob_excess_gas_and_price: env
            .excess_blob_gas
            .map(|excess| BlobExcessGasAndPrice::new(excess, fraction)),
        slot_num: env.slot_num,
    }
}

/// One witness transaction as revm's `TxEnv`.
///
/// `tx_type` is derived from the envelope rather than carried, so a witness
/// cannot claim a type its fields do not support.
fn tx_env(tx: &TxWitness) -> TxEnv {
    let mut env = TxEnv::builder()
        .caller(Address::from(tx.caller))
        .kind(match tx.to {
            Some(to) => TxKind::Call(Address::from(to)),
            None => TxKind::Create,
        })
        .value(U256::from_be_bytes(tx.value))
        .data(Bytes::copy_from_slice(&tx.data))
        .gas_limit(tx.gas_limit)
        .gas_price(tx.gas_price)
        .gas_priority_fee(tx.gas_priority_fee)
        .nonce(tx.nonce)
        .chain_id(tx.chain_id)
        .access_list(access_list(&tx.access_list))
        .build_fill();
    env.derive_tx_type()
        .expect("a witness transaction's envelope names a transaction type");
    env
}

/// The EIP-2930 access list, as revm's type.
fn access_list(list: &[(Address20, Vec<Word32>)]) -> AccessList {
    AccessList(
        list.iter()
            .map(|(address, keys)| AccessListItem {
                address: Address::from(*address),
                storage_keys: keys.iter().map(|k| B256::new(*k)).collect(),
            })
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// The output commitment
// ---------------------------------------------------------------------------

/// fd 1's bytes: must-be-exact 7's three sections, in order and always all
/// three.
///
/// ```text
///   per-tx records, in execution order, one per transaction:
///       status      u8       0 halt, 1 revert, 2 success
///       gas_used    u64 LE
///       output_len  u32 LE
///       output      output_len bytes
///   logs commitment       32 bytes  keccak256(encode_logs(..))
///   post-state summary    32 bytes  keccak256(encode_post_state(..))
/// ```
///
/// The section *list* is fixed — three sections, never an optional one — and
/// the record count is the witness's transaction count, which fd 0 carries
/// and `io_digest` binds alongside these bytes. A record's `output` is the
/// transaction's own return data and is as long as the transaction made it;
/// `output_len` is what makes the stream parseable without it.
fn encode_output(results: &[ExecutionResult], state: &revm::state::EvmState) -> Vec<u8> {
    let mut out = Vec::new();
    let mut logs: Vec<&Log> = Vec::new();
    for result in results {
        let (status, output) = match result {
            ExecutionResult::Success { output, .. } => (
                STATUS_SUCCESS,
                match output {
                    Output::Call(data) => data.clone(),
                    Output::Create(data, _) => data.clone(),
                },
            ),
            ExecutionResult::Revert { output, .. } => (STATUS_REVERT, output.clone()),
            ExecutionResult::Halt { .. } => (STATUS_HALT, Bytes::new()),
        };
        out.push(status);
        out.extend_from_slice(&result.tx_gas_used().to_le_bytes());
        out.extend_from_slice(&(output.len() as u32).to_le_bytes());
        out.extend_from_slice(&output);
        logs.extend(result.logs());
    }
    out.extend_from_slice(keccak256(encode_logs(&logs)).as_slice());
    out.extend_from_slice(keccak256(encode_post_state(state)).as_slice());
    out
}

/// The log list, canonically: the count, then every log in emission order
/// across every transaction.
///
/// ```text
///   count        u32 LE
///   per log:
///       address      20 bytes
///       topic_count  u8
///       topics       32 bytes each
///       data_len     u32 LE
///       data         data_len bytes
/// ```
fn encode_logs(logs: &[&Log]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(logs.len() as u32).to_le_bytes());
    for log in logs {
        out.extend_from_slice(log.address.as_slice());
        out.push(log.topics().len() as u8);
        for topic in log.topics() {
            out.extend_from_slice(topic.as_slice());
        }
        out.extend_from_slice(&(log.data.data.len() as u32).to_le_bytes());
        out.extend_from_slice(&log.data.data);
    }
    out
}

/// The post-state summary's preimage: every account the execution touched,
/// sorted by address, each with its slots sorted by key.
///
/// ```text
///   count        u32 LE
///   per account:
///       address      20 bytes
///       nonce        u64 LE
///       balance      32 bytes BE
///       code_hash    32 bytes
///       slot_count   u32 LE
///       per slot:    key 32 BE ‖ value 32 BE
/// ```
///
/// Sorting is what makes this deterministic: revm's state is a hash map, and
/// its iteration order is neither stable across runs nor the same on a 32-bit
/// guest as on a 64-bit host.
fn encode_post_state(state: &revm::state::EvmState) -> Vec<u8> {
    let mut accounts: Vec<_> = state.iter().collect();
    accounts.sort_unstable_by_key(|(address, _)| **address);
    let mut out = Vec::new();
    out.extend_from_slice(&(accounts.len() as u32).to_le_bytes());
    for (address, account) in accounts {
        let mut slots: Vec<_> = account.storage.iter().collect();
        slots.sort_unstable_by_key(|(key, _)| **key);
        out.extend_from_slice(address.as_slice());
        out.extend_from_slice(&account.info.nonce.to_le_bytes());
        out.extend_from_slice(&account.info.balance.to_be_bytes::<32>());
        out.extend_from_slice(account.info.code_hash.as_slice());
        out.extend_from_slice(&(slots.len() as u32).to_le_bytes());
        for (key, slot) in slots {
            out.extend_from_slice(&key.to_be_bytes::<32>());
            out.extend_from_slice(&slot.present_value.to_be_bytes::<32>());
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The output digest
// ---------------------------------------------------------------------------
