#![no_std]
//! The revm block workload: `BlockWitness` in, the output commitment out.
//!
//! This file is the program, and it compiles from one source twice — for the
//! host, where `crates/emulator/tests/revm.rs` calls [`run`] directly as the
//! native-revm oracle, and for `riscv32imac-unknown-none-elf`, where
//! `src/main.rs` hands it the **advice** region and commits what it returns to
//! the **journal**. This file names no transport: it takes the witness's bytes
//! and returns the commitment's, and which memory those bytes arrive in and
//! leave by is the binary's business, not the workload's — `src/stdio.rs` is
//! the same computation over fd 0 and fd 1. The two halves differ in exactly
//! two ways and in nothing else:
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
//! [`BlockWitness`] is what goes in and the output commitment is what comes
//! out. Since S-IO the witness is **advice**, which nothing binds, and the
//! commitment is the **journal**, whose bytes the statement carries
//! (`docs/spec/public-values.md`); what stands in for binding the witness is
//! this file's own checks — [`BlockWitness::decode`]'s canonicity rules and
//! [`WitnessDb`]'s refusal to default — plus, in the **stateless** mode, the
//! two state roots its journal publishes (`src/stateless.rs`). Neither carries an `Fr`, so the
//! workspace's little-endian rule for field elements does not reach them: an
//! EVM word is Ethereum's **big-endian** 32 bytes here, as it is everywhere
//! else in Ethereum, and the small integers around them are little-endian, as
//! `postcard` and the rest of this repository write them.

extern crate alloc;

pub mod mpt;
pub mod stateless;

use alloc::string::String;
use alloc::vec::Vec;

use revm::context::{BlockEnv, CfgEnv, TxEnv};
use revm::context_interface::block::BlobExcessGasAndPrice;
use revm::context_interface::result::{ExecutionResult, Output};
use revm::context_interface::transaction::{AccessList, AccessListItem};
use revm::context_interface::transaction::{
    Authorization, RecoveredAuthority, RecoveredAuthorization,
};
use revm::primitives::{keccak256, Address, Bytes, Log, StorageKey, TxKind, B256, U256};
use revm::state::{AccountInfo, Bytecode};
use revm::{Context, ExecuteEvm, MainBuilder, MainContext};
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
///
/// 725 since S26, which appended `BlockEnvWitness::blob_gasprice`: the synthetic
/// block sets it to `Some(1)`, which is the `Option` tag plus a one-byte varint
/// (`docs/spec/revm-block.md` §1.6). `cargo run -p kat-gen -- revm` prints the
/// number it should be.
pub const COMMITTED_WITNESS_BYTES: usize = 725;

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

/// The fd 0 buffer `src/stdio.rs` reads its witness into, in one `read`.
///
/// The provable binary has no buffer at all: advice *is* memory, so
/// `src/main.rs` decodes the region in place and this constant does not
/// reach it.
///
/// **A tunable**, and the one number here that is a policy rather than a
/// fact: twice the largest committed witness, so a witness that grows by less
/// than half again still fits and a larger one exits loudly rather than
/// decoding a prefix. The bump allocator never frees, so this is also the
/// largest single allocation the guest makes.
pub const WITNESS_CAPACITY: usize = 2 * COMMITTED_WITNESS_BYTES;

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
    /// Every account the execution touches, **sorted by address**, each with
    /// its slots **sorted by key**.
    ///
    /// **An address absent from this list is an error, not an empty account**
    /// (S25). S24 read an absent address as empty, which made an incomplete
    /// witness indistinguishable from a complete one describing a sparser
    /// chain — and since S-IO nothing binds the witness at all, so a silent
    /// default is a value the prover chose. An account that genuinely does not
    /// exist is *recorded*, with nonce 0, balance 0, no code and no slots, and
    /// [`WitnessDb`] reports exactly that shape to revm as `None`. S25's
    /// must-be-exact 3 asks for this in the stateless mode and there is no
    /// reason for the mini mode to be laxer: `crates/host/tests/witness.rs`'s
    /// completeness control deletes one recorded slot and requires the run to
    /// fail loudly.
    pub accounts: Vec<AccountWitness>,
    /// The transactions, in execution order.
    pub txs: Vec<TxWitness>,
    /// The stateless section, absent in the synthetic and mini modes.
    ///
    /// Its presence is what tells the two modes apart in the data, and
    /// `src/stateless.rs` is the binary that requires it. S24 left the shape to
    /// the stage that needed it; S25 is that stage and [`StatelessWitness`] is
    /// the shape.
    pub stateless: Option<StatelessWitness>,
}

/// What a **stateless** execution needs beyond the values: the trie nodes that
/// authenticate them, and the block-level work that is not a transaction.
///
/// # The completeness requirement, which is normative
///
/// **`nodes` carries every trie node needed to apply the block's state updates
/// deterministically — siblings and boundary nodes included, not merely the
/// nodes on each touched key's own path** (owner's decision, S25). The guest
/// authenticates every node it uses against the trie hash that names it, and
/// refuses by name when one is missing; it never reconstructs, infers or
/// guesses a node it was not given.
///
/// The rule is not bureaucratic. Deleting a key whose branch is left with
/// exactly one child requires merging that child upward, which needs the
/// child's **type and path** and not just its hash — and the child is a
/// *sibling* of the deleted key, so it is on no touched key's path and appears
/// in no `eth_getProof` response. Measured over 300 randomised
/// build-prove-update-recompute trials, 29 % needed at least one such node.
/// Writing zero to a storage slot is a deletion, and the gas refund makes it
/// common, so this is the ordinary case rather than a corner of it.
///
/// A witness that omits one is **incomplete, and the guest says so**
/// ([`mpt::MptError::BlindedCollapse`], which names the hash). The producer's
/// job is to supply them; nothing here infers them, because an inference in the
/// guest would be a shape nobody authenticated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatelessWitness {
    /// The parent block's state root. Every recorded account and slot is
    /// authenticated against this before it is used, and the journal publishes
    /// it, so a witness describing a different pre-state publishes a different
    /// result rather than the same one.
    pub parent_state_root: Word32,
    /// The parent block's hash, which EIP-2935's system call writes into the
    /// history contract.
    pub parent_hash: Word32,
    /// EIP-4788's parent beacon block root, from the header. `None` before
    /// Cancun.
    pub parent_beacon_block_root: Option<Word32>,
    /// EIP-4895 withdrawals, in the header's order.
    pub withdrawals: Vec<WithdrawalWitness>,
    /// The trie nodes, **sorted by their `keccak256`, without repeats** — one
    /// pool for the state trie and every storage trie, because a node is named
    /// by its hash and nothing else. See the completeness requirement above.
    pub nodes: Vec<Vec<u8>>,
}

/// One EIP-4895 withdrawal: a credit the block executor applies after the last
/// transaction, which is not a transaction and which revm does not model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalWitness {
    /// The withdrawal's index, which the header orders by.
    pub index: u64,
    /// The validator it belongs to.
    pub validator_index: u64,
    /// Where the ether goes.
    pub address: Address20,
    /// How much, **in gwei** — the consensus layer's unit, which the execution
    /// layer multiplies by `10^9`.
    pub amount_gwei: u64,
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
    /// EIP-4844 excess blob gas.
    pub excess_blob_gas: Option<u64>,
    /// EIP-4844's **blob gas price**, recorded rather than derived.
    ///
    /// The price is `fake_exponential(1, excess_blob_gas,
    /// BLOB_BASE_FEE_UPDATE_FRACTION)`, and the update fraction is a
    /// **fork parameter that keeps changing**: EIP-4844 set it at 3,338,477,
    /// EIP-7691 raised it to 5,007,716 at Prague, and Fusaka's BPO forks
    /// (EIP-7892) raise it again on a schedule revm 42 does not know — it
    /// carries the Cancun and Prague constants and nothing after them. S25's
    /// guest therefore computed Prague's answer for a post-Fusaka block and got
    /// **4,387,037,219,060,994 where the chain says 5,055,772**, a factor of
    /// 8.7e8, which made every block carrying a type-3 transaction refuse to
    /// execute: revm checks `max_fee_per_blob_gas >= blob_gasprice` per
    /// transaction, and no real transaction sets a limit anywhere near that.
    ///
    /// So it is recorded. `blobGasPrice` is on every receipt of every
    /// post-Cancun block, which makes the chain itself the source, and the
    /// guest does no `fake_exponential` at all — worth 2.0% of a mini-block's
    /// cycles on its own (`docs/spec/profiling.md`). It is **advice like every
    /// other field here**, bound by the journal the execution publishes and, in
    /// the stateless mode, by the post-state root
    /// (`docs/spec/revm-block.md` §1.3).
    ///
    /// `Some` exactly when `excess_blob_gas` is; [`BlockWitness::canonical`]
    /// refuses any other pairing, because a witness that carried an excess and
    /// no price would be one the guest had to derive a price for.
    pub blob_gasprice: Option<u128>,
    /// EIP-7843 slot number.
    pub slot_num: u64,
    /// The ancestor hashes the `BLOCKHASH` opcode may read, **ascending by
    /// number, without repeats**.
    ///
    /// S24 had no such field and that was the one *gap* in this type rather
    /// than a decision (`docs/spec/revm-block.md` §1.2): revm answers
    /// `BLOCKHASH` from its database, S24's database had an empty block-hash
    /// cache, and every lookup fell through to `EmptyDB`, which returns
    /// `keccak256` of the block number's decimal string — a made-up word the
    /// guest and the host happened to agree on. S25 closes it, which is why
    /// `crates/emulator/tests/revm.rs::blockhash_reads_a_placeholder_today`
    /// had to be rewritten rather than merely kept passing: it pinned the
    /// placeholder precisely so that closing the gap would be a decision.
    ///
    /// **At most 256 entries are ever needed**, and a witness carrying more is
    /// carrying dead weight rather than lying: the opcode is served from
    /// `revm-interpreter`'s `blockhash` instruction, which pushes zero without
    /// consulting the database when the requested height is the current one or
    /// more than `BLOCK_HASH_HISTORY = 256` behind it.
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
    /// Every storage slot of this account that the execution reads, **sorted
    /// by key**, including the ones whose value is zero.
    ///
    /// A slot absent here is an error and not a zero: see [`BlockWitness::
    /// accounts`]. A zero-valued slot is therefore a recorded fact, which is
    /// what makes deleting one from a witness detectable.
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
    /// EIP-4844 blob versioned hashes, in the transaction's own order. Empty
    /// for every transaction that is not type 3.
    ///
    /// The blobs themselves are not here and must not be: a type-3
    /// transaction's payload is not part of the execution-layer block, and the
    /// EVM sees only these hashes, through `BLOBHASH`.
    pub blob_hashes: Vec<Word32>,
    /// EIP-4844 max fee per blob gas. `Some` exactly on a type-3 transaction.
    pub max_fee_per_blob_gas: Option<u128>,
    /// EIP-7702 authorization list, in the transaction's own order. Empty for
    /// every transaction that is not type 4.
    pub authorizations: Vec<AuthorizationWitness>,
}

/// One EIP-7702 authorization, **already recovered**.
///
/// `authority` is the address the signature recovers to, or `None` when it
/// recovers to nothing — which is not an error, because EIP-7702 says an
/// authorization that fails to recover is skipped and the transaction still
/// runs. Recovery is the witness producer's job for the same reason `caller`
/// is: there is no `ecrecover` delegation in this repository
/// (`prompts/00-master.md`, "Stage register"), and revm's own
/// `RecoveredAuthorization` takes a recovered authority for the same reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationWitness {
    /// The chain the authorization is for; `0` means every chain.
    pub chain_id: Word32,
    /// The address whose code the authority delegates to.
    pub address: Address20,
    /// The authority's nonce at signing time.
    pub nonce: u64,
    /// The recovered signer, or `None` when the signature recovers to nothing.
    pub authority: Option<Address20>,
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
    /// `spec_id` is a discriminant no `SpecId` takes.
    UnknownSpec { spec_id: u8 },
    /// Two ancestor hashes share a number, or they are not ascending by
    /// number. `at` is the offending index.
    BlockHashesNotSorted { at: usize },
    /// Two stateless trie nodes are equal, or they are not ascending by
    /// `keccak256`. Sorting by hash is what gives one node set exactly one
    /// encoding, a node being named by its hash and nothing else.
    NodesNotSorted { at: usize },
    /// Two withdrawals share an index, or they are not ascending by index.
    WithdrawalsNotSorted { at: usize },
    /// `excess_blob_gas` and `blob_gasprice` are not both present or both
    /// absent. They are one fact about the block — EIP-4844 is on or it is not
    /// — and a witness carrying one without the other would be one the guest had
    /// to derive the other for, which is the derivation
    /// [`BlockEnvWitness::blob_gasprice`] exists to remove.
    BlobPairing,
}

impl BlockWitness {
    /// This witness as the bytes a prover hands over.
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

    /// Those bytes as a witness, or the rule they break.
    ///
    /// Canonicity is checked here rather than assumed, so that the same
    /// logical state has exactly one encoding: the guest and the host agree on
    /// what the prover handed over. Since S-IO the witness is **advice**, which
    /// nothing in the proof system binds, so this is not a tidiness check — it
    /// is one of the two things standing between a prover-supplied byte string
    /// and the block the journal claims was executed
    /// (`docs/spec/public-values.md` §6). The other depends on the mode: the
    /// **stateless** one publishes the state roots the block began and ended on
    /// (`src/stateless.rs`), so a witness describing a different pre-state
    /// publishes a different result; the **mini** one publishes no root, which
    /// is what "claims no state-root recomputation" means, and what it binds is
    /// the journal to the witness and nothing further.
    ///
    /// **The bytes must be exactly what [`BlockWitness::encode`] would write**,
    /// which is checked by re-encoding and comparing, because nothing cheaper
    /// pins `postcard`'s byte-level form. Two padding channels are open
    /// otherwise, and both are a second encoding of one state, chosen by
    /// whoever supplies the bytes:
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
    ///   extra forms — far more than `2^32` distinct advice regions decoding
    ///   to one block.
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
        if self.env.excess_blob_gas.is_some() != self.env.blob_gasprice.is_some() {
            return Err(WitnessError::BlobPairing);
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
        for (i, pair) in self.env.block_hashes.windows(2).enumerate() {
            if pair[0].0 >= pair[1].0 {
                return Err(WitnessError::BlockHashesNotSorted { at: i + 1 });
            }
        }
        if let Some(stateless) = &self.stateless {
            for (i, pair) in stateless.nodes.windows(2).enumerate() {
                if keccak(&pair[0]) >= keccak(&pair[1]) {
                    return Err(WitnessError::NodesNotSorted { at: i + 1 });
                }
            }
            for (i, pair) in stateless.withdrawals.windows(2).enumerate() {
                if pair[0].index >= pair[1].index {
                    return Err(WitnessError::WithdrawalsNotSorted { at: i + 1 });
                }
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The database
// ---------------------------------------------------------------------------

/// Everything [`WitnessDb`] refuses, and it refuses rather than defaults.
///
/// Since S-IO the witness is **advice**, which nothing in the proof system
/// binds (`docs/spec/public-values.md` §6). A database that answered an
/// unrecorded read with a plausible default would therefore be answering it
/// with a value the prover chose, and the guest would commit an output for a
/// state nobody supplied. Every miss is an error instead, and the error names
/// what was missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DbError {
    /// The execution read an account the witness does not carry.
    UnknownAccount { address: Address20 },
    /// The execution read a storage slot the witness does not carry.
    UnknownSlot { address: Address20, key: Word32 },
    /// The execution asked for an ancestor hash the witness does not carry.
    /// Only the 256 blocks below this one can be asked for; the interpreter
    /// answers anything else with zero without consulting a database.
    UnknownBlockHash { number: u64 },
    /// The execution asked for code by hash that no recorded account has.
    /// Unreachable in practice — every [`AccountInfo`] this database returns
    /// carries its code inline, so revm never falls back to the hash — and an
    /// error rather than an empty `Bytecode` so that "unreachable" stays a
    /// claim something would notice breaking.
    UnknownCode { code_hash: Word32 },
    /// An account's recorded code is bytes revm refuses to make a `Bytecode`
    /// of: the only such shape is one beginning `0xef01`, EIP-7702's magic,
    /// that is not a 23-byte delegation. Code like that predates EIP-3541 —
    /// which stopped `0xef` deployments at London — and a handful of such
    /// accounts exist on mainnet. It is an error rather than a panic because a
    /// panicking guest publishes no journal and cannot be proven at all
    /// (`docs/spec/public-values.md` §9), so a crash here would turn a rare
    /// account into an unprovable block.
    MalformedCode { address: Address20 },
}

impl core::fmt::Display for DbError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DbError::UnknownAccount { .. } => f.write_str("the witness carries no such account"),
            DbError::UnknownSlot { .. } => f.write_str("the witness carries no such storage slot"),
            DbError::UnknownBlockHash { .. } => {
                f.write_str("the witness carries no such ancestor hash")
            }
            DbError::UnknownCode { .. } => f.write_str("the witness carries no such code"),
            DbError::MalformedCode { .. } => {
                f.write_str("an account's recorded code is not bytecode revm accepts")
            }
        }
    }
}

impl core::error::Error for DbError {}
impl revm::database_interface::DBErrorMarker for DbError {}

/// The pre-state, exactly as the witness recorded it and no more.
///
/// It replaces S24's `CacheDB<EmptyDB>`, which had two silent defaults: an
/// address it had not been given read as a non-existent account, and a
/// `BLOCKHASH` it had not been given read as `keccak256` of the block number's
/// decimal string (`docs/spec/revm-block.md` §1.2, the one acknowledged *gap*
/// in S24's witness). Both are errors here.
///
/// **Non-existence is recorded, not inferred.** An account that does not exist
/// on chain is in [`BlockWitness::accounts`] with nonce 0, balance 0, no code
/// and no slots, and [`WitnessDb::basic`] answers `None` for exactly that
/// shape — which is what revm needs in order to mark it `LoadedAsNotExisting`
/// and leave it out of the post-state. The encoding is injective on states
/// Ethereum can represent: EIP-161 deletes an account with nonce 0, balance 0
/// and no code at the end of any transaction that touches it, so the state
/// trie holds no such entry to confuse with an absence, and an account that
/// has storage has had code and so has a nonzero nonce.
///
/// The lookups are binary searches over the witness's own sorted vectors
/// rather than maps built up front. The witness is canonical — accounts ascend
/// by address, slots ascend by key, ancestors ascend by number, all checked by
/// [`BlockWitness::decode`] before this type is built — so the order is free,
/// and a `no_std` guest that builds no maps allocates nothing here. A bump
/// allocator that never frees makes that worth having.
pub struct WitnessDb<'a> {
    witness: &'a BlockWitness,
}

impl<'a> WitnessDb<'a> {
    /// A database over a witness [`BlockWitness::decode`] has accepted.
    pub fn new(witness: &'a BlockWitness) -> WitnessDb<'a> {
        WitnessDb { witness }
    }

    fn account(&self, address: Address20) -> Result<&'a AccountWitness, DbError> {
        let at = self
            .witness
            .accounts
            .binary_search_by(|a| a.address.cmp(&address))
            .map_err(|_| DbError::UnknownAccount { address })?;
        Ok(&self.witness.accounts[at])
    }
}

impl revm::Database for WitnessDb<'_> {
    type Error = DbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, DbError> {
        let account = self.account(address.0 .0)?;
        if account.nonce == 0 && account.balance == [0u8; 32] && account.code.is_empty() {
            // Recorded, and recorded as not existing.
            return Ok(None);
        }
        let code = Bytes::copy_from_slice(&account.code);
        let bytecode =
            Bytecode::new_raw_checked(code.clone()).map_err(|_| DbError::MalformedCode {
                address: account.address,
            })?;
        Ok(Some(AccountInfo {
            balance: U256::from_be_bytes(account.balance),
            nonce: account.nonce,
            // `KECCAK_EMPTY` by name rather than by hashing nothing: an
            // externally-owned account is most of a real block's touch set, and
            // each one would otherwise cost a keccak permutation — which on
            // this VM is a `KECCAK_F` delegation row, not a free call.
            code_hash: if code.is_empty() {
                revm::primitives::KECCAK_EMPTY
            } else {
                keccak256(&code)
            },
            // A hint the journal uses to skip an address lookup; a witness has
            // no such hint to give.
            account_id: None,
            code: Some(bytecode),
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, DbError> {
        Err(DbError::UnknownCode {
            code_hash: code_hash.0,
        })
    }

    fn storage(&mut self, address: Address, index: StorageKey) -> Result<U256, DbError> {
        let account = self.account(address.0 .0)?;
        let key = index.to_be_bytes::<32>();
        let at = account
            .slots
            .binary_search_by(|slot| slot.0.cmp(&key))
            .map_err(|_| DbError::UnknownSlot {
                address: address.0 .0,
                key,
            })?;
        Ok(U256::from_be_bytes(account.slots[at].1))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, DbError> {
        let at = self
            .witness
            .env
            .block_hashes
            .binary_search_by(|entry| entry.0.cmp(&number))
            .map_err(|_| DbError::UnknownBlockHash { number })?;
        Ok(B256::new(self.witness.env.block_hashes[at].1))
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

/// Run the block and return the output commitment's bytes.
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
pub fn run(witness: &BlockWitness) -> Result<Vec<u8>, String> {
    run_against(witness, WitnessDb::new(witness))
}

/// The same block against a database the caller supplies.
///
/// [`run`] is this with [`WitnessDb`], and that is the *only* instantiation
/// inside the guest, so the image is exactly what it was. The second caller is
/// `host::recorder::WitnessRecorder`, which answers revm's reads from a cached
/// JSON-RPC endpoint and remembers what it was asked; the recording and the
/// proved run therefore share one block executor rather than two that have to
/// be kept equal. That is what makes the differential in
/// `crates/host/tests/witness.rs` mean something: if the two were separate
/// code paths, "the guest agrees with native revm" would be comparing two
/// implementations of the same idea rather than one implementation over two
/// databases.
///
/// # The generic
///
/// Master anti-goal 2 bans trait generics, and names what it is about: the
/// proving stack's field, polynomial, commitment and transcript types. This is
/// none of those — it is workload code parameterised by *revm's own* database
/// trait, which is how revm itself is built — and anti-goal 3's rule is met in
/// the direction it asks for: the second caller exists, and the generic was
/// introduced for it rather than in case of it.
/// `docs/handoff/S25-block.md` records it.
pub fn run_against<DB: revm::Database>(witness: &BlockWitness, db: DB) -> Result<Vec<u8>, String> {
    let spec = witness
        .env
        .spec()
        .ok_or_else(|| alloc::format!("spec id {} is not a hardfork", witness.env.spec_id))?;

    let mut cfg = CfgEnv::new_with_spec(spec);
    cfg.chain_id = witness.env.chain_id;
    let mut evm = Context::mainnet()
        .with_db(db)
        .with_block(block_env(&witness.env))
        .with_cfg(cfg)
        .build_mainnet();

    let mut results = Vec::with_capacity(witness.txs.len());
    // The invariant this loop keeps: `gas_used <= witness.env.gas_limit`, so
    // the subtraction below never wraps. It holds at 0 and is re-established
    // by the checked accumulation after every transaction.
    let mut gas_used: u64 = 0;
    for (i, tx) in witness.txs.iter().enumerate() {
        let remaining = witness.env.gas_limit - gas_used;
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
            .filter(|total| *total <= witness.env.gas_limit)
            .ok_or_else(|| {
                alloc::format!(
                    "transaction {i} took the block past its gas limit of {}",
                    witness.env.gas_limit
                )
            })?;
        results.push(result);
    }
    let state = evm.finalize();

    Ok(encode_output(&results, &state))
}

/// The witness's header fields as revm's `BlockEnv`.
///
/// The blob base fee's update fraction is the **fork's**, not a constant:
/// EIP-4844 set it at Cancun and EIP-7691 raised it at Prague, and a block
/// priced with the wrong one charges the wrong blob gas. It is picked here
/// rather than in the witness because it is a property of the hardfork the
/// witness already names.
pub(crate) fn block_env(env: &BlockEnvWitness) -> BlockEnv {
    BlockEnv {
        number: U256::from_be_bytes(env.number),
        beneficiary: Address::from(env.beneficiary),
        timestamp: U256::from_be_bytes(env.timestamp),
        gas_limit: env.gas_limit,
        basefee: env.basefee,
        difficulty: U256::from_be_bytes(env.difficulty),
        prevrandao: env.prevrandao.map(B256::new),
        // Recorded, never derived: the update fraction the derivation needs is a
        // fork parameter revm 42 does not know past Prague
        // (`BlockEnvWitness::blob_gasprice`).
        blob_excess_gas_and_price: env.excess_blob_gas.zip(env.blob_gasprice).map(
            |(excess_blob_gas, blob_gasprice)| BlobExcessGasAndPrice {
                excess_blob_gas,
                blob_gasprice,
            },
        ),
        slot_num: env.slot_num,
    }
}

/// One witness transaction as revm's `TxEnv`.
///
/// `tx_type` is derived from the envelope rather than carried, so a witness
/// cannot claim a type its fields do not support.
pub(crate) fn tx_env(tx: &TxWitness) -> TxEnv {
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
        .blob_hashes(tx.blob_hashes.iter().map(|h| B256::new(*h)).collect())
        .max_fee_per_blob_gas(tx.max_fee_per_blob_gas.unwrap_or(0))
        .authorization_list_recovered(
            tx.authorizations
                .iter()
                .map(recovered_authorization)
                .collect(),
        )
        .build_fill();
    env.derive_tx_type()
        .expect("a witness transaction's envelope names a transaction type");
    env
}

/// One witness authorization as revm's, with no recovery performed.
///
/// `RecoveredAuthorization::new_unchecked` is the constructor for exactly this
/// situation and says so: the authority is supplied rather than derived. That
/// is the same arrangement `TxWitness::caller` has, and for the same reason —
/// this VM has no `ecrecover` delegation, so recovery is the witness
/// producer's job. `RecoveredAuthority::Invalid` is the faithful encoding of
/// an authorization whose signature recovers to nothing: EIP-7702 skips such
/// an entry and runs the transaction anyway, so dropping it from the witness
/// would change the nonce bookkeeping revm does over the list.
fn recovered_authorization(auth: &AuthorizationWitness) -> RecoveredAuthorization {
    RecoveredAuthorization::new_unchecked(
        Authorization {
            chain_id: U256::from_be_bytes(auth.chain_id),
            address: Address::from(auth.address),
            nonce: auth.nonce,
        },
        match auth.authority {
            Some(address) => RecoveredAuthority::Valid(Address::from(address)),
            None => RecoveredAuthority::Invalid,
        },
    )
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

/// The output commitment: must-be-exact 7's three sections, in order and
/// always all three. `src/main.rs` commits these bytes to the journal, where
/// the statement carries them; `src/stdio.rs` writes them to fd 1, where
/// nothing does.
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
/// the record count is the witness's transaction count, so a reader who has
/// the witness knows how many records to expect and one who does not reads
/// them sequentially. A record's `output` is the transaction's own return data
/// and is as long as the transaction made it; `output_len` is what makes the
/// stream parseable without it.
fn encode_output(results: &[ExecutionResult], state: &revm::state::EvmState) -> Vec<u8> {
    let mut out = Vec::new();
    let mut logs: Vec<&Log> = Vec::new();
    for result in results {
        push_record(&mut out, result);
        logs.extend(result.logs());
    }
    out.extend_from_slice(keccak256(encode_logs(&logs)).as_slice());
    out.extend_from_slice(keccak256(encode_post_state(state)).as_slice());
    out
}

/// One transaction's record, as the output commitment's first section writes
/// it: `status ‖ gas_used ‖ output_len ‖ output`.
///
/// Factored out because the **stateless** mode digests this stream rather than
/// carrying it (`src/stateless.rs`), and two encodings of one record would be
/// two things to keep equal.
pub(crate) fn push_record(out: &mut Vec<u8>, result: &ExecutionResult) {
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
pub(crate) fn encode_logs(logs: &[&Log]) -> Vec<u8> {
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
