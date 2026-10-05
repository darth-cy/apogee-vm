# Ethereum blocks

`guests/revm-block` runs Ethereum blocks on revm inside the VM. This page specifies its two
binaries: the mini-block binary's input, `BlockWitness`, and its output commitment; the stateless
validator's input, result and rules; how each runs a block on revm; and how a block is recorded.

## 1. The guest crate

One library, `revm_block` (`src/lib.rs` and its modules), and two binaries, each its own program
identity, the same for every block because the block is advice
([public-values.md](public-values.md) §6):

| binary | advice | journal | exit status |
| --- | --- | --- | --- |
| `revm-block` (`src/main.rs`) | a `BlockWitness` (§2) | the output commitment (§3) | 0; 61 not a canonical witness; 62 not executable |
| `revm-block-stateless` (`src/stateless_main.rs`) | `statelessInputBytes` (§4) | the 43-byte result | always 0 |

The **mini-block** binary runs transactions, usually a block's first few, over a pre-state
recorded from a node (§6); it proves an execution, not a block's validity (§3). Full blocks are
proved with the stateless validator: the mini journal grows by a record a transaction and outgrows
the public window ([public-values.md](public-values.md) §9). On the host the library is the
oracle `crates/emulator/tests/revm.rs` holds the mini binary's journal to, over unpatched
upstream crates.

**Dependencies.** revm is the workload being proven: it and what `revm-precompile` brings
(arkworks, `k256`, `p256`, `sha2`, `ripemd`) are reachable from no prover, verifier or other guest.
It is built without default features, so without `blst`, `c-kzg` or libsecp256k1. The pin is
exact, `=43.0.1`, because an identity is a digest of the image ([program.md](program.md) §8), and
the set is the reference stateless guest's (`paradigmxyz/stateless`'s lock): twelve crates, held
in both lockfiles by `crates/host/tests/revm_lock.rs`, its `revm-handler` 43.0.1 carrying the
EIP-8037 system-call state-gas reservoir `tests-zkevm@v21.0.1` expects.

**Delegations.** Both binaries declare `KECCAK_F`, `SHA256_COMP`, `MOD_MUL` and `EC_ADD`: keccak
through `alloy-primitives`' `native-keccak` hook (`revm_block::native_keccak256`), SHA-256,
secp256k1 and BN254 through vendored crates ([delegation.md](delegation.md) §10,
[guests/vendor/README.md](../../guests/vendor/README.md)). `revm-precompile` is patched in its
`Crypto` trait's default bodies, not given a second implementation by `install_crypto`: two types
behind `crypto()`'s `OnceLock<Box<dyn Crypto>>` stop LLVM devirtualizing its calls, keeping code
it otherwise strips, 870,828 bytes of `.text` on the mini binary, past its tables' reach.

**Code size.** No ELF is committed: `host::fixture::build_revm_guest` builds either binary at
`--release`, proved at `host::fixture::revm_params` — `2^20` for every family whose height is a
choice (`revm_block::TRACE_HEIGHT_RELEASE`), each delegation family's default,
`bytecode_size_words = 2^21`. A `2^20` table reaches 1.9375 MiB of `.text`
([program.md](program.md) §5); the stateless binary's is about 1.96 MB, 96.6% of it. The debug
image needs `2^22` and is only ever run.

## 2. `BlockWitness`

The mini binary's advice: `postcard` of `revm_block::BlockWitness`, a format of this repository's,
written by `host::recorder` (§6). Fields in declaration order; a `word` is 32 big-endian bytes; a
`u8`, an `Option` tag (0 or 1) and a fixed array are raw bytes; every other integer and every
length is a varint.

```text
BlockWitness          env BlockEnvWitness; accounts Vec<AccountWitness>, by address;
                      txs Vec<TxWitness>, in execution order
BlockEnvWitness       chain_id u64; spec_id u8 (revm's SpecId); number word; beneficiary [20];
                      timestamp word; gas_limit u64; basefee u64; difficulty word;
                      prevrandao Option<word>; excess_blob_gas Option<u64>;
                      blob_gasprice Option<u128>; slot_num u64;
                      block_hashes Vec<(u64, word)>, by number
AccountWitness        address [20]; nonce u64; balance word; code Vec<u8>;
                      slots Vec<(word, word)>, by key, zero values included
TxWitness             caller [20]; to Option<[20]>, None a creation; value word; data Vec<u8>;
                      gas_limit u64; gas_price u128, the max fee from type 2;
                      gas_priority_fee Option<u128>; nonce u64; chain_id Option<u64>;
                      access_list Vec<([20], Vec<word>)>; blob_hashes Vec<word>;
                      max_fee_per_blob_gas Option<u128>; authorizations Vec<AuthorizationWitness>
AuthorizationWitness  chain_id word; address [20]; nonce u64; authority Option<[20]>, recovered
```

### 2.1 One state, one encoding

`BlockWitness::decode` refuses, with exit 61:

| rule | `WitnessError` |
| --- | --- |
| `spec_id` is a `SpecId` | `UnknownSpec` |
| `excess_blob_gas` and `blob_gasprice` both present or both absent | `BlobPairing` |
| accounts, each account's slots, `block_hashes` strictly ascending | `AccountsNotSorted`, `SlotsNotSorted`, `BlockHashesNotSorted` |
| the bytes are exactly `BlockWitness::encode`'s for the value | `Malformed` |

The last closes `postcard`'s two second encodings: `postcard::from_bytes` ignores trailing bytes,
and its varints accept non-minimal forms (`81 00` reads as 1). A code hash is computed, not
carried, and a transaction's type is derived from its fields (`TxEnv::derive_tx_type`).

### 2.2 Execution

`revm_block::WitnessDb` answers revm from the witness and refuses every miss (`DbError`, exit 62):
the witness is unbound advice, so a default would be a value the prover chose.

- **Absence is recorded**: `WitnessDb::basic` answers `None` for an account recorded with nonce 0,
  balance 0 and no code. A zero slot is recorded like any other.
- **`BLOCKHASH`** reads `env.block_hashes`. revm answers 0 without asking for any block but the
  256 before the current one, and serves those from the database, not EIP-2935's contract: at
  most 256 entries.
- **Code is `Bytecode::new_raw_checked`'s**: bytes beginning `0xef01` that are not a 23-byte
  EIP-7702 delegation, which a few pre-EIP-3541 accounts hold, are `DbError::MalformedCode`, where
  `Bytecode::new_raw` would panic, an exit 101 that names nothing ([ecall-abi.md](ecall-abi.md)
  §7).
- **The block gas limit is a running bound.** revm checks each transaction against the block's
  limit and keeps no total; `revm_block::run`, the block executor, refuses transaction `i` unless
  `gas_limit_i ≤ env.gas_limit − Σ_{j<i} gas_used_j`, the Yellow Paper's intrinsic validity.
- **The blob gas price is recorded** (§6). It derives from the excess through the fork's update
  fraction, 3,338,477 at Cancun, 5,007,716 at Prague, raised by each BPO fork (§4.2), and revm 43
  knows only the first two. revm holds each type-3 transaction's `max_fee_per_blob_gas` to it.

Not in the witness: signatures, `caller` and each `authority` being the producer's recovery,
unchecked; a parent header, and the header rules against it; a state root (§3); a slot number,
which the recorder writes as 0, no JSON-RPC method serving EIP-7843's.

## 3. The output commitment

The mini binary's journal, `revm_block::run`'s return:

```text
per transaction, in order   status u8 (0 halt, 1 revert, 2 success) ‖ gas_used u64 LE
                            ‖ output_len u32 LE ‖ output: the return data, empty on a halt
logs commitment       32    keccak256 of  count u32 LE ‖ per log, in emission order:
                            address 20 ‖ topic_count u8 ‖ topics, 32 each ‖ data_len u32 LE ‖ data
post-state summary    32    keccak256 of  count u32 LE ‖ per account, by address:
                            address 20 ‖ nonce u64 LE ‖ balance 32 BE ‖ code_hash 32
                            ‖ slot_count u32 LE ‖ per slot, by key: key 32 BE ‖ value 32 BE
```

The record count is the witness's. The summary covers the state revm's `finalize` returns: every
account the block loaded, read-only and nonexistent ones included, with every slot it loaded.

**What a proof states**: some canonical `BlockWitness` makes `revm_block::run` return this journal.
Nothing ties the witness to a chain; a reader holding one recomputes the journal natively. And the
journal tells witnesses apart only as far as the execution reads them: a slot read and then
overwritten unconditionally reaches nothing, while every loaded account's final balance and nonce
are in the summary.

## 4. The stateless validator

`revm-block-stateless` maps `tests-zkevm@v21.0.1`'s `statelessInputBytes` to its
`statelessOutputBytes`, byte for byte. The formats and rules are `ethereum/execution-specs`'
`verify_stateless_new_payload` at the release's commit (`host::zkevm::RELEASE_COMMIT`);
`revm_block::stateless::run` is the guest's whole computation, and §5 lists its rules.

### 4.1 Input and output

```text
input    schema_id u16 BE ‖ SSZ(StatelessInput)                          ssz::decode
           new_payload_request   the schema's fork's NewPayloadRequest
           witness               state: trie-node preimages; codes; headers: RLP, oldest
                                 first, the parent last, at most 256
           chain_id              u64
           public_keys           eth-act/ere-guests v0.17.1's layout only: 65 bytes a transaction
output   new_payload_request_root 32 ‖ successful_validation 1 ‖ chain_id u64 LE ‖ schema_id u16 LE
```

The layouts' fixed parts are 16 and 20 bytes, so no input is both; the second is the zkEVM
benchmark's. The root is `hash_tree_root` under EIP-7916's and EIP-7495's progressive forms as of
2026-01-15 (`ssz::request_root`), whatever the layout. Decoding is as strict as the spec's: every
offset against the bytes it bounds, every bounded list against its limit, nothing after the end.

The guest exits 0 on every input. One that does not decode, or names a schema §4.2 does not list,
publishes the **sentinel**, 43 zero bytes (`ssz::SENTINEL`); any other publishes its request's
root, its verdict, its chain id and its schema id. The empty input is the one a run cannot be
given, a run without advice having no advice region.

### 4.2 Forks

The schema id, `fork_index << 8 | 0x01`, names the fork; no activation schedule is compiled in
(`block::fork`).

| schema | fork | request | revm `SpecId` | blob target, max | update fraction |
| --- | --- | --- | --- | --- | --- |
| `0x1201` | Osaka | Electra/Fulu | `OSAKA` | 6, 9 | 5,007,716 |
| `0x1301` | BPO1 | Electra/Fulu | `OSAKA` | 10, 15 | 8,346,193 |
| `0x1401` | BPO2 | Electra/Fulu | `OSAKA` | 14, 21 | 11,684,671 |
| `0x1501` | Amsterdam | Gloas: a block access list, a slot number, EIP-8282's two request types | `AMSTERDAM` | 14, 21 | 11,684,671 |

### 4.3 What a result proves

`true` says the request whose root is published is a valid block on chain `chain_id` under the
fork `schema_id` names. The witness needs no binding: the root fixes the payload, and the witness
is held to it by hashes — the parent header to the payload's `parent_hash`, each ancestor to its
child's, the state trie to the parent's `state_root` and each node to its parent's reference, each
code to its account's code hash. A node a read needs and the witness lacks is an error, never an
absence (`mpt::get`). So a wrong witness cannot make an invalid payload valid; but `false` says
only that this input did not validate, which a prover can arrange for any payload.

### 4.4 How a block runs on revm

The pre-state is `witness::WitnessDb` behind revm's `State`: the state trie under the parent's
root, each storage trie parsed on its first read, codes by hash, and `BLOCKHASH` numbering each
ancestor by its position below the block. `stateless::execute` is the spec's `apply_body`: the
EIP-4788 and EIP-2935 system calls; each transaction; the withdrawals; the requests, from deposit
logs and the checked system calls of EIP-7002, EIP-7251 and, from Amsterdam, EIP-8282. The calls
before the transactions are block access list index 0, each transaction has its own, and what
follows them shares the last. A transaction must fit what is left, Amsterdam metering regular
and state gas apart (EIP-8037):

```text
before Amsterdam   tx.gas_limit ≤ gas_limit − Σ gas_used
Amsterdam          tx.gas_limit ≤ 2^32 − 1,  min(tx.gas_limit, 2^24) ≤ gas_limit − Σ regular,
                   tx.gas_limit ≤ gas_limit − Σ state;  the block uses max(Σ regular, Σ state)
both               2^17·blobs ≤ 2^17·max − Σ blob gas
```

Three rules make the result the spec's where following reth would not:

- **Code loads when revm asks** (`witness::WitnessDb::code_by_hash`), never with its account:
  the witness carries only the code the spec's execution read, and a coinbase may be a contract
  nothing calls.
- **Every write precedes every deletion** in the post-state replay (`stateless::post_state_root`),
  in each trie, as the spec's `mpt_set_storage_slots` orders them. A deletion that leaves a branch
  one child needs that child's node, on no changed key's path; the witness carries those the
  spec's order needs, and writing first needs a subset.
- **One commit per index** (`stateless::commit_index`). revm 43's access-list builder records a
  value that differs from its commit's baseline, and revm re-bases a value at each call, so
  committing call by call records a slot one call toggles and the next restores. An index's calls
  are committed once, each baseline reset to the committed state.

Also the spec's: a checked system contract must have code, deposit events are parsed to the
byte, withdrawals precede requests; the `TxEnv` is built field by field (`build_fill` would put a
dummy authorization in an empty type-4 list); the blob price is a checked `fake_exponential`
(`block::blob_gas_price`); `0xef01` code that is not a delegation runs as legacy. Declared lengths
are added checked and trie parsing is depth-bounded, a panic publishing nothing.

### 4.5 Signatures

Every sender and EIP-7702 authority is recovered in the guest (`tx::recover_key`) under EIP-2's
rules, `0 < r < n`, `0 < s ≤ n/2`, a parity bit, as `Q = r⁻¹(s·R − z·G)` with `k256`'s arithmetic,
which the vendored `k256` routes to `MOD_MUL` and `EC_ADD`. The verification upstream's
`recover_from_prehash` ends with cannot fail once recovery succeeds and costs about as much again,
so it is not done. An authorization that does not recover is skipped, as EIP-7702 says. A key in
ere-guests' layout is checked, never used: one a transaction, `0x04 ‖ x ‖ y`, naming the
recovered sender.

### 4.6 Conformance

All 67,251 pairs of `tests-zkevm@v21.0.1` match natively (`crates/host/tests/conformance.rs`, by
hand); CI holds the library to a committed subset of 34 — a case for each rule the release
reaches, the smallest valid one, every undecodable one — in both layouts, and the binary runs the
subset by hand. The release fills only Amsterdam: `tools/stateless-ref` holds the Electra/Fulu
layout to `eth-act/ere-guests` v0.17.1 and `crates/host/tests/canonical.rs` the encodings and
header rules to two mainnet blocks, but no Osaka-family input has an end-to-end oracle.

## 5. Where each rule is checked

The mini binary's rules, then the validator's step by step. A validator refusal is a
`stateless::Invalid` variant, which `host::zkevm::verdict` names and the guest publishes as
`false`. Paths are `revm_block`'s.

| rule | refusal | code |
| --- | --- | --- |
| mini: a canonical witness | exit 61 | `BlockWitness::decode` |
| mini: every read recorded, code well formed | exit 62 | `WitnessDb` |
| mini: each transaction fits the gas left and executes | exit 62 | `run_against` |
| the input decodes under a listed schema | sentinel | `ssz::decode`, `block::fork` |
| the ancestors decode and chain | `Ancestors` | `stateless::ancestors` |
| no empty transaction | `EmptyTransaction` | `stateless::verify` |
| the base fee fits a `u64` | `Unrepresentable` | `stateless::payload_header` |
| the header the payload implies hashes to `block_hash` | `BlockHash` | `stateless::{verify, payload_header}` |
| each transaction decodes (EIP-2718, types 0–4) | `Transaction(i)` | `tx::decode` |
| keyed layout: a key a transaction | `PublicKeys` | `stateless::verify` |
| the versioned hashes are the request's | `VersionedHashes` | `stateless::verify` |
| EIP-7934's block size | `BlockSize` | `block::block_rlp_len` |
| the header against its parent, twelve rules | `Header(_)` | `block::validate_header` |
| the blob gas price fits a `u128` | `Unrepresentable` | `block::blob_gas_price` |
| the parent's state root is in the witness | `Witness(_)` | `witness::WitnessDb::new` |
| chain id; signature; keyed layout: the key names the sender | `ChainId(i)`, `Signature(i)`, `PublicKeys` | `stateless::execute`, `tx::sender` |
| the transaction fits what is left | `Capacity(i)` | `stateless::execute` |
| revm executes it, every read in the witness | `Execution(i)` | `stateless::execute` |
| the system calls | `SystemCall` | `stateless::{execute, commit_index}` |
| the deposit events | `Deposits` | `block::deposit_requests` |
| gas used, receipts root, bloom, blob gas used, requests hash | `GasUsed`, `ReceiptsRoot`, `Bloom`, `BlobGasUsed`, `RequestsHash` | `stateless::verify`, `block` |
| Amsterdam: the access list's item count and hash | `AccessList` | `stateless::verify`, `alloy_eip7928` |
| the post-state root | `StateRoot`, `Witness(_)` | `stateless::post_state_root`, `mpt` |

## 6. Recording a block

`host::recorder::record(rpc, block_number, range)` makes a `BlockWitness` for a block's first `n`
transactions or all of them (`recorder::TxRange`) by running them once against a node:
`recorder::WitnessRecorder` is a `revm::Database` over the parent block's state that records each
answer, and the transactions run through `revm_block::run_against`, the guest's own executor, so
the record is what the guest will read. The result is put through `BlockWitness::decode`.

- **Reads.** An account is `eth_getProof` with no keys, absent when nonce, balance, code hash and
  storage hash are all empty or both hashes are zero, Geth's answer; code `eth_getCode`, checked
  against the hash; a slot `eth_getStorageAt`; a header `eth_getBlockByNumber`; the blob gas price
  `eth_feeHistory`'s `baseFeePerBlobGas`, a receipt's `blobGasPrice` existing only for type 3.
- **Choices.** The hardfork is mainnet's by number (`recorder::mainnet_spec`): before the Merge is
  refused, after Osaka runs as Osaka. `caller` is the node's `from`; authorities are recovered on
  the host.
- **The client**, `host::rpc::Rpc`, files each response under the SHA-256 of its canonical request
  in the fixture's `rpc-cache/`, so a second recording is byte-identical and offline; a miss
  without `ETH_RPC_URL` is an error. A request goes through `curl`, the endpoint and its key on
  the command line, retried on a transport failure, a 5xx or a 429.
- **On disk** (`host::fixture`): `<stem>.json`, a `Pin` naming the block and the length and
  SHA-256 of `<stem>-witness.bin` and `<stem>-journal.bin`, native revm's journal, beside
  `rpc-cache/`. `crates/host/tests/vectors/mini-block*` is block 26,057,509's first two
  transactions, refreshed by `kat-gen -- block` ([tools.md](../tools.md) §7).

**Nothing here produces a stateless input.** `eth_getProof` returns the nodes on a key's path, and
a deletion that collapses a branch needs its surviving sibling's node, which is on no changed
key's path (`mpt::MptError::BlindedCollapse` is the validator's refusal without it), so the proofs
of a block's keys are not a witness. Stateless inputs come from an external producer, a
`tests-zkevm` release or the zkEVM benchmark's datasets; `host::zkevm` reads every JSON object
carrying both `statelessInputBytes` and `statelessOutputBytes`, and `bench prove --stateless`
proves one as it is ([tools.md](../tools.md) §1).
