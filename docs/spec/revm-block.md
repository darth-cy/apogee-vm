# The revm block workload

This page is normative for two wire formats and nothing else: `BlockWitness`, which is
the revm guest's **advice**, and the **output commitment**, which is its **journal**.
S10's `io_digest` binds the second and this page defines neither of its halves —
`docs/spec/ecall-abi.md` §6 froze that computation and neither S24 nor S-IO changed
anything about it.

*Amended at S-IO: both were fd streams until then — the witness on fd 0 and the commitment
on fd 1 — and neither was bound to the execution, which is why S24 had to prove a second
binary with the witness in its image. The witness is advice now, so one program identity
serves every block, and the commitment is the journal, so the statement carries its bytes.
`docs/spec/public-values.md` is that architecture. The fd binary that was kept beside them
is **deleted** with the syscall it used: there is no executor left that wants one, and both
of this guest's binaries read the advice region and write the journal.*

**The output commitment (§2) is frozen at S24. `BlockWitness` (§1) is not**, by the
owner's decision at the close of that stage, and **S25 moved it** — `block_hashes`,
EIP-4844's two transaction fields and EIP-7702's authorization list are all new, and the
`BLOCKHASH` gap that kept the type open is closed (§1.2). It stays unfrozen: the type is
still the one a recorder produces for a chain that keeps forking. What a change must keep
is §1.1: one logical state, exactly one encoding.

**§2 is frozen, and neither S25 nor S-STREAM touched it.** S-STREAM grew the window
instead, from 1,020 bytes to 16,380 (`docs/spec/public-values.md` §2), which is why the
**mini** mode reaches a few hundred transactions now where it reached 73 — about 360 at
this workload's 45 bytes a record. It did not change the conclusion: a record carries
return data verbatim, so §2's length is a function of the execution and no fixed window
bounds it.

**This page is the mini mode's, and only the mini mode's, since S-STATELESS.** The guest's
other binary, `revm-block-stateless`, is the full-block target (owner's decision,
S-STREAM), and it is now the **canonical stateless validator**: the spec's
`statelessInputBytes` in, its 43-byte `statelessOutputBytes` out, whatever the block.
`docs/spec/stateless.md` is normative for it. It reads no `BlockWitness` and writes no §2,
and S25's stateless witness and S-STREAM's 148-byte journal, which §1.5 and §5 used to
define, are deleted.

The guest that reads and writes them is `guests/revm-block`; what it *is* — its two
binaries, why one exists, and what it costs — is `docs/handoff/S24-revm.md`.

## 0. Byte order

An EVM word is **big-endian**, 32 bytes, as Ethereum writes one. The workspace's
"canonical 32-byte little-endian" rule is about `Fr` (`prompts/00-master.md`,
"One encoding"), and neither format here carries an `Fr`.

Everything that is not an EVM word is little-endian: `postcard` writes the witness's
integers that way, and the output commitment's lengths and counters are written that way
by hand.

## 1. `BlockWitness`

**Not frozen** — see the note above; this is S24's shape, and a later stage may append to
it. `postcard` over the type in `guests/revm-block/src/lib.rs`, which is the workspace's
one wire encoding. Fields in declaration order, which is the canonical order:

```
BlockWitness
    env         BlockEnvWitness
    accounts    Vec<AccountWitness>   ascending by address
    txs         Vec<TxWitness>        execution order

BlockEnvWitness
    chain_id          u64          EIP-155
    spec_id           u8           revm `SpecId`'s repr(u8) discriminant
    number            [u8; 32]     block height
    beneficiary       [u8; 20]     coinbase
    timestamp         [u8; 32]     seconds since the epoch
    gas_limit         u64
    basefee           u64          EIP-1559
    difficulty        [u8; 32]     pre-merge
    prevrandao        Option<[u8; 32]>   post-merge; replaces difficulty
    excess_blob_gas   Option<u64>  EIP-4844; required from Cancun on
    blob_gasprice     Option<u128> S26; RECORDED, never derived -- §1.6.
                                   Some exactly when excess_blob_gas is
    slot_num          u64          EIP-7843
    block_hashes      Vec<(u64, [u8; 32])>   S25; ascending by number, at most 256

AccountWitness
    address     [u8; 20]
    nonce       u64
    balance     [u8; 32]
    code        Vec<u8>                      empty for an EOA
    slots       Vec<([u8; 32], [u8; 32])>    ascending by key, zeros included

TxWitness
    caller               [u8; 20]      already recovered; see §1.2
    to                   Option<[u8; 20]>   None is a contract creation
    value                [u8; 32]
    data                 Vec<u8>
    gas_limit            u64
    gas_price            u128          the max fee per gas for an EIP-1559 tx
    gas_priority_fee     Option<u128>
    nonce                u64
    chain_id             Option<u64>
    access_list          Vec<([u8; 20], Vec<[u8; 32]>)>   EIP-2930
    blob_hashes          Vec<[u8; 32]>       S25; EIP-4844, type 3
    max_fee_per_blob_gas Option<u128>        S25; EIP-4844, type 3
    authorizations       Vec<AuthorizationWitness>   S25; EIP-7702, type 4

AuthorizationWitness                          S25
    chain_id    [u8; 32]     0 means every chain
    address     [u8; 20]     the delegate
    nonce       u64
    authority   Option<[u8; 20]>   ALREADY RECOVERED; None is a signature that
                                   recovers to nothing, which EIP-7702 skips
```

### 1.0 The witness is read strictly, and that is new at S25

**An address the execution touches is in `accounts`, or the run fails.** S24 read an
absent address as an empty account and an absent slot as zero. Since S-IO the witness is
advice, which nothing binds (`docs/spec/public-values.md` §6), so a silent default is a
value *the prover chose* — and a witness with an account deleted from it ran happily and
committed a journal for a state nobody supplied.

`revm_block::WitnessDb` is the strict database that replaces S24's `CacheDB<EmptyDB>`. A
miss on an account, a slot or an ancestor hash is a `DbError` that reaches the caller as a
refusal to execute, never a default. **Non-existence is recorded rather than inferred**: an
account that does not exist is in the list with nonce 0, balance 0, no code and no slots,
and `WitnessDb::basic` answers revm `None` for exactly that shape, which is what makes
revm mark it `LoadedAsNotExisting` and leave it out of the post-state. The encoding is
injective on states Ethereum can represent — EIP-161 deletes an account with nonce 0,
balance 0 and no code at the end of any transaction that touches it, so the state trie
holds no such entry to confuse with an absence, and an account with storage has had code
and so has a nonzero nonce.

A zero-valued **slot** is therefore a recorded fact and not an absence, which is what makes
deleting one detectable. `crates/host/tests/witness.rs`'s two completeness controls sweep
every recorded account and every recorded slot of the pinned mini-block and require each
deletion to be refused.

### 1.1 Canonicity

**One logical state has exactly one encoding**, and `BlockWitness::decode` is what makes
that true rather than hoped for. It refuses, by name:

| Rule | Error |
| --- | --- |
| `spec_id` names a hardfork | `UnknownSpec { spec_id }` |
| accounts ascend by address, without repeats | `AccountsNotSorted { at }` |
| an account's slots ascend by key, without repeats | `SlotsNotSorted { account, at }` |
| ancestor hashes ascend by number, without repeats | `BlockHashesNotSorted { at }` |
| **the bytes are exactly what `encode` writes for this witness** | `Malformed` |

The first three are checks `postcard` knows nothing about: it will happily decode any
order at all, so without them "canonical" would be a comment. The fourth is the one that
is easy to think is free and is not — `postcard` has **two** padding channels, and each
is a second encoding of one state, which is a second `io_digest` for one execution:

- **Trailing bytes.** `postcard::from_bytes` decodes a prefix and ignores what follows,
  so a witness with a byte appended, or with a second witness appended, decodes to the
  value of the first alone.
- **Non-minimal varints.** `postcard`'s varint decoder accumulates continuation bytes and
  rejects only an overflowing *last* byte; it never requires the shortest form, so
  `81 00` reads as 1 exactly as `01` does. Every length, `Option` tag, nonce and gas field
  above is a varint — on the committed 716-byte witness, 32 byte positions take a
  two-byte non-minimal form and `chain_id` takes nine extra widths.

`decode` therefore **re-encodes the witness and compares**, which is the only cheap way to
pin `postcard`'s byte-level form and which subsumes both. It costs the guest about 16,000
cycles, 7 % of the run; `docs/handoff/S24-revm.md` §4 is the account.

An account's **code hash is not carried**: it is `keccak256(code)`, which the guest
recomputes, so a witness cannot claim a hash its code does not have.

### 1.6 The blob gas price is recorded, not derived (S26)

EIP-4844's blob gas price is
`fake_exponential(1, excess_blob_gas, BLOB_BASE_FEE_UPDATE_FRACTION)`, and the update
fraction is a **fork parameter that keeps moving**: 3,338,477 at Cancun, 5,007,716 at
Prague (EIP-7691), and raised again on Fusaka's BPO schedule (EIP-7892). **revm 42 carries
the Cancun and Prague constants and nothing after them**, so a guest that derived the
price computed Prague's answer for a post-Fusaka block.

The number that found it: on block 26,045,657, `excessBlobGas` is 180,365,063 and the
chain's `blobGasPrice` is **5,055,772**. Prague's fraction gives
**4,387,037,219,060,994** — a factor of 8.7e8. revm checks
`max_fee_per_blob_gas >= blob_gasprice` per transaction, so **every block carrying a
type-3 transaction refused to execute**, naming the transaction:

```
transaction 32 is not executable: blob gas price (1864339984718618) is
greater than max fee per blob gas (34515560)
```

S25 did not see it because the pinned mini-block is its first **two** transactions and
neither is type-3: the wrong price was computed, carried in the `BlockEnv`, and read by
nothing. S26's profiler is what hit it, on the first whole block it tried.

So the price is recorded. `blobGasPrice` is on **every receipt of every post-Cancun
block** — it is the block's price, not the transaction's — so one `eth_getBlockReceipts`
answers it and the chain itself is the source. The guest constructs
`BlobExcessGasAndPrice { excess_blob_gas, blob_gasprice }` from the two fields and runs no
`fake_exponential` at all, which is worth **2.0% of a mini-block's cycles** on its own
(`docs/spec/profiling.md`).

It is **advice like every other field here** and it is bound the same way: by the journal
the execution publishes. (The stateless binary reads no `BlockWitness`: it derives the
price from the fork its schema id names, whose update fraction it carries —
`docs/spec/stateless.md` §1.) `BlockWitness::canonical` refuses a witness whose
`excess_blob_gas` and `blob_gasprice` are not both present or both absent
(`WitnessError::BlobPairing`), because a witness carrying one without the other is one the
guest would have to derive the other for — which is the derivation this removes. A
post-Cancun block with **no receipts** is refused by the recorder rather than given a
derived price: it has no transactions, so nothing would read the price, and a number
nothing reads is still a number a later reader would trust.

**This is the general rule the witness keeps learning**, and it is S25's twice over — an
absent account is recorded rather than inferred, an ancestor hash is recorded rather than
invented, and now a fork parameter is recorded rather than hardcoded. What all three have
in common is that the guest was deriving something the chain already knows, from a table
that goes stale.

### 1.2 What is deliberately absent

- **Block hashes were the one *gap* rather than a decision, and S25 closed it.** revm
  answers the `BLOCKHASH` opcode from its `Database`; S24's was a `CacheDB<EmptyDB>` whose
  block-hash cache was empty, so every lookup fell through to `EmptyDB`, which returns
  `keccak256` of the block number's decimal string — a made-up word the guest and the host
  happened to agree on. `BlockEnvWitness::block_hashes` carries the ancestors now and
  `WitnessDb::block_hash` refuses any other, so a contract reading `BLOCKHASH(n)` either
  gets the recorded hash or the block does not execute.

  **At most 256 entries are ever needed**, and the recorder records exactly what the
  execution asked for: `revm-interpreter`'s `blockhash` instruction pushes zero without
  consulting the database when the height is the current one or more than
  `BLOCK_HASH_HISTORY = 256` behind it. EIP-2935's history contract does not change this —
  revm 42 still serves the opcode from the host and not from state, so the Prague system
  call writes that contract's storage and `BLOCKHASH` reads the witness.
  `crates/emulator/tests/revm.rs::blockhash_reads_the_recorded_ancestor_and_refuses_the_rest`
  is the pin, in both directions.
- **A parent header, and the header rules that need one.** EIP-1559's bound on
  `gas_limit` against the parent's, and the `≥ 5000` floor, are checks against a block
  this witness does not carry. What *is* enforced is §1.4.
- **Signatures.** `caller` is the recovered sender. There is no `ecrecover` delegation in
  this repository (`prompts/00-master.md`, "Stage register"), and in this mode recovery
  is the witness producer's job, not the block executor's — revm's own `TxEnv` takes a
  `caller` for the same reason. The stateless binary recovers every sender itself
  (`docs/spec/stateless.md` §3).
- **A post-state root.** S24 runs over a synthetic pre-state; what the execution produces
  is summarized in §2, not proved against a root.
- **Transaction types 3 and 4 were absent at S24 and S25 appended them**, because a real
  mainnet block has both: the block this stage pinned carries 200 type-2 transactions, 38
  type-0, **two type-3 and six type-4**. `blob_hashes` and `max_fee_per_blob_gas` are
  EIP-4844's; `authorizations` is EIP-7702's, and it takes the same "already recovered"
  treatment `caller` gets, for the same reason — this VM has no `ecrecover` delegation, so
  the recorder recovers each authority and the witness carries the answer. An
  authorization whose signature recovers to nothing is `authority: None` rather than
  dropped, because EIP-7702 skips such an entry and still runs the transaction, so
  dropping it would change the nonce bookkeeping revm does over the list.

  `TxEnv::derive_tx_type` still picks the type from the fields, so a witness cannot claim
  one its fields do not support; the recorder additionally checks the type it derives
  against the one the node reported, so a type-3 transaction whose blob hashes did not
  arrive is a refusal and not a type-2 execution under different rules.

### 1.3 The committed fixture

`crates/emulator/tests/vectors/revm_block_witness.bin`, written by
`cargo run -p kat-gen -- revm`, which is where the synthetic pre-state is constructed and
where every balance, gas limit and address is a named constant. `revm_block::
COMMITTED_WITNESS_BYTES` pins its length and `revm_block::WITNESS_CAPACITY` — twice it —
is the buffer the guest reads it into, in one `read`, and the one tunable in the guest.

The fixture's addresses all lead with `0xee`. That is load-bearing: every precompile
lives at an address whose first nineteen bytes are zero, so a "put the label in the last
byte" scheme picks one of them, and the first draft of this fixture sent its transfer to
`0x…02` and got `OutOfGas(Precompile)` from SHA-256 instead of a transfer.

### 1.4 The block's gas limit is a running bound

`env.gas_limit` is not a per-transaction ceiling, and `revm_block::run` is what makes it
a block-wide one. revm validates `tx.gas_limit <= block.gas_limit` for each transaction
and can do no more: `transact_one` is *one* transaction and revm carries no state across
a block, so it has no cumulative gas to compare against. In a real client that check
belongs to the block executor, and here `run` **is** the block executor.

So `run` keeps a running `gas_used`, the sum of each transaction's receipt `gasUsed`
(revm's `tx_gas_used`, which is the same quantity the per-transaction record in §2
carries), and refuses transaction `i` unless

```
    tx.gas_limit  <=  env.gas_limit − gas_used(0..i)
```

which is the Yellow Paper's intrinsic-validity condition and is what makes the block's
own `gasUsed <= gasLimit` true at the end. A witness that breaks it is refused with an
`Err` naming the transaction, exactly as one revm refuses outright is; the guest exits
62. Without it a witness may carry any number of transactions that individually fit the
header and together do not — a block no Ethereum node would accept, for which the guest
would nonetheless commit an output.

The block total is **not** added to §2: every transaction's `gas_used` is already a field
there, so the sum is derivable from bytes `io_digest` already binds.

### 1.5 `StatelessWitness` — deleted at S-STATELESS

S25 appended an `Option<StatelessWitness>` here — the parent's state root, its hash, the
beacon root, the withdrawals and a node set — for the stateless binary to read. That binary
reads the spec's `statelessInputBytes` now (`docs/spec/stateless.md`), whose witness is
trie-node preimages, codes and ancestor headers, so the field is deleted with everything
that wrote or read it (owner's decision). Its `None` tag was the last byte of every mini
and synthetic witness; each committed one is a byte shorter, and neither journal moved.

## 2. The output commitment

the journal, in full, and always all three sections — there is no optional one:

```
   per-tx records, in execution order, one per transaction:
       status       u8       0 halt, 1 revert, 2 success
       gas_used     u64 LE
       output_len   u32 LE
       output       output_len bytes
   logs commitment        32 bytes   keccak256(§2.1)
   post-state summary     32 bytes   keccak256(§2.2)
```

The **section list** is fixed; a record's `output` is the transaction's own return data
and is as long as the transaction made it. There is no record count: the count is the
witness's transaction count, and a reader who has the witness has the count.

**The journal is 16,380 bytes** (`docs/spec/public-values.md` §3), and this commitment
carries per-transaction fields, so how many transactions fit is arithmetic: a record is 13
bytes plus its return data, under 64 bytes of digests, so `(16380 − 64) / 13` = **1,255**
transactions at zero return data and about **360** at the 45 bytes a transaction this
workload measures. The synthetic block's commitment is 122 bytes.

**This paragraph used to offer two ways out; both have now been taken, and only one of
them closes the problem.** It read *"the journal is 1,020 bytes … so a real block's will
outgrow it; the stage that records a real block either commits a digest of this structure
instead of the structure, or grows the window"*, and at 1,020 the limit was **73**
transactions — against the 67, 132, 376 and 450 of the four mainnet blocks S26 profiled
(`docs/handoff/S26-cycle.md`) and the 240 of the pinned one. S-STREAM **grew the window**,
to the geometric ceiling of the hole below `RAM_ORIGIN` (`docs/spec/public-values.md` §2),
and that is what makes the mini mode usable on most real blocks. It is **headroom and not
a bound**: `output` is return data taken verbatim behind a `u32` length, so one
maximum-size top-level `CREATE` is 24,589 bytes in a single record and overflows the grown
window on its own.

**So a fixed-size journal is still the answer, and it is the other binary.** §9 of the
public-values page says why — public values are what a verifier reads, and a
per-transaction record is not. `revm-block-stateless` publishes 43 bytes whatever the
block, the spec's validation result (`docs/spec/stateless.md`), and it is the chosen target
for proving a whole block (owner's decision, S-STREAM). **This section does not move for
it.**

### 2.1 The logs commitment

`keccak256` over every log of every transaction, in emission order across the block:

```
   count       u32 LE
   per log:
       address      20 bytes
       topic_count  u8
       topics       32 bytes each
       data_len     u32 LE
       data         data_len bytes
```

### 2.2 The post-state summary

`keccak256` over every account the execution touched, **sorted by address**, each with its
slots **sorted by key**:

```
   count       u32 LE
   per account:
       address      20 bytes
       nonce        u64 LE
       balance      32 bytes BE
       code_hash    32 bytes
       slot_count   u32 LE
       per slot:    key 32 BE ‖ value 32 BE
```

Sorting is what makes this deterministic, and it is not decoration: revm's state is a
hash map, and its iteration order is neither stable across runs nor the same on a 32-bit
guest as on a 64-bit host. "Touched" is revm's own notion — the accounts in the
`EvmState` its `finalize` returns — which includes accounts only read.

## 3. keccak256

Every keccak in the image is `revm::primitives::keccak256`, which is
`alloy-primitives`' one-shot hash, and on the guest target that crate's `native-keccak`
feature turns it into an `extern "C"` call the guest implements as `guest_sdk::keccak256`
— the S21 delegation, with its bit-identical software fallback behind it
(`docs/spec/delegation.md` §2). So revm's `KECCAK256` opcode, a contract's code hash and
this page's two commitments all reach the same shim — a dependency that has never heard of
this VM ends up using its delegation, and the bytes are the same whichever path answers.

revm uses only the one-shot form; `alloy-primitives`' streaming `Keccak256` — which
`native-keccak` does **not** cover — is not reachable from this workload.

## 4. Where each rule is checked

| Rule | Test |
| --- | --- |
| the fixture is canonical, and re-encodes to itself | `crates/emulator/tests/revm.rs::the_committed_witness_is_canonical` |
| every non-minimal varint in it is refused, swept byte by byte | `…::a_witness_out_of_canonical_order_is_refused` |
| every canonicity rule refuses, by name | `…::a_witness_out_of_canonical_order_is_refused` |
| §1.2's placeholder block hash is what `BLOCKHASH` still answers | `…::blockhash_reads_a_placeholder_today` |
| §1.4, both directions: a block that fits executes, one that does not is refused | `…::a_block_past_its_gas_limit_is_refused` |
| §2's shape, field by field | `…::the_output_commitment_has_the_frozen_shape` |
| native revm produces the committed output | `…::native_revm_produces_the_committed_output` |
| the guest produces it too | `…::a4_the_guest_agrees_with_native_revm` |
| every delegated permutation is the reference | `…::a5_every_delegated_permutation_is_the_reference` |
| and the harvested frames are the committed ones | `…::a5_the_harvested_frames_are_the_committed_ones` |
| the fixture is what the builder still writes | `cargo run -p kat-gen`, regenerated and diffed in CI |
| **§1.0** an absent account or slot is refused, swept over every one | `crates/host/tests/witness.rs::a3_a_deleted_{slot,account}_is_refused` |
| **§1.2** `BLOCKHASH` answers a recorded ancestor and refuses any other | `crates/emulator/tests/revm.rs::blockhash_reads_the_recorded_ancestor_and_refuses_the_rest` |
| the stateless binary, every rule | `docs/spec/stateless.md` §4 |
| the recorder is deterministic, and the pinned block proves and verifies | `crates/host/tests/witness.rs::a1_…`, `crates/host/tests/prove.rs::a4_…` |

## 5. The stateless journal — replaced at S-STATELESS

S-STREAM's 148-byte journal — the parent and post-state roots, the block number, gas, a
transaction count and two digests of §2's encodings — is gone with the witness section that
fed it. `revm-block-stateless` publishes the spec's 43-byte `statelessOutputBytes`, and
`docs/spec/stateless.md` is normative for it, including the order a block runs in.
