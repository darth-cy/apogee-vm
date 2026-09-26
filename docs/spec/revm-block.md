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
`docs/spec/public-values.md` is that architecture; `guests/revm-block/src/stdio.rs` is the
fd 0 / fd 1 binary kept for the executors that have neither region.*

**The output commitment (§2) is frozen at S24. `BlockWitness` (§1) is not**, by the
owner's decision at the close of that stage, and **S25 moved it** — `block_hashes`,
EIP-4844's two transaction fields and EIP-7702's authorization list are all new, and the
`BLOCKHASH` gap that kept the type open is closed (§1.2). It stays unfrozen: the stateless
section (§1.5) is defined by the stage that needs it and the type is still the one a
recorder produces for a chain that keeps forking. What a change must keep is §1.1: one
logical state, exactly one encoding.

**§2 is frozen and S25 did not touch it.** The stateless mode publishes a *different*
journal (§5), on a different binary with a different program identity, rather than
amending this one — which is what must-be-exact 2's "two identities for two modes" makes
possible and what keeps a real block's per-transaction records from having to fit a
1,020-byte window they cannot.

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
    stateless   Option<StatelessWitness>   absent in the synthetic and mini modes

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
  this repository (`prompts/00-master.md`, "Stage register"), and recovery is the
  witness producer's job, not the block executor's — revm's own `TxEnv` takes a `caller`
  for the same reason.
- **A post-state root.** S24 runs over a synthetic pre-state; what the execution produces
  is summarized in §2, not proved against a root.
- **The stateless section's meaning.** `stateless` is `Option<StatelessWitness>`, last,
  and its absence changes the encoding of nothing before it. It is `None` in the synthetic
  mode and in the **mini** mode, which is what "claims no state-root recomputation" means
  concretely: §1.5 is the shape, and a witness without it cannot be read by the stateless
  binary at all.
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

### 1.5 `StatelessWitness`

The section the **stateless** mode requires and the other two modes leave `None`.
`guests/revm-block/src/stateless.rs` is the code; this is the normative shape.

```
StatelessWitness
    parent_state_root         [u8; 32]   what the pre-state is authenticated against
    parent_hash               [u8; 32]   EIP-2935's system-call input
    parent_beacon_block_root  Option<[u8; 32]>   EIP-4788's; None before Cancun
    withdrawals               Vec<WithdrawalWitness>   EIP-4895, ascending by index
    nodes                     Vec<Vec<u8>>   ascending by keccak256, no repeats

WithdrawalWitness
    index             u64      the header orders by this
    validator_index   u64
    address           [u8; 20]
    amount_gwei       u64      GWEI, not wei; the execution layer multiplies by 10^9
```

#### The completeness requirement

**`nodes` carries every trie node needed to apply the block's state updates
deterministically — siblings and boundary nodes included, not merely the nodes on each
touched key's own path** (owner's decision, S25). **The guest authenticates every node it
uses against the trie hash that names it, before using it**, and refuses by name when one
is missing. It never reconstructs, infers or guesses a node it was not given.

The rule is not bureaucratic, and the case that forces it was measured rather than
imagined. Deleting a key whose branch is left with exactly one child requires merging that
child upward, which needs the child's **type and path** and not just its hash — and the
child is a *sibling* of the deleted key, so it lies on no touched key's path and appears in
no `eth_getProof` response. Over 300 randomised build-update-recompute trials, **29 %**
needed at least one such node; the missing ones were 104 leaves, 1 extension and 3
branches, so all three merge arms are live. Writing zero to a storage slot **is** a
deletion, and the gas refund makes it common, so this is the ordinary case and not a corner
of it.

A witness that omits one is **incomplete, and the guest says so**:
`mpt::MptError::BlindedCollapse` names the hash and stops. Producing a complete set is the
witness producer's job and needs a source that can supply siblings — an execution-layer
client serving `debug_executionWitness`, say. `host::recorder::collect_nodes` returns what
`eth_getProof` can give and is explicitly **not** a complete-witness builder;
`docs/handoff/S25-block.md` §4 is the account.

Authentication needs only each key's own path, so it *is* satisfiable from `eth_getProof`
— which is why `crates/host/tests/stateless.rs` authenticates the pinned mini-block's
seventeen real accounts and thirty-seven real slots against block 26,057,508's **real**
state root, and the whole-transition tests run on a block built rather than recorded.

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

**The journal is 1,020 bytes** (`docs/spec/public-values.md` §3), and this commitment
carries per-transaction fields, so a **real** block's will outgrow it. The synthetic
block's is 122 bytes and fits; the stage that records a real block either commits a digest
of this structure instead of the structure, or grows the window. That is a guest-side
choice, and §9 of the public-values page is why it should be the first one: public values
are what a verifier reads, and a per-transaction record is not.

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
this page's two commitments all reach the same shim, and a guest run under
`qemu-riscv32`, where the ecall answers `-ENOSYS`, computes the same bytes.

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
| the same bytes under `qemu-riscv32` | `…::a3_the_two_executors_commit_the_same_bytes` |
| every delegated permutation is the reference | `…::a5_every_delegated_permutation_is_the_reference` |
| and the harvested frames are the committed ones | `…::a5_the_harvested_frames_are_the_committed_ones` |
| the fixture is what the builder still writes | `cargo run -p kat-gen`, regenerated and diffed in CI |
| **§1.0** an absent account or slot is refused, swept over every one | `crates/host/tests/witness.rs::a3_a_deleted_{slot,account}_is_refused` |
| **§1.2** `BLOCKHASH` answers a recorded ancestor and refuses any other | `crates/emulator/tests/revm.rs::blockhash_reads_the_recorded_ancestor_and_refuses_the_rest` |
| **§1.5** every recorded value authenticates against the **real** mainnet state root | `crates/host/tests/stateless.rs::a7_every_recorded_value_authenticates_against_the_real_state_root` |
| **§1.5** a corrupted node is refused, and a dropped one as *missing* rather than *absent* | `…::a7_a_corrupted_node_is_refused`, `…::a7_a_deleted_node_is_a_missing_node_and_not_an_absence` |
| the trie itself, against Ethereum's three published root vectors | `crates/host/tests/mpt.rs` |
| **§5** the transition recomputes its pinned root, on the host and on the guest | `…::a7_the_transition_recomputes_the_pinned_root`, `…::a7_the_guest_recomputes_the_pinned_root` |
| **§5** a corrupted node and a corrupted balance are both refused | `…::a7_a_corrupted_stateless_node_is_refused`, `…::a7_a_corrupted_balance_is_refused` |
| **§5.2** the two system-contract addresses are their EIPs' | `…::the_system_contracts_are_the_addresses_their_eips_name` |
| the recorder is deterministic, and the pinned block proves and verifies | `crates/host/tests/witness.rs::a1_…`, `crates/host/tests/prove.rs::a4_…` |

## 5. The stateless journal

**Not §2, and that is the point.** §2 is frozen and carries a record per transaction — 45
bytes each on this workload, so a 246-transaction block's commitment is about 11 KB against
a public window's 1,020 (`docs/spec/public-values.md` §3). The stateless mode publishes a
journal of its own instead, on its own binary with its own program identity, which is what
must-be-exact 2's *"two identities for two modes"* makes possible. §2 does not move, no
fixture is regenerated, and `docs/spec/public-values.md` §9's recommendation is followed:
*"public values are what a verifier reads, and a per-transaction record is not."*

**148 bytes, whatever the block:**

```
   parent_state_root     32 bytes   what the pre-state was authenticated against
   post_state_root       32 bytes   what this execution recomputed
   block_number           8 bytes LE
   gas_used               8 bytes LE   transactions only; system calls are gas-free
   tx_count               4 bytes LE
   receipts_commitment   32 bytes   keccak256 of §2's per-transaction record stream
   logs_commitment       32 bytes   keccak256 of §2.1
```

The two commitments are §2's own encodings, digested rather than carried, so a reader who
wants the records recomputes them from the witness and checks the digest. There is no
post-state **summary** (§2.2): the post-state *root* supersedes it, being a commitment to
the whole state rather than to the part this execution touched.

### 5.1 What the journal claims, and what binds it

**"From the state whose root is `parent_state_root`, this block produced the state whose
root is `post_state_root`."** Nothing binds advice, so the witness is a byte string the
prover chose — and that is exactly why the claim is stated as a transition between two
roots rather than as a fact about a block. A verifier who knows the real parent state root
for this height, from a header they trust, learns that `post_state_root` is this block's
post-state. The parent root arrives from outside the proof in the same way program identity
does.

**The header's state root is the guest's public input**, not a witness field. A root the
witness carried would be a value compared against itself — the guest would assert that the
prover agreed with the prover. The public input window is the statement's own bytes
(`docs/spec/public-values.md` §5.1), so a verifier puts the header's `stateRoot` there and
the proof says the block reaches it.

### 5.2 The order of the transition

Consensus, not a choice:

1. **EIP-4788**, from Cancun: the parent beacon block root into `0x000F…ac02`.
2. **EIP-2935**, from Prague: the parent hash into `0x0000…2935`.
3. Every transaction, in order, under §1.4's running gas bound.
4. **EIP-7002**, from Prague: the withdrawal-request predeploy `0x0000…7002`.
5. **EIP-7251**, from Prague: the consolidation-request predeploy `0x0000…7251`.
6. **EIP-4895** withdrawals, credited in header order.

Steps 4 and 5 are **post**-block system calls, and revm makes neither for you —
`revm-handler`'s `SystemCallEvm` says in as many words that the client should make the
calls an EIP requires before or after block execution. Each dequeues its request queue and
rewrites the queue head and tail, the excess counter and the per-block count, so a
Prague-or-later block reaches a root the header does not carry without them. Both are
called with **empty** calldata: an empty input is the system call and a non-empty one is a
user's request submission, and they are different paths in the same predeploy.

They sit before the withdrawals because that is go-ethereum's order in `Process`. Nothing
rests on it — the two predeploys and the withdrawal recipients are disjoint accounts, so
either order gives the same root.

All four system contracts must be in the witness **with their real deployed bytecode**.
§1.0's strict database refuses a call to an account the witness does not carry, which is
what makes a missing one a loud refusal rather than a call that hits an empty account,
succeeds, changes nothing and yields a wrong root.

System calls are gas-free and are **not** added to the block's `gasUsed`. revm models
withdrawals not at all — a search across all twelve revm 42 crates finds nothing — so the
block executor credits them itself, through the **journal** rather than the database:
`finalize` returns the journal's own state map, so a credit made straight to the database
would change every later read and be invisible in the post-state.

At the end, EIP-161 applies: an account that is **touched and empty** is removed from the
trie.

**Emptiness is the whole test, and revm's selfdestruct flag is not part of it** (S25).
One journal serves the whole block and finalizes once, and under that arrangement revm's
`SelfDestructed` bit is block-global: `commit_tx` clears the journal, the logs, the
transient storage and `selfdestructed_addresses`, and leaves an account's status alone.
So once any transaction destroys an address, every later transaction's finalized view of
it still reads as destroyed — and removing on that flag deleted an address a later
transaction had refunded or recreated, which Ethereum keeps, a non-zero balance not being
empty. Emptiness reaches the right answer without it: destroyed and not refunded
finalizes empty and goes, refunded or recreated is not empty and stays, and from Cancun
EIP-6780 leaves a pre-existing contract's code in place so sweeping its balance never
made it empty. Before Cancun a selfdestruct did wipe storage, so an address destroyed and
then refunded without being recreated starts from an empty storage trie as a created one
does.
