# The revm block workload

This page is normative for two wire formats and nothing else: `BlockWitness`, which is
the revm guest's fd 0, and the **output commitment**, which is its fd 1. S10's
`io_digest` binds both and this page defines neither of its halves —
`docs/spec/ecall-abi.md` §6 froze that computation and S24 changed nothing about it.

**The output commitment (§2) is frozen at S24. `BlockWitness` (§1) is not**, by the
owner's decision at the close of the stage. `prompts/S24-revm.md` asked for both and the
withdrawal has a concrete reason: a field the type is already known to need is missing,
because this stage cannot fill it. revm answers `BLOCKHASH` from its database and S24
gives it an empty one, so the opcode returns a **placeholder** — §1.2. A later stage adds
`block_hashes` and whatever else a real block needs, and §1's shape moves with it. What a
change must keep is §1.1: one logical state, exactly one encoding.

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
    stateless   Option<Vec<u8>>       absent in the synthetic mode

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

AccountWitness
    address     [u8; 20]
    nonce       u64
    balance     [u8; 32]
    code        Vec<u8>                      empty for an EOA
    slots       Vec<([u8; 32], [u8; 32])>    ascending by key

TxWitness
    caller             [u8; 20]      already recovered; see §1.2
    to                 Option<[u8; 20]>   None is a contract creation
    value              [u8; 32]
    data               Vec<u8>
    gas_limit          u64
    gas_price          u128          the max fee per gas for an EIP-1559 tx
    gas_priority_fee   Option<u128>
    nonce              u64
    chain_id           Option<u64>
    access_list        Vec<([u8; 20], Vec<[u8; 32]>)>   EIP-2930
```

### 1.1 Canonicity

**One logical state has exactly one encoding**, and `BlockWitness::decode` is what makes
that true rather than hoped for. It refuses, by name:

| Rule | Error |
| --- | --- |
| `spec_id` names a hardfork | `UnknownSpec { spec_id }` |
| accounts ascend by address, without repeats | `AccountsNotSorted { at }` |
| an account's slots ascend by key, without repeats | `SlotsNotSorted { account, at }` |
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

- **Block hashes, and this is the one that is a *gap* rather than a decision.** revm
  answers the `BLOCKHASH` opcode from its `Database`, and `revm_block::run` hands it a
  `CacheDB<EmptyDB>` whose block-hash cache is empty. Every lookup therefore falls
  through to `EmptyDB`, which returns **`keccak256` of the block number's decimal
  string** — deterministic, agreed on by the guest and the host, and not any block's
  hash. So a contract reading `BLOCKHASH(n)` for an `n` within the last 256 blocks
  computes on a made-up word and the block still "executes". EIP-2935's history contract
  does not rescue it either: revm 42 serves the opcode from the host, not from state.
  The field that closes this is a `block_hashes: Vec<(u64, [u8; 32])>` on
  `BlockEnvWitness` or `BlockWitness`, loaded into that cache before execution, and it is
  why §1 is **not frozen** — the stage that records a real block adds it.
  `crates/emulator/tests/revm.rs::blockhash_reads_a_placeholder_today` pins today's
  answer, so closing the gap is a decision rather than an accident.
- **A parent header, and the header rules that need one.** EIP-1559's bound on
  `gas_limit` against the parent's, and the `≥ 5000` floor, are checks against a block
  this witness does not carry. What *is* enforced is §1.4.
- **Signatures.** `caller` is the recovered sender. There is no `ecrecover` delegation in
  this repository (`prompts/00-master.md`, "Stage register"), and recovery is the
  witness producer's job, not the block executor's — revm's own `TxEnv` takes a `caller`
  for the same reason.
- **A post-state root.** S24 runs over a synthetic pre-state; what the execution produces
  is summarized in §2, not proved against a root.
- **The stateless section's meaning.** `stateless` is `Option<Vec<u8>>` and S24 says only
  that it is there, that it is last, and that its absence changes the encoding of
  nothing before it. The stage that needs it defines its bytes. It is not an invented
  shape: a guess here would be surface area nobody asked for, and a later stage is
  allowed to edit this file.
- **Transaction types 3 and 4.** `TxWitness` expresses EIP-155, EIP-2930 and EIP-1559
  transactions — types 0, 1 and 2 — and `TxEnv::derive_tx_type` picks the type from the
  fields, so a witness cannot claim one its fields do not support. It carries no
  `blob_hashes`/`max_fee_per_blob_gas` (EIP-4844) and no `authorization_list` (EIP-7702).
  Those are two and one more fields respectively, appended at the end of `TxWitness`, and
  the stage that meets a block containing one appends them — an authorization list needs
  the same "already recovered" treatment `caller` gets, since this VM cannot recover a
  signature, and that is a decision for the stage that has one to encode. They are left
  out here rather than guessed at: a field no fixture exercises is surface area nobody
  tested, and master anti-goal 10 is explicit about adding one because a later stage
  might need it.

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

## 2. The output commitment

fd 1, in full, and always all three sections — there is no optional one:

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
witness's transaction count, and fd 0 and fd 1 are bound by the same `io_digest`, so a
reader of the output has the input.

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
