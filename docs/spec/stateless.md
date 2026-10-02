# The stateless validator

`revm-block-stateless` is the canonical stateless validator: `tests-zkevm@v21.0.1`'s
`statelessInputBytes` in, its `statelessOutputBytes` out, byte for byte, which is what the
zkEVM benchmark compares across zkVMs. **The two wire formats are the spec's, not this
repository's** — `ethereum/execution-specs` at `3ebcb5d0`, `forks/amsterdam/stateless.py`
and the execution-engine modules beside it — so this page does not restate them. It is
normative for what *is* ours: which inputs the guest validates, what it publishes for the
rest, and how a block runs on revm so that the result is the spec's.

`guests/revm-block/src/{ssz,witness,stateless}.rs` is the code, and
`docs/handoff/S-STATELESS.md` is the account of how it was built. The mini mode — S24's
`BlockWitness` and its journal — is `docs/spec/revm-block.md` and is a different program
identity.

## 1. Input and output

```
statelessInputBytes   -> ADVICE          schema_id (u16 BE) ‖ SSZ(StatelessInput)
statelessOutputBytes  -> PUBLIC OUTPUT   SSZ(StatelessValidationResult), 43 bytes

StatelessInput            two layouts, told apart by the fixed part: 16 bytes or 20
    new_payload_request   the schema id's fork's NewPayloadRequest
    witness               state (trie-node preimages), codes, headers (oldest first)
    chain_id              u64
    public_keys           ere-guests' layout only: one 65-byte key per transaction

StatelessValidationResult
    new_payload_request_root   32   hash_tree_root, EIP-7916 as of 2026-01-15
    successful_validation       1
    chain_id                    8   LE
    schema_id                   2   LE
```

**The schema id names the fork, and four are validated** (owner's decision): `0x1201` Osaka,
`0x1301` BPO1 and `0x1401` BPO2, whose request is Electra/Fulu's, and `0x1501` Amsterdam,
whose request is Gloas' — a block access list and a slot number in the payload, EIP-8282's
two builder request lists in the requests. **The fork is never derived from a timestamp**:
no mainnet activation schedule is compiled in, so a chain's schedule is the input's to
state and the spec's to check. Each fork's blob parameters are `block::fork`'s table:

| schema | fork | target | max | update fraction |
| --- | --- | --- | --- | --- |
| `0x1201` | Osaka | 6 | 9 | 5,007,716 |
| `0x1301` | BPO1 | 10 | 15 | 8,346,193 |
| `0x1401` | BPO2 | 14 | 21 | 11,684,671 |
| `0x1501` | Amsterdam | 14 | 21 | 11,684,671 |

**Two layouts share each schema id** (owner's decision). `tests-zkevm@v21.0.1`'s has
three fields. `eth-act/ere-guests` v0.17.1's — the zkEVM benchmark's guests, and the
layout of its published devnet datasets — has a fourth after the chain id: one
uncompressed public key, `0x04 ‖ x ‖ y`, per transaction. A container's first offset
is its fixed size, 16 or 20, so no input is both. **A key is checked, never trusted**:
the sender is still recovered from the signature, and the input is invalid unless there
is exactly one key per transaction and each names its transaction's recovered sender —
ere-guests' reth guest's rule. The request root, and so the result, does not depend on
the layout.

**Three outcomes, and the guest exits 0 in all of them:**

- an input that does not decode — too short for a schema id, a schema id not in the table,
  or an SSZ body that is not exactly that fork's `StatelessInput` — publishes the
  **sentinel**, 43 zero bytes. The decoder is exactly as strict as the spec's: every offset
  against the bytes it bounds, every bounded list against its limit, a key list of whole
  keys, nothing after the last field;
- an input that decodes and breaks any rule after that publishes `false` with the
  **request's real root**, the chain id and the schema id;
- a valid one publishes `true` with them.

The verdict is a field of the journal, as the spec's guest returns it, and a failed
validation is still a successful execution. **The one input the binary cannot be given is
the empty one**: a run with no advice has no advice region (`docs/spec/public-values.md`
§6). The library answers it with the sentinel natively.

**Why the input can be advice.** Nothing binds advice, and nothing needs to. The result
publishes the root of the request it validated, which fixes every byte of the payload;
the witness is held to the payload by hashes — the parent header to the payload's
`parent_hash`, every trie node to the hash its parent names, every code to the code hash
its account names. A witness that is wrong or incomplete cannot make an invalid payload
valid; it can only make the result `false`.

## 2. What validation is

The spec's order, `stateless.rs::verify`, first failure wins:

1. the ancestor headers decode and chain by `parent_hash`; the last is the parent, and a
   header's `BLOCKHASH` number is its **position** counted back from the block's own;
2. no empty transaction; the header the payload implies hashes to its `block_hash`; every
   transaction decodes strictly (EIP-2718, types 0–4); in ere-guests' layout, one public
   key per transaction; the blob transactions' versioned hashes are the request's;
3. EIP-7934's block size, and the header against its parent;
4. the block runs — EIP-4788 and EIP-2935, every transaction (sender recovered and any key
   held to it, chain id checked, admitted against the block's remaining gas, state gas and
   blob gas), the
   withdrawals, the deposit logs and the checked system calls of EIP-7002, EIP-7251 and,
   from Amsterdam, EIP-8282's two;
5. gas used, receipts root, logs bloom, blob gas used, requests hash, and for Amsterdam
   the block access list's item bound and hash, then the post-state root, are the header's.

`Invalid` names each rule for a test; the guest publishes only that one broke.

## 3. How a block runs on revm

**The revm pin is the reference stateless guest's, crate for crate**: revm 43.0.1 as
`paradigmxyz/stateless` locks it, the one release whose system calls carry EIP-8037's
state-gas reservoir (`crates/host/tests/revm_lock.rs`). The pre-state sits behind revm's
`State`, as reth's does, and three rules make the result the spec's where following reth
did not. Each was found by the release and each is load-bearing:

- **Code is loaded when revm asks for it, never with its account.** The witness carries
  exactly the code the spec's execution read, and a block's coinbase can be a contract
  nothing calls. `WitnessDb::basic` answers without code and `code_by_hash` answers on
  demand; 1,830 of the release's valid pairs were refused while it did otherwise. Bytes that begin with
  `0xef01` and are not a 23-byte delegation are ordinary code, as `is_valid_delegation`
  reads them.
- **Every write precedes every deletion** in the post-state replay, in each storage trie
  and in the state trie, as `mpt_set_storage_slots` orders them. A deletion that leaves a
  branch one child needs that child's node, which is on no changed key's path; the witness
  carries the siblings the spec's order needs, and writing first needs a subset of them — a
  branch collapses only if it ends collapsed, and then every order needs its survivor.
- **One commit per block access index, every baseline the index's.** revm 43's access-list
  builder records a value written at an index when it differs from the baseline its commit
  carries, and revm moves each baseline to the start of every call that touches it. The
  system calls before the transactions, and the withdrawals and system calls after them,
  are therefore each one journal, finalized once, with every baseline set back to the
  committed state before the commit (`commit_index`). The reference executor commits per
  call and records a slot one call toggles and the next restores as a write.

**Where reth and the spec differ, this is the spec's**, because the canonical result is the
spec's: a checked system contract must have code; deposit events are parsed to the byte;
withdrawals precede requests; an Amsterdam transaction's gas limit is bounded by
`TX_MAX_TOTAL_GAS_LIMIT`. Three smaller rules have the same root:

- revm's `TxEnv` is built **field by field**: `TxEnvBuilder::build_fill` inserts a dummy
  authorization into an empty type-4 list, and the empty list is a refusal;
- the blob price is a **checked** `fake_exponential` (revm's is unchecked, and an excess
  the header may carry would panic the guest), and an overflow means EIP-7918's reserve
  does not bind;
- a sender or authority is **recovered without re-verifying** (owner's decision): `Q =
  r⁻¹(sR − zG)` over k256's own arithmetic, under EIP-2's rules — `0 < r < n`,
  `0 < s ≤ n/2`, a parity bit. Re-verification cannot fail once recovery succeeds.

## 4. Where each rule is checked

| What | Where |
| --- | --- |
| every pair of the release, natively: 67,251 pairs, 28,978 distinct inputs | `crates/host/tests/conformance.rs::every_stateless_output_is_the_release_s`, **by hand** over an extracted release |
| one case per rule the release reaches, the smallest valid one, every undecodable one and the five the fixes were found by — 34, held to their bytes **and** their rule | `…::the_committed_subset_is_the_release_s`, in CI; cut by `kat-gen -- zkevm` |
| the guest binary publishes those 43 bytes | `…::the_guest_publishes_the_subset_s_outputs`, `#[ignore]`d: it builds the image |
| ere-guests' layout: every decodable subset case is the same validation with its signers' keys, and keys too few, too many, another signer's or not uncompressed are refused | `…::the_keyed_layout_is_the_same_validation`, in CI |
| the zkEVM benchmark's `glamsterdam-devnet-8` dataset — real devnet blocks to 105 Mgas, in ere-guests' layout; 90 blocks across the devnet's history matched natively, the newest ten through the binary | `…::every_stateless_output_is_the_release_s` and `…::every_output_of_a_directory_is_the_binary_s` over an extracted batch, **by hand** |
| the Electra/Fulu layout, which no release fills, and both containers, against `eth-act/ere-guests` v0.17.1 | `crates/host/tests/ssz.rs`, over `tools/stateless-ref`'s vectors |
| headers, transactions, recovery, roots, receipts, the bloom, the block size, deposits and the blob price, against real mainnet blocks; each header rule by its own mutation | `crates/host/tests/canonical.rs` |
| the trie | `crates/host/tests/mpt.rs` |
| the revm set | `crates/host/tests/revm_lock.rs` |

## 5. What no oracle here reaches

- **An Osaka, BPO1 or BPO2 block validated end to end against a canonical output.** The
  release fills only Amsterdam; the layout is `ssz.rs`'s and the components are
  `canonical.rs`'s, but no Electra/Fulu input with a witness has been run through
  `verify`. The witness producer that would make one is the next stage's.
- **Rules no release case decides.** `ReceiptsRoot`, `Bloom` and `StateRoot` are computed
  for every valid case, so each computation is held, but no case is refused by them;
  likewise `EmptyTransaction`, `Unrepresentable` and four of the witness's own refusals —
  a malformed node, a missing node, a missing code, a missing ancestor. Of the twelve header rules the
  release decides four; `canonical.rs` refuses all twelve one mutation at a time.
- **The block-size boundary in CI.** Its smallest refusal is 8 MiB, past the subset's
  64 KiB cap; `canonical.rs` holds `block_rlp_len` to real blocks' sizes and the boundary
  itself is the by-hand run's.
