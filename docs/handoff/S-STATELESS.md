# S-STATELESS — the canonical stateless validator, held to `tests-zkevm@v21.0.1`

**This stage takes no number**, the same reading as `S-IO`, `S-STREAM` and the others. It is
the stage that makes the full-block guest a target whose numbers other zkVM teams' CPU
provers can be compared against. The owner's instruction named two gaps:

> 1. Signature-authenticated transactions … do secp256k1 recovery in the guest and derive
>    the caller rather than trust it … the same for EIP-7702 authorizations.
> 2. Canonical block-output/header validation: cumulative gasUsed, canonical receipts,
>    receiptsRoot, logs bloom, transactions root, withdrawals root, requests hash, header
>    RLP/hash, versioned-hash/payload consistency, relevant parent-header continuity.

and kept the next stage — the canonical benchmark interface, `eth-act/zkevm-benchmark-
workload`'s `StatelessInput` in and its standardized result out — in view. Midway the owner
pulled that interface forward, with Amsterdam, and set the frame: *focus only on the
stateless block guest and how defensible it is; the mini mode is a workaround, not a
reference.*

`docs/spec/stateless.md` is the normative page and this note does not repeat it.

---

## 0. The decisions, and who took them

Every one is the owner's, asked as it arose.

| # | Decision | Alternative rejected |
| --- | --- | --- |
| 1 | Recovery **without re-verification**: `Q = r⁻¹(sR − zG)` over k256's arithmetic, EIP-2's rules | ecdsa's `recover_from_prehash`, which re-verifies — about half the cost, and it cannot fail once recovery succeeds |
| 2 | The pre-state is **trie reads and codes**: the canonical witness, every read a walk from a hash | recorded values with proofs beside them |
| 3 | **Own the encodings** — RLP, transactions, headers, receipts, tries, SSZ | `alloy-consensus` |
| 4 | The statement is **the exact 43-byte `statelessOutputBytes`**: request root, verdict, chain id, schema id | a journal of our own; roots in the public input |
| 5 | The input is **canonical SSZ now**: `statelessInputBytes`, v21's layout, no public keys | our own witness format, converted next stage |
| 6 | Forks **Osaka, BPO1, BPO2 and Amsterdam** (`0x1201`–`0x1501`) | the Osaka family alone |
| 7 | revm **`=43.0.1`, mirroring the reference stateless guest's lock crate for crate** | 42.0.1, whose Amsterdam schedule predates the spec; 43.0.2, which reverted the system-call reservoir |
| 8 | A **reference tool** for the SSZ the release does not fill, out of the workspace like `transcript-ref` | the release alone |
| 9 | **Delete the old stateless format whole**: the generator, its fixtures and tests, `mini-block-nodes.bin`, `BlockWitness.stateless` | keeping it beside the new one |
| 10 | **Read both input layouts**: v21's, and ere-guests v0.17.1's with a public key per transaction, which the benchmark's own datasets carry (§7); a key is checked against the recovered sender, as ere-guests' reth guest checks it | v21's alone, which refused every dataset block; the keyed one alone; stripping the keys on the host, so our input bytes would not be the files other teams prove |

Stated as defaults and not objected to: the fork comes from the schema id and no mainnet
timestamp schedule is compiled in; any failure after decoding publishes `false` with the
real root; an undecodable input or unsupported schema publishes the 43-zero sentinel; the
guest always exits 0; the empty input cannot be given to the binary, a run with no advice
having no advice region, and the library answers it natively.

---

## 1. What was built

Five commits before this note's, on top of S-STREAM:

1. **`096a639`** — the revm set. revm 43.0.1 and its sub-crates exactly as
   `paradigmxyz/stateless` locks them, both lockfiles, held by `crates/host/tests/
   revm_lock.rs`; `guests/vendor/revm-precompile` re-vendored at 43.0.2 with S26c's patch
   unchanged.
2. **`6177fa9`** — the canonical encodings and in-guest recovery: `rlp.rs`, `tx.rs` (the
   five transaction types, signing hashes rebuilt, senders and authorities recovered),
   `block.rs` (headers, the fork table, `validate_header`, base fee, excess blob gas,
   tries, receipts, bloom, withdrawals, deposits, requests hash, block size) and
   `host::canonical`, held to two real mainnet blocks.
3. **`5e68b61`** — the validator: `ssz.rs`, `witness.rs`, `stateless.rs`, the binary, and
   the old format's deletion.
4. **`1676b4c`** — the CI oracles: the release subset, `tools/stateless-ref`, the block-size
   test.
5. **`32b650d`** — the binary through the emulator.

After this note: the keyed layout, decision 10 and §7.

---

## 2. Conformance: what the release found

The first full run matched 65,383 of 67,251 pairs. Four bugs accounted for every miss, and
each was fixed at its cause:

| Bug | Pairs | Fix |
| --- | --- | --- |
| `merkleize` read zero subtrees from a table sized for depth 11; a progressive subtree is `4^k` wide, so a 260 kB transaction rooted wrong | 30 | the zero subtree is hashed up beside the data — no table, no bound to be wrong about |
| `WitnessDb::basic` loaded every account's code with it; the witness carries only what the spec read, and a coinbase can be a contract nothing calls | 1,830: 1,818 refused in execution, 12 at a system contract's code check | code loads only when revm asks; `0xef01` bytes that are not a delegation are ordinary code |
| the post-state replay interleaved deletions with writes; a collapse then needed a sibling the witness lacks | 4 | every write first, as `mpt_set_storage_slots` orders a storage trie, and the state trie too |
| revm 43's access-list builder nets a write against the baseline its commit carries, and revm re-baselines per call; two system calls at one index that toggle a slot back, or a withdrawal a dequeue forwards on, recorded a change | 4 | each block access index is one commit, its baselines set back to the committed state (`commit_index`) |

**The last one is worth knowing beyond this repository.** The reference executor
(`alloy-evm` 0.39's `EthBlockExecutor`) commits each post-block system call separately and
so records the same spurious writes; it also runs the request system calls *before* the
withdrawals, where the spec runs them after. Following reth would have kept both. The
release's own tests named the mechanism — `test_bal_post_execution_calls_net_storage_at_
last_index` and `test_bal_withdrawals_and_dequeues_net_balance_at_last_index` — which is
the reason the oracle had to be the release and not a second implementation.

**After the fixes: 67,251 pairs of 67,251** — 55,808 valid, 11,425 invalid, 18 undecodable
or unsupported — over 28,978 distinct inputs, in about 2 s natively.

---

## 3. The oracles, and what each holds

| Oracle | Holds | Runs |
| --- | --- | --- |
| the whole release | every pair, bytes | by hand: `APOGEE_ZKEVM_FIXTURES=… cargo test --release -p host --test conformance every_stateless -- --ignored` |
| `zkevm-subset.json`, 34 cases | for each rule the release decides, its smallest case; the smallest valid one; all nine undecodable ones; the five the fixes were found by — each to its bytes **and its rule** | CI |
| the binary | the subset's 33 runnable cases, through the emulator | `#[ignore]`d, 17 s, above the line |
| `tools/stateless-ref` | the Electra/Fulu layout against `eth-act/ere-guests` v0.17.1 — 23 inputs and 6 broken ones, including each layout under the other's schema id | CI, regenerated and diffed |
| two real mainnet blocks | headers, 313 transactions and their senders, roots, receipts, bloom, gas, block size, deposits, blob price; each header rule by its own mutation | CI |
| the keyed layout | every decodable subset case re-encoded with its signers' keys is the same 43 bytes; keys too few, too many, another signer's or not uncompressed are refused; a list of part-keys does not decode | CI |
| the benchmark's `glamsterdam-devnet-8` dataset | real devnet blocks in the keyed layout, to their bytes, natively and through the binary (§7) | by hand: `APOGEE_ZKEVM_FIXTURES=<batch> … every_stateless` and `… every_output` |

ere-guests v0.17.1 still carries the `public_keys` field v21 dropped, so `stateless-ref`
declares the v21 container itself with libssz's derive and uses ere for the request types
and their roots.

The subset caps inputs at 64 KiB, which leaves one rule without a case: EIP-7934's block
size, whose smallest refusal is 8 MiB by definition. `canonical.rs::the_block_size_is_the_
node_s` holds `block_rlp_len` to the size the node reports instead.

---

## 4. Cycles

From `the_guest_publishes_the_subset_s_outputs`, on the release image. These are the
release's blocks — one transaction or none, a handful of accounts — so they price the
fixed costs and one transaction, **not a mainnet block**:

| Case | Cycles |
| --- | --- |
| undecodable input | 1,046 – 11,888 |
| refused at the ancestors, the header or the block hash | 143,774 – 230,555 |
| refused at the chain id, before recovery | 600,225 |
| no transactions, valid (`…forward_all`) | 982,770 |
| one transaction, refused after its sender was recovered (`Capacity`, `Execution`, `Deposits`) | about 2,820,000 |
| one transaction, valid (`fill_stack`) | 3,548,433 |
| the largest, valid (`…block_diff_delete_insert_before_delete_order`) | 5,972,895 |

So an empty block's fixed cost — the SSZ decode, the request root, six system calls, the
access list and the post-state root — is about 1.0M cycles. A transaction adds about 1.8M,
and commit `6177fa9`'s measurement puts the verify-free recovery at about 1.4M of that.

The release image's `.text` is **1,959,096 bytes, 96.5% of what a `2^20` decoded table
reaches**, about 72 kB of headroom; the largest share is the precompiles' BN254 and
BLS12-381 arithmetic, live code since Prague's EIP-2537. Decision 10's keyed layout added
2,662 bytes — **1,961,758, 96.6%, about 70 kB** — and moved the cycles above by under 0.1%
(`fill_stack` is 3,548,995).

**A real block is §7's**: the ten newest blocks of the benchmark's devnet dataset, 46–106
transactions and about 101 Mgas each, are **244M–582M cycles** through the binary. Block
257,510's 349M are 37% secp256k1, its 60 recoveries, and 32% `memcpy`.

---

## 5. Fixtures

| File | What |
| --- | --- |
| `crates/host/tests/vectors/zkevm-subset.json` | new; `kat-gen -- zkevm`, opt-in |
| `crates/host/tests/vectors/stateless_ref.txt` | new; `tools/stateless-ref`, in CI; 33 inputs since decision 10, four of them in the keyed container |
| `crates/host/tests/vectors/canonical/` | new; block 26,059,929, its parent, its receipts |
| `crates/emulator/tests/vectors/revm_block_witness.bin` | 725 → 724 bytes: the dropped `None` tag. Output and keccak frames byte-identical |
| `crates/host/tests/vectors/mini-block-witness.bin`, `mini-block.json` | one byte shorter, re-pinned; the journal unchanged |
| `revm_stateless_{witness,root,journal}.bin`, `mini-block-nodes.bin` | **deleted** (decision 9) |

---

## 6. What this stage owes

### Green here

`cargo fmt` in all five workspaces; `cargo clippy --workspace --all-targets`, `(cd guests &&
cargo clippy --bins)` and `stateless-ref`'s, all `-D warnings`; the scoped suites the change
reaches — `host`'s `canonical`, `mpt`, `witness`, `ssz` and `conformance`, `emulator`'s
`revm`; above the line, `program --test delegation -- --ignored` (16 s),
`APOGEE_GUEST_PROFILE=release emulator --test revm -- --ignored` (5 tests, 17 s) and
`host --test conformance the_guest -- --ignored` (33 cases, 17 s); and the whole release by
hand. `cargo test --workspace` is CI's.

### Owed

**1. An Osaka, BPO1 or BPO2 block validated end to end against a canonical output.** The
release fills only Amsterdam. The Electra/Fulu layout is held by `stateless-ref` and every
component by real blocks, but no Electra/Fulu input with a witness has been through
`verify`. It needs a witness producer, which is the next stage's — and this endpoint cannot
be it: S25 found `debug_executionWitness` unserved and `eth_getProof` unable to return a
collapse's sibling. The benchmark's devnet dataset (§7) is Amsterdam's, so it closes this
for that fork alone — with real blocks where the release has test fills.

**2. Rules no release case decides.** `ReceiptsRoot`, `Bloom` and `StateRoot` are computed
in every valid case but refuse in none; `EmptyTransaction`, `Unrepresentable` and four of
the witness's refusals — a malformed node, a missing node, a missing code, a missing
ancestor — likewise. Eight of the twelve header rules are reached only by `canonical.rs`'s
mutations. `docs/spec/stateless.md` §5 is the list.

**3. The `# DEFERRED` suites.** The revm crates moved and `guests/revm-block` changed, so the
mini guest's image, identity and cycle counts moved with them: `prover --test revm` and
`host --test prove`, the mini-block gate, pin numbers this stage did not re-measure. They
run in one batch at the end of the progression, per the root `CLAUDE.md`.

**4. 70 kB of image headroom.** The next feature added to the stateless binary should be
priced against it; past `2^20`'s reach the decoded tables go to `2^22`.

**5. The next stage**, as the owner framed it: `bench prove` over a `statelessInputBytes`
rather than a mini-mode pin — no stateless pin exists, and `fixture::Mode::Stateless` today
only names the binary — and the benchmark workload's positive and rejection fixtures, which
the subset already shows the guest passing for this release. §7's dataset is the input a
first full-block proof can take: real, canonical, its output known, no producer needed.

---

## 7. The benchmark's own datasets

The zkEVM benchmark publishes `glamsterdam-devnet-8`'s blocks as stateless inputs: 72,732
of them in 7,247 batches, each a `blockchain_tests/` fixture carrying
`statelessInputBytes` and `statelessOutputBytes`, written by `witness-generator-spec-cli`
for `ere-hosts --input-folder`. Schema `0x1501`, and real devnet traffic: the newest batch's
blocks are 46–106 transactions and about 101 Mgas each, their inputs 0.85–1.15 MB.

**v21's decoder refused every one.** Their container is ere-guests v0.17.1's: a fourth
field after the chain id holding one 65-byte uncompressed public key per transaction.
Everything else — request, payload, witness — is v21's byte for byte: with the keys cut
out, the validator published the expected 43 bytes for all ten. So the guest reads both
(decision 10), and with keys present does what ere-guests' reth guest does: it recovers the
sender regardless, and refuses unless there is one key per transaction and each,
`0x04 ‖ x ‖ y`, names its sender. The keys are checked and never used. Flipping one byte of
a real block's last key is refused, with the real root, after its 59 other transactions ran.

| By hand | Blocks | Result |
| --- | --- | --- |
| natively, `every_stateless` | 90: the newest batch, and eight from block 93,300 to 255,019 — empty blocks to 105 Mgas, inputs 27 kB to 1.34 MB | every one the expected bytes |
| the binary, `every_output` | the newest ten | exit 0 and the expected bytes, 244M–582M cycles, 59 s in all |

The whole dataset, 22.67 GiB packed, has not been run.
