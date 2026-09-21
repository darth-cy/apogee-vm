---
title: S20 — Sharding + Block Orchestration

---

# S20 — Sharding + Block Orchestration

## Depends on / Inputs
- From S12's `trace` you take `ShardPlan`, `TraceArchive` (the per-phase snapshots) and `MemoryEventLog`.
- From S11 you take `VmConfig` (family set + heights + shard counts) and `ProgramIdentity`.
- S14 gives you the memory argument (global tuple compression, read/write roots, init/teardown family), S15 the per-shard LogUp roots, and S16 `ShardProof`, `VerifyingKey`, the single-shard prover, the verifier entry point and the tamper harness.
- E17–S19 supply the breadth families, any of which may appear in a plan. S09's `pcs` supplies batch opening and verification, S02's `Transcript` snapshot/restore.

## Deliver
- In `prover`, build the block orchestration: execute a `ShardPlan` over a `TraceArchive`, run the global commit phase, prove all shards (parallelizable), assemble a `BlockProof`. Freeze roughly:
  ```rust
  pub fn prove_block(vk: &VerifyingKey, archive: &TraceArchive, plan: &ShardPlan) -> Result<BlockProof, ProveError>;
  pub fn verify_block(vk: &VerifyingKey, proof: &BlockProof, public: &PublicInputs) -> Result<(), VerifyError>;
  ```
- `BlockProof` carries the `VmConfig` descriptor and per-family shard counts as PUBLIC data readable through a stable API. Downstream stages consume exactly these: S24's occupancy assertions, S26/S27's shard-set replay. It also carries the per-shard records (family id, shard index, ts window, memory-column commitments, read/write roots) and the `ShardProof`s. The frozen public-data API also exposes the per-shard record list (family id, shard index, ts window, memory-column commitments, roots) in canonical order, the contained `ShardProof`s, and the `BlockReconciliation` view. S26's host driver and S27's `aggregate_block` are the consumers. No accumulator-entry accessor exists. AccumulatorEntry lists are produced ONLY by deferred verification (`batch_verify_deferred`) during recursion (S26), and are discharged at the endgame (S27/S28). `ShardProof` and `BlockProof` carry no accumulator entries, because base verification executes its pairings inside `pcs`.
- `BlockReconciliation` is the cross-shard record set as a named type: per-shard memory-column commitments plus read/write roots plus ts windows, in canonical (family id, shard index) order. S27's aggregation guest replays it, so freeze its serialization.
- In `verifier`, freeze the verifier factoring as public API inside the no_std verifier core: `derive_global_phase(vk, statement, memory_commitments, ...) -> (GlobalChallenges, global state digest)` and `verify_shard_local(vk, global_digest, shard_record, &ShardProof) -> Result<...>`. These are the exact functions `verify_block` itself composes, so the single-path rule is preserved. S27's leaf/root split is the consumer.
- Extend the `verifier` CLI so it verifies a `BlockProof` file end-to-end.
- In `checker`, build a transcript-tape validator that dumps the global commit phase's absorb sequence and diffs it against the master's frozen pre-fork order, negative-control tested.

## Core algorithm
**Global commit phase (the statement-binding invariant made code).** Absorb exactly per the frozen pre-fork order, not restated here, then squeeze γ_M, α_addr, α_ts and α_val. **Delta — S20-specific refinements only.** (i) The per-family memory-column commitments are absorbed in canonical (family id, shard index) order. (ii) Length delimiting follows the master's per-message framing. (iii) Each shard's ts-window claim is bound via the per-shard ts-window binding absorb, one typed message immediately after the seed triple (global state digest, family id, shard index). S16 binds the trivial full-execution window and S20 generalizes the value. `verify_shard`'s tape is unchanged between S16 and S20, and the S16 seed itself is unaltered. Then fork: each shard's local transcript is seeded per the S16-frozen convention, followed immediately by the typed ts-window binding absorb, then absorbs that shard's witness commitments, and only then draws local challenges. The S16 single-shard path must be reused, not reimplemented, with only the seeding generalized.

**Cross-shard reconciliation (verifier side).**
1. Multiply the read-side roots across all shards and families, including init/teardown, and multiply the write-side roots; the products must be equal. This alone carries PC continuity across shard boundaries. no pc chaining anywhere.
2. Every shard's LogUp channel roots check num == 0 AND den != 0 locally, via the S16 path run per shard.
3. Ts windows. Each shard publicly claims [ts_start, ts_end). The block verifier checks that the windows are pairwise disjoint and ordered within the plan, and that each shard's trace is anchored to its window. Anchoring means row-0 timestamp = ts_start, via a boundary obligation. Window claims are bound via the typed ts-window binding absorb immediately after the seed triple, per the delta above. Disjointness, ordering and row-0 anchoring apply to CYCLE-OWNING families only, per a per-family flag in the `VmConfig`/family artifact. A non-cycle (delegation) family's shard record instead carries its min/max invocation timestamp as its window, with NO disjointness requirement, because per-address ordering is already carried by the multiset gap checks. E21–S23 then slot in with zero `verify_block` changes.
4. Shard-set exactness: the per-family shard counts in the descriptor equal the shard records present, with no duplicate (family, index), no gap and no extras.
5. Zero-shard families: a family in `VmConfig` with zero shards this execution is valid. Omitting a shard whose cycles executed is caught by check 1, because its memory writes/reads (including pc tuples) are missing from one side of the global multiset.

**Shard plan execution.** Cut each family's records from the `TraceArchive` in increasing timestamp order into contiguous chunks of exactly the height `VmConfig` gave that family, with shard indices ascending from 0. Delegation families are cut over their invocation records. Pad each family's last chunk to full height with the canonical padding row, so every shard trace has its family's menu height and a cycle-owning shard's row 0 carries ts_start. Force the two-shard demo by configuration: give the demo guest's main cycle-owning family the smallest menu height, 2^16, so an ordinary run of the unmodified guest spills into a second shard.

**Parallelism.** After the global commit phase closes, prove the shards with a `rayon` parallel iterator over the shard records. Each task forks its transcript from the S02 snapshot of the global state, so shards share no prover state and the schedule cannot influence a challenge. Peak memory stays at one shard trace per worker: a task reads its slice of the archive, proves it, then drops it.

**Serialization.** Within Must-be-exact 5, `BlockProof` and `BlockReconciliation` serialize with `postcard` over `serde`, field elements in canonical 32-byte little-endian, sections ordered by the descriptor.

## Must-be-exact
1. Absorb the pre-fork order verbatim, plus only the flagged delta refinements above. All tags come from `constants`, and per-message framing follows the master transcript discipline. No challenge of any kind is drawn before the full statement is absorbed.
2. `verify_block` takes `(&VerifyingKey, &BlockProof, &PublicInputs)` and nothing else, with one verification path (master rule 7): the CLI calls the same function tests do.
3. The statement descriptor is static VmConfig plus per-proof per-family shard counts, absorbed as two adjacent typed messages (frozen in S11's handoff). Both parts are public, serialized in the proof and covered by the statement absorption, so a proof cannot claim different occupancy than it binds.
4. Shard proving consumes the S16 prover as-is per shard. The only new prover code is orchestration, the global phase and seeding.
5. `BlockProof` shape is fixed given `VmConfig` (the master proof-shape invariant): section lengths derive from the descriptor, never from data-dependent branching.
6. Reconciliation checks (1)–(5) all live in `verify_block`, and none is delegated to prover-side self-checks. The ts-window check applies its disjointness, ordering and row-0-anchoring rules to cycle-owning families only (per-family flag). Delegation-family windows are min/max invocation timestamps with no disjointness requirement, per Core check 3.
7. Every prover phase boundary (post-execution / post-commit / post-GKR / post-opening / final) exports a resumable snapshot including transcript sponge state, across the whole block orchestration and not just per shard. Block-level phase snapshots also land in the TraceArchive phase sections. Phase snapshots ARE the corresponding phase sections of the S12-frozen TraceArchive container, with wall-clock in S12's per-phase timing fields. S16 defines the section schemas for the phases S12 left empty.
8. The assembled `BlockProof` is byte-identical for any thread count and any shard schedule. Block-level parallelism is confined to shard proving after the global phase closes, each shard proves from its own forked transcript, and records are reassembled in canonical (family id, shard index) order.
9. Each `BlockReconciliation` record is laid out as family id, shard index, ts_start, ts_end, memory-column commitments in column order, read root, write root. That is the exact layout S27's aggregation guest replays.

## Acceptance
1. **Stage gate:** one guest execution split across ≥ 2 shards of the SAME family proves to a `BlockProof`, and `verify_block` returns Ok. The global-challenge protocol is live: assert the memory challenges are squeezed exactly once, after all commitments. Pc continuity across the shard boundary is carried only by the global multiset, checked by a structural schema assertion. The `ShardProof`/`BlockProof` schemas contain no per-shard boundary-pc/successor-pc fields, and the transcript-tape validator's absorb list contains no pc-chaining message tags.
2. Multi-family block: a guest touching ≥ 3 breadth families (E16–S19) proves and verifies, and structural count assertions run over shard counts and per-shard root presence.
3. Absorb-order conformance: the checker's transcript tape for run 1 matches the master's frozen list item-for-item, committed as a fixture. Negative control: a test-only fork swapping two absorptions produces different global challenges and a verification failure.
4. Statement-binding negatives each fail with the expected error class. Verify an honest proof against (a) a `PublicInputs` with a one-bit-different public I/O digest → fail; (b) a different `ProgramIdentity`/`VerifyingKey` → fail; (c) a descriptor with one family's shard count altered → fail.
5. Tamper twin — omit one shard. Drop one shard record and proof from an honest `BlockProof`, adjusting counts to match; verification fails via global read/write root product mismatch.
6. Tamper twin — swap ts windows. Exchange two shards' claimed windows in an otherwise honest proof; verification fails at the window anchoring or disjointness check, with the expected error class.
7. Witness tamper twin: re-prove one shard with ONE corrupted trace cell (bus/argument-pinned) and reassemble the block. `verify_block` fails, and the honest twin passes.
8. Zero-shard skipping: a program whose `VmConfig` includes a family with zero occurrences in this execution yields a `BlockProof` with zero shards for it. Verification passes, and the public shard count reads 0 through the stable API.
9. Public-data contract: a test reads the `VmConfig` descriptor and the per-family shard counts from a serialized `BlockProof` via the public API only, with no internal access. That is the S24/S26 consumption path.
10. Resume: kill and resume the block prover at the post-commit and post-GKR boundaries; the resumed run produces a byte-identical `BlockProof`.

## Handoff
Freeze `BlockProof`, together with its public-data API and file format. Freeze `BlockReconciliation` and its serialization, and the `prove_block`/`verify_block` signatures. Freeze the no_std-core verifier factoring: `derive_global_phase(vk, statement, memory_commitments, ...) -> (GlobalChallenges, global state digest)` and `verify_shard_local(vk, global_digest, shard_record, &ShardProof) -> Result<...>`. Freeze the per-shard ts-window binding absorb, one typed message immediately after the seed triple (global state digest, family id, shard index). S16 binds the trivial full-execution window, and S20 generalizes the value. Freeze the ts-window anchoring convention, cycle-owning scoping included, and the CLI verb. Record measured numbers: per-shard prove time, block assembly overhead, and proof size for the two-shard demo.