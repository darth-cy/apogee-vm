# The block: sharding, orchestration and `verify_block`

Frozen as of S20. Changing anything here is a protocol-version change. S21 registered the
first family that owns no cycles and is not a RAM window — the keccak delegation family — and
**changed no line of `verify_block`**: the rule §4 already scoped to `CYCLE_OWNING` is what
admitted it (`docs/spec/delegation.md` §8).

A statement is one execution of one program, proven by one `ShardProof` per shard of
every family, every one of them against one `PublicInputs`
(`docs/spec/shard-proof.md` §1). This page is that set closed into one object: what a
`BlockProof` carries, what `verify_block` checks beyond what a shard's own verification
checks, how the prover cuts an execution into shards and proves them in parallel, and
the cross-shard record set S27's aggregation guest replays. It cites
`docs/spec/shard-proof.md` for the statement, the transcripts and the per-shard checks,
and `docs/spec/memory.md` for the multiset, and restates neither.

| crate | what |
| --- | --- |
| `crates/constants` | `family::CYCLE_OWNING`, which families own cycles |
| `crates/verifier-core` | `#![no_std]`: `BlockProof`, `ShardRecord`, `BlockReconciliation`, `check_ts_windows`, and the `derive_global_phase` / `verify_global_memory` / `verify_shard_local` split |
| `crates/verifier` | `std`: `verify_block`, and the CLI's `block` verb |
| `crates/prover` | `prove_block`, the shard cut, the per-shard time window, and the block's parallel step |
| `crates/trace` | `ShardPlan` and `plan_shards`, S12's |
| `crates/checker` | the transcript-tape validator |

The owner's decisions this page records, each put before any code:

1. **The two-shard demo is a new guest at `2^20`, not an existing one at `2^16`.** The
   stage prompt's "give the demo guest's main cycle-owning family the smallest menu
   height, 2^16" cannot be done: every execution family carries a timestamp gap
   obligation needing `lookup_channel::BITS[TIMESTAMP] = 19` variables and Mercury needs
   an even variable count, so `2^20` is the floor for every family that runs cycles
   (`docs/spec/lookup.md` §3), and `constraints::family_circuit` returns `None` below it
   for all seven. No existing guest spills either: the two that read an fd 0 input, `fib`
   and `heap`, are not provable at all while `EXIT` is the only provable ecall
   (`docs/spec/shard-proof.md` §8.4). So S20 adds `guests/shards`, whose one loop runs
   1,064,970 `ADD_SUB_LUI_AUIPC` cycles. §5.4.
2. **There is no row-0 anchoring obligation** (§4.1). The stage prompt asks for the
   claimed `ts_start` to be pinned to row 0's timestamp by a constraint. The owner's
   decision, on the ground that it buys no soundness: the global memory multiset already
   forces every live row of every shard onto one path from the entry pc to `HALT_PC`
   with strictly increasing timestamps (`docs/spec/memory.md` §4.2), so cross-shard
   ordering, cycle uniqueness and pc continuity are carried without it. **The obligation
   is removed from the design**, and the time window is what §4 says it is: a public
   claim, bound in the shard transcript, checked for shape and for per-family ordering,
   and tied to the trace by nothing.
3. **A `BlockProof` carries the statement it binds**, and `verify_block` holds it to the
   one the verifier was given (§3, check 1).

---

## 1. What a block is

```rust
pub struct BlockProof {
    pub config: VmConfig,
    pub statement: PublicInputs,
    pub shards: Vec<ShardProof>,
}
```

One execution, closed: the static VM shape it was proven under, the statement every
shard is proven against, and one `ShardProof` per statement shard **in statement
order** (`docs/spec/shard-proof.md` §1.2). Nothing in a block is evidence a shard's own
proof does not already carry — `verify_block` is `verify_shard` over every shard plus
§3's structural checks — and nothing in it is an accumulator entry: a base verification
runs its pairings inside `pcs`, and `AccumulatorEntry` lists are produced only by
deferred verification during recursion (S26) and discharged at the endgame.

**The descriptor is carried, not only read from the key.** The statement descriptor is
the static `VmConfig` plus the per-proof per-family shard counts, absorbed as two
adjacent typed messages at G3 and G4 (`docs/spec/shard-proof.md` §2). Both halves are
public data of the proof, so both are serialized in it, and check 1 holds the carried
copies to the key's config and to the verifier's statement. A block therefore cannot
claim one occupancy and bind another.

### 1.1 The public-data API

```rust
impl BlockProof {
    pub fn config(&self) -> &VmConfig;
    pub fn shard_counts(&self) -> &[u32];          // one per config family, in its order
    pub fn shard_count(&self, family: u32) -> u32; // 0 for a detached or unreached family
    pub fn statement(&self) -> &PublicInputs;
    pub fn shard_proofs(&self) -> &[ShardProof];   // statement order
    pub fn reconciliation(&self) -> BlockReconciliation;
    pub fn shape(&self) -> Result<(), &'static str>;
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(bytes: &[u8]) -> Result<BlockProof, &'static str>;
}
```

Frozen. S24's occupancy assertions read `config`, `shard_counts` and `shard_count`;
S26's host driver and S27's `aggregate_block` read `shard_proofs` and `reconciliation`.
`shard_count` answers 0 for a family the config detaches rather than panicking, because
an occupancy question about a family this program does not have has an answer.

**A decoded block is well-shaped, so the accessors are total.** `from_bytes` runs
[`shape`](#21-the-structural-rule) before it returns, and `reconciliation` panics on a
block built in memory whose statement and proofs are different shard sets — a caller
error, as `statement_shards` treats counts that are not its config's.

---

## 2. The cross-shard record set

```rust
pub struct ShardRecord {
    pub family: u32,
    pub shard_index: u32,
    pub ts_window: [u64; 2],                 // [ts_start, ts_end)
    pub memory_commitments: Vec<[u8; 64]>,   // the shard's M columns, layout order
    pub roots: [Fr; 2],                      // [read_root, write_root]
}
pub struct BlockReconciliation { pub records: Vec<ShardRecord> }
```

One record per statement shard, in statement order. A record is a **view**: its window
comes from the shard's own `ShardProof` and everything else from the statement, so the
two cannot disagree — there is one copy of each value in a block, and
`reconciliation()` assembles the view from it.

That is the exact layout S27's aggregation guest replays, and its serialization is
frozen (§6).

### 2.1 The structural rule

`BlockProof::shape()`, checked at decode and again by `verify_block`:

- one shard count per family of the block's `VmConfig`;
- the counts' total equal to the number of proofs, of commitment lists and of root
  pairs — computed in `u64` before any list is built from the counts, which are data;
- the proofs naming `statement_shards(config, counts)`, in that order.

Together these are **shard-set exactness**: no duplicate `(family, shard index)`, no
gap and no extra. A family in the `VmConfig` with zero shards this execution is valid
and has no record.

---

## 3. `verify_block`

`verifier::verify_block(vk, proof, public) -> Result<(), VerifyError>` — the one block
verification path, and it composes the one per-shard path. The CLI and every test call
it and nothing else. Checks run in this order, and the first that fails names the class:

| # | class | check |
| --- | --- | --- |
| B1 | `Statement` | the block's `VmConfig` is the key's, and its statement is `public` |
| B2 | — | `derive_global_phase(vk, public)`: steps 1 to 3 of `docs/spec/shard-proof.md` §6 and the global transcript G1–G11, **once for the whole block** |
| B3 | `Statement` | `BlockProof::shape()`, §2.1 |
| B4 | `Statement` | `check_ts_windows` over the records, §4 |
| B5 | `MemoryArgument` | `verify_global_memory(vk, global, public)` — step 10b — **once for the whole block** |
| B6 | per shard | `verify_shard_local(vk, global, shard, public)` — steps 4 to 10a and 11 — then the opening, step 12 |

**B5 is the cross-shard reconciliation, and it is one check, not one per shard.** It
multiplies the read-side roots and the write-side roots across **every** shard of every
family in the statement, `INIT_TEARDOWN` and `ZERO_WINDOWS` included, applies the
boundary factors once, and requires the products equal and nonzero
(`docs/spec/memory.md` §4.2). Every operand is the statement's or the key's — the
boundary, the root list, `vk.entry_pc` and the four memory challenges B2 drew — and no
`ShardProof` is among them, so the answer is a property of the statement and running it
per shard would recompute one boolean `Σ shard_counts` times.

B6 is what ties a *particular* proof to the product B5 read: step 10a holds each
shard's own two roots, which are outputs of its GKR proof, to the statement's entry for
its position. With B3's shard-set exactness above it — one proof per statement shard,
in statement order, no gap and no extra — every root in B5's product belongs to a shard
B6 verified, so the two checks together are what S16's step 10 was for one shard.
Every channel's LogUp root pair is checked per shard, at step 9.

**B1 to B5 verify no shard.** They read the block's shape, its windows and its
statement — never a GKR transition or an opening — so a statement that cannot reconcile
is refused before any shard's circuit is run, where S16's order reached it only after
the first shard's circuit and opening had been checked.

**Nothing is delegated to a prover-side self-check.** `verify_block` reaches every
check through `verifier_core` and `pcs`, and the prover's own assertions are not on
the path.

**Omitting a shard whose cycles ran is caught by B5**, not by B3: a prover that drops a
shard must also drop its count, its commitment list and its root pair and re-prove the
rest — which is what an honest prover would do for the truncated statement, and gives a
block that passes B1 to B4. Its memory events are then missing from one side of the
global multiset, and step 10b answers `MemoryArgument("the statement's roots do not
reconcile")`.

**The single-path rule.** `verify_shard(vk, proof, public)` is
`derive_global_phase`, then `verify_shard_local`, then `verify_global_memory`, then the
opening; `verify_block` is the same three functions with the two statement ones run
once. `reduce_shard` is their composition, so its steps, their order and their classes
are S16's, unchanged — step 11 cannot fail, so 10b after it is 10b in place.

```rust
// crates/verifier-core, #![no_std]
pub struct GlobalChallenges { pub memory: [Fr; 4], pub digest: Fr }
// once per statement
pub fn derive_global_phase(vk: &VerifyingKey, public: &PublicInputs)
    -> Result<GlobalChallenges, VerifyError>;
pub fn verify_global_memory(vk: &VerifyingKey, global: &GlobalChallenges,
                            public: &PublicInputs)
    -> Result<(), VerifyError>;
// once per shard
pub fn verify_shard_local(vk: &VerifyingKey, global: &GlobalChallenges,
                          proof: &ShardProof, public: &PublicInputs)
    -> Result<OpeningClaim, VerifyError>;
```

**`verify_shard_local` alone is not a verification**, and its signature is the warning:
a caller that runs it over every shard and never calls `verify_global_memory` has
checked every circuit and no memory argument, and would accept a block whose shards are
individually perfect and whose multiset does not close. `verify_block` is the in-tree
block verifier and S27's `aggregate_block` is the other; both owe the one call.

S27's leaf/root split is the consumer: a leaf verifies one shard against a digest the
root derived once.

---

## 4. Time windows

Each shard publicly claims `[ts_start, ts_end)` — the slice of the clock its rows
**write in**, from its row-0 pc write to one past its last row's last slot; its rows'
*reads* reach back before it, as a memory read always may. It is carried in the
`ShardProof` and absorbed at S2 of the shard transcript, one typed `SHARD_TS_WINDOW`
message immediately after the seed triple (`docs/spec/shard-proof.md` §4). S16 bound the trivial window,
`[0, 2^38)`; **S20 generalizes the value, not the field or its position**, and the S16
seed is unaltered.

**Step 4** of `docs/spec/shard-proof.md` §6 is now a well-formedness check:
`ts_start <= ts_end <= 2^38`, refused as `Statement("the time window is not [start,
end) in the clock")`. It was "the time window is `[0, 2^38)`".

**`check_ts_windows`** is the block's rule, over the records in statement order:

- **within each cycle-owning family** — `constants::family::CYCLE_OWNING` — every
  window is non-empty, and consecutive shards' windows are ordered and disjoint:
  `ts_end` of shard `i` is at or below `ts_start` of shard `i + 1`. Records of one
  family are consecutive and ascending by shard index in statement order, so checking
  neighbours gives pairwise disjointness over the family by transitivity;
- **a family that owns no cycles is exempt**. Its window is a claim about invocations,
  not a slice of the execution.

**Per family, and never block-wide.** Cycle numbers are global and unique across
families, but two families interleave: `ADD_SUB_LUI_AUIPC` may own cycles 1 and 3 while
`JUMP_BRANCH_SLT` owns 2, so their windows overlap by construction. A block-wide
disjointness rule could never hold for any real execution.

**Which families own cycles.** The seven instruction families do; `INIT_TEARDOWN` and
`ZERO_WINDOWS` do not, their rows being RAM words rather than cycles
(`docs/spec/memory.md` §3). **`KECCAK_F` does not either, and S21 is where that was paid
out**: it appended to `family::CYCLE_OWNING` as `false`, and its shard record carries a
min/max invocation timestamp with no disjointness requirement — per-address ordering is
already carried by the multiset gap checks. **S21 slotted in with zero `verify_block`
changes**, which is what this paragraph promised at S20, and S22 and S23 will do the same.

An invocation rides the cycle of the request that made it, so a delegation shard's window is
a *sub-interval* of the requesting family's and the two overlap by construction —
`crates/prover/tests/keccak.rs` asserts that containment. A block-wide or unscoped rule would
have refused every honest block with a delegation in it.

`CYCLE_OWNING` is a constant beside the family ids and **not** a field of the
`VmConfig`: the config's wire form is absorbed into program identity and into the global
transcript, so a field there would move every program's identity.

### 4.1 What the window does and does not bind

The honest prover's window is read off the shard's own committed `M[0]` cycle column
(§5.3), so on an honest block it is exactly `[4·cycle(row 0), 4·max cycle + 4)`. But
**no gate of any family ties a claimed window to the rows committed under it**: the
owner removed that obligation (decision 2). So:

- `ts_start` and `ts_end` are claims. A prover free to choose them can satisfy §4's
  rule with any ordered, disjoint, non-empty family of windows.
- What the window *is* bound to is the shard transcript: it is absorbed at S2, before
  the witness commitments, so a proof made under one window does not verify under
  another. That is a self-consistency property of a proof, not a statement about the
  trace.
- **Cross-shard ordering, cycle uniqueness and pc continuity are carried by the global
  memory multiset and by nothing else.** `docs/spec/memory.md` §4.2's chain argument
  gives it: at the pc's single address the writes and reads form one path from
  `T(PC, 0, 0, entry_pc)` to `T(PC, 0, t_pc, HALT_PC)` with strictly increasing
  timestamps, every live row of every shard is an edge of it, and no component can be a
  cycle. There is no per-shard pc chaining anywhere in the protocol, and no message tag
  that could carry one.

So the ts-window checks are a check on the **plan**: they say the block's shards
describe an ordered, non-overlapping cut of each cycle-owning family, which is what
S24's occupancy assertions and S27's replay read. They add nothing to soundness. Read
them that way.

---

## 5. Proving a block

```rust
pub fn prove_block(setup: &ProverSetup, archive: &mut TraceArchive, plan: &ShardPlan)
    -> Result<BlockProof, ProverError>;
```

`plan` is the execution's own shard plan, `trace::plan_shards(archive.cycle_profile(),
config)`, and `prove_block` refuses any other as `ProverError::Trace` rather than
silently proving a different shard set. The rest is `advance(setup, archive,
Phase::Final)` and `finish`, so a block is assembled from the archive's own final
section and every phase snapshot is left in `archive`.

`archive` is `&mut` because the phase sections are written into it: that is the stage
prompt's `&TraceArchive` widened by must-be-exact 7, which requires the block-level
snapshots to *be* the archive's phase sections.

**The two RAM window families run no cycles**, so `plan_shards` counts 0 for both. Their
shards are the statement's, not the plan's: exactly one `INIT_TEARDOWN` shard for window
0, and one `ZERO_WINDOWS` shard per window the execution touches
(`docs/spec/memory.md` §3).

### 5.1 The shard cut

Each family's rows are cut in increasing timestamp order into contiguous chunks of
exactly its `VmConfig` height, with shard indices ascending from 0: shard `i` is rows
`[i·h, min((i+1)·h, len))` of the family's trace buffer, which every family fill has
done since S16. The last chunk is padded to full height by the column builders, whose
padding row is 0 in every memory column, `cycle` included — the artifact's canonical
padding row, which contributes the identity to both product trees and switches every
lookup off by its selector.

### 5.2 Parallelism

After the global commit phase closes, the shards are proved with a `rayon` parallel
iterator over the shard list. Each task forks its transcript from the same global state
(`SHARD_SEED [digest, family, index]`), reads its own slice of the archive, builds its
base layer, proves it and drops it — so the shards share no prover state, **the schedule
cannot influence a challenge**, and the peak is one shard trace per worker on top of the
statement's committed memory columns. An indexed parallel `map` collects in order, so
the records are reassembled in statement order whatever the thread count, and the
assembled block is byte-identical for any thread count and any schedule.

This is the block's **only** parallel step above the ones S07 and S13 already have
inside a shard.

### 5.3 The per-shard window the prover claims

For a cycle-owning family, `[4·cycle(row 0), 4·max cycle + 4)`, read off the shard's own
`M[0]` column — the timestamps of the row-0 pc write and one past the last row's last
slot (`docs/spec/execution-trace.md` §1, the clock's four slots, and §3, a query's write
at `4·cycle + Δ`). Reading it from the committed column rather
than from the archive keeps the S16 `prove_shard_columns` signature, and makes the
honest window a function of exactly what the shard commits. For a **delegation** family,
since S21, the same formula over the same `M[0]`, which there is the requesting cycle of each
invocation: `prover`'s `ts_window` is three-way, and a delegation family reads its cycle
column like a cycle-owning one while being exempt from §4's disjointness. For a RAM window
family, the trivial window.

A tampered cycle column is read as its low 64 bits and multiplied saturatingly: the
prover checks nothing (S13), and a window that is not a window is a proof step 4
refuses.

### 5.4 The demo

`guests/shards` (decision 1): a counted loop whose body is 64 unrolled `add`s, 16,384
iterations. `ADD_SUB_LUI_AUIPC` runs 1,064,970 cycles at height `2^20`, so the plan cuts
it into **two shards of one family**; `JUMP_BRANCH_SLT` runs 16,386 in one shard;
`INIT_TEARDOWN` proves one shard at `2^16`; and `ZERO_WINDOWS` proves **none**, because
nothing in the guest touches RAM — which is also the stage's zero-shard family.

A loop and not a straight line because a family's height is both its shard height and
its decoded table's row count, and the table is pc/2-indexed: `2^20` four-byte
instructions is 4 MiB of `.text` and needs a `2^22` table, which is a `2^22` shard,
which is one shard again.

---

## 6. Wire forms

Every integer little-endian, `bytes` a `u32` length then the bytes, `list<T>` a `u32`
count then the items — `docs/spec/shard-proof.md` §9's primitives, which are the one
encoding for every proof-side type. Every decoder is total, reserves nothing an
untrusted count asks for, and refuses trailing bytes.

```text
BlockProof             config bytes (VmConfig::to_bytes)
                       statement bytes (PublicInputs::to_bytes)
                       shards list<bytes>          each a ShardProof::to_bytes
                       — then BlockProof::shape(), so a decoded block is well-shaped

BlockReconciliation    list<ShardRecord>
ShardRecord            family u32, shard_index u32, ts_start u64, ts_end u64,
                       memory_commitments list<G1>, read_root Fr, write_root Fr
```

`ShardRecord`'s field order **is** must-be-exact 9's layout, and it is what S27's
aggregation guest replays.

**Not `postcard` over `serde`.** The stage prompt asks for it; these two types are
written in §9's primitives instead, because `PublicInputs`, `ShardProof` and `VmConfig`
already have exactly one encoding there and a `postcard` container around them would put
two integer conventions in one file — the master's *One encoding* rule. `TraceArchive`
is still `postcard`, as S12 froze it.

---

## 7. The transcript-tape validator

`checker::tape`, `global_tape`, `expected_global_tape` and `check_global_tape`.

A **tape** is one line per typed transcript message, in order: `absorb <TAG> <n>` for a
message of `n` payload field elements — the scalar count, or the 31-byte chunk count of
a bytes message — and `squeeze <TAG>` for a challenge. The transcript's event log
carries a message's tag and payload length and never its values, so a tape is a
statement about the **script** a transcript ran, which is what a frozen absorb order is
about.

`expected_global_tape` writes G1–G11 out from the statement's shape alone — the family
count, the shard counts, the window list, each shard's commitment-list width — and
**shares no code with `verifier_core::global_commit`**: the order is enforced twice, by
independent code, as the laws are (master rule 8). It does call `statement_shards`, the
public helper that defines a statement's *shard* order (§1.2 of
`docs/spec/shard-proof.md`); the *absorb* order — G8's group order and every message's
position and length — it writes itself. `check_global_tape` runs the real
phase and returns its tape, or names the first line at which it left the order.

```
checker tape <verifying-key> <public-inputs>
```

`crates/checker/tests/vectors/global_tape.txt` is the committed tape of S20's two-shard
statement, regenerated by `cargo run -p kat-gen -- tape` and diffed in CI. What it does
**not** check is the values absorbed; what binds those is that the same `global_commit`
produces the digest every shard is seeded with.

---

## 8. What a block does not do

- **No aggregation and no recursion.** A `BlockProof` is verified by running every
  shard's verification. Folding those into one proof is S26 and S27's.
- **No accumulator entries** (§1).
- **Nothing for a delegation family beyond §4's scoping.** S21 added `KECCAK_F` and
  `verify_block` did not change; S22 and S23 append their own families the same way
  (`docs/spec/delegation.md` §10).
- **No binding of fd 0 and fd 1 to the execution.** The public I/O digest is in the
  statement and no row reads it, as at S16; the I/O-binding stage owes it.
