# S-RECURSION — recursion: the field memory, the tape verifier, and the tree

One stage, one branch (`s-recursion`, draft PR #38), on the owner's request for the full
recursion scheme. The VM recursively proves verifier programs. Only the leaf converts base
shards. Internal layers never open the PCS: they carry an accumulator, and the last one is
discharged onchain. The request also asked for 4-to-1 fan-in accepting 2 to 4 children,
an orphan carried, an async DAG scheduler with its own `max_in_flight`, a Groth16 wrapper
over the top proof, and an onchain verifier — all "the most succinct yet effective
implementation".

**This note covers the tree**, which is built and proved end to end over the full proof of
devnet block 257,510: every base shard verified, the global transcript run, the memory
argument made, one accumulator left. The Groth16 wrapper and the onchain verifier are
**deferred by the owner** ("Tree first"): finish and optimize the tree, then design the
decider from the measured root. §2.5 is that measurement. `docs/spec/recursion.md` is
normative, and this note cites it rather than restating it.

## 0. The decisions, and who took them

| decision | who | where |
| --- | --- | --- |
| Base proving is frozen: its format, its keys, its `ADD_SUB` | owner | spec §0, §1.2 |
| A leaf adapter folds the base's per-column commitments once; from level 1 up, one stacked recursion format; every node folds | owner | §0, §1.3, §8.3 |
| A field memory, one permutation a row, a handle-based verifier, one `Fq` op a row | owner, the recommended options | §2-§7 |
| `FQ_OP` option A: indirect bucket operands, so a point's MSM work is one static template | owner | §6, §8.3 |
| A recursion request leaves `a0` past its frame, amending `delegation.md` §2's `a0 ← 0` for the recursion types only | owner | §1.4 |
| Two images: a leaf binary with the base tapes and `2^22` windows, a node binary with the recursion tapes and `2^20` windows | owner | §8.1 |
| The decider waits for the measured root ("Tree first") | owner | §9 |
| Fan-in 2-4, an orphan carried; the tree fixed upfront; a node's advice built only when it starts; recursion's own `--in-flight` | the request | §8.4 |
| **A node is a process, not a thread** | mine | §8.4 |
| The leaf's size is a scheduler parameter, 64 base shards by default | mine, from §2 | §8.4 |

**A node is a process** because master anti-goal 7 allows one thread site, the shard
pipeline in `crates/prover/src/streaming.rs`, and a scheduler of node workers would be a
second. A process also gives each node its own memory, which is the request's "no
materialized witness queued" by construction, and it lets a node run on any machine that
shares the output directory. The scheduler starts no thread: it spawns
`bench recurse-node` and polls it.

`prompts/00-master.md` is amended in its workspace layout only, as authorized: `pcs-verify/`
in the crate list and `recursion/` among the guests.

## 1. What was built

- **Two formats, one code path** (§1). A statement is in the recursion format when its
  config holds `FIELD_WINDOWS`, which happens exactly when the program declares a field
  family, so no base key, statement or proof changed a byte. Its shards commit **stacks**
  of up to `2^σ` columns at `n + σ ≤ 24`, opened at `u ‖ r` after `σ` challenges. The base
  format is `σ = 0` of the same code. `constraints::recursion_circuit` is the base registry
  byte for byte, except its `ADD_SUB`, which knows four more delegation types and carries
  `deleg_a0_rule` (§1.4), and except the five families below.
- **The field memory** (§2): address space 10, cells of whole `Fr` elements, zero-initialized
  by `FIELD_WINDOWS` (family 18) at a stride of one cell a row.
- **Four coprocessors on it** (§3-§6):
  - `FR_OP` (19, `2^20`): nine `Fr` operations, `DIGIT` the MSM's digit extraction;
  - `P2_FIELD` (20, `2^18`): one Poseidon2 duplex step;
  - `FIELD_IO` (21, `2^18`): RAM words to a cell and back;
  - `FQ_OP` (22, `2^20`): one BN254 base-field operation over elements of four 64-bit-limb
    cells, lazily reduced, its operands optionally indirect through a digit cell. It is the
    one delegation family that carries `TIMESTAMP`, its height meeting that channel's floor.
- **The tape verifier** (§7). `verifier_core::tape` compiles a shard's checks, per family and
  height, into coprocessor calls over cells: the GKR claim chain, the LogUp roots, the
  Mercury verifier's field side and the transcript. `tape::schedule` merges the calls into
  runs; `tape::run` is the native reading, and its `Memory` refuses an `Fq` element read
  whole that was written apart (§8.3, "Cells").
- **Nodes** (§8.1-§8.3). `verifier_core::node::node` is the one procedure, run by the host
  natively and by the guest through coprocessor calls. The image holds everything static —
  pooled shard tapes, prologues, fold templates, the boundary half, constants — so identity
  binds every tape. The global transcript is a chain across the tree (`verifier_core::chain`).
  A node's journal is 47 cells (§8.2). The fold is two Pippenger MSMs over GLV halves,
  every point one static template (§8.3).
- **The tree** (§8.4): `host::recursion::Tree` plans it, `bench recurse` schedules it, and
  each node is a `bench recurse-node` process.

## 2. What the runs showed

All on the 18-core 48 GB Mac, over `../apogee-stateless-runs/2026-10-03/pipeline-257510-proof`
(207 base shards), one node at a time and one shard in flight inside a node.

### 2.1 The first full tree (commit `10a6ea8`)

Leaves were cut at 32 base shards or 750,000 estimated `FQ_OP` rows, that commit's
defaults, so most covered 19 to 28 base shards and the delegation-heavy tail one to seven.

| nodes | shards | proving | wall | peak RSS |
| --- | --- | --- | --- | --- |
| 14 leaves | 246 | 6,491 s | | |
| 5 internal nodes | 141 | 4,386 s | | |
| the tree | **387** | 10,878 s, plus 403 s building advice | **11,433 s** | **31.2 GB** |

The root covers all 207 shards, its journal requires the two programs' identities, and its
accumulator discharges with one pairing check. Its proof is 33 shards and 1,705,052 bytes.

**A node's cost is mostly fixed.** A leaf over one base shard was 17 shards and 426 s; one
over 28 was 18 shards and 491 s. Every family a node runs costs at least one shard,
however few rows it fills, and a node runs sixteen families: six execution families, four field
families, `FIELD_WINDOWS` and five window families. So a leaf is cheapest large, and 387
shards was 1.87× the base proof's 207.

### 2.2 Where an internal node's cycles went

Node 14, over four 18-shard leaves, was 29 shards: `ADD_SUB` 7, `JUMP_BRANCH_SLT` 4,
`MEM_WORD` 3, `MEM_SUBWORD` 2, `ZERO_WINDOWS` 2, and one of every other family. The
field families filled one shard each, so the RISC-V glue set the node's size. Profiled with
the guest over the same children (`tools/profiler`'s machinery, journal held to native):
**42% of its 12.6M cycles were `memcmp`**. The tape's constant map was keyed by a
constant's 32 bytes, which a guest compares byte by byte. `io_digest` rebuilt its thirty
`2^(8k)` units for every 31-byte chunk of a child's journal, and the journal cells rebuilt
their seven `2^(32i)` units for every cell.

Keyed by words, with those units made once (`d5a41b1`), the same node is **5,145,340
cycles where it was 12,635,926**, and `MEM_SUBWORD` 15,127 where it was 1,883,672. A leaf
over shards 0..28 is 3,368,608 where it was 3,742,482.

### 2.3 Big leaves, with the glue fixed

64-shard leaves (the default since `684fd26`), fan-in 4, at `76eee99`:

TBD

### 2.4 What a node still spends, and the next lever

**The ecalls are now most of the RISC-V work.** Every coprocessor call is one `ecall`, and an
`ecall` is an `ADD_SUB` row. The leaf over base shards 0..64 runs 6,920,108 cycles and makes
2,622,456 field calls — `FQ_OP` 1,679,764, `FR_OP` 661,782, `FIELD_IO` 164,204, `P2_FIELD`
116,706 — so 2.62M of its 4.17M `ADD_SUB` rows are ecalls: four of its 21 shards, against
two for `FQ_OP`. `MEM_WORD`'s 1.57M rows are its other two-shard family. A
request that covered a run of frames would cut that by the run's length, but it is a
change to the delegation ABI's one-request-one-invocation pairing, and it is not made here.

`MEM_SUBWORD` (15-20k cycles a node) and `MUL_DIV` (about 550, `Vec` growth's size
multiply) each still cost a whole `2^20` shard a node. Getting both to zero is a refactor
across every guest-side path (`BTreeMap`'s `u16` fields, `VmConfig::from_bytes`, byte
journals, a slice's end pointer), and nothing would hold it at zero but a proving run. It
is costed here and not done.

### 2.5 The root, for the decider

Run 1's root carries **532 Mercury proof points** across its 33 shards (12 a shard plus its
stacks), **54 setup commitments** and the journal's `(A, B)`. The decider must check those
openings or fold those points. §2.3's root is the one to design against.

## 3. Amendments, each the owner's

- **`prompts/00-master.md`**, three places:
  - the workspace layout gains `pcs-verify/` and `recursion/`;
  - the proof-shape bullet is amended inline: recursion **combines**. Each node folds every
    deferred check it verifies into one `(A, B)` and journals it, and the final verifier
    discharges one pairing check. `AccumulatorEntry` stays a base proof's form;
  - the workspace layout's `constants/` line loses "zero logic".
- **`docs/spec/delegation.md` §2's `a0 ← 0`** holds for the base types only. A recursion
  request advances `a0` (spec §1.4).
- **The rule that no delegation family may carry `TIMESTAMP` is withdrawn**, "no longer a
  hard invariant". `FQ_OP` carries it at `2^20`. What stays is the fact behind it: a family
  below `2^20` cannot hold the channel's table. Withdrawn in `docs/spec/delegation.md` §9 and
  §10.3, `docs/spec/lookup.md` §3, `docs/GLOSSARY.md`, the constraint manifest and the root
  `CLAUDE.md`.
- **`crates/constants`' "zero logic, forever" is withdrawn** as too restrictive. A
  `const fn` that derives a value from frozen constants belongs there:
  `delegation::a0_after`, and `ec_add`'s and `mod_mul`'s helpers.

## 4. The frozen API

Each crate's `CLAUDE.md` holds its signatures. The surfaces a later stage builds on:

- `verifier_core::{tape, chain, fold, node}`, and `VmConfig::{is_recursion, stack_vars,
  circuit}`;
- `constraints::recursion_circuit`;
- `host::recursion`'s `leaf`, `internal`, `Tree`, `program_keys`;
- `guest_sdk::recursion`'s four field calls, `replay`, `import`, `import_run`;
- `bench recurse` and `recurse-node`; `profiler leaf`, `base-key`, `program-keys`.

The node journal (§8.2) is what the decider reads.

## 5. Tests

**In `cargo test --workspace`:**

- `verifier-core`'s unit tests: the tape's schedule, encoding and element rule; the chain
  against the global transcript, the public windows and step 10b; the GLV split; a node
  image read back.
- `host`'s `Tree::plan` test, and `tests/msm.rs`: the fold's MSM against `curve::msm`, `φ`
  against `λ`, and the offsets' points.
- `constraints/tests/recursion.rs`: the recursion registry against the base, and every
  recursion circuit pinned by digest (`tests/vectors/recursion.txt`, regenerated by
  `kat-gen -- recursion`).
- `checker/tests/recursion.rs`: every field family's rows from `guests/field-ops`' trace,
  the field memory's balance, and the recursion `ADD_SUB`.
- `checker/tests/add_sub.rs`'s `a0` rule.
- `pcs-verify/tests/tape.rs` and the `gkr` suites: the tape's GKR and Mercury halves against
  the native verifier.

TBD: the negative controls.

**Deferred**: `crates/prover/tests/field_ops.rs`, `guests/field-ops` proved in the
recursion format. It could not have run before `a980fd6`: `FQ_OP` sat below its floor.

**By hand**: `bench recurse` over an archived base proof is the end-to-end test, and every
node of it holds its proved journal to the native run. `profiler leaf` runs a leaf's guest
without proving. Neither runs in CI: both need a base proof archive.

## 6. What this stage owes

- **The decider**: the Groth16 wrapper and the onchain verifier, designed from §2.5.
- **The deferred suites**, in one batch at the end of the progression, `field_ops` first.
- **The per-node waste** of §2.4, if the measured root says it is worth a refactor.
- **`crates/loader/tests/vectors/field-ops.elf`** predates `d5a41b1`'s word-typed records.
  Its record bytes are the same and only its loads differ, so it is refreshed with the next
  `kat-gen -- guests`.
- **Untested paths**:
  - a field window above window 0;
  - `check_memory_windows`' cell bound;
  - `node::node` itself, which only `bench recurse` and `profiler leaf` run;
  - an `FQ_OP` row with a nonzero carry or an indirect operand in CI.
