# S26 — Cycle reduction: the streaming prover, the cycle profiler, the `MOD_MUL` delegation

Branch `s26-cycle`. Three steps, and the stage prompt's own order:

1. **A streaming prover** whose peak does not grow with the shard count, so that a block
   too large to archive can be proved at all.
2. **A cycle profiler**, and a profile of real mainnet blocks, to decide what to accelerate
   from measurement rather than from intuition.
3. **The accelerator the profile ranks first** — one, fully, at the owner's instruction —
   checkpointed against the pinned mini-block.

**The one-line result: the pinned mini-block runs in 24.2% fewer guest cycles and publishes
the same 90-byte journal.** Steps 1 and 2 are what chose the accelerator; step 3 is
`MOD_MUL`, and §7 is the cost it turns up that this stage does not spend.

Normative documents written this stage:

- **`docs/spec/streaming.md`** (new): the two passes, what survives an execution and what
  does not, the shard cut a flush makes, the backpressure, and the acceptance.
- **`docs/spec/profiling.md`** (new): the pc histogram, the ordered classification rules,
  the inlining caveat, how a candidate is priced, and why a ceiling is not a prediction.
- **`docs/spec/delegation.md`** §14 (new section): `MOD_MUL`'s frame, its gates, its
  quotient bound and its backend — and §9.1 (new), what a `2^8` height costs in proof bytes.
- **`docs/spec/constraint-manifest.md`** §18 (new section): `MOD_MUL` column by column and
  gate by gate. Observations moved to §19 and the maintenance checklist to §20.
- **`docs/spec/revm-block.md`** §1.6 (new section): the blob gas price is recorded, not
  derived.
- **`guests/vendor/README.md`** (new): what is vendored, which files changed, and why.

---

## 1. Decisions taken with the owner, before any code

| # | Question | Decision |
| --- | --- | --- |
| 1 | Does the streaming prover **replace** `prove_block` or **join** it, and how far does streaming reach — the prover's materialization only, or the executor too? | **Join, whole pipeline.** A new `prove_block_streaming` beside `prove_block`, with a pull-based streaming executor; the archived path keeps phase-snapshot resume, the tamper harness and every committed fixture, and a test holds the two blocks byte-identical. Materialization-only was put and rejected with the numbers: it lifts the commit phase's `O(total shards)` cap and leaves the executor's `O(cycles)` one, and the pinned block's *trace* alone is ~520 GB |
| 2 | S22's cancellation says there will be **no `ecrecover` delegation**. If the profile ranks secp256k1 first, what is in scope for step 3? | **Defer — decide at the step 2 checkpoint**, with the ranked table in hand. §5 is that checkpoint |
| 3 | Step 2 wants "a few latest blocks", and no mainnet endpoint is committed | The owner supplied the mainnet URL again. It never lands in git: the profiler's RPC cache is a scratch directory under `target/` |
| 4 | Step 3 ends on a dev server, and `../apogee-aws` reports no instance | **Authorize provisioning, stopped the moment the run finishes**, with a confirmation immediately before spending |

---

## 2. Step 1 — the streaming prover

`docs/spec/streaming.md` is the design. What it changes is **when a column exists**, and
nothing else: every commitment, every absorption, every challenge and every proof byte is
what `prove_block` would have produced over the same execution.

### 2.1 What it is for, in numbers

| what | per unit | S25's mini-block (24.2M cycles, 37 shards) | the pinned full block (~1.72e9 cycles) |
| --- | --- | --- | --- |
| `statement_inputs`' memory columns, all live at once | ~300 MB a shard | 11 GiB | **500–600 GB** |
| `trace_run`'s family buffers | 177 B a cycle | 4.3 GB | ~305 GB |
| its memory event log | ~128 B a cycle | 3.1 GB | ~220 GB |

The first line is S25's measurement and the reason this stage exists. The second and third
are the struct definitions, and they are why streaming the commit phase alone would not have
been enough: an `r8i.8xlarge` has 256 GB and the *trace* of that block is 520 GB.

The streaming prover holds one **partial** buffer per family (at most `height − 1` rows),
the last-access tables, at most `max_in_flight` filled shards, and the commitments and
proofs — which are the output.

### 2.2 The four pieces

- **`trace::MemoryState`** — the last-access tables split out of `MemoryEventLog`. It is
  what `record` was already maintaining to fill each new query's read side, and it is
  `O(touched addresses)` where the events are `O(cycles)`. Everything a statement needs
  beyond a shard's own rows is a function of exactly it: the register and pc boundary, the
  `ZERO_WINDOWS` shard list, and every RAM or value window's teardown columns.
- **`trace::RowSlice` / `FrameSlice`** — one shard's rows, borrowed. `docs/spec/block-proof.md`
  §5.1's cut as a view, so one fill serves a slice of an archive and a streaming executor's
  fresh chunk alike. The frame column builders now take a `RowSlice` and derive each row's
  events from the row; the window builders take a `MemoryState` and probe per row.
- **`emulator::StreamingRun`** — the pull-based tracer. The caller steps it and every time
  one family's buffer reaches that family's height the buffer is handed over as a
  `ShardChunk` and a fresh one started. The flush is **inside `record`**, not between
  instructions, which matters: a `read` or `write` ecall commits one transfer cycle per word
  it moves, so one instruction can push tens of thousands of rows and a per-instruction
  flush would overshoot a height.
- **`prover::prove_block_streaming`** — the two passes and the backpressure.

### 2.3 Three things worth having in mind

**Pass 1 produces the statement's commitments in statement order without holding the
columns.** A commitment is an MSM and reads no transcript, so *when* it is computed cannot
matter; what is frozen is the order they are **absorbed** in, and pass 1 collects against
`(family, index)` and places into `statement_shards`' order before absorbing anything.
Shards fill in execution order, which is a different order, and the two init families'
shards do not exist until the execution is over.

**Pass 2 does not recommit `M`, and that is stronger than recommitting it.** A shard's
opening builds `cm*` from the statement's commitments — pass 1's — while its polynomial side
is pass 2's columns, so a pass that built different columns produces an opening that **fails
verification**. The prompt's "optional but valuable" recommit-and-assert would cost a second
full commit phase to catch, as a prover panic, exactly what the verifier already catches.

**There are no threads and no channels.** Master anti-goal 7 bans both and the shape needs
neither: the executor runs until the queue holds `max_in_flight` shards, the queue is proved
with one rayon parallel iterator, the executor resumes. Execution is under 1% of a block's
wall clock (S25 measured 4.3 s of 850 s), so the overlap a producer/consumer queue would buy
is not worth a thread.

### 2.4 What the streaming path does not have

**No phase snapshots and no resume**, because the archive's five sections rest on a
post-execution section holding the whole trace — the thing this path exists not to have. A
killed streaming run re-executes. `prove_block` and `TraceArchive` are unchanged and keep
resume, `checker::TamperHarness` and every committed fixture.

### 2.5 What holds it, and where

| # | claim | where | runs in |
| --- | --- | --- | --- |
| 1 | the two column readings — a shard's rows, and the whole event log — agree column for column and row for row, over eight guests including three that make delegation calls | `checker/tests/memory.rs::the_row_reading_and_the_log_reading_of_a_frame_agree` | CI |
| 2 | the `deleg_space` column is the requested family's tag on every live mirror query and zero elsewhere, over both delegation fixtures | `…::the_delegation_space_column_is_the_requested_family` | CI |
| 3 | the streaming executor's chunks are the planned shards, row for row, no chunk longer than its height, indices ascending | `emulator/tests/streaming.rs::the_chunks_are_the_planned_shards_row_for_row` | CI |
| 4 | its final state is the log's, and so are the window list at three heights and the boundary | `…::the_streamed_state_is_the_logs` | CI |
| 5 | **the streamed block is the archived block, byte for byte**, over S16's statement, a delegation statement and S-IO's | `prover/tests/streaming.rs::a1`, `a2`, `a3` | deferred |
| 6 | it does not depend on `max_in_flight` | `…::a4` | deferred |

Claims 1 to 4 are deliberately where the risk is: everything the streaming path does
differently is a column built from rows instead of from events, and a shard cut by a flush
instead of by arithmetic. `checker::memory_columns_from_log` is the old log-reading builder
moved into the checker as an **independent** description, sharing no code with the
production one — the repository's standing idiom for a rule enforced twice.

**An incidental win.** `frame_rows` used to scan the whole event log and allocate a
`vec![None; max cycle + 1]` index, and `advance` did that **three times per shard per
block**. The row-reading builders are `O(height)`.

---

## 3. Step 2 — the cycle profiler

`docs/spec/profiling.md` is the design; `tools/profiler` is the tool.

### 3.1 How it works, in one paragraph

One `u64` per halfword slot of the image, incremented once per executed cycle. A function's
cycles are the sum over its `[st_value, st_value + st_size)` range; **its calls are the
count at its first instruction**, because a function's entry executes exactly once per call —
so the histogram already holds every call count in the program and no shadow stack is
needed. A mnemonic's cycles are the sum over the slots holding it. The executor is
`emulator::StreamingRun`, which is what makes a whole-block profile possible at all: the
profiler counts each shard's `pc` column and drops the shard, so **a whole Ethereum block
profiles in a few minutes and a few hundred megabytes** where `trace_run` would need
~520 GB. Step 1 is what bought step 2.

### 3.2 What it found, and what it did not

The full tables are §4. The headline is that a profile of a whole mainnet block is
dominated by **one workload** and the margin is a factor of three over anything else.

---

## 4. The measurements

Every number below is a count of **executed guest cycles** on one image, machine-independent
by construction. The guest is `guests/revm-block` at `APOGEE_GUEST_PROFILE=release`, which is
the profile it is proven at. The committed reports are `docs/handoff/reports/S26-block-*.json`
and `S26-mini-block-*.json`; nothing diffs them and nothing asserts on them.

### 4.1 What was profiled

Five workloads, chosen so that a conclusion could not be one block's accident.

| label | block | txs | gas | guest cycles | cycles/gas | exit |
| --- | --- | --- | --- | --- | --- | --- |
| mini-block (the pinned fixture) | 26,057,509, first 2 txs | 2 | 392,997 | 23,733,540 | 60.4 | 0 |
| block-26059929 | 26,059,929 | 67 | 17,342,086 | 175,185,282 | 10.1 | 70 |
| block-26059800 | 26,059,800 | 132 | 60,000,000 | 747,689,251 | 12.5 | 70 |
| block-26059700 | 26,059,700 | 450 | 60,000,000 | 1,010,920,000 | 16.8 | 70 |
| block-26059900 | 26,059,900 | 376 | 60,000,000 | 2,075,897,177 | 34.6 | 70 |

**Exit 70 is not a failed execution** and the report says so in words. It is
`EXIT_IO_ERROR` from `guest_sdk::commit`: a whole block's output commitment does not fit the
journal's 1,020 bytes, so the execution runs to completion and only *publishing* fails. Every
cycle counted was run. The pinned mini-block exits 0 and publishes its 90-byte journal, which
is why it and not a whole block is the checkpoint workload.

**Cycles per gas varies by a factor of six** across these four, which is the first thing the
profile says: cost is not gas. A block of 376 transactions at 34.6 cycles/gas and one of 132
at 12.5 differ because of *what* the transactions do, and the mini-block's 60.4 is the
fixed cost of a small block — the witness decode is a constant.

### 4.2 Where the cycles go

Shares of each execution, by semantic workload:

| workload | mini-block | 26059929 | 26059800 | 26059700 | 26059900 |
| --- | --- | --- | --- | --- | --- |
| **secp256k1** | 46.47% | 56.66% | 30.98% | 43.64% | 47.81% |
| **bn254** | — | — | 18.37% | 19.54% | — |
| **256-bit arithmetic** (`ruint`, inlined into the opcodes) | 2.01% | 1.55% | 2.85% | 1.47% | 4.81% |
| **all 256-bit modular arithmetic** | **48.48%** | **58.21%** | **52.19%** | **64.65%** | **52.61%** |
| memory copy (`memcpy`, `memcmp`, `memset`) | 17.51% | 15.84% | 15.20% | 13.51% | 15.18% |
| evm interpreter | 10.38% | 7.85% | 12.03% | 7.21% | 14.67% |
| witness + block setup (`serde`, `postcard`) | 14.32% | 10.53% | 9.90% | 7.74% | 6.98% |
| evm state + journal | 3.94% | 3.40% | 5.41% | 3.67% | 7.15% |
| keccak256 (**already delegated**, this is the sponge plumbing) | 4.45% | 3.36% | 3.97% | 2.45% | 2.55% |
| unattributed | 0.55% | 0.53% | 0.89% | 0.43% | 0.60% |

**The headline is the fourth row.** Total 256-bit modular arithmetic is **48% to 65% across
five independent workloads**, and the split *inside* it moves while the total does not:
26,059,800 is 31% secp256k1 and 18% BN254, 26,059,900 is 48% secp256k1 and no BN254 at all.
That is the measured argument for a **witnessed** modulus rather than a constant one: whatever
a block happens to contain, one circuit covers half of it. A secp256k1-only accelerator would
have left 18% of block 26,059,800 on the table, and a BN254-only one would have done nothing
for 26,059,900.

**Nothing else is close.** The runner-up is memory copy at a steady 15% to 17.5%, and it is
*three* separate things (`memcpy` at 90–130 cycles a call, `memcmp`, `memset`); the third is
the interpreter's own dispatch, which is not a candidate at all — there is no function to
replace.

### 4.3 The one function

The ranking is sharper at function granularity than at workload granularity, and this is the
number step 3 was decided on:

| function | mini-block | 26059929 | 26059800 | 26059700 | 26059900 | cycles/call |
| --- | --- | --- | --- | --- | --- | --- |
| `k256::…::FieldElementImpl::mul` | 30.15% | 36.76% | 20.10% | 28.32% | 31.02% | **1,318** |
| `k256::…::FieldElement::square` | 6.27% | 7.64% | — | 5.89% | 6.45% | **1,167** |
| the two together | **36.42%** | **44.40%** | ~26% | **34.21%** | **37.47%** | |

**1,318 cycles a call, to five significant figures, on every workload.** That is one
`F_p` multiply of secp256k1's base field — the schoolbook 10×26-limb product of
`field_10x26.rs` — and it is where an `ecrecover` spends its time. Two functions, one
operation, a third of a block.

Three things make the attribution checkable rather than a claim. The symbol table covers
99.997% of `.text`, so **unattributed is 0.89%** at worst — and that figure is itself a
category, counted by the same histogram, not an estimate. The **mnemonic mix** is reported
beside the functions and no symbol table can be wrong about it. And a function's cycles
**include everything the compiler inlined into it**, which the report says in its own footer:
at `opt-level = 3` `ruint`'s `U256` operations are mostly inlined into the opcode handler that
called them, so "256-bit arithmetic" counts `revm_interpreter::instructions::arithmetic::mul`
and not `ruint::mul`. That is the right unit for "what would an accelerator replace" and a
different claim from "cycles inside `ruint`".

### 4.4 Two things the profiler itself found

Both were classification bugs, and both are now regressions in `tools/profiler/tests/rules.rs`.

**`serde_core::` contains `core::`**, so the `CoreRuntime` fallback rule swallowed 13.6% of a
mini-block — which is the witness decode, not the runtime. Fixed by putting `serde` and
`postcard` rules *before* the fallbacks. This is the failure mode an ordered rule list has,
and it is why the test refuses a rule an earlier rule shadows.

**The v0 demangler read a disambiguator's digits as a length.** `CsxJ7lp9_17compiler_builtins`
decoded to `xJ7lp9::c_17compiler_builtins3mem6me`, because a `Cs<base-62>_` disambiguator's
base-62 digits include decimal ones. Fixed twice over: the scanner now skips `s<base-62>_`
after an uppercase tag letter, **and** `classify` matches the raw mangled name as well as the
decoded path — a crate name is a literal substring of both manglings, so matching only the
decoded path trusts a deliberately partial decoder.

A third finding was not a bug but a bad name: `Category::Delegated`, "already delegated", was
hiding 4.3% of *un*-delegated keccak sponge plumbing behind a label that read as "nothing to
do here". It is now "delegation shims", the keccak shim is classified as `Keccak`, and
`recursion` is the only rule that lands in it.

---

## 5. The step 2 checkpoint

The prompt defers step 3's target to this point. The table put to the owner was §4.2 and
§4.3; three questions came with it.

| # | Question | Decision |
| --- | --- | --- |
| 1 | The profile ranks secp256k1's field multiply first, and S22's cancellation says there will be **no `ecrecover` delegation**. `MOD_MUL` is not `ecrecover` — it is one arithmetic primitive, not a curve or a signature scheme — but `k256` exposes no hook for it: the field type is private and the multiply is inherent. Route through a shim the guest calls, or **vendor `k256` and patch its field multiply**? | **Vendor `k256`, patch its field mul.** A `[patch.crates-io]` entry plus the crate under `guests/vendor/`, with `FieldElementImpl::mul` and `::square` routed through the delegation. Needs one exemption: `crates/prover/tests/one_feature.rs` reads every `Cargo.toml` in the repository and would refuse a vendored crate's `[features]` table, so `guests/vendor/**` is skipped — and a second test holds that skip to crates `[patch.crates-io]` actually names |
| 2 | Write one accelerator fully, or the top two? | **One, fully, then report.** The top candidate with its whole load — spec page, constraint-manifest entry, fixture guest, tamper twins, deferred suites — then this checkpoint again with the measurement in hand |
| 3 | A whole block still does not *publish*: its output commitment does not fit the journal's 1,020 bytes, and a collapsing trie deletion needs a sibling `eth_getProof` cannot return | **Record it, do not chase it.** S26 lifted the *memory* cap (§2); the journal size and the witness source are S25's two open blockers and stay open. Every checkpoint is on the pinned mini-block |

**What S22's cancellation does and does not rule out.** It ruled out an `ecrecover`
delegation — a circuit that verifies a signature, which means curve arithmetic, a scalar
ladder and a hash inside one family. `MOD_MUL` is the opposite shape: `out = a·b mod m` over
eight 32-bit limbs, 15 limb equations and a borrow chain, with no curve, no group law and no
notion of a signature anywhere in it. It is an *arithmetic* delegation in exactly the sense
`FR_ARITH` is, one field wider. That distinction was put to the owner with the profile and is
the basis of decision 1.

---

## 6. Step 3 — the `MOD_MUL` delegation

`docs/spec/delegation.md` §14 is the circuit and the ABI;
`docs/spec/constraint-manifest.md` §18 is the column-by-column accounting;
`guests/vendor/README.md` is the account of the vendoring. What follows is what changed and
what it cost.

### 6.1 The shape of it

| piece | where |
| --- | --- |
| the constants — family 15, ecall `0x0503`, address space 7, the frame's word layout | `crates/constants/src/lib.rs`, `mod mod_mul` |
| the circuit | `crates/constraints/src/mod_mul.rs`: 132 `M`, 3,346 `W`, 15 layers, 3,493 enforcing gates, **no channel** |
| the executor | `crates/emulator/src/lib.rs`: `mod_mul_frame`, a schoolbook multiply into 16 lanes then a 512-iteration shift-and-subtract division |
| the fill | `crates/prover/src/fill.rs`: `mod_mul`, and `mod_mul_witness`, which derives the quotient and the fourteen carries the execution never recorded |
| the shim | `crates/guest-sdk/src/lib.rs`: `ModMulFrame::of`, `result`, `recursion::mod_mul` |
| the caller | `guests/vendor/k256`, two changed files |
| the fixture guest | `guests/mod-mul-ops`, exit 12 — the same status under both executors |
| the independent reading | `crates/checker/tests/mod_mul.rs`, 11 tests, its own `U256` and its own division |

**One family serves four moduli and that is the design.** `FR_ARITH` multiplies modulo the
circuit's own field, so its multiply is one degree-2 gate — `prod = a·b` over `Fr` *is* the
reduction. A 256-bit modulus cannot work that way, `p` being 254 bits, so this circuit carries
eight 32-bit limbs and proves `a·b = q·m + out, out < m` over the integers. Carrying `m` in
the frame costs eight words, 256 witness bits and one degree on the borrow chain; §4.2 is what
it buys.

**The quotient is the one thing in the row the execution did not produce.** The guest never
computes it, so `fill::mod_mul_witness` derives it by long division and asserts that every
limb position divides, that every carry is in range, and that the last carry is 0. Those are
assertions about the honest prover's own arithmetic; the *circuit* is what says a cheating
prover's carries were right.

### 6.2 The checkpoint measurement

The pinned mini-block, re-recorded first (it needed one new `eth_feeHistory` call for §1.6's
blob gas price) so that both sides of the comparison read the same 135,109-byte witness. The
only difference between the two runs is one line of `guests/Cargo.toml`.

| | baseline | with `MOD_MUL` | delta |
| --- | --- | --- | --- |
| guest cycles | 23,733,540 | **17,986,969** | **−5,746,571, −24.2%** |
| cycles per gas | 60.4 | **45.8** | −24.2% |
| exit status | 0 | 0 | — |
| journal | 90 bytes | 90 bytes | **identical** |
| `secp256k1` share | 46.47% | 28.11% | −18.4 points |
| `MOD_MUL` invocations | 0 | 6,705 | |

Per family, and the shards each count makes at that family's height:

| family | height | baseline cycles | shards | with `MOD_MUL` | shards |
| --- | --- | --- | --- | --- | --- |
| `ADD_SUB_LUI_AUIPC` | `2^20` | 7,363,650 | 8 | 5,108,700 | 5 |
| `JUMP_BRANCH_SLT` | `2^20` | 6,011,546 | 6 | 3,440,974 | 4 |
| `MEM_WORD` | `2^20` | 4,571,172 | 5 | 5,049,585 | 5 |
| `SHIFT_BITWISE` | `2^20` | 2,353,786 | 3 | 2,308,824 | 3 |
| `MEM_SUBWORD` | `2^20` | 1,894,426 | 2 | 1,921,308 | 2 |
| `MUL_DIV` | `2^20` | 1,538,562 | 2 | 157,180 | 1 |
| `ATOMICS` | `2^20` | 398 | 1 | 398 | 1 |
| `KECCAK_F` | `2^8` | 1,080 inv. | 5 | 1,080 inv. | 5 |
| **`MOD_MUL`** | `2^8` | — | — | **6,705 inv.** | **27** |
| cycle-owning subtotal | | | **27** | | **21** |

`MUL_DIV` falling from 1.54M cycles to 157K is worth a note: the software `F_p` multiply is
100 limb products, and `mul`/`mulhu` is what it spends them on. The delegation removes them
along with everything else.

**The journal is byte-identical, and that is the correctness claim that matters.** An
`ecrecover` that returned a wrong address would give a wrong sender, a wrong nonce, a wrong
balance and a different post-state, and the journal is a commitment over exactly that. It is
also the only end-to-end check available: under every executor but this VM's the delegation
ecall answers `-ENOSYS` and upstream's own `mul_inner` runs, so no host test can see the
patched path at all.

### 6.3 What the vendored patch had to get right, and what it cost to get wrong

The first working version removed only **8%**, not 24%, and the profiler is what said why. The
delegation replaces 1,318 cycles of schoolbook multiply with an ecall — and then pays for
marshalling. Three rounds:

| version | mini-block cycles | what changed |
| --- | --- | --- |
| baseline | 23,733,540 | |
| naive | 22,287,603 | `normalize()` both operands always; `ModMulFrame::new()` then `set` |
| frame in one pass | 19,130,826 | `ModMulFrame::of`: an array literal, so no `memset` before the stores |
| cheapest sufficient reduction | **17,986,969** | `packable` first, then `normalize_weak`, then `normalize` |

**`ModMulFrame::new()` followed by `set` was 1.4 million cycles.** The empty constructor
zeroed 32 words and `set`'s three `copy_from_slice`s went to `memcpy`; at 6,705 invocations
that was a quarter of the whole saving, spent writing zeros over values. `of` builds the array
in one literal — 32 stores, no zeroing pass — with five `const` assertions pinning the word
layout the literal spells out.

**Normalizing both operands was another 0.6 million.** The frame's operands are 256 bits and a
magnitude-8 field element reaches `2^259`, so *something* has to reduce. But it does **not**
have to reduce below `p`: the delegation reduces modulo the modulus it is given, and all
`pack` needs is that the value fit 256 bits. `packable` is the 13-cycle test for that, and it
passes on every fully normalized element — which, since the delegated `mul` returns the
canonical residue, is every `mul` result. A chain of multiplies now reduces nothing at all; an
`add` or `negate` result takes `normalize_weak` at about 86 cycles, and only a value whose top
limb lands in `[2^22, 2^23)` after that pays the full 298.

The lesson generalises: **a delegation's cost is the marshalling, not the ecall.** The ecall
itself is four instructions. Every one of the three fixes was found by re-reading the profile
of the accelerated guest, which is the tool step 2 built.

### 6.4 What the fixture guest had to get right, and what the QEMU leg caught

The first `guests/mod-mul-ops` called the delegation by name over secp256k1's `p`, BN254's `r`
and `2^32`, and on this VM it passed. Under `qemu-riscv32` it **exited 250**: the ecall
answered `-ENOSYS` and the guest had no software path, so it took its own error exit. That is
`docs/guest-program-manual.md` §3 rule 6 — a delegation's caller owes a fallback, and a
fixture that only runs on one executor is not one binary on both. `crates/loader/tests/qemu.rs`
is what caught it, and nothing running on this machine could have.

**The fix was to choose moduli whose fallback is one expression**, not to write the fallback
the first design needed. A 256-bit modulus's software path is a 512-bit long division — a
second copy of `emulator::mod_mul_frame` living in a guest, with no way to share code with it
and nothing holding the two equal. A `u64`-sized modulus's is
`(a as u128 * b as u128 % m as u128) as u64`. So the named half now calls `2^32` and
`2^61 - 1`, its expectations are literals rather than a second computation of the same product
(so nothing is vacuous on either executor), and the **third** modulus — secp256k1's `p`, the
one the stage is actually about — crosses the same circuit through the curve half, where the
fallback is upstream's own `mul_inner` and is the same code by construction.

What that moved, rather than lost: the circuit's coverage over 256-bit moduli now lives only
in `crates/checker/tests/mod_mul.rs`, whose honest rows are a secp256k1 product and a BN254
one, and in the emulator's two unit tests. Both run in ordinary CI, where a guest's
deferred-suite coverage does not.

**The curve half had to shrink for an unrelated reason, and the reason is worth knowing.** It
first checked `7G`, `K·G` and `G·(K + 7)` through `ProjectivePoint`'s scalar multiplication,
which made 9,947 invocations and 39.7 million guest cycles — thirty-nine `2^8` `MOD_MUL` shards
and sixteen `2^20` execution ones, which the tamper harness would have proved once per twin.
Shortening the scalar did nothing: **k256's ladder is constant-time, so it is 256 doublings
whatever the scalar's magnitude.** What shrank it was dropping the ladder entirely for plain
`double` and `+`, which exercise `pack` and `unpack` over exactly the same full-width
coordinates — `G`'s own are full width — at 1,227 invocations and 2.1 million cycles. That is
what keeps `checker/tests/tamper.rs`' seventh statement at fifteen shards instead of fifty-five.

### 6.5 The whole-block confirmation

The mini-block is two transactions. Block **26,059,700** is 450 of them and 60 million gas,
and it was profiled both ways with only `guests/Cargo.toml`'s patch line differing:

| | baseline | with `MOD_MUL` | delta |
| --- | --- | --- | --- |
| guest cycles | 1,010,920,000 | **780,490,506** | **−230,429,494, −22.8%** |
| cycles per gas | 16.8 | **13.0** | −22.6% |
| `secp256k1` cycles | 441,152,093 | **202,146,203** | **−54.2%** |
| `bn254` cycles | 197,564,304 | 197,564,304 | **0** |
| `MOD_MUL` invocations | 0 | 268,200 | |

**Three things make this the load-bearing measurement of the stage.** It is 450 transactions
rather than two, so it is not one workload's accident; the **−22.8%** agrees with the
mini-block's −24.2% and the **−54.2%** inside `secp256k1` agrees with its −54% almost exactly;
and **BN254's cycles are identical to the byte** on both sides, which is the internal check
that the accelerator touched the field it was meant to and nothing else.

The invocation count is checkable from the other side too: the baseline's
`FieldElementImpl::mul` ran 217,200 times and `FieldElement::square` 51,000, and
217,200 + 51,000 = **268,200**, which is exactly the `MOD_MUL` invocation count the
accelerated run reports. Every field multiply the block performs became one delegation call
and none was added or lost.

What it also shows is where the *next* accelerator is: with secp256k1 halved, `bn254` is now
the largest single workload on this block at 25.31%, and it is one `ark_ff::Fp::sum_of_products`
at 5,255 cycles a call. `MOD_MUL` already serves BN254's modulus.

Reports: `docs/handoff/reports/S26-block-26059700-baseline.json` and
`…-mod-mul.json`.

---

## 7. The finding step 3 turns up, and the recommendation

**`MOD_MUL` at `2^8` trades five `2^20` execution shards for twenty-seven `2^8` delegation
shards, and that is a bad trade in proof *bytes* even though it is an excellent one in cycles
and in prover memory.**

The arithmetic. A `2^8` delegation shard's proof is dominated by per-layer sumcheck messages
and base claims, which do not shrink with the row count: `KECCAK_F`'s is a measured 11,880,012
bytes for 256 invocations, and `MOD_MUL`'s circuit is 92% of its committed width, so expect
about 11 MB. Twenty-seven of those is **~290 MB of proof** where the five execution shards
removed were about 60 KB each. Prover *work* moves the other way by a wide margin — a `2^20`
add/sub shard's forward pass is on the order of 150 million inner cells against a `2^8`
`MOD_MUL` shard's 69 thousand — so wall clock and peak memory both improve. It is only the
artefact that grows.

**On a whole block it is measured, not extrapolated.** Block 26,059,700 — 450 transactions —
makes **268,200 invocations**, which is **1,048 shards** and about **11 GB** of proof; and it is
not the worst of the four, block 26,059,900's `mul` and `square` call counts putting it at
603,450 invocations, **2,358 shards** and about 25 GB. The mini-block's 27 shards are the small
case.

**And this is not a cost S26 introduces — it is one S26 makes visible.** S25's own bench report
on the same mini-block (`docs/handoff/reports/S25-mini-block.json`) is 37 shards and
**61,323,886 proof bytes**, of which five `2^8` `KECCAK_F` shards account for 59.4 MB: the
existing mini-block proof is already **97% delegation shards**, and the thirty-two execution
and window shards are the remaining 3%. The delegation height was the dominant term in proof
size before `MOD_MUL` existed. What `MOD_MUL` does is take it from 97% of 61 MB to 97% of
350 MB, which is the same ratio and a number large enough to argue about.

**The fix is a taller delegation height, and it is not this stage's to make.** `2^16` is on
the menu, `family_circuit(15, n)` already accepts it, and one `2^16` `MOD_MUL` shard would
hold 65,536 invocations — the mini-block's 6,705 in a single shard, with a base layer around
1–2 GB, which is *less* than a `2^20` execution shard's. But the same argument applies to all
four delegation families, S21 chose `2^8` for `KECCAK_F` with the forward-pass numbers in
hand, and changing one family's height and not the others would make the registry
inconsistent. So: `DEFAULT_HEIGHTS[MOD_MUL]` stays `2^8`, consistent with its three siblings,
and **the height of the delegation families is put to the owner as a decision for the next
stage**, with the numbers above. Nothing in this stage depends on the answer.

Two smaller candidates the profile ranks next, recorded and not taken:

- **BN254**, and it is now the **largest** single workload on an accelerated block: 25.31% of
  26,059,700 with secp256k1 halved, 18.37% of 26,059,800 before it. `MOD_MUL` already serves
  its modulus, so what it needs is the same vendor-and-patch on `ark-ff`'s `Fp256` multiply —
  one `ark_ff::Fp::sum_of_products` at 5,255 cycles a call is 13.83% of that block by itself.
  This is the cheapest remaining win by a distance, because the circuit already exists.
- **`k256`'s scalar field**, 1.03% of block 26,059,929. `Scalar` is already eight 32-bit limbs,
  so the marshalling §6.3 spent three rounds on is free there — `WideScalar::reduce_impl` is
  672 cycles a call and the delegation would be about 100. Small, but the cheapest code change
  in the list.
- **memory copy**, a steady 15–17.5%: `memcpy` at 90–130 cycles a call over 161,697 to
  2,379,110 calls. There is no arithmetic to delegate here; what it wants is a wide-word copy
  instruction or an alignment-aware `memcpy` in the guest, which is a different kind of change.

---

## 8. What holds step 3, and where

| # | claim | where | runs in |
| --- | --- | --- | --- |
| 1 | the circuit's shape is the manifest's, column for column and gate for gate | `checker/tests/mod_mul.rs::the_shape_is_the_manifests`, and `constraints::mod_mul::check_shape` on every build | CI |
| 2 | an honest witness satisfies every gate over three rows — secp256k1, BN254, and `a = 0` — and the all-zero row does too | `…::an_honest_witness_satisfies_every_gate`, `…::the_all_zero_row_satisfies_every_gate` | CI |
| 3 | **`(q − 1, r + m)` is refused by `out_below_modulus` alone** — the forgery that satisfies every limb equation | `…::a_result_not_below_the_modulus_is_refused` | CI |
| 4 | every other single-cell forgery is refused by the one gate named beside it, and every booleanity gate refuses 2 | `…` (10 tests in all) | CI |
| 5 | the executor's arithmetic is `u128`'s on values that fit, and the full-width identity on secp256k1's `p`; a zero modulus is a fatal guest error | `emulator`'s two unit tests | CI |
| 6 | the fill covers the circuit exactly over a **real trace** — which is also the check that `mod_mul_witness` wrote every carry | `prover/tests/fills.rs::the_mod_mul_fill_covers_its_circuit_exactly` | CI |
| 7 | the guest declares `MOD_MUL` and **only** `MOD_MUL`, at both optimisation levels | `program/tests/delegation.rs`, `emulator/tests/guests.rs::mod_mul_ops_invokes_one_family` | CI (the both-levels half `#[ignore]`d) |
| 8 | **the vendored `pack`/`unpack` seam**: `k256`'s group arithmetic reaches the pinned SEC1 encodings of `G`, `2G`, `3G` and `7G` through the delegation, and the ABI reaches four pinned products over two moduli read from the frame | `emulator/tests/guests.rs::mod_mul_ops_checks_itself_under_the_delegation_ecall` | CI |
| 9 | and the same guest reaches the same answers under `qemu-riscv32`, where the ecall answers `-ENOSYS` and upstream's software multiply runs | `loader/tests/qemu.rs` | a Linux host |
| 10 | the streamed execution of that guest is the planned shards, row for row | `emulator/tests/streaming.rs`, at `2^18` — it is the second committed guest needing a taller table | CI |
| 11 | a corrupted result, quotient, carry or rewritten modulus word is refused as `Constraint`, a padding row's gap bit is free, and **the anchor's four twins** are refused per family | `checker/tests/tamper.rs::s26_the_mod_mul_witness_and_anchor_are_pinned` | deferred |
| 12 | the end-to-end answer: the pinned mini-block's 90-byte journal is byte-identical with the delegation and without it | `host/tests/prove.rs` (the mini-block gate), and the profile of §6.2 | deferred |

Claim 8 is the one worth restating: **it is the only test of the vendored patch's change of
base.** A field element is ten 26-bit limbs and the frame carries eight 32-bit ones, and on
every executor but this VM's the ecall answers `-ENOSYS` and upstream's own `mul_inner` runs —
so a host test cannot see the patched path at all. Claim 9 is what makes that a *consistency*
statement rather than a single reading.

---

## 9. The deferred battery

### 9.1 The QEMU legs, in a Linux container

macOS has no `qemu-riscv32` build, so these ran inside the `colima` + `rust:latest` container
`CLAUDE.md` gives the recipe for. **They are what caught §6.4's defect**, and nothing running
natively on this machine could have.

| suite | result | wall |
| --- | --- | --- |
| `loader --test qemu`, `debug` | **15 passed** | 4.65 s |
| `loader --test qemu`, `APOGEE_GUEST_PROFILE=release` | **15 passed** | 5.45 s |
| `emulator --test qemu_outputs` | **3 passed** | 0.23 s |
| `emulator --test consistency`, the QEMU leg | **8 passed** | 34.18 s |

The first two are the ones that matter for this stage: `guests/mod-mul-ops` exits **12** under
`qemu-riscv32`, where the `MOD_MUL` ecall answers `-ENOSYS` and both halves take their software
paths, and 12 under this VM's emulator, where the circuit answers. Same binary, same status,
both optimisation levels.

### 9.2 The proving suites

On this laptop — 18 cores, 48 GB — each suite under `/usr/bin/time -l`, which
`docs/spec/metrics.md` §4.1 names as the repository's ground truth for peak RSS.

| suite | result | wall | peak RSS |
| --- | --- | --- | --- |
| `program --test delegation` (static detachment, both profiles) | **1 passed** | 5.6 s | 0.23 GB |
| **`checker --test tamper s26`** (S26's twins alone) | **1 passed** | 1,056.8 s | 17.2 GB |
| `prover --test recursion` (S23's block) | **2 passed** | 119.5 s | 33.3 GB |
| `prover --test mem` | **1 passed** | 62.4 s | 39.4 GB |
| `prover --test keccak` | **2 passed** | 130.6 s | 39.4 GB |
| **`prover --test streaming`** (S26's) | **4 passed** | 358.4 s | 41.2 GB |
| **`checker --test tamper`** (whole file, seven statements) | **13 passed** | 5,330.0 s | 20.2 GB |
| `prover --features metrics --test metrics` | **12 passed** | 65.5 s | 11.7 GB |
| `emulator --test revm` (against native revm) | **5 passed** | 34.9 s | 0.51 GB |
| `program --test lookup_tables` | **1 passed** | 0.4 s | 0.58 GB |
| `loader --test layout` | **1 passed** | 7.0 s | — |

S26's own two heavy suites are the third and seventh rows, and both are green on
the first attempt: the streamed block is the archived block byte for byte over
three statements, and the `MOD_MUL` twins — the anchor's four forgeries plus a
corrupted result, quotient, carry and rewritten modulus word — are each refused by
the gate named beside them. `checker --test tamper`'s 5,330 s is 1,100 s longer
than S23's measurement, which is the seventh statement's cost.

### 9.3 Suites this stage leaves RED, and why

**Five suites fail, and the owner's instruction is to leave them failing and say
so** rather than repair another stage's tests inside this PR. Each was checked
against `main`: the assertions below are **byte-identical at HEAD** and fail there
too, for reasons S-IO introduced and S26 does not touch.

| suite | what fails | why, and whose |
| --- | --- | --- |
| `checker --test logup` | all 9 tests, on `fib` exiting **101** | S-IO renamed `GuestIo`'s fields and left `guests/fib`'s four input bytes on `input`. fib reads **fd 0** (`read_stdin`, which asserts it got four bytes), so the guest panics. One-line fix, not taken here: swap `stdin` and `input` |
| `verifier --test cli` | both tests, on `" verifies"` counts and `"2 shards"` | S-IO's `PUBLIC_INPUT` and `PUBLIC_OUTPUT` prove one shard each in **every** statement, so `addsub`'s is 4 shards and the CLI prints 5 lines. Three string literals |
| `prover --test block` | 4 of 7, on the config's family list, the record count, a shard count and a twin's padding | the same three families. The twin at line ~300 also needs its padding taken from the *extra shard's own family's* list rather than the last one, or step 3's width check refuses it before the count check it is about |
| `prover --test acceptance` | `a1`, on `cycle_profile().counts` | the same three families, at zero cycles. **S26's own pin in that test was verified separately**: with this assertion patched locally the add/sub proof is 62,580 bytes and the base claim `42 + 36 + 7`, which is what the committed expectation now says |
| `program --test identity` | 1 of 6, on "only `ZERO_WINDOWS` absorbs an empty list" | four families do since S-IO: `ZERO_WINDOWS`, `PUBLIC_INPUT`, `PUBLIC_OUTPUT` and `ADVICE_WINDOWS` |

**Why nobody had seen them.** `docs/handoff/S-IO.md` line 359 still carries an
unfilled `<!-- FILL: the rest of the deferred batch -- logup, acceptance, cli,
control, alu, mem, ... -->`: that batch was never completed, and S25's own run
covered a different subset. Every one of these files is `#[ignore]`d, so
`cargo test --workspace` — which is green at **1,123 passed** — cannot see them.
They are a standing reminder that the deferred battery is only as good as the last
time somebody ran the whole of it.

### 9.4 What S26 itself moved, and where

Six pinned constants moved, all from one cause: `ADD_SUB_LUI_AUIPC` grows one
`is_deleg_15` selector, which is the standing price `docs/spec/delegation.md` §10
names for a delegation type. Each is now commented with **why** it moves, so the
fifth delegation family finds them.

| where | was | now |
| --- | --- | --- |
| `checker/tests/add_sub.rs` | `add_sub.bin` SHA-256 `96012f12…`, 35 `W` names, 62 gate names, `mult(32 + i)` | `e74869e3…`, 36, 65, `mult(33 + i)` |
| `prover/tests/acceptance.rs` | add/sub proof 62,484 bytes, claim `42 + 35 + 7` | **62,580** (+96: one base claim and one witness commitment), `42 + 36 + 7` |
| `prover/tests/control.rs`, `…/alu.rs` | claim `42 + 35 + 7`, setup at 77 | `42 + 36 + 7`, setup at 78 |
| `verifier-core/tests/common/mod.rs`, `…/reduce.rs` | 35 witness commitments on the synthetic proof | 36 |
| `verifier-core/tests/wire.rs` | wire layout's count field 35 and its offset arithmetic | 36 |
| `prover/tests/revm.rs` | the last four families `[KECCAK_F, PI, PO, ADVICE]` | `[PI, PO, ADVICE, MOD_MUL]` — the revm guest declares `MOD_MUL` through the vendored `k256`, and 15 sorts above S-IO's three |
| `program/tests/delegation.rs`, `…/common/mod.rs` | 3 delegation types, 7 declaring guests, `0x503` unanswered | 4, 8, `0x504` unanswered |
| `constants/tests/ecall_abi.rs` | 16 documented ecall constants | 17 |
| `guests/revm-block/src/lib.rs` | `COMMITTED_WITNESS_BYTES` 723 | 725 — the blob-gas-price field, `Some(1)` on the synthetic block |

The last two are not about the selector: the ecall table gained a row, and the
witness gained a field.

### 9.5 The dev-server run: not taken

`prompts/S26-cycle.md` asks for a closing mini-block prover run on a dev server,
and the owner's decision at the close of the stage was to **skip it**: the
mini-block gate already runs here — `host --test prove`, 41.3 GB peak — and what a
32-core box would add is wall-clock and cost figures, which are a benchmarking
question rather than a correctness one. No instance was provisioned and nothing was
spent. `../apogee-aws` reports no instances managed by that repo, which is its
rule 1.

---

## 10. What is open, and what a reader should not assume

- **A whole block still does not publish.** Its output commitment does not fit the journal's
  1,020 bytes, and a collapsing trie deletion needs a sibling `eth_getProof` cannot return
  (`docs/handoff/S25-block.md`). S26 lifted the *memory* cap and neither of those. Exit 70 in
  a profile is that, and the report says so in words.
- **`prove_block_streaming` has no resume.** The archive's five sections rest on a
  post-execution section holding the whole trace, which is the thing the streaming path exists
  not to have. `prove_block` keeps resume, the tamper harness and every committed fixture.
- **The delegation families' height is an open decision**, §7, and the one thing in this stage
  a reviewer should weigh rather than accept.
- **`guests/vendor/k256` is a fork and will drift.** `guests/vendor/README.md` names the two
  changed files and the refresh procedure. It is pinned at 0.13.4 like every other guest
  dependency, for `revm`'s reason: a guest's identity is a digest of its compiled image.
- **The profiler invokes nothing proving-related and has no committed output anything
  diffs.** Its reports under `docs/handoff/reports/` are records, not fixtures.
