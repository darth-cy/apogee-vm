# The cycle profiler: where a guest's cycles go

New at S26 step 2. It is a **measurement tool** and nothing else: it adds no
protocol, reads no SRS, builds no key, and invokes nothing in `crates/prover`,
`crates/verifier` or `crates/pcs`. Three inputs — a guest ELF, the bytes it runs
on, and the ELF's own symbol table — and arithmetic.

| crate | what |
| --- | --- |
| `crates/loader` | `function_symbols`, the `.symtab` reader, and `symbol_names` |
| `crates/emulator` | `StreamingRun`, the executor a whole block fits in |
| `crates/host` | `fixture::build_revm_guest` and `revm_params`; `recorder::record` |
| `tools/profiler` | the histogram, the rules, the candidates and the report |

---

## 1. Why it exists, and what it must answer

S25 measured **61.6 guest cycles per unit of EVM gas** on two ordinary mainnet
contract calls, which put the pinned block at ~1.72 billion cycles. Cutting that
is what S26 step 3 is for, and the only honest way to choose *what* to accelerate
is to measure where the cycles are. The questions, from the stage prompt:

- how many cycles in **256-bit arithmetic**?
- **hashing**, by algorithm?
- **secp256k1** and **BN254**?
- **memory copying**, **RLP**, **trie** work?
- **interpreter / revm dispatch** overhead?
- the **existing delegations** against ordinary RV32 execution?

each with absolute cycles, a percentage of the block, and an estimate of the
**maximum removable** cycles.

---

## 2. How it collects: one histogram over pc

The profiler keeps `Vec<u64>` with one entry per **halfword slot** of the image —
the same `pc/2` indexing `ProgramImage::slots` has — and adds 1 to slot
`(pc − slot_base)/2` for every executed cycle. That is the whole of the
instrumentation. Everything in a report is derived from it:

| what | how |
| --- | --- |
| a function's cycles | the sum over `[st_value, st_value + st_size)` |
| a function's **calls** | the count at its **first instruction** |
| a mnemonic's cycles | the sum over the slots holding that instruction |
| a category's cycles | the sum over its functions' |
| unattributed cycles | the slots no function symbol's range covers |

The call count is the one that is worth naming: **a function's entry instruction
executes exactly once per call**, so the histogram already holds every call count
in the program and no shadow stack, no instrumentation and no second pass is
needed. What it misses is a function entered by a *tail jump* rather than a call,
which shows as cycles with zero calls and is reported as such.

The executor is `emulator::StreamingRun` (`docs/spec/streaming.md`), and that is
what makes a whole-block profile possible: the profiler counts each shard's `pc`
column and drops the shard, so its memory is the histogram — 8 bytes a halfword,
16 MB for the largest image on the height menu — plus one partial trace buffer
per family. `emulator::trace_run` over the same execution would need about 520 GB.

**A delegation family's rows add nothing.** Its rows are invocations, not cycles,
and the cycle that requested one is already counted by the family that owns the
ecall row (`docs/spec/delegation.md` §8).

---

## 3. How it classifies: ordered substring rules

`tools/profiler/src/categories.rs` is an **ordered** list of `(substring,
category)` rules over the demangled path, first match winning, then a second list
of fallback rules for the generic runtime paths. The order is the semantics:
`revm_interpreter::instructions::system::keccak256` is hashing and
`revm_interpreter::` is interpreter overhead, and the only thing that says so is
that one rule comes first.

Rust's two mangling schemes are both decoded, because
`guests/revm-block` carries both — 1,154 legacy `_ZN…E` and 139 v0 `_R…`, the v0
ones being the precompiled sysroot crates. Legacy is decoded completely; v0 is
decoded to its **identifier run**, which is the path a reader wants. Neither
decoder is load-bearing for classification: a crate and module name appears as a
literal ASCII substring in both forms, so a rule would match the raw symbol too.

### 3.1 The inlining caveat, stated rather than hidden

**A function's cycles include everything the compiler inlined into it.** At
`opt-level = 3` `ruint`'s `U256` operations are mostly inlined into the EVM opcode
handler that called them, so "256-bit arithmetic" counts
`revm_interpreter::instructions::arithmetic::mul` and not `ruint::mul`. That is
the *right* unit for this question — what an accelerator would replace is the
opcode's work, not a source-level function — but it is a different claim from
"cycles inside `ruint`", and a reader should not confuse the two.

Two things make the caveat checkable rather than a disclaimer:

- the report prints the **unattributed** share, the cycles at a pc no function
  symbol claims. On `guests/revm-block` the symbol table covers 99.997% of
  `.text`, so that share is small and a large one is a sign the attribution is
  not to be trusted;
- the report prints the **mnemonic mix** beside the categories, which no symbol
  table can be wrong about. A workload the categories call arithmetic-heavy and
  the mix calls load-heavy is a workload to look at again.

The per-**opcode** granularity holds for a reason worth recording: revm's
interpreter dispatches through `[Instruction; 256]`, a table of function
pointers, and taking a function's address forces it out of line. So every EVM
opcode handler is a distinct symbol, and the profile is per-opcode whether or not
anything was inlined into it.

---

## 4. How it prices a candidate

For each candidate accelerator the report gives

```
removable = cycles − calls · (4 + 2 · frame_words)
```

- `cycles` is the category's measured cycles: what the guest would stop
  executing;
- `calls` is the call count of the candidate's **named entry symbols**;
- `4 + 2·frame_words` is the shim that would remain — the frame's stores, the
  ecall, and the results' loads (`docs/spec/delegation.md` §2), one cycle each.

It is a **ceiling**, and it is labelled one. What it leaves out, in both
directions:

- it does not charge the *proving* cost of the new family's shards, which is what
  `docs/spec/delegation.md` §9 and the shard count actually decide. A delegation
  family's height is `2^8`, so 256 invocations is one shard and one `ShardProof`;
  a candidate firing 100,000 times adds ~390 shards, and that is a real cost the
  cycle count says nothing about;
- it does not charge the work a delegation *cannot* remove — marshalling the
  operands into the frame in the shape the circuit reads, which for a
  non-contiguous operand is a copy;
- a candidate with **no** named entry point charges nothing per call and its
  figure is the category's whole cycle count. The report flags those;
- and it prices the delegation the candidate's *entry points* suggest, which need
  not be the delegation anyone builds. S26 is the worked example: the `secp256k1`
  candidate models one call per `ecrecover`, and what S26 built was `MOD_MUL`, one
  call per 256-bit **multiply** inside it — S22's cancellation having ruled out a
  family that verifies a signature. The ceiling was 30.98% to 56.66% of a block;
  the realized saving on the pinned mini-block was 54% of the category and 24.2%
  of the execution (`docs/handoff/S26-cycle.md` §6.2).

**The gap between the ceiling and the realized saving is marshalling, and it is
large enough to be the whole engineering problem.** S26 measured three versions of
the same delegation at 8%, 19% and 24% of a mini-block, differing only in how the
operands reached the frame: an empty-then-fill frame constructor cost a `memset`
and three `memcpy`s a call, and reducing both operands to canonical form cost more
than the reduction the circuit needed. The ecall itself is four instructions. A
reader pricing a candidate from this page should read the ceiling as an upper
bound on a *well-marshalled* delegation and expect to spend the implementation
effort there; §6.3 of that handoff note is the account.

---

## 5. The three verbs

```
profiler elf <file> [--advice <f>] [--input <f>] [--top <n>] [--json <p>]
profiler block <fixture> [--top <n>] [--json <p>]
profiler record <number|latest> [--txs <n>] [--top <n>] [--json <p>] [--cache <d>]
```

`elf` profiles any guest over any bytes. `block` profiles the revm guest over a
**recorded** fixture under `crates/host/tests/vectors` and touches no network.
`record` is the one verb that reads `ETH_RPC_URL`: it records a mainnet block —
all of its transactions by default — and profiles the guest over it. Its RPC
cache is a scratch directory under `target/` and is never committed, for the
reason `crates/host/src/fixture.rs` gives: a whole block's `eth_getProof`
answers would dwarf the fixture directory.

Every number is machine-**independent**: a count of executed cycles on one
image, not a wall clock. Two runs of one verb on one fixture give the same
report.

---

## 6. What it is not

- **Not a wall-clock profiler.** It does not say which cycles are slow to
  *prove*, and proving cost per cycle differs by family: a `MUL_DIV` row and an
  `ADD_SUB_LUI_AUIPC` row are one cycle each and not one cost each. The
  per-family cycle counts in the report are where that difference becomes
  visible, and `docs/spec/metrics.md` is the harness that prices it.
- **Not a call-graph profiler.** It reports self cycles per function, not
  inclusive ones. A helper called from many places is credited to itself, which
  is what a candidate ranking wants; "cycles under `ecrecover` including
  everything it calls" is the category total instead.
- **Not committed output.** A report is written to `docs/handoff/reports/` when a
  stage records one, the same way `tools/bench`'s is; nothing regenerates it and
  nothing diffs it.
