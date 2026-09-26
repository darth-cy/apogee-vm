# `tools/profiler`

## What this crate owns
**Where a guest's RV32 cycles go**, by function and by semantic workload.
`docs/spec/profiling.md` is normative.

It invokes nothing proving-related — no SRS, no key, no circuit, no commitment, nothing in
`crates/prover`, `crates/verifier` or `crates/pcs`. Three inputs and arithmetic: a guest
ELF, the bytes it runs on, and the ELF's own symbol table.

```
cargo run --release -p profiler -- elf <file> [--advice <f>] [--input <f>] [--top <n>] [--json <p>]
cargo run --release -p profiler -- block <fixture> [--top <n>] [--json <p>]
ETH_RPC_URL=… cargo run --release -p profiler -- record <number|latest> [--txs <n>] …
```

`block` reads a recorded fixture under `crates/host/tests/vectors` and touches no network.
`record` is the one verb that reads `ETH_RPC_URL`; its RPC cache is a scratch directory
under `target/` and is never committed, for the reason `crates/host/src/fixture.rs` gives.

## Frozen invariants
- **One histogram over pc, and everything is derived from it.** One `u64` per halfword slot
  of the image, incremented once per executed cycle. A function's cycles are the sum over
  its `[st_value, st_value + st_size)` range; **its calls are the count at its first
  instruction**, because a function's entry executes exactly once per call — so the
  histogram already holds every call count and no shadow stack is needed. A mnemonic's
  cycles are the sum over the slots holding it; a category's are the sum over its
  functions'.
- **The executor is `emulator::StreamingRun`**, which is what makes a whole-block profile
  possible at all: the profiler counts each shard's `pc` column and drops the shard, so its
  memory is the histogram — 8 bytes a halfword, 16 MB at the menu's largest image — plus one
  partial trace buffer per family. `trace_run` over a whole block would need ~520 GB
  (`docs/spec/streaming.md` §1).
- **A delegation family's rows add nothing.** Its rows are invocations, not cycles, and the
  cycle that requested one is already counted by the family that owns the ecall row.
- **The classification rules are ORDERED and the order is the semantics**
  (`src/categories.rs`). First match wins, so the specific rules come before the general:
  `revm_interpreter::instructions::system::keccak256` is hashing and `revm_interpreter::` is
  interpreter overhead, and the only thing that says so is which rule comes first.
  `tests/rules.rs` holds every case to the category it is meant to give **and** refuses a
  rule an earlier rule shadows, which is the failure mode a list like this has.
- **Rules match the demangled path AND the raw mangled name.** A crate and module name
  appears as a literal substring in both mangling schemes, and the v0 decoder is
  deliberately partial, so matching only the decoded path would misclassify a name the
  decoder read badly. It did: `compiler_builtins::mem::memcpy` landed in the core runtime
  until the raw name was matched too, and `serde_core::` matched the `core::` fallback and
  took 13.6% of a mini-block's cycles with it. Both are regressions in `tests/rules.rs`.
- **Both manglings are decoded here** (`src/demangle.rs`), because master anti-goal 6 makes
  `rustc-demangle` an eight-lines-yourself dependency and `guests/revm-block` carries both
  forms — 1,154 legacy and 139 v0. Legacy is decoded completely; v0 is decoded to its
  **identifier run**, which is the path a reader wants and not a complete decoder. The v0
  scanner skips the `s<base-62>_` disambiguator **by name**, because its base-62 digits
  include decimal ones and a left-to-right scan otherwise reads the `7` in `CsxJ7lp9_` as a
  length.
- **A function's cycles include everything the compiler inlined into it**, and the report
  says so. At `opt-level = 3` `ruint`'s `U256` operations are mostly inlined into the EVM
  opcode handler that called them, so "256-bit arithmetic" counts
  `revm_interpreter::instructions::arithmetic::mul` and not `ruint::mul`. That is the right
  unit for "what would an accelerator replace" and a different claim from "cycles inside
  `ruint`". Two things keep it checkable: the **unattributed** share (0.53% on a whole
  block, the symbol table covering 99.997% of `.text`), and the **mnemonic mix**, which no
  symbol table can be wrong about.
- **A candidate's `removable` is a ceiling and is labelled one.** It charges
  `calls · (4 + 2·frame_words)` for the shim that would remain and nothing for the *proving*
  cost of the new family's shards — which is what `docs/spec/delegation.md` §9 and the shard
  count actually decide, a `2^8` family being 256 invocations a shard.
- **No committed output that anything regenerates.** A report goes to
  `docs/handoff/reports/` when a stage records one, as `tools/bench`'s does; nothing diffs
  it and nothing asserts on it.

## Tests
| File | What |
| --- | --- |
| `src/demangle.rs` (unit) | both manglings: a legacy name with its disambiguator dropped and its `$LT$` escapes expanded, an unmangled name unchanged, a v0 name's path, a name that decodes to nothing surviving as itself, and the `CsxJ7lp9_17compiler_builtins3mem6memcpy` that exposed the disambiguator bug |
| `tests/rules.rs` | 26 real symbols, each held to the category it must land in — including the two a mini-block profile exposed; no rule shadowed by an earlier one; every category reachable by some rule |
