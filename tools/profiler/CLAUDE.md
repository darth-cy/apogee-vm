# `tools/profiler`

## What this crate owns
**Where a guest's RV32 cycles go**, by function and by semantic workload.
`docs/spec/profiling.md` is normative.

It proves nothing: no ceremony read, nothing committed, nothing in `crates/prover`.
Three inputs and arithmetic: a guest ELF, the bytes it runs on, and the ELF's own symbol
table. **The recursion verbs are the exception on the input side** (S-RECURSION): the
recursion guest's input is a block proof and its image is built from two key files, so
`leaf` and `base-key` read an archived key — whose load rebuilds each of its circuits from
the registry to compare (`VerifyingKey::check`) — and `leaf` takes each slice's advice from
`host::recursion::leaf`, which verifies the slice natively, runs the leaf's whole
procedure over it and discharges the accumulator with one pairing against the key's
`SrsVerifier` (`crates/host/CLAUDE.md`).

```
cargo run --release -p profiler -- elf <file> [--advice <f>] [--input <f>] [--top <n>] [--json <p>]
cargo run --release -p profiler -- block <fixture> [--top <n>] [--json <p>]
ETH_RPC_URL=… cargo run --release -p profiler -- record <number|latest> [--txs <n>] …
cargo run --release -p profiler -- leaf <dir>/<stem> --shards <from>..<to> [--shards …] [--top <n>] [--json <p>]
cargo run --release -p profiler -- base-key <dir>/<stem>    # writes guests/recursion/base.key
cargo run --release -p profiler -- program-keys             # writes guests/recursion/programs.key
```

`block` reads a recorded fixture under `crates/host/tests/vectors` and touches no network.
`record` is the one verb that reads `ETH_RPC_URL`; its RPC cache is a scratch directory
under `target/` and is never committed, for the reason `crates/host/src/fixture.rs` gives.

## The recursion verbs
S-RECURSION. `docs/spec/recursion.md` §8.1 says what the two key files are and what the
images built from them hold.

- **`leaf` profiles the recursion guest's leaf** over slices of a base block proof that
  `verifier::proof_archive` wrote (`bench prove --out`), one report a slice, and `--json`
  takes one slice. A slice's positions are in statement order: `INIT_TEARDOWN`'s shards,
  then `ZERO_WINDOWS`', then every other family's ascending
  (`verifier_core::statement_shards`). It builds the `leaf` binary at `--release`
  (`host::fixture::build_guest`; the guest has no committed ELF), takes each slice's advice
  from `host::recursion::leaf` over `leaf_image` of the archive's key, and runs it under
  `host::recursion::leaf_params()`, the parameters the leaf is proved at, rather than the
  smallest height that fits. It refuses unless `guests/recursion/base.key` is this
  archive's key: the binary replays the image `build.rs` made from that file, and the
  advice is the guest's only when the host replayed the same words.
- **`base-key <dir>/<stem>` writes `guests/recursion/base.key`**: `BaseKey::of` the
  archive's key — the base program's config and setup counts, its identity, the SRS digest
  and the generic table, without its circuits. The leaf's image is built from it, tapes
  and identity constant both, and the node's takes its SRS digest and table. **Rerun it
  whenever the archive to be recursed is not the file's**: the file moves whenever the
  base program does — its code through its identity, its parameters through its config —
  or the ceremony does, through the SRS digest, and a leaf verifies that one program's
  proofs and no other's. `profiler leaf` and `bench recurse` both compare the two before
  any guest runs, and name this verb when they differ.
- **`program-keys` writes `guests/recursion/programs.key`**: `host::recursion::program_keys`
  over the two recursion binaries it builds — each one's config under `leaf_params()` or
  `node_params()`, and the setup counts that config implies — which the internal node's
  image is built from. **Rerun it when a recursion program's config or setup widths
  change**: an edit to either parameter function, to the families the guest declares, to a
  registry circuit's setup width, or to `CODE_VERSION`. It prints both programs' families
  at their heights and whether the file changed. A config depends on code and parameters
  and not on `.rodata`, so writing the file changes the node's image and not the configs:
  after `changed`, run it again — it rebuilds both binaries over the new file — and it
  prints `unchanged`. `bench recurse` refuses a `programs.key` that is not the two
  binaries' keys.

Both files are committed, and `build.rs` reads them under `rerun-if-changed`, so a rewrite
rebuilds the images on the next guest build. Without `base.key` the guest does not build;
without `programs.key` the node's image is empty and the node binary exits 10.

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
- **The report counts `ZERO_WINDOWS`' shards** (`ram_windows`, S-RECURSION): the
  ordinary-RAM windows the run touched at the config's window height, window 0 aside —
  `trace::init_windows` over the final memory state, the rule the streaming prover plans
  those shards by. No row count carries it, and since guest-sdk's allocator never frees,
  it is what a guest's heap costs a proof. The JSON field is `#[serde(default)]`, so a
  report written before it still reads.
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

The recursion verbs have no suite here: `leaf` and `base-key` need an archived base proof,
and `program-keys` writes a committed file that `bench recurse` holds to the two binaries
before it proves anything.
