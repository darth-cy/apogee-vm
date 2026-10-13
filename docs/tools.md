# Tools

The binaries around the prover and verifier, none on a proof path: `bench` measures components
(§1), `profiler` counts a guest's cycles (§2), a `debug-info` build logs a proving run (§3),
`checker` validates circuits and the global transcript (§4), `artifact-dump` exports a guest's
`ProgramImage` (§5), `verifier` checks a proof from files (§6), `kat-gen` regenerates the
committed fixtures (§7), and a generator outside the workspace is a reference oracle (§8).

## 1. bench

```text
cargo run --release -p bench [-- <routine>...]   every routine, or those named; --list lists them
```

The routines time one component each, over their own data: `fr-arith` (`Fr` against `ark-ff`),
`poly-bind`, `zerocheck-prove`, `zerocheck-verify` and `gkr-prove`. Their numbers are
machine-dependent and internal.

## 2. The cycle profiler

```text
cargo run --release -p profiler -- elf <file> [--advice <f>] [--input <f>] [--top <n>] [--json <path>]
```

`elf` runs any guest over the given input and advice, at the smallest menu height its code fits.
A run prints a table, the `--top` (30) functions in it, and with `--json` writes a
`ProfileReport`; any error exits 2. Its numbers are counts of executed cycles, the same on any
machine.

### 2.1 One histogram over pc

`profiler::profile` adds 1 to one `u64` per halfword slot of the image for each executed cycle,
reading each chunk's `pc` column off `emulator::StreamingRun` and dropping the chunk, so it holds
the histogram and one partial buffer per family. A function's cycles are the sum over its
`[st_value, st_value + st_size)` (`loader::function_symbols`), its own and not its callees'; its
calls are the count at its first instruction, which runs once a call, so code entered only past
its entry shows cycles and no calls. A mnemonic's cycles are the sum over its slots, a category's
over its functions', and the unattributed ones are at slots no symbol covers.

### 2.2 Classification

`tools/profiler/src/categories.rs` puts each function in one of four categories — memory copy,
allocation, the core runtime, and everything else, the guest's own code — by `RULES`, ordered
substring rules where the first match wins, then `FALLBACK_RULES`, the generic runtime paths, each
matched against the demangled path and the raw symbol (`categories::classify`). The order is the
meaning: `compiler_builtins::mem::memcpy` is memory copy because its rule comes before
`compiler_builtins`'. Legacy mangling is decoded whole, v0 to its identifiers.

A function's cycles include what was inlined into it. The unattributed share and the mnemonic mix,
which no symbol table can misattribute, are the checks on attribution.

## 3. The proving debug log

`crates/prover/src/debug.rs` and the prover's log lines exist only with its `debug-info` feature,
the workspace's one cargo feature: off by default, enabling no dependency, changing no proof byte
(`crates/prover/tests/debug_info.rs` proves one statement with the log off and at `deep` and
compares the blocks). Without it `dlog!` and `debug_only!` expand to nothing, so no scan is
compiled into a proving run. `gkr::explain_self_check` is compiled always.

```text
cargo test --release -p prover --features debug-info --test <suite> -- --include-ignored
APOGEE_DEBUG=off | phase | detail | deep [:FAMILY,FAMILY]
```

`APOGEE_DEBUG`, read at each log site, picks the level, case ignored: unset or empty is `phase`,
`none` and `0` also mean `off`, `1` to `3` the other levels. `:FAMILY,…` (names as the log prints
them, or ids) keeps those families at the level and lowers the others one step; lines naming no
family stay. A bad level falls back to `phase`, an unknown family is dropped, and either is
reported once as `apogee ERROR`. Lines go to the raw `io::stderr()` handle, one locked write
each: libtest shows captured `eprintln!` output only for a failed test, and an OOM kill, a hang
or a `SIGINT` loses it.

| level | adds |
| --- | --- |
| `phase` | the identity in full, in `to_bytes` order as the `verifier` CLI takes it; each shard's `take`, and in pass 2 its `proved`; the global digest and memory challenges, on the `apogee commit` line; each shard's `begin h=` … `gkr done` |
| `detail` | each family's circuit inventory; each shard's time window, `g`, `β` and roots; `gkr::self_check` |
| `deep` | each GKR layer's shape and bytes; the top layer's all-zero columns |

**Where a run died.** A `begin` without its `done` names the shard that died (`FAMILY#index`,
`[k/N]` its statement position); a pass-2 `take` without its `proved`, one in flight. `fill#`
is fill order, which picks the failure returned, and `in_flight=` below the bound mid-pass means
the workers wait on the executor. `fill_ms` is the one-thread fill, `ms` a wall clock shared with
the shards in flight. Every shard forks from the `apogee commit` line's values, so two runs that
should agree diverge there or inside a shard.

**`self_check`** recomputes every gate on every row before the backward pass, a second forward
pass ([gkr.md](spec/gkr.md) §5). `gkr::explain_self_check` turns a failure into the row's first
disagreeing gate and every operand's value, a committed column by its artifact name and an inner
one by the relation that wrote it, where a verifier says only `LayerInconsistency { layer }`.

The log's verdicts:

| marker | |
| --- | --- |
| `self_check FAILED` | a gate fails on the prover's own values |
| `ABORTED` | a nonzero exit status: the block proves a failed execution |
| `OUTPUT-LAYOUT-BREAK` | outputs other than 2 + 2·channels: `reduce_shard` and `channel_cones` index channel roots from opposite ends |
| `ALL ZERO` | a top-layer column all zero: a root of 0 |

```console
$ APOGEE_DEBUG=detail <a debug-info run> 2>&1 | tee run.log
$ grep -c 'begin h=' run.log; grep -c 'gkr done' run.log    # unequal: a shard died
$ grep 'begin h=' run.log | tail -1
$ grep -E 'FAIL|ABORTED' run.log
$ grep -E 'LAYOUT-BREAK|ALL ZERO' run.log
```

At `detail` the self-check doubles each shard's forward work; `deep` reads no layer's cells but
the top's.

## 4. checker

```text
cargo run -p checker -- laws <artifact>       Laws 1–4, then the lookup rules (check_laws)
cargo run -p checker -- padding <artifact>    the padding contract (check_padding)
cargo run -p checker -- dump <artifact>       the circuit, readably (checker::dump)
cargo run -p checker -- tape <verifying-key> <public-inputs>
```

An artifact is a `CircuitArtifact` file, decoded for encoding only so that a lawless one reaches
the checks, such as `crates/constraints/tests/vectors/*.bin`. The validators are
[circuits.md](spec/circuits.md) §3's, independent of `constraints`; `padding` omits the
product-tree clause; `dump` prints any decodable artifact.

`tape` loads a key (`verifier::load_verifying_key`) and a `PublicInputs` file, an archive's `.vk`
and `.public`, refuses a statement the key does not describe
(`verifier_core::derive_global_phase`), and runs `checker::check_global_tape`. That renders the
global commit phase's event log a line a message, `absorb <TAG> <n>` (`n` scalars, or a bytes
message's 31-byte chunks) or `squeeze <TAG>`, and holds it to `expected_global_tape`: G1–G9
([proof.md](spec/proof.md) §2) written from the statement's shape, sharing nothing with
`verifier_core::global_commit`. It prints the tape or the first line out
of order, and checks the script, not the values, which the log does not carry. `checker` exits 0
when a check holds or a listing prints, 1 naming the failure, 2 on a usage error.

## 5. artifact-dump

```text
cargo run -p artifact-dump -- <guest.elf> [--out <dir>]
cargo run --release -p artifact-dump -- tables <guest.elf>
```

The first writes `<name>.img`, the ELF's `ProgramImage` in its `postcard` wire form with nothing
around it ([program.md](spec/program.md) §3), and `<name>.img.txt`, a report rendered from the
image read back off those bytes, which must equal the loaded one or nothing is written: segments,
the listing (address, length, encoding, expanded word), `.symtab` names marked as outside the
artifact, and the artifact's and the ELF's SHA-256, which pin bytes and are not the program
identity. `<name>` is the ELF's stem; `--out` defaults to the working directory.

`tables` prints the `VmConfig`, each instruction's pc, `next_pc`, family, mnemonic and decoded
fields, and the program identity, at `ProgramParams::defaults()` ([program.md](spec/program.md)
§8). **UNFINISHED** ([architecture.md](architecture.md) §0): that identity binds none of the
listing it prints.

## 6. The verifier CLI

```text
cargo run --release -p verifier -- <verifying-key> <identity-hex> <public-inputs> <proof>...
cargo run --release -p verifier -- block <verifying-key> <identity-hex> <public-inputs> <block>
```

The key is loaded by `verifier::load_verifying_key` ([proof.md](spec/proof.md) §7) and its
identity must equal `<identity-hex>`, 64 lowercase hex digits of its canonical bytes from a
channel the prover does not control: never the key, the proof or an archive's `.identity`. The
first form verifies each `ShardProof` file with `verify_shard` and requires the files to be the
statement's shards, each once, in any order; the second verifies a `BlockProof` with
`verify_block`, as an archive's `.vk`, `.public` and `.block` ([proof.md](spec/proof.md) §9). Exit
0 when all verifies, 1 naming the first file refused or a wrong shard set, 2 on usage or a
malformed identity. **Every run prints a warning to stderr that a proof which verifies is
UNSOUND**: there is no commitment scheme ([architecture.md](architecture.md) §0).

## 7. kat-gen and the committed fixtures

`cargo run -p kat-gen` regenerates every group, `cargo run -p kat-gen -- <group>` one.
Each file written prints its SHA-256, which the tests reading it pin.

| group | writes | from |
| --- | --- | --- |
| `field`, `poly` | `Fr` arithmetic and multilinear-polynomial vectors | arkworks' `ark-ff` and `ark-poly` |
| `loader`, `isa` | synthetic ELFs, fib's public-I/O record; an RV32IMA corpus, words that must not decode | the pinned toolchain's `llvm-objdump` |
| `program`, `tape` | a mul-free program; `guests/shards`' global tape | `program`; `checker` |
| `gkr`, `memory`, `lookup`, `family` | `CircuitArtifact` files: toy circuits; the three distinct frames, the two RAM-window circuits and the seven execution circuits, at `2^22` | `constraints` |

CI runs every group and the oracle (§8) and fails on any `git diff` in the vector directories.
**No guest ELF is committed**, nor anything derived from one. A guest ELF is not reproducible across
machines, since rustc embeds absolute paths in the panic-location strings of `core` and of crates
outside the guest workspace, which the guest build does not remap, and every guest-sdk edit moves
every guest's bytes. So `guests/` is source only: a suite that runs a guest builds it with
`test_support::guest_elf`, into `target/guests`, and lists it with the pinned toolchain's
`llvm-objdump` and `llvm-nm` as it runs. Two clean builds on one machine agree
(`crates/loader/tests/reproducible.rs`).

## 8. The reference oracle

```text
cargo run --manifest-path tools/transcript-ref/Cargo.toml
```

`tools/transcript-ref` implements [transcript.md](spec/transcript.md) from its text over Plonky3's
Poseidon2 and HorizenLabs `zkhash`'s round constants, pinned by revision, and writes
`crates/transcript/tests/vectors/`: permutation vectors, transcript scripts and `io_digest`
cases. It is its own workspace root because its dependencies enable features, `serde/std` among
them, that cargo's feature unification would carry into the workspace's `no_std` crates; the one
repository crate it links is `tools/test-support`, a seeded RNG, SHA-256 and hex with no
dependencies.
