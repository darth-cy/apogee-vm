# Tools

The binaries around the prover and verifier, none on a proof path: `bench` measures and proves
(§1), `profiler` counts a guest's cycles (§2), a `debug-info` build logs a proving run (§3),
`checker` validates circuits and the global transcript (§4), `artifact-dump` exports a guest's
`ProgramImage` (§5), `verifier` checks a proof from files (§6), `kat-gen` regenerates the
committed fixtures (§7), and two generators outside the workspace are reference oracles (§8).

## 1. bench

```text
cargo run --release -p bench [-- <routine>...]   every routine, or those named; --list lists them
cargo run --release -p bench -- prove <stem> | --stateless <file> [--case <name>]
    [--in-flight <n>] [--out <dir>] [--json <path>] [--hourly-usd <price>] [--toy-srs]
```

The routines time one component each, over their own data: `fr-arith`, `poly-bind`, `msm`,
`mercury`, `mercury-batch`, `zerocheck-prove`, `zerocheck-verify`, `gkr-prove`. `msm`, `mercury`
and `mercury-batch` run over ceremony bases, `assets/ptau/ppot_0080_24.ptau`, and return without
them.

**`prove`** proves a block through `host::prove` ([streaming.md](spec/streaming.md)) and verifies
it (`host::verify`).

- `<stem>` names a recorded block under `crates/host/tests/vectors`: its pin `<stem>.json`, to
  which `<stem>-witness.bin` and `<stem>-journal.bin` are held, names the guest that proves it;
  `mini-block` is committed ([ethereum.md](spec/ethereum.md) §6).
- `--stateless <file>` is one input to `revm-block-stateless`. A `.json` EEST fixture gives its
  `statelessInputBytes` as the advice, unchanged, and its `statelessOutputBytes` as the journal
  the proof must bind, checked by `revm_block::stateless::run` first and on the proof after;
  `--case` picks one input by part of its name. Any other file is the raw input.
- The guest is built at `--release` (`host::fixture::build_revm_guest`), decoded at
  `host::fixture::revm_params` and keyed over `2^22` ceremony powers or, with `--toy-srs`, over
  τ = `0xc0ffee`, cached as `apogee-bench-toy-22.srs` in the temporary directory: the same
  timings, another identity, which the report names.
- `--in-flight` is `max_in_flight`, 8 by default. The verb asserts that the guest exits 0 and the
  block verifies; `--out` then writes the proof archive ([proof.md](spec/proof.md) §9) under the
  stem's or the input file's name.

The printed `BenchReport` (`--json` writes it too) holds the block, identity, SRS, cycles per
gas, shards per family, proof and statement bytes, clocks, peak RSS, cost and hardware. `commit`
and `gkr` are pass 1's and pass 2's wall clocks; `execution`, the executor's time, runs inside
them and is left out of their total; `opening` and `final` are 0; `unattributed` is the rest of
the proving wall clock; `setup` and `verify` are apart. Peak RSS is Linux's `VmHWM`, absent
elsewhere, where `/usr/bin/time -l` gives it. `--hourly-usd` adds the cost,
`price · proving_ms / 3,600,000`, and the cost per Mgas. Any failure exits 1, a wrong journal or
a failed `--out` after the report prints; a usage error exits 2.

The verbs `recurse`, `recurse-node`, `ceremony` and `decide` are
[recursion.md](spec/recursion.md) §8.4–§10's.

## 2. The cycle profiler

```text
cargo run --release -p profiler -- elf <file> [--advice <f>] [--input <f>] [<common>]
cargo run --release -p profiler -- block <stem> [<common>]
cargo run --release -p profiler -- record <number|latest> [--txs <n>] [--cache <dir>] [<common>]
    <common>: [--top <n>] [--json <path>]
```

`elf` runs any guest over the given input and advice, at the smallest menu height its code fits;
`block` runs the revm guest over a recorded fixture; `record` records a block from `ETH_RPC_URL`
(`latest` is the finalized one; every transaction unless `--txs`; cached in
`target/profiler-cache`) and runs `revm-block` over it, its gas the transactions' limits capped
at the block's. A run prints a table, the `--top` (30) functions in it, and with `--json` writes
a `ProfileReport`; any error exits 2. Its numbers are counts of executed cycles, the same on any
machine.

### 2.1 One histogram over pc

`profiler::profile` adds 1 to one `u64` per halfword slot of the image for each executed cycle,
reading each chunk's `pc` column off `emulator::StreamingRun` and dropping the chunk, so it holds
the histogram and one partial buffer per family. Delegation rows add nothing: their requesting
cycle is the `ecall` row's. A function's cycles are the sum over its
`[st_value, st_value + st_size)` (`loader::function_symbols`), its own and not its callees'; its
calls are the count at its first instruction, which runs once a call, so code entered only past
its entry shows cycles and no calls. A mnemonic's cycles are the sum over its slots, a category's
over its functions', and the unattributed ones are at slots no symbol covers.

### 2.2 Classification

`tools/profiler/src/categories.rs` puts each function in one of 14 categories by `RULES`, ordered
substring rules where the first match wins, then `FALLBACK_RULES`, the generic runtime paths,
each matched against the demangled path and the raw symbol (`categories::classify`). The order is
the meaning: `revm_interpreter::instructions::system::keccak256` is hashing because its rule comes
before `revm_interpreter::`'s. Legacy mangling is decoded whole, v0 to its identifiers.

A function's cycles include what was inlined into it: `ruint`'s 256-bit operations count in the
EVM opcode handlers, each a symbol of its own, revm dispatching through a table of function
pointers. The unattributed share and the mnemonic mix, which no symbol table can misattribute,
are the checks on attribution.

### 2.3 Pricing a candidate

```text
removable = max(0, cycles − calls·(4 + 2·frame_words))
```

`cycles` is the category's, `calls` the entry counts of the candidate's named entry symbols, and
`4 + 2·frame_words` (`categories::shim_cycles`) the shim a delegation leaves: the frame's stores,
the `ecall`, the results' loads. `CANDIDATES` prices secp256k1, 256-bit arithmetic, BN254,
SHA-256/RIPEMD-160 and the keccak sponge; one without entry symbols is charged no shim and
flagged. It is a ceiling: it charges nothing for the new family's shards
([delegation.md](spec/delegation.md) §9) or for marshalling operands into a frame.

## 3. The proving debug log

`crates/prover/src/debug.rs` and the prover's log lines exist only with its `debug-info` feature,
the workspace's one cargo feature: off by default, enabling no dependency, changing no proof byte
(`crates/prover/tests/debug_info.rs` proves one statement with the log off and at `deep` and
compares the blocks). Without it `dlog!` and `debug_only!` expand to nothing, so no scan is
compiled into a proving run. `gkr::explain_self_check` is compiled always.

```text
cargo run --release -p bench --features prover/debug-info -- prove ...
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
| `phase` | identity and SRS digest in full, in `to_bytes` order as the `verifier` CLI takes them; each claim's `take` and its `committed` or `proved`; the global digest and memory challenges, on the `apogee commit` line; each shard's `begin h=` … `gkr done` and `open begin` … `open done` |
| `detail` | each family's circuit inventory; each shard's time window, `g`, `β`, roots and opening commitments; `gkr::self_check`; the scans |
| `deep` | each GKR layer's shape and bytes; the top layer's all-zero columns |

**Where a run died.** A `begin` without its `done` names the shard that died (`FAMILY#index`,
`[k/N]` its statement position); a `take` without `committed` or `proved`, one in flight. `fill#`
is fill order, which picks the failure returned, and `in_flight=` below the bound mid-pass means
the workers wait on the executor. `fill_ms` is the one-thread fill, `ms` a wall clock shared with
the shards in flight. Every shard forks from the `apogee commit` line's values, so two runs that
should agree diverge there or inside a shard.

**`self_check`** recomputes every gate on every row before the backward pass, a second forward
pass ([gkr.md](spec/gkr.md) §5). `gkr::explain_self_check` turns a failure into the row's first
disagreeing gate and every operand's value, a committed column by its artifact name and an inner
one by the relation that wrote it, where a verifier says only `LayerInconsistency { layer }`.

**The scans** read each base delegation shard's live rows: invocations against the height, cycle
and frame-base ranges, timestamp gaps, selector and round histograms, and canonicity, a tally for
`POSEIDON2` and `FR_ARITH`, whose `< p` conclusions are gated to the rows that read a value, and
a verdict for `MOD_MUL`'s operands and the values each `EC_ADD` row's group reads
(`debug::ec_add_reads`). On `ADD_SUB_LUI_AUIPC` they count requests per type, which sum to each
delegation family's invocations, and exit rows, one in all. The log's verdicts:

| marker | |
| --- | --- |
| `self_check FAILED` | a gate fails on the prover's own values |
| `NOT CANONICAL` | a frame value at or above its modulus where a gate needs it below |
| `UNBALANCED` | an `EC_ADD` curve whose three groups' counts differ |
| `OVER the` | a timestamp gap beyond 38 bits |
| `NAMES NO MODULUS` | a `MOD_MUL` selector naming no modulus |
| `DISAGREES` | a `SHA256_COMP` frame its rounds do not produce: the fill's refusal, in every build |
| `NOT LOOPING 24 TIMES` | `KECCAK_F` round counts more than 1 apart |
| `ABORTED` | a nonzero exit status: the block proves a failed execution |
| `OUTPUT-LAYOUT-BREAK` | outputs other than 2 + 2·channels: `reduce_shard` and `channel_cones` index channel roots from opposite ends |
| `ALL ZERO` | a top-layer column all zero: a root of 0 |
| `DECLARED BUT NEVER INVOKED` | a delegation shard with no live row |

```console
$ APOGEE_DEBUG=detail <a debug-info run> 2>&1 | tee run.log
$ grep -c 'begin h=' run.log; grep -c 'gkr done' run.log    # unequal: a shard died
$ grep 'begin h=' run.log | tail -1
$ grep -E 'FAIL|NOT CANONICAL|UNBALANCED|OVER the|NAMES NO|DISAGREES|NOT LOOPING|ABORTED' run.log
$ grep -E 'LAYOUT-BREAK|ALL ZERO' run.log
```

At `detail` the self-check doubles each shard's forward work and the scans cost
`O(live rows × frame words)`; `deep` reads no layer's cells but the top's.

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
message's 31-byte chunks) or `squeeze <TAG>`, and holds it to `expected_global_tape`: G1–G11
([proof.md](spec/proof.md) §2) written from the statement's shape, sharing nothing with
`verifier_core::global_commit` but `statement_shards`. It prints the tape or the first line out
of order, and checks the script, not the values, which the log does not carry. `checker` exits 0
when a check holds or a listing prints, 1 naming the failure, 2 on a usage error.

## 5. artifact-dump

```text
cargo run -p artifact-dump -- <guest.elf> [--out <dir>]
cargo run --release -p artifact-dump -- tables <guest.elf> [--ptau <file>]
```

The first writes `<name>.img`, the ELF's `ProgramImage` in its `postcard` wire form with nothing
around it ([program.md](spec/program.md) §3), and `<name>.img.txt`, a report rendered from the
image read back off those bytes, which must equal the loaded one or nothing is written: segments,
the listing (address, length, encoding, expanded word), `.symtab` names marked as outside the
artifact, and the artifact's and the ELF's SHA-256, which pin bytes and are not the program
identity. `<name>` is the ELF's stem; `--out` defaults to the working directory.

`tables` prints the `VmConfig` and each instruction's pc, `next_pc`, family, mnemonic and decoded
fields at `ProgramParams::defaults()`; with `--ptau` it reads `2^22` powers, the largest default
height, and prints the program identity ([program.md](spec/program.md) §8).

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
`verify_block`, as an archive's `.vk`, `.public` and `.block` ([proof.md](spec/proof.md) §9). It
takes no SRS digest, using the key file's ([srs.md](spec/srs.md) §3). Exit 0 when all verifies,
1 naming the first file refused or a wrong shard set, 2 on usage or a malformed identity.

## 7. kat-gen and the committed fixtures

`cargo run -p kat-gen` regenerates the default groups, `cargo run -p kat-gen -- <group>` one.
Each file written prints its SHA-256, which the tests reading it pin.

| group | writes | from |
| --- | --- | --- |
| `field`, `poly`, `curve`, `tower`, `pairing`, `msm`, `srs`, `moduli` | arithmetic, ceremony-point, KZG and `MOD_MUL` modulus vectors | arkworks; `srs`'s points through its own `.ptau` reader |
| `pcs` | G1 absorption limbs; Mercury proofs | arkworks; `pcs` |
| `loader`, `isa` | listings of the committed guest ELFs, synthetic ELFs; an RV32IMA corpus, words that must not decode | the pinned toolchain's `llvm-objdump`, `llvm-nm` |
| `program`, `tape` | program identities, the generic table's commitments; `guests/shards`' global tape | `program`; `checker` |
| `gkr`, `memory`, `lookup`, `family`, `delegation` | `CircuitArtifact` files: toy circuits; the four frames, the two RAM-window circuits and the seven execution circuits, at `2^22`; each base delegation circuit's shape and SHA-256 | `constraints` |
| `revm` | a synthetic block's witness, output commitment and delegated keccak-f frames | native revm, held to the guest |
| opt-in: `block`, `zkevm`, `guests` | `mini-block`, over `ETH_RPC_URL` ([ethereum.md](spec/ethereum.md) §6); `zkevm-subset.json`, cut from the `tests-zkevm` release at `APOGEE_ZKEVM_FIXTURES` only if every pair matches; the guest ELFs, each built twice and compared | |

`srs`, and `program`'s identities and table commitments, need `assets/ptau/ppot_0080_24.ptau`
and are skipped without it. CI runs the default groups and both oracles (§8) and fails on any
`git diff` in the vector directories. A guest ELF is not reproducible across machines, since
rustc embeds absolute paths in the panic-location strings of `core` and of crates outside the
guest workspace and stable Rust cannot remap them; two clean builds on one machine agree. So
`guests` is run by hand on one machine, and CI regenerates only what derives from the ELFs.

## 8. Reference oracles

```text
cargo run --manifest-path tools/transcript-ref/Cargo.toml
cargo run --manifest-path tools/stateless-ref/Cargo.toml
```

`tools/transcript-ref` implements [transcript.md](spec/transcript.md) from its text over Plonky3's
Poseidon2 and HorizenLabs `zkhash`'s round constants, pinned by revision, and writes
`crates/transcript/tests/vectors/`: permutation vectors, transcript scripts and `io_digest`
cases. `tools/stateless-ref` encodes stateless inputs with `eth-act/ere-guests` v0.17.1's
`stateless-validator-common` over `libssz` 0.3.0 and writes `stateless_ref.txt` under
`crates/host/tests/vectors/`: per input, its request's `hash_tree_root` or `reject`. Each is its
own workspace root because its dependencies enable features, `serde/std` among them, that cargo's
feature unification would carry into the workspace's `no_std` crates; the one repository crate
either links is `tools/test-support`, a seeded RNG, SHA-256 and hex with no dependencies.
