# S-STREAM — the sixteen-kilobyte journal, and streaming as the only proving path

**This stage takes no number**, the same reading as `S-IO`, `S-NATIVE-IO`, `S-DEBUG` and
`S-BATCH`. It is not one of the original twenty-seven. It is the stage that clears the two
things standing between this repository and a full Ethereum block, and the owner's
instruction that opened it named them together:

> Increase the guest journal size. Make it canonical that from now on **only the streaming
> prover path is allowed** — the archive prover path is not to be run, and everything is
> tested through streaming. The only thing archived after base proving is **the proof
> itself**, for recursion development; otherwise no archiving during proving.

Two changes, taken in one stage because each is a precondition of the other: a full block
needs a journal that fits it, and it needs a prover whose peak does not grow with its
shard count.

---

## 0. The decisions, and who took them

Every one of these is the owner's, taken before the code was written.

| # | Decision | Alternative rejected |
| --- | --- | --- |
| 1 | `PUBLIC_WINDOW_HEIGHT` = `2^12`, symmetric, origins `0x8000` / `0xC000` | `2^10` (4,092 bytes), which still exits 70 on most real blocks |
| 2 | The full-block target is **`revm-block-stateless`**, whose journal is a fixed 148 bytes. `docs/spec/revm-block.md` §2 stays frozen | growing the window *and* amending §2 to a digest |
| 3 | The archived path is **retained and never run**, not deleted | deleting `prove_block`, which would take `checker::TamperHarness` with it |
| 4 | The proof bundle is a host/verifier API plus `bench prove --out <dir>` | the `BlockProof` bytes alone; a new container format |
| 5 | `prompts/00-master.md` amended in four places (§7 below) | — |
| 6 | **`prover/metrics` is retired**, not ported | porting it to a `prove_block_streaming_metered` |
| 7 | The streamed-equals-archived oracle is **dropped**, with the loss stated and nothing written to replace it | committing a proof digest per `ShardRows` arm |

---

## 1. The journal: `2^12` is the geometric ceiling

`constants::family::PUBLIC_WINDOW_HEIGHT` went `1 << 8` → **`1 << 12`**, and
`constants::guest_memory::PUBLIC_OUTPUT_ORIGIN` went `0x8400` → **`0xC000`**.
`HEIGHT_MENU` gained `1 << 12` at index 1.

```
            before (2^8)                          after (2^12)

  [0x0000, 0x8000)  hole              [0x0000, 0x8000)  hole
  [0x8000, 0x8400)  PUBLIC_INPUT  w32 [0x8000, 0xC000)  PUBLIC_INPUT   w2
  [0x8400, 0x8800)  PUBLIC_OUTPUT w33 [0xC000, 0x10000) PUBLIC_OUTPUT  w3
  [0x8800, 0x10000) hole                             (no gap: flush)
  [0x10000, …)      RAM_ORIGIN        [0x10000, …)     RAM_ORIGIN

  payload 1,020 B each                payload 16,380 B each
```

**Why `2^12` and not more.** A window's first address is `4·h·w`, so the height is what
places the windows, and both must sit in the hole `[0, RAM_ORIGIN)` — 64 KiB — that no RAM
window family initializes. Two windows of `2^14` need 128 KiB. The one `2^14` window that
*does* fit is window 0, and window 0 initializes address 0, so a null dereference would
balance. There is no step above `2^12` without moving `RAM_ORIGIN`, which would move every
program's load address and eat into every decoded table's pc reach — and
`guests/revm-block`'s release image already uses 82% of the `2^20` reach.

**What the old height cost.** `docs/spec/revm-block.md` §2's journal is
`13·N + Σ output_len + 64`, so 1,020 bytes overflowed above **73** transactions with empty
return data, and `guest_sdk::commit` exits 70 rather than truncating. Every real mainnet
block runs 97–515 transactions, and all three full-transaction-set profiles in
`../apogee-miniblock-report-2026-10-01.md` §5.1 exit 70 with a 0-byte journal.
16,380 bytes reaches **1,255** transactions at zero return data and **~362** at that
report's measured 45 B/tx.

**It is headroom and not a bound, and this must not be mis-read.** A record's `output` is
the transaction's return data taken verbatim under a `u32` length, so one maximum-size
top-level `CREATE` is 24,589 bytes in a single record and overflows `2^12` on its own. Only
a fixed-width record makes the journal a function of the transaction count — which is what
`revm-block-stateless` already does, in 148 bytes, by digesting the per-transaction stream,
and which `docs/spec/public-values.md` §9 and `docs/spec/revm-block.md` §2 both recommended
before this stage existed. **Decision 2 is therefore the one that actually unblocks a full
block**; the window growth is what stops the mini guest hitting a wall on the way there.

### 1.1 What did *not* move

- **No gate changed.** `value_window_artifact` and `zero_window_artifact` pass `trace_vars`
  only to `assemble`, so a height adds halving layers and moves no relation — the same
  conclusion `a_height_moves_only_the_halving_layers` states for the delegation families.
- **`verifier_core::window_height`'s floor.** It requires `4h ≥ public_end`, now `0x10000`,
  so `h ≥ 2^14` and the smallest menu entry that qualifies is still `2^16`.
  `crates/checker/tests/public_values.rs` now asserts that over the *whole* menu rather
  than for `2^16` alone.
- **`trace::addressable`.** It is `addr − PUBLIC_INPUT_ORIGIN < 2 · PUBLIC_WINDOW_BYTES`,
  which is exactly the new pair. It hard-codes **adjacency**, which this placement
  preserves; any asymmetric placement would have to rewrite it.
- **`guest-sdk` and `link.ld`.** Every I/O accessor reads the constants, and `link.ld`'s
  only memory statement is the `RAM` region. No linker symbol names the three regions.

### 1.2 The three things it does cost

1. **Step 10c is sixteen times the work**: two 4,096-point multilinear evaluations rather
   than two 256-point, ≈8,190 `Fr` multiplies and ~163 KiB of scratch per statement. Noise
   on a native verifier. There is **no recursion guest today** — nothing links
   `verifier-core` or `gkr-verify` into a guest — so this is a budget being spent before
   anyone has priced it, which is exactly the reason the old doc comment gave for the pin.
   Recorded here so the stage that writes the recursion guest meets it as a known number
   and not a surprise.
2. **The upper hole is gone.** `addressable` widens from `[0x8000, 0x8800)` to
   `[0x8000, 0x10000)`, so 30 KiB that was a loud executor error is now ordinary provable
   address space. The null page `[0, 0x8000)` is untouched, and that is where the soundness
   argument lives. The two tests that asserted the *upper* hole now assert the geometry
   instead — `end == RAM_ORIGIN` — which is strictly more informative: it is the equality
   that makes `2^12` the ceiling, and a later constant change that broke it is refused.
3. **Every program identity moved**, with no ELF change, because `absorb_vm_config` pushes
   every family's height. §8 has the fixture consequences.

### 1.3 The new menu entry

`2^12` is takeable by no execution family (`TIMESTAMP` needs 19 variables) and by no window
family (the floor above). It widens what a key may declare for the three channel-free
delegation families — `POSEIDON2`, `FR_ARITH`, `SHA256_COMP` — which is benign and was
bought for nothing. The menu's **third** entry is now the smallest instruction-table
height; `crates/program/tests/common/mod.rs::smallest` and `tools/kat-gen/src/program.rs`
assert that by name rather than by index, which is why both failed loudly and correctly.

---

## 2. Streaming is the only proving path

`prover::prove_block_streaming` proves every block and every statement in the repository.
`host::prove` calls it; `bench prove` calls it; every suite calls it.

**`prove_block`, `advance`, `finish`, the phase snapshots and the five section codecs are
retained and compile, and nothing proves through them.** They were not deleted, and the
reason is one fact: `checker::TamperHarness` writes a cell into a shard's columns and
re-proves **that one shard**, and the streaming path has no seam for it. Pass 1 commits the
memory columns and pass 2 re-executes, so a tamper applied in one pass contradicts the
other's commitments; there is no point in the two-pass design where a per-shard mutation
hook could sit and still produce a coherent block. The root `CLAUDE.md` says the harness is
not optional — `crates/host/tests/prove.rs`'s advice twin is built on it and runs in the
default workspace suite — so deleting the archived path would have cost a currently-run
soundness test to buy a tidier tree.

What the harness actually depends on is **not** `prove_block`. It is
`prover::{statement_inputs, global_commit_phase, shard_columns, prove_shard,
prove_shard_columns}` plus the `TraceArchive` type, all of which are path-neutral and all
of which stay. That is the line the rule draws.

### 2.1 The rule, and what enforces it

`crates/prover/tests/one_proving_path.rs`, in the default workspace suite, reads every
`.rs` file in the repository and fails on anything outside `crates/prover/src` that

- calls `prove_block(`, or
- names `advance`, `finish` or `prove_block` in a `use prover::…` list.

It explicitly does **not** forbid the per-shard component above, nor holding a
`TraceArchive`: holding an execution is not proving from one. Its second test asserts
`prove_block` is still *there*, so a later stage that deletes it has to delete the test and
say why. The shape is `tests/one_feature.rs`'s, deliberately — the property is about the
whole repository, so the test reads the whole repository.

### 2.2 What each suite became

| Suite | Before | After |
| --- | --- | --- |
| `acceptance`, `control`, `alu`, `mem` | `advance(…, Final)` + `finish` | `common::streamed_shards`; the archive is still built and read **only** for the memory log's self-check |
| `block` | `prove_block` ×4 | `common::streamed`; the archive survives for `a7`'s column build and the cycle profile |
| `public_io`, `recursion`, `keccak` | `plan_shards` + `prove_block` | `common::streamed`; archives kept where a test asserts on the execution |
| `revm` | `revm_archive` ×2 | **no archive at all** — shard counts read off `block.statement().shard_counts`, exit status off `statement().exit_status` |
| `verifier/tests/cli` | `advance` + `finish`, `prove_block` | `common::streamed_shards` / `common::streamed`, and its four files now come from `verifier::proof_archive::write_proof` |
| `debug_info` | `prove_block` twice | `prove_block_streaming` twice |
| `streaming` | streamed == archived, ×3 arms | `max_in_flight` independence over two statements |
| `block::a10`, `acceptance::a9` | resume, byte-identical | **deleted** — resume is gone |

`crates/prover/tests/revm.rs` dropping its archive is the one with a real resource
consequence: that statement is a ~30M-cycle execution whose trace alone is hundreds of
megabytes, and the suite no longer materializes it.

`tests/common/mod.rs` grew four helpers — `IN_FLIGHT` (4), `empty_io`, `public_io_io`,
`streamed`, `streamed_shards` — so no suite spells the proving call itself.

### 2.3 Three coverage losses, recorded

1. **Resume.** `block::a10` and `acceptance::a9` proved that a statement killed at a phase
   boundary and resumed finishes to the same bytes. Resume no longer exists as a capability
   anything uses, and master rule 9 is withdrawn (§7). Nothing replaces them and nothing
   should: a killed streaming run re-executes, and execution is under 1% of a block's wall
   clock.
2. **"Two independent constructions agree."** `streaming.rs`'s former `a1`–`a3` held the
   streamed block to `prove_block`'s byte for byte over the three `ShardRows` arms. That
   test *ran the archived path*, so it could not survive the rule. The owner chose to drop
   it rather than pin committed proof digests, with the loss stated. **A change that moved
   the prover and the verifier together would now pass.** What is left:
   `verify_block` on every proved statement; `crates/emulator/tests/streaming.rs` (the
   executor's chunks against `trace_run`'s buffers, row for row, over twelve guests);
   `crates/checker/tests/memory.rs`' two-reading comparison over seven guests; and
   `tests/block.rs`'s `a7`, which rebuilds the global commit phase **from a `TraceArchive`**
   and asserts its digest is the **streamed** block's first shard's — the one surviving
   place where an archived construction and a streamed one are held to the same bytes, and
   it costs no extra proof. The three `ShardRows` arms are each still proved and verified,
   by the suites that are about them.
3. **The metrics harness.** §4.

### 2.4 What the suites' `max_in_flight` is

`common::IN_FLIGHT = 4` for the prover suites and `crates/host/tests/prove.rs`;
`bench prove --in-flight` defaults to **8**. The split is deliberate: a deferred suite is
run for its verdict and not its wall clock, and the prior report measured four in flight at
77.10 GiB against eight at 83.91 on a 51-shard statement — 6.8 GiB for 214 s. A benchmark
wants the time; a suite wants the headroom.

---

## 3. The proof is the only thing a proving run archives

`crates/verifier/src/proof_archive.rs`, re-exported as `host::proof_archive`:

```rust
pub struct ProofPaths { pub vk: PathBuf, pub identity: PathBuf,
                        pub public: PathBuf, pub block: PathBuf }
pub fn identity_hex(vk: &VerifyingKey) -> String;
pub fn write_proof(dir: &Path, stem: &str, vk: &VerifyingKey, block: &BlockProof)
    -> Result<ProofPaths, String>;
pub fn read_proof(dir: &Path, stem: &str)
    -> Result<(VerifyingKey, [u8; 32], PublicInputs, BlockProof), String>;
```

Four files, each the bare `to_bytes()` payload with no header and no framing of its own:
`<stem>.vk`, `<stem>.identity` (64 lowercase hex digits and a newline), `<stem>.public`,
`<stem>.block`. That is **exactly** what `verifier block <vk> <identity> <public> <block>`
reads, in that argument order, so a written directory is verifiable from a shell with no
glue.

Three choices worth recording:

- **It lives in `crates/verifier`, not `crates/host`.** The format's *reader* is the CLI,
  so the writer sits beside the reader and there is one definition of it.
  `crates/verifier/tests/cli.rs` now writes its files through it in place of a local
  closure — which is what stops the two drifting — and `host::proof_archive` is a
  re-export, so the host SDK's users find it where they expect. Putting it in `host` would
  have needed a `host` dev-dependency on `verifier`, pulling revm and arkworks into
  `cargo test -p verifier`'s dev graph for a file-writing helper.
- **`<stem>.public` is redundant and is written anyway.** `BlockProof::to_bytes` already
  carries the statement, but the CLI takes it as a separate argument, and a directory that
  is not CLI-ready is a directory someone has to write a script for.
- **`read_proof` goes through `load_verifying_key`**, the loader with the load rules, not
  `VerifyingKey::from_bytes`, which checks encoding only. It does **not** compare the
  identity file against the key's: a key recomputes its own identity, so it is not its own
  authority for it, and the comparison belongs to a caller holding a value from a channel
  the prover does not control.

`bench prove --out <dir>` calls it **after** `host::verify` succeeds. A proof that does not
verify is not worth a reader's disk, and a reader is the point.

**Nothing writes a `TraceArchive` to disk, and nothing ever did** — the export/import pair
exists for `crates/emulator/tests/archive.rs`'s wire-form round-trip and for the deleted
resume tests, and the first of those is unaffected.

---

## 4. `prover/metrics` is retired

Granted at S20 as the first of the workspace's two cargo features, it sized every committed
column and every forward-pass layer and threaded a `&mut Recorder` through every entry
point. It was **archived-path-only**: five of its seven metered entry points took a
`&TraceArchive`, and two of its own assertions were statements about `advance`'s two
parallel regions. With streaming as the only path it would have measured a path nothing
runs, which is not an exception to master anti-goal 1 but the hazard the anti-goal names.

Deleted: `crates/prover/src/metrics/` (the module was a directory — `on.rs` and `off.rs`,
1,362 lines), `crates/prover/tests/metrics.rs`, `docs/spec/metrics.md`,
`advance_metered`, `prove_block_metered`, the `metric!` macro, and with them the `_rec`
indirection — all eight `_rec` functions turned out to be exactly "the plain function plus
a Recorder", so every one collapsed and no `_rec` name survives.

**The repository now has exactly one cargo feature, `prover/debug-info`.**
`crates/prover/tests/one_feature.rs`'s `EXPECTED` is a one-element array.

**One fact was moved rather than dropped**: `docs/spec/metrics.md` §4.1 was where this
repository wrote down that `/proc/self/status`'s `VmHWM` is the RSS ground truth. That
paragraph now lives on `tools/bench/src/report.rs`'s `peak_rss`, and the three citations —
including the runtime `None` message, which previously pointed readers at a file that no
longer exists — point there.

What survives the retirement: `tools/bench`'s `prove` verb, which needs no feature; and
the shape of a block's peak as the `min(threads, shards)` largest shard peaks summed, which
is recorded in `crates/prover/CLAUDE.md`'s parallel-step invariant and in
`docs/handoff/S20-orchestration.md`.

---

## 5. The streaming path gained one line

`prove_block_streaming` now emits the `apogee ABORTED` warning the archived statement phase
emitted, when `x10`'s final value is nonzero. It had none: a guest that panicked exited 101
having published whatever it had committed — a journal that decodes, a proof that verifies,
and an answer to a different question — and on the streaming path nothing said so. The
value was already in hand at the statement build.

---

## 6. The frozen API

```rust
// crates/host
pub fn prove(setup: &ProverSetup, io: &GuestIo, max_in_flight: usize) -> Result<Proven, String>;
pub struct Proven { pub block: BlockProof, pub report: StreamingReport,
                    pub exit_code: i32, pub cycles: u64,
                    pub journal: Vec<u8>, pub wall_nanos: u64 }
pub use verifier::proof_archive;

// crates/verifier
pub mod proof_archive;   // §3

// constants
family::PUBLIC_WINDOW_HEIGHT   = 1 << 12
family::PUBLIC_INPUT_WINDOW    = 2
family::PUBLIC_OUTPUT_WINDOW   = 3
family::HEIGHT_MENU            = [1<<8, 1<<12, 1<<16, 1<<18, 1<<20, 1<<22]
guest_memory::PUBLIC_OUTPUT_ORIGIN = 0x0000_C000
guest_memory::PUBLIC_WINDOW_BYTES  = 16_384
guest_memory::PUBLIC_PAYLOAD_BYTES = 16_380
```

`Proven` lost its `archive` field and with it the five per-phase section clocks. The four
clocks `StreamingReport` carries are **not** the same quantities: `execution` is both
passes summed, and there is no separate opening phase, one shard's GKR and its opening
being one interval. `tools/bench`'s report prints `opening_ms` and `final_ms` as `0.0`, and
a reader comparing a new JSON against a pre-S-STREAM one is comparing different things.
That was already true of the S26 streaming arm; it is now true of every run.

---

## 7. `prompts/00-master.md` — four amendments, each authorized

| Site | Amendment |
| --- | --- |
| Public values and advice | `0x8000` / `0x8400`, "a kilobyte each, at a pinned `2^8`" → `0x8000` / `0xC000`, sixteen kilobytes each at a pinned `2^12`, with the ceiling argument and the "headroom, not a bound" caveat inline |
| Trace heights | the menu gains `2^12`, with one clause on what can and cannot take it |
| **Rule 9, "Archivable stages"** | **withdrawn**, struck through and annotated inline in the same form as rule 10's emulator clause |
| Anti-goal 1 | two granted features → **one**, with the metrics retirement and its reason recorded |

Rule 9 is the substantive one. It read: *"Every prover phase boundary should be able to
export a self-contained snapshot artifact… Later phases can start from the state encoded
within an artifact instead of redoing the work."* That rule **is** the archived path.
Snapshot-and-resume rested on a post-execution section holding the whole trace —
`O(cycles)`, ~305 bytes a cycle — and a commit phase holding every shard's columns at once,
`O(total shards)` at ~300 MB each: together 500–600 GB for a real Ethereum block, which is
the thing the streaming prover exists not to do. The price of withdrawing it is stated in
§2.3: resume, and the byte-equality oracle.

---

## 8. Fixtures

**Every program identity moved**, with no ELF change, because `absorb_vm_config` pushes
every family's height and `PUBLIC_WINDOW_HEIGHT` is one of them.

| Fixture | Group | Moved? |
| --- | --- | --- |
| `crates/program/tests/vectors/identity.txt` | `kat-gen -- program` (needs the ceremony `.ptau`) | **yes, both lines** |
| the 22 committed guest ELFs | `kat-gen -- guests` (opt-in, one machine) | **yes** for the ~10 guests that reference the regions, and the generator rewrites all 22 |
| `crates/loader/tests/vectors/*.objdump.txt`, `*.nm.txt` | `kat-gen -- loader` (in CI) | **yes**, and must be regenerated **back-to-back on the same machine** as `-- guests` |
| `crates/emulator/tests/vectors/revm_*.bin` | `kat-gen -- revm` | content expected identical; the generator rebuilds the guest, so re-run and diff |
| `crates/checker/tests/vectors/global_tape.txt` | `kat-gen -- tape` | **no** — a tape records tags and payload *lengths*, and `VM_CONFIG`'s length is `2k+1` with `k` unchanged |
| `crates/constraints/tests/vectors/*.bin` | `memory`, `family`, `delegation` | **no** — none is written at a public-window height |
| `crates/program/tests/vectors/generic_table.txt` | `kat-gen -- program` | **no** — ceremony constants |
| `crates/host/tests/vectors/mini-block*` | `kat-gen -- block` (needs RPC) | **no** — the window enters only as a `<=` assert that loosens |

Three guests derive a capacity from `PUBLIC_PAYLOAD_BYTES` and their caps grow 16×:
`guests/echo`'s copy bound, `guests/amm`'s `MAX_RECORDS`, `guests/orderbook`'s
`MAX_ORDERS`. All three use the figure as a **bound check** or a `min` and none sizes an
array with it, and no test feeds any of them near the old ceiling — `echo`'s advice fixture
is 100 bytes — so no cycle count and no shard plan moves. Their images change because the
constant does.

**One free improvement while in there**: `crates/emulator/src/lib.rs` seeded every word of
the public-input window unconditionally. At `2^8` that was 256 stores a run; at `2^12` it
would have been 4,096. It now skips zero words, exactly as the advice region already did.

---

## 9. What this stage owes

### Green here

`cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings`;
`cargo clippy -p prover --all-targets --features debug-info -- -D warnings`;
`cargo check --workspace --all-targets`; `cargo test -p prover --test one_feature --test
one_proving_path`.

`cargo test --workspace` is CI's, per the root `CLAUDE.md`. Its first runs here were red on
values the window raise moved and nothing re-pinned: the loader's nineteen fixture digests,
`identity.txt`'s digest in `crates/program/tests/common/mod.rs`, and — in the test binaries
CI had not reached when it stopped — `crates/trace/tests/log.rs`, which still held
`RAM_ORIGIN - 4` to be a hole when it is now the journal's last word.

### Owed, and larger than usual

**1. The fixture regeneration is a two-command, one-machine, non-reproducible operation.**
`kat-gen -- guests` rebuilds and overwrites all 22 ELFs; `kat-gen -- loader` regenerates
the objdumps CI diffs. Run on different machines, or in the wrong order, CI fails on files
this change did not conceptually touch. `identity.txt` needs `assets/ptau/ppot_0080_24.ptau`
and `crates/program/tests/identity.rs` is `#[ignore]`d, **so CI will not catch a stale
identity** — it must be regenerated by hand. What CI *does* catch is the file's own SHA-256
in `crates/program/tests/common/mod.rs`'s `PINS`, which `kat-gen` prints and does not
write: regenerating the file is one step and re-pinning its digest is a second.

**2. The `# DEFERRED` suites have not been run**, and this stage moves more of them than
usual: every verifying key's bytes moved (the height is in `VM_CONFIG`), and every suite
changed its proving call. They are owed a batch run under the root `CLAUDE.md`'s rule —
once, at the end of the progression, no further commits expected.

**3. Every recorded deferred peak is now stale, and deliberately not replaced.** All of
them — above the line in the root `CLAUDE.md`, in `.github/workflows/ci.yml`, in
`docs/handoff/S20-orchestration.md` — are archived-path measurements. A streamed run holds
at most `max_in_flight` shards where the archived one held every shard rayon's
work-stealing happened to co-resident, so **the direction is down and the magnitude is
unmeasured**. They are marked stale rather than guessed. The prior session's report
(`../apogee-miniblock-report-2026-10-01.md` §4.1) is the reason not to guess: at a *fixed*
shard plan and a fixed thread count the archived peak varied 22% run to run, so peak is an
envelope and never a function.

**4. The full-block journal question is only half closed.** §1 says why: 16,380 bytes is
the geometry's ceiling and a single large `CREATE` return can still exceed it. The stage
that proves a full block proves `revm-block-stateless`, which has **no recorded fixture**
and **no proof** — the only things that run it are two `#[ignore]`d tests — and whose
witness cannot be recorded from a Geth endpoint at all, a collapsing MPT deletion needing a
sibling node `eth_getProof` cannot return. That blocker is untouched by this stage and is
not a bug in anyone's code.

**5. The recursion guest will pay for step 10c.** §1.2(1). There is no recursion guest
today, so the 16× is unpriced.
