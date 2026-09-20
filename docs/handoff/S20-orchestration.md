# S20 — Sharding + block orchestration

Branch `s20-orchestration`. Status: implemented; all ten acceptance items are met, items
1 and 5 in the forms the repository owner's answers required (see "Acceptance"). Three
design questions went to the owner before any code and were answered. Each answer and
what follows from it is in "Read these first".

S20 proves one execution as one **block**. `guests/shards` is a counted loop whose
`ADD_SUB_LUI_AUIPC` family runs 1,064,970 cycles — past `2^20`, the floor the timestamp
channel sets — so its plan cuts it into **two shards of one family**, which is the stage
gate. Beside them `JUMP_BRANCH_SLT` proves one shard, `INIT_TEARDOWN` one, and
`ZERO_WINDOWS` **none**, because nothing in the guest touches RAM: the stage's
zero-shard family comes free. The four shards are committed once, proved in parallel,
assembled into a `BlockProof` and verified by one `verify_block`. Pc continuity across
the cut is carried by the global memory multiset and by nothing else.

Normative documents written or amended this stage:

- **`docs/spec/block-proof.md`** (new): the block and its public-data API, the
  cross-shard record set, `verify_block`'s five checks, the time windows and exactly what
  they bind, the prover's shard cut and its one parallel step, the wire forms, and the
  transcript-tape validator.
- **`docs/spec/shard-proof.md`**: §4 (the time window is the shard's own), §6 step 4 (a
  well-formedness check) and §6's note (the `derive_global_phase` / `verify_shard_local`
  split), §10's `PostGkr` row (the window), and a header note. **No frozen rule was
  dropped**; the global transcript's schedule, the SRS digest, the key's layout and load
  rules, the opening and the registry are as S19 left them.
- Also updated to match: `docs/GLOSSARY.md`, `docs/guest-program-manual.md`,
  `.github/workflows/ci.yml`, the root `CLAUDE.md`, and the `CLAUDE.md` of `constants`,
  `checker`, `prover`, `verifier` and `verifier-core`.

`docs/spec/constraint-manifest.md` is **unchanged**: S20 adds no circuit and changes
none, which is the direct consequence of the owner's second answer.

`prompts/S20-orchestration.md` is committed unchanged.

---

## Read these first

Three questions went to the owner before any code, each with the argument and the price.
The answers are the design.

1. **The two-shard demo is a new guest at `2^20`, not an existing one at `2^16`.** The
   prompt's "give the demo guest's main cycle-owning family the smallest menu height,
   `2^16`, so an ordinary run of the unmodified guest spills into a second shard" cannot
   be done, and the reason is frozen in three places. Every execution family carries a
   timestamp gap obligation needing `lookup_channel::BITS[TIMESTAMP] = 19` variables and
   Mercury needs an even variable count, so `2^20` is the floor
   (`docs/spec/lookup.md` §3); `constraints::family_circuit`'s minimum-height arm returns
   `None` below it for all seven; and `VerifyingKey::check` refuses such a key by name.
   No existing guest spills either: `fib` and `heap`, the two that read an fd 0 input,
   are not provable at all while `EXIT` is the only provable ecall. So S20 adds
   `guests/shards`. **A two-shard family is two `2^20` shards whatever the guest**, and
   that is what makes the acceptance suite a deferred one.
2. **There is no row-0 anchoring obligation.** The prompt asks that "row-0 timestamp =
   ts_start" be pinned by a constraint. Building it meant a new `VirtualKind` (an
   indicator at row 0), a new derived challenge slot, and one gate appended to the memory
   frame **all seven execution families share** — so every family's artifact, every
   committed circuit fixture, every verifying key's bytes and seven manifest entries
   would have moved. Put to the owner with that price and with the observation that it
   buys no soundness — `docs/spec/memory.md` §4.2's chain argument already forces every
   live row of every shard onto one path from the entry pc to `HALT_PC` with strictly
   increasing timestamps — the answer was: *"If it doesn't affect soundness, then skip
   it. Make a note to remove this obligation."* **The obligation is removed from the
   design**, recorded at `docs/spec/block-proof.md` §4.1 and in the root `CLAUDE.md`, and
   the time window is what §4 says it is.
3. **A `BlockProof` carries the statement it binds.** The prompt requires the per-shard
   records to be public data of the proof, and `PublicInputs` already holds all of them;
   the owner chose "Proof holds the statement" over carrying a second copy of each field.
   So a block is `{ config, statement, shards }`, `verify_block`'s first check is that the
   statement is the one the verifier was given, and `reconciliation()` assembles the
   record view from the single copy.

Two further readings were taken before code, and are recorded rather than assumed:

- **"Canonical (family id, shard index) order" is S16's statement order.** The prompt
  uses that phrase for the memory-column absorption and the record list, but S16 froze
  the order as `INIT_TEARDOWN`, `ZERO_WINDOWS`, then every other family ascending — which
  is not ascending by id, the two init families being 7 and 8. The prompt also requires
  that `verify_shard`'s tape be unchanged between S16 and S20 and that the S16 seed be
  unaltered, which settles it: canonical order is `statement_shards`, and nothing moved.
- **The ts-window disjointness rule is per family, and can only be per family.** Cycle
  numbers are global and unique, but two families interleave — add/sub may own cycles 1
  and 3 while the jump family owns 2 — so their windows overlap by construction. A
  block-wide rule would fail on every real execution. The demo shows it: add/sub's two
  windows are `[4, 4258832)` and `[4258832, 4325428)`, and the jump family's single
  window is `[280, 4325412)`, which overlaps both.

---

## Frozen public API, as built

**`crates/verifier-core`** (`#![no_std]` + `alloc`), added:

```rust
pub struct GlobalChallenges { pub memory: [Fr; 4], pub digest: Fr }
pub fn derive_global_phase(vk: &VerifyingKey, public: &PublicInputs)
    -> Result<GlobalChallenges, VerifyError>;            // §6 steps 1-3 and the global transcript
pub fn verify_shard_local(vk: &VerifyingKey, global: &GlobalChallenges, proof: &ShardProof,
                          public: &PublicInputs) -> Result<OpeningClaim, VerifyError>;  // steps 4-11
// reduce_shard is now their composition; its order, classes and answers are S16's.

pub struct ShardRecord { pub family: u32, pub shard_index: u32, pub ts_window: [u64; 2],
                         pub memory_commitments: Vec<[u8; 64]>, pub roots: [Fr; 2] }
pub struct BlockReconciliation { pub records: Vec<ShardRecord> }   // to_bytes, from_bytes
pub struct BlockProof { pub config: VmConfig, pub statement: PublicInputs,
                        pub shards: Vec<ShardProof> }
impl BlockProof {
    pub fn config(&self) -> &VmConfig;
    pub fn shard_counts(&self) -> &[u32];
    pub fn shard_count(&self, family: u32) -> u32;
    pub fn statement(&self) -> &PublicInputs;
    pub fn shard_proofs(&self) -> &[ShardProof];
    pub fn reconciliation(&self) -> BlockReconciliation;
    pub fn shape(&self) -> Result<(), &'static str>;
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(bytes: &[u8]) -> Result<BlockProof, &'static str>;
}
pub fn check_ts_windows(records: &[ShardRecord]) -> Result<(), &'static str>;
```

**`crates/verifier`**:

```rust
pub fn verify_block(vk: &VerifyingKey, proof: &BlockProof, public: &PublicInputs)
    -> Result<(), VerifyError>;
pub use verifier_core::{BlockProof, BlockReconciliation, ShardRecord, /* … */};
```
```
verifier block <verifying-key> <identity-hex> <public-inputs> <block>    exit 0 / 1 / 2
```

**`crates/prover`**:

```rust
pub fn prove_block(setup: &ProverSetup, archive: &mut TraceArchive, plan: &ShardPlan)
    -> Result<BlockProof, ProverError>;
```

**`crates/checker`**:

```rust
pub fn tape(events: &[TranscriptEvent]) -> Vec<String>;
pub fn global_tape(vk: &VerifyingKey, statement: &PublicInputs) -> Vec<String>;
pub fn expected_global_tape(vk: &VerifyingKey, statement: &PublicInputs) -> Vec<String>;
pub fn check_global_tape(vk: &VerifyingKey, statement: &PublicInputs) -> Result<Vec<String>, String>;
```
```
checker tape <verifying-key> <public-inputs>
```

**`crates/constants`**: `family::CYCLE_OWNING: [bool; 9]` and
`transcript_tags::NAMES: [&str; 41]`, both data, both append-only. No tag was added and
no value changed.

---

## What this freezes for every later stage

1. **`docs/spec/block-proof.md`** in full.
2. **`BlockProof`**, its public-data API and its file format (§1, §1.1, §6). S24's
   occupancy assertions read `config`, `shard_counts` and `shard_count`; S26's host
   driver and S27's `aggregate_block` read `shard_proofs` and `reconciliation`.
3. **`BlockReconciliation` and `ShardRecord`**, and the record layout — family, shard
   index, `ts_start`, `ts_end`, the memory commitments in column order, read root, write
   root — which is what S27's aggregation guest replays.
4. **`prove_block` and `verify_block`**, and `verify_block`'s five checks in order.
5. **The verifier factoring** inside the no_std core: `derive_global_phase` and
   `verify_shard_local`, which are the exact functions `verify_block` composes and which
   S27's leaf/root split consumes.
6. **The per-shard ts-window binding absorb**, one typed `SHARD_TS_WINDOW` message
   immediately after the seed triple — S16's position, unaltered, with S20's value — and
   the anchoring convention, cycle-owning scoping included, **as the owner settled it**:
   ordered and disjoint within each cycle-owning family, no rule for a family that owns
   no cycles, and **no circuit obligation tying a window to a trace** (§4.1).
7. **`family::CYCLE_OWNING`**, append-only beside the family ids. The delegation
   families E21–S23 append `false` and slot in with **zero `verify_block` changes**.
8. **The CLI verb**: `verifier block <key> <identity-hex> <public-inputs> <block>`.
9. **The transcript tape's rendering** (`absorb <TAG> <n>` / `squeeze <TAG>`) and the
   committed `crates/checker/tests/vectors/global_tape.txt`.

---

## Artifacts

| Path | Size | SHA-256 | What |
| --- | --- | --- | --- |
| `crates/loader/tests/vectors/shards.elf` | 9,108 bytes | `6b05f589f3726b8f7b42cd67547227a23640041eefa2e66d5277618735d34241` | S20's guest, dev profile |
| `crates/checker/tests/vectors/global_tape.txt` | 21 lines | `6c3dcd8ba4b554a4f597bc758e36d2e73f02a5a318423c73416da10d06263037` | the global commit phase's absorb sequence for the two-shard statement |
| `tools/kat-gen/src/tape.rs` | — | — | the `tape` group; `cargo run -p kat-gen -- tape`, and in the default set |

No other committed fixture moved. `shards` has no dependencies, so adding it to the guest
workspace changed no other guest's metadata hashes, and `cargo run -p kat-gen -- guests`
rewrote only the new file — unlike S16, which moved three ELFs.

The tape fixture is this code's output, held first to `checker::expected_global_tape`,
which is written from `docs/spec/shard-proof.md` §2 and shares no code with
`verifier_core::global_commit`. `crates/checker/tests/tape.rs` spells its first seven and
last five lines out a third time, so agreement between the phase and the checker still
has to face a hand-written list.

---

## Acceptance

File paths are under `crates/`. Every test listed passes. The ones marked *deferred* are
`#[ignore]`d and were run locally (see "Verification performed").

| # | Item | Where | Result |
| --- | --- | --- | --- |
| 1 | **Stage gate**: one execution split across ≥ 2 shards of the same family proves to a `BlockProof` and `verify_block` returns Ok; the memory challenges squeezed exactly once after all commitments; pc continuity carried only by the global multiset, by a structural schema assertion | `prover/tests/block.rs::a1_a3_a8_a9_…` (deferred) | The config is `{ADD 2^20, JBS 2^20, INIT 2^16, ZERO 2^16}` and the counts `[2, 1, 1, 0]`. Four records in statement order; `verify_block` Ok; every shard also Ok on the S16 `verify_shard` path. The tape's five squeezes are its last five lines, four `MEMORY_CHALLENGE` and one `GLOBAL_STATE_DIGEST`, and no line carries a tag G1–G11 does not have. **The schema assertion is an exhaustive destructuring** of `ShardProof` and `BlockProof`: a field added to either — a boundary pc, a successor pc — fails to compile here rather than passing unexamined |
| 2 | Multi-family block: a guest touching ≥ 3 breadth families proves and verifies, with structural count assertions | `prover/tests/block.rs::a2_…` (deferred) | `guests/mem`'s five execution families, seven shards; each execution family's count 1, `INIT_TEARDOWN` 1, `ZERO_WINDOWS` 1; every record's commitment list its family's `M` width and both roots present |
| 3 | Absorb-order conformance: the checker's tape for run 1 matches the frozen list item for item, committed as a fixture. Negative control: a fork swapping two absorptions produces different global challenges and a verification failure | `checker/tests/tape.rs` (CI); `prover/tests/block.rs::a1_…` (deferred) | The run's tape equals the fixture. The fork absorbs G7 before G6: its tape leaves the order at exactly that line, all four memory challenges and the digest move, and a `ShardProof` carrying its digest is refused as `Statement("the proof was made for another statement")` at step 5, the honest digest getting past it. Also: the expectation follows the statement's shape — an extra shard adds one `COMMITMENT` line, a `ZERO_WINDOWS` shard adds its window id — and a tape is the script and not the values |
| 4 | Statement-binding negatives each fail with the expected class: (a) a one-bit-different public I/O digest, (b) a different identity/key, (c) an altered shard count | `prover/tests/block.rs::a4_a6_…` (deferred) | All `Statement`, each by the check named: (a) refused as "the block's statement is not the one given", and with the block's own copy moved to match, as "the proof was made for another statement"; (b) another identity as the latter, another `bytecode_size_words` as "the block's VmConfig is not the key's"; (c) a count raised with the lists padded refused by shard-set exactness, and without the padding by step 3 |
| 5 | **Tamper twin — omit one shard**: drop one shard record and proof, adjusting counts to match; verification fails via the global root product | `prover/tests/block.rs::a5_…` (deferred) | Built **as an honest prover would build the truncated statement** — counts, commitment lists and roots adjusted, the global commit phase rerun, the three remaining shards proved against it — so it passes checks 1 to 4 and fails at `MemoryArgument("the statement's roots do not reconcile")`. Simply editing an honest block instead would move the digest and be refused at step 5 as `Statement`, which is why the twin is re-proved; see deviation 4 |
| 6 | Tamper twin — swap ts windows; verification fails at the window check with the expected class | same | The two add/sub shards' windows exchanged: `Statement("a family's shard time windows are not ordered and disjoint")`, before any shard is verified. And **a second, independent refusal**: the window is absorbed at S2, so the same proof under the other window fails its own transcript as `Constraint`/`Lookup` |
| 7 | Witness tamper twin: re-prove one shard with ONE corrupted trace cell and reassemble; `verify_block` fails and the honest twin passes | `prover/tests/block.rs::a7_…` (deferred) | `wrap`, the add/sub carry bit, set on row 0 of the **second** add/sub shard — a cell no lookup tuple reads, so an honest prover recounts nothing and the sum gate is what refuses it. `Constraint`; the honest block still Ok. A defect in a shard the first one says nothing about |
| 8 | Zero-shard skipping: a family in the `VmConfig` with zero occurrences yields zero shards, verification passes, and the count reads 0 through the stable API | `prover/tests/block.rs::a1_…` (deferred); `verifier-core/tests/block.rs` (CI) | `ZERO_WINDOWS` is in the config and proves nothing: `shard_count(ZERO_WINDOWS) == 0`, no record, and the block verifies. The core's suite adds `shard_count` of a family the config **detaches**, which reads 0 rather than panicking |
| 9 | Public-data contract: a test reads the descriptor and the per-family shard counts from a serialized `BlockProof` through the public API only | `prover/tests/block.rs::a1_…` (deferred); `verifier-core/tests/block.rs` (CI) | The real block round-trips byte for byte and the decoded one gives the config, the counts, each family's count, the proofs and the reconciliation, and verifies. The core's suite does the same on a synthetic block and adds every refusal of the wire form |
| 10 | Resume: kill and resume at the post-commit and post-GKR boundaries; the resumed run produces a byte-identical `BlockProof` | `prover/tests/block.rs::a10_…` (deferred) | Stopped after post-commit **and** after post-GKR, each time exported and re-imported through `TraceArchive`, then finished: the block's bytes and every phase section's bytes equal the uninterrupted run's, and the resumed block verifies |

**Beyond the items:**

| What | Where |
| --- | --- |
| Must-be-exact 8: the block is byte-identical on one thread and on all 18 | `prover/tests/block.rs::the_block_does_not_depend_on_the_thread_count` (deferred) |
| Must-be-exact 2: `verify_block`'s signature pinned at compile time, with `verify_shard`'s and both halves of the core's | `verifier/tests/signature.rs` |
| The `block` CLI verb end to end, and every way it refuses: another identity, a statement that is not the block's, a flipped bit anywhere in the block, a shard file given to the block form and a block file given to the shard form, and a short invocation | `verifier/tests/cli.rs::the_cli_verifies_a_block_file` (deferred) |
| `BlockProof`'s and `BlockReconciliation`'s wire forms field by field, every truncation and a trailing byte refused, and every way a block's statement and proofs can be different shard sets refused at decode, by name | `verifier-core/tests/block.rs` |
| The window rule: per cycle-owning family, an empty window and an out-of-order pair each refused, a family that owns no cycles exempt | `verifier-core/src/block.rs` (unit), `verifier-core/tests/block.rs` |
| The `checker tape` verb from files: it prints the committed tape, and a statement the key does not describe exits 1 with the reason — never a panic inside the global commit phase, whose contract is that its caller checked first | `checker/tests/tape.rs::the_tape_verb_reads_a_key_and_a_statement_from_files` |
| Step 4's two new refusals — `start > end`, and `end` past the clock | `verifier-core/tests/reduce.rs` |
| `guests/shards` under `qemu-riscv32`, at both profiles, exiting 2 | `loader/tests/qemu.rs::shards_passes_its_checks` (Linux + qemu-user) |
| The guest-program manual's walkthrough over `guests/shards` | `tools/artifact-dump/tests/manual.rs` |

---

## Must-be-exact, item by item

1. **The pre-fork order is absorbed verbatim.** `global_commit` did not change a line,
   and the only S20-flagged refinement that touches it is (i), the canonical order of the
   per-family memory commitments, which is S16's `statement_shards` order and was already
   that. (ii) is S16's framing, unchanged. (iii), the ts-window binding absorb, is S16's
   `SHARD_TS_WINDOW` at S2 with a real value. No challenge is drawn before the statement
   is fully absorbed, and `checker::check_global_tape` is the standing check of it.
2. **`verify_block` takes `(&VerifyingKey, &BlockProof, &PublicInputs)` and nothing
   else**, pinned at compile time, and it composes `verify_shard_local` plus the opening
   — the same two steps `verify_shard` runs. The CLI calls it and so does every test.
3. **The statement descriptor is carried in the proof**: `BlockProof.config` and
   `BlockProof.statement.shard_counts` are G3 and G4's messages, and check 1 holds both
   to the key's and to the verifier's. A block cannot claim different occupancy than it
   binds.
4. **Shard proving consumes the S16 prover as-is.** The only new prover code is
   `prove_block` (34 lines), the window derivation (20 lines) and the two `for` loops in
   `advance` becoming parallel iterators. No fill changed, no circuit changed, and
   `prove_shard`/`prove_shard_columns` keep their S16 signatures — which is why the
   window is read off the shard's own `M[0]` column rather than passed in.
5. **The block's shape is fixed given the `VmConfig` and the counts.** Every section
   length derives from the descriptor; the `shards` list has `statement_shards`' length,
   each proof its family's fixed size.
6. **Every reconciliation check lives in `verify_block`.** (1) the root product is step
   10, run per shard over every shard's roots; (2) the LogUp roots are step 9, per shard;
   (3) the ts windows are `check_ts_windows`, cycle-owning families only; (4) shard-set
   exactness is `BlockProof::shape()`; (5) a zero-shard family is admitted by
   construction. None of them is a prover self-check.
7. **Every phase boundary exports a resumable snapshot, block-wide.** They are the S12
   `TraceArchive`'s five sections, with S12's per-phase wall-clock fields;
   `PostGkr` gained the shard's time window. `prove_block` is `advance` to `Final` plus
   `finish`, so resume needs nothing of its own.
8. **The assembled block is byte-identical for any thread count and any schedule.**
   Parallelism is confined to the two phases after the global phase closes, each shard
   forks its transcript from the same global state, and an indexed parallel `map`
   collects in statement order.
9. **`ShardRecord`'s field order is the frozen layout**, checked byte by byte against
   offsets in `verifier-core/tests/block.rs`.

---

## Deviations and notes for the reviewer

1. **The demo guest is new and `2^20`** (answer 1). The prompt's `2^16` is impossible.
2. **No row-0 anchoring obligation** (answer 2). The owner removed it. `check_ts_windows`
   therefore checks the plan and not the trace, and `docs/spec/block-proof.md` §4.1, the
   root `CLAUDE.md` and `crates/verifier-core/CLAUDE.md` all say so in those words. If a
   later stage wants windows to bind the trace, the design is written down in answer 2
   and its price with it.
3. **Not `postcard` over `serde`.** The prompt asks for it for `BlockProof` and
   `BlockReconciliation`; both use `docs/spec/shard-proof.md` §9's primitives instead,
   because `PublicInputs`, `ShardProof` and `VmConfig` already have exactly one encoding
   there and a `postcard` container around them would put two integer conventions in one
   file — the master's *One encoding* rule. `TraceArchive` is still `postcard`, as S12
   froze it.
4. **Acceptance 5's twin is re-proved, not edited.** "Drop one shard record and proof
   from an honest `BlockProof`, adjusting counts to match" cannot reach reconciliation:
   the counts are absorbed at G4, so adjusting them moves the digest and every surviving
   proof is refused at step 5 as `Statement` first. The honest-prover twin — the
   truncated statement's own global phase, its own proofs — is what makes the root
   product the first thing to break, and it is what `checker::TamperHarness` already does
   for cells.
5. **`prove_block` takes `&mut TraceArchive`**, not the prompt's `&TraceArchive`:
   must-be-exact 7 requires the block-level phase snapshots to *be* the archive's phase
   sections, which needs the archive to be written.
6. **`prove_block` takes `&ProverSetup`**, not the prompt's `&VerifyingKey`: a
   `VerifyingKey` carries neither the SRS, the registrations nor the fills, all of which
   proving needs. `setup.vk` is the key.
7. **`ProveError` is the existing `ProverError`.** A second error type for one function
   would be error-type architecture (anti-goal 8).
8. **No new `VerifyError` class.** A block's own refusals are `Statement`, which keeps
   §6's frozen check order and the no_std core's frozen enum intact.
9. **Every existing proof's bytes moved**, because a cycle-owning shard's window is no
   longer `[0, 2^38)` and the window is absorbed before the witness commitments. Nothing
   in the key or in identity moved. The pinned proof sizes did not change — a window is
   two `u64` either way.
10. **`checker` is a dev-dependency of `prover`.** Acceptance 3 asks the block suite to
    check the tape of the statement it actually proved, and the tape validator lives in
    `checker`, which depends on `prover`. Cargo resolves dev-dependency cycles; the
    library graph is unchanged.
11. **`constants` kept its zero-logic rule.** `transcript_tags::NAMES` is data; the
    `tag_name` lookup over it lives in `checker::tape`.
12. **A pre-S20 `TraceArchive` does not resume.** `PostGkr`'s section gained the shard's
    time window, so an archive written by an earlier prover is refused by
    `decode_gkrs` — the two window words are read where the commitment count was, and
    the count that follows is refused as longer than the bytes left. It fails as
    `ProverError::Archive`, never silently. Nothing in the repository persists an
    archive across a version, so this costs nothing; it is recorded because the section
    is a frozen schema (`docs/spec/shard-proof.md` §10).
13. **The parallel step picks the *first* failure, not an arbitrary one.** Rayon's
    `collect::<Result<_, _>>()` returns an unspecified error when more than one task
    fails. Every refusal this prover makes names a cycle or a family, and one that named
    a different cycle on a different machine would be a diagnostic nobody could
    reproduce — so `advance` collects in order and picks sequentially
    (`phases::first_error`).
14. **`guests/shards` is not in the QEMU differential's suite.** That comparison reads
    QEMU's per-instruction register log, and a million instructions of it is gigabytes.
    The guest is in `crates/loader/tests/qemu.rs` instead, which runs it at both profiles
    and checks the exit status; the emulator's own reading of the same guest is the block
    suite, which proves the trace it produced.

---

## Measurements

macOS, 18 cores, 48 GB, `--release`, the toy SRS of `2^20` powers. The two-shard demo:
`guests/shards`, four shards — `INIT_TEARDOWN` at `2^16`, two `ADD_SUB_LUI_AUIPC` and
one `JUMP_BRANCH_SLT` at `2^20`.

| Phase | 18 threads | 1 thread |
| --- | --- | --- |
| key build (`ProverSetup::new` over the toy SRS) | 3.4 s | — |
| emulate and archive | 0.25 s | — |
| `PostCommit`: every shard's `M` columns built and committed, then G1–G11 | 11.3 s | 16.7 s |
| `PostGkr`: four shards' witness commitments, forward passes and GKR proofs | 24.6 s | 259.8 s |
| `PostOpening`: four batched Mercury openings | 9.3 s | 42.4 s |
| `Final`: the statement assembled | 75 µs | 73 µs |
| **`prove_block` total** | **44.2 s** | **319 s** |
| **peak resident** | **24.2 GB** | **10.6 GB** |

**Per shard.** On one thread the four shards took 259.8 s of GKR and 42.4 s of opening
together; three of the four are `2^20` and dominate, so a `2^20` shard is about **85 s of
GKR and 14 s of opening**, and the `2^16` window shard is the remainder.

**Block assembly overhead: 284 µs** — `finish` plus the `VmConfig` clone, over an archive
whose final phase is already filled. Assembling a block costs nothing; proving it is the
whole cost.

**`verify_block`: 75 ms** for the four shards, of which the four Mercury openings' pairings
are most. The global transcript is replayed once instead of four times, which is what the
`derive_global_phase` split buys.

**Proof size: 204,848 bytes.** The statement is 8,444; the four proofs are 20,524
(`INIT_TEARDOWN` at `2^16`), 57,100 and 57,100 (`ADD_SUB_LUI_AUIPC` at `2^20`) and
61,612 (`JUMP_BRANCH_SLT` at `2^20`), 196,336 together; the `VmConfig` and the length
prefixes are the remaining 68. Every one is fixed given the key and the family, so a
block's size is a function of its shard counts alone.

### The memory cost of parallel shard proving, plainly

The quantity is **peak resident memory**, and it scales with **how many shards are proved
at the same time**, which `rayon` sets to the core count. On this machine the four-shard
demo is 7.2× faster in wall clock and 2.3× the peak: 44 s at 24.2 GB against 319 s at
10.6 GB. The whole acceptance suite peaked at **25.3 GB**, its largest statement being
`guests/mem`'s seven shards — and **33.4 GB on a second run**; see "Verification
performed" for why the two differ and which to plan for.

So a machine with less than about 26 GB free cannot run the S20 suite on the parallel
path, and a much wider machine proving a much larger block would go higher still. **There
is no knob, and none was added** — a caller that must bound the peak runs `prove_block`
inside a `rayon::ThreadPoolBuilder` pool of its own, which is exactly what
`the_block_does_not_depend_on_the_thread_count` does and where the 10.6 GB figure comes
from. Whether the prover should bound it itself is a question for a stage with a real
workload to measure against; S20 has no benchmark that would justify picking a number.

**It moved every existing suite, and the numbers are re-measured, not inferred.** Every
deferred suite was re-run on this tree, on the machine that produced the figures each
handoff recorded, so these are like-for-like:

| Suite | Before (its own handoff) | On the S20 tree | Why |
| --- | --- | --- | --- |
| `prover --test acceptance` | 8.64 GB, 322 s | 8.64 GB, 324 s | one `2^20` shard: nothing to prove in parallel |
| `verifier --test cli` | 8.56 GB, 20 s | 8.56 GB, 40 s | ditto; the second run is S20's new block case |
| `prover --test control` | 10.1 GB | **18.0 GB**, 64 s | two `2^20` shards, now at once |
| `prover --test alu` | 14.1 GB, 111 s | **30.9 GB**, 67 s | four |
| `prover --test mem` | 14.73 GB, 119 s | **32.3 GB**, 87 s | five |
| `checker --test tamper` | 16.90 GB, 1,469 s | 17.0 GB, 1,512 s | it proves one shard at a time, by design |
| `checker --test logup` | 203 s (no peak recorded) | 18.8 GB, 198 s | first measurement; no delta can be claimed |
| `prover --test block` | — | 33.4 GB, 779 s | new |

So the trade is about **2.2× the peak for about 1.4× the speed** on a statement whose
families each prove a `2^20` shard, and it grows with the family count: each family a
fixture guest adds is another `2^20` forward pass held concurrently rather than in turn.
**`guests/mem`'s statement now peaks above 32 GB**, so a 32 GB machine can no longer hold
it resident, where before S20 it fit in 15. That is the one capability this stage took
away, and it is the reason the numbers above are in `.github/workflows/ci.yml` and the
root `CLAUDE.md` as well as here. The mitigation needs no code and no knob — a caller
installs its own rayon pool — but whether `prove_block` should bound its own concurrency
is a real open question, and the next stage with a workload to measure against should
answer it.

---

## Verification performed

On macOS (18 cores, 48 GB), every gate the root `CLAUDE.md` lists, at the final tree:

- `fmt --check` in all four workspaces, and `clippy -D warnings` in all four;
- `cargo test --workspace`: **958 passed, 65 `#[ignore]`d** (945 and 56 at S19). The 13
  new tests that run in CI: `verifier-core/tests/block.rs` 6 and `src/block.rs`'s unit
  tests 2; `checker/tests/tape.rs` 5. The 9 new ignored ones are
  `prover/tests/block.rs`' 7, `verifier/tests/cli.rs`' block case and
  `loader/tests/qemu.rs`' `shards` case;
- the `riscv32imac` build of `field`, `constants`, `transcript`, `poly`, `sumcheck`,
  `constraints`, `gkr-verify` and `verifier-core`;
- `cargo run -p kat-gen`, then the fixture diff: `global_tape.txt` regenerates byte for
  byte and **nothing else moves** — every circuit artifact, the identity pin and the
  generic table's commitments are unchanged, which is answer 2's direct consequence;
- `cargo run -p kat-gen -- guests`: only `shards.elf` is written, twice to the same
  bytes;
- `guests/shards` builds at both profiles from its own directory.

**The deferred suite**, `cargo test --release -p prover --test block -- --include-ignored
--test-threads=1`, on the final tree:

| Suite | Result | Wall | Peak resident |
| --- | --- | --- | --- |
| `prover --test block` | 7 passed | 779 s | 33.38 GB |

**The peak was 25.34 GB on an earlier run of the same file and 33.38 GB on the last one**,
and the larger figure is the one recorded. The spread is the file's largest test,
`a2_a_multi_family_block_proves_and_verifies`, which proves `guests/mem`'s seven-shard
block — 32.31 GB on its own — so how close the file gets to that ceiling depends on what
else the allocator is holding when it runs. **Plan for 34 GB.**

It is commented out of `.github/workflows/ci.yml` under a `# DEFERRED:` line, master
rule 7: a two-shard family is two `2^20` shards and cannot be made smaller, and the file
proves seven blocks.

**Every other deferred suite was re-run too**, because the window's generalization moves
every proof's bytes and the parallel step moves every statement's memory profile. All
green, and the peaks are the table above:

| Suite | Result | Wall | Peak resident |
| --- | --- | --- | --- |
| `verifier --test cli` | 2 passed | 40 s | 8.56 GB |
| `prover --test acceptance` | 7 passed | 324 s | 8.64 GB |
| `prover --test control` | 2 passed | 64 s | 18.03 GB |
| `prover --test alu` | 1 passed | 67 s | 30.87 GB |
| `prover --test mem` | 1 passed | 87 s | 32.31 GB |
| `checker --test tamper` | 9 passed | 1,512 s | 16.98 GB |
| `checker --test logup` | 9 passed | 198 s | 18.76 GB |

**Not run here**: the QEMU suites, which need a Linux host with `qemu-user`.
`guests/shards`' case in `loader/tests/qemu.rs` is new and should be run in the container
before merge, at both profiles, along with `loader --test qemu`'s other nine and the
emulator's differential and consistency files — none of which S20 touches, but the guest
list grew.

---

## Open for the next stage

- **The ts window binds nothing about a trace**, by the owner's decision. If aggregation
  or a later occupancy check wants more from it, the obligation and its price are in
  answer 2.
- **`prove_block`'s peak scales with the core count**, and nothing bounds it. It cost
  `guests/mem`'s statement its fit on a 32 GB machine (14.7 GB → 32.3 GB), and the cost
  grows with every family a fixture guest adds. A stage with a real workload should
  measure and decide whether the prover bounds its own concurrency; S20 has no benchmark
  that would justify picking a number.
- **E21–S23's delegation families** append `false` to `family::CYCLE_OWNING` and carry a
  min/max invocation window. `verify_block` needs no change.
- **S26 and S27** consume `derive_global_phase`, `verify_shard_local`,
  `BlockProof`'s public data and `BlockReconciliation`'s serialization, all frozen here.
  The Mercury field-side module and `cm*` are still owed by S26, as S16 left them.
- **The I/O-binding stage** still owes `read`, `write`, the transfer rows and the tie
  between fd 0 / fd 1 and the execution. Until then `EXIT` is the only provable ecall,
  which is why no guest that reads an input can be proved.
- **Every prover phase's `# DEFERRED:` step goes back into CI** before the project is
  called finished, master rule 7. There are now nine.
