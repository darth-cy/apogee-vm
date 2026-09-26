# S25 — Witness pipeline, real blocks, bench harness

`crates/host` is new: the host SDK the master prompt's workspace layout has always
reserved, holding `WitnessRecorder` — which pre-executes a real mainnet block's
transactions with native revm against an RPC-backed database, harvests the touch set and
emits a `BlockWitness` — and the `prove`/`verify` wrappers around S20's entry points.
`tools/bench` gains a `prove` verb that runs a proving job and emits a `BenchReport`.
`guests/revm-block` gains the fields a real block needs, a **strict** witness database,
and an in-guest Merkle-Patricia trie.

The stage's testing ladder is normative — *"S24's synthetic state is done → mini-blocks
here → stateless full block last. Do not attempt the full block before the mini-block gate
passes."* — and this note is organised the same way.

**The mini-block gate passes.** Block 26,057,509's first two transactions, recorded from
mainnet, proved against the real ceremony SRS and verified — 24,206,626 guest cycles over
37 shards, 850 s at a 34.1 GiB peak.

**Acceptances 1 to 6 are met.** Acceptance 7 is met on the guest and on real mainnet data
for the half that can be, and **acceptance 8 was not run, by the owner's decision, with
the numbers that decided it** — §7 and §9 are the whole account. The short version: a real
block does not fit a 256 GB box, and a recorded witness cannot be complete, and both are
measurements rather than guesses.

---

## 1. Decisions taken with the owner, before any code

Four, raised together at the start because each changes what gets built and two have lead
time.

| # | Question | Decision |
| --- | --- | --- |
| 1 | No mainnet endpoint exists anywhere in the tree, and `ETH_RPC_URL` was unset | The owner supplied an Alchemy mainnet URL. It is **never committed**: it reaches the refresh command through the environment, and what lands in git is the content-addressed response cache and the recorded fixtures |
| 2 | Must-be-exact 6 wants a minimal JSON-RPC client, but the workspace has no HTTP client and no TLS, and master anti-goal 6 makes the runtime dependency list exhaustive | **`curl` through `std::process::Command`, plus `serde_json`.** We write the JSON-RPC layer — request framing, the retry policy, the content-addressed cache — and only the HTTPS bytes are `curl`'s. §6 is the whole argument |
| 3 | A real block's output commitment does not fit the 1,020-byte journal, and `docs/spec/revm-block.md` §2 is frozen | **The stateless binary gets its own journal.** The mini mode keeps §2 byte for byte — it fits, and nothing regenerates. Must-be-exact 2 already requires two identities for two modes, which is exactly where the difference belongs |
| 4 | Acceptance 8 needs the rented `r8i.8xlarge`, which does not exist, and a full block may not fit one box at all | **Provision after the mini-block gate, with measured numbers.** §7 is the measurement and what it implies |

---

## 2. What shipped

### `crates/host` — the host SDK

`crates/host/CLAUDE.md` is the crate's own account; the frozen API is there in one block.
The three things worth repeating here:

- **`host::verify` adds nothing to the verifier's inputs.** It is
  `verifier::verify_block(vk, block, block.statement())` — the statement read out of the
  proof rather than taken as a second argument that could disagree with it. Master rule 6
  holds exactly, and identity stays the caller's own comparison — a key recomputes its own
  identity when it loads, so it cannot be its own authority for it, and the one line that
  compares `vk.identity.to_bytes()` against a value from a trusted channel is the caller's
  to write, exactly as the `verifier` CLI makes it a separate argument.
- **`host::prove` times the executor**, and that is the one thing it adds beyond the
  eight-step preamble. S12 froze a per-phase wall-clock field on the trace archive's
  post-execution section and **every caller in the repository passed zero**; must-be-exact
  5 wants the bench report's per-stage timings to come from those sections, so that field
  had to become real.
- **The recorder runs the block to discover the touch set**, through
  `revm_block::run_against` — the same block executor the guest runs, over a different
  database. Nothing short of executing knows which accounts and slots an EVM execution
  reads.

### `guests/revm-block` — what the witness gained, and what it lost

`docs/spec/revm-block.md` is normative and §1 moved. The four additions are
`BlockEnvWitness::block_hashes`, `TxWitness::{blob_hashes, max_fee_per_blob_gas,
authorizations}` and the `AuthorizationWitness` they need. The pinned block made all four
necessary rather than speculative: it carries 200 type-2 transactions, 38 type-0, **two
type-3 and six type-4**.

What it lost is its two silent defaults, and that is the more interesting half — §4.

### `guests/revm-block/src/mpt.rs` — the trie

Ethereum's Merkle-Patricia trie and the RLP codec under it, written here because S25's
core algorithm says to own it. One code path serves authentication and recomputation,
because they are the same operation seen twice: resolving a reference through the node map
*is* the verification. `crates/host/tests/mpt.rs` holds it to the three published root
vectors, to order- and delete-invariance laws that need no oracle, and to each refusal
separately.

### `tools/bench` — the `BenchReport`

A `prove` verb rather than a ninth routine: a proving job has to be told which block and
what the hardware costs, and the routine table's `fn()` has nowhere to put either. The
report's per-stage timings are the trace archive's own phase sections — no stopwatch
anywhere inside the prover — and the crate's charter moves by exactly one line, recorded
in its `CLAUDE.md`: a committed report is committed output, which `tools/bench` did not
have before.

### `tools/kat-gen -- block` — the manual refresh

**Not in `DEFAULT_GROUPS`**, the same opt-in the `guests` group has, which is what keeps
must-be-exact 4's *"CI never touches RPC"* true by construction. One session records the
pinned mini-block, checks three further recent blocks live, and re-records the pinned one
from the cache alone.

---

## 3. The mini-block gate

The block is **26,057,509**, the finalized head at refresh time: 246 transactions,
27,971,256 gas, 16 withdrawals, Osaka. The mini-block is its **first two** transactions —
two because the stage says why, *"so inter-tx state carry is exercised"* — which is 392,997
gas, 17 accounts and 37 storage slots, a 135,104-byte witness and a 90-byte journal.

| # | What | Where | Result |
| --- | --- | --- | --- |
| 1 | recorder determinism | `crates/host/tests/witness.rs::a1_…`, and every refresh | two cache-only recordings, byte-identical, **zero network calls** |
| 2 | differential, mini-block | `…::a2_…`, `crates/host/tests/prove.rs::a4_…`, and the refresh | the witness alone reproduces the journal; the guest's journal is the pinned one; **three further recent blocks** (26,057,508/507/506) agree in one refresh session |
| 3 | witness completeness | `…::a3_a_deleted_slot_is_refused`, `…::a3_a_deleted_account_is_refused` | **37 of 37** slots and **17 of 17** accounts deleted in turn, every one refused |
| 4 | the mini-block proof | `crates/host/tests/prove.rs::a4_…` | proved and `verify` Ok — §7 |
| 5 | tamper twin | `…::a5_a_corrupted_advice_cell_is_refused` | one advice cell → `MemoryArgument`; the consistent-pair control verifies |
| 6 | bench report | `cargo run --release -p bench -- prove mini-block` | §7's table, committed below |

### Acceptance 2, and why it is two things

The stage asks for *"guest revm output over the recorded witness equals native revm output
over the live-DB execution"*, on the fixture block **and** on three further recent blocks in
one refresh session. Both halves run, and they are different checks:

- **The committed half** is `a2_the_witness_alone_reproduces_the_journal`: native revm,
  reading nothing but the witness through the strict `WitnessDb`, reproduces the journal
  the recording computed while reading the live chain. That is a *completeness* claim about
  the witness, and it runs in `cargo test --workspace`.
- **The guest half** is `a4`'s journal assertion — the traced guest's journal against the
  pinned one — and the refresh session's three extra blocks, each recorded, run on the
  guest, and held to native revm's answer. Those three are checked live and **not
  committed**: their RPC responses go to a scratch cache under `target/`, because adding
  three more blocks' `eth_getProof` answers to the committed snapshot would quadruple a
  fixture directory for evidence a reader cannot re-derive anyway.

---

## 4. Findings

### The witness had two silent defaults, and advice made them dangerous

S24 read an address absent from `BlockWitness::accounts` as an **empty account** and a slot
absent from `AccountWitness::slots` as **zero**. At S24 the witness was baked into the
guest's `.rodata`, so program identity bound it and a default could only be wrong in a way
the identity already covered. Since S-IO the witness is **advice, which nothing binds** —
so a default is a value *the prover chose*, and a witness with an account deleted from it
ran happily and committed a journal for a state nobody supplied.

`WitnessDb` is the strict database that replaces `CacheDB<EmptyDB>`. Every miss is an
error naming what was missing. **Non-existence is recorded rather than inferred**: an
account that does not exist is in the list with every field zero, and the database answers
revm `None` for exactly that shape.

That is not a change of taste; it is what makes acceptance 3 a test rather than a
formality. `crates/host/tests/witness.rs` sweeps **every** recorded slot and **every**
recorded account of the pinned block, deleting each in turn, and requires all of them to
be refused.

**It found a real gap in this repository's own test helper on the first run.**
`crates/emulator/tests/revm.rs::synthetic_witness` built two accounts — a sender and a
callee — and never the **beneficiary**, which every block that pays a fee reads. Under the
old lax database it read as empty and the tests passed. Under the strict one they stopped,
which is the behaviour that was wanted.

### `BLOCKHASH` read a placeholder, and closing it was a deliberate act

S24 recorded this as the one acknowledged *gap* rather than a decision, and pinned the
placeholder on purpose so that closing it could not be an accident:
`blockhash_reads_a_placeholder_today` asserted that the opcode returned `keccak256` of the
block number's decimal string. It is closed and that test is rewritten in both directions
— a recorded ancestor is answered, an unrecorded one is refused.

The bound that makes the field cheap is worth recording: **at most 256 entries are ever
needed**, because `revm-interpreter`'s `blockhash` instruction pushes zero without
consulting the database when the height is the current one or more than
`BLOCK_HASH_HISTORY = 256` behind it. EIP-2935 does not change this in revm 42 — the
opcode is still served from the host, not from state.

### `Bytecode::new_raw` panics, and a guest that panics publishes nothing

Found by reading, not by failing. `revm::state::Bytecode::new_raw` is
`new_raw_checked(..).expect("Expect correct bytecode")`, and it refuses bytes beginning
`0xef01` — EIP-7702's magic — that are not a 23-byte delegation. Code like that predates
EIP-3541, which stopped `0xef` deployments at London, and a handful of such accounts exist
on mainnet. S24's `run` called `new_raw` on every account's code.

In a guest that is worse than an error: `guest_sdk`'s panic handler writes to fd 2, which
is not a provable ecall, so a panicking run is one no proof can cover
(`docs/spec/public-values.md` §9). Both `WitnessDb` and the recorder use
`new_raw_checked` now, and the failure is a named error on both sides.

### The mini-block journal does not distinguish every witness

Found by a test whose premise was too strong. A sweep that changed each recorded storage
slot by one bit and required the journal to move failed on 1 of 37 slots: the callee reads
that slot and then **overwrites it unconditionally**, so its original value reaches nothing
observable.

That is a true fact about the workload rather than a gap in the binding, and it is worth
stating rather than asserting away. What a mini-block proof says is *"this VM ran revm over
this canonical witness and got this journal"* — and the journal distinguishes every witness
**the execution can tell apart**, which is not the same as every witness. The test now
moves a **balance** instead, which is always visible: every touched account's balance and
nonce are in the output commitment's post-state summary verbatim.

### A collapsing deletion needs a node `eth_getProof` cannot return

The finding that shapes the stateless mode, and it was established by measurement rather
than by reasoning: over 300 randomised trials of build-proofs-update-recompute, **87 (29 %)
needed a node no proof contained**.

When a key is deleted and the branch at the end of its path is left with exactly one child,
that child must be merged upward — which needs its **type and path**, not just its hash.
The child is a *sibling* of the deleted key, so it is not on that key's path and therefore
not in its proof. Supplying exactly the missing siblings fixed all 300; they were 104
leaves, 1 extension and 3 branches, so all three merge arms are live.

**This is not a corner case.** EIP-6780 made account `SELFDESTRUCT` rare, but writing zero
to a storage slot *is* a deletion and the gas refund makes it common.

The endpoint cannot close it directly. `debug_executionWitness` is not served on this
plan; `debug_dbGet` **is** reachable but answers `pebble: not found` for a trie node hash,
because Geth's path-based state scheme does not key nodes by hash; and `eth_getProof`
takes a *preimage*, so a node identified only by its trie-path prefix cannot be asked for.
The remaining route is a second proof round at the **post-state**, from which the
pre-collapse sibling is recoverable by un-merging — and safely, because the guest
authenticates whatever it is handed against the hash the parent branch holds, so the
recorder's reconstruction is a heuristic with a hard check behind it.

`mpt::MptError::BlindedCollapse` is the guest's half: it names the hash and stops, rather
than guessing a shape and producing a silently wrong root.

---

## 5. Deviations, and the rules they touch

1. **A trait generic in a guest.** `revm_block::run_against<DB: revm::Database>` is
   generic over revm's own database trait. Master anti-goal 2 bans trait generics and names
   what it is about — the proving stack's field, polynomial, commitment and transcript
   types — and this is none of those: it is workload code parameterised the way revm itself
   is built. Anti-goal 3's rule is met in the direction it asks for, the second caller
   (`host::recorder::WitnessRecorder`) existing before the generic did. The alternative was
   two block executors to keep equal, which would have made "the guest agrees with native
   revm" a comparison of two implementations rather than one implementation over two
   databases.
2. **`std::thread::sleep`, once.** The RPC client's exponential backoff. Anti-goal 7 bans
   threads; `sleep` spawns nothing and blocks the caller, which is the whole of what a
   backoff is. It is the only occurrence in the workspace.
3. **The deferred suites ran locally, not on the rented box.** The stage's *Rented
   Infrastructure* paragraph says *"from this stage onward, we'll also test all 'heavier'
   including 'DEFERRED' test groups on development server"*, and `../apogee-aws` is present,
   so the paragraph applies. The owner's decision at the mini-block gate was **not to
   provision anything** — §9 — so the mini-block gate and the bench report were measured on
   the 18-core / 48 GB laptop instead, at `RAYON_NUM_THREADS=6`. Both fit; the numbers say
   which machine they are from, as every number in this repository does.
   `./scripts/status.sh` reported no instance at the start of the stage and reports none
   now.
4. **`tools/bench` now has committed output.** Its `CLAUDE.md` said *"no assertions, no
   thresholds, no committed output"*, and the stage requires a report committed to this
   note. The crate's other rules stand, and the one assertion the `prove` verb makes is
   that the proof verifies — a timing for a proof that does not verify is not a measurement
   of anything.

---

## 6. The two new dependencies

Master rule 2's runtime list is exhaustive, so both are argued rather than assumed.

**`serde_json`.** JSON is the RPC wire format and `eth_getProof`'s response is a nested
object of hex-string proof arrays; parsing it is not "write the eight lines yourself".
Master rule 2 names *serialization* among the allowed runtime dependencies, and this is the
second entry under it after `serde`/`postcard`. Must-be-exact 7 independently asks for
`BenchReport` to be "a flat serde struct" emitted as machine-readable JSON.

One unification question was checked rather than assumed. `tools/transcript-ref` sits
outside the workspace precisely so its graph cannot feature-unify `serde/std` into
`crates/field`, which must stay `no_std` for the guest target. `serde_json 1.0.151`
depends on **`serde_core`**, not `serde`, and its `std` feature enables `serde_core/std` —
so `serde/std` stays off and the flag `crates/field` compiles under does not move. The
`serde` entries in `crates/host` and `tools/bench` ask for `["derive", "alloc"]` and
deliberately not `std`, which is what `guests/revm-block` already asks for.

**`curl`, through `std::process::Command`.** Every mainnet endpoint is TLS-only. This
workspace has no HTTP client, no TLS and no async runtime, and anti-goal 7 bans `tokio` by
name; `ureq` clears that but brings a TLS crypto library and about thirty crates into a
repository whose premise is owning its cryptography. Hand-rolling TLS is not what "own the
crypto" means — that is about the *proving system's* cryptography.

So the JSON-RPC client is ours and only the HTTPS bytes are `curl`'s, spawned exactly as
this repository already spawns `cargo`, `qemu-riscv32` and `llvm-objdump`. It is an
undeclared host tool of the same class as those and, like them, reachable only from a
manual path that CI never runs. **One caveat stated rather than hidden:** the endpoint
carries an API key and is passed on `curl`'s command line, so it is visible in `ps` output
on the machine doing the refresh. The request body goes over stdin.

---

## 7. Measurements

All on an 18-core / 48 GB Apple M5 Pro laptop at `RAYON_NUM_THREADS=6`, guest at
`--release`, key over the **real ceremony** (PSE contribution 80, `2^22` of
`ppot_0080_24.ptau`).

### The `BenchReport`, committed as the stage asks

The machine-readable half is `docs/handoff/reports/S25-mini-block.json`, exactly as the
`--json` flag wrote it — 26 flat fields. The human half is below.

```
block
  fixture                  mini-block (mini)
  number                   26057509
  hash                     0xaa564e43eee9604a0051b58c0995fe7f79c557c71d49faf31019e9d47ac97dc5
  transactions             2
  gas used                 392997
  identity                 47404735c5b5e1df69824eedf6cc806faa6e1ba5c65920b26e61c45569148f2d
  srs                      PSE perpetual powers of tau, contribution 80, 2^22

execution
  guest cycles             24206626
  cycles per gas           61.6

proof
  ADD_SUB_LUI_AUIPC        8        MEM_SUBWORD              2
  JUMP_BRANCH_SLT          6        ATOMICS                  1
  SHIFT_BITWISE            3        INIT_TEARDOWN            1
  MUL_DIV                  2        ZERO_WINDOWS             1
  MEM_WORD                 5        KECCAK_F                 5
  PUBLIC_INPUT             1        PUBLIC_OUTPUT            1
  ADVICE_WINDOWS           1
  shards                   37
  proof bytes              61323886
  statement bytes          122626

timing (ms)
  setup                    28052.9
  phase: execution          4280.7
  phase: commit           131661.7
  phase: gkr              620719.7
  phase: opening           90000.2
  phase: final                26.5
  phases total            846688.8
  unattributed              3231.7
  proving (wall)          849920.5
  verify                    9582.0

memory
  peak rss                 34.1 GiB   (/usr/bin/time -l; the report says None on macOS
                                       and names this as the ground truth)
cost
  hourly price (USD)       2.3600     the r8i.8xlarge's on-demand rate, for comparability
  cost (USD)               0.5572     = 2.36 * 849920.5 / 3600000
  cost per Mgas (USD)      1.4177

hardware
  Apple M5 Pro, 18 logical cpus, 48 GiB, macos aarch64, rayon 6
```

Two notes on reading it. The **cost is a formula over two fields of the report**, which is
must-be-exact 7's requirement, and the hourly price is an input rather than a measurement —
it is quoted at the rented box's rate so the number is comparable, not because this ran
there. And the **phases do not sum to the wall clock**: `ProverSetup::new` is outside every
phase and is reported separately, and the 3.2 s remainder inside `proving_ms` is the plan
check, the final assembly and the archive bookkeeping between phases, reported as
`unattributed` rather than absorbed.

### What the shard count says

**37 shards for 393,000 gas.** S24's synthetic block was 9 shards for 50,000 gas of
transfers and one `SSTORE`; these are two ordinary mainnet contract calls, and they cost
**61.6 guest cycles per unit of gas**. That ratio is the number the next stage wants, and
it is the first time this repository has had one measured on real transactions.

### The stateless mode

| | |
| --- | --- |
| synthetic block | 8 accounts, 7 trie nodes, 2 withdrawals, a 2,238-byte witness |
| post-state root | `a20c0e46794c9743ae0eb243312318bed5ea192c4d7d427d60d66a7764ddf16d` |
| journal | **148 bytes**, fixed, whatever the block |
| guest | recomputes that root in **665,154 cycles** |
| real authentication | **17 real accounts and 37 real slots** against block 26,057,508's real state root `e04c464b…` |
| negative controls | **210 of 210** real nodes corrupted in turn and refused; **210 of 210** dropped and refused *as missing rather than as absent* |

### The full block, extrapolated — the numbers behind §9

The pinned block is 27,971,256 gas, **71× the mini-block**. At the measured 61.6 cycles per
gas that is **~1.72 billion cycles** and **~1,900 shards**.

**Time is not the problem.** At 115 core-seconds a shard, 32 vCPUs give about **1.9 hours**
and, at $2.36/h, about **$4.50**.

**Memory is, and it is structural rather than a thread-count setting.**
`prover::statement_inputs` builds **every** shard's memory columns and
`global_commit_phase` commits them all, so they are live simultaneously — before a single
shard is proved, and independent of how many workers there are. Measured at ~300 MB a shard
of trace plus memory columns (11 GiB observed across 37 shards, before the GKR region).
At ~1,900 shards that is **500–600 GB resident**. An `r8i.8xlarge` has 256 GB.

---

## 8. The refresh procedure

```
ETH_RPC_URL=https://… cargo run --release -p kat-gen -- block
```

Records the most recent **finalized** block's first two transactions into
`crates/host/tests/vectors/`, checks three further recent blocks live against the guest,
and re-records the pinned one from the cache alone to prove the recording deterministic.
The endpoint is read from the environment and never written anywhere.

What the session writes, and what it does not: the pinned block's witness, journal, pin
and **its** RPC cache are committed; the three checked blocks' responses go to a scratch
cache under `target/` and are not.

---

## 9. What was run, and the two acceptances that were not

### Acceptance 7 — met on the guest, and on real data for the half that can be

The three claims are *"the guest-recomputed post-state root equals the header's state
root"*, *"corrupting one MPT witness node makes the guest reject"* and *"corrupting one
account balance flips the recomputed root and the guest asserts out"*. All three pass, over
**two** fixtures, because no single one can carry both halves:

- **Authentication runs on real mainnet data**, where a real state root is the oracle: the
  pinned mini-block's 17 accounts and 37 slots, against block 26,057,508's own
  `e04c464b…`, from 210 nodes `eth_getProof` returned. Every one of those 210 corrupted in
  turn is refused, and every one dropped in turn is refused **as a missing node rather than
  as an absence** — the line that, got wrong, would let anyone prove any key absent by
  truncating a witness.
- **The transition runs on a synthetic block**, whose node set is complete by construction.
  The guest recomputes its root in 665,154 cycles; every node corrupted in turn is refused,
  and every account's balance corrupted in turn is refused as `Unauthenticated` — *before*
  the block runs, which is the stronger answer than a root mismatch.

**What is not done is the pinned full block's own header-root comparison**, and the reason
is §4's sibling gap: a witness recorded from this endpoint cannot be complete, so the
recomputation half has no real block to run on. That is a limitation of the witness source,
not of the guest — the trie code is the same code either way, and it is held to Ethereum's
three published root vectors, to real mainnet authentication, and to the whole transition.

### Acceptance 8 — not run, by the owner's decision

The measured extrapolation in §7 put the pinned block at ~1,900 shards and **500–600 GB
resident during the commit phase alone**, against the `r8i.8xlarge`'s 256 GB — and the
constraint is structural, not a thread-count setting, because `statement_inputs` builds
every shard's memory columns before any shard is proved. Put to the owner with those
numbers and four options; the owner chose **not to prove the full block** and not to rent
anything. `../apogee-aws` therefore has no instance and none was created: `status.sh`
reported none at the start of the stage and reports none now.

### Everything above the line, green

```
cargo fmt --all -- --check                      (and the three out-of-workspace manifests)
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p prover --all-targets --features metrics -- -D warnings
(cd crates/guest-sdk && cargo clippy --target riscv32imac-unknown-none-elf -- -D warnings)
(cd guests && cargo clippy --bins -- -D warnings)
cargo test --workspace
cargo test -p prover --features metrics --test metrics
cargo build -p field -p constants ... --target riscv32imac-unknown-none-elf
cargo run -p kat-gen  then  git diff --exit-code -- <every vectors directory>
```

Named in CI and run here:

```
APOGEE_GUEST_PROFILE=release cargo test -p emulator --test revm -- --ignored --skip a3_
cargo test -p host --test stateless -- --ignored          2 passed, 35 s
```

Deferred, run here at `RAYON_NUM_THREADS=6`:

| suite | result | wall clock | peak |
| --- | --- | --- | --- |
| `cargo test --release -p host --test prove -- --include-ignored --test-threads=1` | **3 passed** | 5,090 s | **34.9 GiB** |
| `cargo run --release -p bench -- prove mini-block --hourly-usd 2.36 --json …` | the report in §7 | 905 s | **34.1 GiB** |

The suite proves the statement **five times** — two tests, then the tamper harness's honest
run and its two twins, both of which move a `PolyAddress::Memory` cell and so re-prove the
whole block — which is why 85 minutes buys three assertions. The thread bound is not
optional: shard proving is the block's one parallel step and its peak is one shard's
forward pass per worker, and unbounded on 18 cores this does not fit 48 GB.

`a5`'s two halves are the whole of what a mini-block proof binds. One advice cell moved is
`MemoryArgument` — the execution's load of that word read the honest value, so the read
tuple matches no write and the roots do not reconcile. The **control**, a row the guest
never read with both its init and teardown values moved together, **verifies** — which is
what "nothing binds advice" means in cells rather than in prose, and why the guest checks
its own witness.

### The refresh session

```
ETH_RPC_URL=… cargo run --release -p kat-gen -- block
```

Recorded block 26,057,509 (69 network calls), collected its 210 authenticating trie nodes
(8 more), checked blocks 26,057,508 / 507 / 506 live against the guest, and re-recorded the
pinned block from the cache alone: **0 network calls, byte-identical**.

---

## 10. For the next stage

- **`BlockWitness` is still not frozen**, and `StatelessWitness` (§1.5) is new rather than
  frozen. What a change must keep is §1.1: the field order is the canonical order and
  `decode` re-encodes and compares, so one logical state has exactly one encoding.
- **The witness source is the blocker for real stateless blocks, and it is a source
  problem rather than a guest problem.** `eth_getProof` cannot supply the siblings a
  deletion needs. What closes it is an execution-layer client serving
  `debug_executionWitness`, or any other producer that can return the nodes a block's
  updates touch. The guest is ready for one: it authenticates every node against the hash
  that names it and refuses by name when one is missing.
- **The prover's commit phase caps the provable block size, independently of hardware.**
  `statement_inputs` builds every shard's memory columns and `global_commit_phase` commits
  them all, so peak memory during that phase is O(total shards) — ~300 MB a shard, measured.
  That is what puts a 27.9M-gas block at 500–600 GB before a single shard is proved.
  Streaming that phase would lift the cap for every future block and is its own stage: it
  changes no transcript and no proof byte, only the order in which columns are built.
- **61.6 guest cycles per unit of EVM gas**, measured on two ordinary mainnet contract
  calls. The first such number this repository has, and the one to check the next workload
  change against.
- **The mini-block journal is 45 bytes a transaction**, which is why the stateless mode
  publishes a digest instead. Anything that grows the mini mode's per-transaction record
  runs into the 1,020-byte window sooner.
- **`WITNESS_CAPACITY` no longer bounds anything the provable binaries read.** It is the fd
  0 buffer `src/stdio.rs` uses, and the two advice-fed binaries decode the region in place.
  A recorded witness is 135 KB where the synthetic one is 723 bytes, so the constant is now
  the compatibility binary's alone.
