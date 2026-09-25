# S25b — the ADVICE region

A read-only, prover-supplied address space a guest reads with ordinary loads, so that a
large execution witness reaches a guest without one ecall per word, without a second copy
in RAM, and without being hashed into `io_digest`.

`docs/spec/advice.md` is the page and it is normative from this note onwards. What follows
is what landed, what it costs, what it is worth, and what it is deliberately not.

**The target architecture, as the stage prompt stated it:**

```text
small public inputs   -> fd 0   -> S25a binding
small public outputs  -> fd 1   -> S25a binding
large private witness -> ADVICE -> the guest validates it against public commitments
```

All three lines are built. The third line's *validation* is built for `guests/revm-block`
only, and only partially: it checks which block the witness claims to be and nothing about
its state. §7 is exactly what that proof does and does not say, and it is not to be
softened.

---

## 1. The mechanism, end to end

| | |
| --- | --- |
| Address-space tag | `constants::address_space::ADVICE = 7` |
| Range | `[0x8000_0000, 0x1_0000_0000)` — `guest_memory::ADVICE_ORIGIN`, `ADVICE_LENGTH` |
| Reached by | an ordinary `lw`, `lb`, `lh`, `lbu`, `lhu`. No new instruction, no new ecall |
| Writable | never, by any query of any family |
| Chains | yes — a read is held to the last write at its address |
| Initialized by | `family::ADVICE_WINDOWS = 12`, one shard per window, from a **free** committed column |
| In identity | no, deliberately: `program::setup_commitments` returns an empty list for it |
| In the statement | only its extent, as `SHARD_COUNTS`' entry at that family's position |

**The address decides the space, totally.** `RAM_ORIGIN + RAM_LENGTH` is exactly
`0x8000_0000` and `check_memory_windows` caps a RAM window id at the same ceiling in
window units, so the upper half of the address space was already unreachable by guest RAM
on both sides — the linker's and the argument's. Putting advice there makes the selector a
bit that already existed.

**The selector is `word_index_hi`'s bit 13.** `docs/spec/memory-ops.md` §2 already bounds
`word_index` below `2^30` with three `RANGE16` obligations, so `addr ≥ 2^31 ⟺ word_index ≥
2^29 ⟺ bit 13 of `word_index_hi``. The two load families re-split that column about the
bit rather than comparing against a base: one boolean, one degree-1 split, and the old
`4·word_index_hi` obligation becomes `8·word_index_hi_rest`. Same bound, same tightness at
the top of the address space, no comparison gadget, no gap column.

**The tag reaches the leaf through an `M` column.** `check_memory`'s provenance rule
refuses a `W` column in a memory leaf, and `is_advice` is a `W` column. So the frame
carries `load_space` at `M[1 + 5w]`, pinned to the witness selectors by a
literal-coefficient gate that carries no memory challenge and is therefore outside the
rule's reach. This is exactly the repair `docs/spec/delegation.md` §5.1 made for
`deleg_space` at S21, and it takes the **same column position**: no frame holds both
queries, and `constraints::memory::assemble` asserts that rather than trusting it.

**Read-only is mostly structural.** Only the `load` query carries the advice tag, and
`load` is in `FRAME_READ_ONLY`, so it already carried `write_value − read_value = 0` in
every family. A store and an atomic use the `ram` query, whose space term is the literal
`RAM`. `no_store_to_advice` (`m_ram · is_advice = 0`) is added anyway in the two families that
have an `is_advice` bit, so the refusal there is `Constraint`-class and names a gate
rather than `MemoryArgument`-class and naming nothing. `ATOMICS` has no such bit and keeps
only the global refusal, which is a deliberate asymmetry: giving it the local one would
mean a space column on the `ram` slot plus an exclusion gate over all eleven arms, to make
an already-impossible execution fail one step earlier with a better message.

---

## 2. The soundness argument

**Nothing outside the guest constrains an advice word.** The initial value is a free
committed `M` column of `ADVICE_WINDOWS`: no gate, no statement field and no identity
digest says what it must be. A proof over advice says

> there exist advice contents under which this program, on this public input, produced
> this public output and exited with this status.

That is strictly weaker than the same program on public input, and it is worth exactly
what the guest checks the advice against.

**What the argument *does* give, unconditionally:**

- **Consistency.** Repeated reads of one advice word agree. The init write is stamped 0,
  the first read consumes it and writes back what it read, and every later read chains to
  the write before it — the same mechanism that makes RAM consistent, with no exception
  for advice. A prover cannot answer one address with two values.
- **Read-only.** No query of any family can write the region: a store into it is refused
  locally by a gate, fatally by the executor, and globally by the multiset.
- **No aliasing.** The region is disjoint from RAM by address and from every other space
  by tag. Disjoint *addresses* are the load-bearing half: distinct tags already keep the
  multiset from confusing a RAM tuple with an advice one, but only disjoint ranges stop a
  guest pointer walking from one region into the other, since `p + n` is arithmetic and
  not a tuple.
- **Bounded contents at the point of use.** A window family carries no lookup channel, so
  an advice word's committed value is an unconstrained field element rather than a bounded
  `u32`. That is sound because **every reader bounds what it reads**:
  `docs/spec/memory-ops.md` §5.1's write-side induction makes `mem_word`'s `rd_selected`
  carry a 16+16 pair even though it is a copy, and `mem_subword` bounds what it splices.
  It is nonetheless a **standing obligation on every future consumer** — a family that
  learns to read advice and does not bound what it read inherits a hole — and
  `docs/spec/advice.md` §5.1 is where that debt is recorded.

**What it does not give** is any statement about the *contents*. That is the guest's job,
and §7 is the current state of it.

---

## 3. What it costs in circuit

Per 4-byte word of witness consumed:

| | fd 0 `read` (S25a) | advice (S25b) |
| --- | --- | --- |
| guest cycles | one `ecall` row plus SDK marshalling | one load |
| RAM writes | one — the copy into the guest's buffer | none |
| committed memory rows | RAM init + the copy's write + the read | advice init + the read |
| `io_digest` | Poseidon2 over the **whole** stream, at exit | none |

**The honest claim is not "free random access".** An advice word is still one init tuple
in a committed window shard, so the shard count still grows with the witness — one
`ADVICE_WINDOWS` shard per `4h` bytes at the one window height `h`. A megabyte of advice is
a megabyte of committed columns, exactly as a megabyte of RAM is. What disappears is the
ecall, the second copy, the whole-witness hash, and the Poseidon2/Fr delegation growth
proportional to the witness.

**The per-family circuit cost**, all of it in the two load families:

| | before | after |
| --- | --- | --- |
| `mem_word` memory columns | 31 | 32 |
| `mem_word` witness columns | 24 | 26 |
| `mem_word` committed columns | 62 | 65 |
| `mem_word` enforcing gates | 33 | 37 |
| `mem_word` `RANGE16` obligations | 5 | 6 |
| `mem_subword` memory columns | 31 | 32 |
| `mem_subword` witness columns | 55 | 57 |
| `mem_subword` committed columns | 96 | 99 |
| `mem_subword` enforcing gates | 53 | 57 |
| `mem_subword` `RANGE16` obligations | 22 | 23 |

`ATOMICS` is unchanged: it has no `load` query, its `ram` slot's space is the literal
`RAM`, and an atomic read-modify-write on a region nothing may write has no meaning.
Refusing it costs nothing and admitting it would cost a per-row space column plus an
exclusion gate over all eleven arms.

`ADVICE_WINDOWS` itself is `ZERO_WINDOWS`' circuit with one more `M` column: three
committed columns, one virtual table, two unmasked leaves, no enforcing gate, no lookup,
two outputs.

**Five committed fixtures moved across the stage, and one is new.**

| | why |
| --- | --- |
| `constraints/…/memory_frame_mem.bin` | the two memory families' frame gained `load_space` |
| `constraints/…/mem_word.bin`, `mem_subword.bin` | two columns and four gates each |
| `checker/…/global_tape.txt` | one more `MEMORY_GROUP` header, and two more scalars in the descriptor |
| `program/…/identity.txt` | `VM_CONFIG` lists one more family, so every identity moved |
| **new**: `constraints/…/advice_window.bin` | the family's artifact at `trace_vars` 22 |

The first three landed with the circuit at `3bb603c`; the last three are this commit's.

**Both existing window artifacts, the other three frames and the four other families are
byte-identical**, which is the containment worth checking: a change that moved them would
be a change to something this stage did not touch.

---

## 4. What it costs in surface

The one thing worth recording as a *saving*: **the advice blob reaches the prover through
execution and not through proving.** `build_advice_window_columns` reads the memory log
alone — advice is read-only, so `final_state()`'s value for an advice word *is* the blob's
word, and a word the execution never read is 0 in both columns and cancels. So:

- `TraceArchive` gained no field and its wire form did not move;
- `IoStreams` gained no field, and stayed "the two **committed** streams";
- resume works unchanged, and no archive fixture churned;
- `ProverSetup` and `prove_block` took no new argument.

Only `emulator::GuestIo` and `host::execute`/`host::prove` had to grow, because those are
where the execution happens.

`window_challenges` gained an address-space parameter, which is the one signature in the
no_std verifier core that moved. That was forced: a *new* challenge slot would fall outside
`check_memory`'s `global()` range and silently disable all four of its provenance rules,
so the space had to go where the literal `RAM` already was.

**Every program's identity moved, and that is the one consequence a reader should not
skim.** Program identity absorbs the `VM_CONFIG` message, which lists the families and
their heights; `ADVICE_WINDOWS` is in every `VmConfig`; so every program derives a
different identity than it did at S25a. `crates/program/tests/vectors/identity.txt` is
re-pinned accordingly — `fib default` `b05ee2cd…` → `ba8d210c…` and `fib smallest`
`cf595f47…` → `98e929fd…`.

That is unlike S21's and S23's family additions, which moved identity only for programs
that *declared* the new family. It is the price of the presence rule, it was the owner's
decision, and nothing is published yet — but a stage that ships identities to anyone must
know that this one invalidated every earlier one.

**What else cost surface, and it is the largest single consequence by volume**:
`ADVICE_WINDOWS` is in every `VmConfig`, so every program's family set grew by one. That
moved every hand-built config, every pinned shard-count vector, the `VM_CONFIG` and
`SHARD_COUNTS` message lengths, the `PublicInputs` byte offsets, one more `MEMORY_GROUP`
header in G8, and the committed global-tape fixture. None of it is a soundness change and
all of it is mechanical — but it is why this stage touched 76 files to add one circuit,
and a reader diffing it should expect that ratio rather than look for what they missed.

---

## 5. What was decided, and what was withdrawn

- **ADVICE = 7**, the next tag in the sequence. The delegation tags ceasing to be
  contiguous costs nothing: every reader that must recognise a delegation anchor consults
  `address_space::DELEGATION`, which is an explicit list.
- **Contiguous windows, no id list.** Shard `i` *is* advice window `i`. That is why advice
  needed no new transcript tag, no new `PublicInputs` field and no amendment to the frozen
  absorb order. A sparse advice map would have needed all four, for flexibility nothing
  asked for: advice is a blob and a blob has no holes.
- **`ADVICE_WINDOWS` is in every `VmConfig`**, proving zero shards in a run that reads no
  advice. It is a window family, which is `decode_program`'s presence rule 2, so it joined
  without a fourth rule. `constants::family::WINDOW_FAMILIES` is the list every reader now
  consults.
- **Withdrawn, then reinstated at the owner's instruction: one height for all three window
  families.** The first draft made `window_height` hold `ADVICE_WINDOWS` to the RAM
  families' height; it was withdrawn mid-stage on the reading that the rule binding
  `INIT_TEARDOWN` and `ZERO_WINDOWS` exists only because they tile *one* region between
  them, which advice does not. The owner reinstated it after the stage's first PR, and the
  second argument — the one the withdrawal missed — is what carries it: the advice region's
  stride is read **twice** on the prover's side, by `trace::advice_windows` counting the
  windows a log needs and by the fill sizing each one, and only a rule makes those the same
  number. `prover::statement_inputs_rec` already derived `h` once and handed it to the
  count while the fill took the family's registered height, so the independent-height
  design had the statement's shard count and the shard's own contents able to disagree
  about where a window ends. `window_height` now covers
  `constants::family::WINDOW_FAMILIES` whole, and `check_memory_windows` states RAM's ids
  and advice's extent in the same `h`.
- **Advice guests drop out of the QEMU suites** (owner's decision). A host loader maps
  only the image's `PT_LOAD` segments and advice is in none of them, so the region is
  unmapped and the first load faults. `crates/emulator/tests/revm.rs::
  a3_the_two_executors_commit_the_same_bytes` is **retired**; what it established — that
  the delegated keccak and the SDK's software fallback compute one function — is
  `a5_every_delegated_permutation_is_the_reference`, which checks it directly and needs no
  emulator. Every non-advice guest keeps its QEMU coverage.

---

## 6. Measured

On this laptop (Apple silicon, 18 cores). **Execution only**; the proving numbers are the
deferred batch's and are not re-taken here.

### 6.1 `guests/revm-block` end to end, at `--release`

The same guest, the same 717-byte `BlockWitness`, the same output commitment. What moved
is where the witness arrives.

| | cycles | what fd 0 carries |
| --- | --- | --- |
| S24, witness embedded in `.rodata` | 221,239 | nothing; no `io_digest` at all |
| S25a, witness on fd 0 | 388,598 | 717 bytes, all of it hashed at exit |
| **S25b, witness in advice** | **272,516** | **76 bytes**, and only those hashed |

`crates/emulator/tests/revm.rs::a9_the_cycle_and_occupancy_report` prints it.

**S25a's public-I/O binding cost 167,359 cycles on this workload. S25b gives back 116,082
of them — 69% — and keeps the binding.** What is left is the 76-byte header's own digest
and the output commitment's, which is what the binding is actually for. The residue over
S24 is 51,277 cycles, and it buys a statement that says which block ran and what it
produced, where S24's said neither.

Per family at `--release`, after:

```text
cycles: 272,516
  ADD_SUB_LUI_AUIPC  88,068     MEM_WORD      75,086     KECCAK_F    7 invocations
  JUMP_BRANCH_SLT    50,375     MEM_SUBWORD   25,610     POSEIDON2   6
  SHIFT_BITWISE      30,540     ATOMICS           62     FR_ARITH   60
  MUL_DIV             2,775
  RAM windows above 0: [511]      advice windows: 1
```

**Six Poseidon2 invocations and sixty `Fr` ones**, for a 76-byte fd 0 stream and a
two-transaction output commitment. That is the term §3 calls dominant, and it is now a
function of the *public* streams rather than of the witness: a megabyte of advice adds
nothing to it.

**One `ADVICE_WINDOWS` shard**, not zero: the 717 bytes fit inside a single `2^20` window,
whose other 4,194,187 bytes are rows that cost an init tuple and a teardown tuple and
cancel. That is the floor this mechanism has, and at this witness size it is the whole
cost — which is the case where advice is *least* favourable, and it still wins.

### 6.2 The mechanism in isolation

`cargo run --release -p bench -- advice`, over hand-encoded programs summing the same
words through each path. No SDK, no `io_digest` — this is the per-word transfer and
nothing else.

| words | bytes | fd 0 cycles | fd 0 c/word | advice cycles | advice c/word |
| --- | --- | --- | --- | --- | --- |
| 256 | 1 KiB | 1,545 | 6.04 | 1,286 | 5.02 |
| 4,096 | 16 KiB | 24,585 | 6.00 | 20,486 | 5.00 |
| 16,384 | 64 KiB | 98,313 | 6.00 | 81,926 | 5.00 |
| 65,536 | 256 KiB | 393,225 | 6.00 | 327,686 | 5.00 |
| 262,144 | 1 MiB | 1,572,873 | 6.00 | 1,310,726 | 5.00 |

**1.20× flat**, which is the honest number for the loop alone: an `ecall` row and an `a0`
reset against nothing. It is a *floor*, not the figure of merit — a real guest reads
through `guest_sdk::read_input`, which also appends every byte to the public-input stream,
and then hashes all of it at exit. §6.1 is where both of those are present, and there the
same change is worth 30%.

The shard plans diverge at the top size, and that is the second thing worth seeing:

```text
262,144 words (1 MiB)
  fd 0    ADD_SUB x2  JUMP_BRANCH_SLT x1  SHIFT_BITWISE x1  MEM_WORD x1  INIT_TEARDOWN x1
  advice  ADD_SUB x1  JUMP_BRANCH_SLT x1  SHIFT_BITWISE x1  MEM_WORD x1  INIT_TEARDOWN x1  ADVICE_WINDOWS x1
```

The fd 0 path needs a **second `2^20` add/sub shard** — the ecalls alone push that family
past its height — where advice needs one advice window shard instead. A `2^20` execution
shard and a `2^20` window shard are not the same price: the window artifact is three
columns and two leaves against add/sub's 42 memory columns, 35 witness columns and 100
leaves. Trading one for the other is the whole mechanism in one line.

---

## 7. `guests/revm-block`: what its proof says, exactly

```text
fd 0    advice_len, chain id, block number, parent hash   76 bytes, public, bound
ADVICE  the whole BlockWitness                            private, PARTLY CHECKED
fd 1    the output commitment                             public, bound
```

The guest's one check of the advice is `BlockWitness::matches`, which recomputes the
76-byte header from the decoded witness and compares it whole; a mismatch is exit 63.

**That check fixes which block the witness claims to be — chain, height, parent — and it
fixes nothing about the accounts, the storage, the code or the transactions.** There is no
state root here to validate them against: the committed witness is a synthetic pre-state
and has none. So the proof says

> there exist accounts, storage, code and transactions under which the block at this
> height on this chain, with this parent, executes to this output commitment

and it does **not** say that those accounts are Ethereum's at that block, nor that those
are the block's transactions.

**Both halves of that matter, and the second is a reduction.** The transactions moved into
advice with the rest of the witness, so what was public and bound at S25a is private and
unchecked now. That is the price paid for §3's savings, it was paid knowingly, and it is
recorded here rather than left for a reader to notice.

Closing the gap needs a Merkle-Patricia validator in the guest, a transaction root in the
header, and a witness recorded from a real block. `crates/host`'s `WitnessRecorder` already
carries `parent_state_root`, which is where the state check will anchor.

---

## 8. Deviations and debts

1. **No padding to a fixed window count.** `trace::advice_windows` derives the extent from
   the highest advice word the execution *read*, not from the blob the prover supplied, so
   the shard count leaks what was touched. `docs/spec/advice.md` §2.1 records padding as
   available and unbuilt; implementing it means an explicit count rather than a derived
   one.
2. **The range obligation `ADVICE_WINDOWS` does not carry.** §2 above: sound today because
   every reader bounds what it reads, a standing obligation on every future consumer, and
   undischargeable here without giving a window family its first lookup channel and so
   forcing its height off the menu's floor.
3. **`docs/spec/memory.md` §4.2's counting premise was stale and is re-derived.** It was
   written at `family::COUNT = 9` and named the family count as its re-check trigger. Two
   of its inputs had already moved: the family count, and "at most 16 leaves a row", which
   was the widest *execution* frame and has been wrong since S21 gave `KECCAK_F` a 50-word
   frame and 128 memory leaves. The bound is now `2^73` tuples and `2^111 < p`, a margin of
   `2^143`. The conclusion never changed; the arithmetic behind it had.
4. **Stale claims found while doing this, and fixed.** Each is recorded because the S25a
   audit was asked to find exactly this class and did not:
   - `block_hashes` landed in S25a and closed the `BLOCKHASH` gap, but the `BlockWitness`
     struct doc, `docs/spec/revm-block.md` §1.2, its §4 test table and the root
     `CLAUDE.md` all still described it as open and still named the retired
     `blockhash_reads_a_placeholder_today`.
   - `crates/prover/CLAUDE.md` gave add/sub's opening claim as `36 + 31 + 7`. That was
     S17's; `tests/control.rs:144` has asserted `42 + 35 + 7` since S23.
   - `docs/spec/memory.md` §4.2's "16 leaves a row" was the widest *execution* frame and
     has been wrong since S21 gave `KECCAK_F` 128 (item 3 above).
   - `docs/spec/constraint-manifest.md` §7.6's tightness argument cited a row that is a
     compressed `sw`, not the top-of-address-space one, and stated the "scaling by 2
     instead of 4" consequence backwards for the new split. Three `(§13)` references in §7
     pointed at `POSEIDON2` and meant the observations section.
5. **Two byte counts in the manifest are derived rather than measured.**
   `MEM_WORD`/`MEM_SUBWORD` at `n = 22` are the committed fixtures measured directly;
   the `n = 20` artifact and proof sizes were computed from the S25b delta and from
   `mem.rs`' frozen `proof_bytes` formula, cross-checked against S19's committed numbers.
   Read them off `family_circuit` when the deferred batch next runs.
6. **The advice path's only end-to-end proof is deferred.** `prover/tests/revm.rs` now
   proves one `ADVICE_WINDOWS` shard, and it is a `# DEFERRED` suite. The fast tests that
   stand in for it are in §9's list: the artifact proves and verifies at three windows
   (`gkr/tests/memory.rs`), the window constant carries the space and the origin, an
   advice tuple is arithmetically never a RAM tuple, and the two window rules have
   boundary cases in `program/tests/config.rs`.

7. **Raise with the owner, not actioned here.**
   - Whether this stage should be recorded as `prompts/S25b-advice.md`. `prompts/` is not
     edited unilaterally.
   - Seven `prompts/` lines and two handoff notes still describe the **withdrawn** QEMU
     register differential and the deleted `emulator/tests/differential.rs`:
     `prompts/S12-emulator.md:15,21,28,31,49`, `prompts/S24-revm.md:11`,
     `docs/handoff/S12-emulator.md:179,180,488` and
     `docs/handoff/S17-control-flow.md:222`. Handoff notes are historical records and
     arguably should stay as written; the prompts are the design authority and arguably
     should not.
   - `guests/shards` is still out of the output-oracle SUITE for a reason that is void.
   - Whether the revm public header should carry a **transaction root**, which would
     restore the binding §7 records as given up.
   - Whether §8.1's padding is wanted.

---

## 9. Where to look

| | |
| --- | --- |
| The spec | `docs/spec/advice.md` |
| The space and the family | `crates/constants/src/lib.rs` — `address_space::ADVICE`, `family::ADVICE_WINDOWS`, `family::WINDOW_FAMILIES`, `guest_memory::ADVICE_ORIGIN` |
| The executor | `crates/emulator/src/lib.rs`, `crates/emulator/tests/advice.rs` |
| The log | `crates/trace/src/log.rs` — `AddressSpace::Advice`, `writable`, `initial_value` |
| The circuit | `crates/constraints/src/memory.rs` — `advice_window_artifact`, `load_space`, `frame_query_takes`; `mem_word.rs` and `mem_subword.rs` — the four gates each |
| The window constant | `crates/gkr-verify/src/memory.rs` — `window_challenges`, `window_origin` |
| The columns | `crates/trace/src/memory.rs` — `build_advice_window_columns`; `crates/trace/src/lib.rs` — `advice_windows` |
| The prover | `crates/prover/src/fill.rs` — `advice_window`; `crates/prover/src/lib.rs` — `shard_counts`, `window_of` |
| The guest SDK | `crates/guest-sdk/src/lib.rs` — `advice` |
| The workload | `guests/revm-block/src/lib.rs` — `PublicHeader`, `public_header`, `matches` |
| The benchmark | `cargo run --release -p bench -- advice` |

### 9.1 The tests, and what each one is for

| | |
| --- | --- |
| `crates/emulator/tests/advice.rs` | 13 tests: what a load reads, that a second read chains to the first, that a store, an atomic, a read past the extent and a read with no advice supplied are each **fatal**, that misalignment is still `Misaligned`, that the two spaces' events stay apart, and that `trace::advice_windows` is the highest word read rounded up |
| `crates/checker/tests/mem_word.rs`, `mem_subword.rs` | four tamper cases each: a RAM load claiming the region, a bit that is neither 0 nor 1, the space column moved on its own, and a store into the region — each refused by the gate named |
| `crates/checker/tests/mem_fill.rs` | **the prover's fill on an advice load**, which no committed guest reaches: a hand-encoded program loading one advice word and one RAM word, so both sides of `advice_split` are in one trace, with every gate and obligation checked on both |
| `crates/gkr/tests/memory.rs` | the advice artifact **proves and verifies** at three windows; its two leaves are the tuples of their rows; the window constant is pinned at two windows and refuses a space with none; and an advice tuple is arithmetically never a RAM tuple |
| `crates/program/tests/config.rs` | the extent rule at its boundary — `n` windows accepted and `n + 1` refused, at two heights, the second reached by moving **all three** window families together — and, in `a_config_without_every_window_family_at_one_height_is_refused`, each of the three refused when absent and when apart, at derivation and at decode |
| `crates/verifier-core/src/statement.rs` (unit) | `the_window_height_is_every_window_familys_one_height`: the rule itself, each of `WINDOW_FAMILIES` apart and each absent |
| `crates/verifier-core/tests/reduce.rs` | an `ADVICE_WINDOWS` shard reads its own space at its own window, the index being the window; and advice window 0 is not RAM window 0 |
| `crates/prover/tests/revm.rs` | **`# DEFERRED`**: the one end-to-end proof, one `ADVICE_WINDOWS` shard in a twelve-shard block |
