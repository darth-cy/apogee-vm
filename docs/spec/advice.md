# The advice region

**Status: normative (S25b).** `docs/handoff/S25b-advice.md` is the stage's record and this
page is the specification it closes on. What is **not** frozen is §10: the revm guest's
split between its public header and its private witness is that guest's, not the
mechanism's, and the stage that validates a real block's state against a root will move
it. §2's argument, §3's addressing, §4's read-only rules, §5's family and §6's contiguity
are frozen.

A read-only, prover-supplied address space a guest reads with ordinary loads. It exists
so that a large execution witness — an Ethereum block's touched state, a Merkle proof
set, anything whose size is measured in megabytes — can reach a guest without being
copied, hashed, or carried one ecall at a time.

It is **private nondeterministic advice**. The verifier does not know its contents, does
not commit to them, and learns nothing about them beyond its extent. Everything that
makes a proof over advice *mean* something happens inside the guest, by checking advice
against values that are public.

---

## 1. The space

| | |
| --- | --- |
| Address-space tag | `constants::address_space::ADVICE = 7` |
| Address range | `[0x8000_0000, 0x1_0000_0000)` — `guest_memory::ADVICE_ORIGIN`, length `ADVICE_LENGTH` |
| Granularity | one 32-bit word; a query's address is the 4-aligned word's byte address, as for RAM |
| Chains | **yes** — a read is held to the last write at its address, so repeated reads of one word agree |
| Writable | **no** — by any query, of any family, ever |
| Initialized by | `family::ADVICE_WINDOWS = 12`, one shard per window supplied |
| Bound by identity | **no**, and that is the point (§2) |

### 1.1 Why the range is forced

`guest_memory::RAM_ORIGIN + RAM_LENGTH` is exactly `0x8000_0000`, and
`verifier_core::check_memory_windows` caps a RAM window id at `2^29 / h − 1`, which is
that same ceiling stated in window units. So the upper half of the address space is
already unreachable by guest RAM on both sides — the linker's and the argument's — and it
is the only span where a new memory region cannot collide with something.

**Disjoint addresses are load-bearing, not tidiness.** Distinct tags already make a RAM
tuple and an advice tuple unequal, so the multiset could not confuse them whatever the
addresses were. What distinct tags do *not* prevent is a guest pointer walking out of one
region and into the other: `p + n` is arithmetic, not a tuple. Disjoint ranges are what
make that impossible, and they are why an executor can recover a query's space from its
address alone — which is what lets the trace archive replay a row without storing a space
column, and what lets one `load` query serve both spaces.

### 1.2 Why tag 7

The tag is the next number the sequence was up to. `constants::address_space::DELEGATION`
is an explicit list, and every reader that must tell a delegation anchor from another
space consults that list rather than a range, so the delegation tags ceasing to be
contiguous costs nothing. The next delegation family takes 8.

---

## 2. The soundness argument, stated plainly

**Nothing outside the guest constrains an advice word.** Its initial value is a free
committed column of the `ADVICE_WINDOWS` family: the prover picks it, and no gate, no
statement field and no identity digest says what it must be. `program::setup_commitments`
returns an empty list for the family deliberately — committing the init column there
would put the advice contents into program identity, which is a public per-program
constant, and a program that could only ever be run on one blob would have neither
privacy nor generality.

So a proof over advice says exactly this:

> There exist advice contents under which this program, on this public input, produced
> this public output and exited with this status.

That is a *weaker* statement than the same program run on public input, and it is only
worth as much as what the guest checks. The pattern that makes it worth something is:

1. the guest reads a **public commitment** on fd 0 — a state root, a block hash, a Merkle
   root — which the statement binds through `io_digest` (`docs/spec/memory.md` §10);
2. the guest reads the bulk data from advice;
3. the guest **validates** what it uses against that commitment — a Merkle path, a
   signature, a hash preimage — and refuses otherwise.

Step 3 is the whole soundness argument. Without it, advice is a channel through which a
prover chooses what the program computes on, and a proof of such a run proves only that
*some* input gave this output.

**This repository has step 3 in a partial form and for one guest.**
`guests/revm-block` reads a public header on fd 0 and checks the advice's chain id,
block number and parent hash against it, which is step 3 for *which block this is*. It
does **not** validate the accounts, the storage, the code or the transactions against
anything, because the committed fixture is a synthetic pre-state with no real root to
validate against. That gap is deliberate, documented here and at
`docs/spec/revm-block.md`, and is not to be described as if it were closed. §10 states
exactly what that guest's proof does and does not say.

### 2.1 What the verifier learns

The extent, and only to window granularity: `shard_counts[ADVICE_WINDOWS]` is in the
statement descriptor, so a verifier knows the advice region spans that many windows of
`4a` bytes, `a` being that family's height. It learns nothing about the contents.

The count is derived from the **highest advice word the execution read**, rounded up to a
window (`trace::advice_windows`), and not from the blob the prover supplied. So a prover
that supplies a megabyte and reads the first word proves one window, and the count leaks
what was *touched* rather than what was offered.

**Padding to a fixed window count is not implemented.** A prover wanting to hide even
that much would supply a count rather than have it derived, and pay for the padding
windows; nothing in the prover's path takes such an argument today. It is recorded here
as available and unbuilt, not as a property this stage has.

---

## 3. How a load reaches the space

A guest reads advice with an ordinary `lw`, `lb`, `lh`, `lbu` or `lhu`. There is no new
instruction, no new ecall, and no new addressing mode; the address decides the space.

### 3.1 The selector is a bit that already exists

`docs/spec/memory-ops.md` §2 decomposes every memory address as `addr = 4·word_index
(+ 2·bit1 + bit0)` and bounds `word_index` below `2^30` with three `RANGE16` obligations,
the third of which — `4·word_index_hi < 2^16` — gives `word_index_hi < 2^14`. Then

```text
addr ≥ 2^31   ⟺   word_index ≥ 2^29   ⟺   bit 13 of word_index_hi
```

so the advice selector is the top bit of a column the memory families already commit and
already bound. It is split out rather than compared:

```text
advice_split        word_index_hi − 2^13·is_advice − word_index_hi_rest = 0
is_advice_bool      is_advice² − is_advice                              = 0
word_index_rest_scaled   8·word_index_hi_rest < 2^16      (RANGE16, under m_pc)
```

The scaled obligation gives `word_index_hi_rest < 2^13`, so the split is base-`2^13` and
`is_advice` is the address's bit 31 in **both** directions: an advice address cannot be
read as RAM, and a RAM address cannot be read as advice.

A comparison gadget against a configurable base would cost a gap column, its range
obligation and a degree-2 comparison per row. Putting the region on a power of two costs
one boolean and one re-split, and is the reason the base is not configurable.

### 3.2 The tag crosses into the leaf through an `M` column

A memory leaf may read no `W` column — `constraints::memory::check_memory`'s provenance
rule, `docs/spec/memory.md` §8 — because `W` is committed after the memory challenges, so
a leaf over one is chosen after them and balances any trace. `is_advice` is a `W` column.

This is the same wall S21 hit with delegation types, and the repair is the same one
`docs/spec/delegation.md` §5.1 made: the tag rides a **memory** column of the frame, which
the family pins to its witness selectors with a literal-coefficient enforcing gate.

```text
load_space  = M[1 + 5w]                       one more M column on the frame
load_space − RAM − (ADVICE − RAM)·is_advice = 0      degree 1, literal coefficients
```

The pin gate carries no memory-challenge coefficient, so `check_memory`'s provenance rule
does not reach it and it may read `is_advice` freely. The leaf reads only `load_space`,
which is `M`.

---

## 4. Read-only, and why it is mostly structural

**Only the `load` frame query carries the advice tag.** That query is in
`constraints::memory::FRAME_READ_ONLY`, so it already carries `write_value − read_value =
0` (`docs/spec/memory.md` §9): a load writes back exactly what it read, in every family,
and always did. Advice inherits read-only from the query it is reached through rather
than from a rule of its own.

A store and an atomic use the `ram` query, whose address-space term is the **literal**
`RAM` and cannot be anything else. So a store into the advice range stages a RAM-space
write at an address no RAM window initializes, and the global multiset refuses it: its
write has no reader and its read no writer.

That refusal is correct but late and global — `MemoryArgument` at `verify_shard` step 10,
naming no instruction. So each storing family also carries

```text
no_store_to_advice    m_ram · is_advice = 0        degree 2
```

which refuses the same execution locally, as `Constraint`, naming the gate. `m_ram` is the
`ram` query's own mask, which those two families raise on a store row and nowhere else.

**`ATOMICS` carries no such gate, and its refusal is the global one.** It has no `load`
query, so it has no space column and no `is_advice` bit; its `word_index_hi` is still
scaled by 4, which bounds the address below `2^32` and therefore *permits* bit 31. An
`lr.w` or an AMO at an advice address stages a **RAM-space** tuple there — the `ram`
slot's tag is the literal `RAM` — and no RAM window initializes an address at or above
`2^31`, so its read has no writer and its write no reader, and the multiset refuses it at
`verify_shard` step 10.

That is weaker than the two memory families' treatment: `MemoryArgument` at block level
rather than `Constraint` naming a gate. It is deliberate. Giving `ATOMICS` the local
refusal would mean a per-row space column on the `ram` slot plus an exclusion gate over
all eleven arms, to make an already-impossible execution fail one step earlier with a
better message. An atomic read-modify-write on a region nothing may write has no meaning
in the first place.

The emulator refuses the same three things fatally, before any event is staged, so an
execution the circuit could not prove is one no trace describes.
`trace::AddressSpace::writable` is the predicate both sides read, and the log's
self-check refuses a read-only space whose query wrote a value it did not read — the
executor-side twin of `FRAME_READ_ONLY`'s gate.

---

## 5. Initialisation: `ADVICE_WINDOWS`

The two RAM window families' third sibling, differing in exactly one thing — and sharing
neither their region nor their height (§5.0).

| Family | Window | Initial values |
| --- | --- | --- |
| `INIT_TEARDOWN` | RAM window 0 | the image column, `S[0]`; **identity commits them** |
| `ZERO_WINDOWS` | RAM windows above 0 | the literal `0` |
| `ADVICE_WINDOWS` | advice windows | **free**: `M[2]`, a committed column nothing constrains |

Everything else it shares: no pc, no cycle, no lookup channel, one shard per window,
`V[row]` addressing, and one init tuple per address by construction.

`M` is what the free column must be. `check_memory`'s provenance rule refuses a `W`
column in a leaf — `W` is committed after the memory challenges, so a leaf over one is
chosen after them and balances any trace — and `S` is bound by program identity, which is
where the privacy would go. An `M` column is committed in the memory phase, before the
challenges, and binds to nothing else.

`M[1]` (teardown) and `M[2]` (init) hold the same values in every provable trace, and no
gate says so: the `load` query's `write_back` gate copies each read's value into its
write, so the chain from the init write through every read to the teardown read carries
one value the whole way, and a prover that separated them would not balance. They are two
columns because the artifact mirrors its two siblings', not because a trace can tell them
apart.

**It is present in every `VmConfig`**, like the other two, and proves **zero** shards in a
run that reads no advice. That keeps `program::decode_program`'s three presence rules
intact — rule 2 is "the family is a window family", `constants::family::WINDOW_FAMILIES`
is the list, and this is one — at the cost of one more circuit in every verifying key and
one more group in every statement's G8. Its presence is a **statement** rule, checked in
`verifier_core::check_memory_windows` beside the shard counts, and not a decoding rule:
a config without it proves no advice shard and is unsound in no way, so `VmConfig::from_bytes`
does not need to know about it.

### 5.0 It does not share the RAM windows' height

`verifier_core::window_height` holds `INIT_TEARDOWN` and `ZERO_WINDOWS` to one height
because **they tile one region between them**, and a `ZERO_WINDOWS` height below
`INIT_TEARDOWN`'s would give an image word a second init row (`docs/spec/memory.md` §3.2).
Advice is a different region, tiled by this family alone, so that reason does not reach
it and no rule invents one: `ADVICE_WINDOWS` takes a height off the menu like any other
family, and its extent rule is stated in **its own** height — `ADVICE_LENGTH` is `2^31`
bytes, so at height `a` the region is `2^29 / a` windows of `4a`.

A first draft of this section required one height for all three. It was withdrawn before
the stage closed: it forced every test that varies the RAM window height to vary a third
family for no reason it could state, which is the shape of a rule that exists because it
was easy to write.

### 5.1 The range obligation it does not carry

A window artifact carries no lookup channel, and this one does not either, so an advice
word's initial value is an unconstrained field element rather than a bounded `u32`.

That is sound **because every reader bounds what it reads**: `docs/spec/memory-ops.md`
§5.1's write-side induction makes `mem_word`'s `rd_selected` carry a 16+16 range pair even
though it is a copy, and `mem_subword` bounds what it splices. A value cannot leave the
advice space into a register without passing one of those.

It is nonetheless a **standing obligation on every future consumer**: a family that learns
to read advice and does not bound what it read inherits a hole. This is the same shape of
debt §5.1 recorded as "owed by the I/O-binding stage" and S25 paid. It is recorded here
rather than discharged because discharging it would mean the first lookup channel any
window family has ever carried, which would put the family above the `BITS ≤ trace_vars`
floor and force its height off `2^8`.

---

## 6. The statement, and why there is no advice window list

**Advice is contiguous from `ADVICE_ORIGIN`.** Windows `0 .. k` with no gaps, where
`k = shard_counts[ADVICE_WINDOWS]` — shard `i` *is* advice window `i`, by position and
by nothing else, which is what `prover::window_of` reads. The extent is therefore already
in the statement descriptor's `SHARD_COUNTS` message, and there is nothing further to
carry:

- no new transcript tag,
- no new `PublicInputs` field,
- no amendment to the absorb order `docs/spec/memory.md` §7 freezes,
- no movement in any verifying key's bytes.

A sparse advice map — its own id list beside `MEMORY_WINDOWS` — would have needed all
four, for flexibility nothing has asked for. Advice is a blob; a blob has no holes.

A load above `ADVICE_ORIGIN + 4ak` is an address no window initialized. It is fatal in the
emulator and unbalanced in the argument, exactly as an out-of-window RAM address is
(`docs/spec/memory-ops.md` §2, "What no gate here does").

The window shard's own challenge carries the space: `gkr_verify::window_challenges` takes
an address space beside the window id and derives
`MEM_WINDOW_CONSTANT = γ_M + space + α_addr·(origin + 4·2^trace_vars·window)`, where the
origin is 0 for RAM and `ADVICE_ORIGIN` for advice. The literal `RAM` that used to sit in
that constant is where the space goes, so a window shard of one space cannot answer a
query of the other: their tuples differ in the first term.

---

## 7. What this costs, and what it does not buy

Per 4-byte word of witness consumed:

| | fd 0 `read` (S25a) | advice (S25b) |
| --- | --- | --- |
| guest cycles | one `ecall` row, plus SDK marshalling | one load |
| RAM writes | one — the copy into the guest's buffer | none |
| committed memory rows | RAM init + the copy's write + the read | advice init + the read |
| `io_digest` | Poseidon2 over the **whole** stream, at exit | none: only the compact public header is hashed |

The `io_digest` term dominates and it disappears: a guest that takes its witness on fd 0
hashes every byte of it through a Poseidon2 sponge at exit, which since S25 is delegated
and so grows the `POSEIDON2` and `FR_ARITH` shard counts with the witness size.

**What does not disappear is the committed memory row.** An advice word is still one init
tuple in a window shard, so the shard count still grows with the witness — one
`ADVICE_WINDOWS` shard per `4a` bytes *read*, `a` being that family's height. The honest
claim is

> no ecall per word, no second copy in RAM, no whole-witness hash, and no Poseidon2/Fr
> delegation growth proportional to the witness

and **not** "free random access". A megabyte of advice is a megabyte of committed
columns, exactly as a megabyte of RAM is.

`cargo run --release -p bench -- advice` measures the first two rows in isolation, over
hand-encoded programs summing the same words through each path. It measures neither of
the last two — a bare `EXIT` program pays no `io_digest` and allocates no buffer — and it
says so in its own output. The end-to-end number, where the SDK and the digest are both
present, is `docs/handoff/S25b-advice.md` §6 on `guests/revm-block`.

---

## 8. The emulator

- A load whose address is at or above `ADVICE_ORIGIN` reads the advice blob and stages its
  query in `AddressSpace::Advice`; below it, RAM as before. The address decides, totally.
- A store or an atomic whose address is at or above `ADVICE_ORIGIN` is a **fatal guest
  error**, as a misaligned access is: it returns no trace.
- A load past the supplied extent is a fatal guest error, as an out-of-window RAM access is.
- Misalignment is unchanged and orthogonal.

## 9. The guest SDK

`guest_sdk::advice()` returns the region as a `&'static [u8]`. Its length comes from the
compact public header on fd 0, which is public regardless — the shard count reveals the
extent to window granularity — and having it on fd 0 makes a read past the end a guest
bug rather than a silent zero.

**A guest that reads advice cannot run under `qemu-riscv32`** (owner's decision, S25b). A
host loader maps only the `PT_LOAD` segments the image declares, and advice is by
definition not in the image, so the region is unmapped and the first load faults. Such a
guest is therefore out of `crates/emulator/tests/qemu_outputs.rs`,
`crates/loader/tests/qemu.rs` and the three-way consistency suite. The non-advice guests
keep that coverage, and it is the ISA that those suites were really covering.

## 10. `guests/revm-block`: what its proof says

```text
fd 0    advice_len, chain id, block number, parent hash   76 bytes, public, bound
ADVICE  the whole BlockWitness                            private, PARTLY CHECKED
fd 1    the output commitment                             public, bound
```

fd 0 carries `revm_block::PublicHeader`, and it is 76 bytes whatever the block: the
region's length, the chain id, the height, and the parent hash the witness's
`block_hashes` answers for `number − 1` (zeros when it answers none). The guest's one
check of the advice is `BlockWitness::matches`, which recomputes that header from the
decoded witness and compares it whole; a mismatch is exit 63.

**What that check is worth, exactly.** It fixes *which block* the witness claims to be —
chain, height, parent — and it fixes **nothing** about the accounts, the storage, the
code or the transactions. There is no state root here to validate them against: the
committed witness is a synthetic pre-state and has none. So the proof says

> there exist accounts, storage, code and transactions under which the block at this
> height on this chain, with this parent, executes to this output commitment

and it does **not** say that those accounts are Ethereum's at that block, nor that those
are the block's transactions. Both halves matter: the transactions moved into advice with
the rest of the witness, so what was public and bound at S25a is private and unchecked
now, and that is a **reduction** in what fd 0 binds, bought for the cost removed in §7.

Closing the gap means a Merkle-Patricia validator in the guest, a transaction root in the
header, and a witness recorded from a real block; `crates/host`'s `WitnessRecorder`
already carries `parent_state_root`, which is where the state check will anchor. Until
then this distinction is not to be blurred in a summary, a handoff note or a commit
message.

### 10.1 The consequence for the suites

`crates/emulator/tests/revm.rs::a3_the_two_executors_commit_the_same_bytes` is **retired**.
It ran the same binary under `qemu-riscv32` and compared fd 1, and an advice guest cannot
run there at all (§9). What it established — that the delegated keccak and the SDK's
software fallback compute one function — is
`a5_every_delegated_permutation_is_the_reference`, which checks it directly and needs no
emulator. Every other guest keeps its QEMU coverage.
