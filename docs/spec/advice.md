# The advice region

**Status: in progress (S25b).** Sections 1–6 are the design as decided; the circuit and
prover sections are written against the implementation as it lands and are not frozen
until the stage's handoff note says so.

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

**This repository has step 3 for nothing yet.** `guests/revm-block` reads its
`BlockWitness` from advice and does not validate it against a state root, because the
committed fixture is a synthetic pre-state with no real root to validate against. That
gap is deliberate, documented here and at `docs/spec/revm-block.md`, and is not to be
described as if it were closed. §10 states exactly what that guest's proof does and does
not say.

### 2.1 What the verifier learns

The extent, and only to window granularity: `shard_counts[ADVICE_WINDOWS]` is in the
statement descriptor, so a verifier knows the advice region spans that many windows of
`4h` bytes. It learns nothing about the contents. A prover wanting to hide even the size
pads to a fixed window count and pays for the padding.

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
no_store_to_advice    is_store · is_advice = 0        degree 2
```

which refuses the same execution locally, as `Constraint`, naming the gate. `ATOMICS` has
no `load` query at all and takes the simpler rule: its address may never have bit 31 set,
so `lr.w` cannot read advice either. Refusing that costs nothing — an atomic
read-modify-write on a region nothing may write has no meaning — and admitting it would
cost a per-row space column on the `ram` slot plus an exclusion gate over all eleven arms.

The emulator refuses the same three things fatally, before any event is staged, so an
execution the circuit could not prove is one no trace describes.
`trace::AddressSpace::writable` is the predicate both sides read, and the log's
self-check refuses a read-only space whose query wrote a value it did not read — the
executor-side twin of `FRAME_READ_ONLY`'s gate.

---

## 5. Initialisation: `ADVICE_WINDOWS`

The two RAM window families' third sibling, differing in exactly one thing.

| Family | Window | Initial values |
| --- | --- | --- |
| `INIT_TEARDOWN` | RAM window 0 | the image column; **identity commits them** |
| `ZERO_WINDOWS` | RAM windows above 0 | the literal `0` |
| `ADVICE_WINDOWS` | advice windows | **free**: a committed column nothing constrains |

Everything else it shares: no pc, no cycle, no lookup channel, the same window height `h`,
one shard per window, `V[row]` addressing, and one init tuple per address by construction.

**It is present in every `VmConfig`**, like the other two, and proves **zero** shards in a
run that reads no advice. That keeps `program::decode_program`'s three presence rules
intact — rule 2 is "the family is a window family" and this is one — at the cost of one
more circuit in every verifying key and one more group in every statement's G8.

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
`k = shard_counts[ADVICE_WINDOWS]`. The extent is therefore already in the statement
descriptor's `SHARD_COUNTS` message, and there is nothing further to carry:

- no new transcript tag,
- no new `PublicInputs` field,
- no amendment to the absorb order `docs/spec/memory.md` §7 freezes,
- no movement in any verifying key's bytes.

A sparse advice map — its own id list beside `MEMORY_WINDOWS` — would have needed all
four, for flexibility nothing has asked for. Advice is a blob; a blob has no holes.

A load above `ADVICE_ORIGIN + 4hk` is an address no window initialized. It is fatal in the
emulator and unbalanced in the argument, exactly as an out-of-window RAM address is
(`docs/spec/memory-ops.md` §2, "What no gate here does").

---

## 7. What this costs, and what it does not buy

Per 4-byte word of witness consumed:

| | fd 0 `read` (S25) | advice |
| --- | --- | --- |
| guest cycles | one `ecall` row, plus SDK marshalling | one load |
| RAM writes | one — the copy into the guest's buffer | none |
| committed memory rows | RAM init + the copy's write + the read | advice init + the read |
| `io_digest` | Poseidon2 over the **whole** stream, at exit | none |

The `io_digest` term dominates and it disappears: a guest that takes its witness on fd 0
hashes every byte of it through a Poseidon2 sponge at exit, which since S25 is delegated
and so grows the `POSEIDON2` and `FR_ARITH` shard counts with the witness size.

**What does not disappear is the committed memory row.** An advice word is still one init
tuple in a window shard, so the shard count still grows with the witness — one
`ADVICE_WINDOWS` shard per `4h` bytes supplied. The honest claim is

> no ecall per word, no second copy in RAM, no whole-witness hash, and no Poseidon2/Fr
> delegation growth proportional to the witness

and **not** "free random access". A megabyte of advice is a megabyte of committed
columns, exactly as a megabyte of RAM is.

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
fd 0    block number, parent hash, the header fields, the advice length   public, bound
ADVICE  accounts, storage, code — the bulk BlockWitness                   private, UNVALIDATED
fd 1    the output commitment                                             public, bound
```

The guest does **not** validate the advice against a state root. There is no real root to
validate against: the committed witness is synthetic. So the proof says

> there exist accounts, storage and code under which this block's transactions execute to
> this output commitment, consistent with the public header

and it does **not** say that those accounts are Ethereum's at that block. Closing the gap
means a Merkle-Patricia validator in the guest and a witness recorded from a real block;
`crates/host`'s `WitnessRecorder` already carries `parent_state_root`, which is where the
check will anchor. Until then this distinction is not to be blurred in a summary, a
handoff note or a commit message.
