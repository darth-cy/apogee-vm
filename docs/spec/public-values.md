# Public values, and private advice

**Normative.** This page is the three kinds of memory a zkVM has, the two families that
carry an execution's public input and its public output, the family that carries the
prover's advice, and what each binding is worth. It supersedes `docs/spec/memory.md` §10,
which described a different mechanism, and it retires the guest-side `io_digest`
convention S10 sketched and S14 deferred.

Read `docs/spec/memory.md` first: the tuple, RAM windows, the boundary and the
reconciliation are its, and all three families here are RAM window families.

The stage that wrote this page is **`S-IO`**, and it has no number: it is not one of the
original twenty-seven but the one they forgot, inserted after S24. `docs/handoff/S-IO.md`
is its note. `S25` in `prompts/S24-revm.md` and `docs/handoff/S24-revm.md` means a
different, still-future stage — the recorder that produces a `BlockWitness` for real
blocks — and is not this one.

---

## 0. The shape, and why it is this shape

A zkVM has three kinds of memory and they are not interchangeable:

| | who chooses it | who sees it | here |
| --- | --- | --- | --- |
| **RAM** | the program | nobody | `[RAM_ORIGIN, ADVICE_ORIGIN)`, `docs/spec/memory.md` §3 |
| **private advice** | the prover | nobody | `[ADVICE_ORIGIN, 2^32)`, §6 |
| **public values** | the statement | the verifier | `[0x8000, 0x10000)`, §2 |

The third is the one a proof is *about*. A verifier that cannot say what went in and what
came out has verified that some execution of some program happened, which is not a claim
anyone wants. So the public values are a first-class part of the statement, bound by the
proof system, and **not** by anything the guest does.

That last clause is the design, and it is the conventional one. Jolt lays its program I/O
out in a fixed region of memory below the DRAM origin and binds it at both ends through
its memory-checking argument — the input as the region's initial value, the output as its
final value, each against an extension the verifier computes itself. OpenVM gives its
public values an address space of their own and decommits them from the final memory root.
Neither asks the guest to hash anything. RISC Zero and SP1 do the opposite — the guest
SHA-256s its own journal and publishes the digest — and that is the design this page does
not take, because it rests the soundness of the output on the guest hashing honestly, it
costs a sponge over the whole stream at exit, and it makes a guest that panics after
touching a stream unprovable.

What this VM already had is most of the machinery: the memory multiset argument forces the
first and last value of every address (`docs/spec/memory.md` §4.2), and the statement is
already absorbed before any challenge is drawn. These families are what connect the two.

---

## 1. There is no I/O syscall

**There is no I/O syscall, and there are no descriptors.** Not a provable one and
not an unprovable one; not a compatibility path kept for some other executor.
`read` (63) and `write` (64) are retired and their numbers burned, and the four
file descriptors — standard input, standard output, diagnostics and a private
hint stream — went with them. `docs/spec/ecall-abi.md` §4 is the retirement.

**They were never provable, and that was the smaller reason.** A byte-moving
syscall reaches RAM through *transfer cycles*, and a transfer row that is
permitted but not constrained against its ecall's buffer and length can write any
value to any RAM word; confining it needs cross-row constraints this
arithmetization has nowhere to put. So the calls stayed outside every circuit,
and a guest that used one was a guest no proof covered. The larger reason is that
the shape was wrong. **An execution's public values are not a syscall's
business.** They are a property of the statement, they are bound at both ends by
a memory argument that already exists, and they ask the guest for nothing — no
call, no cursor, no cooperation, not even that it look. A stream API cannot
express that, because a stream is a thing the guest has to *use* for anything to
be published at all.

So the fd model is gone rather than wrapped. An Apogee guest is an Apogee-SDK
program, not a Linux one: `guest_sdk::public_input` and `guest_sdk::commit` issue
no ecall, `guest_sdk::advice` issues no ecall, and the only ecalls left in the ABI
are `EXIT` and the six delegation numbers, every one of which a circuit admits.
`emulator::GuestIo` is `{ input, advice }` and nothing else — the two byte strings
a run is given, one of which the statement carries and one of which nothing binds.

---

## 2. The memory map

```text
0x0000_0000  ┐
             │  a hole: no family initializes it, so a null dereference is a read of a
             │  tuple nothing wrote and the shard cannot balance
0x0000_8000  ┤  PUBLIC_INPUT_ORIGIN    4,096 words   the public input
0x0000_C000  ┤  PUBLIC_OUTPUT_ORIGIN   4,096 words   the journal
0x0001_0000  ┤  RAM_ORIGIN
             │  ordinary RAM: the image, the heap, the stack
0x8000_0000  ┤  ADVICE_ORIGIN
             │  private advice, prover-supplied
0x1_0000_0000┘
```

**The public windows' addresses are not a free choice.** `[0, RAM_ORIGIN)` is already a
hole: `INIT_TEARDOWN` masks RAM window 0's rows below `2^14` with `V[ram_live]` and
`ZERO_WINDOWS` never claims window 0 (`docs/spec/memory.md` §3.3), so no RAM window family
initializes an address there. The mask's bound is a **constant**, `[0, 2^16)`, whatever the
window height, so two windows of that hole are free to claim at every admissible height
without moving a single existing row.

Since S-STREAM the two claim the **whole** of the hole's upper half — `2^12` each,
`[0x8000, 0x10000)`, ending flush against `RAM_ORIGIN` — where until then they were `2^8`
each and `[0x8800, RAM_ORIGIN)` was a second, unclaimed stretch of it. What survives is
`[0, 0x8000)`, and that is the half the null-dereference argument has always rested on: a
read at 0 is a read of a tuple nothing wrote, and a shard carrying one cannot balance.

**The address-space tag is `RAM` for all three regions**, and that is what makes them cost
the rest of the machine nothing. A load's memory leaf names its space with a literal
(`docs/spec/memory.md` §8), so a region with a tag of its own would put a space *column* on
the load path of `mem_word`, `mem_subword` and `atomics`, and a gate to pin it. There is
nothing to buy with that: what tells a public value, an advice word and a heap word apart
is **which family initializes the address**, and the three families' address ranges are
disjoint by construction. The three memory-op families are untouched by this stage, and
their range obligations already admit every 4-aligned address below `2^32`
(`docs/spec/memory-ops.md` §2).

**`ADVICE_WINDOWS` extends the window tiling to the whole address space.** `docs/spec/memory.md`
§3.1 tiles `[0, 2^31)` in `N = 2^29 / h` windows and bounds a `ZERO_WINDOWS` id to
`[1, N − 1]`; that bound is **unchanged**. The advice windows are the `k` consecutive
windows from `advice_first_window(h) = N` up, so the two families' ids are disjoint by
arithmetic and no disjointness rule is needed. `verifier_core::check_memory_windows`
requires `N + k <= 2^30 / h`, which is the top of the address space.

**The window height must be at least `2^16`.** Both public windows have to lie inside RAM
window 0 — `[0, 4h)` — or a `ZERO_WINDOWS` id could claim one and give a public word a
second init row and a prover a second value to choose. `verifier_core::window_height`
requires `4h >= PUBLIC_OUTPUT_ORIGIN + PUBLIC_WINDOW_BYTES`, which every menu height but
`2^8` and `2^12` satisfies. It is a rule about statements, not about programs: derivation
already refuses a smaller window height for other reasons.

**That floor did not move when the windows grew**, which is worth saying because growing
them is exactly the change that could have moved it. The right-hand side went from `0x8800`
to `0x10000`, so the rule went from `h >= 8,704` to `h >= 2^14` — and the smallest menu
entry above either is the same `2^16`.

**The public windows' height is pinned, and `2^12` is the ceiling.** A window's first
address is `4·height·window`, so the height is what places the windows:
`family::PUBLIC_WINDOW_HEIGHT = 2^12` puts the two origins in windows
`family::PUBLIC_INPUT_WINDOW` = 2 and `family::PUBLIC_OUTPUT_WINDOW` = 3, distinct and
ending flush against `RAM_ORIGIN`. **There is no step above it.** The hole is 64 KiB; two
`2^14` windows need 128 KiB, and the only `2^14` window that fits inside 64 KiB is window
0 — which initializes address 0, so a null dereference would balance and the hole's whole
purpose would be gone. Anything further means moving `RAM_ORIGIN`, which moves every
program's load address and eats into every decoded table's pc reach.

**It was `2^8` until S-STREAM**, where the pair was windows 32 and 33 at `0x8000` and
`0x8400`; §9 is why it grew and what the growth is and is not worth.
`family::HEIGHT_MENU` gained `2^12` at index 1 to carry it — an entry no execution family
can take (the `TIMESTAMP` channel needs 19 variables) and no window family can take (the
`4h` rule above), which leaves it widening only what a key may declare for the three
channel-free delegation families, and that is benign.

`program::decode_program` writes the constant and ignores what a caller asked for, so
"every family at `h`" keeps meaning every family whose height is a choice;
`verifier_core::window_height`, which runs inside `VmConfig::from_bytes`, **refuses** any
other, and that is the check that matters, because it is the one on bytes a verifier was
handed. The height is also what fixes the verifier's work over the public values, now two
4,096-point multilinear evaluations (§8).

---

## 3. The layout, and the length word

Each public window is

```text
word 0        the payload's byte length
words 1..     the payload, little-endian, zero-padded to the end of the window
```

so a payload is at most `guest_memory::PUBLIC_PAYLOAD_BYTES` = 16,380 bytes — the window's
`4 · 2^12` less the length word, and 1,020 before S-STREAM raised the height (§2).
`verifier_core::public_io_words` is the one spelling of the conversion, and three readers
call it: the executor seeding the input window, `trace`'s column builder filling the init
column, and the verifier evaluating what it was handed. `derive_global_phase` refuses a
statement whose `input` or `output` is longer than the payload — bytes no window could have
carried — as `Statement`, before anything is built from them.

**The length word is load-bearing, and it is what makes the binding exact.** Without it
`[1, 2, 3]` and `[1, 2, 3, 0]` fill the same window, and both would be honestly provable
from one execution: the prover would pick whichever suited it and the verifier could not
tell. With it, matching the committed column forces `|B'| = |B|` as well as
`words(B') = words(B)`, and therefore `B' = B` exactly. Jolt has the same gap and closes it
one layer up, inside the payload's own `postcard` framing; a word is cheaper and belongs
where the ambiguity is.

---

## 4. The three families

| family | id | height | shards | init leaf | teardown leaf |
| --- | --- | --- | --- | --- | --- |
| `PUBLIC_INPUT` | 12 | `2^12`, pinned | exactly 1, window 2 | `M[2] init_value` | `M[0]`, `M[1]` |
| `PUBLIC_OUTPUT` | 13 | `2^12`, pinned | exactly 1, window 3 | literal 0 | `M[0]`, `M[1]` |
| `ADVICE_WINDOWS` | 14 | the window height | `k >= 0`, windows `N … N+k−1` | `M[2] init_value` | `M[0]`, `M[1]` |

All three are `CYCLE_OWNING` false and in **every** `VmConfig`. The two public families
prove exactly one shard each whether or not the execution used them: a count a prover could
drop is a way to publish nothing while having published something, and a program that
ignores public values simply publishes an empty input and an empty journal. `ADVICE_WINDOWS`
proves `k` shards, `k` being how many windows the supplied advice spans, so a program with
no advice pays nothing.

`PUBLIC_OUTPUT`'s circuit is **`ZERO_WINDOWS`' artifact, byte for byte**, and that is the
point: its init leaf is the literal 0, so there is no init column for a prover to choose.
The other two take `constraints::memory::value_window_artifact`, which is that artifact
with one committed column added:

```text
M[0] teardown_ts     M[1] teardown_value     M[2] init_value     V[row]

L1[0] teardown = Linear { [(α_addr, V[row]) × 4, (α_ts, M[0]), (α_val, M[1])], WC }   read side
L1[1] init     = Linear { [(α_addr, V[row]) × 4,                (α_val, M[2])], WC }  write side
```

then `trace_vars` halving lists to `outputs = [read_root, write_root]`. **No enforcing
gates, no lookups, no channel, no setup column, degree 1 throughout.** Each family is two
leaves and a product tree.

`program::setup_commitments` returns an empty list for all three, deliberately: an `S`
column is bound by program identity, and one execution's public values — or one execution's
advice — have no business in every execution's identity. Theirs is an `M` column, committed
in the global commit phase, which is before the memory challenges are squeezed.

All three are in every `VmConfig`, so **every program's identity moves** relative to a tree
without them: the `VM_CONFIG` message lists the family set (`docs/spec/memory.md` §6.2).

---

## 5. The binding

Two different things bind the two ends, and neither is a gate.

**The multiset**, exactly as for any RAM window (`docs/spec/memory.md` §4.2):

* only the init leaf writes a tuple stamped 0 at these addresses, so a guest's first read of
  one reads the init column's row;
* every later access chains, and the teardown read can only balance against the highest
  write in the chain, so `M[1]` is that address's **final** value.

**The verifier, at the shard's own opening point.** `verify_shard_local` step 10c: a shard's
base claims arrive in layout order `M`, `W`, `S`, and neither public family has a `W` or an
`S` column, so `claims[1]` is `M[1] teardown_value` and `claims[2]` is `M[2] init_value`.
The verifier evaluates the multilinear extension of `public_io_words(...)` at the same point
and compares.

| shard | column | held to |
| --- | --- | --- |
| `PUBLIC_INPUT` | `M[2] init_value` | `public_io_words(public.input)` |
| `PUBLIC_INPUT` | `M[1] teardown_value` | free — a guest may overwrite its own input buffer |
| `PUBLIC_OUTPUT` | `M[1] teardown_value` | `public_io_words(public.output)` |
| `PUBLIC_OUTPUT` | `M[2]` | there is no `M[2]`: the init leaf is a literal 0 |

The last row is not decoration, and it is the one place this design could have gone wrong.
If the journal's window had a committed init column, a prover would fill it with the answer
at timestamp 0, the guest would never store a word, and the teardown column — the final
state, and nothing more — would match anyway. Jolt closes that hole with a mask; here the
family simply has no column to choose, which is cheaper and cannot be forgotten.

A failure is `MemoryArgument`, after step 10a and before the opening, with a message naming
which window disagreed.

### 5.1 The argument, stated plainly

The statement carries `input` and `output` as bytes. The global transcript absorbs
`io_digest(input, output)` at G7, before the memory challenges are squeezed
(`docs/spec/memory.md` §6.1) — S10's frozen digest, in the position it has always had — so
the two byte strings are fixed before any challenge exists. `M[1]` and `M[2]` are **memory**
columns, committed in the global commit phase at G8, which is also before the squeeze. Step
10c then says the committed columns are those bytes, and the multiset says the committed
columns are the execution's first and last values at those addresses.

So: **the guest read the statement's public input, and the statement's public output is what
the guest's stores left behind.** Nothing in that sentence mentions the guest's cooperation,
a hash, or a register convention. S10 froze `io_digest` and S14 recorded that it bound
nothing to the execution; this is the stage that makes it worth something, and it needed no
new message, no new tag and no new challenge to do it.

What it does *not* say is anything about the advice region. That is unbound by
construction, and §6 is what a guest owes for reading it.

---

## 6. Advice

**Advice is memory whose initial values the prover chose.** `ADVICE_WINDOWS` initializes
`[ADVICE_ORIGIN, ADVICE_ORIGIN + 4hk)` from a committed `M[2]`, and **nothing binds that
column** — not identity, not the statement, not a gate. That is not an omission; it is the
definition. A load of an advice word is an ordinary `lw`.

```text
word 0        the payload's byte length
words 1..     the payload, little-endian
```

the same framing as a public window, laid out by `trace::advice_word` — the one spelling the
executor writes, `guest_sdk::advice` reads back and the prover's fill commits, so a host
never frames the bytes itself and the three cannot drift.

**The windows are consecutive from the origin, so the statement needs no advice window
list**: `shard_counts[ADVICE_WINDOWS]` is `k`, and shard `i` is window
`advice_first_window(h) + i`. Nothing is absorbed that was not absorbed before.

**What a guest owes.** The prover picks the advice, so a guest that lets advice change what
it commits, without checking it against something a proof *does* bind, has published a value
the prover chose. The obligation is the guest's and the VM cannot discharge it. The pattern
is: the advice carries the bulk, the **public input** carries a commitment to it, and the
guest checks one against the other — or, as `guests/revm-block`'s **stateless** binary does
since S25, the journal names the state roots the block began and ended on, so a witness
describing a different pre-state publishes a different result rather than the same one
(`docs/spec/revm-block.md` §5.1). Its **mini** binary publishes no root and claims none;
what it owes instead is the strictness that makes its witness worth reading — a canonical
encoding, and a database that refuses every value it was not given rather than defaulting
(§1.0 of the same page).

**Advice is not enforced read-only** (owner's decision, S-IO). A store into the advice region
is an ordinary store and the multiset carries it like any other. Enforcing read-only would
need a space selector on the load path of three frozen families and a gate refusing a store
there, and it would buy no soundness: advice is unbound whether or not the guest writes it.
Jolt's advice regions sit outside its checked mask for the same reason. "Read-only" is the
guest's discipline, and this paragraph is the whole of it.

**The executor bounds a read to what it was given.** `[ADVICE_ORIGIN, ADVICE_ORIGIN + 4·words)`
is addressable and everything above it is the fatal `OutOfBounds`, `words` being
`trace::advice_region_words` over the supplied bytes. Above that bound the region is
initialized by no window of this execution, so a read there could not balance whatever an
executor did with it; refusing it loudly costs the prover a trace and nobody else anything.

**No advice means no region.** `advice_region_words` is 0 for an empty slice, so `k` is 0
and a program that uses no advice pays nothing — the alternative would charge every program
in the repository one whole window at the window height to say that it has none. A guest
that calls `guest_sdk::advice` on a run given none therefore takes that fatal
`OutOfBounds`, which is the right answer to asking for what was not handed over.

---

## 7. The guest

```rust
guest_sdk::public_input() -> &'static [u8]   // the input window's payload, no ecall
guest_sdk::read_input(&mut [u8]) -> usize    // the same, copied, for a ported program
guest_sdk::commit(&[u8])                     // append to the journal, no ecall
guest_sdk::journal() -> &'static [u8]        // the journal so far
guest_sdk::advice() -> &'static [u8]         // §6; nothing binds it
guest_sdk::exit(code) -> !                   // publishes nothing; there is nothing to publish
```

**That is the whole of it**, and there is no second list. The five reading and
writing calls issue no ecall at all — three regions of memory, loads and stores —
so an execution's entire input and output crosses no ABI boundary.

`commit` exits `EXIT_IO_ERROR` on a journal that would not fit the window rather than
truncating: a caller reads `journal()` back and must not see one it did not write. The
length word is a plain store like the payload, so a partial `commit` is not a thing that can
happen.

**A guest that panics has still published what it committed.** The journal is memory and
`#[panic_handler]` does not have to know about it — which is the opposite of the design this
replaces, where a hash computed at exit meant a guest that died published nothing.

**`guest_sdk::exit_with_public_words` is gone.** S24 used it to leave eight words in
`x24..x31`, where the register boundary made them public; that was the stopgap for having no
journal, and the journal is what it was standing in for.

**None of the three regions is in the ELF**, and none of them needs to be: no
linker symbol names them, `link.ld` reserves nothing for them, and a guest
reaches them with ordinary loads and stores at the constants of
`constants::guest_memory`. What makes them addressable is `trace::addressable`,
the executor's rule (§2) — the same mechanism that makes them a hole for every
address a run was given nothing for.

---

## 8. What it costs

| | |
| --- | --- |
| new families | 3 |
| new address spaces | 0 |
| new transcript messages, tags or challenges | 0 |
| new statement fields | 0 |
| changes to any execution family's circuit | 0 |
| enforcing gates added anywhere | 0 |
| new artifact constructors | 1, shared by two families |
| committed columns | 3 at `2^12` rows, 2 at `2^12` rows, and 3 per advice window |
| shards per proof | +2 always, +`k` where there is advice |
| verifier work per proof | two 4,096-point multilinear evaluations |
| guest work | none at exit; a load per public input word read, a store per journal byte |

**S-STREAM moved two of those rows and nothing else.** The two public shards are `2^12`
rows where they were `2^8` — sixteen times the rows on five committed columns of families
with no enforcing gate, no lookup, no channel and degree 1 throughout, which is the
cheapest kind of row this VM has. And step 10c evaluates over 4,096 points rather than
256: `MultilinearPoly::evaluate` folds, so a window costs `2^12 − 1` multiplies where it
cost `2^8 − 1`, **8,190 `Fr` multiplies for the pair against 510**, over a 2,048-entry
`Fr` fold buffer and the 4,096-word `u32` vector `public_io_words` lays out — 80 KiB live
per shard, 163,840 bytes across the two. Noise on a native verifier; a budget a future
recursion guest will carry, which is why it is written down here rather than left to be
rediscovered.

---

## 9. Limits

**16,380 bytes each, and the room to grow is now spent.** This paragraph used to read
"1020 bytes each, and that is deliberate", and it offered the way out in the same breath:
*the windows can grow inside the hole below `RAM_ORIGIN` — 64 KiB is free and `2^10` and
`2^12` are even powers of two — at the price of a longer multilinear evaluation for the
verifier and one more entry on `family::HEIGHT_MENU`.* **S-STREAM took that offer and paid
exactly that price**: `2^12`, the journal at `0xC000`, two 4,096-point evaluations (§8),
and `2^12` at index 1 of the menu. Nothing else in this page's mechanism changed — no new
family, no new message, no new challenge, no gate.

**There is no second growth**, and §2 is the arithmetic: `2^12` is the geometric ceiling.
Two `2^14` windows want 128 KiB where the hole has 64, and the one `2^14` window that fits
is window 0, which initializes address 0 and would make a null dereference balance.
Growing past this means moving `RAM_ORIGIN` — every program's load address, and pc reach
taken off every decoded table.

**What it bought.** `docs/spec/revm-block.md` §2's output commitment is a per-transaction
record — 13 fixed bytes plus the transaction's return data verbatim — under two 32-byte
digests. At zero return data the journal held `(1020 − 64) / 13` = 73 transactions and now
holds `(16380 − 64) / 13` = 1,255; at the 45 bytes a transaction the pinned mini-block
measures, 21 and ~360. The real mainnet blocks measured in this repository carry 67, 132,
240, 376 and 450 transactions (`docs/handoff/S26-cycle.md`, and S25's pinned block): at
1,020 bytes not one of the five fit, and at 16,380 the first three do. The crossover moved
from below the smallest real block to above the median one.

**It is headroom, and it is not a bound.** That distinction is the whole of this
paragraph. A record's `output` is the transaction's return data taken *verbatim* behind a
`u32` length, so a single maximum-size top-level `CREATE` is 24,576 bytes of deployed code
in one record — 24,589 bytes, which overflows `2^12` on its own and would overflow any
window this hole could ever hold. A journal whose length is a function of what the
execution did cannot be made to fit by growing a fixed window. It can only be digested.

**So the digest is still the right answer for an unbounded journal, and it is already
built.** Public values are what the verifier reads: a commitment, a header or a result,
not a blob. A large *input* belongs in the advice region, where it costs the verifier
nothing and the guest checks it against something public — the pattern §6 states and
`guests/revm-block` follows. A large *output* belongs behind a digest, which is what
`guests/revm-block`'s **stateless** binary does: a fixed 43-byte journal, the spec's
stateless validation result, whose first field is the SSZ root of the payload request it
validated (`docs/spec/stateless.md`; S-STREAM's 148-byte journal of two roots and two
digests preceded it). That binary, and not the mini one, is the owner's chosen full-block
target.
`docs/spec/revm-block.md` §2 stays **frozen** — the mini guest's format did not change
here, it only has room now.

**Nothing orders the journal's writes.** The proof binds the window's final contents, so a
guest that writes word 7 before word 3 publishes the same journal. `commit`'s length word is
what gives the bytes an order, and it is a guest-side variable, not a committed cursor.

**Nothing forces a guest to read its input.** The binding is that the input window *held*
the statement's input, not that anybody looked.

**The exit status is still the thing to read first.** A journal is only as meaningful as the
run that produced it; `public.exit_status` is `x10`'s final value and `verify_global_memory`
binds it (`docs/spec/memory.md` §4.1).

**A panicking guest is provable.** `guest_sdk`'s handler is a bare `exit(101)`
with no message: there is no diagnostic stream for it to reach and no ecall on
the panic path, so a run that panics is an ordinary execution ending in a nonzero
status, proven like any other. What it published is what it had committed before
it died — §7's claim about the journal, and now the run itself. The message is the
price, and the trade is deliberate: a diagnostic stream is bytes leaving an
execution that no proof binds, which is the thing this page exists to refuse.
