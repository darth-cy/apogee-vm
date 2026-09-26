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
| **public values** | the statement | the verifier | `[0x8000, 0x8800)`, §2 |

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

**`read` (63) and `write` (64) are not provable ecalls**, and nothing in this mechanism
uses one. `prover::fill::add_sub` refuses a cycle that calls either, by name, as it refuses
every ecall but `EXIT` and a registered delegation number; the add/sub family's
`ecall_is_exit` gate is S16's, unchanged.

They stay in `constants::ecall` — the ABI is append-only — and the executor still answers
them, because a guest built for a POSIX host runs under `qemu-riscv32` and
`crates/emulator/tests/qemu_outputs.rs` holds the two executors to the same exit status and
the same fd 1 bytes. `guest_sdk::read_stdin` and `guest_sdk::write_stdout` are that path
and say so in their own documentation.

**fd 0 is not the public input**, and `emulator::GuestIo` carries the two as separate
fields: `input` fills the window, `stdin` is served on fd 0, and neither seeds the other.
A guest cannot read both paths usefully — the windows are unmapped under `qemu-riscv32`
and `read` is unprovable here — so sharing the bytes would buy nothing and would cap an
fd 0 stream at a public window's 1,020. The two descriptors were called `FD_PUBLIC_INPUT`
and `FD_PUBLIC_OUTPUT` until this stage; their **numbers** are frozen at their Linux
values, and only the names moved, to `FD_STDIN` and `FD_STDOUT`, because they no longer
name a public value.

A guest that wants to be proven calls `guest_sdk::public_input` and `guest_sdk::commit`,
which issue no ecall at all. This is the whole of "fd/syscall APIs are SDK compatibility
wrappers, not the cryptographic source of truth".

---

## 2. The memory map

```text
0x0000_0000  ┐
             │  a hole: no family initializes it, so a null dereference is a read of a
             │  tuple nothing wrote and the shard cannot balance
0x0000_8000  ┤  PUBLIC_INPUT_ORIGIN    256 words   the public input
0x0000_8400  ┤  PUBLIC_OUTPUT_ORIGIN   256 words   the journal
0x0000_8800  ┤  the hole again
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
without moving a single existing row — and the rest of it stays a hole.

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
`2^8` satisfies. It is a rule about statements, not about programs: derivation already
refuses a smaller window height for other reasons.

**The public windows' height is pinned.** A window's first address is `4·height·window`, so
the height is what places the windows, and only `family::PUBLIC_WINDOW_HEIGHT = 2^8` puts
the two origins in two distinct windows — `family::PUBLIC_INPUT_WINDOW` = 32 and
`family::PUBLIC_OUTPUT_WINDOW` = 33. `program::decode_program` therefore writes the
constant and ignores what a caller asked for, so "every family at `h`" keeps meaning every
family whose height is a choice; `verifier_core::window_height`, which runs inside
`VmConfig::from_bytes`, **refuses** any other, and that is the check that matters, because
it is the one on bytes a verifier was handed. The height also caps the verifier's work over
the public values at two 256-point multilinear evaluations, which is what keeps this cheap
inside the recursion guest.

---

## 3. The layout, and the length word

Each public window is

```text
word 0        the payload's byte length
words 1..     the payload, little-endian, zero-padded to the end of the window
```

so a payload is at most `guest_memory::PUBLIC_PAYLOAD_BYTES` = 1020 bytes.
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
| `PUBLIC_INPUT` | 12 | `2^8`, pinned | exactly 1, window 32 | `M[2] init_value` | `M[0]`, `M[1]` |
| `PUBLIC_OUTPUT` | 13 | `2^8`, pinned | exactly 1, window 33 | literal 0 | `M[0]`, `M[1]` |
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

What it does *not* say is anything about fd 1, fd 2, fd 3 or the advice region. Those are
unbound by construction, and §6 is what a guest owes for reading one.

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

guest_sdk::read_stdin(&mut [u8]) -> usize    // fd 0  — compatibility, unprovable
guest_sdk::write_stdout(&[u8])               // fd 1  — compatibility, unprovable
guest_sdk::hint(&mut [u8]) -> usize          // fd 3  — compatibility, unprovable
guest_sdk::log(&[u8])                        // fd 2  — diagnostics, unprovable
```

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

**Under `qemu-riscv32` the public windows and the advice region are unmapped**: a host
loader maps only the image's `PT_LOAD` segments, and none of these three regions is in the
ELF. A guest that uses them is out of the QEMU suites by construction, and a guest that must
be in them uses `read_stdin` and `write_stdout` and is not provable. `guests/revm-block`
carries both binaries for exactly this reason (`docs/spec/revm-block.md`).

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
| committed columns | 3 at `2^8` rows, 2 at `2^8` rows, and 3 per advice window |
| shards per proof | +2 always, +`k` where there is advice |
| verifier work per proof | two 256-point multilinear evaluations |
| guest work | none at exit; a load per public input word read, a store per journal byte |

---

## 9. Limits

**1020 bytes each, and that is deliberate.** Public values are what the verifier reads, so
they should be a commitment, a header or a result — not a blob. A large input belongs in the
advice region, where it costs the verifier nothing and the guest checks it against something
public, which is the pattern §6 states and `guests/revm-block` follows. The windows can grow
inside the hole below `RAM_ORIGIN` — 64 KiB is free and `2^10` and `2^12` are even powers of
two — at the price of a longer multilinear evaluation for the verifier and one more entry on
`family::HEIGHT_MENU`.

**Nothing orders the journal's writes.** The proof binds the window's final contents, so a
guest that writes word 7 before word 3 publishes the same journal. `commit`'s length word is
what gives the bytes an order, and it is a guest-side variable, not a committed cursor.

**Nothing forces a guest to read its input.** The binding is that the input window *held*
the statement's input, not that anybody looked.

**The exit status is still the thing to read first.** A journal is only as meaningful as the
run that produced it; `public.exit_status` is `x10`'s final value and `verify_global_memory`
binds it (`docs/spec/memory.md` §4.1).

**A panicking guest is provable only if its panic handler writes nothing.** Today
`guest_sdk`'s writes the message to fd 2, and `write` is not a provable ecall, so the claim
in §7 is about the journal surviving a panic and not yet about proving the panicking run
itself. Making diagnostics provable is a separate change and this stage does not make it.
