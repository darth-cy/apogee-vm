# The guest ecall ABI

Frozen at S10. **This document is the ABI.** It is a document rather than a
program because the maintenance surface of a document is small and the surface
of another abstraction layer is not; the numbers themselves live once, in
`crates/constants`'s `ecall` module, and `crates/constants/tests/ecall_abi.rs`
holds this file to them on every build.

**Numbers are append-only, forever.** Once a program's identity is published its
ABI is frozen. Redefining a number does not fail loudly — it quietly makes an
old program compute something else — so a number here is assigned once and never
reused, exactly as `transcript_tags` are.

## 1. The calling convention

An ecall follows the **Linux RISC-V syscall convention**:

| Register | Role |
| --- | --- |
| `a7` | the number |
| `a0`–`a5` | the arguments |
| `a0` | the result, or a negated errno |

**An ecall preserves every register except `a0`.** That is part of the frozen ABI, not an
accident of the current executor: `crates/guest-sdk`'s shims declare no clobbers at all,
and every later delegation circuit is written against this table. A precompile that
scratched `t0` would produce silently wrong guest arithmetic with nothing to catch it,
which is the "valid proof of a different computation" failure this whole document exists
to prevent.

The standard calls keep their Linux numbers, which is what lets `qemu-riscv32`
run a guest **unmodified** — QEMU was the only executor S10 had, and since S12 it is
the oracle the emulator's *answers* are compared against, so the choice is
load-bearing rather than decorative.

**What is compared is the exit status and fd 1, and nothing below them**
(owner's decision, S25). S12 compared per-instruction register files and this
page said so; that invariant is **withdrawn**. This emulator is not a QEMU
clone — it takes the execution path its trace generation needs — and a
delegation ecall settles it: QEMU has no circuit for a precompile number,
answers `-ENOSYS`, and the guest computes in software what this VM delegates,
so the two run different instructions *by design* and agree on the result
(`docs/spec/delegation.md` §2). `crates/emulator/tests/qemu_outputs.rs` is the
comparison; a trace's correctness is held against this VM's own semantics and
constraints instead.

Precompile arguments travel as **pointers** in `a0`–`a5`, because their operands
do not fit in registers: a Poseidon2 state is 96 bytes. Dispatch is by ecall and
never by a CSR write.

## 2. The number ranges

| Constant | Value | What |
| --- | --- | --- |
| `ZKVM_IO_FIRST` | 0x0400 | first zkVM host call |
| `ZKVM_IO_LAST` | 0x04FF | last zkVM host call |
| `PRECOMPILE_FIRST` | 0x0500 | first precompile |
| `PRECOMPILE_LAST` | 0x05FF | last precompile |

Everything at or below 1023 is a Linux number, at its Linux value.

Both non-Linux ranges sit **above every Linux number**, and they are disjoint
from each other. The split does real security work, and it is the reason there
are two ranges rather than one:

* a **zkVM host call** is nondeterministic prover advice — whatever the host
  returns is a value the prover chose;
* a **precompile** is a deterministic function of guest memory, and the circuit
  that replaces it proves exactly that function.

A reviewer must be able to tell which a number is at a glance. Mixing them is
how a nondeterministic call ends up treated as proven.

The zkVM host-call range is **reserved and empty** at S10. zkVM I/O is expressed
with the Linux calls over the file descriptors in section 4, because a guest
that used `0x0400` for its input could not run under QEMU at all.

## 3. Syscall numbers

Every number this VM implements, with its nondeterminism class. The
`Constant` column is the name in `constants::ecall`.

| Number | Constant | Class | What |
| --- | --- | --- | --- |
| 63 | `READ` | per fd | `read(fd, buf, len)`; see section 4 |
| 64 | `WRITE` | per fd | `write(fd, buf, len)`; see section 4 |
| 93 | `EXIT` | deterministic | `exit(status)`; nonzero is a failed execution |
| 0x0500 | `PRECOMPILE_POSEIDON2` | deterministic | Poseidon2 over `[Fr; 3]`, `a0` = the 96-byte frame base pointer, permuted in place. A **delegation** call since S23: `docs/spec/delegation.md` §12 is its frame table, `constants::family::POSEIDON2` the circuit that proves it. The three lanes cross the frame as canonical little-endian `Fr`, 8 words each |
| 0x0501 | `PRECOMPILE_KECCAK_F` | deterministic | keccak-f[1600] over the 200-byte state frame at `a0`, permuted in place. The first **delegation** call: `docs/spec/delegation.md` is its ABI, `constants::family::KECCAK_F` the circuit that proves it. An executor with the circuit answers 0; one without answers `-ENOSYS` and the caller runs its software path |
| 0x0502 | `PRECOMPILE_FR_ARITH` | deterministic | one `Fr` add, multiply or inverse over the 100-byte frame at `a0`, in place. A **delegation** call: `docs/spec/delegation.md` §13 is its frame table, `constants::family::FR_ARITH` the circuit. The operands cross the frame in `field::Fr`'s **in-memory** representation, which is what makes the call cheaper than the software operation it replaces |

The classes are:

* **deterministic** — the result is a function of the guest's own state, so
  nothing needs to bind it.
* **per fd** — see section 4; `read` and `write` are two calls each depending on
  which descriptor they name.
* **advice** — the result is chosen by the prover. A proof says nothing about
  which value was chosen unless the value is folded into the public I/O digest,
  or checked by the guest against something that digest does bind.

## 4. File descriptors

| fd | Constant | Committed | What |
| --- | --- | --- | --- |
| 0 | `FD_PUBLIC_INPUT` | yes | public input; the first stream the digest binds |
| 1 | `FD_PUBLIC_OUTPUT` | yes | public output / journal; the second stream |
| 2 | `FD_STDERR` | no | diagnostics, free-form, verifier-ignored |
| 3 | `FD_HINT` | no | private hints: **nondeterministic prover advice** |

So `read(63)` on fd 0 is **committed** and on fd 3 is **advice**; `write(64)` on
fd 1 is **committed** and on fd 2 is neither, being ignored entirely.

A guest that lets a hint change what it writes to fd 1, without checking the
hint against something else, has made its proof meaningless: the prover picks
the hint, so it picks the output. A hint is a shortcut to a value the guest then
verifies, and never an input in its own right.

Added at S12, where the first zkVM executor pinned what the table above left open:

* **Every other descriptor answers `-EBADF`.** `read` on anything but fd 0 and
  fd 3, and `write` on anything but fd 1 and fd 2, move no bytes and return
  `-EBADF` — Linux's answer, and so `qemu-riscv32`'s, which keeps one source tree
  meaning the same thing under both executors.
* **`read` returns what the stream has.** It delivers `min(count, bytes left)` and
  returns that count, so a `read` at the end of a stream returns 0. `write`
  delivers all `count` bytes and returns `count`.
* **A provable `read` moves exactly one 4-aligned word** (S25). On fd 0 and fd 3,
  `count` must be `constants::ecall::READ_WORD_BYTES = 4` and `buf` must be a
  4-aligned address inside the RAM window; each is a **fatal guest error**
  otherwise, joining the list above rather than answering short. The call still
  returns `min(4, bytes left)`, so end of stream is still a 0, and the word's RAM
  query rides the ecall's own row (`docs/spec/execution-trace.md` §6).

  This is S14's open question 10, answered as it recommended, and the reason is
  soundness rather than tidiness: a bulk transfer needs rows of its own, and a
  row of its own carries nothing to bound its own address with. Confining one
  would mean carrying the buffer and the count across rows, which this
  arithmetization can do only through the global memory multiset. One word on
  the row that already read `a1` and `a2` makes the whole confinement two
  degree-2 gates.

  **The guest does its own copying.** `guest_sdk::read_input` loops a word at a
  time through an aligned scratch, so a caller's buffer needs no alignment — but
  its **length must be a multiple of four**, or the last call would consume a
  whole word and keep part of it. The SDK refuses such a buffer with exit 70
  rather than dropping bytes silently.

  **A refused `read` is not provable.** A descriptor fd 0 and fd 3 do not name
  answers `-EBADF` and moves no word, and three gates each refuse the row:
  `read_descriptor` holds `a0` to fd 0 or fd 3 (S25a), `ram_mask_rule` demands
  the RAM query on every `read` row, and `read_count_gap_range` refuses the
  `-EBADF`. `prover::fill::add_sub` refuses the cycle by name rather than
  proving a shard that cannot verify. The SDK never issues one — `read_fd` takes
  the descriptor from its caller and the two public entry points pass 0 and 3 —
  so this is a completeness gap only a hand-written ecall can reach.
* **`write` names one of two descriptors and moves no memory event.** Any buffer,
  any alignment, any count, one cycle; the descriptor is fd 1 or fd 2 and nothing
  else, which the circuit pins since S25a. The RAM query it used to make bound nothing:
  fd 1 is bound by the guest's own `io_digest` over the bytes it assembled with
  ordinary loads and stores, which the memory argument does bind (section 6 and
  `docs/spec/memory.md` §10). Only the RAM-window bound survives.

  **A refused `write` is not provable either** (S25a). It was until then: a
  descriptor fd 1 and fd 2 do not name answers `-EBADF`, appends nothing and
  makes no query, which was an ordinary `write` row and proved as one.
  `write_descriptor` now holds `a0` to fd 1 or fd 2 and
  `write_count_is_the_request` holds the count answered to the count asked for,
  so the row is refused twice over and `prover::fill::add_sub` declines the
  cycle by name.
* **A buffer outside the RAM window is a fatal guest error**, exactly as a load or
  store there is: the bytes a call would move must lie in `[RAM_ORIGIN,
  RAM_ORIGIN + RAM_LENGTH)` (section 7). Linux would answer `-EFAULT`; this VM has
  no memory outside the window for a call to fault on, so there is nothing to
  report back to.
* **The recorded fd 0 stream is the bytes the guest consumed**, in order — what
  `read` on fd 0 actually delivered, not everything the prover offered. Those are
  the bytes the execution trace witnesses, so they are the public input the digest
  in section 6 binds.

How a call's register reads and its buffer traffic appear in the execution trace
is `docs/spec/execution-trace.md`, not this document.

### 4.1 What the circuit pins about a call, and what it does not

Since S25a the `ADD_SUB_LUI_AUIPC` circuit fixes four of the five numbers an I/O
ecall row carries. `docs/spec/shard-proof.md` §8.2 is the normative gate list;
this is what it adds up to, per call, and the one thing left over.

| the row's | a `read` | a `write` |
| --- | --- | --- |
| `a7`, the call | pinned to `ecall::READ` (`read_number`) | pinned to `ecall::WRITE` (`write_number`) |
| `a0` read, the descriptor | pinned to fd 0 or fd 3 (`read_descriptor`) | pinned to fd 1 or fd 2 (`write_descriptor`) |
| `a1`, the buffer | the RAM query's address (`ram_addr_is_the_buffer`) | not pinned; the bytes enter no leaf |
| `a2`, the count asked for | pinned to `READ_WORD_BYTES` (`read_count_is_one_word`) | not pinned |
| `a0` written, the answer | **bounded** to `[0, READ_WORD_BYTES]` (`read_count_gap_range`) | pinned to `a2` (`write_count_is_the_request`) |

**The remaining limitation is a `read`'s exact count.** The circuit bounds it and
cannot fix it, because a short read is a real answer and how many bytes a stream
had left is not a fact any row holds: the cursor lives in the executor, and this
arithmetization has no cross-row state to keep one in. So within `[0, 4]` the
count is the prover's choice, and a prover may claim a stream ended earlier than
it did — a `read` answering 0 where 4 bytes were available, and every later
`read` answering 0 after it.

What that can and cannot do:

* It cannot change the **committed bytes**. fd 0's content is bound by the
  guest's own `io_digest` over the stream it consumed (section 6), which the
  verifier recomputes from the statement's own fd 0. A prover that truncates the
  stream is proving a different, shorter public input, and the verifier compares
  against the input it was given.
* It cannot reach the bytes **already delivered**: the word a `read` moves is
  confined to the buffer by `ram_addr_is_the_buffer`, whatever the count says.
* It **can** change the guest's control flow. `guest_sdk::read_fd` stops on a
  short answer and returns what it filled, so a caller sees a truncated input and
  takes whatever branch that leads to. A guest that must not accept a short read
  checks the length itself — `revm_block::PublicHeader` is the pattern: fd 0
  carries the region's length and the guest compares what it decoded against it
  (`docs/spec/advice.md` §10).

Closing it properly needs a stream cursor the circuit can see — a committed
column advanced by each `read` row and reconciled against the statement's stream
length — which is a cross-row binding of the kind only the global memory
multiset carries today. Not attempted at S25a, and deliberately out of scope
there.

## 5. Every other number

**Unimplemented numbers return `-ENOSYS`**, which is what `qemu-riscv32` does for them
today and what the S12 emulator will do.

| Constant | Value | What |
| --- | --- | --- |
| `ENOSYS` | 38 | returned negated in `a0` for a number this VM does not implement |
| `EBADF` | 9 | returned negated in `a0` for `read` or `write` on a descriptor section 4 does not give that call |

That includes, deliberately, every syscall that would return host data:
`getrandom`, `clock_gettime`, `gettimeofday`, and anything Rust's `HashMap`
reaches for on first use to seed its `RandomState`. Each of those is
nondeterministic prover advice wearing the costume of a library call: unless its
returns are folded into the public I/O digest, the proof does not pin down which
execution happened, and a malicious prover picks the values. They are refused
rather than answered, so a guest that wants one has to say so by asking for a
number in the zkVM host-call range — where a reviewer will see it.

## 6. The public I/O digest

One `Fr` binds the fd 0 and fd 1 byte streams. **Frozen at S10**: later stages
recompute it and never redefine it. This is the value the statement-binding
order absorbs as "public I/O digest".

**Since S25 it is tied to the execution.** The guest computes this digest over
the streams it moved and leaves its eight little-endian `u32` words in
`x24`…`x31` at exit; the verifier recomputes them from the statement's own
streams and compares, unconditionally, in `verify_global_memory`
(`docs/spec/memory.md` §10). `transcript::io_digest_words` is the one spelling
of the split both sides use, and `transcript::exit_with_io_digest` is how a
guest that touched either stream ends. A guest that touched neither publishes
`constants::IO_DIGEST_EMPTY`, which is this digest for two empty streams.

**A guest that panics after touching fd 0 or fd 1 is unprovable**, and that is
a consequence rather than an oversight: `#[panic_handler]` cannot know the
streams and cannot allocate, so it cannot publish their digest. A guest whose
failure paths must be provable exits through
`transcript::exit_with_io_digest(status)` rather than panicking.

```rust
transcript::io_digest(public_input: &[u8], public_output: &[u8]) -> Fr
```

**Packing.** Each stream is packed into `Fr` limbs 31 bytes at a time,
little-endian, with the final partial limb zero-extended. 31 bytes is below
`2^248 < p`, so every limb is canonical by construction. This is exactly the
byte encoding `docs/spec/transcript.md` §10 already froze.

**Absorption.** Into a Poseidon2 duplex of its own, in this order:

1. the input domain tag, `transcript_tags::PUBLIC_INPUT_STREAM` = 20;
2. the input's **byte** length, as an `Fr`;
3. the input limbs;
4. the output domain tag, `transcript_tags::PUBLIC_OUTPUT_STREAM` = 21;
5. the output's byte length;
6. the output limbs.

which is precisely two `Transcript::append_bytes` messages — the typed layer's
framing is `tag, length, payload`, and its length for a byte message is the byte
count. The digest is then **lane 1 after the final permutation**, taken through
the squeeze API: a raw `Transcript::sample`, not a `challenge_scalar`, because a
challenge under one of these tags would be one tag in two message kinds, which
`docs/spec/transcript.md` §8 forbids.

**An empty stream** contributes its tag and a zero length and no limbs.

**Why this binds the pair.** The absorbed stream parses back uniquely: the two
tags are distinct constants, and each length says how many limbs follow it. So

* swapping two unequal streams changes the digest, because it swaps their tags;
* appending a zero byte changes the digest, because it changes a length — this
  is what the length is for, since the zero-extended final limb would otherwise
  make `x` and `x ‖ 0x00` absorb identically;
* flipping any bit of either stream changes a limb.

Test vectors: `crates/transcript/tests/vectors/io_digest.txt`, generated by
`tools/transcript-ref`, which transcribes this section over Plonky3's
permutation and never links `crates/transcript`.

## 7. The memory map

`crates/guest-sdk/link.ld`, frozen with the symbol names:

```ld
MEMORY { RAM (rwx) : ORIGIN = 0x00010000, LENGTH = 0x7FFF0000 }
```

Those two numbers also live in `constants::guest_memory` as `RAM_ORIGIN` and
`RAM_LENGTH`, and `crates/constants/tests/ecall_abi.rs` checks this document, that module
and the linker script against each other. `crates/loader` refuses a `PT_LOAD` segment that
does not lie inside the window: nothing outside it is addressable, so a program that wants
to be there is not one this VM can run — and enforcing it is also what stops a hostile
`p_memsz` from sizing the loader's slot vector.

| Symbol | What |
| --- | --- |
| `__bss_start` | first byte of `.bss`; crt0 zeroes from here |
| `__bss_end` | one past the last byte of `.bss` |
| `__heap_start` | first byte above `.bss`, 16-aligned; the bump allocator's floor |
| `__stack_top` | `ORIGIN(RAM) + LENGTH(RAM)`; the initial `sp`. The allocator's ceiling sits `STACK_RESERVE` below it (§8) |

`_start` lives in its own `.text._start` input section so the linker places it
at `ORIGIN(RAM)`. It sets `sp`, zeroes `.bss` byte by byte, calls `main`, and
exits 0 if `main` returns. The `.bss` zeroing stays even though VM memory starts
zeroed, because the same binary must run correctly under QEMU, where it does
not.

Guests link with `--no-relax`. Linker relaxation rewrites instruction sequences
and shifts every later address, and S11's program identity is a function of
those addresses.

### 7.1 The segment layout, and why it is a normative part of this map

The zkVM executor makes the whole window addressable by construction: it has no
pages and no permissions, so the map above is the entire story for it. A host
program loader — `qemu-riscv32`, which is the only executor before S12, or Linux
itself — is narrower. It maps exactly the `PT_LOAD` segments the program headers
declare, page by page, at the declared permissions, and nothing else in the
address space exists at all. Two rules follow, and both are load-bearing:

- **Every writable byte a guest can touch is declared.** The heap and the stack
  grow toward each other between `__heap_start` and `__stack_top`, so the linker
  script reserves that whole span as one writable segment reaching the top of the
  window. Undeclared, it is unmapped memory under a host loader and the guest's
  first stack write dies on a signal before `main` runs. The reservation itself
  must cost nothing on disk: `p_filesz` may cover an initialised `.data` — lld
  folds one into this same segment — but must stop at or before `.bss`, or the
  ELF carries the whole 2 GiB reservation as zeroes.
- **No two segments share a page.** Each `PT_LOAD` is mapped independently, so a
  shared page takes the second mapping's permissions for all of it: an unaligned
  `.rodata` strips execute from the tail of `.text`, and zero fill landing on a
  read-only page is refused outright. `.text`, `.rodata`, `.data` and `.bss` are
  therefore each page-aligned, which costs three pages of address space.

`crates/loader/tests/layout.rs` holds the image to both rules by reading the
program headers, and needs neither a cross-compiler nor an emulator to do it.

## 8. The guest-sdk surface

```rust
guest_sdk::entry!(main);              // gives a function the `main` symbol

pub fn read_input(buf: &mut [u8]) -> usize;   // fd 0, committed
pub fn commit(bytes: &[u8]);                  // fd 1, committed
pub fn hint(buf: &mut [u8]) -> usize;         // fd 3, advice
pub fn log(bytes: &[u8]);                     // fd 2, ignored
pub fn exit(code: i32) -> !;
pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool;   // false on -ENOSYS
```

`read_input` and `hint` fill the buffer or stop at the end of the stream, and
return how many bytes they got; a caller that needs an exact length must check.
`commit` and `log` write all of their bytes. The allocator bumps upward from
`__heap_start` and `dealloc` does nothing. An allocation that would end above
`__stack_top - STACK_RESERVE` (`constants::guest_memory`, 8 MiB), or above the
live `sp`, exits 71 rather than returning null. The top of RAM therefore belongs
to the stack, and no block is ever handed out over a frame in use.

The ceiling was `__stack_top` until S12. With it, an exhausted heap handed out
blocks over live stack frames, and safe code writing into one rewrote locals and
return addresses. `crates/emulator/tests/consistency.rs` holds each half of the
rule. What no allocator check can see is a stack that grows past its reserve
after the heap has filled below it.
