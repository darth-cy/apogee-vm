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
run a guest **unmodified** — QEMU was the only executor S10 had, and since S12 it is the
oracle for what a guest computes: one binary runs under both executors, so their exit
status and their fd 1 can be compared at all
(`crates/emulator/tests/qemu_outputs.rs`). The choice is load-bearing rather than
decorative.

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

The zkVM host-call range is **reserved and empty**, at S10 and still. The
compatibility streams of section 4 use the Linux calls, because a guest that
used `0x0400` for its input could not run under QEMU at all; and since S25 an
execution's **public values** use no call whatever — they are two fixed windows
of memory a guest reads and writes with ordinary loads and stores
(`docs/spec/public-values.md`).

## 3. Syscall numbers

Every number this VM implements, with its nondeterminism class. The
`Constant` column is the name in `constants::ecall`.

| Number | Constant | Class | What |
| --- | --- | --- | --- |
| 63 | `READ` | per fd | `read(fd, buf, len)`; see section 4. **Not a provable ecall** — no circuit proves it, and `prover::fill::add_sub` refuses a cycle that calls it by name (`docs/spec/public-values.md` §1) |
| 64 | `WRITE` | per fd | `write(fd, buf, len)`; see section 4. **Not a provable ecall**, for the same reason |
| 93 | `EXIT` | deterministic | `exit(status)`; nonzero is a failed execution |
| 0x0500 | `PRECOMPILE_POSEIDON2` | deterministic | Poseidon2 over `[Fr; 3]`, `a0` = the 96-byte frame base pointer, permuted in place. A **delegation** call since S23: `docs/spec/delegation.md` §12 is its frame table, `constants::family::POSEIDON2` the circuit that proves it. The three lanes cross the frame as canonical little-endian `Fr`, 8 words each |
| 0x0501 | `PRECOMPILE_KECCAK_F` | deterministic | keccak-f[1600] over the 200-byte state frame at `a0`, permuted in place. The first **delegation** call: `docs/spec/delegation.md` is its ABI, `constants::family::KECCAK_F` the circuit that proves it. An executor with the circuit answers 0; one without answers `-ENOSYS` and the caller runs its software path |
| 0x0502 | `PRECOMPILE_FR_ARITH` | deterministic | one `Fr` add, multiply or inverse over the 100-byte frame at `a0`, in place. A **delegation** call: `docs/spec/delegation.md` §13 is its frame table, `constants::family::FR_ARITH` the circuit. The operands cross the frame in `field::Fr`'s **in-memory** representation, which is what makes the call cheaper than the software operation it replaces |

The classes are:

* **deterministic** — the result is a function of the guest's own state, so
  nothing needs to bind it.
* **per fd** — see section 4; `read` and `write` are two calls each depending on
  which descriptor they name. Neither is provable on any descriptor.
* **advice** — the result is chosen by the prover. A proof says nothing about
  which value was chosen unless the guest checks it against something a proof
  does bind, which is the statement's public input or the journal it publishes
  (`docs/spec/public-values.md` §6).

## 4. File descriptors

**All four are uncommitted POSIX compatibility streams, and a proof binds none
of them.** That is S25's correction, and it is the one place this document was
wrong rather than incomplete: fd 0 and fd 1 were `FD_PUBLIC_INPUT` and
`FD_PUBLIC_OUTPUT` and were described here as committed. An execution's public
values are not a syscall's business — they are two fixed windows of memory, and
`docs/spec/public-values.md` §1 is normative. The **numbers** are frozen at
their Linux values, as every number in this document is; only the names moved.

| fd | Constant | Committed | What |
| --- | --- | --- | --- |
| 0 | `FD_STDIN` | no | POSIX standard input; **not** the public input |
| 1 | `FD_STDOUT` | no | POSIX standard output; **not** the journal |
| 2 | `FD_STDERR` | no | diagnostics, free-form, verifier-ignored |
| 3 | `FD_HINT` | no | private hints: **nondeterministic prover advice** |

No gate constrains what any of the four moves. fd 0's and fd 3's bytes are the
prover's outright, and `write(64)` on fd 1 and on fd 2 alike reaches no
verifier. Since neither call is provable (section 3), a guest that takes any of
these paths is not a guest that can be proven at all.

**fd 0 is its own stream and is not the public input.** `emulator::GuestIo`
carries the two separately — `input` fills the public input window and `stdin`
is served on fd 0 — and neither seeds the other. They were one field briefly and
the coupling was wrong in both directions: a public input is capped at
`guest_memory::PUBLIC_PAYLOAD_BYTES` and an fd 0 stream is not, and no guest
reads both paths anyway. `qemu-riscv32` maps only the image's `PT_LOAD`
segments, so the public windows and the advice region do not exist under it; a
guest written for the QEMU oracle reads fd 0 and cannot be proven, and a
provable guest reads the window and cannot run there.
`crates/emulator/tests/qemu_outputs.rs` is that comparison — the exit status and
fd 1, and nothing below them — and `guests/revm-block` carries a binary for each
(`docs/spec/public-values.md` §7).

A guest that lets a hint change what it writes to fd 1, without checking the
hint against something else, has made its output the prover's choice. That
warning stands, and since S25 it has a provable counterpart: the **journal** is
what a proof binds, the **advice region** is where the prover's bytes belong,
and the obligation to check one against something public is the guest's either
way (`docs/spec/public-values.md` §6).

Added at S12, where the first zkVM executor pinned what the table above left open:

* **Every other descriptor answers `-EBADF`.** `read` on anything but fd 0 and
  fd 3, and `write` on anything but fd 1 and fd 2, move no bytes and return
  `-EBADF` — Linux's answer, and so `qemu-riscv32`'s, which keeps one source tree
  meaning the same thing under both executors.
* **`read` returns what the stream has.** It delivers `min(count, bytes left)` and
  returns that count, so a `read` at the end of a stream returns 0. `write`
  delivers all `count` bytes and returns `count`.
* **A buffer outside the RAM window is a fatal guest error.** The bytes a call
  would move must lie in `[RAM_ORIGIN, RAM_ORIGIN + RAM_LENGTH)` (section 7) —
  ordinary RAM, and not the public windows or the advice region, which these
  calls have no business in. Linux would answer `-EFAULT`; a fatal error returns
  no trace at all, so there is nothing to report back to.
* **fd 0 is served from the statement's public input**, and `read` delivers a
  prefix of it and advances a cursor. Nothing records or binds which prefix the
  guest consumed: since S25 the executor reports the **whole** public input as
  the execution's, because that is what the window held and what the statement
  carries, whether or not a byte of it was read
  (`docs/spec/public-values.md` §9).

How a call's register reads and its buffer traffic appear in the execution trace
is `docs/spec/execution-trace.md`, not this document.

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
nondeterministic prover advice wearing the costume of a library call: unless the
guest checks what came back against something a proof binds, the proof does not
pin down which execution happened, and a malicious prover picks the values. They
are refused rather than answered, so a guest that wants one has to say so by
asking for a number in the zkVM host-call range — where a reviewer will see it.

## 6. The public I/O digest

One `Fr` over the statement's two public byte strings. **Frozen at S10**: later
stages recompute it and never redefine it, and S25 did not — the recipe below,
its tags, its position in the statement-binding order and its test vectors are
all unchanged.

**S25 is what makes it worth something.** Absorbing the digest fixes the two
byte strings before any challenge exists; what ties them to an *execution* is
the two public value windows, not this hash. The statement's `input` and
`output` are the payloads of two RAM windows, their memory columns are
committed at G8 — also before the memory challenges are squeezed — and
`verify_shard_local` step 10c holds each committed column to the verifier's own
extension of those bytes (`docs/spec/public-values.md` §5,
`docs/spec/shard-proof.md` §6). The design deferred here until S25 — the guest
computing the digest itself and leaving its words in `x24`…`x31` at exit — is
withdrawn, and the guest never computes `io_digest`.

The two tags keep their S10 names, `PUBLIC_INPUT_STREAM` and
`PUBLIC_OUTPUT_STREAM`. A tag is part of the absorbed stream, so renaming one is
not free; they domain-separate the statement's two byte strings, which is the
job they always did.

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
does not lie inside the window: a program is linked into RAM and nowhere else, so one that
wants to be elsewhere is not one this VM can run — and enforcing it is also what stops a
hostile `p_memsz` from sizing the loader's slot vector.

**The RAM window is not the whole addressable space, and has not been since S25.** Two
1 KiB **public value** windows sit below it at `PUBLIC_INPUT_ORIGIN` = `0x8000` and
`PUBLIC_OUTPUT_ORIGIN` = `0x8400`, and the **advice** region sits above it at
`ADVICE_ORIGIN` = `0x8000_0000`; `trace::addressable` is the executor's rule and everything
else — `[0, 0x8000)` and `[0x8800, RAM_ORIGIN)` — is a hole, so a null dereference is still
a loud error. None of the three is in the ELF, so no linker symbol names them and a host
loader does not map them; a guest reaches them with ordinary loads and stores at the
constants. `docs/spec/public-values.md` §2 is normative, and this section's `MEMORY` line
stays exactly what `link.ld` says.

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

pub fn public_input() -> &'static [u8];       // the input window, no ecall
pub fn read_input(buf: &mut [u8]) -> usize;   // the same, copied
pub fn commit(bytes: &[u8]);                  // the journal, no ecall
pub fn journal() -> &'static [u8];            // the journal so far
pub fn advice() -> &'static [u8];             // prover-chosen, bound by nothing

pub fn read_stdin(buf: &mut [u8]) -> usize;   // fd 0, unprovable
pub fn write_stdout(bytes: &[u8]);            // fd 1, unprovable
pub fn hint(buf: &mut [u8]) -> usize;         // fd 3, advice, unprovable
pub fn log(bytes: &[u8]);                     // fd 2, ignored, unprovable
pub fn exit(code: i32) -> !;
pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool;   // false on -ENOSYS
```

The first group issues **no ecall at all** — the windows and the advice region
are ordinary memory — and is the surface a guest that wants to be proven uses.
The second is the POSIX compatibility path of section 4: it issues `read` and
`write`, which are not provable ecalls, so a guest that takes it runs under
`qemu-riscv32` and is not provable. `docs/spec/public-values.md` §7 is the full
surface and `docs/guest-program-manual.md` §3 the guest author's version of the
choice.

`read_stdin` and `hint` fill the buffer or stop at the end of the stream, and
return how many bytes they got; a caller that needs an exact length must check.
`read_input` copies `min(buf.len(), public_input().len())` bytes and never
blocks on anything. `commit` and `log` write all of their bytes; `commit` exits
`EXIT_IO_ERROR` rather than truncating a journal that would not fit its window.
The allocator bumps upward from
`__heap_start` and `dealloc` does nothing. An allocation that would end above
`__stack_top - STACK_RESERVE` (`constants::guest_memory`, 8 MiB), or above the
live `sp`, exits 71 rather than returning null. The top of RAM therefore belongs
to the stack, and no block is ever handed out over a frame in use.

The ceiling was `__stack_top` until S12. With it, an exhausted heap handed out
blocks over live stack frames, and safe code writing into one rewrote locals and
return addresses. `crates/emulator/tests/consistency.rs` holds each half of the
rule. What no allocator check can see is a stack that grows past its reserve
after the heap has filled below it.
