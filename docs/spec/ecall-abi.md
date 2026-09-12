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
the oracle the emulator is compared against instruction by instruction, so
the choice is load-bearing rather than decorative.

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
| 0x0500 | `PRECOMPILE_POSEIDON2` | deterministic | Poseidon2 over `[Fr; 3]`, `a0` = state pointer. No circuit yet: every executor answers `-ENOSYS` and the caller runs its software path |

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
MEMORY { RAM (rwx) : ORIGIN = 0x00010000, LENGTH = 0x0FFF0000 }
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
  ELF carries 256 MiB of zeroes.
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
return addresses. `crates/emulator/tests/portability.rs` holds each half of the
rule. What no allocator check can see is a stack that grows past its reserve
after the heap has filled below it.
