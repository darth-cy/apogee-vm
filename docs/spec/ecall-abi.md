# The guest ABI

The ecall convention, every ecall number, the guest's address space and the SDK over them. A guest
has no file descriptors and no I/O syscall: its public input, journal and advice are memory
([public-values.md](public-values.md)), so an ecall ends the execution or hands a frame to a
delegation.
`crates/constants/tests/ecall_abi.rs` holds this page's tables to `constants::ecall` and its
`MEMORY` line to `link.ld`.

## 1. The calling convention

| Register | Role |
| --- | --- |
| `a7` | the number |
| `a0` | in: the one argument, the exit status or a delegation frame's base |
| `a0` | out: the result, a negated errno |

`a1`–`a5` are reserved for a call that needs more arguments; none does. An ecall preserves every
register but `a0`: its row writes no other ([execution-trace.md](execution-trace.md) §6), so the
memory argument carries the rest across it.

## 2. Syscall numbers

Every number this VM implements.

| Number | Constant | Class | What |
| --- | --- | --- | --- |
| 93 | `EXIT` | deterministic | end the execution with status `a0`, the statement's exit status; nonzero is a failed execution, still provable |
| 0x0507 | `PRECOMPILE_KECCAK_F` | deterministic | one keccak-f[1600] round over the `KECCAK_F` frame at `a0`, in place; `a0` is 0 after |
| 0x0508 | `PRECOMPILE_SHA256_COMP` | deterministic | four SHA-256 rounds over the `SHA256_COMP` frame at `a0`, in place; `a0` is 0 after |

A class says who chooses the result. **deterministic**: a function of the guest's own state, which
a circuit proves. **advice**: chosen by the prover; no number has it. A proof admits `EXIT` alone:
`ADD_SUB_LUI_AUIPC` holds every ecall row's `a7` to 93 ([add-sub.md](add-sub.md)). The two
delegation calls execute, and their families' circuits exist, but **UNFINISHED**: no ecall row
requests them yet (`constants::delegation`).

## 3. Retired numbers

| Number | Constant | Was |
| --- | --- | --- |
| 63 | none | POSIX `read(fd, buf, len)` |
| 64 | none | POSIX `write(fd, buf, len)` |

A number is assigned once. A retired one is never reassigned and answers `-ENOSYS` (§4): given a
second meaning, it would run an old binary to a plausible wrong answer.

## 4. Every other number

| Constant | Value | What |
| --- | --- | --- |
| `ENOSYS` | 38 | answered as `-ENOSYS` in `a0` |

A number not in §2 answers `-ENOSYS` and falls through: the retired numbers, and every syscall a
library might make for host data — `getrandom`, `clock_gettime`, the seeding of std's
`RandomState`. Host data is prover advice, and a guest that needs it takes it from the advice
region, where checking it is visibly the guest's job. Such a call executes and cannot be proved:
the `ADD_SUB_LUI_AUIPC` fill refuses its row.

## 5. The memory map

`crates/guest-sdk/link.ld` declares one region, `constants::guest_memory`'s `RAM_ORIGIN` and
`RAM_LENGTH`:

```ld
MEMORY { RAM (rwx) : ORIGIN = 0x00010000, LENGTH = 0x7FFF0000 }
```

The whole 32-bit address space:

```text
[0x0000_0000, 0x0000_8000)  hole: no family initializes it; an access is a fatal OutOfBounds
[0x0000_8000, 0x0000_C000)  public input window    PUBLIC_INPUT_ORIGIN    16 KiB
[0x0000_C000, 0x0001_0000)  journal                PUBLIC_OUTPUT_ORIGIN   16 KiB
[0x0001_0000, 0x8000_0000)  RAM                    RAM_ORIGIN, RAM_LENGTH
    0x0001_0000             .text, _start first; .rodata, .data, .bss, each page-aligned
    __heap_start            .bss's end rounded up to 16; the heap grows up from here
    0x7F80_0000             __stack_top − STACK_RESERVE (8 MiB): no heap block ends above it
    0x8000_0000             __stack_top, the initial sp; the stack grows down
[0x8000_0000, 2^32)         advice                 ADVICE_ORIGIN          up to 2^29 words
```

- A load or store reaches the four regions alike, every word carrying the `RAM` tag; the windows'
  and the advice's layouts, families and binding are [public-values.md](public-values.md) §2–§6.
  None is in the ELF, so no linker symbol names them. Advice is addressable only up to the words
  the host supplied, and not at all when it supplied none.
- The hole makes a null dereference a fatal error rather than a trace nothing could prove.
- `crates/loader` refuses a `PT_LOAD` outside RAM ([program.md](program.md) §1), and a decoded
  table's height bounds how far `.text` reaches ([program.md](program.md) §5).
- crt0's `_start` sets `sp`, zeroes `[__bss_start, __bss_end)` byte by byte, so that a zero `.bss`
  is the image's property and not the executor's, calls `main`, and exits 0 if it returns.
- Nothing detects a stack that grows past its reserve after the heap has filled below it.

### 5.1 The segment layout

A guest ELF loads under two loaders. `crates/loader` lays its `PT_LOAD`s into a flat space the
executor makes addressable whatever the headers say, with no pages and no permissions. A host loader
maps exactly the `PT_LOAD`s, page by page, at their permissions, and nothing else exists. The
headers are the image's account of its own memory, read by every tool but this VM, so `link.ld`
makes them true:

- **Every writable byte is declared.** `.bss` runs to `ORIGIN(RAM) + LENGTH(RAM)`, so the heap and
  the stack lie in one writable segment ending at `__stack_top`, whose file bytes stop at or before
  `.bss`, the 2 GiB reservation being `NOBITS`. Undeclared, the first stack push would fault.
- **No two segments share a page.** `.text`, `.rodata`, `.data` and `.bss` are each 4096-aligned: a
  page two mappings share takes the second's permissions, stripping execute from `.text`'s tail or
  putting zero fill on a read-only page, which a host loader refuses.

`crates/loader/tests/layout.rs` holds the committed guest ELFs to both by parsing their headers.

## 6. The guest-sdk surface

`crates/guest-sdk` is the guest's runtime. Only `exit` and the two delegation shims issue an
ecall; the rest is loads and stores.

| Item | What |
| --- | --- |
| `entry!(f)` | exports the `main` crt0 calls, a wrapper calling `f` |
| `public_input()` | the public input payload, its length word clamped to the window |
| `read_input(buf)` | copies `min(buf.len(), public_input().len())` bytes and returns the count: it may return short |
| `commit(bytes)` | appends to the journal and its length word; exits 70 rather than overflow the window |
| `journal()` | what has been committed |
| `advice()` | the advice payload, its length clamped to the region; bound by nothing, so the guest checks it |
| `exit(code)` | `EXIT`; publishes nothing beyond what was committed |
| `keccak_f(lanes)` | keccak-f[1600] in place: 24 `PRECOMPILE_KECCAK_F` calls on one frame; exits 72 on a nonzero answer |
| `sha256_compress(state, block)` | one SHA-256 compression into `state`: 16 `PRECOMPILE_SHA256_COMP` calls, then the feed-forward; exits 72 likewise |
| allocator | bumps up from `__heap_start`, never frees; exits 71 when a block would end above `__stack_top − STACK_RESERVE` or the live `sp` |
| panic handler | exits 101 and writes nothing: a panicking guest is provable, having published what it committed |
