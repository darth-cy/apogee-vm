# The guest ABI

The ecall convention, every ecall number, the guest's address space and the SDK over them. A guest
has no file descriptors and no I/O syscall: its public input, journal and advice are memory
([public-values.md](public-values.md)), so an ecall only ends the execution or hands a frame to a
circuit. `crates/constants/tests/ecall_abi.rs` holds this page's tables to `constants::ecall` and
its `MEMORY` line to `link.ld`.

## 1. The calling convention

| Register | Role |
| --- | --- |
| `a7` | the number |
| `a0` | in: the one argument, an exit status or a delegation's frame base ([delegation.md](delegation.md) §4) |
| `a0` | out: the result, 0 or a negated errno |

`a1`–`a5` are reserved for a call that needs more arguments; none does. A recursion-format
delegation answers its frame base advanced past the frame ([recursion.md](recursion.md) §1.4). An
ecall preserves every register but `a0`: its row writes no other
([execution-trace.md](execution-trace.md) §6), so the memory argument carries the rest across it.

## 2. The number ranges

| Constant | Value | What |
| --- | --- | --- |
| `ZKVM_IO_FIRST` | 0x0400 | first host call |
| `ZKVM_IO_LAST` | 0x04FF | last host call |
| `PRECOMPILE_FIRST` | 0x0500 | first precompile |
| `PRECOMPILE_LAST` | 0x05FF | last precompile |

Both ranges lie above 1023, the whole Linux number space, and are disjoint, so a number says its
class: a host call would return a value the prover chose, a precompile is a deterministic function
of guest memory that its circuit proves. The host-call range is reserved and empty: advice is a
memory region the prover fills and the guest checks ([public-values.md](public-values.md) §6),
inside the memory argument, where a value returned in a register would be bound to nothing.

## 3. Syscall numbers

Every number this VM implements. All but `EXIT` are delegations, whose families, anchor spaces and
frames are [delegation.md](delegation.md) §3's registry: the first six are the base format's, the
last four the recursion format's ([recursion.md](recursion.md) §2).

| Number | Constant | Class | What |
| --- | --- | --- | --- |
| 93 | `EXIT` | deterministic | end the execution with status `a0`, the statement's exit status; nonzero is a failed execution, still provable |
| 0x0500 | `PRECOMPILE_POSEIDON2` | deterministic | the width-3 Poseidon2 permutation over canonical `Fr` lanes |
| 0x0502 | `PRECOMPILE_FR_ARITH` | deterministic | one `Fr` add, multiply or inverse over `Fr`'s in-memory form |
| 0x0504 | `PRECOMPILE_MOD_MUL` | deterministic | `a·b mod m`, `m` one of four Ethereum moduli a selector names |
| 0x0506 | `PRECOMPILE_EC_ADD` | deterministic | one third of a complete point addition, secp256k1 or BN254 G1 |
| 0x0507 | `PRECOMPILE_KECCAK_F` | deterministic | one round of keccak-f[1600]; a permutation is 24 calls |
| 0x0508 | `PRECOMPILE_SHA256_COMP` | deterministic | four rounds of SHA-256's compression; a compression is 16 calls |
| 0x0509 | `PRECOMPILE_FR_OP` | deterministic | one operation over field cells |
| 0x050A | `PRECOMPILE_P2_FIELD` | deterministic | one transcript duplex step over field cells |
| 0x050B | `PRECOMPILE_FIELD_IO` | deterministic | eight RAM words into a field cell, or back |
| 0x050C | `PRECOMPILE_FQ_OP` | deterministic | one BN254 base-field operation over field cells |

A class says who chooses the result. **deterministic**: a function of the guest's own state, which
a circuit proves. **advice**: chosen by the prover; no number has it (§2). These are exactly the
ecalls a proof admits: `ADD_SUB_LUI_AUIPC` holds every ecall row's `a7` to 93 or to a registered
delegation number, the base format's circuit knowing the first six ([add-sub.md](add-sub.md),
[recursion.md](recursion.md) §1.2).

## 4. Retired numbers

| Number | Constant | Was |
| --- | --- | --- |
| 63 | none | POSIX `read(fd, buf, len)` |
| 64 | none | POSIX `write(fd, buf, len)` |
| 0x0501 | `RETIRED_KECCAK_F_WHOLE_PERMUTATION` | a whole keccak-f[1600] over a 200-byte frame, which `0x0507` replaces |
| 0x0503 | `RETIRED_MOD_MUL_WITNESSED_MODULUS` | `a·b mod m` over a 128-byte frame carrying `m`, which `0x0504` replaces |
| 0x0505 | `RETIRED_SHA256_COMP_WHOLE_COMPRESSION` | a whole compression over a 96-byte frame, which `0x0508` replaces |

A number is assigned once. A retired one is never reassigned and answers `-ENOSYS` (§5): given a
second meaning, it would run an old binary with its frame misread to a plausible wrong answer.

## 5. Every other number

| Constant | Value | What |
| --- | --- | --- |
| `ENOSYS` | 38 | answered as `-ENOSYS` in `a0` |

A number not in §3 answers `-ENOSYS` and falls through: the retired numbers, the host-call range,
and every syscall a library might make for host data — `getrandom`, `clock_gettime`, the seeding
of std's `RandomState`. Host data is prover advice, and a guest that needs it takes it from the
advice region, where checking it is visibly the guest's job. Such a call executes and cannot be
proved: the `ADD_SUB_LUI_AUIPC` fill refuses its row.

`-ENOSYS` is also the delegation ABI's "no circuit" answer, on which a base-format shim runs its
software path ([delegation.md](delegation.md) §2); this executor never gives it to a §3 number. A
registered number the image did not declare is the fatal `DelegationFamilyAbsent` on the tracing
paths ([delegation.md](delegation.md) §7).

## 6. The memory map

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
- A delegation frame lies wholly in RAM ([delegation.md](delegation.md) §4). `crates/loader`
  refuses a `PT_LOAD` outside RAM ([program.md](program.md) §1), and a decoded table's height bounds
  how far `.text` reaches ([program.md](program.md) §5).
- crt0's `_start` sets `sp`, zeroes `[__bss_start, __bss_end)` byte by byte, so that a zero `.bss`
  is the image's property and not the executor's, calls `main`, and exits 0 if it returns.
- Nothing detects a stack that grows past its reserve after the heap has filled below it.

### 6.1 The segment layout

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

## 7. The guest-sdk surface

`crates/guest-sdk` is the guest's runtime. Only `exit` and the delegation shims issue an ecall; the
rest is loads and stores.

| Item | What |
| --- | --- |
| `entry!(f)` | exports the `main` crt0 calls, a wrapper calling `f` |
| `public_input()` | the public input payload, its length word clamped to the window |
| `read_input(buf)` | copies `min(buf.len(), public_input().len())` bytes and returns the count: it may return short |
| `commit(bytes)` | appends to the journal and its length word; exits 70 rather than overflow the window |
| `journal()` | what has been committed |
| `advice()` | the advice payload, its length clamped to the region; bound by nothing, so the guest checks it |
| `exit(code)` | `EXIT`; publishes nothing beyond what was committed |
| `keccak256`, `sha256` | over `KECCAK_F` and `SHA256_COMP`, with a software fallback on `-ENOSYS` from the first call |
| `poseidon2_permute` | over `POSEIDON2`; `false` on `-ENOSYS`, for the caller's own permutation |
| `ec_add`, `ec_mul`, `ec_identity` | homogeneous projective points over `EC_ADD`; `None` on `-ENOSYS` |
| `recursion::*` | the raw shims over word-aligned frame types, `false` on `-ENOSYS`; the recursion format's (`fr_op`, `p2_field`, `field_io`, `fq_op` and the tape helpers `import`, `import_run`, `replay`) have no software path |
| allocator | bumps up from `__heap_start`, never frees; exits 71 when a block would end above `__stack_top − STACK_RESERVE` or the live `sp` |
| panic handler | exits 101 and writes nothing: a panicking guest is provable, having published what it committed |

A delegation answer other than 0 or `-ENOSYS` exits 72, as do `-ENOSYS` after the first call of a
multi-call operation and a recursion call that does not leave `a0` past its frame. Each shim reads
its number from its declaration record ([delegation.md](delegation.md) §7); which library code
reaches which shim is [delegation.md](delegation.md) §10's.
