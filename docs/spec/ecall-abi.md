# The guest ABI

The ecall convention, every ecall number, the guest's address space and the SDK over them. A guest
has no file descriptors and no I/O syscall: its public input, journal and advice are memory
([public-values.md](public-values.md)), so an ecall ends the execution or hands a frame to a
delegation.
`constants::ecall` and `constants::guest_memory` are the numbers' one home; this page describes them,
and `crates/constants/tests/memory.rs` holds `apogee.ld`'s `MEMORY` line to the map.

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
| 93 | `EXIT` | deterministic | end the execution with status `a0`'s low word, read as an `i32`: the statement's exit status; nonzero is a failed execution, still provable |
| `0x0510` | `POSEIDON2` | deterministic | the Poseidon2-A64-C5 permutation of the 16 lanes at `a0`, two little-endian words each, in place; a lane read mod `p`, written canonical |
| `0x0511` | `MUL_DIV_U256` | deterministic | `a`, `b`, `d` at `a0`, eight little-endian words each, become `⌊a·b/d⌋`, `a·b mod d`, `d`; the caller owes `d ≠ 0` and a quotient below `2^256`, which the emulator refuses as `DelegationFrame` |
| `0x0514` | `FALCON512` | deterministic | the Falcon-512 lattice check over the 5 words at `a0`: the addresses of `h`, `s2` and `c`, 512 `u16` coefficients each, every one read mod `q = 12289`, then `‖s1‖²`'s low and high words, written, `s1 = (c − s2·h) mod (q, x^512 + 1)` centered; the caller owes word-aligned arrays disjoint from each other and the frame, which the emulator refuses as `DelegationFrame` ([precompiles.md](precompiles.md) §7) |
| `0x0515` | `FALCON512_SAMPLE` | deterministic | the 8 lanes at `a0`, two little-endian words each, each below `808·q^4`, become their four base-`q` digits in place, two `u16` a word; a lane at or above the bound is refused as `DelegationFrame` ([precompiles.md](precompiles.md) §9) |
| `0x0516` | `FALCON512_DECODE` | deterministic | the 4 words at `a0`, a source's and a polynomial's addresses, the mode (0 a key's `h`, 1 a signature's compressed `s2`) and a word written: the encoding at the source decoded into 512 coefficients below `q`, a `u16` each, at the polynomial, `‖s2‖²` and the stream's end written over the last two words; a malformed encoding, and misaligned or overlapping addresses, are refused as `DelegationFrame` ([precompiles.md](precompiles.md) §8) |
| `0x0517` | `MPT_ROOT` | deterministic | the 18 words at `a0`, an op program's address and its count `n`, get the program's value over words 2–17, a crit-bit trie's root as 8 lanes, two little-endian words each, canonical; the caller owes `1 ≤ n ≤ 2^20` word-aligned ops whose info words decode, word-aligned blocks, each park taken by exactly one later JOIN and no word read twice, and the emulator refuses any other program as `DelegationFrame` ([precompiles.md](precompiles.md) §6.4) |

A class says who chooses the result. **deterministic**: a function of the guest's own state, which
a circuit proves. **advice**: chosen by the prover; no number has it. A proof admits these seven:
`ADD_SUB_LUI_AUIPC` holds an exit row's `a7` to 93, and a delegation call's row writes an anchor only
the family of its number reads ([precompiles.md](precompiles.md) §2). A delegation call preserves
`a0`, as every register; its frame is a word-aligned span a store could write, each word checked as
one, below `ADVICE_ORIGIN` (§5): a frame reaching the advice is the fatal `OutOfBounds`
([precompiles.md](precompiles.md) §1). `FALCON512`'s arrays, `FALCON512_DECODE`'s source and
`MPT_ROOT`'s ops and blocks are not their frames: each call reads them, each word checked and
bounded as a load's, and they may lie anywhere a load reaches, the advice included.

## 3. Retired numbers

| Number | Constant | Was |
| --- | --- | --- |
| 63 | none | POSIX `read(fd, buf, len)` |
| 64 | none | POSIX `write(fd, buf, len)` |
| 0x0507 | none | a delegation call: one keccak-f[1600] round over a frame at `a0` |
| 0x0508 | none | a delegation call: four SHA-256 compression rounds over a frame at `a0` |
| 0x0512 | none | a delegation call: the root of a fixed-depth Merkle path over a frame at `a0` |
| 0x0513 | none | a delegation call: Keccak-f[1600] of the 25 lanes at `a0`, in place |

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

`crates/guest-sdk/apogee.ld` declares one region, `constants::guest_memory`'s `RAM_ORIGIN` and
`RAM_LENGTH`:

```ld
MEMORY { RAM (rwx) : ORIGIN = 0x00010000, LENGTH = 0x7FFF0000 }
```

Addresses are 64-bit registers, but every address a guest reaches is below `2^32`: an effective
address at or above it is a fatal `OutOfBounds`, a jump target there `NotAnInstruction`, and the ELF's
entry and segments are refused there ([program.md](program.md) §1). The space below `2^32`:

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
  is the image's property and not the executor's, calls each function pointer in
  `[__init_array_start, __init_array_end)` in order, calls `__apogee_main`, and exits with what it
  returned: `entry!`'s `main` returns 0, a C `main` its own status (§7). The pointers are C++'s
  dynamic initializers and C's constructor functions; `apogee.ld` gathers them in `.data`,
  prioritised ones first, with C's destructor functions after them in `[__fini_array_start,
  __fini_array_end)`, and places the small-data sections `.srodata`, `.sdata` and `.sbss` with
  `.rodata`, `.data` and `.bss`. `__apogee_main` is the guest's `main`, unless the guest has
  destructors: for one whose image holds `__cxa_atexit` or destructor functions, `apogee.ld` makes
  it `main`, then the destructors registered with `__cxa_atexit`, the latest first, then the
  destructor functions, the last first. `__cxa_atexit` is an archive member of its own, which the
  linker takes only for a reference and keeps under `--gc-sections` only for one from live code.
  Every other exit, `exit` and a panic among them, skips the destructors.
- Nothing detects a stack that grows past its reserve after the heap has filled below it.

### 5.1 The segment layout

A guest ELF loads under two loaders. `crates/loader` lays its `PT_LOAD`s into a flat space the
executor makes addressable whatever the headers say, with no pages and no permissions. A host loader
maps exactly the `PT_LOAD`s, page by page, at their permissions, and nothing else exists. The
headers are the image's account of its own memory, read by every tool but this VM, so `apogee.ld`
makes them true:

- **Every writable byte is declared.** `.bss` runs to `ORIGIN(RAM) + LENGTH(RAM)`, so the heap and
  the stack lie in one writable segment ending at `__stack_top`, whose file bytes stop at or before
  `.bss`, the 2 GiB reservation being `NOBITS`. Undeclared, the first stack push would fault.
- **No two segments share a page.** `.text`, `.rodata`, `.data` and `.bss` are each 4096-aligned: a
  page two mappings share takes the second's permissions, stripping execute from `.text`'s tail or
  putting zero fill on a read-only page, which a host loader refuses. Every loadable section the
  compilers emit is listed in one of the four, the unwind tables in `.rodata`: an unlisted one is
  an orphan the linker places itself, on `.text`'s page once `--gc-sections` empties `.rodata`.

`crates/loader/tests/layout.rs` holds every guest, built from source, to both by parsing its headers.

## 6. The guest-sdk surface

`crates/guest-sdk` is the guest's runtime. Only `exit` and the precompiles' shims issue an ecall;
the rest is loads and stores.

| Item | What |
| --- | --- |
| `entry!(f)` | exports the `main` crt0 calls, a wrapper calling `f` |
| `public_input()` | the public input payload, its length word clamped to the window |
| `read_input(buf)` | copies `min(buf.len(), public_input().len())` bytes and returns the count: it may return short |
| `commit(bytes)` | appends to the journal and its length word; exits 70 rather than overflow the window |
| `journal()` | what has been committed |
| `advice()` | the advice payload, its length clamped to the region; bound by nothing, so the guest checks it |
| `exit(code)` | `EXIT`; publishes nothing beyond what was committed |
| allocator | bumps up from `__heap_start`, never frees; exits 71 when a block would end above `__stack_top − STACK_RESERVE` or the live `sp` |
| panic handler | exits 101 and writes nothing: a panicking guest is provable, having published what it committed |
| `poseidon2_permute(state)`, `Digest`, `poseidon2_compress(l, r)` | `POSEIDON2` over a `[u64; 16]`; 8 lanes, each below `p`; and the first 8 lanes of the permutation of two `Digest`s ([precompiles.md](precompiles.md) §5) |
| `U256` | a 256-bit integer; its division and `mul_div` are `MUL_DIV_U256` |
| `mpt_eval(ops)` | `MPT_ROOT` over an op program of `ops.len() / 2` ops, whose blocks may be advice read in place ([precompiles.md](precompiles.md) §5, §6.3) |
| `mpt::leaf(key, value)`, `mpt::Trie::{open, root, set, insert, remove}` | a table's crit-bit trie: a leaf, `POSEIDON2`; a batch's touched keys opened from an advised proof and edited, each root one `mpt_eval` ([precompiles.md](precompiles.md) §5, §6.1–§6.3) |
| `falcon512::s1_norm(h, s2, c)`, `falcon512::Poly` | `FALCON512` over three word-aligned `[u16; 512]`, which may be advice read in place: `‖s1‖²` ([precompiles.md](precompiles.md) §5) |
| `falcon512::sample(lanes)` | `FALCON512_SAMPLE` over a `[u64; 8]`, each lane below `808·q^4`, as its four base-`q` digits ([precompiles.md](precompiles.md) §5) |
| `falcon512::PublicKey::{decode, key_digest, address, verify}` | a Falcon-512 key from its advised form, its key digest K and address, and a signature's verification under it and a context, any failure ending the execution: its decoding `FALCON512_DECODE`, its lattice check `FALCON512`, K and HashToPoint `POSEIDON2` and `FALCON512_SAMPLE` ([precompiles.md](precompiles.md) §5, §7.7) |

## 7. The C ABI

`libapogee_guest.a` is `crates/guest-sdk` built as a static library, and `apogee_guest.h` declares
what it exports with C linkage: §6's surface for a C or C++ guest, which the library implements by
calling it.

| C function | §6's item |
| --- | --- |
| `const uint8_t *apogee_public_input(size_t *len)` | `public_input()`, its length stored where `len` is not null |
| `const uint8_t *apogee_advice(size_t *len)` | `advice()` |
| `void apogee_commit(const void *bytes, size_t len)` | `commit` |
| `void apogee_exit(int32_t code)` | `exit`, never returning |
| `void apogee_poseidon2_permute(uint64_t state[16])` | `poseidon2_permute` |
| `int32_t apogee_mul_div_u256(a, b, d, q, r)` | `U256::mul_div_rem` over four-limb arrays: 0, or 1 and nothing written where it is `None` |
| `uint64_t apogee_falcon512_s1_norm(h, s2, c)` | `falcon512::s1_norm` over three `uint16_t[512]`, each 4-aligned, the three apart: a panic, exit 101, otherwise |
| `void apogee_falcon512_sample(uint64_t lanes[8])` | `falcon512::sample` over 8 lanes, 8-aligned and below the advice region: a panic, exit 101, where a lane is at or above `808·q^4` |
| `uint32_t apogee_falcon512_decode(mode, src, dst, end)` | the `FALCON512_DECODE` call in `mode` from `src` into `uint16_t dst[512]`, both 4-aligned and apart: `‖s2‖²`, 0 for a key, and the stream's end stored where `end` is not null; a malformed stream is the call's refusal |
| `int32_t apogee_mpt_eval(ops, n, root)` | `mpt_eval` over the `n` ops at `ops`: 0, or 1 and nothing written where `n` is outside `1..=2^20` or `ops` is not 4-aligned |
| `int32_t apogee_mpt_leaf(key, key_len, value, value_len, leaf)` | `mpt::leaf`: 0, or 1 and nothing written past 112 bytes |
| `int32_t apogee_mpt_root(key_len, m, keys, leaves, proof, root)` | `mpt::Trie::open` over `m` sorted keys of `key_len` bytes, their leaves and the proof at `proof`, then `root()`: 0, or 1 and nothing written where `key_len` is outside `1..=64`, a leaf lane is not below `p` or `proof` is not 4-aligned; keys not strictly ascending, and a proof that does not open them, a panic, exit 101. A batch's inserts and removes are Rust's alone |

The library's `_start` is crt0's (§5): it runs the guest's static initializers and calls its own
`int main(void)`, exiting with what it returns; the header declares `main` with C linkage, which a
freestanding C++ compiler does not give it. Its `__cxa_atexit` and `__dso_handle`, an archive
member of their own (`crates/guest-sdk/cxa`), are what C++ registers a static object's destructor
with: each registration is one record from the allocator, and the destructors run when `main`
returns, for a guest whose image holds them (§5). The library also exports `memcpy`, `memmove`,
`memset`, `memcmp` and the compiler's 128-bit integer helpers, weakly. The toolchain, the bundle
and a worked guest are [guest-program-manual.md](../guest-program-manual.md) §11.
