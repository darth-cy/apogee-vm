---
title: S10 — Guest toolchain + SDK + loader

---

# S10 — Guest toolchain + SDK + loader

This stages touches on ecall ABI, RVC expansion, linker script and startup stub and reproducibility. ELF, a stock target triple and the Linux syscall convention all have external maintainers, so taking the three buys `objdump`/`nm`/`readelf` and qemu-riscv32 for free.

## Depends on / Inputs
- You consume `Fr` from S01 (canonical LE serde) and `poseidon2_permute` from S02, used only by the host-side public I/O digest reference implementation. This stage is otherwise pure toolchain and host-side plumbing.
- Master invariants govern the guest target, ecall ABI and loader-expansion rules.

## Deliver
- The `guest-sdk` crate supplies the `#[entry]` attribute macro and crt0 startup stub, the linker script, a bump allocator, a panic handler, the ecall shims `read_input()`, `commit()` and `hint()`, and the precompile syscall-number range. These are shims only; no precompile circuits exist yet.
- The `loader` crate parses ELF (static PT_LOAD only, rejecting dynamic and relocatable), expands RVC, and produces `ProgramImage`.
- `guests/fib` is a Fibonacci guest that reads n from public input and commits the result.
- `guests/echo` is a read/commit round-trip fixture for the ecall shims, echoing fd 0 input to fd 1 output. This stage owns the master layout's `guests/echo` entry.
- The guest template config comprises `.cargo/config.toml` (target and runner), `rust-toolchain.toml` (pinned stable) and pinned linker flags.
- `docs/spec/ecall-abi.md` holds the syscall table. That document IS the ABI — a document, not a program, which keeps the maintenance surface small. It includes the **public I/O digest** section below.
- You define the **public I/O digest** convention and its host-side reference implementation `io_digest(public_input: &[u8], public_output: &[u8]) -> Fr`. That single Fr value binds the fd 0 and fd 1 byte streams. Compute it with `poseidon2_permute` (S02) over a defined byte→Fr packing, with domain separation between the two streams and explicit length binding for each. The statement-binding order later absorbs it as "public I/O digest". You define it now so every later stage recomputes the identical value.
- A loader differential-test harness checks the loader against `objdump`/QEMU decode.

## Core algorithm
Build for `riscv32imac-unknown-none-elf` on stable Rust with a pinned toolchain.

An ecall follows the Linux RISC-V syscall convention (a7 number, a0–a5 args, a0 return), so qemu-riscv32 runs guests unmodified. Precompile arguments travel as pointers in a0–a5, since a 64-byte block does not fit in registers, and dispatch is by ecall, not a CSR write. zkVM I/O and precompiles live in disjoint documented number ranges, and unknown numbers return `-ENOSYS`.

The loader expands **every** compressed instruction to its exact 32-bit equivalent in a linear sweep of `.text`. The C extension is purely an encoding: every valid 16-bit form is exactly one existing 32-bit instruction, with no compressed-only semantics. Length comes from bits [1:0]: `11` means 32-bit, each of the other three patterns means 16-bit. Addresses are **preserved, never compacted**: a `c.addi` at `0x1002` stays at `0x1002` occupying two bytes. Expansion changes representation, not address. Compacting into 4-byte slots would shift every later address and break linker-resolved function pointers and computed jumps. The sweep is fragile because instruction boundaries are not local: data embedded in `.text` desyncs it and everything after decodes as garbage. Compiler output stays in sync because GCC and LLVM keep constants in `.rodata`, and a desync reaching real code diverges loudly under QEMU.

A `ProgramImage` is the post-load memory image plus entry point plus the expanded instruction stream at halfword granularity, with mid-instruction and non-instruction slots marked. It is a deterministic function of the ELF bytes. Represent it as sorted loaded segments, the entry pc and a pc/2-indexed slot vector. Serialize it with `postcard` over fields in declaration order, using sorted vectors and never hash maps.

The linker script is the memory map, symbols included:

```ld
MEMORY { RAM (rwx) : ORIGIN = 0x00010000, LENGTH = 0x7FFF0000 }
ENTRY(_start)
SECTIONS {
  .text   : { *(.text._start) *(.text*) } > RAM
  .rodata : { *(.rodata*) } > RAM
  .data   : { *(.data*) } > RAM
  .bss    : { __bss_start = .; *(.bss*) *(COMMON); __bss_end = .; } > RAM
  . = ALIGN(16);
  __heap_start = .;
  __stack_top = ORIGIN(RAM) + LENGTH(RAM);
}
```

crt0 is `_start`, in its own `.text._start` section so the linker places it first, and it does four things: point `sp` at `__stack_top`, zero the words from `__bss_start` to `__bss_end`, `call main`, and on return exit through an ecall with a7 = 93 and a0 = 0. Keep the `.bss` zeroing even though VM memory starts zeroed: the same binary must run correctly under QEMU, where memory is not, and QEMU is the only executor this stage has.

`#[entry]` is an attribute macro that gives the annotated function the `main` symbol the stub calls. The allocator bumps from `__heap_start` upward, and `dealloc` is a no-op. An allocation crossing `__stack_top` exits nonzero. The panic handler writes message and location to fd 2, then exits nonzero.

The harness diffs (address, encoding) pairs parsed from `objdump -d` against the image, not mnemonic text. The committed corpus carries at least the fixtures Acceptance 4 and 6 require, and further fixtures are welcome.

## Must-be-exact
1. Pin the toolchain with `rust-toolchain.toml`. The build works on stock stable Rust, with no nightly, no `-Zbuild-std` and no custom target JSON.
2. Link with `--no-relax` and pinned flags. Linker relaxation destabilizes addresses across toolchain versions, and program identity in S11 depends on address stability.
3. Builds are reproducible: two clean builds of the same guest source on the pinned toolchain produce byte-identical ELFs.
4. RVC expansion accepts only base C encodings, in the RV32 flavor. Any `Zc*`, reserved encodingsor unrecognized encoding is a loud loader error naming the offending pc.
5. Addresses are never compacted, and jump and branch targets remain valid at 2-byte granularity.
6. ecall numbering uses Linux numbers for the standard subset you implement, with exit=93, read=63 and write=64 at minimum. zkVM-specific I/O and the precompile range each get their own documented range, disjoint from the Linux numbers and from each other. Numbers are append-only forever: once a program's identity is published its ABI is frozen, and redefining one does not fail loudly — it quietly makes an old program compute something else. One source, pinned: `crates/constants` (`#![no_std]`) defines all ecall numbers and range boundaries once. The guest-sdk shims, the S12 emulator dispatch and every later delegation artifact reference those constants, and the `docs/spec/ecall-abi.md` table is test-asserted against them.
7. The fd conventions are fd 0 = public input (committed), fd 1 = public output/journal (committed), fd 2 = stderr (free, verifier-ignored) and fd 3 = private hint channel (uncommitted). Document them in `docs/spec/ecall-abi.md`, with the per-syscall nondeterminism policy (trap / constant / commit) for every implemented number. Any syscall returning host data — `getrandom`, `time`, or the `RandomState` Rust's `HashMap` reaches for on first use — is nondeterministic prover advice: unless its returns are folded into the public I/O digest, the proof does not pin down which execution happened and a malicious prover picks them. Classify every implemented number.
8. The loader rejects dynamic, relocatable, or non-RV32 ELFs with named errors.
9. The loader is soundness-critical, since wrong expansion means a valid proof of the wrong program. It gets its own differential test, decode-for-decode against `objdump -d` (and QEMU where objdump is ambiguous), not just "the guest ran".
10. `io_digest` is a pure function of the two byte streams. The empty-stream cases are defined. The input and output streams are domain-separated, so swapping unequal streams changes the digest. Each stream is length-bound, so appending a zero byte changes the digest. The output is one canonical-LE `Fr`. The convention is frozen at this stage: later stages recompute it, never redefine it.
11. Both non-Linux ranges sit above every Linux number. zkVM-specific I/O takes `0x0400..=0x04FF`, and the precompile range takes `0x0500..=0x05FF`, which is where shims land. Record both ranges in `docs/spec/ecall-abi.md` and in the handoff. The split does real security work: host calls are nondeterministic prover advice, precompiles are deterministic functions of memory, and a reviewer must tell which a number is at a glance. Mixing them is how a nondeterministic call ends up treated as proven.
12. `io_digest` packing is frozen with the convention. Pack each stream into `Fr` limbs 31 bytes at a time, little-endian, zero-extending the final partial limb so every limb stays canonical. Absorb into the frozen Poseidon2 duplex in this order: input domain tag, input byte length as an `Fr`, input limbs, then the same three for the output. The digest is lane 1 after the final permutation through the squeeze API (squeeze always gives lane 1 first). An empty stream contributes its tag and a zero length, no limbs. Both tags live in `constants`.

## Acceptance
1. `cargo build --target riscv32imac-unknown-none-elf` builds `guests/fib` on the pinned stable toolchain, from the template config, with no extra flags typed.
2. Reproducibility: two clean builds with fresh target dirs give byte-identical ELFs, and CI compares hashes.
3. `guests/fib` runs under `qemu-riscv32` and writes the correct Fibonacci value to fd 1, checked against a host-computed value. No zkVM emulator exists yet, so QEMU is the only executor at this stage.
4. Loader differential: the loader's expanded instruction listing agrees with `objdump -d` instruction-for-instruction at every address, for `guests/fib` plus an RVC-dense fixture set. That set must include compressed loads/stores, `c.jal`, `c.beqz`/`c.bnez` and `c.lwsp`/`c.swsp`. Any mismatch fails the test. Fixtures are committed and pinned by hash.
5. Address preservation: symbol addresses from `nm` on an RVC-dense fixture match the `ProgramImage` addresses of those instructions exactly.
6. Negative controls: (a) a fixture containing an all-zero halfword and a reserved `c.addi4spn` produces error. (b) A crafted `Zcmp`-style encoding produces the loud loader error with the pc named. (c) A dynamic ELF is rejected with the named error.
7. `ProgramImage` determinism: loading the same ELF twice yields byte-identical serialized images.
8. ecall shims: a guest exercising `read_input`/`commit`/`hint` runs under QEMU, and a guest invoking a number from the precompile range receives `-ENOSYS` under QEMU and completes its software fallback path.
9. `docs/spec/ecall-abi.md` exists and lists every implemented number with its nondeterminism classification. A test asserts that the shim numbers in `guest-sdk` match the doc's table, keeping the single source of truth in code with the doc generated or checked.
10. `io_digest` ships committed test vectors with expected Fr values, covering empty/empty, input-only, output-only and a multi-block stream. Sensitivity tests per Must-be-exact 10 show that swapping the streams, appending a zero byte and flipping one byte each change the digest. Recomputing the fib fixture's digest from its recorded fd 0/1 bytes twice yields identical values.

## Handoff
Freeze `ProgramImage` (fields and serialization) and `loader::load_elf(bytes: &[u8]) -> Result<ProgramImage, LoaderError>`. Freeze the full ecall number table and range boundaries, and the fd conventions. Freeze the linker-script symbol names `__heap_start`, `__stack_top`, `__bss_start`/`__bss_end`, the guest-sdk public functions, and the pinned toolchain version and linker flags. Freeze the **public I/O digest** convention too: `io_digest(public_input: &[u8], public_output: &[u8]) -> Fr`, its exact packing and domain-tag recipe, and its test vectors. That is the value the statement-binding order absorbs as "public I/O digest", and later stages recompute it. Record the chosen precompile range explicitly, since all shims must land inside it.