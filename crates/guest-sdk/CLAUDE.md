# `crates/guest-sdk`

## What this crate owns
The guest-side runtime: the crt0 stub, the `entry!` macro, the linker script, a bump
allocator, a panic handler, and the ecall shims. Everything here runs *inside* the proof.

```rust
guest_sdk::entry!(main);                       // gives a function the `main` symbol

pub fn read_input(buf: &mut [u8]) -> usize;    // fd 0, committed
pub fn commit(bytes: &[u8]);                   // fd 1, committed
pub fn hint(buf: &mut [u8]) -> usize;          // fd 3, prover advice
pub fn log(bytes: &[u8]);                      // fd 2, verifier-ignored
pub fn exit(code: i32) -> !;
pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool;   // false on -ENOSYS
```

`docs/spec/ecall-abi.md` is the normative document for all of it, and
`docs/guest-program-manual.md` is the walkthrough for someone writing a guest:
the crate layout, the I/O rules, the build, and exporting the result as a
`ProgramImage` artifact with `tools/artifact-dump`.

## Two things about this crate that are true of nothing else
1. **It is not a workspace member.** It defines `#[panic_handler]` and
   `#[global_allocator]`, which a host build cannot link twice, and it only ever compiles
   for `riscv32imac-unknown-none-elf`. The root manifest excludes it. Its toolchain still
   comes from the repository root's `rust-toolchain.toml`.
2. **It is the one crate allowed `unsafe` and global mutable state.** A startup stub, a
   `#[global_allocator]` and a syscall shim cannot be written without both. Master rule 13
   applies: the stage names these deliverables, so the stage wins. Every `unsafe` block in
   the workspace lives in `src/lib.rs`, each with a `# Safety` note. Nothing else in the
   repository may follow suit.

## Frozen invariants
- **The ecall numbers live in `constants::ecall`, never here.** `crates/constants/tests/
  ecall_abi.rs` checks that this file references them and spells none of them itself.
- **`link.ld` and its four symbols** — `__bss_start`, `__bss_end`, `__heap_start`,
  `__stack_top` — are frozen. `_start` sits in `.text._start` so the linker places it at
  `ORIGIN(RAM)`.
- **The script must produce an image a *host* loader can map, not just one the zkVM can.**
  The zkVM makes the whole RAM window addressable by construction; `qemu-riscv32` maps only
  the `PT_LOAD`s the headers declare, page by page, at the declared permissions. So the
  script reserves `__heap_start .. __stack_top` as one writable `NOBITS` segment reaching
  the top of RAM — undeclared, the stack is unmapped and the first push faults — and
  page-aligns `.text`, `.rodata`, `.data` and `.bss`, because two segments on one page take
  the second mapping's permissions for all of it. Both rules were violated in the layout
  S10 first shipped, and `crates/loader/tests/layout.rs` now pins them.
  `docs/spec/ecall-abi.md` §7.1 is normative.
- **Cargo does not track `link.ld` as a dependency.** Editing it and rebuilding relinks
  nothing; the stale binary is what you get. `cargo clean` first, or trust nothing.
- **`.bss` is zeroed byte by byte**, because `__bss_end` carries no alignment promise, and
  it is zeroed at all because the same binary must run under QEMU, where memory does not
  start zeroed.
- **Guests link with `--no-relax`.** Relaxation rewrites instruction sequences and shifts
  every later address; S11's program identity is a function of those addresses.
- **`read_input` and `hint` may return short.** They fill the buffer or stop at the end of
  the stream. A caller that needs an exact length must check the count — silently
  proceeding on a partly-filled buffer is how a guest ends up proving something about
  zeroes.
- **A hint binds nothing.** The prover chooses fd 3's bytes. A guest that lets them change
  what it writes to fd 1, without checking them against something the public I/O digest
  does bind, has made its proof meaningless.
- **The heap never meets the stack.** The allocator refuses a block — `exit(71)`, never a
  null — that would end above `__stack_top - STACK_RESERVE` (`constants::guest_memory`,
  8 MiB) or above the live `sp`, which it reads with one `mv` from inside `alloc`.
  The ceiling used to be `__stack_top` itself, so an exhausted heap handed out blocks
  over live frames, and safe code writing into a `Vec` rewrote the caller's locals and
  return addresses. The portability suite found that by running a guest's source on the
  host and comparing the two runs. `guests/portability`'s two heap probes pin each half
  of the rule, and each half fails its probe when it is removed. `link.ld` is untouched:
  the reserve is the allocator's policy, not a linker symbol. Still unguarded: a stack
  that grows past its reserve after the heap has filled the space below it.

## `entry!` is a `macro_rules!`, not `#[entry]`
The stage prompt names an `#[entry]` attribute macro. An attribute macro requires a
`proc-macro` crate, which cannot export anything else — so it would mean a second package
for the sake of one spelling, and anti-goal 2 bans proc macros outright. The declarative
form was chosen with the repository owner. It emits a wrapper carrying `#[export_name =
"main"]`, so the annotated function keeps its own name and may itself be called `main`.
