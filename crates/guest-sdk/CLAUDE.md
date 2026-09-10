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

`docs/spec/ecall-abi.md` is the normative document for all of it.

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

## `entry!` is a `macro_rules!`, not `#[entry]`
The stage prompt names an `#[entry]` attribute macro. An attribute macro requires a
`proc-macro` crate, which cannot export anything else — so it would mean a second package
for the sake of one spelling, and anti-goal 2 bans proc macros outright. The declarative
form was chosen with the repository owner. It emits a wrapper carrying `#[export_name =
"main"]`, so the annotated function keeps its own name and may itself be called `main`.
