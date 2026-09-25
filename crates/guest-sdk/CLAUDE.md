# `crates/guest-sdk`

## What this crate owns
The guest-side runtime: the crt0 stub, the `entry!` macro, the linker script, a bump
allocator, a panic handler, and the ecall shims. Everything here runs *inside* the proof.

```rust
guest_sdk::entry!(main);                       // gives a function the `main` symbol

pub fn read_input(buf: &mut [u8]) -> usize;    // fd 0, committed
pub fn commit(bytes: &[u8]);                   // fd 1, committed
pub fn hint(buf: &mut [u8]) -> usize;          // fd 3, prover advice
pub fn advice(len: usize) -> &'static [u8];    // S25b: the ADVICE region, no ecall
pub fn public_input() -> &'static [u8];        // what fd 0 has given this run, in order
pub fn public_output() -> &'static [u8];       // what fd 1 has taken, in order
pub fn log(bytes: &[u8]);                      // fd 2, verifier-ignored
pub fn exit(code: i32) -> !;
pub fn exit_with_public_words(code: i32, words: [u32; 8]) -> !;   // S24: x24..x31, then EXIT
pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool;   // false on -ENOSYS

// S21, docs/spec/delegation.md §2. The signature is frozen; the path is not.
pub fn keccak256(input: &[u8]) -> [u8; 32];
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
- **`keccak256`'s signature is the frozen surface, and both paths are behind it** (S21).
  The shim tries the delegation ecall; on an executor without the circuit it answers
  `-ENOSYS` and an in-guest software permutation runs instead. **The bytes are identical
  either way** — that is acceptance 3, and `guests/keccak-test` checks its own six digests
  under both executors. A guest never chooses the path and cannot tell which ran.
- **The declaration record is kept by reachability, not by `#[used]`** (S21). The static in
  `.rodata.apogee.delegations` is referenced by `delegation_number()` and by nothing else,
  so the linker keeps it exactly when the shim is linked and the preprocessor can see a
  family no pc claims (`docs/spec/delegation.md` §7). Two failures are live here and each
  shipped once: `#[used]` put the record in **every** guest that links this crate —
  `guests/Cargo.toml` pins `codegen-units = 1`, so the SDK is one object file — and at
  `opt-level = 3` LLVM folded the record's number into an immediate and dropped the record,
  which `core::hint::black_box` is what prevents. `crates/program/tests/delegation.rs` holds
  every committed guest to both halves, and it must: neither is visible in this source.
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
- **`advice` binds nothing either, and it is the same rule at a different scale** (S25b,
  `docs/spec/advice.md`). A hint is a few words through fd 3; advice is a read-only region
  the guest addresses with ordinary loads, so `advice(len)` returns a slice and issues
  **no ecall** — a megabyte of advice costs a megabyte of loads, no copy into RAM, no
  `io_digest` over it and no delegation growth with its size. What does not change is what
  it is worth: a guest that does not check what it read against something public has
  proved only that *some* advice gave its output. `len` is the guest's and the prover's
  agreement, and the convention here is to carry it in a compact public header on fd 0, so
  that reading past the supplied extent is a guest bug rather than a silent zero; `advice`
  itself only asserts `len` fits `ADVICE_LENGTH`, and a load past what the prover supplied
  is a **fatal** executor error, the same class as a misaligned access.
- **A guest that reads advice cannot run under `qemu-riscv32`** (owner's decision, S25b).
  Every other rule here is about making an image a host loader can map; this one is the
  limit of that. The advice region is by definition not in the image, so it is in no
  `PT_LOAD`, so it is unmapped and the first advice load faults. Such a guest is out of
  `crates/emulator/tests/qemu_outputs.rs`, `crates/loader/tests/qemu.rs` and the
  three-way consistency suite by construction — not by an exclusion list — and the
  non-advice guests keep that coverage (`docs/spec/advice.md` §9).
- **The heap never meets the stack.** The allocator refuses a block — `exit(71)`, never a
  null — that would end above `__stack_top - STACK_RESERVE` (`constants::guest_memory`,
  8 MiB) or above the live `sp`, which it reads with one `mv` from inside `alloc`.
  The ceiling used to be `__stack_top` itself, so an exhausted heap handed out blocks
  over live frames, and safe code writing into a `Vec` rewrote the caller's locals and
  return addresses. The consistency suite found that by running a guest's source on the
  host and comparing the two runs. `guests/consistency`'s two heap probes pin each half
  of the rule, and each half fails its probe when it is removed. `link.ld` is untouched:
  the reserve is the allocator's policy, not a linker symbol. Still unguarded: a stack
  that grows past its reserve after the heap has filled the space below it.

## `entry!` is a `macro_rules!`, not `#[entry]`
The stage prompt names an `#[entry]` attribute macro. An attribute macro requires a
`proc-macro` crate, which cannot export anything else — so it would mean a second package
for the sake of one spelling, and anti-goal 2 bans proc macros outright. The declarative
form was chosen with the repository owner. It emits a wrapper carrying `#[export_name =
"main"]`, so the annotated function keeps its own name and may itself be called `main`.

## `recursion`: the delegation shims the backends ride on (S23)

`guest_sdk::recursion` is two raw delegation calls and their declaration records, and
nothing else:

```rust
#[repr(C, align(4))] pub struct Poseidon2Frame(pub [u8; 96]);
#[repr(C, align(4))] pub struct FrArithFrame(pub [u8; 100]);
pub fn poseidon2(frame: &mut Poseidon2Frame) -> bool;
pub fn fr_arith(frame: &mut FrArithFrame) -> bool;
```

- **There is no software path in this module, and there must not be.** The callers are
  `field` and `transcript`, whose own implementations *are* the fallback, so the delegated
  path and the fallback are the same function rather than two copies held equal by a test.
  That is the opposite of `keccak256`, whose sponge and permutation this crate owns because
  nothing else can.
- **The frames are word-aligned by their types.** A bare `[u8; N]` has alignment 1 and a
  stack local's address is the code generator's, so a misaligned base would be a guest that
  is correct under `qemu-riscv32` — which answers `-ENOSYS` and never dereferences the
  pointer — and fatally `Misaligned` under this VM. `guest_sdk::poseidon2_permute` keeps its
  S10 `&mut [u8; 96]` signature and copies through an aligned frame; a caller that wants the
  copies gone passes a `Poseidon2Frame` of its own, which is what `transcript` does.
- **Each declaration record has a `#[link_section]` of its own.** The linker's garbage
  collection is per section, so records sharing one section name are kept or dropped
  together — with one name, every guest that reached any shim declared every family and
  static detachment said nothing (`docs/spec/delegation.md` §7).
- **This crate does not depend on `field`, and cannot.** `field` depends on *it* for the
  guest target, and cargo refuses the cycle; that is why the shims take frames of bytes
  rather than `&[Fr]`.
