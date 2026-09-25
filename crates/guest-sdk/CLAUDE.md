# `crates/guest-sdk`

## What this crate owns
The guest-side runtime: the crt0 stub, the `entry!` macro, the linker script, a bump
allocator, a panic handler, and the ecall shims. Everything here runs *inside* the proof.

```rust
guest_sdk::entry!(main);                       // gives a function the `main` symbol

// S25's public values and advice: ordinary loads and stores, NO ecall at all.
pub fn public_input() -> &'static [u8];        // the input window's payload
pub fn read_input(buf: &mut [u8]) -> usize;    // the same, copied, for a ported program
pub fn commit(bytes: &[u8]);                   // append to the journal
pub fn journal() -> &'static [u8];             // the journal so far
pub fn advice() -> &'static [u8];              // the advice region; nothing binds it
pub fn exit(code: i32) -> !;                   // publishes nothing

// The fd path: POSIX compatibility, and NOT provable.
pub fn read_stdin(buf: &mut [u8]) -> usize;    // fd 0
pub fn write_stdout(bytes: &[u8]);             // fd 1
pub fn hint(buf: &mut [u8]) -> usize;          // fd 3, prover advice
pub fn log(bytes: &[u8]);                      // fd 2, verifier-ignored

pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool;   // false on -ENOSYS

// S21, docs/spec/delegation.md §2. The signature is frozen; the path is not.
pub fn keccak256(input: &[u8]) -> [u8; 32];
```

`docs/spec/ecall-abi.md` is the normative document for the ecalls and
**`docs/spec/public-values.md` for the public values and the advice**;
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
- **The provable surface issues no ecall** (S25, `docs/spec/public-values.md` §7).
  `public_input`, `read_input`, `commit`, `journal` and `advice` are plain volatile loads
  and stores against the three regions of `constants::guest_memory`: the public input
  window at `PUBLIC_INPUT_ORIGIN`, the journal at `PUBLIC_OUTPUT_ORIGIN`, the advice at
  `ADVICE_ORIGIN`. Word 0 of each is the payload's byte length, and **every length this
  module reads back out of memory is clamped to its region rather than trusted** — the
  journal's is the guest's own bookkeeping and the advice region's is the prover's, and
  neither is something the SDK put there. `read_stdin`, `write_stdout`, `hint` and `log`
  are the fd path; they go through `read` (63) and `write` (64), and **neither of those is
  a provable ecall**, so a guest that takes that path is one no proof covers. The path
  exists because a guest built for a POSIX host runs under `qemu-riscv32`, and the executor
  serves the same bytes on fd 0 that it lays out in the input window, so one source can be
  compared under both executors.
- **`exit_with_public_words` is deleted.** S24 used it to leave eight words in `x24..x31`,
  where the register boundary made them public; that was the stopgap for having no journal,
  and the journal is what it stood in for. `exit` publishes **nothing**, so a guest that
  panics has still published what it committed — the journal is memory, and
  `#[panic_handler]` does not have to know about it.
- **`commit` exits `EXIT_IO_ERROR` rather than truncate**, because a caller reads `journal`
  back and must not see one it did not write. The length word is a plain store like the
  payload, so a partial `commit` is not a thing that can happen; and nothing orders the
  journal's writes — the proof binds the window's final contents, and the length word is
  what gives the bytes an order.
- **`advice()` on a run given no advice is a fatal `OutOfBounds`, not an empty slice.**
  No advice means no advice **region**: `trace::advice_region_words(&[])` is 0, so the
  executor makes nothing above `ADVICE_ORIGIN` addressable and a program that uses no
  advice pays no `ADVICE_WINDOWS` shard. The alternative would charge every program in the
  repository one whole window at the window height to say that it has none. Asking for what
  was not handed over costs the prover its trace and nobody else anything
  (`docs/spec/public-values.md` §6).
- **Under `qemu-riscv32` none of the three regions is mapped.** A host loader maps only the
  image's `PT_LOAD` segments and none of them is in the ELF, so a guest using the provable
  surface is out of the QEMU suites by construction, and a guest that must be in them uses
  `read_stdin` and `write_stdout` and is not provable. `guests/revm-block` carries both
  binaries for exactly that reason.
- **`read_input`, `read_stdin` and `hint` may return short.** They fill the buffer or stop
  at the end of what there is. A caller that needs an exact length must check the count —
  silently proceeding on a partly-filled buffer is how a guest ends up proving something
  about zeroes.
- **Neither a hint nor advice binds anything.** The prover chooses fd 3's bytes and the
  advice region's alike. A guest that lets either change what it commits, without checking
  it against something a proof *does* bind — the public input, or a hash the public input
  carries — has published a value the prover chose. The obligation is the guest's and the
  VM cannot discharge it.
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
