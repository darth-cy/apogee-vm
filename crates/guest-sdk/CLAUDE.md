# `crates/guest-sdk`

## What this crate owns
The guest-side runtime: the crt0 stub, the `entry!` macro, the linker script, a bump
allocator, a panic handler, and the ecall shims. Everything here runs *inside* the proof.

**An Apogee guest is an Apogee-SDK program, not a generic Linux/POSIX RISC-V
executable.** It has no file descriptors, no streams and no I/O syscall, and there is
nothing left to build one out of. The supported interface is **public input / advice /
public output**, all three of them *memory*, reached with ordinary loads and stores.

```rust
guest_sdk::entry!(main);                       // gives a function the `main` symbol

// S-IO's public values and advice: ordinary loads and stores, NO ecall at all.
pub fn public_input() -> &'static [u8];        // the input window's payload
pub fn read_input(buf: &mut [u8]) -> usize;    // the same, copied, for a ported program
pub fn commit(bytes: &[u8]);                   // append to the journal
pub fn journal() -> &'static [u8];             // the journal so far
pub fn advice() -> &'static [u8];              // the advice region; nothing binds it
pub fn exit(code: i32) -> !;                   // publishes nothing

pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool;   // false on -ENOSYS

// S21, docs/spec/delegation.md §2. The signature is frozen; the path is not.
pub fn keccak256(input: &[u8]) -> [u8; 32];
```

That is the whole of it. `read_stdin`, `write_stdout`, `hint` and `log` are **deleted**,
and with them the `Diagnostics` `fmt::Write` sink the panic handler used to print
through. One raw shim survives, `ecall1`: every ecall a guest may now issue takes exactly
one argument — `EXIT` a status, each delegation a frame base — so the three-argument
`ecall3` the fd path needed went with it, and an unused `in(...)` register is still a
constraint on the register allocator.

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
  The shim tries the delegation ecall; an executor without the circuit answers `-ENOSYS`
  and an in-guest software permutation runs instead. **The bytes are identical either
  way**, and a guest never chooses the path and cannot tell which ran. The fallback is the
  ABI's contract (`docs/spec/delegation.md` §2), not a path any executor in this repository
  takes: this VM implements every delegation, and the second executor that used to exercise
  the branch is gone. What holds the two implementations equal is
  `crates/emulator/tests/keccak.rs`, which checks the emulator's permutation against
  `tiny-keccak` on all 1,600 single-bit states, and `guests/keccak-test`, which checks its
  own six digests in-guest.
- **A permutation is 24 delegated calls since S26d** (`docs/spec/delegation.md` §6), and the
  frame is a `#[repr(C, align(4))]` struct whose first field is a `u32` **round**, so the
  round is frame word 0 and the 200-byte state follows. `permute` writes the round, calls,
  and repeats — the frame is transformed in place, so nothing is copied between calls and the
  chain a proof reads is the frame's own RAM history. **Only the first call may answer
  `-ENOSYS`**: one answering it halfway through a permutation is a broken executor and
  `exit(EXIT_PRECOMPILE_ERROR)` is the answer, because skipping a round silently would be
  worse. The **software** fallback is still a whole permutation, and it runs from the
  untouched state, `-ENOSYS` meaning the executor did nothing.
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
- **The script declares every writable byte and page-aligns every segment, because that
  is what a correct image looks like.** The script reserves `__heap_start .. __stack_top`
  as one writable `NOBITS` segment reaching the top of RAM, and page-aligns `.text`,
  `.rodata`, `.data` and `.bss`. An image whose stack is not in any `PT_LOAD` is an image
  whose program headers are a lie about its own memory, and two segments sharing a page
  cannot both keep their permissions — neither fact depends on who reads the headers. The
  zkVM does not read them that way: it makes the whole RAM window addressable by
  construction and is indifferent to both rules, which is exactly why they need a test of
  their own rather than an executor to notice. Both were violated in the layout S10 first
  shipped, and `crates/loader/tests/layout.rs` pins them — it parses the headers itself and
  needs no compiler and no emulator. `docs/spec/ecall-abi.md` §7.1 is normative.
- **Cargo does not track `link.ld` as a dependency.** Editing it and rebuilding relinks
  nothing; the stale binary is what you get. `cargo clean` first, or trust nothing.
- **`.bss` is zeroed byte by byte**, because `__bss_end` carries no alignment promise, and
  it is zeroed at all because `.bss` being zero is a guarantee the Rust above it relies on.
  This VM's memory does start zeroed, so crt0's loop is redundant *on this executor* — and
  that is the wrong place to put the guarantee. crt0 is the one thing that can make it true
  of the **image** rather than of whatever runs it, and a `static mut` that is zero only by
  the executor's grace is a guarantee nobody wrote down.
- **Guests link with `--no-relax`.** Relaxation rewrites instruction sequences and shifts
  every later address; S11's program identity is a function of those addresses.
- **The I/O surface issues no ecall, and there is no other surface** (S-IO,
  `docs/spec/public-values.md` §7). `public_input`, `read_input`, `commit`, `journal` and
  `advice` are plain volatile loads and stores against the three regions of
  `constants::guest_memory`: the public input window at `PUBLIC_INPUT_ORIGIN`, the journal
  at `PUBLIC_OUTPUT_ORIGIN`, the advice at `ADVICE_ORIGIN`. Word 0 of each is the payload's
  byte length, and **every length this module reads back out of memory is clamped to its
  region rather than trusted** — the journal's is the guest's own bookkeeping and the
  advice region's is the prover's, and neither is something the SDK put there. The fd path
  that used to sit beside this one is gone: `read` (63) and `write` (64) were never
  provable ecalls, so every guest that took it was a guest no proof covered, and a second
  surface that quietly costs a program its proof is worse than no second surface. Every
  guest in `guests/` that reads anything reads it from the public input window or from
  advice, and every one that publishes anything publishes it with `commit`; the
  self-checking family guests — `addsub`, `alu`, `shards` — read nothing and commit
  nothing, and their exit status is the whole of what they say.
- **`exit_with_public_words` is deleted.** S24 used it to leave eight words in `x24..x31`,
  where the register boundary made them public; that was the stopgap for having no journal,
  and the journal is what it stood in for. `exit` publishes **nothing**, so a guest that
  panics has still published what it committed — the journal is memory, and
  `#[panic_handler]` does not have to know about it.
- **A panic is silent, and that is what makes a panicking guest provable.** The handler is
  a bare `exit(EXIT_PANIC)` and writes nothing anywhere. It used to format the
  `PanicInfo` into the `Diagnostics` sink and out on fd 2, through `write` — which is not a
  provable ecall — so *every* panicking execution was one no proof could cover, whatever the
  guest had done up to that point. Now the only bytes leaving an execution are
  the journal, which a proof binds, and the exit status. Routing the message into the
  journal instead would have been worse than losing it: it would break `exit` publishing
  nothing, and a guest's last act before dying would rewrite what it had published
  (`docs/spec/public-values.md` §7).
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
- **`read_input` may return short.** It fills the buffer or stops at the end of what there
  is. A caller that needs an exact length must check the count — silently proceeding on a
  partly-filled buffer is how a guest ends up proving something about zeroes, and
  `guests/fib` asserts the count for exactly that reason.
- **Advice binds nothing.** The prover chooses those bytes and may choose them differently
  on every run. A guest that lets them change what it commits, without checking them
  against something a proof *does* bind — the public input, or a hash the public input
  carries — has published a value the prover chose. The obligation is the guest's and the
  VM cannot discharge it.
- **The heap never meets the stack.** The allocator refuses a block — `exit(71)`, never a
  null — that would end above `__stack_top - STACK_RESERVE` (`constants::guest_memory`,
  8 MiB) or above the live `sp`, which it reads with one `mv` from inside `alloc`.
  The ceiling used to be `__stack_top` itself, so an exhausted heap handed out blocks
  over live frames, and safe code writing into a `Vec` rewrote the caller's locals and
  return addresses. What found that at S12 was the three-way consistency suite, running
  one guest's source on the host and on RV32 and comparing; **that suite and the two heap
  probes that pinned each half of the rule went with `guests/consistency`**, so the rule is
  now asserted here and exercised nowhere — `guests/heap` churns the allocator but never
  reaches the ceiling. `link.ld` is untouched: the reserve is the allocator's policy, not a
  linker symbol. Still unguarded, and always was: a stack that grows past its reserve after
  the heap has filled the space below it.

## `entry!` is a `macro_rules!`, not `#[entry]`
The stage prompt names an `#[entry]` attribute macro. An attribute macro requires a
`proc-macro` crate, which cannot export anything else — so it would mean a second package
for the sake of one spelling, and anti-goal 2 bans proc macros outright. The declarative
form was chosen with the repository owner. It emits a wrapper carrying `#[export_name =
"main"]`, so the annotated function keeps its own name and may itself be called `main`.

## `recursion`: the delegation shims the backends ride on (S23, S26)

`guest_sdk::recursion` is three raw delegation calls and their declaration records, and
nothing else:

```rust
#[repr(C, align(4))] pub struct Poseidon2Frame(pub [u8; 96]);
#[repr(C, align(4))] pub struct FrArithFrame(pub [u8; 100]);
#[repr(C, align(4))] pub struct ModMulFrame(pub [u32; 25]);          // S26, S26b
pub fn poseidon2(frame: &mut Poseidon2Frame) -> bool;
pub fn fr_arith(frame: &mut FrArithFrame) -> bool;
pub fn mod_mul(frame: &mut ModMulFrame) -> bool;                    // out = a * b mod m
impl ModMulFrame {
    pub fn of(modulus: u32, a: &[u32; 8], b: &[u32; 8]) -> ModMulFrame;
    pub fn result(&self) -> [u32; 8];
}
// The selector codes and the two Montgomery corrections, re-exported from
// `constants::mod_mul` so a vendored crate names a constant and not a number.
pub use constants::mod_mul::{BN254_P, BN254_P_R_INV, BN254_R, BN254_R_R_INV,
                             MODULI, SECP256K1_N, SECP256K1_P};
```

- **There is no software path in this module, and there must not be.** The callers are
  `field` and `transcript`, whose own implementations *are* the fallback, so the delegated
  path and the fallback are the same function rather than two copies held equal by a test.
  That is the opposite of `keccak256`, whose sponge and permutation this crate owns because
  nothing else can. S26's caller is a third kind: `guests/vendor/k256`, whose own
  `mul_inner` is the fallback for the same reason.
- **`ModMulFrame` is limbs and not bytes, and it has no empty constructor.** Every caller
  already holds its values as 32-bit limbs, so a byte frame would cost a pack and an unpack
  per call — a fifth of what the delegation saves on a 256-bit multiply — and the `u32`
  element type is also what gives the type its alignment for free. `of` writes the
  selector, the two operands and eight zero result words in **one pass**: an all-zero array
  followed by three `copy_from_slice`s was a `memset` plus three `memcpy`s, and on S26's
  pinned mini-block, at 6,705 invocations, that was 1.4 million guest cycles — a quarter of
  what the delegation saves. Five `const` assertions pin the word layout its array literal
  spells out, so a renumbering fails the build rather than transposing the operands; **they
  are re-pointed and never deleted**, being the only thing holding this literal equal to
  the executor's indexed reads.
- **The caller must reduce, and the shim cannot check it** (S26b). The circuit enforces
  `a < m` and `b < m` for the selected modulus, so a frame carrying anything else is a
  fatal guest error. That is a real obligation on a caller holding a lazily reduced
  representation — `guests/vendor/k256`'s field elements are the worked example — and it
  is why the four codes are re-exported here rather than left for a caller to spell.
- **The frames are word-aligned by their types.** A bare `[u8; N]` has alignment 1 and a
  stack local's address is the code generator's to choose — LLVM puts align-1 stack objects
  at odd offsets whenever the frame packs that way, at every optimisation level — so an
  unaligned buffer would be a guest killed by `EmuError::Misaligned` for where codegen
  happened to put a local. The alignment is therefore the type's promise and not a
  caller's. `guest_sdk::poseidon2_permute` keeps its
  S10 `&mut [u8; 96]` signature and copies through an aligned frame; a caller that wants the
  copies gone passes a `Poseidon2Frame` of its own, which is what `transcript` does.
- **Each declaration record has a `#[link_section]` of its own.** The linker's garbage
  collection is per section, so records sharing one section name are kept or dropped
  together — with one name, every guest that reached any shim declared every family and
  static detachment said nothing (`docs/spec/delegation.md` §7).
- **This crate does not depend on `field`, and cannot.** `field` depends on *it* for the
  guest target, and cargo refuses the cycle; that is why the shims take frames of bytes
  rather than `&[Fr]`.
