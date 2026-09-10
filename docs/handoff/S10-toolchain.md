# S10 — Guest toolchain + SDK + loader

Branch `s10-toolchain`. Status: complete, all 10 acceptance items met.

The normative document written this stage is **`docs/spec/ecall-abi.md`**. It is the ABI:
the syscall table, the two non-Linux ranges, the file-descriptor conventions, the public
I/O digest recipe and the memory map. `crates/constants/tests/ecall_abi.rs` holds it to
`constants::ecall` in both directions on every build. This note is the frozen API, the
artifacts and the deviations.

## Frozen public API, as built

```rust
// crates/loader/src/lib.rs   (std)
pub fn load_elf(bytes: &[u8]) -> Result<ProgramImage, LoaderError>;

pub struct ProgramImage {
    pub entry: u32,               // always the address of an Instruction slot
    pub segments: Vec<Segment>,   // PT_LOAD, sorted by vaddr, pairwise disjoint
    pub slot_base: u32,           // even; the pc of slots[0]; the lowest loaded address
    pub slots: Vec<Slot>,         // one per halfword of the whole loaded image
}
pub struct Segment { pub vaddr: u32, pub mem_len: u32, pub bytes: Vec<u8> }

pub enum Slot {
    Instruction { word: u32, compressed: bool },
    MidInstruction,
    NonInstruction,
}
impl ProgramImage { pub fn slot_at(&self, pc: u32) -> Option<Slot>; }

pub enum LoaderError {
    NotAnElf { reason: &'static str },
    Truncated { what: &'static str, need: usize, have: usize },
    RelocatableElf,
    DynamicElf { reason: &'static str },
    NotRiscV { machine: u16 },
    UnsupportedElfType { e_type: u16 },
    BadSegment { vaddr: u32, reason: &'static str },
    NoExecutableSegment,
    EntryNotAnInstruction { entry: u32 },
    RvcIllegal { pc: u32, encoding: u16, reason: &'static str },
    InstructionTooLong { pc: u32, encoding: u16 },
    TextTruncated { pc: u32 },
}
// Derives: ProgramImage/Segment (Clone, Debug, PartialEq, Eq), Slot and LoaderError
//          additionally Copy. Manual serde::Serialize/Deserialize on the first three.
```

```rust
// crates/guest-sdk/src/lib.rs   (#![no_std], guest-only, NOT a workspace member)
#[macro_export] macro_rules! entry { ($f:ident) => { ... } }   // gives $f the `main` symbol

pub fn read_input(buf: &mut [u8]) -> usize;    // fd 0, committed; may return short
pub fn commit(bytes: &[u8]);                   // fd 1, committed; writes all
pub fn hint(buf: &mut [u8]) -> usize;          // fd 3, prover advice; may return short
pub fn log(bytes: &[u8]);                      // fd 2, verifier-ignored
pub fn exit(code: i32) -> !;
pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool;   // false on -ENOSYS
```

```rust
// crates/transcript/src/lib.rs   (one addition)
pub fn io_digest(public_input: &[u8], public_output: &[u8]) -> Fr;
```

```rust
// crates/constants/src/lib.rs   (additions; still zero logic in src/, #![no_std])
pub mod guest_memory {
    pub const RAM_ORIGIN: u32 = 0x0001_0000;
    pub const RAM_LENGTH: u32 = 0x0FFF_0000;
}
pub mod ecall {
    pub const READ: u32 = 63;
    pub const WRITE: u32 = 64;
    pub const EXIT: u32 = 93;

    pub const ZKVM_IO_FIRST: u32 = 0x0400;      // reserved, empty at S10
    pub const ZKVM_IO_LAST: u32 = 0x04FF;
    pub const PRECOMPILE_FIRST: u32 = 0x0500;
    pub const PRECOMPILE_LAST: u32 = 0x05FF;
    pub const PRECOMPILE_POSEIDON2: u32 = 0x0500;

    pub const FD_PUBLIC_INPUT: u32 = 0;
    pub const FD_PUBLIC_OUTPUT: u32 = 1;
    pub const FD_STDERR: u32 = 2;
    pub const FD_HINT: u32 = 3;

    pub const ENOSYS: u32 = 38;
}
pub mod transcript_tags {
    pub const PUBLIC_INPUT_STREAM: u64 = 20;    // bytes
    pub const PUBLIC_OUTPUT_STREAM: u64 = 21;   // bytes
}
```

The frozen linker symbols are `__bss_start`, `__bss_end`, `__heap_start` and
`__stack_top`, in `crates/guest-sdk/link.ld`. The pinned toolchain is **1.96.1** with
`rustfmt`, `clippy` and `llvm-tools`, and the pinned linker flags are
`-C link-arg=-T../crates/guest-sdk/link.ld` and `-C link-arg=--no-relax`.

## What this freezes for every later stage

1. **`ProgramImage`, fields and serialization.** `postcard` over the four fields in
   declaration order — sorted vectors, never a hash map. `Deserialize` rejects anything
   `Serialize` could not have produced: an unknown slot kind, a word on a non-instruction
   slot, an odd `slot_base`, a segment with more file bytes than memory.
2. **Addresses are preserved, never compacted.** Expansion changes representation, not
   layout. `slots` is pc/2-indexed and `compressed` *is* the instruction's length, which
   is what says whether the next pc is `pc + 2` or `pc + 4`.
3. **The slot vector runs from the lowest loaded address to the top of the highest
   executable segment**, and `slot_at` answers `None` above that. Nothing up there could
   be an instruction, and `.bss` — which this memory map always puts above the code —
   would otherwise cost four bytes of table per byte of zeroes.
4. **The guest memory map**, `constants::guest_memory`: RAM is
   `[0x0001_0000, 0x1000_0000)`. Every `PT_LOAD` must lie inside it. The same two numbers
   appear in `crates/guest-sdk/link.ld` and in `docs/spec/ecall-abi.md` §7, and a test
   checks all three against each other.
5. **The ecall ABI**, per `docs/spec/ecall-abi.md`: numbers, ranges and file descriptors,
   append-only forever.
6. **The public I/O digest.** `io_digest` is two typed byte messages —
   `PUBLIC_INPUT_STREAM` then `PUBLIC_OUTPUT_STREAM` — and one raw `sample`, in a sponge
   of its own. That is exactly must-be-exact 12's recipe: tag, byte length, 31-byte
   little-endian limbs with the final one zero-extended, twice, then lane 1 after the
   final permutation. Later stages recompute it; nobody redefines it.
7. **The precompile range is `0x0500..=0x05FF`** and every shim lands inside it.
   `PRECOMPILE_POSEIDON2 = 0x0500` is the one number assigned; it has a documented
   convention (`a0` = pointer to three canonical little-endian `Fr`) and no circuit, so
   every executor answers `-ENOSYS` today.
8. **The guest template config** — `guests/.cargo/config.toml` (target, runner, linker
   flags), the root `rust-toolchain.toml`, and `guests/Cargo.toml`'s pinned dev profile.
   Guests build from their own directory.

## Artifacts

| Path | What |
| --- | --- |
| `crates/loader/tests/vectors/{fib,echo,rvc-dense,amm,orderbook,vault}.elf` | the committed guest ELFs |
| `crates/loader/tests/vectors/{fib,rvc-dense,amm}.objdump.txt` | `llvm-objdump -d -M no-aliases`, one line per instruction |
| `crates/loader/tests/vectors/rvc-dense.nm.txt` | the text symbols |
| `crates/loader/tests/vectors/*.elf` (11 more) | hand-built ELFs, one per refusal, plus `minimal.elf` |
| `crates/loader/tests/vectors/synthetic_elfs.txt` | that index, each with its digest |
| `crates/loader/tests/vectors/fib_io.txt` | fib's fd 0 and fd 1 byte streams |
| `crates/transcript/tests/vectors/io_digest.txt` | 14 public-I/O-digest cases |
| `docs/spec/ecall-abi.md` | the ABI |
| `tools/kat-gen/src/loader.rs` | the derived listings, the synthetic ELFs, the fib record |
| `tools/kat-gen/src/guests.rs` | the guest ELF rebuild, opt-in |
| `tools/artifact-dump/` | the exporter: a guest ELF out as the frozen wire form, plus a report |
| `docs/guest-program-manual.md` | the guest author's walkthrough, empty crate to artifact |
| `tools/artifact-dump/tests/manual.rs` | that walkthrough, run over every guest in the workspace |
| `guests/{amm,orderbook,vault}/` | the three DeFi guests |

The vector directory is 1.4 MB, most of it the six guest ELFs and the three disassembly
listings. `echo.elf`, `orderbook.elf` and `vault.elf` deliberately have no committed
listing: theirs would be 300 kB to 830 kB of the same kind of evidence `fib` and `amm`
already give. `amm` earns one because its text is long stretches of open-coded 128-bit
arithmetic — LLVM legalises `i128` into 32-bit limbs on this target and calls no builtin
for it — and because it carries the single `c.unimp` halfword the differential's carve-out
exists for.

Every file is pinned by SHA-256 in the test that reads it —
`crates/loader/tests/common/mod.rs` for the loader's, `crates/transcript/tests/io_digest.rs`
for the digest's. The digests are deliberately **not** repeated here: they are a function
of the generator's content, so a copy in a handoff goes stale the first time it changes.

Refresh, in this order:

```
cargo run -p kat-gen -- guests    # rebuild the ELFs; one machine, deliberately
cargo run -p kat-gen -- loader    # everything derived from them
cargo run --manifest-path tools/transcript-ref/Cargo.toml   # the io_digest vectors
```

then move the printed digests into the tests.

## The two loader oracles

The loader is soundness-critical — a wrong expansion is a valid proof of a different
program — so it has two independent differentials rather than one.

**Boundaries: `llvm-objdump`.** `tests/differential.rs` checks that the loader's
instruction set is the disassembler's, at every address, in both directions: every
address objdump lists is an `Instruction` slot of the same length whose original bytes
match, and every `Instruction` slot appears in the listing. The negative control,
`a_shifted_listing_is_rejected`, shows the check distinguishes a synchronised sweep from
one shifted by a halfword.

**Expansions: LLVM's own 32-bit encoder.** `guests/rvc-dense` holds the same 44
instructions twice — once in compressed mnemonics under `.option rvc`, once in the base
mnemonics they abbreviate under `.option norvc`. Every displacement is written `.+N`, so
the two regions encode identical immediates despite being different sizes, and neither
region is executed. The test expands the first and compares it to the second, instruction
for instruction. **Neither side of that comparison is a second reading of the RVC table by
its author**, which is what makes it an oracle rather than a restatement. It also asserts
that every instruction in the compressed region really is 16 bits — an instruction the
assembler quietly declined to compress would weaken the test without saying so.

The immediates in that fixture include each field's extremes (`c.addi4spn` at 1020,
`c.lw`/`c.sw` at 124, `c.lwsp`/`c.swsp` at 252, `c.j`/`c.jal` at ±2048, `c.beqz` at ±254,
shifts at 31, `c.lui` at both ends), because an off-by-one in a shift-and-mask shows up at
the top of a range and nowhere else.

## Verification performed

400 workspace tests, green in debug and release, plus 8 `#[ignore]`d (341 from S09,
unchanged). Eleven of them are `tools/artifact-dump`'s — seven integration tests over the
committed fixtures, three that run `docs/guest-program-manual.md`'s own procedure over
every guest in the workspace, and the doctest that compiles the "read an artifact back"
snippet. `fmt` and `clippy -D warnings` are clean across **all four** workspaces — the
root one, the oracle, `crates/guest-sdk` and `guests/` — with no `#[allow]` added anywhere.

**Acceptances 3 and 8 are not verified on this machine and never were**; see "The defect
CI found" below. The seven `tests/qemu.rs` cases — four from S10 as first written, three
added with the new guests — are `#[ignore]`d, because user-mode QEMU is Linux-only and no
macOS build of it exists.

- **Acceptance 1** — `cd guests/fib && cargo build --target riscv32imac-unknown-none-elf`,
  no other flags, on stock stable. A CI step runs exactly that.
- **Acceptance 2** — `tests/reproducible.rs::two_clean_builds_agree`: each of the six
  guests built twice into two fresh target directories, SHA-256 compared. It is a test
  rather than a CI script so it runs wherever `cargo test` does. See the deviation below
  on what it does *not* claim. `tools/artifact-dump/tests/manual.rs` makes the same
  comparison one step further downstream, over the exported artifacts.
- **Acceptance 3** (`#[ignore]`d; Linux only) — `tests/qemu.rs::fib_computes_the_committed_value`: fib under
  `qemu-riscv32`, fd 0 from the committed record, fd 1 checked against the host-computed
  value. Three more cases joined it for the new guests, and one of them is worth naming:
  `orderbook_ignores_advice_it_cannot_verify` runs the same batch three times — with a
  correct fd 3 permutation, with a transposed one, and with an empty fd 3 — and requires
  fd 1 to be identical in all three. That is the "a hint binds nothing" rule as an
  executable statement, and it is the only form of it this repository can make before a
  prover exists. **None of the four has been run**, here or anywhere: they need a Linux
  host, and this machine is not one.
- **Acceptance 4** — `tests/differential.rs::objdump_agrees_instruction_for_instruction`
  over `fib` (2,157 real compiler instructions) and `rvc-dense`, plus
  `the_fixture_covers_the_required_compressed_forms`, which asserts the stage's required
  list — compressed loads and stores, `c.jal`, `c.beqz`/`c.bnez`, `c.lwsp`/`c.swsp` — is
  present. That coverage check reads the *expanded* words rather than re-decoding the
  compressed ones, so no second decoder appears in the test.
- **Acceptance 5** — `every_symbol_address_is_an_instruction`: every `nm` text symbol is
  the address of an `Instruction` slot. Plus `addresses_are_never_compacted`, which states
  must-be-exact 5 directly: the compressed region is 2 bytes per instruction and the
  uncompressed one 4, and consecutive compressed instructions are exactly 2 apart.
- **Acceptance 6** — `tests/negative.rs`: (a) `zero_halfword.elf` and
  `reserved_addi4spn.elf`, both refused with the pc and the encoding named; (b)
  `zcmp.elf`, refused with a reason that names the Zcmp encoding space; (c) `et_dyn.elf`
  and `pt_dynamic.elf`, refused as dynamic by two different code paths — the test asserts
  the two errors differ, so neither is standing in for the other.
- **Acceptance 7** — `tests/image.rs::loading_twice_serializes_identically` for all three
  ELFs, plus a postcard round trip and re-serialization check.
- **Acceptance 8** (`#[ignore]`d; Linux only) — `tests/qemu.rs::echo_exercises_every_shim`: 100 bytes through fd 0 to
  fd 1 byte for byte (crossing the guest's 64-byte buffer, so both the full-read and
  short-read paths run), a hint arriving on fd 3 and staying off fd 1, and the precompile
  number answering `-ENOSYS` and falling back. The fallback is checked to have produced
  the **actual S02 permutation** of `[1, 2, 3]`, not a marker — so that test also proves
  `crates/transcript` compiles and runs correctly on RV32.
- **Acceptance 9** — `crates/constants/tests/ecall_abi.rs`: the document's tables against
  `constants::ecall` in both directions, every implemented number carrying a
  nondeterminism class, the ranges above Linux and disjoint (as `const` assertions, so a
  violation stops the build), and a check that `guest-sdk` references the constants and
  spells none of the numbers itself.
- **Acceptance 10** — `crates/transcript/tests/io_digest.rs`: 14 committed cases including
  empty/empty, input-only, output-only and multi-block; the three sensitivity properties
  asserted *directly* rather than by example — swapping over four stream pairs, appending
  a zero byte at eight lengths on both streams, and flipping **every** bit of a 40-byte
  input. The fib record's own clause is `crates/loader/tests/io_digest.rs`, which digests
  the recorded fd 0/1 bytes twice, and then shows the digest actually depends on both of
  them — without that second test the first would pass on a function that ignored its
  arguments.
- **Must-be-exact 4** — `src/rvc.rs`'s `every_halfword_either_expands_or_is_named` sweeps
  the whole 16-bit space: nothing panics, every refusal carries a reason, every acceptance
  is a 32-bit encoding whose opcode is one an RVC expansion can produce, and the accepted
  count is checked **per quadrant against a hand derivation** rather than pinned to
  whatever the code happened to produce. The three sums — 6136, 15584 and 7103 — were
  derived on paper from the spec's tables before the test was run, and matched.
- **Robustness, and one hole found by looking for it** — the first version of the slot
  vector spanned the whole loaded image and trusted `p_memsz`, so a 100-byte hostile ELF
  declaring a 4 GB segment would have sized a multi-gigabyte allocation. Two changes
  closed it: the loader now enforces the frozen RAM window on every `PT_LOAD`, and the
  slot vector stops at the top of the highest executable segment rather than the top of
  the image. `segments_must_lie_inside_the_guest_ram_window` is the control, over three
  hostile `p_memsz` values and a segment below the window.
- **Robustness** — `a_corrupted_header_never_panics` flips every bit of every byte of
  `minimal.elf` (about 700 mutations) and asserts only that nothing panics: a malformed
  ELF is untrusted input. `truncated_files_are_refused_rather_than_read_past` cuts the same
  file at each place a length is declared.
- **Negative controls**, since master rule 8 wants one per checker: the shifted-listing
  control for the differential; the malformed-wire-form controls for the deserializer,
  which are built from primitives and **checked against a positive control first** — the
  hand-built good form is asserted to deserialize to exactly the image `load_elf` produces,
  so the three refusals are evidence about the deserializer and not about the test; the
  corrupted-vector-file control for the digest fixture; and a fixture per `LoaderError`
  variant.

`cargo run -p kat-gen && cargo run --manifest-path tools/transcript-ref/Cargo.toml`
followed by `git diff --exit-code` over every vector directory is clean: the regeneration
is byte-identical.

## Adversarial review

A five-dimension review was run over the finished branch — the RVC table against the
spec, the ELF parser against hostile input, the SDK's `unsafe`, the frozen interfaces,
and an acceptance-coverage audit. Its verification stage crashed on a scripting error, so
its findings were triaged by hand rather than by vote. Nine were real and are fixed here;
the rest were stale, duplicated, or style points the anti-goals reject.

The three that mattered:

1. **`read_fd` and `write_fd` trusted the executor's byte count.** `filled += n as usize`
   with no bound meant one over-large return could push the count past `buf.len()`, and
   every caller then slices `buf[..n]`. The executor **is** the prover, and
   `docs/spec/ecall-abi.md` §4 says so in as many words for fd 3, so this was reachable
   from adversarial input: `guests/echo` would have panicked on a 16-byte buffer.
   `write_fd`'s version was quieter and worse — `commit` returning normally having
   delivered fewer bytes to the public journal than the guest believed. Both counts are
   now checked against the space offered and take the same exit a negative return does.
2. **The precompile shim collapsed every failure into "fall back".** `ret == 0` meant a
   half-implemented precompile answering `-EFAULT` was indistinguishable from a VM that
   does not have the circuit yet. It now returns `false` only for exactly `-ENOSYS` and
   exits nonzero on anything else, which is also what finally gives `ecall::ENOSYS` a
   consumer — it had none, and nothing held the document's `38` to it. It now has a table
   row, so the document-versus-constants check covers it in both directions.
3. **The bump allocator was linked into no guest.** No guest allocated, so it was
   dead-stripped from all three binaries and the largest `unsafe` surface in the
   repository — the `GlobalAlloc` impl, the `static mut` read-modify-write, the two extern
   statics — ran nowhere, while a manifest comment claimed the opposite. `guests/echo` now
   heap-allocates its buffers at two alignments, so the allocator is linked and exercised
   under QEMU. Its `.bss` is no longer empty either, which means crt0's zeroing loop now
   does something as well.

The rest: `ProgramImage::deserialize` accepted wire forms `load_elf` could never produce
(unsorted or overlapping segments, a `slot_base` that is not the lowest address, an entry
off an instruction, a 32-bit instruction with no second halfword) — a `validate` function
now re-checks every invariant the type's doc comments declare, with seven more
negative-control cases; `crates/guest-sdk` and `guests/` were outside every `fmt` and
`clippy` gate and both were failing them, so CI now runs all four workspaces; the ABI
document never wrote down the register-preservation rule the shims' clobber-free inline
asm depends on, which is now §1's second paragraph; the ABI checker had no negative
control, and now has one that shows a wrong number, a deleted row and a wrong
classification each move the parse; `constants` dev-depended on itself for no effect; and
two documentation tables had gone stale.

Separately, and before the review, the same adversarial question found the one that would
have hurt most: an untrusted ELF could size the slot vector through `p_memsz`. That is the
RAM-window check recorded below.

## The defect CI found, and what now catches it locally

The four `tests/qemu.rs` cases failed on `ubuntu-latest` — the first machine ever to run
them, since QEMU user-mode does not exist on macOS. They were not failing for a platform
reason. **The guest images were genuinely broken**, in a way every other suite in this
stage was structurally unable to see, and QEMU earned its keep on its first outing.

`crates/loader` reads an ELF the way the zkVM will: `p_vaddr` and `p_memsz` into a flat
RAM window where every address exists by construction. A *host* program loader maps only
the `PT_LOAD`s the headers declare, page by page, at the declared permissions. The linker
script satisfied the first reader and not the second, twice over:

1. **The stack and the heap were never declared.** `__stack_top` was `ORIGIN + LENGTH`
   and `__heap_start` sat just above `.bss`, but the highest address any `PT_LOAD` covered
   was the end of `.rodata` — `0x1240C` in fib, against a stack at `0x10000000`. Under
   QEMU both are unmapped: crt0 set `sp`, called `main`, and `main`'s prologue store
   killed the process on a signal before a single guest instruction ran. fib, the panic
   case and rvc-dense all died this way, with exit status `None` and an empty fd 2 — which
   is why the failure looked so much like an environment problem.
2. **Zero fill shared a page with read-only data.** echo's four-byte `.bss` began at
   `0x1B0A8`, on the same page as the tail of `.rodata`. `qemu-riscv32` refused the image
   outright: `PT_LOAD with bss overlapping non-writable page`. A third instance of the
   same rule was latent and would have bitten later: `.text` and `.rodata` shared a page
   too, so the second mapping would have stripped execute from the tail of the code.

Both are fixed in `link.ld` — one writable `NOBITS` segment covering `__heap_start` to the
top of RAM, and `ALIGN(4096)` on every output section — and `docs/spec/ecall-abi.md` §7.1
makes the two rules normative rather than incidental. The cost is three pages of address
space. The committed ELFs were rebuilt and every derived fixture regenerated, so all of
the addresses in `fib.objdump.txt` and `rvc-dense.objdump.txt` moved.

**`crates/loader/tests/layout.rs` is the new coverage, and it needs no emulator.** It
reads the program headers directly — not through `load_elf`, which drops the flags and
offsets these rules are about — and asserts that every segment is page-aligned with
`p_offset ≡ p_vaddr`, that no two segments share a page, that zero fill only ever lands on
a writable mapping, that `__heap_start` and `__stack_top - 1` are mapped writable, and
that the entry point is mapped executable. `the_layout_that_failed_in_ci_is_rejected`
transcribes the two failing sets of program headers and asserts each is caught, with the
shipping layout as the positive control. Run against the old fixtures the suite reproduces
the CI failure exactly, on macOS, in milliseconds.

Two process lessons worth carrying forward:

- **`cargo` does not track the linker script as a dependency.** Editing `link.ld` and
  rebuilding relinks nothing and hands back the stale binary. Every measurement of a
  script change has to start from `cargo clean`.
- **A test that skips is not a test that passes.** `tests/qemu.rs` used to print a note
  and return when QEMU was absent, so a full local run reported four passes for four
  things that had not happened, and the stage shipped believing them covered. They are
  now `#[ignore]`d, and `qemu()` panics rather than returning when the emulator is
  missing: running them is an explicit request, and a request that cannot be honoured
  should say so.

**What is still unverified.** Execution itself — that fib computes the value it commits,
that the shims move bytes over the right descriptors, that the panic handler reports and
exits nonzero. `layout.rs` proves the image is loadable, not that it is correct. Nothing
but an executor can close that, and until S12 builds one it takes a Linux host:
`cargo test -p loader --test qemu -- --ignored`. `.github/workflows/ci.yml` carries the
two commented steps that would gate on it; enabling them is a one-line decision once a
Linux run confirms green.

## Exporting a `ProgramImage`, and the manual for it

The stage froze `ProgramImage` and its wire form but shipped no way to *get* one out of a
guest, so a guest author had a build command and a type and nothing between them.
`tools/artifact-dump` is that step — the master layout's `tools/ artifact dump` entry —
and `docs/guest-program-manual.md` is the walkthrough from an empty crate to the file.

```
cargo run -p artifact-dump -- <guest.elf> [--out <dir>]
```

It writes `<name>.img` and `<name>.img.txt`. Four decisions in it are worth recording.

**The artifact has no container.** The `.img` is `postcard` over `entry`, `segments`,
`slot_base`, `slots` and stops — no magic, no version word, no length prefix. A header
would have made the file a *second* format to freeze, one `crates/loader`'s tests do not
exercise and every consumer would have to strip. Reading one is
`postcard::from_bytes::<ProgramImage>(&fs::read(path)?)`, which is the point of having
frozen the encoding at all. The doc comment carrying that line is a doctest, so the
snippet in the manual is compiled rather than asserted.

**The report is rendered from the artifact, not from the loaded image.** `dump`
serializes, reads back through the reader that re-checks every invariant, compares the
result to what `load_elf` produced, and renders from *that*. On disagreement it writes
nothing. So the printed page and the exported file cannot describe different things —
which is the whole reason to print a page beside a binary.

**No mnemonics.** An RV32IMAC instruction model is `crates/isa`'s, in a later stage; a
decoder written here would be a second one to keep correct, and it would be the kind of
second reading `tests/differential.rs` exists to avoid. The listing carries the address,
the length, the encoding as it sits in memory and the expanded word, and points at
`llvm-objdump` for the text.

**Symbols are read from the ELF and labelled as such.** A listing of four thousand hex
words with no names is one nobody can navigate, so `.symtab` is read for annotation —
and every part of the report that shows a name says it came from the ELF and not from the
artifact, because two ELFs differing only in their symbols export identical bytes.

The tests hold the tool to `crates/loader` rather than to a recorded expectation. The one
worth naming: `the_listing_is_the_instruction_stream` **parses the printed listing back**
and compares it to the image's instruction slots — same addresses, same lengths, same
expanded words, nothing extra and nothing dropped — and `every_slot_is_accounted_for`
checks that the instruction lines, the mid-instruction slots their lengths imply and the
folded `not code` runs sum to `slots.len()`. A report that quietly dropped a slot fails
there. `tools/artifact-dump/CLAUDE.md` is the design record.

One thing the tool deliberately does not do: **program identity**. The report prints a
sha256 of the artifact so a rebuild can be compared against it, and says in as many words
that this is not identity — that is S11's, over the decoded per-family tables and the
`VmConfig`, in a different field. A digest printed next to the word "program" is exactly
what a reader would otherwise assume.

## Three more guests, and what each is a fixture for

`guests/` went from three crates to six. The three new ones are DeFi programs rather than
toy ones, because the point was to find out what a real guest does that the toolchain has
not seen — and it found something, which is the deviation at the top of the next section.

| Guest | Lines | Instructions | What only it exercises |
| --- | --- | --- | --- |
| `amm` | 753 | 8,227 | exact 128- and 256-bit arithmetic: `mul_div` through a 256-bit intermediate, integer `sqrt`, a constant-product assertion over full products. No heap at all. LLVM legalises `i128` into 32-bit limbs on this target and calls no builtin for it, so all of it is open-coded — a `u128 * u128` is 68 hardware multiplies |
| `orderbook` | 603 | 20,223 | the heap and the collections — `Vec`, `BTreeMap`, sorting, iterator chains, on an allocator whose `dealloc` does nothing — and the reference demonstration of hint-then-verify |
| `vault` | 505 | 11,904 | `crates/field` and `crates/transcript` used for a computation rather than linked to prove they compile: Merkle paths under Poseidon2, `Fr::inverse` for the share price, and the deepest call chain in `guests/` |

`orderbook` is the one to read first. It takes a sorted permutation of its orders from
fd 3 — sorting is `O(n log n)` and checking a claimed permutation is sorted is `O(n)`, so
the advice pays — and verifies it three ways (every index in range, no index twice via a
bitset it builds itself, the permuted sequence in key order) before an advised byte reaches
the auction. If any check fails it sorts the batch itself. **The two paths commit identical
bytes.** Not even a flag saying the advice verified reaches fd 1, because such a flag would
be a committed bit the prover chooses; which path ran goes to fd 2. That is the fd 3 rule
written out at length, and `docs/guest-program-manual.md` §3 now points at it.

Two things the reviewer should know about how they were checked. **None of the three has
been executed** — `qemu-riscv32` is Linux-only — so their logic rests on desk-checking and
on host harnesses that ran the pure arithmetic outside the guest, not on a run. And all
three are committed as ELF fixtures, which took `crates/loader/tests/vectors/` from 524 kB
to 1.4 MB; the alternative was a from-source test CI would not run, and the fixtures buy
host-loadability, round-trip and listing-fidelity coverage on every run for no build cost.

## Deviations and notes for the reviewer

- **The all-zero halfword became a `NonInstruction` slot, after S10 first froze it as a
  refusal.** `crates/loader` used to answer `LoaderError::RvcIllegal` for it. It does not
  any more: the sweep records `Slot::NonInstruction` and resumes two bytes later.

  *Why.* rustc's RISC-V target sets `TrapUnreachable`, so at `opt-level = 0` — the guest
  profile — every LLVM `unreachable` block is emitted as a real `unimp`, and with the C
  extension `unimp` assembles to the two-byte `c.unimp`, which is `0x0000`. That is
  exactly the encoding the loader refused. Four independent minimal reproductions, each
  verified against the loader before the change and each loading after it:

  - `match a.cmp(&b) { Less, Equal, Greater }` — a three-arm match, nothing more;
  - `field::Fr::inverse()`, this repository's own crate, via `Fr::pow`'s
    `for bit in (0..64).rev()`;
  - `for i in 0..4` where the counter infers `i32`, which is the integer fallback;
  - `AtomicU32::fetch_add`, and every other `core::sync::atomic` operation.

  (Each was a four-line guest whose only content was the construct named. The pcs are not
  recorded here: they are properties of throwaway crates, and a number a reader cannot
  reproduce is worse than none.)

  So the loader as S10 froze it could not accept an exhaustive three-arm `match`, any use
  of `core::sync::atomic`, the most common spelling of a `for` loop, `slice::sort_unstable_by`,
  or `Fr::inverse`. The three committed guests dodged it by accident. Nothing in CI would
  have found it, because CI builds only `guests/fib` and the fixtures were generated from
  guests that happen not to call any of the above.

  *Why this fix and not the other.* Setting `opt-level = 1` in `guests/Cargo.toml` also
  removes every trap, in one line, because `unreachable` then fuses into the surrounding
  CFG. It was rejected as the primary fix for two reasons: it rewrites every committed ELF,
  every derived listing and every pinned digest, and it moves the program identity of three
  guests that did not change; and it leaves the loader exactly as brittle against the next
  trap the compiler decides to emit. The widening is strictly additive — **every ELF that
  loaded before the change loads to a byte-identical image after it**, which the unchanged
  `fib`/`echo`/`rvc-dense` digests demonstrate — and it is the semantics the ISA asks for:
  `c.unimp` is *defined*-illegal, so reaching it is a run-time trap, and a loader cannot
  know whether any pc does. Put to the repository owner with all four reproductions and
  both options; they chose the widening.

  *What was given up.* The all-zero halfword was the sweep's canary for a desync into
  zeroed data. The oracle that actually catches a desync is
  `crates/loader/tests/differential.rs`, which compares the whole listing against
  `llvm-objdump` address for address in both directions and does not depend on any single
  encoding being fatal; it grew a carve-out exactly one encoding wide, and `amm.objdump.txt`
  carries one `c.unimp` so that carve-out is exercised on every CI run.
  `crates/loader/tests/image.rs` pins both halves of the new behaviour: the slot is
  `NonInstruction`, and the sweep resynchronises on the far side of a run of them.
  `zero_halfword.elf` moved from `negative.rs` to `image.rs`, and `zero_halfword_run.elf`
  is new.

- **`layout.rs` no longer requires the writable segment's `filesz` to be zero.** It
  requires the file-backed bytes to stop at or before `__bss_start`. A guest with an
  initialised mutable static has a `.data` section, lld folds it into the same `PT_LOAD` as
  `.bss`, and the old rule refused that outright while the property it meant to state — that
  the 256 MiB heap-and-stack reservation costs nothing on disk — still holds. None of the
  six committed guests has a non-empty `.data`; the rule was wrong rather than the guests.
  `docs/spec/ecall-abi.md` §7.1 says the same thing now.

- **`#[entry]` is `entry!`.** The stage prompt names an `#[entry]` attribute macro. An
  attribute macro *requires* a `proc-macro` crate, and rustc refuses to let such a crate
  export anything else (`proc-macro crate types currently cannot export any items other
  than functions tagged with #[proc_macro]…`), so `guest-sdk` cannot be both the macro and
  the runtime — and a proc-macro crate is host-compiled, so the crt0 stub could not live
  there in any case. That leaves a second package, which anti-goal 2 bans outright and
  which is not in the master's frozen layout. Put to the repository owner with the
  evidence; they chose the declarative form. `guest_sdk::entry!(main);` emits a wrapper
  carrying `#[export_name = "main"]`, so the annotated function keeps its own name and may
  itself be called `main`. Verified.
- **`crates/guest-sdk` uses `unsafe` and one `static mut`.** Anti-goals 4 and 7 ban both.
  A crt0 stub, a `#[global_allocator]` and a syscall shim cannot be written without them,
  and the stage names all three as deliverables, so master rule 13 applies: the stage
  wins. Every `unsafe` block in the workspace is in that one file, each with a `# Safety`
  note. Nothing else may follow suit.
- **Guest ELFs are not byte-reproducible across machines, and CI does not pretend they
  are.** This was put to the repository owner, who asked for a full regenerate-and-diff;
  measurement then showed it is not achievable on stable Rust 1.96. rustc passes absolute
  paths for path dependencies outside the guest workspace, and `core`'s own panic-location
  strings resolve to the local rustup sysroot (host triple and `$HOME` included) whenever
  `rust-src` is installed and to `/rustc/<hash>/…` when it is not. Both land in `.rodata`.
  `trim-paths` is still unstable in the pinned cargo, and `--remap-path-prefix` needs the
  machine-specific prefix. Demonstrated by building the identical source from a second
  absolute path: different digest. So `guests` is excluded from a bare
  `cargo run -p kat-gen` and the `.elf` files are refreshed on one machine, while
  **everything derivable from them** — the objdump and nm listings — regenerates and diffs
  in CI, which is master rule 8 applied to everything it can reach. Acceptance 2's literal
  requirement, two clean builds on one machine, is a test and holds.
  `tests/reproducible.rs::the_committed_rvc_regions_are_the_current_assembly` is the
  staleness guard that *is* host-independent: the paired regions are hand-written assembly
  with no relocations into `.rodata`, so both their bytes and their addresses are the same
  everywhere. The QEMU tests build their guest from source rather than reading a fixture,
  so behaviour is always checked against the current `guests/`.
- **RVC HINT encodings have no independent oracle**, because LLVM will neither assemble
  nor disassemble one — its decoder tables exclude `rd = x0` from `c.addi` and its
  siblings, and `llvm-objdump` renders such a halfword as `.word`, which desynchronises
  the listing. They are in `src/rvc.rs`'s unit tests instead, six expansions written
  longhand. What is HINT-specific is only that they are *accepted*; the field arithmetic
  behind each is the same code the paired-region oracle already covers through the
  non-HINT form of the same instruction. The loader accepts them because they are valid
  instructions whose 32-bit forms write `x0`, and rejecting them would reject programs a
  conforming assembler may emit.
- **`io_digest` lives in `crates/transcript`.** Put to the repository owner, who chose it.
  Must-be-exact 12's recipe turns out to be exactly two `append_bytes` messages and one
  `sample` over the encoding S02 already froze, so the function is five lines that reuse
  this crate's own typed layer; and `transcript` is the crate the prover and the verifier
  both already depend on, where `loader` or a new `host` crate would drag an ELF parser
  into the verifier's graph. It follows the precedent of `sumcheck::witness_digest` and
  `pcs::accumulator_digest` — a digest convention living with a sponge of its own.
- **zkVM I/O uses the Linux numbers, not the `0x0400` range.** The master prompt's
  parenthetical reads "zkVM I/O (`read`/`commit`) and precompile calls live in documented
  disjoint number ranges". Acceptance 3 and 8 require the guests to run **unmodified**
  under QEMU, which returns `-ENOSYS` for anything at `0x0400`; a guest whose `read_input`
  used such a number could not do I/O at all under the only executor this stage has. Put
  to the repository owner and resolved as: `read_input`/`commit`/`hint` are Linux
  `read`/`write` over fds 0, 1 and 3 (must-be-exact 6 and 7 spell exactly that), and the
  zkVM range stays documented, frozen and **empty** for future host calls. Recorded here
  because the master's phrasing admits the other reading.
- **The `.text` sweep is bounded by the executable `PT_LOAD` segments**, not by the
  `.text` *section*. The stage says "a linear sweep of `.text`"; with the frozen linker
  script lld emits `.text` as its own `R|X` segment and `.rodata` as a separate `R` one,
  so the two are the same range — and program headers, unlike section headers, survive
  stripping and are the exact set of addresses the VM can execute from. Sweeping a
  section table the loader is not otherwise required to parse would be more surface for no
  gain.
- **`serde` is still featureless**, so there are no `Vec` impls and the three sequences in
  `crates/loader` carry hand-written visitors. That is more lines than turning on
  `serde/alloc` would be, and it is the reason S01's feature graph is still the one that
  ships. The postcard buffer is a heap `Vec` written through `to_slice` for the same
  reason.
- **`crates/constants` gained a `tests/` directory.** Its own rule is "zero logic,
  forever", which `src/` still obeys — an integration test is a separate crate and links
  `std` on its own. Acceptance 9 wants the ABI document checked against the numbers, and
  the numbers live here.
- **`llvm-tools` was added to `rust-toolchain.toml`.** `kat-gen -- loader` needs
  `llvm-objdump` and `llvm-nm`; taking them from the toolchain rather than from `PATH`
  pins the disassembler to the same LLVM as the compiler, so the committed listings
  regenerate identically anywhere. The alternative, GNU riscv binutils, is an unpinned
  external dependency.
- **`guests/rvc-dense` is a fourth guest** beyond the master's `fib`/`echo` list. It is a
  loader fixture that happens to be runnable, and it lives in `guests/` so it inherits the
  template config rather than needing a second copy of it.
- **`.eh_frame` is an orphan section.** The frozen linker script does not place it, so lld
  puts it after `.rodata` in the read-only segment. Deterministic, outside every
  executable segment, and harmless; noted because a reader comparing the script to a
  `readelf` dump will see a section the script never mentions.
- **No `PROTOCOL_VERSION` bump.** It stays `0`: S10 fills in placeholders rather than
  changing a released protocol.

## Open for the next stage

- **The zkVM host-call range `0x0400..=0x04FF` is empty.** The first stage that needs
  nondeterministic host data assigns a number there, documents it in
  `docs/spec/ecall-abi.md` §3 with its class, and folds its returns into the public I/O
  digest — or explains in that table why it does not have to.
- **`PRECOMPILE_POSEIDON2` has a number and a calling convention but no circuit.** The
  delegation stage implements it; until then every executor answers `-ENOSYS` and
  `guests/echo` demonstrates the fallback shape a caller must have.
- **The S12 emulator must answer `-ENOSYS` for every unimplemented number**, exactly as
  QEMU does, and must implement `read`/`write`/`exit` with the fd semantics of §4. The
  differential harness master rule 10 wants — emulator against `qemu-riscv32`,
  per-instruction — has its guests and its loader here already.
- **S11 consumes `ProgramImage`.** Program identity is a deterministic function of it, so
  the `--no-relax` flag and the address-preservation rule are load-bearing from here on.
- **`transcript_tags` now has 21 entries.** Later stages append; they never renumber, and
  they never reuse a tag across message kinds.
- **Whether to keep committing the `objdump` listings is undecided, deliberately.**
  `crates/loader/tests/vectors/{fib,rvc-dense,amm}.objdump.txt` are 12,715 lines
  between them, which was 52% of S10's pull request by line count and made that
  PR hard to review for reasons that had nothing to do with its content. They are
  committed so `tests/differential.rs` has a hermetic oracle pinned to the same
  LLVM as the compiler — regenerating them is `cargo run -p kat-gen -- loader`
  and the digests are pinned in `tests/common/mod.rs`, so a hand-edited listing
  fails the build.

  The alternative is to generate them during the test run: CI already installs
  `llvm-tools` from `rust-toolchain.toml`, so the disassembler is present. That
  would permanently halve diffs of this shape, at the price of making the
  differential suite depend on an external binary at test time rather than on a
  file in the repository, and of reversing a choice S10 made on purpose.

  Neither option is obviously right and nothing here forces the question, so it
  is recorded rather than answered. A stage that adds another disassembled guest
  should decide it first — the cost is per-guest and it compounds. If the answer
  is "generate at test time", note that `synthetic_elfs.txt` and the `.elf`
  fixtures themselves are a separate question: those are inputs, not derivations,
  and they have to stay committed.
