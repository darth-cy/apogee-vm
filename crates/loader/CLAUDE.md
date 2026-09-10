# `crates/loader`

## What this crate owns
Turning guest ELF bytes into a `ProgramImage`: the post-load memory image, the entry pc,
and the expanded instruction stream at halfword granularity. It parses static RV32 ELF
executables, refuses everything else by name, and expands every compressed instruction to
the exact 32-bit instruction it abbreviates.

```rust
pub fn load_elf(bytes: &[u8]) -> Result<ProgramImage, LoaderError>;   // the only entry point

pub struct ProgramImage {                                             // FROZEN AT S10
    pub entry: u32,
    pub segments: Vec<Segment>,   // sorted by vaddr, pairwise disjoint
    pub slot_base: u32,           // even; the pc of slots[0]
    pub slots: Vec<Slot>,         // one per halfword, up to the top of the code
}
pub struct Segment { pub vaddr: u32, pub mem_len: u32, pub bytes: Vec<u8> }
pub enum Slot {
    Instruction { word: u32, compressed: bool },
    MidInstruction,
    NonInstruction,
}
impl ProgramImage { pub fn slot_at(&self, pc: u32) -> Option<Slot>; }

pub enum LoaderError { /* twelve variants, one per failure class */ }
```

`docs/spec/ecall-abi.md` §7 is normative for the memory map and the linker symbols.

## Frozen invariants
- **Addresses are preserved, never compacted.** A `c.addi` at `0x1002` stays at `0x1002`
  and occupies two bytes; expansion changes representation, not layout. Compacting would
  shift every later address, break linker-resolved function pointers and computed jumps,
  and change S11's program identity for a program that did not change.
- **`compressed` is the instruction's length**, and the only thing that says whether the
  next pc is `pc + 2` or `pc + 4`. The expanded word alone cannot say.
- **The slot vector runs from the lowest loaded address to the top of the highest
  executable segment.** It stops there because no pc above the last executable byte can
  ever be an instruction, so a slot there would say nothing — and `.bss`, which this
  memory map always puts above the code, would otherwise cost four bytes of table per byte
  of zeroes. `slot_at` answers `None` above it. `NonInstruction` means data below the
  code, a gap between executable segments, bytes above a segment's `p_filesz`, or a tail
  no instruction fit in.
- **Every `PT_LOAD` must lie inside `constants::guest_memory`'s RAM window.** Nothing
  outside it is addressable. Enforcing it is also what bounds the slot vector: without the
  check, a 100-byte hostile ELF declaring a 4 GB `p_memsz` would size the allocation.
- **`load_elf` is a pure function of the bytes.** No clock, no filesystem, no hash map.
  S11 derives program identity from the result.
- **The wire form is `postcard` over the four fields in declaration order.** Hand-written
  serde impls, sorted vectors, never a hash map. `Deserialize` re-checks every invariant
  above — a wire form is untrusted input, and `load_elf` establishes these by construction
  where a reader cannot.
- **Only the base C extension, in its RV32 flavor.** Every F/D form, every RV64-only form,
  every reserved code point and every `Zc*` slot is a loud error naming the pc. HINTs are
  expanded, not rejected: they are valid instructions whose 32-bit forms write `x0`.

## Why the sweep is fragile on purpose
Instruction boundaries are not local. Data inside an executable segment desynchronises the
linear sweep and everything after it decodes as garbage. Compiler output stays in sync
because GCC and LLVM keep constants in `.rodata`; a desync that reaches real code diverges
loudly — under QEMU, and here the moment it meets a halfword no encoding claims. A loader
that guessed would be a loader that proves the wrong program.

## The two oracles
Master rule 10 wants differential tests, and the loader has two independent ones.

- **Boundaries** — `llvm-objdump` from the pinned toolchain. `tests/differential.rs`
  checks that the loader's instruction set is the disassembler's, address for address and
  encoding for encoding, in both directions.
- **Expansions** — LLVM's own 32-bit encoder. `guests/rvc-dense` holds the same
  instruction sequence twice, once in compressed mnemonics under `.option rvc` and once in
  the base mnemonics they abbreviate under `.option norvc`. The test expands the first
  region and compares it to the second, so neither side of the comparison is a second
  reading of the RVC table by its author.

RVC **HINT** encodings are the one gap: LLVM will neither assemble nor disassemble one, so
`src/rvc.rs`'s unit tests pin those six expansions longhand instead.

A third oracle, of a different kind, is the host program loader itself -- see below.

## Artifacts
| Path | What |
| --- | --- |
| `tests/vectors/{fib,echo,rvc-dense}.elf` | the committed guest ELFs |
| `tests/vectors/{fib,rvc-dense}.objdump.txt` | the disassembly listings |
| `tests/vectors/rvc-dense.nm.txt` | the text symbols |
| `tests/vectors/*.elf` (the rest) | hand-built ELFs, one per refusal |
| `tests/vectors/synthetic_elfs.txt` | that index, with each file's digest |
| `tests/vectors/fib_io.txt` | fib's fd 0 and fd 1 byte streams |

The `.elf` digests are pinned in `tests/common/mod.rs`; `tests/layout.rs` then holds
those same files to the host-loadability rules, so a refresh that regressed the linker
script fails rather than being recorded.

Refresh, in this order and deliberately:

```
cargo run -p kat-gen -- guests    # rebuild the ELFs; one machine, see below
cargo run -p kat-gen -- loader    # everything derived from them
```

then move the digests it prints into `tests/common/mod.rs`.

**The ELFs are not regenerated in CI.** A guest ELF is not byte-reproducible across
machines: rustc embeds absolute paths in the panic-location strings of every crate outside
the guest workspace and of `core` itself, and stable Rust cannot remap them (`trim-paths`
is unstable in the pinned cargo). Two clean builds on one machine do agree, which is what
acceptance 2 asks and what `tests/reproducible.rs` proves. Everything derivable *from* the
ELFs is regenerated and diffed.

## Exporting an image
`tools/artifact-dump` writes a `ProgramImage` out as the frozen `postcard` wire
form — no container, no header — beside a text report of it. It is the path a
guest author takes from an ELF to something later stages read and something a
person can check by eye, and `docs/guest-program-manual.md` is that walkthrough.
Its tests parse the printed listing back and compare it to the image slot for
slot, so the report cannot drift from what this crate produces.

## Host loadability is a separate property, and `tests/layout.rs` owns it
This crate reads an ELF the way the zkVM will: `p_vaddr` and `p_memsz` into a flat RAM
window where every address exists by construction. A **host** program loader --
`qemu-riscv32`, or Linux -- maps only the segments the program headers declare, page by
page, at the declared permissions. An image can be perfectly loadable here and unrunnable
there, and nothing else in this crate would notice.

S10 shipped exactly that bug. `__stack_top` sat at the top of the RAM window with no
segment declaring it, so the first stack write hit unmapped memory and the guest died on a
signal before `main`; and `.bss` shared a page with `.rodata`, which QEMU refuses outright.
`tests/layout.rs` checks the rules that were violated -- every segment page-aligned, no two
sharing a page, zero fill only on writable pages, `__heap_start` and `__stack_top - 1`
mapped writable, the entry point mapped executable -- and pins the two failing layouts as
negative controls. It parses the headers itself rather than through `load_elf`, because
`ProgramImage` drops the flags and offsets the rules are about and because a check routed
through the crate under test is a second reading of one parser, not a witness against it.

It needs no compiler and no emulator, so unlike `tests/qemu.rs` it runs everywhere.

## Notes
- **`tests/qemu.rs` is `#[ignore]`d.** `qemu-riscv32` is user-mode emulation, built for
  Linux hosts only -- there is no macOS build to install, so on a developer machine these
  cannot run at all. They used to print why and return, which reported a pass for work that
  did not happen; now they are ignored and `qemu()` panics when the emulator is missing, so
  there is no path on which they pass without executing. Run them with
  `cargo test -p loader --test qemu -- --ignored` on a Linux host with `qemu-user`.
  CI does not gate on them; `.github/workflows/ci.yml` carries the two steps that would.
  They build their guest from source rather than reading the fixture, so behaviour is
  always checked against the current `guests/`.
- `tests/reproducible.rs`, `tests/qemu.rs` and `tests/layout.rs`'s ignored case shell out to
  `cargo`. Each run gets its own target directory under the system temp dir, because the
  test harness is threaded.
