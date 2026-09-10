# Turning a guest program into a `ProgramImage` artifact

From an empty crate to two files you can keep: the artifact a later stage
reads, and a report of it you can print and check by eye.

Everything below was run against this repository at S10. Commands are given
from the repository root unless a step says otherwise.

---

## 0. What you end up with

`cargo run -p artifact-dump -- <elf>` writes two files, both named after the
ELF:

| File | What it is |
| --- | --- |
| `<name>.img` | **the artifact.** The frozen `ProgramImage` wire form: `postcard` over `entry`, `segments`, `slot_base` and `slots` in declaration order. No header, no magic, no framing of the tool's own. |
| `<name>.img.txt` | **the report.** A rendering of that artifact, in text, with a full instruction listing. For reading, diffing and printing. |

The `.img` is the genuine, production representation of your program. It is
not a debug format or a summary: it is exactly the bytes
`loader::load_elf` produces for your ELF, which is what S11 derives program
identity from and S12 executes. Reading one back is one line:

```rust
let image: loader::ProgramImage = postcard::from_bytes(&std::fs::read("hello.img")?)?;
```

Two things it is **not**:

- **Not program identity.** The report prints a sha256 of the artifact so you
  can pin the bytes and compare a rebuild against them. Program identity is
  S11's, computed over the decoded per-family tables and the `VmConfig`; it is
  a different value, in a different field, for a different purpose.
- **Not a proof of anything about execution.** The artifact says what the
  program *is*. It says nothing about what it does with any particular input.

---

## 1. Before you start

The toolchain, its components and the guest target all come from
`rust-toolchain.toml` at the repository root. `rustup` installs them on your
first `cargo` invocation. Stock stable Rust: no nightly, no `-Z` flags, no
`-Zbuild-std`, no custom target JSON.

The four pieces you will touch:

| Where | What it gives you |
| --- | --- |
| `crates/guest-sdk` | `entry!`, the ecall shims, the allocator, the panic handler, `link.ld` |
| `guests/.cargo/config.toml` | the target, the QEMU runner, and the pinned linker flags |
| `crates/loader` | `load_elf`, `ProgramImage` — the thing being exported |
| `tools/artifact-dump` | the exporter |

`docs/spec/ecall-abi.md` is the normative document for the ABI and the memory
map. Where this manual and that document disagree, that document is right.

---

## 2. Write the guest

A guest is an ordinary `no_std` binary crate that lives in the `guests/`
workspace. Three files, one of which already exists.

`hello` below is the guest this manual builds; you are creating it now. The
repository ships six, and every command here works on those too with the name
changed. They are worth reading before you write your own, because between them
they cover most of what a guest can do:

| Guest | What it is, and what it shows you |
| --- | --- |
| `fib` | the smallest real guest: read a `u32`, commit a `u32` |
| `echo` | the ecall shims end to end — fd 0 to fd 1, a hint, diagnostics, the heap, and the Poseidon2 precompile with its software fallback |
| `rvc-dense` | hand-written assembly and the compressed-instruction table; a loader fixture more than a program |
| `amm` | a constant-product market maker: exact 128- and 256-bit arithmetic, `mul_div`, integer `sqrt`, and no heap at all |
| `orderbook` | a uniform-price auction: `Vec`, `BTreeMap`, sorting, and the reference demonstration of hint-then-verify |
| `vault` | Merkle-gated withdrawals over Poseidon2: `crates/field` and `crates/transcript` running inside the proof, and the deepest call chain in `guests/` |

If you are looking for a pattern to copy, `amm` is the one to read for arithmetic
and framing, `orderbook` for anything that takes prover advice, and `vault` for
anything that hashes.

**`guests/hello/Cargo.toml`**

```toml
[package]
name = "hello"
version.workspace = true
edition.workspace = true
publish.workspace = true

[dependencies]
guest-sdk.workspace = true
```

**`guests/hello/src/main.rs`**

```rust
#![no_std]
#![no_main]

guest_sdk::entry!(main);

fn main() {
    let mut buf = [0u8; 4];
    let n = guest_sdk::read_input(&mut buf);
    guest_sdk::log(b"hello: read the public input\n");
    guest_sdk::commit(&buf[..n]);
}
```

**`guests/Cargo.toml`** — add the crate to the member list:

```toml
members = ["fib", "echo", "rvc-dense", "amm", "orderbook", "vault", "hello"]
```

Four things about that source file are not negotiable:

- **`#![no_std]`** — `riscv32imac-unknown-none-elf` is a bare-metal target and
  has no `std` to link against. That is not only a packaging fact: the parts of
  `std` that look portable are largely the ones that would reach for host
  entropy and host clocks, and those are refused at the ABI. See §3.
- **`#![no_main]`** — the entry point is crt0's `_start`, not Rust's.
- **`guest_sdk::entry!(main)`** gives your function the `main` symbol `_start`
  calls. It is a `macro_rules!` and not an `#[entry]` attribute because an
  attribute macro needs a `proc-macro` crate, and a second package for one
  spelling was not worth it. The annotated function keeps its own name and may
  itself be called `main`; the macro emits a separate wrapper.
- **Returning from `main` is `exit(0)`.** To exit nonzero, call
  `guest_sdk::exit(code)` or panic.

Your guest may use any crate that compiles for `riscv32imac-unknown-none-elf`
without `std`. `crates/field`, `crates/constants`, `crates/transcript`,
`crates/poly` and `crates/sumcheck` all do, and CI builds them for the guest
target on every run precisely so that this stays true.

---

## 3. The I/O surface

```rust
pub fn read_input(buf: &mut [u8]) -> usize;    // fd 0, committed
pub fn commit(bytes: &[u8]);                   // fd 1, committed
pub fn hint(buf: &mut [u8]) -> usize;          // fd 3, prover advice
pub fn log(bytes: &[u8]);                      // fd 2, verifier-ignored
pub fn exit(code: i32) -> !;
pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool;   // false on -ENOSYS
```

| fd | Committed | What it means for you |
| --- | --- | --- |
| 0 | yes | public input; the first stream the public I/O digest binds |
| 1 | yes | public output / journal; the second stream |
| 2 | no | diagnostics. Free-form, and the verifier never looks at it |
| 3 | **no** | private hints: **nondeterministic prover advice** |

Five rules worth having in front of you while you write:

1. **`read_input` and `hint` may return short.** They fill the buffer or stop
   at the end of the stream. If you need an exact length, check the count. A
   guest that proceeds on a partly-filled buffer proves something about zeroes.
2. **A hint binds nothing.** The prover chooses fd 3's bytes. If a hint can
   change what you write to fd 1, and you have not checked it against something
   the public I/O digest *does* bind, your proof is meaningless — the prover
   picked the output. A hint is a shortcut to a value you then verify.
3. **Anything that would return host data is refused.** `getrandom`,
   `clock_gettime`, `gettimeofday`, and whatever `HashMap` reaches for to seed
   its `RandomState` all answer `-ENOSYS`. That is deliberate: each is
   nondeterministic advice wearing the costume of a library call.
4. **`poseidon2_permute` returns `false` today**, on every executor, because
   the precompile has a number and a calling convention but no circuit yet. You
   must have a software path and take it on `false`. Any *other* failure exits
   nonzero rather than falling back silently.
5. **`hint` needs an fd 3 to read.** The zkVM always has one. `qemu-riscv32`
   only has the descriptors you give it, and a `read` on a closed one answers
   `-EBADF`, which the SDK treats as an executor fault and exits 70 on. Running
   a guest that calls `hint` by hand means opening fd 3 yourself, even at an
   empty file:

   ```
   sh -c 'exec 3</dev/null; exec qemu-riscv32 ./yourguest' < input
   ```

`guests/orderbook` is the worked example of rule 2. It takes a sorted
permutation of its orders from fd 3 — sorting costs `O(n log n)` and checking a
claimed permutation is sorted costs `O(n)`, so the advice is worth having — and
then verifies it three ways before a single advised byte reaches the auction. If
any check fails it sorts the batch itself. **The two paths commit identical
bytes**, which is the whole point: not even a flag saying the advice verified
reaches fd 1, because such a flag would be a committed bit the prover chooses.
Which path ran is written to fd 2 and nowhere else.

The allocator bumps upward from `__heap_start` and `dealloc` does nothing, so
`alloc` works but never reclaims. An allocation that would cross `__stack_top`
exits nonzero rather than returning null.

---

## 4. Build it

From the guest's own directory, with no flags beyond the target:

```
cd guests/hello
cargo build --target riscv32imac-unknown-none-elf
```

Everything else comes from `guests/.cargo/config.toml`: the target, the
`qemu-riscv32` runner, and the two linker flags that matter —
`-T../crates/guest-sdk/link.ld` for the frozen memory map, and `--no-relax`,
because linker relaxation rewrites instruction sequences and shifts every later
address, and S11's program identity is a function of those addresses.

The ELF lands at `guests/target/riscv32imac-unknown-none-elf/debug/hello` —
one target directory for the whole guest workspace, not one per guest.

> **If you edit `link.ld`, run `cargo clean` first.** Cargo does not track the
> linker script as a build dependency: it will report "Finished" and relink
> nothing, and you will dump a stale binary while reading a new script.

---

## 5. Export the artifact

```
cargo run -p artifact-dump -- guests/target/riscv32imac-unknown-none-elf/debug/hello --out artifacts/
```

```
guests/target/riscv32imac-unknown-none-elf/debug/hello
  entry 0x00010000, 3 segments, 1897 instructions
  artifact artifacts/hello.img (18502 bytes, sha256 f439f67ad948db0036180e04ef273c617008de3669c08ec07a2b09bbc1a735c4)
  report   artifacts/hello.img.txt
```

`--out` defaults to the working directory. It is separate from the ELF's own
directory on purpose: the ELF lives under `target/`, which `cargo clean`
deletes, and an artifact worth exporting is one worth keeping.

Before writing anything, the tool serializes the loaded image, reads it back
through the reader that re-checks every invariant, and compares the result to
what the loader produced. If those disagree it writes nothing and says so. That
is why the report can be trusted to describe the file beside it: they are
rendered from the same round-tripped value.

**Your digest will not match the one above**, and that is expected. A guest ELF
is not byte-reproducible *across machines* — rustc embeds absolute paths in the
panic-location strings of `core` and of every crate outside the guest
workspace, and stable Rust cannot remap them. On one machine it is exact; §7
shows the check.

---

## 6. Read the report

`artifacts/hello.img.txt` opens with what it is, what it came from, and the two
digests. Then five sections.

### `entry and memory`

```
entry             0x00010000  _start
RAM window        0x00010000 .. 0x10000000    constants::guest_memory
slot_base         0x00010000
slot span         0x00010000 .. 0x00011418    2572 halfwords
```

`_start` sits at `ORIGIN(RAM)` because the linker script puts it in its own
`.text._start` input section. The slot vector runs from the lowest loaded
address to the top of the highest executable segment and stops there: no pc
above the last executable byte can be an instruction, so a slot there would say
nothing, and `slot_at` answers `None`.

### `segments`

```
  #  vaddr       end          mem_len      file bytes    zero fill  instructions
  0  0x00010000  0x00011418   0x00001418          5144            0          1897
  1  0x00012000  0x00012a2c   0x00000a2c          2604            0             0
  2  0x00013000  0x10000000   0x0ffed000             0    268357632             0
```

Three segments is what the frozen `link.ld` produces for every guest in this
repository: `.text` (read + execute), `.rodata` (read only), and one writable
segment holding `.data`, `.bss` and the reservation above them, running to the
top of RAM. Its `file bytes` is zero whenever `.data` is empty, which is the
common case — `hello`, `fib`, `echo` and `rvc-dense` are all like that, so the
whole third segment is zero fill. It is declared because a host program loader
maps exactly what the program headers declare and nothing else — an undeclared
stack is unmapped memory whose first push dies on a signal. Each section is
page-aligned for the same reason: two segments sharing a page take the second
mapping's permissions for the whole page. `docs/spec/ecall-abi.md` §7.1 is
normative, and `crates/loader/tests/layout.rs` enforces it.

Note the artifact carries **no permission bits**. The zkVM has no pages and no
permissions; the `instructions` column is what makes a segment executable as
far as the image is concerned.

### `instruction stream`

```
instructions      1897       675 four-byte, 1222 two-byte
mid-instruction   675        the second halfword of each four-byte instruction
not code          0          the all-zero halfword LLVM pads an unreachable block
                             with, data below the code, gaps, bytes above a
                             segment's file length, tails nothing fit in
total slots       2572       1897 + 675 + 0, and the slot span is 5144 bytes
instruction bytes 5144       4*675 + 2*1222
```

Those last two lines are the same number twice, from both directions. The slot
vector is pc/2-indexed and every halfword is accounted for exactly once.

`hello` has no `not code` slots. Size is not what decides it — `echo` is five
times larger and has none either, while `amm` has one — the constructs in §6a
are, and §6a says why.

### `symbols`

Read from the ELF's own symbol table, **not** from the artifact. They are there
so the listing can be navigated; nothing downstream sees them, and two ELFs
differing only in their symbols export identical artifact bytes. Assembler-local
labels (`.L*`) and mapping symbols (`$*`) are dropped.

```
  0x00010000  _start
  0x0001006a  _ZN5hello4main17h29eb51b0cbda4953E
  0x000100b6  main
  0x00013000  __bss_end, __bss_start, __heap_start
```

The last line is three linker symbols on one address, which is what an empty
`.bss` looks like.

### `listing`

```
address     len  in memory  expanded  symbol
0x00010000    4   0fff0117  0fff0117  _start
0x00010004    4   00010113  00010113
...
0x0001006a    2       1141  ff010113  _ZN5hello4main17h29eb51b0cbda4953E
0x0001006c    2       c606  00112623
0x0001006e    2       4501  00000513
```

Three columns worth understanding:

- **`len`** is the instruction's length in memory, in bytes, and it is the only
  thing that says whether the next pc is `+2` or `+4`. The expanded word cannot
  say: a compressed instruction expands to a full 32-bit encoding while still
  occupying two bytes. **Addresses are never compacted** — a `c.addi` at
  `0x1002` stays at `0x1002`. Compacting would shift every later address and
  change program identity for a program that did not change.
- **`in memory`** is the halfword or word as the ELF stores it at that address:
  four hex digits for a compressed instruction, eight for a full one.
- **`expanded`** is what the artifact carries — the same word for a four-byte
  instruction, and for a two-byte one the exact 32-bit instruction it
  abbreviates. Above, `1141` is `c.addi sp, -16` and `ff010113` is the
  `addi sp, sp, -16` it stands for.

The halfword after a four-byte instruction is a mid-instruction slot and is not
listed; its position is implied by `len`, and the artifact's reader rejects an
image where one is missing or stands alone. Runs of slots that are not code are
folded into one `---- not code: ... ----` line.

There are no mnemonics, deliberately: an instruction model is `crates/isa`'s
job in a later stage, and a second decoder written here would be a second thing
to keep correct. For mnemonics, disassemble the same ELF:

```
llvm-objdump --disassemble --no-print-imm-hex -M no-aliases <elf>
```

`crates/loader/tests/differential.rs` holds the loader's listing to that
disassembler's, address for address and encoding for encoding, in both
directions — so a linear sweep that had lost synchronisation fails there rather
than being printed here.

---

## 6a. The `not code` runs in the middle of your functions

Dump a guest that uses any of the constructs in the table below, and the listing
will have lines like this one, from `amm`:

```
0x00010f52    2       952e  00b50533
0x00010f54    2       4108  00052503
0x00010f56    2       8502  00050067
---- not code: 0x00010f58 .. 0x00010f5a, 1 halfword ----
0x00010f5a    4   18412683  18412683
```

That is not a desynchronised sweep and it is not data in your `.text`. It is two
bytes of `0x0000`, and it is there because **rustc materialises unreachable code
as a trap instruction at `opt-level = 0`**, which is the guest profile. The
RISC-V target sets `TrapUnreachable`, so every LLVM `unreachable` block becomes a
real `unimp`; with the C extension `unimp` assembles to the two-byte `c.unimp`,
which is `0x0000`. `llvm-objdump` spells it `c.unimp`. The loader records it as
not code, because the all-zero halfword is RVC's *defined-illegal* encoding — the
spec gives it that status precisely so that a jump into zeroed memory traps —
and it abbreviates no 32-bit instruction, so there is nothing to put in a slot.
No pc reaches it; if one did, the VM would trap, which is what the ISA asks for.

The three instructions above it are the giveaway: `c.add`, `c.lw`, `c.jr` is a
jump table being indexed and jumped through. The padding is the switch default
that LLVM proved unreachable.

**What emits one.** More than you would guess, and none of it is exotic:

| Construct | Why |
| --- | --- |
| an exhaustive `match` on an enum with three or more variants | the switch default is `unreachable`; two variants are folded into a branch instead and emit nothing |
| `match a.cmp(&b) { Less, Equal, Greater }` | `Ordering` is three variants, so the above |
| any `core::sync::atomic` load, store or read-modify-write | `Ordering` is five variants, and at `opt-level = 0` the helper is a real out-of-line call that matches on it |
| `for i in 0..n` where `i` infers to a signed type | integer fallback is `i32`, and `<i32 as Step>::forward_unchecked` ends in `unwrap_unchecked` |
| `slice::sort_unstable_by` | its pivot selection does the above |
| `field::Fr::inverse`, `Fr::pow`, `field::batch_inverse` | `pow`'s `for bit in (0..64).rev()` infers `i32` |

A `_ =>` wildcard does not save you on an enum, because rustc knows it covers
exactly the remaining variants and the LLVM default is still unreachable. A
wildcard on a `u32` *does*, because the default is then a block a real value can
reach.

None of this is something to avoid. It costs two bytes, no pc reaches it, and
you cannot reliably keep it out of your binary anyway — `core` emits it on your
behalf. It is documented here only so that a `not code` run in the middle of a
function does not look like a bug when you read your own report.

---

## 7. Check it yourself

Five checks, in the order they are worth running.

**The round trip** happens on every dump: the tool refuses to write a file
whose contents are not the image the loader produced. You get it for free.

**Reproducibility on one machine.** Build into a fresh target directory and
dump again; the artifact digest must not move.

```
cd guests/hello
CARGO_TARGET_DIR=/tmp/hello-fresh cargo build --target riscv32imac-unknown-none-elf
cd ../..
cargo run -p artifact-dump -- /tmp/hello-fresh/riscv32imac-unknown-none-elf/debug/hello --out /tmp/art2
cmp artifacts/hello.img /tmp/art2/hello.img
```

The `.img` files must be identical. The `.img.txt` files differ in exactly one
line — `source ELF`, which records where the ELF was read from, and the two
paths are different. A difference anywhere else would mean the report carries
something that is not a function of the artifact.

Across machines the artifact will differ, for the embedded-paths reason in §5.
That is acceptance 2's exact boundary, and `crates/loader/tests/reproducible.rs`
is the test that holds it.

> **This whole walkthrough is a test.** `tools/artifact-dump/tests/manual.rs`
> runs §4, §5 and the check above over **every** crate in `guests/Cargo.toml`'s
> member list, on every CI run: two clean builds each, two exports each, and the
> comparison. It reads the guest list out of the manifest rather than carrying
> its own, so a guest that exists is a guest whose walkthrough is checked, and it
> fails if this document stops naming one of them. If the procedure below ever
> stops working, that is where it shows up.

**Mnemonics**, against the pinned disassembler, per §6.

**Host loadability.** Your ELF has to satisfy two loaders: `crates/loader`,
which reads `p_vaddr` and `p_memsz` into a flat window where every address
exists by construction, and a *host* loader, which maps only what the headers
declare, page by page, at the declared permissions. An image can be fine for
the first and unrunnable under the second — S10 shipped exactly that, twice.

The two rules are properties of `link.ld`, which every guest links against
unmodified, so a guest that changes only its own source has the segment shape
the committed guests have. `crates/loader/tests/layout.rs` checks those over all
six committed guests on every CI run, and its ignored case relinks them from
source and re-checks — which is what to run after touching the script:

```
cargo test -p loader --test layout -- --ignored     # needs the guest target
```

Neither reads *your* ELF, so to check yours directly, look at its headers:

```
"$(rustc --print sysroot)"/lib/rustlib/*/bin/llvm-readobj \
    --elf-output-style=GNU --program-headers <elf>
```

```
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  LOAD           0x001000 0x00010000 0x00010000 0x0173e 0x0173e R E 0x1000
  LOAD           0x003000 0x00012000 0x00012000 0x00ccc 0x00ccc R   0x1000
  LOAD           0x004000 0x00013000 0x00013000 0x00000 0xffed000 RW  0x1000
```

Three things to see there, and each was a real failure:

1. every `VirtAddr` is page-aligned, and `Offset ≡ VirtAddr (mod 0x1000)` —
   a host loader maps from `page_down(offset)` to `page_down(vaddr)`, so
   anything else maps the wrong bytes;
2. no two `LOAD`s share a page, because the second mapping's permissions would
   win for the whole page — an unaligned `.rodata` strips execute from the tail
   of `.text`;
3. the segment with `MemSiz` above `FileSiz` is the one marked `RW`, and it
   reaches `0x10000000`. Zero fill on a read-only page is refused outright, and
   the span up to `__stack_top` is the heap and the stack: undeclared, the
   first push dies on a signal before `main` runs.

**Execution.** `qemu-riscv32` is the only executor before S12. It is user-mode
emulation — it translates the guest's Linux syscalls into the host's — so it
builds for Linux hosts only and there is no native macOS build of it. The tests
stay `#[ignore]`d so a machine with no emulator cannot report silent coverage,
and you ask for them by name:

```
cargo test -p loader --test qemu -- --include-ignored   # a Linux host with qemu-user
```

**On macOS, borrow a Linux.** Apple Silicon runs one at native speed, so only
the innermost hop is emulated: macOS -> arm64 Linux VM -> `qemu-riscv32` ->
guest. About four minutes of setup, once:

```
brew install colima docker
colima start --cpu 4 --memory 8 --disk 60

docker run --rm -v "$PWD":/w -w /w -e CARGO_TARGET_DIR=/tmp/t rust:latest \
  bash -c 'apt-get update -qq && apt-get install -y -qq qemu-user &&
           cargo test -p loader --test qemu -- --include-ignored'
```

`rust:latest` ships rustup, which reads `rust-toolchain.toml` on the first
cargo call and installs the pinned toolchain and the guest target, so nothing
drifts from the pin. Set `CARGO_TARGET_DIR` somewhere outside the repository:
cargo does not namespace `target/` by host triple, so sharing it with the macOS
build makes each run rebuild over the other.

A guest built inside that container is **not** the same bytes as one built on
the host — rustc embeds absolute paths in `core`'s panic-location strings and
stable Rust cannot remap them, so the two differ in size as well as content.
That is why `crates/loader/tests/qemu.rs` builds every guest from source rather
than reading a committed fixture: what it checks is the behaviour of the
current `guests/` tree, and the fixtures are loader-differential inputs pinned
separately. What does *not* differ is your own crate's panic locations, which
are relative to the crate root, or anything on fd 0 and fd 1.

To run your own guest by hand on a Linux host, `cargo run` from the guest's
directory invokes it through QEMU already — that is what the `runner` line in
the template config is for. Guests use Linux syscall numbers precisely so this
works unmodified.

---

## 8. Using the artifact downstream

```rust
use loader::ProgramImage;

let bytes = std::fs::read("artifacts/hello.img")?;
let image: ProgramImage = postcard::from_bytes(&bytes)?;

assert_eq!(image.entry, 0x0001_0000);
let Some(loader::Slot::Instruction { word, compressed }) = image.slot_at(image.entry) else {
    unreachable!("the reader would have refused the file");
};

// `compressed` is the length, and the only thing that gives you the next pc.
let next_pc = image.entry + if compressed { 2 } else { 4 };
println!("{:#010x}: {word:08x}, next pc {next_pc:#010x}", image.entry);
```

What that gives you, and why:

- **The value equals `load_elf`'s** for the same ELF, because that is what was
  serialized.
- **The reader re-validates every invariant** the type declares — segments
  sorted, disjoint and inside the RAM window; `slot_base` even and the lowest
  loaded address; every 32-bit instruction paired with its mid-instruction
  slot; the entry the address of an instruction. A wire form is untrusted
  input, and a field the reader accepts is a field a later stage will believe.
- **The encoding is frozen at S10**, fields and serialization both. Later
  stages read it; nobody redefines it.

`postcard` is taken with no features anywhere in this workspace, so there is no
`to_allocvec`; `artifact_dump::wire_form` sizes a buffer from the image and
uses `to_slice`. Reading back needs nothing special.

---

## 9. When the loader refuses

The tool writes nothing and prints the refusal. Every variant of
`loader::LoaderError` names one class of problem:

| Refusal | What it usually means for you |
| --- | --- |
| `NotAnElf`, `Truncated` | you pointed it at something that is not the ELF — a `.d` file, a directory, a partial write |
| `RelocatableElf` | that is a `.o`, not a program |
| `DynamicElf` | `ET_DYN`, `PT_DYNAMIC` or `PT_INTERP`. Something turned on dynamic linking or PIE; the guest must be static |
| `NotRiscV`, `UnsupportedElfType` | built for the host, not for `riscv32imac-unknown-none-elf` |
| `BadSegment` | a `PT_LOAD` with an odd address, `filesz` above `memsz`, an overlap, or a span leaving the RAM window. Usually a hand-edited `link.ld` |
| `NoExecutableSegment` | nothing is executable — an empty or entirely optimised-away guest |
| `EntryNotAnInstruction` | `e_entry` is odd, outside the image, in a data segment, or mid-instruction. Usually `ENTRY(_start)` lost its target |
| `RvcIllegal` | a halfword no RV32C encoding claims, at a named pc. Either data ended up inside `.text`, or the compiler emitted a `Zc*` form this VM does not accept. **Not** the all-zero halfword, which is a defined-illegal encoding and becomes a not-code slot — see §6a |
| `InstructionTooLong` | an encoding wider than 32 bits. RV32IMAC has none |
| `TextTruncated` | a 32-bit instruction whose second halfword is past the end of its segment |

`RvcIllegal` deep inside otherwise-fine code is the one worth pausing on. The
sweep is linear, and instruction boundaries are not local: data embedded in an
executable segment desynchronises it and everything after decodes as garbage.
Compiler output stays synchronised because GCC and LLVM keep constants in
`.rodata`. A hand-written `.section .text` holding a table is the usual cause.

Nothing in this table is something ordinary Rust can provoke. Every refusal here
is a malformed or mis-targeted ELF, not a program the compiler would not know how
to build — write whatever you like in safe `no_std` Rust and the loader will take
it. That was not true before the all-zero halfword became a not-code slot: until
then an exhaustive three-arm `match`, any use of `core::sync::atomic`, a
`for i in 0..n` with a signed counter, `slice::sort_unstable_by` and
`field::Fr::inverse` each made a guest unloadable, for a two-byte trap no pc
reaches. §6a is the whole story.

---

## 10. What is frozen

Changing any of these is a protocol-version change, not a refactor:

- **`ProgramImage`** — its four fields and their `postcard` encoding.
- **`loader::load_elf(bytes) -> Result<ProgramImage, LoaderError>`** — the one
  way an image is built.
- **The ecall numbers and the fd conventions**, in `constants::ecall`, with
  `docs/spec/ecall-abi.md` as the table. Numbers are append-only forever.
- **The memory map and the linker symbols** — `__bss_start`, `__bss_end`,
  `__heap_start`, `__stack_top` — and the segment-layout rules in
  `docs/spec/ecall-abi.md` §7.1.
- **`--no-relax`**, and the pinned toolchain in `rust-toolchain.toml`.
- **`io_digest`**, the public I/O digest over your fd 0 and fd 1 streams.

Not frozen, and yours to change: the report's text and layout. It is a
rendering. The artifact is the contract.
