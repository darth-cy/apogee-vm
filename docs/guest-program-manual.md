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
repository ships ten, and every command here works on those too with the name
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
| `atomics` | every A-extension instruction as the compiler emits it, from `core::sync::atomic` on one hart; the fixture for the atomics circuit family |
| `opcodes` | every RV32IMAC instruction in hand-written assembly at its edge cases, which the emulator is compared against `qemu-riscv32` on; fd 0 selects the `ebreak` and misaligned-access modes |
| `heap` | `Vec` and `Box` churned through the bump allocator, so the heap's traffic is in the trace |
| `consistency` | ordinary Rust — numerics, collections, text, traits and closures, a codec, hashes, allocation patterns — as a `no_std` library the host calls directly and a thin guest `main`. The consistency suite runs it on the host, under QEMU and on the emulator and holds the three to one answer; §2a is the pattern to copy |

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
members = ["fib", "echo", "rvc-dense", "amm", "orderbook", "vault", "atomics", "opcodes", "heap", "consistency", "hello"]
```

Four things about that source file are not negotiable:

- **`#![no_std]`** — `riscv32imac-unknown-none-elf` is a bare-metal target and
  has no `std` to link against. That is not only a packaging fact: the parts of
  `std` that look harmless are largely the ones that would reach for host
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

### 2a. Run your logic on the host too

A guest you can only run inside the VM is a guest you can only debug there. Put
the program in a `#![no_std]` library and keep `main.rs` to reading fd 0 and
committing what the library returns. `guests/consistency` is the worked example.
Its `src/lib.rs` compiles for the host as well as for the guest, because its
`Cargo.toml` makes `guest-sdk` a dependency of the guest target alone:

```toml
[target.'cfg(target_arch = "riscv32")'.dependencies]
guest-sdk.workspace = true
```

A host test can then call the library directly, and
`crates/emulator/tests/consistency.rs` does exactly that. It runs one input on
the host, under `qemu-riscv32` and on the emulator, and compares fd 1, the exit
status, and a panic's message, line and column. Copy its shape for your own
program: if the host and the guest disagree, the guest is what the proof will
be about.

Some things legitimately differ between a 64-bit machine and the guest, so keep
them out of anything you commit. **Two announce themselves and four do not**,
and that distinction is the one worth carrying, because a hazard that panics
costs you a minute and a hazard that quietly commits a different number can
reach a verifier:

- **`usize` arithmetic overflows at 2^32** — *loud*. Overflow checks are on in
  both profiles, so a product the host answers `Some` for panics on the guest
  alone, with a file and a line. Type a quantity that is not an index `u64`.
- **`as usize` on a wider value keeps the low 32 bits** — *silent*, and the
  worst of the set. Nothing panics and nothing warns; the value is simply wrong
  from there on. Write `usize::try_from(x)?` and treat a bare `as usize` on
  anything wider than a pointer as a defect.
- **`size_of` of anything holding a pointer or a `usize` differs** — *silent*.
  `Vec<u8>` is 12 bytes here and 24 on a 64-bit host; `&[u8]` is 8 and 16;
  `Box<u8>` is 4 and 8.
- **`core::hash` of anything holding a slice, a `String` or a `usize` differs**
  — *silent*, because `#[derive(Hash)]` writes lengths with `write_usize`, four
  bytes here and eight there. Use `core::hash` for lookup, never for output. A
  fingerprint that reaches fd 1 should come from a real hash over bytes you
  chose, which the consistency suite holds identical on all three executors.
- **NaN bits** — *silent*, and unreachable unless you use floats. Which NaN an
  operation produces is the platform's business: `0x7ff8…` from RISC-V's soft
  float and from AArch64, `0xfff8…` from x86-64. Only the raw bits differ —
  `NaN != NaN` and `{}` formatting agree everywhere — so it takes `to_bits()`
  on a NaN reaching fd 1 to bite you. The target has no FPU, so every `f64`
  operation is a software routine: a guest using floats pays for them in
  instruction count long before the NaN bits ever matter.
- **The heap never frees**, so the total you allocate over the run is the limit,
  not the peak (§3) — *loud*, `exit(71)`.
- **The stack has 8 MiB** reserved at the top of RAM — *silent* if you exceed
  it, and the one failure the SDK cannot catch for you.

`guests/consistency/src/hazards.rs` emits each of these on purpose, and its
`PLATFORM_DEPENDENT` table names them. The suite checks that the pointer-width
ones really do differ on a 64-bit host. §7a is the symptom-first version of this
list, for when something has already gone wrong.

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
`alloc` works but never reclaims. What runs a guest out of heap is therefore
the total it allocates over the run, not its peak. The top 8 MiB of RAM
(`constants::guest_memory::STACK_RESERVE`) belong to the stack. An allocation
that would reach into them, or above the live stack pointer, exits 71 rather
than returning null.

**Write for that, because it is the one platform property with no analogue on
your machine.** The budget is just under 248 MiB for a whole run — the RAM
window less the stack's reserve, less your code and static data — which is
generous until something allocates inside a loop, where a host's live footprint
stays flat and the guest's grows without bound:

```rust
use core::fmt::Write;   // `String` implements it, but it has to be in scope

// Costs ~32 bytes per row, forever. Two million rows is 64 MiB gone.
for row in rows {
    let key = format!("{}:{}", row.venue, row.symbol);
    out.push(lookup(&key));
}

// Costs one allocation in total.
let mut key = String::new();
for row in rows {
    key.clear();
    write!(key, "{}:{}", row.venue, row.symbol).expect("writing to a String");
    out.push(lookup(&key));
}
```

The habits that matter, in the order they pay: hoist a buffer out of the loop
and `clear()` it rather than building a new one; `Vec::with_capacity` when the
size is known, so growth does not allocate a fresh buffer per doubling and
abandon the old one; borrow `&str` and `&[T]` where you would have cloned; and
prefer writing into a caller's buffer over returning an owned value from a
function called in a loop. None of this is exotic — it is what a
performance-minded Rust author does anyway — but here it is the difference
between a guest that finishes and one that exits 71.

This is not a quirk of this VM. A bump allocator that never frees is what every
zkVM uses, for the same reason: the program runs once, commits its output, and
its whole address space is discarded, so a free list would be cost paid for
nothing.

Before S12 the ceiling was `__stack_top` itself, and running out of heap handed
out memory on top of live stack frames. `crates/emulator/tests/consistency.rs`
pins the fix. A stack deeper than 8 MiB can still run down into heap blocks
without any check noticing, but recursion that deep would overflow a native
main thread as well.

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

### Building at `--release`

Everything above builds the dev profile, which is what the committed fixtures
are and what the walkthrough checks. A guest also builds optimised:

```
cd guests/hello
cargo build --target riscv32imac-unknown-none-elf --release
```

The ELF lands beside the dev one, at
`guests/target/riscv32imac-unknown-none-elf/release/hello`.

Reach for it when you care about cost. Instruction count is what a zkVM pays
for, and `opt-level = 3` removes between a quarter and a half of the image:

```text
              dev     release
  fib        2186        1299     41% fewer
  echo       9881        6179     37% fewer
  rvc-dense  2277        1468     36% fewer
  amm        8227        6260     24% fewer
  orderbook 20223        8499     58% fewer
  vault     11904        8182     31% fewer
```

**Both profiles are pinned in `guests/Cargo.toml`, and the release one is not
cargo's default.** Cargo would turn `overflow-checks` off in release, and in a
guest that is a semantic change rather than a performance one:

```rust
let total = balance + deposit;      // balance = u32::MAX, deposit = 1
```

```text
  dev      panicked at src/main.rs: attempt to add with overflow, exit 101
  release  no trap, committed 00 00 00 00 on fd 1, exit 0
```

fd 1 is the committed public output, so with the defaults the optimisation level
would be part of the statement you prove. The pinned profile keeps
`overflow-checks` and `debug-assertions` on, so dev and release are the same
program at different optimisation levels, and CI runs the behaviour suite
against both to hold that. If you pin your own profiles in an out-of-tree
guest, copy those two lines.

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
ten committed guests on every CI run, and its ignored case relinks them from
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

**Execution.** `qemu-riscv32` was the only executor before S12; since S12
`crates/emulator` runs a guest too (`emulator::run`), and its trace is held to QEMU's
instruction by instruction. It is user-mode
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

## 7a. When it runs but does the wrong thing

§9 covers an ELF the loader refuses, which is always a malformed or mis-targeted
build. This section is the other failure: a guest that loads, runs, and is
wrong. **Start by running the same input through the library on the host (§2a)
and diffing fd 1.** Which side is wrong tells you which half of this table to
read.

Every exit code the SDK produces, none of which your program chooses:

| Exit | Constant | What happened |
| --- | --- | --- |
| 0 | — | `main` returned, or you called `exit(0)` |
| 70 | `EXIT_IO_ERROR` | an ecall the ABI guarantees failed. Under the zkVM this is a bug; by hand under QEMU it is usually fd 3 not being open (§3 rule 5) |
| 71 | `EXIT_OUT_OF_MEMORY` | the heap reached its ceiling. See below |
| 72 | `EXIT_PRECOMPILE_ERROR` | a precompile failed for a reason other than "not implemented". `poseidon2_permute` returning `false` is *not* this — that is the software-fallback path (§3 rule 4) |
| 101 | `EXIT_PANIC` | a Rust panic. The message, file, line and column go to fd 2 |

### It exits 71

The heap never frees, so the limit is **everything the run ever allocated added
up** — just under 248 MiB, the RAM window less the stack's 8 MiB reserve and
your image — not its high-water mark. A host profiler will show a flat few
hundred kilobytes and tell you nothing.

Look for allocation inside a loop: `format!`, `to_string()`, `to_owned()`,
`clone()`, `collect()` into a temporary, or a `Vec`/`String` built and dropped
per iteration. §3 has the rewrite. Multiply the per-iteration allocation by the
iteration count; if that product is in the hundreds of megabytes, that is your
answer. Growth counts too — a `Vec` pushed to without `with_capacity` abandons
each buffer as it doubles.

This is a clean stop, not corruption. Before S12 it was corruption: the
allocator would hand out blocks sitting on top of live stack frames, and safe
code writing into a `Vec` would rewrite its caller's locals and return address.
That is fixed and pinned by two probes in `guests/consistency`.

### It commits different bytes than the host

In order of how often it is actually the cause:

1. **`as usize` on a `u64`.** Keeps the low 32 bits here, all 64 on the host, in
   silence. Grep your guest for `as usize` and replace each with
   `usize::try_from(x)?`. This is the single highest-yield check on this page.
2. **A `core::hash` fingerprint reached fd 1.** `#[derive(Hash)]` writes slice
   and `String` lengths as `usize`, so every such hash differs by target. Move
   to a real hash over bytes you control.
3. **`size_of` of something holding a pointer** fed an offset, a capacity or a
   serialized length.
4. **Floats.** Only the bits of a NaN differ, so this needs `to_bits()` or a
   transmute on a NaN path. Rare, and a sign you should be using integers.

§2a is the full list with the reasoning; `hazards::PLATFORM_DEPENDENT` is the
machine-readable one.

### It panics on the guest but not on the host

Almost always `usize` arithmetic crossing 2^32, which is in range on a 64-bit
host and out of it here. Overflow checks are on in both profiles deliberately,
so this is the platform telling you loudly what `as usize` would have told you
never. Widen the variable to `u64` if it is a quantity; if it is genuinely an
index, the guest is right and the host was hiding a bug.

### It behaves impossibly — values change under it, or it crashes in `core`

Suspect **stack depth**. You get 8 MiB, the same as a native main thread, but
with no guard page: past its reserve the stack grows down into heap blocks and
nothing notices. Unbounded recursion on attacker-controlled nesting is the usual
cause, and a large local array (`let buf = [0u8; 4_000_000];`) is the other.
Carry an explicit depth counter and return an error past a limit — which is what
you would do in a server for the same reason.

This is the one hazard on this page the SDK cannot catch for you, and it is
recorded as an open item in `docs/handoff/S12-emulator.md`.

### It never finishes

An infinite loop is an infinite loop. The emulator's 38-bit clock stops it
eventually, but not within a useful wall-clock time, so a hung run reads as a
hung test rather than a failure. Bound your loops.

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

This is export-time failure, and every case is a malformed or mis-targeted ELF.
For a guest that loads and runs but misbehaves, §7a is the other table.

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

## 11. What the VM will prove: the decoded tables

The artifact is words. What a proof is about is those words decoded into per-family
tables, and the `tables` form of the same tool prints them:

```
cargo run --release -p artifact-dump -- tables guests/target/riscv32imac-unknown-none-elf/debug/hello
cargo run --release -p artifact-dump -- tables <elf> --ptau assets/ptau/ppot_0080_24.ptau
```

The page shows the `VmConfig` the preprocessor derived for your program — which circuit
families it needs, and how tall each is — and then every instruction with its mnemonic,
its decoded fields and the family that owns it. An instruction the VM does not support
stops the page with `Not all opcodes supported: pc=…` naming where it is, which is the
same refusal proving would give.

With `--ptau` it also prints the **program identity** at the default parameters: the
value a verifier would register for your program. It needs PSE's ceremony file (2^22
powers, and about a minute); `docs/handoff/S07-msm-srs-kzg.md` has the download. Two
things about it are worth knowing before you publish one. It is taken over the decoded
instructions and the `VmConfig` only — at this stage not over `.rodata`, `.data` or
the entry point — and it moves whenever the instructions do, including when a rebuild on
another machine embeds different paths. `crates/program/CLAUDE.md` is the full account.
