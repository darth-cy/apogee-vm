# Writing a guest program

From an empty crate to a proof: write a guest, build it, export and check its `ProgramImage`, see
what the VM will prove of it, and prove a run. Commands run from the repository root unless a step
changes directory.

## 1. Before you start

`rust-toolchain.toml` pins stable Rust 1.96.1 with `llvm-tools` and the target
`riscv32imac-unknown-none-elf`, whose `core` and `alloc` ship prebuilt; rustup applies it in every
directory below the root.

A guest is an Apogee-SDK program, not a Linux one: no file descriptors, streams, clock, entropy or
diagnostic output. Its public input, its journal and the prover's advice are memory, read and
written with ordinary loads and stores, and its only ecalls are `EXIT` and the delegation calls the
SDK makes for it (§3). Any other number answers `-ENOSYS` and leaves the run unprovable
([ecall-abi.md](spec/ecall-abi.md) §5).

## 2. Write the guest

A guest is a `no_std` binary crate in the `guests/` workspace. Create `guests/hello`:

```toml
# guests/hello/Cargo.toml
[package]
name = "hello"
version.workspace = true
edition.workspace = true
publish.workspace = true

[dependencies]
guest-sdk.workspace = true
```

```rust
// guests/hello/src/main.rs
#![no_std]
#![no_main]

guest_sdk::entry!(main);

fn main() {
    // The public input is memory: a slice, with no ecall and no cursor.
    guest_sdk::commit(guest_sdk::public_input());
}
```

and append it to the list in `guests/Cargo.toml`:

```toml
members = ["fib", "echo", "rvc-dense", "amm", "orderbook", "vault", "atomics", "opcodes", "heap", "addsub", "control", "alu", "mem", "shards", "keccak-test", "keccak-unused", "recursion-ops", "recursion-unused", "revm-block", "public-io", "mod-mul-ops", "sha256-ops", "ec-ops", "recursion", "hello"]
```

- `#![no_std]`: the target is bare metal. `extern crate alloc;` adds `Vec`, `Box` and `String`
  over the SDK's allocator; any dependency that builds for the target without `std` will do.
- `#![no_main]`, `entry!(main)`: crt0's `_start` sets `sp`, zeroes `.bss` and calls `main`, a
  wrapper the macro exports around your function. Returning is `exit(0)`; `guest_sdk::exit(code)`
  or a panic ends the run otherwise.

The guests in the tree are worked examples:

| guest | shows |
| --- | --- |
| `public-io` | the three regions, advice checked against the public input; start here |
| `fib` | the smallest SDK guest: a `u32` in, a `u32` out |
| `echo`, `heap` | the allocator: advice copied through heap buffers, `Vec` and `Box` churn |
| `amm`, `orderbook` | 128- and 256-bit integers with no heap; `BTreeMap`, sorting, a sorted order from advice checked |
| `vault`, `recursion-ops` | `crates/field` and `crates/transcript` in a guest, delegating with no shim named |
| `atomics`, `opcodes`, `rvc-dense` | the A extension from `core::sync::atomic`; every RV32IMAC instruction; RVC expansion |
| `addsub`, `control`, `alu`, `mem`, `shards` | assembly with its own `_start` and no SDK, exiting with its result; `shards` fills two `2^20` shards |
| `keccak-test`, `sha256-ops`, `mod-mul-ops`, `ec-ops` | `KECCAK_F`, `SHA256_COMP`, `MOD_MUL` and `EC_ADD`, each checked in the guest against independent values |
| `keccak-unused`, `recursion-unused` | shims linked and never called: families declared, zero shards |
| `revm-block` | revm, binaries `revm-block` and `revm-block-stateless` ([ethereum.md](spec/ethereum.md)) |
| `recursion` | the recursion verifiers, binaries `leaf` and `node` ([recursion.md](spec/recursion.md) §8.1) |

### 2.1 Run the same logic on the host

A guest prints nothing, so debug it on the host: put the program in a `#![no_std]` library from
bytes to bytes, keep `main.rs` to the regions, and make the SDK a guest-target dependency:

```toml
[target.'cfg(target_arch = "riscv32")'.dependencies]
guest-sdk.workspace = true
```

Host code depends on the library by path, as `crates/emulator` does on `guests/revm-block`, and
compares its output with the guest's journal (§7). On the guest `usize` is 32 bits: overflowing it
panics there alone, `x as usize` truncates silently, and `size_of` and `core::hash` of anything
holding a length differ, so keep them out of what you commit.

## 3. Input, advice, journal and delegations

A guest with a large input takes the bulk as advice, which the public input commits to, and checks
one against the other before anything derived from the advice reaches the journal:

```rust
fn main() {
    let want = guest_sdk::public_input(); // 32 bytes: keccak256 of the advice
    let data = guest_sdk::advice(); // the prover's bytes, bound by nothing
    if guest_sdk::keccak256(data).as_slice() != want {
        guest_sdk::exit(1); // refused before anything derived from it is committed
    }
    let sum = data.iter().fold(0u32, |s, b| s.wrapping_add(u32::from(*b)));
    guest_sdk::commit(&sum.to_le_bytes()); // the journal: what the proof publishes
}
```

| region | accessors | holds | bound by the proof |
| --- | --- | --- | --- |
| public input | `public_input()`, `read_input(buf)` | the statement's bytes, at most 16,380 | yes |
| advice | `advice()` | the prover's bytes, up to 2 GiB | no |
| journal | `commit(bytes)`, `journal()` | what the guest appended, at most 16,380 | its final contents |

- `read_input` copies and may return short; `advice()` on a run given no advice is the fatal
  `OutOfBounds`.
- `commit` appends and exits 70 rather than overflow: commit a growing output as a digest.
- Nothing is published at exit: a run that panics or exits nonzero has a verifying proof of what it
  committed, so a verifier reads the exit status.
- Checking the advice is the guest's job: committing a function of unchecked advice publishes what
  the prover chose ([public-values.md](spec/public-values.md) §6).

**Delegations.** `keccak256` is one: the sponge is guest code, and each keccak-f[1600] round an
`ecall` handing a frame of RAM words to the `KECCAK_F` circuit. A guest reaches them through
ordinary functions: `guest_sdk::keccak256`, `sha256`, `ec_add` and `ec_mul`; `field::Fr` arithmetic
and `transcript::poseidon2_permute`, which delegate on the guest target with nothing named; and
`k256`, `ark-ff` and `revm-precompile`, compiled from patched copies under `guests/vendor`.
[delegation.md](spec/delegation.md) §10 says which reaches what, and
[ecall-abi.md](spec/ecall-abi.md) §7 lists the SDK, raw frames included. Linking a shim declares
its family ([delegation.md](spec/delegation.md) §7): a family declared and never called proves zero
shards, and one called once proves a whole shard of its height, `2^18` rows for `KECCAK_F`.

## 4. Build it

From the guest's own directory, with no flag but the target:

```text
cd guests/hello
cargo build --target riscv32imac-unknown-none-elf
cd ../..
```

The ELF is `guests/target/riscv32imac-unknown-none-elf/debug/hello`, the guest workspace having one
target directory. `guests/.cargo/config.toml` adds `-T` of `crates/guest-sdk/link.ld`, the memory
map ([ecall-abi.md](spec/ecall-abi.md) §6), and `--no-relax`: relaxation rewrites instruction
sequences and moves every later address, which identity binds. It names no runner, as nothing
outside this VM maps the regions: §7 runs a guest.

`--release` builds `.../release/hello`. `guests/Cargo.toml` pins both profiles to one semantics:

| | dev | release |
| --- | --- | --- |
| `opt-level` | 0 | 3 |
| `debug-assertions` | on | on in the guest crate, off in its dependencies |
| `overflow-checks` | on | on |

Cargo's default release profile turns overflow checks off, which in a guest changes the statement:
`u32::MAX + 1` would commit `00000000` and exit 0 where the dev build panics. A dependency's debug
assertion checks that crate's own invariant, and a correct dependency computes the same without it.

Prove the release build. Every executed instruction is a proved row, and each family's code must
fit its decoded table (§8): `revm-block`'s debug image needs `2^22` rows a shard
(`revm_block::TRACE_HEIGHT_DEBUG`), its release image `2^20`. The identity you publish is the
release image's.

## 5. Export the artifact

```text
cargo run -p artifact-dump -- guests/target/riscv32imac-unknown-none-elf/debug/hello --out artifacts
```

This writes `artifacts/hello.img`, `postcard` over `ProgramImage`'s four fields with no header
([program.md](spec/program.md) §3), and `artifacts/hello.img.txt`, its report, and prints the entry,
the segment and instruction counts and the artifact's size and SHA-256. The tool first serializes
the image, reads it back through the validating reader and compares; on a difference, or an ELF the
loader refuses (§9), it writes nothing. The report is rendered from the value read back.

The `.img` is the program's static description, for keeping and diffing; nothing downstream needs
it, `host::setup` and the tools taking the ELF. Its SHA-256 pins bytes and is not the program
identity (§8).

The bytes reproduce on one machine, not across machines: the ELF embeds absolute paths in
panic-location strings — the toolchain's `core` sources, `crates/guest-sdk`, the cargo registry —
while the guest's own files appear relative to `guests/`. A build elsewhere is another image with
another identity, so what you register and hand on is a build's ELF, not a recipe.

## 6. Read the report

`hello.img.txt` opens with the artifact's and the source ELF's names, sizes and SHA-256s. Then:

| section | shows |
| --- | --- |
| `entry and memory` | the entry, `_start` at `0x00010000`; the RAM window; `slot_base` and the slot span, a slot a halfword up to the top of the highest executable segment |
| `segments` | address, end, `mem_len`, file bytes, zero fill and instructions of `.text`, `.rodata` if any, and one writable segment to `0x80000000` for `.data`, `.bss`, heap and stack; no permission bits |
| `instruction stream` | four- and two-byte instructions, mid-instruction and `not code` slots (§6a), summing to the slots |
| `symbols` | names by address from the ELF's symbol table, which the artifact does not carry |
| `listing` | per instruction: `address`, `len`, `in memory` (the file's bytes), `expanded` (the word the artifact carries), symbol |

`len` alone says whether the next pc is `pc + 2` or `pc + 4`: a compressed instruction keeps its
address and its two bytes ([program.md](spec/program.md) §2). For mnemonics, use §8's `tables` or
the pinned disassembler:

```text
"$(rustc --print sysroot)"/lib/rustlib/*/bin/llvm-objdump \
    --disassemble --no-print-imm-hex -M no-aliases <elf>
```

## 6a. The `not code` halfwords

From `amm`'s dev image:

```text
0x00010f94    2       952e  00b50533
0x00010f96    2       4108  00052503
0x00010f98    2       8502  00050067
---- not code: 0x00010f9a .. 0x00010f9c, 1 halfword ----
0x00010f9c    4   18412683  18412683
```

`c.add`, `c.lw`, `c.jr` jump through a table, and the next halfword is `0x0000`: LLVM proved the
switch's default unreachable, rustc lowers an unreachable block to the trap `unimp`, and with the C
extension that is `c.unimp`, the all-zero halfword, RVC's defined-illegal encoding. It abbreviates
no instruction, so the loader records a `NonInstruction` slot and resumes two bytes on
([program.md](spec/program.md) §2). No pc reaches it; one that did would stop the run with
`NotAnInstruction`. It is ordinary compiler output: the committed dev images of `amm`, `vault` and
`orderbook` carry 1, 2 and 16.

## 7. Check it

Build into a fresh target directory, export again and compare:

```text
cd guests/hello
CARGO_TARGET_DIR=/tmp/fresh cargo build --target riscv32imac-unknown-none-elf
cd ../..
cargo run -p artifact-dump -- /tmp/fresh/riscv32imac-unknown-none-elf/debug/hello --out /tmp/again
cmp artifacts/hello.img /tmp/again/hello.img
diff artifacts/hello.img.txt /tmp/again/hello.img.txt
```

The artifacts are identical, and the reports differ in the one line `source ELF`.
`tools/artifact-dump/tests/manual.rs` runs §4, §5 and this check over every guest with a committed
ELF, all but `revm-block` and `recursion`.

Then run it. `emulator::run` executes an image over a public input and advice, in host code:

```rust
let image = loader::load_elf(&std::fs::read(elf_path)?).expect("loads");
let io = emulator::GuestIo { input: b"hi".to_vec(), advice: Vec::new() };
let run = emulator::run(&image, &io).expect("no fatal error");
assert_eq!((run.exit_code, run.io.output), (0, b"hi".to_vec()));
```

`cargo run --release -p profiler -- elf <elf> --input <file> --advice <file>` does the same from the
command line, reporting the exit status, the journal's length and where the cycles went
([tools.md](tools.md) §2).

## 8. What the VM will prove

```text
cargo run --release -p artifact-dump -- tables <elf> [--ptau assets/ptau/ppot_0080_24.ptau]
```

This prints, at `ProgramParams::defaults()`, the `VmConfig` the image derives — each family's
height, live rows and decoded columns, a family without a table, such as a declared delegation,
claiming no pc — then each instruction's pc, `next_pc`, family, mnemonic and fields
([program.md](spec/program.md) §4–§7). With `--ptau` and the ceremony file ([srs.md](spec/srs.md)
§1) it prints the **program identity** at those parameters, the value a verifier registers from a
channel of its own ([program.md](spec/program.md) §8). It moves with any file byte, the entry and
any height, and so with the profile and the machine. Derivation refuses, naming the pc or size:

- `Not all opcodes supported: pc=…`: a word outside RV32IMA, such as a CSR access in assembly;
- `TableTooShort`: code past a family's reach, `pc ≤ 2h − 4`, which is 1.9375 MiB of code at `2^20`
  and 7.9375 MiB at `2^22` ([program.md](spec/program.md) §5);
- `ProgramTooLarge`, `ImageOutsideWindow`: an image over `bytecode_size_words`, 4 MiB by default,
  or past RAM window 0 ([program.md](spec/program.md) §7).

## 9. When it goes wrong

**An exit status the SDK chose** ([ecall-abi.md](spec/ecall-abi.md) §7):

| status | cause, and what to do |
| --- | --- |
| 70 | `commit` would pass 16,380 bytes: commit a digest |
| 71 | an allocation would end above `__stack_top − 8 MiB` or the live `sp`. Nothing is freed, so the run's total allocation must fit between the image and `0x7F80_0000`: reuse buffers across a loop, and size them with `with_capacity` |
| 72 | a delegation answered what its shim refuses: an error, or `-ENOSYS` after a multi-call operation's first call |
| 101 | a panic, which prints nothing: rerun the library on the host (§2.1) |

Nothing detects a stack grown past its 8 MiB into heap blocks, which then change under a deep
recursion.

**A fatal executor error**, with no exit status and no proof
([execution-trace.md](spec/execution-trace.md) §10): `OutOfBounds`, a null or wild pointer
(`[0, 0x8000)` is a hole) or advice read past what was supplied; `Misaligned`, a halfword or word
access through an unaligned pointer; `NotAnInstruction`, a jump to a pc holding none;
`DelegationFrame`, a raw frame its circuit cannot prove, such as an operand not below its modulus.

**A refused export**, a `loader::LoaderError` ([program.md](spec/program.md) §1):

| refusal | usual cause |
| --- | --- |
| `NotAnElf`, `Truncated` | not the guest's ELF: a `.d` file, a partial write |
| `NotRiscV`, `UnsupportedElfType`, `RelocatableElf`, `DynamicElf` | a host build, an object file, a PIE or dynamic build |
| `BadSegment`, `NoExecutableSegment`, `EntryNotAnInstruction` | an edited `link.ld`, or no `_start` linked |
| `RvcIllegal`, `InstructionTooLong`, `TextTruncated` | data in `.text`, such as a table in hand-written assembly; never the zero halfword (§6a) |

## 10. Prove it

```rust
let params = program::ProgramParams::defaults();
let ptau = std::path::Path::new("assets/ptau/ppot_0080_24.ptau");
let setup = host::setup(&elf, &params, srs::Srs::from_ptau(ptau, 22).expect("ceremony"))
    .expect("registers");
let proven = host::prove(&setup, &io, 4).expect("proves"); // at most 4 shards in flight
host::verify(&setup.vk, &proven.block).expect("verifies");
assert_eq!(setup.vk.identity.to_bytes(), registered); // from your own channel, never the proof
assert_eq!(proven.exit_code, 0);
```

The block's statement carries the public input, the journal and the exit status. The SRS needs as
many powers as the tallest height, `2^22` at the defaults ([srs.md](spec/srs.md) §1). A family with
rows costs at least a whole shard of its height, so a short run wastes less at smaller heights:
`2^20` is an instruction family's floor ([lookup.md](spec/lookup.md) §3), where
`host::fixture::revm_params` proves `revm-block`; each choice of heights is its own identity.
`bench prove` proves the `revm-block` binaries ([tools.md](tools.md) §1); measured costs are
[architecture.md](architecture.md) §7.
