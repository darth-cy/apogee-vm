# Writing a guest program

From an empty crate to a proof: write a guest, build it, export and check its `ProgramImage`, see
what the VM will prove of it, and prove a run. Commands run from the repository root unless a step
changes directory.

## 1. Before you start

`rust-toolchain.toml` pins stable Rust 1.96.1 with `llvm-tools` and the target
`riscv64imac-unknown-none-elf`, whose `core` and `alloc` ship prebuilt; rustup applies it in every
directory below the root.

A guest is an Apogee-SDK program, not a Linux one: no file descriptors, streams, clock, entropy or
diagnostic output. Its public input, its journal and the prover's advice are memory, read and
written with ordinary loads and stores, and its only ecalls are `EXIT` and the four precompiles the
SDK calls (§3.1). Any other number answers `-ENOSYS` and leaves the run unprovable
([ecall-abi.md](spec/ecall-abi.md) §4).

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
members = ["fib", "echo", "rvc-dense", "amm", "orderbook", "atomics", "opcodes", "heap", "addsub", "control", "alu", "mem", "shards", "public-io", "precompiles", "marketplace", "amazon", "hello"]
```

- `#![no_std]`: the target is bare metal. `extern crate alloc;` adds `Vec`, `Box` and `String`
  over the SDK's allocator; any dependency that builds for the target without `std` will do.
- `#![no_main]`, `entry!(main)`: crt0's `_start` sets `sp`, zeroes `.bss`, runs any static
  initializers and calls `main`, a wrapper the macro exports around your function. Returning is `exit(0)`; `guest_sdk::exit(code)`
  or a panic ends the run otherwise.

The guests in the tree are worked examples:

| guest | shows |
| --- | --- |
| `public-io` | the three regions, advice checked against the public input; start here |
| `fib` | the smallest SDK guest: a `u32` in, a `u32` out |
| `echo`, `heap` | the allocator: advice copied through heap buffers, `Vec` and `Box` churn |
| `amm`, `orderbook` | 128- and 256-bit integers with no heap; `BTreeMap`, sorting, a sorted order from advice checked |
| `marketplace`, `amazon` | a database a proof follows by digest, one table and two (§3.3); requests signed with Falcon-512 (§3.1) |
| `atomics`, `opcodes`, `rvc-dense` | the A extension from `core::sync::atomic`; every RV64IMAC instruction; RVC expansion |
| `addsub`, `control`, `alu`, `mem`, `shards` | assembly with its own `_start` and no SDK, exiting with its result; `shards` fills two `2^20` shards |
| `cpp-primes` | a C++ guest, built by CMake against the C/C++ SDK (§11) |

### 2.1 Run the same logic on the host

A guest prints nothing, so debug it on the host: put the program in a `#![no_std]` library from
bytes to bytes, keep `main.rs` to the regions, and make the SDK a guest-target dependency:

```toml
[target.'cfg(target_arch = "riscv64")'.dependencies]
guest-sdk.workspace = true
```

Host code depends on the library by path and compares its output with the guest's journal (§7).
`usize` is 64 bits on the guest as on a 64-bit host, but no guest address reaches `2^32`
([ecall-abi.md](spec/ecall-abi.md) §5): keep pointer values out of what you commit.

## 3. Input, advice and journal

A guest with a large input takes the bulk as advice, which the public input commits to, and checks
one against the other before anything derived from the advice reaches the journal:

```rust
fn main() {
    let want = guest_sdk::public_input(); // 32 bytes: a digest of the advice
    let data = guest_sdk::advice(); // the prover's bytes, bound by nothing
    if digest(data).as_slice() != want {
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

`digest` is a collision-resistant hash: a Merkle root of `guest_sdk::poseidon2_compress`, say
(§3.1). [ecall-abi.md](spec/ecall-abi.md) §6 lists the SDK.

### 3.1 Precompiles and `U256`

Four operations are not RV64IMAC code but a circuit each, which a guest reaches through the SDK
([precompiles.md](spec/precompiles.md)): the Poseidon2-A64-C5 permutation, the 256-bit `mul_div`
that a token balance's arithmetic is built on, a Merkle path's root and Falcon-512's lattice check.

```rust
use guest_sdk::{falcon512::PublicKey, merkle_root, poseidon2_compress, Digest, U256};

let leaf = poseidon2_compress(&left, &right); // a node over two Digests, each lane below p
let root = merkle_root(slot, &leaf, &advice[at..at + 64 * 20]); // a 20-level path, read in place
let share = U256::from(amount).mul_div(U256::from(total), U256::from(reserve)); // Option<U256>
let key = PublicKey::decode(key_bytes).expect("a key"); // Falcon-512's 897 bytes, v1.2
let signed = key.verify(&request, sig); // a 666-byte signature of the request's bytes
```

- `U256` is four `u64` limbs, least significant first, with `from_be_bytes` for an EVM word. Its
  operators panic on overflow and on a zero divisor; `checked_*` and `overflowing_*` do not.
- Division and `mul_div` are one precompile call each; addition, comparison and multiplication are
  a few instructions a limb. `mul_div` is `None` for a zero divisor or a quotient past `2^256`.
- A `Digest`'s lanes are each below `p`: `Digest::new` refuses any other, as a lane `x + p` would be
  a second encoding of the node `x` opens. Decode every digest the guest compares or publishes from
  advice or input through it; a node `poseidon2_compress` or `merkle_root` returns is one already.
- `merkle_root(slot, &leaf, siblings)` is the fold of `poseidon2_compress` up a path of 16 to 32
  siblings, 64 bytes each, in one call: the depth is `siblings.len() / 64`, the node goes on the left
  where the slot's bit is 0, and each sibling lane is read mod `p`, so a path needs no decoding. It
  costs a level row and sixteen round rows a level and no guest cycles; `Digest::bytes(&path)`
  passes a path the guest holds itself.
- `falcon512::PublicKey::decode(bytes)` reads a Falcon-512 public key, v1.2 of the specification,
  and `key.verify(msg, sig, context)` is whether `sig` signs `msg` under it and the application's
  `context`, at most 255 bytes, a malformed signature `false`: the lattice check is the Falcon-512
  call, and HashToPoint, a Poseidon2 sponge of the key digest K, the salt, the context and the
  message ([precompiles.md](spec/precompiles.md) §7.7), is Poseidon2 calls. A standard Falcon-512
  signature does not verify; `tools/falcon512` signs under this HashToPoint. Decoding computes K
  from the key's bytes and HashToPoint's per-key prefix from K, once, ≈10.7K cycles; verifying a
  signature of a 92-byte message under a 25-byte context continues from there, ≈17.7K.
  `key.key_digest()` is K and `key.address()` the key's address, K's first 32 bytes, which names
  an account; `falcon512::key_digest(bytes)` and `falcon512::address(bytes)` are any bytes', and
  `falcon512::s1_norm` the lattice check alone, for a guest with encodings of its own.
- A precompile's frame is the guest's own memory below the advice region, which the SDK's calls
  always are: advice is copied in before `poseidon2_permute` hashes it, and a frame reaching the
  advice is the fatal `OutOfBounds`. A path's siblings and `s1_norm`'s arrays are not a frame:
  `merkle_root` and `s1_norm` read an advised path or array where it lies.
- A guest that links a precompile pays one shard of each family it declares, at `2^16` rows: worth
  it once the call replaces more instructions than that ([circuits.md](spec/circuits.md) §1).
- `guests/marketplace` is the worked example of a table a proof follows by its root: a listings
  table of `2^20` slots as a Poseidon2 Merkle tree, the root before a batch in the public input, a
  Merkle proof in the advice for each run of operations on one listing, checked by `merkle_root`
  where it lies before it is used, and the root after the batch in the journal. Each listing's price is in its own currency, an
  ERC-20 contract's address or zero for the native one, and the journal tallies each currency's
  volume and fees apart.

### 3.2 Fewer cycles

Cutting a guest's cycles has more than one strategy, and two are in use:

- **A precompile module.** The VM proves a hot operation in a circuit of its own, which the guest
  calls instead of running it (§3.1).
- **The input's format.** Whoever builds the input, a sequencer say, can shape it so the guest does
  less, and the guest presumes that shape rather than making it. `guests/marketplace` opens one
  Merkle proof for each run of consecutive operations on one listing and writes one root back,
  however long the run, so a batch with each listing's operations gathered is one proof a listing.
  The order is the sequencer's policy and becomes part of the batch: the guest proves the order it
  is given and never sorts. Any order is valid input, at a proof a run, and another order can be
  another result. `guests/amazon`'s advice holds each record its batch reads once, its users by
  address and its listings by slot, each ascending, so its batch runs in memory and a record costs
  one opening and at most one write-back however its requests interleave: there the order costs
  nothing (§3.3).

### 3.3 A database's state

A business guest keeps a database the proof follows by digest, and every Apogee guest program
keeps it the same way from here on. This is the common convention for an on-chain database.

- **Two kinds of record.** A *state* record is a current value that persists from batch to batch:
  an account's balance, a listing, an open position. An *action* record is an event that changes
  state: a purchase, a transfer, a new listing.
- **Each state table is a tree.** Each persistent table of state records is a fixed-depth Merkle
  tree of its own, 16 to 32 levels: a record's slot is its key, its leaf a digest of the record's
  encoding, an empty slot the empty record's, and every node `poseidon2_compress` of its children,
  so `merkle_root` opens a record by its path from the advice and writes it back along the same
  path (§3.1).
- **The state is one digest.** The global state hash, the snapshot, is the hash of the tables' roots
  concatenated in the schema's fixed order, absorbed one root at a time:
  `compress(… compress(compress(root_1, root_2), root_3) …, root_k)`; a guest with one table
  publishes its root. A statement carries the snapshot before its batch in the public input and the
  snapshot after it in the journal.
- **Actions stay off-chain.** Proving is what costs, so action records are not in the snapshot. They
  are the batch itself, the input a sequencer orders (§3.2), and once proved they are kept in an
  ordinary database for data availability: whoever holds them and the snapshot before a batch can
  rebuild the state after it.

`guests/marketplace` is the one-table case: its listings are state records under one root, which is
its snapshot, and its operations are actions; its journal's tallies summarize the actions it
proved, which no snapshot holds.

`guests/amazon` is the two-table case, its users and its listings two tables of `2^20` slots and
its snapshot `compress(users_root, listings_root)`, and it opens each record once: its actions are
purchases, each a 92-byte request its buyer signed with Falcon-512 (§3.1) under the context
`apogee/amazon/purchase/v1`, settled against a working set in memory, so a seller may spend later
in a batch what it earned earlier in it. A user is named by its key's address: its record holds
the address, a request names its buyer by it and a listing its seller, and the key advised beside
the record must have that address, computed from the same bytes the user's signatures are
verified under. The signatures are advice, so none decides an outcome: an outcome that turned on
one would publish what the prover chose (§3), a valid request advised a bad signature and
rejected. A request is rejected only for its market, its buyer or its nonce, which the public
input and the snapshot hold, and one past those checks carries a signature that verifies under its
buyer's key, or the batch is malformed. The sequencer verifies the signatures before it batches
the requests and drops a request whose signature does not verify, as a rollup's block producer
does. The advice holds every record the batch reads, each once, the users ascending by
address, each with its slot; after the batch each is verified once and, where it changed, written
back once, its path under its table's root as the writes before it left it, and no record is
opened per purchase. Until the users table is keyed by address it is assumed to hold each address
at most once, and a request from an address the advice does not hold is a malformed batch, as
nothing proves an address absent.

## 4. Build it

From the guest's own directory, with no flag but the target:

```text
cd guests/hello
cargo build --target riscv64imac-unknown-none-elf
cd ../..
```

The ELF is `guests/target/riscv64imac-unknown-none-elf/debug/hello`, the guest workspace having one
target directory. `guests/.cargo/config.toml` adds `-T` of `crates/guest-sdk/apogee.ld`, the memory
map ([ecall-abi.md](spec/ecall-abi.md) §5), and `--no-relax`: relaxation rewrites instruction
sequences and moves every later address, which identity binds. It names no runner, as nothing
outside this VM maps the regions: §7 runs a guest.

`--release` builds `.../release/hello`. `guests/Cargo.toml` pins both profiles to one semantics:

| | dev | release |
| --- | --- | --- |
| `opt-level` | 0 | 3 |
| `debug-assertions` | on | on |
| `overflow-checks` | on | on |

Cargo's default release profile turns overflow checks off, which in a guest changes the statement:
`u32::MAX + 1` would commit `00000000` and exit 0 where the dev build panics.

Prove the release build. Every executed instruction is a proved row, and each family's code must
fit its decoded table (§8). The identity you publish is the release image's.

## 5. Export the artifact

```text
cargo run -p artifact-dump -- guests/target/riscv64imac-unknown-none-elf/debug/hello --out artifacts
```

This writes `artifacts/hello.img`, `postcard` over `ProgramImage`'s five fields with no header
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
`NotAnInstruction`. It is ordinary compiler output: the committed dev images of `amm` and
`orderbook` carry 1 and 16.

## 7. Check it

Build into a fresh target directory, export again and compare:

```text
cd guests/hello
CARGO_TARGET_DIR=/tmp/fresh cargo build --target riscv64imac-unknown-none-elf
cd ../..
cargo run -p artifact-dump -- /tmp/fresh/riscv64imac-unknown-none-elf/debug/hello --out /tmp/again
cmp artifacts/hello.img /tmp/again/hello.img
diff artifacts/hello.img.txt /tmp/again/hello.img.txt
```

The artifacts are identical, and the reports differ in the one line `source ELF`.
`tools/artifact-dump/tests/manual.rs` runs §4, §5 and this check over every guest.

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
cargo run --release -p artifact-dump -- tables <elf>
```

This prints, at `ProgramParams::defaults()`, the `VmConfig` the image derives — each family's
height, live rows and decoded columns, a window family claiming no pc — then each instruction's
pc, `next_pc`, family, mnemonic and fields ([program.md](spec/program.md) §4–§7), and the
**program identity** at those parameters, the value a verifier registers from a channel of its own
([program.md](spec/program.md) §8): it moves with the entry, the families the code needs, any
height and every byte of the code and the image. Derivation refuses, naming the pc or size:

- `Not all opcodes supported: pc=…`: a word outside RV64IMA, such as a CSR access in assembly;
- `TableTooShort`: code past a family's reach, `pc ≤ 2h − 4`, which is 1.9375 MiB of code at `2^20`
  and 7.9375 MiB at `2^22` ([program.md](spec/program.md) §5);
- `ProgramTooLarge`, `ImageOutsideWindow`: an image over `bytecode_size_words`, 4 MiB by default,
  or past RAM window 0 ([program.md](spec/program.md) §7).

## 9. When it goes wrong

**An exit status the SDK chose** ([ecall-abi.md](spec/ecall-abi.md) §6):

| status | cause, and what to do |
| --- | --- |
| 70 | `commit` would pass 16,380 bytes: commit a digest |
| 71 | an allocation would end above `__stack_top − 8 MiB` or the live `sp`. Nothing is freed, so the run's total allocation must fit between the image and `0x7F80_0000`: reuse buffers across a loop, and size them with `with_capacity` |
| 101 | a panic, which prints nothing: rerun the library on the host (§2.1) |

Nothing detects a stack grown past its 8 MiB into heap blocks, which then change under a deep
call chain.

**A fatal executor error**, with no exit status and no proof
([execution-trace.md](spec/execution-trace.md) §10): `OutOfBounds`, a null or wild pointer
(`[0, 0x8000)` is a hole) or advice read past what was supplied; `Misaligned`, a halfword, word or
doubleword access through an unaligned pointer; `NotAnInstruction`, a jump to a pc holding none.

**A refused export**, a `loader::LoaderError` ([program.md](spec/program.md) §1):

| refusal | usual cause |
| --- | --- |
| `NotAnElf`, `Truncated` | not the guest's ELF: a `.d` file, a partial write |
| `NotRiscV`, `UnsupportedElfType`, `RelocatableElf`, `DynamicElf` | a host build, an object file, a PIE or dynamic build |
| `BadSegment`, `NoExecutableSegment`, `EntryNotAnInstruction` | an edited `apogee.ld`, or no `_start` linked |
| `RvcIllegal`, `InstructionTooLong`, `TextTruncated` | data in `.text`, such as a table in hand-written assembly; never the zero halfword (§6a) |

## 10. Prove it

```rust
let params = program::ProgramParams::defaults();
let setup = host::setup(&elf, &params).expect("registers");
let proven = host::prove(&setup, &io, host::DEFAULT_MAX_IN_FLIGHT).expect("proves"); // 8 shards in flight
host::verify(&setup.vk, &proven.block).expect("verifies");
assert_eq!(setup.vk.identity.to_bytes(), registered); // from your own channel, never the proof
assert_eq!(proven.exit_code, 0);
```

The block's statement carries the public input, the journal and the exit status. A family with
rows costs at least a whole shard of its height, so a short run wastes less at smaller heights:
`2^20` is an instruction family's floor
([lookup.md](spec/lookup.md) §3), and each choice of heights is its own identity. A shard's cost is
[architecture.md](architecture.md) §7.

## 11. A guest in C or C++

A guest need not be Rust. The C/C++ SDK, four files published with each release as
`apogee-guest-sdk.tar.gz`, builds one with standard Clang, LLD and CMake and no Rust tooling:

| file | what |
| --- | --- |
| `include/apogee_guest.h` | the C ABI: public input, advice, journal, exit ([ecall-abi.md](spec/ecall-abi.md) §7) |
| `lib/libapogee_guest.a` | startup and that ABI: `crates/guest-sdk` built as a static library |
| `lib/apogee.ld` | the memory map ([ecall-abi.md](spec/ecall-abi.md) §5) |
| `cmake/apogee-rv64.cmake` | the toolchain file: rv64imac/lp64, freestanding, the other three wired in |

A guest defines `int main(void)`, whose return value is the exit status:

```cpp
// main.cpp
#include <apogee_guest.h>

int main() {
    size_t len = 0;
    const uint8_t *input = apogee_public_input(&len);
    uint64_t sum = 0;
    for (size_t i = 0; i < len; ++i) {
        sum += input[i];
    }
    apogee_commit(&sum, sizeof sum);
    return 0;
}
```

```cmake
# CMakeLists.txt
cmake_minimum_required(VERSION 3.20)
project(hello CXX)
add_executable(hello main.cpp)
```

```text
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=<sdk>/cmake/apogee-rv64.cmake
cmake --build build
```

`build/hello` is a static RV64IMAC/LP64 ELF, and §5–§10 apply to it unchanged. The toolchain file
finds `clang`, `clang++` and `ld.lld` on `PATH`, and Homebrew's keg-only LLVM on macOS, whose
system clang has no RISC-V backend: `apt install clang lld cmake` or `brew install llvm lld cmake`.
It compiles freestanding — no exceptions, RTTI, C++ standard library or allocator, the compiler's
own C headers (`stdint.h`, `stddef.h`) — with `-mcmodel=medany`, code and data anywhere below
`2^31`, and links with `--no-relax` (§4). Those flags are the compilers' own arguments and the end
of every link line, so a project's or the command line's `CMAKE_<LANG>_FLAGS` and
`CMAKE_EXE_LINKER_FLAGS` add to them rather than replacing them, and the SDK may sit under a path
with spaces.

Globals are ordinary. Initialized, zero-initialized and small-data globals are where `apogee.ld`
puts them; C++ dynamic initializers and `__attribute__((constructor))` functions run before
`main`, prioritised ones first; and static objects' destructors run when `main` returns, the
latest constructed first, then `__attribute__((destructor))` functions. `apogee_exit` ends the run
without them, as C's `_Exit` does. A guest with no destructor runs no instruction for them, nor
does one whose only registration is in code `--gc-sections` discards.

Building against this repository instead of a release: `cargo rustc --lib --release --crate-type
staticlib --target riscv64imac-unknown-none-elf` in `crates/guest-sdk` builds the library, and
`-DAPOGEE_GUEST_LIB=…`, `-DAPOGEE_LINKER_SCRIPT=…` and `-DAPOGEE_INCLUDE_DIR=…` point the toolchain
file, and every configure check it runs, at the tree's pieces. `test_support::guest_elf` builds
`guests/cpp-primes` that way.
