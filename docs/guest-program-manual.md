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
  computed over the decoded per-family tables, the `VmConfig`, the entry point
  and the image's words; it is a different value, in a different field, for a
  different purpose.
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
| `crates/guest-sdk` | `entry!`, the I/O surface, the allocator, the panic handler, `link.ld` |
| `guests/.cargo/config.toml` | the target and the pinned linker flags |
| `crates/loader` | `load_elf`, `ProgramImage` — the thing being exported |
| `tools/artifact-dump` | the exporter |

`docs/spec/ecall-abi.md` is the normative document for the ABI and the memory
map, and `docs/spec/public-values.md` for the I/O model. Where this manual and
those documents disagree, they are right.

### The one thing to know before you write a line

**An Apogee guest is an Apogee-SDK program, not a generic Linux/POSIX RISC-V
executable.** It has no file descriptors, no streams, no I/O syscall and no
diagnostic output, and there is no host convention it is trying to match. The
supported interface is three regions of *memory*, reached with ordinary loads
and stores:

| | who chooses it | what it is for |
| --- | --- | --- |
| **public input** | the statement | the verifier-known bytes this run is about — at most 1,020 |
| **advice** | the prover | the bulk, bound by nothing, which your guest must check |
| **journal** (public output) | your guest | what the proof publishes — at most 1,020 |

A proof binds the first and the third and says nothing whatever about the
second. That is the whole model; §3 is the API and `docs/spec/public-values.md`
is normative. If you have written for another zkVM, the thing to unlearn is the
stream: there is no cursor to advance and no descriptor to write to, and nothing
your guest does makes a value public except storing it in the journal window.

---

## 2. Write the guest

A guest is an ordinary `no_std` binary crate that lives in the `guests/`
workspace. Three files, one of which already exists.

`hello` below is the guest this manual builds; you are creating it now. The
repository ships twenty-one, and every command here works on those too with the
name changed. They are worth reading before you write your own, because between them
they cover most of what a guest can do:

| Guest | What it is, and what it shows you |
| --- | --- |
| `fib` | the smallest real guest: read a `u32`, commit a `u32` |
| `echo` | the allocator's fixture: the advice region echoed into the journal through a heap buffer, plus the Poseidon2 delegation. Almost nothing else in `guests/` needs `alloc`, so without it the bump allocator would be dead-stripped out of every small binary and the largest `unsafe` surface in the workspace would run nowhere |
| `rvc-dense` | hand-written assembly and the compressed-instruction table; a loader fixture more than a program |
| `amm` | a constant-product market maker: exact 128- and 256-bit arithmetic, `mul_div`, integer `sqrt`, and no heap at all |
| `orderbook` | a uniform-price auction: `Vec`, `BTreeMap`, sorting, and the reference demonstration of **advise-then-verify** — a claimed sorted permutation taken from advice and checked against the public input before a single advised byte reaches the auction |
| `vault` | Merkle-gated withdrawals over Poseidon2: `crates/field` and `crates/transcript` running inside the proof, and the deepest call chain in `guests/` |
| `atomics` | every A-extension instruction as the compiler emits it, from `core::sync::atomic` on one hart; the fixture for the atomics circuit family |
| `opcodes` | every RV32IMAC instruction in hand-written assembly at its edge cases, each result checked by the guest itself; its public input is a mode word selecting the `ebreak` and misaligned-access runs, each of which is a fatal guest error and commits nothing |
| `heap` | `Vec` and `Box` churned through the bump allocator, so the heap's traffic is in the trace |
| `addsub` | S16's tiny guest, the first program proven end to end: a straight run of `add`, `sub`, `addi`, `lui` and `auipc` in both lengths, a `fence`, and an exit whose status, 42, is its result. It is hand-written assembly with no `guest-sdk` under it, one of the two guests that do not use `guest_sdk::entry!` — its own `_start` is the whole program, because crt0's `.bss` loop and its call to `main` are branches, stores and jumps, which S16 has no circuit for — so read it as a proof fixture, not a pattern |
| `control` | S17's guest, proven end to end the same way: the twelve jumps, branches and comparisons of the `JUMP_BRANCH_SLT` family at their edge cases — full-width and mixed-sign orderings, `slti`/`sltiu` against −1, `x0` as a destination, a loop closed by a backward branch, calls and returns in both lengths, and a `jalr` whose `rs1 + imm` has bit 0 set — each checked by the guest itself, exiting with the number of checks, 16. Hand-written assembly with no `guest-sdk`, for `addsub`'s reason: its only instructions are the two families S17 proves |
| `alu` | S18's guest, proven end to end the same way: the twelve shifts and bitwise operations of the `SHIFT_BITWISE` family and the eight M operations of `MUL_DIV`, at the edge cases the stage names — shamt 0, 1 and 31, `rs2 = 32` and 33 for the shift amount's truncation, `sra` of a negative operand, all four sign quadrants of each multiply and each division, `−2^31 × −2^31`, the asymmetric `mulhsu` corner, division by zero for all four, and the one signed overflow — each checked by the guest itself, exiting with the number of checks, 96. Hand-written assembly with no `guest-sdk`, for `addsub`'s reason: its only instructions are the four families S18 proves |
| `mem` | S19's guest, proven end to end the same way: `lw` and `sw` of the `MEM_WORD` family, the six sub-word loads and stores of `MEM_SUBWORD` at every legal byte and halfword offset, and the eleven instructions of `ATOMICS`, at the cases the stage names — a negative byte and a negative halfword sign-extended, `sb` and `sh` truncating a source whose high bytes are set and leaving the rest of the word alone, `amoadd` overflowing `2^32`, two consecutive AMOs to one address, all four min/max at `0x7fffffff` against `0x80000000`, an `lr.w`/`sc.w` pair, and `lw x0` and `amoadd.w x0` — each checked by the guest itself, exiting with the number of checks, 50. Hand-written assembly with no `guest-sdk`, for `addsub`'s reason. It is also the first guest that writes near the top of RAM as well as inside window 0, so its statement is the first with a `ZERO_WINDOWS` shard |
| `shards` | S20's guest, and the only one written for its *size*: a counted loop whose body is 64 unrolled `add`s, so `ADD_SUB_LUI_AUIPC` runs 1,064,970 cycles — past `2^20`, the smallest height a family carrying a timestamp gap obligation can have — and one execution becomes **two shards of one family**, which is S20's stage gate. `JUMP_BRANCH_SLT` runs 16,386 and fits one shard; nothing touches RAM, so `ZERO_WINDOWS` proves zero shards and the block carries a family with a count of 0. It exits with the number of checks, 2. Hand-written assembly with no `guest-sdk`, for `addsub`'s reason, and a loop rather than a straight line because a family's height is both its shard height and its decoded table's row count: 2^20 four-byte instructions would need a 2^22 table, which is a 2^22 shard, which is one shard again |
| `keccak-test` | S21's guest, and the first that calls a **delegation**: `guest_sdk::keccak256` over six inputs — empty, one byte, one short of the 136-byte rate, exactly the rate, one past it, and 400 bytes — each checked in the guest against a pinned digest, exiting with the number of checks, 6. Ten keccak-f[1600] permutations in all, which since S26d is **240 invocations** — one round a call, 24 a permutation — and one `2^18` `KECCAK_F` shard holds with room to spare. Here the delegation ecall runs the permutation the `KECCAK_F` circuit proves and the invocations reach that family's trace; on an executor with no such circuit the same ecall answers `-ENOSYS` and the SDK's software permutation runs, and the digests are identical either way (§3 rule 5) |
| `keccak-unused` | the other half of that story, and the guest to read when you want to know what *linking* a delegation costs: it links `keccak256` behind a `core::hint::black_box` branch the optimiser cannot fold away, and never calls it. The shim is reachable, so its declaration record is in the image, so `KECCAK_F` is in the `VmConfig` — and the run invokes it zero times, so the execution proves zero shards of it. A guest that links no shim declares nothing at all (`docs/spec/delegation.md` §7). It exits 7 |
| `recursion-ops` | S23's guest, and the one to read when you want to know what a delegation costs a *caller*: it does ordinary `field::Fr` arithmetic and calls `transcript::poseidon2_permute`, and names no shim at all. The guest-target backends inside those two crates route every multiply, add and inverse through the `FR_ARITH` delegation and the permutation through the `POSEIDON2` one, so a guest that does field work is a guest whose `VmConfig` holds both families. The fallback is each crate's own software path, which is why the delegated path and the fallback cannot disagree: they are the same code. It exits with the number of checks, 9 |
| `recursion-unused` | `keccak-unused`'s counterpart for S23: it links both backends behind a `core::hint::black_box` branch the optimiser cannot fold away and reaches neither, so both families are in its `VmConfig` and the execution proves zero shards of each. It exits 11 |
| `public-io` | **the guest to read first**, and the whole I/O model in one small program: it issues no ecall but `EXIT`. Its public input is a length and a checksum, its advice is the bulk, and it commits to the journal only after checking the advice against the public input — which is the whole of what a guest owes for reading advice nothing binds (`docs/spec/public-values.md` §6). The checksum is position-dependent on purpose, so a permuted witness is a different answer. Exit 60, 61 or 62 name which half failed |
| `mod-mul-ops` | the guest for the `MOD_MUL` delegation, and the one to read for a delegation reached **three** different ways. It calls `guest_sdk::recursion::mod_mul` **by name** over frames it writes itself, once per selector, so all four of the circuit's moduli cross the frame; and it uses `k256`'s group and scalar arithmetic and `ark-bn254`'s two fields, which name **no** shim at all and reach the delegation through `guests/vendor/k256`'s and `guests/vendor/ark-ff`'s patched multiplies. **Its software path is run, not reserved**, and that is the thing to copy: §3 rule 5 requires a delegation's caller to have one, every selectable modulus here is 256 bits, so the fallback is a schoolbook long division of the guest's own — and rather than leave forty lines nothing ever executes, it computes every by-name call both ways and compares, which makes the fallback a differential oracle against `emulator::mod_mul_frame` instead of dead weight. Its `k256` half is the only test of that patch's `pack` and `unpack` — a field element is ten 26-bit limbs and the frame carries eight 32-bit ones — and its expectations there are absolute, the compressed SEC1 encodings of `G`, `2G`, `3G` and `7G`, because an identity-only test passes under a multiply that is wrong the same way everywhere. **Nothing inside it can see whether a seam is live**, a delegated multiply and a software one agreeing on the value; what sees that is the invocation count, pinned in `crates/emulator/tests/guests.rs`. It exits with the number of checks, 28 |
| `sha256-ops` | the guest for the `SHA256_COMP` delegation, and the one to read for **a delegation that is a *piece* of a function rather than the function**. The circuit is one compression of one 64-byte block; the Merkle-Damgård padding and the block loop are the caller's, and they live in `guest_sdk::sha256` behind the same signature the software path has — which is `keccak256`'s shape, and the reason a guest never chooses a path and cannot tell which ran. It checks the frame ABI by name against FIPS 180-4's own `"abc"` vector — one padded block, so the compressed state *is* the published digest — and then the digest surface at seven message **lengths**, chosen because what can go wrong above the compression is the padding: 55 is the last that pads into one block and 56 the first that needs two. Every one of those is checked twice, against a published digest and against `sha2`, an unpatched crates.io implementation and the only one in the comparison that is not this repository's. It exits with the number of checks, 12 |
| `ec-ops` | the guest for the `EC_ADD` delegation, and the one to read for **a delegation whose one call is three ecalls**. A complete point addition is three invocations in group order, and two transposed is not a refusal anywhere — it is a different point, computed from lanes whose previous contents were zero — so the order is not left to a caller: `guest_sdk::recursion::ec_add_complete` walks it. The guest runs its own Renes–Costello–Batina Algorithm 7 over its own eight-limb long division on **every** delegated addition and compares limb for limb, which it can do because the circuit computes that same formula over that same representation; then it checks the point against `k256` and `ark-bn254` by **cross-multiplication** — `X₃·1 = x·Z₃` — so no modular inverse runs in the guest and neither side has to pick a projective representative. All four completeness cases are covered: `P + P`, `P + O`, `O + O` and `P + (−P)`. It exits with the number of checks, 20 |
| `revm-block` | S24's guest, and the first with a crates.io dependency: [revm](https://github.com/bluealloy/revm) executing a block over a synthetic pre-state, `no_std` and `default-features = false`. Read it for three things a workload guest needs and the others do not. **A library plus two thin binaries**, the pattern of §2a, so the host can run the same source as the native oracle. **A hash hook**: `alloy-primitives`' `native-keccak` feature turns every `keccak256` in the image — revm's `KECCAK256` opcode, a contract's code hash, the guest's own commitments — into an `extern "C"` call the guest implements as `guest_sdk::keccak256`, which is how a dependency that has never heard of this VM ends up using its delegation. **Two binaries for one program**: `revm-block` reads its witness out of the **advice** region and publishes its output commitment to the **journal**, which is the one a mini-block proof is about; `revm-block-stateless` (S25) is the whole block transition — system calls, transactions, withdrawals — with the pre-state authenticated against the parent's state root, the post-state root recomputed and checked against the header's, which arrives as **public input**, and a fixed 148-byte journal naming both roots. **They are separate binaries on purpose** and have separate program identities: they publish different journals, and a verifier holding one should not have to ask which of two meanings it has. There used to be a third, the same computation over fd 0 and fd 1 for an executor that mapped neither region; it is deleted with the syscall it used. It is also the only guest with no committed ELF: 2.2 MB at `--release` is not a fixture worth keeping, and its suites build it from source |

If you are looking for a pattern to copy, **`public-io` is the one to start
with** — it is the input, the advice and the journal in twenty lines — then
`amm` for arithmetic and framing, `orderbook` for anything that takes prover
advice, `vault` for anything that hashes, `keccak-test` for calling a
delegation, and `revm-block` for a real workload with a library behind it.

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
    // The public input is memory, not a stream: no ecall, no cursor.
    let input = guest_sdk::public_input();
    guest_sdk::commit(input);
}
```

That is the whole I/O surface: no ecall but the one `entry!` makes on the way
out. §3 is the rest of it.

**`guests/Cargo.toml`** — add the crate to the member list:

```toml
members = ["fib", "echo", "rvc-dense", "amm", "orderbook", "vault", "atomics", "opcodes", "heap", "addsub", "control", "alu", "mem", "shards", "keccak-test", "keccak-unused", "recursion-ops", "recursion-unused", "revm-block", "public-io", "mod-mul-ops", "sha256-ops", "ec-ops", "hello"]
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
the program in a `#![no_std]` library and keep `main.rs` to reading the input
and publishing what the library returns — which is also what lets one library
carry more than one `main`, each publishing a different journal.
`guests/revm-block` is the worked example. Its `src/lib.rs` compiles for the
host as well as for the guest, because its `Cargo.toml` makes `guest-sdk` a
dependency of the guest target alone:

```toml
[target.'cfg(target_arch = "riscv32")'.dependencies]
guest-sdk.workspace = true
```

A host test can then call the library directly, which is exactly how
`crates/emulator/tests/revm.rs` runs native revm as the oracle its guest is held
to. Copy that shape for your own program: run the same bytes through the library
on the host and through the guest on the emulator, and compare the journals. If
the two disagree, the guest is what the proof will be about.

**A guest has no diagnostic output**, so this is not a convenience — it is the
debugging strategy. A panic writes nothing anywhere; the only things that leave
an execution are the journal and the exit status. So the library on the host is
where you put a `dbg!`, and the guest is where you confirm the answer did not
move.

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
  fingerprint that reaches the journal should come from a real hash over bytes
  you chose — `guest_sdk::keccak256`, or `crates/transcript`'s Poseidon2 — each
  of which is the same function on every target.
- **NaN bits** — *silent*, and unreachable unless you use floats. Which NaN an
  operation produces is the platform's business: `0x7ff8…` from RISC-V's soft
  float and from AArch64, `0xfff8…` from x86-64. Only the raw bits differ —
  `NaN != NaN` and `{}` formatting agree everywhere — so it takes `to_bits()`
  on a NaN reaching the journal to bite you. The target has no FPU, so every `f64`
  operation is a software routine: a guest using floats pays for them in
  instruction count long before the NaN bits ever matter.
- **The heap never frees**, so the total you allocate over the run is the limit,
  not the peak (§3) — *loud*, `exit(71)`.
- **The stack has 8 MiB** reserved at the top of RAM — *silent* if you exceed
  it, and the one failure the SDK cannot catch for you.

§7a is the symptom-first version of this list, for when something has already
gone wrong.

---

## 3. The I/O surface

There is one, it is small, and it issues no ecall:

```rust
pub fn public_input() -> &'static [u8];        // the public input window's payload
pub fn read_input(buf: &mut [u8]) -> usize;    // the same, copied into your buffer
pub fn commit(bytes: &[u8]);                   // append to the journal
pub fn journal() -> &'static [u8];             // the journal so far
pub fn advice() -> &'static [u8];              // prover-chosen; nothing binds it
pub fn exit(code: i32) -> !;

pub fn keccak256(input: &[u8]) -> [u8; 32];               // delegated, or the same in software
pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool;   // false on -ENOSYS
pub mod recursion { /* the poseidon2, fr_arith and mod_mul frames */ }
```

**None of the first five is a system call.** The public input, the journal and
the advice region are three fixed regions of memory that the executor lays out
before your program starts; `public_input` is a bounds-checked slice over one of
them and `commit` is a run of stores into another. There is no cursor, no
buffering, no descriptor and nothing that can fail for an I/O reason. What a
proof binds is the input window's contents and the journal's **final** contents,
and neither binding asks anything of you — no hash at exit, no register
convention, not even that you read your input.
`docs/spec/public-values.md` is the normative page.

That is the whole list. There is no second surface, no compatibility path and no
`println!`: **a guest has no diagnostic output at all.** A panic exits 101
silently, and the only bytes leaving an execution are the journal's.

Six rules worth having in front of you while you write:

1. **`read_input` may return short.** It fills your buffer or stops at the end
   of the input, and returns which. If you need an exact length, check the
   count — a guest that proceeds on a partly-filled buffer proves something
   about zeroes. `public_input()` and `journal()` return slices and copy
   nothing, so they cannot be short.
2. **Advice binds nothing, and this is the rule that matters most.** The prover
   chooses every byte `advice()` returns and may choose them differently on
   every run. If advice can change what you `commit`, and you have not checked
   it against something a proof *does* bind — the public input, or a hash the
   public input carries — then your proof is worth nothing, because the prover
   picked the output. Advice is a shortcut to a value you then verify, never an
   input in its own right, and the obligation is yours: the VM cannot discharge
   it. Advice is also the *only* place a large input can go, the two public
   windows being 1,020 bytes each, so any real workload meets this rule.
3. **`commit` refuses rather than truncates.** A journal that would not fit its
   1,020-byte window exits `EXIT_IO_ERROR` instead of being cut short, because
   you can read `journal()` back and must not see one you did not write. Nothing
   orders the writes, either: the proof binds the window's final contents, and
   `commit`'s length word is what gives the bytes an order.
4. **Anything that would return host data is refused.** `getrandom`,
   `clock_gettime`, `gettimeofday`, and whatever `HashMap` reaches for to seed
   its `RandomState` all answer `-ENOSYS`. That is deliberate: each is
   nondeterministic advice wearing the costume of a library call. If you want
   such a value, take it from advice, where it is visibly yours to authenticate.
5. **A delegation is a function call, and its caller owes a software path.**
   `keccak256` is the worked example: the sponge and the padding run in guest
   code and one ecall covers each keccak-f[1600] block, which this VM answers
   out of the circuit the `KECCAK_F` family proves. An executor without that
   circuit answers `-ENOSYS` and the SDK runs the permutation in software
   instead, and the two paths produce the same digest — so for `keccak256` there
   is no fallback for *you* to write. `poseidon2_permute` is the raw form and
   hands you the choice: it returns `false` on exactly `-ENOSYS`, and you must
   have a software path and take it on `false`. Any *other* failure exits
   nonzero rather than falling back silently, because "this VM does not have
   this yet" and "this call went wrong" are worth telling apart. Calling a
   delegation is also what **declares** its family: the shim carries a record
   the preprocessor scans your image for, kept exactly when the shim is
   reachable, so a guest that never calls `keccak256` declares nothing and a
   guest that links it and never calls it declares a family it proves zero
   shards of. `docs/spec/delegation.md` is the normative page;
   `guests/keccak-test` and `guests/keccak-unused` are the two halves worked
   out, and `guests/mod-mul-ops` is what it looks like when the software path is
   expensive enough to shape the design.
6. **There is nowhere to print.** No `log`, no stderr, no tracing hook. Debug on
   the host through the library of §2a, and use the exit status as your one
   channel: every hand-written fixture in `guests/` exits with the number of
   checks that passed, so one wrong value is a different number.

`guests/orderbook` is the worked example of rule 2. It takes a sorted
permutation of its orders from the advice region — sorting costs `O(n log n)`
and checking that a claimed permutation is sorted costs `O(n)`, so the advice is
worth having — and then verifies it three ways against the batch, which is
public input, before a single advised byte reaches the auction. If any check
fails it sorts the batch itself. **The two paths commit identical bytes**, which
is the whole point: not even a flag saying the advice verified reaches the
journal, because such a flag would be a published bit the prover chooses. And
since there is nowhere else for it to go, which path ran is not recorded at all.

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
out memory on top of live stack frames — safe code writing into a `Vec` rewrote
its caller's locals and return address. The allocator now refuses such a block
instead, and `guests/heap` is the fixture that puts real allocator traffic in a
trace. A stack deeper than 8 MiB can still run down into heap blocks without any
check noticing, but recursion that deep would overflow a native main thread as
well.

---

## 4. Build it

From the guest's own directory, with no flags beyond the target:

```
cd guests/hello
cargo build --target riscv32imac-unknown-none-elf
```

Everything else comes from `guests/.cargo/config.toml`: the target, and the two
linker flags that matter — `-T../crates/guest-sdk/link.ld` for the frozen memory
map, and `--no-relax`, because linker relaxation rewrites instruction sequences
and shifts every later address, and S11's program identity is a function of
those addresses.

There is deliberately **no `runner`**, so `cargo run` on a guest has nothing to
run it with. An Apogee guest's input, advice and journal are windows of guest
memory this VM lays out, and nothing outside the VM maps them; the executor is
`crates/emulator`.

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
  release  no trap, published 00 00 00 00, exit 0
```

What a guest publishes is what a proof is about, so with cargo's defaults the
optimisation level would be part of the statement you prove. The pinned profile keeps
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
RAM window        0x00010000 .. 0x80000000    constants::guest_memory
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
  2  0x00013000  0x80000000   0x7ffed000             0   2147405824             0
```

Three segments is what the frozen `link.ld` produces for every guest in this
repository that has read-only data: `.text` (read + execute), `.rodata` (read
only), and one writable segment holding `.data`, `.bss` and the reservation above
them, running to the top of RAM. A guest with no `.rodata` has two, as `addsub` and
`control`, `alu`, `mem` and `shards` do, each a page of hand-written instructions and nothing
else. The
writable segment's `file bytes` is zero whenever `.data` is empty, which is the
common case — `hello`, `fib`, `echo` and `rvc-dense` are all like that, so the
whole third segment is zero fill. It is declared because **the program headers
are the image's own account of itself**: a header saying the program's writable
memory ends at `.bss`, when the heap and the stack live above it, is wrong about
the program, whatever reads it. Each section is page-aligned for the same
reason — a `PT_LOAD` states its permissions over the pages it covers, so two
segments on one page state two different things about the same bytes.
`docs/spec/ecall-abi.md` §7.1 is normative, and `crates/loader/tests/layout.rs`
enforces it.

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
0x00010000    4   7fff0117  7fff0117  _start
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

**A well-formed image.** `crates/loader` reads `p_vaddr` and `p_memsz` into a
flat window where every address exists by construction, and it would accept an
ELF whose headers describe a different program from the one inside it. Nothing
else would: the headers are what `llvm-readobj`, a disassembler, a debugger and
any loader that is not this one read, and they are entitled to be true. S10
shipped headers that were not, twice, and nothing inside the VM noticed
(`docs/spec/ecall-abi.md` §7.1).

The two rules are properties of `link.ld`, which every guest links against
unmodified, so a guest that changes only its own source has the segment shape
the committed guests have. `crates/loader/tests/layout.rs` checks those over the
committed guests on every CI run, and its ignored case relinks them from
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
  LOAD           0x004000 0x00013000 0x00013000 0x00000 0x7ffed000 RW  0x1000
```

Three things to see there, and each was a real failure:

1. every `VirtAddr` is page-aligned, and `Offset ≡ VirtAddr (mod 0x1000)` — a
   mapping runs from `page_down(offset)` to `page_down(vaddr)`, so anything else
   describes the wrong bytes at that address;
2. no two `LOAD`s share a page, because a page can only carry one set of
   permissions — an unaligned `.rodata` is a claim that the tail of `.text` is
   not executable;
3. the segment with `MemSiz` above `FileSiz` is the one marked `RW`, and it
   reaches `0x80000000`. Zero fill inside a read-only segment would be a claim
   that the image writes to memory it declared read-only, and the span up to
   `__stack_top` is the heap and the stack: undeclared, the headers say the
   program's writable memory ends at `.bss` and its very first stack push is
   outside every segment it names.

**Execution.** The executor is `crates/emulator` — `emulator::run` for a plain
run and `emulator::trace_run` for one that produces a trace — and it is the only
one. It needs no cross-emulator and no Linux: it is an ordinary Rust crate in
this workspace, so `cargo test` runs your guest wherever you are.

Give it the public input and the advice the run is about, and read back the exit
status and the journal. `crates/emulator/tests/guests.rs` is the shape to copy;
it runs every committed guest and checks each one's journal against arithmetic
redone on the host, which is §2a's strategy as a test.

A guest built on another machine is **not** the same bytes as one built here —
rustc embeds absolute paths in `core`'s panic-location strings and stable Rust
cannot remap them, so two builds differ in size as well as content. What does
*not* differ is your own crate's panic locations, which are relative to the
crate root, or anything a guest computes.

---

## 7a. When it runs but does the wrong thing

§9 covers an ELF the loader refuses, which is always a malformed or mis-targeted
build. This section is the other failure: a guest that loads, runs, and is
wrong. **Start by running the same input through the library on the host (§2a)
and diffing the journal.** Which side is wrong tells you which half of this
table to read — and it is the only diagnostic you get, since a guest prints
nothing.

Every exit code the SDK produces, none of which your program chooses:

| Exit | Constant | What happened |
| --- | --- | --- |
| 0 | — | `main` returned, or you called `exit(0)` |
| 70 | `EXIT_IO_ERROR` | `commit` was handed more bytes than the journal window holds. It refuses rather than truncating (§3 rule 3) |
| 71 | `EXIT_OUT_OF_MEMORY` | the heap reached its ceiling. See below |
| 72 | `EXIT_PRECOMPILE_ERROR` | a delegation answered something other than success or `-ENOSYS`. `poseidon2_permute` returning `false` is *not* this — that is the software-fallback path (§3 rule 5) |
| 101 | `EXIT_PANIC` | a Rust panic. **Silently**: there is no message, no file and no line, because there is nowhere for them to go. What you have is the status and whatever the guest had already committed — the journal is memory, so a panicking run still published it |

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
The allocator now refuses such a block instead, against both halves of the
ceiling — the stack's 8 MiB reserve and the live `sp`.

### It commits different bytes than the host

In order of how often it is actually the cause:

1. **`as usize` on a `u64`.** Keeps the low 32 bits here, all 64 on the host, in
   silence. Grep your guest for `as usize` and replace each with
   `usize::try_from(x)?`. This is the single highest-yield check on this page.
2. **A `core::hash` fingerprint reached the journal.** `#[derive(Hash)]` writes
   slice and `String` lengths as `usize`, so every such hash differs by target.
   Move to a real hash over bytes you control — `guest_sdk::keccak256` is right
   there, and it is the same function on every target.
3. **`size_of` of something holding a pointer** fed an offset, a capacity or a
   serialized length.
4. **Floats.** Only the bits of a NaN differ, so this needs `to_bits()` or a
   transmute on a NaN path. Rare, and a sign you should be using integers.

§2a is the full list with the reasoning.

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
- **The ecall numbers**, in `constants::ecall`, with `docs/spec/ecall-abi.md` as
  the table. Numbers are append-only forever, and a retired number stays burned
  rather than being freed for something else.
- **The memory map and the linker symbols** — `__bss_start`, `__bss_end`,
  `__heap_start`, `__stack_top` — and the segment-layout rules in
  `docs/spec/ecall-abi.md` §7.1.
- **`--no-relax`**, and the pinned toolchain in `rust-toolchain.toml`.
- **The public value windows** — their addresses, their 1 KiB size and the
  length word at word 0 — and the advice region above RAM
  (`docs/spec/public-values.md`). `io_digest`, the digest the statement absorbs
  over those two byte strings, is frozen too.

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
instructions, the `VmConfig`, the entry point and every file-backed byte of the image —
`.text`, `.rodata` and `.data` — which must all lie below `4h`, `h` being the init
families' height; and it moves whenever any of those do, including when a rebuild on
another machine embeds different paths. `crates/program/CLAUDE.md` is the full account.
