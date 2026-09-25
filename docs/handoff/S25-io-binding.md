# S25 — Public values, private advice, and the I/O binding

**Branch** `s25-io-binding`. **Normative page: `docs/spec/public-values.md`.**

The stage closes the gap S10 opened and S14 named: a proof now binds what went into an
execution and what came out of it. It also withdraws the QEMU per-instruction oracle and
retires two stopgaps — the embedded-witness binary and `exit_with_public_words`.

---

## 0. What was wrong

`transcript::io_digest(input, output)` has been in the statement since S10 and absorbed at
G7 since S16, and until this stage **it bound nothing to the execution**. The bytes came
off fd 0 and fd 1, `read` and `write` are not provable ecalls, and nothing in any circuit
read either stream. `docs/spec/memory.md` §10 said so outright and described a future
design — the guest hashes both streams at exit and leaves the digest in `x24..x31` — which
this stage does **not** build.

The practical cost was visible at S24: `guests/revm-block` could not be proven at all. What
S24 proved was a second binary with the block witness baked into `.rodata`, so that program
identity bound it — which means a per-block witness is a per-block identity, and per-block
proving is impossible.

## 1. What it is now

Three kinds of memory, and they are not interchangeable:

```text
0x0000_8000  PUBLIC INPUT   1 KiB   the statement's own bytes      bound at init
0x0000_8400  PUBLIC OUTPUT  1 KiB   the journal                    bound at teardown
0x0001_0000  RAM                    image, heap, stack             the program's
0x8000_0000  ADVICE         2 GiB   prover-supplied witness        bound by nothing
```

The public windows sit in the hole below `RAM_ORIGIN` that `V[ram_live]` has always
masked, so they cost no existing row. All three regions are `address_space::RAM`, so **no
execution family's circuit changed**: what tells a public value from a heap word is which
family initializes the address, not a tag a load has to name.

The binding is the memory argument plus one comparison. The multiset already forces a
window's init column to be each address's first value and its teardown column to be its
last; `verify_shard_local` step 10c holds `PUBLIC_INPUT`'s `M[2]` to the verifier's own
multilinear extension of `public.input`, and `PUBLIC_OUTPUT`'s `M[1]` to `public.output`.
The journal's family is `ZERO_WINDOWS`' circuit **byte for byte**, so its init leaf is a
literal 0 and a prover has no column to pre-load the answer into — a structural guarantee
rather than a check that could be forgotten.

**It is the conventional design.** Jolt binds program I/O exactly this way: a fixed region
of ordinary memory below the DRAM origin, the input as the region's initial value and the
output as its final value, each against an extension the verifier computes itself, with
advice deliberately outside the checked mask. OpenVM gives public values an address space
of their own and decommits them from the final memory root. RISC Zero and SP1 take the
other road — the guest SHA-256s its own journal — and that is what the owner's brief ruled
out: it rests the output's soundness on the guest hashing honestly, costs a sponge over
the whole stream at exit, and makes a guest that panics after touching a stream unprovable.

### What it cost the protocol

| | |
| --- | --- |
| new families | 3 |
| new address spaces | 0 |
| new transcript messages, tags or challenges | **0** |
| new statement fields | **0** |
| changes to any execution family's circuit | **0** |
| enforcing gates added anywhere | **0** |
| new artifact constructors | 1, shared by two families |
| verifier work per proof | two 256-point multilinear evaluations |

`io_digest` is unchanged, in the position it has always had. The whole global transcript is
S16's G1–G11, untouched.

---

## 2. The frozen API

### `constants`

```rust
mod guest_memory {
    pub const PUBLIC_INPUT_ORIGIN: u32 = 0x0000_8000;
    pub const PUBLIC_OUTPUT_ORIGIN: u32 = 0x0000_8400;
    pub const PUBLIC_WINDOW_BYTES: u32 = 4 * family::PUBLIC_WINDOW_HEIGHT;   // 1024
    pub const PUBLIC_PAYLOAD_BYTES: u32 = PUBLIC_WINDOW_BYTES - 4;           // 1020
    pub const ADVICE_ORIGIN: u32 = 0x8000_0000;
    pub const ADVICE_WORDS: u32 = 1 << 29;
}
mod family {
    pub const PUBLIC_INPUT: u32 = 12;
    pub const PUBLIC_OUTPUT: u32 = 13;
    pub const ADVICE_WINDOWS: u32 = 14;
    pub const COUNT: u32 = 15;
    pub const PUBLIC_WINDOW_HEIGHT: u32 = 1 << 8;
    pub const PUBLIC_INPUT_WINDOW: u32 = 32;
    pub const PUBLIC_OUTPUT_WINDOW: u32 = 33;
}
mod ecall {
    pub const FD_STDIN: u32 = 0;    // was FD_PUBLIC_INPUT; the NUMBER is frozen, the name moved
    pub const FD_STDOUT: u32 = 1;   // was FD_PUBLIC_OUTPUT
}
```

### `constraints`

```rust
pub fn memory::value_window_artifact(trace_vars: u32) -> CircuitArtifact;
// M[0] teardown_ts, M[1] teardown_value, M[2] init_value, V[row]; two leaves, a product
// tree, no enforcing gate, no lookup, no channel, no setup column, degree 1 throughout.
// family_circuit: PUBLIC_INPUT and ADVICE_WINDOWS take it; PUBLIC_OUTPUT takes
// zero_window_artifact, byte for byte.
```

### `verifier-core`

```rust
pub fn public_io_words(bytes: &[u8]) -> Vec<u32>;   // the window: length word, LE payload, zero pad
pub fn advice_first_window(height: u32) -> u32;     // 2^29 / h
// window_height now requires all three window families at one height, both public
// families at PUBLIC_WINDOW_HEIGHT, and 4h >= PUBLIC_OUTPUT_ORIGIN + PUBLIC_WINDOW_BYTES.
// check_memory_windows adds: one shard each for the two public families, and
// advice_first_window(h) + k <= 2^30 / h.
// derive_global_phase refuses input or output longer than PUBLIC_PAYLOAD_BYTES (Statement).
// verify_shard_local gains step 10c, between 10a and 11, class MemoryArgument.
```

### `trace`

```rust
pub struct InitialMemory<'a> { pub image: &'a ProgramImage,
                               pub public_input: &'a [u8], pub advice: &'a [u8] }
impl InitialMemory<'_> { pub fn word(&self, addr: u32) -> u32; }
impl MemoryEventLog { pub fn self_check(&self, initial: &InitialMemory) -> Result<(), SelfCheckError>; }
pub fn in_ram(addr: u32) -> bool;         // [RAM_ORIGIN, ADVICE_ORIGIN)
pub fn addressable(addr: u32) -> bool;    // RAM, a public window, or the advice region
pub fn advice_region_words(advice: &[u8]) -> u64;   // 0 for empty; else 1 + ceil(len/4)
pub fn advice_word(advice: &[u8], index: u64) -> u32;
pub fn advice_window_count(advice: &[u8], height: u32) -> u32;
pub fn build_value_window_columns(log, initial: &[u32], ram_window, height)
    -> Vec<(PolyAddress, MultilinearPoly)>;
// TraceArchive::from_execution gains an `advice: Vec<u8>` argument, and the post-execution
// payload a seventh field. TraceArchive::advice() reads it back.
```

### `emulator`

```rust
pub struct GuestIo { pub input: Vec<u8>, pub advice: Vec<u8>,
                     pub stdin: Vec<u8>, pub hint: Vec<u8> }
pub struct Execution { .., pub io: IoStreams, pub stdout: Vec<u8>, pub stderr: Vec<u8> }
pub enum EmuError { .., PublicInputTooLong { len: usize }, JournalTooLong { len: u32 } }
```

**Four input fields, because there are four things, and what tells them apart is what
binds them**: `input` fills the public input window and the statement binds it; `advice`
fills the advice region and nothing binds it; `stdin` is fd 0 and `hint` is fd 3, and
neither is provable. `input` and `stdin` do **not** seed each other — they were one field
briefly and the coupling was wrong in both directions, capping an fd 0 stream at a public
window's 1,020 bytes for a sharing no guest can use, the windows being unmapped under
`qemu-riscv32` and `read` being unprovable here.

`Execution::io` is now the **public values** — `input` the window's payload, `output` the
journal — and `stdout` is the fd 1 compatibility stream. `run` and `trace_run` return
`Result`, the journal being read out of the window at exit and the public input's length
refused before the first cycle.

### `guest-sdk`

```rust
pub fn public_input() -> &'static [u8];      // no ecall
pub fn read_input(&mut [u8]) -> usize;       // the same, copied
pub fn commit(&[u8]);                        // append to the journal; no ecall
pub fn journal() -> &'static [u8];
pub fn advice() -> &'static [u8];            // nothing binds it

pub fn read_stdin(&mut [u8]) -> usize;       // fd 0 — compatibility, NOT provable
pub fn write_stdout(&[u8]);                  // fd 1 — compatibility, NOT provable
pub fn hint(&mut [u8]) -> usize;             // fd 3 — as before
pub fn log(&[u8]);                           // fd 2 — as before
```

**`exit_with_public_words` is deleted.** The journal is what it stood in for.

---

## 3. Artifacts

| Path | What |
| --- | --- |
| `docs/spec/public-values.md` | the normative page |
| `guests/public-io/` | the demonstration guest: public input in, advice checked against it, journal out. Issues no ecall but `EXIT` |
| `crates/loader/tests/vectors/public-io.elf` | its committed fixture |
| `crates/checker/tests/public_values.rs` | the proof-free half: the layout's injectivity, the prover/verifier layout seam, the journal's missing init column, and each statement rule's negative control. 12 tests, ordinary CI |
| `crates/prover/tests/public_io.rs` | the end-to-end half, `#[ignore]`d. 5 tests |
| `crates/emulator/tests/qemu_outputs.rs` | the narrowed QEMU oracle: exit status and fd 1, with a negative control |

Every committed guest ELF moved, `guest-sdk` having changed; `cargo run -p kat-gen` was run
and `crates/program/tests/vectors/identity.txt`, `crates/checker/tests/vectors/global_tape.txt`
and the emulator's revm vectors moved with them. **Every program's identity moved**, the
three families being in every `VmConfig` and `VM_CONFIG` listing the family set.

---

## 4. Deviations, and decisions taken

1. **Advice is not enforced read-only** (owner's decision). The brief describes advice as
   "read-only witness data". Enforcing that in-circuit needs a space selector on the load
   path of `mem_word`, `mem_subword` and `atomics` and a gate refusing a store there — a
   frame column and gates in three frozen families, and a manifest rewrite for each — and
   it buys no soundness, advice being unbound whether or not the guest writes it. Jolt's
   advice regions sit outside its checked mask for the same reason. Read-only is the
   guest's discipline, and `docs/spec/public-values.md` §6 is the whole of it.

2. **`prompts/00-master.md` was amended** (owner's decision). Two things there described
   the design this stage replaces: implementation rule 10's per-instruction QEMU oracle,
   and the frozen invariant "Binding public I/O is deferred: the guest will compute
   `io_digest` and leave it in `x24..x31`". Both were rewritten in place, each carrying a
   note of what changed and why. Nothing else in that file moved.

3. **The QEMU per-instruction oracle is withdrawn** (owner's instruction).
   `crates/emulator/src/qemu.rs` (535 lines) and `crates/emulator/tests/differential.rs`
   are deleted; `tests/qemu_outputs.rs` replaces them and compares the exit status and fd 1
   and nothing below that. The reasons, recorded where the invariant used to live: it was
   never the property this project needs — this VM is not a clone of QEMU and its internals
   exist for the witness and the proof — and since S23 it was not even true, a delegation
   ecall running natively here and taking the `-ENOSYS` software fallback under QEMU, so the
   two instruction streams differ *by design* and agree on the answer. `emulator_steps`'
   read-equals-fold self-check was checked for redundancy before deletion:
   `MemoryEventLog::self_check` covers it and more.

4. **`read` and `write` will not become provable ecalls.** They stay in the ABI, the
   executor still answers them, and `guest_sdk::read_stdin`/`write_stdout` say they are
   unprovable. An execution's public values are not a syscall's business.

5. **No advice means no advice region.** `advice_region_words(&[])` is 0, so a program that
   uses none pays no `ADVICE_WINDOWS` shard — the alternative charged every program in the
   repository one whole window at the window height to say it had none. The consequence is
   that `guest_sdk::advice()` on a run given no advice is a fatal `OutOfBounds`.

6. **The public window height is pinned in derivation and refused at decode.**
   `program::decode_program` writes `PUBLIC_WINDOW_HEIGHT` whatever `ProgramParams` says, so
   "every family at `h`" keeps meaning every family whose height is a choice;
   `verifier_core::window_height`, which runs inside `VmConfig::from_bytes`, refuses any
   other. The check that matters is the one on bytes a verifier was handed.

## 5. Known limits, and what a later stage owes

- **1,020 payload bytes per public window.** Deliberate: public values are what a verifier
  reads. `guests/revm-block`'s output commitment is 122 bytes for the synthetic block, but
  it carries per-transaction fields, so a **real** block's commitment will outgrow the
  window. The fix is the guest's, not the VM's — commit a digest, or a header — and it is
  the shape `docs/spec/public-values.md` §9 already recommends. The windows can also grow
  inside the hole, 64 KiB being free, at one more `HEIGHT_MENU` entry and a longer
  multilinear evaluation.
- **A panicking guest is provable only if its panic handler writes nothing.** The journal
  survives a panic — it is memory — but `guest_sdk`'s handler writes the message to fd 2,
  and `write` is not provable. Making diagnostics provable is a separate change.
- **Nothing orders the journal's writes.** The proof binds the window's final contents;
  `commit`'s length word is what gives the bytes an order, and it is a guest-side variable.
- **Transfer cycles still exist in the trace model** and are still refused by the prover.
  Nothing in the provable path produces one now, so they could be deleted — but fd 2
  diagnostics still use them, and that deletion belongs with the panic-provability change.

## 6. What was run

Above the line, all green:

```
cargo fmt --all -- --check                      (and the three out-of-workspace manifests)
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p prover --all-targets --features metrics -- -D warnings
(cd crates/guest-sdk && cargo clippy --target riscv32imac-unknown-none-elf -- -D warnings)
(cd guests && cargo clippy --bins -- -D warnings)
cargo test --workspace
cargo test -p prover --features metrics --test metrics
cargo build -p field -p constants ... --target riscv32imac-unknown-none-elf
cargo run -p kat-gen                            (and -- guests, on this machine)
git diff --exit-code -- <every vectors directory>
```

<!-- FILL: the deferred batch's timings and peaks, measured in one run at the end of the
     progression, per the owner's S20 instruction. -->
