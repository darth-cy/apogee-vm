# S24 — revm guest, synthetic-state block

`guests/revm-block` runs [revm](https://github.com/bluealloy/revm) 42.0.1, `no_std` and
`default-features = false`, over a synthetic pre-state with one funded account, and
executes two transactions: a plain ether transfer and a call into a deployed counter
contract that writes a storage slot and emits a log. It is the first rung of the
normative testing ladder, and the first guest in this repository with a crates.io
dependency.

**Every acceptance item passes, including the deferred proof.** The one deviation is
that acceptance 6, 7 and 8 are delivered on a *second binary* of the same program,
because a guest that touches fd 0 or fd 1 cannot be proved by this repository today.
That is a hard blocker, not a shortcut, and §1 is the whole account.

---

## 1. The I/O blocker, and what was done about it

### What is blocked

The stage's must-be-exact 1 requires every input byte to arrive by `read` on fd 0 and
every output byte to leave by `commit` on fd 1. Acceptance 6 requires that guest to be
proved to a `BlockProof` that verifies.

**A guest that touches fd 0 or fd 1 cannot be proved by this repository today.** Two
independent refusals, both deliberate:

- `crates/constraints/src/add_sub.rs`'s `ecall_is_exit` gate is
  `is_exit·(a7 − EXIT) = 0` with `is_exit = is_ecall − Σ is_deleg_t`, so every ecall row
  is held to `a7 = 93` or a registered delegation number. A `read` row carries `a7 = 63`
  and satisfies no arm.
- `crates/prover/src/fill.rs:498` refuses a transfer cycle by name — *"cycle N is an
  ecall's transfer cycle, and S16 proves EXIT alone"* — and `:519` refuses any other
  ecall number.

This is not an oversight anyone can patch. The root `CLAUDE.md` names it — *"EXIT and a
registered delegation number are the provable ecalls… The I/O-binding stage owes `read`
and `write`"* — and `prompts/00-master.md`'s frozen invariants say *"Binding public I/O
is deferred"*. The stage prompt's Deliver section contains no circuit work at all, and
the work is not a gate or two:

- `read` and `write` need ecall selectors and number gates — mechanical, six gates.
- A **transfer cycle** is a row of the same pc with no `rs1`, `rs2` or `rd` query and one
  RAM query at slot 3 (`docs/spec/execution-trace.md` §6). Its query mask therefore
  cannot come from the row kind, which is the rule every family follows today
  (`docs/spec/memory.md` §2.1); it needs a committed `is_transfer` boolean and a new mask
  rule.
- And the load-bearing part: **nothing ties a transfer row to the ecall row it belongs
  to.** A transfer row that is permitted but not constrained against its ecall's `a1`
  (the buffer) and `a2`/`a0` (the length), in ascending word order, can write **any value
  to any RAM word**. That is not a weak I/O binding; it is a broken machine. Binding it
  needs cross-row constraints, which this arithmetization has nowhere today — rows in a
  shard are independent, and the only cross-row structure is the global memory multiset.

Doing that inside S24 would also change the add/sub circuit, which moves **every**
verifying key's bytes, every pinned identity, the constraint manifest, and re-runs every
deferred suite.

### What was done

Raised with the owner before any code, with three options. **The owner chose "report
blocked + embedded-witness proof".**

So `guests/revm-block` ships **two binaries over one library**:

| Binary | Input | Output | Proved? |
| --- | --- | --- | --- |
| `revm-block` | fd 0, one `read` | fd 1, one `commit` | no — the ecalls are not provable |
| `revm-block-embedded` | a `.rodata` constant | `keccak256` of the commitment, in `x24..x31` | **yes** |

The second is the one acceptance 6, 7 and 8 are delivered on, and it binds the same two
streams by the two means the machine already has:

- **The input** is `include_bytes!` of the committed witness. Program identity commits
  the image window word by word (`docs/spec/memory.md` §6.2), so a changed witness is a
  changed identity — which a verifier takes from a channel the prover does not control.
- **The output** is `keccak256` of the output commitment, left in `x24..x31` by
  `guest_sdk::exit_with_public_words`. The statement carries the final value of every
  register, so those eight words are public, and the memory argument binds them to the
  execution that produced them.

That arrangement is not invented here: `prompts/00-master.md`'s frozen invariants
describe exactly it — *"Binding public I/O is deferred: the guest will compute
`io_digest` and leave it in its final registers (x24..x31)."*

**What it is not.** It is not a substitute for I/O binding, and it does not scale: a
per-block witness in the image means a per-block identity, which is wrong for real
blocks. It is a demonstration that the *workload* proves, on the machine as it stands.
S25 or a dedicated I/O-binding stage owes the real thing.

### The deviation, stated plainly

Must-be-exact 1 holds for `revm-block`, which is the normative guest and the one every
differential runs. It does **not** hold for `revm-block-embedded`, which exists only
because the proof needs it. Master rule 13's other direction: the stage requirement could
not be met, so it is recorded rather than quietly dropped.

One caveat on the output binding, since it is easy to overstate: the eight words are
whatever the program left in `x24..x31`, and only the success path puts the digest there.
A run that exits 61 or 62 goes through `guest_sdk::exit`, which touches no register but
`a0`, so the statement then carries whatever the code generator last left in them. The
reading is "exit status 0 **and** these eight words", never the words alone, and
`crates/prover/tests/revm.rs` asserts the status beside them.

---

## 2. What shipped

### `guests/revm-block`

A library plus two thin binaries, the `guests/consistency` pattern: `src/lib.rs` is the
program and compiles for the host too, so `crates/emulator/tests/revm.rs` calls it
directly as the native-revm oracle and `tools/kat-gen` builds the committed witness
against it. `guest-sdk` and `alloy-primitives` are dependencies of the `riscv32` target
alone.

Frozen public API:

```rust
// the witness, docs/spec/revm-block.md §1
pub type Address20 = [u8; 20];
pub type Word32 = [u8; 32];                       // big-endian: an EVM word, not an Fr
pub struct BlockWitness   { pub env: BlockEnvWitness, pub accounts: Vec<AccountWitness>,
                            pub txs: Vec<TxWitness>, pub stateless: Option<Vec<u8>> }
pub struct BlockEnvWitness { pub chain_id: u64, pub spec_id: u8, pub number: Word32,
                            pub beneficiary: Address20, pub timestamp: Word32,
                            pub gas_limit: u64, pub basefee: u64, pub difficulty: Word32,
                            pub prevrandao: Option<Word32>, pub excess_blob_gas: Option<u64>,
                            pub slot_num: u64 }
pub struct AccountWitness { pub address: Address20, pub nonce: u64, pub balance: Word32,
                            pub code: Vec<u8>, pub slots: Vec<(Word32, Word32)> }
pub struct TxWitness      { pub caller: Address20, pub to: Option<Address20>, pub value: Word32,
                            pub data: Vec<u8>, pub gas_limit: u64, pub gas_price: u128,
                            pub gas_priority_fee: Option<u128>, pub nonce: u64,
                            pub chain_id: Option<u64>,
                            pub access_list: Vec<(Address20, Vec<Word32>)> }
pub enum WitnessError { Malformed, AccountsNotSorted { at }, SlotsNotSorted { account, at },
                        UnknownSpec { spec_id } }
impl BlockWitness { pub fn encode(&self) -> Vec<u8>;
                    pub fn decode(bytes: &[u8]) -> Result<BlockWitness, WitnessError>; }
impl BlockEnvWitness { pub fn spec(&self) -> Option<SpecId>; }
pub use revm::primitives::hardfork::SpecId;

// the program, docs/spec/revm-block.md §2
pub fn run(witness: &BlockWitness) -> Result<Vec<u8>, String>;   // fd 1's bytes
pub fn keccak(bytes: &[u8]) -> Word32;                           // the image's one keccak
pub fn output_digest_words(output: &[u8]) -> [u32; 8];           // what x24..x31 carry

// what this program's VmConfig takes. Identity binds all three.
pub const COMMITTED_WITNESS_BYTES: usize = 716;
pub const WITNESS_CAPACITY: usize = 2 * COMMITTED_WITNESS_BYTES;   // THE tunable
pub const BYTECODE_SIZE_WORDS: u32 = 1 << 21;
pub const TRACE_HEIGHT_RELEASE: u32 = 1 << 20;
pub const TRACE_HEIGHT_DEBUG: u32 = 1 << 22;

// riscv32 only: alloy-primitives' native-keccak hook
#[no_mangle] pub unsafe extern "C" fn native_keccak256(bytes: *const u8, len: usize, output: *mut u8);
```

### `crates/guest-sdk`

One addition, and it is the master's own mechanism rather than this stage's invention:

```rust
pub fn exit_with_public_words(code: i32, words: [u32; 8]) -> !;   // leaves words in x24..x31
```

One `asm!` block, and it has to be: `x28..x31` are caller-saved temporaries, so any
instruction between a write and the `ecall` is free to clobber them.

### `tools/kat-gen -- revm`

The host-side fixture builder, in `DEFAULT_GROUPS` so CI regenerates and diffs it. It
constructs the pre-state and the two transactions from named constants, serializes the
witness, runs `revm_block::run` natively, **then builds and traces the guest and holds
its fd 1 to that answer** — so a regeneration *is* acceptance 4, run on every push. Three
fixtures, in the new `crates/emulator/tests/vectors/`:

| File | Bytes | What |
| --- | --- | --- |
| `revm_block_witness.bin` | 716 | the `BlockWitness`, `postcard`, fd 0 |
| `revm_block_output.bin` | 122 | the output commitment, fd 1 |
| `revm_block_keccak.bin` | 1,800 | 9 keccak-f frames, 200 bytes each |

Unlike the `guests` group it does build a guest and it does run by default: what is
committed is not the ELF's bytes but the run's behaviour, and a keccak preimage never
sees the panic-location strings that make an ELF machine-dependent.

### Specs and docs

- `docs/spec/revm-block.md` — **frozen**: `BlockWitness`, its canonicity rules, and the
  output-commitment structure. S25 produces the first for real blocks; S25 and S26
  consume the second as-is.
- `docs/guest-program-manual.md` — `revm-block`'s row in §2 and the `members` line.

---

## 3. Measurements

All on an 18-core macOS laptop, guest at `--release` unless stated.

### The image (acceptance 10)

`revm-block`, the normative binary (`revm-block-embedded`'s figures are within 0.1 % of
these and `crates/emulator/tests/revm.rs::a10_…` asserts both):

| | `--release` | `debug` |
| --- | --- | --- |
| ELF | 2,233,392 B | 7,791,596 B |
| `.text` | **1,680,244 B** | 5,359,128 B |
| file-backed end | `0x1c68d4` | `0x563e64` |
| span from `RAM_ORIGIN` | **449,077 words** | 1,396,633 words |
| against `BYTECODE_SIZE_WORDS = 2^21` | 21.4 % | 66.6 % |
| expanded slots | 840,122 | 2,679,564 |
| instruction slots | **520,757** | 1,876,912 |
| last instruction pc | `0x1aa370` | `0x52c614` |
| smallest height that holds it | **2^20** | 2^22 |

The height is what matters. A decoded table is pc/2-indexed and absolute, so a family's
height must satisfy `last_pc ≤ 2·height − 4`: **2^20 rows reach pc `0x1ffffc`, which is
1.9375 MiB of `.text` from `RAM_ORIGIN`**. The release image uses **82.7 %** of that, so it
fits the cheapest height a cycle-owning family can have. The debug image does not, and
would need 2^22 — four times the rows in every shard. That percentage is the number to
watch as the workload grows: there is no menu step above 2^22.

`bytecode_size_words` had to move off its `2^20` default: the debug image's span is
1,396,633 words, past the 1,048,576 the default allows. One pinned value, `2^21`, covers
both profiles, so the two builds differ in their code and in nothing else.

### The run (acceptance 9)

`revm-block` at `--release`, on the committed witness: **221,165 cycles**, exit 0, 122
bytes on fd 1, **9 keccak-f delegations**. (Debug: 1,467,839 cycles — 6.6× more, which is
what the profile is worth in a VM where an instruction is proving cost.)
`revm-block-embedded`: **220,984 cycles**, 10 delegations — one more, for the digest it
publishes.

About 16,000 of those cycles are the canonicity check: `BlockWitness::decode` re-encodes
the witness and compares, which is the only way to pin `postcard`'s byte-level form
(§4). 7 % of the run to close a padding channel that would otherwise give one block
more than `2^32` fd 0 encodings.

| Family | Rows | Height | Occupancy | Shards |
| --- | ---: | ---: | ---: | ---: |
| `ADD_SUB_LUI_AUIPC` | 75,863 | 1,048,576 | 7.23 % | 1 |
| `JUMP_BRANCH_SLT` | 42,460 | 1,048,576 | 4.05 % | 1 |
| `SHIFT_BITWISE` | 22,928 | 1,048,576 | 2.19 % | 1 |
| `MUL_DIV` | 3,123 | 1,048,576 | 0.30 % | 1 |
| `MEM_WORD` | 56,318 | 1,048,576 | 5.37 % | 1 |
| `MEM_SUBWORD` | 20,389 | 1,048,576 | 1.94 % | 1 |
| `ATOMICS` | 84 | 1,048,576 | 0.01 % | 1 |
| `INIT_TEARDOWN` | — | 1,048,576 | — | 1 |
| `ZERO_WINDOWS` | — | 1,048,576 | — | 1 (window 511) |
| `KECCAK_F` | 9 | 256 | 3.52 % | 1 |

**Ten shards**, and the first statement in the repository in which every one of the seven
execution families runs. The only RAM window above 0 is 511, the stack's: revm's total
allocation for this block stays inside window 0's remaining ~2.3 MiB.

Occupancy at the debug profile, for contrast, since the from-source suites trace that
build: 1,467,839 cycles, every family at `2^22`, `ADD_SUB_LUI_AUIPC` the busiest at
415,220 rows (9.9 %) — and one RAM window above 0, 127, the same stack at four times the
window size.

Occupancy is low because a cycle-owning family's shard cannot be smaller than 2^20 rows
whatever the guest (`docs/spec/lookup.md` §3). Seven families' worth of that is what a
2^20-floor VM costs a 204,000-cycle program, and it is exactly what the occupancy table
exists to show.

### The block

The two window families are at **2^20** here and not the 2^16 every earlier statement
used, because window 0 is the init family's `4·height` bytes and this image's file-backed
bytes end around 1.85 MB — far past the 256 KiB a 2^16 window 0 covers.
`crates/emulator/tests/revm.rs::a10_…` asserts that, for both binaries.

### The synthetic block's semantics (acceptance 4)

| | status | gas | output |
| --- | --- | ---: | --- |
| tx 1, transfer | success | 21,000 | — |
| tx 2, counter call | success | 29,340 | `0x…06` |

21,000 is an ether transfer's intrinsic cost exactly. The counter's slot goes 5 → 6, one
log is emitted with `keccak256("Incremented(uint256)")` as its topic and the new value as
its data, and the call returns that value.

---

## 4. Findings

### `postcard` has two padding channels, and closing one was not enough

`docs/spec/revm-block.md` §1.1 claims one logical state has exactly one encoding, and
fd 0 is bound by `io_digest` over the *bytes* — so a second encoding of one state is a
second digest for one execution, chosen by whoever writes fd 0. `postcard` gives two ways
to make one, and the first draft of `decode` closed neither:

1. **Trailing bytes.** `postcard::from_bytes` decodes a prefix and ignores whatever
   follows. Appending a byte — or a whole second witness — decoded to the same value.
2. **Non-minimal varints.** `postcard`'s varint decoder accumulates continuation bytes
   and rejects only an overflowing *last* byte; it never requires the shortest form, so
   `81 00` reads as 1 exactly as `01` does. Every length, `Option` tag, nonce and gas
   field in `BlockWitness` is a varint. On the committed 716-byte witness alone, **32 byte
   positions** take a two-byte non-minimal form and `chain_id` takes nine extra widths —
   more than `2^32` distinct fd 0 streams for one block, every one a different digest, and
   all of them inside `WITNESS_CAPACITY`.

`take_from_bytes` with an empty-remainder check closes (1) and does nothing about (2).
What closes both is **re-encoding and comparing**: `decode` now requires the bytes to be
exactly what `encode` would write. That costs about 16,000 guest cycles, 7 % of the run,
and it is the price of the property the spec claims.

`crates/emulator/tests/revm.rs::a_witness_out_of_canonical_order_is_refused` sweeps every
byte of the fixture, widens each varint it finds, and requires each to be refused — a
sweep rather than one hand-picked offset, so a decoder that pinned only the first field
would fail it.

Found by adversarial review after the trailing-byte fix, which is the useful lesson: the
first fix looked complete and was not, because it treated the symptom the author had
thought of rather than the class.

### The `0x…02` collision

The fixture's first draft put its accounts at `0x00…01`, `0x00…02` and so on. The
transfer to `0x00…02` came back `OutOfGas(Precompile)`: that is **SHA-256's address**, and
it charges for a call the 21,000-gas intrinsic left nothing for. Every precompile lives
at an address whose first nineteen bytes are zero, so any "put the label in the last
byte" scheme picks one. The addresses now lead with `0xee` and `synthetic_block` asserts
a nonzero leading byte.

### revm's whole `.text` decodes as RV32IMA

`isa::decode` is RV32IMA's 59 instructions exactly, and `rvc::expand` refuses every F/D
and Zcb/Zcmp encoding — so a build that picked up Zba/Zbb would kill the whole image.
It does not: `decode_program` accepts all 520,757 instruction slots in 54 ms. No
`.option` juggling and no toolchain flag was needed.

### `native-keccak` is the hook, and it covers everything

`alloy-primitives`' `native-keccak` feature replaces `keccak256` with an `extern "C"`
call. revm uses only the one-shot form — 44 call sites, no streaming `Keccak256` — so the
feature catches revm's `KECCAK256` opcode, every contract code hash, and this stage's two
commitments. A `features` key inside a dependency entry selects an upstream crate's
features and is not a `[features]` table of ours; `crates/prover/tests/one_feature.rs`
reads only manifests inside the repository and still holds.

### Two deviations from repository rules, both recorded

1. **`unsafe` outside `guest-sdk`.** `native_keccak256`'s signature is upstream's — a raw
   pointer, a length, a raw output pointer — and no safe function implements it. The root
   `CLAUDE.md` says every `unsafe` block in the workspace lives in
   `crates/guest-sdk/src/lib.rs`; this is the one exception, three lines with a `# Safety`
   section. Putting it in `guest-sdk` instead would be worse: a `#[no_mangle]` export
   there is linked into every guest, and the record it reaches would declare `KECCAK_F`
   for `fib` — precisely the hazard that file's `#[used]` comment describes. Raised with
   the owner, who chose this.

2. **arkworks, `k256`, `p256`, `sha2` and `ripemd` in a guest image.** `revm-precompile`
   depends on them unconditionally, for the EVM's own precompiles. Master rule 2 admits
   reference libraries as dev-dependencies alone and the root `CLAUDE.md` says they are
   *"never reachable from the prover, the verifier or a guest"*. The stage prompt names
   revm a permitted guest dependency because the guest is **workload, not proving stack**,
   and the same reading covers what revm brings with it. Nothing here is reachable from a
   prover, a verifier or any other guest. Master rule 13: the stage wins, recorded here.

### No committed ELF

The owner's decision, and the second question raised. `revm-block`'s ELF is 2.2 MB at
`--release` and 7.8 MB at `debug`, where it expands to 1.88 million instruction slots.
Committing it would put a fixture 1.7× the largest one in the repository into git, make
`tools/artifact-dump/tests/manual.rs` render two full instruction listings of it per run,
and enrol it in the seven `crates/program/tests` loops that decode every committed guest
— at 2^22 rows across 12 families, inside `cargo test --workspace`, the fast gate.
Nothing is derived from its bytes but its identity.

So `tools/artifact-dump/tests/manual.rs` gained `NOT_A_COMMITTED_FIXTURE`, one name with
its reason, and `the_exemptions_are_real_and_still_needed` checks the list in both
directions: the name must be a real guest, and it must really have no committed ELF, so
an exemption cannot outlive its reason.

### The ZERO_WINDOWS count is a heap measurement

One window above 0 — 511, the stack's. Window 0 runs to 4 MiB and the image ends at
1.85 MB, so revm's total allocation for this block fits in the ~2.3 MiB left. The bump
allocator never frees, so that is a *total*, not a peak: a larger block adds
`ZERO_WINDOWS` shards one 4 MiB window at a time.

---

## 5. Acceptance

| # | What | Where | State |
| --- | --- | --- | --- |
| 1 | reproducible identity | `crates/prover/tests/revm.rs::a1_…` | ✅ |
| 2 | family set and partition | `crates/emulator/tests/revm.rs::a2_…` | ✅ |
| 3 | emulator against QEMU | `…::a3_the_two_executors_commit_the_same_bytes` | ✅ |
| 4 | guest against native host revm | `…::a4_the_guest_agrees_with_native_revm`, and `kat-gen -- revm` | ✅ |
| 5 | shim against software fallback | `…::a5_every_delegated_permutation_is_the_reference`, `…::a5_the_harvested_frames_are_the_committed_ones` | ✅ |
| 6 | end-to-end proof | `crates/prover/tests/revm.rs::a6_…` | ✅ **embedded binary; §1** |
| 7 | tamper twin — statement | `…::a7_a_changed_statement_is_refused` | ✅ **embedded binary; §1** |
| 8 | delegation occupancy | `…::a6_…`, `shards(KECCAK) >= 1` | ✅ **embedded binary; §1** |
| 9 | cycle report | `crates/emulator/tests/revm.rs::a9_…`, §3 above | ✅ |
| 10 | `.text` against the ceiling | `…::a10_…`, §3 above | ✅ |

---

## 6. What was run, and where

Everything. Nothing in the acceptance list is outstanding, and the deferred suite was run
rather than left for a machine that does not exist yet.

| Suite | Result | Cost |
| --- | --- | --- |
| `cargo test --workspace` | 1,034 passed, 82 ignored | the fast gate |
| `cargo run -p kat-gen` then `git diff --exit-code` | clean, twice | the `revm` group builds and traces the guest |
| `…emulator --test revm -- --ignored --skip a3_` at `--release` | 5 passed | 47 s, of which 25 s is the guest build |
| `…emulator --test revm -- --ignored a3_` (acceptance 3) | 1 passed | in a `rust:latest` container with `qemu-user`, 35 s |
| `…prover --test revm` (acceptances 1, 6, 7, 8) | 3 passed | **see below** |

### The deferred suite's numbers, and the one caveat on them

`cargo test --release -p prover --test revm -- --include-ignored --test-threads=1`, on an
18-core / 48 GB macOS laptop, **with `RAYON_NUM_THREADS=6`**.

That environment variable is the caveat and it is load-bearing. Shard proving is the
block's one parallel step and its peak is one shard's forward pass per worker
(`docs/handoff/S20-orchestration.md`); this statement is **nine `2^20` shards**, where
S23's ten-shard block — the previous heaviest, at 35.2 GB — had six. Unbounded on 18
cores it would hold ten forward passes at once and does not fit 48 GB. Bounded to six
workers the whole file — acceptance 1's two clean builds and two identity computations,
then the block, then the twins — is **3 passed in 536 s at a 38.4 GB peak**. The block is
byte-identical either way (S20's must-be-exact 8), so what the bound changes is the
measurement and not the proof.

**The unbounded peak has not been measured**, and it is the number a machine-sizing
decision would want. `prompts/S24-revm.md` directs the heavier suites to an
`r8i.8xlarge` provisioned through `../apogee-aws`, and `./scripts/status.sh` reports that
**no such instance exists**: provisioning is a fresh ~45–75 minute, ~$2–3 run, then
~$2.36/h. The owner asked to be asked when the code was ready rather than have one
started speculatively, and the code being ready is now — but the suite passes, so what an
unbounded run would add is a number, not a verdict.

### Identity

`revm-block-embedded`'s `ProgramIdentity` over the **toy SRS**, from two clean builds that
agreed on every byte:

```
5f73c3ff2a3805f6004a3dc3579f5284db5be8f7c5089e50d8f4031cde737019
```

That is not the ceremony's identity and is not meant to be: acceptance 1 asks whether two
builds of one source give one identity, and any structurally valid SRS answers it. A
published identity over PSE's contribution 80 is `crates/program/tests/identity.rs`'s
business, and this program is not pinned there.

## 7. For the next stage

- **`BlockWitness` is frozen** (`docs/spec/revm-block.md` §1). S25's witness recorder
  produces this exact type for a real block. Nothing in it is synthetic-specific: an
  account carries general code and storage, a transaction carries the full EIP-1559/2930
  envelope, and `stateless` is the section S25 defines. `caller` is already recovered —
  there is no `ecrecover` delegation in this repository. **It stops at transaction type
  2**: blob hashes (EIP-4844) and authorization lists (EIP-7702) are two and one fields
  appended at the end of `TxWitness`, left out rather than guessed at, and
  `docs/spec/revm-block.md` §1.2 says what a stage that meets one has to decide.
- **The output commitment is frozen** (§2 of the same page). S25 and S26 consume it
  as-is; they are the fd 1 bytes S10's `io_digest` binds.
- **The I/O-binding work is owed and is scoped in §1.** It is the thing standing between
  this workload and a proof of the binary the stage actually specified.
- **The height wall is close.** `2^22` is the last entry on
  `constants::family::HEIGHT_MENU`, and it reaches 7.9375 MiB of `.text`. The release
  image is 1.68 MB and already uses 82.7 % of what `2^20` reaches, so a workload that
  grows by a fifth costs four times the rows in every shard. There is no menu step above
  `2^22`.
- **`WITNESS_CAPACITY` is the guest's one tunable**: twice the largest committed witness.
  A larger witness exits 60 rather than decoding a prefix.
- **`decode` re-encodes, and a witness that grows makes that cost grow with it.** It is
  7 % of this run; on a real block's witness it will be more, and the alternative is a
  canonicity claim that is not true (§4).
- **The unbounded memory peak is unmeasured** (§6). A nine-`2^20`-shard block is the
  heaviest statement the repository has, and the next one will be heavier.
