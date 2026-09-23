# S21 — keccak256 delegation family + the delegation ABI

Branch `s21-keccak256`. Status: implemented; all nine acceptance items are met. Four
design questions went to the repository owner before any code and were answered. Each
answer and what follows from it is in "Read these first" — one of them, the trace height,
contradicts the stage prompt, and the arithmetic that made it necessary is below.

S21 adds the first family that is **invoked rather than decoded**. A `KECCAK_F` row is not
a cycle and not a RAM word: it is one keccak-f[1600] permutation over the 200-byte frame a
guest handed over, and the family is in a `VmConfig` not because a pc claims it but because
the linked binary **declares** it. `guests/keccak-test` calls `guest_sdk::keccak256` over
six inputs, makes ten invocations, proves as a nine-shard block and verifies; the same
binary under `qemu-riscv32` gets `-ENOSYS` from the same ecall, runs the SDK's software
permutation instead, and reaches the same six digests.

Normative documents written or amended this stage:

- **`docs/spec/delegation.md`** (new): the delegation ABI for every delegation family —
  the ecall convention, the registry, the indirect frame and its alignment rules, the
  anchor and why its pairing is 1:1, the three request-side zeroings, static detachment,
  the keccak-f circuit, the shard and ts-window convention, the height and why there is no
  lookup channel, and what S22 and S23 may append. **Frozen here**; S22 and S23 consume it
  verbatim and may only append their frame tables.
- **`docs/spec/constraint-manifest.md`**: §12 (new, the keccak family) and **§3 rewritten
  from the new artifact** — the eighth memory query moved every relation number in it.
  §0.4, §0.5, §1.1, §1.2, §1.3 and §2 carry the new family and the new query; Observations
  became §13 with **five** new entries — 19 to 23 — and Maintaining §14.
- **`docs/spec/memory.md`**: §2.1 (the query table has nine entries, and
  `ADD_SUB_LUI_AUIPC`'s frame eight), a header note, and a "Status at S21" paragraph
  saying what the delegation families add to the global argument, which is nothing.
- **`docs/spec/shard-proof.md`**: §8.1, §8.2, §8.3 and §8.5 (the add/sub family's eighth
  query, its eight new gates and three amended ones, its sixteen timestamp obligations,
  and the delegation ecall no longer being owed elsewhere) and §11 (the registry).
- **`docs/spec/block-proof.md`**: §4, §5.3 and §8 — **no rule changed**; the paragraph
  S20 wrote promising that delegation families would slot in with zero `verify_block`
  changes is now a statement about what happened.
- **`docs/spec/lookup.md`**: §3, on the way out of the `2^20` floor and why a delegation
  family must carry no channel.
- **`docs/spec/execution-trace.md`** and **`docs/spec/ecall-abi.md`**: the eighth role and
  the delegation request's row; the `0x0501` table row.
- Also updated to match: `docs/GLOSSARY.md`, `docs/guest-program-manual.md`,
  `.github/workflows/ci.yml`, the root `CLAUDE.md`, and the `CLAUDE.md` of `constants`,
  `constraints`, `trace`, `emulator`, `program`, `prover`, `checker` and `guest-sdk`.

`prompts/S21-keccak256.md` is committed unchanged.

---

## Read these first

Four questions went to the owner before any code, each with the argument and the price.
The answers are the design.

### 1. The trace height is `2^8`, and the menu gained it. The prompt's `2^16` is impossible.

The prompt says "take the `2^16` trace height from the menu". That cannot be built, and the
number is not close. One keccak row's forward pass is **354,762 inner columns** — 24 rounds
× 7 sub-layers, each carrying the whole 1,600-bit state — so a shard of `2^n` rows holds
about `354,762 · 2^n · 32` bytes of `Fr` before anything is committed:

| height | forward pass |
| --- | --- |
| `2^8` | **2.9 GB** |
| `2^10` | 11.6 GB |
| `2^12` | 46.5 GB |
| `2^16` | **744 GB** |

The owner's answer: **`2^8`, and the menu gains it.** So `constants::family::HEIGHT_MENU`
opens with `2^8` — an amendment to a frozen constant, taken under the pre-registration
licence (`PROTOCOL_VERSION` is still the placeholder 0) — and
`DEFAULT_HEIGHTS[KECCAK_F]` is that. Three things follow, and they are the shape of the
whole stage:

- **A delegation family's height answers a different question.** For an execution family
  it is "how long may the program be" and "how many cycles fit one shard"; here rows are
  *invocations*, so it is "how many permutations fit one shard". 256 is generous:
  `guests/keccak-test`'s ten fit with room to spare, and a guest needing more gets more
  shards, which is what shards are for.
- **`2^8` is an even power**, which Mercury requires (`b = sqrt(n)` must exist). The menu
  below `2^16` had `2^8`, `2^10`, `2^12` and `2^14` to choose from and nothing else.
- **No lookup channel fits.** `constants::lookup_channel::BITS` bottoms out at 16, and a
  range channel is refused at construction unless `BITS ≤ trace_vars`
  (`docs/spec/lookup.md` §3). So the family carries **none**, and every bound it makes is a
  bit decomposition with a booleanity gate — which costs this circuit nothing it was not
  already paying, its state being 1,600 committed bits. See deviation 2.

### 2. The anchor lives in an address space of its own, `DELEGATION_KECCAK_F = 4`.

The anchor is a pair of memory tuples that must be unreachable from RAM, from the
registers and from any other delegation family's. The options were a new address-space tag,
a reserved RAM range, or a tagged address inside RAM. The owner chose **a new tag**, one per
delegation family. It costs a `constants::address_space` entry and a `trace::AddressSpace`
variant per family; it buys an argument that is one sentence long — nothing but an
invocation writes in that space, and nothing but a request reads — where a reserved range
would have had to argue that no guest pointer can land in it.

### 3. The circuit's fixture is its SHA-256, not its bytes.

`keccak::artifact(8).to_bytes()` is **100,254,040 bytes**, 974 times the largest committed
circuit (`atomics.bin`, 102,965). Committing it would put 100 MB in the tree and 100 MB
through every CI regeneration diff. The owner chose: **commit its SHA-256 and diff that.**
`crates/constraints/tests/vectors/keccak.txt` is one comment block and one line — the shape
counts and the digest — written by `cargo run -p kat-gen -- keccak`, held to the
constructor by kat-gen's own unit test, and regenerated and diffed by CI like every other
fixture. Its readable account is `docs/spec/constraint-manifest.md` §12; there is no
`checker dump` of it, because a 358,525-relation listing is not a readable account of
anything.

### 4. Static detachment is a `.rodata` magic record found by a byte-wise scan.

A delegation family claims no pc, so the instruction sweep can never learn that a program
calls one: the ecall number lives in `a7` at run time and no instruction word carries it.
The options were a named ELF section, a `.rodata` magic record, a symbol name, or a
`.note` section. The owner chose **the `.rodata` magic record**: twelve bytes,
`constants::delegation::MARKER_MAGIC` then the number, emitted by the SDK shim into
`.rodata.apogee.delegations`, and found by `program::declared_delegations` scanning the
image's file-backed segment bytes.

The mechanism underneath is **reachability**, and it is worth stating plainly because two
ways of getting it wrong both shipped during this stage and both are now tested:

- **`#[used]` breaks it.** `guests/Cargo.toml` pins `codegen-units = 1`, so the SDK is one
  object file; with `#[used]` the record survived into **every guest that links the SDK** —
  `fib`, `echo`, `heap` and seven more — and detachment meant nothing. The record is kept
  because `delegation_number()` reads it and the shim calls that, and for no other reason.
- **The optimiser breaks it.** At `--release` LLVM folded the record's number into an
  immediate and dropped the record, so `keccak-test` declared nothing at `opt-level = 3`
  and everything at `opt-level = 0`. `core::hint::black_box` on the read is what prevents
  it.

Neither failure is visible in the SDK source, which is why
`crates/program/tests/delegation.rs` holds **every committed guest** to both halves: the
two keccak guests declare `KECCAK_F`, and no other guest declares anything at all.

---

## Frozen public API, as built

```rust
// constants — append-only; the menu's first entry is the one amendment
family::KECCAK_F: FamilyId = 9;  family::COUNT = 10;
family::HEIGHT_MENU: [u32; 5] = [1 << 8, 1 << 16, 1 << 18, 1 << 20, 1 << 22];
family::CYCLE_OWNING[KECCAK_F] = false;   family::DEFAULT_HEIGHTS[KECCAK_F] = 1 << 8;
ecall::PRECOMPILE_KECCAK_F: u32 = 0x0501;
address_space::DELEGATION_KECCAK_F: u8 = 4;
mod delegation { FRAME_DELTA: u64 = 0; ANCHOR_DELTA: u64 = 3;
                 MARKER_MAGIC: [u8; 8] = *b"APOGDEL1"; MARKER_BYTES: usize = 12; }
mod keccak { LANES, LANE_BITS, STATE_BITS, STATE_BYTES, FRAME_WORDS = 50, ROUNDS = 24,
             RATE_BYTES = 136, DIGEST_BYTES = 32, PAD_FIRST, PAD_LAST,
             ROTATIONS: [[u32; 5]; 5], ROUND_CONSTANTS: [u64; 24] }

// constraints::keccak — the circuit, docs/spec/delegation.md §6
pub const CYCLE: PolyAddress;  LIVE;  BASE;  ANCHOR_VALUE;            // M[0..4]
pub fn word(j: usize, field: u32) -> PolyAddress;                     // M[4 + 4j + f]
pub const WORD_ADDR: u32;  WORD_READ_TS;  WORD_READ_VALUE;  WORD_WRITE_VALUE;
pub fn in_bit(b: usize) -> PolyAddress;                               // W[0..1600]
pub fn gap_bit(j: usize, bit: usize) -> PolyAddress;                  // W[1600..3500]
pub fn base_low_bit(bit: usize) -> PolyAddress;                       // W[3500..3529]
pub fn base_room_bit(bit: usize) -> PolyAddress;                      // W[3529..3560]
pub const MEMORY_COLUMNS: usize = 204;   pub const WITNESS_COLUMNS: usize = 3560;
pub fn artifact(trace_vars: u32) -> CircuitArtifact;
pub fn channels() -> Vec<ChannelSpec>;                                // EMPTY

// constraints::add_sub — the eighth query and the delegation flag
pub const IS_KECCAK: PolyAddress;                                     // W[25]
// and every address after W[7] moved: see "Deviations", item 5.

// constraints::memory — the query table's ninth entry
pub const FRAME_QUERIES: usize = 9;   pub const DELEG: usize = 8;

// trace
pub enum AddressSpace { Reg, Ram, Pc, KeccakF }
impl AddressSpace { pub fn chains(&self) -> bool; }
pub enum Role { Rs1, Rs2, Arg1, Arg2, Load, Ram, Rd, Delegate }
pub const ROLES: [Role; 8];                        // the mask is a full u8 now
pub struct DelegationTrace { pub family, pub height, pub cycle: Vec<u64>,
                             pub base: Vec<u32>, pub words: Vec<QueryColumns> }
pub struct FamilyTraces { pub families: Vec<FamilyTrace>,
                          pub delegations: Vec<DelegationTrace> }

// program — the registry and static detachment
pub const DELEGATIONS: [(FamilyId, u32, usize); 1];
pub fn delegation_family(number: u32) -> Option<FamilyId>;
pub fn delegation_ecall(family: FamilyId) -> Option<u32>;
pub fn delegation_frame_words(family: FamilyId) -> Option<usize>;
pub fn claims_pcs(family: FamilyId) -> bool;
pub fn declared_delegations(image: &ProgramImage) -> Result<Vec<FamilyId>, ProgramError>;
pub enum ProgramError { .., UnknownDelegation { addr: u32, number: u32 } }

// emulator
pub fn keccak_f(state: &mut [u64; 25]);
pub fn lanes_of(words: &[u32; 50]) -> [u64; 25];
pub fn words_of(lanes: &[u64; 25]) -> [u32; 50];
pub enum EmuError { .., DelegationFamilyAbsent { pc: u32, number: u32 } }

// checker — the anchor's twins, parameterized by family for S22 and S23
pub struct AnchorTwins { pub requester: (FamilyId, u32), pub delegation: (FamilyId, u32),
                         pub request: usize, pub invocation: usize, pub other_request: usize,
                         pub rd_selected: PolyAddress, pub cycle: PolyAddress,
                         pub mirror_read_ts: PolyAddress, pub mirror_read_value: PolyAddress,
                         pub mirror_write_value: PolyAddress,
                         pub live: PolyAddress, pub anchor_value: PolyAddress }
pub fn assert_anchor_twins_refused(h: &TamperHarness, t: &AnchorTwins);
impl TamperHarness { pub fn run_block(&self, t: &Tamper) -> Result<(), VerifyError>;
                     pub fn assert_block_rejects(&self, t: &Tamper, expected: VerifyError);
                     pub fn assert_block_verifies(&self, t: &Tamper); }

// guest-sdk — FROZEN, and S24's revm hash hook routes through it
pub fn keccak256(input: &[u8]) -> [u8; 32];
```

**No new entry point.** `global_commit_phase`, `prove_shard`, `prove_block`,
`reduce_shard`, `verify_shard` and `verify_block` are byte-for-byte what S20 left them.
The family is registered by one arm in `constraints::family_circuit` and one in
`prover::family_fill`, which is the surface S16 designed and S17, S18 and S19 each used.

---

## What this freezes for every later stage

1. **`docs/spec/delegation.md` is the ABI for all delegation families.** S22 and S23 append
   a family id, an ecall number and a frame table, and nothing else. In particular the
   anchor's shape — a timestamp-0 answer tuple in the family's own address space, three
   request-side zeroings, a free value column on both sides — is not theirs to redesign.
2. **`guest_sdk::keccak256(&[u8]) -> [u8; 32]` is frozen.** S24's revm hash hook routes
   through it. Which path runs is not part of the signature and a guest cannot tell.
3. **`ecall::PRECOMPILE_KECCAK_F = 0x0501` and `address_space::DELEGATION_KECCAK_F = 4`**
   are append-only like every number beside them. The next delegation family takes the next
   free space. *(S23 took spaces 5 and 6 for `POSEIDON2` and `FR_ARITH`. The ecall numbers
   went the other way: `POSEIDON2` claimed `PRECOMPILE_POSEIDON2 = 0x0500`, reserved since
   S10 and older than `0x0501`, and only `FR_ARITH` took `0x0502`. "Append-only" is a rule
   about never **redefining** a number, not about handing them out in order.)*
4. **The keccak `CircuitArtifact`, its frame layout and `2^8`.** The frame is the 200-byte
   state in SHA-3 byte order at `base + 4j`, word `2i` being lane `i`'s low half.
5. **`checker::assert_anchor_twins_refused` and `AnchorTwins`.** S22 and S23 fill the struct
   with their own addresses and call it by name; they do not write the argument again.
6. **The eighth role.** `Role::Delegate` took `trace::Row::present`'s last spare bit. A
   ninth role widens that `u8`, which is a schema change to the trace archive.

---

## Artifacts

| Path | What |
| --- | --- |
| `docs/spec/delegation.md` | the ABI, eleven sections |
| `crates/constraints/src/keccak.rs` | the circuit, ~1,100 lines, its own `Assembly` |
| `crates/constraints/tests/vectors/keccak.txt` | the artifact's shape and SHA-256 at `n = 8` |
| `crates/constants/tests/keccak.rs` | `ROTATIONS` and `ROUND_CONSTANTS` re-derived |
| `crates/emulator/tests/keccak.rs` | `keccak_f` against `tiny-keccak`, 1,600 single-bit states |
| `crates/checker/tests/keccak.rs` | the circuit's forward pass and ten negative controls |
| `crates/program/tests/delegation.rs` | the registry, the scan, and detachment over every guest |
| `crates/prover/tests/keccak.rs` | acceptances 4 and 8, `#[ignore]`d |
| `crates/loader/tests/qemu.rs` | acceptance 5's QEMU half, `#[ignore]`d |
| `guests/keccak-test`, `guests/keccak-unused` | the fixtures, exit 6 and 7 |
| `tools/kat-gen/src/keccak.rs` | the `keccak` group |

---

## Acceptance

1. **Spec, and the numbers single-sourced.** `docs/spec/delegation.md` has every section
   the prompt lists. Nothing spells an ecall number: the circuit's `keccak_number` gate
   reads `constants::ecall::PRECOMPILE_KECCAK_F`, so do the emulator's arm, the SDK shim
   and `program::DELEGATIONS`, and `crates/constants/tests/ecall_abi.rs` holds the document
   to the module in both directions. `crates/program/tests/delegation.rs` holds the registry
   to the same constant, and a unit test in `add_sub.rs` holds the two provable ecall
   numbers distinct and each in its ABI range — without which `ecall_is_exit` and
   `keccak_number` would not be a partition.
2. **Permutation differential.** `crates/checker/tests/keccak.rs`'
   `the_forward_pass_is_keccak_f` runs the circuit's forward pass over two honest
   invocations and compares all 50 written words with `emulator::keccak_f`, which
   `crates/emulator/tests/keccak.rs` holds to `tiny-keccak` on the zero state, the all-ones
   state, **all 1,600 single-bit states** and a random walk. Both run in ordinary CI.
3. **Shim differential.** `guests/keccak-test` checks six digests in-guest — empty, 1, 135,
   136, 137 and 400 bytes — and exits 6, or `200 + i` naming the entry that failed. The
   delegated path is `crates/emulator/tests/guests.rs`, the fallback
   `crates/loader/tests/qemu.rs`, and **the digests themselves are re-derived from
   `tiny-keccak` and read out of the guest's own source**, so neither path can agree with
   the other on a stale literal.
4. **End to end.** `crates/prover/tests/keccak.rs`' first test: nine shards, the delegation
   family's last, `verify_block` returns `Ok`, every shard also verifies through
   `verify_shard`, the roots reconcile across the CPU and delegation shards together, and
   the proof is its circuit's 11,880,012 bytes.
5. **Witness tamper.** `crates/checker/tests/tamper.rs`' S21 twin corrupts a state bit, a
   state bit with its word, a written word and a gap bit, each refused as `Constraint` on
   the delegation shard; the control moves the two cells of a padding row that really are
   free — a gap bit and a frame-pointer headroom bit, both gated on `live` — and still
   verifies, while a padding row's **state** bit alone is refused, `input_w{j}` being
   ungated (deviation 12). A misaligned frame pointer is acceptance 7, below.
6. **Anchor tamper.** `checker::assert_anchor_twins_refused` runs all four and the control,
   **each at the level that names what refuses it** (see deviation 11): (a) an invocation
   dropped, and (b) the same forgery with its anchor side repaired — both at block level,
   both `MemoryArgument`; (c) each of the three zeroings alone, at **shard** level, each
   `Constraint`, which is the direct evidence that the gates are load-bearing. The control
   moves the free pair — the mirror's write value and the invocation's teardown value —
   **together**, and must still verify as a block.
7. **Alignment negative.** `crates/checker/tests/keccak.rs` refuses a misaligned frame
   pointer by `base_aligned`, one below `RAM_ORIGIN` by `base_aligned`, and one whose frame
   runs past the top of RAM by `base_in_window`. Both gates are asserted present **by name**
   in the emitted artifact by `keccak::check_shape`, which is must-be-exact 4.
8. **Detachment and zero shards.** `crates/program/tests/delegation.rs` holds all seventeen
   committed guests: the two keccak guests declare `KECCAK_F`, **no other guest declares
   anything**, and each config's delegation families are exactly its declared ones.
   `crates/prover/tests/keccak.rs`' second test proves `guests/keccak-unused` — the family
   in the config, in the descriptor and in the transcript's group list, and **zero shards**.
9. **Validators and CI.** `the_circuit_keeps_every_rule` runs `validate`, `check_laws`,
   `check_padding`, `check_padding_identity`, `check_memory` and `check_discharge` on the
   artifact; `artifact()` itself panics on any of them, so the circuit cannot be built
   unlawful. The degree ceiling is `validate`'s and every new gate is degree ≤ 2 —
   `check_shape` counts them on the emitted artifact. The fixture is regenerated and diffed
   in CI.

---

## Must-be-exact, item by item

1. **Done.** Every section is in `delegation.md`, and no number is spelled twice (see
   acceptance 1).
2. **Done, and tested against both ways of losing it.** Membership comes from the linked
   binary's declaration record, found by a byte-wise scan; no flag decides it. An executed
   delegation ecall whose family is absent from the `VmConfig` is
   `EmuError::DelegationFamilyAbsent`, a named fatal error that returns no trace.
3. **Done.** All three zeroings are enforced — `deleg_writes_no_register`,
   `deleg_read_ts_zero`, `deleg_read_value_zero` — and the 1:1 pairing is argued in
   `delegation.md` §5.3 and tested by the four twins.
4. **Done, counted on the emitted artifact.** `keccak::check_shape` runs on every build and
   asserts `base_aligned` and `base_in_window` **by name**, 50 each of `addr_w`, `gap_w`,
   `input_w` and `output_w` **by count over the emitted relations**, gate list 0's exact
   enforcing count, and every layer's width against its three parts. A test additionally
   asserts **no relation's name contains "assume"**. The failure class the prompt names —
   a check pushed onto a drained vector, with an `assume_*` flag asserted in source and
   enforced by nothing — cannot survive any of that.
5. **Done.** See acceptance 3 and 5.
6. **Done.** 3,561 booleanity gates: one per committed witness column and one for the mask.
   Every read word is recomposed from its own 32 input bits (`input_w{j}`), which is its
   bound; every written word from the permutation's 32 output bits (`output_w{j}`), gated
   on `live`. The padding row is all zeros with `zero_row_valid = true`, and
   `check_padding_identity` holds every leaf there to 1.
7. **Done.** `delegation.md` §4 is the frame table, and §10 says what S22 and S23 may append.
8. **Done.** One ecall, one invocation record, one row; `fill::keccak_f` writes exactly
   `trace.len()` live rows and zeroes the rest, and `crates/prover/tests/keccak.rs` asserts
   the shard's invocation count against the cycle profile's.

---

## Deviations and notes for the reviewer

1. **The height is `2^8`, not `2^16`, and the menu gained an entry.** The prompt's number
   is infeasible by three orders of magnitude; see "Read these first" 1. This is the only
   place where what shipped contradicts the prompt, and it went to the owner first.
2. **The gap check is a 38-bit decomposition, not S14's 19+19 lookup.** The prompt says
   "each read carries its own read-ts pair and 19+19 gap check from the S14 gadget". At
   `2^8` rows the timestamp channel's table does not fit (`BITS = 19 > 8`), so there is no
   channel to look up into. The statement is the same one — `gap ∈ [0, 2^38)`, so the read
   strictly precedes its own write — made as a sum of 38 booleans instead of two chunks in
   a table. It is strictly cheaper here: the circuit already commits 1,600 bits a row, so
   38 more cost 38 booleanity gates and no fraction tree, where a channel would have cost a
   table, a multiplicity column and four more tree levels.
3. **`FRAME_DELTA = 0`, not 3.** The prompt says an invocation's writes "land at the
   invocation timestamp within the uniform Δ ∈ {0..3} budget" and leaves the slot open. The
   first build put the frame's 50 RAM events at Δ = 3, where they collided with the add/sub
   family's `ram` query — `trace`'s frame builder assigns an event to the first free query
   of its `(space, Δ)` pair, and 50 RAM events at slot 3 had nowhere to go. The fix is a
   **split**: the invocation's frame rides Δ = 0 (`FRAME_DELTA`), the pc query's slot,
   which no *role* takes, so `(RAM, 0)` is a pair the frame builder recognises as "not this
   row's" and skips; the request's mirror query rides Δ = 3 (`ANCHOR_DELTA`) like any other
   slot-3 role. Both constants are in `constants::delegation` and `delegation.md` §4.1 and
   §5.1 are normative.
4. **A new address space rather than a reserved RAM range.** See "Read these first" 2.
5. **`ADD_SUB_LUI_AUIPC` changed shape, and every relation number in it moved.** This is the
   largest change in the stage that is not the new family, and it is worth reading before
   the diff:

   | | S20 | S21 |
   | --- | --- | --- |
   | queries | 7 | **8** |
   | `M` / `W` / `S` | 36 / 31 / 7 | **41 / 33 / 7** |
   | leaves a side | 8 (7 + 1 pad) | **8, no pad** |
   | `TIMESTAMP` obligations | 14 | **16** |
   | `TIMESTAMP` tree | 16 leaves | **32** |
   | row-wise gate lists | 5 | **6** |
   | enforcing gates | 46 | **55** |
   | lookups | 19 | **21** |
   | inner columns at `n = 20` | 298 | **368** |
   | relations at `n = 20` | 344 | **423** |
   | proof bytes at `n = 20` | 57,100 | **62,260** |
   | `add_sub.bin` SHA-256 | `4c797137…c2ea114b` | `3df1bda9…2114e518` |

   The chain is short: the `deleg` mirror query is the eighth, eight is a power of two so
   the product trees lost their pads, and eight queries give sixteen gap obligations, which
   with the table fraction is **seventeen** timestamp leaves — one past a 16-leaf tree. So
   the tree pads to 32 and the circuit is six row-wise lists deep. `2w + 1 ≤ 16` holds at
   `w = 7` and fails at `w = 8`: the cost is a step, not a slope, and a ninth query would
   pay nothing more. `docs/spec/constraint-manifest.md` §3 is rewritten from the new
   artifact, gate by gate.
6. **Program identity did not move for any pre-existing guest.** The SDK change edits
   `crates/guest-sdk/src/lib.rs`, so every guest's ELF *file* differs (a section-name string
   and `e_shoff`), but the loaded `ProgramImage` is byte-identical for all fifteen
   pre-existing guests, and identity is a function of the image. The committed ELF fixtures
   were refreshed with `cargo run -p kat-gen -- guests`; `crates/program/tests/vectors/
   identity.txt` is unchanged.
7. **The fixture is a digest.** See "Read these first" 3.
8. **Two quadratic scans were fixed, and neither is keccak's.** `keccak::artifact(8)` took
   over ten minutes before they were, and `crates/checker/tests/keccak.rs` likewise:
   `constraints::laws` held `Vec<PolyAddress>` and called `contains` over 354,762 slots in
   two places, and `crates/checker/src/lib.rs` had four more (a per-index
   `relations.filter().count()`, an `a.scratch[..i].any()`, a `position()` in
   `gate_operands`, and two `order.contains()`). All six are `BTreeSet`s, tallies or maps
   now. `validate` on the keccak artifact went **17.6 s → 0.87 s** and the checker suite
   **> 10 min → 5.9 s**. Nothing about the fixes is keccak-specific: they were latent in
   every artifact and only a wide one made them visible.
9. **`crates/checker/tests/tamper.rs` now runs at `--release`.** It carries the anchor twins
   over `guests/keccak-test`'s nine-shard block, and a debug build of that is not a
   reasonable gate. The `# DEFERRED` line in the root `CLAUDE.md` and in
   `.github/workflows/ci.yml` says `--release`.
10. **An unreachable refusal was removed rather than left in place.** `trace`'s archive
    reader refused a `present` mask naming "a role that does not exist". With eight roles
    the mask is a full `u8` and no value can do that, so the branch was dead; it is now a
    `const _: () = assert!(ROLES.len() == 8)` where it stood, which makes a ninth role a
    compile error rather than a silently dropped check. What catches a spurious `present`
    bit is the log replay, and the test case that used to cover the dead branch now asserts
    that refusal instead.
11. **The anchor twins' error classes are the measured ones, and two of them are not what
    the stage prompt's wording implies.** The prompt says a replay of two requests against
    one invocation "fails"; it does, but as `MemoryArgument` and not by the zeroing gates.
    The reason is specific to this family and is now written into `delegation.md` §5.2:
    switching an invocation off drops its **50 RAM frame accesses** with it, so the word at
    `base + 4j` loses a write the next invocation's `read_ts` still names, and repairing
    that means re-running the permutation. What the zeroings buy is that the pairing is
    **local** — a request whose mirror read is stamped is refused by a gate on its own
    shard, with no appeal to the frame's chains — so the three of them are asserted at
    **shard** level, where `verify_shard`'s order puts `Constraint` first. At block level
    `verify_global_memory` runs before any shard's checks (`block-proof.md` §3), so all of
    them would read `MemoryArgument` and say nothing about the gates. **A delegation family
    with a smaller frame would have nothing but those gates**, which is why they are in and
    why S22 and S23 inherit the shard-level assertion.

    This was found by running the suite, not by reading it: the twin asserted `Constraint`
    at block level and the first full deferred run said otherwise. The same run found the
    other half of deviation 12.
12. **`input_w{j}` is ungated, so a padding row's state bits are not free.** The gate needs
    no mask — every term is 0 on an honest padding row — but that also pins those rows'
    1,600 bits to the words they recompose, which are 0. The S21 twin's negative control
    had moved one and asserted the proof still verifies; it does not, and the control now
    moves two cells that genuinely are free (a gap bit and a frame-pointer headroom bit,
    both gated on `live`) and asserts separately that `in_bit(11)` alone **is** refused.
    `constraint-manifest.md` §12.10 records the distinction, because "every gate carries the
    mask" is the natural misreading of §12.5 and is wrong for exactly this gate and the 50
    `output_w{j}`, which carry it for the opposite reason.

---

## Measurements

All on one machine, 18 cores, macOS. `/usr/bin/time -l`'s `maximum resident set size`.

### The circuit

| | value |
| --- | --- |
| `M` / `W` / `S` / `V` | 204 / 3,560 / 0 / 0 |
| committed columns | 3,764 |
| inner columns at `n = 8` | 354,762 (`354,746 + 2n`) |
| relations at `n = 8` | 358,525 (`358,509 + 2n`) |
| depth at `n = 8` | 177 (`169 + n`) |
| enforcing gates | 3,763 (50 degree 1, 3,713 degree 2) |
| lookups | **0** |
| `to_bytes().len()` at `n = 8` | 100,254,040 |
| `ShardProof::to_bytes().len()` | 11,880,012 |
| gate shapes | Linear 170,248 · Product 38,526 · Quadratic 149,735 · TreeProduct 16 |

A keccak shard's proof is 173 times the largest CPU shard's, and almost all of it is final
claims: 358,540 of them at 32 bytes is 11,473,280, against 176,640 for its 1,380 sumcheck
rounds.

### The suites

| Suite | Result |
| --- | --- |
| `cargo test --workspace` | 1,001 passed, 70 `#[ignore]`d |
| `cargo test -p checker --test keccak` | 13 passed, 5.9 s |
| `cargo test -p emulator --test keccak` | 7 passed, < 1 s |
| `cargo test -p program --test delegation` | 9 passed, < 1 s |
| `cargo test -p constants --test keccak` | 4 passed, < 1 s |

The deferred suites' timings and peaks are under "Verification performed", below, beside
what each was at S20.

---

## Verification performed

On macOS (18 cores, 48 GB), every gate the root `CLAUDE.md` lists, at the final tree:

- `fmt --check` in all four workspaces, and `clippy -D warnings` in all four, plus the
  `prover/metrics` configuration;
- `cargo test --workspace`: **1,001 passed, 70 `#[ignore]`d** (960 and 65 at
  S20). The new tests that run in ordinary CI: `checker/tests/keccak.rs` 13,
  `emulator/tests/keccak.rs` 7, `program/tests/delegation.rs` 9,
  `constants/tests/keccak.rs` 4, `emulator/tests/guests.rs` 2, `trace/tests/log.rs` 1,
  `trace/tests/memory.rs` 1, and `checker/tests/tamper.rs`'
  `the_slot_constants_are_the_frames`, which is the one test in that file CI runs. The new
  ignored ones are `prover/tests/keccak.rs`' 2, `loader/tests/qemu.rs`'
  `keccak_falls_back_to_software_and_agrees`, `checker/tests/tamper.rs`' S21 twin and
  `program/tests/delegation.rs`' `reachability_survives_the_optimiser`;
- the `riscv32imac` build of `field`, `constants`, `transcript`, `poly`, `sumcheck`,
  `constraints`, `gkr-verify` and `verifier-core`;
- `cargo run -p kat-gen`, then the fixture diff: **only `crates/constraints/tests/vectors/
  keccak.txt` is new and nothing else moves.** `add_sub.bin` and `memory_frame_alu.bin`
  had already been regenerated over the new frame, and — the one that matters —
  `crates/program/tests/vectors/identity.txt` and `generic_table.txt` regenerate over the
  ceremony **byte for byte**: the SDK change moves every guest's ELF file but not its
  loaded `ProgramImage`, and identity is a function of the image (deviation 6);
- `cargo run -p kat-gen -- guests`, and `guests/keccak-test` builds at both profiles from
  its own directory.

**The QEMU suites, in a Linux container** (`colima` + `rust:latest` + `qemu-user`, the
recipe in `docs/guest-program-manual.md` §7) — all four green, which is where acceptance
5's fallback half and the `--release` half of static detachment actually run:

| Suite | Result |
| --- | --- |
| `loader --test qemu`, debug guests | 14 passed |
| `loader --test qemu`, `APOGEE_GUEST_PROFILE=release` | 14 passed |
| `emulator --test differential` | 3 passed |
| `emulator --test consistency`, debug | 8 passed |
| `emulator --test consistency`, release | 8 passed |

`keccak_falls_back_to_software_and_agrees` is the new case in the first two: under
`qemu-riscv32` the `0x501` ecall answers `-ENOSYS`, the SDK's software permutation runs,
and both keccak guests still exit 6 and 7 — so the six digests are the same on both paths,
at both optimisation levels.

**The deferred suites**, run once at the end of the progression under the owner's standing
instruction (root `CLAUDE.md`, "Commands"):

| Suite | Result | Wall | Peak resident | at S20 |
| --- | --- | --- | --- | --- |
| `checker --test tamper` | 11 passed | 2,568 s | 19.24 GB | 1,512 s / 17.0 |
| `checker --test logup` | 9 passed | 200 s | 18.76 GB | 198 s / 18.76 |
| `prover --test acceptance` | 7 passed | 361 s | 11.52 GB | 324 s / 8.64 |
| `verifier --test cli` | 2 passed | 44 s | 11.47 GB | 40 s / 8.56 |
| `prover --test control` | 2 passed | 61 s | 21.06 GB | 64 s / 18.03 |
| `prover --test alu` | 1 passed | 53 s | 30.28 GB | 67 s / 30.87 |
| `prover --test mem` | 1 passed | 61 s | 33.48 GB | 87 s / 32.31 |
| `prover --test block` | 7 passed | 804 s | **37.98 GB** | 779 s / 33.38 |
| `prover --test metrics` | 12 passed | 58 s | 11.62 GB | — / 8.6 |
| `prover --test keccak` | 2 passed | 130 s | **38.85 GB** | new |

**Two of those peaks are the larger of two runs, and the larger is the one to plan for.**
`prover --test block` measured 33.42 GB inside the batch and 37.98 GB on its own;
`prover --test keccak` measured 38.85 GB on its own and 33.48 GB inside the batch. That is
the spread S20 already recorded for `block` (25.3 against 33.4): the peak depends on what
the allocator is holding when the largest shard's forward pass runs, and it is not
reproducible to three digits. **Plan for 38 GB and 39 GB.** `prover --test keccak` is the
heaviest suite in the repository by memory, `checker --test tamper` the slowest by wall
clock.

**S21's eighth frame query raised some peaks and not others, and the split says why.**
`acceptance` went 8.64 → 11.52 GB, `cli` 8.56 → 11.47, `control` 18.03 → 21.06 and
`metrics` 8.6 → 11.62 — statements of one or two `2^20` shards, where
`ADD_SUB_LUI_AUIPC` *is* the largest thing held, so its 81-column base layer and
368-column inner circuit land straight on the peak. `alu` did not move at all
(30.87 → 30.28, inside the spread) and `mem` moved by about one shard's share
(32.31 → 33.48): those prove five and seven shards in parallel and their peak is set by
the widest family in flight — `SHIFT_BITWISE` and `MEM_SUBWORD` — which S21 did not
touch. `logup` proves no add/sub shard and is unchanged to three digits. So the cost of
the eighth query is real, bounded, and visible only where add/sub is the ceiling.

### What the batch found

Three suites failed on their first run, and **all three were stale test expectations, not
defects in the circuits or the verifier**. They are written up as deviations 11 and 12 and,
for the third, here — because it is not S21's:

**`prover --test block`'s `a4_a6` expected S16's error class from `verify_block`.** Two
statement twins — a flipped public output, and a key with another identity — expected
`Statement("the proof was made for another statement")` and got
`MemoryArgument("the statement's roots do not reconcile")`. The behaviour is right and is
**S20's**: the four memory challenges are drawn from the statement's own transcript (G10),
so re-deriving them from a different statement makes the honest roots' two products
disagree, and since S20's step-10b split `verify_global_memory` runs **before any shard is
verified** — which `verify_block`'s own doc comment says. The refusal is therefore stronger
than the one the test asked for, not weaker: no shard is touched at all.

The test predated the split and had never been re-run: `docs/handoff/S20-orchestration.md`
lists `prover --test block` under "**Owed, not run on the split tree**". Both twins now
expect the class they get, and each carries a second assertion that `verify_shard` on the
same proof still answers `Statement("the proof was made for another statement")`, so the
property the old expectation protected is pinned rather than dropped.

`prover --test keccak` is now **the heaviest suite in the repository**, past
`prover --test block`'s 33.4 GB. The cost is the delegation shard and not the shard count:
354,762 inner columns at `2^8` rows is 2.9 GB of forward pass before anything is
committed, and the block holds it beside six `2^20` execution shards being proved in
parallel.

**`checker --test tamper` moved to `--release`** (deviation 9). It now carries the anchor's
four twins over `guests/keccak-test`'s nine-shard block, and a debug build of that is not a
reasonable gate.

---

## Corrections after review

An owner review of `delegation.md` and the SDK shim, after the deferred batch and before
the merge, found one code defect and a family of documentation drift. All are fixed on
this branch. Nothing here changed a circuit, a proof byte or a fixture.

### The SDK's frame buffer was aligned by luck

`keccak256`'s 200-byte state was a bare `[u8; keccak::STATE_BYTES]`, whose Rust alignment
is **1**, and `permute`'s doc comment asserted it was "8-aligned … by construction". Both
halves were wrong. Disassembling the committed guest put the buffer at `sp + 0xc`
(release) and `sp + 0x4c` (debug), 16-aligned `sp` in both — that is **4**-aligned, not 8.
And nothing guaranteed even the 4: a probe compiled with this repo's own toolchain places
an align-1 local at `sp + 11`, an odd offset, at every optimisation level.

`docs/spec/delegation.md` §4 rule 1 requires a **word**-aligned base, which is what
`emulator::keccak_frame` checks (`base.is_multiple_of(4)`) and what `keccak`'s
`base_aligned` decomposes. So the failure mode was the bad kind: misaligned, the emulator
raises fatal `Misaligned` and returns no trace, while `qemu-riscv32` answers `-ENOSYS`,
never dereferences the pointer, runs the software fallback and gives the right digest —
the same binary correct under one executor and dead under the other, decided by codegen.

**Owner's decision: `align(4)`, not 8** — the number in the type is the number in the
spec. The buffer is now a `#[repr(C, align(4))] struct Frame([u8; STATE_BYTES])`, threaded
through `permute` and `keccak_f1600` so the type carries the guarantee all the way to the
ecall, with `const _: () = assert!(align_of::<Frame>() >= 4)` beside it. The window half
of the old comment was true and is kept, with its argument stated: the buffer is a stack
local, the stack lies below `__stack_top`, and `__stack_top` is the top of the RAM window.

`poseidon2_permute` takes a **caller-supplied** `&mut [u8; 96]` and has the same exposure.
It is inert today — every executor answers `-ENOSYS` — but the next delegation stage should
give it a `Frame` of its own rather than inherit this. *(S23 did: it is
`guest_sdk::recursion::Poseidon2Frame`, and `poseidon2_permute` copies through one.)*

### `delegation.md` carried the pre-split Δ, and one frozen order backwards

Deviation 3 above records the `FRAME_DELTA = 0` / `ANCHOR_DELTA = 3` split.
`execution-trace.md` §7 was updated for it; **§4.1 of this document was not**, and kept the
stage prompt's Δ = 3 under a constant name that does not exist
(`constants::delegation::DELTA`). Four lines said `+3` where the frame is meant — §4.1,
§5.3 twice, and §6.2's gap row — against five that correctly mean the anchor.

That mattered more than a wrong number usually does. `(RAM, 3)` **is** an entry of
`constraints::memory`'s query table — the `ram` query — so an S22 family that stamped its
frame writes at Δ = 3 as §4.1 instructed would have its first frame event filed into the
requesting row and its second reach `trace`'s "no free frame query takes" panic. That is
exactly the collision this stage's first build hit and deviation 3 fixed: the handoff
explained the fix while the normative spec still carried the cause.

§4.1 also stated the **frozen log order backwards** — "the pc query, then its roles … and
then the invocation's frame words", against `archive.rs`'s
`once(pc).chain(frame).chain(queries)`. The frame words ride Δ = 0 and sit *between* the
pc query and the roles. The paragraph ends "Nothing else reconstructs that order", so it
was the one statement in the section with no second source, and it was inverted.

Two more, both of which would have produced an unverifiable proof if followed:

- **§8's window formula** said `[4·cycle(first), 4·cycle(last) + 4)`, "the min and max".
  `prover::ts_window` computes `[4·cycle(row 0), 4·max cycle + 4)`. On a delegation shard
  the difference is not cosmetic: `2^8` rows hold as many invocations as the execution
  made, so the tail is padding and padding carries cycle 0 — the last row's cycle gives an
  end *below* the start, which step 4 of `verify_shard` refuses.
- **§7 contradicted itself** about the same guest: "a guest that links the SDK and does not
  call it declares nothing", four paragraphs above "A guest that links a shim but never
  calls it declares the family … and proves zero shards". `guests/keccak-unused` is the
  second. What decides it is reachability, not execution, and §7 now says so.

Four source comments carried the same drift: `keccak.rs`'s module header, its `leaf` doc
and its gap-gate comment — that last one contradicted by its own follow-up ten lines below
— and `emulator`'s dispatch arm, which cited the phantom `delegation::DELTA` 170 lines
above the code that uses `FRAME_DELTA`.

### Two invariants that were promised and not enforced

`ANCHOR_DELTA`'s documentation says it "must stay equal to"
`constraints::memory::FRAME_DELTA`'s `deleg` entry. Nothing held it. And nothing held the
load-bearing half of `FRAME_DELTA = 0` either — that `(RAM, 0)` is a pair **no** frame
query takes. Both are now `const _: () = assert!(…)` in `constraints::keccak`, so the
collision above cannot be reintroduced by editing a table.

### Stale API sketches

`add_sub::artifact`'s doc still described S16's **seven**-query frame and 14 timestamp
obligations, three lines above its own assertion message saying *eight*; S21 made it 8 and
16. `crates/constraints/CLAUDE.md`'s query-table block still showed the 8-entry table with
no `DELEG`. The root `CLAUDE.md` had been updated; that one had not.

### The guest ELF fixtures moved, and the pin table caught it

Refreshing the fixtures was not optional: `crates/emulator/tests/guests.rs` runs
`keccak-test` from the **committed** `crates/loader/tests/vectors/keccak-test.elf`, so
without a refresh the one test that exercises the delegation path through
`emulator::keccak_frame`'s alignment check would still be running the pre-fix buffer.
`loader/tests/qemu.rs` builds from source and was green at both profiles, but under QEMU
the ecall answers `-ENOSYS` and the frame pointer is never dereferenced, so it cannot
cover this.

`cargo run -p kat-gen -- guests` moved **six** ELFs, not the two that call `keccak256`:
`keccak-test` and `keccak-unused` from the real stack-layout change, and `echo`, `heap`,
`orderbook` and `consistency` at **identical byte size**. The size-preserving churn is
crate-hash propagation — editing `guest-sdk` changes its SVH, which changes the
fixed-width hash suffix in every `guest_sdk` symbol name those four retain. Any edit to
the SDK does this; it is not particular to this one.

That it was this change and not pre-existing drift was checked rather than assumed:
reverting `guest-sdk` to `HEAD` and regenerating brought **every** ELF back byte-identical.
A full `cargo run -p kat-gen` then showed nothing else moved — `identity.txt` pins
`guests/fib`, which does not reference `keccak256` and did not change, and the circuit
artifacts, `keccak.txt` and the global transcript tape are byte-identical, the circuit not
having changed.

`crates/loader/tests/differential.rs`'s `committed_fixtures_match_their_pins` failed on
the refresh, which is exactly its job — master rule 11's tripwire, digests in source so a
fixture refresh is a code edit a reviewer sees. Four pins updated. While there, three
guests turned out never to have been pinned at all — S20's `shards` and S21's
`keccak-test` and `keccak-unused` — so the table's own claim, "every committed fixture is
pinned by SHA-256", was false for precisely the newest three and for the fixture this
change touches. They are pinned now; `PINS` is 21 entries.

### The two deferred suites that read that ELF were re-run

`prover/tests/common/mod.rs` and `checker`'s twins load
`crates/loader/tests/vectors/keccak-test.elf` directly, so the batch's recorded results
were stale the moment it was refreshed. Both were re-run over the new fixture and both
hold:

| suite | result | wall | peak |
| --- | --- | --- | --- |
| `prover --test keccak` | 2 passed | 129.7 s | 31.2 GB |
| `checker --test tamper`, `s21_a5_a6` alone | 1 passed | 1,061.8 s | 19.2 GB |

The peak is inside the 31–39 GB spread already recorded for this suite; the wall times
are within a few seconds of the batch's. The twins were never at risk of a stale row
index — they locate the live invocation row by its `live` mask and the request row by its
delegation mask, not by number — but the input genuinely changed and the numbers above are
a measurement rather than an inference. The other eight deferred suites read guests this
change did not move.

### `reachability_survives_the_optimiser` is now a CI step

**Owner's decision.** §7 called `black_box`-survives-`opt-level = 3` the whole mechanism of
static detachment, and the only test of it was `#[ignore]`d and named in no CI step —
`every_guest_declares_exactly_what_it_links` covers every guest but at one profile only.
Measured before deciding: **0.56 s for all four builds, cold**, because a guest is three
small `no_std` crates and `core` comes prebuilt, and `build_profile` wipes its target
directory before and after. Far too cheap to defer, so it runs in CI.

---

## Open for the next stage

> **Editorial note, added at S23.** This section was written expecting S22 to be the next
> delegation stage. **S22 is cancelled and was never implemented** (`prompts/00-master.md`,
> "Stage register: cancelled stages"): there is no ecrecover delegation in this repository.
> S23 is the stage that answered these items — read "S22" below as "the next delegation
> stage", and `docs/handoff/S23-fr-poseidon2.md` for what each answer turned out to be.
> Items 1, 2, 5 and 6 were all decided there, and item 2 the opposite way from the guess
> here: the frame stayed at eight queries, but what selects the type is a **memory** column
> and not a family flag, because a leaf may read no `W` column.

1. **`docs/spec/delegation.md` §10 is the append list**, and S22 and S23 should read it
   before anything else. A second delegation family is: one `FamilyId`, one ecall number,
   one address space, one `DELEGATIONS` row, one frame table in `delegation.md`, one
   circuit, one fill, one `AnchorTwins`. Nothing in `verify_block`, `verify_shard`, the
   transcripts or the memory argument changes.
2. **The request side is not free of the ninth query yet.** Adding a *second* delegation
   family means a second mirror query in whatever family claims ecall cycles — a ninth
   frame query — unless the two share one. They can: the mirror's address space is the
   thing that separates them, and a shared `deleg` query whose space is selected by the
   row's family flag would keep the frame at eight. That trade was not taken at S21, since
   one family needs no selector, and it is the first thing S22 should weigh. Widening the
   frame again is the expensive direction only in `M` columns; the timestamp tree is
   already at 32 leaves and a ninth query costs nothing more there (deviation 5).
3. **The `present` mask is full.** A ninth *role* — not a ninth query of one family, but a
   ninth entry in `execution-trace.md` §7 — widens `trace::Row::present` past a `u8` and is
   a trace-archive schema change.
4. **A delegation family's shard is one `2^8` block of invocations and there is no batching
   knob.** A guest making more than 256 keccak calls gets more shards, each a full `2^8`
   forward pass whether it is full or not — 2.9 GB apiece. A guest making 257 pays for 512
   rows. Whether the height should be per-program rather than a constant is the same open
   question S12 raised about the execution families' heights, now with a much steeper
   penalty.
5. **The software fallback is a second implementation of keccak-f.** It has to be — it is
   `no_std` guest code and cannot link the emulator — and what holds the two together is
   `guests/keccak-test`'s digests, checked under both executors. Anyone editing either copy
   should run acceptance 3's two halves.
6. **A family whose frame is small enough would make the replay mountable, and its twins
   would then read `Constraint` where S21's read `MemoryArgument`** (deviation 11). What
   blocks the chain here is that an invocation drags 50 RAM accesses with it; a delegation
   whose frame is two words, or whose rows read nothing that chains, has far less of that
   and leans correspondingly harder on the three zeroings. `assert_anchor_twins_refused`
   already runs those at shard level, so an S22 family gets the same evidence without
   changing the helper — but if its block-level twins come back `Constraint` rather than
   `MemoryArgument`, that is a *stronger* result and the helper's two block assertions are
   the ones to revisit, not the shard ones.
7. **`crates/checker/tests/tamper.rs` is now 33 minutes and five statements.** It proves
   `guests/addsub`, `control`, `alu`, `mem` and `keccak-test`, each once honestly and again
   per twin. It is the slowest suite in the repository by wall clock even though
   `prover --test keccak` is the heaviest by memory. Splitting it per stage was considered
   and not done — one harness over one honest proof is what makes a twin cheap — but the
   next stage to add twins should weigh it.
