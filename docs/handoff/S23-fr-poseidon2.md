# S23 — the Fr-arithmetic and Poseidon2 delegation families

Branch `s23-fr-poseidon2`. Status: implemented; all ten acceptance items are met. Four
design questions went to the repository owner before any code and were answered; each
answer and what follows from it is in "Read these first". Several statements in the stage
prompt and in the frozen specs turned out to be contradictory or unimplementable — the
owner asked for those to be raised rather than routed around, and every one is written up
below with the evidence and the resolution.

S23 makes in-VM recursion contract. A guest that writes **ordinary `field::Fr` arithmetic**
and calls **`transcript::poseidon2_permute`** gets both delegated, because the guest-target
backends inside those two crates route them; it names no shim, declares both families
through reachability, and runs 86 times fewer proven cycles than the same source with the
backends off. `guests/recursion-ops` is that guest, and it proves as a ten-shard block and
verifies.

Normative documents written or amended this stage:

- **`docs/spec/delegation.md`**: §3 gains two registry rows and loses S22's promise; §4
  becomes width-generic; §5.1 gains the `deleg_space` column and the argument for it; §10
  is rewritten and gains **§10.1**, which records that S21's prescribed multi-type `AS`
  term is refused by `check_memory` and what replaced it; **§12** (Poseidon2) and **§13**
  (Fr-arithmetic) are new, and §13.4 is the guest-target backend.
- **`docs/spec/constraint-manifest.md`**: **§13** and **§14** are new, the master tables in
  §1.1, §1.2 and §1.3 carry the two families and add/sub's moved counts, §2.1 carries the
  `deleg_space` column and the `deleg` query's absent literal, §3 is rewritten from the new
  artifact, and Observations and Maintaining became §15 and §16.
- **`docs/spec/memory.md`** §2.1's `uses_q` line, which said `PRECOMPILE_POSEIDON2` where
  the code has proved a delegation since S21 and three since S23.
- **`docs/spec/shard-proof.md`** §8.5 and **`docs/spec/execution-trace.md`** §6: `0x0500`
  is no longer "no circuit yet".
- **`docs/spec/ecall-abi.md`** §3: `0x0500` rewritten, `0x0502` added.
- **`docs/spec/block-proof.md`**: two forward references to S22.
- **`prompts/00-master.md`**: a new "Stage register: cancelled stages" section recording
  that **S22 is cancelled and will not be implemented**, on the owner's instruction, and
  that every forward reference promising it a number or a table is stale by construction.
- Also updated to match: `docs/guest-program-manual.md`, `.github/workflows/ci.yml`, the
  root `CLAUDE.md`, and the `CLAUDE.md` of `constants`, `constraints`, `trace`, `emulator`,
  `program`, `prover`, `field`, `transcript` and `guest-sdk`.

`prompts/S23-fr-poseidon2.md` is committed unchanged.

---

## Read these first

### 1. The stage prompt's cargo feature is banned, and the seam it describes is a cycle

The prompt asks for a backend "selected by `#[cfg(target_arch = "riscv32")]` and a
'delegated' cargo feature on `field` and `transcript`". Master anti-goal 1 bans cargo
features outright with one closed exception, and `crates/prover/tests/one_feature.rs`
enforces it by reading every `Cargo.toml` in the repository and failing on any `[features]`
table but `prover`'s. Master rule 1 makes the master the authority, so the feature is out.

The prompt also asks for shims that take `&[Fr]` *and* for `field` to route through them.
Those are mutually exclusive: `&[Fr]` needs `guest-sdk → field`, routing needs
`field → guest-sdk`, and **cargo refuses the cycle even when one edge is target-gated** —
verified, not assumed:

```text
error: cyclic package dependency: package `a v0.1.0` depends on itself.
```

**The owner chose the transparent backend.** So:

- `field` and `transcript` each carry
  `[target.'cfg(target_arch = "riscv32")'.dependencies] guest-sdk = { path = "../guest-sdk" }`
  — a *target* dependency, not a feature. The workspace still has one build configuration,
  a host build never resolves the edge, and `one_feature.rs` stays green. Both directions
  were tested before anything was written: a host `cargo check`, a `riscv32imac` build, and
  the guest workspace, all green.
- `guest_sdk::recursion`'s shims therefore take **frames of bytes**, not `&[Fr]`. That is
  the one place the prompt's Deliver list is not met literally, and it is met in substance:
  the shims are in `guest_sdk::recursion`, their signatures are frozen below, and S26's
  guest reaches them through `Fr`'s own operators rather than by name.
- **The fallback is bit-identical by construction.** It is not a second implementation held
  equal by a test; it is `field`'s and `transcript`'s own code, one branch below the ecall.

### 2. One row is one operation, and it could not be otherwise

The prompt says both "each fr op occupies exactly one row … record ops/row = 1"
(must-be-exact 2) and "one fr-arith invocation carries 64 op-rows" (must-be-exact 8). Those
contradict each other, and the second contradicts the frozen ABI: `delegation.md` §1 says
"one row is one call" and §5 puts the anchor's two leaves on the invocation **row**, which
§10 forbids a family to redesign. An invocation spanning 64 rows would write 64 answer
tuples against one mirror read and **the honest prover would be refused**.

It is also unfixable inside GKR. A circuit here is row-independent — one gate list evaluated
over every row — so nothing can tie a row count to a frame's populated count. A batch would
have to be several operations in **one** row, and that buys nothing: the circuit's cost is
per operation either way, and the guest's marshalling, which dominates, does not amortize.

**The owner chose one operation per invocation.** `ops/row = 1` literally, the anchor
untouched, and no waste when a caller has one operation to do — which, with a transparent
`Mul`, is always.

### 3. The fr-arith frame carries `Fr`'s in-memory representation

Must-be-exact 4 asks for "canonical LE Fr". Taken as *the mathematical value*, that makes
the delegation a pessimization: `Fr` is Montgomery in memory, `to_bytes` is a Montgomery
reduction and `from_bytes` a Montgomery multiply, so a delegated multiply would pay about
twice the software multiply it replaces.

**The owner chose the in-memory representation.** Each 32-byte group is still a canonical
little-endian encoding of a field element — the circuit's borrow chain refuses one at or
above `p`, which is must-be-exact 4's substance and acceptance 3's test — but the element is
`x·R`. The three operations are then exactly what `Fr`'s `Add`, `Mul` and `inverse` compute
on those representatives, so the circuit's multiply carries the literal `R^-1` and its
inverse `R^2`, both derived from `constants::FR_R` rather than restated.

Poseidon2's frame makes the **opposite** choice, canonical mathematical values, for the
opposite reason: there the conversion is six Montgomery operations against 240 the
delegation removes, and it buys a circuit that is `poseidon2_permute` itself rather than
`poseidon2_permute` conjugated by a scaling (`delegation.md` §12.1, §13.2).

### 4. The delegation type rides a memory column, because a leaf may read no `W` column

`delegation.md` §10 told a later stage that the mirror's "leaf's `AS` term is the sum over
types of `(tag_t, m_t)`". **That is not implementable.** A memory leaf carries `γ_M` and the
three `α`s, and `check_memory`'s provenance rule refuses any gate that names a global memory
slot and reads a `W` column — a type selector is one. `crates/constraints/tests/memory.rs`'
`a_tuple_fed_from_a_witness_column_is_refused` is the standing proof.

The cheap alternative — one `deleg` query per type — is blocked too: each would need a
`trace::Role`, and `Row::present` is a full `u8` since S21.

**The owner chose to keep a tag per family and add one memory column.** A frame holding the
`deleg` query carries `deleg_space` at `M[1 + 5w]`, the requested type's address-space tag,
which `add_sub` pins with a degree-1 gate `deleg_space − Σ tag_t·is_deleg_t = 0` and which
`trace`'s frame builder writes from the mirror event's own space. `FRAME_SPACE[DELEG]` is
now **0** — a value no real tag takes — so a stale comparison against it matches nothing and
reaches a loud panic rather than dropping an event. `add_sub` gains one `M` column and two
`W` columns; the keccak circuit's bytes did not move at all.

---

## Frozen public API, as built

```rust
// constants — append-only
family::POSEIDON2: u32 = 10;   family::FR_ARITH: u32 = 11;   family::COUNT = 12;
family::CYCLE_OWNING[POSEIDON2] = false;      CYCLE_OWNING[FR_ARITH] = false;
family::DEFAULT_HEIGHTS[POSEIDON2] = 1 << 8;  DEFAULT_HEIGHTS[FR_ARITH] = 1 << 8;
ecall::PRECOMPILE_FR_ARITH: u32 = 0x0502;     // PRECOMPILE_POSEIDON2 = 0x0500 gets its circuit
address_space::DELEGATION_POSEIDON2: u8 = 5;  DELEGATION_FR_ARITH: u8 = 6;
address_space::DELEGATION: [u8; 3];           // every delegation tag, ascending
delegation::TYPES: [(u32, u32, u8, usize); 3];  // (family, ecall, address space, frame words)
mod poseidon2 { WIDTH = 3, WORDS_PER_LANE = 8, FRAME_WORDS = 24, FRAME_BYTES = 96,
                ROUNDS_FULL = 8, ROUNDS_PARTIAL = 56, ROUNDS = 64, SBOXES = 80 }
mod fr_arith { WORDS_PER_VALUE = 8, OPCODE_WORD = 0, A_WORD = 1, B_WORD = 9, OUT_WORD = 17,
               FRAME_WORDS = 25, FRAME_BYTES = 100,
               OP_ADD = 1, OP_MUL = 2, OP_INV = 3, OPS: [u32; 3] }

// field — the frame's codec, and the guest-target backend
pub fn to_memory_bytes(&self) -> [u8; 32];
pub fn from_memory_bytes(b: &[u8; 32]) -> Option<Fr>;   // None iff >= p

// guest-sdk — FROZEN, and S26's field and hash work rides on them
pub mod recursion {
    #[repr(C, align(4))] pub struct Poseidon2Frame(pub [u8; 96]);
    #[repr(C, align(4))] pub struct FrArithFrame(pub [u8; 100]);
    pub fn poseidon2(frame: &mut Poseidon2Frame) -> bool;   // false on exactly -ENOSYS
    pub fn fr_arith(frame: &mut FrArithFrame) -> bool;
}
pub fn poseidon2_permute(state: &mut [u8; 96]) -> bool;     // S10's, now over an aligned frame

// constraints::delegation — the frame, the anchor and the layered builder, shared by the
// two new circuits; `docs/spec/delegation.md` §4 and §5
pub const CYCLE; LIVE; BASE; ANCHOR_VALUE; HEAD_COLUMNS; WORD_ADDR; WORD_READ_TS;
pub const WORD_READ_VALUE; WORD_WRITE_VALUE; GAP_BITS; BASE_LOW_BITS; BASE_ROOM_BITS;
pub const VALUE_BITS = 256; CANONICITY_BITS = 264; WORDS_PER_VALUE = 8;
pub fn word(j, field);  gap_bit(j, bit);  base_low_bit(words, bit);  base_room_bit(words, bit);
pub fn memory_names(words);  witness_names(words);  frame_witness(words);  leaves_a_side(words);

// constraints::poseidon2 — docs/spec/delegation.md §12
pub const MEMORY_COLUMNS = 100;  WITNESS_COLUMNS = 4092;
pub fn value_bit(v, k, t);  diff_bit(v, k, t);  borrow_bit(v, k);   // v < 6: 3 in, 3 out
pub fn artifact(trace_vars: u32) -> CircuitArtifact;   pub fn channels() -> Vec<ChannelSpec>;  // EMPTY

// constraints::fr_arith — docs/spec/delegation.md §13
pub const MEMORY_COLUMNS = 104;  WITNESS_COLUMNS = 2576;
pub fn value_bit(v, k, t);  diff_bit(v, k, t);  borrow_bit(v, k);   // v < 3: a, b, out
pub fn selector(i);  prod();  inv();  is_zero();
pub fn artifact(trace_vars: u32) -> CircuitArtifact;   pub fn channels() -> Vec<ChannelSpec>;  // EMPTY

// constraints::add_sub — one selector per delegation type, and the tag's column
pub const IS_DELEGATION: [PolyAddress; 3];   // W[25..28]; IS_KECCAK is IS_DELEGATION[0]

// constraints::memory
pub fn deleg_space(width: usize) -> PolyAddress;                      // M[1 + 5w]
pub fn frame_query_takes(q: usize, space: u8, delta: u64) -> bool;    // the routing rule

// trace
pub enum AddressSpace { Reg, Ram, Pc, KeccakF, Poseidon2, FrArith }
pub const DELEGATION_SPACES: [AddressSpace; 3];
impl Role { pub fn space(self, delegation: Option<AddressSpace>) -> AddressSpace; }

// program
pub const DELEGATIONS: [(FamilyId, u32, u8, usize); 3];   // = constants::delegation::TYPES
pub fn delegation_space(family: FamilyId) -> Option<u8>;

// emulator
pub enum EmuError { .., DelegationFrame { pc: u32, detail: &'static str } }
```

**No new entry point.** `global_commit_phase`, `prove_shard`, `prove_block`, `reduce_shard`,
`verify_shard` and `verify_block` are byte-for-byte what S20 left them. Each family is one
arm in `constraints::family_circuit`, one in `prover::family_fill`, and one row in the
registry.

---

## What this freezes for later stages

1. **`guest_sdk::recursion`'s two shims and their frame types.** S26's verifier guest is
   contractually limited to them for its field and hash work — and reaches them through
   `Fr`'s operators and `poseidon2_permute`, not by name.
2. **`ops/row = 1` and `rows/permutation = 1`.** The cost model S26 sizes against. A guest
   doing more than 256 of either gets more shards; the heights are `ProgramParams::heights`
   and a program may raise them (see "Open for the next stage").
3. **The two ecall numbers and address-space tags.** `0x0500`/5 and `0x0502`/6, append-only.
   The next delegation family takes `0x0503` and tag 7.
4. **The frame encodings**: poseidon2's canonical, fr-arith's `Fr`'s in-memory
   representation. Both are checked canonical in-circuit.
5. **The `deleg_space` column and `frame_query_takes`.** A fourth delegation type adds a
   selector and three gates to `add_sub` and nothing else.
6. **The guest-target backend as a target dependency.** Not a cargo feature, in this stage
   or any later one.

---

## Artifacts

| Path | What |
| --- | --- |
| `crates/constraints/src/delegation.rs` | the frame, the anchor, the bounds, the canonicity chain and the layered builder the two new circuits share |
| `crates/constraints/src/poseidon2.rs` | the permutation circuit, ~480 lines |
| `crates/constraints/src/fr_arith.rs` | the arithmetic circuit, ~400 lines |
| `crates/constraints/tests/vectors/poseidon2.txt` | its shape and SHA-256 at `n = 8` |
| `crates/constraints/tests/vectors/fr_arith.txt` | ditto |
| `crates/checker/tests/poseidon2.rs` | the forward pass against `transcript::poseidon2_permute` **and** the committed `poseidon2_perm.txt` vectors, with six negative controls |
| `crates/checker/tests/fr_arith.rs` | the forward pass against host `field::Fr`, with nine negative controls |
| `crates/prover/tests/recursion.rs` | acceptances 4 and 9, `#[ignore]`d |
| `crates/emulator/tests/guests.rs` | the guest under the delegation ecalls, its KAT re-derived, and the invocation counts |
| `guests/recursion-ops`, `guests/recursion-unused` | the fixtures, exit 9 and 11 |
| `tools/kat-gen/src/delegation.rs` | the `delegation` group, three digests (was `keccak`) |

---

## Acceptance

1. **fr-arith differential.** `crates/checker/tests/fr_arith.rs`'
   `the_forward_pass_is_field_fr` builds a witness from **host `field::Fr`** and runs the
   circuit's forward pass over it: add, multiply, inverse, `inverse(0)`, a round trip
   `a·inverse(a) = 1`, and the operands 0, 1 and −1 where a wrong Montgomery factor would
   be least visible. If the circuit computed anything but what `Fr` computes, an honest
   witness would fail its own gates. `the_frame_encoding_is_frs_own_limbs` pins the
   encoding: `to_memory_bytes` decodes as a canonical `Fr`, and the element it spells is
   `x·ρ`. **The fallback is bit-identical because it is the same code** — `field`'s own
   software path, one branch below the ecall — and `guests/recursion-ops` checks its nine
   answers in-guest and exits 9 under both executors.
2. **poseidon2 differential.** `the_forward_pass_is_poseidon2_permute` runs the circuit over
   the `[0,1,2]` known-answer state and over random ones;
   `the_forward_pass_matches_the_committed_vectors` runs it over
   `crates/transcript/tests/vectors/poseidon2_perm.txt`, whose outputs came from
   `tools/transcript-ref`'s Plonky3 permutation, so a circuit that agreed with `transcript`
   and both with nothing else would still fail. The fallback is again the same code.
3. **Canonicity negative.** `a_non_canonical_operand_is_refused` sets an operand's eight
   words to `p` itself, with its bit decomposition and its whole borrow chain repaired, and
   the circuit refuses it at `a_below_modulus`. The emulator refuses it earlier still —
   `EmuError::DelegationFrame` — so an execution it let through is one no proof could cover.
4. **End to end.** `crates/prover/tests/recursion.rs`' first test: ten shards, the two
   delegation families' last and in id order, `verify_block` returns `Ok`, every shard also
   verifies through `verify_shard`, the roots reconcile across the CPU and both delegation
   shards together, and the block round-trips through its own bytes. 125 s, 26.0 GB peak.
5. **Witness tamper twins.** `crates/checker/tests/tamper.rs`'
   `s23_a5_a6_the_recursion_witnesses_and_anchors_are_pinned` corrupts a written lane word
   and an input lane word in poseidon2 and an op result and the product helper in fr-arith,
   each refused as `Constraint` on its own shard; the controls move a padding row's gap bit,
   which really is free, and still verify. The structural counts — ten shards, the two
   families last, each circuit's column counts and height — run in the same test.
6. **Anchor tamper, per family.** The same test fills `checker::AnchorTwins` twice and calls
   `checker::assert_anchor_twins_refused` by name, which runs S21's four twins and their
   control at the level that names what refuses each. The requesting rows of one type are
   told apart from the other's by the `deleg_space` column, which is that column's whole
   purpose.
7. **Selector discipline.** `a_row_claiming_two_operations_is_refused` is chosen so that no
   other gate catches it first: the operation codes are 1, 2 and 3, so `add + mul` spells
   the same opcode word as `inv`, and on an inverse row a prover may set `f_add` and `f_mul`
   instead while `opcode_rule` still holds. `one_op_a_live_row` is the only thing that
   refuses it, which is the sharpest form of this acceptance.
8. **Structure assertion.** `check_shape` runs inside `artifact()` on **the emitted
   artifact** for both families — column counts, no setup column, no obligation, no virtual
   table, the depth, every layer's width against its three regions (poseidon2), and every
   named relation present by name. `crates/emulator/tests/guests.rs`'
   `recursion_ops_invokes_both_families` counts the honest trace's invocations: 2
   permutations and 29 operations, one row each. `fr_arith` additionally asserts that no
   relation's name contains `assume`.
9. **Detachment and zero shards.** `crates/program/tests/delegation.rs` holds all nineteen
   committed guests to declaring exactly what they link, and
   `reachability_survives_the_optimiser` covers `recursion-ops` at **both** optimisation
   levels. `guests/fib` declares nothing. `crates/prover/tests/recursion.rs`' second test
   proves `guests/recursion-unused`: both families in the config, in the descriptor and in
   the transcript's group list, and **zero shards** of each.
10. **Validators, CI, and the measured ratio.** `the_circuit_keeps_every_rule` runs
    `validate`, `check_laws`, `check_padding`, `check_padding_identity`, `check_memory` and
    `check_discharge` on each artifact; `artifact()` itself panics on any of them, so
    neither circuit can be built unlawful. The degree ceiling is `validate`'s and every new
    gate is degree ≤ 2. Both fixtures are regenerated and diffed in CI. The measured ratio
    is under "Measurements": **86×** at `--release`, on the same guest and the same
    executor.

---

## Must-be-exact, item by item

1. **Done.** Both frame tables are `delegation.md` §12.1 and §13.1, and no number is spelled
   twice: `constants::delegation::TYPES` is the registry, `program::DELEGATIONS` *is* that
   array, the shims read their numbers out of their declaration records, the emulator
   dispatches on `program::delegation_family`, and `crates/constants/tests/ecall_abi.rs`
   holds the document to the module in both directions and by count.
2. **Done, and it is the literal reading.** One operation, one invocation, one row. See
   "Read these first" 2 for why the prompt's other reading is unbuildable.
3. **Done.** The circuit is `transcript::poseidon2_permute`'s rounds, constants and matrices,
   with `constants::POSEIDON2_RC3_*` read directly and no second copy. Acceptance 2 is the
   evidence, over the crate *and* over the committed vectors.
4. **Done, with the encoding recorded.** Canonicity is enforced in-circuit by an eight-limb
   borrow chain against `p`; the encoding is canonical little-endian, of `Fr`'s in-memory
   representative for fr-arith and of the mathematical value for poseidon2 ("Read these
   first" 3).
5. **Done, and the prompt's constraint set was not enough.** `a·out = 1 − z` with booleanity
   on `z` lets a prover set `z = 1` at `a ≠ 0` and prove `inv(a) = 0`; adding `a·z = 0`
   fixes that and still leaves `out` free at `a = 0`. The third gate, `z·inv = 0`, is what
   makes `inv(0) = 0` a constraint rather than prose, and
   `a_free_inverse_at_zero_is_refused` is its negative control.
6. **Done.** Both families use `constraints::delegation`'s anchor — the same two leaves, the
   same three zeroings, the same addressing rule — and
   `checker::assert_anchor_twins_refused` runs against each.
7. **Done in substance, not in signature.** The shims are in `guest_sdk::recursion` and
   frozen above; they take frames of bytes rather than `&[Fr]` because cargo refuses the
   cycle ("Read these first" 1). The fallbacks are `field`'s and `transcript`'s own code,
   which is bit-identical by construction.
8. **Done, with the batch dropped.** `delegation.md` §13.1 fixes the granularity at one
   operation per invocation and says why; there is no populated count and no no-op selector,
   because a row is live or it is padding.
9. **Not done, deliberately, and it is the prompt's one factual error about GKR.** `x²` is
   **computed**, not committed. A committed helper is readable by gate list 0 alone
   (`docs/spec/gkr.md` §2), so the 80 of them would be carried up through every layer that
   had not consumed them yet: 5,040 pass-through columns against 736 of actual work. The
   two multiplication layers per S-box the item asks for are there either way; computing
   `x²` costs one more gate list a round and is *stronger*, because a layer value is forced
   by its gate where a committed one needs an enforcing gate to be forced at all.

---

## Deviations and notes for the reviewer

1. **The cargo feature is out, and the shims take bytes.** "Read these first" 1.
2. **One operation per invocation, not 64.** "Read these first" 2.
3. **The fr-arith frame is `Fr`'s in-memory representation.** "Read these first" 3.
4. **The delegation type rides `deleg_space`, an M column.** "Read these first" 4; the
   alternative §10 prescribed is refused by `check_memory`.
5. **`x²` is computed, not committed.** Must-be-exact 9.
6. **`constraints::delegation` is a shared module, and `keccak` does not use it.** S21's
   circuit is frozen, its artifact is 100 MB and its fixture is a digest; rewriting it to
   call the shared module would put a frozen artifact's bytes at risk for tidiness, which
   "build conservatively" refuses. What is in `delegation.rs` was written from `keccak.rs`,
   and the keccak digest is **unchanged** by this stage, which is the evidence that nothing
   of S21's moved.
7. **The linker keeps declaration records per *section*, not per symbol.** With all three
   records in one `#[link_section = ".rodata.apogee.delegations"]`, every guest that reached
   any shim declared every family — `guests/echo` declared `KECCAK_F` — and static
   detachment said nothing at all. Each record now has a section name of its own. This was
   found by `crates/program/tests/delegation.rs` on the first run, not by reading, and it is
   the kind of failure that would have shipped silently: the extra families cost a config
   entry and a transcript group and nothing else visible.
8. **The one shadowing arm in the emulator.** `ecall::PRECOMPILE_POSEIDON2 => -ENOSYS` sat
   *above* the generic delegation arm, so registering `0x0500` would have left it answering
   `-ENOSYS` forever, with no compile error and the guest silently taking its software path.
   It is deleted, and the dispatch is now one `match family` with a `panic!` on a
   `DELEGATIONS` row nobody implemented.
9. **`guests/opcodes` called `0x500` directly** to cover the `ecall` instruction over a
   number nothing answers. That number is now a delegation the guest does not declare, which
   is the fatal `DelegationFamilyAbsent`. It calls `0x5ff` instead, which is what it always
   meant.
10. **Three existing guests changed behaviour, correctly.** `guests/echo`, `vault` and
    `consistency` link `field` and `transcript`, so they now declare both families and take
    the delegated path under this VM. `echo`'s stderr says `precompile=accelerated` where it
    said `precompile=software`; under `qemu-riscv32` it still says `software`, which is
    `crates/loader/tests/qemu.rs`'. No proven statement changed: none of the three is a
    fixture any prover test proves.
11. **`read_tuple(DELEG)` panics, by design.** The delegation mirror's `AS` term names a
    column whose address depends on the family's frame width, so there is no standalone
    tuple to return and answering with a literal would answer wrongly.
    `the_delegation_mirror_has_no_standalone_read_tuple` is the negative control. Nothing
    calls it: `gkr-verify`'s boundary reads `read_tuple(0)` and `read_tuple(1)` only.
12. **The `ADD_SUB_LUI_AUIPC` artifact moved, and with it every key and fixture.**

    | | S21 | S23 |
    | --- | --- | --- |
    | `M` / `W` / `S` | 41 / 33 / 7 | **42 / 35 / 7** |
    | enforcing gates | 55 | **62** |
    | relations at `n = 20` | 423 | **430** |
    | inner columns at `n = 20` | 368 | **368**, unchanged |
    | proof bytes at `n = 20` | 57,100 | **57,660** |
    | `add_sub.bin` SHA-256 | `3df1bda9…2114e518` | `96012f12…af8e811c` |

    Enforcing gates produce no inner column, which is why the circuit grew by seven gates
    and no width. The seven are two selectors' booleanity, two `is_an_ecall` gates, two
    number gates and `deleg_space_rule`; `ecall_is_exit`, `deleg_mask_rule`, `exit_status`
    and `next_pc_rule` each gained terms on an existing product's other factor, which is the
    same shape S21 used and keeps every one of them at degree 2.

---

## Measurements

All on one machine, 18 cores, macOS. Guest cycle counts are `Execution::cycle_count` from
`crates/emulator`, which is the number of proven cycles.

### The circuits

| | `POSEIDON2` | `FR_ARITH` |
| --- | --- | --- |
| `M` / `W` / `S` / `V` | 100 / 4,092 / 0 / 0 | 104 / 2,576 / 0 / 0 |
| committed columns | 4,192 | 2,680 |
| gate lists at `n = 8` | 201 (193 + 8) | 14 (6 + 8) |
| inner columns at `n = 8` | 2,020 | 142 |
| relations at `n = 8` | 6,268 | 2,843 |
| enforcing gates | 4,248 (54 degree 1, 4,194 degree 2) | 2,701 (46 / 2,655) |
| lookups | **0** | **0** |
| `to_bytes().len()` at `n = 8` | 2,056,361 | 1,063,214 |
| forward pass a shard | 51 MB | 23 MB |
| gate shapes | Linear 1,594 · Product 142 · AffineProduct 80 · Quadratic 4,436 · TreeProduct 16 | Linear 58 · Product 62 · Quadratic 2,707 · TreeProduct 16 |

Both are small beside `KECCAK_F`'s 354,762 inner columns and 2.9 GB: a delegation shard of
either costs about 2% of a keccak one.

### The contraction (acceptance 10)

`guests/recursion-ops`, the same source and the same executor, with the guest-target
backends on and off. "Off" is a temporary edit reverted immediately; the committed tree has
them on.

| build | backends off | backends on | ratio |
| --- | --- | --- | --- |
| `--release` | 2,865,234 cycles | **33,164** | **86.4×** |
| `debug` | 20,103,567 cycles | 322,764 | 62.3× |

The run makes **2 `POSEIDON2` invocations and 29 `FR_ARITH` ones** at either optimisation
level. The release figures are the ones to size against: `2,832,070` cycles of software
work replaced by 31 delegated calls plus their marshalling, which is about **91,000 cycles
of software per delegated call** on this mix — dominated by the two permutations, each of
which is 240 Montgomery multiplies and 80 round-constant decodes.

Isolating the two backends at `debug` (poseidon2 off / field on: 14,509,170; field off /
poseidon2 on: 11,126,971) shows what the split costs: neither alone is worth much, because
each one's software path calls the other's operations.

### The suites

| Suite | Result |
| --- | --- |
| `cargo test --workspace` | see "Verification performed" |
| `cargo test -p checker --test poseidon2` | 8 passed, 0.6 s |
| `cargo test -p checker --test fr_arith` | 12 passed, 0.1 s |
| `cargo test -p program --test delegation` | 9 passed, 1 `#[ignore]`d |
| `cargo test -p emulator --test guests` | 15 passed |

---

## Verification performed

See "Verification performed, final tree" below for the full run.

---

## Open for the next stage

1. **The heights are `2^8`, and S26 will want more.** A `2^8` delegation shard holds 256
   operations or 256 permutations. A recursion verifier does far more, and the shard count
   is what a `BlockProof` carries and a verifier walks. The heights are
   `ProgramParams::heights`, so a program may raise them without a protocol change:
   `2^16` gives 65,536 a shard at 5.9 GB (fr-arith) and 13 GB (poseidon2) of forward pass.
   Nothing between `2^8` and `2^16` is on the menu, and adding `2^12` would be a
   frozen-constant amendment of the kind S21 already made once.
2. **Marshalling is 80% of a delegated operation's proven cost.** A delegated multiply is
   ~24 stores and ~8 loads in the guest, all `MEM_WORD` rows, against 25 frame words in the
   delegation shard. The obvious next move is a **two-level frame** — the guest hands over
   pointers to the `Fr` values it already holds, and the circuit dereferences them — which
   `delegation.md` §4 does not allow today and which would cut the guest side by about
   three quarters. It is an ABI change and it needs its own argument about bounding the
   pointers.
3. **The three delegation families' anchor twins all read `MemoryArgument` at block level.**
   S21's deviation 11 predicted a family with a smaller frame might read `Constraint`
   instead, which would be a *stronger* result. Both S23 families still drag dozens of RAM
   frame accesses with an invocation, so they do not test that; a family whose frame is two
   words would.
4. **`guests/echo`, `vault` and `consistency` now declare both families.** That is correct
   and tested, but it means any guest linking `field` carries two more circuits in its
   verifying key. A guest that wants neither must not link `field`, which is a real
   constraint on fixture design and worth knowing before writing the next one.
5. **`Fr::inverse` still has a software path on the guest target**, reached only when the
   executor answers `-ENOSYS`. It is 383 Montgomery multiplies, each of which is itself a
   delegated call on a VM that has the fr-arith circuit and would be reached only under
   QEMU. Nothing is wrong with that; it is simply the slowest code path in the repository
   and worth naming.
6. **The manifest's §3 was rewritten from the artifact, and §15's observations were not
   re-derived.** A stage that changes `ADD_SUB_LUI_AUIPC` again should re-read §15 for
   anything the new accounting turns up.
