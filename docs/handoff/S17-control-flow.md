# S17 — The jump/branch/slt family

Branch `s17-control-flow`. Status: implemented; all nine acceptance items are met, in the
forms the repository owner chose (see "Read these first"). Five questions went to the
owner — four before any code, one after the adversarial review — and each was answered
with the recommended option.

S17 proves the second execution family. `guests/control` is a hand-written guest over the
two families S17 proves — add/sub/lui/auipc and jump/branch/slt — that checks every jump,
branch and comparison it makes and exits with the number of checks, 16. It is built,
decoded, traced, compared with `qemu-riscv32` instruction by instruction, and proved as
three shards — `INIT_TEARDOWN` at `2^16`, `ADD_SUB_LUI_AUIPC` and `JUMP_BRANCH_SLT` at
`2^20` — each verified through `verify_shard` against one statement. The family's twelve
instructions are one circuit whose comparison settles signed and unsigned ordering in one
degree-2 equation, and the family is the first to read the generic channel, whose packed
table is now bound through the SRS digest.

Normative documents written or amended this stage:

- **`docs/spec/jump-branch-slt.md`** (new): what the circuit reads from S11's table, the
  columns, the two gadgets, the gates and lookups, why it is sound, the generic table's
  binding, what it does not do, and the fixture.
- **`docs/spec/shard-proof.md`**: §3, the SRS digest, now over the generic table too, and
  §9, the key's wire form, which gains the table's 192 bytes — both amendments to S16's
  frozen text, so every S16 key's bytes and SRS digest change — and, to match, decision 2,
  §2 (a note: the table has no step of its own), §4, §5.1–§5.2, §7.1–§7.2, §8.5 and §11.
  **`docs/spec/srs.md`** §2.0, §4 and §6 (what the digest covers, and why the table
  belongs in it); **`docs/spec/transcript.md`** §8 (tag 41, inside the digest's sponge);
  **`docs/spec/memory.md`** §6.1 (a note: the absorb order gains no message) and §2.1, §5,
  §8 and §9, **`docs/spec/lookup.md`** §13 and **`docs/spec/mercury.md`** §10 (status
  notes: what S17 discharged, why the table's `S` columns are admitted, what the digest
  now binds).
- **`docs/spec/constraint-manifest.md`**: the family's entry, §4, and the sections after it
  renumbered.
- Also updated to match: `docs/GLOSSARY.md`, `docs/guest-program-manual.md`, the root
  `CLAUDE.md`, `.github/workflows/ci.yml`, and the `CLAUDE.md` of constants, constraints,
  program, prover, verifier-core, verifier and checker. `crates/srs`'s `CLAUDE.md` and
  module doc said no digest existed anywhere, stale since S16; they now say this crate has
  none and name the one that exists.

`prompts/S17-control_flow.md` is committed unchanged. `prompts/00-master.md` is not
edited and needs no edit: the global transcript's absorb order is S16's, the SRS digest
still in its place, and only what that digest covers grew.

---

## Read these first

Four questions went to the owner before any code and a fifth after the review, each with
the argument and the price. The answers are the design.

1. **S11's decoded table stays as it is.** The prompt's five-bit mask — JAL, JALR,
   SLT-family, BRANCH, RD_IS_ZERO, legal set `{1, 2, 4, 17, 18, 20, 24}` — and its extra
   decoder columns (`cmp_imm`, a separate displacement, `sc`, the weight triples)
   conflicted with S11's frozen table for this family, `pc next_pc rs1 rs2 rd imm
   extra_mask` with a twelve-bit one-hot mask. Building the prompt's layout would have
   needed twelve lookup-tuple columns where `lookup_channel::MAX_TUPLE` is seven, a wider
   field mask than S11's `u8`, and new identity pins for every program that jumps.
   Everything those columns carry is a linear form over the twelve bits the table already
   has (`docs/spec/jump-branch-slt.md` §1), so the circuit reads them from there, and the
   legal set is the twelve one-bit masks.
2. **The generic table is bound through the SRS digest** (answer 5, which replaced answer
   2). Before any code the owner chose to carry the table's commitments in the key, per
   family, and absorb them as a new global-transcript message. The adversarial review
   then showed what that left open: the one value a verifier takes on trust besides
   identity is the SRS digest, which covered only the `SrsVerifier`, so a key carrying a
   poisoned `U16GetSign` table's commitments loaded under a trusted identity and a trusted
   digest, and every comparison it proved was the prover's choice. The table's three
   commitments are a constant of the ceremony — one set at every height from `2^18`, the
   table being zero past its entries and a commitment reading it as coefficients — so the
   fifth question offered to fold them into the digest. Now every key carries one triple,
   `generic_table`, the digest is Poseidon2 over the `SrsVerifier` and then that triple
   (tag 41, twelve limbs, in the digest's own sponge), the global transcript is S16's, and
   a family that reads the channel opens the triple after identity's setup commitments.
   Identity still does not bind it (the owner's S16 answer 8).
3. **Every `next_pc` the family writes is range-checked even.** The prompt says no
   alignment constraint is needed, because the next fetch fails at an odd address. That
   misses `HALT_PC = 1`, which is odd and has no next fetch: a `jalr` whose `rs1 + imm` is
   1 could keep bit 0 and write `HALT_PC`, and a program that would crash there — jumping
   to pc 0 — would be proven to exit cleanly with whatever `a0` held. `memory.md` §5 had
   listed "jalr's bit-0 clear" as this stage's. The fix is one more `RANGE16` obligation.
4. **One consolidated fixture guest**, `guests/control`, not one per instruction — the
   owner's standing preference — with tests that check it runs every instruction and every
   case the acceptance names.
5. **Fold the table into the SRS digest** — the question the review raised; answer 2
   above records the design it gave.

Readings announced with the questions, which nobody objected to:

- **No link wrap bit.** The link is the table's fall-through, not a sum; it cannot wrap and
  is still range-checked.
- **`eq`'s is-zero gadget is enabled by `m_pc`**, not the constant 1, so the all-zero
  padding row stays valid. S14's x0 rule is the same gadget, and is now built on the public
  `gadgets::is_zero` with its bytes unchanged.
- **Must-be-exact 8** — "four gate layers above the base plus one output layer" — is read
  as: every comparison intermediate is a committed column, every semantic gate is in gate
  list 0, and the depth is the frozen assembly's, 25 transitions at `2^20` as add/sub's.
- **Acceptance 7's `next_pc` twin** moves a `jalr`'s `rs1` with it, so that every gate and
  bound holds and the memory argument alone refuses it; a lone `next_pc` change is the
  `next_pc` gate's. Moving `rs1` breaks the register's chain as well as the pc's, so a
  second twin also moves the add/sub row that wrote that `rs1`: the pc's chain is then the
  only one that does not balance, and the refusal is still `MemoryArgument`.

Readings recorded after the review:

- **One wrap bit for every target.** The prompt's JALR paragraph gives the jalr sum "its
  own wrap bit"; its next-pc paragraph asks for one wrap bit "applying to whichever target
  the selectors produced". The circuit has the one `pc_wrap`: on a live row one kind bit
  is set and `taken` is 0 off the branches, so one sum is selected, each is below `2^33`,
  and `next_pc` is range-checked and even, which makes the wrap unique
  (`docs/spec/jump-branch-slt.md` §4.3).
- **Acceptance 6 is shown with a `jalr`**, whose target is data, where the prompt says "a
  branch". The refusal is the next row's decoder lookup, whatever instruction wrote the
  pc, so the demonstration covers a branch as well.

---

## Frozen public API, as built

**`crates/constraints`** (`#![no_std]`):

```rust
pub mod gadgets {
    pub fn is_zero(x: &[(Coeff, PolyAddress)], inv: PolyAddress, z: PolyAddress,
                   enable: PolyAddress) -> [GateDef; 2];
    pub struct Comparison {
        pub prefix: String, pub selector: PolyAddress, pub signed: Vec<PolyAddress>,
        pub lhs: PolyAddress, pub lhs_hi: PolyAddress, pub lhs_sign: PolyAddress,
        pub rhs: PolyAddress, pub rhs_hi: PolyAddress, pub rhs_sign: PolyAddress,
        pub lt: PolyAddress, pub gap: PolyAddress, pub gap_hi: PolyAddress,
    }
    pub fn comparison_equation(c: &Comparison, word_bits: u32) -> GateDef;
    pub fn comparison(c: &Comparison) -> (Vec<(String, GateDef)>, Vec<LookupExpr>);
}
pub mod jump_branch_slt {
    pub const DECODED: [PolyAddress; 6];          // W[7..13]
    pub const KINDS: [PolyAddress; 12];           // W[13..25]
    pub const CMP_RHS, RS1_HI, RS1_SIGN, CMP_RHS_HI, CMP_RHS_SIGN, LT, CMP_GAP, CMP_GAP_HI,
              EQ, EQ_INV, TAKEN, JALR_DROP, PC_WRAP, NEXT_PC_HI, RD_HI: PolyAddress;   // W[25..40]
    pub const MULTIPLICITIES: [PolyAddress; 4];   // W[40..44]
    pub const TABLE_WIDTH: usize = 7;             // S[0..7]
    pub const GENERIC_TABLE: [PolyAddress; 3];    // S[7..10]
    pub const LEGAL_MASKS: [u32; 12];
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}
// family_circuit(JUMP_BRANCH_SLT, n) for n in 19..=MAX_TRACE_VARS
```

**`crates/constants`**: `transcript_tags::GENERIC_TABLE = 41` (scalars);
`generic_table::{WIDTH = 3, AND_BASE = 0, SIGN_BASE = 256}`, moved from
`program::lookup_tables`, which keeps the names as aliases.

`FamilyCircuit::reads_generic_table(&self) -> bool`: whether any of its channels is
`GENERIC`.

**`crates/program`**: `lookup_tables::GENERIC_LOG_HEIGHT = 18` and
`lookup_tables::generic_commitments(&Srs) -> [G1Affine; GENERIC_WIDTH]`, the table's
commitments at that height, which are its commitments at every height above it.

**`crates/verifier-core`**: `VerifyingKey::generic_table: [[u8; 64]; 3]`, on the wire as
192 raw bytes between `srs_verifier` and `srs_digest`;
`srs_digest(&[u8; 320], &[[u8; 64]; 3]) -> Fr`; the load rules; and the table after
identity's commitments in `reduce_shard`'s opening claim for a family that reads it.

**`crates/verifier`**: `load_verifying_key` decodes the three table points too.

**`crates/prover`**: `family_fill(JUMP_BRANCH_SLT)`; `ProverSetup::new` fills the key's
generic table and the digest over it.

**The trace-buffer schema** (`crates/trace`) is S12's `FamilyTrace`, unchanged: the family
routes its rows exactly as add/sub does. Per kind, the queries a row holds are `jal`: `rd`;
`jalr`, `slti`, `sltiu`: `rs1`, `rd`; `slt`, `sltu`: `rs1`, `rs2`, `rd`; a branch: `rs1`,
`rs2` — `docs/spec/execution-trace.md` §4 — and the frame, `pc rs1 rs2 rd`, is their union.

**The fixture suite** is `guests/control`, its committed ELF
`crates/loader/tests/vectors/control.elf`, and the circuit fixture
`crates/constraints/tests/vectors/jump_branch_slt.bin`.

---

## What this freezes for every later stage

1. **`docs/spec/jump-branch-slt.md`** in full.
2. **The family's circuit** — its name, its column map (§2), its 42 gates and 22 lookups,
   its four channels in output order — and its fixture `jump_branch_slt.bin`.
3. **The legal masks** are S11's twelve one-bit values, `LEGAL_MASKS`.
4. **The two gadgets' signatures and gates** (§3): S18 builds its magnitude comparisons and
   `rem ≠ 0` on them, S19 `amomin`/`amomax`.
5. **The SRS digest's second message** (tag 41, the table's twelve limbs), the key's
   `generic_table` and its wire position, the load rules, and the opening's `S` list
   order: identity's, then the generic table's.
6. **The `next_pc` evenness obligation** as part of the family, and the rule behind it: a
   family that computes a pc keeps it off `HALT_PC`.
7. **`constants::generic_table`** as the table's layout constants.

---

## Artifacts

| Path | Size | SHA-256 | What |
| --- | --- | --- | --- |
| `crates/constraints/tests/vectors/jump_branch_slt.bin` | 76,980 bytes | `99094d63daa97a1a1cfa5f61f0b9124fa376e8c7e045cdfa0c213ae7742c1305` | `jump_branch_slt::artifact` at `trace_vars` 22 |
| `crates/loader/tests/vectors/control.elf` | 9,392 bytes | `88f5b0ccf00b889c50ec81892a44550b5d19bde75f5fa388cea4027898aecdaa` | the guest, dev profile |
| `crates/program/tests/vectors/generic_table.txt` | 994 bytes | `3754bcd72867a667e71fd6044dae27f63d5ae0c8e160690143bfe0853ff045f8` | the packed table's commitments over the PSE ceremony — one set of three points, checked equal at `2^18`, `2^20` and `2^22` |

No other fixture moved: every S14 frame fixture, `add_sub.bin`, the identity pins and every
other guest ELF regenerate byte for byte. S16's keys and SRS digests do change — the key
gains the table and the digest covers it — but no fixture pins either.

**Proof sizes**, fixed per key and family: a `JUMP_BRANCH_SLT` shard at `2^20` is
**61,612 bytes** (25 transitions, 20 rounds at layer 0, 75 base claims — 21 `M`, 44 `W`,
10 `S`).

---

## Acceptance

File paths are under `crates/`. Every test listed passes; the ones marked *deferred* are
`#[ignore]`d and were run locally ("Verification performed").

| # | Item | Where | Result |
| --- | --- | --- | --- |
| 1 | Per-instruction differential and proof | `emulator/tests/differential.rs` (`control` in `SUITE`), `loader/tests/qemu.rs::control_passes_its_checks`, `checker/tests/jump_branch_slt.rs::the_guest_runs_the_acceptance_matrix`, `prover/tests/control.rs::a1_…` (deferred) | Every one of the twelve instructions runs in `control`, whose register file matches QEMU's at every instruction; the statement's three shards prove and verify, with the shapes from the circuit |
| 2 | Exhaustive reduced-width comparison; the full-width pins | `checker/tests/jump_branch_slt.rs::exactly_one_lt_and_gap_…`, `::the_pinned_full_width_comparisons_…` | At a 6-bit word, every operand pair signed and unsigned has exactly one `(lt, gap)`, the ISA's, in every sign quadrant, through the gadget's own gate; `BLT(0x80000000, 1)` taken, `BGE(1, 0x80000000)` taken, `BLTU(0x80000000, 1)` not taken and a mixed-sign `slt` each answer correctly, and each flipped is refused — by the equation, and with the gap moved by `2^32` by the gap's range alone |
| 3 | The control-flow matrix | `jump_branch_slt.rs::the_control_flow_matrix_…`, `::the_guest_runs_the_acceptance_matrix` | Taken and not-taken branches, forward targets, the −16 back edge taken four times and not once, `jal`'s link and target backward and forward, compressed links of `pc + 2`, and the `jalr` with `rs1 = rd`, `imm = −2`, bit 0 of the sum set — target from the old `rs1`, bit 0 cleared, link written after |
| 4 | `SLTI x5, −1` / `SLTIU x5, −1` | `::the_slti_defect_has_no_analogue`, `::the_guest_runs_…` | 5 and −5 against −1 answer 0 and 1 (`slti`), 1 and 1 (`sltiu`), in rows and in the trace; the retired table's reading — the sign taken from `rs2`'s halfword — satisfies every gate and is refused by `U16GetSign` alone, its halfword by the range pair |
| 5 | `rd = x0` | `::every_row_kind_…`, `::the_guest_runs_…`, `prover/tests/control.rs` (deferred) | `jal x0`, and `slt`, `sltu`, `slti`, `sltiu` each computing 1 into `x0`, hold as rows, run in the guest and prove; every read of `x0` in the trace is 0 |
| 6 | Fetch binding | `jump_branch_slt.rs::a_jump_to_a_pc_holding_no_instruction_cannot_be_counted`, `checker/tests/tamper.rs::s17_a6_…` (deferred) | The `jalr` moved into the middle of the 32-bit instruction it lands on, the next row's pc to match, every gate still holding: in CI, the honest prover's decoder recount over the family's filled shard refuses it by name while every other channel counts; deferred, the proof made anyway is `Lookup { DECODER }` |
| 7 | Tamper twins | `tamper.rs::s17_a7_…` (deferred); as rows, `jump_branch_slt.rs::the_pinned_full_width_comparisons_…` and `::each_gate_is_the_one_…` | The honest statement verifies; a corrupted `lt` on a not-taken `BLT` is `Constraint`, and carried through the gap, `taken` and `next_pc` is `Lookup { RANGE16 }`; the `jalr`'s `next_pc`, moved with its `rs1` so every gate and bound holds, is `MemoryArgument`, and so it is with the add/sub row that wrote that `rs1` moved too, the pc's chain the only one left unbalanced. Beyond the item: a generic count `Lookup { GENERIC }`, a poisoned table row no row reads `Opening`, two padding cells verifying |
| 8 | Padding | `jump_branch_slt.rs::a_padding_row_advances_the_pc`, `::the_circuit_is_the_fixture_…`; CI's fixture diff | The all-zero row passes every validator and gate; a mask-zero row advances to its claimed fall-through, and `next_pc = 0` beside a nonzero one is refused; `jump_branch_slt.bin` is regenerated and diffed |
| 9 | The legal-mask set | `::the_legal_masks_are_the_instruction_list` | The twelve instructions with and without `rd = x0`, routed through `program::row_kind`, give exactly `LEGAL_MASKS`, and so does the guest's decoded table |

**Beyond the items:**

| What | Where |
| --- | --- |
| The fake exit — a `jalr` keeping bit 0 to write `HALT_PC` — breaks no gate and no lookup but `next_pc_even` | `jump_branch_slt.rs::only_the_evenness_obligation_…` |
| Every gate the lone or first refusal of a row it exists for — among them a `jal` landing anywhere through a field-valued wrap and a `jalr` rounding up through a dropped bit of −1, each refused by its booleanity gate alone, and a branch comparing `rs1` against `rs2` plus its displacement, refused by `cmp_rhs_rule` alone; every booleanity gate refusing 2; S14's C8 on this frame | `jump_branch_slt.rs::each_gate_is_the_one_…`, `::every_booleanity_gate_…` |
| The all-zero mask, refused by the decoder's domain alone (S15's and S16's control, on this family) | `::an_all_zero_mask_is_refused_by_the_decoder_domain_alone` |
| The ordering gate is the gadget's equation over the family's columns, and the packed mask recomposes from exactly the twelve kind bits | `::the_layout_and_the_gates_are_the_specs`, `::the_legal_masks_are_the_instruction_list` |
| The guest derives only the families S17 proves, and runs taken and not-taken compressed branches, a branch taken to its own fall-through, `c.j` and `c.jr` | `::the_guest_runs_the_acceptance_matrix` |
| Each table lookup the lone refusal of a row every gate and range accepts: a forged sign on either operand, and a `jal` four bytes past its table row — each under its own selector | `::each_table_lookup_is_the_one_that_refuses_its_row` |
| The prover's own fill over the guest's trace: every channel counts, every live row and the first padding rows satisfy every gate and range, and the setup columns are the decoded table and the generic table row for row | `::the_fill_satisfies_every_gate_and_every_table` |
| The fill over programs built by hand: jumps and a taken branch across a `2^16`-byte page, and a second shard of a buffer longer than its height; and its refusals of a trace its table does not compute | `::jumps_across_a_halfword_page_fill_and_hold`, `::a_second_shard_fills_the_cycles_after_the_first`, `::the_fill_refuses_…` |
| The circuit's construction checks, each through a broken circuit: an obligation dropped, `next_pc`'s direct bound replaced, a gate nonzero on the zero row; the comparison built at 1 to 32 bits only | `constraints/src/jump_branch_slt.rs`, `gadgets.rs` (unit) |
| The key `ProverSetup::new` builds, with no proof: the table over its SRS, the digest over both; each commitment against the toy `tau`, the same over `2^18` powers as over `2^20` | `prover/tests/key.rs` |
| The generic table's binding: the key's triple the ceremony's, the digest over it, the opening claim ending with it; a key with another table's does not load under the honest digest, and under its own every shard is refused as `Statement` | `prover/tests/control.rs` (deferred) |
| The digest's recipe and every byte of both its inputs moving it; the global transcript event for event, S16's; the key's layout read back field by field; every bit of the key's table refused at load; the per-family setup count with and without the table | `verifier-core/tests/reduce.rs`, `wire.rs` |
| `load_verifying_key` decodes every table point | `verifier/src/lib.rs` (unit) |
| Tag 41 in the tag registry, which is now `1..=41` | `transcript/tests/duplex.rs` |
| The table's commitments pinned over the ceremony, one set at every height | `program/tests/lookup_tables.rs` |

---

## Deviations and notes for the reviewer

1. **The decoded table and the mask** (answer 1). The prompt's must-be-exact 4 set
   `{1, 2, 4, 17, 18, 20, 24}` and acceptance 9's "instruction list × its modifier bits"
   become the twelve one-bit masks: there are no modifier bits, because `rd = x0` is the
   table's `rd` column and the frame's x0 rule, and a branch has no `rd` query at all. The
   weight triples of must-be-exact 7 are exactly the prompt's, as linear forms over the
   kind bits rather than table columns.
2. **The evenness obligation** (answer 3) is an addition to the prompt, which said no
   alignment constraint was needed.
3. **No link wrap bit**: the prompt's "JAL at `0xfffffffc`" cannot occur — the link is a
   table value below `2^24`.
4. **`eq`'s gadget is enabled by `m_pc`**, where the prompt wrote the constant 1.
5. **Must-be-exact 8** is read as recorded above.
6. **The generic table's constants moved to `constants`** because the circuit, which is
   `no_std` and cannot depend on `program`, builds a key into the table.
7. **S16's frozen shard-proof spec is amended in two places**, §3 and §9, by answer 5.
   Every key's bytes and SRS digest change, add/sub-only keys included, and a verifier
   that pinned an S16 digest must take the new one.
8. **`check_copowers` runs inside the family's constructor**, over `next_pc`; since key
   loading rebuilds the registry's circuit to compare bytes, it runs at every load too.
9. **One load-rule check cannot fail for any key.** The rule that a reading family's
   generic channel names the three setup columns right after identity's is implied by the
   circuit being the registry's and the count rule. It stays, with its own message, as the
   registry's self-check: `ProverSetup::new` runs the load rules, so a later registry entry
   that breaks it is refused when a key is built.
10. **`jump_branch_slt::artifact` asserts the all-zero row is valid**, which the assembly
    only records; the prover pads with all-zero rows.

---

## Deferred work, by stage

**S18 (shift/bitwise, mul/div).** The gadgets are yours: the comparison for magnitude
checks, `is_zero` for `rem ≠ 0`. The second reader of the generic channel (AND) opens the
key's same triple after its identity commitments — nothing in the key changes. Every
family that computes a pc keeps it even. `constraints::lookup::check_copowers` matches a
`RANGE16` obligation on its expression and never its selector: S17's three `next_pc`
obligations share `m_pc`, but a circuit whose direct pair sits under a narrower selector
than its scaled obligation would pass the check. Tighten it before relying on it.

**S19.** `amomin`/`amomax` on the comparison. `DEFAULT_HEIGHTS[ATOMICS]` (S16 answer 7).

**The I/O-binding stage, S20, S26**: unchanged from S16's list.

---

## Open for the owner

- **How a verifier obtains the trusted SRS digest** is S16's open question, and the
  digest now pins the generic table as well as the `SrsVerifier`. Both are constants of
  the ceremony: anyone holding it recomputes the digest, and
  `crates/program/tests/vectors/generic_table.txt` pins the table's three points. The
  `verifier` CLI still compares only identity with a value its caller supplies; it takes no
  trusted digest, so it trusts the key's.

---

## Verification performed

On macOS (18 cores, 48 GB), every gate the root `CLAUDE.md` lists, at the final tree:

- `fmt --check` in all four workspaces, and `clippy -D warnings` in all four;
- `cargo test --workspace`: **833 passed, 50 `#[ignore]`d** (796 and 44 at S16). The 37
  new tests that run in CI: `checker/tests/jump_branch_slt.rs` 22; `constraints` unit 10
  (five in `gadgets`, five in `jump_branch_slt`); `prover/tests/key.rs` 2;
  `program/tests/lookup_tables.rs` 1; `verifier-core/tests/reduce.rs` 1; `verifier` unit 1. `verifier-core/tests/wire.rs` and
  `transcript/tests/duplex.rs` grew inside existing tests. The 6 new ignored ones are
  `prover/tests/control.rs`' two, `checker/tests/tamper.rs`' two, the ceremony half of
  `lookup_tables.rs`, and `loader/tests/qemu.rs`' control case;
- the `riscv32imac` build of `field`, `constants`, `transcript`, `poly`, `sumcheck`,
  `constraints`, `gkr-verify` and `verifier-core`; the guest workspace's clippy with
  `guests/control` in it; fib's and control's guest builds;
- `cargo run -p kat-gen`, then the fixture diff: nothing tracked moves, and the three new
  fixtures regenerate byte for byte — `generic_table.txt` from the ceremony file;
  `transcript-ref` with no diff;
- the QEMU suites in the colima container (aarch64 Linux with `qemu-user`, its own
  `CARGO_TARGET_DIR`, every guest built from source), at the committed tree:
  `loader --test qemu` 10 passed at both profiles, `control_passes_its_checks` among them;
  `emulator --test differential` 3 passed, control in its suite, its register file equal
  to QEMU's at every instruction; `emulator --test consistency` 8 passed at both profiles;
- on the PSE ceremony: `program --test identity -- --ignored` 6 passed, 71 s — **the
  identity pins did not move** — and `program --test lookup_tables -- --ignored` 1 passed,
  the table's three commitments equal to the pin at `2^18`, `2^20` and `2^22`;
- S15's deferred `checker --test logup`: 9 passed, 199 s.

**The deferred suites**, `--include-ignored --test-threads=1`, on the final tree:

| Suite | Result | Wall | Peak resident |
| --- | --- | --- | --- |
| `prover --test acceptance` | 7 passed | 323 s | 8.64 GB |
| `verifier --test cli` | 1 passed | 20 s | 8.54 GB |
| `checker --test tamper` | 7 passed | 806 s | 11.26 GB |
| `prover --test control` | 2 passed | 84 s | 10.07 GB |

S16's three are unchanged in their results under the new key and digest; the tamper file
is slower and larger with S17's twins, which re-prove a three-shard statement each. All
four stay commented out of `.github/workflows/ci.yml` under `# DEFERRED:` lines, master
rule 7: both execution shards are `2^20` rows, the timestamp channel's floor.

**Measurements.** `control`'s statement — add/sub and jump/branch/slt at `2^20`,
`INIT_TEARDOWN` at `2^16`, the toy SRS — proves in about 40 s on 18 cores, setup
included: each of `control.rs`' two tests proves it, 84 s for the file. The family's
circuit is 25 transitions deep at `2^20`, its base 75 columns wide and layer 1 84 (the
add/sub circuit's are 74 and 68), a shard proof 61,612 bytes, and the artifact builds in
about 4 ms.

---

## Mutation testing

Three agents, each in its own worktree at the stage's second commit, made one semantic edit
at a time to S17's code — a check removed or weakened, a constant, coefficient, selector or
gate term changed, an order swapped, a message dropped — ran the suites named for it, and
reverted. The circuit was measured with its two pins skipped, the fixture's SHA-256 and the
gate-by-gate layout, as S16's was. A fourth agent ran the survivors only a proof could
judge against `prover --test control`, one at a time, and the two it left were run the
same way afterwards.

| Group | Mutants | Caught in CI | Survived |
| --- | --- | --- | --- |
| the circuit: `jump_branch_slt`, `gadgets`, the x0 rule on `is_zero`, the registry arm | 78 | 66 | 12 |
| the binding: the key's codec and load rules, the SRS digest, step 11, the load, the key's construction, `generic_commitments`, the constants | 42 | 29 | 13 |
| the family's fill | 47 | 34 | 13 |
| **all** | **167** | **129** | **38** |

**20 survivors were test gaps, and each is closed by a test that now kills it in CI**
(re-run against the mutant):

- **Two holes in the row suite's table check.** It gated both table channels by the pc
  mask instead of each lookup's own selector, so a selector moved to another column went
  unseen: the decoder lookup under `rs1`'s mask, which frees every `jal` from its table
  row, and the sign lookups under `lt`, which frees both signs wherever `lt = 0`. Only the
  pins caught them. The check now reads each lookup's selector, and three rows — a forged
  sign on each operand and a `jal` past its table row — are each refused by one lookup.
- **A branch's `next_pc` bound**: the range obligations moved under `rd`'s mask, which a
  branch does not have. An unreduced branch target is now a row.
- **The construction checks** — the per-channel count, the copower check, the all-zero-row
  assertion — which no test had fed a broken circuit; `jump_branch_slt` now has a private
  `assemble` seam for that. And the comparison's width guard at 0 bits.
- **The fill, five ways**: `next_pc`'s high halfword taken from the fall-through, which no
  committed guest can tell apart, its code lying in one `2^16`-byte page; a shard's first
  and last cycle, which no suite could tell with one shard; its two refusals of a trace its
  table does not compute; and its setup columns in the wrong row order, which only the
  proof's opening caught (three mutants).
- **The key's construction**, which only the proving suites reached: the table stored in
  another order, the digest over another table, `generic_commitments` committing one column
  three times or at `2^20`. And `load_verifying_key` decoding two of the three points.

**11 are equivalent**, each with the reason in the agent's report: the frame's write-back
gates make `rs1`'s and `rs2`'s written values their read values, so reading either is the
same (two mutants); the comparison's obligations under `rs1`'s mask, which differs from
`m_pc` only on a `jal`, where nothing reads the comparison; two relabelings the prover and
verifier follow together — the generic and decoder multiplicity columns swapped, the range
pairs reordered; the load's registry self-check, which no key whose circuit is the
registry's can fail (deviation 9); the fill's gap by signed subtraction; an equality
inverse of 1 where the difference is 0, and on padding rows, where no gate reads it; a
`jal`'s wrap taken from the immediate's sign, which is the carry for every target the
emulator can reach; and two arms of the fill's `next_pc` match reordered, being disjoint.

**7 are caught only by the proof**: step 11 of `reduce_shard` never listing the table,
listing it for the wrong families, for every family, or before identity's commitments, and
the prover's opening listing it never, for the wrong families, or first. Each fails
`control.rs`' `a1_…` — the verifier-side ones as `Opening`, the prover's first two by
`batch_open`'s length refusal, its order swap as `Opening` under the honest verifier.
