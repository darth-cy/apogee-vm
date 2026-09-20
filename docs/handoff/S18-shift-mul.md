# S18 — The shift/bitwise and mul/div families

Branch `s18-mul`. Status: implemented. Four questions went to the owner before any code and
each was answered; a fifth reading was announced and not objected to (see "Read these
first").

S18 proves the third and fourth execution families, and with them every RV32I ALU
instruction and the whole M extension. `guests/alu` is a hand-written guest over the four
families S18 proves that checks every result it computes and exits with the number of
checks, 96. It is built, decoded, traced, compared with `qemu-riscv32` instruction by
instruction, and proved as five shards — `INIT_TEARDOWN` at `2^16` and
`ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT`, `SHIFT_BITWISE` and `MUL_DIV` each at `2^20` —
every one verified through `verify_shard` against one statement.

The two circuits' centres of gravity:

- **shift/bitwise** ships as **one merged family**. Its six shifts settle both directions
  through a single multiplication — `shift_in` selects the multiplicand, `shift_prod` is
  the one ungated product — and its six bitwise operations derive XOR and OR from a single
  AND accumulator over four byte lookups, with no XOR table and no OR table. Every key it
  looks up carries a range pair of its own, the shift amount and the four `rs1` bytes
  alike, and `ShiftPowers`' domain, a row for each of the 32 amounts and for no other
  value, bounds the amount a second time.
- **mul/div** proves all eight M instructions with **one product identity**, shared by the
  four multiplies and the division alike. Truncation toward zero is one definitional gate;
  `|rem| < |divisor|` is one range-checked gap carrying a zero-divisor correction; and the
  signed overflow `−2^31 ÷ −1` falls out of the encoding with no pin at all, which is also
  why the quotient's sign flag must stay a free boolean.

Normative documents written or amended this stage:

- **`docs/spec/shift-bitwise.md`** (new) and **`docs/spec/mul-div.md`** (new): what each
  circuit reads from S11's table, the columns, the gates, the lookups, why it is sound,
  what it does not do, the fill and the fixture.
- **`docs/spec/lookup.md`** §9: `ShiftPowers` as the packed table's third sub-table, what a
  table's domain fixes and what it leaves to the key's own bound, and why its copower is
  stored halved.
- **`docs/spec/srs.md`** §4 and **`docs/spec/shard-proof.md`** §3, §5.1, §11 and the
  header: the table grew, so its three commitments, every key's SRS digest and every key's
  bytes moved a second time. **The recipe, the message, its tag and its wire position are
  exactly as S17 froze them**; only the value inside one message changed.
- **`docs/spec/constraint-manifest.md`**: both families' entries, §1.1–§1.3, and the
  sections after them renumbered.
- Also updated to match: `docs/GLOSSARY.md`, `docs/guest-program-manual.md`, the root
  `CLAUDE.md`, `.github/workflows/ci.yml`, and the `CLAUDE.md` of constants, constraints,
  program and prover.

`prompts/S18-mul.md` is committed unchanged. `prompts/00-master.md` is not edited and needs
no edit: the global transcript, the SRS digest's recipe and the key's layout are all S17's.

---

## Read these first

Four questions went to the owner before any code, and a fifth reading was announced with
them. The answers are the design.

1. **`ShiftPowers` is packed into the existing generic table**, as a third sub-table beside
   the AND byte table and `U16GetSign` — not a fifth lookup channel over new virtual
   columns, and not a second triple in the verifying key. One triple stays in every key and
   the SRS digest keeps covering it; a table that grows moves those three commitments, the
   digest and every existing key's bytes, and nothing else. The alternative of a new channel
   would have cost `lookup_channel::COUNT` 4 → 5, a new gating, a new multiplicity column
   and fraction tree, and three new `VirtualKind`s with exponential closed forms inside the
   `no_std` verifier — much more surface for one 32-row table.
2. **The copower is stored halved**, `2^(31 − s)` rather than `2^(32 − s)`. The value the
   residue bound multiplies by is `2^(32 − s)`, which at `s = 0` is `2^32` and does not fit
   the packed table's `u32` columns. The table stores half of it and the two gates that read
   it carry the compensating factor 2, so `pow·copow = 2^31` is exactly
   `pow·(2·copow) = 2^32`. The alternative — an `Fr`-backed column — costs about 134 MB per
   shard at `2^22` for one value in one row. `constants::generic_table::SHIFT_COPOWER_BITS`
   is that exponent, and the deviation from the prompt's literal pair is recorded in
   deviation 3 below.
3. **`|rem| < |divisor|` is a directly range-checked gap**, not a `gadgets::comparison`
   call. The Core algorithm's recipe is "magnitude gadgets plus a range-checked gap carrying
   a zero-divisor correction term", and a comparison gadget has nowhere to put that
   correction. Both magnitudes are bounded by their operands' own range checks, so the
   gadget's operand range pairs and its two `U16GetSign` lookups would prove nothing that
   already holds: five committed columns and six obligations per row of dead weight.
   S17's `gadgets::is_zero` **is** used, twice — for `rem ≠ 0` and for the zero-divisor
   test — so must-be-exact 8's is-zero half is met in full (deviation 4).
4. **One consolidated fixture guest**, `guests/alu`, covering both families with branch
   checks in `guests/control`'s style, proved as one four-execution-family statement rather
   than two guests of three families each. It costs two more `2^20` shards in every proof
   and every tamper re-proof; it gives one program that exercises every acceptance matrix
   and localises a failure to a numbered check.

The reading announced with those, which nobody objected to:

- **The signed overflow needs no pin.** `|rem| < |−1|` forces `rem = 0`, the identity forces
  the quotient's adjusted value to `+2^31`, and `q`'s own range check forces the word
  `0x80000000`. A gate would be implied by three gates that already hold. That case is also
  why **`q_sign` must stay a free boolean**: it is the one row whose signed quotient does
  not fit a signed 32-bit word, so tying `q_sign` to bit 31 of `q` — as `s1` and `s2` are
  tied to their operands' top bits — would make `−2^31 ÷ −1` unprovable. The same is true
  of `r_sign`, which is defined from the dividend's sign rather than from the remainder's
  word. `docs/spec/mul-div.md` §5.3.

---

## Frozen public API, as built

**`crates/constants`**: `generic_table::{SHIFT_BASE = SIGN_BASE + 2^16, SHIFT_ROWS = 32,
SHIFT_COPOWER_BITS = 31}`.

**`crates/program`**: `lookup_tables::{SHIFT_BASE, SHIFT_ROWS}`, `GENERIC_ROWS = 131_105`,
and `generic_entries()` extended with `ShiftPowers`' 32 rows. `GENERIC_LOG_HEIGHT` is still
18.

**`crates/constraints`** (`#![no_std]`):

```rust
pub mod lookup {
    // S18: each entry is (a copower-scaled column, the selector its scaled obligation
    // carries), and the direct range pair must sit under that same selector.
    pub fn check_copowers(a: &CircuitArtifact, scaled: &[(PolyAddress, PolyAddress)])
        -> Result<(), String>;
}
pub mod shift_bitwise {
    pub const DECODED: [PolyAddress; 6];          // W[7..13]
    pub const KINDS: [PolyAddress; 12];           // W[13..25]
    pub const F_SHIFT, F_BITWISE: PolyAddress;    // W[25..27], each a lookup selector
    pub const RS1_HI, RS1_SIGN, SRC2_HI, AMOUNT, POW, COPOW, HIGH, HIGH_HI,
              SE, SHIFT_IN, SHIFT_PROD, OVF, OVF_HI, RESIDUE, RESIDUE_HI,
              SCALED, SCALED_HI: PolyAddress;     // W[27..44]
    pub const BYTES_A, BYTES_B, BYTES_AND: [PolyAddress; 4];   // W[44..56]
    pub const RD_HI: PolyAddress;                 // W[56]
    pub const MULTIPLICITIES: [PolyAddress; 4];   // W[57..61]
    pub const TABLE_WIDTH: usize = 7;             // S[0..7]
    pub const GENERIC_TABLE: [PolyAddress; 3];    // S[7..10]
    pub const LEGAL_MASKS: [u32; 12];
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}
pub mod mul_div {
    pub const WORD_BITS: u32 = 32;
    pub const DECODED: [PolyAddress; 5];          // W[7..12] — five: no imm
    pub const KINDS: [PolyAddress; 8];            // W[12..20]
    pub const F_DIV: PolyAddress;                 // W[20], the is-zero gadgets' enable
    pub const RS1_HI, RS1_TOP, RS2_HI, RS2_TOP, S1, S2: PolyAddress;      // W[21..27]
    pub const MX, MY, P_LOW, P_LOW_HI, P_HIGH, P_HIGH_HI, P_SIGN: PolyAddress; // W[27..34]
    pub const Q, Q_HI, Q_SIGN, R, R_HI, R_SIGN: PolyAddress;              // W[34..40]
    pub const R_INV, RZ, D1, D_INV, DZ: PolyAddress;                      // W[40..45]
    pub const ABS_R, ABS_D, GAP, GAP_HI, RD_HI: PolyAddress;              // W[45..50]
    pub const MULTIPLICITIES: [PolyAddress; 4];   // W[50..54]
    pub const TABLE_WIDTH: usize = 6;             // S[0..6] — six: no imm
    pub const GENERIC_TABLE: [PolyAddress; 3];    // S[6..9]
    pub const LEGAL_MASKS: [u32; 8];
    pub fn arithmetic_gates(word_bits: u32) -> Vec<(String, GateDef)>;    // the width seam
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}
// family_circuit(SHIFT_BITWISE, n) and family_circuit(MUL_DIV, n) for n in 19..=MAX_TRACE_VARS
```

**`crates/prover`**: `family_fill(SHIFT_BITWISE)` and `family_fill(MUL_DIV)`. Nothing else
in the crate changed.

**`crates/verifier-core` and `crates/verifier` did not change at all.** The second and third
readers of the generic channel needed no key field, no wire byte and no load rule: every key
already carries the table's triple, and `FamilyCircuit::reads_generic_table` puts it in the
opening. That was the point of S17's answer 5, and S18 is the evidence.

**The trace-buffer schema** (`crates/trace`) is S12's `FamilyTrace`, unchanged: both
families route their rows exactly as add/sub and jump/branch/slt do. Per kind, the queries a
row holds are `rs1`, `rd` for an I-type shift or bitwise op and `rs1`, `rs2`, `rd` for an
R-type one and for every M instruction — `docs/spec/execution-trace.md` §4 — and each
family's frame, `pc rs1 rs2 rd`, is their union.

**The fixture suite** is `guests/alu`, its committed ELF `crates/loader/tests/vectors/alu.elf`,
and the circuit fixtures `crates/constraints/tests/vectors/shift_bitwise.bin` and
`mul_div.bin`.

---

## What this freezes for every later stage

1. **`docs/spec/shift-bitwise.md` and `docs/spec/mul-div.md`** in full.
2. **Both families' circuits** — their names, their column maps, their gates and lookups,
   their four channels in output order — and their fixtures.
3. **The legal masks** are S11's twelve and eight one-bit values.
4. **`ShiftPowers`' place in the packed table**: `SHIFT_BASE`, its 32 rows, and the halved
   copower with `SHIFT_COPOWER_BITS`. A later stage appending a fourth sub-table pays the
   same price — the table's commitments, the SRS digest, every key's bytes — and no more.
5. **`check_copowers` is selector-aware.** S19 and every later stage that uses the copower
   pattern gets the tightened rule.
6. **`mul_div::arithmetic_gates(word_bits)`** as the width seam an exhaustive reduced-width
   check drives, the same role `gadgets::comparison_equation` plays at S17.
7. **`MUL_DIV`'s decoded tuple is six columns**, and a family whose tuple omits `imm` puts
   the packed generic table at `S[6..9]`, not `S[7..10]`. `reads_generic_table` reads the
   *last* three setup columns, so nothing is hard-coded to 7.

---

## Deviations and notes for the reviewer

1. **The prompt's Shape paragraph is not met and was never normative.** It gives "15 memory
   columns" for both families, 46 and 56 witness columns, "19 degree-2 and 9 degree-1" and
   "41 degree-2 and 15 degree-1" constraints, and 4 and 5 gate layers. The frozen frame
   (`constraints::memory::frame_queries`, S14) fixes both families at the four queries
   `pc rs1 rs2 rd`, which is `1 + 5w = 21` memory columns and `w + 3 = 7` frame witness
   columns; resizing a frozen frame to match a pre-build estimate was never an option, and a
   frame narrower than its family cannot balance. What shipped is **21 M, 61 W, 10 S = 92
   committed columns and 48 enforcing gates** for shift/bitwise and **21 M, 54 W, 9 S = 84
   and 54** for mul/div, with every semantic gate in gate list 0 as S17's must-be-exact 8
   was read. The specs and the manifest record the shipped numbers, and the row suites pin
   them.
2. **The byte AND table did not ship this stage; it already had.** The prompt's Deliver
   says "the byte AND table, whose domain supplies the byte bounds; both ship this stage",
   but the AND table is rows `1 ..= 2^16` of the packed generic table, shipped at S15 and
   bound through the SRS digest at S17. Only `ShiftPowers` is new. Nothing was rebuilt;
   the bitwise half reads the existing table by its existing key base.
3. **The copower pair is `(2^s, 2^(31 − s))`, not `(2^s, 2^(32 − s))`** (answer 2). The
   arithmetic the prompt specifies is unchanged — `scaled` is still exactly
   `residue·2^(32 − s)` and the bound is still `[0, 2^32)` — and the factor 2 lives in the
   two gates rather than in the table.
4. **`gadgets::comparison` is not called** (answer 3); `gadgets::is_zero` is, twice. The
   magnitude bound is the Core algorithm's literal recipe.
5. **The helper flags are linear forms over the committed one-hot kind bits**, not new
   decoder columns. The prompt asks the decoder to preprocess "shift-direction and
   arithmetic, three bitwise selectors, two operand-signedness flags, four result
   selectors"; its purpose is to keep every helper product at degree 2, and a linear form
   over committed bits already does. Only the three flags that a **lookup selector** or a
   gadget **enable** must be a single column — `f_shift`, `f_bitwise`, `f_div` — became
   columns, and each carries the booleanity gate `validate` refuses a selector without.
   This is S17's answer 1 applied again: S11's decoded table is not rebuilt.
6. **No overflow pin gate** (the announced reading). `−2^31 ÷ −1` is forced by the three
   gates that already hold; a test pins the behaviour.
7. **`next_pc` carries no wrap bit and no range check in either family.** Neither computes
   a pc: `next_pc_rule` is `next_pc − decoded_next_pc = 0`, degree 1, and the decoder lookup
   binds the table value exactly as it binds `rs1`, `rs2`, `rd` and `imm`, none of which is
   range-checked either. S16's add/sub family range-checks its `next_pc` because its rule
   introduces a free wrap bit for the `HALT_PC` substitution; there is no such bit here.
   S17's rule that a family computing a pc keeps it even does not reach a family that copies
   one.
8. **Two redundant checks are kept deliberately**, each named in the specs: `copower_rule`
   (`pow·copow = 2^31·f_shift`), which the `ShiftPowers` lookup already implies, and
   `rd_selected`'s 16+16 pair in mul/div, which the four selected sources' own ranges
   already imply. Each is one gate or two obligations, and each turns a table-generation or
   fill error into a refusal at the row rather than a wrong word in a register.
9. **Every S16 and S17 verifying key's bytes and SRS digest change again**, because the
   packed table grew. No fixture pins either, and `crates/program/tests/vectors/generic_table.txt`
   was regenerated over the PSE ceremony. Program identity did not move: the identity pins
   regenerate byte for byte, which is the check that the table is outside identity.

---

## Acceptance

File paths are under `crates/`. Every test listed passes; the ones marked *deferred* are
`#[ignore]`d and were run locally ("Verification performed").

| # | Item | Where | Result |
| --- | --- | --- | --- |
| 1 | Per-instruction differential for all 20, and a proof per family | `emulator/tests/differential.rs` (`alu` and `opcodes` in `SUITE`), `emulator/tests/trace.rs` (`alu` in `TRACED`), `loader/tests/qemu.rs::alu_passes_its_checks`, `prover/tests/alu.rs` (deferred) | All twenty run in `guests/alu`, which self-checks every one and exits 96, and in `guests/opcodes`, S12's coverage fixture; the statement's five shards prove and every one verifies, with each proof's shape read off its circuit |
| 2 | Shift edge fixtures | `checker/tests/shift_bitwise.rs::the_guest_runs_the_acceptance_matrix`, `::every_row_kind_…`, `::an_untruncated_amount_…`, `::the_shamt_is_not_free_…` | shamt 0, 1 and 31 for each immediate shift; `rs2 = 32` and 33, with 32 asserted to leave the word alone; `sra` of a negative at three amounts; `srai` against `srli` on one negative operand at one shamt, with different answers — as rows and in the guest's trace; and the negative half, an untruncated amount and a free shamt each refused by what §3.3 and §4.2 say refuses it |
| 3 | The signed-multiply matrix | `checker/tests/mul_div.rs::every_row_kind_…`, `::the_guest_runs_the_acceptance_matrix`, `emulator/tests/differential.rs` | All four sign quadrants of each of the four multiplies, `−2^31 × −2^31`, the asymmetric `mulhsu` corner `−2^31 × (2^32 − 1)` and `mulhu` near `2^64`, each as a row and in the guest, whose every value the emulator and QEMU confirm |
| 4 | The div/rem matrix, and the floored fixture | `checker/tests/mul_div.rs::every_row_kind_…`, `::the_floored_quotient_satisfies_the_identity_and_is_refused_by_the_sign_rule`, `::a_quotient_off_by_one_…`, `::a_zero_divisor_whose_quotient_is_not_all_ones_…`, `::the_signed_overflow_has_exactly_the_pinned_answer` | All four sign quadrants of `div` and `rem` and the unsigned pair; division by zero for all four; the `−2^31 ÷ −1` overflow. `DIV(−7, 2)`'s **floored** witness satisfies the bare division identity and is refused by `r_sign_rule` alone — the prompt's "tampered to floored, that fixture must be unprovable", as a row |
| 5 | The exhaustive reduced-width division check | `checker/tests/mul_div.rs::the_division_encoding_admits_exactly_one_witness_at_a_reduced_width` | At a 4-bit word, over every `(dividend, divisor)` pair and each of the four division kinds, every candidate witness evaluated through `gkr::eval_gate` over `mul_div::arithmetic_gates(4)` **itself**: exactly one satisfies where the divisor is nonzero, and exactly one up to `q_sign` where it is zero — the refinement §6 records |
| 6 | Table differentials | `program/tests/lookup_tables.rs` | `ShiftPowers` and the AND byte table against a reference written from the ISA in that file, `ShiftPowers`' pair asserted to multiply to `2^32`; a poisoned row per table caught; the three key ranges pairwise disjoint and off zero; and over the ceremony, the three commitments at `2^18`, `2^20` and `2^22` |
| 7 | The derived-op exhaustive check | `checker/tests/shift_bitwise.rs::acceptance_7_the_byte_table_is_and_and_or_and_xor_are_derived_from_it` | All 65,536 byte pairs read from the committed table: its result is Rust's `a & b`, and the circuit's derived `a + b − and` and `a + b − 2·and` are Rust's `a \| b` and `a ^ b` |
| 8 | Tamper twins | `checker/tests/tamper.rs::s18_a8_…` (deferred) | A `residue` cell of an `sra` and a `p_high` cell of a `mulh`, one per family, each `Constraint`; beyond the item, a generic multiplicity `Lookup { GENERIC }` and a pc read timestamp `MemoryArgument`, so four classes are on screen; two padding-row controls verify; and the structural counts hold |
| 9 | `rd = x0`, padding, and the fixture diff | both row suites' `every_row_kind_…` and `the_padding_row_is_the_all_zero_row`, `the_circuit_is_the_fixture_…`, CI's fixture diff | `rd = x0` computing a discarded value in each half of each family; the all-zero padding row passing every validator, which `artifact` also asserts at construction; and both `.bin` fixtures regenerated and diffed in CI |

**Beyond the items:**

| What | Where |
| --- | --- |
| The soundness hole the review found, as a row: a byte key of 256 reads a `U16GetSign` row and one of 65,823 a `ShiftPowers` row, each proving a wrong `and`, each refused by its key bound and nothing else | `shift_bitwise.rs::a_byte_key_outside_the_and_table_is_refused_by_its_own_bound` |
| A residue that is not an integer, whose scaled product lands back in range — the copower attack `check_copowers` exists for — refused by `residue`'s own direct bound | `shift_bitwise.rs::a_residue_that_is_not_an_integer_…` |
| Every gate the lone or first refusal of a row it exists for, in both families, and every booleanity gate refusing 2 | `shift_bitwise.rs::each_gate_…`, `mul_div.rs::each_gate_…` |
| The construction checks through a broken circuit: a dropped obligation, `residue`'s pair moved under a narrower selector than its scaled obligation, a gate nonzero on the zero row; and `arithmetic_gates` refused at 0 and 33 bits | `constraints/src/{shift_bitwise,mul_div}.rs` (unit) |
| Each family's fill over the guest's real trace: every channel counted, every gate and range holding on every live row, the two padding rows after them and the last, and the setup columns equal to the decoded table and the packed table row for row | both suites' `the_fill_satisfies_every_gate_and_every_table` |
| The packed table's growth carried through: the digest's inputs, the key ranges' compile-time guard, and identity unmoved | `program/tests/lookup_tables.rs`, `constraints/src/gadgets.rs` (`const` assertions), `program/tests/identity.rs` |

---

## Artifacts

| Path | Size | SHA-256 | What |
| --- | --- | --- | --- |
| `crates/constraints/tests/vectors/shift_bitwise.bin` | 102,837 bytes | `b0af932594af665ca82f2ecd35fba64f8eeecc96fb50a9002466628265e3fd4c` | `shift_bitwise::artifact` at `trace_vars` 22 |
| `crates/constraints/tests/vectors/mul_div.bin` | 94,012 bytes | `98f9f3bdd532b9459bb6a5b155d3a0c3e93667fbb6deb34af6e13b5ea30c357a` | `mul_div::artifact` at `trace_vars` 22 |
| `crates/loader/tests/vectors/alu.elf` | 9,104 bytes | `32f85c1799425f5de1a0ac04368e1e6b952289627710b804202f53895dccc168` | the guest, dev profile |
| `crates/program/tests/vectors/generic_table.txt` | 994 bytes | `3c813459777d65a46855ddb763683714ea3fab182e0ffcba69fb6f74673c7b29` | the packed table's commitments over the PSE ceremony, **moved**: the table gained `ShiftPowers`' 32 rows |

No other fixture moved. Every S14 frame fixture, `add_sub.bin`, `jump_branch_slt.bin`, every
other guest ELF and **both identity pins** regenerate byte for byte — the identity pins being
the check that the packed table is outside program identity. S16's and S17's keys and SRS
digests do change, and no fixture pins either.

**Shapes**, at `2^20`:

| family | committed | depth | gate list 0 | lookups (ts/r16/gen/dec) | proof |
| --- | --- | --- | --- | --- | --- |
| `SHIFT_BITWISE` | 21 `M` + 61 `W` + 10 `S` = 92 | 26 | 124 leaves + 48 enforcing | 39 (8/24/6/1) | 68,564 bytes |
| `MUL_DIV` | 21 `M` + 54 `W` + 9 `S` = 84 | 26 | 116 leaves + 54 enforcing | 27 (8/16/2/1) | 67,412 bytes |

Both are 26 transitions deep where add/sub and jump/branch/slt are 25: shift/bitwise's
`range16` tree carries 24 obligations and pads to 32 leaves, and mul/div's 16 obligations
plus its timestamp tree do the same, so each takes one row-wise level more.

---

## What the adversarial review changed

Six read-only reviewers — each family's soundness against a malicious prover, the two
fills' completeness for an honest program, the packed table's growth and everything that
pins it, the specs against the code against the prompt, and the repository's own rules —
each finding then handed to a skeptic told to refute it.

**One high finding was real, and it was a soundness hole.** Two reviewers found it
independently: *the bitwise half's byte keys were unbounded.* The stage prompt says the AND
table's "domain supplies the byte bounds", and that was true while the generic channel held
one map per key range and every key reaching it was already bounded. It is false for an
unbounded key against a channel holding **three** sub-tables, because an out-of-range key
does not miss the table — it lands on another sub-table's row.

The witness: a bitwise row claiming `byte_a0 = 65_823` produces the gated key `65_824`,
which is `ShiftPowers`' row for `s = 31`, `(65_824, 2^31, 1)`. The lookup holds with
`byte_b0 = 2^31` and `byte_and0 = 1`; with `rs1 = 65_823` and `rs2 = 2^31`, both ordinary
register values, every gate holds, both results are inside `[0, 2^32)`, and the row proves
`and = 1` where the answer is `0`, and `xor` short by 2.

The fix is `docs/spec/lookup.md` §4's own precondition, applied to every key this family
looks up: `amount` bounded to `[0, 32)` and each `byte_a_j` to `[0, 256)`, each by the
pair S15's copower rule asks for — the direct halfword check and the column scaled so that
the product is a halfword only below the bound (`shift-bitwise.md` §3.3). Ten `RANGE16`
obligations, no new column, and `check_copowers` now runs over all six scaled columns.
`MUL_DIV` never had the hole: both of its generic keys are `U16GetSign` keys over
range-checked halfwords, as S17's are.

The review also corrected two claims this note and the specs had made:

- **`copower_rule` was called redundant and was not.** Before `amount` was bounded it was
  the only thing confining the `ShiftPowers` key to `ShiftPowers` — no AND row's
  `b·(a & b)` reaches `2^31` and every sign row's product is 0. It is redundant *now*, and
  kept for the reason §3.1 gives.
- **`rd_selected`'s range pair is not redundant in the shift family.** A left shift's
  `shift_prod = rd + 2^32·ovf` needs `rd < 2^32` for the split to be unique. (It *is*
  redundant in mul/div, where every source of `rd` carries its own pair.)

Smaller findings upheld and fixed: `crates/prover/CLAUDE.md` claimed four `Fr`-backed
columns where there are six (`r_inv` and `d_inv` are inverses); `crates/constraints`,
`crates/checker` and `crates/loader`'s `CLAUDE.md` tables were stale; the root `CLAUDE.md`
pointed at the manifest's checklist by a section number that had moved; two
`core::mem::take` calls and one `unreachable!()` were removed from `shift_bitwise.rs` with
the fixture's bytes unchanged; and `docs/spec/jump-branch-slt.md`'s "`2^17 + 1` rows" and
several "the two tables" phrasings were carried forward to three.

---

## Verification performed

On macOS (18 cores, 48 GB), every gate the root `CLAUDE.md` lists, at the final tree:

- `fmt --check` in all four workspaces, and `clippy -D warnings` in all four;
- `cargo test --workspace`: **881 passed, 53 `#[ignore]`d** (833 and 50 at S17). The new
  CI-sized tests: `checker/tests/shift_bitwise.rs` 17, `checker/tests/mul_div.rs` 17,
  `constraints` unit 11 (six in `shift_bitwise`, five in `mul_div`), and the extensions to
  `program/tests/lookup_tables.rs`, `program/tests/tables.rs` and the loader, emulator and
  artifact-dump fixture suites the new guest joins. The 3 new ignored ones are
  `prover/tests/alu.rs`' one, `checker/tests/tamper.rs`' one and `loader/tests/qemu.rs`'
  `alu` case;
- the `riscv32imac` build of `field`, `constants`, `transcript`, `poly`, `sumcheck`,
  `constraints`, `gkr-verify` and `verifier-core`; the guest workspace's clippy with
  `guests/alu` in it;
- `cargo run -p kat-gen`, then the fixture diff: **nothing tracked moves but
  `generic_table.txt`**, and the three new fixtures regenerate byte for byte;
  `transcript-ref` with no diff;
- on the PSE ceremony: `program --test identity -- --ignored` 6 passed, 71 s — **the
  identity pins did not move** — and `program --test lookup_tables -- --ignored` 1 passed,
  the table's three commitments equal to the new pin at `2^18`, `2^20` and `2^22`. That
  test was checked against a negative control: one flipped hex digit of the pin fails it.

**The deferred suites**, `--include-ignored --test-threads=1`, on the final tree:

| Suite | Result | Wall | Peak resident |
| --- | --- | --- | --- |
| `prover --test alu` | 1 passed | 111 s | 14.15 GB |
| `checker --test tamper` (S18's twins) | 1 passed | 306 s | 15.73 GB |

S16's and S17's deferred suites are unchanged in their results under the new table and
digest. All of them stay commented out of `.github/workflows/ci.yml` under `# DEFERRED:`
lines, master rule 7: every execution shard is `2^20` rows, the timestamp channel's floor.

**Not run here: the QEMU suites.** `qemu-riscv32` is user-mode emulation and has no macOS
build (`crates/loader/CLAUDE.md`), so `loader --test qemu`, `emulator --test differential`
and `emulator --test consistency` need the colima container the root `CLAUDE.md` documents.
`guests/alu`'s emulator side *is* covered in ordinary CI — `emulator --test trace` runs it
and asserts it exits 96, and every expected value in the guest was computed from an exact
RV32IM model — but its QEMU comparison has not been run on this machine.

**Measurements.** `alu`'s statement — the four execution families at `2^20`,
`INIT_TEARDOWN` at `2^16`, the toy SRS — proves and verifies in 111 s on 18 cores, setup
included. The shift/bitwise circuit builds in about 5 ms and the mul/div one in about 5 ms.

---

## Deferred work, by stage

**S19.** `amomin`/`amomax` on S17's comparison gadget, and `DEFAULT_HEIGHTS[ATOMICS]`,
still `2^16`, which the timestamp channel's 19-bit floor makes unprovable (S16 answer 7).
S18 added no new obligation to that list. The copower pattern and `check_copowers` are now
selector-aware, so an atomics family using either gets the tightened rule for free.

**The memory families (S20).** `MEM_WORD` and `MEM_SUBWORD` are the two frames with a
`load` query at slot 2 and a `ram` query at slot 3, and are the first families whose rows
touch RAM. Nothing S18 built stands in the way; the packed table has room for a fourth
sub-table inside `2^18` (131,105 of 262,144 rows used).

**The I/O-binding stage, S26**: unchanged from S16's and S17's lists. `EXIT` is still the
only provable ecall.

---

## Open for the owner

- **Should the key-bounding rule become a construction-time check?** The hole the review
  found (above) was a family forgetting `docs/spec/lookup.md` §4's precondition. Three
  lookups of the packed table now exist across two families, and until this stage each was
  confined by a different accident: `U16GetSign`'s key by a range pair it needed anyway,
  `ShiftPowers`' by `copower_rule`, and the AND table's by nothing. A check in
  `constraints::lookup` shaped like `check_copowers` — every `GENERIC` lookup's key column is
  range-bounded into its own sub-table's range, or the circuit names the gate that excludes
  the foreign rows — would refuse the defect at construction and would carry into S19's
  atomics and every later family. It is new surface area, which the master prompt counts as
  a defect, so S18 did not build it unilaterally. The stage ships the bound itself and the
  row that proves it; the *rule* is the owner's call.
- **Splitting the packed table into three channels** would remove the whole class rather
  than bound each key, at the cost of three multiplicity columns, three table fractions and
  three commitment triples. It reopens S17's answer 5 and the SRS digest both stages have
  now moved. Named here so the cheaper fix is known to be a choice, not an oversight; not
  proposed.
- **How a verifier obtains the trusted SRS digest** is still S16's and S17's open question,
  and the digest now pins a larger table. Both of its inputs remain constants of the
  ceremony: anyone holding the ceremony recomputes them, and
  `crates/program/tests/vectors/generic_table.txt` pins the three points. The `verifier` CLI
  still compares only identity with a value its caller supplies.
- **The four-execution-family statement is the heaviest thing the deferred suites prove**,
  and each new family adds a `2^20` shard to every proof and every tamper re-proof. If the
  cost becomes the binding constraint before the memory families land, splitting the fixture
  guest per family is the lever; it doubles the registration work and the deferred suites,
  which is why S18 did not reach for it.
