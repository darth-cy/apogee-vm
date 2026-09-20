# S19 — The memory-op families and atomics

Branch `s19-mem`. Status: implemented. Four questions went to the owner before any code and
each was answered; the answers are the design.

S19 proves the last three execution families, and with them the whole of RV32IMAC. Every
family the master prompt names is now registered: `constraints::family_circuit` has a
circuit for each and `prover::family_fill` a fill, and `crates/checker/tests/add_sub.rs`'
registry test asserts it. `guests/mem` is a hand-written guest over the three families S19
proves that checks every value it computes and exits with the number of checks, 50. It is
built, decoded, traced, held to `qemu-riscv32` instruction by instruction **in CI** — that
comparison needs a Linux host and was not run on this machine (see "Verification
performed") — and proved as **seven shards** — `INIT_TEARDOWN` and `ZERO_WINDOWS` at `2^16` and
`ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT`, `MEM_WORD`, `MEM_SUBWORD` and `ATOMICS` each at
`2^20` — every one verified through `verify_shard` against one statement. **It is the first
statement whose rows touch RAM**, and so the first with a `ZERO_WINDOWS` shard.

The three circuits' centres of gravity:

- **The addressing is one section shared by all three.** `addr = 4·word_index + 2·bit1 +
  bit0` is an alignment check over ℤ and *nothing at all* over `Fr` — 4 is a unit there, so
  `word_index := addr·4⁻¹` satisfies it for any address whatever. What makes the split
  genuinely base-4 is the range check on `word_index`, and in particular its third
  obligation, `4·word_index_hi`, which caps it at `2^30 − 1` and is exactly tight at the
  top of the address space. `MEM_WORD` carries no offset bits at all, so a misaligned `lw`
  or `sw` has no representation; `half_aligned` clears bit 0 at halfword width.
- **`mem_subword` splices, and its two constants come from gates, not from a table.** The
  splice power `p = 2^(8·offset)` and its halved copower are degree-2 polynomials in the
  address's own two offset bits, so the stage prompt's seven-row `MemoryOffsetGetBits`
  setup table was not built (owner's answer 2). Each of `high`, `sub`, `low` and the store
  source carries both its copower-scaled bound and its own direct range check, and
  `check_copowers` refuses the circuit without them.
- **`atomics` is one `ram_value_rule` over eleven arms.** The RAM query and the `rd` query
  share Δ = 3 at distinct address spaces, which is what lets one row be one
  read-modify-write and makes the A extension the one family with **two queries in one Δ
  slot**, so one of its rows makes five. `rd` takes the **old** word on every kind but `sc.w`, which always succeeds and
  writes 0. OR and XOR are derived from one AND accumulator, min/max from S17's comparison
  gadget, whose four parameters `assemble` asserts because each wrong choice is a silent
  total break of four kinds.

Normative documents written or amended this stage:

- **`docs/spec/memory-ops.md`** (new): one page for all three families, because §2's
  addressing is shared. What each reads from S11's table, the columns, the gates, the
  lookups, why each is sound, the write-side induction stated once with its base case, what
  they do not do, the heights, the registry's guard and the fixture.
- **`docs/spec/constraint-manifest.md`**: the three families' entries, and the sections
  after them renumbered.
- **`docs/spec/memory.md`** §9: "each access's byte address", the last item its owed list
  carried, is discharged, and §2.1 and §5 gain their "Status at S18" and "Status at S19"
  entries. **`docs/spec/lookup.md`** §3: `DEFAULT_HEIGHTS[ATOMICS]` was raised, and the
  minimum-height guard now names all seven. **`docs/spec/shard-proof.md`**: the header's
  per-stage note, §5.1's reader count and §11's registry list gain S19's three; its protocol
  did not change, and neither did the value inside any of its messages.
- Also updated to match: `docs/GLOSSARY.md`, `docs/guest-program-manual.md`, the root
  `CLAUDE.md`, `.github/workflows/ci.yml`, and the `CLAUDE.md` of constraints, program,
  prover and checker.

`prompts/S19-mem.md` is committed unchanged. `prompts/00-master.md` is not edited and needs
no edit.

---

## Read these first

Four questions went to the owner before any code. The answers are the design.

1. **`DEFAULT_HEIGHTS[ATOMICS]` is `2^20`**, and every fixture is proved there. The stage
   prompt's "build every fixture at trace height `2^16`, the menu's smallest" cannot be
   followed by any family that runs cycles: a range channel needs `BITS ≤ trace_vars`
   (`docs/spec/lookup.md` §3), `BITS[TIMESTAMP]` is 19, and a Mercury opening needs an even
   variable count, so `2^20` is the floor. S16 answer 7 deferred the raise to this stage
   "with the circuit that needs it". The alternative of `2^22` was declined: `2^20` is the
   floor and `MUL_DIV` already sits there, and four times the rows per atomics shard is a
   real cost on every proof and every tamper re-proof for a family whose guests run a few
   dozen cycles. Deviation 1.
2. **There is no `MemoryOffsetGetBits` table.** `constants::generic_table::WIDTH` is frozen
   at 3 — a key and two values — so a row cannot carry the splice power, its copower, the
   access width *and* the width's copower, which is what must-be-exact 8 describes; and `p`
   and its copower turn out to be exactly degree-2 polynomials in the two committed offset
   bits. Two gates replace the table. The alternatives were a fourth sub-table of the packed
   generic table, which would have moved its three commitments, every verifying key's SRS
   digest and bytes and the ceremony pin — S18's standing price — and added a fourth key to
   bound into its own range, which is the exact hole S18's review found; or widening the
   packed table to five columns, which breaks a constant three stages are built on.
   Deviation 2, and `docs/spec/memory-ops.md` §4.2.
3. **S11's one-hot `family_extra_mask` is kept.** The stage prompt gives `mem_subword` the
   modifier-bit masks `{0, 1, 2, 3, 4, 6}` with STORE = 1, BYTE = 2 and SIGNEXTEND = 4, and
   `mem_word` "one store bit, masks `{0, 1}`". `constants::extra_mask` is frozen and
   append-only and is one-hot per mnemonic; rebuilding it would move program identity for
   every program that loads or stores, which is nearly all of them. STORE, BYTE and
   SIGNEXTEND are linear forms over the committed one-hot bits, which is S17's answer 1 and
   S18's reading applied a third time. Deviation 3.
4. **One consolidated fixture guest**, `guests/mem`, covering all nineteen instructions and
   proved as one five-execution-family statement, rather than one guest per family. It
   costs the heaviest statement in the repository; it gives one program that exercises every
   acceptance matrix and localises a failure to a numbered check.

---

## Frozen public API, as built

**`crates/constants`**: `family::DEFAULT_HEIGHTS[ATOMICS]` is `1 << 20`. Nothing else moved;
the eleven, six and two `extra_mask` bits and the three `FamilyId`s were S11's already.

**`crates/constraints`** (`#![no_std]`):

```rust
pub mod mem_word {
    pub const DECODED: [PolyAddress; 6];          // W[9..15]
    pub const KINDS: [PolyAddress; 2];            // W[15..17]
    pub const WRAP, WORD_INDEX, WORD_INDEX_HI, RD_HI: PolyAddress;   // W[17..21]
    pub const MULTIPLICITIES: [PolyAddress; 3];   // W[21..24] — three channels, no generic
    pub const TABLE_WIDTH: usize = 7;             // S[0..7]; no generic table
    pub const LEGAL_MASKS: [u32; 2];
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}
pub mod mem_subword {
    pub const BYTE_BITS: u32 = 8;
    pub const DECODED: [PolyAddress; 6];          // W[9..15]
    pub const KINDS: [PolyAddress; 6];            // W[15..21]
    pub const WRAP, WORD_INDEX, WORD_INDEX_HI, BIT0, BIT1: PolyAddress;        // W[21..26]
    pub const P, PCOPOW, WPH, P_RAM, WORD: PolyAddress;                        // W[26..31]
    pub const HIGH, HIGH_HI, HIGH_SCALED, HIGH_SCALED_HI: PolyAddress;         // W[31..35]
    pub const SUB, SUB_SCALED, SUB_SCALED_HI: PolyAddress;                     // W[35..38]
    pub const LOW, LOW_HI, LOW_SCALED, LOW_SCALED_HI: PolyAddress;             // W[38..42]
    pub const SRC_SUB, SRC_SUB_SCALED, SRC_SUB_SCALED_HI,
              SRC_HIGH, SRC_HIGH_HI: PolyAddress;                              // W[42..47]
    pub const SIGN_IN, SIGN, SE, RD_HI: PolyAddress;                           // W[47..51]
    pub const MULTIPLICITIES: [PolyAddress; 4];   // W[51..55]
    pub const TABLE_WIDTH: usize = 7;             // S[0..7]
    pub const GENERIC_TABLE: [PolyAddress; 3];    // S[7..10]
    pub const LEGAL_MASKS: [u32; 6];
    pub fn splice_gates(byte_bits: u32) -> Vec<(String, GateDef)>;   // the width seam
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}
pub mod atomics {
    pub const DECODED: [PolyAddress; 5];          // W[8..13] — five: no imm
    pub const KINDS: [PolyAddress; 11];           // W[13..24]
    pub const WORD_INDEX, WORD_INDEX_HI: PolyAddress;                          // W[24..26]
    pub const SUM, SUM_HI, ADD_WRAP, F_BITWISE: PolyAddress;                   // W[26..30]
    pub const BYTES_A, BYTES_B, BYTES_AND: [PolyAddress; 4];                   // W[30..42]
    pub const OLD_HI, OLD_SIGN, SRC_HI, SRC_SIGN, LT,
              CMP_GAP, CMP_GAP_HI, LO: PolyAddress;                            // W[42..50]
    pub const MULTIPLICITIES: [PolyAddress; 4];   // W[50..54]
    pub const TABLE_WIDTH: usize = 6;             // S[0..6] — six: no imm
    pub const GENERIC_TABLE: [PolyAddress; 3];    // S[6..9]
    pub const LEGAL_MASKS: [u32; 11];
    pub fn artifact(trace_vars: u32) -> CircuitArtifact;
    pub fn channels() -> Vec<lookup::ChannelSpec>;
}
// family_circuit(MEM_WORD | MEM_SUBWORD | ATOMICS, n) for n in 19..=MAX_TRACE_VARS, and
// the minimum-height guard now names all seven execution families.
```

**`crates/prover`**: `family_fill(MEM_WORD)`, `family_fill(MEM_SUBWORD)` and
`family_fill(ATOMICS)`, plus one crate-private helper, `fill::frame_columns`, which is the
frame's columns with `rd_selected` left out — the three fills share it where S16–S18 each
wrote the same four lines. Nothing else in the crate changed.

**`crates/verifier-core` and `crates/verifier` did not change at all**, and neither did
`crates/trace`, `crates/emulator`, `crates/isa` or `crates/loader`. Every frame, every
decoded tuple, every `extra_mask` bit, the emulator's semantics for all nineteen
instructions and the `sc.w` whitelist were in place from S11 and S12; S19 is three circuits,
three fills, a guest and a constant.

**The fixture suite** is `guests/mem`, its committed ELF `crates/loader/tests/vectors/mem.elf`,
and the circuit fixtures `crates/constraints/tests/vectors/mem_word.bin`, `mem_subword.bin`
and `atomics.bin`.

---

## What this freezes for every later stage

1. **`docs/spec/memory-ops.md`** in full, and in particular §2's addressing, §4.1's derived
   splice constants and §5.1's statement of the write-side induction.
2. **The three families' circuits** — their names, column maps, gates and lookups, their
   channels in output order — and their fixtures. `MEM_WORD` has **three** channels and no
   generic table; `ATOMICS`' decoded tuple is **six** columns, so its packed table sits at
   `S[6..9]`.
3. **The legal masks** are S11's two, six and eleven one-bit values, and every arm of every
   circuit indexes them through its `constants::extra_mask` constant, never by position.
4. **`mem_subword::splice_gates(byte_bits)`** as the width seam an exhaustive reduced-width
   check drives, the role `gadgets::comparison_equation` plays at S17 and
   `mul_div::arithmetic_gates` at S18.
5. **`DEFAULT_HEIGHTS[ATOMICS] = 2^20`**, and the rule behind it: no family that runs cycles
   may default below the timestamp channel's floor.
6. **`family_circuit`'s minimum-height guard names every execution family.** A family added
   to the match without being added to the guard is a panic inside `VerifyingKey::check`.
7. **The SC-always-succeeds deviation**, `docs/spec/memory-ops.md` §6.6, and its one
   whitelist entry in the QEMU differential.
8. **The atomics family's four-query use of the S12/S16-frozen Δ-slot assignment**: `pc` 0,
   `rs1` 1, `rs2` 2, `ram` 3 and `rd` 3, the RAM and register queries sharing slot 3 at
   distinct address spaces.
9. **Every family frame is final.** S20 and later treat `constraints::memory::frame_queries`
   as closed.

---

## Deviations and notes for the reviewer

1. **`DEFAULT_HEIGHTS[ATOMICS]` moved, and the stage prompt's `2^16` fixture height is
   unreachable** (answer 1). Every execution family's shard is at least `2^20`, so the three
   circuit fixtures are written at `trace_vars` 22, which is `kat-gen`'s one height for the
   whole `family` group, and the guest is proved at `2^20`. What moved with the constant:
   the derived `VmConfig` of any A-carrying program, hence its identity. The committed
   identity pins are `guests/fib`'s, which is A-free, so `crates/program/tests/vectors/identity.txt`
   did not move. `crates/program/tests/partition.rs` did: `guests/consistency` used to be the
   one guest the frozen defaults refused, and now fits, so the `TableTooShort` refusal keeps
   a test of its own against an explicit `2^16`.
2. **`MemoryOffsetGetBits` does not exist** (answer 2), so must-be-exact 8 is not met as
   written and the Deliver bullet naming the table is not delivered. Precisely what is not
   there: no sub-table in `program::lookup_tables::generic_entries`, no private setup table,
   no key base in `constants::generic_table`, no generation path, no `ZeroEntry` row of its
   own, and no rows in `docs/spec/lookup.md` §9. The Handoff item "freeze the
   MemoryOffsetGetBits schema and its generation path" is replaced by freezing `p_rule`,
   `pcopow_rule` and `wph_rule` with their constants — `255`, `65535`,
   `K = 2^24 − 2^16 − 2^8 + 1 = 16711425`, `32768`, `32640`, `2^31` — and the fact that
   `pcopow` and `wph` are the **halved** copower and width multiplier, the `ShiftPowers`
   pattern, which is what keeps every column inside its `u32` backing.
   `docs/spec/memory-ops.md` §4.2 argues that the replacement is strictly stronger: a table
   keyed `1 + bit0 + 2·bit1 + 4·BYTE` would still have needed `addr_split` to pin `bit0` and
   `bit1` to the address, so the table never carried the pinning — only the values. **The
   packed generic table did not move at S19**, which is the first stage since S16 that has
   not moved it.
3. **The legal masks are S11's one-hot bits, not the prompt's modifier bits** (answer 3).
   `LEGAL_MASKS` is `[1, 2]` for `mem_word` and `[1, 2, 4, 8, 16, 32]` for `mem_subword`;
   `{0, 1, 2, 3, 4, 6}` is not the encoding, and mask 0 is not a legal live mask.
4. **The stage prompt's atomics ordering is not the constants'.** The Deliver list writes
   "AMOXOR.W, AMOAND.W, AMOOR.W"; `constants::extra_mask::atomics` is ascending `funct5`,
   which puts xor at bit 4, or at 5 and and at 6. Following the prose would have made
   `amoor.w` compute AND with every gate holding and the verifier accepting — the artifact
   is frozen at handoff, so it would have become a protocol version. Every arm indexes
   `KINDS` through its constant, and `crates/checker/tests/atomics.rs` maps each of the
   eleven `Instr` variants through `program::row_kind` to the bit its arm uses.
5. **Acceptance 8's `mem_word` premise is corrected, not skipped.** The item says "corrupt
   one loaded-value cell: no gate reads it". That was already false at S14: `load` is in
   `FRAME_READ_ONLY`, so the frame emits `load_write_value − load_read_value = 0` for every
   family holding the query, and S19's `rd_value_rule` reads it too. The cell with the
   stated property in this family is the word a **store** overwrites — `ram` is not a
   read-only query, no `mem_word` gate reads its read value and none of the family's
   eighteen obligations touches it — so the twin moves that, and the refusal genuinely comes
   from the permutation product: `MemoryArgument` at `verify_shard` step 10.
6. **`mem_word` carries no `bit0`/`bit1` at all**, where must-be-exact 1 says word accesses
   "force bit1 = bit0 = 0". Two columns and two gates fewer, and strictly stronger: a
   misaligned `lw` or `sw` has no witness rather than a refused one.
7. **`sub` and `src_sub` carry a single direct obligation, not a 16+16 pair.** Each is below
   the access width and so below `2^16`, which makes one halfword obligation their exact
   direct bound; `check_copowers` accepts that shape. Two columns and two obligations fewer
   than the uniform pattern, with the same bound.
8. **`se` carries no booleanity gate.** It is `SIGNEXT·sign`, a one-hot sum times a table
   bit, so it is boolean by construction, as S17's `eq` is. S18 wrote `se_boolean` for a
   column of the same name because S18's own must-be-exact 5 asked a sign-weighted form to
   carry one; S19 has no counterpart, and master rule 5's list — carry, wrap, selector — does
   not reach it.
9. **`mem_word` is the second registered family with no generic channel**, after
   `ADD_SUB_LUI_AUIPC`. `reads_generic_table()` is false, its setup list is identity's alone,
   and the whole no-generic path — `VerifyingKey::check`'s count rule, `reduce_shard`'s step
   11 and the prover's opening list — was already exercised by add/sub and needed no change.
10. **`lo` is pinned on a padding row, and that is why it is not a tamper control.**
    `lo_rule` is ungated, the shape `add_rule` and `old_bytes_rule` also have, so
    `lo = rs2 + lt·(old − rs2)` holds on every row — `rs2` where `lt` is 0, which a padding
    row's is. The negative control moves bounded columns' high chunks instead,
    whose only readers are their own obligations under `m_pc`. This was found by the twin
    failing, not by reading.
11. **Acceptance 7 needed no new code.** `crates/program/tests/partition.rs` already carried
    all three parts from S11 — `fib`'s derived config excluding atomics, `guests/atomics`
    with the family detached failing at its first atomic's pc with
    `NotAllOpcodesSupported`, and the undetached control deriving the family and passing the
    partition check. S19 cites them rather than rebuilding them; what changed there is the
    default-heights test, per deviation 1.
12. **Acceptance 4's emulator half needed no new code either.** `data_word` has refused a
    misaligned access as `EmuError::Misaligned` since S12, in `run` and `trace_run` alike,
    and a fatal error returns no trace. The circuit half is new and is tested as rows.

---

## Acceptance

File paths are under `crates/` unless stated. Every test listed passes **on this machine**,
except the ones marked *deferred*, which are `#[ignore]`d and were run locally by name
("Verification performed"), and the two marked *(CI)*, which need a Linux host with
`qemu-user` and were **not** run here: `emulator/tests/differential.rs` and
`loader/tests/qemu.rs::mem_passes_its_checks`. Their emulator-side twin,
`emulator/tests/trace.rs`, does run here and asserts the guest exits 50.

| # | Item | Where | Result |
| --- | --- | --- | --- |
| 1 | Per-instruction differential for all 19, and a proof per family | `emulator/tests/differential.rs` *(CI)*, `emulator/tests/trace.rs` (`mem` in `TRACED`), `loader/tests/qemu.rs::mem_passes_its_checks` *(CI)*, `prover/tests/mem.rs` (deferred), `checker/tests/mem_fill.rs` | All nineteen run in `guests/mem`, which self-checks every one and exits 50, and the eleven atomics also in `guests/atomics` and `guests/opcodes`; the statement's seven shards prove and every one verifies, with each proof's shape read off its circuit; and in ordinary CI all three fills run over the guest's real archive with every channel counted and every gate and bound holding |
| 2 | Exhaustive reduced-width splice check | `checker/tests/mem_subword.rs` | `mem_subword::splice_gates(1)` — the family's own gates at a 4-bit word — evaluated through `gkr::eval_gate` over every `(word, offset, width)` the circuit admits and every candidate `(high, sub, low)`: exactly one satisfies the gates and the bounds in each case, and it is the base-`(p, w)` decomposition |
| 3 | Load/store matrix | `checker/tests/mem_subword.rs`, `guests/mem` checks 7–27, `emulator/tests/differential.rs` *(CI)* | `lb`/`lbu` at all four byte offsets and `lh`/`lhu` at both halfword offsets, with sign extension of a negative byte and a negative halfword and zero extension of both; `sb` at all four offsets and `sh` at both, each leaving the rest of its word intact and each truncating a source whose high bytes are set; and `lw`/`sw` round-tripping — as rows, and in the guest whose every value QEMU and the emulator confirm |
| 4 | Misalignment | `checker/tests/mem_word.rs`, `checker/tests/mem_subword.rs`, `emulator/src/lib.rs::data_word` | An `lw` at each of the three non-zero offsets mod 4 and an `lh` at an odd address are unprovable: every gate still holds and the refusal is `word_index`'s own range pair, or `half_aligned` alone. The emulator reports `Misaligned` before staging an event, so no trace exists to prove, and a fatal error returns no trace at all |
| 5 | Atomics semantics matrix | `checker/tests/atomics.rs`, `guests/mem` checks 28–50 | An `lr.w`/`sc.w` pair with `sc.w`'s `rd` asserted 0; every AMO with sign-boundary operands, so signed min and max disagree with unsigned across `0x7fffffff`/`0x80000000` in both directions; two consecutive `amoadd`s to one address, which exercises the timestamp ordering; and `rd = old` asserted for every AMO |
| 6 | `rd = x0` coverage | `checker/tests/mem_word.rs`, `checker/tests/atomics.rs`, `guests/mem` checks 4, 19 and 48 | `lw x0`, `lbu x0` and `amoadd.w x0` prove, each computing a nonzero value the x0 rule discards, and `x0` still reads 0 afterwards — checked in the guest against a zero produced by `lui`, not by reading `x0` |
| 7 | Static detachment | `program/tests/partition.rs` | (a) `fib`'s derived `VmConfig` excludes the atomics family, asserted from the config; (b) `guests/atomics` with `ATOMICS` detached fails preprocessing at its first atomic's pc with `NotAllOpcodesSupported`, the same loud failure as an unknown opcode; (c) the undetached control derives the family and the partition check passes. All three are S11's mechanism, exercised here (deviation 11) |
| 8 | Tamper twins | `checker/tests/tamper.rs::s19_a8_…` (deferred) | One per family, each refused in its class: the word an `sw` overwrites — the cell no gate of that family reads — `MemoryArgument`; a `low` splice cell, `Constraint`; an AMO's `rd_selected`, `Constraint`. Beyond the item a decoder count, `Lookup { DECODER }`, so three classes are on screen; the honest statement verifies (the harness asserts it); the structural counts hold, including the first `ZERO_WINDOWS` shard any acceptance statement has had; and the negative controls verify |
| 9 | Padding rows and the fixture diff | the three row suites' `the_padding_row_is_the_all_zero_row` and `the_circuit_is_the_fixture_and_keeps_every_rule`, CI's fixture diff | The all-zero padding row passes every validator of both enforcement points, which each `artifact` also asserts at construction, and all three `.bin` fixtures are regenerated and diffed in CI |

---

## Artifacts

| Path | Size | SHA-256 | What |
| --- | --- | --- | --- |
| `crates/constraints/tests/vectors/mem_word.bin` | 60,383 bytes | `2c8d94caf25872fca7f9524ec40c47435264676d14819f9da4be8ffdf7ca4500` | `mem_word::artifact` at `trace_vars` 22 |
| `crates/constraints/tests/vectors/mem_subword.bin` | 98,846 bytes | `2c423eb1c5dc9b8a3c326dcb32b57f2a0edecffbb5ca9041e1a6cc9f9f596181` | `mem_subword::artifact` at `trace_vars` 22 |
| `crates/constraints/tests/vectors/atomics.bin` | 102,965 bytes | `ae58b1ca82916f6d519636836c889f31266bc694e7929e43c65ba574643d3108` | `atomics::artifact` at `trace_vars` 22 |
| `crates/loader/tests/vectors/mem.elf` | 9,104 bytes | `c8b5d5e79fa11571661cf11258ebee8cb450e7de8b9043d55b46d45a8f2d9dc1` | the guest, dev profile |

**No other fixture moved.** Every earlier circuit fixture, every other guest ELF, the packed
generic table's commitments and **both identity pins** regenerate byte for byte — the
identity pins because `guests/fib` is A-free, so the `DEFAULT_HEIGHTS[ATOMICS]` change does
not reach its `VmConfig`. The packed table is unmoved because S19 appended nothing to it,
which is the first stage since S16 that has not.

**Shapes**, at `2^20`:

| family | committed | depth | gate list 0 | lookups (ts/r16/gen/dec) | proof |
| --- | --- | --- | --- | --- | --- |
| `MEM_WORD` | 31 `M` + 24 `W` + 7 `S` = 62 | 25 | 68 leaves + 33 enforcing | 18 (12/5/0/1) | 56,268 bytes |
| `MEM_SUBWORD` | 31 `M` + 55 `W` + 10 `S` = 96 | 26 | 120 leaves + 53 enforcing | 36 (12/22/1/1) | 68,116 bytes |
| `ATOMICS` | 26 `M` + 54 `W` + 9 `S` = 89 | 26 | 132 leaves + 46 enforcing | 36 (10/19/6/1) | 68,468 bytes |

`MEM_WORD`'s proof is **the shortest of the seven execution families**, shorter even than
add/sub's: 24 witness commitments against 31 and a 62-column base layer against 74. The
other two are 26 transitions deep where add/sub, jump/branch/slt and `MEM_WORD` are 25 —
their `RANGE16` trees pad past 16 leaves, which costs one row-wise level, as S18's two do.

---

## Verification performed

On macOS (18 cores, 48 GB), every gate the root `CLAUDE.md` lists, at the final tree:

- `fmt --check` in all four workspaces, and `clippy -D warnings` in all four;
- `cargo test --workspace`: **945 passed, 56 `#[ignore]`d** (881 and 53 at S18). The 64 new
  CI-sized tests: `checker/tests/mem_word.rs` 12, `mem_subword.rs` 17, `atomics.rs` 15,
  `mem_fill.rs` 3, and `constraints` unit 17 (five in `mem_word`, seven in `mem_subword`,
  five in `atomics`); plus the extensions to the loader, program, emulator and artifact-dump
  fixture suites the new guest joins, and `kat-gen`'s three new fixture entries under its
  existing test. The 3 new ignored
  ones are `prover/tests/mem.rs`' one, `checker/tests/tamper.rs`' one and
  `loader/tests/qemu.rs`' `mem` case;
- the `riscv32imac` build of `field`, `constants`, `transcript`, `poly`, `sumcheck`,
  `constraints`, `gkr-verify` and `verifier-core`; the guest workspace's clippy with
  `guests/mem` in it;
- `cargo run -p kat-gen`, then the fixture diff: **nothing tracked moves**. The three new
  `.bin` files and `mem.elf` are the only additions, every other guest ELF and every other
  circuit fixture regenerates byte for byte, `generic_table.txt` is unmoved — S19 appended
  nothing to the packed table — and `transcript-ref` leaves no diff;
- a **mutation check** over the three row suites, since a suite written against a circuit
  can agree with it vacuously. Three semantic edits, one per family, each reverted: the `K`
  in `p_rule` off by one (caught by `a_halfword_at_an_odd_address_is_unprovable` and
  `every_row_kind_…`), the comparison's `signed` set widened to include `amominu` — the
  exact break §6.4's assertion exists for — (caught by
  `the_comparison_is_over_the_old_word_and_rs2` *and* by
  `the_min_and_max_kinds_disagree_across_the_sign_boundary`), and the alignment obligation
  scaled by 2 instead of 4 (caught by `a_word_index_above_2_to_the_30_is_refused`). Each is
  caught by a **semantic** test, not only by the fixture pin.

**The deferred suites**, `--include-ignored --test-threads=1`, on the final tree:

| Suite | Result | Wall | Peak resident |
| --- | --- | --- | --- |
| `prover --test mem` | 1 passed | 119 s | 14.73 GB |
| `checker --test tamper`, the **whole file** | 9 passed | 1,469 s | 16.90 GB |

The tamper file was run whole, not only S19's twin, so S16's, S17's and S18's twins are
green under this tree as well — which is also the measurement behind the 16.9 GB every
document now quotes for that file. S19's own twin alone is 346 s and 16.85 GB. None of the
earlier guests contains an A instruction, so the `DEFAULT_HEIGHTS[ATOMICS]` change cannot
reach their configs, and every other change this stage makes to `crates/prover` is
additive. All of
them stay commented out of `.github/workflows/ci.yml` under `# DEFERRED:` lines, master
rule 7: every execution shard is `2^20` rows, the timestamp channel's floor.

**Not run here: the QEMU suites.** `qemu-riscv32` is user-mode emulation and has no macOS
build (`crates/loader/CLAUDE.md`), so `loader --test qemu`, `emulator --test differential`
and `emulator --test consistency` need the colima container the root `CLAUDE.md` documents.
`guests/mem`'s emulator side *is* covered in ordinary CI — `emulator --test trace` runs it
and asserts it exits 50, and every expected value in it was computed from an exact RV32IMA
model — but its QEMU comparison has not been run on this machine.

**Measurements.** `mem`'s statement — five execution families at `2^20`, `INIT_TEARDOWN`
and one `ZERO_WINDOWS` shard at `2^16`, the toy SRS — proves and verifies in 119 s on 18
cores, setup included, which makes it the heaviest statement in the repository. Each of the
three circuits builds in a few milliseconds.

---

## Deferred work, by stage

**The I/O-binding stage.** Unchanged from S16's, S17's and S18's lists, with one addition
S19 makes explicit: when ecall transfer cycles become provable, **that family's
`ram_write_value` must carry a 32-bit bound of its own**. Today no `ADD_SUB_LUI_AUIPC` row
can reach RAM at all — its `ram_mask_rule` is the ungated `ram_mask = 0` — so the write-side
induction (`docs/spec/memory-ops.md` §5.1) rests on a circuit gate, not on
`prover::fill::add_sub` refusing a transfer cycle by name, which is a completeness check.
`EXIT` is still the only provable ecall.

**S20.** Non-trivial time windows, many shards per family, and aggregation. S19 is the first
stage whose statement has a `ZERO_WINDOWS` shard, so the window path is now exercised end to
end by an acceptance test as well as by `crates/checker/tests/memory.rs`.

**The heaviest statement.** `guests/mem`'s is now the largest the repository proves, and the
tamper file peaks at 16.9 GB with it. Each further family added to a fixture guest adds a
`2^20` shard to every proof and every re-proof; S18 named splitting the fixture guest per
family as the lever if that becomes binding, and it still is.

---

## Open for the owner

- **Should the generic-channel key-bounding rule become a construction-time check?** S18
  left this open, and S19 is the first stage that could have reopened the hole and did not:
  `mem_subword`'s one `U16GetSign` key and `atomics`' four AND keys each carry a bound, and
  `check_copowers` covers the four that are scaled. The count of `GENERIC` lookups across
  registered families is now thirteen, in three families. The check S18 described — every
  `GENERIC` lookup's key column is range-bounded into its own sub-table's range, or the
  circuit names the gate that excludes the foreign rows — would refuse the defect at
  construction rather than leaving each family to remember. It is still new surface area and
  still the owner's call; S19 ships the bounds and the row that proves the attack, not the
  rule.
- **How a verifier obtains the trusted SRS digest** is unchanged from S16, S17 and S18. S19
  did not move the packed table, so the pinned commitments are S18's.
- **`MEM_WORD` and `MEM_SUBWORD` default to `2^22` and `ATOMICS` now to `2^20`**, while
  `MUL_DIV` is `2^20` and the rest `2^22`. Whether per-family heights should exist at all is
  S12's open question, and S19 has not touched it; what S19 does add is the rule that no
  family running cycles may default below `2^20`, which is now stated in
  `constants::family::DEFAULT_HEIGHTS`' own doc comment.
