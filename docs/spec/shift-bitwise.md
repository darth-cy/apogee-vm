# The `SHIFT_BITWISE` family: shifts and bitwise operations

Frozen as of S18. Changing anything here is a protocol-version change.

This page is S18's first circuit family as the repository owner decided it: `sll`, `slli`,
`srl`, `srli`, `sra`, `srai`, `and`, `andi`, `or`, `ori`, `xor` and `xori`, proved by **one
merged circuit** whose two halves share a frame, a decoded table and a `rd` column, and
whose shifts settle both directions through one multiplication. It cites
`docs/spec/memory.md` for the frame, `docs/spec/lookup.md` for the channels and
`docs/spec/shard-proof.md` for the statement, the key and the transcripts, and restates none
of them. `docs/spec/mul-div.md` is its sibling and `docs/spec/constraint-manifest.md` §5 is
the column-by-column account.

| crate | what |
| --- | --- |
| `crates/constants` | `generic_table::{SHIFT_BASE, SHIFT_ROWS, SHIFT_COPOWER_BITS}`: `ShiftPowers`' key base and its stored form (§3.1) |
| `crates/constraints` | `shift_bitwise`: the circuit (§2, §4, §5); `lookup::check_copowers`, tightened (§3.4); the registry's arm |
| `crates/program` | `lookup_tables`: `ShiftPowers`' 32 rows, packed into the generic table (§3.1) |
| `crates/prover` | the family's fill |
| `guests/alu` | the family's fixture program, shared with mul/div (§8) |

The owner's decisions this page records, each put before any code:

1. **`ShiftPowers` is packed into the existing generic table**, as a third sub-table beside
   the AND byte table and `U16GetSign`, rather than given a channel or a key entry of its
   own (§3.1). One triple of commitments stays in every verifying key and the SRS digest
   keeps covering it; the price is that the table's three commitments move, so every S16
   and S17 verifying key's bytes and SRS digest move with them, exactly as S17 moved S16's.
2. **The copower is stored halved**, `2^(31 − s)` rather than `2^(32 − s)` (§3.1). The
   value the residue bound multiplies by is `2^(32 − s)`, which at `s = 0` is `2^32` and
   does not fit the packed table's `u32` columns. The table stores half of it and the two
   gates that read it carry the compensating factor 2. The alternative — an `Fr`-backed
   column — costs about 134 MB per shard at `2^22` for one value in one row.
3. **One consolidated fixture guest**, `guests/alu`, covering this family and mul/div
   together, proved as one four-execution-family statement (§8).

A reading announced with those, which nobody objected to: the stage prompt's "preprocess
every degree-2 helper flag in the decoder" is met by the twelve committed one-hot kind
bits. A flag over them is a *linear form*, so every helper product is already degree 2, and
only the two flags a **lookup selector** needs — `f_shift` and `f_bitwise` — become columns
of their own. This is S17's answer 1 applied again: S11's table is not rebuilt.

---

## 1. What the circuit reads from the decoded table

S11's table for this family is `pc next_pc rs1 rs2 rd imm extra_mask`, one row per halfword,
`MINUS_ONE`-padded (`crates/program/CLAUDE.md`). `extra_mask` is one-hot over
`constants::extra_mask::shift_bitwise`:

| bit | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| kind | `slli` | `xori` | `srli` | `srai` | `ori` | `andi` | `sll` | `xor` | `srl` | `sra` | `or` | `and` |

`imm` is the value the instruction uses, two's complement: the **raw five-bit shamt** on
`slli`, `srli` and `srai` — `crates/isa`'s decoder refuses `shamt[5]` on RV32, so it is in
`[0, 32)` by construction — the sign-extended twelve-bit immediate on `andi`, `ori` and
`xori`, and **0** on every R-type row. A form's absent register is `x0`, whose read value is
0. `next_pc` is the fall-through, `pc + 2` or `pc + 4` by the instruction's length; seven of
the twelve have compressed forms, so both lengths occur.

**The legal masks** are the twelve one-bit values, `shift_bitwise::LEGAL_MASKS`, and the
table's domain is what enforces them (`lookup.md` §10). `rd = x0` is not a mask of its own:
the table's `rd` column says it, and the frame's x0 rule acts on it (§4.1).

**One expression is the second operand of all twelve.** `src2 = rs2 + imm`, where `rs2` is
the frame's read value. On an I-type row the frame has no `rs2` query, so its read value is
0 and `src2` is the immediate; on an R-type row the table's `imm` is 0 and `src2` is the
register. One of the two addends is always zero, so the field sum is the integer sum and
needs no wrap bit — the same shape S16 uses for `add/addi/auipc`. The immediate therefore
never enters the permutation-tied `rs2` column.

Every signal the stage prompt asked the decoder for is a linear form over the twelve bits
`b_k` the circuit extracts:

| signal | form | on |
| --- | --- | --- |
| shift direction, left | `b_slli + b_sll` | `shift_in`, `shift_out` |
| shift direction, right | `b_srli + b_srai + b_srl + b_sra` | `shift_in`, `shift_out` |
| arithmetic | `b_srai + b_sra` | `se` |
| `t1`, the a+b term's selector | `b_or + b_ori + b_xor + b_xori` | `bitwise_out` |
| `t2`, the AND term's weight | `(b_and + b_andi) − (b_or + b_ori) − 2·(b_xor + b_xori)` | `bitwise_out` |
| `f_shift`, `f_bitwise` | the sums of the six shift and six bitwise bits | committed, because each is a lookup selector |

## 2. Columns

`constraints::shift_bitwise::artifact(trace_vars)` and `::channels()`, through S15's
`frame_with_channels_artifact`. The circuit is built from `trace_vars = 19` — the timestamp
channel's width, which also holds the packed generic table's rows — and a provable height is
at least 20, a Mercury opening needing an even count.

The frame is `memory.md` §2.1's over the family's four queries — `pc rs1 rs2 rd` at slots 0
to 3 — so `M[0..21]` and `W[0..7]` (the four gap chunks, `rd_inv`, `rd_is_zero`,
`rd_selected`) are the frame's. The circuit adds:

| column | name | what |
| --- | --- | --- |
| `W[7]`–`W[12]` | `decoded_next_pc` … `decoded_mask` | the claimed decoded row, `lookup_tuple` after `pc` |
| `W[13]`–`W[24]` | `kind_slli` … `kind_and` | the mask's twelve bits, §1's order |
| `W[25]`, `W[26]` | `f_shift`, `f_bitwise` | the two halves; each is a lookup selector, so each carries a booleanity gate |
| `W[27]`, `W[28]` | `rs1_hi`, `rs1_sign` | `rs1 >> 16`, and its bit 31 from `U16GetSign` |
| `W[29]` | `src2_hi` | `(rs2 + imm) >> 16` |
| `W[30]` | `amount` | the truncated shift amount, `src2 & 31` |
| `W[31]`, `W[32]` | `pow`, `copow` | `2^amount` and `2^(31 − amount)`, the `ShiftPowers` row `amount` keys |
| `W[33]`, `W[34]` | `high`, `high_hi` | `src2 >> 5`, and its high halfword |
| `W[35]` | `se` | the sign-extension term, `is_arithmetic·rs1_sign` |
| `W[36]`, `W[37]` | `shift_in`, `shift_prod` | the multiplicand both directions share, and `shift_in·pow` |
| `W[38]`, `W[39]` | `ovf`, `ovf_hi` | a left shift's discarded high bits, and its high halfword |
| `W[40]`, `W[41]` | `residue`, `residue_hi` | a right shift's discarded low bits, and its high halfword |
| `W[42]`, `W[43]` | `scaled`, `scaled_hi` | `residue·2^(32 − amount)`, and its high halfword |
| `W[44]`–`W[47]` | `byte_a0` … `byte_a3` | `rs1`'s four bytes, low first |
| `W[48]`–`W[51]` | `byte_b0` … `byte_b3` | `src2`'s four bytes, low first |
| `W[52]`–`W[55]` | `byte_and0` … `byte_and3` | the bytewise AND, from the byte table |
| `W[56]` | `rd_hi` | `rd_selected >> 16` |
| `W[57]`–`W[60]` | `mult_timestamp`, `mult_range16`, `mult_generic`, `mult_decoder` | one multiplicity per channel, last |
| `S[0]`–`S[6]` | `table_pc` … `table_extra_mask` | the decoded table, bound by identity |
| `S[7]`–`S[9]` | `generic_key`, `generic_value`, `generic_result` | the packed generic table, opened against the key's, which the SRS digest covers |
| `V[range19]`, `V[range16]` | | the two range tables |

`rd_selected` (`W[6]`) is the value the instruction **computes**, before the x0 rule masks
it into the write, as at S16 and S17. **21 `M`, 61 `W`, 10 `S`: 92 committed columns**, and
the circuit is 26 transitions deep at `2^20` — one more than add/sub and the jump family,
because its `range16` fraction tree carries 24 obligations and pads to 32 leaves where
theirs fit in 16.

`shift_in` and `shift_prod` are the family's only `Fr`-backed columns: a left shift's
product reaches `2^63` and a right shift's multiplicand is negative on an `sra` of a
negative operand. Every other column is a `u32`.

## 3. The tables, and the bound on every key

### 3.1 `ShiftPowers`

Thirty-two rows, one per RV32 shift amount and none other, packed into the generic table
after `U16GetSign` (`lookup.md` §9):

```text
rows 2^17+1 ..= 2^17+32     (SHIFT_BASE + s + 1,  2^s,  2^(31 − s))
```

`SHIFT_BASE = SIGN_BASE + 2^16`, so the three key ranges are pairwise disjoint and the `+ 1`
the gating adds keeps every real entry off the all-zero tuple the `ZeroEntry` answers. The
packed table is now 131,105 rows, still inside `2^18`, and its three commitments moved —
`crates/program/tests/vectors/generic_table.txt` is the new pin, the SRS digest covers it,
and every S16 and S17 verifying key's bytes change with it. Identity binds none of it
(`jump-branch-slt.md` §6, unchanged).

**The domain is a bound, and not the one this family leans on.** A row that looks up
`ShiftPowers` under `f_shift` is matching a row of the packed table, and no row of it carries a
key above `SHIFT_BASE + 32`, so an amount above 31 matches nothing and the lookup fails. That
holds only because `ShiftPowers` sits at the top of the packed table with nothing above it:
appending a fourth sub-table there would leave those keys landing on its rows, which is §3.3's
whole subject. So `amount` carries a bound of its own besides, and an untruncated amount is
refused twice over.

**Why the copower is stored halved.** The residue bound of §4.3 multiplies by `2^(32 − s)`,
which at `s = 0` is `2^32`. The packed table's columns are `u32`-backed, so the stored value
is `2^(31 − s)` and the two gates that read it carry a factor 2:

```text
copower_rule   pow·copow − 2^31·f_shift = 0
scaled_rule    scaled − 2·residue·copow = 0
```

so `scaled` is exactly `residue·2^(32 − s)`, and `pow·copow = 2^31` is exactly
`pow·(2·copow) = 2^32`. The stored form is an encoding; the arithmetic is the prompt's.

`copower_rule` is redundant **given §3.3's bound on `amount`**, which confines the key to
`ShiftPowers`' own 32 rows, so the looked-up pair is already that row's. It is kept as the
circuit's own reading of the table — a `ShiftPowers` row generated wrong stops the honest
prover here, rather than licensing a residue bound that is not one — and it is a second,
independent reason the key cannot leave the sub-table: no AND row's `b·(a & b)` reaches
`2^31` (the largest is `255·255`), and every `U16GetSign` row's product is 0. On a bitwise
row `f_shift` is 0, so it says `pow·copow = 0` and the fill writes both as 0.

### 3.2 The byte AND table

The AND byte table is S15's and needs nothing new: rows `1 ..= 2^16` of the same packed
table, `(AND_BASE + a + 1, b, a & b)`. A byte column whose key matches one of its rows is
below 256, and the row it matches fixes the other operand and the result — but that is a
statement about *its own* rows, and §3.3 is why it is not enough on its own.

### 3.3 Every key is bounded before it is looked up

`docs/spec/lookup.md` §4 states the precondition: **a family must bound the keys it looks
up.** With three sub-tables packed into one channel it is load-bearing in a way it was not
when the channel held one map each stage used, because an out-of-range key does not *miss*
the table — it lands on **another sub-table's row**, and the lookup holds while the row
means something else entirely.

Concretely, and this is a witness against an earlier draft of this circuit rather than a
hypothetical: a bitwise row that claims `byte_a0 = 65_823` produces the gated key
`65_824`, which is `ShiftPowers`' row for `s = 31`, `(65_824, 2^31, 1)`. The lookup then
holds with `byte_b0 = 2^31` and `byte_and0 = 1`, and with `rs1 = 65_823` and
`rs2 = 2^31` — both ordinary register values — the recomposition writes `1` for
`and`, where the answer is `0`, and `rs1 ^ rs2 − 2` for `xor`. Every other gate holds and
both results are inside `[0, 2^32)`.

So each of the three keys this family looks up carries its own bound, and each bound is a
**pair**: the direct halfword check, and the column scaled so that the product is a
halfword only below the bound.

| key | bound | obligations | under |
| --- | --- | --- | --- |
| `rs1_hi + SIGN_BASE` | `rs1_hi < 2^16` | the 16+16 pair on `rs1` | `m_pc` |
| `amount + SHIFT_BASE` | `amount < 2^5` | `amount`, `2^11·amount` | `f_shift` |
| `byte_a_j + AND_BASE` | `byte_a_j < 2^8` | `byte_a_j`, `2^8·byte_a_j` | `f_bitwise` |

The direct half of each pair is the other half of S15's copower rule: a scaled bound alone
admits `k·2^(bits − 16)` for a small `k`, which is not a small integer at all. Bounding the
**key** is all that is needed — with `byte_a_j` below 256 the matched row is an AND row, and
that row fixes `byte_b_j` below 256 and `byte_and_j` to `byte_a_j & byte_b_j`.

### 3.4 The copower check

`constraints::lookup::check_copowers` is S17's construction-time assertion, **tightened at
this stage**: it now takes each copower-scaled column with the selector its scaled
obligation carries, and requires the direct range pair under *that same* selector. S17
matched an obligation on its expression alone, so a circuit whose direct pair sat under a
narrower selector than its scaled obligation passed the check while bounding nothing on the
rows the narrow selector switches off. The rule is conservative — a direct bound under a
genuinely broader selector is also sound — and conservative is the right side for a check
whose failure mode is silent. This family calls it over every column it bounds by scaling: `residue` under `m_pc`, whose
scale is the looked-up copower, and `amount` and the four byte keys under their own
selectors, whose scales are literals.

## 4. Gates

Forty-eight enforcing gates in gate list 0: the frame's ten (`memory.md` §2.4) and this
family's thirty-eight. Every one is degree 2 or less, and every one is zero on the all-zero
row, which `artifact` asserts.

### 4.1 Presence, addresses and `x0`

`m_rs1` and `m_rd` are `m_pc·Σ(all twelve bits)`, every kind reading `rs1` and writing `rd`;
`m_rs2` is `m_pc·(b_sll + b_srl + b_sra + b_and + b_or + b_xor)`, the R-type half alone.
Each present query's address is the decoded one, each absent operand reads 0, and `rd`
follows S14's x0 rule unchanged. `next_pc_rule` is `next_pc − decoded_next_pc = 0`, degree
1: no kind here computes a pc, so there is no wrap bit and no bound of its own — the decoder
lookup binds `decoded_next_pc` to the identity-committed table exactly as it binds `rs1`,
`rs2`, `rd` and `imm`, none of which is range-checked either. S17's rule that a family
computing a pc keeps it even does not reach a family that copies one.

### 4.2 The shift amount

```text
amount_split    rs2 + imm − 32·high − amount = 0
```

degree 1 and ungated. With `amount` in `[0, 32)` from `ShiftPowers`' domain, `high` bounded
by its own 16+16 pair and `src2` bounded by its own, the split is the unique one and
`amount` is the low five bits of the whole word. **Never leave the shamt free**: an `amount`
used only as a lookup key is prover-chosen, and `sll` with `rs2 = 4` would shift by 8.

On a bitwise row the gate still holds — the fill writes the true split — and `amount` is
unconstrained beyond it, `ShiftPowers` being switched off there.

### 4.3 The one product, and both directions

```text
se_rule         se − (b_srai + b_sra)·rs1_sign = 0
shift_in_rule   shift_in − (b_slli + b_sll)·rs1
                          − (b_srli + b_srai + b_srl + b_sra)·(rd_selected − 2^32·se) = 0
shift_prod_rule shift_prod − shift_in·pow = 0
shift_out_rule  (b_slli + b_sll)·(shift_prod − rd_selected − 2^32·ovf)
              + (b_srli + b_srai + b_srl + b_sra)·(shift_prod + residue − rs1 + 2^32·se) = 0
scaled_rule     scaled − 2·residue·copow = 0
```

`shift_prod_rule` is ungated and is the **only** multiplication by `pow`; `shift_in_rule`
chooses its multiplicand, which is why the gate above it stays degree 2. Writing either arm
as `is_left·(rs1·pow − …)` would be degree 3.

- **Left.** `shift_in = rs1`, so `shift_prod = rs1·2^s`, and the gate splits it as
  `rd + 2^32·ovf` with both parts 16+16 range-checked. `rs1 < 2^32` and `pow ≤ 2^31` put
  the product below `2^63`, so the field identity is the integer one and the split is
  unique.
- **Right.** `se` is the sign-extension term, 0 on every logical shift and `rs1`'s bit 31 on
  `sra` and `srai`. With `rs1_adj = rs1 − 2^32·se` and `rd_adj = rd − 2^32·se`, the gate is
  the floor-division identity `rs1_adj = rd_adj·2^s + residue`. It covers both directions of
  sign because an arithmetic shift of a negative word is the floor division of its signed
  value, and the result's sign is the operand's, so the same `se` adjusts both sides.

`se` is committed rather than inlined for exactly the degree reason: `is_arithmetic·rs1_sign`
appears inside two further products.

**The residue bound is the copower pattern, and it is half a bound twice over.** `scaled` is
`residue·2^(32 − s)` and is 16+16 range-checked, which says `residue < 2^32/2^(32−s) = 2^s`
— *given* `residue` is a genuine integer. Over `Fr` a "residue" of `s·(2^(32−s))^{-1}` would
satisfy the scaled bound and absorb `rs1 − rd·2^s` for any `rd` at all, so **`residue`
carries its own direct 16+16 range check** and `check_copowers` refuses the circuit without
it. With `residue < 2^32` and `copow ≤ 2^31` the product is below `2^64`, so the scaled
bound is an integer statement.

### 4.4 The bitwise half

```text
rs1_bytes        rs1 − Σ_j 2^(8j)·byte_a_j = 0
src2_bytes       rs2 + imm − Σ_j 2^(8j)·byte_b_j = 0
bitwise_out_rule f_bitwise·rd_selected − t1·(rs1 + rs2 + imm) − t2·Σ_j 2^(8j)·byte_and_j = 0
```

Both decompositions are degree 1 and ungated: on a shift row the byte columns carry no table
lookup, so a decomposition always exists and constrains nothing; on a bitwise row §3.3's pair
holds each `byte_a_j` below 256 and the AND row it matches holds `byte_b_j` there, so all eight
columns are bytes and each decomposition is the unique one.

**XOR and OR are derived from the single AND accumulator**, and there is no XOR table and no
OR table. Per byte `or = a + b − and` and `xor = a + b − 2·and`; summing by weight, and
using the two decompositions above,

```text
rd = t1·(rs1 + src2) + t2·Σ_j 2^(8j)·and_j
```

with `t1` and `t2` §1's linear forms. So `and` is `Σ 2^(8j)·and_j`, `or` is
`rs1 + src2 − Σ 2^(8j)·and_j`, and `xor` is `rs1 + src2 − 2·Σ 2^(8j)·and_j` — each exact
over the integers, since `a | b` and `a ^ b` are below `2^32` and no carry crosses a byte.
The accumulator is inlined as that linear form; it is never a committed column.

**The `rd` term is gated by the family bit, not by the bracket.** On a shift row `t1` and
`t2` are both 0, so a bare `rd_selected` would force `rd = 0` and break every shift. With
`f_bitwise` in front, the gate is `0 = 0` there.

### 4.5 Lookups

Thirty-nine obligations: the frame's eight timestamp gaps, then

| channel | obligations |
| --- | --- |
| `RANGE16` (24) | the 16+16 pairs on `rs1`, `src2`, `high`, `ovf`, `residue`, `scaled` and `rd_selected`, all under `m_pc`; then §3.3's key bounds — `amount` and `2^11·amount` under `f_shift`, and `byte_a_j` and `2^8·byte_a_j` under `f_bitwise` for each of the four bytes |
| `GENERIC` (6) | `rs1_get_sign` under `m_pc`; `shift_powers` under `f_shift`; `and_byte_0` … `and_byte_3` under `f_bitwise` |
| `DECODER` (1) | `decode_row` under `m_pc`, the seven-column tuple |

`artifact` asserts those counts when it builds the circuit, so a dropped obligation panics
at construction rather than passing silently, and runs `check_copowers` over all six scaled
columns.

## 5. Why it is sound

Take a live row: `m_pc = 1`, so the decoder lookup holds and the row's `(pc, next_pc, rs1,
rs2, rd, imm, mask)` is a row of the identity-committed table. The mask is therefore one of
the twelve legal values, `decoded_mask_bits` makes the twelve bits its unique boolean
decomposition, and exactly one kind bit is 1.

- **The operands are what the instruction reads.** The mask rules put each query where the
  kind has one, the address rules tie each to the decoded register, and the memory argument
  ties each read value to the last write of that register. `src2` is `rs2 + imm` with one
  addend zero, and its own 16+16 pair bounds it to a word.
- **The amount is the ISA's.** `ShiftPowers`' domain puts `amount` in `[0, 32)` and fixes
  `pow` and `copow`; `amount_split` with `high` bounded makes `amount` the low five bits of
  `src2`, uniquely.
- **A left shift is exact.** `shift_prod = rs1·2^s < 2^63`, and `rd + 2^32·ovf` with both
  below `2^32` is the unique split of an integer below `2^64`. So `rd = (rs1 · 2^s) mod
  2^32`.
- **A right shift is exact.** `residue ∈ [0, 2^s)` from the copower pair and its own direct
  bound; with `rs1_adj = rd_adj·2^s + residue` that determines `rd_adj = ⌊rs1_adj / 2^s⌋`
  uniquely, and `rd = rd_adj + 2^32·se` with `rd < 2^32` determines the word. For `srl`,
  `se = 0` and this is the logical shift; for `sra`, `se` is `rs1`'s bit 31 — bound by
  `U16GetSign` over a range-checked halfword — and `rd_adj` is the arithmetic shift's signed
  result, whose sign is the operand's, so the sign-extended word is `rd_adj + 2^32·se`.
- **A bitwise result is exact.** §3.3's pair bounds each `byte_a_j` below 256, so its gated
  key is inside the AND table's own range and the row it matches is an AND row; that row
  bounds `byte_b_j` below 256 and makes `and_j` the true `a_j & b_j`. The two
  decompositions are then unique given `rs1 < 2^32` and `src2 < 2^32`, and the
  recomposition is the identity above.
- **What it writes is bounded.** `rd_selected` carries its own 16+16 pair, so the value
  entering the memory argument is a word; the x0 rule masks the write where the destination
  is `x0`.

On a padding row `m_pc = 0`, every frame mask is 0, every leaf is 1 and every obligation
under `m_pc` is vacuous. `f_shift` and `f_bitwise` are free booleans there, so a padding row
may look `ShiftPowers` or the byte table up; it consumes a table multiplicity and changes
nothing, the `rd` query being absent. Every gate is zero on the all-zero row the prover pads
with.

## 6. What this family does not do, and the controls

- **It computes no pc.** `next_pc` is the decoded fall-through, so `HALT_PC` is unreachable
  from here and S17's evenness obligation has nothing to bite on.
- **It reads no RAM.** Its frame is four queries; `arg1`, `arg2`, `load` and `ram` are not
  in it, and a trace routing such an event here fails in the honest prover's
  `frame_rows`, loudly (`memory.md` §2.1).
- **It does not bound `rs2` on its own where `src2` suffices.** The bound that matters is on
  `rs2 + imm`, which is what both halves read; a separate bound on `rs2` would be a second
  reading of the same fact.
- **It does not bound `byte_b_j` or `byte_and_j`.** Bounding the key is the whole of it:
  an in-range key matches an AND row, and that row is what fixes the other two (§3.3).
- **`copower_rule` is the one check kept though it is implied** — by `amount`'s bound,
  which confines the key to `ShiftPowers`. It is one gate, and it turns a
  table-generation error into a refusal at the row rather than a wrong word in a register.
  `rd_selected`'s range pair is **not** redundant: a left shift's
  `shift_prod = rd + 2^32·ovf` needs `rd < 2^32` for the split to be unique.

## 7. The fill

`prover::family_fill(SHIFT_BITWISE)`. It reads the shard's cycles from the family's trace
buffer, the decoded row from the family's table at `pc/2`, and computes every column from
Rust's own `u32` and `i64` arithmetic — never from the circuit. It writes `rd_selected` with
the value the instruction computes, where S14's frame builder writes 0 on an `x0` write, and
writes the decoded table as `S[0..7]` and `program::lookup_tables::generic_table` as
`S[7..10]`.

It panics, which the emulator cannot cause, if the trace and the decoded table disagree: a
cycle at a pc the table does not hold, an `rd` write or a `next_pc` that is not what the
instruction computes, a right shift whose residue is not below its power, or a row carrying
both a register `rs2` and a nonzero immediate.

## 8. The fixture

`guests/alu`, shared with `MUL_DIV` (`mul-div.md` §8): a hand-written `_start` in the
instructions of the four families S18 proves plus the exit ecall, checking every result
itself and exiting with the number of checks, 96. Every expected value in it was computed
from an exact RV32IM model rather than by hand, and the emulator, `qemu-riscv32` and the
guest's own checks are three independent readings of the same twenty instructions.

Its shift/bitwise coverage is the stage's acceptance 2 in full: shamt 0, 1 and 31 for each
immediate shift; `rs2 = 32` and `rs2 = 33`, which truncate to 0 and 1; `sra` of a negative
operand at 0, 1 and 31; `srai` against `srli` on the same negative operand at the same
shamt; the immediate bitwise forms against a sign-extended negative immediate; `rd = x0`;
and the seven compressed forms, so the family's decoded rows carry both fall-through widths.

The circuit fixture is `crates/constraints/tests/vectors/shift_bitwise.bin`,
`shift_bitwise::artifact` at `trace_vars` 22, regenerated by `cargo run -p kat-gen -- family`
and diffed in CI.
