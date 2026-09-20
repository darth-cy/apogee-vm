# The `MUL_DIV` family: the M extension

Frozen as of S18. Changing anything here is a protocol-version change.

This page is S18's second circuit family as the repository owner decided it: `mul`, `mulh`,
`mulhsu`, `mulhu`, `div`, `divu`, `rem` and `remu`, proved by one circuit in which **one
product identity serves all four multiplies and the division alike**. It cites
`docs/spec/memory.md` for the frame, `docs/spec/lookup.md` for the channels and
`docs/spec/shard-proof.md` for the statement, the key and the transcripts, and restates none
of them. `docs/spec/shift-bitwise.md` is its sibling and `docs/spec/constraint-manifest.md`
§6 is the column-by-column account.

| crate | what |
| --- | --- |
| `crates/constraints` | `mul_div`: the circuit (§2, §4, §5), and `arithmetic_gates(word_bits)`, the width seam the exhaustive check drives (§6); the registry's arm |
| `crates/prover` | the family's fill |
| `guests/alu` | the family's fixture program, shared with shift/bitwise (§8) |

The owner's decisions this page records, each put before any code:

1. **`|rem| < |divisor|` is a directly range-checked gap**, not a call to S17's comparison
   gadget (§4.5). The Core algorithm's recipe is "magnitude gadgets plus a range-checked gap
   carrying a zero-divisor correction term", and a comparison gadget has nowhere to put that
   correction. The magnitudes are bounded by their operands' own ranges, so the gadget's
   operand range pairs and its two `U16GetSign` lookups would prove nothing that already
   holds: five committed columns and six obligations per row of dead weight. S17's
   `gadgets::is_zero` **is** used, twice.
2. **One consolidated fixture guest**, `guests/alu`, shared with shift/bitwise and proved as
   one four-execution-family statement (§8).

A reading announced with those, which nobody objected to: **the signed overflow needs no pin
of its own**, and adding one would be a redundant gate. See §5.3, which also explains why the
quotient's sign flag must stay free for that case to be provable at all.

---

## 1. What the circuit reads from the decoded table

S11's table for this family is `pc next_pc rs1 rs2 rd extra_mask` — **six columns, not
seven: this family's tuple carries no `imm`**, every one of its instructions being R-type
(`crates/program/CLAUDE.md`). `extra_mask` is one-hot over `constants::extra_mask::mul_div`:

| bit | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| kind | `mul` | `mulh` | `mulhsu` | `mulhu` | `div` | `divu` | `rem` | `remu` |

`next_pc` is the fall-through, always `pc + 4`: the M extension has no compressed form.

**The legal masks** are the eight one-bit values, `mul_div::LEGAL_MASKS`, and the table's
domain is what enforces them (`lookup.md` §10). `rd = x0` is not a mask of its own.

Every signal the stage prompt asked the decoder for is a linear form over the eight bits
`b_k`, except the one a gadget's `enable` needs:

| signal | form | on |
| --- | --- | --- |
| lhs signed | `b_mul + b_mulh + b_mulhsu + b_div + b_rem` | `s1` |
| rhs signed | `b_mul + b_mulh + b_div + b_rem` | `s2` |
| the multiplies | `b_mul + b_mulh + b_mulhsu + b_mulhu` | `mx`, `my` |
| `f_div` | `b_div + b_divu + b_rem + b_remu` | committed, being the `enable` of two is-zero gadgets |
| rd takes the low half | `b_mul` | `rd_value_rule` |
| rd takes the high half | `b_mulh + b_mulhsu + b_mulhu` | `rd_value_rule` |
| rd takes the quotient | `b_div + b_divu` | `rd_value_rule` |
| rd takes the remainder | `b_rem + b_remu` | `rd_value_rule` |

`mul` is listed as signed × signed. Its low half is the same read either way, so the choice
is free; taking it signed is what lets **one** product identity serve all four multiplies.
`mulhsu` is the asymmetric one: its `rs1` is signed and its `rs2` is not, which the two
separate flag lists express and no case split does.

## 2. Columns

`constraints::mul_div::artifact(trace_vars)` and `::channels()`, through S15's
`frame_with_channels_artifact`. The circuit is built from `trace_vars = 19`; a provable
height is at least 20, a Mercury opening needing an even count.

The frame is `memory.md` §2.1's over the family's four queries — `pc rs1 rs2 rd` at slots 0
to 3 — so `M[0..21]` and `W[0..7]` are the frame's. The circuit adds:

| column | name | what |
| --- | --- | --- |
| `W[7]`–`W[11]` | `decoded_next_pc` … `decoded_mask` | the claimed decoded row: **five**, the tuple having no immediate |
| `W[12]`–`W[19]` | `kind_mul` … `kind_remu` | the mask's eight bits, §1's order |
| `W[20]` | `f_div` | the division half; the `enable` of both is-zero gadgets, so it carries a booleanity gate |
| `W[21]`, `W[22]` | `rs1_hi`, `rs1_top` | `rs1 >> 16`, and its bit 31 from `U16GetSign` |
| `W[23]`, `W[24]` | `rs2_hi`, `rs2_top` | `rs2 >> 16`, and its bit 31 |
| `W[25]`, `W[26]` | `s1`, `s2` | the sign **adjustments**: the top bit where the kind reads that operand signed, 0 where it does not |
| `W[27]`, `W[28]` | `mx`, `my` | the one product's two multiplicands |
| `W[29]`–`W[33]` | `p_low`, `p_low_hi`, `p_high`, `p_high_hi`, `p_sign` | the product's halves with their high halfwords, and its sign |
| `W[34]`–`W[36]` | `q`, `q_hi`, `q_sign` | the quotient word, its high halfword, and its sign adjustment |
| `W[37]`–`W[39]` | `r`, `r_hi`, `r_sign` | the remainder word, its high halfword, and its sign adjustment |
| `W[40]`, `W[41]` | `r_inv`, `rz` | `is_zero` over `r`, enabled by `f_div` |
| `W[42]` | `d1` | `f_div·s1`: a division row with a negative dividend |
| `W[43]`, `W[44]` | `d_inv`, `dz` | `is_zero` over `rs2`, enabled by `f_div` |
| `W[45]`, `W[46]` | `abs_r`, `abs_d` | `\|rem\|` and `\|divisor\|` |
| `W[47]`, `W[48]` | `gap`, `gap_hi` | `\|divisor\| − \|rem\| − 1`, corrected on a zero divisor, and its high halfword |
| `W[49]` | `rd_hi` | `rd_selected >> 16` |
| `W[50]`–`W[53]` | `mult_timestamp`, `mult_range16`, `mult_generic`, `mult_decoder` | one multiplicity per channel, last |
| `S[0]`–`S[5]` | `table_pc` … `table_extra_mask` | the decoded table — **six columns** — bound by identity |
| `S[6]`–`S[8]` | `generic_key`, `generic_value`, `generic_result` | the packed generic table, opened against the key's |
| `V[range19]`, `V[range16]` | | the two range tables |

**21 `M`, 54 `W`, 9 `S`: 84 committed columns**, and the circuit is 26 transitions deep at
`2^20`. `mx`, `my`, `r_inv` and `d_inv` are the family's only `Fr`-backed columns: the first
two are signed and the last two are field inverses.

## 3. The sign adjustments

Each operand enters the arithmetic as a signed value:

```text
rs1_adj = rs1 − 2^32·s1        rs2_adj = rs2 − 2^32·s2
```

`rs1_top` and `rs2_top` come from `U16GetSign` over range-checked high halfwords, so each is
the operand's bit 31 — a key bounded to its own sub-table's range, as
`docs/spec/lookup.md` §4 requires and `docs/spec/shift-bitwise.md` §3.3 explains. `s1` and
`s2` are those bits gated by the kind's signedness flags, so an **unsigned position forces
its flag to 0** whatever the operand's top bit, which is what keeps the selection degree 2
and makes `mulhsu`'s asymmetry one gate rather than a case split.

Every boolean the family leaves **free** carries a booleanity gate: `f_div`, `p_sign` and
`q_sign`, and, though each is implied, the two top bits, `s1`, `s2` and `r_sign` besides.
`rz` and `dz` are boolean by the is-zero gadget's construction and `d1` by the two columns
it multiplies, so none of the three carries one, as S17's `eq` does not.

`q_sign` and `r_sign` are **not** sign lookups — see §5.2 and §5.3.

## 4. Gates

Fifty-four enforcing gates in gate list 0: the frame's ten and this family's forty-four.
Every one is degree 2 or less and zero on the all-zero row, which `artifact` asserts. The
arithmetic half is `arithmetic_gates(WORD_BITS)`, a function of the word width so that the
exhaustive reduced-width check evaluates these gates and not a transcription of them (§6).

### 4.1 Presence, addresses and `x0`

Every one of the eight is R-type, so `m_rs1`, `m_rs2` and `m_rd` are each `m_pc·Σ(all eight
bits)`. Addresses, absent operands and the x0 rule are S14's, unchanged. `next_pc_rule` is
`next_pc − decoded_next_pc = 0`, degree 1: this family computes no pc either
(`shift-bitwise.md` §4.1).

### 4.2 One product identity

```text
mx_rule      mx − Σ_mul b·(rs1 − 2^32·s1) − f_div·(rs2 − 2^32·s2) = 0
my_rule      my − Σ_mul b·(rs2 − 2^32·s2) − f_div·(q − 2^32·q_sign) = 0
product_rule mx·my − p_low − 2^32·p_high + 2^64·p_sign = 0
```

On a multiply row the multiplicands are the two operands; on a division row they are the
divisor and the quotient. `product_rule` is ungated and is the **only** multiplication of
two row values, which is what lets both readings share it and keeps the identity degree 2.

On a multiply row `mx` and `my` are the sign-adjusted operands, each in `[−2^31, 2^32)`:
`[−2^31, 2^31)` where the kind reads that operand signed and `[0, 2^32)` where it does not.
On a division row `mx` is the sign-adjusted divisor, the same interval, and `my` is
`q − 2^32·q_sign` with `q` range-checked and `q_sign` boolean, so `(−2^32, 2^32)`. The
product therefore lies in `(−2^64, 2^64)` in both cases — the extreme is `−2^31·(2^32 − 1)`
on one side and just under `2^32·2^32` on the other, and neither reaches the endpoint. With
`p_low` and `p_high` each range-checked below `2^32` and `p_sign` boolean,
`p_low + 2^32·p_high − 2^64·p_sign` covers `(−2^64, 2^64)` exactly once, so the field
identity is the integer identity and the decomposition is unique.

`rd` is `p_low` for `mul` and `p_high` for the three high multiplies, selected by sums of
committed kind bits.

### 4.3 The division identity

```text
division_rule f_div·(p_low + 2^32·p_high − 2^64·p_sign + r − 2^32·r_sign
                     − rs1 + 2^32·s1) = 0
```

which, `mx·my` being `rs2_adj·q_adj` on a division row, is

```text
rs2_adj·q_adj + r_adj = rs1_adj
```

with `q_adj = q − 2^32·q_sign` and `r_adj = r − 2^32·r_sign`. **It is gated, and must be.**
On a multiply row `f_div` is 0, so §4.4 gives `d1 = 0` and therefore `r_sign = 0`, and `r`
is range-checked non-negative — so `r_adj ≥ 0`. An ungated identity over a multiply row
whose `rs2` is 0 then reads `r_adj = rs1_adj`, which no non-negative `r_adj` satisfies when
`rs1_adj` is negative. `mul t0, t1, x0` with a negative `t1` is an ordinary instruction, and
an ungated identity would make it unprovable.

**The identity alone says nothing useful.** On a zero divisor it degenerates to
`r_adj = rs1_adj`, and on every inexact division a floored witness satisfies it as readily
as a truncated one. The next two gates are what pin it.

### 4.4 (a) The remainder's sign

```text
rz_inverse, rz_at_nonzero   is_zero(r) enabled by f_div          → rz = f_div·[r = 0]
d1_rule                     d1 − f_div·s1 = 0
r_sign_rule                 r_sign − d1 + d1·rz = 0              → r_sign = d1·(1 − rz)
```

so `r_sign` is 1 exactly where the row is a division, the dividend is negative, and the
remainder is not zero. Stated as a definition rather than as the implication `rem ≠ 0 ⇒
sign(rem) = sign(dividend)`, it is the same constraint and is cheaper: the implication
gated to division rows is degree 3, and `d1` is the committed column that brings it back to
2.

**This is the easiest line to leave out and the one that separates truncated from floored
division.** Without it `DIV(−7, 2)` takes −4 as readily as −3, because
`2·(−4) + 1 = −7` satisfies the identity and `|1| < |2|` satisfies §4.5. And on an unsigned
row, where `d1` is 0 and so `r_sign` is 0, it is what forces `r_adj = r ≥ 0`, without which
`DIVU(0xDEADBEEF, 0x1234)` could return 801702 for 801701.

### 4.5 (b) The magnitude bound

```text
abs_r_rule  abs_r − r − 2^32·r_sign + 2·r·r_sign = 0            → abs_r = |r_adj|
abs_d_rule  abs_d − rs2 − 2^32·s2 + 2·rs2·s2 = 0                → abs_d = |rs2_adj|
dz_inverse, dz_at_nonzero   is_zero(rs2) enabled by f_div        → dz = f_div·[rs2 = 0]
gap_rule    gap − f_div·abs_d + f_div·abs_r + f_div − 2^32·dz = 0
```

`|x| = x + 2^w·sign − 2·x·sign` is degree 2 and exact for both flag values. `gap` is
`f_div·(abs_d − abs_r − 1 + 2^32·dz)` and is 16+16 range-checked, so on a division row with
a nonzero divisor `abs_d − abs_r − 1 ∈ [0, 2^32)`, which is `|rem| < |divisor|`.

The step that carries it is that **neither magnitude can reach `2^32`**, so the difference
cannot wrap into range from below. `abs_d = 2^32 − rs2` when `s2 = 1`, and `s2 = 1` only
where `rs2`'s top bit is set, so `rs2 ≥ 2^31` and `abs_d ≤ 2^31`; where `s2 = 0`,
`abs_d = rs2 < 2^32`. Likewise `abs_r = 2^32 − r` when `r_sign = 1`, and §4.4 makes
`r_sign = 1` only where `rz = 0`, which the is-zero gadget makes only where `r ≠ 0`, so
`abs_r ≤ 2^32 − 1`; where `r_sign = 0`, `abs_r = r < 2^32`. With both magnitudes in
`[0, 2^32)`, `abs_d − abs_r − 1` lies in `(−2^32 − 1, 2^32)`, and a field element of that
interval is in `[0, 2^32)` exactly when it is non-negative. Neither magnitude needs a range
obligation of its own.

**The zero-divisor correction is what makes a zero divisor impose no bound.** With `dz = 1`,
`abs_d` is 0 and `gap` is `2^32 − abs_r − 1`, which is in range for every `abs_r` below
`2^32`. On a multiply row `f_div` is 0, so `gap` is 0 and in range.

### 4.6 The two pins

```text
zero_divisor_quotient  dz·(q − (2^32 − 1)) = 0
```

is the whole of the div-by-zero pin. The remainder needs none: with `rs2_adj = 0` the
identity gives `r_adj = rs1_adj` directly, and §4.4 then fixes the word to `rs1`.

The **signed overflow** `−2^31 ÷ −1` needs no pin either; see §5.3.

### 4.7 Lookups

Twenty-seven obligations: the frame's eight timestamp gaps, then

| channel | obligations |
| --- | --- |
| `RANGE16` (16) | the 16+16 pairs on `rs1`, `rs2`, `p_low`, `p_high`, `q`, `r`, `gap` and `rd_selected`, all under `m_pc` |
| `GENERIC` (2) | `rs1_get_sign` and `rs2_get_sign` under `m_pc` |
| `DECODER` (1) | `decode_row` under `m_pc`, the **six**-column tuple |

`artifact` asserts those counts when it builds the circuit.

## 5. Why it is sound

Take a live row: the decoder lookup makes the mask one of the eight legal values,
`decoded_mask_bits` makes the eight bits its unique boolean decomposition, and exactly one
kind bit is 1. Both operands are range-checked words tied by the memory argument to the last
writes of the decoded registers, and both sign adjustments are §3's.

### 5.1 The multiplies

`mx·my = rs1_adj·rs2_adj` with the sign adjustments the kind selects, so the product is the
64-bit product RV32M defines — signed × signed for `mul` and `mulh`, signed × unsigned for
`mulhsu`, unsigned × unsigned for `mulhu` — and §4.2's decomposition is the unique one.
`p_low` is its low word and `p_high` its high word, read as two's complement where the
product is negative, which is exactly what an arithmetic `>> 32` of the 64-bit product then
truncated to 32 bits gives.

### 5.2 The divisions

Suppose `rs2_adj ≠ 0`. §4.4 fixes `r_sign` from `s1` and `[r = 0]`, so `r_adj` is determined
by the word `r`; §4.5 bounds `|r_adj| < |rs2_adj|`; §4.3 then gives
`q_adj = (rs1_adj − r_adj)/rs2_adj`, a division in `Fr` with a nonzero divisor and so a
unique value. Truncated division is the unique `(q_adj, r_adj)` with
`rs2_adj·q_adj + r_adj = rs1_adj`, `|r_adj| < |rs2_adj|` and `sign(r_adj) = sign(rs1_adj)`
or `r_adj = 0` — which is precisely the three gates — so `q_adj` and `r_adj` are the ISA's.

`q` is then pinned by its own range: `q = q_adj + 2^32·q_sign` must be in `[0, 2^32)`, and
since `q_adj ∈ (−2^32, 2^32)` exactly one `q_sign` puts it there. A `q_adj` that is not a
genuine small integer — the field quotient of a mismatched numerator, say — lands outside
`[−2^32, 2^32)` and no `q_sign` rescues it, so the range check on `q` refuses it.

With `rs2_adj = 0`: the identity gives `r_adj = rs1_adj`, so `r` is the dividend's word;
§4.6 pins `q` to all ones; `gap` is unconstrained by §4.5's correction; and `q_sign` is
free, which is harmless because `mx·my = 0` either way and `rd` reads the word `q`, not
`q_adj`.

### 5.3 Why the overflow needs no pin, and `q_sign` must stay free

`DIV(−2^31, −1)`: `|rem| < |−1|` forces `rem = 0`, so `r_adj = 0`; the identity gives
`q_adj = (−2^31)/(−1) = 2^31`; and `q = q_adj + 2^32·q_sign ∈ [0, 2^32)` forces `q_sign = 0`
and `q = 0x80000000`, which is the ISA's answer. `REM(−2^31, −1)` is `r = 0`, likewise. A
gate pinning either would be implied by the three gates that already hold.

That case is also why **`q_sign` must not be tied to bit 31 of `q`.** Here `q = 0x80000000`
has its top bit set while `q_sign` is 0 — a signed quotient of `+2^31` that does not fit a
signed 32-bit word, which is exactly what "overflow" names. A circuit that took `q_sign`
from `U16GetSign` over `q_hi`, as it takes `s1` and `s2` from the operands, would make this
one row unprovable. The same is true of `r_sign`, which §4.4 defines from the dividend's
sign rather than from the remainder's word.

### 5.4 What is redundant, and kept

`rd_selected`'s 16+16 pair is implied: every source `rd_value_rule` selects — `p_low`,
`p_high`, `q`, `r` — carries its own. It is kept because every family bounds what it writes
to `rd` in the same place, and one obligation pair is cheaper than a reader having to
re-derive the implication. Nothing else in this circuit is redundant.

### 5.5 Padding

On a padding row `m_pc = 0`, every frame mask is 0, every leaf is 1 and every obligation is
vacuous. `f_div` is a free boolean there, so a padding row may carry a division witness; it
constrains nothing, the `rd` query being absent. Every gate is zero on the all-zero row.

## 6. The width seam

`mul_div::arithmetic_gates(word_bits)` returns every gate whose formula carries the word
width, plus the two is-zero gadgets and the flags and booleanity the arithmetic reads; the
frame plumbing, which has no width, is not in it. `family_spec` calls it at `WORD_BITS = 32`,
the only width a proof uses.

The width is a parameter for one reason: S18's acceptance 5 enumerates, at a reduced width,
every `(dividend, divisor)` pair signed and unsigned and checks that the constraint set
determines the witness — and it must evaluate *these* gates rather than a transcription of
them. `gadgets::comparison_equation` carries its width for the same reason at S17.

**The acceptance item's "exactly one witness" is true up to one freedom, and the check
asserts the true statement.** Where the divisor is nonzero, exactly one `(q, r, q_sign)`
satisfies everything. Where it is zero, `q` is pinned to all ones and `r` to the dividend,
but `q_sign` is unconstrained — the identity's product is zero either way and `rd` reads
the word `q`, not `q_adj` (§5.2) — so both of its values satisfy and nothing else varies.
The kind bits' booleanity is not among the gates this function returns, being frame
plumbing; the check supplies one-hot bits, as a live row's decoder lookup does.

## 7. The fill

`prover::family_fill(MUL_DIV)`. It computes the division witness from Rust's own
`wrapping_div` and `wrapping_rem`, which give RV32M's **overflow** pin exactly —
`i32::MIN.wrapping_div(-1)` is `i32::MIN` and `wrapping_rem` is 0, where `/` and `%` would
panic — with the zero-divisor pin as its own arm before them, since Rust has no division by
zero to wrap; and the product from `i128` arithmetic — never from the circuit. It writes `rd_selected` with the value the
instruction computes, the decoded table as `S[0..6]` and the packed generic table as
`S[6..9]`.

It panics, which the emulator cannot cause, if the trace and the decoded table disagree: a
cycle at a pc the table does not hold, a division identity that does not divide, a quotient
word that is not its adjusted value, a product that does not fit two words, or an `rd` write
or `next_pc` that is not what the instruction computes.

## 8. The fixture

`guests/alu`, shared with `SHIFT_BITWISE` (`shift-bitwise.md` §8). Its mul/div coverage is
the stage's acceptance 3 and 4 in full: all four sign quadrants of each of the four
multiplies; `−2^31 × −2^31`; the asymmetric `mulhsu` corner `−2^31 × (2^32 − 1)`; `mulhu`
just under `2^64`; all four sign quadrants of `div` and `rem` and the unsigned pair;
`DIV(−7, 2)` and `REM(−7, 2)`, the rows a floored quotient would also satisfy the bare
division identity on; division by zero for all four; the one signed overflow; and `rd = x0`.

The circuit fixture is `crates/constraints/tests/vectors/mul_div.bin`, `mul_div::artifact`
at `trace_vars` 22, regenerated by `cargo run -p kat-gen -- family` and diffed in CI.
