# The `JUMP_BRANCH_SLT` family

The circuit of `slti`, `sltiu`, `slt`, `sltu`, the six branches, `jalr` and `jal` over 64-bit
registers: what it adds beside the memory frame every execution family carries
([memory.md](memory.md) §2), and the two gadgets other families reuse (§3). One comparison settles
signed and unsigned order for the branches and the `slt` kinds alike. The circuit is
`constraints::jump_branch_slt::artifact` (`crates/constraints/src/jump_branch_slt.rs`, on
`crates/constraints/src/family.rs`'s builder); `prover::family_fill` writes its witness. Its shape
is [circuits.md](circuits.md) §1's.

## 1. What the circuit reads from the decoded table

The tuple is `pc next_pc rs1 rs2 rd imm extra_mask` ([program.md](program.md) §5). `next_pc` is the
fall-through, `seq` below; `imm` is the low word of the sign-extended value the instruction uses —
`slti`'s and `sltiu`'s immediate (which `sltiu` compares unsigned), a branch's or `jal`'s
displacement, `jalr`'s offset — and `extra_mask`'s bit 31 its sign `neg`. The kind bits, in
`constants::extra_mask::jump_branch_slt` order:

```text
bit    0     1      2    3     4    5    6    7    8     9     10    11
kind   slti  sltiu  slt  sltu  beq  bne  blt  bge  bltu  bgeu  jalr  jal
```

Every signal is a linear form over the bits `b_k`: the signed flag `sc = b_slti + b_slt + b_blt +
b_bge`; the compared immediate `(b_slti + b_sltiu)·imm`, so a displacement never reaches the
comparison; the branch weights of `taken_rule` (§4).

## 2. Columns

The frame's `pc rs1 rs2 rd`; `v1`, `v2`, `vh1`, `vh2` below are the operands' read low and high
words, `pc` and `next_pc` the pc query's read and write, `sel`, `sel_hi` the frame's
`rd_selected`, `rd_selected_hi`. The family adds the builder's decoded row, kind bits and
`imm_negative`, and:

```text
cmp_rhs_lo cmp_rhs_hi           the compared right operand: rs2, or the sign-extended immediate
cmp_…                           §3.2's comparison of rs1 against it
eq eq_inv                       §3.1 over cmp_gap_lo + cmp_gap_hi
taken                           a branch's outcome
jalr_drop                       bit 0 of rs1 + imm on a jalr
pc_wrap hi_wrap                 the target's low-word carry, and its high word's
rd_h16 next_pc_h16              sel's and next_pc's high halfwords
```

## 3. The gadgets

### 3.1 `is_zero(x, inv, z, enable)`

`constraints::gadgets::is_zero`, which also builds the frame's x0 rule and `MUL_DIV`'s zero tests:

```text
x·inv + z − enable = 0          x = Σ c_i·x_i, a linear form
z·x = 0
```

With `enable` boolean, which the caller establishes, these force `z = enable·[x = 0]`: at `x ≠ 0`
the second gives `z = 0` and the first `inv = enable/x`; at `x = 0` the first gives `z = enable`.
So `z` is boolean with no gate of its own, and `enable = 0` gives `z = 0`, which keeps the all-zero
row valid.

### 3.2 The 64-bit comparison

`Family::compare64(p, lhs, rhs, signed)` orders two word pairs, `ATOMICS`' minimum and maximum
among its callers ([memory-ops.md](memory-ops.md)). With `lhs_sign`, `rhs_sign` the high words'
bit 31 from their `SIGN` lookups (`<p>_lhs_hi_get_sign`, `<p>_rhs_hi_get_sign`, which also bound the
high halfwords) and `borrow`, `lt` boolean:

```text
<p>_lo   lhs_lo − rhs_lo + 2^32·borrow − gap_lo
<p>_hi   lhs_hi − rhs_hi − borrow − 2^32·signed·(lhs_sign − rhs_sign) + 2^32·lt − gap_hi
```

and `gap_lo`, `gap_hi` are words, each a high halfword and two `RANGE16` obligations. The first gate
times 1 and the second times `2^32` sum to `lhs_s − rhs_s = gap − 2^64·lt`, `x_s` the operand read
signed where `signed` is 1 and `gap = gap_lo + 2^32·gap_hi ∈ [0, 2^64)`. Each gate's terms are below
`2^35`, so each holds over ℤ; `borrow` is the low words' borrow, the only value putting `gap_lo` in
a word, and since `|lhs_s − rhs_s| < 2^64` exactly one `lt` puts `gap` in range: `lt = [lhs_s <
rhs_s]`. Equality is `gap = 0`, which is `gap_lo + gap_hi = 0`, the two being non-negative words
whose sum is far below `p`.

## 4. Gates

The frame's gates, the builder's (`decoded_mask_bits`, booleanity of every bit, each query's mask,
address and value-mask rules), §3's, and:

```text
rs1_mask_rule     m_rs1 − m_pc·(Σ_k b_k − b_jal)
rs2_mask_rule     m_rs2 − m_pc·(branches + b_slt + b_sltu)
rd_mask_rule      m_rd − m_pc·(b_slti + b_sltiu + b_slt + b_sltu + b_jalr + b_jal)
cmp_rhs_lo_rule   cmp_rhs_lo − v2 − (b_slti + b_sltiu)·imm
cmp_rhs_hi_rule   cmp_rhs_hi − vh2 − (b_slti + b_sltiu)·(2^32 − 1)·neg
eq_inverse        x·eq_inv + eq − m_pc        x = cmp_gap_lo + cmp_gap_hi, §3.1
eq_at_nonzero     eq·x
taken_rule        taken − (b_bne + b_bge + b_bgeu) − (b_beq − b_bne)·eq
                    − (b_blt + b_bltu − b_bge − b_bgeu)·cmp_lt
next_pc_rule      next_pc + 2^32·pc_wrap − seq + (taken + b_jal + b_jalr)·seq
                    − (taken + b_jal)·(pc + imm) − b_jalr·(v1 + imm − jalr_drop)
jalr_hi           b_jalr·(vh1 + pc_wrap − 2^32·hi_wrap + (2^32 − 1)·neg)
rd_value_rule     sel − (b_jal + b_jalr)·seq − (b_slti + b_sltiu + b_slt + b_sltu)·cmp_lt
rd_hi_zero        sel_hi
```

The lookups are the frame's `TIMESTAMP` gaps; under `m_pc`, the comparison's, `rd`'s and
`next_pc`'s `RANGE16` pairs, and `next_pc_even`, `next_pc/2 − 2^15·next_pc_h16` on `RANGE16`; the
two `SIGN` lookups on `GENERIC`; and `decode_row` on `DECODER`.

## 5. Why it is sound

On a live row the decoder makes one kind bit 1 ([lookup.md](lookup.md) §10); the mask, address and
value-mask rules make the row's queries its kind's, an absent operand reading 0. `cmp_rhs` is `rs2`
or the immediate sign-extended to 64 bits, one addend 0, and §3.2 makes `cmp_lt` the signed or
unsigned `rs1 < cmp_rhs` and `eq` their equality. `taken_rule` is each branch's outcome: `eq` for
`beq`, `1 − eq` for `bne`, `cmp_lt` for `blt` and `bltu`, `1 − cmp_lt` for `bge` and `bgeu`.

`next_pc` is a word by its range pair and `pc_wrap` a bit, so `next_pc_rule` holds over ℤ, its terms
below `2^34`, and makes `next_pc` the low word of `seq`, of `pc + imm` for a taken branch or `jal`,
or of `rs1 + imm − jalr_drop` for a `jalr`. `jalr_hi` makes the `jalr` target's high word — `vh1`,
the immediate's sign extension and the carry in, a sum below `2^33` — vanish mod `2^32`, so every
`jalr` target is below `2^32`, as the emulator requires ([execution-trace.md](execution-trace.md)
§10). A branch's or `jal`'s target that leaves `[0, 2^32)` is the low word of one, at an address no
decoded table holds, so the next row's decoder lookup fails ([lookup.md](lookup.md) §10).

`next_pc_even` bounds `next_pc/2 − 2^15·next_pc_h16`, an integer below `2^16` only where `next_pc` is
even, the halving otherwise landing near `p/2` (`check_copowers` holds `next_pc`'s direct bound
beside it). So a `jalr`'s `jalr_drop` is bit 0 of `rs1 + imm`, a branch's target is even, and no row
of this family writes `HALT_PC = 1` ([memory.md](memory.md) §5): without it, a `jalr` whose
`rs1 + imm ≡ 1` would prove a clean exit for a program that jumps to address 0.

The link is `seq` and `rd`'s high word 0, both words, which `rd`'s range pair and `rd_hi_zero`
hold, and the x0 rule masks them at `x0`. On a padding row the mask rules zero every query mask,
`eq` is 0 and every lookup is off, so the row reaches no memory event whatever its free bits hold.

`crates/checker/tests/families.rs` holds the fill to the circuit over `control`'s, `opcodes`' and
`cpp-primes`' traces, every kind among them: every written word one off is refused by the row alone,
every gate and lookup refuses some single-cell edit, and
`a_flipped_comparison_is_refused_by_its_gap_alone` flips `cmp_lt` against its operands, re-solving
every column that follows it, and is refused by the gap's range obligations and nothing else.

## 6. The fill

`prover::family_fill(JUMP_BRANCH_SLT)` computes the comparison over `i64` or `u64`, the gap words,
`eq`'s inverse, `taken`, the wraps and `jalr_drop`, and writes the link or `lt` to `rd_selected` and
0 to `rd_selected_hi`. It panics, on rows the emulator cannot produce, if the trace's `rd` write or
`next_pc` is not what the instruction computes.
