# The `JUMP_BRANCH_SLT` family

The circuit of `slti`, `sltiu`, `slt`, `sltu`, the six branches, `jalr` and `jal`: what it adds
beside the memory frame every execution family carries ([memory.md](memory.md) §2), and the two
gadgets other families reuse (§3). One comparison settles signed and unsigned order for the
branches and the `slt` kinds alike. The circuit is `constraints::jump_branch_slt::artifact`
(`crates/constraints/src/jump_branch_slt.rs`); `prover::family_fill` writes its witness.

## 1. What the circuit reads from the decoded table

The tuple is `pc next_pc rs1 rs2 rd imm extra_mask` ([program.md](program.md) §5). `next_pc` is the
fall-through, `seq` below; `imm` is the two's-complement word of the value the instruction uses: the
sign-extended immediate of `slti` and `sltiu` (which `sltiu` compares unsigned), a branch's or
`jal`'s displacement, `jalr`'s offset. `extra_mask` is one-hot over
`constants::extra_mask::jump_branch_slt`:

```text
bit    0     1      2    3     4    5    6    7    8     9     10    11
kind   slti  sltiu  slt  sltu  beq  bne  blt  bge  bltu  bgeu  jalr  jal
```

The legal masks are these twelve one-bit values, `jump_branch_slt::LEGAL_MASKS`; `rd = x0` is the
table's `rd`, not a mask. The circuit commits the twelve bits `b_k`, and every signal it needs is a
linear form over them: the signed-comparison flag `sc = b_slti + b_slt + b_blt + b_bge`, the
compared immediate `(b_slti + b_sltiu)·imm`, so that a branch's displacement never reaches the
comparison, and the branch weights of `taken_rule` (§4).

## 2. Columns

The frame is `M[0..21]` and `W[0..7]`, over the queries `pc rs1 rs2 rd` at slots 0–3
([memory.md](memory.md) §2). Its `W[6]`, `rd_selected` (`sel` below), holds the value the
instruction computes, which the x0 rule masks into the write. The circuit adds:

| column | name | value |
| --- | --- | --- |
| `W[7..13]` | `decoded_next_pc` … `decoded_mask` | the claimed decoded row after `pc` |
| `W[13..25]` | `kind_slti` … `kind_jal` | the bits `b_k`, in §1's order |
| `W[25]` | `cmp_rhs` | the right operand, `rs2 + (b_slti + b_sltiu)·imm` |
| `W[26]`, `W[27]` | `rs1_hi`, `rs1_sign` | `rs1 >> 16`, `rs1 >> 31` |
| `W[28]`, `W[29]` | `cmp_rhs_hi`, `cmp_rhs_sign` | the same of `cmp_rhs` |
| `W[30]` | `lt` | `rs1 < cmp_rhs`, signed where `sc = 1` |
| `W[31]`, `W[32]` | `cmp_gap`, `cmp_gap_hi` | `(rs1 − cmp_rhs) mod 2^32`, and its high halfword |
| `W[33]`, `W[34]` | `eq`, `eq_inv` | `[rs1 = cmp_rhs]` on a live row; the difference's inverse |
| `W[35]` | `taken` | a taken branch |
| `W[36]` | `jalr_drop` | bit 0 of `rs1 + imm` on a `jalr` row |
| `W[37]` | `pc_wrap` | the carry out of whichever sum `next_pc` is |
| `W[38]`, `W[39]` | `next_pc_hi`, `rd_hi` | `next_pc >> 16`, `sel >> 16` |
| `W[40..44]` | `mult_timestamp` … `mult_decoder` | one multiplicity per channel, in channel order |
| `S[0..7]` | `table_pc` … `table_extra_mask` | the decoded table, which program identity binds |
| `S[7..10]` | `generic_key` … `generic_result` | the packed table ([lookup.md](lookup.md) §9) |
| `V[range19]`, `V[range16]` | | the `TIMESTAMP` and `RANGE16` tables |

21 `M`, 44 `W` and 10 `S` columns, 75 committed; 42 enforcing gates, the frame's 10 and §4's 32;
22 lookups: 8 `TIMESTAMP`, 11 `RANGE16`, 2 `GENERIC`, 1 `DECODER`, counts `artifact` asserts.

## 3. The gadgets

`constraints::gadgets` returns gates and lookups as data. `is_zero` also builds the frame's x0 rule
([memory.md](memory.md) §2) and `MUL_DIV`'s zero tests ([mul-div.md](mul-div.md)); the comparison
also orders `ATOMICS`' minimum and maximum ([memory-ops.md](memory-ops.md) §6).

### 3.1 `is_zero(x, inv, z, enable)`

```text
x·inv + z − enable = 0          x = Σ c_i·x_i, a linear form
z·x = 0
```

With `enable` boolean, which the caller establishes, these force `z = enable·[x = 0]`: at `x ≠ 0`
the second gives `z = 0` and the first `inv = enable/x`; at `x = 0` the first gives `z = enable`.
So `z` is boolean with no gate of its own, and `enable = 0` gives `z = 0`, which keeps the all-zero
row valid.

### 3.2 The comparison

`Comparison` names one comparison `lhs < rhs` by its columns, its lookups' selector, and the kind
bits `signed` whose sum is `sc`, which the caller holds to 0 or 1 on a selected row. `comparison`
returns, for `x` each of `lhs`, `rhs` and `gap`:

| name | kind | expression |
| --- | --- | --- |
| `<p>_order` | gate | `lhs − rhs − 2^32·sc·lhs_sign + 2^32·sc·rhs_sign + 2^32·lt − gap` |
| `<p>_lt_boolean` | gate | `lt − lt²` |
| `<p>_<x>_hi_range`, `<p>_<x>_lo_range` | `RANGE16` | `x_hi`; `x − 2^16·x_hi` |
| `<p>_lhs_get_sign`, `<p>_rhs_get_sign` | `GENERIC` | `(x_hi + SIGN_BASE, x_sign, 0)` |

The range pairs make `lhs`, `rhs` and `gap` words and each `x_hi` the true high halfword
([memory.md](memory.md) §7), which keeps each sign key inside `U16GetSign`'s range
([lookup.md](lookup.md) §4), so each sign is its operand's bit 31. Let
`D = lhs − rhs − 2^32·sc·(lhs_sign − rhs_sign)`: both operands read in two's complement where
`sc = 1`, so mixed signs are no case split, and `D ∈ (−2^32, 2^32)`. The gate says
`gap = D + 2^32·lt`, and only `lt = [D < 0]` puts `gap` in `[0, 2^32)`: at `D ≥ 0`, `lt = 1` puts it
at `2^32` or above; at `D < 0`, `lt = 0` makes it a negative field element. So the range check on
`gap` carries the order, and no comparison table exists; the honest `gap` is `(lhs − rhs) mod 2^32`
whatever `sc` is. Both gates are ungated, since a selector would make the order gate degree 3, and
every row satisfies them with the `gap` its own values give. `comparison_equation(c, word_bits)`
builds the order gate at any width to 32, and the row suite evaluates it at 6 bits over every
operand pair, signed and unsigned, finding exactly one `(lt, gap)`, the ISA's.

## 4. Gates

After the frame's ten in gate list 0, with `m_q`, `a_q`, `v_q` query `q`'s mask, address and read
value, and `pc`, `next_pc` the pc query's read and write:

| gate | polynomial |
| --- | --- |
| `kind_<k>_boolean` ×12 | `b_k − b_k²` |
| `decoded_mask_bits` | `Σ_k 2^k·b_k − decoded_mask` |
| `rs1_mask_rule` | `m_rs1 − m_pc·(Σ_k b_k − b_jal)` |
| `rs2_mask_rule` | `m_rs2 − m_pc·(b_slt + b_sltu + the six branch bits)` |
| `rd_mask_rule` | `m_rd − m_pc·(b_slti + b_sltiu + b_slt + b_sltu + b_jalr + b_jal)` |
| `<q>_addr_rule`, for `rs1`, `rs2`, `rd` | `m_q·(a_q − decoded_q)` |
| `<q>_value_masked`, for `rs1`, `rs2` | `v_q − m_q·v_q` |
| `cmp_rhs_rule` | `cmp_rhs − v_rs2 − (b_slti + b_sltiu)·imm` |
| `cmp_order`, `cmp_lt_boolean` | §3.2: `lhs = v_rs1`, `rhs = cmp_rhs`, `signed` the bits of `sc` |
| `eq_inverse`, `eq_at_nonzero` | §3.1: `x = v_rs1 − cmp_rhs`, `z = eq`, `enable = m_pc` |
| `taken_rule` | `taken − w_1 − w_eq·eq − w_lt·lt` |
| `taken_boolean`, `jalr_drop_boolean`, `pc_wrap_boolean` | `x − x²` |
| `next_pc_rule` | §5's equation |
| `rd_value_rule` | `sel − (b_jal + b_jalr)·seq − (b_slti + b_sltiu + b_slt + b_sltu)·lt` |

The branch weights are `w_1 = b_bne + b_bge + b_bgeu`, `w_eq = b_beq − b_bne` and
`w_lt = b_blt + b_bltu − b_bge − b_bgeu`. Every gate has degree at most 2 and is 0 on the all-zero
row, which `artifact` asserts.

### 4.1 Lookups

After the frame's 8 `TIMESTAMP` obligations, all under `m_pc`:

| lookup | channel | expression |
| --- | --- | --- |
| `cmp_<x>_hi_range`, `cmp_<x>_lo_range` ×3 | `RANGE16` | §3.2 over `v_rs1`, `cmp_rhs`, `cmp_gap` |
| `cmp_lhs_get_sign`, `cmp_rhs_get_sign` | `GENERIC` | §3.2 |
| `rd_hi_range`, `rd_lo_range` | `RANGE16` | `rd_hi`; `sel − 2^16·rd_hi` |
| `next_pc_hi_range`, `next_pc_lo_range` | `RANGE16` | `next_pc_hi`; `next_pc − 2^16·next_pc_hi` |
| `next_pc_even` | `RANGE16` | `2^−1·next_pc − 2^15·next_pc_hi` |
| `decode_row` | `DECODER` | `pc` and `W[7..13]` ([lookup.md](lookup.md) §10) |

The channels, in output order, are `TIMESTAMP` on `V[range19]`, `RANGE16` on `V[range16]`,
`GENERIC` on `S[7..10]` and `DECODER` on `S[0..7]`. `next_pc_even` is the low halfword `lo`
halved, `(lo + p)/2` and far above `2^16` when `lo` is odd.
Because it scales `next_pc`, the constructor runs `lookup::check_copowers`
([lookup.md](lookup.md) §11) over `(next_pc, m_pc)`.

## 5. Why it is sound

On a **live row**, `m_pc = 1`, the decoder lookup makes the claimed tuple the table's row at `pc`,
so `pc` is even, `seq` is below `2^24` and exactly one `b_k` is 1 ([lookup.md](lookup.md) §10). The
mask and address rules make the frame's queries the instruction's
([execution-trace.md](execution-trace.md) §4): `jal` reads nothing, and a branch has no `rd` query,
so nothing it computes is written. An absent operand reads 0, so `cmp_rhs` is `rs2` or the
immediate, never their sum, and the comparison's pairs make both operands words. So `lt` is the
ISA's order (§3.2), `eq` its equality (§3.1), and `taken` its branch decision: `eq` on `beq`,
`1 − eq` on `bne`, `lt` on `blt` and `bltu`, `1 − lt` on `bge` and `bgeu`, and 0 off the branches,
every term of `taken_rule` carrying a branch bit. `taken` is a committed bit because, inlined,
`taken·(pc + imm)` would be degree 3.

**`next_pc`** is held by one gate:

```text
next_pc + 2^32·pc_wrap = (1 − taken − b_jal − b_jalr)·seq
                       + (taken + b_jal)·(pc + imm)
                       + b_jalr·(v_rs1 + imm − jalr_drop)
```

At most one of `taken`, `b_jal`, `b_jalr` is 1, so one sum is selected, and one wrap bit outside the
selectors serves all three: `imm` is a two's-complement word, so every backward branch and jump
wraps, not only `jalr`. With `next_pc` an even word and `pc_wrap`, `jalr_drop` boolean:

- the default arm is `seq`, below `2^24`, so `pc_wrap = 0`;
- `pc + imm` and `v_rs1 + imm` are below `2^33`, so one wrap bit holds the carry, uniquely;
- on `jalr`, `v_rs1 + imm − jalr_drop − 2^32·pc_wrap` is a unique even word, `(rs1 + imm) mod 2^32`
  with bit 0 cleared; a false `jalr_drop` makes `next_pc` odd or negative.

A branch's or `jal`'s target is even unchecked, `pc` and `imm` both being even. Evenness is what
keeps the family off `HALT_PC = 1` ([memory.md](memory.md) §5): without `next_pc_even`, a `jalr`
whose `rs1 + imm ≡ 1` keeps bit 0 and writes `HALT_PC` with every other gate and lookup holding, and
a program that would crash by jumping to address 0 is proven to exit cleanly.

The link is `seq`, a table value and not a sum, so it has no wrap bit; the `rd` pair range-checks
it and `lt` like every register write, and the x0 rule masks both at `x0`. A target needs no check
of its own: at an address holding no instruction, the next row's decoder lookup fails whatever
family claims the row, no table holding a live row there ([lookup.md](lookup.md) §10).

On a **padding row**, `m_pc = 0`, the mask rules zero every query mask, `eq` is 0 and every lookup
is off, so the row reaches no memory event whatever its free bits hold.
