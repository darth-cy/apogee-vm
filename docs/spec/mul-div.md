# The `MUL_DIV` family

The M extension — `mul`, `mulh`, `mulhsu`, `mulhu`, `div`, `divu`, `rem`, `remu` — as one circuit
beside the memory frame every execution family carries ([memory.md](memory.md) §2). One product
identity serves the four multiplies and the division; a sign rule and a range-checked gap make the
division truncated, and one gate pins division by zero. `constraints::mul_div` builds it: 21 `M`,
54 `W` and 9 `S` columns, 54 enforcing gates, 27 lookups.

## 1. What the circuit reads from the decoded table

Every M instruction is R-type, so the decoded tuple has no `imm`: `pc next_pc rs1 rs2 rd
extra_mask`, six columns ([program.md](program.md) §5). `extra_mask` is one-hot over
`constants::extra_mask::mul_div`, bits 0–7 in the order above; the legal masks are its eight single
bits (`mul_div::LEGAL_MASKS`), which the table's domain enforces ([lookup.md](lookup.md) §10). The
circuit commits the bits `b_k` and reads every signal as a linear form over them:

| signal | form |
| --- | --- |
| reads `rs1` signed | `b_mul + b_mulh + b_mulhsu + b_div + b_rem` |
| reads `rs2` signed | `b_mul + b_mulh + b_div + b_rem` |
| a multiply, `Σ_mul` | `b_mul + b_mulh + b_mulhsu + b_mulhu` |
| a division, `f_div` | `b_div + b_divu + b_rem + b_remu`, a column: the is-zero gadgets' `enable` |

`mul` is read signed × signed: its low word is the same either way, which lets one product
identity serve all four multiplies. `mulhsu`'s asymmetry is the two lists, not a case split.

## 2. Columns

The frame is `pc rs1 rs2 rd`, `M[0..21]` and `W[0..7]` ([memory.md](memory.md) §2.1); below,
`m_q`, `a_q` and `v_q` are query `q`'s mask, address and read value, and `rs1`, `rs2` the operands'
read values. The family adds:

```text
W[7..12]   decoded_next_pc decoded_rs1 decoded_rs2 decoded_rd decoded_mask    (no imm)
W[12..20]  kind_mul … kind_remu
W[20]      f_div
W[21..27]  rs1_hi rs1_top rs2_hi rs2_top s1 s2          high halfwords, bit 31, §3
W[27..34]  mx my p_low p_low_hi p_high p_high_hi p_sign  the product
W[34..40]  q q_hi q_sign r r_hi r_sign                   quotient and remainder
W[40..45]  r_inv rz d1 d_inv dz                          is_zero(r), f_div·s1, is_zero(rs2)
W[45..50]  abs_r abs_d gap gap_hi rd_hi
W[50..54]  mult_timestamp mult_range16 mult_generic mult_decoder
S[0..6]    the decoded table, bound by identity
S[6..9]    the packed generic table (lookup.md §9)
V          range19 range16
```

The fill keeps `mx`, `my` (signed) and `r_inv`, `d_inv` (inverses) in `Fr`, every other column in
`u32`.

## 3. The sign adjustments

```text
rs1_adj = rs1 − 2^32·s1      s1 = (b_mul + b_mulh + b_mulhsu + b_div + b_rem)·rs1_top
rs2_adj = rs2 − 2^32·s2      s2 = (b_mul + b_mulh + b_div + b_rem)·rs2_top
q_adj   = q − 2^32·q_sign    r_adj = r − 2^32·r_sign
```

`rs1_top` is the `U16GetSign` lookup of `rs1_hi`, which `rs1`'s 16+16 pair makes its true high
halfword, so the key lies in that sub-table's range and the answer is bit 31
([lookup.md](lookup.md) §4); `rs2_top` likewise. An unsigned position forces its adjustment to 0
whatever the top bit, which keeps the selection degree 2. `q_sign` and `r_sign` are not sign
lookups (§5.3). `f_div`, `rs1_top`, `rs2_top`, `s1`, `s2`, `p_sign`, `q_sign` and `r_sign` carry
booleanity gates; `rz` and `dz` are boolean by the is-zero gadget
([jump-branch-slt.md](jump-branch-slt.md) §3), `d1` as a product of booleans.

## 4. Gates

The frame's ten enforcing gates ([memory.md](memory.md) §2.4) and the family's 44, all in gate
list 0, each formula `= 0`. The plumbing:

```text
kind_<k>_boolean          b_k − b_k²                       eight
decoded_mask_bits         Σ_k 2^k·b_k − decoded_mask
<q>_mask_rule             m_q − m_pc·Σ_k b_k               rs1, rs2, rd: every kind uses all three
<q>_addr_rule             m_q·(a_q − decoded_q)            rs1, rs2, rd
<q>_value_masked          v_q − m_q·v_q                    rs1, rs2
next_pc_rule              next_pc − decoded_next_pc        the fall-through (memory.md §5)
```

The arithmetic, `mul_div::arithmetic_gates(32)`, written with §3's abbreviations:

```text
f_div_rule, s1_rule, s2_rule   §1's and §3's forms, and eight booleanity gates (§3)
mx_rule                mx − Σ_mul b·rs1_adj − f_div·rs2_adj
my_rule                my − Σ_mul b·rs2_adj − f_div·q_adj
product_rule           mx·my − p_low − 2^32·p_high + 2^64·p_sign
division_rule          f_div·(p_low + 2^32·p_high − 2^64·p_sign + r_adj − rs1_adj)
rz_inverse             r·r_inv + rz − f_div          rz_at_nonzero   rz·r
dz_inverse             rs2·d_inv + dz − f_div        dz_at_nonzero   dz·rs2
d1_rule                d1 − f_div·s1
r_sign_rule            r_sign − d1 + d1·rz           so r_sign = f_div·s1·(1 − [r = 0])
abs_r_rule             abs_r − r − 2^32·r_sign + 2·r·r_sign       abs_r = |r_adj|
abs_d_rule             abs_d − rs2 − 2^32·s2 + 2·rs2·s2           abs_d = |rs2_adj|
gap_rule               gap − f_div·(abs_d − abs_r − 1) − 2^32·dz
zero_divisor_quotient  dz·(q − (2^32 − 1))
rd_value_rule          rd_selected − b_mul·p_low − (b_mulh + b_mulhsu + b_mulhu)·p_high
                         − (b_div + b_divu)·q − (b_rem + b_remu)·r
```

The lookups: the frame's eight `TIMESTAMP` gap chunks, each under its query's mask; and under
`m_pc`, 16+16 `RANGE16` pairs on `rs1`, `rs2`, `p_low`, `p_high`, `q`, `r`, `gap` and `rd_selected`,
`rs1_get_sign`, `(rs1_hi + SIGN_BASE, rs1_top, 0)` on `GENERIC`, and `rs2_get_sign`, and
`decode_row` on `DECODER`.

The width is a parameter of `arithmetic_gates` so the encoding can be checked whole:
`crates/checker/tests/mul_div.rs` evaluates `arithmetic_gates(4)` through `gkr::eval_gate` over
every `(dividend, divisor)` pair of a 4-bit word and each division kind, and exactly one `(q, r)`
survives, RV32M's.

## 5. Why it is sound

On a live row the decoder lookup makes exactly one kind bit 1 ([lookup.md](lookup.md) §10), and
`rs1`, `rs2` are words whose `_top` is bit 31, so `rs1_adj`, `rs2_adj ∈ [−2^31, 2^32)` are the
operands as the kind reads them.

### 5.1 The product

On a multiply row `mx·my = rs1_adj·rs2_adj`; on a division row it is `rs2_adj·q_adj`, `q`'s pair
and `q_sign`'s booleanity putting `q_adj` in `[−2^32, 2^32)`. Either way `|mx·my| < 2^64`, and two
words and a boolean cover `[−2^64, 2^64)` once, so `product_rule` holds over the integers with one
solution: `p_low`, `p_high` are the words of the 64-bit two's-complement product, RV32M's for each
multiply. `product_rule` is ungated and the circuit's only product of two row values, which is what
lets both readings share it at degree 2.

### 5.2 The division

With `rs2_adj ≠ 0`, `division_rule` is `rs2_adj·q_adj + r_adj = rs1_adj` over the integers.
Truncated division is its one solution with `|r_adj| < |rs2_adj|` and `r_adj` zero or of the
dividend's sign, and two gates state exactly that:

- **The sign.** `r_sign = f_div·s1·(1 − [r = 0])` makes `r_adj` the word `r` on an unsigned row or
  a non-negative dividend, and `r − 2^32 < 0` on a negative one unless `r = 0`. It is what separates
  truncated division from floored: without it `DIV(−7, 2)` admits `q = −4, r = 1` as readily as
  `q = −3, r = −1`. As a definition, through `d1`, it is degree 2.
- **The magnitude.** `gap = abs_d − abs_r − 1` is range-checked, and neither magnitude reaches
  `2^32`: `abs_d ≤ 2^31` where `s2 = 1`, `abs_r ≤ 2^32 − 1` where `r_sign = 1`, which needs
  `r ≠ 0`, and each is a word elsewhere. So the difference lies in `[−2^32, 2^32)`, in range exactly
  when `|r_adj| < |rs2_adj|`.
  The comparison gadget would repeat bounds that hold and has no place for the zero divisor's term.

So `q_adj` and `r_adj` are RV32M's, and `q_sign` is pinned only by `q`'s range: one value puts
`q_adj + 2^32·q_sign` in `[0, 2^32)`.

**A zero divisor** makes `dz = 1` and `rs2_adj = 0`: the identity leaves `r_adj = rs1_adj`, so `r`
is the dividend's word; `zero_divisor_quotient`, the one pin, makes `q` all ones; the `2^32·dz` term
lifts `gap` to `2^32 − 1 − abs_r`, so the divisor imposes no bound. `q_sign` is free and harmless:
`mx = 0`, and `rd` reads the word `q`.

**The identity is gated.** On a multiply row `r_sign = 0` and `r` is a word, so an ungated identity
would demand `rs1_adj − rs1_adj·rs2_adj ∈ [0, 2^32)`, false for nearly every multiply: `7 × 3`, a
negative `rs1` times `x0`.

### 5.3 The signed overflow, and why `q_sign` is free

`DIV(−2^31, −1)` needs no pin: `|r_adj| < 1` forces `r = 0`, the identity `q_adj = 2^31`, and `q`'s
range `q_sign = 0`, `q = 0x80000000`, RV32M's answer; `REM` gives 0. This row is why `q_sign` is a
free boolean: tied to bit 31 of `q`, as `s1` and `s2` are to their operands', it would force
`q_adj = −2^31` and make the row unprovable. `r_sign` likewise follows the dividend's sign, not
the remainder's word.

`rd_selected`'s pair is implied by its four sources' and kept, every family bounding what it writes
to `rd` ([memory-ops.md](memory-ops.md) §5). Every gate is zero on the all-zero padding row, which
`mul_div::artifact` asserts with each channel's obligation count.

### 5.4 The fill

`prover::family_fill(MUL_DIV)` (`crates/prover/src/fill.rs`) computes the witness with Rust's
integers: the product in `i128`, the division by `wrapping_div` and `wrapping_rem`, which give
RV32M's overflow answer, with the zero divisor an arm of its own, and `q_sign` from the sign of
`q_adj`. It writes the computed value to `rd_selected`, which the frame's x0 rule masks, and panics,
on rows the emulator cannot produce, if the identity does not divide, a product exceeds two words,
or the trace's `rd` write or `next_pc` is not what the instruction computes.
