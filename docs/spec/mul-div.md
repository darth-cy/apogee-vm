# The `MUL_DIV` family

The M extension and its W forms — `mul mulh mulhsu mulhu div divu rem remu mulw divw divuw remw
remuw` — and every shift — `slli srli srai slliw srliw sraiw sll srl sra sllw srlw sraw` — as one
circuit beside the memory frame ([memory.md](memory.md) §2). Each row proves one identity
`q·B + r ≡ Z (mod 2^128)` over 64-bit two's-complement words in 16-bit limbs: a multiply is `q = A`,
`r = 0` and `Z` the product; a division is `Z = A` with `q`, `r` its quotient and remainder, a sign
rule and a range-checked bound making them the ISA's. A left shift multiplies, a right shift
floor-divides, by a looked-up `2^s`. `constraints::mul_div::artifact` builds it on
`crates/constraints/src/family.rs`'s builder; its shape is [circuits.md](circuits.md) §1's.

## 1. What the circuit reads from the decoded table

The tuple is `pc next_pc rs1 rs2 rd imm extra_mask` ([program.md](program.md) §5): `imm` is a shift
immediate's amount and 0 elsewhere, `next_pc` the fall-through. The 25 kind bits are in
`constants::extra_mask::mul_div` order, the list above. The circuit reads them through sums over
these lists (`mul_div.rs`):

| list | kinds |
| --- | --- |
| `DIVIDE` (`f_div`) | the eight divisions and remainders, and every right shift |
| `WORD` | the eleven W forms, which write their low word sign-extended |
| `SHIFT_64`, `SHIFT_W` (`f_shift`) | the 64-bit and the 32-bit shifts |
| `SIGNED_A_64`, `SIGNED_A_W` | `A` read signed: `mulh mulhsu div rem srai sra`; `divw remw sraiw sraw` |
| `SIGNED_B_64`, `SIGNED_B_W` | `B` read signed: `mulh div rem`; `divw remw` |
| `RS2_64` | `B` is all of `rs2`: the eight 64-bit M kinds |
| `TRUNCATED` | a nonzero remainder takes the dividend's sign: `div rem divw remw` |
| `UNSIGNED_Q` | the quotient is not negative: `divu remu divuw remuw srli srl srliw srlw` |
| `FROM_Z0`, `FROM_Z2`, `FROM_Q`, `FROM_R` | `rd` is `Z`'s low or high half, `q` or `r` |

## 2. Columns

The frame's `pc rs1 rs2 rd`: `v1`, `v2`, `vh1`, `vh2` are the operands' low and high words, `sel`,
`sel_hi` the frame's `rd_selected`, `rd_selected_hi`. The family adds the builder's decoded row and
kind bits, and, each `word` a high halfword `<name>_h16` beside it and each signed word also a sign:

```text
f_div f_shift                       the two list sums, committed bits
rs1_lo rs1_hi (signed words)        rs1's words' halfwords and bit 31s: s1l, s1h
a_hi a_sign                         A's high word and sign
amount_high (word) amount_w amount  rs2 + imm = 64·amount_high + 32·amount_w + amount
pow_lo pow_hi                       2^amount as two words, looked up
b_lo b_hi (signed words) b_sign     B's words, their bit 31s, and B's sign
q_lo q_hi (words) q_sign            q
r_lo r_hi (words) r_sign            r
z0 z1 z2 z3 (words)                 Z
carry0 … carry3                     the chunk carries
r_inv r_is_zero                     is_zero(r), enabled by f_div
dividend_signed                     TRUNCATED·a_sign
b_inv b_is_zero                     is_zero(B), enabled by f_div
bound_lo bound_hi (words)           the bound G (§3.3)
bound_carry                         its carry
rd_lo_h16 rd_sign                   rd's low word's high halfword, and its bit 31
```

## 3. Gates

The frame's, the builder's (`decoded_mask_bits`, booleanity, each query's mask, address and
value-mask rules: `rs2` is absent on a shift immediate), and the family's, by group. `T = 2^32`,
`ones = T − 1`; `any(L)` is the list's bit sum.

### 3.1 The operands

```text
next_pc_rule     next_pc − seq
f_div_rule       f_div − any(DIVIDE)                f_shift_rule   f_shift − any(SHIFT_64 + SHIFT_W)
a_hi_rule        a_hi − any(¬WORD)·vh1 − any(SIGNED_A_W)·s1l·ones
a_sign_rule      a_sign − any(SIGNED_A_64)·s1h − any(SIGNED_A_W)·s1l
amount_split     v2 + imm − 64·amount_high − 32·amount_w − amount
amount_w_rule    any(SHIFT_64)·amount_w
b_lo_rule        b_lo − (1 − f_shift)·v2 − f_shift·pow_lo
b_hi_rule        b_hi − any(RS2_64)·vh2 − any(SIGNED_B_W)·s(b_lo)·ones − f_shift·pow_hi
b_sign_rule      b_sign − any(SIGNED_B_64)·s(b_hi) − any(SIGNED_B_W)·s(b_lo)
```

`A` is `rs1`'s low word with `a_hi`, `B` is `b_lo` with `b_hi`; a W form's operands are their low
words extended by sign or zero. `pow` is `GENERIC`'s `(POW or POW_W, amount, pow_lo, pow_hi)` under
`f_shift`, its tag `2·any(SHIFT_64) + 3·any(SHIFT_W)` ([lookup.md](lookup.md) §9).

### 3.2 The core

```text
q_lo_is_a q_hi_is_a q_sign_is_a   (live − f_div)·(q − A), word by word and the sign
r_zero_on_multiply                (live − f_div)·(r_lo + r_hi)
q_sign_unsigned                   any(UNSIGNED_Q)·q_sign
chunk0   s0 + 2^16·s1 + r_lo − Z0 − T·carry0
chunk1   s2 + 2^16·s3 + r_hi + carry0 − Z1 − T·carry1
chunk2   s4 + 2^16·s5 + ones·r_sign − q_sign·b_lo − b_sign·q_lo + carry1 − Z2 − T·carry2
chunk3   s6 + ones·r_sign − q_sign·b_hi − b_sign·q_hi + carry2 − Z3 − T·carry3
```

`s_m = Σ_{i+j=m} q_i·b_j` over the 16-bit limbs `q_0..q_3` and `b_0..b_3`, each limb a word's low
halfword `w − 2^16·w_h16` or its `_h16`. `Zj` is `zj` on a multiply row and `A` sign-extended to 128
bits on a division row (`v1`, `a_hi`, then `a_sign·ones` twice): the gate reads `zj − f_div·zj +
f_div·Aj`. `carry0`, `carry1` are 19-bit and `carry2 + 3`, `carry3 + 3` 19-bit on `TIMESTAMP`'s
table, which admits the corrections' negative carries.

### 3.3 The division

```text
r_is_zero_inverse r_is_zero_at_nonzero    is_zero(r_lo + r_hi, r_inv, r_is_zero, f_div)
dividend_signed_rule   dividend_signed − any(TRUNCATED)·a_sign
r_sign_rule            r_sign − dividend_signed·(1 − r_is_zero)
b_is_zero_inverse b_is_zero_at_nonzero    is_zero(b_lo + b_hi, b_inv, b_is_zero, f_div)
zero_divisor_q_lo      b_is_zero·(q_lo − ones)          zero_divisor_q_hi   b_is_zero·(q_hi − ones)
bound_lo_rule   b_lo − 2·b_sign·b_lo − r_lo + 2·r_sign·r_lo − f_div − bound_lo − T·bound_carry
bound_hi_rule   b_hi − 2·b_sign·b_hi − r_hi + 2·r_sign·r_hi + bound_carry
                  + T·(b_sign − r_sign + b_is_zero) − bound_hi
```

`bound_carry + 3` is 19-bit. Together the two rules say `|B_s| − |r_s| − f_div + 2^64·b_is_zero =
G`, `G = bound_lo + T·bound_hi ∈ [0, 2^64)`.

### 3.4 `rd`

```text
rd_lo_rule       sel − any(FROM_Z0)·z0 − any(FROM_Z2)·z2 − any(FROM_Q)·q_lo − any(FROM_R)·r_lo
rd_lo_h16_rule   rd_lo_h16 − the same selection of the halfwords
rd_hi_rule       sel_hi − z1 (64-bit FROM_Z0) − z3 (FROM_Z2) − q_hi (64-bit FROM_Q)
                   − r_hi (64-bit FROM_R) − any(WORD)·rd_sign·ones
```

`rd_get_sign` is `(SIGN, rd_lo_h16, rd_sign)` under `m_pc`.

## 4. Lookups

The frame's `TIMESTAMP` gaps; the carries' 19-bit obligations; every word's and signed word's
`RANGE16` obligations; `GENERIC`'s sign lookups, `pow` and `rd_get_sign`; and `decode_row`.

## 5. Why it is sound

On a live row the decoder makes one kind bit 1 ([lookup.md](lookup.md) §10). Every committed word
is below `2^32` — a word by its pair, a signed word by its low range and its `SIGN` lookup, which
also makes its sign its bit 31 — and every limb below `2^16`.

### 5.1 Every identity is exact over the integers

`s_m` is a sum of at most four limb products, below `2^34`; `2^16·s_{m+1}` below `2^50`; the carries
lie in `[−3, 2^19)`, so `T·carry` below `2^51` in magnitude; every other term is a word. Each chunk's
terms total below `2^52`, the bound rules', `amount_split`'s and the operand rules' below `2^40`,
all far below `p = 2^64 − 59`, so each gate's field identity is its integer one. Summing the chunks
with weights `T^j` gives

```text
q_s·B_s + r_s = Z_s + 2^128·carry3      q_s = q − 2^64·q_sign,  B_s = B − 2^64·b_sign,
                                        r_s = r − 2^64·r_sign
```

with `Z_s` the 128-bit two's-complement value of `Z`: the corrections are exactly `−2^64·(q_sign·B
+ b_sign·q)` and `r_s`'s, the `2^128·q_sign·b_sign` term vanishing mod `2^128`. So the row proves
`q_s·B_s + r_s ≡ Z (mod 2^128)`.

### 5.2 Multiplies and left shifts

On a multiply row `q = A` and `r = 0` (`r_lo + r_hi = 0` with both words non-negative), so `Z` is
`A_s·B_s mod 2^128` in four words: one solution. `|A_s·B_s| < 2^128` for every pairing of signs, so
that is the full product: `mul` and `mulw` take `z0` (and `z1`), `mulh`, `mulhsu`, `mulhu` `z2` and
`z3`. A left shift is the product with `B = 2^s`: `(A << s) mod 2^64` in `z0`, `z1`.

### 5.3 Divisions and right shifts

On a division row `Z = A_s`. With `B ≠ 0` the operands keep `|q_s·B_s + r_s − A_s| < 2^128` — an
unsigned quotient is not negative (`q_sign_unsigned`), so its product is below `(2^64 − 1)^2`, and a
signed or shifted `B` is at most `2^63` in magnitude — so the congruence is `q_s·B_s + r_s = A_s` over
ℤ. The bound makes `|r_s| < |B_s|`, `G` being a word pair exactly when `|B_s| − |r_s| − 1 ≥ 0`; the
sign rule makes `r_s` zero or of the dividend's sign on a truncated kind, and non-negative on every
other. Those are the two conditions that single out the ISA's quotient: truncated division for
`div`, `rem`, `divw`, `remw`; floor division by a positive `B` for the unsigned kinds and the right
shifts, which is `srl`'s logical and `sra`'s arithmetic shift, `A` read signed for `sra` alone.

**A zero divisor** gives `b_is_zero = 1`: `q` is all ones, the identity leaves `r_s = A_s`, and
`2^64·b_is_zero` lifts `G` so the bound imposes nothing; `q_sign` is free there and multiplies
`B = 0`. **The signed overflow** `div(−2^63, −1)` needs no pin: `|r_s| < 1` forces `r = 0` and the
identity `q_s = 2^63`, which only `q_sign = 0`, `q = 2^63` represent — the ISA's answer, as `divw`'s
low-word one is. A signed kind's `q_sign` is therefore free, pinned only by the identity; tied to
`q`'s bit 63 it would make that row unprovable.

### 5.4 The shift amount and the W forms

`amount_split` decomposes `rs2`'s low word plus the immediate, below `2^33`: `pow`'s tag bounds
`amount` below 64 (`POW`) or 32 (`POW_W`), `amount_w_rule` zeroes `amount_w` on a 64-bit shift, and
`amount_high` is a word, so the decomposition is unique and `amount` is `(rs2 + imm) mod 64`, or mod
32 for a W shift. A W form's operands are its low words extended as the kind reads them, and
`rd_hi_rule` writes the low result word's sign extension, `rd_sign` being its bit 31.

Every gate is zero on the all-zero padding row. `crates/checker/tests/families.rs` holds the fill
to the circuit over `alu`'s, `opcodes`' and `cpp-primes`' traces, all 25 kinds among them: every
written word one off is refused by the row alone, every gate and lookup refuses some single-cell
edit, and `a_remainder_past_its_divisor_is_refused_by_the_bound_alone` forges a quotient one short
with the remainder grown by the divisor, every chunk identity holding, which the bound's range
obligations refuse and nothing else does.

## 6. The fill

`prover::family_fill(MUL_DIV)` (`crates/prover/src/fill.rs`) computes `A`, `B` and the power, then
`q` and `r` in `i128`: the product for a multiply-like row, Rust's truncating or flooring division
for a division row, the zero divisor an arm of its own. It writes the limbs' chunk carries exactly,
asserting each chunk divides, the bound and its carry, and the computed `rd` even where `rd = x0`,
and panics, on rows the emulator cannot produce, if the trace's `rd` write or `next_pc` is not what
the instruction computes.
