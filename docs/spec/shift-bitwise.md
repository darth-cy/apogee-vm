# The `SHIFT_BITWISE` family

The circuit of the shifts `sll`, `slli`, `srl`, `srli`, `sra`, `srai` and the bitwise `and`,
`andi`, `or`, `ori`, `xor`, `xori`, one family, beside the memory frame ([memory.md](memory.md) §2).
A shift either way is one product with a looked-up power of two; AND is four byte lookups, and OR
and XOR are linear forms over it. The circuit is `constraints::shift_bitwise::artifact`
(`crates/constraints/src/shift_bitwise.rs`); `prover::family_fill` writes its witness.

## 1. What the circuit reads from the decoded table

The tuple is `pc next_pc rs1 rs2 rd imm extra_mask` ([program.md](program.md) §5), `next_pc` the
fall-through, `seq` below. `imm` is the shamt of `slli`, `srli` and `srai`, below 32 because the
decoder refuses `shamt[5]` on RV32; the sign-extended immediate, as a word, of `andi`, `ori` and
`xori`; and 0 on a register form. `extra_mask` is one-hot over
`constants::extra_mask::shift_bitwise`, the legal masks its twelve one-bit values
(`shift_bitwise::LEGAL_MASKS`):

```text
bit    0     1     2     3     4    5     6    7    8    9    10   11
kind   slli  xori  srli  srai  ori  andi  sll  xor  srl  sra  or   and
```

**The second operand** of all twelve is `src2 = rs2 + imm`: an immediate form has no `rs2` query,
so `rs2` reads 0, and a register form's `imm` is 0. One addend is always zero, so the sum needs no
wrap bit, and an immediate never enters the `rs2` column the memory argument ties. The circuit
commits the twelve bits `b_k`, and its flags are linear forms over them:

```text
left    b_slli + b_sll
right   b_srli + b_srai + b_srl + b_sra
arith   b_srai + b_sra
t1      b_or + b_ori + b_xor + b_xori
t2      b_and + b_andi − b_or − b_ori − 2·(b_xor + b_xori)
```

Only the two halves' sums, `f_shift` and `f_bitwise`, are columns: each selects lookups, and a
selector is a committed boolean ([lookup.md](lookup.md) §2).

## 2. Columns

The frame is `M[0..21]` and `W[0..7]`, over the queries `pc rs1 rs2 rd` at slots 0–3
([memory.md](memory.md) §2); its `W[6]`, `rd_selected` (`sel` below), holds the value the
instruction computes, which the x0 rule masks into the write. The circuit adds:

| column | name | value |
| --- | --- | --- |
| `W[7..13]` | `decoded_next_pc` … `decoded_mask` | the claimed decoded row after `pc` |
| `W[13..25]` | `kind_slli` … `kind_and` | the bits `b_k`, in §1's order |
| `W[25]`, `W[26]` | `f_shift`, `f_bitwise` | the two halves |
| `W[27]`, `W[28]` | `rs1_hi`, `rs1_sign` | `rs1 >> 16`, `rs1 >> 31` |
| `W[29]` | `src2_hi` | `src2 >> 16` |
| `W[30]` | `amount` | `src2 & 31` |
| `W[31]`, `W[32]` | `pow`, `copow` | `2^amount`, `2^(31 − amount)` on a shift row |
| `W[33]`, `W[34]` | `high`, `high_hi` | `src2 >> 5`, and its high halfword |
| `W[35]` | `se` | `arith·rs1_sign` |
| `W[36]`, `W[37]` | `shift_in`, `shift_prod` | both directions' multiplicand, and `shift_in·pow` |
| `W[38]`, `W[39]` | `ovf`, `ovf_hi` | a left shift's discarded high word, and its high halfword |
| `W[40]`, `W[41]` | `residue`, `residue_hi` | a right shift's remainder, and its high halfword |
| `W[42]`, `W[43]` | `scaled`, `scaled_hi` | `residue·2^(32 − amount)`, and its high halfword |
| `W[44..52]` | `byte_a<j>`, `byte_b<j>` | the bytes of `rs1`, then of `src2`, low first |
| `W[52..56]` | `byte_and<j>` | their bytewise AND |
| `W[56]` | `rd_hi` | `sel >> 16` |
| `W[57..61]` | `mult_timestamp` … `mult_decoder` | one multiplicity per channel, in channel order |
| `S[0..10]`, `V[range19]`, `V[range16]` | | as in [jump-branch-slt.md](jump-branch-slt.md) §2 |

21 `M`, 61 `W` and 10 `S` columns, 92 committed; 48 enforcing gates, the frame's 10 and §4's 38;
39 lookups: 8 `TIMESTAMP`, 24 `RANGE16`, 6 `GENERIC`, 1 `DECODER`, counts `artifact` asserts.

## 3. Tables, and the bound on every key

### 3.1 `ShiftPowers`

Row `s` of the packed table's top sub-table ([lookup.md](lookup.md) §9) is
`(SHIFT_BASE + s + 1, 2^s, 2^(31 − s))`, one for each of the 32 shift amounts and for none other,
so a key past its last row matches nothing. The second value is the copower a residue bound
multiplies by, `2^(32 − s)`, stored halved (`SHIFT_COPOWER_BITS = 31`): at `s = 0` it is `2^32`,
which the table's `u32` columns cannot hold, so the two gates that read it carry the factor 2
(§4.2, §4.3).

### 3.2 The AND rows

An AND row is `(AND_BASE + a + 1, b, a & b)` over bytes `a` and `b`, so a key inside their range
matches a row that makes `byte_b<j>` a byte and `byte_and<j>` its AND with `byte_a<j>`: those two
need no bound of their own.

### 3.3 Every key is bounded

The channel proves membership of the packed table, not of a sub-table ([lookup.md](lookup.md) §4),
so an out-of-range key lands on another sub-table's row. A bitwise row with `byte_a0 = 65,823` gates
to key 65,824, `ShiftPowers`' row `(65,824, 2^31, 1)`; with `rs1 = 65,823` and `rs2 = 2^31` every
gate holds, and `and` writes 1 where the answer is 0. So every key carries its own bound, as
`RANGE16` obligations under its lookup's selector:

| key | bound | obligations | selector |
| --- | --- | --- | --- |
| `rs1_hi + SIGN_BASE` | `rs1_hi < 2^16` | `rs1`'s 16+16 pair | `m_pc` |
| `amount + SHIFT_BASE` | `amount < 2^5` | `amount`; `2^11·amount` | `f_shift` |
| `byte_a<j> + AND_BASE` | `byte_a<j> < 2^8` | `byte_a<j>`; `2^8·byte_a<j>` | `f_bitwise` |

A bound below a halfword takes both obligations: the scaled one alone does not make the key an
integer ([lookup.md](lookup.md) §11), and the direct one alone admits every halfword,
`byte_a0 = 256` landing on `U16GetSign`'s row `(257, 0, 0)`.

### 3.4 The copower check

`artifact` runs `lookup::check_copowers` ([lookup.md](lookup.md) §11) over each column it bounds by
scaling, which must carry its direct bound under its scaled obligation's own selector: `residue`,
scaled by the looked-up copower (§4.3), under `m_pc`; `amount` under `f_shift`; each `byte_a<j>`
under `f_bitwise`.

## 4. Gates

Gate list 0 holds the frame's ten and these 38. `m_q`, `a_q`, `v_q` are query `q`'s mask, address
and read value, and a flag of §1 times `(…)` stands for each of its weighted bits times `(…)`, so
every term is of degree 2.

### 4.1 Presence and `next_pc`

| gate | polynomial |
| --- | --- |
| `kind_<k>_boolean` ×12, `decoded_mask_bits` | as in [jump-branch-slt.md](jump-branch-slt.md) §4 |
| `f_shift_rule`, `f_bitwise_rule` | `f − Σ` its half's six bits |
| `f_shift_boolean`, `f_bitwise_boolean` | `f − f²` |
| `rs1_mask_rule`, `rd_mask_rule` | `m_q − m_pc·Σ_k b_k` |
| `rs2_mask_rule` | `m_rs2 − m_pc·(b_sll + b_srl + b_sra + b_and + b_or + b_xor)` |
| `<q>_addr_rule` ×3, `<q>_value_masked` ×2 | as in [jump-branch-slt.md](jump-branch-slt.md) §4 |
| `next_pc_rule` | `next_pc − seq` |

No kind computes a pc: `next_pc` is the decoder-bound fall-through, with no wrap bit and no bound
of its own, and `HALT_PC` is beyond the family's reach ([memory.md](memory.md) §5).

### 4.2 The shift amount

```text
amount_split    rs2 + imm − 32·high − amount
copower_rule    pow·copow − 2^31·f_shift
```

`amount_split` is ungated. `copower_rule` says `pow·(2·copow) = 2^32` on a shift row, and
`pow·copow = 0` on a bitwise row.

### 4.3 The one product, both directions

```text
se_rule           se − arith·rs1_sign
rs1_sign_boolean  rs1_sign − rs1_sign²
se_boolean        se − se²
shift_in_rule     shift_in − left·v_rs1 − right·(sel − 2^32·se)
shift_prod_rule   shift_prod − shift_in·pow
shift_out_rule    left·(shift_prod − sel − 2^32·ovf)
                    + right·(shift_prod + residue − v_rs1 + 2^32·se)
scaled_rule       scaled − 2·residue·copow
```

`shift_prod_rule`, ungated, is the one multiplication by `pow`; `shift_in_rule` picks its
multiplicand, which keeps `shift_out_rule` at degree 2 where `left·(v_rs1·pow − …)` would be 3, and
`se` is committed for the same reason. A right shift is the floor division
`rs1 − 2^32·se = (sel − 2^32·se)·2^s + residue`, which covers `sra`: the arithmetic shift of a
negative word is the floor division of its signed value, and the result keeps the operand's sign.
`shift_in` and `shift_prod` are the only columns that are not words: the multiplicand is negative
where `se = 1`, and a left shift's product reaches `2^63`.

### 4.4 The bitwise half

```text
rs1_bytes         v_rs1 − Σ_j 2^(8j)·byte_a<j>
src2_bytes        rs2 + imm − Σ_j 2^(8j)·byte_b<j>
bitwise_out_rule  f_bitwise·sel − t1·(v_rs1 + rs2 + imm) − t2·Σ_j 2^(8j)·byte_and<j>
```

Per byte, OR is `a + b − (a & b)` and XOR is `a + b − 2·(a & b)`. Summed by weight through the two
decompositions, `sel` is `rs1 & src2` at `(t1, t2) = (0, 1)`, their OR at `(1, −1)` and their XOR
at `(1, −2)`, exactly, no carry crossing a byte: there is no OR or XOR table, and the AND
accumulator is a linear form, not a column. `sel` is gated by `f_bitwise` because `t1` and `t2` are
0 on a shift row, where a bare `sel` would force `rd = 0`. The decompositions are ungated: on a
shift row the bytes carry no lookup, and a decomposition always exists.

### 4.5 Lookups

After the frame's 8 `TIMESTAMP` obligations, in the channel order of
[jump-branch-slt.md](jump-branch-slt.md) §4.1:

```text
RANGE16   <x>_hi_range, <x>_lo_range     under m_pc, x = rs1 src2 high ovf residue scaled rd
          amount_range, amount_scaled    under f_shift      §3.3
          byte_a<j>_range, _scaled ×4    under f_bitwise    §3.3
GENERIC   rs1_get_sign   (rs1_hi + SIGN_BASE, rs1_sign, 0)                 under m_pc
          shift_powers   (amount + SHIFT_BASE, pow, copow)                 under f_shift
          and_byte_<j>   (byte_a<j> + AND_BASE, byte_b<j>, byte_and<j>)    under f_bitwise
DECODER   decode_row     under m_pc (lookup.md §10)
```

## 5. Why it is sound

On a **live row** the decoder lookup makes the claimed tuple the table's row at `pc`, so one kind
bit is 1 and one of `f_shift`, `f_bitwise` ([lookup.md](lookup.md) §10); the mask and address rules
make the queries the instruction's ([execution-trace.md](execution-trace.md) §4). `rs1`, `src2` and
`sel` are words by their pairs, `rs1_hi` is `rs1`'s true high halfword and `rs1_sign` its bit 31.
Every term of §4 that reads `sel` carries a shift bit or `f_bitwise`, so the inactive half never
constrains it.

- **The amount is the ISA's.** §3.3 bounds `amount` below 32 and `high`'s pair bounds `high` below
  `2^32`, so `amount_split` is an integer identity below `2^37`, `amount = src2 mod 32`, and the
  `ShiftPowers` row it keys gives `pow = 2^amount`. Without `high`'s pair, `sll` by `rs2 = 4` can
  shift by 8, at `high = −1/8`.
- **A left shift**: `shift_prod = rs1·2^s < 2^63`, and `sel + 2^32·ovf`, both words, is its unique
  split, so `sel = (rs1·2^s) mod 2^32`.
- **A right shift**: `se` is `rs1`'s bit 31 on `sra` and `srai` and 0 otherwise, so `se_rule` alone
  keeps an `srai` from carrying `srli`'s answer. Every term of the floor division is below `2^64` in
  magnitude, so `residue` is the integer `(rs1 − 2^32·se) − (sel − 2^32·se)·2^s`, and `scaled`'s
  pair puts it in `[0, 2^s)`: `sel − 2^32·se` is the floor of `(rs1 − 2^32·se)/2^s`. `residue`'s
  own pair, which `check_copowers` requires, bounds it without appeal to `sel`'s, the scaled pair
  alone saying nothing of a non-integer: `2^−28` passes it at `s = 3`.
- **A bitwise result**: each `byte_a<j>` is below 256, so its lookup matches an AND row (§3.2);
  with `rs1` and `src2` words, both decompositions are the unique byte splits and §4.4's identity
  holds.

`copower_rule` is implied by the bounded key and kept as the circuit's own reading of the table: a
`ShiftPowers` row generated wrong stops the honest prover rather than license a residue bound that
is not one. It also confines the key to `ShiftPowers` alone, no other row's two values having the
product `2^31`: an AND row's is at most `255·255`, every other row's 0.

On a **padding row**, `m_pc = 0`, every query mask is 0 and every obligation under `m_pc` vacuous.
`f_shift` and `f_bitwise` are free booleans there, so a padding row may look up `ShiftPowers` or the
AND rows, which consumes a multiplicity and changes nothing.
