# The `BITWISE` family

The circuit of `and`, `andi`, `or`, `ori`, `xor` and `xori` over 64-bit registers, beside the memory
frame ([memory.md](memory.md) §2). Each operand is eight bytes, each byte pair's AND is one lookup,
and OR and XOR are linear forms over it. The circuit is `constraints::bitwise::artifact`
(`crates/constraints/src/bitwise.rs`, on `crates/constraints/src/family.rs`'s builder);
`prover::family_fill` writes its witness. Its shape is [circuits.md](circuits.md) §1's. The shifts
are `MUL_DIV`'s ([mul-div.md](mul-div.md)).

## 1. What the circuit reads from the decoded table

The tuple is `pc next_pc rs1 rs2 rd imm extra_mask` ([program.md](program.md) §5); `imm` is the
immediate's low word and `extra_mask`'s bit 31 its sign `neg`, so the 64-bit immediate is
`imm + 2^32·(2^32 − 1)·neg`. The kind bits, in `constants::extra_mask::bitwise` order:

```text
bit    0     1    2     3    4   5
kind   xori  ori  andi  xor  or  and
```

**The second operand** is `src2 = rs2 + imm`: an immediate form has no `rs2` query, so its `rs2`
reads 0, and a register form's `imm` is 0. One addend is always 0, so the sum needs no carry, and an
immediate never enters the column the memory argument ties. Two linear forms select the result:

```text
t1   b_or + b_ori + b_xor + b_xori
t2   b_and + b_andi − b_or − b_ori − 2·(b_xor + b_xori)
```

## 2. Columns

The frame's `pc rs1 rs2 rd`; `v1`, `v2` and `vh1`, `vh2` below are `rs1`'s and `rs2`'s read low and
high words, `sel` and `sel_hi` the frame's `rd_selected` and `rd_selected_hi`, which the x0 rule
masks into `rd`'s write. The family adds the builder's decoded row, kind bits and `imm_negative`,
and:

```text
byte_a0 … byte_a7       rs1's bytes, low first
byte_b0 … byte_b7       src2's bytes
byte_and0 … byte_and7   their ANDs
```

## 3. Gates and lookups

The frame's gates, the builder's — `decoded_mask_bits`, the kind bits' booleanity, and each query's
`<q>_mask_rule`, `<q>_addr_rule` and `<q>_value_masked` (both words) — and:

```text
next_pc_rule     next_pc − decoded_next_pc
rs1_lo_bytes     v1 − Σ_{j<4} 2^{8j}·byte_a_j
rs1_hi_bytes     vh1 − Σ_{j<4} 2^{8j}·byte_a_{j+4}
src2_lo_bytes    v2 + imm − Σ_{j<4} 2^{8j}·byte_b_j
src2_hi_bytes    vh2 + (2^32 − 1)·neg − Σ_{j<4} 2^{8j}·byte_b_{j+4}
out_lo           sel − t1·(v1 + v2 + imm) − t2·Σ_{j<4} 2^{8j}·byte_and_j
out_hi           sel_hi − t1·(vh1 + vh2 + (2^32 − 1)·neg) − t2·Σ_{j<4} 2^{8j}·byte_and_{j+4}
```

The lookups are the frame's `TIMESTAMP` gap chunks; eight `and_byte_<j>` on `GENERIC`,
`(AND, byte_a_j, byte_b_j, byte_and_j)` under `m_pc`; and `decode_row` on `DECODER`. No `RANGE16`
obligation: every value the row writes is a sum of bytes.

## 4. Why it is sound

On a live row the decoder makes one kind bit 1 ([lookup.md](lookup.md) §10). The `AND` tag bounds
`byte_a_j` and `byte_b_j` below `2^8` and makes `byte_and_j` their AND ([lookup.md](lookup.md) §9),
so each byte gate is the base-256 decomposition of a word: it holds over the integers, its right side
below `2^32`, and it determines the bytes. The words are then `rs1`'s and `src2`'s, `src2`'s high
word the immediate's sign extension on an immediate row.

Byte by byte `a + b − (a & b) = a | b` and `a + b − 2·(a & b) = a ^ b`, each a byte, so the sums
over the bytes are the result's words exactly: `t1 = 1, t2 = −1` writes OR, `t1 = 1, t2 = −2` XOR
and `t1 = 0, t2 = 1` AND. Each gate's terms stay below `2^35`, far below `p`, so the field identity
is the integer one, and `sel`, `sel_hi` are the instruction's two result words; no other value
satisfies the gates. `next_pc_rule` makes the row's pc write the decoded fall-through.

Every gate is zero on the all-zero padding row, whose lookups gate to the `ZeroEntry` and the
decoder's `MINUS_ONE` row. `crates/checker/tests/families.rs` holds the fill to the circuit over
`alu`'s and `opcodes`' traces, every kind among them: every written word one off is refused by the
row alone, and every gate and lookup refuses some single-cell edit.

## 5. The fill

`prover::family_fill(BITWISE)` splits `rs1` and `rs2 + imm` (the immediate sign-extended) into
bytes, writes their ANDs and the result's two words, and panics, on rows the emulator cannot
produce, if the trace's `rd` write or `next_pc` is not what the instruction computes.
