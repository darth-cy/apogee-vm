# The `ADD_SUB_LUI_AUIPC` family

`add`, `sub`, `addi`, `lui`, `auipc`, their 32-bit forms `addw`, `subw`, `addiw`, and `ecall`,
`ebreak` and `fence`, compressed forms included, are family 0, one executed instruction a row;
`constraints::add_sub::artifact` is its circuit, on `crates/constraints/src/family.rs`'s builder.
Every `ecall` is a row of it, so the circuit also proves the exit and a delegation's request. This
page specifies what it adds beside the memory frame ([memory.md](memory.md) §2); its shape is
[circuits.md](circuits.md) §1's.

## 1. Columns

The decoded tuple is `pc next_pc rs1 rs2 rd imm extra_mask` ([program.md](program.md) §5). The kinds,
in bit order (`constants::extra_mask::add_sub_lui_auipc`), are `system addi auipc add sub lui addiw
addw subw`. `ecall`, `ebreak` and `fence` share the system kind, with `imm` 0, 1 and 2
(`constants::extra_mask::system_code`); elsewhere `imm` is the low word of what the instruction adds
— the sign-extended immediate, `lui`'s and `auipc`'s shifted left by 12, 0 for a register form — and
`extra_mask`'s bit 31 its sign `neg`, the immediate's high word being `(2^32 − 1)·neg`.

The frame is `pc rs1 rs2 rd`. Below, `v1`, `v2`, `v_rd` and `vh1`, `vh2`, `vh_rd` are the register
queries' read low and high words, `pc` and `next_pc` the pc query's read and write, `seq` the decoded
fall-through, and `sel`, `sel_hi` the frame's `rd_selected` and `rd_selected_hi`, which the x0 rule
writes to a nonzero `rd`. The family adds the builder's decoded row, kind bits `b_k` and
`imm_negative`, and:

```text
is_exit is_fence         the system kind, split by its code, with delegates
delegates (M)            a delegation request: the mask of its anchor tuple
c0 c1                    the low word's carry or borrow, and the high word's
rd_lo_h16 rd_lo_sign     sel's high halfword and its bit 15, sel's bit 31
rd_hi_h16                sel_hi's high halfword
pc_wrap next_pc_h16      next_pc's wrap and high halfword
```

The fill (`prover::family_fill`, `crates/prover/src/fill.rs`) writes `sel` as the computed value
even where `rd = x0`.

## 2. Gates

The frame's gates, the builder's (`decoded_mask_bits`, booleanity of every bit, each query's mask,
address and value-mask rules), and, each held to 0, with `adds = b_add + b_addi + b_auipc + b_addw +
b_addiw`, `adds64 = b_add + b_addi + b_auipc`, `W = b_addw + b_addiw + b_subw` and 93 `EXIT`:

```text
delegates_live     delegates − delegates·m_pc
system_split       is_ecall + is_fence − b_system          is_ecall = is_exit + delegates
ecall_code         is_ecall·imm
fence_code         is_fence·(imm − 2)
ecall_is_exit      is_exit·(v1 − 93)
ecall_is_exit_hi   is_exit·vh1
delegation_number_hi   delegates·vh1                      delegation_base_hi   delegates·vh2
rs1_mask_rule      m_rs1 − m_pc·(adds − b_auipc + b_sub + b_subw + is_ecall)
rs2_mask_rule      m_rs2 − m_pc·(b_add + b_sub + b_addw + b_subw + is_ecall)
rd_mask_rule       m_rd − m_pc·(adds + b_sub + b_lui + b_subw + is_exit)
<q>_addr_rule      m_q·(a_q − decoded_q − c_q)    c_rs1 = 17·is_ecall, c_rs2 = 10·is_ecall, c_rd = 10·is_exit
add_lo             adds·(v1 + v2 + imm − sel − 2^32·c0) + b_auipc·pc
sub_lo             (b_sub + b_subw)·(v1 − v2 − sel + 2^32·c0)
lui_lo             b_lui·(imm − sel)
add_hi             adds64·(vh1 + vh2 + c0 + (2^32 − 1)·neg − sel_hi − 2^32·c1)
sub_hi             b_sub·(vh1 − vh2 − c0 − sel_hi + 2^32·c1)
lui_hi             b_lui·((2^32 − 1)·neg − sel_hi)
w_extend           W·(sel_hi − (2^32 − 1)·rd_lo_sign)
exit_status        is_exit·(v_rd − sel)
exit_status_hi     is_exit·(vh_rd − sel_hi)
next_pc_rule       next_pc + 2^32·pc_wrap − (1 − is_exit)·seq − is_exit·HALT_PC
```

and `delegates` held boolean. A request's anchor `T(DELEGATION, v2, cycle, v1)` under `delegates`
is folded into `rd`'s write leaf, `rd` being absent on that row
([precompiles.md](precompiles.md) §2):

```text
write_rd           1 + m_rd·(T(REG, a_rd, 4·cycle + 3, w_rd, w_rd_hi) − 1)
                     + delegates·(T(DELEGATION, v2, cycle, v1) − 1)
```

## 3. Lookups

The frame's `TIMESTAMP` gaps, two a query under its mask, and under `m_pc`: `rd_lo_lo_range`,
`rd_hi_hi_range`, `rd_hi_lo_range`, `next_pc_hi_range` and `next_pc_lo_range` on `RANGE16`;
`rd_lo_get_sign`, `(SIGN, rd_lo_h16, rd_lo_sign)` on `GENERIC`; and `decode_row` on `DECODER`.

## 4. Why it is sound

On a live row `decode_row` makes the claimed row the table's at `pc`, so exactly one `b_k` is 1
([lookup.md](lookup.md) §10). The mask rules make each query present exactly where the row's kind
makes it ([execution-trace.md](execution-trace.md) §4, §6); the address rules make a register query
the decoded register or, on an `ecall` row, whose decoded registers are 0, `a7` and `a0`. The value
masks make an absent operand read 0 in both words, which lets one gate serve five sums: `auipc`'s
operands are `pc` and `imm`, an immediate form's `v2` is 0, a register form's `imm` the table's 0.

Read words are words ([memory-ops.md](memory-ops.md)); `sel` is a word by its low range and its
`SIGN` lookup, which bounds `rd_lo_h16` below `2^16` and makes `rd_lo_sign` its bit 15, `sel`'s bit
31; `sel_hi` is a word by its range pair; `c0`, `c1` are boolean. Every arithmetic gate's terms are
below `2^35`, so each is an identity over ℤ with one solution: the low word of the sum or difference
mod `2^32` and its carry or borrow, then the high word with the carry in and the immediate's sign
extension, and its own carry, discarded — the 64-bit result. A W kind takes the low word and
`w_extend` sets the high word to its sign extension; its `c1` is free and nothing reads it. `lui`
writes the shifted immediate sign-extended. Without the range checks a sum at or above `2^32` would
satisfy a gate with a carry of 0 and reach a register.

`next_pc` is a word by its range pair and is `seq` — the table's fall-through, so a compressed
instruction advances by 2 ([program.md](program.md) §5) — or `HALT_PC` on the exit row, less
`2^32·pc_wrap`. Both are below `2^32`, so `pc_wrap = 0` on every live row.

On a system row `system_split` sets exactly one of `is_exit`, `delegates` and `is_fence`, and the
code gates make an ecall or a fence the one `imm` names; `ebreak`'s code 1 satisfies neither, so an
`ebreak` row is unprovable. A `fence` row makes no query but the pc's and falls through. An exit's
`a7` is 93 in both words. The exit row writes back the `a0` it read, both words, so `x10`'s final
low word is the status the statement carries ([proof.md](proof.md) §6, step 10b), and writes
`HALT_PC`, after which no row runs ([memory.md](memory.md) §5).

A request reads `a7` and `a0`, each a word, writes no register and falls through. Its anchor names
its number, base and cycle, and balances only against the frame row of the family that number
registers ([precompiles.md](precompiles.md) §2), so a request of an unregistered number, or of 93,
has no proof; `delegates_live` keeps a padding row from writing one. The fold costs no leaf:
`m_rd` and `delegates` are exclusive, `rd_mask_rule` writing no `rd` where `is_exit` is 0.

A row with `m_pc = 0` is bound to no table row and its kind bits are free; the arithmetic gates are
gated by those bits alone. That is harmless: the mask rules zero the row's other masks and every
lookup is off, so it adds no memory tuple. `crates/checker/tests/families.rs` holds the fill to the
circuit over `addsub`'s and `cpp-primes`' traces, every kind among them: every written word one off
is refused by the row alone, and every gate and lookup refuses some single-cell edit.

## 5. Limits

- An `ecall` whose `a7` is neither 93 nor a registered delegation has no proof. The emulator answers
  any other number `-ENOSYS` and continues ([ecall-abi.md](ecall-abi.md) §4); the fill refuses that
  trace, naming the cycle.
- An `ebreak` has no proof; it is fatal in the emulator
  ([execution-trace.md](execution-trace.md) §10).
- No row touches RAM: an `ecall` row reads `a7` and `a0`, and an exit writes `a0`; a delegation's
  frame is its family's row's.
