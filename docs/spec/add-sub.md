# The `ADD_SUB_LUI_AUIPC` family

`add`, `sub`, `addi`, `lui`, `auipc`, `ecall`, `ebreak` and `fence`, compressed forms included, are
family 0, one executed instruction a row; `constraints::add_sub::artifact` is its circuit. Every
`ecall` is a row of it, so the circuit also proves the exit and the request side of every
delegation call. This page specifies what it adds beside the memory frame
([memory.md](memory.md) §2).

## 1. Columns

The decoded tuple is `pc next_pc rs1 rs2 rd imm extra_mask` ([program.md](program.md) §5), the
mask one-hot over the kinds `system addi auipc add sub lui` in bit order
(`constants::extra_mask::add_sub_lui_auipc`). `ecall`, `ebreak` and `fence` share the system kind,
with `imm` 0, 1 and 2 (`constants::extra_mask::system_code`); elsewhere `imm` is what the
instruction adds — `addi`'s sign-extended immediate, `lui`'s and `auipc`'s shifted left by 12, 0
for `add` and `sub` — and a register field the instruction lacks is 0.

`M[0..26]` and `W[0..8]` are the frame of the five queries `pc rs1 rs2 rd deleg`, and `M[26]`,
`deleg_space`, is the requested delegation type's anchor address space, 0 on a row requesting none
([memory.md](memory.md) §2). The family adds these columns, and reads `V[range19]` and
`V[range16]`:

| column | name | |
| --- | --- | --- |
| `W[8..14]` | `decoded_next_pc`, `decoded_rs1`, `decoded_rs2`, `decoded_rd`, `decoded_imm`, `decoded_mask` | the claimed decoded row |
| `W[14..20]` | `kind_system` … `kind_lui` | `b_k`, the mask's bits |
| `W[20]`, `W[21]` | `is_ecall`, `is_fence` | the system kind, split by its code |
| `W[22..28]` | `is_deleg_<f>`, `f` = 9, 10, 11, 15, 16, 17 | `d_t`: a request of delegation type `t`, family `f` |
| `W[28]`, `W[29]` | `wrap`, `rd_hi` | the sum's carry or the difference's borrow; `sel`'s high halfword |
| `W[30]`, `W[31]` | `pc_wrap`, `next_pc_hi` | `next_pc`'s wrap and high halfword |
| `W[32..35]` | `mult_timestamp`, `mult_range16`, `mult_decoder` | one multiplicity a channel |
| `S[0..7]` | `table_pc` … `table_extra_mask` | the decoded table |

Below, `m_q`, `a_q`, `ts_q` and `v_q` are query `q`'s mask, address, read timestamp and read
value; `pc` and `next_pc` the pc query's read and write values; `sel` is `rd_selected` (`W[7]`),
the value the frame writes to a nonzero `rd`. `N_t` and `tag_t` are type `t`'s ecall number and
anchor space, the first six rows of `constants::delegation::TYPES` in order
([delegation.md](delegation.md) §3); `is_exit = is_ecall − Σ_t d_t`; 93 is
`constants::ecall::EXIT` and `HALT_PC` is 1 ([memory.md](memory.md) §5).

The family's fill (`prover::family_fill`, `crates/prover/src/fill.rs`) writes `sel` as the
computed value even where `rd = x0`.

## 2. Gates

63 enforcing gates, all in gate list 0, each of degree at most 2 and 0 on the all-zero row: the
frame's eleven ([memory.md](memory.md) §2) and these 52, in artifact order, each held to 0:

| gate | expression |
| --- | --- |
| `kind_<k>_boolean`, six | `b_k − b_k²` |
| `decoded_mask_bits` | `Σ_k 2^k·b_k − decoded_mask` |
| `is_ecall_boolean`, `is_fence_boolean` | `y − y²` |
| `system_split` | `is_ecall + is_fence − b_system` |
| `ecall_code` | `is_ecall·decoded_imm` |
| `fence_code` | `is_fence·(decoded_imm − 2)` |
| per type: `is_deleg_<f>_boolean`, `deleg_<f>_is_an_ecall`, `deleg_<f>_number` | `d_t − d_t²`; `d_t·(1 − is_ecall)`; `d_t·(v_rs1 − N_t)` |
| `ecall_is_exit` | `is_exit·(v_rs1 − 93)` |
| `rs1_mask_rule` | `m_rs1 − m_pc·(b_add + b_sub + b_addi + is_ecall)` |
| `rs2_mask_rule` | `m_rs2 − m_pc·(b_add + b_sub + is_ecall)` |
| `rd_mask_rule` | `m_rd − m_pc·(b_add + b_sub + b_addi + b_auipc + b_lui + is_ecall)` |
| `deleg_mask_rule` | `m_deleg − m_pc·Σ_t d_t` |
| `rs1_addr_rule` | `m_rs1·(a_rs1 − decoded_rs1 − 17·is_ecall)` |
| `rs2_addr_rule`, `rd_addr_rule` | `m_q·(a_q − decoded_q − 10·is_ecall)` |
| `rs1_value_masked`, `rs2_value_masked` | `v_q − m_q·v_q` |
| `add_addi_auipc` | `(b_add + b_addi + b_auipc)·(v_rs1 + v_rs2 + decoded_imm − sel − 2^32·wrap) + b_auipc·pc` |
| `sub` | `b_sub·(v_rs1 − v_rs2 − sel + 2^32·wrap)` |
| `lui` | `b_lui·(decoded_imm − sel)` |
| `exit_status` | `is_exit·(v_rd − sel)` |
| `deleg_writes_no_register` | `m_deleg·sel` |
| `deleg_read_ts_zero`, `deleg_read_value_zero` | `m_deleg·ts_deleg`; `m_deleg·v_deleg` |
| `deleg_addr_rule` | `m_deleg·(a_deleg − v_rs2)` |
| `deleg_space_rule` | `deleg_space − Σ_t tag_t·d_t` |
| `wrap_boolean`, `pc_wrap_boolean` | `y − y²` |
| `next_pc_rule` | `next_pc + 2^32·pc_wrap − (1 − is_exit)·decoded_next_pc − is_exit·HALT_PC` |

`N_t` and `tag_t` are literals read from `constants::delegation::TYPES`, so the base circuit
depends on the registry's first `BASE_TYPES = 6` rows and on no row appended after them. The
recursion format's circuit, `add_sub::recursion_artifact`, carries a selector and its three gates
for each of the ten types, the columns after them shifted by four, and in place of
`deleg_writes_no_register` `deleg_a0_rule`,
`Σ_{t<6} d_t·sel + Σ_{t≥6} d_t·(sel − v_rs2 − 4·words_t)` with `words_t` the type's frame length:
a recursion type's request leaves `a0` past its frame ([recursion.md](recursion.md) §1.4).

## 3. Lookups

15 obligations on three channels, none of them `GENERIC`, so the setup columns are the decoded
table alone: the frame's ten `TIMESTAMP` gaps, two a query under its mask
([memory.md](memory.md) §2), and five under `m_pc`:

| lookup | channel | tuple |
| --- | --- | --- |
| `rd_hi_range`, `rd_lo_range` | `RANGE16` | `rd_hi`; `sel − 2^16·rd_hi` |
| `next_pc_hi_range`, `next_pc_lo_range` | `RANGE16` | `next_pc_hi`; `next_pc − 2^16·next_pc_hi` |
| `decode_row` | `DECODER` | `pc`, `decoded_next_pc`, `decoded_rs1`, `decoded_rs2`, `decoded_rd`, `decoded_imm`, `decoded_mask` |

The channels, in output order (`add_sub::channels`), are `TIMESTAMP` over `V[range19]`, `RANGE16`
over `V[range16]` and `DECODER` over `S[0..7]`.

## 4. Why it is sound

On a live row (`m_pc = 1`) `decode_row` makes the claimed row the table's at `pc`, so exactly one
`b_k` is 1 ([lookup.md](lookup.md) §10). The mask rules make each query present exactly where the
row's kind or request makes it ([execution-trace.md](execution-trace.md) §4, §6). The address rules
make a register query the decoded register, or on an `ecall` row, whose decoded registers are 0,
`a7` (17) for `rs1` and `a0` (10) for `rs2` and `rd`. The `_value_masked` gates make an absent
operand read 0, which lets one gate serve three sums: an `addi` or `auipc` row's `v_rs2`, and an
`auipc` row's `v_rs1`, would otherwise be free addends, and `add`'s `imm` is the table's 0.

Read values are words ([memory-ops.md](memory-ops.md) §5), `sel` is a word by its range pair and
`wrap` is boolean, so each arithmetic gate is an identity over ℤ with one solution: the sum mod
`2^32` and its carry, the difference mod `2^32` and its borrow, or `imm`. Without the pair, a sum
at or above `2^32` would satisfy the gate with `wrap = 0` and reach a register. The frame's x0 rule
then writes `sel` or discards it.

`next_pc` is a word by its range pair and is `decoded_next_pc` — the table's fall-through, so a
compressed instruction advances by 2 ([program.md](program.md) §5) — or `HALT_PC` on the exit row,
less `2^32·pc_wrap`. Both are far below `2^32`, so `pc_wrap = 0` on every live row.

On a system row `system_split` sets exactly one of `is_ecall` and `is_fence`, and the code gates
make it the one `imm` names; `ebreak`'s code 1 satisfies neither, so an `ebreak` row is unprovable.
A `fence` row makes no query but the pc's and falls through. Off a system row both bits are 0,
and so, by `deleg_<f>_is_an_ecall`, is every `d_t`.

A set `d_t` forces `is_ecall = 1` and `a7 = N_t`. The numbers are pairwise distinct and none is 93,
`const` assertions beside the circuit, so at most one `d_t` is set, `is_exit` is 0 or 1, and an
`ecall` row is the exit, with `a7 = 93`, or a request of exactly one type; no other `a7` passes.

- The exit row writes back the `a0` it read (`exit_status`), so `x10`'s final value is the status
  the statement carries ([proof.md](proof.md) §6, step 10b), and writes `HALT_PC`, after which no
  row runs ([memory.md](memory.md) §5).
- A request row falls through, writes 0 to `a0`, and makes the mirror query at the frame base it
  read from `a0`, in the space `deleg_space` names, reading timestamp 0 and value 0. Those three
  zeroings pair it one-to-one with an invocation of its type ([delegation.md](delegation.md) §5);
  the mirror's write value is free here, and what the call computed is the invoked family's circuit
  ([delegation-circuits.md](delegation-circuits.md)). `deleg_space` is an `M` column because a
  memory leaf may read no `W` column ([memory.md](memory.md) §8); `deleg_space_rule` ties it to the
  selectors.

A row with `m_pc = 0` is bound to no table row and its kind bits are free; the arithmetic gates are
gated by those bits alone, `m_pc` times a bit being degree 3. That is harmless: the mask rules zero
the row's other four masks and every lookup is off, so it adds no memory tuple. On a live row,
`wrap` outside the four sums and `sel` on a `fence` row are free, and nothing reads them.

## 5. Limits

- An `ecall` whose `a7` is neither 93 nor a type the format's circuit knows has no proof. The
  emulator answers an unassigned number `-ENOSYS` and continues ([ecall-abi.md](ecall-abi.md) §5);
  the fill refuses that trace, naming the cycle.
- An `ebreak` has no proof; it is fatal in the emulator
  ([execution-trace.md](execution-trace.md) §10).
- No row touches RAM: an `ecall` row reads `a7` and `a0` and writes `a0`, and a request's operands
  travel in the invoked family's frame ([delegation.md](delegation.md) §4).
