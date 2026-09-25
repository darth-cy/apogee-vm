# The memory argument: tuples, RAM windows, the register and PC boundary

Frozen as of S14. Changing anything here is a protocol-version change. S21 appended the ninth
query — `deleg`, a delegation request's mirror (§2.1) — and a new address space above RAM's;
`docs/spec/delegation.md` is normative for both, and nothing else on this page moved for it.
S-IO appended three window families and extended the window tiling to the whole address space
(§3); `docs/spec/public-values.md` is normative for them, and the tuple, the frame, the
boundary and the reconciliation are unmoved.

This page is the global memory argument of `prompts/00-master.md`, as the repository owner
decided it at S14: RAM initialization and teardown in fixed **RAM windows**, the register and
PC boundary computed by the **verifier**, and a **halting sentinel** on the exit row. It cites
`docs/spec/execution-trace.md` for what a query is and `docs/spec/gkr.md` for the circuit
model; it restates neither.

| crate | what |
| --- | --- |
| `crates/constants` | the slots, tags, family ids, channel, `HALT_PC`, root positions |
| `crates/constraints` | `memory`: the frame layout, the tuple and leaf gates, the gap and x0 gadgets, the window artifacts, the construction-time rules |
| `crates/gkr-verify` | the window constant, the boundary factors, reconciliation |
| `crates/trace` | the column builders, the window list, the boundary finals |
| `crates/program` | the image column, the identity recipe, the statement's window list and its checks |
| `crates/checker` | the root self-check hook, the native lookup evaluator, the padding-identity check |

---

## 1. The tuple

Every memory event compresses to one field element under four global challenges:

```text
T(AS, ADDR, TS, VAL) = γ_M + AS + α_addr·ADDR + α_ts·TS + α_val·VAL
```

- **Parts, in order**: `AS`, `ADDR`, `TS`, `VAL` — `constants::memory::PART_*`. `γ_M` is
  additive and `AS` is added to it unweighted; `ADDR`, `TS`, `VAL` are weighted by
  `α_addr`, `α_ts`, `α_val` in that order.
- **Address spaces**: `REG = 1`, `RAM = 2`, `PC = 3` (`constants::address_space`, frozen at
  S12). A RAM address is the byte address of a 4-aligned word.
- **Challenge slots** (`constants::challenge_slot`, append-only after S13's `TOY = 0`):

| slot | name | value |
| --- | --- | --- |
| 1 | `MEM_GAMMA` | `γ_M`, drawn |
| 2 | `MEM_ALPHA_ADDR` | `α_addr`, drawn |
| 3 | `MEM_ALPHA_TS` | `α_ts`, drawn |
| 4 | `MEM_ALPHA_VAL` | `α_val`, drawn |
| 5 | `MEM_WINDOW_CONSTANT` | derived, per window shard: `γ_M + RAM + α_addr·4h·w` (§3.3) |

Slots 1–4 are drawn once per statement, after everything §6 lists. Slot 5 is a **derived
slot** (`docs/spec/gkr.md` §5.1): a fixed function of drawn challenges and of statement data
absorbed before them, computed by the verifier and never read from a proof.

A gate coefficient is one `Coeff`, a literal or one slot, so a product such as `α_ts·4` is
written as a term repeated four times. Normalization merges repeats.

**Roots.** Every memory artifact's output map has exactly two entries:
`outputs[READ_ROOT = 0]` is the product of its read tuples and `outputs[WRITE_ROOT = 1]` the
product of its write tuples (`constants::memory::{READ_ROOT, WRITE_ROOT}`), named `read_root`
and `write_root` in the scratch bijection. `checker::memory_roots` recomputes both from the
materialized layer the first halving list reads.

---

## 2. An execution family's memory subtree

### 2.1 The frame columns

Every execution family's memory-argument columns follow one layout, built by
`trace::build_memory_columns`. A row is one cycle. The **query table** has **nine** entries
since S21: query 0 is the pc query, queries 1–8 are the roles of `execution-trace.md` §7 in
their frozen order.

| query `q` | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| what | pc | `rs1` | `rs2` | `arg1` | `arg2` | `load` | `ram` | `rd` | `deleg` |
| `AS` | PC | REG | REG | REG | REG | RAM | RAM | REG | the delegation family's own |
| `Δ` | 0 | 1 | 2 | 2 | 2 | 2 | 3 | 3 | 3 |

`deleg` is a **delegation request's mirror query** (`docs/spec/delegation.md` §5.1), in the
address space of the family it calls — `DELEGATION_KECCAK_F = 4` for S21's one family — at the
frame base the request read from `a0`. It is the eighth role and took `trace::Row::present`'s
last spare bit.

**A family's frame holds a subset of that table, not all of it**: every query an instruction
routed to it can make, and no other. The subsets are frozen in
`constraints::memory::frame_queries`, derived from `execution-trace.md` §4 over
`program::row_kind`'s routing:

| family | queries | `w` | `M` | `W` | leaves a side | obligations |
| --- | --- | --- | --- | --- | --- | --- |
| `ADD_SUB_LUI_AUIPC` | pc `rs1` `rs2` `arg1` `arg2` `ram` `rd` `deleg` | 8 | 41 | 11 | 8 | 16 |
| `JUMP_BRANCH_SLT` | pc `rs1` `rs2` `rd` | 4 | 21 | 7 | 4 | 8 |
| `SHIFT_BITWISE` | pc `rs1` `rs2` `rd` | 4 | 21 | 7 | 4 | 8 |
| `MUL_DIV` | pc `rs1` `rs2` `rd` | 4 | 21 | 7 | 4 | 8 |
| `MEM_WORD` | pc `rs1` `rs2` `load` `ram` `rd` | 6 | 31 | 9 | 8 | 12 |
| `MEM_SUBWORD` | pc `rs1` `rs2` `load` `ram` `rd` | 6 | 31 | 9 | 8 | 12 |
| `ATOMICS` | pc `rs1` `rs2` `ram` `rd` | 5 | 26 | 8 | 8 | 10 |

`arg1`, `arg2` and `deleg` are an ecall row's alone, and `load` is a load's word at slot 2, so
no family holds all nine: the table above is a union no family reaches. The A extension keeps
its RAM query at slot 3 for every instruction it owns, `lr.w` included
(`execution-trace.md` §7), so `ATOMICS` has no `load`. **`ADD_SUB_LUI_AUIPC`'s eight is a power
of two**, so its two product trees carry no pad leaf — the only family of which that is true —
and its sixteen gap obligations, with the table fraction, make seventeen `TIMESTAMP` leaves,
which pads to 32 and costs the circuit one row-wise gate list
(`docs/spec/constraint-manifest.md` §3.6).

**A delegation family has no frame and is not in this table.** Its rows are invocations, not
cycles, and its memory columns are 50 fixed-offset words plus an anchor rather than a subset of
the query table; `frame_queries` panics on it by name. `docs/spec/delegation.md` §4 and §6 are
its layout, and `docs/spec/constraint-manifest.md` §12 the accounting.

A **slot** `s` is a position in the family's list, and the columns are addressed by slot:

```text
M[0]            cycle
M[1 + 5s + f]   the query at slot s, field f:
                0 mask   1 addr   2 read_ts   3 read_value   4 write_value
```

`1 + 5w` memory columns and `w + 3` witness columns, `w` being the family's query count. For
the pc query, `addr = 0`, `read_value = pc`, `write_value = next_pc` and `read_ts` is the
previous cycle's pc write. The honest fill sets `mask` to 1 exactly when the row is live and
its instruction has that query. **A row or query with mask 0 carries 0 in every one of its
memory columns**, `cycle` included on a padding row. `constraints::memory` holds the AS and Δ
table as data, and a test in `crates/trace` holds it to `trace::Role`.

**Why the subset is a completeness rule, not a soundness one.** A frame *narrower* than its
family drops events from the multiset, which leaves their addresses' chains broken: the
honest prover cannot balance, and no forgery is admitted. A frame *wider* than its family
carries columns that are 0 on every row, commits and opens them, and discharges their
obligations vacuously — waste, not a hole. What the subset must be exact for is **S16**,
which ties an instruction's computed value to a `write_value` column: a query with no column
is an instruction with nothing constraining it. So the rule S16 inherits is that a family's
frame is a **superset** of the queries its instructions make, and
`crates/trace/tests/memory.rs` holds `frame_queries` to `program::row_kind` instruction by
instruction.

**What ties a mask to its row is owed by S16.** At S14 the frame holds each mask to
booleanity and nothing else. So three forgeries each balance: a query on a row whose pc mask
is 0, a live row with one of its queries masked off, and a live row carrying a query its
instruction does not have. Each keeps every gate and obligation, and the first lets a padding
row rewrite `x10`, the exit status, after the exit row (`crates/checker/tests/multiset.rs`,
control C8). S16's family constraints make:

- `m_pc` the row's liveness, and the decoded-table lookup's selector `m_pc` itself, not a
  separate witness: a live row of §5 is a row with `m_pc = 1`;
- every other mask `m_q = m_pc·uses_q`, with `uses_q` read from the looked-up row kind:
  - `rs1`, `rs2` and `rd` follow the instruction's form, `x0` included
    (`execution-trace.md` §4);
  - a transfer row shares its ecall's pc and table row and uses `pc` and `ram` only, so
    `is_transfer` is a witness that is itself constrained;
  - on an ecall row, `rs2`, `arg1` and `arg2` (`a0`, `a1`, `a2`) follow the number read at
    slot 1: all three for `READ` and `WRITE`, `rs2` alone for `EXIT` and for every
    **delegation** number, none otherwise (`execution-trace.md` §6). A delegation row uses
    `deleg` as well, whose mask is `m_pc` times the sum of the row's type selectors
    (`delegation.md` §5.1). Each such `uses_q` comes from `is-zero(a7_read − n)`, split
    across layers to keep every gate at degree 2 or below — except where the family
    commits a selector per number and pins it, which is what `ADD_SUB_LUI_AUIPC` does for
    the four ecalls it proves.

**Status at S16.** `ADD_SUB_LUI_AUIPC` discharges this section for its own rows
(`docs/spec/shard-proof.md` §8): `m_pc` is the decoder lookup's selector and every other
mask is `m_pc` times its kind's use. It proves `EXIT` alone, so it needs no `is-zero`: a
gate holds every ecall row's `a7` read to 93, and `arg1`, `arg2` and `ram` are masked off
on every row. No transfer row is provable, so `is_transfer` does not exist yet; the
I/O-binding stage owes it. Every other execution family owed this section at its own stage,
and until then had no circuit, so no statement containing it could be proved.

**Status at S17.** `JUMP_BRANCH_SLT` discharges this section for its own rows
(`docs/spec/jump-branch-slt.md` §4.1): `m_pc` is the decoder lookup's selector, and `rs1`,
`rs2` and `rd` are each `m_pc` times the kind's use of them — a branch has no `rd` query.

**Status at S18.** `SHIFT_BITWISE` and `MUL_DIV` discharge it the same way
(`docs/spec/shift-bitwise.md` §4.1, `docs/spec/mul-div.md` §4.1): `rs1` and `rd` on every
kind, `rs2` on the R-type half alone.

**Status at S19.** `MEM_WORD`, `MEM_SUBWORD` and `ATOMICS` discharge it
(`docs/spec/memory-ops.md` §3.2, §4.6, §6.7), and with them **every execution family
does**. Their `uses_q` sets are `execution-trace.md` §4's: a load makes no `rs2` query and
a store no `rd`, so the two memory families read `load`/`rd` under the load kinds and
`rs2`/`ram` under the store kinds; and `lr.w` makes no `rs2` query, which the atomics
family's rule keys on `b_lr` and never on `is_zero(decoded_rs2)` — a test
`amoadd.w rd, x0, (rs1)`, a real lowering, would also pass.

### 2.2 The leaves

For query `q` with mask `m`, AS `s`, slot `Δ`:

```text
read leaf    R_q = m·T(s, addr, read_ts,         read_value)  + 1 − m
write leaf   W_q = m·T(s, addr, 4·cycle + Δ,     write_value) + 1 − m
```

Each is **one `Quadratic`, written flat**, as `1 + m·(γ_M − 1 + s + …)` with every other term
of the tuple times `m`:

```text
R_q = Quadratic { constant: 1,
                  linear:   [(γ_M, m), (−1, m), (s, m)],
                  products: [(α_addr, addr, m), (α_ts, read_ts, m), (α_val, read_value, m)] }
W_q = Quadratic { constant: 1,
                  linear:   [(γ_M, m), (−1, m), (s, m), (α_ts, m) × Δ],
                  products: [(α_addr, addr, m), (α_ts, cycle, m) × 4, (α_val, write_value, m)] }
```

`s` is a literal; `× k` repeats a term `k` times. The relation is the same polynomial.
`constraints::memory`'s leaf constructor writes both from the unmasked tuple gate
`read_tuple(q)` or `write_tuple(q)` — a `Linear` whose `AS` and `Δ` terms already sit on `m`,
its parts in the order of `constants::memory::PART_*` — in this order: the tuple's constant on
`m`, then `(−1, m)`, then the tuple's terms on `m` as they are, and every other term times `m`.
A term already on `m` enters once. So a leaf is `m·T + 1 − m` at every `m`, with `T` §1's tuple
at `AS = s`, but it equals `m·tuple + 1 − m` for the unmasked gate only at a boolean `m`, and it
is 1 or a tuple only at `m ∈ {0, 1}`, which the booleanity gate of §2.4 supplies.
At `m = 0` a leaf is 1 whatever the other columns hold; at `m = 1` it is the tuple. The
`MaskIntoIdentity` shape is not used: its input would have to be a column or a cached entry,
and a cached tuple inside it refuses the cache-free compilation.

### 2.3 The product

Let `w` be the family's query count and `s = w` rounded up to a power of two. Gate list 0
writes `2s` leaves to layer 1, in the order `R_0..R_{w−1}`, the read pads, `W_0..W_{w−1}`,
the write pads. A **pad leaf** is `Linear { [], 1 }` — the product's identity, reading no
column — so a family whose query count is not a power of two pays inner columns for them and
nothing else: no committed column, no obligation, no enforcing gate. Row-wise lists multiply
neighbours, `L{k+1}[j] = L{k}[2j]·L{k}[2j+1]`, halving the width from `2s` to 2; that last
layer is `[read row product, write row product]`. Then `trace_vars` halving lists of
`TreeProduct`, down to a 0-variable top of width 2. `outputs = [L{N}[0], L{N}[1]]`.
Every list multiplies exactly two children per output, and every gate is degree ≤ 2.

At the seven families' widths that is `2s = 8` leaves for the three 4-query families and 16
for every other. **`ADD_SUB_LUI_AUIPC`, the widest, is the only one where `s = w`**: its
eight queries fill an eight-leaf tree exactly, so since S21 it carries no pad leaf. It was
`w = 7` and one pad a side until the `deleg` query.

### 2.4 The gadgets every execution family carries

**Mask booleanity.** For each of the family's `w` masks, the enforcing gate `m − m·m = 0`. A leaf is 1
or a tuple only at `m ∈ {0, 1}`; at `m = −1` a PC query's two leaves are each
`−T(AS − 2, …)`, one sign flip on each side, so the products still balance and the query
reads as a REG query.

**Read-only queries write back what they read.** For each of `rs1`, `rs2`, `arg1`, `arg2` and
`load` **the family's frame holds**, the enforcing gate `write_value − read_value = 0`
(`execution-trace.md` §3). Without it a read of `x0` could write 5 there. So the count is the
family's: 4 for `ADD_SUB_LUI_AUIPC`, 3 for the two memory families, 2 for the rest.

**The x0 rule** (must-be-exact 7). On the `rd` query — query 7, at the family's last slot,
every execution family having one — with witness columns `rd_inv`, `rd_is_zero` = `z` and
`rd_selected` = `sel`:

```text
addr·rd_inv + z − m = 0          z = 1 exactly when addr = 0 on a live rd query; z = 0 when m = 0
addr·z = 0
z − z·z = 0
write_value − sel + z·sel = 0    write_value = (1 − z)·sel
```

So every rd write at address 0 writes 0, whatever the row computed. With read-only queries
writing back and `x0` initialized to 0 (§4), every read of `x0` returns 0. The final
`v_0 = 0` of §4 pins only `x0`'s last write: without the gadget, a write of 5 followed by a
read of 5 and a write of 0 balances.

**The timestamp gap** (must-be-exact 4). Every read of every query carries

```text
gap_q = 4·cycle + Δ_q − read_ts − 1  ∈ [0, 2^38)
```

as two range obligations on the timestamp channel (§7), both with selector `M[mask_q]`, over
one witness column `W[q_gap_hi]`:

```text
gap_hi_q : Linear { [(1, W[q_gap_hi])], 0 }
gap_lo_q : Linear { [(4, cycle), (−1, read_ts), (−2^19, W[q_gap_hi])], Δ_q − 1 }
```

Each chunk in `[0, 2^19)` makes `gap = lo + 2^19·hi` a field element in `[0, 2^38)`. As
integers that is strictly `read_ts < 4·cycle + Δ`, because every timestamp of a balanced
statement is a canonical integer (§4.2's count). The gadget returns its obligations by value, and the
artifact's construction asserts their number is twice the number of reads.

**Names.** A name is used once per artifact (`docs/spec/gkr.md` §4.2), so a column and the
obligation over it differ. With `<q>` the query's name of §2.1 and `w` the family's query
count, every list below is in **slot order**: `M` columns `cycle`, `<q>_mask`, `<q>_addr`,
`<q>_read_ts`, `<q>_read_value`, `<q>_write_value`; `W` columns `<q>_gap_hi` for the family's
`w` queries, then `rd_inv`, `rd_is_zero`, `rd_selected` (`W[w]`–`W[w + 2]`); obligations
`gap_hi_<q>` and `gap_lo_<q>`, two per query; leaves `read_<q>` then `write_<q>`, each side
followed by its `read_pad_<i>` / `write_pad_<i>` up to the power of two; enforcing gates
`<q>_mask_boolean` for the family's `w` masks, `<q>_writes_back` for each of `rs1`, `rs2`,
`arg1`, `arg2` and `load` the family holds, and `rd_is_zero_inverse`,
`rd_is_zero_at_nonzero`, `rd_is_zero_boolean`, `rd_write_masked` for the four x0 gates in the
order above.

---

## 3. RAM windows

### 3.1 Geometry

Let `h = 2^n` be the height of the window families. **Window `w` covers byte addresses
`[4h·w, 4h·(w+1))`** for `0 ≤ w < 2^30 / h`. Row `y` of window `w` is the word at
`ADDR = 4h·w + 4y`. Since S-IO the windows tile `[0, 2^32)` exactly — 256 of them at
`h = 2^22`, 16,384 at `2^16` — and `N = 2^29 / h` is where ordinary RAM ends and the advice
region begins.

- RAM is `[RAM_ORIGIN, ADVICE_ORIGIN) = [2^16, 2^31)`, `2^29 − 2^14` words, a count no menu
  height divides. A `ZERO_WINDOWS` id is in **`[1, N − 1]`**, exactly as at S14: that bound
  did not move.
- The only rows below `ADVICE_ORIGIN` outside RAM are **window 0's rows `y < 2^14`**
  (addresses `0x0..0xFFFC`), at every height, and `INIT_TEARDOWN` masks every one of them
  with `V[ram_live]`. Two sub-ranges of that masked span are the **public value windows**,
  claimed by two families of their own at their own pinned height
  (`docs/spec/public-values.md` §2); the rest of it stays a hole no family initializes, so a
  null dereference reads a tuple nothing wrote and cannot balance.
- Window 0 holds the image, which starts at `RAM_ORIGIN`. Window `N − 1` holds the initial
  `sp`, `0x8000_0000 − 4` and below; every traced guest touches it.
- The windows from `N` up are the **advice region**, `[ADVICE_ORIGIN, 2^32)`: `ADVICE_WINDOWS`
  shard `i` is window `N + i`, `verifier_core::advice_first_window(h)` being that `N`. The two
  families' ids are therefore disjoint **by arithmetic and not by a rule** — `2^29 / h` is the
  exclusive top of one range and the inclusive bottom of the other, one number serving as both
  — and a statement carries no advice window list, only the count already in `SHARD_COUNTS`
  (`docs/spec/public-values.md` §6).

### 3.2 Three families of one height, and two at a pinned one

| family | id | shards | window | init value |
| --- | --- | --- | --- | --- |
| `INIT_TEARDOWN` | 7 | exactly 1 | 0, the image window | `S[0]`, the image column, committed in program identity |
| `ZERO_WINDOWS` | 8 | `k ≥ 0` | `w_1 < … < w_k`, each in `[1, N − 1]` | literal 0 |
| `ADVICE_WINDOWS` | 14 | `k_a ≥ 0` | `N … N + k_a − 1`, consecutive | `M[2]`, committed and bound to nothing |
| `PUBLIC_INPUT` | 12 | exactly 1 | `PUBLIC_INPUT_WINDOW` = 32, at `2^8` | `M[2]`, held to the statement's `input` |
| `PUBLIC_OUTPUT` | 13 | exactly 1 | `PUBLIC_OUTPUT_WINDOW` = 33, at `2^8` | literal 0 |

All five are present in every `VmConfig` and never detached. The first three have **one
height** `h`: `decode_program` and `VmConfig::from_bytes` refuse a config where any of them
differs or is missing. A `ZERO_WINDOWS` height below `INIT_TEARDOWN`'s would put zero windows
with id ≥ 1 inside the image window, giving image words a second init row; an
`ADVICE_WINDOWS` height of its own would put the advice windows on a different grid from the
one `advice_first_window(h)` computes, and the statement, carrying a count and no list, would
have no way to say which. The default height of all three is `2^22`.

The last two are at **`family::PUBLIC_WINDOW_HEIGHT` = `2^8`, and only that**, because a
window's first address is `4h·w` and the height is therefore what *places* the windows: `2^8`
is the one menu entry putting the two public origins in two distinct windows.
`decode_program` writes the constant and ignores what a caller asked for, so “every family at
`h`” keeps meaning every family whose height is a choice, and `verifier_core::window_height`
refuses any other — the check that matters, because it is the one on bytes a verifier was
handed. `docs/spec/public-values.md` §2 is normative for both families.

### 3.3 The artifacts

All three artifacts: `trace_vars = n`, which is `8` for the two public families, whose
height is pinned; memory columns `M[0] = teardown_ts`, `M[1] = teardown_value`; no witness
columns; no enforcing gates; no lookups and no channel; virtual `V[row]`. `INIT_TEARDOWN` adds `S[0] = init_value`
and `V[ram_live]`; `value_window_artifact` adds `M[2] = init_value` instead. `WC` is slot 5.

```text
ZERO_WINDOWS
  L1[0] teardown = Linear { [(α_addr, V[row]) × 4, (α_ts, M[0]), (α_val, M[1])], WC }     read side
  L1[1] init     = Linear { [(α_addr, V[row]) × 4], WC }                                   write side

INIT_TEARDOWN     (live = V[ram_live]; each leaf is live·tuple + 1 − live)
  L1[0] teardown = Quadratic { 1, [(WC, live), (−1, live)],
                               [(α_addr, V[row], live) × 4, (α_ts, M[0], live), (α_val, M[1], live)] }
  L1[1] init     = Quadratic { 1, [(WC, live), (−1, live)],
                               [(α_addr, V[row], live) × 4, (α_val, S[0], live)] }

value_window_artifact     (`docs/spec/public-values.md` §4)
  M[0] teardown_ts    M[1] teardown_value    M[2] init_value    V[row]

  L1[0] teardown = Linear { [(α_addr, V[row]) × 4, (α_ts, M[0]), (α_val, M[1])], WC }   read side
  L1[1] init     = Linear { [(α_addr, V[row]) × 4,                (α_val, M[2])], WC }   write side
```

`constraints::memory::value_window_artifact` is `zero_window_artifact` with that one column
added, and the two families that take it — `PUBLIC_INPUT` and `ADVICE_WINDOWS` — differ only
in what the verifier does with the column: holds it to the statement's `input` at the shard's
own opening point, or to nothing at all. It is `M` and not `S` because an `S` column is bound
by program identity, and one execution's public input — or one execution's advice — has no
business in every execution's identity. `PUBLIC_OUTPUT` takes `zero_window_artifact` byte for
byte: its init leaf is the literal 0, so there is no init column for a prover to choose
(`docs/spec/public-values.md` §5).

Then `n` halving lists to a 0-variable top of width 2, and `outputs = [L{N}[0], L{N}[1]]`:
read root (teardown), write root (init). The init timestamp is literal 0. Padding row: zeros,
`zero_row_valid`. A window shard has **no inactive rows** — every row is an address — so §2's
padding fill does not apply to it.

`V[ram_live]` is `VirtualKind::RamLive`, wire tag 1 (`docs/spec/gkr.md` §2.1): its value at
row `y` is `[y ≥ 2^14]` and its multilinear extension is `1 − ∏_{j=14}^{n−1} (1 − y_j)`,
evaluable at any point in `n − 14` multiplications and 0 or 1 on the cube by construction. It
is the mask on window 0's rows below `RAM_ORIGIN`, on both leaves.

The window constant for a shard of window `w` is
`WC = γ_M + RAM + α_addr·4h·w`, computed by `gkr_verify::window_challenges` from the drawn
slots and the window id bound in the statement (§6). `verifier_core::shard_challenges` is
what supplies `w`: 0 for `INIT_TEARDOWN`, `windows[index]` for `ZERO_WINDOWS`, the constants
`PUBLIC_INPUT_WINDOW` and `PUBLIC_OUTPUT_WINDOW` for the two public families — their ids are
constants because their height is — and `advice_first_window(h) + index` for `ADVICE_WINDOWS`,
whose shards are consecutive from the origin and so need no list.

`kat-gen`'s `memory` group writes `memory_frame_{alu,reg,mem,atomics}.bin`,
`image_window.bin` and `zero_window.bin` — one file per *distinct* frame of §2, and the
`INIT_TEARDOWN` and `ZERO_WINDOWS` artifacts — at `n = 22` to
`crates/constraints/tests/vectors/`; CI regenerates and diffs them. `value_window_artifact`
has no fixture of its own; `crates/checker/tests/memory.rs` runs the laws and
§8's `check_memory` over it beside the others. Families sharing a query list share their
artifact byte for byte, so `reg` is `JUMP_BRANCH_SLT`, `SHIFT_BITWISE` and `MUL_DIV`, and
`mem` is `MEM_WORD` and `MEM_SUBWORD`;
a test holds each of the seven execution families to one of the four files, so four fixtures
pin all seven frames.

### 3.4 The columns a prover fills

`trace::init_windows(log, h)`: the ascending distinct `⌊a / 4h⌋` over every touched word `a`
of **ordinary RAM**, **without 0**. That is `ZERO_WINDOWS`'s shard list.

“Ordinary RAM” is `trace::in_ram(a)`, `[RAM_ORIGIN, ADVICE_ORIGIN)`, and the filter is
load-bearing since S-IO: a public value and an advice word are `RAM`-tagged tuples like any
other (`docs/spec/public-values.md` §2), and each sits in a window some *other* family
initializes. A zero window over either would give those words a second init row and a prover
a second value to choose, which is the same failure a `ZERO_WINDOWS` id of 0 would be.

`trace::build_init_teardown_columns(log, image, w, h)`, per row `y` at `a = 4h·w + 4y`:

| row | `teardown_ts` | `teardown_value` |
| --- | --- | --- |
| `w = 0` and `y < 2^14` (masked) | 0 | 0 |
| `a` touched | the last write's ts | the last write's value |
| `a` untouched | 0 | `image.initial_word(a)` |

and, for `w = 0`, `S[0]`. An untouched row's init and teardown tuples are equal and cancel.

`trace::build_value_window_columns(log, initial, w, h)` is the same three columns for a
family whose init column is committed: `M[0]` and `M[1]` as above, and `M[2][y] = initial[y]`
— the statement's public input for `PUBLIC_INPUT`, the prover's advice for `ADVICE_WINDOWS`,
0 past the end of either. An untouched row again keeps `(0, initial[y])` on the teardown
side, so it cancels. `trace::advice_window_count(advice, h)` is how many of those windows the
supplied advice spans, and `trace::advice_word` is the one spelling of its layout — the
executor writes it, `guest_sdk::advice` reads it back and this builder commits it, so the
three cannot drift.

**The image column** `program::image_init_column(image, h)`: row `y` is
`image.initial_word(4y)`, `2^n` rows. `ProgramImage::initial_word(a)` assembles the word at `a`
**byte by byte** from file-backed segment bytes, zero wherever no segment has a file byte —
the one source `trace::log`'s initial value also calls, because a segment may start or its file
bytes may end inside a word.

`decode_program` refuses a program whose last file-backed byte lies at or above `4h`
(`ProgramError::ImageOutsideWindow`), counting segments with file bytes only. Otherwise
`.data` placed in window 1 would read as zero and not move the identity.

### 3.5 The verifier's window rules

Before the memory challenges, from the statement: the `VmConfig` has equal heights for
families 7, 8 and 14; `SHARD_COUNTS[INIT_TEARDOWN] = 1`; the window list's length is
`SHARD_COUNTS[ZERO_WINDOWS]`; the list is strictly increasing; every id is in `[1, N − 1]`.
`ZERO_WINDOWS` shard `i` is window `w_i`. Since S-IO, three rules more:

- families 12 and 13 are present at exactly `family::PUBLIC_WINDOW_HEIGHT`, and
  `SHARD_COUNTS[PUBLIC_INPUT] = SHARD_COUNTS[PUBLIC_OUTPUT] = 1`. **One shard each, whether
  or not the execution used them**: a count a prover could drop is a way to publish nothing
  while having published something, and a program that ignores public values publishes an
  empty input and an empty journal;
- `N + SHARD_COUNTS[ADVICE_WINDOWS] ≤ 2^30 / h`, the top of the address space. The advice
  windows need no list and no disjointness rule — they start where the `ZERO_WINDOWS` ids
  stop (§3.1) — so this is the whole of what is asked of them;
- `4h ≥ PUBLIC_OUTPUT_ORIGIN + PUBLIC_WINDOW_BYTES`, so both public windows lie inside RAM
  window 0, whose rows below `RAM_ORIGIN` are masked at every height. Every menu height but
  `2^8` satisfies it. Without it a `ZERO_WINDOWS` id could claim a public window and give a
  public word a second init row.

`program::check_memory_windows` is these rules; the height and presence half of them is
`verifier_core::window_height`, which `VmConfig::from_bytes` also calls, so a config that
breaks them never decodes.

---

## 4. The register and PC boundary

Registers and the pc have **no rows in any family**. Their initial and final tuples are
computed by the verifier, once per statement, whatever the shard counts.

### 4.1 The boundary scalars

The proof carries **64 scalars**, absorbed as one `MEMORY_BOUNDARY` message (§6), in this
order:

| positions | name | what |
| --- | --- | --- |
| 0–31 | `t_0 … t_31` | register `x_r`'s final timestamp: its last query's write ts, 0 if never queried |
| 32 | `t_pc` | the pc's final timestamp: the last cycle's pc write ts |
| 33–63 | `v_1 … v_31` | register `x_r`'s final value, `r = 1..31`: its last write, 0 if never queried |

Each `t` is below `2^38` and each `v` below `2^32`, and S16's decoder of `MEMORY_BOUNDARY`
refuses anything else (since S16, `PublicInputs::from_bytes` does, and `reduce_shard`'s step 10
re-checks the timestamps). Nothing decodes the message at S14: `BoundaryFinals` holds each `v` as
a `u32`, but each `t` as a `u64` that nothing checks against `2^38`. **Two final values are not
carried**: `x0`'s is the constant 0 and the pc's is
the constant `HALT_PC` (§5). `gkr_verify::BoundaryFinals` holds them as
`{ reg_ts: [u64; 32], pc_ts: u64, reg_values: [u32; 31] }`, `reg_values[i]` being `x_{i+1}`,
and `trace::build_boundary_finals(log)` fills it from the log's final state.

What the public statement reads from them: `v_10` is `a0` at exit, the exit status, and that
is all of it. S14's D3 convention would have put a guest-computed I/O digest's words in
`v_24 … v_31`; S-IO **withdrew** it, and no register carries a public value
(§10, `docs/spec/public-values.md`). `t_pc` is **not** a cycle count: nothing may read
`t_pc / 4` as the number of cycles proven.

### 4.2 The factors and the reconciliation

```text
W_b = ∏_{r=0}^{31} T(REG, r, 0, 0) · T(PC, 0, 0, entry_pc)
R_b = T(REG, 0, t_0, 0) · ∏_{r=1}^{31} T(REG, r, t_r, v_r) · T(PC, 0, t_pc, HALT_PC)
```

`entry_pc` comes from the verifying key, bound by program identity (§6).
`gkr_verify::boundary_factors` returns `(W_b, R_b)`, evaluating every tuple through `eval_gate`
on the same tuple gate the circuits use, and `gkr_verify::reconciles` is the check:

```text
∏ read roots · R_b  =  ∏ write roots · W_b   and   ∏ read roots · R_b ≠ 0
```

over every shard of every family in the statement, `INIT_TEARDOWN` and `ZERO_WINDOWS` included.

No timestamp relation is checked on the finals, and none is needed. Per address, the init
write is consumed once, every query consumes one write and produces one strictly later (the
gap), and the final read consumes one: the writes form one chain of strictly increasing
timestamps, and the final read can only balance against its highest.

That chain is over `Fr`, and that it cannot close on itself is a matter of counting. Each
matched step adds an integer in `[1, 2^38]`, one plus a gap, so a closed loop of `k` steps
needs `k·2^38 ≥ p`: more than `2^215` steps. A statement has fewer than `2^70` tuples: at most
`2^32` shards per family (a `u32` count), times `family::COUNT = 9` families, times `2^30`
rows (`MAX_TRACE_VARS`), times at most 16 leaves a row, plus the 66 boundary tuples. So no loop
closes, each address's writes form one path from its init at timestamp 0, and every timestamp
on that path is below `2^70·2^38 = 2^108 < p`: a canonical integer, so "strictly later" holds
as integers. Re-check this count if the shard-count width, `MAX_TRACE_VARS`, the family count,
the leaves per row or the gap width grows.

---

## 5. Halting

`constants::memory::HALT_PC = 1`. **The exit row writes `next_pc = HALT_PC`** instead of
`pc + 4` (`execution-trace.md` §6), and the verifier fixes the pc's final value to `HALT_PC`.

`HALT_PC` is odd, and every entry, fall-through, branch and jump target, and masked `jalr`
target is even; it is below `RAM_ORIGIN`, so no decoded-table row claims it. So a trace whose pc
ends at `HALT_PC` ended on an exit row. Without the sentinel every prefix of an execution
balances: a fib run that panics has 889 prefixes ending with `a0 = 0`.

What S16's constraints owe the sentinel: `jalr`'s bit-0 clear and every jump's and branch's
wrap bit booleanity-constrained; `is_exit` from `a7 = 93` on the system row kind, gated off
transfer rows; the system row's `next_pc = is_exit·HALT_PC + is_transfer·pc +
(1 − is_exit − is_transfer)·table_next_pc`; the decoded-table lookup on every live row
(`m_pc = 1`), transfer rows included, with every other mask coupled to it as §2.1 says; and
the exit row's `a0` write equal to its read.

**Status at S16.** The system row's share is done, for `EXIT` alone: every ecall row reads
`a7 = 93`, writes `a0` back, and writes `HALT_PC`; every other live row of the family writes
the decoded fall-through, with a boolean wrap its range check forces to 0
(`docs/spec/shard-proof.md` §8.4). `jalr`'s bit and the jumps' and branches' wraps are the
jump family's stage's, and `is_transfer` the I/O-binding stage's.

**Status at S17.** The jump family's share is done (`docs/spec/jump-branch-slt.md` §4.3,
§4.4): one boolean wrap on whichever sum `next_pc` is, a boolean dropped bit on a `jalr`
row, and — beyond this list — every `next_pc` the family writes range-checked **even**.
The dropped bit alone does not clear bit 0: a `jalr` whose `rs1 + imm` is 1 could keep it
and write `HALT_PC`, so the even check is what makes "every masked `jalr` target is even",
above, a constraint rather than an intention.

**Status at S18 and S19.** The remaining five families each carry a `next_pc` gate, and
every one of them is the degree-1 `next_pc − decoded_next_pc = 0`: none of the twelve shift
and bitwise kinds, the eight M kinds or the nineteen memory and atomic kinds computes a pc,
so none carries a wrap bit, a bound or an evenness check. S17's rule that a family
computing a pc keeps its `next_pc` even does not reach a family that copies one
(`docs/spec/shift-bitwise.md` §4.1, `docs/spec/memory-ops.md` §3.2). Since S19 every
registered family has its gate.

---

## 6. Binding

### 6.1 The statement (amends the master's absorb order)

```text
PROTOCOL_SUITE → PROTOCOL_VERSION → [SRS digest] → VM_CONFIG → SHARD_COUNTS
  → MEMORY_WINDOWS [w_1 … w_k]
  → program identity → public I/O digest
  → INIT_TEARDOWN's memory-column group → ZERO_WINDOWS's memory-column group
  → every other family's memory-column commitments
  → MEMORY_BOUNDARY [t_0 … t_31, t_pc, v_1 … v_31]
  → squeeze γ_M, α_addr, α_ts, α_val
```

`program::absorb_statement_descriptor` writes `VM_CONFIG`, `SHARD_COUNTS` and
`MEMORY_WINDOWS`. The list's length varies per execution exactly as the shard counts do. The
boundary message and the squeeze belong to S16's global transcript, which is
`docs/spec/shard-proof.md` §2: it frames each family's group with a `MEMORY_GROUP` message,
draws the four challenges under `MEMORY_CHALLENGE`, and ends on the global state digest
every shard seeds from.

Both new items must precede the squeeze. A window list chosen after the challenges is a union
over up to `2^127` lists at `h = 2^22` — void as a bound at `h ≤ 2^20`. A final value chosen
after them is solved outright: `v = (target − γ_M − 1 − α_addr·r − α_ts·t_r)/α_val` reconciles
any trace.

`[SRS digest]` is S16's `SRS_DIGEST` message, G2 of `docs/spec/shard-proof.md` §2, carrying
the digest of its §3. Since S17 that digest is taken over the packed generic table's three
commitments as well as the `SrsVerifier`, so that table, which identity does not bind, is
fixed before the squeeze too. The order above gains no message for it
(`docs/spec/jump-branch-slt.md` §6).

### 6.2 Program identity (amends S11's recipe)

A fresh sponge absorbs, in order:

1. `PROGRAM_IDENTITY`: the code version;
2. `VM_CONFIG`: the family ids ascending, their heights, `bytecode_size_words`;
3. `PROGRAM_ENTRY`: `entry_pc`, one scalar;
4. per family ascending, `COMMITMENT`: families 0–6 their table columns in lookup-tuple order;
   `INIT_TEARDOWN` `[cm(image column)]`; `ZERO_WINDOWS` `[]`;
5. one raw squeeze, the identity.

It binds the image's file-backed bytes inside window 0 and the entry pc, and nothing an
execution chooses: no shard count, no window list. Step 4's list is empty for every family
that has no setup column, which since S21 is every delegation family and since S-IO the three
new window families too — an `S` column is bound by identity, and one execution's public
values or advice have no business in every execution's identity
(`docs/spec/public-values.md` §4). Step 2 still lists the whole family set, so **adding a
family moves every program's identity**, and S-IO did. `program::setup_commitments` is step 4's
commitments (it needs the SRS); `program::identity_from_commitments` is the digest over them
(it does not), which is what a verifying-key loader recomputes.

Recomputing identity binds `cm(image column)`, not the column `INIT_TEARDOWN`'s proof reads.
So the verifying-key path also opens that shard's `S[0]` base claim against the
`cm(image column)` whose identity it recomputed, and refuses a mismatch (S16). Without the
opening, a statement over a different image, with a trace consistent with that image, is
accepted. Since S16 that opening is the shard's own batched opening: its commitment list
takes the verifying key's setup commitments for the `S` columns, so `S[0]` opens against
the very `cm(image column)` identity was recomputed over (`docs/spec/shard-proof.md` §5.2).

### 6.3 Tags

| tag | name | kind |
| --- | --- | --- |
| 30 | `MEMORY_WINDOWS` | scalars |
| 31 | `MEMORY_BOUNDARY` | scalars |
| 32 | `PROGRAM_ENTRY` | scalars |

S16 appends the challenge-kind tag its memory squeeze draws under: `MEMORY_CHALLENGE`, 37,
among seven (`docs/spec/transcript.md` §8).

---

## 7. Range obligations

A range obligation is the artifact's lookup element, shaped at S14 for every channel S15 adds:

```text
LookupExpr = (name, channel: u32, selector: PolyAddress, tuple: [GateDef])
```

`format_version` is 1. The rules `validate` adds, and the checker enforces a second time: the
channel is one of `constants::lookup_channel`; a range channel's tuple has exactly one
expression; every expression is `Linear` with literal coefficients over `M`, `W`, `S`, `V`;
the selector is an `M`, `W` or `S` column; names follow the artifact-wide rule.

| channel | name | bound |
| --- | --- | --- |
| 0 | `TIMESTAMP` | `[0, 2^19)` |
| 1 | `RANGE16` | `[0, 2^16)` |

An obligation **holds on a row** when its selector is 0 there, or its expression's canonical
integer is below the bound. `checker::violated_lookups` is that check, natively, per row; S15
discharges it with LogUp. Until then, a future read, an out-of-window access and a
self-balancing query are caught by the native evaluator only.

**The range convention**, S14 must-be-exact 4, frozen for every later family:

- A value `v < 2^32` is bounded by one witnessed column `h` and two obligations on `RANGE16`,
  `h` and `v − 2^16·h`, both with the row's mask as selector, and no gate.
- A result `r` of an exact expression `e` taken mod `2^32` carries a witnessed `wrap`, the
  enforcing gates `wrap − wrap·wrap = 0` and `e − r − 2^32·wrap = 0`, and `r` bounded as
  above. It is admissible only where `0 ≤ e < 2^33` as integers, so that one boolean wrap
  holds every carry. A wider wrap, such as a multiply's high word, is not frozen here.
- The timestamp gap of §2.4 is the same shape on `TIMESTAMP`, with no wrap.

No S14 artifact uses `RANGE16`.

---

## 8. Construction-time rules

`constraints::memory::check_memory(artifact)` runs where a memory artifact is built, beside
`validate`, and refuses, naming the gate:

- **provenance**: any gate, and any output, whose cone both names a global memory slot (1–5)
  and reads a `W` column. It is computed forward, one pair of flags per column, so a product of
  a tuple with a copy of a `W` column two layers up is refused too;
- **a root that reads a `W` column**: `outputs[READ_ROOT]` or `outputs[WRITE_ROOT]` whose cone
  reads one, whether or not it names a slot. `W` is committed after the memory challenges
  (§6.1), so a root over it is chosen after them and balances any trace. Provenance, which
  needs a slot as well, does not see a root built from `W` columns alone. Neither root's cone
  reads a `W` column;
- **a global slot over anything but `M`, `S` and `V`** — where `S` is admitted only because a
  setup column is bound before the challenges: by identity, or, for the packed generic
  table's columns since S17, by the SRS digest (§6.1). A gate with a global-slot
  coefficient reads no `W` column, no inner column and no cached entry;
- **unconstrained masks**: a leaf's mask that is a committed column — `M`, `W` or `S` — with
  no enforcing gate `m − m·m` in gate list 0, or that is any virtual column but `V[ram_live]`,
  the one virtual that is 0 or 1 on the cube (`V[row]` is not). A leaf is a producing
  `Quadratic` of gate list 0 with constant 1, and its mask the operand of each of its linear
  terms weighted by a global slot. A `W` mask is refused by provenance first.

The window artifacts' read sets are pinned by test: `ZERO_WINDOWS` reads `M[0], M[1], V[row]`;
`INIT_TEARDOWN` reads those and `S[0]`, `V[ram_live]`. `value_window_artifact` (§3.3) reads
`M[0], M[1], M[2], V[row]` and is admitted by the same rules: `M[2]` is a memory column, so a
global slot may weight it, and no root's cone reaches a `W` column because the artifact has
none. `crates/checker/tests/memory.rs` runs the laws, the padding contract and
`check_memory` over all three.

The padding contract gains its product-tree clause (`docs/spec/gkr.md` §4.3): for a family
whose shards have inactive rows, every column the first halving list reads is 1 at
`padding.row`, for every challenge value and row index. `checker::check_padding_identity` holds
an artifact to it.

---

## 9. What the argument rests on

**Sequential consistency** of every address needs exactly one init tuple per address: disjoint
windows, strictly increasing ids, id ≥ 1 for `ZERO_WINDOWS`, exactly one `INIT_TEARDOWN` shard,
equal heights, the boundary counted once — and the gap obligation on every read, over §4.2's
count.

**Coverage**: an accessed address with no init row cannot balance, because its read timestamps
would equal its write timestamps as multisets while each write is strictly later than its
read. This, too, needs the gap obligation.

**The RAM-window bound** is that an address **no family initializes** has no init row, and
since S-IO the initialized regions are not one contiguous span. Below `RAM_ORIGIN` the masked
span holds the two public windows, each claimed by a family of its own at `2^8`, and the rest
of it — `[0, 0x8000)` and `[0x8800, RAM_ORIGIN)` — is a hole. At `2^31` and above is the
advice region, claimed by the `k_a` consecutive `ADVICE_WINDOWS` shards the statement counts
and by nothing past them. The bound rests on the `V[ram_live]` mask, `1 ≤ id ≤ N − 1` for
`ZERO_WINDOWS`, `N + k_a ≤ 2^30 / h` for the advice windows, the pinned public window height
with §3.5's `4h` rule under it, and the gap obligation. A zero window at id 0 has no mask, so
its rows would give the words below `RAM_ORIGIN` init rows
(`crates/checker/tests/multiset.rs`, control C1); the `4h` rule is what keeps a zero window
with id ≥ 1 off a public one.

**That the initial values are the program's** rests on something else: the image refusal of
§3.4, which keeps every file-backed byte inside window 0's column, and the opening of `S[0]`
against identity's `cm(image column)` (§6.2).

**Owed by later stages**: S15 discharges the obligations. S16 owes:

- the **frame superset rule** of §2.1: a family's frame holds every query its instructions
  make. A query it lacks is an instruction S16 has no `write_value` column to constrain,
  which is the one way a narrowed frame could cost soundness rather than completeness;
  `crates/trace/tests/memory.rs` holds `frame_queries` equal to that union over all 59
  instructions, so a family gaining an instruction whose queries it does not carry fails
  there;
- every mask constrained as §2.1 says: `m_pc` the row's liveness and the table lookup's
  selector, and `m_q = m_pc·uses_q`;
- each access's byte address: `low ∈ [0, 3]`, `low = 0` for `lw`/`sw`, `low ∈ {0, 2}` for
  `lh`/`sh`, a boolean wrap on `rs1 + imm`;
- the sentinel's constraints of §5;
- the global transcript of §6.1, including decoding `MEMORY_BOUNDARY` and refusing any
  `t ≥ 2^38` or `v ≥ 2^32`;
- the verifying key's identity recomputation, and the opening of `INIT_TEARDOWN`'s `S[0]`
  against `cm(image column)`;
- the zero-root refusal.

**Status at S16.** Discharged: the frame superset rule, which the add/sub family's frame meets
— seven queries then, eight since S21; the masks and the sentinel for that family (§2.1, §5); the global
transcript and the boundary decoder; the key's identity recomputation and the opening of
`S[0]`; and the zero-root refusal, which is `reconciles`' nonzero half and which step 10 of
`verify_shard` runs. Still owed at S16: the masks and the sentinel for every other family,
at each family's stage, and each access's byte address, at the memory families' stage —
both discharged by S19, below.

**Status at S17.** Discharged: the masks and the sentinel for `JUMP_BRANCH_SLT` (§2.1, §5).

**Status at S18.** Discharged: the masks and the sentinel for `SHIFT_BITWISE` and
`MUL_DIV`, each of which copies the decoded fall-through rather than computing a pc.

**Status at S19.** Discharged: the masks and the sentinel for `MEM_WORD`, `MEM_SUBWORD`
and `ATOMICS`, and **each access's byte address** — the last item on the list above, and
the one the memory families' stage owed. It is not the `low ∈ [0, 3]` shape that line
describes: the split is `addr = 4·word_index + 2·bit1 + bit0`, which is an alignment
statement over ℤ and nothing over `Fr`, and it is the range check on `word_index` that
makes it base-4. `MEM_WORD` carries no offset bits at all, so a misaligned `lw` or `sw` has
no witness; `half_aligned` clears bit 0 at halfword width; and `ATOMICS` derives
`rs1 < 2^32` from `rs1 = 4·word_index` rather than assuming it.
`docs/spec/memory-ops.md` §2 is that section, and with it **every item this list owed is
discharged** but the I/O-binding stage's transfer rows.

S20 reconciles every shard.

**Status at S21, unchanged at S23.** The delegation families ride this argument and add
nothing to it. An
invocation's frame accesses are ordinary `(RAM, base + 4j)` tuples with ordinary gap bounds,
and its anchor pair lives in an address space of its own, above RAM's, whose only writer is an
invocation of that family and whose only reader is a request's `deleg` query. With three
families registered, one `deleg` query serves them all and the requested *type* rides the
frame's `deleg_space` column, which the requesting family pins to its type selectors
(`docs/spec/delegation.md` §5.1): the leaf still reads only `M` columns, which is what §8's
provenance rule asks of it. So a delegation shard's two roots
enter `reconciles`' product exactly as a CPU shard's do, the boundary factors are unchanged, and
**no new global rule exists**: what makes a request and an invocation pair 1:1 is a timestamp-0
tuple that no cycle can write and three gates that pin the read side
(`docs/spec/delegation.md` §5.3). The one thing scoped away from delegation families is the
block's ts-window disjointness, which is per **cycle-owning** family and always was
(`docs/spec/block-proof.md` §4).

**Status at S-IO.** The **I/O-binding** item this list has carried since S14 is
**discharged**, and `docs/spec/public-values.md` is normative for it. It needed no gate and no
new rule here: the statement's public input and its journal are two RAM windows in the hole
below `RAM_ORIGIN`, so §4.2's first-and-last-value rule is the multiset half of the binding
and one comparison at each shard's own opening point is the other
(`docs/spec/shard-proof.md` §6, step 10c). The **transfer rows** the same item carried are
**withdrawn rather than discharged**, and S14's open question 10 — how a transfer row's RAM
write is confined to its ecall's buffer — is moot: a public value does not travel through a
syscall, `read` and `write` are not provable ecalls and will not be
(`docs/spec/public-values.md` §1), and `prover::fill::add_sub` refuses a transfer cycle by
name, so no execution a proof covers holds one. `docs/spec/execution-trace.md` §6 still
describes them, because the executor still answers both calls. Three window families were
added; the tuple, the frame, the boundary and the reconciliation are unmoved. **Every item
this list owed is now discharged or withdrawn.**

**Cost** at `h = 2^22`: at least two `h`-sized window shards per proof (window 0 and the
stack window), `2^23` leaf pairs and four committed `2^22`-entry columns, even for fib's
2,117 cycles; each further touched 16 MiB window adds `2^22` rows; at most `2^29`. S14's
tests run at `h = 2^16`. Since S-IO, two `2^8` shards more in every proof — the two public
families, 5 committed columns of 256 rows between them — and one `h`-sized shard per advice
window the prover supplies.

---

## 10. Binding I/O, landed at S-IO

**`docs/spec/public-values.md` is normative**, and it supersedes what this section used to
describe.

The statement's `input` and `output` are bound to the execution by two RAM window families of
their own, `PUBLIC_INPUT` and `PUBLIC_OUTPUT` (§3.2). What fixes the two byte strings is
`io_digest(input, output)`, absorbed at G7 before any memory column is committed and long
before the challenges are squeezed (§6.1, unchanged). What ties them to the *execution* is
§4.2 plus one comparison: the multiset forces a window's init column to be each address's
first value and its teardown column to be its last, and `verify_shard_local` step 10c holds
`PUBLIC_INPUT`'s init column and `PUBLIC_OUTPUT`'s teardown column to the verifier's own
multilinear extension of those bytes.

The design this section carried until S-IO — the guest computing `io_digest` and leaving its
words in `x24 … x31` at exit — is **withdrawn**: it rested the output's soundness on the guest
hashing honestly, and a guest that panicked published nothing.
