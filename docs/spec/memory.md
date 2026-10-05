# The memory argument

Offline memory checking over a whole statement. Each shard's circuit outputs the product of its
read tuples and of its write tuples; the verifier checks, once per statement, that all reads
times the register and pc finals equal all writes times their initial values. RAM is initialized
by window families over fixed address windows; registers and the pc have no rows. The section
numbers are the ones the code cites.

## 1. The tuple

```text
T(AS, ADDR, TS, VAL) = γ_M + AS + α_addr·ADDR + α_ts·TS + α_val·VAL
```

The parts are in the order of `constants::memory::{PART_AS, PART_ADDR, PART_TS, PART_VAL}`.
`AS`, an address-space tag ([execution-trace.md](execution-trace.md) §2), is unweighted; a RAM
address is a 4-aligned word's byte address. `γ_M, α_addr, α_ts, α_val` are
`constants::challenge_slot` slots 1–4, `MEM_GAMMA` to `MEM_ALPHA_VAL`, drawn once per statement
after everything §6.1 lists; slot 5, `MEM_WINDOW_CONSTANT`, is derived per window shard by the
verifier and never read from a proof (§3.3). A gate coefficient is one literal or one slot
([gkr.md](gkr.md) §3), so `α_ts·4·cycle` is the term `(α_ts, cycle)` four times.

Every memory artifact outputs its read product at `outputs[READ_ROOT = 0]` and its write product
at `outputs[WRITE_ROOT = 1]` (`constants::memory`), before any channel's roots
([lookup.md](lookup.md) §6). All tuples of a statement form one multiset, over `REG`, `RAM` and
`PC`, one anchor space per delegation type, where a request meets its invocation
([delegation.md](delegation.md) §5), and the recursion format's `FIELD` cells
([recursion.md](recursion.md) §2.1).

## 2. An execution family's memory subtree

### 2.1 The frame columns

A row of an execution family is one cycle; its accesses are **queries**, each a read and a write
at one address, the write at `4·cycle + Δ` ([execution-trace.md](execution-trace.md) §1). The
query table is `constraints::memory::{FRAME_NAMES, FRAME_SPACE, FRAME_DELTA}`:

| id | query | space | `Δ` | |
| --- | --- | --- | --- | --- |
| 0 | `pc` | `PC` | 0 | address 0; reads `pc`, writes `next_pc` |
| 1 | `rs1` | `REG` | 1 | read-only; an ecall's `a7` |
| 2 | `rs2` | `REG` | 2 | read-only; an ecall's `a0` |
| 3 | `load` | `RAM` | 2 | read-only; a load's word |
| 4 | `ram` | `RAM` | 3 | a store's or an atomic's word |
| 5 | `rd` | `REG` | 3 | the x0 rule (§2.4) |
| 6 | `deleg` | the row's | 3 | a delegation request's mirror ([delegation.md](delegation.md) §5) |

A family's **frame** is exactly the queries its instructions make
([execution-trace.md](execution-trace.md) §4), in table order: `constraints::memory::frame_queries`,
which `crates/trace/tests/memory.rs` holds to the union over all 59 instructions. A missing query
would leave an instruction's written value unconstrained. No instruction routed to
`ADD_SUB_LUI_AUIPC` touches RAM, and `ATOMICS` keeps every RAM access at `Δ = 3`, `lr.w`
included. Window and delegation families have no frame (§3.3;
[delegation-circuits.md](delegation-circuits.md) §1).

| family | queries, in slot order | `w` | leaves a side |
| --- | --- | --- | --- |
| `ADD_SUB_LUI_AUIPC` | `pc rs1 rs2 rd deleg` | 5 | 8 |
| `JUMP_BRANCH_SLT`, `SHIFT_BITWISE`, `MUL_DIV` | `pc rs1 rs2 rd` | 4 | 4 |
| `MEM_WORD`, `MEM_SUBWORD` | `pc rs1 rs2 load ram rd` | 6 | 8 |
| `ATOMICS` | `pc rs1 rs2 ram rd` | 5 | 8 |

Columns are addressed by **slot** `s`, a query's position in its family's list:

```text
M[0]                  cycle
M[1 + 5s + f]         slot s's <q>_mask, <q>_addr, <q>_read_ts, <q>_read_value, <q>_write_value
M[1 + 5w]             deleg_space, in the one frame holding deleg
W[s]                  <q>_gap_hi, for s < w
W[w], W[w+1], W[w+2]  rd_inv, rd_is_zero, rd_selected
```

That is `1 + 5w` `M` columns, plus `deleg_space`, and `w + 3` `W` columns, the family's own
following ([circuits.md](circuits.md) §2). One `deleg` query serves every delegation type, so its
space is the value of `deleg_space`, an `M` column the family pins to its type selectors: a leaf
may read no `W` column (§8). The honest fill (`trace::build_memory_columns`,
`trace::build_frame_witness`, over a shard's `trace::RowSlice`) sets a mask to 1 where the row is
live and has the query, and every column of an absent query or a padding row to 0.

**A frame holds a mask only to booleanity**, so on the frame alone a padding row's `rd` query
could rewrite `x10`, the exit status, after the exit row, and a live row could drop a query or
carry one its instruction lacks. Every execution family makes `m_pc` the row's liveness and its
decoder lookup's selector ([lookup.md](lookup.md) §10), and holds each other mask to
`m_q = m_pc·uses_q` (its `<q>_mask_rule` gates), `uses_q` the sum of the row's kind and
ecall-type selectors that make the query.

### 2.2 The leaves

For the query at slot `s` with mask `m`, space `AS` and in-cycle slot `Δ`:

```text
read_<q>    m·T(AS, addr, read_ts, read_value) + 1 − m
write_<q>   m·T(AS, addr, 4·cycle + Δ, write_value) + 1 − m
```

Each is one flat `Quadratic` of gate list 0, built from the unmasked tuple, a `Linear` whose `AS`
and `Δ` terms sit on `m` (`constraints::memory::read_tuple` is the read one): constant 1;
linear terms `(γ_M, m)`, `(−1, m)`, `(AS, m)` and, on the write side, `(α_ts, m)` `Δ` times;
every other term multiplied by `m`, as is `deleg`'s `AS`, the product `(1, deleg_space, m)`. At
`m = 0` a leaf is 1 whatever its columns hold, at `m = 1` the tuple, and it is one or the other
only at a boolean `m` (§2.4).

### 2.3 The product

Each side is padded to `w` rounded up to a power of two with `read_pad_<i>` and `write_pad_<i>`,
the literal 1, reading no column. Row-wise `Product` lists reduce each side to one value a row,
and `trace_vars` halving lists of `TreeProduct` multiply the rows ([gkr.md](gkr.md) §1), so the
two roots are the products of the shard's read and write tuples. A padding row has every mask 0
and so every leaf 1, the padding contract's product-tree clause ([gkr.md](gkr.md) §4). The
family's channel trees share the layers ([circuits.md](circuits.md) §2).

### 2.4 The gadgets every execution family carries

Gate list 0's first enforcing gates, in this order, and the circuit's first `2w` obligations:

```text
<q>_mask_boolean       m − m·m = 0                       every query
<q>_writes_back        write_value − read_value = 0      rs1, rs2 and load, where held
rd_is_zero_inverse     addr·rd_inv + z − m = 0           on rd; z = rd_is_zero
rd_is_zero_at_nonzero  addr·z = 0
rd_is_zero_boolean     z − z·z = 0
rd_write_masked        write_value − sel + z·sel = 0     sel = rd_selected

gap_hi_<q>   TIMESTAMP, selector m:   hi                                   hi = <q>_gap_hi
gap_lo_<q>   TIMESTAMP, selector m:   4·cycle + δ_q − read_ts − 2^19·hi        δ_q = Δ − 1; δ_pc = −4
```

- **Booleanity.** At `m = −1` a `pc` query's leaves are each `−T(REG, …)`: one sign flip a
  side, so the products balance and the pc access reads as a register access.
- **Write-back.** Without it a read of `x0` could write 5 there.
- **x0.** The first two `rd` gates (`constraints::gadgets::is_zero`) make `z = m·[addr = 0]`
  and the last `write_value = (1 − z)·sel`: every write to `x0` writes 0, whatever the family
  computed into `sel`, and with write-backs and `x0`'s init 0 every read of it returns 0. The
  boundary's final `x0 = 0` (§4.1) pins only its last write: a write of 5, a read of 5 and a
  write of 0 would otherwise balance.
- **Gap.** Both chunks below `2^19` put `gap = 4·cycle + δ_q − read_ts` in `[0, 2^38)`, so
  `read_ts < 4·cycle + Δ` as integers, every timestamp being a canonical integer by §4.2's
  count. The pc query's `δ = −4` puts a row's pc write at least 4 after the one it reads, so
  consecutive rows' timestamps never interleave (§9). The frame's construction asserts two
  obligations per query.

## 3. RAM windows

### 3.1 Geometry

Window `w` at height `h = 2^n` covers the bytes `[4h·w, 4h·(w + 1))`, its row `y` being the word
at `4h·w + 4y`; the windows tile `[0, 2^32)` from 0. Ordinary RAM is
`[RAM_ORIGIN, ADVICE_ORIGIN) = [2^16, 2^31)` (`trace::in_ram`), ending where window
`N = 2^29/h` begins (`verifier_core::advice_first_window`). Window 0's rows `y < 2^14`
(`constants::memory::RAM_LIVE_BIT`) lie below `RAM_ORIGIN` at every height, and `INIT_TEARDOWN`
masks them (§3.3).

### 3.2 The window families

A window family's shard initializes and tears down one window; its rows are addresses.

| region | family | id | windows | init value |
| --- | --- | --- | --- | --- |
| `[0, 0x8000)` | none: a hole | | | |
| `[0x8000, 0x10000)` | `PUBLIC_INPUT`, `PUBLIC_OUTPUT` | 12, 13 | 2 and 3 at their pinned `2^12` | the statement's input; 0 ([public-values.md](public-values.md) §4) |
| `[RAM_ORIGIN, 4h)` | `INIT_TEARDOWN` | 7 | 0, one shard | `S[0]`, the image column |
| `[4h, 2^31)` | `ZERO_WINDOWS` | 8 | the listed `w_1 < … < w_k` in `[1, N − 1]` | 0 |
| `[2^31, 2^32)` | `ADVICE_WINDOWS` | 14 | `N … N + k_a − 1` | `M[2]`, bound to nothing ([public-values.md](public-values.md) §6) |
| `FIELD` cells | `FIELD_WINDOWS` | 18 | `0 … k_f − 1` | 0 ([recursion.md](recursion.md) §2.2) |

`INIT_TEARDOWN`, `ZERO_WINDOWS` and `ADVICE_WINDOWS` share the window height `h`, `2^22` by
default (§3.5). An unlisted RAM window is initialized by nothing. Every statement proves window 0
and, in practice, the stack's window `N − 1`, the initial `sp` being `ADVICE_ORIGIN`: two `h`-row
shards however small the program, besides the public pair.

### 3.3 The artifacts

```text
INIT_TEARDOWN   image_window_artifact   M[0] teardown_ts, M[1] teardown_value, S[0] init_value
  read    live·(WC + α_addr·4·row + α_ts·M[0] + α_val·M[1]) + 1 − live     live = V[ram_live]
  write   live·(WC + α_addr·4·row + α_val·S[0]) + 1 − live
ZERO_WINDOWS, PUBLIC_OUTPUT    zero_window_artifact     M[0], M[1]
  read    WC + α_addr·4·row + α_ts·M[0] + α_val·M[1]        write   WC + α_addr·4·row
PUBLIC_INPUT, ADVICE_WINDOWS   value_window_artifact    M[0], M[1], M[2] init_value
  read    as above                                          write   WC + α_addr·4·row + α_val·M[2]
FIELD_WINDOWS   field_window_artifact: zero_window_artifact over α_addr·row, one cell a row
```

All are `constraints::memory` constructors: one leaf a side, then `n` halving lists; no witness
column, enforcing gate or lookup; every init timestamp the literal 0; `row` is `V[row]`.
`V[ram_live]` is `[y ≥ 2^14]`, boolean on the cube by construction ([gkr.md](gkr.md) §2). The
window enters only through `WC`, so one artifact serves every window:

```text
WC = γ_M + RAM + α_addr·4h·w        gkr_verify::window_challenges
WC = γ_M + FIELD + α_addr·h·w       gkr_verify::field_window_challenges
```

`w` is `verifier_core::shard_window`'s: 0 for `INIT_TEARDOWN`, the list's `i`-th id for
`ZERO_WINDOWS` shard `i`, 2 and 3 for the public pair, `N + i` for advice shard `i`, `i` for field
shard `i`. An init column is `S` where program identity binds it and `M` where it is one
execution's, committed before the challenges (§6.1). A window shard has no inactive rows.

### 3.4 The columns a prover fills

`trace::init_windows(state, h)` is `ZERO_WINDOWS`' list: the distinct `⌊a/4h⌋` over touched
words `a` of ordinary RAM, ascending, without 0. A public or advice word is a `RAM` tuple too,
and a zero window over it would be its second init row. `trace::build_init_teardown_columns`
fills `INIT_TEARDOWN` and `ZERO_WINDOWS`, and `trace::build_value_window_columns` the value
windows with their `M[2]`, from the last-access tables (`trace::MemoryState`):

| row `y`, `a = 4h·w + 4y` | `teardown_ts` | `teardown_value` |
| --- | --- | --- |
| `w = 0`, `y < 2^14` (masked) | 0 | 0 |
| `a` touched | its last write's timestamp | its last write's value |
| `a` untouched | 0 | its init value |

An untouched row's two tuples are equal and cancel. The image column,
`program::image_init_column(image, h)`, has row `y` = `ProgramImage::initial_word(4y)`: the word
assembled byte by byte from file-backed bytes, 0 elsewhere, which is the trace's initial RAM value
too. `decode_program` refuses an image with a file-backed byte at or above `4h`
(`ProgramError::ImageOutsideWindow`): it would sit in a zero window, read as 0, bound by nothing.

### 3.5 The verifier's window rules

`verifier_core::check_memory_windows`, step 2 of `derive_global_phase`, before the global
transcript (`program::check_memory_windows` wraps it):

| rule | why |
| --- | --- |
| `INIT_TEARDOWN`, `ZERO_WINDOWS`, `ADVICE_WINDOWS` at one height `h` | a lower zero-window height would re-initialize image words; an advice height of its own is a grid `advice_first_window(h)` does not describe |
| `PUBLIC_INPUT`, `PUBLIC_OUTPUT` at `PUBLIC_WINDOW_HEIGHT = 2^12` | the height places their windows ([public-values.md](public-values.md) §2) |
| `4h ≥ PUBLIC_OUTPUT_ORIGIN + PUBLIC_WINDOW_BYTES = 0x10000`: `h ≥ 2^16` on the menu | the public windows lie in window 0's masked rows, out of every zero window's reach |
| one shard each of `INIT_TEARDOWN`, `PUBLIC_INPUT`, `PUBLIC_OUTPUT` | ([public-values.md](public-values.md) §4 for the pair) |
| one id per `ZERO_WINDOWS` shard, strictly increasing, in `[1, N − 1]` | disjoint windows; id 0 is unmasked over `[0, RAM_ORIGIN)`; `N` up is advice |
| `N + k_a ≤ 2^30/h`, `k_a` the advice shard count | advice ends by `2^32`; it needs no list, starting where the zero ids stop |
| `k_f·h ≤ 2^32` field cells | [recursion.md](recursion.md) §2.2 |

The first three are `verifier_core::window_height`, which `VmConfig::from_bytes` runs too: a
config breaking them does not decode.

## 4. The register and pc boundary

Registers and the pc have no rows: the verifier multiplies in their initial and final tuples,
once per statement. Rows for them would repeat the init tuples in every shard holding them, and a
stale read would balance against the copy.

### 4.1 The boundary scalars

The statement carries 64 scalars, `gkr_verify::BoundaryFinals`, absorbed as one `MEMORY_BOUNDARY`
message in this order (`verifier_core::boundary_scalars`):

| positions | | |
| --- | --- | --- |
| 0–31 | `t_0 … t_31` | `x_r`'s final timestamp: its last query's write, 0 if never queried |
| 32 | `t_pc` | the pc's: the exit row's pc write |
| 33–63 | `v_1 … v_31` | `x_r`'s final value, 0 if never queried |

The final values of `x0`, 0, and of the pc, `HALT_PC`, are constants, not carried.
`PublicInputs::from_bytes` refuses `t ≥ 2^38` or `v ≥ 2^32`, and `verify_global_memory`
re-checks the timestamps and holds `v_10` to the exit status; no other register carries a public
value. `t_pc` is not a cycle count: the pc's timestamps increase but need not be consecutive.
`trace::build_boundary_finals(state)` is the fill.

### 4.2 The factors and the reconciliation

```text
W_b = ∏_{r=0}^{31} T(REG, r, 0, 0) · T(PC, 0, 0, entry_pc)
R_b = T(REG, 0, t_0, 0) · ∏_{r=1}^{31} T(REG, r, t_r, v_r) · T(PC, 0, t_pc, HALT_PC)

∏ read roots · R_b  =  ∏ write roots · W_b  ≠  0       over every shard of the statement
```

`entry_pc` is the verifying key's (§6.2). `gkr_verify::boundary_factors` evaluates each tuple
through `gkr_verify::eval_gate` on the circuits' own tuple gate, `read_tuple` of `pc` or `rs1`,
so the boundary and the circuits cannot disagree on the parts; `gkr_verify::reconciles` is the
equation, which `verifier_core::verify_global_memory` runs once per statement
([proof.md](proof.md) §6). A shard's roots are its GKR outputs, held to the statement's entry by
its own verification.

**The count.** Read each query as an edge from its read tuple to its write tuple. Inits are only
written and finals only read, so a balanced multiset is paths from inits to finals plus loops. An
edge advances the timestamp by an integer in `[1, 2^38]` (the gap), so a loop needs more than
`p/2^38 > 2^215` edges, and a statement has fewer than `2^67` tuples: under `2^32` shards a
family (a `u32` count), 23 families, at most `2^22` rows (the menu's top), at most 196 tuples a
row (`EC_ADD`'s 97 frame words and its anchor, both sides), and 66 boundary tuples. So nothing
loops: every path starts at an init at timestamp 0 and ends at a final, and every timestamp on it
is an integer below `2^105`.

## 5. Halting

`constants::memory::HALT_PC = 1`. The exit row, `ecall` with `a7 = 93`, writes
`next_pc = HALT_PC` instead of its fall-through ([execution-trace.md](execution-trace.md) §6),
and `R_b` fixes the pc's final value to it. Nothing else writes it: `HALT_PC` is odd, every other
`next_pc` even, and "odd" is a constraint only where a family makes it one.

- A family copying the decoded fall-through, which is even, holds `next_pc − decoded_next_pc = 0`
  and needs no bound.
- `JUMP_BRANCH_SLT`, the one family computing a pc, range-checks every `next_pc` it writes even;
  otherwise a `jalr` whose `rs1 + imm` is 1 could write `HALT_PC`
  ([jump-branch-slt.md](jump-branch-slt.md)).
- `ADD_SUB_LUI_AUIPC` writes `HALT_PC` on its exit row alone ([add-sub.md](add-sub.md)).

`HALT_PC` is below `RAM_ORIGIN`, so no decoded-table row claims it and no live row reads it
([lookup.md](lookup.md) §10). The pc's path therefore ends with the exit row's write, consumed by
the final read. With a free final pc every prefix of an execution would balance.

## 6. Binding

### 6.1 What precedes the memory challenges

The four challenges are squeezed once per statement, at the end of the global transcript
([proof.md](proof.md) §2 is the schedule), after everything a tuple or the reconciliation reads,
because what is chosen after them can be solved for:

- every shard's `M` commitments, every column a leaf may read but `S` and `V` (§8);
- program identity, fixing `entry_pc` and the image column (§6.2), and the SRS digest, fixing the
  generic table's `S` columns ([proof.md](proof.md) §3);
- the shard counts and `MEMORY_WINDOWS`, the zero-window ids, fixing every window shard's
  addresses through `WC`: a list chosen afterwards is a union over up to `2^(N − 1)` lists,
  `2^127` at `h = 2^22` and no bound at all at `2^20`;
- `io_digest`, fixing the public windows' contents ([public-values.md](public-values.md) §5);
- last, the 64 boundary scalars: a final value chosen afterwards reconciles any trace,
  `v_r = (target − γ_M − REG − α_addr·r − α_ts·t_r)/α_val`.

The roots are not absorbed: each shard's GKR proof binds its own.

### 6.2 The image column and the entry pc

Program identity ([program.md](program.md) §8 is the recipe) binds `INIT_TEARDOWN`'s one setup
commitment, the image column's, and `entry_pc`, under `PROGRAM_ENTRY`. Recomputing identity binds
a commitment, not the column a proof reads; the `INIT_TEARDOWN` shard's batched opening closes
that by taking `S[0]`'s commitment from the verifying key, the list identity is recomputed over
([proof.md](proof.md) §5, §7). Without it a statement over another image, with a trace
consistent with that image, would verify. Without `entry_pc` in identity, a key carrying the
registered identity beside another entry pc would verify an execution starting elsewhere.
Identity binds nothing an execution chooses: no shard count, window list, public or advice word.

## 7. Range obligations

A range obligation holds where its selector is 0 or its one expression is below its channel's
bound ([lookup.md](lookup.md) §1, §3). Every circuit bounds a value one way:

- a **32-bit value** `v`: a witnessed high halfword `h` and `RANGE16` obligations on `h` and on
  `v − 2^16·h`, under the row's selector, and no gate;
- a **result** `r = e mod 2^32` of an exact `0 ≤ e < 2^33`: a witnessed `wrap`, the gates
  `wrap − wrap·wrap = 0` and `e − r − 2^32·wrap = 0`, and `r` bounded as above; a wider carry is
  a family's own construction;
- a **timestamp gap**: two 19-bit `TIMESTAMP` chunks, no wrap (§2.4). Delegation and recursion
  families decompose theirs their own way ([delegation-circuits.md](delegation-circuits.md) §1).

## 8. Construction-time rules

`constraints::memory::check_memory` refuses, naming the gate, a memory artifact with:

1. **provenance**: a gate or output whose cone both names a memory slot (1–5) and reads a `W`
   column, computed forward with two flags a column, so a tuple times a copy of a `W` column two
   layers up is refused too;
2. **a root over `W`**: `outputs[READ_ROOT]` or `outputs[WRITE_ROOT]` whose cone reads a `W`
   column at all, slot or not, which rule 1 does not see;
3. **a memory slot over anything but `M`, `S` and `V`**: a gate carrying one reads no `W`, inner
   or cached column;
4. **an unconstrained mask**: a leaf — a producing `Quadratic` of gate list 0 with constant 1 and
   a slot-weighted linear term — whose mask, that term's operand, is an `M`, `W` or `S` column
   with no `m − m·m` enforcing gate in gate list 0, or a virtual column but `V[ram_live]`.

It runs beside `CircuitArtifact::validate`, whose laws it assumes, wherever a memory artifact is
built (`constraints::memory`'s assembly panics on a refusal) and in `VerifyingKey::check`. A `W`
column is committed in a shard's own transcript, after the memory challenges, so a tuple or root
over one is chosen after them and balances any trace. `M` columns precede the challenges and `V`
columns are closed forms; `S` columns are admitted because they precede them too, bound by
identity or, for the generic table, by the SRS digest (§6.1).

## 9. What the argument rests on

Both sides of §4.2 are products of linear forms in `(γ_M, α_addr, α_ts, α_val)`, one per distinct
tuple, every tuple fixed before those are drawn (§6.1, §8). By Schwartz–Zippel they agree on
unequal multisets with probability at most `N/p`, `N < 2^67` (§4.2), and on equal ones §4.2's
count gives:

- **One init per address** of `REG`, `PC`, `RAM` and `FIELD`: the 33 boundary inits once per
  statement, and §3.5's windows, disjoint and of one height. A second init would let a stale read
  balance. An anchor space has no init: each invocation's answer, stamped 0, starts a path one
  request long ([delegation.md](delegation.md) §5).
- **Coverage.** Every query lies on a path from an init, so nothing reaches an address no family
  initializes: the hole `[0, 0x8000)`, where a null dereference does not balance, an unlisted
  window, a register above `x31`, a pc address but 0. A query reading its own write would balance
  with no init; the gap forbids it.
- **Consistency per address**: on its one path every read returns the write before it, and the
  final tuple holds the last.
- **Initial values**: the image's, by §3.4's refusal and §6.2's opening of `S[0]`; 0 in every
  zero window and the journal; the statement's input in its window
  ([public-values.md](public-values.md) §5). Advice is bound to nothing by design
  ([public-values.md](public-values.md) §6).
- **Order across rows, shards and families.** The pc's path runs from `T(PC, 0, 0, entry_pc)`
  through every live row of every execution family, each `m_pc = 1` row one edge, to the exit
  row (§5). That is pc continuity; it orders the rows by their pc writes `4·cycle`, which are
  therefore distinct, so no cycle is proved twice. Nothing else carries it: there is no per-shard
  pc chaining, and a shard's time window ties to no row ([proof.md](proof.md) §8).

Per address, the order is timestamp order, and it is program order: the pc query's gap puts
consecutive pc writes at least 4 apart (§2.4), so each cycle's four timestamps precede the next
cycle's whatever value `cycle` takes, and a row never reads an address before its predecessor's
write there. An invocation rides its requesting row's cycle ([delegation.md](delegation.md) §5)
and is ordered with it.
