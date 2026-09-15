# The memory argument: tuples, RAM windows, the register and PC boundary

Frozen as of S14. Changing anything here is a protocol-version change.

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
`trace::build_memory_columns`. A row is one cycle. Eight queries per row: query 0 is the pc
query, queries 1–7 are the roles of `execution-trace.md` §7 in their frozen order.

| query `q` | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| what | pc | `rs1` | `rs2` | `arg1` | `arg2` | `load` | `ram` | `rd` |
| `AS` | PC | REG | REG | REG | REG | RAM | RAM | REG |
| `Δ` | 0 | 1 | 2 | 2 | 2 | 2 | 3 | 3 |

```text
M[0]            cycle
M[1 + 5q + f]   query q, field f:  0 mask   1 addr   2 read_ts   3 read_value   4 write_value
```

41 memory columns. For the pc query, `addr = 0`, `read_value = pc`, `write_value = next_pc`
and `read_ts` is the previous cycle's pc write. `mask` is 1 exactly when the row is live and
has query `q`. **A row or query with mask 0 carries 0 in every one of its memory columns**,
`cycle` included on a padding row. `constraints::memory` holds the AS and Δ table as data, and
a test in `crates/trace` holds it to `trace::Role`.

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
`constraints::memory::leaf` writes both from the unmasked tuple gate `read_tuple(q)` or
`write_tuple(q)` — a `Linear` whose `AS` and `Δ` terms already sit on `m` — in this order:
the tuple's constant on `m`, then `(−1, m)`, then the tuple's terms on `m` as they are, and
every other term times `m`. A term already on `m` enters once, so a leaf is `m·T + 1 − m` on a
boolean `m` only, which the booleanity gate of §2.4 supplies.
At `m = 0` a leaf is 1 whatever the other columns hold; at `m = 1` it is the tuple. The
`MaskIntoIdentity` shape is not used: its input would have to be a column or a cached entry,
and a cached tuple inside it refuses the cache-free compilation.

### 2.3 The product

Gate list 0 writes the 16 leaves to layer 1 in the order `R_0..R_7, W_0..W_7`. Three row-wise
lists multiply neighbours, `L{k+1}[j] = L{k}[2j]·L{k}[2j+1]`, taking the width 16 → 8 → 4 →
2; layer 4 is `[read row product, write row product]`. Then `trace_vars` halving lists of
`TreeProduct`, down to a 0-variable top of width 2. `outputs = [L{N}[0], L{N}[1]]`.
Every list multiplies exactly two children per output, and every gate is degree ≤ 2.

### 2.4 The gadgets every execution family carries

**Mask booleanity.** For each of the 8 masks, the enforcing gate `m − m·m = 0`. A leaf is the
multiplicative identity only at `m ∈ {0, 1}`; at `m = −1` a PC query's two leaves each flip
sign, the products still balance, and the query reads as a REG query.

**Read-only queries write back what they read.** For `rs1`, `rs2`, `arg1`, `arg2` and `load`,
the enforcing gate `write_value − read_value = 0` (`execution-trace.md` §3). Without it a read
of `x0` could write 5 there.

**The x0 rule** (must-be-exact 7). On query 7 (`rd`), with witness columns `rd_inv`,
`rd_is_zero` = `z` and `rd_selected` = `sel`:

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

Each chunk in `[0, 2^19)` makes `gap = lo + 2^19·hi` an integer in `[0, 2^38)`, which is
strictly `read_ts < 4·cycle + Δ`. The gadget returns its obligations by value, and the
artifact's construction asserts their number is twice the number of reads.

**Names.** A name is used once per artifact (`docs/spec/gkr.md` §4.2), so a column and the
obligation over it differ. With `<q>` the query's name of §2.1: `M` columns `cycle`,
`<q>_mask`, `<q>_addr`, `<q>_read_ts`, `<q>_read_value`, `<q>_write_value`; `W` columns
`<q>_gap_hi` for the 8 queries in order, then `rd_inv`, `rd_is_zero`, `rd_selected`
(`W[8]`–`W[10]`); obligations `gap_hi_<q>` and `gap_lo_<q>`, two per query in query order;
leaves `read_<q>`, `write_<q>`; enforcing gates `<q>_mask_boolean` for the 8 masks,
`<q>_writes_back` for `rs1` through `load`, and `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`,
`rd_is_zero_boolean`, `rd_write_masked` for the four x0 gates in the order above.

---

## 3. RAM windows

### 3.1 Geometry

Let `h = 2^n` be the height of the init/teardown families. **Window `w` covers byte addresses
`[4h·w, 4h·(w+1))`** for `0 ≤ w < N = 2^29 / h`. Row `y` of window `w` is the word at
`ADDR = 4h·w + 4y`. The windows tile `[0, 2^31)` exactly: 128 of them at `h = 2^22`, 8,192 at
`2^16`.

- RAM is `[RAM_ORIGIN, 2^31) = [2^16, 2^31)`, `2^29 − 2^14` words, a count no menu height
  divides. The only rows outside RAM are **window 0's rows `y < 2^14`** (addresses
  `0x0..0xFFFC`), at every height.
- Window 0 holds the image, which starts at `RAM_ORIGIN`. Window `N − 1` holds the initial
  `sp`, `0x8000_0000 − 4` and below; every traced guest touches it.

### 3.2 Two families of one height

| family | id | shards | window | init value |
| --- | --- | --- | --- | --- |
| `INIT_TEARDOWN` | 7 | exactly 1 | 0, the image window | `S[0]`, the image column, committed in program identity |
| `ZERO_WINDOWS` | 8 | `k ≥ 0` | `w_1 < … < w_k`, each in `[1, N − 1]` | literal 0 |

Both families are present in every `VmConfig`, never detached, and have **one height**:
`decode_program` and `VmConfig::from_bytes` refuse a config where they differ or either is
missing. A `ZERO_WINDOWS` height below `INIT_TEARDOWN`'s would put zero windows with id ≥ 1
inside the image window, giving image words a second init row. The default height of both is
`2^22`.

### 3.3 The artifacts

Both: `trace_vars = n`; memory columns `M[0] = teardown_ts`, `M[1] = teardown_value`; no
witness columns; no enforcing gates; virtual `V[row]`. `INIT_TEARDOWN` adds `S[0] = init_value`
and `V[ram_live]`. `WC` is slot 5.

```text
ZERO_WINDOWS
  L1[0] teardown = Linear { [(α_addr, V[row]) × 4, (α_ts, M[0]), (α_val, M[1])], WC }     read side
  L1[1] init     = Linear { [(α_addr, V[row]) × 4], WC }                                   write side

INIT_TEARDOWN     (live = V[ram_live]; each leaf is live·tuple + 1 − live)
  L1[0] teardown = Quadratic { 1, [(WC, live), (−1, live)],
                               [(α_addr, V[row], live) × 4, (α_ts, M[0], live), (α_val, M[1], live)] }
  L1[1] init     = Quadratic { 1, [(WC, live), (−1, live)],
                               [(α_addr, V[row], live) × 4, (α_val, S[0], live)] }
```

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
slots and the window id bound in the statement (§6); `w = 0` for `INIT_TEARDOWN`.

`kat-gen`'s `memory` group writes `memory_frame.bin`, `image_window.bin` and `zero_window.bin` —
the frame subtree of §2 and both window artifacts — at `n = 22` to
`crates/constraints/tests/vectors/`; CI regenerates and diffs them.

### 3.4 The columns a prover fills

`trace::init_windows(log, h)`: the ascending distinct `⌊a / 4h⌋` over every touched RAM word
`a`, **without 0**. That is `ZERO_WINDOWS`'s shard list.

`trace::build_init_teardown_columns(log, image, w, h)`, per row `y` at `a = 4h·w + 4y`:

| row | `teardown_ts` | `teardown_value` |
| --- | --- | --- |
| `w = 0` and `y < 2^14` (masked) | 0 | 0 |
| `a` touched | the last write's ts | the last write's value |
| `a` untouched | 0 | `image.initial_word(a)` |

and, for `w = 0`, `S[0]`. An untouched row's init and teardown tuples are equal and cancel.

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
families 7 and 8; `SHARD_COUNTS[INIT_TEARDOWN] = 1`; the window list's length is
`SHARD_COUNTS[ZERO_WINDOWS]`; the list is strictly increasing; every id is in `[1, N − 1]`.
`ZERO_WINDOWS` shard `i` is window `w_i`. `program::check_memory_windows` is these rules.

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

Each `t` is below `2^38` and each `v` below `2^32`; the verifier refuses anything else when it
decodes them. **Two final values are not carried**: `x0`'s is the constant 0 and the pc's is
the constant `HALT_PC` (§5). `gkr_verify::BoundaryFinals` holds them as
`{ reg_ts: [u64; 32], pc_ts: u64, reg_values: [u32; 31] }`, `reg_values[i]` being `x_{i+1}`,
and `trace::build_boundary_finals(log)` fills it from the log's final state.

What the public statement reads from them later: `v_10` is `a0` at exit, the exit status; the
guest-computed I/O digest's words will be `v_24 … v_31` (the D3 convention, deferred).
`t_pc` is **not** a cycle count: nothing may read `t_pc / 4` as the number of cycles proven.

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
(1 − is_exit − is_transfer)·table_next_pc`; the decoded-table lookup on every live row,
transfer rows included; and the exit row's `a0` write equal to its read.

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
boundary message and the squeeze belong to S16's global transcript.

Both new items must precede the squeeze. A window list chosen after the challenges is a union
over up to `2^127` lists at `h = 2^22` — void as a bound at `h ≤ 2^20`. A final value chosen
after them is solved outright: `v = (target − γ_M − 1 − α_addr·r − α_ts·t_r)/α_val` reconciles
any trace.

### 6.2 Program identity (amends S11's recipe)

A fresh sponge absorbs, in order:

1. `PROGRAM_IDENTITY`: the code version;
2. `VM_CONFIG`: the family ids ascending, their heights, `bytecode_size_words`;
3. `PROGRAM_ENTRY`: `entry_pc`, one scalar;
4. per family ascending, `COMMITMENT`: families 0–6 their table columns in lookup-tuple order;
   `INIT_TEARDOWN` `[cm(image column)]`; `ZERO_WINDOWS` `[]`;
5. one raw squeeze, the identity.

It binds the image's file-backed bytes inside window 0 and the entry pc, and nothing an
execution chooses: no shard count, no window list. `program::setup_commitments` is steps 4's
commitments (it needs the SRS); `program::identity_from_commitments` is the digest over them
(it does not), which is what a verifying-key loader recomputes.

### 6.3 Tags

| tag | name | kind |
| --- | --- | --- |
| 30 | `MEMORY_WINDOWS` | scalars |
| 31 | `MEMORY_BOUNDARY` | scalars |
| 32 | `PROGRAM_ENTRY` | scalars |

S16 appends the challenge-kind tag its memory squeeze draws under.

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

An obligation **holds on a row** when its selector is 0 there, or its expression's canonical
integer is below the bound. `checker::violated_lookups` is that check, natively, per row; S15
discharges it with LogUp. Until then, a future read, an out-of-window access and a
self-balancing query are caught by the native evaluator only.

---

## 8. Construction-time rules

`constraints::memory::check_memory(artifact)` runs where a memory artifact is built, beside
`validate`, and refuses, naming the gate:

- **provenance**: any gate, and any output, whose cone both names a global memory slot (1–5)
  and reads a `W` column. It is computed forward, one pair of flags per column, so a product of
  a tuple with a copy of a `W` column two layers up is refused too;
- **a global slot over anything but `M`, `S` and `V`** — where `S` is admitted only because a
  setup column is bound by identity before the challenges: a gate with a global-slot
  coefficient reads no `W` column, no inner column and no cached entry;
- **unconstrained masks**: a leaf's mask that is a committed column — `M`, `W` or `S` — with
  no enforcing gate `m − m·m` in gate list 0, or that is any virtual column but `V[ram_live]`,
  the one virtual that is 0 or 1 on the cube (`V[row]` is not). A leaf is a producing
  `Quadratic` of gate list 0 with constant 1, and its mask the operand of each of its linear
  terms weighted by a global slot. A `W` mask is refused by provenance first.

The window artifacts' read sets are pinned by test: `ZERO_WINDOWS` reads `M[0], M[1], V[row]`;
`INIT_TEARDOWN` reads those and `S[0]`, `V[ram_live]`.

The padding contract gains its product-tree clause (`docs/spec/gkr.md` §4.3): for a family
whose shards have inactive rows, every column the first halving list reads is 1 at
`padding.row`, for every challenge value and row index. `checker::check_padding_identity` holds
an artifact to it.

---

## 9. What the argument rests on

**Sequential consistency** of every address needs exactly one init tuple per address: disjoint
windows, strictly increasing ids, id ≥ 1 for `ZERO_WINDOWS`, exactly one `INIT_TEARDOWN` shard,
equal heights, the boundary counted once — and the gap obligation on every read.

**Coverage**: an accessed address with no init row cannot balance, because its read timestamps
would equal its write timestamps as multisets while each write is strictly later than its
read. This, too, needs the gap obligation.

**The RAM-window bound** — no access below `RAM_ORIGIN` or at `2^31` and above — rests on the
`ram_live` mask, the id bound `N − 1`, the image refusal, and the gap obligation.

**Owed by later stages**: S15 discharges the obligations. S16 constrains each access's byte
address (`low ∈ [0, 3]`, `low = 0` for `lw`/`sw`, `low ∈ {0, 2}` for `lh`/`sh`, a boolean wrap
on `rs1 + imm`), the sentinel's constraints of §5, the global transcript of §6.1, the
verifying key's identity recomputation, and the zero-root refusal. S20 reconciles every shard.

**Cost** at `h = 2^22`: at least two window shards per proof (window 0 and the stack window),
`2^23` leaf pairs and four committed `2^22`-entry columns, even for fib's 2,117 cycles; each
further touched 16 MiB window adds `2^22` rows; at most `2^29`. S14's tests run at `h = 2^16`.

---

## 10. Deferred: binding I/O

The guest computes `io_digest` itself and leaves its eight little-endian `u32` words in
`x24 … x31` at exit; the verifier compares them, and `a0`, with its public inputs. S14 lands
none of it: no test or document here claims fd 0 or fd 1 is bound. `docs/handoff/S14-multiset.md`
lists what that stage owes.
