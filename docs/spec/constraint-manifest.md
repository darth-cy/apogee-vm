# The constraint-system manifest: every circuit, every column, every gate

> **What this page is.** An accounting document. The specs say *why*: `gkr.md` the engine,
> `memory.md` the memory argument, `lookup.md` the channels, `shard-proof.md` §8 the add/sub
> family, `jump-branch-slt.md` the jump/branch/slt family, `shift-bitwise.md` the shift and
> bitwise family, `mul-div.md` the M extension. This page says *what exists*: every
> circuit `constraints::family_circuit` returns; every committed and virtual column with its
> position, name, meaning and readers; every intermediate multilinear by layer and offset; and
> every gate with its formula. It gives columns and gates descriptive names and one-line
> purposes that the code does not carry, and puts beside each the identifiers that find it in
> the code: the `PolyAddress`, the artifact's own name for it, and the Rust constant or
> constructor that makes it.
>
> **Status: S18.** Six circuits are registered: `ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT`,
> `SHIFT_BITWISE`, `MUL_DIV`, `INIT_TEARDOWN` and `ZERO_WINDOWS`. The three other execution
> families — `MEM_WORD`, `MEM_SUBWORD` and `ATOMICS` — have a memory frame (§2) and no circuit.
>
> **Descriptive, not normative.** Where this page and the code disagree, the registry is right
> and this page is wrong; where it and a spec disagree, the spec rules. The descriptive names
> are documentation only, as the artifact's own names are (`gkr.md` §4.2): no code reads either.
>
> **Kept current by rule.** A stage that adds or changes a circuit family updates its entry
> here in the same pull request (`prompts/00-master.md`, implementation rule 12). §10 is what an
> entry must hold.
>
> **Machine-derived.** Every count, position, name and formula below was read out of
> `family_circuit`'s artifacts, not off the source by eye. Appendix A's commands print the
> committed `n = 22` artifacts, against which every name, position and positional formula can be
> checked; the `n = 16` and `n = 20` counts were read from `family_circuit` directly, and the
> §3.10 and §4.10 probes by a program over `family_circuit` and those two suites' `honest_rows`
> that is not committed. Each family's §x.9 shows a handful of the rows its suite holds to every
> gate, every range obligation and, from §4 on, both table channels in CI: nine of the sixteen
> in `crates/checker/tests/add_sub.rs`, nine of the 47 in `jump_branch_slt.rs`, nine of the 35
> in `shift_bitwise.rs` and nine of the 64 in `mul_div.rs`. §5.10 and §6.10, unlike §3.10 and
> §4.10, are read from their suites' own committed tamper tables rather than from a probe.

---

## 0. Reading this page

### 0.1 Where the truth is

| what | where |
| --- | --- |
| the circuit a verifying key must carry | `constraints::family_circuit(family, trace_vars)`, `crates/constraints/src/lib.rs` |
| the add/sub circuit | `constraints::add_sub::{artifact, channels}`, `crates/constraints/src/add_sub.rs` |
| the jump/branch/slt circuit | `constraints::jump_branch_slt::{artifact, channels}`, `crates/constraints/src/jump_branch_slt.rs` |
| the shift/bitwise circuit | `constraints::shift_bitwise::{artifact, channels}`, `crates/constraints/src/shift_bitwise.rs` |
| the mul/div circuit, and its width seam | `constraints::mul_div::{artifact, channels, arithmetic_gates}`, `crates/constraints/src/mul_div.rs` |
| the is-zero and comparison gadgets | `constraints::gadgets::{is_zero, comparison, comparison_equation}`, `crates/constraints/src/gadgets.rs` |
| the frame, the memory tuples, the two window circuits | `constraints::memory`, `crates/constraints/src/memory.rs` |
| the fraction trees and their denominators | `constraints::lookup`, `crates/constraints/src/lookup.rs` |
| the layer assembly: reduction, halving, the names of inner nodes | `crates/constraints/src/build.rs`, `assemble` |
| a circuit, printed | `cargo run -p checker -- dump <artifact>` (Appendix A) |
| the columns' values | `trace::{build_memory_columns, build_frame_witness, build_init_teardown_columns, build_multiplicities}` and `prover::family_fill`, `crates/prover/src/fill.rs`; the packed generic table, `program::lookup_tables::generic_table` |
| the copower check every scaled bound must pass | `constraints::lookup::check_copowers`, `crates/constraints/src/lookup.rs` |

### 0.2 Notation

- **Addresses** are `PolyAddress` in its `Display` form (`gkr.md` §2): `M[i]` a memory-argument
  column, `W[i]` a witness column, `S[i]` a setup column, `V[kind]` a virtual table, `L{k}[j]`
  column `j` of inner layer `k`, `scratch[i]` its alias in the flat list. `C{k}[j]` appears
  nowhere: no registered circuit has a cached entry.
- **Gate list `k`** reads layer `k` and writes layer `k + 1`. Layer 0 is the committed columns,
  `M` then `W` then `S`, plus the virtual tables. The top layer `N` holds the outputs and has no
  gate list.
- **Relation `r`** is entry `r` of `CircuitArtifact::relations`, the flat list.
  `build::assemble` numbers relations list by list, producing gates before enforcing ones. A
  producing gate's relation is named `define_<node>`, and `<node>` is the scratch bijection's
  name for the column it writes. An enforcing gate's relation name is the gate's name.
- **Every producing gate** is `L{k+1}[j](x) = Σ_y eq(x, y)·G(inputs at y)` and **every
  enforcing gate** is `0 = G(inputs at y)` for every row `y`. This page writes only `G`. A
  halving gate reads each operand at both children, `x(y,0)` and `x(y,1)`; the child bit is
  layer `k`'s highest variable (`gkr.md` §1).
- **Literals** are integers in Fr, `−c` being `p − c`. `2^32`, `2^19` and `2^16` are those
  integers. `checker dump` prints a literal below `2^32` in decimal, and `p − k` for
  `0 < k < 2^32` as `-k`, so `−2^19` reads `-524288`. Every other literal is `0x` and 64 hex
  digits, so `2^32` reads `0x00…0100000000` and `−2^32` reads `0x30644e72…f592f0000001` there.
- **Positional form** is a gate as stored, term by term; `×k` marks a term the constructor
  repeats `k` times, because a coefficient is one literal or one challenge and `4·α_ts` is
  neither (`memory.md` §1). **Named form** replaces each `M`, `W`, `S` and inner address by
  its artifact name and merges the repeats. A virtual table's artifact name is the word in its
  address (`V[ram_live]` is `ram_live`): §3's, §4's, §5's and §6's tables keep the address form,
  §7 and §8 write the bare word.
- **`n`** is the circuit's `trace_vars`: a shard has `h = 2^n` rows, and RAM window `w` starts
  at byte address `4h·w`.

### 0.3 What row `y` of a column is

Columns of one layer do not all index the same thing.

| column | row `y` is |
| --- | --- |
| an execution family's `M` and `W` columns, multiplicities excepted | the shard's `y`-th cycle of that family, in execution order; rows past the last are **padding**, every cell 0 in an honest fill |
| a multiplicity column | row `y` of its channel's **table**: how many of the shard's gated tuples equal that row, counted on the lowest row holding a repeated tuple (`lookup.md` §7) |
| a decoded-table `S` column | the halfword at pc `2y`; `MINUS_ONE` in every column where no instruction of the family starts (`crates/program/CLAUDE.md`) |
| a generic-table `S` column (`JUMP_BRANCH_SLT`'s and `SHIFT_BITWISE`'s `S[7..10]`, `MUL_DIV`'s `S[6..9]`) | row `y` of the packed table (`lookup.md` §9): row 0 the `ZeroEntry`, all 0; rows 1 to `2^16` the AND byte table's `(AND_BASE + a + 1, b, a & b)`; rows `2^16 + 1` to `2^17` `U16GetSign`'s `(SIGN_BASE + h + 1, h >> 15, 0)`; rows `2^17 + 1` to `2^17 + 32` S18's `ShiftPowers`, `(SHIFT_BASE + s + 1, 2^s, 2^(31 − s))`; every later row 0. `AND_BASE = 0`, `SIGN_BASE = 256` and `SHIFT_BASE = SIGN_BASE + 2^16` are `constants::generic_table`'s, so the three key ranges are pairwise disjoint |
| `V[range19]`, `V[range16]` | the value `y mod 2^19`, `y mod 2^16` |
| a window family's `M` columns, `S[0]`, `V[row]`, `V[ram_live]` | the RAM word at byte address `4h·w + 4y`, `w` being the shard's window (§7, §8) |

### 0.4 The challenges

`constants::challenge_slot`. A coefficient naming a slot reads the value below. `checker dump`
prints a slot by `challenge_slot::NAMES`, its constant in lower case (`mem_gamma`,
`mem_window_constant`, `lookup_g`, `lookup_beta_2`, `lookup_decoder_neutral`); the symbols are
this page's.

| slot | constant | symbol | value | set by | read by |
| --- | --- | --- | --- | --- | --- |
| 0 | `TOY` | — | — | — | S13's toy only |
| 1 | `MEM_GAMMA` | `γ_M` | drawn once per statement | G10 (`shard-proof.md` §2) | frame leaves |
| 2 | `MEM_ALPHA_ADDR` | `α_addr` | drawn | G10 | frame leaves, window tuples |
| 3 | `MEM_ALPHA_TS` | `α_ts` | drawn | G10 | frame leaves, window teardown tuples |
| 4 | `MEM_ALPHA_VAL` | `α_val` | drawn | G10 | frame leaves; window tuples carrying a value |
| 5 | `MEM_WINDOW_CONSTANT` | `WC` | derived per window shard: `γ_M + 2 + α_addr·4h·w` (2 is `address_space::RAM`) | `gkr_verify::window_challenges` | window tuples |
| 6 | `LOOKUP_G` | `g` | drawn per shard | S4 (`shard-proof.md` §4) | every table denominator, and every lookup row denominator except `decode_row`'s (a pad denominator is the literal 1) |
| 7 | `LOOKUP_BETA` | `β` | drawn per shard, after `g` | S4 | every circuit's decoder denominators; and every generic denominator of the three circuits that read that channel — its table's, jump/branch/slt's two sign lookups', shift/bitwise's sign lookup, `shift_powers` and four `and_byte_j`, mul/div's two sign lookups |
| 8 | `LOOKUP_BETA_2` | `β²` | derived: a power of `β` | `gkr_verify::insert_lookup_challenges` | every circuit's decoder denominators; the generic **table**'s denominator in all three; and of the generic lookups only those whose third tuple position is a column — shift/bitwise's `shift_powers` (`copow`) and its four `and_byte_j` (`byte_and_j`). A sign lookup's third position is the constant 0 and adds no term |
| 9–11 | `LOOKUP_BETA_3` … `LOOKUP_BETA_5` | `β³` … `β⁵` | derived: powers of `β` | `insert_lookup_challenges` | every circuit's two decoder denominators |
| 12 | `LOOKUP_BETA_6` | `β⁶` | derived: a power of `β` | `insert_lookup_challenges` | the decoder denominators of add/sub, jump/branch/slt and shift/bitwise, whose tuples are seven wide. **Not mul/div's**: its decoded tuple has no `imm` and is six wide (§6.1) |
| 13 | `LOOKUP_DECODER_NEUTRAL` | `g_dec` | derived: `g − Σ_{j<W} β^j`, `W` the artifact's own decoder tuple width — 7 in add/sub, jump/branch/slt and shift/bitwise, **6 in mul/div** | `insert_lookup_challenges` | `decode_row`'s denominator |

### 0.5 The gate shapes

`GateDef` (`crates/constraints/src/lib.rs`, and `constraints::CATALOGUE`, the same seven rows);
`gkr_verify::eval_gate` evaluates every one. Counts are over one circuit at `n = 20`.

| tag | shape | `G` | list kind | used by |
| --- | --- | --- | --- | --- |
| 0 | `Linear { terms, constant }` | `Σ c_i·x_i + c_0` | row-wise | add/sub, 54: 35 leaves of list 0 (the 2 memory pads, the 22 leaf numerators, the 3 table denominators, the 8 pad-fraction columns), 9 degree-1 enforcing gates, 10 copies in lists 2–4; jump/branch/slt, 71: 54 leaves of list 0 (the 26 leaf numerators, 4 of tables and 22 of lookups, the 4 table denominators, the 24 pad-fraction columns), 3 degree-1 enforcing gates, 14 copies in lists 2–4; shift/bitwise, 108: 77 leaves of list 0 (the 43 leaf numerators, 4 of tables and 39 of lookups, the 4 table denominators, the 30 pad-fraction columns), 9 degree-1 enforcing gates, 22 copies in lists 2–5; mul/div, 108: 81 leaves of list 0 (the 31 leaf numerators, 4 of tables and 27 of lookups, the 4 table denominators, the 46 pad-fraction columns), 5 degree-1 enforcing gates, 22 copies in lists 2–5; `ZERO_WINDOWS`, 2 leaves |
| 1 | `Product { coeff, left, right }` | `c·x·y` | row-wise | add/sub, 37: the 14 row-wise product-tree nodes (lists 1–3) and the 23 row-wise fraction-node denominators (lists 1–4); jump/branch/slt, 40: the 6 row-wise product-tree nodes (lists 1–2) and the 34 row-wise fraction-node denominators (lists 1–4); shift/bitwise, 59: the 6 product-tree nodes (lists 1–2) and the 53 fraction-node denominators (lists 1–5); mul/div, 56: the 6 product-tree nodes and the 50 fraction-node denominators |
| 2 | `MaskIntoIdentity { input, mask }` | `x·m + 1 − m` | row-wise | no registered circuit (`memory.md` §2.2 says why) |
| 3 | `AffineProduct { .. }` | `(Σ a_i·x_i + a_0)·(Σ b_j·y_j + b_0)` | row-wise | no registered circuit |
| 4 | `TreeProduct { input }` | `x(y,0)·x(y,1)` | halving | add/sub, 5 per halving list (100); jump/branch/slt, 6 per halving list (120); shift/bitwise and mul/div, 6 per halving list (120 each); each window circuit, 2 per list (40) |
| 5 | `Quadratic { constant, linear, products }` | `c_0 + Σ a_i·x_i + Σ b_j·y_j·z_j` | row-wise | add/sub, 93: 14 memory leaves and 19 lookup row denominators (list 0), 37 degree-2 enforcing gates, and the 23 row-wise fraction-node numerators (lists 1–4); jump/branch/slt, 103: 8 memory leaves and 22 lookup row denominators (list 0), 39 degree-2 enforcing gates, and the 34 row-wise fraction-node numerators (lists 1–4); shift/bitwise, 139: 8 memory leaves and 39 lookup row denominators (list 0), 39 degree-2 enforcing gates, and the 53 fraction-node numerators (lists 1–5); mul/div, 134: 8 memory leaves and 27 lookup row denominators, 49 degree-2 enforcing gates, and the 50 fraction-node numerators; `INIT_TEARDOWN`, 2 leaves |
| 6 | `TreeCross { left, right }` | `p(y,0)·q(y,1) + p(y,1)·q(y,0)` | halving | add/sub, 3 per halving list (60); jump/branch/slt, 4 per halving list (80); shift/bitwise and mul/div, 4 per halving list (80 each) |

### 0.6 The compound expressions

**The memory tuple** (`memory.md` §1), parts in `constants::memory::PART_{AS, ADDR, TS, VAL}`
order. Its code is the private `memory::tuple`, and its read side `memory::read_tuple`: an
unmasked `Linear` that carries `AS` as the term `(AS, m)` and a write's `Δ` as `(α_ts, m) ×Δ`,
so it is `T` only at `m = 1`.

```text
T(AS, ADDR, TS, VAL) = γ_M + AS + α_addr·ADDR + α_ts·TS + α_val·VAL
```

**A frame leaf** (`memory.md` §2.2) for query `q` with mask `m`, address space `AS_q` and slot
delta `Δ_q`; code: the private `memory::leaf` over `tuple`:

```text
read_<q>  = m·T(AS_q, <q>_addr, <q>_read_ts,        <q>_read_value)  + 1 − m
write_<q> = m·T(AS_q, <q>_addr, 4·cycle + Δ_q,      <q>_write_value) + 1 − m
```

Each is stored as one `Quadratic` with constant 1: linear terms `(γ_M, m)`, `(−1, m)`,
`(AS_q, m)`, and on the write side `(α_ts, m) ×Δ_q`; products `(α_addr, addr, m)`, then
`(α_ts, read_ts, m)` or `(α_ts, cycle, m) ×4`, then `(α_val, value, m)`. The stored polynomial
is `m·T + 1 − m` at every `m`, but it is 1 or a tuple only where `m` is 0 or 1, which is why
every mask carries a booleanity gate.

**A window tuple** (`memory.md` §3.3); code: the private `memory::window_tuple`, and the
inline init tuple in `zero_window_artifact`:

```text
WC       = γ_M + 2 + α_addr·4h·w                                  one value per shard
teardown = WC + 4·α_addr·row + α_ts·teardown_ts + α_val·teardown_value
         = T(RAM, 4h·w + 4·row, teardown_ts, teardown_value)
init     = WC + 4·α_addr·row + α_val·init_value     = T(RAM, 4·row, 0, init_value)          INIT_TEARDOWN, w = 0
init     = WC + 4·α_addr·row                          = T(RAM, 4h·w + 4·row, 0, 0)            ZERO_WINDOWS
```

**A lookup's fraction** (`lookup.md` §4 to §6). With selector `s` and tuple `e_0 … e_{W−1}`, the
gated tuple is `s·e_j` on a range channel, `s·(e_0 + 1)` then `s·e_j` on the generic channel,
and `s·(e_j + 1) − 1` on the decoder channel. The row denominator (code
`lookup::row_denominator`) and the table denominator (code `lookup::table_denominator`) are:

```text
E + g   =  g + s·e_0                                                     range channel (W = 1)
E + g   =  g + s·(e_0 + 1) + Σ_{j≥1} β^j·s·e_j                           generic channel (W = 3)
E + g   =  g + Σ_j β^j·(s·(e_j + 1) − 1)
        =  g_dec + Σ_j β^j·s + Σ_j β^j·s·e_j                             decoder channel
T + g   =  Σ_j β^j·t_j + g                                               t_j the table's columns
```

A constant in `e_0` folds into the literal on `s`. Above position 0, a constant plus the
channel's offset there (1 on the decoder, 0 elsewhere) must be 0 or 1: a 1 adds the term
`β^j·s`, a 0 adds none, and `row_denominator` panics on anything else, since `β^j·c` is not one
coefficient.

A channel's leaf fractions (code: the private `lookup::channel_tree`) are the table's
`(−mult, T + g)` first, then `(1, E_l + g)` for each lookup in artifact order, then `(0, 1)`
pads up to a power of two. The channel claims `Σ_rows Σ_l 1/(E_l + g) − Σ_t mult_t/(T_t + g) = 0`,
and its root pair must be `num = 0` and `den ≠ 0`.

**Tree nodes** (`build::reduce`, `build::halve`):

```text
product node, row-wise     out = a·b                                         Product
fraction node, row-wise    num = a_num·b_den + b_num·a_den                    Quadratic
                           den = a_den·b_den                                  Product
a tree already one node    each column copied up                              Linear
product node, halving      out = x(y,0)·x(y,1)                                TreeProduct
fraction node, halving     num = num(y,0)·den(y,1) + num(y,1)·den(y,0)        TreeCross { num, den }
                           den = den(y,0)·den(y,1)                            TreeProduct { den }
```

Below, `a + b` between two fraction nodes means that pair of gates, and `a·b` between two
product nodes means the one `Product`.

---

## 1. The registry

### 1.1 What `family_circuit` returns

| id | family | constructor | channels | `Some` for | default height | S16's statement (`guests/addsub`) | S17's statement (`guests/control`) | S18's statement (`guests/alu`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | `ADD_SUB_LUI_AUIPC` | `add_sub::artifact(n)` | `add_sub::channels()`: `TIMESTAMP`, `RANGE16`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | one shard at `2^20` | one shard at `2^20` | one shard at `2^20` |
| 1 | `JUMP_BRANCH_SLT` | `jump_branch_slt::artifact(n)` | `jump_branch_slt::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | not in the config: the guest runs no instruction of the family | one shard at `2^20` | one shard at `2^20` |
| 2 | `SHIFT_BITWISE` | `shift_bitwise::artifact(n)` | `shift_bitwise::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | — | — | one shard at `2^20` |
| 3 | `MUL_DIV` | `mul_div::artifact(n)` | `mul_div::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^20` | — | — | one shard at `2^20` |
| 4–6 | `MEM_WORD`, `MEM_SUBWORD`, `ATOMICS` | — | — | never | `2^22`, but `ATOMICS` `2^16` | — | — | — |
| 7 | `INIT_TEARDOWN` | `memory::image_window_artifact(n)` | none | `0 ≤ n ≤ 30` | `2^22` | one shard at `2^16` | one shard at `2^16` | one shard at `2^16` |
| 8 | `ZERO_WINDOWS` | `memory::zero_window_artifact(n)` | none | `0 ≤ n ≤ 30` | `2^22` | at `2^16`, with no shard: the guest touches no RAM | at `2^16`, with no shard | at `2^16`, with no shard |

A verifying key carries only menu heights (`constants::family::HEIGHT_MENU`, `2^16` to `2^22`),
which `VmConfig::from_bytes` enforces, so `n` is 16, 18, 20 or 22 in any key; §9 notes the
other values the registry accepts. The prover pairs each circuit with a fill,
`prover::family_fill`: the private `fill::add_sub` for family 0, `fill::jump_branch_slt` for 1,
`fill::shift_bitwise` for 2, `fill::mul_div` for 3, `fill::window` for 7 and 8. The S16
statement is `crates/prover/tests/acceptance.rs`': its config lists families 0, 7 and 8, and its
shard counts are `[1, 1, 0]`. The S17 statement is `crates/prover/tests/control.rs`': its config
lists families 0, 1, 7 and 8, and its shard counts are `[1, 1, 1, 0]`. The S18 statement is
`crates/prover/tests/alu.rs`': its config is
`[(0, 2^20), (1, 2^20), (2, 2^20), (3, 2^20), (7, 2^16), (8, 2^16)]` and its shard counts are
`[1, 1, 1, 1, 1, 0]` — **five shards, one per family that runs**, `ZERO_WINDOWS` being the one
that does not, the guest touching no RAM. `guests/alu` runs 452 live `ADD_SUB_LUI_AUIPC` rows,
96 `JUMP_BRANCH_SLT`, 45 `SHIFT_BITWISE` and 54 `MUL_DIV`, and exits with 96, the number of
checks it made.

### 1.2 Master table

```text
circuit             n  lists (row-wise + halving)  top   M   W   S   V  committed  inner  enforcing (d1/d2)  lookups (ts/r16/gen/dec)  outputs  relations   bytes
ADD_SUB_LUI_AUIPC  20  25 (5 + 20)                 L25  36  31   7   2      74       298     46 (9/37)          19 (14/4/0/1)              8        344      67,100
ADD_SUB_LUI_AUIPC  22  27 (5 + 22)                 L27  36  31   7   2      74       314     46 (9/37)          19 (14/4/0/1)              8        360      68,190
JUMP_BRANCH_SLT    20  25 (5 + 20)                 L25  21  44  10   2      75       372     42 (3/39)          22 (8/11/2/1)             10        414      75,608
JUMP_BRANCH_SLT    22  27 (5 + 22)                 L27  21  44  10   2      75       392     42 (3/39)          22 (8/11/2/1)             10        434      76,980
SHIFT_BITWISE      20  26 (6 + 20)                 L26  21  61  10   2      92       458     48 (9/39)          39 (8/24/6/1)             10        506     101,465
SHIFT_BITWISE      22  28 (6 + 22)                 L28  21  61  10   2      92       478     48 (9/39)          39 (8/24/6/1)             10        526     102,837
MUL_DIV            20  26 (6 + 20)                 L26  21  54   9   2      84       444     54 (5/49)          27 (8/16/2/1)             10        498      92,640
MUL_DIV            22  28 (6 + 22)                 L28  21  54   9   2      84       464     54 (5/49)          27 (8/16/2/1)             10        518      94,012
INIT_TEARDOWN      16  17 (1 + 16)                 L17   2   0   1   2       3        34      0                  0                         2         34       3,259
INIT_TEARDOWN      22  23 (1 + 22)                 L23   2   0   1   2       3        46      0                  0                         2         46       3,907
ZERO_WINDOWS       16  17 (1 + 16)                 L17   2   0   0   1       2        34      0                  0                         2         34       2,770
ZERO_WINDOWS       22  23 (1 + 22)                 L23   2   0   0   1       2        46      0                  0                         2         46       3,418
```

`committed` is layer 0's width, `M + W + S`. `inner` is the width of every layer above 0,
summed: the multilinears that are never committed, one producing gate each. `relations` is
producing plus enforcing gates. `bytes` is `to_bytes().len()`. The `n = 22` rows are the
committed fixtures: `crates/constraints/tests/vectors/add_sub.bin` (SHA-256 `4c797137…c2ea114b`),
`jump_branch_slt.bin` (`99094d63…742c1305`), `shift_bitwise.bin` (`b0af9325…65e3fd4c`),
`mul_div.bin` (`98f9f3bd…a30c357a`), `image_window.bin` (`39a8655d…2df67ecc`) and
`zero_window.bin` (`f08dde67…aa51ec1c`), each pinned by its suite.

**S18's two circuits are six row-wise lists deep where the first two are five**, and the reason
is one tree apiece: shift/bitwise's `range16` tree carries 24 obligations beside its table
fraction, 25 leaves padding to 32 (§5.6), and mul/div's carries 16, which with its table
fraction is 17 leaves and pads to 32 too (§6.6). Everything else about their shape follows: one
more row-wise level, one more gate list, one more transition in every proof.

The proof a shard of each carries, at `n = 20` and from `crates/prover/tests/alu.rs`:

```text
circuit             n   proof bytes
ADD_SUB_LUI_AUIPC  20        57,100
JUMP_BRANCH_SLT    20        61,612
SHIFT_BITWISE      20        68,564
MUL_DIV            20        67,412
```

A proof's length is `shard-proof.md` §9's layout over the circuit's own shape — one transition
per gate list, `128` bytes per sumcheck round and `32` per final claim — so the two new families
are longer than the two older ones on three counts at once: a wider base layer, a wider `L1`, and
the extra transition their `range16` trees buy.

### 1.3 Shape formulas

`build::assemble` builds every circuit the same way. Let `R` be the largest `log2` leaf count
among its trees; then the depth is `N = 1 + R + n`. Gate list 0 writes the leaves, lists
`1 … R` reduce row-wise, and lists `R + 1 … R + n` halve.

- **add/sub.** Five trees: `read` and `write` with 8 leaves each, `timestamp` with 16 fractions,
  `range16` with 8, `decoder` with 2; so `R = 4`. Layers `L1 … L5` are 68, 34, 18, 10 and 8
  wide, and `L6 … L{n+5}` 8 each: `inner = 138 + 8n`. Relations 0–67 are list 0's leaves,
  68–113 its enforcing gates, 114–147 list 1, 148–165 list 2, 166–175 list 3, 176–183 list 4,
  and halving list `k` (`5 ≤ k ≤ n + 4`) holds `184 + 8(k − 5)` to `191 + 8(k − 5)`. The
  roots are relations `176 + 8n` to `183 + 8n`: 336–343 at `n = 20`, 352–359 at `n = 22`.
- **jump/branch/slt.** Six trees: `read` and `write` with 4 leaves each, `timestamp` with 16
  fractions, `range16` with 16, `generic` with 4, `decoder` with 2; so `R = 4`, the two
  16-fraction trees setting it. Layers `L1 … L5` are 84, 42, 22, 14 and 10 wide, and
  `L6 … L{n+5}` 10 each: `inner = 172 + 10n`. Relations 0–83 are list 0's leaves, 84–125 its
  enforcing gates, 126–167 list 1, 168–189 list 2, 190–203 list 3, 204–213 list 4, and halving
  list `k` (`5 ≤ k ≤ n + 4`) holds `214 + 10(k − 5)` to `223 + 10(k − 5)`. The roots are
  relations `204 + 10n` to `213 + 10n`: 404–413 at `n = 20`, 424–433 at `n = 22`.
- **shift/bitwise.** Six trees: `read` and `write` with 4 leaves each, `timestamp` with 16
  fractions, `range16` with **32**, `generic` with 8, `decoder` with 2; so `R = 5`, the
  32-fraction `range16` tree setting it alone. Layers `L1 … L6` are 124, 62, 32, 18, 12 and 10
  wide, and `L7 … L{n+6}` 10 each: `inner = 258 + 10n`. Relations 0–123 are list 0's leaves,
  124–171 its enforcing gates, 172–233 list 1, 234–265 list 2, 266–283 list 3, 284–295 list 4,
  296–305 list 5, and halving list `k` (`6 ≤ k ≤ n + 5`) holds `306 + 10(k − 6)` to
  `315 + 10(k − 6)`. The roots are relations `296 + 10n` to `305 + 10n`: 496–505 at `n = 20`,
  516–525 at `n = 22`.
- **mul/div.** Six trees: `read` and `write` with 4 leaves each, `timestamp` with 16 fractions,
  `range16` with **32**, `generic` with 4, `decoder` with 2; so `R = 5`, again the `range16`
  tree alone — 17 leaves is one past 16. Layers `L1 … L6` are 116, 58, 30, 18, 12 and 10 wide,
  and `L7 … L{n+6}` 10 each: `inner = 244 + 10n`. Relations 0–115 are list 0's leaves, 116–169
  its enforcing gates, 170–227 list 1, 228–257 list 2, 258–275 list 3, 276–287 list 4, 288–297
  list 5, and halving list `k` (`6 ≤ k ≤ n + 5`) holds `298 + 10(k − 6)` to `307 + 10(k − 6)`.
  The roots are relations `288 + 10n` to `297 + 10n`: 488–497 at `n = 20`, 508–517 at `n = 22`.
- **The two windows.** Two trees of one leaf each, so `R = 0`: `L1 … L{n+1}` are 2 wide and
  `inner = 2n + 2`. Relation 0 is the teardown leaf, 1 the init leaf, and halving list `k`
  (`1 ≤ k ≤ n`) holds `2k` (read side) and `2k + 1` (write side). The roots are relations `2n`
  and `2n + 1`.

---

## 2. The memory frame every execution family carries

`memory::frame_artifact` and `frame_with_channels_artifact` build it; `memory.md` §2 is its
spec. It is the first part of every execution family's circuit, so its columns come first in
`M` and `W`.

### 2.1 The query table and the layout

The eight queries (`memory::{PC, RS1, RS2, ARG1, ARG2, LOAD, RAM, RD}`, with `FRAME_NAMES`,
`FRAME_SPACE`, `FRAME_DELTA`):

| id | constant | `<q>` | `AS` | `Δ` | what it is |
| --- | --- | --- | --- | --- | --- |
| 0 | `PC` | `pc` | PC = 3 | 0 | reads the pc, writes the next pc |
| 1 | `RS1` | `rs1` | REG = 1 | 1 | first operand register; an ecall row's `a7` |
| 2 | `RS2` | `rs2` | REG | 2 | second operand register; an ecall row's `a0` |
| 3 | `ARG1` | `arg1` | REG | 2 | an ecall row's `a1` |
| 4 | `ARG2` | `arg2` | REG | 2 | an ecall row's `a2` |
| 5 | `LOAD` | `load` | RAM = 2 | 2 | a load's word |
| 6 | `RAM` | `ram` | RAM | 3 | a store's, an atomic's or an ecall transfer's word |
| 7 | `RD` | `rd` | REG | 3 | the destination register; an ecall row's `a0` result |

A family holds the subset `memory::frame_queries(family)`. **Slot** `s` is a query's position
in that list, and every column is addressed by slot, never by query id. With `w` the family's
query count:

| address | name | Rust | descriptive name | holds |
| --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the row's cycle `c`, counted from 1; its writes are at `4c + Δ` |
| `M[1 + 5s]` | `<q>_mask` | `memory::frame(s, FIELD_MASK)` | `<q>` present | 1 exactly on a live row that makes query `<q>` |
| `M[2 + 5s]` | `<q>_addr` | `frame(s, FIELD_ADDR)` | `<q>` address | a register index, a RAM word's byte address, or 0 for the pc |
| `M[3 + 5s]` | `<q>_read_ts` | `frame(s, FIELD_READ_TS)` | `<q>` previous-write time | the timestamp of the write this query reads |
| `M[4 + 5s]` | `<q>_read_value` | `frame(s, FIELD_READ_VALUE)` | `<q>` value read | |
| `M[5 + 5s]` | `<q>_write_value` | `frame(s, FIELD_WRITE_VALUE)` | `<q>` value written | written at `4·cycle + Δ_q` |
| `W[s]` | `<q>_gap_hi` | `memory::gap_hi(s)` | `<q>` gap, high chunk | `gap >> 19`, with `gap = 4·cycle + Δ_q − read_ts − 1` |
| `W[w]` | `rd_inv` | `memory::rd_inv(w)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 where `rd_addr = 0` |
| `W[w + 1]` | `rd_is_zero` | `memory::rd_is_zero(w)` | rd-is-x0 flag | 1 exactly on a live `rd` query at address 0 |
| `W[w + 2]` | `rd_selected` | `memory::rd_selected(w)` | Result before the x0 rule | what the instruction computes for `rd`, `x0` writes included, as a family's fill writes it (`fill::add_sub`, §3.3; `fill::jump_branch_slt`, §4.3); S14's `trace::build_frame_witness` writes `rd`'s write value where `rd_addr ≠ 0` and 0 elsewhere, and the frame's gates leave it free where `rd_is_zero = 1` |

Every family has an `rd` query, so every frame has the three x0 columns.

### 2.2 Each execution family's frame

| family | queries, in slot order | `w` | `M` | frame `W` | leaves a side | frame gates | gap obligations | circuit | frame fixture (`n = 22`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 `ADD_SUB_LUI_AUIPC` | pc rs1 rs2 arg1 arg2 ram rd | 7 | 36 | 10 | 8 | 15 | 14 | §3 | `memory_frame_alu.bin` |
| 1 `JUMP_BRANCH_SLT` | pc rs1 rs2 rd | 4 | 21 | 7 | 4 | 10 | 8 | §4 | `memory_frame_reg.bin` |
| 2 `SHIFT_BITWISE` | pc rs1 rs2 rd | 4 | 21 | 7 | 4 | 10 | 8 | §5 | `memory_frame_reg.bin` |
| 3 `MUL_DIV` | pc rs1 rs2 rd | 4 | 21 | 7 | 4 | 10 | 8 | §6 | `memory_frame_reg.bin` |
| 4 `MEM_WORD` | pc rs1 rs2 load ram rd | 6 | 31 | 9 | 8 | 13 | 12 | none yet | `memory_frame_mem.bin` |
| 5 `MEM_SUBWORD` | pc rs1 rs2 load ram rd | 6 | 31 | 9 | 8 | 13 | 12 | none yet | `memory_frame_mem.bin` |
| 6 `ATOMICS` | pc rs1 rs2 ram rd | 5 | 26 | 8 | 8 | 11 | 10 | none yet | `memory_frame_atomics.bin` |

The frame gates are `w` mask booleanity gates, one write-back per read-only query the frame
holds (`rs1`, `rs2`, `arg1`, `arg2`, `load`), and the four x0 gates.

The same layout by index. `M[a..b]` is half-open, and a query's five columns are always in the
order mask, addr, read_ts, read_value, write_value:

| columns | ALU (0) | REG (1, 2, 3) | MEM (4, 5) | ATOMICS (6) |
| --- | --- | --- | --- | --- |
| `cycle` | `M[0]` | `M[0]` | `M[0]` | `M[0]` |
| `pc_*` | `M[1..6]` | `M[1..6]` | `M[1..6]` | `M[1..6]` |
| `rs1_*` | `M[6..11]` | `M[6..11]` | `M[6..11]` | `M[6..11]` |
| `rs2_*` | `M[11..16]` | `M[11..16]` | `M[11..16]` | `M[11..16]` |
| `arg1_*` | `M[16..21]` | — | — | — |
| `arg2_*` | `M[21..26]` | — | — | — |
| `load_*` | — | — | `M[16..21]` | — |
| `ram_*` | `M[26..31]` | — | `M[21..26]` | `M[16..21]` |
| `rd_*` | `M[31..36]` | `M[16..21]` | `M[26..31]` | `M[21..26]` |
| `<q>_gap_hi` | `W[0..7]` | `W[0..4]` | `W[0..6]` | `W[0..5]` |
| `rd_inv`, `rd_is_zero`, `rd_selected` | `W[7]`, `W[8]`, `W[9]` | `W[4]`, `W[5]`, `W[6]` | `W[6]`, `W[7]`, `W[8]` | `W[5]`, `W[6]`, `W[7]` |
| the family's own `W` columns start at | `W[10]` | `W[7]` | `W[9]` | `W[8]` |

### 2.3 The frame's gates and obligations

For the query `<q>` at slot `s`, with `m = <q>_mask`:

| name | kind | named form | code | what it holds |
| --- | --- | --- | --- | --- |
| `read_<q>`, `write_<q>` | leaves | §0.6 | `leaf(&tuple(..))` in `frame_body` | the query's read and write tuples, or 1 where it is absent |
| `read_pad_<i>`, `write_pad_<i>` | leaves, `Linear` | `1` | `frame_body` | the product's identity, padding each side to a power of two |
| `<q>_mask_boolean` | enforcing, degree 2 | `0 = m − m·m` | private `memory::booleanity` | the mask is 0 or 1 |
| `<q>_writes_back` | enforcing, degree 1 | `0 = <q>_write_value − <q>_read_value` | private `write_back` | a read-only query leaves its register or word unchanged |
| `rd_is_zero_inverse` | enforcing, degree 2 | `0 = rd_is_zero − rd_mask + rd_addr·rd_inv` | private `x0_gates`, which since S17 takes it from `gadgets::is_zero(&[(1, rd_addr)], rd_inv, rd_is_zero, rd_mask)[0]`, bytes unchanged | with the next gate: `rd_is_zero` is `rd_mask` at address 0 and 0 elsewhere |
| `rd_is_zero_at_nonzero` | enforcing, degree 2 | `0 = rd_addr·rd_is_zero` | `x0_gates`, from `is_zero(..)[1]` | the flag is 0 at a nonzero address |
| `rd_is_zero_boolean` | enforcing, degree 2 | `0 = rd_is_zero − rd_is_zero·rd_is_zero` | `x0_gates` | the flag is 0 or 1 |
| `rd_write_masked` | enforcing, degree 2 | `0 = rd_write_value − rd_selected + rd_is_zero·rd_selected` | `x0_gates` | the rd write is the result, or 0 into `x0` |
| `gap_hi_<q>` | `TIMESTAMP` obligation, selector `m` | `<q>_gap_hi < 2^19` | private `gap_lookups` | the gap's high chunk |
| `gap_lo_<q>` | `TIMESTAMP` obligation, selector `m` | `4·cycle − <q>_read_ts − 2^19·<q>_gap_hi + (Δ_q − 1) < 2^19` | `gap_lookups` | the low chunk; with the high one, `read_ts < 4·cycle + Δ_q` |

---

## 3. `ADD_SUB_LUI_AUIPC` — family 0

### 3.1 Header

`family_circuit(0, n)` is `add_sub::artifact(n)` with `add_sub::channels()`, built by
`memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` (`QUERIES` and the `SLOT_*`
constants are private to `add_sub.rs`). Normative spec: `shard-proof.md` §8. Fill:
`prover::family_fill(0)`, the private `fill::add_sub`.

74 committed columns (36 `M`, 31 `W`, 7 `S`) and two virtual tables. Gate list 0 writes 68
leaves and holds 46 enforcing gates. 19 lookups on three channels, 8 outputs. At `n = 20`, the
height S16 proves, there are 25 gate lists, the top is `L25`, and the circuit has 298 inner
columns and 344 relations. `artifact` panics unless the frame is `QUERIES` and the channels
carry exactly 14, 4 and 1 obligations. It also panics on every refusal of the assembly, among
them `n < 19` (the 19-bit timestamp table needs 19 variables) and `n > 30` (`MAX_TRACE_VARS`);
`family_circuit` returns `None` for both rather than calling it.

### 3.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::add_sub_lui_auipc`; the system
kind is split by the code the decoded table puts in `imm`
(`constants::extra_mask::system_code`).

| row kind | bit (`decoded_mask`) | `decoded_imm` | queries present | `rd_selected` | `wrap` | `next_pc` | provable at S16 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `add` | 3 (8) | 0 | pc rs1 rs2 rd | `rs1 + rs2 mod 2^32` | the carry | the fall-through | yes |
| `sub` | 4 (16) | 0 | pc rs1 rs2 rd | `rs1 − rs2 mod 2^32` | the borrow, `rs1 < rs2` | the fall-through | yes |
| `addi` | 1 (2) | the immediate, sign-extended, as a `u32` | pc rs1 rd | `rs1 + imm mod 2^32` | the carry | the fall-through | yes |
| `auipc` | 2 (4) | the shifted upper immediate, as a `u32` | pc rd | `pc + imm mod 2^32` | the carry | the fall-through | yes |
| `lui` | 5 (32) | the value loaded | pc rd | `imm` | 0; on this row only `wrap_boolean` constrains it, the sum and difference gates vanishing | the fall-through | yes |
| system: fence | 0 (1) | `FENCE` = 2 | pc | 0 | 0; as on a lui row, only `wrap_boolean` constrains it | the fall-through | yes, `is_fence = 1` |
| system: ecall | 0 (1) | `ECALL` = 0 | pc; rs1 = `x17`, reading 93; rs2 = `x10`; rd = `x10` | `a0` as read | 0; as on a lui row, only `wrap_boolean` constrains it | `HALT_PC` = 1 | `EXIT` only, `is_ecall = 1` |
| system: an ecall's transfer cycle | 0 (1) | `ECALL` = 0, its ecall's table row | pc; ram = the word moved | — | — | the pc, unchanged | never: `fill::add_sub` refuses it by name, and its decoded row forces `is_ecall = 1`, so `rs1_mask_rule`, `rs2_mask_rule` and `rd_mask_rule` demand queries it lacks, `ram_mask_rule` forbids its RAM query, and `next_pc_rule` demands `HALT_PC` |
| system: ebreak | 0 (1) | `EBREAK` = 1 | — | — | — | — | never: no row satisfies `system_split` with the two code gates |
| padding | none; all 0 | 0 | none | 0 | 0 | 0 | every row past the shard's last cycle |

A compressed instruction (`c.add`, `c.li`, …) is one of these kinds at its own length: its
table row's `next_pc` is `pc + 2`.

### 3.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §3.4 and §3.6.

**Memory-argument columns, `M[0..36]`** — filled by `trace::build_memory_columns`; committed in
`PublicInputs::memory_commitments`, absorbed at G8 before the memory challenges.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 7); obligations `gap_lo_*` (all 7) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`; selector of `gap_hi_pc`, `gap_lo_pc`, the four `RANGE16` obligations and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `add_addi_auipc`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | the fall-through, or `HALT_PC` on the exit row | leaf `write_pc`; `next_pc_rule`; `next_pc_lo_range` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on add, sub, addi and the exit row | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | rs1 register | the decoded `rs1`, or 17 (`a7`) on the exit row | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | rs1 value | | leaf `read_rs1`; `rs1_writes_back`, `ecall_is_exit`, `rs1_value_masked`, `add_addi_auipc`, `sub` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on add, sub and the exit row | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | rs2 register | the decoded `rs2`, or 10 (`a0`) on the exit row | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | rs2 value | | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `add_addi_auipc`, `sub` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `arg1_mask` | `frame(3, FIELD_MASK)` | a1 present | 0: `arg1_mask_rule` | leaves `read_arg1`, `write_arg1`; `arg1_mask_boolean`, `arg1_mask_rule`; selector of `gap_hi_arg1`, `gap_lo_arg1` |
| `M[17]` | `arg1_addr` | `frame(3, FIELD_ADDR)` | a1 register | 0 | leaves `read_arg1`, `write_arg1` |
| `M[18]` | `arg1_read_ts` | `frame(3, FIELD_READ_TS)` | a1 previous write | 0 | leaf `read_arg1`; `gap_lo_arg1` |
| `M[19]` | `arg1_read_value` | `frame(3, FIELD_READ_VALUE)` | a1 value | 0 | leaf `read_arg1`; `arg1_writes_back` |
| `M[20]` | `arg1_write_value` | `frame(3, FIELD_WRITE_VALUE)` | a1 written back | 0 | leaf `write_arg1`; `arg1_writes_back` |
| `M[21]` | `arg2_mask` | `frame(4, FIELD_MASK)` | a2 present | 0: `arg2_mask_rule` | leaves `read_arg2`, `write_arg2`; `arg2_mask_boolean`, `arg2_mask_rule`; selector of `gap_hi_arg2`, `gap_lo_arg2` |
| `M[22]` | `arg2_addr` | `frame(4, FIELD_ADDR)` | a2 register | 0 | leaves `read_arg2`, `write_arg2` |
| `M[23]` | `arg2_read_ts` | `frame(4, FIELD_READ_TS)` | a2 previous write | 0 | leaf `read_arg2`; `gap_lo_arg2` |
| `M[24]` | `arg2_read_value` | `frame(4, FIELD_READ_VALUE)` | a2 value | 0 | leaf `read_arg2`; `arg2_writes_back` |
| `M[25]` | `arg2_write_value` | `frame(4, FIELD_WRITE_VALUE)` | a2 written back | 0 | leaf `write_arg2`; `arg2_writes_back` |
| `M[26]` | `ram_mask` | `frame(5, FIELD_MASK)` | RAM word present | 0: `ram_mask_rule` | leaves `read_ram`, `write_ram`; `ram_mask_boolean`, `ram_mask_rule`; selector of `gap_hi_ram`, `gap_lo_ram` |
| `M[27]` | `ram_addr` | `frame(5, FIELD_ADDR)` | RAM word address | 0 | leaves `read_ram`, `write_ram` |
| `M[28]` | `ram_read_ts` | `frame(5, FIELD_READ_TS)` | RAM word previous write | 0 | leaf `read_ram`; `gap_lo_ram` |
| `M[29]` | `ram_read_value` | `frame(5, FIELD_READ_VALUE)` | RAM word read | 0 | leaf `read_ram` |
| `M[30]` | `ram_write_value` | `frame(5, FIELD_WRITE_VALUE)` | RAM word written | 0 | leaf `write_ram` |
| `M[31]` | `rd_mask` | `frame(6, FIELD_MASK)` | rd present | 1 on every kind but the fence | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[32]` | `rd_addr` | `frame(6, FIELD_ADDR)` | rd register | the decoded `rd`, or 10 (`a0`) on the exit row | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[33]` | `rd_read_ts` | `frame(6, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[34]` | `rd_read_value` | `frame(6, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd`; `exit_status` |
| `M[35]` | `rd_write_value` | `frame(6, FIELD_WRITE_VALUE)` | rd new value | `rd_selected`, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |

The frame's slots in `add_sub.rs` are `SLOT_PC = 0` through `SLOT_RD = 6`, so `frame(1, ..)` is
`frame(SLOT_RS1, ..)` there. At S16 the `arg1`, `arg2` and `ram` queries are held absent on
every row. Their fifteen columns and three gap chunks are committed and opened, and carry
nothing until the I/O-binding stage.

**Witness columns, `W[0..31]`** — `W[0..9]` filled by `trace::build_frame_witness`, `W[9..28]`
by `fill::add_sub`, `W[28..31]` by `trace::build_multiplicities` inside `prover::shard_columns`;
committed in `ShardProof::witness_commitments`, absorbed at S3 before `g` and `β`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0]` | `pc_gap_hi` | `memory::gap_hi(0)` | pc gap, high chunk | 0: a pc read's gap is always 3 | `gap_hi_pc`, `gap_lo_pc` |
| `W[1]` | `rs1_gap_hi` | `gap_hi(1)` | rs1 gap, high chunk | `gap >> 19` | `gap_hi_rs1`, `gap_lo_rs1` |
| `W[2]` | `rs2_gap_hi` | `gap_hi(2)` | rs2 gap, high chunk | | `gap_hi_rs2`, `gap_lo_rs2` |
| `W[3]` | `arg1_gap_hi` | `gap_hi(3)` | a1 gap, high chunk | 0 | `gap_hi_arg1`, `gap_lo_arg1` |
| `W[4]` | `arg2_gap_hi` | `gap_hi(4)` | a2 gap, high chunk | 0 | `gap_hi_arg2`, `gap_lo_arg2` |
| `W[5]` | `ram_gap_hi` | `gap_hi(5)` | RAM gap, high chunk | 0 | `gap_hi_ram`, `gap_lo_ram` |
| `W[6]` | `rd_gap_hi` | `gap_hi(6)` | rd gap, high chunk | | `gap_hi_rd`, `gap_lo_rd` |
| `W[7]` | `rd_inv` | `memory::rd_inv(7)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[8]` | `rd_is_zero` | `memory::rd_is_zero(7)` | rd is `x0` | | `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_is_zero_boolean`, `rd_write_masked` |
| `W[9]` | `rd_selected` | `memory::rd_selected(7)`; `sel` in `add_sub.rs` | Result | the kind's result (§3.2), `rd = x0` included: `fill::add_sub` overwrites the 0 that S14's builder writes there | `rd_write_masked`, `add_addi_auipc`, `sub`, `lui`, `exit_status`; `rd_lo_range` |
| `W[10]` | `decoded_next_pc` | `add_sub::DECODED[0]` | Decoded fall-through | the table row's `next_pc` | `next_pc_rule`; `decode_row` position 1 |
| `W[11]` | `decoded_rs1` | `add_sub::DECODED[1]` | Decoded rs1 | | `rs1_addr_rule`; `decode_row` position 2 |
| `W[12]` | `decoded_rs2` | `add_sub::DECODED[2]` | Decoded rs2 | | `rs2_addr_rule`; `decode_row` position 3 |
| `W[13]` | `decoded_rd` | `add_sub::DECODED[3]` | Decoded rd | | `rd_addr_rule`; `decode_row` position 4 |
| `W[14]` | `decoded_imm` | `add_sub::DECODED[4]` | Decoded immediate, or system code | | `ecall_code`, `fence_code`, `add_addi_auipc`, `lui`; `decode_row` position 5 |
| `W[15]` | `decoded_mask` | `add_sub::DECODED[5]` | Decoded kind mask | `1 << bit` | `decoded_mask_bits`; `decode_row` position 6 |
| `W[16]` | `kind_system` | `add_sub::KINDS[0]`; `KIND_SYSTEM` in `add_sub.rs` (index `add_sub_lui_auipc::SYSTEM`) | System row | | `kind_system_boolean`, `decoded_mask_bits`, `system_split` |
| `W[17]` | `kind_addi` | `add_sub::KINDS[1]`; `KIND_ADDI` in `add_sub.rs` (index `add_sub_lui_auipc::ADDI`) | addi row | | `kind_addi_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rd_mask_rule`, `add_addi_auipc` |
| `W[18]` | `kind_auipc` | `add_sub::KINDS[2]`; `KIND_AUIPC` in `add_sub.rs` (index `add_sub_lui_auipc::AUIPC`) | auipc row | | `kind_auipc_boolean`, `decoded_mask_bits`, `rd_mask_rule`, `add_addi_auipc` |
| `W[19]` | `kind_add` | `add_sub::KINDS[3]`; `KIND_ADD` in `add_sub.rs` (index `add_sub_lui_auipc::ADD`) | add row | | `kind_add_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `add_addi_auipc` |
| `W[20]` | `kind_sub` | `add_sub::KINDS[4]`; `KIND_SUB` in `add_sub.rs` (index `add_sub_lui_auipc::SUB`) | sub row | | `kind_sub_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `sub` |
| `W[21]` | `kind_lui` | `add_sub::KINDS[5]`; `KIND_LUI` in `add_sub.rs` (index `add_sub_lui_auipc::LUI`) | lui row | | `kind_lui_boolean`, `decoded_mask_bits`, `rd_mask_rule`, `lui` |
| `W[22]` | `is_ecall` | `add_sub::IS_ECALL` | Exit row | 1 on a system row with code `ECALL` | `is_ecall_boolean`, `system_split`, `ecall_code`, `ecall_is_exit`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `rs1_addr_rule`, `rs2_addr_rule`, `rd_addr_rule`, `exit_status`, `next_pc_rule` |
| `W[23]` | `is_fence` | `add_sub::IS_FENCE` | Fence row | 1 on a system row with code `FENCE` | `is_fence_boolean`, `system_split`, `fence_code` |
| `W[24]` | `wrap` | `add_sub::WRAP` | Carry or borrow | | `add_addi_auipc`, `sub`, `wrap_boolean` |
| `W[25]` | `rd_hi` | `add_sub::RD_HI` | Result, high halfword | `rd_selected >> 16` | `rd_hi_range`, `rd_lo_range` |
| `W[26]` | `pc_wrap` | `add_sub::PC_WRAP` | Next-pc overflow | 0 | `pc_wrap_boolean`, `next_pc_rule` |
| `W[27]` | `next_pc_hi` | `add_sub::NEXT_PC_HI` | Next pc, high halfword | `pc_write_value >> 16` | `next_pc_hi_range`, `next_pc_lo_range` |
| `W[28]` | `mult_timestamp` | `add_sub::MULTIPLICITIES[0]` | Timestamp-table count | per table row `t`: the gated gap chunks (`mask·chunk`) equal to `t`, credited to rows below `2^19` | leaf `timestamp_table_num` |
| `W[29]` | `mult_range16` | `add_sub::MULTIPLICITIES[1]` | 16-bit-table count | per table row `t`: the gated halfwords (`pc_mask·halfword`) equal to `t`, credited to rows below `2^16` | leaf `range16_table_num` |
| `W[30]` | `mult_decoder` | `add_sub::MULTIPLICITIES[2]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all seven positions) on the table's lowest non-live row, which is row 0, since pc 0 lies below `RAM_ORIGIN` and holds no instruction | leaf `decoder_table_num` |

A switched-off obligation's gated tuple is 0 (`s·e` at `s = 0`), so row 0 of `mult_timestamp`
and `mult_range16` counts every switched-off obligation: all 14 timestamp and all 4 `RANGE16`
obligations of each padding row, and in `mult_timestamp` also each live row's six `arg1`,
`arg2` and `ram` gap chunks and the two chunks of any `rs1`, `rs2` or `rd` query the row does
not make. The `RANGE16` obligations are selected by `pc_mask`, so none is off on a live row.
Row 0 also counts every live chunk whose value is 0, such as `pc_gap_hi` on every live row.

**Setup columns, `S[0..7]`** — the family's decoded table, `program::lookup_tuple(0)` order,
filled by `program::FamilyTable::column_poly(j)`; committed in program identity
(`program::setup_commitments`) and carried as `VerifyingKey::setup_commitments` for the family.
Each is read only by `decoder_table_den`, at the `β` power in the last column.

| address | name | Rust | descriptive name | table field | weight |
| --- | --- | --- | --- | --- | --- |
| `S[0]` | `table_pc` | `add_sub::channels()[2].table[0]` | Table pc | `RowField::Pc` | 1 |
| `S[1]` | `table_next_pc` | `channels()[2].table[1]` | Table fall-through | `RowField::NextPc` | `β` |
| `S[2]` | `table_rs1` | `channels()[2].table[2]` | Table rs1 | `RowField::Rs1` | `β²` |
| `S[3]` | `table_rs2` | `channels()[2].table[3]` | Table rs2 | `RowField::Rs2` | `β³` |
| `S[4]` | `table_rd` | `channels()[2].table[4]` | Table rd | `RowField::Rd` | `β⁴` |
| `S[5]` | `table_imm` | `channels()[2].table[5]` | Table immediate | `RowField::Imm` | `β⁵` |
| `S[6]` | `table_extra_mask` | `channels()[2].table[6]` | Table kind mask | `RowField::ExtraMask` | `β⁶` |

`add_sub::TABLE_WIDTH` is 7.

**Virtual tables** — never committed, never opened; `gkr_verify::verify` evaluates their
closed forms.

| address | name | Rust | descriptive name | value at row `y` | read by |
| --- | --- | --- | --- | --- | --- |
| `V[range19]` | `range19` | `VirtualKind::Range19`, wire tag 2 | 19-bit range table | `y mod 2^19` | `timestamp_table_den` |
| `V[range16]` | `range16` | `VirtualKind::Range16`, wire tag 3 | 16-bit range table | `y mod 2^16` | `range16_table_den` |

### 3.4 Gate list 0: the 68 leaves

A leaf's relation number equals its `L1` offset, 0 to 67.

**The memory product trees.** The read side is `L1[0..8]` and the write side `L1[8..16]`, each
leaf per §0.6.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_arg1` | `M[16]` | 1 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `read_arg2` | `M[21]` | 1 | `M[22]` | `M[23]` | `M[24]` |
| 5 | `read_ram` | `M[26]` | 2 | `M[27]` | `M[28]` | `M[29]` |
| 6 | `read_rd` | `M[31]` | 1 | `M[32]` | `M[33]` | `M[34]` |
| 7 | `read_pad_0` | — | — | — | — | the constant 1 |
| 8 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 9 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 10 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 11 | `write_arg1` | `M[16]` | 1 | `M[17]` | `4·M[0] + 2` | `M[20]` |
| 12 | `write_arg2` | `M[21]` | 1 | `M[22]` | `4·M[0] + 2` | `M[25]` |
| 13 | `write_ram` | `M[26]` | 2 | `M[27]` | `4·M[0] + 3` | `M[30]` |
| 14 | `write_rd` | `M[31]` | 1 | `M[32]` | `4·M[0] + 3` | `M[35]` |
| 15 | `write_pad_0` | — | — | — | — | the constant 1 |

Two of them in full:

```text
L{1}[0]  read_pc
  positional  1 + γ_M·M[1] − M[1] + 3·M[1] + α_addr·M[2]·M[1] + α_ts·M[3]·M[1] + α_val·M[4]·M[1]
  named       pc_mask·T(PC, pc_addr, pc_read_ts, pc_read_value) + 1 − pc_mask

L{1}[14]  write_rd
  positional  1 + γ_M·M[31] − M[31] + M[31] + α_ts·M[31] ×3 + α_addr·M[32]·M[31]
                + α_ts·M[0]·M[31] ×4 + α_val·M[35]·M[31]
  named       rd_mask·T(REG, rd_addr, 4·cycle + 3, rd_write_value) + 1 − rd_mask
```

**The `timestamp` fraction tree**, `L1[16..48]`: 16 fractions, the table's then 14 gap
obligations then one pad. Fraction `i` is `(L1[16 + 2i], L1[17 + 2i])`, named `<node>_num` and
`<node>_den`.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 16, 17 | `timestamp_table` | `−mult_timestamp` | `V[range19] + g` |
| 1 | 18, 19 | `gap_hi_pc` | 1 | `g + pc_mask·pc_gap_hi` |
| 2 | 20, 21 | `gap_lo_pc` | 1 | `g − pc_mask + 4·pc_mask·cycle − pc_mask·pc_read_ts − 2^19·pc_mask·pc_gap_hi` |
| 3 | 22, 23 | `gap_hi_rs1` | 1 | `g + rs1_mask·rs1_gap_hi` |
| 4 | 24, 25 | `gap_lo_rs1` | 1 | `g + 4·rs1_mask·cycle − rs1_mask·rs1_read_ts − 2^19·rs1_mask·rs1_gap_hi` |
| 5 | 26, 27 | `gap_hi_rs2` | 1 | `g + rs2_mask·rs2_gap_hi` |
| 6 | 28, 29 | `gap_lo_rs2` | 1 | `g + rs2_mask + 4·rs2_mask·cycle − rs2_mask·rs2_read_ts − 2^19·rs2_mask·rs2_gap_hi` |
| 7 | 30, 31 | `gap_hi_arg1` | 1 | `g + arg1_mask·arg1_gap_hi` |
| 8 | 32, 33 | `gap_lo_arg1` | 1 | `g + arg1_mask + 4·arg1_mask·cycle − arg1_mask·arg1_read_ts − 2^19·arg1_mask·arg1_gap_hi` |
| 9 | 34, 35 | `gap_hi_arg2` | 1 | `g + arg2_mask·arg2_gap_hi` |
| 10 | 36, 37 | `gap_lo_arg2` | 1 | `g + arg2_mask + 4·arg2_mask·cycle − arg2_mask·arg2_read_ts − 2^19·arg2_mask·arg2_gap_hi` |
| 11 | 38, 39 | `gap_hi_ram` | 1 | `g + ram_mask·ram_gap_hi` |
| 12 | 40, 41 | `gap_lo_ram` | 1 | `g + 2·ram_mask + 4·ram_mask·cycle − ram_mask·ram_read_ts − 2^19·ram_mask·ram_gap_hi` |
| 13 | 42, 43 | `gap_hi_rd` | 1 | `g + rd_mask·rd_gap_hi` |
| 14 | 44, 45 | `gap_lo_rd` | 1 | `g + 2·rd_mask + 4·rd_mask·cycle − rd_mask·rd_read_ts − 2^19·rd_mask·rd_gap_hi` |
| 15 | 46, 47 | `timestamp_pad_0` | 0 | 1 |

The linear term on a `gap_lo` denominator's mask is `(Δ_q − 1)·m`: `−1` for pc, none for rs1,
`+1` for rs2, arg1 and arg2, `+2` for ram and rd. In positional form fraction 2's denominator is
`g − M[1] + 4·M[1]·M[0] − M[1]·M[3] − 2^19·M[1]·W[0]`.

**The `range16` fraction tree**, `L1[48..64]`: 8 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 48, 49 | `range16_table` | `−mult_range16` | `V[range16] + g` |
| 1 | 50, 51 | `rd_hi_range` | 1 | `g + pc_mask·rd_hi` |
| 2 | 52, 53 | `rd_lo_range` | 1 | `g + pc_mask·rd_selected − 2^16·pc_mask·rd_hi` |
| 3 | 54, 55 | `next_pc_hi_range` | 1 | `g + pc_mask·next_pc_hi` |
| 4 | 56, 57 | `next_pc_lo_range` | 1 | `g + pc_mask·pc_write_value − 2^16·pc_mask·next_pc_hi` |
| 5 | 58, 59 | `range16_pad_0` | 0 | 1 |
| 6 | 60, 61 | `range16_pad_1` | 0 | 1 |
| 7 | 62, 63 | `range16_pad_2` | 0 | 1 |

**The `decoder` fraction tree**, `L1[64..68]`: 2 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 64, 65 | `decoder_table` | `−mult_decoder` | `table_pc + β·table_next_pc + β²·table_rs1 + β³·table_rs2 + β⁴·table_rd + β⁵·table_imm + β⁶·table_extra_mask + g` |
| 1 | 66, 67 | `decode_row` | 1 | `g_dec + (1 + β + β² + β³ + β⁴ + β⁵ + β⁶)·pc_mask + pc_mask·pc_read_value + β·pc_mask·decoded_next_pc + β²·pc_mask·decoded_rs1 + β³·pc_mask·decoded_rs2 + β⁴·pc_mask·decoded_rd + β⁵·pc_mask·decoded_imm + β⁶·pc_mask·decoded_mask` |

```text
L{1}[67]  decode_row_den
  positional  g_dec + M[1] + β·M[1] + β²·M[1] + β³·M[1] + β⁴·M[1] + β⁵·M[1] + β⁶·M[1]
              + M[1]·M[4] + β·M[1]·W[10] + β²·M[1]·W[11] + β³·M[1]·W[12]
              + β⁴·M[1]·W[13] + β⁵·M[1]·W[14] + β⁶·M[1]·W[15]
  reads as    g + Σ_j β^j·(pc_mask·(v_j + 1) − 1), v = (pc_read_value, decoded_next_pc, …,
              decoded_mask):
              the claimed row at pc_mask = 1, and the table's MINUS_ONE padding row at 0
```

### 3.5 Gate list 0: the 46 enforcing gates

Relations 68–113, in list order. Each block gives the relation number, the name, what the gate
is for, its shape and degree, the constructor, the stored positional form, and the named form,
factored where that is easier to read. Every factoring re-expands to the stored terms.

**A. The frame's gates (68–82)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
68–74   <q>_mask_boolean — each query's presence flag is a bit          Quadratic, degree 2
        code  memory::booleanity(frame(s, FIELD_MASK)), in frame_body

  68 pc_mask_boolean     0 = M[1]  − M[1]·M[1]      0 = pc_mask   − pc_mask²
  69 rs1_mask_boolean    0 = M[6]  − M[6]·M[6]      0 = rs1_mask  − rs1_mask²
  70 rs2_mask_boolean    0 = M[11] − M[11]·M[11]    0 = rs2_mask  − rs2_mask²
  71 arg1_mask_boolean   0 = M[16] − M[16]·M[16]    0 = arg1_mask − arg1_mask²
  72 arg2_mask_boolean   0 = M[21] − M[21]·M[21]    0 = arg2_mask − arg2_mask²
  73 ram_mask_boolean    0 = M[26] − M[26]·M[26]    0 = ram_mask  − ram_mask²
  74 rd_mask_boolean     0 = M[31] − M[31]·M[31]    0 = rd_mask   − rd_mask²

  reads as  a leaf is 1 or its tuple only at a mask of 0 or 1; a mask of −1 on a pc query
            flips both leaves' signs and reads as a REG query (memory.md §2.4). Every mask
            is also a lookup selector, which validate requires to be boolean.

────────────────────────────────────────────────────────────────────────────────────────────
75–78   <q>_writes_back — a read-only register is left unchanged        Linear, degree 1
        code  memory::write_back(s), in frame_body

  75 rs1_writes_back     0 = M[10] − M[9]     0 = rs1_write_value  − rs1_read_value
  76 rs2_writes_back     0 = M[15] − M[14]    0 = rs2_write_value  − rs2_read_value
  77 arg1_writes_back    0 = M[20] − M[19]    0 = arg1_write_value − arg1_read_value
  78 arg2_writes_back    0 = M[25] − M[24]    0 = arg2_write_value − arg2_read_value

  reads as  a query that only reads writes back what it read, so reading x0 cannot put 5 in it.

────────────────────────────────────────────────────────────────────────────────────────────
79      rd_is_zero_inverse — the x0 flag, with gate 80                  Quadratic, degree 2
        code  memory::x0_gates(6, 7)[0]

  positional  0 = W[8] − M[31] + M[32]·W[7]
  named       0 = rd_addr·rd_inv + rd_is_zero − rd_mask

────────────────────────────────────────────────────────────────────────────────────────────
80      rd_is_zero_at_nonzero — no x0 flag at a real register           Quadratic, degree 2
        code  x0_gates(6, 7)[1]

  positional  0 = M[32]·W[8]
  named       0 = rd_addr·rd_is_zero

  reads as (79 with 80)  at rd_addr ≠ 0: rd_is_zero = 0 and rd_addr·rd_inv = rd_mask, so
                         rd_inv = 1/rd_addr on a live rd query (rd_mask = 1) and 0 where
                         rd_mask = 0.
                         at rd_addr = 0: rd_is_zero = rd_mask.
                         So the flag is 1 exactly on a live rd query at x0.

────────────────────────────────────────────────────────────────────────────────────────────
81      rd_is_zero_boolean                                              Quadratic, degree 2
        code  x0_gates(6, 7)[2]

  positional  0 = W[8] − W[8]·W[8]
  named       0 = rd_is_zero − rd_is_zero²

────────────────────────────────────────────────────────────────────────────────────────────
82      rd_write_masked — a write into x0 writes 0                      Quadratic, degree 2
        code  x0_gates(6, 7)[3]

  positional  0 = M[35] − W[9] + W[8]·W[9]
  named       0 = rd_write_value − (1 − rd_is_zero)·rd_selected

  reads as  the rd write is the computed result, except into x0, where it is 0. With the
            write-backs and x0's initial 0, every read of x0 returns 0.
```

**B. What the row is (83–95)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
83–88   kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2
        code  add_sub::booleanity(KINDS[k])

  83 kind_system_boolean   0 = W[16] − W[16]·W[16]    0 = kind_system − kind_system²
  84 kind_addi_boolean     0 = W[17] − W[17]·W[17]    0 = kind_addi   − kind_addi²
  85 kind_auipc_boolean    0 = W[18] − W[18]·W[18]    0 = kind_auipc  − kind_auipc²
  86 kind_add_boolean      0 = W[19] − W[19]·W[19]    0 = kind_add    − kind_add²
  87 kind_sub_boolean      0 = W[20] − W[20]·W[20]    0 = kind_sub    − kind_sub²
  88 kind_lui_boolean      0 = W[21] − W[21]·W[21]    0 = kind_lui    − kind_lui²

────────────────────────────────────────────────────────────────────────────────────────────
89      decoded_mask_bits — the packed mask is its six bits             Linear, degree 1
        code  add_sub::artifact, `bits`

  positional  0 = W[16] + 2·W[17] + 4·W[18] + 8·W[19] + 16·W[20] + 32·W[21] − W[15]
  named       0 = kind_system + 2·kind_addi + 4·kind_auipc + 8·kind_add + 16·kind_sub
                  + 32·kind_lui − decoded_mask

  reads as  the bits are the mask the decoder lookup binds. One-hotness is not here: on a
            live row an all-zero mask satisfies all 46 gates, and only the decoder table,
            whose masks are single bits, refuses it (lookup.md §10). Two bits that each ask
            for an rd write (any two of addi, auipc, add, sub, lui, or the system bit read as
            is_ecall beside one of them) are refused by 101 with 74, since rd_mask comes out
            2. The system bit read as is_fence beside any one other bit passes every gate,
            and only the decoder table refuses it. On a padding row the decoder lookup is
            off, so no table row binds the bits and only the gates above constrain them; the
            honest fill writes 0.

────────────────────────────────────────────────────────────────────────────────────────────
90      is_ecall_boolean      0 = W[22] − W[22]·W[22]      0 = is_ecall − is_ecall²
91      is_fence_boolean      0 = W[23] − W[23]·W[23]      0 = is_fence − is_fence²
        Quadratic, degree 2; code  add_sub::booleanity

────────────────────────────────────────────────────────────────────────────────────────────
92      system_split — a system row is exactly one of exit and fence    Linear, degree 1
        code  add_sub::artifact

  positional  0 = W[22] + W[23] − W[16]
  named       0 = is_ecall + is_fence − kind_system

────────────────────────────────────────────────────────────────────────────────────────────
93      ecall_code — an exit row's code is ECALL                        Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = W[22]·W[14]
  named       0 = is_ecall·decoded_imm

  reads as  is_ecall = 1 needs code 0; this reads "the code is ECALL" only because
            system_code::ECALL is 0, which a const assertion in add_sub.rs pins.

────────────────────────────────────────────────────────────────────────────────────────────
94      fence_code — a fence row's code is FENCE                        Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = −2·W[23] + W[23]·W[14]
  named       0 = is_fence·(decoded_imm − 2)

  reads as (92, 93, 94)  a system row with code 1, EBREAK, can set neither flag, and
                         system_split then fails: no ebreak row is provable.

────────────────────────────────────────────────────────────────────────────────────────────
95      ecall_is_exit — every ecall is EXIT                             Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = −93·W[22] + W[22]·M[9]
  named       0 = is_ecall·(rs1_read_value − 93)

  reads as  an exit row's rs1 query, which reads a7 (gate 102), reads 93.
```

**C. Which queries a row makes, and where (96–106)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
96      rs1_mask_rule — rs1 is read exactly by add, sub, addi, exit     Quadratic, degree 2
        code  add_sub::mask_rule(frame(1, FIELD_MASK), [KIND_ADD, KIND_SUB, KIND_ADDI, IS_ECALL])

  positional  0 = M[6] − M[1]·W[19] − M[1]·W[20] − M[1]·W[17] − M[1]·W[22]
  named       0 = rs1_mask − pc_mask·(kind_add + kind_sub + kind_addi + is_ecall)

────────────────────────────────────────────────────────────────────────────────────────────
97      rs2_mask_rule — rs2 is read exactly by add, sub, exit           Quadratic, degree 2
        code  mask_rule(frame(2, FIELD_MASK), [KIND_ADD, KIND_SUB, IS_ECALL])

  positional  0 = M[11] − M[1]·W[19] − M[1]·W[20] − M[1]·W[22]
  named       0 = rs2_mask − pc_mask·(kind_add + kind_sub + is_ecall)

────────────────────────────────────────────────────────────────────────────────────────────
98      arg1_mask_rule        0 = M[16]      0 = arg1_mask
99      arg2_mask_rule        0 = M[21]      0 = arg2_mask
100     ram_mask_rule         0 = M[26]      0 = ram_mask
        Linear, degree 1; code  add_sub::artifact

  reads as  no row reads a1 or a2 or touches RAM: EXIT takes neither argument, and no
            transfer cycle is provable at S16.

────────────────────────────────────────────────────────────────────────────────────────────
101     rd_mask_rule — rd is written by every kind but the fence        Quadratic, degree 2
        code  mask_rule(frame(6, FIELD_MASK),
                        [KIND_ADD, KIND_SUB, KIND_ADDI, KIND_AUIPC, KIND_LUI, IS_ECALL])

  positional  0 = M[31] − M[1]·W[19] − M[1]·W[20] − M[1]·W[17] − M[1]·W[18] − M[1]·W[21]
                  − M[1]·W[22]
  named       0 = rd_mask − pc_mask·(kind_add + kind_sub + kind_addi + kind_auipc
                                     + kind_lui + is_ecall)

  reads as (96, 97, 101)  on a live row the bits are one-hot, so each sum is 0 or 1 and the
                          mask is the kind's use of the query. On a padding row pc_mask = 0
                          and every mask is 0, whatever the bits hold.

────────────────────────────────────────────────────────────────────────────────────────────
102     rs1_addr_rule — rs1's register is the decoded one, or a7        Quadratic, degree 2
        code  add_sub::addr_rule(1, DECODED_RS1, 17)

  positional  0 = M[6]·M[7] − M[6]·W[11] − 17·M[6]·W[22]
  named       0 = rs1_mask·(rs1_addr − decoded_rs1 − 17·is_ecall)

────────────────────────────────────────────────────────────────────────────────────────────
103     rs2_addr_rule — rs2's register is the decoded one, or a0        Quadratic, degree 2
        code  addr_rule(2, DECODED_RS2, 10)

  positional  0 = M[11]·M[12] − M[11]·W[12] − 10·M[11]·W[22]
  named       0 = rs2_mask·(rs2_addr − decoded_rs2 − 10·is_ecall)

────────────────────────────────────────────────────────────────────────────────────────────
104     rd_addr_rule — rd's register is the decoded one, or a0          Quadratic, degree 2
        code  addr_rule(6, DECODED_RD, 10)

  positional  0 = M[31]·M[32] − M[31]·W[13] − 10·M[31]·W[22]
  named       0 = rd_mask·(rd_addr − decoded_rd − 10·is_ecall)

  reads as (102–104)  a present query's register is the table's; a system row's decoded
                      registers are 0, so on the exit row the constants name a7 and a0.

────────────────────────────────────────────────────────────────────────────────────────────
105     rs1_value_masked — an absent rs1 reads 0                        Quadratic, degree 2
        code  add_sub::value_masked(1)

  positional  0 = M[9] − M[6]·M[9]
  named       0 = (1 − rs1_mask)·rs1_read_value

────────────────────────────────────────────────────────────────────────────────────────────
106     rs2_value_masked — an absent rs2 reads 0                        Quadratic, degree 2
        code  value_masked(2)

  positional  0 = M[14] − M[11]·M[14]
  named       0 = (1 − rs2_mask)·rs2_read_value

  reads as (105, 106)  the sum gate can add both operands on every kind: an addi row's
                       absent rs2, and an auipc row's absent rs1 and rs2, add 0.
```

**D. What the row computes (107–113)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
107     add_addi_auipc — the three sums, one gate                       Quadratic, degree 2
        code  add_sub::artifact, the `sum` loop over [KIND_ADD, KIND_ADDI, KIND_AUIPC]

  positional  0 = W[19]·M[9] + W[19]·M[14] + W[19]·W[14] − W[19]·W[9] − 2^32·W[19]·W[24]
                + W[17]·M[9] + W[17]·M[14] + W[17]·W[14] − W[17]·W[9] − 2^32·W[17]·W[24]
                + W[18]·M[9] + W[18]·M[14] + W[18]·W[14] − W[18]·W[9] − 2^32·W[18]·W[24]
                + W[18]·M[4]
  named, factored
    0 =   kind_add   · ( rs1_read_value + rs2_read_value + decoded_imm − rd_selected − 2^32·wrap )
        + kind_addi  · ( rs1_read_value + rs2_read_value + decoded_imm − rd_selected − 2^32·wrap )
        + kind_auipc · ( rs1_read_value + rs2_read_value + decoded_imm − rd_selected − 2^32·wrap
                         + pc_read_value )

  reads as  one kind at a time:
              add    rs1 + rs2 = sel + 2^32·wrap      its imm is 0, bound by the decoder table
              addi   rs1 + imm = sel + 2^32·wrap      its rs2 is absent and reads 0
              auipc  pc + imm  = sel + 2^32·wrap      its rs1 and rs2 are absent and read 0
            With sel range-checked below 2^32 and wrap a bit, sel is the RISC-V sum and wrap
            its carry: both addends are below 2^32, so the sum is below 2^33.

────────────────────────────────────────────────────────────────────────────────────────────
108     sub — the difference                                            Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = W[20]·M[9] − W[20]·M[14] − W[20]·W[9] + 2^32·W[20]·W[24]
  named       0 = kind_sub·(rs1_read_value − rs2_read_value − rd_selected + 2^32·wrap)

  reads as  rs1 − rs2 = sel − 2^32·wrap: wrap is the borrow.

────────────────────────────────────────────────────────────────────────────────────────────
109     lui — the loaded value                                          Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = W[21]·W[14] − W[21]·W[9]
  named       0 = kind_lui·(decoded_imm − rd_selected)

────────────────────────────────────────────────────────────────────────────────────────────
110     exit_status — the exit row writes a0 back                       Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = W[22]·M[34] − W[22]·W[9]
  named       0 = is_ecall·(rd_read_value − rd_selected)

  reads as  the exit row's result is a0 as read, and its rd query is x10, so x10's final
            value is the exit status verify_shard's step 10 compares with v_10.

────────────────────────────────────────────────────────────────────────────────────────────
111     wrap_boolean          0 = W[24] − W[24]·W[24]      0 = wrap − wrap²
112     pc_wrap_boolean       0 = W[26] − W[26]·W[26]      0 = pc_wrap − pc_wrap²
        Quadratic, degree 2; code  add_sub::booleanity

────────────────────────────────────────────────────────────────────────────────────────────
113     next_pc_rule — the fall-through, or HALT_PC on the exit row     Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = M[5] + 2^32·W[26] − W[10] − W[22] + W[22]·W[10]
  named       0 = pc_write_value + 2^32·pc_wrap − (1 − is_ecall)·decoded_next_pc
                  − HALT_PC·is_ecall                                  (HALT_PC = 1)

  reads as  next_pc + 2^32·pc_wrap is decoded_next_pc on every row but the exit row, and 1
            (HALT_PC) there. On a live row decoded_next_pc is the table's fall-through,
            bound by decode_row; on a padding row nothing else binds decoded_next_pc, so it
            and next_pc are free together (the honest fill writes 0 in both). next_pc is
            range-checked below 2^32 on a live row and the fall-through is below 2^31, so
            pc_wrap is 0 on every live row.
```

Of the 46 gates, 9 are degree 1: the four write-backs, `decoded_mask_bits`, `system_split` and
the three `arg1`/`arg2`/`ram` mask rules. All 46 have constant 0, so each is 0 on the all-zero
row, and the private `memory::assemble` records `zero_row_valid = true`
(`build::zero_on_zero_row`). The padding row itself is all zeros in every assembled artifact
(`build::assemble`), whatever its gates.

### 3.6 The 19 lookups

`CircuitArtifact::lookups`, in order. The frame's 14 come from the private
`memory::gap_lookups`; the rest from `add_sub::artifact` (`range16`, `low_half` and the inline
`decode_row`).

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `gap_hi_pc` | `TIMESTAMP` (0) | `M[1]` | `W[0]` | `pc_gap_hi` | `< 2^19` |
| 1 | `gap_lo_pc` | `TIMESTAMP` | `M[1]` | `4·M[0] − M[3] − 2^19·W[0] − 1` | `4·cycle − pc_read_ts − 2^19·pc_gap_hi − 1` | `< 2^19` |
| 2 | `gap_hi_rs1` | `TIMESTAMP` | `M[6]` | `W[1]` | `rs1_gap_hi` | `< 2^19` |
| 3 | `gap_lo_rs1` | `TIMESTAMP` | `M[6]` | `4·M[0] − M[8] − 2^19·W[1]` | `4·cycle − rs1_read_ts − 2^19·rs1_gap_hi` | `< 2^19` |
| 4 | `gap_hi_rs2` | `TIMESTAMP` | `M[11]` | `W[2]` | `rs2_gap_hi` | `< 2^19` |
| 5 | `gap_lo_rs2` | `TIMESTAMP` | `M[11]` | `4·M[0] − M[13] − 2^19·W[2] + 1` | `4·cycle − rs2_read_ts − 2^19·rs2_gap_hi + 1` | `< 2^19` |
| 6 | `gap_hi_arg1` | `TIMESTAMP` | `M[16]` | `W[3]` | `arg1_gap_hi` | `< 2^19` |
| 7 | `gap_lo_arg1` | `TIMESTAMP` | `M[16]` | `4·M[0] − M[18] − 2^19·W[3] + 1` | `4·cycle − arg1_read_ts − 2^19·arg1_gap_hi + 1` | `< 2^19` |
| 8 | `gap_hi_arg2` | `TIMESTAMP` | `M[21]` | `W[4]` | `arg2_gap_hi` | `< 2^19` |
| 9 | `gap_lo_arg2` | `TIMESTAMP` | `M[21]` | `4·M[0] − M[23] − 2^19·W[4] + 1` | `4·cycle − arg2_read_ts − 2^19·arg2_gap_hi + 1` | `< 2^19` |
| 10 | `gap_hi_ram` | `TIMESTAMP` | `M[26]` | `W[5]` | `ram_gap_hi` | `< 2^19` |
| 11 | `gap_lo_ram` | `TIMESTAMP` | `M[26]` | `4·M[0] − M[28] − 2^19·W[5] + 2` | `4·cycle − ram_read_ts − 2^19·ram_gap_hi + 2` | `< 2^19` |
| 12 | `gap_hi_rd` | `TIMESTAMP` | `M[31]` | `W[6]` | `rd_gap_hi` | `< 2^19` |
| 13 | `gap_lo_rd` | `TIMESTAMP` | `M[31]` | `4·M[0] − M[33] − 2^19·W[6] + 2` | `4·cycle − rd_read_ts − 2^19·rd_gap_hi + 2` | `< 2^19` |
| 14 | `rd_hi_range` | `RANGE16` (1) | `M[1]` | `W[25]` | `rd_hi` | `< 2^16` |
| 15 | `rd_lo_range` | `RANGE16` | `M[1]` | `W[9] − 2^16·W[25]` | `rd_selected − 2^16·rd_hi` | `< 2^16` |
| 16 | `next_pc_hi_range` | `RANGE16` | `M[1]` | `W[27]` | `next_pc_hi` | `< 2^16` |
| 17 | `next_pc_lo_range` | `RANGE16` | `M[1]` | `M[5] − 2^16·W[27]` | `pc_write_value − 2^16·next_pc_hi` | `< 2^16` |
| 18 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[10], W[11], W[12], W[13], W[14], W[15])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_imm, decoded_mask)` | a row of `S[0..7]` |

Read in pairs: `gap_hi_<q>` and `gap_lo_<q>` together say
`gap = 4·cycle + Δ_q − <q>_read_ts − 1 = lo + 2^19·hi` lies in `[0, 2^38)`, so the read strictly
precedes its own write. `rd_hi_range` and `rd_lo_range` bound `rd_selected` below `2^32`, and
the `next_pc` pair bounds the next pc the same way (`memory.md` §7's range convention).

The channels, `add_sub::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[28]` | 14 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[29]` | 4 | 8 |
| 6, 7 | `DECODER` | 3 | `S[0..7]` | `W[30]` | 1 | 2 |

`GENERIC` (2) is not used here. S17's jump/branch/slt family is the first to look it up. S17
put the packed table's three commitments in every verifying key, whatever its families, and
folded them into the SRS digest, which the global transcript absorbs before any challenge;
program identity does not bind them. This family's shard opening does not list them, its
circuit reading no generic channel (§4.3, §4.6, `shard-proof.md` §8.5,
`jump-branch-slt.md` §6).

### 3.7 Inner layers `L2`–`L5`: the row-wise reduction

Every column here is a per-row value, never committed. `a·b` is a `Product`, `a + b` a
fraction-node pair (§0.6), `copy` a `Linear` copy of each column. A fraction node `<node>` is
two columns named `<node>_num` and `<node>_den` (relations `define_<node>_num` and
`define_<node>_den`), as in §3.4; a product node is one column named `<node>`.

**`L2`, gate list 1, 34 columns, relations 114–147.**

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 114 | `read_2_0` | `read_pc · read_rs1` |
| 1 | 115 | `read_2_1` | `read_rs2 · read_arg1` |
| 2 | 116 | `read_2_2` | `read_arg2 · read_ram` |
| 3 | 117 | `read_2_3` | `read_rd · read_pad_0` |
| 4 | 118 | `write_2_0` | `write_pc · write_rs1` |
| 5 | 119 | `write_2_1` | `write_rs2 · write_arg1` |
| 6 | 120 | `write_2_2` | `write_arg2 · write_ram` |
| 7 | 121 | `write_2_3` | `write_rd · write_pad_0` |
| 8, 9 | 122, 123 | `timestamp_2_0` | `timestamp_table + gap_hi_pc` |
| 10, 11 | 124, 125 | `timestamp_2_1` | `gap_lo_pc + gap_hi_rs1` |
| 12, 13 | 126, 127 | `timestamp_2_2` | `gap_lo_rs1 + gap_hi_rs2` |
| 14, 15 | 128, 129 | `timestamp_2_3` | `gap_lo_rs2 + gap_hi_arg1` |
| 16, 17 | 130, 131 | `timestamp_2_4` | `gap_lo_arg1 + gap_hi_arg2` |
| 18, 19 | 132, 133 | `timestamp_2_5` | `gap_lo_arg2 + gap_hi_ram` |
| 20, 21 | 134, 135 | `timestamp_2_6` | `gap_lo_ram + gap_hi_rd` |
| 22, 23 | 136, 137 | `timestamp_2_7` | `gap_lo_rd + timestamp_pad_0` |
| 24, 25 | 138, 139 | `range16_2_0` | `range16_table + rd_hi_range` |
| 26, 27 | 140, 141 | `range16_2_1` | `rd_lo_range + next_pc_hi_range` |
| 28, 29 | 142, 143 | `range16_2_2` | `next_pc_lo_range + range16_pad_0` |
| 30, 31 | 144, 145 | `range16_2_3` | `range16_pad_1 + range16_pad_2` |
| 32, 33 | 146, 147 | `decoder_2_0` | `decoder_table + decode_row` |

Positionally, `timestamp_2_0` is `L{2}[8] = L{1}[16]·L{1}[19] + L{1}[18]·L{1}[17]` and
`L{2}[9] = L{1}[17]·L{1}[19]`: `−mult/(T + g) + 1/(E_gap_hi_pc + g)`, the node `lookup.md` §6
puts first on purpose.

**`L3`, gate list 2, 18 columns, relations 148–165.**

| `L3` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 148 | `read_3_0` | `read_2_0 · read_2_1` |
| 1 | 149 | `read_3_1` | `read_2_2 · read_2_3` |
| 2 | 150 | `write_3_0` | `write_2_0 · write_2_1` |
| 3 | 151 | `write_3_1` | `write_2_2 · write_2_3` |
| 4, 5 | 152, 153 | `timestamp_3_0` | `timestamp_2_0 + timestamp_2_1` |
| 6, 7 | 154, 155 | `timestamp_3_1` | `timestamp_2_2 + timestamp_2_3` |
| 8, 9 | 156, 157 | `timestamp_3_2` | `timestamp_2_4 + timestamp_2_5` |
| 10, 11 | 158, 159 | `timestamp_3_3` | `timestamp_2_6 + timestamp_2_7` |
| 12, 13 | 160, 161 | `range16_3_0` | `range16_2_0 + range16_2_1` |
| 14, 15 | 162, 163 | `range16_3_1` | `range16_2_2 + range16_2_3` |
| 16, 17 | 164, 165 | `decoder_3_0` | copy of `decoder_2_0` |

**`L4`, gate list 3, 10 columns, relations 166–175.**

| `L4` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 166 | `read_4_0` | `read_3_0 · read_3_1` |
| 1 | 167 | `write_4_0` | `write_3_0 · write_3_1` |
| 2, 3 | 168, 169 | `timestamp_4_0` | `timestamp_3_0 + timestamp_3_1` |
| 4, 5 | 170, 171 | `timestamp_4_1` | `timestamp_3_2 + timestamp_3_3` |
| 6, 7 | 172, 173 | `range16_4_0` | `range16_3_0 + range16_3_1` |
| 8, 9 | 174, 175 | `decoder_4_0` | copy of `decoder_3_0` |

**`L5`, gate list 4, 8 columns, relations 176–183** — the row-wise top: one value per row per
tree.

| `L5` | relations | node | formula | value at row `y` |
| --- | --- | --- | --- | --- |
| 0 | 176 | `read_5_0` | copy of `read_4_0` | the product of row `y`'s 8 read leaves |
| 1 | 177 | `write_5_0` | copy of `write_4_0` | the product of row `y`'s 8 write leaves |
| 2, 3 | 178, 179 | `timestamp_5_0` | `timestamp_4_0 + timestamp_4_1` | the sum of row `y`'s 16 timestamp fractions |
| 4, 5 | 180, 181 | `range16_5_0` | copy of `range16_4_0` | the sum of row `y`'s 8 range16 fractions |
| 6, 7 | 182, 183 | `decoder_5_0` | copy of `decoder_4_0` | the sum of row `y`'s 2 decoder fractions |

`checker::memory_roots` recomputes the two roots from `L5[0]` and `L5[1]`, the layer the first
halving list reads.

### 3.8 The halving layers and the outputs

Gate list `k`, for `5 ≤ k ≤ n + 4`, halves layer `k` into layer `k + 1`, which has
`n + 4 − k` variables. Its eight gates, relation `r = 184 + 8(k − 5)`:

| `L{k+1}` | relation | node | shape | formula |
| --- | --- | --- | --- | --- |
| 0 | `r` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` | `L{k}[0](y,0) · L{k}[0](y,1)` |
| 1 | `r + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` | `L{k}[1](y,0) · L{k}[1](y,1)` |
| 2 | `r + 2` | `timestamp_{k+1}_0_num` | `TreeCross { L{k}[2], L{k}[3] }` | `L{k}[2](y,0)·L{k}[3](y,1) + L{k}[2](y,1)·L{k}[3](y,0)` |
| 3 | `r + 3` | `timestamp_{k+1}_0_den` | `TreeProduct { L{k}[3] }` | `L{k}[3](y,0) · L{k}[3](y,1)` |
| 4 | `r + 4` | `range16_{k+1}_0_num` | `TreeCross { L{k}[4], L{k}[5] }` | `L{k}[4](y,0)·L{k}[5](y,1) + L{k}[4](y,1)·L{k}[5](y,0)` |
| 5 | `r + 5` | `range16_{k+1}_0_den` | `TreeProduct { L{k}[5] }` | `L{k}[5](y,0) · L{k}[5](y,1)` |
| 6 | `r + 6` | `decoder_{k+1}_0_num` | `TreeCross { L{k}[6], L{k}[7] }` | `L{k}[6](y,0)·L{k}[7](y,1) + L{k}[6](y,1)·L{k}[7](y,0)` |
| 7 | `r + 7` | `decoder_{k+1}_0_den` | `TreeProduct { L{k}[7] }` | `L{k}[7](y,0) · L{k}[7](y,1)` |

In the last list, `k = n + 4`, the eight nodes are named `read_root`, `write_root`,
`timestamp_num_root`, `timestamp_den_root`, `range16_num_root`, `range16_den_root`,
`decoder_num_root` and `decoder_den_root`. At `n = 20` the halving lists are 5 to 24, `L6` has
19 variables and `L25` none. At `n = 22` they are 5 to 26, and the top is `L27`.

**The outputs**, in output-map order. All eight are absorbed as one `GKR_OUTPUTS` message
(`gkr.md` §5.2, O1) before any challenge of the backward pass (the top has no variables, so O2
draws no point), and travel in `ShardProof::outputs`.

| # | address, `n = 20` | node | value | what `verify_shard` does with it |
| --- | --- | --- | --- | --- |
| 0 | `L{25}[0]` | `read_root` | the product of every read leaf of the shard | step 10: must equal `PublicInputs::memory_roots[p][0]`, `p` being the position of `(0, shard_index)` in `verifier_core::statement_shards`, after `INIT_TEARDOWN`'s shard and every `ZERO_WINDOWS` shard (`shard-proof.md` §1.2); a factor of `reconciles` |
| 1 | `L{25}[1]` | `write_root` | the product of every write leaf | step 10: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |
| 2 | `L{25}[2]` | `timestamp_num_root` | the numerator of the channel's summed fraction `Σ num/den` over every leaf of every row, written over the product of all its denominators | step 9, `channel_holds`: must be 0; otherwise `Lookup { channel: 0 }` |
| 3 | `L{25}[3]` | `timestamp_den_root` | that product of denominators | step 9: must be nonzero; otherwise `Lookup { channel: 0 }` |
| 4 | `L{25}[4]` | `range16_num_root` | as output 2, for `RANGE16` | step 9: must be 0; otherwise `Lookup { channel: 1 }` |
| 5 | `L{25}[5]` | `range16_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 1 }` |
| 6 | `L{25}[6]` | `decoder_num_root` | as output 2, for `DECODER` | step 9: must be 0; otherwise `Lookup { channel: 3 }` |
| 7 | `L{25}[7]` | `decoder_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 3 }` |

`reconciles` holds when `∏ read roots · R_b = ∏ write roots · W_b` and `∏ read roots · R_b ≠ 0`,
the products running over every shard of the statement, with the boundary factors `(W_b, R_b)`
of `memory.md` §4.2.

### 3.9 Witness rows

The table shows nine of the sixteen `honest_rows` in `crates/checker/tests/add_sub.rs`. The
other seven are `add, not carrying`, `sub, not borrowing`, `addi from x0, as c.li` (a 4-byte
`addi`, despite its name), `auipc, not carrying`, `sub to x0, borrowing`, `nop`
(`addi x0, x0, 0`) and `c.add, two bytes` (an `add` whose fall-through is `0x10012`); §3.10
probes all sixteen. Each row is built from Rust's own `u32` arithmetic, and
`every_row_kind_satisfies_every_gate_and_every_bound` holds it to every gate and range
obligation in CI.

A row is checked alone, so three things differ from a real shard. **Every read timestamp is
synthetic**: each register query reads a write made 8 timestamps before its own and the pc
query the previous cycle's, which fixes every gap at 7, or 3 for the pc, and leaves every
`<q>_gap_hi` 0. The multiplicities, which count over a whole shard (§0.3), are left 0. And the
test sets the `S` columns on each live row to that row's own table entry, where a shard indexes
them by pc, not by cycle; the table below omits them. Every live row shown has cycle 9, pc
`0x10010` and a 4-byte instruction, and `P` is 0 in every cell.

`A` add, carrying: `x7 = x5 + x6`, `0xffffefff + 0x12345678`. `B` sub, borrowing:
`x29 = x6 − x5`. `C` addi of −1, carrying: `x5 = x5 − 1`. `D` auipc, carrying:
`x31 = pc + 0xfffff000`. `E` lui: `x6 = 0x12345000`. `F` add into `x0`, carrying. `G` fence.
`H` exit 42. `P` padding.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[2]` `pc_addr` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `M[3]` `pc_read_ts` | 32 | 32 | 32 | 32 | 32 | 32 | 32 | 32 | 0 |
| `M[4]` `pc_read_value` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | 0 |
| `M[5]` `pc_write_value` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | 1 | 0 |
| `M[6]` `rs1_mask` | 1 | 1 | 1 | 0 | 0 | 1 | 0 | 1 | 0 |
| `M[7]` `rs1_addr` | 5 | 6 | 5 | 0 | 0 | 5 | 0 | 17 | 0 |
| `M[8]` `rs1_read_ts` | 29 | 29 | 29 | 0 | 0 | 29 | 0 | 29 | 0 |
| `M[9]`, `M[10]` `rs1_read_value`, `rs1_write_value` | `0xffffefff` | `0x12345678` | `0xfffff000` | 0 | 0 | `0xffffefff` | 0 | 93 | 0 |
| `M[11]` `rs2_mask` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 1 | 0 |
| `M[12]` `rs2_addr` | 6 | 5 | 0 | 0 | 0 | 6 | 0 | 10 | 0 |
| `M[13]` `rs2_read_ts` | 30 | 30 | 0 | 0 | 0 | 30 | 0 | 30 | 0 |
| `M[14]`, `M[15]` `rs2_read_value`, `rs2_write_value` | `0x12345678` | `0xffffefff` | 0 | 0 | 0 | `0x12345678` | 0 | 42 | 0 |
| `M[16..31]` arg1, arg2 and ram | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `M[31]` `rd_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 0 |
| `M[32]` `rd_addr` | 7 | 29 | 5 | 31 | 6 | 0 | 0 | 10 | 0 |
| `M[33]` `rd_read_ts` | 31 | 31 | 31 | 31 | 31 | 31 | 0 | 31 | 0 |
| `M[34]` `rd_read_value` | 3 | 1 | `0xfffff000` | 0 | 0 | 0 | 0 | 42 | 0 |
| `M[35]` `rd_write_value` | `0x12344677` | `0x12346679` | `0xffffefff` | `0xf010` | `0x12345000` | 0 | 0 | 42 | 0 |
| `W[0..7]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[7]` `rd_inv` | `7⁻¹` | `29⁻¹` | `5⁻¹` | `31⁻¹` | `6⁻¹` | 0 | 0 | `10⁻¹` | 0 |
| `W[8]` `rd_is_zero` | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `W[9]` `rd_selected` | `0x12344677` | `0x12346679` | `0xffffefff` | `0xf010` | `0x12345000` | `0x12344677` | 0 | 42 | 0 |
| `W[10]` `decoded_next_pc` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | 0 |
| `W[11]` `decoded_rs1` | 5 | 6 | 5 | 0 | 0 | 5 | 0 | 0 | 0 |
| `W[12]` `decoded_rs2` | 6 | 5 | 0 | 0 | 0 | 6 | 0 | 0 | 0 |
| `W[13]` `decoded_rd` | 7 | 29 | 5 | 31 | 6 | 0 | 0 | 0 | 0 |
| `W[14]` `decoded_imm` | 0 | 0 | `0xffffffff` | `0xfffff000` | `0x12345000` | 0 | 2 | 0 | 0 |
| `W[15]` `decoded_mask` | 8 | 16 | 2 | 4 | 32 | 8 | 1 | 1 | 0 |
| `W[16..22]` the kind bit set | `add` | `sub` | `addi` | `auipc` | `lui` | `add` | `system` | `system` | none |
| `W[22]` `is_ecall` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| `W[23]` `is_fence` | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[24]` `wrap` | 1 | 1 | 1 | 1 | 0 | 1 | 0 | 0 | 0 |
| `W[25]` `rd_hi` | `0x1234` | `0x1234` | `0xffff` | 0 | `0x1234` | `0x1234` | 0 | 0 | 0 |
| `W[26]` `pc_wrap` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[27]` `next_pc_hi` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0 |

`F` computes the same sum as `A` and writes 0: `rd_selected` still holds the result, and
`rd_write_masked` masks it. `H`'s decoded fall-through is `0x10014` while its next pc is 1.

### 3.10 What fixes each cell

All sixteen `honest_rows`, probed one cell at a time: a cell is listed below when adding 5 to
it alone breaks no gate and no range obligation, evaluated row-locally (as `violated_relations`
and `violated_lookups` evaluate a row). Adding 5 never probes a boolean column, whose
booleanity gate refuses 5, so each boolean column was also flipped between 0 and 1; that finds
two more cells, marked (flip). A cell listed is fixed, if at all, by something that is not
row-local: the **memory argument**, when the cell is in a leaf whose mask is 1; the **decoder
table**, when it is in `decode_row`'s tuple on a live row; or nothing. The multiplicities
`W[28..31]` appear on every row and are not a row's property at all.

A read timestamp is a case apart. Its gap obligations hold it only in
`[4·cycle + Δ_q − 2^38, 4·cycle + Δ_q)`, which the timestamp of any earlier write satisfies, so
the memory argument alone fixes it. `+5` happens to stay inside a register's synthetic gap of 7,
so `M[8]`, `M[13]` and `M[33]` show up on every row; the pc's gap is 3, so `M[3]` shows up on
padding alone, but on a live row a rise of 1 to 3 passes too, and so does a fall to any earlier
timestamp once `pc_gap_hi` is re-chosen (a fall of less than `2^19 − 3` passes with it unchanged).

| cell | fixed, on the rows that use it, by | rows where less fixes it, or nothing |
| --- | --- | --- |
| `M[0]` `cycle` | the memory argument (every write leaf's timestamp), with the gap obligations bounding it below | padding: nothing |
| `M[1]` `pc_mask` (flip) | its booleanity gate, the mask rules through the row's other masks, and the memory argument | fence: the memory argument alone (1 → 0 breaks no gate, since the row has no other query for a mask rule to tie to it, and it switches every lookup off); padding: 0 → 1 is refused by `gap_lo_pc`, whose gap becomes −1 |
| `M[2]` `pc_addr` | the memory argument alone: no gate holds it to 0, but a pc chain at any other address has no initial and no final tuple, and cannot balance (`memory.md` §4.2's counting) | padding: nothing |
| `M[4]` `pc_read_value` | the memory argument and the decoder table; on an auipc row, also `add_addi_auipc` | padding: nothing |
| `M[3]`, `M[8]`, `M[13]`, `M[33]` read timestamps | the memory argument alone; the gap obligations only hold each below its own write | rows without that query, padding included: nothing |
| `M[7]` `rs1_addr` | `rs1_addr_rule` | auipc, lui, fence, padding: nothing |
| `M[12]` `rs2_addr` | `rs2_addr_rule` | addi (nop included), auipc, lui, fence, padding: nothing |
| `M[32]` `rd_addr` | `rd_addr_rule` | fence, padding: nothing |
| `M[34]` `rd_read_value` | the memory argument; on the exit row, also `exit_status` | fence, padding: nothing |
| `M[17]`, `M[18]`, `M[22]`, `M[23]`, `M[27]`–`M[30]`; `W[3]`, `W[4]`, `W[5]` | nothing: the `arg1`, `arg2` and `ram` masks are 0 on every row | every row |
| `M[19]`/`M[20]` and `M[24]`/`M[25]`, each pair together | nothing but their write-back gate, which a pair moved together keeps | every row |
| `W[0]` `pc_gap_hi` | its gap obligations | padding: nothing |
| `W[1]`, `W[2]`, `W[6]` gap chunks | their gap obligations | rows without that query: nothing |
| `W[7]` `rd_inv` | `rd_is_zero_inverse`, where `rd_addr ≠ 0` | rows writing `x0` (nop included), fence, padding: nothing |
| `W[10]` `decoded_next_pc` | `next_pc_rule` and the decoder table | the exit row: the decoder table alone, since `next_pc_rule` cancels it there; padding: `next_pc_rule` alone, which only ties it to `pc_write_value` and `pc_wrap` |
| `W[11]` `decoded_rs1` | `rs1_addr_rule` and the decoder table | auipc, lui and fence rows: the decoder table alone; padding: nothing |
| `W[12]` `decoded_rs2` | `rs2_addr_rule` and the decoder table | addi, auipc, lui and fence rows: the decoder table alone; padding: nothing |
| `W[13]` `decoded_rd` | `rd_addr_rule` and the decoder table | fence rows: the decoder table alone; padding: nothing |
| `W[14]` `decoded_imm` | the gate its kind reads it in, and the decoder table | sub rows: the decoder table alone; padding: nothing |
| `W[24]` `wrap` (flip) | `add_addi_auipc` or `sub` | lui, fence, exit and padding rows: `wrap_boolean` alone, since the two gates that read it are gated off there |
| `W[25]` `rd_hi`, `W[27]` `next_pc_hi` | their range obligations | padding: nothing |

On a padding row every mask is 0 and every lookup is switched off, so no cell there reaches a
memory event or a table. The gates still hold `pc_write_value + 2^32·pc_wrap = decoded_next_pc`
and `rd_write_value = rd_selected` there; the honest fill writes 0 everywhere. A fence row,
whose `rd_mask` is 0, leaves the pair `rd_selected`, `rd_write_value` free but for its range
obligations: `rd_write_masked` holds the two equal (the row's `rd_is_zero` is 0),
`rd_hi_range` and `rd_lo_range` keep `rd_selected` below `2^32`, and nothing else reads either.

---

## 4. `JUMP_BRANCH_SLT` — family 1

### 4.1 Header

`family_circuit(1, n)` is `jump_branch_slt::artifact(n)` with `jump_branch_slt::channels()`,
built by `memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` with S17's two
gadgets, `constraints::gadgets::{is_zero, comparison}` (`QUERIES`, the `SLOT_*` constants and
the per-kind constants `SLTI` … `JAL` are private to `jump_branch_slt.rs`). Normative spec:
`jump-branch-slt.md`. Fill: `prover::family_fill(1)`, the private `fill::jump_branch_slt`.

75 committed columns (21 `M`, 44 `W`, 10 `S`) and two virtual tables. Gate list 0 writes 84
leaves and holds 42 enforcing gates. 22 lookups on four channels, 10 outputs. At `n = 20`, the
height S17 proves, there are 25 gate lists, the top is `L25`, and the circuit has 372 inner
columns and 414 relations; a shard proof of it is 61,612 bytes (`crates/prover/tests/control.rs`).
`artifact` panics unless the frame is `QUERIES`, the channels carry exactly 8, 11, 2 and 1
obligations, and `lookup::check_copowers` finds `next_pc`'s direct range pair beside
`next_pc_even`, which halves it. It also panics on every refusal of the assembly, among them
`n < 19` (the 19-bit timestamp table needs 19 variables) and `n > 30` (`MAX_TRACE_VARS`);
`family_circuit` returns `None` for both rather than calling it.

### 4.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::jump_branch_slt`, bit `k` being
`W[13 + k]`. The decoded table's `imm` is the value the instruction uses, two's complement, and
a form's absent register is `x0` (`jump-branch-slt.md` §1). `sc` is
`kind_slti + kind_slt + kind_blt + kind_bge`.

| row kind | bit (`decoded_mask`) | `decoded_imm` | queries present | `cmp_rhs` | `sc` | `taken` | `rd_selected` | `next_pc` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `slti` | 0 (1) | the compare immediate, sign-extended, as a `u32` | pc rs1 rd | the immediate | 1 | 0 | `lt` | the fall-through |
| `sltiu` | 1 (2) | the same, which `sltiu` compares unsigned | pc rs1 rd | the immediate | 0 | 0 | `lt` | the fall-through |
| `slt` | 2 (4) | 0 | pc rs1 rs2 rd | `rs2` | 1 | 0 | `lt` | the fall-through |
| `sltu` | 3 (8) | 0 | pc rs1 rs2 rd | `rs2` | 0 | 0 | `lt` | the fall-through |
| `beq` | 4 (16) | the displacement | pc rs1 rs2 | `rs2` | 0 | `eq` | 0 | `pc + imm mod 2^32` where taken, else the fall-through |
| `bne` | 5 (32) | the displacement | pc rs1 rs2 | `rs2` | 0 | `1 − eq` | 0 | as `beq` |
| `blt` | 6 (64) | the displacement | pc rs1 rs2 | `rs2` | 1 | `lt` | 0 | as `beq` |
| `bge` | 7 (128) | the displacement | pc rs1 rs2 | `rs2` | 1 | `1 − lt` | 0 | as `beq` |
| `bltu` | 8 (256) | the displacement | pc rs1 rs2 | `rs2` | 0 | `lt` | 0 | as `beq` |
| `bgeu` | 9 (512) | the displacement | pc rs1 rs2 | `rs2` | 0 | `1 − lt` | 0 | as `beq` |
| `jalr` | 10 (1024) | the offset | pc rs1 rd | 0 | 0 | 0 | the fall-through, the link | `(rs1 + imm) mod 2^32`, bit 0 cleared |
| `jal` | 11 (2048) | the displacement | pc rd | 0 | 0 | 0 | the fall-through, the link | `pc + imm mod 2^32` |
| padding | none; all 0 | 0 | none | 0 | 0 | 0 | 0 | 0 |

Every kind is provable at S17. `pc_wrap` is the carry of the target sum on a row that takes a
target, and 0 on a fall-through; `jalr_drop` is bit 0 of `rs1 + imm` on a `jalr` row, and 0 on
every other in an honest fill. `rd = x0` is not a kind: the table's `rd` is 0, the frame's x0
rule writes 0, and `rd_selected` keeps the computed value. A compressed instruction (`c.jal`,
`c.beqz`, …) is one of these kinds at its own length: its table row's `next_pc`, which is also a
jump's link, is `pc + 2`. A live row at a pc holding no instruction of the family meets the
table's `MINUS_ONE` row, which its decoder tuple cannot equal (`jump-branch-slt.md` §5).

### 4.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §4.4 and §4.6.

**Memory-argument columns, `M[0..21]`** — §2's REG layout (`w = 4`), filled by
`trace::build_memory_columns`; committed in `PublicInputs::memory_commitments`, absorbed at G8
before the memory challenges.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 4); obligations `gap_lo_*` (all 4) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `eq_inverse` (as its `enable`); selector of `gap_hi_pc`, `gap_lo_pc`, the eleven `RANGE16` obligations, the two `GENERIC` lookups and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `next_pc_rule`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | the target, or the fall-through (§4.2) | leaf `write_pc`; `next_pc_rule`; `next_pc_lo_range`, `next_pc_even` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on every kind but `jal` | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | rs1 register | the decoded `rs1` | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | rs1 value; the comparison's left operand | 0 where absent | leaf `read_rs1`; `rs1_writes_back`, `rs1_value_masked`, `cmp_order`, `eq_inverse`, `eq_at_nonzero`, `next_pc_rule`; `cmp_lhs_lo_range` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on `slt`, `sltu` and the six branches | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | rs2 register | the decoded `rs2` | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | rs2 value | 0 where absent | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `cmp_rhs_rule` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `rd_mask` | `frame(3, FIELD_MASK)` | rd present | 1 on the four `slt` kinds, `jalr` and `jal` | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[17]` | `rd_addr` | `frame(3, FIELD_ADDR)` | rd register | the decoded `rd` | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[18]` | `rd_read_ts` | `frame(3, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[19]` | `rd_read_value` | `frame(3, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd` |
| `M[20]` | `rd_write_value` | `frame(3, FIELD_WRITE_VALUE)` | rd new value | `rd_selected`, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |

The frame's slots in `jump_branch_slt.rs` are `SLOT_PC = 0` through `SLOT_RD = 3`, so
`frame(3, ..)` is `frame(SLOT_RD, ..)` there. Every query of this frame is used by some kind.

**Witness columns, `W[0..44]`** — `W[0..6]` filled by `trace::build_frame_witness`, `W[6..40]`
by `fill::jump_branch_slt` (`W[6]` in place of S14's), `W[40..44]` by
`trace::build_multiplicities` inside `prover::shard_columns`; committed in
`ShardProof::witness_commitments`, absorbed at S3 before `g` and `β`. The `KINDS[k]` rows name
the private constant beside each (`KINDS[kind::SLTI as usize]` is `SLTI`, with `kind` being
`constants::extra_mask::jump_branch_slt`).

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0]` | `pc_gap_hi` | `memory::gap_hi(0)` | pc gap, high chunk | 0: a pc read's gap is always 3 | `gap_hi_pc`, `gap_lo_pc` |
| `W[1]` | `rs1_gap_hi` | `gap_hi(1)` | rs1 gap, high chunk | `gap >> 19` | `gap_hi_rs1`, `gap_lo_rs1` |
| `W[2]` | `rs2_gap_hi` | `gap_hi(2)` | rs2 gap, high chunk | | `gap_hi_rs2`, `gap_lo_rs2` |
| `W[3]` | `rd_gap_hi` | `gap_hi(3)` | rd gap, high chunk | | `gap_hi_rd`, `gap_lo_rd` |
| `W[4]` | `rd_inv` | `memory::rd_inv(4)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[5]` | `rd_is_zero` | `memory::rd_is_zero(4)` | rd is `x0` | | `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_is_zero_boolean`, `rd_write_masked` |
| `W[6]` | `rd_selected` | `memory::rd_selected(4)`; `sel` in `jump_branch_slt.rs` | Result | the link on `jal` and `jalr`, `lt` on the `slt` kinds, 0 on a branch; `rd = x0` included: the fill overwrites the 0 S14's builder writes there | `rd_write_masked`, `rd_value_rule`; `rd_lo_range` |
| `W[7]` | `decoded_next_pc` | `jump_branch_slt::DECODED[0]`; `SEQ` in `jump_branch_slt.rs` | Decoded fall-through | the table row's `next_pc` | `next_pc_rule`, `rd_value_rule`; `decode_row` position 1 |
| `W[8]` | `decoded_rs1` | `DECODED[1]` | Decoded rs1 | | `rs1_addr_rule`; `decode_row` position 2 |
| `W[9]` | `decoded_rs2` | `DECODED[2]` | Decoded rs2 | | `rs2_addr_rule`; `decode_row` position 3 |
| `W[10]` | `decoded_rd` | `DECODED[3]` | Decoded rd | | `rd_addr_rule`; `decode_row` position 4 |
| `W[11]` | `decoded_imm` | `DECODED[4]`; `IMM` in `jump_branch_slt.rs` | Decoded immediate | | `cmp_rhs_rule`, `next_pc_rule`; `decode_row` position 5 |
| `W[12]` | `decoded_mask` | `DECODED[5]` | Decoded kind mask | `1 << bit` | `decoded_mask_bits`; `decode_row` position 6 |
| `W[13]` | `kind_slti` | `KINDS[0]`; `SLTI` | slti row | | `kind_slti_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rd_mask_rule`, `cmp_rhs_rule`, `cmp_order`, `rd_value_rule` |
| `W[14]` | `kind_sltiu` | `KINDS[1]`; `SLTIU` | sltiu row | | `kind_sltiu_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rd_mask_rule`, `cmp_rhs_rule`, `rd_value_rule` |
| `W[15]` | `kind_slt` | `KINDS[2]`; `SLT` | slt row | | `kind_slt_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `cmp_order`, `rd_value_rule` |
| `W[16]` | `kind_sltu` | `KINDS[3]`; `SLTU` | sltu row | | `kind_sltu_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `rd_value_rule` |
| `W[17]` | `kind_beq` | `KINDS[4]`; `BEQ` | beq row | | `kind_beq_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `taken_rule` |
| `W[18]` | `kind_bne` | `KINDS[5]`; `BNE` | bne row | | `kind_bne_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `taken_rule` |
| `W[19]` | `kind_blt` | `KINDS[6]`; `BLT` | blt row | | `kind_blt_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `cmp_order`, `taken_rule` |
| `W[20]` | `kind_bge` | `KINDS[7]`; `BGE` | bge row | | `kind_bge_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `cmp_order`, `taken_rule` |
| `W[21]` | `kind_bltu` | `KINDS[8]`; `BLTU` | bltu row | | `kind_bltu_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `taken_rule` |
| `W[22]` | `kind_bgeu` | `KINDS[9]`; `BGEU` | bgeu row | | `kind_bgeu_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `taken_rule` |
| `W[23]` | `kind_jalr` | `KINDS[10]`; `JALR` | jalr row | | `kind_jalr_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rd_mask_rule`, `next_pc_rule`, `rd_value_rule` |
| `W[24]` | `kind_jal` | `KINDS[11]`; `JAL` | jal row | | `kind_jal_boolean`, `decoded_mask_bits`, `rd_mask_rule`, `next_pc_rule`, `rd_value_rule` |
| `W[25]` | `cmp_rhs` | `jump_branch_slt::CMP_RHS` | Comparison's right operand | `rs2_read_value`, or the immediate on `slti` and `sltiu` | `cmp_rhs_rule`, `cmp_order`, `eq_inverse`, `eq_at_nonzero`; `cmp_rhs_lo_range` |
| `W[26]` | `rs1_hi` | `RS1_HI` | rs1, high halfword | `rs1_read_value >> 16` | `cmp_lhs_hi_range`, `cmp_lhs_lo_range`; `cmp_lhs_get_sign` position 0 |
| `W[27]` | `rs1_sign` | `RS1_SIGN` | rs1, sign bit | `rs1_read_value >> 31` | `cmp_order`; `cmp_lhs_get_sign` position 1 |
| `W[28]` | `cmp_rhs_hi` | `CMP_RHS_HI` | Right operand, high halfword | `cmp_rhs >> 16` | `cmp_rhs_hi_range`, `cmp_rhs_lo_range`; `cmp_rhs_get_sign` position 0 |
| `W[29]` | `cmp_rhs_sign` | `CMP_RHS_SIGN` | Right operand, sign bit | `cmp_rhs >> 31` | `cmp_order`; `cmp_rhs_get_sign` position 1 |
| `W[30]` | `lt` | `LT` | Less-than | `rs1 < cmp_rhs`, read signed where `sc = 1` | `cmp_order`, `cmp_lt_boolean`, `taken_rule`, `rd_value_rule` |
| `W[31]` | `cmp_gap` | `CMP_GAP` | Comparison gap | `(rs1 − cmp_rhs) mod 2^32` | `cmp_order`; `cmp_gap_lo_range` |
| `W[32]` | `cmp_gap_hi` | `CMP_GAP_HI` | Gap, high halfword | `cmp_gap >> 16` | `cmp_gap_hi_range`, `cmp_gap_lo_range` |
| `W[33]` | `eq` | `EQ` | Operands equal | 1 where `rs1_read_value = cmp_rhs`, a `jal` row included (both read 0) | `eq_inverse`, `eq_at_nonzero`, `taken_rule` |
| `W[34]` | `eq_inv` | `EQ_INV` | Inverse of the difference | `(rs1_read_value − cmp_rhs)⁻¹`, or 0 | `eq_inverse` |
| `W[35]` | `taken` | `TAKEN` | Branch taken | | `taken_rule`, `taken_boolean`, `next_pc_rule` |
| `W[36]` | `jalr_drop` | `JALR_DROP` | jalr's dropped bit | bit 0 of `rs1 + imm` on a `jalr` row; 0 elsewhere | `jalr_drop_boolean`, `next_pc_rule` |
| `W[37]` | `pc_wrap` | `PC_WRAP` | Next-pc wrap | the carry of the target sum; 0 on a fall-through | `pc_wrap_boolean`, `next_pc_rule` |
| `W[38]` | `next_pc_hi` | `NEXT_PC_HI` | Next pc, high halfword | `pc_write_value >> 16` | `next_pc_hi_range`, `next_pc_lo_range`, `next_pc_even` |
| `W[39]` | `rd_hi` | `RD_HI` | Result, high halfword | `rd_selected >> 16` | `rd_hi_range`, `rd_lo_range` |
| `W[40]` | `mult_timestamp` | `MULTIPLICITIES[0]` | Timestamp-table count | per table row `t`: the gated gap chunks (`mask·chunk`) equal to `t`, credited to rows below `2^19` | leaf `timestamp_table_num` |
| `W[41]` | `mult_range16` | `MULTIPLICITIES[1]` | 16-bit-table count | per table row `t`: the gated halfwords (`pc_mask·expression`) equal to `t`, credited to rows below `2^16` | leaf `range16_table_num` |
| `W[42]` | `mult_generic` | `MULTIPLICITIES[2]` | Generic-table count | per table row `t`: the gated sign tuples equal to row `t`; a live row's sign lookup lands on row `2^16 + 1 + hi`, `U16GetSign`'s row for its halfword `hi`, and a padding row's two on row 0, the `ZeroEntry` | leaf `generic_table_num` |
| `W[43]` | `mult_decoder` | `MULTIPLICITIES[3]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all seven positions) on the table's lowest non-live row, row 0 | leaf `decoder_table_num` |

A switched-off obligation's gated tuple is 0 (`s·e` at `s = 0`), so row 0 of `mult_timestamp`
and `mult_range16` counts every switched-off obligation: all 8 timestamp and all 11 `RANGE16`
obligations of each padding row, and in `mult_timestamp` also the two chunks of any query a live
row does not make — `rs1` on `jal`; `rs2` on `slti`, `sltiu`, `jal` and `jalr`; `rd` on a
branch. The `RANGE16` and `GENERIC` obligations are selected by `pc_mask`, so none is off on a
live row. Row 0 also counts every live chunk or halfword whose value is 0, such as `pc_gap_hi`
on every live row. The generic table's all-zero tuple repeats on every row past `2^17`, and the
count goes to the lowest, row 0.

**Setup columns, `S[0..10]`** — two tables. `S[0..7]` is the family's decoded table,
`program::lookup_tuple(1)` order, filled by `program::FamilyTable::column_poly(j)`; committed in
program identity (`program::setup_commitments`) and carried as `VerifyingKey::setup_commitments`
for the family. `S[7..10]` is the packed generic table (§0.3), filled by
`program::lookup_tables::generic_table(n)`. Its commitments are the same three points at every
even `n ≥ 18`: `program::lookup_tables::generic_commitments(srs)` computes them once, at `2^18`, and
every key carries them as `VerifyingKey::generic_table`, whatever its families. Identity does
not bind them; the key's SRS digest covers them after its `SrsVerifier`, and the global
transcript absorbs that digest before every challenge. A shard opens `S[7..10]` against them,
after identity's list, because `FamilyCircuit::reads_generic_table` holds for this circuit
(`shard-proof.md` §3, §5.1, §7; `jump-branch-slt.md` §6). Each is read only by its table's
denominator, at the `β` power in the last column.

| address | name | Rust | descriptive name | contents | read by | weight |
| --- | --- | --- | --- | --- | --- | --- |
| `S[0]` | `table_pc` | `jump_branch_slt::channels()[3].table[0]` | Table pc | `RowField::Pc` | `decoder_table_den` | 1 |
| `S[1]` | `table_next_pc` | `channels()[3].table[1]` | Table fall-through | `RowField::NextPc` | `decoder_table_den` | `β` |
| `S[2]` | `table_rs1` | `channels()[3].table[2]` | Table rs1 | `RowField::Rs1` | `decoder_table_den` | `β²` |
| `S[3]` | `table_rs2` | `channels()[3].table[3]` | Table rs2 | `RowField::Rs2` | `decoder_table_den` | `β³` |
| `S[4]` | `table_rd` | `channels()[3].table[4]` | Table rd | `RowField::Rd` | `decoder_table_den` | `β⁴` |
| `S[5]` | `table_imm` | `channels()[3].table[5]` | Table immediate | `RowField::Imm` | `decoder_table_den` | `β⁵` |
| `S[6]` | `table_extra_mask` | `channels()[3].table[6]` | Table kind mask | `RowField::ExtraMask` | `decoder_table_den` | `β⁶` |
| `S[7]` | `generic_key` | `jump_branch_slt::GENERIC_TABLE[0]`, `channels()[2].table[0]` | Generic key | 0, `AND_BASE + a + 1` or `SIGN_BASE + h + 1` | `generic_table_den` | 1 |
| `S[8]` | `generic_value` | `GENERIC_TABLE[1]` | Generic value | 0, `b` or `h >> 15` | `generic_table_den` | `β` |
| `S[9]` | `generic_result` | `GENERIC_TABLE[2]` | Generic result | 0, `a & b` or 0 | `generic_table_den` | `β²` |

`jump_branch_slt::TABLE_WIDTH` is 7 and `constants::generic_table::WIDTH` is 3.

**Virtual tables** — never committed, never opened; `gkr_verify::verify` evaluates their
closed forms.

| address | name | Rust | descriptive name | value at row `y` | read by |
| --- | --- | --- | --- | --- | --- |
| `V[range19]` | `range19` | `VirtualKind::Range19`, wire tag 2 | 19-bit range table | `y mod 2^19` | `timestamp_table_den` |
| `V[range16]` | `range16` | `VirtualKind::Range16`, wire tag 3 | 16-bit range table | `y mod 2^16` | `range16_table_den` |

### 4.4 Gate list 0: the 84 leaves

A leaf's relation number equals its `L1` offset, 0 to 83.

**The memory product trees.** The read side is `L1[0..4]` and the write side `L1[4..8]`, each
leaf per §0.6. Four queries fill each side, so neither has a pad.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_rd` | `M[16]` | 1 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 5 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 6 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 7 | `write_rd` | `M[16]` | 1 | `M[17]` | `4·M[0] + 3` | `M[20]` |

`L{1}[0]`, `read_pc`, is §3.4's, address for address. The rd write in full:

```text
L{1}[7]  write_rd
  positional  1 + γ_M·M[16] − M[16] + M[16] + α_ts·M[16] ×3 + α_addr·M[17]·M[16]
                + α_ts·M[0]·M[16] ×4 + α_val·M[20]·M[16]
  named       rd_mask·T(REG, rd_addr, 4·cycle + 3, rd_write_value) + 1 − rd_mask
```

**The `timestamp` fraction tree**, `L1[8..40]`: 16 fractions, the table's then 8 gap
obligations then 7 pads. Fraction `i` is `(L1[8 + 2i], L1[9 + 2i])`, named `<node>_num` and
`<node>_den`.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 8, 9 | `timestamp_table` | `−mult_timestamp` | `V[range19] + g` |
| 1 | 10, 11 | `gap_hi_pc` | 1 | `g + pc_mask·pc_gap_hi` |
| 2 | 12, 13 | `gap_lo_pc` | 1 | `g − pc_mask + 4·pc_mask·cycle − pc_mask·pc_read_ts − 2^19·pc_mask·pc_gap_hi` |
| 3 | 14, 15 | `gap_hi_rs1` | 1 | `g + rs1_mask·rs1_gap_hi` |
| 4 | 16, 17 | `gap_lo_rs1` | 1 | `g + 4·rs1_mask·cycle − rs1_mask·rs1_read_ts − 2^19·rs1_mask·rs1_gap_hi` |
| 5 | 18, 19 | `gap_hi_rs2` | 1 | `g + rs2_mask·rs2_gap_hi` |
| 6 | 20, 21 | `gap_lo_rs2` | 1 | `g + rs2_mask + 4·rs2_mask·cycle − rs2_mask·rs2_read_ts − 2^19·rs2_mask·rs2_gap_hi` |
| 7 | 22, 23 | `gap_hi_rd` | 1 | `g + rd_mask·rd_gap_hi` |
| 8 | 24, 25 | `gap_lo_rd` | 1 | `g + 2·rd_mask + 4·rd_mask·cycle − rd_mask·rd_read_ts − 2^19·rd_mask·rd_gap_hi` |
| 9–15 | 26–39 | `timestamp_pad_0` … `timestamp_pad_6` | 0 | 1 |

The `gap_lo` masks carry `(Δ_q − 1)·m` as in §3.4. In positional form fraction 8's denominator
is `g + 2·M[16] + 4·M[16]·M[0] − M[16]·M[18] − 2^19·M[16]·W[3]`.

**The `range16` fraction tree**, `L1[40..72]`: 16 fractions, the table's then 11 obligations then
4 pads.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 40, 41 | `range16_table` | `−mult_range16` | `V[range16] + g` |
| 1 | 42, 43 | `cmp_lhs_hi_range` | 1 | `g + pc_mask·rs1_hi` |
| 2 | 44, 45 | `cmp_lhs_lo_range` | 1 | `g + pc_mask·rs1_read_value − 2^16·pc_mask·rs1_hi` |
| 3 | 46, 47 | `cmp_rhs_hi_range` | 1 | `g + pc_mask·cmp_rhs_hi` |
| 4 | 48, 49 | `cmp_rhs_lo_range` | 1 | `g + pc_mask·cmp_rhs − 2^16·pc_mask·cmp_rhs_hi` |
| 5 | 50, 51 | `cmp_gap_hi_range` | 1 | `g + pc_mask·cmp_gap_hi` |
| 6 | 52, 53 | `cmp_gap_lo_range` | 1 | `g + pc_mask·cmp_gap − 2^16·pc_mask·cmp_gap_hi` |
| 7 | 54, 55 | `rd_hi_range` | 1 | `g + pc_mask·rd_hi` |
| 8 | 56, 57 | `rd_lo_range` | 1 | `g + pc_mask·rd_selected − 2^16·pc_mask·rd_hi` |
| 9 | 58, 59 | `next_pc_hi_range` | 1 | `g + pc_mask·next_pc_hi` |
| 10 | 60, 61 | `next_pc_lo_range` | 1 | `g + pc_mask·pc_write_value − 2^16·pc_mask·next_pc_hi` |
| 11 | 62, 63 | `next_pc_even` | 1 | `g + 2⁻¹·pc_mask·pc_write_value − 2^15·pc_mask·next_pc_hi` |
| 12–15 | 64–71 | `range16_pad_0` … `range16_pad_3` | 0 | 1 |

In positional form fraction 11's denominator is `g + 2⁻¹·M[1]·M[5] − 2^15·M[1]·W[38]`. `2⁻¹`
is `(p + 1)/2`, which the dump prints as
`0x183227397098d014dc2822db40c0ac2e9419f4243cdcb848a1f0fac9f8000001`, and `−2^15` as `-32768`.

**The `generic` fraction tree**, `L1[72..80]`: 4 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 72, 73 | `generic_table` | `−mult_generic` | `generic_key + β·generic_value + β²·generic_result + g` |
| 1 | 74, 75 | `cmp_lhs_get_sign` | 1 | `g + 257·pc_mask + pc_mask·rs1_hi + β·pc_mask·rs1_sign` |
| 2 | 76, 77 | `cmp_rhs_get_sign` | 1 | `g + 257·pc_mask + pc_mask·cmp_rhs_hi + β·pc_mask·cmp_rhs_sign` |
| 3 | 78, 79 | `generic_pad_0` | 0 | 1 |

```text
L{1}[75]  cmp_lhs_get_sign_den
  positional  g + 257·M[1] + M[1]·W[26] + β·M[1]·W[27]
  reads as    g + pc_mask·(e_0 + 1) + β·pc_mask·e_1 + β²·pc_mask·e_2,
              e = (rs1_hi + SIGN_BASE, rs1_sign, 0), SIGN_BASE = 256:
              the key rs1_hi + 257 and the sign at pc_mask = 1, the ZeroEntry at 0;
              e_2 is the constant 0 and contributes no term
```

**The `decoder` fraction tree**, `L1[80..84]`: 2 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 80, 81 | `decoder_table` | `−mult_decoder` | `table_pc + β·table_next_pc + β²·table_rs1 + β³·table_rs2 + β⁴·table_rd + β⁵·table_imm + β⁶·table_extra_mask + g` |
| 1 | 82, 83 | `decode_row` | 1 | `g_dec + (1 + β + β² + β³ + β⁴ + β⁵ + β⁶)·pc_mask + pc_mask·pc_read_value + β·pc_mask·decoded_next_pc + β²·pc_mask·decoded_rs1 + β³·pc_mask·decoded_rs2 + β⁴·pc_mask·decoded_rd + β⁵·pc_mask·decoded_imm + β⁶·pc_mask·decoded_mask` |

`decode_row_den` is §3.4's with the decoded row at `W[7..13]`: positionally
`g_dec + M[1] + β·M[1] + … + β⁶·M[1] + M[1]·M[4] + β·M[1]·W[7] + β²·M[1]·W[8] + β³·M[1]·W[9]
+ β⁴·M[1]·W[10] + β⁵·M[1]·W[11] + β⁶·M[1]·W[12]`.

### 4.5 Gate list 0: the 42 enforcing gates

Relations 84–125, in list order, in §3.5's format. The family's 32 come from
`jump_branch_slt::artifact`, its private helpers `booleanity`, `mask_rule`, `addr_rule` and
`value_masked`, and the two gadgets.

**A. The frame's gates (84–93)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
84–87   <q>_mask_boolean — each query's presence flag is a bit          Quadratic, degree 2
        code  memory::booleanity(frame(s, FIELD_MASK)), in frame_body

  84 pc_mask_boolean     0 = M[1]  − M[1]·M[1]      0 = pc_mask  − pc_mask²
  85 rs1_mask_boolean    0 = M[6]  − M[6]·M[6]      0 = rs1_mask − rs1_mask²
  86 rs2_mask_boolean    0 = M[11] − M[11]·M[11]    0 = rs2_mask − rs2_mask²
  87 rd_mask_boolean     0 = M[16] − M[16]·M[16]    0 = rd_mask  − rd_mask²

────────────────────────────────────────────────────────────────────────────────────────────
88–89   <q>_writes_back — a read-only register is left unchanged        Linear, degree 1
        code  memory::write_back(s), in frame_body

  88 rs1_writes_back     0 = M[10] − M[9]     0 = rs1_write_value − rs1_read_value
  89 rs2_writes_back     0 = M[15] − M[14]    0 = rs2_write_value − rs2_read_value

────────────────────────────────────────────────────────────────────────────────────────────
90      rd_is_zero_inverse — the x0 flag, with gate 91                  Quadratic, degree 2
        code  memory::x0_gates(3, 4)[0]
              = gadgets::is_zero(&[(1, rd_addr)], rd_inv, rd_is_zero, rd_mask)[0]

  positional  0 = W[5] − M[16] + M[17]·W[4]
  named       0 = rd_addr·rd_inv + rd_is_zero − rd_mask

────────────────────────────────────────────────────────────────────────────────────────────
91      rd_is_zero_at_nonzero — no x0 flag at a real register           Quadratic, degree 2
        code  x0_gates(3, 4)[1] = is_zero(..)[1]

  positional  0 = M[17]·W[5]
  named       0 = rd_addr·rd_is_zero

────────────────────────────────────────────────────────────────────────────────────────────
92      rd_is_zero_boolean    0 = W[5] − W[5]·W[5]    0 = rd_is_zero − rd_is_zero²
        Quadratic, degree 2; code  x0_gates(3, 4)[2]

────────────────────────────────────────────────────────────────────────────────────────────
93      rd_write_masked — a write into x0 writes 0                      Quadratic, degree 2
        code  x0_gates(3, 4)[3]

  positional  0 = M[20] − W[6] + W[5]·W[6]
  named       0 = rd_write_value − (1 − rd_is_zero)·rd_selected

  reads as (90–93)  §3.5's 79–82 over the REG layout. S17 builds 90 and 91 through
                    gadgets::is_zero; the frame fixtures hold their bytes unchanged.
```

**B. What the row is (94–106)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
94–105  kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2
        code  jump_branch_slt's private booleanity(KINDS[k])

  94  kind_slti_boolean    0 = W[13] − W[13]·W[13]    0 = kind_slti  − kind_slti²
  95  kind_sltiu_boolean   0 = W[14] − W[14]·W[14]    0 = kind_sltiu − kind_sltiu²
  96  kind_slt_boolean     0 = W[15] − W[15]·W[15]    0 = kind_slt   − kind_slt²
  97  kind_sltu_boolean    0 = W[16] − W[16]·W[16]    0 = kind_sltu  − kind_sltu²
  98  kind_beq_boolean     0 = W[17] − W[17]·W[17]    0 = kind_beq   − kind_beq²
  99  kind_bne_boolean     0 = W[18] − W[18]·W[18]    0 = kind_bne   − kind_bne²
  100 kind_blt_boolean     0 = W[19] − W[19]·W[19]    0 = kind_blt   − kind_blt²
  101 kind_bge_boolean     0 = W[20] − W[20]·W[20]    0 = kind_bge   − kind_bge²
  102 kind_bltu_boolean    0 = W[21] − W[21]·W[21]    0 = kind_bltu  − kind_bltu²
  103 kind_bgeu_boolean    0 = W[22] − W[22]·W[22]    0 = kind_bgeu  − kind_bgeu²
  104 kind_jalr_boolean    0 = W[23] − W[23]·W[23]    0 = kind_jalr  − kind_jalr²
  105 kind_jal_boolean     0 = W[24] − W[24]·W[24]    0 = kind_jal   − kind_jal²

────────────────────────────────────────────────────────────────────────────────────────────
106     decoded_mask_bits — the packed mask is its twelve bits          Linear, degree 1
        code  jump_branch_slt::artifact, `bits`

  positional  0 = W[13] + 2·W[14] + 4·W[15] + 8·W[16] + 16·W[17] + 32·W[18] + 64·W[19]
                  + 128·W[20] + 256·W[21] + 512·W[22] + 1024·W[23] + 2048·W[24] − W[12]
  named       0 = Σ_k 2^k·kind_k − decoded_mask,  k in extra_mask::jump_branch_slt order

  reads as  the bits are the mask the decoder lookup binds. One-hotness is not here: a live
            row with an all-zero mask, its queries and values what the rules below then
            demand, breaks no gate, and only the decoder table, whose masks are single bits,
            refuses it (crates/checker/tests/jump_branch_slt.rs,
            an_all_zero_mask_is_refused_by_the_decoder_domain_alone). Two bits that both ask
            for rs1 — any pair without jal — are refused on a live row by 107 with 85: the
            rule demands rs1_mask = 2, which booleanity refuses. On a padding row the
            decoder lookup is off: one kind bit with its packed mask breaks no gate there,
            beside taken = 1 for bne, bge and bgeu (§4.10). The honest fill writes 0.
```

**C. Which queries a row makes, and where (107–114)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
107     rs1_mask_rule — rs1 is read by every kind but jal               Quadratic, degree 2
        code  mask_rule(frame(1, FIELD_MASK),
                        [SLTI, SLTIU, SLT, SLTU, BEQ, BNE, BLT, BGE, BLTU, BGEU, JALR])

  positional  0 = M[6] − M[1]·W[13] − M[1]·W[14] − M[1]·W[15] − M[1]·W[16] − M[1]·W[17]
                  − M[1]·W[18] − M[1]·W[19] − M[1]·W[20] − M[1]·W[21] − M[1]·W[22]
                  − M[1]·W[23]
  named       0 = rs1_mask − pc_mask·(kind_slti + kind_sltiu + kind_slt + kind_sltu
                                      + kind_beq + kind_bne + kind_blt + kind_bge
                                      + kind_bltu + kind_bgeu + kind_jalr)

────────────────────────────────────────────────────────────────────────────────────────────
108     rs2_mask_rule — rs2 is read by slt, sltu and the six branches   Quadratic, degree 2
        code  mask_rule(frame(2, FIELD_MASK), [SLT, SLTU, BEQ, BNE, BLT, BGE, BLTU, BGEU])

  positional  0 = M[11] − M[1]·W[15] − M[1]·W[16] − M[1]·W[17] − M[1]·W[18] − M[1]·W[19]
                  − M[1]·W[20] − M[1]·W[21] − M[1]·W[22]
  named       0 = rs2_mask − pc_mask·(kind_slt + kind_sltu + kind_beq + kind_bne
                                      + kind_blt + kind_bge + kind_bltu + kind_bgeu)

────────────────────────────────────────────────────────────────────────────────────────────
109     rd_mask_rule — rd is written by the four slt kinds and the jumps
                                                                        Quadratic, degree 2
        code  mask_rule(frame(3, FIELD_MASK), [SLTI, SLTIU, SLT, SLTU, JALR, JAL])

  positional  0 = M[16] − M[1]·W[13] − M[1]·W[14] − M[1]·W[15] − M[1]·W[16] − M[1]·W[23]
                  − M[1]·W[24]
  named       0 = rd_mask − pc_mask·(kind_slti + kind_sltiu + kind_slt + kind_sltu
                                     + kind_jalr + kind_jal)

  reads as (107–109)  on a live row the bits are one-hot, so each sum is 0 or 1 and the mask
                      is the kind's use of the query (execution-trace.md §4); a branch has no
                      rd query. On a padding row pc_mask = 0 and every mask is 0, whatever
                      the bits hold: S14's control C8, which the row suite refuses by 109
                      alone on a padding row that claims jal to rewrite x10.

────────────────────────────────────────────────────────────────────────────────────────────
110     rs1_addr_rule — rs1's register is the decoded one               Quadratic, degree 2
        code  addr_rule(1, DECODED_RS1)

  positional  0 = M[6]·M[7] − M[6]·W[8]
  named       0 = rs1_mask·(rs1_addr − decoded_rs1)

────────────────────────────────────────────────────────────────────────────────────────────
111     rs2_addr_rule — rs2's register is the decoded one               Quadratic, degree 2
        code  addr_rule(2, DECODED_RS2)

  positional  0 = M[11]·M[12] − M[11]·W[9]
  named       0 = rs2_mask·(rs2_addr − decoded_rs2)

────────────────────────────────────────────────────────────────────────────────────────────
112     rd_addr_rule — rd's register is the decoded one                 Quadratic, degree 2
        code  addr_rule(3, DECODED_RD)

  positional  0 = M[16]·M[17] − M[16]·W[10]
  named       0 = rd_mask·(rd_addr − decoded_rd)

  reads as (110–112)  a present query's register is the table's; unlike §3.5's, no constant
                      term, since the family has no ecall row. rd = x0 needs no bit: the
                      table's rd is 0, 112 makes the write's address 0, and 90–93 write 0
                      whatever rd_selected is.

────────────────────────────────────────────────────────────────────────────────────────────
113     rs1_value_masked — an absent rs1 reads 0                        Quadratic, degree 2
        code  value_masked(1)

  positional  0 = M[9] − M[6]·M[9]
  named       0 = (1 − rs1_mask)·rs1_read_value

────────────────────────────────────────────────────────────────────────────────────────────
114     rs2_value_masked — an absent rs2 reads 0                        Quadratic, degree 2
        code  value_masked(2)

  positional  0 = M[14] − M[11]·M[14]
  named       0 = (1 − rs2_mask)·rs2_read_value

  reads as (113, 114)  the comparison runs on every live row: a jal row compares 0 with 0, a
                       jalr row rs1 with 0, and an slti row's rs2 adds nothing to cmp_rhs.
```

**D. The comparison and equality (115–119)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
115     cmp_rhs_rule — the comparison's right operand                   Quadratic, degree 2
        code  jump_branch_slt::artifact

  positional  0 = W[25] − M[14] − W[13]·W[11] − W[14]·W[11]
  named       0 = cmp_rhs − rs2_read_value − (kind_slti + kind_sltiu)·decoded_imm

  reads as  cmp_rhs is rs2 on every kind but slti and sltiu, and the immediate there (whose
            rs2 reads 0 by 114). A branch's imm, its displacement, never reaches it.

────────────────────────────────────────────────────────────────────────────────────────────
116     cmp_order — signed or unsigned ordering, one equation           Quadratic, degree 2
        code  gadgets::comparison_equation(&the_comparison(), 32), via gadgets::comparison;
              the_comparison() is private: prefix "cmp", selector pc_mask,
              signed [SLTI, SLT, BLT, BGE], lhs rs1_read_value, rhs cmp_rhs

  positional  0 = M[9] − W[25] + 2^32·W[30] − W[31]
                  − 2^32·W[13]·W[27] + 2^32·W[13]·W[29]
                  − 2^32·W[15]·W[27] + 2^32·W[15]·W[29]
                  − 2^32·W[19]·W[27] + 2^32·W[19]·W[29]
                  − 2^32·W[20]·W[27] + 2^32·W[20]·W[29]
  named, factored
    0 = rs1_read_value − cmp_rhs − 2^32·sc·(rs1_sign − cmp_rhs_sign) + 2^32·lt − cmp_gap,
    sc = kind_slti + kind_slt + kind_blt + kind_bge

  reads as  cmp_gap = D + 2^32·lt, with D = rs1 − cmp_rhs read in two's complement where
            sc = 1. With both operands and cmp_gap below 2^32 (their range pairs), each sign
            its operand's bit 31 (the generic table) and lt a bit (117), exactly one
            (lt, cmp_gap) holds: lt is the ordering sc selects, and cmp_gap is
            (rs1 − cmp_rhs) mod 2^32 whatever sc is (jump-branch-slt.md §3.2). The gate is
            ungated; on a padding row, where the range pairs are off, it leaves lt and
            cmp_gap free together (§4.10). The dump prints 2^32 as 0x…0100000000 and −2^32
            as 0x30644e72…f0000001.

────────────────────────────────────────────────────────────────────────────────────────────
117     cmp_lt_boolean        0 = W[30] − W[30]·W[30]      0 = lt − lt²
        Quadratic, degree 2; code  gadgets::comparison

────────────────────────────────────────────────────────────────────────────────────────────
118     eq_inverse — equality, with gate 119                            Quadratic, degree 2
        code  gadgets::is_zero(&[(1, rs1_read_value), (−1, cmp_rhs)], eq_inv, eq, pc_mask)[0]

  positional  0 = W[33] − M[1] + M[9]·W[34] − W[25]·W[34]
  named       0 = (rs1_read_value − cmp_rhs)·eq_inv + eq − pc_mask

────────────────────────────────────────────────────────────────────────────────────────────
119     eq_at_nonzero — no equality flag where the operands differ     Quadratic, degree 2
        code  is_zero(..)[1]

  positional  0 = M[9]·W[33] − W[25]·W[33]
  named       0 = (rs1_read_value − cmp_rhs)·eq

  reads as (118 with 119)  at rs1 ≠ cmp_rhs: eq = 0 and eq_inv = pc_mask/(rs1 − cmp_rhs).
                           at rs1 = cmp_rhs: eq = pc_mask.
                           So eq is 1 exactly on a live row whose operands are equal — every
                           jal row among them — and 0 on every padding row, with no
                           booleanity gate of its own (jump-branch-slt.md §3.1).
```

**E. What the row decides and writes (120–125)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
120     taken_rule — the branch decision                                Quadratic, degree 2
        code  jump_branch_slt::artifact

  positional  0 = W[35] − W[18] − W[20] − W[22] − W[17]·W[33] + W[18]·W[33]
                  − W[19]·W[30] − W[21]·W[30] + W[20]·W[30] + W[22]·W[30]
  named, factored
    0 = taken − (kind_bne + kind_bge + kind_bgeu)
              − (kind_beq − kind_bne)·eq
              − (kind_blt + kind_bltu − kind_bge − kind_bgeu)·lt

  reads as  one kind at a time: taken = eq on beq, 1 − eq on bne, lt on blt and bltu,
            1 − lt on bge and bgeu, and 0 on every other kind (jump-branch-slt.md §1's
            weight triples).

────────────────────────────────────────────────────────────────────────────────────────────
121     taken_boolean         0 = W[35] − W[35]·W[35]      0 = taken − taken²
122     jalr_drop_boolean     0 = W[36] − W[36]·W[36]      0 = jalr_drop − jalr_drop²
123     pc_wrap_boolean       0 = W[37] − W[37]·W[37]      0 = pc_wrap − pc_wrap²
        Quadratic, degree 2; code  jump_branch_slt's private booleanity

────────────────────────────────────────────────────────────────────────────────────────────
124     next_pc_rule — the target, or the fall-through                  Quadratic, degree 2
        code  jump_branch_slt::artifact

  positional  0 = M[5] + 2^32·W[37] − W[7] + W[35]·W[7] + W[24]·W[7] + W[23]·W[7]
                  − W[35]·M[4] − W[35]·W[11] − W[24]·M[4] − W[24]·W[11]
                  − W[23]·M[9] − W[23]·W[11] + W[23]·W[36]
  named, factored
    0 = pc_write_value + 2^32·pc_wrap
        − (1 − taken − kind_jal − kind_jalr)·decoded_next_pc
        − (taken + kind_jal)·(pc_read_value + decoded_imm)
        − kind_jalr·(rs1_read_value + decoded_imm − jalr_drop)

  reads as  at most one of taken, kind_jal and kind_jalr is 1 on a live row, so one arm:
              fall-through  next_pc = decoded_next_pc − 2^32·pc_wrap
              taken, jal    next_pc = pc + imm − 2^32·pc_wrap
              jalr          next_pc = rs1 + imm − jalr_drop − 2^32·pc_wrap
            With next_pc below 2^32 and even (next_pc_hi_range, next_pc_lo_range,
            next_pc_even), pc_wrap is the sum's carry — 0 on the fall-through, which is below
            2^24 — and, on a jalr row, jalr_drop its bit 0 (jump-branch-slt.md §4.3). The
            wrap and the default arm are ungated: a padding row holds only
            next_pc + 2^32·pc_wrap = decoded_next_pc (the honest fill writes 0 in all
            three). No row of the family can write HALT_PC, which is odd.

────────────────────────────────────────────────────────────────────────────────────────────
125     rd_value_rule — what the row computes for rd                    Quadratic, degree 2
        code  jump_branch_slt::artifact

  positional  0 = W[6] − W[24]·W[7] − W[23]·W[7] − W[13]·W[30] − W[14]·W[30] − W[15]·W[30]
                  − W[16]·W[30]
  named       0 = rd_selected − (kind_jal + kind_jalr)·decoded_next_pc
                  − (kind_slti + kind_sltiu + kind_slt + kind_sltu)·lt

  reads as  the link is the table's fall-through itself, a value with no sum to wrap; the four
            slt kinds write the one lt the branches read; a branch computes 0 and has no rd
            query to write it to (109). rd_selected is range-checked by rd_hi_range and
            rd_lo_range.
```

Of the 42 gates, 3 are degree 1: the two write-backs and `decoded_mask_bits`. All 42 have
constant 0, so each is 0 on the all-zero row, and the assembly records `zero_row_valid = true`
(the dump's padding contract).

### 4.6 The 22 lookups

`CircuitArtifact::lookups`, in order. The frame's 8 come from the private
`memory::gap_lookups`; 8–15 from `gadgets::comparison`; the rest from
`jump_branch_slt::artifact` (its private `range16`, `low_half`, `low_half_halved` and the inline
`decode_row`). Every lookup from 8 on is selected by `pc_mask`.

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `gap_hi_pc` | `TIMESTAMP` (0) | `M[1]` | `W[0]` | `pc_gap_hi` | `< 2^19` |
| 1 | `gap_lo_pc` | `TIMESTAMP` | `M[1]` | `4·M[0] − M[3] − 2^19·W[0] − 1` | `4·cycle − pc_read_ts − 2^19·pc_gap_hi − 1` | `< 2^19` |
| 2 | `gap_hi_rs1` | `TIMESTAMP` | `M[6]` | `W[1]` | `rs1_gap_hi` | `< 2^19` |
| 3 | `gap_lo_rs1` | `TIMESTAMP` | `M[6]` | `4·M[0] − M[8] − 2^19·W[1]` | `4·cycle − rs1_read_ts − 2^19·rs1_gap_hi` | `< 2^19` |
| 4 | `gap_hi_rs2` | `TIMESTAMP` | `M[11]` | `W[2]` | `rs2_gap_hi` | `< 2^19` |
| 5 | `gap_lo_rs2` | `TIMESTAMP` | `M[11]` | `4·M[0] − M[13] − 2^19·W[2] + 1` | `4·cycle − rs2_read_ts − 2^19·rs2_gap_hi + 1` | `< 2^19` |
| 6 | `gap_hi_rd` | `TIMESTAMP` | `M[16]` | `W[3]` | `rd_gap_hi` | `< 2^19` |
| 7 | `gap_lo_rd` | `TIMESTAMP` | `M[16]` | `4·M[0] − M[18] − 2^19·W[3] + 2` | `4·cycle − rd_read_ts − 2^19·rd_gap_hi + 2` | `< 2^19` |
| 8 | `cmp_lhs_hi_range` | `RANGE16` (1) | `M[1]` | `W[26]` | `rs1_hi` | `< 2^16` |
| 9 | `cmp_lhs_lo_range` | `RANGE16` | `M[1]` | `M[9] − 2^16·W[26]` | `rs1_read_value − 2^16·rs1_hi` | `< 2^16` |
| 10 | `cmp_rhs_hi_range` | `RANGE16` | `M[1]` | `W[28]` | `cmp_rhs_hi` | `< 2^16` |
| 11 | `cmp_rhs_lo_range` | `RANGE16` | `M[1]` | `W[25] − 2^16·W[28]` | `cmp_rhs − 2^16·cmp_rhs_hi` | `< 2^16` |
| 12 | `cmp_gap_hi_range` | `RANGE16` | `M[1]` | `W[32]` | `cmp_gap_hi` | `< 2^16` |
| 13 | `cmp_gap_lo_range` | `RANGE16` | `M[1]` | `W[31] − 2^16·W[32]` | `cmp_gap − 2^16·cmp_gap_hi` | `< 2^16` |
| 14 | `cmp_lhs_get_sign` | `GENERIC` (2) | `M[1]` | `(W[26] + 256, W[27], 0)` | `(rs1_hi + SIGN_BASE, rs1_sign, 0)` | the gated tuple `(rs1_hi + 257, rs1_sign, 0)` is a row of `S[7..10]` |
| 15 | `cmp_rhs_get_sign` | `GENERIC` | `M[1]` | `(W[28] + 256, W[29], 0)` | `(cmp_rhs_hi + SIGN_BASE, cmp_rhs_sign, 0)` | the gated tuple `(cmp_rhs_hi + 257, cmp_rhs_sign, 0)` is a row of `S[7..10]` |
| 16 | `rd_hi_range` | `RANGE16` | `M[1]` | `W[39]` | `rd_hi` | `< 2^16` |
| 17 | `rd_lo_range` | `RANGE16` | `M[1]` | `W[6] − 2^16·W[39]` | `rd_selected − 2^16·rd_hi` | `< 2^16` |
| 18 | `next_pc_hi_range` | `RANGE16` | `M[1]` | `W[38]` | `next_pc_hi` | `< 2^16` |
| 19 | `next_pc_lo_range` | `RANGE16` | `M[1]` | `M[5] − 2^16·W[38]` | `pc_write_value − 2^16·next_pc_hi` | `< 2^16` |
| 20 | `next_pc_even` | `RANGE16` | `M[1]` | `2⁻¹·M[5] − 2^15·W[38]` | `(pc_write_value − 2^16·next_pc_hi)/2` | `< 2^16` |
| 21 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[7], W[8], W[9], W[10], W[11], W[12])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_imm, decoded_mask)` | a row of `S[0..7]` |

Read in pairs, as in §3.6: each `gap_hi`/`gap_lo` pair puts a read strictly before its own
write, and each `_hi_range`/`_lo_range` pair bounds `rs1_read_value`, `cmp_rhs`, `cmp_gap`,
`rd_selected` and `pc_write_value` below `2^32`. With `next_pc_lo_range`, `next_pc_even` holds
exactly when `next_pc`'s low halfword is even: an odd one halves to `(lo + p)/2`, far above
`2^16`. The two `_hi_range` obligations keep each sign lookup's key `hi + 257` in
`[257, 2^16 + 256]`, `U16GetSign`'s keys, never the `ZeroEntry` or an AND key (`lookup.md` §4's
precondition), so the only row that key can meet is `(hi + 257, hi >> 15, 0)` and each sign is
its operand's bit 31.

The channels, `jump_branch_slt::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[40]` | 8 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[41]` | 11 | 16 |
| 6, 7 | `GENERIC` | 2 | `S[7..10]` | `W[42]` | 2 | 4 |
| 8, 9 | `DECODER` | 3 | `S[0..7]` | `W[43]` | 1 | 2 |

`artifact` asserts the four obligation counts. The generic table's commitments are the key's
one triple, covered by its SRS digest, not identity's (§4.3).

### 4.7 Inner layers `L2`–`L5`: the row-wise reduction

The conventions are §3.7's.

**`L2`, gate list 1, 42 columns, relations 126–167.**

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 126 | `read_2_0` | `read_pc · read_rs1` |
| 1 | 127 | `read_2_1` | `read_rs2 · read_rd` |
| 2 | 128 | `write_2_0` | `write_pc · write_rs1` |
| 3 | 129 | `write_2_1` | `write_rs2 · write_rd` |
| 4, 5 | 130, 131 | `timestamp_2_0` | `timestamp_table + gap_hi_pc` |
| 6, 7 | 132, 133 | `timestamp_2_1` | `gap_lo_pc + gap_hi_rs1` |
| 8, 9 | 134, 135 | `timestamp_2_2` | `gap_lo_rs1 + gap_hi_rs2` |
| 10, 11 | 136, 137 | `timestamp_2_3` | `gap_lo_rs2 + gap_hi_rd` |
| 12, 13 | 138, 139 | `timestamp_2_4` | `gap_lo_rd + timestamp_pad_0` |
| 14, 15 | 140, 141 | `timestamp_2_5` | `timestamp_pad_1 + timestamp_pad_2` |
| 16, 17 | 142, 143 | `timestamp_2_6` | `timestamp_pad_3 + timestamp_pad_4` |
| 18, 19 | 144, 145 | `timestamp_2_7` | `timestamp_pad_5 + timestamp_pad_6` |
| 20, 21 | 146, 147 | `range16_2_0` | `range16_table + cmp_lhs_hi_range` |
| 22, 23 | 148, 149 | `range16_2_1` | `cmp_lhs_lo_range + cmp_rhs_hi_range` |
| 24, 25 | 150, 151 | `range16_2_2` | `cmp_rhs_lo_range + cmp_gap_hi_range` |
| 26, 27 | 152, 153 | `range16_2_3` | `cmp_gap_lo_range + rd_hi_range` |
| 28, 29 | 154, 155 | `range16_2_4` | `rd_lo_range + next_pc_hi_range` |
| 30, 31 | 156, 157 | `range16_2_5` | `next_pc_lo_range + next_pc_even` |
| 32, 33 | 158, 159 | `range16_2_6` | `range16_pad_0 + range16_pad_1` |
| 34, 35 | 160, 161 | `range16_2_7` | `range16_pad_2 + range16_pad_3` |
| 36, 37 | 162, 163 | `generic_2_0` | `generic_table + cmp_lhs_get_sign` |
| 38, 39 | 164, 165 | `generic_2_1` | `cmp_rhs_get_sign + generic_pad_0` |
| 40, 41 | 166, 167 | `decoder_2_0` | `decoder_table + decode_row` |

Positionally, `generic_2_0` is `L{2}[36] = L{1}[72]·L{1}[75] + L{1}[74]·L{1}[73]` and
`L{2}[37] = L{1}[73]·L{1}[75]`: `−mult_generic/(T + g) + 1/(E_cmp_lhs_get_sign + g)`, each
channel's first node being its table's fraction beside its first lookup's, as in §3.7.

**`L3`, gate list 2, 22 columns, relations 168–189.**

| `L3` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 168 | `read_3_0` | `read_2_0 · read_2_1` |
| 1 | 169 | `write_3_0` | `write_2_0 · write_2_1` |
| 2, 3 | 170, 171 | `timestamp_3_0` | `timestamp_2_0 + timestamp_2_1` |
| 4, 5 | 172, 173 | `timestamp_3_1` | `timestamp_2_2 + timestamp_2_3` |
| 6, 7 | 174, 175 | `timestamp_3_2` | `timestamp_2_4 + timestamp_2_5` |
| 8, 9 | 176, 177 | `timestamp_3_3` | `timestamp_2_6 + timestamp_2_7` |
| 10, 11 | 178, 179 | `range16_3_0` | `range16_2_0 + range16_2_1` |
| 12, 13 | 180, 181 | `range16_3_1` | `range16_2_2 + range16_2_3` |
| 14, 15 | 182, 183 | `range16_3_2` | `range16_2_4 + range16_2_5` |
| 16, 17 | 184, 185 | `range16_3_3` | `range16_2_6 + range16_2_7` |
| 18, 19 | 186, 187 | `generic_3_0` | `generic_2_0 + generic_2_1` |
| 20, 21 | 188, 189 | `decoder_3_0` | copy of `decoder_2_0` |

**`L4`, gate list 3, 14 columns, relations 190–203.**

| `L4` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 190 | `read_4_0` | copy of `read_3_0` |
| 1 | 191 | `write_4_0` | copy of `write_3_0` |
| 2, 3 | 192, 193 | `timestamp_4_0` | `timestamp_3_0 + timestamp_3_1` |
| 4, 5 | 194, 195 | `timestamp_4_1` | `timestamp_3_2 + timestamp_3_3` |
| 6, 7 | 196, 197 | `range16_4_0` | `range16_3_0 + range16_3_1` |
| 8, 9 | 198, 199 | `range16_4_1` | `range16_3_2 + range16_3_3` |
| 10, 11 | 200, 201 | `generic_4_0` | copy of `generic_3_0` |
| 12, 13 | 202, 203 | `decoder_4_0` | copy of `decoder_3_0` |

**`L5`, gate list 4, 10 columns, relations 204–213** — the row-wise top: one value per row per
tree.

| `L5` | relations | node | formula | value at row `y` |
| --- | --- | --- | --- | --- |
| 0 | 204 | `read_5_0` | copy of `read_4_0` | the product of row `y`'s 4 read leaves |
| 1 | 205 | `write_5_0` | copy of `write_4_0` | the product of row `y`'s 4 write leaves |
| 2, 3 | 206, 207 | `timestamp_5_0` | `timestamp_4_0 + timestamp_4_1` | the sum of row `y`'s 16 timestamp fractions |
| 4, 5 | 208, 209 | `range16_5_0` | `range16_4_0 + range16_4_1` | the sum of row `y`'s 16 range16 fractions |
| 6, 7 | 210, 211 | `generic_5_0` | copy of `generic_4_0` | the sum of row `y`'s 4 generic fractions |
| 8, 9 | 212, 213 | `decoder_5_0` | copy of `decoder_4_0` | the sum of row `y`'s 2 decoder fractions |

### 4.8 The halving layers and the outputs

Gate list `k`, for `5 ≤ k ≤ n + 4`, halves layer `k` into layer `k + 1`, which has
`n + 4 − k` variables. Its ten gates, relation `r = 214 + 10(k − 5)`, with §3.8's formulas:

| `L{k+1}` | relation | node | shape |
| --- | --- | --- | --- |
| 0 | `r` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` |
| 1 | `r + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` |
| 2 | `r + 2` | `timestamp_{k+1}_0_num` | `TreeCross { L{k}[2], L{k}[3] }` |
| 3 | `r + 3` | `timestamp_{k+1}_0_den` | `TreeProduct { L{k}[3] }` |
| 4 | `r + 4` | `range16_{k+1}_0_num` | `TreeCross { L{k}[4], L{k}[5] }` |
| 5 | `r + 5` | `range16_{k+1}_0_den` | `TreeProduct { L{k}[5] }` |
| 6 | `r + 6` | `generic_{k+1}_0_num` | `TreeCross { L{k}[6], L{k}[7] }` |
| 7 | `r + 7` | `generic_{k+1}_0_den` | `TreeProduct { L{k}[7] }` |
| 8 | `r + 8` | `decoder_{k+1}_0_num` | `TreeCross { L{k}[8], L{k}[9] }` |
| 9 | `r + 9` | `decoder_{k+1}_0_den` | `TreeProduct { L{k}[9] }` |

In the last list, `k = n + 4`, the ten nodes are named `read_root`, `write_root`,
`timestamp_num_root`, `timestamp_den_root`, `range16_num_root`, `range16_den_root`,
`generic_num_root`, `generic_den_root`, `decoder_num_root` and `decoder_den_root`. At `n = 20`
the halving lists are 5 to 24, `L6` has 19 variables and `L25` none. At `n = 22` they are 5 to
26, and the top is `L27`.

**The outputs**, in output-map order. All ten are absorbed as one `GKR_OUTPUTS` message before
any challenge of the backward pass, and travel in `ShardProof::outputs`, as §3.8's eight do.

| # | address, `n = 20` | node | value | what `verify_shard` does with it |
| --- | --- | --- | --- | --- |
| 0 | `L{25}[0]` | `read_root` | the product of every read leaf of the shard | step 10: must equal `PublicInputs::memory_roots[p][0]`, `p` being the position of `(1, shard_index)` in `verifier_core::statement_shards`, after `INIT_TEARDOWN`'s shard, every `ZERO_WINDOWS` shard and every `ADD_SUB_LUI_AUIPC` shard (`shard-proof.md` §1.2); 2 in S17's statement; a factor of `reconciles` |
| 1 | `L{25}[1]` | `write_root` | the product of every write leaf | step 10: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |
| 2 | `L{25}[2]` | `timestamp_num_root` | as §3.8's output 2 | step 9: must be 0; otherwise `Lookup { channel: 0 }` |
| 3 | `L{25}[3]` | `timestamp_den_root` | as §3.8's output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 0 }` |
| 4 | `L{25}[4]` | `range16_num_root` | as output 2, for `RANGE16` | step 9: must be 0; otherwise `Lookup { channel: 1 }` |
| 5 | `L{25}[5]` | `range16_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 1 }` |
| 6 | `L{25}[6]` | `generic_num_root` | as output 2, for `GENERIC` | step 9: must be 0; otherwise `Lookup { channel: 2 }` |
| 7 | `L{25}[7]` | `generic_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 2 }` |
| 8 | `L{25}[8]` | `decoder_num_root` | as output 2, for `DECODER` | step 9: must be 0; otherwise `Lookup { channel: 3 }` |
| 9 | `L{25}[9]` | `decoder_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 3 }` |

### 4.9 Witness rows

The table shows eight of the 46 live `honest_rows` in `crates/checker/tests/jump_branch_slt.rs`,
and the padding row. The other 38 are `slt` at mixed signs, at equal operands and with
`rd = rs1`; `sltu` at mixed signs; `slti` and `sltiu` against −1 and 2047; the other three
comparisons into `x0`; each branch taken and not taken, a backward `bne` that falls through, and a `beq` taken to its own
fall-through; `jal` backward, into `x0` and `2^19` ahead; `jalr` into `x0`; and `c.jal` and
`c.beqz` at two bytes. §4.10 probes all 47. Each row is built from Rust's own `u32` and `i32`
arithmetic, and `every_row_kind_satisfies_every_gate_and_every_bound` holds it to every gate,
every range obligation and both table channels in CI: the suite's `violated_tables` checks a
generic tuple against `program::lookup_tables::generic_entries` and a decoder tuple against the
row's own `S[0..7]`.

A row is checked alone, as §3.9's are: each register query reads a write made 8 timestamps
before its own and the pc query the previous cycle's, so every `<q>_gap_hi` is 0; the
multiplicities are 0; `S[0..7]` hold the row's own table entry and `S[7..10]` are 0, and the
table below omits them. Every live row shown has cycle 9, pc `0x10100` and a 4-byte instruction,
and `P` is 0 in every cell.

`A` `blt x5, x6, +8` with `x5 = 0x80000000`, `x6 = 1`: taken. `B` `bltu` on the same operands:
not taken. `C` `bne x5, x0, −16` with `x5 = 3`: taken backward. `D` `slti x5, x6, −1` with
`x6 = 5`: 0. `E` `slt x0, x0, x6` with `x6 = 1`: computes 1, writes 0. `F` `jal x1, +0xa4`,
`x1` holding 9. `G` `jalr x7, −2(x7)` with `x7 = 0x101ab`. `H` `jalr x1, −4(x5)` with
`x5 = 0x10000`. `P` padding.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[2]` `pc_addr` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `M[3]` `pc_read_ts` | 32 | 32 | 32 | 32 | 32 | 32 | 32 | 32 | 0 |
| `M[4]` `pc_read_value` | `0x10100` | `0x10100` | `0x10100` | `0x10100` | `0x10100` | `0x10100` | `0x10100` | `0x10100` | 0 |
| `M[5]` `pc_write_value` | `0x10108` | `0x10104` | `0x100f0` | `0x10104` | `0x10104` | `0x101a4` | `0x101a8` | `0xfffc` | 0 |
| `M[6]` `rs1_mask` | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 0 |
| `M[7]` `rs1_addr` | 5 | 5 | 5 | 6 | 0 | 0 | 7 | 5 | 0 |
| `M[8]` `rs1_read_ts` | 29 | 29 | 29 | 29 | 29 | 0 | 29 | 29 | 0 |
| `M[9]`, `M[10]` `rs1_read_value`, `rs1_write_value` | `0x80000000` | `0x80000000` | 3 | 5 | 0 | 0 | `0x101ab` | `0x10000` | 0 |
| `M[11]` `rs2_mask` | 1 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 |
| `M[12]` `rs2_addr` | 6 | 6 | 0 | 0 | 6 | 0 | 0 | 0 | 0 |
| `M[13]` `rs2_read_ts` | 30 | 30 | 30 | 0 | 30 | 0 | 0 | 0 | 0 |
| `M[14]`, `M[15]` `rs2_read_value`, `rs2_write_value` | 1 | 1 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `M[16]` `rd_mask` | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[17]` `rd_addr` | 0 | 0 | 0 | 5 | 0 | 1 | 7 | 1 | 0 |
| `M[18]` `rd_read_ts` | 0 | 0 | 0 | 31 | 31 | 31 | 31 | 31 | 0 |
| `M[19]` `rd_read_value` | 0 | 0 | 0 | 0 | 0 | 9 | `0x101ab` | 0 | 0 |
| `M[20]` `rd_write_value` | 0 | 0 | 0 | 0 | 0 | `0x10104` | `0x10104` | `0x10104` | 0 |
| `W[0..4]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[4]` `rd_inv` | 0 | 0 | 0 | `5⁻¹` | 0 | 1 | `7⁻¹` | 1 | 0 |
| `W[5]` `rd_is_zero` | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `W[6]` `rd_selected` | 0 | 0 | 0 | 0 | 1 | `0x10104` | `0x10104` | `0x10104` | 0 |
| `W[7]` `decoded_next_pc` | `0x10104` | `0x10104` | `0x10104` | `0x10104` | `0x10104` | `0x10104` | `0x10104` | `0x10104` | 0 |
| `W[8]` `decoded_rs1` | 5 | 5 | 5 | 6 | 0 | 0 | 7 | 5 | 0 |
| `W[9]` `decoded_rs2` | 6 | 6 | 0 | 0 | 6 | 0 | 0 | 0 | 0 |
| `W[10]` `decoded_rd` | 0 | 0 | 0 | 5 | 0 | 1 | 7 | 1 | 0 |
| `W[11]` `decoded_imm` | 8 | 8 | `0xfffffff0` | `0xffffffff` | 0 | `0xa4` | `0xfffffffe` | `0xfffffffc` | 0 |
| `W[12]` `decoded_mask` | `0x40` | `0x100` | `0x20` | 1 | 4 | `0x800` | `0x400` | `0x400` | 0 |
| `W[13..25]` the kind bit set | `blt` | `bltu` | `bne` | `slti` | `slt` | `jal` | `jalr` | `jalr` | none |
| `W[25]` `cmp_rhs` | 1 | 1 | 0 | `0xffffffff` | 1 | 0 | 0 | 0 | 0 |
| `W[26]` `rs1_hi` | `0x8000` | `0x8000` | 0 | 0 | 0 | 0 | 1 | 1 | 0 |
| `W[27]` `rs1_sign` | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[28]` `cmp_rhs_hi` | 0 | 0 | 0 | `0xffff` | 0 | 0 | 0 | 0 | 0 |
| `W[29]` `cmp_rhs_sign` | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `W[30]` `lt` | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `W[31]` `cmp_gap` | `0x7fffffff` | `0x7fffffff` | 3 | 6 | `0xffffffff` | 0 | `0x101ab` | `0x10000` | 0 |
| `W[32]` `cmp_gap_hi` | `0x7fff` | `0x7fff` | 0 | 0 | `0xffff` | 0 | 1 | 1 | 0 |
| `W[33]` `eq` | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `W[34]` `eq_inv` | `0x7fffffff⁻¹` | `0x7fffffff⁻¹` | `3⁻¹` | `(5 − 0xffffffff)⁻¹` | −1 | 0 | `0x101ab⁻¹` | `0x10000⁻¹` | 0 |
| `W[35]` `taken` | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[36]` `jalr_drop` | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[37]` `pc_wrap` | 0 | 0 | 1 | 0 | 0 | 0 | 1 | 1 | 0 |
| `W[38]` `next_pc_hi` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 0 |
| `W[39]` `rd_hi` | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 0 |

`A` and `B` differ only in `sc`: the same operands give `cmp_gap = 0x7fffffff` in both, and
`lt` is 1 read signed, 0 read unsigned. `C`'s target is `pc + 0xfffffff0 − 2^32`, so
`pc_wrap = 1`; its `rs2` is `x0`, a present query at address 0. `D`'s right operand is the
immediate, whose sign bit is 1, so `5 < −1` is false; the retired table's SLTI defect, which read
that sign as 0, answered 1 (`jump-branch-slt.md` §5). `E` computes 1 and writes 0: `rd_selected`
keeps the result and `rd_write_masked` masks it, and `rd_inv` is 0 at address 0. `F`'s operands
both read 0, so `eq = 1` on a jump, where nothing reads it. `G`'s sum `0x101ab + 0xfffffffe` is
`2^32 + 0x101a9`: it wraps and has bit 0 set, so `next_pc = 0x101a8`, and its `rd` query reads
the same old `0x101ab` its `rs1` query read. `H`'s target `0xfffc` is below `2^16`, so
`next_pc_hi = 0`.

### 4.10 What fixes each cell

All 47 `honest_rows`, probed as in §3.10: 5 added to one `M` or `W` cell at a time, and each
boolean column flipped between 0 and 1, evaluated row-locally through `violated_relations`,
`violated_lookups` and the suite's `violated_tables`. A cell is listed below when, on some row,
no gate and no range obligation refuses the change. The table then says what does: a **table
channel**, when `violated_tables` alone refuses it; otherwise the **memory argument**, when the
cell is in a leaf whose mask is 1; or nothing. The multiplicities `W[40..44]` are not a row's
property, and the `S` columns are fixed by the opening, so neither is probed. Two cells, marked
(flip), are listed from the flips alone.

A read timestamp is a case apart, as in §3.10: `+5` stays inside a register's synthetic gap of 7,
so `M[8]`, `M[13]` and `M[18]` show up on every row, and the pc's gap is 3, so `M[3]` shows up
on padding alone.

| cell | fixed, on the rows that use it, by | rows where less fixes it, or nothing |
| --- | --- | --- |
| `M[0]` `cycle` | the memory argument (every write leaf's timestamp), with the gap obligations bounding it below | padding: nothing |
| `M[2]` `pc_addr` | the memory argument alone, as in §3.10 | padding: nothing |
| `M[3]`, `M[8]`, `M[13]`, `M[18]` read timestamps | the memory argument alone; the gap obligations only hold each below its own write | rows without that query, padding included: nothing |
| `M[4]` `pc_read_value` | the memory argument and the decoder table; on a taken branch or a `jal` row, also `next_pc_rule` | padding: nothing |
| `M[7]` `rs1_addr` | `rs1_addr_rule` | `jal` and padding rows: nothing |
| `M[12]` `rs2_addr` | `rs2_addr_rule` | `slti`, `sltiu`, `jal`, `jalr` and padding rows: nothing |
| `M[17]` `rd_addr` | `rd_addr_rule`, and the x0 gates | branch and padding rows: nothing |
| `M[19]` `rd_read_value` | the memory argument alone: no gate of this family reads it | branch and padding rows: nothing |
| `W[0]` `pc_gap_hi` | its gap obligations | padding: nothing |
| `W[1]`, `W[2]`, `W[3]` gap chunks | their gap obligations | rows without that query: nothing |
| `W[4]` `rd_inv` | `rd_is_zero_inverse`, where `rd_addr ≠ 0` | rows writing `x0`, branch rows, padding: nothing |
| `W[7]` `decoded_next_pc` | the decoder table, with `next_pc_rule` on a fall-through and `rd_value_rule` on a jump | taken branch rows: the decoder table alone, since `next_pc_rule` cancels it there and `rd_value_rule` does not read it; padding: `next_pc_rule` alone, which only ties it to `pc_write_value` and `pc_wrap` |
| `W[8]` `decoded_rs1` | `rs1_addr_rule` and the decoder table | `jal` rows: the decoder table alone; padding: nothing |
| `W[9]` `decoded_rs2` | `rs2_addr_rule` and the decoder table | `slti`, `sltiu`, `jal` and `jalr` rows: the decoder table alone; padding: nothing |
| `W[10]` `decoded_rd` | `rd_addr_rule` and the decoder table | branch rows: the decoder table alone; padding: nothing |
| `W[11]` `decoded_imm` | the decoder table, with `cmp_rhs_rule` on `slti` and `sltiu` rows and `next_pc_rule` on taken branch, `jal` and `jalr` rows | `slt`, `sltu` and not-taken branch rows: the decoder table alone; padding: nothing |
| `W[26]` `rs1_hi`, `W[28]` `cmp_rhs_hi`, `W[32]` `cmp_gap_hi`, `W[38]` `next_pc_hi`, `W[39]` `rd_hi` | their range obligations | padding: nothing |
| `W[27]` `rs1_sign`, `W[29]` `cmp_rhs_sign` (flip) | `cmp_order` on `slti`, `slt`, `blt` and `bge` rows, and the generic table | `sltiu`, `sltu`, `beq`, `bne`, `bltu`, `bgeu`, `jal` and `jalr` rows: the generic table alone, `cmp_order`'s sign terms being multiplied by `sc = 0`; padding: nothing |
| `W[34]` `eq_inv` | `eq_inverse`, where `rs1_read_value ≠ cmp_rhs` | rows whose operands are equal — the equal-operand comparisons and branches, and every `jal` row — and padding: nothing |
| `W[36]` `jalr_drop` (flip) | `next_pc_rule` on a `jalr` row | every other row, padding included: `jalr_drop_boolean` alone, which leaves it 0 or 1 |

Every other cell is refused row-locally on every row, padding included. Unlike §3.10's fence
row, no row lets `pc_mask` flip: `eq_inverse`, whose `enable` it is, refuses the flip on every
row (a `jal` row at `pc_mask = 0` breaks it and `rd_mask_rule`; the padding row at `pc_mask = 1`
breaks it and `gap_lo_pc`).

On a padding row every mask is 0 and every lookup is switched off, so no cell there reaches a
memory event or a table. With every kind bit 0, the gates hold `rd_selected`, `rd_write_value`,
`taken`, `cmp_rhs` and `eq` to 0 there, and `pc_write_value + 2^32·pc_wrap` to
`decoded_next_pc`. Beyond the cells above they leave free the pair `lt`, `cmp_gap` together
(`lt = 1` with `cmp_gap = 2^32` breaks nothing, `cmp_gap`'s range pair being off), and one kind
bit set with its packed mask, beside `taken = 1` for `bne`, `bge` and `bgeu`, whose constant
weight is 1: the mask rules' `pc_mask` factor, not the bits, keeps such a row from every memory
event. The honest fill writes 0 everywhere.

---

## 5. `SHIFT_BITWISE` — family 2

### 5.1 Header

`family_circuit(2, n)` is `shift_bitwise::artifact(n)` with `shift_bitwise::channels()`, built
by `memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` through the private
`family_spec` (`QUERIES`, the `SLOT_*` constants and the per-kind constants `SLLI` … `AND` are
private to `shift_bitwise.rs`). It uses neither S17 gadget: its comparison-free arithmetic needs
`is_zero` only for the frame's x0 rule, which `memory` builds. Normative spec:
`shift-bitwise.md`. Fill: `prover::family_fill(2)`, the private `fill::shift_bitwise`.

92 committed columns (21 `M`, 61 `W`, 10 `S`) and two virtual tables. Gate list 0 writes 124
leaves and holds 48 enforcing gates. 39 lookups on four channels, 10 outputs. At `n = 20`, the
height S18 proves, there are 26 gate lists, the top is `L26`, and the circuit has 458 inner
columns and 506 relations; a shard proof of it is 68,564 bytes (`crates/prover/tests/alu.rs`).
**It is one gate list deeper than §3's and §4's**, and the reason is §5.6's: its `range16` tree
carries 24 obligations beside its table fraction, 25 leaves padding to 32, where add/sub's and
jump/branch/slt's fit in 16. `artifact` panics unless the frame is `QUERIES`, the channels carry
exactly 8, 24, 6 and 1 obligations, `lookup::check_copowers` finds a direct range pair under the
same selector for each of the six columns it bounds by scaling — `residue`, `amount` and the
four `byte_a` keys — and every gate is zero on the all-zero row. It also panics on every refusal
of the assembly, among them `n < 19` (the 19-bit timestamp table needs 19 variables) and
`n > 30` (`MAX_TRACE_VARS`); `family_circuit` returns `None` for both rather than calling it.

### 5.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::shift_bitwise`, bit `k` being
`W[13 + k]`. The decoded table's `imm` is the value the instruction uses: the **raw five-bit
shamt** on `slli`, `srli` and `srai`, the sign-extended twelve-bit immediate on `andi`, `ori`
and `xori`, and 0 on every R-type row (`shift-bitwise.md` §1). A form's absent register is `x0`.
`src2 = rs2_read_value + decoded_imm` is the second operand of all twelve, one addend always
being 0. Every kind reads `rs1` and writes `rd`; the six R-type kinds read `rs2`.

| row kind | bit (`decoded_mask`) | `decoded_imm` | queries present | `f_shift`, `f_bitwise` | `src2` | `rd_selected` | `next_pc` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `slli` | 0 (1) | the shamt, `[0, 32)` | pc rs1 rd | 1, 0 | the shamt | `rs1 << (src2 mod 32)` | the fall-through |
| `xori` | 1 (2) | the immediate, sign-extended | pc rs1 rd | 0, 1 | the immediate | `rs1 ^ src2` | the fall-through |
| `srli` | 2 (4) | the shamt | pc rs1 rd | 1, 0 | the shamt | `rs1 >> (src2 mod 32)`, logical | the fall-through |
| `srai` | 3 (8) | the shamt | pc rs1 rd | 1, 0 | the shamt | `rs1 >> (src2 mod 32)`, arithmetic | the fall-through |
| `ori` | 4 (16) | the immediate | pc rs1 rd | 0, 1 | the immediate | `rs1 \| src2` | the fall-through |
| `andi` | 5 (32) | the immediate | pc rs1 rd | 0, 1 | the immediate | `rs1 & src2` | the fall-through |
| `sll` | 6 (64) | 0 | pc rs1 rs2 rd | 1, 0 | `rs2` | `rs1 << (src2 mod 32)` | the fall-through |
| `xor` | 7 (128) | 0 | pc rs1 rs2 rd | 0, 1 | `rs2` | `rs1 ^ src2` | the fall-through |
| `srl` | 8 (256) | 0 | pc rs1 rs2 rd | 1, 0 | `rs2` | `rs1 >> (src2 mod 32)`, logical | the fall-through |
| `sra` | 9 (512) | 0 | pc rs1 rs2 rd | 1, 0 | `rs2` | `rs1 >> (src2 mod 32)`, arithmetic | the fall-through |
| `or` | 10 (1024) | 0 | pc rs1 rs2 rd | 0, 1 | `rs2` | `rs1 \| src2` | the fall-through |
| `and` | 11 (2048) | 0 | pc rs1 rs2 rd | 0, 1 | `rs2` | `rs1 & src2` | the fall-through |
| padding | none; all 0 | 0 | none | free booleans | 0 | 0 | 0 |

Every kind is provable at S18. **No kind computes a pc**: `next_pc` is the decoded fall-through
on every row, so this family writes no target, needs no wrap bit and cannot reach `HALT_PC`,
which is odd and which no fall-through is (`shift-bitwise.md` §4.1, §6). `se` is 1 exactly on an
`srai` or `sra` row whose operand's bit 31 is set; `amount` is `src2 mod 32` on every row, and on
a bitwise row it keeps that value with `pow` and `copow` at 0. `rd = x0` is not a kind: the
table's `rd` is 0, the frame's x0 rule writes 0, and `rd_selected` keeps the computed value.
Seven of the twelve have compressed forms, so both fall-through widths occur. A live row at a pc
holding no instruction of the family meets the table's `MINUS_ONE` row, which its decoder tuple
cannot equal.

### 5.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §5.4 and §5.6.

**Memory-argument columns, `M[0..21]`** — §2's REG layout (`w = 4`), the same 21 columns
`JUMP_BRANCH_SLT` carries and the same bare frame fixture (`memory_frame_reg.bin`), filled by
`trace::build_memory_columns`; committed in `PublicInputs::memory_commitments`, absorbed at G8
before the memory challenges.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 4); obligations `gap_lo_*` (all 4) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`; selector of `gap_hi_pc`, `gap_lo_pc`, the fourteen `m_pc` `RANGE16` obligations, `rs1_get_sign` and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | the fall-through | leaf `write_pc`; `next_pc_rule` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on every kind | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | rs1 register | the decoded `rs1` | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | rs1 value; the shift's and the bitwise op's left operand | | leaf `read_rs1`; `rs1_writes_back`, `rs1_value_masked`, `shift_in_rule`, `shift_out_rule`, `rs1_bytes`, `bitwise_out_rule`; `rs1_lo_range` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on the six R-type kinds | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | rs2 register | the decoded `rs2` | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | rs2 value; `src2`'s register addend | 0 on an I-type row | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `amount_split`, `src2_bytes`, `bitwise_out_rule`; `src2_lo_range` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `rd_mask` | `frame(3, FIELD_MASK)` | rd present | 1 on every kind | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[17]` | `rd_addr` | `frame(3, FIELD_ADDR)` | rd register | the decoded `rd` | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[18]` | `rd_read_ts` | `frame(3, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[19]` | `rd_read_value` | `frame(3, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd` |
| `M[20]` | `rd_write_value` | `frame(3, FIELD_WRITE_VALUE)` | rd new value | `rd_selected`, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |

The frame's slots in `shift_bitwise.rs` are `SLOT_PC = 0` through `SLOT_RD = 3`. Every query of
this frame is used by some kind.

**Witness columns, `W[0..61]`** — `W[0..6]` filled by `trace::build_frame_witness`, `W[6..57]`
by `fill::shift_bitwise` (`W[6]` in place of S14's), `W[57..61]` by
`trace::build_multiplicities` inside `prover::shard_columns`; committed in
`ShardProof::witness_commitments`, absorbed at S3 before `g` and `β`. The `KINDS[k]` rows name
the private constant beside each (`KINDS[kind::SLLI as usize]` is `SLLI`, with `kind` being
`constants::extra_mask::shift_bitwise`).

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0]` | `pc_gap_hi` | `memory::gap_hi(0)` | pc gap, high chunk | 0: a pc read's gap is always 3 | `gap_hi_pc`, `gap_lo_pc` |
| `W[1]` | `rs1_gap_hi` | `gap_hi(1)` | rs1 gap, high chunk | `gap >> 19` | `gap_hi_rs1`, `gap_lo_rs1` |
| `W[2]` | `rs2_gap_hi` | `gap_hi(2)` | rs2 gap, high chunk | | `gap_hi_rs2`, `gap_lo_rs2` |
| `W[3]` | `rd_gap_hi` | `gap_hi(3)` | rd gap, high chunk | | `gap_hi_rd`, `gap_lo_rd` |
| `W[4]` | `rd_inv` | `memory::rd_inv(4)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[5]` | `rd_is_zero` | `memory::rd_is_zero(4)` | rd is `x0` | | `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_is_zero_boolean`, `rd_write_masked` |
| `W[6]` | `rd_selected` | `memory::rd_selected(4)`; `sel` in `shift_bitwise.rs` | Result | what the instruction computes, `rd = x0` included: the fill overwrites the 0 S14's builder writes there | `rd_write_masked`, `shift_in_rule`, `shift_out_rule`, `bitwise_out_rule`; `rd_lo_range` |
| `W[7]` | `decoded_next_pc` | `shift_bitwise::DECODED[0]`; `SEQ` | Decoded fall-through | the table row's `next_pc` | `next_pc_rule`; `decode_row` position 1 |
| `W[8]` | `decoded_rs1` | `DECODED[1]` | Decoded rs1 | | `rs1_addr_rule`; `decode_row` position 2 |
| `W[9]` | `decoded_rs2` | `DECODED[2]` | Decoded rs2 | | `rs2_addr_rule`; `decode_row` position 3 |
| `W[10]` | `decoded_rd` | `DECODED[3]` | Decoded rd | | `rd_addr_rule`; `decode_row` position 4 |
| `W[11]` | `decoded_imm` | `DECODED[4]`; `IMM` | Decoded immediate | the shamt, the sign-extended immediate or 0 | `amount_split`, `src2_bytes`, `bitwise_out_rule`; `src2_lo_range`, `decode_row` position 5 |
| `W[12]` | `decoded_mask` | `DECODED[5]` | Decoded kind mask | `1 << bit` | `decoded_mask_bits`; `decode_row` position 6 |
| `W[13]` | `kind_slli` | `KINDS[0]`; `SLLI` | slli row | | `kind_slli_boolean`, `decoded_mask_bits`, `f_shift_rule`, `rs1_mask_rule`, `rd_mask_rule`, `shift_in_rule`, `shift_out_rule` |
| `W[14]` | `kind_xori` | `KINDS[1]`; `XORI` | xori row | | `kind_xori_boolean`, `decoded_mask_bits`, `f_bitwise_rule`, `rs1_mask_rule`, `rd_mask_rule`, `bitwise_out_rule` |
| `W[15]` | `kind_srli` | `KINDS[2]`; `SRLI` | srli row | | `kind_srli_boolean`, `decoded_mask_bits`, `f_shift_rule`, `rs1_mask_rule`, `rd_mask_rule`, `shift_in_rule`, `shift_out_rule` |
| `W[16]` | `kind_srai` | `KINDS[3]`; `SRAI` | srai row | | `kind_srai_boolean`, `decoded_mask_bits`, `f_shift_rule`, `rs1_mask_rule`, `rd_mask_rule`, `se_rule`, `shift_in_rule`, `shift_out_rule` |
| `W[17]` | `kind_ori` | `KINDS[4]`; `ORI` | ori row | | `kind_ori_boolean`, `decoded_mask_bits`, `f_bitwise_rule`, `rs1_mask_rule`, `rd_mask_rule`, `bitwise_out_rule` |
| `W[18]` | `kind_andi` | `KINDS[5]`; `ANDI` | andi row | | `kind_andi_boolean`, `decoded_mask_bits`, `f_bitwise_rule`, `rs1_mask_rule`, `rd_mask_rule`, `bitwise_out_rule` |
| `W[19]` | `kind_sll` | `KINDS[6]`; `SLL` | sll row | | `kind_sll_boolean`, `decoded_mask_bits`, `f_shift_rule`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `shift_in_rule`, `shift_out_rule` |
| `W[20]` | `kind_xor` | `KINDS[7]`; `XOR` | xor row | | `kind_xor_boolean`, `decoded_mask_bits`, `f_bitwise_rule`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `bitwise_out_rule` |
| `W[21]` | `kind_srl` | `KINDS[8]`; `SRL` | srl row | | `kind_srl_boolean`, `decoded_mask_bits`, `f_shift_rule`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `shift_in_rule`, `shift_out_rule` |
| `W[22]` | `kind_sra` | `KINDS[9]`; `SRA` | sra row | | `kind_sra_boolean`, `decoded_mask_bits`, `f_shift_rule`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `se_rule`, `shift_in_rule`, `shift_out_rule` |
| `W[23]` | `kind_or` | `KINDS[10]`; `OR` | or row | | `kind_or_boolean`, `decoded_mask_bits`, `f_bitwise_rule`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `bitwise_out_rule` |
| `W[24]` | `kind_and` | `KINDS[11]`; `AND` | and row | | `kind_and_boolean`, `decoded_mask_bits`, `f_bitwise_rule`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `bitwise_out_rule` |
| `W[25]` | `f_shift` | `shift_bitwise::F_SHIFT` | Row is a shift | the sum of the six shift bits | `f_shift_rule`, `f_shift_boolean`, `copower_rule`; **selector** of `amount_range`, `amount_scaled`, `shift_powers` |
| `W[26]` | `f_bitwise` | `F_BITWISE` | Row is bitwise | the sum of the six bitwise bits | `f_bitwise_rule`, `f_bitwise_boolean`, `bitwise_out_rule`; **selector** of the eight `byte_a*` bounds and the four `and_byte_*` lookups |
| `W[27]` | `rs1_hi` | `RS1_HI` | rs1, high halfword | `rs1 >> 16` | `rs1_hi_range`, `rs1_lo_range`; `rs1_get_sign` position 0 |
| `W[28]` | `rs1_sign` | `RS1_SIGN` | rs1, bit 31 | `rs1 >> 31` | `se_rule`, `rs1_sign_boolean`; `rs1_get_sign` position 1 |
| `W[29]` | `src2_hi` | `SRC2_HI` | `src2`, high halfword | `(rs2 + imm) >> 16` | `src2_hi_range`, `src2_lo_range` |
| `W[30]` | `amount` | `AMOUNT` | Truncated shift amount | `src2 mod 32`, on a bitwise row too | `amount_split`; `amount_range`, `amount_scaled`, `shift_powers` position 0 |
| `W[31]` | `pow` | `POW` | `2^amount` | 0 on a bitwise row | `copower_rule`, `shift_prod_rule`; `shift_powers` position 1 |
| `W[32]` | `copow` | `COPOW` | `2^(31 − amount)` | 0 on a bitwise row | `copower_rule`, `scaled_rule`; `shift_powers` position 2 |
| `W[33]` | `high` | `HIGH` | `src2 >> 5` | | `amount_split`; `high_lo_range` |
| `W[34]` | `high_hi` | `HIGH_HI` | `high`, high halfword | | `high_hi_range`, `high_lo_range` |
| `W[35]` | `se` | `SE` | Sign-extension term | `is_arithmetic·rs1_sign` | `se_rule`, `se_boolean`, `shift_in_rule`, `shift_out_rule` |
| `W[36]` | `shift_in` | `SHIFT_IN` | The one multiplicand | `rs1` on a left shift, `rd_selected − 2^32·se` on a right one, 0 elsewhere; **`Fr`-backed**, being negative on an `sra` of a negative operand | `shift_in_rule`, `shift_prod_rule` |
| `W[37]` | `shift_prod` | `SHIFT_PROD` | `shift_in·pow` | reaches `2^63` on a left shift; **`Fr`-backed** | `shift_prod_rule`, `shift_out_rule` |
| `W[38]` | `ovf` | `OVF` | Left shift's discarded high bits | 0 on every other kind | `shift_out_rule`; `ovf_lo_range` |
| `W[39]` | `ovf_hi` | `OVF_HI` | `ovf`, high halfword | | `ovf_hi_range`, `ovf_lo_range` |
| `W[40]` | `residue` | `RESIDUE` | Right shift's discarded low bits | 0 on every other kind | `shift_out_rule`, `scaled_rule`; `residue_lo_range` |
| `W[41]` | `residue_hi` | `RESIDUE_HI` | `residue`, high halfword | | `residue_hi_range`, `residue_lo_range` |
| `W[42]` | `scaled` | `SCALED` | `residue·2^(32 − amount)` | | `scaled_rule`; `scaled_lo_range` |
| `W[43]` | `scaled_hi` | `SCALED_HI` | `scaled`, high halfword | | `scaled_hi_range`, `scaled_lo_range` |
| `W[44..48]` | `byte_a0` … `byte_a3` | `BYTES_A[j]` | rs1's bytes, low first | `(rs1 >> 8j) & 255` | `rs1_bytes`; `byte_a{j}_range`, `byte_a{j}_scaled`, `and_byte_{j}` position 0 |
| `W[48..52]` | `byte_b0` … `byte_b3` | `BYTES_B[j]` | `src2`'s bytes, low first | `(src2 >> 8j) & 255` | `src2_bytes`; `and_byte_{j}` position 1 |
| `W[52..56]` | `byte_and0` … `byte_and3` | `BYTES_AND[j]` | The bytewise AND | `byte_a_j & byte_b_j` | `bitwise_out_rule`; `and_byte_{j}` position 2 |
| `W[56]` | `rd_hi` | `RD_HI` | Result, high halfword | `rd_selected >> 16` | `rd_hi_range`, `rd_lo_range` |
| `W[57]` | `mult_timestamp` | `MULTIPLICITIES[0]` | Timestamp-table count | per table row `t`: the gated gap chunks (`mask·chunk`) equal to `t`, credited to rows below `2^19` | leaf `timestamp_table_num` |
| `W[58]` | `mult_range16` | `MULTIPLICITIES[1]` | 16-bit-table count | per table row `t`: the gated halfwords equal to `t` — 14 of them under `pc_mask`, 2 under `f_shift` and 8 under `f_bitwise` | leaf `range16_table_num` |
| `W[59]` | `mult_generic` | `MULTIPLICITIES[2]` | Generic-table count | per table row `t`: the gated generic tuples equal to row `t`; a live row's sign lookup lands on `U16GetSign`'s row `2^16 + 1 + rs1_hi`, a shift row's on `ShiftPowers`' row `2^17 + 1 + amount`, a bitwise row's four on the AND table's rows `1 + byte_a_j` | leaf `generic_table_num` |
| `W[60]` | `mult_decoder` | `MULTIPLICITIES[3]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all seven positions) on the table's lowest non-live row, row 0 | leaf `decoder_table_num` |

A switched-off obligation's gated tuple is 0, so row 0 of `mult_timestamp` and `mult_range16`
counts every switched-off obligation. This family switches more off than either earlier one, and
it does so on **live** rows: `f_shift` and `f_bitwise` partition the kinds, so a shift row
switches off the eight `byte_a` bounds and a bitwise row the two `amount` bounds — ten of the 24
`RANGE16` obligations are under a selector that some live row sets to 0, where in §3 and §4
every `RANGE16` obligation is under `pc_mask` and so on wherever the row is live. A padding row
switches all 24 off, and all 8 timestamp obligations with them; a live I-type row also switches
off the two `rs2` chunks. Row 0 also counts every live chunk or
halfword whose value is 0, `pc_gap_hi` on every live row among them. In `mult_generic`, a
padding row's six generic tuples all gate to the all-zero tuple, the `ZeroEntry` at row 0, and so
does a live row's switched-off half (a shift row's four AND lookups, a bitwise row's
`shift_powers`).

**Setup columns, `S[0..10]`** — two tables. `S[0..7]` is the family's decoded table,
`program::lookup_tuple(2)` order, filled by `program::FamilyTable::column_poly(j)`; committed in
program identity (`program::setup_commitments`) and carried as `VerifyingKey::setup_commitments`
for the family. `S[7..10]` is the packed generic table (§0.3), filled by
`program::lookup_tables::generic_table(n)` — the same three commitments at every even `n ≥ 18`,
carried in every key as `VerifyingKey::generic_table` and covered by the key's SRS digest, not by
identity. A shard opens `S[7..10]` against them, after identity's list, because
`FamilyCircuit::reads_generic_table` holds for this circuit (`shard-proof.md` §3, §5.1, §7;
`jump-branch-slt.md` §6, which S18 did not amend). Each is read only by its table's denominator,
at the `β` power in the last column.

| address | name | Rust | descriptive name | contents | read by | weight |
| --- | --- | --- | --- | --- | --- | --- |
| `S[0]` | `table_pc` | `shift_bitwise::channels()[3].table[0]` | Table pc | `RowField::Pc` | `decoder_table_den` | 1 |
| `S[1]` | `table_next_pc` | `channels()[3].table[1]` | Table fall-through | `RowField::NextPc` | `decoder_table_den` | `β` |
| `S[2]` | `table_rs1` | `channels()[3].table[2]` | Table rs1 | `RowField::Rs1` | `decoder_table_den` | `β²` |
| `S[3]` | `table_rs2` | `channels()[3].table[3]` | Table rs2 | `RowField::Rs2` | `decoder_table_den` | `β³` |
| `S[4]` | `table_rd` | `channels()[3].table[4]` | Table rd | `RowField::Rd` | `decoder_table_den` | `β⁴` |
| `S[5]` | `table_imm` | `channels()[3].table[5]` | Table immediate | `RowField::Imm` | `decoder_table_den` | `β⁵` |
| `S[6]` | `table_extra_mask` | `channels()[3].table[6]` | Table kind mask | `RowField::ExtraMask` | `decoder_table_den` | `β⁶` |
| `S[7]` | `generic_key` | `shift_bitwise::GENERIC_TABLE[0]`, `channels()[2].table[0]` | Generic key | 0, `AND_BASE + a + 1`, `SIGN_BASE + h + 1` or `SHIFT_BASE + s + 1` | `generic_table_den` | 1 |
| `S[8]` | `generic_value` | `GENERIC_TABLE[1]` | Generic value | 0, `b`, `h >> 15` or `2^s` | `generic_table_den` | `β` |
| `S[9]` | `generic_result` | `GENERIC_TABLE[2]` | Generic result | 0, `a & b`, 0 or `2^(31 − s)` | `generic_table_den` | `β²` |

`shift_bitwise::TABLE_WIDTH` is 7 and `constants::generic_table::WIDTH` is 3.

**Virtual tables** — never committed, never opened; `gkr_verify::verify` evaluates their
closed forms.

| address | name | Rust | descriptive name | value at row `y` | read by |
| --- | --- | --- | --- | --- | --- |
| `V[range19]` | `range19` | `VirtualKind::Range19`, wire tag 2 | 19-bit range table | `y mod 2^19` | `timestamp_table_den` |
| `V[range16]` | `range16` | `VirtualKind::Range16`, wire tag 3 | 16-bit range table | `y mod 2^16` | `range16_table_den` |

### 5.4 Gate list 0: the 124 leaves

A leaf's relation number equals its `L1` offset, 0 to 123.

**The memory product trees.** The read side is `L1[0..4]` and the write side `L1[4..8]`, each
leaf per §0.6, and each is §4.4's address for address — the frame is the same. Four queries fill
each side, so neither has a pad.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_rd` | `M[16]` | 1 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 5 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 6 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 7 | `write_rd` | `M[16]` | 1 | `M[17]` | `4·M[0] + 3` | `M[20]` |

**The `timestamp` fraction tree**, `L1[8..40]`: 16 fractions, the table's then 8 gap obligations
then 7 pads, §4.4's list unchanged. Fraction `i` is `(L1[8 + 2i], L1[9 + 2i])`, named
`<node>_num` and `<node>_den`.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 8, 9 | `timestamp_table` | `−mult_timestamp` | `V[range19] + g` |
| 1 | 10, 11 | `gap_hi_pc` | 1 | `g + pc_mask·pc_gap_hi` |
| 2 | 12, 13 | `gap_lo_pc` | 1 | `g − pc_mask + 4·pc_mask·cycle − pc_mask·pc_read_ts − 2^19·pc_mask·pc_gap_hi` |
| 3 | 14, 15 | `gap_hi_rs1` | 1 | `g + rs1_mask·rs1_gap_hi` |
| 4 | 16, 17 | `gap_lo_rs1` | 1 | `g + 4·rs1_mask·cycle − rs1_mask·rs1_read_ts − 2^19·rs1_mask·rs1_gap_hi` |
| 5 | 18, 19 | `gap_hi_rs2` | 1 | `g + rs2_mask·rs2_gap_hi` |
| 6 | 20, 21 | `gap_lo_rs2` | 1 | `g + rs2_mask + 4·rs2_mask·cycle − rs2_mask·rs2_read_ts − 2^19·rs2_mask·rs2_gap_hi` |
| 7 | 22, 23 | `gap_hi_rd` | 1 | `g + rd_mask·rd_gap_hi` |
| 8 | 24, 25 | `gap_lo_rd` | 1 | `g + 2·rd_mask + 4·rd_mask·cycle − rd_mask·rd_read_ts − 2^19·rd_mask·rd_gap_hi` |
| 9–15 | 26–39 | `timestamp_pad_0` … `timestamp_pad_6` | 0 | 1 |

**The `range16` fraction tree**, `L1[40..104]`: **32 fractions**, the table's then 24 obligations
then 7 pads. This is the tree that makes the circuit a list deeper than §3's and §4's.

| fraction | `L1` | node | numerator | denominator (named) | selector |
| --- | --- | --- | --- | --- | --- |
| 0 | 40, 41 | `range16_table` | `−mult_range16` | `V[range16] + g` | — |
| 1 | 42, 43 | `rs1_hi_range` | 1 | `g + pc_mask·rs1_hi` | `pc_mask` |
| 2 | 44, 45 | `rs1_lo_range` | 1 | `g + pc_mask·rs1_read_value − 2^16·pc_mask·rs1_hi` | `pc_mask` |
| 3 | 46, 47 | `src2_hi_range` | 1 | `g + pc_mask·src2_hi` | `pc_mask` |
| 4 | 48, 49 | `src2_lo_range` | 1 | `g + pc_mask·rs2_read_value + pc_mask·decoded_imm − 2^16·pc_mask·src2_hi` | `pc_mask` |
| 5 | 50, 51 | `high_hi_range` | 1 | `g + pc_mask·high_hi` | `pc_mask` |
| 6 | 52, 53 | `high_lo_range` | 1 | `g + pc_mask·high − 2^16·pc_mask·high_hi` | `pc_mask` |
| 7 | 54, 55 | `ovf_hi_range` | 1 | `g + pc_mask·ovf_hi` | `pc_mask` |
| 8 | 56, 57 | `ovf_lo_range` | 1 | `g + pc_mask·ovf − 2^16·pc_mask·ovf_hi` | `pc_mask` |
| 9 | 58, 59 | `residue_hi_range` | 1 | `g + pc_mask·residue_hi` | `pc_mask` |
| 10 | 60, 61 | `residue_lo_range` | 1 | `g + pc_mask·residue − 2^16·pc_mask·residue_hi` | `pc_mask` |
| 11 | 62, 63 | `scaled_hi_range` | 1 | `g + pc_mask·scaled_hi` | `pc_mask` |
| 12 | 64, 65 | `scaled_lo_range` | 1 | `g + pc_mask·scaled − 2^16·pc_mask·scaled_hi` | `pc_mask` |
| 13 | 66, 67 | `rd_hi_range` | 1 | `g + pc_mask·rd_hi` | `pc_mask` |
| 14 | 68, 69 | `rd_lo_range` | 1 | `g + pc_mask·rd_selected − 2^16·pc_mask·rd_hi` | `pc_mask` |
| 15 | 70, 71 | `amount_range` | 1 | `g + f_shift·amount` | `f_shift` |
| 16 | 72, 73 | `amount_scaled` | 1 | `g + 2048·f_shift·amount` | `f_shift` |
| 17 | 74, 75 | `byte_a0_range` | 1 | `g + f_bitwise·byte_a0` | `f_bitwise` |
| 18 | 76, 77 | `byte_a0_scaled` | 1 | `g + 256·f_bitwise·byte_a0` | `f_bitwise` |
| 19, 20 | 78–81 | `byte_a1_range`, `byte_a1_scaled` | 1 | as 17, 18 over `byte_a1` | `f_bitwise` |
| 21, 22 | 82–85 | `byte_a2_range`, `byte_a2_scaled` | 1 | as 17, 18 over `byte_a2` | `f_bitwise` |
| 23, 24 | 86–89 | `byte_a3_range`, `byte_a3_scaled` | 1 | as 17, 18 over `byte_a3` | `f_bitwise` |
| 25–31 | 90–103 | `range16_pad_0` … `range16_pad_6` | 0 | 1 | — |

**The `generic` fraction tree**, `L1[104..120]`: 8 fractions, the table's then 6 lookups then 1
pad.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 104, 105 | `generic_table` | `−mult_generic` | `generic_key + β·generic_value + β²·generic_result + g` |
| 1 | 106, 107 | `rs1_get_sign` | 1 | `g + 257·pc_mask + pc_mask·rs1_hi + β·pc_mask·rs1_sign` |
| 2 | 108, 109 | `shift_powers` | 1 | `g + 65793·f_shift + f_shift·amount + β·f_shift·pow + β²·f_shift·copow` |
| 3 | 110, 111 | `and_byte_0` | 1 | `g + f_bitwise + f_bitwise·byte_a0 + β·f_bitwise·byte_b0 + β²·f_bitwise·byte_and0` |
| 4–6 | 112–117 | `and_byte_1` … `and_byte_3` | 1 | as fraction 3 over byte `j` |
| 7 | 118, 119 | `generic_pad_0` | 0 | 1 |

The three literals are the three sub-tables' gated key bases, `constants::generic_table`'s
`AND_BASE + 1 = 1`, `SIGN_BASE + 1 = 257` and `SHIFT_BASE + 1 = 65793`:

```text
L{1}[109]  shift_powers_den
  positional  g + 65793·W[25] + 1·W[25]·W[30] + lookup_beta·W[25]·W[31]
                + lookup_beta_2·W[25]·W[32]
  reads as    g + f_shift·(e_0 + 1) + β·f_shift·e_1 + β²·f_shift·e_2,
              e = (amount + SHIFT_BASE, pow, copow), SHIFT_BASE = 65792:
              the key amount + 65793 and the row's two powers at f_shift = 1,
              the ZeroEntry at 0
```

**The `decoder` fraction tree**, `L1[120..124]`: 2 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 120, 121 | `decoder_table` | `−mult_decoder` | `table_pc + β·table_next_pc + β²·table_rs1 + β³·table_rs2 + β⁴·table_rd + β⁵·table_imm + β⁶·table_extra_mask + g` |
| 1 | 122, 123 | `decode_row` | 1 | `g_dec + (1 + β + β² + β³ + β⁴ + β⁵ + β⁶)·pc_mask + pc_mask·pc_read_value + β·pc_mask·decoded_next_pc + β²·pc_mask·decoded_rs1 + β³·pc_mask·decoded_rs2 + β⁴·pc_mask·decoded_rd + β⁵·pc_mask·decoded_imm + β⁶·pc_mask·decoded_mask` |

`decode_row_den` is §4.4's with the decoded row at `W[7..13]`, address for address.

### 5.5 Gate list 0: the 48 enforcing gates

Relations 124–171, in list order, in §3.5's format. The family's 38 come from
`shift_bitwise::family_spec` and its private helpers `booleanity`, `flag_rule`, `mask_rule`,
`addr_rule` and `value_masked`.

**A. The frame's gates (124–133)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
124–127 <q>_mask_boolean — each query's presence flag is a bit          Quadratic, degree 2
        code  memory::booleanity(frame(s, FIELD_MASK)), in frame_body

  124 pc_mask_boolean    0 = M[1]  − M[1]·M[1]      0 = pc_mask  − pc_mask²
  125 rs1_mask_boolean   0 = M[6]  − M[6]·M[6]      0 = rs1_mask − rs1_mask²
  126 rs2_mask_boolean   0 = M[11] − M[11]·M[11]    0 = rs2_mask − rs2_mask²
  127 rd_mask_boolean    0 = M[16] − M[16]·M[16]    0 = rd_mask  − rd_mask²

────────────────────────────────────────────────────────────────────────────────────────────
128–129 <q>_writes_back — a read-only register is left unchanged        Linear, degree 1
        code  memory::write_back(s), in frame_body

  128 rs1_writes_back    0 = M[10] − M[9]     0 = rs1_write_value − rs1_read_value
  129 rs2_writes_back    0 = M[15] − M[14]    0 = rs2_write_value − rs2_read_value

────────────────────────────────────────────────────────────────────────────────────────────
130–133 the x0 rule                                                    Quadratic, degree 2
        code  memory::x0_gates(3, 4), whose first two are
              gadgets::is_zero(&[(1, rd_addr)], rd_inv, rd_is_zero, rd_mask)

  130 rd_is_zero_inverse     0 = W[5] − M[16] + M[17]·W[4]
                             0 = rd_addr·rd_inv + rd_is_zero − rd_mask
  131 rd_is_zero_at_nonzero  0 = M[17]·W[5]        0 = rd_addr·rd_is_zero
  132 rd_is_zero_boolean     0 = W[5] − W[5]·W[5]  0 = rd_is_zero − rd_is_zero²
  133 rd_write_masked        0 = M[20] − W[6] + W[5]·W[6]
                             0 = rd_write_value − (1 − rd_is_zero)·rd_selected

  reads as (124–133)  §4.5's 84–93, address for address: the frame is the same four
                      queries, and the bare frame fixture memory_frame_reg.bin is the
                      same file.
```

**B. What the row is (134–150)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
134–145 kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2
        code  shift_bitwise's private booleanity(KINDS[k])

  134 kind_slli_boolean   0 = W[13] − W[13]·W[13]    139 kind_andi_boolean  W[18]
  135 kind_xori_boolean   0 = W[14] − W[14]·W[14]    140 kind_sll_boolean   W[19]
  136 kind_srli_boolean   0 = W[15] − W[15]·W[15]    141 kind_xor_boolean   W[20]
  137 kind_srai_boolean   0 = W[16] − W[16]·W[16]    142 kind_srl_boolean   W[21]
  138 kind_ori_boolean    0 = W[17] − W[17]·W[17]    143 kind_sra_boolean   W[22]
                                                     144 kind_or_boolean    W[23]
                                                     145 kind_and_boolean   W[24]

────────────────────────────────────────────────────────────────────────────────────────────
146     decoded_mask_bits — the packed mask is its twelve bits          Linear, degree 1
        code  shift_bitwise::family_spec, `bits`

  positional  0 = W[13] + 2·W[14] + 4·W[15] + 8·W[16] + 16·W[17] + 32·W[18] + 64·W[19]
                  + 128·W[20] + 256·W[21] + 512·W[22] + 1024·W[23] + 2048·W[24] − W[12]
  named       0 = Σ_k 2^k·kind_k − decoded_mask,  k in extra_mask::shift_bitwise order

  reads as  §4.5's 106 over this family's twelve bits. One-hotness is not here: the decoder
            table, whose masks are single bits, is what enforces it (lookup.md §10), and on
            a padding row, where the lookup is off, the bits are free.

────────────────────────────────────────────────────────────────────────────────────────────
147–150 the two halves                                Linear/Quadratic, degrees 1 and 2
        code  flag_rule(F_SHIFT, &SHIFTS), booleanity(F_SHIFT), and the same for BITWISE

  147 f_shift_rule     0 = W[25] − W[13] − W[15] − W[16] − W[19] − W[21] − W[22]
                       0 = f_shift − (kind_slli + kind_srli + kind_srai
                                      + kind_sll + kind_srl + kind_sra)
  148 f_shift_boolean  0 = W[25] − W[25]·W[25]     0 = f_shift − f_shift²
  149 f_bitwise_rule   0 = W[26] − W[14] − W[17] − W[18] − W[20] − W[23] − W[24]
                       0 = f_bitwise − (kind_xori + kind_ori + kind_andi
                                        + kind_xor + kind_or + kind_and)
  150 f_bitwise_boolean 0 = W[26] − W[26]·W[26]    0 = f_bitwise − f_bitwise²

  reads as  each half is a committed column because each is a **lookup selector**, and
            validate refuses a selector without a booleanity gate; every other helper flag
            this family needs is a linear form over the bits and stays inline (§1's
            signals). On a live row the bits are one-hot, so exactly one of the two is 1;
            on a padding row both are free booleans, which costs a table multiplicity and
            nothing else (§5.10).
```

**C. Which queries a row makes, and where (151–158)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
151     rs1_mask_rule — every kind reads rs1                            Quadratic, degree 2
        code  mask_rule(frame(1, FIELD_MASK), &KINDS)

  positional  0 = M[6] − M[1]·W[13] − M[1]·W[14] − … − M[1]·W[24]      (all twelve bits)
  named       0 = rs1_mask − pc_mask·Σ_k kind_k

────────────────────────────────────────────────────────────────────────────────────────────
152     rs2_mask_rule — only the R-type half reads rs2                  Quadratic, degree 2
        code  mask_rule(frame(2, FIELD_MASK), &READS_RS2)

  positional  0 = M[11] − M[1]·W[19] − M[1]·W[21] − M[1]·W[22] − M[1]·W[24] − M[1]·W[23]
                  − M[1]·W[20]
  named       0 = rs2_mask − pc_mask·(kind_sll + kind_srl + kind_sra
                                      + kind_and + kind_or + kind_xor)

────────────────────────────────────────────────────────────────────────────────────────────
153     rd_mask_rule — every kind writes rd                             Quadratic, degree 2
        code  mask_rule(frame(3, FIELD_MASK), &KINDS)

  positional  0 = M[16] − M[1]·W[13] − M[1]·W[14] − … − M[1]·W[24]
  named       0 = rd_mask − pc_mask·Σ_k kind_k

  reads as (151–153)  on a live row the bits are one-hot, so each sum is 0 or 1 and the
                      mask is the kind's use of the query; an I-type row makes no rs2
                      query and reads 0 there (158). On a padding row pc_mask = 0 and every
                      mask is 0, whatever the bits hold: S14's control C8, which the row
                      suite refuses on this frame twice — bare, by 153 with 156, and
                      dressed to satisfy every other gate, by 153 alone (§5.10).

────────────────────────────────────────────────────────────────────────────────────────────
154–156 <q>_addr_rule — a present query's register is the decoded one  Quadratic, degree 2
        code  addr_rule(slot, DECODED_<Q>)

  154 rs1_addr_rule   0 = M[6]·M[7]   − M[6]·W[8]     0 = rs1_mask·(rs1_addr − decoded_rs1)
  155 rs2_addr_rule   0 = M[11]·M[12] − M[11]·W[9]    0 = rs2_mask·(rs2_addr − decoded_rs2)
  156 rd_addr_rule    0 = M[16]·M[17] − M[16]·W[10]   0 = rd_mask·(rd_addr − decoded_rd)

  reads as  §4.5's 110–112: no constant term, this family having no ecall row. rd = x0
            needs no bit — the table's rd is 0, 156 makes the write's address 0, and
            130–133 write 0 whatever rd_selected is.

────────────────────────────────────────────────────────────────────────────────────────────
157–158 <q>_value_masked — an absent operand reads 0                   Quadratic, degree 2
        code  value_masked(slot)

  157 rs1_value_masked  0 = M[9]  − M[6]·M[9]      0 = (1 − rs1_mask)·rs1_read_value
  158 rs2_value_masked  0 = M[14] − M[11]·M[14]    0 = (1 − rs2_mask)·rs2_read_value

  reads as  158 is what makes `src2 = rs2 + imm` one expression for both operand shapes:
            an I-type row's rs2 reads 0, so src2 is the immediate, and an R-type row's
            decoded imm is 0 (the table's), so src2 is the register. One addend is always
            zero, the field sum is the integer sum, and no wrap bit is needed
            (shift-bitwise.md §1).
```

**D. The pc, the amount and the powers (159–164)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
159     next_pc_rule — the pc falls through, always                     Linear, degree 1
        code  shift_bitwise::family_spec

  positional  0 = M[5] − W[7]
  named       0 = pc_write_value − decoded_next_pc

  reads as  no kind here computes a pc, so there is no wrap bit and no bound of its own:
            the decoder lookup binds decoded_next_pc to the identity-committed table
            exactly as it binds rs1, rs2, rd and imm, none of which is range-checked
            either. S17's rule that a family computing a pc keeps its next_pc even does not
            reach a family that copies one (shift-bitwise.md §4.1).

────────────────────────────────────────────────────────────────────────────────────────────
160     amount_split — the shamt is the low five bits of src2           Linear, degree 1
        code  shift_bitwise::family_spec, `split`

  positional  0 = M[14] + W[11] − 32·W[33] − W[30]
  named       0 = rs2_read_value + decoded_imm − 32·high − amount

  reads as  ungated and degree 1. With `amount` in [0, 32) from ShiftPowers' domain, `high`
            bounded by its own 16+16 pair and `src2` by its own, the split is the unique
            one and `amount` really is src2 mod 32. **Never leave the shamt free**: an
            amount used only as a lookup key is prover-chosen, and `sll` with rs2 = 4 would
            shift by 8 — the row the suite's
            the_shamt_is_not_free_and_the_high_chunks_bound_is_what_closes_it builds, whose
            only honest `high` is −1/8 and which one of high's two obligations refuses. On
            a bitwise row the gate still holds, the fill writing the true split, and
            `amount` is unconstrained beyond it, ShiftPowers being off there.

────────────────────────────────────────────────────────────────────────────────────────────
161     copower_rule — the looked-up pair multiplies to 2^31            Quadratic, degree 2
        code  shift_bitwise::family_spec, over generic_table::SHIFT_COPOWER_BITS

  positional  0 = −2147483648·W[25] + W[31]·W[32]
  named       0 = pow·copow − 2^31·f_shift

  reads as  the table stores the copower **halved**, 2^(31 − s) rather than 2^(32 − s),
            because at s = 0 the latter is 2^32 and the packed table's columns are
            u32-backed; the two gates that read it carry the compensating factor 2
            (shift-bitwise.md §3.1). The gate is redundant given 160 and the key bound of
            §5.6 — those confine the key to ShiftPowers' own 32 rows, so the looked-up pair
            is already that row's — and is kept as the circuit's own reading of the table:
            a ShiftPowers row generated wrong stops the honest prover here rather than
            licensing a residue bound that is not one. On a bitwise row f_shift is 0, so it
            says pow·copow = 0 and the fill writes both as 0.

────────────────────────────────────────────────────────────────────────────────────────────
162     se_rule — the sign-extension term                               Quadratic, degree 2
        code  shift_bitwise::family_spec, over ARITHMETIC

  positional  0 = W[35] − W[16]·W[28] − W[22]·W[28]
  named       0 = se − (kind_srai + kind_sra)·rs1_sign

163     rs1_sign_boolean   0 = W[28] − W[28]·W[28]    0 = rs1_sign − rs1_sign²
164     se_boolean         0 = W[35] − W[35]·W[35]    0 = se − se²
        Quadratic, degree 2; code  shift_bitwise's private booleanity

  reads as (162–164)  `se` is 0 on every logical shift and every bitwise row, and rs1's bit
                      31 on sra and srai. It is committed rather than inlined for the
                      degree: is_arithmetic·rs1_sign appears inside two further products
                      (165, 167), and inlining it would make each degree 3. se_boolean is
                      implied by 162 over a boolean rs1_sign and one-hot kind bits; it is
                      written anyway, S18 must-be-exact 5 asking a sign bit's
                      sign-weighted form to carry one. The suite's
                      an_srai_carrying_srlis_answer_is_refused_by_se_rule_alone is the row
                      that shows 162 load-bearing: an srli's whole honest witness with the
                      kind bit and the packed mask swapped to srai, which every other gate
                      and the decoder lookup accept.
```

**E. The one product, and both shift directions (165–168)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
165     shift_in_rule — which multiplicand the product takes            Quadratic, degree 2
        code  shift_bitwise::family_spec, over LEFT then RIGHT

  positional  0 = W[36] − W[13]·M[9] − W[19]·M[9]
                  − W[15]·W[6] + 2^32·W[15]·W[35] − W[16]·W[6] + 2^32·W[16]·W[35]
                  − W[21]·W[6] + 2^32·W[21]·W[35] − W[22]·W[6] + 2^32·W[22]·W[35]
  named, factored
    0 = shift_in − (kind_slli + kind_sll)·rs1_read_value
                 − (kind_srli + kind_srai + kind_srl + kind_sra)·(rd_selected − 2^32·se)

────────────────────────────────────────────────────────────────────────────────────────────
166     shift_prod_rule — the one multiplication by pow                 Quadratic, degree 2
        code  shift_bitwise::family_spec

  positional  0 = W[37] − W[36]·W[31]
  named       0 = shift_prod − shift_in·pow

────────────────────────────────────────────────────────────────────────────────────────────
167     shift_out_rule — both directions read the one product           Quadratic, degree 2
        code  shift_bitwise::family_spec, over LEFT then RIGHT

  positional  0 = W[13]·W[37] − W[13]·W[6] − 2^32·W[13]·W[38]
                  + W[19]·W[37] − W[19]·W[6] − 2^32·W[19]·W[38]
                  + W[15]·W[37] + W[15]·W[40] − W[15]·M[9] + 2^32·W[15]·W[35]
                  + W[16]·W[37] + W[16]·W[40] − W[16]·M[9] + 2^32·W[16]·W[35]
                  + W[21]·W[37] + W[21]·W[40] − W[21]·M[9] + 2^32·W[21]·W[35]
                  + W[22]·W[37] + W[22]·W[40] − W[22]·M[9] + 2^32·W[22]·W[35]
  named, factored
    0 = (kind_slli + kind_sll)·(shift_prod − rd_selected − 2^32·ovf)
      + (kind_srli + kind_srai + kind_srl + kind_sra)
        ·(shift_prod + residue − rs1_read_value + 2^32·se)

────────────────────────────────────────────────────────────────────────────────────────────
168     scaled_rule — the copower half of the residue bound             Quadratic, degree 2
        code  shift_bitwise::family_spec

  positional  0 = W[42] − 2·W[40]·W[32]
  named       0 = scaled − 2·residue·copow

  reads as (165–168)  **one product serves both directions**: 166 is ungated and is the
                      only multiplication by pow, and 165 is what chooses its multiplicand,
                      which is what keeps 167 degree 2 — writing either arm as
                      is_left·(rs1·pow − …) would be degree 3.
                      Left:  shift_in = rs1, so shift_prod = rs1·2^s < 2^63, and 167 splits
                             it as rd + 2^32·ovf with both parts 16+16 range-checked, a
                             split of an integer below 2^64 that is unique.
                      Right: with rs1_adj = rs1 − 2^32·se and rd_adj = rd − 2^32·se, 167 is
                             the floor-division identity rs1_adj = rd_adj·2^s + residue,
                             which covers both signs because an arithmetic shift of a
                             negative word is the floor division of its signed value and
                             the result's sign is the operand's.
                      On a bitwise row every arm is multiplied by a kind bit that is 0, so
                      165–167 hold at shift_in = shift_prod = 0, which the fill writes; the
                      forgeries that show each load-bearing are the suite's `and carrying a
                      shift multiplicand`, `and carrying a shift product` and the two slli
                      rows whose product and whose result each move by themselves.
                      168 is the residue bound's scaled half: scaled = residue·2^(32 − s),
                      16+16 range-checked, which says residue < 2^s — *given* residue is an
                      integer. Over Fr a "residue" of s·(2^(32−s))^{-1} satisfies the scaled
                      bound and absorbs rs1 − rd·2^s for any rd, so residue carries its own
                      **direct** 16+16 pair and check_copowers refuses the circuit without
                      it (shift-bitwise.md §4.3; the suite's
                      a_residue_that_is_not_an_integer_is_refused_by_its_own_bound).
```

**F. The bitwise half (169–171)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
169     rs1_bytes — rs1 is its four bytes                               Linear, degree 1
170     src2_bytes — src2 is its four bytes                             Linear, degree 1
        code  shift_bitwise::family_spec, over byte_weights

  169 positional  0 = M[9] − W[44] − 256·W[45] − 65536·W[46] − 16777216·W[47]
      named       0 = rs1_read_value − Σ_j 2^(8j)·byte_a_j
  170 positional  0 = M[14] + W[11] − W[48] − 256·W[49] − 65536·W[50] − 16777216·W[51]
      named       0 = rs2_read_value + decoded_imm − Σ_j 2^(8j)·byte_b_j

  reads as  both are ungated and degree 1. On a shift row the byte columns carry no table
            lookup — f_bitwise is 0 — so a decomposition always exists and constrains
            nothing; on a bitwise row the byte table's domain bounds each of the eight and
            the decomposition is the unique one.

────────────────────────────────────────────────────────────────────────────────────────────
171     bitwise_out_rule — AND, OR and XOR from one accumulator         Quadratic, degree 2
        code  shift_bitwise::family_spec, `bitwise`

  positional  0 = W[26]·W[6]
                  − (W[23] + W[17] + W[20] + W[14])·(M[14] + W[11] + M[9])   ×as written
                  − Σ_j 2^(8j)·(W[24] + W[18])·byte_and_j
                  + Σ_j 2^(8j)·(W[23] + W[17])·byte_and_j
                  + Σ_j 2^(8j+1)·(W[20] + W[14])·byte_and_j
  named, factored
    0 = f_bitwise·rd_selected − t1·(rs1_read_value + rs2_read_value + decoded_imm)
                              − t2·Σ_j 2^(8j)·byte_and_j,
    t1 = kind_or + kind_ori + kind_xor + kind_xori,
    t2 = (kind_and + kind_andi) − (kind_or + kind_ori) − 2·(kind_xor + kind_xori)

  reads as  per byte `or = a + b − and` and `xor = a + b − 2·and`; summing by weight and
            using 169 and 170, rd = t1·(rs1 + src2) + t2·Σ 2^(8j)·and_j. So **there is no
            XOR table and no OR table**: `and` is Σ 2^(8j)·and_j, `or` is
            rs1 + src2 − Σ 2^(8j)·and_j and `xor` is rs1 + src2 − 2·Σ 2^(8j)·and_j, each
            exact over the integers since a | b and a ^ b are below 2^32 and no carry
            crosses a byte (acceptance 7, checked over the whole 8×8-bit domain by the
            suite). The accumulator is inlined as that linear form and is never a column.
            **The rd term is gated by the family bit, not by the bracket**: on a shift row
            t1 and t2 are both 0, so a bare rd_selected would force rd = 0 and break every
            shift; with f_bitwise in front the gate is 0 = 0 there.
```

Of the 48 gates, 9 are degree 1: the two write-backs, `decoded_mask_bits`, the two flag rules,
`next_pc_rule`, `amount_split` and the two byte decompositions. All 48 have constant 0, so each
is 0 on the all-zero row, and the assembly records `zero_row_valid = true` (the dump's padding
contract) — which `assemble` asserts before returning.

### 5.6 The 39 lookups

`CircuitArtifact::lookups`, in order. The frame's 8 come from the private `memory::gap_lookups`;
the rest from `shift_bitwise::family_spec` (its private `range32`, `low_half`, `key_bound`,
`generic` and the inline `decode_row`). Fourteen `RANGE16` obligations are selected by `pc_mask`,
two by `f_shift` and eight by `f_bitwise`.

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `gap_hi_pc` | `TIMESTAMP` (0) | `M[1]` | `W[0]` | `pc_gap_hi` | `< 2^19` |
| 1 | `gap_lo_pc` | `TIMESTAMP` | `M[1]` | `4·M[0] − M[3] − 2^19·W[0] − 1` | `4·cycle − pc_read_ts − 2^19·pc_gap_hi − 1` | `< 2^19` |
| 2 | `gap_hi_rs1` | `TIMESTAMP` | `M[6]` | `W[1]` | `rs1_gap_hi` | `< 2^19` |
| 3 | `gap_lo_rs1` | `TIMESTAMP` | `M[6]` | `4·M[0] − M[8] − 2^19·W[1]` | `4·cycle − rs1_read_ts − 2^19·rs1_gap_hi` | `< 2^19` |
| 4 | `gap_hi_rs2` | `TIMESTAMP` | `M[11]` | `W[2]` | `rs2_gap_hi` | `< 2^19` |
| 5 | `gap_lo_rs2` | `TIMESTAMP` | `M[11]` | `4·M[0] − M[13] − 2^19·W[2] + 1` | `4·cycle − rs2_read_ts − 2^19·rs2_gap_hi + 1` | `< 2^19` |
| 6 | `gap_hi_rd` | `TIMESTAMP` | `M[16]` | `W[3]` | `rd_gap_hi` | `< 2^19` |
| 7 | `gap_lo_rd` | `TIMESTAMP` | `M[16]` | `4·M[0] − M[18] − 2^19·W[3] + 2` | `4·cycle − rd_read_ts − 2^19·rd_gap_hi + 2` | `< 2^19` |
| 8 | `rs1_hi_range` | `RANGE16` (1) | `M[1]` | `W[27]` | `rs1_hi` | `< 2^16` |
| 9 | `rs1_lo_range` | `RANGE16` | `M[1]` | `M[9] − 2^16·W[27]` | `rs1_read_value − 2^16·rs1_hi` | `< 2^16` |
| 10 | `src2_hi_range` | `RANGE16` | `M[1]` | `W[29]` | `src2_hi` | `< 2^16` |
| 11 | `src2_lo_range` | `RANGE16` | `M[1]` | `M[14] + W[11] − 2^16·W[29]` | `rs2_read_value + decoded_imm − 2^16·src2_hi` | `< 2^16` |
| 12 | `high_hi_range` | `RANGE16` | `M[1]` | `W[34]` | `high_hi` | `< 2^16` |
| 13 | `high_lo_range` | `RANGE16` | `M[1]` | `W[33] − 2^16·W[34]` | `high − 2^16·high_hi` | `< 2^16` |
| 14 | `ovf_hi_range` | `RANGE16` | `M[1]` | `W[39]` | `ovf_hi` | `< 2^16` |
| 15 | `ovf_lo_range` | `RANGE16` | `M[1]` | `W[38] − 2^16·W[39]` | `ovf − 2^16·ovf_hi` | `< 2^16` |
| 16 | `residue_hi_range` | `RANGE16` | `M[1]` | `W[41]` | `residue_hi` | `< 2^16` |
| 17 | `residue_lo_range` | `RANGE16` | `M[1]` | `W[40] − 2^16·W[41]` | `residue − 2^16·residue_hi` | `< 2^16` |
| 18 | `scaled_hi_range` | `RANGE16` | `M[1]` | `W[43]` | `scaled_hi` | `< 2^16` |
| 19 | `scaled_lo_range` | `RANGE16` | `M[1]` | `W[42] − 2^16·W[43]` | `scaled − 2^16·scaled_hi` | `< 2^16` |
| 20 | `rd_hi_range` | `RANGE16` | `M[1]` | `W[56]` | `rd_hi` | `< 2^16` |
| 21 | `rd_lo_range` | `RANGE16` | `M[1]` | `W[6] − 2^16·W[56]` | `rd_selected − 2^16·rd_hi` | `< 2^16` |
| 22 | `amount_range` | `RANGE16` | `W[25]` | `W[30]` | `amount` | `< 2^16` |
| 23 | `amount_scaled` | `RANGE16` | `W[25]` | `2048·W[30]` | `2^11·amount` | `< 2^16`, i.e. `amount < 2^5` |
| 24 | `byte_a0_range` | `RANGE16` | `W[26]` | `W[44]` | `byte_a0` | `< 2^16` |
| 25 | `byte_a0_scaled` | `RANGE16` | `W[26]` | `256·W[44]` | `2^8·byte_a0` | `< 2^16`, i.e. `byte_a0 < 2^8` |
| 26–31 | `byte_a1_range` … `byte_a3_scaled` | `RANGE16` | `W[26]` | `W[45]`, `256·W[45]`, `W[46]`, `256·W[46]`, `W[47]`, `256·W[47]` | the same pair per byte | `byte_a_j < 2^8` |
| 32 | `rs1_get_sign` | `GENERIC` (2) | `M[1]` | `(W[27] + 256, W[28], 0)` | `(rs1_hi + SIGN_BASE, rs1_sign, 0)` | the gated tuple `(rs1_hi + 257, rs1_sign, 0)` is a row of `S[7..10]` |
| 33 | `shift_powers` | `GENERIC` | `W[25]` | `(W[30] + 65792, W[31], W[32])` | `(amount + SHIFT_BASE, pow, copow)` | the gated tuple `(amount + 65793, pow, copow)` is a row of `S[7..10]` |
| 34 | `and_byte_0` | `GENERIC` | `W[26]` | `(W[44], W[48], W[52])` | `(byte_a0 + AND_BASE, byte_b0, byte_and0)` | the gated tuple `(byte_a0 + 1, byte_b0, byte_and0)` is a row of `S[7..10]` |
| 35–37 | `and_byte_1` … `and_byte_3` | `GENERIC` | `W[26]` | `(W[45], W[49], W[53])`, `(W[46], W[50], W[54])`, `(W[47], W[51], W[55])` | the same per byte | as 34 |
| 38 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[7], W[8], W[9], W[10], W[11], W[12])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_imm, decoded_mask)` | a row of `S[0..7]` |

Read in pairs, as in §3.6 and §4.6: each `gap_hi`/`gap_lo` pair puts a read strictly before its
own write, and each `_hi_range`/`_lo_range` pair bounds `rs1_read_value`, `src2`, `high`, `ovf`,
`residue`, `scaled` and `rd_selected` below `2^32`.

**Ten of the 24 `RANGE16` obligations are key bounds, and they are the most important thing in
this family's accounting.** `lookup.md` §4 states the precondition — a family must bound the keys
it looks up — and with **three sub-tables packed into one channel** it is load-bearing in a way
it was not when the channel held one map each stage used: an out-of-range key does not *miss* the
table, it lands on **another sub-table's row**, and the lookup holds while the row means
something else entirely. This is a witness against an earlier draft of this circuit rather than a
hypothesis. A bitwise row claiming `byte_a0 = 65_823` produces the gated key `65_824`, which is
`ShiftPowers`' row for `s = 31`, `(65_824, 2^31, 1)`; the lookup then holds with
`byte_b0 = 2^31` and `byte_and0 = 1`, and with `rs1 = 65_823` and `rs2 = 2^31` — both ordinary
register values — the recomposition writes 1 for `and` where the answer is 0, and
`rs1 ^ rs2 − 2` for `xor`. Every other gate holds and both results are inside `[0, 2^32)`
(`shift-bitwise.md` §3.3; the suite's
`a_byte_key_outside_the_and_table_is_refused_by_its_own_bound`).

So each of the three keys this family looks up carries its own bound, and each bound is a
**pair** — the direct halfword check, and the column scaled so that the product is a halfword
only below the bound:

| key | sub-table | bound | obligations | under |
| --- | --- | --- | --- | --- |
| `rs1_hi + SIGN_BASE` | `U16GetSign` | `rs1_hi < 2^16` | 8, 9 — the 16+16 pair on `rs1` | `pc_mask` |
| `amount + SHIFT_BASE` | `ShiftPowers` | `amount < 2^5` | 22, 23 | `f_shift` |
| `byte_a_j + AND_BASE` | the AND byte table | `byte_a_j < 2^8` | 24–31, two per byte | `f_bitwise` |

Neither half of a pair is redundant. The **direct** half is the other half of S15's copower rule:
a scaled bound alone admits `k·2^(bits − 16)` for a small `k`, which is not a small integer at
all — `byte_a0 = 256` gates to 257, `U16GetSign`'s row for the halfword 0, and is below `2^16`,
so the direct half accepts it and the scaled half alone refuses it. The **scaled** half is what
turns a 16-bit table into a 5-bit or an 8-bit one. `lookup::check_copowers`, **tightened at
S18**, now takes each copower-scaled column with the selector its scaled obligation carries and
requires the direct pair under *that same* selector: S17 matched an obligation on its expression
alone, so a circuit whose direct pair sat under a narrower selector than its scaled obligation
passed while bounding nothing on the rows the narrow selector switches off
(`shift-bitwise.md` §3.4). `assemble` runs it over all six scaled columns — `residue` under
`pc_mask`, whose scale is the looked-up `copow`, and `amount` and the four byte keys under their
own selectors, whose scales are literals — and the unit test
`a_residue_bound_under_a_narrower_selector_fails_the_build` is that check firing.

Bounding the *key* is all that is needed. With `byte_a_j` below 256 the row it matches is an AND
row, and that row fixes `byte_b_j` below 256 and `byte_and_j` to `byte_a_j & byte_b_j`; with
`amount` below 32 the row is a `ShiftPowers` row, and that row fixes `pow` and `copow`.
**`ShiftPowers`' domain is the only thing that bounds `amount` to `[0, 32)`** — no gate does —
which is why the suite's `only_the_shift_powers_table_refuses_an_untruncated_amount` builds a
row whose `amount` is 33 with `pow = 2^33` and a copower of `2^-2`, so that `pow·copow` is still
`2^31`, and finds the table the lone refusal.

The channels, `shift_bitwise::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[57]` | 8 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[58]` | **24** | **32** |
| 6, 7 | `GENERIC` | 2 | `S[7..10]` | `W[59]` | 6 | 8 |
| 8, 9 | `DECODER` | 3 | `S[0..7]` | `W[60]` | 1 | 2 |

`artifact` asserts the four obligation counts. The `RANGE16` row is why this circuit is 26 gate
lists deep at `n = 20` where §3's and §4's are 25: 24 obligations plus one table fraction is 25
leaves, which pads to 32 and takes five row-wise levels instead of four.

### 5.7 Inner layers `L2`–`L6`: the row-wise reduction

The conventions are §3.7's. There are **five** row-wise reduction lists here, not four.

**`L2`, gate list 1, 62 columns, relations 172–233.**

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 172 | `read_2_0` | `read_pc · read_rs1` |
| 1 | 173 | `read_2_1` | `read_rs2 · read_rd` |
| 2 | 174 | `write_2_0` | `write_pc · write_rs1` |
| 3 | 175 | `write_2_1` | `write_rs2 · write_rd` |
| 4, 5 | 176, 177 | `timestamp_2_0` | `timestamp_table + gap_hi_pc` |
| 6, 7 | 178, 179 | `timestamp_2_1` | `gap_lo_pc + gap_hi_rs1` |
| 8, 9 | 180, 181 | `timestamp_2_2` | `gap_lo_rs1 + gap_hi_rs2` |
| 10, 11 | 182, 183 | `timestamp_2_3` | `gap_lo_rs2 + gap_hi_rd` |
| 12, 13 | 184, 185 | `timestamp_2_4` | `gap_lo_rd + timestamp_pad_0` |
| 14, 15 | 186, 187 | `timestamp_2_5` | `timestamp_pad_1 + timestamp_pad_2` |
| 16, 17 | 188, 189 | `timestamp_2_6` | `timestamp_pad_3 + timestamp_pad_4` |
| 18, 19 | 190, 191 | `timestamp_2_7` | `timestamp_pad_5 + timestamp_pad_6` |
| 20, 21 | 192, 193 | `range16_2_0` | `range16_table + rs1_hi_range` |
| 22, 23 | 194, 195 | `range16_2_1` | `rs1_lo_range + src2_hi_range` |
| 24, 25 | 196, 197 | `range16_2_2` | `src2_lo_range + high_hi_range` |
| 26, 27 | 198, 199 | `range16_2_3` | `high_lo_range + ovf_hi_range` |
| 28, 29 | 200, 201 | `range16_2_4` | `ovf_lo_range + residue_hi_range` |
| 30, 31 | 202, 203 | `range16_2_5` | `residue_lo_range + scaled_hi_range` |
| 32, 33 | 204, 205 | `range16_2_6` | `scaled_lo_range + rd_hi_range` |
| 34, 35 | 206, 207 | `range16_2_7` | `rd_lo_range + amount_range` |
| 36, 37 | 208, 209 | `range16_2_8` | `amount_scaled + byte_a0_range` |
| 38, 39 | 210, 211 | `range16_2_9` | `byte_a0_scaled + byte_a1_range` |
| 40, 41 | 212, 213 | `range16_2_10` | `byte_a1_scaled + byte_a2_range` |
| 42, 43 | 214, 215 | `range16_2_11` | `byte_a2_scaled + byte_a3_range` |
| 44, 45 | 216, 217 | `range16_2_12` | `byte_a3_scaled + range16_pad_0` |
| 46, 47 | 218, 219 | `range16_2_13` | `range16_pad_1 + range16_pad_2` |
| 48, 49 | 220, 221 | `range16_2_14` | `range16_pad_3 + range16_pad_4` |
| 50, 51 | 222, 223 | `range16_2_15` | `range16_pad_5 + range16_pad_6` |
| 52, 53 | 224, 225 | `generic_2_0` | `generic_table + rs1_get_sign` |
| 54, 55 | 226, 227 | `generic_2_1` | `shift_powers + and_byte_0` |
| 56, 57 | 228, 229 | `generic_2_2` | `and_byte_1 + and_byte_2` |
| 58, 59 | 230, 231 | `generic_2_3` | `and_byte_3 + generic_pad_0` |
| 60, 61 | 232, 233 | `decoder_2_0` | `decoder_table + decode_row` |

Positionally, `range16_2_8` is `L{2}[36] = L{1}[72]·L{1}[75] + L{1}[74]·L{1}[73]` and
`L{2}[37] = L{1}[73]·L{1}[75]`: `1/(E_amount_scaled + g) + 1/(E_byte_a0_range + g)`, two
obligations under two different selectors added as ordinary fractions — the tree does not know
that one is off wherever the other is on.

**`L3`, gate list 2, 32 columns, relations 234–265.**

| `L3` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 234 | `read_3_0` | `read_2_0 · read_2_1` |
| 1 | 235 | `write_3_0` | `write_2_0 · write_2_1` |
| 2, 3 | 236, 237 | `timestamp_3_0` | `timestamp_2_0 + timestamp_2_1` |
| 4, 5 | 238, 239 | `timestamp_3_1` | `timestamp_2_2 + timestamp_2_3` |
| 6, 7 | 240, 241 | `timestamp_3_2` | `timestamp_2_4 + timestamp_2_5` |
| 8, 9 | 242, 243 | `timestamp_3_3` | `timestamp_2_6 + timestamp_2_7` |
| 10, 11 | 244, 245 | `range16_3_0` | `range16_2_0 + range16_2_1` |
| 12, 13 | 246, 247 | `range16_3_1` | `range16_2_2 + range16_2_3` |
| 14, 15 | 248, 249 | `range16_3_2` | `range16_2_4 + range16_2_5` |
| 16, 17 | 250, 251 | `range16_3_3` | `range16_2_6 + range16_2_7` |
| 18, 19 | 252, 253 | `range16_3_4` | `range16_2_8 + range16_2_9` |
| 20, 21 | 254, 255 | `range16_3_5` | `range16_2_10 + range16_2_11` |
| 22, 23 | 256, 257 | `range16_3_6` | `range16_2_12 + range16_2_13` |
| 24, 25 | 258, 259 | `range16_3_7` | `range16_2_14 + range16_2_15` |
| 26, 27 | 260, 261 | `generic_3_0` | `generic_2_0 + generic_2_1` |
| 28, 29 | 262, 263 | `generic_3_1` | `generic_2_2 + generic_2_3` |
| 30, 31 | 264, 265 | `decoder_3_0` | copy of `decoder_2_0` |

**`L4`, gate list 3, 18 columns, relations 266–283.**

| `L4` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 266 | `read_4_0` | copy of `read_3_0` |
| 1 | 267 | `write_4_0` | copy of `write_3_0` |
| 2, 3 | 268, 269 | `timestamp_4_0` | `timestamp_3_0 + timestamp_3_1` |
| 4, 5 | 270, 271 | `timestamp_4_1` | `timestamp_3_2 + timestamp_3_3` |
| 6, 7 | 272, 273 | `range16_4_0` | `range16_3_0 + range16_3_1` |
| 8, 9 | 274, 275 | `range16_4_1` | `range16_3_2 + range16_3_3` |
| 10, 11 | 276, 277 | `range16_4_2` | `range16_3_4 + range16_3_5` |
| 12, 13 | 278, 279 | `range16_4_3` | `range16_3_6 + range16_3_7` |
| 14, 15 | 280, 281 | `generic_4_0` | `generic_3_0 + generic_3_1` |
| 16, 17 | 282, 283 | `decoder_4_0` | copy of `decoder_3_0` |

**`L5`, gate list 4, 12 columns, relations 284–295.**

| `L5` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 284 | `read_5_0` | copy of `read_4_0` |
| 1 | 285 | `write_5_0` | copy of `write_4_0` |
| 2, 3 | 286, 287 | `timestamp_5_0` | `timestamp_4_0 + timestamp_4_1` |
| 4, 5 | 288, 289 | `range16_5_0` | `range16_4_0 + range16_4_1` |
| 6, 7 | 290, 291 | `range16_5_1` | `range16_4_2 + range16_4_3` |
| 8, 9 | 292, 293 | `generic_5_0` | copy of `generic_4_0` |
| 10, 11 | 294, 295 | `decoder_5_0` | copy of `decoder_4_0` |

**`L6`, gate list 5, 10 columns, relations 296–305** — the row-wise top: one value per row per
tree. Every tree but `range16` has finished and is copied up one more time than in §3 and §4.

| `L6` | relations | node | formula | value at row `y` |
| --- | --- | --- | --- | --- |
| 0 | 296 | `read_6_0` | copy of `read_5_0` | the product of row `y`'s 4 read leaves |
| 1 | 297 | `write_6_0` | copy of `write_5_0` | the product of row `y`'s 4 write leaves |
| 2, 3 | 298, 299 | `timestamp_6_0` | copy of `timestamp_5_0` | the sum of row `y`'s 16 timestamp fractions |
| 4, 5 | 300, 301 | `range16_6_0` | `range16_5_0 + range16_5_1` | the sum of row `y`'s 32 range16 fractions |
| 6, 7 | 302, 303 | `generic_6_0` | copy of `generic_5_0` | the sum of row `y`'s 8 generic fractions |
| 8, 9 | 304, 305 | `decoder_6_0` | copy of `decoder_5_0` | the sum of row `y`'s 2 decoder fractions |

### 5.8 The halving layers and the outputs

Gate list `k`, for `6 ≤ k ≤ n + 5`, halves layer `k` into layer `k + 1`, which has
`n + 5 − k` variables. Its ten gates, relation `r = 306 + 10(k − 6)`, with §3.8's formulas:

| `L{k+1}` | relation | node | shape |
| --- | --- | --- | --- |
| 0 | `r` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` |
| 1 | `r + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` |
| 2 | `r + 2` | `timestamp_{k+1}_0_num` | `TreeCross { L{k}[2], L{k}[3] }` |
| 3 | `r + 3` | `timestamp_{k+1}_0_den` | `TreeProduct { L{k}[3] }` |
| 4 | `r + 4` | `range16_{k+1}_0_num` | `TreeCross { L{k}[4], L{k}[5] }` |
| 5 | `r + 5` | `range16_{k+1}_0_den` | `TreeProduct { L{k}[5] }` |
| 6 | `r + 6` | `generic_{k+1}_0_num` | `TreeCross { L{k}[6], L{k}[7] }` |
| 7 | `r + 7` | `generic_{k+1}_0_den` | `TreeProduct { L{k}[7] }` |
| 8 | `r + 8` | `decoder_{k+1}_0_num` | `TreeCross { L{k}[8], L{k}[9] }` |
| 9 | `r + 9` | `decoder_{k+1}_0_den` | `TreeProduct { L{k}[9] }` |

In the last list, `k = n + 5`, the ten nodes are named `read_root`, `write_root`,
`timestamp_num_root`, `timestamp_den_root`, `range16_num_root`, `range16_den_root`,
`generic_num_root`, `generic_den_root`, `decoder_num_root` and `decoder_den_root`. At `n = 20`
the halving lists are 6 to 25, `L7` has 19 variables and `L26` none. At `n = 22` they are 6 to
27, and the top is `L28`.

**The outputs**, in output-map order. All ten are absorbed as one `GKR_OUTPUTS` message before
any challenge of the backward pass, and travel in `ShardProof::outputs`.

| # | address, `n = 20` | node | value | what `verify_shard` does with it |
| --- | --- | --- | --- | --- |
| 0 | `L{26}[0]` | `read_root` | the product of every read leaf of the shard | step 10: must equal `PublicInputs::memory_roots[p][0]`, `p` being the position of `(2, shard_index)` in `verifier_core::statement_shards`, after `INIT_TEARDOWN`'s shard, every `ZERO_WINDOWS` shard and every `ADD_SUB_LUI_AUIPC` and `JUMP_BRANCH_SLT` shard (`shard-proof.md` §1.2); 3 in S18's statement; a factor of `reconciles` |
| 1 | `L{26}[1]` | `write_root` | the product of every write leaf | step 10: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |
| 2 | `L{26}[2]` | `timestamp_num_root` | as §3.8's output 2 | step 9: must be 0; otherwise `Lookup { channel: 0 }` |
| 3 | `L{26}[3]` | `timestamp_den_root` | as §3.8's output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 0 }` |
| 4 | `L{26}[4]` | `range16_num_root` | as output 2, for `RANGE16` | step 9: must be 0; otherwise `Lookup { channel: 1 }` |
| 5 | `L{26}[5]` | `range16_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 1 }` |
| 6 | `L{26}[6]` | `generic_num_root` | as output 2, for `GENERIC` | step 9: must be 0; otherwise `Lookup { channel: 2 }` |
| 7 | `L{26}[7]` | `generic_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 2 }` |
| 8 | `L{26}[8]` | `decoder_num_root` | as output 2, for `DECODER` | step 9: must be 0; otherwise `Lookup { channel: 3 }` |
| 9 | `L{26}[9]` | `decoder_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 3 }` |

### 5.9 Witness rows

The table shows eight of the 34 live `honest_rows` in `crates/checker/tests/shift_bitwise.rs`,
and the padding row. The other 26 are the remaining kinds over mixed patterns; `slli`, `srli`
and `srai` at shamt 0, 1 and 31; `sll`, `srl` and `sra` by `rs2 = 32`, `33` and `0xffffffff`,
which truncate to 0, 1 and 31; a small-operand `sll by rs2 = 33`, whose doubled word still fits a
32-bit `ovf`; `andi into x0`; and a compressed `srli`, whose fall-through is `pc + 2`. Each row is
built from Rust's own `u32` and `i32` arithmetic, and
`every_row_kind_satisfies_every_gate_and_every_bound` holds it to every gate, every range
obligation and both table channels in CI: the suite's `violated_tables` checks a generic tuple
against `program::lookup_tables::generic_entries` and a decoder tuple against the row's own
`S[0..7]`.

A row is checked alone, as §3.9's and §4.9's are: each register query reads a write made eight
timestamps before its own and the pc query the previous cycle's, so every `<q>_gap_hi` is 0; the
multiplicities are 0; `S[0..7]` hold the row's own table entry and `S[7..10]` are 0, and the
table below omits them. Every live row shown has cycle 7, pc `0x1000` and a 4-byte instruction,
`rs1` is `x5`, `rs2` is `x6` on an R-type row and `x0` on an I-type one, `rd` is `x7`, and `P` is
0 in every cell.

`A` `slli x7, x5, 3` with `x5 = 0x12345679`. `B` `srai x7, x5, 3` with `x5 = 0xfedcba98`.
`C` `sll x7, x5, x6` with `x5 = 0x12345679`, `x6 = 4`. `D` `sra x7, x5, x6` with
`x5 = 0xfedcba99`, `x6 = 33`, which truncates to 1. `E` `and x7, x5, x6` with
`x5 = 0xf0f00ff0`, `x6 = 0x0ff0f00f`. `F` `xori x7, x5, -1` with `x5 = 0x12345678`.
`G` `slli x0, x5, 3` with `x5 = 0x12345679`: computes, writes nothing. `H` `or x7, x0, x6` with
`x6 = 0x0ff0f00f`: an `x0` operand, which reads 0. `P` padding.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[2]` `pc_addr` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `M[3]` `pc_read_ts` | 24 | 24 | 24 | 24 | 24 | 24 | 24 | 24 | 0 |
| `M[4]` `pc_read_value` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | 0 |
| `M[5]` `pc_write_value` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | 0 |
| `M[6]` `rs1_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[7]` `rs1_addr` | 5 | 5 | 5 | 5 | 5 | 5 | 5 | 0 | 0 |
| `M[8]` `rs1_read_ts` | 21 | 21 | 21 | 21 | 21 | 21 | 21 | 21 | 0 |
| `M[9]`, `M[10]` `rs1_read_value`, `rs1_write_value` | `0x12345679` | `0xfedcba98` | `0x12345679` | `0xfedcba99` | `0xf0f00ff0` | `0x12345678` | `0x12345679` | 0 | 0 |
| `M[11]` `rs2_mask` | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 1 | 0 |
| `M[12]` `rs2_addr` | 0 | 0 | 6 | 6 | 6 | 0 | 0 | 6 | 0 |
| `M[13]` `rs2_read_ts` | 0 | 0 | 22 | 22 | 22 | 0 | 0 | 22 | 0 |
| `M[14]`, `M[15]` `rs2_read_value`, `rs2_write_value` | 0 | 0 | 4 | 33 | `0x0ff0f00f` | 0 | 0 | `0x0ff0f00f` | 0 |
| `M[16]` `rd_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[17]` `rd_addr` | 7 | 7 | 7 | 7 | 7 | 7 | 0 | 7 | 0 |
| `M[18]` `rd_read_ts` | 23 | 23 | 23 | 23 | 23 | 23 | 23 | 23 | 0 |
| `M[19]` `rd_read_value` | `0x11111111` | `0x11111111` | `0x11111111` | 0 | `0x11111111` | `0x11111111` | 0 | 0 | 0 |
| `M[20]` `rd_write_value` | `0x91a2b3c8` | `0xffdb9753` | `0x23456790` | `0xff6e5d4c` | `0x00f00000` | `0xedcba987` | 0 | `0x0ff0f00f` | 0 |
| `W[0..4]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[4]` `rd_inv` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | 0 | `7⁻¹` | 0 |
| `W[5]` `rd_is_zero` | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[6]` `rd_selected` | `0x91a2b3c8` | `0xffdb9753` | `0x23456790` | `0xff6e5d4c` | `0x00f00000` | `0xedcba987` | `0x91a2b3c8` | `0x0ff0f00f` | 0 |
| `W[7]` `decoded_next_pc` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | 0 |
| `W[8]` `decoded_rs1` | 5 | 5 | 5 | 5 | 5 | 5 | 5 | 0 | 0 |
| `W[9]` `decoded_rs2` | 0 | 0 | 6 | 6 | 6 | 0 | 0 | 6 | 0 |
| `W[10]` `decoded_rd` | 7 | 7 | 7 | 7 | 7 | 7 | 0 | 7 | 0 |
| `W[11]` `decoded_imm` | 3 | 3 | 0 | 0 | 0 | `0xffffffff` | 3 | 0 | 0 |
| `W[12]` `decoded_mask` | 1 | 8 | `0x40` | `0x200` | `0x800` | 2 | 1 | `0x400` | 0 |
| `W[13..25]` the kind bit set | `slli` | `srai` | `sll` | `sra` | `and` | `xori` | `slli` | `or` | none |
| `W[25]` `f_shift` | 1 | 1 | 1 | 1 | 0 | 0 | 1 | 0 | 0 |
| `W[26]` `f_bitwise` | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 1 | 0 |
| `W[27]` `rs1_hi` | `0x1234` | `0xfedc` | `0x1234` | `0xfedc` | `0xf0f0` | `0x1234` | `0x1234` | 0 | 0 |
| `W[28]` `rs1_sign` | 0 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 |
| `W[29]` `src2_hi` | 0 | 0 | 0 | 0 | `0x0ff0` | `0xffff` | 0 | `0x0ff0` | 0 |
| `W[30]` `amount` | 3 | 3 | 4 | 1 | 15 | 31 | 3 | 15 | 0 |
| `W[31]` `pow` | 8 | 8 | 16 | 2 | 0 | 0 | 8 | 0 | 0 |
| `W[32]` `copow` | `2^28` | `2^28` | `2^27` | `2^30` | 0 | 0 | `2^28` | 0 | 0 |
| `W[33]` `high` | 0 | 0 | 0 | 1 | `0x7f8780` | `0x07ffffff` | 0 | `0x7f8780` | 0 |
| `W[34]` `high_hi` | 0 | 0 | 0 | 0 | `0x7f` | `0x07ff` | 0 | `0x7f` | 0 |
| `W[35]` `se` | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `W[36]` `shift_in` | `0x12345679` | `−2386093` | `0x12345679` | `−9544372` | 0 | 0 | `0x12345679` | 0 | 0 |
| `W[37]` `shift_prod` | `0x91a2b3c8` | `−19088744` | `0x123456790` | `−19088744` | 0 | 0 | `0x91a2b3c8` | 0 | 0 |
| `W[38]` `ovf` | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[40]` `residue` | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 |
| `W[42]` `scaled` | 0 | 0 | 0 | `0x80000000` | 0 | 0 | 0 | 0 | 0 |
| `W[43]` `scaled_hi` | 0 | 0 | 0 | `0x8000` | 0 | 0 | 0 | 0 | 0 |
| `W[44..48]` `byte_a0..3` | `79 56 34 12` | `98 ba dc fe` | `79 56 34 12` | `99 ba dc fe` | `f0 0f f0 f0` | `78 56 34 12` | `79 56 34 12` | `00 00 00 00` | 0 |
| `W[48..52]` `byte_b0..3` | `03 00 00 00` | `03 00 00 00` | `04 00 00 00` | `21 00 00 00` | `0f f0 f0 0f` | `ff ff ff ff` | `03 00 00 00` | `0f f0 f0 0f` | 0 |
| `W[52..56]` `byte_and0..3` | `01 00 00 00` | `00 00 00 00` | `00 00 00 00` | `01 00 00 00` | `00 00 f0 00` | `78 56 34 12` | `01 00 00 00` | `00 00 00 00` | 0 |
| `W[56]` `rd_hi` | `0x91a2` | `0xffdb` | `0x2345` | `0xff6e` | `0x00f0` | `0xedcb` | `0x91a2` | `0x0ff0` | 0 |

`W[39]` `ovf_hi`, `W[41]` `residue_hi` are 0 on all nine and are omitted; `shift_in` and
`shift_prod` are written as signed integers, their field values being `p − |v|` where negative.

`A` is the plain left shift: `0x12345679 · 8` is below `2^32`, so `ovf` is 0 and the whole
product is the result. `C` is the same shift by 4, whose product `0x123456790` overflows a word:
`ovf = 1` and `rd` is the low half. `B` and `D` are the arithmetic right shifts, where `se = 1`
carries the sign into both `shift_in` and `shift_out_rule`'s right arm; `D`'s `rs2` is 33, which
`amount_split` truncates to 1 with `high = 1`, and its residue 1 is the dropped bit, scaled by
`2·copow = 2^31`. `E` and `F` are the bitwise rows: `pow` and `copow` are 0, `shift_in` and
`shift_prod` are 0, and `amount` keeps its honest value with `ShiftPowers` switched off. `F`
shows XOR derived from AND alone — its four `byte_and` are `rs1`'s own bytes, because
`byte_b_j = 0xff` — and `rd = rs1 + src2 − 2·Σ 2^(8j)·and_j` is `0xedcba987`. `G` computes
`0x91a2b3c8` into `rd_selected` and writes 0: the x0 rule masks it, and `rd_inv` is 0 at address
0. `H`'s `rs1` is `x0`, a present query at address 0 reading 0, so `or` returns `src2`.

### 5.10 What fixes each cell

The per-cell accounting is `crates/checker/tests/shift_bitwise.rs`' own, and it is a committed
one: `each_gate_is_the_one_that_refuses_its_row` carries 25 tampers, each an edit to a named
honest row beside **the exact set** of relations that refuse it, asserted equal — not a
membership — so a gate that stopped being load-bearing on the row shape it exists for fails the
suite. The table below is that list read as a cell-by-cell account, with the two address tampers
on one line. `every_booleanity_gate_refuses_a_value_of_two` adds the sixteen booleans this
family commits — the twelve kind bits, the two half flags, `rs1_sign` and `se` — and six
further tests isolate one bound or one gate each. A seventh,
`acceptance_7_the_byte_table_is_and_and_or_and_xor_are_derived_from_it`, reads the AND table
over its whole 8-by-8-bit domain and checks that Rust's own `a | b` and `a ^ b` are the two
forms §5.5's 171 derives from it.

| cell moved | on the row | refused by, exactly |
| --- | --- | --- |
| `decoded_mask` | `slli 3`, claiming `srli`'s mask | `decoded_mask_bits` |
| `f_shift` → 0 | `slli 3`, switching `ShiftPowers` off | `f_shift_rule`, `copower_rule` |
| `f_bitwise` → 0 | `and to zero`, switching the byte table off | `f_bitwise_rule` |
| `rs1_mask` (query dropped) | `or with an x0 operand` | `rs1_mask_rule` |
| `rs2_mask` (query added) | `slli 3` | `rs2_mask_rule` |
| `rd_mask` (query dropped) | `and to zero` | `rd_mask_rule` |
| `rs1_addr`, `rs2_addr` `+ 1` | `sll` | `rs1_addr_rule`, `rs2_addr_rule` |
| `rd_addr` → 5 | `slli 3` | `rd_addr_rule` |
| `rs1_read_value` → 5 | padding | `rs1_value_masked` |
| `rs2_read_value` → 32 | `slli 0`, whose shift by `32 mod 32 = 0` is unchanged by it | `rs2_value_masked` |
| `pc_write_value` `+ 4` | `slli 3` | `next_pc_rule` |
| `amount` → 2, with `pow`, `copow`, `shift_prod`, `ovf` and the result moved to match | `slli 3` | `amount_split` |
| `copow` halved, with `scaled` halved so its own pair still holds | `srli 3` | `copower_rule` |
| `kind_sra` → `kind_srl`, mask and all | an honest `sra` | `se_rule` |
| `shift_in` → 5 | `and`, where `pow` is 0 | `shift_in_rule` |
| `shift_prod` → 5 | `and` | `shift_prod_rule` |
| `shift_prod` `+ 8`, carried into the result | `slli 3` | `shift_prod_rule` |
| `rd_selected` `+ 2^16`, `rd_hi` moved with it | `slli 3` | `shift_out_rule` |
| `scaled` `+ 1` | `srli 3` | `scaled_rule` |
| `byte_a0` `+ 1` | `and` | `rs1_bytes` |
| `byte_b0` `+ 1` | `and` | `src2_bytes` |
| `rd_selected` → the AND accumulator | `or` | `bitwise_out_rule` |
| an `rd` query rewriting `x10` | padding | `rd_mask_rule`, `rd_addr_rule` |
| the same, dressed as `or` with `decoded_rd = 10` and a written 0 | padding | `rd_mask_rule` |

What no gate refuses, and what does:

- **`amount` above 31**: nothing in gate list 0. `ShiftPowers`' domain is the whole bound, which
  is the point of `only_the_shift_powers_table_refuses_an_untruncated_amount` — an `sll by rs2 =
  33, small rs1` row claiming to shift by 33, with `pow = 2^33` and a copower of `2^-2` so that
  `copower_rule` still holds, an `ovf` of `rs1·2` that is still a word, and a result of 0. Every
  gate and every range obligation accepts it; the generic table is the lone refusal.
- **A byte key above 255**: the key bound of §5.6 and nothing else. At `byte_a0 = 256` the scaled
  half alone refuses (256 is a perfectly good halfword); at `byte_a0 = 65_823` both halves do.
- **A shamt claimed different from `src2 mod 32`**: `amount_split` with `high`'s pair, which is
  the only integer witness (`the_shamt_is_not_free_and_the_high_chunks_bound_is_what_closes_it`).
- **A residue at or above `2^amount`**: the scaled pair alone — `residue`'s own direct pair
  accepts 24 on a shift by 4, and so does `shift_out_rule` with the quotient one too low.
- **A residue that is not an integer**: `residue`'s **direct** pair alone on a left shift, where
  `shift_out_rule` does not read it; on a right shift the two direct pairs on `residue` and
  `rd_selected` together, the non-integer residue dragging the result out of the word with it.
  The scaled pair is in neither set, which is `check_copowers`' whole reason for existing.

On a padding row `pc_mask = 0`, every frame mask is 0, every leaf is 1 and every obligation under
`pc_mask` is vacuous. `f_shift` and `f_bitwise` are **free booleans** there, so a padding row may
look `ShiftPowers` or the byte table up; it consumes a table multiplicity, which the honest
prover's recount covers, and changes nothing, the `rd` query being absent. With every kind bit 0
the gates hold `rd_selected` — through `bitwise_out_rule` under a claimed `f_bitwise` — and
`shift_in`, `shift_prod`, `se`, `pc_write_value − decoded_next_pc` and `pow·copow` to 0, and
leave `amount`, `high` and the eight byte columns free subject to the two decompositions and the
split. The honest fill writes 0 everywhere.

---

## 6. `MUL_DIV` — family 3

### 6.1 Header

`family_circuit(3, n)` is `mul_div::artifact(n)` with `mul_div::channels()`, built by
`memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` through the private
`family_spec`, whose arithmetic half is the public `mul_div::arithmetic_gates(WORD_BITS)` — the
**width seam** S18's exhaustive reduced-width check drives, as `gadgets::comparison_equation` is
at S17. It uses one S17 gadget, `gadgets::is_zero`, twice in its own arithmetic — beside the
frame's x0 rule, which `memory` builds on the same gadget — and deliberately not
`gadgets::comparison`: its magnitude bound is a directly range-checked gap, which is where the
zero-divisor correction lives and which the comparison gadget's operand range pairs and two sign
lookups would only duplicate (`mul-div.md` decision 1). Normative spec: `mul-div.md`. Fill:
`prover::family_fill(3)`, the private `fill::mul_div`.

84 committed columns (21 `M`, 54 `W`, **9** `S`) and two virtual tables. Gate list 0 writes 116
leaves and holds 54 enforcing gates. 27 lookups on four channels, 10 outputs. At `n = 20`, the
height S18 proves, there are 26 gate lists, the top is `L26`, and the circuit has 444 inner
columns and 498 relations; a shard proof of it is 67,412 bytes (`crates/prover/tests/alu.rs`).
It is 26 lists deep for a different reason than §5's: **its `range16` tree carries 16
obligations, so with its table fraction it is 17 leaves and pads to 32** — one leaf past the
16-leaf trees of §3 and §4.

**This family's decoded tuple has no immediate, and that is visible everywhere.** RV32M is all
R-type, so `program::lookup_tuple(3)` is `pc next_pc rs1 rs2 rd extra_mask` — **six columns, not
seven** — which makes `mul_div::TABLE_WIDTH` 6, the claimed decoded row five columns
(`W[7..12]`), the decoder tuple six wide, the setup subtree **nine** columns where the other
three registered execution families commit ten, the packed generic table `S[6..9]` rather than
`S[7..10]`, and the decoder denominator's top `β` power `β⁵` rather than `β⁶` (§0.4). It is the
one registered circuit whose `g_dec` is `g − Σ_{j<6} β^j`.

`artifact` panics unless the frame is `QUERIES`, the channels carry exactly 8, 16, 2 and 1
obligations, and every gate is zero on the all-zero row. `arithmetic_gates` panics unless its
width is between 1 and 32. `artifact` also panics on every refusal of the assembly, among them
`n < 19` and `n > 30`; `family_circuit` returns `None` for both rather than calling it.

### 6.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::mul_div`, bit `k` being `W[12 + k]`.
**Every one of the eight is R-type**: it reads `rs1` and `rs2` and writes `rd`, so all three mask
rules are `m_pc·Σ(all eight bits)` and the queries present are the same on every live row.
`next_pc` is the fall-through, always `pc + 4`: the M extension has no compressed form.

| row kind | bit (`decoded_mask`) | `s1` | `s2` | `f_div` | `mx` | `my` | `rd_selected` |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mul` | 0 (1) | `rs1_top` | `rs2_top` | 0 | `rs1_adj` | `rs2_adj` | `p_low` |
| `mulh` | 1 (2) | `rs1_top` | `rs2_top` | 0 | `rs1_adj` | `rs2_adj` | `p_high` |
| `mulhsu` | 2 (4) | `rs1_top` | 0 | 0 | `rs1_adj` | `rs2` | `p_high` |
| `mulhu` | 3 (8) | 0 | 0 | 0 | `rs1` | `rs2` | `p_high` |
| `div` | 4 (16) | `rs1_top` | `rs2_top` | 1 | `rs2_adj` | `q_adj` | `q` |
| `divu` | 5 (32) | 0 | 0 | 1 | `rs2` | `q_adj` | `q` |
| `rem` | 6 (64) | `rs1_top` | `rs2_top` | 1 | `rs2_adj` | `q_adj` | `r` |
| `remu` | 7 (128) | 0 | 0 | 1 | `rs2` | `q_adj` | `r` |
| padding | none; all 0 | 0 | 0 | a free boolean | 0 | 0 | 0 |

`rs1_adj = rs1 − 2^32·s1` and `rs2_adj = rs2 − 2^32·s2`; `q_adj = q − 2^32·q_sign` and
`r_adj = r − 2^32·r_sign`. `mul` is listed as signed × signed: its low half is the same read
either way, so the choice is free, and taking it signed is what lets **one** product identity
serve all four multiplies. `mulhsu` is the asymmetric one — `rs1` signed, `rs2` not — which the
two separate flag lists (`LHS_SIGNED`, `RHS_SIGNED`) express and no case split does. An
**unsigned position forces its flag to 0** whatever the operand's top bit, which is what keeps
the selection degree 2.

Every kind is provable at S18. **No kind computes a pc**: `next_pc` is the decoded fall-through,
so this family, like §5's, needs no wrap bit and cannot reach `HALT_PC`. `rd = x0` is not a kind.
A live row at a pc holding no instruction of the family meets the table's `MINUS_ONE` row, which
its decoder tuple cannot equal.

### 6.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §6.4 and §6.6.

**Memory-argument columns, `M[0..21]`** — §2's REG layout (`w = 4`), the same 21 columns and the
same bare frame fixture (`memory_frame_reg.bin`) as §4's and §5's, filled by
`trace::build_memory_columns`; committed in `PublicInputs::memory_commitments`, absorbed at G8
before the memory challenges. `M[0..9]`, `M[10..14]`, `M[15..21]` and their frame gates are
§5.3's, address for address; the "read by" column below differs only where this family's own
gates read one.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 4); obligations `gap_lo_*` (all 4) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`; selector of `gap_hi_pc`, `gap_lo_pc`, all sixteen `RANGE16` obligations, both `GENERIC` lookups and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | `pc + 4` | leaf `write_pc`; `next_pc_rule` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on every kind | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | rs1 register | the decoded `rs1` | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | rs1; a multiply's left operand, a division's dividend | | leaf `read_rs1`; `rs1_writes_back`, `rs1_value_masked`, `mx_rule`, `division_rule`; `rs1_lo_range` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on every kind | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | rs2 register | the decoded `rs2` | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | rs2; a multiply's right operand, a division's **divisor** | | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `mx_rule`, `my_rule`, `dz_inverse`, `dz_at_nonzero`, `abs_d_rule`; `rs2_lo_range` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `rd_mask` | `frame(3, FIELD_MASK)` | rd present | 1 on every kind | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[17]` | `rd_addr` | `frame(3, FIELD_ADDR)` | rd register | the decoded `rd` | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[18]` | `rd_read_ts` | `frame(3, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[19]` | `rd_read_value` | `frame(3, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd` |
| `M[20]` | `rd_write_value` | `frame(3, FIELD_WRITE_VALUE)` | rd new value | `rd_selected`, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |

The frame's slots in `mul_div.rs` are `SLOT_PC = 0` through `SLOT_RD = 3`. `rs2_read_value` is
the most-read column of the family: it is a multiplicand, the is-zero gadget's subject, the
divisor whose magnitude the gap bounds, and a range-checked word.

**Witness columns, `W[0..54]`** — `W[0..6]` filled by `trace::build_frame_witness`, `W[6..50]`
by `fill::mul_div` (`W[6]` in place of S14's), `W[50..54]` by `trace::build_multiplicities`
inside `prover::shard_columns`; committed in `ShardProof::witness_commitments`, absorbed at S3
before `g` and `β`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0..4]` | `pc_gap_hi` … `rd_gap_hi` | `memory::gap_hi(s)` | gap high chunks | `gap >> 19`; the pc's is always 0 | `gap_hi_<q>`, `gap_lo_<q>` |
| `W[4]` | `rd_inv` | `memory::rd_inv(4)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[5]` | `rd_is_zero` | `memory::rd_is_zero(4)` | rd is `x0` | | `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_is_zero_boolean`, `rd_write_masked` |
| `W[6]` | `rd_selected` | `memory::rd_selected(4)`; `sel` in `mul_div.rs` | Result | the half, quotient or remainder the kind takes, `rd = x0` included: the fill overwrites the 0 S14's builder writes there | `rd_write_masked`, `rd_value_rule`; `rd_lo_range` |
| `W[7]` | `decoded_next_pc` | `mul_div::DECODED[0]`; `SEQ` | Decoded fall-through | `pc + 4` | `next_pc_rule`; `decode_row` position 1 |
| `W[8]` | `decoded_rs1` | `DECODED[1]` | Decoded rs1 | | `rs1_addr_rule`; `decode_row` position 2 |
| `W[9]` | `decoded_rs2` | `DECODED[2]` | Decoded rs2 | | `rs2_addr_rule`; `decode_row` position 3 |
| `W[10]` | `decoded_rd` | `DECODED[3]` | Decoded rd | | `rd_addr_rule`; `decode_row` position 4 |
| `W[11]` | `decoded_mask` | `DECODED[4]` | Decoded kind mask | `1 << bit`; **`DECODED` is five wide, there being no `imm`** | `decoded_mask_bits`; `decode_row` position 5 |
| `W[12]` | `kind_mul` | `KINDS[0]`; `MUL` | mul row | | `kind_mul_boolean`, `decoded_mask_bits`, the three mask rules, `s1_rule`, `s2_rule`, `mx_rule`, `my_rule`, `rd_value_rule` |
| `W[13]` | `kind_mulh` | `KINDS[1]`; `MULH` | mulh row | | as `kind_mul`, with `rd_value_rule` taking `p_high` |
| `W[14]` | `kind_mulhsu` | `KINDS[2]`; `MULHSU` | mulhsu row | | `kind_mulhsu_boolean`, `decoded_mask_bits`, the three mask rules, `s1_rule` **but not `s2_rule`**, `mx_rule`, `my_rule`, `rd_value_rule` |
| `W[15]` | `kind_mulhu` | `KINDS[3]`; `MULHU` | mulhu row | | `kind_mulhu_boolean`, `decoded_mask_bits`, the three mask rules, `mx_rule`, `my_rule`, `rd_value_rule`; **neither sign rule** |
| `W[16]` | `kind_div` | `KINDS[4]`; `DIV` | div row | | `kind_div_boolean`, `decoded_mask_bits`, the three mask rules, `f_div_rule`, `s1_rule`, `s2_rule`, `rd_value_rule` |
| `W[17]` | `kind_divu` | `KINDS[5]`; `DIVU` | divu row | | `kind_divu_boolean`, `decoded_mask_bits`, the three mask rules, `f_div_rule`, `rd_value_rule` |
| `W[18]` | `kind_rem` | `KINDS[6]`; `REM` | rem row | | as `kind_div`, `rd_value_rule` taking `r` |
| `W[19]` | `kind_remu` | `KINDS[7]`; `REMU` | remu row | | as `kind_divu`, `rd_value_rule` taking `r` |
| `W[20]` | `f_div` | `mul_div::F_DIV` | Row is a division | the sum of the four division bits | `f_div_rule`, `f_div_boolean`, `mx_rule`, `my_rule`, `division_rule`, `rz_inverse`, `dz_inverse`, `d1_rule`, `gap_rule` — the **`enable` of both is-zero gadgets**, which is why it is a column |
| `W[21]` | `rs1_hi` | `RS1_HI` | rs1, high halfword | `rs1 >> 16` | `rs1_hi_range`, `rs1_lo_range`; `rs1_get_sign` position 0 |
| `W[22]` | `rs1_top` | `RS1_TOP` | rs1, bit 31 | `rs1 >> 31`, whatever the kind | `s1_rule`, `rs1_top_boolean`; `rs1_get_sign` position 1 |
| `W[23]` | `rs2_hi` | `RS2_HI` | rs2, high halfword | `rs2 >> 16` | `rs2_hi_range`, `rs2_lo_range`; `rs2_get_sign` position 0 |
| `W[24]` | `rs2_top` | `RS2_TOP` | rs2, bit 31 | `rs2 >> 31` | `s2_rule`, `rs2_top_boolean`; `rs2_get_sign` position 1 |
| `W[25]` | `s1` | `S1` | lhs sign **adjustment** | `lhs_signed·rs1_top` | `s1_rule`, `s1_boolean`, `mx_rule`, `division_rule`, `d1_rule` |
| `W[26]` | `s2` | `S2` | rhs sign adjustment | `rhs_signed·rs2_top` | `s2_rule`, `s2_boolean`, `mx_rule`, `my_rule`, `abs_d_rule` |
| `W[27]` | `mx` | `MX` | First multiplicand | `rs1_adj` on a multiply, `rs2_adj` on a division; **`Fr`-backed**, being signed | `mx_rule`, `product_rule` |
| `W[28]` | `my` | `MY` | Second multiplicand | `rs2_adj` on a multiply, `q_adj` on a division; **`Fr`-backed** | `my_rule`, `product_rule` |
| `W[29]` | `p_low` | `P_LOW` | Product, low word | | `product_rule`, `division_rule`, `rd_value_rule`; `p_low_lo_range` |
| `W[30]` | `p_low_hi` | `P_LOW_HI` | `p_low`, high halfword | | `p_low_hi_range`, `p_low_lo_range` |
| `W[31]` | `p_high` | `P_HIGH` | Product, high word | | `product_rule`, `division_rule`, `rd_value_rule`; `p_high_lo_range` |
| `W[32]` | `p_high_hi` | `P_HIGH_HI` | `p_high`, high halfword | | `p_high_hi_range`, `p_high_lo_range` |
| `W[33]` | `p_sign` | `P_SIGN` | Product is negative | | `p_sign_boolean`, `product_rule`, `division_rule` |
| `W[34]` | `q` | `Q` | Quotient, as a word | 0 on a multiply row | `my_rule`, `zero_divisor_quotient`, `rd_value_rule`; `q_lo_range` |
| `W[35]` | `q_hi` | `Q_HI` | `q`, high halfword | | `q_hi_range`, `q_lo_range` |
| `W[36]` | `q_sign` | `Q_SIGN` | Quotient sign adjustment | **a free boolean**, pinned only by `q`'s own range (§6.5 E) | `q_sign_boolean`, `my_rule` |
| `W[37]` | `r` | `R` | Remainder, as a word | 0 on a multiply row | `division_rule`, `rz_inverse`, `rz_at_nonzero`, `abs_r_rule`, `rd_value_rule`; `r_lo_range` |
| `W[38]` | `r_hi` | `R_HI` | `r`, high halfword | | `r_hi_range`, `r_lo_range` |
| `W[39]` | `r_sign` | `R_SIGN` | Remainder sign adjustment | `d1·(1 − rz)`: 1 exactly on a division row with a negative dividend and a nonzero remainder | `r_sign_boolean`, `division_rule`, `r_sign_rule`, `abs_r_rule` |
| `W[40]` | `r_inv` | `R_INV` | Inverse of the remainder | `r⁻¹` on a division row with `r ≠ 0`, else 0; **`Fr`-backed** | `rz_inverse` |
| `W[41]` | `rz` | `RZ` | Remainder is zero | `f_div·[r = 0]`; boolean by the gadget, so no booleanity gate | `rz_inverse`, `rz_at_nonzero`, `r_sign_rule` |
| `W[42]` | `d1` | `D1` | Division with a negative dividend | `f_div·s1`; boolean by the two columns it multiplies | `d1_rule`, `r_sign_rule` |
| `W[43]` | `d_inv` | `D_INV` | Inverse of the divisor | `rs2⁻¹` on a division row with `rs2 ≠ 0`, else 0; **`Fr`-backed** | `dz_inverse` |
| `W[44]` | `dz` | `DZ` | Divisor is zero | `f_div·[rs2 = 0]`; boolean by the gadget | `dz_inverse`, `dz_at_nonzero`, `gap_rule`, `zero_divisor_quotient` |
| `W[45]` | `abs_r` | `ABS_R` | `\|r_adj\|` | | `abs_r_rule`, `gap_rule` |
| `W[46]` | `abs_d` | `ABS_D` | `\|rs2_adj\|` | computed on a multiply row too, the gate being ungated | `abs_d_rule`, `gap_rule` |
| `W[47]` | `gap` | `GAP` | `\|divisor\| − \|rem\| − 1`, corrected | `f_div·(abs_d − abs_r − 1) + 2^32·dz` | `gap_rule`; `gap_lo_range` |
| `W[48]` | `gap_hi` | `GAP_HI` | `gap`, high halfword | | `gap_hi_range`, `gap_lo_range` |
| `W[49]` | `rd_hi` | `RD_HI` | Result, high halfword | `rd_selected >> 16` | `rd_hi_range`, `rd_lo_range` |
| `W[50]` | `mult_timestamp` | `MULTIPLICITIES[0]` | Timestamp-table count | per table row `t`: the gated gap chunks equal to `t`, credited to rows below `2^19` | leaf `timestamp_table_num` |
| `W[51]` | `mult_range16` | `MULTIPLICITIES[1]` | 16-bit-table count | per table row `t`: the gated halfwords (`pc_mask·expression`) equal to `t` | leaf `range16_table_num` |
| `W[52]` | `mult_generic` | `MULTIPLICITIES[2]` | Generic-table count | per table row `t`: the gated sign tuples equal to row `t`; a live row's two land on `U16GetSign`'s rows `2^16 + 1 + rs1_hi` and `2^16 + 1 + rs2_hi`, a padding row's two on row 0, the `ZeroEntry` | leaf `generic_table_num` |
| `W[53]` | `mult_decoder` | `MULTIPLICITIES[3]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all **six** positions) on the table's lowest non-live row, row 0 | leaf `decoder_table_num` |

Every obligation of this family is selected by `pc_mask` except the eight timestamp gaps, whose
selectors are their own queries' masks — and every query of this frame is present on every live
row, so **on a live row nothing is switched off**. Row 0 of `mult_timestamp` and `mult_range16`
therefore counts a padding row's whole set, all 8 and all 16, plus every live chunk or halfword
whose value is 0. That is the simplest multiplicity picture of the four registered execution
families.

**Setup columns, `S[0..9]`** — two tables, **nine columns, not ten**. `S[0..6]` is the family's
decoded table in `program::lookup_tuple(3)` order — `pc next_pc rs1 rs2 rd extra_mask`, with no
`imm` — filled by `program::FamilyTable::column_poly(j)`; committed in program identity and
carried as `VerifyingKey::setup_commitments` for the family. `S[6..9]` is the packed generic
table (§0.3), filled by `program::lookup_tables::generic_table(n)`: the same three commitments
every key carries, covered by the key's SRS digest and not by identity, which a shard opens after
identity's list because `FamilyCircuit::reads_generic_table` holds (`shard-proof.md` §3, §5.1,
§7). Each is read only by its table's denominator, at the `β` power in the last column.

| address | name | Rust | descriptive name | contents | read by | weight |
| --- | --- | --- | --- | --- | --- | --- |
| `S[0]` | `table_pc` | `mul_div::channels()[3].table[0]` | Table pc | `RowField::Pc` | `decoder_table_den` | 1 |
| `S[1]` | `table_next_pc` | `channels()[3].table[1]` | Table fall-through | `RowField::NextPc` | `decoder_table_den` | `β` |
| `S[2]` | `table_rs1` | `channels()[3].table[2]` | Table rs1 | `RowField::Rs1` | `decoder_table_den` | `β²` |
| `S[3]` | `table_rs2` | `channels()[3].table[3]` | Table rs2 | `RowField::Rs2` | `decoder_table_den` | `β³` |
| `S[4]` | `table_rd` | `channels()[3].table[4]` | Table rd | `RowField::Rd` | `decoder_table_den` | `β⁴` |
| `S[5]` | `table_extra_mask` | `channels()[3].table[5]` | Table kind mask | `RowField::ExtraMask` | `decoder_table_den` | `β⁵` |
| `S[6]` | `generic_key` | `mul_div::GENERIC_TABLE[0]`, `channels()[2].table[0]` | Generic key | 0, `AND_BASE + a + 1`, `SIGN_BASE + h + 1` or `SHIFT_BASE + s + 1` | `generic_table_den` | 1 |
| `S[7]` | `generic_value` | `GENERIC_TABLE[1]` | Generic value | 0, `b`, `h >> 15` or `2^s` | `generic_table_den` | `β` |
| `S[8]` | `generic_result` | `GENERIC_TABLE[2]` | Generic result | 0, `a & b`, 0 or `2^(31 − s)` | `generic_table_den` | `β²` |

`mul_div::TABLE_WIDTH` is **6**; `constants::generic_table::WIDTH` is 3. The packed table's other
two sub-tables are there because the table is one artifact of the ceremony shared by every family
that reads the channel; this family looks nothing up in them.

**Virtual tables** — never committed, never opened.

| address | name | Rust | descriptive name | value at row `y` | read by |
| --- | --- | --- | --- | --- | --- |
| `V[range19]` | `range19` | `VirtualKind::Range19`, wire tag 2 | 19-bit range table | `y mod 2^19` | `timestamp_table_den` |
| `V[range16]` | `range16` | `VirtualKind::Range16`, wire tag 3 | 16-bit range table | `y mod 2^16` | `range16_table_den` |

### 6.4 Gate list 0: the 116 leaves

A leaf's relation number equals its `L1` offset, 0 to 115.

**The memory product trees.** `L1[0..4]` read, `L1[4..8]` write, §5.4's table address for
address — the frame is the same. Four queries fill each side, so neither has a pad.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_rd` | `M[16]` | 1 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 5 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 6 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 7 | `write_rd` | `M[16]` | 1 | `M[17]` | `4·M[0] + 3` | `M[20]` |

**The `timestamp` fraction tree**, `L1[8..40]`: 16 fractions, §5.4's and §4.4's list unchanged —
the table's, then `gap_hi_pc`, `gap_lo_pc`, `gap_hi_rs1`, `gap_lo_rs1`, `gap_hi_rs2`,
`gap_lo_rs2`, `gap_hi_rd`, `gap_lo_rd`, then `timestamp_pad_0` … `timestamp_pad_6`. Fraction `i`
is `(L1[8 + 2i], L1[9 + 2i])`.

**The `range16` fraction tree**, `L1[40..104]`: 32 fractions, the table's then 16 obligations then
**15 pads** — the longest pad run of any registered circuit, and the reason the tree costs a
fifth row-wise level for one leaf past 16.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 40, 41 | `range16_table` | `−mult_range16` | `V[range16] + g` |
| 1 | 42, 43 | `rs1_hi_range` | 1 | `g + pc_mask·rs1_hi` |
| 2 | 44, 45 | `rs1_lo_range` | 1 | `g + pc_mask·rs1_read_value − 2^16·pc_mask·rs1_hi` |
| 3 | 46, 47 | `rs2_hi_range` | 1 | `g + pc_mask·rs2_hi` |
| 4 | 48, 49 | `rs2_lo_range` | 1 | `g + pc_mask·rs2_read_value − 2^16·pc_mask·rs2_hi` |
| 5 | 50, 51 | `p_low_hi_range` | 1 | `g + pc_mask·p_low_hi` |
| 6 | 52, 53 | `p_low_lo_range` | 1 | `g + pc_mask·p_low − 2^16·pc_mask·p_low_hi` |
| 7 | 54, 55 | `p_high_hi_range` | 1 | `g + pc_mask·p_high_hi` |
| 8 | 56, 57 | `p_high_lo_range` | 1 | `g + pc_mask·p_high − 2^16·pc_mask·p_high_hi` |
| 9 | 58, 59 | `q_hi_range` | 1 | `g + pc_mask·q_hi` |
| 10 | 60, 61 | `q_lo_range` | 1 | `g + pc_mask·q − 2^16·pc_mask·q_hi` |
| 11 | 62, 63 | `r_hi_range` | 1 | `g + pc_mask·r_hi` |
| 12 | 64, 65 | `r_lo_range` | 1 | `g + pc_mask·r − 2^16·pc_mask·r_hi` |
| 13 | 66, 67 | `gap_hi_range` | 1 | `g + pc_mask·gap_hi` |
| 14 | 68, 69 | `gap_lo_range` | 1 | `g + pc_mask·gap − 2^16·pc_mask·gap_hi` |
| 15 | 70, 71 | `rd_hi_range` | 1 | `g + pc_mask·rd_hi` |
| 16 | 72, 73 | `rd_lo_range` | 1 | `g + pc_mask·rd_selected − 2^16·pc_mask·rd_hi` |
| 17–31 | 74–103 | `range16_pad_0` … `range16_pad_14` | 0 | 1 |

`gap_hi_range` is this family's `RANGE16` obligation on the `gap` column and has nothing to do
with the frame's `gap_hi_<q>` timestamp obligations, which are on channel 0 and named per query.

**The `generic` fraction tree**, `L1[104..112]`: 4 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 104, 105 | `generic_table` | `−mult_generic` | `generic_key + β·generic_value + β²·generic_result + g` |
| 1 | 106, 107 | `rs1_get_sign` | 1 | `g + 257·pc_mask + pc_mask·rs1_hi + β·pc_mask·rs1_top` |
| 2 | 108, 109 | `rs2_get_sign` | 1 | `g + 257·pc_mask + pc_mask·rs2_hi + β·pc_mask·rs2_top` |
| 3 | 110, 111 | `generic_pad_0` | 0 | 1 |

```text
L{1}[107]  rs1_get_sign_den
  positional  g + 257·M[1] + M[1]·W[21] + lookup_beta·M[1]·W[22]
  reads as    g + pc_mask·(e_0 + 1) + β·pc_mask·e_1 + β²·pc_mask·e_2,
              e = (rs1_hi + SIGN_BASE, rs1_top, 0), SIGN_BASE = 256:
              the key rs1_hi + 257 and the top bit at pc_mask = 1, the ZeroEntry at 0;
              e_2 is the constant 0 and contributes no term, so neither sign lookup
              reads β² — §4.6's note, unchanged
```

Each key is bounded before it is looked up, `lookup.md` §4's precondition: `rs1_hi` and `rs2_hi`
by their own 16+16 pairs under the same selector `pc_mask`, which keeps each key `hi + 257` in
`[257, 2^16 + 256]`, `U16GetSign`'s own range, and never the `ZeroEntry`, an AND key or a
`ShiftPowers` key. §5.6 is why that matters now that three sub-tables share the channel.

**The `decoder` fraction tree**, `L1[112..116]`: 2 fractions, and **six** columns wide.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 112, 113 | `decoder_table` | `−mult_decoder` | `table_pc + β·table_next_pc + β²·table_rs1 + β³·table_rs2 + β⁴·table_rd + β⁵·table_extra_mask + g` |
| 1 | 114, 115 | `decode_row` | 1 | `g_dec + (1 + β + β² + β³ + β⁴ + β⁵)·pc_mask + pc_mask·pc_read_value + β·pc_mask·decoded_next_pc + β²·pc_mask·decoded_rs1 + β³·pc_mask·decoded_rs2 + β⁴·pc_mask·decoded_rd + β⁵·pc_mask·decoded_mask` |

Here `g_dec` is `g − Σ_{j<6} β^j`, not `g − Σ_{j<7} β^j`: `gkr_verify::insert_lookup_challenges`
derives it from the artifact's own decoder tuple width, so the six-column tuple gets its own
neutral value and nothing else in the engine changes.

### 6.5 Gate list 0: the 54 enforcing gates

Relations 116–169, in list order, in §3.5's format. The frame's ten are `memory`'s; the family's
forty-four are **eighteen from `mul_div::family_spec`** — the plumbing, which has no width: the
eight kind booleanities, `decoded_mask_bits`, three mask rules, three address rules, two
`value_masked` and `next_pc_rule` — and **twenty-six from `mul_div::arithmetic_gates(32)`**,
relations 144–169, which are the tail of the list in order, a fact
`the_layout_and_the_gates_are_the_spec` asserts by comparing
`enforcing[54 − arithmetic.len()..]` against the function's own output.

**A. The frame's gates (116–125)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
116–125 the frame, §5.5's A and §4.5's A over the REG layout

  116 pc_mask_boolean     0 = M[1]  − M[1]·M[1]          Quadratic, degree 2
  117 rs1_mask_boolean    0 = M[6]  − M[6]·M[6]
  118 rs2_mask_boolean    0 = M[11] − M[11]·M[11]
  119 rd_mask_boolean     0 = M[16] − M[16]·M[16]
  120 rs1_writes_back     0 = M[10] − M[9]                Linear, degree 1
  121 rs2_writes_back     0 = M[15] − M[14]               Linear, degree 1
  122 rd_is_zero_inverse  0 = W[5] − M[16] + M[17]·W[4]
  123 rd_is_zero_at_nonzero  0 = M[17]·W[5]
  124 rd_is_zero_boolean  0 = W[5] − W[5]·W[5]
  125 rd_write_masked     0 = M[20] − W[6] + W[5]·W[6]
        code  memory::booleanity, memory::write_back, memory::x0_gates(3, 4)
```

**B. What the row is (126–134)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
126–133 kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2
        code  mul_div's private booleanity(KINDS[k])

  126 kind_mul_boolean     0 = W[12] − W[12]·W[12]    130 kind_div_boolean   W[16]
  127 kind_mulh_boolean    0 = W[13] − W[13]·W[13]    131 kind_divu_boolean  W[17]
  128 kind_mulhsu_boolean  0 = W[14] − W[14]·W[14]    132 kind_rem_boolean   W[18]
  129 kind_mulhu_boolean   0 = W[15] − W[15]·W[15]    133 kind_remu_boolean  W[19]

────────────────────────────────────────────────────────────────────────────────────────────
134     decoded_mask_bits — the packed mask is its eight bits           Linear, degree 1
        code  mul_div::family_spec, `bits`

  positional  0 = W[12] + 2·W[13] + 4·W[14] + 8·W[15] + 16·W[16] + 32·W[17] + 64·W[18]
                  + 128·W[19] − W[11]
  named       0 = Σ_k 2^k·kind_k − decoded_mask,  k in extra_mask::mul_div order

  reads as  §5.5's 146 over eight bits. One-hotness is the decoder table's domain
            (lookup.md §10), and W[11] is the fifth decoded column, not the sixth: this
            family's tuple has no imm.
```

**C. Which queries a row makes, and where (135–143)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
135–137 <q>_mask_rule — every one of the eight is R-type               Quadratic, degree 2
        code  mask_rule(frame(s, FIELD_MASK), &KINDS), for s = 1, 2, 3

  135 rs1_mask_rule  0 = M[6]  − M[1]·W[12] − M[1]·W[13] − … − M[1]·W[19]
  136 rs2_mask_rule  0 = M[11] − M[1]·W[12] − M[1]·W[13] − … − M[1]·W[19]
  137 rd_mask_rule   0 = M[16] − M[1]·W[12] − M[1]·W[13] − … − M[1]·W[19]
  named             0 = <q>_mask − pc_mask·Σ_k kind_k,  each over all eight bits

  reads as  the three lists are identical, which no other registered family's are: every
            kind reads both operands and writes rd. On a live row the bits are one-hot, so
            each mask is 1; on a padding row pc_mask = 0 and every mask is 0, whatever the
            bits hold. S14's control C8 is refused here by 137 with 140 and 169 — the
            decoded rd of a row that decodes nothing is 0 and the value it claims to write
            is not a selection of anything (§6.10).

────────────────────────────────────────────────────────────────────────────────────────────
138–140 <q>_addr_rule — a present query's register is the decoded one  Quadratic, degree 2
        code  addr_rule(slot, DECODED_<Q>)

  138 rs1_addr_rule  0 = M[6]·M[7]   − M[6]·W[8]
  139 rs2_addr_rule  0 = M[11]·M[12] − M[11]·W[9]
  140 rd_addr_rule   0 = M[16]·M[17] − M[16]·W[10]

────────────────────────────────────────────────────────────────────────────────────────────
141–142 <q>_value_masked — an absent operand reads 0                   Quadratic, degree 2
        code  value_masked(slot)

  141 rs1_value_masked  0 = M[9]  − M[6]·M[9]
  142 rs2_value_masked  0 = M[14] − M[11]·M[14]

  reads as  both operands are present on every live row, so these two bite on padding rows
            alone — which is exactly where they are needed: an unmasked operand carrying a
            value is what a forged padding row would use, and 142 is what keeps a padding
            row's divisor 0 (§6.10).

────────────────────────────────────────────────────────────────────────────────────────────
143     next_pc_rule — the pc falls through, always                     Linear, degree 1
        code  mul_div::family_spec

  positional  0 = M[5] − W[7]
  named       0 = pc_write_value − decoded_next_pc

  reads as  §5.5's 159: this family computes no pc either (shift-bitwise.md §4.1).
```

**D. The flags and the signs (144–154)** — from here to the end, `arithmetic_gates(32)`.

```text
────────────────────────────────────────────────────────────────────────────────────────────
144–145 f_div, the division half                      Linear/Quadratic, degrees 1 and 2
        code  arithmetic_gates, over DIVS

  144 f_div_rule     0 = W[20] − W[16] − W[17] − W[18] − W[19]
                     0 = f_div − (kind_div + kind_divu + kind_rem + kind_remu)
  145 f_div_boolean  0 = W[20] − W[20]·W[20]

  reads as  f_div is a committed column because it is the **enable** of both is-zero
            gadgets (159, 161), which multiply it against another column; every other
            signal this family needs is a linear form over the kind bits and stays inline
            (mul-div.md §1). Unlike §5's two halves it is not a lookup selector — nothing
            here is selected by anything but pc_mask and the frame's masks — but its
            booleanity is load-bearing all the same: at f_div = 2 a gadget's enable would
            make `rz` 2.

────────────────────────────────────────────────────────────────────────────────────────────
146–147 s<i>_rule — each operand's sign adjustment                     Quadratic, degree 2
        code  arithmetic_gates, over LHS_SIGNED and RHS_SIGNED

  146 s1_rule  0 = W[25] − W[12]·W[22] − W[13]·W[22] − W[14]·W[22] − W[16]·W[22]
                   − W[18]·W[22]
      named    0 = s1 − (kind_mul + kind_mulh + kind_mulhsu + kind_div + kind_rem)·rs1_top
  147 s2_rule  0 = W[26] − W[12]·W[24] − W[13]·W[24] − W[16]·W[24] − W[18]·W[24]
      named    0 = s2 − (kind_mul + kind_mulh + kind_div + kind_rem)·rs2_top

  reads as  the two lists differ by exactly one bit, kind_mulhsu, which is the whole of the
            asymmetry: its rs1 is signed and its rs2 is not. An **unsigned position forces
            its flag to 0** whatever the operand's top bit, which is what keeps the
            selection degree 2 and makes mulhsu one gate rather than a case split. The two
            top bits themselves come from U16GetSign over range-checked halfwords (§6.6),
            so each is genuinely the operand's bit 31 on a live row.

────────────────────────────────────────────────────────────────────────────────────────────
148–154 the booleans                                                   Quadratic, degree 2
        code  arithmetic_gates, its booleanity list

  148 rs1_top_boolean  0 = W[22] − W[22]·W[22]    152 p_sign_boolean  W[33]
  149 rs2_top_boolean  0 = W[24] − W[24]·W[24]    153 q_sign_boolean  W[36]
  150 s1_boolean       0 = W[25] − W[25]·W[25]    154 r_sign_boolean  W[39]
  151 s2_boolean       0 = W[26] − W[26]·W[26]

  reads as  every boolean the family leaves **free** carries one — f_div, p_sign and
            q_sign — and the four that are implied carry one anyway: the two top bits by
            the sign lookup, s1 and s2 by 146 and 147 over boolean bits, r_sign by 158.
            `rz`, `dz` and `d1` do not: the first two are boolean by the is-zero gadget's
            construction and the third by the two columns it multiplies, as S17's `eq` is
            (mul-div.md §3).
```

**E. One product identity, and the division built on it (155–158)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
155     mx_rule — the first multiplicand                                Quadratic, degree 2
156     my_rule — the second                                            Quadratic, degree 2
        code  arithmetic_gates, over MULS then F_DIV

  155 positional  0 = W[27] − W[12]·M[9] + 2^32·W[12]·W[25] − W[13]·M[9] + 2^32·W[13]·W[25]
                      − W[14]·M[9] + 2^32·W[14]·W[25] − W[15]·M[9] + 2^32·W[15]·W[25]
                      − W[20]·M[14] + 2^32·W[20]·W[26]
      named, factored
        0 = mx − Σ_mul kind·(rs1_read_value − 2^32·s1) − f_div·(rs2_read_value − 2^32·s2)
  156 positional  0 = W[28] − W[12]·M[14] + 2^32·W[12]·W[26] − … − W[20]·W[34]
                      + 2^32·W[20]·W[36]
      named, factored
        0 = my − Σ_mul kind·(rs2_read_value − 2^32·s2) − f_div·(q − 2^32·q_sign)

────────────────────────────────────────────────────────────────────────────────────────────
157     product_rule — the one multiplication of two row values         Quadratic, degree 2
        code  arithmetic_gates, over word = 2^32 and double = 2^64

  positional  0 = −W[29] − 2^32·W[31] + 2^64·W[33] + W[27]·W[28]
  named       0 = mx·my − p_low − 2^32·p_high + 2^64·p_sign

  reads as (155–157)  on a multiply row the multiplicands are the two operands; on a
                      division row they are the **divisor and the quotient**. 157 is
                      ungated and is the only multiplication of two row values, which is
                      what lets both readings share it and keeps the identity degree 2.
                      On a multiply row mx and my each lie in [−2^31, 2^32); on a division
                      row mx is the sign-adjusted divisor and my is q − 2^32·q_sign with q
                      range-checked and q_sign boolean, so (−2^32, 2^32). The product is
                      therefore in (−2^64, 2^64) — the extremes are −2^31·(2^32 − 1) and
                      just under 2^32·2^32, neither reaching the endpoint — and with p_low
                      and p_high each range-checked below 2^32 and p_sign boolean,
                      p_low + 2^32·p_high − 2^64·p_sign covers that interval exactly once.
                      So the field identity is the integer identity and the decomposition
                      is unique. The dump prints 2^32 as 0x…0100000000, −2^32 as
                      0x30644e72…f0000001, 2^64 as 0x…00010000000000000000 and −2^64 as
                      0x30644e72e131a029b85045b68181585d2833e84879b9709043e1f593f0000001.

────────────────────────────────────────────────────────────────────────────────────────────
158     division_rule — divisor·quotient + rem = dividend               Quadratic, degree 2
        code  arithmetic_gates

  positional  0 = W[20]·W[29] + 2^32·W[20]·W[31] − 2^64·W[20]·W[33] + W[20]·W[37]
                  − 2^32·W[20]·W[39] − W[20]·M[9] + 2^32·W[20]·W[25]
  named, factored
    0 = f_div·(p_low + 2^32·p_high − 2^64·p_sign + r − 2^32·r_sign
               − rs1_read_value + 2^32·s1)
      = f_div·(rs2_adj·q_adj + r_adj − rs1_adj)

  reads as  **it is gated, and must be.** On a multiply row f_div is 0, so 163 gives d1 = 0
            and therefore r_sign = 0, and r is range-checked non-negative — so r_adj ≥ 0.
            An ungated identity over a multiply row whose rs2 is 0 then reads
            r_adj = rs1_adj, which no non-negative r_adj satisfies when rs1_adj is
            negative, and `mul t0, t1, x0` with a negative t1 — an ordinary instruction —
            would be unprovable (mul-div.md §4.3).
            **The identity alone says nothing useful.** On a zero divisor it degenerates to
            r_adj = rs1_adj, and on every inexact division a floored witness satisfies it as
            readily as a truncated one. 159–164 are what pin it.
```

**F. The remainder's sign (159–164)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
159–160 the is-zero gadget over r, enabled by f_div                    Quadratic, degree 2
        code  gadgets::is_zero(&[(1, R)], R_INV, RZ, F_DIV)

  159 rz_inverse     0 = W[41] − W[20] + W[37]·W[40]
                     0 = r·r_inv + rz − f_div
  160 rz_at_nonzero  0 = W[37]·W[41]        0 = r·rz

────────────────────────────────────────────────────────────────────────────────────────────
161–162 the is-zero gadget over the divisor, enabled by f_div          Quadratic, degree 2
        code  gadgets::is_zero(&[(1, rs2_read_value)], D_INV, DZ, F_DIV)

  161 dz_inverse     0 = W[44] − W[20] + M[14]·W[43]
                     0 = rs2_read_value·d_inv + dz − f_div
  162 dz_at_nonzero  0 = M[14]·W[44]        0 = rs2_read_value·dz

  reads as (159–162)  each pair makes its flag `f_div` where the subject is 0 and 0 where it
                      is not, with no booleanity gate of its own — S17's argument for `eq`,
                      unchanged. Enabling both by f_div is what leaves q and r free on a
                      multiply row.

────────────────────────────────────────────────────────────────────────────────────────────
163     d1_rule — a division with a negative dividend                   Quadratic, degree 2
164     r_sign_rule — the remainder's sign, as a definition              Quadratic, degree 2
        code  arithmetic_gates

  163 positional  0 = W[42] − W[20]·W[25]        0 = d1 − f_div·s1
  164 positional  0 = W[39] − W[42] + W[42]·W[41]
      named       0 = r_sign − d1·(1 − rz)

  reads as  r_sign is 1 exactly where the row is a division, the dividend is negative and
            the remainder is not zero. Stated as a **definition** rather than as the
            implication `rem ≠ 0 ⇒ sign(rem) = sign(dividend)`, it is the same constraint
            and is cheaper: the implication gated to division rows is degree 3, and d1 is
            the committed column that brings it back to 2.
            **This is the easiest line to leave out and the one that separates truncated
            from floored division.** Without it DIV(−7, 2) takes −4 as readily as −3,
            because 2·(−4) + 1 = −7 satisfies 158 and |1| < |2| satisfies 165–167 — the row
            the suite builds as `floored_minus_seven_over_two`, which 164 alone refuses. And
            on an unsigned row, where d1 is 0 and so r_sign is 0, it is what forces
            r_adj = r ≥ 0, without which DIVU(0xDEADBEEF, 0x1234) could return 801702 for
            801701 (mul-div.md §4.4).
```

**G. The magnitude bound, the pin and the selection (165–169)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
165–166 abs_<x>_rule — |x| in one degree-2 line                        Quadratic, degree 2
        code  arithmetic_gates, the (name, abs, value, sign) loop

  165 abs_r_rule  0 = W[45] − W[37] − 2^32·W[39] + 2·W[37]·W[39]
      named       0 = abs_r − (r + 2^32·r_sign − 2·r·r_sign)   = |r_adj|
  166 abs_d_rule  0 = W[46] − M[14] − 2^32·W[26] + 2·M[14]·W[26]
      named       0 = abs_d − (rs2 + 2^32·s2 − 2·rs2·s2)       = |rs2_adj|

  reads as  |x| = x + 2^w·sign − 2·x·sign is degree 2 and exact for both flag values. Both
            gates are **ungated**, so a multiply row computes both magnitudes too; nothing
            reads them there, 167's f_div factor being 0 (§6.9's row C carries
            abs_d = 0xffffffff on a mulhsu).

────────────────────────────────────────────────────────────────────────────────────────────
167     gap_rule — |rem| < |divisor|, with the zero-divisor correction  Quadratic, degree 2
        code  arithmetic_gates

  positional  0 = W[47] + W[20] − 2^32·W[44] − W[20]·W[46] + W[20]·W[45]
  named       0 = gap − f_div·(abs_d − abs_r − 1) − 2^32·dz

  reads as  gap is 16+16 range-checked (§6.6), so on a division row with a nonzero divisor
            abs_d − abs_r − 1 ∈ [0, 2^32), which is |rem| < |divisor|. The step that
            carries it is that **neither magnitude can reach 2^32**, so the difference
            cannot wrap into range from below: abs_d = 2^32 − rs2 only where s2 = 1, which
            needs rs2 ≥ 2^31, so abs_d ≤ 2^31; abs_r = 2^32 − r only where r_sign = 1, which
            164 allows only where rz = 0 and so r ≠ 0, so abs_r ≤ 2^32 − 1. With both in
            [0, 2^32), abs_d − abs_r − 1 lies in (−2^32 − 1, 2^32), and a field element of
            that interval is in [0, 2^32) exactly when it is non-negative. Neither magnitude
            needs a range obligation of its own (mul-div.md §4.5).
            **The zero-divisor correction is what makes a zero divisor impose no bound**:
            at dz = 1, abs_d is 0 and gap is 2^32 − abs_r − 1, in range for every abs_r
            below 2^32. On a multiply row f_div is 0, so gap is 0 and in range.

────────────────────────────────────────────────────────────────────────────────────────────
168     zero_divisor_quotient — division by zero is all ones            Quadratic, degree 2
        code  arithmetic_gates, coefficient Fr::ONE − 2^32

  positional  0 = −4294967295·W[44] + W[44]·W[34]
  named       0 = dz·(q − (2^32 − 1))

  reads as  the whole of the div-by-zero pin. The remainder needs none: with rs2_adj = 0 the
            identity gives r_adj = rs1_adj directly, and 164 then fixes the word to rs1. The
            **signed overflow** −2^31 ÷ −1 needs no pin either: |rem| < 1 forces rem = 0,
            158 gives q_adj = 2^31, and q's own range forces q_sign = 0 and q = 0x80000000,
            the ISA's answer. That case is also why **q_sign must stay a free boolean**:
            there q's top bit is set while q_sign is 0, so a circuit taking q_sign from
            U16GetSign over q_hi, as it takes s1 and s2 from the operands, would make that
            one row unprovable (mul-div.md §5.3).

────────────────────────────────────────────────────────────────────────────────────────────
169     rd_value_rule — which of the four results the kind writes       Quadratic, degree 2
        code  arithmetic_gates, over MUL, TAKES_HIGH, TAKES_QUOTIENT, TAKES_REMAINDER

  positional  0 = W[6] − W[12]·W[29] − W[13]·W[31] − W[14]·W[31] − W[15]·W[31]
                  − W[16]·W[34] − W[17]·W[34] − W[18]·W[37] − W[19]·W[37]
  named       0 = rd_selected − kind_mul·p_low
                  − (kind_mulh + kind_mulhsu + kind_mulhu)·p_high
                  − (kind_div + kind_divu)·q − (kind_rem + kind_remu)·r

  reads as  the selection is by sums of committed kind bits and never by a bare decoder
            output. rd_selected carries its own 16+16 pair, which is **implied** — every
            source it selects carries one — and kept anyway, because every family bounds
            what it writes to rd in the same place (mul-div.md §5.4). Nothing else in this
            circuit is redundant.
```

Of the 54 gates, 5 are degree 1: the two write-backs, `decoded_mask_bits`, `next_pc_rule` and
`f_div_rule`. All 54 have constant 0, so each is 0 on the all-zero row, and the assembly records
`zero_row_valid = true`, which `assemble` asserts before returning.

### 6.6 The 27 lookups

`CircuitArtifact::lookups`, in order. The frame's 8 come from the private `memory::gap_lookups`;
the rest from `mul_div::family_spec` (its private `range32`, `get_sign` and the inline
`decode_row`). **Every lookup from 8 on is selected by `pc_mask`** — this family has no
selector of its own, unlike §5's two halves.

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `gap_hi_pc` | `TIMESTAMP` (0) | `M[1]` | `W[0]` | `pc_gap_hi` | `< 2^19` |
| 1 | `gap_lo_pc` | `TIMESTAMP` | `M[1]` | `4·M[0] − M[3] − 2^19·W[0] − 1` | `4·cycle − pc_read_ts − 2^19·pc_gap_hi − 1` | `< 2^19` |
| 2 | `gap_hi_rs1` | `TIMESTAMP` | `M[6]` | `W[1]` | `rs1_gap_hi` | `< 2^19` |
| 3 | `gap_lo_rs1` | `TIMESTAMP` | `M[6]` | `4·M[0] − M[8] − 2^19·W[1]` | `4·cycle − rs1_read_ts − 2^19·rs1_gap_hi` | `< 2^19` |
| 4 | `gap_hi_rs2` | `TIMESTAMP` | `M[11]` | `W[2]` | `rs2_gap_hi` | `< 2^19` |
| 5 | `gap_lo_rs2` | `TIMESTAMP` | `M[11]` | `4·M[0] − M[13] − 2^19·W[2] + 1` | `4·cycle − rs2_read_ts − 2^19·rs2_gap_hi + 1` | `< 2^19` |
| 6 | `gap_hi_rd` | `TIMESTAMP` | `M[16]` | `W[3]` | `rd_gap_hi` | `< 2^19` |
| 7 | `gap_lo_rd` | `TIMESTAMP` | `M[16]` | `4·M[0] − M[18] − 2^19·W[3] + 2` | `4·cycle − rd_read_ts − 2^19·rd_gap_hi + 2` | `< 2^19` |
| 8 | `rs1_hi_range` | `RANGE16` (1) | `M[1]` | `W[21]` | `rs1_hi` | `< 2^16` |
| 9 | `rs1_lo_range` | `RANGE16` | `M[1]` | `M[9] − 2^16·W[21]` | `rs1_read_value − 2^16·rs1_hi` | `< 2^16` |
| 10 | `rs2_hi_range` | `RANGE16` | `M[1]` | `W[23]` | `rs2_hi` | `< 2^16` |
| 11 | `rs2_lo_range` | `RANGE16` | `M[1]` | `M[14] − 2^16·W[23]` | `rs2_read_value − 2^16·rs2_hi` | `< 2^16` |
| 12 | `p_low_hi_range` | `RANGE16` | `M[1]` | `W[30]` | `p_low_hi` | `< 2^16` |
| 13 | `p_low_lo_range` | `RANGE16` | `M[1]` | `W[29] − 2^16·W[30]` | `p_low − 2^16·p_low_hi` | `< 2^16` |
| 14 | `p_high_hi_range` | `RANGE16` | `M[1]` | `W[32]` | `p_high_hi` | `< 2^16` |
| 15 | `p_high_lo_range` | `RANGE16` | `M[1]` | `W[31] − 2^16·W[32]` | `p_high − 2^16·p_high_hi` | `< 2^16` |
| 16 | `q_hi_range` | `RANGE16` | `M[1]` | `W[35]` | `q_hi` | `< 2^16` |
| 17 | `q_lo_range` | `RANGE16` | `M[1]` | `W[34] − 2^16·W[35]` | `q − 2^16·q_hi` | `< 2^16` |
| 18 | `r_hi_range` | `RANGE16` | `M[1]` | `W[38]` | `r_hi` | `< 2^16` |
| 19 | `r_lo_range` | `RANGE16` | `M[1]` | `W[37] − 2^16·W[38]` | `r − 2^16·r_hi` | `< 2^16` |
| 20 | `gap_hi_range` | `RANGE16` | `M[1]` | `W[48]` | `gap_hi` | `< 2^16` |
| 21 | `gap_lo_range` | `RANGE16` | `M[1]` | `W[47] − 2^16·W[48]` | `gap − 2^16·gap_hi` | `< 2^16` |
| 22 | `rd_hi_range` | `RANGE16` | `M[1]` | `W[49]` | `rd_hi` | `< 2^16` |
| 23 | `rd_lo_range` | `RANGE16` | `M[1]` | `W[6] − 2^16·W[49]` | `rd_selected − 2^16·rd_hi` | `< 2^16` |
| 24 | `rs1_get_sign` | `GENERIC` (2) | `M[1]` | `(W[21] + 256, W[22], 0)` | `(rs1_hi + SIGN_BASE, rs1_top, 0)` | the gated tuple `(rs1_hi + 257, rs1_top, 0)` is a row of `S[6..9]` |
| 25 | `rs2_get_sign` | `GENERIC` | `M[1]` | `(W[23] + 256, W[24], 0)` | `(rs2_hi + SIGN_BASE, rs2_top, 0)` | the gated tuple `(rs2_hi + 257, rs2_top, 0)` is a row of `S[6..9]` |
| 26 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[7], W[8], W[9], W[10], W[11])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_mask)` | a row of `S[0..6]`, **six columns** |

Read in pairs: each `gap_hi`/`gap_lo` pair puts a read strictly before its own write, and each
`_hi_range`/`_lo_range` pair bounds `rs1_read_value`, `rs2_read_value`, `p_low`, `p_high`, `q`,
`r`, `gap` and `rd_selected` below `2^32`. The two `_hi_range` obligations keep each sign
lookup's key `hi + 257` in `[257, 2^16 + 256]`, `U16GetSign`'s keys — never the `ZeroEntry`, an
AND key or a `ShiftPowers` key (`lookup.md` §4's precondition, and §5.6 for why the precondition
now matters more than it did) — so the only row that key can meet is `(hi + 257, hi >> 15, 0)`
and each top bit is its operand's bit 31. **There is no copower obligation in this circuit**: no
column here is bounded by scaling, so `check_copowers` has nothing to check and `assemble` does
not call it.

The channels, `mul_div::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[50]` | 8 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[51]` | **16** | **32** |
| 6, 7 | `GENERIC` | 2 | `S[6..9]` | `W[52]` | 2 | 4 |
| 8, 9 | `DECODER` | 3 | `S[0..6]` | `W[53]` | 1 | 2 |

`artifact` asserts the four obligation counts. **Sixteen obligations plus one table fraction is
seventeen leaves**, one past a 16-leaf tree, so the `range16` tree pads to 32 and costs a fifth
row-wise level — which is why this circuit is 26 gate lists deep at `n = 20` where §3's and §4's
are 25. Dropping one obligation would take a whole level off the circuit; none is droppable
(`rd_selected`'s pair is the only implied one, and §6.5 G says why it is kept).

### 6.7 Inner layers `L2`–`L6`: the row-wise reduction

The conventions are §3.7's. There are **five** row-wise reduction lists, as in §5.7.

**`L2`, gate list 1, 58 columns, relations 170–227.**

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 170 | `read_2_0` | `read_pc · read_rs1` |
| 1 | 171 | `read_2_1` | `read_rs2 · read_rd` |
| 2 | 172 | `write_2_0` | `write_pc · write_rs1` |
| 3 | 173 | `write_2_1` | `write_rs2 · write_rd` |
| 4, 5 | 174, 175 | `timestamp_2_0` | `timestamp_table + gap_hi_pc` |
| 6, 7 | 176, 177 | `timestamp_2_1` | `gap_lo_pc + gap_hi_rs1` |
| 8, 9 | 178, 179 | `timestamp_2_2` | `gap_lo_rs1 + gap_hi_rs2` |
| 10, 11 | 180, 181 | `timestamp_2_3` | `gap_lo_rs2 + gap_hi_rd` |
| 12, 13 | 182, 183 | `timestamp_2_4` | `gap_lo_rd + timestamp_pad_0` |
| 14, 15 | 184, 185 | `timestamp_2_5` | `timestamp_pad_1 + timestamp_pad_2` |
| 16, 17 | 186, 187 | `timestamp_2_6` | `timestamp_pad_3 + timestamp_pad_4` |
| 18, 19 | 188, 189 | `timestamp_2_7` | `timestamp_pad_5 + timestamp_pad_6` |
| 20, 21 | 190, 191 | `range16_2_0` | `range16_table + rs1_hi_range` |
| 22, 23 | 192, 193 | `range16_2_1` | `rs1_lo_range + rs2_hi_range` |
| 24, 25 | 194, 195 | `range16_2_2` | `rs2_lo_range + p_low_hi_range` |
| 26, 27 | 196, 197 | `range16_2_3` | `p_low_lo_range + p_high_hi_range` |
| 28, 29 | 198, 199 | `range16_2_4` | `p_high_lo_range + q_hi_range` |
| 30, 31 | 200, 201 | `range16_2_5` | `q_lo_range + r_hi_range` |
| 32, 33 | 202, 203 | `range16_2_6` | `r_lo_range + gap_hi_range` |
| 34, 35 | 204, 205 | `range16_2_7` | `gap_lo_range + rd_hi_range` |
| 36, 37 | 206, 207 | `range16_2_8` | `rd_lo_range + range16_pad_0` |
| 38, 39 | 208, 209 | `range16_2_9` | `range16_pad_1 + range16_pad_2` |
| 40, 41 | 210, 211 | `range16_2_10` | `range16_pad_3 + range16_pad_4` |
| 42, 43 | 212, 213 | `range16_2_11` | `range16_pad_5 + range16_pad_6` |
| 44, 45 | 214, 215 | `range16_2_12` | `range16_pad_7 + range16_pad_8` |
| 46, 47 | 216, 217 | `range16_2_13` | `range16_pad_9 + range16_pad_10` |
| 48, 49 | 218, 219 | `range16_2_14` | `range16_pad_11 + range16_pad_12` |
| 50, 51 | 220, 221 | `range16_2_15` | `range16_pad_13 + range16_pad_14` |
| 52, 53 | 222, 223 | `generic_2_0` | `generic_table + rs1_get_sign` |
| 54, 55 | 224, 225 | `generic_2_1` | `rs2_get_sign + generic_pad_0` |
| 56, 57 | 226, 227 | `decoder_2_0` | `decoder_table + decode_row` |

Seven of the sixteen `range16` nodes here combine two pads, which is the cost of one leaf past 16.

**`L3`, gate list 2, 30 columns, relations 228–257.**

| `L3` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 228 | `read_3_0` | `read_2_0 · read_2_1` |
| 1 | 229 | `write_3_0` | `write_2_0 · write_2_1` |
| 2, 3 | 230, 231 | `timestamp_3_0` | `timestamp_2_0 + timestamp_2_1` |
| 4, 5 | 232, 233 | `timestamp_3_1` | `timestamp_2_2 + timestamp_2_3` |
| 6, 7 | 234, 235 | `timestamp_3_2` | `timestamp_2_4 + timestamp_2_5` |
| 8, 9 | 236, 237 | `timestamp_3_3` | `timestamp_2_6 + timestamp_2_7` |
| 10, 11 | 238, 239 | `range16_3_0` | `range16_2_0 + range16_2_1` |
| 12, 13 | 240, 241 | `range16_3_1` | `range16_2_2 + range16_2_3` |
| 14, 15 | 242, 243 | `range16_3_2` | `range16_2_4 + range16_2_5` |
| 16, 17 | 244, 245 | `range16_3_3` | `range16_2_6 + range16_2_7` |
| 18, 19 | 246, 247 | `range16_3_4` | `range16_2_8 + range16_2_9` |
| 20, 21 | 248, 249 | `range16_3_5` | `range16_2_10 + range16_2_11` |
| 22, 23 | 250, 251 | `range16_3_6` | `range16_2_12 + range16_2_13` |
| 24, 25 | 252, 253 | `range16_3_7` | `range16_2_14 + range16_2_15` |
| 26, 27 | 254, 255 | `generic_3_0` | `generic_2_0 + generic_2_1` |
| 28, 29 | 256, 257 | `decoder_3_0` | copy of `decoder_2_0` |

**`L4`, gate list 3, 18 columns, relations 258–275.**

| `L4` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 258 | `read_4_0` | copy of `read_3_0` |
| 1 | 259 | `write_4_0` | copy of `write_3_0` |
| 2, 3 | 260, 261 | `timestamp_4_0` | `timestamp_3_0 + timestamp_3_1` |
| 4, 5 | 262, 263 | `timestamp_4_1` | `timestamp_3_2 + timestamp_3_3` |
| 6, 7 | 264, 265 | `range16_4_0` | `range16_3_0 + range16_3_1` |
| 8, 9 | 266, 267 | `range16_4_1` | `range16_3_2 + range16_3_3` |
| 10, 11 | 268, 269 | `range16_4_2` | `range16_3_4 + range16_3_5` |
| 12, 13 | 270, 271 | `range16_4_3` | `range16_3_6 + range16_3_7` |
| 14, 15 | 272, 273 | `generic_4_0` | copy of `generic_3_0` |
| 16, 17 | 274, 275 | `decoder_4_0` | copy of `decoder_3_0` |

**`L5`, gate list 4, 12 columns, relations 276–287.**

| `L5` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 276 | `read_5_0` | copy of `read_4_0` |
| 1 | 277 | `write_5_0` | copy of `write_4_0` |
| 2, 3 | 278, 279 | `timestamp_5_0` | `timestamp_4_0 + timestamp_4_1` |
| 4, 5 | 280, 281 | `range16_5_0` | `range16_4_0 + range16_4_1` |
| 6, 7 | 282, 283 | `range16_5_1` | `range16_4_2 + range16_4_3` |
| 8, 9 | 284, 285 | `generic_5_0` | copy of `generic_4_0` |
| 10, 11 | 286, 287 | `decoder_5_0` | copy of `decoder_4_0` |

**`L6`, gate list 5, 10 columns, relations 288–297** — the row-wise top: one value per row per
tree.

| `L6` | relations | node | formula | value at row `y` |
| --- | --- | --- | --- | --- |
| 0 | 288 | `read_6_0` | copy of `read_5_0` | the product of row `y`'s 4 read leaves |
| 1 | 289 | `write_6_0` | copy of `write_5_0` | the product of row `y`'s 4 write leaves |
| 2, 3 | 290, 291 | `timestamp_6_0` | copy of `timestamp_5_0` | the sum of row `y`'s 16 timestamp fractions |
| 4, 5 | 292, 293 | `range16_6_0` | `range16_5_0 + range16_5_1` | the sum of row `y`'s 32 range16 fractions |
| 6, 7 | 294, 295 | `generic_6_0` | copy of `generic_5_0` | the sum of row `y`'s 4 generic fractions |
| 8, 9 | 296, 297 | `decoder_6_0` | copy of `decoder_5_0` | the sum of row `y`'s 2 decoder fractions |

### 6.8 The halving layers and the outputs

Gate list `k`, for `6 ≤ k ≤ n + 5`, halves layer `k` into layer `k + 1`, which has `n + 5 − k`
variables. Its ten gates, relation `r = 298 + 10(k − 6)`, are §5.8's table exactly, node for node
and shape for shape. In the last list, `k = n + 5`, the ten nodes are `read_root`, `write_root`,
`timestamp_num_root`, `timestamp_den_root`, `range16_num_root`, `range16_den_root`,
`generic_num_root`, `generic_den_root`, `decoder_num_root` and `decoder_den_root`. At `n = 20`
the halving lists are 6 to 25 and the top is `L26`; at `n = 22` they are 6 to 27 and the top is
`L28`.

**The outputs**, in output-map order, absorbed as one `GKR_OUTPUTS` message before any challenge
of the backward pass and carried in `ShardProof::outputs`.

| # | address, `n = 20` | node | value | what `verify_shard` does with it |
| --- | --- | --- | --- | --- |
| 0 | `L{26}[0]` | `read_root` | the product of every read leaf of the shard | step 10: must equal `PublicInputs::memory_roots[p][0]`, `p` being the position of `(3, shard_index)` in `verifier_core::statement_shards`, after `INIT_TEARDOWN`'s shard, every `ZERO_WINDOWS` shard and every `ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT` and `SHIFT_BITWISE` shard (`shard-proof.md` §1.2); 4 in S18's statement; a factor of `reconciles` |
| 1 | `L{26}[1]` | `write_root` | the product of every write leaf | step 10: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |
| 2 | `L{26}[2]` | `timestamp_num_root` | as §3.8's output 2 | step 9: must be 0; otherwise `Lookup { channel: 0 }` |
| 3 | `L{26}[3]` | `timestamp_den_root` | as §3.8's output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 0 }` |
| 4 | `L{26}[4]` | `range16_num_root` | as output 2, for `RANGE16` | step 9: must be 0; otherwise `Lookup { channel: 1 }` |
| 5 | `L{26}[5]` | `range16_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 1 }` |
| 6 | `L{26}[6]` | `generic_num_root` | as output 2, for `GENERIC` | step 9: must be 0; otherwise `Lookup { channel: 2 }` |
| 7 | `L{26}[7]` | `generic_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 2 }` |
| 8 | `L{26}[8]` | `decoder_num_root` | as output 2, for `DECODER` | step 9: must be 0; otherwise `Lookup { channel: 3 }` |
| 9 | `L{26}[9]` | `decoder_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 3 }` |

### 6.9 Witness rows

The table shows eight of the 63 live `honest_rows` in `crates/checker/tests/mul_div.rs`, and the
padding row. The catalogue is **every one of the eight kinds over all four sign quadrants** —
`(7, 3)`, `(−7, 3)`, `(7, −3)` and `(−7, −3)` as words, 32 rows — plus the 28 edge cases S18's
acceptance 3 and 4 name: `−2^31 × −2^31`; the asymmetric `mulhsu` corner `−2^31 × (2^32 − 1)`;
`mulhu` just under `2^64`; `DIV(−7, 2)` and `REM(−7, 2)`, the rows a floored quotient would also
satisfy the bare division identity on; division by zero for all four kinds; the one signed
overflow `−2^31 ÷ −1`; unsigned division whose remainder's top bit is set; `mul into x0` and
`div into x0`; and `divu by x0`, whose `rs2` is the `x0` register and whose divisor is therefore
zero. `honest` holds every row's `rd_selected` to `rv32m(bit, a, b)`, the ISA's table written out
again from the unprivileged spec, before the row is used at all; then
`every_row_kind_satisfies_every_gate_and_every_bound` holds the row to every gate, every range
obligation and both table channels in CI.

A row is checked alone: each register query reads a write made eight timestamps before its own
and the pc query the previous cycle's, so every `<q>_gap_hi` is 0; the multiplicities are 0;
`S[0..6]` hold the row's own table entry and `S[6..9]` are 0, and the table below omits them.
Every live row shown has cycle 7, pc `0x1000`, `rs1` `x5`, `rs2` `x6` and `rd` `x7`, and `P` is 0
in every cell.

`A` `mul x7, x5, x6` with `x5 = 7`, `x6 = 3`. `B` `mulh` with `x5 = −7`, `x6 = 3`.
`C` `mulhsu` with `x5 = 0x80000000`, `x6 = 0xffffffff` — the asymmetric corner. `D` `div` with
`x5 = −7`, `x6 = 2`. `E` `rem` on the same pair. `F` `divu x7, x5, x6` with
`x5 = 0xdeadbeef`, `x6 = 0` — division by zero. `G` `div` with `x5 = 0x80000000`,
`x6 = 0xffffffff` — the one signed overflow. `H` `mul x0, x5, x6` with `x5 = −7`, `x6 = 3`.
`P` padding.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[3]` `pc_read_ts` | 24 | 24 | 24 | 24 | 24 | 24 | 24 | 24 | 0 |
| `M[4]` `pc_read_value` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | `0x1000` | 0 |
| `M[5]` `pc_write_value` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | 0 |
| `M[6]`, `M[11]`, `M[16]` the three masks | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[7]` `rs1_addr` | 5 | 5 | 5 | 5 | 5 | 5 | 5 | 5 | 0 |
| `M[8]`, `M[13]`, `M[18]` read timestamps | 21, 22, 23 | 21, 22, 23 | 21, 22, 23 | 21, 22, 23 | 21, 22, 23 | 21, 22, 23 | 21, 22, 23 | 21, 22, 23 | 0 |
| `M[9]`, `M[10]` `rs1_read_value`, `rs1_write_value` | 7 | `0xfffffff9` | `0x80000000` | `0xfffffff9` | `0xfffffff9` | `0xdeadbeef` | `0x80000000` | `0xfffffff9` | 0 |
| `M[12]` `rs2_addr` | 6 | 6 | 6 | 6 | 6 | 6 | 6 | 6 | 0 |
| `M[14]`, `M[15]` `rs2_read_value`, `rs2_write_value` | 3 | 3 | `0xffffffff` | 2 | 2 | 0 | `0xffffffff` | 3 | 0 |
| `M[17]` `rd_addr` | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 0 | 0 |
| `M[19]` `rd_read_value` | `0x11111111` | `0x11111111` | `0x22222222` | `0x22222222` | `0x22222222` | `0x22222222` | `0x22222222` | 0 | 0 |
| `M[20]` `rd_write_value` | 21 | `0xffffffff` | `0x80000000` | `0xfffffffd` | `0xffffffff` | `0xffffffff` | `0x80000000` | 0 | 0 |
| `W[0..4]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[4]` `rd_inv` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | `7⁻¹` | 0 | 0 |
| `W[5]` `rd_is_zero` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| `W[6]` `rd_selected` | 21 | `0xffffffff` | `0x80000000` | `0xfffffffd` | `0xffffffff` | `0xffffffff` | `0x80000000` | `0xffffffeb` | 0 |
| `W[7]` `decoded_next_pc` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | `0x1004` | 0 |
| `W[8]`, `W[9]` `decoded_rs1`, `decoded_rs2` | 5, 6 | 5, 6 | 5, 6 | 5, 6 | 5, 6 | 5, 6 | 5, 6 | 5, 6 | 0 |
| `W[10]` `decoded_rd` | 7 | 7 | 7 | 7 | 7 | 7 | 7 | 0 | 0 |
| `W[11]` `decoded_mask` | 1 | 2 | 4 | `0x10` | `0x40` | `0x20` | `0x10` | 1 | 0 |
| `W[12..20]` the kind bit set | `mul` | `mulh` | `mulhsu` | `div` | `rem` | `divu` | `div` | `mul` | none |
| `W[20]` `f_div` | 0 | 0 | 0 | 1 | 1 | 1 | 1 | 0 | 0 |
| `W[21]` `rs1_hi` | 0 | `0xffff` | `0x8000` | `0xffff` | `0xffff` | `0xdead` | `0x8000` | `0xffff` | 0 |
| `W[22]` `rs1_top` | 0 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `W[23]` `rs2_hi` | 0 | 0 | `0xffff` | 0 | 0 | 0 | `0xffff` | 0 | 0 |
| `W[24]` `rs2_top` | 0 | 0 | 1 | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[25]` `s1` | 0 | 1 | 1 | 1 | 1 | **0** | 1 | 1 | 0 |
| `W[26]` `s2` | 0 | 0 | **0** | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[27]` `mx` | 7 | `−7` | `−2^31` | 2 | 2 | 0 | `−1` | `−7` | 0 |
| `W[28]` `my` | 3 | 3 | `0xffffffff` | `−3` | `−3` | `0xffffffff` | `2^31` | 3 | 0 |
| `W[29]` `p_low` | 21 | `0xffffffeb` | `0x80000000` | `0xfffffffa` | `0xfffffffa` | 0 | `0x80000000` | `0xffffffeb` | 0 |
| `W[31]` `p_high` | 0 | `0xffffffff` | `0x80000000` | `0xffffffff` | `0xffffffff` | 0 | `0xffffffff` | `0xffffffff` | 0 |
| `W[33]` `p_sign` | 0 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 0 |
| `W[34]` `q` | 0 | 0 | 0 | `0xfffffffd` | `0xfffffffd` | `0xffffffff` | `0x80000000` | 0 | 0 |
| `W[36]` `q_sign` | 0 | 0 | 0 | 1 | 1 | **0** | **0** | 0 | 0 |
| `W[37]` `r` | 0 | 0 | 0 | `0xffffffff` | `0xffffffff` | `0xdeadbeef` | 0 | 0 | 0 |
| `W[39]` `r_sign` | 0 | 0 | 0 | 1 | 1 | **0** | 0 | 0 | 0 |
| `W[40]` `r_inv` | 0 | 0 | 0 | `(0xffffffff)⁻¹` | `(0xffffffff)⁻¹` | `(0xdeadbeef)⁻¹` | 0 | 0 | 0 |
| `W[41]` `rz` | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[42]` `d1` | 0 | 0 | 0 | 1 | 1 | 0 | 1 | 0 | 0 |
| `W[43]` `d_inv` | 0 | 0 | 0 | `2⁻¹` | `2⁻¹` | 0 | `(0xffffffff)⁻¹` | 0 | 0 |
| `W[44]` `dz` | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `W[45]` `abs_r` | 0 | 0 | 0 | 1 | 1 | `0xdeadbeef` | 0 | 0 | 0 |
| `W[46]` `abs_d` | 3 | 3 | `0xffffffff` | 2 | 2 | 0 | 1 | 3 | 0 |
| `W[47]` `gap` | 0 | 0 | 0 | 0 | 0 | `0x21524110` | 0 | 0 | 0 |
| `W[48]` `gap_hi` | 0 | 0 | 0 | 0 | 0 | `0x2152` | 0 | 0 | 0 |
| `W[49]` `rd_hi` | 0 | `0xffff` | `0x8000` | `0xffff` | `0xffff` | `0xffff` | `0x8000` | `0xffff` | 0 |

`W[30]` `p_low_hi`, `W[32]` `p_high_hi`, `W[35]` `q_hi` and `W[38]` `r_hi` are each the high
halfword of the column above them and are omitted; `mx` and `my` are written as signed integers,
their field values being `p − |v|` where negative.

The four bold cells are where the family's shape is easiest to misread. `C`'s `s2` is **0**
though `rs2_top` is 1: `mulhsu` reads its right operand unsigned, so the adjustment flag is
forced to 0 and `my` is the whole word `0xffffffff` — that one cell is the entire asymmetry, and
`abs_d` is `0xffffffff` beside it because `abs_d_rule` is ungated and nothing reads it on a
multiply row. `F`'s `s1` is **0** though `rs1_top` is 1, `divu` being unsigned, which is why its
`d1` and `r_sign` are 0 and its remainder is the dividend read non-negative; its `dz = 1` puts
`2^32` into the gap, so `gap = 2^32 − 0xdeadbeef − 1 = 0x21524110` is in range for any remainder
and the bound says nothing, which is exactly what a zero divisor must do. `G` is the signed
overflow: `q_adj = +2^31` with `q = 0x80000000`, so `q_sign` is **0** while `q`'s top bit is set
— a circuit taking `q_sign` from a sign lookup would have no witness for this row. `A`, `B` and
`H` are the same multiply under three readings: `B`'s `p_high` is the sign-extended `−1`,
`H` computes `0xffffffeb` into `rd_selected` and writes 0, `rd_inv` being 0 at address 0. `D`
and `E` are the truncated pair: `q = −3` and `r = −1`, not the floored `−4` and `1`, and
`r_sign = 1` is what says so.

### 6.10 What fixes each cell

The per-cell accounting is `crates/checker/tests/mul_div.rs`' own, and it is a committed one.
`each_gate_is_the_one_that_refuses_its_row` carries 30 tampers, each an edit to a named honest
row beside **the exact set** of relations that refuse it, asserted equal — and it ends with a
**completeness assertion**: of the family's 54 enforcing gates, the 10 frame gates and every
`*_boolean` set aside, the remaining **28** must each be named by some tamper above, so a gate
added with no forgery beside it fails the suite. `every_booleanity_gate_refuses_a_value_of_two`
covers the sixteen booleans this family commits — the eight kind bits, `f_div`, both top bits,
both sign adjustments, and the product's, quotient's and remainder's sign flags — and six
further tests take one soundness question each.

| cell moved | on the row | refused by, exactly |
| --- | --- | --- |
| `decoded_mask` | `mul 7 3`, claiming `mulh`'s mask | `decoded_mask_bits` |
| `f_div` → 1 | `mul 7 3` | `f_div_rule`, `mx_rule`, `division_rule`, `rz_inverse`, `dz_inverse`, `gap_rule` — six formulas read it |
| `s1` → 1, whole row recomputed | a `mulhu` reading its `rs1` signed | `s1_rule` |
| `s2` → 1, whole row recomputed | a `mulhsu` reading its `rs2` signed | `s2_rule` |
| an `rs1` query added | padding | `rs1_mask_rule` |
| an `rs2` query added | padding | `rs2_mask_rule` |
| an `rd` query into `x0` added | padding | `rd_mask_rule` |
| an `rd` query rewriting `x10` | padding | `rd_mask_rule`, `rd_addr_rule`, `rd_value_rule` |
| `rs1_addr`, `rs2_addr` `+ 1` | `mul 7 3` | `rs1_addr_rule`, `rs2_addr_rule` |
| `rd_addr` → 5 | `mul 7 3` | `rd_addr_rule` |
| `rs1_read_value` → 5 | padding | `rs1_value_masked` |
| `rs2_read_value` → 5, `abs_d` moved to match | padding | `rs2_value_masked` |
| `pc_write_value` `+ 4` | `mul 7 3` | `next_pc_rule` |
| `mx` → 8 | `mul 7 3` | `mx_rule`, `product_rule` |
| `my` → 4 | `mul 7 3` | `my_rule`, `product_rule` |
| `p_high` `+ 1` | `mul 7 3` | `product_rule` |
| `(q, r)` → `(2, 0)` on `DIV(7, 3)`, whole witness recomputed | a forged division | `division_rule` |
| `rz` → 0 | an exact `divu` | `rz_inverse` |
| `rz` → 1, `r_inv` → 0 | an inexact `divu` | `rz_at_nonzero` |
| `dz` → 0 | `divu 0xdeadbeef 0` | `dz_inverse`, `gap_rule` |
| `dz` → 1, `d_inv` → 0 | `divu 7 3` | `dz_at_nonzero`, `gap_rule`, `zero_divisor_quotient` |
| `d1` → 0 | `div 0x80000000 0xffffffff` | `d1_rule` |
| `(q, r)` → the **floored** `(−4, 1)` on `DIV(−7, 2)` | a forged division | `r_sign_rule` |
| `abs_r` `+ 1` | `divu 7 3` | `abs_r_rule`, `gap_rule` |
| `abs_d` `+ 1` | `divu 7 3` | `abs_d_rule`, `gap_rule` |
| `gap` `+ 1` | `divu 7 3` | `gap_rule` |
| `q` → 0 on a zero divisor, whole witness recomputed | a forged `divu` | `zero_divisor_quotient` |
| `rd_selected` `+ 1` | `mul 7 3` | `rd_value_rule` |
| the `rd` query dropped | `mul 7 3` | `rd_write_masked`, `rd_mask_rule` |

The six further tests, each isolating one thing the accounting above cannot show cell by cell:

- **`the_division_encoding_admits_exactly_one_witness_at_a_reduced_width`** — S18's acceptance 5,
  and the reason `arithmetic_gates` takes a width at all. At a **four-bit** word it enumerates
  every `(dividend, divisor)` pair and each of `DIV`, `DIVU`, `REM`, `REMU`, freely varying `q`,
  `r`, `q_sign`, `rz`, `dz`, `r_sign` and `p_sign` and computing every other column from the gate
  that defines it, and asserts that exactly one `(q, r)` survives and that it is the width-four
  RV32M answer. The two operands' top bits are supplied from the table's semantics rather than
  enumerated, because a lookup and not a gate is what pins them. Where the divisor is zero
  **both** values of `q_sign` survive and nothing else varies — the acceptance item's "exactly
  one witness" is true up to that one freedom, and the check asserts the true statement
  (`mul-div.md` §6).
- **`the_floored_quotient_satisfies_the_identity_and_is_refused_by_the_sign_rule`** —
  `DIV(−7, 2)` carrying `q = −4` and `rem = 1`: the division identity holds and the magnitude
  bound holds, and `r_sign_rule` alone refuses it.
- **`a_quotient_off_by_one_is_refused_by_the_gap_or_by_the_identity`** — the two gates that
  between them leave no room for a neighbouring quotient.
- **`a_zero_divisor_whose_quotient_is_not_all_ones_is_refused_by_the_pin_alone`** — with the
  divisor zero the identity and the gap say nothing about `q`; `zero_divisor_quotient` is the
  whole pin, and it is the lone refusal.
- **`the_signed_overflow_has_exactly_the_pinned_answer`** — `−2^31 ÷ −1` with no pin of its own:
  the three gates that already hold force `q = 0x80000000` and `r = 0`.
- **`a_forged_operand_sign_is_refused_by_its_lookup_alone`** — a top bit claimed wrong with the
  whole row recomputed around it. No gate sees it; `U16GetSign` over the range-checked halfword
  is the lone refusal, which is why §6.6's key bound is load-bearing.

On a padding row `pc_mask = 0`, every frame mask is 0, every leaf is 1 and every obligation is
vacuous. `f_div` is a **free boolean** there, so a padding row may carry a whole division
witness; it constrains nothing, the `rd` query being absent, and it costs no table multiplicity
either, this family having no selector but `pc_mask` and the frame's masks. With every kind bit 0
the gates hold `s1`, `s2`, `mx`, `my`, `rd_selected` and `pc_write_value − decoded_next_pc` to 0,
tie `p_low + 2^32·p_high − 2^64·p_sign` to 0 through `product_rule`, and — where the claimed
`f_div` is 1 — still hold the whole division identity over a zero dividend and a zero divisor,
which `dz = 1` and the correction make satisfiable. The honest fill writes 0 everywhere.

---

## 7. `INIT_TEARDOWN` — family 7

### 7.1 Header

`family_circuit(7, n)` is `memory::image_window_artifact(n)` with no channels. RAM window 0,
the image window: exactly one shard, window id 0. Spec: `memory.md` §3. Fill:
`prover::family_fill(7)`, the private `fill::window`, which is
`trace::build_init_teardown_columns(log, image, 0, h)`. Three committed columns, two virtual
tables, two leaves, no enforcing gate, no lookup, two outputs. At `n = 16`, S16's statement:
17 gate lists, top `L17`, 34 inner columns and relations.

### 7.2 Columns

| address | name | Rust | descriptive name | row `y` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the timestamp of the last write to the word at `4y`; 0 if the word is untouched or `y < 2^14` | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final word | the last value written; the image word if untouched; 0 if `y < 2^14` | leaf `teardown` |
| `S[0]` | `init_value` | `PolyAddress::Setup(0)` | Image word | `image.initial_word(4y)`: `program::image_init_column(image, h)` | leaf `init` |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |
| `V[ram_live]` | `ram_live` | `VirtualKind::RamLive`, wire tag 1 | Row is RAM | 1 if `y ≥ 2^14`, else 0 | both leaves, as their mask |

`M[0]` and `M[1]` are committed in `PublicInputs::memory_commitments`, whose `INIT_TEARDOWN`
group G8 absorbs first. `S[0]` is identity's `cm(image column)` and is opened against it
(`shard-proof.md` §5.2). Rows `y < 2^14` are the addresses below `RAM_ORIGIN`, which
`V[ram_live]` masks off.

### 7.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `1 + WC·V[ram_live] − V[ram_live] + α_addr·V[row]·V[ram_live] ×4 + α_ts·M[0]·V[ram_live] + α_val·M[1]·V[ram_live]` | `ram_live·T(RAM, 4·row, teardown_ts, teardown_value) + 1 − ram_live` |
| 1 | 1 | `init` (write side) | `1 + WC·V[ram_live] − V[ram_live] + α_addr·V[row]·V[ram_live] ×4 + α_val·S[0]·V[ram_live]` | `ram_live·T(RAM, 4·row, 0, init_value) + 1 − ram_live` |

Here `WC = γ_M + 2`, the window constant at `w = 0`. Both leaves are `Quadratic`; code: the
private `memory::leaf` over `window_tuple`. `check_memory` admits `V[ram_live]` as a mask
because it is 0 or 1 on every row by construction.

Halving list `k`, for `1 ≤ k ≤ n`, writes `L{k+1}` (`n − k` variables):

| `L{k+1}` | relation | node | shape |
| --- | --- | --- | --- |
| 0 | `2k` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` |
| 1 | `2k + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` |

In the last list, `k = n`, the two nodes are `read_root` and `write_root`.

| output | address, `n = 16` | node | value | verifier |
| --- | --- | --- | --- | --- |
| 0 | `L{17}[0]` | `read_root` | the product of every row's teardown leaf | step 10 |
| 1 | `L{17}[1]` | `write_root` | the product of every row's init leaf | step 10 |

### 7.4 Rows

A window shard has no padding: every row is an address.

| row | `teardown_ts` | `teardown_value` | `init_value` | leaves |
| --- | --- | --- | --- | --- |
| `y < 2^14`, below `RAM_ORIGIN` | 0 | 0 | 0 | both 1 |
| a word no cycle touched | 0 | the image word `v` | `v` | both `T(RAM, 4y, 0, v)`: they cancel |
| a word some cycle touched, by a read or a write (a read writes back what it read) | the last query's write timestamp `t` | the value it wrote, `v'` (`v` itself for a word only read) | the image word `v` | `T(RAM, 4y, t, v')` read against `T(RAM, 4y, 0, v)` written |

Nothing in this circuit checks a row alone. On rows `y ≥ 2^14` both `M` columns are fixed by
the memory argument alone. On rows `y < 2^14` every leaf term but the constant 1 carries
`V[ram_live] = 0`, so `M[0]` and `M[1]` there reach no leaf, gate or output, and nothing fixes
them; the honest fill writes 0. `S[0]` is fixed on every row by the opening against identity.

---

## 8. `ZERO_WINDOWS` — family 8

### 8.1 Header

`family_circuit(8, n)` is `memory::zero_window_artifact(n)` with no channels. One shard per RAM
window above 0 that the execution touches, `trace::init_windows(log, h)`; shard `i` is window
`windows[i]`, and `WC` is `γ_M + 2 + α_addr·4h·windows[i]`. Spec: `memory.md` §3. Fill:
`fill::window`, `build_init_teardown_columns(log, image, w, h)`. Two committed columns, one
virtual table, two unmasked leaves, no enforcing gate, no lookup, two outputs. S16's statement
has no shard of this family.

### 8.2 Columns

| address | name | Rust | descriptive name | row `y` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the last write's timestamp to the word at `4h·w + 4y`, or 0 | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final word | the last value written, or 0 | leaf `teardown` |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |

### 8.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `α_addr·V[row] ×4 + α_ts·M[0] + α_val·M[1] + WC` | `T(RAM, 4h·w + 4·row, teardown_ts, teardown_value)` |
| 1 | 1 | `init` (write side) | `α_addr·V[row] ×4 + WC` | `T(RAM, 4h·w + 4·row, 0, 0)` |

Both are `Linear` and carry no mask: every row of a window above 0 is a RAM word, since
`4h ≥ RAM_ORIGIN` at every menu height. The halving lists and outputs are §7.3's, with the same
names, relation numbers and addresses.

### 8.4 Rows

| row | `teardown_ts` | `teardown_value` | leaves |
| --- | --- | --- | --- |
| a word no cycle touched | 0 | 0 | both `T(RAM, 4h·w + 4y, 0, 0)`: they cancel |
| a word some cycle touched, by a read or a write (a read writes back what it read) | the last query's write timestamp | the value it wrote (0 for a word only read) | the final tuple read against the zero tuple written |

---

## 9. Observations

Facts this accounting turned up. None changes a circuit.

1. **The registry and the height menu disagree both ways.** `family_circuit` builds
   all four registered execution circuits at every `n` from 19 to 30, and the two window
   circuits at every `n` from 0 to 30. A key's heights come from `VmConfig`, which
   `VmConfig::from_bytes` holds to `HEIGHT_MENU` (`n` = 16, 18, 20, 22). So the four execution
   circuits are reachable only at 20 and 22, which is `shard-proof.md` §8's,
   `jump-branch-slt.md` §2's, `shift-bitwise.md` §2's and `mul-div.md` §2's `trace_vars ≥ 20`:
   the timestamp channel's 19 variables, made even for Mercury. The windows are reachable only
   at 16, 18, 20 and 22, never at `n ≤ 14`, where `V[ram_live]` is 0 on every row and
   `INIT_TEARDOWN` would mask its whole window. Conversely, no execution circuit exists at the
   menu's 16 and 18, so a `VmConfig` placing one there decodes but no key for it loads
   (`VerifyingKey::check`). **`MUL_DIV`'s default height is `2^20`, not `2^22`**
   (`constants::family::DEFAULT_HEIGHTS`), the one execution family whose default is not the
   maximum.
2. **Eighteen of add/sub's 67 `M` and `W` columns are inert at S16.** The `arg1`, `arg2` and
   `ram` queries (`M[16..31]`, `W[3..6]`) are held absent on every row, but `frame_queries`
   fixes the frame, so they are committed, opened and carried by every shard. They are the
   I/O-binding stage's. The three four-query frames — jump/branch/slt's, shift/bitwise's and
   mul/div's — have no inert query, and all three are the same 21 `M` columns and the same bare
   frame artifact, `memory_frame_reg.bin` (§2.2).
3. **`rd_is_zero_boolean` (relation 81 in §3, 92 in §4, 132 in §5, 124 in §6) is implied** by the two gates before it
   with a boolean `rd_mask`: `rd_is_zero_at_nonzero` makes `rd_is_zero` 0 wherever
   `rd_addr ≠ 0`, and `rd_is_zero_inverse` makes it `rd_mask` wherever `rd_addr = 0`. It remains
   as S14's must-be-exact 7 lists it; `jump-branch-slt.md` §3.1 gives the same argument for the
   `is_zero` gadget, which carries no booleanity gate.
4. **No enforcing gate and no lookup reads `pc_addr`**; only the leaves `read_pc` and
   `write_pc` do (§3.3, §4.3, §5.3, §6.3). It is 0 because the memory argument has initial and
   final pc tuples at address 0 only (§3.10); the same holds for every family's frame. In
   jump/branch/slt, shift/bitwise and mul/div `rd_read_value` is read by the leaf `read_rd`
   alone, too, and so is fixed by the memory argument alone; add/sub's `exit_status` reads it
   there, and is the only registered family that does.
5. **A `sub` row's `decoded_imm` is fixed by the decoder table alone.** No gate constrains it
   there: `sub` has no `imm` term, and the gates that read it (`add_addi_auipc`, `lui`,
   `ecall_code`, `fence_code`) are gated off by bits that are 0 on a sub row. On an `add` row
   `add_addi_auipc` reads it, and the table row's 0 is what `shard-proof.md` §8.4 relies on
   ("an R-type row's `imm` is 0 … so no third addend is live"); on a `sub` row nothing relies
   on it. The same holds in jump/branch/slt on `slt` and `sltu` rows, whose `imm` is 0, and on
   a branch that falls through, whose displacement no gate reads: `cmp_rhs_rule` reads `imm`
   only under the `slti` and `sltiu` bits, and `next_pc_rule` only under `taken` and the jump
   bits (§4.10).
6. **`INIT_TEARDOWN`'s cells below `RAM_ORIGIN` are unconstrained.** On its `2^14` rows
   `y < 2^14`, `V[ram_live]` is 0, so `teardown_ts` and `teardown_value` reach nothing (§7.4).
   They are committed and opened, and only the honest fill makes them 0; no check depends on
   their value.
7. **`jalr_drop` is free on every row but a `jalr` row.** `next_pc_rule` reads it only times
   `kind_jalr`, so elsewhere `jalr_drop_boolean` alone holds it, to 0 or 1 (§4.10: a taken
   `beq` row with `jalr_drop = 1` breaks nothing). No check depends on its value there; the
   honest fill writes 0. Add/sub's `wrap` is the same on its lui, fence, exit and padding rows.
8. **Jump/branch/slt compares on every live row, whatever the kind.** `cmp_order`, `eq_inverse`
   and `eq_at_nonzero` are ungated, and the comparison's six range obligations and two sign
   lookups are selected by `pc_mask`. So a `jal` row compares 0 with 0 (`eq = 1`), a `jalr` row
   compares `rs1` with 0 (`cmp_gap = rs1`), and an unsigned or non-comparing row still looks
   both signs up. There `sc = 0`, so `cmp_order`'s sign terms vanish and the generic table
   alone fixes the signs (§4.10); `taken_rule` and `rd_value_rule` read `eq` and `lt` only
   under branch and `slt` bits. The honest fill computes all of it on every live row.
9. **A jump/branch/slt padding row leaves `lt` and `cmp_gap` free together.** `cmp_order` holds
   on every row, but `cmp_gap`'s range pair is off where `pc_mask = 0`, so `lt = 1` with
   `cmp_gap = 2^32` breaks nothing there (§4.10). No leaf and no table reads either on a
   padding row, so no check depends on the pair; the honest fill writes 0 in both.
10. **S18's stage prompt's Shape paragraph and what was built diverge on the memory-column
    count.** The prompt guessed 15 memory columns for `SHIFT_BITWISE`; the frozen four-query
    frame gives 21 (`1 + 5·4`, `memory.md` §2.1 and §2.2), which is what both new circuits
    carry. The frame is not a stage's to choose — `memory::frame_queries` is frozen, and a
    frame narrower than its family cannot balance — so the circuits are right and the estimate
    was an estimate. It changes nothing; `docs/handoff/S18-shift-mul.md` carries the detail.
11. **The `RANGE16` tree is what sets both new circuits' depth, from opposite sides.**
    Shift/bitwise's carries 24 obligations, comfortably past 16 (§5.6); mul/div's carries 16,
    which with its table fraction is **seventeen** leaves — one past a 16-leaf tree — and pads
    to 32 all the same, so half of its `L2` `range16` nodes combine two pads (§6.7). The extra
    row-wise level costs each circuit one gate list and one proof transition — at `n = 20`, a
    20-round transition over a 12-column layer, 2,952 bytes of the two proofs' 68,564 and 67,412
    (§1.2); the rest of their length over §3's and §4's is their wider layers. Mul/div is the
    circuit where a single dropped obligation would take the level back; §6.6 says why none is
    droppable.
12. **`abs_d` is computed on every live mul/div row, multiply rows included.** `abs_d_rule` and
    `abs_r_rule` are ungated, so a `mulhsu` of `0xffffffff` carries `abs_d = 0xffffffff`
    (§6.9's row `C`); nothing reads either magnitude there, `gap_rule`'s `f_div` factor being
    0. The same shape as observation 8's: the cheaper gate is the ungated one, and the family
    bit is what makes it vacuous.
13. **Three columns of mul/div are boolean without a booleanity gate, and one of shift/bitwise
    carries one it does not need.** `rz` and `dz` are boolean by the is-zero gadget's
    construction and `d1` by the two boolean columns it multiplies, so none carries one — S17's
    argument for `eq`, unchanged. Conversely `se_boolean` (relation 164 in §5) is implied by
    `se_rule` over a boolean `rs1_sign` and one-hot kind bits, and is written anyway because
    S18's must-be-exact 5 asks a sign bit's sign-weighted form to carry one. Neither choice
    costs a degree.
14. **`check_copowers` is a rule with exactly one circuit under it at S18, and it was tightened
    for that circuit.** S17 introduced it for `next_pc`'s halved obligation in jump/branch/slt;
    S18 made it take each scaled column with the selector its scaled obligation carries and
    demand the direct pair under *that same* selector (`shift-bitwise.md` §3.4), and
    shift/bitwise passes six columns to it. Mul/div passes none: it bounds nothing by scaling,
    so `assemble` does not call the check at all (§6.6).

---

## 10. Maintaining this page

A stage that adds a circuit family, or changes one, updates this page in the same pull request
(`prompts/00-master.md`, implementation rule 12). A new family's entry is a section like §3, §4,
§5 or §6 and holds:

1. **A header**: the family id and constant, the constructor, the channels, the fill, the spec
   section that is normative for it, the committed and virtual column counts, and the depth,
   inner-column and relation counts at the heights its stage proves.
2. **Its row kinds**: the kind bits and codes, which queries each kind makes, what each writes,
   and what is not provable.
3. **Every base column**: `PolyAddress`, artifact name, Rust identifier, a descriptive name,
   what the honest fill writes, who fills it, where it is committed, and every gate, leaf and
   obligation that reads it. The frame's columns may cite §2.
4. **Every gate of list 0**, leaves and enforcing gates, by relation number, with its purpose,
   shape, degree, constructor, positional form and named form, factored where it helps. Leaves
   built by one pattern (§0.6) may be given as a table of their operands under that pattern,
   with the pattern's positional form shown once.
5. **Every lookup**: channel, selector and tuple in both forms, and the channel table with
   output positions, table columns and multiplicity column.
6. **Every inner layer**: each row-wise layer in full, and the halving pattern with its relation
   numbers and root names.
7. **The outputs**, and which `verify_shard` step reads each.
8. **Witness rows** taken from a test that holds them to the circuit in CI, and the per-cell
   accounting of §3.10 and §4.10 — or, where the family's suite carries a committed tamper
   table of its own (§5.10, §6.10), that table read as a cell-by-cell account, which is the
   better source: it runs in CI and a probe does not.
9. **Its rows in §1.1, §1.2 and §1.3, its counts in §0.5, the challenge slots it reads in
   §0.4**, and any §9 observation the accounting turns up. A family whose decoded tuple is not
   seven wide also moves §0.4's `β` and `g_dec` rows, as `MUL_DIV`'s six-wide one did.

Appendix A's commands print every `n = 22` name, position and formula, and the `n = 22` counts
follow from them; the `n = 16` and `n = 20` counts and the §3.10 and §4.10 probes were read from
`family_circuit` and the suites' `honest_rows` directly and have no committed command
(Appendix A, last paragraph). The `checker dump` of the family's committed fixture is the machine
view to check the entry against.

---

## Appendix A. Reproducing

```text
cargo run -p checker -- dump crates/constraints/tests/vectors/add_sub.bin           # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/jump_branch_slt.bin   # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/shift_bitwise.bin     # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/mul_div.bin           # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/image_window.bin      # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/zero_window.bin       # n = 22
for f in alu reg mem atomics; do
  cargo run -p checker -- dump crates/constraints/tests/vectors/memory_frame_$f.bin    # §2.2's four bare frames
done
cargo run -p checker -- laws crates/constraints/tests/vectors/add_sub.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/jump_branch_slt.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/shift_bitwise.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/mul_div.bin
cargo test -p checker --test add_sub            # §3.9's rows against every gate and bound
cargo test -p checker --test jump_branch_slt    # §4.9's rows against every gate, bound and table
cargo test -p checker --test shift_bitwise      # §5.9's and §5.10's, 17 tests
cargo test -p checker --test mul_div            # §6.9's and §6.10's, 17 tests
```

The dump prints the header, the committed columns, the virtual tables, every gate list with
each gate as a formula over addresses and its relation number and name, the flat relation list,
the scratch bijection, the output map, the lookups, the padding contract and the gate
catalogue. A relation number, an `L{k}[j]` and a node name in this page are the dump's, except
that the leaf and inner-layer subsections write a fraction node by its stem `x`: the dump names
its two columns `x_num` and `x_den`, defined by relations `define_x_num` and `define_x_den`. The
halving lists repeat one pattern, so the dump at `n = 22` gives every `n`: the row-wise layers do
not depend on `n` — `L1`–`L5` for add/sub and jump/branch/slt, `L1`–`L6` for the two S18
families — nor do relations 0–183 of add/sub, 0–213 of jump/branch/slt, 0–305 of shift/bitwise
and 0–297 of mul/div, and the halving lists follow §3.8's, §4.8's, §5.8's and §6.8's formulas.

The counts at `n = 16` and `n = 20` were read from `family_circuit` directly (its artifact's
`depth()`, layer widths, `relations`, `lookups` and `to_bytes()`), which has no CLI. The §3.10
probe is add/sub's `honest_rows` with one cell moved at a time, run through
`violated_relations` and `violated_lookups`; the §4.10 probe is the same over
jump/branch/slt's `honest_rows`, run also through that suite's own table check,
`violated_tables`. §5.10 and §6.10 need no probe: they are their suites'
`each_gate_is_the_one_that_refuses_its_row` read as a cell-by-cell account, and that test runs
in ordinary CI. §1.2's proof byte lengths are `crates/prover/tests/alu.rs`', which is
`#[ignore]`d and runs with `--include-ignored --test-threads=1`; the formula it checks them
against is `shard-proof.md` §9's over the circuit's own shape.
