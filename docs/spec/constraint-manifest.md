# The constraint-system manifest: every circuit, every column, every gate

> **What this page is.** An accounting document. The specs say *why*: `gkr.md` the engine,
> `memory.md` the memory argument, `lookup.md` the channels, `shard-proof.md` §8 the add/sub
> family, `jump-branch-slt.md` the jump/branch/slt family. This page says *what exists*: every
> circuit `constraints::family_circuit` returns; every committed and virtual column with its
> position, name, meaning and readers; every intermediate multilinear by layer and offset; and
> every gate with its formula. It gives columns and gates descriptive names and one-line
> purposes that the code does not carry, and puts beside each the identifiers that find it in
> the code: the `PolyAddress`, the artifact's own name for it, and the Rust constant or
> constructor that makes it.
>
> **Status: S17.** Four circuits are registered: `ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT`,
> `INIT_TEARDOWN` and `ZERO_WINDOWS`. The five other execution families have a memory frame (§2)
> and no circuit.
>
> **Descriptive, not normative.** Where this page and the code disagree, the registry is right
> and this page is wrong; where it and a spec disagree, the spec rules. The descriptive names
> are documentation only, as the artifact's own names are (`gkr.md` §4.2): no code reads either.
>
> **Kept current by rule.** A stage that adds or changes a circuit family updates its entry
> here in the same pull request (`prompts/00-master.md`, implementation rule 12). §8 is what an
> entry must hold.
>
> **Machine-derived.** Every count, position, name and formula below was read out of
> `family_circuit`'s artifacts, not off the source by eye. Appendix A's commands print the
> committed `n = 22` artifacts, against which every name, position and positional formula can be
> checked; the `n = 16` and `n = 20` counts and the §3.10 and §4.10 probes were read by a program
> over `family_circuit` and the two suites' `honest_rows` that is not committed. §3.9 shows nine
> of the sixteen rows that `honest_rows`, in `crates/checker/tests/add_sub.rs`, holds to every
> gate and range obligation in CI; §4.9 shows nine of the 47 in
> `crates/checker/tests/jump_branch_slt.rs`, which also holds them to both table channels.

---

## 0. Reading this page

### 0.1 Where the truth is

| what | where |
| --- | --- |
| the circuit a verifying key must carry | `constraints::family_circuit(family, trace_vars)`, `crates/constraints/src/lib.rs` |
| the add/sub circuit | `constraints::add_sub::{artifact, channels}`, `crates/constraints/src/add_sub.rs` |
| the jump/branch/slt circuit | `constraints::jump_branch_slt::{artifact, channels}`, `crates/constraints/src/jump_branch_slt.rs` |
| the is-zero and comparison gadgets | `constraints::gadgets::{is_zero, comparison, comparison_equation}`, `crates/constraints/src/gadgets.rs` |
| the frame, the memory tuples, the two window circuits | `constraints::memory`, `crates/constraints/src/memory.rs` |
| the fraction trees and their denominators | `constraints::lookup`, `crates/constraints/src/lookup.rs` |
| the layer assembly: reduction, halving, the names of inner nodes | `crates/constraints/src/build.rs`, `assemble` |
| a circuit, printed | `cargo run -p checker -- dump <artifact>` (Appendix A) |
| the columns' values | `trace::{build_memory_columns, build_frame_witness, build_init_teardown_columns, build_multiplicities}` and `prover::family_fill`, `crates/prover/src/fill.rs`; the packed generic table, `program::lookup_tables::generic_table` |

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
  address (`V[ram_live]` is `ram_live`): §3's and §4's tables keep the address form, §5 and §6
  write the bare word.
- **`n`** is the circuit's `trace_vars`: a shard has `h = 2^n` rows, and RAM window `w` starts
  at byte address `4h·w`.

### 0.3 What row `y` of a column is

Columns of one layer do not all index the same thing.

| column | row `y` is |
| --- | --- |
| an execution family's `M` and `W` columns, multiplicities excepted | the shard's `y`-th cycle of that family, in execution order; rows past the last are **padding**, every cell 0 in an honest fill |
| a multiplicity column | row `y` of its channel's **table**: how many of the shard's gated tuples equal that row, counted on the lowest row holding a repeated tuple (`lookup.md` §7) |
| a decoded-table `S` column | the halfword at pc `2y`; `MINUS_ONE` in every column where no instruction of the family starts (`crates/program/CLAUDE.md`) |
| a generic-table `S` column (`JUMP_BRANCH_SLT`'s `S[7..10]`) | row `y` of the packed table (`lookup.md` §9): row 0 the `ZeroEntry`, all 0; rows 1 to `2^16` the AND byte table's `(AND_BASE + a + 1, b, a & b)`; rows `2^16 + 1` to `2^17` `U16GetSign`'s `(SIGN_BASE + h + 1, h >> 15, 0)`; every later row 0. `AND_BASE = 0` and `SIGN_BASE = 256` are `constants::generic_table`'s |
| `V[range19]`, `V[range16]` | the value `y mod 2^19`, `y mod 2^16` |
| a window family's `M` columns, `S[0]`, `V[row]`, `V[ram_live]` | the RAM word at byte address `4h·w + 4y`, `w` being the shard's window (§5, §6) |

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
| 7 | `LOOKUP_BETA` | `β` | drawn per shard, after `g` | S4 | the decoder's two denominators; in jump/branch/slt also the generic channel's three: its table's and the two sign lookups' |
| 8 | `LOOKUP_BETA_2` | `β²` | derived: a power of `β` | `gkr_verify::insert_lookup_challenges` | the decoder's two denominators; in jump/branch/slt also the generic table's denominator, not the sign lookups', whose third tuple position is the constant 0 and adds no term |
| 9–12 | `LOOKUP_BETA_3` … `LOOKUP_BETA_6` | `β³` … `β⁶` | derived: powers of `β` | `insert_lookup_challenges` | the decoder's two denominators |
| 13 | `LOOKUP_DECODER_NEUTRAL` | `g_dec` | derived: `g − Σ_{j<W} β^j`, `W` the artifact's decoder tuple width, 7 in both circuits that have one | `insert_lookup_challenges` | `decode_row`'s denominator |

### 0.5 The gate shapes

`GateDef` (`crates/constraints/src/lib.rs`, and `constraints::CATALOGUE`, the same seven rows);
`gkr_verify::eval_gate` evaluates every one. Counts are over one circuit at `n = 20`.

| tag | shape | `G` | list kind | used by |
| --- | --- | --- | --- | --- |
| 0 | `Linear { terms, constant }` | `Σ c_i·x_i + c_0` | row-wise | add/sub, 54: 35 leaves of list 0 (the 2 memory pads, the 22 leaf numerators, the 3 table denominators, the 8 pad-fraction columns), 9 degree-1 enforcing gates, 10 copies in lists 2–4; jump/branch/slt, 71: 54 leaves of list 0 (the 26 leaf numerators, 4 of tables and 22 of lookups, the 4 table denominators, the 24 pad-fraction columns), 3 degree-1 enforcing gates, 14 copies in lists 2–4; `ZERO_WINDOWS`, 2 leaves |
| 1 | `Product { coeff, left, right }` | `c·x·y` | row-wise | add/sub, 37: the 14 row-wise product-tree nodes (lists 1–3) and the 23 row-wise fraction-node denominators (lists 1–4); jump/branch/slt, 40: the 6 row-wise product-tree nodes (lists 1–2) and the 34 row-wise fraction-node denominators (lists 1–4) |
| 2 | `MaskIntoIdentity { input, mask }` | `x·m + 1 − m` | row-wise | no registered circuit (`memory.md` §2.2 says why) |
| 3 | `AffineProduct { .. }` | `(Σ a_i·x_i + a_0)·(Σ b_j·y_j + b_0)` | row-wise | no registered circuit |
| 4 | `TreeProduct { input }` | `x(y,0)·x(y,1)` | halving | add/sub, 5 per halving list (100); jump/branch/slt, 6 per halving list (120); each window circuit, 2 per list (40) |
| 5 | `Quadratic { constant, linear, products }` | `c_0 + Σ a_i·x_i + Σ b_j·y_j·z_j` | row-wise | add/sub, 93: 14 memory leaves and 19 lookup row denominators (list 0), 37 degree-2 enforcing gates, and the 23 row-wise fraction-node numerators (lists 1–4); jump/branch/slt, 103: 8 memory leaves and 22 lookup row denominators (list 0), 39 degree-2 enforcing gates, and the 34 row-wise fraction-node numerators (lists 1–4); `INIT_TEARDOWN`, 2 leaves |
| 6 | `TreeCross { left, right }` | `p(y,0)·q(y,1) + p(y,1)·q(y,0)` | halving | add/sub, 3 per halving list (60); jump/branch/slt, 4 per halving list (80) |

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

| id | family | constructor | channels | `Some` for | default height | S16's statement (`guests/addsub`) | S17's statement (`guests/control`) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | `ADD_SUB_LUI_AUIPC` | `add_sub::artifact(n)` | `add_sub::channels()`: `TIMESTAMP`, `RANGE16`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | one shard at `2^20` | one shard at `2^20` |
| 1 | `JUMP_BRANCH_SLT` | `jump_branch_slt::artifact(n)` | `jump_branch_slt::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | not in the config: the guest runs no instruction of the family | one shard at `2^20` |
| 2–6 | `SHIFT_BITWISE` … `ATOMICS` | — | — | never | `2^22`, but `MUL_DIV` `2^20` and `ATOMICS` `2^16` | — | — |
| 7 | `INIT_TEARDOWN` | `memory::image_window_artifact(n)` | none | `0 ≤ n ≤ 30` | `2^22` | one shard at `2^16` | one shard at `2^16` |
| 8 | `ZERO_WINDOWS` | `memory::zero_window_artifact(n)` | none | `0 ≤ n ≤ 30` | `2^22` | at `2^16`, with no shard: the guest touches no RAM | at `2^16`, with no shard: the guest touches no RAM |

A verifying key carries only menu heights (`constants::family::HEIGHT_MENU`, `2^16` to `2^22`),
which `VmConfig::from_bytes` enforces, so `n` is 16, 18, 20 or 22 in any key; §7 notes the
other values the registry accepts. The prover pairs each circuit with a fill,
`prover::family_fill`: the private `fill::add_sub` for family 0, `fill::jump_branch_slt` for 1,
`fill::window` for 7 and 8. The S16 statement is `crates/prover/tests/acceptance.rs`': its
config lists families 0, 7 and 8, and its shard counts are `[1, 1, 0]`. The S17 statement is
`crates/prover/tests/control.rs`': its config lists families 0, 1, 7 and 8, and its shard counts
are `[1, 1, 1, 0]`.

### 1.2 Master table

```text
circuit             n  lists (row-wise + halving)  top   M   W   S   V  committed  inner  enforcing (d1/d2)  lookups (ts/r16/gen/dec)  outputs  relations   bytes
ADD_SUB_LUI_AUIPC  20  25 (5 + 20)                 L25  36  31   7   2      74       298     46 (9/37)          19 (14/4/0/1)              8        344      67,100
ADD_SUB_LUI_AUIPC  22  27 (5 + 22)                 L27  36  31   7   2      74       314     46 (9/37)          19 (14/4/0/1)              8        360      68,190
JUMP_BRANCH_SLT    20  25 (5 + 20)                 L25  21  44  10   2      75       372     42 (3/39)          22 (8/11/2/1)             10        414      75,608
JUMP_BRANCH_SLT    22  27 (5 + 22)                 L27  21  44  10   2      75       392     42 (3/39)          22 (8/11/2/1)             10        434      76,980
INIT_TEARDOWN      16  17 (1 + 16)                 L17   2   0   1   2       3        34      0                  0                         2         34       3,259
INIT_TEARDOWN      22  23 (1 + 22)                 L23   2   0   1   2       3        46      0                  0                         2         46       3,907
ZERO_WINDOWS       16  17 (1 + 16)                 L17   2   0   0   1       2        34      0                  0                         2         34       2,770
ZERO_WINDOWS       22  23 (1 + 22)                 L23   2   0   0   1       2        46      0                  0                         2         46       3,418
```

`committed` is layer 0's width, `M + W + S`. `inner` is the width of every layer above 0,
summed: the multilinears that are never committed, one producing gate each. `relations` is
producing plus enforcing gates. `bytes` is `to_bytes().len()`. The `n = 22` rows are the
committed fixtures: `crates/constraints/tests/vectors/add_sub.bin` (SHA-256 `4c797137…c2ea114b`),
`jump_branch_slt.bin` (`99094d63…742c1305`), `image_window.bin` (`39a8655d…2df67ecc`) and
`zero_window.bin` (`f08dde67…aa51ec1c`), each pinned by its suite.

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
| 2 `SHIFT_BITWISE` | pc rs1 rs2 rd | 4 | 21 | 7 | 4 | 10 | 8 | none yet | `memory_frame_reg.bin` |
| 3 `MUL_DIV` | pc rs1 rs2 rd | 4 | 21 | 7 | 4 | 10 | 8 | none yet | `memory_frame_reg.bin` |
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
`memory::frame_with_channels_artifact(&QUERIES, n, Extras { .. })` (`QUERIES` and the `SLOT_*`
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
built by `memory::frame_with_channels_artifact(&QUERIES, n, Extras { .. })` with S17's two
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

## 5. `INIT_TEARDOWN` — family 7

### 5.1 Header

`family_circuit(7, n)` is `memory::image_window_artifact(n)` with no channels. RAM window 0,
the image window: exactly one shard, window id 0. Spec: `memory.md` §3. Fill:
`prover::family_fill(7)`, the private `fill::window`, which is
`trace::build_init_teardown_columns(log, image, 0, h)`. Three committed columns, two virtual
tables, two leaves, no enforcing gate, no lookup, two outputs. At `n = 16`, S16's statement:
17 gate lists, top `L17`, 34 inner columns and relations.

### 5.2 Columns

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

### 5.3 Leaves and layers

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

### 5.4 Rows

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

## 6. `ZERO_WINDOWS` — family 8

### 6.1 Header

`family_circuit(8, n)` is `memory::zero_window_artifact(n)` with no channels. One shard per RAM
window above 0 that the execution touches, `trace::init_windows(log, h)`; shard `i` is window
`windows[i]`, and `WC` is `γ_M + 2 + α_addr·4h·windows[i]`. Spec: `memory.md` §3. Fill:
`fill::window`, `build_init_teardown_columns(log, image, w, h)`. Two committed columns, one
virtual table, two unmasked leaves, no enforcing gate, no lookup, two outputs. S16's statement
has no shard of this family.

### 6.2 Columns

| address | name | Rust | descriptive name | row `y` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the last write's timestamp to the word at `4h·w + 4y`, or 0 | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final word | the last value written, or 0 | leaf `teardown` |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |

### 6.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `α_addr·V[row] ×4 + α_ts·M[0] + α_val·M[1] + WC` | `T(RAM, 4h·w + 4·row, teardown_ts, teardown_value)` |
| 1 | 1 | `init` (write side) | `α_addr·V[row] ×4 + WC` | `T(RAM, 4h·w + 4·row, 0, 0)` |

Both are `Linear` and carry no mask: every row of a window above 0 is a RAM word, since
`4h ≥ RAM_ORIGIN` at every menu height. The halving lists and outputs are §5.3's, with the same
names, relation numbers and addresses.

### 6.4 Rows

| row | `teardown_ts` | `teardown_value` | leaves |
| --- | --- | --- | --- |
| a word no cycle touched | 0 | 0 | both `T(RAM, 4h·w + 4y, 0, 0)`: they cancel |
| a word some cycle touched, by a read or a write (a read writes back what it read) | the last query's write timestamp | the value it wrote (0 for a word only read) | the final tuple read against the zero tuple written |

---

## 7. Observations

Facts this accounting turned up. None changes a circuit.

1. **The registry and the height menu disagree both ways.** `family_circuit` builds
   `ADD_SUB_LUI_AUIPC` and `JUMP_BRANCH_SLT` at every `n` from 19 to 30, and the two window
   circuits at every `n` from 0 to 30. A key's heights come from `VmConfig`, which
   `VmConfig::from_bytes` holds to `HEIGHT_MENU` (`n` = 16, 18, 20, 22). So the two execution
   circuits are reachable only at 20 and 22, which is `shard-proof.md` §8's and
   `jump-branch-slt.md` §2's `trace_vars ≥ 20`: the timestamp channel's 19 variables, made even
   for Mercury. The windows are reachable only at 16, 18, 20 and 22, never at `n ≤ 14`, where
   `V[ram_live]` is 0 on every row and `INIT_TEARDOWN` would mask its whole window. Conversely,
   neither execution circuit exists at the menu's 16 and 18, so a `VmConfig` placing one there
   decodes but no key for it loads (`VerifyingKey::check`).
2. **Eighteen of add/sub's 67 `M` and `W` columns are inert at S16.** The `arg1`, `arg2` and
   `ram` queries (`M[16..31]`, `W[3..6]`) are held absent on every row, but `frame_queries`
   fixes the frame, so they are committed, opened and carried by every shard. They are the
   I/O-binding stage's. Jump/branch/slt's four-query frame has no inert query.
3. **`rd_is_zero_boolean` (relation 81 in §3, 92 in §4) is implied** by the two gates before it
   with a boolean `rd_mask`: `rd_is_zero_at_nonzero` makes `rd_is_zero` 0 wherever
   `rd_addr ≠ 0`, and `rd_is_zero_inverse` makes it `rd_mask` wherever `rd_addr = 0`. It remains
   as S14's must-be-exact 7 lists it; `jump-branch-slt.md` §3.1 gives the same argument for the
   `is_zero` gadget, which carries no booleanity gate.
4. **No enforcing gate and no lookup reads `pc_addr`**; only the leaves `read_pc` and
   `write_pc` do (§3.3, §4.3). It is 0 because the memory argument has initial and final pc
   tuples at address 0 only (§3.10); the same holds for every family's frame. In jump/branch/slt
   `rd_read_value` is read by the leaf `read_rd` alone, too, and so is fixed by the memory
   argument alone (§4.10); add/sub's `exit_status` reads it there.
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
   `y < 2^14`, `V[ram_live]` is 0, so `teardown_ts` and `teardown_value` reach nothing (§5.4).
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

---

## 8. Maintaining this page

A stage that adds a circuit family, or changes one, updates this page in the same pull request
(`prompts/00-master.md`, implementation rule 12). A new family's entry is a section like §3 or
§4 and holds:

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
   accounting of §3.10 and §4.10.
9. **Its rows in §1.1, §1.2 and §1.3, its counts in §0.5, the challenge slots it reads in
   §0.4**, and any §7 observation the accounting turns up.

Appendix A's commands print every `n = 22` name, position and formula, and the `n = 22` counts
follow from them; the `n = 16` and `n = 20` counts and the §3.10 and §4.10 probes were read from
`family_circuit` and the suites' `honest_rows` directly and have no committed command
(Appendix A, last paragraph). The `checker dump` of the family's committed fixture is the machine view to check
the entry against.

---

## Appendix A. Reproducing

```text
cargo run -p checker -- dump crates/constraints/tests/vectors/add_sub.bin           # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/jump_branch_slt.bin   # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/image_window.bin      # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/zero_window.bin       # n = 22
for f in alu reg mem atomics; do
  cargo run -p checker -- dump crates/constraints/tests/vectors/memory_frame_$f.bin    # §2.2's four bare frames
done
cargo run -p checker -- laws crates/constraints/tests/vectors/add_sub.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/jump_branch_slt.bin
cargo test -p checker --test add_sub            # §3.9's rows against every gate and bound
cargo test -p checker --test jump_branch_slt    # §4.9's rows against every gate, bound and table
```

The dump prints the header, the committed columns, the virtual tables, every gate list with
each gate as a formula over addresses and its relation number and name, the flat relation list,
the scratch bijection, the output map, the lookups, the padding contract and the gate
catalogue. A relation number, an `L{k}[j]` and a node name in this page are the dump's, except
that §3.4, §3.7, §4.4 and §4.7 write a fraction node by its stem `x`: the dump names its two
columns `x_num` and `x_den`, defined by relations `define_x_num` and `define_x_den`. The halving
lists repeat one pattern, so the dump at `n = 22` gives every `n`: layers `L1`–`L5` do not
depend on `n`, nor do relations 0–183 of add/sub and 0–213 of jump/branch/slt, and the halving
lists follow §3.8's and §4.8's formulas.

The counts at `n = 16` and `n = 20` were read from `family_circuit` directly (its artifact's
`depth()`, layer widths, `relations`, `lookups` and `to_bytes()`), which has no CLI. The §3.10
probe is add/sub's `honest_rows` with one cell moved at a time, run through
`violated_relations` and `violated_lookups`; the §4.10 probe is the same over
jump/branch/slt's `honest_rows`, run also through that suite's own table check,
`violated_tables`.
