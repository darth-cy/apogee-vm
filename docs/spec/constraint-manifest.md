# The constraint-system manifest: every circuit, every column, every gate

> **What this page is.** An accounting document. The specs say *why*: `gkr.md` the engine,
> `memory.md` the memory argument, `lookup.md` the channels, `shard-proof.md` §8 the add/sub
> family, `jump-branch-slt.md` the jump/branch/slt family, `shift-bitwise.md` the shift and
> bitwise family, `mul-div.md` the M extension, `memory-ops.md` the three memory-op families.
> `delegation.md` the delegation ABI and the keccak-f family. This page says *what exists*: every
> circuit `constraints::family_circuit` returns; every committed and virtual column with its
> position, name, meaning and readers; every intermediate multilinear by layer and offset; and
> every gate with its formula. It gives columns and gates descriptive names and one-line
> purposes that the code does not carry, and puts beside each the identifiers that find it in
> the code: the `PolyAddress`, the artifact's own name for it, and the Rust constant or
> constructor that makes it.
>
> **Status: S26c.** All **eighteen** circuits are registered: `ADD_SUB_LUI_AUIPC`,
> `JUMP_BRANCH_SLT`, `SHIFT_BITWISE`, `MUL_DIV`, `MEM_WORD`, `MEM_SUBWORD`, `ATOMICS`,
> `INIT_TEARDOWN`, `ZERO_WINDOWS`, `KECCAK_F`, `POSEIDON2`, `FR_ARITH`, `PUBLIC_INPUT`,
> `PUBLIC_OUTPUT`, `ADVICE_WINDOWS`, S26's `MOD_MUL` (§18) and S26c's `SHA256_COMP` (§19) and
> `EC_ADD` (§20). `MOD_MUL` was the fourth delegation family and the first whose behaviour
> depends on a **selector** — one frame word names one of four fixed Ethereum fields,
> secp256k1's two and BN254's two, and the circuit supplies the modulus' limbs as literals. S26
> carried that modulus as a witnessed operand instead; S26b removed it, which is what let the
> circuit state `a < m` and `b < m` (`delegation.md` §10.2). The EVM's `MULMOD` takes an
> arbitrary modulus and is **not** served here.
>
> **S26c's two are the fifth and sixth delegation families, and they broke a rule this page
> stated in four places.** `EC_ADD` carries the `RANGE16` channel and `MOD_MUL` was re-shaped to
> carry it too, where "a delegation family carries no lookup channel" had been an invariant;
> `delegation.md` §10.3 is the amendment, and the half of the rule that survives is that a
> family at `2^8` can carry none and no family on this menu can carry `TIMESTAMP`. The
> consequences reach §0.4, §0.5, §1.1, §1.2, §1.3 and §12.1, and the reshape moved every number
> in §18. `EC_ADD` is also the first family whose row is **one third** of the operation it
> serves: a complete point addition is three invocations glued by the frame, not by a bus. Every execution family the decoder routes to has a
> circuit and a fill, and no `FamilyId` in `constants::family` is without one. S21 added the
> first family that is **invoked rather than decoded** (§12) and, with it, the `deleg` memory
> query — the mirror a delegation request makes — which changed `ADD_SUB_LUI_AUIPC`'s frame, its
> shape and every relation number in §3. S-IO added the three **RAM window** families that carry
> an execution's public input, its public output and the prover's advice (§15, §16, §17), and one
> new artifact constructor, `memory::value_window_artifact`, shared by two of them; it changed no
> existing circuit, added no enforcing gate anywhere, and drew no new challenge. **S-STREAM
> raised the two public families' pinned height from `2^8` to `2^12`** and moved the journal's
> window from `0x8400` to `0xC000` with it, which moves no relation either: a height reaches a
> window artifact only through the halving phase, so §15's and §16's layer counts, root
> relations and artifact byte lengths moved and nothing else in them did (§15.1).
>
> **The query table is seven entries, and §3 is rewritten over the narrower frame.** `read` (63)
> and `write` (64) are retired and their numbers burned (`ecall-abi.md` §4), so `arg1` and
> `arg2` — an ecall row's `a1` and `a2`, which only those two calls passed — became unreachable
> and were removed rather than kept as columns nothing can make nonzero; the table dropped from
> nine entries to seven and every other query kept its id (`memory.md` §2.1, §2.1 here).
> `ADD_SUB_LUI_AUIPC` lost a third query with them: its `ram` query was the ecall **transfer
> row's** alone, no instruction routed there touches memory, and an ecall is now exactly one
> cycle. Its frame is five queries, its layout is §3.3's throughout, three `mask = 0` gates went
> with the queries they refused, and the circuit is **five** row-wise lists deep again (§1.2,
> §1.3, §21 observation 2). **No other circuit changed**: the other six execution families' query
> lists are what they were, and their `M` and `W` indices are computed from their own `w`.
>
> **Descriptive, not normative.** Where this page and the code disagree, the registry is right
> and this page is wrong; where it and a spec disagree, the spec rules. The descriptive names
> are documentation only, as the artifact's own names are (`gkr.md` §4.2): no code reads either.
>
> **Kept current by rule.** A stage that adds or changes a circuit family updates its entry
> here in the same pull request (`prompts/00-master.md`, implementation rule 12). §20 is what an
> entry must hold.
>
> **Machine-derived.** Every count, position, name and formula below was read out of
> `family_circuit`'s artifacts, not off the source by eye. Appendix A's commands print the
> committed `n = 22` artifacts, against which every name, position and positional formula can be
> checked; the `n = 16`, `n = 18` and `n = 20` counts were read from `family_circuit` directly, and the
> §3.10 and §4.10 probes by a program over `family_circuit` and those two suites' `honest_rows`
> that is not committed. Each family's §x.9 shows a handful of the rows its suite holds to every
> gate, every range obligation and, from §4 on, both table channels in CI: nine of the sixteen
> in `crates/checker/tests/add_sub.rs`, nine of the 47 in `jump_branch_slt.rs`, nine of the 35
> in `shift_bitwise.rs` and nine of the 64 in `mul_div.rs`. §12 has no such table: a keccak row
> is 1,764 committed cells, so §12.9 is the chain of independent readings its suite carries
> instead — a whole permutation's 24 rows evaluated row-locally, and the round held to
> `emulator::keccak_round`, which is held to `tiny-keccak` twenty-four at a time.
> §7.9, §8.9 and §9.9 show instead
> rows of `guests/mem`'s own shards, as the three fills write them and as
> `crates/checker/tests/mem_fill.rs` holds them in CI, and name the hand-built catalogue each
> family's row suite carries beside them. §15, §16 and §17 have no such table either, for §10's
> and §11's reason — a window family has no enforcing gate, so there is no per-cell account to
> give — and what holds them in CI is `crates/checker/tests/public_values.rs`, which pins each
> family's shape, the layout of both public windows and of the advice region, and the equality
> of the prover's committed column with the verifier's own extension of the same bytes.
> §5.10, §6.10, §7.10, §8.10 and §9.10, unlike §3.10 and §4.10, are read from their suites'
> own committed tamper tables rather than from a probe.

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
| the word load/store circuit | `constraints::mem_word::{artifact, channels}`, `crates/constraints/src/mem_word.rs` |
| the sub-word circuit, and its width seam | `constraints::mem_subword::{artifact, channels, splice_gates}`, `crates/constraints/src/mem_subword.rs` |
| the atomics circuit | `constraints::atomics::{artifact, channels}`, `crates/constraints/src/atomics.rs` |
| the is-zero and comparison gadgets | `constraints::gadgets::{is_zero, comparison, comparison_equation}`, `crates/constraints/src/gadgets.rs` |
| the frame, the memory tuples, the **three** window circuits | `constraints::memory::{image_window_artifact, zero_window_artifact, value_window_artifact}`, `crates/constraints/src/memory.rs` |
| the fraction trees and their denominators | `constraints::lookup`, `crates/constraints/src/lookup.rs` |
| the layer assembly: reduction, halving, the names of inner nodes | `crates/constraints/src/build.rs`, `assemble` |
| a circuit, printed | `cargo run -p checker -- dump <artifact>` (Appendix A) |
| the columns' values | `trace::{build_memory_columns, build_frame_witness, build_init_teardown_columns, build_value_window_columns, build_multiplicities}` and `prover::family_fill`, `crates/prover/src/fill.rs`; the packed generic table, `program::lookup_tables::generic_table`; the two public windows' and the advice region's layouts, `verifier_core::public_io_words` and `trace::advice_word` |
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
  §10, §11 and §15–§17 write the bare word.
- **`n`** is the circuit's `trace_vars`: a shard has `h = 2^n` rows, and RAM window `w` starts
  at byte address `4h·w`.

### 0.3 What row `y` of a column is

Columns of one layer do not all index the same thing.

| column | row `y` is |
| --- | --- |
| an execution family's `M` and `W` columns, multiplicities excepted | the shard's `y`-th cycle of that family, in execution order; rows past the last are **padding**, every cell 0 in an honest fill |
| a multiplicity column | row `y` of its channel's **table**: how many of the shard's gated tuples equal that row, counted on the lowest row holding a repeated tuple (`lookup.md` §7) |
| a decoded-table `S` column | the halfword at pc `2y`; `MINUS_ONE` in every column where no instruction of the family starts (`crates/program/CLAUDE.md`) |
| a generic-table `S` column (`JUMP_BRANCH_SLT`'s, `SHIFT_BITWISE`'s and `MEM_SUBWORD`'s `S[7..10]`, `MUL_DIV`'s and `ATOMICS`' `S[6..9]`) | row `y` of the packed table (`lookup.md` §9): row 0 the `ZeroEntry`, all 0; rows 1 to `2^16` the AND byte table's `(AND_BASE + a + 1, b, a & b)`; rows `2^16 + 1` to `2^17` `U16GetSign`'s `(SIGN_BASE + h + 1, h >> 15, 0)`; rows `2^17 + 1` to `2^17 + 32` S18's `ShiftPowers`, `(SHIFT_BASE + s + 1, 2^s, 2^(31 − s))`; every later row 0. `AND_BASE = 0`, `SIGN_BASE = 256` and `SHIFT_BASE = SIGN_BASE + 2^16` are `constants::generic_table`'s, so the three key ranges are pairwise disjoint |
| `V[range19]`, `V[range16]` | the value `y mod 2^19`, `y mod 2^16` |
| a window family's `M` columns, `S[0]`, `V[row]`, `V[ram_live]` | the RAM word at byte address `4h·w + 4y`, `w` being the shard's window: 0 for `INIT_TEARDOWN`, the statement's `windows[i]` for `ZERO_WINDOWS`, the constants 32 and 33 for the two public families, and `advice_first_window(h) + i` for `ADVICE_WINDOWS` (§10, §11, §15, §16, §17) |

### 0.4 The challenges

`constants::challenge_slot`. A coefficient naming a slot reads the value below. `checker dump`
prints a slot by `challenge_slot::NAMES`, its constant in lower case (`mem_gamma`,
`mem_window_constant`, `lookup_g`, `lookup_beta_2`, `lookup_decoder_neutral`); the symbols are
this page's.

| slot | constant | symbol | value | set by | read by |
| --- | --- | --- | --- | --- | --- |
| 0 | `TOY` | — | — | — | S13's toy only |
| 1 | `MEM_GAMMA` | `γ_M` | drawn once per statement | G10 (`shard-proof.md` §2) | frame leaves; §12's 102 invocation leaves |
| 2 | `MEM_ALPHA_ADDR` | `α_addr` | drawn | G10 | frame leaves, every window tuple of all **five** window families; §12's 102 invocation leaves |
| 3 | `MEM_ALPHA_TS` | `α_ts` | drawn | G10 | frame leaves, window teardown tuples; §12's invocation leaves **but `write_anchor`**, whose timestamp is the literal 0 |
| 4 | `MEM_ALPHA_VAL` | `α_val` | drawn | G10 | frame leaves; window tuples carrying a value — every teardown tuple, `INIT_TEARDOWN`'s `α_val·S[0]` init tuple, and `PUBLIC_INPUT`'s and `ADVICE_WINDOWS`' `α_val·M[2]` init tuple, but **not** the init tuple of `ZERO_WINDOWS` or `PUBLIC_OUTPUT`, whose value is the literal 0; §12's invocation leaves **but `write_anchor`**, whose value is the literal 0 |
| 5 | `MEM_WINDOW_CONSTANT` | `WC` | derived per window shard: `γ_M + 2 + α_addr·4h·w` (2 is `address_space::RAM`) | `gkr_verify::window_challenges`, off the window `verifier_core::shard_challenges` names for the shard's family | window tuples |
| 6 | `LOOKUP_G` | `g` | drawn per shard | S4 (`shard-proof.md` §4) | every table denominator, and every lookup row denominator except `decode_row`'s (a pad denominator is the literal 1) |
| 7 | `LOOKUP_BETA` | `β` | drawn per shard, after `g` | S4 | every circuit's decoder denominators; and every generic denominator of the **five** circuits that read that channel — its table's, jump/branch/slt's two sign lookups', shift/bitwise's sign lookup, `shift_powers` and four `and_byte_j`, mul/div's two sign lookups, mem_subword's one sign lookup, atomics' two sign lookups and four `and_byte_j`. Not `MEM_WORD`'s: it reads no generic channel |
| 8 | `LOOKUP_BETA_2` | `β²` | derived: a power of `β` | `gkr_verify::insert_lookup_challenges` | every circuit's decoder denominators; the generic **table**'s denominator in all five that carry it; and of the generic lookups only those whose third tuple position is a column — shift/bitwise's `shift_powers` (`copow`) and its four `and_byte_j` (`byte_and_j`), and atomics' four `and_byte_j`. A sign lookup's third position is the constant 0 and adds no term |
| 9–11 | `LOOKUP_BETA_3` … `LOOKUP_BETA_5` | `β³` … `β⁵` | derived: powers of `β` | `insert_lookup_challenges` | every circuit's two decoder denominators |
| 12 | `LOOKUP_BETA_6` | `β⁶` | derived: a power of `β` | `insert_lookup_challenges` | the decoder denominators of add/sub, jump/branch/slt, shift/bitwise, mem_word and mem_subword, whose tuples are seven wide. **Not mul/div's and not atomics'**: each of those decoded tuples has no `imm` and is six wide (§6.1, §9.1) |
| 13 | `LOOKUP_DECODER_NEUTRAL` | `g_dec` | derived: `g − Σ_{j<W} β^j`, `W` the artifact's own decoder tuple width — 7 in add/sub, jump/branch/slt, shift/bitwise, mem_word and mem_subword, **6 in mul/div and atomics** | `insert_lookup_challenges` | `decode_row`'s denominator |

**Eight registered circuits read no lookup challenge at all** — no `g`, no `β`, no derived
power, no neutral: the five window families and `POSEIDON2`, `FR_ARITH` and `SHA256_COMP`, and
for opposite reasons. A window family has no witness to bound; a delegation family at `2^8` has
no table to bound one against, so every bound it makes is a bit decomposition. **`MOD_MUL` was
among them until S26c and `KECCAK_F` until S26d**, and neither is now (§18.1, §12.1).

**Three delegation families now read `g`.** S26c gave `MOD_MUL` and `EC_ADD` the `RANGE16`
channel at `2^16` (`docs/spec/delegation.md` §10.3) and S26d gave `KECCAK_F` both `RANGE16` and
`XOR8` (§10.4). A range channel's tuple is **one expression wide**, so a family carrying only
`RANGE16` reads slot **6** (`g`) and **no `β` slot at all** — `β⁰` is the literal 1 and not a
challenge, `β¹` upward belongs to tuples wider than one, and the decoder neutral is a table
channel's. So the count of circuits reading `g` is **ten**: the seven execution families,
`MOD_MUL`, `EC_ADD` and `KECCAK_F`.

**`KECCAK_F` is the only circuit that reads `β¹` and `β²` without reading `β³`.** Its `XOR8`
tuple is three wide, so the two slots are its 1,020 obligations' second and third positions and
nothing else in the artifact touches them; the decoder neutral is absent, this family having no
decoder channel. Its 24 pad leaves and its `write_anchor` leaf read no challenge past `γ_M`, and
the 385 enforcing gates read none at all.

### 0.5 The gate shapes

`GateDef` (`crates/constraints/src/lib.rs`, and `constraints::CATALOGUE`, the same seven rows);
`gkr_verify::eval_gate` evaluates every one. Counts are over one circuit at `n = 20`, except
`KECCAK_F`'s, which is at `n = 18`, and `MOD_MUL`'s and `EC_ADD`'s, which are at `n = 16`.

| tag | shape | `G` | list kind | used by |
| --- | --- | --- | --- | --- |
| 0 | `Linear { terms, constant }` | `Σ c_i·x_i + c_0` | row-wise | add/sub, 58: 43 leaves of list 0 (the **6** memory pads, the 15 leaf numerators, the 3 table numerators and 3 table denominators, the 16 pad-fraction columns), 5 degree-1 enforcing gates, 10 copies in lists 2–4; jump/branch/slt, 71: 54 leaves of list 0 (the 26 leaf numerators, 4 of tables and 22 of lookups, the 4 table denominators, the 24 pad-fraction columns), 3 degree-1 enforcing gates, 14 copies in lists 2–4; shift/bitwise, 108: 77 leaves of list 0 (the 43 leaf numerators, 4 of tables and 39 of lookups, the 4 table denominators, the 30 pad-fraction columns), 9 degree-1 enforcing gates, 22 copies in lists 2–5; mul/div, 108: 81 leaves of list 0 (the 31 leaf numerators, 4 of tables and 27 of lookups, the 4 table denominators, the 46 pad-fraction columns), 5 degree-1 enforcing gates, 22 copies in lists 2–5; mem_word, 54: 38 leaves of list 0 (the 4 memory pads, the 21 leaf numerators, 3 of tables and 18 of lookups, the 3 table denominators, the 10 pad-fraction columns), 6 degree-1 enforcing gates, 10 copies in lists 2–4; mem_subword, 100: 72 leaves of list 0 (the 4 memory pads, the 40 leaf numerators, the 4 table denominators, the 24 pad-fraction columns), 6 degree-1 enforcing gates, 22 copies in lists 2–5; atomics, 113: 86 leaves of list 0 (the **6** memory pads, the 40 leaf numerators, the 4 table denominators, the 36 pad-fraction columns), 9 degree-1 enforcing gates, 18 copies in lists 2–5; `ZERO_WINDOWS`, `PUBLIC_INPUT`, `PUBLIC_OUTPUT` and `ADVICE_WINDOWS`, 2 unmasked leaves each; **keccak, 1,673**: 1,354 in list 0 (24 pad leaves, the two tables' numerators and denominators, the 1,230 lookup numerators, and the 96 pad-fraction columns), 307 degree-1 enforcing gates, and 12 copies over lists 8–11, where the memory and `range16` trees are already at one node. It was 170,248 at S21, almost all of it state copies through 168 round layers; **`MOD_MUL`, 824**, **`SHA256_COMP`, 7,224** and **`EC_ADD`, 3,185**, each the sum of its leaves, its degree-1 enforcing gates and the copies its reduction lists carry (§18.1, §19.1, §20.1) |
| 1 | `Product { coeff, left, right }` | `c·x·y` | row-wise | add/sub, 37: the 14 row-wise product-tree nodes (lists 1–3) and the 23 row-wise fraction-node denominators (lists 1–4); jump/branch/slt, 40: the 6 row-wise product-tree nodes (lists 1–2) and the 34 row-wise fraction-node denominators (lists 1–4); shift/bitwise, 59: the 6 product-tree nodes (lists 1–2) and the 53 fraction-node denominators (lists 1–5); mul/div, 56: the 6 product-tree nodes and the 50 fraction-node denominators; mem_word, 37: the 14 row-wise product-tree nodes (lists 1–3) and the 23 fraction-node denominators (lists 1–4); mem_subword, 62: the 14 product-tree nodes and the 48 fraction-node denominators (lists 1–5); atomics, 68: the 14 product-tree nodes and the 54 fraction-node denominators; **keccak, 1,404**: the 126 product-tree nodes that reduce 128 memory leaves to 2 over lists 2–7, and the 1,278 row-wise fraction-node denominators of its two channels over lists 2–11 — 255 for `range16` and 1,023 for `xor8`. It had **no fraction node at all** at S21 and 38,400 `v = B'·B'` gates of chi's first step instead; one round a row moved every one of those into an `XOR8` obligation; **`MOD_MUL`, 573**, **`SHA256_COMP`, 9,278** — 9,216 of them the `x·y` helper of each three-way XOR bit, which is what buys the degree — and **`EC_ADD`, 2,301** |
| 2 | `MaskIntoIdentity { input, mask }` | `x·m + 1 − m` | row-wise | no registered circuit (`memory.md` §2.2 says why) |
| 3 | `AffineProduct { .. }` | `(Σ a_i·x_i + a_0)·(Σ b_j·y_j + b_0)` | row-wise | no registered circuit |
| 4 | `TreeProduct { input }` | `x(y,0)·x(y,1)` | halving | add/sub, 5 per halving list (100, `n = 20`); jump/branch/slt, 6 per halving list (120); shift/bitwise and mul/div, 6 per halving list (120 each); mem_word, 5 per halving list (100); mem_subword and atomics, 6 per halving list (120 each); **each of the five window circuits, 2 per halving list** — 40 at `n = 20`, 44 at `n = 22` and 24 at the two public families' pinned `n = 12`, where S-IO's `2^8` gave 16; **keccak, 4 per list (72 at `n = 18`)** — the two memory roots and the two channels' denominators; `SHA256_COMP`, 2 per list (16 at `n = 8`), for the same reason; **`MOD_MUL` and `EC_ADD`, 3 per list** (48 each at `n = 16`) — the two memory roots and the `RANGE16` tree's **denominator**, which is what a fourth output costs |
| 5 | `Quadratic { constant, linear, products }` | `c_0 + Σ a_i·x_i + Σ b_j·y_j·z_j` | row-wise | add/sub, 100: **10** memory leaves and 15 lookup row denominators (list 0), 52 degree-2 enforcing gates, and the 23 row-wise fraction-node numerators (lists 1–4); jump/branch/slt, 103: 8 memory leaves and 22 lookup row denominators (list 0), 39 degree-2 enforcing gates, and the 34 row-wise fraction-node numerators (lists 1–4); shift/bitwise, 139: 8 memory leaves and 39 lookup row denominators (list 0), 39 degree-2 enforcing gates, and the 53 fraction-node numerators (lists 1–5); mul/div, 134: 8 memory leaves and 27 lookup row denominators, 49 degree-2 enforcing gates, and the 50 fraction-node numerators; mem_word, 80: 12 memory leaves and 18 lookup row denominators (list 0), 27 degree-2 enforcing gates, and the 23 fraction-node numerators (lists 1–4); mem_subword, 143: 12 memory leaves and 36 lookup row denominators, 47 degree-2 enforcing gates, and the 48 fraction-node numerators (lists 1–5); atomics, 137: 10 memory leaves and 36 lookup row denominators, 37 degree-2 enforcing gates, and the 54 fraction-node numerators; `INIT_TEARDOWN`, 2 leaves — **the only window circuit with a `Quadratic` gate**, the other four being unmasked and degree 1 throughout; **keccak, 2,690**: 1,334 in list 0 (the 104 real memory leaves — 51 frame words and the anchor, a side — and the 1,230 lookup row denominators), 78 degree-2 enforcing gates (`live_boolean`, the 51 `addr_w`, the two frame-pointer checks and the 24 `round{r}_boolean`), and the 1,278 row-wise fraction-node numerators over lists 2–11. **There is no `gap_w{j}` gate**: the gap is four `RANGE16` obligations since S26d. It was 149,735 at S21; **`MOD_MUL`, 908**, **`SHA256_COMP`, 8,569** and **`EC_ADD`, 3,859**, each its real memory leaves, its lookup row denominators where it has any, its degree-2 enforcing gates and its fraction-node numerators |
| 6 | `TreeCross { left, right }` | `p(y,0)·q(y,1) + p(y,1)·q(y,0)` | halving | **`SHA256_COMP`, none: a circuit with no lookup channel has no fraction tree, and this shape is a fraction tree's alone** — and keccak was in that clause until S26d gave it two channels, where it is now **2 per halving list** (36 at `n = 18`), one per channel; **`MOD_MUL` and `EC_ADD`, 1 per halving list** (16 each at `n = 16`) — their one `RANGE16` tree's numerator, and the shape that makes a delegation family with a channel visible in this table at all (S26c); add/sub, 3 per halving list (60, `n = 20`); jump/branch/slt, 4 per halving list (80); shift/bitwise and mul/div, 4 per halving list (80 each); mem_word, 3 per halving list (60); mem_subword and atomics, 4 per halving list (80 each) |

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

**A window tuple** (`memory.md` §3.3, `public-values.md` §4); code: the private
`memory::window_tuple`, and the inline init tuple in `zero_window_artifact`:

```text
WC       = γ_M + 2 + α_addr·4h·w                                  one value per shard
teardown = WC + 4·α_addr·row + α_ts·teardown_ts + α_val·teardown_value
         = T(RAM, 4h·w + 4·row, teardown_ts, teardown_value)                                  every window family
init     = WC + 4·α_addr·row + α_val·S[0]           = T(RAM, 4·row, 0, init_value)            INIT_TEARDOWN, w = 0
init     = WC + 4·α_addr·row                        = T(RAM, 4h·w + 4·row, 0, 0)              ZERO_WINDOWS, PUBLIC_OUTPUT
init     = WC + 4·α_addr·row + α_val·M[2]           = T(RAM, 4h·w + 4·row, 0, init_value)     PUBLIC_INPUT, ADVICE_WINDOWS
```

The three init forms are the three window artifacts: the init value comes from a **setup**
column that program identity binds, from **nothing** — a literal 0 — or from a **memory** column
committed at G8 that one execution chose. `INIT_TEARDOWN` masks both of its leaves by
`V[ram_live]`, which makes them `Quadratic`; the other four carry no mask and are `Linear`.

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

| id | family | constructor | channels | `Some` for | default height | S16 (`guests/addsub`) | S17 (`guests/control`) | S18 (`guests/alu`) | S19 (`guests/mem`) | S21 (`guests/keccak-test`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | `ADD_SUB_LUI_AUIPC` | `add_sub::artifact(n)` | `add_sub::channels()`: `TIMESTAMP`, `RANGE16`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | one shard at `2^20` | one shard at `2^20` | one shard at `2^20` | one shard at `2^20` | one shard at `2^20` |
| 1 | `JUMP_BRANCH_SLT` | `jump_branch_slt::artifact(n)` | `jump_branch_slt::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | not in the config: the guest runs no instruction of the family | one shard at `2^20` | one shard at `2^20` | one shard at `2^20` | one shard at `2^20` |
| 2 | `SHIFT_BITWISE` | `shift_bitwise::artifact(n)` | `shift_bitwise::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | — | — | one shard at `2^20` | — | one shard at `2^20` |
| 3 | `MUL_DIV` | `mul_div::artifact(n)` | `mul_div::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^20` | — | — | one shard at `2^20` | — | one shard at `2^20` |
| 4 | `MEM_WORD` | `mem_word::artifact(n)` | `mem_word::channels()`: `TIMESTAMP`, `RANGE16`, `DECODER` — **no generic** | `19 ≤ n ≤ 30` | `2^22` | — | — | — | one shard at `2^20` | one shard at `2^20` |
| 5 | `MEM_SUBWORD` | `mem_subword::artifact(n)` | `mem_subword::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^22` | — | — | — | one shard at `2^20` | one shard at `2^20` |
| 6 | `ATOMICS` | `atomics::artifact(n)` | `atomics::channels()`: `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` | `19 ≤ n ≤ 30` | `2^20`, **raised from `2^16` at S19** (§9.1) | — | — | — | one shard at `2^20` | not in the config: the guest runs no atomic |
| 7 | `INIT_TEARDOWN` | `memory::image_window_artifact(n)` | none | `0 ≤ n ≤ 30` | `2^22` | one shard at `2^16` | one shard at `2^16` | one shard at `2^16` | one shard at `2^16` | one shard at `2^16` |
| 8 | `ZERO_WINDOWS` | `memory::zero_window_artifact(n)` | none | `0 ≤ n ≤ 30` | `2^22` | at `2^16`, with no shard: the guest touches no RAM | at `2^16`, with no shard | at `2^16`, with no shard | **one shard at `2^16`**, window 8191 | **one shard at `2^16`**, window 8191 |
| 9 | `KECCAK_F` | `keccak::artifact(n)` | `keccak::channels()`: **`RANGE16`** and **`XOR8`** | `16 ≤ n ≤ 30` | `2^18`, **raised from `2^16`** (§12.1) | — | — | — | — | **one shard at `2^18`**, 240 invocations — ten permutations of 24 rounds |
| 10 | `POSEIDON2` | `poseidon2::artifact(n)` | `poseidon2::channels()`: **none** | `0 ≤ n ≤ 30` | `2^8` | — | — | — | — | — |
| 11 | `FR_ARITH` | `fr_arith::artifact(n)` | `fr_arith::channels()`: **none** | `0 ≤ n ≤ 30` | `2^8` | — | — | — | — | — |
| 12 | `PUBLIC_INPUT` | `memory::value_window_artifact(n)` | none | `0 ≤ n ≤ 30` | `2^12`, **pinned**, raised from `2^8` at S-STREAM | one shard at `2^12`, window 2 | one shard at `2^12`, window 2 | one shard at `2^12`, window 2 | one shard at `2^12`, window 2 | one shard at `2^12`, window 2 |
| 13 | `PUBLIC_OUTPUT` | `memory::zero_window_artifact(n)` — `ZERO_WINDOWS`' artifact, byte for byte | none | `0 ≤ n ≤ 30` | `2^12`, **pinned**, ditto | one shard at `2^12`, window 3 | one shard at `2^12`, window 3 | one shard at `2^12`, window 3 | one shard at `2^12`, window 3 | one shard at `2^12`, window 3 |
| 14 | `ADVICE_WINDOWS` | `memory::value_window_artifact(n)` — `PUBLIC_INPUT`'s artifact at another height | none | `0 ≤ n ≤ 30` | the window height, `2^22` | in the config, with no shard: the guest is handed no advice | ditto | ditto | ditto | ditto |
| 15 | `MOD_MUL` | `mod_mul::artifact(n)` | `mod_mul::channels()`: **`RANGE16`** since S26c | `16 ≤ n ≤ 30`, the floor derived from the channel's `BITS` | `2^16` | — | — | — | — | — |
| 16 | `SHA256_COMP` | `sha256::artifact(n)` | `sha256::channels()`: **none** | `0 ≤ n ≤ 30` | `2^8` | — | — | — | — | — |
| 17 | `EC_ADD` | `ec_add::artifact(n)` | `ec_add::channels()`: **`RANGE16`** — the first a delegation family carried | `16 ≤ n ≤ 30`, ditto | `2^16` | — | — | — | — | — |

A verifying key carries only menu heights (`constants::family::HEIGHT_MENU`, **`2^8` to `2^22`
since S21, with `2^12` inserted at index 1 by S-STREAM**),
which `VmConfig::from_bytes` enforces, so `n` is 8, 12, 16, 18, 20 or 22 in any key — **8 since
S21**, the delegation height the menu opens with (§12.1), and **12 since S-STREAM**, the two
public families' pinned height and nothing else's (§15.1, §16.1); §21 observation 1 notes the
other values the registry accepts. The
prover pairs each circuit with a fill,
`prover::family_fill`: the private `fill::add_sub` for family 0, `fill::jump_branch_slt` for 1,
`fill::shift_bitwise` for 2, `fill::mul_div` for 3, `fill::mem_word` for 4, `fill::mem_subword`
for 5, `fill::atomics` for 6, `fill::window` for 7, 8 **and 13**, `fill::keccak_f` for 9,
`fill::poseidon2` for 10, `fill::fr_arith` for 11, `fill::public_input` for 12,
`fill::advice` for 14, since S26 `fill::mod_mul` for 15, and since S26c
`fill::sha256_comp` for 16 and `fill::ec_add` for 17.
**Every family is provable at S26c.**

**Two families' `Some` range is no longer the whole menu, and that is S26c.**
`MOD_MUL` and `EC_ADD` carry `RANGE16`, whose table needs sixteen variables, so
`family_circuit` returns `None` for either below `2^16` — and the guard that says so is
**derived** rather than listed: it reads each family's own `channels()` and takes the widest
range channel's `BITS`, testing the floor before the artifact is built. Until S26c it named
the seven execution families explicitly with a delegation family's arm below it, which worked
only while no delegation family had a channel (`docs/spec/lookup.md` §3,
`docs/spec/delegation.md` §10.3). The practical consequence is in `crates/prover/tests/common`:
`MOD_MUL_FIXTURE_VARS = 8` is gone, because that height no longer exists for the family.

**The last three rows are in every `VmConfig`, and two of them prove a shard in every
statement.** `program::decode_program` lists families 12, 13 and 14 unconditionally, under the
same presence rule that lists `INIT_TEARDOWN` and `ZERO_WINDOWS` — a **window family is in every
config**, and `decode_program`'s three rules stay three — and `verifier_core::window_height`,
inside `VmConfig::from_bytes`, refuses a config missing any of them or carrying either public
family at a height other than
`family::PUBLIC_WINDOW_HEIGHT`. `verifier_core::check_memory_windows` then requires
`shard_counts[PUBLIC_INPUT]` and `shard_counts[PUBLIC_OUTPUT]` to be exactly 1, because a count a
prover could drop is a way to publish nothing while having published something; a program that
ignores public values publishes an empty input and an empty journal and pays two `2^12`-row
shards for it. `ADVICE_WINDOWS` is the other way round: `trace::advice_region_words` is 0 for
empty advice, so `advice_window_count` is 0 and a program with no advice pays nothing
(`public-values.md` §4, §6). **The shard-count vectors quoted below are the pre-S-IO ones**, one
entry per family of the config as it then was; every statement in the repository gains three
entries, two of them 1.
The S16 statement is `crates/prover/tests/acceptance.rs`': its config lists families 0, 7 and 8, and its
shard counts are `[1, 1, 0]`. The S17 statement is `crates/prover/tests/control.rs`': its config
lists families 0, 1, 7 and 8, and its shard counts are `[1, 1, 1, 0]`. The S18 statement is
`crates/prover/tests/alu.rs`': its config is
`[(0, 2^20), (1, 2^20), (2, 2^20), (3, 2^20), (7, 2^16), (8, 2^16)]` and its shard counts are
`[1, 1, 1, 1, 1, 0]` — **five shards, one per family that runs**, `ZERO_WINDOWS` being the one
that does not, the guest touching no RAM. `guests/alu` runs 452 live `ADD_SUB_LUI_AUIPC` rows,
96 `JUMP_BRANCH_SLT`, 45 `SHIFT_BITWISE` and 54 `MUL_DIV`, and exits with 96, the number of
checks it made. The S19 statement is `crates/prover/tests/mem.rs`': its config is
`[(0, 2^20), (1, 2^20), (4, 2^20), (5, 2^20), (6, 2^20), (7, 2^16), (8, 2^16)]` and its shard
counts are `[1, 1, 1, 1, 1, 1, 1]` — **seven shards, one per family in the config**, and the
first statement of any stage with a `ZERO_WINDOWS` shard: `guests/mem` writes near the top of
RAM as well as inside window 0, so the derived window list is `[8191]` at `h = 2^16`.
`guests/mem` runs 180 live `ADD_SUB_LUI_AUIPC` rows, 56 `JUMP_BRANCH_SLT`, 53 `MEM_WORD`, 21
`MEM_SUBWORD` and 15 `ATOMICS`, and exits with 50, the number of checks it made.

The S21 statement is `crates/prover/tests/keccak.rs`': its config is
`[(0, 2^20), (1, 2^20), (2, 2^20), (3, 2^20), (4, 2^20), (5, 2^20), (7, 2^16), (8, 2^16),
(9, 2^18), (12, 2^8), (13, 2^8), (14, 2^22)]` and its shard counts give **eleven shards** —
S-IO's two public windows raised it from nine, and `ADVICE_WINDOWS` proves none, this guest
using no advice. It was the first statement of any stage that is not one family one height: ten
of the eleven are the shards a CPU family, a RAM window or a public window gets, and the
eleventh is a **delegation shard**, 262,144 rows of which **240** are invocations — ten
permutations of 24 rounds since S26d, where S21's were ten invocations of 256.
`guests/keccak-test` decodes into 1,429 live `ADD_SUB_LUI_AUIPC` rows, 845 `JUMP_BRANCH_SLT`,
252 `SHIFT_BITWISE`, 24 `MUL_DIV`, 1,555 `MEM_WORD` and 103 `MEM_SUBWORD`; it runs 193,156
cycles and exits with 6, the number of corpus entries it checked. **Those counts and that cycle
figure are S26d's and its debug ELF's**: S21's were 1,707 / 1,018 / 315 / 25 / 1,868 / 145 and
154,708 cycles, and the difference is the 24-round loop in `guest_sdk::keccak256`, which at
`opt-level = 0` is a real call with a stack frame per round. At `--release` the same corpus is
22,509 cycles in total (`docs/spec/delegation.md` §6.0). Its `KECCAK_F` entry is in the config because **its image declares the family**, not
because any pc claims it — the third presence rule, and the one S21 adds
(`delegation.md` §7). `guests/keccak-unused` decodes to exactly the same nine families and
proves **eight** shards: `plan_shards`' `ceil(0 / h)` is 0, so a declared family with no
invocation costs a config entry, a transcript group and no proof.

The S23 statement is `crates/prover/tests/recursion.rs`': `guests/recursion-ops` does ordinary
`field::Fr` arithmetic and calls `transcript::poseidon2_permute`, and the guest-target backends
inside those two crates route both through the delegations (`delegation.md` §13.4). Its config
holds families 0, 1, 2, 3, 4, 5, 7, 8, **10 and 11**, each delegation family at `2^8` with one
shard, and the guest exits 9 — the number of checks it made. It names no shim: the families are
in its `VmConfig` because `Fr`'s operators reach the declaration records, which is what makes
the seam a property of the binary rather than of the call site.
`guests/recursion-unused` declares the same two and proves zero shards of each.

The S-IO statement is `crates/prover/tests/public_io.rs`', and it is the first in the repository
whose public input and public output are **bound to the execution**. `guests/public-io` reads
eight public input bytes — a length and a position-dependent checksum — checksums that many
**advice** bytes against them, and commits the checksum and the advice's first eight bytes to
its **journal**; it issues no ecall but `EXIT`, which is what makes it provable, and every one
of those three accesses is an ordinary load or store. Its config holds families 0 through 5 at
`2^20`, `INIT_TEARDOWN`, `ZERO_WINDOWS` and `ADVICE_WINDOWS` at `2^16`, and `PUBLIC_INPUT` and
`PUBLIC_OUTPUT` at the pinned `2^12`; its shard counts for the three new families are **1, 1 and
1** — 64 bytes of advice is a 68-byte region, 17 words, one window. A guest that publishes nothing still binds that: two
empty byte strings, two public shards, and **no** advice window. No test asserts it since the
suite was abridged — the shard counts come from `window_height` and `shard_counts`, not from a
choice a prover makes.

### 1.2 Master table

The `lookups` column has one slot per channel of `constants::lookup_channel`, in channel order.
It gained a fifth at S26d, and **`KECCAK_F`'s row is the only one that fills it**: every other
circuit's parenthesis lists the four that existed before, a trailing `0` being left off rather
than written out twenty times.

```text
circuit             n  lists (row-wise + halving)  top     M      W   S  V  committed    inner  enforcing (d1/d2)  lookups (ts/r16/gen/dec/xor8)  outputs  relations        bytes
ADD_SUB_LUI_AUIPC  20  25 (5 + 20)                 L25    27     33   7  2         67      298  57 (5/52)          15 (10/4/0/1)                   8        355       68,130
ADD_SUB_LUI_AUIPC  22  27 (5 + 22)                 L27    27     33   7  2         67      314  57 (5/52)          15 (10/4/0/1)                   8        371       69,220
JUMP_BRANCH_SLT    20  25 (5 + 20)                 L25    21     44  10  2         75      372  42 (3/39)          22 (8/11/2/1)                  10        414       75,608
JUMP_BRANCH_SLT    22  27 (5 + 22)                 L27    21     44  10  2         75      392  42 (3/39)          22 (8/11/2/1)                  10        434       76,980
SHIFT_BITWISE      20  26 (6 + 20)                 L26    21     61  10  2         92      458  48 (9/39)          39 (8/24/6/1)                  10        506      101,465
SHIFT_BITWISE      22  28 (6 + 22)                 L28    21     61  10  2         92      478  48 (9/39)          39 (8/24/6/1)                  10        526      102,837
MUL_DIV            20  26 (6 + 20)                 L26    21     54   9  2         84      444  54 (5/49)          27 (8/16/2/1)                  10        498       92,640
MUL_DIV            22  28 (6 + 22)                 L28    21     54   9  2         84      464  54 (5/49)          27 (8/16/2/1)                  10        518       94,012
MEM_WORD           20  25 (5 + 20)                 L25    31     24   7  2         62      298  33 (6/27)          18 (12/5/0/1)                   8        331       59,293
MEM_WORD           22  27 (5 + 22)                 L27    31     24   7  2         62      314  33 (6/27)          18 (12/5/0/1)                   8        347       60,383
MEM_SUBWORD        20  26 (6 + 20)                 L26    31     55  10  2         96      452  53 (6/47)          36 (12/22/1/1)                 10        505       97,474
MEM_SUBWORD        22  28 (6 + 22)                 L28    31     55  10  2         96      472  53 (6/47)          36 (12/22/1/1)                 10        525       98,846
ATOMICS            20  26 (6 + 20)                 L26    26     54   9  2         89      472  46 (9/37)          36 (10/19/6/1)                 10        518      101,593
ATOMICS            22  28 (6 + 22)                 L28    26     54   9  2         89      492  46 (9/37)          36 (10/19/6/1)                 10        538      102,965
INIT_TEARDOWN      16  17 (1 + 16)                 L17     2      0   1  2          3       34  0                  0                               2         34        3,259
INIT_TEARDOWN      22  23 (1 + 22)                 L23     2      0   1  2          3       46  0                  0                               2         46        3,907
ZERO_WINDOWS       16  17 (1 + 16)                 L17     2      0   0  1          2       34  0                  0                               2         34        2,770
ZERO_WINDOWS       22  23 (1 + 22)                 L23     2      0   0  1          2       46  0                  0                               2         46        3,418
KECCAK_F           16  27 (11 + 16)                 L27   208  1,556   0  4      1,764    5,478  385 (307/78)       1,230 (0/210/0/0/1,020)         6      5,863    1,899,700
KECCAK_F           18  29 (11 + 18)                 L29   208  1,556   0  4      1,764    5,490  385 (307/78)       1,230 (0/210/0/0/1,020)         6      5,875    1,900,468
POSEIDON2           8  201 (193 + 8)               L201  100  4,092   0  0      4,192    2,020  4,248 (54/4,194)   0                               2      6,268    2,056,361
FR_ARITH            8   14 (6 + 8)                  L14   104  2,576   0  0      2,680      142  2,701 (46/2,655)   0                               2      2,843    1,063,214
PUBLIC_INPUT       12  13 (1 + 12)                 L13     3      0   0  1          3       26  0                  0                               2         26        2,455
PUBLIC_OUTPUT      12  13 (1 + 12)                 L13     2      0   0  1          2       26  0                  0                               2         26        2,338
ADVICE_WINDOWS     16  17 (1 + 16)                 L17     3      0   0  1          3       34  0                  0                               2         34        2,887
ADVICE_WINDOWS     22  23 (1 + 22)                 L23     3      0   0  1          3       46  0                  0                               2         46        3,535
MOD_MUL            16   26 (10 + 16)               L26   104    221   0  1        325    2,244  125 (54/71)        274 (0/274/0/0)                 4      2,369      550,391
SHA256_COMP         8   14 (6 + 8)                 L14   100  8,116   0  0      8,216   16,688  8,399 (232/8,167)  0                               2     25,087   10,895,760
EC_ADD             16   28 (12 + 16)               L28   392  1,028   0  1      1,420    8,772  637 (131/506)      1,110 (0/1,110/0/0)             4      9,409    2,350,670
```

`committed` is layer 0's width, `M + W + S`. `inner` is the width of every layer above 0,
summed: the multilinears that are never committed, one producing gate each. `relations` is
producing plus enforcing gates. `bytes` is `to_bytes().len()`. The `n = 22` rows are the
committed fixtures: `crates/constraints/tests/vectors/add_sub.bin` (SHA-256 `33d0ce5b…956d7f67`),
`jump_branch_slt.bin` (`99094d63…742c1305`), `shift_bitwise.bin` (`b0af9325…65e3fd4c`),
`mul_div.bin` (`98f9f3bd…a30c357a`), `mem_word.bin` (`2c8d94ca…f7ca4500`), `mem_subword.bin`
(`2c423eb1…9f596181`), `atomics.bin` (`ae58b1ca…643d3108`), `image_window.bin`
(`39a8655d…2df67ecc`) and `zero_window.bin` (`f08dde67…aa51ec1c`), each pinned by its suite.
**`zero_window.bin` is `PUBLIC_OUTPUT`'s circuit too**, at `n = 22` rather than at the pinned
`n = 12`: the two families take one constructor and `family_circuit(13, n)` and
`family_circuit(8, n)` agree byte for byte at every `n`. `value_window_artifact` has no committed
fixture of its own; §15, §16 and §17 were read from `family_circuit(12, 12)`,
`family_circuit(13, 12)` and `family_circuit(14, 22)` and from a `checker dump` of their bytes
(Appendix A).

**The two public families are the smallest circuits in the registry**, and by a wide margin:
`PUBLIC_OUTPUT` at its pinned `n = 12` is 2,338 bytes and two gates of list 0 and `PUBLIC_INPUT`
2,455 — 1,910 and 2,027 at S-IO's `2^8`, the four halving lists S-STREAM added costing each
artifact the same 428 bytes — against `atomics.bin`'s 102,965 on 132 leaves and `KECCAK_F`'s
1.9 MB. The whole public-values and advice mechanism costs 8 committed columns across three
families — three, two and three — and not one enforcing gate, lookup or channel.
**`atomics.bin` is the largest circuit artifact committed as bytes**, 102,965 of them to
`shift_bitwise.bin`'s 102,837, on 132 leaves to its 124. **`POSEIDON2` is the largest circuit
and none of the six delegation families is committed as bytes**: `POSEIDON2`'s artifact is
2,056,361 of them and `KECCAK_F`'s 1,900,468, so what
`crates/constraints/tests/vectors/{keccak,poseidon2,fr_arith,mod_mul,sha256,ec_add}.txt` hold is
each artifact's SHA-256 beside its shape line above, written by
`cargo run -p kat-gen -- delegation` and diffed by CI like every other fixture. **`KECCAK_F`'s
was 100,254,040 bytes until S26d** — 974 times `atomics.bin`, which is why the digest convention
exists at all — and one round a row took it to 1.9 MB, small enough that
`checker dump` of it at `n = 16` is 20,333 readable lines. Each is at its family's **default**
height: `2^8` for three, `2^18` for `KECCAK_F` — the second of its two rows above, and the one
`keccak.txt` pins — `2^16` for `MOD_MUL` and `EC_ADD`, and `2^12` for `PUBLIC_INPUT` and
`PUBLIC_OUTPUT`.

**`ADD_SUB_LUI_AUIPC` moved when the POSIX layer went, and by more than three columns.** `read`
(63) and `write` (64) are retired and their numbers burned, so the `arg1` and `arg2` queries
went with them and this family's `ram` query — the ecall transfer row's alone — went with the
transfer row (`ecall-abi.md` §4). Its frame is **five** queries where S21 made it eight: 15 `M`
columns, three gap chunks, three mask booleanity gates, two write-backs and the three
`arg1_mask_rule`, `arg2_mask_rule` and `ram_mask_rule` gates are gone, each of the last three
having said `mask = 0` about a query the family could not make. Five is not a power of two, so
**its two product trees pay three pad leaves a side** where eight paid none; and ten gap
obligations with the table fraction is eleven leaves, which fits a 16-leaf tree, so the
timestamp tree stopped setting the depth and the circuit went from six row-wise lists back to
**five**. Depth, every layer width, every relation number, both fixture digests and the proof's
length moved with it, and §3 is rewritten over the narrowed artifact. Its layer widths are now
`MEM_WORD`'s exactly, `L1 … L5` of 68, 34, 18, 10 and 8. No other circuit in the repository
changed.

**Four of the seven execution circuits are six row-wise lists deep, and one tree apiece is why.**
Shift/bitwise's `range16` tree carries 24 obligations beside its table fraction, 25 leaves
padding to 32 (§5.6), and mul/div's carries 16, which with its table fraction is 17 leaves and
pads to 32 too (§6.6); mem_subword's carries 22 and atomics' 19. Everything else about their
shape follows: one more row-wise level, one more gate list, one more transition in every proof.
**Add/sub was the fifth and is not any more**: its timestamp tree carried 16 obligations from
S21 until the POSIX layer went, which with its table fraction was 17 leaves and padded to 32 for
exactly mul/div's reason; at ten obligations it is eleven leaves in a 16-leaf tree and the level
came back off (§3.6, §21 observation 20).

**Two of S19's three are six lists deep for the same reason, and `MEM_WORD` is five.**
Mem_subword's `range16` tree carries 22 obligations and atomics' 19, so each pads to 32 (§8.6,
§9.6); mem_word's carries 5, which with its table fraction is 6 leaves in an 8-leaf tree, and
its deepest tree is the timestamp's 16 — so it is 25 lists deep at `n = 20`, which is §3's and
§4's depth too. **`ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT` and `MEM_WORD` are the three execution
circuits five row-wise lists deep**, and for one reason: none of their trees needs more than 16
leaves. Jump/branch/slt's four queries give four gap pairs and mem_word's six give six, so their
timestamp trees hold 8 and 12 obligations beside a table fraction; add/sub's five give ten.

The proof a shard of each carries, at `n = 20`, by `shard-proof.md` §9's layout over the
circuit's own shape — the formula `crates/prover/tests/mem.rs`' `proof_bytes` computes and
`crates/prover/tests/alu.rs` and `mem.rs` each assert against `ShardProof::to_bytes().len()`:

```text
circuit             n   proof bytes
ADD_SUB_LUI_AUIPC  20        57,004
JUMP_BRANCH_SLT    20        61,612
SHIFT_BITWISE      20        68,564
MUL_DIV            20        67,412
MEM_WORD           20        56,268
MEM_SUBWORD        20        68,116
ATOMICS            20        68,468
KECCAK_F           18       381,100
```

A proof's length is one transition per gate list, `128` bytes per sumcheck round and `32` per
final claim, plus `64` per **witness** commitment and `32` per output. **`MEM_WORD`'s is the
shortest of the seven execution families and add/sub's is the second**, and the gap between them
is 736 bytes: the two circuits have the same depth, the same `L1` and the same inner widths
since the frame narrowed, so all of it is add/sub's nine extra witness commitments (576) and its
five-column wider base layer (160). `MEM_SUBWORD`'s and `ATOMICS`' are the longest of the seven,
on a wider base layer, a wider `L1` and the extra transition their `range16` trees buy.

**`KECCAK_F`'s proof was 11,880,012 bytes until S26d and is 381,100 at `2^18`**, and the
comparison is the clearest single number this page carries. S21's row was a whole permutation, so
the shard was 3,764 witness commitments and 358,540 final claims — 11,473,280 bytes of claims
alone — for **256 permutations**. One round a row at `2^18` is 1,556 commitments and 7,356
claims for **10,922 permutations**: 34.9 proof bytes a permutation against 46,406, a factor of
**1,330** (`docs/spec/delegation.md` §6.0). That 381,100 is **derived and not measured**:
`proof_bytes` is a closed form over the artifact and it reproduces S26d's measured 373,276 at
`2^16` exactly, which is what licenses reading it forward. It is still the largest delegation
proof of the six, and it is now of the same order as a CPU shard's rather than 173 times one.

### 1.3 Shape formulas

`build::assemble` builds **every** circuit the same way since S26d, `KECCAK_F` included. Let `R`
be the largest `log2` leaf count among its trees; then the depth is `N = 1 + R + n`. Gate list 0
writes the leaves, lists `1 … R` reduce row-wise, and lists `R + 1 … R + n` halve. S21's keccak
was the one exception — a layered circuit with 24 round blocks, assembled by `keccak.rs`'s own
`Assembly` — and one round a row removed the exception along with the blocks: its `R` is 10, the
`XOR8` tree's depth, and `29 = 1 + 10 + 18`.

- **add/sub.** Five trees: `read` and `write` with 8 leaves each — five queries and **three**
  pads a side — `timestamp` with 16 fractions, `range16` with 8, `decoder` with 2; so `R = 4`,
  the timestamp tree setting it. Layers `L1 … L5` are 68, 34, 18, 10 and 8 wide, and
  `L6 … L{n+5}` 8 each: `inner = 138 + 8n`, which is mem_word's formula exactly. Relations
  0–67 are list 0's leaves, 68–124 its enforcing gates, 125–158 list 1, 159–176 list 2,
  177–186 list 3, 187–194 list 4, and halving list `k` (`5 ≤ k ≤ n + 4`) holds
  `195 + 8(k − 5)` to `202 + 8(k − 5)`. The roots are relations `187 + 8n` to `194 + 8n`:
  347–354 at `n = 20`, 363–370 at `n = 22`. **All of this moved when the POSIX layer went**,
  as all of it had moved at S21 when the frame took an eighth query; the S21 numbers are in
  `docs/handoff/S21-keccak256.md`, and §3.1 has the before-and-after.
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
- **mem_word.** Five trees: `read` and `write` with 8 leaves each, `timestamp` with 16
  fractions, `range16` with 8, `decoder` with 2; so `R = 4`, the timestamp tree setting it.
  Layers `L1 … L5` are 68, 34, 18, 10 and 8 wide, and `L6 … L{n+5}` 8 each: `inner = 138 + 8n`,
  which is add/sub's formula exactly. Relations 0–67 are list 0's leaves, 68–100 its enforcing
  gates, 101–134 list 1, 135–152 list 2, 153–162 list 3, 163–170 list 4, and halving list `k`
  (`5 ≤ k ≤ n + 4`) holds `171 + 8(k − 5)` to `178 + 8(k − 5)`. The roots are relations
  `163 + 8n` to `170 + 8n`: 323–330 at `n = 20`, 339–346 at `n = 22`.
- **mem_subword.** Six trees: `read` and `write` with 8 leaves each, `timestamp` with 16
  fractions, `range16` with **32**, `generic` with 2, `decoder` with 2; so `R = 5`, the
  32-fraction `range16` tree setting it alone — 23 leaves is seven past 16. Layers `L1 … L6`
  are 120, 60, 32, 18, 12 and 10 wide, and `L7 … L{n+6}` 10 each: `inner = 252 + 10n`.
  Relations 0–119 are list 0's leaves, 120–172 its enforcing gates, 173–232 list 1, 233–264
  list 2, 265–282 list 3, 283–294 list 4, 295–304 list 5, and halving list `k`
  (`6 ≤ k ≤ n + 5`) holds `305 + 10(k − 6)` to `314 + 10(k − 6)`. The roots are relations
  `295 + 10n` to `304 + 10n`: 495–504 at `n = 20`, 515–524 at `n = 22`.
- **atomics.** Six trees: `read` and `write` with 8 leaves each — five queries and **three**
  pads a side — `timestamp` with 16 fractions, `range16` with **32**, `generic` with 8,
  `decoder` with 2; so `R = 5`, again the `range16` tree alone. Layers `L1 … L6` are 132, 66,
  34, 18, 12 and 10 wide, and `L7 … L{n+6}` 10 each: `inner = 272 + 10n`. Relations 0–131 are
  list 0's leaves, 132–177 its enforcing gates, 178–243 list 1, 244–277 list 2, 278–295 list 3,
  296–307 list 4, 308–317 list 5, and halving list `k` (`6 ≤ k ≤ n + 5`) holds
  `318 + 10(k − 6)` to `327 + 10(k − 6)`. The roots are relations `308 + 10n` to `317 + 10n`:
  508–517 at `n = 20`, 528–537 at `n = 22`.
- **The five windows.** `INIT_TEARDOWN`, `ZERO_WINDOWS`, `PUBLIC_INPUT`, `PUBLIC_OUTPUT` and
  `ADVICE_WINDOWS` share one shape. Two trees of one leaf each, so `R = 0`: `L1 … L{n+1}` are 2
  wide and `inner = 2n + 2`. Relation 0 is the teardown leaf, 1 the init leaf, and halving list
  `k` (`1 ≤ k ≤ n`) holds `2k` (read side) and `2k + 1` (write side). The roots are relations
  `2n` and `2n + 1`: 24 and 25 at the two public families' `n = 12`, 44 and 45 at
  `ADVICE_WINDOWS`' default `n = 22`. The three constructors differ only in the base layer and
  the init leaf — `S[0]`, nothing, or `M[2]` (§0.6) — so every relation number, node name and
  layer width above `L1` is the same in all five.
- **keccak.** Two trees, `read` and `write`, of 64 leaves each — 50 frame words, the anchor, and
  13 pads a side — and no fraction tree at all, the family having no channel. `R` is 6, but the
  depth is **not** `1 + R + n`: the permutation's 24 blocks of 7 sub-layers stack above gate list
  0 and the trees reduce underneath them, so `depth = 169 + n` — 168 round layers, the output
  list, and `n` halving lists — and the trees reach their two roots at `L7`, 162 layers before
  they are needed. `L1` is 2,419 wide (128 tree + 51 carried + 2,240 permutation); `L2 … L7` are
  2,035, 2,003, 1,987, 1,659, 3,255 and 1,653; `L{7r+1} … L{7r+7}` for `1 ≤ r ≤ 23` are 2,293,
  1,973, 1,973, 1,973, 1,653, 3,253 and 1,653, **14,771 a block**; `L169` is 2 and so is every
  halving layer. `inner = 354,746 + 2n`. Relations 0–2,418 are list 0's producing gates,
  2,419–6,131 its 3,713 enforcing gates, 6,132–358,456 lists 1–167, 358,457–358,458 the output
  list's two root copies and 358,459–358,508 its 50 `output_w` gates, and halving list `169 + s`
  (`0 ≤ s < n`) holds `358,509 + 2s` and `358,510 + 2s`. The roots are relations `358,507 + 2n`
  and `358,508 + 2n`: 358,523 and 358,524 at `n = 8`. Every one of those numbers is independent
  of `n` but the last two, because only the halving phase depends on it.

- **mod_mul.** Three trees: `read` and `write` with 32 leaves each — 25 frame words, the
  anchor, and **6 pads a side** — and `range16` with **512** fractions, 274 obligations and a
  table fraction padding to it; so `R = 9`, the `range16` tree setting it alone, a 32-leaf
  product tree being 5 deep. Layers `L1 … L10` are 1,088, 544, 272, 136, 68, 34, 18, 10, 6 and
  4 wide, and `L11 … L{n+10}` 4 each: `inner = 2,180 + 4n`. Relations 0–1,087 are list 0's
  leaves, 1,088–1,212 its 125 enforcing gates, 1,213–1,756 list 1, 1,757–2,028 list 2,
  2,029–2,164 list 3, 2,165–2,232 list 4, 2,233–2,266 list 5, 2,267–2,284 list 6, 2,285–2,294
  list 7, 2,295–2,300 list 8, 2,301–2,304 list 9, and halving list `k` (`10 ≤ k ≤ n + 9`) holds
  `2,305 + 4(k − 10)` to `2,308 + 4(k − 10)`. The roots are relations `2,301 + 4n` to
  `2,304 + 4n`: 2,365–2,368 at `n = 16`. **Until S26c this circuit was six row-wise lists and
  158 inner columns**: the channel's fraction tree is four levels deeper than the product trees
  it sits beside, which is what moved every number here (§18.1, §18.6).

- **sha256.** Two trees, `read` and `write`, of 32 leaves each — 24 frame words, the anchor and
  **7 pads** a side — and no fraction tree, the family having no channel. `R = 5`, and the depth
  **is** `1 + R + n = 6 + n`, but not because `build::assemble` built it: the circuit is
  `delegation::Assembly`'s and has two lists of work above gate list 0, which ride **inside** the
  tree's own five reduction lists and cost no depth at all (§19.8). `L1 … L6` are 15,857, 785,
  16, 8, 4 and 2 wide, and `L7 … L{n+6}` 2 each: `inner = 16,672 + 2n`. Relations 0–15,856 are
  list 0's producing gates (64 leaves, 465 carried scalars, 6,112 carried bits, 9,216 helpers),
  15,857–24,071 its 8,215 enforcing gates, 24,072–24,856 list 1's 785 producing gates,
  24,857–24,872 list 2's 16 tree gates, 24,873–25,056 its 184 enforcing gates, 25,057–25,064 list
  3, 25,065–25,068 list 4, 25,069–25,070 list 5, and halving list `6 + s` (`0 ≤ s < n`) holds
  `25,071 + 2s` and `25,072 + 2s`. The roots are relations `25,069 + 2n` and `25,070 + 2n`:
  25,085 and 25,086 at `n = 8`. Every number but the last two is independent of `n`.

- **ec_add.** Three trees: `read` and `write` with 128 leaves each — 97 frame words, the
  anchor, and **30 pads a side** — and `range16` with **2,048** fractions, 1,110 obligations
  and a table fraction padding to it; so `R = 11`, the `range16` tree setting it alone.
  Layers `L1 … L12` are 4,352, 2,176, 1,088, 544, 272, 136, 68, 34, 18, 10, 6 and 4 wide, and
  `L13 … L{n+12}` 4 each: `inner = 8,708 + 4n`. Relations 0–4,351 are list 0's leaves,
  4,352–4,988 its enforcing gates, 4,989–7,164 list 1, 7,165–8,252 list 2, 8,253–8,796 list 3,
  8,797–9,068 list 4, 9,069–9,204 list 5, 9,205–9,272 list 6, 9,273–9,306 list 7,
  9,307–9,324 list 8, 9,325–9,334 list 9, 9,335–9,340 list 10, 9,341–9,344 list 11, and
  halving list `k` (`12 ≤ k ≤ n + 11`) holds `9,345 + 4(k − 12)` to `9,348 + 4(k − 12)`. The
  roots are relations `9,341 + 4n` to `9,344 + 4n`: 9,405–9,408 at `n = 16`.

---

## 2. The memory frame every execution family carries

`memory::frame_artifact` and `frame_with_channels_artifact` build it; `memory.md` §2 is its
spec. It is the first part of every execution family's circuit, so its columns come first in
`M` and `W`.

### 2.1 The query table and the layout

The **seven** queries (`memory::{PC, RS1, RS2, LOAD, RAM, RD, DELEG}`, with
`FRAME_NAMES`, `FRAME_SPACE`, `FRAME_DELTA`) — the pc query and then
`execution-trace.md` §7's six roles in their frozen order:

| id | constant | `<q>` | `AS` | `Δ` | what it is |
| --- | --- | --- | --- | --- | --- |
| 0 | `PC` | `pc` | PC = 3 | 0 | reads the pc, writes the next pc |
| 1 | `RS1` | `rs1` | REG = 1 | 1 | first operand register; an ecall row's `a7` |
| 2 | `RS2` | `rs2` | REG | 2 | second operand register; an ecall row's `a0` |
| 3 | `LOAD` | `load` | RAM = 2 | 2 | a load's word |
| 4 | `RAM` | `ram` | RAM | 3 | a store's or an atomic's word |
| 5 | `RD` | `rd` | REG | 3 | the destination register; an ecall row's `a0` result |
| 6 | `DELEG` | `deleg` | **not a literal**: `FRAME_SPACE[6]` is 0 and the row's `deleg_space` column carries the tag | 3 | **S21**: a delegation request's mirror query, whose address is the frame base the request read from `a0` (`delegation.md` §5.1) |

**It was nine, and the two that went were `ARG1` and `ARG2`.** They were an ecall row's `a1` and
`a2` at `Δ = 2`, which only `read` (63) and `write` (64) ever passed; those calls are retired
and their numbers burned, so both roles became unreachable and were removed rather than left as
columns nothing can make nonzero (`ecall-abi.md` §4, `memory.md` §2.1). **Every remaining query
kept its id**, `DELEG`'s 6 included: the two that went were the last two of slot 2, nothing
above them is addressed by id, and a family's columns are addressed by *slot* anyway.
`trace::Row::present` is a `u8` with one bit per role, so it now has two spare bits; a seventh
role is still a schema change (`execution-trace.md` §7). `RAM` is no longer an ecall transfer's
word either — there are no transfer cycles — and it is a store's or an atomic's alone.

`DELEG`'s address space is the delegation family's, which is why a request's mirror tuple can
only be answered by an invocation of that family and by nothing in RAM or a register (§12.4).

**Which delegation family is a property of the row, not of the table, since S23.** One `deleg`
query serves all four registered types — a second would need a seventh role — so its `AS` term
is not a literal on the mask but one more `M` column, `deleg_space` at `M[1 + 5w]`, which the
family pins to its type selectors with a degree-1 gate (`delegation.md` §5.1). A leaf may read
no `W` column, which is why the tag cannot ride the selectors directly.
`FRAME_SPACE[DELEG]` is therefore **0**, a value no real tag takes, so a reader that compares it
against an event's space matches nothing and reaches a loud panic rather than a silent skip;
`memory::frame_query_takes` is the routing rule, and a frame holding `deleg` carries the extra
column while one without it does not.

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
| `M[1 + 5w]` | `deleg_space` | `memory::deleg_space(w)` | requested delegation type | that type's address-space tag on a request row, 0 elsewhere; **only on a frame holding `deleg`** |
| `W[s]` | `<q>_gap_hi` | `memory::gap_hi(s)` | `<q>` gap, high chunk | `gap >> 19`, with `gap = 4·cycle + Δ_q − read_ts − 1` |
| `W[w]` | `rd_inv` | `memory::rd_inv(w)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 where `rd_addr = 0` |
| `W[w + 1]` | `rd_is_zero` | `memory::rd_is_zero(w)` | rd-is-x0 flag | 1 exactly on a live `rd` query at address 0 |
| `W[w + 2]` | `rd_selected` | `memory::rd_selected(w)` | Result before the x0 rule | what the instruction computes for `rd`, `x0` writes included, as a family's fill writes it (`fill::add_sub`, §3.3; `fill::jump_branch_slt`, §4.3); S14's `trace::build_frame_witness` writes `rd`'s write value where `rd_addr ≠ 0` and 0 elsewhere, and the frame's gates leave it free where `rd_is_zero = 1` |

Every family has an `rd` query, so every frame has the three x0 columns.

### 2.2 Each execution family's frame

| family | queries, in slot order | `w` | `M` | frame `W` | leaves a side | frame gates | gap obligations | circuit | frame fixture (`n = 22`) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 `ADD_SUB_LUI_AUIPC` | pc rs1 rs2 rd **deleg** | 5 | 27 | 8 | 8 | 11 | 10 | §3 | `memory_frame_alu.bin` |
| 1 `JUMP_BRANCH_SLT` | pc rs1 rs2 rd | 4 | 21 | 7 | 4 | 10 | 8 | §4 | `memory_frame_reg.bin` |
| 2 `SHIFT_BITWISE` | pc rs1 rs2 rd | 4 | 21 | 7 | 4 | 10 | 8 | §5 | `memory_frame_reg.bin` |
| 3 `MUL_DIV` | pc rs1 rs2 rd | 4 | 21 | 7 | 4 | 10 | 8 | §6 | `memory_frame_reg.bin` |
| 4 `MEM_WORD` | pc rs1 rs2 load ram rd | 6 | 31 | 9 | 8 | 13 | 12 | §7 | `memory_frame_mem.bin` |
| 5 `MEM_SUBWORD` | pc rs1 rs2 load ram rd | 6 | 31 | 9 | 8 | 13 | 12 | §8 | `memory_frame_mem.bin` |
| 6 `ATOMICS` | pc rs1 rs2 ram rd | 5 | 26 | 8 | 8 | 11 | 10 | §9 | `memory_frame_atomics.bin` |

The frame gates are `w` mask booleanity gates, one write-back per read-only query the frame
holds — `memory::FRAME_READ_ONLY` is `rs1`, `rs2` and `load`, so it is 3 for the two memory
families and 2 for every other — and the four x0 gates. **`deleg` is not read-only** and carries
no write-back: a mirror query reads the zero tuple an invocation wrote at timestamp 0 and writes
a value of its own, which is what makes the pairing 1:1 (`delegation.md` §5.3).
`ADD_SUB_LUI_AUIPC` is the only family that holds it. **The three four-query families are the
only ones whose leaves a side are exactly their queries**; the two memory families pay two pads
a side, and `ADD_SUB_LUI_AUIPC` and `ATOMICS` three (`memory.md` §2.3).

The same layout by index. `M[a..b]` is half-open, and a query's five columns are always in the
order mask, addr, read_ts, read_value, write_value:

| columns | ALU (0) | REG (1, 2, 3) | MEM (4, 5) | ATOMICS (6) |
| --- | --- | --- | --- | --- |
| `cycle` | `M[0]` | `M[0]` | `M[0]` | `M[0]` |
| `pc_*` | `M[1..6]` | `M[1..6]` | `M[1..6]` | `M[1..6]` |
| `rs1_*` | `M[6..11]` | `M[6..11]` | `M[6..11]` | `M[6..11]` |
| `rs2_*` | `M[11..16]` | `M[11..16]` | `M[11..16]` | `M[11..16]` |
| `load_*` | — | — | `M[16..21]` | — |
| `ram_*` | — | — | `M[21..26]` | `M[16..21]` |
| `rd_*` | `M[16..21]` | `M[16..21]` | `M[26..31]` | `M[21..26]` |
| `deleg_*` | `M[21..26]` | — | — | — |
| `deleg_space` | `M[26]` | — | — | — |
| `<q>_gap_hi` | `W[0..5]` | `W[0..4]` | `W[0..6]` | `W[0..5]` |
| `rd_inv`, `rd_is_zero`, `rd_selected` | `W[5]`, `W[6]`, `W[7]` | `W[4]`, `W[5]`, `W[6]` | `W[6]`, `W[7]`, `W[8]` | `W[5]`, `W[6]`, `W[7]` |
| the family's own `W` columns start at | `W[8]` | `W[7]` | `W[9]` | `W[8]` |

`ADD_SUB_LUI_AUIPC` and `ATOMICS` now share a frame *shape* — five queries, so the same column
positions — and not a frame: slots 3 and 4 are `rd` then `deleg` in the ALU family and `ram`
then `rd` in the A extension, so the two differ in every address space, `Δ` and column name
past slot 2, and only the ALU family carries `deleg_space`, its 27th `M` column.
`memory_frame_alu.bin` and `memory_frame_atomics.bin` are different bytes.

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

**67 committed columns (27 `M`, 33 `W`, 7 `S`)** and two virtual tables. Gate list 0 writes 68
leaves and holds 57 enforcing gates. 15 lookups on three channels, 8 outputs. At `n = 20`, the
height S16 proves, there are 25 gate lists, the top is `L25`, and the circuit has 298 inner
columns and 355 relations. `artifact` panics unless the frame is `QUERIES` and the channels
carry exactly 10, 4 and 1 obligations.

**The frame is what sets those numbers, and it narrowed when the POSIX layer went.** `read`
(63) and `write` (64) are retired and their numbers burned (`ecall-abi.md` §4), so
the `arg1` and `arg2` queries — an ecall row's `a1` and `a2`, which only those two calls ever
passed — became unreachable, and the query table dropped from nine entries to seven
(`memory.md` §2.1, §2.1 here). This family lost a third query with them: its `ram` query was the
ecall **transfer row's** alone, no instruction routed here touches memory, and an ecall is now
exactly one cycle. So `frame_queries(0)` went from eight queries to **five** —
pc `rs1` `rs2` `rd` `deleg` — and with them went 15 `M` columns, three `*_gap_hi` witness
columns, three mask booleanity gates, the two write-backs `arg1` and `arg2` carried (`ram` is
not read-only and carried none) and the three `arg1_mask_rule`, `arg2_mask_rule` and
`ram_mask_rule` gates, each of which said `mask = 0` about a query the family already could not
make. Immediately before the change the circuit was
85 committed columns (42/36/7), 100 leaves, 65 enforcing gates, 21 lookups, 26 gate lists, 368
inner columns and 433 relations at `n = 20`; three of those figures had already moved past what
this page recorded at S23, S26's fourth delegation type (`MOD_MUL`) having added one `W`
column, three enforcing gates and three relations. This entry is read from the current
artifact throughout.

**Two consequences are worth naming, because each undoes something S21 bought.** Five queries no
longer fill an eight-leaf product tree, so each side pays **three** literal-1 pad leaves where
eight paid none — the shape `ATOMICS` has had since S19 (§9.4). And ten gap obligations with
the table fraction is eleven leaves, which fits a 16-leaf tree, so the timestamp tree stopped
setting the depth: the circuit is **five** row-wise lists deep where S21 made it six, and its
layer widths are `MEM_WORD`'s exactly (§1.3, §7.7).

**What did not move**: the frozen rows of `docs/spec/execution-trace.md`, the `deleg` mirror and
everything S21 and S23 built on it, and the family's meaning. `EXIT` is still the only ecall
that halts, and the family still refuses every ecall number but `EXIT`'s and the four registered
delegations' (gates 93, 96, 99, 102 and 103). `artifact` also panics on every refusal of the
assembly, among them `n < 19` (the 19-bit timestamp table needs 19 variables) and `n > 30`
(`MAX_TRACE_VARS`); `family_circuit` returns `None` for both rather than calling it.

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
| system: ecall | 0 (1) | `ECALL` = 0 | pc; rs1 = `x17`, reading 93; rs2 = `x10`; rd = `x10` | `a0` as read | 0; as on a lui row, only `wrap_boolean` constrains it | `HALT_PC` = 1 | `EXIT` only, `is_ecall = 1`, every `is_deleg_t = 0` |
| system: a **delegation request** (S21; one row kind per type since S23) | 0 (1) | `ECALL` = 0 | pc; rs1 = `x17`, reading the type's number — `0x501`, `0x500`, `0x502` or `0x504`; rs2 = `x10`, the frame base; rd = `x10`; **deleg**, at that base | 0 | 0; as above | the fall-through | yes, `is_ecall = 1` **and** exactly one `is_deleg_t = 1` |
| system: ebreak | 0 (1) | `EBREAK` = 1 | — | — | — | — | never: no row satisfies `system_split` with the two code gates |
| padding | none; all 0 | 0 | none | 0 | 0 | 0 | every row past the shard's last cycle |

A compressed instruction (`c.add`, `c.li`, …) is one of these kinds at its own length: its
table row's `next_pc` is `pc + 2`.

**There is no transfer-cycle row kind any more.** An ecall's buffer traffic used to reach RAM
through extra cycles carrying a RAM query apiece, and this family's frame carried the `ram`
query for them and nothing else; the two calls that made them are retired, so the row kind, the
query and the `ram_mask_rule` that forbade the row all went together (`ecall-abi.md` §4,
`public-values.md` §1). An ecall is one cycle.

A delegation request is the family's second provable ecall kind and the only row kind it has
gained since S16. It is an ordinary ecall row with one type selector set, one extra query, one
extra memory column and three zeroings; what makes it *an invocation of that type* is nothing
here — it is the mirror query's tuple meeting an invocation's in the one global multiset
(§12.4 and its counterparts in §13, §14 and §18, `delegation.md` §5.3). **Which type is a
property of the row, not of the frame**: the selector says which, and `deleg_space_rule` (§3.5,
gate 121) copies that type's address-space tag into the row's `deleg_space` cell, which is what
the mirror's leaf reads. The four types are one row kind here and four families elsewhere; this
family never sees a delegation frame, a permutation or a delegation shard.

### 3.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §3.4 and §3.6.

**Memory-argument columns, `M[0..27]`** — filled by `trace::build_memory_columns`; committed in
`PublicInputs::memory_commitments`, absorbed at G8 before the memory challenges.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 5); obligations `gap_lo_*` (all 5) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `deleg_mask_rule`; selector of `gap_hi_pc`, `gap_lo_pc`, the four `RANGE16` obligations and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `add_addi_auipc`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | the fall-through, or `HALT_PC` on the exit row | leaf `write_pc`; `next_pc_rule`; `next_pc_lo_range` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on add, sub, addi and every ecall row | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | rs1 register | the decoded `rs1`, or 17 (`a7`) on an ecall row | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | rs1 value | the `a7` an ecall row reads | leaf `read_rs1`; `rs1_writes_back`, `deleg_9_number`, `deleg_10_number`, `deleg_11_number`, `deleg_15_number`, `ecall_is_exit`, `rs1_value_masked`, `add_addi_auipc`, `sub` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on add, sub and every ecall row | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | rs2 register | the decoded `rs2`, or 10 (`a0`) on an ecall row | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | rs2 value | the frame base on a request row | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `add_addi_auipc`, `sub`, `deleg_addr_rule` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `rd_mask` | `frame(3, FIELD_MASK)` | rd present | 1 on every kind but the fence | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[17]` | `rd_addr` | `frame(3, FIELD_ADDR)` | rd register | the decoded `rd`, or 10 (`a0`) on an ecall row | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[18]` | `rd_read_ts` | `frame(3, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[19]` | `rd_read_value` | `frame(3, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd`; `exit_status` |
| `M[20]` | `rd_write_value` | `frame(3, FIELD_WRITE_VALUE)` | rd new value | `rd_selected`, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |
| `M[21]` | `deleg_mask` | `frame(4, FIELD_MASK)` | Mirror query present | 1 on a delegation request, 0 on every other row | leaves `read_deleg`, `write_deleg`; `deleg_mask_boolean`, `deleg_mask_rule`, `deleg_writes_no_register`, `deleg_read_ts_zero`, `deleg_read_value_zero`, `deleg_addr_rule`; selector of `gap_hi_deleg`, `gap_lo_deleg` |
| `M[22]` | `deleg_addr` | `frame(4, FIELD_ADDR)` | Frame base handed over | the `a0` the row read, its invocation's frame pointer | leaves `read_deleg`, `write_deleg`; `deleg_addr_rule` |
| `M[23]` | `deleg_read_ts` | `frame(4, FIELD_READ_TS)` | Answer-tuple timestamp | 0, the stamp no cycle can make | leaf `read_deleg`; `deleg_read_ts_zero`, `gap_lo_deleg` |
| `M[24]` | `deleg_read_value` | `frame(4, FIELD_READ_VALUE)` | Answer-tuple value | 0 | leaf `read_deleg`; `deleg_read_value_zero` |
| `M[25]` | `deleg_write_value` | `frame(4, FIELD_WRITE_VALUE)` | Consumed-anchor value | **free**; 0 in an honest fill | leaf `write_deleg` **and nothing else**: no gate, no obligation, no table (§3.10) |
| `M[26]` | `deleg_space` | `memory::deleg_space(5)` | Requested delegation type | that type's `constants::address_space` tag — 4, 5, 6 or 7 — on a request row, 0 on every other | leaves `read_deleg`, `write_deleg`; `deleg_space_rule` |

The frame's slots in `add_sub.rs` are `SLOT_PC = 0`, `SLOT_RS1 = 1`, `SLOT_RS2 = 2`,
`SLOT_RD = 3` and `SLOT_DELEG = 4`, so `frame(3, ..)` is `frame(SLOT_RD, ..)` there. **Slot is
not query id**: `rd` is id 5 and `deleg` id 6 in `memory::FRAME_NAMES`, and neither equals its
slot in a frame this narrow — the id is what fixes the column's address space and its `Δ`, the
slot is what fixes its position (§2.1). `deleg_space` is not in that grid: it sits past the last
query's five fields at `M[1 + 5w]`, and a frame without the `deleg` query does not carry it at
all (§2.2).

**Every column of this frame is one some row of the family makes.** Until the POSIX layer went,
fifteen `M` columns and three gap chunks — the `arg1`, `arg2` and `ram` groups — were held to 0
on every row by three `mask = 0` gates, committed and opened by every shard, and carried
nothing; they were the I/O-binding stage's, and what that stage did with them was delete them
(§21 observation 2).

**Why the type rides a memory column, and why one query serves all four.** The mirror's leaf
has to name the requested type — the tag is its `AS` term — and a leaf may read no `W` column,
because `W` is committed after the memory challenges (`memory.md` §8, `check_memory`'s
provenance rule). The type selectors are `W` columns, so the tag crosses into the leaf through
`deleg_space`, which `deleg_space_rule` pins to them; with one delegation family the tag *was*
a literal on the mask, and with four it cannot be. And one `deleg` query serves every type
rather than one query apiece because a second mirror query would need a seventh
`trace::Role` (`execution-trace.md` §7). `delegation.md` §5.1 is that rule, and §10.1 records
what S21 wrote instead and why it was not implementable.

**Witness columns, `W[0..33]`** — `W[0..8]` filled by `trace::build_frame_witness`, `W[7..30]`
by `fill::add_sub` (which overwrites `rd_selected`), `W[30..33]` by
`trace::build_multiplicities` inside `prover::shard_columns`; committed in
`ShardProof::witness_commitments`, absorbed at S3 before `g` and `β`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0]` | `pc_gap_hi` | `memory::gap_hi(0)` | pc gap, high chunk | 0: a pc read's gap is always 3 | `gap_hi_pc`, `gap_lo_pc` |
| `W[1]` | `rs1_gap_hi` | `gap_hi(1)` | rs1 gap, high chunk | `gap >> 19` | `gap_hi_rs1`, `gap_lo_rs1` |
| `W[2]` | `rs2_gap_hi` | `gap_hi(2)` | rs2 gap, high chunk | | `gap_hi_rs2`, `gap_lo_rs2` |
| `W[3]` | `rd_gap_hi` | `gap_hi(3)` | rd gap, high chunk | | `gap_hi_rd`, `gap_lo_rd` |
| `W[4]` | `deleg_gap_hi` | `gap_hi(4)` | Mirror-query gap, high chunk | `(4c + 2) >> 19` on a delegation row, 0 elsewhere | `gap_hi_deleg`, `gap_lo_deleg` |
| `W[5]` | `rd_inv` | `memory::rd_inv(5)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[6]` | `rd_is_zero` | `memory::rd_is_zero(5)` | rd is `x0` | | `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_is_zero_boolean`, `rd_write_masked` |
| `W[7]` | `rd_selected` | `memory::rd_selected(5)`; `sel` in `add_sub.rs` | Result | the kind's result (§3.2), `rd = x0` included: `fill::add_sub` overwrites the 0 that S14's builder writes there | `rd_write_masked`, `add_addi_auipc`, `sub`, `lui`, `exit_status`, `deleg_writes_no_register`; `rd_lo_range` |
| `W[8]` | `decoded_next_pc` | `add_sub::DECODED[0]` | Decoded fall-through | the table row's `next_pc` | `next_pc_rule`; `decode_row` position 1 |
| `W[9]` | `decoded_rs1` | `add_sub::DECODED[1]` | Decoded rs1 | | `rs1_addr_rule`; `decode_row` position 2 |
| `W[10]` | `decoded_rs2` | `add_sub::DECODED[2]` | Decoded rs2 | | `rs2_addr_rule`; `decode_row` position 3 |
| `W[11]` | `decoded_rd` | `add_sub::DECODED[3]` | Decoded rd | | `rd_addr_rule`; `decode_row` position 4 |
| `W[12]` | `decoded_imm` | `add_sub::DECODED[4]` | Decoded immediate, or system code | | `ecall_code`, `fence_code`, `add_addi_auipc`, `lui`; `decode_row` position 5 |
| `W[13]` | `decoded_mask` | `add_sub::DECODED[5]` | Decoded kind mask | `1 << bit` | `decoded_mask_bits`; `decode_row` position 6 |
| `W[14]` | `kind_system` | `add_sub::KINDS[0]`; `KIND_SYSTEM` in `add_sub.rs` (index `add_sub_lui_auipc::SYSTEM`) | System row | | `kind_system_boolean`, `decoded_mask_bits`, `system_split` |
| `W[15]` | `kind_addi` | `add_sub::KINDS[1]`; `KIND_ADDI` in `add_sub.rs` (index `add_sub_lui_auipc::ADDI`) | addi row | | `kind_addi_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rd_mask_rule`, `add_addi_auipc` |
| `W[16]` | `kind_auipc` | `add_sub::KINDS[2]`; `KIND_AUIPC` in `add_sub.rs` (index `add_sub_lui_auipc::AUIPC`) | auipc row | | `kind_auipc_boolean`, `decoded_mask_bits`, `rd_mask_rule`, `add_addi_auipc` |
| `W[17]` | `kind_add` | `add_sub::KINDS[3]`; `KIND_ADD` in `add_sub.rs` (index `add_sub_lui_auipc::ADD`) | add row | | `kind_add_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `add_addi_auipc` |
| `W[18]` | `kind_sub` | `add_sub::KINDS[4]`; `KIND_SUB` in `add_sub.rs` (index `add_sub_lui_auipc::SUB`) | sub row | | `kind_sub_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `sub` |
| `W[19]` | `kind_lui` | `add_sub::KINDS[5]`; `KIND_LUI` in `add_sub.rs` (index `add_sub_lui_auipc::LUI`) | lui row | | `kind_lui_boolean`, `decoded_mask_bits`, `rd_mask_rule`, `lui` |
| `W[20]` | `is_ecall` | `add_sub::IS_ECALL` | Ecall row: the exit, or a delegation | 1 on a system row with code `ECALL` | `is_ecall_boolean`, `system_split`, `ecall_code`, `ecall_is_exit`, `deleg_9_is_an_ecall`, `deleg_10_is_an_ecall`, `deleg_11_is_an_ecall`, `deleg_15_is_an_ecall`, `rs1_mask_rule`, `rs2_mask_rule`, `rd_mask_rule`, `rs1_addr_rule`, `rs2_addr_rule`, `rd_addr_rule`, `exit_status`, `next_pc_rule` |
| `W[21]` | `is_fence` | `add_sub::IS_FENCE` | Fence row | 1 on a system row with code `FENCE` | `is_fence_boolean`, `system_split`, `fence_code` |
| `W[22]` | `is_deleg_9` | `add_sub::IS_DELEGATION[0]`; `add_sub::IS_KECCAK`, S21's name kept | `KECCAK_F` request row | 1 on an ecall row whose `a7` is `0x507` (`0x501` until S26d retired it) | `is_deleg_9_boolean`, `deleg_9_is_an_ecall`, `deleg_9_number`, `ecall_is_exit`, `deleg_mask_rule`, `exit_status`, `deleg_space_rule`, `next_pc_rule` |
| `W[23]` | `is_deleg_10` | `add_sub::IS_DELEGATION[1]` | `POSEIDON2` request row (S23) | 1 on an ecall row whose `a7` is `0x500` | `is_deleg_10_boolean`, `deleg_10_is_an_ecall`, `deleg_10_number`, `ecall_is_exit`, `deleg_mask_rule`, `exit_status`, `deleg_space_rule`, `next_pc_rule` |
| `W[24]` | `is_deleg_11` | `add_sub::IS_DELEGATION[2]` | `FR_ARITH` request row (S23) | 1 on an ecall row whose `a7` is `0x502` | `is_deleg_11_boolean`, `deleg_11_is_an_ecall`, `deleg_11_number`, `ecall_is_exit`, `deleg_mask_rule`, `exit_status`, `deleg_space_rule`, `next_pc_rule` |
| `W[25]` | `is_deleg_15` | `add_sub::IS_DELEGATION[3]` | `MOD_MUL` request row (S26) | 1 on an ecall row whose `a7` is `0x504` | `is_deleg_15_boolean`, `deleg_15_is_an_ecall`, `deleg_15_number`, `ecall_is_exit`, `deleg_mask_rule`, `exit_status`, `deleg_space_rule`, `next_pc_rule` |
| `W[26]` | `wrap` | `add_sub::WRAP` | Carry or borrow | | `add_addi_auipc`, `sub`, `wrap_boolean` |
| `W[27]` | `rd_hi` | `add_sub::RD_HI` | Result, high halfword | `rd_selected >> 16` | `rd_hi_range`, `rd_lo_range` |
| `W[28]` | `pc_wrap` | `add_sub::PC_WRAP` | Next-pc overflow | 0 | `pc_wrap_boolean`, `next_pc_rule` |
| `W[29]` | `next_pc_hi` | `add_sub::NEXT_PC_HI` | Next pc, high halfword | `pc_write_value >> 16` | `next_pc_hi_range`, `next_pc_lo_range` |
| `W[30]` | `mult_timestamp` | `add_sub::MULTIPLICITIES[0]` | Timestamp-table count | per table row `t`: the gated gap chunks (`mask·chunk`) equal to `t`, credited to rows below `2^19` | leaf `timestamp_table_num` |
| `W[31]` | `mult_range16` | `add_sub::MULTIPLICITIES[1]` | 16-bit-table count | per table row `t`: the gated halfwords (`pc_mask·halfword`) equal to `t`, credited to rows below `2^16` | leaf `range16_table_num` |
| `W[32]` | `mult_decoder` | `add_sub::MULTIPLICITIES[2]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all seven positions) on the table's lowest non-live row, which is row 0, since pc 0 lies below `RAM_ORIGIN` and holds no instruction | leaf `decoder_table_num` |

A switched-off obligation's gated tuple is 0 (`s·e` at `s = 0`), so row 0 of `mult_timestamp`
and `mult_range16` counts every switched-off obligation: all 10 timestamp and all 4 `RANGE16`
obligations of each padding row, and in `mult_timestamp` also the two `deleg` chunks of every
row that is not a delegation request and the two chunks of any `rs1`, `rs2` or `rd` query the
row does not make. The `RANGE16` obligations are selected by `pc_mask`, so none is off on a live
row. Row 0 also counts every live chunk whose value is 0, such as `pc_gap_hi` on every live row.

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
leaf per §0.6. Five queries fill eight leaves a side, so each side carries **three** pads — the
shape `ATOMICS` has (§9.4). This family paid one pad a side at S16's seven queries and none at
S21's eight; the POSIX layer's deletion took three queries away and put three pads back.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_rd` | `M[16]` | 1 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `read_deleg` | `M[21]` | **`M[26]`** | `M[22]` | `M[23]` | `M[24]` |
| 5, 6, 7 | `read_pad_0`, `read_pad_1`, `read_pad_2` | — | — | — | — | the literal 1 |
| 8 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 9 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 10 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 11 | `write_rd` | `M[16]` | 1 | `M[17]` | `4·M[0] + 3` | `M[20]` |
| 12 | `write_deleg` | `M[21]` | **`M[26]`** | `M[22]` | `4·M[0] + 3` | `M[25]` |
| 13, 14, 15 | `write_pad_0`, `write_pad_1`, `write_pad_2` | — | — | — | — | the literal 1 |

**The `deleg` pair is the only one whose `AS` is a column and not a literal** (S23). Every
other leaf takes its space from `memory::FRAME_SPACE`, a compile-time constant of the query, so
the term is `(tag, mask)`; the mirror's is `(1, deleg_space, mask)`, the product
`deleg_space · deleg_mask`, because one query serves every delegation type and which one is a
property of the row (§2.2, `delegation.md` §5.1). `deleg_space` holds
`address_space::DELEGATION_KECCAK_F` = 4, `DELEGATION_POSEIDON2` = 5, `DELEGATION_FR_ARITH` = 6
or `DELEGATION_MOD_MUL` = 7, and `deleg_space_rule` is what ties it to the row's type selector.
A row requesting nothing has `deleg_space` 0 and `deleg_mask` 0 alike, so the leaf is the
literal 1 there whichever way it is read.

Four gates below pin what this pair may be — `deleg_space_rule`, `deleg_read_ts_zero`,
`deleg_read_value_zero` and `deleg_addr_rule` — and together they say a request of type `t`
reads the tuple `T(AS_t, rs2_read_value, 0, 0)` and writes
`T(AS_t, rs2_read_value, 4·cycle + 3, deleg_write_value)`. Only an invocation of §12, §13, §14
or §18 writes a timestamp-0 tuple in its own space, and only a request of that type reads one,
which is what makes the pairing 1:1 (`delegation.md` §5.3). The tags are pairwise distinct —
the same `const` assertion in `add_sub.rs` that holds the ecall numbers apart holds the tags
apart — so a request of one type cannot be answered by an invocation of another.

Two of them in full:

```text
L{1}[0]  read_pc
  positional  1 + γ_M·M[1] − M[1] + 3·M[1] + α_addr·M[2]·M[1] + α_ts·M[3]·M[1] + α_val·M[4]·M[1]
  named       pc_mask·T(PC, pc_addr, pc_read_ts, pc_read_value) + 1 − pc_mask

L{1}[12]  write_deleg
  positional  1 + γ_M·M[21] − M[21] + α_ts·M[21] ×3 + M[26]·M[21] + α_addr·M[22]·M[21]
                + α_ts·M[0]·M[21] ×4 + α_val·M[25]·M[21]
  named       deleg_mask·T(deleg_space, deleg_addr, 4·cycle + 3, deleg_write_value)
                + 1 − deleg_mask
```

**The `timestamp` fraction tree**, `L1[16..48]`: 16 fractions, the table's then 10 gap
obligations then 5 pads. Fraction `i` is `(L1[16 + 2i], L1[17 + 2i])`, named `<node>_num` and
`<node>_den`. Eleven leaves fit a 16-leaf tree with room to spare, which is why this circuit is
five row-wise lists deep and not six (§1.3, §21 observation 20).

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 16, 17 | `timestamp_table` | `−mult_timestamp` | `V[range19] + g` |
| 1 | 18, 19 | `gap_hi_pc` | 1 | `g + pc_mask·pc_gap_hi` |
| 2 | 20, 21 | `gap_lo_pc` | 1 | `g − pc_mask + 4·pc_mask·cycle − pc_mask·pc_read_ts − 2^19·pc_mask·pc_gap_hi` |
| 3 | 22, 23 | `gap_hi_rs1` | 1 | `g + rs1_mask·rs1_gap_hi` |
| 4 | 24, 25 | `gap_lo_rs1` | 1 | `g + 4·rs1_mask·cycle − rs1_mask·rs1_read_ts − 2^19·rs1_mask·rs1_gap_hi` |
| 5 | 26, 27 | `gap_hi_rs2` | 1 | `g + rs2_mask·rs2_gap_hi` |
| 6 | 28, 29 | `gap_lo_rs2` | 1 | `g + rs2_mask + 4·rs2_mask·cycle − rs2_mask·rs2_read_ts − 2^19·rs2_mask·rs2_gap_hi` |
| 7 | 30, 31 | `gap_hi_rd` | 1 | `g + rd_mask·rd_gap_hi` |
| 8 | 32, 33 | `gap_lo_rd` | 1 | `g + 2·rd_mask + 4·rd_mask·cycle − rd_mask·rd_read_ts − 2^19·rd_mask·rd_gap_hi` |
| 9 | 34, 35 | `gap_hi_deleg` | 1 | `g + deleg_mask·deleg_gap_hi` |
| 10 | 36, 37 | `gap_lo_deleg` | 1 | `g + 2·deleg_mask + 4·deleg_mask·cycle − deleg_mask·deleg_read_ts − 2^19·deleg_mask·deleg_gap_hi` |
| 11–15 | 38, 39 … 46, 47 | `timestamp_pad_0` … `timestamp_pad_4` | 0 | 1 |

The linear term on a `gap_lo` denominator's mask is `(Δ_q − 1)·m`: `−1` for pc, none for rs1,
`+1` for rs2, `+2` for rd and deleg. **`Δ` is the query's, not the slot's** — `rd` is id 5 and
`deleg` id 6 in `memory::FRAME_DELTA`, and both write at `4·cycle + 3` — so dropping `arg1`,
`arg2` and `ram` from the frame moved every column of the `rd` and `deleg` groups down and
changed no constant in either.
In positional form fraction 2's denominator is
`g − M[1] + 4·M[1]·M[0] − M[1]·M[3] − 2^19·M[1]·W[0]`.

**The `deleg` gap pair is discharged against a timestamp the invocation never wrote.** Its
`read_ts` is held to 0 by `deleg_read_ts_zero`, so `gap_lo_deleg` is `4·cycle + 2` on a
delegation row — a real value below `2^19` only for the first 131,071 cycles, which is why
`deleg_gap_hi` is a committed chunk like every other and not an assumed zero.

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
              + M[1]·M[4] + β·M[1]·W[8] + β²·M[1]·W[9] + β³·M[1]·W[10]
              + β⁴·M[1]·W[11] + β⁵·M[1]·W[12] + β⁶·M[1]·W[13]
  reads as    g + Σ_j β^j·(pc_mask·(v_j + 1) − 1), v = (pc_read_value, decoded_next_pc, …,
              decoded_mask):
              the claimed row at pc_mask = 1, and the table's MINUS_ONE padding row at 0
```

### 3.5 Gate list 0: the 57 enforcing gates

Relations 68–124, in list order. Each block gives the relation number, the name, what the gate
is for, its shape and degree, the constructor, the stored positional form, and the named form,
factored where that is easier to read. Every factoring re-expands to the stored terms.

**A. The frame's gates (68–78)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
68–72   <q>_mask_boolean — each query's presence flag is a bit          Quadratic, degree 2
        code  memory::booleanity(frame(s, FIELD_MASK)), in frame_body

  68 pc_mask_boolean     0 = M[1]  − M[1]·M[1]      0 = pc_mask    − pc_mask²
  69 rs1_mask_boolean    0 = M[6]  − M[6]·M[6]      0 = rs1_mask   − rs1_mask²
  70 rs2_mask_boolean    0 = M[11] − M[11]·M[11]    0 = rs2_mask   − rs2_mask²
  71 rd_mask_boolean     0 = M[16] − M[16]·M[16]    0 = rd_mask    − rd_mask²
  72 deleg_mask_boolean  0 = M[21] − M[21]·M[21]    0 = deleg_mask − deleg_mask²

  reads as  a leaf is 1 or its tuple only at a mask of 0 or 1; a mask of −1 on a pc query
            flips both leaves' signs and reads as a REG query (memory.md §2.4). Every mask
            is also a lookup selector, which validate requires to be boolean.

────────────────────────────────────────────────────────────────────────────────────────────
73, 74  <q>_writes_back — a read-only register is left unchanged        Linear, degree 1
        code  memory::write_back(s), in frame_body

  73 rs1_writes_back     0 = M[10] − M[9]     0 = rs1_write_value − rs1_read_value
  74 rs2_writes_back     0 = M[15] − M[14]    0 = rs2_write_value − rs2_read_value

  reads as  a query that only reads writes back what it read, so reading x0 cannot put 5 in it.
            Two, not four: memory::FRAME_READ_ONLY is rs1, rs2 and load, and this frame holds
            no load — and the two ecall-argument queries that carried the other two gates went
            with the calls that used them (ecall-abi.md §4). `deleg` is NOT read-only and has
            no such gate: it reads the answer tuple an invocation wrote and writes a tuple of
            its own, which is what makes the pairing 1:1 (delegation.md §5.3). Gates 118–121
            pin what it may read instead.

────────────────────────────────────────────────────────────────────────────────────────────
75      rd_is_zero_inverse — the x0 flag, with gate 76                  Quadratic, degree 2
        code  memory::x0_gates(3, 5)[0]

  positional  0 = W[6] − M[16] + M[17]·W[5]
  named       0 = rd_addr·rd_inv + rd_is_zero − rd_mask

────────────────────────────────────────────────────────────────────────────────────────────
76      rd_is_zero_at_nonzero — no x0 flag at a real register           Quadratic, degree 2
        code  x0_gates(3, 5)[1]

  positional  0 = M[17]·W[6]
  named       0 = rd_addr·rd_is_zero

  reads as (75 with 76)  at rd_addr ≠ 0: rd_is_zero = 0 and rd_addr·rd_inv = rd_mask, so
                         rd_inv = 1/rd_addr on a live rd query (rd_mask = 1) and 0 where
                         rd_mask = 0.
                         at rd_addr = 0: rd_is_zero = rd_mask.
                         So the flag is 1 exactly on a live rd query at x0.

────────────────────────────────────────────────────────────────────────────────────────────
77      rd_is_zero_boolean                                              Quadratic, degree 2
        code  x0_gates(3, 5)[2]

  positional  0 = W[6] − W[6]·W[6]
  named       0 = rd_is_zero − rd_is_zero²

────────────────────────────────────────────────────────────────────────────────────────────
78      rd_write_masked — a write into x0 writes 0                      Quadratic, degree 2
        code  x0_gates(3, 5)[3]

  positional  0 = M[20] − W[7] + W[6]·W[7]
  named       0 = rd_write_value − (1 − rd_is_zero)·rd_selected

  reads as  the rd write is the computed result, except into x0, where it is 0. With the
            write-backs and x0's initial 0, every read of x0 returns 0.
```

**B. What the row is (79–103)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
79–84   kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2
        code  add_sub::booleanity(KINDS[k])

  79 kind_system_boolean   0 = W[14] − W[14]·W[14]    0 = kind_system − kind_system²
  80 kind_addi_boolean     0 = W[15] − W[15]·W[15]    0 = kind_addi   − kind_addi²
  81 kind_auipc_boolean    0 = W[16] − W[16]·W[16]    0 = kind_auipc  − kind_auipc²
  82 kind_add_boolean      0 = W[17] − W[17]·W[17]    0 = kind_add    − kind_add²
  83 kind_sub_boolean      0 = W[18] − W[18]·W[18]    0 = kind_sub    − kind_sub²
  84 kind_lui_boolean      0 = W[19] − W[19]·W[19]    0 = kind_lui    − kind_lui²

────────────────────────────────────────────────────────────────────────────────────────────
85      decoded_mask_bits — the packed mask is its six bits             Linear, degree 1
        code  add_sub::artifact, `bits`

  positional  0 = W[14] + 2·W[15] + 4·W[16] + 8·W[17] + 16·W[18] + 32·W[19] − W[13]
  named       0 = kind_system + 2·kind_addi + 4·kind_auipc + 8·kind_add + 16·kind_sub
                  + 32·kind_lui − decoded_mask

  reads as  the bits are the mask the decoder lookup binds. One-hotness is not here: on a
            live row an all-zero mask satisfies all 57 gates, and only the decoder table,
            whose masks are single bits, refuses it (lookup.md §10). Two bits that each ask
            for an rd write (any two of addi, auipc, add, sub, lui, or the system bit read as
            is_ecall beside one of them) are refused by 106 with 71, since rd_mask comes out
            2. The system bit read as is_fence beside any one other bit passes every gate,
            and only the decoder table refuses it. On a padding row the decoder lookup is
            off, so no table row binds the bits and only the gates above constrain them; the
            honest fill writes 0.

────────────────────────────────────────────────────────────────────────────────────────────
86      is_ecall_boolean      0 = W[20] − W[20]·W[20]      0 = is_ecall − is_ecall²
87      is_fence_boolean      0 = W[21] − W[21]·W[21]      0 = is_fence − is_fence²
        Quadratic, degree 2; code  add_sub::booleanity

────────────────────────────────────────────────────────────────────────────────────────────
88      system_split — a system row is exactly one of ecall and fence   Linear, degree 1
        code  add_sub::artifact

  positional  0 = W[20] + W[21] − W[14]
  named       0 = is_ecall + is_fence − kind_system

────────────────────────────────────────────────────────────────────────────────────────────
89      ecall_code — an ecall row's code is ECALL                       Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = W[20]·W[12]
  named       0 = is_ecall·decoded_imm

  reads as  is_ecall = 1 needs code 0; this reads "the code is ECALL" only because
            system_code::ECALL is 0, which a const assertion in add_sub.rs pins.

────────────────────────────────────────────────────────────────────────────────────────────
90      fence_code — a fence row's code is FENCE                        Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = −2·W[21] + W[21]·W[12]
  named       0 = is_fence·(decoded_imm − 2)

  reads as (88, 89, 90)  a system row with code 1, EBREAK, can set neither flag, and
                         system_split then fails: no ebreak row is provable.

────────────────────────────────────────────────────────────────────────────────────────────
91–102  three gates per delegation type, in constants::delegation::TYPES order
                                                                        Quadratic, degree 2
        code  add_sub::artifact, the loop over DELEGATIONS                          S23, S26

  91  is_deleg_9_boolean    0 = W[22] − W[22]·W[22]    0 = is_deleg_9  − is_deleg_9²
  92  deleg_9_is_an_ecall   0 = W[22] − W[22]·W[20]    0 = is_deleg_9·(1 − is_ecall)
  93  deleg_9_number        0 = −1281·W[22] + W[22]·M[9]
                                                       0 = is_deleg_9·(rs1_read_value − 0x501)
  94  is_deleg_10_boolean   0 = W[23] − W[23]·W[23]    0 = is_deleg_10 − is_deleg_10²
  95  deleg_10_is_an_ecall  0 = W[23] − W[23]·W[20]    0 = is_deleg_10·(1 − is_ecall)
  96  deleg_10_number       0 = −1280·W[23] + W[23]·M[9]
                                                       0 = is_deleg_10·(rs1_read_value − 0x500)
  97  is_deleg_11_boolean   0 = W[24] − W[24]·W[24]    0 = is_deleg_11 − is_deleg_11²
  98  deleg_11_is_an_ecall  0 = W[24] − W[24]·W[20]    0 = is_deleg_11·(1 − is_ecall)
  99  deleg_11_number       0 = −1282·W[24] + W[24]·M[9]
                                                       0 = is_deleg_11·(rs1_read_value − 0x502)
  100 is_deleg_15_boolean   0 = W[25] − W[25]·W[25]    0 = is_deleg_15 − is_deleg_15²
  101 deleg_15_is_an_ecall  0 = W[25] − W[25]·W[20]    0 = is_deleg_15·(1 − is_ecall)
  102 deleg_15_number       0 = −1284·W[25] + W[25]·M[9]
                                                       0 = is_deleg_15·(rs1_read_value − 0x504)

  reads as  each is_deleg_t = 1 forces is_ecall = 1, so a delegation request is a system row
            with code ECALL and carries the whole ecall frame. Each flag is free on every
            other row, where its booleanity gate alone holds it to 0 or 1 — and 107 then
            makes a stray 1 ask for a deleg query, 121 makes it name that type's address
            space, the number gate makes it ask a7 for that type's number, and 103 and 116
            turn the exit gates off; the honest fill writes 0 in all four.

            The four numbers are ecall::PRECOMPILE_KECCAK_F, PRECOMPILE_POSEIDON2,
            PRECOMPILE_FR_ARITH and PRECOMPILE_MOD_MUL read straight from
            constants::delegation::TYPES, which is also where the family ids in the names
            come from: no gate here spells a number of its own, and neither does 103. S21 had
            one flag and four gates for the one delegation family; since S23 it is three
            gates per type, the fourth having become 103's sum over types, and S26's MOD_MUL
            cost exactly those three.

────────────────────────────────────────────────────────────────────────────────────────────
103     ecall_is_exit — every ecall that is not a delegation is EXIT    Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = −93·W[20] + 93·W[22] + 93·W[23] + 93·W[24] + 93·W[25]
                  + W[20]·M[9] − W[22]·M[9] − W[23]·M[9] − W[24]·M[9] − W[25]·M[9]
  named       0 = (is_ecall − is_deleg_9 − is_deleg_10 − is_deleg_11 − is_deleg_15)
                  · (rs1_read_value − 93)

  reads as  an ecall row's rs1 query reads a7 (gate 108), and a7 is 93 unless this row is a
            delegation of some type. This is S16's `is_ecall·(rs1_read_value − 93)` with
            every delegation row subtracted out, one linear term and one product per type.

  reads as (91–103)  **an ecall row is an exit or a delegation request of exactly one
                     type.** Each is_deleg_t is a free boolean and is_exit is written out
                     as is_ecall − Σ_t is_deleg_t, so a row setting two type flags at once
                     would need a7 to be two distinct numbers, and a row setting one beside
                     the exit would need a7 to be 93 as well. The partition therefore holds
                     because the ecall numbers are **pairwise distinct** and each is in its
                     ABI range (delegation.md §2, §3) — a `const` assertion in add_sub.rs
                     over every pair of registry rows, not a test, because a violation
                     there is a mis-numbered ABI and should not compile. So the factor is 0
                     or 1 on every row and never −1 or 2, which is what the three amended
                     gates 103, 116 and 124 need of it.
                     **read (63) and write (64) reach none of this**: they are retired and
                     their numbers burned (ecall-abi.md §4), so an image issuing one asks
                     a7 for a number no selector names and 103 refuses the row.
```

**C. Which queries a row makes, and where (104–112)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
104     rs1_mask_rule — rs1 is read exactly by add, sub, addi, ecall    Quadratic, degree 2
        code  add_sub::mask_rule(frame(1, FIELD_MASK), [KIND_ADD, KIND_SUB, KIND_ADDI, IS_ECALL])

  positional  0 = M[6] − M[1]·W[17] − M[1]·W[18] − M[1]·W[15] − M[1]·W[20]
  named       0 = rs1_mask − pc_mask·(kind_add + kind_sub + kind_addi + is_ecall)

────────────────────────────────────────────────────────────────────────────────────────────
105     rs2_mask_rule — rs2 is read exactly by add, sub, ecall          Quadratic, degree 2
        code  mask_rule(frame(2, FIELD_MASK), [KIND_ADD, KIND_SUB, IS_ECALL])

  positional  0 = M[11] − M[1]·W[17] − M[1]·W[18] − M[1]·W[20]
  named       0 = rs2_mask − pc_mask·(kind_add + kind_sub + is_ecall)

────────────────────────────────────────────────────────────────────────────────────────────
106     rd_mask_rule — rd is written by every kind but the fence        Quadratic, degree 2
        code  mask_rule(frame(3, FIELD_MASK),
                        [KIND_ADD, KIND_SUB, KIND_ADDI, KIND_AUIPC, KIND_LUI, IS_ECALL])

  positional  0 = M[16] − M[1]·W[17] − M[1]·W[18] − M[1]·W[15] − M[1]·W[16] − M[1]·W[19]
                  − M[1]·W[20]
  named       0 = rd_mask − pc_mask·(kind_add + kind_sub + kind_addi + kind_auipc
                                     + kind_lui + is_ecall)

  reads as (104, 105, 106)  on a live row the bits are one-hot, so each sum is 0 or 1 and the
                            mask is the kind's use of the query. A delegation row is an ecall
                            row, so it makes all three: a7 at slot 1, a0 at slot 2, a0 at
                            slot 3. On a padding row pc_mask = 0 and every mask is 0,
                            whatever the bits hold.
                            **There is no fourth, fifth or sixth rule here any more.** Until
                            the POSIX layer went, three degree-1 gates said arg1_mask = 0,
                            arg2_mask = 0 and ram_mask = 0 — each refusing a query the frame
                            carried and no kind could make. The queries are gone, so the
                            gates refuse nothing representable and went with them
                            (ecall-abi.md §4, §21 observation 2).

────────────────────────────────────────────────────────────────────────────────────────────
107     deleg_mask_rule — the mirror query is a delegation row's alone  Quadratic, degree 2
        code  mask_rule(frame(4, FIELD_MASK), &IS_DELEGATION)

  positional  0 = M[21] − M[1]·W[22] − M[1]·W[23] − M[1]·W[24] − M[1]·W[25]
  named       0 = deleg_mask − pc_mask·(is_deleg_9 + is_deleg_10 + is_deleg_11 + is_deleg_15)

  reads as  exactly the delegation rows make the mirror query, whatever their type, and
            every delegation row makes it. A row that set a type flag without making the
            query, or made the query without any flag, fails here — and since the mirror
            query is the request's half of the anchor, a request with no mirror query cannot
            balance against its invocation (delegation.md §5.3). The sum is 0 or 1 on every
            row that passes 91–103, so this is the ordinary mask rule of 104–106 with the
            four type flags as its `uses` list; it is what 121 pairs with, one saying the
            query is made and the other which type it names.

────────────────────────────────────────────────────────────────────────────────────────────
108     rs1_addr_rule — rs1's register is the decoded one, or a7        Quadratic, degree 2
        code  add_sub::addr_rule(1, DECODED_RS1, 17)

  positional  0 = M[6]·M[7] − M[6]·W[9] − 17·M[6]·W[20]
  named       0 = rs1_mask·(rs1_addr − decoded_rs1 − 17·is_ecall)

────────────────────────────────────────────────────────────────────────────────────────────
109     rs2_addr_rule — rs2's register is the decoded one, or a0        Quadratic, degree 2
        code  addr_rule(2, DECODED_RS2, 10)

  positional  0 = M[11]·M[12] − M[11]·W[10] − 10·M[11]·W[20]
  named       0 = rs2_mask·(rs2_addr − decoded_rs2 − 10·is_ecall)

────────────────────────────────────────────────────────────────────────────────────────────
110     rd_addr_rule — rd's register is the decoded one, or a0          Quadratic, degree 2
        code  addr_rule(3, DECODED_RD, 10)

  positional  0 = M[16]·M[17] − M[16]·W[11] − 10·M[16]·W[20]
  named       0 = rd_mask·(rd_addr − decoded_rd − 10·is_ecall)

  reads as (108–110)  a present query's register is the table's; a system row's decoded
                      registers are 0, so on an ecall row — exit or delegation of any type
                      alike — the constants name a7 and a0. The three gates key on is_ecall
                      and on no type flag, which is why a delegation row needs no address
                      rule of its own and why adding a type adds none: it is an ecall row and
                      takes the ecall frame.

────────────────────────────────────────────────────────────────────────────────────────────
111     rs1_value_masked — an absent rs1 reads 0                        Quadratic, degree 2
        code  add_sub::value_masked(1)

  positional  0 = M[9] − M[6]·M[9]
  named       0 = (1 − rs1_mask)·rs1_read_value

────────────────────────────────────────────────────────────────────────────────────────────
112     rs2_value_masked — an absent rs2 reads 0                        Quadratic, degree 2
        code  value_masked(2)

  positional  0 = M[14] − M[11]·M[14]
  named       0 = (1 − rs2_mask)·rs2_read_value

  reads as (111, 112)  the sum gate can add both operands on every kind: an addi row's
                       absent rs2, and an auipc row's absent rs1 and rs2, add 0.
```

**D. What the row computes (113–124)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
113     add_addi_auipc — the three sums, one gate                       Quadratic, degree 2
        code  add_sub::artifact, the `sum` loop over [KIND_ADD, KIND_ADDI, KIND_AUIPC]

  positional  0 = W[17]·M[9] + W[17]·M[14] + W[17]·W[12] − W[17]·W[7] − 2^32·W[17]·W[26]
                + W[15]·M[9] + W[15]·M[14] + W[15]·W[12] − W[15]·W[7] − 2^32·W[15]·W[26]
                + W[16]·M[9] + W[16]·M[14] + W[16]·W[12] − W[16]·W[7] − 2^32·W[16]·W[26]
                + W[16]·M[4]
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
114     sub — the difference                                            Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = W[18]·M[9] − W[18]·M[14] − W[18]·W[7] + 2^32·W[18]·W[26]
  named       0 = kind_sub·(rs1_read_value − rs2_read_value − rd_selected + 2^32·wrap)

  reads as  rs1 − rs2 = sel − 2^32·wrap: wrap is the borrow.

────────────────────────────────────────────────────────────────────────────────────────────
115     lui — the loaded value                                          Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = W[19]·W[12] − W[19]·W[7]
  named       0 = kind_lui·(decoded_imm − rd_selected)

────────────────────────────────────────────────────────────────────────────────────────────
116     exit_status — the exit row writes a0 back                       Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = W[20]·M[19] − W[20]·W[7] − W[22]·M[19] + W[22]·W[7]
                  − W[23]·M[19] + W[23]·W[7] − W[24]·M[19] + W[24]·W[7]
                  − W[25]·M[19] + W[25]·W[7]
  named       0 = (is_ecall − is_deleg_9 − is_deleg_10 − is_deleg_11 − is_deleg_15)
                  · (rd_read_value − rd_selected)

  reads as  the exit row's result is a0 as read, and its rd query is x10, so x10's final
            value is the exit status verify_shard's step 10 compares with v_10. A delegation
            row of any type is subtracted out here and answered by 117 instead: it writes 0
            into a0, not a0 back (delegation.md §2). Same shape as 103's amendment, same
            reason, and a new type costs it two more products and no degree.

────────────────────────────────────────────────────────────────────────────────────────────
117     deleg_writes_no_register — a delegation answers 0               Quadratic, degree 2
        code  add_sub::artifact                                                         S21

  positional  0 = M[21]·W[7]
  named       0 = deleg_mask·rd_selected

  reads as  on a delegation row rd_selected is 0, so with 78 the rd query writes 0 into a0 —
            the frozen answer of every delegation call on an executor that has the circuit
            (delegation.md §2). This is the first of the three request-side zeroings; 118 and
            119 are the other two. All three key on deleg_mask and not on a type flag, so
            they are one gate apiece however many types there are.

────────────────────────────────────────────────────────────────────────────────────────────
118     deleg_read_ts_zero — the mirror query reads the answer tuple    Quadratic, degree 2
        code  add_sub::artifact                                                         S21

  positional  0 = M[21]·M[23]
  named       0 = deleg_mask·deleg_read_ts

────────────────────────────────────────────────────────────────────────────────────────────
119     deleg_read_value_zero                                           Quadratic, degree 2
        code  add_sub::artifact                                                         S21

  positional  0 = M[21]·M[24]
  named       0 = deleg_mask·deleg_read_value

  reads as (118, 119)  the tuple the request reads is T(deleg_space, deleg_addr, 0, 0)
                       exactly, and 121 is what fixes deleg_space. Only an invocation writes
                       a timestamp-0 tuple in its own space, and it writes one per row, so
                       the read pairs with an invocation of the type it named and with
                       nothing else.
                       Timestamp 0 is the stamp no ordinary cycle can produce (cycles are
                       numbered from 1), which is what lets the pair be recognised without a
                       tag (delegation.md §5.2, §5.3).

────────────────────────────────────────────────────────────────────────────────────────────
120     deleg_addr_rule — the mirror is at the frame base handed over   Quadratic, degree 2
        code  add_sub::artifact                                                         S21

  positional  0 = M[21]·M[22] − M[21]·M[14]
  named       0 = deleg_mask·(deleg_addr − rs2_read_value)

  reads as  the anchor's address is the a0 the request passed — the same a0 the rs2 query
            read at slot 2 and gate 109 pinned to register 10. So the invocation that answers
            this request permutes the frame at this pointer and no other (delegation.md §5.1).

────────────────────────────────────────────────────────────────────────────────────────────
121     deleg_space_rule — the mirror's leaf names the requested type   Linear, degree 1
        code  add_sub::artifact                                                         S23

  positional  0 = M[26] − 4·W[22] − 5·W[23] − 6·W[24] − 7·W[25]
  named       0 = deleg_space − (4·is_deleg_9 + 5·is_deleg_10 + 6·is_deleg_11
                                 + 7·is_deleg_15)

  reads as  the literals are address_space::DELEGATION_KECCAK_F, DELEGATION_POSEIDON2,
            DELEGATION_FR_ARITH and DELEGATION_MOD_MUL, read through
            constants::delegation::TYPES; the gate spells no tag of its own. It is what
            carries the type into the mirror's two leaves (§3.4), which may not read the W
            selectors themselves: a leaf reading a W column is refused by check_memory, W
            being committed after the memory challenges (memory.md §8, delegation.md §5.1,
            §10.1). Ungated and degree 1, so it holds on every row of the shard — on a row
            requesting nothing it forces deleg_space = 0, because each is_deleg_t is 0 unless
            is_ecall is 1 and is_ecall is 0 on a padding row. With 107 it is the whole of
            "which delegation, if any, this row asks for".

────────────────────────────────────────────────────────────────────────────────────────────
122     wrap_boolean          0 = W[26] − W[26]·W[26]      0 = wrap − wrap²
123     pc_wrap_boolean       0 = W[28] − W[28]·W[28]      0 = pc_wrap − pc_wrap²
        Quadratic, degree 2; code  add_sub::booleanity

────────────────────────────────────────────────────────────────────────────────────────────
124     next_pc_rule — the fall-through, or HALT_PC on the exit row     Quadratic, degree 2
        code  add_sub::artifact

  positional  0 = M[5] + 2^32·W[28] − W[8] − W[20] + W[22] + W[23] + W[24] + W[25]
                  + W[20]·W[8] − W[22]·W[8] − W[23]·W[8] − W[24]·W[8] − W[25]·W[8]
  named       0 = pc_write_value + 2^32·pc_wrap
                  − (1 − is_ecall + is_deleg_9 + is_deleg_10 + is_deleg_11 + is_deleg_15)
                    ·decoded_next_pc
                  − HALT_PC·(is_ecall − is_deleg_9 − is_deleg_10 − is_deleg_11 − is_deleg_15)
                                                                      (HALT_PC = 1)

  reads as  next_pc + 2^32·pc_wrap is decoded_next_pc on every row but the exit row, and 1
            (HALT_PC) there. **A delegation row falls through, whatever its type**: its two
            terms put it back on the decoded_next_pc branch, because a delegation call
            returns to pc + 4 and the program goes on (delegation.md §2); a new type costs
            one linear term and one product and no degree. On a live row decoded_next_pc
            is the table's fall-through, bound by decode_row; on a padding row nothing else
            binds decoded_next_pc, so it and next_pc are free together (the honest fill
            writes 0 in both). next_pc is range-checked below 2^32 on a live row and the
            fall-through is below 2^31, so pc_wrap is 0 on every live row.
```

Of the 57 gates, **5 are degree 1**: the two write-backs, `decoded_mask_bits`, `system_split`
and S23's `deleg_space_rule`. It was 10 before the frame narrowed — four write-backs and the
three `mask = 0` rules for `arg1`, `arg2` and `ram` — so the deletion took **five degree-1 gates
and three degree-2 ones**, the three mask booleanity gates of the queries that went, and the
degree-2 count is 52 where it was 55. **Every gate S23 and S26 added
or amended is degree 2, and `deleg_space_rule` is degree 1**: a registered delegation type
costs three gates and a handful of terms rather than a gate list, because a type flag
multiplies nothing but `is_ecall`, `pc_mask`, `rd_read_value`, `rd_selected`, `rs1_read_value`
and `decoded_next_pc`, each of which some gate already multiplies. All 57 have constant 0, so
each is 0 on the all-zero row, and the private `memory::assemble` records
`zero_row_valid = true` (`build::zero_on_zero_row`). The padding row itself is all zeros in
every assembled artifact (`build::assemble`), whatever its gates.

### 3.6 The 15 lookups

`CircuitArtifact::lookups`, in order. The frame's 10 come from the private
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
| 6 | `gap_hi_rd` | `TIMESTAMP` | `M[16]` | `W[3]` | `rd_gap_hi` | `< 2^19` |
| 7 | `gap_lo_rd` | `TIMESTAMP` | `M[16]` | `4·M[0] − M[18] − 2^19·W[3] + 2` | `4·cycle − rd_read_ts − 2^19·rd_gap_hi + 2` | `< 2^19` |
| 8 | `gap_hi_deleg` | `TIMESTAMP` | `M[21]` | `W[4]` | `deleg_gap_hi` | `< 2^19` |
| 9 | `gap_lo_deleg` | `TIMESTAMP` | `M[21]` | `4·M[0] − M[23] − 2^19·W[4] + 2` | `4·cycle − deleg_read_ts − 2^19·deleg_gap_hi + 2` | `< 2^19` |
| 10 | `rd_hi_range` | `RANGE16` (1) | `M[1]` | `W[27]` | `rd_hi` | `< 2^16` |
| 11 | `rd_lo_range` | `RANGE16` | `M[1]` | `W[7] − 2^16·W[27]` | `rd_selected − 2^16·rd_hi` | `< 2^16` |
| 12 | `next_pc_hi_range` | `RANGE16` | `M[1]` | `W[29]` | `next_pc_hi` | `< 2^16` |
| 13 | `next_pc_lo_range` | `RANGE16` | `M[1]` | `M[5] − 2^16·W[29]` | `pc_write_value − 2^16·next_pc_hi` | `< 2^16` |
| 14 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[8], W[9], W[10], W[11], W[12], W[13])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_imm, decoded_mask)` | a row of `S[0..7]` |

Read in pairs: `gap_hi_<q>` and `gap_lo_<q>` together say
`gap = 4·cycle + Δ_q − <q>_read_ts − 1 = lo + 2^19·hi` lies in `[0, 2^38)`, so the read strictly
precedes its own write. `rd_hi_range` and `rd_lo_range` bound `rd_selected` below `2^32`, and
the `next_pc` pair bounds the next pc the same way (`memory.md` §7's range convention).
**Lookups 8 and 9 are S21's**, and the `deleg` query is bounded exactly as the four before
it: the pair is what makes the mirror query's read obey the clock like any other, even though
the timestamp it reads is the literal 0 (§3.5, gate 118). **The six obligations the POSIX
layer's deletion took were the `arg1`, `arg2` and `ram` pairs**, each bounding a gap on a query
no row could make; nothing else moved, and neither S23 nor S26 added a lookup or moved one — a
delegation type is a selector, a tag and three gates, and none of the three is a key of any
channel.

The channels, `add_sub::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[30]` | **10** | **16** |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[31]` | 4 | 8 |
| 6, 7 | `DECODER` | 3 | `S[0..7]` | `W[32]` | 1 | 2 |

**The timestamp tree's padding is where the three lost queries gave a gate list back.** Ten
obligations and one table fraction is eleven leaves, which fits a 16-leaf tree with five pads;
at sixteen obligations it was seventeen leaves, one past 16, and the tree padded to 32 (§19
observation 20). So this circuit is five row-wise lists deep where S21 made it six, and no tree
of it sets a depth the frame does not.

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
`define_<node>_den`), as in §3.4; a product node is one column named `<node>`. There are four
row-wise reduction lists, and the layer widths are `MEM_WORD`'s (§7.7).

**`L2`, gate list 1, 34 columns, relations 125–158.**

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 125 | `read_2_0` | `read_pc · read_rs1` |
| 1 | 126 | `read_2_1` | `read_rs2 · read_rd` |
| 2 | 127 | `read_2_2` | `read_deleg · read_pad_0` |
| 3 | 128 | `read_2_3` | `read_pad_1 · read_pad_2` |
| 4–7 | 129–132 | `write_2_0` … `write_2_3` | the same over the write side |
| 8, 9 | 133, 134 | `timestamp_2_0` | `timestamp_table + gap_hi_pc` |
| 10, 11 | 135, 136 | `timestamp_2_1` | `gap_lo_pc + gap_hi_rs1` |
| 12, 13 | 137, 138 | `timestamp_2_2` | `gap_lo_rs1 + gap_hi_rs2` |
| 14, 15 | 139, 140 | `timestamp_2_3` | `gap_lo_rs2 + gap_hi_rd` |
| 16, 17 | 141, 142 | `timestamp_2_4` | `gap_lo_rd + gap_hi_deleg` |
| 18, 19 | 143, 144 | `timestamp_2_5` | `gap_lo_deleg + timestamp_pad_0` |
| 20, 21 | 145, 146 | `timestamp_2_6` | `timestamp_pad_1 + timestamp_pad_2` |
| 22, 23 | 147, 148 | `timestamp_2_7` | `timestamp_pad_3 + timestamp_pad_4` |
| 24, 25 | 149, 150 | `range16_2_0` | `range16_table + rd_hi_range` |
| 26, 27 | 151, 152 | `range16_2_1` | `rd_lo_range + next_pc_hi_range` |
| 28, 29 | 153, 154 | `range16_2_2` | `next_pc_lo_range + range16_pad_0` |
| 30, 31 | 155, 156 | `range16_2_3` | `range16_pad_1 + range16_pad_2` |
| 32, 33 | 157, 158 | `decoder_2_0` | `decoder_table + decode_row` |

Positionally, `timestamp_2_0` is `L{2}[8] = L{1}[16]·L{1}[19] + L{1}[18]·L{1}[17]` and
`L{2}[9] = L{1}[17]·L{1}[19]`: `−mult/(T + g) + 1/(E_gap_hi_pc + g)`, the node `lookup.md` §6
puts first on purpose. `read_2_2` and `read_2_3` are the nodes the frame's narrowing changed:
they multiplied two real leaves when the frame was eight queries and now carry the pads.

**`L3`, gate list 2, 18 columns, relations 159–176.**

| `L3` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 159 | `read_3_0` | `read_2_0 · read_2_1` |
| 1 | 160 | `read_3_1` | `read_2_2 · read_2_3` |
| 2, 3 | 161, 162 | `write_3_0`, `write_3_1` | the same over the write side |
| 4, 5 | 163, 164 | `timestamp_3_0` | `timestamp_2_0 + timestamp_2_1` |
| 6, 7 | 165, 166 | `timestamp_3_1` | `timestamp_2_2 + timestamp_2_3` |
| 8, 9 | 167, 168 | `timestamp_3_2` | `timestamp_2_4 + timestamp_2_5` |
| 10, 11 | 169, 170 | `timestamp_3_3` | `timestamp_2_6 + timestamp_2_7` |
| 12, 13 | 171, 172 | `range16_3_0` | `range16_2_0 + range16_2_1` |
| 14, 15 | 173, 174 | `range16_3_1` | `range16_2_2 + range16_2_3` |
| 16, 17 | 175, 176 | `decoder_3_0` | copy of `decoder_2_0` |

**`L4`, gate list 3, 10 columns, relations 177–186.**

| `L4` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 177 | `read_4_0` | `read_3_0 · read_3_1` |
| 1 | 178 | `write_4_0` | `write_3_0 · write_3_1` |
| 2, 3 | 179, 180 | `timestamp_4_0` | `timestamp_3_0 + timestamp_3_1` |
| 4, 5 | 181, 182 | `timestamp_4_1` | `timestamp_3_2 + timestamp_3_3` |
| 6, 7 | 183, 184 | `range16_4_0` | `range16_3_0 + range16_3_1` |
| 8, 9 | 185, 186 | `decoder_4_0` | copy of `decoder_3_0` |

**`L5`, gate list 4, 8 columns, relations 187–194** — the row-wise top: one value per row per
tree.

| `L5` | relations | node | formula | value at row `y` |
| --- | --- | --- | --- | --- |
| 0 | 187 | `read_5_0` | copy of `read_4_0` | the product of row `y`'s 8 read leaves |
| 1 | 188 | `write_5_0` | copy of `write_4_0` | the product of row `y`'s 8 write leaves |
| 2, 3 | 189, 190 | `timestamp_5_0` | `timestamp_4_0 + timestamp_4_1` | the sum of row `y`'s 16 timestamp fractions |
| 4, 5 | 191, 192 | `range16_5_0` | copy of `range16_4_0` | the sum of row `y`'s 8 range16 fractions |
| 6, 7 | 193, 194 | `decoder_5_0` | copy of `decoder_4_0` | the sum of row `y`'s 2 decoder fractions |

`checker::memory_roots` recomputes the two roots from `L5[0]` and `L5[1]`, the layer the first
halving list reads.

### 3.8 The halving layers and the outputs

Gate list `k`, for `5 ≤ k ≤ n + 4`, halves layer `k` into layer `k + 1`, which has
`n + 4 − k` variables. Its eight gates, relation `r = 195 + 8(k − 5)`:

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
of `memory.md` §4.2. **Since S21 that product also runs over the delegation shards**, whose two
roots enter it exactly as a CPU shard's do (§12.7): an invocation's frame reads and writes are
ordinary RAM tuples, and its anchor pair cancels against a request's.

### 3.9 Witness rows

The table shows ten of the seventeen `honest_rows` in `crates/checker/tests/add_sub.rs`. The
other seven are `add, not carrying`, `sub, not borrowing`, `addi from x0, as c.li` (a 4-byte
`addi`, despite its name), `auipc, not carrying`, `sub to x0, borrowing`, `nop`
(`addi x0, x0, 0`) and `c.add, two bytes` (an `add` whose fall-through is `0x10012`); §3.10
probes all seventeen. Each row is built from Rust's own `u32` arithmetic, and
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
`H` exit 42. **`I` keccak delegation request** (S21): `a7 = 0x501`, `a0 = 0x10400`, the frame
base it hands over, and `a0` written back 0. `P` padding. A `POSEIDON2`, `FR_ARITH` or
`MOD_MUL` request is the same row with `a7` `0x500`, `0x502` or `0x504`, its own selector at
`W[23]`, `W[24]` or `W[25]` and its own tag 5, 6 or 7 at `M[26]`; the suite carries one of the
four, the gates being one loop over the registry.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `I` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[2]` `pc_addr` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `M[3]` `pc_read_ts` | 32 | 32 | 32 | 32 | 32 | 32 | 32 | 32 | 32 | 0 |
| `M[4]` `pc_read_value` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | `0x10010` | 0 |
| `M[5]` `pc_write_value` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | 1 | `0x10014` | 0 |
| `M[6]` `rs1_mask` | 1 | 1 | 1 | 0 | 0 | 1 | 0 | 1 | 1 | 0 |
| `M[7]` `rs1_addr` | 5 | 6 | 5 | 0 | 0 | 5 | 0 | 17 | 17 | 0 |
| `M[8]` `rs1_read_ts` | 29 | 29 | 29 | 0 | 0 | 29 | 0 | 29 | 29 | 0 |
| `M[9]`, `M[10]` `rs1_read_value`, `rs1_write_value` | `0xffffefff` | `0x12345678` | `0xfffff000` | 0 | 0 | `0xffffefff` | 0 | 93 | `0x501` | 0 |
| `M[11]` `rs2_mask` | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 1 | 1 | 0 |
| `M[12]` `rs2_addr` | 6 | 5 | 0 | 0 | 0 | 6 | 0 | 10 | 10 | 0 |
| `M[13]` `rs2_read_ts` | 30 | 30 | 0 | 0 | 0 | 30 | 0 | 30 | 30 | 0 |
| `M[14]`, `M[15]` `rs2_read_value`, `rs2_write_value` | `0x12345678` | `0xffffefff` | 0 | 0 | 0 | `0x12345678` | 0 | 42 | `0x10400` | 0 |
| `M[16]` `rd_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 0 |
| `M[17]` `rd_addr` | 7 | 29 | 5 | 31 | 6 | 0 | 0 | 10 | 10 | 0 |
| `M[18]` `rd_read_ts` | 31 | 31 | 31 | 31 | 31 | 31 | 0 | 31 | 31 | 0 |
| `M[19]` `rd_read_value` | 3 | 1 | `0xfffff000` | 0 | 0 | 0 | 0 | 42 | 7 | 0 |
| `M[20]` `rd_write_value` | `0x12344677` | `0x12346679` | `0xffffefff` | `0xf010` | `0x12345000` | 0 | 0 | 42 | 0 | 0 |
| `M[21]` `deleg_mask` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| `M[22]` `deleg_addr` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | `0x10400` | 0 |
| `M[23]`, `M[24]`, `M[25]` `deleg_read_ts`, `deleg_read_value`, `deleg_write_value` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `M[26]` `deleg_space` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 4 | 0 |
| `W[0..5]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[5]` `rd_inv` | `7⁻¹` | `29⁻¹` | `5⁻¹` | `31⁻¹` | `6⁻¹` | 0 | 0 | `10⁻¹` | `10⁻¹` | 0 |
| `W[6]` `rd_is_zero` | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 |
| `W[7]` `rd_selected` | `0x12344677` | `0x12346679` | `0xffffefff` | `0xf010` | `0x12345000` | `0x12344677` | 0 | 42 | 0 | 0 |
| `W[8]` `decoded_next_pc` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | `0x10014` | 0 |
| `W[9]` `decoded_rs1` | 5 | 6 | 5 | 0 | 0 | 5 | 0 | 0 | 0 | 0 |
| `W[10]` `decoded_rs2` | 6 | 5 | 0 | 0 | 0 | 6 | 0 | 0 | 0 | 0 |
| `W[11]` `decoded_rd` | 7 | 29 | 5 | 31 | 6 | 0 | 0 | 0 | 0 | 0 |
| `W[12]` `decoded_imm` | 0 | 0 | `0xffffffff` | `0xfffff000` | `0x12345000` | 0 | 2 | 0 | 0 | 0 |
| `W[13]` `decoded_mask` | 8 | 16 | 2 | 4 | 32 | 8 | 1 | 1 | 1 | 0 |
| `W[14..20]` the kind bit set | `add` | `sub` | `addi` | `auipc` | `lui` | `add` | `system` | `system` | `system` | none |
| `W[20]` `is_ecall` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 0 |
| `W[21]` `is_fence` | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 |
| `W[22]` `is_deleg_9` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 | 0 |
| `W[23]`, `W[24]`, `W[25]` `is_deleg_10`, `is_deleg_11`, `is_deleg_15` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[26]` `wrap` | 1 | 1 | 1 | 1 | 0 | 1 | 0 | 0 | 0 | 0 |
| `W[27]` `rd_hi` | `0x1234` | `0x1234` | `0xffff` | 0 | `0x1234` | `0x1234` | 0 | 0 | 0 | 0 |
| `W[28]` `pc_wrap` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[29]` `next_pc_hi` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 | 1 | 0 |

`F` computes the same sum as `A` and writes 0: `rd_selected` still holds the result, and
`rd_write_masked` masks it. `H`'s decoded fall-through is `0x10014` while its next pc is 1.
**`I` and `H` are the same instruction word** — a `SYSTEM` row with code `ECALL` — and every
column that differs between them follows from one cell, the `a7` the `rs1` query reads: `0x501`
instead of 93 sets `is_deleg_9`, which makes the `deleg` query present (`deleg_mask_rule`),
names address space 4 in `deleg_space` (`deleg_space_rule`), makes the answer 0
(`deleg_writes_no_register`) and makes the next pc the fall-through (`next_pc_rule`), and which
turns `ecall_is_exit` and `exit_status` off. That is the whole of the delegation row kind, and
the type is the whole of what one delegation row differs from another by.

### 3.10 What fixes each cell

All seventeen `honest_rows`, probed one cell at a time: a cell is listed below when adding 5 to
it alone breaks no gate and no range obligation, evaluated row-locally (as `violated_relations`
and `violated_lookups` evaluate a row). Adding 5 never probes a boolean column, whose
booleanity gate refuses 5, so each boolean column was also flipped between 0 and 1; that finds
two more cells, marked (flip). A cell listed is fixed, if at all, by something that is not
row-local: the **memory argument**, when the cell is in a leaf whose mask is 1; the **decoder
table**, when it is in `decode_row`'s tuple on a live row; or nothing. The multiplicities
`W[30..33]` appear on every row and are not a row's property at all.

A read timestamp is a case apart. Its gap obligations hold it only in
`[4·cycle + Δ_q − 2^38, 4·cycle + Δ_q)`, which the timestamp of any earlier write satisfies, so
the memory argument alone fixes it. `+5` happens to stay inside a register's synthetic gap of 7,
so `M[8]`, `M[13]` and `M[18]` show up on every row; the pc's gap is 3, so `M[3]` shows up on
padding alone, but on a live row a rise of 1 to 3 passes too, and so does a fall to any earlier
timestamp once `pc_gap_hi` is re-chosen (a fall of less than `2^19 − 3` passes with it unchanged).

| cell | fixed, on the rows that use it, by | rows where less fixes it, or nothing |
| --- | --- | --- |
| `M[0]` `cycle` | the memory argument (every write leaf's timestamp), with the gap obligations bounding it below | padding: nothing |
| `M[1]` `pc_mask` (flip) | its booleanity gate, the mask rules through the row's other masks, and the memory argument | fence: the memory argument alone (1 → 0 breaks no gate, since the row has no other query for a mask rule to tie to it, and it switches every lookup off); padding: 0 → 1 is refused by `gap_lo_pc`, whose gap becomes −1 |
| `M[2]` `pc_addr` | the memory argument alone: no gate holds it to 0, but a pc chain at any other address has no initial and no final tuple, and cannot balance (`memory.md` §4.2's counting) | padding: nothing |
| `M[4]` `pc_read_value` | the memory argument and the decoder table; on an auipc row, also `add_addi_auipc` | padding: nothing |
| `M[3]`, `M[8]`, `M[13]`, `M[18]` read timestamps | the memory argument alone; the gap obligations only hold each below its own write | rows without that query, padding included: nothing |
| `M[7]` `rs1_addr` | `rs1_addr_rule` | auipc, lui, fence, padding: nothing |
| `M[12]` `rs2_addr` | `rs2_addr_rule` | addi (nop included), auipc, lui, fence, padding: nothing |
| `M[17]` `rd_addr` | `rd_addr_rule` | fence, padding: nothing |
| `M[19]` `rd_read_value` | the memory argument; on the exit row, also `exit_status` | fence, **the delegation row**, padding: nothing — `exit_status` is off there, and 117 reads `rd_selected` rather than what `a0` held |
| `M[22]` `deleg_addr` | `deleg_addr_rule`, and the memory argument | every row but the delegation row: nothing, the mask being 0 |
| `M[23]` `deleg_read_ts` | `deleg_read_ts_zero`, with `gap_lo_deleg` | every row but the delegation row: nothing |
| `M[24]` `deleg_read_value` | `deleg_read_value_zero` | every row but the delegation row: nothing |
| `M[25]` `deleg_write_value` | the memory argument alone, **on every row including the delegation row**: no gate reads it | every row: no gate |
| `W[0]` `pc_gap_hi` | its gap obligations | padding: nothing |
| `W[1]`, `W[2]`, `W[3]`, `W[4]` gap chunks | their gap obligations | rows without that query: nothing |
| `W[5]` `rd_inv` | `rd_is_zero_inverse`, where `rd_addr ≠ 0` | rows writing `x0` (nop included), fence, padding: nothing |
| `W[8]` `decoded_next_pc` | `next_pc_rule` and the decoder table | the exit row: the decoder table alone, since `next_pc_rule` cancels it there — **but not the delegation row**, which falls through, so `next_pc_rule` ties it there like any ordinary row; padding: `next_pc_rule` alone, which only ties it to `pc_write_value` and `pc_wrap` |
| `W[9]` `decoded_rs1` | `rs1_addr_rule` and the decoder table | auipc, lui and fence rows: the decoder table alone; padding: nothing |
| `W[10]` `decoded_rs2` | `rs2_addr_rule` and the decoder table | addi, auipc, lui and fence rows: the decoder table alone; padding: nothing |
| `W[11]` `decoded_rd` | `rd_addr_rule` and the decoder table | fence rows: the decoder table alone; padding: nothing |
| `W[12]` `decoded_imm` | the gate its kind reads it in, and the decoder table | sub rows: the decoder table alone; padding: nothing |
| `W[26]` `wrap` (flip) | `add_addi_auipc` or `sub` | lui, fence, exit, **the delegation row** and padding: `wrap_boolean` alone, since the two gates that read it are gated off there |
| `W[27]` `rd_hi`, `W[29]` `next_pc_hi` | their range obligations | padding: nothing |

**Three rows left this table when the frame narrowed**, and each was there for the same reason:
the `arg1`, `arg2` and `ram` columns and their three gap chunks were fixed by nothing on any
row, and the `arg1` and `arg2` write-back pairs were fixed only by a gate that a pair moved
together keeps. They were the registry's largest block of cells nothing constrained, and they
are gone rather than constrained (§21 observation 2).

On a padding row every mask is 0 and every lookup is switched off, so no cell there reaches a
memory event or a table. The gates still hold `pc_write_value + 2^32·pc_wrap = decoded_next_pc`
and `rd_write_value = rd_selected` there; the honest fill writes 0 everywhere. A fence row,
whose `rd_mask` is 0, leaves the pair `rd_selected`, `rd_write_value` free but for its range
obligations: `rd_write_masked` holds the two equal (the row's `rd_is_zero` is 0),
`rd_hi_range` and `rd_lo_range` keep `rd_selected` below `2^32`, and nothing else reads either.

**`deleg_space` is the one frame column no row leaves free.** `deleg_space_rule` is ungated and
degree 1, so it is not in the table above at all: adding 5 breaks it on the padding row exactly
as on the delegation row, and no other gate, obligation or table is needed to fix the cell. That
is what a type tag has to be — the mirror's leaf reads it on every row, and a leaf is not gated
by anything a row chooses.

**`deleg_write_value` is free on every row, and that is the design** (§21 observation 19). It is
one half of the anchor's answer pair, and its other half is §12's `anchor_value`: nothing fixes
either locally, and the two must be equal or the multiset does not balance. A prover that writes
7 on both sides proves the same statement; a prover that writes 7 on one is refused as
`MemoryArgument`, which is `delegation.md` §5.2's whole argument.

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
on every live row. The generic table's all-zero tuple repeats on every row past `2^17 + 32`,
and the count goes to the lowest, row 0.

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
| `S[7]` | `generic_key` | `jump_branch_slt::GENERIC_TABLE[0]`, `channels()[2].table[0]` | Generic key | 0, `AND_BASE + a + 1`, `SIGN_BASE + h + 1` or `SHIFT_BASE + s + 1` | `generic_table_den` | 1 |
| `S[8]` | `generic_value` | `GENERIC_TABLE[1]` | Generic value | 0, `b`, `h >> 15` or `2^s` | `generic_table_den` | `β` |
| `S[9]` | `generic_result` | `GENERIC_TABLE[2]` | Generic result | 0, `a & b`, 0 or `2^(31 − s)` | `generic_table_den` | `β²` |

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

  reads as (90–93)  §3.5's 75–78 over the REG layout. S17 builds 90 and 91 through
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
`[257, 2^16 + 256]`, `U16GetSign`'s keys, never the `ZeroEntry`, an AND key or a `ShiftPowers`
key (`lookup.md` §4's precondition), so the only row that key can meet is
`(hi + 257, hi >> 15, 0)` and each sign is its operand's bit 31.

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
            nothing; on a bitwise row §5.6's key bound holds each `byte_a_j` below 256 and
            the AND row it matches holds `byte_b_j` there, so all eight are bytes and the
            decomposition is the unique one.

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
**No gate bounds `amount` to `[0, 32)`; its key bound does, and `ShiftPowers`' domain again** —
the table's holding because `ShiftPowers` is the highest sub-table and a key past its last row
matches nothing at all. Which is why the suite's
`an_untruncated_amount_is_refused_by_its_scaled_bound_and_the_table` builds a row whose `amount`
is 33 with `pow = 2^33` and a copower of `2^-2`, so that `pow·copow` is still `2^31`, and finds
`amount_scaled` and the lookup refusing it together.

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
further tests isolate one bound or one gate each. §5.5's 171 derives `or` and `xor` from the one
AND accumulator by linearity, so the AND table is the only one either reads.

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

- **`amount` above 31**: nothing in gate list 0, and not `amount_range` either, 33 being a
  perfectly good halfword. `amount_scaled` refuses it and so does `ShiftPowers`' domain, which is
  the point of `an_untruncated_amount_is_refused_by_its_scaled_bound_and_the_table` — an `sll by
  rs2 = 33, small rs1` row claiming to shift by 33, with `pow = 2^33` and a copower of `2^-2` so
  that `copower_rule` still holds, an `ovf` of `rs1·2` that is still a word, and a result of 0.
  Every gate accepts it; the two obligations on its key are the refusal.
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
(`W[7..12]`), the decoder tuple six wide, the setup subtree **nine** columns where a family
carrying both an immediate and the packed table commits ten, the packed generic table `S[6..9]`
rather than `S[7..10]`, and the decoder denominator's top `β` power `β⁵` rather than `β⁶`
(§0.4). Since S19 it shares that shape with `ATOMICS` (§9), whose tuple has no immediate for
the same reason — RV32A is all R-type — so the two of them are the registered circuits whose
`g_dec` is `g − Σ_{j<6} β^j`.

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
whose value is 0. That is the simplest multiplicity picture of the seven registered execution
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
- **`a_quotient_off_by_one_is_refused_by_the_gap_or_by_the_identity`** — the two gates that
  between them leave no room for a neighbouring quotient.
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

## 7. `MEM_WORD` — family 4

### 7.1 Header

`family_circuit(4, n)` is `mem_word::artifact(n)` with `mem_word::channels()`, built by
`memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` through the private
`family_spec` (`QUERIES`, the `SLOT_*` constants and the per-kind constants `LW` and `SW` are
private to `mem_word.rs`). It uses no S17 or S18 gadget: `is_zero` reaches it only through the
frame's x0 rule, which `memory` builds. Normative spec: `memory-ops.md` §3. Fill:
`prover::family_fill(4)`, the private `fill::mem_word`.

62 committed columns (31 `M`, 24 `W`, 7 `S`) and two virtual tables. Gate list 0 writes 68
leaves and holds 33 enforcing gates. 18 lookups on **three** channels, 8 outputs. At `n = 20`,
the height S19 proves, there are 25 gate lists, the top is `L25`, and the circuit has 298 inner
columns and 331 relations; a shard proof of it is 56,268 bytes. At `n = 22` — the committed
fixture — there are 27 lists, the top is `L27`, and it has 314 inner columns, 347 relations and
60,383 bytes of wire form.

**It reads no generic channel, and it is the second registered family that does not.**
`FamilyCircuit::reads_generic_table` is false, so the setup subtree is the decoded table alone —
seven columns, all of them identity's — and a shard opens 62 commitments and no packed-table
triple (`shard-proof.md` §3, §5.1; `jump-branch-slt.md` §6).
`ADD_SUB_LUI_AUIPC` is the precedent for that shape and the only other one.

`artifact` panics unless the frame is `QUERIES`, the channels carry exactly 12, 5 and 1
obligations, `lookup::check_copowers` finds a direct range pair under the same selector for
`word_index_hi` — the one column it bounds by scaling — and every gate is zero on the all-zero
row. It also panics on every refusal of the assembly, among them `n < 19` (the 19-bit timestamp
table needs 19 variables) and `n > 30` (`MAX_TRACE_VARS`); `family_circuit` returns `None` for
both rather than calling it.

### 7.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::mem_word`, bit `k` being
`W[15 + k]`. The decoded table's `imm` is the load's or store's sign-extended twelve-bit
displacement as a two's-complement `u32`; `next_pc` is the fall-through, and no kind here
computes a pc. The effective address is `rs1 + imm` reduced mod `2^32`, split into
`4·word_index` with a wrap bit (`memory-ops.md` §2). **There are no offset bits**: a word access
takes the whole word, so a misaligned `lw` or `sw` has no witness at all (§7.10).

| row kind | bit (`decoded_mask`) | queries present | what it reads | `rd_selected` | `ram_write_value` | `next_pc` |
| --- | --- | --- | --- | --- | --- | --- |
| `lw` | 0 (1) | pc rs1 load rd | `rs1`, and the word at `4·word_index` | the word it read | 0 — no `ram` query | the fall-through |
| `sw` | 1 (2) | pc rs1 rs2 ram | `rs1`, `rs2`, and the word it overwrites | 0 — no `rd` query | `rs2` | the fall-through |
| padding | none; all 0 | none | nothing | 0 | 0 | 0 |

Both kinds are provable at S19. `rd = x0` is not a kind: on an `lw` row into `x0` the table's
`rd` is 0, the frame's x0 rule writes 0, and `rd_selected` keeps the loaded word, which is what
its own range pair bounds (§7.9's row `C`). `rs1 = x0` is not a kind either — a present query at
address 0 reading 0, so the displacement is the whole address. Both kinds have compressed forms
(`c.lw`, `c.sw`, `c.lwsp`, `c.swsp`), so both fall-through widths occur. A live row at a pc
holding no instruction of the family meets the table's `MINUS_ONE` row, which its decoder tuple
cannot equal.

**What this family does not confine is which word a row may name.** An address in no committed
RAM window is refused by the multiset argument at `verify_shard` step 10 and by nothing here
(`memory-ops.md` §2, `memory.md` §9).

### 7.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §7.4 and §7.6.

**Memory-argument columns, `M[0..31]`** — §2's MEM layout (`w = 6`), the 31 columns
`MEM_SUBWORD` also carries and the same bare frame fixture (`memory_frame_mem.bin`), filled by
`trace::build_memory_columns`; committed in `PublicInputs::memory_commitments`, absorbed at G8
before the memory challenges. The frame's slots in `mem_word.rs` are `SLOT_PC = 0`,
`SLOT_RS1 = 1`, `SLOT_RS2 = 2`, `SLOT_LOAD = 3`, `SLOT_RAM = 4`, `SLOT_RD = 5`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 6); obligations `gap_lo_*` (all 6) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, the five mask rules; selector of `gap_hi_pc`, `gap_lo_pc`, all five `RANGE16` obligations and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | the fall-through | leaf `write_pc`; `next_pc_rule` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on both kinds | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | Base register | the decoded `rs1` | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | Base address | | leaf `read_rs1`; `rs1_writes_back`, `rs1_value_masked`, `addr_split` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on `sw` | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | Source register | the decoded `rs2` | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | The word a store writes | 0 on an `lw` row | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `store_value_rule` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `load_mask` | `frame(3, FIELD_MASK)` | The load's word is present | 1 on `lw` | leaves `read_load`, `write_load`; `load_mask_boolean`, `load_mask_rule`, `load_addr_rule`; selector of `gap_hi_load`, `gap_lo_load` |
| `M[17]` | `load_addr` | `frame(3, FIELD_ADDR)` | The word's byte address | `4·word_index` | leaves `read_load`, `write_load`; `load_addr_rule` |
| `M[18]` | `load_read_ts` | `frame(3, FIELD_READ_TS)` | The word's previous write | | leaf `read_load`; `gap_lo_load` |
| `M[19]` | `load_read_value` | `frame(3, FIELD_READ_VALUE)` | The word loaded | | leaf `read_load`; `load_writes_back`, `rd_value_rule` |
| `M[20]` | `load_write_value` | `frame(3, FIELD_WRITE_VALUE)` | The word written back | `load_read_value` | leaf `write_load`; `load_writes_back` |
| `M[21]` | `ram_mask` | `frame(4, FIELD_MASK)` | The store's word is present | 1 on `sw` | leaves `read_ram`, `write_ram`; `ram_mask_boolean`, `ram_mask_rule`, `ram_addr_rule`, `store_value_rule`; selector of `gap_hi_ram`, `gap_lo_ram` |
| `M[22]` | `ram_addr` | `frame(4, FIELD_ADDR)` | The word's byte address | `4·word_index` | leaves `read_ram`, `write_ram`; `ram_addr_rule` |
| `M[23]` | `ram_read_ts` | `frame(4, FIELD_READ_TS)` | The word's previous write | | leaf `read_ram`; `gap_lo_ram` |
| `M[24]` | `ram_read_value` | `frame(4, FIELD_READ_VALUE)` | The word overwritten | | leaf `read_ram` **and nothing else** (§13) |
| `M[25]` | `ram_write_value` | `frame(4, FIELD_WRITE_VALUE)` | The word stored | `rs2_read_value` | leaf `write_ram`; `store_value_rule` |
| `M[26]` | `rd_mask` | `frame(5, FIELD_MASK)` | rd present | 1 on `lw` | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[27]` | `rd_addr` | `frame(5, FIELD_ADDR)` | rd register | the decoded `rd` | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[28]` | `rd_read_ts` | `frame(5, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[29]` | `rd_read_value` | `frame(5, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd` **and nothing else** |
| `M[30]` | `rd_write_value` | `frame(5, FIELD_WRITE_VALUE)` | rd new value | the loaded word, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |

**Witness columns, `W[0..24]`** — `W[0..8]` filled by `trace::build_frame_witness`, `W[8..21]`
by `fill::mem_word` (`W[8]` in place of S14's), `W[21..24]` by `trace::build_multiplicities`
inside `prover::shard_columns`; committed in `ShardProof::witness_commitments`, absorbed at S3
before `g` and `β`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0]` | `pc_gap_hi` | `memory::gap_hi(0)` | pc gap, high chunk | 0: a pc read's gap is always 3 | `gap_hi_pc`, `gap_lo_pc` |
| `W[1]` | `rs1_gap_hi` | `gap_hi(1)` | rs1 gap, high chunk | `gap >> 19` | `gap_hi_rs1`, `gap_lo_rs1` |
| `W[2]` | `rs2_gap_hi` | `gap_hi(2)` | rs2 gap, high chunk | | `gap_hi_rs2`, `gap_lo_rs2` |
| `W[3]` | `load_gap_hi` | `gap_hi(3)` | Load-word gap, high chunk | | `gap_hi_load`, `gap_lo_load` |
| `W[4]` | `ram_gap_hi` | `gap_hi(4)` | Store-word gap, high chunk | | `gap_hi_ram`, `gap_lo_ram` |
| `W[5]` | `rd_gap_hi` | `gap_hi(5)` | rd gap, high chunk | | `gap_hi_rd`, `gap_lo_rd` |
| `W[6]` | `rd_inv` | `memory::rd_inv(6)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[7]` | `rd_is_zero` | `memory::rd_is_zero(6)` | rd is `x0` | | `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_is_zero_boolean`, `rd_write_masked` |
| `W[8]` | `rd_selected` | `memory::rd_selected(6)`; `sel` in `mem_word.rs` | Loaded value | the word an `lw` read, `rd = x0` included; 0 on a store | `rd_write_masked`, `rd_value_rule`; `rd_lo_range` |
| `W[9]` | `decoded_next_pc` | `mem_word::DECODED[0]`; `SEQ` | Decoded fall-through | the table row's `next_pc` | `next_pc_rule`; `decode_row` position 1 |
| `W[10]` | `decoded_rs1` | `DECODED[1]` | Decoded rs1 | | `rs1_addr_rule`; `decode_row` position 2 |
| `W[11]` | `decoded_rs2` | `DECODED[2]` | Decoded rs2 | | `rs2_addr_rule`; `decode_row` position 3 |
| `W[12]` | `decoded_rd` | `DECODED[3]` | Decoded rd | | `rd_addr_rule`; `decode_row` position 4 |
| `W[13]` | `decoded_imm` | `DECODED[4]`; `IMM` | Decoded displacement | the sign-extended offset | `addr_split`; `decode_row` position 5 |
| `W[14]` | `decoded_mask` | `DECODED[5]` | Decoded kind mask | `1 << bit` | `decoded_mask_bits`; `decode_row` position 6 |
| `W[15]` | `kind_lw` | `KINDS[0]`; `LW` | lw row | | `kind_lw_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `load_mask_rule`, `rd_mask_rule`, `rd_value_rule` |
| `W[16]` | `kind_sw` | `KINDS[1]`; `SW` | sw row | | `kind_sw_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `ram_mask_rule` |
| `W[17]` | `wrap` | `mem_word::WRAP` | Address carry | 1 where `rs1 + imm ≥ 2^32` | `wrap_boolean`, `addr_split` |
| `W[18]` | `word_index` | `WORD_INDEX` | The accessed word's index | `addr / 4` | `load_addr_rule`, `ram_addr_rule`, `addr_split`; `word_index_lo_range` |
| `W[19]` | `word_index_hi` | `WORD_INDEX_HI` | `word_index`, high halfword | `addr >> 18` | `word_index_hi_range`, `word_index_lo_range`, `word_index_hi_scaled` |
| `W[20]` | `rd_hi` | `RD_HI` | Loaded value, high halfword | `rd_selected >> 16` | `rd_hi_range`, `rd_lo_range` |
| `W[21]` | `mult_timestamp` | `MULTIPLICITIES[0]` | Timestamp-table count | per table row `t`: the gated gap chunks equal to `t` | leaf `timestamp_table_num` |
| `W[22]` | `mult_range16` | `MULTIPLICITIES[1]` | 16-bit-table count | per table row `t`: the gated halfwords equal to `t`, all five obligations under `pc_mask` | leaf `range16_table_num` |
| `W[23]` | `mult_decoder` | `MULTIPLICITIES[2]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all seven positions) on the table's lowest non-live row, row 0 | leaf `decoder_table_num` |

**Every `RANGE16` obligation of this family is under `pc_mask`**, so on a live row all five are
on and on a padding row all five are off; there is no second selector anywhere in the circuit.
Row 0 of `mult_timestamp` and `mult_range16` therefore counts the twelve and five switched-off
tuples of every padding row, plus every live chunk or halfword whose value is 0.

**Setup columns, `S[0..7]`** — one table. `S[0..7]` is the family's decoded table,
`program::lookup_tuple(4)` order, filled by `program::FamilyTable::column_poly(j)`; committed in
program identity (`program::setup_commitments`) and carried as `VerifyingKey::setup_commitments`
for the family. There is no second setup group: this is the only S19 family with none.

| address | name | Rust | descriptive name | contents | read by | weight |
| --- | --- | --- | --- | --- | --- | --- |
| `S[0]` | `table_pc` | `mem_word::channels()[2].table[0]` | Table pc | `RowField::Pc` | `decoder_table_den` | 1 |
| `S[1]` | `table_next_pc` | `channels()[2].table[1]` | Table fall-through | `RowField::NextPc` | `decoder_table_den` | `β` |
| `S[2]` | `table_rs1` | `channels()[2].table[2]` | Table rs1 | `RowField::Rs1` | `decoder_table_den` | `β²` |
| `S[3]` | `table_rs2` | `channels()[2].table[3]` | Table rs2 | `RowField::Rs2` | `decoder_table_den` | `β³` |
| `S[4]` | `table_rd` | `channels()[2].table[4]` | Table rd | `RowField::Rd` | `decoder_table_den` | `β⁴` |
| `S[5]` | `table_imm` | `channels()[2].table[5]` | Table displacement | `RowField::Imm` | `decoder_table_den` | `β⁵` |
| `S[6]` | `table_extra_mask` | `channels()[2].table[6]` | Table kind mask | `RowField::ExtraMask` | `decoder_table_den` | `β⁶` |

`mem_word::TABLE_WIDTH` is 7.

**Virtual tables** — never committed, never opened; `gkr_verify::verify` evaluates their closed
forms.

| address | name | Rust | descriptive name | value at row `y` | read by |
| --- | --- | --- | --- | --- | --- |
| `V[range19]` | `range19` | `VirtualKind::Range19`, wire tag 2 | 19-bit range table | `y mod 2^19` | `timestamp_table_den` |
| `V[range16]` | `range16` | `VirtualKind::Range16`, wire tag 3 | 16-bit range table | `y mod 2^16` | `range16_table_den` |

### 7.4 Gate list 0: the 68 leaves

A leaf's relation number equals its `L1` offset, 0 to 67.

**The memory product trees.** The read side is `L1[0..8]` and the write side `L1[8..16]`, each
leaf per §0.6. Six queries fill eight leaves a side, so each side carries **two** pads.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_load` | `M[16]` | 2 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `read_ram` | `M[21]` | 2 | `M[22]` | `M[23]` | `M[24]` |
| 5 | `read_rd` | `M[26]` | 1 | `M[27]` | `M[28]` | `M[29]` |
| 6, 7 | `read_pad_0`, `read_pad_1` | — | — | — | — | the literal 1 |
| 8 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 9 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 10 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 11 | `write_load` | `M[16]` | 2 | `M[17]` | `4·M[0] + 2` | `M[20]` |
| 12 | `write_ram` | `M[21]` | 2 | `M[22]` | `4·M[0] + 3` | `M[25]` |
| 13 | `write_rd` | `M[26]` | 1 | `M[27]` | `4·M[0] + 3` | `M[30]` |
| 14, 15 | `write_pad_0`, `write_pad_1` | — | — | — | — | the literal 1 |

`load` and `ram` are the two RAM-space queries, `AS = 2`, and they are the whole difference
from §3's, §4's, §5's and §6's read sides. Their `Δ`s differ — 2 for the load's word, 3 for the
store's — which is how one cycle can read a word at slot 2 and rewrite one at slot 3
(`execution-trace.md` §7); no row of this family does both.

**The `timestamp` fraction tree**, `L1[16..48]`: 16 fractions, the table's then 12 gap
obligations then 3 pads. Fraction `i` is `(L1[16 + 2i], L1[17 + 2i])`, named `<node>_num` and
`<node>_den`.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 16, 17 | `timestamp_table` | `−mult_timestamp` | `V[range19] + g` |
| 1 | 18, 19 | `gap_hi_pc` | 1 | `g + pc_mask·pc_gap_hi` |
| 2 | 20, 21 | `gap_lo_pc` | 1 | `g − pc_mask + 4·pc_mask·cycle − pc_mask·pc_read_ts − 2^19·pc_mask·pc_gap_hi` |
| 3, 4 | 22–25 | `gap_hi_rs1`, `gap_lo_rs1` | 1 | as 1, 2 over `rs1`, whose `Δ − 1` is 0 |
| 5, 6 | 26–29 | `gap_hi_rs2`, `gap_lo_rs2` | 1 | over `rs2`, `Δ − 1 = 1` |
| 7, 8 | 30–33 | `gap_hi_load`, `gap_lo_load` | 1 | over `load`, `Δ − 1 = 1` |
| 9, 10 | 34–37 | `gap_hi_ram`, `gap_lo_ram` | 1 | over `ram`, `Δ − 1 = 2` |
| 11, 12 | 38–41 | `gap_hi_rd`, `gap_lo_rd` | 1 | over `rd`, `Δ − 1 = 2` |
| 13–15 | 42–47 | `timestamp_pad_0` … `timestamp_pad_2` | 0 | 1 |

**The `range16` fraction tree**, `L1[48..64]`: 8 fractions, the table's then 5 obligations then
2 pads. Every obligation is under `pc_mask`.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 48, 49 | `range16_table` | `−mult_range16` | `V[range16] + g` |
| 1 | 50, 51 | `word_index_hi_range` | 1 | `g + pc_mask·word_index_hi` |
| 2 | 52, 53 | `word_index_lo_range` | 1 | `g + pc_mask·word_index − 2^16·pc_mask·word_index_hi` |
| 3 | 54, 55 | `word_index_hi_scaled` | 1 | `g + 4·pc_mask·word_index_hi` |
| 4 | 56, 57 | `rd_hi_range` | 1 | `g + pc_mask·rd_hi` |
| 5 | 58, 59 | `rd_lo_range` | 1 | `g + pc_mask·rd_selected − 2^16·pc_mask·rd_hi` |
| 6, 7 | 60–63 | `range16_pad_0`, `range16_pad_1` | 0 | 1 |

**The `decoder` fraction tree**, `L1[64..68]`: 2 fractions.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 64, 65 | `decoder_table` | `−mult_decoder` | `table_pc + β·table_next_pc + β²·table_rs1 + β³·table_rs2 + β⁴·table_rd + β⁵·table_imm + β⁶·table_extra_mask + g` |
| 1 | 66, 67 | `decode_row` | 1 | `g_dec + (1 + β + β² + β³ + β⁴ + β⁵ + β⁶)·pc_mask + pc_mask·pc_read_value + β·pc_mask·decoded_next_pc + β²·pc_mask·decoded_rs1 + β³·pc_mask·decoded_rs2 + β⁴·pc_mask·decoded_rd + β⁵·pc_mask·decoded_imm + β⁶·pc_mask·decoded_mask` |

`decode_row_den` is §5.4's with the decoded row at `W[9..15]`, address for address; the tuple is
seven wide, so `g_dec` is `g − Σ_{j<7} β^j` and `β⁶` is live (§0.4).

### 7.5 Gate list 0: the 33 enforcing gates

Relations 68–100, in list order, in §3.5's format. The family's 20 come from
`mem_word::family_spec` and its private helpers `booleanity`, `mask_rule`, `addr_rule`,
`word_addr_rule` and `value_masked`.

**A. The frame's gates (68–80)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
68–73   <q>_mask_boolean — each query's presence flag is a bit          Quadratic, degree 2
        code  memory::booleanity(frame(s, FIELD_MASK)), in frame_body

  68 pc_mask_boolean    M[1]      71 load_mask_boolean  M[16]
  69 rs1_mask_boolean   M[6]      72 ram_mask_boolean   M[21]
  70 rs2_mask_boolean   M[11]     73 rd_mask_boolean    M[26]

────────────────────────────────────────────────────────────────────────────────────────────
74–76   <q>_writes_back — a read-only query leaves its cell unchanged   Linear, degree 1
        code  memory::write_back(s), in frame_body

  74 rs1_writes_back    0 = M[10] − M[9]     0 = rs1_write_value  − rs1_read_value
  75 rs2_writes_back    0 = M[15] − M[14]    0 = rs2_write_value  − rs2_read_value
  76 load_writes_back   0 = M[20] − M[19]    0 = load_write_value − load_read_value

  reads as  76 is the one this frame has that §4's, §5's and §6's do not: a load reads a RAM
            word and writes back exactly what it read, so the word's own value survives the
            cycle and only the timestamp moves (memory.md §2.4).

────────────────────────────────────────────────────────────────────────────────────────────
77–80   the x0 rule                                                    Quadratic, degree 2
        code  memory::x0_gates(5, 6), whose first two are
              gadgets::is_zero(&[(1, rd_addr)], rd_inv, rd_is_zero, rd_mask)

  77 rd_is_zero_inverse     0 = W[7] − M[26] + M[27]·W[6]
  78 rd_is_zero_at_nonzero  0 = M[27]·W[7]
  79 rd_is_zero_boolean     0 = W[7] − W[7]·W[7]
  80 rd_write_masked        0 = M[30] − W[8] + W[7]·W[8]
                            0 = rd_write_value − (1 − rd_is_zero)·rd_selected

  reads as (68–80)  §2.3's, over six queries instead of four: the bare frame fixture is
                    memory_frame_mem.bin, which MEM_SUBWORD carries too.
```

**B. What the row is (81–84)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
81–82   kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2
        code  mem_word's private booleanity(KINDS[k])

  81 kind_lw_boolean   0 = W[15] − W[15]·W[15]
  82 kind_sw_boolean   0 = W[16] − W[16]·W[16]

────────────────────────────────────────────────────────────────────────────────────────────
83      decoded_mask_bits — the packed mask is its two bits             Linear, degree 1
        code  mem_word::family_spec, `bits`

  positional  0 = W[15] + 2·W[16] − W[14]
  named       0 = kind_lw + 2·kind_sw − decoded_mask

  reads as  §5.5's 146 over two bits. One-hotness is not here: the decoder table, whose
            masks are single bits, is what enforces it (lookup.md §10), and on a padding
            row, where the lookup is off, the two bits are free.

────────────────────────────────────────────────────────────────────────────────────────────
84      wrap_boolean — the address carry is a bit                       Quadratic, degree 2
        code  booleanity(WRAP)

  84 wrap_boolean  0 = W[17] − W[17]·W[17]    0 = wrap − wrap²

  reads as  the carry is worth 2^32 in 97, so a wrap of two moves the effective address by
            2^33 and the split would still hold over Fr. This gate is what keeps 97 an
            integer statement (§7.10's `an lw claiming a wrap of two`).
```

**C. Which queries a row makes, and where (85–96)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
85–89   <q>_mask_rule — a query is present exactly where its kind uses it   Quadratic, deg 2
        code  mask_rule(frame(s, FIELD_MASK), &[..])

  85 rs1_mask_rule    0 = M[6]  − M[1]·W[15] − M[1]·W[16]
                      0 = rs1_mask  − pc_mask·(kind_lw + kind_sw)
  86 rs2_mask_rule    0 = M[11] − M[1]·W[16]    0 = rs2_mask  − pc_mask·kind_sw
  87 load_mask_rule   0 = M[16] − M[1]·W[15]    0 = load_mask − pc_mask·kind_lw
  88 ram_mask_rule    0 = M[21] − M[1]·W[16]    0 = ram_mask  − pc_mask·kind_sw
  89 rd_mask_rule     0 = M[26] − M[1]·W[15]    0 = rd_mask   − pc_mask·kind_lw

  reads as  the five together are the family's whole statement about presence: a load reads
            rs1 and one RAM word at slot 2 and writes rd; a store reads rs1 and rs2 and
            rewrites one RAM word at slot 3. On a padding row pc_mask = 0 and every mask is
            0 whatever the bits hold — S14's control C8, which §7.10 refuses twice.

────────────────────────────────────────────────────────────────────────────────────────────
90–92   <q>_addr_rule — a present register query's index is the decoded one  Quadratic, deg 2
        code  addr_rule(slot, DECODED_<Q>)

  90 rs1_addr_rule   0 = M[6]·M[7]   − M[6]·W[10]
  91 rs2_addr_rule   0 = M[11]·M[12] − M[11]·W[11]
  92 rd_addr_rule    0 = M[26]·M[27] − M[26]·W[12]

────────────────────────────────────────────────────────────────────────────────────────────
93–94   <q>_addr_rule — a present RAM query names the word, not the byte  Quadratic, degree 2
        code  word_addr_rule(slot)

  93 load_addr_rule  0 = M[16]·M[17] − 4·M[16]·W[18]
                     0 = load_mask·(load_addr − 4·word_index)
  94 ram_addr_rule   0 = M[21]·M[22] − 4·M[21]·W[18]
                     0 = ram_mask·(ram_addr − 4·word_index)

  reads as  the memory tuple's address is the word's byte address and never a byte address
            inside it. A byte-address form here would be a broken memory model — the same
            cell under four names — and it is what §8 relies on when it splices a sub-word
            out of the same word (memory-ops.md §2).

────────────────────────────────────────────────────────────────────────────────────────────
95–96   <q>_value_masked — an absent operand reads 0                   Quadratic, degree 2
        code  value_masked(slot)

  95 rs1_value_masked  0 = M[9]  − M[6]·M[9]
  96 rs2_value_masked  0 = M[14] − M[11]·M[14]

  reads as  96 is what lets `store_value_rule` be one expression: an lw row's rs2 reads 0, so
            the gate writes 0 into a word it has no query for, and the ram mask is 0 anyway.
            There is no value_masked on `load` or `ram`: a RAM query's read value is the word
            the multiset pins, not an operand the row supplies.
```

**D. The address, and the two copies (97–100)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
97      addr_split — the effective address is four times a word index   Linear, degree 1
        code  mem_word::family_spec, the inline `addr_split`

  positional  0 = M[9] + W[13] − 2^32·W[17] − 4·W[18]
  named       0 = rs1_read_value + decoded_imm − 2^32·wrap − 4·word_index

  reads as  over Fr this says nothing: 4 is a unit, so word_index := addr·4⁻¹ solves it for
            any address at all. What makes it base-4 is the three obligations of §7.6 on
            word_index, which hold it below 2^30 and so make both sides integers below 2^34.
            Then `wrap` is pinned in both directions and a misaligned access has no witness
            (memory-ops.md §2; §7.10's two alignment tests).

────────────────────────────────────────────────────────────────────────────────────────────
98      rd_value_rule — a load writes the word it read                 Quadratic, degree 2
        code  family_spec, over LW and the load query's read value

  positional  0 = W[8] − W[15]·M[19]
  named       0 = rd_selected − kind_lw·load_read_value

  reads as  the whole semantics of `lw`. `load_read_value` carries no bound of its own — a
            value read from memory is exempt, on the write-side induction — so what makes it
            a word is the multiset: some earlier write put it there, and that write was
            bounded. `rd_selected`'s own 16+16 pair is what carries the bound into the
            register file (memory-ops.md §5.1).

────────────────────────────────────────────────────────────────────────────────────────────
99      store_value_rule — a store writes rs2 into the word            Quadratic, degree 2
        code  family_spec, over the ram mask and rs2's read value

  positional  0 = M[25] − M[21]·M[14]
  named       0 = ram_write_value − ram_mask·rs2_read_value

  reads as  the whole semantics of `sw`, and the reason the family needs no bound on what it
            stores: a register value is bounded where it was written. Gated by the ram mask
            rather than by `kind_sw`, so a row with no RAM query writes 0 there.

────────────────────────────────────────────────────────────────────────────────────────────
100     next_pc_rule — the next pc is the decoded fall-through         Linear, degree 1
        code  family_spec, the inline `next_pc_rule`

  positional  0 = M[5] − W[9]
  named       0 = pc_write_value − decoded_next_pc

  reads as  §5.5's and §6.5's: no kind here computes a pc, so there is no wrap bit, no bound
            and no evenness check. The decoder lookup binds the table's fall-through exactly
            as it binds rs1, rs2, rd and imm, none of which is range-checked either, and
            S17's rule that a family computing a pc keeps it even does not reach one that
            copies one.
```

### 7.6 The 18 lookups

`CircuitArtifact::lookups`, in order. The frame's 12 come from the private
`memory::gap_lookups`; the rest from `mem_word::family_spec` (its private `range16`, `range32`
and the inline `decode_row`). **Every one of the five `RANGE16` obligations is selected by
`pc_mask`**: this family has no second selector.

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `gap_hi_pc` | `TIMESTAMP` (0) | `M[1]` | `W[0]` | `pc_gap_hi` | `< 2^19` |
| 1 | `gap_lo_pc` | `TIMESTAMP` | `M[1]` | `4·M[0] − M[3] − 2^19·W[0] − 1` | `4·cycle − pc_read_ts − 2^19·pc_gap_hi − 1` | `< 2^19` |
| 2, 3 | `gap_hi_rs1`, `gap_lo_rs1` | `TIMESTAMP` | `M[6]` | `W[1]`; `4·M[0] − M[8] − 2^19·W[1]` | over `rs1` | `< 2^19` |
| 4, 5 | `gap_hi_rs2`, `gap_lo_rs2` | `TIMESTAMP` | `M[11]` | `W[2]`; `4·M[0] − M[13] − 2^19·W[2] + 1` | over `rs2` | `< 2^19` |
| 6, 7 | `gap_hi_load`, `gap_lo_load` | `TIMESTAMP` | `M[16]` | `W[3]`; `4·M[0] − M[18] − 2^19·W[3] + 1` | over the load's word | `< 2^19` |
| 8, 9 | `gap_hi_ram`, `gap_lo_ram` | `TIMESTAMP` | `M[21]` | `W[4]`; `4·M[0] − M[23] − 2^19·W[4] + 2` | over the store's word | `< 2^19` |
| 10, 11 | `gap_hi_rd`, `gap_lo_rd` | `TIMESTAMP` | `M[26]` | `W[5]`; `4·M[0] − M[28] − 2^19·W[5] + 2` | over `rd` | `< 2^19` |
| 12 | `word_index_hi_range` | `RANGE16` (1) | `M[1]` | `W[19]` | `word_index_hi` | `< 2^16` |
| 13 | `word_index_lo_range` | `RANGE16` | `M[1]` | `W[18] − 2^16·W[19]` | `word_index − 2^16·word_index_hi` | `< 2^16` |
| 14 | `word_index_hi_scaled` | `RANGE16` | `M[1]` | `4·W[19]` | `4·word_index_hi` | `< 2^16`, i.e. `word_index_hi < 2^14` |
| 15 | `rd_hi_range` | `RANGE16` | `M[1]` | `W[20]` | `rd_hi` | `< 2^16` |
| 16 | `rd_lo_range` | `RANGE16` | `M[1]` | `W[8] − 2^16·W[20]` | `rd_selected − 2^16·rd_hi` | `< 2^16` |
| 17 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[9], W[10], W[11], W[12], W[13], W[14])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_imm, decoded_mask)` | a row of `S[0..7]` |

Read in pairs, as in §3.6 to §6.6: each `gap_hi`/`gap_lo` pair puts a read strictly before its
own write, and `rd_hi_range`/`rd_lo_range` bounds `rd_selected` below `2^32`.

**The three obligations on `word_index` are this family's whole soundness argument about
addressing**, and the third is not a duplicate of the first two. `word_index_hi_scaled` holds
`4·word_index_hi` below `2^16`, so `word_index_hi < 2^14`; with the pair, `word_index < 2^30`
and `4·word_index ≤ 2^32 − 4`. **The bound is exactly tight**: the top word of the address
space, `0xfffffffc`, needs `word_index = 2^30 − 1`, `word_index_hi = 0x3fff` and a scaled value
of `0xfffc`, just inside `2^16` — which is §7.9's row `F`. Scaling by 2 instead of 4 would make
the top quarter of the address space unprovable; dropping the obligation would let
`4·word_index` reach `2^33`, an address no 32-bit query can name and one the multiset would
chain against nothing (§7.10's `a_word_index_above_2_to_the_30_is_refused`).
`lookup::check_copowers` takes `(word_index_hi, pc_mask)`, so an edit that narrows or drops the
direct pair fails the build rather than the argument, and `a_dropped_obligation_fails_the_build`
and `word_index_without_its_direct_bound_fails_the_build` in `mem_word.rs` are those two
refusals.

The channels, `mem_word::channels()`, in output order. **There are three**, and the generic
channel is absent:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[21]` | 12 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[22]` | 5 | 8 |
| 6, 7 | `DECODER` | 3 | `S[0..7]` | `W[23]` | 1 | 2 |

`artifact` asserts the three obligation counts. The largest tree is the timestamp's at 16
leaves, so `R = 4` and the circuit is 25 lists deep at `n = 20` — §3's and §4's depth, not §5's
and §6's.

### 7.7 Inner layers `L2`–`L5`: the row-wise reduction

The conventions are §3.7's. There are four row-wise reduction lists.

**`L2`, gate list 1, 34 columns, relations 101–134.**

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 101 | `read_2_0` | `read_pc · read_rs1` |
| 1 | 102 | `read_2_1` | `read_rs2 · read_load` |
| 2 | 103 | `read_2_2` | `read_ram · read_rd` |
| 3 | 104 | `read_2_3` | `read_pad_0 · read_pad_1` |
| 4–7 | 105–108 | `write_2_0` … `write_2_3` | the same over the write side |
| 8, 9 | 109, 110 | `timestamp_2_0` | `timestamp_table + gap_hi_pc` |
| 10, 11 | 111, 112 | `timestamp_2_1` | `gap_lo_pc + gap_hi_rs1` |
| 12, 13 | 113, 114 | `timestamp_2_2` | `gap_lo_rs1 + gap_hi_rs2` |
| 14, 15 | 115, 116 | `timestamp_2_3` | `gap_lo_rs2 + gap_hi_load` |
| 16, 17 | 117, 118 | `timestamp_2_4` | `gap_lo_load + gap_hi_ram` |
| 18, 19 | 119, 120 | `timestamp_2_5` | `gap_lo_ram + gap_hi_rd` |
| 20, 21 | 121, 122 | `timestamp_2_6` | `gap_lo_rd + timestamp_pad_0` |
| 22, 23 | 123, 124 | `timestamp_2_7` | `timestamp_pad_1 + timestamp_pad_2` |
| 24, 25 | 125, 126 | `range16_2_0` | `range16_table + word_index_hi_range` |
| 26, 27 | 127, 128 | `range16_2_1` | `word_index_lo_range + word_index_hi_scaled` |
| 28, 29 | 129, 130 | `range16_2_2` | `rd_hi_range + rd_lo_range` |
| 30, 31 | 131, 132 | `range16_2_3` | `range16_pad_0 + range16_pad_1` |
| 32, 33 | 133, 134 | `decoder_2_0` | `decoder_table + decode_row` |

**`L3`, gate list 2, 18 columns, relations 135–152.**

| `L3` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 135 | `read_3_0` | `read_2_0 · read_2_1` |
| 1 | 136 | `read_3_1` | `read_2_2 · read_2_3` |
| 2, 3 | 137, 138 | `write_3_0`, `write_3_1` | the same over the write side |
| 4, 5 | 139, 140 | `timestamp_3_0` | `timestamp_2_0 + timestamp_2_1` |
| 6, 7 | 141, 142 | `timestamp_3_1` | `timestamp_2_2 + timestamp_2_3` |
| 8, 9 | 143, 144 | `timestamp_3_2` | `timestamp_2_4 + timestamp_2_5` |
| 10, 11 | 145, 146 | `timestamp_3_3` | `timestamp_2_6 + timestamp_2_7` |
| 12, 13 | 147, 148 | `range16_3_0` | `range16_2_0 + range16_2_1` |
| 14, 15 | 149, 150 | `range16_3_1` | `range16_2_2 + range16_2_3` |
| 16, 17 | 151, 152 | `decoder_3_0` | copy of `decoder_2_0` |

**`L4`, gate list 3, 10 columns, relations 153–162.**

| `L4` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 153 | `read_4_0` | `read_3_0 · read_3_1` |
| 1 | 154 | `write_4_0` | `write_3_0 · write_3_1` |
| 2, 3 | 155, 156 | `timestamp_4_0` | `timestamp_3_0 + timestamp_3_1` |
| 4, 5 | 157, 158 | `timestamp_4_1` | `timestamp_3_2 + timestamp_3_3` |
| 6, 7 | 159, 160 | `range16_4_0` | `range16_3_0 + range16_3_1` |
| 8, 9 | 161, 162 | `decoder_4_0` | copy of `decoder_3_0` |

**`L5`, gate list 4, 8 columns, relations 163–170.**

| `L5` | relations | node | formula |
| --- | --- | --- | --- |
| 0 | 163 | `read_5_0` | copy of `read_4_0` |
| 1 | 164 | `write_5_0` | copy of `write_4_0` |
| 2, 3 | 165, 166 | `timestamp_5_0` | `timestamp_4_0 + timestamp_4_1` |
| 4, 5 | 167, 168 | `range16_5_0` | copy of `range16_4_0` |
| 6, 7 | 169, 170 | `decoder_5_0` | copy of `decoder_4_0` |

### 7.8 The halving layers and the outputs

Gate list `k`, for `5 ≤ k ≤ n + 4`, halves layer `k` into layer `k + 1`, which has `n + 4 − k`
variables. Its eight gates, relation `r = 171 + 8(k − 5)`, with §3.8's formulas:

| `L{k+1}` | relation | node | shape |
| --- | --- | --- | --- |
| 0 | `r` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` |
| 1 | `r + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` |
| 2 | `r + 2` | `timestamp_{k+1}_0_num` | `TreeCross { L{k}[2], L{k}[3] }` |
| 3 | `r + 3` | `timestamp_{k+1}_0_den` | `TreeProduct { L{k}[3] }` |
| 4 | `r + 4` | `range16_{k+1}_0_num` | `TreeCross { L{k}[4], L{k}[5] }` |
| 5 | `r + 5` | `range16_{k+1}_0_den` | `TreeProduct { L{k}[5] }` |
| 6 | `r + 6` | `decoder_{k+1}_0_num` | `TreeCross { L{k}[6], L{k}[7] }` |
| 7 | `r + 7` | `decoder_{k+1}_0_den` | `TreeProduct { L{k}[7] }` |

In the last list, `k = n + 4`, the eight nodes are named `read_root`, `write_root`,
`timestamp_num_root`, `timestamp_den_root`, `range16_num_root`, `range16_den_root`,
`decoder_num_root` and `decoder_den_root`. At `n = 20` the halving lists are 5 to 24, `L6` has
19 variables and `L25` none. At `n = 22` they are 5 to 26, and the top is `L27`.

**The outputs**, in output-map order. All eight are absorbed as one `GKR_OUTPUTS` message before
any challenge of the backward pass, and travel in `ShardProof::outputs`.

| # | address, `n = 20` | node | value | what `verify_shard` does with it |
| --- | --- | --- | --- | --- |
| 0 | `L{25}[0]` | `read_root` | the product of every read leaf of the shard | step 10: must equal `PublicInputs::memory_roots[p][0]`, `p` being the position of `(4, shard_index)` in `verifier_core::statement_shards`; a factor of `reconciles` |
| 1 | `L{25}[1]` | `write_root` | the product of every write leaf | step 10: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |
| 2 | `L{25}[2]` | `timestamp_num_root` | as §3.8's output 2 | step 9: must be 0; otherwise `Lookup { channel: 0 }` |
| 3 | `L{25}[3]` | `timestamp_den_root` | as §3.8's output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 0 }` |
| 4 | `L{25}[4]` | `range16_num_root` | as output 2, for `RANGE16` | step 9: must be 0; otherwise `Lookup { channel: 1 }` |
| 5 | `L{25}[5]` | `range16_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 1 }` |
| 6 | `L{25}[6]` | `decoder_num_root` | as output 2, for `DECODER` | step 9: must be 0; otherwise `Lookup { channel: 3 }` |
| 7 | `L{25}[7]` | `decoder_den_root` | as output 3 | step 9: must be nonzero; otherwise `Lookup { channel: 3 }` |

**Eight outputs, not ten.** A shard proof of this family carries `2 + 2·3` (`mem.rs`
acceptance 1), where every other S19 family carries `2 + 2·4`: there is no generic pair.

### 7.9 Witness rows

The table shows eight of the 51 live rows of `guests/mem`'s `MEM_WORD` shard, as
`prover::family_fill(4)` writes them, plus the first padding row after them.
`crates/checker/tests/mem_fill.rs`' `the_mem_word_fill_satisfies_every_gate_and_every_table`
holds exactly these columns to every gate, every range obligation and the decoder channel in
ordinary CI, over every live row, the two padding rows after them and the shard's last row, with
`trace::build_multiplicities` counting every gated tuple against its table. The circuit is also
held to a hand-built catalogue of its own: `crates/checker/tests/mem_word.rs`' `honest_rows`,
twelve live rows and the padding row, built from Rust's own `u32` arithmetic rather than from a
trace — both kinds, an `x0` destination and an `x0` source, a compressed `lw`, the top of the
address space and `RAM_ORIGIN`, a store whose address wraps, a negative displacement with and
without a carry, a load through `x0`, and `lw` at `0xfffffffc + 4`, which is `2^32` exactly and
so wraps to word 0. §7.10's forgeries all start from that catalogue.

`A` `sw` at `0x10018`, storing `x5 = 0x89abcdef` through `x9 = 0x20000` at displacement 0.
`B` the `lw` after it, reading the same word into `x6`. `C` `lw` into `x0`, which reads the
word and writes nothing. `D` `sw` at displacement 4, one word along. `E` `sw` through
`x18 = 0x7ffffef0`, near the top of RAM and in window 8191. `F` a **compressed** `sw`, whose
fall-through is `pc + 2`. `G` the compressed `lw` after it. `H` `lw` from the high window.
`P` the first padding row. Every cell not listed is 0 on all nine; `S[0..7]` hold
`MINUS_ONE` at these rows, the table row being pc `2y`, and are omitted.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 7 | 8 | 22 | 13 | 29 | 37 | 38 | 299 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[3]` `pc_read_ts` | 24 | 28 | 84 | 48 | 112 | 144 | 148 | 1192 | 0 |
| `M[4]` `pc_read_value` | `0x10018` | `0x1001c` | `0x10054` | `0x10030` | `0x10070` | `0x10090` | `0x10092` | `0x104a4` | 0 |
| `M[5]` `pc_write_value` | `0x1001c` | `0x10020` | `0x10058` | `0x10034` | `0x10074` | `0x10092` | `0x10094` | `0x104a8` | 0 |
| `M[6]` `rs1_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[7]` `rs1_addr` | 9 | 9 | 9 | 9 | 18 | 11 | 11 | 14 | 0 |
| `M[9]`, `M[10]` `rs1_read_value`, `rs1_write_value` | `0x20000` | `0x20000` | `0x20000` | `0x20000` | `0x7ffffef0` | `0x20020` | `0x20020` | `0x7fffff00` | 0 |
| `M[11]` `rs2_mask` | 1 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 0 |
| `M[12]` `rs2_addr` | 5 | 0 | 0 | 5 | 5 | 10 | 0 | 0 | 0 |
| `M[14]`, `M[15]` `rs2_read_value`, `rs2_write_value` | `0x89abcdef` | 0 | 0 | `0x0f0f0f0f` | `0x12345678` | `0x0badf00d` | 0 | 0 | 0 |
| `M[16]` `load_mask` | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 0 |
| `M[17]` `load_addr` | 0 | `0x20000` | `0x20000` | 0 | 0 | 0 | `0x20020` | `0x7fffff00` | 0 |
| `M[19]`, `M[20]` `load_read_value`, `load_write_value` | 0 | `0x89abcdef` | `0x89abcdef` | 0 | 0 | 0 | `0x0badf00d` | `0xd000` | 0 |
| `M[21]` `ram_mask` | 1 | 0 | 0 | 1 | 1 | 1 | 0 | 0 | 0 |
| `M[22]` `ram_addr` | `0x20000` | 0 | 0 | `0x20004` | `0x7ffffef0` | `0x20020` | 0 | 0 | 0 |
| `M[24]` `ram_read_value` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `M[25]` `ram_write_value` | `0x89abcdef` | 0 | 0 | `0x0f0f0f0f` | `0x12345678` | `0x0badf00d` | 0 | 0 | 0 |
| `M[26]` `rd_mask` | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 0 |
| `M[27]` `rd_addr` | 0 | 6 | 0 | 0 | 0 | 0 | 12 | 28 | 0 |
| `M[29]` `rd_read_value` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 10 | 0 |
| `M[30]` `rd_write_value` | 0 | `0x89abcdef` | 0 | 0 | 0 | 0 | `0x0badf00d` | `0xd000` | 0 |
| `W[0..6]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[6]` `rd_inv` | 0 | `6⁻¹` | 0 | 0 | 0 | 0 | `12⁻¹` | `28⁻¹` | 0 |
| `W[7]` `rd_is_zero` | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[8]` `rd_selected` | 0 | `0x89abcdef` | `0x89abcdef` | 0 | 0 | 0 | `0x0badf00d` | `0xd000` | 0 |
| `W[9]` `decoded_next_pc` | `0x1001c` | `0x10020` | `0x10058` | `0x10034` | `0x10074` | `0x10092` | `0x10094` | `0x104a8` | 0 |
| `W[10]` `decoded_rs1` | 9 | 9 | 9 | 9 | 18 | 11 | 11 | 14 | 0 |
| `W[11]` `decoded_rs2` | 5 | 0 | 0 | 5 | 5 | 10 | 0 | 0 | 0 |
| `W[12]` `decoded_rd` | 0 | 6 | 0 | 0 | 0 | 0 | 12 | 28 | 0 |
| `W[13]` `decoded_imm` | 0 | 0 | 0 | 4 | 0 | 0 | 0 | 0 | 0 |
| `W[14]` `decoded_mask` | 2 | 1 | 1 | 2 | 2 | 2 | 1 | 1 | 0 |
| `W[15]`, `W[16]` the kind bit set | `sw` | `lw` | `lw` | `sw` | `sw` | `sw` | `lw` | `lw` | none |
| `W[17]` `wrap` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[18]` `word_index` | `0x8000` | `0x8000` | `0x8000` | `0x8001` | `0x1fffffbc` | `0x8008` | `0x8008` | `0x1fffffc0` | 0 |
| `W[19]` `word_index_hi` | 0 | 0 | 0 | 0 | `0x1fff` | 0 | 0 | `0x1fff` | 0 |
| `W[20]` `rd_hi` | 0 | `0x89ab` | `0x89ab` | 0 | 0 | 0 | `0x0bad` | 0 | 0 |

`E` and `H` are the rows that make RAM window 8191 the statement's one `ZERO_WINDOWS` shard:
their byte addresses `0x7ffffef0` and `0x7fffff00` are `4h·8191 + 4y` at `h = 2^16`. `A` and `D`
are the two stores whose `ram_read_value` is 0 — the word they overwrite has never been written,
so the image's 0 is what the multiset hands them, and no gate of this family looks at it (§13).
`C` is the `x0` destination: `rd_selected` carries the whole loaded word, `rd_hi` bounds it, and
`rd_write_masked` writes 0. `F` and `G` are the compressed pair, `pc + 2` on both sides of
`next_pc_rule`. The multiplicity columns are not shown: on a real shard they are the counts over
the whole `2^20` rows, and row 0 of `mult_timestamp` and `mult_range16` carries the twelve and
five switched-off tuples of each of the `2^20 − 51` padding rows.

### 7.10 What fixes each cell

The per-cell accounting is `crates/checker/tests/mem_word.rs`' own, and it is a committed one:
`each_gate_is_the_one_that_refuses_its_row` carries 21 tampers, each an edit to a named honest
row beside **the exact set** of relations that refuse it, asserted equal — not a membership — so
a gate that stopped being load-bearing on the row shape it exists for fails the suite. It ends
with a **completeness assertion**: of the circuit's 33 enforcing gates the frame's thirteen are
set aside, and each of the remaining **20** must be named by some tamper above, so a gate added
with no forgery beside it fails here rather than silently. The table below is that list read as a
cell-by-cell account. The three booleans this family commits — the two kind bits and the wrap —
carry the `x² = x` gates named above, and four further tests take one question each.

| cell moved | on the row | refused by, exactly |
| --- | --- | --- |
| `kind_lw` → 2, packed mask moved with it | padding | `kind_lw_boolean` |
| `kind_sw` → 2, packed mask moved with it | padding | `kind_sw_boolean` |
| `decoded_mask` → `sw`'s | `lw` | `decoded_mask_bits` |
| `wrap` → 2, `word_index` and the query's address moved so the split and the address rule still hold | `lw` | `wrap_boolean` |
| the `rs1` query dropped | `a load through x0`, whose base register reads 0 | `rs1_mask_rule` |
| an `rs2` query added | `lw` | `rs2_mask_rule` |
| a `load` query added | `sw` | `load_mask_rule` |
| a `ram` query added, writing 0 | `lw` | `ram_mask_rule` |
| an `rd` query into `x0` added | `sw` | `rd_mask_rule` |
| `rs1_addr` `+ 1` | `lw` | `rs1_addr_rule` |
| `rs2_addr` `+ 1` | `sw` | `rs2_addr_rule` |
| `rd_addr` → 5 | `lw` | `rd_addr_rule` |
| `load_addr` `+ 4` | `lw` | `load_addr_rule` |
| `ram_addr` `+ 4` | `sw` | `ram_addr_rule` |
| `rs1_read_value` → 4, `word_index` → 1 | padding | `rs1_value_masked` |
| `rs2_read_value` → 5 | `lw` | `rs2_value_masked` |
| `word_index` `+ 1`, the query's address `+ 4` | `lw` | `addr_split` |
| `rd_selected` `+ 1`, with `rd_write_value` and `rd_hi` moved to match | `lw` | `rd_value_rule` |
| `ram_write_value` `+ 1` | `sw` | `store_value_rule` |
| `pc_write_value` `+ 4` | `lw` | `next_pc_rule` |
| an `rd` query zeroing `x10` | padding | `rd_mask_rule`, `rd_addr_rule` |

What no gate refuses, and what does:

- **A misaligned `lw` or `sw`**: nothing in gate list 0.
  `a_misaligned_word_access_is_unprovable` builds, for each of the three offsets, the exact field
  witness `word_index = addr·4⁻¹` — every gate holds on it, the split included, the query's
  address rule included, both copies included, the decoder included — and finds
  `word_index_lo_range` refusing it alone. `addr·4⁻¹` is not a 32-bit integer and not a 64-bit
  one, and no choice of high chunk rescues it, the three obligations together admitting
  `word_index < 2^30` and nothing above.
- **A `word_index` at `2^30`**: `word_index_hi_scaled` alone.
  `a_word_index_above_2_to_the_30_is_refused` takes the honest `lw` at `0xfffffffc + 4`, which
  carries the wrap and reads word 0, and drops the wrap: the query's address becomes the field
  element `2^32`, a cell no 32-bit address can name. The 16+16 pair accepts it — `0x4000` is a
  halfword and the remainder is 0 — and the scaled obligation is the lone refusal.
- **A loaded value that was never in memory**: `rd_value_rule` ties `rd_selected` to the load
  query's read value, and nothing bounds that value here; the multiset is what pins it, and
  `the_loaded_value_is_the_word_the_memory_argument_pins` is that argument as rows.
- **A store's `ram_read_value`**: **nothing at all**. No gate and no obligation of this family
  reads it (§7.3, §13), which is why it is acceptance 8's tamper target for this family and why
  the refusal genuinely comes from the permutation product, as `MemoryArgument`
  (`memory-ops.md` §9).
- **A decoder tuple that is not the table's**: `each_table_lookup_is_the_one_that_refuses_its_row`,
  which `violated_lookups` cannot see — a table channel is held here to the table itself.

On a padding row `pc_mask = 0`, every frame mask is 0, every leaf is 1 and every obligation is
vacuous, all five `RANGE16` ones included: this family has no selector but `pc_mask` and the
frame's masks, so a padding row costs one table multiplicity per channel and nothing else. The
two kind bits and the wrap are **free booleans** there, and with every kind bit 0 the gates hold
`rd_selected`, `ram_write_value` and `pc_write_value − decoded_next_pc` to 0 and leave
`word_index` free subject to the split over a zero `rs1` and a zero `imm` — that is, to 0. The
honest fill writes 0 everywhere.

---

## 8. `MEM_SUBWORD` — family 5

### 8.1 Header

`family_circuit(5, n)` is `mem_subword::artifact(n)` with `mem_subword::channels()`, built by
`memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` through the private
`family_spec`, whose splice half is the public `mem_subword::splice_gates(BYTE_BITS)` — the
**width seam** S19's exhaustive reduced-width check drives, as `mul_div::arithmetic_gates` is at
S18 and `gadgets::comparison_equation` at S17. `splice_gates` panics outside `1..=8` bits to a
byte. It uses no S17 or S18 gadget: `is_zero` reaches it only through the frame's x0 rule, and
the one sign it needs comes from the packed table's `U16GetSign`, not from
`gadgets::comparison`. Normative spec: `memory-ops.md` §4. Fill: `prover::family_fill(5)`, the
private `fill::mem_subword`.

96 committed columns (31 `M`, 55 `W`, 10 `S`) and two virtual tables. Gate list 0 writes 120
leaves and holds 53 enforcing gates. 36 lookups on four channels, 10 outputs. At `n = 20`, the
height S19 proves, there are 26 gate lists, the top is `L26`, and the circuit has 452 inner
columns and 505 relations; a shard proof of it is 68,116 bytes. At `n = 22` — the committed
fixture — there are 28 lists, the top is `L28`, and it has 472 inner columns, 525 relations and
98,846 bytes of wire form.

**It is one gate list deeper than §7's**, for §6's reason and not §5's: its `range16` tree
carries 22 obligations, which with the table fraction is 23 leaves and pads to 32, where
`MEM_WORD`'s five fit in 8 (§8.6). It reads the generic channel — one lookup, the sign of the
sub-word it loaded — so `FamilyCircuit::reads_generic_table` holds and a shard opens the key's
three packed-table commitments after identity's seven, 96 commitments in all
(`shard-proof.md` §3, §5.1; `jump-branch-slt.md` §6).

`artifact` panics unless the frame is `QUERIES`, the channels carry exactly 12, 22, 1 and 1
obligations, `lookup::check_copowers` finds a direct range pair under the same selector for each
of the five columns it bounds by scaling — `word_index_hi`, `high`, `sub`, `low` and `src_sub` —
and every gate is zero on the all-zero row. It also panics on every refusal of the assembly,
among them `n < 19` and `n > 30`; `family_circuit` returns `None` for both rather than calling
it.

### 8.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::mem_subword`, bit `k` being
`W[15 + k]`. The decoded table's `imm` is the sign-extended twelve-bit displacement;
`next_pc` is the fall-through, and no kind here computes a pc. The effective address is
`rs1 + imm` reduced mod `2^32`, split into `4·word_index + 2·bit1 + bit0` with a wrap bit, and
the two offset bits are the only place a byte position lives: the memory tuple names the word
(`memory-ops.md` §2, §4.1).

**The stage prompt's STORE, BYTE, HALF and SIGNEXT modifiers are linear forms over the six
one-hot bits, not columns** (`memory-ops.md` §1): `LOADK = b_lb + b_lh + b_lbu + b_lhu`,
`STORE = b_sb + b_sh`, `BYTE = b_lb + b_lbu + b_sb`, `HALF = b_lh + b_lhu + b_sh`,
`SIGNEXT = b_lb + b_lh`. Each appears as one product per bit in the gate that reads it, which is
what keeps a product with one at degree 2, and no lookup selects on one, so none needs a
booleanity gate. `w`, the access width, is `2^16 − (2^16 − 2^8)·BYTE`: 256 on a byte row and
65536 on a halfword row.

| row kind | bit (`decoded_mask`) | queries present | `w` | `SIGNEXT` | `rd_selected` | `ram_write_value` |
| --- | --- | --- | --- | --- | --- | --- |
| `lb` | 0 (1) | pc rs1 load rd | 256 | 1 | `sub + (2^32 − 256)·se` | 0 |
| `lh` | 1 (2) | pc rs1 load rd | 65536 | 1 | `sub + (2^32 − 65536)·se` | 0 |
| `lbu` | 2 (4) | pc rs1 load rd | 256 | 0 | `sub` | 0 |
| `lhu` | 3 (8) | pc rs1 load rd | 65536 | 0 | `sub` | 0 |
| `sb` | 4 (16) | pc rs1 rs2 ram | 256 | 0 | 0 | `word + (src_sub − sub)·p` |
| `sh` | 5 (32) | pc rs1 rs2 ram | 65536 | 0 | 0 | `word + (src_sub − sub)·p` |
| padding | none; all 0 | none | — | 0 | 0 | 0 |

All six are provable at S19. The splice power `p = 2^(8·offset)` is 1, 256, `2^16` or `2^24`,
and `half_aligned` forces `bit0 = 0` on the three halfword kinds, so `w·p` is at most `2^32` and
never `2^40` — which is what §8.5's `high_scaled` bound rests on (`memory-ops.md` §2, §4.7). On
a **padding row** every gate of the splice reads `0 = 0`: `p_rule`'s constant is `m_pc`, so
`p = 0` there, and `pcopow`, `wph`, `high`, `sub`, `low`, `src_sub` and `src_high` follow.
`pcopow` is then free of every gate, which is what makes it acceptance 8's negative control
(`memory-ops.md` §9).

`rd = x0` is not a kind. Every kind but a store has a compressed form (`c.lw`'s siblings do not
cover the sub-word loads, but the guest's rows carry both fall-through widths through the
decoded table), and a live row at a pc holding no instruction of the family meets the table's
`MINUS_ONE` row, which its decoder tuple cannot equal.

### 8.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §8.4 and §8.6.

**Memory-argument columns, `M[0..31]`** — §2's MEM layout (`w = 6`), the same 31 columns,
the same slots and the same bare frame fixture (`memory_frame_mem.bin`) as §7.3's, address for
address; `M[0..31]`'s meanings and their frame gates are §7.3's. The "read by" column differs
only where this family's own gates read one:

| address and name | what it holds here | read by, beside the frame |
| --- | --- | --- |
| `M[9]` `rs1_read_value` | the base address | `addr_split` |
| `M[14]` `rs2_read_value` | the value a store truncates, not the word it stores | `src_sub_rule` |
| `M[19]` `load_read_value` | the word a load read, which `word` copies | `word_rule` |
| `M[21]` `ram_mask` | 1 on a store row | `ram_mask_rule`, `ram_addr_rule`, `p_ram_rule`, `store_rule` |
| `M[24]` `ram_read_value` | the word a store is rewriting, which `word` copies | `word_rule` — so unlike §7's, this family **does** read it |
| `M[25]` `ram_write_value` | the spliced word | `store_rule` |
| `M[30]` `rd_write_value` | the sign-extended sub-word, or 0 into `x0` | `rd_write_masked` |

Every other `M` column is read exactly as §7.3 lists it.

**Witness columns, `W[0..55]`** — `W[0..8]` filled by `trace::build_frame_witness`, `W[8..51]`
by `fill::mem_subword` (`W[8]` in place of S14's), `W[51..55]` by
`trace::build_multiplicities` inside `prover::shard_columns`; committed in
`ShardProof::witness_commitments`, absorbed at S3 before `g` and `β`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0..6]` | `pc_gap_hi` … `rd_gap_hi` | `memory::gap_hi(s)` | the six gap chunks | `gap >> 19` | `gap_hi_<q>`, `gap_lo_<q>` |
| `W[6]` | `rd_inv` | `memory::rd_inv(6)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[7]` | `rd_is_zero` | `memory::rd_is_zero(6)` | rd is `x0` | | the three x0 gates |
| `W[8]` | `rd_selected` | `memory::rd_selected(6)`; `sel` | Loaded sub-word, extended | `sub + (2^32 − w)·se`; 0 on a store | `rd_write_masked`, `rd_value_rule`; `rd_lo_range` |
| `W[9..15]` | `decoded_next_pc` … `decoded_mask` | `mem_subword::DECODED` | the claimed decoded row | the table row after `pc` | `next_pc_rule`, `rs1_addr_rule`, `rs2_addr_rule`, `rd_addr_rule`, `addr_split`, `decoded_mask_bits`; `decode_row` positions 1–6 |
| `W[15]` | `kind_lb` | `KINDS[0]`; `LB` | lb row | | `kind_lb_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `load_mask_rule`, `rd_mask_rule`, `word_rule`, `se_rule`, `wph_rule`, `sub_scaled_rule`, `src_sub_rule`, `src_sub_scaled_rule`, `sign_in_rule`, `rd_value_rule` |
| `W[16]` | `kind_lh` | `KINDS[1]`; `LH` | lh row | | `kind_lh_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `load_mask_rule`, `rd_mask_rule`, `half_aligned`, `word_rule`, `se_rule`, `rd_value_rule` |
| `W[17]` | `kind_lbu` | `KINDS[2]`; `LBU` | lbu row | | as `kind_lb` without `se_rule` |
| `W[18]` | `kind_lhu` | `KINDS[3]`; `LHU` | lhu row | | as `kind_lh` without `se_rule` |
| `W[19]` | `kind_sb` | `KINDS[4]`; `SB` | sb row | | `kind_sb_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `ram_mask_rule`, `word_rule`, `wph_rule`, `sub_scaled_rule`, `src_sub_rule`, `src_sub_scaled_rule`, `sign_in_rule`, `rd_value_rule` |
| `W[20]` | `kind_sh` | `KINDS[5]`; `SH` | sh row | | `kind_sh_boolean`, `decoded_mask_bits`, `rs1_mask_rule`, `rs2_mask_rule`, `ram_mask_rule`, `half_aligned`, `word_rule` |
| `W[21]` | `wrap` | `mem_subword::WRAP` | Address carry | 1 where `rs1 + imm ≥ 2^32` | `wrap_boolean`, `addr_split` |
| `W[22]` | `word_index` | `WORD_INDEX` | The accessed word's index | `addr / 4` | `load_addr_rule`, `ram_addr_rule`, `addr_split`; `word_index_lo_range` |
| `W[23]` | `word_index_hi` | `WORD_INDEX_HI` | `word_index`, high halfword | | `word_index_hi_range`, `word_index_lo_range`, `word_index_hi_scaled` |
| `W[24]` | `bit0` | `BIT0` | Address bit 0 | | `bit0_boolean`, `addr_split`, `half_aligned`, `p_rule` |
| `W[25]` | `bit1` | `BIT1` | Address bit 1 | | `bit1_boolean`, `addr_split`, `p_rule` |
| `W[26]` | `p` | `P` | Splice power `2^(8·offset)` | 1, 256, `2^16` or `2^24`; 0 on a padding row | `p_rule`, `pcopow_rule`, `wph_rule`, `splice_rule`, `p_ram_rule` |
| `W[27]` | `pcopow` | `PCOPOW` | Halved copower `2^31/p` | | `pcopow_rule`, `low_scaled_rule` |
| `W[28]` | `wph` | `WPH` | Halved `w·p` | | `wph_rule`, `high_scaled_rule` |
| `W[29]` | `p_ram` | `P_RAM` | `p` on a store row | 0 on a load and on padding | `p_ram_rule`, `store_rule` |
| `W[30]` | `word` | `WORD` | The word this row splices | what a load read, or what a store is rewriting | `word_rule`, `splice_rule`, `store_rule` |
| `W[31]` | `high` | `HIGH` | The bytes above the sub-word | `word div (w·p)` | `high_scaled_rule`; `high_lo_range` |
| `W[32]` | `high_hi` | `HIGH_HI` | `high`, high halfword | | `high_hi_range`, `high_lo_range` |
| `W[33]` | `high_scaled` | `HIGH_SCALED` | `high·(w·p)` | | `splice_rule`, `high_scaled_rule`; `high_scaled_lo_range` |
| `W[34]` | `high_scaled_hi` | `HIGH_SCALED_HI` | its high halfword | | `high_scaled_hi_range`, `high_scaled_lo_range` |
| `W[35]` | `sub` | `SUB` | The accessed sub-word | `(word div p) mod w` | `splice_rule`, `sub_scaled_rule`, `sign_in_rule`, `rd_value_rule`, `store_rule`; `sub_range` |
| `W[36]` | `sub_scaled` | `SUB_SCALED` | `sub·(2^32/w)` | | `sub_scaled_rule`; `sub_scaled_lo_range` |
| `W[37]` | `sub_scaled_hi` | `SUB_SCALED_HI` | its high halfword | | `sub_scaled_hi_range`, `sub_scaled_lo_range` |
| `W[38]` | `low` | `LOW` | The bytes below the sub-word | `word mod p` | `splice_rule`, `low_scaled_rule`; `low_lo_range` |
| `W[39]` | `low_hi` | `LOW_HI` | `low`, high halfword | | `low_hi_range`, `low_lo_range` |
| `W[40]` | `low_scaled` | `LOW_SCALED` | `low·(2^32/p)` | | `low_scaled_rule`; `low_scaled_lo_range` |
| `W[41]` | `low_scaled_hi` | `LOW_SCALED_HI` | its high halfword | | `low_scaled_hi_range`, `low_scaled_lo_range` |
| `W[42]` | `src_sub` | `SRC_SUB` | `rs2` truncated to the width | `rs2 mod w` | `src_sub_rule`, `src_sub_scaled_rule`, `store_rule`; `src_sub_range` |
| `W[43]` | `src_sub_scaled` | `SRC_SUB_SCALED` | `src_sub·(2^32/w)` | | `src_sub_scaled_rule`; `src_sub_scaled_lo_range` |
| `W[44]` | `src_sub_scaled_hi` | `SRC_SUB_SCALED_HI` | its high halfword | | `src_sub_scaled_hi_range`, `src_sub_scaled_lo_range` |
| `W[45]` | `src_high` | `SRC_HIGH` | The rest of `rs2` | `rs2 div w` | `src_sub_rule`; `src_high_lo_range` |
| `W[46]` | `src_high_hi` | `SRC_HIGH_HI` | its high halfword | | `src_high_hi_range`, `src_high_lo_range` |
| `W[47]` | `sign_in` | `SIGN_IN` | The sub-word with its sign at bit 15 | `256·sub` on a byte row, `sub` on a halfword one | `sign_in_rule`; `sign_in_range`, `sub_get_sign` position 0 |
| `W[48]` | `sign` | `SIGN` | That sign bit, from the packed table | | `se_rule`; `sub_get_sign` position 1 |
| `W[49]` | `se` | `SE` | The sign-extension term | `SIGNEXT·sign` | `se_rule`, `rd_value_rule` |
| `W[50]` | `rd_hi` | `RD_HI` | The written value, high halfword | | `rd_hi_range`, `rd_lo_range` |
| `W[51]` | `mult_timestamp` | `MULTIPLICITIES[0]` | Timestamp-table count | | leaf `timestamp_table_num` |
| `W[52]` | `mult_range16` | `MULTIPLICITIES[1]` | 16-bit-table count | all 22 obligations under `pc_mask` | leaf `range16_table_num` |
| `W[53]` | `mult_generic` | `MULTIPLICITIES[2]` | Generic-table count | a live row's one tuple lands on `U16GetSign`'s row `2^16 + 1 + sign_in`; a padding row's on the `ZeroEntry`, row 0 | leaf `generic_table_num` |
| `W[54]` | `mult_decoder` | `MULTIPLICITIES[3]` | Decoder-table count | | leaf `decoder_table_num` |

**Like §7 and unlike §5, every obligation and every lookup of this family is under `pc_mask`.**
There is no second selector: the one generic lookup runs on a store row too, where `SIGNEXT` is
0 and it buys nothing, which is S17's shape and deliberate — a narrower selector would have to
be a committed column with a booleanity gate of its own, and the key bound would have to move
with it (`memory-ops.md` §4.5).

**Setup columns, `S[0..10]`** — two tables. `S[0..7]` is the family's decoded table,
`program::lookup_tuple(5)` order, filled by `program::FamilyTable::column_poly(j)`, committed in
program identity. `S[7..10]` is the packed generic table (§0.3), filled by
`program::lookup_tables::generic_table(n)`, carried in every key as
`VerifyingKey::generic_table` and covered by the key's SRS digest, not by identity. The layout
is §5.3's, name for name — `table_pc` … `table_extra_mask` at weights 1 to `β⁶`, then
`generic_key`, `generic_value`, `generic_result` at 1, `β`, `β²` — and each is read only by its
table's denominator. `mem_subword::TABLE_WIDTH` is 7 and `constants::generic_table::WIDTH` is 3.

**Virtual tables** — `V[range19]` and `V[range16]`, §7.3's, read by `timestamp_table_den` and
`range16_table_den`.

### 8.4 Gate list 0: the 120 leaves

A leaf's relation number equals its `L1` offset, 0 to 119.

**The memory product trees**, `L1[0..16]`: §7.4's, address for address — the frame is the same
six queries, and the bare frame fixture `memory_frame_mem.bin` is the same file. Two pads a
side.

**The `timestamp` fraction tree**, `L1[16..48]`: §7.4's list unchanged, 16 fractions — the
table's, then `gap_hi`/`gap_lo` for `pc`, `rs1`, `rs2`, `load`, `ram` and `rd`, then three pads.

**The `range16` fraction tree**, `L1[48..112]`: **32 fractions**, the table's then 22
obligations then 9 pads. This is the tree that makes the circuit a list deeper than §7's. Every
obligation is under `pc_mask`, so the selector column is omitted.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 48, 49 | `range16_table` | `−mult_range16` | `V[range16] + g` |
| 1 | 50, 51 | `word_index_hi_range` | 1 | `g + pc_mask·word_index_hi` |
| 2 | 52, 53 | `word_index_lo_range` | 1 | `g + pc_mask·word_index − 2^16·pc_mask·word_index_hi` |
| 3 | 54, 55 | `word_index_hi_scaled` | 1 | `g + 4·pc_mask·word_index_hi` |
| 4, 5 | 56–59 | `high_hi_range`, `high_lo_range` | 1 | the 16+16 pair on `high` |
| 6, 7 | 60–63 | `high_scaled_hi_range`, `high_scaled_lo_range` | 1 | the pair on `high_scaled` |
| 8 | 64, 65 | `sub_range` | 1 | `g + pc_mask·sub` — a **single** halfword obligation |
| 9, 10 | 66–69 | `sub_scaled_hi_range`, `sub_scaled_lo_range` | 1 | the pair on `sub_scaled` |
| 11, 12 | 70–73 | `low_hi_range`, `low_lo_range` | 1 | the pair on `low` |
| 13, 14 | 74–77 | `low_scaled_hi_range`, `low_scaled_lo_range` | 1 | the pair on `low_scaled` |
| 15 | 78, 79 | `src_sub_range` | 1 | `g + pc_mask·src_sub` — a single obligation again |
| 16, 17 | 80–83 | `src_sub_scaled_hi_range`, `src_sub_scaled_lo_range` | 1 | the pair on `src_sub_scaled` |
| 18, 19 | 84–87 | `src_high_hi_range`, `src_high_lo_range` | 1 | the pair on `src_high` |
| 20 | 88, 89 | `sign_in_range` | 1 | `g + pc_mask·sign_in` — the generic key's own bound, single |
| 21, 22 | 90–93 | `rd_hi_range`, `rd_lo_range` | 1 | the pair on `rd_selected` |
| 23–31 | 94–111 | `range16_pad_0` … `range16_pad_8` | 0 | 1 |

**The `generic` fraction tree**, `L1[112..116]`: 2 fractions, the table's and one lookup — the
narrowest generic tree of any registered circuit.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 112, 113 | `generic_table` | `−mult_generic` | `generic_key + β·generic_value + β²·generic_result + g` |
| 1 | 114, 115 | `sub_get_sign` | 1 | `g + 257·pc_mask + pc_mask·sign_in + β·pc_mask·sign` |

```text
L{1}[115]  sub_get_sign_den
  positional  lookup_g + 257·M[1] + 1·M[1]·W[47] + lookup_beta·M[1]·W[48]
  reads as    g + m_pc·(e_0 + 1) + β·m_pc·e_1,
              e = (sign_in + SIGN_BASE, sign, 0), SIGN_BASE = 256:
              the key sign_in + 257 and the sub-word's sign bit at m_pc = 1,
              the ZeroEntry at 0. The third tuple position is the constant 0,
              so it adds no β² term (§0.4).
```

**The `decoder` fraction tree**, `L1[116..120]`: 2 fractions, §7.4's with the decoded row at
`W[9..15]`, address for address; the tuple is seven wide, so `β⁶` is live and `g_dec` is
`g − Σ_{j<7} β^j`.

### 8.5 Gate list 0: the 53 enforcing gates

Relations 120–172, in list order, in §3.5's format. The frame's thirteen (120–132) are §7.5's
A, address for address. The family's 40 come from `mem_subword::family_spec`, its private
`booleanity`, `form_times`, `mask_rule`, `addr_rule`, `word_addr_rule` and `value_masked`, and
the public `splice_gates(8)`, which builds **twelve** of them (160–171).

**A. What the row is (133–142)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
133–138 kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2

  133 kind_lb_boolean   W[15]    136 kind_lhu_boolean  W[18]
  134 kind_lh_boolean   W[16]    137 kind_sb_boolean   W[19]
  135 kind_lbu_boolean  W[17]    138 kind_sh_boolean   W[20]

────────────────────────────────────────────────────────────────────────────────────────────
139     decoded_mask_bits — the packed mask is its six bits             Linear, degree 1

  positional  0 = W[15] + 2·W[16] + 4·W[17] + 8·W[18] + 16·W[19] + 32·W[20] − W[14]
  named       0 = Σ_k 2^k·kind_k − decoded_mask,  k in extra_mask::mem_subword order

  reads as  §5.5's 146 over six bits. The stage prompt's modifier-bit masks {0,1,2,3,4,6}
            are not the encoding: S11 froze this table one-hot per mnemonic and append-only
            (memory-ops.md §1).

────────────────────────────────────────────────────────────────────────────────────────────
140–142 wrap_boolean, bit0_boolean, bit1_boolean                        Quadratic, degree 2

  140 wrap_boolean  0 = W[21] − W[21]·W[21]
  141 bit0_boolean  0 = W[24] − W[24]·W[24]
  142 bit1_boolean  0 = W[25] − W[25]·W[25]

  reads as  the two offset bits are read by the address split, by half_aligned and by p_rule,
            each of which is a different statement at a value of two; these three gates are
            what make the split an integer statement and p a function of the offset.
```

**B. Which queries a row makes, and where (143–154)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
143–147 <q>_mask_rule — a query is present exactly where its kind uses it   Quadratic, deg 2

  143 rs1_mask_rule   0 = M[6]  − M[1]·(W[15] + … + W[20])      all six bits
  144 rs2_mask_rule   0 = M[11] − M[1]·W[19] − M[1]·W[20]       STORE
  145 load_mask_rule  0 = M[16] − M[1]·(W[15] + W[16] + W[17] + W[18])   LOADK
  146 ram_mask_rule   0 = M[21] − M[1]·W[19] − M[1]·W[20]       STORE
  147 rd_mask_rule    0 = M[26] − M[1]·(W[15] + W[16] + W[17] + W[18])   LOADK

  reads as  every kind reads rs1; a load reads a word at slot 2 and writes rd; a store reads
            rs2 and rewrites a word at slot 3. LOADK and STORE appear here as sums of bits
            and nowhere as columns (§8.2). On a padding row pc_mask = 0 and every mask is 0
            — S14's control C8, which §8.10 refuses twice.

────────────────────────────────────────────────────────────────────────────────────────────
148–150 <q>_addr_rule — a present register query's index is the decoded one  Quadratic, deg 2

  148 rs1_addr_rule   0 = M[6]·M[7]   − M[6]·W[10]
  149 rs2_addr_rule   0 = M[11]·M[12] − M[11]·W[11]
  150 rd_addr_rule    0 = M[26]·M[27] − M[26]·W[12]

────────────────────────────────────────────────────────────────────────────────────────────
151–152 <q>_addr_rule — a present RAM query names the word, not the byte  Quadratic, degree 2

  151 load_addr_rule  0 = M[16]·M[17] − 4·M[16]·W[22]
  152 ram_addr_rule   0 = M[21]·M[22] − 4·M[21]·W[22]

  reads as  §7.5's 93–94, and the whole reason this family works: `lb` at a word's four
            offsets names one cell, and a byte an `sb` writes is visible to a later `lw`.
            The byte position lives only in the splice (memory-ops.md §2).

────────────────────────────────────────────────────────────────────────────────────────────
153–154 <q>_value_masked — an absent operand reads 0                   Quadratic, degree 2

  153 rs1_value_masked  0 = M[9]  − M[6]·M[9]
  154 rs2_value_masked  0 = M[14] − M[11]·M[14]
```

**C. The address and the offset (155–156)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
155     addr_split — the address is a word index and two offset bits    Linear, degree 1

  positional  0 = M[9] + W[13] − 2^32·W[21] − 4·W[22] − 2·W[25] − W[24]
  named       0 = rs1_read_value + decoded_imm − 2^32·wrap − 4·word_index
                  − 2·bit1 − bit0

  reads as  §7.5's 97 with the two low bits kept. The three obligations on word_index hold
            it below 2^30, so both sides are integers below 2^34 and the field equality is
            an integer one: `wrap` is the true carry, and bit1, bit0 are the address's true
            low two bits — which is what pins the offset the splice then uses
            (memory-ops.md §2, §4.2).

────────────────────────────────────────────────────────────────────────────────────────────
156     half_aligned — a halfword access has bit 0 clear               Quadratic, degree 2

  positional  0 = W[16]·W[24] + W[18]·W[24] + W[20]·W[24]
  named       0 = HALF·bit0,  HALF = kind_lh + kind_lhu + kind_sh

  reads as  not only alignment. At BYTE = 0 with bit0 = 1 the product w·p would be 2^40,
            and §8.7's bound on what a store writes needs w·p to divide 2^32. This gate is
            what removes that case (memory-ops.md §2).
```

**D. The splice (157–171)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
157     word_rule — the word this row splices                          Quadratic, degree 2
        code  family_spec, over LOADK and STORE

  positional  0 = W[30] − (W[15] + W[16] + W[17] + W[18])·M[19]
                        − (W[19] + W[20])·M[24]
  named       0 = word − LOADK·load_read_value − STORE·ram_read_value

  reads as  one decomposition serves both directions: `word` is the word a load read, or the
            word a store is rewriting. It is the only gate of this family that reads
            ram_read_value, which §7's does not read at all.

────────────────────────────────────────────────────────────────────────────────────────────
158     p_ram_rule — the splice power, gated to a store row            Quadratic, degree 2

  positional  0 = W[29] − M[21]·W[26]       named  0 = p_ram − ram_mask·p

  reads as  exists so that store_rule stays degree 2, and so that a row with no RAM query
            writes 0 there (memory-ops.md §4.1).

────────────────────────────────────────────────────────────────────────────────────────────
159     se_rule — the sign-extension term                              Quadratic, degree 2

  positional  0 = W[49] − W[15]·W[48] − W[16]·W[48]
  named       0 = se − SIGNEXT·sign,  SIGNEXT = kind_lb + kind_lh

  reads as  `se` is boolean by construction — a one-hot sum times a table bit — and carries
            no booleanity gate, as S17's `eq` does not (memory-ops.md §4.5).

────────────────────────────────────────────────────────────────────────────────────────────
160–171 splice_gates(8) — the twelve gates whose literals are the width
        code  mem_subword::splice_gates(BYTE_BITS), BYTE_BITS = 8

  160 p_rule              0 = W[26] − M[1] − 255·W[24] − 65535·W[25]
                              − 16711425·W[24]·W[25]
                          0 = p − m_pc − 255·bit0 − 65535·bit1 − K·bit0·bit1,
                              K = 2^24 − 2^16 − 2^8 + 1 = 16711425
      the unique degree-2 form taking the four offsets to 1, 256, 2^16, 2^24;
      m_pc stands where a constant would, so the gate is 0 on the all-zero row

  161 pcopow_rule         0 = W[26]·W[27] − 2^31·M[1]
                          0 = p·pcopow − 2^31·m_pc
      pcopow is the halved copower 2^31/p, so the column fits u32 at p = 1 where
      the copower itself is 2^32; 166 carries the compensating factor 2

  162 wph_rule            0 = W[28] − 32768·W[26] + 32640·(W[15] + W[17] + W[19])·W[26]
                          0 = wph − (w·p)/2,  w = 2^16 − (2^16 − 2^8)·BYTE
      halved for the same reason: w·p is the whole word at offset 3 of a byte
      access and at offset 2 of a halfword one

  163 splice_rule         0 = W[30] − W[33] − W[38] − W[35]·W[26]
                          0 = word − high_scaled − low − sub·p

  164 high_scaled_rule    0 = W[33] − 2·W[31]·W[28]      0 = high_scaled − high·(w·p)
  165 sub_scaled_rule     0 = W[36] − 65536·W[35] − 16711680·BYTE·W[35]
                          0 = sub_scaled − sub·(2^32/w)
  166 low_scaled_rule     0 = W[40] − 2·W[38]·W[27]      0 = low_scaled − low·(2^32/p)
  167 src_sub_rule        0 = M[14] − W[42] − 65536·W[45] + 65280·BYTE·W[45]
                          0 = rs2_read_value − src_sub − w·src_high
  168 src_sub_scaled_rule 0 = W[43] − 65536·W[42] − 16711680·BYTE·W[42]
  169 sign_in_rule        0 = W[47] − W[35] − 255·BYTE·W[35]
                          0 = sign_in − sub·(1 + 255·BYTE)
      256·sub on a byte row and sub on a halfword one, so bit 15 of sign_in is the
      sub-word's sign bit at either width and one U16GetSign lookup serves both

  170 rd_value_rule       0 = W[8] − LOADK·W[35] − (2^32 − 2^16)·W[49]
                              − 65280·BYTE·W[49]
                          0 = rd_selected − LOADK·sub − (2^32 − w)·se
      the 32-bit sign extension: at se = 1 it is sub − w + 2^32, the two's-complement
      word, so lb of 0x88 gives 0xffffff88 and lh of 0x8000 gives 0xffff8000

  171 store_rule          0 = M[25] − M[21]·W[30] − W[42]·W[29] + W[35]·W[29]
                          0 = ram_write_value − ram_mask·word − (src_sub − sub)·p_ram
      exactly `new = old + (src_sub − old_sub)·p` on a store row, and
      ram_write_value = 0 on every other

  reads as  164–169 are where the scaled bounds of §8.6 do their work: sub_scaled < 2^32 is
            sub < w, low_scaled < 2^32 is low < p, and with high < 2^32 directly the
            decomposition is the unique base-(p, w) one. A scaled bound alone would not do
            it — p is a unit in Fr, so a "low" of s·p⁻¹ passes the scaled check while being
            no small integer at all, which is S18's residue hole and what check_copowers
            exists to refuse (memory-ops.md §4.4).

────────────────────────────────────────────────────────────────────────────────────────────
172     next_pc_rule — the next pc is the decoded fall-through         Linear, degree 1

  positional  0 = M[5] − W[9]       named  0 = pc_write_value − decoded_next_pc

  reads as  §7.5's 100.
```

### 8.6 The 36 lookups

`CircuitArtifact::lookups`, in order. The frame's 12 come from the private
`memory::gap_lookups`; the rest from `mem_subword::family_spec` (its private `range16`,
`range32`, the inline `sub_get_sign` and the inline `decode_row`). **Every one of the 36 is
selected by `pc_mask`**: this family has no second selector anywhere.

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0–11 | `gap_hi_pc` … `gap_lo_rd` | `TIMESTAMP` (0) | each query's mask | §7.6's 0–11, address for address | | `< 2^19` |
| 12 | `word_index_hi_range` | `RANGE16` (1) | `M[1]` | `W[23]` | `word_index_hi` | `< 2^16` |
| 13 | `word_index_lo_range` | `RANGE16` | `M[1]` | `W[22] − 2^16·W[23]` | `word_index − 2^16·word_index_hi` | `< 2^16` |
| 14 | `word_index_hi_scaled` | `RANGE16` | `M[1]` | `4·W[23]` | `4·word_index_hi` | `word_index_hi < 2^14` |
| 15, 16 | `high_hi_range`, `high_lo_range` | `RANGE16` | `M[1]` | `W[32]`; `W[31] − 2^16·W[32]` | the pair on `high` | `high < 2^32` |
| 17, 18 | `high_scaled_hi_range`, `high_scaled_lo_range` | `RANGE16` | `M[1]` | `W[34]`; `W[33] − 2^16·W[34]` | the pair on `high_scaled` | `high_scaled < 2^32` |
| 19 | `sub_range` | `RANGE16` | `M[1]` | `W[35]` | `sub` | `< 2^16` |
| 20, 21 | `sub_scaled_hi_range`, `sub_scaled_lo_range` | `RANGE16` | `M[1]` | `W[37]`; `W[36] − 2^16·W[37]` | the pair on `sub_scaled` | `sub < w` |
| 22, 23 | `low_hi_range`, `low_lo_range` | `RANGE16` | `M[1]` | `W[39]`; `W[38] − 2^16·W[39]` | the pair on `low` | `low < 2^32` |
| 24, 25 | `low_scaled_hi_range`, `low_scaled_lo_range` | `RANGE16` | `M[1]` | `W[41]`; `W[40] − 2^16·W[41]` | the pair on `low_scaled` | `low < p` |
| 26 | `src_sub_range` | `RANGE16` | `M[1]` | `W[42]` | `src_sub` | `< 2^16` |
| 27, 28 | `src_sub_scaled_hi_range`, `src_sub_scaled_lo_range` | `RANGE16` | `M[1]` | `W[44]`; `W[43] − 2^16·W[44]` | the pair on `src_sub_scaled` | `src_sub < w` |
| 29, 30 | `src_high_hi_range`, `src_high_lo_range` | `RANGE16` | `M[1]` | `W[46]`; `W[45] − 2^16·W[46]` | the pair on `src_high` | `src_high < 2^32` |
| 31 | `sign_in_range` | `RANGE16` | `M[1]` | `W[47]` | `sign_in` | `< 2^16` — the generic key's bound |
| 32, 33 | `rd_hi_range`, `rd_lo_range` | `RANGE16` | `M[1]` | `W[50]`; `W[8] − 2^16·W[50]` | the pair on `rd_selected` | `rd_selected < 2^32` |
| 34 | `sub_get_sign` | `GENERIC` (2) | `M[1]` | `(W[47] + 256, W[48], 0)` | `(sign_in + SIGN_BASE, sign, 0)` | the gated tuple `(sign_in + 257, sign, 0)` is a row of `S[7..10]` |
| 35 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[9], W[10], W[11], W[12], W[13], W[14])` | the seven decoded columns | a row of `S[0..7]` |

**Every part of the splice carries both bounds, and the reason is not symmetry.** `high`,
`low`, `src_high` and each of the four `_scaled` columns carry a 16+16 pair; `sub` and
`src_sub` carry a single halfword obligation, which is their **exact** direct bound, each being
below the access width and so below `2^16`, so a pair there would be two obligations saying the
same thing. The scaled bounds are what make the row-varying widths fixed: `sub_scaled < 2^32`
is `sub < w`, `low_scaled < 2^32` is `low < p`. `lookup::check_copowers` takes
`(word_index_hi, m_pc)`, `(high, m_pc)`, `(sub, m_pc)`, `(low, m_pc)` and `(src_sub, m_pc)` and
refuses the circuit if any of them loses its direct bound or has it moved under a narrower
selector. **`src_high` needs no scaled bound**: `rs2 = src_sub + w·src_high` with `src_sub < w`
and `w·src_high < 2^48` is an integer equation, so `rs2 < 2^32` forces `src_high < 2^32/w` with
no obligation of its own (`memory-ops.md` §4.4).

**`sign_in_range` is the one place in the VM where a bare `RANGE16` obligation, and not a pair,
is the right answer.** `sign_in < 2^16` puts the gated key in `[SIGN_BASE + 1, SIGN_BASE + 2^16]`,
which is `U16GetSign`'s range exactly — never the `ZeroEntry`, never an AND key, never a
`ShiftPowers` key — because that sub-table's key range is exactly a halfword wide. With three
sub-tables packed into one channel an unbounded key does not *miss* the table, it lands on
another sub-table's row (`lookup.md` §4; `shift-bitwise.md` §3.3), and
`the_generic_key_stays_inside_its_sub_table` in `mem_subword.rs` is that bound as rows.

The channels, `mem_subword::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[51]` | 12 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[52]` | **22** | **32** |
| 6, 7 | `GENERIC` | 2 | `S[7..10]` | `W[53]` | 1 | 2 |
| 8, 9 | `DECODER` | 3 | `S[0..7]` | `W[54]` | 1 | 2 |

`artifact` asserts the four obligation counts. The `RANGE16` row is why this circuit is 26 gate
lists deep at `n = 20` where §7's is 25: 22 obligations plus one table fraction is 23 leaves,
which pads to 32 and takes five row-wise levels instead of four. Nine of the 32 leaves are pads,
the widest padding of any registered circuit's `range16` tree.

### 8.7 Inner layers `L2`–`L6`: the row-wise reduction

The conventions are §3.7's. There are **five** row-wise reduction lists here.

**`L2`, gate list 1, 60 columns, relations 173–232.** `read_2_0` … `read_2_3` and
`write_2_0` … `write_2_3` pair the eight leaves a side as §7.7's do; `timestamp_2_0` …
`timestamp_2_7` are §7.7's; `decoder_2_0` is `decoder_table + decode_row`. The two that differ:

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 24, 25 | 197, 198 | `range16_2_0` | `range16_table + word_index_hi_range` |
| 26, 27 | 199, 200 | `range16_2_1` | `word_index_lo_range + word_index_hi_scaled` |
| 28, 29 | 201, 202 | `range16_2_2` | `high_hi_range + high_lo_range` |
| 30, 31 | 203, 204 | `range16_2_3` | `high_scaled_hi_range + high_scaled_lo_range` |
| 32, 33 | 205, 206 | `range16_2_4` | `sub_range + sub_scaled_hi_range` |
| 34, 35 | 207, 208 | `range16_2_5` | `sub_scaled_lo_range + low_hi_range` |
| 36, 37 | 209, 210 | `range16_2_6` | `low_lo_range + low_scaled_hi_range` |
| 38, 39 | 211, 212 | `range16_2_7` | `low_scaled_lo_range + src_sub_range` |
| 40, 41 | 213, 214 | `range16_2_8` | `src_sub_scaled_hi_range + src_sub_scaled_lo_range` |
| 42, 43 | 215, 216 | `range16_2_9` | `src_high_hi_range + src_high_lo_range` |
| 44, 45 | 217, 218 | `range16_2_10` | `sign_in_range + rd_hi_range` |
| 46, 47 | 219, 220 | `range16_2_11` | `rd_lo_range + range16_pad_0` |
| 48–55 | 221–228 | `range16_2_12` … `range16_2_15` | the remaining eight pads in pairs |
| 56, 57 | 229, 230 | `generic_2_0` | `generic_table + sub_get_sign` |
| 58, 59 | 231, 232 | `decoder_2_0` | `decoder_table + decode_row` |

The tree does not know that a 16+16 pair belongs together: `range16_2_4` adds `sub`'s single
obligation to the high half of `sub_scaled`'s pair, and `range16_2_5` its low half to `low`'s
high half. Only the leaves and the root mean anything.

**`L3`, gate list 2, 32 columns, relations 233–264.** `read_3_0`, `read_3_1`, `write_3_0`,
`write_3_1`; `timestamp_3_0` … `timestamp_3_3`; `range16_3_0` … `range16_3_7`, each the sum of
two `L2` nodes in order; `generic_3_0` and `decoder_3_0`, each a **copy** of its `L2` node.

**`L4`, gate list 3, 18 columns, relations 265–282.** `read_4_0`, `write_4_0`;
`timestamp_4_0`, `timestamp_4_1`; `range16_4_0` … `range16_4_3`; `generic_4_0` and
`decoder_4_0`, copies.

**`L5`, gate list 4, 12 columns, relations 283–294.** `read_5_0` and `write_5_0`, copies;
`timestamp_5_0` = `timestamp_4_0 + timestamp_4_1`; `range16_5_0` and `range16_5_1`;
`generic_5_0` and `decoder_5_0`, copies.

**`L6`, gate list 5, 10 columns, relations 295–304.** `read_6_0`, `write_6_0`,
`timestamp_6_0`, `generic_6_0` and `decoder_6_0` are copies; `range16_6_0` =
`range16_5_0 + range16_5_1` is the one real node of the list — the level the `range16` tree
alone pays for.

### 8.8 The halving layers and the outputs

Gate list `k`, for `6 ≤ k ≤ n + 5`, halves layer `k` into layer `k + 1`, which has `n + 5 − k`
variables. Its ten gates, relation `r = 305 + 10(k − 6)`, are §5.8's, node for node:
`read_{k+1}_0`, `write_{k+1}_0`, then the `num`/`den` pair of each of `timestamp`, `range16`,
`generic` and `decoder`. In the last list, `k = n + 5`, the ten nodes are `read_root`,
`write_root`, `timestamp_num_root`, `timestamp_den_root`, `range16_num_root`,
`range16_den_root`, `generic_num_root`, `generic_den_root`, `decoder_num_root` and
`decoder_den_root`. At `n = 20` the halving lists are 6 to 25, `L7` has 19 variables and `L26`
none. At `n = 22` they are 6 to 27, and the top is `L28`.

**The outputs**, in output-map order, are §5.8's with this family's channel ids: outputs 0 and 1
the memory roots, read at `verify_shard` step 10 against `memory_roots[p]` for `p` the position
of `(5, shard_index)` in `verifier_core::statement_shards`; 2–9 the four channels' `num`/`den`
pairs, read at step 9, each failure `Lookup { channel }` for channel 0, 1, 2 and 3 in turn.

### 8.9 Witness rows

The table shows eight of the 20 live rows of `guests/mem`'s `MEM_SUBWORD` shard, as
`prover::family_fill(5)` writes them, plus the first padding row after them.
`crates/checker/tests/mem_fill.rs`' `the_mem_subword_fill_satisfies_every_gate_and_every_table`
holds exactly these columns to every gate, every range obligation and both table channels in
ordinary CI, over every live row, the two padding rows after them and the shard's last row. The
circuit is also held to a hand-built catalogue of its own: `crates/checker/tests/mem_subword.rs`'
`honest_rows`, **25 rows** — every kind at every offset its width allows, both signs at both
widths over one word whose bytes are `0x01`, `0x7f`, `0xfe` and `0x88`, a store whose source
byte is the byte already there, `lb` into `x0`, a base of `x0`, a wrapping address, a negative
displacement, a compressed `lh`, and the padding row. §8.10's forgeries all start from that
catalogue.

Every live row below reads or rewrites one word: `0x88776655` at `0x20010` for the loads,
`0x11223344` at `0x20018` or `0x2001c` for the stores. `A` `lbu` at offset 0. `B` `lbu` at
offset 3. `C` `lb` at offset 3, the same byte sign-extended. `D` `lhu` at offset 2. `E` `lh` at
offset 2, sign-extended. `F` `sb` at offset 0 from `x6 = 0xdeadbeef`. `G` `sb` at offset 3.
`H` `sh` at offset 2 from `x6 = 0xcafebabe`. `P` the first padding row. Every cell not listed is
0 on all nine; `S[0..7]` hold `MINUS_ONE` at these rows and `S[7..10]` the packed table's rows
0 to 8, and both are omitted.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 44 | 56 | 72 | 81 | 91 | 106 | 139 | 161 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[4]` `pc_read_value` | `0x100a8` | `0x100d8` | `0x10118` | `0x1013c` | `0x10164` | `0x101a0` | `0x10224` | `0x1027c` | 0 |
| `M[5]` `pc_write_value` | `0x100ac` | `0x100dc` | `0x1011c` | `0x10140` | `0x10168` | `0x101a4` | `0x10228` | `0x10280` | 0 |
| `M[7]` `rs1_addr` | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 9 | 0 |
| `M[9]` `rs1_read_value` | `0x20000` | `0x20000` | `0x20000` | `0x20000` | `0x20000` | `0x20000` | `0x20000` | `0x20000` | 0 |
| `M[11]` `rs2_mask` | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 0 |
| `M[14]` `rs2_read_value` | 0 | 0 | 0 | 0 | 0 | `0xdeadbeef` | `0xdeadbeef` | `0xcafebabe` | 0 |
| `M[16]` `load_mask` | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |
| `M[17]` `load_addr` | `0x20010` | `0x20010` | `0x20010` | `0x20010` | `0x20010` | 0 | 0 | 0 | 0 |
| `M[19]` `load_read_value` | `0x88776655` | `0x88776655` | `0x88776655` | `0x88776655` | `0x88776655` | 0 | 0 | 0 | 0 |
| `M[21]` `ram_mask` | 0 | 0 | 0 | 0 | 0 | 1 | 1 | 1 | 0 |
| `M[22]` `ram_addr` | 0 | 0 | 0 | 0 | 0 | `0x20018` | `0x20018` | `0x2001c` | 0 |
| `M[24]` `ram_read_value` | 0 | 0 | 0 | 0 | 0 | `0x11223344` | `0x11223344` | `0x11223344` | 0 |
| `M[25]` `ram_write_value` | 0 | 0 | 0 | 0 | 0 | `0x112233ef` | `0xef223344` | `0xbabe3344` | 0 |
| `M[26]` `rd_mask` | 1 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |
| `M[27]` `rd_addr` | 6 | 6 | 6 | 6 | 6 | 0 | 0 | 0 | 0 |
| `M[30]` `rd_write_value` | `0x55` | `0x88` | `0xffffff88` | `0x8877` | `0xffff8877` | 0 | 0 | 0 | 0 |
| `W[0..6]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[8]` `rd_selected` | `0x55` | `0x88` | `0xffffff88` | `0x8877` | `0xffff8877` | 0 | 0 | 0 | 0 |
| `W[13]` `decoded_imm` | 16 | 19 | 19 | 18 | 18 | 24 | 27 | 30 | 0 |
| `W[14]` `decoded_mask` | 4 | 4 | 1 | 8 | 2 | 16 | 16 | 32 | 0 |
| `W[15..21]` the kind bit set | `lbu` | `lbu` | `lb` | `lhu` | `lh` | `sb` | `sb` | `sh` | none |
| `W[21]` `wrap` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[22]` `word_index` | `0x8004` | `0x8004` | `0x8004` | `0x8004` | `0x8004` | `0x8006` | `0x8006` | `0x8007` | 0 |
| `W[24]` `bit0` | 0 | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 |
| `W[25]` `bit1` | 0 | 1 | 1 | 1 | 1 | 0 | 1 | 1 | 0 |
| `W[26]` `p` | 1 | `2^24` | `2^24` | `2^16` | `2^16` | 1 | `2^24` | `2^16` | 0 |
| `W[27]` `pcopow` | `2^31` | 128 | 128 | `2^15` | `2^15` | `2^31` | 128 | `2^15` | 0 |
| `W[28]` `wph` | 128 | `2^31` | `2^31` | `2^31` | `2^31` | 128 | `2^31` | `2^31` | 0 |
| `W[29]` `p_ram` | 0 | 0 | 0 | 0 | 0 | 1 | `2^24` | `2^16` | 0 |
| `W[30]` `word` | `0x88776655` | `0x88776655` | `0x88776655` | `0x88776655` | `0x88776655` | `0x11223344` | `0x11223344` | `0x11223344` | 0 |
| `W[31]` `high` | `0x887766` | 0 | 0 | 0 | 0 | `0x112233` | 0 | 0 | 0 |
| `W[33]` `high_scaled` | `0x88776600` | 0 | 0 | 0 | 0 | `0x11223300` | 0 | 0 | 0 |
| `W[35]` `sub` | `0x55` | `0x88` | `0x88` | `0x8877` | `0x8877` | `0x44` | `0x11` | `0x1122` | 0 |
| `W[36]` `sub_scaled` | `0x55000000` | `0x88000000` | `0x88000000` | `0x88770000` | `0x88770000` | `0x44000000` | `0x11000000` | `0x11220000` | 0 |
| `W[38]` `low` | 0 | `0x776655` | `0x776655` | `0x6655` | `0x6655` | 0 | `0x223344` | `0x3344` | 0 |
| `W[40]` `low_scaled` | 0 | `0x77665500` | `0x77665500` | `0x66550000` | `0x66550000` | 0 | `0x22334400` | `0x33440000` | 0 |
| `W[42]` `src_sub` | 0 | 0 | 0 | 0 | 0 | `0xef` | `0xef` | `0xbabe` | 0 |
| `W[43]` `src_sub_scaled` | 0 | 0 | 0 | 0 | 0 | `0xef000000` | `0xef000000` | `0xbabe0000` | 0 |
| `W[45]` `src_high` | 0 | 0 | 0 | 0 | 0 | `0xdeadbe` | `0xdeadbe` | `0xcafe` | 0 |
| `W[47]` `sign_in` | `0x5500` | `0x8800` | `0x8800` | `0x8877` | `0x8877` | `0x4400` | `0x1100` | `0x1122` | 0 |
| `W[48]` `sign` | 0 | 1 | 1 | 1 | 1 | 0 | 0 | 0 | 0 |
| `W[49]` `se` | 0 | 0 | 1 | 0 | 1 | 0 | 0 | 0 | 0 |
| `W[50]` `rd_hi` | 0 | 0 | `0xffff` | 0 | `0xffff` | 0 | 0 | 0 | 0 |

`W[32]` `high_hi`, `W[34]` `high_scaled_hi`, `W[37]` `sub_scaled_hi`, `W[39]` `low_hi`,
`W[41]` `low_scaled_hi`, `W[44]` `src_sub_scaled_hi` and `W[46]` `src_high_hi` are each the high
halfword of the column above them and are omitted; so are the four multiplicity columns, which
on a real shard are counts over all `2^20` rows.

`B` and `C` are the same byte read two ways: `sub = 0x88`, `sign = 1` from the packed table, and
`se` is 1 only on `C`, where `rd = 0x88 − 256 + 2^32`. `D` and `E` are the same halfword. `A`
and `F` are the offset-0 rows, where `p = 1`, `low = 0` and `pcopow` is `2^31`, its largest
value — the halving is what keeps the column inside a word there. `G` is the offset-3 byte
store, where `wph` is `2^31` and `high` is 0, the sub-word being the top byte. `H` is the
halfword store, where `src_sub = 0xbabe` is a genuine truncation of `0xcafebabe` and
`src_high = 0xcafe` carries the rest.

### 8.10 What fixes each cell

The per-cell accounting is `crates/checker/tests/mem_subword.rs`' own, and it is a committed
one: `each_gate_is_the_one_that_refuses_its_row` carries 32 tampers, each an edit to a named
honest row beside **the exact set** of relations that refuse it, asserted equal. It ends with a
completeness assertion: of the circuit's 53 enforcing gates the frame's thirteen and every
`*_boolean` are set aside, and each of the remaining **31** must be named by some tamper above.
`every_booleanity_gate_refuses_a_value_of_two` covers the nine booleans this family commits —
the six kind bits, the wrap and the two offset bits — and eight further tests take one question
each.

| cell moved | on the row | refused by, exactly |
| --- | --- | --- |
| `decoded_mask` → `lb`'s | `lbu at 0` | `decoded_mask_bits` |
| the `rs1` query dropped | `lbu through x0` | `rs1_mask_rule` |
| an `rs2` query added | `lbu at 0` | `rs2_mask_rule` |
| a `load` query added | `sb at 0` | `load_mask_rule` |
| a `ram` query added, with `p_ram` and the written word dressed to match | `lbu at 0` | `ram_mask_rule` |
| `rs1_addr` `+ 1` | a load | `rs1_addr_rule` |
| `rs2_addr` `+ 1` | a store | `rs2_addr_rule` |
| `rd_addr` moved | `lbu at 0` | `rd_addr_rule` |
| `load_addr` `+ 4` | `lbu at 0` | `load_addr_rule` |
| `ram_addr` `+ 4` | `sb at 0` | `ram_addr_rule` |
| `rs1_read_value` → 4 | padding | `rs1_value_masked` |
| `rs2_read_value` → 5 | `lbu at 0` | `rs2_value_masked` |
| `word_index` one word too high, the query's address with it | `lbu at 0` | `addr_split` |
| `bit0` set at halfword width | an `lhu` | `half_aligned` |
| `word` → something other than the word read, `low` moved so the splice still holds | `lbu at 0` | `word_rule` |
| `p_ram` → 0 | `sb at 0` | `p_ram_rule` |
| `se` → 1 | `lbu at 0` | `se_rule` |
| `p` → offset 0's value | `lbu at 1` | `p_rule` |
| `pcopow` halved | `lbu at 0` | `pcopow_rule` |
| `wph` moved | `lbu at 3` | `wph_rule` |
| the three parts no longer summing to `word` | `lbu at 0` | `splice_rule` |
| a unit moved from `low` into `high` | `lbu at 0` | `high_scaled_rule` |
| `sub_scaled` `+ 1` | `lbu at 0` | `sub_scaled_rule` |
| `low_scaled` `+ 1` | `lbu at 0` | `low_scaled_rule` |
| `src_sub_scaled` `+ 1` | `sb at 0` | `src_sub_scaled_rule` |
| `src_sub` unrelated to `rs2` | `sb at 0` | `src_sub_rule` |
| `sign_in` not the sub-word's | `lbu at 0` | `sign_in_rule` |
| `rd_selected` `+ 1` | `lbu at 0` | `rd_value_rule` |
| `ram_write_value` `+ 1` | `sb at 0` | `store_rule` |
| `pc_write_value` `+ 4` | `lbu at 0` | `next_pc_rule` |
| an `rd` query rewriting `x10` | padding | `rd_mask_rule`, `rd_addr_rule`, `rd_value_rule` |
| the same, dressed as `lbu` with `decoded_rd = 10` | padding | `rd_mask_rule` |

The eight further tests, each isolating one thing the accounting above cannot show cell by cell:

- **`the_splice_admits_exactly_one_witness_at_a_reduced_width`** — S19's reduced-width
  acceptance, and the reason `splice_gates` takes a width at all. At a **one-bit byte** it
  enumerates the witness space and asserts that the decomposition of a word into
  `high·(w·p) + sub·p + low` is unique, over the family's own gates rather than a transcription
  of them.
- **`a_halfword_at_an_odd_address_is_unprovable`** — `half_aligned` as a row, and the statement
  that `w·p` never reaches `2^40`.
- **`an_lbu_that_yields_more_than_a_byte_is_refused`** — `sub_scaled`'s pair, which is what
  makes `sub < w` rather than `sub < 2^16`.
- **`a_free_high_is_refused`** — `high`'s own pair against the scaled one, S18's residue hole in
  this family's shape.
- **`a_store_source_unrelated_to_rs2_is_refused`** — `src_sub_rule` with its bounds: without it
  `sb` could store a byte no register holds.
- **`the_generic_key_stays_inside_its_sub_table`** — the sign lookup's key bound, which is the
  half of §8.6's argument a test still carries.

On a padding row `pc_mask = 0`, every frame mask is 0, every leaf is 1 and every obligation is
vacuous — all 22 `RANGE16` ones and the generic one included, this family having no selector but
`pc_mask` and the frame's masks. `p_rule` then reads `p = 0`, and with `p` zero `pcopow_rule`,
`wph_rule`, `splice_rule` and `store_rule` all read `0 = 0`: **`pcopow` is free there**, which is
what makes it acceptance 8's negative control (`memory-ops.md` §9). The six kind bits, the wrap
and the two offset bits are free booleans, and with every kind bit 0 the gates hold `word`,
`se`, `rd_selected`, `ram_write_value` and `pc_write_value − decoded_next_pc` to 0. The honest
fill writes 0 everywhere.

---

## 9. `ATOMICS` — family 6

### 9.1 Header

`family_circuit(6, n)` is `atomics::artifact(n)` with `atomics::channels()`, built by
`memory::frame_with_channels_artifact(&QUERIES, n, FamilySpec { .. })` through the private
`family_spec` (`QUERIES`, the `SLOT_*` constants and the per-kind constants `AMOADD` … `AMOMAXU`
are private to `atomics.rs`). It uses **S17's comparison gadget** — `gadgets::comparison` over
the private `the_comparison()` — beside the frame's x0 rule, and **S18's byte AND table**, from
which `or` and `xor` are derived by linearity with no table of their own. Normative spec:
`memory-ops.md` §6. Fill: `prover::family_fill(6)`, the private `fill::atomics`.

89 committed columns (26 `M`, 54 `W`, **9** `S`) and two virtual tables. Gate list 0 writes 132
leaves and holds 46 enforcing gates. 36 lookups on four channels, 10 outputs. At `n = 20`, the
height S19 proves, there are 26 gate lists, the top is `L26`, and the circuit has 472 inner
columns and 518 relations; a shard proof of it is 68,468 bytes. At `n = 22` — the committed
fixture — there are 28 lists, the top is `L28`, and it has 492 inner columns, 538 relations and
102,965 bytes of wire form, the largest of any registered circuit.

**This family's decoded tuple has no immediate, and that is visible everywhere.** Every A
instruction is R-type and an atomic's address is `rs1` alone, so `program::lookup_tuple(6)` is
`pc next_pc rs1 rs2 rd extra_mask` — **six columns, not seven** — which makes
`atomics::TABLE_WIDTH` 6, the claimed decoded row five columns (`W[8..13]`), the decoder tuple
six wide, the setup subtree **nine** columns, the packed generic table `S[6..9]` rather than
`S[7..10]`, and the decoder denominator's top `β` power `β⁵` rather than `β⁶` (§0.4). It is the
second registered circuit whose `g_dec` is `g − Σ_{j<6} β^j`, `MUL_DIV` being the first.

**`DEFAULT_HEIGHTS[ATOMICS]` was `2^16` from S11 until this stage and is `2^20` now**
(`memory-ops.md` §7.1). A circuit carrying a timestamp gap obligation needs 19 variables and a
Mercury opening needs an even count, so `2^20` is the floor for every family that runs cycles;
this was the family the frozen defaults placed below it, and S16 answer 7 deferred the raise to
the stage that gave it a circuit. `family_circuit`'s `trace_vars < 19 ⇒ None` arm now names all
seven execution families, so a key naming this one at `2^16` fails to load rather than panicking
inside `lookup::channel_trees` (`memory-ops.md` §7.2).

`artifact` panics unless the frame is `QUERIES`, the comparison's four parameters are the ones
`assemble` asserts — selector `pc_mask`, `lhs` the RAM query's read value, `rhs` `rs2`'s, and
`signed` exactly `[amomin, amomax]` — the channels carry exactly 10, 19, 6 and 1 obligations,
`lookup::check_copowers` finds a direct range pair under the same selector for the five columns
it bounds by scaling — `word_index_hi` under `pc_mask` and the four `byte_a` keys under
`f_bitwise` — and every gate is zero on the all-zero row. It also panics on every refusal of the
assembly, among them `n < 19` and `n > 30`; `family_circuit` returns `None` for both.

### 9.2 Row kinds

A live row has exactly one kind bit, `constants::extra_mask::atomics`, bit `k` being
`W[13 + k]`. The order is **ascending `funct5`** — `amoadd`, `amoswap`, `lr`, `sc`, `amoxor`,
`amoor`, `amoand`, `amomin`, `amomax`, `amominu`, `amomaxu` — which is not the stage prompt's
listing order; every arm of `ram_value_rule` indexes `KINDS` through its `extra_mask` constant
and never by position, and `the_kind_bits_are_the_extra_mask_constants` in
`crates/checker/tests/atomics.rs` holds each of the eleven `Instr` variants to the bit its arm
uses (`memory-ops.md` §1). `aq` and `rl` are not recorded: on one hart they order nothing, so
`lr.w.aq` and `lr.w` are one kind.

**One row is one read-modify-write.** The RAM query at slot 3 carries the old word as its read
and the new word as its write, and the `rd` query at the same `Δ = 3` takes the old word, at a
different address space; this is the one family with **two queries in one `Δ` slot**, so one
of its rows makes five (`execution-trace.md` §4). A `lw` fills all four slots as well — pc,
`rs1`, its word and `rd` — so what is unique here is the sharing. There is no `load` query: the whole extension keeps its RAM query at
slot 3, `lr.w` included, though `lr.w` is a plain word load and a load's word is at slot 2 for
every other family (`execution-trace.md` §7, frozen at S12).

`old` below is the RAM query's read value, `src` is `rs2`'s, and
`A = Σ_j 2^(8j)·byte_and_j` is the AND accumulator, a linear form and never a column.

| row kind | bit (`decoded_mask`) | `rs2` query | `f_bitwise` | `ram_write_value` | `rd_selected` |
| --- | --- | --- | --- | --- | --- |
| `amoadd` | 0 (1) | yes | 0 | `sum` | `old` |
| `amoswap` | 1 (2) | yes | 0 | `src` | `old` |
| `lr` | 2 (4) | **no** | 0 | `old` | `old` |
| `sc` | 3 (8) | yes | 0 | `src` | **0** |
| `amoxor` | 4 (16) | yes | 1 | `old + src − 2A` | `old` |
| `amoor` | 5 (32) | yes | 1 | `old + src − A` | `old` |
| `amoand` | 6 (64) | yes | 1 | `A` | `old` |
| `amomin` | 7 (128) | yes | 0 | `lo`, ordered signed | `old` |
| `amomax` | 8 (256) | yes | 0 | `old + src − lo`, signed | `old` |
| `amominu` | 9 (512) | yes | 0 | `lo`, ordered unsigned | `old` |
| `amomaxu` | 10 (1024) | yes | 0 | `old + src − lo`, unsigned | `old` |
| padding | none; all 0 | none | a free boolean | 0 | 0 |

All eleven are provable at S19. `next_pc` is the fall-through on every row — no kind computes a
pc, and the A extension has no compressed form, so the fall-through is always `pc + 4`.
`rd = x0` is not a kind: the row still reads and rewrites the word and computes `rd_selected`,
and the frame's x0 rule writes 0.

**`lr.w` has no `rs2` register in its form**, so `m_rs2` is `m_pc` times the other ten bits —
keyed on `b_lr`, never on `is_zero(decoded_rs2)`, which `amoadd.w rd, x0, (rs1)` would also
satisfy (`memory-ops.md` §6.1).

**`sc.w` always succeeds**, storing `rs2` and writing `rd = 0` with no reservation state anywhere
in the machine. That is a conformance deviation and not a soundness one — the verifier still
knows exactly which program ran and what it computed — and it is the emulator's semantics too,
so emulator and circuit agree (`memory-ops.md` §6.6); a machine that keeps a reservation
set may fail an unpaired `sc.w` where this one succeeds, and nothing compares the two, there being no oracle for
what a guest computes and never for how this emulator computes it. `sc_w_always_succeeds` in the row suite refuses both halves of failure:
a nonzero code by `rd_value_rule`, and the word left alone by `ram_value_rule`.

### 9.3 The base layer

"Read by" lists every gate, leaf and obligation whose formula contains the column, taken from
the artifact. A leaf or obligation is named as in §9.4 and §9.6.

**Memory-argument columns, `M[0..26]`** — §2's ATOMICS layout (`w = 5`), the only family with
it, and the bare frame fixture `memory_frame_atomics.bin`; filled by
`trace::build_memory_columns`, committed in `PublicInputs::memory_commitments`, absorbed at G8
before the memory challenges. The frame's slots in `atomics.rs` are `SLOT_PC = 0`,
`SLOT_RS1 = 1`, `SLOT_RS2 = 2`, `SLOT_RAM = 3`, `SLOT_RD = 4`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `memory::CYCLE` | Cycle number | the cycle `c` | leaves `write_*` (all 5); obligations `gap_lo_*` (all 5) |
| `M[1]` | `pc_mask` | `frame(0, FIELD_MASK)` | Row is live | 1 | leaves `read_pc`, `write_pc`; `pc_mask_boolean`, the four mask rules; selector of `gap_hi_pc`, `gap_lo_pc`, the eleven `m_pc` `RANGE16` obligations, both sign lookups and `decode_row` |
| `M[2]` | `pc_addr` | `frame(0, FIELD_ADDR)` | PC address | 0 | leaves `read_pc`, `write_pc` |
| `M[3]` | `pc_read_ts` | `frame(0, FIELD_READ_TS)` | Previous pc write | `4(c − 1)` | leaf `read_pc`; `gap_lo_pc` |
| `M[4]` | `pc_read_value` | `frame(0, FIELD_READ_VALUE)` | Current pc | the instruction's pc | leaf `read_pc`; `decode_row` position 0 |
| `M[5]` | `pc_write_value` | `frame(0, FIELD_WRITE_VALUE)` | Next pc | `pc + 4` | leaf `write_pc`; `next_pc_rule` |
| `M[6]` | `rs1_mask` | `frame(1, FIELD_MASK)` | rs1 present | 1 on every kind | leaves `read_rs1`, `write_rs1`; `rs1_mask_boolean`, `rs1_mask_rule`, `rs1_addr_rule`, `rs1_value_masked`; selector of `gap_hi_rs1`, `gap_lo_rs1` |
| `M[7]` | `rs1_addr` | `frame(1, FIELD_ADDR)` | Address register | the decoded `rs1` | leaves `read_rs1`, `write_rs1`; `rs1_addr_rule` |
| `M[8]` | `rs1_read_ts` | `frame(1, FIELD_READ_TS)` | rs1 previous write | | leaf `read_rs1`; `gap_lo_rs1` |
| `M[9]` | `rs1_read_value` | `frame(1, FIELD_READ_VALUE)` | The word's byte address | `4·word_index` | leaf `read_rs1`; `rs1_writes_back`, `rs1_value_masked`, `addr_word` |
| `M[10]` | `rs1_write_value` | `frame(1, FIELD_WRITE_VALUE)` | rs1 written back | `rs1_read_value` | leaf `write_rs1`; `rs1_writes_back` |
| `M[11]` | `rs2_mask` | `frame(2, FIELD_MASK)` | rs2 present | 1 on every kind but `lr` | leaves `read_rs2`, `write_rs2`; `rs2_mask_boolean`, `rs2_mask_rule`, `rs2_addr_rule`, `rs2_value_masked`; selector of `gap_hi_rs2`, `gap_lo_rs2` |
| `M[12]` | `rs2_addr` | `frame(2, FIELD_ADDR)` | Source register | the decoded `rs2` | leaves `read_rs2`, `write_rs2`; `rs2_addr_rule` |
| `M[13]` | `rs2_read_ts` | `frame(2, FIELD_READ_TS)` | rs2 previous write | | leaf `read_rs2`; `gap_lo_rs2` |
| `M[14]` | `rs2_read_value` | `frame(2, FIELD_READ_VALUE)` | The second operand, `src` | 0 on an `lr` row | leaf `read_rs2`; `rs2_writes_back`, `rs2_value_masked`, `add_rule`, `src_bytes_rule`, `cmp_order`, `lo_rule`, `ram_value_rule`; `cmp_rhs_lo_range` |
| `M[15]` | `rs2_write_value` | `frame(2, FIELD_WRITE_VALUE)` | rs2 written back | `rs2_read_value` | leaf `write_rs2`; `rs2_writes_back` |
| `M[16]` | `ram_mask` | `frame(3, FIELD_MASK)` | The word is present | 1 on every kind | leaves `read_ram`, `write_ram`; `ram_mask_boolean`, `ram_mask_rule`, `ram_addr_rule`; selector of `gap_hi_ram`, `gap_lo_ram` |
| `M[17]` | `ram_addr` | `frame(3, FIELD_ADDR)` | The word's byte address | `4·word_index` | leaves `read_ram`, `write_ram`; `ram_addr_rule` |
| `M[18]` | `ram_read_ts` | `frame(3, FIELD_READ_TS)` | The word's previous write | | leaf `read_ram`; `gap_lo_ram` |
| `M[19]` | `ram_read_value` | `frame(3, FIELD_READ_VALUE)` | The old word, `old` | | leaf `read_ram`; `add_rule`, `old_bytes_rule`, `cmp_order`, `lo_rule`, `ram_value_rule`, `rd_value_rule`; `cmp_lhs_lo_range` |
| `M[20]` | `ram_write_value` | `frame(3, FIELD_WRITE_VALUE)` | The new word | the kind's arm | leaf `write_ram`; `ram_value_rule` |
| `M[21]` | `rd_mask` | `frame(4, FIELD_MASK)` | rd present | 1 on every kind | leaves `read_rd`, `write_rd`; `rd_mask_boolean`, `rd_is_zero_inverse`, `rd_mask_rule`, `rd_addr_rule`; selector of `gap_hi_rd`, `gap_lo_rd` |
| `M[22]` | `rd_addr` | `frame(4, FIELD_ADDR)` | rd register | the decoded `rd` | leaves `read_rd`, `write_rd`; `rd_is_zero_inverse`, `rd_is_zero_at_nonzero`, `rd_addr_rule` |
| `M[23]` | `rd_read_ts` | `frame(4, FIELD_READ_TS)` | rd previous write | | leaf `read_rd`; `gap_lo_rd` |
| `M[24]` | `rd_read_value` | `frame(4, FIELD_READ_VALUE)` | rd old value | | leaf `read_rd` **and nothing else** |
| `M[25]` | `rd_write_value` | `frame(4, FIELD_WRITE_VALUE)` | rd new value | the old word, or 0 into `x0` | leaf `write_rd`; `rd_write_masked` |

**`ram_read_value` is read by six of this family's gates**, where §7's is read by none: it is
both the value handed back in `rd` and the left operand of every arithmetic, bitwise and ordering
arm. That is what makes the `rd` old-value cell, `M[24]`, the family's tamper target instead
(`memory-ops.md` §9).

**Witness columns, `W[0..54]`** — `W[0..7]` filled by `trace::build_frame_witness`, `W[7..50]`
by `fill::atomics` (`W[7]` in place of S14's), `W[50..54]` by `trace::build_multiplicities`
inside `prover::shard_columns`; committed in `ShardProof::witness_commitments`, absorbed at S3
before `g` and `β`.

| address | name | Rust | descriptive name | holds on a live row | read by |
| --- | --- | --- | --- | --- | --- |
| `W[0..5]` | `pc_gap_hi` … `rd_gap_hi` | `memory::gap_hi(s)` | the five gap chunks | `gap >> 19` | `gap_hi_<q>`, `gap_lo_<q>` |
| `W[5]` | `rd_inv` | `memory::rd_inv(5)` | Inverse of the rd index | `rd_addr⁻¹`, or 0 | `rd_is_zero_inverse` |
| `W[6]` | `rd_is_zero` | `memory::rd_is_zero(5)` | rd is `x0` | | the three x0 gates |
| `W[7]` | `rd_selected` | `memory::rd_selected(5)`; `sel` | The word handed back | `old`, or 0 on `sc.w` | `rd_write_masked`, `rd_value_rule` |
| `W[8..13]` | `decoded_next_pc` … `decoded_mask` | `atomics::DECODED` | the claimed decoded row — **five** | the table row after `pc` | `next_pc_rule`, `rs1_addr_rule`, `rs2_addr_rule`, `rd_addr_rule`, `decoded_mask_bits`; `decode_row` positions 1–5 |
| `W[13..24]` | `kind_amoadd` … `kind_amomaxu` | `KINDS[k]` | the eleven kind bits | one-hot on a live row | `kind_<k>_boolean`, `decoded_mask_bits`, the four mask rules, `f_bitwise_rule` (three of them), `ram_value_rule`, `rd_value_rule` (ten of them) |
| `W[24]` | `word_index` | `atomics::WORD_INDEX` | The word's index | `rs1 / 4` | `ram_addr_rule`, `addr_word`; `word_index_lo_range` |
| `W[25]` | `word_index_hi` | `WORD_INDEX_HI` | its high halfword | | `word_index_hi_range`, `word_index_lo_range`, `word_index_hi_scaled` |
| `W[26]` | `sum` | `SUM` | `old + src` reduced | on **every** live row | `add_rule`, `ram_value_rule`; `sum_lo_range` |
| `W[27]` | `sum_hi` | `SUM_HI` | `sum`, high halfword | | `sum_hi_range`, `sum_lo_range` |
| `W[28]` | `add_wrap` | `ADD_WRAP` | the addition's carry | | `add_wrap_boolean`, `add_rule` |
| `W[29]` | `f_bitwise` | `F_BITWISE` | Row is `and`, `or` or `xor` | | `f_bitwise_rule`, `f_bitwise_boolean`; **selector** of the eight `byte_a*` bounds and the four `and_byte_*` lookups |
| `W[30..34]` | `byte_a0` … `byte_a3` | `BYTES_A[j]` | the old word's bytes, low first | `(old >> 8j) & 255` | `old_bytes_rule`; `byte_a{j}_range`, `byte_a{j}_scaled`, `and_byte_{j}` position 0 |
| `W[34..38]` | `byte_b0` … `byte_b3` | `BYTES_B[j]` | `rs2`'s bytes, low first | `(src >> 8j) & 255` | `src_bytes_rule`; `and_byte_{j}` position 1 |
| `W[38..42]` | `byte_and0` … `byte_and3` | `BYTES_AND[j]` | the bytewise AND | `byte_a_j & byte_b_j` | `ram_value_rule`; `and_byte_{j}` position 2 |
| `W[42]` | `old_hi` | `OLD_HI` | `old`, high halfword | | no enforcing gate: `cmp_lhs_hi_range`, `cmp_lhs_lo_range`, `cmp_lhs_get_sign` position 0 |
| `W[43]` | `old_sign` | `OLD_SIGN` | `old`, bit 31 | | `cmp_order`; `cmp_lhs_get_sign` position 1 |
| `W[44]` | `src_hi` | `SRC_HI` | `src`, high halfword | | no enforcing gate: `cmp_rhs_hi_range`, `cmp_rhs_lo_range`, `cmp_rhs_get_sign` position 0 |
| `W[45]` | `src_sign` | `SRC_SIGN` | `src`, bit 31 | | `cmp_order`; `cmp_rhs_get_sign` position 1 |
| `W[46]` | `lt` | `LT` | `old` is the smaller | under the row's ordering | `cmp_order`, `cmp_lt_boolean`, `lo_rule` |
| `W[47]` | `cmp_gap` | `CMP_GAP` | the comparison's gap | `old − src + 2^32·lt` | `cmp_order`; `cmp_gap_lo_range` |
| `W[48]` | `cmp_gap_hi` | `CMP_GAP_HI` | its high halfword | | `cmp_gap_hi_range`, `cmp_gap_lo_range` |
| `W[49]` | `lo` | `LO` | the smaller of the two | | `lo_rule`, `ram_value_rule` |
| `W[50]` | `mult_timestamp` | `MULTIPLICITIES[0]` | Timestamp-table count | | leaf `timestamp_table_num` |
| `W[51]` | `mult_range16` | `MULTIPLICITIES[1]` | 16-bit-table count | 11 obligations under `pc_mask`, 8 under `f_bitwise` | leaf `range16_table_num` |
| `W[52]` | `mult_generic` | `MULTIPLICITIES[2]` | Generic-table count | a live row's two sign lookups land on `U16GetSign`'s rows `2^16 + 1 + old_hi` and `2^16 + 1 + src_hi`; a bitwise row's four AND lookups on rows `1 + byte_a_j`; every switched-off tuple on the `ZeroEntry`, row 0 | leaf `generic_table_num` |
| `W[53]` | `mult_decoder` | `MULTIPLICITIES[3]` | Decoder-table count | per table row `t`: the live cycles at pc `2t`; and every padding row's switched-off tuple (`MINUS_ONE` in all six positions) on the table's lowest non-live row, row 0 | leaf `decoder_table_num` |

`f_bitwise` is this family's **one** second selector, and it is a column for exactly the reason
§5's two halves are: it selects lookups, and `validate` refuses a selector without a booleanity
gate. Eight of the 19 `RANGE16` obligations and four of the six generic lookups sit under it, so
a non-bitwise live row switches twelve tuples off and a bitwise row switches none.

**Setup columns, `S[0..9]`** — two tables, and **nine** columns rather than ten. `S[0..6]` is
the family's decoded table, `program::lookup_tuple(6)` order — `table_pc`, `table_next_pc`,
`table_rs1`, `table_rs2`, `table_rd`, `table_extra_mask`, at weights 1 to `β⁵` — filled by
`program::FamilyTable::column_poly(j)` and committed in program identity. `S[6..9]` is the
packed generic table (§0.3) — `generic_key`, `generic_value`, `generic_result` at 1, `β`, `β²` —
filled by `program::lookup_tables::generic_table(n)`, carried in every key as
`VerifyingKey::generic_table` and covered by the key's SRS digest, not by identity. Each is read
only by its table's denominator. `atomics::TABLE_WIDTH` is 6 and
`constants::generic_table::WIDTH` is 3. A shard opens 89 commitments: 26, 54, the six of
identity's list, then the table's three (`shard-proof.md` §3, §5.1; `jump-branch-slt.md` §6).

**Virtual tables** — `V[range19]` and `V[range16]`, §7.3's, read by `timestamp_table_den` and
`range16_table_den`.

### 9.4 Gate list 0: the 132 leaves

A leaf's relation number equals its `L1` offset, 0 to 131.

**The memory product trees.** The read side is `L1[0..8]` and the write side `L1[8..16]`, each
leaf per §0.6. Five queries fill eight leaves a side, so each side carries **three** pads — the
widest memory padding of any registered family.

| `L1` | node | mask | `AS` | addr | timestamp part | value |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | `read_pc` | `M[1]` | 3 | `M[2]` | `M[3]` | `M[4]` |
| 1 | `read_rs1` | `M[6]` | 1 | `M[7]` | `M[8]` | `M[9]` |
| 2 | `read_rs2` | `M[11]` | 1 | `M[12]` | `M[13]` | `M[14]` |
| 3 | `read_ram` | `M[16]` | 2 | `M[17]` | `M[18]` | `M[19]` |
| 4 | `read_rd` | `M[21]` | 1 | `M[22]` | `M[23]` | `M[24]` |
| 5–7 | `read_pad_0` … `read_pad_2` | — | — | — | — | the literal 1 |
| 8 | `write_pc` | `M[1]` | 3 | `M[2]` | `4·M[0] + 0` | `M[5]` |
| 9 | `write_rs1` | `M[6]` | 1 | `M[7]` | `4·M[0] + 1` | `M[10]` |
| 10 | `write_rs2` | `M[11]` | 1 | `M[12]` | `4·M[0] + 2` | `M[15]` |
| 11 | `write_ram` | `M[16]` | 2 | `M[17]` | `4·M[0] + 3` | `M[20]` |
| 12 | `write_rd` | `M[21]` | 1 | `M[22]` | `4·M[0] + 3` | `M[25]` |
| 13–15 | `write_pad_0` … `write_pad_2` | — | — | — | — | the literal 1 |

`write_ram` and `write_rd` share `Δ = 3` at address spaces 2 and 1, which is what lets one row
be one read-modify-write (`memory-ops.md` §6.1).

**The `timestamp` fraction tree**, `L1[16..48]`: 16 fractions, the table's then 10 gap
obligations then **5** pads — the table's, then `gap_hi`/`gap_lo` for `pc`, `rs1`, `rs2`, `ram`
and `rd`, with `Δ − 1` of `−1`, 0, 1, 2 and 2 in the low chunks' constants.

**The `range16` fraction tree**, `L1[48..112]`: **32 fractions**, the table's then 19
obligations then 12 pads. Eleven obligations are under `pc_mask` and eight under `f_bitwise`.

| fraction | `L1` | node | numerator | denominator (named) | selector |
| --- | --- | --- | --- | --- | --- |
| 0 | 48, 49 | `range16_table` | `−mult_range16` | `V[range16] + g` | — |
| 1, 2 | 50–53 | `cmp_lhs_hi_range`, `cmp_lhs_lo_range` | 1 | the 16+16 pair on `ram_read_value` | `pc_mask` |
| 3, 4 | 54–57 | `cmp_rhs_hi_range`, `cmp_rhs_lo_range` | 1 | the pair on `rs2_read_value` | `pc_mask` |
| 5, 6 | 58–61 | `cmp_gap_hi_range`, `cmp_gap_lo_range` | 1 | the pair on `cmp_gap` | `pc_mask` |
| 7 | 62, 63 | `word_index_hi_range` | 1 | `g + pc_mask·word_index_hi` | `pc_mask` |
| 8 | 64, 65 | `word_index_lo_range` | 1 | `g + pc_mask·word_index − 2^16·pc_mask·word_index_hi` | `pc_mask` |
| 9 | 66, 67 | `word_index_hi_scaled` | 1 | `g + 4·pc_mask·word_index_hi` | `pc_mask` |
| 10, 11 | 68–71 | `sum_hi_range`, `sum_lo_range` | 1 | the pair on `sum` | `pc_mask` |
| 12 | 72, 73 | `byte_a0_range` | 1 | `g + f_bitwise·byte_a0` | `f_bitwise` |
| 13 | 74, 75 | `byte_a0_scaled` | 1 | `g + 256·f_bitwise·byte_a0` | `f_bitwise` |
| 14–19 | 76–87 | `byte_a1_range` … `byte_a3_scaled` | 1 | the same pair per byte | `f_bitwise` |
| 20–31 | 88–111 | `range16_pad_0` … `range16_pad_11` | 0 | 1 | — |

**The `generic` fraction tree**, `L1[112..128]`: 8 fractions, the table's then 6 lookups then 1
pad.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 112, 113 | `generic_table` | `−mult_generic` | `generic_key + β·generic_value + β²·generic_result + g` |
| 1 | 114, 115 | `cmp_lhs_get_sign` | 1 | `g + 257·pc_mask + pc_mask·old_hi + β·pc_mask·old_sign` |
| 2 | 116, 117 | `cmp_rhs_get_sign` | 1 | `g + 257·pc_mask + pc_mask·src_hi + β·pc_mask·src_sign` |
| 3 | 118, 119 | `and_byte_0` | 1 | `g + f_bitwise + f_bitwise·byte_a0 + β·f_bitwise·byte_b0 + β²·f_bitwise·byte_and0` |
| 4–6 | 120–125 | `and_byte_1` … `and_byte_3` | 1 | as fraction 3 over byte `j` |
| 7 | 126, 127 | `generic_pad_0` | 0 | 1 |

The two literals are `constants::generic_table`'s gated key bases, `SIGN_BASE + 1 = 257` and
`AND_BASE + 1 = 1`. A sign lookup's third tuple position is the constant 0, so it adds no `β²`
term; an `and_byte` lookup's is a column, so it does (§0.4).

**The `decoder` fraction tree**, `L1[128..132]`: 2 fractions, and **six** wide.

| fraction | `L1` | node | numerator | denominator (named) |
| --- | --- | --- | --- | --- |
| 0 | 128, 129 | `decoder_table` | `−mult_decoder` | `table_pc + β·table_next_pc + β²·table_rs1 + β³·table_rs2 + β⁴·table_rd + β⁵·table_extra_mask + g` |
| 1 | 130, 131 | `decode_row` | 1 | `g_dec + (1 + β + β² + β³ + β⁴ + β⁵)·pc_mask + pc_mask·pc_read_value + β·pc_mask·decoded_next_pc + β²·pc_mask·decoded_rs1 + β³·pc_mask·decoded_rs2 + β⁴·pc_mask·decoded_rd + β⁵·pc_mask·decoded_mask` |

`β⁶` appears nowhere in this circuit, and `g_dec` is `g − Σ_{j<6} β^j` (§0.4, §6.1).

### 9.5 Gate list 0: the 46 enforcing gates

Relations 132–177, in list order, in §3.5's format. The frame's eleven (132–142) are §7.5's A
over five queries: five mask booleanity gates, **two** write-backs (`rs1` and `rs2` — the RAM
query is not read-only here, and there is no `load` query), and the four x0 gates. The family's
35 come from `atomics::family_spec`, its private helpers, and `gadgets::comparison`.

**A. What the row is (143–154)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
143–153 kind_<k>_boolean — each kind bit is a bit                       Quadratic, degree 2

  143 kind_amoadd_boolean   W[13]    149 kind_amoand_boolean   W[19]
  144 kind_amoswap_boolean  W[14]    150 kind_amomin_boolean   W[20]
  145 kind_lr_boolean       W[15]    151 kind_amomax_boolean   W[21]
  146 kind_sc_boolean       W[16]    152 kind_amominu_boolean  W[22]
  147 kind_amoxor_boolean   W[17]    153 kind_amomaxu_boolean  W[23]
  148 kind_amoor_boolean    W[18]

────────────────────────────────────────────────────────────────────────────────────────────
154     decoded_mask_bits — the packed mask is its eleven bits          Linear, degree 1

  positional  0 = W[13] + 2·W[14] + 4·W[15] + 8·W[16] + 16·W[17] + 32·W[18] + 64·W[19]
                  + 128·W[20] + 256·W[21] + 512·W[22] + 1024·W[23] − W[12]
  named       0 = Σ_k 2^k·kind_k − decoded_mask,  k in extra_mask::atomics order

  reads as  §5.5's 146 over eleven bits, and W[12] is the fifth decoded column, not the
            sixth: this family's tuple has no imm. One-hotness is the decoder table's
            (lookup.md §10).
```

**B. Which queries a row makes, and where (155–164)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
155–158 <q>_mask_rule — a query is present exactly where its kind uses it   Quadratic, deg 2

  155 rs1_mask_rule  0 = M[6]  − M[1]·(W[13] + … + W[23])     all eleven bits
  156 rs2_mask_rule  0 = M[11] − M[1]·(every bit but W[15])   ten bits: not lr
  157 ram_mask_rule  0 = M[16] − M[1]·(W[13] + … + W[23])     all eleven
  158 rd_mask_rule   0 = M[21] − M[1]·(W[13] + … + W[23])     all eleven

  reads as  every kind reads rs1, rewrites the word and writes rd; only `lr.w` skips rs2,
            keyed on its own bit and never on is_zero(decoded_rs2), which
            `amoadd.w rd, x0, (rs1)` would also satisfy (memory-ops.md §6.1). On a padding
            row pc_mask = 0 and every mask is 0 — S14's control C8, which §9.10 refuses
            three times, once on the RAM query.

────────────────────────────────────────────────────────────────────────────────────────────
159–161 <q>_addr_rule — a present register query's index is the decoded one  Quadratic, deg 2

  159 rs1_addr_rule  0 = M[6]·M[7]   − M[6]·W[9]
  160 rs2_addr_rule  0 = M[11]·M[12] − M[11]·W[10]
  161 rd_addr_rule   0 = M[21]·M[22] − M[21]·W[11]

────────────────────────────────────────────────────────────────────────────────────────────
162     ram_addr_rule — the RAM query names the word                   Quadratic, degree 2

  positional  0 = M[16]·M[17] − 4·M[16]·W[24]
  named       0 = ram_mask·(ram_addr − 4·word_index)

────────────────────────────────────────────────────────────────────────────────────────────
163–164 <q>_value_masked — an absent operand reads 0                   Quadratic, degree 2

  163 rs1_value_masked  0 = M[9]  − M[6]·M[9]
  164 rs2_value_masked  0 = M[14] − M[11]·M[14]

  reads as  164 is what makes `lr.w`'s second operand 0 rather than free: its rs2 query is
            absent, so every arm and every comparison on that row reads a zero `src`.
```

**C. The address (165)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
165     addr_word — the address is four times a word index             Linear, degree 1

  positional  0 = M[9] − 4·W[24]       named  0 = rs1_read_value − 4·word_index

  reads as  an atomic's address is rs1 alone: the A extension has no immediate, so there is
            no wrap bit and no offset bits. §9.6's three obligations hold word_index below
            2^30, which makes this an integer equation — so a misaligned atomic has no
            witness (§9.10), and `rs1 < 2^32` is **derived** here rather than assumed, which
            is what the write-side induction needs (memory-ops.md §5.2).
```

**D. The eleven arms (166–177)**

```text
────────────────────────────────────────────────────────────────────────────────────────────
166–167 add_wrap_boolean, add_rule — the addition             Quadratic/Linear, degrees 2, 1

  166 add_wrap_boolean  0 = W[28] − W[28]·W[28]
  167 add_rule          0 = M[19] + M[14] − W[26] − 2^32·W[28]
                        0 = old + src − sum − 2^32·add_wrap

  reads as  **ungated**, so `sum` is the true reduced sum on every live row and its 16+16
            pair sits under pc_mask. Gating either to the amoadd bit would leave `sum`
            unbounded on the other ten kinds and ram_write_value pinned by nothing on an
            add row (memory-ops.md §6.3). Both operands are below 2^32 by the comparison's
            own pairs, so one boolean wrap holds the carry and (sum, add_wrap) is unique.

────────────────────────────────────────────────────────────────────────────────────────────
168–169 f_bitwise_boolean, f_bitwise_rule — the bitwise half   Quadratic/Linear, degrees 2, 1

  168 f_bitwise_boolean  0 = W[29] − W[29]·W[29]
  169 f_bitwise_rule     0 = W[29] − W[19] − W[18] − W[17]
                         0 = f_bitwise − (kind_amoand + kind_amoor + kind_amoxor)

  reads as  the **three** bitwise kinds, not amoand alone: gating the lookups by one bit
            would leave amoor and amoxor reading free byte_and columns and writing an
            arbitrary field element into RAM. It is a column because it selects lookups,
            and then it carries the booleanity gate validate refuses a selector without.

────────────────────────────────────────────────────────────────────────────────────────────
170–171 old_bytes_rule, src_bytes_rule — both operands' bytes         Linear, degree 1

  170 old_bytes_rule  0 = M[19] − W[30] − 256·W[31] − 2^16·W[32] − 2^24·W[33]
  171 src_bytes_rule  0 = M[14] − W[34] − 256·W[35] − 2^16·W[36] − 2^24·W[37]

  reads as  ungated, like 167: the decompositions hold on every live row, and it is the key
            bounds under f_bitwise that make the bytes bytes where the table is read.

────────────────────────────────────────────────────────────────────────────────────────────
172–173 cmp_order, cmp_lt_boolean — the comparison               Quadratic, degree 2
        code  gadgets::comparison(&the_comparison()), whose equation is
              gadgets::comparison_equation(c, 32)

  positional  0 = M[19] − M[14] + 2^32·W[46] − W[47]
                  − 2^32·W[20]·W[43] + 2^32·W[20]·W[45]
                  − 2^32·W[21]·W[43] + 2^32·W[21]·W[45]
  named       0 = old − src − 2^32·sc·(old_sign − src_sign) + 2^32·lt − cmp_gap,
              sc = kind_amomin + kind_amomax
  173 cmp_lt_boolean  0 = W[46] − W[46]·W[46]

  reads as  §4's one ungated degree-2 comparison, unchanged: `sc` is the signed half, the
            signs come from U16GetSign over range-checked halfwords, and cmp_gap's own range
            pair carries the soundness. **The gadget's four parameters are asserted at
            construction** — selector, signed, lhs and rhs — because each wrong choice is a
            silent, total break of four of the eleven kinds with nothing else in the circuit
            to catch it (memory-ops.md §6.4), and `the_comparison_is_over_the_old_word_and_rs2`
            reads all four back off the artifact.

────────────────────────────────────────────────────────────────────────────────────────────
174     lo_rule — the smaller of the two                              Quadratic, degree 2

  positional  0 = W[49] − M[14] − W[46]·M[19] + W[46]·M[14]
  named       0 = lo − src − lt·(old − src)

  reads as  `lo` is the smaller under whichever ordering `lt` settled. The larger is the
            linear form old + src − lo, exact in both orderings because {lo, old + src − lo}
            is {old, src} as a set — so amomax and amomaxu need no second column.

────────────────────────────────────────────────────────────────────────────────────────────
175     ram_value_rule — the new word, all eleven arms                Quadratic, degree 2

  named  0 = ram_write_value
             − kind_lr·old − (kind_sc + kind_amoswap)·src − kind_amoadd·sum
             − kind_amoand·A − kind_amoor·(old + src − A) − kind_amoxor·(old + src − 2A)
             − (kind_amomin + kind_amominu)·lo
             − (kind_amomax + kind_amomaxu)·(old + src − lo)
         with A = Σ_j 2^(8j)·byte_and_j inlined as a linear form, 28 products in all

  reads as  the largest gate in the manifest by product count. `or` and `xor` are derived
            from the one AND accumulator by linearity, exact over the integers because no
            carry crosses a byte, and there is no OR table and no XOR table. Each arm is a
            kind bit times a column or a linear form, so the whole gate is degree 2. On a
            row with no kind bit — a padding row — every product vanishes and the gate holds
            ram_write_value to 0, which is one of the three refusals of §9.10's RAM C8.

────────────────────────────────────────────────────────────────────────────────────────────
176     rd_value_rule — the word handed back                          Quadratic, degree 2

  positional  0 = W[7] − (every kind bit but W[16])·M[19]      ten products
  named       0 = rd_selected − (Σ_{k ≠ sc} kind_k)·old

  reads as  every kind but `sc.w` hands back the word it found; `sc.w` writes its success
            code, which is always 0 (§9.2). This is the whole of the family's return value:
            rd_selected is the frame's and the x0 gadget masks it, so this gate is the only
            thing tying it to memory.

────────────────────────────────────────────────────────────────────────────────────────────
177     next_pc_rule — the next pc is the decoded fall-through         Linear, degree 1

  positional  0 = M[5] − W[8]       named  0 = pc_write_value − decoded_next_pc

  reads as  §7.5's 100; the A extension has no compressed form, so the fall-through is
            always pc + 4.
```

### 9.6 The 36 lookups

`CircuitArtifact::lookups`, in order. The frame's 10 come from the private
`memory::gap_lookups`; the comparison's 8 from `gadgets::comparison`; the rest from
`atomics::family_spec` (its private `range16`, `range32`, `byte_key_bound`, `generic` and the
inline `decode_row`). Eleven `RANGE16` obligations are selected by `pc_mask` and eight by
`f_bitwise`; four of the six generic lookups are under `f_bitwise` too.

| # | name | channel | selector | tuple, positional | tuple, named | holds where the selector is 1 |
| --- | --- | --- | --- | --- | --- | --- |
| 0–9 | `gap_hi_pc` … `gap_lo_rd` | `TIMESTAMP` (0) | each query's mask | over `pc`, `rs1`, `rs2`, `ram`, `rd` | | `< 2^19` |
| 10 | `cmp_lhs_hi_range` | `RANGE16` (1) | `M[1]` | `W[42]` | `old_hi` | `< 2^16` |
| 11 | `cmp_lhs_lo_range` | `RANGE16` | `M[1]` | `M[19] − 2^16·W[42]` | `ram_read_value − 2^16·old_hi` | `< 2^16` |
| 12 | `cmp_rhs_hi_range` | `RANGE16` | `M[1]` | `W[44]` | `src_hi` | `< 2^16` |
| 13 | `cmp_rhs_lo_range` | `RANGE16` | `M[1]` | `M[14] − 2^16·W[44]` | `rs2_read_value − 2^16·src_hi` | `< 2^16` |
| 14 | `cmp_gap_hi_range` | `RANGE16` | `M[1]` | `W[48]` | `cmp_gap_hi` | `< 2^16` |
| 15 | `cmp_gap_lo_range` | `RANGE16` | `M[1]` | `W[47] − 2^16·W[48]` | `cmp_gap − 2^16·cmp_gap_hi` | `< 2^16` |
| 16 | `word_index_hi_range` | `RANGE16` | `M[1]` | `W[25]` | `word_index_hi` | `< 2^16` |
| 17 | `word_index_lo_range` | `RANGE16` | `M[1]` | `W[24] − 2^16·W[25]` | `word_index − 2^16·word_index_hi` | `< 2^16` |
| 18 | `word_index_hi_scaled` | `RANGE16` | `M[1]` | `4·W[25]` | `4·word_index_hi` | `word_index_hi < 2^14` |
| 19 | `sum_hi_range` | `RANGE16` | `M[1]` | `W[27]` | `sum_hi` | `< 2^16` |
| 20 | `sum_lo_range` | `RANGE16` | `M[1]` | `W[26] − 2^16·W[27]` | `sum − 2^16·sum_hi` | `< 2^16` |
| 21 | `byte_a0_range` | `RANGE16` | `W[29]` | `W[30]` | `byte_a0` | `< 2^16` |
| 22 | `byte_a0_scaled` | `RANGE16` | `W[29]` | `256·W[30]` | `2^8·byte_a0` | `< 2^16`, i.e. `byte_a0 < 2^8` |
| 23–28 | `byte_a1_range` … `byte_a3_scaled` | `RANGE16` | `W[29]` | `W[31]`, `256·W[31]`, `W[32]`, `256·W[32]`, `W[33]`, `256·W[33]` | the same pair per byte | `byte_a_j < 2^8` |
| 29 | `cmp_lhs_get_sign` | `GENERIC` (2) | `M[1]` | `(W[42] + 256, W[43], 0)` | `(old_hi + SIGN_BASE, old_sign, 0)` | the gated tuple `(old_hi + 257, old_sign, 0)` is a row of `S[6..9]` |
| 30 | `cmp_rhs_get_sign` | `GENERIC` | `M[1]` | `(W[44] + 256, W[45], 0)` | `(src_hi + SIGN_BASE, src_sign, 0)` | as 29 |
| 31 | `and_byte_0` | `GENERIC` | `W[29]` | `(W[30], W[34], W[38])` | `(byte_a0 + AND_BASE, byte_b0, byte_and0)` | the gated tuple `(byte_a0 + 1, byte_b0, byte_and0)` is a row of `S[6..9]` |
| 32–34 | `and_byte_1` … `and_byte_3` | `GENERIC` | `W[29]` | `(W[31], W[35], W[39])`, `(W[32], W[36], W[40])`, `(W[33], W[37], W[41])` | the same per byte | as 31 |
| 35 | `decode_row` | `DECODER` (3) | `M[1]` | `(M[4], W[8], W[9], W[10], W[11], W[12])` | `(pc_read_value, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_mask)` | a row of `S[0..6]` — **six** wide |

Read in pairs: each `gap_hi`/`gap_lo` puts a read strictly before its own write, and each
`_hi_range`/`_lo_range` bounds `ram_read_value`, `rs2_read_value`, `cmp_gap`, `word_index` and
`sum` below `2^32`. **The comparison's two operand pairs are under `pc_mask`, so `old` and `src`
are bounded on every live row, whatever the kind** — which is what the whole write-side chain of
`memory-ops.md` §6.5 rests on: `sum` by its own pair, `A`, `or` and `xor` by the AND table's
domain, `lo` and `old + src − lo` by being `old` and `src` in some order. There is no direct
range check on `ram_write_value` anywhere, and none of the eight arms needs one.

**The four byte keys carry S18's pair, and this family inherits S18's hole with the table.**
With `byte_a0` unbounded the gated key `65_824` is `ShiftPowers`' row for `s = 31`,
`(65_824, 2^31, 1)`, so `byte_b0 = 2^31` and `byte_and0 = 1` satisfy the lookup, and an
`amoand.w` of `65_823` with `2^31` proves `and = 1` where the answer is 0 — and `or` and `xor`,
derived from the same accumulator, are wrong with it. The pair under `f_bitwise` is what refuses
it, `lookup::check_copowers` takes all four keys with that selector, and
`a_byte_key_outside_the_and_table_is_refused` is the attack as a row
(`shift-bitwise.md` §3.3; `memory-ops.md` §6.5).

The channels, `atomics::channels()`, in output order:

| outputs | channel | id | table | multiplicity | obligations | fractions, padded |
| --- | --- | --- | --- | --- | --- | --- |
| 2, 3 | `TIMESTAMP` | 0 | `V[range19]` | `W[50]` | 10 | 16 |
| 4, 5 | `RANGE16` | 1 | `V[range16]` | `W[51]` | **19** | **32** |
| 6, 7 | `GENERIC` | 2 | `S[6..9]` | `W[52]` | 6 | 8 |
| 8, 9 | `DECODER` | 3 | `S[0..6]` | `W[53]` | 1 | 2 |

`artifact` asserts the four obligation counts. The `RANGE16` row is why this circuit is 26 gate
lists deep at `n = 20`: 19 obligations plus one table fraction is 20 leaves, which pads to 32
and takes five row-wise levels instead of four. Twelve of the 32 leaves are pads.

### 9.7 Inner layers `L2`–`L6`: the row-wise reduction

The conventions are §3.7's. There are **five** row-wise reduction lists here.

**`L2`, gate list 1, 66 columns, relations 178–243.** `read_2_0` … `read_2_3` and
`write_2_0` … `write_2_3` pair the eight leaves a side; `timestamp_2_0` … `timestamp_2_7` pair
the sixteen timestamp fractions — `timestamp_2_0` = `timestamp_table + gap_hi_pc`, then the five
`gap_lo`/`gap_hi` seams in query order, `timestamp_2_5` = `gap_lo_rd + timestamp_pad_0`, and two
pad pairs. The rest:

| `L2` | relations | node | formula |
| --- | --- | --- | --- |
| 24, 25 | 202, 203 | `range16_2_0` | `range16_table + cmp_lhs_hi_range` |
| 26, 27 | 204, 205 | `range16_2_1` | `cmp_lhs_lo_range + cmp_rhs_hi_range` |
| 28, 29 | 206, 207 | `range16_2_2` | `cmp_rhs_lo_range + cmp_gap_hi_range` |
| 30, 31 | 208, 209 | `range16_2_3` | `cmp_gap_lo_range + word_index_hi_range` |
| 32, 33 | 210, 211 | `range16_2_4` | `word_index_lo_range + word_index_hi_scaled` |
| 34, 35 | 212, 213 | `range16_2_5` | `sum_hi_range + sum_lo_range` |
| 36, 37 | 214, 215 | `range16_2_6` | `byte_a0_range + byte_a0_scaled` |
| 38–43 | 216–221 | `range16_2_7` … `range16_2_9` | the remaining three byte pairs |
| 44–55 | 222–233 | `range16_2_10` … `range16_2_15` | the twelve pads in pairs |
| 56, 57 | 234, 235 | `generic_2_0` | `generic_table + cmp_lhs_get_sign` |
| 58, 59 | 236, 237 | `generic_2_1` | `cmp_rhs_get_sign + and_byte_0` |
| 60, 61 | 238, 239 | `generic_2_2` | `and_byte_1 + and_byte_2` |
| 62, 63 | 240, 241 | `generic_2_3` | `and_byte_3 + generic_pad_0` |
| 64, 65 | 242, 243 | `decoder_2_0` | `decoder_table + decode_row` |

`range16_2_6` through `range16_2_9` are the one place where a 16+16 pair lands in one node: a
byte key's direct and scaled halves are adjacent in artifact order, so each byte's pair is added
as a single fraction node. The tree does not know that, and nothing depends on it.

**`L3`, gate list 2, 34 columns, relations 244–277.** `read_3_0`, `read_3_1`, `write_3_0`,
`write_3_1`; `timestamp_3_0` … `timestamp_3_3`; `range16_3_0` … `range16_3_7`;
`generic_3_0` and `generic_3_1`, each the sum of two `L2` generic nodes; `decoder_3_0`, a copy.

**`L4`, gate list 3, 18 columns, relations 278–295.** `read_4_0`, `write_4_0`;
`timestamp_4_0`, `timestamp_4_1`; `range16_4_0` … `range16_4_3`;
`generic_4_0` = `generic_3_0 + generic_3_1`; `decoder_4_0`, a copy.

**`L5`, gate list 4, 12 columns, relations 296–307.** `read_5_0` and `write_5_0`, copies;
`timestamp_5_0` = `timestamp_4_0 + timestamp_4_1`; `range16_5_0` and `range16_5_1`;
`generic_5_0` and `decoder_5_0`, copies.

**`L6`, gate list 5, 10 columns, relations 308–317.** `read_6_0`, `write_6_0`,
`timestamp_6_0`, `generic_6_0` and `decoder_6_0` are copies; `range16_6_0` =
`range16_5_0 + range16_5_1` is the one real node of the list.

### 9.8 The halving layers and the outputs

Gate list `k`, for `6 ≤ k ≤ n + 5`, halves layer `k` into layer `k + 1`, which has `n + 5 − k`
variables. Its ten gates, relation `r = 318 + 10(k − 6)`, are §5.8's, node for node. In the last
list, `k = n + 5`, the ten nodes are `read_root`, `write_root`, `timestamp_num_root`,
`timestamp_den_root`, `range16_num_root`, `range16_den_root`, `generic_num_root`,
`generic_den_root`, `decoder_num_root` and `decoder_den_root`. At `n = 20` the halving lists are
6 to 25, `L7` has 19 variables and `L26` none, and the roots are relations 508–517. At `n = 22`
they are 6 to 27, the top is `L28`, and the roots are 528–537.

**The outputs**, in output-map order, are §5.8's with this family's position: outputs 0 and 1 the
memory roots, read at `verify_shard` step 10 against `memory_roots[p]` for `p` the position of
`(6, shard_index)` in `verifier_core::statement_shards` — last of the seven shards in S19's
statement; 2–9 the four channels' `num`/`den` pairs, read at step 9, each failure
`Lookup { channel }` for channel 0, 1, 2 and 3 in turn.

### 9.9 Witness rows

The table shows eight of the 15 live rows of `guests/mem`'s `ATOMICS` shard, as
`prover::family_fill(6)` writes them, plus the first padding row after them.
`crates/checker/tests/mem_fill.rs`' `the_atomics_fill_satisfies_every_gate_and_every_table`
holds exactly these columns to every gate, every range obligation and both table channels in
ordinary CI. The circuit is also held to a hand-built catalogue of its own:
`crates/checker/tests/atomics.rs`' `honest_rows`, **25 live rows and the padding row** — every
one of the eleven kinds, a sum past `2^32`, an `x0` destination, the sign boundary in both
operand orders for all four min/max kinds, the bitwise trio over a second pattern, a row at word
zero and a row at the top of the addressable window. §9.10's forgeries all start from that
catalogue.

Every live row below names the word at `0x20020` through `x13`. `A` `amoadd.w` where the sum
carries: `0xffffffff + 1` is 0 with `add_wrap = 1`. `B` `amoswap.w`. `C` `amoand.w` and `D`
`amoxor.w`, over the same operand pair, the two bitwise rows. `E` `amomin.w` and `F`
`amominu.w`, over `0x7fffffff` and `0x80000000` — the one operand pair where the signed and the
unsigned orderings disagree, and they answer differently. `G` `lr.w`, which makes no `rs2`
query. `H` `sc.w`, which stores `rs2` and returns 0. `P` the first padding row. Every cell not
listed is 0 on all nine; `S[0..6]` hold `MINUS_ONE` at these rows and `S[6..9]` the packed
table's rows 0 to 8, and both are omitted.

| column | `A` | `B` | `C` | `D` | `E` | `F` | `G` | `H` | `P` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `M[0]` `cycle` | 192 | 183 | 219 | 234 | 244 | 251 | 268 | 273 | 0 |
| `M[1]` `pc_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[4]` `pc_read_value` | `0x102f8` | `0x102d4` | `0x10364` | `0x103a0` | `0x103c8` | `0x103e4` | `0x10428` | `0x1043c` | 0 |
| `M[5]` `pc_write_value` | `0x102fc` | `0x102d8` | `0x10368` | `0x103a4` | `0x103cc` | `0x103e8` | `0x1042c` | `0x10440` | 0 |
| `M[7]` `rs1_addr` | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 13 | 0 |
| `M[9]` `rs1_read_value` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | 0 |
| `M[11]` `rs2_mask` | 1 | 1 | 1 | 1 | 1 | 1 | **0** | 1 | 0 |
| `M[12]` `rs2_addr` | 6 | 6 | 6 | 6 | 6 | 6 | 0 | 7 | 0 |
| `M[14]` `rs2_read_value` | 1 | `0x0f0f0f0f` | `0x0ff0f00f` | `0x0ff0f00f` | `0x80000000` | `0x80000000` | 0 | `0x33334444` | 0 |
| `M[16]` `ram_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[17]` `ram_addr` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | `0x20020` | 0 |
| `M[19]` `ram_read_value` (`old`) | `0xffffffff` | `0x5a5a5a5a` | `0xf0f00ff0` | `0xf0f00ff0` | `0x7fffffff` | `0x7fffffff` | `0x11112222` | `0x11112222` | 0 |
| `M[20]` `ram_write_value` | 0 | `0x0f0f0f0f` | `0x00f00000` | `0xff00ffff` | `0x80000000` | `0x7fffffff` | `0x11112222` | `0x33334444` | 0 |
| `M[21]` `rd_mask` | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 1 | 0 |
| `M[22]` `rd_addr` | 7 | 7 | 7 | 7 | 7 | 7 | 6 | 28 | 0 |
| `M[25]` `rd_write_value` | `0xffffffff` | `0x5a5a5a5a` | `0xf0f00ff0` | `0xf0f00ff0` | `0x7fffffff` | `0x7fffffff` | `0x11112222` | **0** | 0 |
| `W[0..5]` `<q>_gap_hi` | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| `W[7]` `rd_selected` | `0xffffffff` | `0x5a5a5a5a` | `0xf0f00ff0` | `0xf0f00ff0` | `0x7fffffff` | `0x7fffffff` | `0x11112222` | 0 | 0 |
| `W[12]` `decoded_mask` | 1 | 2 | 64 | 16 | 128 | 512 | 4 | 8 | 0 |
| `W[13..24]` the kind bit set | `amoadd` | `amoswap` | `amoand` | `amoxor` | `amomin` | `amominu` | `lr` | `sc` | none |
| `W[24]` `word_index` | `0x8008` | `0x8008` | `0x8008` | `0x8008` | `0x8008` | `0x8008` | `0x8008` | `0x8008` | 0 |
| `W[26]` `sum` | 0 | `0x69696969` | `0x00e0ffff` | `0x00e0ffff` | `0xffffffff` | `0xffffffff` | `0x11112222` | `0x44446666` | 0 |
| `W[28]` `add_wrap` | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| `W[29]` `f_bitwise` | 0 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| `W[30..34]` `byte_a0..3` | `ff ff ff ff` | `5a 5a 5a 5a` | `f0 0f f0 f0` | `f0 0f f0 f0` | `ff ff ff 7f` | `ff ff ff 7f` | `22 22 11 11` | `22 22 11 11` | 0 |
| `W[34..38]` `byte_b0..3` | `01 00 00 00` | `0f 0f 0f 0f` | `0f f0 f0 0f` | `0f f0 f0 0f` | `00 00 00 80` | `00 00 00 80` | `00 00 00 00` | `44 44 33 33` | 0 |
| `W[38..42]` `byte_and0..3` | `01 00 00 00` | `0a 0a 0a 0a` | `00 00 f0 00` | `00 00 f0 00` | `00 00 00 00` | `00 00 00 00` | `00 00 00 00` | `00 00 11 11` | 0 |
| `W[42]` `old_hi` | `0xffff` | `0x5a5a` | `0xf0f0` | `0xf0f0` | `0x7fff` | `0x7fff` | `0x1111` | `0x1111` | 0 |
| `W[43]` `old_sign` | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| `W[44]` `src_hi` | 0 | `0x0f0f` | `0x0ff0` | `0x0ff0` | `0x8000` | `0x8000` | 0 | `0x3333` | 0 |
| `W[45]` `src_sign` | 0 | 0 | 0 | 0 | 1 | 1 | 0 | 0 | 0 |
| `W[46]` `lt` | 0 | 0 | 0 | 0 | **0** | **1** | 0 | 1 | 0 |
| `W[47]` `cmp_gap` | `0xfffffffe` | `0x4b4b4b4b` | `0xe0ff1fe1` | `0xe0ff1fe1` | `0xffffffff` | `0xffffffff` | `0x11112222` | `0xddddddde` | 0 |
| `W[49]` `lo` | 1 | `0x0f0f0f0f` | `0x0ff0f00f` | `0x0ff0f00f` | `0x80000000` | `0x7fffffff` | 0 | `0x11112222` | 0 |

`W[25]` `word_index_hi`, `W[27]` `sum_hi` and `W[48]` `cmp_gap_hi` are the high halfwords of the
columns above them and are omitted, as are the four multiplicity columns.

`E` and `F` are the whole of acceptance 5 in two rows: the same `old` and `src`, the same
`cmp_gap` of `0xffffffff`, and `lt` differing because `sc` is 1 on `E` and 0 on `F`, so the
signed row calls `0x80000000` the smaller and the unsigned row calls `0x7fffffff` the smaller.
`C` and `D` share every byte column and differ only in which arm of `ram_value_rule` is live:
`A = 0x00f00000` is the AND, and `xor` is `old + src − 2A = 0xff00ffff`. `A`'s sum carries, so
`add_wrap` is 1 and the stored word is 0. `G` is the one row with no `rs2` query, and its `src`
reads 0 through `rs2_value_masked`, which is why its comparison compares `old` against 0 and its
`lo` is 0. `H` is the `sc.w`: it stores `rs2` and its `rd_selected` is 0, the one kind where the
returned word is not `old`. `sum`, `cmp_gap`, `lo` and the twelve byte columns are computed on
**every** live row, bitwise or not, because `add_rule`, `old_bytes_rule`, `src_bytes_rule`,
`cmp_order` and `lo_rule` are all ungated — the same shape as §4's comparison and §6's `abs_d`.

### 9.10 What fixes each cell

The per-cell accounting is `crates/checker/tests/atomics.rs`' own, and it is a committed one:
`each_gate_is_the_one_that_refuses_its_row` carries 24 tampers, each an edit to a named honest
row beside **the exact set** of relations that refuse it, asserted equal. It ends with a
completeness assertion: of the circuit's 46 enforcing gates the frame's eleven and every
`*_boolean` are set aside, and each of the remaining **21** must be named by some tamper above.
`every_booleanity_gate_refuses_a_value_of_two` covers the fourteen booleans this family commits
— the eleven kind bits, the carry, the bitwise flag and the ordering bit — and seven further
tests take one question each.

| cell moved | on the row | refused by, exactly |
| --- | --- | --- |
| `decoded_mask` → `amoswap`'s | `amoadd` | `decoded_mask_bits` |
| the `rs1` query dropped | `amoswap at word zero`, whose `rs1` reads 0 | `rs1_mask_rule` |
| an `rs2` query added | `lr.w` | `rs2_mask_rule` |
| the `ram` query dropped | `amoswap at word zero` | `ram_mask_rule` |
| the `rd` query dropped | `amoswap at word zero` | `rd_mask_rule` |
| `rs1_addr` `+ 1` | `amoswap` | `rs1_addr_rule` |
| `rs2_addr` `+ 1` | `amoswap` | `rs2_addr_rule` |
| `rd_addr` → 5 | `amoswap` | `rd_addr_rule` |
| `ram_addr` `+ 4` | `amoswap` | `ram_addr_rule` |
| `rs1_read_value` → 4, `word_index` → 1 | padding | `rs1_value_masked` |
| `rs2_read_value` → 4, with `byte_b0`, `sum`, `cmp_gap` and `lo` moved to match | `lr.w` | `rs2_value_masked` |
| `rs1_read_value` `+ 4`, `word_index` left alone | `amoswap` | `addr_word` |
| `sum` `+ 1`, carried into the stored word | `amoadd` | `add_rule` |
| `f_bitwise` → 0 | `amoand` | `f_bitwise_rule` |
| `byte_a0` `+ 1` | `amoand` | `old_bytes_rule` |
| `byte_b0` `+ 1` | `amoand` | `src_bytes_rule` |
| `lt` → 1 with `lo` moved to match | `amoadd`, whose value rule does not read `lo` | `cmp_order` |
| `lo` → the larger, with the stored word moved to match | `amomin` | `lo_rule` |
| `ram_write_value` → the AND accumulator | `amoor` | `ram_value_rule` |
| `rd_selected` → the word it stored | `amoswap` | `rd_value_rule` |
| `pc_write_value` `+ 4` | `amoadd` | `next_pc_rule` |
| a `ram` query storing 42 into a stack word | padding | `ram_mask_rule`, `ram_addr_rule`, `ram_value_rule` |
| an `rd` query zeroing `x10` | padding | `rd_mask_rule`, `rd_addr_rule` |
| the same, dressed with `decoded_rd = 10` and a zero mask | padding | `rd_mask_rule` |

The seven further tests, each isolating one thing the accounting above cannot show cell by cell:

- **`the_comparison_is_over_the_old_word_and_rs2`** — the gadget's four parameters read back off
  the artifact, because they are **not derivable from anything else in it**: `signed` widened to
  all four min/max kinds makes `amominu` order signed; `lhs` and `rhs` swapped turns every
  `amomin` into a max; a narrowed selector drops both operands' 32-bit bounds on the other seven
  kinds (`memory-ops.md` §6.4).
- **`the_kind_bits_are_the_extra_mask_constants`** — each of the eleven `Instr` variants held to
  the bit its arm uses. A transposition of `amoor` and `amoand` would be silent: the decoded
  table is built from the same constants, so both sides would agree on the number and the machine
  proved would be one where `amoor.w` computes AND.
- **`the_min_and_max_kinds_disagree_across_the_sign_boundary`** — each of the four answers over
  `(0x7fffffff, 0x80000000)` proved, and each row claiming the other kind's answer refused. The
  refusal is always the gap's range pair: `lo` is free, so a forged answer fixes `lt` through
  `lo_rule` and `lt` fixes the gap through the one comparison equation, and swapping the ordering
  moves the gap to `2^33 − 1` or to `−1`, neither of which is a word.
- **`a_byte_key_outside_the_and_table_is_refused`** — §9.6's key bound as a row, with both halves
  of `byte_a0`'s pair firing at 65,823.
- **`a_misaligned_atomic_is_unprovable`** — the exact field witness `word_index = rs1·4⁻¹`,
  which every gate accepts and `word_index_lo_range` alone refuses, as §7.10's is for `MEM_WORD`.
- **`an_amo_whose_rd_is_not_the_old_word_is_refused`** and **`sc_w_always_succeeds`** — the
  return value, which `rd_value_rule` alone ties to memory, and the one conformance deviation
  stated as a property of the proved statement: a row claiming a nonzero success code is refused
  by `rd_value_rule`, and one leaving the word alone by `ram_value_rule`.

On a padding row `pc_mask = 0`, every frame mask is 0, every leaf is 1 and every obligation under
`pc_mask` is vacuous. **`f_bitwise` is a free boolean there**, so a padding row may look the byte
table up four times; it consumes table multiplicities, which the honest prover's recount covers,
and changes nothing, the RAM and `rd` queries being absent. With every kind bit 0 the gates hold
`ram_write_value`, `rd_selected` and `pc_write_value − decoded_next_pc` to 0, tie
`old + src − sum − 2^32·add_wrap` to 0 over a zero `old` and a zero `src`, and leave `lt` and
`cmp_gap` free together — `cmp_order` holds on every row, but `cmp_gap`'s range pair is off where
`pc_mask = 0`, so `lt = 1` with `cmp_gap = 2^32` breaks nothing there, exactly as in §4. The
honest fill writes 0 everywhere.

---

## 10. `INIT_TEARDOWN` — family 7

### 10.1 Header

`family_circuit(7, n)` is `memory::image_window_artifact(n)` with no channels. RAM window 0,
the image window: exactly one shard, window id 0. Spec: `memory.md` §3. Fill:
`prover::family_fill(7)`, the private `fill::window`, which is
`trace::build_init_teardown_columns(log, image, 0, h)`. Three committed columns, two virtual
tables, two leaves, no enforcing gate, no lookup, two outputs. At `n = 16`, S16's statement:
17 gate lists, top `L17`, 34 inner columns and relations.

### 10.2 Columns

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

### 10.3 Leaves and layers

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

### 10.4 Rows

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

## 11. `ZERO_WINDOWS` — family 8

### 11.1 Header

`family_circuit(8, n)` is `memory::zero_window_artifact(n)` with no channels. One shard per RAM
window above 0 that the execution touches, `trace::init_windows(log, h)`; shard `i` is window
`windows[i]`, and `WC` is `γ_M + 2 + α_addr·4h·windows[i]`. Spec: `memory.md` §3. Fill:
`fill::window`, `build_init_teardown_columns(log, image, w, h)`. Two committed columns, one
virtual table, two unmasked leaves, no enforcing gate, no lookup, two outputs. S16's statement
has no shard of this family.

### 11.2 Columns

| address | name | Rust | descriptive name | row `y` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the last write's timestamp to the word at `4h·w + 4y`, or 0 | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final word | the last value written, or 0 | leaf `teardown` |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |

### 11.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `α_addr·V[row] ×4 + α_ts·M[0] + α_val·M[1] + WC` | `T(RAM, 4h·w + 4·row, teardown_ts, teardown_value)` |
| 1 | 1 | `init` (write side) | `α_addr·V[row] ×4 + WC` | `T(RAM, 4h·w + 4·row, 0, 0)` |

Both are `Linear` and carry no mask: every row of a window above 0 is a RAM word, since
`4h ≥ RAM_ORIGIN` at every window height a `VmConfig` may carry. That is the menu's `2^16` and
up, and not the menu as a whole: `verifier_core::window_height` requires
`4h ≥ PUBLIC_OUTPUT_ORIGIN + PUBLIC_WINDOW_BYTES` = `0x10000`, so neither `2^8` nor S-STREAM's
`2^12` is a window height, whatever else they are heights for (§21 observation 1). The halving
lists and outputs are §10.3's, with the same names, relation numbers and addresses.

### 11.4 Rows

| row | `teardown_ts` | `teardown_value` | leaves |
| --- | --- | --- | --- |
| a word no cycle touched | 0 | 0 | both `T(RAM, 4h·w + 4y, 0, 0)`: they cancel |
| a word some cycle touched, by a read or a write (a read writes back what it read) | the last query's write timestamp | the value it wrote (0 for a word only read) | the final tuple read against the zero tuple written |

---

## 12. `KECCAK_F` — family 9

| | |
| --- | --- |
| id, constant | 9, `constants::family::KECCAK_F` |
| constructor | `constraints::keccak::artifact(n)` |
| channels | `keccak::channels()`: **`RANGE16`** and **`XOR8`**, in that order |
| fill | the private `prover::fill::keccak_f` |
| normative spec | `docs/spec/delegation.md` §6 |
| committed | 208 `M`, 1,556 `W`, 0 `S` — 1,764 |
| virtual | 4: `V[range16]`, `V[xor8_a]`, `V[xor8_b]`, `V[xor8_out]` |
| obligations | 1,230: **210** on `RANGE16`, **1,020** on `XOR8` |
| enforcing gates | 385, all on gate list 0 |
| outputs | 6 |
| at `n = 18` | depth 29 (11 row-wise + 18 halving), 5,490 inner columns, 5,875 relations, 1,900,468 wire bytes, 381,100 proof bytes (derived, §1.2) |

### 12.1 What one row is, and the height

**One row is one Keccak round**, and a whole keccak-f[1600] permutation is **24
consecutive invocations** glued by the frame being ordinary RAM — the same
decomposition `EC_ADD` makes with three (§20). `docs/spec/delegation.md` §6.0 is
the accounting of why; the short form is that S21's row was a whole permutation at
354,762 inner columns, which forced `2^8`, 256 permutations a shard and 46,406
proof bytes a permutation, and five such shards were 97% of a measured
mini-block's proof.

`DEFAULT_HEIGHTS[KECCAK_F]` is `2^18`, and **16 is the floor while 18 is a
choice above it**: `family_circuit` returns `None` below 16 variables, because
`RANGE16`'s table needs 16 variables and so does `XOR8`'s; Mercury's even
variable count is what makes 16 rather than 17 the first usable height. But
`2^16` stays legal, `family_circuit(KECCAK_F, n)` being `Some`
for `16 ≤ n ≤ 30`, and every gate and obligation below is the same at both, the
halving phase alone differing. Both tables are 65,536 rows at every height, so
at `2^18` each **tiles** four times, exactly as `V[range16]` already does at an
execution family's `2^20`: the closed forms are multilinear and agree with the
table on the whole cube, so they are the tiled table's own extension, and a
duplicate table row carries multiplicity 0 and contributes the neutral
`(0, T + g)` (`docs/spec/lookup.md` §14). `HEIGHT_MENU` still opens with `2^8`
— for `POSEIDON2`, `FR_ARITH` and `SHA256_COMP`, not for this family any more.

**What the extra menu entry buys is fewer, fatter shards.** A delegation
shard's cost is its **height and not its occupancy**, and proof bytes a shard
barely move with height — 381,100 against `2^16`'s 373,276, the sumcheck rounds
growing logarithmically where the rows grow fourfold — so four times the shard
holds four times the permutations, 10,922 against 2,730, for **34.9** proof
bytes a permutation against 137. The price is **~60 GB** a shard against
`2^16`'s ~15 GB: 46.05 GB of forward pass (5,490 inner columns at 262,144 rows
and 32 bytes), 2.23 GB of committed base and 11.27 GB of transition 0's first
bind, 59.56 GB in all. That makes this the **peak-setting delegation family of
a block**, ahead of `EC_ADD`'s 20.5 GB at `2^16` (§20.1).

**It buys the mini-block nothing**: its 1,080 permutations were one shard at
`2^16` and are one 9.9%-occupied shard now. It is aimed at the stateless full
block, where `docs/handoff/S-BATCH-miniblock-gate.md` §11's 45,000–103,000
permutations — 16,000–37,000 trie nodes at 2.786 each — fall from 17–38
keccak shards to **5–10**, and from 6.3–14.2 MB of keccak proof to 1.9–3.8 MB.

**This circuit is flat.** Every relation is an obligation or a degree-≤2 enforcing
gate over base columns; nothing above gate list 0 is anything but the two memory
product trees, the two channels' fraction trees and the halving phase. That is
why §12.7 is eleven lines and not 168.

**There is no bit in it** but the 24 round selectors and `live`. The committed unit
is a **byte**, and every Boolean operation of the round is one `XOR8` obligation;
`AND`, `ANDN` and a top-bit mask are then *linear forms* over the result
(`docs/spec/lookup.md` §14).

### 12.2 Row kinds

There is one kind and a padding row: this family is invoked, not decoded, so there
is no instruction word, no pc, no `family_extra_mask` bit and no decoded table.

| row | `live` | what the fill writes | tuples |
| --- | --- | --- | --- |
| an **invocation** | 1 | the requesting cycle, the frame base, the 51 words read and written, the round selector, the round constant's four bytes, the round's nine byte-wide stages, and two `RANGE16` chunks a frame read | 52 read tuples and 52 write tuples: the 51 frame words at `(RAM, base + 4j)`, and the anchor pair at `(DELEGATION_KECCAK_F, base)` |
| **padding** | 0 | zeros in every column | each leaf is the literal 1; each obligation's gated tuple is the all-zero one, which is a real entry of both tables |

**Not provable**: a round word at or above 24, which has no one-hot selector —
`emulator::keccak_frame` refuses it rather than answering, so no honest trace
contains one.

### 12.3 The base layer

**`M`, 208 columns.** `constraints::delegation`'s shared layout over 51 frame
words, so `docs/spec/delegation.md` §4 and §5 are normative for all of it.

| `PolyAddress` | name | Rust | what the fill writes | read by |
| --- | --- | --- | --- | --- |
| `M[0]` | `cycle` | `keccak::CYCLE` | the requesting cycle | every leaf's timestamp, every gap obligation |
| `M[1]` | `live` | `keccak::LIVE` | 1 on an invocation | every leaf's mask, every obligation's selector, `live_boolean`, `addr_w{j}`, `base_aligned`, `base_in_window`, `one_round_a_live_row`, `rho_pi_l{i}_b{j}` |
| `M[2]` | `base` | `keccak::BASE` | the frame base `a0` carried | `addr_w{j}`, `base_aligned`, `base_in_window`, the anchor's two leaves |
| `M[3]` | `anchor_value` | `keccak::ANCHOR_VALUE` | 0 | `read_anchor` |
| `M[4 + 4j + f]` | `w{j}_{addr,read_ts,read_value,write_value}` | `keccak::word(j, f)` | word `j`'s address, the timestamp of the write its read consumed, its value before the round and after it | `read_w{j}`, `write_w{j}`, `addr_w{j}`, `gap{j}_*`, and — for `j = 0` — `round_rule` and `writes_back_w0`, or — for a state word — `input_w{j}` and `output_w{j}` |

**`W`, 1,556 columns**, in layout order. Every byte column holds an integer in
`[0, 256)`, and what bounds it is the `XOR8` obligation that reads it: membership
of a three-wide tuple bounds each position individually.

| `PolyAddress` | name | Rust | what the fill writes | read by |
| --- | --- | --- | --- | --- |
| `W[2j + c]`, `j < 51`, `c < 2` | `gap{j}_c{c}` | `keccak::gap_chunk(j, c)` | chunk `c + 1` of `4·cycle − read_ts − 1` | `gap{j}_c{c}_range`, `gap{j}_top_scaled` (`c = 1`), `gap{j}_lo_range` |
| `W[102]`, `W[103]` | `base_low`, `base_low_hi` | `keccak::base_low()`, `base_low_hi()` | `(base − RAM_ORIGIN)/4` and its high halfword | `base_aligned`, `base_low_*` |
| `W[104]`, `W[105]` | `base_room`, `base_room_hi` | `keccak::base_room()`, `base_room_hi()` | `2^31 − 204 − base` and its high halfword | `base_in_window`, `base_room_*` |
| `W[106 + r]`, `r < 24` | `round_sel{r}` | `keccak::round_sel(r)` | 1 on the row's own round | `round{r}_boolean`, `round_rule`, `one_round_a_live_row`, `rc{t}_rule` |
| `W[130 + t]`, `t < 4` | `rc_b{b}`, `b` = `IOTA_BYTES[t]` | `keccak::rc(t)` | byte `b` of `ROUND_CONSTANTS[round]` | `rc{t}_rule`, `iota_out_b{b}_xor` |
| `W[134 + 8i + b]` | `state_in_l{i}_b{b}` | `keccak::state_in(i, b)` | byte `b` of input lane `i` | `input_w{j}`, `parity_x{x}_b{b}_s{s}_xor`, `theta_a_l{i}_b{b}_xor` |
| `W[334 + 4(8x + b) + s]` | `parity_x{x}_b{b}_s{s}` | `keccak::parity(x, b, s)` | `s + 2` lanes of column `x` folded; `s = 3` is `C[x]` | `parity_*_xor`, and at `s = 3` also `c_mask_*_xor` and `theta_d_*_xor` |
| `W[494 + 8x + b]` | `c_mask_x{x}_b{b}` | `keccak::c_mask(x, b)` | `C[x]`'s byte `b` XOR `0x80` | `c_mask_*_xor`, `theta_d_*_xor` |
| `W[534 + 8x + b]` | `theta_d_x{x}_b{b}` | `keccak::theta_d(x, b)` | `D[x]`'s byte `b` | `theta_d_*_xor`, `theta_a_*_xor` |
| `W[574 + 8i + b]` | `theta_a_l{i}_b{b}` | `keccak::theta_a(i, b)` | `A'[i]`'s byte `b` | `theta_a_*_xor`, `rho_mask_*_xor`, `rho_pi_l{·}_b{·}` |
| `W[774 + 8·slot + b]`, 22 lanes | `rho_mask_l{i}_b{b}` | `keccak::rho_mask(i, b)` | `A'[i]`'s byte `b` XOR `mask(s_i)` | `rho_mask_*_xor`, `rho_pi_l{·}_b{·}` |
| `W[950 + 8i + b]` | `rho_out_l{i}_b{b}` | `keccak::rho_out(i, b)` | `B[i]`'s byte `b` | `rho_pi_l{i}_b{b}`, `chi_and_*_xor`, `chi_out_*_xor` |
| `W[1150 + 8i + b]` | `chi_and_l{i}_b{b}` | `keccak::chi_and(i, b)` | `B1[i] ^ B2[i]`'s byte `b` | `chi_and_*_xor`, `chi_out_*_xor` |
| `W[1350 + 8i + b]` | `chi_out_l{i}_b{b}` | `keccak::chi_out(i, b)` | chi's output byte | `chi_out_*_xor`, `output_w{j}`, and for lane 0's four iota bytes `iota_out_b{b}_xor` |
| `W[1550 + t]`, `t < 4` | `iota_out_b{b}` | `keccak::iota_out(t)` | `chi_out[0]`'s byte `b` XOR `rc[t]` | `iota_out_b{b}_xor`, `output_w{j}` |
| `W[1554]`, `W[1555]` | `range16_multiplicity`, `xor8_multiplicity` | `keccak::range16_multiplicity()`, `xor8_multiplicity()` | `crates/trace`'s counts | `range16_table_num`, `xor8_table_num` — **and no gate** |

**`S`: none.** Both channels' tables are closed forms, so nothing here needs
binding by identity or by the SRS digest.

**The `rho_mask` block is 22 lanes and not 25**, which is the one place this
circuit's blocks are not uniform: three lanes rotate by 0, 8 and 56 — a whole
number of bytes — so their rotation is a byte permutation and needs no split.

### 12.4 Gate list 0, the leaves

2,688 producing columns, in tree order. Relation `i` defines `L1[i]`.

| relations | columns | what |
| --- | --- | --- |
| 0–51 | 52 | the read side: `read_w{j}` per frame word, then `read_anchor` |
| 52–63 | 12 | `read_pad{i}`, the literal 1, to 64 leaves |
| 64–115 | 52 | the write side: `write_w{j}`, then `write_anchor` |
| 116–127 | 12 | `write_pad{i}` |
| 128–129 | 2 | `range16_table_{num,den}` |
| 130–537 | 408 | the 51 gaps' four obligations, `(num, den)` each |
| 538–549 | 12 | `base_low`'s three and `base_room`'s three |
| 550–639 | 90 | `range16_pad_{i}`, 45 neutral fractions to 256 |
| 640–641 | 2 | `xor8_table_{num,den}` |
| 642–961 | 320 | `parity_x{x}_b{b}_s{s}_xor`, 160 obligations |
| 962–1041 | 80 | `c_mask_x{x}_b{b}_xor`, 40 |
| 1042–1121 | 80 | `theta_d_x{x}_b{b}_xor`, 40 |
| 1122–1521 | 400 | `theta_a_l{i}_b{b}_xor`, 200 |
| 1522–1873 | 352 | `rho_mask_l{i}_b{b}_xor`, 176 |
| 1874–2673 | 800 | `chi_and_l{i}_b{b}_xor` and `chi_out_l{i}_b{b}_xor`, interleaved, 400 |
| 2674–2681 | 8 | `iota_out_b{b}_xor`, 4 |
| 2682–2687 | 6 | `xor8_pad_{i}`, 3 neutral fractions to 1,024 |

The two memory leaves are §0.6's one pattern, `docs/spec/memory.md` §2.2, over the
operands below; the anchor's two are `docs/spec/delegation.md` §5.1's.

```text
pattern     live·T(space, addr, ts, value) + 1 − live
positional  1 + mem_gamma·M[1] − M[1] + space·M[1]
              + mem_alpha_addr·addr·M[1] + <ts terms> + mem_alpha_val·value·M[1]
```

| leaf | space | addr | ts | value |
| --- | --- | --- | --- | --- |
| `read_w{j}` | `RAM` = 2 | `M[4 + 4j]` | `M[5 + 4j]` | `M[6 + 4j]` |
| `write_w{j}` | `RAM` = 2 | `M[4 + 4j]` | `4·cycle + 0` | `M[7 + 4j]` |
| `read_anchor` | 4 | `M[2]` | `4·cycle + 3` | `M[3]` |
| `write_anchor` | 4 | `M[2]` | the literal 0 | absent |

A fraction leaf pair is `docs/spec/lookup.md` §6's: `(1, E_l + g)` per obligation,
`(−mult, T + g)` per table, `(0, 1)` per pad.

### 12.5 Gate list 0, the enforcing gates

385 gates, relations 2,688–3,072, in this order. Every one is `Linear` or
`Quadratic` over base columns; degree 2 where a product of `live` appears and 1
otherwise; and every one is 0 on the all-zero row, so `zero_row_valid` is true.

| relations | n | name | degree | form |
| --- | --- | --- | --- | --- |
| 2688 | 1 | `live_boolean` | 2 | `M[1] − M[1]·M[1]` |
| 2689–2739 | 51 | `addr_w{j}` | 2 | `live·(addr_j − base − 4j) = 0` |
| 2740 | 1 | `base_aligned` | 2 | `live·(base − RAM_ORIGIN − 4·base_low) = 0` |
| 2741 | 1 | `base_in_window` | 2 | `live·((2^31 − 204) − base − base_room) = 0` |
| 2742–2765 | 24 | `round{r}_boolean` | 2 | `round_sel{r} − round_sel{r}²` |
| 2766 | 1 | `round_rule` | 1 | `w0_read_value − Σ_r r·round_sel{r} = 0` |
| 2767 | 1 | `one_round_a_live_row` | 1 | `Σ_r round_sel{r} − live = 0` |
| 2768–2771 | 4 | `rc{t}_rule` | 1 | `rc[t] − Σ_r ROUND_CONSTANTS[r]'s byte `IOTA_BYTES[t]` · round_sel{r} = 0` |
| 2772 | 1 | `writes_back_w0` | 1 | `w0_write_value − w0_read_value = 0` |
| 2773–2872 | 100 | `input_w{j}`, `output_w{j}`, interleaved lane by lane | 1 | `read_value − Σ_{m<4} 2^{8m}·state_in(i, 4h+m) = 0`, and the same over the output bytes |
| 2873–3072 | 200 | `rho_pi_l{i}_b{j}` | 1 | `B[i][j] − 2^{s−1}·(A'[u] + m[u]) − 2^{s−9}·(A'[w] − m[w]) − mask(s)·(2^{s−9} − 2^{s−1})·live = 0`, or `B[i][j] − A'[u] = 0` at `s = 0` |

Four notes, each a thing that is easy to get wrong.

- **`input_w{j}` and `output_w{j}` are ungated and must not be gated.** Both sides
  are 0 on the all-zero row, and each gate is the word's byte decomposition *and*
  its 32-bit bound at once. S21's `output_w{j}` **had** to carry `live`, because
  there the output came through 168 layers from committed bits and an ungated gate
  would have asked a padding row's written word to be keccak-f of the zero state.
  Here the output bytes are committed columns that are 0 on a padding row, and the
  obligations that pin them carry `live` as their selector.
- **A state byte is therefore not free on a padding row**, which is the sharp
  consequence: setting one asks the word it recomposes to be nonzero, and
  `input_w{j}` refuses it. A reviewer reading "the row mask gates everything"
  would expect otherwise, and `crates/checker/tests/keccak.rs::
  a_padding_row_is_free_only_where_the_mask_reaches` is the test that states both
  halves.
- **`one_round_a_live_row` is load-bearing.** The codes are `0..24`, so **every**
  pair sums to another round's word — `1 + 2 = 3` — and without it a row could
  claim two rounds, satisfy `round_rule`, and XOR two round constants into lane
  `(0,0)`. This is `mod_mul::one_modulus_a_live_row`'s argument (§18.5) at its
  sharpest, the codes here being consecutive from zero.
- **The rotation's constant rides `live`**, as `sha256`'s round constants do
  (§19.2): a gate carrying a bare nonzero constant cannot hold on the all-zero row,
  and `build::zero_on_zero_row` refuses it.

### 12.6 The obligations

Selector is `live` on all 1,230.

**`RANGE16`, 210.** `docs/spec/delegation.md` §10.3's shape, built by
`delegation::{gap_lookups_range16, bound_chunked}` and identical to `MOD_MUL`'s and
`EC_ADD`'s.

| name | n | expression |
| --- | --- | --- |
| `gap{j}_c{c}_range` | 102 | `gap{j}_c{c}` |
| `gap{j}_top_scaled` | 51 | `2^{10}·gap{j}_c1` |
| `gap{j}_lo_range` | 51 | `4·cycle − w{j}_read_ts − 1 − 2^{16}·gap{j}_c0 − 2^{32}·gap{j}_c1` |
| `base_low_c0_range`, `base_low_top_scaled`, `base_low_lo_range` | 3 | `base_low_hi`; `2^3·base_low_hi`; `base_low − 2^{16}·base_low_hi` |
| `base_room_c0_range`, `base_room_top_scaled`, `base_room_lo_range` | 3 | `base_room_hi`; `2·base_room_hi`; `base_room − 2^{16}·base_room_hi` |

`lookup::check_copowers` takes the 51 top gap chunks, `base_low_hi` and
`base_room_hi`, each under `live` — 53 pairs, and `keccak::artifact` panics without
them.

**`XOR8`, 1,020.** Tuple `(e0, e1, e2)` against `(a, b, a ^ b)`. Position 0 may be
any literal-weighted linear form with a constant; positions 1 and 2 are single
columns with unit coefficients, because `β^j·c` is not one `Coeff`
(`docs/spec/lookup.md` §5) — which is exactly why `rho_out` is committed and the
derived forms sit at position 0.

| name | n | `e0` | `e1` | `e2` |
| --- | --- | --- | --- | --- |
| `parity_x{x}_b{b}_s{s}_xor` | 160 | `state_in(5·0+x, b)` at `s = 0`, else `parity(x, b, s−1)` | `state_in(5(s+1)+x, b)` | `parity(x, b, s)` |
| `c_mask_x{x}_b{b}_xor` | 40 | the literal `0x80` | `theta_c(x, b)` | `c_mask(x, b)` |
| `theta_d_x{x}_b{b}_xor` | 40 | `ROTL(C[x+1], 1)`'s byte `b`, a linear form over `theta_c` and `c_mask` of column `x+1` with a constant | `theta_c(x+4 mod 5, b)` | `theta_d(x, b)` |
| `theta_a_l{i}_b{b}_xor` | 200 | `theta_d(i mod 5, b)` | `state_in(i, b)` | `theta_a(i, b)` |
| `rho_mask_l{i}_b{b}_xor` | 176 | the literal `mask(s_i)` | `theta_a(i, b)` | `rho_mask(i, b)` |
| `chi_and_l{i}_b{b}_xor` | 200 | `rho_out(B1(i), b)` | `rho_out(B2(i), b)` | `chi_and(i, b)` |
| `chi_out_l{i}_b{b}_xor` | 200 | `(rho_out(B2(i), b) − rho_out(B1(i), b) + chi_and(i, b))/2` | `rho_out(i, b)` | `chi_out(i, b)` |
| `iota_out_b{b}_xor` | 4 | `rc[t]` | `chi_out(0, b)` | `iota_out(t)` |

with `B1(i) = 5y + (x+1 mod 5)` and `B2(i) = 5y + (x+2 mod 5)` for `i = 5y + x`.

**The channel table.**

| channel | output positions | table columns | multiplicity |
| --- | --- | --- | --- |
| `RANGE16` = 1 | 2, 3 | `V[range16]` | `W[1554]` |
| `XOR8` = 4 | 4, 5 | `V[xor8_a]`, `V[xor8_b]`, `V[xor8_out]` | `W[1555]` |

**1,020 is three short of a cliff.** A fraction tree has
`(lookups + 1).next_power_of_two()` leaves, so 1,020 obligations give 1,024 and
1,024 would give 2,048 — 4,096 more inner columns, which at `2^18` is 34.4 GB
more a shard. That is why `ι` is four obligations and not eight, and
`keccak::check_shape` asserts both the count and the cliff.

### 12.7 The inner layers

Eleven row-wise lists — the `XOR8` tree's depth is 10, and it is the deepest —
then 18 halving lists. Each row-wise list reduces every tree pairwise; a tree
already at one node copies itself up so all four reach the halving phase together.

| layer | read tree | write tree | `range16` | `xor8` | width |
| --- | --- | --- | --- | --- | --- |
| `L1` | 64 | 64 | 512 | 2,048 | 2,688 |
| `L2` | 32 | 32 | 256 | 1,024 | 1,344 |
| `L3` | 16 | 16 | 128 | 512 | 672 |
| `L4` | 8 | 8 | 64 | 256 | 336 |
| `L5` | 4 | 4 | 32 | 128 | 168 |
| `L6` | 2 | 2 | 16 | 64 | 84 |
| `L7` | 1 | 1 | 8 | 32 | 42 |
| `L8` | 1 | 1 | 4 | 16 | 22 |
| `L9` | 1 | 1 | 2 | 8 | 12 |
| `L10` | 1 | 1 | 2 | 4 | 8 |
| `L11` | 1 | 1 | 2 | 2 | 6 |
| `L12`–`L29` | 1 | 1 | 2 | 2 | 6 each |

A product tree's node is `TreeProduct` at the halving lists and `Product` below
them; a fraction tree's is `TreeCross` over the pair plus `TreeProduct` of the
denominator, and `Quadratic` plus `Product` below (§0.6). Relations 3,073–5,874
are these lists in order.

`5,490 = 2,688 + 1,344 + 672 + 336 + 168 + 84 + 42 + 22 + 12 + 8 + 6 + 18·6`, and
the inner and relation totals at any admissible `n` are `5,382 + 6n` and
`5,767 + 6n`.

### 12.8 The outputs

| output | `PolyAddress` | name | read by |
| --- | --- | --- | --- |
| 0 | `L{29}[0]` | `read_root` | `verify_shard` step 10a, and step 10b's cross-shard product |
| 1 | `L{29}[1]` | `write_root` | ditto |
| 2, 3 | `L{29}[2..4]` | `range16_num_root`, `range16_den_root` | step 9: `num = 0` **and** `den ≠ 0` |
| 4, 5 | `L{29}[4..6]` | `xor8_num_root`, `xor8_den_root` | ditto |

### 12.9 Witness rows

`crates/checker/tests/keccak.rs` builds **one whole permutation** — 24 rows, round
0 through 23, each reading the state the one before it wrote and all at one frame
base — plus two corner rows and six padding rows, and evaluates every row through
`checker::violated_relations` and every `XOR8` obligation through its own reading
of the table. It runs in ordinary CI, and it is the source for this section rather
than a probe.

The two corners are the states whose byte masks are degenerate: the **all-zero**
state, where every intermediate is 0 until iota puts the round constant into lane
`(0,0)` — so a padding row and a live row differ in the one place that matters —
and the **all-ones** state, where every mask obligation sees `0xff` and every
rotation carries every bit across a byte boundary.

A row table is not reproduced here: a row is 1,764 cells. What stands in for one is
the chain, and each link runs in the fast gate:

1. `the_round_is_the_executors` holds this suite's own `u64` round, written from
   `docs/spec/delegation.md` §6.2, equal to `emulator::keccak_round` on 24 random
   states.
2. `crates/emulator/tests/keccak.rs::twenty_four_rounds_are_the_permutation` holds
   24 of those rounds equal to `tiny_keccak::keccakf`, and
   `a_round_depends_on_its_index` holds the 24 rounds pairwise distinct on one
   state.
3. `an_honest_witness_satisfies_every_gate_and_obligation` evaluates the circuit
   over a witness built from step 1's round and nothing the prover or the executor
   owns.
4. `the_twenty_four_rows_chain_through_the_frame` states the glue: round `r`'s
   written word is round `r + 1`'s read word, at one base.
5. `crates/prover/tests/fills.rs::the_keccak_fill_covers_its_circuit_exactly` holds
   the fill to writing every column the circuit declares, exactly once.

### 12.10 What fixes each cell

| cell | what fixes it |
| --- | --- |
| `cycle`, `base` | the multiset: the frame writes ride `4·cycle`, and the anchor's teardown read is at `4·cycle + 3` against the request's mirror write |
| `live` | `live_boolean`, and the multiset — a row switched off contributes the identity to both trees and the neutral tuple to both channels |
| `anchor_value` | nothing locally, by design: the request's mirror write is the other side and the two cancel only if equal (`docs/spec/delegation.md` §5.2) |
| `w{j}_addr` | `addr_w{j}`, against `base` |
| `w{j}_read_ts` | the four `gap{j}` obligations, and the multiset |
| `w0_read_value` | `round_rule`, so it is one of `0..24` |
| `w0_write_value` | `writes_back_w0` |
| a state word's `read_value` | `input_w{j}`, against its four bytes |
| a state word's `write_value` | `output_w{j}`, against the round's four output bytes |
| `gap{j}_c{c}` | its own `RANGE16` obligation and the derived `gap{j}_lo_range` — **no gate** |
| `base_low`, `base_room` | `base_aligned` / `base_in_window`, and their own obligations |
| `round_sel{r}` | `round{r}_boolean`, `round_rule`, `one_round_a_live_row` |
| `rc[t]` | `rc{t}_rule` |
| `state_in` | `input_w{j}`, and the obligations that read it — which also bound it to a byte |
| `parity`, `c_mask`, `theta_d`, `chi_and` | the `XOR8` channel **alone**: no gate reads any of them |
| `theta_a`, `rho_mask` | their own obligation **and** one of the 200 `rho_pi_l{i}_b{j}` gates |
| `rho_out` | `rho_pi_l{i}_b{j}`, and the two chi obligations that read it |
| `chi_out` | `chi_out_*_xor`, and `output_w{j}` — or, for lane 0's four iota bytes, `iota_out_b{b}_xor` |
| `iota_out` | `iota_out_b{b}_xor` and `output_w{j}` |
| the two multiplicities | their channel's root check, and nothing else — no gate reads them |

`crates/checker/tests/keccak.rs`' negative controls are that table read the other
way: fifteen cells corrupted one at a time, each refused by the relation or the
obligation named beside it, with the two that are refused by **neither a gate nor
the channel alone** separated into their own test because which of the two catches
a stage is a property of the circuit's shape.

---

## 13. `POSEIDON2` — family 10

### 13.1 Header

`family_circuit(10, n)` is `poseidon2::artifact(n)` with `poseidon2::channels()`, which is
**empty**. Like `keccak` it is not built by `build::assemble` — its work needs inner layers of
its own — but unlike `keccak` it does not carry a private builder either: the frame, the anchor,
the bounds and the layered `Assembly` are `constraints::delegation`'s, shared with `FR_ARITH`.
Normative spec: `delegation.md` §4, §5 and §12. Fill: `prover::family_fill(10)`, the private
`fill::poseidon2`.

**4,192 committed columns (100 `M`, 4,092 `W`, no `S`) and no virtual table.** Gate list 0
writes 74 columns — 64 memory leaves, the 4 carried to the top, and round 0's first sub-layer —
and holds 4,245 enforcing gates. **No lookup**, 2 outputs. At `n = 8`, the family's one height,
there are 201 gate lists, the top is `L201`, and the circuit has 2,020 inner columns and 6,268
relations. `artifact` panics unless every layer's width is its three parts' (§13.7), the column
counts are `MEMORY_COLUMNS` and `WITNESS_COLUMNS`, there is no setup column, no obligation and
no virtual table, the depth is `192 + 1 + n`, the relations `base_aligned` and `base_in_window`
exist **by name**, `addr_w` and `gap_w` number 24 each, `out_lane` 3, and the last round list
carries the three output comparisons and nothing else. It also panics on every refusal of
`validate` and of `memory::check_memory`.

**The height is `2^8`**, for the reason S21 gave `KECCAK_F` and which still holds here: one
row's forward pass is about 200 kB of `Fr`, so `2^8` rows are 51 MB and `2^16` would be 13 GB. A
delegation family's rows are invocations, so the height answers "how many permutations may a
shard hold".

**Why there is no lookup channel**: at `2^8` no table fits
(`docs/spec/delegation.md` §9). Every bound here is a bit decomposition with a booleanity gate,
and 4,093 of the 4,245 gates in list 0 are those booleanity gates. **`KECCAK_F` took the other
road at S26d** — a byte-oriented state over a byte XOR table, which fits `2^16` — and this
family did not follow it: a Poseidon2 round is field arithmetic, not a Boolean network, so there
is no byte table for it to look into.

### 13.2 Row kinds

Two, and neither is an instruction: this family is invoked, not decoded.

| row kind | `live` | what the row holds | what it adds to the multiset |
| --- | --- | --- | --- |
| an **invocation** | 1 | the requesting cycle, the frame base, the 24 words read and written, six values' 520 bits apiece, 24 × 38 gap bits and the frame pointer's 60 | 25 read tuples and 25 write tuples: the 24 frame words at `(RAM, base + 4j)`, and the anchor pair at `(DELEGATION_POSEIDON2, base)` |
| **padding** | 0 | every committed cell 0 | nothing: all 64 leaves are 1 |

A padding row still *computes* the permutation — of the all-zero state, whose output is not zero
— and the three `out_lane` gates are gated on `live` for exactly that reason. That gating is
what forces `live` and the three recomposed written lanes to be carried through all 192 round
layers: only gate list 0 can read a committed column, and the comparison happens at the top.

### 13.3 The base layer

| address | name | what it is |
| --- | --- | --- |
| `M[0]` | `cycle` | the requesting cycle |
| `M[1]` | `live` | the row's one mask; the frame and the anchor are one invocation |
| `M[2]` | `base` | the frame base pointer |
| `M[3]` | `anchor_value` | the teardown read's value, free on both sides |
| `M[4 + 4j + f]` | `w{j}_{addr,read_ts,read_value,write_value}` | frame word `j`, `j < 24` |
| `W[38j + i]` | `gap{j}_{i}` | bit `i` of word `j`'s timestamp gap |
| `W[912 + i]` | `base_low{i}` | bit `i` of `(base − RAM_ORIGIN) / 4`, 29 bits |
| `W[941 + i]` | `base_room{i}` | bit `i` of `2^31 − 96 − base`, 31 bits |

**The frame's witness columns start at `W[0]` here and at `W[1600]` in `KECCAK_F`.** S21's
circuit put the input state's bits first and the frame's above them (§12.3); S23's two put the
frame's first, because `constraints::delegation` owns them and cannot know what a family will
add. The `M` side is identical in both, so nothing about a frame's *memory* layout depends on
the family. `prover::fill::delegation_frame` therefore takes the witness base as an argument,
and `crates/prover/tests/fills.rs` holds each family's fill to covering `0..WITNESS_COLUMNS`
exactly once — a family added here that copies either layout must say which it copied.
| `W[972 + 520v + ..]` | `in{v}_*` / `out{v−3}_*` | value `v`'s 256 word bits, then 256 difference bits and 8 borrow bits |

Values `0..3` are the lanes read, `3..6` the lanes written. §13.4's canonicity gates are what
make each one a canonical `Fr`.

### 13.4 Gate list 0: the 4,245 enforcing gates

| count | gate | formula | what it fixes |
| --- | --- | --- | --- |
| 1 | `live_boolean` | `live − live²` | the one mask |
| 4,092 | `…_boolean` | `x − x²` | every gap, base and value bit |
| 24 | `addr_w{j}` | `live·(addr_j − base − 4j)` | the frame is at fixed offsets |
| 24 | `gap_w{j}` | `live·(4·cycle − 1 − read_ts_j − Σ 2^i·gap{j}_{i})` | the read precedes the write |
| 1 | `base_aligned` | `live·(base − RAM_ORIGIN − 4·Σ 2^i·base_low{i})` | word-aligned, at or above `RAM_ORIGIN` |
| 1 | `base_in_window` | `live·(2^31 − 96 − base − Σ 2^i·base_room{i})` | the frame is inside the window |
| 48 | `in{v}_word{k}` / `out{v}_word{k}` | `word − Σ 2^t·bit` | each word below `2^32`, and its decode |
| 48 | `in{v}_canonical{i}` / `out{v}_canonical{i}` | `live·(w_i − p_i) − b_{i−1} + 2^32·b_i − Σ 2^t·diff` | the borrow chain of `X − p` |
| 6 | `in{v}_below_modulus` / `out{v}_below_modulus` | `live − b_7` | the subtraction borrowed out, so `X < p` |

The canonicity argument is `delegation.md` §13.3's, and it is the same eight-limb chain here as
there: every term is a small integer, so the `Fr` equation is the integer equation, and the
eight telescope to `X − p + 2^256·b_7 = D` with `D < 2^256`.

### 13.5 The rounds

Sixty-four blocks of three gate lists, `delegation.md` §12.3's table. Round `r`'s sub-layer
`sub` is written by gate list `3r + sub` and lands in layer `3r + sub + 1`.

| sub | a full round writes | a partial round writes |
| --- | --- | --- |
| 0 | `q_0..q_2` then `t_0..t_2` | `q_0`, `t_0`, and lanes 1 and 2 carried |
| 1 | `q2_0..q2_2` then `t_0..t_2` | `q2_0`, `t_0`, and the two carried |
| 2 | `M_ext · v`, three lanes | `internal_matrix` over `(v_0, s_1, s_2)`, three lanes |

with `v_i = q2_i · t_i`. **Every `q` before every `t`**, because sub-layer 1 addresses the layer
below by region; interleaving them is the one addressing mistake this shape admits, and it is
the bug the differential caught.

`rc(r, i)` is `POSEIDON2_RC3_INITIAL[r][i]` for `r < 4`, `POSEIDON2_RC3_INTERNAL[r − 4]` on lane
0 for `4 ≤ r < 60` and zero on the other two, and `POSEIDON2_RC3_TERMINAL[r − 60][i]` above. The
initial `external_matrix` folds into round 0's first square, which is why `initial_lane(i)`
carries coefficient 2 on lane `i`'s eight words and 1 on the other sixteen.

### 13.6 The output comparison

Gate list 192 reads layer 192 — the final state, `live` and the three carried lanes — and holds
three enforcing gates and no producing ones but the tree's:

```text
out_lane{j}   live·final_j − live·out_j = 0
```

where `out_j` is `Σ_k 2^{32k}·write_value(8j + k)`, carried from gate list 0.

### 13.7 The layer geometry

Every layer is exactly `tree_width + carry_width + perm_width` columns wide, and `check_shape`
asserts it on the emitted artifact for every row-wise list:

| region | `L1` | `L2..L6` | `L7..L192` | `L193` | `L194..L201` |
| --- | --- | --- | --- | --- | --- |
| tree | 64 | 32, 16, 8, 4, 2 | 2 | 2 | 2, halving |
| carry | 4 | 4 | 4 | — | — |
| permutation | 6 | per §13.5 | per §13.5 | — | — |

The memory tree is 25 leaves a side padded to 32, so 64 columns at `L1` and five row-wise
halvings; from `L7` on the two roots are copied up to meet the permutation. Total inner columns
at `n = 8`: 2,020, of which 736 are the permutation, 768 the carry and the rest the tree.

### 13.8 The halving layers and the outputs

Eight halving lists, `L194` to `L201`, each two `TreeProduct`s. `outputs` is
`[L201[0], L201[1]]` — `READ_ROOT` then `WRITE_ROOT` — and nothing else: no channel, no
fraction tree.

### 13.9 What fixes each cell

| cell | what fixes it |
| --- | --- |
| `cycle`, `base` | the request's mirror query, through the anchor (`delegation.md` §5.3) |
| `live` | `live_boolean`, and the leaves' shape |
| `anchor_value` | nothing locally: it is the request's write-back, and the multiset pairs them |
| a frame word's `addr` | `addr_w{j}` |
| a frame word's `read_ts` | the multiset, bounded by `gap_w{j}` |
| a read lane | `in{v}_word{k}` and its canonicity chain; the permutation reads it |
| a written lane | the same, **and** `out_lane{j}` — the permutation says what it must be |
| a gap bit | its booleanity and `gap_w{j}` |
| a base bit | its booleanity and `base_aligned` / `base_in_window` |

---

## 14. `FR_ARITH` — family 11

### 14.1 Header

`family_circuit(11, n)` is `fr_arith::artifact(n)` with `fr_arith::channels()`, which is
**empty**. It is the one delegation circuit that *is* built by `build::assemble`, through
`memory::assemble`: every constraint it makes fits as an enforcing gate on gate list 0, so above
the leaves it is two product trees and nothing else. Normative spec: `delegation.md` §4, §5 and
§13. Fill: `prover::family_fill(11)`, the private `fill::fr_arith`.

**2,680 committed columns (104 `M`, 2,576 `W`, no `S`) and no virtual table.** Gate list 0
writes 64 columns — the two sides' 32 leaves — and holds 2,701 enforcing gates. **No lookup**, 2
outputs. At `n = 8` there are 14 gate lists, the top is `L14`, and the circuit has 142 inner
columns and 2,843 relations. `artifact` panics unless the column counts are `MEMORY_COLUMNS` and
`WITNESS_COLUMNS`, there is no setup column, no obligation and no virtual table, the nine named
relations of §14.4 exist **by name**, `addr_w` and `gap_w` number 25 each, `writes_back_w` 17,
and each value's `_word` and `_canonical` gates number 8. No relation's name may contain
`assume`. It also panics on every refusal of `validate` and of `memory::check_memory`.

**The height is `2^8`**, and a shard is 23 MB of forward pass. One row is one operation, so a
shard holds 256 of them; a guest doing more gets more shards, which is what shards are for.

### 14.2 Row kinds

Two. **One row is one operation** — `ops/row = 1`, which is the cost model the recursion guest's
contraction is sized against — and there is no no-op row kind: a row is live or it is padding.

| row kind | `live` | what the row holds | what it adds to the multiset |
| --- | --- | --- | --- |
| an **operation** | 1 | the requesting cycle, the frame base, the 25 words read and written, three values' 520 bits apiece, 25 × 38 gap bits, the frame pointer's 60, three selectors and three scalars | 26 read tuples and 26 write tuples: the 25 frame words at `(RAM, base + 4j)`, and the anchor pair at `(DELEGATION_FR_ARITH, base)` |
| **padding** | 0 | every committed cell 0 | nothing: all 64 leaves are 1 |

Every gate holds on the all-zero row: `one_op_a_live_row` reads `0 = 0` there, `prod_rule` reads
`0 = 0·0`, and `out_rule` reads `0 = 0`.

### 14.3 The base layer

| address | name | what it is |
| --- | --- | --- |
| `M[0..4]` | `cycle`, `live`, `base`, `anchor_value` | as §13.3 |
| `M[4 + 4j + f]` | `w{j}_*` | frame word `j`, `j < 25` |
| `W[38j + i]` | `gap{j}_{i}` | bit `i` of word `j`'s timestamp gap |
| `W[950 + i]` | `base_low{i}`, then `base_room{i}` | 29 then 31 bits |
| `W[1010 + 520v + ..]` | `a_*`, `b_*`, `out_*` | value `v`'s 256 word bits, 256 difference bits and 8 borrow bits |
| `W[2570..2573]` | `selector1`, `selector2`, `selector3` | one per operation code, in `OPS` order |
| `W[2573]` | `prod` | `a·b`, the one committed helper |
| `W[2574]` | `inv` | the witnessed inverse of `a`, 0 where `a` is 0 |
| `W[2575]` | `is_zero` | 1 exactly on an inverse row whose operand is 0 |

`is_zero` carries no booleanity gate of its own: the gadget's two gates force it
(`constraints/src/gadgets.rs`).

### 14.4 Gate list 0: the 2,701 enforcing gates

| count | gate | formula | what it fixes |
| --- | --- | --- | --- |
| 1 | `live_boolean` | `live − live²` | the one mask |
| 2,573 | `…_boolean` | `x − x²` | every gap, base, value and selector bit |
| 25 | `addr_w{j}` | `live·(addr_j − base − 4j)` | the frame is at fixed offsets |
| 25 | `gap_w{j}` | `live·(4·cycle − 1 − read_ts_j − Σ 2^i·gap{j}_{i})` | the read precedes the write |
| 1 | `base_aligned`, 1 `base_in_window` | as §13.4 | the frame pointer |
| 17 | `writes_back_w{j}` | `write_value_j − read_value_j` | the opcode word and both operands survive the call |
| 24 | `a_word{k}`, `b_word{k}`, `out_word{k}` | `word − Σ 2^t·bit` | each word below `2^32` |
| 24 | `<v>_canonical{i}` | the borrow chain of `X − p` | the value is an `Fr` |
| 3 | `<v>_below_modulus` | `live − b_7` | and a canonical one |
| 1 | `opcode_rule` | `opcode − f_add − 2·f_mul − 3·f_inv` | the opcode word is the selectors |
| 1 | `one_op_a_live_row` | `f_add + f_mul + f_inv − live` | exactly one operation a live row |
| 1 | `prod_rule` | `prod − a·b`, ungated | the product helper |
| 1 | `inv_is_an_inverse` | `a·inv + z − f_inv` | the is-zero gadget, enabled by the inverse selector |
| 1 | `is_zero_at_nonzero` | `a·z` | `z = 0` wherever `a` is not |
| 1 | `inverse_of_zero_is_zero` | `z·inv` | and `inv = 0` where it is |
| 1 | `out_rule` | `out − f_add·(a + b) − R^-1·f_mul·prod − R^2·f_inv·inv` | the operation |

`a`, `b` and `out` are linear forms over eight `M` columns apiece, so `prod_rule` is one
`Quadratic` with 64 products and `out_rule` one with 18. Both are degree 2: every product is two
committed columns.

The three gates the prompt's constraint set leaves incomplete are in the table and worth naming
again. Without `is_zero_at_nonzero` a prover sets `z = 1` at `a ≠ 0` and proves `inv(a) = 0`;
without `inverse_of_zero_is_zero` the witnessed inverse is free at `a = 0` and "inverse(0) = 0"
is prose; and without `one_op_a_live_row` a prover on an inverse row sets `f_add` and `f_mul`
instead, because the codes 1, 2 and 3 make `add + mul` spell `inv`.

### 14.5 The trees and the outputs

The memory subtree is 26 leaves a side padded to 32: 64 columns at `L1`, five row-wise halvings
to two at `L6`, then eight halving lists to `L14`. `outputs` is `[L14[0], L14[1]]`. There is
nothing else above gate list 0 — this circuit's whole statement is enforcing.

### 14.6 What fixes each cell

| cell | what fixes it |
| --- | --- |
| `cycle`, `base`, `live`, `anchor_value` | as §13.9 |
| the opcode word | `opcode_rule` and `one_op_a_live_row`, which together make it 1, 2 or 3 on a live row |
| `a`, `b` | their word gates and canonicity chains; the multiset says they are what the guest wrote |
| `out` | its word gates, its canonicity chain, and `out_rule` |
| `prod` | `prod_rule` |
| `inv`, `is_zero` | the three gadget gates |
| a selector | its booleanity, `opcode_rule` and `one_op_a_live_row` |

---

## 15. `PUBLIC_INPUT` — family 12

### 15.1 Header

`family_circuit(12, n)` is `memory::value_window_artifact(n)` with no channels. RAM window
`family::PUBLIC_INPUT_WINDOW` = 2, the statement's public input: exactly one shard in every
statement, whether or not the execution read a word of it. Spec: `public-values.md` §4 and §5;
`memory.md` §3 is the window machinery it inherits. Fill: `prover::family_fill(12)`, the private
`fill::public_input`, which is `trace::build_value_window_columns(log,
program::public_io_words(input), 2, h)`. **Three** committed columns, one virtual table, two
unmasked leaves, no enforcing gate, no lookup, no channel, two outputs. At `n = 12`, its one
height: 13 gate lists, top `L13`, 26 inner columns and relations.

**Its height is pinned at `2^12` since S-STREAM, and nothing derives another.** A window's first
address is `4h·w`, so the height is what places the window, and both public windows have to sit
inside the 64 KiB hole `[0, guest_memory::RAM_ORIGIN)` that no RAM window family initializes —
`INIT_TEARDOWN` masks RAM window 0's rows below `2^14` with `V[ram_live]` and `ZERO_WINDOWS`
never claims window 0 (`memory.md` §3.3). At `family::PUBLIC_WINDOW_HEIGHT` = `2^12` a window is
`4·2^12` = 16,384 bytes and the pair is windows 2 and 3: `4·2^12·2 = 0x8000` is
`guest_memory::PUBLIC_INPUT_ORIGIN` and `4·2^12·3 = 0xC000` is `PUBLIC_OUTPUT_ORIGIN`, the two
together ending flush against `RAM_ORIGIN` = `0x10000`. **That is a ceiling and not a
preference**: a `2^14` window is 64 KiB, the hole holds exactly one of them, and that one is
window 0 — which initializes address 0, where a null dereference would then balance. `[0,
0x8000)` stays unclaimed for exactly that reason, and windows 0 and 1 belong to nobody.
**It was `2^8` until S-STREAM**, where the pair was windows 32 and 33 at `0x8000` and `0x8400`
and a window carried 1,020 payload bytes against `4·2^12 − 4` = 16,380 now
(`public-values.md` §3, §9). `program::decode_program` writes the constant and ignores what a
caller asked for, and `verifier_core::window_height` refuses any other inside
`VmConfig::from_bytes` (`public-values.md` §2). The registry itself is looser —
`family_circuit(12, n)` is `Some` for `0 ≤ n ≤ 30`, the family carrying no channel and so
meeting no `BITS ≤ trace_vars` guard — and that looseness is never reachable through a key
(§21 observation 1).

**The height moved and not one relation did.** `trace_vars` reaches nothing inside
`memory::value_window_artifact` but its call to `memory::assemble`: both leaves come out of the
private `window_tuple` without it, and the family has no channel, so `lookup::channel_trees` is
handed an empty list and returns none. Inside `build::assemble` the depth is `1 + R + n` with
`R` still 0, so four more variables appended **four halving lists, each carrying one node per
output, and nothing else** — gate list 0, both leaves, the lookups, the outputs, the padding
contract and `zero_row_valid` are what they were at `2^8`, and so is every relation number below
the halving phase. That is the conclusion
`crates/checker/tests/{mod_mul,ec_add}.rs`' `a_height_moves_only_the_halving_layers` states for
the two delegation families that changed height before this one, read off the two window
constructors instead. What *did* move is every number that counts a layer, a row or a byte: 9
gate lists to 13, top `L9` to `L13`, 18 inner columns and relations to 26, the roots from
relations 16 and 17 to 24 and 25, the shard from 256 rows to 4,096, and the artifact from 2,027
bytes to 2,455.

### 15.2 Columns

| address | name | Rust | descriptive name | row `y` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the timestamp of the last write to the word at `0x8000 + 4y`; 0 if the word is untouched | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final word | the last value written; `init_value` if untouched | leaf `teardown` |
| `M[2]` | `init_value` | `PolyAddress::Memory(2)` | Input word | `public_io_words(public.input)[y]`: word 0 the payload's byte length, then the payload little-endian, 0 to the end of the window | leaf `init`; **`verify_shard_local` step 10c** |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |

All three are committed in `PublicInputs::memory_commitments`, in the global commit phase at G8
— **before** the memory challenges are squeezed, which is what `check_memory` requires of any
column a leaf weights by a global slot (`memory.md` §8). There is no `W` column and no `S`
column: `program::setup_commitments(12)` is empty, deliberately, because an `S` column is bound
by program identity and one execution's public input has no business in every execution's
identity (`public-values.md` §4). `M[2]` is `INIT_TEARDOWN`'s `S[0]` moved into the `M` group,
and that move is the whole difference between the two artifacts.

### 15.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `α_addr·V[row] ×4 + α_ts·M[0] + α_val·M[1] + WC` | `T(RAM, 0x8000 + 4·row, teardown_ts, teardown_value)` |
| 1 | 1 | `init` (write side) | `α_addr·V[row] ×4 + α_val·M[2] + WC` | `T(RAM, 0x8000 + 4·row, 0, init_value)` |

Here `WC = γ_M + 2 + α_addr·0x8000`, the window constant at `h = 2^12`, `w = 2`; the `2` added
to `γ_M` is `address_space::RAM`, the tag a public window shares with ordinary RAM and with the
advice region — which is what makes these families cost `MEM_WORD`, `MEM_SUBWORD` and `ATOMICS`
nothing: a load's memory leaf names its space with a literal, so a region with a tag of its own
would put a space *column* on all three load paths (`public-values.md` §2). Since S-STREAM the
window id is `2` as well, and that is a coincidence and nothing more: one `2` is a tag from
`constants::address_space`, the other is `0x8000 / 4h`. Both leaves are
`Linear` and carry no mask: every row of the window is a RAM word, and `V[ram_live]` is not
here and could not be. Its table is 1 only at `row ≥ 2^RAM_LIVE_BIT` and
`constants::memory::RAM_LIVE_BIT` is **14**, so over a `2^12`-row window it is 0 on every row;
its extension `1 − Π_{j ≥ 14}(1 − y_j)` reads the variables from 14 up, of which a 12-variable
point has none, so the product is empty and the extension is identically 0 — the mask would
switch the whole window off. **S-STREAM's raise does not reach that bound**: 12 is still at or
below 14, so both public artifacts stay mask-free exactly as they were at `2^8`, and
`gkr_verify::virtual_at_row` and `virtual_at_point` are where both halves of that are read.
Code: the private
`memory::window_tuple`, twice — `window_tuple(Some(M[0]), M[1])` and `window_tuple(None, M[2])`
— with no `memory::leaf` wrapper, there being nothing to mask. Degree 1 throughout: the circuit
has no `Quadratic` and no `Product` gate at all, its only other shape being the halving lists'
`TreeProduct`.

Halving list `k`, for `1 ≤ k ≤ n`, writes `L{k+1}` (`n − k` variables), exactly as §10.3:

| `L{k+1}` | relation | node | shape |
| --- | --- | --- | --- |
| 0 | `2k` | `read_{k+1}_0` | `TreeProduct { L{k}[0] }` |
| 1 | `2k + 1` | `write_{k+1}_0` | `TreeProduct { L{k}[1] }` |

In the last list, `k = n`, the two nodes are `read_root` and `write_root`.

| output | address, `n = 12` | node | value | verifier |
| --- | --- | --- | --- | --- |
| 0 | `L{13}[0]` | `read_root` | the product of every row's teardown leaf | step 10a: must equal `PublicInputs::memory_roots[p][0]`, `p` being the position of `(12, 0)` in `verifier_core::statement_shards` — after `INIT_TEARDOWN`'s shard, every `ZERO_WINDOWS` shard and every execution and delegation shard, the group order being `INIT_TEARDOWN`, `ZERO_WINDOWS`, then every other family ascending; a factor of `reconciles` |
| 1 | `L{13}[1]` | `write_root` | the product of every row's init leaf | step 10a: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |

**Step 10c is what makes the family mean anything**, and it reads a base claim, not an output.
A shard's base claims arrive in layout order `M`, `W`, `S`; this family has neither a `W` nor an
`S` column, so `claims[2]` is `M[2] init_value` at the shard's own opening point. The verifier
evaluates its own multilinear extension of `public_io_words(public.input)` there and compares,
returning `MemoryArgument("the public input window is not the statement's input")` on a
mismatch — after step 10a and before the opening (`reduce.rs`, `verify_shard_local`). What that
comparison is worth rests on the multiset and not on itself: the multiset already forces a
window's init column to be each address's **first** value (`memory.md` §4.2), so holding `M[2]`
to the statement says the guest's first read of every input word read the statement's input.
`claims[1]`, `M[1] teardown_value`, is held to **nothing**: a guest may overwrite its own input
buffer.

**This is where the raise is paid, and it is the only place.** The verifier's own extension is
`MultilinearPoly::new(PolyBacking::U32(public_io_words(bytes))).evaluate(&point)`, a fold that
costs `2^n − 1` multiplications over a `2^{n−1}`-element scratch: 4,095 and 2,048 `Fr` at
`2^12` where `2^8` cost 255 and 128, so a statement's two step-10c evaluations are **8,190 `Fr`
multiplications against 510**, over 81,920 live bytes a shard — the fold buffer and the
4,096-word `u32` vector `public_io_words` lays out — and 163,840 across the two
(`public-values.md` §8). Nothing else in the verifier's cost moves: step 10a still compares two
roots and step 11 still opens three columns at one point.

### 15.4 Rows

A window shard has no padding: every row is an address, and all 4,096 of them are live — word 0
the payload's byte length and 4,095 payload words, which is
`guest_memory::PUBLIC_PAYLOAD_BYTES` = 16,380 bytes and was 1,020 at `2^8`.
`zero_row_valid` is `true` and the padding contract is `M[0] = 0, M[1] = 0, M[2] = 0`; here that
all-zero row is an ordinary row and a common one — a word past the payload that no cycle
touched — whose two leaves are equal and cancel.

| row | `teardown_ts` | `teardown_value` | `init_value` | leaves |
| --- | --- | --- | --- | --- |
| word 0 | 0, or the last write's timestamp if the guest overwrote it | the payload's byte length, or what overwrote it | the payload's byte length | the length word is a committed cell like any other, and it is what makes the binding exact (`public-values.md` §3) |
| a payload word the guest only read | 0 | the input word `v` | `v` | both `T(RAM, 0x8000 + 4y, 0, v)`: they cancel |
| a payload word the guest overwrote | the last query's write timestamp `t` | the value it wrote, `v'` | the input word `v` | `T(RAM, 0x8000 + 4y, t, v')` read against `T(RAM, 0x8000 + 4y, 0, v)` written |
| a word past the payload | 0 | 0 | 0 | both `T(RAM, 0x8000 + 4y, 0, 0)`: they cancel |

Nothing in this circuit checks a row alone — there is no enforcing gate to check one with.
`M[0]` and `M[1]` are fixed by the memory argument; `M[2]` is fixed by step 10c, on every row at
once, through one multilinear evaluation.

**What holds this in CI**: `crates/checker/tests/public_values.rs`'
`the_input_window_column_is_the_verifiers_own_layout`, which builds `M[2]` from a real log with
`build_value_window_columns` and compares it row by row with `public_io_words`, and
`the_three_families_are_two_leaves_and_a_product_tree`, which refuses a channel, a lookup, a
setup column, a witness column or a third output. The proof half —
`MemoryArgument` for a claimed input that is not the committed column, and the control that the
journal's shard does not care about it — is `crates/prover/tests/public_io.rs`'
`a3_a_claimed_public_value_is_the_committed_column`, `#[ignore]`d for size.

---

## 16. `PUBLIC_OUTPUT` — family 13

### 16.1 Header

`family_circuit(13, n)` is `memory::zero_window_artifact(n)` with no channels — **`ZERO_WINDOWS`'
artifact, byte for byte**, and §11's entry describes it column for column and gate for gate. RAM
window `family::PUBLIC_OUTPUT_WINDOW` = 3, the journal: exactly one shard in every statement,
whether or not the execution committed a byte. Spec: `public-values.md` §4 and §5. Fill:
`prover::family_fill(13)`, the private `fill::window` — `ZERO_WINDOWS`' fill too — which is
`trace::build_init_teardown_columns(log, image, 3, h)`. Two committed columns, one virtual
table, two unmasked leaves, no enforcing gate, no lookup, no channel, two outputs. At `n = 12`,
its one height: 13 gate lists, top `L13`, 26 inner columns and relations. Its height is pinned
for §15.1's reason, and by the same constants.

**Its window moved and §15's did not**, which is the one asymmetry S-STREAM left. A window's
first address is `4h·w` and nothing else, so raising `h` from `2^8` to `2^12` kept
`PUBLIC_INPUT_ORIGIN` at `0x8000` — window 32 and window 2 are the same address at the two
heights — and moved the journal from `0x8400`, which is no window boundary at `2^12`, to
`0xC000`, the next one up. `guest_memory::PUBLIC_OUTPUT_ORIGIN` is the constant that records
it. Why it was raised at all is `revm-block.md` §2: that guest's frozen output commitment is a
per-transaction record of 13 fixed bytes plus the transaction's return data verbatim, under two
32-byte digests, and a 1,020-byte window held 73 of those records at zero return data and 21 at
the 45 bytes the pinned mini-block measures — against the 97 to 515 transactions a mainnet block
carries, so `guest_sdk::commit` exited 70 on all four real blocks S26 profiled. At 16,380 the
two figures are 1,255 and about 360 (`public-values.md` §9). **No circuit changed to buy it** —
§15.1's halving-list paragraph is this family's too, the two constructors differing only in the
init leaf.

**That it is the *same* artifact is the design, not a saving.** `value_window_artifact` was
written at S-IO and the journal does not take it: a committed init column is a column a
prover chooses, and it would choose the answer at timestamp 0, never store a word, and leave a
teardown column that matched anyway. The init leaf here is the literal 0 — no `M[2]`, no `S[0]`,
nothing to choose — so the only way the window ends holding the journal is that the guest's
stores put it there. Jolt closes the same hole with a mask; here the family simply has no column
to fill, which is cheaper and cannot be forgotten (`public-values.md` §5). Nothing checks this,
because there is nothing to check: the absence of a column is not a constraint.

### 16.2 Columns

| address | name | Rust | descriptive name | row `y` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the timestamp of the last write to the word at `0xC000 + 4y`, or 0 | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final word | the last value written, or 0 | leaf `teardown`; **`verify_shard_local` step 10c** |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |

Both are committed in `PublicInputs::memory_commitments` at G8. There is no `W`, no `S` and no
`M[2]`: `program::setup_commitments(13)` is empty, and the last row of `public-values.md` §5's
table — "there is no `M[2]`" — is the one place the design could have gone wrong.

`fill::window` reads `image.initial_word` for every window above 0, and here it returns 0 on
every row, which is what lets `ZERO_WINDOWS`' fill serve this family unchanged: the journal
window is `[0xC000, 0x10000)`, ending flush against `RAM_ORIGIN`, and both `loader`'s ELF
parser and `ProgramImage`'s own validator refuse a segment that leaves
`[RAM_ORIGIN, RAM_ORIGIN + RAM_LENGTH)` — "a segment leaves the guest RAM window" — so no image
byte can land there. An untouched row's teardown value is therefore 0, and its two leaves
cancel against the literal-zero init leaf.

### 16.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `α_addr·V[row] ×4 + α_ts·M[0] + α_val·M[1] + WC` | `T(RAM, 0xC000 + 4·row, teardown_ts, teardown_value)` |
| 1 | 1 | `init` (write side) | `α_addr·V[row] ×4 + WC` | `T(RAM, 0xC000 + 4·row, 0, 0)` |

Here `WC = γ_M + 2 + α_addr·0xC000`, the window constant at `h = 2^12`, `w = 3`. Both are
`Linear` and carry no mask, for §15.3's reason. Code: `memory::window_tuple(Some(M[0]), M[1])`
for the read side and the inline `Linear` of `zero_window_artifact` — four `(α_addr, V[row])`
terms on the window constant, and no value term at all — for the write side. The halving lists
and the outputs are §10.3's and §15.3's, with the same names, relation numbers and addresses;
`p` in step 10a is the position of `(13, 0)` in `statement_shards`, one past `PUBLIC_INPUT`'s.

**Step 10c reads `claims[1]`**: base claims arrive in layout order `M`, `W`, `S`, and this
family's whole layout is `M[0]`, `M[1]`, so index 1 is `teardown_value` and can be nothing
else — where `PUBLIC_INPUT`'s step 10c reads index 2. The verifier evaluates its own
multilinear extension of `public_io_words(public.output)` at the shard's opening point and
compares, returning
`MemoryArgument("the public output window is not the statement's output")` on a mismatch. The
multiset forces a window's teardown column to be each address's **last** value (`memory.md`
§4.2), so the comparison says the statement's output is what the guest's stores left behind.

### 16.4 Rows

A window shard has no padding: every row is an address, and all 4,096 of them are live — word 0
the journal's byte length and 4,095 payload words, `guest_memory::PUBLIC_PAYLOAD_BYTES` =
16,380 bytes against `2^8`'s 1,020. `zero_row_valid` is `true` and the
padding contract is `M[0] = 0, M[1] = 0`.

| row | `teardown_ts` | `teardown_value` | leaves |
| --- | --- | --- | --- |
| word 0, a run that committed nothing | 0 | 0 | both `T(RAM, 0xC000, 0, 0)`: they cancel |
| word 0, a run that committed `b` bytes | the last `commit`'s store timestamp | `b` | the final tuple read against the zero tuple written |
| a journal word the guest stored | that store's timestamp | the word it stored | as above |
| a word past the journal | 0 | 0 | both `T(RAM, 0xC000 + 4y, 0, 0)`: they cancel |

A guest that panics has still published what it committed: the journal is memory and the panic
handler does not have to know about it (`public-values.md` §7).

**What holds this in CI**: `crates/checker/tests/public_values.rs`'
`the_journals_family_has_no_init_column`, which asserts `family_circuit(13, v).to_bytes() ==
zero_window_artifact(v).to_bytes()` at `v = PUBLIC_WINDOW_HEIGHT.trailing_zeros()` — the height
read off the constant, so S-STREAM's raise needed no edit there — and that the family commits
exactly two columns — and whose
doc comment records the consequence of ever failing, that the verifier would then owe a check
that the init column is zero, and a check can be forgotten where a missing column cannot.

---

## 17. `ADVICE_WINDOWS` — family 14

### 17.1 Header

`family_circuit(14, n)` is `memory::value_window_artifact(n)` with no channels —
**`PUBLIC_INPUT`'s artifact at a different height**, and the two differ only in what the
verifier does with `M[2]`: holds it to the statement's `input`, or to nothing at all. The
prover-supplied advice region from `guest_memory::ADVICE_ORIGIN` = `0x8000_0000` up: `k ≥ 0`
shards, shard `i` being window `verifier_core::advice_first_window(h) + i`, consecutive from
the origin, so the statement carries a **count** and no window list. Spec:
`public-values.md` §6. Fill: `prover::family_fill(14)`, the private `fill::advice`, which is
`trace::build_value_window_columns(log, [trace::advice_word(bytes, h·i + y)]_y,
advice_first_window(h) + i, h)`. Three committed columns, one virtual table, two unmasked
leaves, no enforcing gate, no lookup, no channel, two outputs. At `n = 22`, its default and the
window height: 23 gate lists, top `L23`, 46 inner columns and relations; at `n = 16`, the window
height the prover suites set, 17 lists, top `L17`, 34 of each.

**It is in every `VmConfig` and usually proves zero shards.** `program::decode_program` lists it
always, at the window height — `verifier_core::window_height` requires `INIT_TEARDOWN`,
`ZERO_WINDOWS` and `ADVICE_WINDOWS` to be present and equal — while
`trace::advice_window_count` is `ceil(advice_region_words / h)` and
`trace::advice_region_words` is **0** for empty advice, not 1. No advice is no region, not a
region holding a zero length word; otherwise every program in the repository would pay a whole
window at the window height to say it has none. `verifier_core::check_memory_windows` bounds the
count from above instead, `advice_first_window(h) + k ≤ 2^30 / h`, which is the top of the
address space; the `ZERO_WINDOWS` ids stop at `2^29 / h − 1` and the advice ids start at
`2^29 / h`, so the two families' windows are disjoint by arithmetic and no disjointness rule is
needed.

### 17.2 Columns

| address | name | Rust | descriptive name | row `y` of shard `i` holds | read by |
| --- | --- | --- | --- | --- | --- |
| `M[0]` | `teardown_ts` | `PolyAddress::Memory(0)` | Last write time | the timestamp of the last write to the word at `0x8000_0000 + 4h·i + 4y`, or 0 | leaf `teardown` |
| `M[1]` | `teardown_value` | `PolyAddress::Memory(1)` | Final word | the last value written; `init_value` if untouched | leaf `teardown` |
| `M[2]` | `init_value` | `PolyAddress::Memory(2)` | Advice word | `trace::advice_word(advice, h·i + y)`: word 0 of shard 0 the payload's byte length, then the payload little-endian, 0 past the end | leaf `init` — **and nothing else, anywhere** |
| `V[row]` | `row` | `VirtualKind::RowIndex`, wire tag 0 | Row index | `y` | both leaves |

All three are committed in `PublicInputs::memory_commitments` at G8. **`M[2]` is the one
committed column in the registry that no gate, no opening against identity or the SRS digest and
no step of `verify_shard` fixes**: only its own init leaf reads it, and a leaf constrains nothing
by itself — it balances against whatever the guest read, whatever that was. That is not an
omission; it is the definition of advice (`public-values.md` §6). What a guest owes in return
is a check of the advice against something a proof *does* bind — the public input carrying a
commitment to it, or the journal naming the state roots a block began and ended on, as
`guests/revm-block` does — and the VM cannot discharge that obligation for it.

A store into the advice region is an ordinary store and the multiset carries it like any other:
the region is **not** enforced read-only (owner's decision, S-IO), because enforcing it would need
a space selector on the load path of three frozen families and would buy no soundness on a column
nothing binds.

### 17.3 Leaves and layers

| `L1` | relation | node | positional | named |
| --- | --- | --- | --- | --- |
| 0 | 0 | `teardown` (read side) | `α_addr·V[row] ×4 + α_ts·M[0] + α_val·M[1] + WC` | `T(RAM, 4h·w + 4·row, teardown_ts, teardown_value)` |
| 1 | 1 | `init` (write side) | `α_addr·V[row] ×4 + α_val·M[2] + WC` | `T(RAM, 4h·w + 4·row, 0, init_value)` |

Here `w = advice_first_window(h) + i` and `WC = γ_M + 2 + α_addr·4h·w`, so at `h = 2^22` the
first window is 128 and shard `i` starts at `0x8000_0000 + i·2^24`. The address-space tag is
`RAM`, as it is for ordinary RAM and for the two public windows: what tells an advice word from
a heap word is which family initializes the address, and the ranges are disjoint by construction
(`public-values.md` §2). Both leaves are `Linear`, unmasked, degree 1, and the constructor is
§15.3's. The halving lists and the outputs are §10.3's, with the same names, relation numbers
and addresses; at `n = 22` the outputs are `L{23}[0]` and `L{23}[1]`, relations 44 and 45, and
`p` in step 10a is the position of `(14, i)` in `statement_shards`, last of all.

**There is no step 10c for this family.** `verify_shard_local`'s `public_value` match arm names
`PUBLIC_INPUT` and `PUBLIC_OUTPUT` and falls through to `None` for every other family, family 14
included.

### 17.4 Rows

A window shard has no padding: every row is an address. `zero_row_valid` is `true` and the
padding contract is `M[0] = 0, M[1] = 0, M[2] = 0`.

| row | `teardown_ts` | `teardown_value` | `init_value` | leaves |
| --- | --- | --- | --- | --- |
| shard 0's word 0 | 0, or a store's timestamp | the payload's byte length, or what overwrote it | the payload's byte length | the length word, laid out by `trace::advice_word` |
| an advice word the guest only read | 0 | the advice word `v` | `v` | both `T(RAM, a, 0, v)`: they cancel |
| an advice word the guest stored to | that store's timestamp | the value it stored, `v'` | the advice word `v` | `T(RAM, a, t, v')` read against `T(RAM, a, 0, v)` written |
| a word past the supplied advice | 0 | 0 | 0 | both `T(RAM, a, 0, 0)`: they cancel |

The last row is why the shard count is a function of what the **host supplied** and not of what
the guest read: the words a guest never touched still have to be initialized, and their two
tuples cancel. Above `0x8000_0000 + 4·advice_region_words` the executor's read is the fatal
`OutOfBounds`, because no window of this execution initializes an address there and nothing an
executor did with it could balance.

**What holds this in CI**: `crates/checker/tests/public_values.rs`'
`the_advice_region_is_a_length_word_then_a_payload`, `the_window_rules_take_an_honest_statement`
and `the_window_rules_refuse_each_of_their_controls`. That nothing binds `M[2]` is a negative, and
**no test asserts it directly**: the proof-level control that stood in for it — the same program
proved over two different advices, both verifying — was removed when the suite was abridged. What
holds the property now is the construction, not a test: the statement does not carry `M[2]`,
identity does not bind it, and no gate reads it.

---

## 18. `MOD_MUL` — family 15

### 18.1 Header

`family_circuit(15, n)` is `mod_mul::artifact(n)` with `mod_mul::channels()`, which is **one
`RANGE16` channel** since S26c (`delegation.md` §10.3). Like `EC_ADD` and `FR_ARITH` it is built
by `memory::assemble`: every constraint it makes fits as an enforcing gate on gate list 0, so
above the leaves it is two product trees, one fraction tree and nothing else. Normative spec:
`delegation.md` §4, §5 and **§14**. Fill: `prover::family_fill(15)`, the private
`fill::mod_mul`. Ecall `0x0504`, anchor space `address_space::DELEGATION_MOD_MUL` = 7.

**`0x0503` is retired and burned**, and the constant
`ecall::RETIRED_MOD_MUL_WITNESSED_MODULUS` is what says so. It was S26's call over a 32-word
frame carrying a **witnessed** modulus; S26b's frame is 25 words whose word 0 is a *selector*,
and append-only forbids a number a second meaning — an old binary calling `0x0503` would have
had its modulus read as a selector and computed something else, with nothing failing loudly
(`ecall-abi.md`, `delegation.md` §10.2).

**325 committed columns (104 `M`, 221 `W`, no `S`) and one virtual table, `V[range16]`.** Gate
list 0 writes 1,088 columns — 32 leaves a side of the two memory trees plus the `RANGE16` tree's
512 fraction pairs — and holds **125 enforcing gates (54 degree-1, 71 degree-2)**. **274
obligations**, all `RANGE16`, **4 outputs**. At its `n = 16` there are 26 gate lists (10 row-wise
and 16 halving), the top is `L26`, and the circuit has 2,244 inner columns and 2,369 relations,
550,391 bytes of wire form — `crates/constraints/tests/vectors/mod_mul.txt`, which is the
SHA-256 and shape line CI diffs, the artifact itself being half a megabyte. **None of the counts
before that sentence depends on `n`** except the inner and relation totals, which are
`2,180 + 4n` and `2,305 + 4n`: a height adds halving lists and nothing else, one node per output
each (`crates/checker/tests/mod_mul.rs`' `a_height_moves_only_the_halving_layers`, which now
compares `n = 16` against `n = 18`, `2^8` no longer being a height this family has).

`artifact` panics unless the column counts are `MEMORY_COLUMNS` and `WITNESS_COLUMNS`, there is
one `W` name per `W` column, the **multiplicity** closes the witness — a fill that wrote past it
would be writing into nothing, and `lookup`'s own rule wants the multiplicity last — the
obligation count is `lookups()`' own, and `A`, `B` and `OUT` index their own values
(`mod_mul::check_shape`). It also panics on every refusal of `validate`, of
`memory::check_memory`, of `lookup::check_discharge` and of `lookup::check_copowers`.

**What S26c changed is how a bound is spelled, and nothing else.** The frame is the same 25
words, the ecall is the same `0x0504`, the four moduli are the same, and every gate states what
it stated. Every bound this family made was a bit decomposition — 950 gap bits, 768 value bits,
768 chain-difference bits, 256 quotient bits, 518 carry bits, 60 base bits, 3,320 in all, each
with its own booleanity gate — and at `2^16`, where `V[range16]`'s table fits exactly,
`docs/spec/memory.md` §7's 16+16 pair makes a 32-bit bound **one committed column and two
obligations**. So:

| | pre-S26c | now | factor |
| --- | --- | --- | --- |
| committed columns | 3,468 (104 `M`, 3,364 `W`) | **325** (104 `M`, 221 `W`) | 10.7 |
| enforcing gates | 3,502 (86/3,416) | **125** (54/71) | 28.0 |
| obligations | 0 | **274** | — |
| gate lists at `n = 16` | 22 (6 + 16) | **26** (10 + 16) | — |
| inner columns at `n = 16` | 158 | **2,244** | 0.07 |
| wire bytes | 1,404,716 | **550,391** | 2.6 |
| proof bytes a shard at `n = 16` | 360,948 | **135,220** | 2.7 |

The `W` side is the whole of the committed fall: 950 gap bits became 50 chunks, 60 base bits
became 4 columns, each value's 520 columns became 32, `q`'s 264 became 16, and the carries' 518
became 42, with one multiplicity column added — 3,364 to 221, the 3,143 columns
`the_shape_is_the_manifests` names. The 125 enforcing gates are the old 3,502 less exactly three
groups: the 3,320 booleanity gates of those bit decompositions, the 32 `<v>_word{k}` and
`q_word{k}` decodes that read them, and the 25 `gap_w{j}` gates, which the gap's own obligations
now do the work of (§18.5). Nothing else went.

**The proof is where the win lands.** 3,364 witness commitments at 64 bytes were 215,296 of the
old 360,948; 221 are 14,144 of the new 135,220, and the commit phase is 325 Mercury column
commitments where it was 3,468. The numbers are `shard-proof.md` §9's layout over this circuit's
own shape, the formula `crates/prover/tests/mem.rs`' `proof_bytes` computes (§1.2).

**The computed peak barely moves, and that is the trade.** One `2^16` shard is about **5.1 GB**
— 4.57 GB of forward pass over the ten row-wise layers' 2,180 columns at `2^16` rows and 32
bytes (the sixteen halving layers add 8.4 MB between them), 0.16 GB of committed base (285
small-type columns at 4 bytes and 40 `Fr` ones at 32: `cycle`, the 25 read timestamps and the 14
carries), and 0.34 GB of transition 0's first bind, a half-height `Fr` table over 325 columns.
The same accounting on the pre-S26c circuit gives about **4.9 GB** — 0.27 GB of forward pass but
0.96 GB of base and 3.64 GB of first bind. The work moved out of the base layer and its bind and
into the inner layers, at roughly constant peak, and bought the proof and the commitments.
`crates/prover/tests/common`' `DELEGATION_CHANNEL_VARS` records 4.7 GB for this family, which is
the naive `inner × 2^16 × 32`; both are **computed**, and `delegation.md` §9.2's last paragraph
still owes a measured figure from the deferred `prover::revm` and `host::prove` suites.

**One row is one Ethereum field multiplication**, and since S26b the modulus is **one of four** a
frame word selects, supplied by the circuit as literals. S26 carried it as a witnessed 256-bit
operand; `delegation.md` §10.2 records the change and why, and §18.4 is what it bought. The four
are secp256k1's base and scalar fields and BN254's — which `docs/handoff/S26-cycle.md` §4
measures together at 31% to 57% of a mainnet block's guest cycles — and between them they are
every 256-bit field Ethereum block execution multiplies in. **The EVM's `MULMOD` is not among
them**: an arbitrary modulus has no representation in this frame and nothing routes the opcode
here.

**The height is `2^16`, and since S26c it is the only one the family has.** `RANGE16`'s table
needs sixteen variables, so `family_circuit`'s **derived** minimum-height guard — the widest
range channel's `BITS` over the family's own `channels()` — returns `None` below 16, and the
range in §1.1 is `16 ≤ n ≤ 30` where every other delegation family's is `0 ≤ n ≤ 30`. Three
things follow. `MOD_MUL_FIXTURE_VARS = 8` in `crates/prover/tests/common` is **gone**, replaced
by `DELEGATION_CHANNEL_VARS = 16`; `crates/checker/tests/mod_mul.rs` evaluates rows of the real
`2^16` circuit **row-locally** through `checker::violated_relations` rather than running a
whole-shard forward pass, because there is no reduced height to run one at; and
`crates/prover/tests/fills.rs` samples 32 live and 4 padding rows of a filled shard for the same
reason. All three are cheaper than what they replace and two of them are stronger statements.
The height was already `2^16` before S26c, for an unrelated reason — this is the one delegation
family whose invocation count a real workload drives hard, and at `2^8` S26's measured block took
1,048 shards where at `2^16` it takes 5 (`delegation.md` §9.1, §9.2) — so the channel's floor
cost nothing and the two constraints coincide.

**This family has a §0.5 row, and it is at `n = 16`.** §0.5's counts are over one circuit at
`n = 20`, which this family is never built at; its entries there are its own `n = 16` shape
counts — 824 `Linear`, 573 `Product`, 908 `Quadratic`, 48 `TreeProduct` (3 a halving list) and
16 `TreeCross` (1 a halving list) — and they sum to 2,369. The `TreeCross` is what a fourth
output costs and what makes a delegation family with a channel visible in that table at all.

### 18.2 Row kinds

Two, and neither is an instruction: **this family is invoked, not decoded**
(`delegation.md` §1). It claims no pc, `program::lookup_tuple(15)` is empty, it owns no cycle,
it is not in `constants::family::CYCLE_OWNING`, and it is in a `VmConfig` exactly when the linked
binary declares it. **One row is one multiplication** — `ops/row = 1`, as every delegation family
has it — and there is no no-op row kind: a row is live or it is padding.

| row kind | `live` | what the row holds | what it adds to the multiset |
| --- | --- | --- | --- |
| a **multiplication** | 1 | the requesting cycle, the frame base, the 25 words read and written, the four modulus selectors and the eight limbs they name, three values' 24 limb halfwords and 24 chain columns, the quotient's 8 limbs and 8 halfwords, 14 signed carries as a value and two chunks, and 25 × 2 gap chunks with the frame pointer's four columns | 26 read tuples and 26 write tuples: the 25 frame words at `(RAM, base + 4j)`, and the anchor pair at `(DELEGATION_MOD_MUL, base)` |
| **padding** | 0 | every committed cell 0 **as the honest fill writes it**, the multiplicity column excepted | nothing: all 64 leaves are 1 — 52 real ones collapse to the product's identity and 12 are pads that are literally 1 — and 274 gated zeros the channel counts |

The multiplicity column is the one committed column whose row `y` is not this shard's `y`-th
invocation: it is row `y` of `V[range16]`, and what it holds is a count over the whole shard
(§0.3).

Three gates hold the all-zero row and are worth spelling out. `one_modulus_a_live_row` forces
every selector to 0 there, so `m_limb{k}_rule` forces every modulus limb to 0, which is what
lets the three `<v>_canonical{i}` chains be **ungated** and still hold. Each
`<v>_below_modulus` reads `live = borrow7`, so a padding row's last borrow must be 0 where a live
row's must be 1 — three gates say it, and a fill that computed a padding row's chain against the
shard's modulus rather than against the row's zero `m` would fail all three. And `carry_terms`
puts `live` on the offset, so a padding row's carry reads `carry{k} − 2^36·0` and `limb{k}`
reads `0 = 0`, not `−2^36`.

**The padding row is all-zero because the fill writes it so, not because the gates force it**,
and since S26c that is true of *more* cells than before. Every obligation's selector is `live`,
and a lookup holds wherever its selector is 0, so on a padding row no bound applies at all:
with `m = 0` the limb identity reduces to a relation among `a`, `b`, `out`, `q` and the carries
over `Fr`, with none of them bounded, and a padding row could legally carry unbounded cells where
before S26c its ungated `<v>_word{k}` decompositions still pinned every limb below `2^32`. It is
harmless — the row's leaves are the multiset identity, it requests nothing, pairs with no anchor
and writes no register — but a test asserting "a padding row's columns are zero" is asserting a
property of the fill. `crates/checker/tests/tamper.rs` asserts the direction that matters in
both senses: the honest all-zero row satisfies every gate (`zero_row_valid` is `true`, which
`check_padding` recomputes), and its **control** twin writes a 1 into a padding row's
`gap_chunk(5, 0)` and requires the block to **verify** — the cell being genuinely free, because
the four obligations it feeds all carry `live`.

### 18.3 The base layer

**Memory-argument columns, `M[0..104]`** — filled by `fill::mod_mul` through the shared
`delegation_frame_range16`; committed in `PublicInputs::memory_commitments`, absorbed at G8
before the memory challenges.

| address | name | what it is |
| --- | --- | --- |
| `M[0..4]` | `cycle`, `live`, `base`, `anchor_value` | as §12.3: the requesting cycle, the row's one mask, the `a0` the request passed, and the anchor teardown's value, **free on both sides** |
| `M[4 + 4j + f]` | `w{j}_addr`, `w{j}_read_ts`, `w{j}_read_value`, `w{j}_write_value` | frame word `j`, `j < 25`: word 0 the modulus selector, 1–8 `a`, 9–16 `b`, 17–24 the result `out`, eight little-endian 32-bit limbs a value (`constants::mod_mul`'s `SELECTOR_WORD`, `A_WORD`, `B_WORD`, `OUT_WORD`) |

**Witness columns, `W[0..221]`** — all filled by `fill::mod_mul` except the last; committed in
`ShardProof::witness_commitments`, absorbed at S3, with `g` drawn after them at S4.

| address | name | what it is |
| --- | --- | --- |
| `W[2j + c]`, `j < 25`, `c < 2` | `gap{j}_c{c}` | chunk `c` of word `j`'s timestamp gap, weight `2^{16(c+1)}` — `50` columns where S26 had 950 bits |
| `W[50..54]` | `base_low`, `base_low_hi`, `base_room`, `base_room_hi` | `(base − RAM_ORIGIN)/4` and `2^31 − 100 − base`, each with its high halfword |
| `W[54..58]` | `selector1` … `selector4` | the four modulus selectors, in `mod_mul::CODES` order: codes 1, 2, 3, 4 |
| `W[58..66]` | `m_limb{k}` | limb `k` of the selected modulus — **a witness column, and the only place `m` exists** |
| `W[66 + 32v + k]` | `a{k}_hi`, `b{k}_hi`, `out{k}_hi` | the high halfword of limb `k` of value `v`, in frame order: `a` at `W[66..98]`, `b` at `W[98..130]`, `out` at `W[130..162]` |
| `W[66 + 32v + 8 + i]` | `<v>_diff{i}` | difference limb `i` of value `v`'s `< m` chain |
| `W[66 + 32v + 16 + i]` | `<v>_diff{i}_hi` | its high halfword |
| `W[66 + 32v + 24 + i]` | `<v>_borrow{i}` | borrow `i` of that chain; `borrow7` is pinned to `live` |
| `W[162..170]`, `W[170..178]` | `q_limb{k}`, `q_limb{k}_hi` | the quotient's eight limbs — **the one value in the row the execution did not record** — and their halfwords |
| `W[178 + 3k]`, `W[179 + 3k]`, `W[180 + 3k]`, `k < 14` | `carry{k}`, `carry{k}_c0`, `carry{k}_c1` | signed carry `k` as the **unsigned** `carry + 2^36`, and its two chunks. `carry{k}` is `Fr`-backed, the value reaching `2^37` |
| `W[220]` | `range16_multiplicity` | the `RANGE16` table's count, filled by `trace::build_multiplicities` and not by the fill |

Every address is reached through `mod_mul::word`, `gap_chunk`, `base_low`, `base_low_hi`,
`base_room`, `base_room_hi`, `selector`, `m_limb`, `value_hi`, `diff`, `diff_hi`, `borrow_bit`,
`q_limb`, `q_hi`, `carry`, `carry_chunk` and `multiplicity_column`, so a fill, a checker and a
tamper twin name a column and never a number; `the_witness_regions_do_not_overlap` holds those
accessors to covering the witness exactly once each. The value index is `mod_mul::A`, `::B` or
`::OUT` and never a literal — three values where S26 had four, and a bare index would have
silently renumbered every twin.

**136 of the 221 witness columns are read by no gate at all**, and that is the shape of the
re-shape: the 50 gap chunks, `base_low_hi`, `base_room_hi`, the 24 `<v>{k}_hi`, the 24
`<v>_diff{i}_hi`, the 8 `q_limb{k}_hi` and the 28 carry chunks exist only to be the direct half
of a 16+16 pair, and `range16_multiplicity` is read only by the leaf `range16_table_num`. What
*is* read by a gate is the value each pair bounds — `diff(v, i)` by `<v>_canonical{i}`,
`q_limb(k)` and `carry(k)` by the limb equations — so a corrupted halfword breaks no relation
and is refused by the channel alone (§18.5).

**Where each value reads from.** The selector, `a` and `b` are read from each word's
`read_value`; `out` alone is read from `write_value`. That is the whole of what makes the call a
function: the guest's field and operands are what it *passed*, and the result is what the
invocation *wrote*. Seventeen `writes_back_w{j}` gates then hold every non-result word to writing
back what it read, so a call can rewrite neither the guest's operands nor — word 0 being inside
that set — the field it was asked to work in.

### 18.4 The gates

125 enforcing gates on gate list 0, relations 1,088–1,212, in `artifact`'s own order.

| group | relations | count | degree | what it says |
| --- | --- | --- | --- | --- |
| `live_boolean` | 1,088 | 1 | 2 | the row's one mask is a bit |
| `addr_w{j}` | 1,089–1,113 | 25 | 2 | `live·(w{j}_addr − base − 4j)`: word `j` is at `base + 4j`. Degree 2 because it carries `live` — on a padding row `addr` and `base` are 0 and `4j` is not |
| `base_aligned`, `base_in_window` | 1,114–1,115 | 2 | 2 | `live·(base − 4·base_low − RAM_ORIGIN)` and `live·(2^31 − 100 − base − base_room)`: the base is 4-aligned and its whole 100-byte frame is inside RAM |
| `writes_back_w{j}`, `j < 17` | 1,116–1,132 | 17 | 1 | `w{j}_write_value − w{j}_read_value`: the selector and both operands survive the call |
| `selector{code}_boolean` | 1,133–1,136 | 4 | 2 | each of the four modulus selectors is a bit |
| `selector_rule` | 1,137 | 1 | 1 | `w0_read_value − Σ code_i·s_i` |
| `one_modulus_a_live_row` | 1,138 | 1 | 1 | `Σ s_i − live` |
| `m_limb{k}_rule` | 1,139–1,146 | 8 | 1 | `m_k − Σ MODULI[i][k]·s_i`, the literals of the four moduli |
| `<v>_borrow{i}_boolean` | 1,147–1,154, 1,164–1,171, 1,181–1,188 | 24 | 2 | the three chains' borrows are bits |
| `<v>_canonical{i}` | 1,155–1,162, 1,172–1,179, 1,189–1,196 | 24 | 1 | `v_i − m_i − b_{i−1} + 2^32·b_i − d_i`, **ungated** |
| `<v>_below_modulus` | 1,163, 1,180, 1,197 | 3 | 1 | `live − borrow7`: the subtraction borrowed out, so `v < m` |
| **`limb{k}`, `k < 15`** | 1,198–1,212 | 15 | 2 | the schoolbook identity, position by position |

**There is no `gap_w{j}` gate and no `<v>_word{k}` or `q_word{k}` decode.** The 25 gaps and the
40 limbs they bounded are §18.5's obligations, which are the bound and the decomposition at
once, exactly as `memory::gap_lookups` has it for an execution family. That is 57 of the 3,377
gates S26c removed; the other 3,320 are the booleanity gates of the bit columns themselves.

**The fifteen limb equations are the circuit.** With `P_k = Σ_{i+j=k} a_i·b_j` and
`S_k = Σ_{i+j=k} q_i·m_j`, gate `limb{k}` is

```text
P_k − S_k − out_k + c_{k−1} − 2^32·c_k = 0,     c_k = carry{k} − 2^36·live
```

where `out_k` is absent past limb 7, `c_{−1}` is absent, and `c_14` is absent — which is the
closing condition. Weight the fifteen equations by `2^{32k}` and sum: the carries telescope and
what is left is `a·b − q·m − out = c_14·2^{480}`. A last carry that does not exist is a last
carry of zero, so **the absence of a fifteenth carry column is the identity**
(`the_limb_identity_closes`). Each gate is one `Quadratic`: the products are pairs of committed
columns — `a_i·b_j` two `M`s and `q_i·m_j` two `W`s, 64 pairs and so 128 products over the
fifteen gates — and everything else is a column times a literal, so the degree is 2 and never 3.

**Why the equation over `Fr` is the equation over ℤ.** Every operand is bounded to `2^32` by its
own 16+16 pair, so the largest term of any position is `8·(2^32 − 1)^2 < 2^67`, the largest
coefficient is `2^32` times a carry's offset, `2^68`, and `p` is 254 bits. No limb equation can
wrap, so there is no modular-arithmetic loophole to argue about — the same argument
`delegation.md` §13.3's canonicity chain rests on. **Since S26c that premise is a lookup and not
a gate**, which is the one thing the re-shape changed about the soundness story: drop an
obligation and the identity stops being about integers, exactly as dropping a decomposition did.

**`m` has no bound of its own, and `one_modulus_a_live_row` is what stands in for it.** Every
other value in that paragraph is bounded by its two obligations; `m`'s limbs are bounded only by
`m_limb{k}_rule` pinning each to one entry of a four-row table of literals, which holds exactly
while at most one selector is set. **So the gate is load-bearing twice.** Once for the selector:
the codes are 1, 2, 3, 4, so `1 + 3 = 4` and a row claiming secp256k1's `p` *and* BN254's `q`
spells the frame word of a row claiming BN254's `r` — `selector_rule` cannot see the forgery, and
a `const` assertion in `selector_gates` says so, so nobody deletes the gate believing the codes
are separated. And once for the integer semantics: two selectors at once give
`m_0 = 0xffff_fc2f + 0xd036_4141 > 2^32`, `S_k` above `2^68`, and the paragraph above out of
reach. It is therefore **not** made redundant by any code spacing — separating the codes to
1, 2, 4, 8 would let `selector_rule` see the forgery and would still leave `Σ s_i = live` as the
only thing bounding `m`. `two_moduli_at_once_is_refused` is the twin.

**Eight columns for `m`, not four products a limb.** The alternative was substituting
`Σ MODULI[i][k]·s_i` wherever `m_k` appears. The chains would take four linear terms instead of
one, which is free; `limb{k}`'s 64 `q_i·m_j` products would become 256, taking gate list 0 from
128 products to 320. Eight committed columns and eight degree-1 gates is the cheaper half, and it
is also what makes "the modulus is not the selected literal" a cell a tamper twin can corrupt —
`a_modulus_limb_that_is_not_the_selected_literal_is_refused`.

**The signed carry.** A position's partial sum can be negative, and `Fr` has no sign, so a carry
is the committed `carry{k}` minus `2^36·live`: a 37-bit unsigned value read as an offset value in
`[−2^36, 2^36)`. The bound is the fixed point of `C = (2^67 + 2^32 + C)/2^32`, which settles just
above `2^35`, so 37 bits with a `2^36` offset is a full factor of two of room —
`the_carry_offset_covers_the_bound` computes it rather than trusting this paragraph. **The
selector does not tighten it**: the recurrence reads only the limbs' `2^32` bounds. What changed
at S26c is the *witness*: `carry{k}` is now a committed `Fr` column bounded by four obligations
where it used to be 37 boolean columns summed by a gate. The `live` factor on the offset is
unchanged and is what makes a padding row's carry 0 (§18.2).

**Three chains, and the fixed modulus is what makes them free of `live`.** `delegation.md` §13.3's
canonicity chain subtracts `p`, a *literal*, which has to be multiplied by `live` so the gate
vanishes on a padding row. Here the chain subtracts `m_i`, a **column** that `m_limb{k}_rule`
already forces to 0 on a padding row, so the gate is **ungated** and degree 1 with nothing paid
for it. S26 reached the same shape from the opposite direction — `m` was a frame word then, and
gating would have made the gate degree 3.

**`m > 0` needs no gate.** Every entry of `MODULI` is a 256-bit odd prime above `2^253`, which
`every_modulus_is_a_256_bit_odd_value` holds a fifth entry to as well. S26 needed
`emulator::mod_mul_frame` to refuse a zero modulus by name; there is no zero modulus to refuse
any more, and that refusal went with the operand it read.

**What bounds `q`, and what the operand chains buy.** Its sixteen obligations bound it to
`2^256`, and `a < m` with `b < m` make that **enough by construction**:
`q = (a·b − out)/m ≤ (m−1)²/m < m ≤ 2^256`. So the statement is *total* — every frame the circuit
accepts has a witness and every witness it has is accepted — where S26 had only soundness. S26's
note here read "a cost to the **prover**, never a false statement to the verifier", which was
true of an unreduced operand then and is not a thing that can happen now: `a_below_modulus` and
`b_below_modulus` refuse the frame, `emulator::mod_mul_frame` refuses it earlier and by name, and
the fill asserts it earlier still. The price is the caller's, and it is real:
`guests/vendor/k256` reduces an operand below `p` where it used to reduce only below `2^256`
(`delegation.md` §14.3, §14.4). `out < m` remains the **reduction** and is a different statement
from the other two: without it a prover answers `r + m` with the quotient one lower and every
limb equation still holds.

### 18.5 The lookups and the channel

One channel, `RANGE16` = channel 1, table `V[range16]`, multiplicity `W[220]`. The tuple is
**one** expression wide, so it weights its column by the literal 1, reads `g` and **no** power of
`β` and no neutral, and `E + g = g + live·e_0` is the row denominator. Every obligation's
selector is `LIVE`. The helpers are `delegation::{range16, bound32, bound_chunked,
gap_lookups_range16}`, shared with `EC_ADD`.

| obligation | relations | count | tuple | shape |
| --- | --- | --- | --- | --- |
| `gap{j}_c0_range`, `gap{j}_c1_range` | 66–613 | 50 | `gap{j}_c{c}` | direct: each chunk below `2^16` |
| `gap{j}_top_scaled` | ” | 25 | `2^10 · gap{j}_c1` | scaled: the top chunk below `2^6` |
| `gap{j}_lo_range` | ” | 25 | `4·cycle − w{j}_read_ts − 1 − 2^16·c0 − 2^32·c1` | the derived low sixteen bits |
| `base_low_c0_range`, `base_low_top_scaled`, `base_low_lo_range` | ” | 3 | `base_low_hi`, `2^3·base_low_hi`, `base_low − 2^16·base_low_hi` | `[0, 2^29)` |
| `base_room_c0_range`, `base_room_top_scaled`, `base_room_lo_range` | ” | 3 | as above with `2^1` scaling | `[0, 2^31)` |
| `{v}{k}_hi_range`, `{v}{k}_lo_range` | ” | 48 | `<v>{k}_hi`, `w{j}_value − 2^16·<v>{k}_hi` | each limb of `a`, `b`, `out` below `2^32` |
| `{v}_diff{k}_hi_range`, `{v}_diff{k}_lo_range` | ” | 48 | 16+16 over `diff(v, k)` | the three chains' difference limbs |
| `q{k}_hi_range`, `q{k}_lo_range` | ” | 16 | 16+16 over `q_limb(k)` | each quotient limb below `2^32` |
| `carry{k}_c0_range`, `_c1_range`, `_top_scaled`, `_lo_range` | ” | 56 | two chunks, `2^11·carry{k}_c1`, and `carry{k} − 2^16·c0 − 2^32·c1` | each carry's unsigned value below `2^37` |

**274 obligations**, in that order: 100 for the gaps, 3 and 3 for the base, 96 for the three
values and their chains (32 a value, interleaved limb by limb), 16 for the quotient, 56 for the
carries. `check_shape` holds `artifact.lookups.len()` to `lookups()`' own count, so a dropped
obligation is a panic where the artifact is built.

**The 38-bit timestamp gap is `RANGE16`'s and not `TIMESTAMP`'s**, and it cannot be otherwise:
that channel's `BITS` is 19 and its table needs `2^20` rows, which is an execution family's floor
and no delegation height on the menu (`delegation.md` §9, §10.3). Two committed chunks with a
derived low half are three 16-bit pieces for 38 bits, `38 = 16 + 16 + 6`, and the decomposition
is **exact**: the maximum is `(2^16 − 1)(1 + 2^16) + 2^32(2^6 − 1) = 2^38 − 1`. The carries' 37
bits are the same shape at `37 = 16 + 16 + 5`, exact at `2^37 − 1`, and the base's 29 and 31 bits
are one committed chunk each.

**A 16+16 pair is one committed column and two obligations, and that is the whole reason the
channel is worth carrying.** A 32-bit bound by bit decomposition is 32 columns and 32 booleanity
gates, and a 38-bit gap is 38. The low expression is *defined* as the remainder
`x − 2^16·hi`, so no wrap is possible: `hi < 2^16` and `x − 2^16·hi < 2^16` give `x < 2^32`.

**The scaled obligation alone bounds nothing**, and `lookup::check_copowers` is what says so:
`2^{16−r}` is a unit in `Fr`, so an unbounded value sweeps a coset almost none of whose members
is a small integer, and the range check sees nothing wrong. It is the top chunk's own **direct**
obligation under the **same** selector that establishes the premise — S18's fix — and
`mod_mul::scaled_columns` lists all 41 scaled columns with `LIVE` beside each: the 25 gap tops,
`base_low_hi`, `base_room_hi`, and the 14 carry tops. `artifact` runs the check and panics on it.

**One multiplicity column, and no gate reads it.** `trace::build_multiplicities` counts each
`RANGE16` table row's occurrences over the 274 gated tuples of every row of the shard — switched-
off rows included, a padding row contributing 274 zeros, so table row 0's count is large — and
appends the column after the fill; `prover::fill::mod_mul` does not write it, which is why
`crates/prover/tests/fills.rs` passes `WITNESS_COLUMNS − channels().len()` to `covers`. It has to
exist because `artifact.committed()` names it, and it is last in the witness subtree because
`lookup`'s own rule wants it there. It is the fourth output's ancestor and so the whole reason
this family has four outputs and not two.

`checker::violated_lookups` is the native reading of every one of these obligations, the same
statement LogUp proves, and `lookup::check_discharge` — which `memory::assemble` runs because the
family now declares a channel — is what says each obligation has its own denominator leaf with a
numerator of 1 beside it and the channel exactly one table fraction.

### 18.6 The trees, the inner layers and the outputs

Three trees. The two memory product trees take `d::leaves(DELEGATION_MOD_MUL, 25)`: 25 frame
words plus one anchor leaf a side, **26 real leaves padded to 32**, so each side carries 6
`read_pad{i}` / `write_pad{i}` leaves that are literally 1. The read side's leaves consume the
write each frame word names, then the anchor **teardown**
`T(space, base, 4·cycle + 3, anchor_value)`; the write side's write at `4·cycle + 0`, then the
anchor **answer** `T(space, base, 0, 0)`, stamped 0 and valued 0. The `RANGE16` fraction tree
takes 274 obligations plus its table fraction, **275 leaves padded to 512**, so 237 pad
fractions of `(0, 1)`.

**`R = 9`, and the fraction tree sets it alone** — a 32-leaf product tree is 5 deep — so the
depth is `N = 1 + 9 + n` and the circuit is **ten** row-wise lists where before S26c it was six.
That is the whole of why the list count, the inner count and every relation number moved: the
committed width fell by 10.7 and the tree above it grew by four levels.

Layer `L1` is 1,088 wide: `read_1_*` 0–31, `write_1_*` 32–63, then the fraction tree's 512
`(num, den)` pairs at 64–1,087, the table's first and the 237 pads last. Widths:

```text
L1     1,088      L5        68      L9        6      L11 … L{n+10}    4 each
L2       544      L6        34      L10       4
L3       272      L7        18
L4       136      L8        10
```

so `inner = 2,180 + 4n` — 2,244 at `n = 16`. The two product trees reach one node at `L6` and are
carried as `Linear` copies through `L7`–`L10`; the fraction tree reaches one pair at `L10`.

Relations: **0–1,087** are list 0's leaves — `read_w0`…`read_w24`, `read_anchor`,
`read_pad0`…`read_pad5`, then the write side's twelve-plus-twenty, then `range16_table_num`,
`range16_table_den`, the 274 obligations' `{name}_num` / `{name}_den` pairs in `lookups()` order
at 66–613, and `range16_pad_{i}_num` / `_den` at 614–1,087 — **1,088–1,212** its 125 enforcing
gates in §18.4's order, then **1,213–1,756** list 1, **1,757–2,028** list 2, **2,029–2,164**
list 3, **2,165–2,232** list 4, **2,233–2,266** list 5, **2,267–2,284** list 6,
**2,285–2,294** list 7, **2,295–2,300** list 8, **2,301–2,304** list 9, and halving list `k`
(`10 ≤ k ≤ n + 9`) holds `2,305 + 4(k − 10)` to `2,308 + 4(k − 10)`. The roots are relations
`2,301 + 4n` to `2,304 + 4n`: **2,365–2,368** at `n = 16`.

Each halving list is four gates: the `read_root`-side and `write_root`-side `TreeProduct`s, the
channel's denominator `TreeProduct`, and its numerator `TreeCross`. **The channel's fraction tree
is exempt from the padding-identity clause**, and `checker::check_padding_identity` makes that
exemption by shape: it requires every column the first halving list reads to be exactly 1 except
the operands of a `TreeCross`, because a fraction tree's identity is `(0, 1)` and a padding row
is not idle in a channel — it contributes 274 neutral entries the multiplicity column counts.

**The outputs**, in output-map order: 0 `read_root` and 1 `write_root` at `memory::READ_ROOT` and
`WRITE_ROOT`, read at `verify_shard` step 10a against `memory_roots[p]` for `p` the position of
`(15, shard_index)` in `verifier_core::statement_shards` — **last** in every statement it
appeared in until `EC_ADD` arrived above it, family ids being the statement's order — and each a
factor of `gkr_verify::reconciles` over the whole statement; 2 `range16_num_root` and 3
`range16_den_root`, read at step 9, the failure `Lookup { channel: 1 }` and the check **both**
`num == 0` and `den != 0`, a leaf pair of `(0, 0)` otherwise annihilating the tree.

### 18.7 What fixes each cell

| cell | what fixes it |
| --- | --- |
| `cycle`, `base` | the multiset: the request's mirror write is `T(DELEGATION_MOD_MUL, base, 4·cycle + 3, v)` and this row's teardown read is its only reader (§5's anchor); locally `base_aligned`, `base_in_window` and `addr_w{j}` against the words |
| `live` | `live_boolean`, and every leaf's mask |
| `anchor_value` | **nothing local**: the request's `deleg_write_value` must equal it, and the memory argument is what says so (§21 observation 19) |
| `w{j}_read_ts` | the memory argument alone; the four `gap{j}_*` obligations only hold it below this row's own write |
| word 0's value | the frame's read tuple, `writes_back_w0`, and `selector_rule` against the four selectors |
| `selector{code}` | its booleanity gate, `selector_rule` and `one_modulus_a_live_row` — the three together are exactly "one of the four codes, the one the frame names" |
| `m_limb{k}` | `m_limb{k}_rule`: a literal of `MODULI`, chosen by the selector, which is also its `2^32` bound — this family's one bound that is neither an obligation nor a decomposition |
| `a`, `b` word values | the frame's read tuples, `writes_back_w{j}` against their write values, their own 16+16 obligations, and their `< m` chains |
| `out` word values | `limb{k}`, `out`'s chain and its own obligations: given `m`, `a`, `b` and the bounds, integer division has one answer |
| every `<v>{k}_hi`, `<v>_diff{k}_hi`, `q_limb{k}_hi`, `gap{j}_c{c}`, `carry{k}_c{c}`, `base_low_hi`, `base_room_hi` | **its own two or four obligations and nothing else**: no gate reads any of the 136, so a wrong halfword or chunk breaks no relation and the channel is the only thing that refuses it |
| `q_limb{k}` | `limb{k}`: fifteen equations in eight unknowns over the integers, whose solution is unique once `out < m`; its `2^256` bound by its sixteen obligations |
| `<v>_diff{i}`, `<v>_borrow{i}` | `<v>_canonical{i}`, the borrows' booleanity and the `diff` obligations; `borrow7` by `<v>_below_modulus` |
| `carry{k}` | `limb{k}` and `limb{k+1}`, which the carry joins, and its four obligations |
| `range16_multiplicity` | `trace::build_multiplicities`, and the channel's own root check — no gate reads it |
| the padding row | `check_padding`'s all-zero row and §18.2's gates that hold there, subject to §18.2's last paragraph |

**The suite is row-local at `n = 16`, and since S26c it has to be.**
`crates/checker/tests/mod_mul.rs` builds a column set of eight rows — **one invocation per
selector**, so every modulus the circuit holds is run, plus the `a = 0` corner where the product,
the remainder and every carry are zero and the `(m−1)²` corner that is the widest the frame
admits, and two padding rows — and evaluates each row alone through `checker::violated_relations`
over scratch `gkr::gate_values` computes, exactly as `crates/checker/tests/add_sub.rs` does.
There is **no forward pass and there cannot be**: the family's circuit does not exist below
`2^16`, `family_circuit(MOD_MUL, 8)` being `None`, so a whole-shard pass would be 4.6 GB. One row
of the real circuit is both cheaper and a stronger statement than a pass over a toy height was.
Nothing in the file shares a line with `prover::fill::mod_mul` or with `emulator`'s executor: its
own `U256` over two `u128` halves, its own long division, its own borrow chains and its own
carries, so a circuit that stated anything but `a·b mod m` would reject an honest witness. The
moduli themselves are `constants::mod_mul::MODULI`, which `crates/constants/tests/moduli.rs`
holds to arkworks.

Fourteen tests, of which four are worth knowing about.

`a_limb_above_its_bound_is_refused_by_the_channel_alone` zeroes an honest nonzero `a0_hi`, which
leaves the derived low half equal to the whole limb, and asserts **both** halves of the
re-shape's statement: `assert_every_row_holds` finds not one violated relation, and
`checker::violated_lookups` names `a0_lo_range`. Until S26c the bound was `a_word0`, a gate; it
moved rather than vanished, and this is the test that says which.

`a_result_not_below_the_modulus_is_refused`: `(q − 1, r + m)` satisfies **every** limb equation
and every obligation — it is the same product, decomposed one multiple of `m` differently — and
`out_below_modulus` is the only thing that refuses it. It runs on a BN254 row rather than a
secp256k1 one because `p = 2^256 − 2^32 − 977` leaves no room: `r + p` does not fit eight limbs,
so on that row the forgery cannot even be written down.

`an_operand_not_below_the_modulus_is_refused`: `a = m`, then `b = m`, with the quotient, the
result, the carries and all three chains computed honestly for it — `m·b mod m = 0` with `q = b`,
a perfectly well-formed witness of a claim the circuit must refuse. Nothing is corrupted;
`a_below_modulus` and `b_below_modulus` are the only gates that fail. It is not a hypothetical
shape: `m`'s raw limb pattern is upstream `k256`'s second representation of zero, and the
vendored patch handed it across the frame until S26b made it a refusal
(`delegation.md` §14.4).

`the_shape_is_the_manifests` is the third reading of §18.1's numbers, beside
`crates/constraints/tests/vectors/mod_mul.txt` and this page: the widths, the 26 lists, the 16
halving lists, 2,244 inner, 2,369 relations, the `(125, 54, 71)` enforcing split, 274
obligations, 4 outputs, one virtual table, one channel and 550,391 wire bytes.

Two readings sit outside that suite. `crates/prover/tests/fills.rs` holds the **real** fill to
the same gates — `the_mod_mul_and_ec_add_fills_cover_their_circuits_exactly` is set equality over
addresses less the one multiplicity column, and `every_delegation_fill_satisfies_every_gate`
evaluates the first 32 and last 4 rows of a filled `2^16` shard, which is where a `< m` chain
computed against the wrong modulus or a padding row's chain computed against the shard's would
surface. And `crates/checker/tests/tamper.rs`' `s26_the_mod_mul_witness_and_anchor_are_pinned`
re-proves `guests/mod-mul-ops`' block per twin: the result, the quotient, a carry and the
selector word the call rewrote, each moved as a value **and its halfword together** — shifting
both by `2^16` and `1` leaves the derived low half exactly where it was, so both obligations
still hold and what refuses the twin is a limb equation, the gate that says the multiplication
was performed — plus the control that a padding row's gap chunk is free, and the anchor twins
through the family-parameterized `checker::assert_anchor_twins_refused`, of which this is the
fourth caller.

---

## 19. `SHA256_COMP` — family 16

### 19.1 Header

`family_circuit(16, n)` is `sha256::artifact(n)` with `sha256::channels()`, which is **empty**.
Like `POSEIDON2` it is built by `delegation::Assembly`, not by `build::assemble` — `FR_ARITH`,
`MOD_MUL` and `EC_ADD` go through `memory::assemble`, every constraint each makes fitting as an
enforcing gate on gate list 0 (§14.1, §18.1, §20.1) — but unlike `POSEIDON2` it is the first
delegation family whose work needs
**inner layers of its own**, which is what `Assembly` exists for (`crates/constraints/src/
delegation.rs`: `build::push_list` maps an inner address to its scratch slot by scanning every
slot pushed so far, and this circuit's layer 1 is 15,857 columns wide). Normative spec:
`delegation.md` §4, §5 and **§15**. Fill: `prover::family_fill(16)`, the private
`fill::sha256_comp`.

**8,216 committed columns (100 `M`, 8,116 `W`, no `S`) and no virtual table.** Gate list 0
writes 15,857 columns — 64 memory leaves, 465 carried scalars, 6,112 carried bits and one `x·y`
helper for each of 9,216 XOR bits — and holds **8,215 enforcing gates (48 degree-1, 8,167
degree-2)**. Gate list 1 writes 785 and enforces nothing; gate list 2 writes 16 and holds the
**184 degree-1 equations that are the compression function**. **No lookup**, 2 outputs. At its
`n = 8` there are 14 gate lists (6 row-wise and 8 halving), the top is `L14`, and the circuit has
16,688 inner columns and 25,087 relations, 10,895,760 bytes of wire form — every one of those
numbers read from `crates/constraints/tests/vectors/sha256.txt`, the committed shape line, and
re-derived here in §19.7 and §19.8. **Only the last two depend on `n`**: a height adds one
halving list per variable carrying one node per output, so `inner = 16,672 + 2n` and
`relations = 25,071 + 2n`, with the committed width, the gate split and the zero lookups
unmoved. `artifact` panics on every refusal of `validate` and of `memory::check_memory`, and
`check_shape` then asserts the two column counts, that there is no setup column, no lookup and
no channel, and that **layer 1's width is `layer1_width()`** — counted on the emitted artifact,
never on what was handed in (S21 must-be-exact 4).

**One row is one SHA-256 compression: one 64-byte block against one chaining state.** It is
**not the digest**. Padding, the length encoding and the Merkle–Damgård block loop stay in
`guest_sdk::sha256`, exactly as the sponge stays in `guest_sdk::keccak256` (`delegation.md` §11,
§15.0). A digest-shaped frame would have needed a length, a variable block count and a decision
about where padding happens, none of which a fixed-width frame expresses.

**The height is `2^8`**, the menu's opening entry, and it is a ceiling: one row is 16,688 inner
columns, so `gkr::forward` materializes `16,688 × 256 × 32` bytes = **137 MB** a shard at `2^8`
and `16,688 × 65,536 × 32` = **35.0 GB** at `2^16` (`delegation.md` §9.2's table). `artifact`
accepts `0 ≤ n ≤ 30` and `family_circuit` returns `Some` over that whole range, because the
minimum-height guard is derived from the family's own `channels()` and an empty channel list
gives a floor of 0 (§19.6).

**This family has no §0.5 row of its own**, like every delegation family but `KECCAK_F`: §0.5
counts gate *shapes* over one circuit at `n = 20`, which is not a height this family is built
at. §19.1's `8,399 (232/8,167)` is the enforcing split §0.5 would carry, and the row below
gives the shape counts at `n = 8` for an integrator who wants them there.

### 19.2 Row kinds

Two, and neither is an instruction: **this family is invoked, not decoded**. It claims no pc,
`program::lookup_tuple(16)` is empty, its decoded table has no column and no live row
(`crates/program/tests/tables.rs` pins `(SHA256_COMP, 0)`), `program::claims_pcs(16)` is false
and `constants::family::CYCLE_OWNING[16]` is false. It is in a `VmConfig` exactly when the
linked binary declares it — the third presence rule (`delegation.md` §7).

| row kind | `live` | what the row holds | what it adds to the multiset |
| --- | --- | --- | --- |
| an **invocation** | 1 | the requesting cycle, the frame base, the 24 words read and written, all 24 words' 32 read bits, the eight written words' 32 bits and one carry bit each, the 48 derived schedule words' bits and 2 carry bits each, `A_1..A_64` and `E_1..E_64` as bits, 64 `ca` and 64 `ce` of 3 bits, 24 × 38 gap bits and the frame pointer's 60 | 25 read tuples and 25 write tuples: the 24 frame words at `(RAM, base + 4j)` and the anchor pair at `(DELEGATION_SHA256_COMP, base)` |
| **padding** | 0 | every committed cell 0, **as the honest fill writes it** | nothing: all 64 leaves are 1 |

**There is no frame this family can refuse**, and it is the only one of the six of which that is
true (`delegation.md` §15.1): every `u32` is a legal chaining word and a legal schedule word, so
`emulator::sha256_frame` takes no `pc` and has no error path. The only frame errors left are the
two every delegation family shares — a misaligned base and a frame past the top of RAM — and
those are the emulator's `Misaligned` and `OutOfBounds`.

**A padding row is far less free here than in any other family, and the ungated equations are
why.** Of §19.5's and §19.7's gates only five carry `live` — `addr_w{j}`, `gap_w{j}`,
`base_aligned`, `base_in_window` and, through `−K_i·live`, the 128 round gates. Everything else
is ungated because every term is 0 on an all-zero row: so a padding row's `w{j}_read_value` is
pinned to its own 32 bits by `in{j}_word`, its written words to theirs by `out{j}_word`, its
sixteen block words to their read values by `writes_back_w{j}`, and its schedule and round bits
to a **`K`-free compression** by `schedule_w{i}`, `round_a{i}`, `round_e{i}` and `output_h{j}`
with the constants switched off. The all-zero row satisfies all of that, which is why
`zero_row_valid` is `true`. What is genuinely free on a padding row is `cycle`, `base`,
`anchor_value`, the 24 `w{j}_addr` and `w{j}_read_ts`, the 912 gap bits and the 60 base bits —
and a fill could legally write a nonzero `K`-free compression into the rest. It would be
harmless (the row's leaves are the multiset identity, it requests nothing and pairs with no
anchor), but **a test asserting "a padding row's columns are zero" is asserting a property of
the fill**, exactly as §18.2 records for `MOD_MUL`.

### 19.3 The base layer

**Memory-argument columns, `M[0..100]`** — filled by `fill::sha256_comp` through the shared
`delegation_frame`; committed in `PublicInputs::memory_commitments`, absorbed at G8 before the
memory challenges, exactly as a CPU family's are. Every address is reached through
`sha256::CYCLE`, `LIVE`, `BASE`, `ANCHOR_VALUE` and `sha256::word(j, field)`, which are
`delegation`'s re-exported, so a fill, a checker and a tamper twin name a column and never a
number.

| address | name | what it is | read by |
| --- | --- | --- | --- |
| `M[0]` | `cycle` | the requesting cycle | **25 leaves** — the 24 `write_w{j}` at `4·cycle + 0` and `read_anchor` at `4·cycle + 3` — and the 24 `gap_w{j}` gates. **Not** `write_anchor`, whose timestamp is the literal 0 |
| `M[1]` | `live` | the row's one mask | **all 50 real leaves, as their mask** (the 14 pads read nothing); `live_boolean`; the 24 `addr_w{j}`, the 24 `gap_w{j}`, `base_aligned` and `base_in_window`; the carried scalar `live_l1`, and two layers up all **128** round gates (§19.7) |
| `M[2]` | `base` | the `a0` the request passed: 4-aligned, at or above `RAM_ORIGIN`, with `base + 96 ≤ 2^31` | leaves `read_anchor` and `write_anchor`, as their address; all 24 `addr_w{j}`; `base_aligned`, `base_in_window` |
| `M[3]` | `anchor_value` | **free**; 0 in an honest fill | leaf `read_anchor` **and nothing else** |
| `M[4 + 4j]` | `w{j}_addr` | `base + 4j`, `j < 24` | leaves `read_w{j}`, `write_w{j}`; `addr_w{j}` |
| `M[5 + 4j]` | `w{j}_read_ts` | the timestamp of the last write to that word | leaf `read_w{j}`; `gap_w{j}` |
| `M[6 + 4j]` | `w{j}_read_value` | words 0–7 the chaining state `H0..H7`, words 8–23 the block's `W0..W15` big-endian decoded | leaf `read_w{j}`; `in{j}_word`; `writes_back_w{j}` for `j ≥ 8`; and the carried scalar `state_in{j}_l1` for `j < 8` |
| `M[7 + 4j]` | `w{j}_write_value` | words 0–7 the compressed state, words 8–23 the block **unchanged** | leaf `write_w{j}`; for `j < 8` `out{j}_word` and the carried scalar `state_out{j}_l1`; for `j ≥ 8` `writes_back_w{j}` |

The last group is `M[96..100]`. `constants::sha256::STATE_WORD` is 0, `BLOCK_WORD` is 8 and
`FRAME_WORDS` is 24, and `guest_sdk::recursion::Sha256Frame`'s three `const` assertions pin all
three, so a renumbering fails the build rather than transposing the state and the block.

**Witness columns, `W[0..8116]`** — all filled by `fill::sha256_comp`; committed in
`ShardProof::witness_commitments`, absorbed at S3. There is no `g` or `β` to follow them.

| address | name | Rust | what it is |
| --- | --- | --- | --- |
| `W[38j + i]`, `j < 24` | `gap{j}_{i}` | `sha256::gap_bit(j, i)` | bit `i` of `4·cycle + 0 − w{j}_read_ts − 1`, **912** in all |
| `W[912..941]` | `base_low{i}` | `base_low_bit(i)` | the 29 bits of `(base − RAM_ORIGIN)/4` |
| `W[941..972]` | `base_room{i}` | `base_room_bit(i)` | the 31 bits of `2^31 − 96 − base` |
| `W[972 + 32j + t]` | `in{j}_bit{t}` | `in_bit(j, t)` | bit `t` of frame word `j`'s **read** value, 768 |
| `W[1740 + 32j + t]`, `j < 8` | `out{j}_bit{t}` | `out_bit(j, t)` | bit `t` of state word `j`'s **written** value, 256 |
| `W[1996 + j]` | `co{j}` | `out_carry(j)` | the output sum's one carry bit, 8 |
| `W[2004 + 32(i−16) + t]` | `w{i}_bit{t}` | `sched_bit(i, t)` | bit `t` of derived schedule word `W_i`, `16 ≤ i < 64`, 1,536 |
| `W[3540 + 2(i−16) + t]` | `cw{i}_{t}` | `sched_carry_bit(i, t)` | the schedule sum's 2 carry bits, 96 |
| `W[3636 + 32(i−1) + t]` | `a{i}_bit{t}` | `a_bit(i, t)`, `i ≥ 1` | bit `t` of `A_i`, `1 ≤ i ≤ 64`, 2,048 |
| `W[5684 + 32(i−1) + t]` | `e{i}_bit{t}` | `e_bit(i, t)`, `i ≥ 1` | bit `t` of `E_i`, 2,048 |
| `W[7732 + 3i + t]` | `ca{i}_{t}` | `ca_bit(i, t)` | the 3 bits of round carry `ca_i`, 192 |
| `W[7924 + 3i + t]` | `ce{i}_{t}` | `ce_bit(i, t)` | the 3 bits of `ce_i`, 192 |

**Every one of the 8,116 witness columns is a bit, and every one carries its own booleanity
gate** (§19.5). That is what replaces the range channels a `2^8` shard cannot hold, and it is
also every bound this circuit makes — there is no other kind.

**`a_bit` and `e_bit` are total on `i ≤ 0`, and that is the whole of `B`, `C`, `D` and `H`.**
FIPS 180-4 shuffles eight working words a round; six are copies, so with `A_i` and `E_i` the
values of `a` and `e` at the start of round `i`, `B_i = A_{i−1}`, `C_i = A_{i−2}`,
`D_i = A_{i−3}`, `F_i = E_{i−1}`, `G_i = E_{i−2}` and `H_i = E_{i−3}`. The four non-positive
indices of each sequence therefore *are* the frame's state words, and the accessors say so
without a column:

```text
a_bit(i, t) = in_bit(−i, t)         for i ≤ 0:  A_0 = H0, A_{−1} = H1, A_{−2} = H2, A_{−3} = H3
e_bit(i, t) = in_bit(4 − i, t)      for i ≤ 0:  E_0 = H4, E_{−1} = H5, E_{−2} = H6, E_{−3} = H7
w_bit(i, t) = in_bit(8 + i, t)      for i < 16: the block's sixteen words are schedule words 0–15
```

So `in{j}_bit{t}` does triple duty: it is frame word `j`'s decomposition, it is a working-word or
schedule-word bit, and for `j < 8` it is a carried scalar's operand. One set of 768 bits, three
consumers, no copies. The **carried carries** have no such trick: `ca` and `ce` are 3 bits
because `T1 = E_{i−3} + Sigma1 + Ch + K + W < 5·2^32` and `T2 = Sigma0 + Maj < 2·2^32` give
`ca ≤ 6`, and `A_{i−3} + T1 < 6·2^32` gives `ce ≤ 5`; `cw ≤ 3` from the schedule's four-term sum
is 2 bits, and `co ≤ 1` from `H_j + V_j` is one. **All four widths are derived ceilings, not
observations** (`constants::sha256::CARRY_{A,E,W,OUT}_BITS`), and
`sha256.rs`' `the_two_word_recurrence_is_the_compression_function` then *observes* the maxima
over 48 pseudo-random states and asserts each is inside its width — the confirmation, not the
derivation. **`T1` is never reduced and is not a column**: both consumers take it modulo `2^32`,
so reducing it would be two more carries a round for the same answer.

### 19.4 Gate list 0: the 64 leaves, the 465 carried scalars, the 6,112 carried bits and the 9,216 helpers

Gate list 0 writes `L1`'s 15,857 columns, relations 0–15,856, in four blocks whose offsets are
**arithmetic** — `scalar_base(1) = 64`, `bit_base() = 529`, `work_base(1) = 6,641` — which is why
`Assembly` exists and why `every_layer_is_as_wide_as_its_parts` is a test.

**The memory product trees**, `L1[0..64]`, relations 0–63, each leaf per §0.6, built by the
shared `delegation::leaf`. `leaves_a_side(24) = 32`, so **25 real leaves and 7 pads a side**.

| `L1` | relation | node | mask | `AS` | addr | timestamp | value |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `j` (`j < 24`) | `j` | `read_w{j}` | `M[1]` | 2 (RAM) | `M[4 + 4j]` | `M[5 + 4j]` | `M[6 + 4j]` |
| 24 | 24 | `read_anchor` | `M[1]` | **8** | `M[2]` | `4·M[0] + 3` | `M[3]` |
| 25–31 | 25–31 | `read_pad0` … `read_pad6` | — | — | — | — | the constant 1 |
| `32 + j` | `32 + j` | `write_w{j}` | `M[1]` | 2 | `M[4 + 4j]` | `4·M[0] + 0` | `M[7 + 4j]` |
| 56 | 56 | `write_anchor` | `M[1]` | **8** | `M[2]` | the literal **0** | the literal **0** |
| 57–63 | 57–63 | `write_pad0` … `write_pad6` | — | — | — | — | the constant 1 |

The anchor pair is `delegation.md` §5's, unchanged and not restated: `write_anchor` is stamped
0, the timestamp no ordinary cycle can produce; `read_anchor` is stamped `4·cycle + ANCHOR_DELTA`
= `4·cycle + 3`, the slot the request's mirror query wrote at, which is what pins this row's
`cycle` to the request's; `anchor_value` is free on both sides and the multiset is what pairs
them. The frame's writes ride `FRAME_DELTA = 0`, a `(space, Δ)` pair no query of
`constraints::memory`'s table holds, which is what lets `trace`'s frame builder tell an
invocation's events from the requesting row's (`delegation.md` §4.1).

**The carried scalars**, `L1[64..529]`, relations 64–528, **465 of them**. Each is
`Σ_t 2^t · bit` over committed bits — which is that value's 32-bit bound wherever the bits carry
booleanity, and they all do — or a one-term copy, or, for `Ch`, a `Quadratic`. Their order is
`Scalar::index`, and it is the layout:

| indices | scalars | how each is built | count |
| --- | --- | --- | --- |
| 0–67 | `A_{−3} … A_{64}` (`am3_l1` … `a64_l1`) | `Σ 2^t · a_bit(i, t)` | 68 |
| 68–135 | `E_{−3} … E_{64}` | `Σ 2^t · e_bit(i, t)` | 68 |
| 136–199 | `ca_0 … ca_63` | `Σ_{t<3} 2^t · ca_bit(i, t)` | 64 |
| 200–263 | `ce_0 … ce_63` | likewise | 64 |
| 264–311 | `cw_16 … cw_63` | `Σ_{t<2} 2^t · sched_carry_bit(i, t)` | 48 |
| 312–319 | `co_0 … co_7` | the single column `out_carry(j)` | 8 |
| 320–383 | `W_0 … W_63` | `Σ 2^t · w_bit(i, t)` | 64 |
| 384–447 | `Ch_0 … Ch_63` | `ch_gate(i)`, below | 64 |
| 448–455 | `state_in0 … state_in7` | the single column `M[6 + 4j]` | 8 |
| 456–463 | `state_out0 … state_out7` | the single column `M[7 + 4j]` | 8 |
| 464 | `live` | the single column `M[1]` | 1 |

**`carried_scalars()` is that arithmetic and `carried_scalar_list()` is the list, the count is
spelled twice, and `artifact` asserts them equal.** It has to: the arithmetic is what every
layer offset is built from and the list is what the columns are built from, so when they
disagree the failure is a column **silently aliased onto the next block** — a gate reading an
existing neighbour, in range, with no other symptom — and not anything a reader of either
spelling would see. The same assertion covers `carried_bits()` against `carried_bit_list()`.

**`Scalar::Live` exists because a round's constant cannot be a bare literal, and S26c shipped
it as one.** `K_i` is a nonzero element of `constants::sha256::ROUND_CONSTANTS`, and a gate
stating `… − K_i = 0` outright cannot hold on an all-zero row; the padding contract requires it
to (`docs/spec/gkr.md` §4.3, and `padding.zero_row_valid` is `true` here). So the term is
`−K_i·live`, and since `live` is an `M` column that **only gate list 0 may read**, it is carried
like any other value — one column a layer, two layers, one `Linear` copy, which is what the
correct statement costs. The bug was invisible to `validate`, to `check_memory`, to
`check_shape`, to the emulator and to every guest; what found it is
`crates/checker/tests/sha256.rs`' `the_circuit_keeps_every_rule` calling
`checker::check_padding`, the second enforcement point. `delegation.md` §15.2 records it.

**`Ch` needs no helper and is written here**, beside them, because
`Ch(e, f, g) = g + e·f − e·g` is already degree 2 in the bits. Each bit of the result is
`g_t + e_t·f_t − e_t·g_t`, which is 0 or 1 over all eight inputs
(`the_degree_two_spellings_are_the_boolean_functions`, exhaustive), so the weighted sum is the
32-bit value:

```text
ch{i}_l1                                                     Quadratic, degree 2
  positional  Σ_{t<32} [ 2^t·e_bit(i−2, t)
                       + 2^t·e_bit(i, t)·e_bit(i−1, t)
                       − 2^t·e_bit(i, t)·e_bit(i−2, t) ]
  named       Ch_i = Ch(E_i, E_{i−1}, E_{i−2}),  f = E_{i−1}, g = E_{i−2}
```

It reads **committed** bits, which is why **no `E` below 0 is carried**: `Ch(0)`, `Ch(1)` and
`Ch(2)` reach `E_{−1}` and `E_{−2}` here, at the one list that can.

**The carried bits**, `L1[529..6641]`, relations 529–6,640, **6,112 of them**, each a
`d::copy` of a committed bit. They exist because gate list 1 builds the three-way XORs' values
and cannot read a committed column. Their ranges are **narrowed to exactly what list 1 reads**,
because a carried column no gate reads is one `validate` refuses — a relation constructed and
then dropped:

| block | indices | range | why those bounds |
| --- | --- | --- | --- |
| `A_i` bits | 0–2,111 | `A_BIT_FIRST = −2` … `A_BIT_LAST = 63`, 66 words | `Maj(0)` reads `A_0`, `A_{−1}`, `A_{−2}` at list 1, so `−2` is needed; **nothing reads `A_{−3}`'s bits** — it is a value only, the `D` of round 0 — and `A_64` likewise, being `output_h0`'s `V_0` |
| `E_i` bits | 2,112–4,159 | `E_BIT_FIRST = 0` … `E_BIT_LAST = 63`, 64 words | `Sigma1(i)` reads `E_i` for `i < 64` at list 1; `Ch` reads its three `E`s **committed** at list 0, so no negative index is carried, and `E_64` is a value only |
| `W_i` bits | 4,160–6,111 | `W_BIT_FIRST = 1` … `W_BIT_LAST = 61`, 61 words | `sigma0(W_{i−15})` for `i ≥ 16` reads `W_1` first; `sigma1(W_{i−2})` for `i < 64` reads `W_61` last. `W_0`, `W_62` and `W_63` are read only as **values** |

`every_carried_bit_is_read` walks every operand of every combination and holds each inside these
ranges and inside the block, so the ranges are **checked and not asserted**: one too wide is a
column `validate` refuses, one too narrow is an out-of-layer read it also refuses, and a changed
rotation constant moves the bound rather than breaking the circuit silently.

**The helpers**, `L1[6641..15857]`, relations 6,641–15,856, **9,216 = 288 × 32**. A three-way
XOR is degree 3 in bits — `x ⊕ y ⊕ z = x + y + z − 2(xy + yz + zx) + 4xyz` — so one helper a bit
is unavoidable, and this circuit **derives** it rather than committing it:

```text
helper{k}_{t}                                                Product, degree 2
  positional  1 · x.committed() · y.committed()
  named       p_t = x_t · y_t,  x and y operands 0 and 1 of combination k
```

There are 288 combinations, in the order `XORS` counts them: for each round `i < 64`,
`k = 3i` is `Sigma0(A_i)`, `3i + 1` is `Sigma1(E_i)` and `3i + 2` is `Maj(A_i, A_{i−1}, A_{i−2})`;
then for each derived word `i ∈ [16, 64)`, `k = 192 + 2(i − 16)` is `sigma0(W_{i−15})` and
`k = 192 + 2(i − 16) + 1` is `sigma1(W_{i−2})`. The rotations are FIPS 180-4's:
`Sigma0 = ROTR^{2,13,22}`, `Sigma1 = ROTR^{6,11,25}`, `sigma0 = ROTR^7 ⊕ ROTR^{18} ⊕ SHR^3`,
`sigma1 = ROTR^{17} ⊕ ROTR^{19} ⊕ SHR^{10}`, with bit `t` of `ROTR^r(x)` being bit
`(t + r) mod 32` of `x`. **All 9,216 helpers are `Product`**: `xor_operand` returns `None` only
where a `SHR` has shifted a bit away, and a `SHR` occupies operand slot **2** in both shapes that
have one, so the `_ => d::linear(Vec::new())` arm that would write the literal 0 is unreachable
for the five kinds this family has. It is defensive code with no live case, and the case it
guards is a sixth combination shape with a shift in slot 0 or 1.

### 19.5 Gate list 0's 8,215 enforcing gates

Relations 15,857–24,071, in list order. Every one carries constant 0, so the all-zero row
satisfies all of them.

| group | relations | count | shape, degree | what it says |
| --- | --- | --- | --- | --- |
| `live_boolean`, `gap{j}_{i}_boolean`, `base_low{i}_boolean`, `base_room{i}_boolean` | 15,857; 15,858–16,769; 16,770–16,798; 16,799–16,829 | 1 + 912 + 29 + 31 | `Quadratic`, 2 | the frame's own, `delegation::frame_gates`', byte-identical to §12.5's |
| `addr_w{j}`, `gap_w{j}`, `base_aligned`, `base_in_window` | 16,830–16,853; 16,854–16,877; 16,878; 16,879 | 24 + 24 + 1 + 1 | `Quadratic`, 2 | ditto: word `j` is at `base + 4j`, its read precedes its write by a 38-bit gap, the base is 4-aligned and at or above `RAM_ORIGIN`, and `base + 96 ≤ 2^31`. Degree 2 because each carries `live` as a factor — on a padding row `addr` and `base` are 0 and `4j` is not |
| `in{j}_bit{t}_boolean`, `in{j}_word` | 16,880–17,671 | 768 + 24 | 2, then 1 | every read word is its 32 bits |
| `out{j}_bit{t}_boolean`, `out{j}_word`, `j < 8` | 17,672–17,935 | 256 + 8 | 2, then 1 | every written state word is its 32 bits |
| `writes_back_w{j}`, `8 ≤ j < 24` | 17,936–17,951 | 16 | `Linear`, 1 | the block's sixteen words survive the call |
| `w{i}_bit{t}_boolean`, `cw{i}_{t}_boolean` | 17,952–19,583 | 1,536 + 96 | `Quadratic`, 2 | the derived schedule and its carries |
| `a{i}_bit{t}_boolean`, `e{i}_bit{t}_boolean` | 19,584–23,679 | 4,096 | `Quadratic`, 2 | the two sequences' 64 words each |
| `ca{i}_{t}_boolean`, `ce{i}_{t}_boolean` | 23,680–24,063 | 384 | `Quadratic`, 2 | the round carries |
| `co{j}_boolean` | 24,064–24,071 | 8 | `Quadratic`, 2 | the output carries |

The frame's five shapes are `delegation::frame_gates`' and are not restated; §12.5 spells each
one's positional and named form, and this family's differ only in the word count (24 for 50) and
the frame-bytes literal (96 for 200). The three that are this family's own:

```text
────────────────────────────────────────────────────────────────────────────────────────────
16880…  in{j}_bit{t}_boolean — every read bit is a bit              Quadratic, degree 2
  positional  0 = W[972 + 32j + t] − W[972 + 32j + t]·W[972 + 32j + t]
  named       0 = in{j}_bit{t} − in{j}_bit{t}²

  reads as  8,117 booleanity gates with live_boolean and the rest above: EVERY witness column
            of this circuit is a bit, and every bound it makes is a sum of them (§19.6).

────────────────────────────────────────────────────────────────────────────────────────────
        in{j}_word — the word read is its own 32 bits             Linear, degree 1
  positional  0 = M[6 + 4j] − Σ_{t<32} 2^t·W[972 + 32j + t]
  named       0 = w{j}_read_value − Σ_t 2^t·in{j}_bit{t}

  reads as  the recomposition and the 32-bit bound are one gate, as §12.5's input_w{j} is. It
            is the join between the memory columns and the witness: without it the circuit
            would compress whatever the bits said while the multiset carried whatever the word
            said. Ungated, and it needs no mask — every term is 0 on a padding row, which is
            also what pins a padding row's 768 read bits (§19.2).

────────────────────────────────────────────────────────────────────────────────────────────
        out{j}_word — the word written is its own 32 bits         Linear, degree 1
  positional  0 = M[7 + 4j] − Σ_{t<32} 2^t·W[1740 + 32j + t]
  named       0 = w{j}_write_value − Σ_t 2^t·out{j}_bit{t}

  reads as  every word this family writes into RAM is below 2^32, which is the delegation
            form of "a computed value is locally bounded" (memory-ops.md §5.1). The other
            sixteen written words are bounded through writes_back_w{j} against read values
            that in{j}_word already bounds, so all 24 are.

────────────────────────────────────────────────────────────────────────────────────────────
17936…  writes_back_w{j}, 8 ≤ j < 24 — the block is not rewritten  Linear, degree 1
  positional  0 = M[7 + 4j] − M[6 + 4j]
  named       0 = w{j}_write_value − w{j}_read_value

  reads as  the guest's schedule survives the call and the invocation computes the state
            alone. A circuit that let these sixteen move would let a caller's block be
            rewritten by an invocation, which the caller has no way to notice
            (crates/checker/tests/sha256.rs' a_block_word_rewritten_on_the_way_out_is_refused).
            The eight state words are deliberately NOT in this set: out{j}_word is theirs.
```

### 19.6 The lookups

There are none. `sha256::channels()` is empty, `CircuitArtifact::lookups` is empty,
`FamilyCircuit::reads_generic_table` is false, there is no multiplicity column, and
`lookup::check_discharge` over an empty channel list discharges nothing — which
`crates/checker/tests/sha256.rs` asserts rather than skips.

**The reason is the height, and it is the original rule rather than S26c's amendment.**
`constants::lookup_channel::BITS` bottoms out at 16 for `RANGE16` and is 19 for `TIMESTAMP`, and
a range channel is refused at construction unless `BITS ≤ trace_vars` (`lookup.md` §3). This
family lives at `2^8`, where **no channel's table fits at any price**, so every bound is a bit
decomposition with a booleanity gate — 8,116 of them, one per witness column. S26c's §10.3
amendment lets a delegation family at `2^16` carry `RANGE16`, and `MOD_MUL` and `EC_ADD` do; this
family has no reason to join them, its row being 16,688 inner columns where `EC_ADD`'s is 8,772
and `MOD_MUL`'s 2,244, so `2^16` is 35 GB of forward pass a shard (`delegation.md` §9.2).
`family_circuit`'s minimum-height guard is derived from `channels()` and so gives this family a
floor of **0**, which is what lets it take `2^8` without a special arm.

The consequences are §12.6's, and one is worth repeating: the shard's transcript draws `g` and
`β` like any other — they are shard-local and unconditional — and reads neither. Its proof
carries `2 + 2·0` outputs, its opening claim lists no setup commitment, and no padding row of it
pays a multiplicity.

### 19.7 Inner layers `L2` and `L3`: the XOR values and the equations

Above gate list 0 there are exactly two lists of work, and **neither costs the circuit any
depth** (§19.8). A layer's columns are the memory tree's, then the carried scalars, then — at
layer 1 only — the carried bits, then that layer's own work.

**Layer bases are per-layer, and that is a Law 1 requirement rather than a convenience.**
`scalar_base(layer) = tree_width(layer)`: the tree is **64** columns wide at layer 1 and **32**
at layer 2, so the same logical scalar sits at offset `64 + index` in one layer and
`32 + index` in the other. A `PolyAddress::Inner` is a `(layer, offset)` pair and the offset is a
**slot in that layer**, so `Scalar::at(layer)` has to recompute the base; a constant base would
put every layer-2 read 32 columns past where the scalar is — and `64 + index < 785` for every
index, so the address is **in range**, the gate reads an existing neighbour's column, and nothing
in `validate`, `check_shape` or `every_layer_is_as_wide_as_its_parts` refuses it. What refuses it
is the forward pass, which is why this family's suite runs one.

**The carried bits live at layer 1 only.** `bit_base() = scalar_base(1) + carried_scalars() =
529`, and `work_base(layer)` adds `carried_bits()` for `layer == 1` and nothing above it. Gate
list 1 reads the bits to build the XOR values; gate list 2 reads **values and nothing else**. So
carrying a bit higher would be a column nothing reads, which `validate` refuses — and rightly:
a relation constructed and then dropped constrains nothing.

**Gate list 1 → `L2`, 785 columns, relations 24,072–24,856, no enforcing gate.**

| `L2` | relations | node | shape | formula |
| --- | --- | --- | --- | --- |
| 0–31 | 24,072–24,103 | `tree_1_{i}`, `i < 32` | `Product` | `L1[2i] · L1[2i+1]` |
| 32–496 | 24,104–24,568 | `{name}_l2`, 465 | `Linear` | a copy of `L1[64 + index]` |
| 497–784 | 24,569–24,856 | `xor{k}_value`, 288 | `Quadratic` | below |

```text
xor{k}_value, k not a Maj                                     Quadratic, degree 2
  positional  Σ_{t<32} [ 2^t·x.at() + 2^t·y.at() − 2^{t+1}·helper(k,t) + 2^t·z.at()
                       − 2^{t+1}·z.at()·x.at() − 2^{t+1}·z.at()·y.at()
                       + 2^{t+2}·z.at()·helper(k,t) ]
  named       (x ⊕ y) ⊕ z  =  (x + y − 2p) + z − 2·z·(x + y − 2p),   p = x·y

xor{k}_value, k = 3i + 2 (Maj)                                Quadratic, degree 2
  positional  Σ_{t<32} [ 2^t·helper(k,t) + 2^t·c·a + 2^t·c·b − 2^{t+1}·c·helper(k,t) ]
  named       Maj(a, b, c) = pab + c·(a + b − 2·pab),  a = A_i, b = A_{i−1}, c = A_{i−2}
```

Both are degree 2 in `p`, `x`, `y` and `z` — all four at layer 1, the helper because gate list 0
wrote it and the bits because gate list 0 carried them. **`Maj` is not an XOR** but shares the
path: the same three operands, the same one helper a bit, the same degree-2 shape.
`the_degree_two_spellings_are_the_boolean_functions` checks both and `Ch` over all eight inputs,
exhaustively rather than sampled. Where a `SHR` has shifted operand 2 away the `z` terms and
both of its products are simply absent, so `sigma0`'s top 3 bits and `sigma1`'s top 10 are
two-way XORs — `every_carried_bit_is_read` counts exactly
`288·32·3 − 48·(3 + 10) = 27,024` operands for that reason.

**Committing the helpers instead would make the circuit one list shallower and much wider**:
17,560 committed columns against 8,216 — 1.69 MB of proof a shard against 1.33 MB, since a
committed column costs 96 wire bytes where an inner one costs 32. Deriving them is the cheaper
half and is why there are three gate lists at all.

**Gate list 2 → `L3`, 16 columns, relations 24,857–24,872, and the 184 equations that are the
compression**, relations 24,873–25,056. Every one is `Linear`, **degree 1 over layer 2**: all of
this family's nonlinearity is below it, in the 9,216 helpers, the 288 value gates and the 64 `Ch`
gates. Write `S(x)` for `L2[32 + x]`, `x` a scalar index from §19.4, and `X(k)` for
`L2[497 + k]`.

```text
────────────────────────────────────────────────────────────────────────────────────────────
24873–24920   schedule_w{i}, 16 ≤ i < 64 — the message schedule    Linear, degree 1

  positional  0 = S(320+i) + 2^32·S(264+i−16) − X(192+2(i−16)+1) − S(320+i−7)
                  − X(192+2(i−16)) − S(320+i−16)
  named       0 = W_i + 2^32·cw_i − sigma1(W_{i−2}) − W_{i−7} − sigma0(W_{i−15}) − W_{i−16}

  reads as  FIPS 180-4's schedule with the four-term sum's carry witnessed in 2 bits, which
            is what makes the Fr equation the integer one. Ungated: every term is 0 on a
            padding row, which is also what pins a padding row's 1,536 schedule bits.

────────────────────────────────────────────────────────────────────────────────────────────
24921–25048   round_a{i}, round_e{i}, i < 64 — the sixty-four rounds  Linear, degree 1

  T1_i  =  S(68+i)  +  X(3i+1)  +  S(384+i)  +  S(320+i)          E_{i−3} + Sigma1 + Ch + W
  T2_i  =  X(3i)    +  X(3i+2)                                    Sigma0 + Maj

  round_a{i}  0 = S(i+4) + 2^32·S(136+i) − T2_i − T1_i − K_i·S(464)
              0 = A_{i+1} + 2^32·ca_i − T1_i − T2_i − K_i·live
  round_e{i}  0 = S(i) + 2^32·S(200+i) − S(i) … − T1_i − K_i·S(464)
              0 = E_{i+1} + 2^32·ce_i − A_{i−3} − T1_i − K_i·live

  reads as  the whole compression over TWO sequences: b, c, d are A_{i−1..i−3} and f, g, h
            are E_{i−1..i−3}, so the eight-word shuffle costs nothing and the recurrence is
            two equations a round. `T1` appears in both and is never reduced. K_i rides
            `live` for §19.4's reason, and it is the only term of either gate that does.

────────────────────────────────────────────────────────────────────────────────────────────
25049–25056   output_h{j}, j < 8 — the eight output sums            Linear, degree 1

  positional  0 = S(456+j) + 2^32·S(312+j) − S(448+j) − S(v)
  named       0 = w{j}_write_value + 2^32·co_j − w{j}_read_value − V_j
              V = (A_64, A_63, A_62, A_61, E_64, E_63, E_62, E_61)

  reads as  H_j + V_j mod 2^32, the Davies-Meyer feed-forward. The V mapping is where the
            eight-word shuffle reappears and is the easiest line to transpose: j < 4 takes
            A_{64−j} and j ≥ 4 takes E_{64−(j−4)}. `the_written_state_is_the_compression`
            is the test that reads it back off the frame's write columns.
```

**Every carried scalar is read at layer 2, which is why there are 465 and not more.** `A_{−3}`
reaches `round_e0`, `A_0` reaches `round_e3`, `A_64` reaches `output_h0`; `E_0` reaches
`round_a3`, `E_64` reaches `output_h4`; `W_0` reaches `round_a0` and `schedule_w16`; each `ca`,
`ce`, `cw`, `co`, `Ch`, `state_in`, `state_out` and `live` reaches its own gate. A scalar that
reached none would be a column `validate` refuses.

### 19.8 The trees, the halving layers and the outputs

Two product trees of 32 leaves a side — 24 frame words, the anchor and **7 pads**, the pads
being leaves that are literally 1. `tree_width(layer)` halves once a layer and never below two:
64 at `L1`, 32 at `L2`, 16 at `L3`, 8 at `L4`, 4 at `L5` and **2 at `L6`**. The reads occupy the
first half of each tree at every level, so `L6[0]` is the read root and `L6[1]` the write root.

```text
L1   15,857  =  64 tree + 465 scalars + 6,112 bits + 9,216 helpers    (gate list 0)
L2      785  =  32 tree + 465 scalars +   288 XOR values              (gate list 1)
L3       16  =  16 tree                                               (gate list 2)
L4        8      L5  4      L6  2                                     (gate lists 3, 4, 5)
L7 … L{n+6}   2 each, the halving phase
```

Relations 25,057–25,064 are list 3's, 25,065–25,068 list 4's, 25,069–25,070 list 5's, and
halving list `6 + s` (`0 ≤ s < n`) holds `25,071 + 2s` and `25,072 + 2s`, two `TreeProduct`
gates. The roots are relations `25,069 + 2n` and `25,070 + 2n` — **25,085 and 25,086 at
`n = 8`**, the last two of 25,087.

**The tree needs five reduction lists and the work needs two, and six row-wise lists satisfy
both — so this circuit's inner work is free of depth.** With 32 leaves a side the largest
`log2` leaf count is `R = 5`, and `1 + R + n = 6 + n` is both the tree's requirement and this
circuit's actual depth; the XOR values ride inside list 1's reduction and the equations inside
list 2's. It is the first registered circuit with genuine inner work of which that is true:
`FR_ARITH`, `MOD_MUL` and — since S26d — `KECCAK_F` are also flat, putting every constraint on
gate list 0 and reducing nothing but trees above it (§12.7). Here there is **no
`read_up`/`write_up` gate at all**:
the deepest tree and the deepest work end on the same list.

**The outputs**, in output-map order. Both are absorbed as one `GKR_OUTPUTS` message before any
challenge of the backward pass and travel in `ShardProof::outputs`.

| # | address, `n = 8` | node | value | what `verify_shard` does with it |
| --- | --- | --- | --- | --- |
| 0 | `L14[0]` | `read_root` | the product of every read leaf of the shard: 24 frame reads and one anchor teardown per invocation, and 1 per padding row | **step 10a**: must equal `PublicInputs::memory_roots[p][0]`, `p` the position of `(16, shard_index)` in `verifier_core::statement_shards`; a factor of `reconciles` |
| 1 | `L14[1]` | `write_root` | the product of every write leaf | step 10a: `memory_roots[p][1]`, the same `p`; a factor of `reconciles` |

`statement_shards` is ascending by `FamilyId`, so this family's shards follow `MOD_MUL`'s and
precede `EC_ADD`'s. There is no channel root, so step 9 has nothing to check and the `Lookup`
error class cannot arise for this family.

**How the shard rides the block** is §12.8's paragraph unchanged: its ts window is
`[4·c_first, 4·c_last + 4)` over the invocations it holds, read off its own `M[0]`, and it is
excluded from the disjointness rule, `CYCLE_OWNING[16]` being false; its rows are invocations, so
`CycleProfile::total()` leaves them out of the cycle count while `plan_shards` counts them into
this family's shard count, and zero invocations are zero shards.

### 19.9 Witness rows — the chain that stands in for a row table

**There is no row table here, and there cannot usefully be one:** a live row is 8,216 committed
cells, 8,116 of them bits, and 7,144 of those are intermediates no frame word carries. What
stands in its place is a chain, and it is stronger than §12.9's in one respect — its reference is
pinned to the **standard's own published vectors** rather than to a second implementation in this
repository.

1. `crates/checker/tests/sha256.rs`' `compress` is FIPS 180-4 written there, over the circuit's
   two sequences, keeping every intermediate the witness commits. It shares no line with
   `emulator::sha256_frame`, with `guest_sdk`'s `sha256_compress_software` or with
   `prover::fill::sha256_comp`.
2. `the_reference_is_the_published_one` holds *that* to FIPS 180-4 §A.1's `sha256("abc")` and
   §A.2's two-block digest **before any negative control leans on it**. The two-block vector is
   the one that exercises chaining, and between them the two exercise all 64 round constants and
   the IV — which is what stands in for a re-derivation of `constants::sha256::ROUND_CONSTANTS`
   from its generators. Without this step every test below would be holding the circuit to a
   hand-written function with nothing holding *it* to anything.
3. `the_written_state_is_the_compression` reads the answer off the frame's **write columns**,
   not off a witness column the same gates set. This is the test that the *addressing* is right,
   and no negative control can be: a circuit computing a correct SHA-256 of the wrong sixteen
   words passes every one of them.
4. `an_honest_witness_satisfies_every_gate` runs the circuit's **forward pass** at `n = 2` — four
   rows, two live invocations and two padding rows, about 2.1 MB of inner cells — and
   `gkr::self_check`. A pass is affordable here precisely because the family carries no channel
   and so builds at four rows, where `MOD_MUL` and `EC_ADD` exist only at `2^16` and their suites
   evaluate rows locally instead.
5. `crates/prover/tests/fills.rs`' `the_sha256_fill_covers_its_circuit_and_satisfies_every_gate`
   runs the same pass at the family's real `2^8` over `guests/sha256-ops`' **33** invocations,
   from the prover's own fill — every row and the memory roots the halving phase closes.
6. `crates/emulator/tests/guests.rs` closes it from the other end:
   `sha256_ops_checks_itself_under_the_delegation_ecall` runs the guest, which checks the frame
   ABI against the `"abc"` vector and `guest_sdk::sha256` against published digests at every
   length that moves the padding — each of those also against `sha2`, an unpatched crates.io
   implementation and the only party to the comparison that is not this repository's.
   `the_new_families_are_invoked_the_pinned_number_of_times` pins the 33.

An honest live row, in words:

| column group | value |
| --- | --- |
| `cycle` | the requesting cycle, from the `DelegationTrace` |
| `live` | 1 |
| `base` | the frame pointer, 4-aligned, in `[RAM_ORIGIN, 2^31 − 96]` |
| `anchor_value` | 0 |
| `w{j}_addr` | `base + 4j` |
| `w{j}_read_ts` | the last write to that word, from the log |
| `w{j}_read_value` | words 0–7 the chaining state, words 8–23 the block's sixteen |
| `w{j}_write_value` | words 0–7 the compressed state, words 8–23 the block unchanged |
| `in{j}_bit{t}`, `out{j}_bit{t}` | the bits of those read and written words |
| `w{i}_bit{t}`, `cw{i}_{t}` | the 48 derived schedule words and their 2-bit carries |
| `a{i}_bit{t}`, `e{i}_bit{t}` | `A_1..A_64` and `E_1..E_64` |
| `ca{i}_{t}`, `ce{i}_{t}`, `co{j}` | the rounds' two 3-bit carries and the eight output carry bits |
| `gap{j}_{i}` | the 38 bits of `4·cycle − w{j}_read_ts − 1` |
| `base_low{i}`, `base_room{i}` | the 29 bits of `(base − RAM_ORIGIN)/4` and the 31 of `2^31 − 96 − base` |

and a padding row is 0 in every one of them — subject to §19.2's last paragraph, which is the
part of this table that is a fact about the fill rather than about the circuit.

### 19.10 What fixes each cell

| cell | fixed, on a live row, by |
| --- | --- |
| `cycle` | the memory argument (every write leaf's timestamp) and the request's own row, through the anchor's `4·cycle + 3` |
| `live` | `live_boolean`, every leaf's mask, and the 128 round gates through the carried `live` |
| `base` | `base_aligned` and `base_in_window` locally, `addr_w{j}` against the words, and `deleg_addr_rule` on the request's side through the anchor |
| `anchor_value` | **nothing local**: the request's `deleg_write_value` must equal it, and the memory argument is what says so (§21 observation 19) |
| `w{j}_addr` | `addr_w{j}` |
| `w{j}_read_ts` | the memory argument alone; `gap_w{j}` only holds it below this row's own write |
| `w{j}_read_value` | `in{j}_word` against its bits, and the memory argument |
| `w{j}_write_value`, `j < 8` | `out{j}_word` against the out bits, which `output_h{j}` ties to the compression, and the memory argument |
| `w{j}_write_value`, `j ≥ 8` | `writes_back_w{j}` against its read value |
| `in{j}_bit{t}` | `in{j}_bit{t}_boolean`, `in{j}_word`, and — through the carried scalars and bits — the round, schedule and output equations that read it as `A_{−j}`, `E_{4−j}` or `W_{j−8}` |
| `out{j}_bit{t}`, `co{j}` | their booleanity gates, `out{j}_word` and `output_h{j}` |
| `w{i}_bit{t}`, `cw{i}_{t}` | their booleanity gates and `schedule_w{i}`, which is the only thing that says `W_i` is the schedule's and not a number of the prover's choosing |
| `a{i}_bit{t}`, `ca{i}_{t}` | their booleanity gates and `round_a{i−1}`; and every later round, `Sigma0`, `Maj` and `output_h` that reads `A_i` |
| `e{i}_bit{t}`, `ce{i}_{t}` | their booleanity gates and `round_e{i−1}`; likewise `Sigma1`, `Ch` and `output_h` |
| `gap{j}_{i}` | `gap{j}_{i}_boolean` and `gap_w{j}` |
| `base_low{i}`, `base_room{i}` | their booleanity gates and `base_aligned` / `base_in_window` |
| the padding row | `check_padding`'s all-zero row, the five `live`-gated gates that go vacuous there, and the ungated equations that pin the rest of it to a `K`-free compression (§19.2) |

The nine negative controls in `crates/checker/tests/sha256.rs` are that table read backwards,
each naming the gate that must catch it: a wrong output word (`out*`/`write*`), a wrong `A_1`
(`round_a0`), a wrong `E_1` (`round_e0`), a wrong `W_16` (`schedule_w16`), **the last** round and
**the last** schedule word (`round_a63`, `round_e63`, `schedule_w63` — where an off-by-one in a
loop bound shows, and the first of a sequence never would), a wrong round carry (`round_a0`), a
bit that is not a bit (a `*_boolean`), a frame word out of step with its bits (`in{j}_word`) and
a block word rewritten on the way out (`writes_back_w{j}`).

**There is deliberately no anchor twin for this family.** The anchor is one mechanism, built by
`constraints::delegation` identically for all six families and already proved refused at block
level over four of them in `crates/checker/tests/tamper.rs` — including `MOD_MUL`, which also
carries a lookup channel, so even that combination is not new here. A fifth replay would be the
same mutation set at another re-proof in the slowest deferred suite, which is the cost the root
`CLAUDE.md`'s test rule exists to refuse.

---

---

## 20. `EC_ADD` — family 17

### 20.1 Header

`family_circuit(17, n)` is `ec_add::artifact(n)` with `ec_add::channels()`, which is **one
`RANGE16` channel** — the first a delegation family has ever carried
(`delegation.md` §10.3). Like `MOD_MUL` and `FR_ARITH` it is built by `memory::assemble`:
every constraint it makes fits as an enforcing gate on gate list 0, so above the leaves it is
two product trees and one fraction tree and nothing else. Normative spec: `delegation.md`
§4, §5 and **§16**. Fill: `prover::family_fill(17)`, the private `fill::ec_add`. Ecall
`0x0506`, anchor space `address_space::DELEGATION_EC_ADD` = 9.

**1,420 committed columns (392 `M`, 1,028 `W`, no `S`) and one virtual table, `V[range16]`.**
Gate list 0 writes 4,352 columns — 128 leaves a side of the two memory trees plus the
`RANGE16` tree's 2,048 fraction pairs — and holds **637 enforcing gates (131 degree-1, 506
degree-2)**. **1,110 obligations**, all `RANGE16`, 4 outputs. At its `n = 16` there are 28
gate lists (12 row-wise and 16 halving), the top is `L28`, and the circuit has 8,772 inner
columns and 9,409 relations, 2,350,670 bytes of wire form —
`crates/constraints/tests/vectors/ec_add.txt`, which is the SHA-256 and shape line CI diffs,
the artifact itself being 2.4 MB. **None of the counts before that sentence depends on `n`**
except the inner and relation totals, which are `8,708 + 4n` and `9,345 + 4n`: a height adds
halving lists and nothing else, one node per output each
(`crates/checker/tests/ec_add.rs`' `a_height_moves_only_the_halving_layers`).

`artifact` panics unless the column counts are `MEMORY_COLUMNS` and `WITNESS_COLUMNS`, there
is no setup column, `channels()` is exactly one, the obligation count is `lookups()`' own, no
group writes the selector word, and each group's three output words are eight-word runs that
do not overlap (`ec_add::check_shape`). It also panics on every refusal of `validate`, of
`memory::check_memory`, of `lookup::check_discharge` and of `lookup::check_copowers`, and on
either of the two derivations below failing.

**Two derivations run before the artifact is built, and they read one table.** `CEILINGS`
gives each of the nine slots' four operand ceilings as multiples of `m`;
`the_offset_covers_every_slot` requires `OFFSET_MULTIPLE` to cover the largest `a·b + c·d`,
and `the_carry_offset_covers_every_slot` recomputes the carry's fixed point from the same
row. **They were two separate arguments until S26c derived only the second and shipped an
offset the first refutes** (§20.4).

**One row is one third of one complete point addition**, on one of two curves — secp256k1 or
BN254 G1 — that frame word 0 selects together with the group. `GROUPS` is 3, so one addition
is three invocations in ascending group order, glued by the frame and not by a bus
(`delegation.md` §16.2).

**The height is `2^16`, and it is forced rather than chosen.** `RANGE16`'s table needs sixteen
variables, Mercury needs an even count, and `2^18` is four times worse; `family_circuit`'s
derived minimum-height guard returns `None` below 16 (`it_is_the_one_delegation_family_with_a_channel`).
One shard is a computed **20.5 GB** — **18.3 GB** of forward pass (the twelve row-wise
layers' 8,708 columns at `2^16` rows and 32 bytes; the sixteen halving layers add 8.4 MB
between them), **0.7 GB** of committed base (1,255 small-type columns at 4 bytes and 165 `Fr`
ones at 32), and **1.5 GB** of transition 0's first bind, a half-height `Fr` table over 1,420
columns. That is above an execution shard's ~11 GB and above `MOD_MUL`'s 5.1 GB at the same
height, but below `KECCAK_F`'s ~60 GB at its `2^18` (§12.1), so **this is the second-largest
delegation shard peak in a block** and no longer the peak-setting one; the lever that remains is the
group count, five groups of two reductions being about two-thirds the width at two more
invocations an addition. `docs/handoff/S26c-sha256-ec.md` records the deferred run's measured
figure against that estimate.

**This family has no §0.5 row at `n = 20`.** §0.5 counts gate shapes over one circuit at
`n = 20`, which this family is never built at in practice; the rows below give its shape
counts at its own `n = 16` instead, and they sum to 9,409.

### 20.2 Row kinds

Two, and neither is an instruction: **this family is invoked, not decoded**. It claims no pc,
`program::lookup_tuple(17)` is empty, and it is in a `VmConfig` exactly when the linked binary
declares it. It is not in `constants::family::CYCLE_OWNING`.

| row kind | `live` | what the row holds | what it adds to the multiset |
| --- | --- | --- | --- |
| an **invocation** | 1 | the requesting cycle, the frame base, the 97 words read and written, the six selectors and the curve constants they name, the twelve frame values' `< m` chains, and three slots' operands, quotients, results, carries and result chains | 98 read tuples and 98 write tuples: the 97 frame words at `(RAM, base + 4j)`, and the anchor pair at `(DELEGATION_EC_ADD, base)` |
| **padding** | 0 | every committed cell 0 **as the honest fill writes it** | nothing: all 196 real leaves collapse to 1, and 60 are pads that are literally 1 |

Three things hold the all-zero row and are worth spelling out. `one_code_a_live_row` forces
every selector to 0 there, so `m_limb{k}_rule` and `b3_rule` force the modulus limbs and `b3`
to 0 — which is what lets the fifteen chains' `canonical` gates be **ungated** and still hold.
Every operand pin then reads `operand = 0`, because every product in it carries a selector.
And `carry_terms` puts `live` on the offset, so a padding row's carry is
`Σ carry{r}_{c} − 2^46·0`, not `−2^46`.

**The padding row is all-zero because the fill writes it so, not because the gates force it.**
With `m = 0` and every selector 0 the limb identity reduces to a relation among `out`, the
carries and nothing else, and every range obligation is switched off by its `live` selector,
so a padding row could legally carry unbounded cells. It is harmless — the row requests
nothing, pairs with no anchor, writes no register, and its leaves are the product's identity —
but a test asserting "a padding row's columns are zero" is asserting a property of the fill.
`a_padding_row_holds_and_a_live_one_next_to_it_does_too` asserts the direction that matters:
the all-zero row satisfies every gate of a circuit whose identity carries a `1024·m²` offset
and whose carries carry a `2^46` one.

### 20.3 The base layer

**Too wide to enumerate one column a row**, as §12's is: a live row is 1,420 committed cells.
What follows is every address *group*, which is how the circuit itself names them — a fill, a
checker and a tamper twin reach a column through `ec_add::word`, `gap_chunk`, `word_high`,
`selector`, `m_limb`, `b3`, `bzz3_limb`, `byz3_limb`, `bxx9_limb`, `diff`, `diff_hi`,
`borrow`, `operand`, `out_limb`, `out_hi`, `q_limb`, `q_hi`, `carry`, `carry_chunk`,
`out_diff`, `out_diff_hi`, `out_borrow` and `multiplicity_column`, and never through a number.

**Memory-argument columns, `M[0..392]`** — filled by `fill::ec_add` from the archive's
delegation buffer; committed in `PublicInputs::memory_commitments`, absorbed at G8 before the
memory challenges.

| address | name | what it is |
| --- | --- | --- |
| `M[0..4]` | `cycle`, `live`, `base`, `anchor_value` | as §18.3 and §12.3: the requesting cycle, the row's one mask, the `a0` the request passed, and the teardown's value, which is **free on both sides** |
| `M[4 + 4j + f]` | `w{j}_addr`, `w{j}_read_ts`, `w{j}_read_value`, `w{j}_write_value` | frame word `j`, `j < 97`. Word 0 is the selector, 1–8 `X1`, 9–16 `Y1`, 17–24 `Z1`, 25–48 `X2`/`Y2`/`Z2`, 49–72 `xx`/`yy`/`zz`, 73–96 `m4`/`m5`/`m6`, eight little-endian 32-bit limbs a value (`constants::ec_add`'s `*_WORD`) |

**Group 2 writes its results over `X1`, `Y1` and `Z1`**, which groups 0 and 1 have by then
finished reading. That is what keeps the frame at 97 words rather than 121, and it is why
`EcAddFrame::result` reads the first three lanes.

**Witness columns, `W[0..1028]`** — all filled by `fill::ec_add` except the last; committed in
`ShardProof::witness_commitments`, absorbed at S3, with `g` drawn after them at S4.

| address | name | what it is |
| --- | --- | --- |
| `W[2j + c]`, `j < 97` | `gap{j}_c{c}` | chunk `c` of frame word `j`'s timestamp gap, weight `2^{16(c+1)}`; the low sixteen bits are **derived**, not committed. 194 columns |
| `W[194..198]` | `base_low`, `base_low_hi`, `base_room`, `base_room_hi` | `(base − RAM_ORIGIN)/4` and `2^31 − 388 − base`, each with its high halfword |
| `W[198 + j]` | `word{j}_hi` | frame word `j`'s read value's high halfword — its 32-bit bound, and **every** word has one, the selector included |
| `W[295..301]` | `selector{code}` | the six (curve, group) selectors, in `ec_add::CODES` order: codes 1, 2, 3 secp256k1's three groups, 4, 5, 6 BN254 G1's |
| `W[301..309]` | `m_limb{k}` | limb `k` of the selected curve's modulus — a witness column, and the only place `m` exists |
| `W[309]` | `b3` | the selected curve's `b3 = 3b`: 21 for secp256k1's `b = 7`, 9 for BN254's `b = 3`. The curve's `a` is 0 on both and never appears |
| `W[310..334]` | `bzz3_{k}`, `byz3_{k}`, `bxx9_{k}` | the three curve-scaled helpers, eight limbs each |
| `W[334 + 24v + …]` | `{name}_diff{i}`, `{name}_diff{i}_hi`, `{name}_borrow{i}` | frame value `v`'s `< m` chain, `v < 12` in `VALUES` order — `x1`, `y1`, `z1`, `x2`, `y2`, `z2`, `xx`, `yy`, `zz`, `m4`, `m5`, `m6`. 288 columns |
| `W[622 + 135r + …]` | `slot{r}_{a,b,c,d}{k}` | slot `r`'s four operands, eight limbs each, `r < 3`: 32 columns |
| … `+32`, `+40` | `out{r}_{k}`, `out{r}_{k}_hi` | the slot's reduced result and its halfwords |
| … `+48`, `+57` | `q{r}_{i}`, `q{r}_{i}_hi` | the **nine**-limb quotient and its halfwords — the one value in the row the execution did not record |
| … `+66`, `+81` | `carry{r}_{c}`, `carry{r}_{c}_c{j}` | the fifteen signed carries as unsigned `c + 2^46`, and two `RANGE16` chunks each |
| … `+111` | `out{r}_diff{i}`, `out{r}_diff{i}_hi`, `out{r}_borrow{i}` | the result's own `< m` chain |
| `W[1027]` | `range16_multiplicity` | the channel's one multiplicity column, **last in the witness subtree**, filled by `trace::build_multiplicities` after the fill and read by no gate |

**The three helpers are pinned limb-wise, and this is easy to misread.** `bzz3_{k}` is
`b3 · zz_k` — the product of a column and one limb, not a limb of a reduced value. So the
three are **loose limb vectors**: `|bzz3_k| < 21·2^32`, `byz3` is signed, and none of them is
below `m` or below `2^32`. They exist because `b3` is a column, so `b3` times a frame limb
inside a product's operand would be degree 3. The fill commits them as `Fr` columns for that
reason, and `fill::ec_add`'s comment says so.

**Where each value reads from.** Every operand limb is a frame word's `read_value`; every
result limb is the `write_value` of the word the group writes. That is the whole of what makes
the call a function: the guest's frame is what it *passed*, and the results are what the
invocation *wrote*.

### 20.4 The gates

| group | count | degree | what it says |
| --- | --- | --- | --- |
| `live_boolean` | 1 | 2 | §4's, shared with the other five delegation families |
| `addr_w{j}` | 97 | 2 | word `j` is at `base + 4j`. Degree 2 because it carries `live` as a factor — on a padding row `addr` and `base` are 0 and `4j` is not |
| `base_aligned`, `base_in_window` | 2 | 2 | `base = RAM_ORIGIN + 4·base_low`, and `base + 388 ≤ 2^31` through `base_room`. **There is no `gap_w{j}` gate**: the gap's obligations are the bound and the decomposition at once (§20.5) |
| `selector{code}_boolean` | 6 | 2 | each of the six selectors is a bit |
| `selector_rule` | 1 | 1 | `w0_read_value = Σ code_i·s_i` |
| `one_code_a_live_row` | 1 | 1 | `Σ s_i = live` |
| `m_limb{k}_rule` | 8 | 1 | `m_k = Σ CURVE_MODULI[CODE_CURVE[i]][k]·s_i`, the two curves' literals |
| `b3_rule` | 1 | 1 | `b3 = Σ CURVE_B3[CODE_CURVE[i]]·s_i` |
| `bzz3_{k}_rule`, `byz3_{k}_rule`, `bxx9_{k}_rule` | 24 | 2 | `bzz3_k = b3·zz_k`, `byz3_k = b3·(m5_k − yy_k − zz_k)`, `bxx9_k = 3·b3·xx_k` |
| `{v}_borrow{i}_boolean`, `out{r}_borrow{i}_boolean` | 120 | 2 | the fifteen chains' borrow bits |
| `{v}_canonical{i}`, `out{r}_canonical{i}` | 120 | 1 | `v_i − m_i − b_{i−1} + 2^32·b_i = d_i`, **ungated** |
| `{v}_below_modulus`, `out{r}_below_modulus` | 15 | 2 | `enable·(1 − b_7) = 0`: `enable` is the sum of the selectors of the groups that read the value, and `live` for a result |
| `operand{r}_{which}_{k}_rule` | 96 | 2 | the operand column equals `Σ_g g_sel·(group g's expression at limb k)` |
| **`slot{r}_limb{k}`, `k < 16`** | 48 | 2 | the schoolbook identity, position by position |
| `writes_back_w{j}` | 97 | 2 | `write_j − read_j − Σ g_sel·(out[r][k] − read_j) = 0` over the one `(group, slot, limb)` triple that writes word `j`, if any |

**The forty-eight limb equations are the circuit.** With `P_k = Σ_{i+j=k} (A_i B_j + C_i D_j)`,
`O_k = 1024·Σ_{i+j=k} m_i m_j` and `S_k = Σ_{i+j=k} q_i m_j`, gate `slot{r}_limb{k}` is

```text
P_k + O_k − S_k − out_k + c_{k−1} − 2^32·c_k = 0
```

where `out_k` is absent past limb 7, `c_{−1}` is absent, and `c_15` is absent — which is the
closing condition. Weight the sixteen equations by `2^{32k}` and sum: the carries telescope
and what is left is `A·B + C·D + 1024·m² − q·m − out = c_15·2^{480}`, so **the absence of a
sixteenth carry column is the identity**. Each gate is one `Quadratic`: `A_i·B_j`, `C_i·D_j`,
`m_i·m_j` and `q_i·m_j` are all pairs of committed columns, so the degree is 2 and never 3.

**One shape for all nine slots, and `D` carries the sign.** Group 2's slot 0 is
`xy·ym − byz3·xz`, and a per-group sign on a product's coefficient is **not expressible** — a
coefficient is one literal or one challenge — so the minus rides `D`, which is `xx + zz − m6`
where the other two slots' is `m6 − xx − zz`. Groups 0 and 1 leave `C` and `D` empty, so their
second product is zero; the operand pin still exists for those 48 columns and forces them to 0.

**The operands are committed columns pinned to bounded linear combinations, and the pin IS the
bound.** Every term of an operand's sum is a frame limb below `2^32` or a helper limb below
`21·2^32`, under a small literal coefficient, so `operand{r}_{which}_{k}_rule` establishes the
magnitude at the same time as the value and **no operand needs a range check of its own**.
That is what keeps the witness at 1,028 columns: 96 operand limbs bounded by bit decomposition
would be 3,072 columns and 3,072 booleanity gates, and bounded by `RANGE16` would be 96 more
committed halfwords and 192 more obligations in a fraction tree that is already the deepest of
the three (§20.6). `a_wrong_operand_is_refused_by_its_own_pin` is the twin, and it names
`operand0_0_0_rule` and not a product — which is the point.

**Why the equation over `Fr` is the equation over ℤ.** The widest single term of any position
is `2^32·c` with `c` below `2^47`, so under `2^79`; a position has at most 38 terms, so its
sum is under `2^85`, against `p`'s `2^254`. No limb equation can wrap, and there is no
modular-arithmetic loophole to argue about.

**`OFFSET_MULTIPLE` was 256 and is 1024, and the difference is a completeness bug S26c
shipped.** The offset keeps the quotient unsigned: `A·B + C·D` is as low as
`−(a·b + c·d)·m²`, each product minimised with one factor at its positive ceiling and the
other at its negative one. The binding slot is group 2's **`Y3`**, not its `X3`: `yp·ym`
with `yp ≤ 22m` and `ym ≥ −22m` reaches `−484 m²`, and `bxx9·xz` with `bxx9 ≤ 63m` and
`xz ≥ −3m` a further `−189 m²`, for **`−673 m²`**. `X3` reaches `−255 m²` — `66 + 189` —
which is exactly why 256 looked derived and was not. At 256 the honest quotient of a `Y3` row
below `−256 m²` is negative, `q_limb` cannot hold it, and the row is **unprovable**; `zz`
above about `0.76m` is enough on its own, roughly a quarter of random invocations. **Nothing
but an honest witness against the gates can find it**: `emulator::ec_add_frame` computes the
right answer, `guests/ec-ops` agrees with its own software Algorithm 7, every shape test
passes, and only the prover fails — intermittently, hours into a block proof.
`CARRY_OFFSET_BITS` moved with it, 45 → 46, because the same products bound the carry's width:
the widest position is `8·(673 + 1024)·2^64 ≈ 2^78` and the carry's fixed point `2^46`. It
read 44 when the offset was guessed, 45 when the positions were derived, and 46 once the
offset had to cover `−673 m²`. Both are now computed from `CEILINGS` at construction, and
`the_carry_offset_covers_every_slot_is_computed` runs the second as a test besides.

**`below_modulus` said `b_7 = enable` and means `enable·(1 − b_7) = 0`, and the first made
every row of the family unprovable.** The chain telescopes to `v − m + 2^256·b_7 = D` with `D`
below `2^256`, so `b_7 = 1` says the subtraction borrowed out and `v < m`. `b_7 = enable`
also forces `b_7 = 0` where `enable` is 0 — which asserts that a value a row does *not* read
is at or above the modulus. Every lane is such a value: `EcAddFrame::of` zeroes the six
intermediates, and a group-2 row's `X1..Z2` are ordinary coordinates. **The chain's sixteen
`canonical` gates are ungated**, so a non-reading value still owes a real chain, and the
prover's fill — written to match the wrong gate — filled those chains with zeros, which
satisfy the canonical gates only where `v = m`. Nothing in the executor, the guests or the
shape tests could see either half. What found it is an honest witness evaluated against the
gates: `crates/checker/tests/ec_add.rs` for the circuit and
`crates/prover/tests/fills.rs`' `every_delegation_fill_satisfies_every_gate` for the fill,
which exists for this reason and says so in its doc comment.

**Which chain is soundness and which is totality.** A slot's `out < m` is the **reduction**:
without it a prover answers `out + m` with the quotient one lower and every limb equation
holds over the integers just as well. A frame value's `< m` is **totality** — it is what
bounds the honest quotient below nine limbs, so every frame the circuit accepts is one an
honest prover can fill. `emulator::ec_add_frame` refuses an unreduced operand earlier and by
name, six messages keyed to the group's reads, and a selector naming no (curve, group) pair
before that.

**Why one modulus a live row is load-bearing twice.** It is the one-hotness that makes the six
selectors a partition, and with codes 1–6 `selector_rule` cannot see a two-selector forgery:
`1 + 3 = 4`, so a row claiming secp256k1's groups 0 and 2 spells BN254's group 0's word. It is
also the **only** thing bounding `m`'s limbs and `b3` below `2^32`, neither having a bit
decomposition: two selectors at once would give `m_0` above `2^32` and put the integer
argument above out of reach. `two_selectors_at_once_are_refused` is the twin.

### 20.5 The lookups and the channel

One channel, `RANGE16` = channel 1, table `V[range16]`, multiplicity `W[1027]`. The tuple is
**one** expression wide, so it weights its column by the literal 1 and reads `g` and no power
of `β` at all. Every obligation's selector is `LIVE`.

| obligation | count | selector | tuple | shape |
| --- | --- | --- | --- | --- |
| `gap{j}_c0_range`, `gap{j}_c1_range` | 194 | `live` | `gap{j}_c{c}` | direct: each chunk below `2^16` |
| `gap{j}_top_scaled` | 97 | `live` | `2^10 · gap{j}_c1` | scaled: the top chunk below `2^6` |
| `gap{j}_lo_range` | 97 | `live` | `4·cycle − w{j}_read_ts − 1 − 2^16·c0 − 2^32·c1` | the derived low sixteen bits |
| `base_low_c0_range`, `base_low_top_scaled`, `base_low_lo_range` | 3 | `live` | `base_low_hi`, `2^3·base_low_hi`, `base_low − 2^16·base_low_hi` | `[0, 2^29)` |
| `base_room_c0_range`, `base_room_top_scaled`, `base_room_lo_range` | 3 | `live` | as above at `2^31` | `[0, 2^31)` |
| `word{j}_hi_range`, `word{j}_lo_range` | 194 | `live` | `word{j}_hi`, `w{j}_read_value − 2^16·word{j}_hi` | every frame word below `2^32` |
| `{v}_diff{i}_hi_range`, `{v}_diff{i}_lo_range` | 192 | `live` | 16+16 over `diff(v, i)` | the twelve chains' difference limbs |
| `out{r}_{k}_hi_range`, `out{r}_{k}_lo_range` | 48 | `live` | 16+16 over `out_limb(r, k)` | each result limb below `2^32` |
| `out{r}_diff{k}_hi_range`, `out{r}_diff{k}_lo_range` | 48 | `live` | 16+16 over `out_diff(r, k)` | the three result chains |
| `q{r}_{i}_hi_range`, `q{r}_{i}_lo_range` | 54 | `live` | 16+16 over `q_limb(r, i)` | nine quotient limbs a slot |
| `carry{r}_{c}_c0_range`, `_c1_range`, `_top_scaled`, `_lo_range` | 180 | `live` | two chunks, `2·carry{r}_{c}_c1`, and the derived low half | each carry's unsigned value below `2^47` |

**1,110 obligations.** The 38-bit timestamp gap is three chunks and not a `TIMESTAMP`
obligation, because that channel's `BITS` is 19 and its table needs `2^20` rows, which no
delegation height offers (`delegation.md` §9, §10.3). `TIMESTAMP` would be the natural
channel and does not fit; `RANGE16` at three chunks a gap is exact at `2^38`, the maximum
being `(2^16 − 1)(1 + 2^16) + 2^32(2^6 − 1) = 2^38 − 1`.

**A 16+16 pair is one committed column and two obligations, and that is the whole reason the
channel is worth carrying.** A 32-bit bound by bit decomposition is 32 columns and 32
booleanity gates; a 38-bit gap is 38. Without the channel this family's frame alone is 3,686
gap-bit columns against 194 chunk columns, and 24 more 32-bit values want bounding besides.

**The scaled obligation alone bounds nothing**, and `lookup::check_copowers` is what says so:
`2^{16−r}` is a unit in `Fr`, so an unbounded value sweeps a coset almost none of whose
members is small. It is the top chunk's own **direct** obligation under the **same** selector
that establishes the premise — S18's fix, and `ec_add::scaled_columns` lists all 144 scaled
columns with `LIVE` beside each: the 97 gap tops, `base_low_hi`, `base_room_hi`, and the 45
carry tops.

**One multiplicity column, and no gate reads it.** `trace::build_multiplicities` counts each
`RANGE16` table row's occurrences over the 1,110 gated tuples of every live row and appends
the column after the fill; `prover::fill::ec_add` does not write it, which is why
`crates/prover/tests/fills.rs` passes `WITNESS_COLUMNS − channels().len()` to `covers`. It has
to exist because `artifact.committed()` names it.

### 20.6 The trees, the inner layers and the outputs

Three trees. The two memory product trees take `d::leaves(DELEGATION_EC_ADD, 97)`: 97 frame
words plus one anchor leaf a side, **98 real leaves padded to 128**, so each side carries 30
`read_pad{i}` / `write_pad{i}` leaves that are literally 1. The read side's leaves consume the
write each frame word names, then the anchor **teardown**
`T(space, base, 4·cycle + 3, anchor_value)`; the write side's write at `4·cycle + 0`, then the
anchor **answer** `T(space, base, 0, 0)`, stamped 0 and valued 0. The `RANGE16` fraction tree
takes 1,110 obligations plus its table fraction, **1,111 leaves padded to 2,048**, so 937 pad
fractions. `R = 11`, the fraction tree setting it alone, and the depth is `N = 1 + 11 + n`.

Layer `L1` is 4,352 wide: `read_1_*` 0–127, `write_1_*` 128–255, then the fraction tree's
2,048 `(num, den)` pairs at 256–4,351, the table's first and the 937 pads last. Widths:

```text
L1     4,352      L5       272      L9       18      L13 … L{n+12}    4 each
L2     2,176      L6       136      L10      10
L3     1,088      L7        68      L11       6
L4       544      L8        34      L12       4
```

so `inner = 8,708 + 4n` — 8,772 at `n = 16`. The two product trees reach one node at `L8` and
are carried as `Linear` copies through `L9`–`L12`; the fraction tree reaches one pair at `L12`.

Relations: **0–4,351** are list 0's leaves, **4,352–4,988** its 637 enforcing gates in
`artifact`'s own order — 4,352 `live_boolean`, 4,353–4,449 `addr_w0`…`addr_w96`, 4,450
`base_aligned`, 4,451 `base_in_window`, 4,452–4,468 the selector block, 4,469–4,492 the
helpers interleaved by limb, 4,493–4,747 the fifteen chains at 17 relations each in `VALUES`
order then `out0`, `out1`, `out2`, 4,748–4,843 the operand pins, 4,844–4,891 the forty-eight
limb equations, 4,892–4,988 the write-backs. Then **4,989–7,164** list 1, **7,165–8,252** list
2, **8,253–8,796** list 3, **8,797–9,068** list 4, **9,069–9,204** list 5, **9,205–9,272**
list 6, **9,273–9,306** list 7, **9,307–9,324** list 8, **9,325–9,334** list 9,
**9,335–9,340** list 10, **9,341–9,344** list 11, and halving list `k`
(`12 ≤ k ≤ n + 11`) holds `9,345 + 4(k − 12)` to `9,348 + 4(k − 12)`. The roots are relations
`9,341 + 4n` to `9,344 + 4n`: **9,405–9,408** at `n = 16`.

Each halving list is four gates: `read_root`-side and `write_root`-side `TreeProduct`s, the
channel's denominator `TreeProduct`, and its numerator `TreeCross`.

**The outputs**, in output-map order: 0 `read_root` and 1 `write_root` at `memory::READ_ROOT`
and `WRITE_ROOT`, read at `verify_shard` step 10a against `memory_roots[p]` for `p` the
position of `(17, shard_index)` in `verifier_core::statement_shards` — **last** in every
statement it appears in, family ids being the statement's order; 2 `range16_num_root` and 3
`range16_den_root`, read at step 9, the failure `Lookup { channel: 1 }` and the check **both**
`num == 0` and `den != 0`.

### 20.7 Witness rows

**There is no row table here and there cannot usefully be one**: a live row is 1,420 committed
cells, 1,110 of which exist only to be range-checked. What stands in its place is a chain of
four independent readings, and the chain is what §12.9's is for `KECCAK_F`.

1. **`crates/checker/tests/ec_add.rs`** builds honest rows of the real `2^16` circuit and
   evaluates each **row-locally** through `checker::violated_relations` over scratch that
   `gkr::gate_values` computes — a whole-shard forward pass being impossible at a family whose
   circuit exists only at `2^16`. Its **operand structure** is transcribed (a witness builder
   has to know what the circuit expects in a committed operand column) but its **answer** is
   not: `expected` computes each group's three results from Algorithm 7 over ordinary 256-bit
   modular arithmetic — schoolbook multiplication, shift-and-subtract division — sharing no
   line with the emulator or the fill, and `the_reductions_are_the_group_law` holds the `out`
   that falls out of the limb identity's long division equal to it, slot for slot.
   `the_three_invocations_are_one_addition` then runs Algorithm 7 end to end in one expression
   and holds the third row's results to it, which is the check that **the split into three
   invocations is the same function as the whole**.
2. **`crates/prover/tests/fills.rs`** holds the real fill to the same gates:
   `the_mod_mul_and_ec_add_fills_cover_their_circuits_exactly` is set equality over addresses,
   and `every_delegation_fill_satisfies_every_gate` evaluates the first 32 and last 4 rows of a
   filled shard — which is what caught the `below_modulus` fill bug (§20.4).
3. **`crates/emulator/tests/guests.rs`**: `guests/ec-ops` checks every delegated addition
   against its own Algorithm 7 over its own long division, limb for limb, and the resulting
   point against `k256` and `ark-bn254` by cross-multiplication, including `P + P`, `P + O`,
   `O + O` and `P + (−P)`; it exits 20, and a disagreement between its two implementations
   exits 251. `the_new_families_are_invoked_the_pinned_number_of_times` pins **81**
   invocations for `ec-ops` (27 point operations, three groups each) and **39** for
   `mod-mul-ops`, which names no shim and reaches the family through the vendored `k256`
   alone — which is what makes that second count the projective patch's only test.
4. **`crates/checker/tests/ec_add.rs`' fifteen negative controls**, each corrupting one cell of
   an otherwise honest witness or supplying an honest witness for a claim the circuit must
   refuse, and naming the relation that catches it.

An honest live row, in words:

| column group | value |
| --- | --- |
| `cycle`, `live`, `base`, `anchor_value` | the requesting cycle; 1; the frame pointer, 4-aligned, in `[RAM_ORIGIN, 2^31 − 388]`; 0 |
| `w{j}_addr`, `w{j}_read_ts` | `base + 4j`, and the last write to that word from the log |
| `w{j}_read_value`, `w{j}_write_value` | the 97 words before and after the group |
| `gap{j}_c{c}` | bits `[16(c+1), 16(c+2))` of `4·cycle − w{j}_read_ts − 1` |
| `base_low`, `base_room`, and their halfwords | `(base − RAM_ORIGIN)/4` and `2^31 − 388 − base` |
| `word{j}_hi` | `w{j}_read_value >> 16` |
| `selector{code}` | 1 on the frame's code, 0 on the other five |
| `m_limb{k}`, `b3` | the selected curve's modulus limbs and `3b` |
| `bzz3_{k}`, `byz3_{k}`, `bxx9_{k}` | `b3·zz_k`, `b3·(m5_k − yy_k − zz_k)`, `3·b3·xx_k` — **signed and loose** |
| `{v}_diff{i}`, `{v}_borrow{i}` | the honest chain of `v − m`, computed for **all twelve values on every row** |
| `slot{r}_{a,b,c,d}{k}` | the group's expression at limb `k`, signed and loose |
| `out{r}_{k}`, `q{r}_{i}`, `carry{r}_{c}` | the reduction, its nine-limb quotient, and `carry + 2^46` |
| `out{r}_diff{i}`, `out{r}_borrow{i}` | the result's own chain |
| `range16_multiplicity` | `trace`'s count; 0 on a row the table does not hold |

and a padding row is 0 in every one of them. The suite's honest set is **seven live rows and
one padding row**: both curves' three groups over one random point pair each — where each
group's written frame is the next group's read frame, so the three rows of a curve are one
real addition and not three unrelated frames — plus a seventh at the **widest** operands group
2 admits, secp256k1's group 2 with every intermediate at `m − 1`, which is the row the carry
bound is sized for and which a bound off by one bit refuses.

### 20.8 What fixes each cell

| cell | what fixes it |
| --- | --- |
| `cycle`, `base` | the multiset: the request's mirror write is `T(DELEGATION_EC_ADD, base, 4·cycle + 3, v)` and this row's teardown read is its only reader (§5's anchor); locally `base_aligned` and `base_in_window`, and `addr_w{j}` against the words |
| `live` | `live_boolean`, and every leaf's mask |
| `anchor_value` | **nothing local**: the request's `deleg_write_value` must equal it, and the memory argument is what says so |
| `w{j}_read_ts` | the memory argument alone; `gap{j}_*` only holds it below this row's own write |
| word 0's value | the frame's read tuple, `writes_back_w0`, and `selector_rule` against the six selectors |
| `selector{code}` | its booleanity gate, `selector_rule` and `one_code_a_live_row` — the three together are exactly "one of the six codes, the one the frame names" |
| `m_limb{k}`, `b3` | `m_limb{k}_rule` and `b3_rule`: a literal of `CURVE_MODULI` and of `CURVE_B3`, chosen by the selector, which is also their `2^32` bound |
| the twelve values' words | the frame's read tuples, `writes_back_w{j}`, their own `word{j}` obligations, and their `< m` chains where the row's group reads them |
| every `w{j}_write_value` | `writes_back_w{j}`: the result of the one slot that writes word `j`, bounded by that slot's `out{r}_{k}` obligations, or the read value, bounded by `word{j}` |
| `bzz3_{k}`, `byz3_{k}`, `bxx9_{k}` | their degree-2 pins, which are also their bounds |
| `slot{r}_{a,b,c,d}{k}` | `operand{r}_{which}_{k}_rule` alone — the pin is the bound, and no obligation reads an operand |
| `out{r}_{k}` | `slot{r}_limb{k}` and `out{r}`'s chain: given `m`, the operands and the bounds, integer division has one answer |
| `q{r}_{i}` | `slot{r}_limb{k}`: sixteen equations in nine unknowns over the integers, whose solution is unique once `out < m` |
| `carry{r}_{c}` | `slot{r}_limb{k}` and `slot{r}_limb{k+1}`, which the carry joins, and its four obligations |
| every `_diff`, `_borrow` | the chain's `canonical{i}` gates, the borrows' booleanity, and the `diff` obligations; the last borrow by `below_modulus` where a group reads the value |
| `range16_multiplicity` | `trace::build_multiplicities`, and the channel's own root check — no gate reads it |
| the padding row | `check_padding`'s all-zero row and §20.2's gates that hold there, subject to §20.2's last paragraph |

The fifteen negative controls read that table backwards, and four are worth knowing about.
`a_wrong_result_limb_is_refused` names `out0_canonical0` rather than `slot0_limb0` because
**two** gates see a result limb and the chain comes first in relation order — that the identity
also catches it is what `a_wrong_quotient_limb_is_refused` shows, the quotient being a value
only the identity reads. `a_wrong_curve_constant_is_refused` swaps `b3 = 21` for `9`, which is
a correct addition **on the wrong curve** and which nothing else in the row would notice.
`an_unreduced_frame_value_is_refused_on_the_group_that_reads_it` clears `x1`'s last borrow on a
group-0 row, and has to be a group-0 or group-1 row, the conclusion being gated.
`a_frame_word_above_its_bound_is_refused_by_the_channel_alone` is the one place the two kinds
of refusal are told apart: a 32-bit bound is an obligation and not a relation, so
`violated_relations` must name no `*_range` and `violated_lookups` must name the word.

**No anchor twin is called for this family, deliberately.** `checker::assert_anchor_twins_refused`
is `constraints::delegation`'s one mechanism, built identically for all six families and
already proved refused at block level over four of them in `crates/checker/tests/tamper.rs` —
`MOD_MUL` included, which also carries a lookup channel, so even that combination is not new.
A fifth replay would be the same mutation set at another re-proof in the slowest deferred
suite, which the root `CLAUDE.md`'s test rule exists to refuse.

---

---

## 21. Observations

Facts this accounting turned up. None changes a circuit.

1. **The registry and the height menu disagree both ways.** `family_circuit` builds
   all **seven** registered execution circuits at every `n` from 19 to 30, and the **five**
   window circuits and the six delegation circuits at every `n` from 0 to 30. A key's heights
   come from `VmConfig`, which `VmConfig::from_bytes` holds to `HEIGHT_MENU` (`n` = **8**, 16,
   18, 20, 22 since S21, and **12** since S-STREAM).
   So the seven execution circuits are reachable only at 20 and 22, which is `shard-proof.md` §8's,
   `jump-branch-slt.md` §2's, `shift-bitwise.md` §2's, `mul-div.md` §2's and `memory-ops.md`
   §7.1's `trace_vars ≥ 20`: the timestamp channel's 19 variables, made even for Mercury.
   `INIT_TEARDOWN` and `ZERO_WINDOWS` are reachable only at 16, 18, 20 and 22, never at
   `n ≤ 14`, where `V[ram_live]` is 0 on every row and `INIT_TEARDOWN` would mask its whole
   window — and since S-IO `verifier_core::window_height` refuses a window height below `2^16`
   for a second reason, that both public windows must lie inside RAM window 0;
   `ADVICE_WINDOWS` shares that height. **S-STREAM's `2^12` does not widen that**, which is
   worth checking rather than assuming, because growing the public windows is exactly the
   change that could have moved the floor: `window_height` requires
   `4h ≥ PUBLIC_OUTPUT_ORIGIN + PUBLIC_WINDOW_BYTES`, whose right-hand side went from `0x8800`
   to `0x10000`, so the rule went from `h ≥ 8,704` to `h ≥ 2^14` — and the smallest menu entry
   above either is the same `2^16`. **`PUBLIC_INPUT` and `PUBLIC_OUTPUT` are the opposite
   case**: reachable over the whole 0–30 range, like a delegation family and for the same
   reason — no channel, so no `BITS ≤ trace_vars` guard — but derivable at `2^12` and nowhere
   else, because the height is what places their windows (§15.1). Conversely, no execution
   circuit exists at the menu's 16 and 18, so a `VmConfig` placing one there decodes but no key
   for it loads (`VerifyingKey::check`) — and since S19 the `trace_vars < 19 ⇒ None` arm names
   all seven, so such a key is a clean `Err` and not a panic inside `lookup::channel_trees`,
   in the `no_std` crate the recursion guest links (`memory-ops.md` §7.2). **`MUL_DIV`'s and
   `ATOMICS`' default heights are `2^20`, not `2^22`** (`constants::family::DEFAULT_HEIGHTS`),
   the two execution families whose default is not the maximum; `ATOMICS`' was `2^16` until
   S19, which is the stage that gave it a circuit and so the stage that had to raise it.
   **`POSEIDON2`, `FR_ARITH` and `SHA256_COMP` are the other way round**: each is *reachable*
   over the whole 0–30 range, because a family with no channel meets no `BITS ≤ trace_vars`
   assertion, and each is reachable at the menu's 8, 12, 16, 18, 20 and 22 with nothing
   deriving a height for it but `2^8`. The 12 is S-STREAM's, and these three are the only
   families it widened anything for: a key may declare it, nothing derives it, and it bought
   them nothing. **`KECCAK_F` was among them until S26d** and is now `16 ≤ n ≤ 30`
   like `MOD_MUL` and `EC_ADD`, both of its channels' tables needing 16 variables (§12.1). That
   the menu's `2^8` entry is an *even* power is not a coincidence a stage may spend: Mercury
   needs `n` even for `b = sqrt(2^n)` to exist, so the menu below `2^16` had exactly `2^8`,
   `2^10`, `2^12` and `2^14` to choose from — and S-STREAM spent a second of the four, on the
   two public families and on nothing else.
2. **No registered family carries an inert column any more, and add/sub was the last.**
   Eighteen of its `M` and `W` columns used to be: the `arg1`, `arg2` and `ram` queries were
   held absent on every row by three `mask = 0` gates, yet `frame_queries` fixed the frame, so
   they were committed, opened and carried by every shard. They were the I/O-binding stage's,
   and what that stage did with them was **delete them** — `read` and `write` are retired, the
   two ecall-argument roles left the query table with them, and the `ram` query, which was the
   transfer row's alone, went when the transfer row did (`ecall-abi.md` §4). The frame is five
   queries, and every one of them some row of the family makes. Every other family was already
   clean: the three four-query frames — jump/branch/slt's, shift/bitwise's and mul/div's — are
   the same 21 `M` columns and the same bare frame artifact, `memory_frame_reg.bin` (§2.2); the
   two six-query frames, mem_word's and mem_subword's, share `memory_frame_mem.bin`, and every
   one of their six queries is used by some kind — a load's `load` and `rd`, a store's `rs2` and
   `ram`; and atomics' five-query frame, `memory_frame_atomics.bin`, has `rs2` used by ten kinds
   of eleven. **The three gates went with the columns**, and that is the part worth keeping:
   `arg1_mask_rule`, `arg2_mask_rule` and `ram_mask_rule` each refused something the family
   could not represent once the query was gone, so deleting the query deleted the gate's whole
   subject matter.
3. **`rd_is_zero_boolean` (relation 77 in §3, 92 in §4, 132 in §5, 124 in §6, 79 in §7, 131 in
   §8, 141 in §9) is implied** by the two gates before it
   with a boolean `rd_mask`: `rd_is_zero_at_nonzero` makes `rd_is_zero` 0 wherever
   `rd_addr ≠ 0`, and `rd_is_zero_inverse` makes it `rd_mask` wherever `rd_addr = 0`. It remains
   as S14's must-be-exact 7 lists it; `jump-branch-slt.md` §3.1 gives the same argument for the
   `is_zero` gadget, which carries no booleanity gate.
4. **No enforcing gate and no lookup reads `pc_addr`**; only the leaves `read_pc` and
   `write_pc` do (§3.3, §4.3, §5.3, §6.3, §7.3, §8.3, §9.3). It is 0 because the memory argument
   has initial and final pc tuples at address 0 only (§3.10); the same holds for every family's
   frame. **`rd_read_value` is read by the leaf `read_rd` alone in every registered family but
   add/sub**, whose `exit_status` reads it, so in six of the seven execution families it is
   fixed by the memory argument alone; **no** window family carries an `rd` query — none has a
   frame at all. `MEM_WORD` adds a second such column: **`ram_read_value`, the word a store
   overwrites, is read by `read_ram` and by nothing else** — no gate, no obligation, no table
   (§7.3). That is exactly the property `memory-ops.md` §9 wants of a tamper target, and it is
   why the `MEM_WORD` twin moves that cell and is refused as `MemoryArgument` rather than as
   `Constraint`. The other two families read their `ram_read_value`: mem_subword's `word_rule`
   copies it, and six of atomics' gates do. **S21 adds two more such columns, and they are a
   pair**: add/sub's `deleg_write_value` (`M[25]`, §3.3) and keccak's `anchor_value` (`M[3]`,
   §12.3) are each read by one leaf and by nothing else, and the memory argument is the only
   thing that says they are equal — which is observation 19.
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
   `y < 2^14`, `V[ram_live]` is 0, so `teardown_ts` and `teardown_value` reach nothing (§10.4).
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
14. **`check_copowers` had exactly one circuit under its tightened form at S18, and has five
    callers and eighteen columns at S19.** S17 introduced it for `next_pc`'s halved obligation in
    jump/branch/slt; S18 made it take each scaled column with the selector its scaled obligation
    carries and demand the direct pair under *that same* selector (`shift-bitwise.md` §3.4), and
    shift/bitwise passes six columns to it. S19 adds three callers: mem_word one column
    (`word_index_hi` under `pc_mask`), mem_subword five (`word_index_hi`, `high`, `sub`, `low`
    and `src_sub`, all under `pc_mask`) and atomics five (`word_index_hi` under `pc_mask` and
    the four `byte_a` keys under `f_bitwise`). Mul/div is the one registered execution circuit
    that passes none: it bounds nothing by scaling, so `assemble` does not call the check at all
    (§6.6).
15. **`MEM_WORD` is the second registered family with no generic channel, and the last one that
    will be cheap to add.** `ADD_SUB_LUI_AUIPC` was the first. Between them they are the only
    two whose `FamilyCircuit::reads_generic_table` is false, the only two whose setup subtree is
    identity's decoded table alone, and the only two whose shard proof carries `2 + 2·3` outputs
    rather than `2 + 2·4` (§7.1, §7.8). Everything the family needs is either a copy or a
    16-bit decomposition, and a sign, a power or a bytewise AND is what pulls a family into the
    packed table.
16. **Two families make two queries in one `Δ` slot, and `ATOMICS` is no longer alone.** Its
    `ram` query writes at `4·cycle + 3` in address space 2 and its `rd` query at `4·cycle + 3`
    in address space 1, which is what lets one row be one read-modify-write
    (`execution-trace.md` §4). **Since S21 a delegation request does the same**: its `rd` query
    writes `a0` at `4·cycle + 3` in space 1 and its `deleg` mirror at `4·cycle + 3` in space 4,
    5, 6 or 7, the delegation family's own (§3.4). Add/sub's frame *held* two Δ-3 queries from
    S16 to S21 without ever making two — `ram` beside `rd`, with `ram_mask_rule` pinning the
    first to 0 on every row — and the `ram` query has since gone (observation 2). What both
    cases rest on is §3 of `execution-trace.md`: queries at distinct addresses may share a slot,
    and two queries at one address never do.
    **`ADD_SUB_LUI_AUIPC` and `ATOMICS` are the two families with three pads a side.** Five
    queries in an eight-leaf product tree leave three pads on each side, where the memory
    families' six leave two and the three four-query families leave none (§3.4, §9.4);
    add/sub's eight left none either, from S21 until the frame narrowed.
    `ATOMICS` has no `load` query at all, `lr.w` included, though `lr.w` is a plain word load:
    the whole extension keeps its RAM query at slot 3, frozen at S12 (`execution-trace.md` §7).
17. **Three of S19's columns are free on a padding row, and each is free for a different
    reason.** `mem_subword`'s `pcopow` is free because `p_rule`'s constant is `m_pc`, so `p` is
    0 there and `pcopow_rule` reads `0 = 0` — which is what makes it acceptance 8's negative
    control (`memory-ops.md` §9). `atomics`' `f_bitwise` is a free boolean, as §5's `f_shift`
    and `f_bitwise` are, so a padding row may look the byte table up and pay a multiplicity for
    it. `atomics`' `lt` and `cmp_gap` are free together, exactly as §4's are (observation 9):
    `cmp_order` holds on every row, but the gap's range pair is off where `pc_mask = 0`.
    `mem_word` has none of this: its two kind bits and its wrap are free booleans and nothing
    else is, every other column of the family being held to 0 by a gate with a kind bit or a
    mask in it.
18. **S19's statement is the first of any stage with a `ZERO_WINDOWS` shard.** `guests/mem`
    writes near the top of RAM as well as inside window 0, so `trace::init_windows` derives
    `[8191]` at `h = 2^16` and the statement carries seven shards where S18's carried five
    (§1.1). Until S19 §11's circuit was registered, built into every key and never proved.
19. **The anchor's value is free on both sides, and that is the whole of the answer tuple's
    argument.** Add/sub's `deleg_write_value` and keccak's `anchor_value` are each read by one
    leaf and by no gate, obligation or table (§3.10, §12.10). Nothing makes either 0; what makes
    the pair *balance* is that the request writes `T(4, base, 4c+3, v)` and the invocation reads
    `T(4, base, 4c+3, v')`, and the multiset cancels them only at `v = v'`. A prover that writes
    7 on both sides proves the same statement and is honest; a prover that writes 7 on one is
    refused as `MemoryArgument`, never as `Constraint`. Three gates pin the *other* three fields
    instead — `deleg_read_ts_zero`, `deleg_read_value_zero` and `deleg_addr_rule` — which is why
    `delegation.md` §5.2 calls them the three request-side zeroings and stops there. The same
    shape as observation 4's tamper targets, and deliberately so.
20. **A frame's gate list is a step at eight queries, and `ADD_SUB_LUI_AUIPC` has now climbed
    it and come back down.** `2w` gap obligations with the table fraction is `2w + 1` leaves, so
    the timestamp tree fits 16 while `2w + 1 ≤ 16` — true at `w = 7`, false at `w = 8`. S21's
    eighth query put the family over: seventeen leaves padded to 32 and the circuit went from
    five row-wise lists to six, while the same eight queries filled an eight-leaf product tree
    exactly and removed its two pad leaves. The POSIX layer's deletion undid both at once
    (observation 2): at `w = 5` the timestamp tree is eleven leaves in a 16-leaf tree and the
    row-wise list came off, and the product trees pay three pads a side again (§1.3, §3.4,
    §3.6). **A family taking the step a second time pays the list and nothing more** — 19 leaves
    at `w = 9` still pad to 32 — so the cost is a step, not a slope, and no registered frame is
    standing on it today.
21. **`KECCAK_F` was the one registered circuit `build::assemble` did not build, and S26d gave
    the exception back.** S21's was a 168-layer permutation with two trees reducing underneath
    it, so `keccak.rs` carried its own `Assembly`; the reason was not taste, but that
    `build::push_list` resolves an inner address to a scratch slot by scanning every slot pushed
    so far, which is quadratic, and at 354,762 columns that alone took `keccak::artifact(8)` past
    ten minutes. One round a row is flat — 385 enforcing gates and no layer of its own — so it
    goes through `memory::assemble` like every other family, and `keccak.rs`'s private
    `Assembly` is deleted. **What the width bought stays**: S21's quadratic scans in `checker`'s
    validators and in `constraints::laws` were replaced with `BTreeSet`s and tallies, which took
    `validate` from 17.6 s to 0.87 s. Nothing about those fixes was keccak-specific — they were
    latent in every artifact and only a wide one showed them.
22. **A delegation shard's ts window overlaps a CPU shard's by construction, and the block rule
    is scoped so that it may.** An invocation rides the cycle of the request that made it, so
    `KECCAK_F`'s window is a sub-interval of `ADD_SUB_LUI_AUIPC`'s whenever the guest calls the
    shim at all, and `crates/prover/tests/keccak.rs` asserts exactly that containment.
    `verify_block`'s `check_ts_windows` therefore requires non-emptiness, ordering and pairwise
    disjointness **per cycle-owning family** (`constants::family::CYCLE_OWNING`), which is
    `false` for this family as it is for all **five** window families — and for a different
    reason: a window family owns no cycle because its rows are addresses, and a delegation
    family because its rows are invocations of someone else's cycle (§12.8,
    `block-proof.md` §4).
23. **A forgery's error class depends on which entry point verifies it, and S21 is where
    that first mattered.** `verify_shard`'s order is `Statement`, `Malformed`, `Constraint`,
    `Lookup`, `MemoryArgument`; `verify_block` runs `verify_global_memory` — the memory
    argument's statement half — **before** any shard's own checks (`block-proof.md` §3), so
    a witness that both breaks a gate and unbalances the multiset reads `Constraint` through
    one entry point and `MemoryArgument` through the other. Every anchor tamper is such a
    witness: a mirror read that is stamped breaks `deleg_read_ts_zero` *and* matches no
    write. So `checker::assert_anchor_twins_refused` runs the three zeroings at shard level,
    where the gate is the answer, and the dropped-invocation twins at block level, where the
    multiset is — and the helper's doc comment says why, because a twin asserting
    `Constraint` at block level is asserting something false. It did, until S21's first full
    deferred run. No earlier stage met this: every tamper before S21 either broke a gate
    without unbalancing anything or was run through `verify_shard` alone.
24. **Two families share one artifact byte for byte, and the sharing is the soundness
    argument.** `family_circuit(13, n)` and `family_circuit(8, n)` are the same bytes at every
    `n`, so `crates/constraints/tests/vectors/zero_window.bin` pins both. That is not reuse for
    economy: the journal's window takes `ZERO_WINDOWS`' artifact **because** its init leaf is
    the literal 0, leaving a prover no init column to pre-load the answer into at timestamp 0
    (§16.1). `PUBLIC_INPUT` and `ADVICE_WINDOWS` likewise share `value_window_artifact` and
    differ only in what `verify_shard_local` step 10c does with `M[2]` — holds it to the
    statement's `input`, or does not look at it at all. So three of the five S-IO-era window
    families are two artifacts, and **what tells them apart is a verifier step and a window
    id, not a gate**. It is the first place in this registry where two `FamilyId`s carry
    identical circuits, and `VerifyingKey::check` is untroubled by it: a key's circuits are the
    registry's, family by family, and two families returning equal bytes is not a collision.
25. **`ADVICE_WINDOWS`' `M[2]` is the only committed column in the whole registry that nothing
    binds.** Every other committed column is reached by a gate, a leaf, a lookup, an opening
    against identity or the SRS digest, or a verifier step. `M[2]` is reached by its init leaf
    alone, and a leaf constrains nothing by itself — it balances against whatever the guest read
    (§17.2). That is the definition of advice and not a gap, but it is worth writing down beside
    §21 observation 6's unconstrained `INIT_TEARDOWN` cells and §21 observation 19's free anchor
    value, because the three are the registry's whole inventory of deliberately free committed
    cells, and each is free for a different reason: masked off, paired by the multiset, or
    chosen by the prover on purpose.

---

## 22. Maintaining this page

A stage that adds a circuit family, or changes one, updates this page in the same pull request
(`prompts/00-master.md`, implementation rule 12). **Changing one is the same obligation as
adding one**: S21 added §12 and rewrote §3 from the new artifact, because the eighth memory
query moved every relation number in it, and §3 was rewritten again when the POSIX layer's
deletion took three queries back out — a change that added no circuit at all and still moved
every `M` and `W` index, every relation number, both fixture digests, the depth and the proof
length (§3.1). **A retired ecall is a circuit change**, and this is where it lands, and **so is
a pinned height**, even one that moves no gate: S-STREAM moved `family::PUBLIC_WINDOW_HEIGHT`
from `2^8` to `2^12`, which added four halving lists to two artifacts and changed nothing else
about either, and that alone moved §1.1's two registry rows and its menu sentence, §1.2's two
master-table rows and their byte lengths, §1.3's five-windows bullet, §15 and §16 throughout,
§21 observation 1 and Appendix A's dump recipe. The test for whether this page owes an edit is
not "did a gate change" but "did a number here come from something that moved".

A new family's entry is a section like §3, §4, §5 or §6 and holds:

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
   better source: it runs in CI and a probe does not. A family too wide for a row table says so
   and gives the chain that stands in for one instead (§12.9).
9. **Its rows in §1.1, §1.2 and §1.3, its counts in §0.5, the challenge slots it reads in
   §0.4**, and any §21 observation the accounting turns up. A family whose decoded tuple is not
   seven wide also moves §0.4's `β⁶` and `g_dec` rows, as `MUL_DIV`'s and `ATOMICS`' six-wide
   ones did; a family that reads or does not read the generic channel moves §0.4's `β` and `β²`
   rows, as `MEM_WORD`'s absence from them records.

Appendix A's commands print every `n = 22` name, position and formula, and the `n = 22` counts
follow from them; the `n = 8`, `n = 16`, `n = 18` and `n = 20` counts and the §3.10 and §4.10
probes were read from `family_circuit` and the suites' `honest_rows` directly and have no
committed command (Appendix A, last paragraph). **§12's artifact is not committed as bytes**:
like the other five delegation families it is committed by digest
(`crates/constraints/tests/vectors/keccak.txt`), and what this page was read from is
`keccak::artifact(18)` itself — small enough to dump since S26d (Appendix A). §7.9's, §8.9's
and §9.9's rows are the three fills' own output over `guests/mem`, which
`crates/checker/tests/mem_fill.rs` holds to every gate and both table channels in ordinary CI.
The `checker dump` of the family's committed fixture is the machine view to check the entry
against.

---

## Appendix A. Reproducing

```text
cargo run -p checker -- dump crates/constraints/tests/vectors/add_sub.bin           # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/jump_branch_slt.bin   # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/shift_bitwise.bin     # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/mul_div.bin           # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/mem_word.bin          # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/mem_subword.bin       # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/atomics.bin           # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/image_window.bin      # n = 22
cargo run -p checker -- dump crates/constraints/tests/vectors/zero_window.bin       # n = 22
#   zero_window.bin is PUBLIC_OUTPUT's circuit too: family_circuit(13, n) and
#   family_circuit(8, n) are one constructor and agree byte for byte at every n.
# PUBLIC_INPUT's and ADVICE_WINDOWS' artifact has NO committed fixture, value_window_artifact
#   being S-IO's one new constructor. To read §15 and §17 from it, write the bytes and dump them:
#     memory::value_window_artifact(12).to_bytes() -> value_window_12.bin  (2,455 bytes)
#     memory::value_window_artifact(22).to_bytes() -> value_window_22.bin  (3,535 bytes)
#     memory::zero_window_artifact(12).to_bytes()  -> zero_window_12.bin   (2,338 bytes)
#   then `checker dump`, `checker laws` and `checker padding` over each. The 12 is S-STREAM's
#   pinned public-window height; at S-IO the same three reads were n = 8, 22 and 8, and the
#   artifacts were 2,027, 3,535 and 1,910 bytes.
# §13, §14, §18, §19 and §20 have no dump: a delegation family's artifact is megabytes --
# `poseidon2::artifact(8).to_bytes()` is 2,056,361 and `sha256::artifact(8)`'s 10,895,760 -- so
# what is committed is a SHA-256 and the shape line beside it, and what this page was read from
# is the constructor itself. **§12's is small enough to dump since S26d**: write
# `keccak::artifact(18).to_bytes()` to a file (1,900,468 bytes) and `checker dump` it; at the
# `n = 16` §1.2 also pins it is 1,899,700 bytes and 20,333 readable lines, the two differing
# only in the halving phase. S21's was 100,254,040 bytes and had no dump at all.
cat crates/constraints/tests/vectors/keccak.txt
cat crates/constraints/tests/vectors/poseidon2.txt
cat crates/constraints/tests/vectors/fr_arith.txt
cat crates/constraints/tests/vectors/mod_mul.txt      # 2^16 since S26c; §18
cat crates/constraints/tests/vectors/sha256.txt       # §19
cat crates/constraints/tests/vectors/ec_add.txt       # §20
cargo run -p kat-gen -- delegation              # rewrites all six lines from the constructors
for f in alu reg mem atomics; do
  cargo run -p checker -- dump crates/constraints/tests/vectors/memory_frame_$f.bin    # §2.2's four bare frames
done
cargo run -p checker -- laws crates/constraints/tests/vectors/add_sub.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/jump_branch_slt.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/shift_bitwise.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/mul_div.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/mem_word.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/mem_subword.bin
cargo run -p checker -- laws crates/constraints/tests/vectors/atomics.bin
cargo test -p checker --test add_sub            # §3.9's rows against every gate and bound
cargo test -p checker --test jump_branch_slt    # §4.9's rows against every gate, bound and table
cargo test -p checker --test shift_bitwise      # §5.9's and §5.10's, 17 tests
cargo test -p checker --test mul_div            # §6.9's and §6.10's, 17 tests
cargo test -p checker --test mem_word           # §7.10's, 12 tests
cargo test -p checker --test mem_subword        # §8.10's, 17 tests
cargo test -p checker --test atomics            # §9.10's, 15 tests
cargo test -p checker --test mem_fill           # §7.9's, §8.9's and §9.9's rows: the three
                                                # fills over guests/mem's trace, in ordinary CI
cargo test -p checker --test keccak             # §12.9's forward pass and §12.10's ten
                                                # negative controls, 13 tests, in ordinary CI
cargo test -p emulator --test keccak            # emulator::keccak_f against tiny-keccak, which
                                                # is what §12.9's chain rests on
cargo test -p constants --test keccak           # ROTATIONS and ROUND_CONSTANTS re-derived
cargo test -p checker --test mod_mul            # §18's rows and controls, 14 tests, in ordinary
                                                # CI -- row-local at n = 16, this family having
                                                # exactly one height since S26c
cargo test -p checker --test sha256             # §19's forward pass at n = 2 and its controls,
                                                # 14 tests, in ordinary CI
cargo test -p constants --test sha256           # IV and ROUND_CONSTANTS re-derived from the
                                                # square and cube roots of the first primes
cargo test -p checker --test ec_add             # §20's rows and controls, 21 tests, in ordinary
                                                # CI -- row-local at n = 16
cargo test -p prover --test fills               # §18's, §19's and §20's fills held to their
                                                # circuits' gates: a forward pass for SHA256_COMP
                                                # at 2^8 and sampled rows for the two at 2^16,
                                                # whose passes are 4.6 GB and 18.3 GB
cargo test -p checker --test public_values      # §15's, §16's and §17's shapes, both public
                                                # windows' and the advice region's layouts, and
                                                # the window rules, in ordinary CI
cargo test -p prover --test public_io -- --include-ignored --test-threads=1
                                                # S-IO's statement: guests/public-io proved and
                                                # verified, step 10c isolated, and the advice
                                                # shown unbound. DEFERRED; a 2^20 statement
```

The dump prints the header, the committed columns, the virtual tables, every gate list with
each gate as a formula over addresses and its relation number and name, the flat relation list,
the scratch bijection, the output map, the lookups, the padding contract and the gate
catalogue. A relation number, an `L{k}[j]` and a node name in this page are the dump's, except
that the leaf and inner-layer subsections write a fraction node by its stem `x`: the dump names
its two columns `x_num` and `x_den`, defined by relations `define_x_num` and `define_x_den`. The
halving lists repeat one pattern, so the dump at `n = 22` gives every `n`: the row-wise layers do
not depend on `n` — `L1`–`L5` for add/sub, jump/branch/slt and mem_word, `L1`–`L6` for the two
S18 families and for mem_subword and atomics — nor do relations 0–194 of add/sub, 0–213 of
jump/branch/slt, 0–305 of shift/bitwise, 0–297 of mul/div, 0–170 of mem_word, 0–304 of
mem_subword and 0–317 of atomics, and the halving lists follow §3.8's, §4.8's, §5.8's, §6.8's,
§7.8's, §8.8's and §9.8's formulas.

The counts at `n = 16`, `n = 18` and `n = 20` were read from `family_circuit` directly (its artifact's
`depth()`, layer widths, `relations`, `lookups` and `to_bytes()`), which has no CLI; §15's,
§16's and §17's counts were read the same way, from `family_circuit(12, 12)`,
`family_circuit(13, 12)`, `family_circuit(14, 16)` and `family_circuit(14, 22)`, and their
columns, gates, relation numbers, outputs and padding contracts from the dumps above. The §3.10
probe is add/sub's `honest_rows` with one cell moved at a time, run through
`violated_relations` and `violated_lookups`; the §4.10 probe is the same over
jump/branch/slt's `honest_rows`, run also through that suite's own table check,
`violated_tables`. §5.10, §6.10, §7.10, §8.10 and §9.10 need no probe: they are their
suites' `each_gate_is_the_one_that_refuses_its_row` read as a cell-by-cell account, and that
test runs in ordinary CI. §1.2's proof byte lengths are `crates/prover/tests/alu.rs`' and
`crates/prover/tests/mem.rs`', both of which are `#[ignore]`d and run with
`--include-ignored --test-threads=1`; the formula they check them against is
`shard-proof.md` §9's over the circuit's own shape, written out as `mem.rs`' `proof_bytes`.
§12's **381,100** is that same formula over `keccak::artifact(18)`, which
`crates/prover/tests/keccak.rs` asserts against the real `ShardProof::to_bytes().len()` — a
derived figure until that deferred suite runs, the same formula's 373,276 at `2^16` having been
measured.
