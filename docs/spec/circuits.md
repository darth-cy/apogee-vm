# Circuits

Every shard is proved by its family's circuit, a `constraints::CircuitArtifact` in
[gkr.md](gkr.md)'s model, fixed by the format, the family and the height. This page lists the
circuits and their shapes (§1), how one is assembled (§2) and how `crates/checker` checks one
independently (§3); each family's own page specifies its columns, gates and lookups.

## 1. The registry

`constraints::family_circuit(family, trace_vars)` is the base format's registry,
`constraints::recursion_circuit` the recursion format's, and `VmConfig::circuit` picks one by format
([recursion.md](recursion.md) §1.1). Each returns a `FamilyCircuit`, the artifact and its
channel specs ([lookup.md](lookup.md) §11). A verifying key loads only if its circuits are the
registry's at its heights ([proof.md](proof.md) §7), and the prover registers the same (§2).

Families 0–6 (`constants::family`) are the **execution** families, one executed instruction a
row ([add-sub.md](add-sub.md), [jump-branch-slt.md](jump-branch-slt.md),
[shift-bitwise.md](shift-bitwise.md), [mul-div.md](mul-div.md), [memory-ops.md](memory-ops.md) §3,
§4, §6); 7–8 and 12–14 the **window** families, one memory word a row ([memory.md](memory.md) §3,
[public-values.md](public-values.md) §4); 9–11 and 15–17 the **delegation** families, one
invocation a row ([delegation-circuits.md](delegation-circuits.md) §2 to §7, by id); 18–22 the
recursion format's ([recursion.md](recursion.md) §2 to §6).

Shapes at the default height `2^n` (`constants::family::DEFAULT_HEIGHTS`): committed columns,
enforcing gates, obligations per channel (`TIMESTAMP/RANGE16/GENERIC/DECODER/XOR8`), row-wise gate
lists (the halving ones are `n`), inner columns, artifact bytes, and a base-format shard proof's
bytes, [proof.md](proof.md) §9's layout over the shape:

| id | family | `n` | `M` | `W` | `S` | gates | lookups | row-wise | inner | bytes | proof |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | `ADD_SUB_LUI_AUIPC` | 22 | 27 | 35 | 7 | 63 | 10/4/0/1/0 | 5 | 314 | 72,064 | 64,764 |
| | recursion format | 22 | 27 | 39 | 7 | 75 | 10/4/0/1/0 | 5 | 314 | 79,077 | — |
| 1 | `JUMP_BRANCH_SLT` | 22 | 21 | 44 | 10 | 42 | 8/11/2/1/0 | 5 | 392 | 76,980 | 69,436 |
| 2 | `SHIFT_BITWISE` | 22 | 21 | 61 | 10 | 48 | 8/24/6/1/0 | 6 | 478 | 102,837 | 76,644 |
| 3 | `MUL_DIV` | 20 | 21 | 54 | 9 | 54 | 8/16/2/1/0 | 6 | 444 | 92,640 | 67,412 |
| 4 | `MEM_WORD` | 22 | 31 | 24 | 7 | 33 | 12/5/0/1/0 | 5 | 314 | 60,383 | 63,836 |
| 5 | `MEM_SUBWORD` | 22 | 31 | 55 | 10 | 53 | 12/22/1/1/0 | 6 | 472 | 98,846 | 76,196 |
| 6 | `ATOMICS` | 20 | 26 | 54 | 9 | 46 | 10/19/6/1/0 | 6 | 472 | 101,593 | 68,468 |
| 7 | `INIT_TEARDOWN` | 22 | 2 | 0 | 1 | 0 | — | 1 | 46 | 3,907 | 36,316 |
| 8 | `ZERO_WINDOWS` | 22 | 2 | 0 | 0 | 0 | — | 1 | 46 | 3,418 | 36,284 |
| 9 | `KECCAK_F` | 18 | 208 | 1,556 | 0 | 385 | 0/210/0/0/1,020 | 11 | 5,490 | 1,900,468 | 381,100 |
| 10 | `POSEIDON2` | 8 | 100 | 4,092 | 0 | 4,248 | — | 193 | 2,020 | 2,056,361 | 664,780 |
| 11 | `FR_ARITH` | 8 | 104 | 2,576 | 0 | 2,701 | — | 6 | 142 | 1,063,214 | 266,292 |
| 12 | `PUBLIC_INPUT` | 12 | 3 | 0 | 0 | 0 | — | 1 | 26 | 2,455 | 12,556 |
| 13 | `PUBLIC_OUTPUT` | 12 | 2 | 0 | 0 | 0 | — | 1 | 26 | 2,338 | 12,524 |
| 14 | `ADVICE_WINDOWS` | 22 | 3 | 0 | 0 | 0 | — | 1 | 46 | 3,535 | 36,316 |
| 15 | `MOD_MUL` | 16 | 104 | 221 | 0 | 125 | 0/274/0/0/0 | 10 | 2,244 | 550,391 | 135,220 |
| 16 | `SHA256_COMP` | 18 | 104 | 520 | 0 | 119 | 0/114/0/0/336 | 10 | 2,802 | 845,456 | 189,988 |
| 17 | `EC_ADD` | 16 | 392 | 1,028 | 0 | 637 | 0/1,110/0/0/0 | 12 | 8,772 | 2,350,670 | 434,916 |
| 18 | `FIELD_WINDOWS` | 20 | 2 | 0 | 0 | 0 | — | 1 | 42 | 2,758 | — |
| 19 | `FR_OP` | 20 | 31 | 31 | 0 | 44 | 0/36/0/0/0 | 7 | 370 | 89,741 | — |
| 20 | `P2_FIELD` | 18 | 45 | 382 | 0 | 372 | 0/58/0/0/0 | 7 | 392 | 294,425 | — |
| 21 | `FIELD_IO` | 18 | 43 | 39 | 0 | 24 | 0/70/0/0/0 | 8 | 650 | 164,713 | — |
| 22 | `FQ_OP` | 20 | 48 | 73 | 0 | 38 | 30/50/0/0/0 | 7 | 630 | 158,326 | — |

**Heights.** Both registries return `None` above `MAX_TRACE_VARS` = 30, and below the floor
[lookup.md](lookup.md) §3 derives from the family's channels: 19 with `TIMESTAMP`, else 16 with
`RANGE16` or `XOR8`, else 0. A height changes `trace_vars`, each list's variable count and the
number of halving lists, one per variable and as wide as the outputs, and no gate below them: at
`2^20` `ADD_SUB_LUI_AUIPC` has 298 inner columns, 70,974 bytes and a 57,196-byte proof.

**Shared circuits.** The registries agree on families 1–17; the recursion format's
`ADD_SUB_LUI_AUIPC` is `add_sub::recursion_artifact` ([add-sub.md](add-sub.md) §2).
`PUBLIC_OUTPUT`'s circuit is `ZERO_WINDOWS`' and `ADVICE_WINDOWS`' is `PUBLIC_INPUT`'s, byte for
byte at one height, and `FIELD_WINDOWS`' is the zero window at a stride of one cell, all
`constraints::memory` constructors ([memory.md](memory.md) §3). Every other family's is its own
module's `artifact`.

## 2. How a family circuit is assembled

```text
layer 0        M ‖ W ‖ S in layout order, beside the V tables' closed forms
gate list 0    memory leaves: the read side, then the write side, each padded to a power of
                 two with the literal 1
               per channel, in spec order: (−mult, T + g), then (1, E_l + g) per lookup,
                 then (0, 1) up to a power of two                      (lookup.md §6)
               every enforcing gate
lists 1 … r    row-wise: each tree combines sibling nodes, a product by a·b, a fraction by
                 (n_a·d_b + n_b·d_a, d_a·d_b); a tree already at one node is copied up
lists r+1 …    halving, one per variable: TreeProduct on a product, TreeCross (num) and
                 TreeProduct (den) on a fraction
top            no variables: read_root, write_root, then (num, den) per channel
```

`r` is the largest tree's depth, so the circuit has `r + 1` row-wise lists; every registered
circuit, `POSEIDON2` included, ends in a top with no variables. `crates/constraints/src/build.rs`
assembles it, writing the flat relation list and an all-zero padding row, `zero_row_valid` read off
the gates' constants, and validating ([gkr.md](gkr.md) §4). `constraints::memory::assemble` gives
it the product trees and `lookup::channel_trees`' fraction trees ([lookup.md](lookup.md) §11), then
runs `memory::check_memory` ([memory.md](memory.md) §8) and `lookup::check_discharge`: a
constructor panics on a refusal, so every circuit that exists has passed them. Its callers:

- `memory::frame_with_channels_artifact(queries, trace_vars, FamilySpec)`, the execution families:
  [memory.md](memory.md) §2's frame over `memory::frame_queries(family)`, then the family's witness
  columns after the frame's `w + 3`, setup columns from `S[0]`, virtual tables, enforcing gates
  after the frame's, lookups after its `2w` gap obligations, and a non-empty channel list;
- the window constructors ([memory.md](memory.md) §3);
- the delegation and recursion families, every gate in list 0, from `constraints::delegation`'s
  shared columns, leaves and gates ([delegation-circuits.md](delegation-circuits.md) §1) — but
  `POSEIDON2`, which builds its own lists (`delegation::Assembly`): 192 row-wise lists of rounds
  beside its product trees, the last holding three gates on the output lanes.

Beyond the frame, each execution family has `m_pc` as the row's liveness and every other mask
held to `m_pc` times the kinds making that query (`<q>_mask_rule`, [memory.md](memory.md) §2); its
decoded row as `W` columns, bound by `decode_row` to its table at the row's `pc`, and
`decoded_mask_bits`, the mask as boolean kind bits, one-hot by the table's domain
([lookup.md](lookup.md) §10, [program.md](program.md) §6); a `next_pc_rule`
([memory.md](memory.md) §5); a bound on each register value it writes
([memory-ops.md](memory-ops.md) §5); and channels ordered `TIMESTAMP`, `RANGE16`, `GENERIC` if
read, `DECODER`.

`prover::family_fill(family)` is the prover's side: a `prover::Fill` writes a shard's committed
columns but the multiplicities, which `trace::build_multiplicities` counts. `prover::register`
pairs fill and circuit for each family of a `VmConfig` (`ProverError::Unregistered` if either is
missing).

## 3. Checking a circuit independently

`crates/checker`'s validators enforce the rules again in code sharing nothing with
`crates/constraints/src/laws.rs`, never calling `validate`. They evaluate a gate only through the
kernel `gkr_verify::eval_gate` ([gkr.md](gkr.md) §3), so they re-read the rules, not the gates'
meaning. Sampled checks use eight pseudo-random points from fixed seeds.

| | checks |
| --- | --- |
| `check_laws` (`check_law1` … `check_law4`) | the four laws, then the lookup rules ([gkr.md](gkr.md) §4); Law 4 and selector booleanity by evaluation, where `validate` compares expansions |
| `check_padding`, `check_padding_identity` | the padding contract and its product-tree clause, fraction trees exempt |
| `check_lookup_discharge` | [lookup.md](lookup.md) §11's discharge rule, gating and compression re-derived |
| `violated_relations`, `violated_lookups` | a witness row's row-local relations and range obligations |
| `channel_sums`, `check_channel_roots` | each channel's sum and denominator product, folded row by row rather than by a tree, naming every tuple no table row holds; then the circuit's root pairs against them |
| `memory_roots` | the two roots as products over the rows the halving phase reads |
| `memory_columns_from_log`, `frame_witness_from_log` | an execution family's frame columns from the memory event log, where `trace` builds them from a shard's rows |

They do not re-implement `check_memory`, the copower rule ([lookup.md](lookup.md) §11), or
`validate`'s other construction rules, the degree ceiling among them.

**`checker::TamperHarness`** re-proves a statement with witness cells or boundary scalars changed,
as an honest prover would prove the changed witness — each channel's multiplicities recounted
unless one is what changed or the changed tuple is in no table, changed `M` columns recommitted in
a fresh global commit phase, every shard re-proved — then verifies a shard or the block and
asserts the refusal's class (a `Lookup`'s channel too), or that a change breaking nothing
verifies. It relies on the prover checking nothing ([gkr.md](gkr.md) §5), runs on the archived
path ([streaming.md](streaming.md) §6), and carries the delegation anchor's forgeries
(`checker::assert_anchor_twins_refused`, [delegation.md](delegation.md) §5).

**A dump** (`checker::dump`, CLI in [tools.md](../tools.md) §4) prints the columns by address and
name, each list's gates in [gkr.md](gkr.md) §1's template with their relations, the flat relations
over `scratch[i]`, the scratch bijection, outputs, lookups and padding row. Relations are numbered
list by list, producing before enforcing; a producing one is `define_<column>`, an enforcing one
bears its gate's name; a node is named for its tree and layer (`range16_3_1_num`, `read_root`), a
leaf for what it holds (`write_pad_0`, `rd_hi_range_den`). A literal below `2^32` prints in decimal,
`p − k` for such a `k` as `-k`, any other as `0x` and 64 big-endian hex digits; a challenge as
its `constants::challenge_slot::NAMES` entry.
