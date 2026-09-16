# The LogUp channels: tables, gated keys, fraction trees and the root check

Frozen as of S15. Changing anything here is a protocol-version change.

This page is the master prompt's *Lookups (shard-local)* bullet, as the repository
owner decided it at S15. It cites `docs/spec/gkr.md` for the circuit model and
`docs/spec/memory.md` §7 for the range obligations it discharges, and restates
neither.

| crate | what |
| --- | --- |
| `crates/constants` | the channels, their bounds, the challenge slots and the tag |
| `crates/constraints` | `lookup`: the gated tuple, the leaf pair, the fraction tree, the construction rules; `memory::frame_with_channels_artifact` assembles them beside a frame |
| `crates/gkr-verify` | the derived slots and the root check |
| `crates/gkr` | `TreeCross`, the halving shape a fraction tree needs |
| `crates/trace` | the multiplicity columns and their recount |
| `crates/program` | `lookup_tables`: the generic channel's committed table |
| `crates/checker` | the native fractional sums, the root comparison and the discharge cross-check |

---

## 1. What a channel claims

A channel is one rational identity over a whole shard:

```text
Σ_rows Σ_l  1/(E_l + g)   −   Σ_rows  mult/(T + g)   =   0
```

- `E_l` is row `y`'s **gated tuple** for lookup expression `l`, compressed by `β` (§4).
- `T` is the **table** row `y`'s tuple, compressed the same way (§3).
- `mult` is the channel's one **multiplicity column**: row `t` counts how many gated
  tuples over the whole shard are table row `t`'s (§7).

The identity holds exactly when every gated tuple is a row of the table, except with
probability `(rows · lookups)/|Fr|` over `g` — the standard LogUp argument. It is
proved as a tree of fractions whose root pair `(num, den)` the verifier holds to
`num = 0` **and** `den ≠ 0` (§8).

**A range channel** is the special case of a one-column table: its table is the closed
form `[0, 2^BITS)` and its claim is that every expression's canonical integer is below
that bound. **A table channel**'s table is committed.

## 2. The two challenges

| slot | name | value |
| --- | --- | --- |
| 6 | `LOOKUP_G` | `g`, drawn |
| 7 | `LOOKUP_BETA` | `β`, drawn |
| 8–12 | `LOOKUP_BETA_2` … `LOOKUP_BETA_6` | derived: `β^2 … β^6` |
| 13 | `LOOKUP_DECODER_NEUTRAL` | derived: `g − Σ_{j < W} β^j`, `W` the decoder tuple's width |

`g` and `β` are **shard-local**. They are drawn from that shard's own transcript,
in that order, under one challenge tag `LOOKUP_CHALLENGE` (33), **strictly after every
witness and multiplicity commitment of the shard is absorbed**. No global lookup
challenge exists anywhere.

`β^0` is the literal 1, so a one-column tuple names no slot at all. Every power above
the first is a **derived slot** (`docs/spec/gkr.md` §5.1): a gate coefficient is one
literal or one challenge, and `β^j` is neither. `gkr_verify::insert_lookup_challenges`
fills them, and never reads one from a proof.

**Selectors are boolean.** `validate` refuses a lookup whose selector no enforcing gate
of gate list 0 holds to `x − x·x = 0`. LogUp sums `s/(E + g)` over the rows, so a row at
`s = −1` with an out-of-range tuple cancels a row at `s = 1` with the same tuple: without
booleanity, LogUp and the native reading of an obligation (`docs/spec/memory.md` §7 — it
holds where the selector is 0, or where the tuple is in the table) are different
statements.

## 3. The range channels' tables

A range channel's table is a **virtual** setup column: a closed form, evaluated but
never materialized and never committed (`docs/spec/gkr.md` §2.1).

| channel | bound | kind | value at row `y` | closed form |
| --- | --- | --- | --- | --- |
| `TIMESTAMP` = 0 | `[0, 2^19)` | `Range19`, wire tag 2 | `y mod 2^19` | `Σ_{j < 19} 2^j·y_j` |
| `RANGE16` = 1 | `[0, 2^16)` | `Range16`, wire tag 3 | `y mod 2^16` | `Σ_{j < 16} 2^j·y_j` |

At `trace_vars ≥ BITS` the table is exactly `[0, 2^BITS)`, each value once per `2^BITS`
rows; at fewer variables it is `[0, 2^trace_vars)`, a narrower set. **So a circuit whose
`trace_vars` is below a range channel's bound is refused at construction**: a table of
`2^n` rows holds at most `2^n` values, and a prover with an honest value the table does
not hold cannot balance the channel.

**What that costs.** `BITS[TIMESTAMP]` is 19 and a Mercury opening needs an even
variable count (`docs/spec/mercury.md`), so the height menu's even entries put **every
circuit carrying a timestamp gap obligation at `2^20` rows or more** — which is every
execution family (`docs/spec/memory.md` §2.4). Six of the seven default there already;
`constants::family::DEFAULT_HEIGHTS[ATOMICS]` is `2^16` and S16 must raise it.

## 4. Gated keys

A lookup expression **cannot be conditional**: it is a linear form evaluated on every
row, so a row whose key is meaningless must still produce a tuple the table holds. The
selector is what sends such a row somewhere neutral, and the three conventions are:

| channel kind | gated tuple position `j` | neutral tuple |
| --- | --- | --- |
| range | `s·e_j` | `0`, which is a real and in-range entry |
| generic | `s·(e_0 + 1)` at `j = 0`, `s·e_j` above | the all-zero `ZeroEntry` row |
| decoder | `s·(e_j + 1) − 1` | `MINUS_ONE` in every column |

**The `+ 1` on a table channel's key** is what keeps every real entry off the all-zero
tuple. Without it, a table whose key 0 maps to a nonzero value has no all-zero row at
all, and adding a `ZeroEntry` beside a real key-0 entry puts two rows at one key — a
cheating prover then reads the neutral value where the real one lives. The offset
reserves the all-zero tuple for the neutral row and shifts the real domain up by one.

**A range channel needs no offset**, and cannot have one: the table is `[0, 2^BITS)`, so
shifting the domain up by one would put `2^BITS` outside it and the top of the range
would become unprovable. Nothing is lost, because a range table maps nothing: the value
0 is a real, in-range entry, and "0 is in range" is all a switched-off row claims. This
is the first documented exemption from the `ZeroEntry` rule.

**The decoder channel is the second**, defined against S11's frozen no-all-zero-row
layout: a decoded table is `MINUS_ONE`-padded and has no all-zero row, so a padding row
of the table *is* the neutral entry, and a switched-off cycle row looks up the
`MINUS_ONE` tuple. S11's height rule — a family's table is strictly taller than its last
live row — is what guarantees the table holds one. Its multiplicity is counted on the
lowest such row.

The general gated-key plus `ZeroEntry` rule stays mandatory for every other channel.

## 5. The denominator gate

With `s` the selector, `e_j = Σ_i c_{j,i}·x_{j,i} + k_j` the tuple's `j`-th expression,
`o_j` the channel's offset and `n_j` the neutral value the gating subtracts,

```text
E_l + g  =  Σ_j β^j·s·e_j  +  Σ_j β^j·o_j·s  +  (g + Σ_j β^j·n_j)
```

which is **one `Quadratic`**: every term of `e_j` becomes the product `(β^j·c, s, x)`,
each nonzero offset a linear term `(β^j·o_j, s)`, and the bracket the constant — the
drawn `LOOKUP_G`, or the derived `LOOKUP_DECODER_NEUTRAL` where the neutral tuple is
`MINUS_ONE`.

Because `β^j·c` must be one `Coeff`, **a tuple position above 0 weights each of its
columns by 1 and carries no constant**; position 0, where `β^0` is the literal 1, takes
any literal coefficients and any constant. `validate` refuses anything else, so an
artifact read with `from_bytes` never reaches a denominator gate that does not exist.

The table side is `T + g = Σ_j β^j·t_j + g`, a `Linear` over the table's columns.

## 6. The fraction tree

Every leaf is a `(num, den)` pair of gate-list-0 columns:

| leaf | `num` | `den` |
| --- | --- | --- |
| row lookup `l` | `1` | `E_l + g` |
| the table | `−mult` | `T + g` |
| padding | `0` | `1` |

The leaf level is padded to a power of two with the neutral fraction `(0, 1)`. The row
side and the table side are separate leaves; their first pair-addition is exactly
`1/(w + g) − m/(t + g)`.

Fractions add pairwise, `a/b + c/d = (ad + cb)/(bd)`:

```text
row-wise   num' = num_a·den_b + num_b·den_a        den' = den_a·den_b
halving    num' = num(·,0)·den(·,1)
                + num(·,1)·den(·,0)                den' = den(·,0)·den(·,1)
```

The halving numerator is `GateDef::TreeCross { left: num, right: den }`, wire tag 6, a
**new halving shape**: `TreeProduct` reads one column at both children and a fraction's
numerator needs two. `docs/spec/gkr.md`'s halving law relaxes with it — a halving list
still writes exactly as many columns as it reads, and every entry is still a halving
shape over layer `k`'s columns, but an entry may read a column other than its own. The
claim layout, L3's `2·w_k` message and L4's line-folding are unchanged. There are no
per-node special cases above the leaves: one aggregate-pair shape runs the whole tree.

A circuit's trees are assembled together (`crates/constraints`'s `build`): the memory
argument's two product trees first, then one fraction tree per channel, every tree
reduced row-wise until it is one node — a tree that finishes early copies itself up —
and then `trace_vars` halving lists to a zero-variable top. The output map is the memory
roots at `READ_ROOT` and `WRITE_ROOT`, then each channel's `(num, den)` pair in channel
order.

**The padding contract** (`docs/spec/gkr.md` §4.3) does **not** apply to a fraction
tree. Its identity is `(0, 1)`, not 1, and a padding row is not inactive in a channel at
all: it contributes the channel's neutral entry, which the multiplicity column counts
like any other. `checker::check_padding_identity` exempts every column a `TreeCross`
reads, and holds the product trees to the clause as before.

## 7. Multiplicities

Each circuit carries **exactly one committed multiplicity column per channel**, in the
witness subtree, positioned last in it.

`trace::build_multiplicities` counts them in one pass over the trace and one over the
table, and nothing there reads a challenge: a multiplicity is committed *before* `g` and
`β` are drawn, so the counting is over **raw gated tuples** and never over a compressed
one. One counter is incremented once per lookup expression on each row, the rows their
selector switches off included.

A table of `2^n` rows over fewer distinct tuples repeats, so a tuple can sit at several
rows. **The counter credits the lowest row holding it**, which is the convention both
sides recompute. A gated tuple the table does not hold is a build error naming the
channel: the honest prover cannot balance over one.

`trace::check_multiplicities` is the recount, and a column that disagrees with it is a
build error naming the channel and the first differing row.

## 8. The root check

Per channel, on the `(num, den)` pair the output map carries:

```text
accept  iff  num = 0  and  den ≠ 0
```

`gkr_verify::channel_holds` is the check. **Both conditions**, and neither alone: a
fraction pair of `(0, 0)` annihilates everything above it — `(x, y) + (0, 0) = (0, 0)` —
so the root of a channel with one such leaf is `(0, 0)` whatever every other row holds,
and `num = 0` alone would accept a channel that proves nothing.

Under the schedule of §2 a prover cannot steer a denominator to 0: `g` is drawn after
every column is committed. The check costs one comparison and is kept anyway, because it
is the only thing standing between a steerable denominator and a vacuous channel.

## 9. The generic channel's table

`program::lookup_tables::generic_table` packs the two tables a wide field still needs
into one committed setup table of `GENERIC_WIDTH = 3` columns — the key, then two value
columns, the narrower table zero-padded to the wider's width:

```text
row 0                    the ZeroEntry, all zero
rows 1 ..= 2^16          AND:        (AND_BASE  + a + 1,  b,        a & b)
rows 2^16+1 ..= 2^17     U16GetSign: (SIGN_BASE + h + 1,  h >> 15,  0)
rows above               the ZeroEntry again, multiplicity 0
```

`AND_BASE = 0` and `SIGN_BASE = 256` give the two tables disjoint key ranges, so no
tuple of one is a tuple of the other. 131,073 rows: a circuit carrying both is at
`2^18` or more, which every execution family already exceeds (§3).

**`U16GetSign` is committed**, not closed-form. S17 and S18 consume it by name. It is
load-bearing in a way it was not over a small field: with a whole word in one column its
top bit is no longer a column that already exists, so every sign comes from here.

The taxonomy stays small on purpose. XOR and AND are positional — a wide field says
nothing extra about a byte's seventh bit — and everything that only existed to work
around a small field retires into arithmetic gadgets in later stages.

## 10. The decoder channel

The decoder table is a family's own decoded table: `program::lookup_tuple(family)`'s
columns in their frozen order (`crates/program/CLAUDE.md`), as committed setup columns,
at the family's height. Row `i` is pc `2i`, the pc/2 convention of S11.

The cycle row's tuple is those columns' claimed values, its key read from the frame's
own `pc_read_value` so the decoder binds the cycle to the table rather than a copy of it
to a copy of the table. **The selector is the row's pc mask** — its liveness
(`docs/spec/memory.md` §2.1) — and a switched-off row looks up the `MINUS_ONE` padding
tuple of §4.

The tuple carries **one packed mask column**, and **one-hotness comes from the table's
domain and from nothing else**. Booleanity permits any subset of bits, the empty one
included, and on an all-zero mask every gated constraint goes vacuous and `rd` is free;
split the mask into independent boolean columns and the property is lost silently. The
legal set is declared per family and is not always one-hot. Booleanity of any bit a
circuit *extracts* from the mask still comes from its own `x² = x` gate.

**The decoder query is in the artifact's lookup list like every other lookup**, and the
artifact's lookup count is that list's length. A decoder query stored beside the list
would make every tool walking it miss the most important lookup in every family.

## 11. The construction rules

`constraints::lookup` refuses, at the artifact's construction, beside
`CircuitArtifact::validate` and `constraints::memory::check_memory`:

- a range channel whose bound exceeds `trace_vars` (§3);
- a channel with a table and a multiplicity column but no lookup;
- a lookup whose tuple width is not its channel's table width;
- a tuple position above 0 whose coefficient is not 1 or which carries a constant — which
  `validate` refuses too, so a decoded artifact is caught as well (§5);
- a tuple wider than `lookup_channel::MAX_TUPLE`, past which `β` has no slot.

`constraints::lookup::check_discharge` is **the discharge rule**: every lookup of the
artifact is the denominator of exactly one gate-list-0 column, and no column is two
lookups'. It matches by normalized expansion, so a leaf renamed, reordered or rewritten
into an equal polynomial still counts. `checker::check_lookup_discharge` enforces the
same rule by evaluation at pseudo-random points, sharing no code with it.

`constraints::lookup::check_copowers` is **the copower-pairing assertion**: every column
a copower scales also carries a direct range check of its own. A copower turns the
row-varying bound `x < p` into the fixed `x·p' < 2^32`, where `p·p' = 2^32`. That half
bounds nothing alone: `p'` is a unit in `Fr`, so `x = s·p'^{-1}` sweeps a coset of `2^32`
elements, almost none of them small integers, and the range check on `s` sees nothing
wrong. The scaled bound says `x` is under this row's width **given** `x` is bounded; only
the direct check establishes that. S18 and S19 consume it.

## 12. What the checker adds

- `checker::channel_sums` recomputes every channel's fractional sum and denominator
  product natively, re-deriving the gating and the compression from §4 and §5 rather than
  from `constraints::lookup`. It folds fractions rather than inverting per row — a channel
  of `2^20` rows would otherwise cost millions of inversions, and the fold is also a
  different algorithm from the balanced tree it checks. It names a zero denominator, and
  reports every row whose gated tuple no table row answers.
- `checker::channel_roots` reads the root pairs from the materialized top layer, and
  `checker::check_channel_roots` holds them to the native recomputation: `den` is the
  product of every leaf denominator and `num` is `sum · den`.
- `checker::violated_lookups` stays the **range** channels' native evaluator, per row. A
  table channel's membership is a statement about the whole table and not about one row,
  and `channel_sums` is its evaluator.

## 13. What this rests on

- **Every gated tuple is a table row** rests on the LogUp identity over a `g` drawn
  after every column is committed (§2), on boolean selectors (§2), and on the root check
  being both conditions (§8).
- **One channel, one table** rests on the width rule of §11: every lookup of a channel
  compresses to a value that channel's table can hold.
- **No tuple of one packed table is a tuple of another** rests on disjoint key ranges
  (§9) and on the `+ 1` offset keeping every real entry off the neutral tuple (§4).
- **A row that looks up nothing costs nothing** rests on the neutral entry being a real
  table row whose multiplicity counts it (§4, §7).
**What the discharge rule does and does not say.** `check_discharge` establishes that every
lookup of the artifact is the denominator of exactly one gate-list-0 column. It does **not**
establish that that column feeds its channel's fraction tree rather than another's: the
trees' shape is the constructor's, not something the artifact records separately. That
direction is completeness, not soundness — a tree missing a fraction, or carrying one from
another channel, is a channel an honest prover cannot balance — and the same reasoning
covers the `ChannelSpec`s themselves, which a caller supplies and the artifact does not
record. A verifying key conveys the artifact **and** the specs the family was built with;
what binds the setup columns to the tables they are supposed to be is program identity
(`docs/spec/memory.md` §6.2), not anything here.

- **Owed by later stages.** S16 wires the channels into the real shard transcript — the
  commitments, then `g` and `β` under `LOOKUP_CHALLENGE`, then the local challenges — and
  into the one Mercury opening per shard; it also runs `check_discharge` and
  `check_copowers` where a proving or verifying key is loaded, and raises
  `DEFAULT_HEIGHTS[ATOMICS]` to a height its timestamp channel fits (§3). S17 and S18
  consume `U16GetSign` and the copower assertion.
