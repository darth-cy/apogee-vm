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
fills them, and never reads one from a proof. It reads `W` — the decoder tuple's width —
from the **artifact**, not from its caller: a caller passing the wrong `W` would leave
every decoder padding row's gate meaning something else.

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
execution family (`docs/spec/memory.md` §2.4). Six of the seven defaulted there already,
and `constants::family::DEFAULT_HEIGHTS[ATOMICS]` was `2^16` until **S19 raised it to
`2^20`** with the circuit that needs it (S16 answer 7, `docs/spec/memory-ops.md` §7.1). No
family that runs cycles may default below the floor. Since S19 `family_circuit`'s
minimum-height arm names **all seven** execution families, so a key naming any of them at
`2^16` or `2^18` — both on the menu — gets `None` and a clean `Err` at load rather than
reaching this channel's assertion and panicking inside `VerifyingKey::check`.

## 4. Gated keys

A lookup expression **cannot be conditional**: it is a linear form evaluated on every
row, so a row whose key is meaningless must still produce a tuple the table holds. The
selector is what sends such a row somewhere neutral, and the three conventions are:

| channel kind | gated tuple position `j` | neutral tuple |
| --- | --- | --- |
| range | `s·e_j` | `0`, which is a real and in-range entry |
| generic | `s·(e_0 + 1)` at `j = 0`, `s·e_j` above | the all-zero `ZeroEntry` row |
| decoder | `s·(e_j + 1) − 1` | `MINUS_ONE` in every column |

**The `+ 1` on a table channel's key** is what keeps every real *table entry* off the
all-zero tuple. Without it, a table whose key 0 maps to a nonzero value has no all-zero
row at all, and adding a `ZeroEntry` beside a real key-0 entry puts two rows at one key —
a cheating prover then reads the neutral value where the real one lives. The offset
reserves the all-zero tuple for the neutral row and shifts the real domain up by one.

**The converse is a precondition, not a consequence.** The gating sends a row whose
selector is 0 to the neutral tuple; it does **not** stop a row whose selector is 1 from
reaching it. A selected row whose key expression evaluates to `−1` gates to
`1·(−1 + 1) = 0`, and with its remaining columns 0 the whole tuple is the `ZeroEntry`,
which is a table row: the channel balances and the row has "looked up" the neutral entry
instead of a real one. Nothing in a LogUp channel can prevent that, because the channel's
only claim is membership.

So: **every key a table channel looks up is bounded elsewhere**, into its own table's key
range, by the range convention of `docs/spec/memory.md` §7 or by the columns it is built
from. That bound is what does two things the channel cannot. It keeps a selected row's key
away from the neutral value. And it is what makes the disjoint key ranges of §9 mean
anything: an unbounded `a` in an AND lookup's key `a + AND_BASE + 1` reaches
`SIGN_BASE + h + 1` for any `h`, so the row can assert `a AND b = c` by landing on a
`U16GetSign` entry — the *tables* are disjoint, the *keys a row can produce* are not. A
family that reads a value out of a table channel without bounding the key it looked up has
not proved what it thinks: it has proved that *something* is in the table. S15's combined
toy leaves `sign_h` and `and_a` unbounded on purpose — it is a toy for the channels, not a
family — so the forgery above works there, and
`crates/checker/tests/logup.rs::an_unbounded_key_can_reach_the_neutral_entry` is the
control that shows it. S17 and S18 own the bounds.

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

| leaf | position | `num` | `den` |
| --- | --- | --- | --- |
| the table | 0 | `−mult` | `T + g` |
| row lookup `l` | `1 + l` | `1` | `E_l + g` |
| padding | after them | `0` | `1` |

The leaf level is padded to a power of two with the neutral fraction `(0, 1)`. The row
side and the table side are separate leaves, and **the table's is first**, so that the
tree's first pair-addition — leaves 0 and 1 — is literally
`1/(w_0 + g) − mult/(T + g)`. Put it last and that node appears nowhere in a channel with
more than one lookup, because the row fractions pair with each other.

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

**`padding.row` is not a row a prover writes.** It is a row on which every row-local
relation holds, which is what `checker::check_padding` and the product-tree clause are
asked of; a channel-carrying circuit's own inactive rows carry whatever counts their
multiplicity columns hold there, and those are not 0. A witness builder that zeroed a
multiplicity column on inactive rows would leave every channel unable to balance.
`docs/spec/gkr.md` §4.3's "still not covered" note names this beside the setup values it
already named.

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

`program::lookup_tables::generic_table` packs the tables a wide field still needs into one
committed setup table of `GENERIC_WIDTH = 3` columns — the key, then two value columns, a
narrower table zero-padded to the widest's width:

```text
row 0                     the ZeroEntry, all zero
rows 1 ..= 2^16           AND:         (AND_BASE   + a + 1,  b,        a & b)
rows 2^16+1 ..= 2^17      U16GetSign:  (SIGN_BASE  + h + 1,  h >> 15,  0)
rows 2^17+1 ..= 2^17+32   ShiftPowers: (SHIFT_BASE + s + 1,  2^s,      2^(31 − s))
rows above                the ZeroEntry again, multiplicity 0
```

`AND_BASE = 0`, `SIGN_BASE = 256` and `SHIFT_BASE = SIGN_BASE + 2^16` give the three
tables pairwise disjoint key ranges, so no tuple of one is a tuple of another. 131,105
rows: a circuit carrying them is at `2^18` or more, which every execution family already
exceeds (§3).

**The table grows; its home does not.** S18 appended `ShiftPowers` here rather than giving
it a channel of its own or a second triple in the verifying key. Every key carries one set
of the table's three commitments and the SRS digest covers them
(`docs/spec/jump-branch-slt.md` §6), so a table that grows moves those three commitments,
the SRS digest and every existing key's bytes — and nothing else. Identity binds none of
it. A later stage appending a fourth table pays the same price and no more.

**The `ZeroEntry` row is a property of the table's contents, not of the artifact**, which
holds no table values at all — only the addresses its gates read. So it is checked where
the columns are built: `trace::build_multiplicities` refuses a channel whose table does
not hold every gated tuple looked up, and on a table with no all-zero row that is every
switched-off row's neutral entry, naming the channel. There is nothing a construction
rule over the artifact could say about it.

**`U16GetSign` is committed**, not closed-form. S17 and S18 consume it by name. It is
load-bearing in a way it was not over a small field: with a whole word in one column its
top bit is no longer a column that already exists, so every sign comes from here.

**A table's domain bounds what its row fixes, not the key that chose the row.** A lookup
that holds has matched *some* row of the packed table; which sub-table's row it is follows
from the key's own bound and from nothing else (§4). So `ShiftPowers`' 32 rows fix `pow` and
`copow` for an amount the shift family has already held to `[0, 32)`, and the AND table's
rows fix `b` and `a & b` for a key it has already held below 256
(`docs/spec/shift-bitwise.md` §3.3). The highest sub-table's domain does bound its own key
besides, every key past its last row matching nothing at all — but that is a fact about the
packed table's layout, which appending a sub-table changes, and no family leans on it.

**Why `ShiftPowers`' second value is halved.** The copower a residue bound multiplies by is
`2^(32 − s)`, which at `s = 0` is `2^32` and does not fit these columns' `u32` backing. The
table stores `2^(31 − s)` and the two gates that read it carry the compensating factor 2, so
`pow·copow = 2^31` is `pow·(2·copow) = 2^32`. `constants::generic_table::SHIFT_COPOWER_BITS`
is that exponent.

The taxonomy stays small on purpose. XOR and AND are positional — a wide field says
nothing extra about a byte's seventh bit, and S18 derives both XOR and OR from the AND
table alone — and everything that only existed to work around a small field retires into
arithmetic gadgets in later stages.

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
- a tuple wider than `lookup_channel::MAX_TUPLE`, past which `β` has no slot;
- a multiplicity that is not a **witness** column, so a channel cannot be counted by a
  setup column fixed before `g` and `β` are drawn;
- an empty channel list at `frame_with_channels_artifact`, which would be a circuit whose
  every obligation — a frame carries `2w` of its own — is discharged by nothing.

**What is not a construction rule.** §4's `ZeroEntry` row is a property of the table's
*values*, and an artifact holds table *addresses*: that a committed table really has an
all-zero row cannot be decided here. It is caught at witness build, where
`trace::build_multiplicities` refuses a tuple its table does not hold and every padding
row looks up the neutral entry — so a table missing it fails on the first shard, naming
the trace rather than the artifact. Likewise §4's precondition, that a key is bounded
into its own table's range, which the channel cannot supply (§13).

`constraints::lookup::check_discharge` is **the discharge rule**: every lookup of the
artifact is the denominator of exactly one gate-list-0 column, and no column is two
lookups'. It matches by normalized expansion, so a leaf renamed, reordered or rewritten
into an equal polynomial still counts. The count is **per channel**: the two range
channels gate and neutralize identically (§4), so one lookup's denominator gate can be
another channel's leaf byte for byte, and where the caller names the channels the rule
counts inside each lookup's own cone — which also turns a lookup whose only match is in
another channel's tree into a misrouted obligation rather than a missing one. A channel's
**table fraction** is counted the same way and in the same cone: exactly one column of the
channel's own tree is `T + g` over the table its spec names, with `−mult` directly before
it. Counting that one over the whole gate list instead would accept two channels holding
each other's table fraction — each tree still carries one apiece, each numerator is still
beside its denominator, and only the cone says which tree each landed in — and would
refuse two channels that legitimately share a table.
`checker::check_lookup_discharge` enforces the lookup half by evaluation at pseudo-random
points, sharing no code with it; the table half's twin is `checker::check_channel_roots`,
which rebuilds each channel's root from the spec's own table and multiplicity, so a
channel computing with another's table fraction fails there — but only once the columns
are materialized, where `check_discharge` reads the artifact alone.

`constraints::lookup::check_copowers` is **the copower-pairing assertion**: every column
a copower scales also carries a direct range check of its own. A copower turns the
row-varying bound `x < p` into the fixed `x·p' < 2^32`, where `p·p' = 2^32`. That half
bounds nothing alone: `p'` is a unit in `Fr`, so `x = s·p'^{-1}` sweeps a coset of `2^32`
elements, almost none of them small integers, and the range check on `s` sees nothing
wrong. The scaled bound says `x` is under this row's width **given** `x` is bounded; only
the direct check establishes that. S18 and S19 consume it; S19's `mem_subword` is its
heaviest user, with `high`, `sub`, `low` and the store source each carrying a scaled bound
and a direct one, and all three families passing `word_index_hi` to the check.

## 12. What the checker adds

- `checker::channel_sums` recomputes every channel's fractional sum and denominator
  product natively, re-deriving the gating and the compression from §4 and §5 rather than
  from `constraints::lookup`. It folds fractions rather than inverting per row — a channel
  of `2^20` rows would otherwise cost millions of inversions, and the fold is also a
  different algorithm from the balanced tree it checks. It names a zero denominator, and
  names every gated tuple no table row answers, at the lowest row producing
  each — a tuple several rows produce is listed once.
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
- **That a lookup is answered by its own table's entry, and not by the neutral row or by
  another table's**, rests on the key being bounded into that table's range — §4's
  precondition, which the channel itself cannot supply and which S17 and S18 own.
- **A row that looks up nothing costs nothing** rests on the neutral entry being a real
  table row whose multiplicity counts it (§4, §7).
**What the discharge rule does and does not say.** Given the specs, `check_discharge`
establishes that every lookup is the denominator of exactly one column of **its own
channel's** fraction tree, and that each channel's table fraction is a leaf of that same
tree: walking down from a channel's root pair is what makes the tree something the
artifact records rather than the constructor's private knowledge. It does **not** establish
that the specs are the ones the family was built with — which output pair is whose root,
which columns are a table, and which column counts it are all the caller's, and the
artifact records none of it. That direction is completeness, not soundness — a tree
missing a fraction is a channel an honest prover cannot balance — but a verifying key must
convey the artifact **and** the specs, or the rule has run against a description of a
different circuit. With an empty `specs` the column half runs alone, which is all an
artifact by itself can say, and the table half does not run at all.

**Identity does not bind the packed generic table, and until S17 nothing did.** What binds
a setup column to the table it is supposed to be is program identity
(`docs/spec/memory.md` §6.2), and identity's commitment list is each family's *decoded*
table plus `INIT_TEARDOWN`'s image column. §9's packed table is a **fourth kind** of
committed setup column, and `program::setup_commitments` does not commit it, so a
verifying key whose generic table has one poisoned cell — an AND row answering
`37 & 45 = 0` — recomputes the same identity digest, and every construction rule here
accepts it. That was a real gap, not a soundness argument. S15 listed it below as S16's,
S16 moved it to S17, and S17 closed it through the SRS digest (the status below). The
generic channel's guarantee is now conditional on the verifier's SRS digest being the
ceremony's, which it takes from a trusted channel.

- **Owed by later stages.** S16 wires the channels into the real shard transcript — the
  commitments, then `g` and `β` under `LOOKUP_CHALLENGE`, then the local challenges — and
  into the one Mercury opening per shard; it also runs `check_discharge` and
  `check_copowers` where a proving or verifying key is loaded, calls
  `trace::check_multiplicities` where the witness is built, brings the packed generic
  table into the identity recipe or the statement (above), and raises
  `DEFAULT_HEIGHTS[ATOMICS]` to a height its timestamp channel fits (§3). S17 and S18
  consume `U16GetSign` and the copower assertion.

**Status at S16.** The channels are wired into the shard transcript and its one opening
(`docs/spec/shard-proof.md` §4, §5), and `check_discharge` runs at every key load, inside
`VerifyingKey::check`. Three items moved, each recorded in `docs/handoff/S16-add-sub.md`:

- **The packed generic table's binding is S17's**, by the owner's decision: "The generic
  table becomes authenticated when the first family actually consumes the generic lookup
  channel. Bind the exact packed-table commitment into the proof/constraint-system
  statement or transcript before lookup challenges are derived. Do not add it to S16's
  program-image identity merely because the table already exists." The add/sub family
  does not look the generic channel up, so no S16 statement depends on the table.
- **`check_copowers` runs where a family scales by a copower**, S17 and S18: the add/sub
  family scales nothing, and the call over an empty list checks nothing.
- **`trace::check_multiplicities` is not on the proving path.** The prover counts every
  multiplicity column with `trace::build_multiplicities` and nothing else, so the check
  would recount the build it just ran. A multiplicity column from any other source — the
  tamper harness's — is the verifier's to refuse, and `crates/checker/tests/tamper.rs`
  shows it is, as `Lookup`.
- `DEFAULT_HEIGHTS[ATOMICS]` is S19's (§3), and S19 raised it.

**Status at S17.** The jump/branch/slt family is the first to read the generic channel —
two `U16GetSign` lookups, `docs/spec/jump-branch-slt.md` §3.2 — and with it:

- **The packed generic table is bound through the SRS digest**, the owner's decision at
  S17, and so before any lookup challenge, as the owner's words above ask. Every verifying
  key carries the table's three commitments as one triple, `VerifyingKey::generic_table`,
  whether or not any of its families reads the channel. The SRS digest absorbs the triple
  after the `SrsVerifier` (`docs/spec/shard-proof.md` §3), and the global transcript
  absorbs the digest at G2, so every challenge of the statement, and of every shard seeded
  from it, follows the table. A family whose circuit reads the channel names the table as
  its setup columns right after identity's, and its one batched opening opens those
  columns against the key's triple (`docs/spec/shard-proof.md` §5.1). Identity still does
  not bind the table.
- **The triple is a constant of the ceremony**: the same three points at every menu
  height from `2^18`, because the table is zero past its rows — 131,105 since S18 — and a commitment
  reads the table as coefficients. So one trusted SRS digest pins both the points every
  pairing reads and the table every generic lookup reads. The ceremony's triple is pinned
  in `crates/program/tests/vectors/generic_table.txt`
  (`docs/spec/jump-branch-slt.md` §6).
- **§4's precondition is met for its keys**: each `U16GetSign` key is built on a high
  halfword the `RANGE16` channel bounds, so no key reaches the `ZeroEntry` or an AND key.
- **`check_copowers` runs** over `next_pc`, whose evenness obligation scales its low
  halfword by `1/2`, inside the family's constructor — and so at every key load, which
  rebuilds the registry's circuit (`docs/spec/shard-proof.md` §7.2).
- **The generic table's constants moved** to `constants::generic_table` (`WIDTH`,
  `AND_BASE`, `SIGN_BASE`), because a circuit, which cannot depend on `program`, now builds
  a key into it; `program::lookup_tables` keeps every name as an alias.
