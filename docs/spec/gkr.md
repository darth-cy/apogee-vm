# The GKR engine: layered circuits, the artifact, and the backward pass

Frozen as of S13; S14 amended §2.1, §4, §4.1, §4.2, §4.3 and §5.1, and S15
amended §1, §2.1, §3, §4.1, §4.2, §4.3 and §5.3. Changing anything here is a
protocol-version change.

Implementation, by crate:

| crate | what | build |
| --- | --- | --- |
| `crates/constraints` | the circuit as data: addresses, gate shapes, the artifact, its laws and wire form | `#![no_std]` + alloc |
| `crates/gkr-verify` | the verifier half: the gate kernel, the layer sumcheck's verifier, `verify`, and every type `verify` touches | `#![no_std]` + alloc; the recursion guest links it |
| `crates/gkr` | the prover half: the forward pass, its self-check, the layer sumcheck's prover, `prove`; re-exports `gkr-verify` whole | `std` + rayon |
| `crates/checker` | the standalone validators, the witness-row evaluator, the cross-check, the dump | `std` |

Depends on `docs/spec/transcript.md` for the duplex and its typed framing, on
`crates/poly` for the index convention, and on `crates/sumcheck` for the
4-coefficient round format and the `SumcheckProof` shape.

---

## 1. The layer model

A circuit has layers `0..=N`, `N >= 1`. Layer `k` is `w_k` columns, each a
multilinear in `n_k` variables — a table of `2^{n_k}` rows under the frozen
index convention (variable `j` is bit `j`).

- **Layer 0** is the base: the committed columns `M[i]`, `W[i]`, `S[i]` in the
  artifact's layout, plus the virtual tables `V[kind]` it lists. `n_0` is the
  artifact's `trace_vars`; `w_0` counts the committed columns only.
- **Gate list `k`** (`0 <= k < N`) reads layer `k` and writes layer `k + 1`.
- **Layer `N`**, the top, has no gate list. It holds exactly the outputs.

A gate list is one of two kinds:

| kind | `n_{k+1}` | `w_{k+1}` | its producing gates |
| --- | --- | --- | --- |
| row-wise | `n_k` | any | `out(y) = G(inputs at y)` for every row `y` |
| halving | `n_k - 1` | `w_k` | a **halving shape** over layer `k`'s columns, each operand read at both children |

A halving list **halves every column of its layer**: it writes exactly as many
columns as it reads, and `nothing_dropped` (§4.2) refuses a list leaving one
unread. The child bit is the **highest** variable of layer `k`. A halving list
has no enforcing gates and no cached entries, reads inner-layer columns only
(never layer 0), and needs `n_k >= 1`. A row-wise list has no halving shape.

There are two halving shapes. `TreeProduct { x }` is one level of a **product
tree**, `out[i] = x[i]·x[i + 2^{n_k−1}]`, and entry `j` of a product tree halves
column `j` into column `j`. `TreeCross { p, q }` is the numerator of one level of
a **fraction tree** (`docs/spec/lookup.md` §6), `out[i] = p[i]·q[i + h] +
p[i + h]·q[i]` with `h = 2^{n_k−1}`, and it reads its denominator beside its own
column — which is why an entry is no longer pinned to the column at its own
offset. S15 relaxed that; nothing else about the halving model moved, and the
claim layout, L3's message and L4's line-folding are what they were.

Every relation is written in one fixed template, whatever its shape:

```text
producing (row-wise)   L{k+1}[j](x) = Σ_y eq(x, y) · G(inputs at y)
producing (halving)    L{k+1}[j](x) = Σ_y eq(x, y) · G(layer k at (y, 0) and (y, 1))
enforcing              0 = G(inputs at y)   for every y
```

## 2. Addresses

`PolyAddress` is the only way a polynomial is named. Short notation, used in
every dump and diagnostic:

| variant | notation | what |
| --- | --- | --- |
| `Memory(i)` | `M[i]` | committed column, memory-argument subtree |
| `Witness(i)` | `W[i]` | committed column, witness subtree (not memory-tied) |
| `Setup(i)` | `S[i]` | committed setup column |
| `Virtual(kind)` | `V[row]` | virtual setup table, closed form, never materialized or committed |
| `Inner { layer, offset }` | `L{k}[j]` | column `j` of inner layer `k >= 1` |
| `Scratch(i)` | `scratch[i]` | an intermediate value in the flat constraint list |
| `Cached { layer, offset }` | `C{k}[j]` | shared sub-expression `j` of gate list `k` |

Where each may appear:

- **gates** (the layered encoding): `M`, `W`, `S`, `V` in gate list 0;
  `L{k}` in gate list `k >= 1`; `C{k}` in gate list `k`. Never `scratch`.
- **relations** (the flat encoding): `M`, `W`, `S`, `V`, `scratch`. Never `L`
  or `C`.
- **the scratch bijection** maps every `scratch[i]` to one `L{k}[j]` and covers
  every inner address exactly once.

### 2.1 Virtual tables

Four closed forms and one table family. Each closed form **is its multilinear
extension** over `n_0` variables, and the kind tag is how the closed form is in
the artifact:

| kind | notation | value at row `y` | closed form |
| --- | --- | --- | --- |
| `RowIndex` | `V[row]` | `y` | `Σ_j 2^j · y_j` |
| `RamLive` | `V[ram_live]` | 1 if `y ≥ 2^14`, else 0 | `1 − Π_{j=14}^{n_0−1} (1 − y_j)`, which is 0 when `n_0 ≤ 14` |
| `Range19` | `V[range19]` | `y mod 2^19` | `Σ_{j < min(19, n_0)} 2^j · y_j` |
| `Range16` | `V[range16]` | `y mod 2^16` | `Σ_{j < min(16, n_0)} 2^j · y_j` |
| `Schedule(k)` | `V[sched_k]` | `c_k[y mod 2^b]` | `Σ_{i < 2^b} eq(y_0..y_{b−1}, i) · c_k[i]` |

14 is `constants::memory::RAM_LIVE_BIT`. `RamLive` is S14's, the mask on RAM
window 0's rows below `RAM_ORIGIN` (`docs/spec/memory.md` §3.3); its closed form
costs `n_0 − 14` multiplications and is 0 or 1 on the cube by construction.
`Range19` and `Range16` are S15's, the range channels' tables
(`docs/spec/lookup.md` §3); each is `[0, 2^BITS)` exactly when `n_0 ≥ BITS`, and
a narrower set below that, which is why a circuit narrower than a range
channel's bound is refused.

`Schedule` is S22's, and it is the one kind whose extension is a **sum over a
period against a constant vector** rather than a closed form in the row index
alone (`docs/spec/ecrecover.md` §6.2). `b` is
`log2(constants::ecrecover::ROWS_PER_INVOCATION)`, the variables of one
delegation invocation's row block, and `c_k` is column `k` of
`constraints::ecrecover::tables` — the step schedule, the same for every
invocation. It reads only the low `b` variables: that independence of everything
above them is what **step-periodic** means, and a circuit with fewer than `b`
variables has no block to be periodic over and is refused.

Two things keep it affordable, both measured. A term with `c_k[i] = 0` drops out
of the sum, so a column costs its *nonzero* count and not `2^b`; and each column
is stored offset by its modal value, which costs one addition here — `eq` sums
to 1 over the cube, so `Σ_i eq(y, i)·(m + d_i) = m + Σ_i eq(y, i)·d_i` — and
makes the common entry the zero that drops out. Together those take the schedule
from 163,840 constants to 24,882 stored pairs.

`Schedule` is also the one kind that carries **data**: its constants are
generated source that `gkr-verify` links, and the recursion guest links
`gkr-verify`. That is the price `ecrecover.md` §6.2 weighed against committing
the schedule as setup columns, which would have moved every verifying key's SRS
digest and bytes and given a key builder something to substitute. A virtual
table is never committed, so there is nothing there to substitute, and
`family_circuit` binds it the same way it binds a gate list.

A virtual table has layer 0's height. It is **never materialized**: the forward
pass evaluates the closed form per row, the prover at every point a round needs
(`(bound, X, bits)` at `X = 0, 1`), and the verifier at the bound point. It is
never committed, never claimed, and never returned as a `BaseClaim`. A later kind
is admissible only if its MLE has a closed form — or, as `Schedule` has, a
period and a constant vector — at every such point.

## 3. Gate shapes

`GateDef` is a closed enum. Coefficients are `Coeff::Literal(Fr)` or
`Coeff::Challenge(slot)`, a slot of `constants::challenge_slot` resolved from
`ExternalChallenges` at forward, prove and verify time. A challenge is degree 0.

| # | variant | formula | operands, in kernel order |
| --- | --- | --- | --- |
| 0 | `Linear { terms, constant }` | `Σ c_i·x_i + c_0` | `x_1..x_t` |
| 1 | `Product { coeff, left, right }` | `c·x·y` | `x, y` |
| 2 | `MaskIntoIdentity { input, mask }` | `x·m + (1 − m)` | `x, m` |
| 3 | `AffineProduct { left, left_constant, right, right_constant }` | `(Σ a_i·x_i + a_0)·(Σ b_j·y_j + b_0)` | `x_1..x_t, y_1..y_u` |
| 4 | `TreeProduct { input }` | `x(·,0)·x(·,1)` | `x(·,0), x(·,1)` |
| 5 | `Quadratic { constant, linear, products }` | `c_0 + Σ a_i·x_i + Σ b_j·y_j·z_j` | `x_1..x_t, y_1, z_1, .., y_u, z_u` |
| 6 | `TreeCross { left, right }` | `p(·,0)·q(·,1) + p(·,1)·q(·,0)` | `p(·,0), p(·,1), q(·,0), q(·,1)` |

A gate's coefficients, wherever they are listed, are in the order of its fields;
`Quadratic`'s are `c_0, a_1..a_t, b_1..b_u`. `Quadratic` is every degree-2
polynomial written term by term, which is what lets one gate say
`a·b + c·d − e·f`: an `AffineProduct`'s quadratic part is a product of two
linear forms, and that one is not.

**The kernel** — `gkr_verify::eval_gate`, one evaluation per variant over operand
values in that order — is the semantic authority, and nothing else evaluates a gate.
The engine's passes — the forward pass, the self-check and both halves of the layer
sumcheck — reach it through `gkr_verify::ResolvedList`, which resolves a gate list's
operands once and which `gkr_verify::gate_values` and `summand` wrap; the checker's witness-row evaluator, padding check and Law 4 sampler call
it directly over the flat relations. `constraints::CATALOGUE` records, per variant, where it is
defined and evaluated, what it reads and writes, its formula in the template, and
what it is for.

### 3.1 Cached entries and the degree ceiling

A cached entry `C{k}[j] = H` is a sub-expression of gate list `k`, reading
layer-`k` columns only (never another cached entry), and named by at least one
gate of its list. It is **substituted** into every gate that names it: it is not
a column, has no table, is never claimed, contributes nothing to a width or to
the gate totals, and does not appear in `LayerValues`. The forward pass evaluates
`H` once per row. The sumcheck prover evaluates `H` at every evaluation node of
every round from the columns' values there, and **never binds it as a table**:
binding a table gives the multilinear extension of `H`'s values, which for a
degree-2 `H` is not `H` of the columns' extensions.

**Degree** is counted after substitution: a column is degree 1, a challenge
degree 0, `C{k}[j]` the degree of its expression. A `Quadratic` is as wide as its
widest term — a linear term `d(x_i)`, a product `d(y_j) + d(z_j)` — and degree 0
when it has neither. Every gate, every cached
expression, and every relation must be degree ≤ 2 in the layer it reads.
`Product(C, y)` with `C` of degree 2 is the degree-3 gate construction refuses.

**A relation that will not fit is split across layers** with an intermediate
column: the toy's `a·b·masked_m` is `ab = a·b` in layer 1, then
`abm = ab · masked_m` in layer 2.

**Cache-free compilation** (`CircuitArtifact::inline_cached`) rewrites every
reference into its inline form and empties the cached lists. The one inlinable
reference is a `Product` with exactly one factor naming a `Linear` cached entry:

```text
Product { c, C, y }  →  AffineProduct { C.terms, C.constant ; [(c, y)], 0 }
Product { c, x, C }  →  AffineProduct { [(c, x)], 0 ; C.terms, C.constant }
```

Anything else — both factors cached, a cached entry that is not `Linear`, a
reference from any of the other five shapes, a `Quadratic` included — refuses to
inline. A gate naming no cached entry, of any shape, is left as it is. Layer count, widths, gate
totals, forward-pass values and proofs are unchanged.

## 4. The artifact

`CircuitArtifact` holds, in wire order:

| field | what |
| --- | --- |
| `format_version` | `1` since S14; S13's was `0`. A postcard layout is not self-describing, so this is how a reader refuses an artifact of another layout instead of misreading it |
| `coefficient_encoding` | `0` = every `Fr` canonical 32-byte little-endian; the only value, and how the file declares it |
| `trace_vars` | `n_0`; the trace length is `2^{trace_vars}`, at most `2^30` so `1 << n` fits a 32-bit `usize` |
| `memory`, `witness`, `setup` | the committed layout per subtree, one name per column |
| `virtuals` | `(kind, name)`: the virtual tables the circuit reads |
| `layers` | gate list `k` for `k = 0..N` |
| `relations` | the flat constraint list |
| `lookups` | the range obligations: format 1's element, which carries a selector (`docs/spec/memory.md` §7); S15 discharges them |
| `scratch` | `(name, L{k}[j])`: the scratch bijection |
| `outputs` | the output map: a permutation of the top layer, in `OutputClaims` order |
| `padding` | `(row, zero_row_valid)`: the padding contract, §4.3 |

```text
LayerSpec   = (halving, num_vars, width,
               cached:    [(name, C{k}[j], GateDef)],
               producing: [(relation, L{k+1}[j], GateDef)],
               enforcing: [(relation, GateDef)])
Relation    = (name, output: Option<scratch index>, GateDef)
LookupExpr  = (name, channel, selector: PolyAddress, tuple: [GateDef])
```

`num_vars` and `width` are the layer **written**, `k + 1`: derived values stored
for readers, which Law 2 holds to what the gates imply. The `j`-th cached and
producing entry sit at `C{k}[j]` and `L{k+1}[j]`.

A lookup holds on a row where its selector is 0, or where its tuple is in its
channel's table. Every channel of `constants::lookup_channel` is a range channel
at S14: its tuple is one expression, which holds when its canonical integer is
below `2^BITS[channel]`.

### 4.1 Wire form

`postcard` over the tuple above, hand-written serde. A `u32` is a postcard
varint; a `u8` tag and a `bool` are one raw byte; `Option` is postcard's tag; a sequence is a varint
length then its elements; a name is a `str`; an `Fr` is its 32 canonical bytes
with no length prefix (`crates/field`'s `[u8; 32]` tuple).

```text
VirtualKind     u32                           0 RowIndex, 1 RamLive, 2 Range19, 3 Range16
PolyAddress     (tag u8, a u32, b u32)        tags: 0 M, 1 W, 2 S, 3 V, 4 L, 5 scratch, 6 C
                                              V: a = kind; L, C: a = layer, b = offset;
                                              every unused field is 0
Coeff           (tag u8, slot u32, value Fr)  0 Literal (slot 0), 1 Challenge (value 0)
GateDef         (tag u8, split u32, coeffs [Coeff], operands [PolyAddress])
                0 Linear         split 0, coeffs c_1..c_t c_0,              operands x_1..x_t
                1 Product        split 0, coeffs c,                         operands x y
                2 Mask           split 0, coeffs none,                      operands x m
                3 AffineProduct  split t, coeffs a_1..a_t a_0 b_1..b_u b_0, operands x_1..x_t y_1..y_u
                4 TreeProduct    split 0, coeffs none,                      operands x
                5 Quadratic      split t, coeffs c_0 a_1..a_t b_1..b_u,     operands x_1..x_t y_1 z_1 .. y_u z_u
LookupExpr      (name str, channel u32, selector PolyAddress, tuple [GateDef])
```

A `Quadratic` decodes only when `t` is at most the operand count, the operands
after the first `t` pair up, and there are exactly `1 + t + (operands − t)/2`
coefficients. Tags are append-only. `from_bytes` is total — it returns an error and never
panics, whatever it is handed, and reserves nothing an untrusted length asks for
— and accepts exactly the bytes `to_bytes` writes: it re-encodes and compares. It
reads `format_version` first and refuses any version but 1 before decoding
anything after it, because the layout that follows is the version's. It checks no
law: a decoded artifact may break every one, which is what lets the
checker be handed one.

### 4.2 The laws

Enforced twice: by `CircuitArtifact::validate` in `constraints`, which whatever
builds or loads an artifact calls, once, and by `checker`'s standalone
validators, which share no code with it. The engine's entry points assume an
artifact that has passed `validate` and do not check it again (§5.1).

1. **Locality.** Every operand of gate list `k` is at layer `k` in the sense of
   §2 (base and setup counting as layer 0), in range, and a cached operand is one
   of list `k`'s own entries.
2. **Derived width.** A stored `width` is the number of producing gates, their
   outputs are exactly `L{k+1}[0..width)` in order, and a stored `num_vars` is
   `n_k` or `n_k − 1` by the list's kind. A halving list's width is `w_k`, and
   every entry of one is a halving shape over layer `k`'s columns. Layer 0's
   size is the committed layout.
3. **Top layer.** The last list writes layer `N`, which has no list, and
   `outputs` is a permutation of `L{N}[0..w_N)`: nothing more, nothing less.
4. **Single source of truth.** Every relation is named by exactly one gate
   entry and every gate entry names one relation (equal cardinality); a
   producing entry's output maps to its relation's scratch output through the
   bijection, an enforcing entry's relation has none; and the relation and the
   gate are the same polynomial — scratch mapped to `L` through the bijection,
   cached entries substituted. `constraints` compares expanded normal forms
   (monomials over columns, children and challenge slots, merged and sorted);
   `checker` compares kernel evaluations at independent pseudo-random points.

Besides the laws, `validate` refuses: degree above 2 (§3.1); a halving list
breaking §1's rules; a relation operand outside §2's set; a scratch slot that is
not exactly one producing relation's output; an inner column below the top that the
next list never reads — decided on the gates' normalized expansions, so a cancelling
or zero-coefficient term reads nothing — a cached entry no gate names, and an
enforcing gate whose normalized expansion is zero, each a relation constructed and
then dropped, on which nothing depends; an empty name, one outside
`[a-z0-9_]`, or one used twice anywhere in the artifact; an unknown challenge
slot; a `padding.row` whose length is not `w_0`; a format version other than 1 or
a coefficient encoding other than 0; `trace_vars > 30`. Every refusal is a
`ConstraintError` naming the law, gate or address.

**The lookup rules** (S14, `docs/spec/memory.md` §7; S15, `docs/spec/lookup.md`).
`validate` refuses a lookup whose channel is not one of
`constants::lookup_channel`; whose tuple is not exactly one expression on a range
channel, or is empty or wider than `lookup_channel::MAX_TUPLE` on a table one;
whose width differs from another lookup's of the same channel, since one channel
has one table; whose expression is not `Linear` with literal coefficients, its
constant included, over in-range `M`, `W`, `S` columns and virtual tables
`virtuals` lists; whose selector is not an in-range `M`, `W` or `S` column; or
whose **selector no enforcing gate of gate list 0 holds to booleanity**, without
which LogUp and the native reading of an obligation are different statements
(`docs/spec/lookup.md` §2). Its name is held to the name rule above. Each refusal
is a `ConstraintError` naming the lookup, and `checker::check_laws` enforces the
same rules with code of its own.

Names are documentation, never semantics, stored beside what they name rather
than derived from a position, so none can drift with a layer index. An artifact
is a struct literal of complete vectors followed by `validate`; there is no
incremental builder to push into after a collection point.

### 4.3 The padding contract

S13 has no gating: **every relation must hold on every row, padding rows
included.** `padding.row` is the committed columns' values on an inactive row,
in layout order. Computing the row-local scratch values from it — every
producing relation below the first halving list — makes every row-local
enforcing relation vanish, for every challenge value and every row index.

Since S15 that is a statement about the columns the contract reads, not about
every cell a prover writes on a padding row. A channel's **multiplicity** column
(`docs/spec/lookup.md` §7) counts a table value over the whole shard, padding
rows included, so it is nonzero on rows where `padding.row` says 0; it enters no
enforcing relation and no product tree, so neither clause below asks anything of
it, and a witness builder must not zero it to match `padding.row`. A circuit
with no channel is unchanged: there, `padding.row` is every committed cell of
every padding row, and `crates/checker/tests/multiset.rs` holds S14's frames to
exactly that.
`zero_row_valid` says whether the all-zero committed row has the same property.
The checker holds both statements to the relations, at pseudo-random challenge
values and row indices.

**The product-tree clause** (S14, master rule 7). For a family whose shards have
inactive rows, every column the first halving list reads — computed from
`padding.row` through every row-wise producing relation below that list — is
exactly 1, for every challenge value and every row index: an inactive row
contributes the multiplicative identity to every product. A RAM window family
(`docs/spec/memory.md` §3) has no inactive rows — every row is an address — so the
clause does not apply to it. Neither does it apply to a **fraction tree** (S15):
its identity is `(0, 1)` and a padding row is not inactive in a channel at all —
it contributes the channel's neutral entry, which the multiplicity column counts
(`docs/spec/lookup.md` §6) — so `checker::check_padding_identity` exempts every
column a `TreeCross` reads. `checker::check_padding_identity` holds an artifact
to the clause at pseudo-random challenge values and row indices; an artifact with
no halving list passes.

Still not covered: that the contract holds for the setup values a real padding
row carries rather than the ones `padding.row` names, and — since S15 — that a
real padding row's **multiplicity columns** carry what `padding.row` says. They
do not: a multiplicity counts table rows, not trace rows, and is nonzero on
inactive rows of a channel-carrying circuit (`docs/spec/lookup.md` §6).
`padding.row` is a row on which every row-local relation holds, which is what
this contract asks of it, and not the row a prover writes.

## 5. The backward pass

### 5.0 The types

All but the prover's are `gkr-verify`'s, re-exported by `gkr`.

| type | what |
| --- | --- |
| `ExternalChallenges` | `slot -> Fr`; `new`, `insert` (a slot once), `get` |
| `OutputClaims { tables }` | `tables[i]` is the full `2^{n_N}`-row table of `outputs[i]` |
| `BaseClaim { address, point, value }` | a committed column's claimed value at `point`, `point[j]` bound to variable `j` |
| `GkrProof { layers: Vec<SumcheckProof> }` | `layers[k]` is transition `k` |
| `GkrError` | §5.5 |
| `gkr::BaseLayer` | the committed columns by address, one per `M`, `W`, `S` address; `new` takes them as given |
| `gkr::LayerValues { base, layers }` | the forward pass's output: the base, then layers `1..=N` in offset order |
| `gkr::SelfCheckError { layer, row, relation }` | the first gate the materialized values break |

`gkr::forward` materializes every layer. `gkr::self_check` recomputes every gate
against those layers and names the first broken relation. It is a debugging hook,
not a step of proving: a caller may run it after `forward`.
`gkr::prove` does **not** run it and recomputes nothing: it proves whatever
`LayerValues` holds, and a verifier rejects what is wrong.

The layer sumcheck driver is two functions, and each owns step L2 only: the
caller draws L1's batch before it and absorbs L3's claims after it.

```rust
gkr::prove_sumcheck(eq_point: &[Fr], summand: &LayerSummand, tables: &mut LayerTables,
                    t: &mut Transcript) -> (Vec<[Fr; 4]>, Vec<Fr>)
gkr_verify::verify_sumcheck(claim: Fr, rounds: &[[Fr; 4]], t: &mut Transcript)
                    -> Option<(Vec<Fr>, Fr)>
```

The prover's summand is one gate list with its batch weights; the verifier's
returns the bound point and the last claim, which the caller holds to
`eq(eq_point, point) · S(values)`. The claim is not a prover input: an honest
round 0 sums to it by construction. The master's claim-merging sumcheck was to
extend this driver to a weighted sum of `eq` tables; S16 found no claims to merge —
a shard is one circuit and the backward pass leaves every committed column at one
point — and has none (`docs/spec/shard-proof.md` §5.3). The single point here is
the only one.

### 5.1 What the caller owes

- **Before** `prove` or `verify`, the caller has bound the base layer into the
  transcript (at S13 the tests absorb `sumcheck::witness_digest` of the committed
  columns; since S16 the shard transcript absorbs the commitments,
  `docs/spec/shard-proof.md` §4). The engine never absorbs base material.
- Every `ExternalChallenges` value is either drawn **after** everything its
  gates can reach is bound — every committed column on any path from a gate
  naming the slot down through the inner layers — or a **derived** value: a fixed
  function of such challenges and of statement data absorbed before them,
  computed by the verifier and never read from a proof.
  `constants::challenge_slot::MEM_WINDOW_CONSTANT` is the one derived slot at
  S14. At S13 the tests draw the toy's slot as
  `challenge_scalar(SUMCHECK_CHALLENGE)` immediately after the digest. This rule
  suffices for the GKR argument but not for the multiset argument, whose
  provenance rule is `docs/spec/memory.md` §8.
- The artifact is the verifier's, not the prover's: it is part of what a
  verifying key conveys.
- The artifact has passed `CircuitArtifact::validate`. `verify`, `forward`,
  `self_check` and `prove` do not check it again: validation belongs to a
  verifying or proving key, once, not to every proof, and the routine that loads
  a key calls it. No such routine exists at S13; the stage that introduces
  `VerifyingKey` must call `validate` there. On an artifact that breaks a law the
  engine's answer means nothing: it may panic, and `verify` may accept.
- The base, the layer values and the challenges have the artifact's shape.
  `forward`, `self_check` and `prove` check nothing about their inputs: soundness
  is `verify`'s alone, and a cheating prover runs none of the prover's code, so a
  malformed input costs only the honest prover — a panic where it is first read,
  or a proof or base claims that fail downstream.

### 5.2 The transcript schedule (frozen)

Both sides, in this order. Every squeeze is `challenge_scalar(tag)`. `p` is the
current claim point and `v_j` the claim on column `j` of the layer the next list
writes.

| step | op | tag | message |
| --- | --- | --- | --- |
| O1 | absorb | `GKR_OUTPUTS` (25, scalars) | `OutputClaims.tables` in output-map order, rows in index order, as **one** message of `w_N · 2^{n_N}` scalars |
| O2 | squeeze ×`n_N` | `GKR_OUTPUT_POINT` (26, challenge) | `p = r`, `r_i` bound to variable `i`; `v_j = tables[i](r)` for the `i` with `outputs[i] = L{N}[j]` |

then for `k = N − 1` down to `0`:

| step | op | tag | message |
| --- | --- | --- | --- |
| L1 | squeeze | `GKR_BATCH` (27, challenge) | `λ`; the claim is `c = Σ_j λ^j · v_j` |
| L2 | ×`n_{k+1}`: absorb, squeeze | `SUMCHECK_ROUND` (4), `SUMCHECK_CHALLENGE` (5) | the round cubic `[c0, c1, c2, c3]`, then `ρ_i`, binding variable `i` |
| L3 | absorb | `GKR_LAYER_CLAIMS` (28, scalars) | row-wise: `w_k` values, `L{k}[0..]` in offset order (at `k = 0`: `M`, `W`, `S` in layout order); halving: `2·w_k` values, `L{k}[j](ρ,0), L{k}[j](ρ,1)` per `j` |
| L4 | squeeze (halving only) | `GKR_CHILD` (29, challenge) | `τ`; `p = (ρ, τ)`, `v_j = (1 − τ)·L{k}[j](ρ,0) + τ·L{k}[j](ρ,1)` |

After a row-wise list `p = ρ` and `v` is L3's message. After `k = 0` the
`BaseClaim`s are `(M[i] | W[i] | S[i], ρ, value)` in layout order — all at one
point.

### 5.3 The layer sumcheck

Transition `k` proves `c = Σ_y eq(p, y) · S_k(y)` over `n_{k+1}` variables:

```text
row-wise   S_k(y) = Σ_j λ^j · G_j(inputs at y) + Σ_e λ^{w_{k+1} + e} · E_e(inputs at y)
halving    S_k(x) = Σ_j λ^j · G_j(layer k at (x, 0) and (x, 1))
```

`G_j` is the producing gate writing `L{k+1}[j]`; `E_e` is the `e`-th enforcing
gate of the list, whose claim is the constant `0`. **Enforcing claims share the
descending point.** `eq` is multilinear and every summand term degree ≤ 2 in the
layer below, so each round is a cubic, sent as exactly 4 ascending coefficients;
there is one round per variable of layer `k + 1`, and none is skipped.

The verifier checks round `i` as `g_i(0) + g_i(1) = claim`, sets
`claim = g_i(ρ_i)`, and after L3 checks

```text
claim = eq(p, ρ) · S_k(values)
```

where layer-`k` operands take L3's values, `V[row]` its closed form at `ρ`, a
cached entry its expression over those, and a challenge its slot. A failing
round or final check is `GkrError::LayerInconsistency { layer: k }`; a verifier
cannot tell a wrong descending claim from a violated enforcing gate, and does
not try.

**A zero claim is legal.** The stage prompt calls the driver's initial claim
"nonzero"; what it means is that the claim is an arbitrary batched value rather
than the constant 0 of S04's zerocheck. Outputs that are zero, or a list with
only enforcing gates above a width-0 layer, give `c = 0`, and an honest proof of
it verifies. A transition with `n_{k+1} = 0` has no rounds and its final check is
`c = S_k(values)`.

### 5.4 Why it is sound

Every challenge is drawn after what it protects is absorbed.

- **Outputs before `r`.** `r` is drawn after O1, so an output table cannot be
  chosen after `r` is known. Without O1 a prover can predict `r` and forge a
  different table with the same evaluation there.
- **`λ` after the claims.** If some `v_j` is wrong, or some enforcing gate is
  nonzero on the cube, then `Σ_j λ^j (v_j − true_j) + Σ_e λ^{w+e} Ẽ_e(p)` is a
  nonzero polynomial in `λ` of degree below `w + |E|`, vanishing with probability
  at most `(w + |E|)/|Fr|`. `Ẽ_e(p)` is nonzero except with probability
  `n/|Fr|`, because `E_e`'s values on the cube are fixed by the bound base and
  the external challenges — hence by the true inner layers — all determined
  before any coordinate of `p` is squeezed.
- **`τ` after both children.** A wrong pair of child values defines a line that
  meets the true line `τ ↦ L{k}[j](ρ, τ)` in at most one point.
- **The rounds** are the textbook argument: a wrong cubic agrees with the true
  one at a random `ρ_i` with probability at most `3/|Fr|`.

At the bottom, only claims about committed columns at one point remain, and
discharging them against the commitments is the caller's.

### 5.5 Shapes and errors

`layers[k].rounds` has `n_{k+1}` entries and `layers[k].final_evals` L3's count;
nothing in a proof is data-dependent. `verify` runs these checks, in this order,
before it touches the transcript, and returns an error rather than panicking on
anything the proof or the claims carry:

| order | variant | when |
| --- | --- | --- |
| 1 | `MissingChallenge { slot }` | a gate or cached entry names a slot the caller did not supply |
| 2 | `OutputShape` | `OutputClaims` does not match the output map in count or variables |
| 3 | `ProofShape { layer }` | `layer = N`: the proof has the wrong number of layers; otherwise transition `layer`, lowest first, has the wrong round or claim count |
| — | `LayerInconsistency { layer }` | a round or the final check of transition `layer` failed |

The artifact is not among what `verify` checks. It is assumed to have passed
`CircuitArtifact::validate` where its verifying key was loaded (§5.1), and the
guarantee above — no panic on anything the proof or the claims carry — is for
such an artifact. On one that breaks a law `verify`'s answer means nothing: it
may panic, and it may accept.
