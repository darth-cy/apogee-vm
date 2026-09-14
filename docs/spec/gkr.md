# The GKR engine: layered circuits, the artifact, and the backward pass

Frozen as of S13. Changing anything here is a protocol-version change.

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
| halving | `n_k - 1` | `w_k` | entry `j` is `TreeProduct { L{k}[j] }`: `out[i] = in[i] · in[i + 2^{n_k - 1}]` |

A halving list **halves every column of its layer, in order**. The child bit is
the **highest** variable of layer `k`. A halving list has no enforcing gates and
no cached entries, reads inner-layer columns only (never layer 0), and needs
`n_k >= 1`. A row-wise list has no `TreeProduct`.

Every relation is written in one fixed template, whatever its shape:

```text
producing (row-wise)   L{k+1}[j](x) = Σ_y eq(x, y) · G(inputs at y)
producing (halving)    L{k+1}[j](x) = Σ_y eq(x, y) · L{k}[j](y, 0) · L{k}[j](y, 1)
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

`VirtualKind::RowIndex`, `V[row]`, is the one kind at S13. Its value at row `y`
is `y`; its closed form **is its multilinear extension**, `Σ_j 2^j · y_j` over
`n_0` variables, and the kind tag is how the closed form is in the artifact. A
virtual table has layer 0's height. It is **never materialized**: the forward
pass evaluates the closed form per row, the prover at every point a round needs
(`(bound, X, bits)` at `X = 0, 1`), and the verifier at the bound point. It is
never committed, never claimed, and never returned as a `BaseClaim`. A later kind
is admissible only if its MLE has a closed form at every such point.

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
| `format_version` | `0`. A postcard layout is not self-describing, so this is how a reader refuses an artifact of a later, extended layout instead of misreading it |
| `coefficient_encoding` | `0` = every `Fr` canonical 32-byte little-endian; the only value, and how the file declares it |
| `trace_vars` | `n_0`; the trace length is `2^{trace_vars}`, at most `2^30` so `1 << n` fits a 32-bit `usize` |
| `memory`, `witness`, `setup` | the committed layout per subtree, one name per column |
| `virtuals` | `(kind, name)`: the virtual tables the circuit reads |
| `layers` | gate list `k` for `k = 0..N` |
| `relations` | the flat constraint list |
| `lookups` | must be empty at S13; S15 gives the element its meaning and bumps `format_version` if it reshapes it |
| `scratch` | `(name, L{k}[j])`: the scratch bijection |
| `outputs` | the output map: a permutation of the top layer, in `OutputClaims` order |
| `padding` | `(row, zero_row_valid)`: the padding contract, §4.3 |

```text
LayerSpec   = (halving, num_vars, width,
               cached:    [(name, C{k}[j], GateDef)],
               producing: [(relation, L{k+1}[j], GateDef)],
               enforcing: [(relation, GateDef)])
Relation    = (name, output: Option<scratch index>, GateDef)
LookupExpr  = (name, channel, tuple: [GateDef])
```

`num_vars` and `width` are the layer **written**, `k + 1`: derived values stored
for readers, which Law 2 holds to what the gates imply. The `j`-th cached and
producing entry sit at `C{k}[j]` and `L{k+1}[j]`.

### 4.1 Wire form

`postcard` over the tuple above, hand-written serde. A `u32` is a postcard
varint; a `u8` tag and a `bool` are one raw byte; `Option` is postcard's tag; a sequence is a varint
length then its elements; a name is a `str`; an `Fr` is its 32 canonical bytes
with no length prefix (`crates/field`'s `[u8; 32]` tuple).

```text
VirtualKind     u32                           0 RowIndex
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
```

A `Quadratic` decodes only when `t` is at most the operand count, the operands
after the first `t` pair up, and there are exactly `1 + t + (operands − t)/2`
coefficients. Tags are append-only. `from_bytes` is total — it returns an error and never
panics, whatever it is handed, and reserves nothing an untrusted length asks for
— and accepts exactly the bytes `to_bytes` writes: it re-encodes and compares. It
checks no law: a decoded artifact may break every one, which is what lets the
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
   its entry `j` reads `L{k}[j]`. Layer 0's size is the committed layout.
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
slot; a non-empty `lookups`; a `padding.row` whose length is not `w_0`; a format
version or coefficient encoding other than 0; `trace_vars > 30`. Every refusal is
a `ConstraintError` naming the law, gate or address.

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
`zero_row_valid` says whether the all-zero committed row has the same property.
The checker holds both statements to the relations, at pseudo-random challenge
values and row indices.

Not covered at S13, and owed by the stage that builds product trees over trace
rows: that a padding row contributes the multiplicative identity to every column
a halving list reads (master rule 7), and that the contract holds for the setup
values a real padding row carries rather than the ones `padding.row` names.

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
| `gkr::BaseLayer` | the committed columns by address; `new` refuses anything but `M`, `W`, `S`, and repeats |
| `gkr::LayerValues { base, layers }` | the forward pass's output: the base, then layers `1..=N` in offset order |
| `gkr::SelfCheckError { layer, row, relation }` | the first gate the materialized values break |

`gkr::forward` materializes every layer. `gkr::self_check` recomputes every gate
against those layers and names the first broken relation; the caller runs it.
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
round 0 sums to it by construction. S16's claim-merging sumcheck, whose claims
sit at several points, extends this driver to a weighted sum of `eq` tables; the
single point here is S13's.

### 5.1 What the caller owes

- **Before** `prove` or `verify`, the caller has bound the base layer into the
  transcript (at S13 the tests absorb `sumcheck::witness_digest` of the committed
  columns; S16 absorbs commitments). The engine never absorbs base material.
- Every `ExternalChallenges` value is drawn **after** everything its gates can
  reach is bound: every committed column on any path from a gate naming the slot
  down through the inner layers. At S13 the tests draw the toy's slot as
  `challenge_scalar(SUMCHECK_CHALLENGE)` immediately after the digest.
- The artifact is the verifier's, not the prover's: it is part of what a
  verifying key conveys.
- The artifact has passed `CircuitArtifact::validate`. `verify`, `forward`,
  `self_check` and `prove` do not check it again: validation belongs to a
  verifying or proving key, once, not to every proof, and the routine that loads
  a key calls it. No such routine exists at S13; the stage that introduces
  `VerifyingKey` must call `validate` there. On an artifact that breaks a law the
  engine's answer means nothing: it may panic, and `verify` may accept.

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
halving    S_k(x) = Σ_j λ^j · L{k}[j](x, 0) · L{k}[j](x, 1)
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
