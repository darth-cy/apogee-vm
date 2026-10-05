# The GKR engine

The layered-circuit model every family circuit is written in, the artifact that carries one, its
laws, and the backward pass reducing a circuit's outputs to claims on its committed columns at one
point, which the shard's opening discharges ([proof.md](proof.md) §5).

`crates/constraints` is §1–§4; `crates/gkr-verify` is §5's verifier half and the verifier's
helpers for the memory argument ([memory.md](memory.md) §3, §4) and LogUp
([lookup.md](lookup.md) §2, §8). Both are `no_std`, as `verifier-core` and the recursion guest
build on them. `crates/gkr`, `std` and rayon, is the prover half and re-exports `gkr-verify`.
`crates/checker` enforces §4.2–§4.3 again ([circuits.md](circuits.md) §3).

## 1. The layer model

Layer `k`, `0 ≤ k ≤ N`, `N ≥ 1`, is `w_k` columns of `n_k` variables, indexed as
[primitives.md](primitives.md) §6 fixes. **Layer 0** is the committed columns `M`, `W`, `S` in
layout order at `n_0 = trace_vars`, beside the virtual tables the artifact lists (§2.1), which
count in no width. **Gate list** `k` reads layer `k` and writes layer `k + 1`; the **top**, layer
`N`, is exactly the outputs. A list is **row-wise**, `n_{k+1} = n_k`, or **halving**,
`n_{k+1} = n_k − 1`.

A halving list halves each column of its layer: it writes `w_k` columns by halving shapes (§3)
reading layer-`k` columns at both **children** — child 0 is rows `[0, h)`, child 1 rows `[h, 2h)`,
`h = 2^{n_k−1}`, the child bit being the highest variable. An entry may read any column, as a
fraction tree's numerator reads its denominator ([lookup.md](lookup.md) §6), but every column is
read (§4.2). Only halving lists hold halving shapes; a halving list is never list 0, has no cached
or enforcing entries and needs `n_k ≥ 1`. Every relation has the one template `checker dump` prints:

```text
producing, row-wise   L{k+1}[j](x) = Σ_y eq(x, y)·G(layer k at y)
producing, halving    L{k+1}[j](x) = Σ_y eq(x, y)·G(layer k at (y, 0) and (y, 1))
enforcing             0 = G(layer k at y)   for every y ∈ {0,1}^{n_k}
```

## 2. Addresses

`constraints::PolyAddress` names every polynomial; dumps use its `Display` notation:

| variant | notation | | read by |
| --- | --- | --- | --- |
| `Memory(i)`, `Witness(i)`, `Setup(i)` | `M[i]`, `W[i]`, `S[i]` | committed columns | list 0, relations, lookups |
| `Virtual(kind)` | `V[row]`, … | virtual tables, §2.1 | the same, if `virtuals` lists it |
| `Inner { layer, offset }` | `L{k}[j]` | column `j` of layer `k ≥ 1` | list `k` |
| `Cached { layer, offset }` | `C{k}[j]` | cached entry `j` of list `k`, §3.1 | list `k` |
| `Scratch(i)` | `scratch[i]` | an intermediate of the flat relation list, §4 | relations |

The **scratch bijection** maps each `scratch[i]` to one `L{k}[j]`, covering every inner column
once. A committed value needed above layer 1 is carried up by copy gates. `M`, `W` and `S` differ
in when they are bound ([memory.md](memory.md) §8).

### 2.1 Virtual tables

A virtual table is a closed form, evaluated per row by `gkr_verify::virtual_at_row` and at a point
by `virtual_at_point`, never materialized, committed or claimed. Each form is its table's
multilinear extension, so the verifier evaluates what the prover sums
(`crates/gkr/tests/{lookup,ram_live}.rs` check all but `V[row]`). Wire form: a `u32`, in table
order from 0.

| kind | notation | value at row `y` | closed form at `(y_0, …, y_{n−1})` |
| --- | --- | --- | --- |
| `RowIndex` | `V[row]` | `y` | `Σ_{j<n} 2^j·y_j` |
| `RamLive` | `V[ram_live]` | 1 if `y ≥ 2^14`, else 0 | `1 − Π_{14≤j<n} (1 − y_j)`; 0 if `n ≤ 14` |
| `Range19` | `V[range19]` | `y mod 2^19` | `Σ_{j<min(19,n)} 2^j·y_j` |
| `Range16` | `V[range16]` | `y mod 2^16` | `Σ_{j<min(16,n)} 2^j·y_j` |
| `Xor8A` | `V[xor8_a]` | `a = y mod 2^8` | `Σ_{j<8} 2^j·y_j` |
| `Xor8B` | `V[xor8_b]` | `b = ⌊y/2^8⌋ mod 2^8` | `Σ_{j<8} 2^j·y_{j+8}` |
| `Xor8Out` | `V[xor8_out]` | `a ⊕ b` | `Σ_{j<8} 2^j·(y_j + y_{j+8} − 2·y_j·y_{j+8})` |

14 is `constants::memory::RAM_LIVE_BIT` ([memory.md](memory.md) §3); the range and `XOR8` kinds
are channel tables ([lookup.md](lookup.md) §3). `Xor8Out`'s form is multilinear because
`y ⊕ z = y + z − 2yz` is.

## 3. Gate shapes

`constraints::GateDef` is a closed enum. A coefficient is `Coeff::Literal(Fr)` or
`Coeff::Challenge(slot)`, a `constants::challenge_slot` read from the pass's `ExternalChallenges`,
of degree 0.

| tag | variant | value |
| --- | --- | --- |
| 0 | `Linear { terms, constant }` | `Σ c_i·x_i + c_0` |
| 1 | `Product { coeff, left, right }` | `c·x·y` |
| 2 | `MaskIntoIdentity { input, mask }` | `x·m + (1 − m)` |
| 3 | `AffineProduct { left, left_constant, right, right_constant }` | `(Σ a_i·x_i + a_0)·(Σ b_j·y_j + b_0)` |
| 4 | `TreeProduct { input }` | `x(·,0)·x(·,1)` |
| 5 | `Quadratic { constant, linear, products }` | `c_0 + Σ a_i·x_i + Σ b_j·y_j·z_j` |
| 6 | `TreeCross { left, right }` | `p(·,0)·q(·,1) + p(·,1)·q(·,0)` |

`Quadratic` spells degree-2 relations, such as `a·b + c·d − e·f`, that no product of affine forms
does. **The kernel**, `gkr_verify::eval_gate`, takes one value per operand in `GateDef::operands`
order, a halving shape's each at child 0 then child 1, and is the semantic authority. Both passes
reach it through `gkr_verify::ResolvedList`, `crates/checker` calls it over the relations, and
`verifier_core::tape` transcribes it for the recursion nodes ([recursion.md](recursion.md) §7).

### 3.1 Cached entries and the degree ceiling

A **cached entry** `C{k}[j] = H` is a sub-expression of row-wise list `k` over its layer's columns,
not another cached entry, substituted into the gates of its list naming it, with no table, claim
or width. The prover evaluates `H` at every round node and never binds it: a bound table is
the extension of `H`'s values, which for a degree-2 `H` is not `H` of the extensions. No
registered circuit has one. `CircuitArtifact::inline_cached` writes a `Product` with one `Linear`
cached factor as an `AffineProduct` and refuses any other reference; both prove the same bytes.

**Degree** is read from the shape after substitution — a column or virtual table 1, a challenge 0,
`C{k}[j]` its expression's, a halving shape 2, a `Quadratic` its widest term — and `validate` holds
every gate, cached entry and relation to at most 2, so a higher relation is split across layers.
With `eq` multilinear, every round polynomial is then a cubic (§5.3).

## 4. The circuit artifact

`constraints::CircuitArtifact` holds a circuit twice: as **layered gates**, which the engine
proves, and as a **flat relation list** over `M`, `W`, `S`, `V` and `scratch`, which the row-local
checks read ([circuits.md](circuits.md) §3). Law 4 makes them one constraint set. In wire order:

```text
CircuitArtifact = (format_version = 1, coefficient_encoding = 0, trace_vars ≤ 30,
                   memory, witness, setup: [name], virtuals: [(VirtualKind, name)],
                   layers: [LayerSpec], relations: [Relation], lookups: [LookupExpr],
                   scratch: [(name, L{k}[j])], outputs: [L{N}[j]],
                   padding: (row: [Fr], zero_row_valid: bool))
LayerSpec       = (halving, num_vars, width,
                   cached:    [(name, C{k}[j], GateDef)],
                   producing: [(relation, L{k+1}[j], GateDef)],
                   enforcing: [(relation, GateDef)])
Relation        = (name, output: Option<scratch index>, GateDef)
LookupExpr      = (name, channel, selector: PolyAddress, tuple: [GateDef])
```

`validate` holds the first three to those values and every name to non-empty `[a-z0-9_]`, unique
in the artifact; names mean nothing to the engine. Encoding 0, `COEFFICIENT_ENCODING_CANONICAL_LE`,
is every `Fr` canonical 32-byte little-endian, and 30 is `MAX_TRACE_VARS`. `outputs` orders the
top layer as `OutputClaims` lists it; a relation with an output defines that slot, one without is
enforcing; `lookups` are [lookup.md](lookup.md) §1's.

### 4.1 Wire form

`postcard` over §4's tuples, hand-written serde: a `u32` is a varint, a `u8` tag and a `bool` a
byte, an `Option` a tag byte, a sequence a varint count then its elements, a name a `str`, an `Fr`
its 32 canonical bytes.

```text
PolyAddress  (tag u8, a u32, b u32): 0 M, 1 W, 2 S, 5 scratch (a = index); 3 V (a = kind);
             4 L, 6 C (a = layer, b = offset); unused fields 0
Coeff        (tag u8, slot u32, value Fr): 0 literal (slot 0), 1 challenge (value 0)
GateDef      (tag u8, split u32, coefficients [Coeff], operands [PolyAddress] in operands() order)
  0 Linear            split 0  c_1..c_t, c_0                 x_1..x_t
  1 Product           split 0  c                             x, y
  2 MaskIntoIdentity  split 0  —                             x, m
  3 AffineProduct     split t  a_1..a_t, a_0, b_1..b_u, b_0  x_1..x_t, y_1..y_u
  4 TreeProduct       split 0  —                             x
  5 Quadratic         split t  c_0, a_1..a_t, b_1..b_u       x_1..x_t, y_1, z_1, …, y_u, z_u
  6 TreeCross         split 0  —                             p, q
```

`CircuitArtifact::from_bytes` refuses a `format_version` other than 1 before decoding the rest,
postcard not being self-describing; refuses an unknown tag, a nonzero unused field, a gate with
counts its shape lacks and a non-canonical `Fr`; re-encodes and compares, as postcard admits
overlong varints and trailing bytes; never panics or reserves what a declared length asks; and
checks no law.

### 4.2 The laws

`CircuitArtifact::validate` runs once where an artifact is built or loaded, never per proof: each
`constraints` constructor panics on a refusal, and `verifier_core::VerifyingKey::check` applies it
to a key's circuits, for prover and verifier ([proof.md](proof.md) §7). `checker::check_laws`
enforces Laws 1–4 and the lookup rules again, sharing no code with `crates/constraints/src/laws.rs`
([circuits.md](circuits.md) §3).

1. **Locality.** Every operand of list `k` is in range and readable at layer `k` (§2): a `V` only
   if listed, a `C{k}[j]` only one of list `k`'s own, from a producing or enforcing gate.
2. **Derived width.** A list's stored `width` is its producing count, entry `j` writes
   `L{k+1}[j]`, and its stored `num_vars` is `n_k`, or `n_k − 1` if halving.
3. **Top layer.** `outputs` is a permutation of `L{N}[0..w_N)`.
4. **Single source of truth.** Relations and gate entries correspond one to one, a producing
   entry's relation defining the slot the bijection maps to its output, an enforcing entry's none,
   and each pair is one polynomial, scratch read through the bijection and cached entries
   substituted: `validate` compares normalized expansions, `checker` evaluations at random points.

`validate` also refuses, each a `ConstraintError` naming what broke: §4's bounds, no gate list,
`padding.row` not `w_0` long, a virtual kind listed twice, §1's halving rules, degree above 2, a
relation reading anything but `M`, `W`, `S`, listed `V` and existing `scratch`, a scratch list that
is no bijection onto the inner columns or not defined once each, a slot outside
`constants::challenge_slot`, and a relation constructed and then dropped — an inner column below
the top the list above never reads, a cached entry no gate names, an enforcing gate whose
expansion is zero. Reads are decided on normalized expansions: `x − x` and `0·x` read nothing.

**The lookup rules.** A lookup's channel is in `constants::lookup_channel`; its tuple is one
expression on a range channel, else 1 to `lookup_channel::MAX_TUPLE` (7), as wide as its channel's
other lookups'; its selector is an in-range committed column some enforcing gate of list 0 holds
to booleanity (`x − x²` up to normal form); and each expression is `Linear` over in-range committed
columns and listed virtual tables, with literal coefficients, unit and constant-free above
position 0 ([lookup.md](lookup.md) says what each protects).

### 4.3 The padding contract

The engine gates nothing, an enforcing gate being a zerocheck over the whole cube, so a family
switches relations off with its own columns ([memory.md](memory.md) §2). On `padding.row`, a
committed row, the **row-local** scratch values, those of producing relations not at or above a
halving shape, make every row-local enforcing relation vanish at every challenge value and row
index; `zero_row_valid` says whether the all-zero row does too. **The product-tree clause**: where
shards have inactive rows, every column the first halving list reads is 1 on `padding.row`, so
padding leaves each product unchanged; the RAM window families ([memory.md](memory.md) §3) and the
columns a `TreeCross` reads ([lookup.md](lookup.md) §6) are exempt. This is completeness, not
soundness: a cheating prover's padding rows are its family's gates' business. Nor is `padding.row`
the row a prover writes, multiplicities and setup columns differing; no prover or verifier reads
it, and `checker::check_padding` and `checker::check_padding_identity` test it.

## 5. The backward pass

`gkr::forward` materializes every layer from the committed columns; `gkr::prove` proves those
values as they stand, one `sumcheck::SumcheckProof` per transition; `gkr_verify::verify` replays
the schedule, checking, from `OutputClaims`, one table per output, to `BaseClaim`s or a
`GkrError`. `gkr::self_check`, naming the first failing gate, row and relation, and
`gkr::explain_self_check`, listing that row's operands, are a debugging hook costing a second
forward pass ([tools.md](../tools.md) §3). Rayon splits rows and row pairs, never lists or rounds:
proofs do not depend on the thread count.

### 5.1 What the caller owes

- The base is bound into the transcript before `prove` or `verify`, which absorb none of it
  ([proof.md](proof.md) §4 binds a shard's commitments).
- Each challenge is drawn after every committed column its gates reach is bound, or is
  **derived**: a fixed function of such challenges and of statement data bound before them,
  computed by the verifier. That suffices for GKR; the memory argument needs more
  ([memory.md](memory.md) §8).
- The artifact has passed `validate` (§4.2) and is not checked again; on a lawless one the engine
  may panic, and `verify` may accept.
- The prover's inputs have the artifact's shape; it checks none, nor that its values satisfy the
  gates. Soundness is `verify`'s alone and a cheating prover runs none of this code, so a bad
  input costs the honest prover only a panic or a failing proof.

### 5.2 The transcript schedule

`prove` and `verify` run these steps and end in one sponge state; the tags are
[transcript.md](transcript.md) §5's. `p` is the claim point, `v_j` the claim on column `j` of the
layer the next list writes.

| step | op | tag | message |
| --- | --- | --- | --- |
| O1 | absorb | `GKR_OUTPUTS` | the output tables in output-map order, rows in index order: one message of `w_N·2^{n_N}` scalars |
| O2 | squeeze ×`n_N` | `GKR_OUTPUT_POINT` | `p = r`, `r_i` binding variable `i`; `v_j = tables[i](r)` for `outputs[i] = L{N}[j]` |
| L1 | squeeze | `GKR_BATCH` | `λ`; the claim is `c = Σ_j λ^j·v_j` |
| L2 | ×`n_{k+1}`: absorb, squeeze | `SUMCHECK_ROUND`, `SUMCHECK_CHALLENGE` | a round's cubic, then `ρ_i`, binding variable `i` |
| L3 | absorb | `GKR_LAYER_CLAIMS` | row-wise: `L{k}[j](ρ)` per `j` in offset order, layout order at `k = 0`; halving: `L{k}[j](ρ,0), L{k}[j](ρ,1)` per `j` |
| L4 | squeeze, halving only | `GKR_CHILD` | `τ`; `p = (ρ, τ)`; `v_j = L{k}[j](ρ,0) + τ·(L{k}[j](ρ,1) − L{k}[j](ρ,0))` |

L1–L4 run for `k = N − 1` down to 0; after a row-wise list `p = ρ` and `v` is L3's message. The
base claims are layer 0's, in layout order at one point. Every registered circuit halves to a top
with no variables ([circuits.md](circuits.md) §2), so O2 draws nothing and O1 fixes the roots
before `λ`.

### 5.3 The layer sumcheck

Transition `k` proves `c = Σ_{y∈{0,1}^{n_{k+1}}} eq(p, y)·S_k(y)`, where

```text
row-wise   S_k(y) = Σ_j λ^j·G_j(layer k at y) + Σ_e λ^{w_{k+1}+e}·E_e(layer k at y)
halving    S_k(y) = Σ_j λ^j·G_j(layer k at (y, 0) and (y, 1))
```

`G_j` writes `L{k+1}[j]` and `E_e`, the list's `e`-th enforcing gate, claims 0: enforcing gates are
zerochecks sharing the descending point and its batch. The rounds are
[primitives.md](primitives.md) §7's cubics, run from `c`, one per variable of layer `k + 1`, a
halving list's two children being separate tables. After L3 the verifier checks
`claim = eq(p, ρ)·S_k(values)`, layer-`k` operands taking L3's values, virtual tables their closed
form at `ρ`, cached entries their expression; with `n_{k+1} = 0` there are no rounds and the check
is `c = S_k(values)`. A zero claim is legal. `gkr::prove_sumcheck` and
`gkr_verify::verify_sumcheck` run L2.

### 5.4 Why it is sound

Each challenge is drawn after what it protects:

- **`r` after the outputs**, or a prover predicting `r` claims another table agreeing with the
  true one there.
- **`λ` after the claims and `p`.** If some `v_j` is not the true `v̂_j`, or some `E_e` is nonzero
  on the cube, `Σ_j λ^j·(v_j − v̂_j) − Σ_e λ^{w_{k+1}+e}·Ê_e(p)` is a nonzero polynomial in `λ` of
  degree below `w_{k+1} + |E_k|`; `Ê_e`, the extension of `E_e`'s values, is fixed before `p` is
  drawn and vanishes there with probability at most `n_{k+1}/|Fr|`.
- **`ρ_i` after round `i`**: a wrong cubic agrees with the true one there with chance ≤ `3/|Fr|`.
- **`τ` after both children**: a wrong pair's line meets `τ ↦ L{k}[j](ρ, τ)` in at most one point.

Summed over a registered circuit's transitions at its default height, these stay under
`2^14/|Fr|`. The random-oracle assumption is [architecture.md](../architecture.md)'s.

### 5.5 Shapes and errors

Transition `k` carries `n_{k+1}` rounds and `w_k` claims, `2·w_k` if halving, so a proof's shape
is the artifact's alone (wire form: [proof.md](proof.md) §9). `verify` checks, in order and
before touching the transcript, and on a validated artifact never panics on proof or claim data:

| `GkrError` | when |
| --- | --- |
| `MissingChallenge { slot }` | a gate names a slot not supplied |
| `OutputShape` | `OutputClaims` mismatches the output map in count or variables |
| `ProofShape { layer }` | `layer = N`: a wrong transition count; else transition `layer`, lowest first, has a wrong round or claim count |
| `LayerInconsistency { layer }` | a round or the final check of transition `layer` fails |

One `LayerInconsistency` covers a wrong descending claim and a violated enforcing gate alike: a
batched sum cannot tell them apart, and the proof spends nothing on it. [proof.md](proof.md) §6
maps these errors to its classes.
