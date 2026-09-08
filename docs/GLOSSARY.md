# Glossary

The vocabulary of `docs/spec/`. One word per concept; if two words appear for one
thing, one of them is wrong.

**Fr** — the BN254 *scalar* field, modulus
`21888242871839275222246405745257275088548364400416034343698204186575808495617`.
The field everything in this VM is arithmetized over. Not to be confused with **Fq**,
the BN254 *base* field, which is where curve coordinates live.

**Canonical form** — a field element as a 32-byte little-endian integer in `[0, p)`.
The only encoding that ever reaches a file, an artifact, or a transcript.

**Montgomery form** — the in-memory representation `x · R mod p` used for fast
multiplication. An implementation detail of `crates/field`; never serialized.

**Column = multilinear = polynomial** — three names for the same object: a vector of
`2^k` Fr values, viewed as the evaluations of a multilinear polynomial over the
boolean hypercube `{0,1}^k`. Prefer *column* when talking about a trace, *multilinear*
when talking about sumcheck.

**Index convention** — the map from a hypercube point to a table index, frozen in
`crates/poly`: variable `j` is bit `j`, so the evaluation at `y` sits at
`index = sum_j y_j 2^j`. Little-endian, variable 0 in the low bit. Every column, gate
and layer in every later stage is indexed this way.

**Bind** — fixing the current variable 0 of a multilinear to a challenge `r`, halving
its table by `f'(i) = f(2i) + r*(f(2i+1) - f(2i))`. The old variable 1 becomes the new
variable 0, so a sequence of binds fixes the variables in order. *Evaluate* is the same
fold done non-destructively, leaving the receiver untouched.

**Backing** — how a column's table is stored: a bitset, `u8`, `u16`, `u32`, or `Fr`.
Trace columns are mostly narrow integers, so storage stays at native width. **Lift** is
the canonical embedding of such an integer into `Fr`. It is *lazy*, meaning
bind-triggered: reads lift on the fly and change nothing, the first bind lifts the whole
table, and the backing is `Fr` from then on.

**eq** — the equality indicator `eq(r, y) = prod_j (r_j y_j + (1-r_j)(1-y_j))`, the
multilinear extension of "y equals r" on the cube. `eq_table(r)` tabulates it over the
cube; `eq_eval(r, y)` is the closed form. It is the weight a zerocheck sums against and
is always a virtual column.

**Layer** — one level of a GKR circuit. Each layer's values are determined by gates of
degree ≤ 2 in the layer below.

**Committed vs virtual** — a *committed* column is one the prover commits to with
Mercury and later opens. A *virtual* column is derived in closed form by the verifier
(range tables, timestamp tables, `eq`) and never committed.

**Shard** — one fixed-height trace instance of a circuit family, proven independently
except for the global memory argument.

**Family** — a circuit family: one arithmetization shape (its own gates, columns and
height) covering a set of program counters. The family set for a program is derived by
the preprocessor and recorded in `VmConfig`.

**Transcript** — the Poseidon2 duplex sponge every challenge is drawn from. Two layers:
the *raw duplex* (`observe`/`sample`) and the *typed layer* (`append_*`/
`challenge_scalar`), which frames each message as `tag, length, payload`. Specified in
`docs/spec/transcript.md`.

**Tag** — a `u64` domain-separation label for one kind of transcript message. Values
live only in `constants::transcript_tags`; each names exactly one message kind.

**Absorb / squeeze** — material going into the sponge, and challenges coming out. An
absorb of `n` elements zero-pads the rate and adds `n` to the capacity; a squeeze with
nothing pending just permutes again.

**Snapshot** — a transcript's sponge state and both buffers, enough to resume the
challenge stream exactly. The unit of master rule 9's archivable phase boundaries.
