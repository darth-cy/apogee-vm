# Recursion

How one base block proof becomes one Groth16 proof a contract checks. The section numbers are
the ones the code cites. Where this page and the code disagree, the code is right.

```text
base proof ──► leaves ──────► internal nodes ──► root ───► decider ───► contract
N shards,      each a run     each 2–4           covers    the root in  folds the root's
base format    of base shards children           0..N      Groth16      points; two pairings
```

- A **node** is this VM proving a verifier program. It verifies shards and folds every Mercury
  check they defer into one accumulator `(A, B)`, the claim `e(A, [1]_2) = e(B, [x]_2)`.
  Nothing pairs before the contract.
- **Base proving is untouched.** No base key, statement or proof moved a byte: a leaf verifies
  base shards as they are.
- Nodes are proved in a **recursion format** (§1) over a **field memory** (§2) with four
  coprocessor families on it (§3–§6), and they replay **tapes** (§7) rather than run
  `verifier-core` on RV32, which measured 3.0B cycles for block 257,510's 207 shards: fifteen
  times the block itself.

## 1. Two formats, one code path

### 1.1 The rule

A statement is in the recursion format exactly when its `VmConfig` holds `FIELD_WINDOWS`
(`VmConfig::is_recursion`), which is exactly when its program declares a field family. No wire
form says which format applies.

### 1.2 The delegation registry

`constants::delegation::TYPES` is one append-only table, and its first `BASE_TYPES = 6` rows
are all the base format knows. `constraints::family_circuit` is the base registry;
`constraints::recursion_circuit` differs from it in two ways only: its `ADD_SUB` knows every
row and carries §1.4's rule, and the five families of §2–§6 exist. `VmConfig::circuit` picks
the registry, for a key's load rule and the prover alike.

### 1.3 Stacked commitments

Every commitment a shard opens is a point its parent folds (§8.3). So a recursion shard commits
each of its two phases — its `M` columns, and its `W` columns with the multiplicities — as
**stacks** of `2^σ` columns. At height `2^n`, with `k_M` and `k_W` columns
(`VmConfig::stack_vars`):

```text
σ = min(24 − n, the smallest even σ with 2^σ ≥ max(k_M, k_W))
```

- Column `i` is slot `i mod 2^σ` of stack `⌊i / 2^σ⌋`. A stack is the `(n + σ)`-variate
  multilinear whose evaluations `[j·2^n, (j + 1)·2^n)` are slot `j`'s column, and its
  commitment is that polynomial's Mercury commitment. 24 is the ceremony's size.
- The GKR pass leaves each column's value `v` at `u`. Then `σ` challenges `r` are drawn
  (`STACK_CHALLENGE`), a stack's value is `Σ_j eq(r, j)·v_j`, and a setup column is a stack of
  one, `eq(r, 0)·v`, its commitment unchanged. The shard's one batch opening is at `u ‖ r`,
  over the `M` stacks, the `W` stacks, then the setup columns.

`σ = 0` is the base format exactly.

### 1.4 A recursion request leaves `a0` past its frame

A base delegation request writes 0 into `a0`. A request of a type past `BASE_TYPES` writes
`a0 + 4·words` (`constants::delegation::a0_after`), which the recursion `ADD_SUB`'s
`deleg_a0_rule` holds it to. So frames laid back to back replay as back-to-back `ecall`s, one
RISC-V row a call.

## 2. The field memory

### 2.1 The space

`address_space::FIELD = 10`: cells addressed by a `u32`, each a whole `Fr`. Its tuples
`(FIELD, cell, ts, value)` join RAM's in the one memory multiset. No instruction reaches it.
Only §3–§6's rows do, each access at its row's requesting cycle `c` and its own slot, `4c + Δ`,
with a read's usual gap check; a read-only access writes back what it read. A field access is
not a `MemoryEventLog` event, a value not being a `u32`: `trace::MemoryState` keeps each cell's
last `(ts, value)`, and a recursion execution has no `TraceArchive` form. It streams.

### 2.2 `FIELD_WINDOWS`

Family 18, `2^20` rows: `ZERO_WINDOWS`' circuit at a stride of one cell a row. Window `w` is
cells `[h·w, h·(w + 1))`, initialized to 0. The windows are consecutive from cell 0 — shard `i`
is window `i` — so a statement lists none, and a cell outside them has no tuple to balance a
read against.

The four families on it are *invoked*, by the delegation ABI: an `ecall` whose `a0` is a frame
of words in RAM. A frame's words name cells.

| § | family | id | ecall | anchor space | height | frame | a row is |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 3 | `FR_OP` | 19 | `0x0509` | 11 | `2^20` | `[op, d, a, b]` | one field operation |
| 4 | `P2_FIELD` | 20 | `0x050A` | 12 | `2^18` | `[n, s, x, y, d]` | one transcript duplex step |
| 5 | `FIELD_IO` | 21 | `0x050B` | 13 | `2^18` | `[op, cell, ptr]` | eight RAM words to a cell, or back |
| 6 | `FQ_OP` | 22 | `0x050C` | 14 | `2^20` | `[op, d, a, b]` | one BN254 base-field operation |

## 3. `FR_OP` — one field operation a row

| op | | | op | | |
| --- | --- | --- | --- | --- | --- |
| 1 | `MUL` | `d ← a·b` | 6 | `EQ` | `a = b`, or the row has no witness |
| 2 | `ADD` | `d ← a + b` | 7 | `IMM` | `d ←` word `b`, as an integer |
| 3 | `SUB` | `d ← a − b` | 8 | `SHL` | `d ← a·2^32 +` word `b` |
| 4 | `MAC` | `d ← d + a·b` | 9 | `DIGIT` | `d ←` `a`'s low byte, `b ← (a − d)/2^8` |
| 5 | `INV` | `d ← a⁻¹`, and 0 at `a = 0` | | | |

`a`, `b` and `d` are accessed at slots of their own, so any two may name one cell. `EQ` is how
a tape asserts. `IMM` and `SHL` are how it builds a constant with no field arithmetic of the
guest's. A scalar's 32 `DIGIT`s ending at 0 represent it mod `p`, which is all a scalar
multiplication needs.

## 4. `P2_FIELD` — one duplex step a row

With the state at cells `s..s+3`, the row absorbs `n ∈ {0, 1, 2}` of the cells `x, y` — the
lanes are `(n ≥ 1 ? x : s₀, n = 2 ? y : n = 1 ? 0 : s₁, s₂ + n)` — and writes
`poseidon2_permute` of them to `d..d+3`. A state is never overwritten, so a challenge is a cell
of the triple that made it. The circuit is flat, every S-box's `u²` and `u⁴` committed, so a
parent verifies it as one gate list.

## 5. `FIELD_IO` — between RAM and a cell

Over the eight RAM words `w_k` at `ptr`:

- `IMPORT` (1): the cell takes `Σ_k w_k·2^{32k}` mod `p`. A non-canonical encoding is harmless.
- `EXPORT` (2): the words take limbs below `2^32` congruent to the cell. Congruence, not
  canonicity: a guest that needs the canonical value compares the words with `p` itself.

Addressability is the multiset's. A word no window initializes cannot balance.

## 6. `FQ_OP` — one base-field operation a row

An **element** of BN254's `Fq` is four consecutive cells of 64-bit limbs, congruent to its
value mod `q` and not necessarily below it. Only this family writes one. The op word is a code,
three flags and a **digit cell** (`word >> 6`): a flagged operand's element is its word plus
`8·digit`, a bucket chosen by a digit, which is what lets an MSM be a static tape (§8.3).

| op | | |
| --- | --- | --- |
| 1 | `MUL` | `d ← a·b` |
| 2 | `ADD` | `d ← a + b` |
| 3 | `SUB` | `d ← a − b` |
| 4 | `MULEQ` | asserts `a·b ≡ d` |
| 5 | `FROM128` | `d ← a₀ + 2^128·a₁` from two cells below `2^128`: a coordinate from its transcript limbs |

One integer identity serves all five, `a·y + z = q·K + d′`, checked over 128-bit groups of
limbs with a range-checked quotient and carries. Some of those ranges go through `TIMESTAMP`,
which is why the family is at `2^20`. `b`'s and `d`'s four cells share one read timestamp, so
**an element is only ever written whole**; `tape::run` refuses a tape that reads one written
apart, before a fill would.

## 7. Tapes

A shard's checks have a fixed shape for its family and height. So the host compiles them, once,
into a **tape** (`verifier_core::tape`): a straight-line list of coprocessor calls over absolute
cells, in which nothing branches on a value. A tape reads three kinds of cell:

- **constants**, which it builds itself from `IMM` and `SHL`, so they are bound with it;
- **slots**, which its caller fills: the statement's digest and memory challenges, and the
  shard's index, window, roots and commitments;
- **inputs**, the proof, `IMPORT`ed from a blob laid out in the tape's `Input` order
  (`tape::shard_blob`), which the tape's own checks are what bind.

`tape::shard_tape` is `verify_shard_local`'s steps 7–11 and Mercury's field side
(`pcs_verify`), call for call: the shard transcript, the GKR backward pass, the lookup and root
checks, the stack challenges and values, and the opening's twelve scalars. Every check is an
`EQ`. It leaves three things to its caller (§8): the shard's time window against its
neighbours', step 10c on the two public shards, and everything on the curve — to a tape a point
is four transcript limbs, and the batch's `cm*` is a hint.

`tape::schedule` reorders a tape into runs of one family's calls, `tape::encode` is the form a
guest replays — the cells its imports fill, then runs of frames — and `tape::run` is the native
reading, over a `Memory` that models each access's timestamp as well as each cell's value.

## 8. Nodes and the tree

### 8.1 Two programs, one procedure

`guests/recursion` is two binaries. The **leaf** verifies shards `from..to` of one statement of
the base program. The **node** verifies two to four whole statements of the two recursion
programs — its children's proofs — reads each child's journal out of the output window step 10c
binds, holds the children to one another, and folds their accumulators beside their shards'.

Both run `verifier_core::node::node` through a `Driver`. The host runs it natively
(`host::recursion`), so it refuses whatever a guest would, first and by name, and it writes the
advice the guest reads. The guest runs it by coprocessor calls. A binary's **image** — every
shard tape, the fold's templates, the constants — is built by `build.rs` with `verifier-core`
itself and sits in `.rodata`, so a program's identity binds every tape it replays.

- The base program's identity is a constant of the leaf's image. The SRS digest and the generic
  table are constants of both images.
- A node takes the two recursion programs' identities as claims and journals them, for the top
  to check once.
- A program's setup commitments are advice, held to its identity by recomputing it.

**The global transcript is a chain across the tree** (`verifier_core::chain`). The node with
shard 0 runs the prefix, G1–G7. Every node absorbs its own shards' memory commitments, G8, from
the state its predecessor left. The node with the last shard runs the suffix, G9–G11, which
settles the digest and the memory challenges every node took as claims. A node that holds a
whole statement makes its memory argument, `Π reads · R_b = Π writes · W_b`.

A node holds its children to: exit status 0; one base statement — its shape, digest, challenges,
`io_digest`, exit status and shard count; adjacent shards; chain states that meet; time windows
in order across the seam; and, of a node child, the two identities it requires itself.

### 8.2 The journal

47 cells, each a 32-byte word (`node::journal`):

| cells | |
| --- | --- |
| 0 | a digest of the base statement's shape: its shard counts and windows |
| 1–7 | its global digest, four memory challenges, `io_digest`, exit status |
| 8–10 | its shard count, and the shards this node covers, `from..to` |
| 11–18 | the chain's state at `from` and at `to`: three lanes and a pending input each |
| 19–22 | the covered shards' read and write root products; the boundary factors where `to` is the count |
| 23–28 | the first and last covered shard's family and time window |
| 29–44 | `A` and `B`, each `x` then `y` in four 64-bit limbs |
| 45–46 | the leaf program's and the node program's identities this node requires; 0 for a leaf |

The **root** covers `0..count`: every base shard verified, the transcript run end to end, the
memory argument made. What is left is one pairing check and two identities.

### 8.3 Folding

After each shard's tape the node's own transcript absorbs the shard transcript's final state
(`FOLD_STATE`) and draws `w` and `w′` (`FOLD_WEIGHT`), so a shard's weights follow everything
they weight. Then, as scalars of points:

- entry `i` of the shard's Mercury check gets `w·e_i`, on its side (`pcs_verify::ENTRY_POINTS`);
- the batch check `cm* = Σ ρ^i·cm_i` is folded beside it: `cm*` gets `w′` more, and each `cm_i`
  gets `−w′·ρ^i`;
- `[1]_1` and the setup commitments, which every shard of a family shares, accumulate one scalar
  each and enter once;
- a child's `A` and `B` enter under a weight drawn after its whole journal (`FOLD_CHILD`).

Each side is one MSM on `FQ_OP` (`verifier_core::fold`): Pippenger with 8-bit digits over GLV
halves, 16 windows of 256 buckets, every step a static template. A point is held to the curve
and its scalar's split to the scalar, then added to one bucket a window through an indirect
operand. Inversions are host witnesses held by a `MULEQ`, and buckets start at offsets so that
no addition degenerates. A point costs about 400 `FQ_OP` calls.

### 8.4 The scheduler

`bench recurse <dir>/<stem> --out <out>`, over a base proof archive
(`tools/bench/src/recurse.rs`):

- **Keys.** It writes `base.key` and `programs.key` into `<out>` and builds the two binaries
  with `APOGEE_RECURSION_KEYS=<out>`, where their `build.rs` reads them. The node is built
  twice: once with no image, for the two programs' keys, and once over them.
- **Plan**, fixed before anything is proved (`host::recursion::Tree::plan`, `<out>/tree.txt`):
  leaves of at most `--leaf` (64) consecutive base shards, then levels of internal nodes over
  two to `--fan-in` (4) children, a lone leftover carried up. A program has sixteen families
  and each costs at least a shard, so a node is sixteen shards before any work and leaves are
  cut large.
- **A node is a process**, `bench recurse-node`: it verifies its inputs natively, builds its
  advice only then, proves, verifies, holds the proved journal to the native one and writes
  `<out>/<id>.block`. At most `--in-flight` nodes run, with `--in-flight × --shards-in-flight`
  shards in flight across them: a node takes its share of what is spare when it starts, so a
  root alone has the whole budget. A proof already in `<out>` is kept, so a stopped run
  resumes; a run whose plan or programs differ is refused.
- **At the root** it checks what a verifier owes beside the root's own proof — the journal
  covers `0..count` and is the archive's statement, it requires the two programs' identities,
  and `(A, B)` discharges — and then runs §9.

## 9. The decider

The root is still a GKR proof and some hundreds of points, and a contract can check neither.
`host::decider` splits its verification in two.

**The circuit** is §8.1's node procedure over one child, the root, through a `Driver` that
writes rank-1 constraints: an `FR_OP` is one constraint in the common case and none where it
only copies, a duplex is 255, advice is a free wire. It verifies the root as a node would, and
holds its journal to `from = 0` and `to = count`. But it **folds nothing**: every MSM template
is skipped, and each point's four limbs and its scalar are **bound** wires instead, after the
two identities, the base statement's exit status, and its public input and output, a wire a
byte, whose digest the circuit holds to the journal's `io_digest`.

**`crates/groth16`** is Groth16 over this repository's BN254. A circuit streams its constraints
into a sink, so no matrix is held. Three things are not the textbook's:

- **Bound wires** are values the verifier holds, too many to be public inputs. The proof
  carries their commitment `D = Σ w_j·[(β·A_j + α·B_j + C_j)/η]_1` under a fifth trapdoor `η`.
  A challenge `c` is SHA-256 of `D` and the verifier's values, and the circuit ends with
  `acc ← (acc + wire)·c` over the bound wires. The public inputs are `c` and that result, both
  of which the verifier computes from its own values, and the check is
  `e(A, B) = e(α, β)·e(IC, γ)·e(C, δ)·e(D, η)`, `IC` being the public wires' points under 1,
  `c` and the result. `D` is fixed before `c`, so wires that differ from the values agree with
  them at `c` with probability `len/r`.
- **No blinding.** A proof hides nothing and is a function of its witness.
- **A Lagrange basis.** `A` and `B` are sums over the constraints, `Σ_j (A·w)_j·[L_j(τ)]`, not
  over the wires. So the one element a key holds a wire is `[(β·A_i + α·B_i + C_i)/x]_1`, `x`
  being `γ`, `η` or `δ` — and a powers-of-tau ceremony already publishes `[L_j(τ)]`.

**The key is a ceremony's**, in two phases:

- **Phase 1 is `ppot_0080_24.ptau`**, the ceremony the tree's own commitments are under
  (`srs::Phase1`): the Lagrange basis at the circuit's domain in both groups, and the powers a
  quotient takes. Everything of the key that depends on `τ` is a combination of those points,
  and nothing derives `τ`.
- **Phase 2 is the circuit's own** (`groth16::phase2`, `bench ceremony`), and makes `α`, `β`,
  `γ`, `δ` and `η` from 1 by **contributions**: each multiplies a trapdoor by a factor only its
  contributor knew, so a trapdoor is unknown while one contributor to it was honest.

  | step | |
  | --- | --- |
  | `init` | every trapdoor 1: a wire's `[A_i(τ)]_1`, `[B_i(τ)]_1`, `[C_i(τ)]_1`, and `[τ^k·Z(τ)]_1`. Deterministic from the circuit and the file |
  | round 1, `contribute` | to `α` and `β`: `[β·A_i]_1` and `[α·B_i]_1`, kept apart |
  | `seal` | a wire's three terms summed |
  | round 2, `contribute` | to `γ`, `δ` and `η`: the sum over the wire's trapdoor, and `[τ^k·Z(τ)/δ]_1` |
  | `key` | the last state verified and, if every trapdoor has a contribution, written as the key |

  **The order of the rounds is the soundness.** A prover may hold a wire's three terms only
  summed, over `δ` or `η`: apart, it could give `A`, `B` and `C` three witnesses. A contribution
  to `α` or `β` scales the terms apart, so those are finished before anything is divided.

  A state carries each contribution's record — its factor in G1 with a Schnorr proof of knowing
  it, bound to the records before it, and the trapdoor in G2 afterwards. Verifying a state
  checks that chain, then its elements against `init`'s under those trapdoors, one pairing
  equation over a random combination: against the circuit and the file alone, with no earlier
  state. Every step lists the records by their factors' points, so a contributor finds its own
  under the state the key is made of. `bench decide` reads the key `key` wrote, and nothing
  else writes one.
- **`setup_dev`**, `bench decide --dev-key`, derives all six trapdoors from a public seed. It
  is for development and tests: anyone forges under it.

**The contract** (`contracts/ApogeeVerifier.sol`) is `verify(input, output, exitStatus, proof,
points)`, a point being `x, y, scalar`, side `[1]_2`'s points and then side `[x]_2`'s. It
rebuilds the bound values — a point's limbs are its coordinates' halves, or four sentinels at
infinity, which is what the root's transcript absorbed — recomputes `c` and the result, checks
the Groth16 pairing, folds each side with `ecMul` and `ecAdd`, which is also what holds a point
to the curve, and checks `e(A, [1]_2) = e(B, [x]_2)`. Its Groth16 key, the ceremony's two G2
points and the two identities are set at deployment.

`bench decide <out>` proves under the ceremony's key, checks the proof natively, deploys and
calls the contract in revm, and writes `decision.constructor` and `decision.calldata` — under
`--dev-key`, `development.*`.

**What a deployment still owes.** A key is as trustworthy as its ceremony: one honest
contributor a round, which a ceremony run on one machine is not. The circuit depends on the
root's shape — its program, its shard counts, the public values' lengths — so a key, and its
ceremony, is per shape. And the contract pays about 9k gas a point, because the circuit folds
none.

## 10. Running it

```text
bench prove --stateless <fixture> --out <dir>             the base proof
bench recurse <dir>/<stem> --out <out> --in-flight 4      the tree
bench ceremony <out> init                                 the decider's key: once a root shape,
bench ceremony <out> contribute                           each contributor in turn, to alpha and beta
bench ceremony <out> seal
bench ceremony <out> contribute                           and to gamma, delta and eta
bench ceremony <out> key
bench decide <out>                                        the Groth16 proof, and the contract
```

It needs `assets/ptau/ppot_0080_24.ptau`. Measured on block 257,510 — the tree on a 32-CPU,
247 GiB machine, the ceremony and the decider on an 18-core laptop:

| | |
| --- | --- |
| base proof | 207 shards, 14.5 MB, 2,481 s |
| tree | 4 leaves of at most 64 base shards and a root: 116 shards |
| leaves, four at once | 21, 24, 23 and 27 shards; 2,157 s; 92 GiB peak |
| root, four shards in flight | 21 shards, 460 s, 1.03 MB |
| decider's circuit | 7,896,686 constraints, a domain of `2^23` |
| ceremony | `init` 65 s; a contribution 50–56 s; `key` 70 s, 12.7 GB; the key 2.65 GB |
| decider | the key read in 1 s, the proof 18.5 s, 6.1 GB |
| contract | 358 points; 3,620,026 gas; 34,980 bytes of calldata |
