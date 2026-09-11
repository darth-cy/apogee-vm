# Glossary

The vocabulary of `docs/spec/`. One word per concept; if two words appear for one
thing, one of them is wrong.

**Fr** — the BN254 *scalar* field, modulus
`21888242871839275222246405745257275088548364400416034343698204186575808495617`.
The field everything in this VM is arithmetized over. Not to be confused with **Fq**,
the BN254 *base* field, which is where curve coordinates live.

**Canonical form** — a field element as a 32-byte little-endian integer in `[0, p)`.
The only encoding that ever reaches a file, an artifact, or a transcript.

**Fq2** — the quadratic extension `Fq[u]/(u^2+1)`, tower level one, where G2's coordinates
live. `u^2 = -1`; an element is written `c0 + c1 u` and encoded `c0 || c1`.

**Twist** — `E'/Fq2: y^2 = x^3 + 3/(9+u)`, the D-type sextic twist of `E/Fq: y^2 = x^3 + 3`.
G2 is its order-`r` subgroup. `#E'(Fq2) = r(2q-r)`, so the twist's **cofactor** `2q-r` is
not 1 and a G2 subgroup check is real arithmetic; G1's cofactor *is* 1, so on-curve implies
in-subgroup there.

**xi** — `9 + u`, the nonresidue that builds Fq6 over Fq2. `Fq2::mul_by_nonresidue`
multiplies by it. Not to be confused with the Fq2 nonresidue `-1`, which gives `u^2+1`.

**Fq6, Fq12** — the rest of the tower: `Fq6 = Fq2[v]/(v^3 - xi)` and
`Fq12 = Fq6[w]/(w^2 - v)`, so `w^6 = xi`. Fq12 is the pairing's target group. Elements are
written `c0 + c1 v + c2 v^2` and `c0 + c1 w`, and encoded in that coefficient order. Fq12
has a **conjugate**, `c0 - c1 w`, which is its `q^6` Frobenius; Fq6 has none, because a
cubic extension has no order-two automorphism over its base.

**Frobenius map** — `a -> a^(q^i)`, spelled `frobenius_map(i)` and reduced modulo the
extension degree. Coefficientwise it is a conjugation of each Fq2 times a fixed power of
**xi**; those powers are the frozen tables in `crates/constants`.

**Pairing** — the optimal ate pairing `e : G1 x G2 -> Fq12`,
`e(P, Q) = f_{6x+2, Q}(P)^((q^12 - 1)/r)` with `x = 4965661367192848881`. Bilinear and
non-degenerate. It appears only in verification; no prover, and no recursion guest, ever
computes one.

**Miller loop** — the first half of a pairing: a double-and-add over the signed-digit
(NAF) expansion of `6x + 2`, accumulating a line function per step, then two Frobenius
correction steps. `miller_loop` runs one shared loop over many pairs, so a multi-pair check
costs one loop and not one per pair.

**Final exponentiation** — the second half: raising to `(q^12 - 1)/r`, which is what makes
the result independent of the Miller loop's conventions. Split into an *easy part*,
`(q^6 - 1)(q^2 + 1)`, and a *hard part*, `(q^4 - q^2 + 1)/r`. Ours is the **exact** power,
never a fixed multiple of it.

**Cyclotomic subgroup** — where the easy part lands: the elements of order dividing
`q^4 - q^2 + 1`. On them, conjugation *is* inversion (they are **unitary**), which is how
the hard part's negative exponents are taken for free.

**Pairing check** — `prod_i e(P_i, Q_i) == 1`, over one shared Miller loop and exactly one
final exponentiation. The verifier shape for the whole project: the deferred-pairing
accumulator is discharged by one of these.

**Uncompressed affine** — the one point encoding: `x || y` for G1 (64 bytes), `x || y` over
Fq2 for G2 (128), each coordinate canonical, all-zero for the point at infinity. There is no
compressed form anywhere in the protocol. Distinct from a point's *transcript* form, which is
four ~128-bit Fr limbs.

**Montgomery form** — the in-memory representation `x · R mod p` used for fast
multiplication. An implementation detail of `crates/field` and `crates/curve`; never
serialized.

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

**Gate** — a formula of degree at most 2 over named columns, written as a sum of terms
`coef * x_a * x_b` with the second factor optional. The degree ceiling is structural: a
term names at most two factors, so a gate above it cannot be constructed.

**Zerocheck** — the claim that a gate vanishes on every point of the cube, discharged as
the sumcheck `0 = sum_y eq(r, y) * G(y)` for `r` drawn after the witness is bound to the
transcript. Because `eq` is multilinear and `G` is degree 2, each round polynomial is a
cubic and a round message is always 4 coefficients.

**Round polynomial** — the univariate a sumcheck prover sends for one variable. Here it
is always the ascending-coefficient cubic `[c0, c1, c2, c3]`, and round `i` binds
variable `i`, so the bound point reads in the same little-endian order as a table index.

**Final evals** — the claimed value of every input column at the fully bound point,
carried in the proof and absorbed before any later challenge. They are an evaluation
claim, not a proof: discharging them against a commitment is the PCS's job.

**Layer** — one level of a GKR circuit. Each layer's values are determined by gates of
degree ≤ 2 in the layer below.

**Committed vs virtual** — a *committed* column is one the prover commits to with
Mercury and later opens. A *virtual* column is derived in closed form by the verifier
(range tables, timestamp tables, `eq`) and never committed.

**Mercury** — the multilinear polynomial commitment scheme, ePrint 2025/385, specified in
`docs/spec/mercury.md` and implemented in `crates/pcs`. A commitment *is* the univariate
KZG commitment of the column's evaluation table read as coefficients — there is no second
commitment scheme. An opening is a fixed 8 G1 points and 6 Fr values however large the
column is, costs `O(n)` field operations and `2n + O(sqrt n)` scalar multiplications, and
costs the verifier `O(log n)` field operations and two pairings. Not hiding; no ZK.

**t and b** — Mercury's shape parameters: a column of `n = 2^(2t)` evaluations is worked
on in `b = 2^t = sqrt(n)` blocks. Everything the prover builds except `q` and the fold's
KZG quotient has `O(b)` coefficients, which is why an opening's transform is size `2b` and
never larger. This is why the master prompt's trace-height menu is *even* powers of two.

**u1 and u2** — the two halves of a Mercury opening point `u`. **`u1` is the FIRST `t`
coordinates**, the ones pairing with the low `t` bits of a table index; `u2` is the last
`t`. Getting this backwards is the integration bug `docs/spec/mercury.md` §2 exists to
prevent, and the verifier rejects a swapped pair.

**Fold** — Mercury's `f(X) = (X^b - alpha) q(X) + g(X)`, the univariate division that
reduces a size-`n` claim to size-`b` ones. `g`'s coefficients are `f_i(alpha)`, and the
whole division is `b` interleaved Horner passes over the table, `O(n)` field operations
with no transform.

**Limb form** — a G1 point's *transcript* representation: four Fr values, the 128-bit
halves of each affine coordinate in the order `x` low, `x` high, `y` low, `y` high. The
point at infinity absorbs four copies of `constants::G1_INFINITY_SENTINEL`, which is
`2^128` and so cannot be any real point's limb. Frozen in `docs/spec/mercury.md` §4;
distinct from the *uncompressed affine* byte form, which is what reaches a file.

**Batched opening** — `k` same-size columns opened at **one** point as a single Mercury
instance: a challenge `rho` is squeezed after every commitment and every claimed value is
absorbed, and `cm* = sum rho^i cm_i` is opened once. The proof is one 704-byte
`MercuryProof` however many columns went into it, and the soundness cost is `(k-1)/|Fr|`.
`docs/spec/mercury.md` §11. A shard prover calls it once per shard.

**Deferred verification** — running every field-side check of a Mercury verification and
emitting the two pairing relations' terms instead of computing the pairings. The terms are
*accumulator entries*; `docs/spec/accumulator.md`.

**Accumulator** — the list of `(side, scalar, G1 point)` terms deferred verifications
produce. Lists are **concatenated, never combined**; only the final verifier spends one, and
`ShardProof` and `BlockProof` carry none, because base verification pairs inside `crates/pcs`.

**Deferred check** — one pairing relation `e(A, [1]_2) = e(B, [x]_2)` whose terms are
deferred. One Mercury verification is one deferred check and emits twelve entries, whatever
`n` and whatever a batch's `k`. Its entries are one **group**, and a group's boundary
travels with the list — as a count word on the wire, as the `checks` slice in memory.

**Pairing side** — which of the two fixed G2 arguments an accumulator term pairs against:
`G2One` is `[1]_2`, `G2X` is `[x]_2`. Written `0` and `1` on the wire.

**Discharge** — spending an accumulator: weight each deferred check by a power of a
challenge drawn from the accumulator's own digest, one MSM per side, one two-pairing check.
The weight is what keeps two checks from cancelling each other's errors.

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

**Guest** — a program proven by this VM: `no_std` Rust built for
`riscv32imac-unknown-none-elf`, linking `crates/guest-sdk`. It runs unmodified under
`qemu-riscv32`, which is what the Linux ecall numbers buy.

**ecall** — the guest's one way out. Number in `a7`, arguments in `a0`–`a5`, result in
`a0`, errors as a negated errno. `docs/spec/ecall-abi.md` is the table.

**Precompile** — a deterministic function of guest memory, dispatched by an ecall in
`0x0500..=0x05FF` with pointer arguments. A delegation circuit proves exactly that
function. Distinct from a **zkVM host call** (`0x0400..=0x04FF`), whose result is
nondeterministic prover advice. The two ranges are separate so a reviewer can tell them
apart at a glance.

**Hint** — bytes the guest reads from fd 3. Uncommitted prover advice: a shortcut to a
value the guest then checks against something bound, never an input in its own right.

**Public I/O digest** — the single `Fr` binding the guest's fd 0 and fd 1 byte streams,
`transcript::io_digest`. Frozen at S10; the statement-binding order absorbs it.
`docs/spec/ecall-abi.md` §6.

**RVC expansion** — rewriting a 16-bit compressed instruction as the exact 32-bit
instruction it abbreviates. A representation change only: addresses are preserved, never
compacted, so a two-byte instruction still occupies two bytes.

**ProgramImage** — a loaded program: sorted memory segments, the entry pc, and a
pc/2-indexed slot vector. A deterministic function of the ELF bytes, and what S11 derives
program identity from.

**Slot** — one halfword of a `ProgramImage`: the start of an instruction, the second
halfword of a 32-bit one, or not code at all. The three cases are distinguished rather
than inferred.

**FamilyId** — a circuit family's number, `constants::family`: 0 add/sub/lui/auipc,
1 jump/branch/SLT, 2 shift/bitwise, 3 mul/div, 4 mem word, 5 mem subword, 6 atomics,
7 init/teardown. Append-only; ascending `FamilyId` is the canonical order everywhere.

**Decoded table** — one family's committed setup: one row per halfword of the address
space, row `i` standing for pc `2i`, holding that family's instruction there in the
fields of its **lookup tuple**. `crates/program/CLAUDE.md`.

**Padding row** — a decoded-table row that holds no live instruction of its family:
`Fr::MINUS_ONE` in every field, never 0, because pc 0 is a valid pc and an all-zero row
would be claimable.

**Row kind** — what a live row's one-hot `family_extra_mask` bit names: its mnemonic,
except the add/sub/lui/auipc family's bit 0, the **system** kind of `ecall`, `ebreak`
and `fence`, told apart by `imm`.

**Static detachment** — a family appears in a program's `VmConfig` exactly when the
program has an instruction it claims, and init/teardown always; the preprocessor derives the set, nothing selects
it. An instruction whose family is absent fails preprocessing loudly.

**VmConfig** — a program's static VM shape: the family set, each family's trace height
from the menu `{2^16, 2^18, 2^20, 2^22}`, and `bytecode_size_words`. Per-proof shard
counts are not part of it.

**Statement descriptor** — the static `VmConfig` plus the per-proof shard count of each
of its families, absorbed as **two adjacent typed messages**, `VM_CONFIG` then
`SHARD_COUNTS`. The static part says what VM a program needs; the counts say how much of
it one execution used. `program::absorb_statement_descriptor`.

**Memory query** — one read and one write at one address: the value last written there
and when, and the value written now and when. A query that only reads writes back what
it read, so a register read is one query, never two. The memory argument's unit;
`docs/spec/execution-trace.md` is the convention every query follows.

**Memory event** — a memory query as the trace records it: address space, address,
write timestamp, read timestamp, read value, write value. The `MemoryEventLog` is every
event of one execution in timestamp order.

**Address space** — registers (`REG`, tag 1), RAM (`RAM`, tag 2, word-granular) or the
program counter (`PC`, tag 3). The tags are nonzero so no real tuple is all zeros.

**In-cycle slot, Δ** — one of a cycle's four timestamps, `4·cycle + Δ` for `Δ` in
`0..4`: slot 0 the pc query, 1 the first register read, 2 the second or a load's word, 3
the register write or a store's word. Not a `ProgramImage` slot, which is a halfword.
Distinct addresses may share a slot; one address never queries twice in one.

**Role** — what a query does in its cycle — `rs1`, `rs2`, `arg1`, `arg2`, `load`, `ram`,
`rd` — which fixes its address space, its slot, and its place among the cycle's events.

**Transfer cycle** — a cycle an ecall spends moving one word of a `read`'s or `write`'s
buffer: the pc re-written unchanged at slot 0, the word at slot 3, nothing else. A
call's transfer cycles come immediately before its own row, which writes the real
`next_pc`.

**Family buffer** — one family's executed cycles, one row each, column-major in small
integer types, holding every value the cycle's queries carried. Live rows only: padding
and polynomials are the constraint system's.

**Cycle profile** — how many cycles each family of a `VmConfig` ran, transfer cycles
included; the counts sum to the cycle count. **Shard plan** — `ceil(occupancy / height)`
shards per family, derived from it.

**Trace archive** — the self-contained snapshot of a run: a section per **phase
boundary** (post-execution, post-commit, post-GKR, post-opening, final), filled in
order, and a timing section after them, outside the deterministic payload by
construction.

**Program identity** — one `Fr`: Mercury commitments to every decoded-table column,
digested with the `VmConfig` through a fresh typed transcript. A program's identity the
way a code hash is a contract's, taken by a verifier from a channel the prover does not
control. At S11 it binds the instruction tables but not `.rodata`, `.data` or the entry pc.
