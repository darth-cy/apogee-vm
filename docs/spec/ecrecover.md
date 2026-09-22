# ecrecover: the secp256k1 recovery delegation family

Frozen as of S22. This page is the **ecrecover family**: the EVM semantics it
implements, its frame, the non-native arithmetic it is built from, the scalar
multiplication at its centre, and the scratch bus that carries a value from one
of its rows to the next.

It **consumes `docs/spec/delegation.md`** — the delegation ABI, the ecall
convention, the indirect frame, the anchor and static detachment — and amends
exactly three things there, each recorded in §8: §1's "one row is one call",
§9's "a delegation family must carry no lookup channel", and §3's forward-looking
sentence about which ecall number S22 takes. Everything else in that page is
this family's unchanged.

It cites `docs/spec/memory.md` for the memory argument, `docs/spec/lookup.md`
for the channels, `docs/spec/gkr.md` for the engine and
`docs/spec/execution-trace.md` for the clock; it restates none of them.

| crate | what |
| --- | --- |
| `crates/constants` | the ecall number, the two address-space tags, the curve, the frame offsets, the row budget |
| `crates/program` | `secp256k1`, the native arithmetic and the frame transform; the registry row |
| `crates/guest-sdk` | the shim, the software fallback, and the declaration record |
| `crates/emulator` | the ecall, and the frame's execution |
| `crates/trace` | the scratch address space, and the witness builder |
| `crates/constraints` | `ecrecover`, the circuit; `add_sub`, the request-side tag column |
| `crates/prover` | the fill, the shard plan and the ts window |
| `crates/checker` | the row suite and the tamper twins |

---

## 1. What is being proven

### 1.1 The EVM precompile

`0x01`. Input `hash(32) ‖ v(32) ‖ r(32) ‖ s(32)`, each big-endian; output is
either 32 bytes holding a 20-byte address, or **empty** — failure is an empty
return with the call still succeeding, never a revert. The validity rules, in
order:

1. `v` is 27 or 28. Nothing else, ever.
2. `1 ≤ r < n` and `1 ≤ s < n`.
3. **No low-s restriction.** EIP-2's `s ≤ n/2` rule is a *transaction-signature*
   rule; the precompile does not carry it. `crates/program/tests/vectors/
   ecrecover.txt` holds five accepted `s > n/2` lines, answered by the
   `libsecp256k1` oracle.

Then `x = r`; `c = x³ + 7 mod p`; if `c` is a quadratic non-residue there is no
point and the call fails. Otherwise `y = ±√c` with `y mod 2 = v − 27`, and

```text
e  = hash mod n                       a hash at or above n is reduced, not refused
u1 = −e · r⁻¹ mod n
u2 =  s · r⁻¹ mod n
Q  = u1·G + u2·R
```

`Q = ∞` fails. Otherwise the address is `keccak256(Q.x ‖ Q.y)[12..]`, the
64-byte uncompressed key with SEC1's `0x04` tag stripped.

**The circuit proves `Q`, or the failure. It never hashes.** The address is the
shim's, through S21's `guest_sdk::keccak256`, which is the stage prompt's
must-be-exact 4 and the reason there is no second keccak here.

### 1.2 Recovery ids 2 and 3 are unreachable

They mean `x = r + n`, and the precompile has no encoding for them: `v` is one
byte and only 27 and 28 pass. Even given an encoding they would need
`r < p − n ≈ 2^128.35`, which a uniform `r` reaches with probability about
`2^-128`. Both reasons stand alone; the first is sufficient, and the circuit
takes `x = r` unconditionally.

### 1.3 Failure is provable, in **both** directions

The frame carries a success flag, and on failure every output word is zero. Two
forgeries are therefore refused and both matter:

- **a live pubkey under a failure flag** — the stage prompt's must-be-exact 2,
  and the easy half: the output words are gated to 0 on `¬success`;
- **a failure flag on a valid signature** — the half that is *also* soundness
  and not liveness. In the target workload a contract that gets an empty return
  where the EVM returns an address takes a different branch, so a prover that
  could claim failure at will could forge state. Every branch bit of §4 is
  therefore pinned as an **exact function of the inputs**, in both directions,
  and §4.4 is the table of what pins each.

### 1.4 The curve

```text
p  = 2^256 − 2^32 − 977
n  = fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
Gx = 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
```

`constants::secp256k1`, four 64-bit limbs each, least significant first.
`crates/program/tests/secp256k1.rs` re-derives every one of them — `p` from its
closed form, `G` from the curve equation, `n` from `n·G = ∞`, and the fifteen
window multiples from the group law — rather than trusting the digits.

Three facts about the curve are load-bearing below and each is checked there:

- **`p ≡ 3 mod 4`**, so a square root is one exponentiation and **`−1` is a
  quadratic non-residue**, which §4.2's certificate needs.
- **`x³ + 7 = 0` has no solution.** `#E = n` is an odd prime, so the curve has
  no 2-torsion and no point has `y = 0`; equivalently `−7` is not a cube mod
  `p`. This is what leaves §4.2's flag no `c = 0` escape.
- **`2n > 2^256`**, so `hash mod n` has a **boolean** quotient (§4.1).

---

## 2. The family

### 2.1 The frame

42 words, 168 bytes, at `base + 4j` (`constants::ecrecover`):

| words | field | direction |
| --- | --- | --- |
| `0 ..8` | `hash` | in |
| `8` | `v` | in |
| `9 ..17` | `r` | in |
| `17..25` | `s` | in |
| `25..33` | `pubkey.x` | out |
| `33..41` | `pubkey.y` | out |
| `41` | `success`, 0 or 1 | out |

A 256-bit field is eight **little-endian** 32-bit words: word `2i` is limb `i`'s
low half and word `2i + 1` its high half.

**Little-endian, and not the EVM's big-endian.** The circuit's unit is a 64-bit
limb bounded by four 16-bit chunks; a big-endian frame would need the circuit to
reverse bytes, which 16-bit chunks cannot do at byte granularity. The shim
reverses instead, in guest code, at a few hundred instructions a call. This is
the one place this family's frame differs in kind from keccak's, whose SHA-3
byte order *is* the natural memory image.

An input word is written back unchanged, so all 42 words are read **and**
written, and `delegation.md` §4.1's frame rules apply to all of them without
exception.

The two frame rules of `delegation.md` §4 hold unchanged: the base is
word-aligned, and `RAM_ORIGIN ≤ base` with `base + 168 ≤ 2^31`. Both are fatal
guest errors in the emulator and bit decompositions in the circuit.

### 2.2 An invocation is a block of rows

**This amends `delegation.md` §1.** A keccak row is a whole permutation; a
recovery is 259 point doublings and 133 point additions over a 256-bit field,
about 1,180 non-native congruences, and no single row holds it. So:

> An invocation of `ECRECOVER` occupies `constants::ecrecover::ROWS_PER_INVOCATION`
> = **4,096** consecutive rows, aligned to that boundary. Invocation `i` of a
> shard is rows `[4096·i, 4096·(i+1))`, and a shard of `2^20` rows holds **256**
> recoveries.

Everything else §1 says is unchanged: rows are invocations rather than cycles,
the accesses ride the one global multiset, and the family is present exactly
when the binary declares it. What changes is only the row-to-invocation ratio,
and with it three mechanical things — the shard plan divides the invocation
count by `2^20 / 4096` rather than by `2^20`, the fill writes 4,096 rows per
invocation, and the frame and anchor sit on designated **steps** of the block
rather than on its one row.

A row's **step** is its index within the block, `row mod 2048`. The schedule is
a function of the step alone and is the same for every invocation, so every
per-step constant — which congruence to run, which frame word to touch, which
window digit to select — is a **schedule column**, periodic with period 2,048.
§6.2 says what a schedule column is and what binds it.

`ROWS_PER_INVOCATION` is **by measurement, not by decree** (owner's decision,
S22), and the measurement has been taken: `constraints::ecrecover::schedule`
is **3,779 steps**, which 4,096 holds with 8% to spare. It was 2,048 when this
page was first written, from an estimate of the congruence count that the
program itself corrected. What may not change is that the block is fixed,
aligned and protocol-wide rather than anything a prover or a program picks.

`crates/constraints/tests/schedule.rs` pins the step count and compares the
shapes that were measured against it:

| window | fan-out cap | steps | rows | value slots a row |
| --- | --- | --- | --- | --- |
| 2 bits | 4 | 5,086 | 8,192 | 7 |
| 3 bits | 4 | 4,159 | 8,192 | 9 |
| **3 bits** | **6** | **3,639** | **4,096** | **9** |
| 4 bits | 6 | 3,231 | 4,096 | 13 |

The chosen row is the cheapest per recovery: a wider window saves steps and
spends value slots, which every row of the shard pays for whether it selects
anything or not. (The 3,639 there is the shape before the digit's sign moved
into the selectors, which §5.2 explains and which costs 140 steps.)

### 2.3 The scratch bus

A row computes a value another row reads, and this engine has no cross-row
wiring: a gate list is row-wise or halving, and nothing else connects rows
(`docs/spec/gkr.md` §1).

**The carry rides the one global memory multiset**, in an address space of the
family's own, `address_space::DELEGATION_ECRECOVER_SCRATCH = 6`:

```text
the producing row   write   live · T(SCRATCH, addr, 4·cycle, value) + 1 − live
the consuming row   read    live · T(SCRATCH, addr, 4·cycle, value) + 1 − live
```

with `addr = ι · VALUES_PER_INVOCATION + value_id`, `ι` the invocation's index
and `cycle` its requesting cycle. The two cancel only when **every** field
agrees, which is what ties the consumer's operand to the producer's result.

Four things make that argument hold, and each is a constraint rather than a
convention:

1. **The space does not chain and needs no gap check.** Nothing initializes it,
   nothing is read twice, and `AddressSpace::chains()` is false — the same rule
   the anchor space has (`delegation.md` §5.4). A read here is not "the last
   write at this address"; it is "the one write at this address", and the
   multiset says so.
2. **It cannot be RAM.** Every row of an invocation writes at the same timestamp
   `4·cycle + FRAME_DELTA`, so a RAM scratch word written and read inside one
   invocation would need a gap of −1, which `memory.md` §7's gadget refuses.
   This is why the bus needs a space of its own and not a guest buffer.
3. **`ι` is bounded on every row**, by a bit decomposition, and not only on the
   rows that carry a frame query. `delegation.md` §5.3 bounds a keccak
   invocation's `4·cycle` through its frame writes' RAM chains; a body row of
   this family carries no chained query, so without its own bound `ι` is a free
   field element and two `(invocation, value id)` pairs could collide, forking
   the chain. §6.3 is the gate.
4. **The carried values are `M` columns.** `constraints::memory::check_memory`
   refuses any gate whose cone names a global memory slot and reads a `W`
   column, so a bus leaf's value cannot be a witness column. The limbs a row
   buses are therefore committed in the global commit phase, before the memory
   challenges, and tied to their 16-bit chunks — which *are* `W` — by an
   ordinary enforcing gate, which names no slot and may read both.

**A bus defect is a block-level `MemoryArgument` failure, not a shard-level
`Constraint` one**, because `verify_block` runs `verify_global_memory` before
any shard's own checks (`docs/spec/block-proof.md` §3). The twins of §7 are
asserted at the level that names what refuses them, which is the split S21 had
to make for the anchor.

### 2.4 The anchor, and the second delegation type

`delegation.md` §5 is unchanged: two leaves, three request-side zeroings, one
addressing rule, and the 1:1 pairing argument. `DELEGATION_ECRECOVER = 5` is
this family's anchor tag.

What S22 adds is the **tag column**. §10 of that page says a second delegation
type makes the mirror leaf's `AS` term "a sum over types of `(tag_t, m_t)`".
That cannot be built as written: `constraints::memory`'s `FRAME_SPACE[DELEG]`
is a *literal* per query slot, and `check_memory` refuses a leaf cone that
reads a `W` column — so the per-type selector `is_<t>`, which is a witness
column, can never reach it.

The requesting family therefore gains **one `M` column**, `deleg_space`,
carrying the tag, and one enforcing gate — which *may* read `W`, being no
leaf — pins it:

```text
deleg_space_rule    m_deleg · (deleg_space − Σ_t tag_t · is_t) = 0
```

The mirror leaf's `AS` part becomes the product `(1, deleg_space, m_deleg)`
rather than the literal `(tag, m_deleg)`. `ADD_SUB_LUI_AUIPC`'s memory subtree
goes from `1 + 5w` to `2 + 5w` columns and every `M` index below `deleg_space`
moves; `docs/spec/constraint-manifest.md` §3 is rewritten from the new
artifact. Nothing else about the anchor changes, and keccak's own circuit does
not change at all.

---

## 3. The non-native gadget

### 3.1 The congruence row

Every piece of arithmetic in this family is one shape:

```text
Σ_m c_m · A_m · B_m  +  Σ_j d_j · C_j  +  K·P  =  Q · P            over ℤ
```

with `A`, `B`, `C` 256-bit values in four 64-bit limbs, `c_m` and `d_j` small
signed integer literals, `P` the modulus (`p` or `n`) as limb literals, `K` a
per-shape constant chosen so the left side is never negative, and `Q` the
witnessed quotient.

Limb-wise, with `X = 2^64`, the identity is a polynomial one of degree 6:

```text
e_k = Σ_{m} c_m · Σ_{i+j=k} A_{m,i}·B_{m,j}  +  Σ_j d_j · C_{j,k}
      +  (K·P)_k  −  Σ_{i+j=k} Q_i·P_j                          k = 0 .. 6
```

`P` is a literal, so `Q_i·P_j` is **linear** in `Q`; only the `A·B` terms are
products. Each `e_k` is therefore one `Quadratic` gate with at most a handful of
products — degree 2, inside the ceiling, with no gadget.

### 3.2 The carry chain, and why the field equations lift to ℤ

```text
e_0                    = 2^64 · t_0
e_k + t_{k-1}          = 2^64 · t_k                              k = 1 .. 5
e_6 + t_5              = 0
```

**Six carries, `t_0 .. t_5`, and position 6 carries no `t_6` term at all.** A
free `t_6` would make the whole chain vacuous: telescoping would give
`Σ e_k 2^{64k} = 2^{448}·t_6`, satisfiable for any `Q` and any result, and every
product in the circuit would be free. Position 6's gate is written without it,
which is not the same as writing it and zeroing it.

Magnitudes: with at most two products a position,
`|e_k| ≤ 2·4·(2^64−1)² + … < 2^132`, and inductively `|t_k| < 2^68`. Each is
range-checked to `[0, 2^68)` after an offset of `2^67` — four 16-bit chunks on
`RANGE16` plus four booleans, which is six obligations cheaper than five chunks.

Each position equation, read as an integer statement, has both sides below
`2^133`, and `2^133 ≪ |Fr|/2 ≈ 2^253`. An integer of that size has a unique
representative mod `Fr`, so **equality in `Fr` forces equality in ℤ**. Multiply
position `k` by `2^{64k}` and sum: the carries cancel pairwise and the seven
integer identities give §3.1's equation over ℤ.

Drop any one range check and it is vacuous — a loose carry solves every position
independently, and a loose limb breaks both the uniqueness of
`Σ 2^{64i} a_i` and the magnitude argument above.

### 3.3 Canonicality, and why it is not optional

Every witnessed 256-bit value is proved **canonical**, `value < P`, and not
merely limb-bounded. The stage prompt's must-be-exact 6 requires it, and two
independent things break without it:

- **The quotient stops fitting.** With `A, B` merely below `2^256`,
  `⌊(2^256−1)² / p⌋ ≥ 2^256`, so the honest quotient needs a fifth limb and the
  honest prover has no witness. With `A, B < P` it fits four:
  `⌊(p−1)²/p⌋ < 2^256` and `⌊(n−1)²/n⌋ < 2^256`. Checked numerically in
  `crates/program/tests/secp256k1.rs`.
- **Equality stops meaning equality.** §3.4.

- **The result stops being a result.** §3.1's equation says
  `result ≡ … (mod P)`, which is all it can say: a congruence admits the whole
  residue class that fits four limbs, so `result` and `result + P` satisfy the
  same gates and a prover picks which one to bus onward. Canonicality is what
  turns a class into a representative, and it is needed on **every value a row
  writes**, not only on the ones the EVM semantics bound. This is checked
  exhaustively at reduced width in
  `crates/constraints/tests/nonnative.rs`, where the congruence alone is shown
  to admit exactly the class and the complement to leave exactly one of it.

The check is a complement with a borrow chain: witness `D` with
`value + D = P − 1` limb-wise, three boolean borrows, `D`'s limbs range-checked
like any other. Sixteen obligations and three booleans, no multiplication.

### 3.4 Equality is on 128-bit halves, never on one `Fr`

**A 256-bit value recomposed to a single `Fr` element is 6-to-1.**
`⌊p / |Fr|⌋ = ⌊n / |Fr|⌋ = 5`, so the six integers `0, |Fr|, …, 5·|Fr|` are all
below `p`, all have limbs below `2^64`, and all recompose to `0` in `Fr`. One of
them is

```text
30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
```

which is canonical and whose `Σ 2^{64i}·x_i` is zero. A difference of two
canonical values reaches ten nonzero such witnesses.

So **every equality and every zero test in this family is two 128-bit halves**:

```text
lo = x_0 + 2^64·x_1        hi = x_2 + 2^64·x_3        both < 2^128 < |Fr|
```

each injective, and `x = y` is `lo_x = lo_y ∧ hi_x = hi_y`. The repo already
splits at 128 bits for exactly this reason — `transcript::g1_limbs`, and
`G1_INFINITY_SENTINEL = 2^128` chosen because no real limb reaches it.

Writing a single-`Fr` `is_zero` anywhere here is a **total break**, not a
rounding error: §5.2's case selectors are built on it, and a selectable
degenerate branch frees `λ` (§5.3).

---

## 4. The recovery, step by step

### 4.1 Validation

| what | how it is pinned, in both directions |
| --- | --- |
| `v ∈ {27, 28}` | the frame word decomposed to 32 bits; `v − 27` is one boolean, the `recid`, and every other bit is 0 |
| `r ≠ 0`, `s ≠ 0` | `is_zero` on the two 128-bit halves (§3.4), never on the 256-bit recomposition |
| `r < n`, `s < n` | a borrow chain against `n`'s literal limbs; the final borrow **is** the boolean, so the comparison pins `r ≥ n` as exactly as it pins `r < n` |
| `hash mod n` | `hash = κ·n + e` with `e` canonical and **`κ` a single boolean**, because `2n > 2^256` |

An out-of-range input must not make the honest prover *unable* to witness: at
`r = 0` there is no `r⁻¹`. The fix is substitution, not gating —
`r_eff = r + (1 − valid_r)` is degree 1 and always invertible — which works only
because `valid_r` is exact, which is the table above.

### 4.2 The point at `x = r`

`c = r³ + 7 mod p` (two congruences). Then a **flag `f`**, boolean, and a
witnessed `w` with `t = w·w mod p` and one gate

```text
t ≡ c · (2f − 1)   (mod p)
```

`f = 1` asserts `t = c`, so `w` is a square root and the point exists. `f = 0`
asserts `t = −c`, which is a **certificate that `c` is a non-residue**: `p ≡ 3
mod 4` makes `−1` a non-residue, so `−c` being a square forces `c` not to be.
One extra congruence, against about 502 for Euler's criterion
(`(p−1)/2` has Hamming weight 249), which is why the exponentiation is not used.

At `f = 0` the gate is `t + c = p` over limbs with a borrow chain, not
`t = −c` over ℤ — free, but it has to be written that way.

**Both branches cannot hold at once**: they would force `2c ≡ 0`, i.e. `c = 0`,
which no `x` reaches (§1.4). So `f` is pinned to the truth on every input, with
no escape hatch to constrain — and that is the whole of "failure is provable in
both directions" for this case.

`y`'s parity is the recovery id: the lowest chunk of `y`'s limb 0 is split as
`2·h + b` with `h` range-checked to 15 bits, and `b = recid`.

### 4.3 The scalars

`r_inv` witnessed with `r · r_inv ≡ 1 (mod n)`; `u1 = (n − e) · r_inv mod n`;
`u2 = s · r_inv mod n`. Four congruences.

### 4.4 The outcome, and what a failing call runs

`success = valid_v ∧ valid_r ∧ valid_s ∧ is_residue`, each an exact boolean
from the rows above. The output words are `success · Q.x` and `success · Q.y`
limb-wise, so a failure zeroes them by the gate rather than by the fill.

**A failing call runs every row the successful one does.** The block is a
fixed number of rows and the same program fills it either way, so a call whose
`r` is on no curve point still walks the ladder — on substitute values, since
it has no recovered point to walk it on. That substitution is a correctness
requirement rather than a convenience: the ladder's steps assert `x2 ≠ x1` and
`y ≠ 0` (§5.3), and a point that is not on the curve, or one that is
degenerate against the other base, makes an honest prover unable to prove a
**failure** — a call the EVM says succeeds with empty output.

The substitute is `constants::secp256k1::H`, and it is **not** `G`:

| substituted | to | why |
| --- | --- | --- |
| the base point | `H` | with both of the ladder's bases equal, the accumulator and the addend are multiples of one point and `acc = ±addend` turns up within a few windows |
| `r`, in the inverse | `1` | `r = 0` is one of the failure classes, and the inverse of the divisor has to exist |
| the root's parity | `0` | a failing call has no root to take the parity of, and `y = 0` is what the two roots of §4.2 leave |

`H` is the point with the **smallest positive x** for which `x³ + 7` is a
square, taking the even `y` — a nothing-up-my-sleeve rule with no free choice
in it, re-derived from that rule in `crates/program/tests/secp256k1.rs`. Its
discrete logarithm base `G` is nobody's to know, which is what keeps the
failure path out of the exceptional case for **chosen** inputs and not merely
for random ones: steering it there needs `α·H = β·G` for an `α` and `β` the
caller picks, and on the failure path they do pick both.

---

## 5. The scalar multiplication

### 5.1 One joint ladder, three-bit signed-odd windows

`Q = u1·G + u2·R` is computed by a **single accumulator with shared
doublings**, `WINDOW_BITS = 3` and `WINDOWS = 86`:

```text
A ← T_R[d2_85] ; A ← A + T_G[d1_85]
for w in 84 .. 0:
    A ← 8·A                        three doublings
    A ← A + T_R[d2_w]
    A ← A + T_G[d1_w]
```

with `T_G = {±1, ±3, ±5, ±7}·G` and `T_R` the same multiples of `R`.

**The digits are signed and odd, and that is the whole completeness
argument.** A zero digit is an identity addition and the chord formula has no
answer for it; with every digit in `{±1, ±3, ±5, ±7}` no window ever adds the
identity, and the accumulator is initialized from a table entry rather than
from `O`, so the identity never enters the ladder at all. Every scalar has
such a representation: `u` and `u + n` are the same multiple of a point of
order `n` and exactly one of them is odd, and the recoding of an odd scalar
keeps it odd at every step. `crates/program/tests/ecrecover_schedule.rs`
checks that over random scalars.

**`G`'s eight multiples are gate literals and not committed setup columns**,
which is a deviation from the stage prompt's "G's multiples are constant, so
they ship as committed setup columns" and is recorded as one. `T_G` is the
same on every row, so a selection over it is `Σ_k (lit(T_k), s_k)` — one
`Quadratic` gate over the row's selectors and the schedule's constants, with
no commitment, no opening and no fan-out to pay for. `T_R` is not constant
and is built in circuit from one doubling and three additions, its entries
bussed like any other value.

### 5.2 Selectors, and the digits' tie to the scalar

A window's digit drives `SELECTORS = 8` boolean one-hot columns, one per
**signed** digit. Putting the sign in the selector rather than in a column of
its own is what keeps the selection at degree two: a sign column would have to
be tied to the digit on every row that reads it and then multiplied into the
selection, which is degree three. The price is four more bussed table entries
— `−y` for each of the four `x` — and nothing else.

**One-hotness alone is not enough.** With free digits a prover computes
`Σ d_w 8^w · R` for any digit string, which is any multiple of `R`, which is a
complete forgery from a missing linear gate. So the digit is accumulated:

```text
u_acc ← 8·u_acc + digit_w              one step a window a scalar
Σ_w digit_w 8^w = u                    in two 128-bit halves, never in one Fr
```

The split of §3.4 is not optional here for the same reason as everywhere
else, and more so: the attacker *chooses* the digits, so a wrap by `±q·|Fr|`
is free rather than a grinding problem.

**A window's three rows must agree on their digit.** The two selections and
the accumulation each carry selector columns of their own, and nothing ties
one row's to another's — so a prover would otherwise take `x` from one table
entry and `y` from a different one, and the "point" the ladder then adds is on
no curve at all. One row of the window **emits** its digit onto the bus and
the other two **check** their selectors against it
(`constraints::ecrecover::schedule::Digit`). The digit is bussed shifted into
`[1, 2^(w+1))`, so a negative digit is still a small positive value whose
limbs above the lowest are zero.

### 5.3 The exceptional case, and where it is refused

`λ·(x2 − x1) = y2 − y1` is **vacuous** at `x1 = x2, y1 = y2`: `0 = 0`, `λ` is
free, and `x3 = λ² − x1 − x2` then ranges over the whole field. One such row
anywhere in the ladder recovers an arbitrary public key from an honest
signature. This is the family's top forging vector.

It is refused **locally**, by one step an addition:

```text
add_dx_nonzero      witness 1/(x2 − x1)          x2 ≠ x1
dbl_y_nonzero       witness 1/y                  y ≠ 0
```

Neither witness is bussed: each exists to prove something exists, and a bus
write with no read leaves the global multiset unbalanced (§2.3). With `x2 ≠ x1`
asserted the chord's slope is determined, and with `y ≠ 0` the tangent's is.

The stage prompt's five-case complete addition — an infinity flag per point,
`z_x = [x1 = x2]`, `z_y = [y1 + y2 ≡ 0]`, and a selected branch — is **not
built**, and this is recorded as a deviation. It costs about three times the
rows, and what it buys is an answer for cases the signed-odd digits have
already removed: no window adds the identity, and `acc = ±T` mid-ladder is an
equality of group elements that a caller cannot steer into. What it does not
remove is `y = 0`, which the assertion above covers and the curve does not
have anyway (`#E = n` is odd, so there is no 2-torsion and `x³ + 7 = 0` has no
root).

The one place that argument fails is a **failing** call, and §4.4 is what
answers it.

## 6. The row schedule and the budget

### 6.1 Why one congruence a row

A channel's fraction tree costs `4F − 2 + 2(R − d) + 2n` inner columns with
`F = next_pow2(L + 1)`, `L` the row's obligations (`docs/spec/lookup.md` §6).
`F` **doubles** at `L = 128`, so the row's obligation count is a cliff and not a
slope:

| obligations a row | `F` | inner from `RANGE16` | rows an invocation | forward pass at `2^20` |
| --- | --- | --- | --- | --- |
| ≤ 127 | 128 | 510 | 2,048 | ~28 GB |
| ≤ 255 | 256 | 1,022 | 1,024 | ~40 GB |
| ≤ 511 | 512 | 2,046 | 512 | ~70 GB |

One whole point operation is about 290 obligations and lands in the third row of
that table, which `2^20` does not have the memory for. **One congruence a row**
— its quotient's 16 chunks, its six carries' 24, and the one value it witnesses
with its canonicality complement, 32 — is about 72, comfortably under the cliff.

A coarser row is cheaper *per signature* and the handoff records the
measurement; what pins the choice is the height, and the height is the stage
prompt's.

### 6.2 The step schedule, and what binds it

The schedule is a table of 2,048 steps, each naming a congruence shape, its
operands' bus addresses and its result's, and it is the same for every
invocation. A row's behaviour must be a function of its step and of **nothing a
prover chooses**: if a prover could pick which operands a step reads, the bus
would carry a dataflow of their choosing and the multiset would still balance,
because a multiset pairs a read with a write and says nothing about which write
it should have been.

**The schedule columns are virtual** (owner's decision, S22), not committed.
`VirtualKind` gains this family's tables, each a step-periodic constant with a
closed-form multilinear extension over the low `log2(ROWS_PER_INVOCATION)`
variables, evaluated by both halves of the engine from the same source:

```
V[sched_k](y) = Σ_{i < 2048} eq(y_0..y_10, i) · c_k[i]
```

Three routes were weighed, and they differ in what a verifier must trust:

| route | what binds the schedule | price |
| --- | --- | --- |
| **virtual columns** | `family_circuit`, which `VerifyingKey::check` already holds every key's circuit equal to | `gkr.md` §2's virtual-table set grows, and the tables' constants sit in a `no_std` crate |
| setup columns, identity | the identity channel, as the decoded tables are bound | identity would cover a protocol constant that is the same for every program |
| setup columns, SRS digest | the ceremony, recomputable by anyone holding it (S17's generic table) | every verifying key's SRS digest and bytes move again, and a new pinned vector file |

The first was chosen because it adds **no trust surface at all**: a virtual
column is never committed, never opened, and never sent, so there is nothing for
a key builder to substitute. The schedule becomes part of the circuit, and a
circuit that is not the protocol's is already refused by
`VerifyingKey::check` — the same check that refuses a tampered gate list refuses
a tampered schedule, for free. It also keeps every S16–S21 key's identity and
SRS digest exactly where they are.

The price is real and is paid in one place: `gkr-verify` is `#![no_std]` and the
recursion guest links it, so the schedule's constants are image bytes for that
guest. They are protocol constants either way; what the choice moves is whether
they are carried as curve points in a key or as a table in the source.

### 6.3 The bounds every row carries

| what | how |
| --- | --- |
| a limb `< 2^64` | four 16-bit chunks on `RANGE16` |
| a carry `∈ [0, 2^68)` | four chunks and four booleans, after an offset of `2^67` |
| a value canonical | the complement of §3.3 |
| the invocation index `ι` | a bit decomposition, **on every row** (§2.3 rule 3) |
| a frame read's timestamp gap | `memory.md` §7's 19+19 pair on `TIMESTAMP`, which fits: `19 ≤ 20` |
| every selector, flag and borrow | `x² = x` |

`TIMESTAMP` fitting is the one thing this family has that keccak does not, and
it is what `2^20` buys over `2^8`: the gap check is S14's gadget rather than 38
booleans.

---

## 7. What this does not do

- **It does not derive an address.** §1.1.
- **It does not batch.** One invocation is one signature, in the fixed frame of
  §2.1 (the stage prompt's must-be-exact 8).
- **It does not bind the result to anything but memory.** The frame after is the
  function of the frame before; that the guest then reads it is the RAM chain's
  business, as it is for every delegation (`delegation.md` §11).
- **It does not change the proof's shape.** An `ECRECOVER` `ShardProof` is a
  `ShardProof`.

---

## 8. What S22 amends, and the price

Three sentences of `docs/spec/delegation.md`, each because it was written when
only one delegation family existed.

| where | what it said | what it says now | price |
| --- | --- | --- | --- |
| §1 | "Its rows are invocations, not cycles. One row is one call." | rows are invocations; **a family may take a fixed aligned block of rows per invocation** (§2.2) | the shard plan, the fill and the ts window read the block size; keccak, at one row, is unchanged |
| §9 | "A delegation family … must carry no lookup channel." | a delegation family must be absent from `family_circuit`'s minimum-height arm; **a channel is allowed at a height that fits it** | none for keccak, which still carries none at `2^8` |
| §3 | "`0x0500` is `PRECOMPILE_POSEIDON2` … S22 gives it one and takes address-space tag 5" | S22 is **ecrecover**; it takes `0x0502` and tags 5 and 6, and S23 takes the next of each | S23's pencilled tag 6 becomes 7; nothing is published, `PROTOCOL_VERSION` is still 0 |

It also amends **one sentence of `docs/spec/gkr.md`** §2, the virtual-table set:

| where | what it said | what it says now | price |
| --- | --- | --- | --- |
| `gkr.md` §2 | the four virtual tables are `V[row]`, `V[ram_live]`, `V[range19]`, `V[range16]` | a virtual table may also be a **step-periodic schedule table**, whose extension is a sum over one period of `eq` against a constant vector (§6.2) | the constants are `no_std` source the recursion guest will link; no key's bytes, identity or SRS digest move |

§9's sentence is the one worth reading twice. Its stated reason was that at
`2^8` no range channel's table fits, which is true of `BITS = 16` and is not a
principle. What *is* a principle, and is unchanged, is that a delegation family
must not be in the minimum-height arm: that arm exists so a family missing from
it cannot reach `lookup::channel_trees`' assertion inside `VerifyingKey::check`
on bytes a verifier was handed. `ECRECOVER` at `2^20` satisfies
`BITS[RANGE16] = 16 ≤ 20` and `BITS[TIMESTAMP] = 19 ≤ 20` and returns `None`
below that, which is the same guarantee reached the other way.
