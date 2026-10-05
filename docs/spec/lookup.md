# Lookups

How a circuit's lookup obligations are proved: per shard, by one LogUp channel per table, each
summed by a fraction tree inside the circuit's own GKR pass and checked at its root.

## 1. What a channel claims

A **lookup** is `LookupExpr { name, channel, selector, tuple }`: a channel of
`constants::lookup_channel`, a committed `M`, `W` or `S` column as **selector**, and a tuple of
`Linear` expressions with literal coefficients over committed columns and the circuit's virtual
tables. It holds on a row where the selector is 0, or

- on a **range channel**, where its one expression's canonical integer is below `2^BITS[channel]`;
- on a **table channel**, where its tuple is a row of the channel's one table: 1 to
  `MAX_TUPLE = 7` expressions, the same number for every lookup of the channel.

[memory.md](memory.md) §7 is the convention range obligations follow. A **channel** discharges all
of a shard's lookups on it as one identity over the shard's rows `y`:

```text
Σ_y Σ_l 1/(E_l(y) + g)  −  Σ_y mult(y)/(T(y) + g)  =  0
```

`E_l(y)` is lookup `l`'s gated tuple (§4) and `T(y)` the table's row `y`, both compressed by `β`
(§5); `mult` is the channel's multiplicity column (§7). A range table is the one column
`[0, 2^BITS)`.

## 2. The challenges

| slot | `challenge_slot` | value |
| --- | --- | --- |
| 6 | `LOOKUP_G` | `g`, drawn |
| 7 | `LOOKUP_BETA` | `β`, drawn |
| 8–12 | `LOOKUP_BETA_2` … `LOOKUP_BETA_6` | `β^2` … `β^6`, derived |
| 13 | `LOOKUP_DECODER_NEUTRAL` | `g − Σ_{j<W} β^j`, derived; `W` the decoder tuple's width |

`g` and `β` are **shard-local**: the shard's transcript draws them, in that order under the tag
`LOOKUP_CHALLENGE` (33), right after absorbing its witness commitments, multiplicities included
([proof.md](proof.md) §4). `M` columns are committed in the global transcript the shard is seeded
from and `S` columns are bound by identity or the SRS digest, so every column a channel reads is
fixed before either challenge exists.

`β^0` is the literal 1, so a one-column tuple names no slot. A gate coefficient is one literal or
one slot ([gkr.md](gkr.md) §3), so each higher power is a slot of its own, computed by the verifier
and never read from a proof (`gkr_verify::insert_lookup_challenges`, which reads `W` off the
artifact's decoder lookup).

**Selectors are boolean**: `CircuitArtifact::validate` refuses a lookup whose selector no enforcing
gate of gate list 0 holds to `s − s·s = 0`. The selector multiplies the tuple inside the denominator
(§5), so a channel proves the gated tuple `s·(e + o) + n` is a table row, which is the obligation
only at `s ∈ {0, 1}`. At any other `s` a scaled tuple is looked up instead: on a range channel,
`s = t·e⁻¹` lands any nonzero `e` on any table value `t`.

## 3. Tables

| channel | id | kind | table, at row `y` | width | `table_vars` |
| --- | --- | --- | --- | --- | --- |
| `TIMESTAMP` | 0 | range | `V[range19]`: `y mod 2^19` | 1 | 19 |
| `RANGE16` | 1 | range | `V[range16]`: `y mod 2^16` | 1 | 16 |
| `GENERIC` | 2 | table, committed | the packed table (§9) | 3 | 0 |
| `DECODER` | 3 | table, committed | the family's decoded table (§10) | 7 or 6 | 0 |
| `XOR8` | 4 | table, virtual | `V[xor8_a]`, `V[xor8_b]`, `V[xor8_out]`: `y`'s low two bytes and their XOR | 3 | 16 |

A virtual table is a closed form of the row index, never committed: the verifier evaluates its
multilinear extension where the GKR pass ends (`gkr_verify::virtual_at_point`, [gkr.md](gkr.md) §2).
Each is a weighted sum of the row's bits but `V[xor8_out]`,
`Σ_{j<8} 2^j·(y_j + y_{j+8} − 2·y_j·y_{j+8})`, which is exact because `y ^ z = y + z − 2yz` is
multilinear. So `XOR8` costs no commitment and nothing in the SRS digest.

`constraints::lookup::table_vars` is the fewest variables at which a table is complete: `BITS` for a
range channel, 16 for `XOR8`, 0 for a committed table, a setup column at the circuit's own height.
Below it a virtual table holds only part of its range, which costs completeness, not soundness.
`family_circuit` returns `None` below the largest `table_vars` of a family's channels, so a key
naming such a height fails to load ([proof.md](proof.md) §7). On the height menu
([program.md](program.md) §7) a family carrying `TIMESTAMP` is at `2^20` or more, and one carrying
`RANGE16` or `XOR8` at `2^16` or more. The packed table needs `2^18` rows (§9), and every family
that reads it carries `TIMESTAMP`. Above `table_vars` a table repeats, which §7 makes harmless.

`XOR8`'s tuple is three wide so that membership bounds each entry to `[0, 256)` on its own; a packed
key `x + 256·y` would bound neither, `(x, y)` and `(x + 256, y − 1)` compressing alike. Every other
bitwise operation on bytes is a linear form over its results
([delegation-circuits.md](delegation-circuits.md) §1).

## 4. Gated keys

A lookup expression is evaluated on every row, so the selector sends a row whose key means nothing
to a **neutral** tuple, which is a real table row:

| gating | channels | gated position `j` | neutral tuple |
| --- | --- | --- | --- |
| `NoOffset` | `TIMESTAMP`, `RANGE16`, `XOR8` | `s·e_j` | all zero |
| `ZeroEntry` | `GENERIC` | `s·(e_0 + 1)`, then `s·e_j` | the all-zero `ZeroEntry` row |
| `MinusOne` | `DECODER` | `s·(e_j + 1) − 1` | −1 in every column, a padding row |

The `+ 1` keeps every real key of the packed table at 1 or above, so no real entry is the all-zero
tuple a switched-off row looks up. A range table needs no offset, 0 being in range, and one would
push `2^BITS − 1` out of it; `XOR8`'s `(0, 0, 0)` is a true entry. A decoded table has no all-zero
row, pc 0 being a valid pc, and its `MINUS_ONE` padding rows ([program.md](program.md) §5) are the
neutral entry.

**Each key a table channel looks up is bounded by the family that looks it up**, because a channel
proves membership and nothing more. A selected row whose key expression is −1 gates to the
`ZeroEntry`, and an unbounded key reaches any sub-table of the packed table: an AND key
`a + AND_BASE` with `a` unbounded lands on a `U16GetSign` row and proves a false AND. Families bound
their keys with `RANGE16` obligations or build them from bounded columns
([shift-bitwise.md](shift-bitwise.md) §3 and the other family pages); the decoder's key is §10's.

## 5. The denominator

With `s` the selector, `e_j = Σ_i c_{j,i}·x_{j,i} + k_j`, and §4's offset `o_j` (1 or 0) and
neutral value `n_j` (−1 or 0):

```text
E + g  =  Σ_j β^j·(s·(e_j + o_j) + n_j)  +  g
       =  Σ_j β^j·s·e_j  +  Σ_j β^j·o_j·s  +  (g + Σ_j β^j·n_j)
T + g  =  Σ_j β^j·t_j  +  g
```

`E + g` is one `Quadratic` (`constraints::lookup::row_denominator`): each term of `e_j` the product
`(β^j·c)·s·x`, each offset the linear term `β^j·o_j·s`, and the bracket the slot `LOOKUP_G` or, for
the decoder, `LOOKUP_DECODER_NEUTRAL`. `β^j·c` is one coefficient only where `β^0 = 1` makes it a
literal or `c = 1` makes it the slot, so position 0 takes any literal coefficients and constant and
every later position weights its columns by 1 with no constant. `T + g` is one `Linear` over the
table's columns (`table_denominator`).

## 6. The fraction tree

A channel's leaf level is `(num, den)` pairs of gate-list-0 columns,
`P = (L + 1).next_power_of_two()` of them for `L` lookups:

| leaf | `num` | `den` |
| --- | --- | --- |
| the table, first | `−mult` | `T + g` |
| each lookup, in artifact order | 1 | `E_l + g` |
| padding, up to `P` | 0 | 1 |

Row-wise gate lists add sibling pairs, `(n_a·d_b + n_b·d_a, d_a·d_b)`, until each row holds one
pair; a tree shallower than the circuit's deepest copies itself up. Then `trace_vars` halving lists
add the rows' pairs, `TreeCross` writing the numerator and `TreeProduct` the denominator
([gkr.md](gkr.md) §3). The circuit's outputs are the memory argument's read and write roots, then
each channel's `(num, den)` in the order of its channel specs (`crates/constraints/src/build.rs`).

A channel costs `4P − 2` inner columns to reduce a row, 2 more per copy-up layer and 2 per halving
list, and one committed column. `P` doubles each time `L` reaches a power of two.

The padding clause ([gkr.md](gkr.md) §4) asks a padding row to feed 1 into every product tree. A
fraction tree is exempt: its identity is `(0, 1)`, and a padding row is not idle in a channel but
looks up the neutral tuple, which the multiplicity counts. `checker::check_padding_identity` exempts
every column a `TreeCross` reads.

## 7. Multiplicities

Each channel has one multiplicity column, a committed `W` column; a circuit's are its last `W`
columns, in channel order. Row `t` counts the (row, lookup) pairs of the shard whose gated tuple is
table row `t`'s, switched-off rows included. A tuple at several table rows is credited to the
lowest; every other copy holds 0 and contributes `0/(T + g)`. The count is over raw gated tuples,
the column being committed before `g` and `β` exist (`trace::build_multiplicities`, which refuses a
tuple no table row holds: the honest prover cannot balance it).

No gate or range check constrains the column, and soundness needs none. If a gated tuple `v` is in
no table row, the left side of §1's identity, as a rational function of `g`, has a pole at `−v`
whose residue is the number of lookups producing `v`: a positive integer below `p`, whatever the
column holds.

## 8. The root check

```text
accept  iff  num = 0  and  den ≠ 0
```

on each channel's root pair, at step 9 of [proof.md](proof.md) §6 (`gkr_verify::channel_holds`); a
failure is `VerifyError::Lookup { channel }`. The GKR pass absorbs the pair before its first
challenge and proves it ([gkr.md](gkr.md) §5). `den` is the product of every leaf denominator, and
`num = 0` means the sum vanishes only where `den ≠ 0`: one leaf `(0, 0)` — a table row whose
`T + g` vanishes, counted 0 — makes the root `(0, 0)` whatever the other leaves hold. With `g`
drawn after the columns that has probability at most fractions/`|Fr|`, and `den ≠ 0` makes it a
refusal.

## 9. The generic table

One committed table of `constants::generic_table::WIDTH = 3` columns, a key and two values, packing
three sub-tables under disjoint key ranges (`program::lookup_tables::generic_table`):

```text
row 0                      ZeroEntry    (0, 0, 0)
rows 1 ..= 2^16            AND          (AND_BASE + a + 1,    b,        a & b)        a, b < 2^8
rows 2^16+1 ..= 2^17       U16GetSign   (SIGN_BASE + h + 1,   h >> 15,  0)            h < 2^16
rows 2^17+1 ..= 2^17+32    ShiftPowers  (SHIFT_BASE + s + 1,  2^s,      2^(31 − s))   s < 32
rows above                 zero
```

`AND_BASE = 0`, `SIGN_BASE = 256` and `SHIFT_BASE = 65,792` put the keys at `1..=256`,
`257..=65,792` and `65,793..=65,824`; a lookup's key expression is `x + BASE`, and the gating adds
the 1. `U16GetSign` serves every sign an execution family computes, AND the bitwise operations of
`SHIFT_BITWISE` and `ATOMICS`, `ShiftPowers` the shifts. The copower `2^(32 − s)` is stored halved
(`SHIFT_COPOWER_BITS = 31`), `2^32` not fitting a `u32` column, and the two gates that read it carry
the factor 2 ([shift-bitwise.md](shift-bitwise.md) §4). 131,105 rows in all (`GENERIC_ROWS`).

**Its commitments are a constant of the ceremony.** A Mercury commitment reads the evaluation table
as coefficients ([mercury.md](mercury.md) §2) and the table is zero past its entries, so over `2^n`
rows it commits to the same three points for every `n ≥ 18`; `generic_commitments(srs)` computes
them at `2^18` (`GENERIC_LOG_HEIGHT`). Every verifying key carries them once, as
`VerifyingKey::generic_table`, whether or not a family reads the channel, and its SRS digest covers
them ([proof.md](proof.md) §3); program identity does not. A circuit that reads `GENERIC` names the
table as its three setup columns after identity's (`FamilyCircuit::reads_generic_table`), and a
shard's opening checks them against the key's points ([proof.md](proof.md) §5).

## 10. The decoder channel

The `DECODER` table is the family's decoded table, `program::lookup_tuple(family)`'s columns, as its
first setup columns at its height, row `i` holding pc `2i` ([program.md](program.md) §5); program
identity commits them ([program.md](program.md) §8). Each execution family makes one lookup on it,
`imm` absent for `MUL_DIV` and `ATOMICS`:

```text
decode_row    selector m_pc    tuple (pc read value, next_pc, rs1, rs2, rd, [imm], extra_mask)
```

The key is the frame's own pc read ([memory.md](memory.md) §2), so the cycle itself is bound to the
program; the rest are the row's decoded columns, which the family's other gates read. The selector
is the row's liveness, so a padding row looks up the `MINUS_ONE` tuple, which every decoded table
holds, being taller than its last instruction.

The family's `decoded_mask_bits` gate ties the packed mask to boolean kind bits. That the bits are
one-hot, and that a live row is an instruction at all, is the table's domain: its live rows hold
one-hot masks and its padding rows −1, which no sum of kind bits reaches. Boolean columns looked up
one by one would lose this: booleanity admits any subset of bits, the empty one included, and an
all-zero mask makes every gate a kind selects vacuous.

## 11. Construction rules

`CircuitArtifact::validate` enforces §1's form and widths, §2's selector rule and §5's coefficients
wherever an artifact is built or loaded ([gkr.md](gkr.md) §4). When a circuit is assembled,
`constraints::lookup` asserts that a channel has a lookup, that its multiplicity is a `W` column,
that every lookup has its table's width, and that a range channel's table is the one its bound names
(`range_table`) with `BITS ≤ trace_vars`; `constraints::memory::frame_with_channels_artifact`
refuses an empty channel list, which would leave a frame's gap obligations discharged by nothing.

**The discharge rule**, `constraints::lookup::check_discharge`, at assembly and at every key load
(`VerifyingKey::check`): every lookup is the denominator of exactly one gate-list-0 column, its
numerator 1 directly before it; no column is two lookups'; each channel's `(−mult, T + g)` appears
once. It matches by normalized expansion inside the cone below the channel's own root pair, so an
obligation or table fraction in another channel's tree is refused, and the two range channels,
which gate alike, are not confused. Which output pair is whose root, which columns are a table and
which counts it is not in the artifact but in its `ChannelSpec`s, which a key carries in
`FamilyCircuit::channels` and must hold as the registry's ([circuits.md](circuits.md) §1). `checker`
enforces this rule and the lookup rules a second time, with code of its own
([circuits.md](circuits.md) §3).

**The copower rule**, `constraints::lookup::check_copowers`, run by every constructor that bounds a
column through a copower. A bound `x < p` written as `x·p′ < 2^32`, `p·p′ = 2^32`, bounds nothing
alone: `p′` is a unit of `Fr`, so `x = s·p′⁻¹` ranges over a coset of `2^32` values. Each such `x`
therefore also carries a direct `RANGE16` bound, as a halfword or as a high chunk and a remainder,
under the same selector.

## 12. What it rests on

- **Every gated tuple is a table row**: §1's identity over challenges drawn after every column it
  reads, boolean selectors (§2), both root conditions (§8) and the GKR pass. The error is at most
  fractions/`|Fr|` for `g`, plus looked-up tuples × table rows × (width − 1)/`|Fr|` for a `β`
  collision: below `2^−190` at every menu height.
- **A lookup answers from its own sub-table**: one width per channel (§11), disjoint key ranges and
  the `+ 1` (§9), and its family's bound on the key (§4).
- **A switched-off row costs nothing**: its neutral tuple is a table row the multiplicity counts
  (§4).
- **The table is the intended one**: the verifier's own closed form (§3), or a table bound by
  identity or by the SRS digest, as trustworthy as the channel the verifier took that from
  ([program.md](program.md) §8, [srs.md](srs.md) §3).
- **Every declared obligation is discharged**: the discharge rule over the registry's specs (§11).

The channel does not check the multiplicity column (§7), a key's bound (§4), or that a committed
table holds its neutral row, a property of its values that no artifact states: a table without one
stops the honest prover at `trace::build_multiplicities`.
