# The `JUMP_BRANCH_SLT` family: comparisons, branches, jumps

Frozen as of S17. Changing anything here is a protocol-version change.

This page is S17's circuit family as the repository owner decided it: `jal`, `jalr`, the six
branches, `slt`, `sltu`, `slti` and `sltiu`, proved by one circuit whose comparison settles
signed and unsigned ordering in one degree-2 equation; the two gadgets S18 and S19 reuse; and
the binding of the generic table this family is the first to read. It cites
`docs/spec/memory.md` for the frame, `docs/spec/lookup.md` for the channels and
`docs/spec/shard-proof.md` for the statement, the key and the transcripts, and restates none
of them. `docs/spec/constraint-manifest.md` §4 is the column-by-column account.

| crate | what |
| --- | --- |
| `crates/constants` | `generic_table`: the packed table's width and key bases, moved from `program` (`lookup.md` §9); tag 41, `GENERIC_TABLE`, the SRS digest's second message |
| `crates/constraints` | `gadgets`: `is_zero` and the comparison (§3); `jump_branch_slt`: the circuit (§2, §4, §5); the registry's arm; `FamilyCircuit::reads_generic_table` (§6) |
| `crates/program` | `lookup_tables::generic_commitments` and `GENERIC_LOG_HEIGHT`: the packed table's commitments (§6) |
| `crates/verifier-core` | the key's `generic_table`, its wire form and load rules, the SRS digest over it, the opening's `S` list (§6) |
| `crates/verifier` | the table's three points decoded at load (§6) |
| `crates/prover` | the family's fill; the key's generic table and the SRS digest over it; the opening's `S` list |
| `guests/control` | the family's fixture program |

The owner's decisions this page records. Each was put before any code, except decision 2,
which the owner settled after the review:

1. **The decoded table is S11's, unchanged.** The stage prompt's five-bit mask — JAL, JALR,
   SLT-family, BRANCH, RD_IS_ZERO, legal set `{1, 2, 4, 17, 18, 20, 24}` — and its extra
   decoder columns (`cmp_imm`, a separate displacement, `sc`, the weight triples) would have
   rebuilt the family's frozen table, needed twelve lookup-tuple columns where
   `lookup_channel::MAX_TUPLE` is seven, and moved every identity pin over a program that
   jumps. Everything they carry is a function of the twelve one-hot bits S11's table
   already has (§1).
2. **The generic table is folded into the SRS digest** (§6), not bound in program
   identity. The owner's S16 answer 8 gave the binding to the first family that reads the
   channel, and the owner's answer at S17 chose the SRS digest. Besides identity, the SRS
   digest is the one value a verifier takes on trust. Commitments that a
   key carries and no trusted value covers would let a key with another table's
   commitments load under a trusted identity and a trusted digest. Every key carries one
   set of the table's three commitments, and the SRS digest covers them after the
   `SrsVerifier`. The table is a constant of the ceremony, as the verifier points are, so
   one trusted digest pins both, and S16's global transcript is unchanged. This amends
   `shard-proof.md` §3 and §9.
3. **Every `next_pc` this family writes is range-checked even** (§4.4) — a sixth range
   obligation on `next_pc` the prompt did not ask for. Without it a `jalr` whose `rs1 + imm`
   is 1 keeps bit 0 and writes `HALT_PC`, and a statement over a program that would crash
   there is accepted as a clean exit (§7.3). `memory.md` §5 already listed "jalr's bit-0
   clear" as this family's.
4. **One consolidated fixture guest**, `guests/control`, not one per instruction, with a
   test that checks it runs every instruction and every case the acceptance names.

---

## 1. What the circuit reads from the decoded table

S11's table for this family is `pc next_pc rs1 rs2 rd imm extra_mask`, one row per halfword,
`MINUS_ONE`-padded (`crates/program/CLAUDE.md`). `extra_mask` is one-hot over
`constants::extra_mask::jump_branch_slt`:

| bit | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| kind | `slti` | `sltiu` | `slt` | `sltu` | `beq` | `bne` | `blt` | `bge` | `bltu` | `bgeu` | `jalr` | `jal` |

`imm` is the value the instruction uses, two's complement: the compare immediate of `slti`
and `sltiu` (sign-extended, which is what `sltiu` compares unsigned), the displacement of a
branch or `jal`, the offset of `jalr`. A form's absent register is `x0`. `next_pc` is the
fall-through, `pc + 2` or `pc + 4` by the instruction's length.

**The legal masks** are the twelve one-bit values, `jump_branch_slt::LEGAL_MASKS`, and the
table's domain is what enforces them (`lookup.md` §10). `rd = x0` is not a mask of its own:
the table's `rd` column says it, and the frame's x0 rule acts on it (§4.1). Every signal the
prompt asked the decoder for is a linear form over the twelve bits `b_k` the circuit extracts:

| signal | form | on |
| --- | --- | --- |
| `sc`, signed compare | `b_slti + b_slt + b_blt + b_bge` | the comparison's two sign terms |
| `cmp_imm` | `(b_slti + b_sltiu)·imm` | `cmp_rhs` — zero on every branch row, whose `imm` is a displacement |
| `w_const` | `b_bne + b_bge + b_bgeu` | `taken` |
| `w_eq` | `b_beq − b_bne` | `taken` |
| `w_lt` | `b_blt + b_bltu − b_bge − b_bgeu` | `taken` |
| `seq`, the fall-through | the table's `next_pc` | `next_pc`'s default arm, and the link |

The weight triples `(w_const, w_eq, w_lt)` are therefore BEQ `(0, 1, 0)`, BNE `(1, −1, 0)`,
BLT and BLTU `(0, 0, 1)`, BGE and BGEU `(1, 0, −1)`, and `(0, 0, 0)` on every other row.

## 2. Columns

`constraints::jump_branch_slt::artifact(trace_vars)` and `::channels()`, through S15's
`frame_with_channels_artifact`. The circuit is built from `trace_vars = 19` — the timestamp
channel's width, which also holds the generic table's `2^17 + 1` rows — and a provable
height is at least 20, a Mercury opening needing an even count (as `shard-proof.md` §8 says
of add/sub).

The frame is `memory.md` §2.1's over the family's four queries — `pc rs1 rs2 rd` at slots 0
to 3 — so `M[0..21]` and `W[0..7]` (the four gap chunks, `rd_inv`, `rd_is_zero`,
`rd_selected`) are the frame's. The circuit adds:

| column | name | what |
| --- | --- | --- |
| `W[7]`–`W[12]` | `decoded_next_pc` … `decoded_mask` | the claimed decoded row, `lookup_tuple` after `pc` |
| `W[13]`–`W[24]` | `kind_slti` … `kind_jal` | the mask's twelve bits, §1's order |
| `W[25]` | `cmp_rhs` | the comparison's right operand, `rs2 + cmp_imm` |
| `W[26]`, `W[27]` | `rs1_hi`, `rs1_sign` | `rs1 >> 16`, `rs1 >> 31` |
| `W[28]`, `W[29]` | `cmp_rhs_hi`, `cmp_rhs_sign` | `cmp_rhs >> 16`, `cmp_rhs >> 31` |
| `W[30]` | `lt` | `rs1 < cmp_rhs` in the ordering `sc` selects |
| `W[31]`, `W[32]` | `cmp_gap`, `cmp_gap_hi` | `(rs1 − cmp_rhs) mod 2^32`, and its high halfword |
| `W[33]`, `W[34]` | `eq`, `eq_inv` | `[rs1 = cmp_rhs]` on a live row, and the inverse of the difference |
| `W[35]` | `taken` | a taken branch |
| `W[36]` | `jalr_drop` | bit 0 of `rs1 + imm` on a `jalr` row |
| `W[37]` | `pc_wrap` | the wrap of the sum `next_pc` is |
| `W[38]` | `next_pc_hi` | `next_pc >> 16` |
| `W[39]` | `rd_hi` | `rd_selected >> 16` |
| `W[40]`–`W[43]` | `mult_timestamp`, `mult_range16`, `mult_generic`, `mult_decoder` | one multiplicity per channel, last |
| `S[0]`–`S[6]` | `table_pc` … `table_extra_mask` | the decoded table, bound by identity |
| `S[7]`–`S[9]` | `generic_key`, `generic_value`, `generic_result` | the packed generic table, opened against the key's generic table, which the SRS digest covers (§6) |
| `V[range19]`, `V[range16]` | | the two range tables |

`rd_selected` (`W[6]`) is the value the instruction **computes** — the link, or `lt` —
before the x0 rule masks it into the write, as at S16. **21 `M`, 44 `W`, 10 `S`: 75
committed columns.**

## 3. The two gadgets

`constraints::gadgets`, public for S18 (magnitude comparisons, `rem ≠ 0`) and S19
(`amomin`/`amomax`).

### 3.1 `is_zero`

```rust
pub fn is_zero(x: &[(Coeff, PolyAddress)], inv: PolyAddress, z: PolyAddress,
               enable: PolyAddress) -> [GateDef; 2]
```

```text
x·inv + z − enable = 0          x = Σ c_i·x_i
z·x = 0
```

With `enable` boolean — the caller's to establish — these force `z = enable·[x = 0]`: at
`x ≠ 0` the second gives `z = 0` and the first `inv = enable/x`; at `x = 0` the first gives
`z = enable`. So `z` is boolean with no gate of its own, and a row with `enable = 0` has
`z = 0`, which is what keeps the all-zero padding row valid. (The prompt's `diff·inv + eq −
1 = 0` would make the all-zero row invalid.) S14's x0 rule is this gadget over `x = addr`,
enabled by the `rd` mask, and is rebuilt on it with its bytes unchanged.

### 3.2 The comparison

```rust
pub struct Comparison { pub prefix: String, pub selector: PolyAddress, pub signed: Vec<PolyAddress>,
                        pub lhs, pub lhs_hi, pub lhs_sign, pub rhs, pub rhs_hi, pub rhs_sign,
                        pub lt, pub gap, pub gap_hi: PolyAddress }
pub fn comparison_equation(c: &Comparison, word_bits: u32) -> GateDef
pub fn comparison(c: &Comparison) -> (Vec<(String, GateDef)>, Vec<LookupExpr>)
```

**The equation**, one ungated degree-2 gate, with `sc = Σ signed`:

```text
0 = lhs − rhs − 2^32·sc·lhs_sign + 2^32·sc·rhs_sign + 2^32·lt − gap
```

With `D = lhs − rhs − 2^32·sc·(lhs_sign − rhs_sign)` — both operands read in two's
complement where `sc` is 1, so mixed signs are never a case split — and `lhs`, `rhs` in
`[0, 2^32)`, the signs their bit 31, and `sc` in `{0, 1}`, `D` lies in `(−2^32, 2^32)`.
The equation says `gap = D + 2^32·lt`. With `lt` boolean and `gap` in `[0, 2^32)` exactly one
pair survives: at `D ≥ 0`, `lt = 1` puts `gap` at `2^32` or above; at `D < 0`, `lt = 0`
makes `gap` a negative field element, which is no integer below `2^32`. **The range check on
`gap` carries the soundness.** The honest `gap` is `(lhs − rhs) mod 2^32` whatever `sc` is,
since `D ≡ lhs − rhs`.

**What `comparison` returns**, every lookup under `selector`:

| name | kind | expression |
| --- | --- | --- |
| `<p>_order` | gate | the equation at 32 bits |
| `<p>_lt_boolean` | gate | `lt − lt·lt` |
| `<p>_lhs_hi_range`, `<p>_lhs_lo_range` | `RANGE16` | `lhs_hi`; `lhs − 2^16·lhs_hi` |
| `<p>_rhs_hi_range`, `<p>_rhs_lo_range` | `RANGE16` | `rhs_hi`; `rhs − 2^16·rhs_hi` |
| `<p>_gap_hi_range`, `<p>_gap_lo_range` | `RANGE16` | `gap_hi`; `gap − 2^16·gap_hi` |
| `<p>_lhs_get_sign` | `GENERIC` | `(lhs_hi + SIGN_BASE, lhs_sign, 0)` |
| `<p>_rhs_get_sign` | `GENERIC` | `(rhs_hi + SIGN_BASE, rhs_sign, 0)` |

The range pairs make each operand a 32-bit integer and each `_hi` its true high halfword
(`memory.md` §7). That bounds each `U16GetSign` key `hi + SIGN_BASE + 1` into
`[SIGN_BASE + 1, SIGN_BASE + 2^16]` — `lookup.md` §4's precondition: never the `ZeroEntry`,
never an AND key — so each sign is its operand's bit 31. No comparison table exists
anywhere (must-be-exact 1). `word_bits` is a parameter only so that the reduced-width
exhaustive check evaluates this gate rather than a transcription of it.

## 4. Gates

In the frame's gate list 0, after its own 10 (four booleanity, two write-backs, four x0),
with `m_q` the query `q`'s mask, `a_q` its address, `v_q` its read value, `pc` and
`next_pc` the pc query's read and write values, `sel = rd_selected`, `seq =
decoded_next_pc`, `imm = decoded_imm`, and `b_k` the kind bits:

| gate | polynomial | what it holds |
| --- | --- | --- |
| `kind_<k>_boolean` ×12 | `b − b²` | each bit is 0 or 1 |
| `decoded_mask_bits` | `Σ_k 2^k·b_k − decoded_mask` | the packed mask is its bits |
| `rs1_mask_rule` | `m_rs1 − m_pc·(every kind but jal)` | `rs1` read on a live row whose form has it |
| `rs2_mask_rule` | `m_rs2 − m_pc·(b_slt + b_sltu + the six branches)` | |
| `rd_mask_rule` | `m_rd − m_pc·(b_slti + b_sltiu + b_slt + b_sltu + b_jalr + b_jal)` | a branch has no `rd` query |
| `rs1_addr_rule`, `rs2_addr_rule`, `rd_addr_rule` | `m_q·(a_q − decoded_q)` | a present query's address is the decoded one |
| `rs1_value_masked`, `rs2_value_masked` | `v_q − m_q·v_q` | an absent operand reads 0 |
| `cmp_rhs_rule` | `cmp_rhs − v_rs2 − (b_slti + b_sltiu)·imm` | the right operand |
| `cmp_order`, `cmp_lt_boolean` | §3.2 | the comparison of `v_rs1` against `cmp_rhs`, `sc = b_slti + b_slt + b_blt + b_bge` |
| `eq_inverse`, `eq_at_nonzero` | §3.1 over `v_rs1 − cmp_rhs`, `inv = eq_inv`, `z = eq`, `enable = m_pc` | `eq = [v_rs1 = cmp_rhs]` on a live row, 0 on every other |
| `taken_rule` | `taken − w_const − w_eq·eq − w_lt·lt` | the branch decision, §1's triples |
| `taken_boolean`, `jalr_drop_boolean`, `pc_wrap_boolean` | `x − x²` | |
| `next_pc_rule` | `next_pc + 2^32·pc_wrap − (1 − taken − b_jal − b_jalr)·seq − (taken + b_jal)·(pc + imm) − b_jalr·(v_rs1 + imm − jalr_drop)` | §4.3 |
| `rd_value_rule` | `sel − (b_jal + b_jalr)·seq − (b_slti + b_sltiu + b_slt + b_sltu)·lt` | the link, or the one `lt` |

Every gate is of degree at most 2 and 0 on the all-zero row; the constructor asserts both
through the assembly. **42 enforcing gates** in all.

### 4.1 Presence, addresses and `x0`

The mask rules fix every query's presence from the kind, exactly as
`execution-trace.md` §4 lists it — `jal` reads nothing and writes `rd`; `jalr`, `slti` and
`sltiu` read `rs1` and write `rd`; `slt` and `sltu` read both and write `rd`; a branch reads
both and writes nothing — and each is `m_pc` times the kind's use, so a padding row
(`m_pc = 0`) reaches no memory event whatever its free bits claim (S14's control C8). The
address rules fix every present address. `rd = x0` needs no mask bit: the table's `rd` is 0,
the address rule makes the write's address 0, and the frame's x0 rule writes 0 whatever
`sel` is. A branch has no `rd` query, so nothing it computes is written anywhere.

### 4.2 The branch

`taken` is a committed bit held to the branch linear form, which is zero on every row whose
kind is not a branch: every term is a branch bit, or a branch bit times `eq` or `lt`. It
needs its own column — `w·eq` is already degree 2, and `taken·(pc + imm)` another factor —
and its own booleanity gate, since a padding row's free bits could otherwise make it 2. On a
live row it is exactly the ISA's decision: BEQ `eq`, BNE `1 − eq`, BLT/BLTU `lt`, BGE/BGEU
`1 − lt`. One `lt` feeds the branches and the `slt` kinds (must-be-exact 6).

### 4.3 `next_pc`

```text
next_pc + 2^32·pc_wrap = (1 − taken − b_jal − b_jalr)·seq
                       + (taken + b_jal)·(pc + imm)
                       + b_jalr·(v_rs1 + imm − jalr_drop)
```

On a live row at most one of `taken`, `b_jal`, `b_jalr` is 1, so the right side is one sum.
**The wrap is ungated** and applies to whichever sum the selectors chose: a sign-extended
negative displacement makes `pc + imm` pass `2^32` on every backward branch and jump, and a
wrap gated inside a bracket would make those unprovable. **The default arm is ungated too**:
a row with every kind bit 0 advances to its claimed fall-through, and the canonical padding
row, all zero, advances to 0 because its claimed fall-through is 0 — the rule never demands
`next_pc = 0`. With `next_pc` in `[0, 2^32)` (§4.4) and `pc_wrap`, `jalr_drop` boolean:

- the default arm is the table's fall-through, below `2^24`, so `pc_wrap = 0`;
- `pc + imm` and `v_rs1 + imm` are below `2^33`, so one wrap bit holds every carry;
- on a `jalr` row, `v_rs1 + imm − drop − 2^32·wrap` is a unique even value below `2^32`:
  `(rs1 + imm) mod 2^32` with bit 0 cleared. A cheating `drop` makes `next_pc` odd, which
  §4.4 refuses; a sum of 0 with `drop = 1` makes `next_pc` negative, which it refuses too.

`jal` and `jalr` reach their targets through their own kind bits, never the branch weights.
The target of a branch or `jal` is even without a check: `pc` is a table row's pc and `imm` a
multiple of 2. The link is `seq` itself — a table value, not a sum — so it has no wrap bit;
it is still range-checked (§4.4).

### 4.4 Lookups

After the frame's 8 timestamp obligations, all under `m_pc`:

| lookup | channel | tuple |
| --- | --- | --- |
| `cmp_lhs_hi_range` … `cmp_gap_lo_range` | `RANGE16` | §3.2, over `v_rs1`, `cmp_rhs` and `cmp_gap` |
| `cmp_lhs_get_sign`, `cmp_rhs_get_sign` | `GENERIC` | §3.2 |
| `rd_hi_range`, `rd_lo_range` | `RANGE16` | `rd_hi`; `sel − 2^16·rd_hi` |
| `next_pc_hi_range`, `next_pc_lo_range` | `RANGE16` | `next_pc_hi`; `next_pc − 2^16·next_pc_hi` |
| `next_pc_even` | `RANGE16` | `(next_pc − 2^16·next_pc_hi)/2`, written `2^{-1}·next_pc − 2^15·next_pc_hi` |
| `decode_row` | `DECODER` | `pc, decoded_next_pc, decoded_rs1, decoded_rs2, decoded_rd, decoded_imm, decoded_mask` |

**8 timestamp, 11 `RANGE16`, 2 generic and 1 decoder obligation**; the constructor asserts
the counts. The channels, in output order, are `TIMESTAMP` over `V[range19]`, `RANGE16` over
`V[range16]`, `GENERIC` over `S[7..10]` and `DECODER` over `S[0..7]`.

**`next_pc_even`**: with the low halfword `lo` in `[0, 2^16)` by `next_pc_lo_range`, the
value `lo/2` is `lo`'s half when `lo` is even and `(lo + p)/2`, far above `2^16`, when it is
odd. So the obligation holds exactly when `next_pc` is even. It scales `next_pc` by `1/2`, so
the constructor runs `lookup::check_copowers` over `next_pc`: the direct pair above must be
there, or the halved bound would bound nothing.

**Depth.** Every channel has at most 15 obligations, so each fraction tree has at most 16
leaves — the timestamp and `RANGE16` trees exactly 16, the generic tree 4 and the decoder's
2, copied up to meet them — and four row-wise levels reduce the widest; the circuit is
1 + 4 + `trace_vars` transitions deep — 25 at `2^20`,
add/sub's depth — with layer 1 84 columns wide (8 product leaves, then 32, 32, 8 and 4
fraction columns). Must-be-exact 8's "four gate layers above the base plus one output
layer" is read as this: every comparison intermediate is a committed base column, every
semantic gate sits in gate list 0, no value lives at an inner layer, and four row-wise
levels reduce the leaves before the halving lists.

## 5. Why it is sound

On a **live row** (`m_pc = 1`) the decoder lookup binds the claimed row to the table row at
`pc`. `pc` is a 32-bit value — the entry pc, or an earlier row's range-checked, even
`next_pc` — so the row is a live row of the table, and its mask is one of the twelve single
bits: exactly one `b_k` is 1. **One-hotness is the table's domain**: an all-zero mask
satisfies booleanity and the recomposition, reaches no gate, and is refused by the decoder
channel alone. A pc that holds no instruction of this family has the table's `MINUS_ONE`
padding row, which no live tuple equals: **fetch binding** — a jump or branch to an address
holding no decoded instruction leaves a live row there that no table answers
(acceptance 6).

The presence and address rules make the frame's queries exactly the instruction's, and
every read value is a 32-bit integer (every value any row writes is range-checked, every
init and boundary value is a `u32`). So `cmp_rhs` is `rs2` or the immediate, never both
(one of them reads 0), and below `2^32`; the comparison gives the ISA's ordering (§3.2);
`eq` is equality; `taken` is the ISA's decision; `next_pc` is the ISA's target, reduced and
bit 0 cleared on `jalr` (§4.3); the written value is the link or `lt`, masked to 0 at `x0`.

The **SLTI defect** of the retired table — SLTI's sign read from `rs2`'s high halfword, 0
since `rs2` is absent, so `slti x5, x6, −1` compared `5 < 0xffffffff` unsigned — has no
analogue: the comparison's right operand is `cmp_rhs`, whose own halfword and sign are
looked up, and that reading satisfies every gate but is refused by `U16GetSign` (and its
halfword by the range pair).

On a **padding row** every mask is 0 by the mask rules, `eq` is 0, every lookup is switched
off, and the row reaches no memory event.

## 6. The generic table's binding

The packed table (`lookup.md` §9) is a program-independent constant of the ceremony.
`program::lookup_tables::generic_table(n)` fills its three columns over `2^n` rows, zero past
its `2^17 + 1` entries, and a Mercury commitment is a plain KZG commitment of the evaluation
table read as coefficients (`mercury.md`). So the table over `2^n` rows commits to the same
three points at every even `n ≥ 18`. `program::lookup_tables::generic_commitments(srs)` computes
them once, at `GENERIC_LOG_HEIGHT = 18`, key column first. It panics if `srs` holds fewer
than `2^18` powers. A real program's SRS never does: it holds at least as many powers as the
program's tallest family has rows, and every execution family's shard is at least `2^20`
rows.

- **Carried once, by every key.** `VerifyingKey::generic_table` is
  `constants::generic_table::WIDTH` points, the key, value and result columns' commitments,
  whether or not any family of the key reads the `GENERIC` channel. On the wire it is 192
  raw bytes with no count, between the `SrsVerifier` and the SRS digest (`shard-proof.md`
  §9). `ProverSetup::new` computes it.
- **Bound through the SRS digest.** `verifier_core::srs_digest(verifier, generic_table)`
  absorbs, in a fresh sponge, the 320-byte `SrsVerifier` as one `SRS_VERIFIER` (35) bytes
  message, then the three points as one `GENERIC_TABLE` (41) scalars message of twelve
  limbs, four limbs a point in S08's split; the digest is one raw squeeze
  (`shard-proof.md` §3). Tag 41 is used in that sponge and nowhere else. The global
  transcript is S16's G1–G11, unchanged: G2 absorbs the key's SRS digest before every
  challenge, and every shard is seeded from the global digest, so each shard's `g` and `β`
  follow the table as well.
- **Opened in the shard.** A shard's one batched opening lists its commitments in layout
  order: the statement's `M` for the shard, the proof's `W`, then `S`, which is identity's
  setup list for the family followed, where `FamilyCircuit::reads_generic_table` says the
  circuit reads `GENERIC`, by the key's three table commitments (`shard-proof.md` §5.1).
  `reduce_shard`'s step 11 and the prover's opening build the same list. For this family
  identity's list is the seven commitments of `S[0..7]` and the key's three are those of
  `S[7..10]`, so a shard opens 21 + 44 + 10 = 75 commitments, the table's last, and the
  table columns the circuit read are checked against the key's points. A family that reads
  no generic channel opens identity's list alone: add/sub's shard opens 36 + 31 + 7.
- **Loaded.** `VerifyingKey::check` (`shard-proof.md` §7.2) recomputes the SRS digest over
  the key's `SrsVerifier` and generic table, and refuses a key whose digest differs: "the
  SRS digest is not the digest of the key's SrsVerifier and generic table". Per family, it
  refuses an identity list whose length, plus 3 where the circuit reads `GENERIC`, is not
  the artifact's setup count: "family F: N setup commitments and G of the generic table for
  S setup columns". It also asserts that every `GENERIC` channel spec names the table as
  the three setup columns right after identity's: "family F: the circuit does not name the
  generic table as its last setup columns". No key whose circuit is the registry's can fail
  that assertion; it guards later registry entries, and it fires when a key is built, since
  `ProverSetup::new` runs `check`. `verifier::load_verifying_key` then decodes the three
  points through `G1Affine`'s validating decoder.
- **Trusted as the SRS digest is.** The loader recomputes the digest from the key's own
  points, so the digest makes a key consistent with itself, not honest. A key whose table
  commitments are another table's — its value and result commitments swapped, or an AND
  row answering `37 & 45 = 0` — does not load while it carries the honest digest. With its
  digest recomputed it loads, but that digest is not the trusted one, and every proof made
  under the honest key is refused under it as `Statement` ("the proof was made for another
  statement"), G2 having absorbed another digest. A verifier holding only the
  `SrsVerifier` cannot recompute a commitment, so it must hold the SRS digest from a
  trusted channel, as it holds identity — or the `SrsVerifier` and the table's commitments,
  which anyone holding the ceremony recomputes with `generic_commitments`. That is S16's
  presumption over the `SrsVerifier` (`shard-proof.md` §7.2), extended to three more
  points: one trusted value pins the points every pairing reads and the table every generic
  lookup reads. Identity is unchanged and binds neither. A proof whose table columns are not
  the ones its key commits is refused as `Opening`.
- **Pinned.** `crates/program/tests/vectors/generic_table.txt` holds the three points as
  64-byte hex after a `# ceremony` line. `cargo run -p kat-gen -- program` writes it from
  `assets/ptau/ppot_0080_24.ptau`, after checking that the table commits to the same points
  at `2^18`, `2^20` and `2^22`. In CI, `crates/program/tests/lookup_tables.rs`'
  `the_generic_table_commitments_are_pinned_over_the_ceremony` checks that the pin names
  `identity.txt`'s ceremony and holds three points. The `#[ignore]`d
  `the_generic_table_commitments_are_the_ceremonys_at_every_height` recomputes them over the
  ceremony at each of those heights:
  `cargo test --release -p program --test lookup_tables -- --ignored`.
- **What it amends.** S16's frozen shard-proof spec, in two places: §3, whose recipe gains
  the second message, and §9, whose key layout gains the 192 bytes. Every S16 key's bytes
  and SRS digest change with them.

**The tests.** `crates/verifier-core/tests/wire.rs`: `every_value_round_trips_byte_for_byte`
over both keys; `the_layouts_are_the_specs`, which reads a key with this family back field
by field through its first circuit's artifact; `the_readers_refuse_rather_than_panic`,
which flips every one of the table's 1,536 bits in both keys and gets the digest refusal
each time; `a_key_that_breaks_a_load_rule_is_refused`, where a table byte flipped or two
points swapped is the digest refusal and an identity list of ten or six commitments for this
family is the count refusal; and `the_srs_digest_is_the_documented_recipe`.
`crates/verifier-core/tests/reduce.rs`:
`the_global_transcript_is_the_frozen_order`, G1–G11 event for event, and
`the_generic_table_is_bound_through_the_srs_digest`, which finds no `GENERIC_TABLE` message
in a statement with this family and moves the statement's digest with each point and their
order. `crates/verifier/src/lib.rs`: `every_generic_table_commitment_is_decoded_at_load`.
`crates/prover/tests/key.rs`, in CI with no proof: the key `ProverSetup::new` builds carries
the table over its SRS under a digest over both, and each commitment is the column's
coefficients evaluated at the toy SRS's `tau`, the same over `2^18` powers as over `2^20`.
`crates/prover/tests/control.rs`, deferred: `a1_the_guest_proves_and_every_shard_verifies`
and `a_key_with_another_generic_table_is_another_statement`.

## 7. What this family does not do, and the controls

1. **No link wrap bit.** The prompt's "link reduced mod `2^32` with a wrap bit" guards a
   `jal` at `0xfffffffc`; here the link is the table's fall-through, which is below `2^24`
   (a table of at most `2^22` rows), so there is no sum to wrap. The link is still
   range-checked.
2. **No comparison lookup table**, and no decoder column beyond S11's.
3. **The halting sentinel.** A `jalr` row with `rs1 + imm ≡ 1` and `jalr_drop = 0` satisfies
   every gate and writes `next_pc = HALT_PC`; the one thing that refuses it is
   `next_pc_even` (`crates/checker/tests/jump_branch_slt.rs`). Without it, any program with
   a `jalr` that can reach address 1 — a null function pointer plus one — could be proven to
   exit cleanly with whatever `a0` holds at that point.
4. **The controls**, each refused in its class: a corrupted `lt` on a not-taken branch,
   `Constraint`; the same forgery carried through the gap, `taken` and `next_pc`, whose gap
   leaves the range, `Lookup { RANGE16 }`; a `jalr`'s `next_pc` moved with the `rs1` it is
   formed from, every gate and bound holding, `MemoryArgument`; a jump into the middle of a
   32-bit instruction, `Lookup { DECODER }`, the honest prover's recount refusing it by name;
   a generic count, `Lookup { GENERIC }`; a poisoned table cell no row looks up, `Opening`
   (`crates/checker/tests/tamper.rs`).

## 8. The fixture

`guests/control`, hand-written assembly over the two families S17 proves and the exit
ecall, with no SDK. It checks every result itself and exits with the number of checks, 16.
Its QEMU differential is `crates/emulator/tests/differential.rs`'; the rows the acceptance
names are held to its trace by `crates/checker/tests/jump_branch_slt.rs`'
`the_guest_runs_the_acceptance_matrix`; its statement is proved and verified by
`crates/prover/tests/control.rs`: one `INIT_TEARDOWN` shard at `2^16`, one
`ADD_SUB_LUI_AUIPC` and one `JUMP_BRANCH_SLT` shard at `2^20`.
