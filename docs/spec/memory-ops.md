# The memory-op families: `MEM_WORD`, `MEM_SUBWORD` and `ATOMICS`

Frozen as of S19. Changing anything here is a protocol-version change.

This page is S19's three circuit families as the repository owner decided them: `lw` and
`sw`; the six sub-word loads and stores; and `lr.w`, `sc.w` and the nine AMOs. They are the
first families whose rows touch RAM, so the addressing of §2 is shared by all three and is
the part of this page the rest depends on. It cites `docs/spec/memory.md` for the frame,
`docs/spec/execution-trace.md` for what each instruction's cycle records,
`docs/spec/lookup.md` for the channels and `docs/spec/shard-proof.md` for the statement,
the key and the transcripts, and restates none of them.
`docs/spec/constraint-manifest.md` §7–§9 is the column-by-column account.

| crate | what |
| --- | --- |
| `crates/constants` | `DEFAULT_HEIGHTS[ATOMICS]`, raised from `2^16` to `2^20` (§7.1) |
| `crates/constraints` | `mem_word`, `mem_subword` and `atomics`: the three circuits; `mem_subword::splice_gates`, the width seam; the registry's three arms and its minimum-height guard |
| `crates/prover` | the three fills |
| `guests/mem` | the three families' fixture program |

The owner's decisions this page records. Each was put before any code.

1. **`DEFAULT_HEIGHTS[ATOMICS]` is `2^20`**, the timestamp channel's floor, and every
   fixture is proved there. The stage prompt's "build every fixture at trace height
   `2^16`" cannot be followed by any family that runs cycles: a range channel needs
   `BITS ≤ trace_vars` (`lookup.md` §3), `BITS[TIMESTAMP]` is 19, and a Mercury opening
   needs an even variable count. S16 answer 7 deferred the raise to this stage
   (§7.1).
2. **There is no `MemoryOffsetGetBits` table.** The splice power and its copower are two
   degree-2 gates over the address's own low two bits (§4.1), not a fourth sub-table of
   the packed generic table. §4.2 gives the argument and the price avoided.
3. **S11's one-hot `family_extra_mask` is kept**, and the stage prompt's STORE, BYTE and
   SIGNEXTEND modifier bits are linear forms over it (§1). Rebuilding the table would move
   program identity for every program that loads or stores.
4. **One consolidated fixture guest**, `guests/mem`, covering all nineteen instructions,
   proved as one five-execution-family statement (§8).

---

## 1. What the circuits read from the decoded table

S11's table for `MEM_WORD` and `MEM_SUBWORD` is `pc next_pc rs1 rs2 rd imm extra_mask`, one
row per halfword, `MINUS_ONE`-padded (`crates/program/CLAUDE.md`). `ATOMICS`' is **six
columns**, `pc next_pc rs1 rs2 rd extra_mask`: every A instruction is R-type, so the tuple
carries no `imm` and an atomic's address is `rs1` alone. `imm` is the load's or store's
sign-extended offset as a two's-complement `u32`. `next_pc` is the fall-through; no kind
here computes a pc.

`extra_mask` is one-hot over `constants::extra_mask`:

| family | bit | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `MEM_WORD` | kind | `lw` | `sw` | | | | | | | | | |
| `MEM_SUBWORD` | kind | `lb` | `lh` | `lbu` | `lhu` | `sb` | `sh` | | | | | |
| `ATOMICS` | kind | `amoadd` | `amoswap` | `lr` | `sc` | `amoxor` | `amoor` | `amoand` | `amomin` | `amomax` | `amominu` | `amomaxu` |

**The legal masks** are those two, six and eleven one-bit values, and the table's domain is
what enforces them (`lookup.md` §10). The atomics order is ascending `funct5`, which is
**not** the stage prompt's listing order: the prompt writes "AMOXOR.W, AMOAND.W, AMOOR.W"
where the constants have xor, or, and. Every arm of `atomics::ram_value_rule` indexes
`KINDS` through its `extra_mask` constant and never by position, and
`the_kind_bits_are_the_extra_mask_constants` in `crates/checker/tests/atomics.rs` holds each
of the eleven `Instr` variants to the bit its arm uses. A transposition there would be
silent: the table's `extra_mask` is built from the same constants, so both sides would agree
on the number and the machine proved would be one where `amoor.w` computes AND.

**The prompt's modifier bits are linear forms**, as S17's `sc` and branch weights and S18's
op selectors are:

| signal | form | on |
| --- | --- | --- |
| `LOADK` | `b_lb + b_lh + b_lbu + b_lhu` | `word_rule`, `rd_value_rule`, the `load` and `rd` mask rules |
| `STORE` | `b_sb + b_sh` | `word_rule`, the `rs2` and `ram` mask rules |
| `BYTE` | `b_lb + b_lbu + b_sb` | `wph_rule`, `sub_scaled_rule`, `src_sub_rule`, `src_sub_scaled_rule`, `sign_in_rule`, `rd_value_rule` |
| `HALF` | `b_lh + b_lhu + b_sh` | `half_aligned` |
| `SIGNEXT` | `b_lb + b_lh` | `se_rule` |
| `f_bitwise` | `b_amoand + b_amoor + b_amoxor` | a **column**, because it is a lookup selector |

Only a flag a lookup selector needs becomes a column, and then it carries the booleanity
gate `validate` refuses a selector without. Everything else is a sum of committed bits, so
a product with one is already degree 2.

## 2. Addressing, shared by all three

The effective address of a load or a store is `rs1 + imm` reduced mod `2^32`; an atomic's
is `rs1`. Both memory families decompose it:

```text
addr_split (MEM_WORD)     rs1 + imm − 2^32·wrap − 4·word_index                 = 0
addr_split (MEM_SUBWORD)  rs1 + imm − 2^32·wrap − 4·word_index − 2·bit1 − bit0 = 0
addr_word  (ATOMICS)      rs1 − 4·word_index                                   = 0
```

each degree 1, with `wrap`, `bit0` and `bit1` boolean. **That equation is an alignment
check over ℤ and nothing at all over `Fr`**: 4 is a unit there, so `word_index := addr·4⁻¹`
satisfies it for any address whatever. What makes the split genuinely base-4 is three
`RANGE16` obligations under `m_pc`:

```text
word_index_hi_range     word_index_hi
word_index_lo_range     word_index − 2^16·word_index_hi
word_index_hi_scaled    4·word_index_hi
```

The third gives `word_index_hi < 2^14`, so `word_index ≤ 2^30 − 1` and
`4·word_index + 2·bit1 + bit0 ≤ 2^32 − 1`. **The bound is exactly tight at both ends**: the
top word of the address space, `0xfffffffc`, needs `word_index = 2^30 − 1`,
`word_index_hi = 2^14 − 1` and `4·word_index_hi = 65532 < 2^16`. Scaling by 2 instead of 4
would make the top quarter of the address space unprovable; dropping the obligation would
let `4·word_index` reach `2^33`, which only the statement-level multiset would then refuse.
`lookup::check_copowers` takes `(word_index_hi, m_pc)` in all three families, so a later
edit that narrows or drops the direct obligation fails the build rather than the argument.

With `word_index < 2^30` both sides of `addr_split` are integers below `2^34`, far under the
modulus, so the field equality is an integer equality. That pins `wrap` in both directions —
at `rs1 + imm < 2^32` a `wrap` of 1 makes the left side negative, and at `rs1 + imm ≥ 2^32`
a `wrap` of 0 leaves it above the right side's ceiling — and it makes `bit1`, `bit0` the
true low two bits. **A misaligned `lw` or `sw` has no representation at all**: `MEM_WORD`
carries no offset bits, so its split is `addr = 4·word_index` and an address 1, 2 or 3 mod 4
needs a `word_index` that is not an integer, which its own range pair refuses. A halfword at
an odd address is refused by one more gate:

```text
half_aligned    (b_lh + b_lhu + b_sh)·bit0 = 0
```

degree 2. `half_aligned` is not only an alignment rule: §4.2's bound on what a store writes
needs `w·p` to divide `2^32`, and at `BYTE = 0` with `bit0 = 1` it would be `2^40`. It is
the gate that removes that case.

**Unified word addressing.** Every RAM query's address is the word's byte address and never
a byte address:

```text
load_addr_rule / ram_addr_rule    m_q·(a_q − 4·word_index) = 0
```

so a sub-word access, a word access and an atomic all name one cell. A byte-address form
there would be a broken memory model: `lb` at a word's four offsets would name four
different cells, and a byte `sb` wrote would be invisible to a later `lw`. The byte position
lives only in the splice.

**What no gate here does** is confine the address to a live RAM window. That is the multiset
argument's (`memory.md` §9): an address no committed window initializes has no init write,
its reads and writes would have to match as multisets while every read's timestamp is
strictly below its own write's, and the two are incompatible. So an out-of-window access
produces a proof whose per-shard checks all pass and which fails at `verify_shard` step 10
as `MemoryArgument`. A *misaligned* access is the opposite: a local refusal, and one the
emulator makes fatal before any event is staged, so no trace exists to prove.

## 3. `MEM_WORD`

### 3.1 Columns

`constraints::mem_word::artifact(trace_vars)` and `::channels()`, through S15's
`frame_with_channels_artifact`. The frame is `memory.md` §2.1's over the family's six
queries — `pc rs1 rs2 load ram rd` at slots 0 to 5 — so `M[0..31]` and `W[0..9]` (the six
gap chunks, `rd_inv`, `rd_is_zero`, `rd_selected`) are the frame's. The circuit adds:

| column | name | what |
| --- | --- | --- |
| `W[9]`–`W[14]` | `decoded_next_pc` … `decoded_mask` | the claimed decoded row, `lookup_tuple` after `pc` |
| `W[15]`, `W[16]` | `kind_lw`, `kind_sw` | the mask's two bits |
| `W[17]` | `wrap` | the wrap of `rs1 + imm` |
| `W[18]`, `W[19]` | `word_index`, `word_index_hi` | §2 |
| `W[20]` | `rd_hi` | the written `rd` value's high halfword |
| `W[21]`–`W[23]` | `mult_timestamp`, `mult_range16`, `mult_decoder` | one multiplicity per channel, last |
| `S[0]`–`S[6]` | `table_pc` … `table_extra_mask` | the decoded table, bound by identity |
| `V[range19]`, `V[range16]` | | the two range tables |

**31 `M`, 24 `W`, 7 `S`: 62 committed columns.** There is **no generic channel**:
`FamilyCircuit::reads_generic_table` is false, the setup list is identity's alone, and a
shard opens 62 commitments. `ADD_SUB_LUI_AUIPC` is the precedent for that shape.

### 3.2 Gates

Twenty beside the frame's thirteen (six mask booleanity, three write-backs on `rs1`, `rs2`
and `load`, four x0), thirty-three in all:

| gate | polynomial | what it holds |
| --- | --- | --- |
| `kind_lw_boolean`, `kind_sw_boolean` | `b − b²` | |
| `decoded_mask_bits` | `b_lw + 2·b_sw − decoded_mask` | the packed mask is its bits |
| `wrap_boolean` | `wrap − wrap²` | |
| `rs1_mask_rule` | `m_rs1 − m_pc·(b_lw + b_sw)` | every kind reads `rs1` |
| `rs2_mask_rule`, `ram_mask_rule` | `m_q − m_pc·b_sw` | a store's alone |
| `load_mask_rule`, `rd_mask_rule` | `m_q − m_pc·b_lw` | a load's alone |
| `rs1_addr_rule`, `rs2_addr_rule`, `rd_addr_rule` | `m_q·(a_q − decoded_q)` | |
| `load_addr_rule`, `ram_addr_rule` | `m_q·(a_q − 4·word_index)` | §2 |
| `rs1_value_masked`, `rs2_value_masked` | `v_q − m_q·v_q` | an absent operand reads 0 |
| `addr_split` | §2 | |
| `rd_value_rule` | `rd_selected − b_lw·load_read_value` | a load writes the word it read |
| `store_value_rule` | `ram_write_value − m_ram·v_rs2` | a store writes `rs2` |
| `next_pc_rule` | `next_pc − decoded_next_pc` | degree 1; no kind computes a pc |

`next_pc_rule` carries no wrap bit and no bound of its own, and no evenness check: S18's
reading, which `crates/constraints/src/shift_bitwise.rs` states in full — the decoder lookup
binds the table's fall-through exactly as it binds `rs1`, `rs2`, `rd` and `imm`, none of
which is range-checked either, and S17's rule that a family computing a pc keeps it even
does not reach one that copies one.

### 3.3 Lookups

After the frame's twelve timestamp obligations, all under `m_pc`: §2's three on
`word_index`, and `rd_hi_range` / `rd_lo_range`, the 16+16 pair on `rd_selected`. **Five
`RANGE16`**, one decoder, no generic; `artifact` asserts the counts.

### 3.4 Why it is sound

On a live row the decoder lookup binds the claimed row to the table row at `pc`, so exactly
one kind bit is 1 (`lookup.md` §10). The mask rules make the queries exactly the
instruction's — a load reads `rs1` and the word and writes `rd`; a store reads `rs1` and
`rs2` and rewrites the word — so a padding row reaches no memory event whatever its free
bits claim (S14's control C8). §2's split makes the address the ISA's and the access
aligned. `rd_value_rule` and `store_value_rule` are each a copy, which is the whole
semantics of the family.

Two values the family writes are copies, and §5.1 is why neither needs more than it has:
`ram_write_value` is a register value and carries no bound here, while `rd_selected` carries
its own 16+16 pair, which is what keeps every register value in this VM locally 32-bit.

**What no gate reads** is `ram_read_value` — the old word a store overwrites. It is pinned
by the memory argument alone, which makes it acceptance 8's tamper target for this family
(§9).

## 4. `MEM_SUBWORD`

### 4.1 The splice, and where its constants come from

Memory is word-addressed, so the position of a sub-word inside its word lives entirely in

```text
word = high·(w·p) + sub·p + low
```

with `p = 2^(8·offset)` the splice power and `w` the access width — 256 for a byte, 65536
for a halfword. The stage prompt puts `p`, `w` and their copowers in a seven-row
`MemoryOffsetGetBits` setup table keyed `1 + bit0 + 2·bit1 + 4·BYTE`. **S19 does not build
it.** `p` is exactly a degree-2 polynomial in the two offset bits, and so is its copower:

```text
p_rule       p − m_pc − 255·bit0 − 65535·bit1 − K·bit0·bit1 = 0,  K = 2^24 − 2^16 − 2^8 + 1
pcopow_rule  p·pcopow − 2^31·m_pc                            = 0
wph_rule     wph − 32768·p + 32640·p·BYTE                    = 0
p_ram_rule   p_ram − m_ram·p                                 = 0
```

`p_rule` takes the four offsets to `1`, `256`, `2^16` and `2^24`, and `m_pc` stands where a
constant would so that the gate is zero on the all-zero padding row. `pcopow` is the halved
copower `2^31/p`, determined by `p_rule`'s value of `p` being a unit on a live row;
`low_scaled_rule` carries the compensating factor 2, the `ShiftPowers` pattern of
`shift-bitwise.md` §3.1, and it is what keeps the column inside `u32` at `p = 1`, where the
copower itself is `2^32`. `wph` is `w·p` halved for the same reason. `p_ram` is `p` on a
store row and 0 elsewhere, and exists to keep `store_rule` at degree 2.

On the all-zero padding row every one of these reads `0 = 0`, so `pcopow` is free there —
which makes it a cell acceptance 8's negative control can move (§9).

### 4.2 What dropping the table buys, and what it costs

Must-be-exact 8's stated worry is "the key must pin the position: a freely chosen position
is a freely chosen sub-word". The replacement chain pins it more directly and in fewer
steps: `bit0` and `bit1` are boolean and `addr_split` ties them to the true low two bits of
`rs1 + imm` over ℤ (§2); `p_rule` makes `p` a *function* of them; `half_aligned` forces
`bit0 = 0` at halfword width; and `BYTE` is a linear form over one-hot kind bits the decoder
lookup binds. A table keyed by `1 + bit0 + 2·bit1 + 4·BYTE` would still have needed
`addr_split` to pin `bit0` and `bit1` to the address — the table never carried the pinning —
so what it carried was the `p` and copower *values*, which two gates now produce with no
lookup, no multiplicity, and no key to police.

It also avoids a real hazard and a real price. The hazard is `lookup.md` §4's precondition:
a fourth sub-table means a fourth key that must be bounded into its own range, and an
unbounded key does not miss the packed table — it lands on another sub-table's row. That is
the hole S18's review found (§6.5). The price is S18's standing one: appending a sub-table
moves the packed table's three commitments, hence every verifying key's SRS digest and
bytes, and re-pins `crates/program/tests/vectors/generic_table.txt` over the ceremony. S19
pays none of it, and **the generic table did not move this stage**.

What is recorded as a deviation, in `docs/handoff/S19-mem.md`: the table does not exist, so
the Deliver bullet naming it is not delivered, and the Handoff item "freeze the
MemoryOffsetGetBits schema and its generation path" is replaced by freezing `p_rule`,
`pcopow_rule` and `wph_rule` with their constants.

### 4.3 Columns

The frame is the same six queries as `MEM_WORD`'s, so `M[0..31]` and `W[0..9]` are the
frame's. The circuit adds `W[9..15]` the decoded row, `W[15..21]` the six kind bits,
`W[21..26]` `wrap word_index word_index_hi bit0 bit1`, `W[26..30]` `p pcopow wph p_ram`,
`W[30]` `word`, `W[31..42]` the splice's three parts with the columns their bounds scale,
`W[42..47]` the store source's split, `W[47..50]` `sign_in sign se`, `W[50]` `rd_hi`, and
`W[51..55]` the four multiplicities. `S[0..7]` is the decoded table and `S[7..10]` the
packed generic table. **31 `M`, 55 `W`, 10 `S`: 96 committed columns.**

### 4.4 The splice's gates, and the width seam

`mem_subword::splice_gates(byte_bits)` builds the **twelve** gates whose literals depend on
the width, or which read a column one of them defines, over the family's own columns;
`family_spec` calls it at `BYTE_BITS = 8`. The width is a parameter for one reason: so the
exhaustive reduced-width check of acceptance 2 evaluates *these* gates and not a
transcription of them, the role `gadgets::comparison_equation(c, word_bits)` plays at S17.
It panics outside `1..=8`. The block below shows seven of the twelve; `word_rule` beside
them is `family_spec`'s, not one of them, and §4.6 counts it separately. The other five are
§4.1's `p_rule`, `pcopow_rule` and `wph_rule` and §4.5's `sign_in_rule` and
`rd_value_rule`.

```text
word_rule            word − LOADK·load_read_value − STORE·ram_read_value = 0
splice_rule          word − high_scaled − sub·p − low                    = 0
high_scaled_rule     high_scaled − 2·high·wph                            = 0
sub_scaled_rule      sub_scaled − 2^16·sub − 16711680·sub·BYTE           = 0
low_scaled_rule      low_scaled − 2·low·pcopow                           = 0
src_sub_rule         rs2 − src_sub − 65536·src_high + 65280·src_high·BYTE = 0
src_sub_scaled_rule  src_sub_scaled − 2^16·src_sub − 16711680·src_sub·BYTE = 0
store_rule           ram_write_value − m_ram·word − src_sub·p_ram + sub·p_ram = 0
```

`word` is the word the row operates on — the one a load read, or the one a store is
rewriting — so one decomposition serves both directions, and `store_rule` is exactly
`new = old + (src_sub − old_sub)·p` on a store row and `ram_write_value = 0` on every other.

**Every part carries both bounds.** `high`, `low`, `src_high` and each of the four `_scaled`
columns carry a 16+16 pair; `sub` and `src_sub` carry a single halfword obligation, which is
their exact direct bound since each is below the access width and so below `2^16`. The
scaled bounds are what make the row-varying widths fixed: `sub_scaled < 2^32` is `sub < w`,
`low_scaled < 2^32` is `low < p`. `lookup::check_copowers` takes `(high, m_pc)`,
`(sub, m_pc)`, `(low, m_pc)` and `(src_sub, m_pc)` beside `word_index_hi`, and refuses the
circuit if any of them loses its direct bound or has it moved under a narrower selector.

**Uniqueness.** `high < 2^32` directly, so `high·w·p < 2^64` and the field identity is the
integer one; `low < p` and `sub < w` then make the decomposition the unique base-`(p, w)`
one, which is `low = word mod p`, `sub = (word div p) mod w`, `high = word div (w·p)`. A
scaled bound alone would not do it: `p'` is a unit in `Fr`, so a "low" of `s·p'^{-1}` passes
the scaled check for a small `s` while being no small integer at all — S18's residue hole,
and what `check_copowers` exists to refuse.

**`src_high` needs no scaled bound.** `rs2 = src_sub + w·src_high` with `src_sub < w ≤ 2^16`
and `w·src_high < 2^48` is an integer equation, so `rs2 < 2^32` forces
`src_high < 2^32/w` with no obligation of its own.

### 4.5 The load's result

```text
sign_in_rule   sign_in − sub − 255·sub·BYTE                       = 0
se_rule        se − SIGNEXT·sign                                  = 0
rd_value_rule  rd_selected − LOADK·sub − (2^32 − 2^16)·se − 65280·se·BYTE = 0
```

`sign_in` is `256·sub` on a byte row and `sub` on a halfword row, so bit 15 of `sign_in` is
the sub-word's sign bit at either width and **one `U16GetSign` lookup serves both**. Its
tuple is `(sign_in + SIGN_BASE, sign, 0)` — the `+ 1` that keeps a real entry off the
`ZeroEntry` is the channel's, added by `lookup::Gating::ZeroEntry`, and writing it at the
caller would shift every key one row. One `RANGE16` obligation, `sign_in`, bounds the key:
`sign_in < 2^16` puts the gated key in `[SIGN_BASE + 1, SIGN_BASE + 2^16]`, which is
`U16GetSign`'s range exactly, never the `ZeroEntry` and never an AND or `ShiftPowers` key.
The sub-table's range is exactly a halfword wide, so that single obligation is the exact
bound and needs no scaled partner — this is the one place in the VM where a bare `RANGE16`
obligation, not a pair, is the right answer.

`rd = sub + (2^32 − w)·se` is the 32-bit sign extension: at `se = 1` it is
`sub − w + 2^32`, the two's-complement word, so `lb` of `0x88` gives `0xffffff88` and `lh`
of `0x8000` gives `0xffff8000`, matching `v as u8 as i8 as u32` and `v as u16 as i16 as u32`
in the emulator. `se` is boolean by construction — a one-hot sum times a table bit — and
carries no booleanity gate, as S17's `eq` does not; S18's `se_boolean` was written to
satisfy S18's own must-be-exact 5, which S19 has no counterpart of.

The `U16GetSign` lookup and `sign_in`'s obligation fire under `m_pc`, so they run on store
rows too, where `SIGNEXT` is 0 and they buy nothing. That is S17's shape (the jump family
compares on every live row) and is deliberate: a narrower selector would have to be a
committed column with a booleanity gate of its own, and the key bound would have to move
with it.

### 4.6 Gates and lookups, in counts

**Fifty-three enforcing gates**: the frame's thirteen and this family's forty — six kind
booleanity, `decoded_mask_bits`, `wrap_boolean`, `bit0_boolean`, `bit1_boolean`, five mask
rules, five address rules, two `value_masked`, `addr_split`, `half_aligned`, `word_rule`,
`p_ram_rule`, `se_rule`, the **twelve** of `splice_gates`, and `next_pc_rule`. **Twelve
timestamp, 22 `RANGE16`, 1 generic and 1 decoder obligations**; `artifact` asserts every
count and the gate total, so a dropped obligation or a stray gate panics at construction.

### 4.7 Why it is sound

§2 gives the address and the offset bits; §4.1 gives `p` and `w` from them; §4.4 gives the
unique decomposition of the word; §4.5 gives the extension. A load writes `sub`
sign-extended and a store writes the word with `src_sub` spliced in, and `src_sub` is `rs2`
truncated to the access width — without `src_sub_rule` and its bounds, `sb` could store a
byte unrelated to `rs2`.

**What a store writes is below `2^32` without any induction.** `high_scaled < 2^32` and
`high_scaled = high·w·p` is a multiple of `w·p`, which divides `2^32` (§2's `half_aligned`
is what keeps it there), so `high_scaled ≤ 2^32 − w·p`; `src_sub·p + low ≤ w·p − 1`; the
sum is at most `2^32 − 1`. That is why `high_scaled` keeps its own range pair even though
`word < 2^32` would imply it: the implication runs the other way, and the local argument is
the one §5.1 wants.

## 5. The write-side induction

### 5.1 The rule, and where it grounds

The prompt's rule is "values READ from memory are exempt from range checks (write-side
induction); every produced part is checked", and S19 follows it with one addition. The
statement it needs is: **every value written to a register or to a RAM word in any family is
below `2^32`.** It is two one-directional inductions over the timestamp order, not a mutual
one:

- **Registers.** Every `rd` write of every family is either range-checked by that family or
  forced to 0 by the frame's x0 rule. Two copy a RAM word rather than compute one, and each
  is bounded for a different reason. `MEM_WORD`'s `rd_selected` carries a 16+16 pair of its
  own, which is why it has one at all. `ATOMICS`' is `(every kind but sc)·old`, and what
  bounds it is the **comparison gadget's `lhs` range pair**, which is under `m_pc` and so
  holds on every live row — one of the two things §6.4's assertion on the gadget's selector
  carries, and the reason that assertion is not only about the min/max kinds. Register
  values are therefore bounded without reference to RAM.
- **RAM.** Every RAM word is an init value (`program::image_init_column`'s `u32`, or
  `ZERO_WINDOWS`' literal 0) or a family's `ram_write_value`. `MEM_WORD` writes a register
  value, bounded above. `MEM_SUBWORD` writes a value §4.7 bounds locally. `ATOMICS` writes
  one of eight arms, each bounded by §6.5's chain. No step reads back into the register
  induction.

**Owed by the I/O-binding stage**: when ecall transfer cycles become provable, that family's
`ram_write_value` must carry a 32-bit bound of its own. Today no `ADD_SUB_LUI_AUIPC` row can
reach RAM at all — its `ram_mask_rule` is the ungated `ram_mask = 0`
(`docs/spec/shard-proof.md` §8) — so the induction rests on a circuit gate and not on
`prover::fill::add_sub` refusing a transfer cycle by name, which is a completeness check.

### 5.2 What the induction is for

`addr_split`'s integer argument (§2) needs `rs1 < 2^32`, and `ATOMICS`' `addr_word` derives
it rather than assuming it (`4·word_index` with `word_index < 2^30`). The rest of the VM
needs it wherever a wrap bit holds a carry: S16's `a + b − 2^32·wrap` is only a reduction if
`a` and `b` are words.

## 6. `ATOMICS`

### 6.1 The frame

`memory.md` §2.1's over five queries — `pc rs1 rs2 ram rd` at slots 0 to 4 — so `M[0..26]`
and `W[0..8]`. **The RAM query and the `rd` query share Δ = 3** at distinct address spaces,
which is what lets one row be one read-modify-write; the A extension is the one family with
two queries in one Δ slot, so one of its rows makes five (`execution-trace.md` §4). `lr.w`'s form has no `rs2`, so `m_rs2` is
`m_pc` times the other ten bits — keyed on `b_lr`, never on `is_zero(decoded_rs2)`, which
`amoadd.w rd, x0, (rs1)` would also satisfy.

`frame_queries(ATOMICS)` has no `load` query: the whole extension keeps its RAM query at
slot 3, `lr.w` included, though `lr.w` is a plain word load and a load's word is at slot 2
for every other family. That is `execution-trace.md` §7, frozen at S12.

### 6.2 Columns

Beside the frame: `W[8..13]` the decoded row — **five, the tuple having no `imm`** —
`W[13..24]` the eleven kind bits, `W[24..26]` `word_index` and its halfword, `W[26..29]`
`sum sum_hi add_wrap`, `W[29]` `f_bitwise`, `W[30..42]` both operands' bytes and their AND,
`W[42..49]` the comparison, `W[49]` `lo`, `W[50..54]` the four multiplicities. `S[0..6]` is
the decoded table and `S[6..9]` the packed generic table — the `MUL_DIV` shape, not the
seven-column one. **26 `M`, 54 `W`, 9 `S`: 89 committed columns.**

### 6.3 The eleven arms

```text
ram_write_value = b_lr·old + (b_sc + b_swap)·rs2 + b_add·sum
                + b_and·A + b_or·(old + rs2 − A) + b_xor·(old + rs2 − 2A)
                + (b_min + b_minu)·lo + (b_max + b_maxu)·(old + rs2 − lo)

rd_selected     = (every kind but sc)·old
```

with `old` the RAM query's read value and `A = Σ_j 2^(8j)·byte_and_j` **inlined as a linear
form**, never a committed column, as S18's AND accumulator is. `rd` takes the **old** word
on every kind but `sc.w`, which writes 0.

- **add**: `add_rule`, `old + rs2 − sum − 2^32·add_wrap = 0`, ungated, with `sum`'s 16+16
  pair under `m_pc`. Both operands are below `2^32` by §6.5, so one boolean wrap holds the
  carry and `(sum, add_wrap)` is unique. Keeping the gate ungated and the pair under `m_pc`
  is deliberate: gating either to `b_amoadd` would leave `sum` unbounded on the other ten
  kinds, and `ram_write_value` pinned by nothing on an add row.
- **and, or, xor**: four `GENERIC` lookups of the byte AND table under `f_bitwise`, each
  key bounded by S18's pair — `byte_a_j` and `2^8·byte_a_j`, both under `f_bitwise`. `or`
  and `xor` are derived from the one accumulator by linearity, exact over the integers
  because no carry crosses a byte. `f_bitwise` is the **three** bitwise kinds: gating the
  lookups by `b_amoand` alone would leave `amoor` and `amoxor` reading free `byte_and`
  columns and writing an arbitrary field element into RAM.
- **min, max, minu, maxu**: `gadgets::comparison` over `lhs = old`, `rhs = rs2`, selector
  `m_pc`, `signed = [b_amomin, b_amomax]`. `lo_rule`, `lo − rs2 − lt·old + lt·rs2 = 0`,
  makes `lo` the smaller under whichever ordering `lt` settled; the larger is the linear
  form `old + rs2 − lo`, exact in both orderings because `{lo, old + rs2 − lo}` is
  `{old, rs2}` as a set, so `amomax` needs no second column.
- **lr, sc, swap**: `old` and `rs2` copied.

### 6.4 The comparison's four parameters are asserted

`gadgets::comparison` takes `selector`, `signed`, `lhs` and `rhs` as plain addresses, and
each wrong choice is a silent, total break of four of the eleven kinds with nothing else in
the circuit to catch it: `signed` widened to the four min/max kinds makes `amominu` order
signed; `lhs` and `rhs` swapped turns every `amomin` into a max; a narrowed selector drops
both operands' 32-bit bounds on the other seven kinds. `atomics::assemble` therefore asserts
all four at construction, and `crates/checker/tests/atomics.rs` reads them back off the
artifact. This is a must-be-exact of this page: **the parameterisation is not derivable
from anything else.**

### 6.5 Why what it writes is a word

There is no direct range check on `ram_write_value`. Every arm is bounded, and the chain is
worth stating in one place because it is a chain: `old` and `rs2` are below `2^32` by the
comparison gadget's own `lhs` and `rhs` range pairs, which are under `m_pc` and so hold on
every live row; `sum` by its own pair; `A`, `or` and `xor` by the AND table's domain, which
bounds `byte_b_j` and `byte_and_j` once `byte_a_j` is bounded into the AND sub-table's key
range; `lo` and `old + rs2 − lo` by being `old` and `rs2` in some order. Those are the only
eight arms.

The one attack that reaches this is S18's, restated: with `byte_a0` unbounded, the gated key
`65824` is `ShiftPowers`' `s = 31` row `(65824, 2^31, 1)`, so `byte_b0 = 2^31` and
`byte_and0 = 1` satisfy the lookup, and an `amoand.w` of `65823` with `2^31` proves
`and = 1` where the answer is 0. The pair under `f_bitwise` is what refuses it, and
`check_copowers` takes all four keys.

### 6.6 `sc.w` always succeeds

`sc.w` stores `rs2` and writes `rd = 0` unconditionally, with no reservation state anywhere
in the machine. The ISA requires an `sc.w` without a valid reservation to fail. **This is a
conformance deviation, not a soundness one**: the verifier still knows exactly which program
ran and what it computed, and fidelity would cost a reservation flag in machine state that
every family would then have to carry. LLVM never emits an unpaired `sc.w` and never relies
on spurious failure. The emulator has the same semantics, so emulator and circuit agree.
Frozen at S12, and S19 is the stage that gives it a circuit.

It was the QEMU differential's **one** whitelist entry — after an `sc.w`, `rd` could hold 1
in QEMU where the emulator had 0 — from S12 until S25. That whitelist is **gone with the
comparison it belonged to** (owner's decision, S25): nothing holds this emulator to QEMU's
registers any more, only to what a guest computes, so there is no exemption to grant. What
would surface the deviation is a guest whose committed output depended on spurious failure,
and compiled code has none, for the reason above.

### 6.7 Gates and lookups, in counts

**Forty-six enforcing gates**: the frame's eleven (five mask booleanity, two write-backs,
four x0) and this family's thirty-five — eleven kind booleanity, `decoded_mask_bits`, four
mask rules, four address rules, two `value_masked`, `addr_word`, `add_wrap_boolean`,
`add_rule`, `f_bitwise_boolean`, `f_bitwise_rule`, `old_bytes_rule`, `src_bytes_rule`, the
comparison's two, `lo_rule`, `ram_value_rule`, `rd_value_rule` and `next_pc_rule`. **Ten
timestamp, 19 `RANGE16`, 6 generic and 1 decoder obligations.**

## 7. Heights, and the registry

### 7.1 `DEFAULT_HEIGHTS[ATOMICS]`, `2^16` → `2^20`

A circuit carrying a timestamp gap obligation needs 19 variables, and a Mercury opening
needs an even count, so `2^20` is the floor for every family that runs cycles
(`lookup.md` §3). `ATOMICS` sat at `2^16` from S11 until this stage, which is the height
S16 answer 7 deferred to S19 "with the circuit that needs it".

What moves with it: every `VmConfig` containing the family, and so program identity for
every A-carrying program. The committed identity pins are `guests/fib`'s, which is A-free,
so `crates/program/tests/vectors/identity.txt` does not move. What does change is
`crates/program/tests/partition.rs`, where `guests/consistency` used to be the one guest the
frozen defaults refused — its atomics run up to pc `0x18e62a`, past a `2^16` table — and now
fits; the refusal keeps a test of its own against an explicit `2^16`.

### 7.2 The registry's minimum-height guard

`constraints::family_circuit`'s `trace_vars < 19 ⇒ None` arm now names **all seven**
execution families. It has to: `HEIGHT_MENU` legally contains `2^16` and `2^18`,
`VerifyingKey::check` builds a circuit from a key's own `VmConfig`, and without the guard a
key naming one of the three new families at `2^16` would reach `lookup::channel_trees`'
`BITS ≤ trace_vars` assertion — a **panic inside key validation**, in the `no_std` crate the
recursion guest links, on bytes a verifier was handed. With it, the answer is `None` and the
load is a clean `Err`.

## 8. The fixture

`guests/mem`, hand-written `global_asm!` with no SDK, checking every result itself and
exiting with the number of checks, **50**. Its statement is five execution families at
`2^20` — add/sub and jump/branch/slt beside the three this page defines — plus
`INIT_TEARDOWN` and, for the first time in any acceptance fixture, a `ZERO_WINDOWS` shard:
the guest writes near the top of RAM as well as inside window 0, so the derived window list
is `[8191]` at `h = 2^16`.

`crates/prover/tests/mem.rs` proves and verifies it;
`crates/emulator/tests/qemu_outputs.rs` holds what it computes — its exit status and its
fd 1 — to QEMU's; `crates/checker/tests/mem_fill.rs` runs all three fills over its archive
in ordinary CI, with every channel counted, and that is where the trace itself is checked.

## 9. What these families do not do, and the controls

1. **No `MemoryOffsetGetBits` table** (§4.2), and the packed generic table did not move.
2. **No confinement of an address to a live RAM window** (§2): that is the multiset
   argument's, and an out-of-window access is refused at `verify_shard` step 10.
3. **No reservation state** (§6.6).
4. **The tamper twins**, one per family, each refused in its class: for `MEM_WORD` the RAM
   query's `ram_read_value` on a store row, which **no gate and no obligation of that family
   reads** — the stage prompt names "one loaded-value cell" for this, which the frame's own
   `load_writes_back` gate and `rd_value_rule` both read, so the store's old word is the cell
   with the stated property and the refusal genuinely comes from the permutation product,
   `MemoryArgument`; for `MEM_SUBWORD` a `low` splice cell, `Constraint`; for `ATOMICS` the
   `rd` old-value cell of one AMO, `Constraint`. The negative control moves cells nothing
   reads on an all-zero padding row — `pcopow`, free there because `p` is 0 (§4.1).
