# The memory-op families

`MEM_WORD` (`lw`, `sw`), `MEM_SUBWORD` (`lb`, `lh`, `lbu`, `lhu`, `sb`, `sh`) and `ATOMICS`
(`lr.w`, `sc.w`, the nine AMOs): the execution families whose rows touch RAM, each a circuit beside
the memory frame ([memory.md](memory.md) §2), sharing §2's addressing. They are
`constraints::{mem_word, mem_subword, atomics}`, filled by `prover::family_fill`
(`crates/prover/src/fill.rs`), which computes each witness with Rust's integer operations.

| family | `M` | `W` | `S` | gates, frame + own | `TIMESTAMP`, `RANGE16`, `GENERIC`, `DECODER` |
| --- | --- | --- | --- | --- | --- |
| `MEM_WORD` | 31 | 24 | 7 | 13 + 20 | 12, 5, 0, 1 |
| `MEM_SUBWORD` | 31 | 55 | 10 | 13 + 40 | 12, 22, 1, 1 |
| `ATOMICS` | 26 | 54 | 9 | 11 + 35 | 10, 19, 6, 1 |

Each `artifact` asserts its gate and obligation counts and that the all-zero padding row satisfies
every gate. Below, `m_q`, `a_q` and `v_q` are query `q`'s mask, address and read value, `rs1` and
`rs2` the operands' read values ([memory.md](memory.md) §2.1), and `b_k` (`b_lw`, `b_lr`, …) the
committed kind bits.

## 1. What the circuits read from the decoded table

`MEM_WORD`'s and `MEM_SUBWORD`'s tuple is `pc next_pc rs1 rs2 rd imm extra_mask`, `imm` the
offset's two's-complement `u32`; `ATOMICS`' has no `imm`, its address being `rs1`
([program.md](program.md) §5). The tuple is the first setup columns, and the packed generic table
follows it where a family reads one: `S[7..10]` in `MEM_SUBWORD`, `S[6..9]` in `ATOMICS`
([lookup.md](lookup.md) §9). `extra_mask` is one-hot over `constants::extra_mask`, bit `k` the
`k`-th mnemonic below, and each module's `LEGAL_MASKS` is those single bits:

```text
mem_word      lw sw
mem_subword   lb lh lbu lhu sb sh
atomics       amoadd amoswap lr sc amoxor amoor amoand amomin amomax amominu amomaxu
```

The atomics order is ascending `funct5`; `aq` and `rl` order nothing on one hart and are not
recorded. `MEM_SUBWORD`'s modifiers are linear forms over its bits:

```text
LOADK = b_lb + b_lh + b_lbu + b_lhu     BYTE = b_lb + b_lbu + b_sb     SIGNEXT = b_lb + b_lh
STORE = b_sb + b_sh                     HALF = b_lh + b_lhu + b_sh
```

All three carry the same plumbing, each formula `= 0`:

```text
kind_<k>_boolean    b_k − b_k²
decoded_mask_bits   Σ_k 2^k·b_k − decoded_mask
<q>_mask_rule       m_q − m_pc·uses_q              every query but pc
<q>_addr_rule       m_q·(a_q − decoded_q)          rs1, rs2, rd
                    m_q·(a_q − 4·word_index)       load, ram (§2)
<q>_value_masked    v_q − m_q·v_q                  rs1, rs2
next_pc_rule        next_pc − decoded_next_pc      the fall-through (memory.md §5)
```

| `uses_q` | `rs1` | `rs2` | `load` | `ram` | `rd` |
| --- | --- | --- | --- | --- | --- |
| `MEM_WORD` | `b_lw + b_sw` | `b_sw` | `b_lw` | `b_sw` | `b_lw` |
| `MEM_SUBWORD` | `LOADK + STORE` | `STORE` | `LOADK` | `STORE` | `LOADK` |
| `ATOMICS` | every bit | every bit but `b_lr` | no query | every bit | every bit |

`m_rs2` is keyed on `b_lr`, the one kind without an `rs2` field, and not on `rs2 = x0`: an
`amoadd.w` whose `rs2` is `x0` still reads it.

## 2. Addressing

The effective address is `rs1 + imm` mod `2^32`, or `rs1` for an atomic. One degree-1 gate splits
it, with `wrap`, `bit0` and `bit1` boolean:

```text
MEM_WORD      addr_split   rs1 + imm − 2^32·wrap − 4·word_index
MEM_SUBWORD   addr_split   rs1 + imm − 2^32·wrap − 4·word_index − 2·bit1 − bit0
ATOMICS       addr_word    rs1 − 4·word_index
```

Over `Fr` that says nothing, 4 being a unit. Three `RANGE16` obligations under `m_pc`, on
`word_index_hi`, `word_index − 2^16·word_index_hi` and `4·word_index_hi` (`word_index_hi_range`,
`word_index_lo_range`, `word_index_hi_scaled`), cap `word_index` at `2^30 − 1`, the top word's. With
`rs1` a word (§5) and `imm` a table value the split is then one of integers: `wrap` is the true
carry, `bit1` and `bit0` the true low bits, and every RAM address is a 4-aligned address below
`2^32`. Having no offset bits, a misaligned `MEM_WORD` or `ATOMICS` access needs a `word_index` that
is not an integer, which its pair refuses; the emulator refuses it first
([execution-trace.md](execution-trace.md) §10). `addr_word` derives `rs1 < 2^32` rather than
assuming it. `half_aligned`, `HALF·bit0 = 0`, refuses a halfword at an odd address and keeps `w·p`
a divisor of `2^32` (§4.3).

Every RAM query's address is `4·word_index`, so byte, halfword, word and atomic accesses to one word
name one cell; the byte position lives only in `MEM_SUBWORD`'s splice. Confining an access to
initialized memory is the multiset's ([memory.md](memory.md) §9): an out-of-window access fails the
statement's memory argument, not a gate.

## 3. `MEM_WORD`

A load copies the word into `rd`, a store copies `rs2` into the word; there is no splice, no
generic lookup, and the decoded table is the only setup.

```text
W[9..15]   decoded_next_pc decoded_rs1 decoded_rs2 decoded_rd decoded_imm decoded_mask
W[15..21]  kind_lw kind_sw wrap word_index word_index_hi rd_hi
W[21..24]  mult_timestamp mult_range16 mult_decoder

wrap_boolean, addr_split (§2)
rd_value_rule       rd_selected − b_lw·load_read_value
store_value_rule    ram_write_value − m_ram·rs2
```

Its `RANGE16` obligations are §2's three and the 16+16 pair on `rd_selected`, and the two copies
are its whole semantics. `rd_selected` is range-checked although it copies a RAM word, because a RAM
word need not be a word, advice's initial values being bound to nothing
([public-values.md](public-values.md) §6): the pair keeps every register value a word without
reference to RAM (§5). No gate reads `ram_read_value`, the word a store overwrites; the memory
argument alone pins it.

## 4. `MEM_SUBWORD`

### 4.1 The splice

A sub-word's position in its word lives only in

```text
word = high·(w·p) + sub·p + low      p = 2^(8·offset), offset = 2·bit1 + bit0
                                     w, the access width: 2^8 if BYTE, 2^16 if HALF
```

`p` and its copower are degree-2 forms in the offset bits, written as gates rather than looked up:

```text
p_rule        p − m_pc − 255·bit0 − 65535·bit1 − K·bit0·bit1      K = 2^24 − 2^16 − 2^8 + 1
pcopow_rule   p·pcopow − 2^31·m_pc                                 pcopow = 2^31/p
wph_rule      wph − 32768·p + 32640·BYTE·p                         wph = w·p/2
p_ram_rule    p_ram − m_ram·p
```

`p_rule` takes the four offsets to `1, 2^8, 2^16, 2^24`, `m_pc` standing for the constant so the
all-zero row satisfies it. The copower and `w·p` are stored halved so that `2^32` fits a `u32`
column, the gates reading them carrying the factor 2, as `ShiftPowers`' do
([lookup.md](lookup.md) §9). `p_ram` keeps `store_rule` degree 2. A table keyed by the offset would
pin nothing `addr_split` does not, and add a key to bound ([lookup.md](lookup.md) §4).

### 4.2 Columns and gates

```text
W[9..21]   the decoded row; kind_lb … kind_sh
W[21..31]  wrap word_index word_index_hi bit0 bit1 p pcopow wph p_ram word
W[31..42]  high high_hi high_scaled high_scaled_hi sub sub_scaled sub_scaled_hi
           low low_hi low_scaled low_scaled_hi
W[42..51]  src_sub src_sub_scaled src_sub_scaled_hi src_high src_high_hi sign_in sign se rd_hi
W[51..55]  the four multiplicities
```

Its gates, beside the plumbing: `wrap_boolean`, `bit0_boolean`, `bit1_boolean`, `addr_split`,
`half_aligned`, §4.1's four, and

```text
word_rule            word − LOADK·load_read_value − STORE·ram_read_value
splice_rule          word − high_scaled − sub·p − low
high_scaled_rule     high_scaled − 2·high·wph                             = high·w·p
sub_scaled_rule      sub_scaled − 2^16·sub − (2^24 − 2^16)·BYTE·sub       = sub·2^32/w
low_scaled_rule      low_scaled − 2·low·pcopow                            = low·2^32/p
src_sub_rule         rs2 − src_sub − 2^16·src_high + 65280·BYTE·src_high
src_sub_scaled_rule  src_sub_scaled − 2^16·src_sub − (2^24 − 2^16)·BYTE·src_sub
store_rule           ram_write_value − m_ram·word − (src_sub − sub)·p_ram
sign_in_rule         sign_in − sub − 255·BYTE·sub                         = 2^8·sub or sub
se_rule              se − SIGNEXT·sign
rd_value_rule        rd_selected − LOADK·sub − (2^32 − 2^16)·se − 65280·BYTE·se
```

`mem_subword::splice_gates(byte_bits)` builds the twelve whose literals depend on the byte width —
§4.1's first three and these but `word_rule` and `se_rule` — and the circuit takes it at
`BYTE_BITS = 8`. Its `RANGE16` obligations, all under `m_pc`, are §2's three, 16+16 pairs on
`high`, `high_scaled`, `sub_scaled`, `low`, `low_scaled`, `src_sub_scaled`, `src_high` and
`rd_selected`, and one obligation each on `sub`, `src_sub` and `sign_in`; its `GENERIC` lookup is
`sub_get_sign`, `(sign_in + SIGN_BASE, sign, 0)`.

### 4.3 Why it is sound

§2 fixes the offset bits and `half_aligned` clears `bit0` at halfword width, so `p` and `w` are the
access's. Each part has a direct bound and a scaled one: `high < 2^32` makes `high·w·p` an integer,
`sub_scaled < 2^32` is `sub < w` and `low_scaled < 2^32` is `low < p`. So `splice_rule` holds over ℤ
with one solution, the base-`(p, w)` digits of the word, and a word not below `2^32` has none. A
scaled bound alone admits non-integers, its scale being a unit of `Fr` ([lookup.md](lookup.md)
§11); `constraints::lookup::check_copowers` holds `word_index_hi`, `high`, `sub`, `low` and
`src_sub` to their direct bounds, one obligation being exact for `sub` and `src_sub`, both below
`w ≤ 2^16`. `src_high`'s pair makes `rs2 = src_sub + w·src_high` integral, so `src_sub` is
`rs2 mod w`: without it `sb` could store a byte unrelated to `rs2`.

**A load** writes `rd = sub + (2^32 − w)·se`: the sub-word, or at `se = 1` its two's-complement
extension (`lb` of `0x88` is `0xffffff88`). `sign_in` is `2^8·sub` for a byte and `sub` for a
halfword, so its bit 15 is the sign at either width and one `U16GetSign` lookup serves both; its own
obligation bounds the key into that sub-table ([lookup.md](lookup.md) §4). `se` is a one-hot sum
times a table bit, boolean without a gate.

**A store** writes `word + (src_sub − sub)·p = high_scaled + src_sub·p + low`, a word with no appeal
to memory: `high_scaled` is a multiple of `w·p` below `2^32` and `w·p` divides `2^32` (a halfword
at offset 3 would make it `2^40`; `half_aligned` excludes it), so `high_scaled ≤ 2^32 − w·p` and
`src_sub·p + low ≤ w·p − 1`. That is why `high_scaled` keeps its own pair.

`crates/checker/tests/mem_subword.rs` checks the splice whole at a 4-bit word: for every word,
admissible offset and width, `splice_gates(1)` and the bounds admit exactly one `(high, sub, low)`.

## 5. The write-side induction

A circuit may use a register operand as a word without bounding it. That rests on two facts:

- **Every register write is a word on its own row.** Every execution family's `rd_selected` carries
  a 16+16 pair under `m_pc`, but `ATOMICS`', which is the old word or 0, the old word bounded by its
  comparison's pair under `m_pc` (§6). The frame writes `(1 − z)·rd_selected`
  ([memory.md](memory.md) §2.4), registers start at 0 and a read returns the last write
  ([memory.md](memory.md) §9), so every register read is a word, with no appeal to RAM.
- **Every RAM write of an execution family is a word**: `MEM_WORD` writes `rs2`, a register value;
  `MEM_SUBWORD` bounds its merged word itself (§4.3); each `ATOMICS` arm is bounded (§6); a
  read-only query writes back what it read.

RAM's initial values are words — the image's, 0, the public input's — but advice's, which nothing
bounds. No execution family relies on a RAM word being one: each bounds the value it uses, by
`MEM_WORD`'s `rd` pair, `MEM_SUBWORD`'s splice or `ATOMICS`' comparison, so a row using a non-word
is unprovable. The register half is what every carry needs: `a + b − 2^32·wrap` is a reduction only
for words ([memory.md](memory.md) §7), and `addr_split`'s integer argument needs `rs1 < 2^32`.

## 6. `ATOMICS`

One row is one read-modify-write: the `ram` query reads `old` and writes `new` at Δ = 3, beside
`rd` ([execution-trace.md](execution-trace.md) §4), `lr.w` included, which writes its word back.

```text
W[8..13]   decoded_next_pc decoded_rs1 decoded_rs2 decoded_rd decoded_mask    (no imm)
W[13..24]  kind_amoadd … kind_amomaxu
W[24..30]  word_index word_index_hi sum sum_hi add_wrap f_bitwise
W[30..42]  byte_a0..3 byte_b0..3 byte_and0..3       old's bytes, rs2's, their AND
W[42..50]  old_hi old_sign src_hi src_sign lt cmp_gap cmp_gap_hi lo
W[50..54]  the four multiplicities
```

With `A = Σ_j 2^(8j)·byte_and_j` inlined, its gates beside the plumbing are:

```text
ram_value_rule    new − b_lr·old − (b_sc + b_amoswap)·rs2 − b_amoadd·sum − b_amoand·A
                    − b_amoor·(old + rs2 − A) − b_amoxor·(old + rs2 − 2A)
                    − (b_amomin + b_amominu)·lo − (b_amomax + b_amomaxu)·(old + rs2 − lo)
rd_value_rule     rd_selected − Σ_{k ≠ sc} b_k·old
add_rule          old + rs2 − sum − 2^32·add_wrap
f_bitwise_rule    f_bitwise − b_amoand − b_amoor − b_amoxor
old_bytes_rule    old − Σ_j 2^(8j)·byte_a_j          src_bytes_rule   rs2 − Σ_j 2^(8j)·byte_b_j
lo_rule           lo − rs2 − lt·(old − rs2)
addr_word (§2); add_wrap_boolean, f_bitwise_boolean; cmp_order, cmp_lt_boolean (below)
```

Each takes a kind's bit through its `constants::extra_mask` constant, from which the table's masks
are built too, so a transposed arm would pass the decoder lookup. Under `m_pc` the family looks up
the comparison's pairs on `old`, `rs2` and `cmp_gap` and its two signs, §2's three and `sum`'s pair;
under `f_bitwise`, for each `j`, `byte_a_j` and `2^8·byte_a_j` on `RANGE16` and `and_byte_j`,
`(byte_a_j + AND_BASE, byte_b_j, byte_and_j)`, on `GENERIC`.

**The comparison** is `constraints::gadgets::comparison` ([jump-branch-slt.md](jump-branch-slt.md)
§3) with selector `m_pc`, `lhs = old`, `rhs = rs2` and `signed = [b_amomin, b_amomax]`. The
family's `assemble` asserts all four, nothing else in the artifact determining them: `signed`
widened to `amominu` orders it signed, `lhs` and `rhs` swapped turn `amomin` into a max, and a
selector narrowed to the min/max kinds drops `old`'s bound on the other seven, and with it the
bound on their `rd` write (§5). `lo` is the smaller under the ordering `lt` settles, and
`old + rs2 − lo` the larger.

**Why `new` is a word.** `old` and `rs2` are bounded by the comparison, `sum` by its own pair
(`add_rule` is ungated: `sum = (old + rs2) mod 2^32` on every live row), `lo` and the larger by
being `old` and `rs2`. On a bitwise row `byte_a_j`'s pair puts the key in the AND sub-table, whose
row bounds `byte_b_j` and fixes `byte_and_j = byte_a_j & byte_b_j`; the byte rules are then the
operands' decompositions, and `A`, `old + rs2 − A`, `old + rs2 − 2A` are AND, OR and XOR, carry-free
byte by byte. Without its pair `byte_a0 = 65,823` reads `ShiftPowers`' `(65,824, 2^31, 1)`
([lookup.md](lookup.md) §4); `check_copowers` takes the four keys under `f_bitwise`, which covers
all three bitwise kinds: under `b_amoand` alone `amoor` and `amoxor` would read free `byte_and`.

**`sc.w` always succeeds**: it stores `rs2` and writes 0 to `rd`, and the machine holds no
reservation. The emulator does the same ([execution-trace.md](execution-trace.md) §10), and a row
claiming failure, a nonzero `rd` or an unchanged word, is refused by `rd_value_rule` or
`ram_value_rule`. This is a conformance deviation, not a soundness one: the proof is of what the
program did on this machine. A guest may not rely on an `sc.w` failing where the ISA requires it to:
with no valid reservation (no earlier `lr.w`, or one an earlier `sc.w` consumed) or at an address
outside the reservation set. The `lr.w`/`sc.w` retry loop compiled code uses is unaffected,
first-pass success being legal on any hart.
