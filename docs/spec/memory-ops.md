# The memory-op families

`MEM_WORD` (`lw`, `sw`, `ld`, `sd`, `lwu`), `MEM_SUBWORD` (`lb`, `lh`, `lbu`, `lhu`, `sb`, `sh`) and
`ATOMICS` (`lr`, `sc` and the nine AMOs, each `.w` and `.d`): the execution families whose rows touch
RAM, each a circuit beside the memory frame ([memory.md](memory.md) §2), sharing §2's addressing.
They are `constraints::{mem_word, mem_subword, atomics}` on `crates/constraints/src/family.rs`'s
builder, filled by `prover::family_fill` (`crates/prover/src/fill.rs`), which computes each witness
with Rust's integer operations; their shapes are [circuits.md](circuits.md) §1's.

RAM is 32-bit words, registers two words each. All three frames are `pc rs1 rs2 load ram rd`; a
doubleword touches two words, the low at its 8-aligned address and the high 4 above it, through
`load` (Δ 2) and `ram` (Δ 3) ([execution-trace.md](execution-trace.md) §4). Below, `v_q`, `vh_q` and
`w_q` are query `q`'s read low word, read high word and written low word, `sel`, `sel_hi` the frame's
`rd_selected`, `rd_selected_hi`, and `b_k` the kind bits.

## 1. What the circuits read from the decoded table

`MEM_WORD`'s and `MEM_SUBWORD`'s tuple is `pc next_pc rs1 rs2 rd imm extra_mask`, `imm` the offset's
low word and `extra_mask`'s bit 31 its sign `neg`; `ATOMICS`' has no `imm`, its address being `rs1`
([program.md](program.md) §5). The kinds, in `constants::extra_mask` order:

```text
mem_word      lw sw ld sd lwu
mem_subword   lb lh lbu lhu sb sh
atomics       amoadd amoswap lr sc amoxor amoor amoand amomin amomax amominu amomaxu, .w then .d
```

Each circuit has the builder's plumbing (`decoded_mask_bits`, booleanity, each query's mask, address
and value-mask rules) and `next_pc_rule`, `next_pc − decoded_next_pc`. The masks:

| `uses_q` | `rs1` | `rs2` | `load` | `ram` | `rd` |
| --- | --- | --- | --- | --- | --- |
| `MEM_WORD` | every kind | `sw sd` | every kind | `ld sd` | `lw ld lwu` |
| `MEM_SUBWORD` | every kind | `sb sh` | the loads | the stores | the loads |
| `ATOMICS` | every kind | all but `lr` | the `.d` kinds | every kind | every kind |

## 2. Addressing

`mem_word::address(f, low)`, which `MEM_SUBWORD` shares, splits the effective address of a word
or sub-word access:

```text
addr_split   v_rs1 + imm − 2^32·wrap − 8·dword_index − 4·bit2 − low
addr_hi      vh_rs1 + wrap + (2^32 − 1)·neg − 2^32·hi_wrap
```

`low` is 0 for `MEM_WORD` and `2·bit1 + bit0` for `MEM_SUBWORD`; `wrap`, `hi_wrap`, `bit2` are bits,
`dword_index` a word, and `dword_index_hi_scaled` bounds `8·dword_index_h16` below `2^16`, so
`8·dword_index < 2^32` (`check_copowers` holds `dword_index_h16`'s direct bound beside it). `rs1`'s
words are words (§5), so `addr_split` holds over ℤ, its terms below `2^34`, and has one solution:
the 64-bit address's low word in digits, `wrap` its carry. `addr_hi` makes its high word —
`vh_rs1`, the offset's sign extension and the carry, below `2^33` — vanish mod `2^32`, so every
address is below `2^32` ([ecall-abi.md](ecall-abi.md) §5). The word read is at `8·dword_index +
4·bit2`, a doubleword's high word 4 above it. `ATOMICS` has no offset:

```text
addr_word    v_rs1 − 8·dword_index − 4·bit2          addr_hi   vh_rs1
```

so its address is `rs1`, 4-aligned, below `2^32`. `dword_aligned`, `(b_ld + b_sd)·bit2` in
`MEM_WORD` and `Σ .d·bit2` in `ATOMICS`, makes a doubleword 8-aligned. A misaligned access is
unprovable, as it is fatal in the emulator ([execution-trace.md](execution-trace.md) §10).

## 3. `MEM_WORD`

```text
load: address 8·dword_index + 4·bit2        ram: 4 above it
load_value_rule   w_load − v_load − (b_sw + b_sd)·(v_rs2 − v_load)
ram_value_rule    w_ram − v_ram − b_sd·(vh_rs2 − v_ram)
rd_lo_rule        sel − (b_lw + b_ld + b_lwu)·v_load
rd_hi_rule        sel_hi − b_ld·v_ram − b_lw·rd_lo_sign·(2^32 − 1)
```

`sel` is a signed word (`rd_lo_h16`, `rd_lo_sign` from its `SIGN` lookup) and `sel_hi` a word.
A load writes back both words it reads; `sw` writes `rs2`'s low word, `sd` both. `lw` sign-extends
the word by its bit 31, `lwu` zero-extends it, `ld` takes the two words. Every value identity is a
selection of words, exact over ℤ.

## 4. `MEM_SUBWORD`

### 4.1 The splice

A sub-word's position in its word lives only in

```text
word = high·(w·p) + sub·p + low      p = 2^(8·offset), offset = 2·bit1 + bit0
                                     w, the access width: 2^8 for a byte, 2^16 for a halfword
```

`p` and its copower are degree-2 forms in the offset bits, written as gates rather than looked up:

```text
p_rule        p − m_pc − 255·bit0 − 65535·bit1 − K·bit0·bit1      K = 2^24 − 2^16 − 2^8 + 1
pcopow_rule   p·pcopow − 2^31·m_pc                                 pcopow = 2^31/p
wph_rule      wph − 32768·p + 32640·BYTE·p                         wph = w·p/2
p_ram_rule    p_ram − m_ram·p
```

`p_rule` takes the four offsets to `1, 2^8, 2^16, 2^24`, `m_pc` standing for the constant so the
all-zero row satisfies it. The copower and `w·p` are stored halved so `2^32` fits a word, the gates
reading them carrying the factor 2. `p_ram` keeps `store_rule` degree 2.

### 4.2 Gates

With `LOADK`, `STORE`, `BYTE`, `SIGNEXT` the sums of the loads, the stores, `lb lbu sb` and
`lb lh`, beside the plumbing and §2:

```text
half_aligned         (b_lh + b_lhu + b_sh)·bit0
load_writes_back     w_load − v_load
word_rule            word − LOADK·v_load − STORE·v_ram
splice_rule          word − high_scaled − sub·p − low
high_scaled_rule     high_scaled − 2·high·wph                             = high·w·p
sub_scaled_rule      sub_scaled − 2^16·sub − (2^24 − 2^16)·BYTE·sub       = sub·2^32/w
low_scaled_rule      low_scaled − 2·low·pcopow                            = low·2^32/p
src_sub_rule         v_rs2 − src_sub − 2^16·src_high + 65280·BYTE·src_high
src_sub_scaled_rule  src_sub_scaled − 2^16·src_sub − (2^24 − 2^16)·BYTE·src_sub
store_rule           w_ram − m_ram·word − (src_sub − sub)·p_ram
sign_in_rule         sign_in − sub − 255·BYTE·sub                         = 2^8·sub or sub
se_rule              se − SIGNEXT·sign
rd_value_rule        sel − LOADK·sub − (2^32 − 2^16)·se − 65280·BYTE·se
rd_hi_rule           sel_hi − (2^32 − 1)·se
```

`mem_subword::splice_gates(byte_bits)` builds the twelve whose literals depend on the byte width —
`p_rule`, `pcopow_rule`, `wph_rule` and the splice, scaled, source, sign-in, `rd` and store rules —
and the circuit takes it at `BYTE_BITS = 8`. Its `RANGE16` obligations, under `m_pc`, are §2's and
word pairs on `high`, `high_scaled`, `sub_scaled`, `low`, `low_scaled`, `src_sub_scaled`, `src_high`
and `rd`, with one obligation each on `sub` and `src_sub`; its `GENERIC` lookup `sub_get_sign` is
`(SIGN, sign_in, sign)`, whose tag bounds `sign_in` by the sub-table.

### 4.3 Why it is sound

§2 fixes the offset bits and `half_aligned` clears `bit0` at halfword width, so `p` and `w` are the
access's and `w·p` divides `2^32`. Each part has a direct bound and a scaled one: `high < 2^32`
makes `high·w·p` an integer, `sub_scaled < 2^32` is `sub < w` and `low_scaled < 2^32` is `low < p`.
So `splice_rule` holds over ℤ with one solution, the base-`(p, w)` digits of the word, and a word
not below `2^32` has none. A scaled bound alone admits non-integers, its scale being a unit of `Fp`
([lookup.md](lookup.md) §11); `check_copowers` holds `dword_index_h16`, `high`, `sub`, `low` and
`src_sub` to their direct bounds. `src_high`'s pair makes `rs2`'s low word `src_sub + w·src_high`
integral, so `src_sub` is it mod `w`: without it `sb` could store a byte unrelated to `rs2`.

**A load** writes `rd = sub + (2^64 − w)·se`: the sub-word, or at `se = 1` its two's-complement
extension to 64 bits, `rd_hi_rule` filling the high word. `sign_in` is `2^8·sub` for a byte and
`sub` for a halfword, so its bit 15 is the sign at either width and one `SIGN` lookup serves both.

**A store** writes `word + (src_sub − sub)·p = high_scaled + src_sub·p + low`, a word with no
appeal to memory: `high_scaled` is a multiple of `w·p` below `2^32`, so `high_scaled ≤ 2^32 − w·p`
and `src_sub·p + low ≤ w·p − 1`. That is why `high_scaled` keeps its own pair.

`crates/checker/tests/families.rs`' `the_splice_admits_exactly_one_witness_at_a_reduced_width`
checks the splice whole at a 4-bit word: for every word, admissible offset and width,
`splice_gates(1)` and the bounds admit exactly one `(high, sub, low)`.

## 5. The write-side induction

A circuit may use a register operand's words as words without bounding them. That rests on two
facts:

- **Every register write is two words on its own row.** Every execution family bounds both words of
  what it writes to `rd`: a range pair, a signed word's bound, a selection of words it bounds, a sum
  of looked-up bytes, or a sign times `2^32 − 1`. The frame writes `(1 − z)·rd_selected` and
  `(1 − z)·rd_selected_hi` ([memory.md](memory.md) §2.4), registers start at 0 and a read returns
  the last write ([memory.md](memory.md) §9), so every register word read is a word, with no appeal
  to RAM.
- **Every RAM write of an execution family is a word**: `MEM_WORD` writes a register word,
  `MEM_SUBWORD` bounds its merged word itself (§4.3), each `ATOMICS` arm is a word (§6), and a load
  writes back what it read.

RAM's initial values are words — the image's, 0, the public input's — but advice's, which nothing
bounds. No execution family relies on a RAM word being one: each bounds the value it uses, by
`MEM_WORD`'s `rd` words, `MEM_SUBWORD`'s splice or `ATOMICS`' signed words and comparison, so a row
using a non-word is unprovable. The register half is what every carry needs: `a + b − 2^32·c` is a
reduction only for words ([memory.md](memory.md) §7), and §2's integer argument needs `rs1`'s
words.

## 6. `ATOMICS`

One row is one read-modify-write: the `ram` query reads `old` and writes `new` at the address,
`load` reads `old_hi` and writes `new_hi` 4 above it on a `.d` row, `lr` writing back what it read,
and `rd` gets the old value ([execution-trace.md](execution-trace.md) §4). A `.w` row's operands are
its low words sign-extended; the comparison and sum run over 64 bits for both widths.

```text
old_lo, src_lo (signed words)   old's and rs2's low words, signs old_sign, src_sign
lhs_hi_rule   lhs_hi − old_hi − (b_amomin_w + b_amomax_w)·old_sign·(2^32 − 1)
rhs_hi_rule   rhs_hi − Σ .d·vh_rs2 − (b_amomin_w + b_amomax_w)·src_sign·(2^32 − 1)
cmp_…         compare64 of (old, lhs_hi) against (v_rs2, rhs_hi), signed on amomin and amomax
min_lo_rule   min_lo − v_rs2 − cmp_lt·(old − v_rs2)
min_hi_rule   min_hi − rhs_hi − cmp_lt·(lhs_hi − rhs_hi)
add_lo        old + v_rs2 − sum_lo − 2^32·add_carry_lo
add_hi        old_hi + rhs_hi + add_carry_lo − sum_hi − 2^32·add_carry_hi
f_bitwise_rule  f_bitwise − (amoand + amoor + amoxor, both widths)
old_lo_bytes old_hi_bytes src_lo_bytes src_hi_bytes    old, old_hi, v_rs2, rhs_hi in bytes
ram_value_rule  new − written(old, v_rs2, sum_lo, AND_lo, min_lo), each kind's arm by both widths
load_value_rule new_hi − written(old_hi, vh_rs2, sum_hi, AND_hi, min_hi), by the .d kinds
rd_lo_rule    sel − Σ_{k ≠ sc} b_k·old
rd_hi_rule    sel_hi − Σ_{.d ≠ sc.d} b_k·old_hi − Σ_{.w ≠ sc.w} b_k·old_sign·(2^32 − 1)
```

`written` is `lr`: the old value; `sc`, `amoswap`: the source; `amoadd`: the sum; `amoand`: `A`,
the looked-up ANDs; `amoor`: `old + src − A`; `amoxor`: `old + src − 2A`; `amomin(u)`: `min`;
`amomax(u)`: `old + src − min`. The eight `and_byte_<j>` lookups, `(AND, byte_a_j, byte_b_j,
byte_and_j)`, are under `f_bitwise`; `sum_lo`, `sum_hi` are words.

**Why it is sound.** §2 makes the address `rs1`, below `2^32`, aligned to its width. `old` is a word
by its signed word, `old_hi` by the comparison's `cmp_lhs_hi` signed word, so a RAM value that is not
a word leaves the row unprovable. `.w` operands are sign- or zero-extended as `amomin`/`amomax` and
the rest read them, and §3.2 of [jump-branch-slt.md](jump-branch-slt.md) makes `cmp_lt` the order of
the two 64-bit values, so `min` is the minimum and `old + src − min` the maximum, each word a
selection of words. The sum's words and carries are exact over ℤ, every term below `2^34`. On an
AND, OR or XOR row the byte gates and lookups make `A` the AND of the two words, byte by byte, and
`a + b − (a & b)`, `a + b − 2·(a & b)` OR and XOR, each a word. `sc` always succeeds: it stores and
writes 0 to `rd`, as the emulator does ([execution-trace.md](execution-trace.md) §10), there being no
reservation state on one hart. A `.w` row's `load` query is absent, its read and high words 0.

`crates/checker/tests/families.rs` holds each family's fill to its circuit over `mem`'s, `atomics`'
and `opcodes`' traces, every kind among them: every written word one off is refused by the row
alone, and every gate and lookup refuses some single-cell edit.
