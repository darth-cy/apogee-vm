# The precompiles

The delegation calls: an `ecall` that hands a frame of RAM words to a circuit other than the CPU's,
the request and the invocation paired through the memory multiset. Three are registered, the
Poseidon2-A64-C5 permutation, `mul_div_u256` and `merkle_root`. `constants::delegation::TYPES` is the
registry; this page is the mechanism (§1, §2), the calls' circuits (§3, §4, §6) and the SDK over
them (§5).

## 1. The mechanism

| number | family | id | an entry | words | rows | channels |
| --- | --- | --- | --- | --- | --- | --- |
| `0x0510` | `POSEIDON2` | 12 | a call | 32 | 1 | `RANGE16` |
| `0x0510` | `POSEIDON2_ROUNDS` | 13 | a call | 32 | 16 | none |
| `0x0511` | `MUL_DIV_U256` | 14 | a call | 24 | 1 | `RANGE16` |
| `0x0512` | `MERKLE_ROOT` | 15 | a call | 19 | 1 | `RANGE16` |
| `0x0512` | `MERKLE_LEVELS` | 16 | a level | 16 | 1 | `RANGE16` |
| `0x0512` | `MERKLE_ROUNDS` | 17 | a level | 16 | 16 | `RANGE16` |

A call is one cycle of `ADD_SUB_LUI_AUIPC`: `a7` the number, `a0` the frame's word-aligned base,
both preserved; the row writes no register and falls through. Each family of the number records
every entry of its kind: the call, or for `MERKLE_ROOT`'s later two families each level of the
call's path (§6). The first is its **frame family**, whose row reads and writes every frame word at
the requesting cycle's `4·cycle + FRAME_DELTA`, `FRAME_DELTA = 0`, and reads the anchor (§2); the
first level family, `MERKLE_LEVELS`, reads its level's sibling at the same timestamp; a later family
expands an entry into rows of its own, holding its words in its buffer and reaching no memory but
its own address space. A delegation family owns no cycle and claims no pc: it is in a `VmConfig`
exactly when the image declares its number ([program.md](program.md) §7), and it plans
`⌈entries·rows/h⌉` shards ([streaming.md](streaming.md) §4) under the trivial time window
([proof.md](proof.md) §8).

**Declarations.** Each SDK shim's record is a `u32` static, its ecall number, in an input section of
its own, `.apogee.delegations.<name>`, which `--gc-sections` keeps exactly where the shim is linked.
`apogee.ld` gathers them into the output section `constants::delegation::SECTION`,
`.apogee.delegations`, and `loader::load_elf` reads that section's records by its name into
`ProgramImage::delegations` ([program.md](program.md) §3): no other byte of the image declares
anything. An image without the section declares nothing, and a number no family registers is
refused (`UnknownDelegation`).

**The frame**, `constraints::delegation::frame`, over a row whose one mask is `live`:

```text
M   live cycle number, then per word j  w{j}_addr w{j}_read_ts w{j}_read_value [w{j}_write_value]
W   w{j}_gap_c0 w{j}_gap_c1             RANGE16 chunks of 4·cycle + FRAME_DELTA − 1 − read_ts
    room_h16                            the room's high halfword
number_rule   number − NUMBER·live      addr_w{j}   addr_j − addr_0 − 4j·live,  j ≥ 1
room          (ADVICE_ORIGIN − 4·words)·live − addr_0, a word
read   word j (RAM, addr_j, read_ts_j, read_j)      the anchor (DELEGATION, addr_0, cycle, number)
write  word j (RAM, addr_j, 4·cycle + FRAME_DELTA, write_j), read_j for a word written back
```

A gap in `[0, 2^38)` is two chunks and four obligations: each chunk direct, the top one scaled by
`2^10`, and the remainder ([lookup.md](lookup.md) §11's copower rule holds the scaled one to its
direct bound); **UNFINISHED: A64-C5 CHARACTERISTIC**, as every gap ([memory.md](memory.md) §4.2).
**The room keeps the frame below the advice.** `addr_0` is the request's `a0`, a word (§2), so
`room` is a word exactly when the frame ends at or below `ADVICE_ORIGIN`. Below it every value is a
word: initialized from the image, the public input or 0 ([memory.md](memory.md) §3), and written
only as one, which every writer leaves in RAM ([memory-ops.md](memory-ops.md) §5). So every frame
word a call reads is a word with no bound of its own; an advice word, initialized from an `M`
column nothing bounds ([public-values.md](public-values.md) §6), could be any field element. A
word below it that no window initializes, unaligned or in the hole, reads a tuple nothing wrote,
and the memory argument refuses it ([memory.md](memory.md) §9). The emulator refuses a frame past
`ADVICE_ORIGIN` as `OutOfBounds` and checks each word as it checks a store's; every word a call
writes is bounded by its circuit.

## 2. The request and the anchor

The ecall row writes one tuple in `address_space::DELEGATION = 4`, and the frame row of the family
its number names reads it:

```text
request (ADD_SUB_LUI_AUIPC)   writes   T(DELEGATION, a0, cycle, a7)       mask delegates
invocation (frame row)        reads    T(DELEGATION, addr_0, cycle, NUMBER)
```

Nothing else reaches the space, so its reads and writes are equal multisets. Every request's tuple is
its own, no two rows sharing a cycle ([memory.md](memory.md) §9), so each frame row is exactly one
request's, at its base, its cycle and its number, and each request has exactly one frame row: the
frame's RAM accesses are that point of each word's history. A number no family registers has no
reader, and its request does not balance.

**The request side**, [add-sub.md](add-sub.md) §2: the system kind splits three ways, `is_exit +
delegates + is_fence`, `delegates` an `M` column held to booleanity and to live rows; a request reads
`a7` and `a0`, both words (`delegation_number_hi`, `delegation_base_hi`), and has no `rd` query. Its
tuple is folded into `rd`'s write leaf, `1 + m_rd·(T_rd − 1) + delegates·(T − 1)`, the two masks
exclusive by the mask rules, so the request costs the family one column and no leaf.

## 3. Poseidon2

`transcript::poseidon2_permute` ([transcript.md](transcript.md) §1.2): the external layer `M_E`, six
full rounds, 42 partial rounds, six full rounds. A lane is two frame words, little-endian; the call
reads it mod `p` and writes it canonical. The state between rows is `address_space::POSEIDON2 = 5`:
lane pair `j` of the call at `cycle`, at boundary `b`, is the tuple

```text
T(POSEIDON2, cycle, 8b + j, lane 2j, lane 2j + 1)           j < 8,  b ≤ 15
```

The call is the address and its place the timestamp, so two calls' tuples differ wherever their
cycles do, which no two requests share (§2), whatever value a cycle takes
([memory.md](memory.md) §4.2); `8b + j < 128` names one pair of one boundary.

### 3.1 `POSEIDON2`, the frame row

The frame (§1) over 32 words, all written; `u` the input after `M_E`, sent at boundary 0; `o` the
output, received at boundary 15, whose stamp `8·15` is the column `last`, and written:

```text
last_rule   last − 120·live
u{j}_rule   u_j − Σ_k M_E[j][k]·(read_{2k} + 2^32·read_{2k+1})
o{l}_rule   o_l − write_{2l} − 2^32·write_{2l+1}
o{l}_top    is_zero(3·0xFFFF − h1 − h0 − l1; inv, top)       top = 1 exactly when all the pair's
                                                              halfwords but the lowest are 0xFFFF
o{l}_canonical   0xFFFF − 59·top − l0  ∈ [0, 2^16)
send  (POSEIDON2, cycle, j, u_2j, u_2j+1)      receive  (POSEIDON2, cycle, last + j, o_2j, o_2j+1)
```

`l0 l1` and `h0 h1` are the output words' halfwords, each bounded, so the pair is a canonical lane:
below `2^64` with `top = 0`, and with `top = 1` at most `2^64 − 60 = p − 1`. 294 committed columns,
210 obligations (the `RANGE16` tree at 256 leaves, 45 free), 41 and 40 leaves.

### 3.2 `POSEIDON2_ROUNDS`

Sixteen rows a call: rows 0–5 the initial full rounds, 6–8 fourteen partial rounds each, 9–14 the
terminal full rounds, 15 idle; row `k` reads boundary `k` and writes `k + 1`. One layout of sixteen
S-boxes, `y`, `y²`, `y³` committed, serves both kinds: a full round's are its lanes in parallel, a
partial row's its fourteen rounds in sequence. No row mixes the two.

```text
M   live cycle stamp s0..s15 o0..o15      W   row0..row14 ext int y{j} y{j}_sq y{j}_cube
one_kind      Σ_k row_k − live            stamp_rule   stamp − Σ_k 8k·row_k
ext_rule      ext − Σ_{k external} row_k  int_rule     int − live + ext
y{j}_rule     y_j − ext·s_j − int·L_j(s, y³) − Σ_k row_k·c_k[j]
y{j}_sq_rule  y{j}_sq − y_j·y_j           y{j}_cube_rule   y{j}_cube − y{j}_sq·y_j
o{l}_rule     o_l − ext·Σ_k M_E[l][k]·y³_k − int·K_l(s, y³)
read   (POSEIDON2, cycle, stamp + j, s_2j, s_2j+1)
write  (POSEIDON2, cycle, stamp + 8 + j, o_2j, o_2j+1)
```

`c_k` is row `k`'s round constants (`constraints::poseidon2::round_constant`): a full round's per
lane, a partial row's per round, 0 at its two idle slots. `L_j` and `K_l` are the partial rounds as
linear forms in the row's lanes and S-box outputs (`internal_forms`): round `m` S-boxes lane 0 and
applies `M_I = J + diag(μ − 1)`. The kind rides a linear factor, so every gate is degree 2. 100
committed columns, no obligation, 8 leaves a side; at `2^16`, 4,096 calls a shard.

### 3.3 Why the rows are one permutation

The state's reads and writes are equal multisets: nothing initializes the space and no final reads
it. Boundary 0, timestamps 0 to 7, is written by frame rows alone and read by round-0 rows alone, a
round row's boundary pinned by its one-hot kind, which also chooses its constants; each frame row
writes its 8 pairs at its own cycle, unique because its anchor is (§2), and each round row reads one
of each pair at one cycle. So the round-0 rows are the frame rows' one each, reading exactly `u`. By
induction on `b`, the round-`b` rows are too, each reading what the round-`b − 1` row wrote. At
boundary 15 the frame row reads the row-14 output, which it writes to the frame. There is no chain
without a frame row: one would start at a boundary-0 read no frame row wrote.

## 4. `mul_div_u256`

One row a call. The frame is `a`, `b`, `d`, eight little-endian words each; the call writes
`q = ⌊a·b/d⌋` over `a`, `r = a·b mod d` over `b`, and `d` back. **The caller owes `d ≠ 0` and
`q < 2^256`**: the emulator refuses either (`EmuError::DelegationFrame`) and neither has a witness.

```text
limbs        every word of a, b, d, q, r its two RANGE16 halfwords
chunk{k}     S_k(a·b) − S_k(q·d) − [k < 8]·r_k + carry_{k−1} − 2^32·carry_k      k = 0 … 15
carry{k}     carry_k + 2^21 ∈ [0, 2^22)                                          k = 0 … 14
bound{k}     d_k − r_k − [k = 0] + 2^32·borrow_k − borrow_{k−1}, a word         borrow_7 = 0
```

`S_k` sums the limb products at limb positions `2k` and `2k + 1`, the second weighted `2^16`: below
`2^53`, so each chunk is an identity over ℤ, and their sum with weights `2^32k` is `a·b = q·d + r`.
The bound is `d − r − 1 ≥ 0`, so `r < d` and `d ≥ 1`, and `q`'s words make `q < 2^256`: the two
conditions that single out the quotient. 226 committed columns, 239 obligations (256 leaves, 16 free),
25 and 24 leaves.

## 5. The SDK

`crates/guest-sdk` ([guest-program-manual.md](../guest-program-manual.md) §3.1):

| item | |
| --- | --- |
| `poseidon2_permute(&mut [u64; 16])` | the call over the array itself, in place, each lane read mod `p` |
| `Digest` | 8 lanes, each below `p`: `Digest::new` refuses any other, so a node has one encoding; what the call writes is one already |
| `poseidon2_compress(&Digest, &Digest) -> Digest` | a Merkle node: `P(left ‖ right)[0..8]`, truncated |
| `U256` | four `u64` limbs; `+ − * / %` panic on overflow and a zero divisor, `checked_*`, `overflowing_*`, `wrapping_*` do not; `<< >> & | ^ !`, `Ord`, bytes in either order |
| `U256::mul_div_rem`, `mul_div`, `div_rem` | the call; `None` where the caller's precondition fails, checked first: `d = 0`, or the high half of `a·b`, skipped when both are below `2^128`, at or above `d` |
| `merkle_root(slot, &Digest, siblings: &[u8]) -> Digest` | the call over a path of `siblings.len() / 64` siblings where they lie; panics first where its precondition fails (§6) |
| `Digest::bytes(&[Digest]) -> &[u8]` | a path the guest holds, as `merkle_root` takes it |

`apogee_poseidon2_permute`, `apogee_mul_div_u256` and `apogee_merkle_root` are the C ABI's
([ecall-abi.md](ecall-abi.md) §7). Every frame is the caller's own memory below the advice region
(§1), a guest copying advice in before it permutes it; a path's siblings are not a frame, and
`merkle_root` reads an advised path in place (§6). A digest decoded from advice or input, that the
guest compares or publishes, is `Digest::new`'s to check.

## 6. `merkle_root`

The root of a binary Merkle path: a leaf, its slot and its `depth` siblings, `16 ≤ depth ≤ 32`.
Level `L`'s node is `P(left ‖ right)[0..8]`, the first eight lanes of
`transcript::poseidon2_permute`, the node below on the left where bit `L` of the slot is 0: the fold
of `poseidon2_compress`, one call for the whole path. The frame, `constants::delegation::merkle`:

```text
words 0..16   lanes      8 lanes, two little-endian words each: the leaf in, the root out
word  16      slot       below 2^depth
word  17      depth      16..=32
word  18      siblings   the address of depth siblings, 64 bytes each, level 0's first
```

**The caller owes** a depth in `16..=32`, a slot below `2^depth`, and word-aligned siblings clear of
the frame: the emulator refuses any other frame as `EmuError::DelegationFrame` and a sibling word no
load could read as `OutOfBounds`, and none has a witness. The leaf is read mod `p` and the root
written canonical. **The siblings are not the frame.** `MERKLE_LEVELS` reads their words at the
call's timestamp and writes them back unchanged, and takes each lane mod `p`; any field element is
a lane of a sibling, so a word the advice initialized to a non-word names only a sibling some pair
of words names as well, and no word anywhere changes. So the siblings may lie anywhere a load
reaches, the advice included, and a guest hashes an advised proof where it lies.

The state between rows is `address_space::MERKLE = 6`, one counter for the whole call: boundary `B`
is timestamps `16B` to `16B + 15`, sixteen boundaries a level.

```text
T(MERKLE, cycle, 16B + s, lane 2s, lane 2s + 1)     a lane pair, s < 8; s < 4 at a level's boundary 16L, the node
T(MERKLE, cycle, 256L + 8, rest, ptr)               level L's control: the slot's bits not yet taken, its sibling's address
```

Level `L`'s row takes boundary `16L` to `16L + 1`, and its fifteen round rows `16L + 1` to
`16(L + 1)`; the frame row writes boundary 0 and reads boundary `16·depth`. As in §3 the call is the
address and its place the timestamp, so two calls' tuples differ wherever their cycles do, whatever
value a cycle takes; every stamp is held to fewer than `2^16` levels, so a timestamp, below `2^25`,
names one boundary and one slot.

### 6.1 `MERKLE_ROOT`, the frame row

```text
frame        19 words (§1), the lanes written
depth_low    depth − 16 ∈ [0, 2^16)            depth_high   32 − depth ∈ [0, 2^16)
last_rule    last − 256·depth                  end_rule     end − siblings − 64·depth
n{i}_rule    n_i − read_{2i} − 2^32·read_{2i+1}             the leaf, read mod p
o{l}         o_l − write_{2l} − 2^32·write_{2l+1}, canonical as §3.1's o{l}
send     (MERKLE, cycle, s, n_2s, n_2s+1), s < 4      (MERKLE, cycle, 8, slot, siblings)
receive  (MERKLE, cycle, last + s, o_2s, o_2s+1)      (MERKLE, cycle, last + 8, 0, end)
```

166 committed columns, 120 obligations (the `RANGE16` tree at 128 leaves, 7 free), 25 and 24 leaves.

### 6.2 `MERKLE_LEVELS`

One row a level `L`, its stamp `256L`:

```text
M   live cycle stamp next rest rest_next ptr  w{j}_read_ts w{j}_read_value (j < 16)  n0..n7 u0..u15
W   bit  w{j}_gap_c0 w{j}_gap_c1
level_range   stamp/256 ∈ [0, 2^16)              next_rule   next − stamp − 256
rest_rule     rest − bit − 2·rest_next           bit boolean
u{j}_rule     u_j − Σ_k (M_E[j][k]·n_k + M_E[j][8+k]·s_k) − bit·Σ_k (M_E[j][k] − M_E[j][8+k])·(s_k − n_k)
w{j}          read (RAM, ptr + 4j, read_ts_j, read_j), write (RAM, ptr + 4j, 4·cycle + FRAME_DELTA, read_j),
              the gap below it in [0, 2^38)
receive  (MERKLE, cycle, stamp + s, n_2s, n_2s+1), s < 4    (MERKLE, cycle, stamp + 8, rest, ptr)
send     (MERKLE, cycle, stamp + 16 + s, u_2s, u_2s+1), s < 8    (MERKLE, cycle, next + 8, rest_next, ptr + 64)
```

`s_k = read_2k + 2^32·read_2k+1` is the sibling's lane `k`, and `u` is `M_E(n ‖ s)` where the bit is
0 and `M_E(s ‖ n)` where it is 1, degree 2 with no column for either order. A word's address is
`ptr + 4j` in its leaves, `4j` mask terms (§1's parts) rather than a column. 97 committed columns, 65
obligations (128 leaves, 62 free), 21 and 25 leaves.

### 6.3 `MERKLE_ROUNDS`

§3.2's rows from the same builder, `constraints::poseidon2::rounds`, keyed for a level:

```text
level_range   (stamp − Σ_k 16(k + 1)·row_k)/256 ∈ [0, 2^16)     for stamp_rule: stamp = 256L + 16(k + 1)
keep_rule     keep − live + row14, keep boolean
read   (MERKLE, cycle, stamp + s, s_2s, s_2s+1)
write  (MERKLE, cycle, stamp + 16 + s, o_2s, o_2s+1), under keep where s ≥ 4
```

The last round writes the first four pairs alone, the node: truncation is the circuit's, so no row
reads the lanes a level drops. 102 committed columns, 1 obligation; at `2^16`, 4,096 levels a shard.

### 6.4 Why the rows are one path

The controls, slot 8, are written only by the frame row (level 0's) and by level rows (level
`L + 1`'s), and read only by level rows (level `L`'s) and the frame row (level `depth`'s). The frame
row is its anchor's, one a cycle (§2), so its control is read by exactly one level-0 row, and by
induction there is exactly one level row each `L < depth`, the last writing the control the frame
row reads. `rest_{L+1} = (rest_L − bit_L)/2` runs from the slot to 0, so `slot = Σ 2^L·bit_L` in
`Fp`, both sides below `2^32 < p`: the bits are the slot's, and the slot is below `2^depth`.
`ptr_L = siblings + 64L`, so level `L` reads sibling `L`, a memory-consistent read at the call's
timestamp. Boundary `16L + 1` is read only by level `L`'s round 0, a round row's boundary pinned by
its kind and its level by its bound; `16L + 2 + k` only by round `k + 1`; and `16(L + 1)` only by
level `L + 1`'s row or, at `L + 1 = depth`, the frame row. So the frame row receives `N_depth`,
where `N_0` is the leaf and `N_{L+1}` the first eight lanes of the permutation of `N_L` and sibling
`L` in the bit's order: the root. No row of the space exists without its call's frame row: the
least control or boundary any of them reads was written by none.

### 6.5 The trace

A call is one `MERKLE_ROOT` entry, its frame, and `depth` entries in each of `MERKLE_LEVELS` and
`MERKLE_ROUNDS`, one a level (`constants::delegation::Per::Level`): the level's sibling, its 16
words at its address, accessed at the call's timestamp after the frame's, and its carry
(`delegation::CARRY`), the node it starts from, the slot's bits not yet taken and its level. The
carry is what a row starts from that no word of its entry gives, so a shard may begin mid-path
([streaming.md](streaming.md) §4); `trace::TraceArchive` checks a level's words against the log as
it does a frame's.
