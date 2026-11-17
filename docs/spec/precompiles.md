# The precompiles

The delegation calls: an `ecall` that hands a frame of RAM words to a circuit other than the CPU's,
the request and the invocation paired through the memory multiset. Five are registered, the
Poseidon2-A64-C5 permutation, `mul_div_u256`, `merkle_root`, Keccak-f[1600] and the Falcon-512
lattice check. `constants::delegation::TYPES` is the registry; this page is the mechanism (§1, §2),
the calls' circuits (§3, §4, §6, §7, §8) and the SDK over them (§5).

## 1. The mechanism

| number | family | id | an entry | words | rows | channels |
| --- | --- | --- | --- | --- | --- | --- |
| `0x0510` | `POSEIDON2` | 12 | a call | 32 | 1 | `RANGE16` |
| `0x0510` | `POSEIDON2_ROUNDS` | 13 | a call | 32 | 16 | none |
| `0x0511` | `MUL_DIV_U256` | 14 | a call | 24 | 1 | `RANGE16` |
| `0x0512` | `MERKLE_ROOT` | 15 | a call | 19 | 1 | `RANGE16` |
| `0x0512` | `MERKLE_LEVELS` | 16 | a level | 16 | 1 | `RANGE16` |
| `0x0512` | `MERKLE_ROUNDS` | 17 | a level | 16 | 16 | `RANGE16` |
| `0x0513` | `KECCAK` | 18 | a call | 50 | 8 | `RANGE16`, `XOR8` |
| `0x0513` | `KECCAK_RHO` | 19 | a call | 50 | 128 | `XOR8` |
| `0x0513` | `KECCAK_CHI` | 20 | a call | 50 | 128 | `XOR8` |
| `0x0514` | `FALCON` | 21 | a call | 5 | 1 | `RANGE16` |
| `0x0514` | `FALCON_SPLIT` | 22 | the arrays | 768 | 64 | `RANGE16` |
| `0x0514` | `FALCON_PRODUCT` | 23 | the arrays | 768 | 16 | `RANGE16` |

A call is one cycle of `ADD_SUB_LUI_AUIPC`: `a7` the number, `a0` the frame's word-aligned base,
both preserved; the row writes no register and falls through. Each family of the number records
every entry of its kind (`constants::delegation::Per`): the call, or for `MERKLE_ROOT`'s later two
families each level of the call's path (§6), or for `FALCON512`'s later two the call's three arrays
(§8). The first is its **frame family**, whose rows read and write every frame word at the
requesting cycle's `4·cycle + FRAME_DELTA`, `FRAME_DELTA = 0`, and read the anchor (§2); the first
level family, `MERKLE_LEVELS`, reads its level's sibling at the same timestamp, and the first
arrays family, `FALCON_SPLIT`, the arrays' words; a later family expands an entry into rows of its
own, holding its words in its buffer and reaching no memory but its own address space. An entry's
rows are a block of a power of two, the rows past its live ones all zero, padding: `KECCAK`'s 8
rows hold 5 live, `KECCAK_RHO`'s and `KECCAK_CHI`'s 128 hold 120, and `FALCON_SPLIT`'s 64 hold 48
(§7, §8). A delegation family owns no cycle and claims no pc: it is in a `VmConfig` exactly when the
image declares its number ([program.md](program.md) §7), and it plans `⌈entries·rows/h⌉` shards
([streaming.md](streaming.md) §4) under the trivial time window ([proof.md](proof.md) §8).

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
direct bound); `cycle` is the request's, through the anchor, so every gap holds over the integers
([memory.md](memory.md) §4.2). `KECCAK`'s frame is five rows of its own, ten words a row, each with
these accesses, gaps and `room` (§7.1).
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
| `keccak_f1600(&mut [u64; 25])` | the call over the array itself, in place (§7): lane `A[x][y]` at `x + 5y`, its byte `k` bits `8k..8k + 8`; any 25 lanes are a state |
| `Shake256` | SHAKE256 over `keccak_f1600`: `absorb` bytes, `finalize`, then `squeeze` any number; rate `Shake256::RATE = 136` bytes, the padding `0x1F` after the message and `0x80` into the rate's last byte; absorbing after `finalize`, finalizing twice or squeezing before it panics |
| `falcon512::Poly` | 512 `u16` coefficients, word-aligned, coefficient `i` at index `i`: any 512 are a polynomial, read mod `q` |
| `falcon512::s1_norm(&Poly, &Poly, &Poly) -> u64` | the call over `h`, `s2` and `c` where they lie, its frame five words on the caller's stack: `‖s1‖²`, below `2^35` (§8); panics first unless the three arrays are apart |

`apogee_poseidon2_permute`, `apogee_mul_div_u256`, `apogee_merkle_root`, `apogee_keccak_f1600` and
`apogee_falcon512_s1_norm` are the C ABI's ([ecall-abi.md](ecall-abi.md) §7). Every frame is the
caller's own memory below the advice region (§1), a guest copying advice in before it permutes it;
a path's siblings and the lattice check's arrays are not a frame, and their calls read them in
place where they lie, the advice included (§6, §8). A digest decoded from advice or input, that the
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
call's timestamp, writes them back unchanged, and holds each to a word, two `RANGE16` halfwords, as
a load holds the word it reads. The bound is what lets them lie in the advice, whose init column
nothing bounds: unbounded, a pair of low word 0 and high word `2^−32` would hash as the lane 1
while a load of the low word reads 0, a lane no two words give. Bounded, a sibling's lane is the
one its two words give to every reader, taken mod `p`. So the siblings may lie anywhere a load
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
W   bit  w{j}_gap_c0 w{j}_gap_c1  w{j}_h16
level_range   stamp/256 ∈ [0, 2^16)              next_rule   next − stamp − 256
rest_rule     rest − bit − 2·rest_next           bit boolean
u{j}_rule     u_j − Σ_k (M_E[j][k]·n_k + M_E[j][8+k]·s_k) − bit·Σ_k (M_E[j][k] − M_E[j][8+k])·(s_k − n_k)
w{j}          read (RAM, ptr + 4j, read_ts_j, read_j), write (RAM, ptr + 4j, 4·cycle + FRAME_DELTA, read_j),
              the gap below it in [0, 2^38), and read_j a word: w{j}_h16 and read_j − 2^16·w{j}_h16
              each in [0, 2^16)
receive  (MERKLE, cycle, stamp + s, n_2s, n_2s+1), s < 4    (MERKLE, cycle, stamp + 8, rest, ptr)
send     (MERKLE, cycle, stamp + 16 + s, u_2s, u_2s+1), s < 8    (MERKLE, cycle, next + 8, rest_next, ptr + 64)
```

`s_k = read_2k + 2^32·read_2k+1` is the sibling's lane `k`, and `u` is `M_E(n ‖ s)` where the bit is
0 and `M_E(s ‖ n)` where it is 1, degree 2 with no column for either order. A word's address is
`ptr + 4j` in its leaves, `4j` mask terms (§1's parts) rather than a column. 113 committed columns,
97 obligations (128 leaves, 30 free), 21 and 25 leaves.

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

## 7. `keccak_f1600`

FIPS 202's Keccak-f[1600], 24 rounds, in place on the 50-word frame,
`constants::delegation::keccak`: lane `A[x][y]` is `i = x + 5y`, words `2i` (low) and `2i + 1`
(high), its byte `k` bits `8k..8k + 8`. Any 50 words are a state, so the emulator refuses no frame
but those §1 refuses. Round `t`, indices mod 5:

```text
theta    C[x] = ⊕_y A[x][y]    D[x] = C[x − 1] ⊕ rot1(C[x + 1])    A'[x][y] = A[x][y] ⊕ D[x]
rho, pi  B[y][2x + 3y] = A'[x][y] rotated left by ROTATIONS[y][x]
chi      A[x][y] = B[x][y] ⊕ (¬B[x + 1][y] ∧ B[x + 2][y])
iota     A[0][0] ⊕= ROUND_CONSTANTS[t]
```

**Bytes.** Every value a row holds of the state is a byte, and every byte operation one `XOR8`
lookup `(a, b, e)`, `e = a ⊕ b` ([lookup.md](lookup.md) §3): from it `a ∧ b = (a + b − e)/2` and
`¬a ∧ b = (b − a + e)/2` are linear, a byte splits at bit `8 − sh` against the mask
`2^(8 − sh) − 1`, and each of the three is bounded to a byte. A rotation by `8q + sh` splits each
byte and relabels the bytes by `q`; iota changes bytes 0, 1, 3 and 7 alone (`IOTA_BYTES`, every
round constant's other bytes 0, checked at compile time).

**The space**, `address_space::KECCAK = 7`: two bytes of the call at `cycle` are the tuple
`T(KECCAK, cycle, stamp, byte, byte)`. A group `g` takes the 32 stamps from `32g`
(`constraints::keccak::GROUP`): pair `i < 20` of a plane is lane `⌊i/4⌋`'s bytes `2(i mod 4)` and
`2(i mod 4) + 1`; a B-plane's slot `x` is its pairs `4x + m`, `m < 4`; a `KECCAK` parity group
holds the frame's base at its stamp 20 (`BASE`). `KECCAK(y)` is row `y` of a call's 8, and
`RHO(t, y)` and `CHI(t, y)` row `5t + y` of their 128:

```text
group g               holds                         written by                read by
5s + y, s ≤ 24        plane y of A_s                KECCAK(y) at s = 0,       RHO(s, y), or
                                                    else CHI(s − 1, y)        KECCAK(y) at s = 24
125 + 5t + y          D_t                           KECCAK(4) at (0, 0),      RHO(t, y)
                                                    CHI(t − 1, 4) at y = 0,
                                                    else RHO(t, y − 1)
245 + 5t + y          B-plane y of round t          RHO(t, x), slot x         CHI(t, y)
365 + 5t + y, y ≥ 1   CHI(t, < y)'s parity          CHI(t, y − 1)             CHI(t, y)
485 + y, y ≥ 1        KECCAK(< y)'s parity, base    KECCAK(y − 1)             KECCAK(y)
```

A row's stamps are committed columns, each held by a linear gate to its position through the plane
one-hot `y0..y4` and, in the expansions, the round one-hot `r0..r23` (`frame_stamps`,
`rho_stamps`, `chi_stamps`); a tuple adds its pair alone, below `GROUP`. A plane's tuples are its 20
pairs at `stamp + i`, its byte columns `{plane}{x}_{k}` lane `x`'s byte `k`.

### 7.1 `KECCAK`, the frame rows

Row `y < 5` is plane `y`: frame words `10y` to `10y + 9`, at `ra = base + 40y`.

```text
M   live cycle number base ra y0..y4 st_send st_recv st_pin st_pout pin pout
    w{j}_read_ts w{j}_read_value w{j}_write_value (j < 10)    in out p q d, 40 bytes each
W   w{j}_gap_c0 w{j}_gap_c1 room_h16 s (40 bytes)
one_y          Σ_v y_v − live, each y_v boolean      number_rule   number − 0x0513·live
ra_rule        ra − base − Σ_v 40v·y_v               st_*_rule     the stamps, frame_stamps(y)
pin_rule       pin − live + y0                       pout_rule     pout − live + y4, both boolean
room           (ADVICE_ORIGIN − 200)·live − base, a word
w{j}           the word at ra + 4j, read and written at 4·cycle + FRAME_DELTA, its gap in [0, 2^38)
in_w{j}        read_j − Σ_k 256^k·in[⌊j/2⌋][4(j mod 2) + k]      out_w{j}   write_j and out likewise
p_zero{x}_{k}  y0·p[x][k]                            parity{x}_{k}  XOR8 (p, in, q): q = p ⊕ in
rot{x}_{j}     XOR8 (0x7F·y4, q[x][j], s[x][j])      under y4
dxor{x}_{j}    XOR8 (2·(q[x+1][j] ∧ 0x7F) + (q[x+1][j−1] ≫ 7), q[x−1][j], d[x][j])     under y4
read   anchor (DELEGATION, base, cycle, number) under y0
       p at st_pin and the base at st_pin + 20, under pin       out at st_recv, CHI(23, y)'s plane
write  in at st_send, RHO(0, y)'s plane
       q at st_pout and the base at st_pout + 20, under pout    d at st_pout under y4, D_0
```

The running parity `q` is `C` at `y = 4`, and `rot`, `dxor` (`theta_d`) are
`D = C[x − 1] ⊕ rot1(C[x + 1])`: from `s = 0x7F ⊕ c`, `c ∧ 0x7F = (0x7F + c − s)/2` and
`c ≫ 7 = (c − 0x7F + s)/256`, so `rot1(C)`'s byte `j` is `C_j`'s low seven bits up one and
`C_{j−1}`'s top bit below them, a linear form at position 0. 309 committed columns, 42 `RANGE16`
obligations (64 leaves, 21 free) and 120 `XOR8` (128 leaves, 7 free), 52 and 71 leaves; at `2^16`,
8,192 calls a shard.

### 7.2 `KECCAK_RHO`

Row `5t + y`, rows 120–127 padding: source plane `y` of round `t`, theta's `D` applied, rho and pi.

```text
M   live cycle a d b (40 bytes each) st_a st_din st_dout st_b0..st_b4 dfwd
W   y0..y4 r0..r23 t s (40 bytes each)
one_y, one_r   Σ_v y_v − live, Σ_t r_t − live, each bit boolean
st_*_rule      the stamps, rho_stamps(t, y)                 dfwd_rule   dfwd − live + y4, boolean
theta{x}_{k}   XOR8 (a, d, t): t = A' = A ⊕ D[x]
split{x}_{k}   XOR8 (Σ_v y_v·m[x][v], t, s): s = m ⊕ t, m[x][v] = 2^(8 − sh) − 1
b{x}_{j}_rule  b − Σ_v y_v·(2^sh·lo_{j−q} + hi_{j−q−1}),  (q, sh) of ROTATIONS[v][x] = 8q + sh
               lo = (m + t − s)/2, hi = (t − m + s)/2^(9 − sh), byte indices mod 8
read   a at st_a, the plane; d at st_din, D_t
write  d at st_dout under dfwd, to RHO(t, y + 1)
       lane x's 8 bytes at st_b{x} + m, m < 4: B-plane 2x + 3y, slot y
```

`lo` and `hi` are a byte's low `8 − sh` and high `sh` bits; the mask, the shifts and the byte
indices are the plane's, so the rotation's gates are degree 2 through its bits. 241 committed
columns, 80 `XOR8` obligations (128 leaves, 47 free), 40 leaves a side; at `2^16`, 512 calls a
shard.

### 7.3 `KECCAK_CHI`

Row `5t + y`, rows 120–127 padding: B-plane `y` of round `t`, chi, iota on lane `(0, 0)`, the
running parity of the planes written, and at `y = 4` the next round's `D`, or at `t = 23` the
output.

```text
M   live cycle b p q a d (40 bytes each) st_b st_pin st_pout st_a pin pout dnext
W   y0..y4 r0..r23 e (40 bytes) c0_0 c0_1 c0_3 c0_7 s (40 bytes)
one_y, one_r     as §7.2's                      st_*_rule   the stamps, chi_stamps(t, y)
pin_rule         pin − live + y0                pout_rule   pout − live + y4
dnext_rule       dnext − y4 + y4·r23, each boolean
chi_e{x}_{k}     XOR8 (b[x+1], b[x+2], e): e = B[x+1] ⊕ B[x+2]
chi{x}_{k}       XOR8 ((b[x+2] − b[x+1] + e)/2, b[x], a): a = B[x] ⊕ (¬B[x+1] ∧ B[x+2]);
                 c0_k in a[0][k]'s place, k ∈ IOTA_BYTES
iota{k}          XOR8 (Σ_t r_t·RC_t[k], c0_k, a[0][k]) under y0
iota_keep{k}     (live − y0)·(a[0][k] − c0_k)
p_zero{x}_{k}    y0·p[x][k]                     parity{x}_{k}  XOR8 (p, a, q)
rot, dxor        §7.1's, under dnext: D_{t+1} from C = q
read   b's lane x at st_b + 4x + m, m < 4; p at st_pin under pin
write  a at st_a, the plane A_{t+1}[·][y]
       q at st_pout under pout; d at st_pout under dnext, D_{t+1}
```

323 committed columns, 204 `XOR8` obligations (256 leaves, 51 free), 40 and 60 leaves; at `2^16`,
512 calls a shard.

### 7.4 Why the rows are one permutation

The space's reads and writes are equal multisets: nothing initializes it and no final reads it. A
row's position, `y` or `(t, y)`, is pinned by its one-hots, each stamp to the exact integer its
position names and each mask (`pin`, `pout`, `dfwd`, `dnext`) to its bit, and the groups are
disjoint, so the key `(cycle, stamp)` of a live tuple names one group and one pair: one kind of row
(a family and a position) writes it, once a row, and one kind reads it, once a row. Equal multisets
then give every key at a cycle as many writing rows as reading ones, so two kinds a group joins
have equally many rows there. The groups join every kind to `KECCAK(0)`: its parity chain to
`KECCAK(1..4)`, the planes to `RHO(0, ·)`, `D_0` to `RHO(0, 0)` and its chain to `RHO(0, 1..4)`, the
B-planes to `CHI(0, ·)`, and so on round by round to `CHI(23, ·)`, whose planes `KECCAK(·)` reads. A
`KECCAK(0)` row is its anchor's, one a requesting cycle (§2), so at a call's cycle there is exactly
one row of each kind and at any other cycle none: every key is written once and read once, and its
reader holds what its writer wrote. The base rides the parity chain, so row `y` accesses the words
at `base + 40y + 4j`, the frame's fifty once each at the call's timestamp, and `room` holds them
below `ADVICE_ORIGIN`.

Each row computes its step exactly. `XOR8` bounds every byte a row reads or computes, so
`A' = A ⊕ D` byte by byte; the split's `lo` and `hi` are a byte's low and high bits and `B` the lane
rotated; chi's `¬B[x+1] ∧ B[x+2]` and every parity are the byte operations, `D` is
`C[x − 1] ⊕ rot1(C[x + 1])`, and iota XORs round `t`'s constant. A frame row holds each word to its
four bytes, exact since a byte is below `2^8` and a word below `2^32 < p`, so the words written are
words. `KECCAK(y)` writes plane `y` of Keccak-f[1600] of the frame it read.

### 7.5 The trace

A call is one entry in each of `KECCAK`, `KECCAK_RHO` and `KECCAK_CHI`, its 50 words and no carry:
every row of a call is a function of its words, so a shard holds whole calls, and
`trace::TraceArchive` checks `KECCAK`'s words against the log as a frame's.

## 8. The Falcon-512 lattice check

The lattice check of Falcon-512 verification over `Z_q[x]/(x^512 + 1)`, `q = 12289`
(`constants::delegation::falcon`): from the public key `h`, the signature's half `s2` and the
hashed message `c`, `s1 = (c − s2·h) mod (q, x^512 + 1)` with each coefficient centered to
`[−6144, 6144]`, and `n = ‖s1‖²`. The frame:

```text
word 0   h      the address of h's array
word 1   s2     the address of s2's array
word 2   c      the address of c's array
word 3   n_lo   n's low word, written
word 4   n_hi   n's high word, below 2^16, written
```

An array is 256 words, 512 `u16` coefficients: coefficient `2i` is word `i`'s low halfword and
`2i + 1` its high one, every one read mod `q`. **No value is refused**: any three arrays have an
`s1`, and `n < 512·6144² < 2^35`. **The caller owes** the layout alone: word-aligned arrays,
disjoint from each other and from the frame, which the emulator refuses otherwise as
`EmuError::DelegationFrame`, each word one a load could read, else `OutOfBounds`; neither has a
witness. **The arrays are not the frame.** `FALCON_SPLIT` reads their words at the call's
timestamp, writes them back unchanged and holds each to a word as a load does, so an array may lie
anywhere a load reaches, the advice included.

**The CRT.** `ζ = 11^384 mod q` is a primitive 32nd root of unity, 11 generating `Z_q*`, of order
`12288 = 32·384`. The `β_r = ζ^(2r + 1)`, `r < 16`, are the sixteen distinct roots of `y^16 + 1`,
checked at compile time, so `x^512 + 1 = Π_r (x^32 − β_r)`, coprime factors over `Z_q`
(`constraints::falcon::{ZETA, BETA}`). Since `x^32 ≡ β_r` modulo `x^32 − β_r`, residue `r` of a
polynomial `a` has coefficient `j < 32` equal to `Σ_{m<16} V[r][m]·a_{32m + j}`,
`V[r][m] = β_r^m mod q` (`V`). Coefficients `32m + 2j` and `32m + 2j + 1` are an array's word
`16m + j`, at `ptr + 64m` for `ptr` its word `j`'s address: those sixteen words give coefficients
`2j` and `2j + 1` of every residue.

**The space**, `address_space::FALCON = 8`, two kinds of tuple:

```text
T(FALCON, cycle, σ, ptr, acc)                       a chain's control at stamp σ
T(FALCON, 64·cycle + place(P, j), r, rr_0, rr_1)    split row (P, j)'s residue pair r < 16
```

The chains `P = 0, 1, 2` are `s2`, `h`, `c` (`delegation::falcon::CHAINS`). Chain `P` takes the
stamps `start(P) = 16 + 17P` to `start(P) + 16`, and `place(P, j) = 17P + j < 64`
(`constraints::falcon::{start, place, KEY}`). `SPLIT(P, j)` is row `16P + j` of a call's 64 in
`FALCON_SPLIT`, rows 48–63 padding, and `PRODUCT(r)` row `r` of its 16 in `FALCON_PRODUCT`:

```text
tuple      written by                           read by
control    FALCON, σ = start(P)                 FALCON, σ = start(P) + 16
           SPLIT(P, j), σ = start(P) + j + 1    SPLIT(P, j), σ = start(P) + j
residue    SPLIT(P, j), r < 16                  PRODUCT(r)
```

### 8.1 `FALCON`, the frame row

```text
frame        5 words (§1), words 3 and 4 written
n_lo         write_3 a word                    n_hi_range   write_4 ∈ [0, 2^16)
n_rule       n − write_3 − 2^32·write_4        st{P}_rule   st_P − start(P)·live
write  (FALCON, cycle, st_P, ptr_P, 0)         ptr_P the read of frame word CHAINS[P]
read   (FALCON, cycle, st_P + 16, end_P, 0), P = s2, h      (FALCON, cycle, st_2 + 16, end_2, n)
```

`end_P` is free: the chain's last row sent `ptr_P + 64`. 40 committed columns, 25 obligations (the
`RANGE16` tree at 32 leaves, 6 free), 9 and 8 leaves.

### 8.2 `FALCON_SPLIT`

Row `(P, j)`, its stamp `σ = start(P) + j`: column `j` of chain `P`.

```text
M   live cycle stamp key ptr acc acc_out a1..a15 w{m}_read_ts w{m}_read_value (m < 16) rr{r}_{e}
W   w{m}_gap_c0 w{m}_gap_c1 w{m}_h16 s{m}_{e} kk{r}_{e} kk{r}_{e}_h16              r < 16, e < 2
stamp_range  σ − 16 ∈ [0, 2^16)                  key_rule   key − 64·cycle − σ + 16
a{m}_rule    a_m − ptr − 64m·live, m ≥ 1         a_0 = ptr
w{m}         read (RAM, a_m, read_ts_m, read_m), write (RAM, a_m, 4·cycle + FRAME_DELTA, read_m),
             its gap in [0, 2^38), and read_m a word: v_{m,1} = w{m}_h16, v_{m,0} = read_m − 2^16·v_{m,1}
s{m}_{e}     s_{m,e} + 6144 and 6144 − s_{m,e} each in [0, 2^16)
acc_rule     acc_out − acc − Σ_{m,e} s_{m,e}²
res{r}_{e}   Σ_m V[r][m]·(v_{m,e} − s_{m,e}) − rr_{r,e} − q·kk_{r,e}
kk{r}_{e}    kk_{r,e} + 2^31 a word
read   (FALCON, cycle, σ, ptr, acc)
write  (FALCON, cycle, σ + 1, ptr + 4, acc_out)     (FALCON, key, r, rr_{r,0}, rr_{r,1}), r < 16
```

No column says which chain a row is: the frame row ends `s2`'s and `h`'s at `acc = 0`, which holds
their `s` to 0, and takes `c`'s as `n`. 231 committed columns, 225 obligations (256 leaves, 30
free), 17 and 33 leaves; at `2^16`, 1,024 calls a shard.

### 8.3 `FALCON_PRODUCT`

Row `r`: residue `r`, its one-hot bit `o_r`.

```text
M   live r base0 base1 base2 a0..a31 b0..b31 d0..d31
W   o0..o15 wrap0..wrap30 w{k}_c0 w{k}_c1 w{k}_c2 (k < 32)
one_o         Σ_i o_i − live, each o_i boolean       r_rule   r − Σ_i i·o_i
base{P}_rule  base_P − base_0 − 17P·live, P ≥ 1
{a,b,d}{i}    ∈ [0, 2^16)
wrap{k}_rule  W_k − Σ_{i+j=k+32} a_i·b_j, k < 31
prod{k}       Σ_{i+j=k} a_i·b_j + (Σ_i β_i·o_i)·W_k − d_k − q·Σ_c 2^16c·w_{k,c}, no W_31
w{k}_c{c}     ∈ [0, 2^16), c < 3
read   (FALCON, base_P + j, r, x_{2j}, x_{2j+1}), j < 16, x = a, b, d for P = s2, h, c
```

245 committed columns, 192 obligations (256 leaves, 63 free), 48 and 0 leaves; at `2^16`, 4,096
calls a shard.

### 8.4 Why every key is written once and read once

The space's reads and writes are equal multisets: nothing initializes it and no final reads it.

*Controls and residues never meet.* A split row bounds `σ − 16`, so its controls' timestamps `σ`
and `σ + 1` lie in `[16, 2^16 + 17)`, as the frame row's `16` to `66` do, while a residue's is
`r < 16`: a literal in a split row, the one-hot's integer in a product row.

*The split rows are the chains.* Fix an address `A` and let `n_t` count the split rows of cycle `A`
and stamp `t`. At `(A, t)` the writes are the frame row's start at `t`, if any, and the `n_{t−1}`
rows before; the reads its end at `t` and the `n_t` rows at `t`. So
`n_t = n_{t−1} + [t a start] − [t an end]`, with `n_t = 0` below 16. A frame row is its anchor's,
one a requesting cycle (§2): at any other `A` there is no start and no end and `n` is 0
throughout, and at a call's cycle the starts `16, 33, 50` and ends `32, 49, 66` give `n_t = 1` on
`start(P) + j`, `j < 16`, and 0 elsewhere. Every split row is one position `(P, j)` of one call, its
`cycle` the requesting ecall's, an integer below `2^36`; every control key is written once and read
once, so row `(P, j)` receives what row `(P, j − 1)` sent: `ptr = ptr_P + 4j` and the running `acc`.

*The product rows are the residues.* A split row's key `64·cycle + place` names its call and
position, `place < 64`, so each residue key is written once. A product row of one-hot `r` reads
`(base_0 + ρ, r)` for every place `ρ`; its read at `ρ = 0` is written, so `base_0 = 64·c + u` for a
call `c` and a place `u`. Were `u ≠ 0`, some place `ρ` would put `(u + ρ) mod 64` where no call
writes (`falcon::NO_SHIFT`, checked at compile time). So `base_0 = 64·c`, the row reads exactly call
`c`'s 48 pairs of residue `r`, and since each is written once there is exactly one product row per
call and residue.

### 8.5 Why the rows are the check

Row `(P, j)` reads the words `ptr_P + 4j + 64m`, `m < 16`: each array's 256 words once each, at the
call's timestamp, written back unchanged. An array overlapping another or the frame would access a
word twice at one timestamp, which no memory history allows. Each word is bounded as a load bounds
the word it reads, so the coefficients are its halfwords, each below `2^16`, read mod `q`.

A split identity's sum is below `2^34` in size, `rr` is below `2^16` at its reader and
`kk ∈ [−2^31, 2^31)`, so it holds over the integers and `rr_{r,e} ≡ Σ_m V[r][m]·(v_{m,e} − s_{m,e})`
mod `q`: coefficient `2j + e` of residue `r` of `array_P − s`. Each chain's `acc` sums its rows'
`Σ s²`, below `512·6144² < 2^35`: the frame ends `s2`'s and `h`'s at the literal 0, so their `s` are
all 0, and `c`'s at `n = n_lo + 2^32·n_hi`, which with `n_lo` a word and `n_hi` below `2^16` is that
sum's integer, written as its two words. So `a`, `b` and `d` are residue `r` of `s2`, `h` and
`c − s1`, `s1` the coefficients chain `c` holds, each in `[−6144, 6144]`, and `n = ‖s1‖²`.

A product identity's left side is below `2^51` in size and `q·w_k` below `2^62`, so it holds over
the integers: `a·b ≡ d` mod `(x^32 − β_r, q)`. By the CRT, `s2·h ≡ c − s1` mod `(q, x^512 + 1)`. A
coefficient in `[−6144, 6144]` is its class's centered representative, `q = 2·6144 + 1`: `s1` is
the centered `(c − s2·h) mod q`, and `n` its squared norm.

### 8.6 The trace

A call is one `FALCON` entry, its frame, and one entry in each of `FALCON_SPLIT` and
`FALCON_PRODUCT`, its arrays (`constants::delegation::Per::Arrays`): `falcon::ARRAYS = 768` words in
`CHAINS` order, chain `P`'s word `i` entry word `256P + i`, at the address frame word `CHAINS[P]`
holds plus `4i`, accessed at the call's timestamp after the frame's and written back unchanged; its
base is `s2`'s array. It carries nothing: every row of it is a function of its words, so a shard
holds whole calls, and `trace::TraceArchive` checks `FALCON_SPLIT`'s words against the log as it
does a frame's.
