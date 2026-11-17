# The precompiles

The delegation calls: an `ecall` that hands a frame of RAM words to a circuit other than the CPU's,
the request and the invocation paired through the memory multiset. Four are registered, the
Poseidon2-A64-C5 permutation, `mul_div_u256`, `merkle_root` and the Falcon-512 lattice check.
`constants::delegation::TYPES` is the registry; this page is the mechanism (§1, §2), the calls'
circuits (§3, §4, §6, §7) and the SDK over them (§5; Falcon-512's HashToPoint, §7.7).

The VM has no Keccak precompile. A bitwise hash is inefficient to prove: in a 254-purchase
`guests/amazon` proof, Keccak's three families took 25.8% of shard time against Poseidon2's 5.3%.
A scheme that specifies SHAKE or SHA-3 has its hashing replaced by a Poseidon2-A64-C5
construction, as Falcon-512's HashToPoint is (§7.7). Restoring Keccak is a negative choice.

## 1. The mechanism

| number | family | id | an entry | words | rows | channels |
| --- | --- | --- | --- | --- | --- | --- |
| `0x0510` | `POSEIDON2` | 12 | a call | 32 | 1 | `RANGE16` |
| `0x0510` | `POSEIDON2_ROUNDS` | 13 | a call | 32 | 16 | none |
| `0x0511` | `MUL_DIV_U256` | 14 | a call | 24 | 1 | `RANGE16` |
| `0x0512` | `MERKLE_ROOT` | 15 | a call | 19 | 1 | `RANGE16` |
| `0x0512` | `MERKLE_LEVELS` | 16 | a level | 16 | 1 | `RANGE16` |
| `0x0512` | `MERKLE_ROUNDS` | 17 | a level | 16 | 16 | `RANGE16` |
| `0x0514` | `FALCON` | 21 | a call | 5 | 1 | `RANGE16` |
| `0x0514` | `FALCON_SPLIT` | 22 | the arrays | 768 | 64 | `RANGE16` |
| `0x0514` | `FALCON_PRODUCT` | 23 | the arrays | 768 | 16 | `RANGE16` |

A call is one cycle of `ADD_SUB_LUI_AUIPC`: `a7` the number, `a0` the frame's word-aligned base,
both preserved; the row writes no register and falls through. Each family of the number records
every entry of its kind (`constants::delegation::Per`): the call, or for `MERKLE_ROOT`'s later two
families each level of the call's path (§6), or for `FALCON512`'s later two the call's three arrays
(§7). The first is its **frame family**, whose row reads and writes every frame word at the
requesting cycle's `4·cycle + FRAME_DELTA`, `FRAME_DELTA = 0`, and reads the anchor (§2); the first
level family, `MERKLE_LEVELS`, reads its level's sibling at the same timestamp, and the first
arrays family, `FALCON_SPLIT`, the arrays' words; a later family expands an entry into rows of its
own, holding its words in its buffer and reaching no memory but its own address space. An entry's
rows are a block of a power of two, the rows past its live ones all zero, padding:
`FALCON_SPLIT`'s 64 hold 48 (§7). A delegation family owns no cycle and claims no pc: it is in a
`VmConfig` exactly when the image declares its number ([program.md](program.md) §7), and it plans
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
direct bound); `cycle` is the request's, through the anchor, so every gap holds over the integers
([memory.md](memory.md) §4.2).
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
| `U256` | four `u64` limbs; `+ − * / %` panic on overflow and a zero divisor, `checked_*`, `overflowing_*`, `wrapping_*` do not; `<< >> & \| ^ !`, `Ord`, bytes in either order |
| `U256::mul_div_rem`, `mul_div`, `div_rem` | the call; `None` where the caller's precondition fails, checked first: `d = 0`, or the high half of `a·b`, skipped when both are below `2^128`, at or above `d` |
| `merkle_root(slot, &Digest, siblings: &[u8]) -> Digest` | the call over a path of `siblings.len() / 64` siblings where they lie; panics first where its precondition fails (§6) |
| `Digest::bytes(&[Digest]) -> &[u8]` | a path the guest holds, as `merkle_root` takes it |
| `falcon512::Poly` | 512 `u16` coefficients, word-aligned, coefficient `i` at index `i`: any 512 are a polynomial, read mod `q` |
| `falcon512::s1_norm(&Poly, &Poly, &Poly) -> u64` | the call over `h`, `s2` and `c` where they lie, its frame five words on the caller's stack: `‖s1‖²`, below `2^35` (§7); panics first unless the three arrays are apart |
| `falcon512::Q`, `SQBETA`, `PUBLIC_KEY_BYTES`, `SIGNATURE_BYTES` | `q = 12289`; `⌊β²⌋ = 34,034,726`, the most `‖s1‖² + ‖s2‖²` a signature verifies at; 897 and 666, a key's bytes and a signature's |
| `falcon512::PublicKey::decode(&[u8]) -> Option<PublicKey>` | the key `h` from exactly 897 bytes, v1.2 of the specification: the header `0x09`, then its 512 coefficients in order, 14 bits each, packed big-endian, each below `q`; `None` for any other bytes, so a key has one encoding. A key that decodes then has K computed from the same bytes and HashToPoint's per-key prefix from K (§7.7), both kept with `h` |
| `falcon512::key_digest(&[u8]) -> Digest`, `falcon512::address(&[u8]) -> [u8; 32]` | K and the address (§7.7) of any bytes, a key that does not decode included |
| `falcon512::PublicKey::key_digest(&self) -> &Digest`, `falcon512::PublicKey::address(&self) -> [u8; 32]` | the key's K and address, computed once by `decode` |
| `falcon512::PublicKey::verify(&self, msg: &[u8], sig: &[u8], context: &[u8]) -> bool` | whether `sig` is a v1.2 padded signature of `msg` under the key and `context`: `context` at most 255 bytes; `sig` exactly 666 bytes, the header `0x39`, the 40-byte salt, then `s2` compressed, each coefficient a sign bit, the low 7 bits of its size, then that size `>> 7` zeros and a one, and zeros to the end; `false` for any other bytes, among them a coefficient `−0`, one above 2047 in size or one reaching past the end, and a one bit after the 512th. `c` is HashToPoint (§7.7) of K, the salt, `context` and `msg`, from the key's prefix; it verifies exactly when `s1_norm(h, s2, c) + ‖s2‖² ≤ SQBETA` |

`apogee_poseidon2_permute`, `apogee_mul_div_u256`, `apogee_merkle_root` and
`apogee_falcon512_s1_norm` are the C ABI's ([ecall-abi.md](ecall-abi.md) §7). Every frame is the
caller's own memory below the advice region (§1), a guest copying advice in before it permutes it;
a path's siblings and the lattice check's arrays are not a frame, and their calls read them in
place where they lie, the advice included (§6, §7). A digest decoded from advice or input, that the
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

## 7. The Falcon-512 lattice check

The lattice check of Falcon-512 verification over `Z_q[x]/(x^512 + 1)`, `q = 12289`
(`constants::delegation::falcon`): from the public key `h`, the signature's half `s2` and the
hashed message `c` (§7.7), `s1 = (c − s2·h) mod (q, x^512 + 1)` with each coefficient centered to
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

### 7.1 `FALCON`, the frame row

```text
frame        5 words (§1), words 3 and 4 written
n_lo         write_3 a word                    n_hi_range   write_4 ∈ [0, 2^16)
n_rule       n − write_3 − 2^32·write_4        st{P}_rule   st_P − start(P)·live
write  (FALCON, cycle, st_P, ptr_P, 0)         ptr_P the read of frame word CHAINS[P]
read   (FALCON, cycle, st_P + 16, end_P, 0), P = s2, h      (FALCON, cycle, st_2 + 16, end_2, n)
```

`end_P` is free: the chain's last row sent `ptr_P + 64`. 40 committed columns, 25 obligations (the
`RANGE16` tree at 32 leaves, 6 free), 9 and 8 leaves.

### 7.2 `FALCON_SPLIT`

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

### 7.3 `FALCON_PRODUCT`

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

### 7.4 Why every key is written once and read once

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

### 7.5 Why the rows are the check

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

### 7.6 The trace

A call is one `FALCON` entry, its frame, and one entry in each of `FALCON_SPLIT` and
`FALCON_PRODUCT`, its arrays (`constants::delegation::Per::Arrays`): `falcon::ARRAYS = 768` words in
`CHAINS` order, chain `P`'s word `i` entry word `256P + i`, at the address frame word `CHAINS[P]`
holds plus `4i`, accessed at the call's timestamp after the frame's and written back unchanged; its
base is `s2`'s array. It carries nothing: every row of it is a function of its words, so a shard
holds whole calls, and `trace::TraceArchive` checks `FALCON_SPLIT`'s words against the log as it
does a frame's.

### 7.7 HashToPoint

Falcon-512 here is v1.2's (the NIST round-3 specification), its keys, encodings, signer and
acceptance rule, in all but HashToPoint, the map to the point `c`: not SHAKE256 of the salt (v1.2's
nonce `r`) and the message but a sponge over `P`, the Poseidon2-A64-C5 permutation (§3), of the
key digest K, the salt, the application's context and the message. K is a sponge over the key's
bytes, and the key's address is K's first 32 bytes. The SDK's `falcon512` computes both over
`poseidon2_permute` (§5).

The sponge is [transcript.md](transcript.md) §2's duplex from the zero state: rate lanes 0–7,
capacity 8–15, no padding, absorbing overwrites the next rate lane, permuting first when the rate
is full. A field `(tag, bytes)` absorbs the tag, the length in bytes, then the bytes seven to a
lane, little-endian, the last chunk shorter, so every lane is below `2^56 < p`. The squeeze stream
permutes, then reads rate lanes 0–7 in order, and again; a rate lane the last absorb did not write
keeps its value.

```text
KEY_DOMAIN        the 13 ASCII bytes "apogee/key/v1"
SCHEME_ID         the 22 ASCII bytes "falcon512-poseidon2/v1"
SIGNATURE_DOMAIN  the 33 ASCII bytes "apogee/falcon512/hash-to-point/v1"
T                 ⌊p / q^4⌋·q^4 = 808·q^4 = 0xFFBD4EAA725E0328; (p − T)/p ≈ 1.0177·10^−3

K(pk)             field(1, KEY_DOMAIN), field(2, SCHEME_ID), field(3, pk); the stream's first
                  8 lanes, 64 bytes as each lane's u64 little-endian
address(pk)       K(pk)'s first 32 bytes: lanes 0–3
HashToPoint(pk, salt, context, msg)
                  field(1, SIGNATURE_DOMAIN), field(2, K(pk)), field(3, salt), field(4, context),
                  field(5, msg); then each lane x of the stream: x ≥ T is skipped, and x < T is
                  the next four coefficients, ⌊x / q^j⌋ mod q for j = 0, 1, 2, 3, until 512
```

`pk` is the exact 897-byte key the signature is verified under: a verifier computes K from the
bytes it decodes `h` from. `salt` is the signature's 40 bytes after its header. `context` is the
application's, 0 to 255 bytes, FIPS 204's and 206's convention: a signer refuses a longer one and
verification is false for it, and a signature under one context does not verify under another. K
is defined for any bytes, a key that does not decode included. The address is the key's name in a
guest's state (`guests/amazon`), 256 bits, each of its four lanes below `p`.

**The per-key prefix.** For an 897-byte key K is 141 lanes, 17 permutations absorbing and one to
squeeze, and `(1, SIGNATURE_DOMAIN)` and `(2, K)` are 7 + 12 = 19 lanes, 2 permutations, leaving
three rate lanes written. Every signature under the key continues from that state, so `PublicKey::decode`
computes K and the prefix once. A 92-byte message under a 25-byte context is then 30 lanes, 4
permutations, and the squeeze 16, one more when a lane among the first 128 is skipped, with
probability `1 − (1 − 1.0177·10^−3)^128 ≈ 12.2%`.

**Why `c` is uniform.** In the sponge's model the stream's lanes are independent and uniform on
`[0, p)`. A lane below `T` is then uniform on `[0, 808·q^4)`, so its four low base-`q` digits are
uniform on `Z_q^4` and independent of the rest of it, and a lane at or above `T` is skipped,
rejection rather than reduction, so no residue is favored: `c` is exactly uniform on `Z_q^512`, the
distribution v1.2's security argument takes HashToPoint's output to have. The stream is squeezed
from the sponge that absorbed the salt, the context and the message, with no fixed-width digest
between them for distinct inputs to collide in; the key enters as K, eight lanes, so two keys
share a stream only through a collision of K's sponge, whose capacity is eight lanes. Each framing
is injective, each field its tag, its length and whole lanes in a fixed order, so distinct
`(K, salt, context, msg)` are distinct lane sequences, and the first field, `KEY_DOMAIN` or
`SIGNATURE_DOMAIN`, separates each sponge from the other and from every other over `P`.

**Interoperability.** Keys and signatures are v1.2's encodings, and a key from v1.2's keygen is a
key here, but a signature is not interchangeable with standard Falcon-512's: a standard signature
does not verify under this HashToPoint, nor the reverse. `tools/falcon512` holds the host
implementations, Rust, JavaScript and Python, which sign and verify under it, and `vectors.json`,
the vectors all three agree on, whose signatures the SDK's verifier is held to.
