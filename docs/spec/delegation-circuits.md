# The delegation circuits

The circuits of the six delegation families the base format registers
([recursion.md](recursion.md) §1.2): `KECCAK_F`, `POSEIDON2`, `FR_ARITH`, `MOD_MUL`, `SHA256_COMP`,
`EC_ADD`. A row is one invocation of a function of a frame of guest memory. For each circuit: its
frame, columns, gates and lookups, and why it admits that function and no other. The call, the
anchor's pairing, declaration and heights are [delegation.md](delegation.md)'s.

## 1. Shared constructions

Each circuit is `constraints::delegation`'s frame over `words` frame words beside the family's
function. None has a setup column; its only tables are its channels' virtual ones
([lookup.md](lookup.md) §3). `live` is the one mask, boolean by `live_boolean` and every lookup's
selector. A padding row is all zero and satisfies every gate, a constant term riding `live`
([gkr.md](gkr.md) §4).

```text
M[0..4]        cycle  live  base  anchor_value
M[4 + 4j ..]   word j: addr_j  read_ts_j  read_j  write_j        w{j}_addr … w{j}_write_value
```

**Frame chain.** Each word is read and written once at a pinned address, as two RAM leaves over
[memory.md](memory.md) §1's tuple `T`, from `M` columns because a leaf reads no `W`
([memory.md](memory.md) §8):

```text
read_w{j}        live·T(RAM, addr_j, read_ts_j, read_j) + 1 − live
write_w{j}       live·T(RAM, addr_j, 4·cycle, write_j) + 1 − live
addr_w{j}        live·(addr_j − base − 4j) = 0
base_aligned     live·(base − RAM_ORIGIN − 4·base_low) = 0          base_low  < 2^29
base_in_window   live·(2^31 − 4·words − base − base_room) = 0       base_room < 2^31
```

The bounds are [delegation.md](delegation.md) §4's frame rules, alignment a decomposition because 4
is a unit of `Fr`. A word the call leaves alone is held by `writes_back_w{j}`, `write_j = read_j`;
every other written word is bounded below `2^32` by its circuit. A frame lies in RAM proper
([delegation.md](delegation.md) §4), which starts as the image's words or 0 and which every writer
— an execution family ([memory-ops.md](memory-ops.md) §5), a frame, `FIELD_IO`'s export
([recursion.md](recursion.md) §5) — leaves holding words, so a frame word a circuit reads is a word
without a bound of its own.

**Anchor read.** Two leaves in the family's address space `s` ([delegation.md](delegation.md) §5)
pair the row with its request: it writes the answer `T(s, base, 0, 0)` and reads
`T(s, base, 4·cycle + 3, anchor_value)`, what the request wrote back; `anchor_value` is free. That
makes `words + 1` leaves a side, padded with literal 1s to a power of two.

**Gap decomposition.** Each read precedes the row's write: `gap_j = 4·cycle − 1 − read_ts_j` is in
`[0, 2^38)`. `TIMESTAMP` would need a `2^20` shard ([lookup.md](lookup.md) §3), so the frame bounds
its gaps, `base_low` and `base_room` itself, at the head of `W`:

- **bit form**, at `2^8`, where no table fits: 38 booleans a word, `gap{j}_{i}`, under `gap_w{j}`,
  `live·(gap_j − Σ_i 2^i·g_i) = 0`, and 29 and 31 for `base_low` and `base_room`: `38·words + 60`
  columns, each with its booleanity gate.
- **chunk form**, at `2^16` and above, with no gate: a bound `x ∈ [0, 2^{16q+r})`, `0 < r < 16`,
  is `q` committed chunks `c_k` of weight `2^{16(k+1)}`, a `RANGE16` obligation on each and on the
  remainder `x − Σ_k 2^{16(k+1)}·c_k`, and one on `2^{16−r}·c_top`, which bounds only beside the
  chunk's direct one ([lookup.md](lookup.md) §11). A gap (`r = 6`) is `gap{j}_c0` and `gap{j}_c1`;
  `base_low` and `base_room` (`r` = 13, 15) take `base_low_hi` and `base_room_hi`: `2·words + 4`
  columns and `4·words + 6` obligations.

The frame's gates are `live_boolean`, the `addr_w{j}`, `base_aligned` and `base_in_window`,
`words + 3`, and in the bit form the `gap_w{j}` and each bit's booleanity besides.

**Canonicity chain.** A value `X` in limbs `x_0 … x_7 < 2^32` is compared with a modulus `m`,
limbs `m_i < 2^32`, through boolean borrows `β_i` and differences `d_i ∈ [0, 2^32)`:

```text
<v>_canonical{i}    x_i − m_i − β_{i−1} + 2^32·β_i − d_i = 0        i = 0 … 7, β_{−1} = 0
```

Every term is a small integer, so the eight sum over ℤ to `X − m + 2^256·β_7 = D`, `0 ≤ D < 2^256`:
`β_7 = 1` exactly when `X < m`. Against `Fr`'s `p` (§3, §4) the `m_i` are literals, `x_i − p_i`
rides `live` and each `d_i` is 32 booleans; against a selected modulus (§5, §7) the `m_i` are
columns, 0 on a padding row, and each `d_i` has a 32-bit bound ([memory.md](memory.md) §7).

**Gated conclusion.** The chain's last gate, `<v>_below_modulus`, is `live − β_7 = 0` where every
live row reads `X`; where only rows with `enable = 1` read it, it is the gated conclusion
`enable·(1 − β_7) = 0`. `β_7 = enable` would demand `X ≥ m` wherever `enable = 0`, so a row
holding a reduced `X` it does not read would have no witness.

**One-code rule.** A frame word naming one of `k` cases is decoded into boolean selectors `s_c` by
`word − Σ_c code_c·s_c = 0` and `Σ_c s_c − live = 0`. The second is not implied: a code 0 has no
selector set and a code that is a sum of two has two (`1 + 2 = 3`), mixing cases. With both, the
word and any column pinned to `Σ_c lit_c·s_c` are one entry of a table of literals, selected and
bounded by a degree-1 gate.

**Byte operations.** Where the unit is the byte (§2, §6), each Boolean operation is one `XOR8`
obligation `(e_0, e_1, e_2)`, `e_2 = e_0 ^ e_1` with all three bytes ([lookup.md](lookup.md) §3):
`e_1` and `e_2` columns, `e_0` any literal-weighted form with a constant ([lookup.md](lookup.md)
§5). The rest is linear in the results: `a & b = (a + b − (a ^ b))/2`,
`¬a & b = (b − a + (a ^ b))/2`; against a literal `k`, `v & k = (v + k − (v ^ k))/2` splits a byte
at any bit, so a rotation or shift of a word held as bytes is a literal-weighted form over its
bytes and their masked copies; and `(0, c, c)` bounds `c` to a byte. On true bytes and true XORs
each form is exact over ℤ, so its value is the integer it denotes.

**RAM glue.** An operation too wide for a row is several invocations on one frame, a frame word
naming the step (§2, §6, §7). Each proves its step on the frame as it finds it: its reads lie on
each word's one history ([memory.md](memory.md) §9), so it reads the previous step's writes unless
the guest wrote there between. No gate joins two rows, and a shard boundary may fall between them.
That every step runs, in order, is the calling code's, which the execution families prove.

## 2. `KECCAK_F`

One invocation is one round of keccak-f[1600]; a permutation is 24 on one frame, the sponge and
padding being guest code. The circuit, `constraints::keccak`, is flat, every gate in gate list 0,
and its unit is the byte (§1): no column is a bit but `live` and the 24 round selectors.

### 2.1 Frame and columns

51 words (`constants::keccak`; `M[0..208]`), the state in SHA-3 byte order: lane `A[x][y]`,
`i = 5y + x`, at words `1 + 2i` (low half) and `2 + 2i`. `A[i][b]` is its byte `b`; lane
coordinates are mod 5.

| word | | read | written |
| --- | --- | --- | --- |
| 0 | the round `r ∈ [0, 24)` | yes | unchanged |
| 1–50 | the state | yes | the round's output |

| `W` | name | |
| --- | --- | --- |
| `0..106` | | the frame's chunks (§1) |
| `106..130` | `round_sel{r}` | `s_r`, one a round |
| `130..134` | `rc_b{b}` | `rc_t`, byte `b_t` = 0, 1, 3, 7 of the round's constant |
| `134..334` | `state_in_l{i}_b{b}` | `A` |
| `334..494` | `parity_x{x}_b{b}_s{s}` | column `x`'s lanes XORed in four steps, the last `C[x]` |
| `494..574` | `c_mask_…`, `theta_d_…` | `C ^ 0x80`; `D` |
| `574..774` | `theta_a_…` | `A′ = A ^ D` |
| `774..950` | `rho_mask_…` | `A′ ^ mask` on the 22 lanes not rotated by whole bytes |
| `950..1150` | `rho_out_…` | `B`, after ρ and π |
| `1150..1550` | `chi_and_…`, `chi_out_…` | `B1 ^ B2`; χ's output |
| `1550..1554` | `iota_out_b{b}` | lane 0's bytes `b_t` after ι |
| `1554..1556` | | the multiplicities |

### 2.2 Gates and obligations

385 gates; `O` is `chi_out`, but `iota_out` at lane 0's bytes `b_t`; `r_xy = ROTATIONS[y][x]`.

| gate | count | expression |
| --- | --- | --- |
| the frame's (§1) | 54 | |
| `round{r}_boolean` | 24 | `s_r − s_r²` |
| `round_rule` | 1 | `read_0 − Σ_r r·s_r` |
| `one_round_a_live_row` | 1 | `Σ_r s_r − live` |
| `rc{t}_rule` | 4 | `rc_t − Σ_r s_r·(byte b_t of ROUND_CONSTANTS[r])` |
| `writes_back_w0` | 1 | `write_0 − read_0` |
| `input_w{j}`, `j = 1 + 2i + h` | 50 | `read_j − Σ_{k<4} 2^{8k}·A[i][4h + k]` |
| `output_w{j}` | 50 | `write_j − Σ_{k<4} 2^{8k}·O[i][4h + k]` |
| `rho_pi_l{i}_b{j}` | 200 | `B[y][2x + 3y][j] − rot_j(A′[x][y], r_xy)`, its constant times `live` |

A rotation by `8q + s` is linear in a lane's bytes `v` and their copies `μ = v ^ mask` (§1),
`mask = 256 − 2^{8−s}` being the top `s` bits; with `u = j − q` and `w = u − 1` mod 8,

```text
rot_j(v) = 2^{s−1}·(v_u + μ_u) + 2^{s−9}·(v_w − μ_w) + mask·(2^{s−9} − 2^{s−1})      s > 0
rot_j(v) = v_u                                                                    s = 0
```

`v_u`'s low bits moved up and `v_w`'s top bits down, `(v + mask − μ)/2` being `v & mask`.

The obligations are the frame's 210 on `RANGE16` (§1) and 1,020 on `XOR8`, one a byte:

| step | count | obligation `e_2 = e_0 ^ e_1` |
| --- | --- | --- |
| θ | 160 | `parity_s = parity_{s−1} ^ A[x][s + 1]`, `s < 4`, `parity_{−1} = A[x][0]` |
| θ | 40 | `c_mask = 0x80 ^ C[x]` |
| θ | 40 | `D[x] = rot(C[x + 1], 1) ^ C[x − 1]`, `c_mask` as `μ` |
| θ | 200 | `A′[x][y] = D[x] ^ A[x][y]` |
| ρ | 176 | `rho_mask = mask ^ A′` |
| χ | 200 | `chi_and = B1 ^ B2`, `Bk = B[x + k][y]` |
| χ | 200 | `chi_out = ((B2 − B1 + chi_and)/2) ^ B[x][y]` |
| ι | 4 | `iota_out_t = rc_t ^ chi_out[0][b_t]` |

### 2.3 Why it is sound

Every byte column is an entry of some obligation, so all are bytes, each obligation is the
operation it names and each form the integer it denotes (§1): `rot` because `μ` is the true XOR,
and `(B2 − B1 + chi_and)/2` is `¬B1 & B2`. The channel alone fixes `parity`, `c_mask`, `theta_d`
and `chi_and`. `B` is committed, and pinned by `rho_pi`, because χ reads every lane at an
entry only a column may fill.

`input_w` and `output_w` are each a word's byte decomposition and its 32-bit bound, so no state
word has a range obligation; without `output_w` a row could write any state. Both are ungated and
degree 1, a padding row's words and bytes being 0, which pins its state bytes to 0; a cell that
only `live`-gated gates and obligations reach is free on a padding row, to no effect.

`one_round_a_live_row` is the one-code rule (§1) over codes 0 … 23: without it a live row could
set no selector, claiming round 0, or two spelling a third, and ι would add no constant or a wrong
one. The constant is a table of literals the selectors pick (`rc{t}_rule`), with no lookup or
commitment. So a live row writes round `read_0` of the state it read.

A permutation is RAM glue (§1) over `guest_sdk::keccak256`'s loop, which stores `r = 0 … 23` in
word 0 before each call. `crates/checker/tests/keccak.rs` holds every gate and obligation over 24
such rows to a round written apart in `u64` and, through `emulator::keccak_round`, to `tiny-keccak`.

### 2.4 Cost and callers

1,764 committed columns and, at `2^18`, 5,490 inner ones in 29 gate lists, 11 row-wise and 18
halving, all the two memory trees' and the two fraction trees'. The 1,020 obligations and the
table's fraction fill 1,021 of the `XOR8` tree's 1,024 leaves ([lookup.md](lookup.md) §6); four
more would double it, 4,100 more inner columns. So ι is four obligations: a round constant is zero
outside bytes 0, 1, 3 and 7 (`constants::keccak::IOTA_BYTES_ARE_THE_ONLY_ONES`, checked at compile
time).

A `2^18` shard ([delegation.md](delegation.md) §9) holds 10,922 permutations; its proof is 381,100
bytes ([proof.md](proof.md) §9), 34.9 a permutation, and its forward pass 45.2 GB of inner layers
([streaming.md](streaming.md) §1), which is what sets a block's peak. Caller: `guest_sdk::keccak256`
([delegation.md](delegation.md) §10).

## 3. `POSEIDON2`

One invocation is one `transcript::poseidon2_permute` ([transcript.md](transcript.md) §1). The
circuit, `constraints::poseidon2`, is at `2^8` with no lookup, bounding in bits (§1), and is the
one delegation circuit that computes above gate list 0.

### 3.1 Frame and columns

24 words (`constants::poseidon2`):

| words | | read | written |
| --- | --- | --- | --- |
| `8l … 8l + 7` | lane `l`, `l < 3` | yes | the permuted lane |

A lane is its value's canonical encoding (`Fr::to_bytes`), not §4's Montgomery form, so the circuit
is the permutation itself; the caller's six conversions are small beside the 240 S-box
multiplications a call replaces.

`M[0..100]` and `W[0..972]` are the frame (§1). `W[972..4092]` holds 520 booleans for each of six
values, the lanes read (`in0` … `in2`) then written (`out0` … `out2`): 256 word bits, then the
canonicity chain's (§1) 256 difference bits and 8 borrows.

### 3.2 Gates

Gate list 0 holds 4,245: the frame's 51 (§1), a booleanity gate on each `W` column, and 17 a
value, over its read or written words: eight `<v>_word{k}`, `word_k − Σ_t 2^t·bit_{k,t}`, and its
canonicity chain against `p` (§1), eight `<v>_canonical{i}` and `<v>_below_modulus`,
`live − β_7`.

The permutation is computed, not witnessed: three gate lists a round `r`, S-boxing every lane of a
full round and lane 0 of a partial one, whose other lanes the first two lists copy:

```text
list 3r         q_i = (x_i + c_{r,i})²       t_i = x_i + c_{r,i}
list 3r + 1     q2_i = q_i²                  t_i copied
list 3r + 2     x′ = M_r·v                   v_i = q2_i·t_i, or x_i on a copied lane
```

`M_r` is `E` or `I` and the constants are literals of the gates; round 0's `x` is `E` applied to
`in_l = Σ_k 2^{32k}·read_{8l+k}`. A committed column is read by gate list 0 only
([gkr.md](gkr.md) §2), so `live` and `out_l = Σ_k 2^{32k}·write_{8l+k}` are carried up to gate list
192, which holds the last three gates,

```text
out_lane{l}     live·(x_l − out_l) = 0          x the state after round 63
```

gated because a padding row computes the permutation of the zero state, which is not zero.

### 3.3 Why it is sound

A layer's column is forced by the gate that writes it, so `x` is the permutation of
`(in_0, in_1, in_2)` as field elements. The word gates make each `in_l` and `out_l` the integer its
words spell, and the chains put it below `p`: a lane at or above `p` has no witness, and `out_lane`
fixes all 24 written words, where without the chains on `out` a row could write `x_l + p`. The
forward pass accepts Plonky3's permutation vectors (`crates/checker/tests/poseidon2.rs`).

### 3.4 Cost and callers

4,192 committed columns and 2,020 inner ones in 201 gate lists, 193 row-wise and 8 halving: 736 the
rounds' (15 a full round, 11 a partial one), 768 the four carried columns', the rest the memory
trees'. A `2^8` shard holds 256 permutations; its proof is 664,780 bytes, 2,597 a permutation.
Caller: `transcript::poseidon2_permute` on the guest target ([delegation.md](delegation.md) §10).

## 4. `FR_ARITH`

One invocation is one `Fr` addition, multiplication or inversion. The circuit,
`constraints::fr_arith`, is flat, at `2^8` with no lookup, bounding in bits (§1).

### 4.1 Frame and encoding

25 words (`constants::fr_arith`):

| words | | read | written |
| --- | --- | --- | --- |
| 0 | the code: 1 add, 2 multiply, 3 inverse (`OPS`) | yes | unchanged |
| 1–8, 9–16 | `a`, `b` | yes | unchanged |
| 17–24 | `out` | yes, unconstrained | the result |

A value is `Fr`'s in-memory form, `Fr::to_memory_bytes`: the canonical encoding of the Montgomery
representative `x·R`, `R = 2^256 mod p`. The circuit computes what `Fr`'s own operators compute on
representatives,

```text
add         out = a + b
multiply    out = a·b·R⁻¹
inverse     out = R²·a⁻¹, and 0 at a = 0
```

because a frame of values would cost the guest a Montgomery conversion per value, more than the
multiplication a call replaces. `Fr::inverse` answers `None` at 0 itself and makes no call.

### 4.2 Columns and gates

`M[0..104]` and `W[0..1010]` are the frame (§1); `W[1010..2570]` 520 booleans for each of `a`, `b`
(read) and `out` (written), as §3.1; `W[2570..2573]` the selectors `f_add`, `f_mul`, `f_inv`
(`selector1` … `selector3`); `W[2573..2576]` the field columns `prod`, `inv` and `z` (`is_zero`).
The 2,701 gates: the frame's 53 (§1); 2,573 booleanity gates, on every bit and selector; §3.2's 17
per value; `writes_back_w{j}` for `j < 17`; and, `a`, `b` and `out` being the forms
`Σ_k 2^{32k}·word_k`,

| gate | expression |
| --- | --- |
| `opcode_rule` | `read_0 − f_add − 2·f_mul − 3·f_inv` |
| `one_op_a_live_row` | `f_add + f_mul + f_inv − live` |
| `prod_rule` | `prod − a·b` |
| `inv_is_an_inverse` | `a·inv + z − f_inv` |
| `is_zero_at_nonzero` | `a·z` |
| `inverse_of_zero_is_zero` | `z·inv` |
| `out_rule` | `out − f_add·(a + b) − R⁻¹·f_mul·prod − R²·f_inv·inv` |

`R⁻¹` and `R²` are literals derived from `constants::FR_R`.

### 4.3 Why it is sound

As in §3.3, each value is the integer below `p` its words spell, so `out_rule` fixes the eight
written words. `prod` is committed, under an ungated gate, because a selector times `a·b` is
degree 3. On an inverse row `a ≠ 0` forces `z = 0` and `inv = a⁻¹`, and `a = 0` forces `z = 1` and
`inv = 0`; without `is_zero_at_nonzero`, `z = 1` and `inv = 0` pass at any `a`, and without
`inverse_of_zero_is_zero`, `inv` is free at `a = 0`. `one_op_a_live_row` is the one-code rule
(§1): `1 + 2 = 3`, so `opcode_rule` alone lets `f_add` and `f_mul` answer an inversion with
`a + b + a·b·R⁻¹`.

### 4.4 Cost and callers

2,680 committed columns and 142 inner ones, all the memory trees', in 14 gate lists, 6 row-wise
and 8 halving. A `2^8` shard holds 256 operations; its proof is 266,292 bytes, 1,040 an operation.
Caller: `field`'s addition, Montgomery multiplication and `inverse` on the guest target
([delegation.md](delegation.md) §10).

## 5. `MOD_MUL`

One invocation is one multiplication `out = a·b mod m` of 256-bit integers, `m` one of four fixed
primes a frame word selects. The circuit is `constraints::mod_mul`.

### 5.1 The frame and the columns

25 words (`constants::mod_mul`). A value is a plain residue, not a Montgomery one, in eight 32-bit
limbs, least significant first.

| words | | |
| --- | --- | --- |
| 0 | the selector: 1 secp256k1's base field `p`, 2 its order `n`, 3 BN254's base field `q`, 4 its scalar field `r` (`CODES`, `MODULI`) | read, written back |
| 1–8, 9–16 | `a`, `b`, each below the selected modulus | read, written back |
| 17–24 | `out` | written; the value read is ignored |

Codes start at 1, so a zero word names no field. The EVM's `MULMOD`, whose modulus is arbitrary,
is not this call and runs as guest code.

```text
M[0..104], W[0..54]   the frame (§1)
W[54..58]     selector1 … selector4        s_c, one a code
W[58..66]     m_limb{k}                    m_k, the selected modulus
W[66..162]    <v>{k}_hi, <v>_diff{i}, <v>_diff{i}_hi, <v>_borrow{i}     for v = a, b, out
W[162..178]   q_limb{k}, q_limb{k}_hi      the quotient and its halfwords
W[178..220]   carry{k}, carry{k}_c0, carry{k}_c1      c_k + 2^36 for k < 14, and two chunks
W[220]        range16_multiplicity
```

### 5.2 Gates and lookups

`read_j` and `write_j` are word `j`'s two values (§1), `a_i` and `b_i` read limbs, `out_i`
written ones, and `c_k = carry{k} − 2^36·live`. Each expression is held to 0:

| gate | count | expression |
| --- | --- | --- |
| the frame's (§1) | 28 | |
| `writes_back_w{j}`, `j < 17` | 17 | `write_j − read_j` |
| `selector{c}_boolean`; `selector_rule`; `one_modulus_a_live_row` | 6 | `s_c − s_c²`; `read_0 − Σ_c c·s_c`; `Σ_c s_c − live` |
| `m_limb{k}_rule` | 8 | `m_k − Σ_c s_c·MODULI[c][k]` |
| `<v>_borrow{i}_boolean`, `<v>_canonical{i}`, `<v>_below_modulus` | 51 | `v`'s canonicity chain (§1) against the `m_k` columns, concluding `live − β_7` |
| `limb{k}`, `k < 15` | 15 | `Σ_{i+j=k} (a_i·b_j − q_i·m_j) − out_k + c_{k−1} − 2^32·c_k`; `out_k` past limb 7, `c_{−1}` and `c_14` are 0 |

274 `RANGE16` obligations, all under `live`: the frame's 106 (§1); a **pair** — the 32-bit bound
of [memory.md](memory.md) §7, two obligations over a committed high halfword — on every limb of
`a`, `b`, `out` and `q` and on every `diff_i` (112); and each `carry{k}` in `[0, 2^37)`, by two
chunks and four obligations as a gap (§1) (56).

### 5.3 Why it is sound

**The field.** By the one-code rule (§1), `m` is the modulus word 0 names. Codes add
(1 + 3 = 4), so without `one_modulus_a_live_row` selectors 1 and 3 answer a request for `r`
modulo `p + q`; with it each `m_k` is one literal, which is all that keeps `m`'s limbs, bound by
no obligation, below `2^32`.

**The product.** Every limb of `a`, `b`, `out`, `q` and `m` being below `2^32`, a position's
products sum below `2^67` a side and the carries lie in `[−2^36, 2^36)`, so no term nears `Fr`'s
modulus: the fifteen `limb{k}` equations hold over ℤ and, weighted by `2^{32k}`, sum to
`a·b = q·m + out`, position 14 having no carry out.

**The reduction** is `out_below_modulus`: without it `(q − 1, out + m)` satisfies every other
relation wherever `out + m` fits eight limbs.

**The operand bounds** make the relation total, not `out` right: with `a, b < m`,
`q = (a·b − out)/m < m`, so every frame the circuit admits has an eight-limb quotient. A caller
holding a lazily reduced value therefore owes a reduction below `m`, not below `2^256`. The
emulator's `mod_mul_frame` refuses the frames no proof could cover, a selector that is no code
and an operand at or above `m` (`EmuError::DelegationFrame`).

### 5.4 Cost and callers

Shape: [circuits.md](circuits.md) §1. A `2^16` shard ([delegation.md](delegation.md) §9) is
65,536 multiplications at 2.1 proof bytes each; its forward pass, 2,180 row-wise inner columns ×
`2^16` rows × 32 bytes, is 4.6 GB.

`guest_sdk::recursion::mod_mul` makes the call over a `ModMulFrame`. The vendored `k256` reaches
it from its field and scalar multiplies (codes 1, 2), the vendored `ark-ff` from BN254's
Montgomery multiply (codes 3, 4): [delegation.md](delegation.md) §10.

## 6. `SHA256_COMP`

One invocation is four rounds of SHA-256's compression function and four words of its message
schedule; a compression is sixteen invocations on one frame, joined by RAM glue (§1). Padding,
the block loop and the final addition of the chaining value are the caller's. The circuit is
`constraints::sha256`.

### 6.1 The frame

25 words (`constants::sha256`):

| words | read | written |
| --- | --- | --- |
| 0 | the round group `r < 16` | unchanged |
| 1–8 | the working variables `a … h` | `a … h` four rounds on |
| 9–24 | the schedule window `W_{4r} … W_{4r+15}` | moved down four words, `W_{4r+16} … W_{4r+19}` last |

Call 0 reads the chaining value as `a … h` and the block, decoded big-endian, as the window. Over
a row the state is two sequences: `A_0 … A_{−3}` are `a … d` as read, `A_4 … A_1` are `a … d` as
written, and `E_j` is the same over `e … h`, so each of the sixteen is a frame column. For `k < 4`
and `m < 4`, every sum mod `2^32`:

```text
T1          = E_{k−3} + Σ1(E_k) + Ch(E_k, E_{k−1}, E_{k−2}) + K_{4r+k} + W_{4r+k}
A_{k+1}     = T1 + Σ0(A_k) + Maj(A_k, A_{k−1}, A_{k−2})
E_{k+1}     = A_{k−3} + T1
W_{4r+16+m} = σ1(W_{4r+14+m}) + W_{4r+9+m} + σ0(W_{4r+1+m}) + W_{4r+m}
```

Call `r + 4`'s rounds read the words call `r` derives, so the guest computes no schedule; calls
12–15 derive words no round reads.

### 6.2 Bytes and their obligations

No column is a bit but `live` and the group selectors `g_r`. A word that enters a Boolean
operation has four byte columns, and each such operation is one `XOR8` obligation
`(x, y, x ^ y)` a byte ([lookup.md](lookup.md) §3), of which position 0 alone may be a
literal-weighted form ([lookup.md](lookup.md) §5).

- A rotation is linear. With `μ = v ^ (2^s − 1)` committed, a byte `v` splits into
  `lo = (v + 2^s − 1 − μ)/2` and `hi = (v − lo)/2^s`. Byte `j` of `ROTR_{8t+s}(V)` is
  `hi(v_{j+t}) + 2^{8−s}·lo(v_{j+t+1})`, indices mod 4, and for `s < 8` the word `ROTR_s(V)` is
  `(V − lo(v_0))/2^s + 2^{32−s}·lo(v_0)`.
- The big sigmas nest, `Σ0(a) = ROTR2(a ^ ROTR11(a ^ ROTR9(a)))` and
  `Σ1(e) = ROTR6(e ^ ROTR5(e ^ ROTR14(e)))`, so each XOR has one rotated operand and the outer
  rotation is a word's: 17 obligations a sigma.
- The small sigmas end in a shift, `σ0(x) = ROTR7(x ^ ROTR11(x)) ^ SHR3(x)` and
  `σ1(x) = ROTR17(x ^ ROTR2(x)) ^ SHR10(x)`, so their outer XOR has two derived operands: the
  shifted bytes are committed and pinned by gates. 16 and 15 obligations, `SHR10`'s top byte
  being 0.
- `Ch` and `Maj` are linear in XORs, `Ch(e, f, g) = (f + g − (e ^ f) + (e ^ g))/2` and
  `Maj(a, b, c) = (a + b + c − (a ^ b ^ c))/2`: 8 obligations each.
- A carry `c` is a byte by `(0, c, c)`.

That is 52 obligations a round and 32 a schedule word, 336 on `XOR8`. `RANGE16` carries 114: the
frame's 106 (§1) and a pair (§5.2) on each written word without bytes, `A_4`, `E_4`,
`W_{4r+18}` and `W_{4r+19}`.

```text
M[0..104], W[0..54]   the frame (§1)
W[54..70]     group{r}                     g_r, one a group
W[70..118]    a{j}_b{b}, e{j}_b{b}         bytes of A_{−2} … A_3 and E_{−2} … E_3 (j = m2 … 3)
W[118..150]   w{i}_b{b}, n{m}_b{b}         bytes of window words 1–4, 14, 15, derived words 0, 1
W[150..358]   r{k}_…                       52 a round: the big sigmas' masks and XORs (34),
                                           e^f, e^g, a^b, c^a^b (16), two carries
W[358..514]   s{m}_…                       39 a schedule word: the small sigmas' masks, XORs
                                           and shifted bytes (38), a carry
W[514..518]   w{j}_written_hi              high halfwords of A_4, E_4, W_{4r+18}, W_{4r+19}
W[518..520]   range16_multiplicity, xor8_multiplicity
```

### 6.3 Gates

All of degree 1 but the frame's and the booleans:

| gate | count | expression |
| --- | --- | --- |
| the frame's (§1) | 28 | |
| `group{r}_boolean`; `group_rule`; `one_group_a_live_row` | 18 | `g_r − g_r²`; `read_0 − Σ_r r·g_r`; `Σ_r g_r − live` |
| `writes_back_w0` | 1 | `write_0 − read_0` |
| `a{j}_decode`, `a{j}_encode`, `e{j}_…`, `w{i}_decode`, `n{m}_encode` | 20 | a word `− Σ_b 2^{8b}·byte_b`, for every word with bytes |
| `w{i}_shift`, `i < 12` | 12 | `write_{9+i} − read_{13+i}` |
| `r{k}_a`, `r{k}_e` | 8 | §6.1's `A_{k+1}` and `E_{k+1}`, as `word + 2^32·carry − sum` |
| `s{m}_sum` | 4 | §6.1's `W_{4r+16+m}`, likewise |
| `s{m}_shr3_b{b}`, `s{m}_shr10_b{b}` | 28 | a committed shifted byte `−` its form |

`K_{4r+k}` is the form `Σ_r K_{4r+k}·g_r`.

### 6.4 Why it is sound

A sum's operands are words: those with bytes by their obligations, and `d`, `h`, `W_{4r}` and
`W_{4r+9} … W_{4r+12}`, which only sums read, because the frame lies in `[RAM_ORIGIN, 2^31)`
(§1), below advice, where every initial value and every write is a word
([memory-ops.md](memory-ops.md) §5; §1 for these circuits). Its carry being a byte, a sum gate
holds over ℤ, and its left word, bounded by its bytes or its pair, is the sum mod `2^32`.
Without the carry's range any word satisfies the gate; without the pair on `A_4`, a carry of 0
writes the unreduced sum. Every word a row writes is therefore a word: a copy, one with bytes, or
one of the four with a pair.

Group 0's code being 0, `group_rule` alone admits a live row with no selector or with `g_0`
beside another; `one_group_a_live_row` refuses those and two selectors spelling a third group,
each a round under a wrong constant. Sixteen rows are one compression by RAM glue (§1) and by
`guest_sdk::recursion::sha256_comp`, which stores `r = 0 … 15` in word 0 before each call; the
emulator's `sha256_frame` refuses a group word of 16 or more. `crates/checker/tests/sha256.rs`
evaluates every gate and obligation over sixteen chained rows built from FIPS 180-4 in `u32`
arithmetic and holds their output to the standard's `abc` digest.

### 6.5 Cost and callers

Shape: [circuits.md](circuits.md) §1. A `2^18` shard ([delegation.md](delegation.md) §9) holds
16,384 compressions at 11.6 proof bytes each; its forward pass, 2,694 row-wise inner columns ×
`2^18` × 32 bytes, is 22.6 GB.

`guest_sdk::sha256` pads, walks the blocks, and for each runs `sha256_comp`'s sixteen calls and
adds the result to the chaining value. The vendored `revm-precompile` routes `Crypto::sha256` to
it: precompile `0x02`, and the stateless guest's SSZ hashing ([delegation.md](delegation.md) §10).

## 7. `EC_ADD`

One invocation is a third of one complete point addition `P1 + P2` on secp256k1 or BN254 G1, in
homogeneous projective coordinates (`x = X/Z`, `y = Y/Z`). An addition is three invocations on
one frame in group order, joined by RAM glue (§1); scalar multiplication is guest code over it.
The circuit is `constraints::ec_add`.

### 7.1 The formula

Renes–Costello–Batina 2015, Algorithm 7, for `y² = x³ + b`, with `b3 = 3b`: 21 and 9
(`constants::ec_add::CURVE_B3`).

```text
group 0   xx = X1·X2            yy = Y1·Y2            zz = Z1·Z2
group 1   m4 = (X1+Y1)(X2+Y2)   m5 = (Y1+Z1)(Y2+Z2)   m6 = (X1+Z1)(X2+Z2)
group 2   X3 = xy·ym − byz3·xz  Y3 = yp·ym + bxx9·xz  Z3 = yz·yp + xx3·xy

xy = m4 − xx − yy   yz = m5 − yy − zz   xz = m6 − xx − zz   ym = yy − b3·zz
yp = yy + b3·zz     byz3 = b3·yz        xx3 = 3·xx          bxx9 = 3·b3·xx
```

Both groups have prime order, so the formula is complete: a doubling, `P + (−P)`, the identity
`(0 : 1 : 0)` and any `Z` take no special case, in the guest or in a row, and nothing is
inverted. The formula is the caller's: the vendored `k256`'s `ProjectivePoint` addition is this
algorithm on these coordinates, so the delegated and the software path return the same
representative.

The twelve multiplications are nine reductions, each of `X3`, `Y3`, `Z3` being two products under
one quotient. A row holds three, not nine, because a shard's memory grows with its row's width
and its height cannot fall below `2^16` (§7.5).

### 7.2 The frame and the columns

97 words (`constants::ec_add`), a value as in §5.1:

| words | | read by group | written by group |
| --- | --- | --- | --- |
| 0 | the selector, one of `CODES`: 1–3 secp256k1's groups 0–2, 4–6 BN254 G1's | all | none |
| 1–24 | `X1`, `Y1`, `Z1` | 0, 1 | 2, as `X3`, `Y3`, `Z3` |
| 25–48 | `X2`, `Y2`, `Z2` | 0, 1 | none |
| 49–72 | `xx`, `yy`, `zz` | 2 | 0 |
| 73–96 | `m4`, `m5`, `m6` | 2 | 1 |

A row has three **slots**, each one reduction of one shape:

```text
A·B + C·D + 1024·m² = q·m + out,     out < m
```

Group 0's `(A, B)` are `(X1, X2)`, `(Y1, Y2)`, `(Z1, Z2)` and group 1's the three pairs of sums,
both with `C = D = 0`. Group 2's `(A, B, C, D)` are `(xy, ym, byz3, −xz)`, `(yp, ym, bxx9, xz)`
and `(yz, yp, xx3, xy)`: a product's sign rides its operand.

```text
M[0..392], W[0..198]   the frame (§1)
W[198..295]   word{j}_hi                   the high halfword of every word's read value
W[295..301]   selector{c}                  s_c, one a code
W[301..310]   m_limb{k}, b3                the curve's modulus and 3b
W[310..334]   bzz3_{k}, byz3_{k}, bxx9_{k}     b3·zz_k, b3·(m5_k − yy_k − zz_k), 3·b3·xx_k
W[334..622]   <v>_diff{i}, <v>_diff{i}_hi, <v>_borrow{i}     chains of the twelve values x1 … m6
W[622..1027]  slot{r}_…, out{r}_…, q{r}_…, carry{r}_…    135 a slot: four operands (32), out and
              its halfwords (16), a nine-limb q and its halfwords (18), 15 carries c_k + 2^46
              with two chunks each (45), out's chain (24)
W[1027]       range16_multiplicity
```

### 7.3 Gates and lookups

`G_g` is the sum of the two selectors naming group `g`, and `c_k = carry − 2^46·live`:

| gate | count | expression |
| --- | --- | --- |
| the frame's (§1) | 100 | |
| `selector{c}_boolean`, `selector_rule`, `one_code_a_live_row` | 8 | §5.2's, over six codes |
| `m_limb{k}_rule`, `b3_rule` | 9 | the column `− Σ_c s_c·`(its literal for code `c`'s curve) |
| `bzz3_{k}_rule`, `byz3_{k}_rule`, `bxx9_{k}_rule` | 24 | the column `−` its product above |
| `<v>_borrow{i}_boolean`, `<v>_canonical{i}` | 240 | canonicity chains (§1) of the twelve values and the three `out`s, against `m_k` |
| `<v>_below_modulus` | 15 | `e·(1 − β_7)`: `e` is `G_0 + G_1` for `x1 … z2`, `G_2` for `xx … m6`, `live` for an `out` |
| `operand{r}_{o}_{k}_rule` | 96 | an operand limb `− Σ_g G_g·`(group `g`'s expression at that limb) |
| `slot{r}_limb{k}`, `k < 16` | 48 | `Σ_{i+j=k} (A_i·B_j + C_i·D_j + 1024·m_i·m_j − q_i·m_j) − out_k + c_{k−1} − 2^32·c_k`, `q` having nine limbs |
| `writes_back_w{j}` | 97 | `write_j − read_j − G_g·(out_k − read_j)`, for the group `g` and slot limb `k` that write word `j`, if any |

1,110 `RANGE16` obligations under `live`: the frame's 394 (§1); a pair (§5.2) on every word's
read value (194), every chain difference (240), every `out` limb (48) and every `q` limb (54);
and each carry in `[0, 2^47)`, four apiece (180).

### 7.4 Why it is sound

**The curve and the group** are §5.3's argument over six codes: codes add (1 + 3 = 4,
2 + 4 = 6), and the one-code rule is also all that keeps `m`'s limbs and `b3` literals.

**The operands.** An operand limb is its group's expression: a combination, with coefficients
of at most 3, of frame limbs below `2^32` and of their products with `b3`. Its pin is therefore
its bound, below `2^38` in magnitude, and it carries no obligation. It is a committed column
because the expression depends on the group, and a selector times a product of limbs would be
degree 3; `b3` enters through the three helper columns for the same reason.

**The identity.** As in §5.3: a position stays below `2^78`, the carries in `[−2^46, 2^46)`
(`CARRY_OFFSET_BITS`), the sixteen equations hold over ℤ and close because position 15 has no
carry out, and `out < m` makes `out` the residue of `A·B + C·D`. The `1024·m²`
(`OFFSET_MULTIPLE`) keeps the left side non-negative, a quotient's limbs being unsigned: it is
lowest in group 2's `Y3`, at `−673·m²` by its operands' ceilings `22m`, `22m`, `63m` and `3m`.
One literal serves every slot, a group-dependent offset being degree 3, and `q < 1697·m` fits
nine limbs. `ec_add::artifact` checks both constants against the ceilings when it builds the
circuit.

**Canonicity.** `out < m` is the reduction. A read value below `m` is what the ceilings assume,
and so what gives every admitted frame a quotient; the emulator's `ec_add_frame` refuses a frame
whose group reads a value at or above `m`, or whose selector is no code. Each such conclusion is
gated (§1) on the groups that read the value: every lane is below `m` on every row a guest builds
(`EcAddFrame::of` zeroes the intermediates), so `β_7 = e` would leave no row a witness.

**What the guest owns.** Each third is proved; their order is the guest's.
`guest_sdk::recursion::ec_add_complete` writes the three codes in turn, and groups out of order
are not refused but compute another point from stale lanes. Nor is a point held to its curve:
what is proved is the formula's arithmetic.

### 7.5 Cost and callers

Every bound is a `RANGE16` obligation, so the family sits at `2^16`, the channel's floor
([lookup.md](lookup.md) §3), and no other height is practical: as bits the 97 gaps alone would
be 3,686 columns, and at `2^18` the forward pass below would be 73 GB. Shape:
[circuits.md](circuits.md) §1. A shard holds 21,845 additions at 19.9 proof bytes each; its
forward pass, 8,708 row-wise inner columns × `2^16` × 32 bytes, is 18.3 GB.

`guest_sdk::ec_add` makes the three calls over an `EcAddFrame`, and `guest_sdk::ec_mul` is
double-and-add over it. The vendored `k256` routes `ProjectivePoint`'s addition, mixed addition
and doubling here, and the vendored `revm-precompile` routes `Crypto::bn254_g1_add` and
`Crypto::bn254_g1_mul`, precompiles `0x06` and `0x07`: [delegation.md](delegation.md) §10.
