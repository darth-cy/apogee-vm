# The transcript

Every challenge in the protocol is drawn from a Poseidon2 duplex sponge over the A64-C5 field
through a typed message layer. This page specifies the permutation and where its parameters come
from, the sponge, the framing and every tag, and §5 states what the construction claims.
Implementation: `crates/transcript`, `#![no_std]`, over `crates/field`
([primitives.md](primitives.md) §1).

## 1. Poseidon2-A64-C5

### 1.1 The field

Every lane is an element of `Fp`, the base field of [primitives.md](primitives.md) §1, and a
challenge one of its quadratic extension `Fp2`. `3 ∤ p − 1`, so `x ↦ x^3` permutes the field, and
its 2-adicity is 2 (§5.2).

### 1.2 The permutation

| | |
| --- | --- |
| width | `t = 16`: rate 8, capacity 8 |
| S-box | `x^3` |
| rounds | `R_F = 12` full rounds, 6 before and 6 after `R_P = 42` partial rounds: 234 S-boxes |
| external layer | `M_E = circ(2·M4, M4, M4, M4)` over four 4-lane blocks, `M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]` |
| internal layer | `M_I = J + diag(μ − 1)`: `μ_i` on the diagonal, 1 everywhere else |
| constants | 234 round constants and the 16 `μ_i − 1`, `crates/transcript/src/params.rs` |

```text
E(s): s_b ← M4·s_b + Σ_j M4·s_j  for each 4-lane block b        = M_E · s
I(s): s_i ← (μ_i − 1)·s_i + Σ_j s_j                             = M_I · s

poseidon2_permute(s):
  s ← E(s)
  rows 0–5:    s_i ← (s_i + c_{r,i})^3, every lane;   s ← E(s)
  rows 6–47:   s_0 ← (s_0 + c_r)^3;                   s ← I(s)
  rows 48–53:  s_i ← (s_i + c_{r,i})^3, every lane;   s ← E(s)

poseidon2_permute([0, 1, …, 15])₀ = 0x59bb4dfebd9c36af
```

`M4` is MDS over `p`: each of its 69 minors is a nonzero integer of magnitude at most 64. Before
reduction a lane of `E` is below `80p` and one of `I` below `p² + 16p < 2^128`, so each lane is
reduced once.

**Every constant is generated; none is chosen.** They are the output of HorizenLabs'
`poseidon2_rust_params.sage`, the Poseidon2 authors' reference generator, at commit
`055bde3f4782731ba5f5ce5888a440a94327eaf3`, edited at three lines: `p`, `t = 16` and `R_F += 4`
(§5.2). [tools.md](../tools.md) §8 is the run. The generator seeds the Poseidon paper's Grain LFSR
with field 1, S-box 0, `n = 64`, `t = 16`, `R_F = 12`, `R_P = 42` and thirty ones, discards 160
bits, and samples each round constant as 64 bits, redrawn until it is below `p`. It then draws the
16 `μ_i` from the same stream until the minimal polynomial of `M_I^k` is irreducible of degree 16
for every `k ≤ 32`, which rules out subspace trails through arbitrarily many partial rounds
[GRS21], and runs its three subspace-trail checks on the result. PARI re-checks that condition
independently. `params.rs` holds the output value for value, in the generator's order, and
`tests/permutation.rs` holds the permutation to the generator's own Sage evaluation at
`[0, 1, …, 15]`, which every constant reaches.

## 2. The duplex sponge

```text
state [Fp; 16]: lanes 0–7 the rate, 8–15 the capacity

new():      rate ← 0; capacity ← PROTOCOL_ID, 7 bytes a lane little-endian, zero after it;
            a ← 0; s ← 8
absorb(x):  if a = 8: permute, a ← 0;   state[a] ← x; a ← a + 1;   s ← 8
squeeze():  if s = 8: permute, s ← 0;   a ← 0;   s ← s + 1; return state[s − 1]
```

`PROTOCOL_ID = "apogee-vm/transcript-a64-c5/v1"`, 30 bytes in lanes 8–12. This is Chiesa and
Orrù's duplex sponge [CO25, Construction 3.3], as spongefish implements it in `DuplexSponge`:

- Absorption overwrites the rate lanes in order, which the duplex makes as secure as adding into
  them [BDPV11]. The permutation runs lazily, when a ninth lane arrives or at the first squeeze
  after an absorb, so that squeeze reads a fresh permutation of everything absorbed.
- Squeezes read lanes 0 upward and permute again past lane 7. An absorb after a squeeze overwrites
  from lane 0.
- There is no padding. Domain separation is the capacity's starting value and an IO pattern the
  protocol fixes: every sponge here runs a script its statement determines and its verifier checks
  message by message, and §3's framing is prefix-free. Those are the conditions spongefish
  documents for [CO25]'s duplex.
- `PROTOCOL_ID` separates these sponges from every other use of the permutation, and it changes
  whenever this construction does.

`tests/transcript.rs` holds the transcript to a transcription of spongefish's `DuplexSponge` on
seeded scripts.

## 3. Typed messages

```text
append_scalars(tag, xs):  absorb(tag); absorb(|xs|); absorb(x) for x in xs
append_scalar(tag, x)  =  append_scalars(tag, [x])
append_ext(tag, xs)    =  append_scalars(tag, [x.c0, x.c1 for x in xs])
append_bytes(tag, b):     absorb(tag); absorb(|b|); absorb(c) for each 7-byte chunk c of b,
                          zero-padded to 8 bytes, read little-endian
challenge(tag):           absorb(tag); return Fp2 { c0: squeeze(), c1: squeeze() }
digest():                 return squeeze() eight times
```

Every lane is canonical: a tag is a small constant, a length is below `2^63` and a chunk below
`2^56 < p`. The length, the lane count or for bytes the byte count, delimits a message: `"abc"`
and `"abc\0"` are each one chunk, and differ. An `Fp2` message is a scalar message of its values'
coordinates, two lanes a value: the protocol fixes which messages carry which field, so the kind
need not be framed.

A **challenge** is one element of the quadratic extension `Fp2`: two independent uniform lanes
of a fresh permutation, `c0` then `c1` in the order they leave the rate. A protocol draws as many as it needs, each under its own tag absorb. A **digest** is the
whole rate of one more permutation, 8 lanes. Every digest (program identity, `io_digest`
([public-values.md](public-values.md) §5), `sumcheck::witness_digest`) is a fresh sponge of typed
messages ended by `digest()`, never by a challenge under one of its message tags.

The framing carries no kind, so each tag names exactly one of scalars, bytes or a challenge (§4): a
tag of two kinds would make `append_bytes(T, b"")` and `append_scalars(T, [])` the same `T, 0`.

`snapshot()` captures the state and both positions, and `Transcript::restore` resumes the same
stream. Its serde form is `([Fp; 16], a: u8, s: u8)`, each lane in `Fp`'s 8 canonical bytes, so a
snapshot is a fixed 130 bytes under `postcard`. Decoding refuses a lane at or above `p` and
the positions the duplex never reaches: `a > 8`, `s` outside `1..=8`, or `a > 0` with `s < 8`. The
archived path's phase files hold the global transcript, and each shard's after its GKR pass, in this
form ([streaming.md](streaming.md) §6). A shard transcript is no restored global sponge but a fresh
one whose first message carries the global state digest ([proof.md](proof.md) §4).

Each typed operation appends `Absorb { tag, n }` (payload lanes: scalars, two per `Fp2` value, or
chunks) or
`Challenge { tag }` to `event_log()`. The log never feeds the sponge and a snapshot omits it;
`checker::tape` holds the global transcript's log to the order G1–G9 ([tools.md](../tools.md) §4).

## 4. Tags

`Tag = u64`: `constants::transcript_tags`, 29 tags numbered from 1 to 30 and named by
`transcript_tags::NAMES[tag − 1]`; 0 is not a tag, and 13 is retired, never to be reassigned.
Kinds: **S** scalars, `Fp` or `Fp2` (†† marks `Fp2`, two lanes a value), **B** bytes, **C**
challenge. Where: G1–G9 and the shard transcript are
[proof.md](proof.md) §2, §4; identity [program.md](program.md) §8; GKR [gkr.md](gkr.md) §5;
`io_digest` [public-values.md](public-values.md) §5; the opening [pcs.md](pcs.md) §7. † marks a
tag on no proof path.

| tag | | | where |
| --- | --- | --- | --- |
| 1 | `PROTOCOL_SUITE` | S | G1: `[PROTOCOL_VERSION]` |
| 2 | `PUBLIC_INPUTS` | S | G6: `io_digest`'s 8 lanes |
| 3 | `SUMCHECK_ROUND` | S †† | a sumcheck round's coefficients |
| 4 | `SUMCHECK_CHALLENGE` | C | a round's challenge; first, a zerocheck's eq-randomizers |
| 5 | `WITNESS_DIGEST` | S | `sumcheck::witness_digest`'s sponge, and its result † |
| 6 | `SUMCHECK_FINAL_EVALS` | S †† | the zerocheck's final evaluations † |
| 7 | `PUBLIC_INPUT_STREAM` | B | `io_digest`: the input |
| 8 | `PUBLIC_OUTPUT_STREAM` | B | `io_digest`: the output |
| 9 | `PROGRAM_IDENTITY` | S | identity: `[code_version]`; G5: the identity's 8 lanes |
| 10 | `VM_CONFIG` | S | identity; G2 |
| 11 | `SHARD_COUNTS` | S | G3 |
| 12 | `GKR_OUTPUTS` | S †† | GKR: the outputs |
| 13 | — | | retired: no message carries it |
| 14 | `GKR_BATCH` | C | GKR: a transition's claim batch |
| 15 | `GKR_LAYER_CLAIMS` | S †† | GKR: a transition's claimed values |
| 16 | `GKR_CHILD` | C | GKR: a halving transition's line point |
| 17 | `MEMORY_WINDOWS` | S | G4 |
| 18 | `MEMORY_BOUNDARY` | S | G7 |
| 19 | `PROGRAM_ENTRY` | S | identity: `[entry_pc]` |
| 20 | `LOOKUP_CHALLENGE` | C | shard: `g`, then `β` ([lookup.md](lookup.md) §2) |
| 21 | `MEMORY_CHALLENGE` | C | G8, five times |
| 22 | `GLOBAL_STATE_DIGEST` | C | G9 |
| 23 | `SHARD_SEED` | S | shard: `[digest.c0, digest.c1, family, index]` |
| 24 | `SHARD_TS_WINDOW` | S | shard: `[start, end]` |
| 25 | `SETUP_COMMITMENT` | S | identity: one family's setup commitment, its payloads |
| 26 | `MEMORY_COMMITMENT` | S | G6a: one statement shard's memory commitment |
| 27 | `WITNESS_COMMITMENT` | S | shard, S2a: the shard's witness commitment |
| 28 | `PCS_MESSAGE` | S, S †† | the opening: every prover message |
| 29 | `PCS_CHALLENGE` | C | the opening: every challenge |
| 30 | `PCS_DIGEST` | S | a terminal digest's own sponge |

## 5. Security

### 5.1 Claims

The target is 128 bits against a quantum adversary, from classical bounds of 256 bits that a
square-root speedup halves.

- **Sponge.** The capacity is 8 lanes, `8 · log2 p ≈ 512` bits. The cheapest generic attack on a
  sponge, an inner collision, takes about `2^256` permutation calls; quantumly about `2^170`
  queries, with as much quantum memory [BHT98]; recovering a state takes `2^256` Grover iterations.
- **Digests.** 512 bits: a collision takes about `2^256` calls classically and `2^170` quantumly.
- **Challenges.** One carries `2 · log2 p ≈ 128` bits. A prover hunting a draw in a bad set of
  density `ε` needs about `1/ε` permutation calls, and about `ε^(−1/2)` with Grover, so a soundness
  argument counts each draw at half its bits against a quantum prover. How many draws it takes is
  the protocol's to say.
- **Permutation.** The rounds meet every bound of the Poseidon2 analysis at the 256-bit level, with
  four more full rounds against round skipping (§5.2). No attack on full-round Poseidon or
  Poseidon2 is known.

### 5.2 The round numbers

The generator's analysis [GKRRS21, GKS23, ABM23] has six bounds: statistical attacks need
`R_F ≥ 6`; interpolation needs `R_F + R_P ≥ 1 + ⌈min(M, log2 p) · log_3 2⌉ + ⌈log_3 t⌉`; three
Gröbner-basis bounds; and [ABM23]'s binomial bound. Its cheapest solution at `t = 16` is
`(R_F, R_P) = (6, 39)`; its margin of two more full rounds and 7.5% more partial ones gives
`(8, 42)`. Interpolation binds at 45 rounds, and since it is capped at `log2 p = 64` the solution
is the same at `M = 128` and `M = 256`, and at every width from 12 to 24. At `M = 256` every other
bound holds with room.

The four extra full rounds answer "Skipping Class" [MR26]. `M_E` maps `(0, X, −X, 0)` to
`(0, M4·X, −M4·X, 0)`, so two opposite blocks can cross a full round as a change of variables
instead of a cubing, at the price of four linear conditions per round on the inputs the attacker
controls: about `t/4 = 4` full rounds when every lane is free. It breaks no recommended parameter
set, but it erodes the full-round margin enough that the Ethereum Foundation's Poseidon Initiative
moved from Poseidon2 to Poseidon1 [Kho26]. Twelve full rounds leave the generator's eight after a
four-round skip, in any mode of use, for 234 S-boxes instead of 170.

The rest of the 2025–26 cryptanalysis reaches reduced rounds only: Graeffe-transform root finding
[SV25, ZSVD25], which targets NTT-friendly fields, while A64-C5's `p − 1` has 2-adicity 2 and a
43-bit prime factor; bivariate resultants for CICO-2 [BH26]; subspace restriction [BTA26]; and
Gröbner bases over subspace trails [GKR25], which finds the original estimates off in both
directions, depending on the instance. `M_E` is Poseidon2's own, and `M_I` and every constant come
from the generator's stream (§1.2): MDS-ness and the subspace-trail checks alone admit a backdoored
matrix, so the generation itself has to be verifiable [JLS26].

### 5.3 What is not claimed

- No proof covers a quantum adversary. A sponge whose permutation the adversary may invert in
  superposition has no known quantum security bound, and the quantum algebraic cryptanalysis of
  Poseidon is open [Kho26]. The quantum figures in §5.1 are the best known generic attacks.
- [CO25]'s Fiat–Shamir theorem is in the classical ideal-permutation model.
- For any hash, Fiat–Shamir over GKR admits false proofs of statements whose circuit evaluates that
  hash [KRS25]. Excluding them is the protocol's concern, not the transcript's.

### References

- [ABM23] T. Ashur, T. Buschman, M. Mahzoun. Algebraic cryptanalysis of HADES design strategy:
  application to POSEIDON and Poseidon2. ePrint 2023/537.
- [BDPV11] G. Bertoni, J. Daemen, M. Peeters, G. Van Assche. Duplexing the sponge: single-pass
  authenticated encryption and other applications. SAC 2011, ePrint 2011/499.
- [BH26] A. Bak, M. Hostettler. A better bivariate resultant attack on round-reduced Poseidon.
  ePrint 2026/1905.
- [BHT98] G. Brassard, P. Høyer, A. Tapp. Quantum cryptanalysis of hash and claw-free functions.
  LATIN 1998.
- [BTA26] A. S. Bhati, S. Tariq, T. Ashur. How to attack Poseidon via smart subspace restriction.
  ePrint 2026/1692.
- [CO25] A. Chiesa, M. Orrù. A Fiat–Shamir transformation from duplex sponges. TCC 2025, ePrint
  2025/536.
- [GKR25] L. Grassi, K. Koschatko, C. Rechberger. Poseidon and Neptune: Gröbner basis cryptanalysis
  exploiting subspace trails. ToSC 2025, ePrint 2025/954.
- [GKRRS21] L. Grassi, D. Khovratovich, C. Rechberger, A. Roy, M. Schofnegger. Poseidon: a new hash
  function for zero-knowledge proof systems. USENIX Security 2021, ePrint 2019/458.
- [GKS23] L. Grassi, D. Khovratovich, M. Schofnegger. Poseidon2: a faster version of the Poseidon
  hash function. AFRICACRYPT 2023, ePrint 2023/323.
- [GRS21] L. Grassi, C. Rechberger, M. Schofnegger. Proving resistance against infinitely long
  subspace trails: how to choose the linear layer. ToSC 2021(2), ePrint 2020/500.
- [JLS26] H. Jeong, M. S. Leip, M. Son. Nothing up my matrix: kleptographic backdoors in ZK-friendly
  hash functions. ePrint 2026/1901.
- [Kho26] D. Khovratovich. Poseidon Cryptanalysis Initiative 2024–2026: state of the art. SPRING,
  10 May 2026.
- [KRS25] D. Khovratovich, R. D. Rothblum, L. Soukhanov. How to prove false statements: practical
  attacks on Fiat–Shamir. ePrint 2025/118.
- [MR26] S.-P. Merz, À. Rodríguez García. Skipping class: algebraic attacks exploiting weak matrices
  and operation modes of Poseidon2(b). ePrint 2026/306.
- [SV25] A. Sanso, G. Vitto. Attacking Poseidon via Graeffe-based root-finding over NTT-friendly
  fields. ePrint 2025/937.
- [ZSVD25] Z. Zhao, A. Sanso, G. Vitto, J. Ding. Graeffe-based attacks on Poseidon and NTT lower
  bounds. ePrint 2025/1916.
