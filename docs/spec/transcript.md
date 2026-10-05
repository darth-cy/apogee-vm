# The transcript

Every challenge in the protocol is drawn from a Poseidon2 duplex sponge over `Fr` through a typed
message layer. This page specifies the permutation, the sponge, the framing, a G1 point's transcript
form and every tag. Implementation: `crates/transcript`, `#![no_std]`.

## 1. The Poseidon2 permutation

Width 3 over `Fr`, S-box `x^5`, 4 full rounds, 56 partial rounds (S-box on lane 0 only), 4 full
rounds. The round constants are `RC3` of HorizenLabs/poseidon2,
`plain_implementations/src/poseidon2/poseidon2_instance_bn256.rs` at commit
`055bde3f4782731ba5f5ce5888a440a94327eaf3`.

```text
E(s) = s + (s₀+s₁+s₂)·(1,1,1)                 circ(2, 1, 1)
I(s) = s + (s₀+s₁+s₂)·(1,1,1) + (0,0,s₂)      1 + diag(1, 1, 2)

poseidon2_permute(s):
  s ← E(s)
  RC3 rows 0–3:    s_i ← (s_i + c_i)^5, every lane;   s ← E(s)
  RC3 rows 4–59:   s₀ ← (s₀ + c₀)^5;                  s ← I(s)
  RC3 rows 60–63:  s_i ← (s_i + c_i)^5, every lane;   s ← E(s)

poseidon2_permute([0, 1, 2])₀ = 0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033
```

`constants::POSEIDON2_RC3_INITIAL`, `_INTERNAL` and `_TERMINAL` hold the 80 entries read
(upstream's partial rows are zero in lanes 1 and 2) as upstream's big-endian hex literals, character
for character, decoded by `Fr::from_hex` on every call. They are pinned through the permutation, by
the oracle's 128 vectors (§2), each of which reads every constant.

On `riscv32`, `poseidon2_permute` is one `POSEIDON2` delegation call over the lanes' canonical
bytes, falling back to these rounds when the executor answers `-ENOSYS`
([delegation.md](delegation.md) §10).

## 2. The duplex sponge

```text
state  [Fr; 3]   lanes 0, 1 the rate, lane 2 the capacity; zero in Transcript::new()
input  [Fr; 2]   absorbed, not yet permuted: 0 or 1 pending between operations
output [Fr; 2]   squeezed, not yet handed out: 0 to 2

observe(x):  output ← []; input.push(x); if |input| = 2: duplex()
sample():    if |input| > 0 or |output| = 0: duplex(); return output.pop()
duplex():    n ← |input|; state[0..n] ← input; input ← []
             if n > 0: state[n..2] ← 0; state[2] += n
             poseidon2_permute(state); output ← [state[0], state[1]]
```

- Absorption overwrites the rate. A short absorb zero-fills the rest of it and adds its length to
  the capacity, so `[a]` and `[a, 0]` differ; with nothing pending, a duplex is a pure squeeze and
  does neither.
- Squeezed lanes leave from the end: the first `sample` after an absorb is `state[1]`, the second
  `state[0]`, and a third permutes again.
- `observe` drops unread output and lanes past a buffer's length stay zero, which moves no
  challenge and makes the state a function of the operation sequence alone.

This is Plonky3's `DuplexChallenger` at width 3 and rate 2. The vectors `crates/transcript` is
tested against come from `tools/transcript-ref`, which shares no code with it: Plonky3's Poseidon2
keyed with zkhash's own `RC3`, and a transcription of this section and §3 run beside that type,
agreeing with it on every squeeze. The recursion format replays the same sponge over field cells,
one `P2_FIELD` row a duplex step ([recursion.md](recursion.md) §4).

## 3. Typed messages

```text
append_scalars(tag, xs):  observe(tag); observe(|xs|); observe(x) for x in xs
append_scalar(tag, x)  =  append_scalars(tag, [x])
append_bytes(tag, b):     observe(tag); observe(|b|); observe(c) for each 31-byte chunk c of b,
                          zero-padded to 32 bytes, read little-endian
challenge_scalar(tag):    observe(tag); return sample()
```

The length, the scalar count or for bytes the byte count, delimits a message: `"abc"` and `"abc\0"`
are each one chunk, below `2^248 < p`, and differ. A challenge absorbs its tag, so it always comes
from a fresh permutation.

The framing carries no kind, so each tag names exactly one of scalars, bytes or a challenge (§5):
a tag of two kinds would make `append_bytes(T, b"")` and `append_scalars(T, [])` the same `T, 0`.
So every digest — program identity, the SRS digest, `transcript::io_digest`,
`sumcheck::witness_digest`, `pcs::accumulator_digest` — is a fresh sponge of typed messages ended
by a raw `sample()`, never by a challenge under one of its message tags.

`snapshot()` captures the state and both buffers, and `Transcript::restore` resumes the same
challenge stream. Its postcard form is 226 bytes, `state[3]`, `input[2]`, `input_len: u8`,
`output[2]`, `output_len: u8`, each `Fr` canonical; decoding refuses `input_len ≥ 2`,
`output_len > 2` and a nonzero lane past either length. The archived path's phase files hold the
global transcript, and each shard's after its GKR pass, in this form ([streaming.md](streaming.md)
§6). A shard transcript is no restored global sponge but a fresh one whose first message carries
the global state digest ([proof.md](proof.md) §4).

Each typed operation appends `Absorb { tag, n_scalars }` (payload elements: scalars, or chunks) or
`Challenge { tag }` to `event_log()`. Raw `observe` and `sample` are not logged, the log never
feeds the sponge and a snapshot omits it; `checker::tape` holds the global transcript's log to the
order G1–G11 ([tools.md](../tools.md) §4).

## 4. G1 points

A point is absorbed as four `Fr` limbs of its 64-byte encoding `x ‖ y`
([primitives.md](primitives.md) §3), with no curve arithmetic (`transcript::g1_limbs`):

```text
[ x[0..16], x[16..32], y[0..16], y[16..32] ]   each half read little-endian, below 2^128 < p
[ S, S, S, S ]                                 the 64 zero bytes of infinity; S = 2^128
```

A coordinate is an `Fq` element and `q > p`, hence the halves. `S` is
`constants::G1_INFINITY_SENTINEL`: no 16-byte half reaches `2^128`, so the limbs determine the 64
bytes whether or not they encode a point on the curve. The absorber never refuses; a point is
validated where it is decoded, before a pairing reads it.

`transcript::append_g1_points(tr, tag, points)` absorbs `k` points as one message of `4k` limbs,
never `k` messages, so the framed length binds `k`. `pcs::append_g1_list` is it over
`G1Affine::to_bytes`, and `pcs::append_g1` a list of one.

## 5. Tags

`Tag = u64`: `constants::transcript_tags`, 45 tags numbered from 1 and named by
`transcript_tags::NAMES[tag − 1]`; 0 is not a tag. Kinds: **S** scalars, **B** bytes, **C**
challenge. Where: G1–G11 and the shard transcript are [proof.md](proof.md) §2, §4, the SRS digest
§3 there; identity [program.md](program.md) §8; Mercury [mercury.md](mercury.md); GKR
[gkr.md](gkr.md) §5; `io_digest` [public-values.md](public-values.md) §5; stacks and nodes
[recursion.md](recursion.md) §1.3, §8.3. † marks a tag on no proof path.

| tag | | | where |
| --- | --- | --- | --- |
| 1 | `PROTOCOL_SUITE` | S | G1: `[PROTOCOL_VERSION]` |
| 2 | `PUBLIC_INPUTS` | B | G7: `io_digest`'s 32 canonical bytes |
| 3 | `COMMITMENT` | S | a commitment list: identity, G8, shard witness, Mercury |
| 4 | `SUMCHECK_ROUND` | S | a sumcheck round's coefficients |
| 5 | `SUMCHECK_CHALLENGE` | C | a round's challenge; first, a zerocheck's eq-randomizers |
| 6 | `EVALUATION_CLAIM` | S | Mercury: the point, then the claimed values |
| 7 | `PCS_OPENING` | S | Mercury: proof points and evaluations |
| 8 | `WITNESS_DIGEST` | S | `sumcheck::witness_digest`'s sponge, and its result † |
| 9 | `SUMCHECK_FINAL_EVALS` | S | the zerocheck's final evaluations † |
| 10 | `MERCURY_INSTANCE` | S | Mercury: `[n]` |
| 11 | `MERCURY_ALPHA` | C | Mercury: `α` |
| 12 | `MERCURY_GAMMA` | C | Mercury: `γ` |
| 13 | `MERCURY_Z` | C | Mercury: `z`, redrawn while 0 |
| 14 | `BDFG_BATCH` | C | Mercury: `δ` |
| 15 | `BDFG_POINT` | C | Mercury: `z′` |
| 16 | `PAIRING_MERGE` | C | Mercury: the pairing merge `ρ` |
| 17 | `MERCURY_BATCH` | C | Mercury: the column batch `ρ` |
| 18 | `ACCUMULATOR_DIGEST` | S | `pcs::discharge`: the entry words' sponge, and its result † |
| 19 | `ACCUMULATOR_MERGE` | C | `pcs::discharge`: the per-check weight † |
| 20 | `PUBLIC_INPUT_STREAM` | B | `io_digest`: the input |
| 21 | `PUBLIC_OUTPUT_STREAM` | B | `io_digest`: the output |
| 22 | `PROGRAM_IDENTITY` | S | identity: `[code_version]`; G6: `[identity]` |
| 23 | `VM_CONFIG` | S | identity; G3 |
| 24 | `SHARD_COUNTS` | S | G4 |
| 25 | `GKR_OUTPUTS` | S | GKR: the output tables |
| 26 | `GKR_OUTPUT_POINT` | C | GKR: the top point |
| 27 | `GKR_BATCH` | C | GKR: a transition's claim batch |
| 28 | `GKR_LAYER_CLAIMS` | S | GKR: a transition's claimed values |
| 29 | `GKR_CHILD` | C | GKR: a halving transition's line point |
| 30 | `MEMORY_WINDOWS` | S | G5 |
| 31 | `MEMORY_BOUNDARY` | S | G9 |
| 32 | `PROGRAM_ENTRY` | S | identity: `[entry_pc]` |
| 33 | `LOOKUP_CHALLENGE` | C | shard: `g`, then `β` ([lookup.md](lookup.md) §2) |
| 34 | `SRS_DIGEST` | S | G2 |
| 35 | `SRS_VERIFIER` | B | the SRS digest: the 320-byte `SrsVerifier` |
| 36 | `MEMORY_GROUP` | S | G8: `[family, shard count]` |
| 37 | `MEMORY_CHALLENGE` | C | G10, four times |
| 38 | `GLOBAL_STATE_DIGEST` | C | G11 |
| 39 | `SHARD_SEED` | S | shard: `[digest, family, index]` |
| 40 | `SHARD_TS_WINDOW` | S | shard: `[start, end]` |
| 41 | `GENERIC_TABLE` | S | the SRS digest: the generic table's 3 points, 12 limbs |
| 42 | `STACK_CHALLENGE` | C | a recursion-format shard: its `σ` stack challenges |
| 43 | `FOLD_STATE` | S | a node: a verified shard's final transcript state |
| 44 | `FOLD_WEIGHT` | C | a node: a shard's `w`, `w′`, or a child's weight |
| 45 | `FOLD_CHILD` | S | a node: a child's journal |
