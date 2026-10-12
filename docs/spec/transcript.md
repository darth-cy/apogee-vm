# The transcript

Every challenge in the protocol is drawn from a Poseidon2 duplex sponge over `Fr` through a typed
message layer. This page specifies the permutation, the sponge, the framing and every tag.
Implementation: `crates/transcript`, `#![no_std]`.

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
agreeing with it on every squeeze.

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

The framing carries no kind, so each tag names exactly one of scalars, bytes or a challenge (§4):
a tag of two kinds would make `append_bytes(T, b"")` and `append_scalars(T, [])` the same `T, 0`.
So every digest — program identity, `transcript::io_digest`, `sumcheck::witness_digest` — is a
fresh sponge of typed messages ended by a raw `sample()`, never by a challenge under one of its
message tags.

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
order G1–G9 ([tools.md](../tools.md) §4).

## 4. Tags

`Tag = u64`: `constants::transcript_tags`, 24 tags numbered from 1 and named by
`transcript_tags::NAMES[tag − 1]`; 0 is not a tag. Kinds: **S** scalars, **B** bytes, **C**
challenge. Where: G1–G9 and the shard transcript are [proof.md](proof.md) §2, §4; identity
[program.md](program.md) §8; GKR [gkr.md](gkr.md) §5; `io_digest`
[public-values.md](public-values.md) §5. † marks a tag on no proof path.

| tag | | | where |
| --- | --- | --- | --- |
| 1 | `PROTOCOL_SUITE` | S | G1: `[PROTOCOL_VERSION]` |
| 2 | `PUBLIC_INPUTS` | B | G6: `io_digest`'s 32 canonical bytes |
| 3 | `SUMCHECK_ROUND` | S | a sumcheck round's coefficients |
| 4 | `SUMCHECK_CHALLENGE` | C | a round's challenge; first, a zerocheck's eq-randomizers |
| 5 | `WITNESS_DIGEST` | S | `sumcheck::witness_digest`'s sponge, and its result † |
| 6 | `SUMCHECK_FINAL_EVALS` | S | the zerocheck's final evaluations † |
| 7 | `PUBLIC_INPUT_STREAM` | B | `io_digest`: the input |
| 8 | `PUBLIC_OUTPUT_STREAM` | B | `io_digest`: the output |
| 9 | `PROGRAM_IDENTITY` | S | identity: `[code_version]`; G5: `[identity]` |
| 10 | `VM_CONFIG` | S | identity; G2 |
| 11 | `SHARD_COUNTS` | S | G3 |
| 12 | `GKR_OUTPUTS` | S | GKR: the output tables |
| 13 | `GKR_OUTPUT_POINT` | C | GKR: the top point |
| 14 | `GKR_BATCH` | C | GKR: a transition's claim batch |
| 15 | `GKR_LAYER_CLAIMS` | S | GKR: a transition's claimed values |
| 16 | `GKR_CHILD` | C | GKR: a halving transition's line point |
| 17 | `MEMORY_WINDOWS` | S | G4 |
| 18 | `MEMORY_BOUNDARY` | S | G7 |
| 19 | `PROGRAM_ENTRY` | S | identity: `[entry_pc]` |
| 20 | `LOOKUP_CHALLENGE` | C | shard: `g`, then `β` ([lookup.md](lookup.md) §2) |
| 21 | `MEMORY_CHALLENGE` | C | G8, four times |
| 22 | `GLOBAL_STATE_DIGEST` | C | G9 |
| 23 | `SHARD_SEED` | S | shard: `[digest, family, index]` |
| 24 | `SHARD_TS_WINDOW` | S | shard: `[start, end]` |

**ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** No tag absorbs a commitment, because
there is none ([proof.md](proof.md) §3). A commitment scheme's messages take new numbers from 25.
