# The Poseidon2 duplex transcript

Frozen as of S02. Every challenge in this protocol is drawn through this
construction; changing anything here is a protocol-version change.

Implementation: `crates/transcript`. Reference implementation (the oracle that
produces every committed vector): `tools/transcript-ref`, which transcribes this
document over Plonky3's Poseidon2 with the HorizenLabs `RC3` constants, and
never links `crates/transcript`. Sections 5, 6 and 7 are also exactly Plonky3's
`DuplexChallenger` at width 3 and rate 2, and the oracle runs both on every
operation and asserts they agree, so the committed vectors check the text below
*and* the reference type. Sections 8 to 13 are this protocol's own and have no
upstream counterpart.

---

## 1. Field and permutation parameters

Poseidon2 over `Fr`, the BN254 scalar field.

| Parameter | Value |
| --- | --- |
| State width `t` | 3 |
| Rate `r` | 2 (lanes 0 and 1) |
| Capacity | 1 (lane 2) |
| S-box | `x -> x^5` |
| Full rounds `R_F` | 8, split 4 initial and 4 terminal |
| Partial rounds `R_P` | 56 |
| Partial-round S-box lane | 0 |

This is the established width-3 BN254 Poseidon2 instance from the Poseidon2
paper (ePrint 2023/323), Table 1, `(n, t, d) = (256, 3, 5)`.

## 2. Round constants

The 64 rounds' constants are the upstream `RC3` table of
<https://github.com/HorizenLabs/poseidon2>, file
`plain_implementations/src/poseidon2/poseidon2_instance_bn256.rs`, at commit
`055bde3f4782731ba5f5ce5888a440a94327eaf3` — the same table Plonky3 checks its
BN254 Poseidon2 against.

`RC3` is 64 rows of 3 constants. Rows `0..4` are the initial full rounds and
rows `60..64` the terminal full rounds, both using all three lanes; rows
`4..60` are the partial rounds and use lane 0 only, with zero in lanes 1 and 2
upstream.

`constants` stores exactly the entries the permutation reads, split by phase:
`POSEIDON2_RC3_INITIAL` (`[[&str; 3]; 4]`), `POSEIDON2_RC3_INTERNAL`
(`[&str; 56]`), `POSEIDON2_RC3_TERMINAL` (`[[&str; 3]; 4]`). The literals are
copied from upstream character for character — `0x` plus 64 lowercase hex
digits, big-endian — so the vendored table diffs against its source by eye.
The vendored tables are checked by the permutation vectors rather than against a
separate dump of `RC3`: every constant is read on every permutation call, so a
single wrong digit changes the output for essentially every input and fails both
the `[0,1,2]` KAT and all 128 committed vectors in
`crates/transcript/tests/poseidon2.rs`.

`field::Fr::from_hex` decodes them, at runtime, on every permutation call: `Fr`
has no compile-time constructor, and giving it one would have meant editing the
S01 multiplier. The measured cost is **1.76x** on the permutation: 4667 ns with
the decode already done, 8201 ns as shipped.

## 3. The permutation

`poseidon2_permute(state: &mut [Fr; 3])`:

```
external_matrix(state)
for rc in RC_INITIAL:                       # 4 rounds
    for lane in 0..3: state[lane] = (state[lane] + rc[lane])^5
    external_matrix(state)
for rc in RC_INTERNAL:                      # 56 rounds
    state[0] = (state[0] + rc)^5
    internal_matrix(state)
for rc in RC_TERMINAL:                      # 4 rounds
    for lane in 0..3: state[lane] = (state[lane] + rc[lane])^5
    external_matrix(state)
```

At width 3 the two linear layers are:

- **external** — multiplication by the circulant matrix
  `[[2,1,1],[1,2,1],[1,1,2]]`, i.e. add the state sum to every lane;
- **internal** — multiplication by `1 + diag(1,1,2) = [[2,1,1],[1,2,1],[1,1,3]]`.

Note the external linear layer applied *before* the first round: this is the
Poseidon2 initial matrix multiplication, not an off-by-one.

## 4. Sponge state

```
state:      [Fr; 3]   lanes 0,1 are the rate; lane 2 is the capacity
input:      [Fr; 2]   absorbed, not yet permuted
input_len:  0 or 1    between operations; momentarily 2 inside `observe`
output:     [Fr; 2]   squeezed, not yet handed out
output_len: 0, 1 or 2
```

`Transcript::new()` sets every lane and length to zero. Absorbing the protocol
preamble is the caller's job, through the typed layer.

**Canonicalisation invariant.** Lanes at or past a buffer's length are always
zero, and no squeezed material outlives an absorb (§5). The duplex never reads
either, so this costs nothing and makes the state — and therefore the §12
snapshot — a deterministic function of the operation sequence: replay the same
script and get the same bytes.

It does *not* say that any two transcripts with the same challenge future have
equal snapshots. When input is pending the rate lanes are already dead, so
states that differ only there behave identically; reaching such a pair through
the API would take a capacity collision, but a hand-built snapshot can simply
be one.

**The input buffer is never full between operations.** `observe` duplexes the
moment the rate fills, so `input_len` is 0 or 1 whenever a caller can see the
transcript. `output_len` has no such bound: an `observe` that completes an
absorb leaves both squeezed lanes waiting.

## 5. `observe` — raw absorb

```
observe(x):
    output = [0, 0]; output_len = 0     # any buffered output is now stale
    input[input_len] = x; input_len += 1
    if input_len == 2: duplex()
```

Dropping the buffered output is not what makes a challenge depend on the
material absorbed before it — §6's guard already forces a fresh permutation
whenever input is pending, and an absorb that filled the rate refilled the
output on its way through. What it buys is that the sponge state is a function
of the operation sequence alone, which is what makes §12's snapshots canonical.

## 6. `sample` — raw squeeze

```
sample() -> Fr:
    if input_len > 0 or output_len == 0: duplex()
    output_len -= 1
    x = output[output_len]; output[output_len] = 0
    return x
```

Challenges leave the rate **from the end**: the first challenge after an absorb
is `state[1]`, the second is `state[0]`.

## 7. `duplex` — one sponge step

```
duplex():
    n = input_len
    for i in 0..n: state[i] = input[i]; input[i] = 0
    input_len = 0
    if n > 0:                           # an absorb
        for i in n..2: state[i] = 0     # zero pad
        state[2] += n                   # absorb-length tag, into the capacity
    permute(state)                      # a pure squeeze does neither of the above
    output = [state[0], state[1]]; output_len = 2
```

Three properties are load-bearing:

- **Overwrite absorption.** Absorbed elements replace the rate; they are not
  added to it.
- **Zero pad and length tag.** A short absorb zero-fills the rest of the rate
  and adds the absorbed count to the capacity. Without the length tag, `[a]` and
  `[a, 0]` would collide; the tag is what separates transcript cases D and E.
- **A pure squeeze is not an absorb.** With nothing pending, the rate is left
  alone and nothing is added to the capacity — the state is simply permuted
  again. This is what a third consecutive `sample` does.

## 8. Tags

`Tag = u64`. Values live only in `constants::transcript_tags`, are sequential
from 1, and are never renumbered or reused. `0` is not a tag, so an
uninitialised value can never be a valid message.

| Name | Value | Kind |
| --- | --- | --- |
| `PROTOCOL_SUITE` | 1 | scalars |
| `PUBLIC_INPUTS` | 2 | bytes |
| `COMMITMENT` | 3 | scalars |
| `SUMCHECK_ROUND` | 4 | scalars |
| `SUMCHECK_CHALLENGE` | 5 | challenge |
| `EVALUATION_CLAIM` | 6 | scalars |
| `PCS_OPENING` | 7 | scalars |

**One tag, one message kind.** The typed layer frames a message as
`tag, length, payload...` and nothing more, so injectivity of the absorbed
stream rests on each tag naming exactly one kind. Reusing a tag across kinds
would make `append_bytes(T, b"")` and `append_scalars(T, &[])` absorb the same
stream. Later stages append to the table; they must not reuse.

## 9. `append_scalar`, `append_scalars` — scalar messages

```
append_scalars(tag, xs):
    observe(tag)
    observe(xs.len())
    for x in xs: observe(x)

append_scalar(tag, x) = append_scalars(tag, [x])
```

The length is what makes `append_scalars(T, [a, b])` differ from
`append_scalar(T, a); append_scalar(T, b)`: the first absorbs `T, 2, a, b`, the
second `T, 1, a, T, 1, b`.

## 10. `append_bytes` — byte messages

```
append_bytes(tag, bytes):
    observe(tag)
    observe(bytes.len())
    for chunk in bytes.chunks(31):
        observe(chunk, zero-padded to 32 bytes, read little-endian)
```

31 bytes is `< 2^248 < p`, so every chunk is a canonical field element. The
trailing chunk is zero-padded, so the **byte** length — not the chunk count — is
what makes the encoding injective: `"abc"` and `"abc\0"` differ, and `"ab"`
differs from `"a"` then `"b"`.

An empty byte string is a real message: it absorbs `tag, 0` and no payload.

## 11. `challenge_scalar`

```
challenge_scalar(tag) -> Fr:
    observe(tag)
    return sample()
```

The tag is absorbed, so a challenge is domain-separated and always follows a
fresh permutation: the two pending elements (`tag`, plus whatever preceded it)
or the tag alone force a duplex step inside `sample`.

## 12. `snapshot` / `restore`

`snapshot()` captures the sponge state and both buffers — exactly what §4 lists,
and nothing else. `restore(&snapshot)` rebuilds a transcript that emits the same
challenge stream the original would have from that point.

The wire form is a fixed 226 bytes: `state[3]`, `input[2]`, `input_len: u8`,
`output[2]`, `output_len: u8`, with every field element canonical
little-endian. Deserialisation refuses anything `snapshot` could not have
produced, so `restore` can never be handed a state outside the §4 invariant:

- `input_len < 2` — **strictly** below the rate, because `observe` duplexes the
  moment the rate fills, so a transcript is never handed back to a caller with a
  full input buffer;
- `output_len <= 2` — not strict: `observe` leaves a full output buffer behind
  when the absorb it completed duplexed the sponge;
- every lane at or past a buffer's length is zero.

The event log is **not** captured: it is metadata, and a restored transcript
starts a fresh one.

## 13. The event log

```rust
enum TranscriptEvent {
    Absorb { tag: Tag, n_scalars: usize },
    Challenge { tag: Tag },
}
```

Always on, and metadata only — the log never feeds the sponge, so it cannot
affect a challenge. `n_scalars` counts payload field elements: the scalar count
for `append_scalar`/`append_scalars`, the 31-byte chunk count for
`append_bytes`. The framing elements are not counted. Raw `observe` and `sample`
are not recorded; they are the layer below.
