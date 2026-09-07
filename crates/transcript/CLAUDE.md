# `crates/transcript`

## What this crate owns
The Poseidon2 permutation and the duplex transcript, and nothing else. Every challenge
in the protocol is drawn through `Transcript`; there is no other source of randomness.

The full specification is `docs/spec/transcript.md`. This file is the summary a reader
needs before touching the code.

## Frozen invariants
- **The construction is frozen.** Width 3, rate 2, capacity 1, `x^5`, 4 initial full
  rounds / 56 partial rounds / 4 terminal full rounds, partial-round S-box on lane 0,
  upstream `RC3` constants. Changing any of it is a protocol-version change. The constants
  live in `constants` as upstream's hex literals and are decoded by `Fr::from_hex` on every
  call; the measured cost of that is in `docs/decisions.md`.
- **Overwrite absorption, zero pad, length tag.** A duplex step with `n > 0` pending
  elements overwrites the first `n` rate lanes, zero-fills the rest, and adds `n` to
  the capacity. A step with nothing pending leaves the rate alone and adds nothing —
  it is a pure squeeze. This is what separates transcript cases D and E.
- **Challenges leave the rate from the end.** The first `sample` after an absorb is
  `state[1]`, the second is `state[0]`.
- **`observe` invalidates buffered output.** A challenge can never predate material
  absorbed before it was read.
- **Buffer lanes at or past their length are zero.** The duplex never reads them; the
  invariant is what makes a snapshot canonical, and serde enforces it on the way in.
- **Typed framing is `tag, length, payload`,** with no message-kind field. Injectivity
  therefore rests on **one tag, one message kind** — see `constants::transcript_tags`.
- **The event log is metadata.** It never feeds the sponge, and it is not part of a
  snapshot.
- **`#![no_std]`, forever.** The recursion guest links this crate. CI-equivalent check:
  `cargo build -p field -p constants -p transcript --target riscv32imac-unknown-none-elf`.

## Wire formats
- Field elements: canonical 32-byte little-endian, via `Fr`, per master rule 3.
- `TranscriptSnapshot`: a fixed 226 bytes — `state[3]`, `input[2]`, `input_len: u8`,
  `output[2]`, `output_len: u8`. Serde is hand-written, so no derive macro enters the
  build, and deserialisation rejects any state `snapshot` could not have produced.

## Tests
| File | Covers |
| --- | --- |
| `tests/poseidon2.rs` | Vendored `RC3` vs upstream; the `[0,1,2]` KAT; 128 reference permutation vectors; negative controls. |
| `tests/duplex.rs` | Cases A-E and the rest replayed from file; the tag table and the one-tag-one-kind rule; output order; squeeze repetition; typed-layer separation; the byte encoding; the event log; negative controls. |
| `tests/snapshot.rs` | The 20-operation script snapshotted at operation 10; byte round trip; malformed-snapshot rejection. |
| `tests/common/mod.rs` | Fixture pinning, the vector reader, the case replayer. Test-only. |
| `tools/test-support` | The seeded RNG, hex, and the SHA-256 behind the pin. Shared. |

## Fixtures
`tests/vectors/` holds three committed files, all produced by the reference oracle and
pinned by SHA-256 in the tests. **`crates/transcript` never generates its own expected
values**; that is what makes the tests a differential rather than a self-oracle. The
oracle transcribes `docs/spec/transcript.md` over Plonky3's Poseidon2, and asserts on
every raw operation that its transcription agrees with Plonky3's own `DuplexChallenger`
— so a run that succeeds has checked the spec text and the reference type against each
other before a single vector is written.

```
cargo run --manifest-path tools/transcript-ref/Cargo.toml   # rewrites all three in place
shasum -a 256 crates/transcript/tests/vectors/*.txt
```

then update the pinned digests in `tests/poseidon2.rs` and `tests/duplex.rs`. The
generator is deterministic: rerunning it against the same pinned revisions reproduces
the files byte for byte, which is what CI checks.

`tools/transcript-ref` is deliberately **not** a workspace member — its Plonky3 and
`zkhash` dependency graphs would hand `serde/std` to `crates/field` through cargo's
feature unification during `cargo test --workspace`. The reason is in its manifest and
in `docs/decisions.md`. It has exactly one path dependency back into the repository,
`tools/test-support`, for the seeded RNG that picks its inputs; that crate declares no
dependencies of its own and has a test that keeps it that way, so the edge cannot reach
anything the oracle is supposed to be an independent witness to.
