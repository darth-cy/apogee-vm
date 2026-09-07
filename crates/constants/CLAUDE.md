# `crates/constants`

## What this crate owns
Every frozen numeric constant and domain-separation tag in the protocol, and nothing
else. If a later stage needs a magic number that outlives one function, it belongs
here.

## Frozen invariants
- **Zero logic, forever.** Constant items and doc comments only: no functions, no
  `const fn`, no traits, no macros, no tests, no dependencies. A test that checks a
  constant lives in the crate that consumes it (see `crates/field/tests/constants_check.rs`).
- **`#![no_std]`, forever.** Guest-side code links this crate.
- Changing any value here is a protocol-version change and must bump
  `PROTOCOL_VERSION`.

## Contents as of S02
| Item | Meaning |
| --- | --- |
| `PROTOCOL_VERSION: u32` | Placeholder, `0`. First item absorbed into every transcript. |
| `FR_MODULUS: [u64; 4]` | BN254 **scalar** field modulus `p`, little-endian limbs. |
| `FR_MODULUS_MINUS_TWO: [u64; 4]` | `p - 2`, the Fermat exponent for inversion. |
| `FR_R: [u64; 4]` | `2^256 mod p`. Also the Montgomery form of `1`. |
| `FR_R2: [u64; 4]` | `2^512 mod p`. Converts canonical → Montgomery in one multiply. |
| `FR_INV: u64` | `-p^{-1} mod 2^64`, the CIOS reduction multiplier. |
| `POSEIDON2_RC3_INITIAL: [[[u64; 4]; 3]; 4]` | Round constants, 4 initial full rounds. |
| `POSEIDON2_RC3_INTERNAL: [[u64; 4]; 56]` | Round constants, 56 partial rounds, lane 0. |
| `POSEIDON2_RC3_TERMINAL: [[[u64; 4]; 3]; 4]` | Round constants, 4 terminal full rounds. |
| `transcript_tags` | The frozen tag table: 7 tags as of S02, sequential from 1. |

`FR_MODULUS_MINUS_TWO` is an additive extension beyond S01's enumerated list; it is a
property of the modulus and belongs next to it.

The `POSEIDON2_RC3_*` tables are the upstream HorizenLabs `RC3` constants, canonical
little-endian limbs, split by the permutation phase that reads them; their provenance and
the reason the partial rounds store one lane are in the source comment.
`crates/transcript/tests/poseidon2.rs` checks them against a committed dump of the full
upstream table rather than trusting the transcription.

Tags are sequential from 1, never renumbered, never reused, and `0` is not a tag. Every
tag names exactly **one** message kind — scalars, bytes or a challenge — because the
typed layer's `tag, length, payload` framing is only injective under that rule. See
`docs/spec/transcript.md` section 8.
