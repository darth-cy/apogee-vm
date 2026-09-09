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

## Contents as of S05
| Item | Meaning |
| --- | --- |
| `PROTOCOL_VERSION: u32` | Placeholder, `0`. First item absorbed into every transcript. |
| `FR_MODULUS: [u64; 4]` | BN254 **scalar** field modulus `p`, little-endian limbs. |
| `FR_MODULUS_MINUS_TWO: [u64; 4]` | `p - 2`, the Fermat exponent for inversion. |
| `FR_R: [u64; 4]` | `2^256 mod p`. Also the Montgomery form of `1`. |
| `FR_R2: [u64; 4]` | `2^512 mod p`. Converts canonical → Montgomery in one multiply. |
| `FR_INV: u64` | `-p^{-1} mod 2^64`, the CIOS reduction multiplier. |
| `FQ_MODULUS: [u64; 4]` | BN254 **base** field modulus `q`, little-endian limbs. |
| `FQ_MODULUS_MINUS_TWO: [u64; 4]` | `q - 2`, the Fermat exponent for inversion. |
| `FQ_MODULUS_PLUS_ONE_DIV_FOUR: [u64; 4]` | `(q+1)/4`, the square-root exponent (`q = 3 mod 4`). |
| `FQ_R`, `FQ_R2`, `FQ_INV` | Fq's Montgomery radix, its square, and the CIOS multiplier. |
| `FQ2_NONRESIDUE: &str` | `q - 1`, so `Fq2 = Fq[u]/(u^2+1)`. |
| `FQ6_NONRESIDUE_C0/_C1: &str` | `xi = 9 + u`, the Fq6 nonresidue. Reserved for the pairing stage. |
| `G1_B: &str` | `3`: `E/Fq: y^2 = x^3 + 3`. |
| `G2_B_C0/_C1: &str` | `3/xi = 3/(9+u)`: the D-type sextic twist. |
| `G1_GENERATOR_X/_Y: &str` | The standard G1 generator `(1, 2)`. |
| `G2_GENERATOR_X_C0/_C1`, `_Y_C0/_C1: &str` | EIP-197's G2 generator, coordinate for coordinate. |
| `POSEIDON2_RC3_INITIAL: [[&str; 3]; 4]` | Round constants, 4 initial full rounds. |
| `POSEIDON2_RC3_INTERNAL: [&str; 56]` | Round constants, 56 partial rounds, lane 0. |
| `POSEIDON2_RC3_TERMINAL: [[&str; 3]; 4]` | Round constants, 4 terminal full rounds. |
| `transcript_tags` | The frozen tag table: 9 tags as of S04, sequential from 1. |

`FR_MODULUS_MINUS_TWO` is an additive extension beyond S01's enumerated list; it is a
property of the modulus and belongs next to it. The same reasoning puts
`FQ_MODULUS_MINUS_TWO` and `FQ_MODULUS_PLUS_ONE_DIV_FOUR` beside `FQ_MODULUS`.

The Fq tower and curve parameters are **hex string literals read big-endian** by
`curve::Fq::from_hex`, the same one accepted spelling `field::Fr::from_hex` defines, so each
diffs against EIP-197 and arkworks-bn254 by eye. Their Montgomery-form counterparts live
privately in `crates/curve` — a `const GENERATOR` needs limbs at const-evaluation time and
`from_hex` is not a `const fn` — and every one of them is pinned against the canonical hex
here by `crates/curve/tests/constants_check.rs`.

The `POSEIDON2_RC3_*` tables are the upstream HorizenLabs `RC3` constants as **hex string
literals, copied from upstream character for character**, split by the permutation phase
that reads them. `field::Fr::from_hex` reads them big-endian, as upstream writes them, so
the vendored table diffs against its source by eye. Their provenance and the reason the
partial rounds store one lane are in the source comment, and
`crates/transcript/tests/poseidon2.rs` checks them against a committed dump of the full
upstream table rather than trusting the transcription — which is also where the two
textual conventions meet, since the dump is little-endian canonical bytes.

Tags are sequential from 1, never renumbered, never reused, and `0` is not a tag. Every
tag names exactly **one** message kind — scalars, bytes or a challenge — because the
typed layer's `tag, length, payload` framing is only injective under that rule. See
`docs/spec/transcript.md` section 8.
