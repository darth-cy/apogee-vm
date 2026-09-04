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

## Contents as of S01
| Item | Meaning |
| --- | --- |
| `PROTOCOL_VERSION: u32` | Placeholder, `0`. First item absorbed into every transcript. |
| `FR_MODULUS: [u64; 4]` | BN254 **scalar** field modulus `p`, little-endian limbs. |
| `FR_MODULUS_MINUS_TWO: [u64; 4]` | `p - 2`, the Fermat exponent for inversion. |
| `FR_R: [u64; 4]` | `2^256 mod p`. Also the Montgomery form of `1`. |
| `FR_R2: [u64; 4]` | `2^512 mod p`. Converts canonical → Montgomery in one multiply. |
| `FR_INV: u64` | `-p^{-1} mod 2^64`, the CIOS reduction multiplier. |
| `transcript_tags` | Empty module. Every future domain-separation tag goes here. |

`FR_MODULUS_MINUS_TWO` is an additive extension beyond the stage's enumerated list; it
is a property of the modulus and belongs next to it.
