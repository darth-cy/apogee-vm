# `crates/field`

## What this crate owns
`Fr`, the BN254 scalar field, and nothing else. Arithmetic, the canonical wire form,
and `batch_inverse`.

## Frozen invariants
- **`Fr` is a concrete struct.** No `F: Field` generic exists anywhere in the
  workspace, now or later.
- **The limbs are always reduced.** Every constructor and every operator returns a
  value in `[0, p)`, in Montgomery form. That is what makes the derived `PartialEq`
  correct; nothing may create an unreduced `Fr`.
- **Montgomery form never escapes memory.** `to_bytes` and `from_bytes` are the only
  wire path, and `Debug` and the serde impls both route through them.
- **`from_bytes` rejects, never reduces.** A value `>= p` returns `None`.
- **`batch_inverse` maps zero to zero.** Zeros are skipped, not an error.
- **`#![no_std]`, portable stable Rust, `u128` intermediates only.** No carry
  intrinsics, no assembly, no nightly, no `unsafe`. It compiles unchanged for
  `riscv32imac-unknown-none-elf`; CI-equivalent check:
  `cargo build -p field -p constants --target riscv32imac-unknown-none-elf`.

## Wire format
Canonical (non-Montgomery) 32-byte little-endian, per master rule 3. `Fr::ONE`
serializes to `01` followed by 31 zero bytes — the test that proves the Montgomery
representation is not leaking. `Debug` prints the same value in big-endian hex, which
is the human reading order and deliberately not the byte order.

## Algorithms
- Multiplication: CIOS Montgomery (Koç–Acar–Kaliski), four limbs, `u128`
  limb-product intermediates. With reduced operands the accumulator stays below `2p`,
  and `2p < 2^255`, so it never spills past the fourth limb and one conditional
  subtraction reduces the result.
- Inversion: Fermat, `pow(p-2)` through the frozen `pow`.
- `batch_inverse`: Montgomery's trick over the nonzero entries.

## Tests
| File | Covers |
| --- | --- |
| `tests/kat.rs` | The committed vector file, its SHA-256 pin, and the negative control. |
| `tests/differential.rs` | 1,000 seeded random inputs per operator against ark-bn254. |
| `tests/edge_cases.rs` | `0`, `1`, `p-1`, `R`, `R²` for every op; wire rules; `batch_inverse`. |
| `tests/constants_check.rs` | Re-derives every frozen constant instead of trusting it. |
| `tests/common/mod.rs` | Seeded RNG, hex, arkworks bridge, SHA-256. Test-only. |

## Fixtures
`tests/vectors/fr_kats.txt` — 536 known-answer vectors generated from ark-bn254.
Refresh is manual and deliberate:

```
cargo run -p kat-gen                  # rewrites the file in place
shasum -a 256 crates/field/tests/vectors/fr_kats.txt
```

then update `KAT_SHA256` in `tests/kat.rs`. The generator is deterministic: rerunning
it without changing arkworks reproduces the file byte for byte.
