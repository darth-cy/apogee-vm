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
- **`from_bytes` rejects, never reduces.** A value `>= p` returns `None`. So does
  `from_hex`, for the same reason and with the same discipline.
- **`batch_inverse` maps zero to zero.** Zeros are skipped, not an error.
- **`#![no_std]`, plain stable Rust, `u128` intermediates only.** No carry
  intrinsics, no assembly, no nightly, no `unsafe`. It compiles unchanged for
  `riscv32imac-unknown-none-elf`; CI-equivalent check:
  `cargo build -p field -p constants --target riscv32imac-unknown-none-elf`.

## Wire format
Canonical (non-Montgomery) 32-byte little-endian, per master rule 3. `Fr::ONE`
serializes to `01` followed by 31 zero bytes — the test that proves the Montgomery
representation is not leaking. `Debug` prints the same value in big-endian hex, which
is the human reading order and deliberately not the byte order.

## Source literals
`from_hex` is the second, deliberately separate crossing: `0x` plus exactly 64 lowercase
hex digits, read **big-endian**, `None` for anything else or for a value `>= p`. It is
for frozen constant tables in source — the order `Debug` prints, and the order upstream
tables such as the Poseidon2 round constants are written in, so a vendored table diffs
against its source by eye. There is exactly one accepted spelling, so a mistyped constant
fails at its `expect` rather than becoming a different field element. It is a runtime
function: `Fr` has no compile-time constructor, and adding one would have meant editing
the S01 multiplier, which this stage deliberately did not do.

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
| `tests/common/mod.rs` | Sampling an `Fr` by rejection, and the arkworks bridge. Test-only. |
| `tools/test-support` | The seeded RNG, hex, and the SHA-256 behind the fixture pin. Shared. |

## Fixtures
`tests/vectors/fr_kats.txt` — 536 known-answer vectors generated from ark-bn254.
Refresh is manual and deliberate:

```
cargo run -p kat-gen                  # rewrites the file in place
shasum -a 256 crates/field/tests/vectors/fr_kats.txt
```

then update `KAT_SHA256` in `tests/kat.rs`. The generator is deterministic: rerunning
it without changing arkworks reproduces the file byte for byte.

## The guest-target backend (S23)

`Fr`'s `add_limbs`, `mont_mul` and `inverse` route through
`guest_sdk::recursion::fr_arith` under `#[cfg(target_arch = "riscv32")]`, and fall back to
the code below them when the executor answers `-ENOSYS`. `docs/spec/delegation.md` §13 is
the ABI.

- **It is a target dependency, not a cargo feature.**
  `[target.'cfg(target_arch = "riscv32")'.dependencies] guest-sdk` — the workspace still has
  one build configuration, a host build never resolves the edge, and master anti-goal 1
  stands. The direction is forced: cargo refuses the cycle, so `guest-sdk` cannot name `Fr`.
- **The fallback is this crate's own code**, one branch below the ecall, so the delegated
  path and the software path are one definition rather than two held equal by a test.
- **`to_memory_bytes` / `from_memory_bytes` are the frame's codec and exist for this caller
  alone.** They are the four Montgomery limbs written out, which is a canonical little-endian
  encoding of the element `x·R`; everything that is not the delegation uses `to_bytes`.
  They are limb copies, which is what keeps a delegated multiply from recursing into itself.
- **`inverse` never asks the delegation for `inverse(0)`.** `None` is this crate's answer and
  `0` is the frame ABI's, and the two are reconciled here.
