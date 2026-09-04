# S01 — Fr Field (with Montgomery) + Constants Skeleton

Branch `s01-field`. Status: complete, all acceptance items met.

## Frozen public API, as built

```rust
// crates/field/src/lib.rs   (#![no_std], extern crate alloc)
pub struct Fr(/* private [u64; 4], Montgomery form, always reduced to [0, p) */);

impl Fr {
    pub const ZERO: Fr;
    pub const ONE: Fr;
    pub const MINUS_ONE: Fr;                        // p - 1; S11 padding sentinel

    pub fn from_u64(x: u64) -> Fr;
    pub fn square(&self) -> Fr;
    pub fn pow(&self, exp: &[u64; 4]) -> Fr;        // exp is a plain 256-bit LE integer
    pub fn inverse(&self) -> Option<Fr>;            // None for zero
    pub fn to_bytes(&self) -> [u8; 32];             // canonical LE
    pub fn from_bytes(b: &[u8; 32]) -> Option<Fr>;  // None if >= p; never reduces
}

pub fn batch_inverse(xs: &mut [Fr]);                // zero entries stay zero

// Derives:  Clone, Copy, PartialEq, Eq
// Manual :  Debug (canonical big-endian hex), serde::Serialize, serde::Deserialize
// Operators: Add, Sub, Mul for all four owned/by-ref combinations;
//            AddAssign, SubAssign, MulAssign for Fr and &Fr; Neg for Fr and &Fr.
```

```rust
// crates/constants/src/lib.rs   (#![no_std], zero logic)
pub const PROTOCOL_VERSION: u32 = 0;
pub const FR_MODULUS: [u64; 4];
pub const FR_MODULUS_MINUS_TWO: [u64; 4];
pub const FR_R: [u64; 4];       // 2^256 mod p, also the Montgomery form of 1
pub const FR_R2: [u64; 4];      // 2^512 mod p
pub const FR_INV: u64;          // -p^{-1} mod 2^64
pub mod transcript_tags {}      // empty
```

## What this freezes for every later stage
1. **`Fr` semantics.** A concrete struct, `Copy`, always reduced, Montgomery in memory.
   No `F: Field` generic exists or will exist. `pow`'s exponent is a plain 256-bit
   integer, not a field element, and is not reduced. `x^0 == ONE` for every `x`.
2. **The canonical-LE wire rule.** Field elements in files, artifacts and transcripts
   are the 32-byte little-endian canonical integer. `to_bytes`/`from_bytes` are the
   only crossing, `from_bytes` rejects `>= p` with `None` and never silently reduces,
   and serde routes through both. `Debug` prints the canonical value big-endian, which
   is a human reading order and deliberately not the byte order.
3. **The `batch_inverse` zero convention.** Zeros stay zero; they are skipped, never an
   error. Callers relying on padding rows can pass zero-padded slices safely.
4. **`crates/constants` is the home of every future frozen constant and tag.** Zero
   logic, `#![no_std]`, and `transcript_tags` is where domain-separation tags go.

## Artifacts
| Path | What |
| --- | --- |
| `crates/field/tests/vectors/fr_kats.txt` | 536 known-answer vectors from ark-bn254 0.6 |
| `tools/kat-gen/src/main.rs` | Deterministic regenerator (`cargo run -p kat-gen`) |
| `tools/bench/src/main.rs` | Comparative microbenchmark (`cargo run --release -p bench`) |

`fr_kats.txt` SHA-256 `cfb9db2443dc6d803104f7d89924235bcb2fa56cf6cfc04fc2e24cd31d0ce1df`,
pinned in `tests/kat.rs::KAT_SHA256`. Refresh is manual: rerun the generator, re-hash,
update the constant. Verified reproducible — rerunning the generator produced a
byte-identical file.

Vector format is one whitespace-delimited line per case, values as 64 lowercase hex
characters in little-endian byte order (`add|sub|mul a b c`, `square|inv a c`,
`pow a e c`; `inv` of zero has the expected field `none`). The stage allowed "or
similar committed format"; the reason for text over JSON is in `docs/decisions.md`.

## Verification performed
- 33 tests, all green in both debug and release: 536 KATs, 1,000 seeded random inputs
  per operator against ark-bn254 in-process (add, sub, mul, neg, square, inverse, pow,
  from_u64, wire roundtrip, batch_inverse, operator forms), the full edge matrix
  `{0, 1, p-1, R, R²}²` for every operator, wire-canonicity rejection, serde roundtrip
  and serde rejection, and `batch_inverse` at lengths 0/1/2/1000 in all-zero,
  all-nonzero and interleaved shapes plus seven boundary shapes.
- Negative control (`corrupted_kats_are_rejected`) proves the KAT harness fails on a
  bit-flipped expected value, on a truncated line, and on an unknown operator — for
  every operator, not just one.
- Every frozen constant is re-derived in `tests/constants_check.rs` rather than
  trusted: the modulus against `ark_bn254::Fr::MODULUS` and against the master
  prompt's decimal from both sides, `R` and `R²` as `2^256` and `2^512 mod p`,
  `FR_INV` by `p · FR_INV ≡ -1 mod 2^64`, `p-2`, and `MINUS_ONE` three ways.
- The CIOS limb sequence was additionally transcribed into a Python model and checked
  against bignum arithmetic over 225 structured pairs and 20,000 random pairs: zero
  mismatches, no `u128` intermediate ever exceeded its bound, the accumulator never
  spilled past the fourth limb, and the pre-reduction value was always `< 2p` — which
  is what makes the single conditional subtraction sufficient.
- `cargo clippy --workspace --all-targets` is warning-free with no `#[allow]` in
  library code (one in a test, on the function whose subject is by-ref operators).
- `cargo build -p field -p constants --target riscv32imac-unknown-none-elf` succeeds,
  satisfying must-be-exact 10.

## Bench (acceptance 8, non-blocking)
`cargo run --release -p bench`, Apple Silicon (aarch64-apple-darwin), rustc 1.96.1,
best of 3, n = 2²⁰ (inverse n = 2¹⁴). Internal numbers; no public claims.

| op | ours (ns) | arkworks (ns) | ratio |
| --- | ---: | ---: | ---: |
| mul | 9.33 | 8.16 | **1.14** |
| square | 8.69 | 7.67 | 1.13 |
| inverse | 3864.34 | 2039.10 | 1.90 |
| batch_inverse / element | 31.46 | 29.67 | 1.06 |

The stage's target is own **mul** throughput within 2× of arkworks: measured **1.14×**,
met, nothing to flag. Inversion is 1.90× because the stage pins Fermat while arkworks
uses a binary GCD; still inside 2×, and `batch_inverse` amortizes it to 1.06×.

## Additive extensions (everything added beyond the stage's literal list)
1. `constants::FR_MODULUS_MINUS_TWO` — the Fermat exponent. A property of the modulus;
   it belongs beside it rather than as a literal inside `field`.
2. `Neg` for `Fr` and `&Fr`. The stage names "Add/Sub/Mul/Neg operator impls".
3. `rust-toolchain.toml` pinning 1.96.1 plus the guest target — required by the master
   prompt's stable-only rule and by must-be-exact 10.
4. `.gitignore` (`/target`, `.DS_Store`).
5. `tools/kat-gen` — the stage offers "dev-dependency or `tools/` generator"; the
   explicit binary makes regenerate-and-diff a one-liner.
6. Test-only SHA-256 in `crates/field/tests/common/mod.rs`, ~55 lines, itself checked
   against the two NIST vectors. Implements master rule 11's "fixtures pinned by hash"
   without adding a dependency.
7. `crates/field/tests/constants_check.rs` — not requested, but a wrong Montgomery
   constant is silent: every operation stays self-consistent while the field is the
   wrong one. This is the test that catches it.

## Deviations and notes for the reviewer
- **`serde` is taken with no features at all** (`default-features = false`, and nothing
  added back), in both the shipped graph and the test graph, so the tests exercise the
  same serde the guest links. `postcard` is likewise featureless in dev-dependencies and
  the roundtrip test uses `to_slice` into a stack buffer rather than `to_allocvec`; with
  postcard's `alloc` feature on, cargo's feature unification handed `serde/alloc` to
  `field` during tests only, which would have left the shipped configuration compiled
  but never executed. Anti-goal 1 bans cargo features;
  must-be-exact 8 and 10 require `field` and `constants` to be `no_std` and to build for
  the guest target, which serde's default `std` feature would prevent. Read as a
  dependency's feature selection rather than a build configuration of ours, there is no
  conflict — the workspace still has exactly one build configuration — but it is
  recorded here and in `docs/decisions.md` because it is the closest call in the stage.
- **arkworks is a normal dependency of `tools/kat-gen` and `tools/bench`**, not a
  dev-dependency, because a `bin` target cannot express one. Master rule 2 permits
  reference libraries as "dev-dependencies or fixture generators"; both tools are
  fixture/measurement harnesses and neither is reachable from the prover, the verifier,
  or a guest. In `crates/field` arkworks is strictly a dev-dependency.
- **CI was added at the user's request**, after the stage work was otherwise complete.
  S01 does not ask for CI and the anti-goals warn against extra CI machinery, so it is
  deliberately one job in one file with no matrix, no caching and no third-party
  actions: fmt, clippy (`-D warnings`), `cargo test --workspace`, the guest-target
  build that must-be-exact 10 requires, and the regenerate-and-diff of the committed
  fixtures that master rule 8 wants. The toolchain, its components and the guest target
  all come from `rust-toolchain.toml`, so CI cannot drift from the pin.
- **No conflicts between the master prompt and the stage prompt were found.**

## Open for the next stage
`PROTOCOL_VERSION` is `0` and `transcript_tags` is empty by design; the transcript stage
fills both. Nothing in S01 depends on either value.
