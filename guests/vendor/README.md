# `guests/vendor`

Upstream crates, copied from their crates.io releases and patched so that a guest's library code
reaches a delegation ([delegation.md](../../docs/spec/delegation.md) §10). `guests/Cargo.toml`'s
`[patch.crates-io]` makes each copy the one every guest compiles; the root workspace has no such
table, so host builds — the native revm oracle in `crates/emulator/tests/revm.rs`,
`host::recorder`, `tools/kat-gen` — run upstream's code. Each crate is its release byte for byte
but for the files listed and its `Cargo.toml`, which adds a
`[target.'cfg(target_arch = "riscv32")'.dependencies]` entry on `guest-sdk`; cargo's `.cargo-ok`
and `Cargo.toml.orig` are not copied.

| crate | upstream | routes to | reached from |
| --- | --- | --- | --- |
| `k256` 0.13.4 | `RustCrypto/elliptic-curves` `5ac8f5d7` | `MOD_MUL` (`SECP256K1_P`, `SECP256K1_N`), `EC_ADD` | `0x01`; sender recovery |
| `ark-ff` 0.6.0 | `arkworks-rs/algebra` `d168323a` | `MOD_MUL` (`BN254_P`, `BN254_R`) | `ark-bn254`, in `0x06`–`0x08` |
| `revm-precompile` 43.0.2 | `bluealloy/revm` `30e94e47` | `SHA256_COMP`, `EC_ADD` | `0x02`, `0x06`, `0x07`; SSZ roots |

Every routed path is under `cfg(target_arch = "riscv32")`. A shim returning `false` is `-ENOSYS`,
an executor with no circuit, and the caller then runs upstream's code. The crates are compiled by
`guests/revm-block`, and by `guests/mod-mul-ops` and `guests/ec-ops`, which call `k256` and
`ark-bn254` directly.

## `k256` 0.13.4

| file | change |
| --- | --- |
| `src/arithmetic/field/field_10x26.rs` | `FieldElement10x26::{mul, square}` call `apogee::mul_mod_p`, with `mul_inner` the fallback; `to_words`, `from_words`; private `mod apogee`: `packable`, `pack`, `unpack`, `operand`, `mul_mod_p` |
| `src/arithmetic/field.rs`, `src/arithmetic/field/field_impl.rs` | `to_words` and `from_words` on `FieldElement` and the debug wrapper, forwarding |
| `src/arithmetic/scalar.rs` | `Scalar::mul` calls `apogee::mul_mod_n`; `square` is `self.mul(self)` upstream |
| `src/arithmetic/projective.rs` | `ProjectivePoint::{add, add_mixed, double}` call `apogee::{add, add_mixed, double}` (`guest_sdk::recursion::ec_add_complete`); upstream's bodies, unchanged, become the fallbacks `add_inner`, `add_mixed_inner`, `double_inner` |
| `src/arithmetic/mul.rs` | `LookupTable::select` indexes (`apogee::select`), upstream's scan kept off-target as `select_inner`; on every target, `lincomb` borrows its tables where upstream copies them on each of 33 passes |

- **Values, not representations.** A delegated product is the canonical residue, where upstream's
  is weakly normalized. `k256`'s point equalities test `normalizes_to_zero` of a difference, and
  `to_bytes` and `to_affine` normalize first.
- **The operand bound.** `MOD_MUL` and `EC_ADD` refuse an operand at or above the modulus. A field
  element is ten 26-bit limbs, below `2^259`; `operand` packs it into eight 32-bit words as it
  stands when it is below `2^256` (`packable`: limbs 0–8 below `2^26`, limb 9 below `2^22`,
  exactly) and below `p` (`!get_overflow()`), and normalizes it first otherwise. `packable` alone
  would pass `p`'s own limb pattern, upstream's second zero, which the complete formulas produce.
  Delegated results are canonical, so a chain of multiplications normalizes nothing. A `Scalar`
  is below `n` by its type, and its `u32` words are the frame's.
- **Points.** Upstream's `add` is Renes–Costello–Batina Algorithm 7 in homogeneous projective
  coordinates, and so is `EC_ADD`: the delegated sum is upstream's projective representative,
  normalized. Being complete, it doubles too, so `double` is `P + P`; its fallback stays
  Algorithm 9. `add_mixed` keeps upstream's identity correction: the affine identity `(0, 0)`
  lifts to `(0 : 0 : 1)`, neither the identity nor a curve point.
- **`select`** returns upstream's representative, in time that depends on the digit.
- **Both field types route**: the debug wrapper (`field_impl.rs`, under `debug_assertions`) and
  the bare 10×26 element multiply through `FieldElement10x26::mul`. A release guest has the bare
  one, `guests/Cargo.toml` turning dependencies' debug assertions off at `--release`.

## `ark-ff` 0.6.0

| file | change |
| --- | --- |
| `src/fields/models/fp/montgomery_backend.rs` | an inherent `impl MontBackend<T, N>` with `const APOGEE: Option<(u32, [u32; 8])>`; `FpConfig::{mul_assign, square_in_place}` call `apogee::mont_mul` when it is `Some`; private `mod apogee` |

- **Which fields.** `APOGEE` is computed at compile time from `T::MODULUS`:
  `(BN254_P, BN254_P_R_INV)` or `(BN254_R, BN254_R_R_INV)` for a four-limb field with BN254's
  base or scalar modulus, `None` for every other, `ark-bls12-381`'s included. `ark-bn254`'s
  `#[derive(MontConfig)]` generates its own multiply, so the patch sits below it, where it also
  covers `Fq2`, `Fq6` and `Fq12`.
- **Two calls a multiplication.** arkworks holds `x·R`, `R = 2^256 mod m`, and multiplies to
  `â·b̂·R⁻¹`; the delegation multiplies residues. `mont_mul` computes `t = â·b̂ mod m`, then
  `t·R⁻¹ mod m`, `R⁻¹` a literal of `constants::mod_mul`: the canonical representative arkworks
  returns. Both operands of both calls are below `m`. `a` is written only after both answer.

## `revm-precompile` 43.0.2

| file | change |
| --- | --- |
| `src/interface.rs` | the default bodies of `Crypto::sha256` (`guest_sdk::sha256`), `Crypto::bn254_g1_add` and `Crypto::bn254_g1_mul` take the delegated path; no type or implementation is added |
| `src/bn254/arkworks.rs` | `g1_point_add_delegated`, `g1_point_mul_delegated`, and private `mod apogee`, the point conversion; nothing existing changes |

- **Upstream's parsing.** The two functions call the crate-private `read_g1_point` and
  `encode_g1_point`, so the code that does it on the host refuses a coordinate at or above `q` or
  a point off the curve, and reads `(0, 0)` as infinity. Only the group law is delegated:
  `guest_sdk::ec_add`, and `guest_sdk::ec_mul`, double-and-add over it from the top bit.
- **Coordinates.** arkworks' `Projective` is Jacobian, the delegation's homogeneous: an affine
  point lifts to `Z = 1`, the infinity to `(0 : 1 : 0)`, and `(X, Y, Z)` returns as
  `(X·Z, Y·Z², Z)`. Coordinates cross as canonical integers (`into_bigint`).
- **One implementation.** Patching default bodies keeps `DefaultCrypto` the only `Crypto`
  ([ethereum.md](../../docs/spec/ethereum.md) §1). `0x08` stays `ark-bn254`'s pairing, its field
  multiplications routed by the `ark-ff` patch.

A delegated result and upstream's agree in value, so no check inside a guest sees whether a seam
routes. `crates/emulator/tests/guests.rs` pins `guests/mod-mul-ops`' invocation counts: `MOD_MUL`'s,
to which the three `MOD_MUL` seams contribute different amounts, and `EC_ADD`'s, which the guest
reaches only through `k256`'s projective patch.
