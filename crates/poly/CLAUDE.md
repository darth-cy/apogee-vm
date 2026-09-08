# `crates/poly`

## What this crate owns
`MultilinearPoly` — a table of `2^n` `Fr` evaluations over the boolean hypercube —
its small-type backing, `bind`/`evaluate`, and the `eq` machinery. Nothing else.
Sumcheck, gates and layers live in later crates and are built on this one.

## The index convention (frozen)
**Variable `j` is bit `j` of the index.** The evaluation at `y = (y_0, ..., y_{n-1})`
sits at `index = sum_j y_j * 2^j`, so indexing is little-endian and variable 0 is the
low bit. For `n = 3`, `get(0b011)` is the evaluation at `y_0 = 1, y_1 = 1, y_2 = 0`.

`bind(r)` fixes **variable 0**, halving the table by
`f'(i) = f(2i) + r * (f(2i+1) - f(2i))`. The old variable 1 becomes the new variable 0,
so binding `r_0, r_1, ...` in that order fixes the variables in order and leaves
`evaluate(&[r_0, r_1, ...])` alone in the last cell. `evaluate(point)` reads
`point[j]` as variable `j` and is the same fold done non-destructively.

`eq(r, y) = prod_j (r_j y_j + (1 - r_j)(1 - y_j))`. `eq_table(r)` is that function
tabulated over the cube under the same index convention; `eq_eval(r, y)` is the closed
form, off the cube in both arguments.

Every later circuit stage builds on this. It is checked against arkworks'
`DenseMultilinearExtension` — which uses the same order — in `tests/differential.rs`,
on both `evaluate` and `bind`.

## Frozen invariants
- **One concrete type, one enum.** No trait-generic polynomial abstraction exists in
  the workspace, now or later. `MultilinearPoly` is a struct and `PolyBacking` is a
  plain `enum`.
- **The lift is bind-triggered, never read-triggered.** `get` and `evaluate` lift on
  the fly and leave the backing alone; the first `bind` lifts the whole table to
  `PolyBacking::Fr`, and after any `bind` the backing is `Fr` forever. There are never
  two representations of one polynomial.
- **Lift is the canonical embedding.** A `U1` bit becomes `Fr::ZERO` or `Fr::ONE`; a
  `U8`/`U16`/`U32` word becomes `Fr::from_u64` of its value. One definition, in
  `PolyBacking::entry`, used by every read and by the lift itself.
- **`U1` is a bitset.** `Vec<u64>` limbs plus an entry count; entry `i` is bit `i % 64`
  of limb `i / 64`, little-endian to match the index convention. The count is a power
  of two, there are exactly `count.div_ceil(64)` limbs, and the bits past the count in
  the final limb are zero. `MultilinearPoly::new` enforces all three.
- **Loud errors, no `Result`.** A non-power-of-two `new`, a malformed `U1`, a `get`
  past the table, a `bind` with no variables left, a `point` of the wrong length and an
  `eq_eval` length mismatch all panic with a message naming the invariant. The frozen
  signatures return values, so a data error here is a programmer error.
- **`#![no_std]` + `alloc`, forever.** The recursion guest links this crate.
  CI-equivalent check:
  `cargo build -p field -p constants -p transcript -p poly --target riscv32imac-unknown-none-elf`.

## Wire formats
None. This crate never serialises: a polynomial is an in-memory object, and the only
`Fr` values that cross a boundary do so through `crates/field`'s canonical little-endian
form. The committed fixtures are the exception and are described below.

## Tests
| File | Covers |
| --- | --- |
| `tests/kats.rs` | The committed 10-variable fixture: bind chain, 20 evaluations, `eq_table` prefixes; the corrupted- and malformed-file controls. |
| `tests/differential.rs` | 100 seeded polys at `n <= 12` against the committed arkworks answers, a naive `eq_eval` sum, and `ark-poly` in-process; `bind` against `fix_variables`. |
| `tests/backing.rs` | All 256 three-variable bit tables exhaustively, seeded-random wider tables, the width edges, and the laziness of the lift. |
| `tests/conventions.rs` | The index convention as a literal, bind/evaluate consistency, the `eq` machinery, and every panic. |
| `tests/common/mod.rs` | The vector reader, the corpus rebuild rule, bit packing, the arkworks bridge. Test-only. |
| `tools/test-support` | The seeded RNG, hex, and the SHA-256 behind the fixture pin. Shared. |

## Fixtures
`tests/vectors/` holds two committed files, both produced by `tools/kat-gen` against
`ark-poly` and pinned by SHA-256 in the test that reads them. **This crate never
generates its own expected values.**

- `poly_kats.txt` — one fixed seeded 10-variable `u32`-backed polynomial: the source
  table, ten bind challenges, the table after each bind (from `fix_variables`), 20
  evaluation points and their results (from `evaluate`), and `eq_table` on the
  challenge prefixes `r[..k]` for `k <= 6` (from the direct product formula).
- `evaluate_diff.txt` — 100 cases, case `i` having `i % 13` variables and backing
  `["u1","u8","u16","u32","fr"][i % 5]`. The tables are **not** written out; at 100
  cases of up to 4096 entries that is a megabyte of hex. Each case instead carries a
  SHA-256 digest of its lifted table, and the test rebuilds the table from the seeded
  draw rule the file header documents. A rebuild that differs by one entry fails on the
  digest before it ever reaches an answer.

```
cargo run -p kat-gen                       # rewrites both in place
shasum -a 256 crates/poly/tests/vectors/*.txt
```

then update `KATS_SHA256` in `tests/kats.rs` and `DIFF_SHA256` in `tests/differential.rs`.
The generator is deterministic: rerunning it without changing arkworks reproduces both
files byte for byte, which is what CI's regenerate-and-diff step checks.
