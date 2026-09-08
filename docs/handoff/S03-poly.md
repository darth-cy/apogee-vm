# S03 — Multilinear Polynomials + Small-Type Backing

Branch `s03-poly`. Status: complete, all 10 acceptance items met.

## Frozen public API, as built

```rust
// crates/poly/src/lib.rs   (#![no_std], extern crate alloc)

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolyBacking {
    /// The `Vec<u64>` limbs, then the entry count.
    U1(Vec<u64>, usize),
    U8(Vec<u8>),
    U16(Vec<u16>),
    U32(Vec<u32>),
    Fr(Vec<Fr>),
}

#[derive(Clone, Debug)]
pub struct MultilinearPoly { /* backing + num_vars, private */ }

impl MultilinearPoly {
    pub fn new(backing: PolyBacking) -> MultilinearPoly;
    pub fn num_vars(&self) -> usize;
    pub fn len(&self) -> usize;
    pub fn get(&self, index: usize) -> Fr;
    pub fn bind(&mut self, r: Fr);
    pub fn evaluate(&self, point: &[Fr]) -> Fr;
    pub fn backing(&self) -> &PolyBacking;
}

pub fn eq_table(r: &[Fr]) -> Vec<Fr>;
pub fn eq_eval(r: &[Fr], y: &[Fr]) -> Fr;
```

That is the stage's list exactly, with no additions. The library is 261 lines including
its documentation; there are no other public items, no traits, no macros, and no
dependencies beyond `crates/field`.

## The convention, in one paragraph

A polynomial in `n` variables is a table of `2^n` evaluations over `{0,1}^n`.
**Variable `j` is bit `j` of the index**, so the evaluation at `y = (y_0, ..., y_{n-1})`
sits at `index = sum_j y_j * 2^j`: indexing is little-endian and variable 0 is the low
bit. For `n = 3`, `get(0b011)` is the evaluation at `y_0 = 1, y_1 = 1, y_2 = 0`.
`bind(r)` fixes **variable 0**, the lowest bit, halving the table by
`f'(i) = f(2i) + r * (f(2i+1) - f(2i))`; the old variable 1 then becomes the new
variable 0, so binding `r_0, r_1, ...` in that order fixes the variables in that order.
`evaluate(point)` reads `point[j]` as variable `j` and is the same fold performed
non-destructively into a scratch table, returning `get(0)` when `num_vars` is 0; binding
all `n` variables to `point` therefore leaves exactly `evaluate(point)` in the single
remaining cell. `eq(r, y) = prod_j (r_j y_j + (1 - r_j)(1 - y_j))`; `eq_table(r)`
tabulates it over the cube under the same index convention, and `eq_eval(r, y)` is the
closed form, defined off the cube in both arguments and symmetric in them.

## What this freezes for every later stage

1. **The index convention above.** Every column, gate, layer and opening point in every
   later stage is indexed this way. It is checked against arkworks'
   `DenseMultilinearExtension`, which uses the same order, on both `evaluate` and
   `bind` — see the differential below.
2. **The lift is bind-triggered, never read-triggered.** `get` and `evaluate` lift on
   the fly and leave the backing untouched; the first `bind` lifts the whole table to
   `PolyBacking::Fr`, and after any `bind` the backing is `Fr` forever. No dual
   representation of one polynomial ever exists. `backing()` is the discriminant
   accessor acceptance 5 asks for: it is the only way to observe this, and it is
   deliberately the only one.
3. **Lift is the canonical embedding.** A `U1` bit becomes `Fr::ZERO`/`Fr::ONE`; a
   `U8`/`U16`/`U32` word becomes `Fr::from_u64` of its value. One definition, in
   `PolyBacking::entry`, used by every read and by the lift itself.
4. **The `U1` bitset shape.** `Vec<u64>` limbs plus an entry count; entry `i` is bit
   `i % 64` of limb `i / 64`, little-endian to match the index convention. The count is
   a power of two, there are exactly `count.div_ceil(64)` limbs, and the bits past the
   count in the final limb are zero. `new` enforces all three, and rejecting a malformed
   bitset there is what lets `entry` be a bare shift.
5. **Errors are panics.** The frozen signatures return values, so a bad `new`, a bad
   `get`, a `bind` with nothing left, a mis-sized `point` and an `eq_eval` length
   mismatch all panic with a message naming the invariant. Nothing in this crate returns
   `Result`.

## Artifacts

| Path | What |
| --- | --- |
| `crates/poly/tests/vectors/poly_kats.txt` | The fixed seeded 10-variable polynomial: source table, 10 bind challenges, the table after each bind, 20 evaluation points and results, `eq_table` on the challenge prefixes `r[..k]` for `k <= 6` |
| `crates/poly/tests/vectors/evaluate_diff.txt` | 100-case differential corpus, `n <= 12`, all five backings |
| `tools/kat-gen/src/poly.rs` | The generator; `cargo run -p kat-gen` rewrites both |
| `tools/bench/src/main.rs` | The acceptance-10 bench line |

Both files are pinned by SHA-256 in the test that reads them — `KATS_SHA256` in
`tests/kats.rs`, `DIFF_SHA256` in `tests/differential.rs`. The digests are deliberately
not repeated here: they are a function of the generator's seed and content, and a copy
in a handoff goes stale the first time either changes. Read them from the tests. Refresh
is manual:

```
cargo run -p kat-gen
shasum -a 256 crates/poly/tests/vectors/*.txt
```

then update the two constants. Verified reproducible — rerunning the generator produced
byte-identical files, and CI runs exactly that and diffs.

**`evaluate_diff.txt` does not store its tables.** 100 cases of up to 4096 entries is
about a megabyte of hex. Each case instead carries a SHA-256 digest of its *lifted*
table — 32 canonical little-endian bytes per entry, concatenated in index order — and
the test rebuilds the table from the seeded draw rule the file header documents. The
generator computes that digest from arkworks values through arkworks' own serialisation;
the test computes it from our `get`. So the digest is not a self-check: a rebuild that
differs by one entry, or a lift that embeds an integer wrongly, fails on the digest
before it ever reaches an answer. The one rule the two sides share is "four `u64` draws
read as a 256-bit little-endian integer mod p", which arkworks spells
`from_le_bytes_mod_order` and we spell as a Horner sum of `Fr::from_u64` limbs, because
`crates/field` deliberately has no reducing constructor;
`the_corpus_rebuild_rule_matches_the_arkworks_reduction` holds the two to each other
over 1,000 draws rather than assuming it.

## Verification performed

113 workspace tests, green in debug and release (74 from S01/S02, unchanged; 39 new).

- **Acceptance 1** — `the_committed_bind_chain_replays`, `the_committed_evaluations_replay`
  and `the_committed_eq_tables_replay` replay `poly_kats.txt` byte-exact: after each of
  the 10 binds the *whole* remaining table is compared, not just the last value, and the
  20 committed evaluations are checked on one instance whose backing is then asserted to
  still be `U32`. `the_committed_fixture_covers_what_it_claims` pins the fixture's shape
  first, so a generator that quietly shrank could not thin the coverage silently.
  `the_full_bind_chain_is_the_committed_evaluation` makes the two paths meet on the
  fixture's own value.
- **Acceptance 2** — 100 seeded cases at `n = i % 13` (so 0 through 12, every size
  present) across all five backings, each checked three ways:
  `evaluate_matches_the_committed_arkworks_values` (the committed file),
  `evaluate_matches_the_naive_eq_sum` (`sum_x f(x) * eq_eval(point, x)`, through
  `eq_eval` alone as the stage specifies), and `evaluate_matches_arkworks_in_process`
  (`ark-poly` as a dev-dependency of `crates/poly`, evaluated live).
  `bind_matches_arkworks_fix_variables` adds the other half of the convention against
  the same authority. `every_committed_table_rebuilds` checks all 100 digests, and
  `the_corpus_covers_what_it_claims` asserts the corpus really spans every backing and
  every size.
- **Acceptance 3** — `every_three_variable_bit_table_agrees_across_backings` runs all
  256 three-variable 0/1 tables through `U1`, `U8`, `U16`, `U32` and `Fr`, comparing
  every `get`, `evaluate`, and the table left by *every* step of a full bind chain; it
  also asserts the bitset for a table is the byte itself, which pins the bit order.
  `wider_backings_agree_on_seeded_tables` does the same on seeded random tables at
  `num_vars` 0, 1, 2, 4, 6, 8 for `u8`, `u16` and `u32` widths — each table expressed in
  every width it fits in, so a `u8` table is checked four ways — and
  `backings_agree_at_the_edges_of_their_width` covers 0, 1 and the maximum of each width,
  which a random table never produces.
- **Acceptance 4** — `binding_every_variable_equals_evaluate`: ten `n = 10` polys,
  alternating `U32` and `Fr` backing, bound one variable at a time with `num_vars` and
  `len` checked at each step; the final cell equals `evaluate(r)`, `evaluate(&[])` on the
  fully bound poly returns the same, and binding a 4-variable prefix then evaluating the
  remaining 6 does too.
- **Acceptance 5** — `the_lift_is_lazy_and_one_way`: a `U16` poly reports `U16` after
  every `get` and after `evaluate` — and the whole backing compares equal, so a read did
  not disturb the table either — then `Fr` after one `bind`, and still `Fr` after a
  second bind and after further reads. `no_read_lifts_any_backing` repeats the read half
  for `U1`, `U8` and `U32`.
- **Acceptance 6** — `the_eq_machinery_agrees_with_itself`, ten rounds at `n = 6`:
  `eq_table(r)[y] == eq_eval(r, vertex(y))` for all 64 vertices, the table sums to
  `Fr::ONE`, and `eq_eval(r, r') == eq_eval(r', r)`. It additionally checks that the
  table *is* the multilinear extension of `eq_eval` off the cube, which is the property
  later stages lean on when they treat `eq` as a virtual column, plus the empty case and
  the two one-variable tables by hand.
- **Acceptance 7** — `the_index_convention_is_little_endian` builds an `n = 3` table
  whose values spell their own vertex (`110` is `y_0 = 1, y_1 = 1, y_2 = 0`) and asserts
  `get(0b011) == 110` along with each single-variable index, then that the same vertex as
  a *point* evaluates to the same value, then that `bind(1)` keeps the odd indices and
  `bind(0)` the even ones. An endianness flip is visible in the assertion itself.
- **Acceptance 8** — thirteen `#[should_panic]` tests, one per error plus the variants
  that matter: non-power-of-two `new` (a plain table, an empty table, a bitset), a
  bitset with the wrong limb count, a bitset with a dirty tail, `bind` on a constant and
  one bind too many, a short point, a long point, a point given to a constant, `get`
  past the table and `get` past a *bound* table, and an `eq_eval` length mismatch. Each
  matches on the message text, so a panic for the wrong reason fails.
  `the_legal_edges_are_accepted` is the control on the controls: a 1-entry bitset, a
  full 64-bit limb and a 128-entry two-limb bitset must all be accepted, so the
  validation cannot pass by rejecting everything.
- **Acceptance 9** — `a_corrupted_fixture_is_rejected` flips one hex digit in a
  committed *answer* (a bind value, an evaluation result, an `eq` entry) and in a
  committed *input* (a source value, a challenge), and asserts the corresponding replay
  fails in each case; it also shows the SHA-256 pin changes. `a_corrupted_corpus_is_rejected`
  does the same for the differential file, including a tampered table digest.
- **Acceptance 10** — the bench line below.

Beyond the acceptance list, master rule 8 wants every checker provably able to fail, so
both parsers have negative controls: `a_malformed_fixture_is_rejected` (unknown record,
an out-of-order value, an out-of-order bind block, a dropped line, a truncated line, bad
hex, a short `u32`) and `a_malformed_corpus_is_rejected` (unknown record, out-of-order
case, a point after its result, a truncated case, bad hex, a result with no case), each
ending by asserting the unmodified text still parses.

**Both fixtures were re-derived from scratch in Python**, as a third implementation
independent of both arkworks and this repository: bignum arithmetic mod p, splitmix64
transcribed from the published reference, and SHA-256 from the standard library. It
reproduced every one of `poly_kats.txt`'s 1,023 bind-chain values, its 20 evaluations,
and its 127 committed `eq` entries (each table also summing to one), confirmed that
`bind[10][0]` is `evaluate(challenges)`, and re-derived one evaluation a second way as
`sum_x f(x) eq(point, x)`. For `evaluate_diff.txt` it rebuilt all 100 tables from the
documented draw rule, reproduced all 100 digests and all 100 results, and confirmed the
corpus really does span sizes 0 through 12 and all five backings. Nothing in the
generator or in `crates/poly` was consulted while writing it.

**Mutation testing.** Seven single-edit mutants of `lib.rs` were built and the whole
suite run against each with `--no-fail-fast`. Every one is caught by more than one
independent test, and in each case at least one of them is a committed-fixture replay or
an arkworks differential rather than a self-consistency check:

| mutant | caught by |
| --- | --- |
| `bind` folds `hi + r(lo - hi)` | `the_committed_bind_chain_replays`, `bind_matches_arkworks_fix_variables`, `binding_every_variable_equals_evaluate`, `the_index_convention_is_little_endian` |
| `eq_table` puts the `y_j = 1` half at the wrong offset | `the_committed_eq_tables_replay`, `eq_table_matches_eq_eval_over_the_whole_cube`, `the_eq_machinery_agrees_with_itself` |
| `U1` bits read big-endian within a limb | `every_three_variable_bit_table_agrees_across_backings`, `every_committed_table_rebuilds`, `evaluate_matches_the_committed_arkworks_values`, `backings_agree_at_the_edges_of_their_width`, `the_legal_edges_are_accepted` |
| `evaluate`'s first round swaps `lo`/`hi` | 3 tests across 2 suites |
| `U32` lift byte-swapped | 3 tests across 2 suites |
| `eq_eval` drops the `(1-r)(1-y)` term | the eq tests above |
| no-op control edit | nothing fails, as it must not |

**Adversarial review.** Five independent reviewers went over the branch with disjoint
lenses — the math and the conventions derived from scratch, adversarial edge cases and
panic behaviour, a line-by-line audit of the stage prompt's Deliver / Must-be-exact /
Acceptance items, test vacuity and oracle independence (including running their own
mutants), and compliance with the master prompt's rules and anti-goals. Four returned
nothing. The fifth found one thing: `ark_to_fr`, an arkworks-to-`Fr` bridge in
`tests/common/mod.rs` that no test called, kept invisible by the module's
`#![allow(dead_code)]`. It is deleted. No correctness finding survived, and no mutant of
theirs survived the suite either.

`cargo clippy --workspace --all-targets -- -D warnings` is clean, with one `#[allow]` in
library code — `clippy::len_without_is_empty` on `len`, because a polynomial always has
at least one evaluation and an `is_empty` beside it would be a constant `false` with no
caller, which anti-goal 10 rules out.
`cargo build -p field -p constants -p transcript -p poly --target riscv32imac-unknown-none-elf`
succeeds, satisfying must-be-exact 8; `poly` was added to that CI step and to the
regenerate-and-diff step.

## Bench (acceptance 10, no threshold)

`cargo run --release -p bench`, Apple Silicon (aarch64-apple-darwin), rustc 1.96.1,
best of 3. Internal number; no public claims.

| what | time |
| --- | ---: |
| lift + full bind chain, `U32` backing, `n = 20` (1,048,576 evaluations) | **29.0 ms** |

The table is built and cloned outside the timed region, so what is measured is the first
bind's lift of 2^20 `u32` values into `Fr` plus the 20 folds — 2^21 - 1 field
multiplications and twice as many additions. Reruns landed within 0.1 ms of each other.
The `Fr` microbenchmark rows are unchanged from S01.

## Additive extensions (everything beyond the stage's literal list)

Must-be-exact 9 asks for these to be recorded. There are four, all small:

1. **`Debug`, `PartialEq` and `Eq` on `PolyBacking`, and `Debug` on `MultilinearPoly`**,
   beside the `Clone` the stage names. `PartialEq` is what lets a test compare a whole
   post-bind table, or assert that a read did not disturb a backing, in one line; `Debug`
   is what makes such a failure readable. No public function takes or returns them.
   `PartialEq` is deliberately **not** derived on `MultilinearPoly`: two polys with
   different backings hold the same function, and an equality that called them different
   would be a trap.
2. **`ark-poly` as a workspace dependency**, used by `tools/kat-gen` and as a
   dev-dependency of `crates/poly`. Acceptance 2 requires the latter by name. Its default
   feature set is empty and it pulls no `serde`, so the trap S01 and S02 both hit is not
   reachable here; verified with `cargo tree -e features -i serde`, which shows `serde`
   still reaching `crates/field` with only `derive`/`serde_derive`, from `postcard`, as
   before this stage.
3. **The poly bench line in `tools/bench`**, which acceptance 10 asks for. It is the
   existing binary, one extra function, and `poly` in its manifest.
4. **A three-line deletion in `tools/kat-gen/src/main.rs`**: its private `hex` helper is
   now `test_support::to_hex`, which is character-for-character the same function and was
   already a dependency. `fr_kats.txt` regenerates byte-identically, which is the proof.

## Deviations and notes for the reviewer

- **`PolyBacking::U1(Vec<u64>, usize)` is a two-field tuple variant**, not a named
  `BitSet` struct. The stage writes `U1(/* bitset */)` — one slot — while must-be-exact 7
  describes "`Vec<u64>` limbs plus an entry count", which is two things. A `BitSet` type
  would match the shape of the signature; the tuple matches the description and adds no
  public type, so it is what the anti-goals point at. The invariants that a named type
  would carry are enforced in `new` instead, and `tests/common/mod.rs::pack_bits` is the
  test-side constructor. If a later stage finds itself packing bitsets in three places,
  that is the moment to extract one — not before.
- **The differential corpus is digest-pinned rather than written out**, for the size
  reason given under Artifacts. This is the one place S03 departs from the letter of
  "test vectors are committed files": the *answers* are all in the file, and the
  *inputs* are pinned by a SHA-256 of the lifted table rather than by their own hex.
  Called out because it is the closest call in the stage. The alternative considered and
  rejected was shrinking the corpus until it fitted, which would have bought a smaller
  file with less coverage.
- **`poly_kats.txt` writes source values as 8 big-endian hex digits, not as field
  elements.** Every field element in both files is the canonical 32-byte little-endian
  form master rule 3 requires. A `u32` table entry is not a field element, though — it is
  a number — and the repository already has a rule for numbers in text, namely
  `Fr::from_hex`'s big-endian spelling, chosen in S02 because "a constant in source is a
  number". Writing the source table that way keeps it 9 KB instead of 66 KB and records
  in the file that the fixture's backing really is `U32`. The file header states both
  encodings and which records use which.
- **`eq_table` is committed only on the challenge prefixes `r[..k]` for `k <= 6`.**
  The prefixes at 7 through 10 would have added about 130 KB of hex for no new algorithm;
  `eq_table_matches_eq_eval_over_the_whole_cube` instead checks all 1,024 entries of the
  full 10-variable table against `eq_eval` in process, which is strictly more coverage.
  `eq_eval` itself is pinned externally through the committed prefixes and through the
  naive differential.
- **`crates/poly/tests/common/mod.rs` has its own vector reader**, roughly 25 lines that
  resemble `crates/transcript/tests/common/mod.rs`. The genuinely shared primitives — the
  RNG, hex, SHA-256 — come from `tools/test-support` and were not copied. Unifying the
  three test suites' file readers is a repository-wide cleanup that would touch two
  finished stages for a small dedup; flagging it here rather than doing it inside S03.
- **`tools/kat-gen` grew a module rather than a new tool.** It already is the
  arkworks-backed fixture generator, already runs in CI's regenerate-and-diff step, and
  its name still describes what it does. A second binary would have been a second CI
  line and a second manifest for no gain.
- **S02's handoff expected G1 point absorption to "land with S03".** It does not: S03 is
  the polynomial stage and needs no curve. That work still waits on `crates/curve`.
- **No conflicts between the master prompt and the stage prompt were found.**

## Open for the next stage

- `MultilinearPoly` has no arithmetic: no `add`, no `mul`, no `fix_last_variable`, no
  iterator adaptors. Sumcheck will want some of that, and the right time to add it is
  when there is a caller — the stage that needs it should add exactly what it needs.
- There is no parallelism here. `bind` at `n = 20` is 29 ms single-threaded; if a real
  workload ever says that matters, rayon over the fold is the obvious change, and master
  rule 11 wants the benchmark in the same commit.
- `constants::transcript_tags` is untouched by this stage and still has its seven S02
  entries.
