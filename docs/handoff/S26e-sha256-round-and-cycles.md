# S26e — `SHA256_COMP` four rounds a row, and guest cycle reductions

One stage, one branch (`s26e-sha256-round-and-cycles`), PR #36, two parts as two
commits, on the owner's three answers at the start:

- the `SHA256_COMP` shape: **four rounds a row, at `2^18`**;
- the cycle work: **dependencies' debug assertions off**, and **k256's `EC_ADD` glue**
  (limb-form `invert`/`sqrt` and the BN254 and hash paths were offered and not taken);
- the landing: **one stage, one PR**.

The owner's other instruction shaped how much was written down: observe the master
prompt's coding principles, and do not invest in the invariant documentation, which
the next stage cleans up. The specs were updated where they would otherwise be
false, and no further.

Everything is measured on devnet block 257510 through `revm-block-stateless`
(`../apogee-stateless-runs`' input), and its 43-byte journal is
`033e5716…0115` at every step below.

| | guest cycles | |
| --- | --- | --- |
| `main` before this stage | 349,255,265 | |
| part A, `SHA256_COMP` re-shaped | 351,586,466 | +2.33M, sixteen ecalls a compression |
| + dependency debug assertions off | 327,812,834 | −23.77M, −6.8% |
| + k256's `EC_ADD` glue | **197,923,891** | −129.89M; **−43.7%** against part A |

## 1. Part A — `SHA256_COMP`: four rounds a row, at `2^18`

`docs/spec/delegation.md` §15 and §10.5 and `docs/spec/constraint-manifest.md` §19
are the account; this is the summary.

**Why.** S26c's row was a whole compression with every word as bits: 8,216
committed and 16,688 inner columns, forced to `2^8`, 256 compressions a shard,
10,895,760 artifact bytes, about 1.33 MB of proof a shard — **5,186 proof bytes a
compression**. The stateless guest's SSZ hashing calls it 8,011 times on block
257510: **32 shards and 42.5 MB, two thirds of that block's proof.** It was
`KECCAK_F`'s pre-S26d shape, and S26d's trade fixes it the same way.

**The shape.** A compression is **sixteen invocations**, glued by the frame being
ordinary RAM. The frame is 25 words: the round group `r` (word 0, written back
unchanged), `a..h`, and a sixteen-word **schedule window** `W_{4r} … W_{4r+15}`
that each call shifts down four and refills with the four words it derives — so
the message schedule crosses the frame and costs the guest nothing. Calls 12–15
derive `W_64 … W_79`, which nothing reads: a uniform row is cheaper than a mode.

**No bit anywhere.** Every Boolean operation is one `XOR8` obligation; a rotation
is a literal-weighted form over a word's bytes and one mask byte each (`KECCAK_F`'s
rho device); the big sigmas **nest** —
`Σ0(a) = ROTR2(a ^ ROTR11(a ^ ROTR9(a)))`, `Σ1(e) = ROTR6(e ^ ROTR5(e ^ ROTR14(e)))`,
each checked over 10,000 random words before it was built on — so each is 17
obligations against 20; `Ch` and `Maj` are linear forms over XORs; every addition
is a degree-1 gate whose carry is the byte-range tuple `(0, c, c)`; and the frame's
own bounds are `RANGE16`'s, as for every family at `2^16` or above. `K` is a linear
form over sixteen one-hot group selectors, so no gate carries a bare constant and
the all-zero row is valid.

| | S26c | S26e |
| --- | --- | --- |
| committed (M / W) | 8,216 | **624** (104 / 520) |
| inner at the default height | 16,688 at `2^8` | **2,802** at `2^18` (2,790 at `2^16`) |
| enforcing gates | 8,215 | **119** (75 degree 1, 44 degree 2) |
| obligations | 0 | **450**: 114 `RANGE16`, 336 `XOR8` (128- and 512-leaf trees) |
| relations, depth, wire bytes at `2^18` | — | 2,921, 28, 845,456 |
| compressions a shard | 256 | **16,384** |
| proof bytes a shard | ~1.33 MB | **189,988** (derived, the §1.2 model) |
| proof bytes a compression | 5,186 | **11.6** |
| forward pass a shard | — | 23.5 GB; derived peak ~30 GB |

**The price**, stated when the shape was chosen: sixteen rows of 2,802 inner
columns are 44,832 forward-pass cells a compression where S26c's row was 16,688,
**2.7×**; and the guest pays sixteen ecalls and their loop where it paid one,
+2.33M cycles (0.67%) on block 257510, `guest_sdk::sha256_compress` now 405 cycles
a call. What it buys is the height: block 257510's SHA work goes from 32 shards and
42.5 MB of proof to **one shard and about 0.19 MB**.

**What changed outside the family.** Ecall `0x0505` is **retired and burned**
(`RETIRED_SHA256_COMP_WHOLE_COMPRESSION`) and the call is `0x0508`, the frame having
changed shape; that number is a literal in `ADD_SUB_LUI_AUIPC`'s request gate, which
is the only reason `add_sub.bin` moved. `DEFAULT_HEIGHTS[SHA256_COMP]` is `2^18`.
`guests/sha256-ops` checks one raw call against FIPS 180-4's `t = 3` row and
`W_16..W_19`, two whole compressions and the digest surface; it exits 13 and makes
529 invocations. `sha256-ops.elf` was rebuilt and re-pinned.

## 2. Part B — guest cycles

### Dependencies' debug assertions off, at `--release` only

One `[profile.release.package."*"]` table in `guests/Cargo.toml` with one key,
`debug-assertions = false`. `"*"` is every package that is not a guest — the
crates.io dependencies, the vendored ones (which are **not** workspace members,
`cargo metadata` listing the 23 guests alone; the comment claiming otherwise was
wrong and is corrected), and this repository's guest-sdk, `field` and `transcript`,
whose `debug_assert!`s are internal invariant checks. Every guest keeps its own,
`overflow-checks` is inherited and on, and the dev profile, which builds every
committed fixture, is untouched, so no committed ELF moved for it.
`crates/prover/tests/one_feature.rs` pins the override's exact shape: one table, at
release, one key.

**−23.77M, −6.8%.** k256 drops its 48-byte magnitude-tracking debug field element
for the plain 10×26 one, and `core`'s inlined precondition checks compile out of
every dependency. **Measured alone, k256's half was a regression** — 2.5% slower —
because the bare element's `conditional_select` is 342 cycles a point against the
wrapper's 90, and upstream's constant-time `LookupTable::select` is made of them;
the indexed `select` below removes the call, so the two were measured together.

### k256's `EC_ADD` glue

An `EC_ADD` addition cost **5,275 cycles, of which its three ecalls were 68**: six
coordinates out through `to_bytes` (a full normalization and a big-endian byte
array, 478 cycles each), three back through `from_bytes_unchecked` (408), and a
frame zeroed and then copied over (977). Four changes, all in
`guests/vendor/k256` and guest-sdk, all under `cfg(target_arch = "riscv32")` but
one; `guests/vendor/README.md` lists every changed file:

1. **A coordinate crosses the frame as words.** `FieldElement::{to_words,
   from_words}` (and the debug wrapper's pair) are `field_10x26`'s existing
   `operand` and `unpack`: pack when the value is already canonical — every
   coordinate the delegation returns is — and normalize otherwise.
2. **`EcAddFrame::of` writes each of its 97 words once**, as an array literal, where
   it zeroed 388 bytes and copied six lanes over them. The 48 zeros go through one
   `core::hint::black_box`: as literals LLVM merged them into a 192-byte `memset`
   call costing 163 cycles a frame (−3.12M against plain stores).
3. **`LookupTable::select` indexes** where upstream conditionally assigns all eight
   entries and negates under a mask. Constant time buys nothing in a zkVM — whoever
   proves an execution holds every value it computes — and the result is the
   representative upstream's returns.
4. **`lincomb` borrows its digits and tables** where upstream copied both tables
   out of the slice on all 33 passes. The one unconditional change, and
   behaviour-preserving.

**−129.89M** on top of the profile change. secp256k1 work falls from 147.4M to
52.3M and memory copying from 81.3M to 52.2M. The delegation invocations are the
same calls with the same canonical words, so no invocation count moves.
`ec-ops.elf` and `mod-mul-ops.elf` were rebuilt from clean target directories,
twice each and identical, and re-pinned.

## 3. Verification

### Ran, green

- **Part A**, scoped: `constants`, `constraints` (lib and tests), `emulator` (lib,
  and `guests` without the deferred test), `program --test delegation`,
  `checker --test sha256` (23 tests: the call held to the executor and sixteen of
  them to `sha256("abc")`, every gate class and obligation class refused, and the
  prover's fill over `sha256-ops`' real trace) and `--test add_sub`,
  `prover --test fills`, `loader`; `kat-gen -- delegation` and `-- family` with the
  fixtures committed; every `fmt` and `clippy` line of CLAUDE.md's gate and the
  riscv32 build of the `no_std` crates.
- **Part B**, scoped: `prover --test one_feature`, `loader`, `emulator --test guests`
  (`ec-ops` exits 20 and `mod-mul-ops` 28, the routing bounds hold),
  `program --test delegation` including the ignored
  `reachability_survives_the_optimiser`, which builds guests at `--release` under
  the new override; guest-sdk's riscv32 clippy, the guests' clippy, and `fmt` over
  the root, guest-sdk and the guests.
- **The stateless guest on block 257510**, built at `--release` at every step and
  run through `profiler elf` and the emulator: the journal is byte-identical each
  time.
- **CI**: the workspace suite on PR #36 — see §5.

### Deferred, not run

Every `# DEFERRED` suite but the one count pin §4 records. Three of them — `prover::keccak`, `prover::revm` and
`host::prove` — carry S26d's `2^18` `KECCAK_F` shard at ~60 GB and do not fit the
48 GB machine this stage ran on at any thread count. **Before this stage nothing
but `prover::revm` proved a `SHA256_COMP` shard**, and §4 records the one
end-to-end proof that was run instead.

## 4. The end-to-end proof

`guests/sha256-ops` proved through `prover::prove_block_streaming` at
`max_in_flight = 1` and checked with `verifier::verify_block`, over
`crates/prover/tests/common`'s own `sha256_program()` — `SHA256_COMP` at `2^18`, the
execution families at `2^20` — and its toy SRS, from a throwaway crate that includes
that module by path. **`Ok(())`**, 11 shards, 201.5 s on 18 cores, **33.1 GB peak
RSS** for the whole run.

| shard | proof bytes |
| --- | --- |
| `SHA256_COMP` | **189,988** — exactly the §1.2 model's figure |
| the six execution families | 56,268–68,564 each |
| `INIT_TEARDOWN`, `ZERO_WINDOWS` | 25,276, 25,244 |
| `PUBLIC_INPUT`, `PUBLIC_OUTPUT` | 12,556, 12,524 |

The peak is the statement's and the run does not attribute it to a shard; the model
puts the `SHA256_COMP` shard at ~30 GB, its forward pass alone at 23.5 GB, and no
execution shard of this statement near that, so it is very probably that shard's. It
is the first proof of the re-shaped circuit anywhere — before it, only the deferred
`prover::revm` proved a `SHA256_COMP` shard at all.

The deferred `emulator::guests` count pin was also run, alone:
`the_new_families_are_invoked_the_pinned_number_of_times` — `sha256-ops` 529
`SHA256_COMP` invocations (part A's new number, derived by hand in the test), `ec-ops`
81 `EC_ADD` and 2,084 `MOD_MUL`, `mod-mul-ops` 39 `EC_ADD` (part B's, unchanged) —
green in 122.8 s at 24.2 GB peak RSS.

## 5. CI

**Part A's run failed, and not in the workspace suite**, which passed. The step
after it, `cargo test -p prover --features debug-info --test debug_info`, failed
`every_documented_grep_marker_is_in_the_sources`: `docs/spec/debug-info.md` §8's grep
recipe looks for `DISAGREES`, and the only source that emitted it was S26c's
debug-only comparison in the `SHA256_COMP` fill, which part A rewrote. The rewritten
fill makes the same comparison **always** and refuses the shard on a mismatch, so the
fix is that its two errors carry the marker — the recipe finds a failing run's line
again — and §6.5 of the spec says what changed. Two comments that put `sha256`'s
outputs at 2 now say 6. The `debug-info` step was then run locally, both halves, and
is green.

Because `cargo test` stopped at that binary, the job skipped the five steps after it
— the `debug-info` `--lib` tests, static detachment at both profiles, the revm guest
against native revm, the guest target builds and the fixture regenerate-and-diff —
so for part A they were unverified until the run on the fixed tree; that run is the
PR's.

## 6. Deviations and judgement calls

- **The profiles now differ in one more key**, for dependencies at `--release`.
  The release profile's own comment and `one_feature.rs` say why that is not the
  semantic change they forbid: a dependency's debug assertion is its own invariant
  check, and `overflow-checks` — the one that changes what a guest computes — is on
  everywhere.
- **Variable-time `select`** (§2, item 3), and the reasoning in its doc comment.
- **`black_box` for code shape, not for a value** (§2, item 2), measured.
- **Calls 12–15 derive four schedule words nothing reads** (§1).
- **One stale paragraph left alone**: `constraint-manifest.md`'s per-circuit tree
  list still describes S21's `KECCAK_F` (`- **keccak.**`, "no fraction tree at
  all"). It predates this stage, and the documentation clean-up is the next one.

## 7. For the next stage

- **Measure the `2^18` `SHA256_COMP` shard** — its peak and proof bytes are the
  model's (§1).
- **Where block 257510's 197.9M cycles go now**: memory copying 52.2M (the trie's
  `parse_at` 8.0M, `lincomb`'s by-value point returns 6.4M — about three 120-byte
  copies a select-and-add, from upstream's `AddAssign` shape), `operand` 25.7M
  (217,382 calls at 118 cycles: the canonical check and the pack are the floor
  without changing k256's storage), keccak256 15.4M, BN254 19.0M, and the two
  options not taken this stage: k256's `invert`/`sqrt` addition chains in limb form
  (~20M) and the BN254 and hash paths (~20M).
