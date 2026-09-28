# `guests/vendor`

Upstream crates vendored so that a **guest** can patch them. Nothing here is part
of the proving stack, and nothing in `crates/` may depend on any of it: master
rule 2 keeps this repository's cryptography in this repository, and a guest
program is the thing being proven, not part of the prover
(`CLAUDE.md`, "A guest may take a crates.io dependency when the guest is the
workload").

`guests/Cargo.toml`'s `[patch.crates-io]` is what makes a vendored copy the one
that compiles. The root workspace has no such table, so `crates/emulator/tests/
revm.rs`' native revm oracle resolves every crate here from crates.io, unpatched
— which is the whole reason the oracle is worth anything.

Each crate below is a **verbatim** copy of its crates.io release with the two
or three files named against it changed and nothing else, so the diff a reviewer has to
read is that list and not a crate. `cargo fmt --all` covers the tree (cargo makes
a path dependency inside a workspace directory a member of it) and has never had
anything to say about it; the upstream sources are rustfmt-clean and so are the
patches. Their own `[features]` tables are the ones
`crates/prover/tests/one_feature.rs` skips, and
`the_vendored_crates_are_the_ones_a_guest_patches` holds every directory here to
being a crate that `[patch.crates-io]` actually names.

**Upstream warnings are visible here and were not before.** cargo caps lints on a
registry dependency and does not cap them on a path one, so a guest build now
prints the 12 warnings `k256` 0.13.4's own source raises under this toolchain —
four `unused_qualifications`, three deprecated `GenericArray` aliases and five
`#[must_use]` on trait methods. They are upstream's, they are not silenced, and
they are the price of being able to read the code that runs.

---

## `k256` 0.13.4 — S26, extended at S26b and S26c

Upstream `https://github.com/RustCrypto/elliptic-curves`, commit
`5ac8f5d77f11399ff48d87b0554935f6eddda342` (`.cargo_vcs_info.json`), as published.
`Cargo.toml.orig` and cargo's `.cargo-ok` marker are not copied; every other file
is byte-identical to the release.

**Why.** S26's profile ranked secp256k1 first in every workload it measured:
30.98% to 47.81% of a whole mainnet block's guest cycles, and inside that, **one
function** — `FieldElementImpl::mul` — took 36.76% of block 26,059,929 by itself
at 1,318 cycles a call, with `FieldElement::square` a further 7.64% at 1,167.
That is the `F_p` multiply of the `ecrecover` precompile, and
`docs/spec/delegation.md` §14's `MOD_MUL` circuit is exactly that operation.
There was no way to reach it from outside the crate: the field type is private,
the multiply is inherent, and there is no hook. S26b added the **scalar** half
for the same reason — `ecrecover`'s `r^-1` is an addition chain of some 250
scalar multiplies — and it is cheaper to route than the field half, a `Scalar`
being already reduced and already eight 32-bit limbs.

**The three changed files.**

| file | change |
| --- | --- |
| `Cargo.toml` | one `[target.'cfg(target_arch = "riscv32")'.dependencies]` entry on `guest-sdk`. A target dependency and never a cargo feature, which is how `crates/field` and `crates/transcript` reach their own shims |
| `src/arithmetic/field/field_10x26.rs` | `mul` and `square` select `apogee::mul_mod_p` under `cfg(target_arch = "riscv32")` and are otherwise untouched, plus a new private `mod apogee` at the end of the file holding `packable`, `pack`, `unpack`, `operand` and `mul_mod_p` |
| `src/arithmetic/scalar.rs` | `Scalar::mul` selects `apogee::mul_mod_n` under the same `cfg` and is otherwise untouched, plus a new private `mod apogee` at the end of the file. `Scalar::square` is `self.mul(self)` upstream, so it follows |
| `src/arithmetic/projective.rs` | **S26c.** `add`, `add_mixed` and `double` select `apogee::{add, add_mixed, double}` under the same `cfg`; each upstream body moves down one function to `add_inner`, `add_mixed_inner` and `double_inner`, unchanged, and is the fallback. A new private `mod apogee` at the end of the file holds `limbs`, `field`, `lanes`, `point` and the three entry points. **`ProjectivePoint`'s storage is untouched** |

**Why the projective patch is a drop-in, and why that is not luck.** Upstream's
`ProjectivePoint::add` *is* Renes–Costello–Batina 2015 Algorithm 7 in homogeneous
projective coordinates, and `docs/spec/delegation.md` §16's `EC_ADD` circuit is
the same algorithm over the same representation — because it was designed to be
(the owner's rule: a delegation understands the representation its caller already
uses). So the delegated path and `add_inner` agree **limb for limb** and not
merely as points, which is the opposite of the field patch, where upstream
returns a weakly normalized product and the delegation returns the canonical
residue. Three consequences worth knowing:

- **`double` routes too.** Algorithm 7 is complete, so `P + P` is a correct
  doubling and the delegation needs no second frame. The *fallback* stays
  Algorithm 9, upstream's dedicated doubling, because in software that is the
  cheaper of the two and an executor taking the fallback is paying software
  prices for everything.
- **`add_mixed`'s identity correction is kept.** An affine identity is `(0, 0)`
  here, which lifted to `(0 : 0 : 1)` is neither the projective identity nor a
  curve point, so no complete formula rescues it — upstream's
  `conditional_assign` is what does, and it is still there.
- **The operand bound costs a normalization per coordinate.** `FieldElement::
  to_bytes` fully normalizes before encoding, so the circuit's `a < m` holds by
  construction. There is no fast path as there is in `field_10x26`'s `operand`:
  this runs six times per addition against twelve multiplies removed, where that
  runs twice per multiply.

**And it changes what `guests/mod-mul-ops` declares.** That guest's `k256` group
arithmetic now reaches the `EC_ADD` shim as well, so it declares two delegation
families where it declared one, and its `MOD_MUL` invocation count falls. Both
are re-pinned; `docs/handoff/S26c-sha256-ec.md` records the numbers.

**Why `field_10x26.rs` and not `field_impl.rs`.** `field.rs` picks its
`FieldElementImpl` by `cfg(debug_assertions)`: the magnitude-tracking wrapper in
`field_impl.rs` when they are on, the bare `FieldElement10x26` when they are off.
Both route through `FieldElement10x26::mul`, so patching the one file covers both
configurations. `guests/Cargo.toml` pins `debug-assertions = true` in **both**
profiles, so the wrapper is what a guest gets either way, and it records the
delegated result as magnitude 1 and not normalized — which a fully normalized
value also is.

**What the field patch has to get right.** A field element is ten 26-bit limbs;
the frame carries eight 32-bit ones. `pack` and `unpack` are that change of base,
and `packable` is the 13-cycle test for whether the value is below `2^256` at
all — a magnitude-8 element reaches `2^259`, so an operand has to be reduced
before it can cross the frame.

`packable`'s bound is exact: limbs 0–8 below `2^26` with limb 9 below `2^22` admit
`[0, 2^256)` and nothing more, the maximum being `2^256 - 1` exactly.

**And since S26b it is not enough on its own.** The circuit enforces `a < m` and
`b < m`, so an operand must be below `p` and not merely below `2^256`. That is
not a corner case: `p`'s own raw limb pattern is upstream's **second
representation of zero** — `normalizes_to_zero`'s `z1` mask is exactly it — and
the complete projective formulas produce it whenever a coordinate difference
vanishes, so a lazily reduced zero reaches a multiply as the literal value `p`,
which `packable` accepts. `operand` therefore tests
`packable(x) && !x.get_overflow()`, upstream's own "is this magnitude-1 value at
or above `p`", ordered after `packable` because that is where it is meaningful,
and falls back to a full `normalize`. Every delegated `mul` and `square` result
is canonical, so the fast path is what a chain of multiplies takes. The cost is
the `normalize` S26 measured at 0.6 million guest cycles on the pinned mini-block
and deliberately removed; enforcing the operand bound put it back, and
`docs/spec/delegation.md` §14.3 is the trade.

**The scalar patch has none of that to get right**, and it is worth saying why:
`Scalar` is a `crypto-bigint` `U256` whose representative is always below `n`,
and on this target a `Word` is a `u32`, so `to_words()`/`from_words()` are the
identity on the frame's limb layout and the operand bound holds by the type's own
invariant. If a target had 64-bit limbs the conversion would be a type error
rather than a silent miscoding.

**What it deliberately does not preserve.** Upstream's `mul` returns a *weakly*
normalized product; the delegated one returns the canonical residue. The two
agree as field elements and not as limb patterns. Nothing in `k256` compares
field elements by representation — every comparison is `normalizes_to_zero` over a
difference (`AffinePoint::ct_eq`, `ProjectivePoint::ct_eq`) — and `to_bytes`
normalizes first.

---

## `ark-ff` 0.6.0 — S26b

Upstream `https://github.com/arkworks-rs/algebra`, commit
`d168323a6c7adf25210030fdd2c0be734b52f85b` (`.cargo_vcs_info.json`), as
published. `Cargo.toml.orig` and cargo's `.cargo-ok` marker are not copied;
every other file is byte-identical to the release.

**Why.** `revm-precompile`'s `0x06`, `0x07` and `0x08` — BN254 addition,
multiplication and pairing — are `ark-bn254` over this crate's generic `Fp`, and
S26's profile measured BN254 at 18% of block 26,059,800's guest cycles and the
cheapest remaining win after secp256k1. S26b's `MOD_MUL` holds BN254's two
moduli, so the circuit was already there.

**The two changed files.**

| file | change |
| --- | --- |
| `Cargo.toml` | one `[target.'cfg(target_arch = "riscv32")'.dependencies]` entry on `guest-sdk`, as `k256`'s |
| `src/fields/models/fp/montgomery_backend.rs` | an inherent `impl MontBackend<T, N>` holding one associated `const APOGEE`, `FpConfig::mul_assign` and `::square_in_place` consulting it under `cfg(target_arch = "riscv32")`, and a new private `mod apogee` at the end of the file |

**Why `ark-ff` and not `ark-bn254`.** The obvious patch point is the field
config, and it does not work: `ark-bn254`'s `#[derive(MontConfig)]` *generates*
`mul_assign` and `square_in_place`, so overriding them there means hand-writing
the whole `MontConfig` impl — fifteen associated constants, three of them
required and the rest derived — which is a much larger diff to review and a much
easier one to get subtly wrong. `MontBackend::mul_assign` is one level below the
derive and forwards to it, so intercepting there is one function pair and covers
`Fq2`, `Fq6` and `Fq12` for free, all three being built on `Fq`'s multiply.

**How the field is chosen, and why every other arkworks field is untouched.**
`APOGEE` is an associated `const` evaluated per monomorphization from
`T::MODULUS`, so the match costs nothing at run time and returns `None` for
everything but BN254's two — `ark-bls12-381`'s six-limb field included, which
this guest workspace also compiles.

**Two calls, not one, and that is the whole design.** arkworks holds `x·R` with
`R = 2^256 mod p` and a Montgomery multiply is `â·b̂·R^-1`; the delegation
multiplies plain integers. So the patch issues `t = â·b̂ mod p` and then
`out = t·R^-1 mod p`, with `R^-1` a literal from
`constants::mod_mul::{BN254_P_R_INV, BN254_R_R_INV}` — which
`crates/constants/tests/moduli.rs` multiplies back out against a doubling chain,
so a wrong one is a failed test and not a guest that computes the wrong answer.
Both operands of both calls are below `p`: arkworks keeps every representative
reduced and `R^-1` is a residue, so the delegation's `a < m` requirement costs
this path nothing. `a` is written only after **both** calls answer, so a
`-ENOSYS` halfway leaves no half-computed representative behind.

---

## What tests all three

`guests/mod-mul-ops`, and only that: on every executor but this VM's the ecall
answers `-ENOSYS` and upstream's own multiply runs, so a host test cannot see a
patched path at all. The guest calls the delegation by name once per selector
against literal expectations *and* against a long division of its own, then
exercises `k256`'s group arithmetic, `k256`'s scalar inversion and
`ark-bn254`'s two fields.

**No check inside the guest can tell a delegated multiply from a software one**
— they agree on the value, which is the point — so what tests that a patch still
*routes* is the **invocation count**, pinned by
`crates/emulator/tests/guests.rs::mod_mul_ops_routes_every_vendored_patch_through_the_ecall`.
Each of the three seams contributes a different number, so any one of them
falling back moves it.

Beyond that, S26's pinned mini-block is the end-to-end check, and the strongest
one: its 90-byte journal is a commitment over the post-state of two real
transactions whose senders come out of `ecrecover`, and it is byte-identical
with the delegations and without them.

**What the k256 patch bought at S26.** On the pinned mini-block (block
26,057,509's first two transactions) 23,733,540 guest cycles became 17,986,969 —
**−24.2%**, 60.4 cycles per gas down to 45.8 — with `secp256k1` falling from
46.47% of the execution to 28.11%. **That figure is S26's and S26b moves it in
both directions**: the frame is seven words narrower, which is cheaper per call,
and `operand` now fully normalizes when it must, which is dearer. The net is not
derivable from the numbers above and `docs/handoff/S26b-eth-field-mul.md` records
the re-measurement.

**Refreshing either.** Copy the release over the directory again, re-apply the
changes listed against it above, rebuild the guests with
`cargo run -p kat-gen -- guests`, and re-run the mini-block profile.
`docs/handoff/S26-cycle.md` §6 is the account of S26's measurement.
