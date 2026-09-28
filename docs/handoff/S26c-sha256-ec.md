# S26c — SHA-256 compression, and secp256k1/BN254 point addition

Branch `s26c-sha256-ec`. Two delegation families, stated in two sentences:

> **`SHA256_COMP`** proves one SHA-256 compression a row: one 64-byte block
> against one chaining state, with the Merkle–Damgård padding and the block loop
> left in the guest.
>
> **`EC_ADD`** proves one **third** of a complete elliptic-curve point addition a
> row, on secp256k1 or BN254 G1, in homogeneous projective coordinates — three
> invocations glued by the frame.

There is no stage prompt in `prompts/`: the owner's instruction is the stage, and
§1 quotes it.

**The three things worth reading first.**

1. **`EC_ADD` is the first delegation family to carry a lookup channel**, which
   `docs/spec/delegation.md` §9 forbade in four places. §10.3 is the amendment,
   and `MOD_MUL` was re-shaped the same way in the same stage: its committed
   width fell from 3,468 columns to **325**.
2. **The two new checker suites found three real bugs, one of which made every
   row of `EC_ADD` unprovable.** None was visible to the emulator, to either
   fixture guest or to any shape test — in all three cases the executor computes
   the right answer and only an honest prover fails. §5 is the account.
3. **`EC_ADD` at `2^16` is a computed 20.5 GB a shard**, which makes it the
   peak-setting family in a block. `2^16` is forced rather than chosen, and the
   owner's decision was to keep the three-group split and measure it (§7).

Documents amended this stage:

- **`docs/spec/delegation.md`**: §3's two registry rows; §9 retitled and its
  rule split into the half that stands and the half withdrawn; **§10.3 (new)**,
  the amendment record; §9.2's table; **§15 (new)** and **§16 (new)**, the two
  frame tables and the two designs; §14.2's gate table and §9.2's closing
  paragraph, both of which were pre-reshape.
- **`docs/spec/constraint-manifest.md`**: **§19 (new)** and **§20 (new)**;
  **§18 rewritten**; §0.4, §0.5, §1.1, §1.2, §1.3, §12.1, the preamble and
  Appendix A; the old §19 and §20 renumbered to §21 and §22, and the fifteen
  cross-references that pointed at them.
- **`docs/spec/ecall-abi.md`**: §3's two rows.
- **`docs/spec/lookup.md`**: §3, where the delegation exemption lived.
- **`docs/spec/memory.md`**: the address-space tag list, 4 through 9.
- **`docs/spec/public-values.md`**, **`docs/spec/shard-proof.md`**,
  **`docs/GLOSSARY.md`**: the family count, and the glossary's "Witnessed
  parameter" entry, stale since S26b, now two entries.
- **`docs/guest-program-manual.md`**: both fixture guests.
- **`guests/vendor/README.md`**: the `k256` section's third changed file.
- Seven `CLAUDE.md` files.

---

## 1. The instruction

The owner's instruction, in full:

> Read `./prompts/00-master.md` and add 3 more precompiles to the
> ECALL/delegation for EVM executor cycle reduction.
>
> 1. SHA-256 compression. targets Ethereum's 0x02 precompile. Small, regular
>    circuit surface. easy routing at the compression-function layer.
> 2. secp256k1 EC operations (NOT the full ecrecover, only the curve
>    operations). targeting transaction signatures.
> 3. BN254 EC operations. mainly point add/scalar mul primitives underlying
>    Ethereum ECADD/ECMUL. Don't do pairing.
>
> Remember these are all Ethereum specific acceleration ECALLs and for general
> guest program they're likely to be detached, so you can make them specialized
> to the EVM executor guest program, no need to make them generic. Complete this
> as stage 26c.

### 1.1 The decisions taken before any code

Eight, over four rounds, and two of them reversed a design already drafted.

| question | answer |
| --- | --- |
| three families or two? | **two**: `SHA256_COMP`, and one `EC_ADD` with a selector naming a curve *and* a group |
| build all three precompiles? | yes |
| how to reach BN254? | revm's `install_crypto` hook; **vendor nothing new** |
| SHA-256's circuit shape | **layered** — helpers derived in two extra gate lists |
| how to reach secp256k1? | a **narrow** patch of `ProjectivePoint`'s methods, storage unchanged; "design a projective-compatible delegation instead" |
| cross-row intermediates | **drop the bus; split through the frame** |
| `EC_ADD`'s channel | **amend §9**; `RANGE16` on the family at `2^16` |
| re-shape `MOD_MUL` too? | **yes, fold it into this stage** |
| `EC_ADD`'s split factor | **k = 3**: a 97-word frame, three reductions a row |

**Two circuit shapes were rejected before the third was accepted**, and the
reasons are the stage's real content.

The first put one whole addition on one row: twelve projective reductions
side by side, about 25,000 committed columns. The owner's answer named the
error directly — *"You're likely putting one high-level operation into one
single row containing entire computational witness which is NOT right. don't
inline ten or twenty full big-integer multiplication witnesses side-by-side."*

The second went affine with a `λ` witness: five products, three quotients,
9,074 columns. The owner refused that too — *"You're still treating each
modular identity as a huge independent base-layer witness"* — and pointed at
the shape that worked: **account separately for external-frame columns and
internal-stage columns.**

**And the affine redesign was unsound, which I found rather than the owner.**
The "one complete unified affine formula" has a degenerate case at
`P + (−βP)`, `β` the GLV cube root of unity: `1 + β + β² = 0` kills both the
numerator and the denominator, `λ` is free, and the circuit accepts any
answer. `k256`'s own ladder reaches that point at attacker-chosen scalars, so
it is not hypothetical. That ruled the design out on soundness before the
column count mattered.

---

## 2. What was built

### 2.1 `SHA256_COMP` — family 16, ecall `0x0505`, space 8

One compression a row, a 24-word frame, `2^8`, **no lookup channel**. 100 `M`
and 8,116 `W` columns, 16,688 inner, 25,087 relations, 10,895,760 bytes of wire
form — the second-largest circuit in the registry after `KECCAK_F`, and the
widest committed base layer of any.

**The recurrence is over two sequences, not eight working words.** `b`, `c` and
`d` are `A_{i−1}`, `A_{i−2}` and `A_{i−3}`; `f`, `g` and `h` are `E_{i−1}`,
`E_{i−2}` and `E_{i−3}`, so the round is
`A_{i+1} = T1 + T2 − 2^32·ca_i` and `E_{i+1} = A_{i−3} + T1 − 2^32·ce_i`, the
eight-variable shuffle costs nothing, and the four non-positive indices of each
sequence **are** the frame's state words. `constraints::sha256`'s `a_bit(i)` and
`e_bit(i)` for `i ≤ 0` are that mapping, and it is the whole of `B`, `C`, `D` and
`H`'s existence in this arithmetization.

**Three gate lists**, which is the owner's "layered": list 0 bit-decomposes the
frame, copies the carried bits and builds the `x·y` helper of each three-way XOR
bit; list 1 assembles the carried scalars and the XOR values; list 2 is the
sixty-four rounds, the forty-eight schedule equations and the eight output sums.

### 2.2 `EC_ADD` — family 17, ecall `0x0506`, space 9

One third of an addition a row, a 97-word frame, `2^16`, **`RANGE16`**. 392 `M`
and 1,028 `W`, 8,772 inner, 9,409 relations, 1,110 obligations, four outputs.

Renes–Costello–Batina 2015 **Algorithm 7** for `a = 0`, homogeneous projective,
**complete**. Twelve multiplications in three groups of three reductions, and
**nine reductions rather than twelve** — each of the three outputs is two
products under one quotient, which the limb identity's shape allows for free.

**The formula is the caller's, not the circuit's.** `guests/vendor/k256`'s
`ProjectivePoint::add` *is* Algorithm 7 over homogeneous projective coordinates,
so the delegation is a drop-in for a method whose storage does not move, and the
two paths agree **limb for limb** and not merely as points. That was the owner's
rule — a delegation understands the representation its caller already uses — and
it is the reason the patch is three method bodies rather than a rewrite.

---

## 3. The guest side

### 3.1 `guest-sdk`

Two frames, two declaration records in their own `#[link_section]`s, two raw
shims, and `ec_add_complete`, which walks one addition's three selectors in
order. **That last is the only thing about this ABI that is a wrong answer
rather than a refusal if a caller gets it wrong**: two groups transposed is a
different point, computed from lanes whose previous contents were zero, so the
order is not left to a caller.

`guest_sdk::sha256` is the patchable digest surface, `keccak256`'s shape: the
padding and the block loop in guest code, one delegation ecall per compression,
and a software compression behind the same signature, so a guest never chooses a
path and cannot tell which ran.

### 3.2 The three callers

| caller | reaches | how |
| --- | --- | --- |
| `guests/vendor/k256` | `EC_ADD` | `ProjectivePoint::{add, add_mixed, double}` select `apogee::*` under `cfg(target_arch = "riscv32")`; each upstream body moves down one function and becomes the fallback. Storage untouched |
| `guests/vendor/revm-precompile` | `SHA256_COMP`, `EC_ADD` | the **default bodies** of `Crypto::{sha256, bn254_g1_add, bn254_g1_mul}` select a delegated path under the same `cfg`. No second implementation — §3.5 is why |
| `guests/{sha256-ops,ec-ops}` | both | by name, over frames they write themselves |

**`double` routes through the delegation and its fallback stays Algorithm 9.**
Algorithm 7 is complete, so `P + P` is a correct doubling and the delegation
needs no second frame; in *software* the dedicated doubling is cheaper, and an
executor taking the fallback is paying software prices for everything.

**`add_mixed`'s identity correction is kept.** An affine identity is `(0, 0)`
here, which lifted to `(0 : 0 : 1)` is neither the projective identity nor a
curve point, so no complete formula rescues it — upstream's `conditional_assign`
is what does.

**The BN254 parsing is upstream's own, not a copy.** `read_g1_point` and
`encode_g1_point` are `pub(super)`, so the two new functions go *inside*
`src/bn254/arkworks.rs` where they are in scope. A malformed point, a coordinate
at or above the modulus and the `(0, 0)` encoding of infinity are then refused
by exactly the code that refuses them on the host. A second parser for a
consensus boundary is a risk with no upside once the first is reachable, and an
earlier draft of this stage carried one.

### 3.3 Two fixture guests

`guests/sha256-ops` checks the frame ABI against FIPS 180-4's own `"abc"` vector
— one padded block, so the compressed state *is* the published digest — and the
digest surface at seven message **lengths**, chosen because what can go wrong
above the compression is the padding: 55 is the last that pads into one block
and 56 the first that needs two. Every vector is checked twice, against a
published digest and against `sha2`, an unpatched crates.io implementation and
the only one in that comparison which is not this repository's. Exit 12.

`guests/ec-ops` runs its own Algorithm 7 over its own eight-limb long division
on **every** delegated addition and compares limb for limb — which it can,
because the circuit computes that same formula over that same representation —
then checks the point against `k256` and `ark-bn254` by **cross-multiplication**,
`X₃·1 = x·Z₃`, so no modular inverse runs in the guest and neither side has to
pick a projective representative. All four completeness cases are covered:
`P + P`, `P + O`, `O + O` and `P + (−P)`. Exit 20.

### 3.4 The invocation counts, and what they are for

Pinned in `crates/emulator/tests/guests.rs`, and every one is derivable by hand
from the guest's source, which is what makes it a pin and not a recording.

| guest | family | invocations | why that number |
| --- | --- | --- | --- |
| `sha256-ops` | `SHA256_COMP` | 33 | 2 by name, 31 through the block loop |
| `ec-ops` | `EC_ADD` | 81 | 27 point operations × 3 — 20 its own, 7 inside its own `k256` oracle |
| `ec-ops` | `MOD_MUL` | 2,084 | the field arithmetic under its software path and its oracles' inversions |
| `mod-mul-ops` | `EC_ADD` | 39 | 13 point operations × 3, **all inside `k256`** |
| `mod-mul-ops` | `MOD_MUL` | 1,443 | 1,567 before the projective patch moved its group arithmetic out |

**`mod-mul-ops`' two counts are the projective patch's only test.** That guest's
own source names no shim at all, so if the patch stopped routing, every check in
it would still pass and only these two numbers would move.

---

## 4. `MOD_MUL` re-shaped, in the same stage

The owner folded it in, and it is the clearest measurement of what a channel is
worth on a delegation family.

| | pre-S26c | now | factor |
| --- | --- | --- | --- |
| committed columns | 3,468 | **325** | 10.7 |
| enforcing gates | 3,502 | **125** | 28.0 |
| obligations | 0 | **274** | — |
| wire bytes | 1,404,716 | **550,391** | 2.6 |
| proof bytes a shard | 360,884 | **135,220** | 2.7 |
| computed peak a shard | ~4.9 GB | ~5.1 GB | 1.0 |

**The peak does not fall**, and `constraints::mod_mul`'s header claimed it fell
1.9×. The work moved out of the base layer and its first bind and into the inner
layers: 158 inner columns became 2,244, so the forward pass grew 0.27 → 4.57 GB
while the committed base fell 0.96 → 0.16 and the first bind 3.64 → 0.34. What
the channel buys is the **proof and the commitments** — 325 Mercury column
commitments where there were 3,468 — at constant peak.

**One consequence reached further than expected.** The family can no longer be
built below `2^16`, so `MOD_MUL_FIXTURE_VARS = 8` is gone and
`DELEGATION_CHANNEL_VARS = 16` replaces it. That in turn retired the multi-shard
fixture — at `2^16` the 1,443 invocations are one shard, 98% padding — and
forced both the checker suite and the prover fill test onto **row-local**
evaluation, a forward pass at that height being 4.6 GB. Both are cheaper than
what they replaced and both are the same statement per row.

### 3.5 Why `install_crypto` was abandoned, with the number

The owner chose revm's `Crypto` hook at the start of the stage and it was the
right first answer: it is the seam revm offers, it needs no vendoring, and the
precompile boundary hands points over in affine form, which is a semantic
boundary rather than a representation one. **It costs 870,828 bytes of guest
`.text`**, and that is what changed the answer.

Installing a second `Crypto` implementation makes `crypto()`'s `OnceLock` hold
one of two types, which kills LLVM's devirtualization of every call through it —
and with the devirtualization goes the dead-stripping of the arkworks BLS12-381
pairing and the KZG point-evaluation verifier, neither of which this workload
reaches. The measurement is unambiguous: the release image went 2,224,940 →
**3,101,112** bytes with a provider whose every method forwarded straight back to
`DefaultCrypto`, so the cost is the **coercion** and not the code.

That matters because a decoded table's row `i` is pc `2i`: a `2^20` table reaches
`2·2^20 − 4 = 2,097,148`, and S24's release image already used 82% of it.
`revm-block` would have needed `2^22` — the menu's last entry, at four times the
table and about 42 GB of forward pass a shard — for code it never runs. `blst`
and `c-kzg` are already off, so no feature removes the BLS12-381 path; the
arkworks one is not optional.

**Patching the default bodies has none of that cost**: there is still exactly one
implementation, so the image grows by **10,568 bytes**. The owner's instruction
was to do it that way and to leave the host build byte-for-byte upstream, which
is what every `cfg(not(target_arch = "riscv32"))` arm does.

---

## 4. `MOD_MUL` re-shaped, in the same stage

*(§4 is above; this section continues at §5.)*

---

## 5. The three bugs, and what found each

None was visible to the emulator, to either fixture guest or to any shape test.
In all three the executor computes the right answer and only an honest prover
fails — which is the class of bug a checker suite exists for, and the reason the
owner's build order put those suites after the fills rather than before.

### 5.1 SHA-256's round constants could not ride a padding row

`round_a{i}` and `round_e{i}` carried `K_i` as a **bare literal constant**. A
padding row is an all-zero row, so the gate evaluated to `−K_i ≠ 0` and
`checker::check_padding` refused the circuit outright. `K_i` now rides a carried
`Scalar::Live`, one column a layer — the mask is an `M` column that only gate
list 0 may read, so it has to be carried like any other value.

**What made it possible is a count spelled twice.** `carried_scalars()` is
arithmetic and `carried_scalar_list()` is the list; adding a scalar to the second
without the first aliased its column onto the next block, and the first symptom
was `L{1}[15856] is written but gate list 1 never reads it`. `artifact` now
asserts the two equal, and the same for the carried bits.

### 5.2 `EC_ADD`'s offset was sized against the wrong slot

`OFFSET_MULTIPLE` exists to keep the quotient unsigned and was **256**, sized
against group 2's slot 0 at `−189 m²`. The binding slot is **slot 1**:
`yp·ym + bxx9·xz` reaches `−(22·22 + 63·3)·m² = −673 m²`. At 256 the honest
quotient of such a row is negative, `q_limb` cannot hold it, and the row is
unprovable — and `zz` above about `0.76m` is enough on its own, which is roughly
**a quarter of random invocations**.

Raised to 1024, which moved `CARRY_OFFSET_BITS` from 45 to 46. The carry's width
already had a derivation over an operand-ceiling table;
`the_offset_covers_every_slot` now derives this floor from **the same table**,
because the same products bound both and only one of the two arguments had been
made.

### 5.3 A gated conclusion written as an equality made every row unprovable

`{name}_below_modulus` read `enable − b_7 = 0` and means
`enable·(1 − b_7) = 0`. The first **forces** `b_7 = 0` where `enable` is 0, so a
value that *is* below the modulus on a row that does not read it becomes
unprovable — and every lane is such a value: `EcAddFrame::of` zeroes the six
intermediates, and a group-2 row's `X1..Z2` are ordinary coordinates.

**Every row of the family was unprovable**, and the prover fill had been written
to match: it filled a non-reading value's chain with zeros, which the chain's
sixteen *ungated* `canonical` gates accept only where `v = m`. Both are fixed,
and `crates/prover/tests/fills.rs` now evaluates a filled shard's rows against
the gates rather than only counting its addresses, which is what catches the
fill half.

### 5.4 And one that was not a bug in this stage's code

`trace::AddressSpace::from_tag` is a match on a `u8` and needs a catch-all. That
`_ => None` let S26c add two spaces to the enum, to `tag` and to five other match
sites while leaving `from_tag` answering `None` for both — a
`Row::delegation_space` panic reachable only from a guest that invokes the
family, which is how the fixture guests found it.
`crates/trace/tests/log.rs` now derives the round trip over `DELEGATION_SPACES`
rather than listing it.

---

## 6. The measurement

`cargo run --release -p profiler -- block mini-block`, the pinned mini-block —
block 26,057,509's first two transactions, 392,997 gas.

| | guest cycles | cycles per gas | against the baseline |
| --- | --- | --- | --- |
| before any delegation (S26 §6) | 23,733,540 | 60.4 | — |
| S26, witnessed modulus | 17,986,969 | 45.8 | −24.2% |
| S26b, four fixed moduli | 19,286,372 | 49.1 | −18.7% |
| **S26c** | **15,899,359** | **40.5** | **−33.0%** |

**−17.6% against S26b**, and the first time the block has gone below 41 cycles
per gas.

**All of it is the `k256` projective patch, and none of it is the revm hook.**
The mini-block's two transactions call **no** `0x02`, `0x06` or `0x07` — the
profiler's `bn254` and `sha256/ripemd160` candidates are both 0 calls — so the
`revm-precompile` patch is worth nothing on this fixture and is there for the
blocks that do call them. What moved is secp256k1: `EC_ADD` is invoked **1,728**
times, 576 point operations of three, and `MOD_MUL` falls from S26's 6,705 to
**1,123** as the twelve field multiplies an addition used to cost move inside the
EC circuit.

**A named follow-up, measured rather than guessed.** The conversion between
`k256`'s ten 26-bit limbs and the frame's eight 32-bit ones runs through
`FieldElement::to_bytes`, and it costs **778,752 cycles — 4.9% of the block**
(`apogee::limbs` 467,712 over 2,688 calls, `apogee::field` 311,040 over 1,728).
`field_10x26`'s own `apogee::{operand, unpack}` are the direct change of base and
would cut most of it, but reaching them from `projective.rs` means exposing them
through `FieldElement` and `FieldElementImpl` — two more changed files in a
vendored crate whose discipline is "the two or three files named against it". It
is left as a follow-up rather than taken here, and the figure above is what it
is worth.

---

## 7. `EC_ADD`'s peak, which is the stage's one unresolved cost

One `2^16` shard is a **computed 20.5 GB**: 18.3 GB of forward pass over 8,772
inner columns, 0.7 GB of committed base, 1.5 GB of transition 0's first bind.
Against ~11 GB for an execution shard and 5.1 GB for `MOD_MUL` at the same
height, **this is the peak-setting family in a block**.

`2^16` is **forced rather than chosen**: the `RANGE16` channel needs sixteen
variables, Mercury needs an even count, and `2^18` is four times worse. The only
lever is the group count — five groups of two reductions would be about
two-thirds the width at two more invocations an addition — and the owner's
decision was to keep `k = 3` and measure it rather than redesign on an estimate.
The model is calibrated: it predicts `MOD_MUL`'s 5.09 GB against a measured 4.86
GiB.

An earlier draft of `constraints::ec_add`'s module comment said 10.5 GiB, which
was wrong by a factor of two and is corrected in place.

---

## 8. What tests what

| level | what it says | where |
| --- | --- | --- |
| the constants | SHA-256's `IV` and `ROUND_CONSTANTS` **re-derived** from FIPS 180-4's generators — the fractional parts of the square roots of the first eight primes and the cube roots of the first sixty-four — in exact integer arithmetic | `crates/constants/tests/sha256.rs` |
| the circuits | the laws, the padding contract, `check_memory`, discharge, and the derivations that re-check their own constants | `constraints::{sha256, ec_add}`'s unit tests |
| the arithmetic | an honest witness against every gate, and one negative control per gate | `crates/checker/tests/{sha256,ec_add}.rs`, 14 + 21 tests |
| the fills | the fill's own columns against the circuit's gates — a forward pass for `SHA256_COMP` at `2^8`, sampled rows for the two at `2^16` | `crates/prover/tests/fills.rs` |
| the executor | the frame executors against independent oracles | `crates/emulator/src/lib.rs`' unit tests |
| the guests | the ABI by name, against published digests and against a foreign implementation | `guests/sha256-ops`, `guests/ec-ops` |
| the routing | the invocation counts, which are the only thing that can see a vendored patch still routing | `crates/emulator/tests/guests.rs` |
| detachment | which families each image declares, at both optimisation levels | `crates/program/tests/delegation.rs` |

**No anchor twin was added**, and that is deliberate. The anchor is one
mechanism, built by `constraints::delegation` identically for all six families
and already proved refused at block level over four of them — including
`MOD_MUL`, which also carries a channel, so even that combination is not new. A
fifth and sixth replay would be the same mutation set at two more re-proofs in
the slowest deferred suite, which the root `CLAUDE.md`'s test rule exists to
refuse.

---

## 9. Deviations and decisions, listed

1. **`docs/spec/delegation.md` §9's rule is amended, not merely extended.** "A
   delegation family carries no lookup channel" was stated in four places and is
   now false for two families. §10.3 is the record, and the half that survives is
   stated as such.
2. **`MOD_MUL` changed shape in a stage that was not about it.** The owner folded
   it in; §4 is what it bought, and §18 of the manifest is rewritten.
3. **`MOD_MUL` can no longer be built at `2^8`.** `MOD_MUL_FIXTURE_VARS` is gone.
   Two suites moved to row-local evaluation as a result, and a deferred tamper
   test's `mm_shards >= 2` became `== 1`.
4. **A third crate is vendored**, `revm-precompile`, for the measured reason in
   §3.5. The owner directed it after the `install_crypto` cost was measured.
5. **`guests/revm-block` gained and then lost a `precompile` module.** Its
   mirrored BN254 parser is deleted in favour of upstream's own, reachable from
   inside the vendored crate.
6. **`EC_ADD`'s peak is 20.5 GB a shard and is not measured yet**, §7.
7. **The `k256` limb conversion costs 4.9% of the block** and is a named
   follow-up, §6.

---

## 10. What a later stage would pick up

- **The pairing.** `0x08` is where the measured BN254 cycles in every profiled
  block actually are — `sum_of_products` call counts pin block 26,059,700's to
  one ~4-pair pairing plus some thirteen cheap G1 calls — and it was out of scope
  by the owner's own terms. `EC_ADD` accelerates the G1 operations *inside* a
  pairing not at all, because arkworks' Miller loop works in `Fq12` and not on
  G1.
- **`ark_ff::Fp::sum_of_products`**, which S26b's patch does **not** route and
  which is 18.88% of block 26,059,700 by itself. It is a candidate the owner
  declined to widen to at S26b; the number has not moved.
- **RIPEMD-160**, the other half of the `OtherHash` category, which shares a
  profiler row with SHA-256 and nothing else: five words of state where SHA-256
  has eight, little-endian where it is big-endian, and a different round
  function. One frame does not serve both.
- **`EC_ADD` at `k = 5`**, if §7's measured peak turns out to matter.
