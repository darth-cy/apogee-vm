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
| `guests/revm-block` | `SHA256_COMP`, `EC_ADD` | a `Crypto` provider installed on the guest target alone, overriding `sha256`, `bn254_g1_add` and `bn254_g1_mul` of the trait's eighteen methods |
| `guests/{sha256-ops,ec-ops}` | both | by name, over frames they write themselves |

**`double` routes through the delegation and its fallback stays Algorithm 9.**
Algorithm 7 is complete, so `P + P` is a correct doubling and the delegation
needs no second frame; in *software* the dedicated doubling is cheaper, and an
executor taking the fallback is paying software prices for everything.

**`add_mixed`'s identity correction is kept.** An affine identity is `(0, 0)`
here, which lifted to `(0 : 0 : 1)` is neither the projective identity nor a
curve point, so no complete formula rescues it — upstream's `conditional_assign`
is what does.

**The BN254 parsing is upstream's, mirrored, and deliberately not cfg-gated.**
`revm_precompile::bn254::arkworks`' `read_g1_point` and `encode_g1_point` are
`pub(super)` and out of reach, so `guests/revm-block/src/precompile.rs` carries
its own. A divergence there is a **consensus** bug, not a slow path, so they
compile for the host too and can be held against the real `DefaultCrypto`.

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
