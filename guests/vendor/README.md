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
files named against it changed and nothing else, so the diff a reviewer has to
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

## `k256` 0.13.4 — S26

Upstream `https://github.com/RustCrypto/elliptic-curves`, commit
`5ac8f5d77f11399ff48d87b0554935f6eddda342` (`.cargo_vcs_info.json`), as published.
`Cargo.toml.orig` and cargo's `.cargo-ok` marker are not copied; every other file
is byte-identical to the release.

**Why.** S26's profile ranked secp256k1 first in every workload it measured:
30.98% to 47.81% of a whole mainnet block's guest cycles, and inside that, **one
function** — `FieldElementImpl::mul` — took 36.76% of block 26,059,929 by itself
at 1,318 cycles a call, with `FieldElement::square` a further 7.64% at 1,167.
That is the `F_p` multiply of the `ecrecover` precompile, and
`docs/spec/delegation.md` §14's `MOD_MUL` circuit is a 256-bit modular multiply
with a **witnessed** modulus, which is exactly the operation. There was no way to
reach it from outside the crate: the field type is private, the multiply is
inherent, and there is no hook.

**The two changed files.**

| file | change |
| --- | --- |
| `Cargo.toml` | one `[target.'cfg(target_arch = "riscv32")'.dependencies]` entry on `guest-sdk`. A target dependency and never a cargo feature, which is how `crates/field` and `crates/transcript` reach their own shims |
| `src/arithmetic/field/field_10x26.rs` | `mul` and `square` select `apogee::mul_mod_p` under `cfg(target_arch = "riscv32")` and are otherwise untouched, plus a new private `mod apogee` at the end of the file holding `P`, `packable`, `pack`, `unpack`, `operand` and `mul_mod_p` |

**Why that file and not `field_impl.rs`.** `field.rs` picks its
`FieldElementImpl` by `cfg(debug_assertions)`: the magnitude-tracking wrapper in
`field_impl.rs` when they are on, the bare `FieldElement10x26` when they are off.
Both route through `FieldElement10x26::mul`, so patching the one file covers both
configurations. `guests/Cargo.toml` pins `debug-assertions = true` in **both**
profiles, so the wrapper is what a guest gets either way, and it records the
delegated result as magnitude 1 and not normalized — which a fully normalized
value also is.

**What the patch has to get right.** A field element is ten 26-bit limbs; the
frame carries eight 32-bit ones. `pack` and `unpack` are that change of base, and
`packable` is the 13-cycle test for whether the value is below `2^256` at all —
a magnitude-8 element reaches `2^259`, and an operand has to be reduced before it
can cross the frame. It does **not** have to be reduced below `p`: the delegation
reduces modulo the modulus it is given. `operand` therefore tries three steps
cheapest-first — already packable, weakly normalized, fully normalized — and the
first applies to every `mul` result, so a chain of multiplies reduces nothing.

`packable`'s bound is exact: limbs 0–8 below `2^26` with limb 9 below `2^22` admit
`[0, 2^256)` and nothing more, the maximum being `2^256 - 1` exactly. So the test
is precisely "does this value fit the frame", and neither over- nor
under-approximates it.

**What it deliberately does not preserve.** Upstream's `mul` returns a *weakly*
normalized product; the delegated one returns the canonical residue. The two
agree as field elements and not as limb patterns. Nothing in `k256` compares
field elements by representation — every comparison is `normalizes_to_zero` over a
difference (`AffinePoint::ct_eq`, `ProjectivePoint::ct_eq`) — and `to_bytes`
normalizes first.

**What tests it.** `guests/mod-mul-ops`, and only that: on every executor but this
VM's the ecall answers `-ENOSYS` and upstream's own `mul_inner` runs, so a host
test cannot see the patched path at all. The guest's expectations are the absolute
compressed SEC1 encodings of `G`, `2G`, `3G` and `7G`, because an identity-only
test passes under a multiply that is wrong the same way everywhere; `crates/loader/
tests/qemu.rs` then runs the same binary under `qemu-riscv32`, where the software
path answers, and requires the same exit status — which is what makes it a
consistency statement and not one reading.

It checks points rather than a scalar multiplication on purpose: `k256`'s ladder is
**constant-time**, so `G · 7` is 256 doublings and shortening the scalar buys
nothing, while `double` and `+` exercise `pack` and `unpack` over exactly the same
full-width coordinates — `G`'s own are full width — at 3% of the invocations.

Beyond that, S26's pinned mini-block is the end-to-end check, and the strongest one:
its 90-byte journal is a commitment over the post-state of two real transactions
whose senders come out of `ecrecover`, and it is byte-identical with the delegation
and without it.

**What it bought.** On the pinned mini-block (block 26,057,509's first two
transactions) 23,733,540 guest cycles became 17,986,969 — **−24.2%**, 60.4
cycles per gas down to 45.8 — with `secp256k1` falling from 46.47% of the
execution to 28.11%.

**Refreshing it.** Copy the release over this directory again, re-apply the two
changes above, and re-run the mini-block profile. `docs/handoff/S26-cycle.md` §6
is the account of the measurement; `cargo run -p kat-gen -- guests` rebuilds
`mod-mul-ops.elf`.
