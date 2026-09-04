# Decision log

One entry per decision that a later reader would otherwise have to re-derive. Newest
last. A decision that is only "we did the obvious thing" does not belong here.

## S01 — Fr field and constants skeleton

**Edition 2021, not 2024.** Nothing in the workspace needs 2024, and 2021 is the
edition every stable toolchain in use understands. Pinned alongside the toolchain in
`rust-toolchain.toml` (1.96.1), because reproducible guest builds are program-identity
load-bearing.

**Crate package names equal their directory names** (`field`, `constants`, …), matching
the frozen layout in the master prompt. Nothing is published, so the generic names cost
nothing.

**`serde` is taken with `default-features = false`.** `crates/constants` and
`crates/field` are `#![no_std]` forever, because guest code links them; serde's default
`std` feature would make them unbuildable for `riscv32imac-unknown-none-elf`. This is
not a cargo feature *of ours* — the workspace still has exactly one build
configuration, which is what anti-goal 1 protects.

**`Fr` serde is hand-written, not derived**, so no proc-macro (`serde_derive`) enters
the build and so the impls visibly route through `to_bytes`/`from_bytes`. It is 12
lines.

**Inversion is Fermat (`pow(p-2)`), not extended Euclid**, as the stage pins. It costs
~1.9× arkworks' binary-GCD inverse and is a fraction of the code. `batch_inverse`
amortizes it away wherever inversion is on a hot path.

**`square()` calls the general multiplier.** A dedicated squaring routine is an
optimization, and there is no benchmark yet showing it matters on the real workload.

**KAT fixtures are a whitespace-delimited hex text file, not JSON.** The stage allows
"or similar committed format". A line-oriented format needs ten lines of parsing rather
than a JSON dependency, diffs cleanly, and hashes the same way.

**Fixtures are pinned by SHA-256 checked in a test**, per master rule 11. SHA-256 is
implemented in ~55 lines of test-only support code rather than taken as a dependency,
and is itself checked against the two NIST vectors.

**`tools/bench` and `tools/kat-gen` depend on arkworks as normal dependencies.** Master
rule 2 allows reference libraries as dev-dependencies or fixture generators; a bin
target cannot express "dev-dependency". Neither tool is reachable from the prover, the
verifier, or a guest.
