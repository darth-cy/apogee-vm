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

**CI is one job, one file, no caching and no third-party actions.** Anti-goal 12 warns
against tooling that creates friction without catching bugs, so the job runs only
checks that can actually fail on a real defect: fmt, clippy at `-D warnings`, the test
suite, the guest-target build, and regenerate-and-diff of the committed fixtures. The
toolchain comes from `rust-toolchain.toml` rather than a setup action, so there is
exactly one place the pinned version lives. No dependency caching until a build is slow
enough to justify it — an unmeasured optimization is still unmeasured in CI.

## S02 — Poseidon2 permutation and duplex transcript

**The oracle both transcribes the spec and cross-checks Plonky3's `DuplexChallenger`.**
The stage asks for "a small spec-pseudocode transcript driver", and a transcription is
what checks that the *specification text* produces the committed values. But spec sections
5-7 are also exactly `DuplexChallenger` at width 3 and rate 2, and a transcription alone
would only test our reading of Plonky3 against our reading of Plonky3. So the driver runs
both on every raw operation and asserts they agree; the committed values come from the
transcription, and the reference type confirms each one as it is produced. A disagreement
fails the generator and therefore CI. Verified non-vacuous: deleting the absorb-length tag
from the transcription makes the generator abort.

**The reference oracle links two upstream implementations, not one.** The stage names
Plonky3 as the differential oracle, but Plonky3 does not ship the BN254 `RC3` constants —
its own BN254 test imports them from HorizenLabs' `zkhash`, which also carries an
independent Poseidon2. `tools/transcript-ref` takes the constants from `zkhash` and the
permutation from Plonky3, exactly as Plonky3's own differential test does, so the
committed vectors are agreed by two upstream implementations before this repository sees
them.

**`tools/transcript-ref` is excluded from the cargo workspace.** Its dependency graph
enables `serde/std` (`zkhash` takes serde with default features). Inside the workspace,
cargo's feature unification would hand `serde/std` to `crates/field` during
`cargo test --workspace`, so the featureless serde the guest actually links would be
compiled but never executed — the exact trap S01 documented and avoided. The tool is its
own workspace root with its own committed `Cargo.lock`, and CI drives it by
`--manifest-path`. `tools/kat-gen` stays a member: arkworks does not pull `serde/std`.

**Round constants are vendored as upstream's hex literals and decoded at runtime.**
`poseidon2_permute` reads 80 constants per call, and after S01 there is no way to write
down an `Fr` *table* at compile time: the limb field is private and every constructor is a
runtime function. So the choice was to give `field` a compile-time constructor or to decode
per call.

The first version of this stage took the compile-time route — a `const fn`
`Fr::from_canonical_limbs`, which required const-ifying `mont_mul` and its helpers. That
was reverted. Two claims used to justify it did not survive measurement: "roughly doubles
the cost of a permutation" was really **1.23x** for a byte-array table, and "the
permutation is the recursion verifier's hot loop" is wrong — in the guest, Poseidon2 is a
delegation circuit, so this Rust code is host-prover and native-verifier work. Master rule
11 forbids optimising without a benchmark showing it matters on the real workload, and
there is no real workload yet.

What ships instead: `constants` holds the literals copied from upstream character for
character, and `field::Fr::from_hex` decodes them on every call. `crates/field/src/lib.rs`
is otherwise byte-identical to its S01 state — the diff is 40 added lines and nothing
else. Measured: **4667 ns** per permutation with the decode already done, **8201 ns** as
shipped, so decoding costs **1.76x**. That is the price of a vendored table a reviewer can
diff against upstream by eye and an S01 crate nobody had to edit. If a real workload ever
says it matters, the fix is a decoded table and it needs a benchmark in the same commit.

**`Fr::from_hex` is big-endian, `to_bytes` is little-endian, and that is deliberate.** A
hex literal in source is a number, so it reads in the order `Debug` already prints and the
order upstream writes its tables; the wire form is bytes, so it stays little-endian per
master rule 3. There is exactly one accepted spelling — `0x`, then 64 lowercase digits —
so a mistyped constant fails at its `expect` instead of becoming a different field
element.

**Only the round constants the permutation reads are vendored.** Upstream `RC3` is 64 rows
of 3, but the 56 partial rounds use lane 0 alone and upstream stores zero in the other
two. Storing the full table would have put 112 rows of zeros in `constants`. The three
vendored tables are split by the phase that reads them, and the test checks them against a
committed dump of the *full* upstream table — including that the dropped lanes really are
zero, so nothing was quietly discarded.

**Typed framing is `tag, length, payload` with no message-kind discriminant.** A kind
field would have made the absorbed stream unconditionally injective; without it,
injectivity rests on each tag naming exactly one message kind, since
`append_bytes(T, b"")` and `append_scalars(T, &[])` otherwise absorb the same stream. The
repository owner chose the smaller framing; the invariant is stated in
`constants::transcript_tags`, in `docs/spec/transcript.md` section 8, and in the crate's
`CLAUDE.md`, and every tag records its kind.

**`Fr` constant tables use `#[rustfmt::skip]` and hex without digit separators.** Left to
rustfmt, `POSEIDON2_RC3_*` runs to 500 lines of one limb per line. One constant per line
is both shorter and diffable by eye against the upstream file.

**A restored transcript starts with an empty event log.** The stage says a snapshot
captures the sponge state and both buffers; the log is metadata that never feeds the
sponge, so replaying it would be a second, silently divergent copy of state that does not
affect anything.

**Snapshots are canonical.** Buffer lanes at or past their length are kept zero in the
live transcript, not just when a snapshot is taken, and serde rejects a snapshot where
they are not. A snapshot is therefore a deterministic function of the operation sequence —
replay the same script, get the same bytes — which is what master rule 9's archivable
phase boundaries need. The stronger-sounding claim, that equal challenge futures imply
equal snapshots, is *not* made: when input is pending the rate lanes are already dead, so
a hand-built snapshot can differ there and still behave identically.

**SHA-256 is duplicated into `crates/transcript/tests/common/mod.rs`.** Master rule 11
wants fixtures pinned by hash. Sharing the ~55 test-only lines would mean a new crate or a
cross-crate `#[path]` include; the master prompt prefers duplication to an abstraction,
and both copies are checked against the two NIST vectors where they live.
