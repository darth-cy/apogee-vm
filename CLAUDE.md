# apogee-vm

A RISC-V zkVM proving RV32IMAC guest programs, arithmetized as GKR circuit families
over the BN254 scalar field Fr, proven with gate-based sumcheck, committed with the
Mercury multilinear PCS, transcripted with Poseidon2. No FRI anywhere. The full
specification, the frozen protocol invariants, the effort budget and the anti-goals
live in `prompts/00-master.md` — **read it before writing code**, along with the stage
prompt you are working on.

## Where things are
```
.github/         CI: fmt, clippy, tests, guest build, fixture regenerate-and-diff
prompts/         00-master.md (design authority) + one prompt per build stage
docs/
  GLOSSARY.md    the vocabulary (column = multilinear = poly; layer; shard; family)
  spec/          the frozen protocol specs; read before touching what they cover
  handoff/       one note per completed stage: frozen API, artifacts, deviations
crates/
  constants/     frozen constants and tags; zero logic; no_std
  field/         Fr arithmetic (Montgomery); no_std
  curve/         Fq tower through Fq12 + G1/G2 + the optimal ate pairing + Pippenger MSM; std
  transcript/    Poseidon2 permutation + duplex transcript; no_std
  poly/          MultilinearPoly + small-type backing + eq machinery; no_std
  sumcheck/      Gate + zerocheck prover/verifier; no_std
  srs/           snarkjs .ptau ingestion, the SRS archive, univariate KZG; std
assets/          gitignored: the PSE powers-of-tau ceremony files; see the S07 handoff
tools/
  kat-gen/       regenerates the committed Fr, multilinear, curve, MSM and SRS vectors from arkworks
  bench/         one routine per measurement, individually selectable
  transcript-ref/ the transcript oracle: Plonky3 + zkhash, NOT a workspace member
  test-support/  seeded RNG, SHA-256, hex; shared by every suite and generator
```
Later stages add the crates listed in the master prompt's workspace layout. Crate names
are frozen; internals are not.

## Build stage protocol
Read `prompts/00-master.md`, then the stage prompt, then every prior note in
`docs/handoff/`. Branch off `main`, commit on the branch, open a PR, and finish by
writing `docs/handoff/<stage>.md` and updating this file. Raise conflicts and
open questions with the user rather than picking a default silently.

## Commands
Everything above the line is what CI runs (`.github/workflows/ci.yml`); a green local
run of these is a green CI run.
```
cargo fmt --all -- --check
cargo fmt --manifest-path tools/transcript-ref/Cargo.toml --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --manifest-path tools/transcript-ref/Cargo.toml --all-targets -- -D warnings
cargo test --workspace                      # 251 tests as of S07
cargo build -p field -p constants -p transcript -p poly -p sumcheck --target riscv32imac-unknown-none-elf
cargo run -p kat-gen
cargo run --manifest-path tools/transcript-ref/Cargo.toml
git diff --exit-code -- crates/field/tests/vectors/ crates/transcript/tests/vectors/ crates/poly/tests/vectors/ crates/curve/tests/vectors/ crates/srs/tests/vectors/
-------------------------------------------------------------------------------
cargo run -p kat-gen                        # refresh every fixture (manual, deliberate)
cargo run -p kat-gen -- <group>             # just one: field | poly | curve | tower | pairing | msm | srs
cargo run --manifest-path tools/transcript-ref/Cargo.toml   # ditto, transcript vectors
cargo run --release -p bench                # every routine; internal numbers only
cargo run --release -p bench -- --list      # the routines, and what each measures
cargo run --release -p bench -- <routine>   # just that one; setup is per-routine
```

`tools/transcript-ref` is deliberately outside the cargo workspace, so it takes
`--manifest-path` rather than `-p`. Its Plonky3 and `zkhash` dependencies would otherwise
feature-unify `serde/std` into `crates/field` during `cargo test --workspace`.
The toolchain, its components and the guest target come from `rust-toolchain.toml`. CI
does not name a version anywhere, so it cannot drift from that pin.

## The rules that bite most often
- **Concrete types.** `Fr` is a struct. There is no `F: Field`, and there never will be.
- **No cargo features. Zero.** One build configuration for the whole workspace.
- **One encoding.** Field elements on the wire are canonical (non-Montgomery) 32-byte
  little-endian. Montgomery form exists only in memory. Source literals are the one
  exception and are their own single form: `Fr::from_hex`, `0x` plus 64 lowercase digits,
  big-endian, because a constant in source is a number and should diff against upstream.
- **Fq is not Fr.** `Fr` is the scalar field everything is arithmetized over; `Fq` is the
  base field curve coordinates live in. The moduli agree in their top 128 bits. `curve::Fq`
  is a deliberate literal duplicate of `field::Fr`'s Montgomery kernel, not an abstraction
  over it, and `curve::g2` is a literal mirror of `curve::g1`.
- **The pairing is the exact power.** `final_exponentiation` returns `f^((q^12-1)/r)` and
  never a fixed multiple of it, so the Fuentes-Castañeda hard part is out — which also
  means arkworks' own `Bn254::pairing` is *not* a drop-in oracle, and the fixtures raise
  its Miller output to the literal exponent instead.
- **Points on the wire are uncompressed affine.** 64 bytes `x ‖ y` for G1, 128 bytes
  `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1` for G2, each coordinate canonical 32-byte LE, all-zero for
  infinity. No compressed form, no decompression, ever. A point's *transcript* form is a
  different thing: four ~128-bit Fr limbs.
- **One index convention.** Variable `j` is bit `j`: the evaluation at `y` sits at
  `index = sum_j y_j 2^j`, and `bind` fixes variable 0, the low bit. Frozen in
  `crates/poly` and load-bearing for every later circuit stage. Sumcheck round `i`
  binds variable `i`, so a claim's point reads in that same order.
- **Fixed proof shapes.** A sumcheck round message is 4 coefficients, always — the
  degree ceiling makes the round polynomial a cubic, and nothing in a proof has a
  data-dependent length.
- **One tag, one message kind.** The transcript frames typed messages as
  `tag, length, payload`, so a tag in `constants::transcript_tags` must name exactly one
  of scalars, bytes or a challenge. Reusing one across kinds is a soundness bug.
- **The ceremony is PSE's, not Hermez's.** `ppot_0080_<power>.ptau` from PSE's perpetual
  powers of tau, contribution 80, and nothing else. Hermez's `powersOfTau28_hez_final_*`
  is a *different ceremony with a different `tau`*: the two are not interchangeable, and
  swapping one in silently gives a correct-looking SRS whose committed fixtures do not
  match. `docs/spec/srs.md` §2.0.
- **`.ptau` points are little-endian *Montgomery*.** The one file format here that is
  not canonical: a ceremony file stores `coord * R mod q`, because that is
  ffjavascript's in-memory layout written straight out. `crates/srs` multiplies by
  `R^-1` and hands canonical bytes to S05's `from_bytes`, so there is still exactly one
  validating decoder.
- **SRS integrity is presumed; there is no SRS digest.** S07's Poseidon2 digest over the
  SRS was dropped on instruction, so the master's statement-binding item `SRS digest`
  has no implementation and nothing binds a proof to a particular SRS. Read
  `docs/spec/srs.md` §4 before building statement binding.
- **Own the crypto.** Runtime dependencies are limited to serialization, rayon, CLI and
  error handling. arkworks, Plonky3 and `zkhash` are reference oracles for tests and
  fixtures only, and never reachable from the prover, the verifier or a guest.
- **No `unsafe`, no nightly, no async, no threads.** Parallelism is rayon over data.
- **Boring beats clever.** Added surface area is a defect. Every verifier entry point is
  `(&VerifyingKey, &Proof, &PublicInputs)` and nothing else.

## Status
| Stage | State | Handoff |
| --- | --- | --- |
| S01 — Fr field + constants skeleton | done | `docs/handoff/S01-field.md` |
| S02 — Poseidon2 permutation + duplex transcript | done | `docs/handoff/S02-transcript.md` |
| S03 — MultilinearPoly + small-type backing | done | `docs/handoff/S03-poly.md` |
| S04 — Gate-based sumcheck (zerocheck) | done | `docs/handoff/S04-sumcheck.md` |
| S05 — Fq tower + G1/G2 arithmetic | done | `docs/handoff/S05-fq-tower-curve.md` |
| S06 — Fq6/Fq12, Miller loop, final exponentiation | done | `docs/handoff/S06-pairing.md` |
| S07 — Pippenger MSM + ptau ingestion + KZG | done | `docs/handoff/S07-msm-srs-kzg.md` |
