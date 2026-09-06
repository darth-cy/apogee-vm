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
  decisions.md   why a non-obvious choice was made; newest last
  GLOSSARY.md    the vocabulary (column = multilinear = poly; layer; shard; family)
  handoff/       one note per completed stage: frozen API, artifacts, deviations
crates/
  constants/     frozen constants and tags; zero logic; no_std
  field/         Fr arithmetic (Montgomery); no_std
tools/
  kat-gen/       regenerates the committed Fr test vectors from arkworks
  bench/         comparative microbenchmarks against arkworks
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
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace                      # 33 tests as of S01
cargo build -p field -p constants --target riscv32imac-unknown-none-elf   # guest target
cargo run -p kat-gen && git diff --exit-code -- crates/field/tests/vectors/
-------------------------------------------------------------------------------
cargo run -p kat-gen                        # refresh fixtures (manual, deliberate)
cargo run --release -p bench                # internal numbers only, no public claims
```
The toolchain, its components and the guest target come from `rust-toolchain.toml`. CI
does not name a version anywhere, so it cannot drift from that pin.

## The rules that bite most often
- **Concrete types.** `Fr` is a struct. There is no `F: Field`, and there never will be.
- **No cargo features. Zero.** One build configuration for the whole workspace.
- **One encoding.** Field elements on the wire are canonical (non-Montgomery) 32-byte
  little-endian. Montgomery form exists only in memory.
- **Own the crypto.** Runtime dependencies are limited to serialization, rayon, CLI and
  error handling. arkworks is a reference oracle for tests and fixtures only.
- **No `unsafe`, no nightly, no async, no threads.** Parallelism is rayon over data.
- **Boring beats clever.** Added surface area is a defect. Every verifier entry point is
  `(&VerifyingKey, &Proof, &PublicInputs)` and nothing else.

## Status
| Stage | State | Handoff |
| --- | --- | --- |
| S01 — Fr field + constants skeleton | done | `docs/handoff/S01-field.md` |
