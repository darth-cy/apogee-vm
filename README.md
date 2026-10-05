# Apogee

Apogee is a RISC-V zkVM. It proves that an RV32IMAC program, named by a digest of its image, ran on
a given public input to an exit status and wrote a given public output, and it carries that proof
through a recursion tree to one Groth16 proof a contract checks. Its workload is Ethereum block
validation. Proofs are succinct, not zero-knowledge.

```text
guest ELF ──► ProgramImage ──► decoded tables, VmConfig, program identity
                   │
              execution ──► rows, one table per circuit family ──► shards of 2^8 … 2^22 rows
                   │
   per shard: commit the columns (Mercury) · GKR backward pass (sumcheck) · one batched opening
                   │
              block proof ──► recursion tree ──► Groth16 decider ──► ApogeeVerifier.sol
```

- **Arithmetization.** 23 circuit families over BN254's scalar field, each a layered GKR circuit:
  seven for instructions, five for memory windows, six **delegations** (Keccak-f, SHA-256,
  Poseidon2, field and curve arithmetic) and five for recursion. Gates are checked by sumcheck,
  memory by one read/write multiset over the whole execution, lookups by LogUp.
- **Commitments.** Mercury, a multilinear scheme over KZG with a constant-size opening, on the PSE
  powers-of-tau ceremony. No FRI, no hash-based commitment.
- **Fiat–Shamir.** A Poseidon2 duplex transcript.
- **Scale.** A two-pass streaming prover whose memory follows the shards in flight, not the length
  of the execution.
- **No external cryptography.** Fields, curve, pairing, MSM, hash, PCS, GKR and Groth16 are
  implemented here; arkworks, Plonky3 and zkhash appear only as test oracles.

## Documentation

[docs/architecture.md](docs/architecture.md) is the place to start: what a proof states, how
soundness composes, what it assumes, its limits and its measured cost. The specification is
[docs/spec/](docs/spec/), one page per subject, mapped to the code below;
[docs/glossary.md](docs/glossary.md) indexes the vocabulary,
[docs/guest-program-manual.md](docs/guest-program-manual.md) walks through writing and proving a
guest, and [docs/tools.md](docs/tools.md) covers every binary. Source comments cite the spec by
section (`docs/spec/memory.md` §2.4); where a page and the code disagree, the code is right.

## Repository

| path | what it is | specified in |
| --- | --- | --- |
| `crates/constants` | every protocol constant, tag and identifier; no logic | the page that uses each |
| `crates/field`, `curve`, `poly`, `sumcheck` | `Fr`; the `Fq` tower, G1/G2, pairing, MSM; multilinear polynomials; zerocheck | [primitives](docs/spec/primitives.md) |
| `crates/transcript` | Poseidon2 and the duplex transcript | [transcript](docs/spec/transcript.md) |
| `crates/srs` | ceremony ingestion, the SRS archive, KZG, Groth16's phase 1 | [srs](docs/spec/srs.md) |
| `crates/pcs`, `pcs-verify` | Mercury and deferred verification; `pcs-verify` is verification's field side | [mercury](docs/spec/mercury.md) |
| `crates/loader`, `isa`, `program` | ELF to `ProgramImage`; the decoder; decoded tables, `VmConfig`, program identity | [program](docs/spec/program.md) |
| `crates/emulator`, `trace` | the executor and its tracers; rows, memory state, column builders | [execution-trace](docs/spec/execution-trace.md) |
| `crates/constraints` | every circuit as data: memory frames, lookup channels, the family circuits, the registries | [gkr](docs/spec/gkr.md), [memory](docs/spec/memory.md), [lookup](docs/spec/lookup.md), [circuits](docs/spec/circuits.md) and the family pages |
| `crates/gkr-verify`, `gkr` | the GKR verifier and prover | [gkr](docs/spec/gkr.md) |
| `crates/verifier-core` | statement, transcripts, verifying key, every check of a shard and a block but the opening; recursion's tapes, nodes and folding | [proof](docs/spec/proof.md), [recursion](docs/spec/recursion.md) |
| `crates/verifier` | `verify_shard`, `verify_block`, the proof archive, the `verifier` CLI | [proof](docs/spec/proof.md) |
| `crates/prover` | key construction, column fills, the streaming prover, the debug log | [streaming](docs/spec/streaming.md) |
| `crates/groth16` | Groth16 with bound wires and a two-phase ceremony | [recursion](docs/spec/recursion.md) §9 |
| `crates/host` | the host SDK: setup, prove, verify; the block-witness recorder; the recursion tree and decider | [ethereum](docs/spec/ethereum.md), [recursion](docs/spec/recursion.md) |
| `crates/checker` | independent validators of the circuit laws, native lookup and memory evaluators, the tamper harness, the `checker` CLI | [circuits](docs/spec/circuits.md) §3 |
| `crates/guest-sdk` | the guest runtime: entry, linker script, allocator, memory regions, delegation shims | [ecall-abi](docs/spec/ecall-abi.md), [delegation](docs/spec/delegation.md) |
| `guests/` | test and workload guests, a workspace of their own; `vendor/` holds patched upstream crates | [manual](docs/guest-program-manual.md), [vendor](guests/vendor/README.md) |
| `contracts/` | `ApogeeVerifier.sol` | [recursion](docs/spec/recursion.md) §9 |
| `tools/` | `kat-gen`, `bench`, `profiler`, `artifact-dump`, `test-support`; `transcript-ref` and `stateless-ref`, independent oracles outside the workspace | [tools](docs/tools.md) |
| `docs/publication/` | the papers the PCS and the pairing follow | [mercury](docs/spec/mercury.md), [primitives](docs/spec/primitives.md) |

The circuit families are specified in [add-sub](docs/spec/add-sub.md),
[jump-branch-slt](docs/spec/jump-branch-slt.md), [shift-bitwise](docs/spec/shift-bitwise.md),
[mul-div](docs/spec/mul-div.md), [memory-ops](docs/spec/memory-ops.md),
[public-values](docs/spec/public-values.md), [delegation](docs/spec/delegation.md) and
[delegation-circuits](docs/spec/delegation-circuits.md).

## Requirements

- The toolchain, its components and the `riscv32imac-unknown-none-elf` target are pinned in
  `rust-toolchain.toml`; `rustup` installs them on first use.
- Program identity, real keys and proving need the ceremony file `assets/ptau/ppot_0080_24.ptau`
  ([srs](docs/spec/srs.md) §1). The workspace tests do not.
- Proving is memory-bound: a full block peaked at 174 GiB ([streaming](docs/spec/streaming.md) §1).

## Commands

```sh
# What CI runs (.github/workflows/ci.yml is the full list)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p kat-gen && git diff --exit-code     # committed fixtures regenerate identically

# Guests: their own workspace and target
(cd guests && cargo clippy --bins -- -D warnings)
(cd guests/fib && cargo build --target riscv32imac-unknown-none-elf)   # --release for proving

# Prove and verify a block, then recurse and decide (docs/spec/recursion.md §10)
cargo run --release -p bench -- prove mini-block --out <dir>
cargo run --release -p verifier -- block <stem>.vk <identity-hex> <stem>.public <stem>.block
cargo run --release -p bench -- recurse <dir>/<stem> --out <out>
```

The suites that prove real shards are `#[ignore]`d and CI does not run them: each proves over a toy
SRS of its own and needs tens of GiB.

```sh
cargo test --release -p prover --test <suite> -- --include-ignored --test-threads=1
#   acceptance, control, alu, mem, fills, block, streaming, keccak, recursion, public_io, revm
cargo test --release -p host --test prove -- --include-ignored --test-threads=1   # a mainnet mini-block
cargo test --release -p checker --test tamper -- --include-ignored --test-threads=1   # every tamper twin
```
