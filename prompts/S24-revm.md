---
title: 'S24 — revm guest, synthetic-state block'

---

# S24 — revm guest, synthetic-state block

## Depends on / Inputs
- S10 supplies `guest-sdk` (entry, ecall shims, allocator, `read`/`commit` io) and `loader`'s `ProgramImage`.
- S11 supplies `program`: `VmConfig` derivation and `ProgramIdentity`.
- S12 supplies the `emulator`, its QEMU differential harness, and `trace`/`TraceArchive`.
- S20 supplies `prover`/`verifier`: `BlockProof`, cross-shard reconciliation and `VerifyingKey`.
- S21 supply the keccak256 guest-side precompile shims, with bit-identical software fallbacks.

## Deliver
- `guests/revm-block` is a no-std guest running revm over a **synthetic in-memory pre-state** with one funded EOA. It runs two txs: (tx 1) a plain ETH transfer, (tx 2) a call into one small deployed contract. revm (no-std feature set) is a permitted guest dependency: the guest is workload, not proving stack.
- A host-side fixture builder, a dev tool or a test module, constructs the synthetic pre-state and txs and serializes the guest input.
- Freeze the guest input format as `BlockWitness` (serde/postcard). It carries the env/header fields revm needs, the pre-state accounts with nonce/balance/code/storage slots, and the txs. S25's witness recorder must be able to produce this exact type for real blocks, so keep account, slot and code entries general, not synthetic-specific. An optional stateless extension section may be absent in this mode.
- Consume S10's frozen io_digest verbatim, per S10's handoff and its `docs/spec/ecall-abi.md` section. That spec already froze exactly how the public I/O digest is computed over the committed input stream (fd 0) and committed output stream (fd 1). This stage defines nothing about its computation. This stage freezes ONLY the **output-commitment structure**: revm execution results — per-tx status/gas, the logs commitment and the post-state summary of Must-be-exact 7. Those are the fd 1 bytes fed INTO io_digest.

## Core algorithm
The guest reads a `BlockWitness` via `guest-sdk::read`, builds an in-memory revm `Database` from the pre-state, executes the two txs, serializes the outputs and calls `guest-sdk::commit`. keccak256 inside revm route through the S21 shims, whose host-feature fallback stays bit-identical for native runs. ecrecover delegation unfortunately is not available. The host test builds the guest reproducibly, derives `VmConfig`/`ProgramIdentity`, runs the emulator, proves a `BlockProof` and verifies. This is the first rung of the normative testing ladder (assessment §6): synthetic state comes strictly before S25's mini-blocks and stateless blocks. No RPC, no Merkle witnesses and no network appear anywhere in this stage.

revm is pinned to one exact version, `default-features = false`, with only the no-std features this workload needs. The wrapper covers one `Database` and one execution call. The synthetic contract is a counter writing one storage slot and emitting one log; named fixture-builder constants set balances and gas so both txs succeed. The guest reads its witness in one `read` call, from a compile-time heap sized at twice the largest committed fixture and documented as a tunable. Acceptance 10 and 11 fix the required instrumentation; further cycle-count instrumentation is permitted, defaulting to none.

## Must-be-exact
1. All guest input enters via `read` on fd 0 and all output leaves via `commit` on fd 1; both streams fold into the public I/O digest. No other nondeterminism exists: no fd 3 hints in this guest.
2. All keccak calls route through the S21 shim entry points. 
3. `VmConfig` is derived by the preprocessor from the decoded guest (static detachment). The delegation families appear via the S21-frozen static-detachment mechanism, per delegation.md, never a manual flag.
4. Guest build is reproducible under the pinned `rust-toolchain.toml` (identity is load-bearing): two clean builds yield the same `ProgramIdentity`.
5. `BlockWitness` uses the workspace's one wire encoding, and its serialized bytes are a committed fixture, not an inline literal.
6. `BlockWitness` serializes canonically: env/header fields, then pre-state accounts sorted by address with slots sorted by key, then txs in execution order, then the optional stateless extension section. The same logical state therefore serializes to identical bytes.
7. The output commitment is fixed-shape with no data-dependent sections. It opens with per-tx records in execution order, each carrying status, gas used and output data. A logs commitment follows: keccak256 over the canonically encoded log list. A post-state summary closes it: keccak256 over touched accounts sorted by address, each with nonce, balance, code hash and sorted slots.

## Acceptance
1. **Reproducible identity:** build the guest twice from clean; the `ProgramIdentity` bytes are identical.
2. **Family set check:** derived `VmConfig` includes the keccak delegation family and excludes any family the decoded program never uses; the family-partition check passes (every pc claimed by exactly one family).
3. **Differential oracle — execution:** the guest under our own emulator and under qemu-riscv32 produce identical committed output bytes for the same `BlockWitness` fixture.
4. **Differential oracle — semantics:** guest revm output (per-tx success, gas used, output data, post-state summary) equals **native host revm** run over the same synthetic pre-state and txs. This is the guest-level correctness check.
5. **Shim equivalence:** for the keccak inputs this workload produces, delegation-shim results equal the bit-identical software fallback. Harvest the call inputs from a traced run and commit them as fixtures.
6. **End-to-end proof:** prove the synthetic block to a `BlockProof`; `verify(&vk, &proof, &public_inputs)` returns `Ok`. Public inputs carry the public I/O digest recomputed by the host from the fixture's input/output bytes; a digest recomputed independently of the guest run must match.
7. **Tamper twin — statement:** verifying the honest proof against a public I/O digest differing in one byte fails; verifying against a different `ProgramIdentity` fails.
8. **Delegation occupancy:** the proof bundle contains ≥1 shard for keccak family (occupancy assertion on the honest run), and structural count assertions pass.
9. **Cycle report:** the run prints total guest cycles and per-family trace occupancy (rows used / height, shard count per family); numbers land in the S24 handoff.
10. record the revm guest's measured `.text` size and expanded instruction-slot count against the `bytecode_size_words` default; numbers land in the handoff.

## Testing
From this stage onward, we'll test all "heavier" (use best judgement) including "DEFERRED" test groups on development server. In the future, first check if the folder `../apogee-aws` is available locally. That's the repo for provisioning and managing aws resources. If it's not available, no heavier or deferred test suites may run. Use existing (or provision one, if not present) development server `r8i.8xlarge` for running the heavier tests. 

DISCIPLINE: 
1. Default EC2 instance state is STOPPED. 
2. Only bring instances online when actual testing or tasks are happening. Don't allow EC2 instances to idle. Stop dev server instance when finished. Always. 
3. The ptau file is in a S3 bucket. Fetch from this location if tests require it. 

## Handoff
- S24 freezes the `guests/revm-block` build workflow and its `ProgramIdentity`.
- It freezes the `BlockWitness` type with its committed synthetic fixture; S25 produces it for real blocks.
- It documents the output-commitment structure, the fd 1 bytes fed into S10's frozen io_digest, which S25 and S26 consume as-is.
- It reports cycle and occupancy numbers, plus the measured `.text` size and expanded instruction-slot count against the `bytecode_size_words` default.