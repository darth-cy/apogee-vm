---
title: S23 — Fr-Arithmetic + Poseidon2 Delegation Families (recursion support)

---

# S23 — Fr-Arithmetic + Poseidon2 Delegation Families (recursion support)

## Depends on / Inputs
- **S21.** You consume `docs/spec/delegation.md` (frozen ABI — append two frame tables only), the request-side anchor gates, the emulator delegation-support API, and the detachment mechanism.
- **S01 and S02.** S01 gives `field::Fr` (ops, `inv`, canonical LE serde — the guest↔frame encoding). S02 gives `poseidon2_permute`, `docs/spec/transcript.md`, and the RC3 constant tables already in `constants`.
- **S13 through S20.** S13 gives `CircuitArtifact` and the checker suite, S14 the memory gates and gap gadget, S15 the 16-bit range channel. S16 gives `ShardProof`, the verifier entry point and the tamper harness, and S20 `BlockProof` with reconciliation.

## Deliver
Two delegation families. Per register D2 these are what make in-VM recursion contract; they are non-optional core once a program uses them.
- **fr-arith family:** this batches Fr add/mul/inv and is trivially native, costing ONE row per op.
- **poseidon2 family:** this proves the full t=3 permutation (8 full + 56 partial rounds, exactly the S02 parameters), and its gates ARE the round structure.

Plus:
- The `guest-sdk` recursion-support module `guest_sdk::recursion` provides shim entry points for batched fr add/mul/inv and `poseidon2_permute` over a 3-element state. Each shim carries a bit-identical software fallback for the QEMU path: guest-side bignum Fr, guest-side Poseidon2. S26's recursion-verifier guest uses ONLY these entry points for field and hash work.
- The backend seam, by name: the S23 guest-target backend is selected by `#[cfg(target_arch = "riscv32")]` and a 'delegated' cargo feature on `field` and `transcript`. That is cfg-target selection, not trait genericity. The backend routes Fr add/mul/inv and `poseidon2_permute` through the `guest_sdk` recursion shims at the frozen batching granularity. This backend lets the SAME no_std verifier core run natively on the host and delegated in-guest.
- You append both frame tables to `delegation.md`. Batching granularity is decided and documented here.
- The emulator supports both ecalls per the S21 pattern, and a fixture guest exercises both shims.

## Core algorithm
- **fr-arith.** One invocation carries a fixed-capacity batch. Each op-row holds boolean opcode selectors from a small legal set, operands `a` and `b`, and a result `out`. Selectors gate `out = a + b` and `out = a·b`. Inversion uses a witnessed inverse, `a·out = 1 − z`, with a witnessed is-zero gadget `z`, so inv(0) = 0 by convention. Never use the sum-of-parts-is-zero trick, forgeable in a wide field per the conversion note. Add, mul and inv share one trace under row-level selection rather than split sub-shapes. Operands and results cross the indirect frame as canonical little-endian Fr, 8 words each. Frame decode must enforce canonicity in-circuit by limb recomposition plus range obligations, so a non-canonical claimed encoding is unprovable.
- **poseidon2.** The base layer commits the input state (3 Fr) plus one x² helper per S-box. Rounds unroll as GKR layers: round-constant additions and the linear/MDS layers are degree-1 gates. The x^5 S-box decomposes into degree-2 stages: the witnessed x², then x⁴ = (x²)², then x⁵ = x⁴·x, which is two multiplication layers with transported pass-through values. Partial rounds S-box one lane only. Each round maps onto its own layer group; rounds never fuse. The output state is the written frame words. Parameters are identical to S02's permutation, and RC3 comes from `constants` with no second copy.
- **Both families.** The delegation ABI is per `delegation.md`: pointer plus fixed-offset word frame, per-read read-ts pairs with gap checks, all three anchor zeroings, the same global multiset. Take small heights from the menu (2^16 suggested); zero-shard skipping and static detachment apply. The shims are plain free functions, not builders: the fr ops take `&[Fr]` operands with a `&mut [Fr]` result, and the permutation takes `&mut [Fr; 3]` in place. They chunk into invocations internally; the signatures stay stable and S26-consumable.

## Must-be-exact
1. Frame tables and ecall constants land in `delegation.md`, with shim, emulator and artifact assert-match tests.
2. Each fr op occupies exactly one row. This is the cost model recursion contraction rests on, so record ops/row = 1 and rows/permutation in the handoff.
3. The Poseidon2 circuit is bit-equal to `transcript::poseidon2_permute`: same rounds, same constants, same layout.
4. The frame Fr encoding is canonical LE, and canonicity is enforced in-circuit.
5. The witnessed inverse plus is-zero gadget yields inv(0) = 0, documented in the artifact docs.
6. Both families meet the anchor obligations exactly per `delegation.md`: all three zeroings and 1:1 pairing.
7. Shims live in `guest_sdk::recursion` with signatures frozen in the handoff, and the fallbacks are bit-identical.
8. `delegation.md` fixes batching granularity. One fr-arith invocation carries 64 op-rows: a one-word populated count, one opcode word per row, then the `(a, b, out)` triples. Unpopulated rows carry the all-zero no-op selector, which the legal set admits as valid padding. One poseidon2 invocation carries exactly one permutation, since the duplex is sequential.
9. The S-box x² is a committed helper pinned by an enforcing `x² = x·x` gate. That yields exactly two multiplication layers per S-box and one layer group per round.

## Acceptance
1. fr-arith differential: the delegated path matches host `field::Fr` ops on randomized committed vectors covering add, mul, inv, inv(0), and a·inv(a) = 1 round trips. The fallback is bit-identical under QEMU.
2. poseidon2 differential: the circuit output equals `transcript::poseidon2_permute` on the spec §12 KAT ([0,1,2] input) and random committed vectors. The shim fallback is bit-identical.
3. Canonicity negative: a frame operand ≥ the Fr modulus is unprovable.
4. End-to-end: the fixture guest proves through S20 to a `BlockProof` containing ≥1 shard of each family, `verify_block(&VerifyingKey, &BlockProof, &PublicInputs)` returns Ok, and global roots reconcile.
5. Witness-tamper twins (circuit cell), one per family: a corrupted op-result cell in fr-arith fails; a corrupted mid-round state cell in poseidon2 fails. Honest twins pass, and structural count assertions run.
6. Anchor tamper, per family: a request with no matching invocation gives a global multiset failure; violating one of the three zeroings fails.
7. Selector discipline: opcode selectors are boolean and legal-set constrained, and a row claiming two ops simultaneously is unprovable (negative test).
8. Structure assertion: rows/permutation and ops/row counted from the honest trace match the artifact's declared shape — a test, not a log line.
9. Detachment and zero-shard: a guest using neither shim derives a family set excluding both; a guest linking but never calling proves with zero shards of each and verifies.
10. Checker validators, artifact regeneration and diff run in CI, along with degree-2 assertions and padding validity. The handoff records the measured cycle cost of one shim call versus its software fallback. That ratio is the contraction S26 sizes against (internal numbers only, D11).

## Handoff
Freeze both `CircuitArtifact`s with their frame tables and trace heights. Freeze the ecall constants, `guest_sdk::recursion` signatures, batching granularity and the S23 guest-target backend. Freeze the measured numbers: rows/permutation, ops/row and shim-vs-fallback cycle ratio. S26's verifier guest is contractually limited to these entry points for all field and hash work on its verification path. Note for S24: the revm guest asserts the same exclusion, so a guest using neither shim derives a family set excluding both families.