---
title: S22 — secp256k1 ecrecover Delegation Family

---

# S22 — secp256k1 ecrecover Delegation Family

## Depends on / Inputs
- S21 supplies `docs/spec/delegation.md`, whose ABI is frozen: consume it, amend it only by appending this family's frame table. It also supplies the request-side anchor gates, the emulator delegation-support API, the delegation detachment mechanism, and `guest_sdk::keccak256` for address derivation.
- S13 supplies `CircuitArtifact` and the checker suite; S14 the memory gates, gap gadget and Δ budget; S15 the 16-bit range channel with its carry and limb obligations. S16 supplies `ShardProof`, `VerifyingKey`, the verifier entry point and the tamper harness; S20 `BlockProof` and cross-shard reconciliation.
- S10 supplies the precompile ecall range, S11 the `VmConfig` derivation.

## Deliver
- Build the ecrecover delegation circuit family: `CircuitArtifact`, trace routing, and wiring through existing entry points. An honest scope note: non-native secp256k1 over Fr makes this the largest single circuit in the VM. Budget the stage accordingly; never silently cut validation cases to fit.
- Build a `guest-sdk` shim `pub fn ecrecover(msg_hash: &[u8; 32], v: u8, r: &[u8; 32], s: &[u8; 32]) -> Option<[u8; 20]>` with a bit-identical software fallback. This signature is the patchable entry point S24's revm precompile hook routes through, so freeze it. The address is the last 20 bytes of `keccak256(pubkey)` via the S21 shim. The circuit proves recovery to the affine pubkey; hashing is S21's job, never a second keccak.
- Append this family's frame table to delegation.md. It is fixed-size: inputs h, v, r, s; outputs pubkey x, y and a success flag.
- Add emulator support for the new ecall, per the S21 pattern.

## Build sessions
This stage runs as TWO explicitly ordered build sessions.
- **Session A** builds the non-native field gadget library and the windowed scalar-multiplication sub-circuit, with reduced-width exhaustive checks and edge-case gates. It delivers a checked `CircuitArtifact` fragment and the gadget API.
- **Session B** builds the recovery composition, the EVM validation semantics, the frame table, the shim and fallback, and the end-to-end proof with tamper twins.

Session B begins only after Session A's acceptance sub-list passes.

## Core algorithm
Implement EVM precompile semantics exactly. Accept v ∈ {27, 28} only, recovery ids 0 and 1; the r+n candidate ids 2 and 3 are unreachable through the precompile, so document that. Require 0 < r < n and 0 < s < n, with no low-s restriction. Recover R from (r, v), then compute pubkey = r⁻¹(s·R − h·G). Failure covers r or s out of range, a bad v, an x that is not a curve point, and a result at infinity. Failure is a PROVABLE outcome via the success flag, never an unprovable execution: revm must be able to prove blocks containing failed ecrecover calls.

Non-native arithmetic is forced: secp256k1's p and n are about 2^256 and exceed Fr. Values live in a limb representation with range-checked carries on the S15 16-bit channel. Every modular reduction witnesses a quotient and a remainder, both range-checked. Under the conversion-note rules an unbounded limb or carry is a total break, and divisibility equations are vacuous over Fr without the range checks. Pin the layout at four 64-bit limbs per 256-bit value, each limb range-checked as four 16-bit chunks; a schoolbook 4×4 product then stays far inside Fr.

Scalar multiplication is windowed at width 4, fixed-window for G and windowed for R. Record the per-invocation row budget in the artifact docs. G's multiples are constant, so they ship as committed setup columns; R's are built in-circuit. Witness r⁻¹ mod n under a product check. Point-addition edge cases (doubling, identity, equal-x) must be constrained, not assumed away.

The delegation ABI is identical to S21's: pointer register plus fixed-offset word frame, per-read read-ts pairs with gap checks, all three anchor zeroings, the same global multiset. Take the trace height from the menu; candidates are 2^18 and 2^20. Pin 2^20 as the documented default, justified from the measured rows per invocation.

## Must-be-exact
1. The frame table and ecall number are appended to delegation.md; shim, emulator and artifact numbers assert-match the doc.
2. The EVM validation set above holds. Failure is provable via the success flag, with output words constrained to zero on failure, so a forged "failure with a live pubkey" is impossible.
3. Every limb, carry, quotient and remainder is range-checked, and every selector and window bit is boolean. No `assume_*`-style unchecked hypothesis appears anywhere in the artifact (Airbender §5.2 class).
4. The circuit proves pubkey recovery only; the shim composes the S21 keccak path for the address.
5. Anchor obligations hold exactly per delegation.md: all three zeroings, and 1:1 pairing.
6. The limb layout is exactly four 64-bit limbs per 256-bit value, each range-checked as four 16-bit chunks on the S15 channel, and every remainder is proved canonical, not merely limb-bounded.
7. Both scalar multiplications use window width 4, and each window digit drives a selector mask with boolean bits whose sum is constrained to one.
8. One invocation proves exactly one signature in the fixed-size frame above; the family does not batch.

## Acceptance
**Session A**
1. Gadget differential: the non-native mul/reduce gadget matches a bignum oracle on randomized committed vectors AND is checked exhaustively at reduced limb width.
2. Point-arithmetic edge cases: three in-circuit cases each prove and verify honestly — an accumulator step with P == Q (doubling), an identity intermediate, and an equal-x-different-y add. One edge-case row also carries a tamper twin. Verify each at reduced width, or via a harness pinning which row hit which case.

**Session B**
3. ecrecover differential: circuit and shim on the delegated path match a reference implementation on a committed corpus. Use k256 or libsecp256k1 as the dev-dependency oracle. The corpus holds several real mainnet-tx signatures, v = 27 and 28, r and s at 1 and n−1, and s > n/2 (accepted). It also holds three failing inputs: r ≥ n, an r whose x has no curve point, and a wrong recovery id for an otherwise-valid signature. That last input fails or gives a wrong address per the reference; match the oracle. The fallback is bit-identical to the delegated path on the full corpus, run under QEMU.
4. End-to-end: a fixture guest calling `ecrecover` proves through S20 to a `BlockProof` with ≥1 ecrecover shard. `verify_block(&VerifyingKey, &BlockProof, &PublicInputs)` returns Ok, and global roots reconcile across families.
5. Failure-path proof: a guest whose ecrecover input is invalid proves and verifies with the shim returning `None`, under its own committed fixture.
6. Witness-tamper twin (circuit cell): re-proving with one corrupted carry or limb cell fails with the expected error class, and the honest twin passes. Pin that cell by a range obligation or the bus, not a row constraint.
7. Anchor tamper (linkage): a request with no matching invocation gives a global multiset failure, and violating one of the three zeroings also fails. Reuse the S21 harness cases against this family.
8. Forged-outcome tamper: an honest valid-signature run re-proved with the success flag flipped to failure (outputs zeroed) fails. An honest failure run re-proved as success with a forged pubkey also fails.
9. Checker validators pass; the artifact is regenerated and diffed in CI; degree-2 assertions hold; padding rows are valid.
10. The handoff records measured rows per invocation and single-invocation prover wall-clock: internal numbers only per D11, no public claims.

## Handoff
Freeze the `guest_sdk::ecrecover` signature, the ecall constant, and the frame table in delegation.md. Freeze the family `CircuitArtifact`, its chosen trace height, and the limb parameters. Freeze the Session A gadget API unconditionally: Session B and any later consumer compile against it. S24 routes revm's ecrecover precompile through the shim.