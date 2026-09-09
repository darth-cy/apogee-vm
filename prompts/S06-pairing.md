---
title: S06-pairing.md

---

# S06 — Pairing: Fq6/Fq12 Tower, Miller Loop, Final Exponentiation

Provided reference: ePrint 2010/354 (Beuchat et al., optimal ate pairing over BN curves) in `./docs/publication`. The differential fixtures, not the paper, are the correctness authority.

## Depends on / Inputs
- S01 `field` supplies `Fr` for exponent arithmetic in the property tests, and `constants`.
- S05 `curve` supplies `Fq`, `Fq2`, `G1Affine`, `G2Affine`, serde, and subgroup checks.

## Deliver
Module `curve::pairing` completes the tower and the optimal ate pairing.

**Priority statement:** the base prover never computes a pairing; pairings appear only in verification. This stage is correctness-critical and NOT performance-critical, so prefer clear, textbook, auditable code over optimized code. Skip lazy-reduction tricks, hand-scheduled towers, and assembly. A slow correct pairing passes this stage; a fast unclear one is worse.

Frozen public API:

```rust
pub struct Fq6 { pub c0: Fq2, pub c1: Fq2, pub c2: Fq2 }  // Fq2[v]/(v³ − ξ), ξ = 9+u
pub struct Fq12 { pub c0: Fq6, pub c1: Fq6 }              // Fq6[w]/(w² − v)
// Both: ops, square, inv, conjugate, frobenius_map(power), pow; Fq12::ONE.

pub fn miller_loop(pairs: &[(G1Affine, G2Affine)]) -> Fq12;   // product of loops, shared iteration
pub fn final_exponentiation(f: &Fq12) -> Fq12;
pub fn pairing(p: &G1Affine, q: &G2Affine) -> Fq12;           // convenience: full single pairing
pub fn pairing_check(pairs: &[(G1Affine, G2Affine)]) -> bool; // ∏ e(Pᵢ,Qᵢ) == 1: one shared
                                                              // miller_loop + one final_exponentiation
```

## Core algorithm
- Implement the optimal ate pairing with BN parameter x = 4965661367192848881, looping over 6x+2 in signed NAF form. Evaluate lines against the D-twist, then apply Frobenius correction steps at the end of the loop.
- Carry each pair's G2 accumulator in homogeneous projective coordinates over Fq2, as the published line formulas do. Materialize each line evaluation as a full `Fq12`, its three non-zero `Fq2` coefficients sitting in the D-twist's slots, and accumulate it with the generic `Fq12` multiplication. Use no sparse-multiplication shortcut and no cyclotomic squaring: D5 keeps this stage off the prover's hot path.
- Compute the final exponentiation (q¹²−1)/r as an easy part of conjugation, inversion and Frobenius, plus a hard part. The hard part uses the classic Devegili-style decomposition, cited in a comment. Fuentes-Castañeda is excluded: it returns a fixed power of the true value, which Acceptance 2 rejects.
- The Frobenius coefficients for Fq6/Fq12 and the twist correction constants are precomputed into `constants`, each pinned by a fixture test (never trusted from derivation alone).
- `pairing_check` is the verifier entry shape for the whole project: multi-pair, one final exp, compare to `Fq12::ONE`.

## Must-be-exact
1. The tower is constructed exactly as above (ξ = 9+u, w² = v), matching arkworks-bn254/py_ecc so full-pairing outputs are directly comparable.
2. Pairs where either point is infinity contribute the identity to `miller_loop`/`pairing_check`, skipped rather than a panic. An empty `pairs` slice gives `Fq12::ONE` / `true`.
3. `pairing_check` performs exactly one final exponentiation regardless of pair count. A test asserts this, via instrumentation or via a code inspection recorded in the handoff.
4. All new constants live in `constants` with a fixture test each; no magic literals appear in `curve`.
5. Extend the fixture-generator dev-tool from S05 (same tool, new subcommands) to emit this stage's fixtures from arkworks-bn254 AND py_ecc; fixtures are committed and hash-pinned, tests read files only.
6. `final_exponentiation` returns the exact (q¹²−1)/r power, so a fixed-power shortcut is forbidden, and a comment names the decomposition used.
7. `miller_loop` is the only Miller implementation, called by both `pairing` and `pairing_check`, and precomputes no G2 line coefficients.

## Acceptance
1. **Tower differential fixtures.** Draw ≥1000 random vectors per op for Fq6 and Fq12 (add/mul/square/inv/frobenius_map powers 1–3/conjugate) from both oracles, plus edges: zero, one, elements with zero sub-components. All pass.
2. **Pairing differential fixtures.** ≥100 random (P, Q) pairs carry full pairing values e(P,Q) from py_ecc AND arkworks. Comparison is post-final-exp only; intermediate Miller values are convention-dependent and are NOT compared. The set includes P = G1 gen, Q = G2 gen as a named KAT.
3. **Bilinearity.** Property tests on random a, b, P, Q establish e(aP, Q) = e(P, aQ) = e(P, Q)^a; e(aP, bQ) = e(P, Q)^(ab); e(P+P', Q) = e(P,Q)·e(P',Q).
4. **Final-exp identities.** Tests establish e(P,Q)^r = 1 and e(G1::GENERATOR, G2::GENERATOR) ≠ 1, which is non-degeneracy. The final_exponentiation output f satisfies the cyclotomic-subgroup condition f^(q⁶) · f = conjugate relation, i.e. unitarity f⁻¹ = f̄. Finally, final_exponentiation(ONE) returns ONE.
5. **Infinity handling.** pairing(∞, Q) and pairing(P, ∞) both return Fq12::ONE. A pairing_check over a list containing infinity pairs matches the same list with those pairs removed.
6. **pairing_check product relations.** Positive: [(aP, Q), (−P, aQ)] returns true, and the KZG shape [(C − v·G, H_gen), (−W, τ-term)] on a hand-built toy instance returns true. Negative twin: perturbing one scalar in each relation turns each result false.
7. **Multi-pair vs single-pair consistency.** miller_loop over k pairs followed by final exp equals the product of k individual pairings, for k ∈ {2, 3, 5}.
8. **Negative control.** One corrupted fixture byte fails the corresponding test; run this once and note it in the handoff.

## Handoff
`docs/handoff/S06-pairing.md` records the frozen API as implemented. It names the hard-part decomposition and the loop form built, with a citation. It lists the fixture paths and the tool subcommands.