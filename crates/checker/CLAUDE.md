# `crates/checker`

## What this crate owns
The second enforcement point for a `CircuitArtifact`, written from
`docs/spec/gkr.md` alone: the four law validators of §4.2, the padding contract of
§4.3, the witness-row evaluator, the artifact cross-check, the circuit dump, and the
`checker` CLI over the first, second and last of those.

**It never calls `CircuitArtifact::validate` or `inline_cached`**, and shares no code
with `crates/constraints/src/laws.rs`: the laws are enforced twice, by independent
code (S13 must-be-exact 4). Gates are evaluated only through the kernel,
`gkr::eval_gate` and `gkr::gate_values`, which is the semantic authority.

```rust
pub fn check_law1(a: &CircuitArtifact) -> Result<(), String>;   // locality
pub fn check_law2(a: &CircuitArtifact) -> Result<(), String>;   // derived width, num_vars, halving order
pub fn check_law3(a: &CircuitArtifact) -> Result<(), String>;   // top layer = output map
pub fn check_law4(a: &CircuitArtifact) -> Result<(), String>;   // flat list = gates, count and semantics
pub fn check_laws(a: &CircuitArtifact) -> Result<(), String>;   // all four, in order
pub fn check_padding(a: &CircuitArtifact) -> Result<(), String>;
pub struct WitnessRow { pub committed: Vec<Fr>, pub row: usize, pub scratch: Vec<Fr> }
pub fn violated_relations(a: &CircuitArtifact, w: &WitnessRow, challenges: &ExternalChallenges) -> Vec<String>;
pub fn dump(a: &CircuitArtifact) -> String;
pub struct VerifierConstants { /* trace_vars, committed and virtual names, per-list halving,
                                  num_vars, widths, enforcing and cached counts, output names,
                                  challenge slots */ }
pub struct ReferenceRun { pub outputs: Vec<Vec<Fr>>, pub enforcing: Vec<(String, Vec<Fr>)> }
pub fn cross_check(a: &CircuitArtifact, expected: &VerifierConstants,
                   reference: fn(&[Vec<Fr>], &ExternalChallenges) -> ReferenceRun) -> Result<(), String>;
```

```
checker laws <artifact>      # exit 0, or 1 naming the law; 2 on a usage error
checker padding <artifact>
checker dump <artifact>
```

## Frozen invariants
- **Every check says what it does not cover**, on the function, and the list is in
  `src/lib.rs`. In short: each law validator covers its own law and nothing else;
  Law 4 and the padding check are **sampled** at fixed-seed pseudo-random points, so a
  trial accepts two different polynomials with probability about `degree/|Fr|`;
  the witness-row evaluator and the padding check cover row-local relations only —
  nothing at or above a halving list; the cross-check covers the fields a verifier's
  description names, not documentation-only names, `format_version`,
  `coefficient_encoding`, lookups or padding.
- **An error names its law first** (`Law 2 (derived width): ...`), so a failure is
  attributable. Where `constraints` files a rule under a different heading — the
  halving order and a halving gate list 0 are Law 2 here and `Malformed` there, a
  cached entry out of position is Law 1 here — both still refuse the same artifacts,
  which `tests/laws.rs`' differential holds.
- **The cross-check's source is independent**: `tests/cross_check.rs`' constants and
  reference function are written from the toy's description, not read from its
  definition or from the committed file.
- **Deterministic.** The sampled checks use the crate's own splitmix64 with fixed seeds.

## Tests
| File | Covers |
| --- | --- |
| `tests/laws.rs` | acceptance 5: both fixtures pass; 35 mutants of both compilations — 4 lawful controls and 31 law-breaking, 2 of those also breaking a rule outside the laws — plus 4 of the cached compilation's cached entries, each failing exactly the laws it breaks: among them a gate reading two layers down, a cached entry reading another or of another layer, a width the gates do not produce, a halving gate list 0, a halving list skipping a column, a top layer the output map does not hold or names twice, a scratch slot no relation defines, and a flat list disagreeing in count and in meaning; `check_laws` against `validate` over 70 of the 74 mutant runs, no disagreement |
| `tests/padding.rs` | both fixtures pass; a flipped `zero_row_valid`, a padding row breaking the gated equality, and a wrong-length row each fail |
| `tests/witness.rs` | acceptance 8: a satisfying row passes; perturbing each of 14 cells reports exactly the relations derived by hand for it, on active and inactive rows; an evaluator reporting nothing or everything fails |
| `tests/cross_check.rs` | acceptance 9: the hand-written description passes both fixtures; 24 perturbations, each on both compilations, each caught by the check the test names — among them a renamed memory, witness and setup column and a lawful added cached entry; documentation-only renames pass |
| `tests/dump.rs` | acceptance 10: the dump's header, columns, layers, relations, addresses and catalogue; one exact line per gate shape, the cached entry, a scratch-bijection line and an output-map line; a literal at or above `2^64` printed as hex; the CLI on the fixtures, a corrupted file and a lawless one |
