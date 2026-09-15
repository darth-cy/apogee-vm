# `crates/checker`

## What this crate owns
The second enforcement point for a `CircuitArtifact`, written from
`docs/spec/gkr.md` alone: the four law validators and the lookup rules of §4.2, the
padding contract of §4.3 and its product-tree clause, the witness-row evaluator and the
native lookup evaluator, the artifact cross-check, the circuit dump, and the `checker`
CLI over the laws with the lookup rules, the padding contract and the dump.

**It never calls `CircuitArtifact::validate` or `inline_cached`**, and shares no code
with `crates/constraints/src/laws.rs`: the laws are enforced twice, by independent
code (S13 must-be-exact 4). Gates are evaluated only through the kernel,
`gkr::eval_gate` and `gkr::gate_values`, which is the semantic authority. A gate's
shape is otherwise read in three ways only: the dump's `formula` prints every shape;
Law 2, the Law 4 sampler and the row-local order tell a `TreeProduct` — which reads
children and spans rows — from every row-wise shape, `Quadratic` among them; and the
lookup rules tell `Linear` from every other shape.

```rust
pub fn check_law1(a: &CircuitArtifact) -> Result<(), String>;   // locality
pub fn check_law2(a: &CircuitArtifact) -> Result<(), String>;   // derived width, num_vars, halving order
pub fn check_law3(a: &CircuitArtifact) -> Result<(), String>;   // top layer = output map
pub fn check_law4(a: &CircuitArtifact) -> Result<(), String>;   // flat list = gates, count and semantics
pub fn check_laws(a: &CircuitArtifact) -> Result<(), String>;   // all four, in order, then the lookup rules
pub fn check_padding(a: &CircuitArtifact) -> Result<(), String>;
pub fn check_padding_identity(a: &CircuitArtifact) -> Result<(), String>;   // the product-tree clause
pub struct WitnessRow { pub committed: Vec<Fr>, pub row: usize, pub scratch: Vec<Fr> }
pub fn violated_relations(a: &CircuitArtifact, w: &WitnessRow, challenges: &ExternalChallenges) -> Vec<String>;
pub fn violated_lookups(a: &CircuitArtifact, w: &WitnessRow) -> Vec<String>;
pub fn memory_roots(a: &CircuitArtifact, values: &gkr::LayerValues) -> Result<(Fr, Fr), String>;   // (read, write)
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
  nothing at or above a halving list; the product-tree clause covers the first halving
  list's inputs, on `padding.row` only; the lookup evaluator is membership on one row,
  not the LogUp argument; the root hook `memory_roots` recomputes the two roots from the
  layer the first halving list reads, and covers nothing below it; the cross-check covers the fields a verifier's
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
| `tests/laws.rs` | acceptance 5: both fixtures pass; 36 mutants of both compilations — 4 lawful controls and 32 law-breaking, 2 of those also breaking a rule outside the laws — plus 4 of the cached compilation's cached entries, each failing exactly the laws it breaks: among them a gate reading two layers down, a cached entry reading another or of another layer, a width the gates do not produce, a halving gate list 0, a halving list skipping a column, a top layer the output map does not hold or names twice, a scratch slot no relation defines, and a flat list disagreeing in count and in meaning, among them one product coefficient of the toy's `Quadratic` gate; `check_laws` against `validate` over 72 of the 76 mutant runs, no disagreement |
| `tests/padding.rs` | both fixtures pass; a flipped `zero_row_valid`, a padding row breaking the gated equality, and a wrong-length row each fail; the product-tree clause: the toy fails it, pinned and explained, the toy edited to pad its leaves with 1 passes and each leaf moved off 1 fails naming it, the same edit with a second halving list stacked on the first still passes, and an artifact with no halving list passes |
| `tests/lookups.rs` | `check_laws` against `validate` over 25 lookup mutants of both toys — 5 lawful, an `M`, a `W` and an `S` selector among them, 20 breaking one rule each — with no disagreement; `violated_lookups` on 11 hand-derived rows, among them the bound's edge, a selector of 2, `−1` read canonically, and `V[row]` and `V[ram_live]` read at the witness's row; evaluators reporting nothing or everything fail |
| `tests/memory.rs` | `memory_roots` on a forwarded `ZERO_WINDOWS` artifact and a forwarded frame — halving inputs at layers 1 and 4 — equal to the top and to the halving input's products; refused when one row under either root changes, when the halving input is replaced by one-row columns holding the roots, when a layer is missing, and on an artifact with no halving list; the three `constraints::memory` artifacts passing `check_laws` and `check_padding`, and the frame `check_padding_identity` |
| `tests/witness.rs` | acceptance 8: a satisfying row passes; perturbing each of 14 cells reports exactly the relations derived by hand for it, on active and inactive rows; an evaluator reporting nothing or everything fails |
| `tests/cross_check.rs` | acceptance 9: the hand-written description passes both fixtures; 24 perturbations, each on both compilations, each caught by the check the test names — among them a renamed memory, witness and setup column and a lawful added cached entry; documentation-only renames pass |
| `tests/dump.rs` | acceptance 10: the dump's header, columns, layers, relations, addresses and catalogue; one exact line per gate shape, the toy's `Quadratic` gate and its relation, the cached entry, a scratch-bijection line and an output-map line; a literal at or above `2^64` printed as hex; the CLI on the fixtures, a corrupted file and a lawless one; a lookup's line, with its channel's name and its selector |
