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
| `tests/padding.rs` | both fixtures pass; a flipped `zero_row_valid`, a padding row breaking the gated equality, and a wrong-length row each fail; the product-tree clause: the toy fails it, pinned and explained, the toy edited to pad its leaves with 1 passes and each leaf moved off 1 fails naming it, a leaf that is 1 at row 0 alone fails, the same edit with a second halving list stacked on the first still passes, and an artifact with no halving list passes |
| `tests/lookups.rs` | `check_laws` against `validate` over 35 lookup mutants of both toys — 6 lawful, an `M`, a `W` and an `S` selector and the `range16` channel among them, 29 breaking one rule each, among them a name taken from a memory column, a setup column, a listed virtual table, a relation and a scratch slot, and an `M` or `S` operand or selector past the layout — with no disagreement; a `range16` lookup bound below `2^16`, not the timestamp channel's bound; `violated_lookups` on 11 hand-derived rows, among them the bound's edge, a selector of 2, `−1` read canonically, and `V[row]` and `V[ram_live]` read at the witness's row; evaluators reporting nothing or everything fail |
| `tests/memory.rs` | `memory_roots` on a forwarded `ZERO_WINDOWS` artifact and a forwarded frame — halving inputs at layers 1 and 4 — equal to the top and to the halving input's products; refused when one row under either root changes, when the halving input is replaced by one-row columns holding the roots, when a layer is missing, and on an artifact with no halving list; all seven families' frames and both window artifacts passing `check_laws` and `check_padding`, and every frame `check_padding_identity`; S14 acceptance 1, an honest statement over the committed `fib` and `heap` ELFs decoded at 2^16 and traced — **one frame shard per family that ran**, over that family's own cycles at the smallest power-of-two height and addressed by that family's `frame_queries`, `INIT_TEARDOWN`, and one `ZERO_WINDOWS` shard per `trace::init_windows` id, each filled by `trace`'s builders under slots 1–4 from a transcript binding nothing (S16 owns the schedule): every shard's `gkr::self_check`, `memory_roots`, `check_laws` and `check_padding`, `violated_relations` empty on every row of both windows and on every live row and the first padding row of the frame, `violated_lookups` empty on every row, the frame's product-tree clause, `check_memory_windows`, `reconciles` with `build_boundary_finals` at the image's entry pc, and every shard proved, verified and its base claims discharged — heap's 2^18-row frame excepted; the same statement with one frame per family that ran, over that family's non-contiguous cycles and one list reversed, each row holding its `cycles[i]`, every shard self-checked and the roots reconciling with the windows'; and each family's frame columns held to that family's buffers row by row, each role at its slot and the first padding row, with a role its frame has no slot for asserted to be a role no row of that family has — which holds `frame_queries` to the real execution, not just to the spec |
| `tests/multiset.rs` | S14's acceptance items and the design's controls on fib's trace at `h = 2^16`, which shards as five frames — `ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT`, `SHIFT_BITWISE`, `MEM_WORD`, `MEM_SUBWORD` — plus windows 0 and 8191, pinned in the harness; each tamper beside its honest twin and measured as one surface — the first gate `gkr::self_check` names, every obligation `violated_lookups` names across **every** frame, and `reconciles`. A tamper names the shard it targets, which is load-bearing: fib's first two `rd` writes to `x11` fall in different families: 2, a store's read value moved, reconciliation alone; 3, a pc read timestamp moved, reconciliation alone, and a cycle moved, also `gap_lo_pc` and `gap_lo_rs1`; 4, a future read of `x0` by two swapped read timestamps, reconciling with `gap_lo_rs1` alone named and no high chunk rescuing it; 5, a flipped image byte under the one window-0 word fib reads, not reconciling, and under an untouched word, cancelling; 6, a hand-forged `ZERO_WINDOWS` init column, reconciling at 0 and not at 7 on a stack word; 7, every touched RAM word of fib and heap on exactly one teardown row holding its last write, and a stale stack read balanced by window 8191 listed twice; 8, every `x0` query reading and writing 0, a write of 5 to `x0` read back as 5 reconciling while `self_check` names `rd_write_masked`, a register write zeroed and an `x0` write of 5 each balanced and each refused by exactly `rd_is_zero_at_nonzero` or `rd_is_zero_inverse`, and each of the five read-only queries writing back another value refused by exactly its `<q>_writes_back` — `arg1` and `arg2` existing only in `ADD_SUB_LUI_AUIPC`'s frame and `load` only in `MEM_WORD`'s, with the frames used asserted so a silent drop from five to four fails; 10, the `ADD_SUB_LUI_AUIPC` frame at 2^16 proved and verified, every committed cell of its 64,879 padding rows the artifact's all-zero padding row, `cycle` included, its padding rows' leaves and row products 1, its roots the 2^12 frame's; 11, the frame's `rs1` obligations accepting gaps 0 and `2^38 − 1` and refusing −1 and `2^38`; C1, a query at word `0x4` unbalanced, balanced against window 0 without `V[ram_live]` and against a zero window listed at id 0; C2, each single change of fib's window list or shard counts refused by its rule, `[8191, 8191]` among them; C3, a boundary timestamp, value or entry pc moved; C4, a trace stopped before its exit row refused by `build_boundary_finals`, and with finals claiming `HALT_PC` not reconciling where its own final pc would; C5, a padding row's pc query at mask −1 moving `x10`'s final value to 42, reconciling while `self_check` names `pc_mask_boolean`; C6, `x10`'s final value solved after the challenges, reconciling and not a `u32`; C7, a query reading its own write at `0x4000_0000` and at register 32, where no row is, reconciling with only its `gap_lo` named; C8, S16's mask targets — a padding row's `rd` query rewriting `x10` after exit, a live row's `rd` write masked off, and the exit row given a store rewriting a stack word's final value — each reconciling with nothing at S14 refusing it |
| `tests/common/mod.rs` | the pinned toy fixtures and their editing helpers; the committed guests traced at 2^16, their memory shards, a shard with cells rewritten, roots, reconciliation, a forwarded row as a `WitnessRow`, and the prove-verify-discharge harness, shared by `memory.rs` and `multiset.rs` |
| `tests/witness.rs` | acceptance 8: a satisfying row passes; perturbing each of 14 cells reports exactly the relations derived by hand for it, on active and inactive rows; an evaluator reporting nothing or everything fails |
| `tests/cross_check.rs` | acceptance 9: the hand-written description passes both fixtures; 24 perturbations, each on both compilations, each caught by the check the test names — among them a renamed memory, witness and setup column and a lawful added cached entry; documentation-only renames pass |
| `tests/dump.rs` | acceptance 10: the dump's header, columns, layers, relations, addresses and catalogue; one exact line per gate shape, the toy's `Quadratic` gate and its relation, the cached entry, a scratch-bijection line and an output-map line; a literal at or above `2^64` printed as hex; the CLI on the fixtures, a corrupted file and a lawless one; a lookup's line, with its channel's name and its selector |
