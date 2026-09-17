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
Law 2, the Law 4 sampler and the row-local order tell a **halving shape** —
`TreeProduct` or S15's `TreeCross`, which read children and span rows — from every
row-wise shape, `Quadratic` among them; and the lookup rules tell `Linear` from every
other shape.

Since S15 it also owns the LogUp channels' second description
(**`docs/spec/lookup.md` §12**): the native fractional sums, the comparison against the
circuit's root pairs, and the obligation-discharge cross-check.

Since S16 it also owns **the tamper-twin harness**, `TamperHarness`: an honest statement
proved once, then proved again with cells of its witness or its boundary changed, as an
honest prover would prove the changed witness, and one shard verified through
`verifier::verify_shard`. It is the only place outside their own suites where a statement
is both proved and verified, which is why `checker` now depends on both (the prover
itself depends on `verifier` only for `encode_srs_verifier`).

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

// docs/spec/lookup.md §12
pub struct ChannelSum { pub channel: u32, pub num: Fr, pub den: Fr,
                        pub unmatched: Vec<(usize, String)> }
impl ChannelSum { pub fn sum(&self) -> Option<Fr>; }
pub fn channel_sums(a: &CircuitArtifact, base: &gkr::BaseLayer, specs: &[ChannelSpec],
                    challenges: &ExternalChallenges) -> Result<Vec<ChannelSum>, String>;
pub fn channel_roots(a: &CircuitArtifact, values: &gkr::LayerValues, specs: &[ChannelSpec])
    -> Result<Vec<(Fr, Fr)>, String>;
pub fn check_channel_roots(roots: &[(Fr, Fr)], sums: &[ChannelSum]) -> Result<(), String>;
pub fn check_lookup_discharge(a: &CircuitArtifact, specs: &[ChannelSpec]) -> Result<(), String>;
pub fn dump(a: &CircuitArtifact) -> String;

// S16, docs/spec/shard-proof.md §6
pub struct Cell { pub family: FamilyId, pub shard: u32, pub address: PolyAddress, pub row: usize, pub value: Fr }
pub struct Tamper { pub cells: Vec<Cell>, pub boundary: Option<BoundaryFinals> }   // + Default
impl<'a> TamperHarness<'a> {
    pub fn new(setup: &'a ProverSetup, archive: &'a TraceArchive) -> TamperHarness<'a>;  // proves, asserts it verifies
    pub fn honest(&self) -> (&PublicInputs, &[ShardProof]);
    pub fn cell(&self, family: FamilyId, shard: u32, address: PolyAddress, row: usize) -> Fr;
    pub fn run(&self, tamper: &Tamper, target: (FamilyId, u32)) -> Result<(), VerifyError>;
    pub fn assert_rejects(&self, tamper: &Tamper, target: (FamilyId, u32), expected: VerifyError);  // by class
    pub fn assert_verifies(&self, tamper: &Tamper, target: (FamilyId, u32));
}
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
  list's inputs, on `padding.row` only, and **exempts every column a `TreeCross` reads**,
  a fraction tree's identity being `(0, 1)` and its padding rows not idle at all
  (`docs/spec/lookup.md` §6); `violated_lookups` is membership on one row for the
  **range** channels alone — a table channel's is a statement about the whole table, and
  `channel_sums` is its evaluator; `channel_sums` leaves `unmatched` empty where a
  channel balances, and folds fractions rather than inverting per row; the root hook `memory_roots` recomputes the two roots from the
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
- **The harness proves what an honest prover would.** A tampered cell is written into the
  columns the honest fill produced; each channel's multiplicities are recounted over the
  tampered columns **channel by channel**, and a channel keeps its honest counts only when
  its own multiplicity column is the tamper or its own recount is impossible (a tuple its
  table does not hold) — which never stops another channel's recount; a changed memory
  column or boundary reruns the global commit phase, and every shard of the new statement
  is proved again. So a refusal's class is the class of what the tamper broke, and
  `assert_rejects` compares classes, not reasons — except that a `Lookup` refusal must
  name the expected channel, since which table refuses is what a lookup twin is about. A tamper that breaks nothing verifies,
  and `tests/tamper.rs`' acceptance 11 is that negative control. A tamper that keeps the
  global state reuses the honest proofs of every shard it does not name.
- **Deterministic.** The sampled checks use the crate's own splitmix64 with fixed seeds.
  `check_lookup_discharge`'s points fill the LogUp slots through
  `gkr::insert_lookup_challenges`, never at random: `β`'s powers are derived, and a point
  where they are independent values is a point no gate's coefficients mean what they say.

## Tests
| File | Covers |
| --- | --- |
| `tests/laws.rs` | acceptance 5: both fixtures pass; 36 mutants of both compilations — 4 lawful controls and 32 law-breaking, 2 of those also breaking a rule outside the laws — plus 4 of the cached compilation's cached entries, each failing exactly the laws it breaks: among them a gate reading two layers down, a cached entry reading another or of another layer, a width the gates do not produce, a halving gate list 0, a halving list skipping a column, a top layer the output map does not hold or names twice, a scratch slot no relation defines, and a flat list disagreeing in count and in meaning, among them one product coefficient of the toy's `Quadratic` gate; `check_laws` against `validate` over 72 of the 76 mutant runs, no disagreement |
| `tests/padding.rs` | both fixtures pass; a flipped `zero_row_valid`, a padding row breaking the gated equality, and a wrong-length row each fail; the product-tree clause: the toy fails it, pinned and explained, the toy edited to pad its leaves with 1 passes and each leaf moved off 1 fails naming it, a leaf that is 1 at row 0 alone fails, the same edit with a second halving list stacked on the first still passes, and an artifact with no halving list passes |
| `tests/lookups.rs` | `check_laws` against `validate` over 35 lookup mutants of both toys — 6 lawful, an `M`, a `W` and an `S` selector and the `range16` channel among them, 29 breaking one rule each, among them a name taken from a memory column, a setup column, a listed virtual table, a relation and a scratch slot, and an `M` or `S` operand or selector past the layout — with no disagreement; a `range16` lookup bound below `2^16`, not the timestamp channel's bound; `violated_lookups` on 11 hand-derived rows, among them the bound's edge, a selector of 2, `−1` read canonically, and `V[row]` and `V[ram_live]` read at the witness's row; evaluators reporting nothing or everything fail; and S15's three negative controls — a selector with no booleanity gate refused by `check_laws` and by `validate` alike, `check_lookup_discharge` on an unconsumed obligation and on a column two lookups share, and `check_channel_roots` refusing each half of a root pair alone |
| `tests/memory.rs` | `memory_roots` on a forwarded `ZERO_WINDOWS` artifact and a forwarded frame — halving inputs at layers 1 and 4 — equal to the top and to the halving input's products; refused when one row under either root changes, when the halving input is replaced by one-row columns holding the roots, when a layer is missing, and on an artifact with no halving list; all seven families' frames and both window artifacts passing `check_laws` and `check_padding`, and every frame `check_padding_identity`; S14 acceptance 1, an honest statement over the committed `fib` and `heap` ELFs decoded at 2^16 and traced — **one frame shard per family that ran**, over that family's own cycles at the smallest power-of-two height and addressed by that family's `frame_queries`, `INIT_TEARDOWN`, and one `ZERO_WINDOWS` shard per `trace::init_windows` id, each filled by `trace`'s builders under slots 1–4 from a transcript binding nothing (S16 owns the schedule): every shard's `gkr::self_check`, `memory_roots`, `check_laws` and `check_padding`, `violated_relations` empty on every row of both windows and on every live row and the first padding row of the frame, `violated_lookups` empty on every row, the frame's product-tree clause, `check_memory_windows`, `reconciles` with `build_boundary_finals` at the image's entry pc, and every shard proved, verified and its base claims discharged — heap's 2^18-row frame excepted; the same statement with one frame per family that ran, over that family's non-contiguous cycles and one list reversed, each row holding its `cycles[i]`, every shard self-checked and the roots reconciling with the windows'; and each family's frame columns held to that family's buffers row by row, each role at its slot and the first padding row, with a role its frame has no slot for asserted to be a role no row of that family has — which holds `frame_queries` to the real execution, not just to the spec |
| `tests/multiset.rs` | S14's acceptance items and the design's controls on fib's trace at `h = 2^16`, which shards as five frames — `ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT`, `SHIFT_BITWISE`, `MEM_WORD`, `MEM_SUBWORD` — plus windows 0 and 8191, pinned in the harness; each tamper beside its honest twin and measured as one surface — the first gate `gkr::self_check` names, every obligation `violated_lookups` names across **every** frame, and `reconciles`. A tamper names the shard it targets, which is load-bearing: fib's first two `rd` writes to `x11` fall in different families: 2, a store's read value moved, reconciliation alone; 3, a pc read timestamp moved, reconciliation alone, and a cycle moved, also `gap_lo_pc` and `gap_lo_rs1`; 4, a future read of `x0` by two swapped read timestamps, reconciling with `gap_lo_rs1` alone named and no high chunk rescuing it; 5, a flipped image byte under the one window-0 word fib reads, not reconciling, and under an untouched word, cancelling; 6, a hand-forged `ZERO_WINDOWS` init column, reconciling at 0 and not at 7 on a stack word; 7, every touched RAM word of fib and heap on exactly one teardown row holding its last write, and a stale stack read balanced by window 8191 listed twice; 8, every `x0` query reading and writing 0, a write of 5 to `x0` read back as 5 reconciling while `self_check` names `rd_write_masked`, a register write zeroed and an `x0` write of 5 each balanced and each refused by exactly `rd_is_zero_at_nonzero` or `rd_is_zero_inverse`, and each of the five read-only queries writing back another value refused by exactly its `<q>_writes_back` — `arg1` and `arg2` existing only in `ADD_SUB_LUI_AUIPC`'s frame and `load` only in `MEM_WORD`'s, with the frames used asserted so a silent drop from five to four fails; 10, the `ADD_SUB_LUI_AUIPC` frame at 2^16 proved and verified, every committed cell of its 64,879 padding rows the artifact's all-zero padding row, `cycle` included, its padding rows' leaves and row products 1, its roots the 2^12 frame's; 11, the frame's `rs1` obligations accepting gaps 0 and `2^38 − 1` and refusing −1 and `2^38`; C1, a query at word `0x4` unbalanced, balanced against window 0 without `V[ram_live]` and against a zero window listed at id 0; C2, each single change of fib's window list or shard counts refused by its rule, `[8191, 8191]` among them; C3, a boundary timestamp, value or entry pc moved; C4, a trace stopped before its exit row refused by `build_boundary_finals`, and with finals claiming `HALT_PC` not reconciling where its own final pc would; C5, a padding row's pc query at mask −1 moving `x10`'s final value to 42, reconciling while `self_check` names `pc_mask_boolean`; C6, `x10`'s final value solved after the challenges, reconciling and not a `u32`; C7, a query reading its own write at `0x4000_0000` and at register 32, where no row is, reconciling with only its `gap_lo` named; C8, S16's mask targets — a padding row's `rd` query rewriting `x10` after exit, a live row's `rd` write masked off, and the exit row given a store rewriting a stack word's final value — each reconciling with nothing at S14 refusing it |
| `tests/common/mod.rs` | the pinned toy fixtures and their editing helpers; the committed guests traced at 2^16, their memory shards, a shard with cells rewritten, roots, reconciliation, a forwarded row as a `WitnessRow`, and the prove-verify-discharge harness, shared by `memory.rs` and `multiset.rs` |
| `tests/witness.rs` | acceptance 8: a satisfying row passes; perturbing each of 14 cells reports exactly the relations derived by hand for it, on active and inactive rows; an evaluator reporting nothing or everything fails |
| `tests/cross_check.rs` | acceptance 9: the hand-written description passes both fixtures; 24 perturbations, each on both compilations, each caught by the check the test names — among them a renamed memory, witness and setup column and a lawful added cached entry; documentation-only renames pass |
| `tests/logup.rs` | **`#[ignore]`d; CI runs the file by name with `--include-ignored --test-threads=1`** — the toy is 2^20 rows and one forward pass holds 4.63 GB of inner cells. S15's acceptance over the combined toy filled from fib's `JUMP_BRANCH_SLT` cycles and decoded table: 1, the honest circuit — laws, padding, both discharge checks, no violated lookup or relation, every channel's root reproduced natively and holding, proved and verified; 2, the stage gate, one `word_hi` moved out of `[0, 2^16)` with the multiplicities recounted over it, which cannot even be counted, and the honest twin beside it; 3, the transcript order, every witness and multiplicity commitment absorbed before `g` and `β` are drawn, event for event and as an invariant; 4, S14's future read rerun, balancing and breaking no gate, now refused by the timestamp channel; 6, the gated keys — garbage under a flag of 0 leaving every root where it was, a flag = 1 key moved, and the `+ 1` offset distinguishing the AND table's real `(0, 0, 0)` from the `ZeroEntry`; 7, a moved decoded output and two illegal packed masks, the all-zero one included, each refused by the table's domain with every gate still holding; 8, one multiplicity cell changed; 12, a non-boolean extracted bit refused by its own gate; and the control for §4's precondition — a selected row whose key evaluates to `−1` gates to the `ZeroEntry`, and every check accepts it, which is why a family must bound the keys it looks up |
| `src/tamper.rs` (unit) | `assert_rejects`' comparison: the variant whatever the reason or layer, and a `Lookup`'s channel |
| `tests/add_sub.rs` | S16's circuit row by row, in ordinary CI, with no forward pass: the fixture pinned and equal to its constructor, and the circuit passing the laws, the padding contract, the product-tree clause, `check_memory` and both discharge checks through both enforcement points; §8's layout, 31 gates, five lookups and three channels by name and in order; the registry's three families, and its `None`s; every row kind — each sum with and without its carry, each difference with and without its borrow, an `x0` destination, an `x0` operand, a two-byte instruction, a fence, the exit and the padding row — satisfying every gate and bound, each row built from Rust's own `u32` arithmetic; a table of single-cell tampers, each refused by exactly the gates written beside it — padding rows claiming a kind bit or storing into RAM among them; every booleanity gate §8.2 adds refusing 2; and acceptance 7's rows breaking exactly what their controls say — the unreduced result on an add, an addi and a sub, a `next_pc` past 32 bits through either halfword — the all-zero mask breaking no gate and no range |
| `tests/jump_branch_slt.rs` | S17's circuit row by row, in ordinary CI, with no forward pass: the fixture pinned and equal to its constructor, the circuit passing both enforcement points' rules, depth 25 at `2^20`; the layout, 42 gates, 22 lookups and four channels by name and in order — the generic channel's table `S[7..10]`, the decoder's `S[0..7]` — and a sign lookup's tuple in full; the registry's arm at 19 and 20 variables, its `None` at 18, and still none for the families no stage has built; 47 honest instruction rows and the padding row, each built from Rust's own `u32`/`i32` arithmetic — every comparison at full width and mixed signs, every branch taken and not, backward and to its own fall-through, each jump forward, backward and to `x0`, a wrapping `jalr` and one dropping bit 0, the compressed forms, and `rd = x0` for all four comparisons, each computing 1 and writing 0 (acceptance 5) — each satisfying every gate, range obligation and both table channels (each table lookup gated by its own selector, read from the row: a row's gated generic tuple held to `program::lookup_tables`' entries, its decoder tuple to its own table columns or the `MINUS_ONE` row); a table of tampers each refused by exactly the gates beside it — among them S14's C8 on this frame, a branch comparing `rs1` against `rs2` plus its displacement refused by `cmp_rhs_rule` alone, a `jal` landing anywhere through a wrap that is not a bit refused by `pc_wrap_boolean` alone, a `jalr` rounding its target up through a dropped bit of −1 refused by `jalr_drop_boolean` alone, and a branch writing `HALT_PC`; every booleanity gate refusing 2; acceptance 2 — at a 6-bit word, every operand pair signed and unsigned admits exactly one `(lt, gap)` with `gap` in the word, through `comparison_equation`, in every sign quadrant, and at full width the pinned comparisons holding and, with `lt` flipped — acceptance 7's forged `lt` as rows, a not-taken `bltu` among them — refused by `cmp_order` alone, and with the gap moved by `2^32` to match, by `cmp_gap_hi_range` alone; 4, the SLTI defect satisfying every gate and refused by the `U16GetSign` lookup alone, and with `rs2`'s halfword taken too by `cmp_rhs_lo_range` alone; each table lookup the lone refusal of a row every gate and range accepts — `slt(-1, 1)` answering 0 with `rs1`'s sign read as 0 (`cmp_lhs_get_sign`), `slt(1, -1)` answering 1 with `rs2`'s (`cmp_rhs_get_sign`), and a `jal`, which reads no `rs1`, four bytes further than its table row (`decode_row`); the fake exit — a `jalr` keeping bit 0 to write `HALT_PC` — refused by `next_pc_even` alone, as is an odd target elsewhere, and an unreduced jump or branch target by `next_pc_hi_range`; 3 as rows; the decoder-domain control S15 and S16 carry, `an_all_zero_mask_is_refused_by_the_decoder_domain_alone` — an all-zero mask on a live row, its `rd` query and operands dropped to match, breaking no gate and no range; 8, padding advancing to its claimed fall-through; 9, the legal masks equal to the instruction list routed through `row_kind`, to the mask recomposition gate's weights and to the guest's decoded masks; the guest's trace running all twelve instructions and the acceptance matrix — the pinned comparisons, branches taken and not, a compressed branch taken and one not taken, a branch taken to its own fall-through, `c.j` and `c.jr`, `c.jal` and `c.jalr` linking `pc + 2`, the loop's back edge five times, `jal` forward and backward, the `jalr` with `rs1 = rd`, `slti` and `sltiu` against −1, and `jal`, `slt`, `sltu`, `slti` and `sltiu` into `x0`, each comparison's operands making it compute 1 — with every `x0` event reading and writing 0; acceptance 6's honest half, `a_jump_to_a_pc_holding_no_instruction_cannot_be_counted`: over `control`'s filled shard, the `jalr` moved two bytes into the 32-bit `sltiu` it lands on and the next row's pc moved with it, `trace::build_multiplicities` refuses the decoder channel by name while every other channel still counts; and the prover's own fill over that trace counting every channel and satisfying every gate and range on every live row, the two padding rows after them and the last row, its setup columns equal row for row to the decoded table and to `generic_table`; the fill over two programs built by hand — a taken branch, a `jal` and a `jalr` each landing in another `2^16`-byte page than its fall-through, and a branch looping `2^18 + 5` times at `2^18`, whose second shard fills the cycles after the first's — and refusing, by its own panics, `control`'s trace against a table whose first `jal` jumps four bytes further or whose `slt(-1, 1)` is an `sltu` |
| `tests/tamper.rs` | **`#[ignore]`d; run with `--include-ignored --test-threads=1`** (11.3 GB peak: a statement's proof beside the honest one the harness keeps). S17's twins over `guests/control`, in `s17_a7_the_comparison_and_the_pc_are_pinned`: a corrupted `lt` on `BLT(1, 0x80000000)` `Constraint`, carried through the gap, `taken` and `next_pc` `Lookup { RANGE16 }`; the `jalr`'s `next_pc` moved two bytes on with its `rs1`, every gate and bound holding, `MemoryArgument` — and again with the add/sub row that wrote that `rs1` moved to match, so the register's chain balances and the pc's alone does not, `MemoryArgument` on the jump family's shard; the generic channel's count of the `ZeroEntry` `Lookup { GENERIC }`; a packed-table AND cell no row looks up, poisoned, refused by the opening of the table's columns against the key's `generic_table`, `Opening`; and two padding cells verifying. In `s17_a6_a_jump_to_a_pc_holding_no_instruction_is_unprovable`, acceptance 6: the same `jalr` moved into the middle of the 32-bit instruction it lands on with the next row's pc to match, the honest prover's decoder recount refused by name and the proof `Lookup { DECODER }`. S16's, over `guests/addsub`: acceptance 2–4, a wrap bit and a computed value `Constraint`, a teardown value and a pc read timestamp `MemoryArgument`, a `RANGE16` and a decoder multiplicity each `Lookup` on its own channel; 7, an unreduced sum and a `next_pc` past 32 bits refused by `RANGE16`, a wrap of 2 by its gate, an all-zero mask by `DECODER` — each channel named exactly; 11, cells nothing reads verifying; 13 as remapped, a teardown value or timestamp and `x10`'s final value under an honest exit status each `MemoryArgument`, on both shards, and a boundary timestamp past the clock refused by exactly step 10's re-check; and S14's C8 forgeries, the exit rewriting its status, a non-exit row writing `HALT_PC`, and an image byte moved with its teardown value (`Opening`) |
| `tests/dump.rs` | acceptance 10: the dump's header, columns, layers, relations, addresses and catalogue; one exact line per gate shape, the toy's `Quadratic` gate and its relation, the cached entry, a scratch-bijection line and an output-map line; a literal at or above `2^64` printed as hex; the CLI on the fixtures, a corrupted file and a lawless one; a lookup's line, with its channel's name and its selector |
