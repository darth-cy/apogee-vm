# `crates/prover`

## What this crate owns
The prover: a program's verifying key, the statement an execution proves, the global
commit phase, each shard's proof, the family fills, and the phase snapshots with resume.
`docs/spec/shard-proof.md` is normative; this crate is its §2, §4, §5, §10 and §11 from the
prover's side, over `verifier-core`'s statement code.

```rust
pub struct Program { pub image: ProgramImage, pub tables: DecodedTables, pub config: VmConfig }
pub struct FamilyRegistration { pub family: FamilyId, pub height: u32, pub circuit: FamilyCircuit, pub fill: Fill }
pub fn register(config: &VmConfig) -> Result<Vec<FamilyRegistration>, ProverError>;
pub type Fill = fn(&ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String>;
pub struct ShardSource<'a> { program, archive, family, index, height, window }
pub fn family_fill(family: FamilyId) -> Option<Fill>;
pub struct ProverSetup { pub program: Program, pub families: Vec<FamilyRegistration>,
                         pub vk: VerifyingKey, pub srs: Srs }
impl ProverSetup { pub fn new(program: Program, srs: Srs) -> Result<ProverSetup, ProverError>; }

pub struct StatementInputs { input, output, exit_status, shard_counts, windows, boundary,
                             memory_columns: Vec<Vec<MultilinearPoly>> }
pub fn statement_inputs(setup: &ProverSetup, archive: &TraceArchive) -> Result<StatementInputs, ProverError>;
pub struct GlobalCommitState { pub statement: PublicInputs, pub transcript: TranscriptSnapshot,
                               pub memory_challenges: [Fr; 4], pub digest: Fr }
pub fn global_commit_phase(vk: &VerifyingKey, srs: &Srs, inputs: &StatementInputs) -> GlobalCommitState;
pub fn public_inputs(global: &GlobalCommitState, proofs: &[ShardProof]) -> PublicInputs;

pub struct ProvingContext<'a> { pub setup: &'a ProverSetup, pub global: GlobalCommitState }
pub fn shard_columns(setup: &ProverSetup, archive: &TraceArchive, family: FamilyId, index: u32,
                     windows: &[u32]) -> Result<Vec<(PolyAddress, MultilinearPoly)>, ProverError>;
pub fn prove_shard(ctx: &ProvingContext, archive: &TraceArchive, family: FamilyId, shard_idx: u32) -> ShardProof;
pub fn prove_shard_columns(ctx: &ProvingContext, family: FamilyId, shard_idx: u32,
                           columns: Vec<(PolyAddress, MultilinearPoly)>) -> (ShardProof, Vec<TranscriptEvent>);
pub fn advance(setup: &ProverSetup, archive: &mut TraceArchive, until: Phase) -> Result<(), ProverError>;
pub fn finish(archive: &TraceArchive) -> Result<(PublicInputs, Vec<ShardProof>), ProverError>;
pub fn prove_block(setup: &ProverSetup, archive: &mut TraceArchive, plan: &ShardPlan)
    -> Result<BlockProof, ProverError>;                    // S20, docs/spec/block-proof.md §5
pub enum ProverError { Unregistered { family, height }, Key(String), Trace(String), Archive(String) }
```

## Frozen invariants
- **The family-registration surface.** A family is proved when `constraints::family_circuit`
  has its circuit and `family_fill` its fill; `register` takes the families of a
  `VmConfig` and refuses the first that lacks either. A later family adds one of each, and
  `global_commit_phase`, `prove_shard`, `reduce_shard` and `verify_shard` do not change.
  S17's jump family was that, plus the binding of the generic table it is the first to
  read: every key carries the table's commitments, and `opening_part` and `reduce_shard`'s
  step 11 list them after identity's setup commitments for a family whose circuit reads
  the `GENERIC` channel. **S18's two families were that and nothing else**: two circuits,
  two fills, and no edit anywhere in this crate's phase code — the second and third readers
  of the generic channel needed no key change at all, which is what carrying the triple in
  every key buys. **S19's three were the same**: three circuits, three fills, and nothing
  else in this crate, `MEM_WORD` — which reads no generic lookup — going down the same
  no-generic path `ADD_SUB_LUI_AUIPC` already took. With them every family the master
  prompt names is registered.
- **A shard's proof is two crate-private halves**, `gkr_part` (through the GKR proof, to
  a `ShardGkr` — the post-GKR snapshot's entry) and `opening_part` (the batched opening),
  which `prove_shard_columns` runs back to back and `advance` runs a phase apart.
- **`prove_shard` is shard-local**: the witness commitments, the shard transcript, the
  lookup challenges, the forward pass, the GKR proof and the one batched opening. The
  global phase is `global_commit_phase`, shard-count generic, whose state a
  `ProvingContext` carries; one context serves every shard of every family.
- **The prover checks nothing a verifier does not** (S13). A tampered column gets a proof,
  which is what `checker::TamperHarness` relies on. `gkr_part` reads the base claims' one
  point back by **replaying the frozen GKR schedule over the proof without its checks**
  (`replay_point`), and asserts the replay ends in the prover's own transcript state: that
  is what holds this copy of `docs/spec/gkr.md` §5.2 to the engine's, and a failing
  replay is a schedule drift, never a witness defect. `opening_part` asserts the opened
  values are the base claims.
- **What the prover does refuse is its own program**: a family with no circuit or fill,
  and a trace S16 cannot prove — an ecall other than `EXIT`, a transfer cycle — each by
  name. The add/sub fill panics if the trace and the decoded table disagree, which the
  emulator cannot cause.
- **Multiplicities come from `trace::build_multiplicities` and nowhere else.** A fill
  returns every column but them, and `shard_columns` counts them over the family's
  channels. `trace::check_multiplicities` is not called on this path: it is a recount of
  exactly that build, and a column the prover counted itself cannot disagree with it.
- **The add/sub fill writes the computed `rd` value into `rd_selected`**, where S14's frame
  builder writes 0 on an `x0` write: the family's semantic gates read what the instruction
  computed, and the frame's x0 rule masks it into the write. S17's jump/branch/slt fill
  does the same with the link or `lt`, computes every comparison cell from Rust's own
  `u32`/`i32` ordering — `cmp_gap` is `(rs1 − cmp_rhs) mod 2^32` whatever the signedness —
  and writes the packed generic table (`program::lookup_tables::generic_table`) as its
  `S[7..10]`; it panics, like add/sub's, if the trace's `next_pc` or `rd` write is not what
  the instruction computes. **S18's two do the same.** `fill::shift_bitwise` computes the
  shift amount, the shared product, the overflow or residue and the eight byte columns from
  Rust's own `u32` and `i64` arithmetic, writes `pow` and `copow` as 0 on a bitwise row, and
  panics on a residue not below its power or a row carrying both a register `rs2` and a
  nonzero immediate — which the emulator cannot produce, one addend always being zero.
  `fill::mul_div` computes the division witness from `wrapping_div` and `wrapping_rem`,
  which are RV32M's two pins exactly, and the product from `i128`; it derives `q_sign` from
  the sign of the adjusted quotient rather than from bit 31 of the word, which is what makes
  `−2^31 ÷ −1` fillable (`docs/spec/mul-div.md` §5.3), and panics if the identity does not
  divide, if a quotient word is not its adjusted value or if a product does not fit two
  words. Its decoded row is **five** values, not six: the family's tuple has no immediate,
  so its table is `S[0..6]` and the packed table `S[6..9]`.
- **Six `Fr`-backed columns exist across the S18 fills**, and no more: `shift_in` and
  `shift_prod`, whose values are signed on a right shift and reach `2^63` on a left one;
  `mx` and `my`, which are signed; and `r_inv` and `d_inv`, which are field inverses. Every
  other column of those fills is `u32`-backed, and **every column of all three S19 fills
  is**: the splice's halved copower and halved width multiplier are what keep them there
  (`docs/spec/memory-ops.md` §4.1).
- **S19's three fills** share one helper, `frame_columns`, which is S14's frame columns and
  frame witness with `rd_selected` left out so each fill writes the value the instruction
  computes there. `fill::mem_word` splits the effective address with `overflowing_add` and
  asserts the access is word-aligned; `fill::mem_subword` computes `p`, `w`, the three
  splice parts and the store source's split with ordinary `u64` division and remainder, and
  asserts a halfword access is halfword-aligned and that the trace's stored word is the
  spliced one; `fill::atomics` computes all eleven results from Rust's own operators —
  `wrapping_add` for `amoadd`, the byte AND for the three bitwise kinds with `or` and `xor`
  derived from it through `wrapping_add`/`wrapping_sub`, since `old + rs2` on its own can
  pass `2^32`, and `i32`/`u32` `min`/`max` for the four min/max — and asserts the trace's
  stored word and `rd` write are what the instruction computes. Its decoded row is **five**
  values like mul/div's, the tuple having no immediate. Each panics on a disagreement the
  emulator cannot produce, never on a witness a cheating prover could write.
- **Every key carries the generic table's commitments** (S17): `ProverSetup::new` takes
  them from `program::lookup_tables::generic_commitments(&srs)` — the table committed
  once, at `2^18`, the same three points at every height — puts them in the key's
  `generic_table` whatever its families read, and computes the SRS digest over the
  `SrsVerifier` and them. It then runs the key's own load rules, `VerifyingKey::check`, so
  a registry entry that broke them fails there. `opening_part` lists the three after
  identity's setup commitments for a family whose circuit reads the `GENERIC` channel, as
  `reduce_shard`'s step 11 does. The SRS must hold at least `2^18` powers, which every
  provable program's does: its tallest family is at least `2^20` rows.
- **Snapshots are the S12 archive's later sections**, `docs/spec/shard-proof.md` §10, in
  §9's encodings, each phase timed into the archive's timing section. `advance` reads back
  any phase the archive holds; the columns are never stored and a resumed phase rebuilds
  them. A resumed statement finishes to the same bytes as an uninterrupted one.
- **`prove_block` is orchestration and nothing else** (S20): it refuses a `ShardPlan`
  that is not `trace::plan_shards` over this archive's cycle profile, runs `advance` to
  `Phase::Final`, and assembles the block from `finish`. The shard cut is the one every
  family fill has done since S16 — rows `[i·h, min((i+1)·h, len))` of the family's trace
  buffer, the last chunk padded by the column builders. The two RAM window families run
  no cycles, so the plan counts 0 for both and their shards are the statement's.
- **Shard proving is the block's one parallel step**, a `rayon` parallel iterator over
  the shard list in `advance`'s `PostGkr` and `PostOpening` phases, and it starts only
  after the global commit phase has closed. Each task forks its transcript from the same
  global state, builds its own slice of the archive, proves it and drops it, so the
  shards share no prover state and the schedule cannot reach a challenge; an indexed
  parallel `map` collects in order. The peak is one shard trace per worker on top of the
  statement's committed memory columns — **measured at 24.2 GB for a four-shard block,
  three of them at `2^20`, and at 32.3 GB for `guests/mem`'s seven, five of them
  `2^20` — where the same statement was 14.7 GB when the shards were proved one at a
  time.** The trade is about 2.2× the peak for about 1.4× the speed, it grows with the
  family count, and there is no knob: a caller that must bound it installs its own rayon
  pool. `docs/handoff/S20-orchestration.md` has the table.
- **A shard's claimed time window is read off its own `M[0]` cycle column**:
  `[4·cycle(row 0), 4·max cycle + 4)` for a cycle-owning family, the trivial window for
  one whose rows are RAM words. Reading it from the committed column rather than from
  the archive keeps `prove_shard_columns`' signature and makes the honest window a
  function of exactly what the shard commits; a tampered column is read as its low 64
  bits and multiplied saturatingly, because the prover checks nothing.
- **Deterministic.** Commitments are computed in parallel and collected in order; the
  forward pass, the sumcheck and the MSMs are thread-count independent (S07, S13). Proofs
  are byte-identical on one thread and on all of them, and so is an assembled block.

## Tests
| File | Covers |
| --- | --- |
| `tests/common/mod.rs` | the S16 statement: `guests/addsub`'s committed ELF decoded with its family at `2^20` and everything else at `2^16`, traced into an archive, over a toy SRS whose `tau` is written down and whose archive is cached under `target/tmp` (`CARGO_TARGET_TMPDIR`), shared by the four suites that include this module — `tests/acceptance.rs`, `tests/control.rs`, `crates/verifier/tests/cli.rs` and `crates/checker/tests/tamper.rs`; and S17's, `guests/control`'s, with both of its execution families at `2^20` (`control_setup`, `control_archive`, `CONTROL_RESULT = 16`); `toy_tau` |
| `tests/key.rs` | S17, in ordinary CI, no proof: `ProverSetup::new` over `control` and the toy SRS gives a key whose `generic_table` is `generic_commitments` over that SRS, whose SRS digest is over its `SrsVerifier` and them, and which loads; each of the three commitments is `[Σ_i c_i·τ^i]_1` of its column, computed by Horner's rule from the toy `τ`, the three distinct, and the same over `2^18` powers as over `2^20` |
| `tests/control.rs` | **`#[ignore]`d; run with `--include-ignored --test-threads=1`** (18.0 GB peak since S20 proves its two `2^20` shards at once; 10.1 GB at S17). S17 acceptance 1: `control`'s four-family config, its self-checking trace, three shards — `INIT_TEARDOWN`, `ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT` — each verifying, with round and claim counts and byte lengths from the circuit, the jump family's pinned at 61,612 bytes; the generic table's binding — the key's `generic_table` equal to `generic_commitments` over this SRS, its SRS digest the digest over the `SrsVerifier` and them, and the jump family's opening claim `M ++ W ++ S`, 21 + 44 + 10 commitments ending with the table's three, while add/sub's is 36 + 31 + 7 and ends with identity's; and `a_key_with_another_generic_table_is_another_statement`: a key whose table's value and result commitments are swapped does not load under the honest SRS digest, loads under its own recomputed one, which differs, and refuses every honest shard as `Statement("the proof was made for another statement")` |
| `src/phases.rs` (unit) | the post-commit section round-trips and refuses a trailing byte and a missing one; the post-GKR and final sections refuse a trailing byte |
| `tests/block.rs` | **`#[ignore]`d; run with `cargo test --release -p prover --test block -- --include-ignored --test-threads=1`** (779 s, 33.4 GB peak). S20's acceptance over `guests/shards`, whose add/sub family runs 1,064,970 cycles and so proves **two shards of one family**: 1, 3, 8 and 9 — the block proves and verifies, every shard also verifies on the S16 path, the records are statement order, the descriptor and counts read through the serialized proof alone, `ZERO_WINDOWS` proves zero shards and reads 0, the `ShardProof` and `BlockProof` schemas destructured exhaustively so a boundary-pc field could not be added unnoticed, the run's transcript tape equal to the committed fixture with its five squeezes after every absorb and no tag G1–G11 does not have, and the windows ordered and disjoint within add/sub while the jump family's overlaps both; 4 and 6 — a one-bit-different I/O digest, another identity, another config, a shard count altered with and without matching lists, and two shards' windows exchanged, each refused as `Statement` by the check named, the window swap also refused independently by the shard's own transcript; 5 — the truncated statement **re-proved as an honest prover would**, its counts, lists and roots adjusted and its global phase rerun, refused by `MemoryArgument` on the root product; 7 — one `wrap` cell of the **second** add/sub shard, re-proved, refused as `Constraint` with the honest twin still passing; 10 — killed and resumed at post-commit and post-GKR, byte-identical; must-be-exact 8 — byte-identical on one thread; and 2 — `guests/mem`'s five-family block, seven shards, every record carrying its family's memory commitments and both roots |
| `tests/acceptance.rs` | **`#[ignore]`d; run with `--include-ignored --test-threads=1`** (a statement's proof peaks at 8.6 GB). Acceptance 1 (the guest's family set and trace; both shards verify; round counts, claim counts and byte lengths from the circuit); 5 (every statement twin refused as `Statement`, on both shards); 6 and 8 (the shard transcript event for event: seed, window, commitments, `g` and `β`, then the GKR schedule rebuilt from the artifact's shape — outputs, every batch, round and claim message, every child challenge — with one outstanding point after every batch, then one batched opening whose column-RLC challenge follows every evaluation claim; the verifier's reduction re-deriving the prover's point; the global transcript's challenges after every memory commitment); 9 (stopped after post-execution — nothing filled — and resumed after it, post-commit, post-GKR and post-opening, byte-identical); 10's library half (proofs, statement and key round-trip, and the key loads back to itself); step 10a's root comparison, which is per shard and stayed there when S20 lifted 10b out (the init shard's statement roots scaled by one constant still reconcile — 10b passes — and that shard's proof refuses them exactly while the add/sub shard's accepts); and one-thread against all-threads determinism |
