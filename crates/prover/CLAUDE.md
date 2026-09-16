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
impl ProvingContext<'_> {
    pub fn gkr_part(&self, family: FamilyId, index: u32, base: &BaseLayer) -> ShardGkr;
    pub fn opening_part(&self, shard: ShardGkr, base: &BaseLayer) -> (ShardProof, Vec<TranscriptEvent>);
}
pub struct ShardGkr { family, index, witness_commitments, outputs, gkr, point, transcript: Transcript }
pub fn shard_columns(setup: &ProverSetup, archive: &TraceArchive, family: FamilyId, index: u32,
                     windows: &[u32]) -> Result<Vec<(PolyAddress, MultilinearPoly)>, ProverError>;
pub fn prove_shard(ctx: &ProvingContext, archive: &TraceArchive, family: FamilyId, shard_idx: u32) -> ShardProof;
pub fn prove_shard_columns(ctx: &ProvingContext, family: FamilyId, shard_idx: u32,
                           columns: Vec<(PolyAddress, MultilinearPoly)>) -> (ShardProof, Vec<TranscriptEvent>);
pub fn advance(setup: &ProverSetup, archive: &mut TraceArchive, until: Phase) -> Result<(), ProverError>;
pub fn finish(archive: &TraceArchive) -> Result<(PublicInputs, Vec<ShardProof>), ProverError>;
pub enum ProverError { Unregistered { family, height }, Key(String), Trace(String), Archive(String) }
```

## Frozen invariants
- **The family-registration surface.** A family is proved when `constraints::family_circuit`
  has its circuit and `family_fill` its fill; `register` takes the families of a
  `VmConfig` and refuses the first that lacks either. A later family adds one of each, and
  `global_commit_phase`, `prove_shard`, `reduce_shard` and `verify_shard` do not change.
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
  computed, and the frame's x0 rule masks it into the write.
- **Snapshots are the S12 archive's later sections**, `docs/spec/shard-proof.md` §10, in
  §9's encodings, each phase timed into the archive's timing section. `advance` reads back
  any phase the archive holds; the columns are never stored and a resumed phase rebuilds
  them. A resumed statement finishes to the same bytes as an uninterrupted one.
- **Deterministic.** Commitments are computed in parallel and collected in order; the
  forward pass, the sumcheck and the MSMs are thread-count independent (S07, S13). Proofs
  are byte-identical on one thread and on all of them.

## Tests
| File | Covers |
| --- | --- |
| `tests/common/mod.rs` | the S16 statement: `guests/addsub`'s committed ELF decoded with its family at `2^20` and everything else at `2^16`, traced into an archive, over a toy SRS whose `tau` is written down and whose archive is cached under `target/tmp` (`CARGO_TARGET_TMPDIR`), shared by the three suites that include this module |
| `tests/acceptance.rs` | **`#[ignore]`d; run with `--include-ignored --test-threads=1`** (a statement's proof peaks at 8.6 GB). Acceptance 1 (the guest's family set and trace; both shards verify; round counts, claim counts and byte lengths from the circuit); 5 (every statement twin refused as `Statement`, on both shards); 6 and 8 (the shard transcript event for event: seed, window, commitments, `g` and `β`, then the GKR schedule rebuilt from the artifact's shape — outputs, every batch, round and claim message, every child challenge — with one outstanding point after every batch, then one batched opening whose column-RLC challenge follows every evaluation claim; the verifier's reduction re-deriving the prover's point; the global transcript's challenges after every memory commitment); 9 (stopped after post-execution — nothing filled — and resumed after it, post-commit, post-GKR and post-opening, byte-identical); 10's library half (proofs, statement and key round-trip, and the key loads back to itself); and one-thread against all-threads determinism |
