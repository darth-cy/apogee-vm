# S16 — Vertical slice: add/sub family end to end

Branch `s16-add-sub`. Status: implemented; all thirteen acceptance items are met, item 13 in
the form the repository owner chose (see "Acceptance"). Eight design questions went to the
owner before any code and were answered. Each answer and what follows from it is in "Read
these first".

S16 proves a real program. `guests/addsub` is a straight-line chain of 29 instructions over
the add/sub family's roster, and its exit status is 42. It is built, decoded, traced,
committed, proved as two shards — `INIT_TEARDOWN` and `ADD_SUB_LUI_AUIPC` at `2^20` rows —
and each shard is verified through `verify_shard` against one statement. Tamper twins are
re-proved as an honest prover would prove them. They are refused in the class of what they
broke: `Constraint`, `Lookup`, `MemoryArgument`, `Statement` and `Opening`, all five on
screen.

Normative documents written or amended this stage:

- **`docs/spec/shard-proof.md`** (new): the statement and `PublicInputs`, the global
  transcript G1–G11, the SRS digest, the shard transcript S1–S6, the one opening per shard,
  `verify_shard`'s check order and error classes, the verifying key and its load rules, the
  add/sub family (columns, gates, lookups, why it is sound, what it does not do), the wire
  forms, the prover's phase snapshots and the registry.
- **`docs/spec/transcript.md`** §8: tags 34–40.
- **`docs/spec/memory.md`** §2.1, §4.1, §5, §6.1–§6.3 and §9, **`docs/spec/lookup.md`** §3
  and §13, **`docs/spec/gkr.md`** §5 and **`docs/spec/srs.md`** §4: status notes on
  what S16 discharged and what moved, plus a few sentences edited in place where they
  pointed forward at S16 — `gkr.md` §5.0 (the claim-merging sumcheck S16 was to add,
  now answer 6) and §5.1 (what S16 absorbs), and `memory.md` §4.1, §6.1, §6.2 and §6.3,
  each extended with what S16 did. No frozen rule changed.
- Also updated to match: `docs/GLOSSARY.md`, `docs/guest-program-manual.md`, the root
  `CLAUDE.md`, `.github/workflows/ci.yml`, and the `CLAUDE.md` of constants, transcript,
  pcs, program, trace, constraints and checker. The three new crates each have one.

`prompts/S16-add_sub.md` is committed unchanged.

---

## Read these first

Eight questions went to the owner before any code, each with the argument and the price.
The answers are the design.

1. **The verifier is two crates, and `pcs` is not split.** `crates/verifier-core` is
   `#![no_std]` and does everything but the one Mercury opening, returning that opening's
   claim; `crates/verifier` is the `std` wrapper that decodes the curve points and calls
   `pcs::batch_verify`, and it holds the CLI. `VmConfig`, the statement descriptor, the
   window rules and the identity digest moved from `program` into the core, and `program`
   re-exports or wraps each, so every old path resolves. G1 limb absorption moved into
   `transcript` over the 64-byte encoding, and `pcs` calls it. The prompt's "curve-free
   Mercury field-side/deferred-scalar module, shared with `pcs`" is **not** built: it and
   S09's open question of how a guest obtains `cm* = Σ ρ^i·cm_i` are the recursion stage's
   (S26). `verifier-core` is a crate name outside the master's layout, as `gkr-verify` was
   at S13.
2. **The SRS digest is Poseidon2 over the 320-byte `SrsVerifier`**, stored in the key and
   absorbed third (G2). It is not a digest of the powers; S07's full digest stays dropped.
   See deviation 3 for what this does and does not bind.
3. **EXIT is the only provable ecall.** `PublicInputs.exit_status` is compared with `v_10`,
   `x10`'s final value, at step 10. Acceptance 13 is remapped (see "Acceptance"). The
   result is below 256 because `qemu-riscv32` reports eight bits of an exit status.
4. **The statement's variable-length record lives in `PublicInputs`**: shard counts,
   windows, boundary scalars, and every shard's memory commitments and roots. A
   `ShardProof` has a fixed shape per key and family and carries the global state digest.
5. **`next_pc` is the decoder's fall-through**: `next_pc + 2^32·pc_wrap = decoded_next_pc`
   on every live row but the exit row, which writes `HALT_PC`, with `next_pc` range-checked
   16+16. The prompt's `final_pc = initial_pc + 4 − 2^32·pc_wrap` would prove every
   compressed instruction at the wrong length.
6. **No separate claim-merging sumcheck.** GKR's layer-0 transition already leaves every
   committed column at one point, so the merge has one point to merge.
   `docs/spec/shard-proof.md` §5.3.
7. **`DEFAULT_HEIGHTS[ATOMICS]` stays `2^16`**, for S19 to raise with the circuit that
   needs it. `family_circuit` has no atomics circuit at any height.
8. **The packed generic table's binding is S17's.** In the owner's words: "Defer to S17.
   The generic table becomes authenticated when the first family actually consumes the
   generic lookup channel. Bind the exact packed-table commitment into the
   proof/constraint-system statement or transcript before lookup challenges are derived.
   Do not add it to S16's program-image identity merely because the table already
   exists."

Five further readings were announced before code, and nobody objected:

- **Add/sub's legal mask set is the table's six one-hot kinds**, `{1, 2, 4, 8, 16, 32}`, not
  the prompt's five: S11 froze a sixth kind, the system row (`ecall`, `ebreak`, `fence`), in
  bit 0 of this family's mask, and the exit path needs it.
- **The decoder's neutral tuple is `MINUS_ONE`**, S15's frozen convention, not the prompt's
  `(0, 0)`: S11's table has no all-zero row, because pc 0 is valid.
- **The time window is the trivial one**, `[0, 2^38)`, and a verifier refuses any other.
- **The proving suites are `#[ignore]`d and deferred** under master rule 7 (see
  "Verification performed").
- `prompts/S16-add_sub.md` was untracked on `main`, and is committed as it stands.

---

## Frozen public API, as built

**`crates/verifier-core`** (`#![no_std]` + `alloc`):

```rust
pub struct VmConfig { pub families: Vec<(u32, u32)>, pub bytecode_size_words: u32 }   // moved from program
pub fn window_height(config: &VmConfig) -> Result<u32, &'static str>;
pub fn absorb_statement_descriptor(tr: &mut Transcript, config: &VmConfig, shard_counts: &[u32], windows: &[u32]);
pub fn check_memory_windows(config: &VmConfig, shard_counts: &[u32], windows: &[u32]) -> Result<(), &'static str>;
pub struct ProgramIdentity(pub Fr);
pub fn identity_digest(code_version: u32, config: &VmConfig, entry_pc: u32, commitments: &[Vec<[u8; 64]>]) -> ProgramIdentity;
pub fn srs_digest(verifier: &[u8; 320]) -> Fr;
pub const TRIVIAL_TS_WINDOW: [u64; 2];
pub fn statement_shards(config: &VmConfig, shard_counts: &[u32]) -> Vec<(u32, u32)>;
pub fn boundary_scalars(finals: &BoundaryFinals) -> Vec<Fr>;
pub struct GlobalTranscript { pub transcript: Transcript, pub memory: [Fr; 4], pub digest: Fr }
pub fn global_commit(vk: &VerifyingKey, statement: &PublicInputs) -> GlobalTranscript;
pub fn shard_transcript(digest: Fr, family: u32, index: u32, ts_window: [u64; 2], witness_commitments: &[[u8; 64]]) -> (Transcript, Fr, Fr);
pub fn memory_slots(memory: &[Fr; 4]) -> ExternalChallenges;
pub fn shard_challenges(circuit: &FamilyCircuit, index: u32, windows: &[u32], memory: &[Fr; 4], g: Fr, beta: Fr) -> ExternalChallenges;
pub enum VerifyError { Statement(&'static str), Malformed(&'static str), Constraint { layer: usize },
                       Lookup { channel: u32 }, MemoryArgument(&'static str), Opening }
pub struct PublicInputs { pub input: Vec<u8>, pub output: Vec<u8>, pub exit_status: u32,
                          pub shard_counts: Vec<u32>, pub windows: Vec<u32>, pub boundary: BoundaryFinals,
                          pub memory_commitments: Vec<Vec<[u8; 64]>>, pub memory_roots: Vec<[Fr; 2]> }
pub struct ShardProof { pub family: u32, pub shard_index: u32, pub ts_window: [u64; 2], pub global_digest: Fr,
                        pub witness_commitments: Vec<[u8; 64]>, pub outputs: Vec<Fr>, pub gkr: GkrProof,
                        pub opening: [u8; 704] }
pub struct VerifyingKey { pub code_version: u32, pub config: VmConfig, pub entry_pc: u32,
                          pub identity: ProgramIdentity, pub setup_commitments: Vec<Vec<[u8; 64]>>,
                          pub srs_verifier: [u8; 320], pub srs_digest: Fr, pub circuits: Vec<FamilyCircuit> }
impl VerifyingKey { pub fn circuit(&self, family: u32) -> Option<&FamilyCircuit>; pub fn check(&self) -> Result<(), String>; }
// PublicInputs, ShardProof, VerifyingKey: pub fn to_bytes(&self) -> Vec<u8>; pub fn from_bytes(&[u8]) -> Result<Self, _>
pub struct OpeningClaim { pub commitments: Vec<[u8; 64]>, pub point: Vec<Fr>, pub values: Vec<Fr>, pub transcript: Transcript }
pub fn reduce_shard(vk: &VerifyingKey, proof: &ShardProof, public: &PublicInputs) -> Result<OpeningClaim, VerifyError>;
pub fn write_gkr(w: &mut wire::Writer, gkr: &GkrProof);  pub fn read_gkr(r: &mut wire::Reader) -> wire::Read<GkrProof>;
pub const OPENING_BYTES: usize = 704;  pub const SRS_VERIFIER_BYTES: usize = 320;
```

**`crates/verifier`**:

```rust
pub fn verify_shard(vk: &VerifyingKey, proof: &ShardProof, public: &PublicInputs) -> Result<(), VerifyError>;
pub fn load_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, String>;
pub fn decode_srs_verifier(bytes: &[u8; 320]) -> Option<SrsVerifier>;
pub fn encode_srs_verifier(vsrs: &SrsVerifier) -> [u8; 320];
```
```
verifier <verifying-key> <identity-hex> <public-inputs> <proof>...    exit 0 / 1 / 2
```

**`crates/prover`**:

```rust
pub struct Program { pub image: ProgramImage, pub tables: DecodedTables, pub config: VmConfig }
pub struct FamilyRegistration { pub family: FamilyId, pub height: u32, pub circuit: FamilyCircuit, pub fill: Fill }
pub fn register(config: &VmConfig) -> Result<Vec<FamilyRegistration>, ProverError>;   // the registration API
pub type Fill = fn(&ShardSource) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String>;
pub struct ShardSource<'a> { pub program, pub archive, pub family, pub index, pub height, pub window }
pub fn family_fill(family: FamilyId) -> Option<Fill>;
pub struct ProverSetup { pub program: Program, pub families: Vec<FamilyRegistration>, pub vk: VerifyingKey, pub srs: Srs }
impl ProverSetup { pub fn new(program: Program, srs: Srs) -> Result<ProverSetup, ProverError>; }
pub struct StatementInputs { pub input, pub output, pub exit_status, pub shard_counts, pub windows,
                             pub boundary, pub memory_columns: Vec<Vec<MultilinearPoly>> }
pub fn statement_inputs(setup: &ProverSetup, archive: &TraceArchive) -> Result<StatementInputs, ProverError>;
pub struct GlobalCommitState { pub statement: PublicInputs, pub transcript: TranscriptSnapshot,
                               pub memory_challenges: [Fr; 4], pub digest: Fr }
pub fn global_commit_phase(vk: &VerifyingKey, srs: &Srs, inputs: &StatementInputs) -> GlobalCommitState;
pub fn public_inputs(global: &GlobalCommitState, proofs: &[ShardProof]) -> PublicInputs;
pub struct ProvingContext<'a> { pub setup: &'a ProverSetup, pub global: GlobalCommitState }
pub fn shard_columns(setup: &ProverSetup, archive: &TraceArchive, family: FamilyId, index: u32, windows: &[u32])
    -> Result<Vec<(PolyAddress, MultilinearPoly)>, ProverError>;
pub fn prove_shard(ctx: &ProvingContext, archive: &TraceArchive, family: FamilyId, shard_idx: u32) -> ShardProof;
pub fn prove_shard_columns(ctx: &ProvingContext, family: FamilyId, shard_idx: u32,
                           columns: Vec<(PolyAddress, MultilinearPoly)>) -> (ShardProof, Vec<TranscriptEvent>);
pub fn advance(setup: &ProverSetup, archive: &mut TraceArchive, until: Phase) -> Result<(), ProverError>;  // resume
pub fn finish(archive: &TraceArchive) -> Result<(PublicInputs, Vec<ShardProof>), ProverError>;
pub enum ProverError { Unregistered { family: FamilyId, height: u32 }, Key(String), Trace(String), Archive(String) }
```

**`crates/constraints`**: `FamilyCircuit { family, artifact, channels }`,
`family_circuit(family, trace_vars) -> Option<FamilyCircuit>`, and `add_sub::{artifact,
channels, DECODED, KINDS, IS_ECALL, IS_FENCE, WRAP, RD_HI, PC_WRAP, NEXT_PC_HI,
MULTIPLICITIES, TABLE_WIDTH}`.

**`crates/checker`**: `Cell { family, shard, address, row, value }`, `Tamper { cells,
boundary }`, and `TamperHarness::{new, honest, cell, run, assert_rejects,
assert_verifies}`.

**`crates/transcript`**: `g1_limbs(&[u8; 64]) -> [Fr; 4]` and
`append_g1_points(&mut Transcript, Tag, &[[u8; 64]])`.
**`crates/trace`**: `TraceArchive::fill(phase, content, timing)` and `content(phase)`.
**`crates/constants`**: tags 34–40.

---

## What this freezes for every later stage

1. **`docs/spec/shard-proof.md`** in full.
2. **The proof-side types and their wire forms** (§9): `PublicInputs`, `ShardProof`,
   `VerifyingKey`, and the `VerifyError` classes in check order.
3. **The global transcript** G1–G11, `global_commit`, run once by the prover and once per
   shard by the verifier; the group header `MEMORY_GROUP [family, count]`; the global state
   digest under tag 38.
4. **The shard transcript** S1–S6: `SHARD_SEED [digest, family, index]`,
   `SHARD_TS_WINDOW [start, end]`, the witness commitments, `g` and `β`, the GKR schedule,
   the batched opening.
5. **The opening's column order** `M, W, S` and the commitment sources: the statement for
   `M`, the proof for `W`, **the key's setup commitments for `S`**, which is what opens
   `INIT_TEARDOWN`'s `S[0]` against identity's `cm(image column)`.
6. **The SRS digest** (§3) and tag 35, bytes kind.
7. **The key's load rules** (§7.2), circuits byte for byte the registry's among them.
8. **The registry and the fill table** as the family-registration surface (§11): a later
   family adds one constructor arm in `constraints::family_circuit` and one fill in
   `prover::family_fill`, and changes nothing in `global_commit_phase`, `prove_shard`,
   `reduce_shard` or `verify_shard`.
9. **The add/sub family** (§8) and its fixture `add_sub.bin`.
10. **The phase snapshot schemas** (§10) inside S12's container, and resume as
    `TraceArchive::import` + `advance`.
11. **The `TamperHarness` API.**
12. **S12's per-query-kind Δ-slot assignment, re-frozen as the per-family frame
    convention** (the prompt's handoff clause): `execution-trace.md` §7's roles at the
    slots `constraints::memory::FRAME_DELTA` lists — pc 0, rs1 1, rs2/arg1/arg2/load 2,
    ram/rd 3 — and each family's frame the `frame_queries` subset of them. The add/sub
    family is the first circuit built on it; S17–S19 build theirs the same way.
13. **The curve-free G1 absorption** is `transcript::g1_limbs`, and every absorber calls it.

---

## Artifacts

| Path | Size | SHA-256 | What |
| --- | --- | --- | --- |
| `crates/constraints/tests/vectors/add_sub.bin` | 68,190 bytes | `4c79713708774c2cb0c8a58504a95d43da02b9c1bb9e68f6e9c60016c2ea114b` | `add_sub::artifact` at `trace_vars` 22, the family's default height |
| `crates/loader/tests/vectors/addsub.elf` | 9,064 bytes | `587f6bd45be8f242015a8870be2b765ede1e87d94219758dc9bc996a38827145` | the tiny guest, dev profile |
| `crates/loader/tests/vectors/echo.elf` | 164,512 bytes | `aaca0ff1750df7aaf766266488690b2b29ec6067f36add46cea87323d76207a8` | refreshed, see deviation 12 |
| `crates/loader/tests/vectors/vault.elf` | 178,444 bytes | `05d3ba4f0268422244bc8b27b665c5ef00412e843702cfdff9571bcc020a00e8` | refreshed |
| `crates/loader/tests/vectors/consistency.elf` | 4,449,144 bytes | `7bdea84047995fda5f967297f7c6353e146f8bbbe7923908f9e06f884a6d4600` | refreshed |
| `tools/kat-gen/src/family.rs` | — | — | the `family` group; `cargo run -p kat-gen -- family` |

`add_sub.bin` is pinned in `crates/checker/tests/add_sub.rs`, held to its constructor by
kat-gen's own unit test, and regenerated and diffed by CI. It is this code's output, not an
oracle. What it is held to independently is §8's table, gate by gate, in
`checker/tests/add_sub.rs`, over rows built from Rust's own `u32` arithmetic.

**Proof sizes**, fixed per key and family and asserted by acceptance 1: an
`ADD_SUB_LUI_AUIPC` shard at `2^20` is **57,100 bytes** (25 transitions, 20 rounds at
layer 0, 74 base claims — 36 `M`, 31 `W`, 7 `S` — one 704-byte opening); an
`INIT_TEARDOWN` shard at `2^16` is **20,524 bytes**.

---

## Acceptance

File paths are under `crates/`. Every test listed passes. The ones marked *deferred* are
`#[ignore]`d and were run locally (see "Verification performed").

| # | Item | Where | Result |
| --- | --- | --- | --- |
| 1 | Honest twin: the guest builds, its trace passes the QEMU differential, both shards prove and verify, structural counts hold | `prover/tests/acceptance.rs::a1_the_tiny_guest_proves_and_both_shards_verify` (deferred); `emulator/tests/differential.rs` (addsub in `SUITE`); `loader/tests/qemu.rs::addsub_exits_with_its_result` | The config is exactly `{ADD 2^20, INIT 2^16, ZERO 2^16}`, the family table's 29 live rows are the image's 29 instructions, the memory log self-checks, the profile is 29 add/sub cycles. Statement: counts `[1, 1, 0]`, no windows, exit status 42, empty I/O. Proofs in statement order `(INIT, 0), (ADD, 0)`, each verifying; per transition the round count is the layer's variables and the claim count its width (×2 when halving); layer 0's claims are the committed layout; outputs are `2 + 2·channels`; byte lengths from the circuit, and the two pinned |
| 2 | A semantics cell fails as `Constraint` | `checker/tests/tamper.rs::a2_a3_a4_…` (deferred) | Row 4's (`add t2, t0, t1`) wrap bit, 1, cleared; and row 5's computed `rd` value moved by one. Each `Constraint` |
| 3 | A memory-event cell, value or timestamp, fails as `MemoryArgument` | same | A window-0 teardown value that no gate reads (the word at `RAM_ORIGIN`) moved by one; and row 3's pc read timestamp lowered from 12 to 11, its gap still in range and its multiplicities recounted. Both are pinned by the multiset alone; each `MemoryArgument`, the columns recommitted and the statement re-proved |
| 4 | A multiplicity cell fails as `Lookup` | same | Row 0's `RANGE16` multiplicity raised by one: `Lookup { RANGE16 }`. The decoder multiplicity of the first instruction's table row, 1, set to 0: `Lookup { DECODER }`. Items 2–4 are the stage gate, three classes on screen |
| 5 | Every statement twin fails as `Statement` | `prover/tests/acceptance.rs::a5_every_statement_twin_is_refused_as_statement` (deferred); `verifier-core/tests/reduce.rs` | On both shards: another identity; another output, so another public-I/O digest; another `bytecode_size_words` and another static height; the add/sub shard count raised, and a zero-window shard added with its window, commitments and roots; another SRS digest; two memory commitments swapped, and one replaced; and another input. The core's suite adds every step-1–5 reason one by one, in CI |
| 6 | One `MercuryProof`; all base claims at one point, asserted by the prover and re-derived by the verifier; the column-RLC challenge after every evaluation-claim absorb | `acceptance.rs::a6_a8_…` (deferred) | On both shards: the log holds one `MERCURY_BATCH` and one `PAIRING_MERGE` challenge, the last event, and the opening decodes as one `MercuryProof`. The GKR walk ends with one outstanding point; `opening_part` asserts the opened values are the base claims; `reduce_shard` returns a claim at a `trace_vars`-long point with layer 0's values and every committed column's commitment, and the shard verifies. After the GKR events: B1 (every commitment), B2 (the point and every claim), then B3's `ρ`. `prove_shard` returns the same bytes |
| 7 | Soundness-floor controls | `checker/tests/tamper.rs::a7_…` (deferred); `checker/tests/add_sub.rs::the_negative_controls_…` | On row 8, `add x0, t0, t1`, whose sum carries and whose write the x0 rule discards: the unreduced sum (wrap 0, computed value `a + b ≥ 2^32`, its high halfword to match) is `Lookup { RANGE16 }`; a wrap of 2 with the value `a + b − 2^33` is `Constraint`. Row 0, `lui t0`, with its mask and its kind bit cleared and its `rd` query dropped to match: `Lookup { DECODER }`. Row 4's `next_pc` written as `decoded_next_pc − 2^32` with `pc_wrap = 1`: `Lookup { RANGE16 }`. The row suite shows the unreduced sum, the `next_pc` and the all-zero mask breaking no gate, and the wrap of 2 breaking only its booleanity, in CI |
| 8 | The eq point and every layer-RLC challenge after the commitments, in spec order; ≤ 1 outstanding claim after every batch | `acceptance.rs::a6_a8_…` (deferred) | On both shards, the log event for event: seed, window, the witness commitments, `g`, `β`, then the whole GKR schedule rebuilt from the artifact's shape — the outputs, the top point (the top layer has no variables), and per transition from the top the batch, one cubic and one challenge per round, the claims and a halving transition's child challenge — and after every batch one outstanding point. The global log: every memory commitment before the four memory challenges and the digest |
| 9 | Interrupt after post-commit and post-GKR, resume, byte-identical | `acceptance.rs::a9_a_resumed_statement_is_byte_identical` (deferred) | Stopped after post-execution (nothing filled), post-commit, post-GKR **and** post-opening, each phase filled and timed exactly when reached, exported, re-imported, advanced to final: every phase's content and the deterministic payload equal the uninterrupted run's, and so do the proofs; a finished archive advanced again is unchanged |
| 10 | `ShardProof` and `VerifyingKey` round-trip; the CLI verifies the dumped files and rejects a bit-flipped copy | `acceptance.rs::a10_…` (deferred); `verifier/tests/cli.rs` (deferred); `verifier-core/tests/wire.rs` | Byte-identical round trips of both proofs, the statement and the key, each decoded proof still verifying, and `load_verifying_key` returning the key. The CLI exits 0 on the dumped key, statement and two proofs, in either order; 1 on another identity; 1 on each of five flipped bits in each proof, four in the statement and three in the key; 1 on either proof alone and on either given twice, which are not the statement's shards; 2 with no arguments |
| 11 | The harness's negative control: a harmless mutation still verifies | `tamper.rs::a11_a_cell_nothing_reads_still_verifies` (deferred) | A padding row's gap chunk (its obligation's selector is 0) and a padding row's `rd_inv` (it multiplies an address of 0) changed: both verify |
| 12 | `verify_shard`'s signature pinned | `verifier/tests/signature.rs` | `verify_shard` and `reduce_shard` coerced to `fn(&VerifyingKey, &ShardProof, &PublicInputs) -> _` at compile time |
| 13 | **As remapped by the owner** (answer 3): with `PublicInputs` honest, a RAM teardown cell changed, or `x10`'s final value changed, fails as `MemoryArgument` | `tamper.rs::a13_the_teardown_binds_the_final_values` (deferred) | A window-0 teardown value moved: `MemoryArgument` on both shards. A teardown timestamp moved: `MemoryArgument`. `v_10` moved to 43 while `exit_status` stays 42: on the add/sub shard exactly `MemoryArgument("x10's final value is not the exit status")`, step 10's comparison, and `MemoryArgument` on the init shard. The prompt's "one committed output byte" has nothing to bind: addsub writes no fd 1, and fd 1's rows are the I/O-binding stage's |

**Beyond the items**, S14's and S15's owed targets:

| What | Where |
| --- | --- |
| S14 control C8, all three: a padding row's `rd` query rewriting `x10` from 42 to 43 after the exit, with the boundary moved to match; row 5's `rd` write masked off; and the exit row storing 7 into the top stack word — each `Constraint` | `tamper.rs::the_targets_s14_left_to_s16_are_refused` (deferred) |
| The exit row rewriting its status (`a0` write ≠ read): `Constraint` | same |
| Row 27, `addi a7, x0, 93`, writing `HALT_PC`, the truncation target: `Constraint` | same |
| An image byte moved together with its teardown value, so the multiset still balances: `Opening`, the `S[0]` opening against identity's `cm(image column)` | same |
| Every gate of §8.2 the lone or first refusal of a row it exists for, or a booleanity gate refusing 2 | `checker/tests/add_sub.rs` |
| Every row kind — each sum with and without carry, each difference with and without borrow, an `x0` destination computing a nonzero value it discards, an `x0` operand, a two-byte instruction, a fence, the exit, the padding row — satisfying every gate and bound | same |
| The circuit passing the laws, both padding clauses, `check_memory` and both discharge checks through both enforcement points | same |
| The G1 absorption over bytes, and `pcs`'s arkworks vectors through it | `transcript/tests/g1.rs`, `pcs/tests/kats.rs` |
| The global transcript event for event; each statement field moving the digest but the roots and the exit status, which do not (the exit status is bound at step 10); the shard seed's parts moving `g` | `verifier-core/tests/reduce.rs` |
| 2,000 garbage statements and proofs refused with no panic; every truncation of every type refused | `verifier-core/tests/reduce.rs`, `wire.rs` |
| One-thread and all-thread proofs byte-identical | `acceptance.rs::the_proofs_do_not_depend_on_the_thread_count` (deferred) |

---

## Must-be-exact, item by item

1. **The pre-fork order** is `global_commit`, implemented once and called by both sides. It
   matches the master's list as S14 amended it, with one addition: a `MEMORY_GROUP
   [family, count]` header before each family's commitments, which is the list's
   "domain-separated … length-delimited".
2. **Seeding**: `GLOBAL_STATE_DIGEST` (38) is a `challenge_scalar` after the memory
   challenges; `SHARD_SEED` (39) carries `[digest, family, index]` as one message into a
   fresh transcript; `SHARD_TS_WINDOW` (40) follows immediately. The window lives in the
   `ShardProof` and step 4 holds it to the trivial one.
3. **One opening**, at the one point GKR leaves, with Mercury's `u1` first; `ρ` after
   every claim; only committed columns are opened, and virtual columns are evaluated in
   closed form by `gkr_verify::verify`. No merge sumcheck (answer 6).
4. **Fixed shape**, no optional section, no accumulator entry. Step 6 holds every length
   to the circuit.
5. **The key** carries `VmConfig`, identity, the `SrsVerifier` and its digest, and the full
   artifacts in S13's schema, plus each family's channel specs, which an artifact does not
   record.
6. **The soundness floor**: `rd`'s computed value and `next_pc` are each 16+16
   range-checked; `wrap`, `pc_wrap`, the six kinds, `is_ecall` and `is_fence` each have a
   booleanity gate; one-hotness is the decoder table's domain. The `next_pc` formula is
   answer 5's.
7. **Snapshots** are the archive's four later sections, in §9's encodings, with S02's
   226-byte sponge snapshot and S12's timing fields; resume is `import` + `advance`.
8. **One path**: the CLI, every test and `TamperHarness` call `verify_shard`.
9. **Blind cells**: acceptance 3 targets a teardown value and a read timestamp, which no
   row gate reads and only the memory argument pins, and acceptance 4 two multiplicities,
   pinned only by their channels.
10. **`prove_shard` is shard-local**; `global_commit_phase` is separate and public.
11. **`ProvingContext`** holds the setup (key, registrations, SRS) and the global state,
    and nothing per shard.
12. **`global_commit_phase` is shard-count generic**: it takes every shard's memory columns
    in statement order and commits them in parallel, in order.

---

## Deviations and notes for the reviewer

1. **No curve-free Mercury field-side module** (answer 1). The core stops at the opening
   claim, and `verifier` spends it with `pcs::batch_verify`. S26 owes the field-side half
   and `cm*`.
2. **No claim-merge sumcheck** (answer 6), recorded in `docs/spec/shard-proof.md` §5.3 and
   `docs/spec/gkr.md` §5.
3. **The SRS digest binds the verifier points, and the points themselves are presumed.**
   Found while writing the docs. Identity binds the setup commitments, not the SRS they
   were computed over, and `VerifyingKey::check` recomputes the SRS digest from the key's
   own points. So a key file whose `SrsVerifier` is replaced by points for a `tau` someone
   knows, with the digest recomputed, loads and matches the true identity. Whoever knows
   that `tau` can then open any commitment to any value. This is `docs/spec/srs.md` §4's
   standing presumption, narrowed and not removed: the S16 digest makes a proof specific
   to one set of verifier points, but does not show that those points are the
   ceremony's. The verifier needs the ceremony's `SrsVerifier`, or its digest, from a
   trusted channel, as it needs identity. **The `verifier` CLI does not yet take one**:
   it trusts the key file's points. `docs/spec/shard-proof.md` §7.2 and the root
   `CLAUDE.md` state this. It is **open for the owner**. The cheapest fix is a second
   trusted CLI argument, the expected SRS digest, compared at load; the alternative is to
   bind the SRS digest into identity, which changes S11's frozen recipe and every
   identity pin.
4. **EXIT only** (answer 3). The family's gate holds every ecall row's `a7` to 93, so no
   `is-zero` gadget exists yet; `arg1`, `arg2` and `ram` are masked off on every row. The
   fill refuses a transfer cycle or another ecall by name.
5. **Acceptance 13 remapped** (answer 3), as the table says.
6. **The `next_pc` formula** (answer 5).
7. **The generic table's binding is S17's** (answer 8). `docs/spec/lookup.md` §13 records
   the owner's words.
8. **`DEFAULT_HEIGHTS[ATOMICS]`** stays `2^16` (answer 7).
9. **`trace::check_multiplicities` is not on the proving path.** S15 listed it as S16's.
   The prover builds every multiplicity column with `trace::build_multiplicities` and
   nothing else, so the check would recount the build it just ran. A multiplicity from
   any other source — the harness's — is refused by the verifier as `Lookup`, which
   acceptance 4 shows. **`check_copowers` is not called either**: the add/sub family
   scales nothing by a copower, so the call would check an empty list. S17 and S18, the
   first families that scale, call it where their keys load.
10. **`VerifyError` has a sixth class, `Malformed`**, between `Statement` and `Constraint`:
    a proof whose shape is not the circuit's (step 6). The prompt asks for "at least" the
    five.
11. **`TamperHarness` takes a `ProverSetup` and an archive, not a `ProvingContext`.** A
    memory-cell or boundary tamper changes the statement, so the global commit phase runs
    again and the honest context cannot be reused. The harness keeps the honest global
    state and honest proofs whenever a tamper touches neither, and re-proves only the
    shards it names.
12. **Three guest ELFs were refreshed.** `kat-gen -- guests` rebuilds every guest, and
    adding `guests/addsub` changed `guests/Cargo.lock`, which moved crate metadata hashes
    and so symbol order and a few bytes in `echo`, `vault` and `consistency`. Their pins
    in `loader/tests/common/mod.rs` are updated; nothing derived from them moved — none
    of the three has a loader listing (only fib, rvc-dense and amm do). S12 did the
    same.
13. **Acceptance 11 edits padding-row cells, not "an unused scratch slot".** A scratch
    slot is not committed, and a lawful circuit has no committed column no gate reads.
    What a verifier cannot see is a cell whose reading is switched off on its row, and
    the test edits two of those.
14. **The fence's code is 2**, S11's `system_code::FENCE`, and `fence_code` holds it:
    `is_fence·(imm − 2)`. `ebreak` (code 1) satisfies neither `ecall_code` nor
    `fence_code`, so no row can be an `ebreak`, which the execution trace already treats
    as fatal.
15. **The prover's GKR replay.** `gkr_part` reads the base claims' point back by replaying
    `docs/spec/gkr.md` §5.2 over its own proof with no checks, and asserts the replay ends
    in its own transcript state. The first version called `gkr::verify` for the point,
    which panicked on every tampered witness; a prover must not check.
16. **`ProgramIdentity`, `VmConfig`, `absorb_statement_descriptor`, `check_memory_windows`
    and the identity digest moved** into `verifier-core` (answer 1). `program` re-exports
    the first three unchanged, wraps `check_memory_windows` into `WindowRule`, and
    `identity_from_commitments` encodes its points and calls `identity_digest`. The
    recipe did not change a byte, and the identity pin is unmoved.

---

## What the adversarial review changed

Six read-only reviewers — the circuit's soundness, the verifier, the prover, the tests
and the harness, spec-against-code, and the docs — each followed by a skeptic told to
refute every finding. 44 findings; 35 survived, several reported twice.

- **Critical: the `verifier` CLI accepted a subset of a statement's shards.** It exited 0
  when every proof it was given verified, so the init shard's proof alone "verified" the
  statement and the add/sub shard's circuit was never checked: one shard's
  reconciliation reads the roots the statement *claims* for the others. The CLI now
  requires the proofs to be exactly `statement_shards`, each once in any order;
  `docs/spec/shard-proof.md` §6 states the rule, and `tests/cli.rs` refuses each proof
  alone and each given twice.
- **The tamper harness recounted all channels or none**, and compared a `Lookup` refusal
  by variant alone. So acceptance 7's all-zero-mask twin — whose decoder tuple no table
  holds — left the timestamp and `RANGE16` counts stale too, and was refused by the
  *timestamp* channel while the test said "decoder". The recount is now per channel, and
  `assert_rejects` requires a `Lookup`'s channel; every lookup twin now names its channel
  and gets it.
- **Tests that claimed more than they checked**: `is_fence_boolean` was never broken; the
  key's reader was never truncated and its flips were sampled; the SRS digest was moved at
  five bytes of 320; acceptance 8 walked batches and claims, not rounds; the a13 timestamp
  twin targeted one shard; a digest assertion was `… || true` (clippy's catch). Each now
  checks what its doc says — the key truncated at every header length, one bit of every
  header byte flipped and refused, all 320 SRS bytes, and the GKR schedule rebuilt from the
  artifact's shape and compared event for event.
- **`advance(.., PostExecution)` proved the whole statement.** It now returns at once,
  and acceptance 9 stops there too.
- **Spec against code**: §10's `PostCommit` and `Final` layouts now show the `bytes`
  length prefix the prover writes before the embedded `PublicInputs`; §8.2 says "degree at
  most 2"; §7.2 no longer claims steps 1–5 catch an in-memory edit inside a circuit;
  `global_commit`'s doc and the core's test table say the exit status is not absorbed
  (step 10 binds it); `PROTOCOL_SUITE`'s doc names the transcript it opens.
- **Docs**: `TABLE_WIDTH` is a `usize`, and the channel counts are asserted at
  construction, not by a `const`; step 10 re-checks timestamps only (values are `u32` by
  type); the toy SRS cache is `target/tmp`, shared by three suites; deviation 12 and the
  normative-documents list above corrected.

**Refuted**, with the reason kept: acceptance 13's `x10` twin being a comparison of two
statement fields (it is the owner's remap, stated as such); acceptance 11 not exercising
the recommit branch (it does not claim to); "the SRS digest is absorbed third" (the
master counts the suite tag and the version as two items); §8's `trace_vars ≥ 20` against
a registry that accepts 19 (§8 states provable heights); `advance` not re-checking an
imported archive (the prover checks nothing, by the frozen rule); the two
`window_height` refusals being untested at step 2 (a loaded key cannot carry them);
tests calling `reduce_shard` (it is the first eleven steps of `verify_shard`, not a second
path); two wording nits.

---

## Mutation testing

Four agents, each in its own worktree at the first S16 commit, made one semantic edit at a
time to the new code — a check removed or weakened, a constant or a gate term changed, a
transcript message dropped or moved — ran the suites named for it, and reverted. The
proof-level group ran the deferred suites one mutant at a time.

| Group | Mutants | Caught | Survived |
| --- | --- | --- | --- |
| `verifier-core` (steps 1–6, the key's load rules, the readers, the transcripts) | 54 | 43 | 11 |
| the add/sub circuit, against the row suite with its fixture and name pins skipped | 57 | 43 | 14 |
| the G1 absorption, the archive, the `SrsVerifier` codec, `program`'s wrappers, tags | 17 | 12 | 5 |
| steps 7–12, the fill and the harness, against the deferred suites | 11 | 7 | 4 |
| **all** | **139** | **105** | **34** |

**15 survivors were test gaps, and each is closed by a test that now kills it** (re-run
against the mutant):

- **Step 10's root comparison** — the one link between the roots a shard's proof
  establishes and the roots reconciliation multiplies. Without it a statement whose
  root pair is scaled by a constant verifies on every shard; the harness always built the
  statement from the proofs, so nothing had tried. `acceptance.rs` now has that statement,
  refused by exactly that check on the init shard and accepted by the add/sub shard.
- **Four circuit rows** the row suite lacked: a padding row claiming a kind bit and
  rewriting `x10` (the mask rules' `m_pc` factor), a padding row storing into RAM, an
  unreduced `addi` and `sub` (the range check on every kind, not only add), and a
  `next_pc` past 32 bits whose high halfword is solved in the field.
- **The window constant of a `ZERO_WINDOWS` shard** — no suite at any speed built one —
  and which squeeze is `g` and which `β`.
- **A boundary scalar wider than 64 bits** with in-range low bytes, which the reader had
  refused untested; a key one setup list short in memory; a boundary timestamp past the
  clock reaching step 10 in memory.
- **The `SrsVerifier` codec**: its test used one point for both G2 fields, so a swapped
  offset passed, and never flipped a bit in a G2 point.
- **Infrastructure**: `content(PostExecution)` panicking; the post-commit, post-GKR and
  final snapshot sections refusing trailing bytes (`decode_final` extracted to test it);
  the harness's class comparison.

**16 are equivalent or redundant**, each with the reason in the agent's report: step 6's
output-width check and `gkr_verify::verify`'s own (each masks the other); two dead error
arms for a loaded key; the key load's `validate`, `check_memory` and `check_discharge`
after byte equality with a registry circuit the constructor already checked (kept, as
§7.2 says, on purpose); the key's canonical re-encode after canonical sub-decoders;
step 8, which `gkr_verify::verify` makes true by construction; a gate scaled by 2; four
gate edits that only add constraints on cells no memory event reads, or restate what the
memory argument already forces; two channel relabelings the prover and verifier follow
together.

**3 are caught only by the deferred suites**: the decoder lookup's selector moved to one
kind bit, the decoder tuple reordered (the honest prover cannot count it), and `advance`
missing its post-GKR stop.

---

## Deferred work, by stage

**S17 (the jump/branch/slt family, the first generic-channel consumer).**
- **Bind the packed generic table** — the owner's answer 8, verbatim in
  `docs/spec/lookup.md` §13.
- `check_copowers` at key load, over the family's scaled columns.
- `jalr`'s bit-0 clear and every jump's and branch's wrap bit (`docs/spec/memory.md` §5),
  and the family's own mask rules (§2.1).

**S18 / S19.**
- The memory families' byte-address constraints (`docs/spec/memory.md` §9).
- `DEFAULT_HEIGHTS[ATOMICS]` to `2^20` or above, with the atomics circuit (answer 7).

**The I/O-binding stage.**
- `read`, `write`, `PRECOMPILE_POSEIDON2`, `-EBADF`, `-ENOSYS`, transfer rows and
  `is_transfer`, and the `is-zero` gadget over `a7` that tells them apart.
- Tying fd 0 and fd 1 to the execution. At S16 the public I/O digest is in the statement
  and no row reads it.

**S20.** Non-trivial time windows (the field exists; step 4 refuses any value but the
trivial one), many shards per family, and aggregation.

**S26.** The Mercury field-side module and `cm*`; linking `verifier-core` into the guest.
CI already builds the core for `riscv32imac`.

**Open for the owner now.** Deviation 3: how a verifier obtains the ceremony's
`SrsVerifier`.

---

## Open for the next stage

- **`transcript_tags` has 40 entries.** Append, never renumber, never reuse a tag across
  kinds.
- **A new family is one arm and one fill.** `constraints::family_circuit` and
  `prover::family_fill`. `crates/checker/tests/add_sub.rs` is the model for its CI suite:
  rows built by hand, every gate the lone refusal of a row it exists for, no forward pass.
- **Every execution family is at least `2^20` rows**, and a statement's proof peaks at
  8.6 GB at that height. Run a proving suite with `--test-threads=1`.
- **The prover checks nothing.** A fill may refuse a trace it cannot prove, by name; it
  must not refuse a witness because a gate fails. The harness depends on that.

---

## Verification performed

On macOS (18 cores, 48 GB), every gate the root `CLAUDE.md` lists, at the final tree:

- `fmt --check` in all four workspaces, and `clippy -D warnings` in all four;
- `cargo test --workspace`: **796 passed, 44 `#[ignore]`d** (761 and 30 at S15). The 35
  new tests that run in CI: `verifier-core` — `tests/wire.rs` 5, `tests/reduce.rs` 7, unit
  4; `verifier` — `tests/signature.rs` 2, unit 1; `checker` — `tests/add_sub.rs` 7, unit 1;
  `prover` unit 2; `transcript/tests/g1.rs` 2; `trace`'s archive unit tests 2; one each in
  `constraints::add_sub`'s unit tests and in `kat-gen`'s `family` group. The 14 new ignored
  ones are the three deferred suites below and `loader/tests/qemu.rs`' addsub case;
- the `riscv32imac` build of `field`, `constants`, `transcript`, `poly`, `sumcheck`,
  `constraints`, `gkr-verify` **and `verifier-core`**, which CI now builds too;
- `cargo run -p kat-gen`, then the fixture diff: `add_sub.bin` regenerates byte for byte
  and nothing else moves; `transcript-ref` with no diff; fib's guest build;
- the QEMU suites in the colima container (`rust` on aarch64 Linux with `qemu-user`, its
  own `CARGO_TARGET_DIR`, every guest built from source): `loader --test qemu` 9 passed at
  both profiles, `emulator --test differential` 3 passed — addsub among its guests — and
  `emulator --test consistency` 8 passed at both profiles;
- `cargo test --release -p program --test identity -- --ignored`, on the PSE ceremony: 6
  passed, 73 s. **The identity pins did not move** through the move of the digest into
  `verifier-core`;
- S15's deferred `checker --test logup`: 9 passed, 203 s — S16 wires its channels.

**The three deferred suites**, `--include-ignored --test-threads=1`, on the final tree:

| Suite | Result | Wall | Peak resident |
| --- | --- | --- | --- |
| `prover --test acceptance` | 7 passed | 322 s | 8.64 GB |
| `verifier --test cli` | 1 passed | 20 s | 8.56 GB |
| `checker --test tamper` | 5 passed | 509 s | 9.25 GB |

They are commented out of `.github/workflows/ci.yml` under `# DEFERRED:` lines, master
rule 7: the add/sub shard cannot be smaller than `2^20` rows, and at the logup step's
measured nine-fold runner slowdown they would take about 50, 3 and 75 minutes there.

**Measurements**, one statement (`guests/addsub`, add/sub at `2^20`, the two window
families at `2^16`, the toy SRS of `2^20` points): the global commit phase 1.8 s, the two
shards' GKR 11.7 s, their openings 4.2 s — about 20 s end to end on 18 cores, of which
the forward pass and the layer sumchecks are most. A tamper twin re-proves in about 16 s.
The add/sub circuit is 25 transitions deep, layer 1 is 68 columns wide, and its artifact
builds in about 2 ms.
