# `crates/verifier-core`

## What this crate owns
Everything a shard's verification does except its one Mercury opening, `#![no_std]` +
`alloc`, because the recursion guest links it and re-implementation is forbidden (S16).
**`docs/spec/shard-proof.md` is normative**, and this crate is its §1–§7 and §9.

- **Statement binding.** The static `VmConfig` and its frozen wire form, the statement
  descriptor, the RAM window rules and the identity digest — S11's and S14's, moved here
  from `crates/program` at S16 so the prover and the verifier bind a statement with one
  implementation; `program` re-exports or wraps each, and every old path still resolves.
  The SRS digest. The statement's shard order and the global transcript.
- **The shard transcript** and its external challenges.
- **`reduce_shard`**: the eleven steps of §6 that end at the opening claim, reachable
  since S20 in three public parts, split by what each reads — `derive_global_phase`
  (steps 1–3 and the global transcript) and `verify_global_memory` (step 10b, the
  boundary and the cross-shard root product) read the statement and run **once** for
  it; `verify_shard_local` (steps 4–10a and 11) is the only one that reads a
  `ShardProof`, and is the only one a block runs per shard.
- **The block** (S20, `docs/spec/block-proof.md`): `BlockProof`, `ShardRecord`,
  `BlockReconciliation`, their wire forms, the structural rule a decoded block keeps, and
  `check_ts_windows`.
- **The proof-side types**: `PublicInputs`, `ShardProof`, `VerifyingKey`, `VerifyError`,
  `OpeningClaim`, their byte layouts, and a key's load rules.

```rust
pub struct VmConfig { pub families: Vec<(u32, u32)>, pub bytecode_size_words: u32 }
impl VmConfig { pub fn height(&self, f: u32) -> Option<u32>; pub fn to_bytes(&self) -> Vec<u8>;
                pub fn from_bytes(b: &[u8]) -> Option<VmConfig>; }
pub fn window_height(config: &VmConfig) -> Result<u32, &'static str>;
pub fn absorb_statement_descriptor(tr: &mut Transcript, config: &VmConfig, shard_counts: &[u32], windows: &[u32]);
pub fn check_memory_windows(config: &VmConfig, shard_counts: &[u32], windows: &[u32]) -> Result<(), &'static str>;
pub struct ProgramIdentity(pub Fr);                        // to_bytes, from_bytes
pub fn identity_digest(code_version: u32, config: &VmConfig, entry_pc: u32,
                       commitments: &[Vec<[u8; 64]>]) -> ProgramIdentity;
pub fn srs_digest(verifier: &[u8; 320], generic_table: &[[u8; 64]; 3]) -> Fr;   // S17: the table too
pub const TRIVIAL_TS_WINDOW: [u64; 2];                     // [0, 2^38)
pub fn statement_shards(config: &VmConfig, shard_counts: &[u32]) -> Vec<(u32, u32)>;
pub fn boundary_scalars(finals: &BoundaryFinals) -> Vec<Fr>;
pub struct GlobalTranscript { pub transcript: Transcript, pub memory: [Fr; 4], pub digest: Fr }
pub fn global_commit(vk: &VerifyingKey, statement: &PublicInputs) -> GlobalTranscript;
pub fn shard_transcript(digest: Fr, family: u32, index: u32, ts_window: [u64; 2],
                        witness_commitments: &[[u8; 64]]) -> (Transcript, Fr, Fr);   // (t, g, β)
pub fn memory_slots(memory: &[Fr; 4]) -> ExternalChallenges;
pub fn shard_challenges(circuit: &FamilyCircuit, index: u32, windows: &[u32], memory: &[Fr; 4],
                        g: Fr, beta: Fr) -> ExternalChallenges;

pub enum VerifyError { Statement(&'static str), Malformed(&'static str), Constraint { layer: usize },
                       Lookup { channel: u32 }, MemoryArgument(&'static str), Opening }   // + Display
pub struct PublicInputs { input, output, exit_status, shard_counts, windows, boundary,
                          memory_commitments: Vec<Vec<[u8; 64]>>, memory_roots: Vec<[Fr; 2]> }
pub struct ShardProof { family, shard_index, ts_window: [u64; 2], global_digest: Fr,
                        witness_commitments: Vec<[u8; 64]>, outputs: Vec<Fr>, gkr: GkrProof,
                        opening: [u8; 704] }
pub struct VerifyingKey { code_version, config, entry_pc, identity, setup_commitments,
                          srs_verifier: [u8; 320],
                          generic_table: [[u8; 64]; 3],   // S17, in every key; 3 = generic_table::WIDTH
                          srs_digest: Fr, circuits: Vec<FamilyCircuit> }
impl VerifyingKey { pub fn circuit(&self, f: u32) -> Option<&FamilyCircuit>; pub fn check(&self) -> Result<(), String>; }
// PublicInputs, ShardProof, VerifyingKey: to_bytes, from_bytes
pub struct OpeningClaim { pub commitments: Vec<[u8; 64]>, pub point: Vec<Fr>, pub values: Vec<Fr>,
                          pub transcript: Transcript }
pub fn reduce_shard(vk: &VerifyingKey, proof: &ShardProof, public: &PublicInputs)
    -> Result<OpeningClaim, VerifyError>;
// S20, docs/spec/block-proof.md
pub struct GlobalChallenges { pub memory: [Fr; 4], pub digest: Fr }
pub fn derive_global_phase(vk: &VerifyingKey, public: &PublicInputs)
    -> Result<GlobalChallenges, VerifyError>;                       // steps 1-3 and G1-G11
pub fn verify_global_memory(vk: &VerifyingKey, global: &GlobalChallenges,
                            public: &PublicInputs) -> Result<(), VerifyError>;   // step 10b
pub fn verify_shard_local(vk: &VerifyingKey, global: &GlobalChallenges, proof: &ShardProof,
                          public: &PublicInputs) -> Result<OpeningClaim, VerifyError>;  // 4-10a, 11
pub struct ShardRecord { pub family: u32, pub shard_index: u32, pub ts_window: [u64; 2],
                         pub memory_commitments: Vec<[u8; 64]>, pub roots: [Fr; 2] }
pub struct BlockReconciliation { pub records: Vec<ShardRecord> }    // to_bytes, from_bytes
pub struct BlockProof { pub config: VmConfig, pub statement: PublicInputs,
                        pub shards: Vec<ShardProof> }
impl BlockProof { pub fn config(&self) -> &VmConfig; pub fn shard_counts(&self) -> &[u32];
                  pub fn shard_count(&self, family: u32) -> u32;
                  pub fn statement(&self) -> &PublicInputs;
                  pub fn shard_proofs(&self) -> &[ShardProof];
                  pub fn reconciliation(&self) -> BlockReconciliation;
                  pub fn shape(&self) -> Result<(), &'static str>;
                  pub fn to_bytes(&self) -> Vec<u8>; pub fn from_bytes(&[u8]) -> Result<Self, _>; }
pub fn check_ts_windows(records: &[ShardRecord]) -> Result<(), &'static str>;
pub fn write_gkr(w: &mut Writer, gkr: &GkrProof);  pub fn read_gkr(r: &mut Reader) -> Read<GkrProof>;
pub mod wire { pub struct Writer; pub struct Reader; pub type Read<T>; }   // §9's primitives
pub const OPENING_BYTES: usize = 704;  pub const SRS_VERIFIER_BYTES: usize = 320;
```

## Frozen invariants
- **The check order is the class.** `reduce_shard` runs `docs/spec/shard-proof.md` §6's
  steps in order and returns the first failure: `Statement` (1–5), `Malformed` (6),
  `Constraint` (7–8), `Lookup` (9), `MemoryArgument` (10a, 10b). `verifier::verify_shard`
  adds `Opening` (12). A prover that proves a tampered witness honestly is refused by the
  class of what the tamper broke, which is what `checker::TamperHarness` asserts. S20's
  three-part split does not move a step: `reduce_shard` calls `verify_global_memory`
  after `verify_shard_local` returns, and step 11, the only step between 10a and 10b,
  builds the opening claim and cannot fail — so the first failure, its class and its
  message are S16's for every input.
- **Step 10b is once per statement, and `verify_shard_local` is not a verification.**
  The memory argument's statement half names no `ShardProof`: its operands are
  `vk.entry_pc`, `public.boundary`, `public.memory_roots` and the four memory
  challenges. Running it per shard recomputes one boolean `Σ shard_counts` times — 66
  boundary tuples folded and one root product — for the same answer. A block-level
  caller owes exactly one call, and one that omits it has checked every circuit and no
  memory argument. What binds a shard into the product is step 10a's `own !=
  public.memory_roots[position]`, which stays per shard and must.
- **Nothing a proof or public inputs carry makes it panic.** Steps 1–4 check the statement
  against the key before anything is indexed, and the total shard count is bounded before
  anything is built from it. The key is assumed loaded (`VerifyingKey::check`); a key edited
  in memory meets steps 1–5 as `Statement` only where its config or its circuit list
  changed, and an edit inside a circuit is not caught there.
- **Curve-free.** A `G1` point is its 64 canonical bytes, absorbed through
  `transcript::append_g1_points` (all-zero is infinity) and never decoded here: validating
  a point is `crates/verifier`'s. The Mercury proof is 704 opaque bytes. **`pcs` is not
  split** (the owner's decision, S16): the Mercury field-side module and the `cm*` question
  S09 left open are the recursion stage's.
- **One statement, many shards.** A statement is proven when every one of its shards'
  proofs verifies against one `PublicInputs`: a shard checks the memory argument's
  reconciliation over roots the other shards' proofs establish.
- **The global transcript is §2's G1–G11, implemented once** (`global_commit`), called by
  the prover's global commit phase and by `reduce_shard`. It has no step for the generic
  table: since S17 the table's commitments are inside the SRS digest, which G2 absorbs.
  `memory_roots` are not absorbed: they are computed after the challenges, and each is
  bound by its own shard's GKR proof, which step 10a compares with the statement.
- **The SRS digest is §3's recipe** (`srs_digest`): a fresh transcript absorbs the
  320-byte `SrsVerifier` as one `SRS_VERIFIER` (35) bytes message, then, since S17, the
  key's three generic-table points as one `GENERIC_TABLE` (41) message of twelve limbs, and
  the digest is one raw `sample()`. Tag 41 is absorbed in this sponge and nowhere else.
  S17 amended S16's frozen spec in two places: §3 gained the second message, and §9's key
  layout gained the three points, 192 raw bytes with no count, between the `SrsVerifier`
  and the digest. Every S16 key's bytes and SRS digest changed.
- **A key's load is §7.2**, `VerifyingKey::check`: its config derivable, its code version
  `CODE_VERSION`, one setup list per config family, its identity the digest of its setup
  commitments, its SRS digest the digest of its `SrsVerifier` and its generic table, and
  its circuits **byte for byte** `constraints::family_circuit(family, trace_vars)` — the
  circuits are protocol constants given a family and a height, and identity binds the
  program, not the circuit — plus `validate`, `check_memory` and `check_discharge` at
  every load. Per family, the setup list's length plus 3 where the circuit reads the
  `GENERIC` channel (`FamilyCircuit::reads_generic_table`) is the artifact's `S` width.
  Since S17 every key carries **one `generic_table`**, the packed table's three points,
  whatever its families read. They are not in identity. A loaded key's digest agrees with
  its own points and says nothing about whether they are the ceremony's, so a verifier
  takes the digest from a trusted channel (§3). One further check guards the registry
  rather than keys: every `GENERIC` channel spec names exactly the three setup columns
  right after identity's. No key whose circuits are the registry's can fail it;
  `prover::ProverSetup::new` runs `check`, so a later registry entry that broke it would
  fail when its key is built. `from_bytes` refuses a non-canonical encoding; the key's
  curve points are decoded by `verifier::load_verifying_key`, not here.
- **The opening's commitments are `M`, `W`, then `S`** (step 11): the statement's memory
  commitments for the shard, the proof's witness commitments, then
  `vk.setup_commitments[family]` followed, where the circuit reads the generic channel, by
  `vk.generic_table` (S17). That is the circuit's layout order: the jump family's shard
  opens 21 + 44 + 10 commitments, the last three the table's.
- **Every decoder is total** (`wire::Reader`): a count is refused unless the bytes left
  could hold it, a field element at or above `p` is refused, trailing bytes are refused,
  and a boundary scalar out of range — a timestamp at or above `2^38`, a value at or above
  `2^32` — is refused by `PublicInputs::from_bytes`; step 10b re-checks the timestamps, a
  value being a `u32` in `BoundaryFinals` by type.
- **The time window is the shard's own** (S20). Step 4 holds it to `start <= end <= 2^38`
  and nothing more; the block's rule — non-empty, ordered and pairwise disjoint within
  each **cycle-owning** family (`constants::family::CYCLE_OWNING`), and no rule at all
  for a family whose rows are not cycles — is `check_ts_windows`, which needs every
  shard and so is `verify_block`'s. **A window is a claim about the plan and not about
  the trace**: no gate ties it to the rows committed under it (the owner's S20 decision,
  `docs/spec/block-proof.md` §4.1), and cross-shard ordering, cycle uniqueness and pc
  continuity are carried by the global memory multiset alone (`docs/spec/memory.md`
  §4.2). What it *is* bound to is the shard transcript, which absorbs it at S2 before
  the witness commitments. At S16 it was the trivial `[0, 2^38)` and step 4 refused any
  other.
- **A block carries the statement it binds, and one proof per statement shard in
  statement order.** `BlockProof::from_bytes` runs `shape()` before it returns — one
  count per config family, the counts' total equal to the number of proofs, commitment
  lists and root pairs, and the proofs naming `statement_shards` in its order — so a
  decoded block's public-data API is total. `reconciliation()` panics on a block built in
  memory that breaks it, as `statement_shards` does on counts that are not its config's.
  The descriptor is carried rather than only read from the key because it is public data
  of the proof (G3 and G4); `verify_block` holds both copies to the verifier's.
- **`#![no_std]` + `alloc`, forever.** CI builds it for `riscv32imac-unknown-none-elf`.

## Tests
| File | Covers |
| --- | --- |
| `src/statement.rs` (unit) | the statement order puts the init families first; the window height and its two refusals; the boundary scalars' order; the trivial window |
| `tests/wire.rs` | every type round-trips byte for byte, S16's key and one with S17's family among them; §9's layouts read back field by field — the proof's, the statement's, and the key's through its first circuit's artifact, S17's family key with its three generic-table points raw between its `SrsVerifier` and its SRS digest; the statement's and the proof's readers refuse truncation at every length, each key's at every length before its circuits and at one in 97 after, and all three a trailing byte; an overlong count, a field element at the modulus and each out-of-range boundary scalar refused, one wider than 64 bits with in-range low bytes among them; each key with one bit flipped — one bit of every byte before its circuits, every bit of one circuit byte in 1009, and every one of the generic table's 1,536 bits, each of those refused with the SRS digest's message — refused, never loaded and never a panic; each of §7.2's load rules but the registry's own order check, which no key can trip, refuses its edited key, by name, in memory and from bytes — S17's among them: a generic-table byte flipped and two of its points swapped, each refused by the SRS digest, and the jump family's setup list at 10 or at 6, each refused by the setup-count rule; the SRS digest is the documented recipe, its second message the table's twelve limbs, and moves with each of the `SrsVerifier`'s 320 bytes and each of the table's 192 |
| `tests/block.rs` | S20: the record list is statement order and each record is §2's layout read off the statement and the shard's own proof; the public data — descriptor, counts, a detached family's 0, the proofs, the reconciliation — through the wire form alone; every way a block's statement and proofs can be different shard sets refused at decode, by name; the reader refused a trailing byte, every truncation and a `VmConfig` no derivation produces; `BlockReconciliation`'s layout field by field over one record, and its reader the same way; the window rule per cycle-owning family, with the init family's trivial window inside add/sub's and exempt |
| `tests/reduce.rs` | the global transcript event for event, G1–G11 and nothing else; S17's generic table bound through the SRS digest: a key with S17's family has S16's schedule and no `GENERIC_TABLE` message, the statement's digest moves with each of the table's points and with their order once the key's SRS digest is recomputed over them, and a key whose table moved without it does not load; every statement field but the roots and the exit status moving the digest, and those two not — the exit status is bound at step 10; the key's SRS digest and identity each moving it; the shard transcript's first five events and every part of its seed moving `g`; `g` and `β` the first and second `LOOKUP_CHALLENGE` squeezes of a transcript replayed by hand; each shard's challenges — the window constant at `INIT_TEARDOWN`'s window 0 and at each `ZERO_WINDOWS` shard's own window, none for an execution family, and the memory and LogUp slots; each of steps 1–5's refusals as `Statement`, by reason, a key one setup list short among them; each of step 6's as `Malformed`; two thousand garbage statements and proofs refused with no panic |

The proofs themselves are `crates/prover/tests/acceptance.rs`,
`crates/prover/tests/control.rs` and `crates/checker/tests/tamper.rs`, `#[ignore]`d for
size.
