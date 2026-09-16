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
- **`reduce_shard`**: the eleven steps of §6 that end at the opening claim.
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
pub fn srs_digest(verifier: &[u8; 320]) -> Fr;
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
                          srs_verifier: [u8; 320], srs_digest: Fr, circuits: Vec<FamilyCircuit> }
impl VerifyingKey { pub fn circuit(&self, f: u32) -> Option<&FamilyCircuit>; pub fn check(&self) -> Result<(), String>; }
// PublicInputs, ShardProof, VerifyingKey: to_bytes, from_bytes
pub struct OpeningClaim { pub commitments: Vec<[u8; 64]>, pub point: Vec<Fr>, pub values: Vec<Fr>,
                          pub transcript: Transcript }
pub fn reduce_shard(vk: &VerifyingKey, proof: &ShardProof, public: &PublicInputs)
    -> Result<OpeningClaim, VerifyError>;
pub fn write_gkr(w: &mut Writer, gkr: &GkrProof);  pub fn read_gkr(r: &mut Reader) -> Read<GkrProof>;
pub mod wire { pub struct Writer; pub struct Reader; pub type Read<T>; }   // §9's primitives
pub const OPENING_BYTES: usize = 704;  pub const SRS_VERIFIER_BYTES: usize = 320;
```

## Frozen invariants
- **The check order is the class.** `reduce_shard` runs `docs/spec/shard-proof.md` §6's
  steps in order and returns the first failure: `Statement` (1–5), `Malformed` (6),
  `Constraint` (7–8), `Lookup` (9), `MemoryArgument` (10). `verifier::verify_shard` adds
  `Opening` (12). A prover that proves a tampered witness honestly is refused by the class
  of what the tamper broke, which is what `checker::TamperHarness` asserts.
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
  the prover's global commit phase and by `reduce_shard`. `memory_roots` are not absorbed:
  they are computed after the challenges, and each is bound by its own shard's GKR proof,
  which step 10 compares with the statement.
- **A key's load is §7.2**, `VerifyingKey::check`: its config derivable, its code version
  `CODE_VERSION`, its identity the digest of its setup commitments, its SRS digest the
  digest of its `SrsVerifier`, and its circuits **byte for byte**
  `constraints::family_circuit(family, trace_vars)` — the circuits are protocol constants
  given a family and a height, and identity binds the program, not the circuit — plus
  `validate`, `check_memory` and `check_discharge` at every load, and every setup list its
  artifact's `S` width. `from_bytes` refuses a non-canonical encoding.
- **Every decoder is total** (`wire::Reader`): a count is refused unless the bytes left
  could hold it, a field element at or above `p` is refused, trailing bytes are refused,
  and a boundary scalar out of range — a timestamp at or above `2^38`, a value at or above
  `2^32` — is refused by `PublicInputs::from_bytes`; step 10 re-checks the timestamps, a
  value being a `u32` in `BoundaryFinals` by type.
- **The time window is the trivial one**, `[0, 2^38)`, and step 4 refuses any other. S20
  generalizes the value, not the field.
- **`#![no_std]` + `alloc`, forever.** CI builds it for `riscv32imac-unknown-none-elf`.

## Tests
| File | Covers |
| --- | --- |
| `src/statement.rs` (unit) | the statement order puts the init families first; the window height and its two refusals; the boundary scalars' order; the trivial window |
| `tests/wire.rs` | every type round-trips byte for byte; §9's layouts read back field by field; the statement's and the proof's readers refuse truncation at every length, the key's at every length before its circuits and at one in 97 after, and all three a trailing byte; an overlong count, a field element at the modulus and each out-of-range boundary scalar refused; a key with one bit flipped — one bit of every header byte, every bit of one circuit byte in 1009 — refused, never loaded and never a panic; each of §7.2's load rules refuses its edited key, by name, in memory and from bytes; the SRS digest is the documented recipe and moves with each of its 320 bytes |
| `tests/reduce.rs` | the global transcript event for event (G1–G11); every statement field but the roots and the exit status moving the digest, and those two not — the exit status is bound at step 10; the shard transcript's first five events and every part of its seed moving `g`; each of steps 1–5's refusals as `Statement`, by reason; each of step 6's as `Malformed`; two thousand garbage statements and proofs refused with no panic |

The proofs themselves are `crates/prover/tests/acceptance.rs` and
`crates/checker/tests/tamper.rs`, `#[ignore]`d for size.
