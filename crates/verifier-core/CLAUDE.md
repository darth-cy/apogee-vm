# `crates/verifier-core`

## What this crate owns
Everything a shard's verification does except its one Mercury opening, `#![no_std]` +
`alloc`, because the recursion guest links it and re-implementation is forbidden (S16).
**`docs/spec/shard-proof.md` is normative**, and this crate is its §1–§7 and §9. Since
S-RECURSION it is also the recursion half, whose design authority is
**`docs/spec/recursion.md`**: its §1.1, §1.3, §7 and §8.1–§8.3 are here, and §8.4's
tree and scheduler are `host::recursion`'s and `bench recurse`'s.

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
  it; `verify_shard_local` (steps 4–10a, S-IO's 10c, and 11) is the only one that reads a
  `ShardProof`, and is the only one a block runs per shard.
- **The block** (S20, `docs/spec/block-proof.md`): `BlockProof`, `ShardRecord`,
  `BlockReconciliation`, their wire forms, the structural rule a decoded block keeps, and
  `check_ts_windows`.
- **The proof-side types**: `PublicInputs`, `ShardProof`, `VerifyingKey`, `VerifyError`,
  `OpeningClaim`, their byte layouts, and a key's load rules.
- **The recursion half** (S-RECURSION): the **stacked opening** (§1.3) — `STACK_LOG`,
  `stack_count`, `stack_challenges`, `stack_values`, `VmConfig::stack_vars` — and four
  modules that write verification as **tapes** over field-memory cells. `tape` (§7), the
  cell model: `Tape`, `CellTranscript`, `shard_tape` (a shard's checks per family and
  height), the guest's form (`encode`, `decode`, `schedule`) and `run`, the native reading
  over a `Memory` whose whole-element rule refuses an `Fq` element not written whole.
  `chain` (§8.1), the global transcript as a chain across the tree (`identity`, `prefix`,
  `segment`, `suffix`) and the cross-shard checks (`boundary`, `reconcile`, `below`).
  `fold` (§8.3), the two MSMs as `FQ_OP` templates: GLV `split`, offset buckets, `Node`,
  `shard_fold`. `node` (§8.1–§8.2), the one procedure both node
  programs run: `ProgramKey`, `BaseKey`, `node_image`, `Header`, `Driver`, `node`, and the
  `claim` and `journal` layouts.

```rust
pub struct VmConfig { pub families: Vec<(u32, u32)>, pub bytecode_size_words: u32 }
impl VmConfig { pub fn height(&self, f: u32) -> Option<u32>; pub fn to_bytes(&self) -> Vec<u8>;
                pub fn from_bytes(b: &[u8]) -> Option<VmConfig>; }
pub fn window_height(config: &VmConfig) -> Result<u32, &'static str>;
pub fn absorb_statement_descriptor(tr: &mut Transcript, config: &VmConfig, shard_counts: &[u32], windows: &[u32]);
pub fn check_memory_windows(config: &VmConfig, shard_counts: &[u32], windows: &[u32]) -> Result<(), &'static str>;
// S-IO, docs/spec/public-values.md. Neither adds a message, a tag or a challenge.
pub fn public_io_words(bytes: &[u8]) -> Vec<u32>;   // the window: length word, LE payload, zero pad
pub fn advice_first_window(height: u32) -> u32;     // 2^29 / h: the window holding ADVICE_ORIGIN
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
pub fn shard_window(family: u32, index: u32, windows: &[u32], trace_vars: u32) -> Option<u32>;
pub fn shard_challenges(circuit: &FamilyCircuit, index: u32, windows: &[u32], memory: &[Fr; 4],
                        g: Fr, beta: Fr) -> ExternalChallenges;
// S-RECURSION, docs/spec/recursion.md §1: the format is the config's. σ = 0 is the base
// format exactly, and one code path carries both.
impl VmConfig { pub fn is_recursion(&self) -> bool;                            // holds FIELD_WINDOWS
                pub fn stack_vars(&self, artifact: &CircuitArtifact) -> u32;    // σ; 0 in the base format
                pub fn circuit(&self, family: u32, trace_vars: u32) -> Option<FamilyCircuit>; }  // its registry
pub const STACK_LOG: u32 = 24;  pub fn stack_count(columns: usize, sigma: u32) -> usize;
pub fn stack_challenges(t: &mut Transcript, sigma: u32) -> Vec<Fr>;
pub fn stack_values(values: &[Fr], memory: usize, witness: usize, r: &[Fr]) -> Vec<Fr>;
// §7-§8.3: tapes over field cells, built on the host, replayed by the guest. `t: &mut Tape`.
pub mod tape {   // also gkr_verify, batch_preamble, mercury_scalars: shard_tape's parts
    pub type Cell = u32;  pub const ZERO: Cell = 0;  pub type Limbs = [Cell; 4];
    pub enum Op { Fr([u32; 4]), Duplex([u32; 5]), Fq([u32; 4]), Import { cell: Cell, offset: u32 } }
    pub struct Tape { pub ops: Vec<Op>, .. }   pub struct CellTranscript;   pub struct Memory;
    pub fn shard_tape(config: &VmConfig, circuit: &FamilyCircuit, setup: usize, first: Cell) -> ShardTape;
    pub fn shard_blob(inputs: &[Input], proof: &ShardProof, cm_star: &[u8; 64]) -> Vec<u8>;
    pub fn encode(ops: &[Op]) -> Encoded;  pub fn decode(body: &[u32]) -> Option<Vec<Op>>;
    pub fn schedule(ops: &[Op]) -> Vec<Op>;
    pub fn run(ops: &[Op], memory: &mut Memory, blob: &[u8]) -> Result<(), usize>;   // Err: the op
}
pub mod chain {   // also boundary (10b), reconcile, below, pending, shape_digest, public_value (10c)
    pub fn identity(t, code_version: u32, config: &VmConfig, entry_pc: Cell, setup: &[Vec<Limbs>]) -> Cell;
    pub fn prefix(t, shape: &Shape, srs_digest: &[u8; 32], identity: Cell, io: Cell) -> CellTranscript; // G1-G7
    pub fn segment(t, tr: &mut CellTranscript, shape: &Shape, from: u32, lists: &[Vec<Limbs>]);        // G8
    pub fn suffix(t, tr: &mut CellTranscript, shape: &Shape, boundary: &[Cell]) -> ([Cell; 4], Cell);  // G9-G11
}
pub mod fold {   // also WINDOWS, BUCKETS, OFFSET, CORRECTION, BETA, LAMBDA, Layout, Template, simulate
    pub fn prelude(l: &Layout) -> Vec<Phase>;  pub fn point_template(l: &Layout) -> Template;
    pub fn finish(l: &Layout) -> Vec<Phase>;   pub fn split(k: Fr) -> [Fr; 6];   // [|k₁|, |k₂|, b₁, 0, b₂, 0]
    pub fn shard_fold(shape: &ShardTape, node: &Node, merged: &[u32]) -> (Vec<Op>, Vec<FoldPoint>);
    pub fn load_point(p: &FoldPoint, l: &Layout, sentinel: Cell, infinity: bool) -> Load;  // Deref<[Op]>
}
pub mod node {   // also FIRST = 3, claim, journal, ProgramKey, BaseKey, NodeImage::read
    pub fn node_image(kind: Kind, base: &BaseKey, programs: &[ProgramKey]) -> Vec<u32>;  // Leaf, Internal
    pub struct Header { pub statements: Vec<StatementHeader> }   // to_words, read
    pub enum Advice { Identities, Setup(u32), Claims(u32), Commitments(u32, u32), Roots(u32, u32),
                      Blob(u32, u32), Input(u32), Output(u32), Boundary(u32) }
    pub trait Driver { fn replay(&mut self, body: &[u32]); fn run(&mut self, ops: &[Op]);
                       fn advise(&mut self, cells: &[Cell], what: Advice);
                       fn template(&mut self, template: &ImageTemplate, scalar: Option<Cell>);
                       fn infinity(&mut self, limbs: Cell) -> bool; fn read(&mut self, cell: Cell) -> u32;
                       fn export(&mut self, cells: &[Cell]); }
    pub fn node<D: Driver>(d: &mut D, image: &NodeImage, h: &Header);
}

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
                          public: &PublicInputs) -> Result<OpeningClaim, VerifyError>;  // 4-10a, 10c, 11
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
  `Constraint` (7–8), `Lookup` (9), `MemoryArgument` (10a, **10c**, 10b).
  `verifier::verify_shard` adds `Opening` (12). A prover that proves a tampered witness
  honestly is refused by the class of what the tamper broke, which is what
  `checker::TamperHarness` asserts. S20's three-part split does not move a step:
  `reduce_shard` calls `verify_global_memory` after `verify_shard_local` returns, and step
  11, the only step between 10c and 10b, builds the opening claim and cannot fail — so the
  first failure, its class and its message are S16's for every input.
- **Step 10c is S-IO's one new check, it sits between 10a and 11, and its class is
  `MemoryArgument`** (`docs/spec/public-values.md` §5). It is in `verify_shard_local`,
  because it reads a `ShardProof`'s own base claims, and it runs only on the two public
  value shards. Their base claims arrive in layout order `M`, `W`, `S`, and neither family
  has a `W` or an `S` column, so `claims[1]` is `M[1] teardown_value` and `claims[2]` is
  `M[2] init_value`; the verifier evaluates the multilinear extension of
  `public_io_words(...)` at that shard's own opening point and compares. `PUBLIC_INPUT`'s
  `M[2]` is held to `public.input`, `PUBLIC_OUTPUT`'s `M[1]` to `public.output`, each with
  a message naming which window disagreed. **Its cost is two multilinear evaluations over
  `family::PUBLIC_WINDOW_HEIGHT` points, and that is 4,096 since S-STREAM where it was
  256**: the step did not change, the window it reads got sixteen times larger, and the
  bill is ~8,190 `Fr` multiplies and ~163 KiB of scratch per statement — noise natively,
  and a budget a recursion guest carries. **What each is worth rests on the memory
  argument and not on the comparison**: the multiset already forces a window's init column
  to be each address's first value and its teardown column to be its last. `PUBLIC_OUTPUT`
  has no `M[2]` at all — its circuit is `ZERO_WINDOWS`', whose init leaf is a literal 0 —
  so there is nothing to pre-load the journal into and nothing here to check about it.
- **The global transcript did not change at S-IO, and that is the claim to hold.** No new
  message, no new tag, no new challenge, no new statement field, no new address space, and
  no change to any execution family's circuit. `io_digest(input, output)` is S10's, absorbed
  at G7 where it has always been — before the memory challenges are squeezed, which is what
  fixes the two byte strings before any challenge exists — and `M[1]` and `M[2]` are
  **memory** columns, committed at G8, which is also before the squeeze. Step 10c then says
  the committed columns are those bytes. The whole schedule is S16's G1–G11, untouched.
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
  changed, and an edit inside a circuit is not caught there. **S-IO added two `Statement`
  refusals to `derive_global_phase`**, both at step 2 and both before `public_io_words` is
  ever asked to lay a window out: `public.input` longer than
  `guest_memory::PUBLIC_PAYLOAD_BYTES`, and `public.output` longer than it. Bytes no window
  could have carried are a statement nobody can have proved, and `public_io_words` panics
  on such a slice rather than encoding it, so the ceiling is checked where a decoded
  statement first reaches the verifier. Step 10c then calls `public_io_words` **assuming**
  it: that is a precondition of the three-part split, and a caller that reaches
  `verify_shard_local` without having derived the global phase from the *same*
  `PublicInputs` has skipped step 2.
- **`window_height` and `check_memory_windows` grew S-IO's rules, and `window_height` is the
  one that matters** — it runs inside `VmConfig::from_bytes`, on bytes a verifier was
  handed. It now requires `INIT_TEARDOWN`, `ZERO_WINDOWS` **and `ADVICE_WINDOWS`** all
  present at one height `h` — an `ADVICE_WINDOWS` height of its own would put the advice
  region on a different grid from the one `advice_first_window` computes — `PUBLIC_INPUT`
  and `PUBLIC_OUTPUT` present at exactly `family::PUBLIC_WINDOW_HEIGHT`, and
  `4h >= PUBLIC_OUTPUT_ORIGIN + PUBLIC_WINDOW_BYTES`, so both public windows lie inside RAM
  window 0, whose rows below `RAM_ORIGIN` are masked by `V[ram_live]` at every height.
  **The last rule's floor is `2^16` and S-STREAM did not move it**, though both of its
  operands moved: the public windows now end at `RAM_ORIGIN` exactly, so the rule reads
  `4h >= 2^16`, and `2^14` is not on the menu. What changed is how many menu entries fail
  it — `2^8` and now `2^12`, S-STREAM's own entry, which a *window* family may therefore
  never take even though the two public families are pinned to it. Without the rule a
  `ZERO_WINDOWS` id could claim a public window and give a public word a second init row.
  `check_memory_windows` adds three: exactly one `PUBLIC_INPUT` shard, exactly one
  `PUBLIC_OUTPUT` shard — a count a prover could drop is a way to publish nothing while
  having published something — and `advice_first_window(h) + k <= 2^30 / h`, the top of the
  address space, `k` being `ADVICE_WINDOWS`' shard count. **The advice windows need no
  list and no disjointness rule**: they are the `k` consecutive windows from
  `advice_first_window(h) = 2^29 / h` up, which is exactly where the `ZERO_WINDOWS` bound
  `[1, 2^29/h − 1]` stops, so the two families' ids are disjoint by arithmetic and shard `i`
  is window `advice_first_window(h) + i`. `MEMORY_WINDOWS` still carries `ZERO_WINDOWS`' ids
  and nothing else (`docs/spec/public-values.md` §2, §6). S-RECURSION adds one rule:
  `FIELD_WINDOWS`' count times its height is at most `2^32`, a cell being a `u32`; shard `i`
  is window `i` from cell 0 (`shard_window`), one cell a row where RAM's is four bytes.
- **Curve-free.** A `G1` point is its 64 canonical bytes, absorbed through
  `transcript::append_g1_points` (all-zero is infinity) and never decoded here: validating
  a point is `crates/verifier`'s and, in a node, the fold's, whose template holds it to
  `y² = x³ + 3` in `FQ_OP` calls (cofactor 1), natively `constraints::fq_op`'s integers,
  so the crate links no curve. The Mercury proof is 704 opaque bytes. S-RECURSION split
  Mercury's field side out as `pcs-verify`, which S16 had deferred, and this crate reads its
  `ENTRY_POINTS` alone; S09's `cm*` is a hint the fold holds to `Σ ρ^i·cm_i` (below).
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
  its circuits **byte for byte** `VmConfig::circuit(family, trace_vars)` —
  `constraints::family_circuit`, or since S-RECURSION `constraints::recursion_circuit` for a
  config in the recursion format; the circuits are protocol constants given a format, a
  family and a height, and identity binds the program, not the circuit — plus `validate`,
  `check_memory` and `check_discharge` at every load. Per family, the setup list's length
  plus 3 where the circuit reads the `GENERIC` channel
  (`FamilyCircuit::reads_generic_table`) is the artifact's `S` width.
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
  opens 21 + 44 + 10 commitments, the last three the table's. In the recursion format `M`
  and `W` are stacks of `2^σ` columns, counted so at steps 3 and 6: after the GKR pass
  step 11 draws `r` under `STACK_CHALLENGE` (42) and claims each stack's
  `Σ_j eq(r, j)·v_j`, and each setup column's `eq(r, 0)·v`, at `u ‖ r`.
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
- **The format is the config's, and `σ = 0` is the base format** (S-RECURSION,
  `docs/spec/recursion.md` §1.1, §1.3). A config holding `FIELD_WINDOWS` is in the
  recursion format (`is_recursion`), and no wire form says so. Outside it `σ` is 0, no
  stack challenge is drawn and `stack_values` is the identity, so every base key, statement
  and proof keeps its bytes; inside, `σ` is the least even one whose `2^σ` slots hold the
  wider of a shard's `M` and `W` phases, capped at `STACK_LOG − n`. `VmConfig::circuit`
  picks the registry for the key's load and the prover alike.
- **A node is one procedure, run by two drivers** (§8.1). `host::recursion` runs
  `node::node` natively over `tape::run`, recording each word of advice in the order the
  procedure asks; `guests/recursion` runs it by coprocessor calls, reading that stream in
  that order. So the layout cannot drift, and a host refuses what a guest would, by name,
  first. Its control follows only the header, the image, `Driver::read` (a bound cell below
  `2^32`) and `Driver::infinity`, whose lie fails either way (the sentinel's `EQ`s,
  `FROM128`'s range). It does **no `Fr` arithmetic of its own**, which would make both
  programs declare S23's two families: run-time constants are `IMM` and `SHL` from their
  words (`Tape::small`, `Tape::power`, `Tape::words`, `Tape::bytes`), and `Tape::constant`,
  which computes over an `Fr`, is the image build's. A tape finds a constant it has made by
  its **words**, never its bytes: a guest compares `[u8; 32]` keys with `memcmp`, a byte a
  step, and on block 257510 that was 42% of an internal node's cycles. A header the statement rules refuse panics: there is no proof.
- **The image is everything static; nothing advised is trusted** (§8.1).
  `guests/recursion/build.rs` puts each binary's `node_image` in its `.rodata`, so identity
  binds every tape and template, the boundary half, the constants, the SRS digest, each
  `ProgramKey` and a leaf's base identity. Setup commitments and the entry pc are advice
  held to a program's identity by recomputing it (`chain::identity`); an internal node's
  two identities are claims it journals for the top. The other claims are held where they
  can be — digest and challenges by `suffix`, `io_digest` at a public shard, exit by
  `x10` — and journaled where they cannot.
- **Shard tapes share their cells; the procedure's own are never reused.** Cells `0..3` are
  the zero state, every shard tape runs from `node::FIRST = 3`, then come the `claim` cells,
  `fold::Node`'s, and from `NodeImage::runtime` the procedure's. So a shard's time window is
  copied out and its roots multiplied in before the next shard's advice lands, and
  `chain::segment` copies a pending transcript input, a slot the next shard overwrites;
  every segment message being an even number of scalars, a seam is three lanes and at most
  one input (`chain::pending`), the journal's four chain cells. An import's cell is fresh,
  which is what lets `encode` hoist a tape's imports: `Tape::reset` is for the fold's
  import-free templates alone, and `schedule` refuses an `FQ_OP` tape, whose indirect
  operands name cells only their digits know.
- **An `Fq` element is written whole** (§6). `FQ_OP` reads `b`'s and `d`'s four cells under
  one timestamp and one gap, so an element whose cells were last accessed apart has no
  witness; `tape::run` refuses it first, so a layout breaking the rule fails natively and
  not as an unprovable fill. Hence `fold`'s temporaries are elements on one grid of four
  from `Layout::scratch`. `a` is exempt, `FROM128`'s operand being limbs imported singly.
- **A fold weight is drawn after everything it weights** (§8.3): `w` and `w′` under
  `FOLD_WEIGHT` (44) once the shard transcript's final state, which binds its deferred
  checks, is absorbed under `FOLD_STATE` (43); a child's once its whole journal is, under
  `FOLD_CHILD` (45). A weight known sooner would let two checks' errors cancel, and the
  folded check fails, but with probability about `2/r` a shard, unless every one holds.
  Entry `i` takes `w·e_i` on `ENTRY_POINTS`' side, `cm*` `w′` more and each opened
  commitment `−w′·ρ^i`, folding the batch check `cm* = Σ ρ^i·cm_i` a tape cannot make.
  `[1]_1` and the setup commitments enter their MSM once, after the last shard. No MSM
  replay branches on a value: the GLV split and the inverses are host witnesses a template
  holds, and offset buckets keep every addition off infinity.
- **The journal is 47 cells** (`node::journal`, §8.2), one 32-byte word each as `EXPORT`
  writes it, not necessarily canonical. The node writing it, a parent reading it out of the
  child's step-10c window (`output_len == journal::BYTES`, 1,504) and `host::recursion`'s
  discharge of `(A, B)` at cells 29 and 37 all read one layout; `journal_cells` asserts 47.
- **`#![no_std]` + `alloc`, forever.** CI builds it for `riscv32imac-unknown-none-elf`;
  since S-RECURSION `guests/recursion` links it, and its `build.rs` runs `node_image`.

## Tests
| File | Covers |
| --- | --- |
| `src/statement.rs` (unit) | the statement order puts the init families first; the window height and its five refusals (S-IO added three: `ADVICE_WINDOWS` at the window families' one height, both public families at `PUBLIC_WINDOW_HEIGHT`, and a height that would put a public window outside RAM window 0); the boundary scalars' order; the trivial window |
| `src/tape.rs` (unit) | `schedule` over a transcript interleaved with arithmetic on its challenges, a `DIGIT` among it, computes every cell the tape does in fewer runs, its imports in blob order; `Memory`'s whole-element rule — an element `FQ_OP` reads as `b` or as `d` refused once one of its cells is accessed alone, and as `a` not; `encode` keeps every frame in order, a run a family, and hoists the imports in blob order, `decode` reads the body back as the tape less its imports, and the hoisted form replays to the tape's values |
| `src/chain.rs` (unit) | `prefix`, `segment` and `suffix` over cells give `global_commit`'s memory challenges and digest however the shards are cut among nodes — one, three, one a shard — with a family of no shards mid-statement and at its end, and the slot cells overwritten between segments as a node's are, which is what catches a pending input not copied; the prefix's parity is `pending`'s; `identity` is `identity_digest`; `window_bytes` then `io_digest` is `transcript::io_digest`, `public_value` is the output window's extension at a point, and a padding byte that is not 0 refuses; `boundary` is `gkr_verify::boundary_factors`, and a timestamp at `2^38`, a value at `2^32` or an `x10` that is not the exit status refuses |
| `src/fold.rs` (unit) | `split`: each half below `2^128`, each sign a bit and each spacer 0, and `s₁·k₁ + λ·s₂·k₂` its scalar, at 0, ±1 and ±λ and over a thousand random scalars |
| `src/node.rs` (unit) | `ProgramKey::of` a six-family config, setups `[7, 1, 0, 0, 0, 0]`; a `BaseKey`, a `ProgramKey` list and a `Header` round-trip; both kinds of image read back — a program a key, a family a config family, every body runs of field frames, a tape the two programs share held once — and one word more is refused |
| `tests/wire.rs` | every type round-trips byte for byte, S16's key and one with S17's family among them, and since S26d one with `KECCAK_F`'s — the only key fixture whose circuits carry the **`XOR8`** channel, and so the only fast-gate reading of `types.rs`' three new `VirtualKind` wire tags: that codec keeps its own copy of the tag table beside `constraints::wire`'s, every other fixture names only `V[range19]`, `V[range16]` and setup columns, and a wrong arm for tags 4–6 would make a verifying key for any program that hashes unloadable; §9's layouts read back field by field — the proof's, the statement's, and the key's through its first circuit's artifact, S17's family key with its three generic-table points raw between its `SrsVerifier` and its SRS digest; the statement's and the proof's readers refuse truncation at every length, each key's at every length before its circuits and at one in 97 after, and all three a trailing byte; an overlong count, a field element at the modulus and each out-of-range boundary scalar refused, one wider than 64 bits with in-range low bytes among them; each key with one bit flipped — one bit of every byte before its circuits, every bit of one circuit byte in 1009, and every one of the generic table's 1,536 bits, each of those refused with the SRS digest's message — refused, never loaded and never a panic; each of §7.2's load rules but the registry's own order check, which no key can trip, refuses its edited key, by name, in memory and from bytes — S17's among them: a generic-table byte flipped and two of its points swapped, each refused by the SRS digest, and the jump family's setup list at 10 or at 6, each refused by the setup-count rule; the SRS digest is the documented recipe, its second message the table's twelve limbs, and moves with each of the `SrsVerifier`'s 320 bytes and each of the table's 192 |
| `tests/block.rs` | S20: the record list is statement order and each record is §2's layout read off the statement and the shard's own proof; the public data — descriptor, counts, a detached family's 0, the proofs, the reconciliation — through the wire form alone; every way a block's statement and proofs can be different shard sets refused at decode, by name; the reader refused a trailing byte, every truncation and a `VmConfig` no derivation produces; `BlockReconciliation`'s layout field by field over one record, and its reader the same way; the window rule per cycle-owning family, with the init family's trivial window inside add/sub's and exempt |
| `tests/reduce.rs` | the global transcript event for event, G1–G11 and nothing else; S17's generic table bound through the SRS digest: a key with S17's family has S16's schedule and no `GENERIC_TABLE` message, the statement's digest moves with each of the table's points and with their order once the key's SRS digest is recomputed over them, and a key whose table moved without it does not load; every statement field but the roots and the exit status moving the digest, and those two not — the exit status is bound at step 10; the key's SRS digest and identity each moving it; the shard transcript's first five events and every part of its seed moving `g`; `g` and `β` the first and second `LOOKUP_CHALLENGE` squeezes of a transcript replayed by hand; each shard's challenges — the window constant at `INIT_TEARDOWN`'s window 0 and at each `ZERO_WINDOWS` shard's own window, none for an execution family, and the memory and LogUp slots; each of steps 1–5's refusals as `Statement`, by reason, a key one setup list short among them; each of step 6's as `Malformed`; two thousand garbage statements and proofs refused with no panic |

The proofs themselves are `crates/prover/tests/acceptance.rs`,
`crates/prover/tests/control.rs` and `crates/checker/tests/tamper.rs`, `#[ignore]`d for
size.

The recursion half is held to the native verifier by suites outside this crate:
`crates/gkr/tests` (`tape::gkr_verify` against `gkr::verify`, refusals included),
`crates/pcs-verify/tests/tape.rs` (the Mercury side, to the sponge state),
`crates/host/tests/msm.rs` (the fold against `curve::msm`, and its constants) and the
deferred `crates/prover/tests/field_ops.rs` (every shard tape of a recursion-format block).
**`node::node` itself has no suite**: `host::recursion` runs it, under `bench recurse` and
`profiler leaf`.
