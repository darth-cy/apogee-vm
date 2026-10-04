# `crates/host`

## What this crate owns
The host SDK — the path from a guest ELF and its inputs to a `BlockProof` — and the
**witness recorder** that produces a real Ethereum block's `BlockWitness`.
`prompts/00-master.md`'s projected workspace layout froze the crate's name and its
charter, *"host SDK: prove/verify API, input building, witness recorder"*, long before
S25 filled it in. The normative pages are `docs/spec/revm-block.md` for the witness and
`docs/spec/public-values.md` for what a proof binds. Since S-RECURSION it is also a
recursion node's **host side** — the native run that is a node's advice, and the tree a
base proof is aggregated by — which is input building for the recursion guest;
`docs/spec/recursion.md` §8 is normative for it.

```rust
// the wrappers. `prover::prove_block_streaming` and `verifier::verify_block` remain the
// protocol entry points; these save a caller the preamble and nothing else.
pub fn setup(elf: &[u8], params: &ProgramParams, srs: Srs) -> Result<ProverSetup, String>;
// S-STREAM: `max_in_flight` is the THIRD argument, the backpressure that bounds the peak.
pub fn prove(setup: &ProverSetup, io: &GuestIo, max_in_flight: usize) -> Result<Proven, String>;
pub fn verify(vk: &VerifyingKey, block: &BlockProof) -> Result<(), VerifyError>;
// S-STREAM: a `StreamingReport` where a `TraceArchive` was, and no per-phase section clocks.
pub struct Proven { pub block: BlockProof, pub report: StreamingReport, pub exit_code: i32,
                    pub cycles: u64, pub journal: Vec<u8>, pub wall_nanos: u64 }

// S-STREAM: `verifier::proof_archive`, re-exported whole. The four files a proved block
// leaves on disk -- <stem>.{vk,identity,public,block}; `verifier block` reads the .vk,
// .public and .block, and takes its identity from the verifier, never from .identity,
// which is only the run's claim. **The proof is the only thing a proving run
// archives.** It lives in `crates/verifier` because the format's reader is the CLI, so
// there is one definition of it; `crates/verifier/CLAUDE.md` is the account.
pub use verifier::proof_archive;   // ProofPaths, identity_hex, write_proof, read_proof

// the recorder
pub mod recorder {
    pub enum TxRange { First(usize), All }
    pub struct WitnessRecorder { /* an RPC-backed revm::Database that remembers */ }
    impl WitnessRecorder { pub fn new(rpc: Rpc, at: u64) -> Self;
                           pub fn rpc_counts(&self) -> (u64, u64); }
    pub struct Recording { pub witness: BlockWitness, pub block_hash: Word32,
                           pub parent_hash: Word32, pub parent_state_root: Word32,
                           pub state_root: Word32, pub txs_in_block: usize,
                           pub rpc_hits: u64, pub rpc_misses: u64 }
    pub fn record(rpc: Rpc, block_number: u64, range: TxRange) -> Result<Recording, String>;
    pub fn mainnet_spec(block_number: u64) -> Result<SpecId, String>;
}

// S-STATELESS: JSON-RPC objects back to the bytes the chain hashes, for
// tests/canonical.rs to hold the stateless guest's encodings to real blocks
pub mod canonical {
    pub fn header(json: &Value) -> Result<Header, String>;
    pub fn transaction(json: &Value) -> Result<Vec<u8>, String>;   // EIP-2718
    pub fn withdrawal(json: &Value) -> Result<Withdrawal, String>;
    pub fn receipt(json: &Value) -> Result<(u8, bool, u64, Vec<Log>), String>;
}

// S-STATELESS: a tests-zkevm release on disk -- the one reader of it
pub mod zkevm {
    pub const FIXTURES_VAR: &str = "APOGEE_ZKEVM_FIXTURES";
    pub const RELEASE_COMMIT: &str;          // the release the stateless guest implements
    pub struct Pair { pub name: String, pub input: Vec<u8>, pub output: Vec<u8> }
    pub fn files(dir: &Path) -> Vec<PathBuf>;           // sorted
    pub fn pairs(path: &Path) -> Vec<Pair>;
    pub fn pairs_in(fixture: &Value) -> Vec<Pair>;   // the same, over parsed JSON
    pub fn release_commit(dir: &Path) -> Option<String>;
    pub fn verdict(input: &[u8]) -> String;  // the rule `verify` refuses by, `valid`, `undecodable`
}

// the minimal JSON-RPC client
pub mod rpc {
    pub const ENDPOINT_VAR: &str = "ETH_RPC_URL";
    pub const ATTEMPTS: u32 = 5;
    pub struct Rpc { pub hits: u64, pub misses: u64 }
    impl Rpc { pub fn new(cache: PathBuf) -> Rpc;      // uses ETH_RPC_URL if set
               pub fn cached(cache: PathBuf) -> Rpc;   // cache only, whatever the env says
               pub fn online(&self) -> bool;
               pub fn call(&mut self, method: &str, params: Value) -> Result<Value, String>; }
    pub fn cache_dir(fixtures: &Path) -> PathBuf;
    pub fn digest_hex(bytes: &[u8]) -> String;
    // hex helpers: u64_of, u128_of, word_of, address_of, bytes_of, hex_data, hex_quantity
}

// what a recorded block is on disk
pub mod fixture {
    pub enum Mode { Mini, Stateless }   // binary() names the guest; only Mini is ever recorded
    pub struct Pin { /* the block, its roots, and the SHA-256 of the other two files */ }
    impl Pin { pub fn to_bytes(&self) -> Vec<u8>; pub fn from_bytes(&[u8]) -> Result<Pin, String>;
               pub fn check(&self, witness: &[u8], journal: &[u8]) -> Result<(), String>; }
    pub fn pin_file(stem: &str) -> String;  // and witness_file, journal_file
// S26: the revm guest, built from source. One copy, shared by `tools/bench`'s `prove`
// verb, `tools/profiler` and the suites -- three copies of the same 60 lines before.
pub fn revm_params() -> ProgramParams;
pub fn build_revm_guest(mode: Mode) -> Result<Vec<u8>, String>;   // always --release
// Any guest with no committed ELF, built at --release in a scratch target directory
// keyed on the pid, so two processes building one guest no longer destroy each other's.
pub fn build_guest(guest: &str, bin: &str) -> Result<Vec<u8>, String>;
}

// S-RECURSION: a recursion node's host side (docs/spec/recursion.md §8). `leaf` and
// `internal` run `verifier_core::node::node` natively and return what the node's guest
// reads and publishes; `bench recurse` and `profiler leaf` are the callers.
pub mod recursion {
    pub struct Run { pub advice: Vec<u8>, pub journal: Vec<Fr> }   // the journal's 47 cells
    // The two programs' parameters, which their identities bind: every cycle-owning family
    // at 2^20 in both; the window families and the bytecode ceiling at 2^22 for the leaf,
    // whose image is 5.6 MB, and at 2^20 for the node, whose image is 2.8 MB.
    pub fn leaf_params() -> ProgramParams;
    pub fn node_params() -> ProgramParams;
    // node_image(Kind::Leaf, &BaseKey::of(vk), &[]): the words build.rs puts in the leaf
    // binary while guests/recursion/base.key is BaseKey::of(vk)'s bytes
    pub fn leaf_image(vk: &VerifyingKey) -> Vec<u32>;
    // shards `shards` of a base block, in statement order, against the base key `vk`
    pub fn leaf(vk: &VerifyingKey, words: &[u32], block: &BlockProof, shards: Range<usize>)
        -> Result<Run, String>;
    pub struct Child<'a> { pub vk: &'a VerifyingKey, pub block: &'a BlockProof,
                           pub program: u32 }   // 0 a leaf's proof, 1 an internal node's
    // two to four whole children; `identities` the leaf program's and the node program's
    pub fn internal(words: &[u32], children: &[Child], identities: [Fr; 2])
        -> Result<Run, String>;
    // the global transcript's state at statement position `at`, computed natively: three
    // lanes and the pending input, 0 if none -- the chain claim of a node starting there
    pub fn chain_state(vk: &VerifyingKey, public: &PublicInputs, io: Fr, at: u32)
        -> ([Fr; 3], Fr);
    // [leaf, node]: each ELF's config under its parameters and the setup counts that config
    // implies -- what guests/recursion/programs.key holds
    pub fn program_keys(leaf: &[u8], node: &[u8]) -> Result<Vec<ProgramKey>, String>;
    // the tree, fixed before anything is proved (§8.4)
    pub struct Tree { pub nodes: Vec<TreeNode>, pub root: usize }   // Clone, Debug, PartialEq, Eq
    pub enum TreeNode { Leaf { from: u32, to: u32 }, Internal { children: Vec<usize> } }
    impl Tree { pub fn plan(costs: &[u64], leaf: usize, budget: u64, fan_in: usize) -> Tree;
                pub fn to_text(&self) -> String;   // `<id> leaf <from> <to>`, `<id> node <c>…`, `root <id>`
                pub fn from_text(text: &str) -> Option<Tree>; }
    // each base shard's estimated FQ_OP rows in a leaf's folds: the unit of `--budget`
    pub fn shard_costs(block: &BlockProof) -> Vec<u64>;
}
```

## Frozen invariants
- **The blob gas price is recorded, not derived** (S26, `docs/spec/revm-block.md` §1.6).
  `block_env` takes it as an argument and `blob_gasprice` reads it from
  `eth_feeHistory`'s `baseFeePerBlobGas` — **not** from a receipt's `blobGasPrice`, which a
  node reports only on the receipts of type-3 transactions, so a block with none has no
  receipt carrying it and the `BLOBBASEFEE` opcode can read the price in any block. What it
  replaces is a `fake_exponential` in the guest whose update fraction revm 42 only knows up
  to Prague: on a post-Fusaka block that computed 4,387,037,219,060,994 where the chain says
  5,055,772, and **every block carrying a type-3 transaction refused to execute**.
- **`verify` adds nothing to the verifier's inputs.** Master rule 6's signature discipline
  is `(&VerifyingKey, &Proof, &PublicInputs)` and nothing else; `host::verify` takes
  `(&VerifyingKey, &BlockProof)` and reads the statement out of the proof, which is what
  every caller of `verifier::verify_block` in this repository already writes. There is no
  witness, no trace and no prover state in it, and no second copy of the statement to
  disagree with the first. **Identity is not checked there and cannot be** — a key
  recomputes its own identity when it loads, so it is not its own authority for it. What
  makes a proof a proof *of a particular program* is `vk.identity.to_bytes()` against a
  value from a channel the prover does not control; that is one comparison and the caller
  writes it, exactly as the `verifier` CLI makes it a separate argument.
- **`prove` is `prove_block_streaming` and nothing else** (S-STREAM). The archived path —
  `prover::prove_block` over a `TraceArchive` — still compiles, because
  `checker::TamperHarness` and the checker's column-fill suites are built on the archive
  it reads, but **nothing proves through it**, here or anywhere
  (`crates/prover/tests/one_proving_path.rs` greps the repository for it). Two consequences
  a caller sees. `max_in_flight` is an **argument**, at least 1: it is the backpressure
  that bounds the peak, and the caller is the only one that knows the machine. And there is
  **no archive to return**, so `Proven` carries a `StreamingReport` and there are no
  per-phase section clocks — the report's four are *sums of disjoint intervals*, execution
  and proving interleaving and the guest being executed **twice**, so one of them is not
  the same quantity as a pre-S-STREAM archived phase number and must not be compared with
  one.
- **`prove` no longer times the executor, and does not need to.** S12 froze a per-phase
  wall-clock field on the trace archive's post-execution section and every caller passed
  zero, because nothing timed `trace_run`; S25's must-be-exact 5 wanted the bench report's
  per-stage timings to come from those sections, so this function measured it, being the
  one place on the proving path that ran the executor. Since S-STREAM the measurement is
  inside the prover, around the executor itself — `StreamingReport`'s `pass1_execute_ns`
  and `pass2_execute_ns` — which is a tighter interval than this function could take, and
  the archive those sections lived on is gone.
- **`prove` does not check the exit status.** A failing guest is still a provable execution
  and its journal is still bound; whether exit 0 was required is the caller's statement to
  make, and `Proven::exit_code` is how it makes it. Since S-STREAM that field and
  `Proven::journal` are read off `block.statement()` — `exit_status` as an `i32` of the
  same 32 bits, so `exit(-1)` still reads back as `-1`, and `output` — rather than off an
  `Execution`, there being none to read. They are the values the **proof binds**, which is
  strictly better than a second reading of them beside it.
- **The recorder's touch set comes from running the block, never from a list.** Nothing
  short of executing knows which accounts and slots an EVM execution reads: a recorder that
  took the access lists plus every `to` would miss every `SLOAD` of a dynamic key and every
  `CALL` to a computed address. `record` therefore executes the transactions once, natively,
  through **`revm_block::run_against`** — the same block executor the guest runs, over a
  different database — and harvests what the database was asked for. The two are one code
  path on purpose: if they were two, "the guest agrees with native revm" would be comparing
  two implementations of an idea rather than one implementation over two databases.
- **Determinism is structural, not lucky** (must-be-exact 1). The touch set lives in
  `BTreeMap`s keyed by address and by slot, so its order *is* the witness's canonical
  order; every RPC answer is content-addressed in the cache, so a second recording reads
  the same bytes; and `BlockWitness::decode` re-encodes and compares, so a recorder that
  produced two encodings of one state could not get either past the guest.
- **The state is read at the PARENT block.** `record(rpc, n, ..)` builds a
  `WitnessRecorder` at `n - 1`: the pre-state of block `n`'s transactions is the state at
  the end of its parent. Reading at `n` would record the *post*-state and the block would
  execute against its own output.
- **The hardfork comes from a table and an unknown block is refused.**
  `recorder::mainnet_spec` is the mainnet activation schedule by block number, taken from
  revm's own `SpecId` doc comments, and it errs below the merge. A recording made under the
  wrong fork is not one that fails; it is one that quietly computes a different block, and
  in the mini mode — which checks no state root — nothing would notice.
- **A cache miss with no endpoint is an error, never a default.** `Rpc::cached` refuses the
  network whatever `ETH_RPC_URL` says, so a test runs identically on a machine with an
  endpoint configured and one without. That is what keeps must-be-exact 4's "CI never
  touches RPC" true by construction rather than by everyone remembering.
- **Retries are ours and they are bounded.** Five attempts, exponential backoff from one
  second, on a transport failure or a 5xx or a 429 — then a hard failure naming the last
  one. A 4xx other than 429 is not retried: the request reached a server that understood
  it and refused it, so asking four more times asks the same question.
- **A node's advice is its native run, and the run is the guest's own procedure**
  (S-RECURSION, `docs/spec/recursion.md` §8.1). `recursion::leaf` and `internal` run
  `verifier_core::node::node`, the procedure `guests/recursion` runs, through `Native`,
  this crate's `Driver`, over one `tape::Memory`. Each statement is verified natively
  first: `derive_global_phase` and `verify_global_memory` once, then for each shard of the
  slice `verify_shard_local` and `pcs::batch_verify_deferred`, whose first entry is the
  `cm*` hint the shard's blob carries. Then every image body and run-time tape is replayed
  by `tape::run` and every MSM template by `fold::simulate`, which is also where each
  witness the guest imports is computed — a scalar's GLV split, an inversion. So a shard, a
  chain claim, a child that does not fit beside its neighbour, a point off the curve or an
  element read whole that was written apart refuses **here, by name, before any guest
  runs**: the `Err` is the first failure — a native verifier's own message, or the
  procedure's prefixed with where it happened (`statement <s>, shard <p>: op <k> of an
  image body refuses`). The procedure changes in `verifier_core::node` and nowhere else;
  the two drivers only answer it.
- **The advice is `[n][header][stream]`, in the order the guest reads it.** A `u32` `n`;
  the `Header`'s `n` words (`Header::to_words`: each statement's program, shard counts,
  windows, `from`, `to` and its two window lengths); then the stream — 32 little-endian
  bytes a cell, which `IMPORT` reduces, for every `advise` and for every template's
  witnesses, a point's six split cells then two 128-bit halves an inversion, and a `u32`
  flag a point, nonzero for infinity. `guests/recursion/src/lib.rs` reads exactly that,
  and exits 10 when the header is not exactly `n` words or the stream runs short. **The
  two `Driver`s are kept in step by hand**: a stream written in another order is not
  refused here, where nothing reads it back, but misread there, so a change to one
  driver's method is a change to the other's. `profiler leaf` is the cheapest run that
  shows a mismatch, executing the guest over the advice and proving nothing: a check the
  misread words fail is a failing `EQ` or `MULEQ`, which the emulator refuses as a fatal
  error, and a stream read past its end is exit 10 in the report.
- **The accumulator is discharged on the host, at every node.** After the procedure,
  `run_node` reads `A` and `B` out of the journal (`journal::A`, `journal::B`, four 64-bit
  limbs a coordinate) and checks `e(A, [1]_2) = e(B, [x]_2)` against a key's `SrsVerifier`
  — the base key for a leaf, the first child's for an internal node. The guest makes no
  pairing, `(A, B)` being journaled for the top to discharge once, so this check is the
  host's alone: it is what makes a wrong fold — a weight, a side, a merged scalar, an MSM
  template — an `Err` (`the folded accumulator does not discharge`) at the node that
  folded it, and not a root that fails at the top.
- **Two programs, two parameter sets, and each identity binds its own** (the owner's
  decision, §8.1). `leaf_params()` puts every cycle-owning family at `2^20` — the leaf's
  code is some 50 KB — and keeps the window families at their `2^22` default, raising
  `bytecode_size_words` to `2^22` with them, because window 0 holds the image and a leaf's
  image is the base program's tapes, 5.6 MB. `node_params()` is the leaf's with
  `INIT_TEARDOWN`, `ZERO_WINDOWS`, `ADVICE_WINDOWS` and the bytecode ceiling at `2^20`: the
  recursion programs' tapes are 2.8 MB, inside window 0's 4 MiB. Every other family keeps
  `ProgramParams::defaults()`'s height. An edit to either function moves that program's
  config, and with it its identity and its entry in `guests/recursion/programs.key`: rerun
  `profiler program-keys`, without which `bench recurse` refuses to start.
- **The words a caller passes must be the binary's.** The host replays the `words` it is
  handed; the guest replays the image in its `.rodata`, which `guests/recursion/build.rs`
  makes with the same `node_image` from `base.key` and, for the node, `programs.key`.
  `leaf_image(vk)` is that call, so the two agree only while `base.key` is
  `BaseKey::of(vk)`'s bytes, and an internal node's words only while `programs.key` is
  `program_keys` of the two ELFs. `profiler leaf` compares the first file before it builds
  the guest, and `bench recurse` both before it proves anything, each refusing with the
  verb that rewrites the file.
- **A refusal is an `Err`; a request no node can make is a panic.** Proof data that does
  not verify, a shard the block does not have, a child that does not fit: `Err`. A leaf
  over an empty slice, an internal node over fewer than two children or more than four, or
  a child whose statement is not a node's — a nonempty public input, or a journal other
  than 1,504 bytes: an `assert!` in `verifier_core::node::node`, the procedure having no
  proof for such a header. So a caller that takes a slice or a fan-in from a user refuses
  it first: `profiler leaf` an empty slice or one past the statement, `bench recurse` a
  fan-in outside 2 to 4.
- **The tree is planned from an estimate and fixed before anything is proved** (§8.4).
  `Tree::plan(costs, leaf, budget, fan_in)` closes a leaf of consecutive shards before a
  shard that would take it past `leaf` shards or its summed cost past `budget`, so a shard
  alone over the budget is a leaf of its own. It then builds levels over `chunks(fan_in)`,
  a group of one carried up a level as it is, the procedure refusing a node of one child.
  Ids are creation order — the leaves in shard order, then each level's nodes — so a
  child's id is below its parent's and the root is the last node. `shard_costs` is the
  budget's unit: 400 `FQ_OP` rows a point (the point template is 396 calls) over a shard's
  twelve Mercury points and its memory and witness commitments, its setup commitments
  being merged and paid once a node. `from_text` reads `to_text`'s lines and nothing else —
  ids in order from 0 and a root that names a node, nothing more checked — and `plan`
  panics on no shards, `leaf == 0` or `fan_in < 2`.

## The dependencies, and why each is allowed
Master rule 2's runtime list is exhaustive, so both additions are recorded here and in
`docs/handoff/S25-block.md`.

- **`serde_json`.** JSON is the RPC wire format and `eth_getProof`'s response is a nested
  object of hex-string proof arrays. Master rule 2 names *serialization* among the allowed
  runtime dependencies and this is the second entry under it, after `serde`/`postcard`. It
  is reachable from no prover, no verifier and no guest.
- **`curl`, through `std::process::Command`.** Every mainnet endpoint is TLS-only; this
  workspace has no HTTP client, no TLS and no async runtime, and anti-goal 7 bans `tokio`
  by name. Hand-rolling TLS is not what "own the crypto" means — that is about the
  *proving system's* cryptography. So the JSON-RPC client is ours (request framing, the
  retry policy, the cache) and only the HTTPS bytes are `curl`'s, spawned the way this
  repository already spawns `cargo` and `llvm-objdump`. It is an undeclared host tool of the
  same class, reachable only from the manual refresh.
  **Caveat worth stating:** the endpoint carries an API key and is passed on `curl`'s
  command line, so it is visible in `ps` output on the machine doing the refresh. The
  request body goes over stdin.
- **`std::thread::sleep`, once**, for the backoff. Anti-goal 7 bans threads; `sleep` spawns
  nothing and blocks the caller, which is the whole of what a backoff is.
- **`revm` and `revm-block`.** The recorder's database implements revm's `Database` trait
  and its harvest reads revm's own state types. `tools/kat-gen` already takes the same path
  dependency on the guest library, and with it revm; S24's licence — *the guest is the
  workload, not the proving stack* — is what admits it, and a host-side recorder of that
  workload is the same graph.
- **`test-support`**, for SHA-256 and hex: the cache's content addresses and the fixtures'
  pins. It declares no dependencies of its own, on purpose, so taking it cannot unify a
  feature into anything.

## The fixtures
`tests/vectors/`, and `docs/spec/revm-block.md` §1.3 is the normative account.

| file | committed | what |
| --- | --- | --- |
| `mini-block.json` | yes | the `Pin`: the block, its roots, and the SHA-256 of the other two |
| `mini-block-witness.bin` | yes | the `BlockWitness`, `postcard`, the guest's advice |
| `mini-block-journal.bin` | yes | what native revm makes of it |
| `rpc-cache/` | yes | the content-addressed snapshot that re-records the pinned block |
| `canonical/` | yes | S-STATELESS: block 26,059,929 in full, its parent and its receipts, as the node served them |
| `zkevm-subset.json` | yes | S-STATELESS: 34 stateless pairs of `tests-zkevm@v21.0.1`, cut by `kat-gen -- zkevm` |
| `stateless_ref.txt` | yes | S-STATELESS: 33 stateless inputs and their request roots, by `tools/stateless-ref`, in both containers |

The refresh is `cargo run -p kat-gen -- block`, which needs `ETH_RPC_URL` and is **not** in
`DEFAULT_GROUPS` — the same opt-in the `guests` group has, and what keeps CI off the
network. A session records the pinned block, checks three further recent blocks live
(acceptance 2's repeated-blocks check, cached under `target/` and never committed), and
re-records the pinned one from the cache alone to prove the recording deterministic.

## Tests
| File | What |
| --- | --- |
| `tests/mpt.rs` | the trie: Ethereum's three published root vectors (empty, `dogglesworth`, `horse`), order- and delete-invariance over every permutation, a sparse rebuild from every prefix of its own nodes, and each refusal separately — a missing node is not an absence, a blinded collapse names its hash, every canonical-form rule refuses. 18 tests |
| `tests/canonical.rs` | S-STATELESS: the stateless guest's encodings against two real blocks — every header to its hash, 313 transactions to their hashes and senders, the roots, receipts, bloom, gas and block size, each header rule by its own mutation, EIP-2's signature rules, the strict decoder, the deposit parser and the blob price. 10 tests |
| `tests/conformance.rs` | S-STATELESS: the committed subset, each case held to its 43 bytes and its rule, and again in ere-guests' keyed layout with its signers' keys, plus four refused key lists; **`#[ignore]`d**, the whole release by hand (`APOGEE_ZKEVM_FIXTURES`), the subset through the guest binary in the emulator, printing cycles, and any fixtures directory — a benchmark devnet batch — through the binary. `docs/spec/stateless.md` §4 |
| `tests/ssz.rs` | S-STATELESS: the stateless decoder and request root against `eth-act/ere-guests` v0.17.1 on all 33 of `stateless_ref.txt`'s inputs — the Electra/Fulu layout no release fills, and both containers |
| `tests/revm_lock.rs` | S-STATELESS: both lockfiles hold the reference stateless guest's revm set, crate for crate |
| `tests/prove.rs` | **`#[ignore]`d** — the mini-block gate (acceptance 4) and the advice tamper twin (acceptance 5). Since S-STREAM it proves through `host::prove(.., IN_FLIGHT)` with `IN_FLIGHT = 4`: the suite is run for its verdict and not its wall clock, and four shards proved at once was 77.10 GiB against eight at 83.91 on a 51-shard statement |
| `tests/witness.rs` | acceptance 1 (two cache-only recordings, byte-identical, zero network calls, equal to the committed fixture), acceptance 2's native half (the witness alone reproduces the pinned journal), acceptance 3 twice (every recorded slot deleted in turn, and every recorded account, each refused), the fixture against its pin, the fork table both ways, the journal against the public window's ceiling, and a one-wei balance change moving the journal |
| `src/recursion.rs` (unit) | S-RECURSION: `Tree::plan` — leaves closing at the shard limit and at the budget, a shard over the budget a leaf alone, internal nodes of two to four children with a group of one carried up a level, a one-shard tree whose root is its leaf — and `from_text` reading `to_text` back |
| `tests/msm.rs` | S-RECURSION: `verifier_core::fold`'s MSM against `curve`'s, here because `verifier-core` is `no_std` and has no curve. Twelve random points, each loaded from its transcript limbs by `load_point`, through the prelude, one point template each and the finish, give `curve::msm`'s `Σ s_i·P_i`; the point at infinity is held to the sentinel and adds nothing, and a real point said to be infinity refuses; `φ(x, y) = (β·x, y)` is `λ` on the generator and on a random point; `OFFSET` is `k·G` for the templates' `k` and `CORRECTION` is `−(Σ_w 256^w)(Σ_b b(b + 1))·R`. 3 tests |

**The journal does not distinguish every witness, and that is a fact about the workload
rather than a gap.** On the pinned mini-block, one of thirty-seven recorded slots is read
by the callee and then overwritten unconditionally, so its original value reaches nothing
observable and changing it leaves the journal identical. A balance is the cell to move in
a test that wants a guaranteed difference: every touched account's balance and nonce are
in the output commitment's post-state summary verbatim.

**`recursion::leaf` and `internal` have no suite of their own**: each needs an archived
base proof and the key files made from it. What runs them is `profiler leaf`, and every
node of `bench recurse`, which holds its proved journal to the native `Run::journal`
before it writes the proof.
