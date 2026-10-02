# `crates/host`

## What this crate owns
The host SDK — the path from a guest ELF and its inputs to a `BlockProof` — and the
**witness recorder** that produces a real Ethereum block's `BlockWitness`.
`prompts/00-master.md`'s projected workspace layout froze the crate's name and its
charter, *"host SDK: prove/verify API, input building, witness recorder"*, long before
S25 filled it in. The normative pages are `docs/spec/revm-block.md` for the witness and
`docs/spec/public-values.md` for what a proof binds.

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

**The journal does not distinguish every witness, and that is a fact about the workload
rather than a gap.** On the pinned mini-block, one of thirty-seven recorded slots is read
by the callee and then overwritten unconditionally, so its original value reaches nothing
observable and changing it leaves the journal identical. A balance is the cell to move in
a test that wants a guaranteed difference: every touched account's balance and nonce are
in the output commitment's post-state summary verbatim.
