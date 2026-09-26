# `crates/host`

## What this crate owns
The host SDK — the path from a guest ELF and its inputs to a `BlockProof` — and the
**witness recorder** that produces a real Ethereum block's `BlockWitness`.
`prompts/00-master.md`'s projected workspace layout froze the crate's name and its
charter, *"host SDK: prove/verify API, input building, witness recorder"*, long before
S25 filled it in. The normative pages are `docs/spec/revm-block.md` for the witness and
`docs/spec/public-values.md` for what a proof binds.

```rust
// the wrappers. `prover::prove_block` and `verifier::verify_block` remain the
// protocol entry points; these save a caller the eight-step preamble and nothing else.
pub fn setup(elf: &[u8], params: &ProgramParams, srs: Srs) -> Result<ProverSetup, String>;
pub fn prove(setup: &ProverSetup, io: &GuestIo) -> Result<Proven, String>;
pub fn verify(vk: &VerifyingKey, block: &BlockProof) -> Result<(), VerifyError>;
pub struct Proven { pub block: BlockProof, pub archive: TraceArchive, pub exit_code: i32,
                    pub cycles: u64, pub journal: Vec<u8>, pub wall_nanos: u64 }

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
    // the stateless pass: the trie nodes that AUTHENTICATE a touch set. Not a
    // complete stateless witness -- see below.
    pub fn collect_nodes(rpc: Rpc, at: u64, witness: &BlockWitness)
        -> Result<(Vec<Vec<u8>>, u64, u64), String>;
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
    pub enum Mode { Mini, Stateless }              // Mode::binary() names the guest binary
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
- **`prove` times the executor, and that is the one thing it adds.** S12 froze a per-phase
  wall-clock field on the trace archive's post-execution section and **every caller in the
  repository passed zero**, because nothing timed `trace_run`. S25's must-be-exact 5 wants
  the bench report's per-stage timings to come from those sections rather than from
  stopwatches inside the prover, so the execution phase's number has to be real, and this
  is the one place on the proving path that runs the executor.
- **`prove` does not check the exit status.** A failing guest is still a provable execution
  and its journal is still bound; whether exit 0 was required is the caller's statement to
  make, and `Proven::exit_code` is how it makes it.
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
  repository already spawns `cargo`, `qemu-riscv32` and `llvm-objdump`. It is an undeclared
  host tool of the same class, reachable only from the manual refresh.
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

## `collect_nodes` authenticates; it does not complete
`docs/spec/revm-block.md` §1.5 requires a stateless witness's `nodes` to carry every node
needed to apply the block's updates **deterministically**, siblings and boundary nodes
included, and the guest to authenticate each against the trie hash that names it before
using it. `collect_nodes` returns what `eth_getProof` can give, which is the nodes on each
touched key's own path — enough to *authenticate* every recorded value, and **not** enough
to *update*.

The gap is a deletion. Removing a key whose branch is left with one child needs that
child's type and path to merge into, and the child is a *sibling* of the deleted key, so it
lies on no touched key's path. Measured at 29 % of randomised trials, and common in
practice because writing zero to a storage slot is a deletion. This endpoint cannot close
it: `debug_executionWitness` is not served, `debug_dbGet` answers `pebble: not found` for a
node hash under Geth's path-based state scheme, and `eth_getProof` takes a preimage.

So the two halves of the stateless mode are tested against two different things, and
`tests/stateless.rs` says which is which: **authentication** runs on the pinned
mini-block's real nodes against block 26,057,508's **real** state root, and the **whole
transition** runs on a synthetic block whose node set is complete by construction. Neither
is a substitute for the other.

## The fixtures
`tests/vectors/`, and `docs/spec/revm-block.md` §1.3 is the normative account.

| file | committed | what |
| --- | --- | --- |
| `mini-block.json` | yes | the `Pin`: the block, its roots, and the SHA-256 of the other two |
| `mini-block-witness.bin` | yes | the `BlockWitness`, `postcard`, the guest's advice |
| `mini-block-journal.bin` | yes | what native revm makes of it |
| `mini-block-nodes.bin` | yes | a `StatelessWitness` whose `nodes` authenticate the touch set against the **real** parent state root |
| `rpc-cache/` | yes | the content-addressed snapshot that re-records the pinned block |

The refresh is `cargo run -p kat-gen -- block`, which needs `ETH_RPC_URL` and is **not** in
`DEFAULT_GROUPS` — the same opt-in the `guests` group has, and what keeps CI off the
network. A session records the pinned block, checks three further recent blocks live
(acceptance 2's repeated-blocks check, cached under `target/` and never committed), and
re-records the pinned one from the cache alone to prove the recording deterministic.

## Tests
| File | What |
| --- | --- |
| `tests/mpt.rs` | the trie: Ethereum's three published root vectors (empty, `dogglesworth`, `horse`), order- and delete-invariance over every permutation, a sparse rebuild from every prefix of its own nodes, and each refusal separately — a missing node is not an absence, a blinded collapse names its hash, every canonical-form rule refuses. 16 tests |
| `tests/stateless.rs` | acceptance 7: 17 real mainnet accounts and 37 real slots authenticated against the real parent state root, every one of 210 real nodes corrupted in turn and refused, every one dropped in turn and refused **as missing rather than as absent**; then the synthetic transition — the pinned root recomputed, every node corrupted, every balance corrupted, and the two system-contract addresses against their EIPs. 9 fast, 2 `#[ignore]`d for the guest |
| `tests/prove.rs` | **`#[ignore]`d** — the mini-block gate (acceptance 4) and the advice tamper twin (acceptance 5) |
| `tests/witness.rs` | acceptance 1 (two cache-only recordings, byte-identical, zero network calls, equal to the committed fixture), acceptance 2's native half (the witness alone reproduces the pinned journal), acceptance 3 twice (every recorded slot deleted in turn, and every recorded account, each refused), the fixture against its pin, the fork table both ways, the journal against the public window's ceiling, and a one-wei balance change moving the journal |

**The journal does not distinguish every witness, and that is a fact about the workload
rather than a gap.** On the pinned mini-block, one of thirty-seven recorded slots is read
by the callee and then overwritten unconditionally, so its original value reaches nothing
observable and changing it leaves the journal identical. A balance is the cell to move in
a test that wants a guaranteed difference: every touched account's balance and nonce are
in the output commitment's post-state summary verbatim.
