This is an extra build stage that's not in the original build stage set. This is a stage that deals with cycle reduction. 

In the previous stage S25, the mini block run modes returned astronomical cycle numbers and resource requirements for full block proving. As a result, the full block proving is delayed. Here're the steps in this stage we'll take to address this:

## Step 1: Streaming scheme for the prover
Crude idea: first do an initial execution and as soon as memory column fills for a sub-circuit family, turn it into Mercury commitment, discard the memory column. Then global challenges are drawn from these commitments. Then, execute the block a second time (repeat), this time as soon as the trace for a sub-family fills, dispatch a proving job for that family. 

```
PASS 1 — EXECUTE + PRECOMMIT

execute guest
   ↓
one active partial shard buffer per family
   ↓ whenever family shard fills
construct its M columns
   ↓
Mercury commit M
   ↓
save only commitment
   ↓
discard M + completed shard buffer

end execution
   ↓
finish partial shards + RAM windows
   ↓
statement now has:
  public I/O
  shard counts
  boundary
  all M commitments
   ↓
global transcript
   ↓
derive global memory challenges
```

Then,
```
PASS 2 — REEXECUTE + PROVE

execute identical guest again
   ↓
one active partial shard per family
   ↓ whenever shard fills
construct full M + W + S
   ↓
(optional but valuable)
recommit M and assert == pass-1 commitment
   ↓
GKR + Mercury opening
   ↓
write ShardProof / roots
   ↓
discard entire shard
```

One critical requirement: the proving-job queue must have backpressure. If execution generates shards faster than workers prove them and you simply queue full columns in RAM, you've recreated the same problem. For Step 1, the goal is to change prover scheduling/materialization only, not the proof statement or transcript semantics. Pass 1 must produce the exact ordered set of per-shard memory commitments that the current monolithic statement_inputs/global_commit_phase would have produced. Pass 2 must deterministically regenerate the same shard boundaries. Completed shard data should never accumulate between the executor and proving workers. The allowed live state should be approximately: one partial shard per family + bounded N proving jobs + transcript/commitment metadata + necessary global RAM-window state — not “all shards but compressed differently.”

## Step 2: Profile for More Precompiles/Delegation for cycle reduction
Construct an ultra lightweight profiler that determines which new precompiles/delegation circuits will be the most impactful. This is directly targeting Ethereum block execution. Potential top candidates include: Big-integer / U256 arithmetic, Keccak / SHA-256, Elliptic-curve crypto (secp256k1, BN254), MULMOD/MODEXP, etc. For this new tool, profile a few latest blocks. You shouldn't even invoke anything proving related with this type of profiling. Document the profiling tool, generate reports and make recommendations for top candidate precompiles/delegations.

We want attribution of guest RV32 cycles to semantic workloads, because something like U256 multiplication may manifest as hundreds of RV32 instructions spread through revm. The profiler should answer questions like:
- how many cycles are spent in 256-bit arithmetic?
- hashing by algorithm?
- secp256k1 / BN254 operations?
- memory copying / RLP / trie work?
- interpreter/REVM dispatch overhead?
- existing Apogee delegations versus ordinary RV32 execution?
And report both absolute cycles and percentage of total block execution, plus an estimate of the maximum theoretically removable cycles for each candidate. 

## Step 3: We write the top impactful precompile for cycle reduction. Potentially we also write the next two top candidates.
Sequentially, not simultaneously. Checkpoint after each implementation using the mini block run profiling. Make sure the guest routes all relevant operations through available precompile accelerations. After each accelerator, rerun the exact same pinned mini-block and profiler workload. Report guest cycles, cycles/gas, shard counts by family, wall time, and delta versus the previous checkpoint. 

After all implementations are finished, do a mini block prover run, this time on dev server. If one is not present, provision one using instructions in `../apogee-aws`.