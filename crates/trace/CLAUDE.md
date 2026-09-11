# `crates/trace`

## What this crate owns
The data an execution leaves behind, and nothing that produces it: the memory event log
with its last-access bookkeeping and self-check, the per-family trace buffers, the cycle
profile and the shard plan, and the `TraceArchive` that snapshots them. `crates/emulator`
is the only producer. **`docs/spec/execution-trace.md` is normative** for every value
here — the clock, the address spaces, the frame of each instruction class, the x0 rule,
the ecall frame and the order of the log.

```rust
pub enum AddressSpace { Reg, Ram, Pc }            // tags: constants::address_space, 1 2 3
pub struct MemoryEvent { pub space: AddressSpace, pub addr: u32, pub ts: u64,
                         pub read_ts: u64, pub read_value: u32, pub write_value: u32 }
pub struct FinalValue { pub space: AddressSpace, pub addr: u32, pub ts: u64, pub value: u32 }
pub struct SelfCheckError { pub space: AddressSpace, pub addr: u32, pub ts: u64, pub reason: String }
impl MemoryEventLog {
    pub fn new() -> MemoryEventLog;
    pub fn record(&mut self, space, addr, ts, read_value, write_value) -> MemoryEvent;
    pub fn from_events(events: Vec<MemoryEvent>) -> MemoryEventLog;
    pub fn events(&self) -> &[MemoryEvent];
    pub fn touched_addresses(&self) -> Vec<(AddressSpace, u32)>;   // sorted
    pub fn final_state(&self) -> Vec<FinalValue>;                   // sorted: last write per address
    pub fn self_check(&self, image: &ProgramImage) -> Result<(), SelfCheckError>;
}

pub enum Role { Rs1, Rs2, Arg1, Arg2, Load, Ram, Rd }
pub const ROLES: [Role; 7];                           // the frozen in-cycle order
pub struct Query { pub addr: u32, pub read_ts: u64, pub read_value: u32, pub write_value: u32 }
pub struct Row { pub cycle: u64, pub pc: u32, pub next_pc: u32, pub present: u8, pub queries: [Query; 7] }
pub struct QueryColumns { pub addr: Vec<u32>, pub read_ts: Vec<u64>, pub read_value: Vec<u32>, pub write_value: Vec<u32> }
pub struct FamilyTrace { pub family: FamilyId, pub height: u32, pub cycle: Vec<u64>, pub pc: Vec<u32>,
                         pub next_pc: Vec<u32>, pub present: Vec<u8>, pub queries: [QueryColumns; 7] }
pub struct FamilyTraces { pub families: Vec<FamilyTrace> }

pub struct CycleProfile { pub counts: Vec<(FamilyId, u64)> }
pub struct ShardPlan { pub shards: Vec<(FamilyId, u32)> }
pub fn plan_shards(profile: &CycleProfile, config: &VmConfig) -> ShardPlan;

pub enum Phase { PostExecution, PostCommit, PostGkr, PostOpening, Final }   // tags 0..5
pub struct PhaseTiming { pub wall_nanos: u64 }
pub struct IoStreams { pub input: Vec<u8>, pub output: Vec<u8> }
impl TraceArchive {
    pub fn from_execution(FamilyTraces, MemoryEventLog, CycleProfile, IoStreams, PhaseTiming) -> TraceArchive;
    pub fn family_traces(&self) -> &FamilyTraces;  pub fn memory_log(&self) -> &MemoryEventLog;
    pub fn cycle_profile(&self) -> &CycleProfile;  pub fn io_streams(&self) -> &IoStreams;
    pub fn is_filled(&self, Phase) -> bool;        pub fn timing(&self, Phase) -> Option<PhaseTiming>;
    pub fn deterministic_payload(&self) -> Vec<u8>;
    pub fn export(&self, w: impl Write) -> Result<(), String>;
    pub fn import(r: impl Read) -> Result<TraceArchive, String>;
}
```

## Frozen invariants
- **The event schema.** One event per query: space, address, write timestamp, read
  timestamp, read value, write value. A read writes back what it read. The log is a flat
  vector in timestamp order — cycle order, and inside a cycle the pc query then the
  roles in `ROLES` order. The last-access tables (a 32-entry array for the registers, an
  `Option` for the pc, a hash map keyed by RAM word address) fill each new event's read
  side and are never serialized; `from_events` rebuilds them.
- **`record` panics on a broken invariant**: an address outside its space, a timestamp
  past 38 bits or out of order, a read that does not strictly precede its write, or a
  machine read that disagrees with the last write — the emulator and the log disagreeing
  about memory is not something a guest can cause.
- **`self_check` is the memory argument at trace level.** Timestamp rules first (every
  address in its space, every timestamp on the clock, every gap non-negative, one query
  per address per timestamp), then multiset balance: init (timestamp 0, value from the
  image) plus every write, against every read plus teardown (each address's last write,
  taken from the log). It names the query where the fault is observed — the one that
  reads a value no write produced. A changed *final* value balances by construction, as
  in the argument, where teardown is bound by something else.
- **Family buffers are raw live rows, column-major, in small types.** No padding and no
  polynomial: a padding row's content and a column's multilinear form belong to the
  constraint system, which S12 does not have. A row holds every value its cycle's
  queries carried — address, read timestamp, read value, write value per role — so a
  later witness fill reads the buffer rather than re-joining the log. `present` says
  which roles the cycle has; an absent role is `Query::ABSENT`, all zero. The pc query's
  read timestamp is not stored: it is always `4 * (cycle - 1)`.
- **The frozen column names** are `cycle`, `pc`, `next_pc`, `present`, then for each
  role in `ROLES` order `rs1.addr` `rs1.read_ts` `rs1.read_value` `rs1.write_value` …
  through `rd.write_value`: the fields of `FamilyTrace` and `QueryColumns`. Append-only.
- **`FamilyTraces` has one buffer per `VmConfig` family, in its order**, the ones the run
  never reached included, and `CycleProfile` one count per buffer; the counts sum to the
  cycle count, transfer cycles included.
- **`plan_shards` is `ceil(occupancy / height)`**, a pure function, zero for a family that
  never ran. Init/teardown counts 0 cycles and so plans 0 shards here; its occupancy is
  addresses, not cycles, and the stage that builds it decides what it is.
- **The archive container.** Two `postcard` values back to back: the payload section —
  five `(phase tag, Option<bytes>)` entries, phases in order — then the timing section,
  five `(phase tag, Option<wall_nanos>)`. The deterministic payload is exactly the first
  value's bytes, so timing is outside it by construction. Filled phases are a prefix,
  post-execution always among them; a phase is timed exactly when it is filled; import
  refuses anything else. The post-execution content's own layout is in
  `src/archive.rs`'s module docs. Later phases are opaque bytes here. No compression.
- **`export` and `import` take `impl Write` and `impl Read`** because the stage prompt
  froze those signatures; master anti-goal 2 would not have written them, and the S12
  handoff records it.
- **serde is featureless**, so reading a `Vec` goes through one hand-written visitor,
  `Seq<T>`, which reserves at most 4096 elements before any arrive — a hostile length
  costs nothing until the bytes are there to back it.

## Tests
| File | What |
| --- | --- |
| `src/archive.rs` (unit) | an in-order later phase accepted; out-of-order, timing without content, content without timing, and trailing bytes refused |
| `tests/plan.rs` | acceptance 9: occupancy 0 / 1 / height / height+1 → 0 / 1 / 1 / 2 at every menu height, zero-occurrence families, the whole 38-bit clock at 2^16, purity, a mismatched profile refused |

The self-check, the buffers and the archive are exercised over real executions in
`crates/emulator/tests/{trace,archive}.rs`, which is where executions exist.
