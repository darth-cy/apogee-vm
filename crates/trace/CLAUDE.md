# `crates/trace`

## What this crate owns
The data an execution leaves behind, and nothing that produces it: the memory event log
with its last-access bookkeeping and self-check, the per-family trace buffers, the cycle
profile and the shard plan, the `TraceArchive` that snapshots them, and the memory
argument's columns filled from the log. `crates/emulator` is the only producer.
**`docs/spec/execution-trace.md` is normative** for every value here — the clock, the
address spaces, the frame of each instruction class, the x0 rule, the ecall frame and the
order of the log — **`docs/spec/memory.md`** for the memory columns, and
**`docs/spec/lookup.md` §7** for the multiplicity columns.

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
pub fn init_windows(log: &MemoryEventLog, height: u32) -> Vec<u32>;   // ZERO_WINDOWS' shard list

// src/memory.rs, docs/spec/memory.md §2.1, §2.4, §3.4, §4.1; columns keyed by constraints::memory
pub fn build_memory_columns(log: &MemoryEventLog, queries: &[usize], cycles: &[u64], height: usize)
    -> Vec<(PolyAddress, MultilinearPoly)>;                    // the frame's 1 + 5w M columns
pub fn build_frame_witness(log: &MemoryEventLog, queries: &[usize], cycles: &[u64], height: usize)
    -> Vec<(PolyAddress, MultilinearPoly)>;                    // its w + 3 W columns
pub fn build_init_teardown_columns(log: &MemoryEventLog, image: &ProgramImage, ram_window: u32,
    height: usize) -> Vec<(PolyAddress, MultilinearPoly)>;          // M[0], M[1]; S[0] at window 0
pub fn build_boundary_finals(log: &MemoryEventLog) -> BoundaryFinals;   // gkr_verify's

// docs/spec/lookup.md §7
pub fn build_multiplicities(artifact: &CircuitArtifact, columns: &[(PolyAddress, MultilinearPoly)],
                            specs: &[ChannelSpec]) -> Result<Vec<(PolyAddress, MultilinearPoly)>, String>;
pub fn check_multiplicities(artifact, columns, specs, given) -> Result<(), String>;

pub enum Phase { PostExecution, PostCommit, PostGkr, PostOpening, Final }   // tags 0..5
pub struct PhaseTiming { pub wall_nanos: u64 }
pub struct IoStreams { pub input: Vec<u8>, pub output: Vec<u8> }
impl TraceArchive {
    pub fn from_execution(FamilyTraces, MemoryEventLog, CycleProfile, IoStreams, PhaseTiming) -> TraceArchive;
    pub fn family_traces(&self) -> &FamilyTraces;  pub fn memory_log(&self) -> &MemoryEventLog;
    pub fn cycle_profile(&self) -> &CycleProfile;  pub fn io_streams(&self) -> &IoStreams;
    pub fn is_filled(&self, Phase) -> bool;        pub fn timing(&self, Phase) -> Option<PhaseTiming>;
    pub fn fill(&mut self, Phase, content: Vec<u8>, PhaseTiming) -> Result<(), String>;   // S16
    pub fn content(&self, Phase) -> Option<&[u8]>;                                        // S16
    pub fn deterministic_payload(&self) -> Vec<u8>;
    pub fn export(&self, w: impl Write) -> Result<(), String>;
    pub fn import(r: impl Read) -> Result<TraceArchive, String>;
}
```

## Frozen invariants
- **A multiplicity is counted over raw gated tuples, never over a compressed one.** It is
  committed before `g` and `β` are drawn (`docs/spec/lookup.md` §2), so nothing in
  `build_multiplicities` reads a challenge. One counter per channel per table row,
  incremented once per lookup expression on each row, the rows their selector switches off
  included; a tuple at several table rows credits the **lowest**; and a tuple the table
  does not hold is a build error, because the honest prover cannot balance over one.
- **The event schema.** One event per query: space, address, write timestamp, read
  timestamp, read value, write value. A read writes back what it read. The log is a flat
  vector in timestamp order — cycle order, and inside a cycle the pc query then the
  roles by slot and then by role number, which today is exactly `ROLES` order; a role
  appended later takes its place by slot and renumbers nothing. The last-access tables (a 32-entry array for the registers, an
  `Option` for the pc, a hash map keyed by RAM word address) fill each new event's read
  side and are never serialized; `from_events` rebuilds them.
- **`record` panics on a broken invariant**: an address outside its space, a timestamp
  past 38 bits or out of order, a read that does not strictly precede its write, or a
  machine read that disagrees with the last write — the emulator and the log disagreeing
  about memory is not something a guest can cause.
- **`self_check` is the memory argument at trace level.** Timestamp rules first (every
  address in its space, every timestamp on the clock, the events in timestamp order,
  every gap non-negative, one query per address per timestamp), then multiset balance:
  init (timestamp 0, value from the image — `ProgramImage::initial_word` for a RAM word —
  never from the log) plus every write, against
  every read plus teardown (each address's last write, taken from the log). When the
  balance fails it replays the unbalanced address and names the first query whose read
  is not the last write before it — the corrupted read, the reader of a corrupted write,
  or a stale read, never the honest reader beside it. **Its blind spot is everything
  after an address's last honest query** — a final value changed, a final query moved or
  added, trailing cycles removed — by the argument's own shape; for a snapshot the
  archive binds the log to the rows.
- **Family buffers are raw live rows, column-major, in small types.** No padding and no
  polynomial: a padding row's content and a column's multilinear form belong to the
  constraint system, and the memory builders below, not the buffers, fill them. A row
  holds every value its cycle's queries carried — address, read timestamp, read value,
  write value per role — so a later witness fill reads the buffer rather than re-joining
  the log. `present` says
  which roles the cycle has; an absent role is `Query::ABSENT`, all zero. The pc query's
  read timestamp is not stored: it is always `4 * (cycle - 1)`.
- **The frozen column names** are `cycle`, `pc`, `next_pc`, `present`, then for each
  role in `ROLES` order `rs1.addr` `rs1.read_ts` `rs1.read_value` `rs1.write_value` …
  through `rd.write_value`: the fields of `FamilyTrace` and `QueryColumns`. Append-only.
- **`FamilyTraces` has one buffer per `VmConfig` family, in its order**, the ones the run
  never reached included, and `CycleProfile` one count per buffer; the counts sum to the
  cycle count, transfer cycles included.
- **`plan_shards` is `ceil(occupancy / height)`**, a pure function, zero for a family that
  never ran. `INIT_TEARDOWN` and `ZERO_WINDOWS` count 0 cycles and so plan 0 shards here;
  their rows are addresses, not cycles, and the prover assembles exactly 1 `INIT_TEARDOWN`
  shard (RAM window 0) and `init_windows(log, h).len()` `ZERO_WINDOWS` shards.
- **`init_windows(log, h)` is `ZERO_WINDOWS`' shard list**: the distinct `addr / 4h` of
  every touched RAM word, ascending, without window 0 (`docs/spec/memory.md` §3.4). `h`
  is the two init families' one height.
- **The memory columns are `docs/spec/memory.md`'s, keyed by `constraints::memory`'s
  layout**, which is the one place the layout lives. `build_memory_columns` and
  `build_frame_witness` fill one row per cycle of `cycles` — a shard's, in the order given —
  from one pass over the log, then zero rows to `height`: a query the cycle lacks and a
  padding row are 0 in every column, `cycle` included. The pc query's fields are its
  event's: address 0, the pc read, `next_pc` written, the previous pc write's timestamp.
  A cycle the log lacks or `cycles` repeats panics, naming it.
- **`queries` is the family's query list**, `constraints::memory::frame_queries(family)`,
  and a column's position is a **slot** in that list, not a query id. A family's frame
  holds only the queries its instructions can make, so the builders must be handed that
  family's list; an event with no free slot panics, naming the cycle, the space and the
  slot, which is how a frame too narrow for what it is filled with fails loudly instead
  of dropping the event. `crates/trace/tests/memory.rs` holds `frame_queries` to
  `program::row_kind` over all 59 instructions.
- **An event takes the first free frame query of its space and slot.** Only the three
  slot-2 register roles share both, and they fill in log order, `rs2`, `arg1`, `arg2`.
  That is exact because an ecall's arguments are a prefix of `a0, a1, a2` and no other
  row reads `arg1` (`docs/spec/execution-trace.md` §6); no gate could tell the three apart,
  so `crates/checker/tests/memory.rs` holds the columns to the family buffers, which file
  by role. An ecall reading `a1` without `a0` would break it.
- **A column takes the narrowest backing its largest value fits**: `U1`, `U8`, `U16`,
  `U32`, or `Fr` for a timestamp past 32 bits; `rd_inv` is always `Fr`.
- **`build_init_teardown_columns` is §3.4's table**, per row `y` at `4h·w + 4y`: 0 on
  window 0's rows below `2^14`; a touched word's last write; an untouched word's
  `image.initial_word`; plus `program::image_init_column` as `S[0]` for window 0. The
  window is `ram_window`, never `window`. **`build_boundary_finals` panics unless the pc's
  final value is `HALT_PC` and `x0`'s is 0**: the verifier fixes both, and a log that did
  not end on an exit row has no statement.
- **Why the dependencies**: `constraints` for the layout that keys every column,
  `gkr-verify` for `BoundaryFinals`, `poly` and `field` for a column's form. None of them
  depends on `trace`.
- **The archive container.** Two `postcard` values back to back: the payload section —
  five `(phase tag, Option<bytes>)` entries, phases in order — then the timing section,
  five `(phase tag, Option<wall_nanos>)`. The deterministic payload is exactly the first
  value's bytes, so timing is outside it by construction. Filled phases are a prefix,
  post-execution always among them; a phase is timed exactly when it is filled; import
  refuses anything else. The post-execution content's own layout is in
  `src/archive.rs`'s module docs. Later phases are opaque bytes here, filled by the prover
through `fill` — which refuses post-execution, a phase already filled and one whose
predecessor is empty, so the prefix rule holds in memory as it does on import — and read
back through `content`; their schemas are `docs/spec/shard-proof.md` §10. No compression.
- **The reader takes exactly what the writer writes.** A snapshot's parts must agree —
  every buffer well formed (a family `constants::family` has, and one that claims a pc —
  the two init families claim none, so their buffers are empty — one column length, height on the
  menu, no unknown role, an absent role all zero, families ascending), the profile
  counting the buffers, the rows'
  cycles `1..=n` each once, every event in its space and on the clock, and the log
  exactly the one the rows rebuild — and `from_execution` applies the same rule, so every
  archive that can be built can be read back. A file must also be the canonical
  encoding of the archive it decodes to: `postcard` reads overlong varints, and one
  archive must be one byte string for the payload boundary to mean anything.
- **`export` and `import` take `impl Write` and `impl Read`** because the stage prompt
  froze those signatures; master anti-goal 2 would not have written them, and the S12
  handoff records it.
- **serde is featureless**, so reading a `Vec` goes through one hand-written visitor,
  `Seq<T>`, which reserves at most 4096 elements before any arrive — a hostile length
  costs nothing until the bytes are there to back it.

## Tests
| File | What |
| --- | --- |
| `src/archive.rs` (unit) | `fill` keeping the phases a prefix: post-execution, a refill and an out-of-order phase refused, each later phase's content and timing read back; `content` panicking on post-execution; an in-order later phase accepted; out-of-order, timing without content, content without timing, trailing bytes and an overlong varint refused; every one of the reader's fifteen part-disagreement refusals (a buffer of rows for each init family among them), a mis-tagged section and bytes after the post-execution content refused as a named `Err`, never a panic, beside the untouched content; the constructor refusing parts that disagree |
| `tests/log.rs` | the address-space tags against `constants::address_space`, and exactly which addresses each space has |
| `tests/plan.rs` | acceptance 9: occupancy 0 / 1 / height / height+1 → 0 / 1 / 1 / 2 at every menu height, zero-occurrence families (both init families among them), the whole 38-bit clock at 2^16, purity, a mismatched profile refused |
| `tests/memory.rs` | `constraints::memory`'s query table against `Role` in `ROLES` order, the pc query first, names included; **every family's frame equal to the union of its instructions' queries**, taken over all 59 `Instr` variants with the per-instruction queries written from `execution-trace.md` §4 and the routing from `program::row_kind`, so the two tables cannot drift; the finals of a hand-written two-cycle log; `build_boundary_finals` refusing a pc that does not end at `HALT_PC` and a nonzero `x0`; `build_memory_columns` refusing a cycle the log lacks; `build_frame_witness`' gap columns at the chunk's edge, gaps `2^19 − 1`, `2^19` and `2^19 + 3`; a RAM write at `4h`, the first word of window 1, in window 1's columns alone |

The self-check, the buffers, `init_windows` and the archive are exercised over real
executions in `crates/emulator/tests/{trace,archive}.rs`, which is where executions exist;
the memory builders, held to the circuits and to the family buffers, in
`crates/checker/tests/memory.rs`.
