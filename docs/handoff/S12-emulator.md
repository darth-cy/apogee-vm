# S12 — Emulator + trace generation

Branch `s12-emulator`. Status: complete, all eleven acceptance items met. Every
deviation below was put to the repository owner before it was built.

The normative document written this stage is **`docs/spec/execution-trace.md`**: the
timestamp convention, the address spaces, the frame of every instruction class, the x0
rule, the ecall frame and the order of the log. S14's memory-argument fill and S16's
ecall-row constraints cite it. The design records are `crates/emulator/CLAUDE.md` and
`crates/trace/CLAUDE.md`. This note is the frozen API, the artifacts, the numbers and
the deviations.

---

## Read these first

1. **Cycles are numbered from 1.** Timestamp 0 is the initial write of every address,
   and a query's read must strictly precede its write; a cycle-0 pc query would write at
   timestamp 0, which cannot strictly follow the initial write it reads. So the first
   cycle occupies timestamps 4–7, the gap of its pc read is 3, and an execution's cycle
   count is its last cycle's number. Nothing in the prompt says this, and the arithmetic
   forces it.
2. **`trace_run` returns four things, not three**: `(FamilyTraces, MemoryEventLog,
   CycleProfile, Execution)`. The frozen constructor `TraceArchive::from_execution` needs
   the fd 0/1 streams, and none of the prompt's three types carries them. The owner chose
   returning the `Execution` over a second execution pass or rebuilding the streams from
   the log.
3. **Family buffers are raw live rows, not polynomials.** The prompt asked for
   `MultilinearPoly` exports while forbidding buffers to invent padding; a multilinear
   needs a power-of-two length, so one of the two had to give. The owner's answer: keep
   raw live rows in small types, with enough data per row to fill any evaluation vector
   later, and build polynomials once the constraint system exists. So each row holds
   every value its cycle's queries carried — address, read timestamp, read value, write
   value, per role — beside `cycle`, `pc`, `next_pc` and a `present` mask.
4. **One coverage guest, not one guest per opcode.** `guests/opcodes` executes every
   RV32IMAC instruction; the owner judged 59 single-opcode programs wasteful. A test
   checks that all 58 non-trapping mnemonics really execute, and the differential names
   the pc of any disagreement, so a failure still points at one instruction.

---

## Frozen public API, as built

```rust
// crates/emulator/src/lib.rs   (std)
pub struct GuestIo { pub input: Vec<u8>, pub hint: Vec<u8> }
pub struct Execution { pub regs: [u32; 32], pub exit_code: i32, pub cycle_count: u64,
                       pub io: IoStreams, pub stderr: Vec<u8> }
pub enum EmuError {
    NotAnInstruction { pc: u32 },
    IllegalInstruction { pc: u32, word: u32 },
    Ebreak { pc: u32 },
    Misaligned { pc: u32, addr: u32, width: u32 },
    OutOfBounds { pc: u32, addr: u32 },
    ClockOverflow { cycle: u64 },
}   // + Display
pub fn run(image: &ProgramImage, io: &GuestIo) -> Result<Execution, EmuError>;
pub fn trace_run(image: &ProgramImage, io: &GuestIo, tables: &DecodedTables, config: &VmConfig)
    -> Result<(FamilyTraces, MemoryEventLog, CycleProfile, Execution), EmuError>;

// crates/emulator/src/qemu.rs — the differential harness
pub const QEMU_FLAGS: [&str; 3];           // "-one-insn-per-tb", "-d", "nochain,cpu"
pub struct Divergence { pub instruction: &'static str, pub rule: &'static str, pub reason: &'static str }
pub const WHITELIST: [Divergence; 1];      // sc.w
pub struct Record { pub pc: u32, pub regs: [u32; 32] }
pub struct Step { pub pc: u32, pub regs: [u32; 32], pub instr: Instr, pub writes: u32 }
pub struct Agreement { pub records: usize, pub sc_w_whitelisted: usize }
pub struct Mismatch { pub index: usize, pub pc: u32, pub reg: Option<usize>, pub reason: String }
pub fn parse_log(text: &str) -> Result<Vec<Record>, String>;
pub fn emulator_steps(image: &ProgramImage, log: &MemoryEventLog) -> Vec<Step>;
pub fn compare(steps: &[Step], records: &[Record]) -> Result<Agreement, Mismatch>;
```

```rust
// crates/trace/src/   (std)
pub enum AddressSpace { Reg, Ram, Pc }      // tag(), from_tag(), holds()
pub struct MemoryEvent { pub space, pub addr: u32, pub ts: u64, pub read_ts: u64,
                         pub read_value: u32, pub write_value: u32 }   // cycle(), delta()
pub struct FinalValue { pub space, pub addr: u32, pub ts: u64, pub value: u32 }
pub struct SelfCheckError { pub space, pub addr: u32, pub ts: u64, pub reason: String }
impl MemoryEventLog {
    pub fn new() -> MemoryEventLog;
    pub fn record(&mut self, space, addr, ts, read_value, write_value) -> MemoryEvent;
    pub fn from_events(events: Vec<MemoryEvent>) -> MemoryEventLog;
    pub fn events(&self) -> &[MemoryEvent];
    pub fn touched_addresses(&self) -> Vec<(AddressSpace, u32)>;
    pub fn final_state(&self) -> Vec<FinalValue>;
    pub fn self_check(&self, image: &ProgramImage) -> Result<(), SelfCheckError>;
}
pub enum Role { Rs1, Rs2, Arg1, Arg2, Load, Ram, Rd }   // delta(), space()
pub const ROLES: [Role; 7];
pub struct Query { pub addr: u32, pub read_ts: u64, pub read_value: u32, pub write_value: u32 }
pub struct Row { pub cycle: u64, pub pc: u32, pub next_pc: u32, pub present: u8, pub queries: [Query; 7] }
pub struct QueryColumns { pub addr: Vec<u32>, pub read_ts: Vec<u64>, pub read_value: Vec<u32>, pub write_value: Vec<u32> }
pub struct FamilyTrace { pub family: FamilyId, pub height: u32, pub cycle: Vec<u64>, pub pc: Vec<u32>,
                         pub next_pc: Vec<u32>, pub present: Vec<u8>, pub queries: [QueryColumns; 7] }
impl FamilyTrace { pub fn new(..); pub fn len(&self) -> usize; pub fn push(&mut self, &Row); pub fn row(&self, i) -> Row; }
pub struct FamilyTraces { pub families: Vec<FamilyTrace> }   // family(id)
pub struct CycleProfile { pub counts: Vec<(FamilyId, u64)> } // total()
pub struct ShardPlan { pub shards: Vec<(FamilyId, u32)> }
pub fn plan_shards(profile: &CycleProfile, config: &VmConfig) -> ShardPlan;
pub enum Phase { PostExecution = 0, PostCommit = 1, PostGkr = 2, PostOpening = 3, Final = 4 }
pub const PHASES: [Phase; 5];
pub struct PhaseTiming { pub wall_nanos: u64 }
pub struct IoStreams { pub input: Vec<u8>, pub output: Vec<u8> }
impl TraceArchive {
    pub fn from_execution(traces: FamilyTraces, log: MemoryEventLog, profile: CycleProfile,
                          io: IoStreams, timing: PhaseTiming) -> TraceArchive;
    pub fn family_traces(&self) -> &FamilyTraces;
    pub fn memory_log(&self) -> &MemoryEventLog;
    pub fn cycle_profile(&self) -> &CycleProfile;
    pub fn io_streams(&self) -> &IoStreams;
    pub fn is_filled(&self, phase: Phase) -> bool;
    pub fn timing(&self, phase: Phase) -> Option<PhaseTiming>;
    pub fn deterministic_payload(&self) -> Vec<u8>;
    pub fn export(&self, w: impl Write) -> Result<(), String>;
    pub fn import(r: impl Read) -> Result<TraceArchive, String>;
}
```

```rust
// crates/constants/src/lib.rs   (additions; still zero logic)
pub mod ecall { pub const EBADF: u32 = 9; }                          // appended
pub mod address_space { pub const REG: u8 = 1; pub const RAM: u8 = 2; pub const PC: u8 = 3; }
pub mod memory { pub const TS_STEP: u64 = 4; pub const TS_BITS: u32 = 38; }
```

## What this freezes for every later stage

1. **The timestamp convention**, `docs/spec/execution-trace.md` §1–§7: `ts = 4·cycle +
   Δ`, cycles from 1, the 38-bit clock and its fatal error, the per-class frame, the
   slot-sharing rule, the x0 rule, the ecall frame, the transfer cycles and their place
   before the ecall row, and the order of events inside a cycle.
2. **The event schema** and **the address-space tags** 1/2/3, RAM word-granular at the
   aligned byte address.
3. **The family-buffer contract**: one row per cycle, the frozen column names (`cycle`,
   `pc`, `next_pc`, `present`, then `addr`/`read_ts`/`read_value`/`write_value` per role
   in `ROLES` order), live rows only, one buffer per `VmConfig` family in its order.
4. **The trace archive container**: the payload section of five `(phase, content)`
   entries then the timing section of five `(phase, wall_nanos)`, the deterministic
   payload a byte prefix of the file, filled phases a prefix, a phase timed exactly when
   filled, post-execution's content as documented in `crates/trace/src/archive.rs`.
5. **`CycleProfile` and `plan_shards`**, `ceil(occupancy / height)`.
6. **The QEMU invocation, the entry-state rule and the whitelist format** —
   instruction, rule, reason — with one entry.
7. **The ABI additions** in `docs/spec/ecall-abi.md` §4: `-EBADF` for a descriptor a call
   does not have, `read` returning what the stream has, a buffer outside RAM a fatal
   error, and the recorded fd 0 stream being the bytes consumed.

## Artifacts

| Path | What |
| --- | --- |
| `docs/spec/execution-trace.md` | the timestamp convention, normative |
| `crates/loader/tests/vectors/opcodes.elf` | `guests/opcodes`: every RV32IMAC instruction, the ebreak and misalignment modes |
| `crates/loader/tests/vectors/heap.elf` | `guests/heap`: the allocator exercise |
| `guests/opcodes/`, `guests/heap/` | their sources |

Both ELFs are pinned in `crates/loader/tests/common/mod.rs`, built by `cargo run -p
kat-gen -- guests` (which rebuilt the seven existing ELFs byte-identically) and held to
the host-loadability rules by `crates/loader/tests/layout.rs` like every other guest.

## Acceptance

| # | Item | Where | Result |
| --- | --- | --- | --- |
| 1 | QEMU differential over the suite | `emulator/tests/differential.rs` (`#[ignore]`d; CI) | every register of every instruction equal to `qemu-riscv32` 10.0.11's: `opcodes` 2,344 instructions (the one `sc.w` whitelisted), `rvc-dense` 638, `fib` 2,115, `heap` 138,359, `atomics` 22,507; exit status and fd 1 equal too |
| 2 | harness negative control | `differential.rs`, and `src/qemu.rs` unit tests | a perturbed register at three positions in fib, and a perturbed pc, each reported at exactly that instruction and register |
| 3 | self-check positive, heap traffic included | `emulator/tests/trace.rs` | fib, heap, atomics, opcodes and rvc-dense balance; heap changes over 100 heap words |
| 4 | self-check tamper twin | `trace.rs` | a RAM read, a register write, a pc write and a negative gap, each failing with the space, address and timestamp named |
| 5 | timestamp scan; `amoadd.w` fills four slots | `trace.rs` | every event of five guests on the four-slot clock; each of atomics' `amoadd.w` cycles holds slots 0–3, slot 3 shared by the RAM query and `rd` |
| 6 | routing | `trace.rs` | fib's cycles each in exactly one buffer, the family `row_kind` independently assigns its pc, counts summing to the cycle count; atomics' A cycles all and only in the atomics buffer, which its config has |
| 7 | archive round trip, determinism, answers without re-execution | `emulator/tests/archive.rs` | byte-identical export → import → export for three guests; hash-equal payloads from two runs with different timings; cycle count, occupancy, fd 0/1 and `io_digest` from the import; family rows and log rebuilt |
| 8 | five phases; out-of-order refused | `archive.rs`, `trace/src/archive.rs` | the payload ends with four present, empty sections and the timing section is pinned byte for byte; a byte-patched archive filling post-GKR before post-commit is refused beside an in-order control |
| 9 | `ShardPlan` edges | `trace/tests/plan.rs` | 0 / 1 / h / h+1 → 0 / 1 / 1 / 2 at every menu height; zero-occurrence families zero; purity |
| 10 | precompile `-ENOSYS` and fallback | `emulator/tests/guests.rs`, and `opcodes`' `cover_ecall` under the differential | echo's fallback computes the S02 permutation; `opcodes` makes the `0x500` and `0x4ff` calls, whose `a0` QEMU's matches |
| 11 | misalignment fatal in both paths | `guests.rs` | `lw`, `sw`, `lh`, `sh`, `lr.w`, `sc.w`, `amoadd.w`: `Misaligned` at that instruction from `run` and `trace_run` alike, no trace |

## Measured

Cycle counts and per-family occupancy, debug-profile guests, at the inputs the suites
use (transfer cycles included in both the count and add/sub/lui/auipc's occupancy):

| Guest | Input | Cycles | Transfers | Events | Per family |
| --- | --- | ---: | ---: | ---: | --- |
| fib | n = 24 | 2,117 | 2 | 7,190 | ADD 657 · JBS 481 · SHIFT 15 · MUL 0 · MEMW 952 · MEMSW 12 |
| heap | n = 40 | 138,364 | 5 | 463,680 | ADD 41,716 · JBS 31,654 · SHIFT 5,308 · MUL 764 · MEMW 54,175 · MEMSW 4,747 |
| opcodes | mode 0 | 2,356 | 12 | 8,231 | ADD 764 · JBS 410 · SHIFT 170 · MUL 83 · MEMW 829 · MEMSW 77 · ATOMICS 23 |
| atomics | n = 37 | 22,517 | 10 | 76,854 | … ATOMICS 409 |
| rvc-dense | x = 7 | 642 | 4 | 2,206 | |
| echo | 100 bytes | 4,635,604 | | | (software Poseidon2; `run` only) |

At the default heights every family that ran plans one shard for each of these guests,
and a family that did not run, init/teardown included, plans zero. `heap`'s allocations
start at the bottom of the heap-and-stack reservation and change more than a hundred
words there. Each trace suite runs in well under a second.

## Verification performed

VERIFICATION-RESULT

## Deviations and notes for the reviewer

Each of these was put to the owner, except where it says it was forced.

1. **`trace_run` returns the `Execution` as a fourth element** (see the top).
2. **Family buffers are raw rows, not `MultilinearPoly`s** (see the top). Must-be-exact
   7's column list is a superset of what the prompt pins: `rs1.read_value` is "the rs1
   read value", `rs2.read_value` rs2's, `rd.write_value` "the rd write value", and
   `load.read_value` / `ram.read_value` / `ram.write_value` "load/store data", with every
   address and read timestamp beside them.
3. **One coverage guest** (see the top), and a second, `guests/heap`, for the allocator
   exercise. `opcodes`' fd 0 also selects `ebreak` and seven misaligned-access modes, so
   the same guest is the misalignment fixture.
4. **The harness has one rule besides the whitelist: the entry state.** QEMU starts a
   process with Linux's stack pointer in `x2`; the emulator starts every register at 0
   (must-be-exact 10). The prompt says to normalize log formatting only and to whitelist
   SC.W only, and neither covers an executor's environment. The owner chose a named
   entry-state rule — `x2` may differ at the first record, only until the guest writes
   it, and QEMU's entry is asserted to differ from zero in `x2` alone — over skipping
   records or seeding the emulator's `sp`.
5. **`-EBADF`** for `read`/`write` on a descriptor the ABI does not give the call —
   Linux's and QEMU's answer — appended as `constants::ecall::EBADF` with a row in the ABI
   table, which the existing doc-versus-constants test now covers.
6. **The recorded fd 0 stream is the bytes consumed**, not the whole offered input: those
   are what the trace witnesses, so they are what `io_digest` binds.
7. **Transfer cycles come before the ecall row.** "The ecall's completion writes the real
   next_pc" read either way; the owner chose transfers first, so every ecall row has the
   fixed `next_pc = pc + 4` and every transfer `next_pc = pc`.
8. **Address-space tags are 1, 2, 3**, so the initial `(REG, x0, 0, 0)` is not an
   all-zero tuple; RAM addresses are aligned byte addresses.
9. **The ecall frame's slot assignment** — `a7` at slot 1, all arguments at slot 2, `a0`
   at slot 3 — is the prompt's "share the Δ=1 and Δ=2 slots" made concrete, with `exit`
   writing back its status and an unimplemented number reading no argument. Forced to
   choose; recorded in the spec.
10. **`export`/`import` take `impl Write`/`impl Read`.** Master anti-goal 2 bans `impl
    Trait` in public signatures; the stage prompt freezes exactly these, and master rule
    13 says the stage wins.
11. **`Execution` has a `stderr` field** beyond the prompt's list. Acceptance 10 needs
    echo's fallback to be observable, and echo reports it on fd 2 by design. It is never
    archived.
12. **A buffer outside the RAM window is fatal**, not `-EFAULT`: there is no memory
    outside the window for a call to fault on, and one rule — every access outside RAM is
    fatal — is simpler than two. Documented in the ABI.
13. **Init/teardown plans zero shards.** It runs no cycles; its occupancy is addresses,
    and the stage that builds its table decides how to count it.
14. **Not compared with QEMU**: the misaligned modes (QEMU performs a misaligned `lw`,
    `sw`, `lh` or `sh` in user mode and faults on the atomics — neither is the zkVM's
    semantics, which is why they are fatal here), `echo` (4.6 M instructions, a ~2 GB
    log), and `amm`, `orderbook` and `vault`, whose behaviour `crates/loader/tests/qemu.rs`
    already checks under QEMU. **Stores into the code region** are allowed here — the
    zkVM's memory has no permissions, and the instruction stream is the decoded table,
    not RAM — where QEMU maps text read-only; no guest does it.
15. **serde stays featureless.** Reading a `Vec` goes through one hand-written visitor in
    `crates/trace/src/archive.rs`, as S10 did for the loader, so `crates/field`'s tests
    still run the configuration the guest links.
16. **No `PROTOCOL_VERSION` bump**: the additions fill in placeholders.

## Adversarial review

REVIEW-RESULT

## Open for the next stage

- **The ecall row's constraints (S16)** have the frame they need in the trace; what they
  must prove about transfer cycles — that their addresses walk `[buf, buf + n)` and that
  fd 0/1 bytes are the digest's — has no mechanism yet.
- **Init/teardown's occupancy** is `touched_addresses()` plus whatever image enumeration
  that family does; `plan_shards` gives it zero today.
- **Polynomials from the buffers**: the constraint stage turns the raw rows into columns
  and decides padding rows; nothing here pads.
- **The archive's later phases** are opaque bytes; each phase's stage defines its content
  and appends it through a constructor of its own.
