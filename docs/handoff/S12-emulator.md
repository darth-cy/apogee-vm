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
   filled, post-execution's content as documented in `crates/trace/src/archive.rs`. The
   reader takes only the canonical encoding of an archive whose parts agree — the family
   rows well formed, the profile counting them, their cycles `1..=n`, and the log exactly
   the one the rows rebuild — and the frozen constructor applies the same rule, so every
   archive that can be built can be read back.
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
| `crates/loader/tests/vectors/consistency.elf` | `guests/consistency`: the three-way suite's guest, 4.4 MB of it |
| `guests/opcodes/`, `guests/heap/`, `guests/consistency/` | their sources |

All three are pinned in `crates/loader/tests/common/mod.rs`, built by `cargo run -p
kat-gen -- guests` and held to the host-loadability rules by
`crates/loader/tests/layout.rs` like every other guest. The first run of that command
rebuilt the seven existing ELFs byte-identically; the second, after the allocator fix
below, changed all nine. Two of them changed in their code: `echo` and `orderbook` link
the allocator and gained 37 instructions each, so their decoded tables move with it. The
other seven changed only in their symbol and string tables — `fib`'s `.text` is
byte-identical across the fix, and the committed `objdump` and `nm` listings, which are
`fib`'s, `rvc-dense`'s and `amm`'s, did not move at all. Nor did the identity pin, which
is `fib`'s.

## Acceptance

| # | Item | Where | Result |
| --- | --- | --- | --- |
| 1 | QEMU differential over the suite | `emulator/tests/differential.rs` (`#[ignore]`d; CI) | every register of every instruction equal to `qemu-riscv32` 10.0.11's: `opcodes` 2,354 instructions (the one `sc.w` whitelisted), `rvc-dense` 638, `fib` 2,115, `heap` 141,827, `atomics` 22,507, `consistency` 25,945 on its hazards workload; exit status and fd 1 equal too. `heap` was 138,359 before the allocator fix below: the ceiling check `alloc` now runs on every allocation is the whole difference |
| 2 | harness negative control | `differential.rs`, and `src/qemu.rs` unit tests | a perturbed register at three positions in fib, and a perturbed pc, each reported at exactly that instruction and register |
| 3 | self-check positive, heap traffic included | `emulator/tests/trace.rs` | fib, heap, atomics, opcodes and rvc-dense balance; heap changes over 100 heap words |
| 4 | self-check tamper twin | `trace.rs` | a RAM read, a register write mid-chain, a pc write, a negative gap, a forged initial value (a RAM word's and the entry pc's) and a stale read, each failing with the space, address and timestamp of the offending query named |
| 5 | timestamp scan; `amoadd.w` fills four slots | `trace.rs` | every event of five guests on the four-slot clock; each of atomics' `amoadd.w` cycles holds slots 0–3, slot 3 shared by the RAM query and `rd` |
| 6 | routing | `trace.rs` | fib's cycles each in exactly one buffer, the family `row_kind` independently assigns its pc, counts summing to the cycle count; atomics' A cycles all and only in the atomics buffer, which its config has |
| 7 | archive round trip, determinism, answers without re-execution | `emulator/tests/archive.rs` | byte-identical export → import → export for three guests; hash-equal payloads from two runs with different timings; cycle count, occupancy, fd 0/1 and `io_digest` from the import; family rows and log rebuilt |
| 8 | five phases; out-of-order refused | `archive.rs`, `trace/src/archive.rs` | the payload ends with four present, empty sections and the timing section is pinned byte for byte; a byte-patched archive filling post-GKR before post-commit is refused beside an in-order control; every other refusal of the reader — fourteen ways the parts can disagree, trailing bytes, a mis-tagged section, an overlong varint — has a negative control of its own |
| 9 | `ShardPlan` edges | `trace/tests/plan.rs` | 0 / 1 / h / h+1 → 0 / 1 / 1 / 2 at every menu height; zero-occurrence families zero; purity |
| 10 | precompile `-ENOSYS` and fallback | `emulator/tests/guests.rs`, and `opcodes`' `cover_ecall` under the differential | echo's fallback computes the S02 permutation; `opcodes` makes the `0x500` and `0x4ff` calls, whose `a0` QEMU's matches |
| 11 | misalignment fatal in both paths | `guests.rs` | `lw`, `sw`, `lh`, `sh`, `lr.w`, `sc.w`, `amoadd.w`: `Misaligned` at that instruction from `run` and `trace_run` alike, no trace |

## Measured

Cycle counts and per-family occupancy, debug-profile guests, at the inputs the suites
use (transfer cycles included in both the count and add/sub/lui/auipc's occupancy):

| Guest | Input | Cycles | Transfers | Events | Per family |
| --- | --- | ---: | ---: | ---: | --- |
| fib | n = 24 | 2,117 | 2 | 7,190 | ADD 657 · JBS 481 · SHIFT 15 · MUL 0 · MEMW 952 · MEMSW 12 |
| heap | n = 40 | 141,832 | 5 | 475,512 | ADD 42,838 · JBS 32,470 · SHIFT 5,410 · MUL 764 · MEMW 55,603 · MEMSW 4,747 |
| opcodes | mode 0 | 2,366 | 12 | 8,266 | ADD 768 · JBS 414 · SHIFT 172 · MUL 83 · MEMW 829 · MEMSW 77 · ATOMICS 23 |
| atomics | n = 37 | 22,517 | 10 | 76,854 | … ATOMICS 409 |
| rvc-dense | x = 7 | 642 | 4 | 2,206 | |
| echo | 100 bytes, a 14-byte hint | 4,635,773 | | | (software Poseidon2; `run` only) |

`heap` is the one row the allocator fix moved — 138,364 cycles and 463,680 events before
it. Nothing about where its blocks land changed: `__heap_start` is the same address and
every block is at the same offset from it. What changed is `alloc` itself, which grew the
ceiling arithmetic and a `stack_pointer` call — 42 bytes of code — and `heap` makes about
120 allocations. Every other guest's numbers are unchanged.

At the default heights every family that ran plans one shard for each of these guests,
and a family that did not run, init/teardown included, plans zero. `heap`'s allocations
start at the bottom of the heap-and-stack reservation and change more than a hundred
words there. Each trace suite runs in well under a second.

## Verification performed

**488 workspace tests, all green, plus 18 `#[ignore]`d** (438 and 15 at S11). The 50 new:
14 in `crates/trace` (8 archive unit tests, 2 address-space tests, 4 shard-plan tests),
35 in `crates/emulator` (8 unit tests, 10 guest tests, 13 trace tests, 4 archive tests),
and 1 in `crates/constants` (the emulator dispatches on the ABI constants). The 3 new
ignored are the QEMU differential. `fmt` and `clippy -D warnings` are clean across all
four workspaces; the one `#[allow]` added is `clippy::too_many_arguments` on the
emulator's `load`, beside the usual `dead_code` on `tests/common`. `cargo run -p kat-gen`
then `git diff` over every vector directory is clean: the `loader` group reproduces its
listings unchanged, and `kat-gen -- guests` rebuilt all nine guest ELFs with the seven
from S11 byte-identical. `crates/loader/tests/layout.rs`'s ignored case relinked every
guest, the two new ones included, and holds them to the host-loadability rules.

**The QEMU differential ran in two places.** Locally, `qemu-riscv32` 10.0.11 in a Debian
container on the owner's arm64 machine (colima): the numbers in acceptance 1. And on the
draft pull request, `ubuntu-latest` — x86_64, the distribution's qemu-user 8.2 — where
the whole CI job, differential included, passed in 4m29s. Two QEMU versions and two host
architectures agree with the emulator register for register.

**The emulator was run against its guests before QEMU saw it**: fib, heap, atomics and
rvc-dense against host-computed answers, echo's precompile fallback against the S02
permutation, orderbook's advice invariance — all on the first run. The first QEMU run
then passed on every instruction of five guests; its only failure beforehand was the
harness's own, a guest ELF written without its execute bit.

**After the allocator fix and the consistency suite: 495 workspace tests, all green,
plus 20 `#[ignore]`d** — seven tests and two ignored more than the stage shipped with:
six in `crates/emulator/tests/consistency.rs`, and one in `crates/program/tests/
partition.rs` holding the frozen default heights to the guests they can and cannot
preprocess. `fmt` and `clippy -D warnings` stay
clean across the four workspaces, `cargo run -p kat-gen` reproduces every derived fixture
unchanged, and `kat-gen -- guests` rebuilt all ten guest ELFs. In the Linux container on
the owner's arm64 machine (`qemu-riscv32` 10.0.11): `crates/loader`'s guest suite passes
at both profiles, the differential agrees register for register over six guests with
`consistency` contributing 25,945 instructions, and the three-way consistency suite
passes at `debug` and at `release`. The allocator fix was mutation-checked three ways —
the old `__stack_top` ceiling, the ceiling without its live-`sp` half, and the ceiling
without its reserve — and each mutation fails a heap probe.

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
   writing back its status, `PRECOMPILE_POSEIDON2` reading its `a0` pointer although it
   answers `-ENOSYS` (the ABI table lists that argument, so the row already has the frame
   it keeps when the circuit lands), and a number the ABI does not list reading none.
   Forced to choose; recorded in the spec.
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
    `sw`, `lh`, `sh` and — its default CPU allowing a misaligned AMO inside an aligned
    16-byte block — `amoadd.w`, and faults on `lr.w` and `sc.w`; none of it is the zkVM's
    semantics, which is why all seven are fatal here), `echo` (4.6 M instructions, a ~2 GB
    log), and `amm`, `orderbook` and `vault`, whose behaviour `crates/loader/tests/qemu.rs`
    already checks under QEMU. **Stores into the code region** are allowed here — the
    zkVM's memory has no permissions, and the instruction stream is the decoded table,
    not RAM — where QEMU maps text read-only; no guest does it.
15. **serde stays featureless.** Reading a `Vec` goes through one hand-written visitor in
    `crates/trace/src/archive.rs`, as S10 did for the loader, so `crates/field`'s tests
    still run the configuration the guest links.
16. **No `PROTOCOL_VERSION` bump**: the additions fill in placeholders.
17. **`lr.w`'s word sits at slot 3**, where a load's sits at slot 2. The prompt pins the
    atomics frame's RAM read-modify-write at Δ=3 and keeps the whole A extension in one
    circuit; `lr.w` has no `rs2`, and the per-query-kind rule ("a load's data read" at
    Δ=2) could be read to cover it. One family, one frame: the atomics family's RAM query
    is at slot 3 for every instruction it owns. Resolved and written into the spec §7,
    since S14 would otherwise have to guess.
18. **A cycle's queries are ordered by slot, then role number**, not by the role list
    alone. Every role today is numbered in slot order, so the log is unchanged by the
    rule; it exists so a role appended later — an ecall's `a3` — takes its place by slot
    and renumbers nothing. The `present` mask has one spare bit.

## Adversarial review

Six lenses over the finished branch — an independent re-derivation of the ISA against
the emulator and the `opcodes` asm; the trace convention held to the prompt and the spec
word for word; a malicious prover against `self_check`; the archive's reader and its
determinism; stage-and-master compliance and documentation truth; the QEMU harness —
then a skeptic told to refute each finding of medium severity or above. **22 findings, 7
at medium; 6 survived refutation** (5 at medium, 1 downgraded to low), and the seventh —
the core dump, below — was refuted as already fixed.

No lens found an instruction the emulator gets wrong. The ISA lens re-derived all 59 and
found none; what it found was in the guest's comments. **Every medium finding was a test
that would have passed on a wrong implementation**, which is the class this review exists
for:

- **The slots of a load's word and of an ecall's `a1`/`a2` were never checked against the
  spec.** Every test took the slot from `Role::delta`, the function under test, so moving
  either to slot 3 — a trace S14 could not balance — stayed green. The spec's slot table is
  now restated in the test, and `ROLES` is checked to be in slot order.
- **An ecall transfer's bytes were never checked**: a `read` zeroing a partial word's
  other bytes, or a `write` clobbering the buffer, passed. Every transfer byte is now held
  to the recorded streams, the bytes beside the buffer to their old values, and the
  recorded fd 0, fd 1 and fd 2 streams to exactly the bytes the transfers moved.
- **`import` accepted overlong varints**, so one archive had many files and the payload
  boundary was a property of the writer only. It now takes only the canonical encoding.
- **None of `import`'s refusals was tested**, including the one that stops hostile bytes
  reaching an assertion. Each now has a negative control, and the reader and the
  constructor share one rule — the parts must agree, down to the log being exactly what
  the rows rebuild — which also closed two of the lows (an archive whose log contradicts
  its rows was accepted; the constructor could build archives the reader refused).

Lows acted on: `self_check` named the honest reader of a write rather than a stale read
of it (it now replays the address), and a timestamp-blind balance was caught only by
where it named (a stale-read tamper now fails it outright); `self_check` did not require
timestamp order, so `final_state` could disagree with the teardown it balanced; its
documented blind spot was narrower than the real one; the precompile row read no
argument though the ABI table gives it `a0`; the role order could not take an appended
slot-2 role; `lr.w`'s slot needed recording (deviation 17); the `sc.w` exemption's end was
untested; and the guest's claim that QEMU faults on a misaligned `amoadd.w`, a stale test
count, an echo figure measured with the wrong hint, and the unused `Role::name` were
wrong or surplus.

**The core dump.** The first commit of this branch carried a 403 MB `crates/emulator/core`:
the `ebreak` case makes QEMU die on a trap signal, cargo runs a test from its crate's
directory, and the container had core dumps on. GitHub refused the push, the unpushed
commit was amended, and the harness now runs QEMU in its scratch directory under
`ulimit -c 0`. Nothing of it reached the remote.

**Mutation.** 42 single-edit mutants over the emulator, the trace crate and the harness,
in three isolated worktrees, the semantic ones also run through the QEMU differential:
**37 killed, 9 of them only by the differential** — the instruction-semantics mutants
whose effect no host-computed answer reaches, which is the differential's job. Five
survived. One is equivalent: without the one-query-per-timestamp check, a duplicate still
fails the balance, under a different message. The other four were test gaps and are
closed: a signed `sltiu` (no guest compared mixed signs — `opcodes` now does), recording
the offered rather than the consumed input (a test now offers bytes the guest never
reads), a load's word at slot 3 (the restated slot table), and unaligned RAM addresses
(address-space tests).

**The fixes, re-checked by mutation.** In a fresh worktree of the fix commit, twelve
single edits were applied one at a time: the four fixed survivors, and each mutation the
reviewers used to show a gap — a load's word and an ecall's `a1`/`a2` at slot 3, a `read`
zeroing a partial word's neighbours, a `write` clobbering its buffer, the old naming, the
canonical-encoding check removed, the reader's address check removed, the rows-rebuild
check removed, and a balance blind to timestamps. **Eleven were killed first time**, the
signed `sltiu` by the QEMU differential and the rest by the local suites. The twelfth, the
timestamp-blind balance, survived — the stale-read tamper written to kill it had picked a
register's *last* query, so teardown read the stale value back and a value-only balance
failed anyway, for the wrong reason. The case now requires a later query at that
register; with the edit re-applied it fails, and on the real code it passes. **Twelve of
twelve.**

**Found after the PR opened: the reader took any family id.** Raised in review of PR #12.
`check_parts` held the buffers to ascending order and the profile to naming the same
ids, but never held an id to `constants::family` — so an archive renaming a buffer and
its profile entry to 42, to `u32::MAX`, or to init/teardown (which claims no pc, and so
never holds an execution row) imported cleanly, and the first thing to notice was
`plan_shards`' assertion downstream. A probe confirmed all three were accepted. The rule
now requires every buffer's id to be in `program::FAMILIES` and init/teardown's buffer
to be empty, and the reader's refusal table carries both cases, fourteen in all.

**Found after the PR opened: the heap was handed out over the live stack.** Raised in
review of PR #12, by the three-way idea below applied by hand before the suite existed —
one source file compiled for the host and for the guest, and the two outputs diffed.

guest-sdk's allocator refused only a block ending above `__stack_top`, and the stack
grows down from exactly there, so **every block ending between the live `sp` and the top
was handed out on top of live stack frames**. In safe Rust that is memory corruption with
no `unsafe` in sight: the probe wrote one byte into a `Vec`'s spare capacity and watched
an unrelated local change from `0x00` to `0xaa`, and the next ordinary `format!` wrote
over saved return addresses, ending the guest on a load from `0xc8d5f907`. Because the
allocator never frees, the trigger is the *total* a run allocates — about 256 MiB — not
its peak, and running out of heap therefore corrupted the stack far more often than it
reached the `exit(71)` the SDK documented. It also broke the `GlobalAlloc` contract the
`unsafe impl` claims to meet.

The fix, on the repository owner's instruction, leaves `link.ld` alone: a new
`constants::guest_memory::STACK_RESERVE` (8 MiB, a native main thread's default stack)
gives the top of RAM to the stack, and `alloc` refuses any block ending above
`min(__stack_top - STACK_RESERVE, sp)`, reading the live `sp` with one `mv` from inside
itself. `guests/consistency`'s two heap probes pin the two halves, and each half is
load-bearing: with the ceiling back at `__stack_top` the first probe commits "allocated
past the ceiling" and exits 0; without the live-`sp` half the second is granted a block
covering its own frame; without the reserve the first fails again.

The adversarial review asked for a third, against the alignment round-up `alloc` does
before it tests the end, and building it showed there is nothing there to catch. The
reserve ceiling is `__stack_top - STACK_RESERVE`, which is 2^23-aligned, and a Rust
type's size is always a multiple of its alignment — so rounding a block's start up can
never carry it across that ceiling, and an allocator testing the end before rounding up
gives the same answer for every block. The order could only matter for a block aligned
past sixteen against the live-`sp` ceiling, since the ABI aligns `sp` to sixteen and no
further, and a guest cannot construct that deterministically. The probe was written,
run, found to pass against the mutation as well as the fix, and removed. What no allocator can
see is a stack that grows past its reserve after the heap has filled below it — that
needs a guard under every frame, and a program recursing that deep would overflow a
native main thread too.

## The consistency suite

A developer moving ordinary `no_std` Rust into this VM has to know that it computes what
it computed on their machine. `guests/consistency` is that question made executable: a
`#![no_std] + alloc` library of about 14,000 lines — numerics, collections, text,
traits, closures and iterators, a codec, hashes and the repository's own field and
permutation, allocation patterns — beside a thin guest `main`. The host calls the library
directly; the guest ELF is built from the same source at test time, so the two legs are
always one program.

`crates/emulator/tests/consistency.rs` runs one corpus three ways and reads the
disagreements off a table:

| host | QEMU | emulator | reading |
| --- | --- | --- | --- |
| a | a | a | consistent, on this input |
| a | b | b | the host differs from both RV32 executors: Rust's target, the SDK, or 32-bit behaviour |
| a | a | b | an emulator semantics bug |
| a | b | a | QEMU differs from both: the harness, or QEMU's environment |
| a | b | c | all three differ |

Compared: the exit status, fd 1 byte for byte — split into its sections, so a mismatch
names the workload that wrote it — and a panic's message, line and column. The host leg
runs with overflow checks on (asserted, because `cargo test --release` would turn them
off) on a 64 MiB stack.

**What Rust itself lets differ is declared, not tolerated.** `hazards::PLATFORM_DEPENDENT`
names six sections — `core::hash` of a slice and of a `usize`, `size_of` of anything
holding a pointer, `usize` arithmetic overflowing at 2^32, a `u64` narrowed with
`as usize`, and the bits of a NaN an operation produces — with the reason for each. The
two RV32 executors are never excused from any of them. The host is excused from the
pointer-width ones, which on a 64-bit host **must** then differ, so that list cannot go
stale by quietly becoming false; and from the NaN one only where its own convention
differs, which on AArch64 it does not, so there that section is compared like any other.
The narrowing cast is the quiet member of the set: overflow checks catch 32-bit `usize`
arithmetic, and nothing at all catches `as usize` dropping a value's top half.

Coverage: 100 section tags across eight workloads, plus the input check's, 28 deliberate
faults (four per workload, hazards none), and about 80 corpus inputs — three whole-guest runs, one per
workload, six payload shapes including invalid UTF-8, three malformed fd 0s, one per
fault, and 32 seeded random ones whose scale is drawn twice so small scales are commoner.
Each fault is checked to panic on both legs with the same message at the same line and
column, and with the same sections committed before it.

It plugs into the two suites that already existed. `tests/differential.rs` gains
`consistency` on its hazards workload — 25,945 instructions, which is all of a 4.4 MB
guest a per-instruction QEMU log can afford — and the traced test runs `numeric` and
`structures` through `trace_run` and `self_check`, which is where the claim that every
instruction family but init/teardown runs, and that all eight M instructions execute,
is made.

**Measured**, debug-profile guest, emulator cycles for one workload alone:

| Workload | scale 0 | MAX_SCALE | fd 1 bytes |
| --- | ---: | ---: | ---: |
| numeric | 742,247 | 12,918,950 | 5,989 |
| collections | 398,601 | 3,615,779 | 350 |
| text | 500,298 | 7,746,501 | 5,293 |
| structures | 774,697 | 6,341,254 | 305 |
| codec | 930,125 | 7,171,470 | 4,005 |
| crypto | 30,256,051 | 168,968,485 | 990 |
| alloc_patterns | 1,210,785 | 10,050,502 | 2,159 |
| hazards | 22,507 | 22,507 | 74 |

Crypto is the outlier and the reason is worth writing down: at the guests' `opt-level =
0`, one Poseidon2 permutation costs about 4.6M cycles and one `Fr::inverse` about 5.7M,
because `crates/field`'s Montgomery multiply is compiled unoptimised along with
everything else. The permutation's known answer and one batch inversion run at every
scale; the Merkle tree, the sponge squeeze and Fermat's inversion run from scale 1 up.

**Both guest profiles run it, and the second is what `opt-level = 3` has to say.** The
whole suite is green three ways at `debug` and at `release`, with one difference worth
recording: at `opt-level = 3` LLVM computes a remainder as `a - (a / b) * b`, so `rem`
and `remu` are never emitted and the traced run's coverage claim is the committed debug
build's. It is the same program either way — every section, exit status and panic
matches across the profiles — but which *instructions* a proof will be about is the
optimiser's business, which is worth knowing before a circuit is sized from a profile.

**What it found:** the allocator bug above. Nothing else: the host and the emulator agree
on every corpus input, and QEMU agrees with both. `docs/guest-program-manual.md` §2a now
teaches the shape — logic in a `no_std` library, `guest-sdk` a dependency of the guest
target alone — so a guest author can run their own program both ways.

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
- **The reader cannot see a row filed under the wrong real family.** An `add` row in the
  `MUL_DIV` buffer names a valid, pc-claiming family, and whether that family claims the
  row's pc is a fact about the program, which the archive does not carry. The stage that
  reads an archive back into a proof has the decoded tables and checks routing there;
  the constraint system's decoded-table lookup refuses it regardless.
- **A host call or precompile with more than three arguments** needs a role per extra
  register: one fits the spare `present` bit, a second widens the mask, which is a schema
  change to the buffers and the archive.
- **`self_check` cannot see past an address's last honest query**, by the argument's own
  shape: a changed final value, a moved or added final query, trailing cycles removed.
  The archive binds the log to the rows; teardown and the cycle count are the constraint
  stages' to bind.
- **The frozen default heights cannot preprocess a large guest that uses an atomic**, and
  `guests/consistency` is the first one to show it. Decoded-table rows are absolute pcs,
  one per halfword, so a family's height has to reach past its last instruction — and
  `DEFAULT_HEIGHTS` gives atomics 2^16 rows, which run out at pc `0x20000`. That guest is
  1.7 MB of code with an `Arc` in it, and its atomics run up to pc `0x18e62a` — the row
  `TableTooShort` names — so `decode_program` refuses it at the defaults and takes a
  uniform 2^20. Every suite here that is not *about* the heights now asks for the smallest menu
  height that fits (`common::fitting`, `common::preprocess`). Whether heights should be
  per family at all, or derived from the program's code span, is the next stage's to
  decide; nothing about the defaults was changed here.
- **The ISA's edge cases are still QEMU's to check, not the consistency suite's.** Rust
  settles division by zero and `INT_MIN / -1` with its own checks before the hardware sees
  the operands, so no input to a Rust guest can reach the emulator's `div`/`rem` edge
  semantics: a mutation making `div` by zero return 0 rather than all-ones survives the
  whole local suite. `guests/opcodes` does exercise them and commits the answers on fd 1,
  but `tests/guests.rs` compares which mnemonics ran, not what they computed. The QEMU
  differential covers it in CI; pinning those committed words would cover it everywhere.
- **A stack deeper than its reserve is unguarded.** The allocator keeps the heap 8 MiB
  below the top of RAM and below the live `sp`, so no block is handed out over a live
  frame — but nothing watches the stack grow *down* into blocks already handed out. That
  needs a guard under every frame, which is instrumentation rather than allocation.
- **The consistency guest's crypto workload costs 30M cycles at scale 0**, because
  `crates/field`'s Montgomery multiply and `crates/transcript`'s permutation compile at
  the guests' `opt-level = 0` like everything else: one permutation is about 4.6M cycles
  and one `Fr::inverse` about 5.7M. A stage that wants them cheaper has
  `guests/Cargo.toml`'s profiles to change, and the rule that the two differ only in
  `opt-level` to keep.
