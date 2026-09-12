# `crates/emulator`

## What this crate owns
The reference emulator — RV32IMAC on one hart over a `ProgramImage` — its ecall
dispatch, the tracing path that fills `crates/trace`'s structures, and the QEMU
differential harness. **`docs/spec/execution-trace.md` is the convention the trace
follows; `docs/spec/ecall-abi.md` is the ABI the ecalls implement.**

```rust
pub struct GuestIo { pub input: Vec<u8>, pub hint: Vec<u8> }
pub struct Execution { pub regs: [u32; 32], pub exit_code: i32, pub cycle_count: u64,
                       pub io: IoStreams, pub stderr: Vec<u8> }
pub enum EmuError { NotAnInstruction { pc }, IllegalInstruction { pc, word }, Ebreak { pc },
                    Misaligned { pc, addr, width }, OutOfBounds { pc, addr },
                    ClockOverflow { cycle } }                                // + Display

pub fn run(image: &ProgramImage, io: &GuestIo) -> Result<Execution, EmuError>;
pub fn trace_run(image: &ProgramImage, io: &GuestIo, tables: &DecodedTables, config: &VmConfig)
    -> Result<(FamilyTraces, MemoryEventLog, CycleProfile, Execution), EmuError>;

pub mod qemu {
    pub const QEMU_FLAGS: [&str; 3];                   // -one-insn-per-tb -d nochain,cpu
    pub struct Divergence { pub instruction, pub rule, pub reason }   // &'static str each
    pub const WHITELIST: [Divergence; 1];              // sc.w
    pub struct Record { pub pc: u32, pub regs: [u32; 32] }
    pub struct Step { pub pc: u32, pub regs: [u32; 32], pub instr: Instr, pub writes: u32 }
    pub struct Agreement { pub records: usize, pub sc_w_whitelisted: usize }
    pub struct Mismatch { pub index: usize, pub pc: u32, pub reg: Option<usize>, pub reason: String }
    pub fn parse_log(text: &str) -> Result<Vec<Record>, String>;
    pub fn emulator_steps(image: &ProgramImage, log: &MemoryEventLog) -> Vec<Step>;
    pub fn compare(steps: &[Step], records: &[Record]) -> Result<Agreement, Mismatch>;
}
```

`trace_run` returns the `Execution` too — a fourth element beside the stage's three —
because `TraceArchive::from_execution` needs the fd 0/1 streams and none of the other
three carries them. Put to the repository owner, who chose it over a second execution
or rebuilding the streams from the log.

## Frozen invariants
- **One core.** `run` and `trace_run` execute through the same `Machine`; the tracing
  path differs only in a `Recorder` that receives each cycle's staged queries. A cycle
  stages its queries by role as it executes, and commits them — pc query first, then
  roles in order — only when it completes, so a fatal error leaves nothing behind.
- **Machine state is plain**: `[u32; 32]` registers, the pc, RAM as a hash map of 4 KiB
  pages (absent is zeros), every slot decoded once up front. Registers start at 0, `x0`
  included; the pc starts at the entry point; RAM starts as the image.
- **Semantics.** Every A instruction is its plain read-modify-write; `aq`/`rl` order
  nothing. **`sc.w` always succeeds** — it stores and writes 0 — a conformance deviation
  and never a soundness one, and the one entry on the whitelist. M follows the ISA's
  edge cases: division by zero gives all-ones (`div`, `divu`) or the dividend (`rem`,
  `remu`), and `INT_MIN / -1` gives `INT_MIN` remainder 0.
- **Fatal guest errors, never emulated around**: a halfword or word access not a multiple
  of its width (`Misaligned`, in both paths — must-be-exact 9), any data access or
  ecall byte outside the RAM window (`OutOfBounds`), `ebreak`, a pc that is not the
  start of an instruction (the all-zero halfword included), a slot the decoder refuses,
  and the 38-bit clock running out (`ClockOverflow`).
- **A nonzero exit is an execution.** `run` returns it with its `exit_code`; refusing to
  prove one is a later stage's policy.
- **Routing panics, never skips**: a pc no decoded table claims, or claimed by a family
  that is not its instruction's, means `tables` are not this program's.
- **The recorded fd 0 stream is what the guest consumed**, not what it was offered; fd 2
  is kept in `Execution::stderr` for diagnostics and archived nowhere.
- **An ecall row reads the arguments the ABI table gives its number**, whether or not the
  call is implemented yet: `PRECOMPILE_POSEIDON2` reads its `a0` pointer and answers
  `-ENOSYS`, so its frame will not change when its circuit lands. A number the table does
  not list reads none. The emulator spells no ABI number itself;
  `crates/constants/tests/ecall_abi.rs` checks that.

## The QEMU differential
`qemu-riscv32 -one-insn-per-tb -d nochain,cpu -D <log> <elf>`, fd 0 and fd 3 regular
files (an empty hint), fd 1 captured to a file. One instruction per block and no
chaining means `-d cpu` logs the register file before every instruction. The emulator's
side is **replayed from its `MemoryEventLog`**, so what is held to QEMU is the trace
itself; ecall transfer cycles, which QEMU has no record of, are skipped as instructions
and folded in as memory.

Two rules, nothing else:
1. **The entry state.** QEMU starts with Linux's stack pointer in `x2`; the emulator
   starts every register at 0. `x2` alone may differ at the first record, and only until
   the guest writes it — which crt0 does first. Put to the repository owner, who chose
   this named rule over skipping records.
2. **`WHITELIST`**, one entry: after an `sc.w`, `rd` may be 1 in QEMU (it failed) where
   the emulator has 0, until the emulator next writes `rd`. `guests/opcodes` holds one
   unpaired `sc.w` so the rule is exercised, exactly once.

```
cargo test -p emulator --test differential -- --include-ignored     # Linux with qemu-user; CI runs it
```

On macOS, in a container (`docs/guest-program-manual.md` §7):

```
docker run --rm -v "$PWD":/w -w /w -e CARGO_TARGET_DIR=/tmp/t rust:latest bash -c \
  'apt-get update -qq && apt-get install -y -qq qemu-user &&
   cargo test -p emulator --test differential -- --include-ignored'
```

## Tests
| File | What |
| --- | --- |
| `src/lib.rs` (unit) | the last cycle on the 38-bit clock runs and the next is `ClockOverflow` |
| `src/qemu.rs` (unit) | a real log parses; the entry rule is x2's and ends at its first write; a perturbed register is reported where it is; the whitelist is sc.w and bounded, and its exemption ends at the next write of rd |
| `tests/guests.rs` | the guests' host-computed answers (fib, heap, atomics, rvc-dense), acceptance 10 (echo's `-ENOSYS` fallback computes the S02 permutation), orderbook's advice invariance, `opcodes` executes all 58 non-trapping mnemonics and every instruction of its compressed block, acceptance 11 (seven misaligned kinds, both paths), `run` == `trace_run`, the recorded fd 0 stream is what the guest consumed |
| `tests/trace.rs` | acceptance 3 (balance, heap traffic included), 4 (a corrupted RAM read, register write mid-chain, pc write and gap, a forged initial value, and a stale read, each named), 5 (the four-slot clock over every event; `amoadd.w` fills all four slots), 6 (routing), the frame table — roles and slots — restated from the spec and checked on every row, ecall transfers with every byte held to the recorded streams, every ecall answering as the ABI says (must-be-exact 2 without QEMU), the rows rebuilding the log exactly, `final_state` |
| `tests/archive.rs` | acceptance 7 (byte-identical round trip, hash-equal payloads, answers without re-execution, `io_digest`) and 8 (five phases, the timing section byte for byte, out-of-order refused by byte patch) |
| `tests/differential.rs` | **`#[ignore]`d** — acceptance 1 over `opcodes`, `rvc-dense`, `fib`, `heap`, `atomics`; acceptance 2 (perturbed registers and pc caught at their instruction); `ebreak` at one pc in both |
| `tests/consistency.rs` | the three-way consistency suite over `guests/consistency`: host and emulator agree on every corpus input (fd 1 by section, exit status, a panic's message, line and column); every workload, fault and bad input exercised; `trace_run` == `run` and the log balances, with every family but init/teardown and all eight M instructions executed; the heap probes exit 71; a flipped byte caught at its workload and every leg's flip classified; **`#[ignore]`d** — the same corpus with QEMU as the third leg |

The guests are the committed ELFs in `crates/loader/tests/vectors/`, pinned there — except
in `tests/consistency.rs`, which builds `guests/consistency` from source at test time so
its guest is always the source the host leg calls.

## The consistency suite
`guests/consistency` is a `no_std` library plus a thin guest `main`. The host calls the
library directly; the guest is the same source, built here. Where the legs disagree says
what broke: the host alone against both RV32 executors is Rust's target, the SDK or 32-bit
behaviour; the emulator alone is an emulator bug; QEMU alone is the harness or QEMU's
environment. `hazards::PLATFORM_DEPENDENT` declares the sections Rust itself lets differ
per target — excused for the host, never between the two RV32 executors — and the
pointer-width ones must actually differ on a 64-bit host. The host leg runs with
overflow checks on (asserted) on a 64 MiB stack.
