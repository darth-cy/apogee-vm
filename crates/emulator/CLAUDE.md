# `crates/emulator`

## What this crate owns
The reference emulator — RV32IMAC on one hart over a `ProgramImage` — its ecall
dispatch, and the tracing path that fills `crates/trace`'s structures. **It is not a
QEMU clone**: it takes the execution path its trace generation needs, and since S25
nothing holds it to QEMU's below the level of what a guest computes (see "QEMU is an
output oracle" below). **`docs/spec/execution-trace.md` is the convention the trace
follows; `docs/spec/ecall-abi.md` is the ABI the ecalls implement**; and, since S21,
**`docs/spec/delegation.md`** for what a delegation ecall does.

```rust
pub struct GuestIo { pub input: Vec<u8>, pub hint: Vec<u8> }
pub struct Execution { pub regs: [u32; 32], pub exit_code: i32, pub cycle_count: u64,
                       pub io: IoStreams, pub stderr: Vec<u8> }
pub enum EmuError { NotAnInstruction { pc }, IllegalInstruction { pc, word }, Ebreak { pc },
                    Misaligned { pc, addr, width }, OutOfBounds { pc, addr },
                    ClockOverflow { cycle },
                    DelegationFamilyAbsent { pc, number } }                  // + Display

pub fn run(image: &ProgramImage, io: &GuestIo) -> Result<Execution, EmuError>;
pub fn trace_run(image: &ProgramImage, io: &GuestIo, tables: &DecodedTables, config: &VmConfig)
    -> Result<(FamilyTraces, MemoryEventLog, CycleProfile, Execution), EmuError>;

// S21: the reference permutation, and the frame's two readings of it.
pub fn keccak_f(state: &mut [u64; 25]);
pub fn lanes_of(words: &[u32; 50]) -> [u64; 25];
pub fn words_of(lanes: &[u64; 25]) -> [u32; 50];

// `pub mod qemu` — the register-comparison harness, S12 to S25 — is **deleted**.
// `QEMU_FLAGS`, `Divergence`, `WHITELIST`, `Record`, `Step`, `Agreement`,
// `Mismatch`, `parse_log`, `emulator_steps` and `compare` went with it.
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
  and never a soundness one, and one the circuits share, so emulator and constraint
  agree (`docs/spec/memory-ops.md` §6.6). M follows the ISA's
  edge cases: division by zero gives all-ones (`div`, `divu`) or the dividend (`rem`,
  `remu`), and `INT_MIN / -1` gives `INT_MIN` remainder 0.
- **Fatal guest errors, never emulated around**: a halfword or word access not a multiple
  of its width (`Misaligned`, in both paths — must-be-exact 9), any data access or
  ecall byte outside the RAM window (`OutOfBounds`), `ebreak`, a pc that is not the
  start of an instruction (the all-zero halfword included), a slot the decoder refuses,
  and the 38-bit clock running out (`ClockOverflow`).
- **A nonzero exit is an execution.** `run` returns it with its `exit_code`; refusing to
  prove one is a later stage's policy.
- **The exit row writes the halting sentinel.** An `EXIT` ecall's row commits
  `next_pc = constants::memory::HALT_PC` (1), not the fall-through, in `run` and
  `trace_run` alike; every other row, transfer cycles and other ecalls included, is
  unchanged. So a log's final pc value is `HALT_PC`, written once, and every other pc
  write is even. Added at S14, `docs/spec/memory.md` §5.
- **Routing panics, never skips**: a pc no decoded table claims, or claimed by a family
  that is not its instruction's, means `tables` are not this program's.
- **The recorded fd 0 stream is what the guest consumed**, not what it was offered; fd 2
  is kept in `Execution::stderr` for diagnostics and archived nowhere.
- **An ecall row reads the arguments the ABI table gives its number**, whether or not the
  call is implemented yet: `PRECOMPILE_POSEIDON2` reads its `a0` pointer and answers
  `-ENOSYS`, so its frame will not change when its circuit lands. A number the table does
  not list reads none. The emulator spells no ABI number itself;
  `crates/constants/tests/ecall_abi.rs` checks that.
- **A delegation ecall performs the permutation and answers 0** (S21). The arm keys on
  `program::delegation_family(n)`, never on a literal: it reads `a0` as the frame base,
  refuses a misaligned or out-of-window one as the ordinary `Misaligned` / `OutOfBounds`
  fatal errors, permutes the 50 words in place, logs the 50 RAM events at
  `constants::delegation::FRAME_DELTA` — **right after the pc query and before the roles**,
  which is what makes `(RAM, 0)` a pair no role takes — stages the mirror query
  (`Role::Delegate`, at the base, reading the zero tuple), routes an `Invocation` to the
  family's `DelegationTrace`, and writes 0 into `a0` with `next_pc` the fall-through. A
  program whose `VmConfig` lacks the family it calls is `DelegationFamilyAbsent`, loudly:
  the executor and the preprocessor disagreeing about the ABI is not something to answer
  `-ENOSYS` to. An executor *without* the circuit — `qemu-riscv32` — answers `-ENOSYS` and
  the guest's software fallback runs, which is the whole of acceptance 3.
- **`keccak_f` is the one keccak permutation in the repository** and the emulator owns it, because
  the emulator is what executes it; the circuit's forward pass is checked against it and
  `tests/keccak.rs` checks it against `tiny-keccak` on all 1,600 single-bit states. The
  guest SDK's software fallback is a second implementation by necessity — it is `no_std`
  guest code — and `guests/keccak-test` is what holds the two to the same digests.

## QEMU is an output oracle, and nothing more (owner's decision, S25)
`qemu-riscv32 <elf>`, fd 0 and fd 3 regular files (an empty hint), fd 1 captured to a
file. What is compared is the **exit status** and **fd 1**, and nothing else: no
instruction count, no pc, no intermediate register, no trace.

S12 built this as a per-instruction register-file comparison — `-one-insn-per-tb -d
nochain,cpu`, the emulator's side replayed from its `MemoryEventLog` — with an
entry-state rule for `x2` and a one-entry whitelist for `sc.w`. **That invariant is
withdrawn.** It was never the property the project needs, and since S23 it is not even
true: a **delegation** ecall goes native here and takes the `-ENOSYS` software fallback
under QEMU (`docs/spec/delegation.md` §2), so the two instruction streams differ *by
design* while computing the same value. S25 made that universal — publishing `io_digest`
at exit means Poseidon2, so every guest that moves committed bytes delegates — and the
register comparison, kept alive, would have been a suite asserting that this VM must
execute the way a foreign emulator does.

What covers a trace instead is this VM's own semantics and constraints: `tests/trace.rs`
for the frame, the clock, routing, the halting sentinel and every ecall's answer;
`crates/trace`'s log self-check; `crates/checker/tests/multiset.rs` and `memory.rs` for
the memory argument over real guests' logs, each forgery refused by the gate that refuses
it; and each family's row suite over its fill. The `sc.w` conformance deviation is
unchanged and still documented (`docs/spec/memory-ops.md` §6.5) — the circuits share it,
so emulator and constraint agree — it simply is not a whitelist entry any more, because
there is no register comparison to exempt it from.

```
cargo test -p emulator --test qemu_outputs -- --include-ignored     # Linux with qemu-user; CI runs it
```

On macOS, in a container (`docs/guest-program-manual.md` §7):

```
docker run --rm -v "$PWD":/w -w /w -e CARGO_TARGET_DIR=/tmp/t rust:latest bash -c \
  'apt-get update -qq && apt-get install -y -qq qemu-user &&
   cargo test -p emulator --test qemu_outputs -- --include-ignored'
```

## Tests
| File | What |
| --- | --- |
| `src/lib.rs` (unit) | the last cycle on the 38-bit clock runs and the next is `ClockOverflow` |
| `tests/keccak.rs` | `keccak_f` against `tiny-keccak`: the all-zero state, the all-ones state, **all 1,600 single-bit states**, a random walk, and `lanes_of`/`words_of` round-tripping. 7 tests |
| `tests/guests.rs` | the guests' host-computed answers (fib, heap, atomics, rvc-dense), acceptance 10 (echo's `-ENOSYS` fallback computes the S02 permutation), orderbook's advice invariance, `opcodes` executes all 58 non-trapping mnemonics and every instruction of its compressed block, acceptance 11 (seven misaligned kinds, both paths), `run` == `trace_run`, the recorded fd 0 stream is what the guest consumed; and **S21's acceptance 3**: the six digests `guests/keccak-test` checks itself against, re-derived from `tiny-keccak` and read out of the guest's own source so a stale literal cannot pass, and both keccak guests run to their exit statuses under the delegation ecall |
| `tests/trace.rs` | acceptance 3 (balance, heap traffic included), 4 (a corrupted RAM read, register write mid-chain, pc write and gap, a forged initial value, and a stale read, each named), 5 (the four-slot clock over every event; `amoadd.w` fills all four slots), 6 (routing), the frame table — roles and slots — restated from the spec and checked on every row, the halting sentinel (the exit row alone writes `HALT_PC`, as the last pc write; every other pc write even), ecall transfers with every byte held to the recorded streams, every ecall answering as the ABI says (must-be-exact 2 without QEMU), the rows rebuilding the log exactly, `final_state`, and `trace::init_windows` (fib's stack window at 2^22, 2^20 and 2^16; every traced guest's list exactly its touched windows above 0 at every height, and passing `program::check_memory_windows`) |
| `tests/archive.rs` | acceptance 7 (byte-identical round trip, hash-equal payloads, answers without re-execution, `io_digest`) and 8 (five phases, the timing section byte for byte, out-of-order refused by byte patch) |
| `tests/qemu_outputs.rs` | **`#[ignore]`d** — the ten-guest suite computes the same exit status and the same fd 1 under both executors; a different input gives a different answer, which is what keeps the comparison from passing on nothing; `ebreak` stops both. Internals are not compared (see above) |
| `tests/revm.rs` | **S24**, over `guests/revm-block`, which is built from source rather than read from a committed ELF. In the `test` step: the committed `BlockWitness` is canonical and re-encodes to itself, each canonicity rule refuses by name, the output commitment's three sections read back field by field, native host revm produces the committed output, every keccak-f frame the workload delegated is `tiny-keccak`'s answer, a block whose transactions do not fit its gas limit is refused — including the case revm cannot see, two transactions that each fit the header and together do not — and `BLOCKHASH` still answers `EmptyDB`'s placeholder, which is the pin on the gap that keeps `BlockWitness` unfrozen. **`#[ignore]`d, and CI asks for them by name** at `APOGEE_GUEST_PROFILE=release`: the derived family set (`KECCAK_F` in, S23's two out, every instruction a live row of exactly one family), the guest's fd 1 against native revm's on the same witness, the harvested frames against the committed ones, the cycle and occupancy report, and the image against the two ceilings its height turns on. One more needs `qemu-riscv32`: the same binary under both executors commits the same bytes, which is the delegation against the software fallback end to end |
| `tests/consistency.rs` | the three-way consistency suite over `guests/consistency`: host and emulator agree on every corpus input (fd 1 by section, exit status, a panic's message, line and column); every workload, fault and bad input exercised; `trace_run` == `run` and the log balances and ends on `HALT_PC`, a nonzero exit included, with every family but the two init families and all eight M instructions executed; the heap probes exit 71; a flipped byte caught at its workload and every leg's flip classified; **`#[ignore]`d** — the same corpus with QEMU as the third leg |

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
