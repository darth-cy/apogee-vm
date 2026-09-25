# `crates/emulator`

## What this crate owns
The reference emulator — RV32IMAC on one hart over a `ProgramImage` — its ecall
dispatch, and the tracing path that fills `crates/trace`'s structures.
**`docs/spec/execution-trace.md` is the convention the trace
follows; `docs/spec/ecall-abi.md` is the ABI the ecalls implement**; since S21,
**`docs/spec/delegation.md`** for what a delegation ecall does; and, since S-IO,
**`docs/spec/public-values.md`** for the two public windows and the advice region.

```rust
// S-IO: FOUR fields, and the split is the point. `input` and `advice` are memory
// the proof knows about; `stdin` and `hint` are fd streams it does not. A guest is
// provable or QEMU-runnable, never both, so one field cannot serve two roles.
pub struct GuestIo { pub input: Vec<u8>, pub advice: Vec<u8>,
                     pub stdin: Vec<u8>, pub hint: Vec<u8> }
pub struct Execution { pub regs: [u32; 32], pub exit_code: i32, pub cycle_count: u64,
                       pub io: IoStreams, pub stdout: Vec<u8>, pub stderr: Vec<u8> }
pub enum EmuError { NotAnInstruction { pc }, IllegalInstruction { pc, word }, Ebreak { pc },
                    Misaligned { pc, addr, width }, OutOfBounds { pc, addr },
                    ClockOverflow { cycle },
                    PublicInputTooLong { len }, JournalTooLong { len },   // S-IO
                    DelegationFamilyAbsent { pc, number },
                    DelegationFrame { pc, detail } }                         // + Display

pub fn run(image: &ProgramImage, io: &GuestIo) -> Result<Execution, EmuError>;
pub fn trace_run(image: &ProgramImage, io: &GuestIo, tables: &DecodedTables, config: &VmConfig)
    -> Result<(FamilyTraces, MemoryEventLog, CycleProfile, Execution), EmuError>;

// S21: the reference permutation, and the frame's two readings of it.
pub fn keccak_f(state: &mut [u64; 25]);
pub fn lanes_of(words: &[u32; 50]) -> [u64; 25];
pub fn words_of(lanes: &[u64; 25]) -> [u32; 50];
```

`trace_run` returns the `Execution` too — a fourth element beside the stage's three —
because `TraceArchive::from_execution` needs the two public byte strings and none of the
other three carries them. Put to the repository owner, who chose it over a second execution
or rebuilding them from the log.

**`GuestIo` is the four things a guest is given, and the split into two pairs is the
point.** `input` is the statement's public input, which the executor lays out in the public
input window with `program::public_io_words`, and `advice` the prover's private bytes at
`guest_memory::ADVICE_ORIGIN`, framed by `trace::advice_word` — both are *memory*, and both
are what a proof is about. `stdin` is the fd 0 stream and `hint` the fd 3 one — both are
*streams*, and a proof binds neither. `input` does **not** also serve fd 0: a guest is
provable or runnable under `qemu-riscv32`, never both, the windows and the advice region
being unmapped there, so one field serving two roles would only cap fd 0 at the window's
1,020 bytes for no gain.

**`Execution::io` is the execution's public values, not its streams** (S-IO). `io.input` is
the public input it was given — the window's contents, whether or not the guest read a byte
of it, because it is not a stream cursor — and `io.output` is the **journal** `Machine::
finish` reads back out of the public output window at exit. `stdout` is the fd 1
compatibility stream, which `qemu-riscv32` can be compared against and which a proof binds
none of; `stderr` is fd 2, diagnostics, archived nowhere.

## Frozen invariants
- **One core.** `run` and `trace_run` execute through the same `Machine`; the tracing
  path differs only in a `Recorder` that receives each cycle's staged queries. A cycle
  stages its queries by role as it executes, and commits them — pc query first, then
  roles in order — only when it completes, so a fatal error leaves nothing behind.
- **Machine state is plain**: `[u32; 32]` registers, the pc, RAM as a hash map of 4 KiB
  pages (absent is zeros), every slot decoded once up front. Registers start at 0, `x0`
  included; the pc starts at the entry point; RAM starts as the image, plus — since S-IO —
  the public input window and the advice region, seeded below.
- **Semantics.** Every A instruction is its plain read-modify-write; `aq`/`rl` order
  nothing. **`sc.w` always succeeds** — it stores and writes 0 — a conformance deviation
  and never a soundness one (`docs/spec/memory-ops.md` §6.6), and the circuits share that
  semantics, so emulator and constraint agree. M follows the ISA's
  edge cases: division by zero gives all-ones (`div`, `divu`) or the dividend (`rem`,
  `remu`), and `INT_MIN / -1` gives `INT_MIN` remainder 0.
- **Fatal guest errors, never emulated around**: a halfword or word access not a multiple
  of its width (`Misaligned`, in both paths — must-be-exact 9), a data access outside the
  **addressable regions** or an ecall byte outside the RAM window (`OutOfBounds`),
  `ebreak`, a pc that is not the start of an instruction (the all-zero halfword included),
  a slot the decoder refuses, the 38-bit clock running out (`ClockOverflow`), and, since
  S-IO, a journal whose length word is above `guest_memory::PUBLIC_PAYLOAD_BYTES` at exit
  (`JournalTooLong`).
- **The addressable set is `trace::addressable`, not the RAM window** (S-IO). A load or a
  store reaches ordinary RAM, either public window, or the advice region; the two holes —
  `[0, PUBLIC_INPUT_ORIGIN)` and the gap between the windows and `RAM_ORIGIN` — are
  `OutOfBounds`, so a null dereference is still a loud error and not a trace nothing can
  prove. **Advice is bounded at what the host supplied**: `Machine::advice_end` is
  `ADVICE_ORIGIN + 4 · trace::advice_region_words(io.advice)`, and a read above it is the
  same fatal error, because nothing in *this* execution initializes that address. So
  `guest_sdk::advice()` on a run given no advice is fatal, which is the right answer to
  asking for what was not handed over (`docs/spec/public-values.md` §6). Two bounds did
  **not** widen and are still the RAM window: an ecall's transfer buffer, and a delegation
  frame.
- **`JournalTooLong` is fatal and has to be.** `Machine::finish` reads the journal back out
  of the public output window through its length word; the verifier reads the same window
  through `program::public_io_words`, which has no encoding for a length above the payload,
  so an execution this let through would be one no proof could cover.
  `guest_sdk::commit` exits `EXIT_IO_ERROR` rather than overflow the window, so an honest
  guest never reaches it.
- **A nonzero exit is an execution.** `run` returns it with its `exit_code`; refusing to
  prove one is a later stage's policy.
- **The exit row writes the halting sentinel.** An `EXIT` ecall's row commits
  `next_pc = constants::memory::HALT_PC` (1), not the fall-through, in `run` and
  `trace_run` alike; every other row, transfer cycles and other ecalls included, is
  unchanged. So a log's final pc value is `HALT_PC`, written once, and every other pc
  write is even. Added at S14, `docs/spec/memory.md` §5.
- **Routing panics, never skips**: a pc no decoded table claims, or claimed by a family
  that is not its instruction's, means `tables` are not this program's.
- **`Machine::new` seeds the two prover-chosen regions and nothing else.** The public input
  window is `program::public_io_words(io.input)`, word for word — the one spelling of the
  layout, shared with `trace`'s column builder and the verifier's own extension, so the
  three cannot drift — and the advice region is `trace::advice_word` over `io.advice`. The
  journal window starts at 0 and stays there until the guest stores into it, which is
  `PUBLIC_OUTPUT`'s literal-0 init leaf. **fd 0 is a different stream**, `io.stdin`, and
  `Machine::new` does not touch it: a guest built for a POSIX host reads that one under
  `qemu-riscv32` and reads no window at all.
- **`Execution::io` is the public values and `Execution::stdout` is fd 1** (S-IO). `io.input`
  is the window's whole contents — what the *statement* carries, whether or not the guest
  read a byte of it, because a window is not a stream cursor — and `io.output` is the
  journal read out at exit. fd 2 is kept in `Execution::stderr` for diagnostics and
  archived nowhere.
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

## The QEMU output oracle
`qemu-riscv32 <elf>`, fd 0 and fd 3 regular files (an empty hint), fd 1 captured to a
file. The comparison is the guest's **exit status** and its **fd 1 bytes**, and nothing
below that — no register, no pc, no instruction count, no trace. S12 held the two to each
other register file by register file; S-IO withdrew that. It was never the property this
project needs — this VM is not a clone of QEMU, and its internals exist for the witness
and the proof — and since S23 it is not even true: a delegation ecall runs natively here
and takes the `-ENOSYS` software fallback under QEMU, so the two instruction streams
differ *by design* and agree on the answer. What holds a trace to *this* VM's own
semantics is `tests/trace.rs`, `crates/trace`'s log self-check and each family's row
suite, all of which run in `cargo test --workspace` with no emulator installed.

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
| `tests/guests.rs` | the guests' host-computed answers (fib, heap, atomics, rvc-dense), acceptance 10 (echo's `-ENOSYS` fallback computes the S02 permutation), orderbook's fd 3 invariance, `opcodes` executes all 58 non-trapping mnemonics and every instruction of its compressed block, acceptance 11 (seven misaligned kinds, both paths), `run` == `trace_run`, **the recorded public input is what the host supplied and not the prefix the guest consumed** — a cursor is guest state and a statement is not; **S-IO's mechanism executed**, over `guests/public-io` — the guest reads its public input with ordinary loads, checks its advice against it and leaves its result in the journal, which the executor reads back out of the window at exit; advice the public input does not commit to publishes nothing; asking for advice that was not supplied is the fatal `OutOfBounds`, because no advice means no region; and a public input longer than its window is refused by name before the first cycle; and **S21's acceptance 3**: the six digests `guests/keccak-test` checks itself against, re-derived from `tiny-keccak` and read out of the guest's own source so a stale literal cannot pass, and both keccak guests run to their exit statuses under the delegation ecall |
| `tests/trace.rs` | acceptance 3 (balance, heap traffic included), 4 (a corrupted RAM read, register write mid-chain, pc write and gap, a forged initial value, and a stale read, each named), 5 (the four-slot clock over every event; `amoadd.w` fills all four slots), 6 (routing), the frame table — roles and slots — restated from the spec and checked on every row, the halting sentinel (the exit row alone writes `HALT_PC`, as the last pc write; every other pc write even), ecall transfers with every byte held to the recorded streams, every ecall answering as the ABI says (must-be-exact 2 without QEMU), the rows rebuilding the log exactly, `final_state`, and `trace::init_windows` (fib's stack window at 2^22, 2^20 and 2^16; every traced guest's list exactly its touched windows above 0 at every height, and passing `program::check_memory_windows`) |
| `tests/archive.rs` | acceptance 7 (byte-identical round trip, hash-equal payloads, answers without re-execution, `io_digest`) and 8 (five phases, the timing section byte for byte, out-of-order refused by byte patch) |
| `tests/qemu_outputs.rs` | **`#[ignore]`d** — the ten-guest suite (`opcodes`, `rvc-dense`, `fib`, `heap`, `atomics`, `consistency` and the four family guests) run under both executors, agreeing on the exit status and on fd 1; the negative control, which holds one QEMU run against the emulator's answer for a *different* input and requires a disagreement; and `ebreak`, which stops both executors and neither cleanly |
| `tests/revm.rs` | **S24**, over `guests/revm-block`, which is built from source rather than read from a committed ELF. In the `test` step: the committed `BlockWitness` is canonical and re-encodes to itself, each canonicity rule refuses by name, the output commitment's three sections read back field by field, native host revm produces the committed output, every keccak-f frame the workload delegated is `tiny-keccak`'s answer, a block whose transactions do not fit its gas limit is refused — including the case revm cannot see, two transactions that each fit the header and together do not — and `BLOCKHASH` still answers `EmptyDB`'s placeholder, which is the pin on the gap that keeps `BlockWitness` unfrozen. **`#[ignore]`d, and CI asks for them by name** at `APOGEE_GUEST_PROFILE=release`: the derived family set (`KECCAK_F` in, S23's two out, every instruction a live row of exactly one family), the guest's **journal** against native revm's answer on the same witness — and its fd 1 empty, the provable binary writing none — the harvested frames against the committed ones, the cycle and occupancy report, and the image against the two ceilings its height turns on. One more needs `qemu-riscv32`: the same binary under both executors commits the same bytes, which is the delegation against the software fallback end to end |
| `tests/consistency.rs` | the three-way consistency suite over `guests/consistency`: host and emulator agree on every corpus input (fd 1 by section, exit status, a panic's message, line and column); every workload, fault and bad input exercised; `trace_run` == `run` and the log balances and ends on `HALT_PC`, a nonzero exit included, with every **cycle-owning** family and all eight M instructions executed — the exemption is `constants::family::CYCLE_OWNING`, so it covers the two RAM window families, the three delegation ones and, since S-IO, the two public value families and `ADVICE_WINDOWS`; the heap probes exit 71; a flipped byte caught at its workload and every leg's flip classified; **`#[ignore]`d** — the same corpus with QEMU as the third leg |

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
