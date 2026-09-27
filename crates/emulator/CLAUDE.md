# `crates/emulator`

## What this crate owns
The reference emulator — RV32IMAC on one hart over a `ProgramImage` — its ecall
dispatch, and the tracing path that fills `crates/trace`'s structures.
**`docs/spec/execution-trace.md` is the convention the trace
follows; `docs/spec/ecall-abi.md` is the ABI the ecalls implement**; since S21,
**`docs/spec/delegation.md`** for what a delegation ecall does; and, since S-IO,
**`docs/spec/public-values.md`** for the two public windows and the advice region.

```rust
// TWO fields, because there are two things a guest is given and what tells them
// apart is what binds them. Both are MEMORY; there is no third field and no stream.
pub struct GuestIo { pub input: Vec<u8>, pub advice: Vec<u8> }
pub struct Execution { pub regs: [u32; 32], pub exit_code: i32, pub cycle_count: u64,
                       pub io: IoStreams }
pub enum EmuError { NotAnInstruction { pc }, IllegalInstruction { pc, word }, Ebreak { pc },
                    Misaligned { pc, addr, width }, OutOfBounds { pc, addr },
                    ClockOverflow { cycle },
                    PublicInputTooLong { len }, JournalTooLong { len },   // S-IO
                    DelegationFamilyAbsent { pc, number },
                    DelegationFrame { pc, detail } }                         // + Display

pub fn run(image: &ProgramImage, io: &GuestIo) -> Result<Execution, EmuError>;
pub fn trace_run(image: &ProgramImage, io: &GuestIo, tables: &DecodedTables, config: &VmConfig)
    -> Result<(FamilyTraces, MemoryEventLog, CycleProfile, Execution), EmuError>;

// S26: the PULL-BASED tracer. One partial buffer per family and the last-access tables,
// and nothing that grows with the cycle count. `docs/spec/streaming.md`.
pub struct ShardChunk { pub family: FamilyId, pub index: u32, pub rows: ChunkRows }
pub enum ChunkRows { Cycles(Box<FamilyTrace>), Invocations(DelegationTrace) }
pub struct StreamedExecution { pub state: MemoryState, pub profile: CycleProfile,
                               pub execution: Execution }
pub struct StreamingRun<'a> { /* a Machine with a streaming recorder */ }
impl<'a> StreamingRun<'a> {
    pub fn new(image: &ProgramImage, io: &'a GuestIo, tables: &'a DecodedTables,
               config: &VmConfig) -> Result<StreamingRun<'a>, EmuError>;
    pub fn next_shards(&mut self) -> Result<Vec<ShardChunk>, EmuError>;  // empty == exited
    pub fn finish(self) -> Result<(Vec<ShardChunk>, StreamedExecution), EmuError>;
}

// S21: the reference permutation, and the frame's two readings of it.
pub fn keccak_f(state: &mut [u64; 25]);
pub fn lanes_of(words: &[u32; 50]) -> [u64; 25];
pub fn words_of(lanes: &[u64; 25]) -> [u32; 50];
```

`trace_run` returns the `Execution` too — a fourth element beside the stage's three —
because `TraceArchive::from_execution` needs the two public byte strings and none of the
other three carries them. Put to the repository owner, who chose it over a second execution
or rebuilding them from the log.

**`GuestIo` is the two things a guest is given, and what tells them apart is what binds
them.** `input` is the statement's public input, which the executor lays out in the public
input window with `program::public_io_words`; `advice` is the prover's private bytes at
`guest_memory::ADVICE_ORIGIN`, framed by `trace::advice_word`. Both are *memory*, reached
by ordinary loads; the statement binds the first at the window's init column and binds
nothing of the second. It had four fields until the POSIX layer was deleted — `stdin` and
`hint` were served over `read`, which was never a provable ecall, so a guest reading either
was a guest no proof covered. **An Apogee guest has no file descriptors**, so there is
nothing a host could hand it that is neither of these two.

**`Execution::io` is the execution's public values, and there is nothing else to carry**
(S-IO). `io.input` is the public input it was given — the window's contents, whether or not
the guest read a byte of it, because a window is not a stream cursor — and `io.output` is
the **journal** `Machine::finish` reads back out of the public output window at exit. The
`stdout` and `stderr` fields beside them are gone with the descriptors that fed them.

## Frozen invariants
- **One core.** `run`, `trace_run` and `StreamingRun` execute through the same `Machine`;
  the tracing paths differ only in a `Recorder` that receives each cycle's staged queries.
  A cycle stages its queries by role as it executes, and commits them — pc query first, then
  roles in order — only when it completes, so a fatal error leaves nothing behind.
- **There is ONE `Recorder::record`, and the two tracing paths differ in what it keeps**
  (S26). `Keep::Whole` holds a `MemoryEventLog` and every family's every row;
  `Keep::Streaming` holds a `MemoryState` and hands a buffer away the moment it reaches its
  family's height. Two `record` implementations would be two traces to keep equal and the
  divergence would be silent, so the row building, the routing and the ordering are one
  function and only the memory arm differs.
- **A streaming buffer never holds more than `height − 1` rows at a record boundary**
  (S26), because the flush happens inside `record` and not between instructions. At S26
  that was load-bearing: a `read` or `write` ecall committed one **transfer cycle** per word
  it moved, so a single instruction could push tens of thousands of rows, and a flush that
  only ran per instruction would overshoot a height and leave a chunk to split. Every
  instruction now commits exactly one cycle, so no instruction can overshoot by more than a
  row — but the flush stays where it is, because "a chunk **is**
  `docs/spec/block-proof.md` §5.1's cut" is a property worth holding by construction rather
  than by an argument about what instructions exist. `tests/streaming.rs` holds every chunk
  to that buffer's own slice, row for row.
- **The streaming run's shard indices and cycle profile survive a flush** (S26), because
  the recorder counts rows per family rather than reading a buffer's length: a flushed
  buffer is replaced by an empty one, so `len()` is no longer the occupancy.
- **Two runs of one `(image, io)` are one execution** — no clock, no randomness, no
  threads, and the one hash map is accessed by key — which is what lets the streaming
  prover's two passes cut the same shards (`docs/spec/streaming.md` §2).
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
  **addressable regions** or a delegation frame byte outside the RAM window (`OutOfBounds`),
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
  asking for what was not handed over (`docs/spec/public-values.md` §6). One bound did
  **not** widen and is still the RAM window: a delegation frame. It was two until the POSIX
  layer went, the other being an ecall's transfer buffer, and there is no ecall that moves
  a buffer any more.
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
  `trace_run` alike; every other row, a delegation request's included, is unchanged. So a
  log's final pc value is `HALT_PC`, written once, and every other pc write is even. Added
  at S14, `docs/spec/memory.md` §5.
- **Routing panics, never skips**: a pc no decoded table claims, or claimed by a family
  that is not its instruction's, means `tables` are not this program's.
- **`Machine::new` seeds the two prover-chosen regions and nothing else.** The public input
  window is `program::public_io_words(io.input)`, word for word — the one spelling of the
  layout, shared with `trace`'s column builder and the verifier's own extension, so the
  three cannot drift — and the advice region is `trace::advice_word` over `io.advice`. The
  journal window starts at 0 and stays there until the guest stores into it, which is
  `PUBLIC_OUTPUT`'s literal-0 init leaf. There is no third thing to seed: a guest reads its
  input out of the window or takes it as advice, and those are the two fields `GuestIo` has.
- **`Execution::io` is the public values, and the only values an execution reports**
  (S-IO). `io.input` is the window's whole contents — what the *statement* carries, whether
  or not the guest read a byte of it, because a window is not a stream cursor — and
  `io.output` is the journal read out at exit.
- **An ecall is exactly one cycle, and there are no transfer cycles.** Every ecall a guest
  may issue takes one argument in `a0` and moves no bytes, so `Machine::transfer` is
  **deleted** and the `ecall` arm commits one row: `a7` at slot 1, `a0` at slot 2, `a0`
  written at slot 3, and the fall-through — or `HALT_PC` on an exit. `read` and `write`
  were the only calls that moved a buffer, each bringing one transfer cycle per word
  touched, and both went with the POSIX layer. A number the ABI does not list reads `a7`
  and `a0` like any other and answers `-ENOSYS`. The emulator spells no ABI number itself;
  `crates/constants/tests/ecall_abi.rs` checks that.
- **A delegation ecall's own answer can be a fatal error, and `MOD_MUL`'s is** (S26). The
  other three delegations are total on their frames: any 200, 96 or 100 bytes are a state, a
  triple of `Fr`s or an operand pair. A modular multiply is not — `a · b mod 0` is nothing —
  so `mod_mul_frame` returns `EmuError::DelegationFrame { detail: "the modulus is zero" }`
  and the execution stops. That is a **guest** error like a misaligned load, not an answer,
  and the circuit agrees by construction: its `out < m` borrow chain cannot hold at `m = 0`,
  so a zero-modulus row is unprovable rather than provable-with-a-wrong-answer.
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
  `-ENOSYS` to. An executor *without* the circuit answers `-ENOSYS` and the guest's software
  fallback runs; this VM has all four circuits, so it never takes that branch, and the
  fallback is the ABI's contract (`docs/spec/delegation.md` §2) rather than a path anything
  in this repository exercises.
- **`keccak_f` is the one keccak permutation in the repository** and the emulator owns it, because
  the emulator is what executes it; the circuit's forward pass is checked against it and
  `tests/keccak.rs` checks it against `tiny-keccak` on all 1,600 single-bit states. The
  guest SDK's software fallback is a second implementation by necessity — it is `no_std`
  guest code — and `guests/keccak-test` is what holds the two to the same digests.

## There is no second executor
`qemu-riscv32` is gone from the repository: not an oracle, not a runner, not a dependency,
not a consideration. It was the only executor before S12 and the output oracle after it,
and `tests/qemu_outputs.rs` is deleted along with the guest I/O layer that made a shared
comparison possible — a POSIX host can give a guest fd 0 and read its fd 1, and it cannot
give one a public input window, an advice region or a journal, none of which is in any
`PT_LOAD`. So an Apogee-SDK guest was never runnable there, and once every guest became one
there was nothing left to compare.

What holds a trace to *this* VM's own semantics is `tests/trace.rs`, `crates/trace`'s log
self-check, `crates/checker`'s multiset and memory suites and each family's row suite — all
of which run in `cargo test --workspace`, with no emulator to install. That is the better
arrangement in any case: this VM is not a clone of QEMU, its internals exist for the witness
and the proof, and since S23 the two instruction streams differed *by design*, a delegation
ecall running natively here and taking the `-ENOSYS` software fallback there.

## Tests
| File | What |
| --- | --- |
| `src/lib.rs` (unit) | the last cycle on the 38-bit clock runs and the next is `ClockOverflow` |
| `tests/keccak.rs` | `keccak_f` against `tiny-keccak`: the all-zero state, the all-ones state, **all 1,600 single-bit states**, a random walk, and `lanes_of`/`words_of` round-tripping. 7 tests |
| `tests/guests.rs` | the guests' host-computed answers (fib, heap, atomics, rvc-dense), `echo` copying its advice into the journal through the heap, orderbook committing the same journal under advice it cannot verify, `opcodes` executes all 58 non-trapping mnemonics and every instruction of its compressed block, acceptance 11 (seven misaligned kinds, both paths), `run` == `trace_run`, **the recorded public input is what the host supplied and not the prefix the guest consumed** — a cursor is guest state and a statement is not; **S-IO's mechanism executed**, over `guests/public-io` — the guest reads its public input with ordinary loads, checks its advice against it and leaves its result in the journal, which the executor reads back out of the window at exit; advice the public input does not commit to publishes nothing; asking for advice that was not supplied is the fatal `OutOfBounds`, because no advice means no region; and a public input longer than its window is refused by name before the first cycle; and **S21's acceptance 3**: the six digests `guests/keccak-test` checks itself against, re-derived from `tiny-keccak` and read out of the guest's own source so a stale literal cannot pass, and both keccak guests run to their exit statuses under the delegation ecall |
| `tests/trace.rs` | acceptance 3 (balance, heap traffic included), 4 (a corrupted RAM read, register write mid-chain, pc write and gap, a forged initial value, and a stale read, each named), 5 (the four-slot clock over every event; `amoadd.w` fills all four slots), 6 (routing), the frame table — roles and slots — restated from the spec and checked on every row, the halting sentinel (the exit row alone writes `HALT_PC`, as the last pc write; every other pc write even), every ecall answering as the ABI says — an exit, a delegation answered 0, or `-ENOSYS`, and one cycle each — the rows rebuilding the log exactly, `final_state`, and `trace::init_windows` (fib's stack window at 2^22, 2^20 and 2^16; every traced guest's list exactly its touched windows above 0 at every height, and passing `program::check_memory_windows`) |
| `tests/streaming.rs` | **S26**: `StreamingRun` against `trace_run` over twelve guests — every chunk equal to that family's own slice of the whole buffer row for row, the chunk set equal to `trace::plan_shards`' counts, no chunk longer than its height, the final `MemoryState` equal to the log's (and the window list at three heights and the boundary read off it), and the profile and `Execution` equal. `keccak-test` and `recursion-ops` are in the list for the `Invocations` arm and `guests/shards` for the flush path: its add/sub family runs 1,064,970 cycles, so at `2^16` it fills **sixteen** buffers before its last short one, and without it every chunk would come from the tail |
| `tests/archive.rs` | acceptance 7 (byte-identical round trip, hash-equal payloads, answers without re-execution, `io_digest`) and 8 (five phases, the timing section byte for byte, out-of-order refused by byte patch) |
| `tests/revm.rs` | **S24**, over `guests/revm-block`, which is built from source rather than read from a committed ELF. In the `test` step: the committed `BlockWitness` is canonical and re-encodes to itself, each canonicity rule refuses by name, the output commitment's three sections read back field by field, native host revm produces the committed output, every keccak-f frame the workload delegated is `tiny-keccak`'s answer, a block whose transactions do not fit its gas limit is refused — including the case revm cannot see, two transactions that each fit the header and together do not — and `BLOCKHASH` still answers `EmptyDB`'s placeholder, which is the pin on the gap that keeps `BlockWitness` unfrozen. **`#[ignore]`d, and CI asks for them by name** at `APOGEE_GUEST_PROFILE=release`: the derived family set (`KECCAK_F` in, S23's two out, every instruction a live row of exactly one family), the guest's **journal** against native revm's answer on the same witness, the harvested frames against the committed ones, the cycle and occupancy report, and the image against the two ceilings its height turns on. Acceptance 3 was the same computation under both executors, over a second `revm-block-stdio` binary reading fd 0; the binary and the test are **deleted**, there being no second executor and no fd 0 |

The guests are the committed ELFs in `crates/loader/tests/vectors/`, pinned there — except
`revm-block`, which `tests/revm.rs` builds from source because it has no committed fixture.
