# `crates/emulator`

## What this crate owns
The reference emulator — RV32IMAC on one hart over a `ProgramImage` — its ecall
dispatch, the tracing path that fills `crates/trace`'s structures, and, since
S-RECURSION, the field memory and the four coprocessors that work on it.
**`docs/spec/execution-trace.md` is the convention the trace
follows; `docs/spec/ecall-abi.md` is the ABI the ecalls implement**; since S21,
**`docs/spec/delegation.md`** for what a delegation ecall does; since S-IO,
**`docs/spec/public-values.md`** for the two public windows and the advice region;
and, since S-RECURSION, **`docs/spec/recursion.md`** §1.4 and §2-§6 for the field
memory, its four families and the `a0` a recursion request leaves.

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
pub fn keccak_round(state: &mut [u64; 25], round: usize);   // S26d: what ONE invocation does
pub fn keccak_f(state: &mut [u64; 25]);                     // 24 of them
// S26e: what ONE SHA256_COMP invocation does -- four rounds and four schedule words.
pub fn sha256_call(group: usize, state: &mut [u32; 8], window: &mut [u32; 16]);
pub fn lanes_of(words: &[u32; 50]) -> [u64; 25];            // the STATE words, not the frame's
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
  threads, and the two hash maps, RAM's pages and since S-RECURSION the field memory's
  cells, are accessed only by key — which is what lets the streaming prover's two passes
  cut the same shards (`docs/spec/streaming.md` §2).
- **Machine state is plain**: `[u32; 32]` registers, the pc, RAM as a hash map of 4 KiB
  pages (absent is zeros), every slot decoded once up front, and since S-RECURSION the
  field memory as a hash map of `u32` cells to `Fr` (absent is 0). Registers start at 0,
  `x0` included; the pc starts at the entry point; RAM starts as the image, plus — since
  S-IO — the public input window and the advice region, seeded below; the field memory
  starts empty.
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
  store reaches ordinary RAM, either public window, or the advice region; the hole below
  them is `OutOfBounds`, so a null dereference is still a loud error and not a trace
  nothing can prove. **There is one hole below `RAM_ORIGIN` since S-STREAM and there were
  two before it**: at `family::PUBLIC_WINDOW_HEIGHT = 2^12` the two windows are 16 KiB
  each, at `0x8000` and `0xC000`, and end flush against `RAM_ORIGIN`, so the gap that sat
  between them and the image — they were a kilobyte each, at `0x8000` and `0x8400` — is
  gone. What survives is `[0, PUBLIC_INPUT_ORIGIN)`, which is the half the null-dereference
  argument rests on. **Advice is bounded at what the host supplied**:
  `Machine::advice_end` is
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
  three cannot drift — and the advice region is `trace::advice_word` over `io.advice`.
  **A zero word is skipped**, as the advice seeding already skipped one: since S-STREAM
  the window is 4,096 words where it was 256, nearly all of them padding on a real input,
  and a page that was never written reads 0 anyway — so the skip changes no value a guest
  or a column builder can observe and saves seeding 16 KiB of zeros per run. The
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
- **A delegation ecall's own answer can be a fatal error, and only `POSEIDON2`'s never
  is** (S26, restated at S26b–S26e). Any 96 bytes are a Poseidon2 state, so
  `poseidon2_frame` takes no `pc`; `FR_ARITH` refuses an opcode that is not add, multiply
  or inverse and an operand that is not a canonical `Fr`; `KECCAK_F` and, since S26e,
  `SHA256_COMP` refuse the one word that indexes the call — a round at or above 24, a
  group at or above 16 — which has no one-hot selector in the circuit. `MOD_MUL`'s frame is not
  total, and since S26b it refuses **three** frames by name rather than one: a selector word
  no `mod_mul::CODES` entry holds, and either operand at or above the modulus it selects.
  **`EC_ADD`'s is not either**, and it refuses **seven**: a selector naming no (curve,
  group) pair, and each of the six values its group reads at or above the selected modulus —
  which are `x1..z2` on a group-0 or group-1 row and the six intermediates on a group-2
  one, so the refusal set is a function of the group and not a fixed list.
  (S26's zero-modulus refusal is gone with the operand it read — there is no zero modulus
  in a four-entry table of primes.) Each is a **guest** error like a misaligned load, not
  an answer, and each is a frame the circuit has no witness for.
  **The operand refusals are not tidiness.** Long division answers correctly for any
  operands below `2^256`, so an executor that accepted them would run a guest clean, pass
  every trace-level test, and leave the failure to a gate — anonymously, as
  `LayerInconsistency { layer }`, hours into a deferred block proof. `guests/vendor/k256`
  handed the delegation an operand equal to `p` by design until S26b, so this is a case
  that has actually occurred, not one imagined for the comment.
- **A delegation ecall performs the permutation and answers 0** (S21). The arm keys on
  `program::delegation_family(n)`, never on a literal: it reads `a0` as the frame base,
  refuses a misaligned or out-of-window one as the ordinary `Misaligned` / `OutOfBounds`
  fatal errors, permutes the 50 words in place, logs the 50 RAM events at
  `constants::delegation::FRAME_DELTA` — **right after the pc query and before the roles**,
  which is what makes `(RAM, 0)` a pair no role takes — stages the mirror query
  (`Role::Delegate`, at the base, reading the zero tuple), routes an `Invocation` to the
  family's `DelegationTrace`, and writes `constants::delegation::a0_after` into `a0` with
  `next_pc` the fall-through — 0 for the six base types, and since S-RECURSION the frame
  base advanced past the frame for the four field families (below). A
  program whose `VmConfig` lacks the family it calls is `DelegationFamilyAbsent`, loudly:
  the executor and the preprocessor disagreeing about the ABI is not something to answer
  `-ENOSYS` to. An executor *without* the circuit answers `-ENOSYS` and the guest's software
  fallback runs; this VM has every delegation's circuit, so it never takes that branch, and
  the fallback is the ABI's contract (`docs/spec/delegation.md` §2) rather than a path
  anything in this repository exercises.
- **`keccak_round` is what one invocation does, and `keccak_f` is 24 of them.** S26d made one
  `KECCAK_F` delegation row one *round* (`docs/spec/delegation.md` §6), so the round is the
  function the circuit is checked against and the permutation is the function every oracle
  compares: `tests/keccak.rs` holds `keccak_f` to `tiny-keccak` on all 1,600 single-bit states
  and holds 24 `keccak_round`s to `tiny_keccak::keccakf` besides, with the round's **index**
  shown to be load-bearing — the 24 rounds of one state are pairwise distinct. The guest SDK's
  software fallback is a second implementation by necessity — it is `no_std` guest code — and
  `guests/keccak-test` is what holds the two to the same digests.
- **`keccak_frame` and `sha256_frame` can refuse a frame**: a round word at or above 24, or
  a group word at or above 16, has no one-hot selector in the circuit, so answering it would
  produce a trace no honest prover could prove. It is `EmuError::DelegationFrame`, as
  `mod_mul_frame`'s and `ec_add_frame`'s refusals are.
- **`sha256_call` is what one `SHA256_COMP` invocation does** (S26e): four rounds with
  `K_{4r+k}` and window word `k`, then the four schedule words those rounds unlock, the
  window shifted down four and refilled with them. Sixteen calls are one compression, the
  feed-forward being the caller's; its unit test holds the first call to FIPS 180-4's
  `t = 3` working variables and `W_16..W_19`, and sixteen to `sha256("abc")`.
- **The field memory belongs to the four field families and to nothing else**
  (S-RECURSION, `docs/spec/recursion.md` §2). No load or store reaches a cell; only
  `FR_OP`, `P2_FIELD`, `FIELD_IO` and `FQ_OP` invocations read and write one, each access
  at its family's own slot `4c + Δ` on the requesting cycle `c`. **A field access is not a
  `MemoryEvent`**, a value not being a `u32`: the recorder hands it to
  `MemoryState::record_field` — the log's own state on the whole path, the streaming state
  on the other, `Keep::record_field` being the one arm that differs, as `Keep::record` is —
  which asserts, per cell, that the value read is the cell's last write and that the read
  strictly precedes the write, and returns the read timestamp. The access itself goes to
  the invocation's `DelegationTrace::accesses` as a `trace::Access`,
  `program::delegation_accesses(family)` of them a row (3, 8, 9 and 13), `None` where the
  op makes no such access. `FIELD_IO`'s eight RAM data words are the exception: they are
  ordinary RAM events at `field_io::DATA_DELTA` = 1, after the frame's slot 0, so a frame
  and its data may overlap, and they appear among the accesses too. A `TraceArchive`
  holding a field family's buffer has no wire form — `deterministic_payload` panics on
  one — so a recursion execution streams.
- **A field request leaves `a0` past its frame, and its frame is read-only** (§1.4). The
  ecall arm answers `a0_after(index, base) = base + 4·words` for the number's row of
  `program::DELEGATIONS`, every field family's being past `BASE_TYPES`, so a tape of
  consecutive frames replays as back-to-back `ecall`s. The frame is written back unchanged,
  still logged as RAM events at `FRAME_DELTA`, and what a call computes lands in field
  cells — or, for an `EXPORT`, in its RAM data words. Each executor checks before it writes,
  and every refusal is `EmuError::DelegationFrame`, a frame no witness exists for:
  - **`FR_OP`** `[op, d, a, b]`, §3's nine ops: `a` at Δ0 read-only, `b` at Δ1, `d` at Δ2,
    each absent where its op makes none — `IMM` reads neither operand, `INV` and `SHL` not
    `b`, and `EQ` writes nothing. `INV` of 0 answers 0; `IMM` and `SHL` read `b`'s frame
    word as an integer; `DIGIT` writes `b ← (a − d′)/2^8` before `d ← d′`, the low 8 bits
    of `a`'s canonical integer, so `b = a` peels in place. Refused: an op outside
    `fr_op::OPS`, and an `EQ` whose two cells differ — an assertion, so a check that fails
    is a fatal guest error and never an answer.
  - **`P2_FIELD`** `[n, s, x, y, d]`: one duplex step of `transcript::Transcript`, the
    lanes `(n ≥ 1 ? x : s₀, n = 2 ? y : (n = 1 ? 0 : s₁), s₂ + n)` through
    `transcript::poseidon2_permute` and written to `d..d+2` at Δ3, after reading `s..s+2`
    at Δ0, `x` at Δ1 when `n ≥ 1` and `y` at Δ2 when `n = 2`. Refused: `n > 2`, and a
    triple at `s` or `d` that would pass `u32::MAX`.
  - **`FIELD_IO`** `[op, cell, ptr]`: the eight words at `ptr + 4k` take the **load**
    rule, not the frame's — `Misaligned` off a word boundary, `OutOfBounds` outside
    `trace::addressable` or past `advice_end`, or where `ptr + 4k` wraps — so a blob in the
    advice region is imported where it lies. `IMPORT` writes `Σ w_k·2^{32k}` mod p to the
    cell and the words back unchanged; `EXPORT` writes the cell's canonical encoding to the
    words — the honest representative, the circuit asking only congruence and 32-bit
    limbs — and the cell back unchanged. Refused: any other op.
  - **`FQ_OP`** `[op, d, a, b]`: the op word's code (bits 0..3), its `IND_D`, `IND_A` and
    `IND_B` flags (bits 3..6) and its digit cell (`word >> 6`), read at Δ0 on every row;
    an indirect operand's element is its word plus `8·digit`; then `a`'s, `b`'s and `d`'s
    four cells at Δ1, Δ2 and Δ3 — thirteen accesses, every one live. `MUL`, `ADD` and `SUB`
    write `d′` reduced below q, the circuit admitting any representative below `2^256` and
    this being the honest one; `MULEQ` writes `d` back unchanged; `FROM128` writes
    `a₀ + 2^128·a₁`, unreduced. Refused: a digit cell not holding an integer below `2^24`,
    an element whose cells would pass `u32::MAX`, an operand limb not below `2^64` (and
    `d`'s, on `MULEQ`), a `FROM128` half not below `2^128`, a `MULEQ` whose `a·b ≢ d`
    mod q, and any other code. **§6's element rule is not checked here**: that `b`'s and
    `d`'s four cells were last written together is `prover::fill::fq_op`'s assertion and
    `verifier_core::tape::run`'s refusal.

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
| `tests/keccak.rs` | `keccak_f` against `tiny-keccak`: the all-zero state, the all-ones state, **all 1,600 single-bit states**, a random walk, and `lanes_of`/`words_of` round-tripping over the 50 **state** words. Since S26d also `keccak_round`, which is what one invocation does: 24 of them are `tiny_keccak::keccakf` and one of them is not, and the 24 rounds of one state are pairwise distinct — the index is load-bearing, and it is what the circuit's one-hot selector has to get right. 9 tests |
| `tests/guests.rs` | the guests' host-computed answers (fib, heap, atomics, rvc-dense), `echo` copying its advice into the journal through the heap, orderbook committing the same journal under advice it cannot verify, `opcodes` executes all 58 non-trapping mnemonics and every instruction of its compressed block, acceptance 11 (seven misaligned kinds, both paths), `run` == `trace_run`, **the recorded public input is what the host supplied and not the prefix the guest consumed** — a cursor is guest state and a statement is not; **S-IO's mechanism executed**, over `guests/public-io` — the guest reads its public input with ordinary loads, checks its advice against it and leaves its result in the journal, which the executor reads back out of the window at exit; advice the public input does not commit to publishes nothing; asking for advice that was not supplied is the fatal `OutOfBounds`, because no advice means no region; and a public input longer than its window is refused by name before the first cycle; and **S21's acceptance 3**: the six digests `guests/keccak-test` checks itself against, re-derived from `tiny-keccak` and read out of the guest's own source so a stale literal cannot pass, and both keccak guests run to their exit statuses under the delegation ecall; and **S-RECURSION's** `guests/field-ops` — every `FR_OP` and `FQ_OP` op, a `P2_FIELD` step at each of `n = 2, 1, 0`, both `FIELD_IO` moves and a replayed tape, each result held to a literal through an `EXPORT` — exiting 26, its config the recursion format, and, traced, 38, 5, 51 and 11 invocations of the four families, one field window at `2^20`, and cell 0, read and never written, re-stamped and still 0. No suite here streams it; `crates/checker/tests/recursion.rs` holds its rows to the circuits |
| `tests/trace.rs` | acceptance 3 (balance, heap traffic included), 4 (a corrupted RAM read, register write mid-chain, pc write and gap, a forged initial value, and a stale read, each named), 5 (the four-slot clock over every event; `amoadd.w` fills all four slots), 6 (routing), the frame table — roles and slots — restated from the spec and checked on every row, the halting sentinel (the exit row alone writes `HALT_PC`, as the last pc write; every other pc write even), every ecall answering as the ABI says — an exit, a delegation answered 0, or `-ENOSYS`, and one cycle each — the rows rebuilding the log exactly, `final_state`, and `trace::init_windows` (fib's stack window at 2^22, 2^20 and 2^16; every traced guest's list exactly its touched windows above 0 at every height, and passing `program::check_memory_windows`) |
| `tests/streaming.rs` | **S26**: `StreamingRun` against `trace_run` over thirteen guests — every chunk equal to that family's own slice of the whole buffer row for row, the chunk set equal to `trace::plan_shards`' counts, no chunk longer than its height, the final `MemoryState` equal to the log's (and the window list at three heights and the boundary read off it), and the profile and `Execution` equal. `keccak-test` and `recursion-ops` are in the list for the `Invocations` arm and `guests/shards` for the flush path: its add/sub family runs 1,064,970 cycles, so at `2^16` it fills **sixteen** buffers before its last short one, and without it every chunk would come from the tail |
| `tests/archive.rs` | acceptance 7 (byte-identical round trip, hash-equal payloads, answers without re-execution, `io_digest`) and 8 (five phases, the timing section byte for byte, out-of-order refused by byte patch) |
| `tests/revm.rs` | **S24**, over `guests/revm-block`, which is built from source rather than read from a committed ELF. In the `test` step: the committed `BlockWitness` is canonical and re-encodes to itself, each canonicity rule refuses by name, the output commitment's three sections read back field by field, native host revm produces the committed output, every keccak-f frame the workload delegated is `tiny-keccak`'s answer, a block whose transactions do not fit its gas limit is refused — including the case revm cannot see, two transactions that each fit the header and together do not — and `BLOCKHASH` still answers `EmptyDB`'s placeholder, which is the pin on the gap that keeps `BlockWitness` unfrozen. **`#[ignore]`d, and CI asks for them by name** at `APOGEE_GUEST_PROFILE=release`: the derived family set (`KECCAK_F` in, S23's two out, every instruction a live row of exactly one family), the guest's **journal** against native revm's answer on the same witness, the harvested frames against the committed ones, the cycle and occupancy report, and the image against the two ceilings its height turns on. Acceptance 3 was the same computation under both executors, over a second `revm-block-stdio` binary reading fd 0; the binary and the test are **deleted**, there being no second executor and no fd 0 |

The guests are the committed ELFs in `crates/loader/tests/vectors/`, pinned there — except
`revm-block`, which `tests/revm.rs` builds from source because it has no committed fixture.
