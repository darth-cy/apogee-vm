# S14 — Memory multiset argument, timestamps, init/teardown

Branch `s14-multiset`, 22 commits over `main`, this note the last. Status: implemented,
reviewed by five adversarial lenses with every confirmed finding fixed or assigned to a
stage, and every CI gate green at the final commit — the local gates, the Linux-only QEMU
suites in a container, and the ceremony-backed identity suites on the ceremony machine
("Verification performed"). Twelve acceptance items are met, several in the form the repository owner
chose instead of the prompt's (the remapping is in "Acceptance"). Eight controls
(C1–C8) sit beside them: six show that a rule the design depends on is needed, and C8
is the tamper target for the mask constraints S16 owes.

S14 builds the global memory argument. Every memory event compresses to one field
element. An execution family's reads and writes feed two product trees. RAM is
initialized and torn down in fixed **RAM windows**, carried by two families of one
height. The registers and the pc have **no rows at all**: the verifier computes their
initial and final tuples once per statement, the finals from **64 boundary scalars**
the proof carries. The exit row writes the **halting sentinel** `HALT_PC = 1`, so a
trace that stops early cannot balance. Program identity now also binds the entry pc
and the image window's initial words. Every read carries two timestamp range
obligations in a new lookup element. S15 discharges them; until then a native
evaluator checks them. Binding public I/O to the execution does **not** land here
(deviation 10).

Normative documents written or amended this stage:

- **`docs/spec/memory.md`** (new): the tuple, the frame of an execution family's
  memory columns, RAM windows, the boundary, halting, binding, range obligations, the
  construction-time rules, and what the argument rests on.
- **`docs/spec/gkr.md`** §2.1 (the `RamLive` virtual kind), §4, §4.1 and §4.2 (format
  version 1, the lookup element with a selector, the lookup rules), §4.3 (the
  product-tree padding clause), §5.1 (derived challenge slots).
- **`docs/spec/execution-trace.md`** §4, §6 and §9: the exit row's `next_pc` is
  `HALT_PC`, and what the argument does with final values.
- **`docs/spec/transcript.md`** §8: tags 30–32, the three-message statement descriptor,
  and the amended identity sponge.
- **`prompts/00-master.md`**: three bullets amended, and only those, on the owner's
  authorization: *Statement binding*, *Memory argument (global)*, and
  *VmConfig / program identity*.
- Also updated to match: `docs/spec/ecall-abi.md` §6 (one sentence),
  `docs/guest-program-manual.md` (two identity sentences), `docs/GLOSSARY.md`, the root
  `CLAUDE.md`, and the `CLAUDE.md` of constants, constraints, gkr-verify, gkr,
  checker, trace, program, loader and emulator.

---

## Read these first

The design was settled before any code. A first review of the owner's original
decisions (sparse first-touch init, an image commitment, I/O as an event transcript)
found that a sorted sparse init table cannot be enforced in this engine: a gate reads
row `y` or the pair `y, y + half`, never `y + 1` (`docs/spec/gkr.md` §1). The owner
then gave eight decisions, D1–D8. A second review split them across five clusters
(windows, boundary, I/O, identity, engine). Each cluster had an analyst, a skeptic
told to refute it, and probes against real traces. A critic consolidated them into one
design and a list of owner questions. The owner approved that design and every
recommendation.

For comparison, the design review read zksync-airbender's memory argument
(`docs/subarguments_used.md`). It lets the prover supply a strictly increasing list of
init addresses, which is possible because its circuits compare neighbouring rows. It
keeps registers inside the RAM argument, and its verifier checks the total cycle count.
None of those three carries over here. Only the lesson on the window-id list below does.

1. **RAM windows, not a sparse or a dense enumeration (D1, D6).** Window `w` covers byte
   addresses `[4h·w, 4h·(w+1))`, aligned at address 0, `h` the init families' height
   (default `2^22`, so 16 MiB and 128 windows). Row `y` is the word at
   `4h·w + 4y`. Addresses are distinct inside a window by construction. Across windows
   they are distinct because of verifier-checked window ids: strictly increasing,
   bounded, and absorbed before the memory challenges. The review found that a window
   list chosen after the challenges is a union over up to `2^127` lists at `2^22`, and
   void as a bound at `h ≤ 2^20`; that is the ordering bug the design review records the
   peer project as having fixed. RAM holds `2^29 − 2^14` words, a count no menu height
   divides, so exactly `2^14` rows fall outside RAM at every height. Aligned at 0 they
   are window 0's head, masked by a virtual column. Aligned at `RAM_ORIGIN` they would be
   the top of the stack window, which every traced guest touches. The owner's "short
   final window" (D6) therefore became a fixed head mask, and that mask is a rule against
   a cheating prover, not something that depends on how much memory a guest uses.
2. **Two families of one height (D1, D4).** `INIT_TEARDOWN = 7` is window 0, the image
   window, exactly one shard. `ZERO_WINDOWS = 8` (new) is every touched window above 0,
   zero-initialized, one shard each. Two families keep S13's model of one artifact, one
   height and one identity commitment list per family. The one-family alternatives
   needed two artifacts per family, or per-shard special cases in the verifier. The cost
   is one rule: equal heights. A lower `ZERO_WINDOWS` height would give image words a
   second init row, and a stale read then balances.
3. **The image window's initial values are a setup column bound by identity (D4).**
   `S[0]`, the image column, has row `y` = `image.initial_word(4y)`. It is committed in
   program identity's `INIT_TEARDOWN` slot. A zero window's init value and every init
   timestamp are literal 0. So no init value is a prover column: a committed init value
   would let a stack word start at 5. The probe that motivated this found real traces
   reading initialized image words first: fib 1, atomics 20, heap 7, opcodes 2.
   `decode_program` refuses an image with a file-backed byte at or above `4h`, so the
   owner's "windows covering the image" is narrowed to exactly one image window, which
   the owner confirmed.
4. **Registers and the pc belong to the verifier (D2, D7).** A closed-form family with
   more than one shard would repeat the 32 register rows and the pc row in every shard.
   That duplicates their init tuples, and a stale register read balances. Instead the
   verifier multiplies in `W_b` (32 register inits at 0, the pc at the entry) and `R_b`
   (their finals) once per statement. The finals come from the 64 boundary scalars of
   the next section, absorbed before the challenges. No family has a register or pc row.
5. **`HALT_PC = 1` on the exit row (owner-approved; reverses S12 item 7 for exit
   rows).** Without it every prefix of an execution balances. Measured: a fib run that
   panics (exit 101 after 3,566 cycles) has 889 prefixes ending with `a0 = 0`, and the
   last of them balances with zero residue. `HALT_PC` is odd and below `RAM_ORIGIN`, so
   no entry, fall-through, branch or jump target produces it and no decoded-table row
   claims it. The verifier fixes the pc's final value to it. The emulator and trace side
   landed in S14. The constraints that make "only the exit row writes it" true are
   S16's (`docs/spec/memory.md` §5).
6. **The guest will compute `io_digest` itself; that binding is deferred (D3, D5).** The
   guest leaves the digest's eight little-endian `u32` words in `x24 … x31` at exit, and
   the verifier compares them and `a0` with its public inputs. None of it is S14 work.
   It needs SDK changes (a non-allocating digest, an exit shim, buffers the heap cannot
   exhaust). It also needs the Poseidon2 precompile first: one permutation measured
   **613,100 cycles at release and 4,598,021 at debug**. The 64-scalar boundary already
   carries every register's final value, so the proof shape does not change when it
   lands. No S14 test or document claims fd 0 or fd 1 is bound.
7. **The entry pc is part of program identity (D8).** It is absorbed as a new scalars tag,
   `PROGRAM_ENTRY`, right after `VM_CONFIG`. Without it, a verifying key carrying the
   registered identity next to a different entry pc would verify an execution that
   starts elsewhere. Identity is split into `setup_commitments` (needs the SRS) and
   `identity_from_commitments` (does not), so a verifying-key loader can recompute it.
8. **Engine amendments the owner approved along the way.**
   - A second virtual kind, `RamLive`: `[y ≥ 2^14]`, boolean on the cube by construction,
     no commitment. It is preferred over an identity-committed mask column.
   - A **derived** challenge slot for the window constant `γ_M + RAM + α_addr·4h·w`. One
     artifact then serves every window. The rejected alternative was an extra literal
     layer, which costs one artifact per window id and one more `2^22`-row layer per
     shard.
   - A generic lookup element with a required selector at `FORMAT_VERSION = 1`, rather
     than a range-only record that S15 would reshape again.
   - `PROTOCOL_VERSION` and `CODE_VERSION` stay 0 until the first registered identity
     (deviation 30).

---

## Frozen public API, as built

```rust
// crates/constants/src/lib.rs   (appended; still zero logic)
pub const PROTOCOL_VERSION: u32 = 0;                   // unchanged, owner's decision
pub mod transcript_tags {
    pub const MEMORY_WINDOWS: u64 = 30;                // scalars
    pub const MEMORY_BOUNDARY: u64 = 31;               // scalars
    pub const PROGRAM_ENTRY: u64 = 32;                 // scalars
}
pub mod challenge_slot {
    pub const TOY: u32 = 0;
    pub const MEM_GAMMA: u32 = 1;                      // drawn
    pub const MEM_ALPHA_ADDR: u32 = 2;                 // drawn
    pub const MEM_ALPHA_TS: u32 = 3;                   // drawn
    pub const MEM_ALPHA_VAL: u32 = 4;                  // drawn
    pub const MEM_WINDOW_CONSTANT: u32 = 5;            // derived, never read from a proof
    pub const NAMES: [&str; 6] = ["toy", "mem_gamma", "mem_alpha_addr", "mem_alpha_ts",
                                  "mem_alpha_val", "mem_window_constant"];
}
pub mod lookup_channel {
    pub const TIMESTAMP: u32 = 0;
    pub const RANGE16: u32 = 1;                        // the range convention's halfword; unused at S14
    pub const BITS: [u32; 2] = [19, 16];
    pub const NAMES: [&str; 2] = ["timestamp", "range16"];
}
pub mod family {
    pub const INIT_TEARDOWN: u32 = 7;                  // RAM window 0, exactly one shard
    pub const ZERO_WINDOWS: u32 = 8;                   // new: the touched windows above 0
    pub const COUNT: u32 = 9;
    pub const DEFAULT_HEIGHTS: [u32; COUNT as usize] =
        [1 << 22, 1 << 22, 1 << 22, 1 << 20, 1 << 22, 1 << 22, 1 << 16, 1 << 22, 1 << 22];
                                                       // [7] was 2^20 at S11
    pub const CODE_VERSION: u32 = 0;                   // unchanged, owner's decision
}
pub mod memory {                                       // TS_STEP = 4, TS_BITS = 38 are S12's
    pub const HALT_PC: u32 = 1;
    pub const PART_AS: usize = 0;
    pub const PART_ADDR: usize = 1;
    pub const PART_TS: usize = 2;
    pub const PART_VAL: usize = 3;
    pub const READ_ROOT: usize = 0;
    pub const WRITE_ROOT: usize = 1;
    pub const RAM_LIVE_BIT: u32 = 14;                  // RAM_ORIGIN == 4 << RAM_LIVE_BIT
}
```

```rust
// crates/constraints/src/lib.rs   (#![no_std] + alloc)
pub const FORMAT_VERSION: u32 = 1;                     // was 0; from_bytes reads it first
pub enum VirtualKind { RowIndex, RamLive }             // RamLive: wire tag 1, prints V[ram_live]
pub struct LookupExpr { pub name: String, pub channel: u32,
                        pub selector: PolyAddress,     // an M, W or S column
                        pub tuple: Vec<GateDef> }
pub mod memory;

// crates/constraints/src/memory.rs
pub const CYCLE: PolyAddress = PolyAddress::Memory(0);
pub const FIELD_MASK: u32 = 0;   pub const FIELD_ADDR: u32 = 1;   pub const FIELD_READ_TS: u32 = 2;
pub const FIELD_READ_VALUE: u32 = 3;   pub const FIELD_WRITE_VALUE: u32 = 4;
pub const FRAME_QUERIES: usize = 8;
pub const FRAME_NAMES: [&str; FRAME_QUERIES];          // pc rs1 rs2 arg1 arg2 load ram rd
pub const FRAME_SPACE: [u8; FRAME_QUERIES];            // PC REG REG REG REG RAM RAM REG
pub const FRAME_DELTA: [u64; FRAME_QUERIES] = [0, 1, 2, 2, 2, 2, 3, 3];
pub const PC: usize = 0;  RS1 = 1;  RS2 = 2;  ARG1 = 3;  ARG2 = 4;  LOAD = 5;  RAM = 6;  RD = 7;
pub const FRAME_READ_ONLY: [usize; 5];                   // RS1 RS2 ARG1 ARG2 LOAD
pub fn frame_queries(family: u32) -> &'static [usize];   // the frozen per-family subset
pub fn frame(slot: usize, field: u32) -> PolyAddress;    // M[1 + 5·slot + f]; SLOT, not query id
pub fn gap_hi(slot: usize) -> PolyAddress;               // W[slot]
pub fn rd_inv(width: usize) -> PolyAddress;              // W[width]
pub fn rd_is_zero(width: usize) -> PolyAddress;          // W[width + 1]
pub fn rd_selected(width: usize) -> PolyAddress;         // W[width + 2]
pub fn read_tuple(query: usize) -> GateDef;              // term PART_* is that part
pub fn frame_artifact(queries: &[usize], trace_vars: u32) -> CircuitArtifact;
pub fn family_frame_artifact(family: u32, trace_vars: u32) -> CircuitArtifact;
pub fn image_window_artifact(trace_vars: u32) -> CircuitArtifact;
pub fn zero_window_artifact(trace_vars: u32) -> CircuitArtifact;
pub fn check_memory(a: &CircuitArtifact) -> Result<(), String>;
```

```rust
// crates/gkr-verify/src/memory.rs   (#![no_std]; re-exported at the crate root and by gkr)
pub struct BoundaryFinals { pub reg_ts: [u64; 32], pub pc_ts: u64, pub reg_values: [u32; 31] }
pub fn window_challenges(memory: &ExternalChallenges, window: u32, trace_vars: u32)
    -> ExternalChallenges;                             // copies slots 1–4, derives slot 5
pub fn boundary_factors(memory: &ExternalChallenges, entry_pc: u32, finals: &BoundaryFinals)
    -> (Fr, Fr);                                       // (W_b, R_b), through eval_gate,
                                                       // operand values placed by PART_*
pub fn reconciles(read_roots: &[Fr], write_roots: &[Fr], factors: (Fr, Fr)) -> bool;
// and virtual_at_row / virtual_at_point now cover VirtualKind::RamLive
```

```rust
// crates/checker/src/lib.rs   (std)
pub fn check_padding_identity(a: &CircuitArtifact) -> Result<(), String>;
pub fn violated_lookups(a: &CircuitArtifact, w: &WitnessRow) -> Vec<String>;
pub fn memory_roots(a: &CircuitArtifact, values: &LayerValues) -> Result<(Fr, Fr), String>;
// check_laws now also applies the lookup rules, with code of its own
```

```rust
// crates/trace/src/lib.rs, crates/trace/src/memory.rs   (std)
pub fn init_windows(log: &MemoryEventLog, height: u32) -> Vec<u32>;
pub fn build_memory_columns(log: &MemoryEventLog, queries: &[usize], cycles: &[u64], height: usize)
    -> Vec<(PolyAddress, MultilinearPoly)>;            // the frame's 1 + 5w M columns
pub fn build_frame_witness(log: &MemoryEventLog, queries: &[usize], cycles: &[u64], height: usize)
    -> Vec<(PolyAddress, MultilinearPoly)>;            // its w + 3 W columns
pub fn build_init_teardown_columns(log: &MemoryEventLog, image: &ProgramImage, ram_window: u32,
                                   height: usize) -> Vec<(PolyAddress, MultilinearPoly)>;
                                                       // M[0], M[1]; and S[0] for window 0
pub fn build_boundary_finals(log: &MemoryEventLog) -> BoundaryFinals;
```

```rust
// crates/program/src/lib.rs   (std)
pub const FAMILIES: [FamilyId; family::COUNT as usize];   // nine
pub enum ProgramError { /* S11's five, then */
    ImageOutsideWindow { end: u64, height: u32 },
    WindowRule { rule: &'static str } }
pub fn image_init_column(image: &ProgramImage, height: u32) -> MultilinearPoly;   // U32-backed
pub fn program_identity(image: &ProgramImage, tables: &DecodedTables, config: &VmConfig,
                        srs: &Srs) -> ProgramIdentity;                            // gained `image`
pub fn setup_commitments(image: &ProgramImage, tables: &DecodedTables, config: &VmConfig,
                         srs: &Srs) -> Vec<Vec<G1Affine>>;
pub fn identity_from_commitments(code_version: u32, config: &VmConfig, entry_pc: u32,
                                 commitments: &[Vec<G1Affine>]) -> ProgramIdentity;
pub fn absorb_statement_descriptor(tr: &mut Transcript, config: &VmConfig, shard_counts: &[u32],
                                   windows: &[u32]);                               // gained `windows`
pub fn check_memory_windows(config: &VmConfig, shard_counts: &[u32], windows: &[u32])
    -> Result<(), ProgramError>;
// VmConfig::from_bytes(&[u8]) -> Option<VmConfig> now returns None on a missing or unequal init family
```

```rust
// crates/loader/src/lib.rs
impl ProgramImage { pub fn initial_word(&self, addr: u32) -> u32; }   // the one image-word source
```

`crates/emulator`: no signature changed. `Machine::ecall` commits `next_pc = HALT_PC`
when the ecall number is `EXIT`, and the fall-through otherwise. `run` and `trace_run`
share that path. `Execution` exposes no pc, so the sentinel can be observed only
through `trace_run`.

---

## The boundary scalars

The proof carries **64 scalars**, absorbed as one `MEMORY_BOUNDARY` message (tag 31,
kind scalars). The owner asked for them to be documented here in full.

| position | scalar | meaning | range |
| --- | --- | --- | --- |
| 0–31 | `t_0 … t_31` | register `x_r`'s final timestamp: the write timestamp of its last query, 0 if it was never queried | `< 2^38` |
| 32 | `t_pc` | the pc's final timestamp: the last cycle's pc write | `< 2^38` |
| 33–63 | `v_1 … v_31` | register `x_r`'s final value, `r = 1..31`: its last write, 0 if it was never queried | `< 2^32` |

Position `p` in 33–63 is `v_{p−32}`. Every scalar is a canonical field element whose
integer is below its range. The verifier refuses anything else when it decodes the
message; that decoder is S16's, and nothing decodes the message at S14. In memory each `v`
is a `u32`, but each `t` a `u64` that nothing checks against `2^38`.

**What is not carried, and why.** Two final values are verifier constants:

- `x0`'s is 0. The x0 gadget of `docs/spec/memory.md` §2.4 makes every rd write at
  address 0 write 0. The constant pins only `x0`'s *last* write; without the gadget, a
  write of 5 followed by a read of 5 and a write of 0 balances. `t_0` is still carried,
  because `x0` is queried.
- The pc's is `HALT_PC = 1`. That is what makes the finals mean "the machine halted".

**A register that was never queried** has `(t_r, v_r) = (0, 0)`. Its init tuple
`T(REG, r, 0, 0)` and its final tuple are equal, and they cancel.

**In memory**, `gkr_verify::BoundaryFinals`:

| field | message positions | notes |
| --- | --- | --- |
| `reg_ts: [u64; 32]` | 0–31 | `reg_ts[r] = t_r` |
| `pc_ts: u64` | 32 | `t_pc` |
| `reg_values: [u32; 31]` | 33–63 | `reg_values[i] = v_{i+1}`, register `x_{i+1}`; no entry for `x0` |

`trace::build_boundary_finals(log)` fills it from the log's final state. It panics,
naming the value, if the pc's final value is not `HALT_PC` (the log did not end on an
exit row, or has no pc query) or `x0`'s is not 0.

**The factors** (`docs/spec/memory.md` §4.2), with
`T(AS, ADDR, TS, VAL) = γ_M + AS + α_addr·ADDR + α_ts·TS + α_val·VAL`:

```text
W_b = ∏_{r=0}^{31} T(REG, r, 0, 0) · T(PC, 0, 0, entry_pc)
R_b = T(REG, 0, t_0, 0) · ∏_{r=1}^{31} T(REG, r, t_r, v_r) · T(PC, 0, t_pc, HALT_PC)

accept  iff  ∏ read roots · R_b = ∏ write roots · W_b   and   ∏ read roots · R_b ≠ 0
```

The products run over every shard of every family in the statement, `INIT_TEARDOWN` and
`ZERO_WINDOWS` included, and the boundary enters **once per statement**, never per
shard proof. `entry_pc` comes from the verifying key, which is bound by identity.
`gkr_verify::boundary_factors` evaluates every tuple through `eval_gate` on
`constraints::memory::read_tuple` of query 0 (PC) or 1 (REG), whose term `PART_*` is that
part, at operand values placed by the same constants: mask 1, `addr`, `ts`, `value`. That
is the circuits' own tuple gate, so the boundary cannot drift from the families' part
order. `gkr_verify::reconciles` is the equation.

**Where they are absorbed, and why there.** They are the last message before the
memory challenges are squeezed: after every memory-column commitment, immediately
before `γ_M, α_addr, α_ts, α_val`. A final value chosen *after* the challenges can be
solved outright, `v = (target − γ_M − 1 − α_addr·r − α_ts·t_r)/α_val`, and any trace
then reconciles. Control C6
(`checker/tests/multiset.rs::a_final_value_solved_after_the_challenges_reconciles_and_is_not_a_u32`)
measures this. It takes the unbalanced statement of Acceptance 2 (fib with one `ram`
read value moved by 1) and solves `x10`'s final value from the drawn challenges. The
statement then reconciles, and the solved value has nonzero bytes above bit 32. A `u32`
wire type does not close this: 33 pairs chosen after the challenges give an attacker
many equations to choose from. At S14 no code absorbs the message. The global
transcript that does is S16's.

**No timestamp relation is checked on the finals, and none is needed.** Per address, the
init write is consumed once, every query consumes one write and produces one strictly
later (the gap obligation), and the final read consumes one. So the writes form one
chain of strictly increasing timestamps, and the final read can balance only against the
highest. Cycle contiguity is not the reason.

**`t_pc` is not a cycle count.** The pc query's `read_ts` is a witnessed column under
the frozen frame. One row at cycle 2 can read the timestamp-0 init with gap 7 and write
at timestamp 8, giving `t_pc = 8` from one row. A brute force over one pc address found
125 balanced multisets ending at `HALT_PC`, and 112 of them had cycles that are not
`1..n`. Memory consistency is intact, but nothing may read `t_pc / 4` as "cycles
proven". If S16 fixes the pc read timestamp to the literal `4(c − 1)`, then
`t_pc = 4n`.

**What later stages read from them.**

- `v_10` is `a0` at exit, the exit status. The verifier compares it with a status in
  `PublicInputs` as a `u32`. The policy (require 0, or compare) is the owner's.
- `v_24 … v_31` will be the guest-computed I/O digest's words:
  `x(24+k) = u32::from_le_bytes(d[4k..4k+4])`, with `d = io_digest(I, O).to_bytes()`.
  This convention is recorded here and freezes with the SDK change (deferred). The
  64-scalar format does not depend on which registers hold the digest.

---

## Per-family frames

Landed after the first review pass, on the owner's instruction. The frame was one uniform
8-query layout every execution family carried; it is now the subset of queries each family's
instructions can actually make.

**Why.** No family ever used all eight. `arg1` and `arg2` are read by an ecall's own row
alone; `load` is a load's word at slot 2, and the atomics family keeps its RAM query at slot
3 for every instruction it owns. So the 8-query frame was a union no family reached, and
every family carried dead columns: five memory columns, one witness column, two vacuous
obligations and two leaves per dead query, committed and opened on every row.

| family | `w` | committed columns | obligations | fixture bytes at 22 |
| --- | --- | --- | --- | --- |
| `ADD_SUB_LUI_AUIPC` | 7 | 46 | 14 | 22,611 |
| `JUMP_BRANCH_SLT`, `SHIFT_BITWISE`, `MUL_DIV` | 4 | 28 | 8 | 13,892 |
| `MEM_WORD`, `MEM_SUBWORD` | 6 | 40 | 12 | 20,282 |
| `ATOMICS` | 5 | 34 | 10 | 17,953 |
| *the old uniform frame* | 8 | 52 | 16 | 24,940 |

Committed columns are `1 + 5w` memory plus `w + 3` witness. The three 4-query families drop
46% of their memory-argument committed columns and half their timestamp obligations, and two
of them default to `2^22` rows.

**Soundness is not affected, and the direction of failure is what makes that true.** A frame
*narrower* than its family drops events from the multiset, which leaves their addresses'
chains broken: the honest prover cannot balance, so the failure mode is a refused honest
proof, never an admitted forgery. A frame *wider* than its family carries columns that are 0
on every row — waste, not a hole. Nothing about the tuple, the leaves, the product tree, the
windows, the boundary or reconciliation changed.

**What it hands S16.** S16 ties an instruction's computed value to a `write_value` column, so
a query with no column is an instruction with nothing constraining it. The rule S16 inherits
is therefore that **a family's frame is a superset of the queries its instructions make**.
`crates/trace/tests/memory.rs::every_familys_frame_is_exactly_its_instructions_queries` holds
`frame_queries` *equal* to that union over all 59 `Instr` variants, with the per-instruction
queries written from `execution-trace.md` §4 and the routing taken from `program::row_kind`,
so neither table can drift from the other. Equality rather than containment is deliberate: it
also refuses a query no instruction of the family makes, which would be a dead column again.

**Shape notes for later stages.**

- A column's position is a **slot** in the family's query list; its address space and its
  in-cycle `Δ` come from its **id** in the query table. The two differ for every family, and
  `gkr/tests/memory.rs` pins the distinction per family.
- The row-wise tree pairs neighbours, so each side is padded to a power of two with leaves
  that are literally 1 (`Linear { [], 1 }`). Those cost inner columns only — no committed
  column, no obligation, no enforcing gate. Four of the seven families pad.
- `frame_queries` panics on the two init families, which run no cycles and have no frame.
- One fixture per *distinct* frame: families sharing a query list share bytes, and a test
  holds each of the seven families to one of the four files, so four fixtures pin all seven.

---

## What the argument rests on

`docs/spec/memory.md` §4.2 and §9 are normative; the review corrected both.

- **The RAM-window bound** — no access below `RAM_ORIGIN`, or at `2^31` and above — rests
  on the `V[ram_live]` mask, `1 ≤ id ≤ N − 1` for `ZERO_WINDOWS`, and the gap obligation.
  A zero window at id 0 has no mask, so it would give the words below `RAM_ORIGIN` init
  rows: control C1 balances an access at `0x4` against one. The image refusal is **not**
  part of the bound (§9 as reviewed listed it, and omitted `id ≥ 1`).
- **That the initial values are the program's** rests on the image refusal, which keeps
  every file-backed byte inside window 0's column, and on S16 opening `INIT_TEARDOWN`'s
  `S[0]` base claim against identity's `cm(image column)`. Recomputing identity binds the
  commitment, not the column the proof reads.
- **Coverage**: an address with no init row cannot balance, because every read strictly
  precedes its write. That needs the gap obligation: control C7 shows a query reading its
  own write at `0x4000_0000`, and at register 32, reconciling with only `gap_lo` naming it.
  Until S15 the native evaluator is the only check.
- **Timestamps are integers by counting**, not by a range check. `cycle`, `read_ts` and
  `teardown_ts` are `Fr` columns that nothing bounds. Each matched step adds an integer in
  `[1, 2^38]`, so a closed loop needs more than `p/2^38 > 2^215` steps. A statement has
  fewer than `2^70` tuples: `2^32` shards per family, times 9 families, times `2^30` rows,
  times at most 16 leaves, plus 66 boundary tuples. So no loop closes, and every timestamp is a
  canonical integer below `2^108`. Re-check the count if the shard-count width,
  `MAX_TRACE_VARS`, the family count, the leaves per row or the gap width grows.
- **What ties a mask to its row is S16's.** At S14 a mask is held to booleanity only.
  Control C8 shows three forgeries that keep every gate and obligation and reconcile:
  - a padding row's `rd` query rewriting `x10`, the exit status, after the exit row;
  - a live row's `rd` write masked off;
  - the exit row given a store that rewrites a stack word's final value.

  S16 makes `m_pc` the row's liveness and the table lookup's selector, and every other
  mask `m_q = m_pc·uses_q` (Deferred, S16).

---

## The statement absorb order and the identity recipe

`docs/spec/memory.md` §6 is normative. It amends the master's *Statement binding*
bullet, and the master now says the same.

```text
PROTOCOL_SUITE → PROTOCOL_VERSION → [SRS digest] → VM_CONFIG → SHARD_COUNTS
  → MEMORY_WINDOWS [w_1 … w_k]                               tag 30, possibly empty
  → program identity → public I/O digest
  → INIT_TEARDOWN's memory-column group → ZERO_WINDOWS's memory-column group
                                        (each domain-separated and length-delimited)
  → every other family's memory-column commitments
  → MEMORY_BOUNDARY [t_0 … t_31, t_pc, v_1 … v_31]           tag 31, 64 scalars
  → squeeze γ_M, α_addr, α_ts, α_val
```

`program::absorb_statement_descriptor` writes `VM_CONFIG`, `SHARD_COUNTS` and
`MEMORY_WINDOWS` as three adjacent messages. The list's length varies per execution,
as the shard counts do. Before the challenges, `program::check_memory_windows` checks,
in order:

- both init families are present at one height `h`;
- `SHARD_COUNTS[INIT_TEARDOWN] = 1`;
- the list's length is `SHARD_COUNTS[ZERO_WINDOWS]`;
- the ids are strictly increasing;
- every id is in `[1, 2^29/h − 1]`.

`ZERO_WINDOWS` shard `i` is window `w_i`. The boundary message, the squeeze and the
per-family groups' domain tags belong to S16's global transcript. S16 also appends the
challenge-kind tag the memory squeeze is drawn under.

**Program identity** (`docs/spec/memory.md` §6.2) is a fresh typed transcript that
absorbs:

1. `PROGRAM_IDENTITY` (22): the code version, one scalar;
2. `VM_CONFIG` (23): the family ids ascending, their heights, `bytecode_size_words`;
3. `PROGRAM_ENTRY` (32): `entry_pc`, one scalar;
4. per family ascending, `COMMITMENT`, one list of 4-limb G1 points per family:
   families 0–6 their decoded-table columns in lookup-tuple order; `INIT_TEARDOWN`
   `[cm(image column)]`; `ZERO_WINDOWS` `[]`;
5. one raw `sample`, the identity.

It binds every file-backed byte of the image below `4h` (`.text`, `.rodata`, `.data`)
and the entry pc. It binds nothing an execution chooses: no shard count, no window
list. `setup_commitments` is step 4's lists and needs the SRS.
`identity_from_commitments` is steps 1–5 over given lists and does not, and it is what
a verifying-key loader recomputes against a trusted identity. The new pins
(`crates/program/tests/vectors/identity.txt`) are fib default
`c534517be3117edc9b3230a8c4ef215895ed9ff0382ad420f0e1f9d47ef4ef14` and fib smallest
`417c345b83c15d30e49b66d8d4a186ce1012e53e3fd669f93a905997840b581e`.

---

## What this freezes for every later stage

1. **`docs/spec/memory.md`** in full.
2. **The `gkr.md` amendments**: `VirtualKind::RamLive` (wire tag 1, closed form
   `1 − ∏_{j=14}^{n−1}(1 − y_j)`); derived challenge slots; format version 1, with
   `LookupExpr = (name, channel, selector, tuple)` and the lookup rules; the product-tree
   padding clause.
3. **The tuple.** Parts `AS, ADDR, TS, VAL` in that order; `γ_M` additive; `AS`
   unweighted with `REG = 1, RAM = 2, PC = 3`; `α_addr, α_ts, α_val` in that order.
   Challenge slots 1–5 and their names.
4. **Tags 30, 31, 32**, all scalars, and the channels `lookup_channel::TIMESTAMP = 0`,
   19-bit chunks (`2·19 = TS_BITS`, held by a test), and `RANGE16 = 1`, 16-bit. **The range
   convention** of `docs/spec/memory.md` §7:
   - a value `v < 2^32` is one witnessed column `h` and two `RANGE16` obligations, `h` and
     `v − 2^16·h`, under the row's mask, with no gate;
   - a mod-`2^32` result `r` of an exact expression `e` carries a witnessed `wrap`, the
     gates `wrap − wrap·wrap = 0` and `e − r − 2^32·wrap = 0`, and `r` bounded as above,
     admissible only where `0 ≤ e < 2^33`;
   - a wider wrap is not frozen (open question 12).
5. **The frame** of an execution family's memory columns, over the `w` queries that
   family's instructions can make (`constraints::memory::frame_queries`).
   - A **query table** of 8 — pc, rs1, rs2, arg1, arg2, load, ram, rd — each with its AS
     and Δ. No family holds all eight: `w` is 4, 5, 6 or 7.
   - A column's position is a **slot** in the family's list; its AS and Δ come from the
     query's **id** in the table. The two differ for every family.
   - `M[0]` cycle and `M[1 + 5·slot + f]` for the five fields: `1 + 5w` `M` columns.
   - `W[slot]` `<q>_gap_hi`, then `rd_inv`, `rd_is_zero`, `rd_selected` at `W[w]`–`W[w + 2]`:
     `w + 3` `W` columns.
   - Leaves `read_<q>` then `write_<q>`, each a flat `Quadratic` `m·T + 1 − m`, each side
     padded to a power of two with `Linear { [], 1 }` pad leaves; then row-wise lists
     halving the width to 2, then `trace_vars` halving lists.
   - Enforcing gates: `w` mask booleanity, one write-back per read-only query the family
     holds, 4 x0 gates.
   - `2w` gap obligations, two per read, each with selector `M[mask_slot]`.
   - Every name, and the **padding fill**: a mask-0 row or query carries 0 in every one
     of its memory columns, `cycle` included on a padding row.
6. **RAM window geometry and the two init families**: ids 7 and 8, one height, default
   `2^22`, window 0 always one shard, the window rules of `check_memory_windows`.
7. **The window artifacts**.
   - `M[0] teardown_ts`, `M[1] teardown_value`, no witness columns and no enforcing
     gates.
   - `INIT_TEARDOWN` also reads `S[0] init_value` and `V[ram_live]`.
   - The window constant `WC = γ_M + RAM + α_addr·4h·w` in slot 5, and `outputs =
     [read_root, write_root]` at `READ_ROOT = 0`, `WRITE_ROOT = 1`.
   - Their fixtures, with the frame's, at `n = 22`.
8. **The 64-scalar boundary format** and `BoundaryFinals`, as in the section above.
9. **`HALT_PC = 1`** and the exit row that writes it.
10. **The statement descriptor as three messages**, and the identity recipe with
    `PROGRAM_ENTRY` and the image column. The `setup_commitments` /
    `identity_from_commitments` split.
11. **The builders**: `build_memory_columns`, `build_frame_witness`,
    `build_init_teardown_columns`, `build_boundary_finals`, `init_windows`. S16 and S20
    consume them rather than re-deriving the fill. `ProgramImage::initial_word` is the
    one image-word source, byte by byte from file-backed bytes.
12. **The construction-time rules** of `constraints::memory::check_memory`: forward
    provenance, neither root's cone reading a `W` column, a global slot over `M`, `S` and
    `V` only, and leaf masks that are boolean.
13. **Recorded, not frozen**: the digest register convention `x24 … x31`. It freezes with
    the SDK change.

---

## Artifacts

| Path | Size | SHA-256 | What |
| --- | --- | --- | --- |
| `crates/constraints/tests/vectors/memory_frame_alu.bin` | 22,611 bytes | `48622aa5376f82bdffc501932772f7ac04ce0c8e4838513ff5b9db550470d289` | `ADD_SUB_LUI_AUIPC`'s frame at 22, `w = 7` |
| `crates/constraints/tests/vectors/memory_frame_reg.bin` | 13,892 bytes | `f94da36c6f7052acd10c36a3a0bd04ce09fe2419cdbfa046db4a58b1a716cbc0` | `JUMP_BRANCH_SLT`'s, `w = 4`; also `SHIFT_BITWISE` and `MUL_DIV` |
| `crates/constraints/tests/vectors/memory_frame_mem.bin` | 20,282 bytes | `7a31fd867d4b5490821bcef24e356daf34d834a397efed8fa41b8e821b6fee6f` | `MEM_WORD`'s, `w = 6`; also `MEM_SUBWORD` |
| `crates/constraints/tests/vectors/memory_frame_atomics.bin` | 17,953 bytes | `518c3853426a2ca30216536edc41a2659189c6c1e5abbeca9b516cf2032488c8` | `ATOMICS`', `w = 5` |
| `crates/constraints/tests/vectors/image_window.bin` | 3,907 bytes | `39a8655d430ed5c031e4f27075662fe92a9a1274cd23dc300ae5e2e82df67ecc` | `image_window_artifact(22)` |
| `crates/constraints/tests/vectors/zero_window.bin` | 3,418 bytes | `f08dde677a70c8a15cc7b67b35806e6ee5d9afff9cb703586f21426baa51ec1c` | `zero_window_artifact(22)` |
| `crates/constraints/tests/vectors/toy_cached.bin` | 1,486 bytes | `ee27e1192c4bcf9afa003509f6c06fead29628b02a4c17f86e381bf5609f1c70` | S13's toy, regenerated at format 1 |
| `crates/constraints/tests/vectors/toy_cache_free.bin` | 1,500 bytes | `5318afeb5b5ba5d09871358c89db36a0db12680fa9559a70c67c50b41181251d` | its cache-free compilation, at format 1 |
| `crates/program/tests/vectors/identity.txt` | 713 bytes | `3232810e92795fef2ce795c3c0b84044d54294cc7238da4bb5b11022c4a8032b` | fib's identity at the defaults and at `2^16`, new recipe |
| `docs/spec/memory.md` | 32,386 bytes | — | the normative memory spec |
| `tools/kat-gen/src/memory.rs` | — | — | the `memory` group; `cargo run -p kat-gen -- memory` |

The six memory fixtures are pinned by SHA-256 in `crates/constraints/tests/memory.rs`,
and CI regenerates and diffs them. The toy's sizes did not move from S13 (the format
word 0 → 1 has the same length, and its lookup list is empty), but its hashes did, and
they are repinned in `crates/{constraints,gkr,checker}/tests/common/mod.rs`.
`identity.txt` needs the ceremony, so it is regenerated locally only: `kat-gen` skips it
without `assets/`. Its S11-era digests had already moved before this branch
(`3e08099e…cf18` and `7182f500…1d14`, not S11's `c57dbf1f…151a`).

---

## Acceptance

The stage prompt's items as remapped by the owner's design. File paths are under
`crates/`, and every test listed passes.

| # | Item (as remapped) | Where | Result |
| --- | --- | --- | --- |
| 1 | Honest statement: execution frame + `INIT_TEARDOWN` + `ZERO_WINDOWS` + boundary, over real traces; forward, self-check, roots, laws, witness rows, prove and verify | `checker/tests/memory.rs::fib_honest_statement_reconciles_and_proves`, `::heap_honest_statement_reconciles_and_proves_its_windows`, `::a_frame_per_family_in_any_order_reconciles` | fib (2,117 cycles): one frame shard per family that ran — `ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT`, `SHIFT_BITWISE`, `MEM_WORD`, `MEM_SUBWORD`, each over its own cycles and addressed by its own `frame_queries` — plus windows 0 and 8191 at `2^16`; every shard self-checks, `memory_roots` recomputes its roots, `check_laws`/`check_padding` pass, `violated_relations` and `violated_lookups` empty, `check_memory_windows` passes, `reconciles` true, every shard proved, verified and discharged. heap: the same, except its tallest frame is not proved (deviation 22). The frames in any order, one cycle list reversed, also reconcile |
| 2 | Tamper: one changed value | `checker/tests/multiset.rs::one_changed_value_does_not_reconcile` | fib's first store's `ram` read value + 1: no gate, no obligation, `reconciles` false |
| 3 | Tamper: one changed timestamp, a distinct surface | `multiset.rs::one_changed_timestamp_does_not_reconcile_and_a_moved_cycle_breaks_a_gap` | pc `read_ts` 40 → 39: reconciliation only. Cycle 11 → 10: reconciliation, plus `gap_lo_pc` and `gap_lo_rs1` on that row, a list the test derives |
| 4 | Future read: balanced, roots reconcile, the obligation catches it; comment names S15 | `multiset.rs::a_future_read_balances_and_only_its_gap_obligation_catches_it` | two x0 `rs1` queries' `read_ts` swapped: self-check Ok, `reconciles` true, `violated_lookups` exactly `[(row, gap_lo_rs1)]`; four `gap_hi` values each still caught |
| 5 | Image binding: one flipped image byte | `multiset.rs::a_flipped_image_byte_under_a_read_word_does_not_reconcile` | the byte under `0x12000`, fib's only window-0 word, first touched by a read: false. The entry word, which nothing touches: true (init and teardown rows cancel) |
| 6 | No nonzero init value outside the image | `multiset.rs::a_forged_nonzero_init_value_does_not_reconcile`; `constraints/tests/memory.rs::the_read_sets_are_pinned` | the zero window reads no `S` and no init column (pinned); a forged zero window with an `M[2]` init column validates and passes `check_memory`, reconciles at 0, and does not at 7 on `0x7ffffffc` |
| 7 | Remapped: every touched RAM word lies in exactly one listed window; a duplicated window breaks reconciliation | `multiset.rs::every_touched_ram_word_has_exactly_one_teardown_row`, `::a_duplicated_window_lets_a_stale_read_balance`, `::window_rules_refuse_each_single_change_of_fibs_statement`; `emulator/tests/trace.rs::the_window_list_is_exactly_the_touched_windows_above_zero` | teardown rows with a nonzero `ts` equal the log's final RAM state, for fib and heap. A stale read at `0x7fffff70` fails against the honest statement and balances with a second window-8191 shard. `[8191, 8191]` refused. The list is exactly the touched windows at every menu height for every traced guest |
| 8 | x0 | `multiset.rs::every_read_of_x0_returns_0`, `::a_write_of_5_to_x0_balances_and_rd_write_masked_refuses_it`, `::a_zeroed_register_write_and_a_nonzero_x0_write_are_each_refused_by_their_gate`, `::a_read_only_query_writing_back_another_value_is_refused_by_its_gate`; `gkr/tests/memory.rs::every_frame_proves_and_verifies_and_rejects_a_write_to_x0` | all 432 x0 queries read and write 0, swept across every frame. A write of 5 then a read of 5 reconciles with no obligation, and the self-check and `violated_relations` name exactly `rd_write_masked`. The proof is rejected at layer 0. Each other gate refuses a balanced forgery of its own, named alone: `rd_is_zero_at_nonzero` a register write zeroed through `z = 1`, `rd_is_zero_inverse` an `x0` write of 5 through `z = 0`, and each of the five `<q>_writes_back` a read-only query writing back its read value plus one |
| 9 | Construction-time assertion: tuple-fed witness column | `constraints/tests/memory.rs::a_tuple_fed_from_a_witness_column_is_refused`, `::a_product_of_a_tuple_and_a_witness_copy_two_layers_up_is_refused`, `::cached_entries_are_held_to_the_memory_rules`, `::a_frame_missing_a_booleanity_gate_is_refused`, `::a_window_leaf_masked_by_a_setup_column_or_the_row_index_is_refused`, `::a_global_slot_over_an_inner_column_is_refused` | each mutant passes `validate` and is refused by `check_memory`, naming the gate |
| 10 | Padding: the frame at a menu height verifies; padding rows contribute exactly 1 | `multiset.rs::the_frame_padded_to_2_16_proves_and_its_padding_rows_are_1` | fib's `ADD_SUB_LUI_AUIPC` frame at `2^16`: 657 live rows, every committed cell on its 64,879 padding rows is 0, every row-wise layer exactly 1 there with the depth read off the artifact, the roots equal the `2^12` frame's, `check_padding_identity` Ok, proved and verified |
| 11 | Exhaustive reduced-width gap test | `constraints/tests/memory.rs::the_gap_encoding_is_strict_at_reduced_width`; `multiset.rs::the_gap_obligations_accept_exactly_0_through_2_38_minus_1` | each slot's `gap_lo` expression from each of the four distinct frames at 12 — 22 slot sweeps, with a coverage assertion that they reach all 8 queries of the table — chunks of 5 bits, every cycle `< 2^8` and `read_ts < 2^10`: admitted exactly when `read_ts < ts`. At full width the real obligations accept 0 and `2^38 − 1` and refuse −1 and `2^38` |
| 12 | Dropped obligation fails the build | `constraints/src/memory.rs::a_dropped_gap_obligation_fails_the_build` | 15 of 16 obligations panic at the count assertion, before `validate` |

**The design's controls**, each a rule removed or bypassed, all over fib's trace:

| # | Rule it shows is needed | Where | Result |
| --- | --- | --- | --- |
| C1 | the `V[ram_live]` head mask and `id ≥ 1` | `multiset.rs::a_query_below_ram_origin_balances_only_without_the_head_mask` | a forged `ram` query at `0x4`: false with the mask; honest and forged both reconcile against an unmasked image window that still validates, and the forgery reconciles against the honest window 0 plus a `ZERO_WINDOWS` shard listed at id 0 |
| C2 | the window rules | `multiset.rs::window_rules_refuse_each_single_change_of_fibs_statement`; `program/tests/config.rs::the_window_rules_hold_at_their_boundaries` | on fib's real config, `[8191]` passes; `[0]`, `[8192]`, `[8191, 8191]`, `[8191, 1]`, an `INIT_TEARDOWN` count of 2 and a `ZERO_WINDOWS` count of 2 are each refused by their rule |
| C3 | the boundary scalars and the entry pc | `multiset.rs::a_changed_boundary_scalar_does_not_reconcile` | x2's final ts + 1, x10's final value 1, entry pc + 4: each false |
| C4 | the halting sentinel | `multiset.rs::the_finals_refuse_a_trace_stopped_before_its_exit_row`, `::a_prefix_claiming_halt_pc_does_not_reconcile` | a prefix's log panics "not HALT_PC"; the prefix's shards with `HALT_PC` in `R_b` do not reconcile, and with the prefix's own final pc they do |
| C5 | mask booleanity | `multiset.rs::a_pc_query_masked_by_minus_1_reads_as_a_register_and_only_booleanity_refuses_it` | a pc query at mask −1 on the `ADD_SUB_LUI_AUIPC` frame's first padding row, 657, reads x10 and writes 42: reconciles, no obligation, self-check names `pc_mask_boolean`; the same cells at mask 1 do not reconcile |
| C6 | boundary absorbed before the challenges | `multiset.rs::a_final_value_solved_after_the_challenges_reconciles_and_is_not_a_u32` | see "The boundary scalars" |
| C7 | the gap obligation, for coverage | `multiset.rs::a_query_reading_its_own_write_balances_where_no_row_is_and_only_its_gap_catches_it` | a `ram` query at `0x4000_0000` (window 4096, unlisted) and an `rs2` query at register 32, each reading its own write: self-check Ok, `reconciles` true, `violated_lookups` exactly that row's `gap_lo`; with `read_ts` one lower, false |
| C8 | S16's mask coupling (a documentation test, and S16's tamper target) | `multiset.rs::queries_their_row_does_not_have_reconcile_until_s16_couples_the_masks` | the `ADD_SUB_LUI_AUIPC` frame's padding row 657 with pc mask 0 and an `rd` query moving `x10` to 42 after exit; a live row's `rd` write masked to 0; the exit row, that frame's row 656, given a store over the first stack word's last write: each keeps every gate and obligation and reconciles |

**The earlier phases' tests.**

- **Halting sentinel**: `emulator/tests/trace.rs::the_exit_row_alone_writes_the_halting_sentinel`
  (every traced guest) and
  `emulator/tests/consistency.rs::a_traced_run_is_the_same_execution_and_its_memory_balances`
  (final pc `HALT_PC` on every input, at least one with a nonzero exit).
- **Constants**: `constants/tests/memory.rs` (`RAM_ORIGIN == 4 << RAM_LIVE_BIT`, two
  timestamp chunks are the clock, `HALT_PC` odd and below RAM).
- **One image-word source**: `loader/tests/image.rs::initial_word_assembles_words_across_segment_edges`
  and `::initial_word_agrees_with_the_bytes_of_every_guest`.
- **`RamLive`**: `gkr/tests/ram_live.rs`, the closed form against the table at
  `n = 14, 15, 16, 18`, and a circuit that proves and rejects a violation at row
  `2^14 − 1`.
- **Lookup rules**: `checker/tests/lookups.rs`, 35 mutants on which `check_laws` and
  `validate` agree — among them names taken from every other named part and `M` or `S`
  past the layout — with `violated_lookups` on 11 hand-derived rows, a `range16` lookup
  bound at `2^16`, and two degenerate evaluators.
- **Padding identity**: `checker/tests/padding.rs`, including
  `a_second_halving_list_is_not_read` and `a_leaf_that_is_1_at_row_0_alone_fails`.
- **Wire**: `constraints/tests/wire.rs::a_format_version_other_than_one_is_refused`,
  `::a_lookup_round_trips_byte_for_byte`, `::virtual_kind_tags_are_zero_and_one`.
- **Window kernel functions**: `gkr/tests/memory.rs`, leaves, window constant, boundary
  factors, reconciliation, and both windows proved at `2^16`.
- **Builders**: `trace/tests/memory.rs`, including the gap columns at the chunk's edge
  (`2^19 − 1`, `2^19`, `2^19 + 3`) and a write at a window's first word.
- **Construction-time rules**: `constraints/tests/memory.rs::the_read_tuples_parts_are_at_their_named_positions`
  and `::a_root_read_from_a_witness_column_alone_is_refused`.
- **Program**: `program/tests/config.rs::a_config_without_both_init_families_at_one_height_is_refused`,
  `::the_statement_descriptor_is_three_adjacent_messages`,
  `::a_config_of_every_family_round_trips`;
  `program/tests/tables.rs::file_bytes_past_the_image_window_are_refused`,
  `::a_program_above_bytecode_size_words_fails_loudly`,
  `::the_image_column_is_window_zero_word_by_word`;
  `program/tests/identity.rs::the_digest_over_commitments_is_the_documented_recipe` and
  `::the_digest_over_commitments_moves_with_the_entry_pc_and_each_commitment`, plus the
  `#[ignore]`d ceremony tests.

---

## Verification performed

**722 workspace tests, all green, plus 21 `#[ignore]`d** (617 and 20 at S13), from
one `cargo test --workspace` at the stage's last commit: 92 new passing tests. The new ignored
test is `program/tests/identity.rs::a_segment_without_file_bytes_does_not_move_the_identity_by_its_size`.
New test files, and the tests in each:

| File | Tests |
| --- | --- |
| `checker/tests/multiset.rs` | 22 |
| `constraints/tests/memory.rs` | 15 |
| `checker/tests/memory.rs` | 9 |
| `gkr/tests/memory.rs` | 8 |
| `trace/tests/memory.rs` | 7 |
| `checker/tests/lookups.rs` | 5 |
| `constants/tests/memory.rs` | 4 |
| `gkr/tests/ram_live.rs` | 2 |
| `constraints/src/memory.rs` (unit) | 1 |

That count, and every run below marked "at `8b1993f`", was taken on the tree of
`8b1993f`; this closing commit changes only this file and the root `CLAUDE.md`, so no code,
test or fixture differs from it.

Every gate `CLAUDE.md` lists, run locally at `8b1993f` on macOS, each exit 0:
- `fmt --check` in all four workspaces (root, `tools/transcript-ref`, `crates/guest-sdk`,
  `guests`);
- `clippy -D warnings` in all four (the workspace and `transcript-ref` with
  `--all-targets`, `guest-sdk` for `riscv32imac`, `guests --bins`);
- the `riscv32imac` build of `field`, `constants`, `transcript`, `poly`, `sumcheck`,
  `constraints` and `gkr-verify`;
- `cargo run -p kat-gen`, then `git diff --exit-code` over all ten fixture directories
  `CLAUDE.md` and CI name: no diff. `identity.txt` was regenerated too, since the ceremony
  file is present, byte-identically (sha256 `3232810e…032b`);
- `transcript-ref`, with no diff, and fib's guest build.

**Mutation runs, from the phase reports.** Each mutant was applied alone, run against
its named suite, and reverted (sources confirmed byte-identical after).

| Phase | Mutants | Outcome |
| --- | --- | --- |
| 1: constants, sentinel, image word | reviewer's mutant writing `HALT_PC` only on exit status 0; a stash of the emulator change | the mutant survived, and the test added for it now fails on the workload fault (exit 101); the stash fails 2 tests |
| 2A: engine amendments | 7 (implementer) + 4 (fix) | the implementer's 7 were all caught. The review named two classes no test could catch: a check reading the last halving list, and an `M` selector refused. The fix ran 4 mutants of those classes (`rposition`, every halving list, an `M` selector refused in each crate), and all were killed |
| 2B: program identity, init families | 6 (implementer) + 1 (review) + 2 (fix) | 6 killed. The review's `k >= family::COUNT` in `VmConfig::from_bytes` survived, because a test had been deleted; it was killed once the test was restored. Removing `file_bytes_end`'s empty-segment filter was killed by two tests |
| 3.1: memory circuits, verifier functions, root hook | 14 (implementer); 4 (review 1); 13 (review 2); 13 (fix) | reviews found survivors: a write leaf reading the next query's mask (caught only by the fixture's SHA pin), `memory_roots` reading layer 1, provenance skipping enforcing gates, four cached-entry mutants, two mask-rule mutants, and a `V[row]` leaf mask the code accepted. After the fix all 13 were killed, and the `V[row]` hole was closed in code and spec |
| 3.2: builders | 8 (implementer) + 6 (review) + 2 (fix) | a row mapping of `cycle − 1` instead of position in `cycles` survived. `a_frame_per_family_in_any_order_reconciles` now kills it and a sorted-cycles mutant |
| 4: acceptance tests | 14 (review) + 3 (fix) | 13 failed at their own assertion; cycle 1 on padding rows after the first survived. A10 now checks every padding cell, and the reduced-width test now reads the frame's own expression. Both killed |

**Ceremony runs.**
- At `3c94535`, in the program worktree and again in a reviewer's scratch copy,
  `cargo test --release -p program --test identity -- --ignored` passed 6 (70.0 s and
  74.1 s of test time).
- At that commit, `cargo run --release -p kat-gen -- program` rewrote `identity.txt`
  byte-identically (sha256 `3232810e…032b`).
- At `d5c9229`, the suite passed 6 again (71.5 s), and
  `artifact-dump --test tables -- --ignored` passed 1, its page's identity equal to the pin.
- At `8b1993f`, with `assets/ptau/ppot_0080_24.ptau`:
  `cargo test --release -p program --test identity -- --ignored` passed 6 (92.3 s of test
  time, alongside other runs; the two non-ignored tests filtered out), and
  `cargo test --release -p artifact-dump --test tables -- --ignored` passed 1 (32.8 s).
  `kat-gen`'s `program` group rewrote `identity.txt` byte-identically, as above. The
  review's fixes change no identity input: they add one SRS-free recipe test and doc text
  to `crates/program`.

**QEMU runs**, in the colima container `CLAUDE.md` describes (`rust:latest` on aarch64
Linux with qemu-user, its own `CARGO_TARGET_DIR`, every guest built from source), at
`d5c9229` by the review's CI run and again at `8b1993f`:

| Command | `d5c9229` | `8b1993f` |
| --- | --- | --- |
| `cargo test -p loader --test qemu -- --include-ignored` | 8 passed | 8 passed |
| `APOGEE_GUEST_PROFILE=release cargo test -p loader --test qemu -- --include-ignored` | 8 passed | 8 passed |
| `cargo test -p emulator --test differential -- --include-ignored` | 3 passed | 3 passed |
| `cargo test -p emulator --test consistency -- --include-ignored` | 8 passed | 8 passed (62.4 s) |
| the same at `APOGEE_GUEST_PROFILE=release` | 8 passed | 8 passed (24.0 s) |
| `cargo test -p loader --test layout -- --ignored` | 1 passed | 1 passed |

The review's fixes touch no emulator, loader or guest code; the rerun confirms it.

**Debug-build runtime.**
- Of `checker/tests/multiset.rs`'s 15.4 s, 15.2 s is A10's `2^16` frame proof.
- `checker/tests/memory.rs` runs in 7.6 s.
- heap's `2^18` frame forwards in 0.1 s but would take 62 s to prove, so it is not proved
  in the test.

## Adversarial review

Five lenses reviewed `d5c9229`, read-only, with every probe and mutant in a scratch copy
with its own target directory; a CI run over the same commit sat beside them. Every
finding was put to a skeptic told to refute it. A finding that survived was scoped either
*fix now*, and fixed in the four commits after `d5c9229` plus this note, or *defer and
record*, and written into "Deferred work, by stage" under the stage that owes it (or, for
the one that needs the owner, into the open questions).

| Lens | What it did | Raised | Confirmed | Refuted | Major / minor | Fix now / defer |
| --- | --- | --- | --- | --- | --- | --- |
| Mathematics | derived the soundness argument from `docs/spec/memory.md` alone, then held the code to the spec line by line; two probes | 6 | 6 | 0 | 1 / 5 | 5 / 1 |
| Malicious prover | 17 probes on fib at `h = 2^16` through `validate` + `check_memory`, `check_memory_windows`, `self_check`, `violated_lookups`, `reconciles`, and prove, verify and discharge where run | 10 | 10 | 0 | 2 / 8 | 4 / 6 |
| Stage-prompt compliance | clause by clause against `prompts/S14-multiset.md` as the owner amended it, and the approved design | 7 | 6 | 1 | 1 / 5 | 5 / 1 |
| Mutation | 96 single mutants over constraints, gkr-verify, checker, trace, program, loader, emulator and constants | 8 | 8 | 0 | 2 / 6 | 8 / 0 |
| Master rules and doc truth | anti-goals and rules over the diff, commit attribution, every S14 claim in the docs checked against code | 8 | 8 | 0 | 0 / 8 | 7 / 1 |
| **Total** | | **39** | **38** | **1** | **6 / 32** | **29 / 9** |

The CI run (every `CLAUDE.md` gate at `d5c9229`, QEMU in the container, the ceremony
suites) was green and raised one minor fix-now finding, the stale test count, fixed in
`8b1993f`. The refuted finding was compliance's "the QEMU suites were never run on the
S14 tree": the CI run had run them, all passing.

What each lens concluded:
- **Mathematics.** No blocker: from the spec alone the argument holds, and the code
  matches the spec everywhere it was held to it (tuple, leaf, booleanity, write-back, x0
  and gap gates, every name, the product trees, both window artifacts, `check_memory`,
  `window_challenges`, `boundary_factors`, `reconciles`, `RamLive` at a row and at a
  point, the builders, the image column, the identity split, the window rules, the
  lookup evaluators, `HALT_PC`). The findings were places where the spec's own claims were
  incomplete or false.
- **Malicious prover.** No attack got past a check S14 itself claims. Eight attacks were
  accepted by every S14 check: four are the `HALT_PC` constraints §5 already gave S16, and
  four rested on obligations no document recorded (a mask tied to nothing, twice; written
  values `≥ 2^32`; the `S[0]` opening). Rejected: a trace starting at entry + 4, reads of
  a nonexistent init, a second query consuming one write, every window-rule change, an
  unmasked `V[ram_live]` (verify fails at layer 0), masks −1 and 2 (verify fails at layer
  0), and the window constant at the top windows.
- **Compliance.** Nearly every clause met as written or as amended. Missing: the handoff
  and the range convention. Partial: `PART_*` read by nothing, and the Q7 version rule.
- **Mutation.** 90 of 96 mutants killed; one survivor, `initial_word` computing byte
  addresses with `u32` wrapping, is equivalent under `ProgramImage`'s segment invariant,
  so 90 of 95 real mutants (94.7%). Counting only CI-reachable tests, 87 of 95: three
  identity-recipe mutants died only in the ceremony tests. Five more, among them two x0
  gates and the write-back gates weakened under their kept names, died only by a fixture
  SHA pin or the gate-name list. No verifier or
  circuit mutant with a soundness effect passed every test.
- **Master rules.** Nothing blocks: no anti-goal broken, every commit attributed to the
  configured identity alone. The findings were documentation truth, a little surplus
  public surface, and stage-close bookkeeping.

**No defect in S14's own circuits or verifier functions let a forgery past a check S14
claims**, and no probe reached a panic. The major findings were soundness debts no
document assigned to a later stage, a stage deliverable not yet written, and gates with no
behavioural test; one minor finding (4 below) was a construction-time rule weaker than the
roots need, and it is now strengthened in code.

The fix commits: `ed18252` (constraints, gkr-verify), `9ae0256` (constants, the lookup
rule tests), `2e8eada` (checker, trace and program tests, crate docs), `82d5120`
(`docs/spec/memory.md`, `GLOSSARY`), `8b1993f` and this commit (the handoff, root
`CLAUDE.md`).

**Major.**

1. **A mask is tied to nothing** (math-1, attacker-1, attacker-2). A query on a row whose
   pc mask is 0, a live row with a query masked off, and a live row with a query its
   instruction lacks each balance, keeping every S14 gate and obligation. A padding row's
   `rd` query rewriting `x10`, the exit status, after exit was accepted by every S14 check
   under two unrelated challenge sets. On a live row, a ghost store handed a later load a
   value no instruction wrote. §2.1 described the honest fill as if it were enforced, and
   neither §5, §9 nor the draft handoff gave any stage the rule.
   *Done* (`82d5120`, `2e8eada`, `8b1993f`): §2.1, §5 and §9 state what S16 owes (`m_pc` as
   liveness and lookup selector, `m_q = m_pc·uses_q`, the transfer and ecall-argument
   cases), and so does the S16 list below. Control C8 is the tamper target, and a root
   `CLAUDE.md` rule records it. The S14-only half, seven gates `m_q − m_q·m_pc = 0`, is
   offered as open question 13, not applied.
2. **Two x0 gates and all five write-back gates had no behavioural test** (mutation, two
   findings). A gate weakened under its kept name was caught only by the fixture's SHA pin,
   which `kat-gen -- memory` regenerates: `rd_is_zero_at_nonzero` over `rd_inv` (a prover
   then zeroes any register write), `rd_is_zero_inverse` removed (`x0` then holds 5), or
   every `<q>_writes_back` over `rs1`'s columns.
   *Done* (`2e8eada`): balanced forgeries refused by exactly `rd_is_zero_at_nonzero`, by
   exactly `rd_is_zero_inverse`, and by each `<q>_writes_back` in turn.
3. **The handoff and the `CLAUDE.md` update were undelivered** (compliance-1, rules-08,
   CI-1). *Done* (`8b1993f`, and this commit): this file, the status row, the test count
   and the boundary scalars.

**Minor.**

4. **A root built from `W` columns alone passed `check_memory`** (math). §8 refused a cone
   holding both a slot and a `W` column, but not one holding `W` alone; such a root is
   chosen after the challenges. *Done* (`ed18252`, §8 in `82d5120`): `check_memory` refuses
   any root whose cone reads `W`, with its test (a strengthening of the owner-approved §8
   rules). No fixture moved.
5. **§9's window bound listed the image refusal and omitted `id ≥ 1`** (math-3). *Done*
   (`82d5120`, C1 in `2e8eada`): corrected, and C1 now balances an access at `0x4` against
   a zero window at id 0.
6. **§2.2 and §2.4's leaf algebra was misstated**, and a leaf is `m·T + 1 − m` at every `m`
   (math-4). *Done* (`82d5120`, `leaf`'s doc in `ed18252`): text corrected; `leaf`'s doc
   says which tuple it means.
7. **Timestamps as integers rested on an unstated count** (math-6). *Done* (`82d5120`):
   §4.2 states it, with the corrected row bound `2^30`.
8. **Nothing assigned the opening of `S[0]` against `cm(image column)`** (attacker-4): a
   different image with a consistent trace passed every S14 check. *Done* (`82d5120`):
   §6.2, §9 and the S16 list below.
9. **`check_memory_windows` trusted a hand-built config** (attacker-10). *Done*
   (`2e8eada`): documented precondition; `from_bytes` already refuses the bytes.
10. **The range convention was not written, and no 16-bit channel existed** (compliance-2).
    *Done* (§7 in `82d5120`, the channel in `9ae0256`): §7's convention and
    `lookup_channel::RANGE16 = 1`.
11. **`PART_*` were read by nothing** (compliance-3, rules-02). *Done* (`ed18252`): one
    private tuple constructor places each part's terms by `PART_*`, `boundary_factors`
    places its operands by them, and a test pins every read tuple's parts at their
    positions. The fixtures did not move.
12. **The version rule contradicted the owner's Q7 decision** (compliance-4, rules-01).
    *Done* (`9ae0256`): `constants/CLAUDE.md` and `PROTOCOL_VERSION`'s doc amended, with
    the S12 precedent corrected (S11 and S13 changed no existing value).
13. **No test built a self-balancing query** (compliance-5). *Done* (`2e8eada`): control C7.
14. **The identity recipe's S14 changes were reachable only by ignored tests** (mutation).
    *Done* (`2e8eada`): an SRS-free test of the absorb order. Which column `INIT_TEARDOWN`
    commits, and at which height, is still reached only by the ignored recipe test (a CI
    gap, recorded under S16).
15. **Builder, validator and padding mutants survived** (mutation, five findings):
    `gap_hi` chunking `gap + 1`, a window taking the next window's first word, a lookup
    named after a scratch slot, `S` past the layout, and the padding clause sampling row 0
    alone. *Done*: one test each, and `M` past the layout too — the builders' and the
    padding clause's in `2e8eada`, the lookup rules' in `9ae0256`.
16. **Four `constraints::memory` functions were public with no outside caller**, and
    `gap_lookups` took a parameter with one value (rules-03). *Done* (`ed18252`): private,
    parameter dropped.
17. **`MEMORY_BOUNDARY`'s range refusal was stated in the present tense** (rules-04,
    rules-05, rules-06), and `CLAUDE.md`, `GLOSSARY` and the `checker laws` line overstated
    S14; `memory.md` had a typo. *Done* (`82d5120`, `8b1993f`): reworded and assigned to
    S16.

**Deferred and recorded**, each confirmed and each written into "Deferred work, by stage"
under the stage named:

| Finding | What is owed | Stage |
| --- | --- | --- |
| math-5 | lookup selectors boolean, or LogUp disagrees with `violated_lookups` | S15 |
| attacker-8 | the self-balancing and same-timestamp forgeries only `violated_lookups` catches today | S15 (discharge), S16 (address decomposition) |
| attacker-3 | every written value range-checked below `2^32` | S16 |
| attacker-5, -6, -7 | the truncation, run-past-halt and exit-status tamper targets | S16 |
| attacker-9 | the boundary decode refusing `t ≥ 2^38` | S16 |
| compliance-6 | `check_memory` at every artifact load, and a per-family obligation count | S16 |
| rules-07 | the master's *Trace heights* bullet | owner (open question 1) |

**Mutants re-run against the fixes**, each applied alone in a scratch copy with its own
target directory, run against its suite, and reverted:

| Mutant | Killed by |
| --- | --- |
| `check_memory`'s root rule off (the fix reverted) | `a_root_read_from_a_witness_column_alone_is_refused` |
| `PART_TS`/`PART_VAL` renumbered, tuple positions hardcoded (the fix reverted) | `the_read_tuples_parts_are_at_their_named_positions` |
| `PART_TS`/`PART_VAL` renumbered, code reading them | `the_fixtures_are_the_constructors_bytes` |
| `rd_is_zero_at_nonzero` over `rd_inv`, name kept | `a_zeroed_register_write_and_a_nonzero_x0_write_are_each_refused_by_their_gate` |
| `rd_is_zero_inverse` as `z − z·z`, name kept | the same |
| every `<q>_writes_back` over `rs1`'s columns, names kept | `a_read_only_query_writing_back_another_value_is_refused_by_its_gate` |
| `load_writes_back` removed | the same |
| `gap_lo`'s constant `Δ` instead of `Δ − 1` | C7, and two acceptance tests |
| `build_frame_witness` chunking `gap + 1` | `the_gap_columns_hold_the_high_chunk_at_the_chunks_edge` |
| a window taking word `4h·(w+1)` | `the_first_word_of_a_window_is_that_windows_alone` |
| `check_lookups` without scratch names | `check_laws_agrees_with_validate_on_every_lookup_mutant` |
| `validate` admitting `S[setup.len()]`, and `M[memory.len()]` | the same |
| `check_padding_identity` at row 0 alone | `a_leaf_that_is_1_at_row_0_alone_fails` |
| `PROGRAM_ENTRY` absorbed before `VM_CONFIG` | `the_digest_over_commitments_is_the_documented_recipe` |
| `violated_lookups` reading the timestamp bound for every channel | `a_range16_lookup_is_bound_below_2_16` |

All 16 were killed.

**Not acted on.**
- The S14-only mask gates: they change the frozen frame (17 → 24 enforcing gates) and its
  fixture, so they are the owner's call (open question 13).
- A toy SRS in `crates/program`'s tests, to reach `setup_commitments` in CI: recorded as a
  CI gap instead.
- `docs/spec/execution-trace.md`'s "only an exit row writes `HALT_PC`": it holds for every
  trace the emulator writes, and its next sentence cites what S16 owes.

---

## Deviations and notes for the reviewer

**From `prompts/S14-multiset.md`**, each approved by the owner as part of the
consolidated design (the review's conflict list, G19). The prompt is not edited.

1. **Line 17, "new `GateDef` kinds".** None were added. The tuple is a `Linear`, a leaf is
   a flat `Quadratic`, the row-wise products are `Product` and the trees `TreeProduct`.
   The memory "gate kinds" are frozen as the constructors in `constraints::memory` plus
   artifact data. `MaskIntoIdentity` is not used: its input would have to be a column
   or a cached entry, and a cached tuple inside it refuses the cache-free compilation.
2. **Line 18, the init/teardown artifact.** It is two artifacts over two families, and
   `INIT_TEARDOWN` reads a setup column `S[0]` and the virtual `V[ram_live]`, not
   memory-subtree columns only. The rest holds: closed-form addresses (`V[row]` and the
   derived window constant), no committed address column, no witness columns, no
   enforcing gates, a two-wide top carrying the two roots.
3. **Line 19, "`RangeObligation` of channel id, expression and bound".** It is a generic
   `LookupExpr (name, channel, selector, tuple)`. The bound is fixed by the channel
   (`lookup_channel::BITS`), and the selector is required: an all-zero padding row
   gives the pc query's low chunk `p − 1`, which no range admits.
4. **Line 21, the builders.**
   - `build_memory_columns` takes `cycles: &[u64]`, a shard's own cycle list in any
     order, instead of `window`, and returns `Vec<(PolyAddress, MultilinearPoly)>`
     rather than a `MemorySubtreeColumns` type.
   - `build_init_teardown_columns` takes `ram_window: u32`. "Window" now means a slice of
     the address space only, and GLOSSARY distinguishes it from a shard's cycles.
   - `build_frame_witness` and `build_boundary_finals` were added.
   - The padding convention holds for every memory column. AS and Δ are literals times
     the mask, so they are not columns to fill.
5. **Line 29, the tree.** There is no copy gate, because every width and height is a
   power of two. Every list multiplies exactly two children. The leaves are not
   `MaskIntoIdentity` (deviation 1).
6. **Lines 31 and 65, "the mechanism [binding teardown to `io_digest`] lands here".** No
   mechanism lands. Teardown binds nothing about I/O (D5, deviation 10), and S16's
   teardown-binding tamper acceptance is retargeted (Deferred).
7. **Line 33, last-write bookkeeping in a dense array and a hash map.** The builders read
   `MemoryEventLog::final_state()` and make one pass over the log for the frame.
8. **Line 36, must-be-exact 1, "named indices every builder and gate constructor
   reads".** The tuple constructor places each part's terms in slot
   `constants::memory::PART_*`, and `boundary_factors` places its operand values by the
   same constants. The trace builders fill columns by frame field, not by tuple part, so
   they have nothing to read. `READ_ROOT` and `WRITE_ROOT` are read by
   `constraints::memory` and `checker::memory_roots`.
9. **Line 37, must-be-exact 2's partition assertion.** It is restated as `check_memory`'s
   four rules.
   - Forward provenance: no gate or output whose cone both names a slot 1–5 and reads a
     `W` column.
   - Neither root's cone reads a `W` column. The review added this rule, strengthening the
     approved set: a root built from `W` alone names no slot, so provenance passed it.
   - A global slot only over `M`, `S` (admitted because a setup column is bound by
     identity before the challenges) and `V`.
   - Leaf masks boolean.
   "AS discriminators" are not columns at all. The walk-down reading of `gkr.md` §5.1 was
   replaced by the forward rule, because a product of a tuple and a copy of a `W` column
   passes the walk-down.
10. **Lines 41, 42, 45 and 46, must-be-exact 6, 7, 10 and 11.**
    - Registers and the pc, x0 included, are not enumerated in init/teardown; the
      verifier's boundary replaces them.
    - There is no single row-index partition into register file, PC and RAM segments.
    - Image init values are a committed setup column bound by identity, not a
      "never committed" polynomial. The *address* enumeration is closed-form and
      uncommitted, as asked.
    - The x0 gadget is kept exactly as must-be-exact 7 asks, in the mask-gated form
      `addr·rd_inv + z − m = 0`, `addr·z = 0`, `z − z² = 0`,
      `write_value = (1 − z)·sel`. `z = 0` on a mask-0 row keeps padding rows
      satisfying.
    - The "≤ 1-page design note" is `docs/spec/memory.md` §2.4's x0 rule, which also
      states why `v_0 = 0` does not replace the gadget.
11. **Line 43, must-be-exact 8, `read_root == write_root`.** The check is `reconciles`:
    the product of every shard's roots, times the boundary factors, and nonzero.
12. **Line 55, Acceptance 7.** Remapped to "every touched RAM address lies in exactly one
    listed window", with a duplicated-*window* forgery.
13. **Must-be-exact 4, "zero row constraints".** It holds: the gadget is one witness
    column and two obligations. The obligations carry the row mask as a selector. "The
    general range convention this stage freezes" is `docs/spec/memory.md` §7, with the
    channel `RANGE16 = 1` allocated for it and used by no S14 artifact. A wrap wider than
    one boolean is left open (open question 12).

**From the master**, amended with the owner's authorization, three bullets only.

14. *Statement binding* gains the window list, the two init families' groups (each
    domain-separated and length-delimited), and the boundary scalars before the squeeze.
    *Memory argument* is rewritten for RAM windows, the verifier's boundary, `HALT_PC`,
    and deferred I/O binding. *VmConfig / program identity* adds the entry pc and the
    image column. The sweep first dropped the old "under its own domain tag" rule for the
    init group. The docs review restored it as "each domain-separated and
    length-delimited" (`e017d28`).

**From earlier handoffs.**

15. **S12 item 7** ("every ecall row has the fixed `next_pc = pc + 4`") no longer holds
    for the exit row, which writes `HALT_PC`.
16. **S11 deviation 1** ("identity binds the instruction tables only") and **deviation 15**
    ("`ProgramIdentity` is the digest alone") are superseded by the new recipe and the
    `setup_commitments` split. S11's open item "bind the data image and the entry pc" is
    closed. `prompts/S11-decoder.md`'s 2^20 init/teardown height is superseded by the
    `2^22` default.

**From the approved design, and implementation notes.**

17. **`init_windows(log, height: u32)`**, not `(log, config)`.
18. **The leaf's term order.** `leaf` writes `[(c0, m), (−1, m), then the tuple's own
    mask terms]`, then every other term as a product with `m`. For the frame that is
    `(γ_M, m), (−1, m), (s, m), (α_ts, m) × Δ`, not one merged `(s − 1, m)`. It is the
    same polynomial, and the window leaves come out as written.
19. **Gap column naming.** The column is `<q>_gap_hi` and the obligations are `gap_hi_<q>`
    and `gap_lo_<q>`. A name is used once per artifact, so column and obligation must
    differ. Middle product columns are `read_<layer>_<i>` / `write_<layer>_<i>`, the
    roots `read_root` / `write_root`, and relations `define_<name>`. Fixtures pin all of
    it.
20. **`check_memory` reads its slot rule strictly.** A slot 1–5 coefficient is refused in
    any gate reading an inner column or a cached entry, even when the cone never reads
    `W`. Nothing built needs more. A later challenge-weighted inner gate would be refused
    (open question 6). The mask rule's `W` arm is unreachable, because a `W` mask trips
    provenance first; it is kept because the spec names `M`, `W` and `S`. The mask rule
    refuses every virtual mask except `V[ram_live]`, and `V[row]` is not boolean; the
    review found that hole and it is closed.
21. **The builders fill the three slot-2 register queries in log order.** `rs2`, `arg1`
    and `arg2` share an address space and a slot, so the log alone cannot tell them
    apart. Log order is exact while every ecall's arguments are a prefix of
    `a0, a1, a2`, which the ABI and the emulator satisfy today. No gate can tell them
    apart either. `checker/tests/memory.rs::the_frame_columns_are_the_family_buffers`
    holds fib and heap to the family rows, which record roles.
22. **heap's `2^18` frame is forwarded, self-checked and lookup-checked on every row, but
    not proved** in the debug-build test (62 s). fib's frame proves the same artifact.
23. **The window artifacts are exempt from the product-tree padding clause.** A window
    has no inactive rows, and its zero row gives a teardown leaf of `WC`, not 1. Only the
    frame is held to `check_padding_identity`. The `checker padding` CLI does not run the
    clause.
24. **The S13 toy fails `check_padding_identity`**: its zero row makes `abm = 0`, and
    `fingerprint3 = … + 3` has no mask. This is pinned as `Err` in
    `checker/tests/padding.rs::the_toy_does_not_keep_the_product_tree_clause` (open
    question 7).
25. **Lookup refusals are `ConstraintError::Malformed`**, with a detail naming the lookup;
    no new variant was added.
26. **`check_memory_windows` panics** when `shard_counts.len()` is not the config's family
    count, mirroring `absorb_statement_descriptor`. A hand-built config with an init
    height of 0 panics on division by zero rather than being refused, and one listing
    `ZERO_WINDOWS` twice passes on its first entry. The function documents its
    precondition: a `VmConfig` that `decode_program` derived or `from_bytes` decoded,
    which refuses both. S16's verifier reads the counts from a proof and must refuse a
    wrong length first.
27. **`identity_from_commitments` checks no list shapes** (one point for `INIT_TEARDOWN`,
    none for `ZERO_WINDOWS`, a table's column count for the others). The digest binds the
    lengths, so a wrong shape is just a different identity. A verifying-key loader may
    still want the explicit check.
28. **The image refusal counts only segments with file bytes**, and so does
    `ProgramTooLarge` now, through one helper `file_bytes_end`. Before, an empty `NOBITS`
    segment counted. fib's measured span changes from 3,072 words (its reservation's
    start at `0x13000`) to 2,867. No identity moves because of this: the configured
    `bytecode_size_words` is what identity absorbs. At the defaults the image ceiling is
    16 MiB of address space. `guests/consistency`, last file-backed byte `0x1efea0`, needs
    `h ≥ 2^20`.
29. **`plan_shards` gives both init families 0 shards.** It stays a pure function of the
    cycle profile. The prover assembles `1` and `init_windows(..).len()` for the
    statement.
30. **`PROTOCOL_VERSION` and `CODE_VERSION` stay 0**, by owner decision (design question
    Q7), although several frozen things changed: the identity recipe,
    `DEFAULT_HEIGHTS[7]`, `family::COUNT`, `challenge_slot::NAMES`, `lookup_channel` and
    the artifact format. The version policy is now written down: from the first
    registered program identity on, any value change bumps `PROTOCOL_VERSION`; until then
    both stay 0.
    - `crates/constants/CLAUDE.md` and `PROTOCOL_VERSION`'s doc comment say so.
    - The one earlier value change without a bump was S12's `RAM_LENGTH` (`891075f`).
      S11 and S13 only added constants.
31. **`decode_program_detaching`'s init-family path.** Derivation always adds both init
    families, so "a config missing either is refused" is reachable only through the test
    hook. Detaching `INIT_TEARDOWN` or `ZERO_WINDOWS` now leaves it out of the family set,
    and `window_height` refuses it. Before, detaching init/teardown was a silent no-op.
32. **The window-rule refusals are one variant**, `WindowRule { rule: &'static str }`,
    following `NotAllOpcodesSupported`'s `reason`. `VmConfig::from_bytes` returns `None`
    on the same rule.
33. **`crates/program` depends on `curve`** for `G1Affine` in `setup_commitments`'
    signature; `pcs` does not re-export it. **`crates/trace` depends on `constraints`,
    `field`, `gkr-verify` and `poly`** for the builders. The root rule "family buffers are
    raw live rows" is reworded: the buffers still are, and the memory builders fill padded
    columns from the log.
34. **`initial_word_agrees_with_the_bytes_of_every_guest` covers each segment's file bytes
    plus one page above them**, not the near-2 GiB zero reservation. Every word holding a
    file byte, and every word where file bytes end, is covered.
35. **`crates/constants/tests/memory.rs` is a second in-crate constants test**, beside
    `ecall_abi.rs`, for constants that are claims about other constants.
36. **`rd_selected` on an rd write at address 0 is unconstrained** by the gadget, which
    only forces the write to 0. The builder sets it to 0.
37. **The frame builder keeps one `Option<MemoryEvent>` per query of the family's frame,
    per cycle** — `w` of them, 4 to 7, not a fixed 8 — so roughly 160 to 280 bytes a row
    and about 0.7 to 1.2 GB at a `2^22`-row shard, against 1.3 GB when every family
    carried all eight. The row is a `Vec`, so there is also a header and one allocation
    per row; a fixed-capacity row would trade that for the widest family's footprint.
    That is fine for tests; S16 and S20 may want to stream, and the per-row allocation is
    a second reason to.
38. **Tests pin measured facts about the committed `fib.elf`**:
    - `0x12000` as the only window-0 word;
    - 29 stack words, all first touched by a store;
    - 432 x0 queries;
    - the gap list at row 11 of `ADD_SUB_LUI_AUIPC`'s frame, cycle 18;
    - the stale store at `0x7fffff70`.
    A deliberate `kat-gen -- guests` refresh must re-measure them.
39. **The test frame shards use the smallest power of two at or above the cycle count**
    (at least 16), not a menu height. The builders accept any power of two; real shards
    will be menu heights.
40. **`memory_roots` also refuses** a `LayerValues` whose depth is not the artifact's, and
    a root column of the halving input whose height is not `2^layer_vars(k)`. Both were
    added from the review.
41. **`write_tuple`, `leaf`, `booleanity` and `gap_lookups` are private**, and `gap_lookups`
    takes the query alone. No crate outside `constraints::memory` called them; `trace`,
    `gkr-verify` and `kat-gen` use the layout constants, `read_tuple` and the three
    constructors. `docs/spec/memory.md` names the gadgets' conventions, not these functions.
42. **Control C8 is a documentation test**, like C6. It passes at S14, and S16's mask
    constraints must turn each of its three forgeries into a refusal.
43. **C8's third forgery is a final RAM value, not a load**: a store on the exit row,
    the stack window's teardown claiming it. The review's live-row probe placed the store
    before a load, but then the load's `rd` write differs from the value read, which S16's
    load constraint refuses on its own. On the exit row nothing but the mask rule refuses
    it.

---

## Open questions for the owner

1. **The master's *Trace heights* bullet** says "a family with zero occurrences in the
   execution proves zero shards". `INIT_TEARDOWN` runs zero cycles and always proves one
   shard. `ZERO_WINDOWS` runs zero cycles and proves one per touched window. The bullet
   was outside the three authorized amendments and is unedited. A suggested wording:
   "(instruction families; the init families' shards are RAM windows,
   `docs/spec/memory.md` §3.2)".
2. **The master's *Proof shape* bullet** says "no data-dependent lengths". The window list
   `MEMORY_WINDOWS` has a data-dependent length, 0 to `N − 1` ids. The shard counts
   already vary per execution, so the design accepted it, and the list maps shard `i`
   straight to `w_i`. The fixed-shape alternative is a presence bitmap of `N − 1` bits:
   127 at `2^22`, 8,191 at `2^16`. Does the bullet need an amendment, or the bitmap?
3. **Domain tags for the two init families' memory-column groups.** The master now
   requires them to be domain-separated and length-delimited, and `memory.md` §6.3
   defines no tag. The recommendation is that S16 chooses them with the memory squeeze's
   challenge tag. Confirm.
4. **The SRS digest is still unimplemented** (pre-existing since S07): the master's
   statement order lists it, and `memory.md` §6.1 writes it in brackets. Should a later
   amendment mark it absent?
5. **The frozen names** of deviation 19. Is this the naming to freeze?
6. **`check_memory`'s strict slot rule** (deviation 20). Keep it, or let provenance alone
   govern gate lists above 0?
7. **The S13 toy and the product-tree clause** (deviation 24). Exempt the toy in writing,
   or change it (which moves its fixtures again)? Relatedly, the artifact records nothing
   about whether a family has inactive rows, so the caller decides whether to run
   `check_padding_identity`, and the clause is checked on `padding.row` only, not on the
   zero row.
8. **Closed: the version-bump rule** (deviation 30). The owner approved the design review's
   recommendation, and `crates/constants/CLAUDE.md` now applies the rule from the first
   registered identity.
9. **Exit status policy.** Does the verifier require `v_10 = 0`, or compare it with a
   status in `PublicInputs`? The design recommends the latter, as a `u32`, so `exit(-1)`
   is `0xFFFFFFFF`.
10. **Before S16: confining ecall RAM traffic.** Choose one: one word per read ecall (the
    RAM query moves into the ecall row, and the SDK issues `count ≤ 4 − buf mod 4`), or
    transfers bounded to `[buf, buf + count)`, re-reading `a1`, `a2`, `a7`, with a
    documented unspecified tail past `n`. Also: should write transfer cycles be dropped?
    The design recommends one word per read and dropping write transfers. Both options
    amend `execution-trace.md` §6.
11. **Should the builders take the family rows instead of the log** (deviation 21), which
    would drop the prefix assumption? Also: should `crates/loader/tests/image.rs`'s
    `GUESTS` list, which names 7 of the 10 committed guests, be widened? And should A10's
    15 s proof or A1's every-row evaluator pass be trimmed?
12. **Wider wraps under the range convention.** §7 freezes a boolean `wrap` for a result
    `r` of an expression `e < 2^33`. A multiply's high word, or a sum of more than two
    words, needs a wrap bounded by a range obligation instead. Should its shape be frozen
    now, or by the stage that first needs it?
13. **The S14-only half of the mask rule** (review finding 1). Seven degree-2 enforcing
    gates `m_q − m_q·m_pc = 0`, one per query `q = 1..7`, would refuse C8's first forgery
    at S14. They read no decoder output and are 0 on the all-zero padding row. Measured on
    fib's honest frame at `2^12` and `2^16`, they pass `self_check`, `check_laws`,
    `check_padding` and proving, and the forgery is named `rd_mask_implies_pc` at row
    2,117, with `verify` returning `LayerInconsistency { layer: 0 }`. They would change
    every family's frame — one enforcing gate per query beyond the pc query, so 6 more for
    `ADD_SUB_LUI_AUIPC` and 3 for the 4-query families — their names, and all four frame
    fixtures.
    They do not cover the other two forgeries, which need the row kind. Land them at S14,
    or leave the whole rule to S16?

---

## Deferred work, by stage

**S15.**
- The LogUp discharge of the gap obligations and the timestamp range channel.
- Until then a future read, an out-of-window access and a self-balancing query (a read
  tuple equal to its own write tuple) are rejected **only by the native evaluator**,
  `checker::violated_lookups`. Coverage and the RAM-window bound both rest on it.
- **Boolean selectors** (review math-5). `docs/spec/memory.md` §7 says an obligation holds
  where its selector is 0 or its expression is in range, admits any `M`, `W` or `S` column
  as the selector, and requires no booleanity; `violated_lookups` treats any nonzero
  selector as active. LogUp checks `Σ_i s_i/(X − e_i) = Σ_t mult_t/(X − t)`, which equals
  that rule only for boolean selectors: a row with `s = −1` and an out-of-range `e` cancels
  a row with `s = 1` and the same `e`, so a gap of −1 that `violated_lookups` reports would
  pass. Either `validate` or `check_memory` refuses a lookup whose selector has no
  booleanity gate in gate list 0, or §7 states the premise and S15's LogUp enforces it. A
  gap obligation's selector must also be its own query's leaf mask: a `W` selector, or any
  selector not tied to the mask, switches the obligation off even when it is boolean. At
  S14 every selector is a booleanity-gated `M` mask of its own query, so nothing is exposed
  now; §7 does not yet say this.
- **Discharge targets** (review attacker-8), each accepted today by every S14 check but
  `violated_lookups`:
  - a self-balancing `ram` query (`read_ts = 4c + 3`, read = write = 7) at `0x7ffffff9`,
    `0x80000000`, `2^32`, `p − 4` and `0x8`, named `gap_lo_ram` (or `gap_hi_ram` when
    `gap_hi = −1`);
  - an `arg1` query at `rs2`'s register in the same row, reading `rs2`'s write at the
    timestamp it writes itself (`4c + 2`), named `gap_lo_arg1`;
  - control C7's two forgeries.

**S16.**
- **The global transcript** in the amended order of `docs/spec/memory.md` §6.1:
  - every memory-column commitment;
  - `MEMORY_WINDOWS` and `check_memory_windows` before the challenges;
  - `MEMORY_BOUNDARY` immediately before the squeeze;
  - a new challenge-kind tag for drawing `γ_M, α_addr, α_ts, α_val`;
  - the init groups' domain tags.
- **Decoding the boundary scalars** with their ranges, `t < 2^38` and `v < 2^32` (review
  rules-04, attacker-9). At S14 `boundary_factors` takes any `u64` timestamp, `2^40` and
  `u64::MAX` included, and simply fails to reconcile with honest roots. No attack was found
  that needs `t ≥ 2^38`, but C6 shows why the decode must refuse out-of-range values.
- **The zero-root refusal** in the real verifier.
- **The `VerifyingKey` and `ProvingKey` loads** (review compliance-6):
  - `CircuitArtifact::validate`, once, and `constraints::memory::check_memory` beside it on
    every memory artifact. Today both of `check_memory` and the obligation count run only
    inside the private assembler behind the three constructors, so an artifact read with
    `from_bytes` — or an execution family joining the frame to its instruction constraints
    outside that assembler — gets neither, and one whose leaf is fed from a `W` column or
    whose range obligation was dropped would load and verify;
  - recompute identity with `identity_from_commitments` from the carried entry pc and
    commitments, and refuse a mismatch with the trusted identity;
  - check the two init families' equal heights;
  - open `S[0]` against `cm(image column)`.
- **A per-family obligation count** (review compliance-6): every family builder that adds
  obligations (32-bit halfwords, address low bits) asserts its expected count, derived from
  the reads and 32-bit ranges it declares, against `artifact.lookups.len()`, as the frame's
  `lookups.len() == 2·reads` does.
- **The frame superset rule** (`docs/spec/memory.md` §2.1 and §9). A family's frame holds
  only the queries its instructions can make, so S16 must keep it a **superset** of them: a
  query the frame lacks is an instruction with no `write_value` column to constrain its
  result against, and that — not the narrowing itself — is the one way this could cost
  soundness rather than completeness. `frame_queries` is held *equal* to that union over all
  59 instructions by
  `crates/trace/tests/memory.rs::every_familys_frame_is_exactly_its_instructions_queries`,
  routed by `program::row_kind`, so a family that gains an instruction whose queries it does
  not carry fails there rather than silently dropping the event. **When S16 adds or moves a
  row kind — another ecall argument, a precompile, a new transfer shape — change that
  family's list in `constraints::memory::frame_queries` first**, and expect the four frame
  fixtures to move with it.
- **Every written value below `2^32`** (review attacker-3): `rd`'s selected value, a store's
  or an atomic's RAM write, and `next_pc`, each range-checked under §7's convention. Read
  and teardown values are then `u32` through the multiset, because every init value (the
  `U32` image column, literal 0) and every boundary `v_r` is. The memory argument itself
  needs no value range — the tuple compression is injective over field elements — but
  instruction semantics and the digest-register comparison do. Tamper targets: an `rd`
  write storing `2^32 + 5` that the register's next query reads, and the last store to a
  stack word writing `2^32 + 5` into window 8191's teardown.
- **Every mask constrained** (`docs/spec/memory.md` §2.1; review finding 1):
  - `m_pc` is the row's liveness, and the decoded-table lookup's selector is `m_pc`
    itself, not a separate witness.
  - Every other mask is `m_q = m_pc·uses_q`, `uses_q` read from the looked-up row kind:
    - `rs1`, `rs2` and `rd` from the instruction's form, `x0` included;
    - a transfer row uses `pc` and `ram` only, with `is_transfer` a constrained witness;
    - on an ecall row, `rs2`, `arg1` and `arg2` follow the number read at slot 1: three for
      `READ` and `WRITE`, one for `EXIT` and `PRECOMPILE_POSEIDON2`, none otherwise. Each
      comes from `is-zero(a7_read − n)`, split across layers to keep degree 2.
  - **Tamper targets**, each to be refused:
    - C8's three forgeries;
    - the review's live-row probe, a store on fib's cycle-40 row over stack word
      `0x7fffffa0` writing 99 that the load at cycle 41 then reads.
- **The `S[0]` opening's tamper target.** fib with one byte of `0x12000` flipped: window 0
  and `S[0]` rebuilt from the flipped image, and the one load of that word reading the
  flipped word. Every S14 check accepts this, including discharge against the prover's own
  `S[0]`.
- **Family constraints.**
  - Byte-level address decomposition and alignment: `low ∈ [0, 3]` range-checked,
    `low = 0` for `lw`/`sw`, `low ∈ {0, 2}` for `lh`/`sh`, a boolean wrap on `rs1 + imm`,
    `ADDR = rs1 + imm − 2^32·wrap − low`. Its tamper targets (review attacker-8) are the
    self-balancing `ram` queries at the misaligned `0x7ffffff9` and at `2^32`.
  - Literal AS and Δ over boolean masks in every family.
  - The x0 gadget in every family that writes rd.
- **`HALT_PC`'s constraints** (`docs/spec/memory.md` §5):
  - `jalr`'s bit-0 clear and every jump's and branch's wrap bit booleanity-constrained;
  - `is_exit` from `a7 = 93` on the system row kind, gated off transfer rows;
  - `next_pc = is_exit·HALT_PC + is_transfer·pc + (1 − is_exit − is_transfer)·table_next_pc`;
  - the decoded-table lookup on every live row, transfer rows included;
  - the exit row's `a0` write equal to its read;
  - a tamper test for each. The review's probes on fib, each accepted by every S14 check,
    are the targets (attacker-5, -6, -7):
    - **truncation**: fib cut at cycle 1,058 of 2,117, its last row's `next_pc` set to
      `HALT_PC`, the finals and windows taken from the prefix;
    - **running past halt**: after the exit row, a live row at `pc = HALT_PC` reading pc 1
      at `4n`, writing it at `4(n + 1)` and rewriting `x10 := 42`;
    - **resuming from `HALT_PC`**: a live row writing `next_pc = HALT_PC` and the next row
      reading pc 1;
    - **exit status**: the exit row's `a0` write changed from the status it read (0) to 42,
      the finals claiming `v_10 = 42`.

    The table lookup refuses the middle two, because pc 1 is odd and no table row claims
    it. It does not reach a row whose pc mask is 0; that is the mask rule above.
- **Ecall RAM confinement** in the shape the owner picks (open question 10), and the
  `-EBADF`/`-ENOSYS` rows.
- **Optionally**, a literal pc read timestamp `4(c − 1)`, which saves one gap column and
  two lookups per row and makes `t_pc = 4n`.
- **A CI gap to close when convenient**: `setup_commitments` — which column
  `INIT_TEARDOWN` commits, at which height — is reached only by the ceremony-backed
  ignored recipe test. A toy SRS in `crates/program`'s tests would bring it into CI.

**S20.**
- Reconciliation over every shard of every family, with the boundary factors applied
  exactly once per statement.
- Snapshots under master rule 9 carrying the window list and the 64 boundary scalars.

**The I/O-binding stage (D3, D5).**
- A **non-allocating `transcript::io_digest`**, rewritten over observe/sample with the
  same value.
- The **SDK exit shim** loading `x24 … x31` with the digest words, with a re-entrancy
  guard so `exit(71)` or a panic inside exit cannot recurse.
- **`crt0` calling the SDK exit** after `main`, so every SDK exit path (70, 71, 72, 101)
  loads the digest. Raw `exit` or raw fd 0/1 ecalls are documented as unverifiable, and
  `guests/opcodes` is a named exception.
- **SDK stream buffers in storage the guest heap cannot exhaust**, reserved before the
  write ecall, so `heap_ceiling` still ends with exit 71 and its committed line. Also an
  **fd 0 end-of-stream latch**.
- **`PublicInputs` = (input, output, status)**, and the verifier's 8-word and status
  checks.
- A **per-guest digest test** whose exclusion list is exactly `{opcodes}`.
- The **QEMU differential truncated at the exit function**. QEMU logs about 603 bytes per
  instruction, and fib would grow from 2,117 to about 13.8M debug instructions. The
  emulator and QEMU will also disagree on `0x500`'s `a0` once the precompile lands.
- **Regenerated guest ELFs** and derived fixtures.
- **S16's tamper acceptance retargeted** to: flip a claimed output byte, a final
  `x(24+k)`, or drop the exit row.
- Updates to `ecall-abi.md`, `guest-program-manual.md` and `guest-sdk/CLAUDE.md`.
- **The Poseidon2 precompile as a prerequisite** for real workloads. Measured: 613,100
  cycles per permutation at release and 4,598,021 at debug. About 1 MiB of I/O at debug
  already exceeds the `2^36 − 1` cycle clock, and doubling buffers cost 2 to 4 times each
  stream.

**Recursion.**
- A `no_std` `identity_from_commitments`. `pcs::append_g1_list` is `std` today.
- The accumulator digest committed on fd 1.
- The inner verifier's word and status checks.

---

## Cost at h = 2^22

From `docs/spec/memory.md` §9 and the design review.

- **Minimum per proof: two window shards**, window 0 and the stack window (127). That is
  `2^23` = 8,388,608 init/teardown leaf pairs, four committed `2^22`-entry teardown
  columns (`teardown_ts`, `teardown_value` per shard) and one opened setup column
  (`S[0]`). This holds even for fib's 2,117 cycles, and for `guests/rvc-dense`, which
  touches no window-0 RAM but still proves window 0. Requiring window 0 when it is
  untouched is a simplicity choice for the verifier, not a soundness requirement.
- **Each further touched 16 MiB window adds `2^22` rows and two committed columns.** One
  `sw` into a fresh window costs `2^22` rows. A guest doing 126 stores, one into each of
  windows 1..126, forces about `5.3·10^8` rows and 252 committed columns from 126 cycles.
- **Worst case: 128 windows, `2^29` rows.**
- The traced guests fib, heap, atomics, opcodes and echo touch windows {0, 127};
  rvc-dense touches {127}.
- S14's tests run at `h = 2^16` (8,192 windows; the stack window is 8191), so debug builds
  never construct `2^22`-row trees.
- At other heights: 512 windows at `2^20`, 2,048 at `2^18`.

---

## Open for the next stage

- **`transcript_tags` has 32 entries** and **`challenge_slot` six**. Append, never
  renumber, never reuse a tag across kinds. S16's memory squeeze needs a challenge-kind
  tag, and the init groups need their domain tags.
- **`lookup_channel` has two channels**, `TIMESTAMP` and `RANGE16`. S15 discharges both
  with LogUp, and appends its decoder and generic lookup channels after them.
- **Before touching the memory argument, read `docs/spec/memory.md` §2.1 and §9.** They say
  what S14 does not enforce and which stage owes it.
- **The window geometry assumes `h ≤ 2^29`.** `HEIGHT_MENU` tops out at `2^22` today. A
  menu entry of `2^30` would give `N = 2^29/h = 0` and put window 0's live rows at
  `[2^31, 2^32)`, so the menu must not grow past `2^29` without revisiting
  `docs/spec/memory.md` §3.1. The derived window constant's `u64` product `(4 << n)·w`
  stays below `2^64` for `n ≤ 30` and any `u32` window.
- **S14's test harness draws the memory challenges from a transcript that binds nothing.**
  So solving after the challenges, as C6 does, is possible there by construction. Every
  forgery the review found accepted is a balanced multiset, independent of the challenges;
  the binding comes with S16's global transcript.
