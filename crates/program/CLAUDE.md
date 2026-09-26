# `crates/program`

## What this crate owns
Preprocessing: a `ProgramImage` in; the per-family decoded tables, the `VmConfig` they
derive, the image column, and the `ProgramIdentity` that commits to them, out; and the
statement descriptor with its RAM window rules. The table shape, the family list and its
pc-claiming rule and the extra-mask encoding are **frozen at S11**; the identity recipe is
S11's as amended at S14 (`docs/spec/memory.md` §6.2). Changing any of them re-registers
every program.

```rust
pub type FamilyId = u32;                                   // constants::family
pub const FAMILIES: [FamilyId; family::COUNT as usize];    // 15 since S-IO; ascending, the canonical order
pub fn row_kind(instr: &Instr) -> (FamilyId, u32);         // the pc-claiming rule + mask bit
pub enum RowField { Pc, NextPc, Rs1, Rs2, Rd, Imm, Funct3, ExtraMask }
pub const ROW_FIELDS: [RowField; 8];                       // frozen column order
pub fn lookup_tuple(family: FamilyId) -> &'static [RowField];
pub fn field_mask(family: FamilyId) -> u8;                 // derived from the tuple

pub struct ProgramParams { pub bytecode_size_words: u32,
                           pub heights: [u32; family::COUNT as usize], pub code_version: u32 }
impl ProgramParams { pub fn defaults() -> ProgramParams; }
pub struct VmConfig { pub families: Vec<(FamilyId, u32)>, pub bytecode_size_words: u32 }
impl VmConfig { pub fn to_bytes(&self) -> Vec<u8>; pub fn from_bytes(b: &[u8]) -> Option<VmConfig>;
                pub fn height(&self, f: FamilyId) -> Option<u32>; }
pub struct DecodedTables { pub code_version: u32, pub families: Vec<FamilyTable> }
pub struct FamilyTable { pub family: FamilyId, pub height: u32, pub live: PolyBacking,
                         pub columns: Vec<(RowField, PolyBacking)> }
impl FamilyTable { pub fn is_live(&self, row: usize) -> bool;
                   pub fn get(&self, column: usize, row: usize) -> Option<u32>;
                   pub fn column_poly(&self, column: usize) -> MultilinearPoly; }   // the export
pub struct ProgramIdentity(pub Fr);
impl ProgramIdentity { pub fn to_bytes(&self) -> [u8; 32]; pub fn from_bytes(b: &[u8; 32]) -> Option<Self>; }
pub enum ProgramError { UnsupportedCodeVersion, HeightNotOnMenu, ProgramTooLarge,
                        NotAllOpcodesSupported, TableTooShort,
                        ImageOutsideWindow { end: u64, height: u32 },
                        WindowRule { rule: &'static str },
                        UnknownDelegation { addr: u32, number: u32 } }   // + Display

// S21: delegation families, three of them since S23. docs/spec/delegation.md §3 and §7.
// The table *is* `constants::delegation::TYPES`: one array, no second copy.
pub const DELEGATIONS: [(FamilyId, u32, u8, usize); 3];   // (family, ecall, address space, frame words)
pub fn delegation_family(number: u32) -> Option<FamilyId>;
pub fn delegation_ecall(family: FamilyId) -> Option<u32>;
pub fn delegation_space(family: FamilyId) -> Option<u8>;
pub fn delegation_frame_words(family: FamilyId) -> Option<usize>;
pub fn claims_pcs(family: FamilyId) -> bool;
pub fn declared_delegations(image: &ProgramImage) -> Result<Vec<FamilyId>, ProgramError>;

pub fn decode_program(image: &ProgramImage, params: &ProgramParams)
    -> Result<(DecodedTables, VmConfig), ProgramError>;
pub fn decode_program_detaching(image, params, detached: &[FamilyId]) -> ...;   // test hook only
pub fn image_init_column(image: &ProgramImage, height: u32) -> MultilinearPoly;
pub fn program_identity(image: &ProgramImage, tables: &DecodedTables, config: &VmConfig, srs: &Srs)
    -> ProgramIdentity;
pub fn setup_commitments(image: &ProgramImage, tables: &DecodedTables, config: &VmConfig, srs: &Srs)
    -> Vec<Vec<G1Affine>>;
pub fn identity_from_commitments(code_version: u32, config: &VmConfig, entry_pc: u32,
    commitments: &[Vec<G1Affine>]) -> ProgramIdentity;                     // no SRS
pub fn absorb_statement_descriptor(tr: &mut Transcript, config: &VmConfig, shard_counts: &[u32],
    windows: &[u32]);
pub fn check_memory_windows(config: &VmConfig, shard_counts: &[u32], windows: &[u32])
    -> Result<(), ProgramError>;
pub fn family_name(family: FamilyId) -> &'static str;
// S-IO: re-exported from verifier-core beside VmConfig and the descriptor.
pub use verifier_core::{advice_first_window, public_io_words};

pub mod lookup_tables {                  // docs/spec/lookup.md §9
    pub const GENERIC_WIDTH: usize = 3;  // a key and two values; the narrower table zero-padded
                                         // since S17 these three are constants::generic_table's
    pub const AND_BASE: u32 = 0;   pub const AND_ROWS: usize = 1 << 16;
    pub const SIGN_BASE: u32 = 256;  pub const SIGN_ROWS: usize = 1 << 16;
    pub const SHIFT_BASE: u32 = SIGN_BASE + (1 << 16);   pub const SHIFT_ROWS: usize = 32;   // S18
    pub const GENERIC_ROWS: usize = 1 + AND_ROWS + SIGN_ROWS + SHIFT_ROWS;
    pub const GENERIC_LOG_HEIGHT: u32 = 18;   // S17: 2^18 is the first power of two >= GENERIC_ROWS
    pub fn generic_table(log_height: u32) -> Vec<MultilinearPoly>;
    pub fn generic_entries() -> Vec<[u32; GENERIC_WIDTH]>;
    pub fn zero_entry() -> [Fr; GENERIC_WIDTH];
    pub fn generic_commitments(srs: &Srs) -> [G1Affine; GENERIC_WIDTH];   // S17; panics below 2^18 powers
}
```

## The families, and who claims what
`constants::family`, append-only; later transcript seeding and canonical ordering cite
these numbers. `row_kind` is a total function of the decoded instruction, so every pc
is claimed by exactly one family by construction.

| Id | Family | Claims | Default height |
| --- | --- | --- | --- |
| 0 | `ADD_SUB_LUI_AUIPC` | `add sub addi lui auipc`, and **the system row kind: `ecall ebreak fence`** | 2^22 |
| 1 | `JUMP_BRANCH_SLT` | `jal jalr beq bne blt bge bltu bgeu slt sltu slti sltiu` | 2^22 |
| 2 | `SHIFT_BITWISE` | `sll srl sra slli srli srai and or xor andi ori xori` | 2^22 |
| 3 | `MUL_DIV` | `mul mulh mulhsu mulhu div divu rem remu` | 2^20 |
| 4 | `MEM_WORD` | `lw sw` | 2^22 |
| 5 | `MEM_SUBWORD` | `lb lh lbu lhu sb sh` | 2^22 |
| 6 | `ATOMICS` | `lr.w sc.w` and the nine AMOs | 2^20 |
| 7 | `INIT_TEARDOWN` | no pc; RAM window 0, the image window, exactly one shard; present in every `VmConfig`; an **empty** table: no columns, no live rows | 2^22 |
| 8 | `ZERO_WINDOWS` | no pc; the zero-initialized RAM windows above window 0, one shard per touched window; present in every `VmConfig`; an **empty** table | 2^22 |
| 9 | `KECCAK_F` | no pc; **invoked, not decoded**: ecall `0x501`, one keccak-f[1600] permutation a row, present exactly when the image declares it; an **empty** table | 2^8 |
| 10 | `POSEIDON2` | no pc; the same, ecall `0x500`, one width-3 permutation a row | 2^8 |
| 11 | `FR_ARITH` | no pc; the same, ecall `0x502`, one `Fr` add, multiply or inverse a row | 2^8 |
| 12 | `PUBLIC_INPUT` | no pc; the public input window at `0x8000`, **exactly one shard**, present in every `VmConfig` at the **pinned** `family::PUBLIC_WINDOW_HEIGHT`; an **empty** table | 2^8 |
| 13 | `PUBLIC_OUTPUT` | no pc; the journal at `0x8400`, exactly one shard, present in every `VmConfig` at the same pinned height; an **empty** table | 2^8 |
| 14 | `ADVICE_WINDOWS` | no pc; the prover's advice from `0x8000_0000` up, `k >= 0` consecutive windows, present in every `VmConfig` at the window height; an **empty** table | 2^22 |
| 15 | `MOD_MUL` | no pc; **invoked, not decoded**: ecall `0x503`, one `a·b mod m` over eight 32-bit limbs a row, the modulus **witnessed** rather than a constant of the circuit; an **empty** table | 2^8 |

The **three** window families — `INIT_TEARDOWN`, `ZERO_WINDOWS` and, since S-IO,
`ADVICE_WINDOWS` — have **one height**, `h`: RAM window `w` is the bytes
`[4h·w, 4h·(w+1))` (`docs/spec/memory.md` §3). `bytecode_size_words` defaults to 2^20
(a 4 MiB ceiling), the code version to 0.

**Static detachment.** A family is in the `VmConfig` exactly when it claims at least one
pc, a **window family** always, and — since S21 — **a delegation family exactly when the
image declares it**. Those are the three presence rules and there are no others. S-IO added
no fourth: its three families join the second, so "always" now names five — the two init
families, the two public value families and `ADVICE_WINDOWS`. The two public families are
in every `VmConfig` **whether or not the execution uses them**, and each proves exactly one
shard, because a count a prover could drop is a way to publish nothing while having
published something; a program that ignores public values simply publishes an empty input
and an empty journal (`docs/spec/public-values.md` §4). The consequence is that **every
program's identity moved at S-IO** relative to a tree without them, the `VM_CONFIG` message
listing the family set. The
preprocessor derives the set; nothing selects it. A pc whose family is unavailable is
claimed by nobody, which is the same loud failure as an unknown instruction — that is what
makes detachment sound. `decode_program_detaching` exists only to show it; detaching an init
family leaves it out of the set, which is refused.

**The two public families' height is pinned in derivation, not read from `ProgramParams`.**
`height_of` writes `family::PUBLIC_WINDOW_HEIGHT` for both whatever a caller asked for,
because a window's first address is `4·height·window` — the height is what *places* the
windows, and `2^8` is the only menu entry putting `PUBLIC_INPUT_ORIGIN` and
`PUBLIC_OUTPUT_ORIGIN` in two distinct windows. So there is nothing a caller could usefully
say, and "every family at `h`" keeps meaning every family whose height is a choice.
**Derivation pins it; decoding refuses a wrong one**, and that is the check that matters:
`verifier_core::window_height` runs inside `VmConfig::from_bytes`, on bytes a verifier was
handed, where the input is not the caller's own (`docs/spec/public-values.md` §2).

**A delegation family claims no pc, so the instruction sweep can never learn that a program
calls one**: the ecall number lives in `a7` at run time and no instruction word carries it.
What decides membership is a **declaration record** the SDK shim emits into
`.rodata.apogee.delegations` — `constants::delegation::MARKER_MAGIC` then the number, twelve
bytes — and `declared_delegations` scans the image's file-backed segment bytes for it,
**byte-wise**, because a `static`'s address is the linker's and the record has landed at an
odd offset in practice. The mechanism is **reachability**: the record is referenced by the
shim and by nothing else, so the linker keeps it exactly when the shim is linked. Two things
break exactly one half of that and each is caught by
`crates/program/tests/delegation.rs`: a `#[used]` record survives into every guest that links
the SDK — `guests/Cargo.toml` pins `codegen-units = 1`, so the SDK is one object file and ten
guests carried the marker before `#[used]` came off — and an optimiser that folds the record's
number into an immediate drops it at `--release`, which `core::hint::black_box` in
`guest_sdk::delegation_number` is what prevents. A record naming a number no family answers is
`UnknownDelegation`, loudly: the guest and this preprocessor disagreeing about the ABI is not
something to ignore.

## The table
- **One row per halfword, absolute.** Row `i` is pc `2i`. A family's table has exactly
  its `VmConfig` height, an even power of two, and that is the length committed.
- **Live rows** hold the family's instructions; every other row — the second halfword of
  a 32-bit instruction, a not-code slot, a pc another family owns, every address outside
  the code — is **padding: `Fr::MINUS_ONE` in every field**. Never 0: pc 0 is a valid pc,
  so an all-zero row would be claimable. No live row can equal the padding row (its `pc`
  is below `2^32`), and none is all zeros (`next_pc >= 2`).
- **Strictly taller than the program.** A family's height must exceed its last live row
  by at least one, or derivation fails with `TableTooShort` naming the pc. So a 2^16
  atomics table would hold atomics at or below pc `0x1fffc` only, which is what the
  defaults gave until S19. A row above a *shorter*
  family's height is simply outside that table -- padding there -- so a program's code
  may reach past every table but its own family's. Every committed guest's code ends
  below `0x1c990` — `orderbook`'s is the highest — **except `consistency`**, which is
  1.7 MB of it with an `Arc` inside: its atomics run up to pc `0x18e62a`, and until S19
  the frozen defaults gave atomics 2^16 rows and refused that guest, which then took a
  uniform 2^20 — the height its file bytes, ending at `0x1efea0`, need for window 0 too.
  **S19 raised `DEFAULT_HEIGHTS[ATOMICS]` to 2^20**, the timestamp channel's floor, with
  the circuit that needs it (`docs/spec/memory-ops.md` §7.1), so every committed guest now
  preprocesses at the defaults and `TableTooShort` keeps a test of its own against an
  explicit 2^16. Whether heights should be per family at all is an open question in
  `docs/handoff/S12-emulator.md`; the suites here that are not *about* the heights take
  `common::fitting`, the smallest menu height the code fits.
- **Fields**, in frozen column order `pc, next_pc, rs1, rs2, rd, imm, funct3,
  extra_mask`. A form's absent register is `x0` and absent immediate 0. `imm` is the
  two's-complement `u32` of the value the instruction uses (`crates/isa` defines it),
  except on a system row. `next_pc` is the sequential fall-through — `pc + 2` for an
  instruction two bytes long in memory, `pc + 4` otherwise — never a branch target, so
  the fall-through constraint is linear.
- **Storage** is column-major, each column in the narrowest `PolyBacking` its live values
  fit (`U1`, `U8`, `U16`, `U32`), zero on non-live rows, beside a `U1` liveness column.
  `MINUS_ONE` is materialised only by `column_poly`, which is the export later stages
  consume and exactly what identity commits.

### Per-family fields: the lookup tuples
`lookup_tuple` is the one place a family's columns are chosen; `field_mask` walks
`ROW_FIELDS` pushing `true` for a field the tuple holds and `false` otherwise, and
asserts the `true` count is the tuple's arity, the tuple is in frozen order, and every
instruction family starts `pc, next_pc`. A decoder-derived column the lookup does not
cover is therefore not expressible.

| Family | Tuple | Mask |
| --- | --- | --- |
| `ADD_SUB_LUI_AUIPC`, `JUMP_BRANCH_SLT`, `SHIFT_BITWISE`, `MEM_WORD`, `MEM_SUBWORD` | `pc next_pc rs1 rs2 rd imm extra_mask` | `0b1011_1111` |
| `MUL_DIV`, `ATOMICS` | `pc next_pc rs1 rs2 rd extra_mask` | `0b1001_1111` |
| `INIT_TEARDOWN`, `ZERO_WINDOWS`, the four delegation families, `PUBLIC_INPUT`, `PUBLIC_OUTPUT`, `ADVICE_WINDOWS` | — | `0` |

**`funct3` is in no tuple.** The extra mask is one-hot per mnemonic, which leaves it
nothing to say; it remains a row field so a later family that wants it can take it.

### `family_extra_mask`
**One-hot per row kind**, and a row kind is a mnemonic — except the add/sub/lui/auipc
family's bit 0, the system kind, shared by `ecall`, `ebreak` and `fence`, whose rows are
told apart by `imm`: `constants::extra_mask::system_code` gives `ECALL = 0`,
`EBREAK = 1`, `FENCE = 2` (the first two are their own `funct12`; every fence is a no-op
on one hart, so its `pred`/`succ`/`fm` are not recorded). A circuit unpacks the mask
into selector bits, and one-hotness comes from the table's domain, not a constraint.

Bits are frozen in `constants::extra_mask`, append-only, packed little-endian (bit `k`
is `1 << k`), in canonical ascending order of `(opcode, funct3, funct7)` — `funct5` for
the atomics — with the system kind pinned to bit 0 ahead of that order:

| Family | Bits |
| --- | --- |
| 0 | `SYSTEM ADDI AUIPC ADD SUB LUI` |
| 1 | `SLTI SLTIU SLT SLTU BEQ BNE BLT BGE BLTU BGEU JALR JAL` |
| 2 | `SLLI XORI SRLI SRAI ORI ANDI SLL XOR SRL SRA OR AND` |
| 3 | `MUL MULH MULHSU MULHU DIV DIVU REM REMU` |
| 4 | `LW SW` |
| 5 | `LB LH LBU LHU SB SH` |
| 6 | `AMOADD_W AMOSWAP_W LR_W SC_W AMOXOR_W AMOOR_W AMOAND_W AMOMIN_W AMOMAX_W AMOMINU_W AMOMAXU_W` |

`aq` and `rl` are not recorded: on one hart they order nothing.

## The generic lookup table
`lookup_tables` packs the tables a wide field still needs — an 8×8 AND byte table,
`U16GetSign` and, since S18, `ShiftPowers` — into one committed setup table,
`docs/spec/lookup.md` §9: the `ZeroEntry` at row 0, AND at rows 1..=2^16 as
`(AND_BASE + a + 1, b, a & b)`, `U16GetSign` at the next 2^16 as
`(SIGN_BASE + h + 1, h >> 15, 0)`, `ShiftPowers` at the next 32 as
`(SHIFT_BASE + s + 1, 2^s, 2^(31 − s))`, and the `ZeroEntry` again above them. The three
key ranges are pairwise disjoint, so no tuple of one is a tuple of another, and the `+ 1`
the gating adds keeps every real entry off the all-zero tuple the `ZeroEntry` answers.
131,105 rows, so a circuit carrying them is at 2^18 or more. **`U16GetSign` is committed,
not closed-form**; S17 and S18 consume it by name. **`ShiftPowers`' domain is a bound**:
32 rows, one per RV32 shift amount, is what truncates a shift
(`docs/spec/shift-bitwise.md` §3.1), and its second value is `2^(31 − s)` rather than
`2^(32 − s)` because `2^32` does not fit these `u32` columns — the two gates that read it
carry the factor 2.

**Since S17** the three layout constants are `constants::generic_table`'s — a circuit,
which cannot depend on this crate, builds a key into the table — and the names here are
aliases. `generic_commitments(srs)` is the table's three commitments, in tuple order,
computed at `GENERIC_LOG_HEIGHT`; it panics if `srs` holds fewer than `2^18` powers. They
are the same three points at every height `2^n` with `n` even and at least 18, a commitment reading the
table as coefficients and every row past its entries being zero. So they are a constant of
the ceremony: every verifying key carries them, whatever its families read, and its SRS
digest covers them (`docs/spec/shard-proof.md` §3, `docs/spec/jump-branch-slt.md` §6).
Anyone holding the ceremony recomputes them with this function; a verifier holding only
the `SrsVerifier` cannot. `tests/vectors/generic_table.txt` pins them over the ceremony,
and `kat-gen -- program` writes it when the ceremony file is present, after checking that
the table commits to the same points at every menu height from `2^18` up: `2^18`, `2^20`
and `2^22`.

## The image column
`image_init_column(image, h)` is RAM window 0's initial words: row `y` is
`image.initial_word(4y)`, `h` rows, `U32`-backed. `initial_word` assembles a word byte
by byte from segments' file-backed bytes, zero everywhere else, and is the one source
`trace`'s initial RAM value calls too. Rows `y < 2^14` lie below `RAM_ORIGIN` and are 0.
Identity commits the column as `INIT_TEARDOWN`'s one setup column.

## Refusals
Every one is an `Err`, and `Display` names what it refused.

- `UnsupportedCodeVersion` — only `constants::family::CODE_VERSION` is built.
- `HeightNotOnMenu` — every family's height is checked, present or not.
- `ProgramTooLarge` — the word span from `RAM_ORIGIN` to the last file-backed byte of the
  image exceeds `bytecode_size_words`. Only segments with file bytes count: `.bss` and the
  heap-and-stack reservation are zero and not in the span, wherever they lie.
- `NotAllOpcodesSupported { pc, word, reason }` — "Not all opcodes supported: pc=…": the
  word does not decode, or its family is detached.
- `TableTooShort { family, pc, height }`.
- `WindowRule { rule }` — `verifier_core::window_height`'s answer, mapped. The derived
  family set lacks one of the **three** window families (only a detaching test can make it)
  or their heights differ — a `ZERO_WINDOWS` height below `INIT_TEARDOWN`'s would give image
  words a second init row, and an `ADVICE_WINDOWS` height of its own would put the advice
  region on another grid than `advice_first_window` computes — or, since S-IO, the set lacks
  a public value family, one of them is not at `family::PUBLIC_WINDOW_HEIGHT`, or `4h` is
  below `PUBLIC_OUTPUT_ORIGIN + PUBLIC_WINDOW_BYTES`, which would let a `ZERO_WINDOWS` id
  claim a public window.
- `UnknownDelegation { addr, number }` — a declaration record in the image names an ecall
  number no registered family answers. Loud rather than ignored: the guest and this
  preprocessor disagree about the ABI, and a silently dropped declaration makes the guest's
  own call fail much later and much less clearly.
- `ImageOutsideWindow { end, height }` — one past the last file-backed byte is above
  `4 · height(INIT_TEARDOWN)`, counting segments with file bytes only. Otherwise `.data`
  placed in window 1 would read as zero and not move the identity.

Then `check_partition` re-reads the finished tables and **panics** unless every
instruction slot is live in exactly one table and the live rows number the instructions:
two claims for one pc is a broken invariant of this crate, not something a program can
cause.

## `VmConfig` and the statement descriptor
**Since S16 these live in `crates/verifier-core`**, which the no_std verifier and the prover
share: `VmConfig`, `ProgramIdentity` and `absorb_statement_descriptor` are re-exported
here unchanged; `check_memory_windows` wraps the core's, mapping its `&'static str` into
`WindowRule`; and `identity_from_commitments` encodes its points and calls the core's
`identity_digest`, which takes the 64-byte encodings. The recipes and wire forms below did
not move a byte, and every path above still resolves.

`VmConfig` is the static shape: the family set ascending with each height, and
`bytecode_size_words`. **Per-proof shard counts are not in it.** A delegation family's id is
above the two RAM window families', so a config lists it after them — but **not last since
S-IO**, whose three families take the highest ids; `crates/program/tests/delegation.rs`
holds every registered delegation to that position. Wire form, frozen: `u32`
LE family count `k`, then `k` pairs `u32` LE `(family, height)`, then `u32` LE
`bytecode_size_words`; `from_bytes` refuses a wrong length, an unknown or out-of-order
family, a height off the menu, and **anything `window_height` refuses** — which since S-IO
is every rule in the `WindowRule` list above, the public families' pinned height included.
That is the check that matters, because it is the one on bytes a verifier was handed.
Presence, not position: since S21 the init families no
longer have the highest ids, `KECCAK_F` being 9.

The **statement descriptor** is the static `VmConfig`, the per-proof shard count of each
of its families, and the RAM window list, as three adjacent typed messages: `VM_CONFIG`
carrying `[ids..., heights..., bytecode_size_words]` (length `2k+1`, which fixes `k`),
`SHARD_COUNTS` carrying one count per family in the same order, and `MEMORY_WINDOWS`
carrying `ZERO_WINDOWS`' window ids `[w_1 … w_k]`, empty when there are none.
`absorb_statement_descriptor` is it, and checks nothing.

`check_memory_windows` is the verifier's rule over the same three, before the memory
challenges (`docs/spec/memory.md` §3.5): `window_height`'s rules; `INIT_TEARDOWN`'s shard
count 1; one window id per `ZERO_WINDOWS` shard; the ids strictly increasing; every id in
`[1, 2^29 / h − 1]`; and, since S-IO, exactly one `PUBLIC_INPUT` shard, exactly one
`PUBLIC_OUTPUT` shard, and `advice_first_window(h) + k <= 2^30 / h` for `ADVICE_WINDOWS`'
count `k`. `ZERO_WINDOWS` shard `i` is window `w_i`; the advice windows need no list, being
the `k` consecutive windows from `advice_first_window(h) = 2^29 / h` up — exactly where the
`ZERO_WINDOWS` bound stops, so the two families' ids are disjoint by arithmetic. A
breach is `WindowRule`, its `rule` naming which. It takes the `VmConfig` as
`decode_program` derives it or `VmConfig::from_bytes` decodes it — families strictly
ascending — and does not check that shape again.

## Program identity
**The recipe, frozen** (`docs/spec/memory.md` §6.2). A fresh S02 typed transcript:

1. `append_scalar(PROGRAM_IDENTITY, code_version)`;
2. `append_scalars(VM_CONFIG, [ids..., heights..., bytecode_size_words])` — the same
   message the statement descriptor opens with;
3. `append_scalar(PROGRAM_ENTRY, entry_pc)`;
4. for each family ascending: `append_g1_list(COMMITMENT, points)`, **one**
   length-delimited message per family, each point four `Fr` limbs — an instruction
   family's exported columns in lookup-tuple order; `INIT_TEARDOWN`'s
   `[cm(image_init_column(image, h))]`; an empty list for every other family;
5. one raw `sample()`: the identity. Raw, not a `challenge_scalar`, because a challenge
   under a scalars tag would be one tag in two kinds.

**`setup_commitments` returns an empty list for `PUBLIC_INPUT`, `PUBLIC_OUTPUT` and
`ADVICE_WINDOWS`, deliberately** — as it does for `ZERO_WINDOWS`, which has no setup
column, and for a delegation family, which has no decoded table at all. The reason here is
sharper than "nothing to commit": an `S` column is bound by program identity, and **one
execution's public values — or one execution's advice — have no business in every
execution's identity**. Theirs is an `M` column instead, committed in the global commit
phase, which is before the memory challenges are squeezed; the two public families' is held
to the statement by `verify_shard_local`'s step 10c rather than by identity, and
`ADVICE_WINDOWS`' is held to nothing at all, which is what makes it advice
(`docs/spec/public-values.md` §4).
`INIT_TEARDOWN`'s init column is `S[0]` for the opposite reason: the image is the program.

`setup_commitments` is step 4's lists, and needs the SRS; `identity_from_commitments` is
the digest over given lists, and does not — it is what a verifying-key loader recomputes.
`program_identity` is the two composed. Wire form: the `Fr`'s canonical 32-byte
little-endian encoding.

**What it binds.** Identity is a pure function of `(ProgramImage's instruction slots, its
file-backed bytes, its entry, family set, heights, bytecode_size_words, code version)` —
and the SRS it commits over, which identity does not bind: since S16 the statement binds
the SRS's verifier points instead, and since S17 the generic table's three commitments,
through the verifying key's SRS digest (`docs/spec/shard-proof.md` §3). `decode_program`
refuses file bytes past window 0, so every one of them is in the image column. Every step
is deterministic: `load_elf` and `decode_program` touch no clock, filesystem or hash map;
the tables are sorted vectors; Mercury's MSM is exact and thread-count independent (S07);
the transcript is a fixed permutation. Anyone can rerun ELF → image → tables and image
column → commitments → digest and reproduce the value, which is why S10's reproducible
builds matter: if two honest builds of one source disagreed, no one could confirm a
registry entry.

A Mercury commitment is binding (AGM + q-DLOG over the ceremony), so two different
column sets of one height commit to different points except with negligible
probability, and the transcript framing — tag, length, payload — is injective. Different
tables, a different image window, a different entry pc or a different config therefore
give a different identity.

**What it does not bind.** Nothing an execution chooses: not the input, the trace, the
cycle count, the prover, a shard count or the window list — multiplicities and the
statement live elsewhere. Nor a segment's zero tail: resizing a segment with no file
bytes, or the `.bss` above a segment's file bytes, leaves the image column as it was, and
every such byte initializes to 0 regardless.

**How a verifier uses it.** Like a public key: taken from a channel the prover does not
control — a registry, a constant, an operator — and never from the proof. A proof
checked against a prover-supplied identity proves "some program ran", which is true and
useless. The verifier never sees an ELF.

## Tests and fixtures
| File | What |
| --- | --- |
| `tests/partition.rs` | Acceptance 3 over every guest (claimed pcs are the instruction slots, each once; both init families in every config), 4 (`guests/atomics` with atomics detached fails at its first atomic's pc), 5 (fib has no atomics; `atomics` has them; `mul_free.elf` has no mul/div), and an unknown opcode's named failure |
| `tests/delegation.rs` | **S21.** The registry read three ways and its two rules (every number in the precompile range, every family above the window ones, none claiming a pc or carrying a table); the byte-wise scan at every offset 0–7; a family declared twice counted once; a truncated record declaring nothing; a segment with no file bytes carrying none; an unknown number refused by name; and **acceptance 8 over every committed guest** — the two keccak guests declare `KECCAK_F`, no other guest declares anything at all, and each config's delegation families are exactly its declared ones. The second clause is the one that matters: `#[used]` would put the record in all seventeen. Plus, `#[ignore]`d, `reachability_survives_the_optimiser`: `keccak-test` and `fib` built from source at **both** optimisation levels, since the committed fixtures are `debug` and the `core::hint::black_box` in the shim exists for `opt-level = 3` |
| `tests/tables.rs` | Acceptance 6 (every exported column of every table scanned: non-live rows are all `MINUS_ONE`, live rows equal to the stored values and neither padding nor zero), code above a shorter family's table, the 59 row kinds pinned numerically, `narrowest` at each width boundary, 7 (`next_pc` against the loader's halfword map), exact heights, `TableTooShort` at the boundary, `ProgramTooLarge` at the ceiling with segments without file bytes not counted, `ImageOutsideWindow` at `4h − 1` / `4h`, the image column of every guest against `initial_word` and the segment bytes, menu and version refusals, the frozen field masks, one-hot kinds naming exactly 59 mnemonics over the ISA corpus, narrowest storage, determinism, fixture pins |
| `tests/config.rs` | The `VmConfig` wire form byte for byte, its refusals, a config without either init family or with the two at different heights refused by derivation and by `from_bytes`, a round trip of every family there is, the identity wire form, the statement descriptor as three adjacent messages, and every `check_memory_windows` rule at its boundary |
| `tests/identity.rs` | **All but two `#[ignore]`d — they need `assets/ptau/ppot_0080_24.ptau`.** fib at the defaults twice in-process and against the pin; the recipe rebuilt message by message; acceptance 9's moves plus a `.rodata` byte, a `.data` byte and the entry pc; a segment without file bytes resized does not move it; fib rebuilt from source twice. In CI: `identity_from_commitments` rebuilt message by message over a distinct point per family, and moved by the entry pc and by each commitment. `setup_commitments` — which column `INIT_TEARDOWN` commits, at which height — is reached only by the ignored recipe test |
| `tests/lookup_tables.rs` | S15's acceptance 10 — the packed table against an independent reference, and a poisoned row caught — a height below the table's 131,105 rows refused with a panic, and the three key ranges pairwise disjoint and off zero; and S17's pin: in CI, `the_generic_table_commitments_are_pinned_over_the_ceremony` holds `generic_table.txt` to `identity.txt`'s ceremony and to three 64-byte points; `#[ignore]`d, `the_generic_table_commitments_are_the_ceremonys_at_every_height` recomputes `generic_commitments` over the ceremony, holds it to the pin, and holds the table over `2^18`, `2^20` and `2^22` to the same three points |

```
cargo test --release -p program --test identity -- --ignored   # locally, with the ceremony
cargo test --release -p program --test lookup_tables -- --ignored
```

`tests/vectors/mul_free.elf` (hand-encoded, no M or A) and `tests/vectors/identity.txt`
(fib's identity at the defaults and at all-2^16, with a `# ceremony` line the tests check
first) come from `cargo run -p kat-gen -- program`, and so, since S17, does
`tests/vectors/generic_table.txt` (the same `# ceremony` line, then one row: the packed
table's three commitments, key column first, each 64 bytes as hex); the identity and
generic-table halves need the ceremony file and are skipped without it, as the `srs` group
is. The identities and the table's commitments are generated by this crate — there is no
second preprocessor — so they are a regression pin on the recipe. Guest ELFs and the ISA
corpus are read in place from `crates/loader` and `crates/isa`.
