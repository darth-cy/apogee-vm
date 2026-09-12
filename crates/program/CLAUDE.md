# `crates/program`

## What this crate owns
Preprocessing: a `ProgramImage` in; the per-family decoded tables, the `VmConfig` they
derive, and the `ProgramIdentity` that commits to both, out. The table shape, the
family list and its pc-claiming rule, the extra-mask encoding and the identity recipe
below are **frozen at S11**; changing any of them re-registers every program.

```rust
pub type FamilyId = u32;                                   // constants::family
pub const FAMILIES: [FamilyId; 8];                         // ascending: the canonical order
pub fn row_kind(instr: &Instr) -> (FamilyId, u32);         // the pc-claiming rule + mask bit
pub enum RowField { Pc, NextPc, Rs1, Rs2, Rd, Imm, Funct3, ExtraMask }
pub const ROW_FIELDS: [RowField; 8];                       // frozen column order
pub fn lookup_tuple(family: FamilyId) -> &'static [RowField];
pub fn field_mask(family: FamilyId) -> u8;                 // derived from the tuple

pub struct ProgramParams { pub bytecode_size_words: u32, pub heights: [u32; 8], pub code_version: u32 }
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
                        NotAllOpcodesSupported, TableTooShort }   // + Display

pub fn decode_program(image: &ProgramImage, params: &ProgramParams)
    -> Result<(DecodedTables, VmConfig), ProgramError>;
pub fn decode_program_detaching(image, params, detached: &[FamilyId]) -> ...;   // test hook only
pub fn program_identity(tables: &DecodedTables, config: &VmConfig, srs: &Srs) -> ProgramIdentity;
pub fn absorb_statement_descriptor(tr: &mut Transcript, config: &VmConfig, shard_counts: &[u32]);
pub fn family_name(family: FamilyId) -> &'static str;
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
| 6 | `ATOMICS` | `lr.w sc.w` and the nine AMOs | 2^16 |
| 7 | `INIT_TEARDOWN` | no pc; present in every `VmConfig`; an **empty** table: no columns, no live rows | 2^20 |

`bytecode_size_words` defaults to 2^20 (a 4 MiB ceiling), the code version to 0.

**Static detachment.** A family is in the `VmConfig` exactly when it claims at least one
pc (init/teardown always). The preprocessor derives the set; nothing selects it. A pc
whose family is unavailable is claimed by nobody, which is the same loud failure as an
unknown instruction — that is what makes detachment sound. `decode_program_detaching`
exists only to show it.

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
  atomics table holds atomics at or below pc `0x1fffc` only. A row above a *shorter*
  family's height is simply outside that table -- padding there -- so a program's code
  may reach past every table but its own family's. Every committed guest's code ends
  below `0x1c990` — `orderbook`'s is the highest — **except `consistency`**, which is
  1.7 MB of it with an `Arc` inside: its atomics run up to pc `0x18e62a`, the row
  `TableTooShort` names, so the frozen defaults refuse that guest and it takes a uniform
  2^20. Whether heights should be per family at
  all is an open question in `docs/handoff/S12-emulator.md`; the suites here that are not
  *about* the heights take `common::fitting`, the smallest menu height the code fits.
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
| `INIT_TEARDOWN` | — | `0` |

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

## Refusals
Every one is an `Err`, and `Display` names what it refused.

- `UnsupportedCodeVersion` — only `constants::family::CODE_VERSION` is built.
- `HeightNotOnMenu` — every family's height is checked, present or not.
- `ProgramTooLarge` — the word span from `RAM_ORIGIN` to the last file-backed byte of the
  image exceeds `bytecode_size_words`. That span is what an init family enumerating the
  image in closed form would cover; `.bss` and the heap-and-stack reservation are zero
  and not in it.
- `NotAllOpcodesSupported { pc, word, reason }` — "Not all opcodes supported: pc=…": the
  word does not decode, or its family is detached.
- `TableTooShort { family, pc, height }`.

Then `check_partition` re-reads the finished tables and **panics** unless every
instruction slot is live in exactly one table and the live rows number the instructions:
two claims for one pc is a broken invariant of this crate, not something a program can
cause.

## `VmConfig` and the statement descriptor
`VmConfig` is the static shape: the family set ascending with each height, and
`bytecode_size_words`. **Per-proof shard counts are not in it.** Wire form, frozen: `u32`
LE family count `k`, then `k` pairs `u32` LE `(family, height)`, then `u32` LE
`bytecode_size_words`; `from_bytes` refuses a wrong length, an unknown or out-of-order
family, a height off the menu, and a family set without init/teardown. Presence, not
position: init/teardown has the highest id only until the delegation families are
appended above it.

The **statement descriptor** is the static `VmConfig` plus the per-proof shard count of
each of its families, as two adjacent typed messages: `VM_CONFIG` carrying
`[ids..., heights..., bytecode_size_words]` (length `2k+1`, which fixes `k`), then
`SHARD_COUNTS` carrying one count per family in the same order.
`absorb_statement_descriptor` is it.

## Program identity
**The recipe, frozen.** A fresh S02 typed transcript:

1. `append_scalar(PROGRAM_IDENTITY, code_version)`;
2. `append_scalars(VM_CONFIG, [ids..., heights..., bytecode_size_words])` — the same
   message the statement descriptor opens with;
3. for each family ascending: `append_g1_list(COMMITMENT, points)`, the Mercury
   commitments of that family's exported columns in lookup-tuple order, each point four
   `Fr` limbs, **one** length-delimited message per family — an empty list for
   init/teardown;
4. one raw `sample()`: the identity. Raw, not a `challenge_scalar`, because a challenge
   under a scalars tag would be one tag in two kinds.

Wire form: the `Fr`'s canonical 32-byte little-endian encoding.

**What it binds.** Identity is a pure function of `(ProgramImage, family set, heights,
bytecode_size_words, code version)` — and the SRS it commits over, which is presumed
(`docs/spec/srs.md` §4). Every step is deterministic: `load_elf` and `decode_program`
touch no clock, filesystem or hash map; the tables are sorted vectors; Mercury's MSM is
exact and thread-count independent (S07); the transcript is a fixed permutation. Anyone
can rerun ELF → image → tables → commitments → digest and reproduce the value, which is
why S10's reproducible builds matter: if two honest builds of one source disagreed, no
one could confirm a registry entry. It is **not** a function of the input, the trace,
the cycle count or the prover: multiplicities live in the witness, never here.

A Mercury commitment is binding (AGM + q-DLOG over the ceremony), so two different
column sets of one height commit to different points except with negligible
probability, and the transcript framing — tag, length, payload — is injective. Different
tables or a different config therefore give a different identity.

**What it does not bind, yet: the data image.** `.rodata` and `.data` are not in any
decoded table, so two programs identical in code and different in a constant or a jump
table have the same identity. On the repository owner's instruction S11 commits the
instruction tables only; the init/teardown family is in every `VmConfig` and absorbs an
**empty** commitment list, and the stage that builds its table fills that slot. **Nor the entry pc**: `ProgramImage.entry` reaches no table and not the
`VmConfig`, so two images differing only in `e_entry` share an identity. The PC address
space's initial value is init/teardown's to bind, with the data image. Until then,
identity is not a full program identity.

**How a verifier uses it.** Like a public key: taken from a channel the prover does not
control — a registry, a constant, an operator — and never from the proof. A proof
checked against a prover-supplied identity proves "some program ran", which is true and
useless. The verifier never sees an ELF.

## Tests and fixtures
| File | What |
| --- | --- |
| `tests/partition.rs` | Acceptance 3 over every guest (claimed pcs are the instruction slots, each once), 4 (`guests/atomics` with atomics detached fails at its first atomic's pc), 5 (fib has no atomics; `atomics` has them; `mul_free.elf` has no mul/div), and an unknown opcode's named failure |
| `tests/tables.rs` | Acceptance 6 (every exported column of every table scanned: non-live rows are all `MINUS_ONE`, live rows equal to the stored values and neither padding nor zero), code above a shorter family's table, the 59 row kinds pinned numerically, `narrowest` at each width boundary, 7 (`next_pc` against the loader's halfword map), exact heights, `TableTooShort` at the boundary, `ProgramTooLarge` at the ceiling, menu and version refusals, the frozen field masks, one-hot kinds naming exactly 59 mnemonics over the ISA corpus, narrowest storage, determinism, fixture pins |
| `tests/config.rs` | The `VmConfig` wire form byte for byte, its refusals (including a config without init/teardown), an eight-family round trip, the identity wire form, and the statement descriptor as two adjacent messages |
| `tests/identity.rs` | **`#[ignore]`d — needs `assets/ptau/ppot_0080_24.ptau`.** fib at the defaults twice in-process and against the pin; the recipe rebuilt message by message; acceptance 9's four moves; fib rebuilt from source twice |

```
cargo test --release -p program --test identity -- --ignored   # locally, with the ceremony
```

`tests/vectors/mul_free.elf` (hand-encoded, no M or A) and `tests/vectors/identity.txt`
(fib's identity at the defaults and at all-2^16, with a `# ceremony` line the tests check
first) come from `cargo run -p kat-gen -- program`; the identity half needs the ceremony
file and is skipped without it, as the `srs` group is. The identities are generated by
this crate — there is no second preprocessor — so they are a regression pin on the
recipe. Guest ELFs and the ISA corpus are read in place from `crates/loader` and
`crates/isa`.
