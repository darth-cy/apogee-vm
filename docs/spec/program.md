# The program: from ELF to identity

How a guest binary becomes the static, verifier-known description of a program. `crates/loader`
reads an ELF into a `ProgramImage`, `crates/isa` decodes its instructions, and `crates/program`
routes them into per-family decoded tables, derives the `VmConfig` and commits to all of it as the
**program identity**. Every step is a pure function of its input.

## 1. Loading

`loader::load_elf` accepts a static executable — `ELFCLASS32`, little-endian, `ET_EXEC`,
`EM_RISCV` — whose `PT_LOAD` segments lie inside guest RAM (`constants::guest_memory`) at even
addresses, pairwise disjoint, with `p_filesz ≤ p_memsz`, at least one of them executable.
Anything else is a named `LoaderError`: `DynamicElf` for `ET_DYN`, `PT_DYNAMIC` or `PT_INTERP`,
`EntryNotAnInstruction` for an `e_entry` that is not the first halfword of an instruction, and the
sweep's refusals (§2).

Of a program header it reads `p_type`, `p_offset`, `p_vaddr`, `p_filesz`, `p_memsz` and the `PF_X`
bit, and nothing else: the VM has no pages, and all of RAM is addressable whatever the segments
declare. The address map, and the segment layout a guest ELF keeps for host loaders, are
[ecall-abi.md](ecall-abi.md) §6.

## 2. RVC expansion and slots

`slots` holds one `Slot` per halfword from `slot_base`, the lowest loaded address, to the end of
the highest executable segment: the slot of `pc` is `slots[(pc − slot_base)/2]`. `load_elf` sweeps
each executable segment's file bytes from its start, by the halfword at `pc`:

```text
low bits 11   pc += 4   Instruction { word: the four bytes, compressed: false }, MidInstruction
0x0000        pc += 2   NonInstruction
otherwise     pc += 2   Instruction { word: rvc::expand(halfword), compressed: true }
```

Every other halfword is `NonInstruction`. An encoding longer than 32 bits (`InstructionTooLong`),
one cut off by the end of the file bytes (`TextTruncated`) or a halfword `rvc::expand` refuses
(`RvcIllegal`) refuses the image; 32-bit words are decoded in §5.

- **Addresses are never compacted.** A `c.addi` at `0x1002` stays there and occupies two bytes,
  so linker-resolved addresses hold; `compressed`, the instruction's length, is the only record of
  whether the next pc is `pc + 2` or `pc + 4`.
- `rvc::expand` takes the base C extension in its RV32 form and refuses the floating-point forms,
  the RV64-only forms (`c.addw`, `c.subw`, a shift with `shamt[5]`), the reserved code points and
  the `Zc*` encodings. A HINT such as `c.addi x0, 5` is expanded; its 32-bit form writes `x0`.
- `0x0000`, RVC's defined-illegal encoding, is not refused: LLVM pads unreachable blocks with it.
  Reaching it is fatal at run time.

**A desynchronised sweep cannot make a wrong instruction provable.** A slot is a function of the
bytes at its own pc, so every `Instruction` slot is what a hart fetching there would decode; data
that shifts the sweep off the true boundaries can only lose true instruction starts, whose pcs
then have no table row (§5), or meet an unclaimed encoding and refuse the image.
`crates/loader/tests/differential.rs` holds committed guests' slots to `llvm-objdump`'s listing,
and the expansion to LLVM's own encoder over `guests/rvc-dense`, one sequence assembled compressed
and not: a wrong expansion would be a valid proof of another program.

## 3. `ProgramImage` and its wire form

The wire form is `postcard` over `ProgramImage`'s four fields in order, with no header; every
integer but `kind` is a LEB128 varint:

```text
ProgramImage = entry ‖ n ‖ n × Segment ‖ slot_base ‖ m ‖ m × Slot
Segment      = vaddr ‖ mem_len ‖ len ‖ bytes    mem_len is p_memsz; bytes, the p_filesz file bytes
Slot         = kind: u8 ‖ word                  kind 0 a four-byte instruction, 1 a two-byte one,
                                                2 MidInstruction, 3 NonInstruction; word 0 for 2, 3
```

The reader re-checks what `load_elf` establishes — segments at even addresses, sorted, disjoint
and inside RAM; `slot_base` the lowest segment's address; each four-byte `Instruction` followed by
its `MidInstruction`; `entry` an `Instruction` slot — but not `slots` against the bytes.
`artifact-dump` writes this form ([tools.md](../tools.md) §5); no prover or verifier reads it,
`host::setup` starting from the ELF.

`ProgramImage::initial_word(addr)` is the little-endian word at `addr` before the first cycle:
file bytes where a segment has them, zero elsewhere. The image column (§8) and the trace's initial
RAM values are read from it.

## 4. The instruction set and family routing

`isa::decode` takes 32-bit words only and accepts exactly RV32IMA's 59 instructions — 40 of
RV32I, 8 of M, 11 of A — with any value in an operand field, `x0` destinations included, and the
one legal value in every fixed field: `funct7`, `jalr`'s `funct3`, all of `ecall` and `ebreak`, an
atomic's `.w` width, `lr.w`'s `rs2 = 0`. Everything else is a `DecodeError`: RV64 encodings, F, D,
Zicsr, `fence.i`, privileged instructions. `crates/isa/tests/sweep.rs` holds it, over all `2^30`
words with low bits `11`, to accepted counts derived from the ISA's tables and to an independent
encoder.

- **`fence` is every `MISC-MEM` word with `funct3 = 000`**, `2^22` of them, whatever its `rd`,
  `rs1`, `fm`, `pred` and `succ`: the ISA has a base implementation treat a reserved setting as a
  normal fence (`llvm-objdump` prints those `<unknown>`), and on one hart a fence does nothing.
- An immediate is the value the instruction uses: sign-extended for I, S, B and J, the shifted
  word for U, the amount for a shift immediate. B and J displacements are even by encoding;
  nothing asks for 4-byte alignment.

`program::row_kind`, a total function, routes an instruction to one family and one bit of that
family's mask (§6):

| id | family | mnemonics, from mask bit 0 up |
| --- | --- | --- |
| 0 | `ADD_SUB_LUI_AUIPC` | *system* (`ecall ebreak fence`), `addi auipc add sub lui` |
| 1 | `JUMP_BRANCH_SLT` | `slti sltiu slt sltu beq bne blt bge bltu bgeu jalr jal` |
| 2 | `SHIFT_BITWISE` | `slli xori srli srai ori andi sll xor srl sra or and` |
| 3 | `MUL_DIV` | `mul mulh mulhsu mulhu div divu rem remu` |
| 4 | `MEM_WORD` | `lw sw` |
| 5 | `MEM_SUBWORD` | `lb lh lbu lhu sb sh` |
| 6 | `ATOMICS` | `amoadd amoswap lr sc amoxor amoor amoand amomin amomax amominu amomaxu`, each `.w` |

## 5. Decoded tables

`program::decode_program(image, params)` decodes every `Instruction` slot — a word `isa::decode`
refuses fails the program, reachable or not (`NotAllOpcodesSupported`) — and builds a table for
each family of the config. An instruction family's columns are committed setup columns, which each
cycle's decoder lookup reads ([lookup.md](lookup.md) §10); other families' tables have none.

- **One row per halfword, absolute.** Row `i` is pc `2i`, and a table has exactly its family's
  height `h` (§7).
- **A live row** holds one of the family's instructions in the fields of its lookup tuple
  (`program::lookup_tuple`): `pc, next_pc, rs1, rs2, rd, imm, extra_mask`, without `imm` for
  `MUL_DIV` and `ATOMICS`; no tuple holds `funct3`, the mask saying more. `next_pc` is the
  fall-through, `pc + 2` or `pc + 4` by the slot's length, never a branch target. A register the
  form lacks is 0; `imm` is the two's complement of §4's value, 0 where the form has none, or a
  system code (§6).
- **Every other row is padding, `Fr::MINUS_ONE` in every field** (`FamilyTable::column_poly`).
  An all-zero row would be a claimable instruction at pc 0 with an empty mask; a live field is
  below `2^32`, so no live row is the padding row.
- **Reach.** Derivation fails (`TableTooShort`) unless the family's own last instruction has
  `pc ≤ 2h − 4`; another family's code may lie beyond it. Code is linked from `RAM_ORIGIN = 2^16`,
  so a family reaches 1.9375 MiB of it at `2^20` and 7.9375 MiB at `2^22`, the largest height.

Every `Instruction` slot is a live row of exactly one table, and no table has another
(`check_partition`).

**Code is static.** A cycle's instruction comes from these tables, never from RAM: a store into
`.text` changes what a load reads, not what executes, and a pc that is not an `Instruction` slot
has no row, so reaching it is fatal and unprovable ([execution-trace.md](execution-trace.md) §10).

## 6. The extra mask

A tuple's last field, `family_extra_mask`, is `1 << kind`, the kind being the instruction's
position in its row of §4's table (`constants::extra_mask`). A kind is a mnemonic, except family
0's bit 0, the **system** kind, whose three instructions are told apart by `imm`
(`constants::extra_mask::system_code`): `ecall` 0, `ebreak` 1, `fence` 2. A fence's `fm`, `pred`
and `succ`, and an atomic's `aq` and `rl`, are not recorded; on one hart they order nothing.

One-hotness is the table's, not a gate's: a circuit holds each bit it extracts boolean, and the
decoder lookup, which admits only the table's rows, is what excludes an empty or many-bit mask
([lookup.md](lookup.md) §10).

## 7. `VmConfig` and heights

`verifier_core::VmConfig { families: Vec<(family, height)>, bytecode_size_words }` is a program's
static shape: its families, ascending by id (`constants::family`), each with its height, the row
count of one of its shards; an execution's shard counts are not in it. `decode_program` derives
the family set, and nothing selects it:

1. an **instruction** family (0–6), whose rows are cycles, is present when the image holds one of
   its instructions;
2. a **window** family, whose rows are memory locations — `INIT_TEARDOWN` (7), `ZERO_WINDOWS` (8),
   `PUBLIC_INPUT` (12), `PUBLIC_OUTPUT` (13), `ADVICE_WINDOWS` (14) — is always present, and
   `FIELD_WINDOWS` (18) when one of families 19–22 is, which puts the config in the recursion
   format (`VmConfig::is_recursion`), the one whose registry `VmConfig::circuit` reads for 18–22
   ([recursion.md](recursion.md) §1.1, §1.2);
3. a **delegation** family (9–11, 15–17, 19–22), whose rows are invocations, is present when the
   image declares it by a record among its file bytes (`program::declared_delegations`,
   [delegation.md](delegation.md) §7); a record naming a number no family answers is
   `UnknownDelegation`.

A height is a parameter (`ProgramParams::heights`, defaulting to
`constants::family::DEFAULT_HEIGHTS`, [circuits.md](circuits.md) §1), except the public families',
pinned at `2^12` because it places their windows ([public-values.md](public-values.md) §2). Four
things constrain it:

- the menu, `constants::family::HEIGHT_MENU`: `2^8, 2^12, 2^16, 2^18, 2^20, 2^22`
  (`HeightNotOnMenu`), even powers of two as a Mercury opening needs ([mercury.md](mercury.md) §1);
- an instruction family's code (§5);
- the window rules (`verifier_core::window_height`, `WindowRule`; [memory.md](memory.md) §3.5),
  and RAM window 0, `[0, 4·h_w)`, holding every file byte of the image (`ImageOutsideWindow`);
- the floor of the family's lookup channels, below which the registry has no circuit and no key
  can be built: `2^20` for an instruction family ([lookup.md](lookup.md) §3), its own for a
  delegation family ([delegation.md](delegation.md) §9).

`bytecode_size_words`, `2^20` (4 MiB) by default, is a declared ceiling on the words from
`RAM_ORIGIN` to the image's last file byte (`ProgramTooLarge`); no circuit reads it.

The wire form is `8k + 8` bytes; `VmConfig::from_bytes` refuses a wrong length, a family id above
22, ids not strictly ascending, a height off the menu, and what `window_height` refuses:

```text
k: u32 LE ‖ k × (family: u32 LE ‖ height: u32 LE) ‖ bytecode_size_words: u32 LE
```

In a transcript a config is one `VM_CONFIG` message, `[f_1 … f_k, h_1 … h_k, bytecode_size_words]`:
the second message of the identity (§8) and the first of a statement's descriptor
([proof.md](proof.md) §2).

## 8. Program identity

One `Fr`, `ProgramIdentity`, on the wire its canonical 32 bytes ([primitives.md](primitives.md)
§1): the raw squeeze of a fresh transcript after these messages (`verifier_core::identity_digest`;
tag values in [transcript.md](transcript.md) §5):

| # | tag | message |
| --- | --- | --- |
| 1 | `PROGRAM_IDENTITY` | `[code_version]`: `constants::family::CODE_VERSION`, 0, the only one derivation builds (`UnsupportedCodeVersion`) |
| 2 | `VM_CONFIG` | §7's |
| 3 | `PROGRAM_ENTRY` | `[entry_pc]` |
| 4 | `COMMITMENT`, one per family of the config, ascending | its setup commitments, four limbs a point ([transcript.md](transcript.md) §4) |

A family's setup commitments (`program::setup_commitments`) are Mercury commitments
([mercury.md](mercury.md) §2): of an instruction family's decoded-table columns in tuple order, 7
or 6 points; of `INIT_TEARDOWN`'s **image column** (`program::image_init_column`), row `y` being
`image.initial_word(4y)` over RAM window 0, one point; none, an empty message, for every other
family.

Committing needs the ceremony's SRS, with as many powers as the tallest table has rows
([srs.md](srs.md) §1). The digest over given points (`program::identity_from_commitments`) needs
no SRS and no curve arithmetic: a verifying key carries the lists, its load recomputes the identity
from them, and every shard opens its setup columns against the same points ([proof.md](proof.md)
§5, §7), which is what ties the tables a proof reads to the identity.

**It binds** every instruction the sweep found, with its pc, length, operands and kind, and that
no other pc holds one; every file byte of the image (`.text`, `.rodata`, `.data`, the delegation
declarations among them); the entry pc; the family set, every height, `bytecode_size_words` and
the code version. One ELF at two settings of the heights has two identities.

**It does not bind**:

- the SRS its commitments are under, or the generic lookup table: those are the SRS digest's
  ([proof.md](proof.md) §3);
- the circuits, which a key's load holds to the registry ([proof.md](proof.md) §7);
- anything an execution chooses: its input, advice, shard counts, window list;
- memory past a segment's file bytes (`.bss`, the heap and the stack): `mem_len` enters nothing,
  and such memory starts at zero whatever is declared;
- the symbol table, which `loader::function_symbols` and `loader::symbol_names` read beside the
  image for the profiler and listings, or anything else of the ELF §1 does not read.

**A verifier takes the identity from a channel the prover does not control** and compares it with
its key's; it never sees an ELF. Against a prover-supplied identity a proof shows only that some
program ran. Whoever holds the ELF, the parameters and the ceremony file recomputes it.
