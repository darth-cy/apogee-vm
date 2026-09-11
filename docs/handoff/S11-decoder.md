# S11 — Decoder + program identity

Branch `s11-decoder`. Status: complete. All ten acceptance items are met, one of them
(8's CI matrix) replaced by a local cross-OS run on the repository owner's instruction.
The deviations are at the end, and every one of them was put to the owner.

The design records written this stage are **`crates/program/CLAUDE.md`** — the table
shape, the family list and its claiming rule, the extra-mask encoding, the identity
recipe and the binding argument — and **`crates/isa/CLAUDE.md`**, what the decoder
accepts. This note is the frozen API, the artifacts, the numbers and the deviations.

---

## The one thing to read before anything else

**Program identity binds the instruction tables, not the data image.** `.rodata` and
`.data` reach no decoded table, so two programs identical in code and different in a
constant or a jump table have the **same identity** at S11. The stage prompt's recipe
commits the per-family decoded tables and the `VmConfig`, and nothing else; the master's
"program-image addresses bound to program identity" belongs to the init/teardown family,
which S11 puts in every `VmConfig` (height 2^20) with an **empty** table — no columns,
no live rows. Put to the owner with the alternative — committing an image column now —
and they chose the recipe as written. So init/teardown absorbs an **empty** commitment
list in the identity recipe, and the stage that builds its table fills that slot. That
is a versioning event, free before anything is registered.

**The entry pc is not bound either.** `ProgramImage.entry` reaches no table and not the
`VmConfig`, so two images differing only in `e_entry` share an identity. Setting the
PC's initial value is init/teardown's business too, and it has to be bound with the data
image. Until both are, identity is not a full program identity, and nothing downstream
should treat it as one.

---

## Frozen public API, as built

```rust
// crates/isa/src/lib.rs   (std, no dependencies)
pub enum Instr { /* 59 variants, one per RV32IMA mnemonic, carrying that form's fields */ }
pub struct DecodeError { pub word: u32, pub reason: &'static str }
pub fn decode(word: u32) -> Result<Instr, DecodeError>;
pub struct Fields { pub rd: Option<u8>, pub rs1: Option<u8>, pub rs2: Option<u8>,
                    pub imm: Option<i32>, pub funct3: Option<u8> }
impl Instr {
    pub fn mnemonic(&self) -> &'static str;
    pub fn fields(&self) -> Fields;
    pub fn aq_rl(&self) -> Option<(bool, bool)>;
}
```

```rust
// crates/program/src/lib.rs   (std)
pub type FamilyId = u32;
pub const FAMILIES: [FamilyId; 8];
pub fn family_name(family: FamilyId) -> &'static str;
pub fn row_kind(instr: &Instr) -> (FamilyId, u32);          // the claiming rule + mask bit
pub enum RowField { Pc, NextPc, Rs1, Rs2, Rd, Imm, Funct3, ExtraMask }
pub const ROW_FIELDS: [RowField; 8];
pub fn lookup_tuple(family: FamilyId) -> &'static [RowField];
pub fn field_mask(family: FamilyId) -> u8;

pub struct ProgramParams { pub bytecode_size_words: u32, pub heights: [u32; 8], pub code_version: u32 }
impl ProgramParams { pub fn defaults() -> ProgramParams; }
pub struct VmConfig { pub families: Vec<(FamilyId, u32)>, pub bytecode_size_words: u32 }
impl VmConfig {
    pub fn height(&self, family: FamilyId) -> Option<u32>;
    pub fn to_bytes(&self) -> Vec<u8>;
    pub fn from_bytes(bytes: &[u8]) -> Option<VmConfig>;
}
pub struct DecodedTables { pub code_version: u32, pub families: Vec<FamilyTable> }
impl DecodedTables { pub fn family(&self, family: FamilyId) -> Option<&FamilyTable>; }
pub struct FamilyTable { pub family: FamilyId, pub height: u32, pub live: PolyBacking,
                         pub columns: Vec<(RowField, PolyBacking)> }
impl FamilyTable {
    pub fn is_live(&self, row: usize) -> bool;
    pub fn get(&self, column: usize, row: usize) -> Option<u32>;
    pub fn column_poly(&self, column: usize) -> MultilinearPoly;   // the export
}
pub struct ProgramIdentity(pub Fr);
impl ProgramIdentity {
    pub fn to_bytes(&self) -> [u8; 32];
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<ProgramIdentity>;
}
pub enum ProgramError {
    UnsupportedCodeVersion { version: u32 },
    HeightNotOnMenu { family: FamilyId, height: u32 },
    ProgramTooLarge { words: u64, bytecode_size_words: u32 },
    NotAllOpcodesSupported { pc: u32, word: u32, reason: &'static str },
    TableTooShort { family: FamilyId, pc: u32, height: u32 },
}   // + Display

pub fn decode_program(image: &ProgramImage, params: &ProgramParams)
    -> Result<(DecodedTables, VmConfig), ProgramError>;
pub fn decode_program_detaching(image: &ProgramImage, params: &ProgramParams,
    detached: &[FamilyId]) -> Result<(DecodedTables, VmConfig), ProgramError>;   // test hook
pub fn program_identity(tables: &DecodedTables, config: &VmConfig, srs: &Srs) -> ProgramIdentity;
pub fn absorb_statement_descriptor(tr: &mut Transcript, config: &VmConfig, shard_counts: &[u32]);
```

```rust
// crates/constants/src/lib.rs   (additions; still zero logic, #![no_std])
pub mod transcript_tags {
    pub const PROGRAM_IDENTITY: u64 = 22;   // scalars
    pub const VM_CONFIG: u64 = 23;          // scalars
    pub const SHARD_COUNTS: u64 = 24;       // scalars
}
pub mod family {       // append-only
    pub const ADD_SUB_LUI_AUIPC: u32 = 0;  pub const JUMP_BRANCH_SLT: u32 = 1;
    pub const SHIFT_BITWISE: u32 = 2;      pub const MUL_DIV: u32 = 3;
    pub const MEM_WORD: u32 = 4;           pub const MEM_SUBWORD: u32 = 5;
    pub const ATOMICS: u32 = 6;            pub const INIT_TEARDOWN: u32 = 7;
    pub const COUNT: u32 = 8;
    pub const HEIGHT_MENU: [u32; 4];                      // 2^16, 2^18, 2^20, 2^22
    pub const DEFAULT_HEIGHTS: [u32; 8];                  // by FamilyId
    pub const DEFAULT_BYTECODE_SIZE_WORDS: u32 = 1 << 20;
    pub const CODE_VERSION: u32 = 0;
}
pub mod extra_mask { /* one module per family of bit positions, plus system_code */ }
```

```
cargo run --release -p artifact-dump -- tables <guest.elf> [--ptau <ppot_0080_24.ptau>]
```

## What this freezes for every later stage

1. **`Instr` and `decode`.** Exactly the 59 RV32IMA instructions; fixed fields must hold
   their values; `fence` accepts every `funct3 = 000` word, as the ISA says. An
   immediate is the value the instruction uses.
2. **The family list and the claiming rule.** Eight `FamilyId`s, append-only; `row_kind`
   maps every instruction to exactly one family. **ECALL, EBREAK and FENCE belong to
   add/sub/lui/auipc as its bit-0 system row kind**, told apart by `imm` 0, 1, 2.
3. **The table.** One per family present, one row per halfword with row `i` at pc `2i`,
   exactly the family's height, strictly taller than the last live row, `MINUS_ONE` in
   every field of every row that is not a live instruction of that family. Fields in the
   frozen order `pc next_pc rs1 rs2 rd imm funct3 extra_mask`; per-family lookup tuples
   and the masks derived from them (`0b1011_1111` for five families, `0b1001_1111` for
   mul/div and atomics, `0` for init/teardown); `column_poly` is the export.
4. **`family_extra_mask`**: one-hot per mnemonic, bits in `constants::extra_mask`,
   append-only. No family keeps `funct3`.
5. **`VmConfig`**, its fields and its wire form: `u32` LE count, `(family, height)`
   pairs, `bytecode_size_words`. Shard counts are not in it.
6. **`ProgramParams::defaults()`**: heights 2^22 for families 0, 1, 2, 4, 5; 2^20 for
   mul/div and init/teardown; 2^16 for atomics; `bytecode_size_words = 2^20`; code
   version 0.
7. **The identity recipe**: `PROGRAM_IDENTITY` code version, `VM_CONFIG`, one
   `COMMITMENT` list per family ascending (empty for init/teardown), one raw squeeze;
   wire form 32 bytes canonical LE.
8. **The statement descriptor**: the `VM_CONFIG` message then the `SHARD_COUNTS`
   message, adjacent. `docs/GLOSSARY.md` carries the note.

## Artifacts

| Path | What |
| --- | --- |
| `crates/isa/tests/vectors/isa_corpus.elf` | 302 hand-encoded words: every RV32IMA mnemonic, register-file ends, `x0`, boundary immediates |
| `crates/isa/tests/vectors/isa_corpus.objdump.txt` | llvm-objdump's reading of it — the acceptance-1 oracle for the whole ISA |
| `crates/isa/tests/vectors/isa_negative.txt` | 49 words that must not decode, each with format and reason |
| `crates/program/tests/vectors/mul_free.elf` | a hand-encoded program with no M and no A |
| `crates/program/tests/vectors/identity.txt` | fib's identity at the defaults and at all-2^16, over the ceremony it names |
| `crates/loader/tests/vectors/atomics.elf` | `guests/atomics`: every A-extension instruction as the compiler emits it |
| `guests/atomics/` | the guest; runs under QEMU (`tests/qemu.rs::atomics_computes_its_cells`) |
| `tools/kat-gen/src/{isa,program}.rs` | the two new generator groups |
| `tools/artifact-dump/src/tables.rs` | the `tables` subcommand |

Pins: `crates/isa/tests/common/mod.rs`, `crates/program/tests/common/mod.rs`, and
`atomics.elf` in `crates/loader/tests/common/mod.rs`. CI regenerates and diffs both new
vector directories; `identity.txt` needs the ceremony file, so CI's kat-gen run skips it
and says so, as it does the `srs` group.

## Acceptance

| # | Item | Where | Result |
| --- | --- | --- | --- |
| 1 | decode vs `objdump -d`, the S10 corpus + a per-opcode list | `isa/tests/objdump.rs` | every instruction of `fib`, `rvc-dense`, `amm` (compressed ones through the loader's expansion) and all 302 corpus words: our decode, rendered in LLVM's syntax, equals the disassembler's text; 59 mnemonics counted from both sides |
| 2 | malformed / reserved words refused | `isa/tests/negative.rs` | 49 words, a near miss for every format with a fixed field, each checked to be one field from an instruction |
| 3 | fib's partition | `program/tests/partition.rs` | claimed-pc union equals the instruction slots, each claimed once — over all seven guests |
| 4 | `amoadd.w` under detached atomics | `partition.rs` | fails naming the first atomic's pc: `Not all opcodes supported: pc=…` |
| 5 | static detachment per fixture | `partition.rs` | fib: no atomics; `guests/atomics`: atomics; `mul_free.elf`: no mul/div |
| 6 | padding scan | `program/tests/tables.rs` | every exported column of every table of every guest scanned; RVC mid-instruction slots counted |
| 7 | `next_pc` | `tables.rs` | `pc + 2` or `pc + 4` against the loader's halfword map, both lengths exercised in every guest |
| 8 | identity determinism | `program/tests/identity.rs` (`#[ignore]`) | twice in-process, across process runs, against the pin, from two fresh source builds, and in a Linux container — see below |
| 9 | identity sensitivity | `identity.rs` (`#[ignore]`) | an instruction word, `bytecode_size_words`, one family removed, one height: each moves it |
| 10 | the print tool on any ELF | `artifact-dump/tests/tables.rs` | every guest and a hand-built ELF render; the listing is parsed back against the tables; loader and decoder errors are named |

## Measured

**fib's tables**, at the defaults — live rows / height:

| Family | Live | Height |
| --- | ---: | ---: |
| ADD_SUB_LUI_AUIPC | 820 | 4,194,304 |
| JUMP_BRANCH_SLT | 404 | 4,194,304 |
| SHIFT_BITWISE | 177 | 4,194,304 |
| MUL_DIV | 9 | 1,048,576 |
| MEM_WORD | 693 | 4,194,304 |
| MEM_SUBWORD | 83 | 4,194,304 |
| INIT_TEARDOWN | 0 (empty table, no columns) | 1,048,576 |

2,186 instructions, 789 of them four bytes long; the committed columns are 7 + 7 + 7 + 6
+ 7 + 7 = 41 Mercury commitments, 35 of them at 2^22.

**fib's identity** over PSE contribution 80:

```
default   c57dbf1f2e442210f621e3a0ba3d3c9eeabe81d8b717bcfcb585c9531862151a
smallest  a64bc9f51f45aec0c76417435f3f9f39874226eaffd0ed5b4c3d23a995238e07
```

The default-parameter identity takes about 25 s in release on the Apple M5 Pro (the
whole ignored suite, which computes it twice, is 69 s): 35 general `Fr` MSMs at 2^22,
because a `MINUS_ONE`-padded column is never a small-integer column. Optimising that is
possible — a padded column is its zero-padded small column minus the commitment of the
non-live indicator — and deliberately not done: nothing needs identity to be fast, and
anti-goal 11 wants a real-workload benchmark first.

**Cross-OS**, the first result, in place of the CI matrix (deviation 2). On 2026-09-10
the ignored identity suite ran on two operating systems against the same ceremony file:

| Host | Toolchain | Identity suite | fib, defaults |
| --- | --- | --- | --- |
| macOS 26.6.2, Apple M5 Pro (arm64) | rustc 1.96.1 aarch64-apple-darwin | 5 passed | `c57dbf1f…151a` |
| Linux 6.8 in a container on the same machine (aarch64) | rustc 1.96.1 aarch64-unknown-linux-gnu | 5 passed | `c57dbf1f…151a` |

Byte-identical, and equal to the committed pin. Each run is also a separate process
reproducing the pin, which is acceptance 8's "two local process runs". Inside the
container fib rebuilt from source is **not** byte-identical to the committed fixture —
rustc embeds absolute paths, which differ there — and the test says so and compares the
container's two clean rebuilds with each other, which agree; on macOS the rebuild *is*
the fixture and reproduces the pinned identity. Both hosts are arm64; no x86 host has
run the suite, so this is cross-OS and cross-libc, not cross-architecture. The QEMU
suite ran in the same container, eight of eight in both profiles, `atomics` included —
twice, the second time after the review's changes to that guest.

CI on the draft pull request, `ubuntu-latest` (x86_64), passed in 5m39s: fmt, clippy,
the workspace suite, the QEMU suite in both profiles and the fixture regenerate-and-diff,
with the identity pin skipped as designed. It runs no identity test.

## Verification performed

**438 workspace tests, all green, plus 15 `#[ignore]`d** (400 and 8 at S10). The 38
new: 9 in `crates/isa`, 24 in `crates/program`, 5 in `tools/artifact-dump`. The 7 new
ignored: `atomics_computes_its_cells` under QEMU, the five identity tests and the
tool's identity line, all run and green as recorded above. `fmt` and
`clippy -D warnings` are clean across all four workspaces; the only `#[allow]`s added
are the `dead_code` ones on the two new `tests/common` modules, as every earlier suite's
shared test module has.
`cargo run -p kat-gen` then `git diff` over every vector directory is clean, and the new
fixtures regenerate to their pinned digests.

- **The whole 32-bit space.** `isa/tests/sweep.rs` decodes all 2^30 words with low bits
  `11`: the accepted count of each of the 32 major opcodes equals a count derived by hand
  from the ISA tables, and every accepted word round-trips through an encoder transcribed
  in the test from the same tables. Both passed on the first run.
- **The decoder against LLVM, first run clean.** The objdump differential passed on its
  first execution over 12,691 guest instructions and the 302-word corpus. The one
  disagreement is designed and recorded: llvm-objdump prints `<unknown>` for a fence
  with a nonzero `rs1` or an unknown `fm`, which the ISA says to accept; no corpus holds
  one.
- **Every guest at both profiles, once, after the PR opened.** The committed listings
  cover `fib`, `rvc-dense` and `amm` (S10's choice, kept); asked whether every guest
  decodes, a one-off harness ran a fresh `llvm-objdump` over all seven committed ELFs
  and all seven `--release` builds and put each through the same differential, plus
  `decode_program` at the defaults. All fourteen: 91,519 instructions, every one
  decoded and rendered equal to the disassembler, every instruction slot compared,
  every listing line accounted for (the only lines skipped are the 33 `c.unimp`
  halfwords the loader records as not code), no `<unknown>`, and every build derives.
  Not committed: the release ELFs are not fixtures, and four more listings would be
  about 1.9 MB of the evidence the three already give.
- **`guests/atomics` is real compiler output for the whole A extension**: all eleven
  instructions in every `aq`/`rl` combination rustc emits, `lr.w`/`sc.w` loops and six
  fences, run under QEMU in both profiles. Its nine committed words observe both halves
  of every AMO: the cell each one writes, and — folded in order into the ninth — the old
  value each one returns in `rd`.
- **Every existing guest ELF regenerated byte-identically** on this machine when
  `kat-gen -- guests` rebuilt all seven, so adding `atomics` moved no S10 fixture.

## Adversarial review

Five lenses over the finished branch:
- an independent re-derivation of the ISA;
- a malicious prover against `crates/program`;
- a stage-and-master compliance audit;
- a fixtures and tooling audit;
- a 29-mutant sweep in an isolated worktree.

Every finding of medium severity or above then went to a skeptic told to refute it, 13
agents in all. **Seven survived refutation, one was refuted, and 29 were raised at low
severity.** All seven, and most of the lows, are acted on in this branch.

The ISA lens found **no defect in `decode`**. Its own decoder, written in Python from the
ISA text, agreed with this one on all 2^30 words with low bits `11`, word for word and
field for field, and on the 3·2^30 others, all refused.

**The one that mattered: a panic out of preprocessing.** `FamilyTable::is_live` read the
liveness bitset with no bound, and `check_partition` asks every table about every
instruction's row. So code at or above a *shorter* family's height indexed past the end
of that table. At the defaults this meant any program with an instruction at pc
`0x200000` or higher, since init/teardown has 2^20 rows, and any atomics program with
code above `0x20000`. A valid program crashed derivation instead of producing tables, and
`artifact-dump tables` had the same read. Two lenses found it independently, and both
skeptics reproduced it. The fix makes a row outside a table not live, which is what the
table model already said it was, with regressions for both shapes.

The rest:
- **The entry pc is not bound either**, while the documentation named only
  `.rodata`/`.data` as unbound. One skeptic confirmed it as a documentation gap; another
  refuted it as a code defect, since the stage recipe fixes what identity absorbs. Both
  are right: the recipe is unchanged, and the gap is now stated everywhere the data image
  is.
- **`guests/atomics` could not observe `amominu.w`.** Its minimum was 0 from the first
  round, and it folded into a cell that was already negative. The minimum is now offset
  and folded into `SUM`, which is one-to-one in the value. A ninth committed word folds
  every value an atomic returns, so the `rd` half of every AMO is checked too.
- **Four test gaps, found by surviving mutants.**
  - The export was never compared with the stored columns in CI.
  - The frozen mnemonic-to-bit assignment was checked only against `row_kind` itself, so
    an ADD/SUB swap survived. It is now pinned by a numeric 59-row table, which also pins
    the system codes.
  - `TableTooShort` was tested only on one-instruction images, so checking the first
    claim instead of the last survived.
  - The height-menu check was exercised on one family only.
- **Lows acted on:**
  - the sweep checks each immediate's canonical range, since a U immediate with stray low
    bits would have passed the masked round trip;
  - `VmConfig::from_bytes` refuses a config without init/teardown;
  - an eight-family round trip;
  - `narrowest` at each width boundary;
  - the partition assertion also checks every live row's `pc` column;
  - the MISC-MEM refusal reason;
  - three negative-corpus reasons that called ratified extensions' encodings (Zicbom,
    Zacas, Zabha) "nothing";
  - the tool's VmConfig section, parsed back;
  - `atomics` in `dump.rs`;
  - the manual's `tables` section;
  - every wrong number and stale sentence in the docs (302 corpus words, not 323; 35
    commitments at 2^22, not 36).
- **Not acted on, and why.** Three mutants are equivalent: the `field_mask` arity
  assertion, `check_partition`'s count, and `decode`'s compressed-shape guard. No input
  can kill them. Three recipe properties are covered only by the `#[ignore]`d identity
  suite: the code version being absorbed, the empty init/teardown message, and the
  tables/config consistency assertion. Reaching them needs an SRS, and the owner's
  instruction keeps the ceremony out of CI.

**The fixes, re-checked by mutation.** In a fresh worktree of the fix commit, ten single
edits were applied one at a time against the CI-run suites (`isa` and `program`, no
ignored tests):
- the seven earlier survivors that are not equivalent: the export reading column 0, ADD
  and SUB swapped, ECALL and EBREAK codes swapped, `TableTooShort` on the first claim,
  the height check over four families only, `from_bytes` refusing eight families, and
  `narrowest`'s `u8` boundary off by one;
- `is_live`'s new bound removed;
- the init/teardown check deleted from `from_bytes`;
- a U immediate that keeps stray low bits.

**All ten are killed**, each by a named test, and a reworded-comment control survives.
The U-immediate mutant is killed only by the sweep's new range check: the objdump
differential cannot see it, because it prints the immediate shifted right by 12.

## Deviations and notes for the reviewer

1. **Identity binds the instruction tables only.** The owner's decision; see the top.
2. **No CI cross-OS matrix; the identity tests are `#[ignore]`d and local.** Identity
   needs the 2^22 ceremony SRS, which CI does not have. Put to the owner with a toy-SRS
   matrix as the alternative; their instruction was to ignore these tests in CI and run
   them locally when the `.ptau` file is present. Acceptance 8's "committing the passing
   matrix config" is therefore not delivered. What replaces it: the suite was run on
   macOS (arm64) and in a Linux container (see *Cross-OS*), and both reproduce the
   committed value.
3. **One-hot per mnemonic, and no family keeps `funct3`.** The owner's choice between
   this and a funct3-plus-kind-bits encoding. `funct3` stays a row field, unused.
4. **The atomics fixture is a real guest; the mul-free fixture is synthetic.** Every
   compiled guest multiplies — the SDK's panic formatter reaches `mul` and `divu` — so no
   compiled mul-free program exists; `mul_free.elf` is hand-encoded. The owner chose a
   real `guests/atomics` over a synthetic one.
5. **Acceptance 1 runs over the three committed listings plus the ISA corpus**, not over
   `echo`, `orderbook` and `vault`, which S10 left unlisted. S10's open question —
   commit listings or generate them at test time — is answered by adding no new guest
   listing: the corpus covers every mnemonic, and all seven guests still go through the
   decoder in `program`'s suites.
6. **`decode` returns `Result`.** The prompt writes `-> Instr` "roughly" and asks for
   error types; acceptance 2 needs the error.
7. **Rows are absolute pc/2**, as the prompt says, so the first 32,768 rows of every table
   (pc below `RAM_ORIGIN`) are always padding, and the 2^16 atomics default reaches atomics
   at or below pc `0x1fffc` only. Code above a shorter family's table is simply outside
   it. Every committed guest's code ends below `0x1c938`.
8. **"Strictly greater than the program's live rows"** is read as: the height exceeds the
   last live row's index plus one, so a table always has a padding row above its code.
   `TableTooShort` is tested at exactly that boundary.
9. **`bytecode_size_words` measures the word span from `RAM_ORIGIN` to the last
   file-backed byte** — what an init family enumerating the image in closed form would
   cover. The prompt fixes the ceiling, not the measure; this was stated to the owner
   with the identity-scope question.
10. **System instructions carry a code in `imm`**: 0 ecall, 1 ebreak, 2 fence. With one
    system bit, as the prompt pins, something has to tell the three apart; the first two
    are their own `funct12`. A fence's `pred`/`succ`/`fm` are not recorded.
11. **Init/teardown's table is empty** — no columns, no live rows — and it is in every
    `VmConfig`. "`pc` and `next_pc` are mandatory in every family" is enforced for the
    seven instruction families; init/teardown claims no pc.
12. **The code version is its own constant**, `constants::family::CODE_VERSION = 0`,
    not `PROTOCOL_VERSION`: a protocol change that leaves the tables alone should not
    re-register every program. Derivation refuses any other version.
13. **The print tool is `artifact-dump tables`**, a subcommand of the existing tool, as
    the prompt's "CLI/tool subcommand" reads; the S10 report remains mnemonic-free.
14. **"Jump/branch target alignment is validated at 2-byte granularity"** is met by
    construction and by test rather than by a preprocessing check: B and J immediates
    are even by encoding, nothing demands 4-byte alignment, and a static target landing
    off an instruction is not refused, because `guests/rvc-dense` deliberately carries
    never-executed jumps whose `.+N` targets land anywhere.
15. **`ProgramIdentity` is the digest alone.** The per-column commitments are computed
    and absorbed but not returned; the stage that builds a verifying key will want them,
    and is free to expose them then.
16. **No `PROTOCOL_VERSION` bump.** It stays 0: S11 fills in placeholders rather than
    changing a released protocol.

## Open for the next stage

- **Bind the data image and the entry pc.** Init/teardown's table, its columns
  committed in the identity's init/teardown slot — which is already in the recipe,
  absorbing an empty list — and the PC's initial value with them.
- **The verifying key** needs the per-column commitments `program_identity` computes
  and does not return, and a recomputation check against a registered identity.
- **The SRS digest is still absent** (`docs/spec/srs.md` §4), and identity is taken over
  a presumed SRS; `identity.txt` records which ceremony by its `[x]_1`.
- **Delegation families take ids 8 and up, above init/teardown.** `VmConfig::from_bytes`
  requires init/teardown to be *present*, not last, so a config holding one parses.
  Two more places read "not init/teardown" as "claims pcs", and the delegation stage
  must revisit both: `field_mask` exempts only init/teardown from the mandatory
  `pc, next_pc` prefix, and `decode_program` puts a family in the config only if it
  claims a pc (init/teardown always). A delegation family claims no pc (its call is an
  `ecall` row in family 0), and which precompile runs is the run-time value of `a7`,
  so static detachment cannot see it. That stage must give delegation families a
  presence rule of their own. A program that uses no delegation family keeps its
  identity: the `VM_CONFIG` message lists only the families present.
- **`transcript_tags` has 24 entries.** Append, never renumber, never reuse across kinds;
  the same rule now covers `constants::family` and `constants::extra_mask`.
