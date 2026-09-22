//! Preprocessing: a [`ProgramImage`] in, the per-family decoded tables, the
//! [`VmConfig`] they derive, and the [`ProgramIdentity`] that commits to both,
//! to the image's words in RAM window 0 and to the entry pc.
//!
//! `crates/program/CLAUDE.md` is the design record: the table shape, the
//! extra-mask encoding, the family list with its pc-claiming rule, the digest
//! recipe and the binding argument. This file is that record in code.
//!
//! # The table, in one paragraph
//!
//! One table per family present in the program, one row per **halfword** of
//! the address space: row `i` is pc `2i`, absolute, so a row index needs no
//! base to be read. A live row holds the instruction at that pc in the fields
//! of the family's lookup tuple — a subset of [`ROW_FIELDS`], always starting
//! with `pc` and `next_pc`. Every other row is padding, and padding is
//! `Fr::MINUS_ONE` in every field: never zero, because pc 0 is a valid pc and
//! an all-zero row would be claimable. Storage is column-major, each column in
//! the narrowest backing its live values fit beside a one-bit liveness column;
//! `MINUS_ONE` appears only when a column is exported as a polynomial, which is
//! also what gets committed.

use std::fmt;

pub mod lookup_tables;
pub mod secp256k1;

use constants::extra_mask::{
    add_sub_lui_auipc as alu, atomics, jump_branch_slt as jbs, mem_subword, mem_word, mul_div,
    shift_bitwise as sb, system_code,
};
use constants::{delegation, ecall, ecrecover, family, guest_memory, keccak};
use curve::G1Affine;
use field::Fr;
use isa::{decode, Instr};
use loader::{ProgramImage, Slot};
use pcs::commit;
use poly::{MultilinearPoly, PolyBacking};
use srs::Srs;

/// A family's number: an index into `constants::family`'s table.
pub type FamilyId = u32;

// ---------------------------------------------------------------------------
// Families, row kinds and row fields
// ---------------------------------------------------------------------------

/// Every family, ascending: the canonical order.
pub const FAMILIES: [FamilyId; family::COUNT as usize] = [
    family::ADD_SUB_LUI_AUIPC,
    family::JUMP_BRANCH_SLT,
    family::SHIFT_BITWISE,
    family::MUL_DIV,
    family::MEM_WORD,
    family::MEM_SUBWORD,
    family::ATOMICS,
    family::INIT_TEARDOWN,
    family::ZERO_WINDOWS,
    family::KECCAK_F,
    family::ECRECOVER,
];

/// Every **delegation** family, with the ecall number that invokes it and the
/// width of its memory frame in 32-bit words. Ascending by family id,
/// append-only: `docs/spec/delegation.md` §3 is the table this mirrors.
///
/// This is the one place the three are tied together. An ecall number here is
/// answered by that family's circuit, the frame it dereferences is that many
/// words, and a guest declares it by linking the shim that emits the marker
/// record of §7.
pub const DELEGATIONS: [(FamilyId, u32, usize); 2] = [
    (
        family::KECCAK_F,
        ecall::PRECOMPILE_KECCAK_F,
        keccak::FRAME_WORDS,
    ),
    (
        family::ECRECOVER,
        ecall::PRECOMPILE_ECRECOVER,
        ecrecover::FRAME_WORDS,
    ),
];

/// The family that answers `number`, or `None` if it is not a delegation call.
pub fn delegation_family(number: u32) -> Option<FamilyId> {
    DELEGATIONS
        .iter()
        .find(|(_, n, _)| *n == number)
        .map(|(f, _, _)| *f)
}

/// The ecall number that invokes `family`, or `None` if it is not a delegation
/// family.
pub fn delegation_ecall(family: FamilyId) -> Option<u32> {
    DELEGATIONS
        .iter()
        .find(|(f, _, _)| *f == family)
        .map(|(_, n, _)| *n)
}

/// `family`'s memory frame in 32-bit words, or `None` if it is not a
/// delegation family.
pub fn delegation_frame_words(family: FamilyId) -> Option<usize> {
    DELEGATIONS
        .iter()
        .find(|(f, _, _)| *f == family)
        .map(|(_, _, w)| *w)
}

/// Whether `family`'s rows are cycles, and so whether it claims pcs.
///
/// The two coincide and always will: a family whose rows are cycles is one the
/// decoder routes instructions to, and a family whose rows are addresses or
/// invocations claims nothing. `constants::family::CYCLE_OWNING` is the table.
pub fn claims_pcs(family: FamilyId) -> bool {
    family::CYCLE_OWNING[family as usize]
}

/// The family's name as `constants::family` spells it.
pub fn family_name(family: FamilyId) -> &'static str {
    match family {
        family::ADD_SUB_LUI_AUIPC => "ADD_SUB_LUI_AUIPC",
        family::JUMP_BRANCH_SLT => "JUMP_BRANCH_SLT",
        family::SHIFT_BITWISE => "SHIFT_BITWISE",
        family::MUL_DIV => "MUL_DIV",
        family::MEM_WORD => "MEM_WORD",
        family::MEM_SUBWORD => "MEM_SUBWORD",
        family::ATOMICS => "ATOMICS",
        family::INIT_TEARDOWN => "INIT_TEARDOWN",
        family::ZERO_WINDOWS => "ZERO_WINDOWS",
        family::KECCAK_F => "KECCAK_F",
        family::ECRECOVER => "ECRECOVER",
        other => panic!("family {other} is not in constants::family"),
    }
}

/// The pc-claiming rule: the family that owns an instruction, and the one bit
/// of that family's `family_extra_mask` naming the row's kind.
///
/// A total function of the instruction, so a pc can be claimed by one family
/// and no other. `ecall`, `ebreak` and `fence` share the add/sub/lui/auipc
/// family's system kind, bit 0; their rows tell them apart by
/// `constants::extra_mask::system_code` in the `imm` field.
pub fn row_kind(instr: &Instr) -> (FamilyId, u32) {
    use Instr::*;
    let (alu_f, jbs_f, sb_f) = (
        family::ADD_SUB_LUI_AUIPC,
        family::JUMP_BRANCH_SLT,
        family::SHIFT_BITWISE,
    );
    let (md_f, mw_f, msw_f, at_f) = (
        family::MUL_DIV,
        family::MEM_WORD,
        family::MEM_SUBWORD,
        family::ATOMICS,
    );
    match instr {
        Ecall | Ebreak | Fence { .. } => (alu_f, alu::SYSTEM),
        Addi { .. } => (alu_f, alu::ADDI),
        Auipc { .. } => (alu_f, alu::AUIPC),
        Add { .. } => (alu_f, alu::ADD),
        Sub { .. } => (alu_f, alu::SUB),
        Lui { .. } => (alu_f, alu::LUI),

        Slti { .. } => (jbs_f, jbs::SLTI),
        Sltiu { .. } => (jbs_f, jbs::SLTIU),
        Slt { .. } => (jbs_f, jbs::SLT),
        Sltu { .. } => (jbs_f, jbs::SLTU),
        Beq { .. } => (jbs_f, jbs::BEQ),
        Bne { .. } => (jbs_f, jbs::BNE),
        Blt { .. } => (jbs_f, jbs::BLT),
        Bge { .. } => (jbs_f, jbs::BGE),
        Bltu { .. } => (jbs_f, jbs::BLTU),
        Bgeu { .. } => (jbs_f, jbs::BGEU),
        Jalr { .. } => (jbs_f, jbs::JALR),
        Jal { .. } => (jbs_f, jbs::JAL),

        Slli { .. } => (sb_f, sb::SLLI),
        Xori { .. } => (sb_f, sb::XORI),
        Srli { .. } => (sb_f, sb::SRLI),
        Srai { .. } => (sb_f, sb::SRAI),
        Ori { .. } => (sb_f, sb::ORI),
        Andi { .. } => (sb_f, sb::ANDI),
        Sll { .. } => (sb_f, sb::SLL),
        Xor { .. } => (sb_f, sb::XOR),
        Srl { .. } => (sb_f, sb::SRL),
        Sra { .. } => (sb_f, sb::SRA),
        Or { .. } => (sb_f, sb::OR),
        And { .. } => (sb_f, sb::AND),

        Mul { .. } => (md_f, mul_div::MUL),
        Mulh { .. } => (md_f, mul_div::MULH),
        Mulhsu { .. } => (md_f, mul_div::MULHSU),
        Mulhu { .. } => (md_f, mul_div::MULHU),
        Div { .. } => (md_f, mul_div::DIV),
        Divu { .. } => (md_f, mul_div::DIVU),
        Rem { .. } => (md_f, mul_div::REM),
        Remu { .. } => (md_f, mul_div::REMU),

        Lw { .. } => (mw_f, mem_word::LW),
        Sw { .. } => (mw_f, mem_word::SW),

        Lb { .. } => (msw_f, mem_subword::LB),
        Lh { .. } => (msw_f, mem_subword::LH),
        Lbu { .. } => (msw_f, mem_subword::LBU),
        Lhu { .. } => (msw_f, mem_subword::LHU),
        Sb { .. } => (msw_f, mem_subword::SB),
        Sh { .. } => (msw_f, mem_subword::SH),

        AmoaddW { .. } => (at_f, atomics::AMOADD_W),
        AmoswapW { .. } => (at_f, atomics::AMOSWAP_W),
        LrW { .. } => (at_f, atomics::LR_W),
        ScW { .. } => (at_f, atomics::SC_W),
        AmoxorW { .. } => (at_f, atomics::AMOXOR_W),
        AmoorW { .. } => (at_f, atomics::AMOOR_W),
        AmoandW { .. } => (at_f, atomics::AMOAND_W),
        AmominW { .. } => (at_f, atomics::AMOMIN_W),
        AmomaxW { .. } => (at_f, atomics::AMOMAX_W),
        AmominuW { .. } => (at_f, atomics::AMOMINU_W),
        AmomaxuW { .. } => (at_f, atomics::AMOMAXU_W),
    }
}

/// One field of a decoded-table row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RowField {
    Pc,
    NextPc,
    Rs1,
    Rs2,
    Rd,
    Imm,
    Funct3,
    ExtraMask,
}

/// The eight row fields in frozen column order. Field `k` of this list is bit
/// `k` of a family's field mask.
pub const ROW_FIELDS: [RowField; 8] = [
    RowField::Pc,
    RowField::NextPc,
    RowField::Rs1,
    RowField::Rs2,
    RowField::Rd,
    RowField::Imm,
    RowField::Funct3,
    RowField::ExtraMask,
];

/// The lookup tuple a family's circuit builds against its decoded table, in
/// frozen column order.
///
/// This is the one place a family's columns are chosen; [`field_mask`] and
/// the committed column order are both read off it. `funct3` is in no tuple:
/// the extra mask is one-hot per mnemonic, which leaves it nothing to say.
/// A family that claims no pc — the two init families, and every delegation
/// family — has an empty table with no columns.
pub fn lookup_tuple(family: FamilyId) -> &'static [RowField] {
    use RowField::*;
    match family {
        family::ADD_SUB_LUI_AUIPC
        | family::JUMP_BRANCH_SLT
        | family::SHIFT_BITWISE
        | family::MEM_WORD
        | family::MEM_SUBWORD => &[Pc, NextPc, Rs1, Rs2, Rd, Imm, ExtraMask],
        family::MUL_DIV | family::ATOMICS => &[Pc, NextPc, Rs1, Rs2, Rd, ExtraMask],
        family::INIT_TEARDOWN | family::ZERO_WINDOWS | family::KECCAK_F | family::ECRECOVER => &[],
        other => panic!("family {other} is not in constants::family"),
    }
}

/// The family's field mask: bit `k` set exactly when [`ROW_FIELDS`]`[k]` is in
/// its lookup tuple.
///
/// Derived, never chosen. Walking the frozen field list, a field the tuple
/// holds pushes `true` and one it skips pushes `false`; the assertions are
/// that the `true`s count the tuple's arity — so no field is repeated and none
/// is outside the frozen set — and that the tuple is in frozen order, so the
/// order columns are committed in is the order this mask reads.
pub fn field_mask(family: FamilyId) -> u8 {
    let tuple = lookup_tuple(family);
    let mut mask = 0u8;
    let mut pushed = 0usize;
    for (k, field) in ROW_FIELDS.iter().enumerate() {
        if tuple.contains(field) {
            mask |= 1 << k;
            pushed += 1;
        }
    }
    assert_eq!(
        pushed,
        tuple.len(),
        "{}: the field mask's true count must be the lookup tuple's arity",
        family_name(family)
    );
    assert!(
        tuple.windows(2).all(|w| w[0] < w[1]),
        "{}: a lookup tuple lists its fields in frozen column order",
        family_name(family)
    );
    if claims_pcs(family) {
        assert!(
            tuple.starts_with(&[RowField::Pc, RowField::NextPc]),
            "{}: pc and next_pc are mandatory in every instruction family",
            family_name(family)
        );
    }
    mask
}

/// The instruction at `pc` as a row: all eight fields, in frozen order.
///
/// A field the form has no use for is 0 — register `x0`, immediate 0 — and
/// only the fields of the owning family's tuple reach its table. `imm` is the
/// two's-complement `u32` of the value the instruction uses, or the system
/// code on a system row. `next_pc` is the sequential fall-through, never a
/// branch target: `pc + 2` for an instruction that is two bytes in memory,
/// `pc + 4` otherwise.
fn row_values(instr: &Instr, pc: u32, compressed: bool) -> [u32; 8] {
    let (_, kind) = row_kind(instr);
    let fields = instr.fields();
    let imm = match instr {
        Instr::Ecall => system_code::ECALL,
        Instr::Ebreak => system_code::EBREAK,
        Instr::Fence { .. } => system_code::FENCE,
        _ => fields.imm.unwrap_or(0) as u32,
    };
    [
        pc,
        pc + if compressed { 2 } else { 4 },
        fields.rs1.unwrap_or(0) as u32,
        fields.rs2.unwrap_or(0) as u32,
        fields.rd.unwrap_or(0) as u32,
        imm,
        fields.funct3.unwrap_or(0) as u32,
        1 << kind,
    ]
}

// ---------------------------------------------------------------------------
// Parameters, configuration, identity
// ---------------------------------------------------------------------------

/// Everything derivation takes besides the image.
///
/// Explicit, never inferred: identity is a function of every field here, so a
/// value that crept in from anywhere else would be a program identity nobody
/// could reproduce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramParams {
    /// The ceiling on the word span from `RAM_ORIGIN` to the last file-backed
    /// byte of the image. A larger program fails loudly.
    pub bytecode_size_words: u32,
    /// Every family's trace height, indexed by `FamilyId`. Menu values only.
    pub heights: [u32; family::COUNT as usize],
    /// The decoded-table construction's version. Only
    /// `constants::family::CODE_VERSION` is accepted: a table claiming another
    /// version, built by this code, would be a claim this code cannot keep.
    pub code_version: u32,
}

impl ProgramParams {
    /// The frozen defaults of `constants::family`.
    pub fn defaults() -> ProgramParams {
        ProgramParams {
            bytecode_size_words: family::DEFAULT_BYTECODE_SIZE_WORDS,
            heights: family::DEFAULT_HEIGHTS,
            code_version: family::CODE_VERSION,
        }
    }
}

// `VmConfig`, its wire form, `ProgramIdentity` and the statement descriptor
// moved to `crates/verifier-core` at S16, so the no_std verifier binds a
// statement with the same code the prover does. They are re-exported here, and
// every path that named them still does.
pub use verifier_core::{absorb_statement_descriptor, ProgramIdentity, VmConfig};

/// The init families' one height, or the window rule a config breaks, as a
/// `ProgramError`. `verifier_core::window_height` is the rule.
fn window_height(config: &VmConfig) -> Result<u32, ProgramError> {
    verifier_core::window_height(config).map_err(|rule| ProgramError::WindowRule { rule })
}

/// Every way derivation refuses a program. Each is loud and names what it
/// refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProgramError {
    /// `ProgramParams::code_version` is not the version this code builds.
    UnsupportedCodeVersion { version: u32 },
    /// A family's height is not on `constants::family::HEIGHT_MENU`.
    HeightNotOnMenu { family: FamilyId, height: u32 },
    /// The image spans more words than `bytecode_size_words` allows.
    ProgramTooLarge {
        words: u64,
        bytecode_size_words: u32,
    },
    /// An instruction slot no family claims: the word does not decode, or the
    /// family that owns it is detached. `reason` says which.
    NotAllOpcodesSupported {
        pc: u32,
        word: u32,
        reason: &'static str,
    },
    /// A family's table cannot hold its program: its height is not strictly
    /// greater than the row after its highest live row. `pc` is that row's pc.
    TableTooShort {
        family: FamilyId,
        pc: u32,
        height: u32,
    },
    /// The image's file-backed bytes reach past RAM window 0: `end`, one past
    /// the highest file-backed byte, is above `4 * height`, `height` being
    /// `INIT_TEARDOWN`'s. `docs/spec/memory.md` §3.4.
    ImageOutsideWindow { end: u64, height: u32 },
    /// A RAM window rule of `docs/spec/memory.md` §3.2 or §3.5 is broken;
    /// `rule` says which.
    WindowRule { rule: &'static str },
    /// The image carries a delegation declaration record naming an ecall
    /// number no delegation family answers. `addr` is the record's address.
    /// `docs/spec/delegation.md` §7.
    UnknownDelegation { addr: u32, number: u32 },
}

impl fmt::Display for ProgramError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ProgramError::UnsupportedCodeVersion { version } => write!(
                f,
                "code version {version} is not the one this preprocessor builds ({})",
                family::CODE_VERSION
            ),
            ProgramError::UnknownDelegation { addr, number } => write!(
                f,
                "the delegation record at {addr:#x} declares ecall {number:#x}, \
                 which no delegation family answers"
            ),
            ProgramError::HeightNotOnMenu { family, height } => write!(
                f,
                "{} height {height} is not on the trace-height menu {:?}",
                family_name(family),
                family::HEIGHT_MENU
            ),
            ProgramError::ProgramTooLarge {
                words,
                bytecode_size_words,
            } => write!(
                f,
                "the image spans {words} words from RAM_ORIGIN, above bytecode_size_words = \
                 {bytecode_size_words}"
            ),
            ProgramError::NotAllOpcodesSupported { pc, word, reason } => write!(
                f,
                "Not all opcodes supported: pc={pc:#010x}, word {word:#010x}: {reason}"
            ),
            ProgramError::TableTooShort { family, pc, height } => write!(
                f,
                "the {} table of height {height} cannot hold the instruction at pc={pc:#010x}: \
                 its height must exceed its last live row by at least one",
                family_name(family)
            ),
            ProgramError::ImageOutsideWindow { end, height } => write!(
                f,
                "the image's file-backed bytes end at {end:#x}, past RAM window 0, which \
                 ends at 4 * {height} = {:#x}",
                4 * height as u64
            ),
            ProgramError::WindowRule { rule } => write!(f, "RAM window rule broken: {rule}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The decoded tables
// ---------------------------------------------------------------------------

/// Every family table of one program, ascending by family, one per family in
/// its [`VmConfig`] and in the same order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedTables {
    /// The `ProgramParams::code_version` the tables were built under.
    pub code_version: u32,
    pub families: Vec<FamilyTable>,
}

impl DecodedTables {
    /// The table of `family`, or `None` if it is detached.
    pub fn family(&self, family: FamilyId) -> Option<&FamilyTable> {
        self.families.iter().find(|t| t.family == family)
    }
}

/// One family's decoded table, column-major.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FamilyTable {
    pub family: FamilyId,
    /// The row count, which is the family's `VmConfig` height.
    pub height: u32,
    /// One bit per row, as `PolyBacking::U1` of `height` entries: set on the
    /// rows holding one of this family's instructions.
    pub live: PolyBacking,
    /// The family's [`lookup_tuple`], in its order: each column in the
    /// narrowest backing its live values fit, **zero** on rows that are not
    /// live. The padding sentinel is not stored; see
    /// [`FamilyTable::column_poly`].
    pub columns: Vec<(RowField, PolyBacking)>,
}

impl FamilyTable {
    /// Whether `row` holds one of this family's instructions. A row at or above
    /// the table's height is not live: it is outside the table, and code there
    /// belongs to some taller family.
    pub fn is_live(&self, row: usize) -> bool {
        row < self.height as usize && read(&self.live, row) == 1
    }

    /// The value of column `column` at `row`, or `None` on a padding row.
    pub fn get(&self, column: usize, row: usize) -> Option<u32> {
        self.is_live(row)
            .then(|| read(&self.columns[column].1, row))
    }

    /// Column `column` as the polynomial that is committed: `height`
    /// evaluations, the stored value on a live row and `Fr::MINUS_ONE` on
    /// every other.
    pub fn column_poly(&self, column: usize) -> MultilinearPoly {
        let values = &self.columns[column].1;
        let table: Vec<Fr> = (0..self.height as usize)
            .map(|row| {
                if self.is_live(row) {
                    Fr::from_u64(read(values, row) as u64)
                } else {
                    Fr::MINUS_ONE
                }
            })
            .collect();
        MultilinearPoly::new(PolyBacking::Fr(table))
    }
}

/// Entry `i` of a small backing, as the integer it stores.
fn read(backing: &PolyBacking, i: usize) -> u32 {
    match backing {
        PolyBacking::U1(limbs, _) => ((limbs[i / 64] >> (i % 64)) & 1) as u32,
        PolyBacking::U8(v) => v[i] as u32,
        PolyBacking::U16(v) => v[i] as u32,
        PolyBacking::U32(v) => v[i],
        PolyBacking::Fr(_) => unreachable!("a decoded-table column is never Fr-backed"),
    }
}

/// `values` in the narrowest small backing that holds its largest entry.
fn narrowest(values: Vec<u32>) -> PolyBacking {
    let max = values.iter().copied().max().unwrap_or(0);
    if max <= 1 {
        let mut limbs = vec![0u64; values.len().div_ceil(64)];
        for (i, v) in values.iter().enumerate() {
            limbs[i / 64] |= (*v as u64) << (i % 64);
        }
        PolyBacking::U1(limbs, values.len())
    } else if max <= u8::MAX as u32 {
        PolyBacking::U8(values.into_iter().map(|v| v as u8).collect())
    } else if max <= u16::MAX as u32 {
        PolyBacking::U16(values.into_iter().map(|v| v as u16).collect())
    } else {
        PolyBacking::U32(values)
    }
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

/// Decode a program into its family tables, and derive its `VmConfig`.
///
/// The family set is derived, never chosen: a family is present exactly when
/// it claims at least one pc, and `INIT_TEARDOWN` and `ZERO_WINDOWS` are
/// always present. See `crates/program/CLAUDE.md` for every refusal.
///
/// `image` must satisfy `ProgramImage`'s documented invariants, which
/// `loader::load_elf` and the wire-form reader establish: an even
/// `slot_base`, every 32-bit instruction followed by its second halfword. A
/// hand-built image that breaks them is a caller error, and trips the
/// partition assertion rather than producing a table.
/// The delegation families the linked binary **declares**, ascending.
///
/// Static detachment for a delegation family, `docs/spec/delegation.md` §7.
/// A delegation family claims no pc, so the instruction sweep can never learn
/// that a program calls one: the ecall number lives in `a7` at run time, not
/// in any instruction word. What decides membership instead is a declaration
/// record the shim itself emits — `constants::delegation::MARKER_MAGIC` then
/// the declared ecall number, little-endian — placed in an allocated
/// `.rodata` section, so the linker keeps it exactly when the shim is linked.
///
/// The scan is over the image's **file-backed bytes**, at every byte offset,
/// in address order. Those bytes are already what program identity binds
/// through the image column (`docs/spec/memory.md` §6.2), so a declaration
/// cannot be altered without moving identity, and no loader change is needed
/// to carry it: a record is an ordinary run of `.rodata` bytes. The scan is
/// byte-wise and not word-wise because a `static`'s address is the linker's,
/// and a record that landed off a word boundary would be a declaration
/// silently lost.
///
/// A record naming a number no delegation family answers is
/// [`ProgramError::UnknownDelegation`] — loud, because it means the guest and
/// this preprocessor disagree about the ABI. A number declared twice is one
/// declaration; a user flag never adds or removes one.
pub fn declared_delegations(image: &ProgramImage) -> Result<Vec<FamilyId>, ProgramError> {
    let mut found: Vec<FamilyId> = Vec::new();
    let mut segments: Vec<&loader::Segment> = image
        .segments
        .iter()
        .filter(|s| !s.bytes.is_empty())
        .collect();
    segments.sort_by_key(|s| s.vaddr);
    for segment in segments {
        let bytes = &segment.bytes;
        let n = delegation::MARKER_MAGIC.len();
        for at in 0..bytes.len().saturating_sub(delegation::MARKER_BYTES - 1) {
            if bytes[at..at + n] != delegation::MARKER_MAGIC {
                continue;
            }
            let number = u32::from_le_bytes([
                bytes[at + n],
                bytes[at + n + 1],
                bytes[at + n + 2],
                bytes[at + n + 3],
            ]);
            let Some(family) = delegation_family(number) else {
                return Err(ProgramError::UnknownDelegation {
                    addr: segment.vaddr.wrapping_add(at as u32),
                    number,
                });
            };
            if !found.contains(&family) {
                found.push(family);
            }
        }
    }
    found.sort_unstable();
    Ok(found)
}

pub fn decode_program(
    image: &ProgramImage,
    params: &ProgramParams,
) -> Result<(DecodedTables, VmConfig), ProgramError> {
    decode_program_detaching(image, params, &[])
}

/// [`decode_program`], with `detached` families unavailable to claim a pc.
///
/// **A test hook, and the only way to force a detachment.** It exists to show
/// that detachment is sound: an instruction whose family is not available is
/// claimed by no family, which is the same loud failure as an instruction no
/// family knows. Production derivation detaches nothing it did not derive.
/// Detaching `INIT_TEARDOWN` or `ZERO_WINDOWS` leaves it out of the family
/// set, which is refused.
pub fn decode_program_detaching(
    image: &ProgramImage,
    params: &ProgramParams,
    detached: &[FamilyId],
) -> Result<(DecodedTables, VmConfig), ProgramError> {
    if params.code_version != family::CODE_VERSION {
        return Err(ProgramError::UnsupportedCodeVersion {
            version: params.code_version,
        });
    }
    for family in FAMILIES {
        let height = params.heights[family as usize];
        if !family::HEIGHT_MENU.contains(&height) {
            return Err(ProgramError::HeightNotOnMenu { family, height });
        }
    }

    // The bytecode ceiling: the word span from the bottom of RAM to the last
    // file-backed byte, which is what an init family enumerating image words
    // in closed form would have to cover.
    let image_end = file_bytes_end(image).unwrap_or(guest_memory::RAM_ORIGIN as u64);
    let words = image_end
        .saturating_sub(guest_memory::RAM_ORIGIN as u64)
        .div_ceil(4);
    if words > params.bytecode_size_words as u64 {
        return Err(ProgramError::ProgramTooLarge {
            words,
            bytecode_size_words: params.bytecode_size_words,
        });
    }

    // Claim every instruction slot.
    let mut claims: Vec<Vec<(usize, [u32; 8])>> = vec![Vec::new(); family::COUNT as usize];
    for (i, slot) in image.slots.iter().enumerate() {
        let Slot::Instruction { word, compressed } = *slot else {
            continue;
        };
        let pc = image.slot_base + 2 * i as u32;
        let instr = decode(word).map_err(|e| ProgramError::NotAllOpcodesSupported {
            pc,
            word,
            reason: e.reason,
        })?;
        let (family, _) = row_kind(&instr);
        if detached.contains(&family) {
            return Err(ProgramError::NotAllOpcodesSupported {
                pc,
                word,
                reason: "the family that owns this instruction is detached",
            });
        }
        claims[family as usize].push(((pc / 2) as usize, row_values(&instr, pc, compressed)));
    }

    // The family set, and one table per member.
    let mut config = VmConfig {
        families: Vec::new(),
        bytecode_size_words: params.bytecode_size_words,
    };
    let mut tables = DecodedTables {
        code_version: params.code_version,
        families: Vec::new(),
    };
    let declared = declared_delegations(image)?;
    for family in FAMILIES {
        let rows = &claims[family as usize];
        // Three presence rules, and no fourth. A family that claims a pc is
        // present because it claims one. The two init families are present in
        // every config (`docs/spec/memory.md` §3.2). A delegation family is
        // present exactly when the linked binary declares it
        // (`docs/spec/delegation.md` §7) — never because a caller asked.
        let always = (family == family::INIT_TEARDOWN
            || family == family::ZERO_WINDOWS
            || declared.contains(&family))
            && !detached.contains(&family);
        if rows.is_empty() && !always {
            continue;
        }
        let height = params.heights[family as usize];
        if let Some((last, values)) = rows.last() {
            // Slots are swept in address order, so the last claim is the
            // highest row.
            if *last as u64 + 1 >= height as u64 {
                return Err(ProgramError::TableTooShort {
                    family,
                    pc: values[0],
                    height,
                });
            }
        }
        config.families.push((family, height));
        tables.families.push(build_table(family, height, rows));
    }

    // RAM window 0, `INIT_TEARDOWN`'s, holds every file-backed byte: the image
    // column commits exactly that window, so a byte above it would read as
    // zero and move no identity. `docs/spec/memory.md` §3.4.
    let height = window_height(&config)?;
    if let Some(end) = file_bytes_end(image) {
        if end > 4 * height as u64 {
            return Err(ProgramError::ImageOutsideWindow { end, height });
        }
    }

    check_partition(image, &tables);
    Ok((tables, config))
}

/// One past the highest file-backed byte of the image, over the segments with
/// file bytes; `None` when no segment has any. A segment without — `.bss`, the
/// heap-and-stack reservation — holds no image byte, wherever it lies.
fn file_bytes_end(image: &ProgramImage) -> Option<u64> {
    image
        .segments
        .iter()
        .filter(|s| !s.bytes.is_empty())
        .map(|s| s.vaddr as u64 + s.bytes.len() as u64)
        .max()
}

/// One family's table from its claimed rows.
fn build_table(family: FamilyId, height: u32, rows: &[(usize, [u32; 8])]) -> FamilyTable {
    let height_usize = height as usize;
    let mut live = vec![0u32; height_usize];
    for (row, _) in rows {
        live[*row] = 1;
    }
    let mask = field_mask(family);
    let columns = ROW_FIELDS
        .iter()
        .enumerate()
        .filter(|(k, _)| mask & (1 << k) != 0)
        .map(|(k, field)| {
            let mut values = vec![0u32; height_usize];
            for (row, row_values) in rows {
                values[*row] = row_values[k];
            }
            (*field, narrowest(values))
        })
        .collect();
    FamilyTable {
        family,
        height,
        live: narrowest(live),
        columns,
    }
}

/// The family-partition assertion: every instruction slot is live in exactly
/// one table, and no table has a live row anywhere else.
///
/// Claiming is a function of the decoded instruction, so two families cannot
/// claim one pc by construction and a pc no family claims has already failed
/// derivation. This re-reads the finished tables rather than trusting that
/// argument, and a failure is a broken invariant of this crate, not something
/// a program can cause.
fn check_partition(image: &ProgramImage, tables: &DecodedTables) {
    let mut instructions = 0usize;
    for (i, slot) in image.slots.iter().enumerate() {
        if let Slot::Instruction { .. } = slot {
            instructions += 1;
            let row = (image.slot_base / 2) as usize + i;
            let owners: Vec<&FamilyTable> =
                tables.families.iter().filter(|t| t.is_live(row)).collect();
            assert_eq!(
                owners.len(),
                1,
                "family partition: pc={:#010x} is claimed by {} families",
                2 * row,
                owners.len()
            );
            assert_eq!(
                owners[0].get(0, row),
                Some(2 * row as u32),
                "decoded table: row {row} must hold pc {:#010x}",
                2 * row
            );
        }
    }
    let live: usize = tables
        .families
        .iter()
        .map(|t| (0..t.height as usize).filter(|r| t.is_live(*r)).count())
        .sum();
    assert_eq!(
        live, instructions,
        "family partition: the tables hold {live} live rows for {instructions} instructions"
    );
}

// ---------------------------------------------------------------------------
// Identity and the statement descriptor
// ---------------------------------------------------------------------------

/// The verifier's RAM window rules over the statement,
/// `docs/spec/memory.md` §3.5, as a `ProgramError`:
/// `verifier_core::check_memory_windows` is the rule, and its doc the
/// precondition. A breach is `WindowRule`, its `rule` naming which.
pub fn check_memory_windows(
    config: &VmConfig,
    shard_counts: &[u32],
    windows: &[u32],
) -> Result<(), ProgramError> {
    verifier_core::check_memory_windows(config, shard_counts, windows)
        .map_err(|rule| ProgramError::WindowRule { rule })
}

/// RAM window 0's initial words, the image column: row `y` is
/// `image.initial_word(4y)`, `height` rows, `height` being `INIT_TEARDOWN`'s.
/// Program identity commits it as that family's one setup column.
/// `docs/spec/memory.md` §3.4.
///
/// `U32`-backed: a word is 32 bits, and nothing narrower holds every image.
pub fn image_init_column(image: &ProgramImage, height: u32) -> MultilinearPoly {
    let words = (0..height).map(|y| image.initial_word(4 * y)).collect();
    MultilinearPoly::new(PolyBacking::U32(words))
}

/// The program's identity: its [`setup_commitments`], digested with the code
/// version, the static `VmConfig` and the entry pc by
/// [`identity_from_commitments`]. `docs/spec/memory.md` §6.2.
pub fn program_identity(
    image: &ProgramImage,
    tables: &DecodedTables,
    config: &VmConfig,
    srs: &Srs,
) -> ProgramIdentity {
    identity_from_commitments(
        tables.code_version,
        config,
        image.entry,
        &setup_commitments(image, tables, config, srs),
    )
}

/// Every family's setup commitments, one list per family of `config`, in its
/// order: an instruction family's decoded-table columns in lookup-tuple order;
/// `INIT_TEARDOWN`'s one, the [`image_init_column`] at its height;
/// `ZERO_WINDOWS`' none.
///
/// `tables` and `config` must be `image`'s derivation, and `srs` must hold as
/// many powers as the tallest table has rows; either failing is a broken
/// caller invariant and panics.
pub fn setup_commitments(
    image: &ProgramImage,
    tables: &DecodedTables,
    config: &VmConfig,
    srs: &Srs,
) -> Vec<Vec<G1Affine>> {
    assert_eq!(
        tables.families.len(),
        config.families.len(),
        "setup_commitments: the tables and the VmConfig name different family sets"
    );
    for (table, (family, height)) in tables.families.iter().zip(&config.families) {
        assert!(
            table.family == *family && table.height == *height,
            "setup_commitments: the {} table does not match the VmConfig's entry",
            family_name(table.family)
        );
    }
    let cm = |table: &FamilyTable, poly: &MultilinearPoly| {
        commit(srs, poly)
            .unwrap_or_else(|e| {
                panic!(
                    "setup_commitments: committing a {} column failed: {e:?}",
                    family_name(table.family)
                )
            })
            .0
    };
    tables
        .families
        .iter()
        .map(|table| match table.family {
            family::INIT_TEARDOWN => vec![cm(table, &image_init_column(image, table.height))],
            // `ZERO_WINDOWS` has no setup column, and a delegation family has
            // no decoded table at all: it is invoked, never decoded, so there
            // is nothing about it for identity to commit but its presence in
            // the `VM_CONFIG` message.
            family::ZERO_WINDOWS | family::KECCAK_F | family::ECRECOVER => Vec::new(),
            // One column at a time: at 2^22 rows an `Fr` column is 128 MiB.
            _ => (0..table.columns.len())
                .map(|c| cm(table, &table.column_poly(c)))
                .collect(),
        })
        .collect()
}

/// The identity digest over given setup commitments. It needs no SRS: this is
/// what a verifying-key loader recomputes, and it is
/// `verifier_core::identity_digest` over the points' canonical encodings,
/// whose doc is the frozen recipe (`docs/spec/memory.md` §6.2).
///
/// `commitments` holds one list per family of `config`; anything else is a
/// caller error and panics.
pub fn identity_from_commitments(
    code_version: u32,
    config: &VmConfig,
    entry_pc: u32,
    commitments: &[Vec<G1Affine>],
) -> ProgramIdentity {
    let encoded: Vec<Vec<[u8; 64]>> = commitments
        .iter()
        .map(|points| points.iter().map(G1Affine::to_bytes).collect())
        .collect();
    verifier_core::identity_digest(code_version, config, entry_pc, &encoded)
}
