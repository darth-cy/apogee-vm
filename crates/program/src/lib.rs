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

use constants::extra_mask::{
    add_sub_lui_auipc as alu, atomics, jump_branch_slt as jbs, mem_subword, mem_word, mul_div,
    shift_bitwise as sb, system_code,
};
use constants::{family, guest_memory, transcript_tags as tags};
use curve::G1Affine;
use field::Fr;
use isa::{decode, Instr};
use loader::{ProgramImage, Slot};
use pcs::{append_g1_list, commit};
use poly::{MultilinearPoly, PolyBacking};
use srs::Srs;
use transcript::Transcript;

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
];

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
/// The two init families claim no pc: their tables are empty, with no columns.
pub fn lookup_tuple(family: FamilyId) -> &'static [RowField] {
    use RowField::*;
    match family {
        family::ADD_SUB_LUI_AUIPC
        | family::JUMP_BRANCH_SLT
        | family::SHIFT_BITWISE
        | family::MEM_WORD
        | family::MEM_SUBWORD => &[Pc, NextPc, Rs1, Rs2, Rd, Imm, ExtraMask],
        family::MUL_DIV | family::ATOMICS => &[Pc, NextPc, Rs1, Rs2, Rd, ExtraMask],
        family::INIT_TEARDOWN | family::ZERO_WINDOWS => &[],
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
    if family != family::INIT_TEARDOWN && family != family::ZERO_WINDOWS {
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

/// The static VM shape a program derives: which families it needs, how tall
/// each family's trace is, and the bytecode ceiling it was checked against.
///
/// Per-proof shard counts are deliberately **not** here — they vary with the
/// execution, and a program's shape does not. They join it in the statement
/// descriptor; see [`absorb_statement_descriptor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmConfig {
    /// `(family, height)`, strictly ascending by family, heights on the menu.
    pub families: Vec<(FamilyId, u32)>,
    pub bytecode_size_words: u32,
}

impl VmConfig {
    /// The height of `family`, or `None` if it is detached.
    pub fn height(&self, family: FamilyId) -> Option<u32> {
        self.families
            .iter()
            .find(|(f, _)| *f == family)
            .map(|(_, h)| *h)
    }

    /// The frozen wire form: `u32` LE family count `k`, then `k` pairs of
    /// `u32` LE `(family, height)`, then `u32` LE `bytecode_size_words`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 8 * self.families.len());
        out.extend_from_slice(&(self.families.len() as u32).to_le_bytes());
        for (f, h) in &self.families {
            out.extend_from_slice(&f.to_le_bytes());
            out.extend_from_slice(&h.to_le_bytes());
        }
        out.extend_from_slice(&self.bytecode_size_words.to_le_bytes());
        out
    }

    /// Decode, refusing anything [`VmConfig::to_bytes`] could not have written
    /// from a derived config: a wrong length, an unknown or out-of-order family,
    /// a height off the menu, a family set without `INIT_TEARDOWN` or
    /// `ZERO_WINDOWS` — which derivation puts in every config — or those two
    /// at different heights. `None` rather than a panic.
    ///
    /// The two init families are required to be *present*, not last. They
    /// have the highest ids today, but `FamilyId`s are append-only and the
    /// delegation families take ids above them, so a config holding one lists
    /// it after both.
    pub fn from_bytes(bytes: &[u8]) -> Option<VmConfig> {
        let word = |i: usize| -> Option<u32> {
            Some(u32::from_le_bytes(
                bytes.get(4 * i..4 * i + 4)?.try_into().ok()?,
            ))
        };
        let k = word(0)? as usize;
        if k > family::COUNT as usize || bytes.len() != 4 * (2 * k + 2) {
            return None;
        }
        let mut families = Vec::with_capacity(k);
        for j in 0..k {
            let (f, h) = (word(1 + 2 * j)?, word(2 + 2 * j)?);
            if f >= family::COUNT || !family::HEIGHT_MENU.contains(&h) {
                return None;
            }
            if families.last().is_some_and(|(prev, _)| *prev >= f) {
                return None;
            }
            families.push((f, h));
        }
        let config = VmConfig {
            families,
            bytecode_size_words: word(1 + 2 * k)?,
        };
        window_height(&config).ok()?;
        Some(config)
    }
}

/// The one height of the two init families, or the rule a config breaks:
/// `INIT_TEARDOWN` and `ZERO_WINDOWS` both present, at one height.
/// `docs/spec/memory.md` §3.2: a `ZERO_WINDOWS` height below
/// `INIT_TEARDOWN`'s would give image words a second init row.
fn window_height(config: &VmConfig) -> Result<u32, ProgramError> {
    match (
        config.height(family::INIT_TEARDOWN),
        config.height(family::ZERO_WINDOWS),
    ) {
        (Some(init), Some(zero)) if init == zero => Ok(init),
        (Some(_), Some(_)) => Err(ProgramError::WindowRule {
            rule: "INIT_TEARDOWN and ZERO_WINDOWS have one height",
        }),
        _ => Err(ProgramError::WindowRule {
            rule: "INIT_TEARDOWN and ZERO_WINDOWS are in every VmConfig",
        }),
    }
}

/// A program's identity: one `Fr`, squeezed from the recipe in
/// [`program_identity`]. Its wire form is that element's canonical 32-byte
/// little-endian encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProgramIdentity(pub Fr);

impl ProgramIdentity {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// `None` for a non-canonical encoding; never reduces.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<ProgramIdentity> {
        Fr::from_bytes(bytes).map(ProgramIdentity)
    }
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
}

impl fmt::Display for ProgramError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ProgramError::UnsupportedCodeVersion { version } => write!(
                f,
                "code version {version} is not the one this preprocessor builds ({})",
                family::CODE_VERSION
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
    for family in FAMILIES {
        let rows = &claims[family as usize];
        let always = (family == family::INIT_TEARDOWN || family == family::ZERO_WINDOWS)
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

/// The static `VmConfig` as one typed message: the family ids ascending, then
/// their heights in the same order, then `bytecode_size_words`. Its length,
/// `2k + 1`, is what fixes `k`.
fn absorb_vm_config(tr: &mut Transcript, config: &VmConfig) {
    let mut message: Vec<Fr> = config
        .families
        .iter()
        .map(|(f, _)| Fr::from_u64(*f as u64))
        .collect();
    message.extend(config.families.iter().map(|(_, h)| Fr::from_u64(*h as u64)));
    message.push(Fr::from_u64(config.bytecode_size_words as u64));
    tr.append_scalars(tags::VM_CONFIG, &message);
}

/// The statement descriptor: the static `VmConfig`, the per-proof shard count
/// of each of its families, and the RAM window list, as three adjacent typed
/// messages.
///
/// The first is exactly the `VmConfig` message program identity absorbs; the
/// second is one count per family, in the same ascending order, under
/// `SHARD_COUNTS`. A family present in the config and run zero times has count
/// 0 — it still has a slot, so the counts line up with the families by
/// position and by nothing else. The third is `ZERO_WINDOWS`' window ids
/// `[w_1 … w_k]` under `MEMORY_WINDOWS`, empty when `k = 0`: its length varies
/// per execution exactly as the counts do. Absorbing checks nothing;
/// [`check_memory_windows`] is the rule over the same three.
/// `docs/spec/memory.md` §6.1.
pub fn absorb_statement_descriptor(
    tr: &mut Transcript,
    config: &VmConfig,
    shard_counts: &[u32],
    windows: &[u32],
) {
    assert_eq!(
        shard_counts.len(),
        config.families.len(),
        "the statement descriptor carries one shard count per family in the VmConfig"
    );
    absorb_vm_config(tr, config);
    let counts: Vec<Fr> = shard_counts
        .iter()
        .map(|c| Fr::from_u64(*c as u64))
        .collect();
    tr.append_scalars(tags::SHARD_COUNTS, &counts);
    let ids: Vec<Fr> = windows.iter().map(|w| Fr::from_u64(*w as u64)).collect();
    tr.append_scalars(tags::MEMORY_WINDOWS, &ids);
}

/// The verifier's RAM window rules over the statement, checked before the
/// memory challenges (`docs/spec/memory.md` §3.5): `INIT_TEARDOWN` and
/// `ZERO_WINDOWS` present at one height `h`; exactly one `INIT_TEARDOWN`
/// shard; one window id per `ZERO_WINDOWS` shard; the ids strictly increasing;
/// every id in `[1, 2^29 / h - 1]`. `ZERO_WINDOWS` shard `i` is window
/// `windows[i]`, so together they give every RAM word exactly one init row.
///
/// `config` is one `decode_program` derived or `VmConfig::from_bytes`
/// decoded — families strictly ascending, heights on the menu — and nothing
/// here checks that again: a hand-built config listing a family twice is
/// outside what these rules decide. `shard_counts` holds one count per family
/// of `config`, as the statement descriptor does; anything else is a caller
/// error and panics.
pub fn check_memory_windows(
    config: &VmConfig,
    shard_counts: &[u32],
    windows: &[u32],
) -> Result<(), ProgramError> {
    assert_eq!(
        shard_counts.len(),
        config.families.len(),
        "check_memory_windows: one shard count per family in the VmConfig"
    );
    let height = window_height(config)?;
    let count = |id: FamilyId| {
        let i = config.families.iter().position(|(f, _)| *f == id);
        shard_counts[i.expect("window_height found both init families")]
    };
    let broken = |rule| Err(ProgramError::WindowRule { rule });
    if count(family::INIT_TEARDOWN) != 1 {
        return broken("INIT_TEARDOWN proves exactly one shard");
    }
    if windows.len() as u64 != count(family::ZERO_WINDOWS) as u64 {
        return broken("the window list has one id per ZERO_WINDOWS shard");
    }
    if windows.windows(2).any(|pair| pair[0] >= pair[1]) {
        return broken("the window ids are strictly increasing");
    }
    let n = (1u64 << 29) / height as u64;
    if windows.iter().any(|w| *w == 0 || *w as u64 >= n) {
        return broken("every window id is in [1, 2^29 / h - 1]");
    }
    Ok(())
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
            family::ZERO_WINDOWS => Vec::new(),
            // One column at a time: at 2^22 rows an `Fr` column is 128 MiB.
            _ => (0..table.columns.len())
                .map(|c| cm(table, &table.column_poly(c)))
                .collect(),
        })
        .collect()
}

/// The identity digest over given setup commitments. It needs no SRS: this is
/// what a verifying-key loader recomputes. A fresh typed transcript absorbs,
/// in this frozen order:
///
/// 1. `PROGRAM_IDENTITY`: `code_version`, one scalar;
/// 2. `VM_CONFIG`: the family ids, their heights, `bytecode_size_words`;
/// 3. `PROGRAM_ENTRY`: `entry_pc`, one scalar;
/// 4. per family of `config`, in its order, `COMMITMENT`: that family's list
///    in `commitments`, as one message of 4-limb G1 points;
/// 5. one raw squeeze, which is the identity.
///
/// `commitments` holds one list per family of `config`; anything else is a
/// caller error and panics.
pub fn identity_from_commitments(
    code_version: u32,
    config: &VmConfig,
    entry_pc: u32,
    commitments: &[Vec<G1Affine>],
) -> ProgramIdentity {
    assert_eq!(
        commitments.len(),
        config.families.len(),
        "identity_from_commitments: one commitment list per family in the VmConfig"
    );
    let mut tr = Transcript::new();
    tr.append_scalar(tags::PROGRAM_IDENTITY, Fr::from_u64(code_version as u64));
    absorb_vm_config(&mut tr, config);
    tr.append_scalar(tags::PROGRAM_ENTRY, Fr::from_u64(entry_pc as u64));
    for points in commitments {
        append_g1_list(&mut tr, tags::COMMITMENT, points);
    }
    ProgramIdentity(tr.sample())
}
