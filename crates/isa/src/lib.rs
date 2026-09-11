//! The RV32IMAC instruction model: [`Instr`], and [`decode`] for 32-bit words.
//!
//! The loader expands every compressed instruction to the exact 32-bit
//! instruction it abbreviates before anything reaches this crate, so there is
//! no 16-bit decoder here and there never should be: [`decode`] refuses a word
//! whose low two bits are not `11`. RVC is an encoding, not a set of
//! instructions, and the one reading of it lives in `crates/loader`.
//!
//! # What is accepted
//!
//! Exactly the 59 RV32IMA instructions, in every encoding the ISA defines for
//! them and in no other:
//!
//! - every field that is an operand may hold any value — `x0` as a
//!   destination included, which is how RVC HINTs and `nop` arrive;
//! - every field that is fixed must hold its one value: `funct7` of the
//!   register-register and shift-immediate forms, `funct3` of `jalr`, the
//!   whole of `ecall` and `ebreak`, the `.w` width and `rs2 = 0` of `lr.w`;
//! - **`fence` is the exception, on the ISA's own instruction.** Its `rd`,
//!   `rs1` and every `fm`/`pred`/`succ` setting are either ignored or reserved
//!   with the rule "base implementations shall treat all such reserved
//!   configurations as normal fences", so every `funct3 = 000` MISC-MEM word
//!   is a fence. On one hart a fence orders nothing, which is why nothing
//!   downstream needs to tell them apart.
//!
//! Everything else — RV64-only encodings, the F and D extensions, Zicsr,
//! `fence.i`, privileged instructions, reserved `funct3`/`funct7`/`funct5`
//! values — is a [`DecodeError`] naming why. `tests/sweep.rs` counts the
//! accepted words of each major opcode across the whole 32-bit space and holds
//! the count to one derived by hand from the ISA tables.
//!
//! # Immediates
//!
//! An immediate is the **value the instruction uses**, as an `i32`: sign
//! extended for the I, S, B and J forms, the whole shifted word for the U form
//! (`lui a0, 1` has `imm = 4096`), and the shift amount for the three shift
//! immediates. B and J immediates are always even — bit 0 is not encoded — so
//! a static branch or jump target is always 2-byte aligned, which is exactly
//! the granularity RVC code needs and the pc/2 indexing of the decoded tables
//! assumes. Nothing here demands 4-byte alignment.

/// One RV32IMAC instruction: one variant per mnemonic, carrying that form's
/// fields. Register fields are indices `0..32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instr {
    // RV32I: upper immediates and jumps
    Lui {
        rd: u8,
        imm: i32,
    },
    Auipc {
        rd: u8,
        imm: i32,
    },
    Jal {
        rd: u8,
        imm: i32,
    },
    Jalr {
        rd: u8,
        rs1: u8,
        imm: i32,
    },

    // RV32I: branches
    Beq {
        rs1: u8,
        rs2: u8,
        imm: i32,
    },
    Bne {
        rs1: u8,
        rs2: u8,
        imm: i32,
    },
    Blt {
        rs1: u8,
        rs2: u8,
        imm: i32,
    },
    Bge {
        rs1: u8,
        rs2: u8,
        imm: i32,
    },
    Bltu {
        rs1: u8,
        rs2: u8,
        imm: i32,
    },
    Bgeu {
        rs1: u8,
        rs2: u8,
        imm: i32,
    },

    // RV32I: loads and stores
    Lb {
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    Lh {
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    Lw {
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    Lbu {
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    Lhu {
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    Sb {
        rs1: u8,
        rs2: u8,
        imm: i32,
    },
    Sh {
        rs1: u8,
        rs2: u8,
        imm: i32,
    },
    Sw {
        rs1: u8,
        rs2: u8,
        imm: i32,
    },

    // RV32I: register-immediate
    Addi {
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    Slti {
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    Sltiu {
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    Xori {
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    Ori {
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    Andi {
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    Slli {
        rd: u8,
        rs1: u8,
        shamt: u8,
    },
    Srli {
        rd: u8,
        rs1: u8,
        shamt: u8,
    },
    Srai {
        rd: u8,
        rs1: u8,
        shamt: u8,
    },

    // RV32I: register-register
    Add {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Sub {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Sll {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Slt {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Sltu {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Xor {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Srl {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Sra {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Or {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    And {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },

    // RV32I: memory ordering and the environment
    Fence {
        fm: u8,
        pred: u8,
        succ: u8,
    },
    Ecall,
    Ebreak,

    // M
    Mul {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Mulh {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Mulhsu {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Mulhu {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Div {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Divu {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Rem {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    Remu {
        rd: u8,
        rs1: u8,
        rs2: u8,
    },

    // A
    LrW {
        rd: u8,
        rs1: u8,
        aq: bool,
        rl: bool,
    },
    ScW {
        rd: u8,
        rs1: u8,
        rs2: u8,
        aq: bool,
        rl: bool,
    },
    AmoswapW {
        rd: u8,
        rs1: u8,
        rs2: u8,
        aq: bool,
        rl: bool,
    },
    AmoaddW {
        rd: u8,
        rs1: u8,
        rs2: u8,
        aq: bool,
        rl: bool,
    },
    AmoxorW {
        rd: u8,
        rs1: u8,
        rs2: u8,
        aq: bool,
        rl: bool,
    },
    AmoandW {
        rd: u8,
        rs1: u8,
        rs2: u8,
        aq: bool,
        rl: bool,
    },
    AmoorW {
        rd: u8,
        rs1: u8,
        rs2: u8,
        aq: bool,
        rl: bool,
    },
    AmominW {
        rd: u8,
        rs1: u8,
        rs2: u8,
        aq: bool,
        rl: bool,
    },
    AmomaxW {
        rd: u8,
        rs1: u8,
        rs2: u8,
        aq: bool,
        rl: bool,
    },
    AmominuW {
        rd: u8,
        rs1: u8,
        rs2: u8,
        aq: bool,
        rl: bool,
    },
    AmomaxuW {
        rd: u8,
        rs1: u8,
        rs2: u8,
        aq: bool,
        rl: bool,
    },
}

/// A word [`decode`] refuses, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeError {
    pub word: u32,
    pub reason: &'static str,
}

/// Decode one expanded 32-bit instruction word.
pub fn decode(word: u32) -> Result<Instr, DecodeError> {
    use Instr::*;
    let refuse = |reason| Err(DecodeError { word, reason });

    if word & 0b11 != 0b11 {
        return refuse(
            "bits 1:0 are not 11: a compressed encoding, which the loader expands first",
        );
    }

    let rd = ((word >> 7) & 0x1f) as u8;
    let rs1 = ((word >> 15) & 0x1f) as u8;
    let rs2 = ((word >> 20) & 0x1f) as u8;
    let funct3 = (word >> 12) & 0b111;
    let funct7 = word >> 25;

    // Sign-extending the immediates: each takes its top bit from bit 31, which
    // an arithmetic right shift of the whole word as `i32` carries down.
    let imm_i = (word as i32) >> 20;
    let imm_s = ((word as i32) >> 25 << 5) | ((word >> 7) & 0x1f) as i32;
    let imm_b = ((word as i32) >> 31 << 12)
        | (((word >> 7) & 1) << 11) as i32
        | (((word >> 25) & 0x3f) << 5) as i32
        | (((word >> 8) & 0xf) << 1) as i32;
    let imm_u = (word & 0xffff_f000) as i32;
    let imm_j = ((word as i32) >> 31 << 20)
        | (word & 0x000f_f000) as i32
        | (((word >> 20) & 1) << 11) as i32
        | (((word >> 21) & 0x3ff) << 1) as i32;

    match word & 0x7f {
        0x37 => Ok(Lui { rd, imm: imm_u }),
        0x17 => Ok(Auipc { rd, imm: imm_u }),
        0x6f => Ok(Jal { rd, imm: imm_j }),
        0x67 => match funct3 {
            0 => Ok(Jalr { rd, rs1, imm: imm_i }),
            _ => refuse("jalr: funct3 must be 000"),
        },
        0x63 => {
            let (rs1, rs2, imm) = (rs1, rs2, imm_b);
            match funct3 {
                0b000 => Ok(Beq { rs1, rs2, imm }),
                0b001 => Ok(Bne { rs1, rs2, imm }),
                0b100 => Ok(Blt { rs1, rs2, imm }),
                0b101 => Ok(Bge { rs1, rs2, imm }),
                0b110 => Ok(Bltu { rs1, rs2, imm }),
                0b111 => Ok(Bgeu { rs1, rs2, imm }),
                _ => refuse("branch: funct3 010 and 011 are reserved"),
            }
        }
        0x03 => {
            let imm = imm_i;
            match funct3 {
                0b000 => Ok(Lb { rd, rs1, imm }),
                0b001 => Ok(Lh { rd, rs1, imm }),
                0b010 => Ok(Lw { rd, rs1, imm }),
                0b100 => Ok(Lbu { rd, rs1, imm }),
                0b101 => Ok(Lhu { rd, rs1, imm }),
                _ => refuse("load: funct3 011 and 110 are RV64's ld and lwu, 111 is reserved"),
            }
        }
        0x23 => {
            let imm = imm_s;
            match funct3 {
                0b000 => Ok(Sb { rs1, rs2, imm }),
                0b001 => Ok(Sh { rs1, rs2, imm }),
                0b010 => Ok(Sw { rs1, rs2, imm }),
                _ => refuse("store: funct3 011 is RV64's sd, 1xx is reserved"),
            }
        }
        0x13 => {
            let imm = imm_i;
            // The shift immediates keep a funct7 in the immediate's top bits.
            // shamt[5] -- bit 25 -- is RV64's; on RV32 it is reserved.
            let shamt = rs2;
            match funct3 {
                0b000 => Ok(Addi { rd, rs1, imm }),
                0b010 => Ok(Slti { rd, rs1, imm }),
                0b011 => Ok(Sltiu { rd, rs1, imm }),
                0b100 => Ok(Xori { rd, rs1, imm }),
                0b110 => Ok(Ori { rd, rs1, imm }),
                0b111 => Ok(Andi { rd, rs1, imm }),
                0b001 => match funct7 {
                    0b000_0000 => Ok(Slli { rd, rs1, shamt }),
                    _ => refuse("slli: funct7 must be 0000000 on RV32"),
                },
                _ => match funct7 {
                    0b000_0000 => Ok(Srli { rd, rs1, shamt }),
                    0b010_0000 => Ok(Srai { rd, rs1, shamt }),
                    _ => refuse("srli/srai: funct7 must be 0000000 or 0100000 on RV32"),
                },
            }
        }
        0x33 => match (funct7, funct3) {
            (0b000_0000, 0b000) => Ok(Add { rd, rs1, rs2 }),
            (0b010_0000, 0b000) => Ok(Sub { rd, rs1, rs2 }),
            (0b000_0000, 0b001) => Ok(Sll { rd, rs1, rs2 }),
            (0b000_0000, 0b010) => Ok(Slt { rd, rs1, rs2 }),
            (0b000_0000, 0b011) => Ok(Sltu { rd, rs1, rs2 }),
            (0b000_0000, 0b100) => Ok(Xor { rd, rs1, rs2 }),
            (0b000_0000, 0b101) => Ok(Srl { rd, rs1, rs2 }),
            (0b010_0000, 0b101) => Ok(Sra { rd, rs1, rs2 }),
            (0b000_0000, 0b110) => Ok(Or { rd, rs1, rs2 }),
            (0b000_0000, 0b111) => Ok(And { rd, rs1, rs2 }),
            (0b000_0001, 0b000) => Ok(Mul { rd, rs1, rs2 }),
            (0b000_0001, 0b001) => Ok(Mulh { rd, rs1, rs2 }),
            (0b000_0001, 0b010) => Ok(Mulhsu { rd, rs1, rs2 }),
            (0b000_0001, 0b011) => Ok(Mulhu { rd, rs1, rs2 }),
            (0b000_0001, 0b100) => Ok(Div { rd, rs1, rs2 }),
            (0b000_0001, 0b101) => Ok(Divu { rd, rs1, rs2 }),
            (0b000_0001, 0b110) => Ok(Rem { rd, rs1, rs2 }),
            (0b000_0001, 0b111) => Ok(Remu { rd, rs1, rs2 }),
            _ => refuse("register-register: no RV32IM operation has this funct7 and funct3"),
        },
        0x0f => match funct3 {
            0b000 => Ok(Fence {
                fm: (word >> 28) as u8,
                pred: ((word >> 24) & 0xf) as u8,
                succ: ((word >> 20) & 0xf) as u8,
            }),
            _ => refuse("MISC-MEM: funct3 001 is fence.i (Zifencei), which RV32IMAC does not have"),
        },
        0x73 => match word {
            0x0000_0073 => Ok(Ecall),
            0x0010_0073 => Ok(Ebreak),
            _ => refuse("SYSTEM: only ecall and ebreak; Zicsr and the privileged encodings are not RV32IMAC"),
        },
        0x2f => {
            if funct3 != 0b010 {
                return refuse("AMO: funct3 must be 010, the .w width; 011 is RV64's .d");
            }
            let aq = (word >> 26) & 1 == 1;
            let rl = (word >> 25) & 1 == 1;
            match word >> 27 {
                0b00010 if rs2 == 0 => Ok(LrW { rd, rs1, aq, rl }),
                0b00010 => refuse("lr.w: rs2 must be x0"),
                0b00011 => Ok(ScW { rd, rs1, rs2, aq, rl }),
                0b00001 => Ok(AmoswapW { rd, rs1, rs2, aq, rl }),
                0b00000 => Ok(AmoaddW { rd, rs1, rs2, aq, rl }),
                0b00100 => Ok(AmoxorW { rd, rs1, rs2, aq, rl }),
                0b01100 => Ok(AmoandW { rd, rs1, rs2, aq, rl }),
                0b01000 => Ok(AmoorW { rd, rs1, rs2, aq, rl }),
                0b10000 => Ok(AmominW { rd, rs1, rs2, aq, rl }),
                0b10100 => Ok(AmomaxW { rd, rs1, rs2, aq, rl }),
                0b11000 => Ok(AmominuW { rd, rs1, rs2, aq, rl }),
                0b11100 => Ok(AmomaxuW { rd, rs1, rs2, aq, rl }),
                _ => refuse("AMO: no A-extension operation has this funct5"),
            }
        }
        _ => refuse("an opcode RV32IMAC does not have"),
    }
}

/// An instruction's fields, projected onto the names every form shares.
///
/// `None` means the form has no such field — not that it is zero. `imm` is
/// the value the instruction uses (see the crate docs); `funct3` is the
/// encoding's `funct3` bits for every form that has them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fields {
    pub rd: Option<u8>,
    pub rs1: Option<u8>,
    pub rs2: Option<u8>,
    pub imm: Option<i32>,
    pub funct3: Option<u8>,
}

impl Instr {
    /// The base mnemonic, lowercase, as the ISA manual spells it. An atomic's
    /// `aq`/`rl` suffix is not part of it; see [`Instr::aq_rl`].
    pub fn mnemonic(&self) -> &'static str {
        self.spelled().0
    }

    /// The fields this form has.
    pub fn fields(&self) -> Fields {
        self.spelled().1
    }

    /// `(aq, rl)` for the eleven atomics, `None` for everything else.
    pub fn aq_rl(&self) -> Option<(bool, bool)> {
        use Instr::*;
        match *self {
            LrW { aq, rl, .. }
            | ScW { aq, rl, .. }
            | AmoswapW { aq, rl, .. }
            | AmoaddW { aq, rl, .. }
            | AmoxorW { aq, rl, .. }
            | AmoandW { aq, rl, .. }
            | AmoorW { aq, rl, .. }
            | AmominW { aq, rl, .. }
            | AmomaxW { aq, rl, .. }
            | AmominuW { aq, rl, .. }
            | AmomaxuW { aq, rl, .. } => Some((aq, rl)),
            _ => None,
        }
    }

    /// The mnemonic and the fields, in one table. One arm per variant, so a
    /// reader checks each row against the ISA manual once.
    fn spelled(&self) -> (&'static str, Fields) {
        use Instr::*;
        // The five shapes the arms below are built from.
        let u = |rd, imm| Fields {
            rd: Some(rd),
            rs1: None,
            rs2: None,
            imm: Some(imm),
            funct3: None,
        };
        let i = |rd, rs1, imm, f3| Fields {
            rd: Some(rd),
            rs1: Some(rs1),
            rs2: None,
            imm: Some(imm),
            funct3: Some(f3),
        };
        let s = |rs1, rs2, imm, f3| Fields {
            rd: None,
            rs1: Some(rs1),
            rs2: Some(rs2),
            imm: Some(imm),
            funct3: Some(f3),
        };
        let r = |rd, rs1, rs2, f3| Fields {
            rd: Some(rd),
            rs1: Some(rs1),
            rs2: Some(rs2),
            imm: None,
            funct3: Some(f3),
        };
        let bare = |f3| Fields {
            rd: None,
            rs1: None,
            rs2: None,
            imm: None,
            funct3: Some(f3),
        };
        match *self {
            Lui { rd, imm } => ("lui", u(rd, imm)),
            Auipc { rd, imm } => ("auipc", u(rd, imm)),
            Jal { rd, imm } => ("jal", u(rd, imm)),
            Jalr { rd, rs1, imm } => ("jalr", i(rd, rs1, imm, 0b000)),

            Beq { rs1, rs2, imm } => ("beq", s(rs1, rs2, imm, 0b000)),
            Bne { rs1, rs2, imm } => ("bne", s(rs1, rs2, imm, 0b001)),
            Blt { rs1, rs2, imm } => ("blt", s(rs1, rs2, imm, 0b100)),
            Bge { rs1, rs2, imm } => ("bge", s(rs1, rs2, imm, 0b101)),
            Bltu { rs1, rs2, imm } => ("bltu", s(rs1, rs2, imm, 0b110)),
            Bgeu { rs1, rs2, imm } => ("bgeu", s(rs1, rs2, imm, 0b111)),

            Lb { rd, rs1, imm } => ("lb", i(rd, rs1, imm, 0b000)),
            Lh { rd, rs1, imm } => ("lh", i(rd, rs1, imm, 0b001)),
            Lw { rd, rs1, imm } => ("lw", i(rd, rs1, imm, 0b010)),
            Lbu { rd, rs1, imm } => ("lbu", i(rd, rs1, imm, 0b100)),
            Lhu { rd, rs1, imm } => ("lhu", i(rd, rs1, imm, 0b101)),
            Sb { rs1, rs2, imm } => ("sb", s(rs1, rs2, imm, 0b000)),
            Sh { rs1, rs2, imm } => ("sh", s(rs1, rs2, imm, 0b001)),
            Sw { rs1, rs2, imm } => ("sw", s(rs1, rs2, imm, 0b010)),

            Addi { rd, rs1, imm } => ("addi", i(rd, rs1, imm, 0b000)),
            Slti { rd, rs1, imm } => ("slti", i(rd, rs1, imm, 0b010)),
            Sltiu { rd, rs1, imm } => ("sltiu", i(rd, rs1, imm, 0b011)),
            Xori { rd, rs1, imm } => ("xori", i(rd, rs1, imm, 0b100)),
            Ori { rd, rs1, imm } => ("ori", i(rd, rs1, imm, 0b110)),
            Andi { rd, rs1, imm } => ("andi", i(rd, rs1, imm, 0b111)),
            Slli { rd, rs1, shamt } => ("slli", i(rd, rs1, shamt as i32, 0b001)),
            Srli { rd, rs1, shamt } => ("srli", i(rd, rs1, shamt as i32, 0b101)),
            Srai { rd, rs1, shamt } => ("srai", i(rd, rs1, shamt as i32, 0b101)),

            Add { rd, rs1, rs2 } => ("add", r(rd, rs1, rs2, 0b000)),
            Sub { rd, rs1, rs2 } => ("sub", r(rd, rs1, rs2, 0b000)),
            Sll { rd, rs1, rs2 } => ("sll", r(rd, rs1, rs2, 0b001)),
            Slt { rd, rs1, rs2 } => ("slt", r(rd, rs1, rs2, 0b010)),
            Sltu { rd, rs1, rs2 } => ("sltu", r(rd, rs1, rs2, 0b011)),
            Xor { rd, rs1, rs2 } => ("xor", r(rd, rs1, rs2, 0b100)),
            Srl { rd, rs1, rs2 } => ("srl", r(rd, rs1, rs2, 0b101)),
            Sra { rd, rs1, rs2 } => ("sra", r(rd, rs1, rs2, 0b101)),
            Or { rd, rs1, rs2 } => ("or", r(rd, rs1, rs2, 0b110)),
            And { rd, rs1, rs2 } => ("and", r(rd, rs1, rs2, 0b111)),

            Fence { .. } => ("fence", bare(0b000)),
            Ecall => ("ecall", bare(0b000)),
            Ebreak => ("ebreak", bare(0b000)),

            Mul { rd, rs1, rs2 } => ("mul", r(rd, rs1, rs2, 0b000)),
            Mulh { rd, rs1, rs2 } => ("mulh", r(rd, rs1, rs2, 0b001)),
            Mulhsu { rd, rs1, rs2 } => ("mulhsu", r(rd, rs1, rs2, 0b010)),
            Mulhu { rd, rs1, rs2 } => ("mulhu", r(rd, rs1, rs2, 0b011)),
            Div { rd, rs1, rs2 } => ("div", r(rd, rs1, rs2, 0b100)),
            Divu { rd, rs1, rs2 } => ("divu", r(rd, rs1, rs2, 0b101)),
            Rem { rd, rs1, rs2 } => ("rem", r(rd, rs1, rs2, 0b110)),
            Remu { rd, rs1, rs2 } => ("remu", r(rd, rs1, rs2, 0b111)),

            LrW { rd, rs1, .. } => (
                "lr.w",
                Fields {
                    rd: Some(rd),
                    rs1: Some(rs1),
                    rs2: None,
                    imm: None,
                    funct3: Some(0b010),
                },
            ),
            ScW { rd, rs1, rs2, .. } => ("sc.w", r(rd, rs1, rs2, 0b010)),
            AmoswapW { rd, rs1, rs2, .. } => ("amoswap.w", r(rd, rs1, rs2, 0b010)),
            AmoaddW { rd, rs1, rs2, .. } => ("amoadd.w", r(rd, rs1, rs2, 0b010)),
            AmoxorW { rd, rs1, rs2, .. } => ("amoxor.w", r(rd, rs1, rs2, 0b010)),
            AmoandW { rd, rs1, rs2, .. } => ("amoand.w", r(rd, rs1, rs2, 0b010)),
            AmoorW { rd, rs1, rs2, .. } => ("amoor.w", r(rd, rs1, rs2, 0b010)),
            AmominW { rd, rs1, rs2, .. } => ("amomin.w", r(rd, rs1, rs2, 0b010)),
            AmomaxW { rd, rs1, rs2, .. } => ("amomax.w", r(rd, rs1, rs2, 0b010)),
            AmominuW { rd, rs1, rs2, .. } => ("amominu.w", r(rd, rs1, rs2, 0b010)),
            AmomaxuW { rd, rs1, rs2, .. } => ("amomaxu.w", r(rd, rs1, rs2, 0b010)),
        }
    }
}
