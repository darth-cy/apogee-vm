//! RV32C expansion: every 16-bit encoding to the exact 32-bit instruction it
//! abbreviates.
//!
//! The C extension is *purely an encoding*. Every valid compressed form is one
//! existing 32-bit instruction and there is no compressed-only semantics, so
//! this file changes representation and nothing else. It is soundness-critical
//! for exactly that reason: a wrong expansion is a valid proof of a different
//! program.
//!
//! # What is accepted
//!
//! The base C extension in its **RV32 flavor**, and nothing else. Everything
//! below is a loud error, never a silently-passed word:
//!
//! - the floating-point forms (`c.fld`, `c.flw`, `c.fsd`, `c.fsw`, and their
//!   `sp` variants) — the F and D extensions are not in RV32IMAC;
//! - the RV64-only forms (`c.addw`, `c.subw`, and any shift with `shamt[5]`
//!   set, which on RV32 is a reserved encoding rather than a 64-bit shift);
//! - the reserved code points (`c.addi4spn` with `nzuimm = 0`, `c.addi16sp`
//!   and `c.lui` with `nzimm = 0`, `c.lwsp` with `rd = x0`, `c.jr` with
//!   `rs1 = x0`, the all-zero halfword);
//! - the `Zc*` extensions, which reuse the reserved slots this file rejects:
//!   `Zcb` sits in quadrant 0 `funct3 = 100`, `Zcmp`/`Zcmt` in quadrant 2
//!   `funct3 = 101`.
//!
//! **HINTs are expanded, not rejected.** `c.addi x0, imm`, `c.li x0, imm`,
//! `c.slli x0, shamt`, `c.mv x0, rs2` and friends are valid instructions whose
//! 32-bit forms write `x0` and therefore do nothing. Expanding them is the
//! representation-preserving answer; rejecting them would reject programs a
//! conforming assembler may emit.
//!
//! # Reading the immediate helpers
//!
//! Each one lists the spec's bit assignment and then builds the value with one
//! shift-and-mask per field. `(c >> a) & m` and `(c << a) & m` are the same
//! operation written two ways: a field moving down, and a field moving up.
//! They are deliberately written out rather than driven by a table, so each
//! line diffs against the RISC-V spec's own "RVC instruction formats" figure by
//! eye.

// Base opcodes, from the RISC-V unprivileged spec's opcode map.
const OP_IMM: u32 = 0b001_0011;
const OP: u32 = 0b011_0011;
const LOAD: u32 = 0b000_0011;
const STORE: u32 = 0b010_0011;
const BRANCH: u32 = 0b110_0011;
const JAL: u32 = 0b110_1111;
const JALR: u32 = 0b110_0111;
const LUI: u32 = 0b011_0111;

/// `ebreak`: the one instruction with no fields to build.
const EBREAK: u32 = 0x0010_0073;

/// Expand one compressed halfword.
///
/// `Err` carries the reason, which the caller pairs with the offending pc.
pub fn expand(c: u16) -> Result<u32, &'static str> {
    let c = c as u32;

    // The all-zero halfword is defined illegal, and is also the shape that
    // uninitialised memory and section padding take. It falls into
    // `c.addi4spn`'s reserved case below, but a program that desyncs into data
    // hits it constantly, so it gets its own message.
    if c == 0 {
        return Err("the all-zero halfword is a defined-illegal encoding");
    }

    let funct3 = (c >> 13) & 0b111;
    // The 5-bit register fields, at their two fixed positions.
    let rd_rs1 = (c >> 7) & 0b1_1111;
    let rs2 = (c >> 2) & 0b1_1111;
    // The 3-bit register fields, which name x8..x15 only. The spec calls the
    // one at bits 9:7 `rs1'/rd'` and the one at bits 4:2 `rs2'/rd'`, so they
    // are named by position rather than by a role that changes per instruction.
    let rp_hi = 8 + ((c >> 7) & 0b111);
    let rp_lo = 8 + ((c >> 2) & 0b111);

    match c & 0b11 {
        // -------------------------------------------------------------------
        // Quadrant 0
        // -------------------------------------------------------------------
        0b00 => match funct3 {
            0b000 => {
                let nzuimm = ciw_imm(c);
                if nzuimm == 0 {
                    return Err("c.addi4spn with nzuimm = 0 is a reserved encoding");
                }
                // c.addi4spn rd', nzuimm  ->  addi rd', x2, nzuimm
                Ok(i_type(nzuimm as i32, 2, 0b000, rp_lo, OP_IMM))
            }
            0b001 => Err("c.fld: the D extension is not in RV32IMAC"),
            // c.lw rd', uimm(rs1')  ->  lw rd', uimm(rs1')
            0b010 => Ok(i_type(cl_cs_imm(c) as i32, rp_hi, 0b010, rp_lo, LOAD)),
            0b011 => Err("c.flw: the F extension is not in RV32IMAC"),
            0b100 => Err("quadrant 0 funct3 = 100 is reserved (the Zcb encoding space)"),
            0b101 => Err("c.fsd: the D extension is not in RV32IMAC"),
            // c.sw rs2', uimm(rs1')  ->  sw rs2', uimm(rs1')
            0b110 => Ok(s_type(cl_cs_imm(c) as i32, rp_lo, rp_hi, 0b010, STORE)),
            _ => Err("c.fsw: the F extension is not in RV32IMAC"),
        },

        // -------------------------------------------------------------------
        // Quadrant 1
        // -------------------------------------------------------------------
        0b01 => match funct3 {
            // c.addi rd, nzimm / c.nop  ->  addi rd, rd, imm
            //
            // One arm for both: c.nop is c.addi with rd = x0 and imm = 0, and
            // `addi x0, x0, 0` is what it expands to. The rd = x0 and imm = 0
            // cases with the other field nonzero are HINTs, and expand the same
            // way.
            0b000 => Ok(i_type(ci_imm(c), rd_rs1, 0b000, rd_rs1, OP_IMM)),
            // c.jal offset  ->  jal x1, offset   (RV32-only encoding)
            0b001 => Ok(j_type(cj_imm(c), 1, JAL)),
            // c.li rd, imm  ->  addi rd, x0, imm
            0b010 => Ok(i_type(ci_imm(c), 0, 0b000, rd_rs1, OP_IMM)),
            0b011 => {
                if rd_rs1 == 2 {
                    let nzimm = addi16sp_imm(c);
                    if nzimm == 0 {
                        return Err("c.addi16sp with nzimm = 0 is a reserved encoding");
                    }
                    // c.addi16sp nzimm  ->  addi x2, x2, nzimm
                    Ok(i_type(nzimm, 2, 0b000, 2, OP_IMM))
                } else {
                    // c.lui rd, nzimm  ->  lui rd, nzimm[17:12]
                    //
                    // The 6-bit field is the immediate's bits 17:12, sign
                    // extended through bit 31; LUI's own field is bits 31:12,
                    // so it is that sign-extended 6-bit value masked to 20
                    // bits.
                    let nzimm = ci_imm(c);
                    if nzimm == 0 {
                        return Err("c.lui with nzimm = 0 is a reserved encoding");
                    }
                    Ok(u_type(nzimm as u32 & 0xf_ffff, rd_rs1, LUI))
                }
            }
            0b100 => match (c >> 10) & 0b11 {
                // c.srli rd', shamt  ->  srli rd', rd', shamt
                0b00 => Ok(i_type(rv32_shamt(c)? as i32, rp_hi, 0b101, rp_hi, OP_IMM)),
                // c.srai rd', shamt  ->  srai rd', rd', shamt
                //
                // SRAI is SRLI with bit 30 of the word set, which is bit 10 of
                // the 12-bit immediate field.
                0b01 => Ok(i_type(
                    (0b0100_0000_0000 | rv32_shamt(c)?) as i32,
                    rp_hi,
                    0b101,
                    rp_hi,
                    OP_IMM,
                )),
                // c.andi rd', imm  ->  andi rd', rd', imm
                0b10 => Ok(i_type(ci_imm(c), rp_hi, 0b111, rp_hi, OP_IMM)),
                _ => {
                    // The register-register block. Bit 12 selects the 32-bit
                    // group from the 64-bit one.
                    match ((c >> 12) & 1, (c >> 5) & 0b11) {
                        // c.sub / c.xor / c.or / c.and rd', rs2'
                        (0, 0b00) => Ok(r_type(0b010_0000, rp_lo, rp_hi, 0b000, rp_hi, OP)),
                        (0, 0b01) => Ok(r_type(0, rp_lo, rp_hi, 0b100, rp_hi, OP)),
                        (0, 0b10) => Ok(r_type(0, rp_lo, rp_hi, 0b110, rp_hi, OP)),
                        (0, _) => Ok(r_type(0, rp_lo, rp_hi, 0b111, rp_hi, OP)),
                        (_, 0b00) => Err("c.subw is an RV64-only encoding"),
                        (_, 0b01) => Err("c.addw is an RV64-only encoding"),
                        _ => Err("quadrant 1 funct3 = 100, bit 12 = 1, bits 6:5 = 1x is reserved"),
                    }
                }
            },
            // c.j offset  ->  jal x0, offset
            0b101 => Ok(j_type(cj_imm(c), 0, JAL)),
            // c.beqz rs1', offset  ->  beq rs1', x0, offset
            0b110 => Ok(b_type(cb_imm(c), 0, rp_hi, 0b000, BRANCH)),
            // c.bnez rs1', offset  ->  bne rs1', x0, offset
            _ => Ok(b_type(cb_imm(c), 0, rp_hi, 0b001, BRANCH)),
        },

        // -------------------------------------------------------------------
        // Quadrant 2
        // -------------------------------------------------------------------
        0b10 => match funct3 {
            // c.slli rd, shamt  ->  slli rd, rd, shamt
            0b000 => Ok(i_type(rv32_shamt(c)? as i32, rd_rs1, 0b001, rd_rs1, OP_IMM)),
            0b001 => Err("c.fldsp: the D extension is not in RV32IMAC"),
            0b010 => {
                if rd_rs1 == 0 {
                    return Err("c.lwsp with rd = x0 is a reserved encoding");
                }
                // c.lwsp rd, uimm(x2)  ->  lw rd, uimm(x2)
                Ok(i_type(lwsp_imm(c) as i32, 2, 0b010, rd_rs1, LOAD))
            }
            0b011 => Err("c.flwsp: the F extension is not in RV32IMAC"),
            0b100 => match ((c >> 12) & 1, rs2) {
                (0, 0) => {
                    if rd_rs1 == 0 {
                        return Err("c.jr with rs1 = x0 is a reserved encoding");
                    }
                    // c.jr rs1  ->  jalr x0, 0(rs1)
                    Ok(i_type(0, rd_rs1, 0b000, 0, JALR))
                }
                // c.mv rd, rs2  ->  add rd, x0, rs2
                (0, _) => Ok(r_type(0, rs2, 0, 0b000, rd_rs1, OP)),
                // c.ebreak
                (_, 0) if rd_rs1 == 0 => Ok(EBREAK),
                // c.jalr rs1  ->  jalr x1, 0(rs1)
                (_, 0) => Ok(i_type(0, rd_rs1, 0b000, 1, JALR)),
                // c.add rd, rs2  ->  add rd, rd, rs2
                (_, _) => Ok(r_type(0, rs2, rd_rs1, 0b000, rd_rs1, OP)),
            },
            0b101 => Err("c.fsdsp: the D extension is not in RV32IMAC (the Zcmp encoding space)"),
            // c.swsp rs2, uimm(x2)  ->  sw rs2, uimm(x2)
            0b110 => Ok(s_type(swsp_imm(c) as i32, rs2, 2, 0b010, STORE)),
            _ => Err("c.fswsp: the F extension is not in RV32IMAC"),
        },

        // `c & 0b11 == 0b11` is a 32-bit instruction; the caller never asks.
        _ => Err("not a compressed encoding: bits 1:0 are 11"),
    }
}

// ---------------------------------------------------------------------------
// Immediates
// ---------------------------------------------------------------------------

/// Sign-extend the low `bits` of `v`.
fn sext(v: u32, bits: u32) -> i32 {
    let shift = 32 - bits;
    ((v << shift) as i32) >> shift
}

/// CIW, `c.addi4spn`: a zero-extended, word-scaled 10-bit offset from `x2`.
///
/// `nzuimm[5:4] = c[12:11]`, `[9:6] = c[10:7]`, `[2] = c[6]`, `[3] = c[5]`.
fn ciw_imm(c: u32) -> u32 {
    ((c >> 7) & 0b11_0000) | ((c >> 1) & 0b11_1100_0000) | ((c >> 4) & 0b100) | ((c >> 2) & 0b1000)
}

/// CL/CS, `c.lw` and `c.sw`: a zero-extended, word-scaled 7-bit offset.
///
/// `uimm[5:3] = c[12:10]`, `[2] = c[6]`, `[6] = c[5]`.
fn cl_cs_imm(c: u32) -> u32 {
    ((c >> 7) & 0b11_1000) | ((c >> 4) & 0b100) | ((c << 1) & 0b100_0000)
}

/// CI, the plain 6-bit signed immediate: `imm[5] = c[12]`, `[4:0] = c[6:2]`.
///
/// Shared by `c.addi`, `c.li`, `c.andi` and `c.lui` — for `c.lui` it is the
/// immediate's bits 17:12 rather than 5:0, which is the caller's business.
fn ci_imm(c: u32) -> i32 {
    sext(((c >> 7) & 0b10_0000) | ((c >> 2) & 0b1_1111), 6)
}

/// `c.addi16sp`: a sign-extended, 16-scaled 10-bit immediate.
///
/// `nzimm[9] = c[12]`, `[4] = c[6]`, `[6] = c[5]`, `[8:7] = c[4:3]`,
/// `[5] = c[2]`.
fn addi16sp_imm(c: u32) -> i32 {
    sext(
        ((c >> 3) & 0b10_0000_0000)
            | ((c >> 2) & 0b1_0000)
            | ((c << 1) & 0b100_0000)
            | ((c << 4) & 0b1_1000_0000)
            | ((c << 3) & 0b10_0000),
        10,
    )
}

/// `c.lwsp`: a zero-extended, word-scaled 8-bit offset from `x2`.
///
/// `uimm[5] = c[12]`, `[4:2] = c[6:4]`, `[7:6] = c[3:2]`.
fn lwsp_imm(c: u32) -> u32 {
    ((c >> 7) & 0b10_0000) | ((c >> 2) & 0b1_1100) | ((c << 4) & 0b1100_0000)
}

/// `c.swsp`: a zero-extended, word-scaled 8-bit offset to `x2`.
///
/// `uimm[5:2] = c[12:9]`, `[7:6] = c[8:7]`.
fn swsp_imm(c: u32) -> u32 {
    ((c >> 7) & 0b11_1100) | ((c >> 1) & 0b1100_0000)
}

/// CJ, `c.j` and `c.jal`: a sign-extended, halfword-scaled 12-bit offset.
///
/// `imm[11] = c[12]`, `[4] = c[11]`, `[9:8] = c[10:9]`, `[10] = c[8]`,
/// `[6] = c[7]`, `[7] = c[6]`, `[3:1] = c[5:3]`, `[5] = c[2]`. Bit 0 is zero.
fn cj_imm(c: u32) -> i32 {
    sext(
        ((c >> 1) & 0b1000_0000_0000)
            | ((c >> 7) & 0b1_0000)
            | ((c >> 1) & 0b11_0000_0000)
            | ((c << 2) & 0b100_0000_0000)
            | ((c >> 1) & 0b100_0000)
            | ((c << 1) & 0b1000_0000)
            | ((c >> 2) & 0b1110)
            | ((c << 3) & 0b10_0000),
        12,
    )
}

/// CB, `c.beqz` and `c.bnez`: a sign-extended, halfword-scaled 9-bit offset.
///
/// `imm[8] = c[12]`, `[4:3] = c[11:10]`, `[7:6] = c[6:5]`, `[2:1] = c[4:3]`,
/// `[5] = c[2]`. Bit 0 is zero.
fn cb_imm(c: u32) -> i32 {
    sext(
        ((c >> 4) & 0b1_0000_0000)
            | ((c >> 7) & 0b1_1000)
            | ((c << 1) & 0b1100_0000)
            | ((c >> 2) & 0b110)
            | ((c << 3) & 0b10_0000),
        9,
    )
}

/// The shift amount shared by `c.slli`, `c.srli` and `c.srai`.
///
/// `shamt[5] = c[12]`, `[4:0] = c[6:2]`. On RV32 the high bit must be zero: a
/// set bit is not a 64-bit shift, it is a reserved encoding.
fn rv32_shamt(c: u32) -> Result<u32, &'static str> {
    if (c >> 12) & 1 != 0 {
        return Err("a compressed shift with shamt[5] set is reserved on RV32");
    }
    Ok((c >> 2) & 0b1_1111)
}

// ---------------------------------------------------------------------------
// The base instruction formats
// ---------------------------------------------------------------------------
//
// One function per format, each a transcription of the spec's "RISC-V base
// instruction formats" figure. Every immediate arrives as the *value*, and each
// function scatters it into the fields that format uses.

fn r_type(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

fn i_type(imm: i32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    ((imm as u32 & 0xfff) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
}

fn s_type(imm: i32, rs2: u32, rs1: u32, funct3: u32, opcode: u32) -> u32 {
    let imm = imm as u32;
    (((imm >> 5) & 0x7f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | ((imm & 0x1f) << 7)
        | opcode
}

fn b_type(imm: i32, rs2: u32, rs1: u32, funct3: u32, opcode: u32) -> u32 {
    let imm = imm as u32;
    (((imm >> 12) & 1) << 31)
        | (((imm >> 5) & 0x3f) << 25)
        | (rs2 << 20)
        | (rs1 << 15)
        | (funct3 << 12)
        | (((imm >> 1) & 0xf) << 8)
        | (((imm >> 11) & 1) << 7)
        | opcode
}

fn u_type(imm_31_12: u32, rd: u32, opcode: u32) -> u32 {
    (imm_31_12 << 12) | (rd << 7) | opcode
}

fn j_type(imm: i32, rd: u32, opcode: u32) -> u32 {
    let imm = imm as u32;
    (((imm >> 20) & 1) << 31)
        | (((imm >> 1) & 0x3ff) << 21)
        | (((imm >> 11) & 1) << 20)
        | (((imm >> 12) & 0xff) << 12)
        | (rd << 7)
        | opcode
}

#[cfg(test)]
mod tests {
    use super::expand;

    /// The RVC HINTs, which LLVM will neither assemble nor disassemble.
    ///
    /// Their expansions are written out here because the paired-region oracle
    /// in `tests/differential.rs` cannot reach them: LLVM's decoder tables
    /// exclude `rd = x0` from `c.addi` and its siblings, so a raw HINT halfword
    /// in that fixture would only desynchronise `llvm-objdump`. Each line is
    /// two independent statements — the 16-bit encoding and the 32-bit one —
    /// and both are short enough to check against the spec's figures by hand.
    ///
    /// What is HINT-specific here is only that these are *accepted*. The field
    /// arithmetic behind each one is the same code the oracle already covers
    /// through the non-HINT form of the same instruction.
    #[test]
    fn hints_expand_rather_than_being_rejected() {
        // (compressed, expanded, what it is)
        let cases: [(u16, u32, &str); 6] = [
            (0x0015, 0x0050_0013, "c.addi x0, 5    -> addi x0, x0, 5"),
            (0x4005, 0x0010_0013, "c.li   x0, 1    -> addi x0, x0, 1"),
            (0x0006, 0x0010_1013, "c.slli x0, 1    -> slli x0, x0, 1"),
            (0x8101, 0x0005_5513, "c.srli a0, 0    -> srli a0, a0, 0"),
            (0x8016, 0x0050_0033, "c.mv   x0, t0   -> add  x0, x0, t0"),
            (0x9016, 0x0050_0033, "c.add  x0, t0   -> add  x0, x0, t0"),
        ];
        for (compressed, expanded, what) in cases {
            assert_eq!(expand(compressed), Ok(expanded), "{what}");
        }
    }

    /// The two forms with nothing to get wrong, as a floor under everything
    /// else: if these move, the opcode constants moved.
    #[test]
    fn the_fixed_forms_are_fixed() {
        assert_eq!(expand(0x0001), Ok(0x0000_0013), "c.nop -> addi x0, x0, 0");
        assert_eq!(expand(0x9002), Ok(0x0010_0073), "c.ebreak -> ebreak");
    }

    /// Every encoding this loader refuses, with the class it belongs to.
    ///
    /// The list is the module doc's four bullets made executable; a fixture
    /// exists for the ones a program is most likely to contain.
    #[test]
    fn the_rejected_classes_are_rejected() {
        let cases: [(u16, &str); 22] = [
            (0x0000, "the all-zero halfword"),
            (0x0008, "c.addi4spn with nzuimm = 0"),
            // quadrant 0: the F/D forms and the Zcb slot
            (0x2000, "c.fld"),
            (0x6000, "c.flw"),
            (0x8000, "quadrant 0 funct3 = 100 (Zcb)"),
            (0xa000, "c.fsd"),
            (0xe000, "c.fsw"),
            // quadrant 1: the reserved immediates and the RV64 forms
            (0x6101, "c.addi16sp with nzimm = 0"),
            (0x6181, "c.lui with nzimm = 0"),
            (0x9101, "c.srli with shamt[5] set"),
            (0x9501, "c.srai with shamt[5] set"),
            (0x9c01, "c.subw"),
            (0x9c21, "c.addw"),
            (0x9c41, "quadrant 1 reserved, bits 6:5 = 10"),
            (0x9c61, "quadrant 1 reserved, bits 6:5 = 11"),
            // quadrant 2
            (0x1082, "c.slli with shamt[5] set"),
            (0x2002, "c.fldsp"),
            (0x4002, "c.lwsp with rd = x0"),
            (0x6002, "c.flwsp"),
            (0x8002, "c.jr with rs1 = x0"),
            (0xa002, "c.fsdsp / the Zcmp slot"),
            (0xe002, "c.fswsp"),
        ];
        for (encoding, what) in cases {
            let got = expand(encoding);
            assert!(
                got.is_err(),
                "{what} ({encoding:#06x}) expanded to {got:?} instead of being refused"
            );
        }
    }

    /// The whole 16-bit space, swept: nothing panics, every refusal says
    /// something, and every acceptance is a 32-bit instruction of a shape this
    /// ISA has.
    ///
    /// A sweep like this is what catches an arm that falls through to a
    /// `u32` built out of the wrong opcode, which no hand-written case list
    /// would find.
    #[test]
    fn every_halfword_either_expands_or_is_named() {
        // The only opcodes an RVC expansion can produce, from the table in the
        // module docs.
        const OPCODES: [u32; 9] = [
            super::OP_IMM,
            super::OP,
            super::LOAD,
            super::STORE,
            super::BRANCH,
            super::JAL,
            super::JALR,
            super::LUI,
            0b111_0011, // SYSTEM, which is c.ebreak alone
        ];

        // Counted per quadrant, so each number is derivable rather than
        // recorded. Each (quadrant, funct3) slot holds 2048 encodings.
        let mut accepted = [0usize; 3];
        let mut refused = 0usize;
        for c in 0..=u16::MAX {
            // A 32-bit encoding is not this function's business.
            if c & 0b11 == 0b11 {
                continue;
            }
            match expand(c) {
                Ok(word) => {
                    assert_eq!(
                        word & 0b11,
                        0b11,
                        "{c:#06x} expanded to {word:#010x}, which is not a 32-bit encoding"
                    );
                    assert!(
                        OPCODES.contains(&(word & 0x7f)),
                        "{c:#06x} expanded to {word:#010x}, whose opcode is not one \
                         an RVC expansion can produce"
                    );
                    accepted[(c & 0b11) as usize] += 1;
                }
                Err(reason) => {
                    assert!(!reason.is_empty(), "{c:#06x} was refused without a reason");
                    refused += 1;
                }
            }
        }

        // Three quarters of the 16-bit space is compressed encodings.
        assert_eq!(accepted.iter().sum::<usize>() + refused, 49152);

        // Quadrant 0: c.lw and c.sw take two whole slots; c.addi4spn takes its
        // slot less the eight encodings whose nzuimm is zero (one per rd');
        // the five F/D and Zcb slots are gone entirely.
        assert_eq!(accepted[0], 2 * 2048 + (2048 - 8), "quadrant 0");

        // Quadrant 1: six whole slots (c.addi, c.jal, c.li, c.j, c.beqz,
        // c.bnez), plus
        //   funct3 = 011: 64 encodings have rd = x2 and are c.addi16sp, one of
        //     which has nzimm = 0; the other 1984 are c.lui, of which the 31
        //     with nzimm = 0 (one per rd != x2) are reserved;
        //   funct3 = 100: c.srli and c.srai keep half of their 512 encodings
        //     each (shamt[5] must be zero), c.andi keeps all 512, and the
        //     register-register block keeps the 256 with bit 12 clear and none
        //     of the 256 with it set (c.subw, c.addw and two reserved corners).
        assert_eq!(
            accepted[1],
            6 * 2048 + (63 + 1953) + (256 + 256 + 512 + 256),
            "quadrant 1"
        );

        // Quadrant 2: c.swsp takes a whole slot; c.slli keeps the half with
        // shamt[5] clear; c.lwsp loses the 64 encodings with rd = x0; the
        // funct3 = 100 slot loses only c.jr with rs1 = x0; the four F/D slots
        // are gone.
        assert_eq!(
            accepted[2],
            2048 + 1024 + (2048 - 64) + (2048 - 1),
            "quadrant 2"
        );
    }
}
