//! The whole 32-bit space, against the ISA tables.
//!
//! Every word whose low two bits are `11` — 2^30 of them, 2^25 per major
//! opcode — goes through `decode`, and two things are checked:
//!
//! 1. **the accepted count per opcode** equals a count derived by hand from
//!    the ISA manual's tables (the derivation is written beside each number),
//!    rather than whatever the code happens to accept;
//! 2. **every accepted word round-trips**: re-encoded from its decoded fields
//!    by an encoder transcribed here, independently of `crates/isa`, from the
//!    same tables, it is the word it came from. `fence` is compared outside
//!    its `rd` and `rs1` fields, which the ISA says to ignore.
//!
//! Together they say `decode` accepts exactly the words the tables name, and
//! reads each one's fields from exactly the bits the tables put them in.

use rayon::prelude::*;

use isa::{decode, Instr};

/// `(mnemonic, format, opcode, funct3, funct7 or funct5)`, from the ISA
/// manual's instruction listings. Formats: `U`, `J`, `I`, `H` (shift
/// immediate), `S`, `B`, `R`, `A` (atomic), `F` (fence), `E` (environment).
const TABLE: [(&str, char, u32, u32, u32); 59] = [
    ("lui", 'U', 0x37, 0, 0),
    ("auipc", 'U', 0x17, 0, 0),
    ("jal", 'J', 0x6f, 0, 0),
    ("jalr", 'I', 0x67, 0, 0),
    ("beq", 'B', 0x63, 0, 0),
    ("bne", 'B', 0x63, 1, 0),
    ("blt", 'B', 0x63, 4, 0),
    ("bge", 'B', 0x63, 5, 0),
    ("bltu", 'B', 0x63, 6, 0),
    ("bgeu", 'B', 0x63, 7, 0),
    ("lb", 'I', 0x03, 0, 0),
    ("lh", 'I', 0x03, 1, 0),
    ("lw", 'I', 0x03, 2, 0),
    ("lbu", 'I', 0x03, 4, 0),
    ("lhu", 'I', 0x03, 5, 0),
    ("sb", 'S', 0x23, 0, 0),
    ("sh", 'S', 0x23, 1, 0),
    ("sw", 'S', 0x23, 2, 0),
    ("addi", 'I', 0x13, 0, 0),
    ("slti", 'I', 0x13, 2, 0),
    ("sltiu", 'I', 0x13, 3, 0),
    ("xori", 'I', 0x13, 4, 0),
    ("ori", 'I', 0x13, 6, 0),
    ("andi", 'I', 0x13, 7, 0),
    ("slli", 'H', 0x13, 1, 0x00),
    ("srli", 'H', 0x13, 5, 0x00),
    ("srai", 'H', 0x13, 5, 0x20),
    ("add", 'R', 0x33, 0, 0x00),
    ("sub", 'R', 0x33, 0, 0x20),
    ("sll", 'R', 0x33, 1, 0x00),
    ("slt", 'R', 0x33, 2, 0x00),
    ("sltu", 'R', 0x33, 3, 0x00),
    ("xor", 'R', 0x33, 4, 0x00),
    ("srl", 'R', 0x33, 5, 0x00),
    ("sra", 'R', 0x33, 5, 0x20),
    ("or", 'R', 0x33, 6, 0x00),
    ("and", 'R', 0x33, 7, 0x00),
    ("fence", 'F', 0x0f, 0, 0),
    ("ecall", 'E', 0x73, 0, 0),
    ("ebreak", 'E', 0x73, 0, 1),
    ("mul", 'R', 0x33, 0, 0x01),
    ("mulh", 'R', 0x33, 1, 0x01),
    ("mulhsu", 'R', 0x33, 2, 0x01),
    ("mulhu", 'R', 0x33, 3, 0x01),
    ("div", 'R', 0x33, 4, 0x01),
    ("divu", 'R', 0x33, 5, 0x01),
    ("rem", 'R', 0x33, 6, 0x01),
    ("remu", 'R', 0x33, 7, 0x01),
    ("lr.w", 'A', 0x2f, 2, 0b00010),
    ("sc.w", 'A', 0x2f, 2, 0b00011),
    ("amoswap.w", 'A', 0x2f, 2, 0b00001),
    ("amoadd.w", 'A', 0x2f, 2, 0b00000),
    ("amoxor.w", 'A', 0x2f, 2, 0b00100),
    ("amoand.w", 'A', 0x2f, 2, 0b01100),
    ("amoor.w", 'A', 0x2f, 2, 0b01000),
    ("amomin.w", 'A', 0x2f, 2, 0b10000),
    ("amomax.w", 'A', 0x2f, 2, 0b10100),
    ("amominu.w", 'A', 0x2f, 2, 0b11000),
    ("amomaxu.w", 'A', 0x2f, 2, 0b11100),
];

/// Re-encode a decoded instruction from [`TABLE`] and its fields.
fn reencode(instr: &Instr) -> u32 {
    let mn = instr.mnemonic();
    let (_, format, op, f3, f7) = *TABLE
        .iter()
        .find(|row| row.0 == mn)
        .unwrap_or_else(|| panic!("{mn} is not in the table"));
    let f = instr.fields();
    let rd = f.rd.unwrap_or(0) as u32;
    let rs1 = f.rs1.unwrap_or(0) as u32;
    let rs2 = f.rs2.unwrap_or(0) as u32;
    let imm = f.imm.unwrap_or(0) as u32;
    match format {
        'U' => (imm & 0xffff_f000) | rd << 7 | op,
        'J' => {
            ((imm >> 20) & 1) << 31
                | ((imm >> 1) & 0x3ff) << 21
                | ((imm >> 11) & 1) << 20
                | ((imm >> 12) & 0xff) << 12
                | rd << 7
                | op
        }
        'I' => (imm & 0xfff) << 20 | rs1 << 15 | f3 << 12 | rd << 7 | op,
        'H' => f7 << 25 | (imm & 0x1f) << 20 | rs1 << 15 | f3 << 12 | rd << 7 | op,
        'S' => {
            ((imm >> 5) & 0x7f) << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | (imm & 0x1f) << 7 | op
        }
        'B' => {
            ((imm >> 12) & 1) << 31
                | ((imm >> 5) & 0x3f) << 25
                | rs2 << 20
                | rs1 << 15
                | f3 << 12
                | ((imm >> 1) & 0xf) << 8
                | ((imm >> 11) & 1) << 7
                | op
        }
        'R' => f7 << 25 | rs2 << 20 | rs1 << 15 | f3 << 12 | rd << 7 | op,
        'A' => {
            let (aq, rl) = instr.aq_rl().expect("an atomic");
            f7 << 27
                | (aq as u32) << 26
                | (rl as u32) << 25
                | rs2 << 20
                | rs1 << 15
                | f3 << 12
                | rd << 7
                | op
        }
        'F' => match *instr {
            Instr::Fence { fm, pred, succ } => {
                (fm as u32) << 28 | (pred as u32) << 24 | (succ as u32) << 20 | op
            }
            _ => unreachable!(),
        },
        'E' => f7 << 20 | op,
        other => panic!("format {other}"),
    }
}

/// Whether the immediate is in its format's range: U a multiple of 4096, I and
/// S twelve signed bits, B thirteen and even, J twenty-one and even, a shift
/// amount below 32.
fn canonical(instr: &Instr) -> bool {
    let format = TABLE
        .iter()
        .find(|row| row.0 == instr.mnemonic())
        .expect("every mnemonic is in the table")
        .1;
    let Some(imm) = instr.fields().imm else {
        return true;
    };
    let signed = |bits: u32| imm == (imm << (32 - bits)) >> (32 - bits);
    match format {
        'U' => imm & 0xfff == 0,
        'I' | 'S' => signed(12),
        'B' => imm & 1 == 0 && signed(13),
        'J' => imm & 1 == 0 && signed(21),
        'H' => (0..32).contains(&imm),
        _ => false,
    }
}

/// The accepted words of opcode `op`, round-tripping each one.
fn accepted(op: u32) -> u64 {
    (0u32..1 << 25)
        .into_par_iter()
        .map(|upper| {
            let word = upper << 7 | op;
            match decode(word) {
                Err(_) => 0u64,
                Ok(instr) => {
                    let ignored = match instr {
                        // fence's rd and rs1: "base implementations shall ignore".
                        Instr::Fence { .. } => 0x000f_8f80,
                        _ => 0,
                    };
                    let back = reencode(&instr);
                    assert_eq!(
                        back & !ignored,
                        word & !ignored,
                        "{word:#010x} decodes to {instr:?}, which re-encodes to {back:#010x}"
                    );
                    // The re-encoding masks each immediate to its bits, so on
                    // its own it would not see a value with stray bits outside
                    // them. The immediate must be in its format's canonical
                    // range, where the encoded bits determine it.
                    assert!(canonical(&instr), "{word:#010x}: {instr:?}");
                    1
                }
            }
        })
        .sum()
}

#[test]
fn the_accepted_space_is_exactly_the_isa_tables() {
    const FULL: u64 = 1 << 25; // every one of the 25 bits above the opcode
    const I: u64 = 1 << 22; // funct3 fixed: rd, rs1, imm12 free
    const R: u64 = 1 << 15; // funct3 and funct7 fixed: rd, rs1, rs2 free
    let expected: [(u32, &str, u64); 12] = [
        (0x37, "LUI: every word", FULL),
        (0x17, "AUIPC: every word", FULL),
        (0x6f, "JAL: every word", FULL),
        (0x67, "JALR: funct3 000", I),
        (0x63, "BRANCH: six funct3", 6 * I),
        (0x03, "LOAD: five funct3", 5 * I),
        (0x23, "STORE: three funct3", 3 * I),
        // Six funct3 with a 12-bit immediate, slli with one funct7, srli and
        // srai sharing funct3 101 with one funct7 each.
        (0x13, "OP-IMM", 6 * I + R + 2 * R),
        // Ten RV32I operations and eight M, one (funct7, funct3) each.
        (0x33, "OP: eighteen (funct7, funct3)", 18 * R),
        (0x0f, "MISC-MEM: funct3 000, everything else a fence", I),
        (0x73, "SYSTEM: ecall and ebreak, one word each", 2),
        // funct3 010; ten operations with aq, rl and rs2 free; lr.w with
        // aq and rl free and rs2 = 0.
        (0x2f, "AMO", 10 * 4 * R + 4 * (1 << 10)),
    ];

    for k in 0..32u32 {
        let op = k << 2 | 0b11;
        let want = expected
            .iter()
            .find(|(o, _, _)| *o == op)
            .map(|(_, _, n)| *n)
            .unwrap_or(0);
        let got = accepted(op);
        assert_eq!(
            got, want,
            "opcode {op:#04x}: accepted {got}, the tables say {want}"
        );
    }
}

/// Words whose low two bits are not `11` are compressed shapes, and every one
/// is refused: 2^24 upper patterns spread across the word by an odd
/// multiplier, under each of the three low-bit pairs.
#[test]
fn no_compressed_shape_decodes() {
    let accepted = (0u32..1 << 24)
        .into_par_iter()
        .map(|x| {
            let upper = x.wrapping_mul(0x9e37_79b9) & !0b11;
            (0..3).filter(|low| decode(upper | low).is_ok()).count()
        })
        .sum::<usize>();
    assert_eq!(accepted, 0);
}
