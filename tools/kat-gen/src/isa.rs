//! `crates/isa`'s fixtures: a hand-encoded corpus of every RV32IMA mnemonic,
//! llvm-objdump's reading of it, and a corpus of words that must not decode.
//!
//! The corpus words are built by the small field encoders below, and **the
//! encoders are not the oracle**: a wrong encoder produces a different valid
//! word, and llvm-objdump — pinned with the compiler by `rust-toolchain.toml` —
//! then says what that word is. The test decodes each word itself and compares
//! with the disassembler's text. This generator never links `crates/isa`, so
//! neither file is a restatement of the decoder under test.

use std::fs;
use std::path::PathBuf;

use crate::loader::{llvm_tool, parse_objdump_line, run, ElfBuilder};
use crate::write_vectors;

// ---------------------------------------------------------------------------
// Field encoders, from the ISA manual's format diagrams
// ---------------------------------------------------------------------------

pub(crate) fn r(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    funct7 << 25 | rs2 << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | opcode
}

pub(crate) fn i(imm: i32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
    ((imm as u32) & 0xfff) << 20 | rs1 << 15 | funct3 << 12 | rd << 7 | opcode
}

pub(crate) fn s(imm: i32, rs2: u32, rs1: u32, funct3: u32) -> u32 {
    let m = imm as u32;
    ((m >> 5) & 0x7f) << 25 | rs2 << 20 | rs1 << 15 | funct3 << 12 | (m & 0x1f) << 7 | 0x23
}

pub(crate) fn b(imm: i32, rs2: u32, rs1: u32, funct3: u32) -> u32 {
    let m = imm as u32;
    ((m >> 12) & 1) << 31
        | ((m >> 5) & 0x3f) << 25
        | rs2 << 20
        | rs1 << 15
        | funct3 << 12
        | ((m >> 1) & 0xf) << 8
        | ((m >> 11) & 1) << 7
        | 0x63
}

pub(crate) fn u(imm20: u32, rd: u32, opcode: u32) -> u32 {
    (imm20 & 0xfffff) << 12 | rd << 7 | opcode
}

pub(crate) fn j(imm: i32, rd: u32) -> u32 {
    let m = imm as u32;
    ((m >> 20) & 1) << 31
        | ((m >> 1) & 0x3ff) << 21
        | ((m >> 11) & 1) << 20
        | ((m >> 12) & 0xff) << 12
        | rd << 7
        | 0x6f
}

fn amo(funct5: u32, aq: u32, rl: u32, rs2: u32, rs1: u32, rd: u32) -> u32 {
    r(funct5 << 2 | aq << 1 | rl, rs2, rs1, 0b010, rd, 0x2f)
}

fn fence(fm: u32, pred: u32, succ: u32) -> u32 {
    fm << 28 | pred << 24 | succ << 20 | 0x0f
}

// ---------------------------------------------------------------------------
// The corpus
// ---------------------------------------------------------------------------

/// Register triples `(rd, rs1, rs2)`, cycled through: both ends of the file on
/// each operand, and `x0` everywhere it can go.
const REGS: [(u32, u32, u32); 4] = [(31, 0, 15), (0, 31, 1), (10, 2, 31), (5, 16, 8)];

/// Twelve-bit immediates: zero, one, minus one, both extremes, and two
/// alternating patterns that a transposed field would scramble.
const IMM12: [i32; 7] = [0, 1, -1, 2047, -2048, 0x2aa, -0x2ab];

/// Branch displacements: even, within 13 signed bits, both extremes.
const BRANCH: [i32; 7] = [0, 2, -2, 4094, -4096, 0x556, -0x556];

/// Jump displacements: even, within 21 signed bits, both extremes.
const JUMP: [i32; 6] = [0, 2, -2, 1_048_574, -1_048_576, 0x5_5556];

/// Upper immediates, as the 20-bit field.
const UPPER: [u32; 6] = [0, 1, 0x80000, 0xfffff, 0x7ffff, 0x12345];

fn corpus() -> Vec<u32> {
    let mut words = Vec::new();
    let regs = |k: usize| REGS[k % REGS.len()];

    for (k, imm) in UPPER.iter().enumerate() {
        words.push(u(*imm, regs(k).0, 0x37)); // lui
        words.push(u(*imm, regs(k + 1).0, 0x17)); // auipc
    }
    for (k, imm) in JUMP.iter().enumerate() {
        words.push(j(*imm, regs(k).0));
    }
    for (k, imm) in IMM12.iter().enumerate() {
        let (rd, rs1, _) = regs(k);
        words.push(i(*imm, rs1, 0b000, rd, 0x67)); // jalr
    }
    for f3 in [0b000, 0b001, 0b100, 0b101, 0b110, 0b111] {
        for (k, imm) in BRANCH.iter().enumerate() {
            let (_, rs1, rs2) = regs(k + f3 as usize);
            words.push(b(*imm, rs2, rs1, f3));
        }
    }
    for f3 in [0b000, 0b001, 0b010, 0b100, 0b101] {
        for (k, imm) in IMM12.iter().enumerate() {
            let (rd, rs1, _) = regs(k + f3 as usize);
            words.push(i(*imm, rs1, f3, rd, 0x03)); // loads
        }
    }
    for f3 in [0b000, 0b001, 0b010] {
        for (k, imm) in IMM12.iter().enumerate() {
            let (_, rs1, rs2) = regs(k + f3 as usize);
            words.push(s(*imm, rs2, rs1, f3)); // stores
        }
    }
    for f3 in [0b000, 0b010, 0b011, 0b100, 0b110, 0b111] {
        for (k, imm) in IMM12.iter().enumerate() {
            let (rd, rs1, _) = regs(k + f3 as usize);
            words.push(i(*imm, rs1, f3, rd, 0x13)); // addi .. andi
        }
    }
    for (funct7, f3) in [
        (0b000_0000, 0b001),
        (0b000_0000, 0b101),
        (0b010_0000, 0b101),
    ] {
        for (k, shamt) in [0u32, 1, 17, 31].iter().enumerate() {
            let (rd, rs1, _) = regs(k + f3 as usize);
            words.push(r(funct7, *shamt, rs1, f3, rd, 0x13)); // slli srli srai
        }
    }
    let register_ops: [(u32, u32); 18] = [
        (0b000_0000, 0b000),
        (0b010_0000, 0b000),
        (0b000_0000, 0b001),
        (0b000_0000, 0b010),
        (0b000_0000, 0b011),
        (0b000_0000, 0b100),
        (0b000_0000, 0b101),
        (0b010_0000, 0b101),
        (0b000_0000, 0b110),
        (0b000_0000, 0b111),
        (0b000_0001, 0b000),
        (0b000_0001, 0b001),
        (0b000_0001, 0b010),
        (0b000_0001, 0b011),
        (0b000_0001, 0b100),
        (0b000_0001, 0b101),
        (0b000_0001, 0b110),
        (0b000_0001, 0b111),
    ];
    for (n, (funct7, f3)) in register_ops.iter().enumerate() {
        for k in 0..REGS.len() {
            let (rd, rs1, rs2) = regs(k + n);
            words.push(r(*funct7, rs2, rs1, *f3, rd, 0x33));
        }
    }
    // Every fence llvm-objdump will spell. pred and succ are `iorw`, bit 3
    // first; fm 1000 with rw,rw is fence.tso.
    for (fm, pred, succ) in [
        (0, 0b0011, 0b0011),
        (0, 0b1111, 0b1111),
        (0, 0b0001, 0b0000),
        (0, 0b0000, 0b0000),
        (0, 0b1100, 0b0010),
        (0, 0b1010, 0b0101),
        (0b1000, 0b0011, 0b0011),
    ] {
        words.push(fence(fm, pred, succ));
    }
    words.push(0x0000_0073); // ecall
    words.push(0x0010_0073); // ebreak
    for (n, funct5) in [
        0b00010, 0b00011, 0b00001, 0b00000, 0b00100, 0b01100, 0b01000, 0b10000, 0b10100, 0b11000,
        0b11100,
    ]
    .iter()
    .enumerate()
    {
        for aq in 0..2 {
            for rl in 0..2 {
                let (rd, rs1, rs2) = regs(n + 2 * aq as usize + rl as usize);
                // lr.w has no rs2: the field must be zero.
                let rs2 = if *funct5 == 0b00010 { 0 } else { rs2 };
                words.push(amo(*funct5, aq, rl, rs2, rs1, rd));
            }
        }
    }
    words
}

// ---------------------------------------------------------------------------
// The negative corpus
// ---------------------------------------------------------------------------

/// `(word, format, why)`: words one field away from a real instruction, plus
/// the encodings of extensions RV32IMAC does not have.
///
/// The U and J formats have no entry because they have no near miss: every
/// bit that is not the opcode is immediate or `rd`, so every word with those
/// opcodes is an instruction.
fn negatives() -> Vec<(u32, &'static str, &'static str)> {
    vec![
        (
            r(0b000_0010, 3, 2, 0b000, 1, 0x33),
            "R",
            "OP funct7 0000010 names nothing",
        ),
        (
            r(0b010_0000, 3, 2, 0b001, 1, 0x33),
            "R",
            "OP funct7 0100000 with funct3 001: only sub and sra take 0100000",
        ),
        (
            r(0b010_0000, 3, 2, 0b111, 1, 0x33),
            "R",
            "OP funct7 0100000 with funct3 111",
        ),
        (
            r(0b100_0000, 3, 2, 0b000, 1, 0x33),
            "R",
            "OP funct7 1000000 names nothing",
        ),
        (
            r(0b000_0011, 3, 2, 0b000, 1, 0x33),
            "R",
            "OP funct7 0000011, one bit from mul",
        ),
        (
            r(0b010_0000, 5, 2, 0b001, 1, 0x13),
            "I",
            "slli funct7 0100000",
        ),
        (
            r(0b000_0001, 5, 2, 0b001, 1, 0x13),
            "I",
            "slli with shamt[5] set: RV64 only",
        ),
        (
            r(0b000_0001, 5, 2, 0b101, 1, 0x13),
            "I",
            "srli with shamt[5] set: RV64 only",
        ),
        (
            r(0b010_0001, 5, 2, 0b101, 1, 0x13),
            "I",
            "srai with shamt[5] set: RV64 only",
        ),
        (
            r(0b000_0010, 5, 2, 0b101, 1, 0x13),
            "I",
            "shift-right funct7 0000010 names nothing",
        ),
        (i(8, 2, 0b011, 1, 0x03), "I", "load funct3 011 is RV64's ld"),
        (
            i(8, 2, 0b110, 1, 0x03),
            "I",
            "load funct3 110 is RV64's lwu",
        ),
        (i(8, 2, 0b111, 1, 0x03), "I", "load funct3 111 is reserved"),
        (i(8, 2, 0b001, 1, 0x67), "I", "jalr funct3 001"),
        (i(8, 2, 0b111, 1, 0x67), "I", "jalr funct3 111"),
        (s(8, 3, 2, 0b011), "S", "store funct3 011 is RV64's sd"),
        (s(8, 3, 2, 0b100), "S", "store funct3 100 is reserved"),
        (s(8, 3, 2, 0b111), "S", "store funct3 111 is reserved"),
        (b(8, 3, 2, 0b010), "B", "branch funct3 010 is reserved"),
        (b(8, 3, 2, 0b011), "B", "branch funct3 011 is reserved"),
        (
            r(0b00000 << 2, 3, 2, 0b011, 1, 0x2f),
            "AMO",
            "amoadd.d: funct3 011 is RV64's width",
        ),
        (
            r(0b00000 << 2, 3, 2, 0b000, 1, 0x2f),
            "AMO",
            "AMO funct3 000 names no width",
        ),
        (
            amo(0b00010, 0, 0, 5, 2, 1),
            "AMO",
            "lr.w with rs2 = x5: rs2 must be x0",
        ),
        (
            amo(0b00101, 0, 0, 3, 2, 1),
            "AMO",
            "AMO funct5 00101 names nothing",
        ),
        (
            amo(0b11111, 1, 1, 3, 2, 1),
            "AMO",
            "AMO funct5 11111 names nothing",
        ),
        (0x0000_00f3, "SYSTEM", "ecall with rd = x1"),
        (0x0000_8073, "SYSTEM", "ecall with rs1 = x1"),
        (0x0010_00f3, "SYSTEM", "ebreak with rd = x1"),
        (
            0x0020_0073,
            "SYSTEM",
            "funct12 2: uret, which RV32IMAC does not have",
        ),
        (0x3020_0073, "extension", "mret: privileged"),
        (0x1050_0073, "extension", "wfi: privileged"),
        (0x1200_0073, "SYSTEM", "sfence.vma: privileged"),
        (0xc000_2573, "extension", "csrrs a0, cycle, zero: Zicsr"),
        (0x0000_100f, "MISC-MEM", "fence.i: Zifencei"),
        (0x0000_200f, "MISC-MEM", "MISC-MEM funct3 010 names nothing"),
        (0x0005_a507, "opcode", "flw: F extension"),
        (0x00a5_a027, "opcode", "fsw: F extension"),
        (0x00b5_7553, "opcode", "fadd.s: F extension"),
        (0x6000_0043, "opcode", "fmadd: F extension"),
        (0x0015_051b, "opcode", "addiw: RV64's OP-IMM-32"),
        (0x00b5_053b, "opcode", "addw: RV64's OP-32"),
        (0x0000_000b, "opcode", "custom-0"),
        (0x0000_0057, "opcode", "OP-V: the vector extension"),
        (0x0000_001f, "opcode", "bits 4:2 = 111: a 48-bit encoding"),
        (
            0x0000_003f,
            "opcode",
            "bits 6:0 = 0111111: a 64-bit encoding",
        ),
        (
            0x0000_007f,
            "opcode",
            "bits 6:0 = 1111111: an 80-bit or longer encoding",
        ),
        (
            0x0000_0001,
            "compressed",
            "bits 1:0 = 01: c.nop's shape, which the loader expands first",
        ),
        (
            0x0000_0000,
            "compressed",
            "all zeros: the defined-illegal halfword, twice",
        ),
        (
            0xffff_0002,
            "compressed",
            "bits 1:0 = 10: a quadrant-2 halfword",
        ),
    ]
}

// ---------------------------------------------------------------------------
// Writing it out
// ---------------------------------------------------------------------------

pub fn generate() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/isa/tests/vectors");
    fs::create_dir_all(&dir).expect("creating crates/isa/tests/vectors");

    let words = corpus();
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let elf = ElfBuilder::rv32_exec(&text).build();
    crate::write_bytes("crates/isa/tests/vectors/isa_corpus.elf", &elf);

    // The synthetic ELF carries no `.riscv.attributes`, so the disassembler is
    // told the extensions explicitly; without it, M and A print `<unknown>`.
    let out = run(
        llvm_tool("llvm-objdump"),
        &[
            "--disassemble",
            "--no-print-imm-hex",
            "-M",
            "no-aliases",
            "--mattr=+m,+a,+c",
            dir.join("isa_corpus.elf")
                .to_str()
                .expect("fixture paths are UTF-8"),
        ],
    );
    let mut body = String::new();
    let mut count = 0usize;
    for line in out.lines() {
        let Some((addr, enc, text)) = parse_objdump_line(line) else {
            continue;
        };
        assert!(
            !text.contains("unknown"),
            "llvm-objdump does not recognise corpus word {enc} at {addr:#x}: every \
             corpus word must be one the disassembler reads"
        );
        body.push_str(&format!("{addr:08x} {enc} {text}\n"));
        count += 1;
    }
    assert_eq!(count, words.len(), "one listed line per corpus word");
    write_vectors(
        "crates/isa/tests/vectors/isa_corpus.objdump.txt",
        &format!(
            "# `llvm-objdump -d -M no-aliases --mattr=+m,+a,+c` of isa_corpus.elf.\n\
             # Generated by `cargo run -p kat-gen -- isa`. Do not edit.\n\
             #\n\
             # Every RV32IMA mnemonic, hand-encoded with varied registers and\n\
             # boundary immediates. Fields: address, encoding, disassembly. The\n\
             # test decodes each encoding and compares with the disassembly.\n\
             #\n\
             # {count} instructions.\n\
             {body}"
        ),
    );

    let mut negative = String::from(
        "# Words crates/isa must refuse. Generated by `cargo run -p kat-gen -- isa`.\n\
         # Do not edit.\n\
         #\n\
         # Fields: word (hex, as an integer), format, why. Near misses of every\n\
         # format that has a fixed field -- R, I, S, B, AMO, SYSTEM, MISC-MEM --\n\
         # plus encodings of extensions RV32IMAC does not have -- `extension` inside\n\
         # its own opcodes, `opcode` for foreign major opcodes -- and the\n\
         # compressed shapes the loader expands before anything is decoded. U\n\
         # and J have no entry: every non-opcode bit of theirs is an operand, so\n\
         # they have no near miss.\n",
    );
    for (word, format, why) in negatives() {
        negative.push_str(&format!("{word:08x} {format} {why}\n"));
    }
    write_vectors("crates/isa/tests/vectors/isa_negative.txt", &negative);
}
