//! Fixture plumbing for `crates/isa`'s suites.
//!
//! This crate's own fixtures live in `tests/vectors/`. The guests are built from
//! `guests/` and listed by the pinned toolchain's `llvm-objdump` as the tests run
//! (`test_support`).

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

pub fn own(name: &str) -> Vec<u8> {
    read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors")
            .join(name),
    )
}

fn read(path: PathBuf) -> Vec<u8> {
    fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// Every non-comment, non-blank line.
pub fn lines(bytes: &[u8]) -> Vec<String> {
    String::from_utf8(bytes.to_vec())
        .expect("a committed listing is UTF-8")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// The 59 RV32IMA mnemonics, from the ISA manual's tables: RV32I's 40, M's 8,
/// A's 11. The corpus must cover every one.
pub const MNEMONICS: [&str; 59] = [
    "lui",
    "auipc",
    "jal",
    "jalr",
    "beq",
    "bne",
    "blt",
    "bge",
    "bltu",
    "bgeu",
    "lb",
    "lh",
    "lw",
    "lbu",
    "lhu",
    "sb",
    "sh",
    "sw",
    "addi",
    "slti",
    "sltiu",
    "xori",
    "ori",
    "andi",
    "slli",
    "srli",
    "srai",
    "add",
    "sub",
    "sll",
    "slt",
    "sltu",
    "xor",
    "srl",
    "sra",
    "or",
    "and",
    "fence",
    "ecall",
    "ebreak",
    "mul",
    "mulh",
    "mulhsu",
    "mulhu",
    "div",
    "divu",
    "rem",
    "remu",
    "lr.w",
    "sc.w",
    "amoswap.w",
    "amoadd.w",
    "amoxor.w",
    "amoand.w",
    "amoor.w",
    "amomin.w",
    "amomax.w",
    "amominu.w",
    "amomaxu.w",
];
