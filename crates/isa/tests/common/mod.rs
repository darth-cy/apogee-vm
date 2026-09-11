//! Fixture plumbing for `crates/isa`'s suites.
//!
//! This crate's own fixtures live in `tests/vectors/` and are pinned by
//! SHA-256 in [`PINS`]. The guest ELFs and their listings are
//! `crates/loader`'s, pinned there and read in place.

#![allow(dead_code)]

use std::fs;
use std::path::PathBuf;

use test_support::{sha256, to_hex};

/// Every committed fixture of this crate, and the digest it must have.
/// Refresh with `cargo run -p kat-gen -- isa`, which prints the digests.
pub const PINS: [(&str, &str); 3] = [
    (
        "isa_corpus.elf",
        "a6172fcd6e4c1c5da73dfb3db6e1a7029fee212f9cb891f80da622d57008719b",
    ),
    (
        "isa_corpus.objdump.txt",
        "c121d3f5b8db8563356dfa7810ef25c860fabf0d52f38226f550b99abd13a0b2",
    ),
    (
        "isa_negative.txt",
        "71aa9cdf27f643b409ddbed3d3a9ae3ee6c98a2351972ba45a82e3630c30a848",
    ),
];

pub fn own(name: &str) -> Vec<u8> {
    read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/vectors")
            .join(name),
    )
}

pub fn loader(name: &str) -> Vec<u8> {
    read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../loader/tests/vectors")
            .join(name),
    )
}

fn read(path: PathBuf) -> Vec<u8> {
    fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

pub fn digest(bytes: &[u8]) -> String {
    to_hex(&sha256(bytes))
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
