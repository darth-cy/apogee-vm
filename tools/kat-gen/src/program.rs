//! `crates/program`'s fixture: a mul-free program.
//!
//! No program identity is pinned: an identity is a digest over a guest's build,
//! and a pin of it would move with every change to the guest SDK or the
//! protocol. `crates/program/tests/identity.rs` checks the recipe instead.

use std::path::PathBuf;

use crate::isa::{b, i, j, r, s, u};
use crate::loader::ElfBuilder;

pub fn generate() {
    mul_free();
}

/// A program with no M and no A instruction: base loads and stores, both
/// memory families, a branch, a jump, an ecall — so its derived config holds
/// every instruction family except mul/div and atomics.
fn mul_free() {
    let words = [
        i(10, 0, 0b000, 10, 0x13),     // addi a0, zero, 10
        u(0x12, 5, 0x37),              // lui t0, 0x12
        u(0, 6, 0x17),                 // auipc t1, 0
        s(0, 10, 2, 0b010),            // sw a0, 0(sp)
        i(0, 2, 0b010, 11, 0x03),      // lw a1, 0(sp)
        i(1, 2, 0b100, 12, 0x03),      // lbu a2, 1(sp)
        r(0, 12, 11, 0b100, 13, 0x33), // xor a3, a1, a2
        i(2, 13, 0b001, 13, 0x13),     // slli a3, a3, 2
        b(8, 0, 13, 0b000),            // beq a3, zero, +8
        j(4, 0),                       // jal zero, +4
        i(93, 0, 0b000, 17, 0x13),     // addi a7, zero, 93
        0x0000_0073,                   // ecall
    ];
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    std::fs::create_dir_all(repo_root().join("crates/program/tests/vectors"))
        .expect("creating crates/program/tests/vectors");
    crate::write_bytes(
        "crates/program/tests/vectors/mul_free.elf",
        &ElfBuilder::rv32_exec(&text).build(),
    );
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}
