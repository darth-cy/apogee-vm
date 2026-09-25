#![no_std]
#![no_main]
//! S16's tiny guest: a straight-line chain of 32-bit additions and
//! subtractions over the add/sub family's roster — `add`, `sub`, `addi`, `lui`,
//! `auipc`, and the system kind's `fence` and `ecall` — that exits with its
//! result word. It is the one program S16 proves end to end
//! (`docs/spec/shard-proof.md`).
//!
//! Everything in its image is an instruction of that family, which is what
//! lets a proof with one execution family and the two RAM window families
//! claim every pc: no SDK, no `main`, no panic path. The panic handler below
//! is required of a `no_std` binary and is unreachable, so the linker drops it.
//!
//! The chain covers every row shape the family's circuit distinguishes:
//! each kind, with and without a carry or a borrow; `rd = x0`, whose computed
//! value is nonzero and discarded; an operand of `x0`; both instruction
//! lengths, so the decoder's fall-through is `pc + 2` on some rows and `pc + 4`
//! on others; a fence; and the exit.
//!
//! # fd 0, fd 1, fd 2, fd 3
//!
//! Unused. The guest reads nothing and writes nothing.
//!
//! # The result
//!
//! The exit status, `a0`, which is 42: `(t0 + t1) − t1 − t0` wraps twice back
//! to 0, and the compressed rows add 4 and the last `addi` 38. It is below
//! 256 on purpose — Linux, and so `qemu-riscv32`, reports eight bits of an exit
//! status, and that status is what the two executors are held to
//! (`crates/emulator/tests/qemu_outputs.rs`).

use core::arch::global_asm;

global_asm!(
    ".section .text._start,\"ax\",@progbits",
    ".globl _start",
    "_start:",
    ".option norvc",
    // Two operands whose sum carries and whose difference borrows.
    "  lui   t0, 0xfffff",   // t0 = 0xfffff000
    "  addi  t0, t0, -1",    // t0 = 0xffffefff; the addition carries
    "  lui   t1, 0x12345",   // t1 = 0x12345000
    "  addi  t1, t1, 0x678", // t1 = 0x12345678
    "  add   t2, t0, t1",    // t2 = 0x12344677, carrying
    "  add   t3, t1, t1",    // t3 = 0x2468acf0, not carrying
    "  sub   t4, t1, t0",    // t4 = 0x12346679, borrowing
    "  sub   t5, t0, t1",    // t5 = 0xedcb9987, not borrowing
    // Computed values that x0 discards: the circuit still proves them.
    "  add   x0, t0, t1",
    "  sub   x0, t1, t0",
    // The pc as an operand, carrying and not.
    "  auipc t6, 0xfffff", // pc + 0xfffff000, carrying
    "  auipc s1, 0",       // pc
    "  sub   s2, s1, t6",  // 0x1004: the two pcs are four apart
    // A no-op of the system kind.
    "  fence",
    // The compressed forms of the same kinds: two bytes each, so each row's
    // fall-through is pc + 2.
    ".option rvc",
    "  c.li   a1, -3",        // addi a1, x0, -3
    "  c.addi a1, 7",         // a1 = 4, carrying
    "  c.mv   a2, t2",        // add a2, x0, t2
    "  c.add  a2, t4",        // add a2, a2, t4
    "  c.lui  a3, 31",        // lui a3, 31
    "  c.nop",                // addi x0, x0, 0
    "  c.li   sp, 16",        // sp is written before it is read: QEMU starts it elsewhere
    "  c.addi16sp sp, 32",    // sp = 48
    "  c.addi4spn a4, sp, 8", // a4 = 56
    ".option norvc",
    // The result: (t0 + t1) − t1 − t0 = 0, wrapping twice, plus 4, plus 38.
    "  sub   a0, t2, t1", // a0 = t0, borrowing
    "  sub   a0, a0, t0", // a0 = 0
    "  add   a0, a0, a1", // a0 = 4
    "  addi  a0, a0, 38", // a0 = 42
    "  addi  a7, x0, 93", // EXIT
    "  ecall",
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
