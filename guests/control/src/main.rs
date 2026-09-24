#![no_std]
#![no_main]
//! S17's guest: the jump/branch/slt family's twelve instructions — `jal`,
//! `jalr`, the six branches, `slt`, `sltu`, `slti`, `sltiu` — with the
//! operands and control flow the stage's acceptance names, checking every
//! result itself and exiting with the number of checks that passed. It is the
//! one program S17 proves end to end (`docs/spec/jump-branch-slt.md`), and
//! `qemu-riscv32` reaches the same exit status on the same binary.
//!
//! Everything in its image is an instruction of the two families S17 proves,
//! add/sub/lui/auipc and jump/branch/slt, plus the exit ecall: no SDK, no
//! `main`, no panic path. The panic handler below is required of a `no_std`
//! binary and is unreachable, so the linker drops it.
//!
//! The sections, in order:
//!
//! - **comparisons**: `slt` and `sltu` at full width — `0x80000000` against 1
//!   both ways, mixed signs, equal operands, `rd = rs1`;
//! - **`slti` / `sltiu` against −1**, writing `x5`, over a positive, a negative
//!   and an equal `rs1` — the immediate's sign is the comparison's, not
//!   `rs2`'s — and against the largest positive immediate;
//! - **`rd = x0`**: `slt`, `sltu`, `slti`, `sltiu` each computing 1 into `x0`,
//!   then `x0` read back twice in one cycle and compared with 0;
//! - **the branch matrix**: each branch taken and not taken to a forward
//!   target, `BLT(0x80000000, 1)`, `BGE(1, 0x80000000)`,
//!   `BLTU(0x80000000, 1)` and their mirrors among them, equal operands for
//!   every ordering branch, and a taken branch to its own fall-through;
//! - **a loop** closed by a backward branch of −16;
//! - **`jal`**: a forward call whose link is checked, the plain-jump idiom
//!   `jal x0`, and a call with a negative displacement;
//! - **`jalr`** with `rs1 = rd` and a negative immediate that sets bit 0 of
//!   `rs1 + imm`: the target is formed from the old `rs1` with the bit
//!   cleared, the link is written after, and returns are `jalr x0`;
//! - **compressed forms**: `c.beqz` and `c.bnez` taken and not taken, `c.jal`
//!   and `c.jalr`, whose links are `pc + 2`, and `c.jr` and `c.j`.
//!
//! Each section ends by adding 1 to `s0` — each call adds 1 in its callee —
//! and any wrong answer jumps to `fail`.
//!
//! # fd 0, fd 1, fd 2, fd 3
//!
//! Unused. The guest reads nothing and writes nothing.
//!
//! # The result
//!
//! The exit status, `a0`: 16, the number of checks, on success; 1 from `fail`.
//! Both are below 256, which is all of an exit status `qemu-riscv32` reports.

use core::arch::global_asm;

global_asm!(
    ".section .text._start,\"ax\",@progbits",
    ".globl _start",
    "_start:",
    ".option norvc",
    "  addi  s0, x0, 0",
    // Comparisons at full width.
    "  lui   t0, 0x80000", // t0 = 0x80000000
    "  addi  t1, x0, 1",
    "  addi  t2, x0, -1", // t2 = 0xffffffff
    "  slt   t3, t0, t1", // INT_MIN < 1: 1
    "  beq   t3, x0, fail",
    "  addi  s0, s0, 1",
    "  sltu  t3, t0, t1", // 2^31 < 1: 0
    "  bne   t3, x0, fail",
    "  addi  s0, s0, 1",
    "  slt   t3, t2, t1", // -1 < 1: 1, mixed signs
    "  beq   t3, x0, fail",
    "  addi  s0, s0, 1",
    "  slt   t3, t1, t2", // 1 < -1: 0, mixed signs
    "  bne   t3, x0, fail",
    "  addi  s0, s0, 1",
    "  sltu  t3, t1, t2", // 1 < 2^32 - 1: 1
    "  beq   t3, x0, fail",
    "  addi  s0, s0, 1",
    "  slt   t3, t1, t1", // equal: 0
    "  bne   t3, x0, fail",
    "  addi  s0, s0, 1",
    "  slt   t0, t0, t1", // rd = rs1: INT_MIN < 1, so t0 = 1
    "  bne   t0, t1, fail",
    "  addi  s0, s0, 1",
    // slti and sltiu against -1, into x5 (t0).
    "  addi  t1, x0, 5",
    "  slti  t0, t1, -1", // 5 < -1: 0
    "  bne   t0, x0, fail",
    "  sltiu t0, t1, -1", // 5 < 2^32 - 1: 1
    "  beq   t0, x0, fail",
    "  addi  t1, x0, -5",
    "  slti  t0, t1, -1", // -5 < -1: 1
    "  beq   t0, x0, fail",
    "  sltiu t0, t1, -1", // 2^32 - 5 < 2^32 - 1: 1
    "  beq   t0, x0, fail",
    "  addi  t0, x0, -1",
    "  slti  t0, t0, -1", // rs1 = rd = x5: -1 < -1: 0
    "  bne   t0, x0, fail",
    "  addi  t0, x0, -1",
    "  sltiu t0, t0, -1", // equal: 0
    "  bne   t0, x0, fail",
    "  slti  t0, t1, 2047", // -5 < 2047: 1
    "  beq   t0, x0, fail",
    "  sltiu t0, t1, 2047", // 2^32 - 5 < 2047: 0
    "  bne   t0, x0, fail",
    "  addi  s0, s0, 1",
    // rd = x0: each computes 1, and x0 stays 0.
    "  addi  t1, x0, 1",
    "  slt   x0, x0, t1",
    "  sltu  x0, x0, t1",
    "  slti  x0, x0, 1",
    "  sltiu x0, x0, 1",
    "  bne   x0, x0, fail", // x0 read at two slots of one cycle
    "  sltiu t3, x0, 1",    // x0 == 0
    "  beq   t3, x0, fail",
    "  addi  s0, s0, 1",
    // The branch matrix, forward targets.
    "  lui   t0, 0x80000",
    "  addi  t1, x0, 1",
    "  blt   t0, t1, 1f", // BLT(0x80000000, 1): taken
    "  jal   x0, fail",
    "1:",
    "  blt   t1, t0, fail", // BLT(1, 0x80000000): not taken
    "  blt   t1, t1, fail", // equal: not taken
    "  bge   t1, t0, 1f",   // BGE(1, 0x80000000): taken
    "  jal   x0, fail",
    "1:",
    "  bge   t0, t1, fail", // BGE(0x80000000, 1): not taken
    "  bge   t1, t1, 1f",   // equal: taken
    "  jal   x0, fail",
    "1:",
    "  bltu  t0, t1, fail", // BLTU(0x80000000, 1): not taken
    "  bltu  t1, t1, fail", // equal: not taken
    "  bltu  t1, t0, 1f",   // BLTU(1, 0x80000000): taken
    "  jal   x0, fail",
    "1:",
    "  bgeu  t0, t1, 1f", // BGEU(0x80000000, 1): taken
    "  jal   x0, fail",
    "1:",
    "  bgeu  t1, t0, fail", // BGEU(1, 0x80000000): not taken
    "  bgeu  t1, t1, 1f",   // equal: taken
    "  jal   x0, fail",
    "1:",
    "  beq   t1, t1, 1f", // equal: taken
    "  jal   x0, fail",
    "1:",
    "  beq   t0, t1, fail", // unequal: not taken
    "  bne   t1, t1, fail", // equal: not taken
    "  bne   t0, t1, 1f",   // unequal: taken
    "  jal   x0, fail",
    "1:",
    "  beq   x0, x0, 1f", // taken, to its own fall-through
    "1:",
    "  addi  s0, s0, 1",
    // A loop closed by a backward branch of -16: 5 + 4 + 3 + 2 + 1.
    "  addi  t0, x0, 5",
    "  addi  t1, x0, 0",
    "2:",
    "  add   t1, t1, t0",
    "  addi  t0, t0, -1",
    "  addi  t2, t0, 0", // filler: the branch is four words after the head
    "  addi  t3, t1, 0", // filler
    "  bne   t0, x0, 2b",
    "  addi  t2, x0, 15",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1",
    // jal: a forward call, the plain jump, a call backwards.
    "  jal   ra, call_forward",
    "link_forward:",
    "  jal   x0, 3f", // jal x0: the plain-jump idiom
    "call_backward:",
    "  lla   t5, link_backward",
    "  bne   ra, t5, fail",
    "  addi  s0, s0, 1",
    "  jalr  x0, 0(ra)",
    "3:",
    "  jal   ra, call_backward", // a negative displacement
    "link_backward:",
    // jalr with rs1 = rd, a negative immediate, and bit 0 of rs1 + imm set.
    "  lla   t2, jalr_target",
    "  addi  t2, t2, 3",  // the target plus 3
    "  jalr  t2, -2(t2)", // rs1 + imm is the target plus 1: bit 0 dropped
    "link_jalr:",
    "  jal   x0, fail",
    "jalr_target:",
    "  sltiu t3, t2, 1", // t2 holds the link now, which is not 0
    "  bne   t3, x0, fail",
    "  lla   t5, link_jalr",
    "  bne   t2, t5, fail",
    "  addi  s0, s0, 1",
    // Compressed forms: two bytes each, so a link is pc + 2.
    ".option rvc",
    "  c.li   a0, 0",
    "  c.beqz a0, 4f", // taken
    "  c.j    cfail",
    "4:",
    "  c.bnez a0, cfail", // not taken
    "  c.li   a1, 1",
    "  c.bnez a1, 5f", // taken
    "  c.j    cfail",
    "5:",
    "  c.beqz a1, cfail", // not taken
    "  c.jal  ccall",     // link: pc + 2
    "clink:",
    "  lla    t6, ccall2",
    "  c.jalr t6", // link: pc + 2
    "clink2:",
    "  c.j    done", // jal x0
    "cfail:",
    "  jal    x0, fail",
    "ccall:",
    "  lla    t5, clink",
    "  bne    ra, t5, fail",
    "  c.addi s0, 1",
    "  c.jr   ra", // jalr x0, 0(ra)
    "ccall2:",
    "  lla    t5, clink2",
    "  bne    ra, t5, fail",
    "  c.addi s0, 1",
    "  c.jr   ra",
    ".option norvc",
    // The result.
    "done:",
    "  addi  a0, s0, 0",
    "  addi  a7, x0, 93", // EXIT
    "  ecall",
    "fail:",
    "  addi  a0, x0, 1",
    "  addi  a7, x0, 93",
    "  ecall",
    // The forward call's callee.
    "call_forward:",
    "  lla   t5, link_forward",
    "  bne   ra, t5, fail",
    "  addi  s0, s0, 1",
    "  jalr  x0, 0(ra)",
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
