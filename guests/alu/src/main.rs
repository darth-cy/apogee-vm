#![no_std]
#![no_main]
//! S18's guest: the shift/bitwise family's twelve instructions and the mul/div
//! family's eight, with the operands the stage's acceptance names, checking
//! every result itself and exiting with the number of checks that passed. It
//! is the program S18 proves end to end (`docs/spec/shift-bitwise.md`,
//! `docs/spec/mul-div.md`), and `qemu-riscv32` reaches the same exit status on
//! the same binary.
//!
//! Everything in its image is an instruction of the four families S18 proves —
//! add/sub/lui/auipc, jump/branch/slt, shift/bitwise and mul/div — plus the
//! exit ecall: no SDK, no `main`, no panic path. The panic handler below is
//! required of a `no_std` binary and is unreachable, so the linker drops it.
//!
//! Every expected value below was computed from an exact RV32IM model, not by
//! hand; the emulator, `qemu-riscv32` and the guest's own checks are three
//! independent readings of what the twenty instructions compute.
//!
//! The sections, in order:
//!
//! - **bitwise**: `and`, `or`, `xor` over patterns covering every bit position
//!   of every byte, and their immediate forms, whose immediate is sign
//!   extended before the operation — so `andi x, −1` masks against all ones;
//! - **immediate shifts** at shamt 0, 1 and 31, and `srai` against `srli` on
//!   the same negative operand at the same shamt (acceptance 2);
//! - **register shifts**, whose amount is the low five bits of the whole word:
//!   `rs2 = 32` shifts by 0 and `rs2 = 33` by 1, which is what the truncation
//!   is for, and `sra` of a negative operand at 0, 1 and 31;
//! - **the signed-multiply matrix**: all four sign quadrants of each of the
//!   four multiplies, `−2^31 × −2^31`, the asymmetric `mulhsu` corner
//!   `−2^31 × (2^32 − 1)`, and `mulhu` just under `2^64` (acceptance 3);
//! - **the div/rem matrix**: all four sign quadrants of `div` and `rem`, the
//!   unsigned pair, division by zero for all four, and the one signed
//!   overflow `−2^31 ÷ −1` (acceptance 4). `DIV(−7, 2)` and `REM(−7, 2)` are
//!   the rows a *floored* quotient would also satisfy the bare division
//!   identity on: the answer is −3 and −1, not −4 and 1;
//! - **`rd = x0`** in each family, with `x0` read back and compared with 0
//!   (acceptance 9);
//! - **compressed forms**: `c.and`, `c.or`, `c.xor`, `c.slli`, `c.srli`,
//!   `c.srai` and `c.andi`, so the family's decoded rows carry a fall-through
//!   of `pc + 2` as well as `pc + 4`.
//!
//! Each check adds 1 to `s0`, and any wrong answer jumps to `fail`.
//!
//! # fd 0, fd 1, fd 2, fd 3
//!
//! Unused. The guest reads nothing and writes nothing.
//!
//! # The result
//!
//! The exit status, `a0`: 96, the number of checks, on success; 1 from `fail`.
//! Both are below 256, which is all of an exit status `qemu-riscv32` reports.

use core::arch::global_asm;

global_asm!(
    ".section .text._start,\"ax\",@progbits",
    ".globl _start",
    "_start:",
    ".option norvc",
    "  addi  s0, x0, 0",
    // Bitwise, register-register: every bit position of every byte covered
    // by the two patterns, and the byte table's domain is what bounds them.
    "  li    t0, 0xf0f00ff0",
    "  li    t1, 0x0ff0f00f",
    "  and    t2, t0, t1",
    "  li    t3, 0x00f00000", // and 0xf0f00ff0, 0x0ff0f00f = 0x00f00000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xf0f00ff0",
    "  li    t1, 0x0ff0f00f",
    "  or     t2, t0, t1",
    "  li    t3, 0xfff0ffff", // or 0xf0f00ff0, 0x0ff0f00f = 0xfff0ffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xf0f00ff0",
    "  li    t1, 0x0ff0f00f",
    "  xor    t2, t0, t1",
    "  li    t3, 0xff00ffff", // xor 0xf0f00ff0, 0x0ff0f00f = 0xff00ffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff",
    "  li    t1, 0x00000000",
    "  and    t2, t0, t1",
    "  li    t3, 0x00000000", // and 0xffffffff, 0x00000000 = 0x00000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000000",
    "  li    t1, 0xffffffff",
    "  or     t2, t0, t1",
    "  li    t3, 0xffffffff", // or 0x00000000, 0xffffffff = 0xffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff",
    "  li    t1, 0xffffffff",
    "  xor    t2, t0, t1",
    "  li    t3, 0x00000000", // xor 0xffffffff, 0xffffffff = 0x00000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // Bitwise, register-immediate: the immediate is sign extended before the
    // operation, so a negative one masks against all ones in the high half.
    "  li    t0, 0x12345678",
    "  andi   t2, t0, -1",
    "  li    t3, 0x12345678", // andi 0x12345678, -1 = 0x12345678
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345678",
    "  andi   t2, t0, 2047",
    "  li    t3, 0x00000678", // andi 0x12345678, 2047 = 0x00000678
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345678",
    "  ori    t2, t0, -2048",
    "  li    t3, 0xfffffe78", // ori 0x12345678, -2048 = 0xfffffe78
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345678",
    "  xori   t2, t0, -1",
    "  li    t3, 0xedcba987", // xori 0x12345678, -1 = 0xedcba987  the ones' complement
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345678",
    "  ori    t2, t0, 0",
    "  li    t3, 0x12345678", // ori 0x12345678, 0 = 0x12345678
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345678",
    "  xori   t2, t0, 2047",
    "  li    t3, 0x12345187", // xori 0x12345678, 2047 = 0x12345187
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // Immediate shifts at shamt 0, 1 and 31 (S18 acceptance 2).
    "  li    t0, 0x12345679",
    "  slli   t2, t0, 0",
    "  li    t3, 0x12345679", // slli 0x12345679, 0 = 0x12345679
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345679",
    "  slli   t2, t0, 1",
    "  li    t3, 0x2468acf2", // slli 0x12345679, 1 = 0x2468acf2
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345679",
    "  slli   t2, t0, 31",
    "  li    t3, 0x80000000", // slli 0x12345679, 31 = 0x80000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345679",
    "  srli   t2, t0, 0",
    "  li    t3, 0x12345679", // srli 0x12345679, 0 = 0x12345679
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345679",
    "  srli   t2, t0, 1",
    "  li    t3, 0x091a2b3c", // srli 0x12345679, 1 = 0x091a2b3c
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345679",
    "  srli   t2, t0, 31",
    "  li    t3, 0x00000000", // srli 0x12345679, 31 = 0x00000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345679",
    "  srai   t2, t0, 0",
    "  li    t3, 0x12345679", // srai 0x12345679, 0 = 0x12345679
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345679",
    "  srai   t2, t0, 1",
    "  li    t3, 0x091a2b3c", // srai 0x12345679, 1 = 0x091a2b3c
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345679",
    "  srai   t2, t0, 31",
    "  li    t3, 0x00000000", // srai 0x12345679, 31 = 0x00000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // SRAI against SRLI on the same negative operand, at the same shamt.
    "  li    t0, 0xfedcba98",
    "  srli   t2, t0, 4",
    "  li    t3, 0x0fedcba9", // srli 0xfedcba98, 4 = 0x0fedcba9
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba98",
    "  srai   t2, t0, 4",
    "  li    t3, 0xffedcba9", // srai 0xfedcba98, 4 = 0xffedcba9  the sign replicated
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba98",
    "  srli   t2, t0, 31",
    "  li    t3, 0x00000001", // srli 0xfedcba98, 31 = 0x00000001
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba98",
    "  srai   t2, t0, 31",
    "  li    t3, 0xffffffff", // srai 0xfedcba98, 31 = 0xffffffff  the sign replicated
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // Register shifts, whose amount is the low five bits of the WHOLE word:
    // 32 shifts by 0 and 33 by 1, which is what the truncation is for.
    "  li    t0, 0xfedcba98",
    "  li    t1, 0x00000020",
    "  sll    t2, t0, t1",
    "  li    t3, 0xfedcba98", // sll 0xfedcba98, 0x00000020 = 0xfedcba98
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba98",
    "  li    t1, 0x00000021",
    "  sll    t2, t0, t1",
    "  li    t3, 0xfdb97530", // sll 0xfedcba98, 0x00000021 = 0xfdb97530
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba98",
    "  li    t1, 0x00000020",
    "  srl    t2, t0, t1",
    "  li    t3, 0xfedcba98", // srl 0xfedcba98, 0x00000020 = 0xfedcba98
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba98",
    "  li    t1, 0x00000021",
    "  srl    t2, t0, t1",
    "  li    t3, 0x7f6e5d4c", // srl 0xfedcba98, 0x00000021 = 0x7f6e5d4c
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba98",
    "  li    t1, 0x00000020",
    "  sra    t2, t0, t1",
    "  li    t3, 0xfedcba98", // sra 0xfedcba98, 0x00000020 = 0xfedcba98
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba98",
    "  li    t1, 0x00000021",
    "  sra    t2, t0, t1",
    "  li    t3, 0xff6e5d4c", // sra 0xfedcba98, 0x00000021 = 0xff6e5d4c
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345679",
    "  li    t1, 0x0000001f",
    "  sll    t2, t0, t1",
    "  li    t3, 0x80000000", // sll 0x12345679, 0x0000001f = 0x80000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x12345679",
    "  li    t1, 0x00000000",
    "  srl    t2, t0, t1",
    "  li    t3, 0x12345679", // srl 0x12345679, 0x00000000 = 0x12345679
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba98",
    "  li    t1, 0x00000000",
    "  sra    t2, t0, t1",
    "  li    t3, 0xfedcba98", // sra 0xfedcba98, 0x00000000 = 0xfedcba98  shamt 0 leaves the word alone
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba98",
    "  li    t1, 0x0000001f",
    "  sra    t2, t0, t1",
    "  li    t3, 0xffffffff", // sra 0xfedcba98, 0x0000001f = 0xffffffff  every bit the sign bit
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff",
    "  li    t1, 0xdeadbee4",
    "  sll    t2, t0, t1",
    "  li    t3, 0xfffffff0", // sll 0xffffffff, 0xdeadbee4 = 0xfffffff0  amount 4, the high bits ignored
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // The signed-multiply matrix: all four sign quadrants of each of the
    // four multiplies (S18 acceptance 3).
    "  li    t0, 0x00000007",
    "  li    t1, 0x00000003",
    "  mul    t2, t0, t1",
    "  li    t3, 0x00000015", // mul 0x00000007, 0x00000003 = 0x00000015
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0x00000003",
    "  mul    t2, t0, t1",
    "  li    t3, 0xffffffeb", // mul 0xfffffff9, 0x00000003 = 0xffffffeb
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000007",
    "  li    t1, 0xfffffffd",
    "  mul    t2, t0, t1",
    "  li    t3, 0xffffffeb", // mul 0x00000007, 0xfffffffd = 0xffffffeb
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0xfffffffd",
    "  mul    t2, t0, t1",
    "  li    t3, 0x00000015", // mul 0xfffffff9, 0xfffffffd = 0x00000015
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000007",
    "  li    t1, 0x00000003",
    "  mulh   t2, t0, t1",
    "  li    t3, 0x00000000", // mulh 0x00000007, 0x00000003 = 0x00000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0x00000003",
    "  mulh   t2, t0, t1",
    "  li    t3, 0xffffffff", // mulh 0xfffffff9, 0x00000003 = 0xffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000007",
    "  li    t1, 0xfffffffd",
    "  mulh   t2, t0, t1",
    "  li    t3, 0xffffffff", // mulh 0x00000007, 0xfffffffd = 0xffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0xfffffffd",
    "  mulh   t2, t0, t1",
    "  li    t3, 0x00000000", // mulh 0xfffffff9, 0xfffffffd = 0x00000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000007",
    "  li    t1, 0x00000003",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0x00000000", // mulhsu 0x00000007, 0x00000003 = 0x00000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0x00000003",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0xffffffff", // mulhsu 0xfffffff9, 0x00000003 = 0xffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000007",
    "  li    t1, 0xfffffffd",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0x00000006", // mulhsu 0x00000007, 0xfffffffd = 0x00000006
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0xfffffffd",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0xfffffff9", // mulhsu 0xfffffff9, 0xfffffffd = 0xfffffff9
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000007",
    "  li    t1, 0x00000003",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0x00000000", // mulhu 0x00000007, 0x00000003 = 0x00000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0x00000003",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0x00000002", // mulhu 0xfffffff9, 0x00000003 = 0x00000002
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000007",
    "  li    t1, 0xfffffffd",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0x00000006", // mulhu 0x00000007, 0xfffffffd = 0x00000006
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0xfffffffd",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0xfffffff6", // mulhu 0xfffffff9, 0xfffffffd = 0xfffffff6
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // The named edge cases: INT_MIN squared, MULHSU's asymmetric corner, and
    // MULHU just under 2^64.
    "  li    t0, 0x80000000",
    "  li    t1, 0x80000000",
    "  mul    t2, t0, t1",
    "  li    t3, 0x00000000", // mul 0x80000000, 0x80000000 = 0x00000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0x80000000",
    "  mulh   t2, t0, t1",
    "  li    t3, 0x40000000", // mulh 0x80000000, 0x80000000 = 0x40000000  2^62 >> 32
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0xffffffff",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0x80000000", // mulhsu 0x80000000, 0xffffffff = 0x80000000  signed x unsigned
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0xffffffff",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0x7fffffff", // mulhu 0x80000000, 0xffffffff = 0x7fffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff",
    "  li    t1, 0xffffffff",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0xfffffffe", // mulhu 0xffffffff, 0xffffffff = 0xfffffffe  (2^32-1)^2 >> 32
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff",
    "  li    t1, 0xffffffff",
    "  mul    t2, t0, t1",
    "  li    t3, 0x00000001", // mul 0xffffffff, 0xffffffff = 0x00000001  the low half is sign agnostic
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0x7fffffff",
    "  mulh   t2, t0, t1",
    "  li    t3, 0xc0000000", // mulh 0x80000000, 0x7fffffff = 0xc0000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff",
    "  li    t1, 0x00000001",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0xffffffff", // mulhsu 0xffffffff, 0x00000001 = 0xffffffff  -1 x 1, high half -1
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // The div/rem matrix: all four sign quadrants (S18 acceptance 4). The
    // negative-dividend rows are the ones a floored quotient would also
    // satisfy the bare division identity on: DIV(-7, 2) is -3, not -4.
    "  li    t0, 0x00000007",
    "  li    t1, 0x00000003",
    "  div    t2, t0, t1",
    "  li    t3, 0x00000002", // div 0x00000007, 0x00000003 = 0x00000002
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0x00000003",
    "  div    t2, t0, t1",
    "  li    t3, 0xfffffffe", // div 0xfffffff9, 0x00000003 = 0xfffffffe
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000007",
    "  li    t1, 0xfffffffd",
    "  div    t2, t0, t1",
    "  li    t3, 0xfffffffe", // div 0x00000007, 0xfffffffd = 0xfffffffe
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0xfffffffd",
    "  div    t2, t0, t1",
    "  li    t3, 0x00000002", // div 0xfffffff9, 0xfffffffd = 0x00000002
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0x00000002",
    "  div    t2, t0, t1",
    "  li    t3, 0xfffffffd", // div 0xfffffff9, 0x00000002 = 0xfffffffd
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffa",
    "  li    t1, 0x00000002",
    "  div    t2, t0, t1",
    "  li    t3, 0xfffffffd", // div 0xfffffffa, 0x00000002 = 0xfffffffd
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000007",
    "  li    t1, 0x00000003",
    "  rem    t2, t0, t1",
    "  li    t3, 0x00000001", // rem 0x00000007, 0x00000003 = 0x00000001
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0x00000003",
    "  rem    t2, t0, t1",
    "  li    t3, 0xffffffff", // rem 0xfffffff9, 0x00000003 = 0xffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000007",
    "  li    t1, 0xfffffffd",
    "  rem    t2, t0, t1",
    "  li    t3, 0x00000001", // rem 0x00000007, 0xfffffffd = 0x00000001
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0xfffffffd",
    "  rem    t2, t0, t1",
    "  li    t3, 0xffffffff", // rem 0xfffffff9, 0xfffffffd = 0xffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffff9",
    "  li    t1, 0x00000002",
    "  rem    t2, t0, t1",
    "  li    t3, 0xffffffff", // rem 0xfffffff9, 0x00000002 = 0xffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffa",
    "  li    t1, 0x00000002",
    "  rem    t2, t0, t1",
    "  li    t3, 0x00000000", // rem 0xfffffffa, 0x00000002 = 0x00000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000007",
    "  li    t1, 0x00000003",
    "  divu   t2, t0, t1",
    "  li    t3, 0x00000002", // divu 0x00000007, 0x00000003 = 0x00000002
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef",
    "  li    t1, 0x00001234",
    "  divu   t2, t0, t1",
    "  li    t3, 0x000c3ba5", // divu 0xdeadbeef, 0x00001234 = 0x000c3ba5
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff",
    "  li    t1, 0x00000001",
    "  divu   t2, t0, t1",
    "  li    t3, 0xffffffff", // divu 0xffffffff, 0x00000001 = 0xffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000003",
    "  li    t1, 0x00000007",
    "  divu   t2, t0, t1",
    "  li    t3, 0x00000000", // divu 0x00000003, 0x00000007 = 0x00000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000007",
    "  li    t1, 0x00000003",
    "  remu   t2, t0, t1",
    "  li    t3, 0x00000001", // remu 0x00000007, 0x00000003 = 0x00000001
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef",
    "  li    t1, 0x00001234",
    "  remu   t2, t0, t1",
    "  li    t3, 0x0000076b", // remu 0xdeadbeef, 0x00001234 = 0x0000076b
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff",
    "  li    t1, 0x00000001",
    "  remu   t2, t0, t1",
    "  li    t3, 0x00000000", // remu 0xffffffff, 0x00000001 = 0x00000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x00000003",
    "  li    t1, 0x00000007",
    "  remu   t2, t0, t1",
    "  li    t3, 0x00000003", // remu 0x00000003, 0x00000007 = 0x00000003
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // Division by zero, all four, and the one signed overflow.
    "  li    t0, 0xdeadbeef",
    "  li    t1, 0x00000000",
    "  div    t2, t0, t1",
    "  li    t3, 0xffffffff", // div 0xdeadbeef, 0x00000000 = 0xffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef",
    "  li    t1, 0x00000000",
    "  divu   t2, t0, t1",
    "  li    t3, 0xffffffff", // divu 0xdeadbeef, 0x00000000 = 0xffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef",
    "  li    t1, 0x00000000",
    "  rem    t2, t0, t1",
    "  li    t3, 0xdeadbeef", // rem 0xdeadbeef, 0x00000000 = 0xdeadbeef
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef",
    "  li    t1, 0x00000000",
    "  remu   t2, t0, t1",
    "  li    t3, 0xdeadbeef", // remu 0xdeadbeef, 0x00000000 = 0xdeadbeef
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0x00000000",
    "  div    t2, t0, t1",
    "  li    t3, 0xffffffff", // div 0x80000000, 0x00000000 = 0xffffffff  a negative dividend by zero
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0x00000000",
    "  rem    t2, t0, t1",
    "  li    t3, 0x80000000", // rem 0x80000000, 0x00000000 = 0x80000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0xffffffff",
    "  div    t2, t0, t1",
    "  li    t3, 0x80000000", // div 0x80000000, 0xffffffff = 0x80000000  INT_MIN / -1 wraps to INT_MIN
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0xffffffff",
    "  rem    t2, t0, t1",
    "  li    t3, 0x00000000", // rem 0x80000000, 0xffffffff = 0x00000000  and leaves no remainder
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // A destination of x0 in each family: the row is proven, and x0 keeps
    // its zero (S18 acceptance 9).
    "  li    t0, 0x12345679",
    "  li    t1, 5",
    "  sll   x0, t0, t1",
    "  and   x0, t0, t1",
    "  mul   x0, t0, t1",
    "  div   x0, t0, t1",
    "  li    t3, 0",
    "  bne   x0, t3, fail",
    "  addi  s0, s0, 1",
    // The compressed forms of both halves: seven two-byte instructions, so
    // the family's decoded rows carry a fall-through of pc + 2 as well as
    // pc + 4. c.slli takes any register; the rest take x8..x15.
    ".option rvc",
    "  li     a4, 0x0ff0f00f",
    "  li     a5, 0xf0f00ff0",
    "  c.and  a5, a4",
    "  li     a3, 0x00f00000", // c.and = 0x00f00000
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
    "  li     a5, 0xf0f00ff0",
    "  c.or   a5, a4",
    "  li     a3, 0xfff0ffff", // c.or = 0xfff0ffff
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
    "  li     a5, 0xf0f00ff0",
    "  c.xor  a5, a4",
    "  li     a3, 0xff00ffff", // c.xor = 0xff00ffff
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
    "  li     a5, 0x12345679",
    "  c.slli a5, 3",
    "  li     a3, 0x91a2b3c8", // c.slli 3 = 0x91a2b3c8
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
    "  li     a5, 0xfedcba98",
    "  c.srli a5, 1",
    "  li     a3, 0x7f6e5d4c", // c.srli 1 = 0x7f6e5d4c
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
    "  li     a5, 0xfedcba98",
    "  c.srai a5, 2",
    "  li     a3, 0xffb72ea6", // c.srai 2 = 0xffb72ea6
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
    "  li     a5, 0x1234567b",
    "  c.andi a5, -3",
    "  li     a3, 0x12345679", // c.andi -3 = 0x12345679
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
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
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
