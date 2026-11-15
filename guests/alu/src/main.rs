#![no_std]
#![no_main]
//! The bitwise family's six instructions and the mul/div family's twenty-five —
//! the M extension, its W forms, and every shift — at the operands where each
//! is easiest to get wrong, checking every result itself and exiting with the
//! number of checks that passed. `crates/prover/tests/alu.rs` proves it end to
//! end (`docs/spec/bitwise.md`, `docs/spec/mul-div.md`).
//!
//! Everything in its image is an instruction of four execution families —
//! add/sub/lui/auipc, jump/branch/slt, bitwise and mul/div — plus the exit
//! ecall: no SDK, no `main`, no panic path. The panic handler below is
//! required of a `no_std` binary and is unreachable, so the linker drops it.
//!
//! Every expected value below was computed from an exact RV64IM model, not by
//! hand; the emulator and the guest's own checks are two independent readings
//! of the same instructions.
//!
//! The sections, in order:
//!
//! - **bitwise**: `and`, `or`, `xor` over patterns covering every bit position
//!   of every byte of both words, and their immediate forms, whose immediate
//!   is sign extended to 64 bits before the operation;
//! - **immediate shifts** at shamt 0, 1, 31, 32 and 63, and `srai` against
//!   `srli` on the same negative operand;
//! - **register shifts**, whose amount is the low six bits of `rs2`: 64 shifts
//!   by 0 and 65 by 1;
//! - **the W shifts**, which read `rs1`'s low word under garbage high bits,
//!   take the low five bits of the amount, and sign-extend their result;
//! - **the signed-multiply matrix**: all four sign quadrants of each of the
//!   four multiplies, `−2^63 × −2^63`, the asymmetric `mulhsu` corner
//!   `−2^63 × (2^64 − 1)`, and `mulhu` just under `2^128`;
//! - **the div/rem matrix**: all four sign quadrants of `div` and `rem` —
//!   `DIV(−7, 2)` is −3 and `REM(−7, 2)` −1, not the floored −4 and 1 — the
//!   unsigned pair over full words, division by zero, and the one signed
//!   overflow `−2^63 ÷ −1`;
//! - **the W forms of M**, over the low words, division by zero and
//!   `−2^31 ÷ −1` among them;
//! - **`rd = x0`** in each family, the row proven and its value discarded,
//!   with `x0` read back and compared with 0;
//! - **compressed forms**: `c.and`, `c.or`, `c.xor`, `c.slli` and `c.srli`
//!   with amounts above 31, `c.srai` and `c.andi`, so the families' decoded
//!   rows carry a fall-through of `pc + 2` as well as `pc + 4`.
//!
//! Each check adds 1 to `s0`, and any wrong answer jumps to `fail`.
//!
//! # Input, advice and the journal
//!
//! Unused. The guest reads nothing and commits nothing: `EXIT` is its only
//! ecall, and its result is the status.
//!
//! # The result
//!
//! The exit status, `a0`: 144, the number of checks, on success; 1 from
//! `fail`.

use core::arch::global_asm;

global_asm!(
    ".section .text._start,\"ax\",@progbits",
    ".globl _start",
    "_start:",
    ".option norvc",
    "  addi  s0, x0, 0",
    // Bitwise, register-register: every bit position of every byte of both
    // words covered by the two patterns, and all ones against all zeros.
    "  li    t0, 0xf0f00ff00ff0f00f",
    "  li    t1, 0xf0ff0f0f00f0f0f",
    "  and    t2, t0, t1",
    "  li    t3, 0xf00000000f", // and 0xf0f00ff00ff0f00f, 0xf0ff0f0f00f0f0f = 0xf00000000f
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0x0",
    "  and    t2, t0, t1",
    "  li    t3, 0x0", // and 0xffffffffffffffff, 0x0 = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xf0f00ff00ff0f00f",
    "  li    t1, 0xf0ff0f0f00f0f0f",
    "  or     t2, t0, t1",
    "  li    t3, 0xfffffff0ffffff0f", // or 0xf0f00ff00ff0f00f, 0xf0ff0f0f00f0f0f = 0xfffffff0ffffff0f
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0x0",
    "  or     t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // or 0xffffffffffffffff, 0x0 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xf0f00ff00ff0f00f",
    "  li    t1, 0xf0ff0f0f00f0f0f",
    "  xor    t2, t0, t1",
    "  li    t3, 0xffffff00ffffff00", // xor 0xf0f00ff00ff0f00f, 0xf0ff0f0f00f0f0f = 0xffffff00ffffff00
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0xffffffffffffffff",
    "  xor    t2, t0, t1",
    "  li    t3, 0x0", // xor 0xffffffffffffffff, 0xffffffffffffffff = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // Bitwise, register-immediate: the immediate is sign extended to 64 bits,
    // so a negative one masks against all ones in the high word.
    "  li    t0, 0x123456789abcdef0",
    "  andi   t2, t0, -1",
    "  li    t3, 0x123456789abcdef0", // andi 0x123456789abcdef0, -1 = 0x123456789abcdef0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef0",
    "  andi   t2, t0, 2047",
    "  li    t3, 0x6f0", // andi 0x123456789abcdef0, 2047 = 0x6f0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef0",
    "  ori    t2, t0, -2048",
    "  li    t3, 0xfffffffffffffef0", // ori 0x123456789abcdef0, -2048 = 0xfffffffffffffef0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef0",
    "  xori   t2, t0, -1",
    "  li    t3, 0xedcba9876543210f", // xori 0x123456789abcdef0, -1 = 0xedcba9876543210f
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef0",
    "  ori    t2, t0, 0",
    "  li    t3, 0x123456789abcdef0", // ori 0x123456789abcdef0, 0 = 0x123456789abcdef0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef0",
    "  xori   t2, t0, 2047",
    "  li    t3, 0x123456789abcd90f", // xori 0x123456789abcdef0, 2047 = 0x123456789abcd90f
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // Immediate shifts at shamt 0, 1, 31, 32 and 63, and srai against srli on
    // the same negative operand.
    "  li    t0, 0xfedcba9876543210",
    "  slli   t2, t0, 0",
    "  li    t3, 0xfedcba9876543210", // slli 0xfedcba9876543210, 0 = 0xfedcba9876543210
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  slli   t2, t0, 1",
    "  li    t3, 0xfdb97530eca86420", // slli 0xfedcba9876543210, 1 = 0xfdb97530eca86420
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  slli   t2, t0, 31",
    "  li    t3, 0x3b2a190800000000", // slli 0xfedcba9876543210, 31 = 0x3b2a190800000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  slli   t2, t0, 32",
    "  li    t3, 0x7654321000000000", // slli 0xfedcba9876543210, 32 = 0x7654321000000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  slli   t2, t0, 63",
    "  li    t3, 0x0", // slli 0xfedcba9876543210, 63 = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  srli   t2, t0, 0",
    "  li    t3, 0xfedcba9876543210", // srli 0xfedcba9876543210, 0 = 0xfedcba9876543210
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  srli   t2, t0, 1",
    "  li    t3, 0x7f6e5d4c3b2a1908", // srli 0xfedcba9876543210, 1 = 0x7f6e5d4c3b2a1908
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  srli   t2, t0, 31",
    "  li    t3, 0x1fdb97530", // srli 0xfedcba9876543210, 31 = 0x1fdb97530
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  srli   t2, t0, 32",
    "  li    t3, 0xfedcba98", // srli 0xfedcba9876543210, 32 = 0xfedcba98
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  srli   t2, t0, 63",
    "  li    t3, 0x1", // srli 0xfedcba9876543210, 63 = 0x1
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  srai   t2, t0, 0",
    "  li    t3, 0xfedcba9876543210", // srai 0xfedcba9876543210, 0 = 0xfedcba9876543210
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  srai   t2, t0, 1",
    "  li    t3, 0xff6e5d4c3b2a1908", // srai 0xfedcba9876543210, 1 = 0xff6e5d4c3b2a1908
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  srai   t2, t0, 31",
    "  li    t3, 0xfffffffffdb97530", // srai 0xfedcba9876543210, 31 = 0xfffffffffdb97530
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  srai   t2, t0, 32",
    "  li    t3, 0xfffffffffedcba98", // srai 0xfedcba9876543210, 32 = 0xfffffffffedcba98
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  srai   t2, t0, 63",
    "  li    t3, 0xffffffffffffffff", // srai 0xfedcba9876543210, 63 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // Register shifts take the low six bits of rs2: 64 shifts by 0 and 65 by 1.
    "  li    t0, 0xfedcba9876543210",
    "  li    t1, 0x1",
    "  sll    t2, t0, t1",
    "  li    t3, 0xfdb97530eca86420", // sll 0xfedcba9876543210, 0x1 = 0xfdb97530eca86420
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  li    t1, 0x21",
    "  sll    t2, t0, t1",
    "  li    t3, 0xeca8642000000000", // sll 0xfedcba9876543210, 0x21 = 0xeca8642000000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  li    t1, 0x40",
    "  sll    t2, t0, t1",
    "  li    t3, 0xfedcba9876543210", // sll 0xfedcba9876543210, 0x40 = 0xfedcba9876543210
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  li    t1, 0x41",
    "  sll    t2, t0, t1",
    "  li    t3, 0xfdb97530eca86420", // sll 0xfedcba9876543210, 0x41 = 0xfdb97530eca86420
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  li    t1, 0x1",
    "  srl    t2, t0, t1",
    "  li    t3, 0x7f6e5d4c3b2a1908", // srl 0xfedcba9876543210, 0x1 = 0x7f6e5d4c3b2a1908
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  li    t1, 0x21",
    "  srl    t2, t0, t1",
    "  li    t3, 0x7f6e5d4c", // srl 0xfedcba9876543210, 0x21 = 0x7f6e5d4c
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  li    t1, 0x40",
    "  srl    t2, t0, t1",
    "  li    t3, 0xfedcba9876543210", // srl 0xfedcba9876543210, 0x40 = 0xfedcba9876543210
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  li    t1, 0x41",
    "  srl    t2, t0, t1",
    "  li    t3, 0x7f6e5d4c3b2a1908", // srl 0xfedcba9876543210, 0x41 = 0x7f6e5d4c3b2a1908
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  li    t1, 0x1",
    "  sra    t2, t0, t1",
    "  li    t3, 0xff6e5d4c3b2a1908", // sra 0xfedcba9876543210, 0x1 = 0xff6e5d4c3b2a1908
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  li    t1, 0x21",
    "  sra    t2, t0, t1",
    "  li    t3, 0xffffffffff6e5d4c", // sra 0xfedcba9876543210, 0x21 = 0xffffffffff6e5d4c
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  li    t1, 0x40",
    "  sra    t2, t0, t1",
    "  li    t3, 0xfedcba9876543210", // sra 0xfedcba9876543210, 0x40 = 0xfedcba9876543210
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfedcba9876543210",
    "  li    t1, 0x41",
    "  sra    t2, t0, t1",
    "  li    t3, 0xff6e5d4c3b2a1908", // sra 0xfedcba9876543210, 0x41 = 0xff6e5d4c3b2a1908
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // The W shifts read rs1's low word and sign-extend their result: 0x...80000001
    // under garbage high bits, and the amount the low five bits of rs2.
    "  li    t0, 0xdeadbeef80000001",
    "  slliw  t2, t0, 0",
    "  li    t3, 0xffffffff80000001", // slliw 0xdeadbeef80000001, 0 = 0xffffffff80000001
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  slliw  t2, t0, 1",
    "  li    t3, 0x2", // slliw 0xdeadbeef80000001, 1 = 0x2
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  slliw  t2, t0, 31",
    "  li    t3, 0xffffffff80000000", // slliw 0xdeadbeef80000001, 31 = 0xffffffff80000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  srliw  t2, t0, 0",
    "  li    t3, 0xffffffff80000001", // srliw 0xdeadbeef80000001, 0 = 0xffffffff80000001
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  srliw  t2, t0, 1",
    "  li    t3, 0x40000000", // srliw 0xdeadbeef80000001, 1 = 0x40000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  srliw  t2, t0, 31",
    "  li    t3, 0x1", // srliw 0xdeadbeef80000001, 31 = 0x1
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  sraiw  t2, t0, 0",
    "  li    t3, 0xffffffff80000001", // sraiw 0xdeadbeef80000001, 0 = 0xffffffff80000001
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  sraiw  t2, t0, 1",
    "  li    t3, 0xffffffffc0000000", // sraiw 0xdeadbeef80000001, 1 = 0xffffffffc0000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  sraiw  t2, t0, 31",
    "  li    t3, 0xffffffffffffffff", // sraiw 0xdeadbeef80000001, 31 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  li    t1, 0x1",
    "  sllw   t2, t0, t1",
    "  li    t3, 0x2", // sllw 0xdeadbeef80000001, 0x1 = 0x2
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  li    t1, 0x20",
    "  sllw   t2, t0, t1",
    "  li    t3, 0xffffffff80000001", // sllw 0xdeadbeef80000001, 0x20 = 0xffffffff80000001
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  li    t1, 0x21",
    "  sllw   t2, t0, t1",
    "  li    t3, 0x2", // sllw 0xdeadbeef80000001, 0x21 = 0x2
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  li    t1, 0x1",
    "  srlw   t2, t0, t1",
    "  li    t3, 0x40000000", // srlw 0xdeadbeef80000001, 0x1 = 0x40000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  li    t1, 0x20",
    "  srlw   t2, t0, t1",
    "  li    t3, 0xffffffff80000001", // srlw 0xdeadbeef80000001, 0x20 = 0xffffffff80000001
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  li    t1, 0x21",
    "  srlw   t2, t0, t1",
    "  li    t3, 0x40000000", // srlw 0xdeadbeef80000001, 0x21 = 0x40000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  li    t1, 0x1",
    "  sraw   t2, t0, t1",
    "  li    t3, 0xffffffffc0000000", // sraw 0xdeadbeef80000001, 0x1 = 0xffffffffc0000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  li    t1, 0x20",
    "  sraw   t2, t0, t1",
    "  li    t3, 0xffffffff80000001", // sraw 0xdeadbeef80000001, 0x20 = 0xffffffff80000001
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000001",
    "  li    t1, 0x21",
    "  sraw   t2, t0, t1",
    "  li    t3, 0xffffffffc0000000", // sraw 0xdeadbeef80000001, 0x21 = 0xffffffffc0000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // The signed-multiply matrix: the four sign quadrants of each multiply, the
    // most negative value squared, mulhsu's asymmetric corner and mulhu just under
    // 2^128.
    "  li    t0, 0x7",
    "  li    t1, 0x9",
    "  mul    t2, t0, t1",
    "  li    t3, 0x3f", // mul 0x7, 0x9 = 0x3f
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0x9",
    "  mul    t2, t0, t1",
    "  li    t3, 0xffffffffffffffc1", // mul 0xfffffffffffffff9, 0x9 = 0xffffffffffffffc1
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0xfffffffffffffff7",
    "  mul    t2, t0, t1",
    "  li    t3, 0xffffffffffffffc1", // mul 0x7, 0xfffffffffffffff7 = 0xffffffffffffffc1
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0xfffffffffffffff7",
    "  mul    t2, t0, t1",
    "  li    t3, 0x3f", // mul 0xfffffffffffffff9, 0xfffffffffffffff7 = 0x3f
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x8000000000000000",
    "  li    t1, 0x8000000000000000",
    "  mul    t2, t0, t1",
    "  li    t3, 0x0", // mul 0x8000000000000000, 0x8000000000000000 = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x8000000000000000",
    "  li    t1, 0xffffffffffffffff",
    "  mul    t2, t0, t1",
    "  li    t3, 0x8000000000000000", // mul 0x8000000000000000, 0xffffffffffffffff = 0x8000000000000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0xffffffffffffffff",
    "  mul    t2, t0, t1",
    "  li    t3, 0x1", // mul 0xffffffffffffffff, 0xffffffffffffffff = 0x1
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef",
    "  li    t1, 0xfedcba9876543210",
    "  mul    t2, t0, t1",
    "  li    t3, 0x2236d88fe5618cf0", // mul 0x123456789abcdef, 0xfedcba9876543210 = 0x2236d88fe5618cf0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0x9",
    "  mulh   t2, t0, t1",
    "  li    t3, 0x0", // mulh 0x7, 0x9 = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0x9",
    "  mulh   t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // mulh 0xfffffffffffffff9, 0x9 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0xfffffffffffffff7",
    "  mulh   t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // mulh 0x7, 0xfffffffffffffff7 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0xfffffffffffffff7",
    "  mulh   t2, t0, t1",
    "  li    t3, 0x0", // mulh 0xfffffffffffffff9, 0xfffffffffffffff7 = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x8000000000000000",
    "  li    t1, 0x8000000000000000",
    "  mulh   t2, t0, t1",
    "  li    t3, 0x4000000000000000", // mulh 0x8000000000000000, 0x8000000000000000 = 0x4000000000000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x8000000000000000",
    "  li    t1, 0xffffffffffffffff",
    "  mulh   t2, t0, t1",
    "  li    t3, 0x0", // mulh 0x8000000000000000, 0xffffffffffffffff = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0xffffffffffffffff",
    "  mulh   t2, t0, t1",
    "  li    t3, 0x0", // mulh 0xffffffffffffffff, 0xffffffffffffffff = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef",
    "  li    t1, 0xfedcba9876543210",
    "  mulh   t2, t0, t1",
    "  li    t3, 0xfffeb49923cc0953", // mulh 0x123456789abcdef, 0xfedcba9876543210 = 0xfffeb49923cc0953
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0x9",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0x0", // mulhsu 0x7, 0x9 = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0x9",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // mulhsu 0xfffffffffffffff9, 0x9 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0xfffffffffffffff7",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0x6", // mulhsu 0x7, 0xfffffffffffffff7 = 0x6
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0xfffffffffffffff7",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0xfffffffffffffff9", // mulhsu 0xfffffffffffffff9, 0xfffffffffffffff7 = 0xfffffffffffffff9
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x8000000000000000",
    "  li    t1, 0x8000000000000000",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0xc000000000000000", // mulhsu 0x8000000000000000, 0x8000000000000000 = 0xc000000000000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x8000000000000000",
    "  li    t1, 0xffffffffffffffff",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0x8000000000000000", // mulhsu 0x8000000000000000, 0xffffffffffffffff = 0x8000000000000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0xffffffffffffffff",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // mulhsu 0xffffffffffffffff, 0xffffffffffffffff = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef",
    "  li    t1, 0xfedcba9876543210",
    "  mulhsu t2, t0, t1",
    "  li    t3, 0x121fa00ad77d742", // mulhsu 0x123456789abcdef, 0xfedcba9876543210 = 0x121fa00ad77d742
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0x9",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0x0", // mulhu 0x7, 0x9 = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0x9",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0x8", // mulhu 0xfffffffffffffff9, 0x9 = 0x8
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0xfffffffffffffff7",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0x6", // mulhu 0x7, 0xfffffffffffffff7 = 0x6
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0xfffffffffffffff7",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0xfffffffffffffff0", // mulhu 0xfffffffffffffff9, 0xfffffffffffffff7 = 0xfffffffffffffff0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x8000000000000000",
    "  li    t1, 0x8000000000000000",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0x4000000000000000", // mulhu 0x8000000000000000, 0x8000000000000000 = 0x4000000000000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x8000000000000000",
    "  li    t1, 0xffffffffffffffff",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0x7fffffffffffffff", // mulhu 0x8000000000000000, 0xffffffffffffffff = 0x7fffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0xffffffffffffffff",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0xfffffffffffffffe", // mulhu 0xffffffffffffffff, 0xffffffffffffffff = 0xfffffffffffffffe
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef",
    "  li    t1, 0xfedcba9876543210",
    "  mulhu  t2, t0, t1",
    "  li    t3, 0x121fa00ad77d742", // mulhu 0x123456789abcdef, 0xfedcba9876543210 = 0x121fa00ad77d742
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // The div/rem matrix: the four sign quadrants — DIV(-7, 2) is -3, not the
    // floored -4 — the unsigned pair over full words, division by zero for all
    // four, and the one signed overflow, INT64_MIN / -1.
    "  li    t0, 0x7",
    "  li    t1, 0x2",
    "  div    t2, t0, t1",
    "  li    t3, 0x3", // div 0x7, 0x2 = 0x3
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0x2",
    "  div    t2, t0, t1",
    "  li    t3, 0xfffffffffffffffd", // div 0xfffffffffffffff9, 0x2 = 0xfffffffffffffffd
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0xfffffffffffffffe",
    "  div    t2, t0, t1",
    "  li    t3, 0xfffffffffffffffd", // div 0x7, 0xfffffffffffffffe = 0xfffffffffffffffd
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0xfffffffffffffffe",
    "  div    t2, t0, t1",
    "  li    t3, 0x3", // div 0xfffffffffffffff9, 0xfffffffffffffffe = 0x3
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x8000000000000000",
    "  li    t1, 0x0",
    "  div    t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // div 0x8000000000000000, 0x0 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x8000000000000000",
    "  li    t1, 0xffffffffffffffff",
    "  div    t2, t0, t1",
    "  li    t3, 0x8000000000000000", // div 0x8000000000000000, 0xffffffffffffffff = 0x8000000000000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef",
    "  li    t1, 0x100000001",
    "  div    t2, t0, t1",
    "  li    t3, 0x1234567", // div 0x123456789abcdef, 0x100000001 = 0x1234567
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0x2",
    "  rem    t2, t0, t1",
    "  li    t3, 0x1", // rem 0x7, 0x2 = 0x1
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0x2",
    "  rem    t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // rem 0xfffffffffffffff9, 0x2 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0xfffffffffffffffe",
    "  rem    t2, t0, t1",
    "  li    t3, 0x1", // rem 0x7, 0xfffffffffffffffe = 0x1
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0xfffffffffffffffe",
    "  rem    t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // rem 0xfffffffffffffff9, 0xfffffffffffffffe = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x8000000000000000",
    "  li    t1, 0x0",
    "  rem    t2, t0, t1",
    "  li    t3, 0x8000000000000000", // rem 0x8000000000000000, 0x0 = 0x8000000000000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x8000000000000000",
    "  li    t1, 0xffffffffffffffff",
    "  rem    t2, t0, t1",
    "  li    t3, 0x0", // rem 0x8000000000000000, 0xffffffffffffffff = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef",
    "  li    t1, 0x100000001",
    "  rem    t2, t0, t1",
    "  li    t3, 0x88888888", // rem 0x123456789abcdef, 0x100000001 = 0x88888888
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0x3",
    "  divu   t2, t0, t1",
    "  li    t3, 0x5555555555555555", // divu 0xffffffffffffffff, 0x3 = 0x5555555555555555
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0xffffffffffffffff",
    "  divu   t2, t0, t1",
    "  li    t3, 0x1", // divu 0xffffffffffffffff, 0xffffffffffffffff = 0x1
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef",
    "  li    t1, 0x100000001",
    "  divu   t2, t0, t1",
    "  li    t3, 0x1234567", // divu 0x123456789abcdef, 0x100000001 = 0x1234567
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0x0",
    "  divu   t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // divu 0xffffffffffffffff, 0x0 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0x3",
    "  remu   t2, t0, t1",
    "  li    t3, 0x0", // remu 0xffffffffffffffff, 0x3 = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0xffffffffffffffff",
    "  remu   t2, t0, t1",
    "  li    t3, 0x0", // remu 0xffffffffffffffff, 0xffffffffffffffff = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x123456789abcdef",
    "  li    t1, 0x100000001",
    "  remu   t2, t0, t1",
    "  li    t3, 0x88888888", // remu 0x123456789abcdef, 0x100000001 = 0x88888888
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffffffffffff",
    "  li    t1, 0x0",
    "  remu   t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // remu 0xffffffffffffffff, 0x0 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // The W forms of M: 32-bit operands from the low words, results
    // sign-extended; division by zero and INT32_MIN / -1 among them.
    "  li    t0, 0xdeadbeef80000007",
    "  li    t1, 0x12345678fffffffe",
    "  mulw   t2, t0, t1",
    "  li    t3, 0xfffffffffffffff2", // mulw 0xdeadbeef80000007, 0x12345678fffffffe = 0xfffffffffffffff2
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0x2",
    "  mulw   t2, t0, t1",
    "  li    t3, 0xe", // mulw 0x7, 0x2 = 0xe
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0x2",
    "  mulw   t2, t0, t1",
    "  li    t3, 0xfffffffffffffff2", // mulw 0xfffffffffffffff9, 0x2 = 0xfffffffffffffff2
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff80000000",
    "  li    t1, 0xffffffffffffffff",
    "  mulw   t2, t0, t1",
    "  li    t3, 0xffffffff80000000", // mulw 0xffffffff80000000, 0xffffffffffffffff = 0xffffffff80000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0x0",
    "  mulw   t2, t0, t1",
    "  li    t3, 0x0", // mulw 0x80000000, 0x0 = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000007",
    "  li    t1, 0x12345678fffffffe",
    "  divw   t2, t0, t1",
    "  li    t3, 0x3ffffffc", // divw 0xdeadbeef80000007, 0x12345678fffffffe = 0x3ffffffc
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0x2",
    "  divw   t2, t0, t1",
    "  li    t3, 0x3", // divw 0x7, 0x2 = 0x3
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0x2",
    "  divw   t2, t0, t1",
    "  li    t3, 0xfffffffffffffffd", // divw 0xfffffffffffffff9, 0x2 = 0xfffffffffffffffd
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff80000000",
    "  li    t1, 0xffffffffffffffff",
    "  divw   t2, t0, t1",
    "  li    t3, 0xffffffff80000000", // divw 0xffffffff80000000, 0xffffffffffffffff = 0xffffffff80000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0x0",
    "  divw   t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // divw 0x80000000, 0x0 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000007",
    "  li    t1, 0x12345678fffffffe",
    "  divuw  t2, t0, t1",
    "  li    t3, 0x0", // divuw 0xdeadbeef80000007, 0x12345678fffffffe = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0x2",
    "  divuw  t2, t0, t1",
    "  li    t3, 0x3", // divuw 0x7, 0x2 = 0x3
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0x2",
    "  divuw  t2, t0, t1",
    "  li    t3, 0x7ffffffc", // divuw 0xfffffffffffffff9, 0x2 = 0x7ffffffc
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff80000000",
    "  li    t1, 0xffffffffffffffff",
    "  divuw  t2, t0, t1",
    "  li    t3, 0x0", // divuw 0xffffffff80000000, 0xffffffffffffffff = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0x0",
    "  divuw  t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // divuw 0x80000000, 0x0 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000007",
    "  li    t1, 0x12345678fffffffe",
    "  remw   t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // remw 0xdeadbeef80000007, 0x12345678fffffffe = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0x2",
    "  remw   t2, t0, t1",
    "  li    t3, 0x1", // remw 0x7, 0x2 = 0x1
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0x2",
    "  remw   t2, t0, t1",
    "  li    t3, 0xffffffffffffffff", // remw 0xfffffffffffffff9, 0x2 = 0xffffffffffffffff
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff80000000",
    "  li    t1, 0xffffffffffffffff",
    "  remw   t2, t0, t1",
    "  li    t3, 0x0", // remw 0xffffffff80000000, 0xffffffffffffffff = 0x0
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0x0",
    "  remw   t2, t0, t1",
    "  li    t3, 0xffffffff80000000", // remw 0x80000000, 0x0 = 0xffffffff80000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xdeadbeef80000007",
    "  li    t1, 0x12345678fffffffe",
    "  remuw  t2, t0, t1",
    "  li    t3, 0xffffffff80000007", // remuw 0xdeadbeef80000007, 0x12345678fffffffe = 0xffffffff80000007
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x7",
    "  li    t1, 0x2",
    "  remuw  t2, t0, t1",
    "  li    t3, 0x1", // remuw 0x7, 0x2 = 0x1
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xfffffffffffffff9",
    "  li    t1, 0x2",
    "  remuw  t2, t0, t1",
    "  li    t3, 0x1", // remuw 0xfffffffffffffff9, 0x2 = 0x1
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0xffffffff80000000",
    "  li    t1, 0xffffffffffffffff",
    "  remuw  t2, t0, t1",
    "  li    t3, 0xffffffff80000000", // remuw 0xffffffff80000000, 0xffffffffffffffff = 0xffffffff80000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    "  li    t0, 0x80000000",
    "  li    t1, 0x0",
    "  remuw  t2, t0, t1",
    "  li    t3, 0xffffffff80000000", // remuw 0x80000000, 0x0 = 0xffffffff80000000
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1",
    // A destination of x0 in each family: the row is proven, and x0 keeps
    // its zero.
    "  li    t0, 0x123456789",
    "  li    t1, 5",
    "  sll   x0, t0, t1",
    "  and   x0, t0, t1",
    "  mul   x0, t0, t1",
    "  divw  x0, t0, t1",
    "  li    t3, 0",
    "  bne   x0, t3, fail",
    "  addi  s0, s0, 1",
    // The compressed forms of both families: two bytes each, so the decoded
    // rows carry a fall-through of pc + 2 as well as pc + 4. c.slli takes any
    // register; the rest take x8..x15.
    ".option rvc",
    "  li     a4, 0xff0f00ff0f00ff0",
    "  li     a5, 0xf0f00ff00ff0f00f",
    "  c.and  a5, a4",
    "  li     a3, 0xf0000000f00000", // c.and = 0xf0000000f00000
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
    "  li     a5, 0xf0f00ff00ff0f00f",
    "  c.or   a5, a4",
    "  li     a3, 0xfff0fffffff0ffff", // c.or = 0xfff0fffffff0ffff
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
    "  li     a5, 0xf0f00ff00ff0f00f",
    "  c.xor  a5, a4",
    "  li     a3, 0xff00ffffff00ffff", // c.xor = 0xff00ffffff00ffff
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
    "  li     a5, 0x123456789abcdef1",
    "  c.slli a5, 40",
    "  li     a3, 0xbcdef10000000000", // c.slli 40 = 0xbcdef10000000000
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
    "  li     a5, 0xfedcba9876543210",
    "  c.srli a5, 33",
    "  li     a3, 0x7f6e5d4c", // c.srli 33 = 0x7f6e5d4c
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
    "  li     a5, 0xfedcba9876543210",
    "  c.srai a5, 2",
    "  li     a3, 0xffb72ea61d950c84", // c.srai 2 = 0xffb72ea61d950c84
    "  bne    a5, a3, fail",
    "  c.addi s0, 1",
    "  li     a5, 0x123456789abcdef1",
    "  c.andi a5, -3",
    "  li     a3, 0x123456789abcdef1", // c.andi -3 = 0x123456789abcdef1
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
