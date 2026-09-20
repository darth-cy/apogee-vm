#![no_std]
#![no_main]
//! `guests/mem`: the fixture for S19's three families, hand-written so that its
//! image holds their instructions and nothing else's.
//!
//! # What it covers
//!
//! - **`mem_word`**: `sw`/`lw` round trips at two addresses, the compressed
//!   `c.sw`/`c.lw` forms, a `lw x0` whose write the x0 rule discards, a word in a
//!   RAM window above window 0, and a negative displacement, which is the one
//!   shape whose effective address wraps past `2^32`.
//! - **`mem_subword`**: `lbu` and `lb` at all four byte offsets, `lhu` and `lh`
//!   at both halfword offsets, sign extension of a negative byte and a negative
//!   halfword, `sb` at all four offsets and `sh` at both — each leaving the rest
//!   of its word intact and each truncating a source whose high bytes are
//!   nonzero — and a `lbu x0`.
//! - **`atomics`**: `amoswap`, `amoadd` overflowing `2^32`, two consecutive
//!   `amoadd`s to one address, `amoand`/`amoor`/`amoxor`, all four min/max at
//!   `0x7fffffff` against `0x80000000` so signed disagrees with unsigned in both
//!   directions, an `lr.w`/`sc.w` pair asserting `sc.w`'s `rd` is 0, an
//!   `amoadd.w x0`, and an atomic in a RAM window above window 0, with `rd`
//!   asserted to be the old word on every one of the eleven.
//!
//! Every value is checked against a literal the comment gives, and a mismatch
//! jumps to `fail`.
//!
//! # fd 0, fd 1, fd 2, fd 3
//!
//! Unused.
//!
//! # The result
//!
//! The exit status, `a0`: **50**, the number of checks, or 1 from `fail`.

use core::arch::global_asm;

global_asm!(
    ".section .text._start,\"ax\",@progbits",
    ".globl _start",
    "_start:",
    ".option norvc",
    "  addi  s0, x0, 0",
    "  li    s1, 0x20000",    // scratch inside RAM window 0
    "  li    s2, 0x7ffffef0", // scratch near the top of RAM, a window above 0
    // ---- mem_word ---------------------------------------------------
    "  li    t0, 0x89abcdef",
    "  sw    t0, 0(s1)",
    "  lw    t1, 0(s1)",
    "  bne   t1, t0, fail",
    "  addi  s0, s0, 1", // 1: sw then lw round-trips a whole word
    "  li    t0, 0x0f0f0f0f",
    "  sw    t0, 4(s1)",
    "  lw    t1, 4(s1)",
    "  bne   t1, t0, fail",
    "  addi  s0, s0, 1", // 2: a second word at a second offset
    "  lw    t1, 0(s1)",
    "  li    t2, 0x89abcdef",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 3: the first word is still what it was
    "  lw    x0, 0(s1)",
    "  lui   t3, 0",
    "  addi  t2, x0, 0",
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1", // 4: lw x0 proves, and x0 still reads 0
    "  li    t0, 0x12345678",
    "  sw    t0, 0(s2)",
    "  lw    t1, 0(s2)",
    "  bne   t1, t0, fail",
    "  addi  s0, s0, 1", // 5: a word in a RAM window above window 0
    "  li    a1, 0x20020",
    "  li    a0, 0x0badf00d",
    ".option rvc",
    "  c.sw  a0, 0(a1)",
    "  c.lw  a2, 0(a1)",
    ".option norvc",
    "  bne   a2, a0, fail",
    "  addi  s0, s0, 1", // 6: the compressed word forms, and a pc + 2 row
    // ---- mem_subword: loads -----------------------------------------
    "  li    t0, 0x88776655",
    "  sw    t0, 16(s1)",
    "  lbu   t1, 16(s1)",
    "  li    t2, 0x55",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 7: lbu at byte offset 0
    "  lbu   t1, 17(s1)",
    "  li    t2, 0x66",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 8: lbu at byte offset 1
    "  lbu   t1, 18(s1)",
    "  li    t2, 0x77",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 9: lbu at byte offset 2
    "  lbu   t1, 19(s1)",
    "  li    t2, 0x88",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 10: lbu at byte offset 3, the high byte zero-extended
    "  lb    t1, 16(s1)",
    "  li    t2, 0x55",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 11: lb at offset 0, sign bit clear
    "  lb    t1, 17(s1)",
    "  li    t2, 0x66",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 12: lb at offset 1
    "  lb    t1, 18(s1)",
    "  li    t2, 0x77",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 13: lb at offset 2
    "  lb    t1, 19(s1)",
    "  li    t2, 0xffffff88",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 14: lb at offset 3, sign bit set: 0x88 -> 0xffffff88
    "  lhu   t1, 16(s1)",
    "  li    t2, 0x6655",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 15: lhu at halfword offset 0
    "  lhu   t1, 18(s1)",
    "  li    t2, 0x8877",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 16: lhu at halfword offset 2
    "  lh    t1, 16(s1)",
    "  li    t2, 0x6655",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 17: lh at offset 0, sign bit clear
    "  lh    t1, 18(s1)",
    "  li    t2, 0xffff8877",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 18: lh at offset 2, sign bit set: 0x8877 -> 0xffff8877
    "  lbu   x0, 16(s1)",
    "  lui   t3, 0",
    "  addi  t2, x0, 0",
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1", // 19: lbu x0 proves, and x0 still reads 0
    // ---- mem_subword: stores ----------------------------------------
    "  li    t0, 0x11223344",
    "  sw    t0, 24(s1)",
    "  li    t1, 0xdeadbeef",
    "  sb    t1, 24(s1)",
    "  lw    t2, 24(s1)",
    "  li    t3, 0x112233ef",
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1", // 20: sb at offset 0, rs2 truncated to its low byte
    "  li    t0, 0x11223344",
    "  sw    t0, 24(s1)",
    "  li    t1, 0xdeadbeef",
    "  sb    t1, 25(s1)",
    "  lw    t2, 24(s1)",
    "  li    t3, 0x1122ef44",
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1", // 21: sb at offset 1
    "  li    t0, 0x11223344",
    "  sw    t0, 24(s1)",
    "  li    t1, 0xdeadbeef",
    "  sb    t1, 26(s1)",
    "  lw    t2, 24(s1)",
    "  li    t3, 0x11ef3344",
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1", // 22: sb at offset 2
    "  li    t0, 0x11223344",
    "  sw    t0, 24(s1)",
    "  li    t1, 0xdeadbeef",
    "  sb    t1, 27(s1)",
    "  lw    t2, 24(s1)",
    "  li    t3, 0xef223344",
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1", // 23: sb at offset 3, the top byte
    "  li    t0, 0x11223344",
    "  sw    t0, 28(s1)",
    "  li    t1, 0xcafebabe",
    "  sh    t1, 28(s1)",
    "  lw    t2, 28(s1)",
    "  li    t3, 0x1122babe",
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1", // 24: sh at halfword offset 0, rs2 truncated
    "  li    t0, 0x11223344",
    "  sw    t0, 28(s1)",
    "  li    t1, 0xcafebabe",
    "  sh    t1, 30(s1)",
    "  lw    t2, 28(s1)",
    "  li    t3, 0xbabe3344",
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1", // 25: sh at halfword offset 2
    // A negative displacement, which is the only shape that makes the effective
    // address wrap past 2^32: `imm` is sign-extended, so `rs1 + imm` is
    // `rs1 + 2^32 + imm` and the wrap bit is 1 on every one of them. Every
    // compiled guest emits them; none of the checks above does.
    "  addi  a5, s1, 64",
    "  li    t0, 0x0c0ffee0",
    "  sw    t0, -8(a5)",
    "  lw    t1, -8(a5)",
    "  bne   t1, t0, fail",
    "  addi  s0, s0, 1", // 26: sw and lw at a negative displacement
    "  lbu   t1, -7(a5)",
    "  li    t2, 0xfe",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 27: and a sub-word load at one
    "  li    t0, 0x44332211",
    "  sw    t0, 4(s2)",
    "  li    t1, 0x99",
    "  sb    t1, 5(s2)",
    "  lw    t2, 4(s2)",
    "  li    t3, 0x44339911",
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1", // 28: a sub-word store in a RAM window above window 0
    // ---- atomics ----------------------------------------------------
    "  addi  a3, s1, 32",
    "  li    t0, 0x5a5a5a5a",
    "  sw    t0, 0(a3)",
    "  li    t1, 0x0f0f0f0f",
    "  amoswap.w t2, t1, (a3)",
    "  bne   t2, t0, fail",
    "  addi  s0, s0, 1", // 29: amoswap's rd is the old word
    "  lw    t3, 0(a3)",
    "  bne   t3, t1, fail",
    "  addi  s0, s0, 1", // 30: and the word is rs2
    "  li    t0, 0xffffffff",
    "  sw    t0, 0(a3)",
    "  li    t1, 1",
    "  amoadd.w t2, t1, (a3)",
    "  bne   t2, t0, fail",
    "  addi  s0, s0, 1", // 31: amoadd's rd is the old word
    "  lw    t3, 0(a3)",
    "  lui   t4, 0",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 32: 0xffffffff + 1 wraps to 0
    "  li    t0, 10",
    "  sw    t0, 0(a3)",
    "  li    t1, 5",
    "  amoadd.w t2, t1, (a3)",
    "  amoadd.w t3, t1, (a3)",
    "  li    t4, 10",
    "  bne   t2, t4, fail",
    "  addi  s0, s0, 1", // 33: the first of two amoadds to one address sees 10
    "  li    t4, 15",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 34: the second sees 15, so their timestamps order
    "  lw    t5, 0(a3)",
    "  li    t4, 20",
    "  bne   t5, t4, fail",
    "  addi  s0, s0, 1", // 35: and the word ends at 20
    "  li    t0, 0xf0f00ff0",
    "  li    t1, 0x0ff0f00f",
    "  sw    t0, 0(a3)",
    "  amoand.w t2, t1, (a3)",
    "  bne   t2, t0, fail",
    "  addi  s0, s0, 1", // 36: amoand's rd is the old word
    "  lw    t3, 0(a3)",
    "  li    t4, 0x00f00000",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 37: and 0xf0f00ff0, 0x0ff0f00f = 0x00f00000
    "  sw    t0, 0(a3)",
    "  amoor.w t2, t1, (a3)",
    "  bne   t2, t0, fail",
    "  lw    t3, 0(a3)",
    "  li    t4, 0xfff0ffff",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 38: or  0xf0f00ff0, 0x0ff0f00f = 0xfff0ffff
    "  sw    t0, 0(a3)",
    "  amoxor.w t2, t1, (a3)",
    "  bne   t2, t0, fail",
    "  lw    t3, 0(a3)",
    "  li    t4, 0xff00ffff",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 39: xor 0xf0f00ff0, 0x0ff0f00f = 0xff00ffff
    "  li    t0, 0x7fffffff",
    "  li    t1, 0x80000000",
    "  sw    t0, 0(a3)",
    "  amomin.w t2, t1, (a3)",
    "  bne   t2, t0, fail",
    "  addi  s0, s0, 1", // 40: amomin's rd is the old word
    "  lw    t3, 0(a3)",
    "  bne   t3, t1, fail",
    "  addi  s0, s0, 1", // 41: signed min of 0x7fffffff and 0x80000000 is 0x80000000
    // The next two seed the word with 0x80000000 and pass 0x7fffffff, so the
    // answer is not the value already there: seeded the other way round, an
    // `amominu` or `amomax` that did nothing at all would pass.
    "  sw    t1, 0(a3)",
    "  amominu.w t2, t0, (a3)",
    "  bne   t2, t1, fail",
    "  lw    t3, 0(a3)",
    "  bne   t3, t0, fail",
    "  addi  s0, s0, 1", // 42: unsigned min of the same pair is 0x7fffffff
    "  sw    t1, 0(a3)",
    "  amomax.w t2, t0, (a3)",
    "  bne   t2, t1, fail",
    "  lw    t3, 0(a3)",
    "  bne   t3, t0, fail",
    "  addi  s0, s0, 1", // 43: signed max is 0x7fffffff
    "  sw    t0, 0(a3)",
    "  amomaxu.w t2, t1, (a3)",
    "  bne   t2, t0, fail",
    "  lw    t3, 0(a3)",
    "  bne   t3, t1, fail",
    "  addi  s0, s0, 1", // 44: unsigned max is 0x80000000
    "  li    t0, 0x11112222",
    "  sw    t0, 0(a3)",
    "  lr.w  t1, (a3)",
    "  bne   t1, t0, fail",
    "  addi  s0, s0, 1", // 45: lr.w reads the word and writes it back
    "  li    t2, 0x33334444",
    "  sc.w  t3, t2, (a3)",
    "  lui   t4, 0",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 46: sc.w always succeeds here, so its rd is 0
    "  lw    t5, 0(a3)",
    "  bne   t5, t2, fail",
    "  addi  s0, s0, 1", // 47: and the word is the stored one
    "  li    t0, 7",
    "  sw    t0, 0(a3)",
    "  li    t1, 3",
    "  amoadd.w x0, t1, (a3)",
    "  lui   t4, 0",
    "  addi  t2, x0, 0",
    "  bne   t2, t4, fail",
    "  addi  s0, s0, 1", // 48: amoadd.w x0 proves, and x0 still reads 0
    "  lw    t3, 0(a3)",
    "  li    t4, 10",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 49: its memory side happened all the same
    "  addi  a4, s2, 16",
    "  li    t0, 0x0000beef",
    "  sw    t0, 0(a4)",
    "  li    t1, 0x00001111",
    "  amoadd.w t2, t1, (a4)",
    "  bne   t2, t0, fail",
    "  lw    t3, 0(a4)",
    "  li    t4, 0x0000d000",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 50: an atomic in a RAM window above window 0
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
