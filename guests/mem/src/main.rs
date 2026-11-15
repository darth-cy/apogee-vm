#![no_std]
#![no_main]
//! `guests/mem`: the fixture for the three memory-op families, hand-written so
//! that its image holds their instructions and nothing else's.
//!
//! # What it covers
//!
//! - **`mem_word`**: `sw`/`lw` round trips at two addresses, `lw` sign-extending
//!   and `lwu` zero-extending, the compressed `c.sw`/`c.lw` forms, a `lw x0`
//!   whose write the x0 rule discards, a word in a RAM window above window 0, a
//!   negative displacement — the shape whose 64-bit sum carries out of both
//!   words — and the doubleword: `sd`/`ld` round trips, each half read back as
//!   a word, `c.sd`/`c.ld` and `c.sdsp`/`c.ldsp`, and a negative displacement.
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
//!   asserted to be the old word, sign-extended, on every one of the eleven;
//!   then the `.d` forms: `amoadd.d` carrying across the two words, the bitwise
//!   three, min/max at `2^63 − 1` against `2^63`, `lr.d`/`sc.d`, and `amoadd.w`
//!   whose `rs2` carries garbage above the word it reads.
//!
//! Every value is checked against a literal the comment gives, and a mismatch
//! jumps to `fail`.
//!
//! # Input, advice and the journal
//!
//! Unused.
//!
//! # The result
//!
//! The exit status, `a0`: **66**, the number of checks, or 1 from `fail`.

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
    "  li    t0, 0xffffffff89abcdef",
    "  sw    t0, 0(s1)",
    "  lw    t1, 0(s1)",
    "  bne   t1, t0, fail",
    "  addi  s0, s0, 1", // 1: sw then lw round-trips a word, sign-extended
    "  li    t0, 0x0f0f0f0f",
    "  sw    t0, 4(s1)",
    "  lw    t1, 4(s1)",
    "  bne   t1, t0, fail",
    "  addi  s0, s0, 1", // 2: a second word at a second offset
    "  lwu   t1, 0(s1)",
    "  li    t2, 0x89abcdef",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 3: the first word is still what it was, zero-extended
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
    "  li    t2, 0xffffffffffffff88",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 14: lb at offset 3, sign bit set, extended to 64 bits
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
    "  li    t2, 0xffffffffffff8877",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 18: lh at offset 2, sign bit set, extended to 64 bits
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
    "  li    t3, 0xffffffffef223344",
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
    "  li    t3, 0xffffffffbabe3344",
    "  bne   t2, t3, fail",
    "  addi  s0, s0, 1", // 25: sh at halfword offset 2
    // A negative displacement: `imm` is sign-extended to 64 bits, so
    // `rs1 + imm` carries out of the low word and out of the high one, and both
    // carry bits are 1. Every compiled guest emits them; none of the checks
    // above does.
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
    "  li    t0, -1",
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
    "  li    t0, 0xfffffffff0f00ff0",
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
    "  li    t4, 0xfffffffffff0ffff",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 38: or  0xf0f00ff0, 0x0ff0f00f = 0xfff0ffff
    "  sw    t0, 0(a3)",
    "  amoxor.w t2, t1, (a3)",
    "  bne   t2, t0, fail",
    "  lw    t3, 0(a3)",
    "  li    t4, 0xffffffffff00ffff",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 39: xor 0xf0f00ff0, 0x0ff0f00f = 0xff00ffff
    "  li    t0, 0x7fffffff",
    "  li    t1, 0xffffffff80000000",
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
    // ---- doublewords -------------------------------------------------
    "  li    t0, 0x0123456789abcdef",
    "  sd    t0, 128(s1)",
    "  ld    t1, 128(s1)",
    "  bne   t1, t0, fail",
    "  addi  s0, s0, 1", // 51: sd then ld round-trips a doubleword
    "  lwu   t1, 128(s1)",
    "  li    t2, 0x89abcdef",
    "  bne   t1, t2, fail",
    "  lw    t1, 132(s1)",
    "  li    t2, 0x01234567",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 52: its low word first, as little-endian lays it out
    "  li    t0, 0xfedcba9876543210",
    "  sw    t0, 136(s1)",
    "  sw    t0, 140(s1)",
    "  ld    t1, 136(s1)",
    "  li    t2, 0x7654321076543210",
    "  bne   t1, t2, fail",
    "  addi  s0, s0, 1", // 53: two words read back as one doubleword
    "  addi  a5, s1, 160",
    "  li    t0, 0x8000000000000001",
    "  sd    t0, -16(a5)",
    "  ld    t1, -16(a5)",
    "  bne   t1, t0, fail",
    "  addi  s0, s0, 1", // 54: sd and ld at a negative displacement
    "  li    t0, 0x1122334455667788",
    "  sd    t0, 8(s2)",
    "  ld    t1, 8(s2)",
    "  bne   t1, t0, fail",
    "  addi  s0, s0, 1", // 55: a doubleword in a RAM window above window 0
    "  addi  sp, s1, 256",
    "  li    a1, 0x20100",
    "  li    a0, 0x0badf00d0badf00d",
    ".option rvc",
    "  c.sd   a0, 8(a1)",
    "  c.ld   a2, 8(a1)",
    "  c.sdsp a0, 16(sp)",
    "  c.ldsp a3, 16(sp)",
    ".option norvc",
    "  bne   a2, a0, fail",
    "  bne   a3, a0, fail",
    "  addi  s0, s0, 1", // 56: the compressed doubleword forms
    "  ld    x0, 128(s1)",
    "  bne   x0, zero, fail",
    "  addi  s0, s0, 1", // 57: ld x0 proves, and x0 still reads 0
    // ---- atomics, doublewords ------------------------------------------
    "  addi  a3, s1, 96",
    "  li    t0, 0x00000000ffffffff",
    "  sd    t0, 0(a3)",
    "  li    t1, 1",
    "  amoadd.d t2, t1, (a3)",
    "  bne   t2, t0, fail",
    "  ld    t3, 0(a3)",
    "  li    t4, 0x0000000100000000",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 58: amoadd.d carries from the low word into the high
    "  li    t0, 0xf0f00ff00ff0f00f",
    "  li    t1, 0x0ff0f00ff0f00ff0",
    "  sd    t0, 0(a3)",
    "  amoand.d t2, t1, (a3)",
    "  bne   t2, t0, fail",
    "  ld    t3, 0(a3)",
    "  li    t4, 0x00f0000000f00000",
    "  bne   t3, t4, fail",
    "  sd    t0, 0(a3)",
    "  amoor.d t2, t1, (a3)",
    "  ld    t3, 0(a3)",
    "  li    t4, 0xfff0fffffff0ffff",
    "  bne   t3, t4, fail",
    "  sd    t0, 0(a3)",
    "  amoxor.d t2, t1, (a3)",
    "  ld    t3, 0(a3)",
    "  li    t4, 0xff00ffffff00ffff",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 59: and, or, xor over both words
    "  li    t0, 0x7fffffffffffffff",
    "  li    t1, 0x8000000000000000",
    "  sd    t0, 0(a3)",
    "  amomin.d t2, t1, (a3)",
    "  bne   t2, t0, fail",
    "  ld    t3, 0(a3)",
    "  bne   t3, t1, fail",
    "  addi  s0, s0, 1", // 60: signed min is 2^63, negative
    "  sd    t1, 0(a3)",
    "  amominu.d t2, t0, (a3)",
    "  ld    t3, 0(a3)",
    "  bne   t3, t0, fail",
    "  addi  s0, s0, 1", // 61: unsigned min is 2^63 - 1
    "  sd    t1, 0(a3)",
    "  amomax.d t2, t0, (a3)",
    "  ld    t3, 0(a3)",
    "  bne   t3, t0, fail",
    "  sd    t0, 0(a3)",
    "  amomaxu.d t2, t1, (a3)",
    "  ld    t3, 0(a3)",
    "  bne   t3, t1, fail",
    "  addi  s0, s0, 1", // 62: signed max 2^63 - 1, unsigned max 2^63
    "  li    t0, 0x1111222233334444",
    "  sd    t0, 0(a3)",
    "  lr.d  t1, (a3)",
    "  bne   t1, t0, fail",
    "  li    t2, 0x5555666677778888",
    "  sc.d  t3, t2, (a3)",
    "  bne   t3, zero, fail",
    "  ld    t5, 0(a3)",
    "  bne   t5, t2, fail",
    "  addi  s0, s0, 1", // 63: lr.d, and sc.d storing with rd 0
    "  amoswap.d t2, t0, (a3)",
    "  bne   t2, t5, fail",
    "  ld    t3, 0(a3)",
    "  bne   t3, t0, fail",
    "  addi  s0, s0, 1", // 64: amoswap.d
    "  li    t0, 5",
    "  sw    t0, 0(a3)",
    "  li    t1, 0x1234567800000003",
    "  amoadd.w t2, t1, (a3)",
    "  lw    t3, 0(a3)",
    "  li    t4, 8",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 65: amoadd.w reads rs2's low word only
    "  li    t0, 0x00000000fffffffe",
    "  sw    t0, 0(a3)",
    "  li    t1, 0x7fffffff00000001",
    "  amomin.w t2, t1, (a3)",
    "  li    t4, -2",
    "  bne   t2, t4, fail",
    "  lw    t3, 0(a3)",
    "  bne   t3, t4, fail",
    "  addi  s0, s0, 1", // 66: amomin.w compares the words signed: -2 < 1
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
