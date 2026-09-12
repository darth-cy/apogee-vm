#![no_std]
#![no_main]
//! Every RV32IMAC instruction, executed.
//!
//! The fixture for S12's QEMU differential: every one of the 59 RV32IMA
//! instructions runs here with edge-case operands, and a block of compressed
//! code runs every compressed form a program can execute, so the emulator's
//! register trace is compared with `qemu-riscv32`'s for each of them.
//! `crates/emulator/tests/` checks that every mnemonic really does execute,
//! rather than trusting this comment.
//!
//! The instructions live in `global_asm!` blocks, not compiled Rust, so what
//! runs is exactly what is written:
//!
//! - `cover_base`: RV32I in 32-bit encodings — upper immediates, every
//!   register-immediate and register-register operation at its boundaries,
//!   every branch taken and not taken, `jal`/`jalr` (an odd `jalr` target
//!   included, whose bit 0 the ISA clears), every load and store width at
//!   every offset, `x0` as source and destination, and the fences;
//! - `cover_m`: the eight M operations over ten operand pairs, including
//!   division by zero and the one signed overflow, `INT_MIN / -1`;
//! - `cover_a`: all nine AMOs with `aq`/`rl` variants, paired `lr.w`/`sc.w`,
//!   and one **unpaired** `sc.w` — which QEMU fails and the emulator
//!   succeeds, the whitelisted divergence, exercised on purpose;
//! - `cover_rvc`: every executable compressed form (all but `c.ebreak` and
//!   `c.unimp`, which trap), each instruction of the block executed;
//! - `cover_ecall`: `read` into and `write` from an unaligned buffer, a
//!   zero-length `write`, `-EBADF` for both calls, the empty hint stream, and
//!   `-ENOSYS` for the precompile range and an unassigned host-call number.
//!
//! # fd 0, the public input
//!
//! ```text
//!           0..4     mode            u32 LE; a shorter stream means 0
//!           4..10    payload         mode 0 only: six bytes cover_ecall reads
//! ```
//!
//! - mode 0 runs every block;
//! - mode 1 executes `ebreak`, which both executors trap on;
//! - modes 2 to 8 each make one misaligned access — `lw`, `sw`, `lh`, `sh`,
//!   `lr.w`, `sc.w`, `amoadd.w` — which the zkVM refuses as a fatal guest
//!   error. QEMU performs the first four and the `amoadd.w` — its default
//!   CPU allows a misaligned AMO inside an aligned 16-byte block — and
//!   faults on `lr.w` and `sc.w`. None of it is compared: the emulator's
//!   refusal is what these modes are for.
//!
//! # fd 1, the public output (mode 0)
//!
//! The payload back, as `cover_ecall` wrote it; then seven `u32` LE words —
//! the five blocks' folds in the order above, and the compressed block's
//! first and one-past-last address.
//!
//! # fd 3
//!
//! Read once, expected empty.

use core::arch::global_asm;

guest_sdk::entry!(main);

extern "C" {
    fn cover_base(scratch: *mut u32) -> u32;
    fn cover_m() -> u32;
    fn cover_a(scratch: *mut u32) -> u32;
    fn cover_rvc() -> u32;
    fn cover_ecall(scratch: *mut u32) -> u32;
    fn misaligned(mode: u32, scratch: *mut u32);

    static __cover_rvc_begin: u8;
    static __cover_rvc_end: u8;
}

fn main() {
    let mut mode = [0u8; 4];
    let mode = match guest_sdk::read_input(&mut mode) {
        4 => u32::from_le_bytes(mode),
        _ => 0,
    };
    let mut scratch = [0u32; 16];
    let scratch = scratch.as_mut_ptr();

    match mode {
        0 => {
            // SAFETY: each block is a leaf routine defined below, following
            // the C calling convention, touching only caller-saved registers
            // and the sixteen words of `scratch` it is handed.
            let folds = unsafe {
                [
                    cover_base(scratch),
                    cover_m(),
                    cover_a(scratch),
                    cover_rvc(),
                    cover_ecall(scratch),
                ]
            };
            for fold in folds {
                guest_sdk::commit(&fold.to_le_bytes());
            }
            let begin = core::ptr::addr_of!(__cover_rvc_begin) as u32;
            let end = core::ptr::addr_of!(__cover_rvc_end) as u32;
            guest_sdk::commit(&begin.to_le_bytes());
            guest_sdk::commit(&end.to_le_bytes());
        }
        // SAFETY: `ebreak` touches no memory and no register.
        1 => unsafe { core::arch::asm!("ebreak") },
        // SAFETY: as the blocks above; the misaligned address is inside
        // `scratch`.
        2..=8 => unsafe { misaligned(mode, scratch) },
        _ => guest_sdk::exit(2),
    }
}

// ---------------------------------------------------------------------------
// RV32I, every instruction in its 32-bit encoding. a6 holds the scratch words
// and a0 the fold; t0-t6, a1-a5 and a7 are scratch registers.
// ---------------------------------------------------------------------------

global_asm!(
    r#"
.section .text.cover_base,"ax",@progbits
.option push
.option norvc
.globl cover_base
cover_base:
    addi    sp, sp, -16
    sw      ra, 12(sp)
    mv      a6, a0
    li      a0, 0

    /* upper immediates */
    lui     t0, 0x80000
    lui     t1, 0xfffff
    lui     x0, 0x12345
    auipc   t2, 0
    auipc   t3, 0xfffff
    sub     t2, t3, t2
    add     a0, a0, t0
    xor     a0, a0, t1
    add     a0, a0, t2

    /* register-immediate, at the immediates' extremes */
    li      t0, -5
    addi    t1, t0, 2047
    addi    t2, t0, -2048
    addi    x0, t0, 1
    slti    t3, t0, -4
    slti    t4, t0, -5
    sltiu   t5, t0, -1
    sltiu   t6, x0, 1
    xori    a1, t0, -1
    ori     a2, t0, 0x70
    andi    a3, t0, 0x7ff
    slli    a4, t0, 31
    srli    a5, t0, 31
    srai    a7, t0, 31
    srai    t0, t0, 1
    add     a0, a0, t0
    xor     a0, a0, t1
    add     a0, a0, t2
    xor     a0, a0, t3
    add     a0, a0, t4
    xor     a0, a0, t5
    add     a0, a0, t6
    xor     a0, a0, a1
    add     a0, a0, a2
    xor     a0, a0, a3
    add     a0, a0, a4
    xor     a0, a0, a5
    add     a0, a0, a7

    /* the compare-immediates with mixed signs, where a signed and an
       unsigned comparison disagree: 1 < -1 is false signed and true unsigned,
       and -5 < 1 the other way round */
    li      t0, -5
    li      t1, 1
    slti    t2, t1, -1
    sltiu   t3, t1, -1
    sltiu   t4, t0, 1
    slti    t5, t0, 1
    add     a0, a0, t2
    xor     a0, a0, t3
    add     a0, a0, t4
    xor     a0, a0, t5

    /* register-register: wrapping, shift amounts past 31, signedness */
    li      t0, 0x7fffffff
    li      t1, 1
    add     t2, t0, t1
    sub     t3, t1, t0
    sub     t4, x0, t1
    li      a1, 33
    sll     t5, t1, a1
    li      a2, 32
    srl     t6, t0, a2
    sra     a3, t4, a1
    srl     a4, t4, a1
    slt     a5, t4, t1
    sltu    a7, t4, t1
    xor     t0, t0, t4
    or      t1, t1, t2
    and     t2, t2, t4
    add     t3, t3, t3
    sub     t4, t4, t4
    sll     a1, a1, a1
    add     x0, t0, t1
    add     a0, a0, t0
    xor     a0, a0, t1
    add     a0, a0, t2
    xor     a0, a0, t3
    add     a0, a0, t4
    xor     a0, a0, t5
    add     a0, a0, t6
    xor     a0, a0, a1
    add     a0, a0, a3
    xor     a0, a0, a4
    add     a0, a0, a5
    xor     a0, a0, a7

    /* every branch, taken and not taken; a taken one skips an addi */
    li      t0, -1
    li      t1, 1
    beq     t0, t0, 1f
    addi    a0, a0, 1
1:  beq     t0, t1, 1f
    addi    a0, a0, 3
1:  bne     t0, t1, 1f
    addi    a0, a0, 5
1:  bne     t0, t0, 1f
    addi    a0, a0, 7
1:  blt     t0, t1, 1f
    addi    a0, a0, 11
1:  blt     t1, t0, 1f
    addi    a0, a0, 13
1:  bge     t1, t0, 1f
    addi    a0, a0, 17
1:  bge     t0, t1, 1f
    addi    a0, a0, 19
1:  bge     t0, t0, 1f
    addi    a0, a0, 23
1:  bltu    t1, t0, 1f
    addi    a0, a0, 29
1:  bltu    t0, t1, 1f
    addi    a0, a0, 31
1:  bgeu    t0, t1, 1f
    addi    a0, a0, 37
1:  bgeu    t1, t0, 1f
    addi    a0, a0, 41
1:  beq     x0, x0, 1f
    addi    a0, a0, 43
1:

    /* jal and jalr: links, a skipped instruction, an odd jalr target */
    jal     ra, 1f
    addi    a0, a0, 47
1:  auipc   t0, 0
    sub     t1, t0, ra
    add     a0, a0, t1
    la      t2, 1f
    addi    t2, t2, 1
    jalr    t3, 0(t2)
    addi    a0, a0, 53
1:  auipc   t4, 0
    sub     t5, t4, t3
    add     a0, a0, t5
    la      t2, 1f
    jalr    x0, 4(t2)
1:  addi    a0, a0, 59
    jal     x0, 1f
    addi    a0, a0, 61
1:

    /* loads, every width at every offset they allow, and stores likewise */
    li      t0, 0x80ff7f01
    sw      t0, 0(a6)
    li      t1, 0x8001fffe
    sw      t1, 4(a6)
    lb      t2, 0(a6)
    lb      t3, 1(a6)
    lb      t4, 2(a6)
    lb      t5, 3(a6)
    lbu     t6, 2(a6)
    lbu     a1, 3(a6)
    lh      a2, 0(a6)
    lh      a3, 2(a6)
    lhu     a4, 2(a6)
    lhu     a5, 6(a6)
    lw      a7, 4(a6)
    lw      x0, 0(a6)
    add     a0, a0, t2
    xor     a0, a0, t3
    add     a0, a0, t4
    xor     a0, a0, t5
    add     a0, a0, t6
    xor     a0, a0, a1
    add     a0, a0, a2
    xor     a0, a0, a3
    add     a0, a0, a4
    xor     a0, a0, a5
    add     a0, a0, a7
    sb      t0, 8(a6)
    sb      t1, 9(a6)
    sb      t0, 10(a6)
    sb      t1, 11(a6)
    sh      t0, 12(a6)
    sh      t1, 14(a6)
    addi    a1, a6, 32
    sw      t1, -16(a1)
    sw      x0, 20(a6)
    sb      x0, 21(a6)
    lw      t2, 8(a6)
    lw      t3, 12(a6)
    lw      t4, -16(a1)
    lw      t5, 20(a6)
    add     a0, a0, t2
    xor     a0, a0, t3
    add     a0, a0, t4
    xor     a0, a0, t5

    /* the fences: on one hart each is a no-op */
    fence
    fence   rw, rw
    fence   r, w
    fence   iorw, iorw
    fence.tso

    lw      ra, 12(sp)
    addi    sp, sp, 16
    ret
.option pop
"#
);

// ---------------------------------------------------------------------------
// M: the eight operations over ten operand pairs.
// ---------------------------------------------------------------------------

global_asm!(
    r#"
.macro mops a, b
    li      t0, \a
    li      t1, \b
    mul     t2, t0, t1
    mulh    t3, t0, t1
    mulhsu  t4, t0, t1
    mulhu   t5, t0, t1
    div     t6, t0, t1
    divu    a1, t0, t1
    rem     a2, t0, t1
    remu    a3, t0, t1
    add     a0, a0, t2
    xor     a0, a0, t3
    add     a0, a0, t4
    xor     a0, a0, t5
    add     a0, a0, t6
    xor     a0, a0, a1
    add     a0, a0, a2
    xor     a0, a0, a3
.endm

.section .text.cover_m,"ax",@progbits
.option push
.option norvc
.globl cover_m
cover_m:
    li      a0, 0
    mops    7, 3
    mops    -7, 3
    mops    7, -3
    mops    -7, -3
    mops    0x80000000, -1
    mops    5, 0
    mops    0x80000000, 0
    mops    0xffffffff, 0xffffffff
    mops    0x80000000, 0x80000000
    mops    0x12345678, 0x9abcdef0
    mul     t0, t0, t0
    divu    x0, t0, t1
    add     a0, a0, t0
    ret
.option pop
"#
);

// ---------------------------------------------------------------------------
// A: every AMO, lr.w/sc.w paired, and one unpaired sc.w.
// ---------------------------------------------------------------------------

global_asm!(
    r#"
.section .text.cover_a,"ax",@progbits
.option push
.option norvc
.globl cover_a
cover_a:
    mv      a6, a0
    li      a0, 0
    li      t0, 0x80000000
    sw      t0, 0(a6)
    li      t1, 5
    amoadd.w    t2, t1, (a6)
    amoswap.w   t3, t1, (a6)
    amoxor.w    t4, t0, (a6)
    amoand.w    t5, t1, (a6)
    amoor.w     t6, t0, (a6)
    amomin.w    a1, t1, (a6)
    amomax.w    a2, t1, (a6)
    amominu.w   a3, t0, (a6)
    amomaxu.w   a4, t0, (a6)
    amomin.w    a5, t0, (a6)
    amominu.w   a7, t1, (a6)
    add     a0, a0, t2
    xor     a0, a0, t3
    add     a0, a0, t4
    xor     a0, a0, t5
    add     a0, a0, t6
    xor     a0, a0, a1
    add     a0, a0, a2
    xor     a0, a0, a3
    add     a0, a0, a4
    xor     a0, a0, a5
    add     a0, a0, a7
    amoadd.w.aq     t2, t1, (a6)
    amoadd.w.rl     t3, t1, (a6)
    amoadd.w.aqrl   t4, t1, (a6)
    amomaxu.w.aqrl  t5, t0, (a6)
    amoswap.w   t1, t1, (a6)
    amoadd.w    x0, t0, (a6)
    add     a0, a0, t2
    xor     a0, a0, t3
    add     a0, a0, t4
    xor     a0, a0, t5
    add     a0, a0, t1

    /* lr.w/sc.w paired: the reservation holds, so both executors store and
       return 0 */
    lr.w        t2, (a6)
    addi        t2, t2, 1
    sc.w        t3, t2, (a6)
    lr.w.aq     t4, (a6)
    sc.w.rl     t5, t4, (a6)
    lw          t6, 0(a6)
    add     a0, a0, t2
    xor     a0, a0, t3
    add     a0, a0, t4
    xor     a0, a0, t5
    add     a0, a0, t6

    /* An unpaired sc.w: no reservation is held. QEMU fails it -- t6 = 1 and
       nothing stored -- and the emulator succeeds -- t6 = 0 and t0 stored.
       This is the whitelisted divergence, so t6 and the word are both
       overwritten before either is read again. */
    sc.w        t6, t0, (a6)
    li          t6, 0
    sw          x0, 0(a6)

    /* rd = rs1: the address register overwritten with the old value */
    mv          a7, a6
    amoadd.w    a7, t1, (a7)
    add     a0, a0, a7
    ret
.option pop
"#
);

// ---------------------------------------------------------------------------
// RVC: every compressed form a program can execute, every instruction
// between the two symbols executed. a0-a5 are x10-x15, the registers the
// three-bit fields reach.
// ---------------------------------------------------------------------------

global_asm!(
    r#"
.section .text.cover_rvc,"ax",@progbits
.option push
.option rvc
.globl cover_rvc
.globl __cover_rvc_begin
.globl __cover_rvc_end
cover_rvc:
    mv          t6, ra
    li          a0, 0
__cover_rvc_begin:
    c.addi16sp  sp, -32
    c.addi4spn  a1, sp, 8
    c.li        a2, -7
    c.li        a3, 31
    c.lui       a4, 0x12
    c.addi      a4, 5
    c.addi      a2, -1
    c.nop
    c.sw        a2, 0(a1)
    c.lw        a5, 0(a1)
    c.swsp      a3, 4(sp)
    c.lwsp      a2, 4(sp)
    c.add       a0, a5
    c.mv        a5, a4
    c.add       a5, a3
    c.sub       a5, a2
    c.xor       a5, a4
    c.or        a5, a3
    c.and       a5, a4
    c.slli      a5, 3
    c.srli      a5, 1
    c.srai      a2, 2
    c.andi      a5, -3
    c.add       a0, a5
    c.add       a0, a2
    c.beqz      a5, 1f
1:  c.bnez      a5, 1f
1:  c.li        a3, 0
    c.beqz      a3, 1f
1:  c.bnez      a3, 1f
1:  c.j         1f
1:  c.j         2f
3:  c.addi      a0, 1
    c.jr        ra
2:  c.jal       3b
    c.mv        a4, ra
    c.addi      a4, 6
    c.jalr      a4
    c.mv        a4, ra
    c.addi      a4, 6
    c.jr        a4
    c.addi16sp  sp, 32
__cover_rvc_end:
    mv          ra, t6
    ret
.option pop
"#
);

// ---------------------------------------------------------------------------
// ecall: the calls a guest makes through the SDK, made directly, at their
// edges. t0 holds the scratch words and t1 the fold, because a0 is every
// call's argument and result.
// ---------------------------------------------------------------------------

global_asm!(
    r#"
.section .text.cover_ecall,"ax",@progbits
.option push
.option norvc
.globl cover_ecall
cover_ecall:
    mv      t0, a0
    li      t1, 0

    /* read(0, scratch + 1, 6): the rest of fd 0, into two partial words */
    li      a7, 63
    li      a0, 0
    addi    a1, t0, 1
    li      a2, 6
    ecall
    add     t1, t1, a0
    lw      t2, 0(t0)
    lw      t3, 4(t0)
    add     t1, t1, t2
    xor     t1, t1, t3

    /* write(1, scratch + 1, 6): the same bytes back out, unaligned */
    li      a7, 64
    li      a0, 1
    addi    a1, t0, 1
    li      a2, 6
    ecall
    add     t1, t1, a0

    /* write(1, scratch, 0): nothing moves, and 0 comes back */
    li      a7, 64
    li      a0, 1
    mv      a1, t0
    li      a2, 0
    ecall
    add     t1, t1, a0

    /* read and write on a descriptor neither has: -EBADF */
    li      a7, 63
    li      a0, 1000
    mv      a1, t0
    li      a2, 4
    ecall
    add     t1, t1, a0
    li      a7, 64
    li      a0, 1000
    ecall
    add     t1, t1, a0

    /* read(3, scratch, 4): the hint stream, empty here, so 0 */
    li      a7, 63
    li      a0, 3
    mv      a1, t0
    li      a2, 4
    ecall
    add     t1, t1, a0

    /* the precompile range, and a host-call number nobody assigned: -ENOSYS */
    li      a7, 0x500
    mv      a0, t0
    ecall
    add     t1, t1, a0
    li      a7, 0x4ff
    ecall
    add     t1, t1, a0

    mv      a0, t1
    ret
.option pop
"#
);

// ---------------------------------------------------------------------------
// One misaligned access per mode, 2 to 8. a0 is the mode and a1 the scratch
// words; every address below is inside them.
// ---------------------------------------------------------------------------

global_asm!(
    r#"
.section .text.misaligned,"ax",@progbits
.option push
.option norvc
.globl misaligned
misaligned:
    addi    t0, a1, 2
    li      t1, 2
    beq     a0, t1, 2f
    li      t1, 3
    beq     a0, t1, 3f
    li      t1, 4
    beq     a0, t1, 4f
    li      t1, 5
    beq     a0, t1, 5f
    li      t1, 6
    beq     a0, t1, 6f
    li      t1, 7
    beq     a0, t1, 7f
    li      t1, 8
    beq     a0, t1, 8f
    ret
2:  lw      t2, 2(a1)
    ret
3:  sw      t2, 2(a1)
    ret
4:  lh      t2, 1(a1)
    ret
5:  sh      t2, 1(a1)
    ret
6:  lr.w    t2, (t0)
    ret
7:  sc.w    t2, t1, (t0)
    ret
8:  amoadd.w t2, t1, (t0)
    ret
.option pop
"#
);
