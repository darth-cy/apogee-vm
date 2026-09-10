#![no_std]
#![no_main]
//! An RVC-dense loader fixture, and a runnable guest.
//!
//! Two things live here.
//!
//! **The paired regions** `rvcpair` and `norvcpair` hold the *same* instruction
//! sequence twice: once written in compressed mnemonics under `.option rvc`,
//! once in the base mnemonics those compressed forms abbreviate, under
//! `.option norvc`. The loader test expands the first region and compares it,
//! instruction for instruction, against the second — so the oracle for every
//! expansion is LLVM's own 32-bit encoder, not a second reading of the same
//! table by the same author. Every displacement is written `.+N`, so the two
//! regions encode identical immediates even though their instructions are
//! different sizes. Neither region is ever executed.
//!
//! RVC **HINT** encodings are not here. LLVM will neither assemble nor
//! disassemble one — its decoder tables exclude `rd = x0` from `c.addi` and
//! friends — so there is no independent oracle for them in this toolchain, and
//! a raw halfword in this region would only desynchronise `llvm-objdump`. The
//! loader expands them per the spec, and `crates/loader/src/rvc.rs`'s unit
//! tests pin the six expansions longhand.
//!
//! **The executed pair** `rvc_exec` and `norvc_exec` compute the same function
//! two ways and run under QEMU, which is what says the fixture is real code at
//! real addresses rather than a well-formed byte string.
//!
//! # fd 0, the public input
//!
//! ```text
//!           0..4     x               u32 LE, optional
//! ```
//!
//! Optional in a way no other guest's input is: a stream shorter than four
//! bytes leaves `x = 3` instead of faulting. This one is a loader fixture
//! before it is a program, and it is dumped and disassembled far more often
//! than it is executed, so it has to produce an image without an input to
//! produce it from.
//!
//! # fd 1, the public output
//!
//! Twelve bytes — three little-endian `u32`s, written as three separate
//! commits, because fd 1 is a stream and not a record:
//!
//! ```text
//!           0..4     y               what both routines answered for x
//!           4..8     rvc_len         bytes in the compressed paired region
//!           8..12    norvc_len       bytes in the uncompressed one
//! ```
//!
//! `y` is `(5*x + 11) & 0xff`, except at the single `x` for which `5*x + 4`
//! wraps to exactly zero — `0xcccccccc` — where the branch skips the `+ 7` and
//! `y` is `0`. The function is arbitrary and chosen for its *shape*: a stack
//! frame, a store followed by a load of the same word, a taken branch and a
//! masked result. Eleven of the fourteen instructions that shape produces
//! compress, across quadrants 1 and 2; the three that do not — a non-destructive
//! `addi`, and an `andi` whose immediate overflows the six-bit field — are what
//! keep the executed region mixed rather than uniformly 16-bit. Exhaustive
//! quadrant coverage is the paired regions' job, not this routine's.
//!
//! The two lengths are what make the last eight bytes worth committing. They
//! are the regions' sizes as the linker laid them out, so a compressed region
//! that quietly stopped being compressed — a toolchain that ignored
//! `.option rvc`, or a relaxation pass that rewrote it — changes fd 1 rather
//! than changing nothing.
//!
//! # fd 2 and fd 3
//!
//! Unused.

use core::arch::global_asm;

guest_sdk::entry!(main);

extern "C" {
    fn rvc_exec(x: u32) -> u32;
    fn norvc_exec(x: u32) -> u32;

    static __rvcpair_begin: u8;
    static __rvcpair_end: u8;
    static __norvcpair_begin: u8;
    static __norvcpair_end: u8;
}

fn main() {
    // Referencing the four boundary symbols is also what keeps the paired
    // regions alive: rustc links with `--gc-sections`, and nothing else calls
    // into them.
    let rvc_len = span(
        core::ptr::addr_of!(__rvcpair_begin),
        core::ptr::addr_of!(__rvcpair_end),
    );
    let norvc_len = span(
        core::ptr::addr_of!(__norvcpair_begin),
        core::ptr::addr_of!(__norvcpair_end),
    );

    let mut input = [0u8; 4];
    let n = guest_sdk::read_input(&mut input);
    let x = if n == 4 { u32::from_le_bytes(input) } else { 3 };

    // SAFETY: both are `extern "C"` leaf routines taking one `u32` in `a0` and
    // returning one in `a0`, defined below in this file.
    let a = unsafe { rvc_exec(x) };
    let b = unsafe { norvc_exec(x) };
    assert_eq!(a, b, "the compressed and uncompressed routines disagree");

    guest_sdk::commit(&a.to_le_bytes());
    guest_sdk::commit(&rvc_len.to_le_bytes());
    guest_sdk::commit(&norvc_len.to_le_bytes());
}

fn span(begin: *const u8, end: *const u8) -> u32 {
    (end as usize - begin as usize) as u32
}

// ---------------------------------------------------------------------------
// The paired regions.
//
// One line per pair, in the same order in both, so the loader test can zip
// them. Read them side by side: the left file says what the 16-bit encoding
// is, the right says what it means.
//
// Registers are chosen so the compressed forms are expressible: the 3-bit
// fields name x8..x15 only, and the sp-relative forms take x2. Immediates
// include each field's extremes, because an off-by-one in a shift-and-mask
// shows up at the top of the range and nowhere else.
// ---------------------------------------------------------------------------

global_asm!(
    r#"
.section .text.rvcpair,"ax",@progbits
.option push
.option rvc
.globl __rvcpair_begin
__rvcpair_begin:
    /* quadrant 0 */
    c.addi4spn  a0, sp, 4
    c.addi4spn  a5, sp, 1020
    c.lw        a1, 0(a0)
    c.lw        a4, 124(a3)
    c.sw        a1, 4(a0)
    c.sw        a4, 124(a3)
    /* quadrant 1 */
    c.nop
    c.addi      a2, 1
    c.addi      s1, -32
    c.addi      t0, 31
    c.jal       .+16
    c.jal       .-2048
    c.li        a3, -1
    c.li        a4, 31
    c.addi16sp  sp, 16
    c.addi16sp  sp, -512
    c.lui       a5, 1
    c.lui       s1, 0xfffe0
    c.srli      a0, 1
    c.srli      a0, 31
    c.srai      a1, 31
    c.andi      a2, -32
    c.andi      a3, 31
    c.sub       a0, a1
    c.xor       a0, a1
    c.or        a0, a1
    c.and       a0, a1
    c.j         .+8
    c.j         .-2048
    c.beqz      a0, .+8
    c.beqz      s1, .-256
    c.bnez      a4, .-8
    c.bnez      a5, .+254
    /* quadrant 2 */
    c.slli      a0, 1
    c.slli      t0, 31
    c.lwsp      a0, 0(sp)
    c.lwsp      t1, 252(sp)
    c.jr        t0
    c.mv        a0, t1
    c.ebreak
    c.jalr      t0
    c.add       a0, t1
    c.swsp      ra, 4(sp)
    c.swsp      t2, 252(sp)
.globl __rvcpair_end
__rvcpair_end:
.option pop
"#
);

global_asm!(
    r#"
.section .text.norvcpair,"ax",@progbits
.option push
.option norvc
.globl __norvcpair_begin
__norvcpair_begin:
    /* quadrant 0 */
    addi        a0, sp, 4
    addi        a5, sp, 1020
    lw          a1, 0(a0)
    lw          a4, 124(a3)
    sw          a1, 4(a0)
    sw          a4, 124(a3)
    /* quadrant 1 */
    addi        zero, zero, 0
    addi        a2, a2, 1
    addi        s1, s1, -32
    addi        t0, t0, 31
    jal         ra, .+16
    jal         ra, .-2048
    addi        a3, zero, -1
    addi        a4, zero, 31
    addi        sp, sp, 16
    addi        sp, sp, -512
    lui         a5, 1
    lui         s1, 0xfffe0
    srli        a0, a0, 1
    srli        a0, a0, 31
    srai        a1, a1, 31
    andi        a2, a2, -32
    andi        a3, a3, 31
    sub         a0, a0, a1
    xor         a0, a0, a1
    or          a0, a0, a1
    and         a0, a0, a1
    jal         zero, .+8
    jal         zero, .-2048
    beq         a0, zero, .+8
    beq         s1, zero, .-256
    bne         a4, zero, .-8
    bne         a5, zero, .+254
    /* quadrant 2 */
    slli        a0, a0, 1
    slli        t0, t0, 31
    lw          a0, 0(sp)
    lw          t1, 252(sp)
    jalr        zero, 0(t0)
    add         a0, zero, t1
    ebreak
    jalr        ra, 0(t0)
    add         a0, a0, t1
    sw          ra, 4(sp)
    sw          t2, 252(sp)
.globl __norvcpair_end
__norvcpair_end:
.option pop
"#
);

// ---------------------------------------------------------------------------
// The executed pair. Same source, one region compressed and one not, so QEMU
// checks that the compressed encodings mean what the loader says they mean.
// ---------------------------------------------------------------------------

global_asm!(
    r#"
.section .text.rvcexec,"ax",@progbits
.option push
.option rvc
.globl rvc_exec
rvc_exec:
    addi    sp, sp, -16
    sw      ra, 12(sp)
    addi    a1, a0, 1
    slli    a1, a1, 2
    sw      a1, 0(sp)
    lw      a2, 0(sp)
    add     a0, a0, a2
    beqz    a0, 1f
    addi    a0, a0, 7
1:
    andi    a0, a0, 255
    lw      ra, 12(sp)
    addi    sp, sp, 16
    ret
.option pop

.section .text.norvcexec,"ax",@progbits
.option push
.option norvc
.globl norvc_exec
norvc_exec:
    addi    sp, sp, -16
    sw      ra, 12(sp)
    addi    a1, a0, 1
    slli    a1, a1, 2
    sw      a1, 0(sp)
    lw      a2, 0(sp)
    add     a0, a0, a2
    beqz    a0, 1f
    addi    a0, a0, 7
1:
    andi    a0, a0, 255
    lw      ra, 12(sp)
    addi    sp, sp, 16
    ret
.option pop
"#
);
