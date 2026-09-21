#![no_std]
#![no_main]
//! S20's guest: the smallest program whose *one* busiest family does not fit
//! one shard. It exists to make the block layer's stage gate real — one
//! execution cut into two shards of the same cycle-owning family, with pc
//! continuity across the cut carried by the global memory multiset and by
//! nothing else (`docs/spec/block-proof.md` §3).
//!
//! The shape is a counted loop whose body is 64 unrolled `add`s:
//!
//! ```text
//! t1 = 0; t2 = 1; t0 = 16384
//! spin:  add t1, t1, t2   x64        65 add/sub cycles per iteration
//!        addi t0, t0, -1
//!        bne  t0, x0, spin            1 jump/branch/slt cycle per iteration
//! ```
//!
//! so `ADD_SUB_LUI_AUIPC` runs `65 * 16384 + 4 prologue + 6 epilogue =
//! 1,064,970` cycles — 16,394 past `2^20`, the smallest height a family
//! carrying a timestamp gap obligation can have (`docs/spec/lookup.md` §3) —
//! and `JUMP_BRANCH_SLT` runs `16384 + 2 = 16,386`, which fits one shard. Two
//! shards of one family, one of every other, and a family in the `VmConfig`
//! with zero shards: `ZERO_WINDOWS`, because nothing here touches RAM.
//!
//! **Why a loop and not a straight line.** A family's `VmConfig` height is
//! both its shard height *and* its decoded table's row count, and the table is
//! pc/2-indexed, so 2^20 rows reach pc `0x1FFFFE`. A straight-line run of
//! 2^20 four-byte instructions is 4 MiB of `.text` and would need a 2^22 table
//! — which is a 2^22 shard, and one shard again. Only a loop separates
//! occupancy from image size.
//!
//! **Why no compressed instructions.** `.option norvc` throughout: the demo is
//! about the shard cut, and uniform four-byte instructions keep the pc
//! arithmetic obvious. `guests/control` is where RVC control flow is proven.
//!
//! # fd 0, fd 1, fd 2, fd 3
//!
//! Unused. The guest reads nothing and writes nothing: `EXIT` is still the
//! only provable ecall (`docs/spec/shard-proof.md` §8.4).
//!
//! # The result
//!
//! The exit status, `a0`: 2, the number of checks — the accumulator reached
//! `64 * 16384 = 0x100000` and the counter reached 0 — or 1 from `fail`. Both
//! are below 256, which is all of an exit status `qemu-riscv32` reports.

use core::arch::global_asm;

global_asm!(
    ".section .text._start,\"ax\",@progbits",
    ".globl _start",
    "_start:",
    ".option norvc",
    "  addi  s0, x0, 0", // checks passed
    "  addi  t1, x0, 0", // the accumulator
    "  addi  t2, x0, 1", // the addend
    "  lui   t0, 4",     // the counter: 4 << 12 = 16384
    "spin:",
    ".rept 64",
    "  add   t1, t1, t2",
    ".endr",
    "  addi  t0, t0, -1",
    "  bne   t0, x0, spin",
    // The accumulator is 64 * 16384 = 0x100000, which `lui` writes whole.
    "  lui   t3, 0x100",
    "  bne   t1, t3, fail",
    "  addi  s0, s0, 1",
    // The counter fell to exactly 0.
    "  bne   t0, x0, fail",
    "  addi  s0, s0, 1",
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
