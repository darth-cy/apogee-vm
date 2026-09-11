#![no_std]
#![no_main]
//! Every A-extension instruction, as the compiler emits them.
//!
//! This guest exists for the atomics family. It is the program that makes the
//! preprocessor derive that family, and — decoded with the family
//! force-detached — the program that shows detachment is sound: an `amoadd.w`
//! nobody claims is a loud failure naming its pc, not a silent drop.
//!
//! One hart means no contention, so each atomic below is just a read-modify-
//! write. That is the point: the answers are plain arithmetic a host can
//! recompute, while the instructions are the real ones. The operations cover
//! all eleven: `fetch_add` is `amoadd.w`, `swap` is `amoswap.w`, `fetch_xor`,
//! `fetch_and` and `fetch_or` are `amoxor.w`, `amoand.w` and `amoor.w`, the
//! signed and unsigned `fetch_min`/`fetch_max` are the four min/max AMOs, and
//! `compare_exchange` is an `lr.w`/`sc.w` loop. The `SeqCst` load in the
//! compare-and-swap loop brings `fence` instructions with it.
//!
//! # fd 0, the public input
//!
//! ```text
//!           0..4     n               u32 LE; how many rounds to run
//! ```
//!
//! # fd 1, the public output
//!
//! Nine `u32` LE words: the final value of each cell in declaration order —
//! `SUM`, `LAST`, `MIXED`, `MASKED`, `FLAGS`, `LOW`, `HIGH`, `STEPS`, the
//! signed cell as its two's-complement bits — then `OLD`, every value an
//! atomic returned, folded in order. An AMO has two halves, the memory write
//! and the old value it hands back in `rd`, and `OLD` is what makes the
//! second observable. See `crates/loader/tests/qemu.rs` for the host's
//! recomputation.

use core::sync::atomic::{AtomicI32, AtomicU32, Ordering::SeqCst};

guest_sdk::entry!(main);

static SUM: AtomicU32 = AtomicU32::new(0);
static LAST: AtomicU32 = AtomicU32::new(0);
static MIXED: AtomicU32 = AtomicU32::new(0);
static MASKED: AtomicU32 = AtomicU32::new(u32::MAX);
static FLAGS: AtomicU32 = AtomicU32::new(0);
static LOW: AtomicI32 = AtomicI32::new(i32::MAX);
static HIGH: AtomicU32 = AtomicU32::new(0);
static STEPS: AtomicU32 = AtomicU32::new(1);
// Written only to be read back through the other two min/max forms.
static SIGNED_HIGH: AtomicI32 = AtomicI32::new(i32::MIN);
static UNSIGNED_LOW: AtomicU32 = AtomicU32::new(u32::MAX);

fn main() {
    let mut n = [0u8; 4];
    assert_eq!(
        guest_sdk::read_input(&mut n),
        4,
        "atomics: public input is one u32"
    );
    let n = u32::from_le_bytes(n);

    let mut old = 0u32;
    for i in 0..n {
        // A spread of values: an odd multiplier visits every residue.
        let x = i.wrapping_mul(0x9e37_79b9);
        old = fold(old, SUM.fetch_add(x, SeqCst));
        old = fold(old, LAST.swap(x, SeqCst));
        old = fold(old, MIXED.fetch_xor(x, SeqCst));
        old = fold(old, MASKED.fetch_and(!(1 << (i % 32)), SeqCst));
        old = fold(old, FLAGS.fetch_or(1 << (x >> 27), SeqCst));
        old = fold(old, LOW.fetch_min(x as i32, SeqCst) as u32);
        old = fold(old, SIGNED_HIGH.fetch_max(x as i32, SeqCst) as u32);
        old = fold(old, HIGH.fetch_max(x, SeqCst));
        // Offset so the minimum is not the trivial 0 the first round would
        // otherwise leave it at.
        old = fold(old, UNSIGNED_LOW.fetch_min(x ^ 0x5555_5555, SeqCst));

        // A compare-and-swap loop: lr.w and sc.w.
        loop {
            let cur = STEPS.load(SeqCst);
            let next = cur.wrapping_mul(3).wrapping_add(1);
            if STEPS.compare_exchange(cur, next, SeqCst, SeqCst).is_ok() {
                break;
            }
        }
    }

    // The signed maximum and the unsigned minimum fold into two other cells,
    // each by an operation that is one-to-one in the value folded, so each of
    // the eleven instructions' memory effects reaches fd 1.
    HIGH.fetch_xor(SIGNED_HIGH.load(SeqCst) as u32, SeqCst);
    SUM.fetch_add(UNSIGNED_LOW.load(SeqCst), SeqCst);

    for cell in [&SUM, &LAST, &MIXED, &MASKED, &FLAGS] {
        guest_sdk::commit(&cell.load(SeqCst).to_le_bytes());
    }
    guest_sdk::commit(&LOW.load(SeqCst).to_le_bytes());
    guest_sdk::commit(&HIGH.load(SeqCst).to_le_bytes());
    guest_sdk::commit(&STEPS.load(SeqCst).to_le_bytes());
    guest_sdk::commit(&old.to_le_bytes());
}

/// One step of an order-sensitive fold: multiplying by an odd number is
/// invertible modulo 2^32, so a change in any one folded value changes the
/// result.
fn fold(acc: u32, value: u32) -> u32 {
    acc.wrapping_mul(31).wrapping_add(value)
}
