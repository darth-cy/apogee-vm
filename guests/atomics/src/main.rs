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
//! # The public input
//!
//! ```text
//!           0..4     n               u32 LE; how many rounds to run
//! ```
//!
//! # The journal
//!
//! Nine `u32` LE words: the final value of each cell in declaration order —
//! `SUM`, `LAST`, `MIXED`, `MASKED`, `FLAGS`, `LOW`, `HIGH`, `STEPS`, the
//! signed cell as its two's-complement bits — then `OLD`, every value an
//! atomic returned, folded in order. An AMO has two
//! halves, the memory write and the old value it hands back in `rd`, and
//! `OLD` is what makes the second observable.
//!
//! Then two `u64` LE words from the same rounds over 64-bit cells, whose
//! atomics are the eleven `.d` forms: the cells folded in declaration order,
//! and every value they returned, folded.
//!
//! # The advice
//!
//! Unused: every cell here is a short deterministic function of `n`.

use core::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, AtomicU64, Ordering::SeqCst};

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
// The same cells, 64 bits wide.
static WIDE: [AtomicU64; 6] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(u64::MAX),
    AtomicU64::new(0),
    AtomicU64::new(1),
];
static WIDE_LOW: AtomicI64 = AtomicI64::new(i64::MAX);
static WIDE_HIGH: AtomicI64 = AtomicI64::new(i64::MIN);
static WIDE_ULOW: AtomicU64 = AtomicU64::new(u64::MAX);
static WIDE_UHIGH: AtomicU64 = AtomicU64::new(0);

fn main() {
    let mut n = [0u8; 4];
    assert_eq!(
        guest_sdk::read_input(&mut n),
        4,
        "atomics: the public input is one u32"
    );
    let n = u32::from_le_bytes(n);

    let mut old = 0u32;
    let mut wide_old = 0u64;
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

        // The `.d` forms, over values whose high words matter.
        let y = (x as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ i as u64;
        wide_old = fold64(wide_old, WIDE[0].fetch_add(y, SeqCst));
        wide_old = fold64(wide_old, WIDE[1].swap(y, SeqCst));
        wide_old = fold64(wide_old, WIDE[2].fetch_xor(y, SeqCst));
        wide_old = fold64(wide_old, WIDE[3].fetch_and(!(1 << (i % 64)), SeqCst));
        wide_old = fold64(wide_old, WIDE[4].fetch_or(1 << (y >> 58), SeqCst));
        wide_old = fold64(wide_old, WIDE_LOW.fetch_min(y as i64, SeqCst) as u64);
        wide_old = fold64(wide_old, WIDE_HIGH.fetch_max(y as i64, SeqCst) as u64);
        wide_old = fold64(wide_old, WIDE_ULOW.fetch_min(y, SeqCst));
        wide_old = fold64(wide_old, WIDE_UHIGH.fetch_max(y, SeqCst));
        loop {
            let cur = WIDE[5].load(SeqCst);
            let next = cur.wrapping_mul(3).wrapping_add(1);
            if WIDE[5].compare_exchange(cur, next, SeqCst, SeqCst).is_ok() {
                break;
            }
        }
    }

    // The signed maximum and the unsigned minimum fold into two other cells,
    // each by an operation that is one-to-one in the value folded, so each of
    // the eleven instructions' memory effects reaches the journal.
    HIGH.fetch_xor(SIGNED_HIGH.load(SeqCst) as u32, SeqCst);
    SUM.fetch_add(UNSIGNED_LOW.load(SeqCst), SeqCst);

    for cell in [&SUM, &LAST, &MIXED, &MASKED, &FLAGS] {
        guest_sdk::commit(&cell.load(SeqCst).to_le_bytes());
    }
    guest_sdk::commit(&LOW.load(SeqCst).to_le_bytes());
    guest_sdk::commit(&HIGH.load(SeqCst).to_le_bytes());
    guest_sdk::commit(&STEPS.load(SeqCst).to_le_bytes());
    guest_sdk::commit(&old.to_le_bytes());
    let mut wide = 0u64;
    for cell in &WIDE {
        wide = fold64(wide, cell.load(SeqCst));
    }
    for v in [
        WIDE_LOW.load(SeqCst) as u64,
        WIDE_HIGH.load(SeqCst) as u64,
        WIDE_ULOW.load(SeqCst),
        WIDE_UHIGH.load(SeqCst),
    ] {
        wide = fold64(wide, v);
    }
    guest_sdk::commit(&wide.to_le_bytes());
    guest_sdk::commit(&wide_old.to_le_bytes());
}

/// [`fold`] over 64 bits.
fn fold64(acc: u64, value: u64) -> u64 {
    acc.wrapping_mul(31).wrapping_add(value)
}

/// One step of an order-sensitive fold: multiplying by an odd number is
/// invertible modulo 2^32, so a change in any one folded value changes the
/// result.
fn fold(acc: u32, value: u32) -> u32 {
    acc.wrapping_mul(31).wrapping_add(value)
}
