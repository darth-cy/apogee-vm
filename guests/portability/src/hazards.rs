//! What Rust itself lets differ between a 64-bit host and the 32-bit guest.
//!
//! Every other workload emits the same bytes on every target. These emit
//! values that are *allowed* to differ, one section per hazard, so that the
//! suite can hold QEMU and the emulator to each other on them, show the host
//! differing where Rust says it may, and hand a guest author the list in one
//! place. None of them is a bug: each is a program depending on something
//! Rust defines per target, which is the surprise worth knowing about before
//! moving code into a proof.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::hash::{Hash, Hasher};
use core::hint::black_box;
use core::mem::size_of;

use crate::{Ctx, Fault};

pub const TAGS: (u8, u8) = (0xe0, 0xef);
pub const FAULTS: &[Fault] = &[];

/// How a platform-dependent section may differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Divergence {
    /// Follows `usize`'s width, so it differs on every 64-bit host by Rust's
    /// definition. The suite insists that it does.
    PointerWidth,
    /// Follows the host's floating-point unit. Rust leaves the bits of a NaN
    /// an operation produces unspecified: RISC-V's soft float and AArch64
    /// produce the positive quiet NaN, x86-64's SSE the negative one.
    NanBits,
}

/// One declared divergence.
pub struct Platform {
    pub tag: u8,
    pub kind: Divergence,
    pub what: &'static str,
}

pub const TAG_HASH_SLICE: u8 = 0xe0;
pub const TAG_HASH_USIZE: u8 = 0xe1;
pub const TAG_SIZE_OF: u8 = 0xe2;
pub const TAG_USIZE_OVERFLOW: u8 = 0xe3;
pub const TAG_NAN_BITS: u8 = 0xe4;
pub const TAG_USIZE_CAST: u8 = 0xe5;

/// Every section the host is excused from, and why.
pub const PLATFORM_DEPENDENT: [Platform; 6] = [
    Platform {
        tag: TAG_HASH_SLICE,
        kind: Divergence::PointerWidth,
        what: "`core::hash` of a slice: the length prefix goes through `write_usize`, 4 bytes \
               on the guest and 8 on a 64-bit host, so a `#[derive(Hash)]` fingerprint of \
               anything holding a `Vec`, a `String` or a slice differs",
    },
    Platform {
        tag: TAG_HASH_USIZE,
        kind: Divergence::PointerWidth,
        what: "`core::hash` of a `usize`",
    },
    Platform {
        tag: TAG_SIZE_OF,
        kind: Divergence::PointerWidth,
        what: "`size_of` of anything holding a pointer or a `usize`: `usize`, `Box<T>`, `&[T]`, \
               `(u8, usize)`, `Option<Box<T>>`",
    },
    Platform {
        tag: TAG_USIZE_OVERFLOW,
        kind: Divergence::PointerWidth,
        what: "`usize` arithmetic overflows at 2^32 on the guest: a `checked_mul` the host \
               answers `Some` for is `None`, and an unchecked one panics",
    },
    Platform {
        tag: TAG_NAN_BITS,
        kind: Divergence::NanBits,
        what: "the bits of a NaN an operation produces: 0x7ff8... from RISC-V's soft float and \
               from AArch64, 0xfff8... from x86-64",
    },
    Platform {
        tag: TAG_USIZE_CAST,
        kind: Divergence::PointerWidth,
        what: "the quiet half of the width problem: `as usize` on a value past 2^32 keeps the low \
               32 bits on the guest and all 64 on the host, with no panic to announce it — unlike \
               the arithmetic above, which overflow checks catch. `usize::BITS` and `usize::MAX` \
               go with it",
    },
];

/// FNV-1a behind `core::hash::Hasher`, so what reaches it is exactly what
/// `Hash` writes.
struct Fnv(u64);

impl Hasher for Fnv {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.0 = (self.0 ^ u64::from(*b)).wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

fn hash<T: Hash + ?Sized>(value: &T) -> [u8; 8] {
    let mut hasher = Fnv(0xcbf2_9ce4_8422_2325);
    value.hash(&mut hasher);
    hasher.finish().to_le_bytes()
}

pub fn run(cx: &mut Ctx) {
    // At least 16 bytes, so the overflow below always happens on the guest.
    let spread = 16 + cx.scale() as usize;
    let len = 16 + cx.rng().index(spread);
    let data: Vec<u8> = cx.rng().bytes(len);

    cx.section(TAG_HASH_SLICE, &hash(data.as_slice()));
    cx.section(TAG_HASH_USIZE, &hash(&data.len()));

    let sizes = [
        size_of::<usize>(),
        size_of::<Box<u8>>(),
        size_of::<&[u8]>(),
        size_of::<(u8, usize)>(),
        size_of::<Option<Box<u64>>>(),
    ];
    let sizes: Vec<u8> = sizes.iter().map(|s| *s as u8).collect();
    cx.section(TAG_SIZE_OF, &sizes);

    // len * 2^28 >= 2^32: in range for a 64-bit usize, not for a 32-bit one.
    let product = black_box(data.len()).checked_mul(1 << 28);
    let product = product.map_or(u64::MAX, |p| p as u64);
    cx.section(TAG_USIZE_OVERFLOW, &product.to_le_bytes());

    // 0/0 and inf + -inf, from operands the compiler cannot fold.
    let zero = black_box(f64::from(data[0]) * 0.0);
    let infinities = (black_box(f64::INFINITY), black_box(f64::NEG_INFINITY));
    let mut bits = Vec::with_capacity(20);
    bits.extend_from_slice(&(zero / black_box(-0.0)).to_bits().to_le_bytes());
    bits.extend_from_slice(&(infinities.0 + infinities.1).to_bits().to_le_bytes());
    let zero32 = black_box(f32::from(data[1]) * 0.0);
    bits.extend_from_slice(&(zero32 / black_box(-0.0f32)).to_bits().to_le_bytes());
    cx.section(TAG_NAN_BITS, &bits);

    // Narrowing, which says nothing when it loses the top half.
    let wide = black_box(0x1_0000_0007u64 | (u64::from(data[2]) << 40));
    let mut cast = Vec::with_capacity(24);
    cast.extend_from_slice(&((wide as usize) as u64).to_le_bytes());
    cast.extend_from_slice(&u64::from(usize::BITS).to_le_bytes());
    cast.extend_from_slice(&(usize::MAX as u64).to_le_bytes());
    cx.section(TAG_USIZE_CAST, &cast);
}
