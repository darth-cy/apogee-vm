#![no_std]
#![no_main]
//! S21's guest: `guest_sdk::keccak256` over a corpus that covers every shape
//! the sponge has, checked in-guest against digests a reference computed.
//!
//! It is the fixture for the keccak-f[1600] delegation family
//! (`docs/spec/delegation.md`), and it is the same binary under both
//! executors. Under `crates/emulator` the delegation ecall runs the circuit's
//! function and the invocations reach the `KECCAK_F` trace buffer; under
//! `qemu-riscv32` the same ecall answers `-ENOSYS` and the SDK's software
//! fallback runs. **The digests are the same either way**, which is exactly
//! what acceptance 3 asks: the two paths are bit-identical behind one frozen
//! signature.
//!
//! # The corpus
//!
//! Byte `i` of the source is `(31i + 7) mod 256`, and the six inputs are its
//! first 0, 1, 135, 136, 137 and 400 bytes:
//!
//! - **0** — the empty input, whose only block is the padding;
//! - **1** — one byte, the shortest partial block;
//! - **135** — one short of the rate, the block where `pad10*1`'s two bytes
//!   land in the same byte;
//! - **136** — exactly the rate, so the padding takes a whole extra block;
//! - **137** — one past it, the first input with a full block and a partial;
//! - **400** — two full blocks and a partial: a multi-block input.
//!
//! Ten keccak-f permutations in all, so a `2^8` delegation shard holds them
//! with room to spare.
//!
//! # fd 0, fd 1, fd 2, fd 3
//!
//! Unused. The guest reads nothing and writes nothing: `EXIT` and the
//! delegation call are the only provable ecalls, so a `write` would make the
//! fixture unprovable.
//!
//! # The result
//!
//! The exit status, `a0`: **6**, one per check passed, or `200 + i` on the
//! first mismatch — which names the corpus entry rather than leaving a count
//! one short of what it should be.

use constants::keccak;
use guest_sdk::{entry, exit, keccak256};

entry!(main);

/// The corpus's source bytes.
const SOURCE: usize = 400;

/// The input lengths, ascending.
const LENGTHS: [usize; 6] = [0, 1, 135, 136, 137, SOURCE];

/// `keccak256` of each entry, as eight little-endian `u32` words.
///
/// Derived by `tiny-keccak` and pinned here;
/// `crates/emulator/tests/guests.rs` re-derives them from the same reference
/// so a stale literal cannot pass.
const DIGESTS: [[u32; 8]; 6] = [
    // keccak256 of the first 0 bytes
    [
        0x0146d2c5, 0x3c23f786, 0xb27d7e92, 0xc003c7dc, 0x53b600e5, 0x3b2782ca, 0x04d8fa7b,
        0x70a4855d,
    ],
    // keccak256 of the first 1 bytes
    [
        0xc74b2aee, 0x2bda81db, 0x6be56471, 0xe2b14936, 0xc4589ca0, 0xab5db155, 0x6c14d9dd,
        0xbcce8275,
    ],
    // keccak256 of the first 135 bytes
    [
        0x4581eead, 0x03dc33bb, 0x9444ad20, 0x91b3ee5e, 0x0f8f66e4, 0xbbcc697c, 0x7c0a55f6,
        0x525e24ba,
    ],
    // keccak256 of the first 136 bytes
    [
        0x5afcccea, 0xf16bbfa7, 0xef091894, 0x6aeec97c, 0xa706a32f, 0xf2e31ddd, 0x494850e8,
        0xc4e3a5b0,
    ],
    // keccak256 of the first 137 bytes
    [
        0x960b0eea, 0x0b9f4657, 0x4f60534f, 0x4bab6810, 0xb0e7a5d4, 0x4ad258a4, 0x2efef178,
        0xb04dbdc7,
    ],
    // keccak256 of the first 400 bytes
    [
        0x26e1438e, 0xb3dc94fd, 0xd7709796, 0x0ef7ff20, 0xac6e751c, 0x70d7ef34, 0x28ffeb8a,
        0xd2790a74,
    ],
];

fn main() {
    let mut source = [0u8; SOURCE];
    for (i, byte) in source.iter_mut().enumerate() {
        *byte = (31u32.wrapping_mul(i as u32).wrapping_add(7)) as u8;
    }
    let mut passed = 0u32;
    for (i, len) in LENGTHS.iter().enumerate() {
        let digest = keccak256(&source[..*len]);
        let mut want = [0u8; keccak::DIGEST_BYTES];
        for (w, word) in DIGESTS[i].iter().enumerate() {
            want[4 * w..4 * w + 4].copy_from_slice(&word.to_le_bytes());
        }
        if digest != want {
            exit(200 + i as i32);
        }
        passed += 1;
    }
    exit(passed as i32);
}
