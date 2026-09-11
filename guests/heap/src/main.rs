#![no_std]
#![no_main]
//! The allocator exercise: `Vec` and `Box` churned through the bump
//! allocator, so the heap's traffic is in the trace and the memory
//! self-check has to balance it.
//!
//! Every allocation here is real — a `Vec` grown one push at a time
//! reallocates and copies, one `Box` per element, a vector of vectors
//! filtered and cloned — and `dealloc` does nothing, so the heap only ever
//! grows upward from `__heap_start`. `crates/emulator/tests/guests.rs` redoes
//! the arithmetic on the host.
//!
//! # fd 0, the public input
//!
//! ```text
//!           0..4     n               u32 LE; how many elements to allocate
//! ```
//!
//! # fd 1, the public output
//!
//! ```text
//!           0..4     sum             the squares 0^2 .. (n-1)^2, wrapping
//!           4..8     boxed           each square xor 0x5555, boxed, summed
//!           8..12    lengths         the kept rows' lengths, summed
//!          12..16    content         the kept rows' bytes, folded
//! ```
//!
//! Row `i` is the bytes `0 .. i % 13`, and a row is kept when its length is
//! even. The fold is `acc * 31 + byte`, wrapping.

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;

guest_sdk::entry!(main);

fn main() {
    let mut n = [0u8; 4];
    assert_eq!(
        guest_sdk::read_input(&mut n),
        4,
        "heap: public input is one u32"
    );
    let n = u32::from_le_bytes(n);

    // Grown from empty, one element at a time: every growth reallocates.
    let mut squares: Vec<u32> = Vec::new();
    for i in 0..n {
        squares.push(i.wrapping_mul(i));
    }

    let boxes: Vec<Box<u32>> = squares.iter().map(|s| Box::new(s ^ 0x5555)).collect();

    let mut rows: Vec<Vec<u8>> = (0..n).map(|i| (0..(i % 13) as u8).collect()).collect();
    rows.retain(|r| r.len().is_multiple_of(2));
    let kept = rows.clone();
    drop(rows);

    let sum = squares.iter().fold(0u32, |a, s| a.wrapping_add(*s));
    let boxed = boxes.iter().fold(0u32, |a, b| a.wrapping_add(**b));
    let lengths = kept
        .iter()
        .fold(0u32, |a, r| a.wrapping_add(r.len() as u32));
    let content = kept
        .iter()
        .flatten()
        .fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(*b as u32));
    for word in [sum, boxed, lengths, content] {
        guest_sdk::commit(&word.to_le_bytes());
    }
}
