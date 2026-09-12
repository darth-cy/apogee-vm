#![no_std]
#![no_main]
//! The portability guest: `portability::run` over fd 0, each section
//! committed to fd 1 the moment it is produced, so a run that panics has
//! committed exactly what the host's run of the same source had emitted before
//! its panic. `crates/emulator/tests/portability.rs` runs it against the host
//! and against QEMU.
//!
//! Two inputs are the guest's alone, because the host has no such heap: fd 0
//! beginning `MODE_HEAP_CEILING` or `MODE_HEAP_UNDER_DEEP_STACK` runs one of the
//! probes below, which hold guest-sdk's allocator to its ceiling. Each commits a
//! line when the block it is owed is granted, then asks for the block it must
//! be refused; the refusal is `exit(71)`, so the second line is never written.

extern crate alloc;

use alloc::vec::Vec;
use core::cell::Cell;
use core::hint::black_box;
use core::mem::forget;

use constants::guest_memory::{RAM_LENGTH, RAM_ORIGIN, STACK_RESERVE};
use portability::{MODE_HEAP_CEILING, MODE_HEAP_UNDER_DEEP_STACK};

guest_sdk::entry!(main);

fn main() {
    let input = read_all();
    match input.first() {
        Some(&MODE_HEAP_CEILING) => heap_ceiling(),
        Some(&MODE_HEAP_UNDER_DEEP_STACK) => descend(DEPTH),
        _ => portability::run(&input, &mut |section| guest_sdk::commit(section)),
    }
}

/// All of fd 0. `read_input` stops short only at the end of the stream.
fn read_all() -> Vec<u8> {
    let mut input = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        let n = guest_sdk::read_input(&mut buf);
        input.extend_from_slice(&buf[..n]);
        if n < buf.len() {
            return input;
        }
    }
}

/// The untouched blocks the probes walk the heap up with: moving the bump
/// costs no memory traffic.
const CHUNK: usize = 1 << 20;

/// Where the next block will start, read by taking a one-byte block.
fn bump() -> usize {
    let block: Vec<u8> = Vec::with_capacity(1);
    let next = block.as_ptr() as usize + 1;
    forget(block);
    next
}

/// Take untouched blocks until the next would start within `CHUNK` of `limit`,
/// and return where that is.
fn walk_to(limit: usize) -> usize {
    let mut next = bump();
    while limit - next > CHUNK {
        let block: Vec<u8> = Vec::with_capacity(CHUNK);
        next = block.as_ptr() as usize + CHUNK;
        forget(block);
    }
    next
}

/// Take the block `[next, end)`, which must be granted exactly where asked.
fn take_up_to(next: usize, end: usize) {
    if end > next {
        let block: Vec<u8> = Vec::with_capacity(end - next);
        assert_eq!(
            block.as_ptr() as usize + block.capacity(),
            end,
            "the block was not placed at the bump"
        );
        forget(block);
    }
}

/// The ceiling while the stack is shallow: the top `STACK_RESERVE` bytes of RAM
/// are the stack's. A block ending exactly at them is granted; one byte more is
/// not.
fn heap_ceiling() {
    let ceiling = (RAM_ORIGIN + RAM_LENGTH - STACK_RESERVE) as usize;
    take_up_to(walk_to(ceiling), ceiling);
    guest_sdk::commit(b"reached the ceiling\n");
    forget(black_box(Vec::<u8>::with_capacity(1)));
    guest_sdk::commit(b"allocated past the ceiling\n");
}

/// Frames the deep probe recurses through.
const FRAME: usize = 4096;

/// Deep enough that the stack is 1 MiB past its reserve even if every frame
/// were only `FRAME` bytes.
const DEPTH: usize = (STACK_RESERVE as usize + (1 << 20)) / FRAME;

/// Recurse `depth` frames down, then probe from the bottom.
#[inline(never)]
fn descend(depth: usize) {
    let frame = black_box([0u8; FRAME]);
    if depth == 0 {
        under_deep_stack();
    } else {
        descend(depth - 1);
    }
    black_box(&frame);
}

/// The live-`sp` half of the ceiling. The stack is deeper than its reserve
/// here, so nothing but `sp` stands between the heap and this frame: a block
/// ending well below it is granted, and one reaching over its local is not.
///
/// Before the ceiling looked at `sp`, the second block was granted and a write
/// to it rewrote `local` — the bug the portability suite found.
fn under_deep_stack() {
    /// Room for the allocator's own call chain below this frame.
    const CLEARANCE: usize = 64 << 10;
    let local = Cell::new(0u8);
    let here = local.as_ptr() as usize;
    take_up_to(walk_to(here - CLEARANCE), here - CLEARANCE);
    guest_sdk::commit(b"granted a block below the live stack\n");
    forget(black_box(Vec::<u8>::with_capacity(CLEARANCE + 1)));
    local.set(black_box(1));
    guest_sdk::commit(b"allocated over the live stack\n");
}
