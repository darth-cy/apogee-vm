#![no_std]
#![no_main]
//! The ecall-shim fixture: a byte-for-byte echo of fd 0 to fd 1, plus the three
//! shims that are not an echo — the private hint channel, diagnostics, and a
//! precompile that is not there yet.
//!
//! Its buffers are heap-allocated on purpose. Nothing else in `guests/` needs
//! `alloc`, so without this the bump allocator would be dead-stripped out of
//! every binary and the largest `unsafe` surface in the workspace would run
//! nowhere. Here it is linked and exercised under QEMU, at two alignments.
//!
//! # fd 0, the public input
//!
//! Any number of bytes, with no structure of any kind. They are read 64 at a
//! time until a read comes back short, which is the end of the stream.
//!
//! # fd 1, the public output
//!
//! The fd 0 stream, byte for byte, and nothing else. Neither the hint nor the
//! permuted state ever reaches it; see below for why that is the point.
//!
//! # fd 2, the diagnostics
//!
//! Four lines, in this order, none of which a verifier looks at:
//!
//! ```text
//! hint=<the fd 3 bytes, raw>
//! heap=ok
//! precompile=software              or `accelerated`, once a circuit exists
//! state0=<64 hex digits>           lane 0 of the permuted state
//! ```
//!
//! # fd 3, the prover's advice
//!
//! Up to 16 bytes, unstructured, and they reach fd 2 and nowhere else. That is
//! the whole reason this guest reads them: a hint binds nothing, so one that
//! reached fd 1 would be a committed value the prover chose.
//!
//! **This guest cannot run without an fd 3 to read from.** The zkVM always has
//! one. `qemu-riscv32` has only the descriptors it is given, and a `read` on a
//! closed one answers `-EBADF`, which the SDK treats as an executor fault and
//! exits 70 on. Running it by hand means opening fd 3 yourself, even on an
//! empty file:
//!
//! ```text
//! sh -c 'exec 3</dev/null; exec qemu-riscv32 ./echo' < input
//! ```

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use field::Fr;

guest_sdk::entry!(main);

fn main() {
    // fd 0 to fd 1, byte for byte. `read_input` fills the buffer or stops at
    // the end of the stream, so a short read is the end.
    let mut buf: Vec<u8> = vec![0u8; 64];
    loop {
        let n = guest_sdk::read_input(&mut buf);
        guest_sdk::commit(&buf[..n]);
        if n < buf.len() {
            break;
        }
    }

    // fd 3 is private and uncommitted, so what it carries goes to fd 2 and
    // never to fd 1. A guest that let a hint reach fd 1 would be proving a
    // statement the prover gets to choose.
    let mut h: Vec<u8> = vec![0u8; 16];
    let n = guest_sdk::hint(&mut h);
    guest_sdk::log(b"hint=");
    guest_sdk::log(&h[..n]);
    guest_sdk::log(b"\n");

    // The precompile has a number and a calling convention but no circuit, so
    // every executor answers -ENOSYS and this takes the software path.
    // A four-byte-aligned allocation as well as the byte ones above, so the
    // allocator's alignment rounding runs.
    let mut words: Vec<u32> = vec![0u32; 4];
    words[3] = 0xdead_beef;
    assert_eq!(
        words[3], 0xdead_beef,
        "the heap did not hand back what it was given"
    );
    guest_sdk::log(b"heap=ok\n");

    let mut state_bytes = [0u8; 96];
    state_bytes[0] = 1;
    state_bytes[32] = 2;
    state_bytes[64] = 3;
    if guest_sdk::poseidon2_permute(&mut state_bytes) {
        guest_sdk::log(b"precompile=accelerated\n");
    } else {
        software_poseidon2(&mut state_bytes);
        guest_sdk::log(b"precompile=software\n");
    }
    guest_sdk::log(b"state0=");
    log_hex(&state_bytes[..32]);
    guest_sdk::log(b"\n");
}

/// The precompile's software twin: the frozen S02 permutation, over the same
/// 96-byte canonical little-endian state the ecall takes.
fn software_poseidon2(bytes: &mut [u8; 96]) {
    let mut state = [Fr::ZERO; 3];
    for (i, lane) in state.iter_mut().enumerate() {
        let mut w = [0u8; 32];
        w.copy_from_slice(&bytes[32 * i..32 * (i + 1)]);
        *lane = Fr::from_bytes(&w).expect("precompile state lanes are canonical");
    }
    transcript::poseidon2_permute(&mut state);
    for (i, lane) in state.iter().enumerate() {
        bytes[32 * i..32 * (i + 1)].copy_from_slice(&lane.to_bytes());
    }
}

fn log_hex(bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for b in bytes {
        guest_sdk::log(&[DIGITS[(b >> 4) as usize], DIGITS[(b & 0xf) as usize]]);
    }
}
