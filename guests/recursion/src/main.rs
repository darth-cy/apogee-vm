#![no_std]
#![no_main]
//! The recursion guest's leaf (`docs/spec/recursion.md` §7, §8): base shards
//! verified by replaying their families' tapes over the field memory, each
//! folded into the node's accumulator `(A, B)` — two MSMs on `FQ_OP` — and the
//! accumulator journaled.
//!
//! **A measurement guest, not yet a recursion node.** It runs blind: its
//! advice is a list of steps `host::recursion::leaf_advice` chose and ran
//! natively first, tapes and slots included, and nothing binds them. What it
//! measures is a leaf's work, by family. A node derives its steps from the
//! statement, replays tapes its image holds, and fills its slots from its own
//! run of the statement's global phase (§8).
//!
//! A body is copied into RAM once, before its first replay, because a
//! delegation frame lies below `2^31` and advice above it.
//!
//! # Journal and exit status
//!
//! The accumulator's two points, `A` then `B`, each coordinate four limb
//! cells, each cell the eight little-endian words `EXPORT` writes. Exit 0, or
//! 10 if the advice does not decode; a step that refuses is a fatal frame
//! error, the coprocessor's `EQ` and `MULEQ` having no witness.

extern crate alloc;

use alloc::vec::Vec;

use constants::{field_io as io, fq_op as fq, fr_op as fr};
use guest_sdk::recursion::{field_io, fq_op, fr_op, import, replay};
use guest_sdk::{advice, commit, entry, exit};

entry!(main);

/// The advice does not decode.
const EXIT_INPUT: i32 = 10;

/// A cursor over the advice; any read past its end is [`EXIT_INPUT`].
struct Advice {
    bytes: &'static [u8],
    at: usize,
}

impl Advice {
    fn take(&mut self, n: usize) -> &'static [u8] {
        let end = self.at.checked_add(n).unwrap_or_else(|| exit(EXIT_INPUT));
        let out = self
            .bytes
            .get(self.at..end)
            .unwrap_or_else(|| exit(EXIT_INPUT));
        self.at = end.next_multiple_of(4);
        out
    }

    fn u32(&mut self) -> u32 {
        let mut word = [0u8; 4];
        word.copy_from_slice(self.take(4));
        u32::from_le_bytes(word)
    }

    /// A count and that many words, copied out.
    fn words(&mut self) -> Vec<u32> {
        let n = self.u32() as usize;
        let bytes = self.take(n.checked_mul(4).unwrap_or_else(|| exit(EXIT_INPUT)));
        bytes
            .chunks_exact(4)
            .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
            .collect()
    }

    /// A length and that many bytes, in place.
    fn bytes(&mut self) -> &'static [u8] {
        let n = self.u32() as usize;
        self.take(n)
    }
}

fn main() {
    let mut input = Advice {
        bytes: advice(),
        at: 0,
    };
    // A's point, scalar and zero cells, B's, then the sentinel's.
    let header = input.words();
    if header.len() != 7 {
        exit(EXIT_INPUT);
    }
    let bodies: Vec<Vec<u32>> = (0..input.u32()).map(|_| input.words()).collect();
    let lists: Vec<Vec<u32>> = (0..input.u32()).map(|_| input.words()).collect();
    for _ in 0..input.u32() {
        match input.u32() {
            0 => {
                let list = lists
                    .get(input.u32() as usize)
                    .unwrap_or_else(|| exit(EXIT_INPUT));
                import(list, input.bytes());
            }
            1 => replay(
                bodies
                    .get(input.u32() as usize)
                    .unwrap_or_else(|| exit(EXIT_INPUT)),
            ),
            2 => {
                let first = input.u32();
                let blob = input.bytes();
                let cells: Vec<u32> = (first..first + (blob.len() / 32) as u32).collect();
                import(&cells, blob);
            }
            3 => {
                let (limbs, scalar) = (input.u32(), input.u32());
                let (point, at, zero) = match input.u32() {
                    0 => (header[0], header[1], header[2]),
                    1 => (header[3], header[4], header[5]),
                    _ => exit(EXIT_INPUT),
                };
                fq_op(&mut [fq::FROM128, point, limbs, zero]);
                fq_op(&mut [fq::FROM128, point + 4, limbs + 2, zero]);
                fr_op(&mut [fr::ADD, at, scalar, 0]);
            }
            4 => {
                let limbs = input.u32();
                for k in 0..4 {
                    fr_op(&mut [fr::EQ, 0, limbs + k, header[6]]);
                }
            }
            _ => exit(EXIT_INPUT),
        }
    }
    let mut journal = Vec::new();
    for cell in input.words() {
        let mut words = [0u32; 8];
        field_io(&mut [io::EXPORT, cell, words.as_mut_ptr() as u32]);
        for w in words {
            journal.extend_from_slice(&w.to_le_bytes());
        }
    }
    commit(&journal);
}
