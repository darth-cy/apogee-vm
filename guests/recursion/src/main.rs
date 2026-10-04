#![no_std]
#![no_main]
//! The recursion guest's leaf, by tape (`docs/spec/recursion.md` §7): each
//! base shard it is handed is verified by importing its slots and its proof's
//! inputs into the field memory and replaying its family's tape, every check
//! an assertion a coprocessor call makes.
//!
//! **A measurement guest, not yet a recursion node.** Its tapes and slots
//! are advice, which nothing binds, and it folds nothing: what it measures is
//! a leaf's verification work, by family. A node's tapes live in its image,
//! and its slots come from its own run of the statement's global phase
//! (`docs/spec/recursion.md` §8). `host::recursion::leaf_advice` lays the
//! advice out, and replays every tape natively first.
//!
//! A tape's body is copied into RAM once before its first replay, because a
//! delegation frame lies below `2^31` and advice above it.
//!
//! # Journal and exit status
//!
//! The number of shards verified, a little-endian `u32`. Exit 0, or 10 if the
//! advice does not decode; a shard whose tape refuses it is a fatal frame
//! error, the coprocessor's `EQ` having no witness.

extern crate alloc;

use alloc::vec::Vec;

use guest_sdk::recursion::{import, replay};
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
    let tapes: Vec<(Vec<u32>, Vec<u32>)> = (0..input.u32())
        .map(|_| (input.words(), input.words()))
        .collect();
    let n = input.u32();
    for _ in 0..n {
        let t = input.u32() as usize;
        let (imports, body) = tapes.get(t).unwrap_or_else(|| exit(EXIT_INPUT));
        let cells = input.words();
        import(&cells, input.bytes());
        import(imports, input.bytes());
        replay(body);
    }
    commit(&n.to_le_bytes());
}
