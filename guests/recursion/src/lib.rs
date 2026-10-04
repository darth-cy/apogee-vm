#![no_std]
//! The recursion nodes' guest side (`docs/spec/recursion.md` §8,
//! `verifier_core::node`), which the two binaries share: `leaf` verifies a
//! slice of a base statement, `node` two to four children's proofs. Each
//! holds its image — every tape it replays — in `.rodata`, built by
//! `build.rs`, so its identity binds them. Its advice is the header and the
//! stream `host::recursion` laid out, read in the procedure's order, and
//! nothing in it is trusted: what it claims the procedure checks, or a later
//! node does.
//!
//! # Journal and exit status
//!
//! `verifier_core::node::journal`'s cells, each the eight little-endian words
//! `EXPORT` writes. Exit 0, or 10 if the image or the advice does not read; a
//! check that fails is a fatal frame error, the coprocessor's `EQ` and `MULEQ`
//! having no witness, or a panic.

extern crate alloc;

use alloc::vec::Vec;

use constants::field_io as io;
use guest_sdk::recursion::{field_io, fq_op, fr_op, import, import_run, p2_field, replay};
use guest_sdk::{advice, commit, exit};
use verifier_core::node::{node, Advice, Driver, Header, ImageTemplate, NodeImage};
use verifier_core::tape::{Cell, Op};

/// The image or the advice does not read.
pub const EXIT_INPUT: i32 = 10;

/// The guest's driver: each call the procedure makes, by its coprocessor
/// call, and each word of advice read where it is asked for.
struct Guest {
    advice: &'static [u8],
    at: usize,
    journal: Vec<u8>,
}

impl Guest {
    fn take(&mut self, n: usize) -> &'static [u8] {
        let end = self.at.checked_add(n).unwrap_or_else(|| exit(EXIT_INPUT));
        let out = self
            .advice
            .get(self.at..end)
            .unwrap_or_else(|| exit(EXIT_INPUT));
        self.at = end;
        out
    }

    fn word(&mut self) -> u32 {
        let w = self.take(4);
        u32::from_le_bytes([w[0], w[1], w[2], w[3]])
    }

    fn export(cell: Cell) -> [u32; 8] {
        let mut words = [0u32; 8];
        field_io(&mut [io::EXPORT, cell, words.as_mut_ptr() as u32]);
        words
    }
}

impl Driver for Guest {
    fn replay(&mut self, body: &[u32]) {
        replay(body);
    }

    fn run(&mut self, ops: &[Op]) {
        // Built at run time: a call each, its frame on the stack.
        for op in ops {
            match *op {
                Op::Fr(mut frame) => fr_op(&mut frame),
                Op::Duplex(mut frame) => p2_field(&mut frame),
                Op::Fq(mut frame) => fq_op(&mut frame),
                Op::Import { .. } => exit(EXIT_INPUT),
            }
        }
    }

    fn advise(&mut self, cells: &[Cell], _: Advice) {
        let blob = self.take(32 * cells.len());
        import(cells, blob);
    }

    fn template(&mut self, template: &ImageTemplate, _: Option<Cell>) {
        if let Some(cells) = template.witnesses() {
            let blob = self.take(32 * cells.len());
            import_run(cells.start, blob);
        }
        replay(template.body.body);
    }

    fn infinity(&mut self, _: Cell) -> bool {
        self.word() != 0
    }

    fn read(&mut self, cell: Cell) -> u32 {
        // An export is any representative; a word's is itself, and only a
        // word's has its seven high words 0.
        let words = Guest::export(cell);
        if words[1..].iter().any(|w| *w != 0) {
            exit(EXIT_INPUT);
        }
        words[0]
    }

    fn export(&mut self, cells: &[Cell]) {
        for cell in cells {
            for w in Guest::export(*cell) {
                self.journal.extend_from_slice(&w.to_le_bytes());
            }
        }
    }
}

/// The node whose image is `image`, over the advice, its journal committed.
pub fn run(image: &'static [u32]) {
    let image = NodeImage::read(image).unwrap_or_else(|| exit(EXIT_INPUT));
    let mut guest = Guest {
        advice: advice(),
        at: 0,
        journal: Vec::new(),
    };
    let n = guest.word() as usize;
    let words: Vec<u32> = (0..n).map(|_| guest.word()).collect();
    let header = match Header::read(&words) {
        Some((header, used)) if used == n => header,
        _ => exit(EXIT_INPUT),
    };
    node(&mut guest, &image, &header);
    commit(&guest.journal);
}
