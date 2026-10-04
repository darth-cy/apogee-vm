#![no_std]
#![no_main]
//! The recursion leaf (`docs/spec/recursion.md` §8, `verifier_core::node`):
//! shards `from..to` of a base statement verified and folded into an
//! accumulator, and a journal that holds what a parent needs to fit the leaf
//! beside its neighbours.
//!
//! Its image holds every tape it replays, built by `build.rs` from
//! `base.key`, the base program's key, so this program's identity binds them.
//! Its advice is the header and the stream `host::recursion::leaf` laid out,
//! read in the procedure's order, and nothing in it is trusted: what it
//! claims the procedure checks, or a later node does.
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
use guest_sdk::recursion::{field_io, import, replay, Words};
use guest_sdk::{advice, commit, entry, exit};
use verifier_core::node::{leaf, Advice, BaseKey, Driver, Header, ImageTemplate, LeafImage};
use verifier_core::tape::{encode, Cell, Op};

entry!(main);

/// The image or the advice does not read.
const EXIT_INPUT: i32 = 10;

static IMAGE: &Words<[u8]> = &Words(*include_bytes!(concat!(env!("OUT_DIR"), "/leaf.img")));
static KEY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/base.key"));

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
}

impl Driver for Guest {
    fn replay(&mut self, body: &[u32]) {
        replay(body);
    }

    fn run(&mut self, ops: Vec<Op>) {
        replay(&encode(&ops).body);
    }

    fn advise(&mut self, cells: &[Cell], _: Advice) {
        let blob = self.take(32 * cells.len());
        import(cells, blob);
    }

    fn template(&mut self, template: &ImageTemplate, _: Option<Cell>) {
        if let Some(cells) = template.witnesses() {
            let cells: Vec<Cell> = cells.collect();
            let blob = self.take(32 * cells.len());
            import(&cells, blob);
        }
        replay(template.body.body);
    }

    fn infinity(&mut self, _: Cell) -> bool {
        self.word() != 0
    }

    fn export(&mut self, cells: &[Cell]) {
        for cell in cells {
            let mut words = [0u32; 8];
            field_io(&mut [io::EXPORT, *cell, words.as_mut_ptr() as u32]);
            for w in words {
                self.journal.extend_from_slice(&w.to_le_bytes());
            }
        }
    }
}

fn main() {
    let image = LeafImage::read(IMAGE.words()).unwrap_or_else(|| exit(EXIT_INPUT));
    let key = BaseKey::from_bytes(KEY).unwrap_or_else(|| exit(EXIT_INPUT));
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
    leaf(&mut guest, &image, &key, &header);
    commit(&guest.journal);
}
