#![no_std]
#![no_main]
//! The recursion leaf (`docs/spec/recursion.md` §8): `recursion::run` over
//! its image, which `build.rs` writes and this binary holds in `.rodata`.

use guest_sdk::entry;
use guest_sdk::recursion::Words;

entry!(main);

static IMAGE: &Words<[u8]> = &Words(*include_bytes!(concat!(env!("OUT_DIR"), "/leaf.img")));

fn main() {
    recursion::run(IMAGE.words());
}
