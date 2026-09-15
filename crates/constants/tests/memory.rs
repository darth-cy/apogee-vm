//! `constants::memory`'s and `constants::lookup_channel`'s S14 numbers against
//! the constants they are defined beside, because each is a claim about another
//! constant.
//!
//! An integration test rather than a unit test, for the reason
//! `tests/ecall_abi.rs` gives: `crates/constants` holds no code.

use constants::{guest_memory, lookup_channel, memory};

/// `docs/spec/memory.md` §3.1: window 0's rows below `2^RAM_LIVE_BIT` are
/// exactly the words below `RAM_ORIGIN`.
#[test]
fn ram_origin_is_where_ram_live_begins() {
    assert_eq!(guest_memory::RAM_ORIGIN, 4 << memory::RAM_LIVE_BIT);
}

/// `docs/spec/memory.md` §2.4: the timestamp gap's two chunks on the
/// timestamp channel cover the clock exactly.
#[test]
fn two_timestamp_chunks_are_the_clock() {
    assert_eq!(
        2 * lookup_channel::BITS[lookup_channel::TIMESTAMP as usize],
        memory::TS_BITS
    );
}

/// `docs/spec/memory.md` §7's range convention: a 32-bit value is two halfwords
/// on the `range16` channel; and every channel has a bound and a name.
#[test]
fn two_halfwords_are_a_word() {
    assert_eq!(
        2 * lookup_channel::BITS[lookup_channel::RANGE16 as usize],
        32
    );
    assert_eq!(lookup_channel::BITS.len(), lookup_channel::NAMES.len());
}

/// `docs/spec/memory.md` §5: the halting sentinel is odd, so no instruction's
/// `next_pc` is it, and below `RAM_ORIGIN`, so no decoded-table row claims it.
#[test]
fn the_halting_sentinel_is_odd_and_below_ram() {
    assert_eq!(memory::HALT_PC % 2, 1);
    const { assert!(memory::HALT_PC < guest_memory::RAM_ORIGIN) }
}
