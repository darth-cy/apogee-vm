//! `constants::memory`'s and `constants::lookup_channel`'s numbers against the
//! constants they are defined beside, because each is a claim about another
//! constant.
//!
//! An integration test rather than a unit test: `crates/constants` is
//! `#![no_std]` and holds no tests, and a test target is a separate crate that
//! changes neither.

use std::fs;
use std::path::Path;

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

/// `crates/guest-sdk/link.ld` is what the linker reads and
/// `constants::guest_memory` is what `crates/loader` enforces, and a linker
/// script cannot name a constant.
#[test]
fn the_linker_script_is_the_memory_map() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest-sdk/link.ld");
    let script = fs::read_to_string(&path).expect("crates/guest-sdk/link.ld is readable");
    let memory_line = script
        .lines()
        .find(|l| l.trim_start().starts_with("MEMORY"))
        .expect("link.ld declares a MEMORY region")
        .trim();

    let value = |key: &str| -> u32 {
        let at = memory_line
            .find(key)
            .unwrap_or_else(|| panic!("link.ld's MEMORY line has no {key}"));
        let rest = memory_line[at + key.len()..]
            .trim_start()
            .strip_prefix('=')
            .expect("an ld assignment")
            .trim_start();
        let digits: String = rest
            .strip_prefix("0x")
            .expect("link.ld writes the map in hex")
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        u32::from_str_radix(&digits, 16).expect("a hex literal")
    };

    assert_eq!(value("ORIGIN"), guest_memory::RAM_ORIGIN, "ORIGIN");
    assert_eq!(value("LENGTH"), guest_memory::RAM_LENGTH, "LENGTH");

    // The map has to leave room for a program and a stack, and its top has to
    // stay inside the 32-bit address space -- `__stack_top` is ORIGIN + LENGTH.
    const {
        assert!(
            guest_memory::RAM_ORIGIN > 0,
            "address 0 stays unmapped so a null pointer traps"
        );
        assert!(
            (guest_memory::RAM_ORIGIN as u64) + (guest_memory::RAM_LENGTH as u64)
                <= u32::MAX as u64 + 1,
            "the RAM window must fit in the 32-bit address space"
        );
        assert!(
            guest_memory::STACK_RESERVE > 0
                && guest_memory::STACK_RESERVE < guest_memory::RAM_LENGTH / 2,
            "the stack's reserve must leave the heap most of RAM"
        );
        assert!(
            guest_memory::STACK_RESERVE.is_multiple_of(4096),
            "the stack's reserve is whole pages"
        );
        // At least a native main thread's stack on Linux and macOS, 8 MiB, so
        // a program whose call depth fits on the host fits here. A smaller
        // reserve lets that program's stack run into heap blocks, and nothing
        // detects it.
        assert!(
            guest_memory::STACK_RESERVE >= 8 << 20,
            "the stack's reserve is at least a native main thread's 8 MiB"
        );
    }
}
