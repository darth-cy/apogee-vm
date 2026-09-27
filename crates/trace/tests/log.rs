//! The address spaces: the frozen tags, which addresses each space has, and
//! which of them chain — the gate `record`, `from_events`, `self_check` and
//! the archive reader all pass every event through.

use constants::{address_space, guest_memory};
use trace::AddressSpace;

#[test]
fn the_tags_are_the_frozen_constants() {
    for (space, tag) in [
        (AddressSpace::Reg, address_space::REG),
        (AddressSpace::Ram, address_space::RAM),
        (AddressSpace::Pc, address_space::PC),
        (AddressSpace::KeccakF, address_space::DELEGATION_KECCAK_F),
        (AddressSpace::Poseidon2, address_space::DELEGATION_POSEIDON2),
        (AddressSpace::FrArith, address_space::DELEGATION_FR_ARITH),
        (AddressSpace::ModMul, address_space::DELEGATION_MOD_MUL),
    ] {
        assert_eq!(space.tag(), tag);
        assert_eq!(AddressSpace::from_tag(tag), Some(space));
    }
    assert_eq!(
        (
            address_space::REG,
            address_space::RAM,
            address_space::PC,
            address_space::DELEGATION_KECCAK_F,
            address_space::DELEGATION_POSEIDON2,
            address_space::DELEGATION_FR_ARITH,
            address_space::DELEGATION_MOD_MUL,
        ),
        (1, 2, 3, 4, 5, 6, 7)
    );
    // Every tag is nonzero, so no real tuple is all zeros, and 8 is the tag the
    // next delegation family takes — it names no space yet
    // (`docs/spec/delegation.md` §3).
    for tag in [0u8, 8, 255] {
        assert_eq!(AddressSpace::from_tag(tag), None, "tag {tag}");
    }
    // The delegation set is the four tags and nothing else: one `deleg` frame
    // query serves them all, and `frame_query_takes` reads this array.
    assert_eq!(
        trace::DELEGATION_SPACES.map(|s| s.tag()),
        address_space::DELEGATION
    );
    assert!(trace::DELEGATION_SPACES.iter().all(|s| !s.chains()));
}

#[test]
fn each_space_has_exactly_its_addresses() {
    assert!(AddressSpace::Reg.holds(0) && AddressSpace::Reg.holds(31));
    assert!(!AddressSpace::Reg.holds(32));
    assert!(AddressSpace::Pc.holds(0));
    assert!(!AddressSpace::Pc.holds(4));

    let (origin, top) = (
        guest_memory::RAM_ORIGIN,
        guest_memory::RAM_ORIGIN + guest_memory::RAM_LENGTH,
    );
    // A delegation anchor's address is a request's frame base pointer, and
    // `docs/spec/delegation.md` §4 puts the whole frame inside ordinary RAM,
    // so a delegation space has exactly that. What says a tuple is a
    // delegation's is the tag, never the address.
    for space in [AddressSpace::Ram, AddressSpace::KeccakF] {
        assert!(space.holds(origin) && space.holds(top - 4), "{space:?}");
        for addr in [origin + 1, origin + 2, origin + 3, top - 1] {
            assert!(
                !space.holds(addr),
                "{space:?}: {addr:#x} is not a word address"
            );
        }
        for addr in [0, origin - 4] {
            assert!(
                !space.holds(addr),
                "{space:?}: {addr:#x} is below RAM and in no public window"
            );
        }
    }

    // **`Ram` is wider than ordinary RAM since S-IO** and a delegation space is
    // not: the two public windows sit below `RAM_ORIGIN` and the advice region
    // above RAM, and all three are `address_space::RAM` tuples
    // (`docs/spec/public-values.md` §2). A delegation frame may be in none of
    // them.
    for addr in [
        guest_memory::PUBLIC_INPUT_ORIGIN,
        guest_memory::PUBLIC_OUTPUT_ORIGIN,
        guest_memory::ADVICE_ORIGIN,
        0xffff_fffc,
    ] {
        assert!(AddressSpace::Ram.holds(addr), "Ram: {addr:#x}");
        assert!(!AddressSpace::KeccakF.holds(addr), "KeccakF: {addr:#x}");
    }
    // And the hole stays a hole, at both ends of it.
    for addr in [
        0,
        guest_memory::PUBLIC_INPUT_ORIGIN - 4,
        guest_memory::PUBLIC_OUTPUT_ORIGIN + guest_memory::PUBLIC_WINDOW_BYTES,
        origin - 4,
    ] {
        assert!(!AddressSpace::Ram.holds(addr), "Ram: {addr:#x} is the hole");
    }
}

/// `docs/spec/delegation.md` §5.4: the three memory spaces chain — a query's
/// read is the last write at its address — and a delegation space does not.
/// Every query there reads the invocation's answer tuple, stamped 0, whatever
/// stands at that frame base already, which is what pairs two requests at one
/// base with two invocations rather than with each other. `record` fills a
/// non-chaining query's read side with `(0, 0)` instead of the last write, and
/// `self_check` credits each request its own pair, so a delegation space
/// balances by itself.
#[test]
fn only_the_memory_spaces_chain() {
    for space in [AddressSpace::Reg, AddressSpace::Ram, AddressSpace::Pc] {
        assert!(space.chains(), "{space:?}");
    }
    assert!(!AddressSpace::KeccakF.chains());
}
