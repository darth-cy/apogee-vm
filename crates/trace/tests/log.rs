//! The address spaces: the tags and which addresses each space has — the gate
//! `record`, `from_events`, `self_check` and the archive reader all pass every
//! event through.

use constants::{address_space, guest_memory};
use trace::AddressSpace;

#[test]
fn the_tags_are_the_frozen_constants() {
    for (space, tag) in [
        (AddressSpace::Reg, address_space::REG),
        (AddressSpace::Ram, address_space::RAM),
        (AddressSpace::Pc, address_space::PC),
    ] {
        assert_eq!(space.tag(), tag);
        assert_eq!(AddressSpace::from_tag(tag), Some(space));
    }
    assert_eq!(
        [address_space::REG, address_space::RAM, address_space::PC],
        [1, 2, 3]
    );
    // Every tag is nonzero, so no real tuple is all zeros, and 4 is the tag
    // the next space takes.
    for tag in [0u8, 4, 255] {
        assert_eq!(AddressSpace::from_tag(tag), None, "tag {tag}");
    }
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
    let space = AddressSpace::Ram;
    assert!(space.holds(origin) && space.holds(top - 4));
    for addr in [origin + 1, origin + 2, origin + 3, top - 1] {
        assert!(!space.holds(addr), "{addr:#x} is not a word address");
    }
    assert!(!space.holds(0), "0 is below RAM and in no public window");

    // **`Ram` is wider than ordinary RAM**: the two public windows sit below
    // `RAM_ORIGIN` and the advice region above RAM, and all three are
    // `address_space::RAM` tuples (`docs/spec/public-values.md` §4).
    for addr in [
        guest_memory::PUBLIC_INPUT_ORIGIN,
        guest_memory::PUBLIC_OUTPUT_ORIGIN,
        origin - 4,
        guest_memory::ADVICE_ORIGIN,
        0xffff_fffc,
    ] {
        assert!(AddressSpace::Ram.holds(addr), "Ram: {addr:#x}");
    }
    // And the hole stays a hole. **The hole is only below the windows**: at
    // `2^12` the two of them fill `[0x8000, RAM_ORIGIN)` exactly, so there is
    // no gap above them and the geometry is asserted instead — that equality
    // is what makes `2^12` the ceiling, and it is the thing a constant change
    // would silently break.
    assert_eq!(
        guest_memory::PUBLIC_OUTPUT_ORIGIN + guest_memory::PUBLIC_WINDOW_BYTES,
        origin,
        "the two public windows end flush against RAM_ORIGIN"
    );
    for addr in [0, guest_memory::PUBLIC_INPUT_ORIGIN - 4] {
        assert!(!AddressSpace::Ram.holds(addr), "Ram: {addr:#x} is the hole");
    }
}
