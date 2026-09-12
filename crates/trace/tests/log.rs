//! The address spaces: the frozen tags, and which addresses each space has —
//! the gate `record`, `from_events`, `self_check` and the archive reader all
//! pass every event through.

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
        (address_space::REG, address_space::RAM, address_space::PC),
        (1, 2, 3)
    );
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
    assert!(AddressSpace::Ram.holds(origin) && AddressSpace::Ram.holds(top - 4));
    for addr in [origin + 1, origin + 2, origin + 3, top - 1] {
        assert!(
            !AddressSpace::Ram.holds(addr),
            "{addr:#x} is not a word address"
        );
    }
    for addr in [0, origin - 4, top, 0xffff_fffc] {
        assert!(
            !AddressSpace::Ram.holds(addr),
            "{addr:#x} is outside the RAM window"
        );
    }
}
