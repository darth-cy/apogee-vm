//! `ProgramImage`: the structural invariants, and the frozen serialization.

mod common;

use loader::{load_elf, LoaderError, ProgramImage, Slot};

/// Every committed guest, which is every compiled ELF the loader is held to.
///
/// One list rather than three copies, because a guest added to `guests/` and
/// wired into the fixtures should reach every structural check here without a
/// second edit -- the checks below are about the shape of an image, and there
/// is no image they are meant to skip.
const GUESTS: [&str; 6] = [
    "fib.elf",
    "echo.elf",
    "rvc-dense.elf",
    "amm.elf",
    "orderbook.elf",
    "vault.elf",
];

/// Acceptance 7: loading the same ELF twice yields byte-identical images.
#[test]
fn loading_twice_serializes_identically() {
    for name in GUESTS {
        let bytes = common::bytes(name);
        let a = load_elf(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let b = load_elf(&bytes).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(a, b, "{name}: two loads produced different images");
        assert_eq!(
            common::to_postcard(&a),
            common::to_postcard(&b),
            "{name}: two loads serialized differently"
        );
    }
}

/// The frozen wire form reads back to the value it was written from.
#[test]
fn the_image_round_trips_through_postcard() {
    for name in ["minimal.elf"].into_iter().chain(GUESTS) {
        let image = load_elf(&common::bytes(name)).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let wire = common::to_postcard(&image);
        let back: ProgramImage = postcard::from_bytes(&wire).expect("the wire form parses");
        assert_eq!(back, image, "{name}");
        assert_eq!(
            common::to_postcard(&back),
            wire,
            "{name}: re-serialization moved"
        );
    }
}

/// The negative control for the deserializer's validation: forms `serialize`
/// could not have produced are refused rather than accepted quietly.
///
/// The wire forms are built here from primitives rather than by patching a
/// serialized image, so each one is exactly the malformation it is named
/// after. The first case is a **positive** control on that construction: if the
/// hand-built layout were wrong, the three refusals below would all be
/// evidence about this test rather than about the deserializer.
#[test]
fn malformed_wire_forms_are_rejected() {
    // `minimal.elf`: one R|X segment of `c.nop; c.jr ra`, and the two slots
    // those expand to.
    const TEXT: &[u8] = &[0x01, 0x00, 0x82, 0x80];
    const NOP: u32 = 0x0000_0013;
    const RET: u32 = 0x0000_8067;
    // The wire form, spelled in primitives: entry, segments, slot_base, slots.
    type WireSegment<'a> = (u32, u32, &'a [u8]);
    type WireSlot = (u8, u32);
    type WireImage<'a> = (u32, &'a [WireSegment<'a>], u32, &'a [WireSlot]);
    let wire = |slot_base: u32, slots: &[WireSlot]| -> Vec<u8> {
        let image: WireImage = (0x0001_0000, &[(0x0001_0000, 4, TEXT)], slot_base, slots);
        let mut buf = [0u8; 256];
        postcard::to_slice(&image, &mut buf)
            .expect("the buffer is far larger than this image")
            .to_vec()
    };

    let good = wire(0x0001_0000, &[(1, NOP), (1, RET)]);
    assert_eq!(
        postcard::from_bytes::<ProgramImage>(&good).expect("the hand-built form parses"),
        load_elf(&common::synthetic("minimal.elf")).expect("minimal.elf loads"),
        "the hand-built wire form must be the one the loader produces, or the \
         refusals below prove nothing"
    );

    for (what, bytes) in [
        (
            "an unknown slot kind",
            wire(0x0001_0000, &[(9, NOP), (1, RET)]),
        ),
        (
            "a word on a mid-instruction slot",
            wire(0x0001_0000, &[(0, NOP), (2, 7)]),
        ),
        ("an odd slot_base", wire(0x0001_0001, &[(1, NOP), (1, RET)])),
    ] {
        assert!(
            postcard::from_bytes::<ProgramImage>(&bytes).is_err(),
            "{what} was accepted"
        );
    }

    // The segment list has invariants of its own, and a hand-built wire form is
    // the only way to state one it could not have.
    let multi = |segments: &[(u32, u32, &[u8])]| -> Vec<u8> {
        let image: WireImage = (0x0001_0000, segments, 0x0001_0000, &[(1, NOP), (1, RET)]);
        let mut buf = [0u8; 256];
        postcard::to_slice(&image, &mut buf)
            .expect("the buffer is far larger than this image")
            .to_vec()
    };
    for (what, bytes) in [
        (
            "unsorted segments",
            multi(&[(0x0002_0000, 4, TEXT), (0x0001_0000, 4, TEXT)]),
        ),
        (
            "overlapping segments",
            multi(&[(0x0001_0000, 8, TEXT), (0x0001_0004, 4, TEXT)]),
        ),
        (
            "a segment whose end wraps past 2^32",
            multi(&[(0x0001_0000, 4, TEXT), (0xffff_fff0, 0xffff_ffff, &[])]),
        ),
        (
            "a segment below the guest RAM window",
            multi(&[(0x0000_0000, 4, TEXT)]),
        ),
    ] {
        assert!(
            postcard::from_bytes::<ProgramImage>(&bytes).is_err(),
            "{what} was accepted"
        );
    }

    // And truncation, at every length: no panic, no partial value.
    for cut in 0..good.len() {
        let _ = postcard::from_bytes::<ProgramImage>(&good[..cut]);
    }
}

/// The slot vector says what it claims to say.
#[test]
fn the_slot_vector_is_structurally_sound() {
    for name in GUESTS {
        let image = load_elf(&common::bytes(name)).unwrap_or_else(|e| panic!("{name}: {e:?}"));

        assert_eq!(image.slot_base % 2, 0, "{name}: slot_base must be even");
        assert_eq!(
            image.slot_base, image.segments[0].vaddr,
            "{name}: the slot vector must start at the lowest loaded address"
        );
        // The vector stops at the top of the highest executable segment: the
        // last instruction has to fit inside it, it may not run past the image,
        // and its end has to *be* a segment's end rather than an arbitrary
        // address.
        let top = image.slot_base as u64 + 2 * image.slots.len() as u64;
        let last = image
            .slots
            .iter()
            .rposition(|s| matches!(s, Slot::Instruction { .. }))
            .expect("a loaded image has at least one instruction");
        let width = match image.slots[last] {
            Slot::Instruction {
                compressed: true, ..
            } => 2,
            _ => 4,
        };
        assert!(
            top >= image.slot_base as u64 + 2 * last as u64 + width,
            "{name}: the last instruction runs off the end of the slot vector"
        );
        let segment_ends: Vec<u64> = image
            .segments
            .iter()
            .map(|s| (s.vaddr as u64 + s.mem_len as u64 + 1) & !1)
            .collect();
        assert!(
            top <= *segment_ends
                .iter()
                .max()
                .expect("a loaded image has segments"),
            "{name}: the slot vector runs past the image"
        );
        assert!(
            segment_ends.contains(&top),
            "{name}: the slot vector ends at {top:#x}, which is not a segment's end"
        );

        // A mid-instruction slot follows a 32-bit instruction and nothing else,
        // and a 32-bit instruction is followed by one.
        for (i, slot) in image.slots.iter().enumerate() {
            match slot {
                Slot::Instruction {
                    compressed: false, ..
                } => assert_eq!(
                    image.slots.get(i + 1),
                    Some(&Slot::MidInstruction),
                    "{name}: the 32-bit instruction at {:#010x} has no second halfword",
                    image.slot_base + 2 * i as u32
                ),
                Slot::MidInstruction => {
                    assert!(
                        i > 0
                            && matches!(
                                image.slots[i - 1],
                                Slot::Instruction {
                                    compressed: false,
                                    ..
                                }
                            ),
                        "{name}: the mid-instruction slot at {:#010x} follows nothing",
                        image.slot_base + 2 * i as u32
                    );
                }
                _ => {}
            }
        }

        // The entry is an instruction, which `load_elf` promises.
        assert!(matches!(
            image.slot_at(image.entry),
            Some(Slot::Instruction { .. })
        ));

        // Segments are sorted and disjoint.
        for pair in image.segments.windows(2) {
            assert!(
                pair[0].vaddr as u64 + pair[0].mem_len as u64 <= pair[1].vaddr as u64,
                "{name}: segments overlap or are unsorted"
            );
            assert!(
                pair[0].bytes.len() as u64 <= pair[0].mem_len as u64,
                "{name}: a segment has more file bytes than memory"
            );
        }
    }
}

/// The frozen memory map is enforced: a segment outside the guest RAM window is
/// not something this VM can run, and refusing it is also what bounds the slot
/// vector a hostile `p_memsz` can ask for.
#[test]
fn segments_must_lie_inside_the_guest_ram_window() {
    let good = common::synthetic("minimal.elf");
    assert!(load_elf(&good).is_ok());

    // p_memsz is the sixth word of the one program header, which starts at 52.
    let memsz_at = 52 + 20;
    for memsz in [0x7fff_ffffu32, 0xffff_ffff, 0x1000_0000] {
        let mut bad = good.clone();
        bad[memsz_at..memsz_at + 4].copy_from_slice(&memsz.to_le_bytes());
        assert!(
            matches!(load_elf(&bad), Err(LoaderError::BadSegment { .. })),
            "a segment claiming {memsz:#x} bytes of memory was accepted, so the \
             slot vector is sized by an attacker"
        );
    }

    // And a segment below the window.
    let mut bad = good.clone();
    bad[52 + 8..52 + 12].copy_from_slice(&0u32.to_le_bytes());
    bad[52 + 12..52 + 16].copy_from_slice(&0u32.to_le_bytes());
    assert!(matches!(
        load_elf(&bad),
        Err(LoaderError::BadSegment { .. })
    ));
}

/// `slot_at` refuses the addresses that are not halfword slots.
#[test]
fn slot_at_refuses_odd_and_outside() {
    let image = load_elf(&common::bytes("minimal.elf")).expect("minimal.elf loads");
    assert!(image.slot_at(image.slot_base + 1).is_none(), "odd address");
    assert!(
        image.slot_at(image.slot_base - 2).is_none(),
        "below the image"
    );
    assert!(
        image
            .slot_at(image.slot_base + 2 * image.slots.len() as u32)
            .is_none(),
        "one past the image"
    );
}

/// A load is a pure function of the bytes: no path, no clock, no environment.
#[test]
fn the_image_does_not_depend_on_where_the_bytes_came_from() {
    let from_file = common::bytes("minimal.elf");
    let mut padded = from_file.clone();
    padded.extend_from_slice(&[0xaa; 64]); // trailing junk the headers do not claim
    assert_eq!(
        load_elf(&from_file),
        load_elf(&padded),
        "bytes past the last declared structure changed the image"
    );
    assert!(matches!(load_elf(&[]), Err(LoaderError::Truncated { .. })));
}

// ---------------------------------------------------------------------------
// The all-zero halfword
// ---------------------------------------------------------------------------

/// RVC's defined-illegal encoding is not code, and is not a refusal.
///
/// The spec gives the all-zero halfword that status so that a jump into zeroed
/// memory traps. Trapping is a run-time event: a loader cannot know whether any
/// pc reaches a given halfword, so the honest record is [`Slot::NonInstruction`]
/// and the trap belongs to the executor.
///
/// It is also not a corner case. rustc's RISC-V target sets `TrapUnreachable`,
/// so at `opt-level = 0` — which is the guest profile — every LLVM `unreachable`
/// block becomes a real `unimp`, and with the C extension that assembles to this
/// halfword. An exhaustive `match` on a three-variant enum emits one; so does
/// every `core::sync::atomic` operation, and so does `field::Fr::inverse`.
/// Refusing it meant refusing ordinary compiler output.
#[test]
fn the_all_zero_halfword_is_not_code() {
    let image = load_elf(&common::synthetic("zero_halfword.elf")).expect("it loads");
    assert_eq!(
        image.slot_at(0x0001_0000),
        Some(Slot::Instruction {
            word: 0x0000_0013,
            compressed: true
        }),
        "the c.nop before the padding"
    );
    assert_eq!(
        image.slot_at(0x0001_0002),
        Some(Slot::NonInstruction),
        "the all-zero halfword must be recorded as not code"
    );
}

/// The sweep resumes at `pc + 2`, so what follows the padding is still found.
///
/// This is the half that matters. Skipping the halfword is only correct if the
/// next instruction starts immediately after it — which is what LLVM emits,
/// two-byte padding between basic blocks. Swallowing four bytes instead, or
/// giving up on the rest of the segment, would silently drop real code.
/// `tests/differential.rs` holds the same claim over whole compiled guests,
/// against llvm-objdump.
///
/// **The lone halfword at index 4 is what gives this test teeth**, and a run of
/// two would not have. An unswept slot is already `NonInstruction`, so after a
/// *pair* of padding halfwords a sweep that advanced four bytes instead of two
/// lands back on an instruction boundary and leaves a slot vector identical to
/// the correct one — the assertion would hold while the bug it names was
/// present. After a single one it lands mid-stream, never reaches the `c.nop`
/// at index 5, and the last slot comes back `NonInstruction`.
#[test]
fn the_sweep_resynchronises_after_a_run_of_padding() {
    let image = load_elf(&common::synthetic("zero_halfword_run.elf")).expect("it loads");
    let kinds: Vec<Slot> = (0..6)
        .map(|i| {
            image
                .slot_at(0x0001_0000 + 2 * i)
                .expect("all six halfwords are in the image")
        })
        .collect();
    let nop = Slot::Instruction {
        word: 0x0000_0013,
        compressed: true,
    };
    let jr = Slot::Instruction {
        word: 0x0000_8067,
        compressed: true,
    };
    assert_eq!(
        kinds,
        vec![
            nop,
            Slot::NonInstruction,
            Slot::NonInstruction,
            jr,
            Slot::NonInstruction,
            nop,
        ],
        "c.nop, two halfwords of padding, c.jr ra, one more halfword, c.nop"
    );
}
