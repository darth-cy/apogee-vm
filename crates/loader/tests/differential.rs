//! The loader against two independent oracles.
//!
//! **Boundaries** come from `llvm-objdump`: for `guests/fib` and the RVC-dense
//! fixture, the loader's instruction set must be the disassembler's, address
//! for address and encoding for encoding. That is what catches a sweep that
//! has lost synchronisation — the failure mode that turns a valid proof into a
//! proof of a different program.
//!
//! **Expansions** come from LLVM's own 32-bit encoder. `guests/rvc-dense`
//! holds the same instruction sequence twice, once compressed and once not, so
//! the test can expand the first region and compare it to the second. Neither
//! side of that comparison is a second reading of the RVC table by the author
//! of the first.

mod common;

use std::collections::BTreeSet;

use loader::{load_elf, Slot};

/// Acceptance 4: the loader's listing is the disassembler's, at every address.
#[test]
fn objdump_agrees_instruction_for_instruction() {
    for name in ["fib", "rvc-dense", "amm"] {
        let image = load_elf(&common::bytes(&format!("{name}.elf")))
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        let listing = common::objdump(name);
        assert!(
            listing.len() > 16,
            "{name}: the committed listing has only {} instructions",
            listing.len()
        );

        let mut listed = BTreeSet::new();
        for (pc, encoding, width) in &listing {
            // objdump spells the all-zero halfword `c.unimp` and lists it as an
            // instruction. The image records it as not code, because it is
            // RVC's defined-illegal encoding and abbreviates nothing -- see
            // `crates/loader/src/lib.rs`'s sweep. The two still agree about
            // where it is and how wide it is, which is what this differential
            // is for, so the carve-out is exactly one encoding wide.
            if *encoding == 0 && *width == 2 {
                assert_eq!(
                    image.slot_at(*pc),
                    Some(Slot::NonInstruction),
                    "{name}: the c.unimp at {pc:#010x} is not recorded as not code"
                );
                listed.insert(*pc);
                continue;
            }
            match image.slot_at(*pc) {
                Some(Slot::Instruction { compressed, .. }) => {
                    assert_eq!(
                        *width,
                        if compressed { 2 } else { 4 },
                        "{name}: objdump and the loader disagree about the length \
                         of the instruction at {pc:#010x}"
                    );
                    assert_eq!(
                        common::original_encoding(&image, *pc, *width),
                        *encoding,
                        "{name}: the bytes at {pc:#010x} are not what objdump disassembled"
                    );
                }
                other => panic!(
                    "{name}: objdump found an instruction at {pc:#010x}, \
                     the image has {other:?}"
                ),
            }
            listed.insert(*pc);
        }

        // The converse, which is the half that catches a sweep running long:
        // an instruction the loader believes in and the disassembler never saw.
        for (i, slot) in image.slots.iter().enumerate() {
            let pc = image.slot_base + 2 * i as u32;
            if matches!(slot, Slot::Instruction { .. }) {
                assert!(
                    listed.contains(&pc),
                    "{name}: the image has an instruction at {pc:#010x} \
                     that objdump did not list"
                );
            }
        }
    }
}

/// The expansion oracle: every compressed form against LLVM's 32-bit encoding
/// of the instruction it abbreviates.
#[test]
fn every_compressed_form_expands_to_its_uncompressed_twin() {
    let (rvc, norvc) = paired_regions();

    assert_eq!(
        rvc.len(),
        norvc.len(),
        "the two regions must hold the same instruction sequence"
    );
    assert!(
        rvc.len() >= 40,
        "the fixture covers only {} forms, which is not the RV32C table",
        rvc.len()
    );
    assert!(
        rvc.iter().all(|(_, _, compressed)| *compressed),
        "every instruction in the rvc region must be 16-bit: one that the \
         assembler declined to compress would silently weaken this test"
    );
    assert!(
        norvc.iter().all(|(_, _, compressed)| !*compressed),
        "every instruction in the norvc region must be 32-bit"
    );

    for (i, ((pc, ours, _), (twin_pc, theirs, _))) in rvc.iter().zip(&norvc).enumerate() {
        assert_eq!(
            ours, theirs,
            "pair {i}: the compressed instruction at {pc:#010x} expands to \
             {ours:#010x}, but LLVM encodes the same instruction at \
             {twin_pc:#010x} as {theirs:#010x}"
        );
    }
}

/// Must-be-exact 5, stated directly: a compressed instruction occupies two
/// bytes after expansion, exactly as it did before.
#[test]
fn addresses_are_never_compacted() {
    let nm = common::nm("rvc-dense");
    let (rvc, norvc) = paired_regions();

    assert_eq!(
        nm["__rvcpair_end"] - nm["__rvcpair_begin"],
        2 * rvc.len() as u32,
        "the compressed region must still be two bytes per instruction"
    );
    assert_eq!(
        nm["__norvcpair_end"] - nm["__norvcpair_begin"],
        4 * norvc.len() as u32
    );

    // And the addresses themselves: consecutive, two apart, no gaps.
    for pair in rvc.windows(2) {
        assert_eq!(
            pair[1].0 - pair[0].0,
            2,
            "compressed instructions at {:#010x} and {:#010x} are not adjacent",
            pair[0].0,
            pair[1].0
        );
    }
}

/// Acceptance 5: every symbol `nm` reports is the address of an instruction.
#[test]
fn every_symbol_address_is_an_instruction() {
    let image = load_elf(&common::bytes("rvc-dense.elf")).expect("the fixture loads");
    let nm = common::nm("rvc-dense");
    assert!(
        nm.len() > 4,
        "the committed nm listing is suspiciously short"
    );

    for (symbol, addr) in &nm {
        match image.slot_at(*addr) {
            Some(Slot::Instruction { .. }) => {}
            other => panic!(
                "symbol {symbol} is at {addr:#010x}, where the image has {other:?}; \
                 an address moved"
            ),
        }
    }
}

/// Acceptance 4's required corpus, asserted on the *expanded* words rather than
/// on a second decoder: a compressed slot whose expansion is `lw rd, imm(x2)`
/// was a `c.lwsp`, and so on down the list.
#[test]
fn the_fixture_covers_the_required_compressed_forms() {
    let (rvc, _) = paired_regions();

    let mut seen: BTreeSet<&'static str> = BTreeSet::new();
    for (_, word, _) in &rvc {
        let opcode = word & 0x7f;
        let funct3 = (word >> 12) & 0b111;
        let rd = (word >> 7) & 0b1_1111;
        let rs1 = (word >> 15) & 0b1_1111;
        let rs2 = (word >> 20) & 0b1_1111;
        let name = match (opcode, funct3) {
            (0x03, 0b010) if rs1 == 2 => "c.lwsp",
            (0x03, 0b010) => "c.lw",
            (0x23, 0b010) if rs1 == 2 => "c.swsp",
            (0x23, 0b010) => "c.sw",
            (0x6f, _) if rd == 1 => "c.jal",
            (0x6f, _) => "c.j",
            (0x63, 0b000) if rs2 == 0 => "c.beqz",
            (0x63, 0b001) if rs2 == 0 => "c.bnez",
            _ => continue,
        };
        seen.insert(name);
    }

    for required in [
        "c.lw", "c.sw", "c.lwsp", "c.swsp", "c.jal", "c.j", "c.beqz", "c.bnez",
    ] {
        assert!(
            seen.contains(required),
            "the RVC-dense fixture no longer covers {required}"
        );
    }
}

/// The negative control for the differential itself: a listing that disagrees
/// with the image must fail, or the two tests above prove nothing.
#[test]
fn a_shifted_listing_is_rejected() {
    let image = load_elf(&common::bytes("rvc-dense.elf")).expect("the fixture loads");
    let listing = common::objdump("rvc-dense");

    // Move one instruction one halfword along, which is precisely what a
    // desynchronised sweep looks like.
    let (pc, encoding, width) = listing[8];
    let agrees = matches!(
        image.slot_at(pc + 2),
        Some(Slot::Instruction { compressed, .. }) if (if compressed { 2 } else { 4 }) == width
    ) && common::original_encoding(&image, pc + 2, width) == encoding;
    assert!(
        !agrees,
        "the image agreed with a listing shifted by one halfword, so the \
         differential cannot distinguish a synchronised sweep from a broken one"
    );
}

/// Both paired regions, read out of the committed image.
fn paired_regions() -> (Vec<common::Expanded>, Vec<common::Expanded>) {
    let image = load_elf(&common::bytes("rvc-dense.elf")).expect("the fixture loads");
    let nm = common::nm("rvc-dense");
    let region = |begin: &str, end: &str| {
        common::instructions_in(
            &image,
            *nm.get(begin)
                .unwrap_or_else(|| panic!("{begin} is not in the nm listing")),
            *nm.get(end)
                .unwrap_or_else(|| panic!("{end} is not in the nm listing")),
        )
    };
    (
        region("__rvcpair_begin", "__rvcpair_end"),
        region("__norvcpair_begin", "__norvcpair_end"),
    )
}

/// Master rule 11: the committed fixtures are what they were when the digests
/// were written down.
#[test]
fn committed_fixtures_match_their_pins() {
    for (name, want) in common::PINS {
        assert_eq!(
            common::digest(name),
            want,
            "{name} has changed. If that was deliberate, rerun the generator and \
             update the digest in tests/common/mod.rs."
        );
    }
    assert_eq!(
        common::digest("synthetic_elfs.txt"),
        "4b637a7fc691b033a952ef1d2ecb28e4d18f6da8c3136c2fe224ddedca168436",
        "the synthetic ELF index has changed"
    );
    assert_eq!(
        common::digest("fib_io.txt"),
        "7a8ba676b87ec976f4206cc58874c7a439bb903502f4ab7ea228df72e3e4dca2",
        "the fib public-I/O record has changed"
    );
}
