//! Every way the loader refuses, exercised against a committed fixture.
//!
//! Master rule 8 wants a negative control for every checker. A loader is
//! nothing but checkers, so this file is the list: one fixture per refusal,
//! each one a named deviation from `minimal.elf`, which loads.
//!
//! The fixtures are hand-built rather than compiled, because no RV32 toolchain
//! will emit most of them — `tools/kat-gen/src/loader.rs` writes them and
//! `synthetic_elfs.txt` says what each one is.

mod common;

use loader::{load_elf, LoaderError};

/// The positive control. If this stops loading, every refusal below is
/// evidence about the fixture builder rather than about the loader.
#[test]
fn the_minimal_elf_loads() {
    let image = load_elf(&common::synthetic("minimal.elf")).expect("minimal.elf loads");
    assert_eq!(image.entry, 0x0001_0000);
    assert_eq!(image.segments.len(), 1);
    assert_eq!(image.slots.len(), 2, "two halfwords, two slots");
}

/// Acceptance 6(a): the all-zero halfword, and the reserved `c.addi4spn`.
#[test]
fn illegal_compressed_encodings_are_refused_with_the_pc() {
    let cases: [(&str, u16); 2] = [
        ("zero_halfword.elf", 0x0000),
        ("reserved_addi4spn.elf", 0x0008),
    ];
    for (fixture, want_encoding) in cases {
        match load_elf(&common::synthetic(fixture)) {
            Err(LoaderError::RvcIllegal {
                pc,
                encoding,
                reason,
            }) => {
                assert_eq!(pc, 0x0001_0002, "{fixture}: the wrong pc was named");
                assert_eq!(encoding, want_encoding, "{fixture}");
                assert!(!reason.is_empty(), "{fixture}: no reason given");
            }
            other => panic!("{fixture}: expected RvcIllegal, got {other:?}"),
        }
    }
}

/// Acceptance 6(b): a `Zcmp`-shaped halfword, refused with the pc named.
#[test]
fn a_zcmp_encoding_is_refused_with_the_pc() {
    match load_elf(&common::synthetic("zcmp.elf")) {
        Err(LoaderError::RvcIllegal {
            pc,
            encoding,
            reason,
        }) => {
            assert_eq!(pc, 0x0001_0002);
            assert_eq!(encoding, 0xb872);
            assert!(
                reason.contains("Zcmp"),
                "the reason should say what the encoding space is: {reason}"
            );
        }
        other => panic!("expected RvcIllegal, got {other:?}"),
    }
}

/// Acceptance 6(c), and the rest of must-be-exact 8: dynamic, relocatable and
/// non-RV32 files, each with its own name.
#[test]
fn dynamic_relocatable_and_non_rv32_files_are_refused() {
    assert!(
        matches!(
            load_elf(&common::synthetic("et_dyn.elf")),
            Err(LoaderError::DynamicElf { .. })
        ),
        "an ET_DYN file must be refused as dynamic"
    );
    assert!(
        matches!(
            load_elf(&common::synthetic("pt_dynamic.elf")),
            Err(LoaderError::DynamicElf { .. })
        ),
        "a PT_DYNAMIC segment must be refused as dynamic"
    );
    assert!(
        matches!(
            load_elf(&common::synthetic("et_rel.elf")),
            Err(LoaderError::RelocatableElf)
        ),
        "an ET_REL file must be refused as relocatable"
    );
    assert_eq!(
        load_elf(&common::synthetic("not_riscv.elf")),
        Err(LoaderError::NotRiscV { machine: 40 })
    );
    assert!(
        matches!(
            load_elf(&common::synthetic("elf64.elf")),
            Err(LoaderError::NotAnElf { .. })
        ),
        "an ELFCLASS64 file is not a 32-bit ELF"
    );

    // The two dynamic refusals must not be the same code path saying the same
    // thing: one is the header, one is a program header.
    let a = load_elf(&common::synthetic("et_dyn.elf"));
    let b = load_elf(&common::synthetic("pt_dynamic.elf"));
    assert_ne!(a, b, "both dynamic refusals gave the identical reason");
}

/// The rest of the enum, so no variant is unreachable in practice.
#[test]
fn the_remaining_refusals_each_have_a_fixture() {
    assert_eq!(
        load_elf(&common::synthetic("instruction_too_long.elf")),
        Err(LoaderError::InstructionTooLong {
            pc: 0x0001_0000,
            encoding: 0x001f
        }),
        "bits 4:2 all ones is a 48-bit encoding, which RV32IMAC has none of"
    );
    assert_eq!(
        load_elf(&common::synthetic("text_truncated.elf")),
        Err(LoaderError::TextTruncated { pc: 0x0001_0002 })
    );
    assert_eq!(
        load_elf(&common::synthetic("no_executable_segment.elf")),
        Err(LoaderError::NoExecutableSegment)
    );
    assert!(
        matches!(
            load_elf(&common::synthetic("overlapping_segments.elf")),
            Err(LoaderError::BadSegment {
                vaddr: 0x0001_0002,
                ..
            })
        ),
        "overlapping segments must name the upper one"
    );
    assert_eq!(
        load_elf(&common::synthetic("entry_mid_instruction.elf")),
        Err(LoaderError::EntryNotAnInstruction { entry: 0x0001_0002 }),
        "an entry pointing into the middle of an instruction is a preprocessing \
         failure, not something to find at cycle 0"
    );
}

/// Truncation, at each of the three places a length is declared.
///
/// Built by cutting the committed `minimal.elf` rather than by adding three
/// more fixtures: what is being tested is arithmetic on lengths, and the input
/// is exactly "the good file, shorter".
#[test]
fn truncated_files_are_refused_rather_than_read_past() {
    let good = common::synthetic("minimal.elf");
    for cut in [0, 1, 51, 52, 60, 83] {
        assert!(
            load_elf(&good[..cut]).is_err(),
            "a {cut}-byte prefix of minimal.elf was accepted"
        );
    }
    assert!(
        load_elf(&good).is_ok(),
        "the whole file must still load, or the loop above proves nothing"
    );
}

/// Every byte of the header, flipped: the loader either refuses or produces an
/// image, and never panics.
///
/// A malformed ELF is untrusted input. This is the cheap sweep that says so.
#[test]
fn a_corrupted_header_never_panics() {
    let good = common::synthetic("minimal.elf");
    for i in 0..good.len() {
        for bit in 0..8 {
            let mut bad = good.clone();
            bad[i] ^= 1 << bit;
            // The result is not asserted: some flips produce a different but
            // perfectly loadable program. What matters is that none of them
            // reaches an index out of bounds or an arithmetic overflow.
            let _ = load_elf(&bad);
        }
    }
}
