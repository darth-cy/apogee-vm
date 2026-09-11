//! `artifact-dump tables`: acceptance 10.
//!
//! The page must render for any ELF the loader and the decoder accept — not
//! only the committed ones — and fail with the loader's or the decoder's named
//! error for any other. The listing is parsed back and held to the tables row
//! for row, so the printed page cannot describe something other than what is
//! committed.

use std::fs;
use std::path::PathBuf;

use artifact_dump::tables::render;
use loader::{load_elf, Slot};
use program::{decode_program, family_name, DecodedTables, ProgramParams, RowField};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn loader_vector(name: &str) -> Vec<u8> {
    let path = root().join("crates/loader/tests/vectors").join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// A static RV32 executable holding `words` at `0x10000`, built here rather
/// than taken from any fixture: the "arbitrary user-supplied ELF".
fn elf_of(words: &[u32]) -> Vec<u8> {
    let text: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    let mut out = vec![0x7f, b'E', b'L', b'F', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    for half in [2u16, 243] {
        out.extend_from_slice(&half.to_le_bytes()); // e_type ET_EXEC, e_machine RISC-V
    }
    for word in [1u32, 0x1_0000, 52, 0, 0] {
        out.extend_from_slice(&word.to_le_bytes()); // version, entry, phoff, shoff, flags
    }
    for half in [52u16, 32, 1, 40, 0, 0] {
        out.extend_from_slice(&half.to_le_bytes()); // ehsize, phentsize, phnum, ...
    }
    let len = text.len() as u32;
    for word in [1u32, 84, 0x1_0000, 0x1_0000, len, len, 5, 4] {
        out.extend_from_slice(&word.to_le_bytes()); // one PT_LOAD, R|X
    }
    out.extend_from_slice(&text);
    out
}

/// Parse every listing line back and compare it with the tables.
fn check_listing(page: &str, elf: &[u8], tables: &DecodedTables) {
    let image = load_elf(elf).unwrap();
    let instructions: Vec<(u32, u32)> = image
        .slots
        .iter()
        .enumerate()
        .filter_map(|(i, s)| match *s {
            Slot::Instruction { word, .. } => Some((image.slot_base + 2 * i as u32, word)),
            _ => None,
        })
        .collect();
    let rows: Vec<Vec<&str>> = page
        .lines()
        .filter(|l| l.starts_with("0x"))
        .map(|l| l.split_whitespace().collect())
        .collect();
    assert_eq!(rows.len(), instructions.len(), "one line per instruction");

    let hex = |s: &str| u32::from_str_radix(s.trim_start_matches("0x"), 16).unwrap();
    for (row, (pc, word)) in rows.iter().zip(&instructions) {
        assert_eq!(row.len(), 9, "{row:?}");
        assert_eq!(hex(row[0]), *pc);
        let table = tables
            .families
            .iter()
            .find(|t| family_name(t.family) == row[2])
            .unwrap_or_else(|| panic!("{} is not a family in the tables", row[2]));
        let r = (*pc / 2) as usize;
        assert!(table.is_live(r), "{pc:#010x} is not live in {}", row[2]);
        let field = |f: RowField| {
            table
                .columns
                .iter()
                .position(|(c, _)| *c == f)
                .map(|c| table.get(c, r).unwrap())
        };
        let shown = |s: &str, v: Option<u32>, radix16: bool| match v {
            None => assert_eq!(s, "-", "{pc:#010x}: a field not in the tuple"),
            Some(v) if radix16 => assert_eq!(hex(s), v, "{pc:#010x}"),
            Some(v) => assert_eq!(s.parse::<u32>().unwrap(), v, "{pc:#010x}"),
        };
        shown(row[1], field(RowField::NextPc), true);
        assert_eq!(row[3], isa::decode(*word).unwrap().mnemonic());
        shown(row[4], field(RowField::Rs1), false);
        shown(row[5], field(RowField::Rs2), false);
        shown(row[6], field(RowField::Rd), false);
        shown(row[7], field(RowField::Imm), true);
        shown(
            row[8],
            field(RowField::ExtraMask).map(|m| m.trailing_zeros()),
            false,
        );
    }
}

#[test]
fn every_committed_guest_renders_and_the_listing_is_the_tables() {
    for name in [
        "fib",
        "echo",
        "rvc-dense",
        "amm",
        "orderbook",
        "vault",
        "atomics",
        "opcodes",
        "heap",
    ] {
        let elf = loader_vector(&format!("{name}.elf"));
        let page = render(&elf, name, &ProgramParams::defaults(), None).unwrap();
        let (tables, _) =
            decode_program(&load_elf(&elf).unwrap(), &ProgramParams::defaults()).unwrap();
        check_listing(&page, &elf, &tables);
        assert!(page.contains("program identity  not computed"), "{name}");
    }
}

/// Acceptance 10: an ELF that is not a fixture.
#[test]
fn an_arbitrary_elf_renders() {
    let elf = elf_of(&[
        0x0050_0513, // addi a0, zero, 5
        0x02a5_05b3, // mul a1, a0, a0
        0x00b1_262f, // amoadd.w a2, a1, (sp)
        0x0000_0073, // ecall
    ]);
    let page = render(&elf, "handmade", &ProgramParams::defaults(), None).unwrap();
    let (tables, _) = decode_program(&load_elf(&elf).unwrap(), &ProgramParams::defaults()).unwrap();
    check_listing(&page, &elf, &tables);
    for family in ["ADD_SUB_LUI_AUIPC", "MUL_DIV", "ATOMICS", "INIT_TEARDOWN"] {
        assert!(page.contains(family), "{family} is in the VmConfig section");
    }
}

#[test]
fn a_file_the_loader_refuses_is_a_named_loader_error() {
    let err = render(b"not an elf", "junk", &ProgramParams::defaults(), None).unwrap_err();
    assert!(err.contains("the loader refused it: Truncated"), "{err}");
    let err = render(&[0u8; 64], "zeros", &ProgramParams::defaults(), None).unwrap_err();
    assert!(err.contains("the loader refused it: NotAnElf"), "{err}");
    let err = render(
        &loader_vector("not_riscv.elf"),
        "arm",
        &ProgramParams::defaults(),
        None,
    )
    .unwrap_err();
    assert!(err.contains("the loader refused it: NotRiscV"), "{err}");
}

#[test]
fn an_instruction_nobody_decodes_is_a_named_decode_error() {
    let flw = 0x0005_a507;
    let err = render(&elf_of(&[flw]), "float", &ProgramParams::defaults(), None).unwrap_err();
    assert!(
        err.contains("Not all opcodes supported: pc=0x00010000"),
        "{err}"
    );
}

/// With the ceremony, the identity line is the program identity: the value
/// `crates/program`'s pinned fixture holds for fib at the defaults.
#[test]
#[ignore = "needs assets/ptau/ppot_0080_24.ptau; run with --ignored"]
fn the_identity_line_is_the_program_identity() {
    let ptau = root().join("assets/ptau/ppot_0080_24.ptau");
    assert!(ptau.exists(), "{} is absent", ptau.display());
    let srs = srs::Srs::from_ptau(&ptau, 22).unwrap();
    let page = render(
        &loader_vector("fib.elf"),
        "fib",
        &ProgramParams::defaults(),
        Some(&srs),
    )
    .unwrap();
    let pinned = fs::read_to_string(root().join("crates/program/tests/vectors/identity.txt"))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("fib default "))
        .unwrap()
        .to_string();
    assert!(
        page.contains(&format!("program identity  {pinned}")),
        "the page's identity is not the pinned one"
    );
}

/// The VmConfig section, parsed back: one row per family of the config, in
/// order, with its id, height, live-row count and field mask.
#[test]
fn the_vm_config_section_is_the_config() {
    for name in ["fib", "atomics"] {
        let elf = loader_vector(&format!("{name}.elf"));
        let page = render(&elf, name, &ProgramParams::defaults(), None).unwrap();
        let (tables, config) =
            decode_program(&load_elf(&elf).unwrap(), &ProgramParams::defaults()).unwrap();

        let section: Vec<Vec<&str>> = page
            .lines()
            .skip_while(|l| *l != "VmConfig")
            .skip(3)
            .take_while(|l| !l.is_empty())
            .map(|l| l.split_whitespace().collect())
            .collect();
        assert_eq!(
            section.len(),
            config.families.len(),
            "{name}: one row per family"
        );
        for (row, (table, (family, height))) in section
            .iter()
            .zip(tables.families.iter().zip(&config.families))
        {
            assert_eq!(row[0].parse::<u32>().unwrap(), *family, "{name}");
            assert_eq!(row[1], family_name(*family), "{name}");
            assert_eq!(row[2].parse::<u32>().unwrap(), *height, "{name}");
            let live = (0..table.height as usize)
                .filter(|r| table.is_live(*r))
                .count();
            assert_eq!(row[3].parse::<usize>().unwrap(), live, "{name}");
            let mask = row.last().unwrap().trim_end_matches(')');
            assert_eq!(
                u8::from_str_radix(mask.trim_start_matches("0b"), 2).unwrap(),
                program::field_mask(*family),
                "{name}"
            );
        }
    }
}
