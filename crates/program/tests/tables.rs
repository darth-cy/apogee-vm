//! The decoded tables: padding, the fall-through pc, the table length, the
//! field masks and the extra-mask encoding. Acceptance 6 and 7, must-be-exact
//! 3 and 5.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use constants::{extra_mask, family};
use field::Fr;
use loader::Slot;
use poly::PolyBacking;
use program::{
    decode_program, family_name, field_mask, lookup_tuple, row_kind, FamilyId, ProgramError,
    ProgramParams, RowField, FAMILIES,
};

/// Acceptance 6: a scan of every exported column of every table proves that
/// every row that is not one of the family's live instructions is
/// `MINUS_ONE` in every field, and that no live row is the padding row — or
/// all zeros.
///
/// Exported columns, not the stored ones: the committed polynomial is what the
/// sentinel rule is about. The mid-instruction and not-code slots of the
/// RVC-dense guest get their own count, so the check is not satisfied by a
/// corpus that happened to have none.
#[test]
fn every_row_that_is_not_live_is_padding_in_every_field() {
    for name in common::GUESTS {
        let image = common::guest(name);
        let (tables, _) = decode_program(&image, &common::smallest()).unwrap();
        for table in &tables.families {
            let columns: Vec<_> = (0..table.columns.len())
                .map(|c| table.column_poly(c))
                .collect();
            let padding = vec![Fr::MINUS_ONE; columns.len()];
            for row in 0..table.height as usize {
                let values: Vec<Fr> = columns.iter().map(|p| p.get(row)).collect();
                if table.is_live(row) {
                    assert!(
                        values.iter().all(|v| *v != Fr::MINUS_ONE),
                        "{name}: a live {} row holds the sentinel",
                        family_name(table.family)
                    );
                    assert!(
                        values.iter().any(|v| *v != Fr::ZERO),
                        "{name}: a live {} row is all zeros",
                        family_name(table.family)
                    );
                } else {
                    assert_eq!(
                        values,
                        padding,
                        "{name}: {} row {row} is not live and not padding",
                        family_name(table.family)
                    );
                }
            }
        }

        // The slots that are padding for a reason: the second halfword of a
        // 32-bit instruction, and anything that is not code.
        let (mut mid, mut non, mut interleaved) = (0usize, 0usize, 0usize);
        for (i, slot) in image.slots.iter().enumerate() {
            let row = (image.slot_base / 2) as usize + i;
            match slot {
                Slot::MidInstruction => {
                    mid += 1;
                    // Directly followed by a two-byte instruction: RVC-expanded
                    // code, where the halfword grid is dense.
                    if let Some(Slot::Instruction {
                        compressed: true, ..
                    }) = image.slots.get(i + 1)
                    {
                        interleaved += 1;
                    }
                }
                Slot::NonInstruction => non += 1,
                Slot::Instruction { .. } => continue,
            }
            for table in &tables.families {
                assert!(!table.is_live(row), "{name}: row {row} is not code");
            }
        }
        println!("{name}: {mid} mid-instruction slots, {interleaved} of them before RVC code, {non} not code");
        assert!(
            mid > 0 && interleaved > 0,
            "{name}: no mid-instruction slot inside RVC code"
        );
        if name == "amm" {
            assert!(non > 0, "amm carries a c.unimp, which is not code");
        }
    }
}

/// Acceptance 7: every live row's `next_pc` is `pc + 2` or `pc + 4`, as the
/// loader's halfword map says the instruction's length is.
#[test]
fn next_pc_is_the_fall_through_the_encoding_implies() {
    for name in common::GUESTS {
        let image = common::guest(name);
        let (tables, _) = decode_program(&image, &common::smallest()).unwrap();
        let (mut two, mut four) = (0usize, 0usize);
        for table in tables.families.iter().filter(|t| !t.columns.is_empty()) {
            assert_eq!(table.columns[0].0, RowField::Pc);
            assert_eq!(table.columns[1].0, RowField::NextPc);
            for row in (0..table.height as usize).filter(|r| table.is_live(*r)) {
                let pc = table.get(0, row).unwrap();
                let next = table.get(1, row).unwrap();
                let Some(Slot::Instruction { compressed, .. }) = image.slot_at(pc) else {
                    panic!("{name}: a live row at {pc:#010x} that is not an instruction");
                };
                let want = pc + if compressed { 2 } else { 4 };
                assert_eq!(next, want, "{name}: next_pc at {pc:#010x}");
                if compressed {
                    two += 1;
                } else {
                    four += 1;
                }
            }
        }
        assert!(two > 0 && four > 0, "{name}: both lengths are exercised");
    }
}

/// Must-be-exact 3: every table is exactly its family's `VmConfig` height, an
/// even variable count, and exports at that length.
#[test]
fn every_table_is_exactly_its_config_height() {
    let image = common::guest("fib");
    let (tables, config) = decode_program(&image, &ProgramParams::defaults()).unwrap();
    assert_eq!(tables.families.len(), config.families.len());
    for (table, (family, height)) in tables.families.iter().zip(&config.families) {
        assert_eq!((table.family, table.height), (*family, *height));
        assert_eq!(*height, family::DEFAULT_HEIGHTS[*family as usize]);
        let live_len = match &table.live {
            PolyBacking::U1(_, n) => *n,
            other => panic!("liveness is a bitset, not {other:?}"),
        };
        assert_eq!(live_len, *height as usize);
        for (_, backing) in &table.columns {
            let len = match backing {
                PolyBacking::U1(_, n) => *n,
                PolyBacking::U8(v) => v.len(),
                PolyBacking::U16(v) => v.len(),
                PolyBacking::U32(v) => v.len(),
                PolyBacking::Fr(_) => panic!("a stored column is never Fr"),
            };
            assert_eq!(len, *height as usize);
        }
    }
    // One export at the full default height, to see the length and the
    // variable count directly. 2^22 rows of Fr is 128 MiB.
    let alu = tables.family(family::ADD_SUB_LUI_AUIPC).unwrap();
    let exported = alu.column_poly(0);
    assert_eq!(exported.len(), 1 << 22);
    assert_eq!(exported.num_vars() % 2, 0);
}

/// Must-be-exact 3: the table must be strictly taller than the row after its
/// last live row, or derivation fails loudly naming the pc.
#[test]
fn a_table_that_cannot_hold_its_program_fails_loudly() {
    let addi = 0x0000_0013;
    // Row 65534 at pc 0x1fffc: one padding row above it in a 2^16 table.
    let fits = common::image_of(0x1_fffc, &[addi]);
    assert!(decode_program(&fits, &common::smallest()).is_ok());
    // Row 65535: no row above it.
    let full = common::image_of(0x1_fffe, &[addi]);
    assert_eq!(
        decode_program(&full, &common::smallest()).unwrap_err(),
        ProgramError::TableTooShort {
            family: family::ADD_SUB_LUI_AUIPC,
            pc: 0x1_fffe,
            height: 1 << 16,
        }
    );
    // The same program is fine one menu step up.
    let mut taller = common::smallest();
    taller.heights[family::ADD_SUB_LUI_AUIPC as usize] = 1 << 18;
    assert!(decode_program(&full, &taller).is_ok());
}

/// Must-be-exact 5: `bytecode_size_words` is an explicit input, and a program
/// above it fails loudly.
#[test]
fn a_program_above_bytecode_size_words_fails_loudly() {
    let image = common::guest("fib");
    let end = image
        .segments
        .iter()
        .map(|s| s.vaddr as u64 + s.bytes.len() as u64)
        .max()
        .unwrap();
    let words = (end - constants::guest_memory::RAM_ORIGIN as u64).div_ceil(4);

    let mut params = ProgramParams::defaults();
    params.bytecode_size_words = words as u32;
    let (_, config) = decode_program(&image, &params).expect("exactly at the ceiling");
    assert_eq!(
        config.bytecode_size_words, words as u32,
        "and it is recorded"
    );

    params.bytecode_size_words = words as u32 - 1;
    assert_eq!(
        decode_program(&image, &params).unwrap_err(),
        ProgramError::ProgramTooLarge {
            words,
            bytecode_size_words: words as u32 - 1,
        }
    );
}

#[test]
fn parameters_off_the_menu_and_unknown_versions_are_refused() {
    let image = common::guest("fib");
    for height in [0, 1, 1 << 17, 1 << 24, u32::MAX] {
        let mut params = ProgramParams::defaults();
        params.heights[family::MUL_DIV as usize] = height;
        assert_eq!(
            decode_program(&image, &params).unwrap_err(),
            ProgramError::HeightNotOnMenu {
                family: family::MUL_DIV,
                height,
            }
        );
    }
    let mut params = ProgramParams::defaults();
    params.code_version = family::CODE_VERSION + 1;
    assert!(matches!(
        decode_program(&image, &params),
        Err(ProgramError::UnsupportedCodeVersion { .. })
    ));
}

/// The per-family field masks, frozen. `funct3` is bit 6 and no family keeps
/// it; mul/div and the atomics have no immediate.
#[test]
fn the_field_masks_are_frozen() {
    let want: [(FamilyId, u8); 8] = [
        (family::ADD_SUB_LUI_AUIPC, 0b1011_1111),
        (family::JUMP_BRANCH_SLT, 0b1011_1111),
        (family::SHIFT_BITWISE, 0b1011_1111),
        (family::MUL_DIV, 0b1001_1111),
        (family::MEM_WORD, 0b1011_1111),
        (family::MEM_SUBWORD, 0b1011_1111),
        (family::ATOMICS, 0b1001_1111),
        (family::INIT_TEARDOWN, 0),
    ];
    for (family, mask) in want {
        assert_eq!(field_mask(family), mask, "{}", family_name(family));
        assert_eq!(lookup_tuple(family).len(), mask.count_ones() as usize);
    }
    assert_eq!(FAMILIES.len(), family::COUNT as usize);
}

/// The extra mask over every RV32IMA mnemonic: each live row's mask is
/// one-hot, the bit is the one `constants::extra_mask` names, `(family, mask,
/// system code)` names exactly one mnemonic, and each family's bits are dense
/// from 0.
#[test]
fn every_row_kind_is_one_hot_and_names_exactly_one_mnemonic() {
    let image = loader::load_elf(&common::isa_vector("isa_corpus.elf")).unwrap();
    let (tables, _) = decode_program(&image, &common::smallest()).unwrap();

    let mut kinds: BTreeMap<(FamilyId, u32, Option<u32>), &'static str> = BTreeMap::new();
    let mut bits: BTreeMap<FamilyId, BTreeSet<u32>> = BTreeMap::new();
    for (pc, word, _) in common::instructions(&image) {
        let instr = isa::decode(word).unwrap();
        let (family, bit) = row_kind(&instr);
        let table = tables.family(family).unwrap();
        let column = |field| table.columns.iter().position(|(f, _)| *f == field).unwrap();
        let row = (pc / 2) as usize;
        let mask = table.get(column(RowField::ExtraMask), row).unwrap();
        assert_eq!(
            mask,
            1 << bit,
            "{pc:#010x}: the mask is the one-hot kind bit"
        );

        let system = (family == family::ADD_SUB_LUI_AUIPC
            && bit == extra_mask::add_sub_lui_auipc::SYSTEM)
            .then(|| table.get(column(RowField::Imm), row).unwrap());
        let mnemonic = instr.mnemonic();
        if let Some(other) = kinds.insert((family, mask, system), mnemonic) {
            assert_eq!(other, mnemonic, "two mnemonics share one row kind");
        }
        bits.entry(family).or_default().insert(bit);
    }
    assert_eq!(kinds.len(), 59, "one row kind per RV32IMA mnemonic");
    let widths: BTreeMap<FamilyId, usize> = [
        (family::ADD_SUB_LUI_AUIPC, 6),
        (family::JUMP_BRANCH_SLT, 12),
        (family::SHIFT_BITWISE, 12),
        (family::MUL_DIV, 8),
        (family::MEM_WORD, 2),
        (family::MEM_SUBWORD, 6),
        (family::ATOMICS, 11),
    ]
    .into_iter()
    .collect();
    for (family, used) in bits {
        let dense: BTreeSet<u32> = (0..widths[&family] as u32).collect();
        assert_eq!(
            used,
            dense,
            "{}: bits are dense from 0",
            family_name(family)
        );
    }
}

/// Each stored column is in the narrowest backing its live values fit, with
/// zero on every row that is not live.
#[test]
fn each_column_is_stored_in_the_narrowest_backing() {
    for name in ["fib", "atomics"] {
        let (tables, _) = decode_program(&common::guest(name), &common::smallest()).unwrap();
        for table in &tables.families {
            for (c, (field, backing)) in table.columns.iter().enumerate() {
                let max = (0..table.height as usize)
                    .filter_map(|r| table.get(c, r))
                    .max()
                    .unwrap();
                let fits = match backing {
                    PolyBacking::U1(..) => max <= 1,
                    PolyBacking::U8(_) => (2..=0xff).contains(&max),
                    PolyBacking::U16(_) => (0x100..=0xffff).contains(&max),
                    PolyBacking::U32(_) => max > 0xffff,
                    PolyBacking::Fr(_) => false,
                };
                assert!(fits, "{name} {field:?}: max {max} in {backing:?}");
            }
        }
    }
}

#[test]
fn decoding_is_a_function_of_its_inputs() {
    for name in common::GUESTS {
        let image = common::guest(name);
        let a = decode_program(&image, &ProgramParams::defaults()).unwrap();
        let b = decode_program(&image.clone(), &ProgramParams::defaults()).unwrap();
        assert_eq!(a, b, "{name}");
    }
}

#[test]
fn committed_fixtures_match_their_pins() {
    for (name, want) in common::PINS {
        assert_eq!(
            common::digest(&common::own_vector(name)),
            want,
            "{name} has changed. If that was deliberate, rerun `cargo run -p kat-gen -- \
             program` and update the digest in tests/common/mod.rs."
        );
    }
}
