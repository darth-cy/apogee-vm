//! The family partition and static detachment: acceptance 3, 4 and 5.

mod common;

use std::collections::BTreeMap;

use constants::family;
use program::{decode_program, family_name, ProgramParams};

/// Acceptance 3: every executable pc lands in exactly one family table, and
/// nothing else does.
///
/// The claimed-pc union is recomputed from the finished tables — the pc a live
/// row stands for is twice its index — and compared with the image's
/// instruction slots, both ways. Run over every committed guest, fib first.
#[test]
fn every_instruction_is_claimed_by_exactly_one_family() {
    for name in common::GUESTS {
        let image = common::guest(name);
        let (tables, config) = decode_program(&image, &common::fitting(&image))
            .unwrap_or_else(|e| panic!("{name}: {e}"));

        let mut owner: BTreeMap<u32, u32> = BTreeMap::new();
        for table in &tables.families {
            for row in 0..table.height as usize {
                if !table.is_live(row) {
                    continue;
                }
                let pc = 2 * row as u32;
                assert_eq!(
                    table.get(0, row),
                    Some(pc),
                    "{name}: a live row's pc column must be twice its index"
                );
                if let Some(other) = owner.insert(pc, table.family) {
                    panic!(
                        "{name}: pc {pc:#010x} is claimed by {} and {}",
                        family_name(other),
                        family_name(table.family)
                    );
                }
            }
        }
        let slots: Vec<u32> = common::instructions(&image)
            .iter()
            .map(|(pc, _, _)| *pc)
            .collect();
        let claimed: Vec<u32> = owner.keys().copied().collect();
        assert_eq!(
            claimed, slots,
            "{name}: the claimed pcs are not the image's instruction slots"
        );

        let sizes: Vec<String> = tables
            .families
            .iter()
            .map(|t| {
                let live = (0..t.height as usize).filter(|r| t.is_live(*r)).count();
                format!("{} {live}/{}", family_name(t.family), t.height)
            })
            .collect();
        println!("{name}: {} instructions; {}", slots.len(), sizes.join(", "));
        assert!(
            config
                .families
                .iter()
                .any(|(f, _)| *f == family::INIT_TEARDOWN),
            "{name}: init/teardown is in every VmConfig"
        );
    }
}

/// Acceptance 4: an `amoadd.w` whose family is detached is claimed by nobody,
/// and derivation fails naming its pc. That failure is what makes detachment
/// sound: a config without a family cannot quietly drop that family's
/// instructions.
#[test]
fn an_atomic_under_detached_atomics_fails_naming_its_pc() {
    let image = common::guest("atomics");
    let (pc, _, _) = common::instructions(&image)
        .into_iter()
        .find(|(_, w, _)| {
            isa::decode(*w)
                .map(|i| i.mnemonic() == "amoadd.w")
                .unwrap_or(false)
        })
        .expect("guests/atomics carries an amoadd.w");
    // The first instruction the atomics family owns, whichever it is.
    let (first, first_word, _) = common::instructions(&image)
        .into_iter()
        .find(|(_, w, _)| {
            isa::decode(*w)
                .map(|i| program::row_kind(&i).0 == family::ATOMICS)
                .unwrap_or(false)
        })
        .unwrap();
    assert!(first <= pc);

    let err =
        program::decode_program_detaching(&image, &ProgramParams::defaults(), &[family::ATOMICS])
            .unwrap_err();
    assert!(
        matches!(err, program::ProgramError::NotAllOpcodesSupported { pc, word, .. }
            if pc == first && word == first_word),
        "{err:?}"
    );
    assert!(
        err.to_string()
            .starts_with(&format!("Not all opcodes supported: pc={first:#010x}")),
        "{err}"
    );

    // The control: undetached, the same image derives the family.
    let (_, config) = decode_program(&image, &ProgramParams::defaults()).unwrap();
    assert!(config.height(family::ATOMICS).is_some());
}

/// Acceptance 5: the family set is derived from each program.
#[test]
fn each_program_derives_only_the_families_it_uses() {
    let fib = decode_program(&common::guest("fib"), &ProgramParams::defaults())
        .unwrap()
        .1;
    assert_eq!(fib.height(family::ATOMICS), None, "fib has no atomics");
    assert!(
        fib.height(family::MUL_DIV).is_some(),
        "fib's panic path multiplies"
    );

    let atomics = decode_program(&common::guest("atomics"), &ProgramParams::defaults())
        .unwrap()
        .1;
    assert_eq!(
        atomics.height(family::ATOMICS),
        Some(family::DEFAULT_HEIGHTS[family::ATOMICS as usize])
    );

    let mul_free = loader::load_elf(&common::own_vector("mul_free.elf")).unwrap();
    let config = decode_program(&mul_free, &ProgramParams::defaults())
        .unwrap()
        .1;
    let set: Vec<u32> = config.families.iter().map(|(f, _)| *f).collect();
    assert_eq!(
        set,
        [
            family::ADD_SUB_LUI_AUIPC,
            family::JUMP_BRANCH_SLT,
            family::SHIFT_BITWISE,
            family::MEM_WORD,
            family::MEM_SUBWORD,
            family::INIT_TEARDOWN,
        ],
        "a mul-free program derives no mul/div family"
    );
    // Detaching a family the program never uses changes nothing.
    let detached = program::decode_program_detaching(
        &mul_free,
        &ProgramParams::defaults(),
        &[family::MUL_DIV, family::ATOMICS],
    )
    .unwrap();
    assert_eq!(detached.1, config);
}

/// Which committed guests the frozen default heights can preprocess, and which
/// cannot.
///
/// The suites that are not about the heights take `common::fitting`, so without
/// this nothing would notice a guest — or growth in an existing one — crossing
/// a default. `portability` is the first program to cross one: a family's table
/// is indexed by absolute pc and the defaults give atomics 2^16 rows, which run
/// out at pc `0x20000`, while that guest's atomics run up to `0x18e8a0`.
#[test]
fn the_default_heights_hold_every_guest_but_the_largest() {
    for name in common::GUESTS {
        let image = common::guest(name);
        let decoded = decode_program(&image, &ProgramParams::defaults());
        if name == "portability" {
            let Err(program::ProgramError::TableTooShort { family, height, .. }) = decoded else {
                panic!("{name} is expected to cross the default atomics height");
            };
            assert_eq!((family, height), (family::ATOMICS, 1 << 16));
            assert!(
                decode_program(&image, &common::fitting(&image)).is_ok(),
                "{name} fits no menu height"
            );
        } else {
            assert!(decoded.is_ok(), "{name}: {:?}", decoded.err());
        }
    }
}

/// A word no family knows is a loud failure naming its pc, with the decoder's
/// reason attached.
#[test]
fn an_instruction_no_family_knows_fails_naming_its_pc() {
    let flw = 0x0005_a507;
    let image = common::image_of(0x1_0000, &[0x0000_0013, flw, 0x0000_0073]);
    let err = decode_program(&image, &ProgramParams::defaults()).unwrap_err();
    assert_eq!(
        err,
        program::ProgramError::NotAllOpcodesSupported {
            pc: 0x1_0004,
            word: flw,
            reason: "an opcode RV32IMAC does not have",
        }
    );
    assert!(err
        .to_string()
        .starts_with("Not all opcodes supported: pc=0x00010004"));
}
