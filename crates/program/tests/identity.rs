//! Program identity: determinism, the recipe of `docs/spec/program.md` §8,
//! and sensitivity.
//!
//! **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** Identity is
//! meant to commit to the program's setup columns — every decoded table and the
//! image column — and with no commitment scheme it digests the code version,
//! the `VmConfig` and the entry pc alone. What it binds today is held below; what
//! it is meant to bind and does not, every instruction word and every
//! file-backed image byte, is held by
//! `UNFINISHED_every_code_and_image_byte_moves_the_identity`, which is
//! `#[ignore]`d until a commitment scheme fills the void
//! (`docs/architecture.md` §0).

mod common;

use constants::{family, transcript_tags as tags};
use field::Fr;
use loader::{load_elf, ProgramImage, Slot};
use program::{decode_program, program_identity, ProgramIdentity, ProgramParams};
use test_support::to_hex;
use transcript::Transcript;

fn identity_of(image: &ProgramImage, params: &ProgramParams) -> ProgramIdentity {
    let (tables, config) = decode_program(image, params).unwrap();
    program_identity(image, &tables, &config)
}

fn pinned(label: &str) -> String {
    common::pinned_identities()
        .into_iter()
        .find(|(l, _)| l == label)
        .unwrap_or_else(|| panic!("identity.txt has no `{label}`"))
        .1
}

/// `image` with the file-backed byte at `addr` flipped. The byte must be one,
/// and not code: what moves is then the image column alone.
fn flip_byte(image: &ProgramImage, addr: u32) -> ProgramImage {
    assert!(
        !matches!(
            image.slot_at(addr),
            Some(Slot::Instruction { .. } | Slot::MidInstruction)
        ),
        "{addr:#x} is code"
    );
    let mut flipped = image.clone();
    let segment = flipped
        .segments
        .iter_mut()
        .find(|s| addr >= s.vaddr && ((addr - s.vaddr) as usize) < s.bytes.len())
        .unwrap_or_else(|| panic!("{addr:#x} is not file-backed"));
    segment.bytes[(addr - segment.vaddr) as usize] ^= 1;
    flipped
}

/// fib's identity at the defaults, computed twice in one process, equals
/// itself and the committed value.
#[test]
fn fib_at_the_defaults_is_deterministic_and_pinned() {
    let image = common::guest("fib");
    let a = identity_of(&image, &ProgramParams::defaults());
    let b = identity_of(&image, &ProgramParams::defaults());
    assert_eq!(a, b, "two computations in one process");
    assert_eq!(to_hex(&a.to_bytes()), pinned("fib default"));
}

#[test]
fn fib_at_the_smallest_heights_is_pinned() {
    let identity = identity_of(&common::guest("fib"), &common::smallest());
    assert_eq!(to_hex(&identity.to_bytes()), pinned("fib smallest"));
}

/// The digest is exactly the documented recipe, rebuilt here message by
/// message: `PROGRAM_IDENTITY`, `VM_CONFIG`, `PROGRAM_ENTRY`, then one raw
/// sample. Fails if a message moved or one were added.
#[test]
fn the_identity_is_the_documented_recipe() {
    let image = common::guest("fib");
    let (tables, config) = decode_program(&image, &common::smallest()).unwrap();

    let fr = |x: u32| Fr::from_u64(x as u64);
    let mut tr = Transcript::new();
    tr.append_scalar(tags::PROGRAM_IDENTITY, fr(family::CODE_VERSION));
    let mut vm: Vec<Fr> = config.families.iter().map(|(f, _)| fr(*f)).collect();
    vm.extend(config.families.iter().map(|(_, h)| fr(*h)));
    vm.push(fr(config.bytecode_size_words));
    tr.append_scalars(tags::VM_CONFIG, &vm);
    tr.append_scalar(tags::PROGRAM_ENTRY, fr(image.entry));
    assert_eq!(
        ProgramIdentity(tr.sample()),
        program_identity(&image, &tables, &config)
    );
}

/// Each input the identity digests today moves it: the entry pc,
/// `bytecode_size_words`, one height, one family removed from the set.
#[test]
fn every_digested_input_moves_the_identity() {
    let image = common::guest("fib");
    let params = common::smallest();
    let base = identity_of(&image, &params);

    // The entry pc, moved to the next instruction: tables and image unchanged.
    let mut entered = image.clone();
    entered.entry = common::instructions(&image)
        .into_iter()
        .map(|(pc, _, _)| pc)
        .find(|pc| *pc > image.entry)
        .unwrap();
    assert_ne!(identity_of(&entered, &params), base, "the entry pc");

    let mut ceiling = params;
    ceiling.bytecode_size_words -= 1;
    assert_ne!(identity_of(&image, &ceiling), base, "bytecode_size_words");

    let mut taller = params;
    taller.heights[family::MEM_WORD as usize] = 1 << 18;
    assert_ne!(identity_of(&image, &taller), base, "one height");

    // Removing a family from the set: not something derivation will do for a
    // program that uses it, so the pair is edited directly.
    let (mut tables, mut config) = decode_program(&image, &params).unwrap();
    tables.families.retain(|t| t.family != family::MUL_DIV);
    config.families.retain(|(f, _)| *f != family::MUL_DIV);
    assert_ne!(
        program_identity(&image, &tables, &config),
        base,
        "one family"
    );
}

/// **ALARM — UNFINISHED — WARNING — TODO: NO COMMITMENT SCHEME.** What identity
/// is for: one instruction word, one `.rodata` byte and one `.data` byte each
/// move it. None does today, because nothing commits the decoded tables or the
/// image column, and this test fails. It is held here, disabled, as the property
/// a commitment scheme must restore (`docs/architecture.md` §0).
#[test]
#[ignore = "UNFINISHED: identity commits no setup column until a commitment scheme exists \
            (docs/architecture.md §0)"]
#[allow(non_snake_case)]
fn UNFINISHED_every_code_and_image_byte_moves_the_identity() {
    let image = common::guest("fib");
    let params = common::smallest();
    let base = identity_of(&image, &params);

    // One instruction word: the low immediate bit of the first 32-bit addi.
    let mut flipped = image.clone();
    let i = flipped
        .slots
        .iter()
        .position(|s| {
            matches!(s, Slot::Instruction { word, compressed: false }
                if isa::decode(*word).map(|x| x.mnemonic() == "addi").unwrap_or(false))
        })
        .unwrap();
    let Slot::Instruction { word, .. } = flipped.slots[i] else {
        unreachable!()
    };
    flipped.slots[i] = Slot::Instruction {
        word: word ^ (1 << 20),
        compressed: false,
    };
    assert_ne!(identity_of(&flipped, &params), base, "an instruction word");

    // One `.rodata` byte: fib's `.rodata` starts at 0x12000 (`llvm-objdump -h`).
    assert_ne!(
        identity_of(&flip_byte(&image, 0x1_2000), &params),
        base,
        "a .rodata byte"
    );

    // One `.data` byte. fib has no `.data`; `guests/atomics` is the one guest
    // with one, 20 bytes at 0x15000 (`llvm-objdump -h`).
    let atomics = common::guest("atomics");
    assert_ne!(
        identity_of(&flip_byte(&atomics, 0x1_5000), &params),
        identity_of(&atomics, &params),
        "a .data byte"
    );
}

/// Identity is meant to bind file-backed bytes, not a segment's zero tail:
/// resizing fib's heap-and-stack reservation, a segment with no file bytes,
/// does not move it.
#[test]
fn a_segment_without_file_bytes_does_not_move_the_identity_by_its_size() {
    let image = common::guest("fib");
    let mut resized = image.clone();
    let reservation = resized
        .segments
        .iter_mut()
        .find(|s| s.bytes.is_empty())
        .expect("fib's heap-and-stack reservation has no file bytes");
    reservation.mem_len -= 0x1000;
    assert_ne!(resized, image);
    assert_eq!(
        identity_of(&resized, &common::smallest()),
        identity_of(&image, &common::smallest())
    );
}

/// fib rebuilt from source, twice, into fresh target directories, has one
/// identity — and on the machine the fixture was built on, it is the committed
/// one. `#[ignore]`d because it builds the guest twice from source.
#[test]
#[ignore = "builds guests/fib twice from source; run with --ignored"]
fn a_rebuilt_guest_has_the_same_identity() {
    let a = common::build("fib", "identity-a");
    let b = common::build("fib", "identity-b");
    let ia = identity_of(&load_elf(&a).unwrap(), &common::smallest());
    let ib = identity_of(&load_elf(&b).unwrap(), &common::smallest());
    assert_eq!(ia, ib, "two clean builds");
    if a == common::loader_vector("fib.elf") {
        assert_eq!(to_hex(&ia.to_bytes()), pinned("fib smallest"));
        println!("the rebuild is the committed fixture, and so is its identity");
    } else {
        println!(
            "the rebuild differs from the committed fixture in bytes -- rustc embeds \
             absolute paths -- so only the two rebuilds are compared"
        );
    }
}
