//! Program identity: determinism, the recipe of `docs/spec/program.md` §8,
//! and sensitivity — to the code version, the `VmConfig` and the entry pc, and
//! through the setup commitments to every instruction word and every
//! file-backed image byte.

mod common;

use constants::{family, transcript_tags as tags};
use field::Fp;
use loader::{load_elf, ProgramImage, Slot};
use program::{decode_program, program_identity, ProgramIdentity, ProgramParams};
use transcript::Transcript;

/// The smallest menu heights every family has a circuit at: identity commits
/// each family's setup columns under its circuit's opening schedule, and a
/// cycle-owning family's timestamp channel has a floor of `2^19`.
fn provable() -> ProgramParams {
    let mut params = common::smallest();
    for (f, h) in params.heights.iter_mut().enumerate() {
        if family::CYCLE_OWNING[f] {
            *h = 1 << 20;
        }
    }
    params
}

fn identity_of(image: &ProgramImage, params: &ProgramParams) -> ProgramIdentity {
    let (tables, config) = decode_program(image, params).unwrap();
    program_identity(image, &tables, &config).unwrap()
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
/// itself. No value is pinned: the identity is a digest over a build, and the
/// recipe below is what holds it.
#[test]
fn fib_at_the_defaults_is_deterministic() {
    let image = common::guest("fib");
    let a = identity_of(&image, &ProgramParams::defaults());
    let b = identity_of(&image, &ProgramParams::defaults());
    assert_eq!(a, b, "two computations in one process");
}

/// The digest is exactly the documented recipe, rebuilt here message by
/// message: `PROGRAM_IDENTITY`, `VM_CONFIG`, `PROGRAM_ENTRY`, one
/// `SETUP_COMMITMENT` per family, then `digest()`. Fails if a message moved or
/// one were added.
#[test]
fn the_identity_is_the_documented_recipe() {
    let image = common::guest("fib");
    let (tables, config) = decode_program(&image, &provable()).unwrap();

    let fp = |x: u32| Fp::from_u64(x as u64);
    let mut tr = Transcript::new();
    tr.append_scalar(tags::PROGRAM_IDENTITY, fp(family::CODE_VERSION));
    let mut vm: Vec<Fp> = config.families.iter().map(|(f, _)| fp(*f)).collect();
    vm.extend(config.families.iter().map(|(_, h)| fp(*h)));
    vm.push(fp(config.bytecode_size_words));
    tr.append_scalars(tags::VM_CONFIG, &vm);
    tr.append_scalar(tags::PROGRAM_ENTRY, fp(image.entry));
    let circuits: Vec<_> = config
        .families
        .iter()
        .map(|&(f, h)| config.circuit(f, h.trailing_zeros()).unwrap())
        .collect();
    let pcs = pcs::expand_setup(verifier_core::pcs_setup_len(&circuits));
    for opener in program::setup_openers(&image, &tables, &circuits, &pcs) {
        let c = program::setup_commitment(opener.as_ref());
        tr.append_scalars(tags::SETUP_COMMITMENT, &c.0.concat());
    }
    assert_eq!(
        ProgramIdentity(tr.digest()),
        program_identity(&image, &tables, &config).unwrap()
    );
}

/// Each input the identity digests today moves it: the entry pc,
/// `bytecode_size_words`, one height, one family removed from the set.
#[test]
fn every_digested_input_moves_the_identity() {
    let image = common::guest("fib");
    let params = provable();
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
    taller.heights[family::MEM_WORD as usize] = 1 << 22;
    assert_ne!(identity_of(&image, &taller), base, "one height");

    // Removing a family from the set: not something derivation will do for a
    // program that uses it, so the pair is edited directly.
    let (mut tables, mut config) = decode_program(&image, &params).unwrap();
    tables.families.retain(|t| t.family != family::MUL_DIV);
    config.families.retain(|(f, _)| *f != family::MUL_DIV);
    assert_ne!(
        program_identity(&image, &tables, &config).unwrap(),
        base,
        "one family"
    );
}

/// What identity is for: one instruction word, one `.rodata` byte and one
/// `.data` byte each move it, through the commitments to the decoded tables
/// and the image column.
#[test]
fn every_code_and_image_byte_moves_the_identity() {
    let image = common::guest("fib");
    let params = provable();
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
/// resizing fib's heap-and-stack reservation, the zero tail of its writable
/// segment, does not move it.
#[test]
fn a_segments_zero_tail_does_not_move_the_identity_by_its_size() {
    let image = common::guest("fib");
    let mut resized = image.clone();
    let reservation = resized
        .segments
        .iter_mut()
        .find(|s| s.mem_len as usize > s.bytes.len() + 0x1000)
        .expect("fib's heap-and-stack reservation is a segment's zero tail");
    reservation.mem_len -= 0x1000;
    assert_ne!(resized, image);
    assert_eq!(
        identity_of(&resized, &provable()),
        identity_of(&image, &provable())
    );
}

/// fib rebuilt from source, twice, into fresh target directories, has one
/// identity. `#[ignore]`d because it builds the guest twice more.
#[test]
#[ignore = "builds guests/fib twice from source; run with --ignored"]
fn a_rebuilt_guest_has_the_same_identity() {
    let a = common::build("fib", "identity-a");
    let b = common::build("fib", "identity-b");
    let ia = identity_of(&load_elf(&a).unwrap(), &provable());
    let ib = identity_of(&load_elf(&b).unwrap(), &provable());
    assert_eq!(ia, ib, "two clean builds");
}
