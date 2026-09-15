//! Program identity: determinism, the recipe, and sensitivity. Acceptance 8
//! and 9, and the recipe of `docs/spec/memory.md` §6.2.
//!
//! **Every test here but the last is `#[ignore]`d.** Identity is Mercury
//! commitments over the public SRS, which is PSE's 19 GB ceremony file,
//! gitignored and absent from CI; asked for by name without it, each test
//! panics saying so. The last is the digest over given commitments, which
//! needs no SRS.
//!
//!     cargo test --release -p program --test identity -- --ignored
//!
//! Running that twice is acceptance 8's two local process runs: each run
//! compares against the same committed value.

mod common;

use constants::{family, transcript_tags as tags};
use curve::G1Affine;
use field::Fr;
use loader::{load_elf, ProgramImage, Slot};
use pcs::{append_g1_list, commit};
use poly::{MultilinearPoly, PolyBacking};
use program::{
    decode_program, identity_from_commitments, program_identity, setup_commitments,
    ProgramIdentity, ProgramParams,
};
use srs::Srs;
use test_support::to_hex;
use transcript::Transcript;

fn srs(power: u32) -> Srs {
    let srs = Srs::from_ptau(&common::ptau(), power).expect("the ceremony file ingests");
    let (ceremony, _) = common::pinned_identities();
    assert_eq!(
        to_hex(&srs.g1()[1].to_bytes()),
        ceremony,
        "this is not the ceremony identity.txt was generated over"
    );
    srs
}

fn identity_of(image: &ProgramImage, params: &ProgramParams, srs: &Srs) -> ProgramIdentity {
    let (tables, config) = decode_program(image, params).unwrap();
    program_identity(image, &tables, &config, srs)
}

fn pinned(label: &str) -> String {
    common::pinned_identities()
        .1
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

/// Acceptance 8: fib's identity at the frozen defaults, computed twice in one
/// process, equals itself and the committed value.
#[test]
#[ignore = "needs assets/ptau/ppot_0080_24.ptau; run with --ignored"]
fn fib_at_the_defaults_is_deterministic_and_pinned() {
    let srs = srs(22);
    let image = common::guest("fib");
    let a = identity_of(&image, &ProgramParams::defaults(), &srs);
    let b = identity_of(&image, &ProgramParams::defaults(), &srs);
    assert_eq!(a, b, "two computations in one process");
    assert_eq!(to_hex(&a.to_bytes()), pinned("fib default"));
    println!("fib default identity {}", to_hex(&a.to_bytes()));
}

#[test]
#[ignore = "needs assets/ptau/ppot_0080_24.ptau; run with --ignored"]
fn fib_at_the_smallest_heights_is_pinned() {
    let identity = identity_of(&common::guest("fib"), &common::smallest(), &srs(16));
    assert_eq!(to_hex(&identity.to_bytes()), pinned("fib smallest"));
}

/// The digest is exactly the documented recipe: rebuilt here message by
/// message, with nothing of the crate's but the tables and `pcs::commit`. The
/// image column is built here too, as `Fr`s read from `initial_word`.
#[test]
#[ignore = "needs assets/ptau/ppot_0080_24.ptau; run with --ignored"]
fn the_identity_is_the_documented_recipe() {
    let srs = srs(16);
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
    let mut lists: Vec<Vec<G1Affine>> = Vec::new();
    for table in &tables.families {
        let points: Vec<G1Affine> = match table.family {
            family::INIT_TEARDOWN => {
                let words = (0..table.height)
                    .map(|y| fr(image.initial_word(4 * y)))
                    .collect();
                let column = MultilinearPoly::new(PolyBacking::Fr(words));
                vec![commit(&srs, &column).unwrap().0]
            }
            family::ZERO_WINDOWS => Vec::new(),
            _ => (0..table.columns.len())
                .map(|c| commit(&srs, &table.column_poly(c)).unwrap().0)
                .collect(),
        };
        append_g1_list(&mut tr, tags::COMMITMENT, &points);
        lists.push(points);
    }
    assert_eq!(
        lists.iter().filter(|l| l.is_empty()).count(),
        1,
        "ZERO_WINDOWS absorbs an empty list, and only it"
    );
    assert_eq!(lists, setup_commitments(&image, &tables, &config, &srs));
    assert_eq!(
        ProgramIdentity(tr.sample()),
        program_identity(&image, &tables, &config, &srs)
    );
}

/// Acceptance 9, and what S14 binds: each of the inputs moves the identity —
/// one instruction word, one `.rodata` byte, one `.data` byte, the entry pc,
/// `bytecode_size_words`, one family removed from the set, one height.
#[test]
#[ignore = "needs assets/ptau/ppot_0080_24.ptau; run with --ignored"]
fn every_input_moves_the_identity() {
    let srs = srs(18);
    let image = common::guest("fib");
    let params = common::smallest();
    let base = identity_of(&image, &params, &srs);

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
    assert_ne!(
        identity_of(&flipped, &params, &srs),
        base,
        "an instruction word"
    );

    // One `.rodata` byte: fib's `.rodata` starts at 0x12000 (`llvm-objdump -h`).
    assert_ne!(
        identity_of(&flip_byte(&image, 0x1_2000), &params, &srs),
        base,
        "a .rodata byte"
    );

    // The entry pc, moved to the next instruction: tables and image unchanged.
    let mut entered = image.clone();
    entered.entry = common::instructions(&image)
        .into_iter()
        .map(|(pc, _, _)| pc)
        .find(|pc| *pc > image.entry)
        .unwrap();
    assert_ne!(identity_of(&entered, &params, &srs), base, "the entry pc");

    let mut ceiling = params;
    ceiling.bytecode_size_words -= 1;
    assert_ne!(
        identity_of(&image, &ceiling, &srs),
        base,
        "bytecode_size_words"
    );

    let mut taller = params;
    taller.heights[family::MEM_WORD as usize] = 1 << 18;
    assert_ne!(identity_of(&image, &taller, &srs), base, "one height");

    // Removing a family from the set: not something derivation will do for a
    // program that uses it, so the pair is edited directly.
    let (mut tables, mut config) = decode_program(&image, &params).unwrap();
    tables.families.retain(|t| t.family != family::MUL_DIV);
    config.families.retain(|(f, _)| *f != family::MUL_DIV);
    assert_ne!(
        program_identity(&image, &tables, &config, &srs),
        base,
        "one family"
    );

    // One `.data` byte. fib has no `.data`; `guests/atomics` is the one guest
    // with one, 20 bytes at 0x15000 (`llvm-objdump -h`).
    let atomics = common::guest("atomics");
    assert_ne!(
        identity_of(&flip_byte(&atomics, 0x1_5000), &params, &srs),
        identity_of(&atomics, &params, &srs),
        "a .data byte"
    );
}

/// Identity binds file-backed bytes, not a segment's zero tail: resizing fib's
/// heap-and-stack reservation, a segment with no file bytes, does not move it.
#[test]
#[ignore = "needs assets/ptau/ppot_0080_24.ptau; run with --ignored"]
fn a_segment_without_file_bytes_does_not_move_the_identity_by_its_size() {
    let srs = srs(16);
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
        identity_of(&resized, &common::smallest(), &srs),
        identity_of(&image, &common::smallest(), &srs)
    );
}

/// Acceptance 8's last clause: fib rebuilt from source, twice, into fresh
/// target directories, has one identity — and on the machine the fixture was
/// built on, it is the committed one.
#[test]
#[ignore = "needs assets/ptau/ppot_0080_24.ptau; run with --ignored"]
fn a_rebuilt_guest_has_the_same_identity() {
    let srs = srs(16);
    let a = common::build("fib", "identity-a");
    let b = common::build("fib", "identity-b");
    let ia = identity_of(&load_elf(&a).unwrap(), &common::smallest(), &srs);
    let ib = identity_of(&load_elf(&b).unwrap(), &common::smallest(), &srs);
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

/// The digest over given commitments needs no SRS, so it runs in CI: over
/// fixed synthetic points it is a function of its inputs, and moving the entry
/// pc or any one commitment moves it.
#[test]
fn the_digest_over_commitments_moves_with_the_entry_pc_and_each_commitment() {
    let (_, config) = decode_program(&common::guest("fib"), &common::smallest()).unwrap();
    let lists: Vec<Vec<G1Affine>> = config
        .families
        .iter()
        .map(|(f, _)| match *f {
            family::ZERO_WINDOWS => Vec::new(),
            _ => vec![G1Affine::GENERATOR; 2],
        })
        .collect();
    let digest = |entry_pc: u32, lists: &[Vec<G1Affine>]| {
        identity_from_commitments(family::CODE_VERSION, &config, entry_pc, lists)
    };
    let base = digest(0x1_0000, &lists);
    assert_eq!(digest(0x1_0000, &lists), base, "a function of its inputs");
    assert_ne!(digest(0x1_0002, &lists), base, "the entry pc");
    for (i, list) in lists.iter().enumerate() {
        for j in 0..list.len() {
            let mut moved = lists.clone();
            moved[i][j] = G1Affine::IDENTITY;
            assert_ne!(
                digest(0x1_0000, &moved),
                base,
                "commitment {j} of family {}",
                config.families[i].0
            );
        }
    }
}
