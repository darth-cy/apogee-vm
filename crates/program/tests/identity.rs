//! Program identity: determinism, the recipe, and sensitivity. Acceptance 8
//! and 9.
//!
//! **Every test here is `#[ignore]`d.** Identity is Mercury commitments over
//! the public SRS, which is PSE's 19 GB ceremony file, gitignored and absent
//! from CI; asked for by name without it, each test panics saying so.
//!
//!     cargo test --release -p program --test identity -- --ignored
//!
//! Running that twice is acceptance 8's two local process runs: each run
//! compares against the same committed value.

mod common;

use constants::{family, transcript_tags as tags};
use field::Fr;
use loader::{load_elf, Slot};
use pcs::{append_g1_list, commit};
use program::{decode_program, program_identity, ProgramIdentity, ProgramParams};
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

fn identity_of(image: &loader::ProgramImage, params: &ProgramParams, srs: &Srs) -> ProgramIdentity {
    let (tables, config) = decode_program(image, params).unwrap();
    program_identity(&tables, &config, srs)
}

fn pinned(label: &str) -> String {
    common::pinned_identities()
        .1
        .into_iter()
        .find(|(l, _)| l == label)
        .unwrap_or_else(|| panic!("identity.txt has no `{label}`"))
        .1
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
/// message, from the exported columns, with nothing of the crate's but the
/// tables and `pcs::commit`.
#[test]
#[ignore = "needs assets/ptau/ppot_0080_24.ptau; run with --ignored"]
fn the_identity_is_the_documented_recipe() {
    let srs = srs(16);
    let (tables, config) = decode_program(&common::guest("fib"), &common::smallest()).unwrap();

    let fr = |x: u32| Fr::from_u64(x as u64);
    let mut tr = Transcript::new();
    tr.append_scalar(tags::PROGRAM_IDENTITY, fr(family::CODE_VERSION));
    let mut vm: Vec<Fr> = config.families.iter().map(|(f, _)| fr(*f)).collect();
    vm.extend(config.families.iter().map(|(_, h)| fr(*h)));
    vm.push(fr(config.bytecode_size_words));
    tr.append_scalars(tags::VM_CONFIG, &vm);
    let mut empty = 0;
    for table in &tables.families {
        let points: Vec<_> = (0..table.columns.len())
            .map(|c| commit(&srs, &table.column_poly(c)).unwrap().0)
            .collect();
        empty += points.is_empty() as usize;
        append_g1_list(&mut tr, tags::COMMITMENT, &points);
    }
    assert_eq!(empty, 1, "init/teardown absorbs an empty list, and only it");
    assert_eq!(
        ProgramIdentity(tr.sample()),
        program_identity(&tables, &config, &srs)
    );
}

/// Acceptance 9: each of the inputs moves the identity — one instruction
/// word, `bytecode_size_words`, one family removed from the set, one height.
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
    assert_ne!(program_identity(&tables, &config, &srs), base, "one family");
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
