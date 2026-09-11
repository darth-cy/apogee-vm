//! The frozen wire forms — `VmConfig` and `ProgramIdentity` — and the
//! statement descriptor.

mod common;

use constants::{family, transcript_tags as tags};
use field::Fr;
use program::{
    absorb_statement_descriptor, decode_program, ProgramIdentity, ProgramParams, VmConfig,
};
use transcript::{Transcript, TranscriptEvent};

fn fib_config() -> VmConfig {
    decode_program(&common::guest("fib"), &ProgramParams::defaults())
        .unwrap()
        .1
}

/// The wire form, written out byte for byte from its definition, and read
/// back.
#[test]
fn the_vm_config_wire_form_is_frozen_and_round_trips() {
    let config = fib_config();
    let mut want: Vec<u32> = vec![7];
    for (f, h) in [
        (family::ADD_SUB_LUI_AUIPC, 1 << 22),
        (family::JUMP_BRANCH_SLT, 1 << 22),
        (family::SHIFT_BITWISE, 1 << 22),
        (family::MUL_DIV, 1 << 20),
        (family::MEM_WORD, 1 << 22),
        (family::MEM_SUBWORD, 1 << 22),
        (family::INIT_TEARDOWN, 1 << 20),
    ] {
        want.extend([f, h]);
    }
    want.push(1 << 20);
    let want: Vec<u8> = want.iter().flat_map(|w| w.to_le_bytes()).collect();
    assert_eq!(config.to_bytes(), want);
    assert_eq!(VmConfig::from_bytes(&want), Some(config));
}

#[test]
fn a_malformed_vm_config_is_refused() {
    let good = fib_config().to_bytes();
    assert!(VmConfig::from_bytes(&good).is_some(), "the control decodes");

    let word = |bytes: &mut Vec<u8>, i: usize, v: u32| {
        bytes[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
    };
    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("truncated", good[..good.len() - 1].to_vec()),
        ("a trailing byte", [good.clone(), vec![0]].concat()),
        ("empty", Vec::new()),
    ];
    let mut unknown = good.clone();
    word(&mut unknown, 13, family::COUNT); // the last family id
    cases.push(("an unknown family", unknown));
    let mut unordered = good.clone();
    word(&mut unordered, 1, family::JUMP_BRANCH_SLT); // first id == second id
    cases.push(("a repeated family", unordered));
    let mut descending = good.clone();
    word(&mut descending, 1, family::MEM_SUBWORD);
    cases.push(("families out of order", descending));
    let mut off_menu = good.clone();
    word(&mut off_menu, 2, 1 << 17);
    cases.push(("a height off the menu", off_menu));
    let mut too_many = good.clone();
    word(&mut too_many, 0, family::COUNT + 1);
    cases.push(("more families than exist", too_many));
    for (what, bytes) in cases {
        assert_eq!(VmConfig::from_bytes(&bytes), None, "{what}");
    }
}

#[test]
fn the_identity_wire_form_is_one_canonical_field_element() {
    let identity = ProgramIdentity(Fr::from_u64(0x1234_5678));
    let bytes = identity.to_bytes();
    assert_eq!(&bytes[..4], &[0x78, 0x56, 0x34, 0x12], "little-endian");
    assert_eq!(ProgramIdentity::from_bytes(&bytes), Some(identity));
    // p itself is not canonical, and is refused rather than reduced.
    let mut p = Fr::MINUS_ONE.to_bytes();
    p[0] += 1;
    assert_eq!(ProgramIdentity::from_bytes(&p), None);
}

/// The statement descriptor is two adjacent typed messages: the `VmConfig`
/// under `VM_CONFIG`, then one shard count per family under `SHARD_COUNTS`.
#[test]
fn the_statement_descriptor_is_two_adjacent_messages() {
    let config = fib_config();
    let counts = [3, 1, 1, 0, 2, 1, 1];

    let mut tr = Transcript::new();
    absorb_statement_descriptor(&mut tr, &config, &counts);
    assert_eq!(
        tr.event_log(),
        &[
            TranscriptEvent::Absorb {
                tag: tags::VM_CONFIG,
                n_scalars: 2 * 7 + 1,
            },
            TranscriptEvent::Absorb {
                tag: tags::SHARD_COUNTS,
                n_scalars: 7,
            },
        ]
    );

    // The same two messages, written out from the definition.
    let fr = |x: u32| Fr::from_u64(x as u64);
    let mut vm: Vec<Fr> = config.families.iter().map(|(f, _)| fr(*f)).collect();
    vm.extend(config.families.iter().map(|(_, h)| fr(*h)));
    vm.push(fr(config.bytecode_size_words));
    let mut replay = Transcript::new();
    replay.append_scalars(tags::VM_CONFIG, &vm);
    replay.append_scalars(tags::SHARD_COUNTS, &counts.map(fr));
    assert_eq!(tr.snapshot(), replay.snapshot());

    // Shard counts are per proof: changing one moves the sponge.
    let mut other = Transcript::new();
    absorb_statement_descriptor(&mut other, &config, &[3, 1, 1, 0, 2, 1, 2]);
    assert_ne!(tr.snapshot(), other.snapshot());
}

#[test]
#[should_panic(expected = "one shard count per family")]
fn the_descriptor_needs_one_shard_count_per_family() {
    absorb_statement_descriptor(&mut Transcript::new(), &fib_config(), &[1, 2]);
}

/// Derivation puts init/teardown in every config, so a wire form without it —
/// including the empty one — is not a config `to_bytes` could have written
/// from a derivation. Presence is what is checked, not position: delegation
/// families are appended above init/teardown's id.
#[test]
fn a_config_without_init_teardown_is_refused() {
    let mut config = fib_config();
    let before = config.families.len();
    config.families.retain(|(f, _)| *f != family::INIT_TEARDOWN);
    assert_eq!(config.families.len(), before - 1);
    assert_eq!(VmConfig::from_bytes(&config.to_bytes()), None);
    let empty = VmConfig {
        families: Vec::new(),
        bytecode_size_words: 1 << 20,
    };
    assert_eq!(VmConfig::from_bytes(&empty.to_bytes()), None);
}

/// The largest config: every family present, which no committed guest derives.
#[test]
fn a_config_of_every_family_round_trips() {
    let all = VmConfig {
        families: program::FAMILIES
            .iter()
            .map(|f| (*f, family::DEFAULT_HEIGHTS[*f as usize]))
            .collect(),
        bytecode_size_words: 1 << 20,
    };
    assert_eq!(VmConfig::from_bytes(&all.to_bytes()), Some(all));
}
