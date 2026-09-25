//! The frozen wire forms — `VmConfig` and `ProgramIdentity` — the statement
//! descriptor, and the RAM window rules of `docs/spec/memory.md` §3.

mod common;

use constants::{family, transcript_tags as tags};
use field::Fr;
use program::{
    absorb_statement_descriptor, check_memory_windows, decode_program, decode_program_detaching,
    ProgramError, ProgramIdentity, ProgramParams, VmConfig,
};
use transcript::{Transcript, TranscriptEvent};

fn fib_config() -> VmConfig {
    decode_program(&common::guest("fib"), &ProgramParams::defaults())
        .unwrap()
        .1
}

/// `config` with the heights of `families` set to `height`.
fn with_height(config: &VmConfig, families: &[u32], height: u32) -> VmConfig {
    let mut config = config.clone();
    for (f, h) in config.families.iter_mut() {
        if families.contains(f) {
            *h = height;
        }
    }
    config
}

/// The wire form, written out byte for byte from its definition, and read
/// back.
#[test]
fn the_vm_config_wire_form_is_frozen_and_round_trips() {
    let config = fib_config();
    // Eleven families since S25b, not eight: `fib` reads fd 0 and commits to
    // fd 1, so it computes `io_digest` at exit (`docs/spec/memory.md` §10) and
    // the guest-target backends route Poseidon2 and `Fr`'s arithmetic through
    // their delegations. Declaring a delegation is what puts it in the config
    // (`docs/spec/delegation.md` §7), at its own `2^8` height. The eleventh is
    // `ADVICE_WINDOWS`, which is in every config whatever the program and
    // proves nothing here (`docs/spec/advice.md` §5).
    let mut want: Vec<u32> = vec![11];
    for (f, h) in [
        (family::ADD_SUB_LUI_AUIPC, 1 << 22),
        (family::JUMP_BRANCH_SLT, 1 << 22),
        (family::SHIFT_BITWISE, 1 << 22),
        (family::MUL_DIV, 1 << 20),
        (family::MEM_WORD, 1 << 22),
        (family::MEM_SUBWORD, 1 << 22),
        (family::INIT_TEARDOWN, 1 << 22),
        (family::ZERO_WINDOWS, 1 << 22),
        (family::POSEIDON2, 1 << 8),
        (family::FR_ARITH, 1 << 8),
        (family::ADVICE_WINDOWS, 1 << 22),
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
    word(&mut unknown, 15, family::COUNT); // the last family id
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

/// The statement descriptor is three adjacent typed messages: the `VmConfig`
/// under `VM_CONFIG`, one shard count per family under `SHARD_COUNTS`, and the
/// RAM window list under `MEMORY_WINDOWS`.
#[test]
fn the_statement_descriptor_is_three_adjacent_messages() {
    let config = fib_config();
    // Eleven families since S25b; see the wire-form test above.
    let counts = [3, 1, 1, 0, 2, 1, 1, 1, 1, 1, 0];
    let windows = [127];

    let mut tr = Transcript::new();
    absorb_statement_descriptor(&mut tr, &config, &counts, &windows);
    assert_eq!(
        tr.event_log(),
        &[
            TranscriptEvent::Absorb {
                tag: tags::VM_CONFIG,
                n_scalars: 2 * 11 + 1,
            },
            TranscriptEvent::Absorb {
                tag: tags::SHARD_COUNTS,
                n_scalars: 11,
            },
            TranscriptEvent::Absorb {
                tag: tags::MEMORY_WINDOWS,
                n_scalars: 1,
            },
        ]
    );

    // The same three messages, written out from the definition.
    let fr = |x: u32| Fr::from_u64(x as u64);
    let mut vm: Vec<Fr> = config.families.iter().map(|(f, _)| fr(*f)).collect();
    vm.extend(config.families.iter().map(|(_, h)| fr(*h)));
    vm.push(fr(config.bytecode_size_words));
    let mut replay = Transcript::new();
    replay.append_scalars(tags::VM_CONFIG, &vm);
    replay.append_scalars(tags::SHARD_COUNTS, &counts.map(fr));
    replay.append_scalars(tags::MEMORY_WINDOWS, &windows.map(fr));
    assert_eq!(tr.snapshot(), replay.snapshot());

    // Shard counts are per proof: changing one moves the sponge.
    let mut other = Transcript::new();
    absorb_statement_descriptor(
        &mut other,
        &config,
        &[3, 1, 1, 0, 2, 1, 1, 2, 1, 1, 0],
        &windows,
    );
    assert_ne!(tr.snapshot(), other.snapshot());

    // So is the window list: one id differs.
    let mut moved = Transcript::new();
    absorb_statement_descriptor(&mut moved, &config, &counts, &[126]);
    assert_ne!(tr.snapshot(), moved.snapshot());

    // An execution touching no window above 0 still absorbs the message, empty.
    let mut empty = Transcript::new();
    absorb_statement_descriptor(&mut empty, &config, &[3, 1, 1, 0, 2, 1, 1, 0, 1, 1, 0], &[]);
    assert_eq!(
        empty.event_log()[2],
        TranscriptEvent::Absorb {
            tag: tags::MEMORY_WINDOWS,
            n_scalars: 0,
        }
    );
}

#[test]
#[should_panic(expected = "one shard count per family")]
fn the_descriptor_needs_one_shard_count_per_family() {
    absorb_statement_descriptor(&mut Transcript::new(), &fib_config(), &[1, 2], &[]);
}

/// Derivation puts `INIT_TEARDOWN` and `ZERO_WINDOWS` in every config at one
/// height, so derivation refuses to produce a config without either or with
/// the two apart, and the wire form refuses to read one — the empty config
/// included. Presence is what is checked, not position: delegation families
/// are appended above both ids.
#[test]
fn a_config_without_both_init_families_at_one_height_is_refused() {
    let image = common::guest("fib");
    let missing = ProgramError::WindowRule {
        rule: "INIT_TEARDOWN and ZERO_WINDOWS are in every VmConfig",
    };
    let apart = ProgramError::WindowRule {
        rule: "INIT_TEARDOWN and ZERO_WINDOWS have one height",
    };
    for init in [family::INIT_TEARDOWN, family::ZERO_WINDOWS] {
        let err = decode_program_detaching(&image, &ProgramParams::defaults(), &[init]);
        assert_eq!(err.unwrap_err(), missing, "{init} detached");
        let mut config = fib_config();
        config.families.retain(|(f, _)| *f != init);
        assert_eq!(config.families.len(), 10);
        assert_eq!(
            VmConfig::from_bytes(&config.to_bytes()),
            None,
            "{init} missing"
        );

        let mut params = ProgramParams::defaults();
        params.heights[init as usize] = 1 << 20;
        assert_eq!(
            decode_program(&image, &params).unwrap_err(),
            apart,
            "{init} lowered"
        );
        let config = with_height(&fib_config(), &[init], 1 << 20);
        assert_eq!(
            VmConfig::from_bytes(&config.to_bytes()),
            None,
            "{init} lowered"
        );
    }
    let empty = VmConfig {
        families: Vec::new(),
        bytecode_size_words: 1 << 20,
    };
    assert_eq!(VmConfig::from_bytes(&empty.to_bytes()), None);

    // Just inside: both lowered together derives, and reads back.
    let mut params = ProgramParams::defaults();
    params.heights[family::INIT_TEARDOWN as usize] = 1 << 20;
    params.heights[family::ZERO_WINDOWS as usize] = 1 << 20;
    let (_, config) = decode_program(&image, &params).unwrap();
    assert_eq!(VmConfig::from_bytes(&config.to_bytes()), Some(config));
}

/// `docs/spec/memory.md` §3.5, rule by rule, each refused at its boundary and
/// accepted just inside it. fib at the defaults has both init families at
/// 2^22 rows, so there are `2^29 / 2^22 = 128` windows and ids run 1 to 127.
#[test]
fn the_window_rules_hold_at_their_boundaries() {
    let config = fib_config();
    // One shard for each instruction family, then INIT_TEARDOWN's and
    // ZERO_WINDOWS', then one for each of the two delegation families S25's
    // exit-time `io_digest` brings in, then `ADVICE_WINDOWS`', which this
    // program has none of.
    let counts = |init: u32, zero: u32, advice: u32| [1, 1, 1, 1, 1, 1, init, zero, 1, 1, advice];
    let check =
        |counts: [u32; 11], windows: &[u32]| check_memory_windows(&config, &counts, windows);
    let refused = |rule| Err(ProgramError::WindowRule { rule });

    assert_eq!(check(counts(1, 0, 0), &[]), Ok(()), "no window above 0");
    assert_eq!(check(counts(1, 1, 0), &[127]), Ok(()));

    let one = "INIT_TEARDOWN proves exactly one shard";
    assert_eq!(check(counts(0, 1, 0), &[127]), refused(one));
    assert_eq!(check(counts(2, 1, 0), &[127]), refused(one));

    let length = "the window list has one id per ZERO_WINDOWS shard";
    assert_eq!(check(counts(1, 2, 0), &[127]), refused(length));
    assert_eq!(check(counts(1, 0, 0), &[127]), refused(length));
    assert_eq!(check(counts(1, 1, 0), &[]), refused(length));
    assert_eq!(check(counts(1, 2, 0), &[1, 127]), Ok(()));

    let increasing = "the window ids are strictly increasing";
    assert_eq!(check(counts(1, 2, 0), &[5, 5]), refused(increasing));
    assert_eq!(check(counts(1, 2, 0), &[6, 5]), refused(increasing));
    assert_eq!(check(counts(1, 2, 0), &[5, 6]), Ok(()));

    let range = "every window id is in [1, 2^29 / h - 1]";
    assert_eq!(check(counts(1, 1, 0), &[0]), refused(range));
    assert_eq!(check(counts(1, 1, 0), &[1]), Ok(()));
    assert_eq!(check(counts(1, 1, 0), &[128]), refused(range));
    assert_eq!(check(counts(1, 2, 0), &[0, 1]), refused(range));
    assert_eq!(check(counts(1, 2, 0), &[126, 128]), refused(range));

    // At 2^16 rows there are 8,192 windows.
    let short = with_height(
        &config,
        &[family::INIT_TEARDOWN, family::ZERO_WINDOWS],
        1 << 16,
    );
    assert_eq!(
        check_memory_windows(&short, &counts(1, 1, 0), &[8191]),
        Ok(())
    );
    assert_eq!(
        check_memory_windows(&short, &counts(1, 1, 0), &[8192]),
        refused(range)
    );

    // The config's own rule: the two init families present, at one height.
    let apart = with_height(&config, &[family::ZERO_WINDOWS], 1 << 16);
    assert_eq!(
        check_memory_windows(&apart, &counts(1, 0, 0), &[]),
        refused("INIT_TEARDOWN and ZERO_WINDOWS have one height")
    );
    let mut missing = config.clone();
    missing.families.retain(|(f, _)| *f != family::ZERO_WINDOWS);
    assert_eq!(
        check_memory_windows(&missing, &[1, 1, 1, 1, 1, 1, 1, 1, 1, 0], &[]),
        refused("INIT_TEARDOWN and ZERO_WINDOWS are in every VmConfig")
    );

    // `ADVICE_WINDOWS`' two rules (`docs/spec/advice.md` §5 and §6). Its
    // windows are contiguous from 0, so there is no id list and nothing to
    // order — the whole rule is the extent. The region is `2^31` bytes, which
    // at this config's `2^22` advice height is `2^29 / 2^22 = 128` windows of
    // `4a`; unlike RAM's ids the count is 0-based and 128 tiles the region
    // exactly, so the boundary is `<= n` and not `< n`.
    let extent = "the advice windows fit the advice region";
    assert_eq!(check(counts(1, 0, 0), &[]), Ok(()), "no advice at all");
    assert_eq!(check(counts(1, 0, 128), &[]), Ok(()), "the whole region");
    assert_eq!(check(counts(1, 0, 129), &[]), refused(extent));

    // And the ceiling is stated in **advice's own** height, which is why that
    // family is not held to the RAM families'. At `2^16` there are 8,192.
    let small = with_height(&config, &[family::ADVICE_WINDOWS], 1 << 16);
    assert_eq!(
        check_memory_windows(&small, &counts(1, 0, 8192), &[]),
        Ok(()),
        "a height of its own moves its ceiling and nothing else"
    );
    assert_eq!(
        check_memory_windows(&small, &counts(1, 0, 8193), &[]),
        refused(extent)
    );

    // Presence is a statement rule and not a decoding one: a config without
    // the family is refused here, where the shard counts are.
    let mut no_advice = config.clone();
    no_advice
        .families
        .retain(|(f, _)| *f != family::ADVICE_WINDOWS);
    assert_eq!(
        check_memory_windows(&no_advice, &[1, 1, 1, 1, 1, 1, 1, 0, 1, 1], &[]),
        refused("ADVICE_WINDOWS is in every VmConfig")
    );
}
