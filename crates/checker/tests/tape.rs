//! The transcript-tape validator, S20: the global commit phase's absorb
//! sequence against the frozen pre-fork order of `docs/spec/shard-proof.md`
//! §2, the committed tape of S20's two-shard statement, and the negative
//! control — a fork that swaps two absorptions.
//!
//! The statement here is built **shape only**, with stand-in points: a tape
//! carries tags and payload lengths, never values. It is the same shape
//! `tools/kat-gen/src/tape.rs` writes the fixture from and the same shape
//! `guests/shards` proves, and it is written out again here rather than shared,
//! so a drift between the three fails loudly.

use constants::transcript_tags as tags;
use constants::{family, generic_table};
use constraints::family_circuit;
use field::Fr;
use transcript::{append_g1_points, io_digest, Transcript};
use verifier_core::{
    absorb_statement_descriptor, boundary_scalars, derive_global_phase, global_commit,
    identity_digest, reduce_shard, srs_digest, statement_shards, BoundaryFinals, GkrProof,
    PublicInputs, ShardProof, VerifyError, VerifyingKey, VmConfig, OPENING_BYTES,
    TRIVIAL_TS_WINDOW,
};

const POINT: [u8; 64] = [0; 64];

/// S20's two-shard statement's shape: add/sub in two shards, jump/branch/slt
/// in one, `INIT_TEARDOWN` in one, `ZERO_WINDOWS` in none — and, since S25,
/// the two public value families in one each and `ADVICE_WINDOWS` in none
/// (`docs/spec/public-values.md` §4).
fn key_and_statement() -> (VerifyingKey, PublicInputs) {
    let config = VmConfig {
        families: vec![
            (family::ADD_SUB_LUI_AUIPC, 1 << 20),
            (family::JUMP_BRANCH_SLT, 1 << 20),
            (family::INIT_TEARDOWN, 1 << 16),
            (family::ZERO_WINDOWS, 1 << 16),
            (family::PUBLIC_INPUT, family::PUBLIC_WINDOW_HEIGHT),
            (family::PUBLIC_OUTPUT, family::PUBLIC_WINDOW_HEIGHT),
            (family::ADVICE_WINDOWS, 1 << 16),
        ],
        bytecode_size_words: family::DEFAULT_BYTECODE_SIZE_WORDS,
    };
    let circuits: Vec<_> = config
        .families
        .iter()
        .map(|(f, h)| family_circuit(*f, h.trailing_zeros()).expect("a registered family"))
        .collect();
    let setup: Vec<Vec<[u8; 64]>> = circuits
        .iter()
        .map(|c| {
            let generic = match c.reads_generic_table() {
                true => generic_table::WIDTH,
                false => 0,
            };
            vec![POINT; c.artifact.setup.len() - generic]
        })
        .collect();
    let generic = [POINT; generic_table::WIDTH];
    let srs_verifier = [0u8; 320];
    let entry_pc = 0x1_0000;
    let width = |f: u32| {
        circuits
            .iter()
            .find(|c| c.family == f)
            .expect("a config family")
            .artifact
            .memory
            .len()
    };
    let memory_commitments = vec![
        vec![POINT; width(family::INIT_TEARDOWN)],
        vec![POINT; width(family::ADD_SUB_LUI_AUIPC)],
        vec![POINT; width(family::ADD_SUB_LUI_AUIPC)],
        vec![POINT; width(family::JUMP_BRANCH_SLT)],
        vec![POINT; width(family::PUBLIC_INPUT)],
        vec![POINT; width(family::PUBLIC_OUTPUT)],
    ];
    let mut boundary = BoundaryFinals {
        reg_ts: [0; 32],
        pc_ts: 4,
        reg_values: [0; 31],
    };
    boundary.reg_values[9] = 2;
    let statement = PublicInputs {
        input: Vec::new(),
        output: Vec::new(),
        exit_status: 2,
        shard_counts: vec![2, 1, 1, 0, 1, 1, 0],
        windows: Vec::new(),
        boundary,
        memory_commitments,
        memory_roots: vec![[Fr::ZERO; 2]; 6],
    };
    let vk = VerifyingKey {
        code_version: family::CODE_VERSION,
        entry_pc,
        identity: identity_digest(family::CODE_VERSION, &config, entry_pc, &setup),
        config,
        setup_commitments: setup,
        srs_verifier,
        generic_table: generic,
        srs_digest: srs_digest(&srs_verifier, &generic),
        circuits,
    };
    (vk, statement)
}

/// The committed fixture's lines, comments dropped.
fn fixture() -> Vec<String> {
    let text = include_str!("vectors/global_tape.txt");
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(str::to_string)
        .collect()
}

/// Acceptance 3: the global commit phase's tape is the frozen pre-fork order,
/// item for item, and it is the committed fixture.
#[test]
fn the_global_tape_is_the_frozen_order_and_the_committed_fixture() {
    let (vk, statement) = key_and_statement();
    let lines = checker::check_global_tape(&vk, &statement)
        .expect("the phase keeps the frozen pre-fork order");
    assert_eq!(lines, fixture(), "the tape is the committed fixture");
    // The order, spelled out here a third time, so a change to both the phase
    // and the checker's expectation still has to face this list.
    assert_eq!(
        &lines[..7],
        &[
            "absorb PROTOCOL_SUITE 1",
            "absorb SRS_DIGEST 1",
            "absorb VM_CONFIG 15",
            "absorb SHARD_COUNTS 7",
            "absorb MEMORY_WINDOWS 0",
            "absorb PROGRAM_IDENTITY 1",
            "absorb PUBLIC_INPUTS 2",
        ]
    );
    assert_eq!(
        &lines[lines.len() - 5..],
        &[
            "squeeze MEMORY_CHALLENGE",
            "squeeze MEMORY_CHALLENGE",
            "squeeze MEMORY_CHALLENGE",
            "squeeze MEMORY_CHALLENGE",
            "squeeze GLOBAL_STATE_DIGEST",
        ],
        "no challenge is drawn before the statement is absorbed"
    );
    // G8: a group header per config family, a family with no shards included,
    // then one commitment message per shard, four limbs to a point. Seven
    // families since S25, two of which run no shard here.
    assert_eq!(
        lines
            .iter()
            .filter(|l| *l == "absorb MEMORY_GROUP 2")
            .count(),
        7
    );
    assert_eq!(
        lines
            .iter()
            .filter(|l| l.starts_with("absorb COMMITMENT"))
            .count(),
        6,
        "one message per statement shard"
    );
}

/// The expectation is a function of the statement's shape, not a constant: a
/// changed shard count, window list or commitment width moves both tapes
/// together, and the phase still keeps the order.
#[test]
fn the_expected_tape_follows_the_statement_shape() {
    let (vk, base) = key_and_statement();
    let baseline = checker::expected_global_tape(&vk, &base);

    let mut three = base.clone();
    three.shard_counts[0] = 3;
    three
        .memory_commitments
        .insert(3, three.memory_commitments[1].clone());
    three.memory_roots.push([Fr::ZERO; 2]);
    let grown = checker::expected_global_tape(&vk, &three);
    assert_eq!(grown.len(), baseline.len() + 1, "one more COMMITMENT line");
    assert_eq!(checker::global_tape(&vk, &three), grown);

    let mut windowed = base.clone();
    windowed.shard_counts[3] = 1;
    windowed.windows = vec![7];
    let zero_width = vk
        .circuit(family::ZERO_WINDOWS)
        .expect("a config family")
        .artifact
        .memory
        .len();
    windowed
        .memory_commitments
        .insert(1, vec![POINT; zero_width]);
    windowed.memory_roots.push([Fr::ZERO; 2]);
    let with_window = checker::expected_global_tape(&vk, &windowed);
    assert!(with_window.contains(&"absorb MEMORY_WINDOWS 1".to_string()));
    assert_eq!(checker::global_tape(&vk, &windowed), with_window);
    assert_eq!(
        statement_shards(&vk.config, &windowed.shard_counts)[1],
        (family::ZERO_WINDOWS, 0),
        "the window shard takes second place in statement order"
    );
}

/// The negative control: a fork of the global commit phase that swaps two
/// absorptions. Its tape is not the frozen order, its memory challenges and
/// its digest all differ, and a proof carrying its digest is refused as
/// `Statement`.
///
/// The fork absorbs G7, the public-I/O digest, before G6, the program
/// identity, and is otherwise `verifier_core::global_commit` written out.
fn swapped_global_commit(vk: &VerifyingKey, statement: &PublicInputs) -> Transcript {
    let mut t = Transcript::new();
    t.append_scalar(
        tags::PROTOCOL_SUITE,
        Fr::from_u64(constants::PROTOCOL_VERSION as u64),
    );
    t.append_scalar(tags::SRS_DIGEST, vk.srs_digest);
    absorb_statement_descriptor(
        &mut t,
        &vk.config,
        &statement.shard_counts,
        &statement.windows,
    );
    // The swap: G7 then G6, where the frozen order is G6 then G7.
    let io = io_digest(&statement.input, &statement.output);
    t.append_bytes(tags::PUBLIC_INPUTS, &io.to_bytes());
    t.append_scalar(tags::PROGRAM_IDENTITY, vk.identity.0);

    let mut lists = statement.memory_commitments.iter();
    let ids = || vk.config.families.iter().map(|(f, _)| *f);
    let order = ids()
        .filter(|f| *f == family::INIT_TEARDOWN)
        .chain(ids().filter(|f| *f == family::ZERO_WINDOWS))
        .chain(ids().filter(|f| *f != family::INIT_TEARDOWN && *f != family::ZERO_WINDOWS));
    let shards = statement_shards(&vk.config, &statement.shard_counts);
    for f in order {
        let count = shards.iter().filter(|(g, _)| *g == f).count();
        t.append_scalars(
            tags::MEMORY_GROUP,
            &[Fr::from_u64(f as u64), Fr::from_u64(count as u64)],
        );
        for _ in 0..count {
            append_g1_points(&mut t, tags::COMMITMENT, lists.next().expect("a list"));
        }
    }
    t.append_scalars(
        tags::MEMORY_BOUNDARY,
        &boundary_scalars(&statement.boundary),
    );
    t
}

#[test]
fn swapping_two_absorptions_is_caught_and_changes_every_challenge() {
    let (vk, statement) = key_and_statement();
    let honest = global_commit(&vk, &statement);

    let mut forked = swapped_global_commit(&vk, &statement);
    let mut memory = [Fr::ZERO; 4];
    for slot in memory.iter_mut() {
        *slot = forked.challenge_scalar(tags::MEMORY_CHALLENGE);
    }
    let digest = forked.challenge_scalar(tags::GLOBAL_STATE_DIGEST);

    // 1. The tape names the first line at which it left the order.
    let forked_tape = checker::tape(forked.event_log());
    let expected = checker::expected_global_tape(&vk, &statement);
    let first = forked_tape
        .iter()
        .zip(&expected)
        .position(|(a, b)| a != b)
        .expect("the swap shows in the tape");
    assert_eq!(forked_tape[first], "absorb PUBLIC_INPUTS 2");
    assert_eq!(expected[first], "absorb PROGRAM_IDENTITY 1");
    assert_eq!(forked_tape.len(), expected.len(), "only the order moved");

    // 2. Every challenge the statement fixes moves with it.
    for (i, (fork, real)) in memory.iter().zip(&honest.memory).enumerate() {
        assert_ne!(fork, real, "memory challenge {i}");
    }
    assert_ne!(digest, honest.digest);

    // 3. A proof made under the forked phase is refused as `Statement`, at
    //    step 5, which is the check that binds a proof to its statement.
    let proof = ShardProof {
        family: family::ADD_SUB_LUI_AUIPC,
        shard_index: 0,
        ts_window: TRIVIAL_TS_WINDOW,
        global_digest: digest,
        witness_commitments: Vec::new(),
        outputs: Vec::new(),
        gkr: GkrProof { layers: vec![] },
        opening: [0; OPENING_BYTES],
    };
    assert_eq!(
        reduce_shard(&vk, &proof, &statement).err(),
        Some(VerifyError::Statement(
            "the proof was made for another statement"
        ))
    );
    // The honest digest gets past step 5 and is refused later, on its shape:
    // the fork is what step 5 catches, and nothing else here.
    let mut honest_proof = proof.clone();
    honest_proof.global_digest = honest.digest;
    assert!(matches!(
        reduce_shard(&vk, &honest_proof, &statement).err(),
        Some(VerifyError::Malformed(_))
    ));
}

/// The `checker tape` verb, from files: it prints the tape on a key and a
/// statement that agree, and exits 1 rather than panicking on one that does
/// not — `global_commit`'s contract is that its caller checked first, and the
/// CLI is that caller.
#[test]
fn the_tape_verb_reads_a_key_and_a_statement_from_files() {
    use std::process::Command;

    let (vk, statement) = key_and_statement();
    let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("s20-tape-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("the test directory");
    let write = |name: &str, bytes: &[u8]| {
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("writing a file");
        path
    };
    let key = write("shape.vk", &vk.to_bytes());
    let public = write("shape.public", &statement.to_bytes());
    let run = |args: [&std::path::Path; 2]| {
        Command::new(env!("CARGO_BIN_EXE_checker"))
            .arg("tape")
            .args(args)
            .output()
            .expect("running checker")
    };

    let out = run([&key, &public]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        text.lines().map(str::to_string).collect::<Vec<_>>(),
        fixture(),
        "the verb prints the committed tape"
    );

    // A statement the key does not describe: exit 1 with the reason, never a
    // panic inside the global commit phase.
    let mut short = statement.clone();
    short.shard_counts.pop();
    let bad = write("short.public", &short.to_bytes());
    let out = run([&key, &bad]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not one shard count per config family"),
        "{stderr}"
    );
    assert!(!stderr.contains("panicked"), "{stderr}");

    // And one whose commitment lists do not match its counts.
    let mut lists = statement.clone();
    lists.memory_commitments.pop();
    let bad = write("lists.public", &lists.to_bytes());
    let out = run([&key, &bad]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not one commitment list per shard"),
        "{stderr}"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// The validator is a check on the *script*, and says so: a statement whose
/// values all change keeps the same tape, while the digest does not.
#[test]
fn the_tape_is_the_script_and_not_the_values() {
    let (vk, statement) = key_and_statement();
    let mut other = statement.clone();
    for list in other.memory_commitments.iter_mut() {
        for point in list.iter_mut() {
            point[0] = 9;
        }
    }
    other.boundary.pc_ts = 400;
    assert_eq!(
        checker::global_tape(&vk, &other),
        checker::global_tape(&vk, &statement)
    );
    let moved = derive_global_phase(&vk, &other).expect("a statement the key describes");
    let base = derive_global_phase(&vk, &statement).expect("a statement the key describes");
    assert_ne!(moved.digest, base.digest);
    assert_ne!(moved.memory, base.memory);
}
