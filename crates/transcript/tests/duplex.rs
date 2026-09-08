//! The duplex and the typed layer, against the committed reference scripts.
//!
//! Every expected value replayed here was produced by `tools/transcript-ref`,
//! which implements `docs/spec/transcript.md` over the Plonky3 permutation and
//! never links this crate.

mod common;

use common::{assert_sha256, case, parse_cases, read_vectors, run_case, tag_by_name, Case, Op};
use constants::transcript_tags as tags;
use field::Fr;
use transcript::{poseidon2_permute, Tag, Transcript, TranscriptEvent};

const CASES_PATH: &str = "tests/vectors/transcript_cases.txt";
const CASES_SHA256: &str = "b81cdd9651ead3c7d0c8b49dc5147d99b7944f95567864766b7592ba24ae7017";

fn load() -> Vec<Case> {
    let text = read_vectors(CASES_PATH);
    assert_sha256(CASES_PATH, &text, CASES_SHA256);
    parse_cases(&text).expect("the committed case file must parse")
}

/// Replay a case and return every value it produced.
fn outputs(cases: &[Case], name: &str) -> Vec<Fr> {
    run_case(case(cases, name)).unwrap_or_else(|e| panic!("case {name} must replay: {e}"))
}

// ---------------------------------------------------------------------------
// Acceptance 3: every committed case replays byte-exact.
// ---------------------------------------------------------------------------

#[test]
fn every_committed_case_replays() {
    let cases = load();

    // The inventory, not just cases A-E: a case silently dropped from the
    // generator would otherwise shrink the coverage of every test below without
    // failing anything.
    let names: Vec<&str> = cases.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "A",
            "B",
            "C",
            "D",
            "E",
            "F_order",
            "G_squeeze",
            "H_three", // absorbs spanning the rate: the sponge duplexes mid-message
            "T1_tag_x",
            "T2_tag_y",
            "T3_run",
            "T4_split",
            "T5_empty_run",
            "Y0_bytes",
            "Y1_bytes",
            "Y30_bytes",
            "Y31_bytes",
            "Y32_bytes",
            "Y62_bytes",
            "Y100_bytes",
            "Y_ab",
            "Y_a_b",
            "S_mixed",
        ]
    );

    for c in &cases {
        run_case(c).unwrap_or_else(|e| panic!("case {} must replay: {e}", c.name));
    }
}

/// The frozen kind of every tag, mirroring `constants::transcript_tags`.
const TAG_KINDS: [(&str, &str); 7] = [
    ("PROTOCOL_SUITE", "scalars"),
    ("PUBLIC_INPUTS", "bytes"),
    ("COMMITMENT", "scalars"),
    ("SUMCHECK_ROUND", "scalars"),
    ("SUMCHECK_CHALLENGE", "challenge"),
    ("EVALUATION_CLAIM", "scalars"),
    ("PCS_OPENING", "scalars"),
];

/// Every tag used in `cases` must be used in the one kind the table gives it.
fn check_tag_kinds(cases: &[Case]) -> Result<(), String> {
    let documented = |tag: Tag| -> Option<&'static str> {
        TAG_KINDS
            .iter()
            .find(|(name, _)| tag_by_name(name).expect("a named tag resolves") == tag)
            .map(|(_, kind)| *kind)
    };

    for c in cases {
        for op in &c.ops {
            let (tag, used_as) = match op {
                Op::AppendScalar(tag, _) | Op::AppendScalars(tag, _) => (*tag, "scalars"),
                Op::AppendBytes(tag, _) => (*tag, "bytes"),
                Op::Challenge(tag, _) => (*tag, "challenge"),
                Op::Observe(_) | Op::Sample(_) => continue,
            };
            if documented(tag) != Some(used_as) {
                return Err(format!(
                    "case {} uses tag {tag} as {used_as}, against the frozen table",
                    c.name
                ));
            }
        }
    }
    Ok(())
}

/// The framing is injective only if each tag names exactly one kind of message,
/// so the committed cases must not themselves be a counterexample to the rule
/// the protocol rests on.
#[test]
fn every_tag_is_used_in_exactly_one_kind() {
    check_tag_kinds(&load()).expect("the committed cases must respect the tag table");
}

/// Negative control: a tag used in two kinds is caught. Under the plain
/// `tag, length, payload` framing this really does collide —
/// `challenge_scalar(T)` and `append_scalars(T, xs)` can absorb the same stream
/// — which is why the rule is a rule and this checker exists.
#[test]
fn a_tag_used_in_two_kinds_is_caught() {
    let offender = Case {
        name: "synthetic".to_string(),
        ops: vec![
            Op::AppendScalar(tags::PCS_OPENING, Fr::ONE),
            Op::Challenge(tags::PCS_OPENING, Fr::ZERO),
        ],
    };
    assert!(check_tag_kinds(&[offender]).is_err());

    // And the collision it forbids is real, not hypothetical. Under
    // `tag, length, payload` a challenge absorbs one element where a message
    // absorbs a length, so a challenge tag reused as a message tag lets the two
    // framings line up element for element — here the run's declared length, 3,
    // is exactly what the other reading takes for the COMMITMENT tag.
    let x = Fr::from_u64(4);
    let y = Fr::from_u64(9);

    let mut a = Transcript::new();
    a.append_scalar(tags::PCS_OPENING, x); //                     P, 1, x
    let _ = a.challenge_scalar(tags::PCS_OPENING); //             P
    a.append_scalar(tags::COMMITMENT, y); //                      C, 1, y
    let from_a = a.challenge_scalar(tags::SUMCHECK_CHALLENGE); // S

    let mut b = Transcript::new();
    b.append_scalar(tags::PCS_OPENING, x); //                     P, 1, x
    b.append_scalars(
        tags::PCS_OPENING,
        // P, 3, then the run — and 3 is the COMMITMENT tag.
        &[Fr::from_u64(1), y, Fr::from_u64(tags::SUMCHECK_CHALLENGE)],
    );
    let from_b = b.sample();

    assert_eq!(
        from_a, from_b,
        "the collision the tag rule forbids must be the real one"
    );
}

/// Acceptance 4: absorb-length framing keeps one zero apart from two.
#[test]
fn case_d_differs_from_case_e() {
    let cases = load();
    assert_ne!(outputs(&cases, "D")[0], outputs(&cases, "E")[0]);
}

/// Acceptance 5: after one absorb, the first challenge is `state[1]` and the
/// second is `state[0]` — challenges leave the rate from the end.
#[test]
fn samples_leave_the_rate_from_the_end() {
    let cases = load();
    let got = outputs(&cases, "F_order");
    assert_eq!(got.len(), 2);

    // `observe(7)` then `sample` absorbs one element: lane 0 takes 7, lane 1 is
    // zero-filled, and the capacity takes the absorbed length 1.
    let mut state = [Fr::from_u64(7), Fr::ZERO, Fr::from_u64(1)];
    poseidon2_permute(&mut state);
    assert_eq!(got[0], state[1]);
    assert_eq!(got[1], state[0]);
}

/// Acceptance 6: observing invalidates buffered output, so sampling between two
/// absorbs is not the same as absorbing both and then sampling twice.
#[test]
fn observing_after_sampling_invalidates_the_output() {
    let cases = load();
    let split = outputs(&cases, "C"); // observe 1, sample, observe 2, sample
    let together = outputs(&cases, "B"); // observe 1, observe 2, sample, sample
    assert_eq!(split.len(), 2);
    assert_eq!(together.len(), 2);
    assert_ne!(split, together);
    // The second challenge is the one that must move: both transcripts have
    // absorbed 1 by the time the first is drawn in case C.
    assert_ne!(split[1], together[1]);
}

/// Acceptance 7: a third sample with nothing absorbed since permutes again,
/// rather than handing back a stale lane.
#[test]
fn repeated_squeezing_permutes_again() {
    let cases = load();
    let got = outputs(&cases, "G_squeeze");
    assert_eq!(got.len(), 4);

    // First duplex step: absorb 3, zero-fill lane 1, capacity 1.
    let mut first = [Fr::from_u64(3), Fr::ZERO, Fr::from_u64(1)];
    poseidon2_permute(&mut first);
    assert_eq!(got[0], first[1]);
    assert_eq!(got[1], first[0]);

    // Third sample: nothing pending, so the rate is left alone, no length is
    // added, and the state is simply permuted again.
    let mut second = first;
    poseidon2_permute(&mut second);
    assert_eq!(got[2], second[1]);
    assert_eq!(got[3], second[0]);

    let distinct: std::collections::BTreeSet<[u8; 32]> = got.iter().map(|x| x.to_bytes()).collect();
    assert_eq!(distinct.len(), 4, "four squeezes, four distinct values");
}

// ---------------------------------------------------------------------------
// Acceptance 8: the typed layer separates tags and frames messages.
// ---------------------------------------------------------------------------

#[test]
fn typed_layer_separates_tags_and_messages() {
    let cases = load();

    // Same value, same challenge tag, different message tag.
    assert_ne!(outputs(&cases, "T1_tag_x"), outputs(&cases, "T2_tag_y"));

    // One run of two scalars is not two runs of one: the length is framed.
    assert_ne!(outputs(&cases, "T3_run"), outputs(&cases, "T4_split"));

    // An empty run is still a message.
    assert_ne!(outputs(&cases, "T5_empty_run"), outputs(&cases, "T3_run"));
    assert_ne!(outputs(&cases, "T5_empty_run"), outputs(&cases, "T1_tag_x"));
}

/// `append_scalar` is exactly `append_scalars` with one element, and the typed
/// layer really is the documented `tag, length, payload` framing over the raw
/// duplex.
#[test]
fn typed_layer_is_the_documented_framing() {
    let x = Fr::from_u64(1234);

    let mut typed = Transcript::new();
    typed.append_scalar(tags::COMMITMENT, x);
    let a = typed.challenge_scalar(tags::SUMCHECK_CHALLENGE);

    let mut run = Transcript::new();
    run.append_scalars(tags::COMMITMENT, &[x]);
    let b = run.challenge_scalar(tags::SUMCHECK_CHALLENGE);
    assert_eq!(a, b, "append_scalar is append_scalars of one element");

    let mut raw = Transcript::new();
    raw.observe(Fr::from_u64(tags::COMMITMENT));
    raw.observe(Fr::from_u64(1));
    raw.observe(x);
    raw.observe(Fr::from_u64(tags::SUMCHECK_CHALLENGE));
    let c = raw.sample();
    assert_eq!(
        a, c,
        "the typed layer is tag, length, payload over the duplex"
    );
}

// ---------------------------------------------------------------------------
// Acceptance 9: the byte encoding.
// ---------------------------------------------------------------------------

/// The committed cases cover empty, 1, 30, 31, 32, 62 and 100 bytes — both
/// sides of every 31-byte chunk boundary. Replay is covered by
/// `every_committed_case_replays`; this pins the boundary list itself.
#[test]
fn byte_cases_cover_the_chunk_boundaries() {
    let cases = load();
    for n in [0usize, 1, 30, 31, 32, 62, 100] {
        let name = format!("Y{n}_bytes");
        let c = case(&cases, &name);
        let lengths: Vec<usize> = c
            .ops
            .iter()
            .filter_map(|op| match op {
                Op::AppendBytes(_, b) => Some(b.len()),
                _ => None,
            })
            .collect();
        assert_eq!(
            lengths,
            vec![n],
            "case {name} must absorb exactly {n} bytes"
        );
    }
}

/// The length prefix is what keeps `"ab"` apart from `"a"` then `"b"`.
#[test]
fn byte_length_prefix_separates_split_absorbs() {
    let cases = load();
    assert_ne!(outputs(&cases, "Y_ab"), outputs(&cases, "Y_a_b"));
}

/// A message's trailing chunk is zero-padded, so the byte length — not the
/// chunk count — is what makes the encoding injective.
#[test]
fn trailing_zero_bytes_are_distinguished() {
    let a = challenge_over_bytes(&[1, 2, 3]);
    let b = challenge_over_bytes(&[1, 2, 3, 0]);
    assert_ne!(a, b, "a trailing zero byte must change the transcript");
}

fn challenge_over_bytes(bytes: &[u8]) -> Fr {
    let mut t = Transcript::new();
    t.append_bytes(tags::PUBLIC_INPUTS, bytes);
    t.challenge_scalar(tags::SUMCHECK_CHALLENGE)
}

// ---------------------------------------------------------------------------
// The event log.
// ---------------------------------------------------------------------------

#[test]
fn event_log_records_typed_operations_only() {
    let mut t = Transcript::new();
    t.observe(Fr::from_u64(9));
    let _ = t.sample();
    assert!(
        t.event_log().is_empty(),
        "the raw duplex is not a typed operation"
    );

    t.append_scalar(tags::COMMITMENT, Fr::from_u64(1));
    t.append_scalars(tags::EVALUATION_CLAIM, &[Fr::ZERO, Fr::ONE, Fr::ZERO]);
    t.append_bytes(tags::PUBLIC_INPUTS, &[7u8; 32]);
    t.append_bytes(tags::PUBLIC_INPUTS, &[]);
    let _ = t.challenge_scalar(tags::SUMCHECK_CHALLENGE);

    assert_eq!(
        t.event_log(),
        [
            TranscriptEvent::Absorb {
                tag: tags::COMMITMENT,
                n_scalars: 1
            },
            TranscriptEvent::Absorb {
                tag: tags::EVALUATION_CLAIM,
                n_scalars: 3
            },
            // 32 bytes is two 31-byte chunks.
            TranscriptEvent::Absorb {
                tag: tags::PUBLIC_INPUTS,
                n_scalars: 2
            },
            TranscriptEvent::Absorb {
                tag: tags::PUBLIC_INPUTS,
                n_scalars: 0
            },
            TranscriptEvent::Challenge {
                tag: tags::SUMCHECK_CHALLENGE
            },
        ]
    );
}

/// The log is metadata: reading it cannot change a challenge, and two
/// transcripts that ran the same script agree whether or not it was read.
#[test]
fn event_log_does_not_affect_challenges() {
    let mut a = Transcript::new();
    let mut b = Transcript::new();
    for t in [&mut a, &mut b] {
        t.append_scalar(tags::COMMITMENT, Fr::from_u64(5));
    }
    let _ = a.event_log();
    assert_eq!(
        a.challenge_scalar(tags::SUMCHECK_CHALLENGE),
        b.challenge_scalar(tags::SUMCHECK_CHALLENGE)
    );
}

// ---------------------------------------------------------------------------
// Tag table
// ---------------------------------------------------------------------------

/// The tags are distinct, nonzero, and every name the vector file uses resolves.
#[test]
fn tag_table_is_well_formed() {
    let names = [
        "PROTOCOL_SUITE",
        "PUBLIC_INPUTS",
        "COMMITMENT",
        "SUMCHECK_ROUND",
        "SUMCHECK_CHALLENGE",
        "EVALUATION_CLAIM",
        "PCS_OPENING",
        "WITNESS_DIGEST",
        "SUMCHECK_FINAL_EVALS",
    ];
    let values: Vec<u64> = names
        .iter()
        .map(|n| tag_by_name(n).expect("every named tag resolves"))
        .collect();
    let mut sorted = values.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len(), "tag values must be distinct");
    assert!(values.iter().all(|v| *v != 0), "0 is not a tag");
}

// ---------------------------------------------------------------------------
// Acceptance 11 and friends: negative controls.
// ---------------------------------------------------------------------------

/// Replay a case file from text, so a corrupted copy can be fed in.
fn replay_all(text: &str) -> Result<(), String> {
    for c in parse_cases(text)? {
        run_case(&c)?;
    }
    Ok(())
}

/// Acceptance 11: one flipped bit in case C's committed vector fails the replay.
#[test]
fn a_flipped_bit_in_case_c_fails() {
    let text = read_vectors(CASES_PATH);

    let mut corrupted = String::new();
    let mut done = false;
    let mut in_case_c = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("case ") {
            in_case_c = trimmed == "case C";
        }
        if in_case_c && !done && trimmed.starts_with("sample ") {
            let value = trimmed.trim_start_matches("sample ");
            let head = value.chars().next().expect("a sample has a value");
            let flipped = head.to_digit(16).expect("hex nibble") ^ 1;
            corrupted.push_str(&format!("  sample {flipped:x}{}\n", &value[1..]));
            done = true;
            continue;
        }
        corrupted.push_str(line);
        corrupted.push('\n');
    }
    assert!(done, "case C must contain a sample line");
    assert!(
        replay_all(&corrupted).is_err(),
        "a flipped bit in case C must fail the replay"
    );
}

#[test]
fn malformed_case_files_are_rejected() {
    let text = read_vectors(CASES_PATH);

    // An unknown operation.
    assert!(replay_all(&text.replace("  observe ", "  absorb ")).is_err());

    // An unknown tag name.
    assert!(replay_all(&text.replace(" COMMITMENT ", " COMMITMENTS ")).is_err());

    // A truncated line: `sample` with no expected value.
    assert!(replay_all(&text.replace(
        "case A\n  observe 0100000000000000000000000000000000000000000000000000000000000000\n  sample ",
        "case A\n  observe 0100000000000000000000000000000000000000000000000000000000000000\n  sample\n#"
    ))
    .is_err());

    // A run whose declared length does not match its payload.
    assert!(replay_all(&text.replace(
        "  append_scalars COMMITMENT 2 ",
        "  append_scalars COMMITMENT 3 "
    ))
    .is_err());

    // A byte message whose declared length does not match its payload.
    assert!(replay_all(&text.replace(
        "  append_bytes PUBLIC_INPUTS 2 6162",
        "  append_bytes PUBLIC_INPUTS 3 6162"
    ))
    .is_err());

    // A case that never ends.
    assert!(replay_all(&text.replacen("end\n", "\n", 1)).is_err());

    // An operation outside any case.
    assert!(replay_all(
        "observe 0100000000000000000000000000000000000000000000000000000000000000\n"
    )
    .is_err());
}
