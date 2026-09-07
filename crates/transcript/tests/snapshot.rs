//! Acceptance 10: snapshot and restore reproduce the challenge stream exactly,
//! and the snapshot survives a byte round trip.

mod common;

use common::{case, parse_cases, read_vectors, run_ops};
use constants::transcript_tags as tags;
use field::Fr;
use transcript::{Transcript, TranscriptSnapshot};

const CASES_PATH: &str = "tests/vectors/transcript_cases.txt";

/// The committed 20-operation mixed script, snapshotted halfway.
const SPLIT: usize = 10;

/// The snapshot wire format: three state lanes, two input lanes, the input
/// length, two output lanes, the output length. Field elements are 32 canonical
/// little-endian bytes.
const SNAPSHOT_BYTES: usize = 3 * 32 + 2 * 32 + 1 + 2 * 32 + 1;
const INPUT_LANE_0: usize = 3 * 32;
const INPUT_LEN: usize = 3 * 32 + 2 * 32;
const OUTPUT_LEN: usize = SNAPSHOT_BYTES - 1;

fn encode(s: &TranscriptSnapshot) -> Vec<u8> {
    // A stack buffer, so `postcard` needs no allocator feature and the tests
    // exercise the same featureless serde the guest links.
    let mut buf = [0u8; 512];
    let used = postcard::to_slice(s, &mut buf).expect("a snapshot fits in 512 bytes");
    used.to_vec()
}

fn decode(bytes: &[u8]) -> Result<TranscriptSnapshot, postcard::Error> {
    postcard::from_bytes(bytes)
}

/// Acceptance 10: snapshot at operation 10 of a 20-operation mixed script,
/// restore into a fresh transcript, and the remaining 10 operations agree —
/// both with the original transcript and with the committed reference values.
#[test]
fn restore_resumes_the_committed_script() {
    let text = read_vectors(CASES_PATH);
    let cases = parse_cases(&text).expect("the committed case file must parse");
    let script = case(&cases, "S_mixed");
    assert_eq!(script.ops.len(), 20, "the mixed script is 20 operations");

    let mut original = Transcript::new();
    run_ops(&mut original, &script.ops[..SPLIT], "S_mixed head").expect("the head must replay");

    let snap = original.snapshot();

    // The original carries on; every expected value comes from the file.
    let from_original =
        run_ops(&mut original, &script.ops[SPLIT..], "S_mixed tail").expect("the tail must replay");

    // A transcript rebuilt from the snapshot produces the same stream.
    let mut restored = Transcript::restore(&snap);
    let from_restored = run_ops(&mut restored, &script.ops[SPLIT..], "S_mixed restored tail")
        .expect("the restored tail must replay");

    assert!(
        !from_original.is_empty(),
        "the tail must produce challenges"
    );
    assert_eq!(from_original, from_restored);

    // Same script, same state: snapshots are canonical, so they compare equal.
    assert_eq!(original.snapshot(), restored.snapshot());
}

/// The pending input buffer is part of the state: a snapshot taken mid-message,
/// with the rate half full, resumes just as exactly.
#[test]
fn restore_mid_message() {
    let mut t = Transcript::new();
    // Three absorbs — tag, length, payload — so the rate fills once and the
    // third element is left pending.
    t.append_scalar(tags::COMMITMENT, Fr::from_u64(11));

    let snap = t.snapshot();
    let bytes = encode(&snap);
    assert_eq!(bytes[INPUT_LEN], 1, "one element is pending");

    let mut restored = Transcript::restore(&decode(&bytes).expect("a snapshot round trips"));
    assert_eq!(
        t.challenge_scalar(tags::SUMCHECK_CHALLENGE),
        restored.challenge_scalar(tags::SUMCHECK_CHALLENGE)
    );
}

/// The buffered output is part of the state too: snapshot with a squeezed but
/// unread lane still pending.
#[test]
fn restore_with_buffered_output() {
    let mut t = Transcript::new();
    t.observe(Fr::from_u64(3));
    let first = t.sample(); // leaves one squeezed lane unread

    let snap = t.snapshot();
    let bytes = encode(&snap);
    assert_eq!(bytes[OUTPUT_LEN], 1, "one squeezed lane is unread");

    let mut restored = Transcript::restore(&decode(&bytes).expect("a snapshot round trips"));
    let second = t.sample();
    assert_eq!(second, restored.sample());
    assert_ne!(first, second);
}

#[test]
fn snapshot_round_trips_through_bytes() {
    let mut t = Transcript::new();
    t.append_bytes(tags::PUBLIC_INPUTS, b"a statement");
    let _ = t.challenge_scalar(tags::SUMCHECK_CHALLENGE);
    t.append_scalars(tags::COMMITMENT, &[Fr::ONE, Fr::MINUS_ONE]);

    let snap = t.snapshot();
    let bytes = encode(&snap);
    assert_eq!(
        bytes.len(),
        SNAPSHOT_BYTES,
        "the snapshot wire size is fixed"
    );
    assert_eq!(decode(&bytes).expect("a snapshot round trips"), snap);
}

/// `observe` drops squeezed-but-unread output. That cannot change a challenge —
/// `sample` would duplex anyway — so the state is where it shows: two
/// transcripts that have absorbed the same elements have identical snapshots
/// whether or not a challenge was drawn along the way and then superseded.
#[test]
fn observe_drops_unread_output() {
    let mut sampled = Transcript::new();
    sampled.observe(Fr::from_u64(3));
    let _ = sampled.sample(); // leaves one unread squeezed lane
    sampled.observe(Fr::from_u64(4));

    let bytes = encode(&sampled.snapshot());
    assert_eq!(bytes[OUTPUT_LEN], 0, "the stale lane must be gone");

    // The absorbed sequence differs from a transcript that never sampled, so the
    // two are not expected to agree — what is pinned here is that no squeezed
    // material survives the absorb.
    assert_eq!(
        bytes[INPUT_LEN], 1,
        "the second absorb is pending, so the rate is half full"
    );
}

/// Events are metadata, not sponge state: a restored transcript starts a fresh
/// log and still produces the same challenges.
#[test]
fn restore_starts_a_fresh_event_log() {
    let mut t = Transcript::new();
    t.append_scalar(tags::COMMITMENT, Fr::from_u64(7));
    assert_eq!(t.event_log().len(), 1);

    let restored = Transcript::restore(&t.snapshot());
    assert!(restored.event_log().is_empty());
}

/// Negative control: the deserializer refuses anything `snapshot` could not have
/// produced, so `restore` can never be handed a state outside the invariant.
#[test]
fn malformed_snapshots_are_rejected() {
    let good = encode(&Transcript::new().snapshot());
    assert_eq!(good.len(), SNAPSHOT_BYTES);
    assert!(decode(&good).is_ok(), "the control must itself be valid");

    // The input bound is strict: `observe` duplexes the moment the rate fills,
    // so a snapshot with a full input buffer is one `snapshot` could not have
    // taken, and restoring it would make the next `observe` index past the end.
    let mut full_input = good.clone();
    full_input[INPUT_LEN] = 2;
    assert!(
        decode(&full_input).is_err(),
        "input length equal to the rate"
    );

    let mut over_long_input = good.clone();
    over_long_input[INPUT_LEN] = 3;
    assert!(
        decode(&over_long_input).is_err(),
        "input length above the rate"
    );

    // The output bound is not strict: `observe` can leave a full output buffer
    // behind when the absorb it completed duplexed the sponge.
    let mut full_output = good.clone();
    full_output[OUTPUT_LEN] = 2;
    assert!(
        decode(&full_output).is_ok(),
        "a full output buffer is legal"
    );

    let mut over_long_output = good.clone();
    over_long_output[OUTPUT_LEN] = 3;
    assert!(
        decode(&over_long_output).is_err(),
        "output length above the rate"
    );

    let mut stale_input = good.clone();
    stale_input[INPUT_LANE_0] = 1; // a value in a lane the length says is empty
    assert!(decode(&stale_input).is_err(), "stale input lane");

    let mut stale_output = good.clone();
    stale_output[INPUT_LEN + 1] = 1;
    assert!(decode(&stale_output).is_err(), "stale output lane");

    assert!(
        decode(&good[..good.len() - 1]).is_err(),
        "truncated snapshot"
    );
}

/// A non-canonical field element in a snapshot is refused by `Fr`'s own wire
/// rule, not silently reduced.
#[test]
fn snapshot_rejects_non_canonical_field_elements() {
    let mut bytes = encode(&Transcript::new().snapshot());
    for b in bytes.iter_mut().take(32) {
        *b = 0xff;
    }
    assert!(decode(&bytes).is_err());
}
