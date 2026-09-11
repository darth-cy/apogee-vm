//! The trace archive over real runs: acceptance 7 (round trip, determinism,
//! answering without re-execution) and acceptance 8 (the five phases).
//! `crates/trace/src/archive.rs` holds the refusals that need a hand-built
//! archive.

mod common;

use common::{traced, Traced};
use test_support::{sha256, to_hex};
use trace::{Phase, PhaseTiming, TraceArchive, PHASES};
use transcript::io_digest;

fn archive_of(t: &Traced, wall_nanos: u64) -> TraceArchive {
    TraceArchive::from_execution(
        t.traces.clone(),
        t.log.clone(),
        t.profile.clone(),
        t.execution.io.clone(),
        PhaseTiming { wall_nanos },
    )
}

fn export(archive: &TraceArchive) -> Vec<u8> {
    let mut bytes = Vec::new();
    archive.export(&mut bytes).expect("exporting into memory");
    bytes
}

/// Acceptance 7: export, import, export is byte-identical.
#[test]
fn an_archive_round_trips_byte_for_byte() {
    for name in ["fib", "heap", "opcodes"] {
        let archive = archive_of(&traced(name), 1234);
        let bytes = export(&archive);
        let back = TraceArchive::import(&bytes[..]).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(back, archive, "{name}");
        assert_eq!(
            to_hex(&sha256(&export(&back))),
            to_hex(&sha256(&bytes)),
            "{name}"
        );
    }
}

/// ... two independent runs have hash-equal deterministic payloads whatever
/// their timings, and the payload is the file's prefix, so the timing is
/// outside it by construction.
#[test]
fn two_runs_have_hash_equal_payloads() {
    let first = archive_of(&traced("heap"), 11);
    let second = archive_of(&traced("heap"), 22);
    let (a, b) = (
        first.deterministic_payload(),
        second.deterministic_payload(),
    );
    assert_eq!(to_hex(&sha256(&a)), to_hex(&sha256(&b)));
    let (file_a, file_b) = (export(&first), export(&second));
    assert_ne!(file_a, file_b, "the timings differ, so the files do");
    assert!(file_a.starts_with(&a) && file_b.starts_with(&b));
    assert_eq!(file_a[a.len()..].len(), file_b[b.len()..].len());
}

/// ... and an imported archive yields the cycle count, the per-family
/// occupancy and the fd 0/1 streams, `io_digest` of those equals the live
/// run's, and the family columns and the log rebuild without executing
/// anything.
#[test]
fn an_imported_archive_answers_without_reexecution() {
    let t = traced("fib");
    let bytes = export(&archive_of(&t, 5));
    let archive = TraceArchive::import(&bytes[..]).unwrap();

    assert_eq!(archive.cycle_profile().total(), t.execution.cycle_count);
    for (trace, (family, count)) in archive
        .family_traces()
        .families
        .iter()
        .zip(&archive.cycle_profile().counts)
    {
        assert_eq!((trace.family, trace.len() as u64), (*family, *count));
    }

    let io = archive.io_streams();
    assert_eq!(io, &t.execution.io);
    assert_eq!((io.input.clone(), io.output.clone()), common::fib_record());
    assert_eq!(
        io_digest(&io.input, &io.output),
        io_digest(&t.execution.io.input, &t.execution.io.output)
    );

    for (live, back) in t
        .traces
        .families
        .iter()
        .zip(&archive.family_traces().families)
    {
        assert_eq!(
            (live.family, live.height, live.len()),
            (back.family, back.height, back.len())
        );
        for i in 0..live.len() {
            assert_eq!(live.row(i), back.row(i), "family {} row {i}", live.family);
        }
    }
    assert_eq!(archive.memory_log(), &t.log);
    assert_eq!(archive.memory_log().final_state(), t.log.final_state());
    archive.memory_log().self_check(&t.image).unwrap();
}

/// Acceptance 8: the section table lists all five phases; post-execution is
/// filled and timed, the four later ones are present and empty; and an
/// archive claiming a later phase filled out of order is refused, beside the
/// in-order control. The byte patches follow the frozen wire form in
/// `crates/trace/src/archive.rs`: each empty section is `tag 00`, and the
/// timing section is five `(tag, Option<varint>)` pairs.
#[test]
fn the_five_phases_and_their_order() {
    let archive = archive_of(&traced("fib"), 99);
    assert_eq!(PHASES.len(), 5);
    assert!(archive.is_filled(Phase::PostExecution));
    assert_eq!(
        archive.timing(Phase::PostExecution),
        Some(PhaseTiming { wall_nanos: 99 })
    );
    for phase in &PHASES[1..] {
        assert!(!archive.is_filled(*phase), "{phase:?}");
        assert_eq!(archive.timing(*phase), None, "{phase:?}");
    }

    let bytes = export(&archive);
    let empty_later = [1, 0, 2, 0, 3, 0, 4, 0];
    let timing = [0, 1, 99, 1, 0, 2, 0, 3, 0, 4, 0];
    let payload = archive.deterministic_payload();
    assert!(
        payload.ends_with(&empty_later),
        "the later sections are present and empty"
    );
    assert_eq!(
        &bytes[payload.len()..],
        &timing,
        "the timing section, byte for byte"
    );
    let head = &payload[..payload.len() - empty_later.len()];

    let patched = |sections: &[u8], timing: &[u8]| {
        let mut file = head.to_vec();
        file.extend_from_slice(sections);
        file.extend_from_slice(timing);
        TraceArchive::import(&file[..])
    };
    // PostCommit filled with no bytes, and timed: in order, accepted.
    let back = patched(
        &[1, 1, 0, 2, 0, 3, 0, 4, 0],
        &[0, 1, 99, 1, 1, 5, 2, 0, 3, 0, 4, 0],
    )
    .expect("a later phase filled in order is accepted");
    assert!(back.is_filled(Phase::PostCommit));
    // PostGkr filled while PostCommit is empty: refused.
    let e = patched(
        &[1, 0, 2, 1, 0, 3, 0, 4, 0],
        &[0, 1, 99, 1, 0, 2, 1, 5, 3, 0, 4, 0],
    )
    .unwrap_err();
    assert!(e.contains("out of order") || e.contains("in order"), "{e}");
}
