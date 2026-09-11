//! The trace archive: the self-contained post-execution snapshot, in the
//! container every later prover phase appends to.
//!
//! # The container, frozen
//!
//! A file is two `postcard` values back to back, deterministic payload first:
//!
//! ```text
//! payload = [(phase: u8, content: Option<bytes>); 5]     phases 0..5 in order
//! timing  = [(phase: u8, wall_nanos: Option<u64>); 5]    the same five
//! ```
//!
//! The payload is the section table: one entry per [`Phase`], each either
//! empty or holding that phase's bytes. Timing is its own section, last, so
//! [`TraceArchive::deterministic_payload`] is exactly the first value's bytes
//! — the determinism boundary is a byte boundary, not a comparison that knows
//! to skip a field. A phase has timing exactly when it has content, and the
//! filled phases are a prefix of the five, post-execution always among them.
//!
//! This stage fills post-execution only. Its content is one `postcard` value:
//!
//! ```text
//! ( families: [(family u32, height u32, cycle [u64], pc [u32], next_pc [u32],
//!               present [u8], [(addr [u32], read_ts [u64], read_value [u32],
//!                               write_value [u32]); 7]
//!             )],
//!   events:   [(space tag u8, addr u32, ts u64, read_ts u64, read_value u32,
//!               write_value u32)],
//!   profile:  [(family u32, count u64)],
//!   input:    [u8],
//!   output:   [u8] )
//! ```
//!
//! The four later phases' contents are theirs to define; this stage carries
//! them as opaque bytes and never interprets them.
//!
//! No compression: an uncompressed canonical encoding is what makes two runs'
//! payloads byte-identical with nothing further to argue.
//!
//! # What a reader takes
//!
//! Exactly what [`TraceArchive::export`] writes, and nothing else. The parts
//! of a post-execution snapshot must agree — `check_parts` is the rule, and
//! the constructor applies the same one, so every archive that can be built
//! can be read back — and a file must be the canonical encoding of the archive
//! it decodes to, because `postcard` also reads overlong varints, and two
//! files for one archive would make the payload boundary a property of the
//! writer alone.

use std::fmt;
use std::io::{Read, Write};
use std::marker::PhantomData;

use constants::{family, memory};
use serde::de::{Deserialize, Deserializer, SeqAccess, Visitor};
use serde::Serialize;

use crate::family::{FamilyTrace, FamilyTraces, Query, QueryColumns, Row, ROLES};
use crate::log::{AddressSpace, MemoryEvent, MemoryEventLog};
use crate::CycleProfile;

/// A prover phase boundary. The tag is the discriminant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Phase {
    PostExecution = 0,
    PostCommit = 1,
    PostGkr = 2,
    PostOpening = 3,
    Final = 4,
}

/// The five boundaries, in order.
pub const PHASES: [Phase; 5] = [
    Phase::PostExecution,
    Phase::PostCommit,
    Phase::PostGkr,
    Phase::PostOpening,
    Phase::Final,
];

/// How long a phase took, wall clock. Outside the deterministic payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhaseTiming {
    pub wall_nanos: u64,
}

/// The two committed streams: the fd 0 bytes the guest consumed and the fd 1
/// bytes it wrote. `transcript::io_digest(&input, &output)` is the public I/O
/// digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoStreams {
    pub input: Vec<u8>,
    pub output: Vec<u8>,
}

/// The snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceArchive {
    traces: FamilyTraces,
    log: MemoryEventLog,
    profile: CycleProfile,
    io: IoStreams,
    /// Post-commit through final, opaque. Every one is `None` at S12.
    later: [Option<Vec<u8>>; 4],
    timing: [Option<PhaseTiming>; 5],
}

impl TraceArchive {
    /// The post-execution archive of one run: `trace_run`'s outputs, the
    /// streams its `Execution` recorded, and how long it took.
    ///
    /// The three trace parts must be one run's — the family rows, the log
    /// and the profile agreeing by the same rule [`TraceArchive::import`]
    /// applies, so an archive built here is one the reader takes back. Parts
    /// that disagree are a caller error and panic.
    pub fn from_execution(
        traces: FamilyTraces,
        log: MemoryEventLog,
        profile: CycleProfile,
        io: IoStreams,
        timing: PhaseTiming,
    ) -> TraceArchive {
        if let Err(e) = check_parts(&traces, log.events(), &profile) {
            panic!("TraceArchive::from_execution: {e}");
        }
        TraceArchive {
            traces,
            log,
            profile,
            io,
            later: [None, None, None, None],
            timing: [Some(timing), None, None, None, None],
        }
    }

    pub fn family_traces(&self) -> &FamilyTraces {
        &self.traces
    }

    pub fn memory_log(&self) -> &MemoryEventLog {
        &self.log
    }

    pub fn cycle_profile(&self) -> &CycleProfile {
        &self.profile
    }

    pub fn io_streams(&self) -> &IoStreams {
        &self.io
    }

    /// Whether `phase` has content.
    pub fn is_filled(&self, phase: Phase) -> bool {
        match phase {
            Phase::PostExecution => true,
            later => self.later[later as usize - 1].is_some(),
        }
    }

    /// `phase`'s timing, which it has exactly when it is filled.
    pub fn timing(&self, phase: Phase) -> Option<PhaseTiming> {
        self.timing[phase as usize]
    }

    /// The payload section's bytes: everything but the timing, and what two
    /// runs of one guest on one input agree on byte for byte.
    pub fn deterministic_payload(&self) -> Vec<u8> {
        let post = self.post_execution_bytes();
        let sections: [(u8, Option<&[u8]>); 5] = std::array::from_fn(|i| {
            let content = if i == 0 {
                Some(&post[..])
            } else {
                self.later[i - 1].as_deref()
            };
            (i as u8, content)
        });
        encode(&sections)
    }

    /// Write the archive: the payload section, then the timing section.
    ///
    /// `impl Write` because the stage prompt freezes that signature; master
    /// anti-goal 2 would not have written it, and the handoff records the call.
    pub fn export(&self, mut w: impl Write) -> Result<(), String> {
        let timing: [(u8, Option<u64>); 5] =
            std::array::from_fn(|i| (i as u8, self.timing[i].map(|t| t.wall_nanos)));
        w.write_all(&self.deterministic_payload())
            .and_then(|()| w.write_all(&encode(&timing)))
            .map_err(|e| format!("writing the trace archive: {e}"))
    }

    /// Read an archive back, refusing anything [`TraceArchive::export`] could
    /// not have written: a section table out of order, a filled phase after
    /// an empty one, timing without content or content without timing, a
    /// post-execution payload whose parts disagree, trailing bytes, and any
    /// encoding of an archive but its canonical one.
    pub fn import(mut r: impl Read) -> Result<TraceArchive, String> {
        let mut bytes = Vec::new();
        r.read_to_end(&mut bytes)
            .map_err(|e| format!("reading the trace archive: {e}"))?;
        let (sections, rest) = postcard::take_from_bytes::<[(u8, Option<Seq<u8>>); 5]>(&bytes)
            .map_err(|e| format!("the payload section does not decode: {e}"))?;
        let (timing, rest) = postcard::take_from_bytes::<[(u8, Option<u64>); 5]>(rest)
            .map_err(|e| format!("the timing section does not decode: {e}"))?;
        if !rest.is_empty() {
            return Err(format!("{} bytes follow the timing section", rest.len()));
        }

        let mut filled = [false; 5];
        for (i, ((tag, content), (timing_tag, nanos))) in sections.iter().zip(&timing).enumerate() {
            if *tag as usize != i || *timing_tag as usize != i {
                return Err(format!(
                    "section {i} is tagged {tag} and its timing {timing_tag}: the table \
                     lists the five phases in order"
                ));
            }
            filled[i] = content.is_some();
            if filled[i] != nanos.is_some() {
                return Err(format!(
                    "{:?} has {} but {}: a phase is timed exactly when it is filled",
                    PHASES[i],
                    if filled[i] { "content" } else { "no content" },
                    if nanos.is_some() {
                        "a timing"
                    } else {
                        "no timing"
                    }
                ));
            }
        }
        if let Some(i) = (1..5).find(|&i| filled[i] && !filled[i - 1]) {
            return Err(format!(
                "{:?} is filled but {:?} before it is not: phases fill in order",
                PHASES[i],
                PHASES[i - 1]
            ));
        }
        let [(_, post), (_, a), (_, b), (_, c), (_, d)] = sections;
        let post = post.ok_or("the post-execution phase is empty")?;
        let (traces, log, profile, io) = decode_post_execution(&post.0)?;

        let archive = TraceArchive {
            traces,
            log,
            profile,
            io,
            later: [
                a.map(|s| s.0),
                b.map(|s| s.0),
                c.map(|s| s.0),
                d.map(|s| s.0),
            ],
            timing: std::array::from_fn(|i| {
                timing[i].1.map(|wall_nanos| PhaseTiming { wall_nanos })
            }),
        };
        let mut canonical = Vec::new();
        archive.export(&mut canonical)?;
        if canonical != bytes {
            return Err(
                "the file is not the canonical encoding of the archive it decodes to".into(),
            );
        }
        Ok(archive)
    }

    fn post_execution_bytes(&self) -> Vec<u8> {
        let events: Vec<EventWire> = self.log.events().iter().map(event_wire).collect();
        post_execution_wire(&self.traces, &events, &self.profile.counts, &self.io)
    }
}

type QueryRef<'a> = (&'a [u32], &'a [u64], &'a [u32], &'a [u32]);
type FamilyRef<'a> = (
    u32,
    u32,
    &'a [u64],
    &'a [u32],
    &'a [u32],
    &'a [u8],
    [QueryRef<'a>; 7],
);
type QueryWire = (Seq<u32>, Seq<u64>, Seq<u32>, Seq<u32>);
type FamilyWire = (
    u32,
    u32,
    Seq<u64>,
    Seq<u32>,
    Seq<u32>,
    Seq<u8>,
    [QueryWire; 7],
);
type EventWire = (u8, u32, u64, u64, u32, u32);
type PostExecutionWire = (
    Seq<FamilyWire>,
    Seq<EventWire>,
    Seq<(u32, u64)>,
    Seq<u8>,
    Seq<u8>,
);

fn event_wire(e: &MemoryEvent) -> EventWire {
    (
        e.space.tag(),
        e.addr,
        e.ts,
        e.read_ts,
        e.read_value,
        e.write_value,
    )
}

fn post_execution_wire(
    traces: &FamilyTraces,
    events: &[EventWire],
    counts: &[(u32, u64)],
    io: &IoStreams,
) -> Vec<u8> {
    let families: Vec<FamilyRef> = traces
        .families
        .iter()
        .map(|t| {
            (
                t.family,
                t.height,
                &t.cycle[..],
                &t.pc[..],
                &t.next_pc[..],
                &t.present[..],
                std::array::from_fn(|r| {
                    let q = &t.queries[r];
                    (
                        &q.addr[..],
                        &q.read_ts[..],
                        &q.read_value[..],
                        &q.write_value[..],
                    )
                }),
            )
        })
        .collect();
    encode(&(&families[..], events, counts, &io.input[..], &io.output[..]))
}

fn decode_post_execution(
    bytes: &[u8],
) -> Result<(FamilyTraces, MemoryEventLog, CycleProfile, IoStreams), String> {
    let (wire, rest) = postcard::take_from_bytes::<PostExecutionWire>(bytes)
        .map_err(|e| format!("the post-execution payload does not decode: {e}"))?;
    if !rest.is_empty() {
        return Err("bytes follow the post-execution payload".into());
    }
    let (families, events, counts, input, output) = wire;

    let traces = FamilyTraces {
        families: families
            .0
            .into_iter()
            .map(
                |(family, height, cycle, pc, next_pc, present, queries)| FamilyTrace {
                    family,
                    height,
                    cycle: cycle.0,
                    pc: pc.0,
                    next_pc: next_pc.0,
                    present: present.0,
                    queries: queries.map(|(addr, read_ts, read_value, write_value)| QueryColumns {
                        addr: addr.0,
                        read_ts: read_ts.0,
                        read_value: read_value.0,
                        write_value: write_value.0,
                    }),
                },
            )
            .collect(),
    };
    let mut log_events = Vec::with_capacity(events.0.len().min(4096));
    for (tag, addr, ts, read_ts, read_value, write_value) in events.0 {
        let space = AddressSpace::from_tag(tag)
            .ok_or_else(|| format!("an event names address-space tag {tag}"))?;
        log_events.push(MemoryEvent {
            space,
            addr,
            ts,
            read_ts,
            read_value,
            write_value,
        });
    }
    let profile = CycleProfile { counts: counts.0 };
    check_parts(&traces, &log_events, &profile)?;
    Ok((
        traces,
        MemoryEventLog::from_events(log_events),
        profile,
        IoStreams {
            input: input.0,
            output: output.0,
        },
    ))
}

/// The parts of a post-execution snapshot agree: the one rule the
/// constructor and the reader share.
///
/// - every buffer names a family `constants::family` has, and one that
///   claims a pc — init/teardown claims none, so its buffer is empty;
/// - every buffer's columns have one length, its height is on the menu, no
///   `present` bit names a role past the seventh, a role a row does not have
///   is `Query::ABSENT`, and the families ascend;
/// - the profile counts the buffers, row for row;
/// - the rows' cycles are exactly `1..=total`, each once;
/// - every event names an address its space has, lies on the 38-bit clock
///   and reads strictly before it writes;
/// - and the log is exactly the one the rows rebuild — each row's pc query,
///   then its present roles in `ROLES` order — event for event.
///
/// Whether the log is a correct execution is `MemoryEventLog::self_check`'s
/// question, not this one's; this says only that the snapshot is one thing.
fn check_parts(
    traces: &FamilyTraces,
    events: &[MemoryEvent],
    profile: &CycleProfile,
) -> Result<(), String> {
    for (i, t) in traces.families.iter().enumerate() {
        let n = t.cycle.len();
        if !program::FAMILIES.contains(&t.family) {
            return Err(format!("family {} is not in constants::family", t.family));
        }
        if t.family == family::INIT_TEARDOWN && n != 0 {
            return Err(format!(
                "init/teardown claims no pc, yet its buffer holds {n} rows"
            ));
        }
        let columns_agree = t.pc.len() == n
            && t.next_pc.len() == n
            && t.present.len() == n
            && t.queries.iter().all(|q| {
                q.addr.len() == n
                    && q.read_ts.len() == n
                    && q.read_value.len() == n
                    && q.write_value.len() == n
            });
        if !columns_agree {
            return Err(format!("family {}'s columns differ in length", t.family));
        }
        if !family::HEIGHT_MENU.contains(&t.height) {
            return Err(format!(
                "family {}'s height {} is not on the menu",
                t.family, t.height
            ));
        }
        if i > 0 && traces.families[i - 1].family >= t.family {
            return Err("the family buffers are not in ascending family order".into());
        }
        for r in 0..n {
            let row = t.row(r);
            if row.present >> 7 != 0 {
                return Err(format!(
                    "family {} row {r} marks a role that does not exist",
                    t.family
                ));
            }
            for role in ROLES {
                if row.query(role).is_none() && row.queries[role as usize] != Query::ABSENT {
                    return Err(format!(
                        "family {} row {r} holds a {role:?} query its present mask does \
                         not name",
                        t.family
                    ));
                }
            }
        }
    }
    consistent(traces, profile)?;

    let mut rows: Vec<Row> = traces
        .families
        .iter()
        .flat_map(|t| (0..t.len()).map(move |i| t.row(i)))
        .collect();
    rows.sort_by_key(|row| row.cycle);
    if rows
        .iter()
        .enumerate()
        .any(|(i, row)| row.cycle != i as u64 + 1)
    {
        return Err("the rows' cycles are not 1 to their count, each once".into());
    }

    for e in events {
        if !e.space.holds(e.addr) {
            return Err(format!(
                "an event names {:?} address {:#x}",
                e.space, e.addr
            ));
        }
        if e.ts >= 1 << memory::TS_BITS || e.read_ts >= e.ts {
            return Err(format!(
                "an event at ts {} reading ts {} is off the clock or reads no earlier \
                 than it writes",
                e.ts, e.read_ts
            ));
        }
    }

    let mut next = 0usize;
    for row in &rows {
        let base = memory::TS_STEP * row.cycle;
        let pc = MemoryEvent {
            space: AddressSpace::Pc,
            addr: 0,
            ts: base,
            read_ts: base - memory::TS_STEP,
            read_value: row.pc,
            write_value: row.next_pc,
        };
        let queries = ROLES.iter().filter_map(|role| {
            row.query(*role).map(|q| MemoryEvent {
                space: role.space(),
                addr: q.addr,
                ts: base + role.delta(),
                read_ts: q.read_ts,
                read_value: q.read_value,
                write_value: q.write_value,
            })
        });
        for want in std::iter::once(pc).chain(queries) {
            if events.get(next) != Some(&want) {
                return Err(format!(
                    "the log disagrees with the row of cycle {} at event {next}",
                    row.cycle
                ));
            }
            next += 1;
        }
    }
    if next != events.len() {
        return Err(format!(
            "the log has {} events no row accounts for",
            events.len() - next
        ));
    }
    Ok(())
}

/// The profile counts exactly the buffers' families, in order, row for row.
fn consistent(traces: &FamilyTraces, profile: &CycleProfile) -> Result<(), String> {
    let agree = traces.families.len() == profile.counts.len()
        && traces
            .families
            .iter()
            .zip(&profile.counts)
            .all(|(t, (f, n))| t.family == *f && t.len() as u64 == *n);
    if agree {
        Ok(())
    } else {
        Err(format!(
            "the cycle profile {:?} does not count the family buffers",
            profile.counts
        ))
    }
}

fn encode<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    postcard::to_extend(value, Vec::new())
        .unwrap_or_else(|e| panic!("encoding the trace archive into memory failed: {e}"))
}

/// A `Vec<T>` read back from a sequence.
///
/// The workspace's serde has no `alloc` feature (S01's choice, and
/// `crates/loader` explains the cost), so `Vec` has no `Deserialize` of its
/// own. Writing needs nothing: a slice serializes as a sequence in `core`.
struct Seq<T>(Vec<T>);

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Seq<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Seq<T>, D::Error> {
        d.deserialize_seq(SeqVisitor(PhantomData))
    }
}

struct SeqVisitor<T>(PhantomData<T>);

impl<'de, T: Deserialize<'de>> Visitor<'de> for SeqVisitor<T> {
    type Value = Seq<T>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a sequence")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Seq<T>, A::Error> {
        // The declared length is untrusted, so it bounds nothing it could
        // make us allocate before the elements arrive.
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(4096));
        while let Some(x) = seq.next_element()? {
            out.push(x);
        }
        Ok(Seq(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::family::{Query, Row};
    use constants::address_space;

    /// A one-cycle archive, built through the frozen constructor.
    fn tiny() -> TraceArchive {
        let mut log = MemoryEventLog::new();
        log.record(AddressSpace::Pc, 0, 4, 0x1_0000, 0x1_0004);
        let mut trace = FamilyTrace::new(0, 1 << 16);
        trace.push(&Row {
            cycle: 1,
            pc: 0x1_0000,
            next_pc: 0x1_0004,
            present: 0,
            queries: [Query::ABSENT; 7],
        });
        TraceArchive::from_execution(
            FamilyTraces {
                families: vec![trace],
            },
            log,
            CycleProfile {
                counts: vec![(0, 1)],
            },
            IoStreams {
                input: vec![1, 2],
                output: vec![3],
            },
            PhaseTiming { wall_nanos: 7 },
        )
    }

    fn reimport(archive: &TraceArchive) -> Result<TraceArchive, String> {
        let mut bytes = Vec::new();
        archive.export(&mut bytes).expect("exporting into memory");
        TraceArchive::import(&bytes[..])
    }

    /// A file holding `post` as its post-execution content, timed as `tiny`.
    fn file(post: &[u8]) -> Vec<u8> {
        let sections: [(u8, Option<&[u8]>); 5] =
            [(0, Some(post)), (1, None), (2, None), (3, None), (4, None)];
        let timing: [(u8, Option<u64>); 5] =
            [(0, Some(7)), (1, None), (2, None), (3, None), (4, None)];
        let mut out = encode(&sections);
        out.extend(encode(&timing));
        out
    }

    /// `tiny`'s post-execution content after `edit`, with its events
    /// replaced by `events` when given — the parts written as they are, with
    /// no check, so the reader is the only thing judging them.
    fn post(edit: fn(&mut TraceArchive), events: Option<Vec<EventWire>>) -> Vec<u8> {
        let mut a = tiny();
        edit(&mut a);
        let events = events.unwrap_or_else(|| a.log.events().iter().map(event_wire).collect());
        post_execution_wire(&a.traces, &events, &a.profile.counts, &a.io)
    }

    /// The positive control for the refusals below: a later phase filled in
    /// order, with its timing, is an archive this reader takes.
    #[test]
    fn a_later_phase_filled_in_order_is_accepted() {
        let mut archive = tiny();
        archive.later[0] = Some(vec![9, 9]);
        archive.timing[1] = Some(PhaseTiming { wall_nanos: 1 });
        let back = reimport(&archive).expect("an in-order archive imports");
        assert_eq!(back, archive);
        assert!(back.is_filled(Phase::PostCommit));
        assert!(!back.is_filled(Phase::PostGkr));
    }

    #[test]
    fn a_phase_filled_out_of_order_is_refused() {
        let mut archive = tiny();
        archive.later[1] = Some(vec![9]);
        archive.timing[2] = Some(PhaseTiming { wall_nanos: 1 });
        let e = reimport(&archive).unwrap_err();
        assert!(e.contains("PostGkr is filled but PostCommit"), "{e}");
    }

    #[test]
    fn timing_without_content_is_refused() {
        let mut archive = tiny();
        archive.timing[3] = Some(PhaseTiming { wall_nanos: 1 });
        let e = reimport(&archive).unwrap_err();
        assert!(e.contains("PostOpening has no content but a timing"), "{e}");
    }

    #[test]
    fn content_without_timing_is_refused() {
        let mut archive = tiny();
        archive.later[0] = Some(vec![1]);
        let e = reimport(&archive).unwrap_err();
        assert!(e.contains("PostCommit has content but no timing"), "{e}");
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let mut bytes = Vec::new();
        tiny().export(&mut bytes).unwrap();
        bytes.push(0);
        assert!(TraceArchive::import(&bytes[..]).is_err());
    }

    /// `postcard` reads `87 00` as 7, as it reads `07`; the reader takes only
    /// the canonical form, so one archive is one byte string.
    #[test]
    fn an_overlong_varint_is_refused() {
        let mut bytes = Vec::new();
        tiny().export(&mut bytes).unwrap();
        // The timing section is `00 01 07 01 00 02 00 03 00 04 00`.
        let at = bytes.len() - 9;
        assert_eq!(bytes[at], 7);
        bytes.splice(at..at + 1, [0x87, 0x00]);
        let e = TraceArchive::import(&bytes[..]).unwrap_err();
        assert!(e.contains("canonical"), "{e}");
    }

    /// Every refusal of the post-execution content, each an `Err` naming what
    /// it refused — never a panic, though some of these, let through, would
    /// reach an assertion — beside the untouched content as the control.
    #[test]
    fn every_disagreement_in_the_parts_is_refused() {
        assert_eq!(
            TraceArchive::import(&file(&post(|_| {}, None))[..]).unwrap(),
            tiny()
        );
        let pc = (address_space::PC, 0, 4, 0, 0x1_0000, 0x1_0004);
        let cases: [(&str, Vec<u8>); 14] = [
            // The profile renames the family too, so only the id is wrong.
            (
                "family 42 is not in constants::family",
                post(
                    |a| {
                        a.traces.families[0].family = 42;
                        a.profile.counts[0].0 = 42;
                    },
                    None,
                ),
            ),
            (
                "init/teardown claims no pc",
                post(
                    |a| {
                        a.traces.families[0].family = constants::family::INIT_TEARDOWN;
                        a.profile.counts[0].0 = constants::family::INIT_TEARDOWN;
                    },
                    None,
                ),
            ),
            (
                "differ in length",
                post(|a| a.traces.families[0].pc.push(0), None),
            ),
            (
                "role that does not exist",
                post(|a| a.traces.families[0].present[0] = 0x80, None),
            ),
            (
                "does not name",
                post(|a| a.traces.families[0].queries[6].write_value[0] = 1, None),
            ),
            (
                "not on the menu",
                post(|a| a.traces.families[0].height = 3, None),
            ),
            (
                "ascending",
                post(
                    |a| {
                        a.traces.families.push(FamilyTrace::new(0, 1 << 16));
                        a.profile.counts.push((0, 0));
                    },
                    None,
                ),
            ),
            ("does not count", post(|a| a.profile.counts[0].1 = 2, None)),
            (
                "cycles are not 1",
                post(|a| a.traces.families[0].cycle[0] = 2, None),
            ),
            (
                "address-space tag 9",
                post(|_| {}, Some(vec![(9, 0, 4, 0, 0x1_0000, 0x1_0004)])),
            ),
            (
                "names Reg address 0x28",
                post(|_| {}, Some(vec![pc, (address_space::REG, 40, 5, 0, 0, 0)])),
            ),
            (
                "reads no earlier",
                post(
                    |_| {},
                    Some(vec![(address_space::PC, 0, 4, 4, 0x1_0000, 0x1_0004)]),
                ),
            ),
            (
                "disagrees with the row",
                post(
                    |_| {},
                    Some(vec![(address_space::PC, 0, 4, 0, 0x1_0000, 0x1_0008)]),
                ),
            ),
            (
                "no row accounts for",
                post(|_| {}, Some(vec![pc, (address_space::REG, 1, 5, 0, 0, 0)])),
            ),
        ];
        for (want, content) in cases {
            let e = TraceArchive::import(&file(&content)[..]).unwrap_err();
            assert!(e.contains(want), "expected '{want}': {e}");
        }

        let mut content = post(|_| {}, None);
        content.push(0);
        let e = TraceArchive::import(&file(&content)[..]).unwrap_err();
        assert!(e.contains("follow the post-execution"), "{e}");

        let mut bytes = file(&post(|_| {}, None));
        bytes[0] = 1;
        let e = TraceArchive::import(&bytes[..]).unwrap_err();
        assert!(e.contains("is tagged 1"), "{e}");
    }

    /// The constructor applies the reader's rule, so it cannot build an
    /// archive the reader would refuse.
    #[test]
    #[should_panic(expected = "disagrees with the row")]
    fn parts_that_disagree_are_refused_at_construction() {
        let a = tiny();
        TraceArchive::from_execution(
            a.traces,
            MemoryEventLog::new(),
            a.profile,
            a.io,
            PhaseTiming { wall_nanos: 1 },
        );
    }
}
