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

use std::fmt;
use std::io::{Read, Write};
use std::marker::PhantomData;

use serde::de::{Deserialize, Deserializer, SeqAccess, Visitor};
use serde::Serialize;

use crate::family::{FamilyTrace, FamilyTraces, QueryColumns};
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
    /// `profile` must count exactly `traces`' families, row for row — a
    /// mismatch is a caller error and panics.
    pub fn from_execution(
        traces: FamilyTraces,
        log: MemoryEventLog,
        profile: CycleProfile,
        io: IoStreams,
        timing: PhaseTiming,
    ) -> TraceArchive {
        if let Err(e) = consistent(&traces, &profile) {
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
    /// post-execution payload whose parts disagree, trailing bytes.
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

        Ok(TraceArchive {
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
        })
    }

    fn post_execution_bytes(&self) -> Vec<u8> {
        let families: Vec<FamilyRef> = self
            .traces
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
        let events: Vec<EventWire> = self
            .log
            .events()
            .iter()
            .map(|e| {
                (
                    e.space.tag(),
                    e.addr,
                    e.ts,
                    e.read_ts,
                    e.read_value,
                    e.write_value,
                )
            })
            .collect();
        encode(&(
            &families[..],
            &events[..],
            &self.profile.counts[..],
            &self.io.input[..],
            &self.io.output[..],
        ))
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

fn decode_post_execution(
    bytes: &[u8],
) -> Result<(FamilyTraces, MemoryEventLog, CycleProfile, IoStreams), String> {
    let (wire, rest) = postcard::take_from_bytes::<PostExecutionWire>(bytes)
        .map_err(|e| format!("the post-execution payload does not decode: {e}"))?;
    if !rest.is_empty() {
        return Err("bytes follow the post-execution payload".into());
    }
    let (families, events, counts, input, output) = wire;

    let mut traces = FamilyTraces {
        families: Vec::new(),
    };
    for (family, height, cycle, pc, next_pc, present, queries) in families.0 {
        let n = cycle.0.len();
        let columns_agree = pc.0.len() == n
            && next_pc.0.len() == n
            && present.0.len() == n
            && queries.iter().all(|(a, b, c, d)| {
                a.0.len() == n && b.0.len() == n && c.0.len() == n && d.0.len() == n
            });
        if !columns_agree {
            return Err(format!("family {family}'s columns differ in length"));
        }
        if present.0.iter().any(|p| *p >> 7 != 0) {
            return Err(format!("family {family} marks a role that does not exist"));
        }
        if traces.families.last().is_some_and(|t| t.family >= family) {
            return Err("the family buffers are not in ascending family order".into());
        }
        traces.families.push(FamilyTrace {
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
        });
    }

    let mut log_events = Vec::with_capacity(events.0.len());
    for (tag, addr, ts, read_ts, read_value, write_value) in events.0 {
        let space = AddressSpace::from_tag(tag)
            .ok_or_else(|| format!("an event names address-space tag {tag}"))?;
        if !space.holds(addr) {
            return Err(format!("an event names {space:?} address {addr:#x}"));
        }
        if log_events.last().is_some_and(|e: &MemoryEvent| e.ts > ts) {
            return Err("the events are not in timestamp order".into());
        }
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
    consistent(&traces, &profile)?;
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
}
