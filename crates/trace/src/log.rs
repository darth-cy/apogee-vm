//! The memory event log: every memory query of one execution, in order.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use constants::{address_space, guest_memory, memory};
use loader::ProgramImage;

/// The address space a query names. The tags are `constants::address_space`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AddressSpace {
    /// The 32 registers; the address is the register index.
    Reg,
    /// RAM, a word at a time; the address is the byte address of the 4-aligned word.
    Ram,
    /// The program counter; the one address is 0.
    Pc,
}

impl AddressSpace {
    /// The frozen tag.
    pub fn tag(self) -> u8 {
        match self {
            AddressSpace::Reg => address_space::REG,
            AddressSpace::Ram => address_space::RAM,
            AddressSpace::Pc => address_space::PC,
        }
    }

    /// The space a tag names, or `None` for a tag that names none.
    pub fn from_tag(tag: u8) -> Option<AddressSpace> {
        match tag {
            address_space::REG => Some(AddressSpace::Reg),
            address_space::RAM => Some(AddressSpace::Ram),
            address_space::PC => Some(AddressSpace::Pc),
            _ => None,
        }
    }

    /// Whether `addr` is an address this space has: a register index, a
    /// 4-aligned word inside the RAM window, or the pc's one address.
    pub fn holds(self, addr: u32) -> bool {
        match self {
            AddressSpace::Reg => addr < 32,
            AddressSpace::Ram => {
                addr.is_multiple_of(4)
                    && addr >= guest_memory::RAM_ORIGIN
                    && addr - guest_memory::RAM_ORIGIN < guest_memory::RAM_LENGTH
            }
            AddressSpace::Pc => addr == 0,
        }
    }
}

/// One memory query: a read of `read_value`, last written at `read_ts`, and a
/// write of `write_value` at `ts`, both at one address. A query that only
/// reads writes back what it read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryEvent {
    pub space: AddressSpace,
    pub addr: u32,
    /// The write timestamp: `4 * cycle + delta`.
    pub ts: u64,
    /// When the value read was written: the address's previous query, or 0
    /// for its initial value.
    pub read_ts: u64,
    pub read_value: u32,
    pub write_value: u32,
}

impl MemoryEvent {
    /// The cycle the query belongs to.
    pub fn cycle(&self) -> u64 {
        self.ts / memory::TS_STEP
    }

    /// Its in-cycle slot, `0..4`.
    pub fn delta(&self) -> u64 {
        self.ts % memory::TS_STEP
    }
}

/// An address's last write: the value teardown binds, and when it was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FinalValue {
    pub space: AddressSpace,
    pub addr: u32,
    pub ts: u64,
    pub value: u32,
}

/// Why [`MemoryEventLog::self_check`] refused a log, and where.
///
/// `ts` is the timestamp of the query at which the fault is observed: the one
/// that breaks a timestamp rule, or the one that reads a value no write
/// produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfCheckError {
    pub space: AddressSpace,
    pub addr: u32,
    pub ts: u64,
    pub reason: String,
}

impl fmt::Display for SelfCheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "memory self-check failed at {:?} address {:#x}, ts {}: {}",
            self.space, self.addr, self.ts, self.reason
        )
    }
}

/// Every memory query of an execution, in cycle-then-delta order, beside the
/// "last-access" tables that fill each new query's read side.
///
/// The events are the log; the tables are bookkeeping, rebuilt from the events
/// whenever a log is built from them, and are never serialized.
#[derive(Clone, Debug, Default)]
pub struct MemoryEventLog {
    events: Vec<MemoryEvent>,
    /// Per register: the last write's `(ts, value)`, or `None` if untouched.
    regs: [Option<(u64, u32)>; 32],
    pc: Option<(u64, u32)>,
    /// Per RAM word address. A hash map because it is only ever looked up;
    /// everything that reads it out sorts first.
    ram: HashMap<u32, (u64, u32)>,
}

impl PartialEq for MemoryEventLog {
    /// Two logs are equal when their events are; the tables follow from them.
    fn eq(&self, other: &MemoryEventLog) -> bool {
        self.events == other.events
    }
}

impl Eq for MemoryEventLog {}

impl MemoryEventLog {
    pub fn new() -> MemoryEventLog {
        MemoryEventLog::default()
    }

    /// Append one query, filling its read side from the last-access tables,
    /// and return it as recorded.
    ///
    /// `read_value` is what the machine read. On an address's first query it
    /// is the initial value, read at timestamp 0; on every later one it must
    /// equal the last value written there, or the machine and the log disagree
    /// about memory. That, a timestamp out of order, a read that does not
    /// strictly precede its write, and an address outside its space are broken
    /// invariants of the caller, and panic.
    pub fn record(
        &mut self,
        space: AddressSpace,
        addr: u32,
        ts: u64,
        read_value: u32,
        write_value: u32,
    ) -> MemoryEvent {
        assert!(
            space.holds(addr),
            "memory event log: {space:?} has no address {addr:#x}"
        );
        assert!(
            ts < 1 << memory::TS_BITS,
            "memory event log: timestamp {ts} is past the {}-bit clock",
            memory::TS_BITS
        );
        if let Some(last) = self.events.last() {
            assert!(
                ts >= last.ts,
                "memory event log: events are appended in cycle-then-delta order, \
                 but ts {ts} follows {}",
                last.ts
            );
        }
        let (read_ts, last_value) = self.last(space, addr).unwrap_or((0, read_value));
        assert_eq!(
            last_value, read_value,
            "memory event log: {space:?} {addr:#x} at ts {ts} read {read_value:#x}, \
             but the last write there was {last_value:#x}"
        );
        assert!(
            read_ts < ts,
            "memory event log: {space:?} {addr:#x}: the read at ts {read_ts} does not \
             precede the write at ts {ts}, so two queries at one address share a slot"
        );
        let event = MemoryEvent {
            space,
            addr,
            ts,
            read_ts,
            read_value,
            write_value,
        };
        self.remember(&event);
        self.events.push(event);
        event
    }

    /// A log holding exactly `events`, with its tables rebuilt from them.
    ///
    /// Checks nothing but that every address is one its space has: a log
    /// built this way is the thing [`MemoryEventLog::self_check`] exists to
    /// judge, so refusing a bad one here would leave nothing to judge.
    pub fn from_events(events: Vec<MemoryEvent>) -> MemoryEventLog {
        let mut log = MemoryEventLog::new();
        for event in &events {
            assert!(
                event.space.holds(event.addr),
                "memory event log: {:?} has no address {:#x}",
                event.space,
                event.addr
            );
            log.remember(event);
        }
        log.events = events;
        log
    }

    /// Every event, in order.
    pub fn events(&self) -> &[MemoryEvent] {
        &self.events
    }

    /// Every address the execution touched, ascending by space and address.
    pub fn touched_addresses(&self) -> Vec<(AddressSpace, u32)> {
        self.final_state()
            .iter()
            .map(|f| (f.space, f.addr))
            .collect()
    }

    /// Every touched address's last write, ascending by space and address.
    pub fn final_state(&self) -> Vec<FinalValue> {
        let mut out = Vec::new();
        for (r, last) in self.regs.iter().enumerate() {
            if let Some((ts, value)) = *last {
                out.push(FinalValue {
                    space: AddressSpace::Reg,
                    addr: r as u32,
                    ts,
                    value,
                });
            }
        }
        let mut ram: Vec<FinalValue> = self
            .ram
            .iter()
            .map(|(addr, (ts, value))| FinalValue {
                space: AddressSpace::Ram,
                addr: *addr,
                ts: *ts,
                value: *value,
            })
            .collect();
        ram.sort_by_key(|f| f.addr);
        out.extend(ram);
        if let Some((ts, value)) = self.pc {
            out.push(FinalValue {
                space: AddressSpace::Pc,
                addr: 0,
                ts,
                value,
            });
        }
        out
    }

    /// The trace-level memory argument, independent of any circuit.
    ///
    /// Recomputed from the events alone, never from the tables. First the
    /// timestamp rules: every address is one its space has, every timestamp is
    /// on the 38-bit clock, every read strictly precedes its write (the gap
    /// `ts - read_ts - 1` is non-negative), and no two queries at one address
    /// share a timestamp. Then the multiset balance the global argument
    /// checks: the writes — an initial write at timestamp 0 of every touched
    /// address, holding its value in `image`, plus every query's write — equal
    /// the reads — every query's read, plus a teardown read of every address's
    /// last write.
    ///
    /// Together those say each read sees exactly the last write before it:
    /// with one write per address per timestamp, the balance pairs every write
    /// with one later read, and the gap rule leaves only the chronological
    /// pairing. The last write of an address is read by teardown, which is
    /// derived here from the log itself — so a changed final value balances by
    /// construction, as it does in the argument, where teardown's values are
    /// bound by something else.
    pub fn self_check(&self, image: &ProgramImage) -> Result<(), SelfCheckError> {
        let refuse = |e: &MemoryEvent, reason: String| SelfCheckError {
            space: e.space,
            addr: e.addr,
            ts: e.ts,
            reason,
        };

        let mut written: HashSet<(AddressSpace, u32, u64)> = HashSet::new();
        for e in &self.events {
            if !e.space.holds(e.addr) {
                return Err(refuse(e, "not an address of its space".into()));
            }
            if e.ts >= 1 << memory::TS_BITS {
                return Err(refuse(e, "the timestamp is past the 38-bit clock".into()));
            }
            if e.read_ts >= e.ts {
                return Err(refuse(
                    e,
                    format!(
                        "the gap is negative: a read at ts {} for a write at ts {}",
                        e.read_ts, e.ts
                    ),
                ));
            }
            if !written.insert((e.space, e.addr, e.ts)) {
                return Err(refuse(
                    e,
                    "a second query at this address and timestamp".into(),
                ));
            }
        }

        // +1 per write, -1 per read, keyed by the whole tuple.
        let mut balance: BTreeMap<(AddressSpace, u32, u64, u32), i64> = BTreeMap::new();
        let mut last: BTreeMap<(AddressSpace, u32), (u64, u32)> = BTreeMap::new();
        for e in &self.events {
            *balance
                .entry((e.space, e.addr, e.ts, e.write_value))
                .or_default() += 1;
            *balance
                .entry((e.space, e.addr, e.read_ts, e.read_value))
                .or_default() -= 1;
            let slot = last
                .entry((e.space, e.addr))
                .or_insert((e.ts, e.write_value));
            if e.ts >= slot.0 {
                *slot = (e.ts, e.write_value);
            }
        }
        for (&(space, addr), &(ts, value)) in &last {
            let init = initial_value(image, space, addr);
            *balance.entry((space, addr, 0, init)).or_default() += 1;
            *balance.entry((space, addr, ts, value)).or_default() -= 1;
        }

        let Some((&(space, addr, ts, value), &count)) = balance.iter().find(|(_, n)| **n != 0)
        else {
            return Ok(());
        };
        // Name the query that reads timestamp `ts` here, where the imbalance
        // is observed; failing that, the one that wrote it.
        let at = self
            .events
            .iter()
            .filter(|e| e.space == space && e.addr == addr)
            .find(|e| e.read_ts == ts)
            .or_else(|| {
                self.events
                    .iter()
                    .find(|e| e.space == space && e.addr == addr && e.ts == ts)
            });
        Err(SelfCheckError {
            space,
            addr,
            ts: at.map_or(ts, |e| e.ts),
            reason: format!(
                "the read and write multisets differ: value {value:#x} at ts {ts} is \
                 written {count:+} more times than it is read"
            ),
        })
    }

    fn last(&self, space: AddressSpace, addr: u32) -> Option<(u64, u32)> {
        match space {
            AddressSpace::Reg => self.regs[addr as usize],
            AddressSpace::Pc => self.pc,
            AddressSpace::Ram => self.ram.get(&addr).copied(),
        }
    }

    fn remember(&mut self, e: &MemoryEvent) {
        let last = (e.ts, e.write_value);
        match e.space {
            AddressSpace::Reg => self.regs[e.addr as usize] = Some(last),
            AddressSpace::Pc => self.pc = Some(last),
            AddressSpace::Ram => {
                self.ram.insert(e.addr, last);
            }
        }
    }
}

/// An address's value before the first cycle: 0 for a register, the entry
/// point for the pc, and the image's bytes for a RAM word — zero wherever no
/// segment has a file byte.
fn initial_value(image: &ProgramImage, space: AddressSpace, addr: u32) -> u32 {
    match space {
        AddressSpace::Reg => 0,
        AddressSpace::Pc => image.entry,
        AddressSpace::Ram => (0..4u32).fold(0, |word, i| {
            word | image_byte(image, addr.wrapping_add(i)) << (8 * i)
        }),
    }
}

fn image_byte(image: &ProgramImage, addr: u32) -> u32 {
    for s in &image.segments {
        if addr >= s.vaddr && ((addr - s.vaddr) as usize) < s.bytes.len() {
            return s.bytes[(addr - s.vaddr) as usize] as u32;
        }
    }
    0
}
