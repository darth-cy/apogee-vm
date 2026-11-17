//! The reference emulator: RV64IMAC on one hart, over a [`ProgramImage`].
//!
//! Two entry points, one instruction-execution core. [`run`] executes;
//! [`trace_run`] executes the same way and also hands each cycle's memory
//! queries to a recorder, which fills the memory event log and routes the
//! cycle's row to the family that owns its pc. The recorder is the only
//! difference between the two: neither path has its own copy of the
//! semantics.
//!
//! `docs/spec/execution-trace.md` specifies the convention the recorder
//! follows — timestamps, slots, the x0 rule, the ecall frame — and, in §10,
//! the emulator itself.
//!
//! # Semantics, in one paragraph
//!
//! One hart, no interrupts, no privilege levels. Every A-extension
//! instruction is its plain read-modify-write, and `aq`/`rl` order nothing.
//! **`sc` always succeeds**: it stores and writes 0 to `rd`. The ISA requires
//! an `sc` without a valid reservation to fail, so this is a conformance
//! deviation — never a soundness one, since the verifier still knows exactly
//! which program ran, and the circuits share the semantics
//! (`docs/spec/memory-ops.md` §6). An access at an address that is not a
//! multiple of its width, and any access outside the addressable regions —
//! every address at or above `2^32` among them — is a fatal guest error, never
//! rotated, split or emulated. So is `ebreak`, and so is a pc that is not the
//! start of an instruction.
//!
//! Memory is 32-bit words: a doubleword access is two of them, the word at the
//! address at slot 2 and the one above it at slot 3
//! (`docs/spec/execution-trace.md` §4).

use std::collections::HashMap;
use std::fmt;

use constants::delegation::Per;
use constants::{delegation, ecall, guest_memory, memory};
use field::Fp;
use isa::{decode, AmoOp, Instr};
use loader::{ProgramImage, Slot};
use program::{row_kind, DecodedTables, FamilyId, VmConfig};
use trace::{
    AddressSpace, CycleProfile, DelegationTrace, FamilyTrace, FamilyTraces, IoStreams, MemoryEvent,
    MemoryEventLog, MemoryState, Query, Role, Row, ROLES,
};

/// What a guest is given to read. **Two fields, because there are two things,
/// and what tells them apart is what binds them**
/// (`docs/spec/public-values.md`).
///
/// | field | where the guest finds it | what binds it |
/// | --- | --- | --- |
/// | `input` | the public input window, an ordinary load | the statement, at the window's init column |
/// | `advice` | `guest_memory::ADVICE_ORIGIN`, an ordinary load | **nothing**; the guest owes a check |
///
/// Both are *memory*. There is no third field and no stream: an Apogee guest
/// has no file descriptors, so there is nothing a host could hand it that is
/// neither of these two.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestIo {
    pub input: Vec<u8>,
    pub advice: Vec<u8>,
}

/// A finished execution: the guest called `exit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execution {
    /// The register file after the last cycle.
    pub regs: [u64; 32],
    /// The status passed to `exit`: `a0`'s low word. A nonzero status is a
    /// failed execution, which is still an execution: it is reported, not
    /// refused.
    pub exit_code: i32,
    /// Cycles run. Cycles are numbered from 1, so
    /// this is also the last cycle's number.
    pub cycle_count: u64,
    /// The execution's **public values**: the public input it was given, and
    /// the journal its stores left in the public output window
    /// (`docs/spec/public-values.md`). These are the two byte strings a
    /// statement carries and a proof binds.
    pub io: IoStreams,
}

/// Every way an execution stops other than by `exit`. Each is a fatal guest
/// error — the program did something this VM does not define — and neither
/// entry point returns any part of a trace alongside one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmuError {
    /// The pc is not the start of an instruction: the middle of one, data,
    /// the all-zero halfword, or outside the image's code — a jump target at
    /// or above `2^32` among them.
    NotAnInstruction { pc: u64 },
    /// An instruction slot holds a word the decoder refuses.
    IllegalInstruction { pc: u32, word: u32 },
    /// `ebreak`: a trap with nothing to trap to.
    Ebreak { pc: u32 },
    /// An access at an address that is not a multiple of its width.
    Misaligned { pc: u32, addr: u64, width: u32 },
    /// A data access outside the addressable regions — RAM, the two public
    /// windows, and the advice words the host supplied — or a delegation frame
    /// that reaches the advice region.
    OutOfBounds { pc: u32, addr: u64 },
    /// Cycle `cycle`'s timestamps would pass the 38-bit clock.
    ClockOverflow { cycle: u64 },
    /// The public input handed to the run is longer than a public window's
    /// payload, so no statement could carry it.
    ///
    /// Checked before the first cycle rather than left to panic inside the
    /// window's layout: a host that offers too much input has made a mistake,
    /// and the executor says so by name.
    PublicInputTooLong { len: usize },
    /// The journal's length word is above `guest_memory::PUBLIC_PAYLOAD_BYTES`
    /// at exit, so the public output window does not describe a byte string
    /// any statement could carry.
    ///
    /// Fatal, and it has to be: the verifier reads the window back through
    /// `program::public_io_words`, which has no encoding for such a length, so
    /// an execution this let through would be one no proof could cover.
    /// `guest_sdk::commit` refuses to overflow the window rather than reach
    /// here.
    JournalTooLong { len: u32 },
    /// A delegation ecall whose family the `VmConfig` does not hold: the
    /// program calls a delegation its image does not declare, so no trace
    /// can describe it. Only the tracing path raises it.
    DelegationFamilyAbsent { pc: u32, number: u32 },
    /// A delegation frame its family cannot answer: a word its circuit has no
    /// selector for, such as a round number out of range.
    DelegationFrame { pc: u32, detail: &'static str },
}

impl fmt::Display for EmuError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EmuError::NotAnInstruction { pc } => {
                write!(f, "pc {pc:#010x} is not the start of an instruction")
            }
            EmuError::IllegalInstruction { pc, word } => write!(
                f,
                "illegal instruction at pc {pc:#010x}: {word:#010x} is not RV64IMAC"
            ),
            EmuError::Ebreak { pc } => write!(f, "ebreak at pc {pc:#010x}"),
            EmuError::PublicInputTooLong { len } => write!(
                f,
                "the public input is {len} bytes, above the window's {}",
                guest_memory::PUBLIC_PAYLOAD_BYTES
            ),
            EmuError::JournalTooLong { len } => write!(
                f,
                "the journal's length word is {len}, above the window's {} payload bytes",
                guest_memory::PUBLIC_PAYLOAD_BYTES
            ),
            EmuError::Misaligned { pc, addr, width } => write!(
                f,
                "misaligned data access at pc {pc:#010x}: a {width}-byte access at {addr:#010x}"
            ),
            EmuError::OutOfBounds { pc, addr } => write!(
                f,
                "data access outside addressable memory at pc {pc:#010x}: address {addr:#010x}"
            ),
            EmuError::ClockOverflow { cycle } => write!(
                f,
                "cycle {cycle} would pass the {}-bit timestamp clock",
                memory::TS_BITS
            ),
            EmuError::DelegationFamilyAbsent { pc, number } => write!(
                f,
                "the delegation ecall {number:#x} at pc {pc:#010x} has no family in this \
                 VmConfig: the image does not declare it"
            ),
            EmuError::DelegationFrame { pc, detail } => write!(
                f,
                "the delegation frame at pc {pc:#010x} is not a call its family answers: {detail}"
            ),
        }
    }
}

/// What a run's inputs must satisfy before the first cycle: the public input
/// fits the window that will carry it (`docs/spec/public-values.md` §3).
///
/// The advice needs no such rule — the region is sized to what it was given.
fn check_io(io: &GuestIo) -> Result<(), EmuError> {
    if io.input.len() > guest_memory::PUBLIC_PAYLOAD_BYTES as usize {
        return Err(EmuError::PublicInputTooLong {
            len: io.input.len(),
        });
    }
    Ok(())
}

/// Run a guest to its `exit`.
pub fn run(image: &ProgramImage, io: &GuestIo) -> Result<Execution, EmuError> {
    check_io(io)?;
    let mut machine = Machine::new(image, io);
    machine.run()?;
    machine.finish()
}

/// Run a guest to its `exit`, recording its trace: the family buffers, the
/// memory event log, the cycle profile, and the same [`Execution`] [`run`]
/// returns.
///
/// `tables` and `config` must be one `program::decode_program` of `image`:
/// every cycle is routed to the family whose table claims its pc, so a pc no
/// table claims — impossible under the family partition — panics, as does a
/// `config` that describes other families than `tables`.
pub fn trace_run(
    image: &ProgramImage,
    io: &GuestIo,
    tables: &DecodedTables,
    config: &VmConfig,
) -> Result<(FamilyTraces, MemoryEventLog, CycleProfile, Execution), EmuError> {
    assert!(
        tables.families.len() == config.families.len()
            && tables
                .families
                .iter()
                .zip(&config.families)
                .all(|(t, (f, h))| t.family == *f && t.height == *h),
        "trace_run: the decoded tables and the VmConfig describe different VMs"
    );
    check_io(io)?;
    let mut machine = Machine::new(image, io);
    machine.recorder = Some(Recorder::new(
        tables,
        config,
        Keep::Whole(MemoryEventLog::new()),
    ));
    machine.run()?;
    let recorder = machine
        .recorder
        .take()
        .expect("trace_run installed a recorder");
    let execution = machine.finish()?;
    let profile = recorder.profile();
    assert_eq!(
        profile.total(),
        execution.cycle_count,
        "routing: every cycle lands in exactly one family buffer"
    );
    let Keep::Whole(log) = recorder.memory else {
        unreachable!("trace_run keeps the whole log")
    };
    Ok((recorder.traces, log, profile, execution))
}

// ---------------------------------------------------------------------------
// The streaming run
// ---------------------------------------------------------------------------

/// One completed shard's rows, handed back as soon as the family's buffer fills.
///
/// `index` is the shard index `docs/spec/streaming.md` §4 gives it — rows
/// `[index·h, min((index+1)·h, len))` of the family's buffer — so a streaming
/// run's shards are the same shards `trace::plan_shards` counts and the same
/// cut every family fill makes.
///
/// A cycle-owning family's shards and a delegation family's are chunks: a
/// window family's rows are addresses, and what fills them is the final
/// [`MemoryState`]. A delegation family's chunk carries its entries, calls or
/// path levels, in `calls` and no `rows`, its shard being
/// `docs/spec/streaming.md` §4's cut of its rows at `program::delegation_rows`
/// an entry.
pub struct ShardChunk {
    pub family: FamilyId,
    pub index: u32,
    pub rows: FamilyTrace,
    pub calls: Option<DelegationTrace>,
}

/// What a streaming execution leaves behind when it ends: the last-access
/// tables, the cycle profile and the same [`Execution`] [`run`] returns.
///
/// There is no memory event log and no whole-execution buffer here, and that is
/// the point: both are `O(cycles)` — about 300 bytes a cycle between them — and
/// a block of a billion cycles cannot hold either (`docs/spec/streaming.md` §1).
pub struct StreamedExecution {
    pub state: MemoryState,
    pub profile: CycleProfile,
    pub execution: Execution,
}

/// A guest executing under a **pull-based** tracer: the caller steps it, and
/// every time one family's buffer reaches that family's height the buffer is
/// handed over and a fresh one started.
///
/// The live state is one partial buffer per family — at most `height - 1` rows
/// each — plus the last-access tables. Nothing accumulates: a shard the caller
/// takes and drops is gone.
///
/// `tables` and `config` must be one `program::decode_program` of `image`, as
/// [`trace_run`]'s must, and the execution is the same execution: the emulator
/// is a pure function of `(image, io)`, so two runs give identical cycle
/// numbering, identical rows and identical shard boundaries. That is what lets
/// the streaming prover's two passes agree (`docs/spec/streaming.md` §2).
pub struct StreamingRun<'a> {
    machine: Machine<'a>,
}

impl<'a> StreamingRun<'a> {
    pub fn new(
        image: &ProgramImage,
        io: &'a GuestIo,
        tables: &'a DecodedTables,
        config: &VmConfig,
    ) -> Result<StreamingRun<'a>, EmuError> {
        assert!(
            tables.families.len() == config.families.len()
                && tables
                    .families
                    .iter()
                    .zip(&config.families)
                    .all(|(t, (f, h))| t.family == *f && t.height == *h),
            "StreamingRun: the decoded tables and the VmConfig describe different VMs"
        );
        check_io(io)?;
        let mut machine = Machine::new(image, io);
        machine.recorder = Some(Recorder::new(
            tables,
            config,
            Keep::Streaming(MemoryState::new()),
        ));
        Ok(StreamingRun { machine })
    }

    /// Step the guest until at least one shard is ready, or until it exits.
    ///
    /// The shards are returned in the order they filled, which is **not**
    /// statement order: a caller that needs statement order places them by
    /// `(family, index)`. An empty result means the guest has exited and
    /// [`StreamingRun::finish`] is what comes next.
    pub fn next_shards(&mut self) -> Result<Vec<ShardChunk>, EmuError> {
        loop {
            let recorder = self.recorder();
            if !recorder.ready.is_empty() {
                return Ok(std::mem::take(&mut self.recorder().ready));
            }
            if self.machine.exit.is_some() {
                return Ok(Vec::new());
            }
            self.machine.step()?;
        }
    }

    /// The execution's tail: every partial buffer as a final short shard, and
    /// what the execution left behind. Call it after [`StreamingRun::next_shards`]
    /// has returned empty.
    ///
    /// Panics if the guest has not exited: a partial buffer is not a shard
    /// until no more rows can reach it.
    pub fn finish(mut self) -> Result<(Vec<ShardChunk>, StreamedExecution), EmuError> {
        assert!(
            self.machine.exit.is_some(),
            "StreamingRun::finish before the guest exited"
        );
        let mut recorder = self
            .machine
            .recorder
            .take()
            .expect("a streaming run installed a recorder");
        assert!(
            recorder.ready.is_empty(),
            "StreamingRun::finish with {} shards not taken",
            recorder.ready.len()
        );
        let tail = recorder.flush_partial();
        let profile = recorder.profile();
        let execution = self.machine.finish()?;
        assert_eq!(
            profile.total(),
            execution.cycle_count,
            "routing: every cycle lands in exactly one family buffer"
        );
        let Keep::Streaming(state) = recorder.memory else {
            unreachable!("a streaming run keeps the tables alone")
        };
        Ok((
            tail,
            StreamedExecution {
                state,
                profile,
                execution,
            },
        ))
    }

    fn recorder(&mut self) -> &mut Recorder<'a> {
        self.machine
            .recorder
            .as_mut()
            .expect("a streaming run installed a recorder")
    }
}

// ---------------------------------------------------------------------------
// The machine
// ---------------------------------------------------------------------------

const PAGE: u32 = 4096;

/// What the pc can find in a slot, decoded once up front.
#[derive(Clone, Copy)]
enum Fetch {
    Code(Instr, bool),
    Illegal(u32),
    NotCode,
}

/// One cycle's queries before they are committed, by role:
/// `(address, value read, value written)`, a register's value 64 bits.
///
/// `delegation` is the invocation a delegation ecall made, if any. It is the
/// delegation family's row, not this cycle's.
struct Cycle {
    queries: [Option<(u32, u64, u64)>; 8],
    delegation: Option<Invocation>,
}

/// One delegation invocation: the ecall number, the frame base, one
/// `(address, old, new)` per frame word in frame order, a path's levels, and
/// a call's arrays.
struct Invocation {
    number: u32,
    base: u32,
    frame: Vec<(u32, u32, u32)>,
    levels: Vec<Level>,
    arrays: ArrayWords,
}

/// A `FALCON512` call's arrays: `(address, word)` per word, in
/// `delegation::falcon::CHAINS` order, each read and left as it was.
type ArrayWords = Vec<(u32, u32)>;

/// One level of a `MERKLE_ROOT` path: its sibling's address and words, which
/// the call reads and leaves, and what the level's entry carries
/// (`delegation::CARRY`).
struct Level {
    base: u32,
    words: [u32; delegation::merkle::SIBLING],
    carry: [u64; delegation::CARRY],
}

impl Cycle {
    fn new() -> Cycle {
        Cycle {
            queries: [None; 8],
            delegation: None,
        }
    }

    fn stage(&mut self, role: Role, addr: u32, read: u64, write: u64) {
        let slot = &mut self.queries[role as usize];
        assert!(slot.is_none(), "one cycle issued two {role:?} queries");
        *slot = Some((addr, read, write));
    }
}

struct Machine<'a> {
    code: Vec<Fetch>,
    slot_base: u32,
    regs: [u64; 32],
    pc: u32,
    /// RAM, 4 KiB pages by page number; an absent page is zeros.
    ram: HashMap<u32, Box<[u8; PAGE as usize]>>,
    /// The number the next cycle gets. The first is 1: timestamp 0 is the
    /// initial write of every address, and a cycle-0 pc query could not
    /// strictly follow it.
    cycle: u64,
    /// The public input this run was given: the window's payload, which
    /// `finish` reports as the statement's `input` whether or not the guest
    /// looked (`docs/spec/public-values.md` §9).
    public_input: &'a [u8],
    /// One past the highest advice byte the host supplied, rounded up to a
    /// word: the top of what a guest may load. Above it the advice region is
    /// addressable in principle and initialized by nothing in this execution,
    /// so a read there is refused loudly here rather than left to fail as an
    /// unprovable trace. A `u64`, because a full region, `ADVICE_WORDS` words,
    /// ends at `2^32`, which a `u32` wraps to 0.
    advice_end: u64,
    exit: Option<i32>,
    recorder: Option<Recorder<'a>>,
}

impl<'a> Machine<'a> {
    fn new(image: &ProgramImage, io: &'a GuestIo) -> Machine<'a> {
        let code = image
            .slots
            .iter()
            .map(|slot| match *slot {
                Slot::Instruction { word, compressed } => match decode(word) {
                    Ok(instr) => Fetch::Code(instr, compressed),
                    Err(_) => Fetch::Illegal(word),
                },
                Slot::MidInstruction | Slot::NonInstruction => Fetch::NotCode,
            })
            .collect();
        let mut machine = Machine {
            code,
            slot_base: image.slot_base,
            regs: [0; 32],
            pc: image.entry,
            ram: HashMap::new(),
            cycle: 1,
            public_input: &io.input,
            advice_end: guest_memory::ADVICE_ORIGIN as u64
                + 4 * trace::advice_region_words(&io.advice),
            exit: None,
            recorder: None,
        };
        for segment in &image.segments {
            for (i, byte) in segment.bytes.iter().enumerate() {
                if *byte != 0 {
                    let addr = segment.vaddr + i as u32;
                    let page = machine.page(addr);
                    page[(addr % PAGE) as usize] = *byte;
                }
            }
        }
        // The public input window: word 0 the payload's byte length, then the
        // payload. `program::public_io_words` is the one spelling of the
        // layout, shared with the prover's column builder and the verifier's
        // check, so the three cannot drift. A zero word is skipped, as advice
        // is below: a page that was never written reads 0 anyway, and the
        // window is 4,096 words, nearly all of them padding on a real input.
        for (y, word) in program::public_io_words(&io.input).iter().enumerate() {
            if *word != 0 {
                machine.set_word(guest_memory::PUBLIC_INPUT_ORIGIN + 4 * y as u32, *word);
            }
        }
        // The advice region: its length word, then the payload. Laid out by
        // `trace::advice_word`, the one spelling `guest_sdk::advice` reads
        // back and the prover's fill commits. The journal window starts at 0
        // and stays there until the guest stores into it.
        for y in 0..trace::advice_region_words(&io.advice) {
            let word = trace::advice_word(&io.advice, y);
            if word != 0 {
                machine.set_word(guest_memory::ADVICE_ORIGIN + 4 * y as u32, word);
            }
        }
        machine
    }

    /// The journal at exit: the public output window's length word, then that
    /// many payload bytes (`docs/spec/public-values.md` §3).
    fn journal(&self) -> Result<Vec<u8>, EmuError> {
        let len = self.word(guest_memory::PUBLIC_OUTPUT_ORIGIN);
        if len > guest_memory::PUBLIC_PAYLOAD_BYTES {
            return Err(EmuError::JournalTooLong { len });
        }
        let mut out = Vec::with_capacity(len as usize);
        for y in 0..len.div_ceil(4) {
            let word = self.word(guest_memory::PUBLIC_OUTPUT_ORIGIN + 4 + 4 * y);
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.truncate(len as usize);
        Ok(out)
    }

    fn run(&mut self) -> Result<(), EmuError> {
        while self.exit.is_none() {
            self.step()?;
        }
        Ok(())
    }

    fn finish(self) -> Result<Execution, EmuError> {
        let output = self.journal()?;
        Ok(Execution {
            regs: self.regs,
            exit_code: self.exit.expect("an execution finishes at its exit"),
            cycle_count: self.cycle - 1,
            // The public input is what the statement carries, whether or not
            // the guest read a byte of it: it is the window's contents, not a
            // stream cursor.
            io: IoStreams {
                input: self.public_input.to_vec(),
                output,
            },
        })
    }

    fn fetch(&self, pc: u32) -> Result<(Instr, bool), EmuError> {
        let slot = pc
            .checked_sub(self.slot_base)
            .filter(|d| d.is_multiple_of(2))
            .and_then(|d| self.code.get((d / 2) as usize));
        match slot {
            Some(Fetch::Code(instr, compressed)) => Ok((*instr, *compressed)),
            Some(Fetch::Illegal(word)) => Err(EmuError::IllegalInstruction { pc, word: *word }),
            Some(Fetch::NotCode) | None => Err(EmuError::NotAnInstruction { pc: pc as u64 }),
        }
    }

    /// One instruction: one cycle.
    fn step(&mut self) -> Result<(), EmuError> {
        let pc = self.pc;
        let (instr, compressed) = self.fetch(pc)?;
        let fall = pc + if compressed { 2 } else { 4 };
        if instr == Instr::Ecall {
            return self.ecall(instr, pc, fall);
        }
        let mut cycle = Cycle::new();
        let next_pc = self.execute(&mut cycle, instr, pc, fall)?;
        self.commit(&cycle, instr, pc, next_pc)
    }

    /// Close a cycle: check the clock, hand the queries to the recorder, and
    /// move the pc. The pc query itself — `pc` read, `next_pc` written, at
    /// slot 0 — is the recorder's to log, since every cycle has one.
    fn commit(
        &mut self,
        cycle: &Cycle,
        instr: Instr,
        pc: u32,
        next_pc: u32,
    ) -> Result<(), EmuError> {
        let number = self.cycle;
        if memory::TS_STEP * number + (memory::TS_STEP - 1) >= 1 << memory::TS_BITS {
            return Err(EmuError::ClockOverflow { cycle: number });
        }
        if let Some(recorder) = &mut self.recorder {
            recorder.record(number, pc, next_pc, instr, cycle);
        }
        self.cycle += 1;
        self.pc = next_pc;
        Ok(())
    }

    // -- registers --------------------------------------------------------

    /// Read a register, staging the query: a read, and a write-back of the
    /// same value. `x0` reads 0 like any register holding 0.
    fn read(&mut self, cycle: &mut Cycle, role: Role, r: u8) -> u64 {
        let value = self.regs[r as usize];
        cycle.stage(role, r as u32, value, value);
        value
    }

    /// Write `rd`, staging the query. `x0` logs a write-back of 0 and keeps it.
    fn write(&mut self, cycle: &mut Cycle, rd: u8, value: u64) {
        let old = self.regs[rd as usize];
        let value = if rd == 0 { 0 } else { value };
        cycle.stage(Role::Rd, rd as u32, old, value);
        self.regs[rd as usize] = value;
    }

    // -- memory -----------------------------------------------------------

    fn page(&mut self, addr: u32) -> &mut [u8; PAGE as usize] {
        self.ram
            .entry(addr / PAGE)
            .or_insert_with(|| Box::new([0; PAGE as usize]))
    }

    /// The word at a 4-aligned address.
    fn word(&self, addr: u32) -> u32 {
        match self.ram.get(&(addr / PAGE)) {
            Some(page) => {
                let at = (addr % PAGE) as usize;
                u32::from_le_bytes([page[at], page[at + 1], page[at + 2], page[at + 3]])
            }
            None => 0,
        }
    }

    fn set_word(&mut self, addr: u32, value: u32) {
        let at = (addr % PAGE) as usize;
        self.page(addr)[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// The word a `width`-byte access at `addr` begins in, refusing a
    /// misaligned access and one outside the addressable regions: RAM, the
    /// two public windows, and the advice words the host supplied. A
    /// doubleword is two words, and both must be reachable.
    fn data_word(&self, pc: u32, addr: u64, width: u32) -> Result<u32, EmuError> {
        if !addr.is_multiple_of(width as u64) {
            return Err(EmuError::Misaligned { pc, addr, width });
        }
        let reachable = |word: u64| {
            word <= u32::MAX as u64
                && trace::addressable(word as u32)
                && (word < guest_memory::ADVICE_ORIGIN as u64 || word < self.advice_end)
        };
        let word = addr & !3;
        if !reachable(word) || !reachable((addr + width as u64 - 1) & !3) {
            return Err(EmuError::OutOfBounds { pc, addr });
        }
        Ok(word as u32)
    }

    /// Replace a word, staging its query in `role`.
    fn ram_write(&mut self, cycle: &mut Cycle, role: Role, word: u32, old: u32, new: u32) {
        cycle.stage(role, word, old as u64, new as u64);
        self.set_word(word, new);
    }

    /// A pc a jump or branch reaches, refusing one at or above `2^32`: no
    /// instruction is there.
    fn target(addr: u64) -> Result<u32, EmuError> {
        u32::try_from(addr).map_err(|_| EmuError::NotAnInstruction { pc: addr })
    }

    // -- instructions -----------------------------------------------------

    /// Every instruction but `ecall`: stage its queries and return `next_pc`.
    fn execute(
        &mut self,
        c: &mut Cycle,
        instr: Instr,
        pc: u32,
        fall: u32,
    ) -> Result<u32, EmuError> {
        use Instr::*;
        // Every immediate is used sign-extended to 64 bits.
        let at = |base: u64, imm: i32| base.wrapping_add(imm as i64 as u64);
        let mut next = fall;
        match instr {
            Lui { rd, imm } => self.write(c, rd, imm as i64 as u64),
            Auipc { rd, imm } => self.write(c, rd, at(pc as u64, imm)),
            Jal { rd, imm } => {
                self.write(c, rd, fall as u64);
                next = Self::target(at(pc as u64, imm))?;
            }
            Jalr { rd, rs1, imm } => {
                let base = self.read(c, Role::Rs1, rs1);
                self.write(c, rd, fall as u64);
                next = Self::target(at(base, imm) & !1)?;
            }

            Beq { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, pc, imm, fall, |a, b| a == b)?
            }
            Bne { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, pc, imm, fall, |a, b| a != b)?
            }
            Blt { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, pc, imm, fall, |a, b| (a as i64) < (b as i64))?
            }
            Bge { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, pc, imm, fall, |a, b| (a as i64) >= (b as i64))?
            }
            Bltu { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, pc, imm, fall, |a, b| a < b)?
            }
            Bgeu { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, pc, imm, fall, |a, b| a >= b)?
            }

            Lb { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 1, |v| v as u8 as i8 as u64)?,
            Lh { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 2, |v| v as u16 as i16 as u64)?,
            Lw { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 4, |v| v as i32 as u64)?,
            Ld { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 8, |v| v)?,
            Lbu { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 1, |v| v as u8 as u64)?,
            Lhu { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 2, |v| v as u16 as u64)?,
            Lwu { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 4, |v| v as u32 as u64)?,
            Sb { rs1, rs2, imm } => self.store(c, pc, rs1, rs2, imm, 1)?,
            Sh { rs1, rs2, imm } => self.store(c, pc, rs1, rs2, imm, 2)?,
            Sw { rs1, rs2, imm } => self.store(c, pc, rs1, rs2, imm, 4)?,
            Sd { rs1, rs2, imm } => self.store(c, pc, rs1, rs2, imm, 8)?,

            Addi { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| a.wrapping_add(i)),
            Slti { rd, rs1, imm } => {
                self.op_imm(c, rd, rs1, imm, |a, i| ((a as i64) < (i as i64)) as u64)
            }
            Sltiu { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| (a < i) as u64),
            Xori { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| a ^ i),
            Ori { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| a | i),
            Andi { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| a & i),
            Slli { rd, rs1, shamt } => self.op_imm(c, rd, rs1, shamt as i32, |a, s| a << s),
            Srli { rd, rs1, shamt } => self.op_imm(c, rd, rs1, shamt as i32, |a, s| a >> s),
            Srai { rd, rs1, shamt } => {
                self.op_imm(c, rd, rs1, shamt as i32, |a, s| ((a as i64) >> s) as u64)
            }
            Addiw { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| {
                sext32((a as u32).wrapping_add(i as u32))
            }),
            Slliw { rd, rs1, shamt } => {
                self.op_imm(c, rd, rs1, shamt as i32, |a, s| sext32((a as u32) << s))
            }
            Srliw { rd, rs1, shamt } => {
                self.op_imm(c, rd, rs1, shamt as i32, |a, s| sext32((a as u32) >> s))
            }
            Sraiw { rd, rs1, shamt } => {
                self.op_imm(c, rd, rs1, shamt as i32, |a, s| ((a as i32) >> s) as u64)
            }

            Add { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a.wrapping_add(b)),
            Sub { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a.wrapping_sub(b)),
            Sll { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a << (b & 63)),
            Slt { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| ((a as i64) < (b as i64)) as u64)
            }
            Sltu { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| (a < b) as u64),
            Xor { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a ^ b),
            Srl { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a >> (b & 63)),
            Sra { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| ((a as i64) >> (b & 63)) as u64)
            }
            Or { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a | b),
            And { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a & b),
            Addw { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                sext32((a as u32).wrapping_add(b as u32))
            }),
            Subw { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                sext32((a as u32).wrapping_sub(b as u32))
            }),
            Sllw { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| sext32((a as u32) << (b & 31)))
            }
            Srlw { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| sext32((a as u32) >> (b & 31)))
            }
            Sraw { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| ((a as i32) >> (b & 31)) as u64)
            }

            // One hart: a fence orders nothing, and it has no register queries.
            Fence { .. } => {}
            Ebreak => return Err(EmuError::Ebreak { pc }),
            Ecall => unreachable!("ecall is dispatched before execute"),

            Mul { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a.wrapping_mul(b)),
            Mulh { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                ((a as i64 as i128 * b as i64 as i128) >> 64) as u64
            }),
            Mulhsu { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                ((a as i64 as i128 * b as i128) >> 64) as u64
            }),
            Mulhu { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                ((a as u128 * b as u128) >> 64) as u64
            }),
            Div { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| match b {
                0 => u64::MAX,
                _ => (a as i64).wrapping_div(b as i64) as u64,
            }),
            Divu { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| a.checked_div(b).unwrap_or(u64::MAX))
            }
            Rem { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| match b {
                0 => a,
                _ => (a as i64).wrapping_rem(b as i64) as u64,
            }),
            Remu { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a.checked_rem(b).unwrap_or(a)),
            Mulw { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                sext32((a as u32).wrapping_mul(b as u32))
            }),
            Divw { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| match b as u32 {
                0 => u64::MAX,
                _ => sext32((a as i32).wrapping_div(b as i32) as u32),
            }),
            Divuw { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                sext32((a as u32).checked_div(b as u32).unwrap_or(u32::MAX))
            }),
            Remw { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| match b as u32 {
                0 => sext32(a as u32),
                _ => sext32((a as i32).wrapping_rem(b as i32) as u32),
            }),
            Remuw { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                sext32((a as u32).checked_rem(b as u32).unwrap_or(a as u32))
            }),

            Amo {
                op,
                double,
                rd,
                rs1,
                rs2,
                ..
            } => self.amo(c, pc, op, double, rd, rs1, rs2)?,
        }
        Ok(next)
    }

    fn op(&mut self, c: &mut Cycle, rd: u8, rs1: u8, rs2: u8, f: fn(u64, u64) -> u64) {
        let a = self.read(c, Role::Rs1, rs1);
        let b = self.read(c, Role::Rs2, rs2);
        self.write(c, rd, f(a, b));
    }

    fn op_imm(&mut self, c: &mut Cycle, rd: u8, rs1: u8, imm: i32, f: fn(u64, u64) -> u64) {
        let a = self.read(c, Role::Rs1, rs1);
        self.write(c, rd, f(a, imm as i64 as u64));
    }

    #[allow(clippy::too_many_arguments)]
    fn branch(
        &mut self,
        c: &mut Cycle,
        rs1: u8,
        rs2: u8,
        pc: u32,
        imm: i32,
        fall: u32,
        taken: fn(u64, u64) -> bool,
    ) -> Result<u32, EmuError> {
        let a = self.read(c, Role::Rs1, rs1);
        let b = self.read(c, Role::Rs2, rs2);
        match taken(a, b) {
            true => Self::target((pc as u64).wrapping_add(imm as i64 as u64)),
            false => Ok(fall),
        }
    }

    /// A load: `rs1` at slot 1, the word at slot 2, a doubleword's high word
    /// at slot 3 written back, `rd` at slot 3. `extend` gets the value shifted
    /// down to the accessed bytes.
    #[allow(clippy::too_many_arguments)]
    fn load(
        &mut self,
        c: &mut Cycle,
        pc: u32,
        rd: u8,
        rs1: u8,
        imm: i32,
        width: u32,
        extend: fn(u64) -> u64,
    ) -> Result<(), EmuError> {
        let addr = self.read(c, Role::Rs1, rs1).wrapping_add(imm as i64 as u64);
        let word = self.data_word(pc, addr, width)?;
        let value = self.word(word);
        c.stage(Role::Load, word, value as u64, value as u64);
        let mut wide = (value >> (8 * (addr & 3))) as u64;
        if width == 8 {
            let high = self.word(word + 4);
            c.stage(Role::Ram, word + 4, high as u64, high as u64);
            wide |= (high as u64) << 32;
        }
        self.write(c, rd, extend(wide));
        Ok(())
    }

    /// A store: `rs1` at slot 1, `rs2` at slot 2, then the word with the
    /// stored bytes merged in — a sub-word store's at slot 3, a word or a
    /// doubleword's low word at slot 2 and a doubleword's high word at slot 3.
    fn store(
        &mut self,
        c: &mut Cycle,
        pc: u32,
        rs1: u8,
        rs2: u8,
        imm: i32,
        width: u32,
    ) -> Result<(), EmuError> {
        let addr = self.read(c, Role::Rs1, rs1).wrapping_add(imm as i64 as u64);
        let value = self.read(c, Role::Rs2, rs2);
        let word = self.data_word(pc, addr, width)?;
        let old = self.word(word);
        if width >= 4 {
            self.ram_write(c, Role::Load, word, old, value as u32);
            if width == 8 {
                let high = self.word(word + 4);
                self.ram_write(c, Role::Ram, word + 4, high, (value >> 32) as u32);
            }
            return Ok(());
        }
        let shift = 8 * (addr & 3) as u32;
        let mask = (u32::MAX >> (32 - 8 * width)) << shift;
        let new = (old & !mask) | (((value as u32) << shift) & mask);
        self.ram_write(c, Role::Ram, word, old, new);
        Ok(())
    }

    /// An atomic: `rs1` at slot 1, `rs2` at slot 2 unless it is `lr`, then
    /// the word at the address rewritten at slot 3 — a `.d` form's high word
    /// beside it at slot 2 — and `rd` given the old value, sign-extended from
    /// a `.w` form's word. `sc` stores and writes 0.
    #[allow(clippy::too_many_arguments)]
    fn amo(
        &mut self,
        c: &mut Cycle,
        pc: u32,
        op: AmoOp,
        double: bool,
        rd: u8,
        rs1: u8,
        rs2: u8,
    ) -> Result<(), EmuError> {
        let addr = self.read(c, Role::Rs1, rs1);
        let src = match op {
            AmoOp::Lr => 0,
            _ => self.read(c, Role::Rs2, rs2),
        };
        let word = self.data_word(pc, addr, if double { 8 } else { 4 })?;
        let old_lo = self.word(word);
        let old_hi = if double { self.word(word + 4) } else { 0 };
        let old = match double {
            true => old_lo as u64 | (old_hi as u64) << 32,
            false => old_lo as i32 as u64,
        };
        // Each op over 64 bits; a `.w` form's operands are sign-extended
        // words, and only the low word is stored.
        let src = if double {
            src
        } else {
            src as u32 as i32 as u64
        };
        let new = match op {
            AmoOp::Lr => old,
            AmoOp::Sc | AmoOp::Swap => src,
            AmoOp::Add => old.wrapping_add(src),
            AmoOp::Xor => old ^ src,
            AmoOp::Or => old | src,
            AmoOp::And => old & src,
            AmoOp::Min => (old as i64).min(src as i64) as u64,
            AmoOp::Max => (old as i64).max(src as i64) as u64,
            AmoOp::Minu if double => old.min(src),
            AmoOp::Maxu if double => old.max(src),
            AmoOp::Minu => (old as u32).min(src as u32) as u64,
            AmoOp::Maxu => (old as u32).max(src as u32) as u64,
        };
        if double {
            self.ram_write(c, Role::Load, word + 4, old_hi, (new >> 32) as u32);
        }
        self.ram_write(c, Role::Ram, word, old_lo, new as u32);
        self.write(c, rd, if op == AmoOp::Sc { 0 } else { old });
        Ok(())
    }

    // -- ecall ------------------------------------------------------------

    /// An ecall: one row — `a7` at slot 1, its one argument `a0` at slot 2,
    /// `a0` written at slot 3, and `next_pc` the fall-through — except an
    /// exit's, which is the halting sentinel `HALT_PC`
    /// (`docs/spec/memory.md` §5).
    ///
    /// Every ecall a guest may issue takes exactly one argument and moves no
    /// bytes, so an ecall is one cycle.
    fn ecall(&mut self, instr: Instr, pc: u32, fall: u32) -> Result<(), EmuError> {
        let mut row = Cycle::new();
        let number = self.read(&mut row, Role::Rs1, 17);
        let delegation = u32::try_from(number)
            .ok()
            .filter(|n| program::delegation_family(*n).is_some());
        let result = match number {
            n if n == ecall::EXIT as u64 => {
                let status = self.read(&mut row, Role::Rs2, 10);
                self.exit = Some(status as u32 as i32);
                status
            }
            // A delegation call: `a0` is the frame base, and the frame is
            // answered in place by an invocation riding this cycle
            // (`constants::delegation`). `a0` is preserved, so the row
            // writes no register.
            _ if delegation.is_some() => {
                let n = delegation.expect("just matched");
                let family = program::delegation_family(n).expect("a frame family");
                let base = self.read(&mut row, Role::Rs2, 10);
                if let Some(recorder) = &self.recorder {
                    if recorder.traces.delegation(family).is_none() {
                        return Err(EmuError::DelegationFamilyAbsent { pc, number: n });
                    }
                }
                row.delegation = Some(self.delegate(n, family, pc, base)?);
                return self.commit(&row, instr, pc, fall);
            }
            // Every other number is unassigned or retired: answered, and the
            // row refused at proving (`docs/spec/ecall-abi.md` §4).
            _ => (ecall::ENOSYS as u64).wrapping_neg(),
        };
        self.write(&mut row, 10, result);
        let next_pc = if number == ecall::EXIT as u64 {
            memory::HALT_PC
        } else {
            fall
        };
        self.commit(&row, instr, pc, next_pc)
    }

    /// Execute delegation `family`, ecall `number`, over the frame at `base`,
    /// in place, returning each frame word as `(address, old, new)`, a path's
    /// levels and a call's arrays.
    ///
    /// Every frame word must be one a store could write, below the advice
    /// region; anything else is a fatal guest error, as a misaligned store is.
    /// What the call computes is [`frame_function`]'s, or for the calls that
    /// read RAM past their frames, `MERKLE_ROOT` and `FALCON512`,
    /// [`Machine::merkle_root`]'s and [`Machine::falcon512`]'s.
    fn delegate(
        &mut self,
        number: u32,
        family: FamilyId,
        pc: u32,
        base: u64,
    ) -> Result<Invocation, EmuError> {
        let words = program::delegation_frame_words(family).expect("a delegation family");
        // The frame ends at or below the advice, the circuit's `room`, and
        // every word is checked as a store's is: aligned, and in a region a
        // guest may write.
        let end = base
            .checked_add(4 * words as u64)
            .filter(|end| *end <= guest_memory::ADVICE_ORIGIN as u64)
            .ok_or(EmuError::OutOfBounds { pc, addr: base })?;
        for addr in (base..end).step_by(4) {
            self.data_word(pc, addr, 4)?;
        }
        let base = base as u32;
        let old: Vec<u32> = (0..words).map(|j| self.word(base + 4 * j as u32)).collect();
        let (mut levels, mut arrays) = (Vec::new(), Vec::new());
        let new = match family {
            constants::family::MERKLE_ROOT => {
                let (new, path) = self.merkle_root(pc, base, &old)?;
                levels = path;
                new
            }
            constants::family::FALCON => {
                let (new, words) = self.falcon512(pc, base, &old)?;
                arrays = words;
                new
            }
            _ => frame_function(family)(pc, &old)?,
        };
        let frame = (0..words)
            .map(|j| {
                let addr = base + 4 * j as u32;
                self.set_word(addr, new[j]);
                (addr, old[j], new[j])
            })
            .collect();
        Ok(Invocation {
            number,
            base,
            frame,
            levels,
            arrays,
        })
    }

    /// The `FALCON512` call over the frame at `base`, whose words are
    /// `frame`: `‖s1‖²` written over its words 3 and 4 by [`falcon512_s1`],
    /// and the arrays' words, `(address, word)` in chain order, which the call
    /// reads and leaves (`constants::delegation::falcon`).
    ///
    /// The caller owes three word-aligned arrays of 256 words, apart from each
    /// other and from the frame: the call reads every word of them at one
    /// timestamp. Any other frame is refused. An array may be anywhere a load
    /// reaches, the advice included, each of its words checked as a load's;
    /// every halfword is a coefficient, read mod `q`.
    fn falcon512(
        &self,
        pc: u32,
        base: u32,
        frame: &[u32],
    ) -> Result<(Vec<u32>, ArrayWords), EmuError> {
        use delegation::falcon::{ARRAY, ARRAYS, C, CHAINS, H, N, NORM_HI, NORM_LO, S2};
        let refuse = |detail| Err(EmuError::DelegationFrame { pc, detail });
        // Each array and the frame as a byte range `[start, end)`, in 64 bits:
        // an array's end may pass `2^32`, where no load reaches.
        let span = |at: u32, words: usize| (at as u64, at as u64 + 4 * words as u64);
        let arrays = CHAINS.map(|word| span(frame[word], ARRAY));
        let apart = |(a, b): (u64, u64), (c, d): (u64, u64)| b <= c || d <= a;
        if arrays.iter().any(|(at, _)| !at.is_multiple_of(4)) {
            return refuse("falcon512's array is not word-aligned");
        }
        if arrays.iter().any(|a| !apart(*a, span(base, frame.len()))) {
            return refuse("falcon512's array overlaps its frame");
        }
        if !(apart(arrays[0], arrays[1])
            && apart(arrays[0], arrays[2])
            && apart(arrays[1], arrays[2]))
        {
            return refuse("falcon512's arrays overlap");
        }
        let mut words = Vec::with_capacity(ARRAYS);
        for (at, _) in arrays {
            for i in 0..ARRAY as u64 {
                let addr = self.data_word(pc, at + 4 * i, 4)?;
                words.push((addr, self.word(addr)));
            }
        }
        // Chain `P`'s coefficient `2i` is its word `i`'s low halfword.
        let poly = |word: usize| -> [u16; N] {
            let p = CHAINS.iter().position(|w| *w == word).expect("a chain");
            std::array::from_fn(|t| (words[ARRAY * p + t / 2].1 >> (16 * (t % 2))) as u16)
        };
        let s1 = falcon512_s1(&poly(H), &poly(S2), &poly(C));
        let norm: u64 = s1.iter().map(|x| (*x as i64 * *x as i64) as u64).sum();
        let mut new = frame.to_vec();
        new[NORM_LO] = norm as u32;
        new[NORM_HI] = (norm >> 32) as u32;
        Ok((new, words))
    }

    /// The `MERKLE_ROOT` call over the frame at `base`, whose words are
    /// `frame`: the root of the path it names written over its lanes, and each
    /// level's sibling and carry (`docs/spec/precompiles.md` §6).
    ///
    /// Level `L` hashes the node with its sibling, the node on the left where
    /// slot bit `L` is 0, as `transcript::poseidon2_permute`'s first eight
    /// lanes: `guest_sdk::poseidon2_compress`. A sibling's lanes are read mod
    /// `p`, so a sibling may be anywhere a load reaches, advice included; each
    /// of its words is checked as a load's. The caller owes a depth in
    /// `16..=32`, a slot below `2^depth` and siblings clear of the frame, whose
    /// words the call reads at the same timestamp; any other frame is refused.
    fn merkle_root(
        &self,
        pc: u32,
        base: u32,
        frame: &[u32],
    ) -> Result<(Vec<u32>, Vec<Level>), EmuError> {
        use delegation::merkle::{DEPTH, LANES, MAX_DEPTH, MIN_DEPTH, SIBLING, SIBLINGS, SLOT};
        let refuse = |detail| Err(EmuError::DelegationFrame { pc, detail });
        let (slot, depth, siblings) = (frame[SLOT] as u64, frame[DEPTH], frame[SIBLINGS] as u64);
        if !(MIN_DEPTH..=MAX_DEPTH).contains(&depth) {
            return refuse("merkle_root's depth is outside 16..=32");
        }
        if slot >> depth != 0 {
            return refuse("merkle_root's slot is not below 2^depth");
        }
        let end = siblings + (4 * SIBLING) as u64 * depth as u64;
        if siblings < base as u64 + 4 * frame.len() as u64 && (base as u64) < end {
            return refuse("merkle_root's siblings overlap its frame");
        }
        let lanes = |w: &[u32]| -> [Fp; 8] {
            std::array::from_fn(|i| Fp::from_u64(w[2 * i] as u64 | (w[2 * i + 1] as u64) << 32))
        };
        let mut node = lanes(&frame[..LANES]);
        let mut levels = Vec::with_capacity(depth as usize);
        for level in 0..depth as u64 {
            let at = siblings + (4 * SIBLING) as u64 * level;
            let mut words = [0u32; SIBLING];
            for (j, w) in words.iter_mut().enumerate() {
                *w = self.word(self.data_word(pc, at + 4 * j as u64, 4)?);
            }
            let mut carry = [0u64; delegation::CARRY];
            for (c, x) in carry.iter_mut().zip(node) {
                *c = x.to_u64();
            }
            carry[8] = slot >> level;
            carry[9] = level;
            let sibling = lanes(&words);
            let (left, right) = match slot >> level & 1 {
                0 => (node, sibling),
                _ => (sibling, node),
            };
            let mut state: [Fp; 16] = std::array::from_fn(|i| match i < 8 {
                true => left[i],
                false => right[i - 8],
            });
            transcript::poseidon2_permute(&mut state);
            node.copy_from_slice(&state[..8]);
            levels.push(Level {
                base: at as u32,
                words,
                carry,
            });
        }
        let mut new = frame.to_vec();
        for (i, x) in node.iter().enumerate() {
            new[2 * i] = x.to_u64() as u32;
            new[2 * i + 1] = (x.to_u64() >> 32) as u32;
        }
        Ok((new, levels))
    }
}

/// A 32-bit result, sign-extended: what every W form writes.
fn sext32(v: u32) -> u64 {
    v as i32 as i64 as u64
}

/// A delegation's function: from the requesting pc and the frame's words
/// before the call, the words after it, or why the frame is not a call the
/// family answers (`EmuError::DelegationFrame`).
type FrameFn = fn(u32, &[u32]) -> Result<Vec<u32>, EmuError>;

/// The function delegation `family`, a frame family, performs. The one
/// dispatch: a family with no arm here is a `constants::delegation::TYPES` row
/// nobody implemented.
fn frame_function(family: FamilyId) -> FrameFn {
    match family {
        constants::family::POSEIDON2 => poseidon2_frame,
        constants::family::MUL_DIV_U256 => mul_div_u256_frame,
        constants::family::FALCON_SAMPLE => falcon512_sample_frame,
        other => panic!("emulator: delegation family {other} has no implementation"),
    }
}

/// `transcript::poseidon2_permute` over 16 lanes, lane `i` words `2i` and
/// `2i + 1` little-endian, read mod `p` and written canonical.
fn poseidon2_frame(_pc: u32, words: &[u32]) -> Result<Vec<u32>, EmuError> {
    let mut state: [Fp; 16] = std::array::from_fn(|i| {
        Fp::from_u64(words[2 * i] as u64 | (words[2 * i + 1] as u64) << 32)
    });
    transcript::poseidon2_permute(&mut state);
    Ok(state
        .iter()
        .flat_map(|x| [x.to_u64() as u32, (x.to_u64() >> 32) as u32])
        .collect())
}

/// `a`, `b`, `d` at words 0, 8, 16 become `floor(a·b/d)`, `a·b mod d`, `d`.
/// Refuses `d = 0` and a quotient at or above `2^256`, which no witness
/// proves.
fn mul_div_u256_frame(pc: u32, words: &[u32]) -> Result<Vec<u32>, EmuError> {
    let limbs = |at: usize| -> [u64; 4] {
        std::array::from_fn(|i| words[at + 2 * i] as u64 | (words[at + 2 * i + 1] as u64) << 32)
    };
    let (a, b, d) = (limbs(0), limbs(8), limbs(16));
    if d == [0; 4] {
        return Err(EmuError::DelegationFrame {
            pc,
            detail: "mul_div_u256 by a zero divisor",
        });
    }
    // The product, eight limbs, schoolbook.
    let mut p = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = a[i] as u128 * b[j] as u128 + p[i + j] as u128 + carry;
            p[i + j] = t as u64;
            carry = t >> 64;
        }
        p[i + 4] = carry as u64;
    }
    let below = |x: &[u64], y: &[u64; 4]| {
        (0..4)
            .rev()
            .find(|&i| x[i] != y[i])
            .is_some_and(|i| x[i] < y[i])
    };
    if !below(&p[4..], &d) {
        return Err(EmuError::DelegationFrame {
            pc,
            detail: "mul_div_u256's quotient is not below 2^256",
        });
    }
    // Restoring division, one bit of the product at a time: the remainder
    // stays below `d`, its doubling's carry out deciding the subtraction.
    let (mut q, mut r) = ([0u64; 4], [0u64; 4]);
    for bit in (0..512).rev() {
        let carry = r[3] >> 63;
        for i in (1..4).rev() {
            r[i] = r[i] << 1 | r[i - 1] >> 63;
        }
        r[0] = r[0] << 1 | (p[bit / 64] >> (bit % 64)) & 1;
        if carry == 1 || !below(&r, &d) {
            let mut borrow = 0u64;
            for i in 0..4 {
                let (x, o1) = r[i].overflowing_sub(d[i]);
                let (x, o2) = x.overflowing_sub(borrow);
                r[i] = x;
                borrow = (o1 | o2) as u64;
            }
            debug_assert!(bit < 256, "the precondition keeps the quotient below 2^256");
            q[bit / 64] |= 1 << (bit % 64);
        }
    }
    let words = |x: [u64; 4]| x.into_iter().flat_map(|v| [v as u32, (v >> 32) as u32]);
    Ok(words(q).chain(words(r)).chain(words(d)).collect())
}

/// HashToPoint's sampler: each lane `x`, words `2l` and `2l + 1`
/// little-endian, becomes its base-`q` digits `d_j = ⌊x/q^j⌋ mod q`, `j < 4`,
/// word `2l` `d_0 + 2^16·d_1` and word `2l + 1` `d_2 + 2^16·d_3`. Refuses a
/// lane at or above `T`, the largest multiple of `q^4` below `p`, which no row
/// proves (`constraints::falcon`).
fn falcon512_sample_frame(pc: u32, words: &[u32]) -> Result<Vec<u32>, EmuError> {
    use delegation::falcon::Q;
    const T: u64 = field::A64_C5 / Q.pow(4) * Q.pow(4);
    let mut out = Vec::with_capacity(words.len());
    for lane in words.chunks_exact(2) {
        let mut x = lane[0] as u64 | (lane[1] as u64) << 32;
        if x >= T {
            return Err(EmuError::DelegationFrame {
                pc,
                detail: "falcon512_sample's lane is not below 808·q^4",
            });
        }
        let mut d = [0u32; 4];
        for digit in &mut d {
            *digit = (x % Q) as u32;
            x /= Q;
        }
        out.extend([d[0] | d[1] << 16, d[2] | d[3] << 16]);
    }
    Ok(out)
}

/// `s1 = (c − s2·h) mod (q, x^512 + 1)`, each coefficient centered to
/// `[−6144, 6144]`, `q = 12289 = 2·6144 + 1`, every coefficient of `h`, `s2`
/// and `c` read mod `q`: Falcon-512 verification's lattice check, whose
/// squared norm `FALCON512` answers, and the one copy of it, from which the
/// prover's fills take theirs (`constraints::falcon`). Schoolbook: `x^512`
/// wraps to `−1`.
pub fn falcon512_s1(
    h: &[u16; delegation::falcon::N],
    s2: &[u16; delegation::falcon::N],
    c: &[u16; delegation::falcon::N],
) -> [i16; delegation::falcon::N] {
    use delegation::falcon::{N, Q};
    let q = Q as i64;
    let h = h.map(|x| x as i64 % q);
    // Each coefficient a sum of 512 products below `q^2`: below `2^37`.
    let mut product = [0i64; N];
    for (i, a) in s2.iter().enumerate() {
        let a = *a as i64 % q;
        for (j, b) in h.iter().enumerate() {
            match i + j < N {
                true => product[i + j] += a * b,
                false => product[i + j - N] -= a * b,
            }
        }
    }
    std::array::from_fn(|t| {
        let x = (c[t] as i64 - product[t]).rem_euclid(q);
        (if 2 * x > q { x - q } else { x }) as i16
    })
}

// ---------------------------------------------------------------------------
// The recorder: the tracing path's one addition
// ---------------------------------------------------------------------------

struct Recorder<'a> {
    tables: &'a DecodedTables,
    /// The execution's memory: every event for [`trace_run`], the last-access
    /// tables alone for a [`StreamingRun`].
    memory: Keep,
    traces: FamilyTraces,
    /// Rows pushed per `traces.families[i]`, flushed shards included, so the
    /// cycle profile survives a buffer being handed away.
    family_rows: Vec<u64>,
    /// Entries pushed per `traces.delegations[i]`, likewise.
    calls: Vec<u64>,
    /// Shards a streaming run has filled and the caller has not taken.
    /// [`Keep::Whole`] never fills it: it holds every row to the end.
    ready: Vec<ShardChunk>,
}

/// How much of the memory argument a recorder keeps.
///
/// The events and the last-access tables answer different questions, and only
/// the first grows with the cycle count: the tables are `O(touched addresses)`
/// and are what the register and pc boundary, the RAM windows' teardown columns
/// and the window list are functions of (`docs/spec/streaming.md` §3). So a
/// streaming run keeps the tables and never collects an event at all.
enum Keep {
    /// The whole log, which is the tables plus every event.
    Whole(MemoryEventLog),
    /// The tables alone.
    Streaming(MemoryState),
}

impl Keep {
    fn record(
        &mut self,
        space: AddressSpace,
        addr: u32,
        ts: u64,
        read_value: u64,
        write_value: u64,
    ) -> MemoryEvent {
        match self {
            Keep::Whole(log) => log.record(space, addr, ts, read_value, write_value),
            Keep::Streaming(state) => state.record(space, addr, ts, read_value, write_value),
        }
    }
}

impl<'a> Recorder<'a> {
    /// One recorder over `config`'s families: an empty buffer each, in the
    /// config's order.
    fn new(tables: &'a DecodedTables, config: &VmConfig, memory: Keep) -> Recorder<'a> {
        let traces = FamilyTraces {
            families: config
                .families
                .iter()
                .filter(|(family, _)| program::delegation_frame_words(*family).is_none())
                .map(|(family, height)| FamilyTrace::new(*family, *height))
                .collect(),
            delegations: config
                .families
                .iter()
                .filter_map(|(family, height)| {
                    program::delegation_frame_words(*family)
                        .map(|width| DelegationTrace::new(*family, *height, width))
                })
                .collect(),
        };
        Recorder {
            tables,
            memory,
            family_rows: vec![0; traces.families.len()],
            calls: vec![0; traces.delegations.len()],
            traces,
            ready: Vec::new(),
        }
    }

    /// Log one cycle's queries — the pc query, then each role's in role
    /// order — and route its row to the family that owns its pc.
    fn record(&mut self, cycle: u64, pc: u32, next_pc: u32, instr: Instr, queries: &Cycle) {
        let base = memory::TS_STEP * cycle;
        self.memory
            .record(AddressSpace::Pc, 0, base, pc as u64, next_pc as u64);
        // An invocation's frame accesses ride this cycle at
        // `delegation::FRAME_DELTA`, 0: after the pc query, before the roles,
        // its levels' or its arrays' after its frame's. Every family of the
        // number records the call, each of its levels, or its arrays.
        if let Some(call) = &queries.delegation {
            let memory = &mut self.memory;
            let mut query = |addr: u32, read: u32, write: u32| {
                let (read, write) = (read as u64, write as u64);
                let ts = base + delegation::FRAME_DELTA;
                let event = memory.record(AddressSpace::Ram, addr, ts, read, write);
                Query {
                    addr,
                    read_ts: event.read_ts,
                    read_value: read,
                    write_value: write,
                }
            };
            let words: Vec<Query> = call.frame.iter().map(|&(a, r, w)| query(a, r, w)).collect();
            let levels: Vec<Vec<Query>> = call
                .levels
                .iter()
                .map(|l| {
                    let at = |j: usize| l.base + 4 * j as u32;
                    l.words
                        .iter()
                        .enumerate()
                        .map(|(j, &w)| query(at(j), w, w))
                        .collect()
                })
                .collect();
            let arrays: Vec<Query> = call.arrays.iter().map(|&(a, w)| query(a, w, w)).collect();
            for family in program::delegation_families(call.number) {
                let at = self
                    .traces
                    .delegations
                    .iter()
                    .position(|t| t.family == family)
                    .expect("a declared number declares all its families");
                match program::delegation_per(family) {
                    Per::Call => {
                        self.traces.delegations[at].push(cycle, call.base, &words, &[]);
                        self.calls[at] += 1;
                        self.flush_calls(at);
                    }
                    Per::Level => {
                        for (level, words) in call.levels.iter().zip(&levels) {
                            let buffer = &mut self.traces.delegations[at];
                            buffer.push(cycle, level.base, words, &level.carry);
                            self.calls[at] += 1;
                            self.flush_calls(at);
                        }
                    }
                    // UNFINISHED: S-FALCON-CODEC's FALCON512_DECODE recording.
                    Per::Decode => unimplemented!("FALCON512_DECODE entries"),
                    // One entry, its base the first array's: `s2`'s.
                    Per::Arrays => {
                        let base = call.arrays.first().expect("a call's arrays").0;
                        self.traces.delegations[at].push(cycle, base, &arrays, &[]);
                        self.calls[at] += 1;
                        self.flush_calls(at);
                    }
                }
            }
        }
        let mut row = Row {
            cycle,
            pc,
            next_pc,
            present: 0,
            queries: [Query::ABSENT; 8],
        };
        for role in ROLES {
            if let Some((addr, read, write)) = queries.queries[role as usize] {
                let event =
                    self.memory
                        .record(role.space(), addr, base + role.delta(), read, write);
                row.queries[role as usize] = Query {
                    addr,
                    read_ts: event.read_ts,
                    read_value: read,
                    write_value: write,
                };
                row.present |= 1 << role as u8;
            }
        }
        let owner = self.owner(pc, instr);
        let at = self
            .traces
            .families
            .iter()
            .position(|t| t.family == owner)
            .expect("the owning family has a buffer");
        self.traces.families[at].push(&row);
        self.family_rows[at] += 1;
        self.flush_family(at);
    }

    /// Hand `traces.families[at]` away if it has just reached its height, so a
    /// partial buffer never holds more than `height - 1` rows at a record
    /// boundary — which is what makes a shard's rows exactly the cut
    /// `docs/spec/streaming.md` §4 defines, with nothing to split.
    ///
    /// A whole-run recorder flushes nothing: `Keep::Whole` is the archive's
    /// input and holds every row.
    fn flush_family(&mut self, at: usize) {
        if !matches!(self.memory, Keep::Streaming(_)) {
            return;
        }
        let buffer = &mut self.traces.families[at];
        let height = buffer.height as usize;
        if buffer.len() < height {
            return;
        }
        let (family, rows) = (buffer.family, self.family_rows[at]);
        let full = std::mem::replace(buffer, FamilyTrace::new(family, height as u32));
        self.ready.push(ShardChunk {
            family,
            index: (rows / height as u64 - 1) as u32,
            rows: full,
            calls: None,
        });
    }

    /// Hand `traces.delegations[at]` away if it holds a shard's entries: its
    /// height over the family's rows an entry. As [`Recorder::flush_family`].
    fn flush_calls(&mut self, at: usize) {
        if !matches!(self.memory, Keep::Streaming(_)) {
            return;
        }
        let buffer = &self.traces.delegations[at];
        let per = (buffer.height / program::delegation_rows(buffer.family)) as usize;
        if buffer.len() < per {
            return;
        }
        let (family, height, words) = (buffer.family, buffer.height, buffer.words.len());
        let full = std::mem::replace(
            &mut self.traces.delegations[at],
            DelegationTrace::new(family, height, words),
        );
        self.ready.push(ShardChunk {
            family,
            index: (self.calls[at] / per as u64 - 1) as u32,
            rows: FamilyTrace::new(family, height),
            calls: Some(full),
        });
    }

    /// Every partial buffer as a final shard, in family order: what an
    /// execution's last, short shard of each family is.
    fn flush_partial(&mut self) -> Vec<ShardChunk> {
        let mut out = Vec::new();
        for (at, buffer) in self.traces.families.iter_mut().enumerate() {
            if buffer.is_empty() {
                continue;
            }
            let (family, height) = (buffer.family, buffer.height);
            let full = std::mem::replace(buffer, FamilyTrace::new(family, height));
            out.push(ShardChunk {
                family,
                index: (self.family_rows[at] / height as u64) as u32,
                rows: full,
                calls: None,
            });
        }
        for (at, buffer) in self.traces.delegations.iter_mut().enumerate() {
            if buffer.is_empty() {
                continue;
            }
            let (family, height, words) = (buffer.family, buffer.height, buffer.words.len());
            let per = (height / program::delegation_rows(family)) as u64;
            let full = std::mem::replace(buffer, DelegationTrace::new(family, height, words));
            out.push(ShardChunk {
                family,
                index: (self.calls[at] / per) as u32,
                rows: FamilyTrace::new(family, height),
                calls: Some(full),
            });
        }
        out
    }

    /// The execution's cycle profile: every buffer's total row count, flushed
    /// shards included, ascending by family id — the shape
    /// `FamilyTraces::row_counts` has.
    fn profile(&self) -> CycleProfile {
        let mut counts: Vec<(FamilyId, u64)> = self
            .traces
            .families
            .iter()
            .zip(&self.family_rows)
            .map(|(t, n)| (t.family, *n))
            .chain(
                self.traces
                    .delegations
                    .iter()
                    .zip(&self.calls)
                    .map(|(t, n)| (t.family, n * program::delegation_rows(t.family) as u64)),
            )
            .collect();
        counts.sort_by_key(|(f, _)| *f);
        CycleProfile { counts }
    }

    /// The one family whose table claims `pc`, by family id.
    fn owner(&self, pc: u32, instr: Instr) -> FamilyId {
        let row = (pc / 2) as usize;
        let mut owners = self
            .tables
            .families
            .iter()
            .enumerate()
            .filter(|(_, t)| t.is_live(row));
        let (_at, table) = owners.next().unwrap_or_else(|| {
            panic!(
                "routing: pc {pc:#010x} is claimed by no family, so the decoded tables \
                 are not this program's"
            )
        });
        assert!(
            owners.next().is_none(),
            "routing: pc {pc:#010x} is claimed by two families"
        );
        assert_eq!(
            table.family,
            row_kind(&instr).0,
            "routing: the table claiming pc {pc:#010x} is not the family of the \
             instruction there"
        );
        table.family
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use loader::Segment;

    /// `addi a0, a0, 1` then `jal x0, -4`: an endless loop, two cycles a lap.
    fn spin() -> ProgramImage {
        let words: [u32; 2] = [0x0015_0513, 0xffdf_f06f];
        let mut bytes = Vec::new();
        for w in words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        ProgramImage {
            entry: guest_memory::RAM_ORIGIN,
            segments: vec![Segment {
                vaddr: guest_memory::RAM_ORIGIN,
                mem_len: 8,
                bytes,
            }],
            slot_base: guest_memory::RAM_ORIGIN,
            slots: vec![
                Slot::Instruction {
                    word: words[0],
                    compressed: false,
                },
                Slot::MidInstruction,
                Slot::Instruction {
                    word: words[1],
                    compressed: false,
                },
                Slot::MidInstruction,
            ],
            delegations: Vec::new(),
        }
    }

    /// The last cycle whose four timestamps fit the 38-bit clock runs; the
    /// next is refused, by name, before anything is recorded for it.
    #[test]
    fn the_clock_refuses_the_first_cycle_past_38_bits() {
        let io = GuestIo {
            input: Vec::new(),
            advice: Vec::new(),
        };
        let image = spin();
        let mut machine = Machine::new(&image, &io);
        let last = (1u64 << (memory::TS_BITS - 2)) - 1;
        machine.cycle = last;
        machine
            .step()
            .expect("cycle 2^36 - 1 ends at ts 2^38 - 1, on the clock");
        assert_eq!(
            machine.step(),
            Err(EmuError::ClockOverflow { cycle: last + 1 })
        );
    }

    /// A full advice region, `ADVICE_WORDS` words from `ADVICE_ORIGIN`, ends at
    /// `2^32`: its last word loads, and a region one word shorter refuses that
    /// word by name. The bound is set on the machine rather than reached by
    /// supplying the advice, which would take 2 GiB.
    #[test]
    fn a_full_advice_region_reaches_the_top_of_the_address_space() {
        let io = GuestIo {
            input: Vec::new(),
            advice: Vec::new(),
        };
        let image = spin();
        let mut machine = Machine::new(&image, &io);
        let full = guest_memory::ADVICE_ORIGIN as u64 + 4 * guest_memory::ADVICE_WORDS as u64;
        assert_eq!(full, 1 << 32);
        let (first, last) = (guest_memory::ADVICE_ORIGIN, u32::MAX - 3);
        machine.advice_end = full;
        assert_eq!(machine.data_word(0, first as u64, 4), Ok(first));
        assert_eq!(machine.data_word(0, last as u64, 4), Ok(last));
        machine.advice_end = full - 4;
        assert_eq!(
            machine.data_word(0, last as u64, 4),
            Err(EmuError::OutOfBounds {
                pc: 0,
                addr: last as u64
            })
        );
        // A doubleword whose high word is past the advice the host supplied.
        assert_eq!(
            machine.data_word(0, last as u64 - 4, 8),
            Err(EmuError::OutOfBounds {
                pc: 0,
                addr: last as u64 - 4
            })
        );
        // And an address at or above 2^32, which no region holds.
        assert_eq!(
            machine.data_word(0, 1 << 32, 4),
            Err(EmuError::OutOfBounds {
                pc: 0,
                addr: 1 << 32
            })
        );
    }

    /// `merkle_root` answers the fold of the permutation up the path its frame
    /// names, siblings just below the frame included, and refuses by name each
    /// frame its caller owes it not to send.
    #[test]
    fn merkle_root_answers_its_path_and_refuses_what_its_caller_owes() {
        let io = GuestIo {
            input: Vec::new(),
            advice: Vec::new(),
        };
        let image = spin();
        let mut machine = Machine::new(&image, &io);
        let base = guest_memory::RAM_ORIGIN + 0x2000;
        let below = base - 64 * 16;
        for j in 0..16 * 16 {
            machine.set_word(below + 4 * j, j.wrapping_mul(0x9e37_79b9) | 1);
        }
        let frame = |slot: u32, depth: u32, siblings: u32| {
            let mut f: Vec<u32> = (0..16).map(|i| 7 * i + 1).collect();
            f.extend([slot, depth, siblings]);
            f
        };
        let lanes = |w: &[u32]| -> Vec<Fp> {
            (0..8)
                .map(|i| Fp::from_u64(w[2 * i] as u64 | (w[2 * i + 1] as u64) << 32))
                .collect()
        };
        let slot = 0b1011_0000_0000_0110;
        let mut node = lanes(&frame(0, 0, 0)[..16]);
        for level in 0..16 {
            let words: Vec<u32> = (0..16)
                .map(|j| machine.word(below + 64 * level + 4 * j))
                .collect();
            let sibling = lanes(&words);
            let (l, r) = match slot >> level & 1 {
                0 => (&node, &sibling),
                _ => (&sibling, &node),
            };
            let mut state: [Fp; 16] = std::array::from_fn(|i| if i < 8 { l[i] } else { r[i - 8] });
            transcript::poseidon2_permute(&mut state);
            node = state[..8].to_vec();
        }
        let (new, levels) = machine
            .merkle_root(0, base, &frame(slot, 16, below))
            .expect("a path clear of its frame");
        assert_eq!(lanes(&new[..16]), node, "the root is the fold");
        assert_eq!(
            new[16..],
            frame(slot, 16, below)[16..],
            "the rest written back"
        );
        assert_eq!(levels.len(), 16);
        let refused = |slot, depth, siblings| {
            machine
                .merkle_root(0, base, &frame(slot, depth, siblings))
                .err()
        };
        let frame_error = |detail| Some(EmuError::DelegationFrame { pc: 0, detail });
        let depth = "merkle_root's depth is outside 16..=32";
        let overlap = "merkle_root's siblings overlap its frame";
        assert_eq!(refused(0, 15, below), frame_error(depth));
        assert_eq!(refused(0, 33, below), frame_error(depth));
        assert_eq!(
            refused(1 << 16, 16, below),
            frame_error("merkle_root's slot is not below 2^depth")
        );
        assert_eq!(refused(0, 16, base + 72), frame_error(overlap));
        assert_eq!(refused(0, 16, below + 4), frame_error(overlap));
        let addr = below as u64 - 1022;
        assert_eq!(
            refused(0, 16, below - 1022),
            Some(EmuError::Misaligned {
                pc: 0,
                addr,
                width: 4
            })
        );
        assert_eq!(
            refused(0, 16, 0x7000),
            Some(EmuError::OutOfBounds {
                pc: 0,
                addr: 0x7000
            })
        );
    }

    /// `‖s1‖²` by its definition, written apart from [`falcon512_s1`]: the
    /// whole product `s2·h`, of degree 1,022, folded by `x^512 = −1`, and each
    /// coefficient of `c − s2·h` mod `q` taken at its least absolute value.
    fn falcon512_norm(h: &[u16; 512], s2: &[u16; 512], c: &[u16; 512]) -> u64 {
        let q = 12289u64;
        let mut whole = [0u64; 1023];
        for (i, a) in s2.iter().enumerate() {
            for (j, b) in h.iter().enumerate() {
                whole[i + j] += (*a as u64 % q) * (*b as u64 % q) % q;
            }
        }
        (0..512)
            .map(|t| {
                let wrapped = whole.get(t + 512).map_or(0, |x| x % q);
                let product = (whole[t] % q + q - wrapped) % q;
                let s = (c[t] as u64 % q + q - product) % q;
                s.min(q - s).pow(2)
            })
            .sum()
    }

    /// `FALCON512` answers `‖s1‖²` of the arrays its frame names, `h` in the
    /// advice: held to [`falcon512_norm`] over arbitrary halfwords, most of
    /// them at or above `q`, and by hand where the product wraps. It reads each
    /// array word once, in chain order, and leaves it, and writes the norm's
    /// two words. It refuses by name what its caller owes: a frame reaching
    /// the advice, an array misaligned, overlapping another or the frame, and
    /// a word no load could read. An array ending at the frame, and a frame
    /// ending at the advice, are a call's.
    #[test]
    fn falcon512_answers_the_norm_and_refuses_what_its_caller_owes() {
        let coefficient = |a: u32, t: u32| match t {
            0 => u16::MAX,
            _ => ((t + 1).wrapping_mul(0x9e37_79b9) >> 16 ^ a << 13) as u16,
        };
        let poly = |a: u32| -> [u16; 512] { std::array::from_fn(|t| coefficient(a, t as u32)) };
        let (h, s2, c) = (poly(0), poly(1), poly(2));
        let io = GuestIo {
            input: Vec::new(),
            advice: h.iter().flat_map(|x| x.to_le_bytes()).collect(),
        };
        let image = spin();
        let mut machine = Machine::new(&image, &io);
        let word = |p: &[u16; 512], i: usize| p[2 * i] as u32 | (p[2 * i + 1] as u32) << 16;
        let put = |machine: &mut Machine, at: u32, p: &[u16; 512]| {
            for i in 0..256 {
                machine.set_word(at + 4 * i as u32, word(p, i));
            }
        };
        let base = guest_memory::RAM_ORIGIN + 0x2000;
        let (h_at, s2_at, c_at) = (guest_memory::ADVICE_ORIGIN + 4, base + 0x400, base - 0x400);
        put(&mut machine, s2_at, &s2);
        put(&mut machine, c_at, &c);
        let falcon = |machine: &mut Machine, base: u32, arrays: [u32; 3]| {
            let frame = [arrays[0], arrays[1], arrays[2], 0xdead_beef, 0x1234_5678];
            for (j, w) in frame.iter().enumerate() {
                machine.set_word(base + 4 * j as u32, *w);
            }
            machine.delegate(ecall::FALCON512, constants::family::FALCON, 0, base as u64)
        };

        let call = falcon(&mut machine, base, [h_at, s2_at, c_at]).expect("a call");
        let n = falcon512_norm(&h, &s2, &c);
        assert!(n >> 32 != 0, "the norm {n} has a high word");
        let frame: Vec<(u32, u32, u32)> = [h_at, s2_at, c_at, n as u32, (n >> 32) as u32]
            .iter()
            .zip([h_at, s2_at, c_at, 0xdead_beef, 0x1234_5678])
            .enumerate()
            .map(|(j, (new, old))| (base + 4 * j as u32, old, *new))
            .collect();
        assert_eq!(
            call.frame, frame,
            "the arrays' addresses kept, the norm written"
        );
        let arrays: Vec<(u32, u32)> = [(s2_at, &s2), (h_at, &h), (c_at, &c)]
            .iter()
            .flat_map(|(at, p)| (0..256).map(move |i| (at + 4 * i as u32, word(p, i))))
            .collect();
        assert_eq!(
            call.arrays, arrays,
            "s2's, h's and c's words, each as it was"
        );
        assert!(call.levels.is_empty());
        for (addr, w) in &arrays {
            assert_eq!(machine.word(*addr), *w, "{addr:#x} left as it was");
        }

        // s2 = x and h = x^511 wrap to −1, so s1 = c + 1: with c_0 = 6144,
        // s1_0 = 6145, centered to −6144. Each halfword read mod q.
        let q = 12289u16;
        let mut wrap = [[0u16; 512]; 3];
        wrap[0][511] = q + 1;
        wrap[1][1] = 1;
        wrap[2][0] = q + 6144;
        let at = [base + 0x800, base + 0xc00, base + 0x1000];
        for (p, a) in wrap.iter().zip(at) {
            put(&mut machine, a, p);
        }
        let end = guest_memory::ADVICE_ORIGIN - 20;
        for b in [base, end] {
            let call = falcon(&mut machine, b, at).expect("a call");
            let n = call.frame[3].2 as u64 | (call.frame[4].2 as u64) << 32;
            assert_eq!(n, 6144 * 6144, "a frame at {b:#x}");
        }

        let mut refused = |arrays: [u32; 3]| falcon(&mut machine, base, arrays).err();
        let frame_error = |detail| Some(EmuError::DelegationFrame { pc: 0, detail });
        let overlap = "falcon512's arrays overlap";
        let over_frame = "falcon512's array overlaps its frame";
        assert_eq!(
            refused([h_at + 2, s2_at, c_at]),
            frame_error("falcon512's array is not word-aligned")
        );
        assert_eq!(refused([h_at, s2_at, s2_at]), frame_error(overlap));
        assert_eq!(refused([s2_at + 1020, s2_at, c_at]), frame_error(overlap));
        assert_eq!(refused([h_at, s2_at, base - 1020]), frame_error(over_frame));
        assert_eq!(refused([h_at, base + 16, c_at]), frame_error(over_frame));
        let addr = guest_memory::ADVICE_ORIGIN as u64 + 4 + 1024;
        assert_eq!(
            refused([h_at + 4, s2_at, c_at]),
            Some(EmuError::OutOfBounds { pc: 0, addr })
        );
        assert_eq!(
            refused([0x7000, s2_at, c_at]),
            Some(EmuError::OutOfBounds {
                pc: 0,
                addr: 0x7000
            })
        );
        let past = guest_memory::ADVICE_ORIGIN as u64 - 16;
        assert_eq!(
            machine
                .delegate(ecall::FALCON512, constants::family::FALCON, 0, past)
                .err(),
            Some(EmuError::OutOfBounds { pc: 0, addr: past })
        );
    }

    /// `FALCON512_SAMPLE` writes each lane below `T = 808·q^4` over its two
    /// words as its base-`q` digits `⌊x/q^j⌋ mod q`, two a word: lanes at 0,
    /// 1, `q^4 − 1`, `q^4` and `T − 1`, and arbitrary ones. It refuses `T`,
    /// the first lane HashToPoint skips, and `2^64 − 1`, by name, writing
    /// nothing.
    #[test]
    fn falcon512_sample_writes_each_lanes_digits_and_refuses_one_at_t() {
        let (q, q4) = (12289u64, 12289u64.pow(4));
        let t = 808 * q4;
        let io = GuestIo {
            input: Vec::new(),
            advice: Vec::new(),
        };
        let image = spin();
        let mut machine = Machine::new(&image, &io);
        let base = guest_memory::RAM_ORIGIN + 0x2000;
        let sample = |machine: &mut Machine, lanes: [u64; 8]| {
            for (l, x) in lanes.iter().enumerate() {
                machine.set_word(base + 8 * l as u32, *x as u32);
                machine.set_word(base + 8 * l as u32 + 4, (x >> 32) as u32);
            }
            let (number, family) = (ecall::FALCON512_SAMPLE, constants::family::FALCON_SAMPLE);
            machine.delegate(number, family, 0, base as u64)
        };
        let lanes = [
            0,
            1,
            q4 - 1,
            q4,
            t - 1,
            0x0123_4567_89ab_cdef,
            t / 3,
            t - q4,
        ];
        let call = sample(&mut machine, lanes).expect("a call");
        let frame: Vec<(u32, u32, u32)> = lanes
            .iter()
            .flat_map(|x| {
                let d = |j: u32| (x / q.pow(j) % q) as u32;
                [
                    (*x as u32, d(0) | d(1) << 16),
                    ((x >> 32) as u32, d(2) | d(3) << 16),
                ]
            })
            .enumerate()
            .map(|(j, (old, new))| (base + 4 * j as u32, old, new))
            .collect();
        assert_eq!(call.frame, frame, "each lane its digits, two a word");
        assert!(call.levels.is_empty() && call.arrays.is_empty());
        for (addr, _, new) in &frame {
            assert_eq!(machine.word(*addr), *new, "{addr:#x} written");
        }

        let detail = "falcon512_sample's lane is not below 808·q^4";
        for x in [t, u64::MAX] {
            let mut lanes = lanes;
            lanes[5] = x;
            assert_eq!(
                sample(&mut machine, lanes).err(),
                Some(EmuError::DelegationFrame { pc: 0, detail }),
                "the lane {x:#x}"
            );
            for (l, x) in lanes.iter().enumerate() {
                let at = base + 8 * l as u32;
                assert_eq!(machine.word(at), *x as u32, "{at:#x} as it was");
            }
        }
    }
}
