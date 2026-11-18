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

use std::collections::{HashMap, HashSet};
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
/// [`MemoryState`]. A delegation family's chunk carries its entries, calls,
/// arrays or ops, in `calls` and no `rows`, its shard being
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
/// `(address, old, new)` per frame word in frame order, a call's arrays, a
/// decode call's stream, a program's ops, and what the call's entry carries:
/// an `MPT_ROOT` call's last `pending` (`delegation::mpt::CALL_CARRY`),
/// nothing for any other.
struct Invocation {
    number: u32,
    base: u32,
    frame: Vec<(u32, u32, u32)>,
    arrays: ArrayWords,
    stream: StreamWords,
    ops: Vec<Op>,
    carry: Vec<u64>,
}

/// A `FALCON512` call's arrays: `(address, word)` per word, in
/// `delegation::falcon::CHAINS` order, each read and left as it was.
type ArrayWords = Vec<(u32, u32)>;

/// A `FALCON512_DECODE` call's words past its frame, `(address, old, new)` in
/// entry order (`delegation::Per::Decode`): the polynomial's
/// `delegation::falcon_decode::OUTPUT`, each its old value and a coefficient
/// pair, then the source words the stream reached, in address order, each
/// left as it was.
type StreamWords = Vec<(u32, u32, u32)>;

/// One op of an `MPT_ROOT` program: its address, its info and arg words, its
/// block's words where it reads one, which a JOIN does not, each read and
/// left as it was, and what its entry carries (`delegation::mpt::CARRY`).
struct Op {
    at: u32,
    info: u32,
    arg: u32,
    block: Option<[u32; delegation::mpt::BLOCK]>,
    carry: [u64; delegation::mpt::CARRY],
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
    /// in place, returning each frame word as `(address, old, new)`, a call's
    /// arrays, a decode call's stream and a program's ops.
    ///
    /// Every frame word must be one a store could write, below the advice
    /// region; anything else is a fatal guest error, as a misaligned store is.
    /// What the call computes is [`frame_function`]'s, or for the calls that
    /// touch RAM past their frames, `FALCON512`, `FALCON512_DECODE` and
    /// `MPT_ROOT`, [`Machine::falcon512`]'s, [`Machine::falcon512_decode`]'s
    /// and [`Machine::mpt_root`]'s.
    fn delegate(
        &mut self,
        number: u32,
        family: FamilyId,
        pc: u32,
        base: u64,
    ) -> Result<Invocation, EmuError> {
        // A decode call's entry is its frame and its stream; only the frame is
        // at `base` (`delegation::Per::Decode`).
        let words = match family {
            constants::family::FALCON_DECODE => delegation::falcon_decode::FRAME,
            _ => program::delegation_frame_words(family).expect("a delegation family"),
        };
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
        let (mut arrays, mut stream) = (Vec::new(), Vec::new());
        let (mut ops, mut carry) = (Vec::new(), Vec::new());
        let new = match family {
            constants::family::FALCON => {
                let (new, words) = self.falcon512(pc, base, &old)?;
                arrays = words;
                new
            }
            constants::family::FALCON_DECODE => {
                let (new, words) = self.falcon512_decode(pc, base, &old)?;
                stream = words;
                new
            }
            constants::family::MPT => {
                let (new, program, pending) = self.mpt_root(pc, base, &old)?;
                (ops, carry) = (program, vec![pending]);
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
        for &(addr, _, new) in &stream {
            self.set_word(addr, new);
        }
        Ok(Invocation {
            number,
            base,
            frame,
            arrays,
            stream,
            ops,
            carry,
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

    /// The `FALCON512_DECODE` call over the frame at `base`, whose words are
    /// `frame`: the encoding at its source decoded in its mode by
    /// [`falcon512_decode`] into the polynomial at its destination, `‖s2‖²`
    /// and the stream's end written over its words `MODE` and `END`; and the
    /// call's [`StreamWords`] (`constants::delegation::falcon_decode`).
    ///
    /// The source is read a word at a time, each word checked as a load's,
    /// the advice included, and only as far as the stream reaches: the words
    /// `0..=⌊(end − 1)/32⌋`, which the caller owes readable. The destination's
    /// 256 words are checked as stores'. The caller owes both word-aligned,
    /// the destination apart from the frame and from the source words read,
    /// and those apart from the frame: the call touches each word at one
    /// timestamp. Any other frame is refused, and any stream that is not an
    /// encoding.
    fn falcon512_decode(
        &self,
        pc: u32,
        base: u32,
        frame: &[u32],
    ) -> Result<(Vec<u32>, StreamWords), EmuError> {
        use delegation::falcon_decode::{
            DST, END, FRAME, KEY, MODE, OUTPUT, SIGNATURE, SIGNATURE_BITS, SOURCE, SRC,
        };
        let refuse = |detail| Err(EmuError::DelegationFrame { pc, detail });
        // Each range as bytes `[start, end)` in 64 bits, as `falcon512`'s.
        let span = |at: u32, words: usize| (at as u64, at as u64 + 4 * words as u64);
        let apart = |(a, b): (u64, u64), (c, d): (u64, u64)| b <= c || d <= a;
        let (src, dst, mode) = (frame[SRC], frame[DST], frame[MODE]);
        if !src.is_multiple_of(4) {
            return refuse("falcon512_decode's source is not word-aligned");
        }
        if !dst.is_multiple_of(4) {
            return refuse("falcon512_decode's destination is not word-aligned");
        }
        let output = span(dst, OUTPUT);
        if !apart(output, span(base, FRAME)) {
            return refuse("falcon512_decode's destination overlaps its frame");
        }
        // The words the stream may reach, a key's `SOURCE` or a signature's
        // 157, none in a mode the decoder refuses, up to the first no load
        // reaches: the call's fault only if the stream reaches it.
        let most = match mode {
            KEY => SOURCE,
            SIGNATURE => SIGNATURE_BITS.div_ceil(32) as usize,
            _ => 0,
        };
        let (mut source, mut fault) = (Vec::with_capacity(most), None);
        for i in 0..most as u64 {
            match self.data_word(pc, src as u64 + 4 * i, 4) {
                Ok(addr) => source.push(self.word(addr)),
                Err(e) => {
                    fault = Some(e);
                    break;
                }
            }
        }
        let decoded = falcon512_decode(mode, &source).map_err(|detail| match fault {
            Some(e) if detail == SHORT => e,
            _ => EmuError::DelegationFrame { pc, detail },
        })?;
        let read = span(src, decoded.read);
        if !apart(read, span(base, FRAME)) {
            return refuse("falcon512_decode's source overlaps its frame");
        }
        if !apart(output, read) {
            return refuse("falcon512_decode's destination overlaps its source");
        }
        // Coefficient `2i` is word `i`'s low halfword.
        let mut stream = Vec::with_capacity(OUTPUT + decoded.read);
        for (i, pair) in decoded.coefficients.chunks_exact(2).enumerate() {
            let addr = self.data_word(pc, output.0 + 4 * i as u64, 4)?;
            let new = pair[0] as u32 | (pair[1] as u32) << 16;
            stream.push((addr, self.word(addr), new));
        }
        // Every word read is below `2^32`: a load reached it.
        let words = source[..decoded.read].iter().enumerate();
        stream.extend(words.map(|(i, w)| (src + 4 * i as u32, *w, *w)));
        let mut new = frame.to_vec();
        new[MODE] = decoded.norm;
        new[END] = decoded.end;
        Ok((new, stream))
    }

    /// The `MPT_ROOT` call over the frame at `base`, whose words are `frame`:
    /// the root of the op program it names written over its lanes, each op's
    /// words and carry, and the last op's `pending`, which the call's entry
    /// carries (`constants::delegation::mpt`).
    ///
    /// The value `cur` is its raw lanes with `pending` added to lane 0, zero
    /// to start. Op `i` parks the `cur` entering it where its park bit is
    /// set. A LOAD makes the raw lanes its block's and `pending` 0; a SIB or
    /// a JOIN makes them `guest_sdk::poseidon2_compress` of `cur` and the
    /// other child, the other on the left where the left bit is set, and
    /// `pending` `d + 1`. A SIB's other child is its block, a JOIN's the value
    /// the op its arg names parked. A block's lanes are read mod `p`, so a
    /// block may be anywhere a load reaches, advice included; each of its
    /// words and each op's is checked as a load's. The caller owes 1 to `2^20`
    /// word-aligned ops whose info words decode, word-aligned blocks, each
    /// park taken by exactly one later JOIN, and no word read twice across the
    /// frame, the ops and the blocks, which the call reads at one timestamp;
    /// any other program is refused.
    fn mpt_root(
        &self,
        pc: u32,
        base: u32,
        frame: &[u32],
    ) -> Result<(Vec<u32>, Vec<Op>, u64), EmuError> {
        use delegation::mpt::{
            BLOCK, CARRY, COUNT, DEPTH_BOUND, DEPTH_SHIFT, JOIN, LEFT, LOAD, MAX_OPS, OPS, PARK,
            ROOT,
        };
        let refuse = |detail| EmuError::DelegationFrame { pc, detail };
        let (ops, n) = (frame[OPS], frame[COUNT]);
        if !(1..=MAX_OPS).contains(&n) {
            return Err(refuse("mpt_root's count is outside 1..=2^20"));
        }
        if !ops.is_multiple_of(4) {
            return Err(refuse("mpt_root's ops are not word-aligned"));
        }
        // Every word the call reads, each once: the frame's, then each op's
        // and its block's as the program reaches them.
        let mut read: HashSet<u32> = (0..frame.len() as u32).map(|j| base + 4 * j).collect();
        let mut load = |addr: u64| match self.data_word(pc, addr, 4)? {
            word if read.insert(word) => Ok(self.word(word)),
            _ => Err(refuse("mpt_root reads a word twice")),
        };
        let lanes = |w: &[u32]| -> [Fp; 8] {
            std::array::from_fn(|k| Fp::from_u64(w[2 * k] as u64 | (w[2 * k + 1] as u64) << 32))
        };
        // The parks by op, each `None` once a JOIN has taken it.
        let mut parked: HashMap<u32, Option<[Fp; 8]>> = HashMap::new();
        let (mut raw, mut pending) = ([Fp::ZERO; 8], 0u64);
        let mut program = Vec::new();
        for i in 0..n {
            let at = ops as u64 + 8 * i as u64;
            let (info, arg) = (load(at)?, load(at + 4)?);
            let kind = info & 3;
            if kind > JOIN || info >= DEPTH_BOUND << DEPTH_SHIFT {
                return Err(refuse("mpt_root's info word does not decode"));
            }
            let mut cur = raw;
            cur[0] += Fp::from_u64(pending);
            let mut carry = [0u64; CARRY];
            for (c, x) in carry.iter_mut().zip(raw) {
                *c = x.to_u64();
            }
            carry[8] = pending;
            carry[9] = i as u64;
            let (other, block) = match kind {
                JOIN => {
                    let value = match parked.get_mut(&arg).map(Option::take) {
                        Some(Some(value)) => value,
                        Some(None) => return Err(refuse("mpt_root's JOIN takes a park twice")),
                        None => return Err(refuse("mpt_root's JOIN names no earlier park")),
                    };
                    for (c, x) in carry[10..].iter_mut().zip(value) {
                        *c = x.to_u64();
                    }
                    (value, None)
                }
                _ => {
                    if !arg.is_multiple_of(4) {
                        return Err(refuse("mpt_root's block is not word-aligned"));
                    }
                    let mut words = [0u32; BLOCK];
                    for (j, w) in words.iter_mut().enumerate() {
                        *w = load(arg as u64 + 4 * j as u64)?;
                    }
                    (lanes(&words), Some(words))
                }
            };
            // After the JOIN's take, which an op's own park cannot answer.
            if info & PARK != 0 {
                parked.insert(i, Some(cur));
            }
            (raw, pending) = match kind {
                LOAD => (other, 0),
                _ => {
                    let (l, r) = match info & LEFT {
                        0 => (cur, other),
                        _ => (other, cur),
                    };
                    let mut state: [Fp; 16] =
                        std::array::from_fn(|k| if k < 8 { l[k] } else { r[k - 8] });
                    transcript::poseidon2_permute(&mut state);
                    let d = (info >> DEPTH_SHIFT) as u64;
                    (std::array::from_fn(|k| state[k]), d + 1)
                }
            };
            program.push(Op {
                at: at as u32,
                info,
                arg,
                block,
                carry,
            });
        }
        if parked.values().any(Option::is_some) {
            return Err(refuse("mpt_root leaves a park no JOIN takes"));
        }
        let mut new = frame.to_vec();
        raw[0] += Fp::from_u64(pending);
        for (k, x) in raw.iter().enumerate() {
            new[ROOT + 2 * k] = x.to_u64() as u32;
            new[ROOT + 2 * k + 1] = (x.to_u64() >> 32) as u32;
        }
        Ok((new, program, pending))
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

/// [`falcon512_decode`]'s answer: the polynomial `FALCON512_DECODE` writes at
/// its destination, the two words it writes over its frame, and how much of
/// its source it reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FalconDecode {
    /// The coefficients, each below `q`: a key's fields, or each of a
    /// signature's `s` as `s mod q`.
    pub coefficients: [u16; delegation::falcon::N],
    /// `‖s2‖² = Σ s²`, at most `512 · 2047² < 2^31`; 0 for a key.
    pub norm: u32,
    /// The stream's end, the bit after the last coefficient's, counted from
    /// the source's first: a key's `KEY_END`, a signature's at most
    /// `SIGNATURE_BITS`.
    pub end: u32,
    /// The source words the call reads, `⌊(end − 1)/32⌋ + 1`, the last the one
    /// holding the stream's last bit: a key's `SOURCE`, a signature's at most
    /// 157.
    pub read: usize,
}

/// [`falcon512_decode`]'s refusal of a stream running past its source's
/// words: the executor's load fault, where a load refused the next word.
const SHORT: &str = "falcon512_decode's source ends before its stream";

/// The Falcon-512 encoding `source` holds, decoded in `mode`,
/// `delegation::falcon_decode::KEY` or `SIGNATURE`: `FALCON512_DECODE`'s
/// answer, and the one copy of it, from which the prover's fill takes its
/// rows (`constraints::falcon_decode`).
///
/// `source` is the words as RAM holds them, little-endian: the stream is
/// their bytes in address order, each byte MSB first. A key is `h`'s 512
/// fields of 14 bits, each a coefficient below `q`, and no header. A
/// signature's `s2` is 512 codewords, each a sign bit `b`, the low 7 bits of
/// `|s|`, then `k = |s| >> 7` zeros and a one: `k` at most 15, so `|s|` at
/// most 2047, never `−0` (`b = 1`, `|s| = 0`), and the last codeword ending
/// within `SIGNATURE_BITS`, the bits after it in its word zeros; its
/// coefficient is `|s|`, or `q − |s|` where `b = 1`.
///
/// Refuses anything else by name, and a stream running past `source`. **No
/// word past the one holding the end is read**: a key's end is a word's, and
/// a signature's last word is read whole, a bit set after the end refused.
pub fn falcon512_decode(mode: u32, source: &[u32]) -> Result<FalconDecode, &'static str> {
    use delegation::falcon::{N, Q};
    use delegation::falcon_decode::{KEY, KEY_END, SIGNATURE, SIGNATURE_BITS};
    let limit = match mode {
        KEY => KEY_END,
        SIGNATURE => SIGNATURE_BITS,
        _ => return Err("falcon512_decode's mode is neither a key's nor a signature's"),
    };
    let mut bits = Bits {
        source,
        at: 0,
        limit,
    };
    let (mut coefficients, mut norm) = ([0u16; N], 0u32);
    if mode == KEY {
        for x in &mut coefficients {
            let field = bits.take(14)?;
            if field as u64 >= Q {
                return Err("falcon512_decode's key coefficient is not below q");
            }
            *x = field as u16;
        }
    } else {
        for x in &mut coefficients {
            let head = bits.take(8)?;
            let mut k = 0;
            while bits.take(1)? == 0 {
                k += 1;
                if k > 15 {
                    return Err("falcon512_decode's coefficient is above 2047 in size");
                }
            }
            let (negative, size) = (head >> 7 == 1, (head & 0x7f) + 128 * k);
            if negative && size == 0 {
                return Err("falcon512_decode's coefficient is -0");
            }
            norm += size * size;
            *x = if negative { Q as u32 - size } else { size } as u16;
        }
    }
    // The last word's `rest` bits after the end: zeros. A key ends on a word.
    let (end, read) = (bits.at, bits.at.div_ceil(32) as usize);
    let rest = 32 * read as u32 - end;
    if source[read - 1].swap_bytes() & ((1 << rest) - 1) != 0 {
        return Err("falcon512_decode's signature has a bit set after its end");
    }
    Ok(FalconDecode {
        coefficients,
        norm,
        end,
        read,
    })
}

/// [`falcon512_decode`]'s place in its stream: `at` bits taken, none at or
/// past `limit`.
struct Bits<'a> {
    source: &'a [u32],
    at: u32,
    limit: u32,
}

impl Bits<'_> {
    /// The next `n` bits, `1 ≤ n ≤ 32`, MSB first. Word `i`'s bytes reversed
    /// are the stream's bits `32i..32i + 32`, and a word is read only where
    /// one of the `n` is in it. A key takes exactly its `limit`, `KEY_END`, so
    /// only a signature can pass it.
    fn take(&mut self, n: u32) -> Result<u32, &'static str> {
        if self.at + n > self.limit {
            return Err("falcon512_decode's signature runs past 5000 bits");
        }
        let limb = |i: u32| {
            let word = self.source.get(i as usize).ok_or(SHORT);
            word.map(|w| w.swap_bytes() as u64)
        };
        let (i, o) = (self.at / 32, self.at % 32);
        let pair = limb(i)? << 32 | if o + n > 32 { limb(i + 1)? } else { 0 };
        self.at += n;
        Ok((pair << o >> (64 - n)) as u32)
    }
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
        // its arrays', its stream's or its ops' after its frame's. Every
        // family of the number records the call, its arrays, its frame and
        // stream, each of its ops, or each of its hash ops.
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
            let arrays: Vec<Query> = call.arrays.iter().map(|&(a, w)| query(a, w, w)).collect();
            let stream: Vec<Query> = call
                .stream
                .iter()
                .map(|&(a, r, w)| query(a, r, w))
                .collect();
            // An op's info and arg, then its block's words, or for a JOIN,
            // which reads none, slots `Query::ABSENT`, which no event records.
            let mut ops: Vec<Vec<Query>> = Vec::with_capacity(call.ops.len());
            for op in &call.ops {
                let mut words = vec![query(op.at, op.info, op.info)];
                words.push(query(op.at + 4, op.arg, op.arg));
                match op.block {
                    Some(block) => {
                        for (j, w) in (0..).zip(block) {
                            words.push(query(op.arg + 4 * j, w, w));
                        }
                    }
                    None => words.resize(delegation::mpt::OP_WORDS, Query::ABSENT),
                }
                ops.push(words);
            }
            for family in program::delegation_families(call.number) {
                let at = self
                    .traces
                    .delegations
                    .iter()
                    .position(|t| t.family == family)
                    .expect("a declared number declares all its families");
                let per = program::delegation_per(family);
                match per {
                    Per::Call => {
                        self.traces.delegations[at].push(cycle, call.base, &words, &call.carry);
                        self.calls[at] += 1;
                        self.flush_calls(at);
                    }
                    // One entry: the frame's words, then the stream's, the
                    // source slots past the words it read `Query::ABSENT`,
                    // which no event records.
                    Per::Decode => {
                        let mut entry = [&words[..], &stream[..]].concat();
                        entry.resize(delegation::falcon_decode::WORDS, Query::ABSENT);
                        self.traces.delegations[at].push(cycle, call.base, &entry, &[]);
                        self.calls[at] += 1;
                        self.flush_calls(at);
                    }
                    // One entry an op, or a hash op, its base the op's address.
                    Per::Op | Per::Hash => {
                        for (op, words) in call.ops.iter().zip(&ops) {
                            if per == Per::Hash && op.info & 3 == delegation::mpt::LOAD {
                                continue;
                            }
                            let buffer = &mut self.traces.delegations[at];
                            buffer.push(cycle, op.at, words, &op.carry);
                            self.calls[at] += 1;
                            self.flush_calls(at);
                        }
                    }
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

    /// `F(l ‖ r)`: the permutation's first eight lanes, no feed-forward.
    fn compress(l: [Fp; 8], r: [Fp; 8]) -> [Fp; 8] {
        let mut s: [Fp; 16] = std::array::from_fn(|k| if k < 8 { l[k] } else { r[k - 8] });
        transcript::poseidon2_permute(&mut s);
        std::array::from_fn(|k| s[k])
    }

    /// A trie's branch at crit bit `c`: `F(l ‖ r)`, `c + 1` added to lane 0.
    fn branch(c: u32, l: [Fp; 8], r: [Fp; 8]) -> [Fp; 8] {
        let mut out = compress(l, r);
        out[0] += Fp::from_u64(c as u64 + 1);
        out
    }

    /// The frame at `MPT_FRAME` naming `n` ops at `at`, `ops` written there,
    /// `(info, arg)` each, and the `MPT_ROOT` call over it.
    fn mpt_call(
        machine: &mut Machine,
        at: u32,
        ops: &[(u32, u32)],
        n: u32,
    ) -> Result<(Vec<u32>, Vec<Op>, u64), EmuError> {
        for (i, &(info, arg)) in (0..).zip(ops) {
            machine.set_word(at + 8 * i, info);
            machine.set_word(at + 8 * i + 4, arg);
        }
        let mut frame = vec![at, n];
        frame.extend((0..16).map(|j| 0x5a5a_0000 | j));
        machine.mpt_root(0, MPT_FRAME, &frame)
    }

    const MPT_FRAME: u32 = guest_memory::RAM_ORIGIN + 0x2000;

    /// `mpt_root` answers the trie hash of the programs the SDK emits — a
    /// leaf, a branch with a block on either side, a branch of two subtrees
    /// joined, and those nested, the parked one a branch — with a block's
    /// lanes read mod `p`, and refuses by name each program its caller owes
    /// it not to send.
    #[test]
    fn mpt_root_answers_its_program_and_refuses_what_its_caller_owes() {
        use delegation::mpt::{DEPTH_SHIFT, JOIN, LEFT, LOAD, MAX_OPS, PARK, ROOT, SIB};
        let io = GuestIo {
            input: Vec::new(),
            advice: Vec::new(),
        };
        let image = spin();
        let mut machine = Machine::new(&image, &io);
        let ops_at = MPT_FRAME + 0x1000;
        // Six blocks; block 4's top lane is all ones, `2^64 − 1`, which is 58
        // mod `p`.
        let block = |k: u32| MPT_FRAME + 0x2000 + 64 * k;
        let word = |k: u32, j: u32| match (k, j) {
            (4, 14 | 15) => u32::MAX,
            _ => (16 * k + j + 1).wrapping_mul(0x9e37_79b9),
        };
        for k in 0..6 {
            for j in 0..16 {
                machine.set_word(block(k) + 4 * j, word(k, j));
            }
        }
        let lane = |k: u32, l: u32| {
            Fp::from_u64(word(k, 2 * l) as u64 | (word(k, 2 * l + 1) as u64) << 32)
        };
        let d: Vec<[Fp; 8]> = (0..6)
            .map(|k| std::array::from_fn(|l| lane(k, l as u32)))
            .collect();
        assert_eq!(d[4][7], Fp::from_u64(58));
        let info = |kind: u32, flags: u32, depth: u32| kind | flags | depth << DEPTH_SHIFT;
        let root = |new: &[u32]| -> [u64; 8] {
            std::array::from_fn(|l| new[ROOT + 2 * l] as u64 | (new[ROOT + 2 * l + 1] as u64) << 32)
        };
        let answers = |machine: &mut Machine, ops: &[(u32, u32)], want: [Fp; 8]| {
            let (new, program, pending) =
                mpt_call(machine, ops_at, ops, ops.len() as u32).expect("a program it answers");
            assert_eq!(
                root(&new),
                want.map(Fp::to_u64),
                "{ops:x?}: the root, canonical"
            );
            assert_eq!(
                new[..ROOT],
                [ops_at, ops.len() as u32],
                "the rest written back"
            );
            (program, pending)
        };
        // A leaf: a LOAD's left bit and depth are free.
        answers(&mut machine, &[(info(LOAD, LEFT, 300), block(0))], d[0]);
        // A branch with a block on the right, then on the left.
        let leaf = (LOAD, block(0));
        let right = [leaf, (info(SIB, 0, 5), block(1))];
        answers(&mut machine, &right, branch(5, d[0], d[1]));
        let left = [leaf, (info(SIB, LEFT, 5), block(1))];
        answers(&mut machine, &left, branch(5, d[1], d[0]));
        // Two leaves joined, the left one parked.
        let joined = [
            leaf,
            (info(LOAD, PARK, 0), block(1)),
            (info(JOIN, LEFT, 511), 1),
        ];
        answers(&mut machine, &joined, branch(511, d[0], d[1]));
        // A block whose top lane is at or above `p`.
        let high = [(LOAD, block(4)), (info(SIB, 0, 0), block(5))];
        answers(&mut machine, &high, branch(0, d[4], d[5]));
        // Two branches joined: the parked value is a branch, its `pending` in
        // lane 0.
        let nested = [
            leaf,
            (info(SIB, 0, 9), block(1)),
            (info(LOAD, PARK, 0), block(2)),
            (info(SIB, LEFT, 3), block(3)),
            (info(JOIN, LEFT, 1), 2),
        ];
        let (l, r) = (branch(9, d[0], d[1]), branch(3, d[3], d[2]));
        let (program, pending) = answers(&mut machine, &nested, branch(1, l, r));
        assert_eq!(pending, 2, "the last op's d + 1");
        for (i, op) in (0..).zip(&program) {
            assert_eq!(
                (op.at, op.info, op.arg),
                (ops_at + 8 * i, nested[i as usize].0, nested[i as usize].1)
            );
            assert_eq!(op.carry[8..10], [[0, 0, 10, 0, 4][i as usize], i as u64]);
            match op.info & 3 {
                JOIN => assert_eq!(op.block, None),
                _ => {
                    let k = (op.arg - block(0)) / 64;
                    assert_eq!(op.block, Some(std::array::from_fn(|j| word(k, j as u32))));
                }
            }
        }
        let raw = compress(d[3], d[2]).map(Fp::to_u64);
        assert_eq!(
            program[4].carry[..8],
            raw,
            "the JOIN enters with the SIB's raw lanes"
        );
        assert_eq!(
            program[4].carry[10..],
            l.map(Fp::to_u64),
            "and the branch parked"
        );

        let frame_error = |detail| Some(EmuError::DelegationFrame { pc: 0, detail });
        let refused = |machine: &mut Machine, ops: &[(u32, u32)]| {
            mpt_call(machine, ops_at, ops, ops.len() as u32).err()
        };
        let out_of_bounds = |addr: u32| {
            Some(EmuError::OutOfBounds {
                pc: 0,
                addr: addr as u64,
            })
        };
        let count = "mpt_root's count is outside 1..=2^20";
        assert_eq!(
            mpt_call(&mut machine, ops_at, &[leaf], 0).err(),
            frame_error(count)
        );
        let past = MAX_OPS + 1;
        assert_eq!(
            mpt_call(&mut machine, ops_at, &[leaf], past).err(),
            frame_error(count)
        );
        // `2^20` ops pass the count: op 1, past the top of RAM, stops the call.
        let top = guest_memory::ADVICE_ORIGIN - 8;
        assert_eq!(
            mpt_call(&mut machine, top, &[leaf], MAX_OPS).err(),
            out_of_bounds(guest_memory::ADVICE_ORIGIN)
        );
        let decode = "mpt_root's info word does not decode";
        assert_eq!(refused(&mut machine, &[(3, block(0))]), frame_error(decode));
        assert_eq!(
            refused(&mut machine, &[(1 << 13, block(0))]),
            frame_error(decode)
        );
        // A JOIN of an op that did not park, of its own park, of a later op's.
        let named = frame_error("mpt_root's JOIN names no earlier park");
        assert_eq!(refused(&mut machine, &[leaf, (JOIN, 0)]), named);
        assert_eq!(
            refused(&mut machine, &[leaf, (info(JOIN, PARK, 0), 1)]),
            named
        );
        let later = [leaf, (JOIN, 2), (info(LOAD, PARK, 0), block(1))];
        assert_eq!(refused(&mut machine, &later), named);
        let twice = [
            (info(LOAD, PARK, 0), block(0)),
            (LOAD, block(1)),
            (JOIN, 0),
            (JOIN, 0),
        ];
        assert_eq!(
            refused(&mut machine, &twice),
            frame_error("mpt_root's JOIN takes a park twice")
        );
        assert_eq!(
            refused(&mut machine, &[(info(LOAD, PARK, 0), block(0))]),
            frame_error("mpt_root leaves a park no JOIN takes")
        );
        assert_eq!(
            mpt_call(&mut machine, ops_at + 2, &[leaf], 1).err(),
            frame_error("mpt_root's ops are not word-aligned")
        );
        assert_eq!(
            refused(&mut machine, &[(LOAD, block(0) + 2)]),
            frame_error("mpt_root's block is not word-aligned")
        );
        assert_eq!(
            mpt_call(&mut machine, 0x7000, &[leaf], 1).err(),
            out_of_bounds(0x7000)
        );
        assert_eq!(
            refused(&mut machine, &[(LOAD, 0x7000)]),
            out_of_bounds(0x7000)
        );
        // The advice region, which this run was not given.
        let advice = guest_memory::ADVICE_ORIGIN;
        assert_eq!(
            refused(&mut machine, &[leaf, (SIB, advice)]),
            out_of_bounds(advice)
        );
        // A word read twice: one block twice, two overlapping by a word, a
        // block on the frame's root and on the ops, and ops on the frame.
        let again = frame_error("mpt_root reads a word twice");
        assert_eq!(refused(&mut machine, &[leaf, (SIB, block(0))]), again);
        assert_eq!(refused(&mut machine, &[leaf, (SIB, block(0) + 60)]), again);
        let on_root = MPT_FRAME + 4 * ROOT as u32;
        assert_eq!(refused(&mut machine, &[(LOAD, on_root)]), again);
        assert_eq!(refused(&mut machine, &[leaf, (SIB, ops_at + 8)]), again);
        assert_eq!(
            mpt_call(&mut machine, MPT_FRAME + 64, &[leaf], 1).err(),
            again
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
        assert!(call.arrays.is_empty());
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

    /// `bytes` as RAM holds them: little-endian words, the last zero-padded.
    fn le_words(bytes: &[u8]) -> Vec<u32> {
        bytes
            .chunks(4)
            .map(|c| {
                let mut w = [0; 4];
                w[..c.len()].copy_from_slice(c);
                u32::from_le_bytes(w)
            })
            .collect()
    }

    /// The words holding the stream `bits`, a string of `0`s and `1`s, each
    /// byte MSB first.
    fn stream_words(bits: &str) -> Vec<u32> {
        let byte = |c: &[u8]| (0..c.len()).fold(0, |b, i| b | (c[i] - b'0') << (7 - i));
        le_words(&bits.as_bytes().chunks(8).map(byte).collect::<Vec<u8>>())
    }

    /// Signature coefficients `s` as their codewords: the sign, the low 7
    /// bits of `|s|`, `|s| >> 7` zeros and a one.
    fn codewords(s: &[i32]) -> String {
        let codeword = |s: &i32| {
            let size = s.unsigned_abs() as usize;
            let zeros = "0".repeat(size >> 7);
            format!("{}{:07b}{zeros}1", (*s < 0) as u8, size & 0x7f)
        };
        s.iter().map(codeword).collect()
    }

    /// A decoded polynomial's words: coefficient `2i` word `i`'s low halfword.
    fn pairs(d: &FalconDecode) -> Vec<u32> {
        let pair = |p: &[u16]| p[0] as u32 | (p[1] as u32) << 16;
        d.coefficients.chunks(2).map(pair).collect()
    }

    /// A v1.2 public key's compact form, a key's source: `h`, its header
    /// `0x09` dropped.
    fn compact(pk: &[u8]) -> &[u8] {
        assert_eq!((pk.len(), pk[0]), (897, 0x09), "a v1.2 key");
        &pk[1..]
    }

    /// [`falcon512_decode`]'s answer to an encoding by the definitions,
    /// written apart from it over the bytes one bit at a time: the
    /// coefficients, `Σ s²` and the bit after the last coefficient's. The
    /// encoding is taken to be one.
    fn decoded_by_hand(mode: u32, bytes: &[u8]) -> ([u16; 512], u32, u32) {
        let bits: Vec<u32> = bytes
            .iter()
            .flat_map(|b| (0..8).rev().map(move |i| (b >> i & 1) as u32))
            .collect();
        let field = |at: usize, n: usize| bits[at..at + n].iter().fold(0, |x, b| x << 1 | b);
        let mut c = [0u16; 512];
        if mode == delegation::falcon_decode::KEY {
            for (i, x) in c.iter_mut().enumerate() {
                *x = field(14 * i, 14) as u16;
            }
            return (c, 0, 14 * 512);
        }
        let (mut at, mut norm) = (0, 0);
        for x in &mut c {
            let (negative, mut size) = (bits[at] == 1, field(at + 1, 7));
            at += 8;
            while bits[at] == 0 {
                size += 128;
                at += 1;
            }
            at += 1;
            norm += size * size;
            *x = if negative { 12289 - size } else { size } as u16;
        }
        (c, norm, at as u32)
    }

    /// `falcon512_decode` answers what the encodings' definitions do, read
    /// apart from it: the coefficients, `‖s2‖²` and the stream's end, for the
    /// keys, compact, and signatures of every implementation in
    /// `tools/falcon512/vectors.json` and this one's signer. It reads the
    /// words up to the one holding the end and no further, ones past it
    /// changing nothing, and refuses each bit set after the end in that word.
    #[test]
    fn falcon512_decode_answers_every_implementations_encodings() {
        use delegation::falcon_decode::{KEY, SIGNATURE};
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../../../tools/falcon512/vectors.json"))
                .expect("the vectors are JSON");
        let hex = |v: &serde_json::Value| {
            test_support::hex_to_bytes(v.as_str().expect("hex")).expect("hex")
        };
        let mut encodings = Vec::new();
        for section in ["standard_kat", "signatures"] {
            for v in vectors[section].as_array().expect("a section") {
                encodings.push((KEY, compact(&hex(&v["pk"])).to_vec()));
                encodings.push((SIGNATURE, hex(&v["sig"])[41..].to_vec()));
            }
        }
        for seed in 0..2 {
            let (sk, pk) = apogee_falcon512::keygen([seed; 32]);
            let sig = apogee_falcon512::sign(&sk, b"a purchase", b"");
            encodings.push((KEY, compact(&pk).to_vec()));
            encodings.push((SIGNATURE, sig[41..].to_vec()));
        }
        assert_eq!(encodings.len(), 24);
        for (mode, bytes) in encodings {
            let (coefficients, norm, end) = decoded_by_hand(mode, &bytes);
            let read = (end as usize - 1) / 32 + 1;
            let want = FalconDecode {
                coefficients,
                norm,
                end,
                read,
            };
            let words = le_words(&bytes);
            assert_eq!(falcon512_decode(mode, &words), Ok(want.clone()));
            assert_eq!(falcon512_decode(mode, &words[..read]), Ok(want.clone()));
            assert_eq!(falcon512_decode(mode, &words[..read - 1]), Err(SHORT));
            let mut ones = words.clone();
            ones.push(0);
            ones[read..].fill(!0);
            assert_eq!(falcon512_decode(mode, &ones), Ok(want), "a tail of ones");
            for t in end as usize..32 * read {
                let mut one = words.clone();
                one[t / 32] |= 1 << (8 * (t / 8 % 4) + 7 - t % 8);
                let after = Err("falcon512_decode's signature has a bit set after its end");
                assert_eq!(falcon512_decode(mode, &one), after, "bit {t}");
            }
        }
    }

    /// `FALCON512_DECODE` decodes a key and a signature in the advice, both
    /// compact, into the polynomial at its destination, writes `‖s2‖²` and
    /// the stream's end over its frame, and answers its stream: the
    /// polynomial's words, old and new, then the source words it read, as
    /// they were. A signature ending the advice is a call's — no word past
    /// its end's is read — as are a frame ending at the advice, the edges of
    /// `|s| ≤ 2047`, of `q` and of 5,000 bits, and a destination ending at
    /// the frame or starting just past the source words read. It refuses by
    /// name every malformed encoding, a bit set after a signature's end among
    /// them, and what its caller owes: a mode, alignment, a destination clear
    /// of the frame and the source, a source clear of the frame, and words a
    /// load reaches or a store could write.
    #[test]
    fn falcon512_decode_answers_and_refuses_what_its_caller_owes() {
        use delegation::falcon_decode::{KEY, SIGNATURE};
        let (sk, pk) = apogee_falcon512::keygen([3; 32]);
        let sig = apogee_falcon512::sign(&sk, b"a purchase", b"");
        let compressed = le_words(&sig[41..]);
        let signed = falcon512_decode(SIGNATURE, &compressed).expect("a signature");
        let key = falcon512_decode(KEY, &le_words(compact(&pk))).expect("a key");
        let mut advice = compact(&pk).to_vec();
        advice.extend(
            compressed[..signed.read]
                .iter()
                .flat_map(|w| w.to_le_bytes()),
        );
        let io = GuestIo {
            input: Vec::new(),
            advice,
        };
        let image = spin();
        let mut machine = Machine::new(&image, &io);
        let key_at = guest_memory::ADVICE_ORIGIN + 4;
        let (sig_at, advice_end) = (key_at + 896, key_at + 896 + 4 * signed.read as u32);
        let base = guest_memory::RAM_ORIGIN + 0x2000;
        let (dst, raw) = (base + 0x400, base + 0x1000);
        let decode = |machine: &mut Machine, base: u32, src: u32, dst: u32, mode: u32| {
            for (j, w) in [src, dst, mode, 0xdead_beef].iter().enumerate() {
                machine.set_word(base + 4 * j as u32, *w);
            }
            let family = constants::family::FALCON_DECODE;
            machine.delegate(ecall::FALCON512_DECODE, family, 0, base as u64)
        };
        let stream = |old: &[u32], new: &[u32], src: u32, words: &[u32]| {
            let output = (0..256).map(|i| (dst + 4 * i as u32, old[i], new[i]));
            let source = (0..words.len()).map(|i| (src + 4 * i as u32, words[i], words[i]));
            output.chain(source).collect::<Vec<_>>()
        };

        let call = decode(&mut machine, base, key_at, dst, KEY).expect("a key");
        let frame = vec![
            (base, key_at, key_at),
            (base + 4, dst, dst),
            (base + 8, KEY, 0),
            (base + 12, 0xdead_beef, 7168),
        ];
        assert_eq!(call.frame, frame);
        assert_eq!(
            call.stream,
            stream(&[0; 256], &pairs(&key), key_at, &le_words(compact(&pk)))
        );
        assert!(call.arrays.is_empty());
        let call = decode(&mut machine, base, sig_at, dst, SIGNATURE).expect("a signature");
        assert_eq!(
            call.frame[2..],
            [
                (base + 8, SIGNATURE, signed.norm),
                (base + 12, 0xdead_beef, signed.end)
            ]
        );
        let words = &compressed[..signed.read];
        assert_eq!(
            call.stream,
            stream(&pairs(&key), &pairs(&signed), sig_at, words)
        );
        for (i, w) in pairs(&signed).iter().enumerate() {
            assert_eq!(
                machine.word(dst + 4 * i as u32),
                *w,
                "the polynomial written"
            );
        }
        let edge = guest_memory::ADVICE_ORIGIN - 16;
        decode(&mut machine, edge, key_at, dst, KEY).expect("a frame ending at the advice");

        // Encodings by hand at `raw`, each a call's or refused by name.
        let mut answer = |bits: &str, mode: u32, dst: u32| {
            for (i, w) in stream_words(bits).iter().enumerate() {
                machine.set_word(raw + 4 * i as u32, *w);
            }
            let call = decode(&mut machine, base, raw, dst, mode);
            call.map(|c| (c.frame[2].2, c.frame[3].2, c.stream[0].2, c.stream[1].2))
        };
        let frame_error = |detail| Err(EmuError::DelegationFrame { pc: 0, detail });
        let (q, zeros) = (12289, |n: usize| "0".repeat(n));
        let key_of = |first: u32| format!("{first:014b}{}", zeros(14 * 511));
        assert_eq!(answer(&key_of(q - 1), KEY, dst), Ok((0, 7168, q - 1, 0)));
        assert_eq!(
            answer(&key_of(q), KEY, dst),
            frame_error("falcon512_decode's key coefficient is not below q")
        );
        let edges = codewords(&[&[2047, -2047][..], &[1; 510]].concat());
        let pair = 2047 | (q - 2047) << 16;
        let norm = 2 * 2047 * 2047 + 510;
        assert_eq!(
            answer(&edges, SIGNATURE, dst),
            Ok((norm, 48 + 9 * 510, pair, 1 | 1 << 16))
        );
        // 145 words read: a destination just past them is a call's.
        assert_eq!((48 + 9 * 510u32).div_ceil(32), 145);
        assert!(answer(&edges, SIGNATURE, raw + 4 * 145).is_ok());
        assert_eq!(
            answer(&edges, SIGNATURE, raw + 4 * 144),
            frame_error("falcon512_decode's destination overlaps its source")
        );
        assert_eq!(
            answer(&format!("{edges}1"), SIGNATURE, dst),
            frame_error("falcon512_decode's signature has a bit set after its end")
        );
        let full = codewords(&[&[128; 392][..], &[-1; 120]].concat());
        let norm = 392 * 128 * 128 + 120;
        assert_eq!(
            answer(&full, SIGNATURE, dst),
            Ok((norm, 5000, 128 | 128 << 16, 128 | 128 << 16))
        );
        assert_eq!(
            answer(
                &codewords(&[&[128; 393][..], &[1; 119]].concat()),
                SIGNATURE,
                dst
            ),
            frame_error("falcon512_decode's signature runs past 5000 bits")
        );
        assert_eq!(
            answer(
                &format!("100000001{}", codewords(&[1; 511])),
                SIGNATURE,
                dst
            ),
            frame_error("falcon512_decode's coefficient is -0")
        );
        let unary = format!("00000000{}1{}", zeros(16), codewords(&[1; 511]));
        assert_eq!(
            answer(&unary, SIGNATURE, dst),
            frame_error("falcon512_decode's coefficient is above 2047 in size")
        );
        assert_eq!(
            answer(&full, 2, dst),
            frame_error("falcon512_decode's mode is neither a key's nor a signature's")
        );

        // The frame's addresses. A key at `raw`, zeros but its last word, for
        // a frame there: that word is the frame's source, `raw`, as it was.
        let mut held = vec![0; 224];
        held[223] = raw;
        falcon512_decode(KEY, &held).expect("a key ending in `raw`");
        for (i, w) in held.iter().enumerate() {
            machine.set_word(raw + 4 * i as u32, *w);
        }
        let mut refused =
            |base: u32, src: u32, dst: u32| decode(&mut machine, base, src, dst, KEY).err();
        let frame_error = |detail| Some(EmuError::DelegationFrame { pc: 0, detail });
        assert_eq!(
            refused(base, key_at + 2, dst),
            frame_error("falcon512_decode's source is not word-aligned")
        );
        assert_eq!(
            refused(base, key_at, dst + 2),
            frame_error("falcon512_decode's destination is not word-aligned")
        );
        let over_frame = frame_error("falcon512_decode's destination overlaps its frame");
        assert_eq!(refused(base, key_at, base - 1020), over_frame);
        assert_eq!(refused(base, key_at, base + 12), over_frame);
        assert_eq!(refused(base, key_at, base - 1024), None);
        assert_eq!(refused(base, key_at, base + 16), None);
        assert_eq!(
            refused(raw + 4 * 223, raw, dst),
            frame_error("falcon512_decode's source overlaps its frame")
        );
        assert_eq!(refused(raw + 4 * 224, raw, dst), None);
        assert_eq!(
            refused(base, raw, raw + 4 * 223),
            frame_error("falcon512_decode's destination overlaps its source")
        );
        let out = |addr: u32| {
            Some(EmuError::OutOfBounds {
                pc: 0,
                addr: addr as u64,
            })
        };
        assert_eq!(refused(base, key_at, advice_end), out(advice_end));
        assert_eq!(refused(base, 0x7000, dst), out(0x7000));
        assert_eq!(refused(edge + 4, key_at, dst), out(edge + 4));

        // A key the advice cuts short: the first word it does not reach.
        let io = GuestIo {
            input: Vec::new(),
            advice: compact(&pk)[..800].to_vec(),
        };
        let mut machine = Machine::new(&image, &io);
        assert_eq!(
            decode(&mut machine, base, key_at, dst, KEY).err(),
            out(key_at + 800)
        );
    }

    /// A guest's `FALCON512_DECODE` calls, a key's and a signature's, both
    /// compact in the advice, are one entry each: the frame's words, the
    /// polynomial's, then the source words the stream reached, the slots past
    /// them `Query::ABSENT` and in no event. The archive's check and the log's
    /// self-check take the run.
    #[test]
    fn falcon512_decode_records_the_words_its_stream_reached() {
        use delegation::falcon_decode::{KEY, SIGNATURE, SOURCE, WORDS};
        let (sk, pk) = apogee_falcon512::keygen([5; 32]);
        let sig = apogee_falcon512::sign(&sk, b"a purchase", b"");
        let (h, compressed) = (le_words(compact(&pk)), le_words(&sig[41..]));
        let key = falcon512_decode(KEY, &h).expect("a key");
        let signed = falcon512_decode(SIGNATURE, &compressed).expect("a signature");
        let words = [&h[..], &compressed[..signed.read]].concat();
        let io = GuestIo {
            input: Vec::new(),
            advice: words.iter().flat_map(|w| w.to_le_bytes()).collect(),
        };
        let key_at = guest_memory::ADVICE_ORIGIN + 4;
        let sig_at = key_at + 896;
        let frames = guest_memory::RAM_ORIGIN + 0x2000;
        let (dst0, dst1) = (frames + 0x1000, frames + 0x2000);
        let data = [key_at, dst0, KEY, 0, sig_at, dst1, SIGNATURE, 0];
        // `lui a0, frames`, `li a7, FALCON512_DECODE`, a call, `a0 += 16`, a
        // call, then `exit(0)`.
        let (a0, a7) = (10, 17);
        let addi = |rd: u32, rs1: u32, imm: u32| imm << 20 | rs1 << 15 | rd << 7 | 0x13;
        let code = [
            frames | a0 << 7 | 0x37,
            addi(a7, 0, ecall::FALCON512_DECODE),
            0x73,
            addi(a0, a0, 16),
            0x73,
            addi(a7, 0, ecall::EXIT),
            addi(a0, 0, 0),
            0x73,
        ];
        let bytes = |w: &[u32]| -> Vec<u8> { w.iter().flat_map(|w| w.to_le_bytes()).collect() };
        let segment = |vaddr: u32, words: &[u32]| Segment {
            vaddr,
            mem_len: 4 * words.len() as u32,
            bytes: bytes(words),
        };
        let image = ProgramImage {
            entry: guest_memory::RAM_ORIGIN,
            segments: vec![
                segment(guest_memory::RAM_ORIGIN, &code),
                segment(frames, &data),
            ],
            slot_base: guest_memory::RAM_ORIGIN,
            slots: code
                .iter()
                .flat_map(|&word| {
                    let first = Slot::Instruction {
                        word,
                        compressed: false,
                    };
                    [first, Slot::MidInstruction]
                })
                .collect(),
            delegations: vec![ecall::FALCON512_DECODE],
        };
        let params = program::ProgramParams::defaults();
        let (tables, config) = program::decode_program(&image, &params).expect("a program");
        let (traces, log, profile, execution) =
            trace_run(&image, &io, &tables, &config).expect("a run");
        assert_eq!(execution.exit_code, 0);

        let calls = traces
            .delegation(constants::family::FALCON_DECODE)
            .expect("its buffer");
        assert_eq!((calls.len(), calls.words.len()), (2, WORDS));
        assert!(key.read == SOURCE && signed.read < SOURCE);
        for (e, (decoded, src, dst)) in [(&key, key_at, dst0), (&signed, sig_at, dst1)]
            .into_iter()
            .enumerate()
        {
            let query = |j: usize| {
                let q = &calls.words[j];
                (q.addr[e], q.read_value[e], q.write_value[e])
            };
            let source = (0..decoded.read as u32).map(|i| src + 4 * i);
            let addrs: Vec<u32> = (0..256).map(|i| dst + 4 * i).chain(source).collect();
            let touched = 4 + addrs.len();
            assert_eq!(calls.base[e], frames + 16 * e as u32);
            assert_eq!(query(2).2, decoded.norm as u64);
            assert_eq!(query(3).2, decoded.end as u64);
            for (j, addr) in (4..touched).zip(addrs) {
                assert_eq!(query(j).0, addr, "entry {e} word {j}");
            }
            for (i, pair) in pairs(decoded).iter().enumerate() {
                assert_eq!(query(4 + i), (dst + 4 * i as u32, 0, *pair as u64));
            }
            for j in touched..WORDS {
                let q = &calls.words[j];
                let absent = Query {
                    addr: q.addr[e],
                    read_ts: q.read_ts[e],
                    read_value: q.read_value[e],
                    write_value: q.write_value[e],
                };
                assert_eq!(absent, Query::ABSENT, "entry {e} word {j}");
            }
        }
        let ram = log.events().iter().filter(|e| e.space == AddressSpace::Ram);
        assert_eq!(ram.count(), 2 * (4 + 256) + key.read + signed.read);
        let initial = trace::InitialMemory {
            image: &image,
            public_input: &io.input,
            advice: &io.advice,
        };
        log.self_check(&initial).expect("one memory");
        trace::TraceArchive::from_execution(
            traces,
            log,
            profile,
            execution.io,
            io.advice.clone(),
            trace::PhaseTiming { wall_nanos: 0 },
        );
    }
}
