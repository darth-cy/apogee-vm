//! The reference emulator: RV32IMAC on one hart, over a [`ProgramImage`].
//!
//! Two entry points, one instruction-execution core. [`run`] executes;
//! [`trace_run`] executes the same way and also hands each cycle's memory
//! queries to a recorder, which fills the memory event log and routes the
//! cycle's row to the family that owns its pc. The recorder is the only
//! difference between the two: neither path has its own copy of the
//! semantics.
//!
//! `docs/spec/execution-trace.md` is the frozen convention the recorder
//! follows — timestamps, slots, the x0 rule, the ecall frame.
//! `crates/emulator/CLAUDE.md` is the design record.
//!
//! # Semantics, in one paragraph
//!
//! One hart, no interrupts, no privilege levels. Every A-extension
//! instruction is its plain read-modify-write, and `aq`/`rl` order nothing.
//! **`sc.w` always succeeds**: it stores and writes 0 to `rd`. The ISA
//! requires an `sc.w` without a valid reservation to fail, so this is a
//! conformance deviation — never a soundness one, since the verifier still
//! knows exactly which program ran, and the circuits share the semantics
//! (`docs/spec/memory-ops.md` §6.5). A halfword or word access at an address
//! that is not a multiple of its width, and any access outside the
//! addressable regions, is a fatal guest error, never rotated, split or
//! emulated. So is `ebreak`, and so is a pc that is not the start of an
//! instruction.

use std::collections::HashMap;
use std::fmt;

use constants::{
    delegation, ecall, family, fr_arith, guest_memory, keccak, memory, mod_mul, poseidon2,
};
use field::Fr;
use isa::{decode, Instr};
use loader::{ProgramImage, Slot};
use program::{row_kind, DecodedTables, FamilyId, VmConfig};
use trace::{
    AddressSpace, CycleProfile, DelegationTrace, FamilyTrace, FamilyTraces, IoStreams, MemoryEvent,
    MemoryEventLog, MemoryState, Query, Role, Row, ROLES,
};

/// What a guest is given to read. **Four fields, because there are four
/// things, and what tells them apart is what binds them**
/// (`docs/spec/public-values.md`).
///
/// | field | where the guest finds it | what binds it |
/// | --- | --- | --- |
/// | `input` | the public input window, an ordinary load | the statement, at the window's init column |
/// | `advice` | `guest_memory::ADVICE_ORIGIN`, an ordinary load | **nothing**; the guest owes a check |
/// | `stdin` | fd 0, a `read` ecall | nothing; `read` is not provable |
/// | `hint` | fd 3, a `read` ecall | nothing; the older spelling of advice |
///
/// `input` and `stdin` are **not** the same bytes and neither seeds the other.
/// They were one field briefly and the coupling was wrong in both directions: a
/// public input is capped at `guest_memory::PUBLIC_PAYLOAD_BYTES` and an fd 0
/// stream is not, and a guest cannot be both provable and runnable under
/// `qemu-riscv32` anyway — the windows and the advice region are unmapped
/// there, so no guest reads both paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestIo {
    pub input: Vec<u8>,
    pub advice: Vec<u8>,
    pub stdin: Vec<u8>,
    pub hint: Vec<u8>,
}

/// A finished execution: the guest called `exit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execution {
    /// The register file after the last cycle.
    pub regs: [u32; 32],
    /// The status passed to `exit`. A nonzero status is a failed execution,
    /// which is still an execution: it is reported, not refused.
    pub exit_code: i32,
    /// Cycles run, transfer cycles included. Cycles are numbered from 1, so
    /// this is also the last cycle's number.
    pub cycle_count: u64,
    /// The execution's **public values**: the public input it was given, and
    /// the journal its stores left in the public output window
    /// (`docs/spec/public-values.md`). These are the two byte strings a
    /// statement carries and a proof binds.
    pub io: IoStreams,
    /// The fd 1 bytes: the POSIX compatibility stream, uncommitted. It is what
    /// `qemu-riscv32` can be compared against; a proof binds none of it.
    pub stdout: Vec<u8>,
    /// The fd 2 bytes: diagnostics, uncommitted, and never archived.
    pub stderr: Vec<u8>,
}

/// Every way an execution stops other than by `exit`. Each is a fatal guest
/// error — the program did something this VM does not define — and neither
/// entry point returns any part of a trace alongside one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmuError {
    /// The pc is not the start of an instruction: the middle of one, data,
    /// the all-zero halfword, or outside the image's code.
    NotAnInstruction { pc: u32 },
    /// An instruction slot holds a word the decoder refuses.
    IllegalInstruction { pc: u32, word: u32 },
    /// `ebreak`: a trap with nothing to trap to.
    Ebreak { pc: u32 },
    /// A halfword or word access at an address that is not a multiple of
    /// its width.
    Misaligned { pc: u32, addr: u32, width: u32 },
    /// A data access, or a byte an ecall would move, outside the RAM window.
    OutOfBounds { pc: u32, addr: u32 },
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
    /// A delegation ecall whose family the `VmConfig` does not hold.
    ///
    /// Only the tracing path raises it: the family set is a property of the
    /// linked binary (`docs/spec/delegation.md` §7), and a program that calls
    /// a delegation it did not declare is one no trace can describe and no
    /// proof can cover. Loud rather than answered `-ENOSYS`, because the two
    /// are different failures — one is a VM that lacks the circuit, the other
    /// a program whose declaration and whose code disagree.
    DelegationFamilyAbsent { pc: u32, number: u32 },
    /// A delegation's frame does not describe a call its family can answer:
    /// an operation code outside the legal set, or a value that is not a
    /// canonical `Fr`.
    ///
    /// Fatal, and it has to be: the circuit refuses both — the opcode by its
    /// selector sum, a non-canonical value by its borrow chain — so an
    /// execution the emulator let through here would be one no proof could
    /// cover (`docs/spec/delegation.md` §13).
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
                "illegal instruction at pc {pc:#010x}: {word:#010x} is not RV32IMAC"
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
                "data access outside the RAM window at pc {pc:#010x}: address {addr:#010x}"
            ),
            EmuError::ClockOverflow { cycle } => write!(
                f,
                "cycle {cycle} would pass the {}-bit timestamp clock",
                memory::TS_BITS
            ),
            EmuError::DelegationFamilyAbsent { pc, number } => write!(
                f,
                "the delegation ecall {number:#x} at pc {pc:#010x} has no family in this \
                 VmConfig, so the program calls a delegation it does not declare"
            ),
            EmuError::DelegationFrame { pc, detail } => write!(
                f,
                "the delegation frame at pc {pc:#010x} is not a call this family answers: {detail}"
            ),
        }
    }
}

/// The Poseidon2 delegation over its 24-word frame: three canonical
/// little-endian `Fr` lanes, permuted in place.
///
/// The permutation is `transcript::poseidon2_permute` and nothing else — the
/// executor and the circuit are held to one definition, not to each other.
/// A lane that is not canonical is refused by the caller before this runs.
fn poseidon2_frame(old: &[u32]) -> Vec<u32> {
    let mut state = [Fr::ZERO; poseidon2::WIDTH];
    for (i, lane) in state.iter_mut().enumerate() {
        *lane = Fr::from_bytes(&value_bytes(old, poseidon2::WORDS_PER_LANE * i))
            .expect("the caller checked canonicity");
    }
    transcript::poseidon2_permute(&mut state);
    let mut out = old.to_vec();
    for (i, lane) in state.iter().enumerate() {
        write_value(&mut out, poseidon2::WORDS_PER_LANE * i, &lane.to_bytes());
    }
    out
}

/// The Fr-arithmetic delegation over its 25-word frame: the opcode word, then
/// `a`, `b` and the result in `field::Fr`'s in-memory representation.
///
/// The three operations are `Fr`'s own `Add`, `Mul` and `inverse`, with
/// `inverse(0) = 0` in place of `None`, which is this delegation's convention
/// (`docs/spec/delegation.md` §13).
fn fr_arith_frame(pc: u32, old: &[u32]) -> Result<Vec<u32>, EmuError> {
    let operand = |first: usize| -> Result<Fr, EmuError> {
        Fr::from_memory_bytes(&value_bytes(old, first)).ok_or(EmuError::DelegationFrame {
            pc,
            detail: "an operand is not a canonical Fr",
        })
    };
    let a = operand(fr_arith::A_WORD)?;
    let b = operand(fr_arith::B_WORD)?;
    // The result's words are read and thrown away, but they must still be a
    // canonical `Fr`: the circuit decomposes every frame value it names, and
    // the words it writes are the ones its canonicity gates bind.
    let out = match old[fr_arith::OPCODE_WORD] {
        fr_arith::OP_ADD => a + b,
        fr_arith::OP_MUL => a * b,
        fr_arith::OP_INV => a.inverse().unwrap_or(Fr::ZERO),
        _ => {
            return Err(EmuError::DelegationFrame {
                pc,
                detail: "the operation code is not add, mul or inverse",
            })
        }
    };
    let mut frame = old.to_vec();
    write_value(&mut frame, fr_arith::OUT_WORD, &out.to_memory_bytes());
    Ok(frame)
}

/// `MOD_MUL`'s frame, permuted: `out = a * b mod m` over eight 32-bit limbs.
///
/// **Schoolbook, in `u64` lanes, and long division by shift-and-subtract.** No
/// Montgomery form, no reciprocal, no assumption about the modulus but that it
/// is not zero: the circuit proves `a*b = q*m + out` with `out < m` and nothing
/// else (`docs/spec/delegation.md` §14), so the executor computes exactly that
/// and the two agree by definition rather than by a shared trick.
///
/// A zero modulus is a `DelegationFrame` error and not a wrapped answer: the
/// circuit's borrow chain cannot put `out` below zero, so there is no witness
/// for such a call and a trace carrying one is a trace no proof covers.
fn mod_mul_frame(pc: u32, old: &[u32]) -> Result<Vec<u32>, EmuError> {
    let limb = |first: usize, k: usize| old[first + k] as u64;
    let m: [u64; mod_mul::LIMBS] = core::array::from_fn(|k| limb(mod_mul::M_WORD, k));
    if m.iter().all(|w| *w == 0) {
        return Err(EmuError::DelegationFrame {
            pc,
            detail: "the modulus is zero",
        });
    }
    // The 512-bit product, sixteen limbs, carried in `u64` lanes: each partial
    // product is below `2^64` and each accumulation below `2^64` again because
    // the running lane is reduced to 32 bits before the next addend.
    let mut product = [0u64; 2 * mod_mul::LIMBS];
    for i in 0..mod_mul::LIMBS {
        let mut carry = 0u64;
        for j in 0..mod_mul::LIMBS {
            let at = i + j;
            let total = product[at] + limb(mod_mul::A_WORD, i) * limb(mod_mul::B_WORD, j) + carry;
            product[at] = total & 0xffff_ffff;
            carry = total >> 32;
        }
        let mut at = i + mod_mul::LIMBS;
        while carry != 0 {
            let total = product[at] + carry;
            product[at] = total & 0xffff_ffff;
            carry = total >> 32;
            at += 1;
        }
    }
    // `product mod m`, bit by bit from the top: the remainder doubles, takes the
    // next bit, and the modulus is subtracted once if it fits. 512 iterations of
    // 8-limb arithmetic, which is slow and is the executor's own cost, not the
    // guest's.
    let mut rem = [0u64; mod_mul::LIMBS];
    for bit in (0..32 * 2 * mod_mul::LIMBS).rev() {
        // rem = 2*rem + bit
        let mut carry = (product[bit / 32] >> (bit % 32)) & 1;
        for word in rem.iter_mut() {
            let total = (*word << 1) | carry;
            *word = total & 0xffff_ffff;
            carry = total >> 32;
        }
        // The shifted-out bit and a remainder at or above `m` both mean one
        // subtraction. `carry` can only be 1 because `rem < m <= 2^256`.
        if carry == 1 || !less_than(&rem, &m) {
            let mut borrow = 0i64;
            for k in 0..mod_mul::LIMBS {
                let diff = rem[k] as i64 - m[k] as i64 - borrow;
                borrow = i64::from(diff < 0);
                rem[k] = (diff + if diff < 0 { 1i64 << 32 } else { 0 }) as u64;
            }
        }
    }
    let mut frame = old.to_vec();
    for k in 0..mod_mul::LIMBS {
        frame[mod_mul::OUT_WORD + k] = rem[k] as u32;
    }
    Ok(frame)
}

/// Whether `a < b` over eight little-endian 32-bit limbs.
fn less_than(a: &[u64; mod_mul::LIMBS], b: &[u64; mod_mul::LIMBS]) -> bool {
    for k in (0..mod_mul::LIMBS).rev() {
        if a[k] != b[k] {
            return a[k] < b[k];
        }
    }
    false
}

/// The 32 bytes a frame value occupies, from its eight little-endian words.
fn value_bytes(frame: &[u32], first: usize) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for k in 0..8 {
        bytes[4 * k..4 * k + 4].copy_from_slice(&frame[first + k].to_le_bytes());
    }
    bytes
}

/// Write 32 bytes back over a frame value's eight words.
fn write_value(frame: &mut [u32], first: usize, bytes: &[u8; 32]) {
    for k in 0..8 {
        let mut word = [0u8; 4];
        word.copy_from_slice(&bytes[4 * k..4 * k + 4]);
        frame[first + k] = u32::from_le_bytes(word);
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
/// table claims — impossible after S11's partition — panics, as does a
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
/// `index` is the shard index `docs/spec/block-proof.md` §5.1 gives it — rows
/// `[index·h, min((index+1)·h, len))` of the family's buffer — so a streaming
/// run's shards are the same shards `trace::plan_shards` counts and the same
/// cut every family fill has made since S16.
pub struct ShardChunk {
    pub family: FamilyId,
    pub index: u32,
    pub rows: ChunkRows,
}

/// A shard's rows, by the kind of family: cycles for a cycle-owning family,
/// invocations for a delegation one. A window family has neither — its rows are
/// addresses, and what fills them is the final [`MemoryState`].
///
/// The cycle arm is boxed because a `FamilyTrace` is 872 bytes of column
/// headers against a `DelegationTrace`'s 80, and one allocation a shard is
/// nothing beside the rows it points at.
pub enum ChunkRows {
    Cycles(Box<FamilyTrace>),
    Invocations(DelegationTrace),
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
/// `(address, value read, value written)`.
///
/// `delegation` is the invocation a delegation request made, if any: the
/// family, the frame base, and one `(address, old, new)` per frame word in
/// frame order. It is not a role — 50 frame words do not fit eight — and it is
/// the invocation's row, not the requesting cycle's
/// (`docs/spec/delegation.md` §4).
struct Cycle {
    queries: [Option<(u32, u32, u32)>; 8],
    delegation: Option<Invocation>,
}

/// One delegation invocation: the family, the frame base, and one
/// `(address, old, new)` per frame word in frame order.
type Invocation = (FamilyId, u32, Vec<(u32, u32, u32)>);

impl Cycle {
    fn new() -> Cycle {
        Cycle {
            queries: [None; 8],
            delegation: None,
        }
    }

    fn stage(&mut self, role: Role, addr: u32, read: u32, write: u32) {
        let slot = &mut self.queries[role as usize];
        assert!(slot.is_none(), "one cycle issued two {role:?} queries");
        *slot = Some((addr, read, write));
    }
}

struct Machine<'a> {
    code: Vec<Fetch>,
    slot_base: u32,
    regs: [u32; 32],
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
    stdin: &'a [u8],
    stdin_at: usize,
    hint: &'a [u8],
    hint_at: usize,
    /// One past the highest advice byte the host supplied, rounded up to a
    /// word: the top of what a guest may load. Above it the advice region is
    /// addressable in principle and initialized by nothing in this execution,
    /// so a read there is refused loudly here rather than left to fail as an
    /// unprovable trace.
    advice_end: u32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
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
            stdin: &io.stdin,
            stdin_at: 0,
            hint: &io.hint,
            hint_at: 0,
            advice_end: guest_memory::ADVICE_ORIGIN
                + 4 * trace::advice_region_words(&io.advice) as u32,
            stdout: Vec::new(),
            stderr: Vec::new(),
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
        // check, so the three cannot drift.
        for (y, word) in program::public_io_words(&io.input).iter().enumerate() {
            machine.set_word(guest_memory::PUBLIC_INPUT_ORIGIN + 4 * y as u32, *word);
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
            stdout: self.stdout,
            stderr: self.stderr,
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
            Some(Fetch::NotCode) | None => Err(EmuError::NotAnInstruction { pc }),
        }
    }

    /// One instruction: one cycle, or for a `read`/`write` ecall one cycle
    /// per word moved and then the ecall's own.
    fn step(&mut self) -> Result<(), EmuError> {
        let pc = self.pc;
        let (instr, compressed) = self.fetch(pc)?;
        let fall = pc.wrapping_add(if compressed { 2 } else { 4 });
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
    fn read(&mut self, cycle: &mut Cycle, role: Role, r: u8) -> u32 {
        let value = self.regs[r as usize];
        cycle.stage(role, r as u32, value, value);
        value
    }

    /// Write `rd`, staging the query. `x0` logs a write-back of 0 and keeps it.
    fn write(&mut self, cycle: &mut Cycle, rd: u8, value: u32) {
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

    /// The word a `width`-byte access at `addr` touches, refusing a
    /// misaligned access and one outside the RAM window.
    fn data_word(&self, pc: u32, addr: u32, width: u32) -> Result<u32, EmuError> {
        if !addr.is_multiple_of(width) {
            return Err(EmuError::Misaligned { pc, addr, width });
        }
        let word = addr & !3;
        let reachable = trace::addressable(word)
            && (word < guest_memory::ADVICE_ORIGIN || word < self.advice_end);
        if !reachable {
            return Err(EmuError::OutOfBounds { pc, addr });
        }
        Ok(word)
    }

    /// Read the `words`-word frame at `base`, checking the two frame rules of
    /// `docs/spec/delegation.md` §4, and nothing else checks them: the base is
    /// word-aligned, and the whole frame lies inside the RAM window. Both are
    /// fatal guest errors, as a misaligned load is — the circuit refuses the
    /// same two, so an execution this refuses is one no proof could cover. The
    /// bound is computed in `u64` because `base + frame bytes` wraps a `u32`
    /// at the top of the window, and a wrapped comparison passes a check it
    /// should fail.
    fn delegation_frame(&mut self, pc: u32, base: u32, words: usize) -> Result<Vec<u32>, EmuError> {
        if !base.is_multiple_of(4) {
            return Err(EmuError::Misaligned {
                pc,
                addr: base,
                width: 4,
            });
        }
        let window = guest_memory::RAM_ORIGIN as u64 + guest_memory::RAM_LENGTH as u64;
        if (base as u64) < guest_memory::RAM_ORIGIN as u64
            || base as u64 + 4 * words as u64 > window
        {
            return Err(EmuError::OutOfBounds { pc, addr: base });
        }
        Ok((0..words).map(|j| self.word(base + 4 * j as u32)).collect())
    }

    /// Write a delegation's answer back over its frame, returning the word
    /// queries as `(address, old, new)` in frame order.
    fn delegation_writeback(
        &mut self,
        base: u32,
        old: &[u32],
        new: &[u32],
    ) -> Vec<(u32, u32, u32)> {
        let mut frame = Vec::with_capacity(old.len());
        for j in 0..old.len() {
            let addr = base + 4 * j as u32;
            self.set_word(addr, new[j]);
            frame.push((addr, old[j], new[j]));
        }
        frame
    }

    /// Execute delegation family `family` over the frame at `base`, in place.
    ///
    /// The one dispatch: every delegation number reaches it, and a family with
    /// no arm here is a `DELEGATIONS` row nobody implemented, which is a build
    /// error rather than a silent `-ENOSYS`.
    fn delegate(
        &mut self,
        family: FamilyId,
        pc: u32,
        base: u32,
    ) -> Result<Vec<(u32, u32, u32)>, EmuError> {
        let words =
            program::delegation_frame_words(family).expect("the caller matched a delegation");
        let old = self.delegation_frame(pc, base, words)?;
        let new = match family {
            family::KECCAK_F => {
                let mut state: [u32; keccak::FRAME_WORDS] = core::array::from_fn(|j| old[j]);
                let mut lanes = lanes_of(&state);
                keccak_f(&mut lanes);
                state = words_of(&lanes);
                state.to_vec()
            }
            family::POSEIDON2 => poseidon2_frame(&old),
            family::FR_ARITH => fr_arith_frame(pc, &old)?,
            family::MOD_MUL => mod_mul_frame(pc, &old)?,
            other => panic!("emulator: delegation family {other} has no implementation"),
        };
        assert_eq!(new.len(), words, "a delegation writes its whole frame");
        Ok(self.delegation_writeback(base, &old, &new))
    }

    /// Replace a word, staging the slot-3 RAM query.
    fn ram_write(&mut self, cycle: &mut Cycle, word: u32, old: u32, new: u32) {
        cycle.stage(Role::Ram, word, old, new);
        self.set_word(word, new);
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
        let at = |base: u32, imm: i32| base.wrapping_add(imm as u32);
        let mut next = fall;
        match instr {
            Lui { rd, imm } => self.write(c, rd, imm as u32),
            Auipc { rd, imm } => self.write(c, rd, at(pc, imm)),
            Jal { rd, imm } => {
                self.write(c, rd, fall);
                next = at(pc, imm);
            }
            Jalr { rd, rs1, imm } => {
                let base = self.read(c, Role::Rs1, rs1);
                self.write(c, rd, fall);
                next = at(base, imm) & !1;
            }

            Beq { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, at(pc, imm), fall, |a, b| a == b)
            }
            Bne { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, at(pc, imm), fall, |a, b| a != b)
            }
            Blt { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, at(pc, imm), fall, |a, b| {
                    (a as i32) < (b as i32)
                })
            }
            Bge { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, at(pc, imm), fall, |a, b| {
                    (a as i32) >= (b as i32)
                })
            }
            Bltu { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, at(pc, imm), fall, |a, b| a < b)
            }
            Bgeu { rs1, rs2, imm } => {
                next = self.branch(c, rs1, rs2, at(pc, imm), fall, |a, b| a >= b)
            }

            Lb { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 1, |v| v as u8 as i8 as u32)?,
            Lh { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 2, |v| v as u16 as i16 as u32)?,
            Lw { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 4, |v| v)?,
            Lbu { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 1, |v| v as u8 as u32)?,
            Lhu { rd, rs1, imm } => self.load(c, pc, rd, rs1, imm, 2, |v| v as u16 as u32)?,
            Sb { rs1, rs2, imm } => self.store(c, pc, rs1, rs2, imm, 1)?,
            Sh { rs1, rs2, imm } => self.store(c, pc, rs1, rs2, imm, 2)?,
            Sw { rs1, rs2, imm } => self.store(c, pc, rs1, rs2, imm, 4)?,

            Addi { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| a.wrapping_add(i)),
            Slti { rd, rs1, imm } => {
                self.op_imm(c, rd, rs1, imm, |a, i| ((a as i32) < (i as i32)) as u32)
            }
            Sltiu { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| (a < i) as u32),
            Xori { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| a ^ i),
            Ori { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| a | i),
            Andi { rd, rs1, imm } => self.op_imm(c, rd, rs1, imm, |a, i| a & i),
            Slli { rd, rs1, shamt } => self.op_imm(c, rd, rs1, shamt as i32, |a, s| a << s),
            Srli { rd, rs1, shamt } => self.op_imm(c, rd, rs1, shamt as i32, |a, s| a >> s),
            Srai { rd, rs1, shamt } => {
                self.op_imm(c, rd, rs1, shamt as i32, |a, s| ((a as i32) >> s) as u32)
            }

            Add { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a.wrapping_add(b)),
            Sub { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a.wrapping_sub(b)),
            Sll { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a << (b & 31)),
            Slt { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| ((a as i32) < (b as i32)) as u32)
            }
            Sltu { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| (a < b) as u32),
            Xor { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a ^ b),
            Srl { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a >> (b & 31)),
            Sra { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| ((a as i32) >> (b & 31)) as u32)
            }
            Or { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a | b),
            And { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a & b),

            // One hart: a fence orders nothing, and it has no register queries.
            Fence { .. } => {}
            Ebreak => return Err(EmuError::Ebreak { pc }),
            Ecall => unreachable!("ecall is dispatched before execute"),

            Mul { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a.wrapping_mul(b)),
            Mulh { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                ((a as i32 as i64 * b as i32 as i64) >> 32) as u32
            }),
            Mulhsu { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                ((a as i32 as i64 * b as i64) >> 32) as u32
            }),
            Mulhu { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| ((a as u64 * b as u64) >> 32) as u32)
            }
            Div { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                if b == 0 {
                    u32::MAX
                } else {
                    (a as i32).wrapping_div(b as i32) as u32
                }
            }),
            Divu { rd, rs1, rs2 } => {
                self.op(c, rd, rs1, rs2, |a, b| a.checked_div(b).unwrap_or(u32::MAX))
            }
            Rem { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| {
                if b == 0 {
                    a
                } else {
                    (a as i32).wrapping_rem(b as i32) as u32
                }
            }),
            Remu { rd, rs1, rs2 } => self.op(c, rd, rs1, rs2, |a, b| a.checked_rem(b).unwrap_or(a)),

            LrW { rd, rs1, .. } => {
                let addr = self.read(c, Role::Rs1, rs1);
                let word = self.data_word(pc, addr, 4)?;
                let old = self.word(word);
                self.ram_write(c, word, old, old);
                self.write(c, rd, old);
            }
            ScW { rd, rs1, rs2, .. } => {
                let addr = self.read(c, Role::Rs1, rs1);
                let src = self.read(c, Role::Rs2, rs2);
                let word = self.data_word(pc, addr, 4)?;
                let old = self.word(word);
                self.ram_write(c, word, old, src);
                self.write(c, rd, 0);
            }
            AmoswapW { rd, rs1, rs2, .. } => self.amo(c, pc, rd, rs1, rs2, |_, b| b)?,
            AmoaddW { rd, rs1, rs2, .. } => {
                self.amo(c, pc, rd, rs1, rs2, |a, b| a.wrapping_add(b))?
            }
            AmoxorW { rd, rs1, rs2, .. } => self.amo(c, pc, rd, rs1, rs2, |a, b| a ^ b)?,
            AmoandW { rd, rs1, rs2, .. } => self.amo(c, pc, rd, rs1, rs2, |a, b| a & b)?,
            AmoorW { rd, rs1, rs2, .. } => self.amo(c, pc, rd, rs1, rs2, |a, b| a | b)?,
            AmominW { rd, rs1, rs2, .. } => {
                self.amo(c, pc, rd, rs1, rs2, |a, b| (a as i32).min(b as i32) as u32)?
            }
            AmomaxW { rd, rs1, rs2, .. } => {
                self.amo(c, pc, rd, rs1, rs2, |a, b| (a as i32).max(b as i32) as u32)?
            }
            AmominuW { rd, rs1, rs2, .. } => self.amo(c, pc, rd, rs1, rs2, |a, b| a.min(b))?,
            AmomaxuW { rd, rs1, rs2, .. } => self.amo(c, pc, rd, rs1, rs2, |a, b| a.max(b))?,
        }
        Ok(next)
    }

    fn op(&mut self, c: &mut Cycle, rd: u8, rs1: u8, rs2: u8, f: fn(u32, u32) -> u32) {
        let a = self.read(c, Role::Rs1, rs1);
        let b = self.read(c, Role::Rs2, rs2);
        self.write(c, rd, f(a, b));
    }

    fn op_imm(&mut self, c: &mut Cycle, rd: u8, rs1: u8, imm: i32, f: fn(u32, u32) -> u32) {
        let a = self.read(c, Role::Rs1, rs1);
        self.write(c, rd, f(a, imm as u32));
    }

    fn branch(
        &mut self,
        c: &mut Cycle,
        rs1: u8,
        rs2: u8,
        target: u32,
        fall: u32,
        taken: fn(u32, u32) -> bool,
    ) -> u32 {
        let a = self.read(c, Role::Rs1, rs1);
        let b = self.read(c, Role::Rs2, rs2);
        if taken(a, b) {
            target
        } else {
            fall
        }
    }

    /// A load: `rs1` at slot 1, the word at slot 2, `rd` at slot 3.
    /// `extend` gets the word shifted down to the accessed bytes.
    #[allow(clippy::too_many_arguments)]
    fn load(
        &mut self,
        c: &mut Cycle,
        pc: u32,
        rd: u8,
        rs1: u8,
        imm: i32,
        width: u32,
        extend: fn(u32) -> u32,
    ) -> Result<(), EmuError> {
        let addr = self.read(c, Role::Rs1, rs1).wrapping_add(imm as u32);
        let word = self.data_word(pc, addr, width)?;
        let value = self.word(word);
        c.stage(Role::Load, word, value, value);
        self.write(c, rd, extend(value >> (8 * (addr & 3))));
        Ok(())
    }

    /// A store: `rs1` at slot 1, `rs2` at slot 2, the word at slot 3 with the
    /// stored bytes merged into it.
    fn store(
        &mut self,
        c: &mut Cycle,
        pc: u32,
        rs1: u8,
        rs2: u8,
        imm: i32,
        width: u32,
    ) -> Result<(), EmuError> {
        let addr = self.read(c, Role::Rs1, rs1).wrapping_add(imm as u32);
        let value = self.read(c, Role::Rs2, rs2);
        let word = self.data_word(pc, addr, width)?;
        let shift = 8 * (addr & 3);
        let mask = (u32::MAX >> (32 - 8 * width)) << shift;
        let old = self.word(word);
        self.ram_write(c, word, old, (old & !mask) | ((value << shift) & mask));
        Ok(())
    }

    /// An AMO: `rs1` at slot 1, `rs2` at slot 2, then at slot 3 the word
    /// rewritten to `f(old, rs2)` and `rd` given the old value.
    fn amo(
        &mut self,
        c: &mut Cycle,
        pc: u32,
        rd: u8,
        rs1: u8,
        rs2: u8,
        f: fn(u32, u32) -> u32,
    ) -> Result<(), EmuError> {
        let addr = self.read(c, Role::Rs1, rs1);
        let src = self.read(c, Role::Rs2, rs2);
        let word = self.data_word(pc, addr, 4)?;
        let old = self.word(word);
        self.ram_write(c, word, old, f(old, src));
        self.write(c, rd, old);
        Ok(())
    }

    // -- ecall ------------------------------------------------------------

    /// An ecall: its transfer cycles, if it moves bytes, then its own row —
    /// `a7` at slot 1, the arguments its number uses at slot 2, `a0` written
    /// at slot 3, and `next_pc` the fall-through — except an exit's, which is
    /// the halting sentinel `HALT_PC` (`docs/spec/memory.md` §5).
    fn ecall(&mut self, instr: Instr, pc: u32, fall: u32) -> Result<(), EmuError> {
        let mut row = Cycle::new();
        let number = self.read(&mut row, Role::Rs1, 17);
        let result = match number {
            ecall::READ | ecall::WRITE => {
                let fd = self.read(&mut row, Role::Rs2, 10);
                let buf = self.read(&mut row, Role::Arg1, 11);
                let count = self.read(&mut row, Role::Arg2, 12);
                self.transfer(instr, pc, number == ecall::READ, fd, buf, count)?
            }
            ecall::EXIT => {
                let status = self.read(&mut row, Role::Rs2, 10);
                self.exit = Some(status as i32);
                status
            }
            // A delegation call: the frame base is its one argument, read as
            // the ABI table says, and the frame is permuted in place. The
            // invocation is not a cycle of its own — it rides this one, at
            // `delegation::FRAME_DELTA` (`docs/spec/delegation.md` §4.1).
            n if program::delegation_family(n).is_some() => {
                let family = program::delegation_family(n).expect("just matched");
                let base = self.read(&mut row, Role::Rs2, 10);
                if let Some(recorder) = &self.recorder {
                    if recorder.traces.delegation(family).is_none() {
                        return Err(EmuError::DelegationFamilyAbsent { pc, number: n });
                    }
                }
                let frame = self.delegate(family, pc, base)?;
                // The mirror query: the request consumes the invocation's
                // answer tuple, whose timestamp and value are both 0
                // (`docs/spec/delegation.md` §5). Its write-back is 0 too,
                // which nothing constrains and the honest fill writes.
                row.stage(Role::Delegate, base, 0, 0);
                row.delegation = Some((family, base, frame));
                0
            }
            _ => ecall::ENOSYS.wrapping_neg(),
        };
        self.write(&mut row, 10, result);
        let next_pc = if number == ecall::EXIT {
            memory::HALT_PC
        } else {
            fall
        };
        self.commit(&row, instr, pc, next_pc)
    }

    /// Move a `read`'s or a `write`'s bytes, one transfer cycle per word they
    /// touch — the pc re-written unchanged at slot 0, the word at slot 3 —
    /// and return what `a0` gets.
    fn transfer(
        &mut self,
        instr: Instr,
        pc: u32,
        reading: bool,
        fd: u32,
        buf: u32,
        count: u32,
    ) -> Result<u32, EmuError> {
        let left = |stream: &[u8], at: usize| (count as usize).min(stream.len() - at) as u32;
        let n = match (reading, fd) {
            (true, ecall::FD_STDIN) => left(self.stdin, self.stdin_at),
            (true, ecall::FD_HINT) => left(self.hint, self.hint_at),
            (false, ecall::FD_STDOUT | ecall::FD_STDERR) => count,
            _ => return Ok(ecall::EBADF.wrapping_neg()),
        };
        if n == 0 {
            return Ok(0);
        }
        let (start, end) = (buf as u64, buf as u64 + n as u64);
        let top = guest_memory::RAM_ORIGIN as u64 + guest_memory::RAM_LENGTH as u64;
        if start < guest_memory::RAM_ORIGIN as u64 || end > top {
            let addr = if start < guest_memory::RAM_ORIGIN as u64 {
                buf
            } else {
                buf.max(top as u32)
            };
            return Err(EmuError::OutOfBounds { pc, addr });
        }

        let (source, source_at) = if fd == ecall::FD_HINT {
            (self.hint, self.hint_at)
        } else {
            (self.stdin, self.stdin_at)
        };
        let mut written = Vec::new();
        let mut word = buf & !3;
        while (word as u64) < end {
            let old = self.word(word);
            let mut bytes = old.to_le_bytes();
            for (k, byte) in bytes.iter_mut().enumerate() {
                let addr = word as u64 + k as u64;
                if addr >= start && addr < end {
                    if reading {
                        *byte = source[source_at + (addr - start) as usize];
                    } else {
                        written.push(*byte);
                    }
                }
            }
            let new = u32::from_le_bytes(bytes);
            let mut cycle = Cycle::new();
            self.ram_write(&mut cycle, word, old, new);
            self.commit(&cycle, instr, pc, pc)?;
            word += 4;
        }
        match (reading, fd) {
            (true, ecall::FD_HINT) => self.hint_at += n as usize,
            (true, _) => self.stdin_at += n as usize,
            (false, ecall::FD_STDOUT) => self.stdout.extend_from_slice(&written),
            (false, _) => self.stderr.extend_from_slice(&written),
        }
        Ok(n)
    }
}

/// keccak-f[1600] over the state as 25 little-endian lanes, lane `5y + x` at
/// index `x + 5y`.
///
/// The reference permutation, written from `docs/spec/delegation.md` §6 and
/// the two tables of `constants::keccak`. `crates/guest-sdk` carries its own
/// copy for the software fallback — the two are held bit-identical by
/// `crates/emulator/tests/keccak.rs` and both to `tiny-keccak` — because the
/// SDK builds only for the guest target and is not a workspace member, and a
/// crate whose only purpose was to be shared by two callers would be the
/// abstraction the master's anti-goals refuse.
pub fn keccak_f(lanes: &mut [u64; keccak::LANES]) {
    for round in 0..keccak::ROUNDS {
        // theta
        let mut c = [0u64; 5];
        for (x, c) in c.iter_mut().enumerate() {
            *c = lanes[x] ^ lanes[x + 5] ^ lanes[x + 10] ^ lanes[x + 15] ^ lanes[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                lanes[x + 5 * y] ^= d;
            }
        }
        // rho and pi
        let mut b = [0u64; keccak::LANES];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    lanes[x + 5 * y].rotate_left(keccak::ROTATIONS[y][x]);
            }
        }
        // chi
        for x in 0..5 {
            for y in 0..5 {
                lanes[x + 5 * y] =
                    b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        // iota
        lanes[0] ^= keccak::ROUND_CONSTANTS[round];
    }
}

/// The 50 frame words as 25 lanes: word `2i` is lane `i`'s low half.
pub fn lanes_of(words: &[u32; keccak::FRAME_WORDS]) -> [u64; keccak::LANES] {
    core::array::from_fn(|i| words[2 * i] as u64 | (words[2 * i + 1] as u64) << 32)
}

/// The 25 lanes as 50 frame words: the inverse of [`lanes_of`].
pub fn words_of(lanes: &[u64; keccak::LANES]) -> [u32; keccak::FRAME_WORDS] {
    core::array::from_fn(|j| (lanes[j / 2] >> (32 * (j % 2))) as u32)
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
    /// The same per `traces.delegations[i]`, whose rows are invocations.
    deleg_rows: Vec<u64>,
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
        read_value: u32,
        write_value: u32,
    ) -> MemoryEvent {
        match self {
            Keep::Whole(log) => log.record(space, addr, ts, read_value, write_value),
            Keep::Streaming(state) => state.record(space, addr, ts, read_value, write_value),
        }
    }
}

impl<'a> Recorder<'a> {
    /// One recorder over `config`'s families: an empty buffer each, in the
    /// config's order, with the delegation families' buffers apart because
    /// their rows are invocations.
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
            deleg_rows: vec![0; traces.delegations.len()],
            traces,
            ready: Vec::new(),
        }
    }

    /// Log one cycle's queries — the pc query, then each role's in role
    /// order — and route its row to the family that owns its pc.
    fn record(&mut self, cycle: u64, pc: u32, next_pc: u32, instr: Instr, queries: &Cycle) {
        let base = memory::TS_STEP * cycle;
        self.memory.record(AddressSpace::Pc, 0, base, pc, next_pc);
        // An invocation's frame accesses ride this cycle at
        // `delegation::FRAME_DELTA`, which is 0, so they follow the pc query
        // and precede the row's roles: the log is in timestamp order
        // (`docs/spec/delegation.md` §4.1).
        let mut invocation: Vec<Query> = Vec::new();
        if let Some((_, _, frame)) = &queries.delegation {
            for (addr, read, write) in frame {
                let event = self.memory.record(
                    AddressSpace::Ram,
                    *addr,
                    base + delegation::FRAME_DELTA,
                    *read,
                    *write,
                );
                invocation.push(Query {
                    addr: *addr,
                    read_ts: event.read_ts,
                    read_value: *read,
                    write_value: *write,
                });
            }
        }
        // The row's mirror query names the delegation family's own anchor
        // space, which the role alone does not say: the invocation riding this
        // cycle does (`trace::Role::space`).
        let delegation = queries.delegation.as_ref().and_then(|(family, ..)| {
            program::delegation_space(*family).and_then(AddressSpace::from_tag)
        });
        let mut row = Row {
            cycle,
            pc,
            next_pc,
            present: 0,
            queries: [Query::ABSENT; 8],
        };
        for role in ROLES {
            if let Some((addr, read, write)) = queries.queries[role as usize] {
                let event = self.memory.record(
                    role.space(delegation),
                    addr,
                    base + role.delta(),
                    read,
                    write,
                );
                row.queries[role as usize] = Query {
                    addr,
                    read_ts: event.read_ts,
                    read_value: read,
                    write_value: write,
                };
                row.present |= 1 << role as u8;
            }
        }
        if let Some((family, frame_base, _)) = &queries.delegation {
            let at = self
                .traces
                .delegations
                .iter()
                .position(|t| t.family == *family)
                .expect("the ecall checked the family is in the config");
            self.traces.delegations[at].push(cycle, *frame_base, &invocation);
            self.deleg_rows[at] += 1;
            self.flush_delegation(at);
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
    /// `docs/spec/block-proof.md` §5.1 defines, with nothing to split.
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
            rows: ChunkRows::Cycles(Box::new(full)),
        });
    }

    /// [`Recorder::flush_family`] for a delegation family, whose rows are
    /// invocations.
    fn flush_delegation(&mut self, at: usize) {
        if !matches!(self.memory, Keep::Streaming(_)) {
            return;
        }
        let buffer = &mut self.traces.delegations[at];
        let height = buffer.height as usize;
        if buffer.len() < height {
            return;
        }
        let (family, rows, width) = (buffer.family, self.deleg_rows[at], buffer.words.len());
        let full = std::mem::replace(buffer, DelegationTrace::new(family, height as u32, width));
        self.ready.push(ShardChunk {
            family,
            index: (rows / height as u64 - 1) as u32,
            rows: ChunkRows::Invocations(full),
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
                rows: ChunkRows::Cycles(Box::new(full)),
            });
        }
        for (at, buffer) in self.traces.delegations.iter_mut().enumerate() {
            if buffer.is_empty() {
                continue;
            }
            let (family, height, width) = (buffer.family, buffer.height, buffer.words.len());
            let full = std::mem::replace(buffer, DelegationTrace::new(family, height, width));
            out.push(ShardChunk {
                family,
                index: (self.deleg_rows[at] / height as u64) as u32,
                rows: ChunkRows::Invocations(full),
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
                    .zip(&self.deleg_rows)
                    .map(|(t, n)| (t.family, *n)),
            )
            .collect();
        counts.sort_by_key(|(f, _)| *f);
        CycleProfile { counts }
    }

    /// The one family whose table claims `pc`.
    ///
    /// By family id rather than by position: a delegation family is in the
    /// decoded tables — with an empty table, claiming nothing — but its buffer
    /// is a `DelegationTrace`, so the two lists no longer line up by index.
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

    /// `mod_mul_frame` against `u128` arithmetic, which is an independent
    /// reference for every case a `u128` can hold.
    ///
    /// The executor's long division is 512 iterations of limb arithmetic and is
    /// exactly the sort of loop that is right on most inputs. The comparison is
    /// against `u128::checked_mul` and `%` on operands that fit 64 bits — which
    /// leaves the top limbs untested, so the second half of the test is the
    /// **identity** `a·b = q·m + out` recomputed over the full 256-bit width from
    /// the frame the executor wrote, on wide random operands.
    #[test]
    fn mod_mul_frame_computes_a_times_b_mod_m() {
        let limbs = |x: u128| -> [u32; mod_mul::LIMBS] {
            core::array::from_fn(|k| match k < 4 {
                true => (x >> (32 * k)) as u32,
                false => 0,
            })
        };
        let frame_of = |m: [u32; 8], a: [u32; 8], b: [u32; 8]| -> Vec<u32> {
            let mut old = vec![0u32; mod_mul::FRAME_WORDS];
            old[mod_mul::M_WORD..mod_mul::M_WORD + 8].copy_from_slice(&m);
            old[mod_mul::A_WORD..mod_mul::A_WORD + 8].copy_from_slice(&a);
            old[mod_mul::B_WORD..mod_mul::B_WORD + 8].copy_from_slice(&b);
            mod_mul_frame(0, &old).expect("a nonzero modulus")
        };
        // Small cases a `u128` answers directly, the corners included.
        for (a, b, m) in [
            (0u128, 0u128, 1u128),
            (0, 12345, 97),
            (1, 1, 2),
            (u64::MAX as u128, u64::MAX as u128, (1u128 << 61) - 1),
            (7, 9, 5),
            (6, 7, 42),
            (0xdead_beef, 0xfeed_face, 0xffff_fffb),
            ((1u128 << 63) - 1, (1u128 << 63) + 1, (1u128 << 64) - 59),
        ] {
            let out = frame_of(limbs(m), limbs(a), limbs(b));
            let got = (0..4).fold(0u128, |acc, k| {
                acc | (out[mod_mul::OUT_WORD + k] as u128) << (32 * k)
            });
            assert_eq!(got, a * b % m, "{a} * {b} mod {m}");
            for k in 4..8 {
                assert_eq!(out[mod_mul::OUT_WORD + k], 0, "the result fits 128 bits");
            }
            // The words the invocation does not compute are written back.
            let mut old = [0u32; mod_mul::FRAME_WORDS];
            old[mod_mul::M_WORD..mod_mul::M_WORD + 8].copy_from_slice(&limbs(m));
            old[mod_mul::A_WORD..mod_mul::A_WORD + 8].copy_from_slice(&limbs(a));
            old[mod_mul::B_WORD..mod_mul::B_WORD + 8].copy_from_slice(&limbs(b));
            for j in 0..mod_mul::OUT_WORD {
                assert_eq!(out[j], old[j], "word {j} is written back unchanged");
            }
        }
        // The full width: the identity, over `i128`-free limb arithmetic.
        let mut seed = 0x0123_4567_89ab_cdefu64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        // secp256k1's `p`, the modulus this family exists for.
        let mut p = [0xffff_ffffu32; 8];
        p[0] = 0xffff_fc2f;
        p[1] = 0xffff_fffe;
        for _ in 0..8 {
            let mut wide = || -> [u32; 8] { core::array::from_fn(|_| next() as u32) };
            let (a, b) = (wide(), wide());
            let out = frame_of(p, a, b);
            let result: [u32; 8] = core::array::from_fn(|k| out[mod_mul::OUT_WORD + k]);
            // `out < p`, and `a·b − out` divisible by `p`: the two halves of
            // "out is the remainder", checked over 16-limb arithmetic here.
            assert!(
                super::less_than(
                    &core::array::from_fn(|k| result[k] as u64),
                    &core::array::from_fn(|k| p[k] as u64)
                ),
                "the result is reduced"
            );
            let product = wide_mul16(&a, &b);
            let mut left = product;
            sub16(&mut left, &result);
            assert!(divides16(&left, &p), "a·b − out is a multiple of p");
        }
    }

    /// `x · y` over eight 32-bit limbs, as sixteen. Test-only.
    fn wide_mul16(x: &[u32; 8], y: &[u32; 8]) -> [u32; 16] {
        let mut out = [0u64; 16];
        for i in 0..8 {
            let mut carry = 0u64;
            for j in 0..8 {
                let total = out[i + j] + x[i] as u64 * y[j] as u64 + carry;
                out[i + j] = total & 0xffff_ffff;
                carry = total >> 32;
            }
            let mut at = i + 8;
            while carry != 0 {
                let total = out[at] + carry;
                out[at] = total & 0xffff_ffff;
                carry = total >> 32;
                at += 1;
            }
        }
        core::array::from_fn(|k| out[k] as u32)
    }

    /// `x -= y` over sixteen limbs against eight. Test-only.
    fn sub16(x: &mut [u32; 16], y: &[u32; 8]) {
        let mut borrow = 0i64;
        for k in 0..16 {
            let sub = if k < 8 { y[k] as i64 } else { 0 };
            let d = x[k] as i64 - sub - borrow;
            borrow = i64::from(d < 0);
            x[k] = (d + if d < 0 { 1i64 << 32 } else { 0 }) as u32;
        }
        assert_eq!(borrow, 0, "a·b is at least the remainder");
    }

    /// Whether `x` is a multiple of `m`, by long division. Test-only.
    fn divides16(x: &[u32; 16], m: &[u32; 8]) -> bool {
        let mut rem = [0u64; 9];
        for bit in (0..32 * 16).rev() {
            let mut carry = ((x[bit / 32] >> (bit % 32)) & 1) as u64;
            for word in rem.iter_mut() {
                let total = (*word << 1) | carry;
                *word = total & 0xffff_ffff;
                carry = total >> 32;
            }
            let ge = rem[8] != 0
                || (0..8)
                    .rev()
                    .find(|k| rem[*k] != m[*k] as u64)
                    .is_none_or(|k| rem[k] > m[k] as u64);
            if ge {
                let mut borrow = 0i64;
                for k in 0..8 {
                    let d = rem[k] as i64 - m[k] as i64 - borrow;
                    borrow = i64::from(d < 0);
                    rem[k] = (d + if d < 0 { 1i64 << 32 } else { 0 }) as u64;
                }
                rem[8] -= borrow as u64;
            }
        }
        rem.iter().all(|w| *w == 0)
    }

    /// A zero modulus is refused by name rather than wrapped.
    #[test]
    fn mod_mul_refuses_a_zero_modulus() {
        let old = vec![0u32; mod_mul::FRAME_WORDS];
        assert_eq!(
            mod_mul_frame(0x1234, &old),
            Err(EmuError::DelegationFrame {
                pc: 0x1234,
                detail: "the modulus is zero"
            })
        );
    }

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
        }
    }

    /// The last cycle whose four timestamps fit the 38-bit clock runs; the
    /// next is refused, by name, before anything is recorded for it.
    #[test]
    fn the_clock_refuses_the_first_cycle_past_38_bits() {
        let io = GuestIo {
            input: Vec::new(),
            advice: Vec::new(),
            stdin: Vec::new(),
            hint: Vec::new(),
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
}
