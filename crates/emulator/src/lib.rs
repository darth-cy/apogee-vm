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
//! knows exactly which program ran — and one this VM's circuits share, so
//! emulator and constraint agree on it. It is **not** held against
//! `qemu-riscv32`: since S25 nothing below the level of what a guest computes
//! is (`crates/emulator/tests/qemu_outputs.rs`).
//! A halfword or word access at an address that is
//! not a multiple of its width, and any access outside the RAM window, is a
//! fatal guest error, never rotated, split or emulated. So is `ebreak`, and
//! so is a pc that is not the start of an instruction.

use std::collections::HashMap;
use std::fmt;

use constants::{delegation, ecall, family, fr_arith, guest_memory, keccak, memory, poseidon2};
use field::Fr;
use isa::{decode, Instr};
use loader::{ProgramImage, Slot};
use program::{row_kind, DecodedTables, FamilyId, VmConfig};
use trace::{
    AddressSpace, CycleProfile, DelegationTrace, FamilyTrace, FamilyTraces, IoStreams,
    MemoryEventLog, Query, Role, Row, ROLES,
};

/// What a guest can read: the fd 0 public input and the fd 3 hint stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestIo {
    pub input: Vec<u8>,
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
    /// The fd 0 bytes the guest consumed and the fd 1 bytes it wrote.
    pub io: IoStreams,
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
    /// A `read` on fd 0 or fd 3 whose `a2` is not
    /// [`constants::ecall::READ_WORD_BYTES`].
    ///
    /// Fatal, not a short answer. One provable `read` moves exactly one
    /// 4-aligned word (`docs/spec/ecall-abi.md` §4), and the circuit pins
    /// `a2 = 4` on every row that makes the query — so an executor that
    /// answered a different count would produce a trace no prover can prove,
    /// which is the one divergence this crate exists to prevent.
    ReadNotOneWord { pc: u32, count: u32 },
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
            EmuError::Misaligned { pc, addr, width } => write!(
                f,
                "misaligned data access at pc {pc:#010x}: a {width}-byte access at {addr:#010x}"
            ),
            EmuError::ReadNotOneWord { pc, count } => write!(
                f,
                "read at pc {pc:#010x} asked for {count} bytes; one read moves exactly {}",
                ecall::READ_WORD_BYTES
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

/// Run a guest to its `exit`.
pub fn run(image: &ProgramImage, io: &GuestIo) -> Result<Execution, EmuError> {
    let mut machine = Machine::new(image, io);
    machine.run()?;
    Ok(machine.finish())
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
    let mut machine = Machine::new(image, io);
    machine.recorder = Some(Recorder {
        tables,
        log: MemoryEventLog::new(),
        traces: FamilyTraces {
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
        },
    });
    machine.run()?;
    let recorder = machine
        .recorder
        .take()
        .expect("trace_run installed a recorder");
    let execution = machine.finish();
    let profile = CycleProfile {
        counts: recorder.traces.row_counts(),
    };
    assert_eq!(
        profile.total(),
        execution.cycle_count,
        "routing: every cycle lands in exactly one family buffer"
    );
    Ok((recorder.traces, recorder.log, profile, execution))
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
    input: &'a [u8],
    input_at: usize,
    hint: &'a [u8],
    hint_at: usize,
    output: Vec<u8>,
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
            input: &io.input,
            input_at: 0,
            hint: &io.hint,
            hint_at: 0,
            output: Vec::new(),
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
        machine
    }

    fn run(&mut self) -> Result<(), EmuError> {
        while self.exit.is_none() {
            self.step()?;
        }
        Ok(())
    }

    fn finish(self) -> Execution {
        Execution {
            regs: self.regs,
            exit_code: self.exit.expect("an execution finishes at its exit"),
            cycle_count: self.cycle - 1,
            io: IoStreams {
                input: self.input[..self.input_at].to_vec(),
                output: self.output,
            },
            stderr: self.stderr,
        }
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
        if word < guest_memory::RAM_ORIGIN
            || word - guest_memory::RAM_ORIGIN >= guest_memory::RAM_LENGTH
        {
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

    /// An ecall: **one row**, since S25 removed the transfer cycle — `a7` at
    /// slot 1, the arguments its number uses at slot 2, `a0` written at slot 3
    /// with a provable `read`'s delivered word beside it, and `next_pc` the
    /// fall-through — except an exit's, which is the halting sentinel
    /// `HALT_PC` (`docs/spec/memory.md` §5).
    fn ecall(&mut self, instr: Instr, pc: u32, fall: u32) -> Result<(), EmuError> {
        let mut row = Cycle::new();
        let number = self.read(&mut row, Role::Rs1, 17);
        let result = match number {
            ecall::READ | ecall::WRITE => {
                let fd = self.read(&mut row, Role::Rs2, 10);
                let buf = self.read(&mut row, Role::Arg1, 11);
                let count = self.read(&mut row, Role::Arg2, 12);
                if number == ecall::READ {
                    self.read_word(&mut row, pc, fd, buf, count)?
                } else {
                    self.write_stream(pc, fd, buf, count)?
                }
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

    /// Deliver **one 4-aligned word** of a `read`, into the ecall's own row,
    /// and return what `a0` gets.
    ///
    /// # Why one word, and why on this row
    ///
    /// S14's open question 10 asked how an ecall's RAM traffic is confined and
    /// offered two answers; S25 took the one it recommended. A multi-word
    /// transfer needs rows of its own, and a row of its own has nothing on it
    /// to bound its own address with — so confining it needs the buffer and
    /// the count carried across rows, which this arithmetization can only do
    /// through the global memory multiset. Delivering one word per ecall puts
    /// the RAM query on the row that already reads `a1` and `a2`, and the
    /// whole confinement becomes two degree-2 gates on that row.
    ///
    /// So **there are no transfer cycles**: every instruction is one cycle
    /// again (`docs/spec/execution-trace.md` §1), and this query rides slot 3
    /// beside the `a0` write, at a different address — which §3 permits and
    /// the atomics family has always done.
    ///
    /// `count` must be exactly [`ecall::READ_WORD_BYTES`] and `buf` must be
    /// 4-aligned and inside the RAM window. Each is a **fatal guest error**
    /// rather than a short answer, because the circuit pins `a2 = 4` and
    /// `ram_addr = a1` on every row that makes this query: an executor that
    /// answered otherwise would produce a trace no prover can prove, and a
    /// silent divergence between the executor and the circuit is the one
    /// failure this file exists to prevent.
    ///
    /// **The query is staged even at end of stream**, writing the word back
    /// unchanged. That is what lets the circuit key the query's mask on
    /// `is_read` alone, with no "did it move anything" selector to constrain.
    fn read_word(
        &mut self,
        row: &mut Cycle,
        pc: u32,
        fd: u32,
        buf: u32,
        count: u32,
    ) -> Result<u32, EmuError> {
        if !matches!(fd, ecall::FD_PUBLIC_INPUT | ecall::FD_HINT) {
            return Ok(ecall::EBADF.wrapping_neg());
        }
        if count != ecall::READ_WORD_BYTES {
            return Err(EmuError::ReadNotOneWord { pc, count });
        }
        if !buf.is_multiple_of(4) {
            return Err(EmuError::Misaligned {
                pc,
                addr: buf,
                width: ecall::READ_WORD_BYTES,
            });
        }
        let top = guest_memory::RAM_ORIGIN as u64 + guest_memory::RAM_LENGTH as u64;
        if (buf as u64) < guest_memory::RAM_ORIGIN as u64
            || buf as u64 + ecall::READ_WORD_BYTES as u64 > top
        {
            return Err(EmuError::OutOfBounds { pc, addr: buf });
        }

        let (source, at) = if fd == ecall::FD_HINT {
            (self.hint, self.hint_at)
        } else {
            (self.input, self.input_at)
        };
        let n = (ecall::READ_WORD_BYTES as usize).min(source.len() - at);
        let old = self.word(buf);
        let mut bytes = old.to_le_bytes();
        bytes[..n].copy_from_slice(&source[at..at + n]);
        self.ram_write(row, buf, old, u32::from_le_bytes(bytes));
        if fd == ecall::FD_HINT {
            self.hint_at += n;
        } else {
            self.input_at += n;
        }
        Ok(n as u32)
    }

    /// Append a `write`'s bytes to its stream, and return what `a0` gets.
    ///
    /// **It stages no memory query at all.** A write reads the guest's buffer
    /// and writes it back unchanged, so the query it used to make bound
    /// nothing: what ties fd 1 to the execution is the guest's own
    /// `io_digest` over the bytes it passed to `commit`, which it assembled
    /// with ordinary loads and stores that the memory argument does bind
    /// (`docs/spec/memory.md` §10). Dropping the query is the other half of
    /// S14's open question 10, and the half its recorded recommendation also
    /// took.
    ///
    /// So a `write` is unrestricted: any buffer, any alignment, any count, one
    /// cycle. Only the RAM-window bound survives, because reading outside the
    /// window is a fatal guest error however the bytes are used.
    fn write_stream(&mut self, pc: u32, fd: u32, buf: u32, count: u32) -> Result<u32, EmuError> {
        if !matches!(fd, ecall::FD_PUBLIC_OUTPUT | ecall::FD_STDERR) {
            return Ok(ecall::EBADF.wrapping_neg());
        }
        if count == 0 {
            return Ok(0);
        }
        let (start, end) = (buf as u64, buf as u64 + count as u64);
        let top = guest_memory::RAM_ORIGIN as u64 + guest_memory::RAM_LENGTH as u64;
        if start < guest_memory::RAM_ORIGIN as u64 || end > top {
            let addr = if start < guest_memory::RAM_ORIGIN as u64 {
                buf
            } else {
                buf.max(top as u32)
            };
            return Err(EmuError::OutOfBounds { pc, addr });
        }
        let mut written = Vec::with_capacity(count as usize);
        for addr in start..end {
            let word = self.word((addr as u32) & !3);
            written.push(word.to_le_bytes()[(addr & 3) as usize]);
        }
        if fd == ecall::FD_PUBLIC_OUTPUT {
            self.output.extend_from_slice(&written);
        } else {
            self.stderr.extend_from_slice(&written);
        }
        Ok(count)
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
    log: MemoryEventLog,
    traces: FamilyTraces,
}

impl Recorder<'_> {
    /// Log one cycle's queries — the pc query, then each role's in role
    /// order — and route its row to the family that owns its pc.
    fn record(&mut self, cycle: u64, pc: u32, next_pc: u32, instr: Instr, queries: &Cycle) {
        let base = memory::TS_STEP * cycle;
        self.log.record(AddressSpace::Pc, 0, base, pc, next_pc);
        // An invocation's frame accesses ride this cycle at
        // `delegation::FRAME_DELTA`, which is 0, so they follow the pc query
        // and precede the row's roles: the log is in timestamp order
        // (`docs/spec/delegation.md` §4.1).
        let mut invocation: Vec<Query> = Vec::new();
        if let Some((_, _, frame)) = &queries.delegation {
            for (addr, read, write) in frame {
                let event = self.log.record(
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
                let event = self.log.record(
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
            let buffer = self
                .traces
                .delegations
                .iter_mut()
                .find(|t| t.family == *family)
                .expect("the ecall checked the family is in the config");
            buffer.push(cycle, *frame_base, &invocation);
        }
        let owner = self.owner(pc, instr);
        self.traces
            .families
            .iter_mut()
            .find(|t| t.family == owner)
            .expect("the owning family has a buffer")
            .push(&row);
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
