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
//! knows exactly which program ran — and it is the one divergence
//! [`qemu::WHITELIST`] names. A halfword or word access at an address that is
//! not a multiple of its width, and any access outside the RAM window, is a
//! fatal guest error, never rotated, split or emulated. So is `ebreak`, and
//! so is a pc that is not the start of an instruction.

use std::collections::HashMap;
use std::fmt;

use constants::{ecall, guest_memory, memory};
use isa::{decode, Instr};
use loader::{ProgramImage, Slot};
use program::{row_kind, DecodedTables, VmConfig};
use trace::{
    AddressSpace, CycleProfile, FamilyTrace, FamilyTraces, IoStreams, MemoryEventLog, Query, Role,
    Row, ROLES,
};

pub mod qemu;

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
            EmuError::OutOfBounds { pc, addr } => write!(
                f,
                "data access outside the RAM window at pc {pc:#010x}: address {addr:#010x}"
            ),
            EmuError::ClockOverflow { cycle } => write!(
                f,
                "cycle {cycle} would pass the {}-bit timestamp clock",
                memory::TS_BITS
            ),
        }
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
                .map(|(family, height)| FamilyTrace::new(*family, *height))
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
        counts: recorder
            .traces
            .families
            .iter()
            .map(|t| (t.family, t.len() as u64))
            .collect(),
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
struct Cycle {
    queries: [Option<(u32, u32, u32)>; 7],
}

impl Cycle {
    fn new() -> Cycle {
        Cycle { queries: [None; 7] }
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
    /// at slot 3, and `next_pc` the fall-through.
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
            _ => ecall::ENOSYS.wrapping_neg(),
        };
        self.write(&mut row, 10, result);
        self.commit(&row, instr, pc, fall)
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
            (true, ecall::FD_PUBLIC_INPUT) => left(self.input, self.input_at),
            (true, ecall::FD_HINT) => left(self.hint, self.hint_at),
            (false, ecall::FD_PUBLIC_OUTPUT | ecall::FD_STDERR) => count,
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
            (self.input, self.input_at)
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
            (true, _) => self.input_at += n as usize,
            (false, ecall::FD_PUBLIC_OUTPUT) => self.output.extend_from_slice(&written),
            (false, _) => self.stderr.extend_from_slice(&written),
        }
        Ok(n)
    }
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
        let mut row = Row {
            cycle,
            pc,
            next_pc,
            present: 0,
            queries: [Query::ABSENT; 7],
        };
        for role in ROLES {
            if let Some((addr, read, write)) = queries.queries[role as usize] {
                let event = self
                    .log
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
        self.traces.families[owner].push(&row);
    }

    /// The position of the one family whose table claims `pc`.
    fn owner(&self, pc: u32, instr: Instr) -> usize {
        let row = (pc / 2) as usize;
        let mut owners = self
            .tables
            .families
            .iter()
            .enumerate()
            .filter(|(_, t)| t.is_live(row));
        let (at, table) = owners.next().unwrap_or_else(|| {
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
        at
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
